// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: profile_photo.ts
//
// ===========================================================================
// A PERSON'S PROFILE PHOTO (#719): one image this realm keeps and serves for
// a person, set by them on the portal or copied from a federation partner.
//
// `pictureUrl` (#1292) was already the attribute behind OpenID Connect's
// `picture` claim, and a partner's `picture` already landed on it through
// `federation_map.ts`. What was missing is the image: the claim named
// somebody else's address, nothing here could show a photo, and a person
// could not set one. So this module adds the image and leaves that claim
// path alone: while a person has a photo here, `pictureUrl` holds its
// address, and every reader of the attribute follows without knowing.
//
// THE DESIGN, in the order a reader meets it:
//
//   * **THE BYTES ARE NOT ON THE ENTRY.** Every sign-in and every token reads
//     the entry, and each read opens its sealed body, so an image on it
//     would be paid for by everything that has nothing to do with a photo.
//     `jpegPhoto` also says JPEG, and a partner may send a PNG. The bytes are
//     a row of `profilePhoto.images`, read on demand (`persistence/CLAUDE.md`,
//     *A store that grows with every person*); the entry carries one JSON
//     value of `stsProfilePhoto` saying which row is theirs.
//   * **THE CACHE IS BOUNDED BY COUNT, SO A ROW IS KEPT SMALL.** That bound is
//     why `profilePhoto.maxStoredBytes` is a good deal less than the file a
//     person may choose (`profilePhoto.maxFileBytes`): the browser crops and
//     scales what they chose before it is sent.
//   * **THE ADDRESS IS RANDOM AND IT CHANGES WITH THE PHOTO.** A relying party
//     fetches `picture` with no credential, so the address has to be the
//     capability: 128 random bits stamped with the minting cell's tag, as a
//     person's published DID is (#1291), never a username or an entryUUID.
//     Nobody enumerates people by probing it. A new photo is a new id, so a
//     cached old one is not refreshed into a new person's face.
//   * **UNDER `/web`, ON PURPOSE**, for the logo's reason (#717): everything
//     there answers on every listener, so the three surfaces' existing
//     `img-src 'self'` admits it wherever each is hosted, and no origin joins
//     a policy. It is `artifact`-placed, because the row lives in a cell.
//   * **THE BYTES DECIDE THE TYPE**, never a header or a file name, and only
//     JPEG and PNG are kept. SVG is the one to name: it is a document that can
//     carry script. What is kept is REWRITTEN first (`stripped()`): metadata
//     out — a phone's EXIF holds where it was taken, and this image is served
//     to anybody with the address — and nothing after the image's end, so a
//     file cannot be a picture and something else at once. It is served
//     `nosniff` under a sandboxing policy.
//   * **A DISABLED OR DELETED PERSON'S ADDRESS ANSWERS 404**, decided when it
//     is served, so re-enabling the account restores it; deleting the entry
//     removes the row.
//
// THE PARTNER'S COPY (`noteFederated()`): the twenty-third of the URLs this
// service dials (`federation/CLAUDE.md`, which argues it). Never while the
// sign-in waits. A person's own photo always wins, and removing a copied one
// is remembered (`declined`), or the next sign-in would bring it back. Where
// a copy cannot be made the partner's address stays on `pictureUrl`, as it
// always did: a `picture` claim that works is better than none.
//
// **A LIBRARY OF `config`, `realms`, `crypto`** with one route module's worth
// of routes, beside the logo in the route order; it reaches the directory, the
// account state and federation's dialer lazily, because each is loaded long
// after it. It is a static utility class, as `branding.ts` is.
// ===========================================================================

import helpers = require('./helpers');
import config = require('./config');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import stsCrypto = require('./crypto');
import mode = require('./mode');
import cellLocator = require('./cell_locator');

const log = helpers.log;

type Json = any;

// The route, its id being the row's key.
const ROUTE = '/web/photo/:id';
const PATH_PREFIX = '/web/photo/';

// Who put the photo there.
const ORIGINS = Object.freeze({ PERSON: 'person', FEDERATION: 'federation' });

// The id's size, as a person's published DID's is (#1291).
const RID_BITS = 128;

// How long a partner's same address is believed before it is asked again: a
// person who changes their photo there gets a new address at most providers,
// and the ones that keep the address are caught up with this slowly enough
// that no sign-in storm dials anybody.
const REFETCH_MS = 7 * 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 10000;

// A partner's own default is often small (one sends 96 by 96 unless asked),
// so the person's minimum cannot apply to a copy. This only refuses a
// tracking pixel presented as a photo.
const SMALLEST_COPY = 16;

// The chunks of a PNG a viewer needs: its image and how to colour it. Everything
// else — text, EXIF, an animation's frames, a chunk nobody registered — goes.
const PNG_KEPT = Object.freeze(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA',
                                'cHRM', 'sRGB', 'iCCP', 'sBIT', 'pHYs']);

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47,
                                   0x0d, 0x0a, 0x1a, 0x0a]);

// `<rid>` -> `{ type, data (base64), sha256, width, height, bytes, sub,
// updatedAt }`. Per realm at the declaration (root CLAUDE.md, trust realms 2),
// and on demand: a store that grows with every person is never read back
// whole. Cell-tier in `persistence/tiers.js`, beside the entry it belongs to.
// The bound is low because the rows are the largest in the process.
const images = realms.map({ persist: 'profilePhoto.images',
                            onDemand: { maxEntries: 200 } });

// An image needs nothing, and is sandboxed if it is ever opened as a document.
// Through `app.contentSecurityPolicy()` (root CLAUDE.md): a header set by hand
// without `frame-ancestors` is replaced at the flush by the base policy, which
// is what the first version of this did, with nothing failing in-process.
const SERVED_POLICY = Object.freeze({ 'style-src': null, 'img-src': null,
                                      sandbox: '' });

// The partner addresses being dialled now, per process, so a burst of
// sign-ins by one person dials once. Not a store: it means nothing past the
// request that added it.
const inFlight = new Set<string>();

/**
 * A person's profile photo. A static utility class; its one store is declared
 * above.
 */
class ProfilePhoto {
  static readonly ORIGINS = ORIGINS;
  static readonly PATH_PREFIX = PATH_PREFIX;

  /**
   * Reads a setting with a fallback for a realm that cannot be asked.
   *
   * @param key - the setting
   * @param fallback - what to answer when it cannot be read
   * @returns the value
   */
  static setting(key: string, fallback: unknown): unknown {
    log.debug("Entering ProfilePhoto.setting(). " + key);
    let value: unknown = fallback;
    try {
      value = config.value(key);
    } catch (e) {
      log.debug("Caught in ProfilePhoto.setting(): " +
                ((e && e.message) || e));
      // Only a process with no settings yet, which serves nothing.
    }
    log.debug("Leaving ProfilePhoto.setting().");
    return value;
  }

  /**
   * What a person choosing a photo is held to, for the page and the refusals.
   *
   * @returns `{ maxFileBytes, maxStoredBytes, minPixels, maxPixels, types }`
   */
  static limits(): Json {
    log.debug("Entering ProfilePhoto.limits().");
    const out = {
      maxFileBytes: Number(ProfilePhoto.setting('profilePhoto.maxFileBytes',
                                                5242880)),
      maxStoredBytes: Number(ProfilePhoto.setting(
        'profilePhoto.maxStoredBytes', 1048576)),
      minPixels: Number(ProfilePhoto.setting('profilePhoto.minPixels', 250)),
      maxPixels: Number(ProfilePhoto.setting('profilePhoto.maxPixels', 4096)),
      types: ['image/jpeg', 'image/png']
    };
    log.debug("Leaving ProfilePhoto.limits().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE BYTES.
  // -------------------------------------------------------------------------
  /**
   * A JPEG or PNG's type and sides, decided by its bytes.
   *
   * @param bytes - the file
   * @returns `{ type, width, height }`, `type` empty for anything else
   */
  static sniff(bytes: Buffer): { type: string, width: number,
                                 height: number } {
    log.debug("Entering ProfilePhoto.sniff().");
    // The logo's reader (#717): one answer to what a file is. WebP is the one
    // it knows that is not kept here, because `stripped()` has no writer for
    // it and an image that cannot be cleaned is not served to the world.
    const seen = require('./branding').sniff(bytes);
    const kept = seen.type === 'image/jpeg' || seen.type === 'image/png';
    log.debug("Leaving ProfilePhoto.sniff(). " + seen.type);
    return kept ? seen : { type: '', width: 0, height: 0 };
  }

  /**
   * A JPEG with its metadata segments and anything after its end removed.
   *
   * APP0 (JFIF), APP2 (a colour profile) and APP14 (Adobe's colour transform,
   * without which some files decode wrongly) stay; every other application
   * segment and every comment goes. A file that is not walkable to its scan
   * is not an image this service will rewrite, and it answers null.
   *
   * @param b - the file, starting with the SOI marker
   * @returns the rewritten file, or null
   */
  static strippedJpeg(b: Buffer): Buffer | null {
    log.debug("Entering ProfilePhoto.strippedJpeg().");
    const pieces: Buffer[] = [b.slice(0, 2)];
    let i = 2;
    while (i + 4 <= b.length) {
      if (b[i] !== 0xff) {
        log.debug("Leaving ProfilePhoto.strippedJpeg(). Not a marker.");
        return null;
      }
      const marker = b[i + 1];
      if (marker === 0xff) {
        i += 1;
        continue;
      }
      if (marker === 0xda) {
        // The scan. Everything from here is the image, to the LAST end marker
        // in the file: bytes after that are what a polyglot is made of.
        const end = b.lastIndexOf(Buffer.from([0xff, 0xd9]));
        if (end <= i) {
          log.debug("Leaving ProfilePhoto.strippedJpeg(). No end.");
          return null;
        }
        pieces.push(b.slice(i, end + 2));
        log.debug("Leaving ProfilePhoto.strippedJpeg().");
        return Buffer.concat(pieces);
      }
      const length = b.readUInt16BE(i + 2);
      if (length < 2 || i + 2 + length > b.length) {
        log.debug("Leaving ProfilePhoto.strippedJpeg(). A bad length.");
        return null;
      }
      const application = marker >= 0xe0 && marker <= 0xef;
      const keptApplication = marker === 0xe0 || marker === 0xe2 ||
                              marker === 0xee;
      const dropped = marker === 0xfe || (application && !keptApplication);
      if (!dropped) {
        pieces.push(b.slice(i, i + 2 + length));
      }
      i += 2 + length;
    }
    log.debug("Leaving ProfilePhoto.strippedJpeg(). No scan.");
    return null;
  }

  /**
   * A PNG holding only the chunks in `PNG_KEPT`, and nothing after `IEND`.
   *
   * @param b - the file, starting with the PNG signature
   * @returns the rewritten file, or null when it does not walk to `IEND`
   */
  static strippedPng(b: Buffer): Buffer | null {
    log.debug("Entering ProfilePhoto.strippedPng().");
    if (!b.slice(0, 8).equals(PNG_SIGNATURE)) {
      log.debug("Leaving ProfilePhoto.strippedPng(). No signature.");
      return null;
    }
    const pieces: Buffer[] = [b.slice(0, 8)];
    let i = 8;
    while (i + 12 <= b.length) {
      const length = b.readUInt32BE(i);
      const end = i + 12 + length;
      if (end > b.length) {
        log.debug("Leaving ProfilePhoto.strippedPng(). A bad length.");
        return null;
      }
      const name = b.toString('latin1', i + 4, i + 8);
      if (PNG_KEPT.indexOf(name) >= 0) {
        pieces.push(b.slice(i, end));
      }
      if (name === 'IEND') {
        log.debug("Leaving ProfilePhoto.strippedPng().");
        return Buffer.concat(pieces);
      }
      i = end;
    }
    log.debug("Leaving ProfilePhoto.strippedPng(). No IEND.");
    return null;
  }

  /**
   * The file as it will be kept, or null when it cannot be rewritten.
   *
   * @param bytes - the file
   * @param type - its type, from `sniff()`
   * @returns the rewritten file, or null
   */
  static stripped(bytes: Buffer, type: string): Buffer | null {
    log.debug("Entering ProfilePhoto.stripped(). " + type);
    const out = type === 'image/png' ? ProfilePhoto.strippedPng(bytes)
                                     : ProfilePhoto.strippedJpeg(bytes);
    log.debug("Leaving ProfilePhoto.stripped().");
    return out;
  }

  /**
   * Checks a file against the limits and rewrites it for keeping.
   *
   * @param bytes - the file
   * @param minPixels - the shortest side allowed
   * @returns `{ ok, bytes, type, width, height }`, or `{ ok: false, code,
   *   status, error }`
   */
  static checked(bytes: Buffer, minPixels: number): Json {
    log.debug("Entering ProfilePhoto.checked().");
    const limits = ProfilePhoto.limits();
    const refusal = function (code: string, status: number,
                              error: string): Json {
      log.debug("Entering refusal(). " + code);
      log.debug("Leaving refusal().");
      return { ok: false, code: code, status: status, error: error };
    };
    const b = Buffer.isBuffer(bytes) ? bytes : Buffer.alloc(0);
    if (b.length > limits.maxStoredBytes) {
      log.debug("Leaving ProfilePhoto.checked(). Too large.");
      return refusal('STS-PORTAL-0631', 413, 'The photo is ' + b.length +
                     ' bytes, and at most ' + limits.maxStoredBytes +
                     ' are kept.');
    }
    const seen = ProfilePhoto.sniff(b);
    if (!seen.type) {
      log.debug("Leaving ProfilePhoto.checked(). Not an image.");
      return refusal('STS-PORTAL-0630', 400,
                     'A profile photo is a JPEG or a PNG file.');
    }
    const shortest = Math.min(seen.width, seen.height);
    const longest = Math.max(seen.width, seen.height);
    if (shortest < minPixels || longest > limits.maxPixels) {
      log.debug("Leaving ProfilePhoto.checked(). The sides.");
      return refusal('STS-PORTAL-0632', 400, 'The photo is ' + seen.width +
                     ' by ' + seen.height + ' pixels: each side has to be ' +
                     'at least ' + minPixels + ' and at most ' +
                     limits.maxPixels + '.');
    }
    const kept = ProfilePhoto.stripped(b, seen.type);
    if (!kept) {
      log.debug("Leaving ProfilePhoto.checked(). Not rewritable.");
      return refusal('STS-PORTAL-0630', 400,
                     'A profile photo is a JPEG or a PNG file, and this one ' +
                     'could not be read to its end.');
    }
    log.debug("Leaving ProfilePhoto.checked().");
    return { ok: true, bytes: kept, type: seen.type, width: seen.width,
             height: seen.height };
  }

  // -------------------------------------------------------------------------
  // THE RECORD ON THE ENTRY.
  // -------------------------------------------------------------------------
  /**
   * The directory, lazily: it is loaded long after this library.
   *
   * @returns the module
   */
  static directory(): Json {
    log.debug("Entering ProfilePhoto.directory().");
    log.debug("Leaving ProfilePhoto.directory().");
    return require('../ldap/ldap_server');
  }

  /**
   * A person's record: which row is theirs, whose it was, and whether a copy
   * was declined.
   *
   * @param username - the person
   * @returns the record, `{}` for none, or null with no directory entry
   */
  static recordOf(username: string): Json {
    log.debug("Entering ProfilePhoto.recordOf().");
    const value = ProfilePhoto.directory().readProfilePhoto(username);
    if (value === null) {
      log.debug("Leaving ProfilePhoto.recordOf(). No entry.");
      return null;
    }
    log.debug("Leaving ProfilePhoto.recordOf().");
    return ProfilePhoto.parsed(value);
  }

  /**
   * One stored attribute value as a record.
   *
   * @param value - the JSON text, or nothing
   * @returns the record, `{}` for none or for a value that does not parse
   */
  static parsed(value: unknown): Json {
    log.debug("Entering ProfilePhoto.parsed().");
    let out: Json = {};
    try {
      const read = value ? JSON.parse(String(value)) : {};
      out = read && typeof read === 'object' ? read : {};
    } catch (e) {
      log.debug("Caught in ProfilePhoto.parsed(): " +
                ((e && e.message) || e));
      // Written by this module alone, so this is a hand edit over LDAP, which
      // is refused; a person with an unreadable record has no photo.
    }
    log.debug("Leaving ProfilePhoto.parsed().");
    return out;
  }

  /**
   * The realm-relative path a person's own photo is drawn from, for a menu.
   *
   * Only this realm's own copy: a URL on `pictureUrl` that names somewhere
   * else is not admitted by any surface's `img-src`, and fetching one would
   * tell that party who is looking at a console.
   *
   * @param username - the person
   * @returns the path including the realm's prefix, or ''
   */
  static pathFor(username: string): string {
    log.debug("Entering ProfilePhoto.pathFor().");
    let out = '';
    try {
      const record = username ? ProfilePhoto.recordOf(username) : null;
      if (record && record.rid) {
        out = realms.currentPrefix() + PATH_PREFIX + String(record.rid);
      }
    } catch (e) {
      log.debug("Caught in ProfilePhoto.pathFor(): " +
                ((e && e.message) || e));
      // A menu without a picture is still a menu.
    }
    log.debug("Leaving ProfilePhoto.pathFor().");
    return out;
  }

  /**
   * What the portal draws the photo card from.
   *
   * @param username - the person
   * @returns `{ path, origin, selfService, limits }`
   */
  static viewFor(username: string): Json {
    log.debug("Entering ProfilePhoto.viewFor().");
    const record = ProfilePhoto.recordOf(username) || {};
    log.debug("Leaving ProfilePhoto.viewFor().");
    return {
      path: ProfilePhoto.pathFor(username),
      origin: record.rid ? String(record.origin || '') : '',
      selfService: ProfilePhoto.setting('profilePhoto.selfService',
                                        true) === true,
      limits: ProfilePhoto.limits()
    };
  }

  // -------------------------------------------------------------------------
  // WRITING AND REMOVING.
  // -------------------------------------------------------------------------
  /**
   * The base a new address is built on, or a refusal: an address goes into a
   * token, so in product mode a `Host` header never becomes part of one.
   *
   * @param req - the request
   * @returns `{ base }`, or `{ base: '', why }`
   */
  static baseOf(req: Json): Json {
    log.debug("Entering ProfilePhoto.baseOf().");
    const pinned = !!helpers.pinnedBaseUrl('');
    if (!pinned && !mode.mintsPhotoAddressesOnRequestAddress()) {
      log.debug("Leaving ProfilePhoto.baseOf(). Not pinned.");
      return { base: '', why: 'this realm\'s public base URL is not pinned: ' +
                              'set global.publicBaseUrl first, so that no ' +
                              'Host header becomes part of an address a ' +
                              'token carries.' };
    }
    log.debug("Leaving ProfilePhoto.baseOf().");
    return { base: helpers.baseUrlOf(req, '') };
  }

  /**
   * Keeps a checked image as a person's photo: a new row under a new address,
   * the record and `pictureUrl` on the entry, then the old row gone.
   *
   * @param username - the person
   * @param checked - what `checked()` answered
   * @param base - the base the address is built on
   * @param extra - the record's other members: `origin` and, for a copy,
   *   `source`, `relationship` and `fetchedAt`
   * @returns `{ ok, path }`, or a refusal
   */
  static store(username: string, checked: Json, base: string,
               extra: Json): Json {
    log.debug("Entering ProfilePhoto.store().");
    const before = ProfilePhoto.recordOf(username);
    if (before === null) {
      log.debug("Leaving ProfilePhoto.store(). No entry.");
      return { ok: false, code: 'STS-PORTAL-0633', status: 404,
               error: 'There is no directory entry for this person in this ' +
                      'realm.' };
    }
    const rid = cellLocator.stamp(stsCrypto.randomToken(RID_BITS));
    const data = checked.bytes.toString('base64');
    images.set(rid, {
      type: checked.type,
      data: data,
      sha256: stsCrypto.sha256Hex(checked.bytes),
      width: checked.width,
      height: checked.height,
      bytes: checked.bytes.length,
      sub: String(helpers.subjectForName(username) || ''),
      updatedAt: Date.now()
    });
    const record = Object.assign({ rid: rid, updatedAt: Date.now() }, extra);
    const written = ProfilePhoto.directory().writeProfilePhoto(username,
      JSON.stringify(record), base + PATH_PREFIX + rid);
    if (!written) {
      images.delete(rid);
      log.debug("Leaving ProfilePhoto.store(). Not written.");
      return { ok: false, code: 'STS-PORTAL-0633', status: 404,
               error: 'The directory did not take the photo.' };
    }
    if (before.rid) {
      images.delete(String(before.rid));
    }
    log.debug("Leaving ProfilePhoto.store().");
    return { ok: true, path: realms.currentPrefix() + PATH_PREFIX + rid };
  }

  /**
   * A person setting their own photo on the portal.
   *
   * @param req - the request
   * @param username - the person, from the token
   * @param bytes - the file
   * @returns `{ ok, path }`, or `{ ok: false, code, status, error }`
   */
  static setOwn(req: Json, username: string, bytes: Buffer): Json {
    log.debug("Entering ProfilePhoto.setOwn().");
    if (ProfilePhoto.setting('profilePhoto.selfService', true) !== true) {
      log.debug("Leaving ProfilePhoto.setOwn(). Off.");
      return { ok: false, code: 'STS-PORTAL-0634', status: 403,
               error: 'This realm does not let people set their own photo.' };
    }
    const limits = ProfilePhoto.limits();
    const checked = ProfilePhoto.checked(bytes, limits.minPixels);
    if (!checked.ok) {
      log.debug("Leaving ProfilePhoto.setOwn(). " + checked.code);
      return checked;
    }
    const base = ProfilePhoto.baseOf(req);
    if (!base.base) {
      log.debug("Leaving ProfilePhoto.setOwn(). No base.");
      return { ok: false, code: 'STS-PORTAL-0635', status: 409,
               error: 'The photo was not saved: ' + base.why };
    }
    const out = ProfilePhoto.store(username, checked, base.base,
                                   { origin: ORIGINS.PERSON });
    log.debug("Leaving ProfilePhoto.setOwn().");
    return out;
  }

  /**
   * A person removing their photo. A copy from a partner is remembered as
   * declined, so that the next sign-in through that partner does not put it
   * back; setting one of their own later clears that.
   *
   * @param username - the person, from the token
   * @returns `{ ok, removed }`
   */
  static removeOwn(username: string): Json {
    log.debug("Entering ProfilePhoto.removeOwn().");
    const before = ProfilePhoto.recordOf(username);
    if (!before || !before.rid) {
      log.debug("Leaving ProfilePhoto.removeOwn(). None.");
      return { ok: true, removed: false };
    }
    const declined = before.origin === ORIGINS.FEDERATION
      ? JSON.stringify({ declined: true }) : '';
    ProfilePhoto.directory().writeProfilePhoto(username, declined, '');
    images.delete(String(before.rid));
    log.debug("Leaving ProfilePhoto.removeOwn().");
    return { ok: true, removed: true };
  }

  /**
   * Removes the row of a directory entry being deleted. The directory calls
   * this from the deletion's own bookkeeping, with what the entry held.
   *
   * @param values - the entry's `stsProfilePhoto` values
   */
  static forgetEntry(values: unknown): void {
    log.debug("Entering ProfilePhoto.forgetEntry().");
    const record = ProfilePhoto.parsed(([] as unknown[]).concat(
      (values as unknown[]) || [])[0]);
    if (record.rid) {
      images.delete(String(record.rid));
    }
    log.debug("Leaving ProfilePhoto.forgetEntry().");
  }

  // -------------------------------------------------------------------------
  // MOVING BETWEEN CELLS. The row is cell-tier, so it travels with the entry,
  // inside the attribute value on the way. The id's tag names the cell that
  // minted it and a request is relayed there, so a moved photo needs a NEW
  // address: moving in mints one and `pictureUrl` follows. A token already
  // issued names the old address, which answers 404 once the old entry and
  // its row are gone.
  // -------------------------------------------------------------------------
  /**
   * The entry's attribute value with the image inside it, for the transfer.
   *
   * @param values - the entry's `stsProfilePhoto` values
   * @returns the values to send
   */
  static movingOut(values: unknown): string[] {
    log.debug("Entering ProfilePhoto.movingOut().");
    const list = ([] as unknown[]).concat((values as unknown[]) || []);
    const record = ProfilePhoto.parsed(list[0]);
    const row = record.rid ? images.get(String(record.rid)) : null;
    if (!row) {
      log.debug("Leaving ProfilePhoto.movingOut(). No row.");
      return list.map(String);
    }
    log.debug("Leaving ProfilePhoto.movingOut().");
    return [JSON.stringify(Object.assign({}, record, { image: row }))];
  }

  /**
   * Keeps an image that arrived with a moved entry, under an id of this cell.
   *
   * @param values - the values `movingOut()` sent
   * @param pictureUrl - the address the entry arrived with
   * @returns `{ values, pictureUrl }`; `pictureUrl` empty when no image came
   */
  static movingIn(values: unknown, pictureUrl: string): Json {
    log.debug("Entering ProfilePhoto.movingIn().");
    const list = ([] as unknown[]).concat((values as unknown[]) || []);
    const record = ProfilePhoto.parsed(list[0]);
    if (!record.image) {
      log.debug("Leaving ProfilePhoto.movingIn(). No image.");
      return { values: list.map(String), pictureUrl: '' };
    }
    const rid = cellLocator.stamp(stsCrypto.randomToken(RID_BITS));
    images.set(rid, record.image);
    const kept = Object.assign({}, record, { rid: rid });
    delete kept.image;
    log.debug("Leaving ProfilePhoto.movingIn().");
    return { values: [JSON.stringify(kept)],
             pictureUrl: String(pictureUrl || '').replace(String(record.rid),
                                                           rid) };
  }

  // -------------------------------------------------------------------------
  // THE PARTNER'S COPY.
  // -------------------------------------------------------------------------
  /**
   * Whether a federated sign-in should dial this address now.
   *
   * @param record - the person's record
   * @param source - the partner's address
   * @param now - the instant
   * @returns the reason not to, or ''
   */
  static copyDeclined(record: Json, source: string, now: number): string {
    log.debug("Entering ProfilePhoto.copyDeclined().");
    let why = '';
    if (!record) {
      why = 'no entry';
    } else if (record.declined) {
      why = 'the person removed a copy';
    } else if (record.rid && record.origin !== ORIGINS.FEDERATION) {
      why = 'the person set their own';
    } else if (record.rid && record.source === source &&
               now - Number(record.fetchedAt || 0) < REFETCH_MS) {
      why = 'this address was copied recently';
    }
    log.debug("Leaving ProfilePhoto.copyDeclined(). " + (why || 'dial'));
    return why;
  }

  /**
   * Copies a partner's photo after a federated sign-in. Never awaited by the
   * sign-in, and it never rejects: a photo is not a reason for a sign-in to
   * fail or to wait, and the next sign-in tries again.
   *
   * @param req - the request, for the base URL
   * @param username - the person
   * @param source - the partner's `picture`, already on `pictureUrl`
   * @param relationship - the relationship's id
   * @returns a promise of what happened, for a test
   */
  static async noteFederated(req: Json, username: string, source: string,
                             relationship: string): Promise<Json> {
    log.debug("Entering ProfilePhoto.noteFederated().");
    const realm = realms.currentId();
    const flight = realm + ' ' + username;
    const outcome = async function (): Promise<Json> {
      log.debug("Entering outcome().");
      if (ProfilePhoto.setting('profilePhoto.cacheFederated', true) !== true) {
        log.debug("Leaving outcome(). Off.");
        return { copied: false, why: 'off' };
      }
      const declined = ProfilePhoto.copyDeclined(
        ProfilePhoto.recordOf(username), source, Date.now());
      if (declined) {
        log.debug("Leaving outcome(). " + declined);
        return { copied: false, why: declined };
      }
      const base = ProfilePhoto.baseOf(req);
      if (!base.base) {
        log.warn(errorCodes.tag('STS-FED-0220') + 'profile photo: not copied ' +
                 'through ' + relationship + ': ' + base.why);
        log.debug("Leaving outcome(). No base.");
        return { copied: false, why: 'not pinned' };
      }
      const limits = ProfilePhoto.limits();
      const fetched = await require('../federation/federation_http')
        .fetchPublished(source, { accept: 'image/jpeg, image/png',
                                  timeoutMs: FETCH_TIMEOUT_MS,
                                  maxBytes: limits.maxStoredBytes });
      if (!fetched.ok) {
        log.info(errorCodes.tag('STS-FED-0219') + 'profile photo: not copied ' +
                 'through ' + relationship + ': ' + fetched.why);
        log.debug("Leaving outcome(). Not fetched.");
        return { copied: false, why: fetched.kind || 'fetch' };
      }
      const scanned = await require('./malware_scan').refusal(fetched.body);
      if (scanned) {
        log.debug("Leaving outcome(). Refused by the scanner.");
        return { copied: false, why: scanned.code };
      }
      const checked = ProfilePhoto.checked(fetched.body, SMALLEST_COPY);
      if (!checked.ok) {
        log.info(errorCodes.tag('STS-FED-0221') + 'profile photo: not copied ' +
                 'through ' + relationship + ': ' + checked.error);
        log.debug("Leaving outcome(). Refused.");
        return { copied: false, why: checked.code };
      }
      // Asked again across the dial: the person may have set their own while
      // this was waiting, and that wins.
      if (ProfilePhoto.copyDeclined(ProfilePhoto.recordOf(username), source,
                                    Date.now())) {
        log.debug("Leaving outcome(). Overtaken.");
        return { copied: false, why: 'overtaken' };
      }
      const stored = ProfilePhoto.store(username, checked, base.base, {
        origin: ORIGINS.FEDERATION,
        source: source,
        relationship: relationship,
        fetchedAt: Date.now()
      });
      log.debug("Leaving outcome().");
      return { copied: !!stored.ok, path: stored.path || '' };
    };
    if (inFlight.has(flight)) {
      log.debug("Leaving ProfilePhoto.noteFederated(). In flight.");
      return { copied: false, why: 'in flight' };
    }
    inFlight.add(flight);
    try {
      const out = await outcome();
      log.debug("Leaving ProfilePhoto.noteFederated().");
      return out;
    } catch (e) {
      log.warn(errorCodes.tag('STS-FED-0219') + 'profile photo: not copied ' +
               'through ' + relationship + ': ' + ((e && e.message) || e));
      log.debug("Leaving ProfilePhoto.noteFederated(). Failed.");
      return { copied: false, why: 'failed' };
    } finally {
      inFlight.delete(flight);
    }
  }

  // -------------------------------------------------------------------------
  // SERVING.
  // -------------------------------------------------------------------------
  /**
   * The row to answer with, or null where this address answers nothing: no
   * such row, a person who is gone, or a disabled account.
   *
   * @param rid - the address's id
   * @returns the row, or null
   */
  static servable(rid: string): Json {
    log.debug("Entering ProfilePhoto.servable().");
    const row = images.get(String(rid));
    if (!row) {
      log.debug("Leaving ProfilePhoto.servable(). No row.");
      return null;
    }
    const username = String(helpers.nameForSubject(String(row.sub || '')) ||
                            '');
    if (!username ||
        require('./account_state').isDisabled(username)) {
      log.debug("Leaving ProfilePhoto.servable(). Nobody to show.");
      return null;
    }
    log.debug("Leaving ProfilePhoto.servable().");
    return row;
  }

  /**
   * Registers `GET /web/photo/{rid}`.
   *
   * @param app - the express app
   */
  static registerRoutes(app: Json): void {
    log.debug("Entering ProfilePhoto.registerRoutes().");
    app.get(ROUTE, function (req: Json, res: Json): void {
      log.debug("Entering GET " + ROUTE + ".");
      const row = ProfilePhoto.servable(String(req.params.id || ''));
      if (!row) {
        errorCodes.mark(res, 'STS-PORTAL-0636');
        res.status(404).type('text/plain').set('Cache-Control', 'no-store')
           .send('There is no photo at this address.');
        log.debug("Leaving GET " + ROUTE + ". None.");
        return;
      }
      const etag = '"' + String(row.sha256).slice(0, 32) + '"';
      // Short, because a disabled account has to stop answering: the ETag
      // keeps what this costs a browser to a revalidation.
      res.set('ETag', etag)
         .set('X-Content-Type-Options', 'nosniff')
         .set('Content-Security-Policy',
              require('./app').contentSecurityPolicy(SERVED_POLICY))
         .set('Cross-Origin-Resource-Policy', 'cross-origin')
         .set('Cache-Control', 'public, max-age=300');
      if (req.headers && req.headers['if-none-match'] === etag) {
        res.status(304).end();
        log.debug("Leaving GET " + ROUTE + ". Not modified.");
        return;
      }
      res.status(200).type(String(row.type))
         .send(Buffer.from(String(row.data), 'base64'));
      log.debug("Leaving GET " + ROUTE + ".");
    });
    log.debug("Leaving ProfilePhoto.registerRoutes().");
  }
}

export = ProfilePhoto;
