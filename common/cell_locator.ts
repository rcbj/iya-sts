// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: cell_locator.ts
//
// ---------------------------------------------------------------------------
// WHICH CELL MINTED AN ARTIFACT (#98 D10, 2026-09-28).
//
// A code, a request_uri, a device code, a token's `jti` or a SAML artifact is
// minted in the cell that ran the flow — and very often presented at another:
// a relying party's server resolves the public name to the cell nearest IT,
// not to the one nearest the browser. The receiving cell has to find the
// minting cell without a round trip anywhere, and without anything a client
// can read saying where that is.
//
// **THE LOCATOR IS A KEYED TAG, APPENDED.** `stamp(value)` appends twelve
// base64url characters — the first 72 bits of an HMAC of the minting cell's
// id under the service key-encryption key, which every cell holds and nobody
// else does (`keystore.keyedDigest()`). `locate(value)` tries each cell's tag
// against the end of the value. Three properties follow, each the reason for
// the shape:
//
//   * **Nothing readable names a cell.** Without the key a tag is noise; the
//     one thing an outsider can see is that two artifacts share a suffix,
//     which says they came from the same place and not which place.
//   * **No separator.** The stamped value is still base64url of the length a
//     validation rule already allows (plus twelve), so no pattern anywhere in
//     the service has to learn a new character. A random value that happens
//     to end in a cell's tag is a 2^-72 event per cell.
//   * **Single-cell mode stamps nothing**, and `locate()` answers ''.
//
// A tag is cached per cell id: the key does not change while a process runs.
//
// **A FIXED-LAYOUT ARTIFACT CANNOT BE APPENDED TO**, and SAML's are fixed: a
// SAML 2.0 artifact is TypeCode, EndpointIndex, a 20-byte SourceID and a
// 20-byte MessageHandle (saml-bindings-2.0-os section 3.6.4), a SAML 1.1 one
// TypeCode, SourceID and a 20-byte AssertionHandle (saml-bindings-1.1 section
// 3.2.2) — a service provider decodes both by length and reads SourceID to
// find the issuer, so a byte added anywhere breaks it and SourceID cannot
// carry anything. So the tag goes INSIDE the handle: `stampBytes()` overwrites
// its last bytes with the first bytes of the cell's tag, and `locateBytes()`
// reads them back. The handle keeps SIXTEEN random bytes, which is the floor
// section 3.6.4 sets for a MessageHandle, so the tag there is FOUR bytes.
//
// **FOUR BYTES IS A WEAKER TAG, AND WHAT IT IS WEAKER AT IS SAID HERE.** In
// multi-cell mode every artifact is stamped, so reading one back is a lookup
// among a handful of cells' tags, not a search for a needle among randoms.
// Two things can go wrong, and neither sends an artifact to a cell that then
// answers for it wrongly: (1) two cells' 32-bit tags may COLLIDE — about
// k^2/2^33 for k cells, fixed for a given key and set of ids — and then
// `locateBytes()` names neither and warns (an artifact of either is served
// where it lands, and refused there as unknown unless that is its cell);
// (2) a handle nobody stamped — a forgery, or one minted before the service
// became multi-cell — ends in some cell's tag with probability k/2^32, and is
// relayed to that cell, which refuses it as it would have refused it here.
//
// A LIBRARY: no route. The keystore is required lazily, because this module
// is reached from `app.js`'s placement middleware, above everything.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import cells = require('./cells');
import errorCodes = require('./error_codes');

const log = bunyan.createLogger({ name: 'sts-cell-locator' });

// Twelve base64url characters: 72 bits of the HMAC.
const TAG_LENGTH = 12;
// The tag inside a SAML artifact's 20-byte handle: four bytes, leaving the
// sixteen random ones saml-bindings-2.0-os section 3.6.4 asks for.
const SAML_HANDLE_TAG_BYTES = 4;

// What the locator reads of the cell map; a test hands in a stub.
interface LocatorCells {
  isMulti(): boolean;
  id(): string;
  all(): Array<{ id: string }>;
}

/**
 * Stamps and reads the keyed tag that says which cell minted an artifact.
 */
class CellLocator {
  private readonly tags = new Map<string, string>();
  private readonly cellMap: LocatorCells;
  private readonly keyedDigest: (label: string, text: string) => string | null;

  /**
   * Builds the locator. It holds no tag until one is asked for.
   *
   * @param deps - the cell map and the keyed digest; the module's own when
   *   absent (a test hands in both)
   */
  constructor(deps?: { cells?: LocatorCells;
                       digest?: (label: string, text: string) =>
                         string | null }) {
    log.debug("Entering CellLocator.constructor().");
    this.cellMap = (deps && deps.cells) || cells;
    this.keyedDigest = (deps && deps.digest) || function (label, text) {
      return require('./keystore').keyedDigest(label, text);
    };
    log.debug("Leaving CellLocator.constructor().");
  }

  /**
   * The tag of one cell, or '' where there is no key to make it with.
   *
   * @param cellId - the cell
   * @returns twelve base64url characters, or ''
   */
  tagOf(cellId: string): string {
    log.debug("Entering CellLocator.tagOf().");
    const id = String(cellId || '');
    const held = this.tags.get(id);
    if (held) {
      log.debug("Leaving CellLocator.tagOf(). Cached.");
      return held;
    }
    const digest = this.keyedDigest('cell-locator', id);
    if (!digest) {
      log.debug("Leaving CellLocator.tagOf(). No key.");
      return '';
    }
    const tag = String(digest).slice(0, TAG_LENGTH);
    this.tags.set(id, tag);
    log.debug("Leaving CellLocator.tagOf().");
    return tag;
  }

  /**
   * Appends this cell's tag to a freshly minted value. In single-cell mode,
   * or with no key, the value is returned as it is.
   *
   * @param value - the minted value (base64url)
   * @returns the stamped value
   */
  stamp(value: string): string {
    log.debug("Entering CellLocator.stamp().");
    if (!this.cellMap.isMulti()) {
      log.debug("Leaving CellLocator.stamp(). Single-cell.");
      return String(value);
    }
    const tag = this.tagOf(this.cellMap.id());
    log.debug("Leaving CellLocator.stamp().");
    return String(value) + tag;
  }

  /**
   * Finds the cell that minted a value.
   *
   * @param value - a value `stamp()` may have produced
   * @returns the cell id, or '' when it carries no known cell's tag (or in
   *   single-cell mode)
   */
  locate(value: string): string {
    log.debug("Entering CellLocator.locate().");
    const text = String(value || '');
    if (!this.cellMap.isMulti() || text.length <= TAG_LENGTH) {
      log.debug("Leaving CellLocator.locate(). Nothing to read.");
      return '';
    }
    const tail = text.slice(-TAG_LENGTH);
    const found = this.cellMap.all().filter((one) =>
      this.tagOf(one.id) === tail)[0];
    log.debug("Leaving CellLocator.locate(). " +
              (found ? found.id : 'none'));
    return found ? found.id : '';
  }

  /**
   * Tells whether a value was minted in ANOTHER cell, and which.
   *
   * @param value - a value `stamp()` may have produced
   * @returns the other cell's id, or '' when it is this cell's, unstamped,
   *   or the service is single-cell
   */
  elsewhere(value: string): string {
    log.debug("Entering CellLocator.elsewhere().");
    const at = this.locate(value);
    log.debug("Leaving CellLocator.elsewhere().");
    return at && at !== this.cellMap.id() ? at : '';
  }

  /**
   * The first `n` bytes of a cell's tag, for a fixed-layout artifact.
   *
   * @param cellId - the cell
   * @param n - how many bytes, at most the tag's nine
   * @returns the bytes, or an empty Buffer where there is no key
   */
  tagBytes(cellId: string, n: number): Buffer {
    log.debug("Entering CellLocator.tagBytes().");
    const tag = this.tagOf(cellId);
    const bytes = tag ? Buffer.from(tag, 'base64url') : Buffer.alloc(0);
    log.debug("Leaving CellLocator.tagBytes().");
    return bytes.length >= n ? bytes.subarray(0, n) : Buffer.alloc(0);
  }

  /**
   * Stamps this cell's tag into the last `n` bytes of a fixed-length random
   * handle. In single-cell mode, or with no key, the handle is returned as
   * it is.
   *
   * @param handle - the random handle
   * @param n - how many of its bytes carry the tag
   * @returns a stamped copy of the handle, or the handle itself
   */
  stampBytes(handle: Buffer, n: number): Buffer {
    log.debug("Entering CellLocator.stampBytes().");
    if (!this.cellMap.isMulti() || handle.length <= n) {
      log.debug("Leaving CellLocator.stampBytes(). Single-cell.");
      return handle;
    }
    const tag = this.tagBytes(this.cellMap.id(), n);
    if (tag.length !== n) {
      log.debug("Leaving CellLocator.stampBytes(). No key.");
      return handle;
    }
    const out = Buffer.from(handle);
    tag.copy(out, out.length - n);
    log.debug("Leaving CellLocator.stampBytes().");
    return out;
  }

  /**
   * Finds the cell that stamped a fixed-length handle.
   *
   * @param handle - a handle `stampBytes()` may have produced
   * @param n - how many of its bytes carry the tag
   * @returns the cell id, or '' when no cell's tag ends it, when two cells'
   *   short tags collide, or in single-cell mode
   */
  locateBytes(handle: Buffer, n: number): string {
    log.debug("Entering CellLocator.locateBytes().");
    if (!this.cellMap.isMulti() || !handle || handle.length <= n) {
      log.debug("Leaving CellLocator.locateBytes(). Nothing to read.");
      return '';
    }
    const tail = handle.subarray(handle.length - n);
    const found = this.cellMap.all().filter((one) => {
      const tag = this.tagBytes(one.id, n);
      return tag.length === n && tag.equals(tail);
    });
    if (found.length > 1) {
      log.warn(errorCodes.tag('STS-CELL-0120') + 'cells: the ' + n +
               '-byte tags of cells ' + found.map(function (one) {
                 return '"' + one.id + '"';
               }).join(' and ') + ' collide, so a fixed-layout artifact ' +
               'naming them is served where it arrives.');
      log.debug("Leaving CellLocator.locateBytes(). Ambiguous.");
      return '';
    }
    log.debug("Leaving CellLocator.locateBytes(). " +
              (found.length ? found[0].id : 'none'));
    return found.length ? found[0].id : '';
  }

  /**
   * Tells whether a fixed-length handle was stamped by ANOTHER cell, and
   * which.
   *
   * @param handle - a handle `stampBytes()` may have produced
   * @param n - how many of its bytes carry the tag
   * @returns the other cell's id, or '' when it is this cell's, unknown,
   *   ambiguous, or the service is single-cell
   */
  elsewhereBytes(handle: Buffer, n: number): string {
    log.debug("Entering CellLocator.elsewhereBytes().");
    const at = this.locateBytes(handle, n);
    log.debug("Leaving CellLocator.elsewhereBytes().");
    return at && at !== this.cellMap.id() ? at : '';
  }

  /**
   * Forgets the cached tags; for the tests, which change the key.
   */
  reset(): void {
    log.debug("Entering CellLocator.reset().");
    this.tags.clear();
    log.debug("Leaving CellLocator.reset().");
  }
}

const locator = new CellLocator();

/**
 * Which cell minted an artifact (#98 D10): a keyed tag appended when it is
 * minted and read when it is presented. A library: no route.
 * @namespace
 */
export = {
  CellLocator: CellLocator,
  TAG_LENGTH: TAG_LENGTH,
  SAML_HANDLE_TAG_BYTES: SAML_HANDLE_TAG_BYTES,
  tagOf: (cellId: string): string => locator.tagOf(cellId),
  stamp: (value: string): string => locator.stamp(value),
  locate: (value: string): string => locator.locate(value),
  elsewhere: (value: string): string => locator.elsewhere(value),
  tagBytes: (cellId: string, n: number): Buffer => locator.tagBytes(cellId, n),
  stampBytes: (handle: Buffer, n: number): Buffer =>
    locator.stampBytes(handle, n),
  locateBytes: (handle: Buffer, n: number): string =>
    locator.locateBytes(handle, n),
  elsewhereBytes: (handle: Buffer, n: number): string =>
    locator.elsewhereBytes(handle, n),
  reset: (): void => locator.reset()
};
