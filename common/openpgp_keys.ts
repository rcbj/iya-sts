// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: openpgp_keys.ts
//
// ===========================================================================
// A PERSON'S OpenPGP KEY, ITS WEB KEY DIRECTORY ENTRY, AND HOW THEIR MAIL IS
// ENCRYPTED (#1955 P6, design S5).
//
// Three things, each a fact about a person kept on their entry:
//
//   1. **THEIR OpenPGP PUBLIC KEY, REGISTERED WITH PROOF OF POSSESSION.** The
//      portal (`/account-api/openpgp`) or an administrator (`/admin-api/
//      users/openpgp`) asks for a CHALLENGE: a few lines naming the realm, the
//      account, the address and a random nonce, kept for the person for
//      `openpgp.challengeLifetimeS`. The person signs it with `gpg
//      --clearsign` — on a YubiKey's OpenPGP card the card signs — and pastes
//      the signed text and their public key. The key must read as one public
//      key, be neither revoked nor expired, use an algorithm the allow list
//      takes (`common/crypto.js` section 19), carry a valid user id whose
//      address IS the entry's `mail`, and have made the signature, over the
//      challenge's exact text, by a signing-capable key of it, after the
//      challenge was issued. Then it is stored: `stsOpenPgpKey` (armored),
//      `stsOpenPgpFingerprint`, `stsOpenPgpKeyInfo` (what the page draws).
//      One key per person; a new one replaces it, after its own proof.
//   2. **ITS PUBLICATION IN THE WEB KEY DIRECTORY** (draft-koch-openpgp-
//      webkey-service), only for a person who opted in on the portal and
//      only where the realm turned it on (`openpgp.wkd`, off by default):
//      the advanced method `https://openpgpkey.<domain>/.well-known/
//      openpgpkey/<domain>/hu/<hash>?l=<local>` and the direct method
//      `https://<domain>/.well-known/openpgpkey/hu/<hash>`, and the `policy`
//      file of each. `registerRoutes()` registers them.
//   3. **HOW MAIL TO THEM IS ENCRYPTED** — `stsMailEncryption`: `none`,
//      `openpgp` (PGP/MIME to the key above) or `smime` (S/MIME to their
//      `userSMIMECertificate`), chosen on the portal. `common/mail.ts` asks
//      `encryptionFor()` at queue time; `common/mail_transports.ts` builds
//      the encrypted message at send time.
//
//   4. **A KEY BELONGS TO THE ADDRESSES ITS USER IDS NAME.** Registration
//      records them (`stsOpenPgpKeyInfo.addresses`); mail is encrypted to
//      the key, and the Web Key Directory answers it, only for an address
//      one of them names (`keyNames()`). When the entry's `mail` changes
//      to an address the key does not name, `addressChanged()` — called by
//      `ldap/ldap_server.js` after the write — retires the key.
//
// **NOTHING HERE IS RECORDED AS HARDWARE-BOUND.** The server cannot see an
// OpenPGP card: a signature made on a YubiKey and one made by a key in a
// file are the same bytes, and no OpenPGP card attestation is carried by
// `gpg --clearsign`. So no `openpgp` credential is put on a hardware token
// record (`common/hardware_tokens.ts`) by this module; a later phase that
// verifies a YubiKey's OpenPGP attestation (`ykman openpgp keys attest`) is
// the one that may, through `recordAttested()`. What this module does
// install now is the RETIRER for that kind (`registerRetirer('openpgp')`):
// when a token holding a person's OpenPGP key is reported lost, the key is
// removed from their entry and so from the Web Key Directory, and mail to
// them is no longer encrypted to it.
//
// **THE CHALLENGE STORE IS PER REALM AT ITS DECLARATION**, persisted where
// this service persists what it mints (a request worker may issue it and
// another verify it), keyed by the person's entryUUID so a person has one
// outstanding challenge and a rename changes nothing. **SPENT ONCE**: a
// cluster claim on the nonce (`cluster/cluster_claims.js`) before anything
// is written, so two workers handed the same signed text cannot both
// register it.
//
// **THE PUBLICATION REGISTER** (`openpgp.wkd`) is per realm too: `<domain>/
// <hash>` to the holder's entryUUID and the published fingerprint, on
// demand with a bound, so a lookup is one keyed read. It is a pointer: the
// answer is read from the ENTRY, and only when the entry's `mail` still
// hashes to the asked name, the person still opts in and the stored
// fingerprint is the one published. **A minted store is not kept across a
// restart in development mode** (`persistence/CLAUDE.md`), so there the
// lookup also accepts the draft's `l` parameter (which GnuPG sends): the
// address it names is looked up by `mail` and checked against the hash.
//
// **WHICH REALM ANSWERS A WKD REQUEST.** A WKD client knows a mail domain,
// never a realm path, so a request with no realm segment is answered by the
// realm that serves the domain — the one whose `openpgp.wkdDomains` names it,
// or, when that list is empty, whose own DNS domain it is
// (`realms.domainOf()`) — the default realm first, then the others in id
// order. A request under `/realm/<id>/` asks that realm only. The direct
// method's domain is the request's Host header: it only chooses whose
// directory is asked, and the answer is a public key the person published.
//
// **CORS FOLLOWS THIS SERVICE'S RULE, NOT THE DRAFT'S `*`.** The draft says
// a server SHOULD send `Access-Control-Allow-Origin: *` so a web mail client
// can read a key. rcbj's CORS decision (`common/CLAUDE.md`, `cors.js`) is an
// allowlist on every path and no wildcard, and a WKD answer names no client,
// so it is the realm's union of `appCorsOrigin` like discovery and JWKS: a
// deployment that runs a web mail client lists its origin on that client's
// application. Desktop clients (GnuPG, Thunderbird) do not use CORS at all.
// The route sets no CORS header of its own, which `cors.js` forbids.
//
// **A KEY DOCUMENT IS SERVED `Cache-Control: no-store`** (the root
// CLAUDE.md's rule), the answer `application/octet-stream` as the draft says,
// and the `policy` file `text/plain`, empty: this service supports no Web Key
// Service submission, so there is no `submission-address` file.
//
// A route module (rule 1): `registerRoutes(app)`, called by
// `common/protocol_stack.ts`. It requires `helpers`, `config`, `realms`,
// `audit`, `error_codes`, `crypto`, `domain_classes`, `cache_registry`,
// `cluster/cluster_claims` and `hardware_tokens` — libraries all — and
// reaches the directory through `setDirectory()`, filled by
// `ldap/ldap_server.js` (rule 3e: `common/mail.ts` asks this module at 8a,
// long before the directory loads at 21, and a require of it from here
// would load the JavaScript directory module and its routes out of order).
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import realms = require('./realms');
import config = require('./config');
import audit = require('./audit');
import errorCodes = require('./error_codes');
import stsCrypto = require('./crypto');
import Classes = require('./domain_classes');
import cacheRegistry = require('./cache_registry');
import clusterClaims = require('../cluster/cluster_claims');
import hardwareTokens = require('./hardware_tokens');
import entryObserver = require('./entry_observer');

type Json = any;

/** What `stsMailEncryption` may be. */
const MAIL_ENCRYPTION = ['none', 'openpgp', 'smime'];

/** The attributes this module writes, and the only ones its slot writes. */
const ATTRIBUTES = {
  key: 'stsOpenPgpKey',
  fingerprint: 'stsOpenPgpFingerprint',
  info: 'stsOpenPgpKeyInfo',
  mailEncryption: 'stsMailEncryption',
  // RFC 4522's transfer form, as an LDAP client writes it.
  smime: 'userSMIMECertificate;binary',
  // THE CLASSICAL KEY KEPT BESIDE A POST-QUANTUM ONE (#2009 P2, rcbj's D3).
  classicalKey: 'stsOpenPgpClassicalKey',
  classicalInfo: 'stsOpenPgpClassicalKeyInfo'
};

// The claim scope a challenge's nonce is spent under.
const CHALLENGE_SCOPE = 'openpgp.challenge';

// A WKD hashed local part: 32 characters of z-base-32.
const WKD_HASH = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{32}$/;

// The first line of every challenge, so a person sees what they sign.
const CHALLENGE_TITLE = 'iya-sts OpenPGP key registration';

// The publication register's bound per realm, as the hardware token
// register's.
const PUBLISHED_MAX = 5000;

// The challenges a process holds per realm (a cache over the store, which
// holds one per person registering).
const CHALLENGES_MAX = 5000;

// ---------------------------------------------------------------------------
// THE CHALLENGES, per realm at the declaration (header). `expiresAt` in
// milliseconds, so the minted store drops a spent one by itself. On demand,
// as the publication register is, so what a process holds is bounded: one
// challenge per person is a store as large as the directory, and is read
// by its holder's key.
// ---------------------------------------------------------------------------
const challenges = realms.map({
  persist: 'openpgp.challenges',
  onDemand: { maxEntries: CHALLENGES_MAX },
  tombstone: true,
  expiresAt: realms.expiryField('expiresAt', 1)
});

// THE PUBLICATION REGISTER (header): `<domain>/<hash>` → `{ holder,
// fingerprint, publishedAt }`. On demand, so a process holds the rows it
// was asked about. `indexBy` runs on every row a flush writes, so it has no
// Entering/Leaving pair (a hot path).
const published = realms.map({
  persist: 'openpgp.wkd',
  onDemand: { maxEntries: PUBLISHED_MAX },
  indexBy: function (row: Json): string[] {
    return row && row.holder ? ['h:' + String(row.holder)] : [];
  }
});

// ---------------------------------------------------------------------------
// THE CLASSICAL KEYS KEPT, AND UNTIL WHEN (#2009 P2, rcbj's D3): entryUUID →
// `{ keptUntil, fingerprint }`, one row per person whose classical OpenPGP
// key sits beside the post-quantum key the post-login mail-encryption
// activity registered. It is what the job `post-login.mail-classical-retire`
// walks — the rows to act on and nothing else, so the job never walks the
// directory (no index answers "holds stsOpenPgpClassicalKey" without a
// scan). The entry is the truth: a row whose entry no longer holds that
// classical key is dropped, and a key past `keptUntil` is not published
// whether or not the job has run (the read-time check, `classicalKept()`).
// On demand, as the challenges are.
// ---------------------------------------------------------------------------
const classicalKept = realms.map({
  persist: 'openpgp.classicalKept',
  onDemand: { maxEntries: CHALLENGES_MAX }
});

cacheRegistry.register({
  name: 'openpgp.challenges',
  title: 'OpenPGP registration challenges',
  description: 'One challenge per person registering an OpenPGP key: the ' +
    'text they sign with gpg --clearsign, its nonce and when it lapses. ' +
    'Spent once, by a cluster claim on the nonce.',
  owner: 'common/openpgp_keys.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  settings: ['openpgp.challengeLifetimeS'],
  maxEntries: function (): number {
    return CHALLENGES_MAX;
  },
  bound: 'Enforced: the challenges a process holds are a cache of 5,000 per ' +
    'realm, the oldest dropped and read from the store again when next ' +
    'asked; the store holds one per person (keyed by entryUUID), each for ' +
    'openpgp.challengeLifetimeS.',
  lifetime: function (): string {
    return String(config.value('openpgp.challengeLifetimeS')) +
      ' seconds after it was issued, or until it is used.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, challenges,
      function (row: Json, key: unknown): object {
        return { key: String(key), expiresAt: Number((row &&
                 row.expiresAt) || 0), basis: 'expiry' };
      });
  }
});

cacheRegistry.register({
  name: 'openpgp.wkd',
  title: 'Web Key Directory publications',
  description: 'Which OpenPGP key the Web Key Directory answers for each ' +
    'hashed address: the holder (an entryUUID) and the fingerprint they ' +
    'published. A pointer: the key itself is read from the entry. Never a ' +
    'secret.',
  owner: 'common/openpgp_keys.ts',
  scope: 'realm',
  kind: 'cache',
  persisted: true,
  settings: ['openpgp.wkd'],
  maxEntries: function (): number {
    return PUBLISHED_MAX;
  },
  bound: 'Enforced: the rows a process holds are a cache of 5,000 per ' +
    'realm, the oldest dropped and read from the store again when next ' +
    'asked; the register holds one row per person who opted in.',
  lifetime: function (): string {
    return 'Until the person stops publishing or removes the key.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, published,
      function (row: Json, key: unknown): object {
        return { key: String(key), basis: 'none' };
      });
  }
});

interface DirectoryHooks {
  // A person of the ambient realm: `{ dn, username, attributes, smime }`,
  // `smime` the values of userSMIMECertificate under either spelling.
  locate: (username: string) => Json;
  // One of ATTRIBUTES' names, replaced in place; [] removes it.
  write: (dn: string, name: string, values: string[]) => boolean;
  // A person of the ambient realm by `mail`, or ''.
  personByMail: (address: string) => string;
}

let directory: DirectoryHooks | null = null;

interface OpenPgpKeysDeps {
  log: typeof helpers.log;
  helpers: typeof helpers;
  config: typeof config;
  realms: typeof realms;
  audit: typeof audit;
  errorCodes: typeof errorCodes;
  crypto: typeof stsCrypto;
  claims: typeof clusterClaims;
  now: () => number;
  directory: () => DirectoryHooks | null;
}

/**
 * A person's OpenPGP key, its Web Key Directory publication and their mail
 * encryption choice (#1955 P6).
 */
class OpenPgpKeys {
  static readonly MAIL_ENCRYPTION = MAIL_ENCRYPTION;
  static readonly ATTRIBUTES = ATTRIBUTES;
  static readonly CHALLENGE_TITLE = CHALLENGE_TITLE;

  // How many entry writes of this module's own are in progress (#2050).
  private selfWrites = 0;

  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: OpenPgpKeysDeps) {
    deps.log.debug("Entering OpenPgpKeys.constructor().");
    deps.log.debug("Leaving OpenPgpKeys.constructor().");
  }

  /**
   * The dependencies the service uses.
   *
   * @returns the dependencies
   */
  static defaultDeps(): OpenPgpKeysDeps {
    helpers.log.debug("Entering OpenPgpKeys.defaultDeps().");
    helpers.log.debug("Leaving OpenPgpKeys.defaultDeps().");
    return {
      log: helpers.log, helpers: helpers, config: config, realms: realms,
      audit: audit, errorCodes: errorCodes, crypto: stsCrypto,
      claims: clusterClaims, now: Date.now,
      directory: function (): DirectoryHooks | null {
        return directory;
      }
    };
  }

  // -------------------------------------------------------------------------
  // SMALL HELPERS.
  // -------------------------------------------------------------------------
  private refuse(code: string, why: string, extra?: Json): Json {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering OpenPgpKeys.refuse(). " + code);
    log.debug("Leaving OpenPgpKeys.refuse().");
    return codes.mark(Object.assign({ ok: false, errors: [why],
                                      error: why }, extra || {}), code);
  }

  private holderOf(username: string): string {
    const { log, helpers: h } = this.deps;
    log.debug("Entering OpenPgpKeys.holderOf().");
    const sub = String(h.subjectForName(username) || '');
    log.debug("Leaving OpenPgpKeys.holderOf().");
    return sub.indexOf('urn:uuid:') === 0 ? sub.slice(9) : '';
  }

  private nameOfHolder(holder: string): string {
    const { log, helpers: h } = this.deps;
    log.debug("Entering OpenPgpKeys.nameOfHolder().");
    const name = holder ? String(h.nameForSubject('urn:uuid:' + holder) ||
                                 '') : '';
    log.debug("Leaving OpenPgpKeys.nameOfHolder().");
    return name;
  }

  private setting(key: string): Json {
    const { log, config: c } = this.deps;
    log.debug("Entering OpenPgpKeys.setting(). " + key);
    log.debug("Leaving OpenPgpKeys.setting().");
    return c.value(key);
  }

  /**
   * An address's local part and domain, the domain lower-cased.
   *
   * @param address - the address
   * @returns `{ local, domain }`, both '' for something that is not one
   */
  static splitAddress(address: unknown): { local: string; domain: string } {
    helpers.log.debug("Entering OpenPgpKeys.splitAddress().");
    const text = String(address || '').trim();
    const at = text.lastIndexOf('@');
    if (at < 1 || at === text.length - 1) {
      helpers.log.debug("Leaving OpenPgpKeys.splitAddress(). Not one.");
      return { local: '', domain: '' };
    }
    helpers.log.debug("Leaving OpenPgpKeys.splitAddress().");
    return { local: text.slice(0, at),
             domain: text.slice(at + 1).toLowerCase() };
  }

  /**
   * One person of the ambient realm, as this module reads them: their entry,
   * their address and the stored key, its information and their choice.
   *
   * @param username - the person
   * @returns the person, or null when there is no entry or no directory
   */
  person(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.person().");
    const dir = this.deps.directory();
    const found = dir && username ? dir.locate(String(username)) : null;
    if (!found) {
      log.debug("Leaving OpenPgpKeys.person(). Nobody.");
      return null;
    }
    const attrs = found.attributes || {};
    const user = Classes.User.fromEntry(attrs);
    const credential = Classes.Credential.fromEntry(attrs);
    const record = Classes.PersonRecord.fromEntry(attrs);
    let info: Json = null;
    try {
      info = credential.openPgpKeyInfo
        ? JSON.parse(String(credential.openPgpKeyInfo)) : null;
    } catch (e) {
      log.debug("Caught in OpenPgpKeys.person(): " + ((e && e.message) || e));
      // A value written by hand that is not ours: drawn as no information,
      // and the key itself still reads.
      info = null;
    }
    const choice = String(record.mailEncryption || 'none');
    // THE CLASSICAL KEY KEPT BESIDE A POST-QUANTUM ONE (#2009 P2), and what
    // is drawn about it; a value written by hand that is not ours reads as
    // none, as the key information above does.
    let classicalInfo: Json = null;
    try {
      classicalInfo = credential.openPgpClassicalKeyInfo
        ? JSON.parse(String(credential.openPgpClassicalKeyInfo)) : null;
    } catch (e) {
      log.debug("Caught in OpenPgpKeys.person(): " + ((e && e.message) || e));
      classicalInfo = null;
    }
    log.debug("Leaving OpenPgpKeys.person().");
    return {
      classicalKey: String(credential.openPgpClassicalKey || ''),
      classicalInfo: classicalInfo || {},
      dn: String(found.dn), username: String(found.username || username),
      mail: String(user.email || '').trim(),
      key: String(credential.openPgpKey || ''),
      fingerprint: String(credential.openPgpFingerprint || '').toLowerCase(),
      info: info || {},
      mailEncryption: MAIL_ENCRYPTION.indexOf(choice) >= 0 ? choice : 'none',
      // THROUGH THE CONCEPT (#2050): `userSMIMECertificate` is declared on
      // the person, and `Credential.smimeCertificate` reads it under either
      // RFC 4522 spelling, in the order the store's `smime` gave.
      smime: [].concat(credential.smimeCertificate || [])
    };
  }

  private write(p: Json, name: string, values: string[]): boolean {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.write(). " + name);
    const dir = this.deps.directory();
    let ok = false;
    // OUR OWN WRITE (#2050): the entry observer's handler below is told of
    // it inside the write, and ignores it.
    this.selfWrites += 1;
    try {
      ok = !!dir && dir.write(p.dn, name, values) === true;
    } finally {
      this.selfWrites -= 1;
    }
    log.debug("Leaving OpenPgpKeys.write(). " + ok);
    return ok;
  }

  /**
   * THE ENTRY OBSERVER'S HANDLER FOR `userSMIMECertificate` (#2050,
   * `common/entry_observer.ts`). The entry is the master of a person's
   * S/MIME certificates, and there is no index of them to keep; what a
   * write by another door may not do is leave a value that holds no
   * certificate, which mail to them would then be encrypted to nothing
   * with. Such a value is taken off again and audited (STS-OPENPGP-0034).
   *
   * @param change - the observer's change
   * @returns how many values were taken off
   */
  entryChanged(change: Json): number {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.entryChanged().");
    const c = change || {};
    if (this.selfWrites > 0 || c.deleted) {
      log.debug("Leaving OpenPgpKeys.entryChanged(). Nothing to check.");
      return 0;
    }
    const crypto = this.deps.crypto;
    const before = (c.before || []).map(String);
    const bad = (c.after || []).map(String).filter(function (value: string) {
      if (before.indexOf(value) >= 0) {
        return false;
      }
      let held: Json[] = [];
      try {
        held = crypto.smimeCertificatesOf(value) || [];
      } catch (e) {
        log.debug("Caught in OpenPgpKeys.entryChanged(): " +
                  ((e && e.message) || e));
        held = [];
      }
      return !held.length;
    });
    if (!bad.length) {
      log.debug("Leaving OpenPgpKeys.entryChanged(). Every value reads.");
      return 0;
    }
    const kept = (c.after || []).map(String).filter(function (v: string) {
      return bad.indexOf(v) < 0;
    });
    const p = { dn: String(c.dn || '') };
    // One spelling written back, as `setSmime()` writes it, the other
    // cleared.
    const written = this.write(p, ATTRIBUTES.smime, kept) &&
      this.write(p, 'userSMIMECertificate', []);
    this.recordAudit('openpgp.smime-certificate', String(c.actor ||
      c.door || 'directory'), String(c.username || ''), bad.length +
      ' S/MIME certificate value(s) written onto the entry hold no ' +
      'certificate and were taken off', { door: String(c.door || ''),
                                          written: written },
      'refused', 'STS-OPENPGP-0034');
    log.warn(errorCodes.tag('STS-OPENPGP-0034') + 'openpgp: ' + bad.length +
             ' userSMIMECertificate value(s) on ' + c.dn + ' hold no ' +
             'certificate and were taken off.');
    log.debug("Leaving OpenPgpKeys.entryChanged(). " + bad.length);
    return bad.length;
  }

  private recordAudit(action: string, actor: string, target: string,
                      summary: string, detail: Json, outcome?: string,
                      code?: string): void {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.recordAudit(). " + action);
    this.deps.audit.audit(Object.assign({
      action: action, actor: String(actor || ''),
      target: String(target || ''), protocol: 'OpenPGP',
      outcome: outcome || 'success', summary: summary, detail: detail || {}
    }, code ? { errorCode: code } : {}));
    log.debug("Leaving OpenPgpKeys.recordAudit().");
  }

  // -------------------------------------------------------------------------
  // WHAT A PAGE DRAWS.
  // -------------------------------------------------------------------------
  /**
   * A person's state, as the portal and the console draw it.
   *
   * @param username - the person
   * @returns the view, or a coded refusal for nobody
   */
  view(username: string): Json {
    const { log, realms: r } = this.deps;
    log.debug("Entering OpenPgpKeys.view().");
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.view(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    const info = p.info || {};
    const holder = this.holderOf(p.username);
    const held = holder ? challenges.get(holder) : null;
    const pending = held && Number(held.expiresAt) > this.deps.now()
      ? held : null;
    const split = OpenPgpKeys.splitAddress(p.mail);
    const domains = this.wkdDomains();
    const smime = p.smime.length
      ? this.deps.crypto.smimeRecipientCertificate(p.smime,
                                                   new Date(this.deps.now()))
      : null;
    const out = {
      ok: true,
      username: p.username,
      mail: p.mail,
      key: p.key ? {
        fingerprint: p.fingerprint,
        version: Number(info.version || 0),
        algorithm: String(info.algorithm || ''),
        encryption: String(info.encryption || ''),
        userIds: [].concat(info.userIds || []).map(String),
        created: String(info.created || ''),
        expiresAt: String(info.expiresAt || ''),
        registeredAt: String(info.registeredAt || ''),
        registeredVia: String(info.via || ''),
        armored: p.key
      } : null,
      // THE CLASSICAL KEY KEPT BESIDE THIS ONE (#2009 P2), until when.
      classicalKept: this.classicalKept(p),
      challenge: pending ? { text: String(pending.text),
        expiresAt: new Date(Number(pending.expiresAt)).toISOString() }
        : null,
      wkd: {
        enabled: !!this.setting('openpgp.wkd'),
        optedIn: !!info.wkd,
        published: !!(p.key && info.wkd && this.setting('openpgp.wkd') &&
                      split.domain && domains.indexOf(split.domain) >= 0 &&
                      OpenPgpKeys.keyNames(info, p.mail)),
        domainServed: !!split.domain && domains.indexOf(split.domain) >= 0,
        hash: split.local ? this.deps.crypto.wkdHash(split.local) : '',
        url: split.local && split.domain
          ? 'https://openpgpkey.' + split.domain + '/.well-known/openpgpkey/' +
            split.domain + '/hu/' + this.deps.crypto.wkdHash(split.local) +
            '?l=' + encodeURIComponent(split.local) : ''
      },
      mailEncryption: {
        choice: p.mailEncryption,
        openpgpUsable: !!(p.key && info.encryption && !this.expired(info) &&
                          OpenPgpKeys.keyNames(info, p.mail)),
        smimeUsable: !!(smime && smime.ok),
        smimeCertificate: smime && smime.ok
          ? { subject: String(smime.subject), serial: String(smime.serial) }
          : null,
        smimeProblem: smime && !smime.ok ? String(smime.error) : ''
      },
      realm: r.currentId()
    };
    log.debug("Leaving OpenPgpKeys.view().");
    return out;
  }

  /**
   * Whether a stored key's encryption key is post-quantum: one of RFC 9980's
   * ML-KEM composites (#2009 P2). A key with no encryption key is not.
   *
   * @param info - the stored key information
   * @returns true when it is
   */
  static encryptionIsPq(info: Json): boolean {
    helpers.log.debug("Entering OpenPgpKeys.encryptionIsPq().");
    const name = String((info && info.encryption) || '').trim()
      .split(' ')[0];
    const out = !!name && stsCrypto.openpgpIsPq(name);
    helpers.log.debug("Leaving OpenPgpKeys.encryptionIsPq(). " + out);
    return out;
  }

  /**
   * The classical key a person keeps beside a post-quantum one (#2009 P2,
   * rcbj's D3), while it is kept: its fingerprint, its algorithms and until
   * when. Null where there is none, or its time has passed — then it is
   * neither drawn nor published, whether or not the job has removed it yet.
   *
   * @param p - the person, as `person()` reads them
   * @returns the description, or null
   */
  classicalKept(p: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering OpenPgpKeys.classicalKept().");
    const info = (p && p.classicalInfo) || {};
    const until = Date.parse(String(info.keptUntil || ''));
    const out = p && p.classicalKey && until > now()
      ? { fingerprint: String(info.fingerprint || ''),
          algorithm: String(info.algorithm || ''),
          encryption: String(info.encryption || ''),
          replacedAt: String(info.replacedAt || ''),
          keptUntil: new Date(until).toISOString() }
      : null;
    log.debug("Leaving OpenPgpKeys.classicalKept(). " + (out ? 'Kept.'
                                                             : 'None.'));
    return out;
  }

  private expired(info: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.expired().");
    const at = Date.parse(String((info && info.expiresAt) || ''));
    log.debug("Leaving OpenPgpKeys.expired().");
    return at > 0 && at <= this.deps.now();
  }

  /**
   * The addresses a stored key is bound to: the addresses of its valid user
   * ids, as registration recorded them (`addresses`), or, for a key stored
   * before that member existed, read back from the user ids it kept.
   *
   * @param info - the stored key information
   * @returns lower-case addresses
   */
  static keyAddresses(info: Json): string[] {
    helpers.log.debug("Entering OpenPgpKeys.keyAddresses().");
    const listed = info && Array.isArray(info.addresses)
      ? info.addresses : [].concat((info && info.userIds) || [])
        .map(function (text: unknown): string {
          const t = String(text || '').trim();
          const bracketed = (t.match(/<([^<>\s]+@[^<>\s]+)>/) || [])[1];
          return bracketed || (/^[^\s<>]+@[^\s<>]+$/.test(t) ? t : '');
        });
    const out = listed.map(function (a: unknown): string {
      return String(a || '').trim().toLowerCase();
    }).filter(Boolean);
    helpers.log.debug("Leaving OpenPgpKeys.keyAddresses(). " + out.length);
    return out;
  }

  /**
   * Whether a stored key names an address in one of its valid user ids.
   *
   * @param info - the stored key information
   * @param address - the address
   * @returns true when it does
   */
  static keyNames(info: Json, address: string): boolean {
    helpers.log.debug("Entering OpenPgpKeys.keyNames().");
    const wanted = String(address || '').trim().toLowerCase();
    const out = !!wanted &&
      OpenPgpKeys.keyAddresses(info).indexOf(wanted) >= 0;
    helpers.log.debug("Leaving OpenPgpKeys.keyNames(). " + out);
    return out;
  }

  // -------------------------------------------------------------------------
  // THE CHALLENGE (header point 1).
  // -------------------------------------------------------------------------
  /**
   * Issues a person a registration challenge, replacing any earlier one.
   *
   * @param username - the person
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, challenge: { text, expiresAt }, command }`, or a coded
   *   refusal
   */
  issueChallenge(username: string, ctx: Json): Json {
    const { log, realms: r, crypto: c, now } = this.deps;
    log.debug("Entering OpenPgpKeys.issueChallenge().");
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.issueChallenge(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    if (!OpenPgpKeys.splitAddress(p.mail).domain) {
      log.debug("Leaving OpenPgpKeys.issueChallenge(). No address.");
      return this.refuse('STS-OPENPGP-0006', p.username + '\'s entry has ' +
        'no mail address, and an OpenPGP key is registered for the address ' +
        'its user id names.');
    }
    const holder = this.holderOf(p.username);
    const issuedAt = now();
    const lifetimeS = Number(this.setting('openpgp.challengeLifetimeS'));
    const nonce = c.randomBytes(24).toString('base64url');
    const text = [CHALLENGE_TITLE,
                  'Realm: ' + r.currentId(),
                  'Account: ' + p.username,
                  'Address: ' + p.mail,
                  'Nonce: ' + nonce,
                  'Issued: ' + new Date(issuedAt).toISOString()].join('\n');
    const row = { text: text, nonce: nonce, issuedAt: issuedAt,
                  expiresAt: issuedAt + lifetimeS * 1000,
                  actor: String((ctx && ctx.actor) || ''),
                  via: String((ctx && ctx.via) || '') };
    challenges.set(holder, row);
    this.recordAudit('openpgp.challenge', row.actor, p.username,
      'an OpenPGP registration challenge was issued for ' + p.username,
      { via: row.via, expiresAt: new Date(row.expiresAt).toISOString() });
    log.debug("Leaving OpenPgpKeys.issueChallenge().");
    return { ok: true, challenge: {
      text: text, expiresAt: new Date(row.expiresAt).toISOString() },
      command: 'gpg --clearsign' };
  }

  // -------------------------------------------------------------------------
  // REGISTRATION (header point 1).
  // -------------------------------------------------------------------------
  /**
   * Registers a person's OpenPGP public key, on a proof of possession of
   * their outstanding challenge.
   *
   * @param username - the person
   * @param input - `{ publicKey, signed }`
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, fingerprint, replaced }`, or a coded refusal
   */
  async register(username: string, input: Json, ctx: Json): Promise<Json> {
    const { log, crypto: c, now } = this.deps;
    log.debug("Entering OpenPgpKeys.register().");
    const actor = String((ctx && ctx.actor) || '');
    const via = String((ctx && ctx.via) || '');
    const self = this;
    const refused = function (answer: Json): Json {
      self.recordAudit('openpgp.key-refused', actor, String(username || ''),
        'an OpenPGP key was not registered for ' + String(username || '') +
        ': ' + String(answer.error || ''), { via: via }, 'refused',
        self.deps.errorCodes.codeOf(answer));
      return answer;
    };
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.register(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    if (!OpenPgpKeys.splitAddress(p.mail).domain) {
      log.debug("Leaving OpenPgpKeys.register(). No address.");
      return refused(this.refuse('STS-OPENPGP-0006', p.username + '\'s ' +
        'entry has no mail address to match the key\'s user id against.'));
    }
    const holder = this.holderOf(p.username);
    const held: Json = holder ? challenges.get(holder) : null;
    const at = now();
    if (!held || !(Number(held.expiresAt) > at)) {
      log.debug("Leaving OpenPgpKeys.register(). No challenge.");
      return refused(this.refuse('STS-OPENPGP-0012', 'There is no ' +
        'outstanding challenge for ' + p.username + ', or it lapsed: ask ' +
        'for a new one and sign it.'));
    }
    const minRsaBits = Number(this.setting('openpgp.minRsaBits'));
    // pqcOnly and alongside narrow THIS registration. Verification of the
    // proof below passes the algorithm list and not those switches, so a
    // classical key already accepted is not re-judged by them.
    const algorithms = [].concat(this.setting('openpgp.algorithms') || []);
    const pqcOnly = this.setting('openpgp.pqcOnly') === true;
    const alongside = this.setting('openpgp.pqcAlongsideClassical') === true;
    const key: Json = await c.openpgpReadKey(String((input &&
      input.publicKey) || ''), {
      at: new Date(at), minRsaBits: minRsaBits, accept: algorithms,
      registration: true, pqcOnly: pqcOnly,
      pqcAlongsideClassical: alongside });
    if (!key.ok) {
      log.debug("Leaving OpenPgpKeys.register(). The key.");
      return refused(this.refuse(this.deps.errorCodes.codeOf(key) ||
                                 'STS-OPENPGP-0001', String(key.error)));
    }
    // A POST-QUANTUM KEY, WHERE THE CALLER ASKS FOR ONE (#2009 P2: the
    // post-login mail-encryption activity): its encryption key one of RFC
    // 9980's ML-KEM composites. Asked before the proof, so a classical key
    // is refused with nothing spent and nothing written.
    if (ctx && ctx.requirePostQuantum === true &&
        !OpenPgpKeys.encryptionIsPq({ encryption: key.description.encryption
          ? OpenPgpKeys.algorithmText(key.description.encryption) : '' })) {
      log.debug("Leaving OpenPgpKeys.register(). Not post-quantum.");
      return refused(this.refuse('STS-OPENPGP-0033', 'The key\'s ' +
        'encryption key is ' + (key.description.encryption
          ? OpenPgpKeys.algorithmText(key.description.encryption)
          : 'missing') + ', not one of RFC 9980\'s ML-KEM composites ' +
        '(ML-KEM-768+X25519, ML-KEM-1024+X448).'));
    }
    const wanted = p.mail.toLowerCase();
    const matching = key.description.users.filter(function (u: Json) {
      return u.valid && String(u.email || '').toLowerCase() === wanted;
    });
    if (!matching.length) {
      log.debug("Leaving OpenPgpKeys.register(). No matching user id.");
      return refused(this.refuse('STS-OPENPGP-0005', 'No valid user id of ' +
        'the key carries ' + p.mail + ', the address on the entry (it has ' +
        (key.description.users.map(function (u: Json) {
          return u.email || u.text;
        }).join(', ') || 'none') + ').'));
    }
    const proof: Json = await c.openpgpVerifyChallenge(
      String((input && input.signed) || ''), key.key, {
        expectedText: String(held.text), issuedAt: Number(held.issuedAt),
        at: new Date(at), skewS: Number(this.setting(
          'openpgp.signatureSkewS')), minRsaBits: minRsaBits,
        accept: algorithms });
    if (!proof.ok) {
      log.debug("Leaving OpenPgpKeys.register(). The proof.");
      return refused(this.refuse(this.deps.errorCodes.codeOf(proof) ||
                                 'STS-OPENPGP-0008', String(proof.error)));
    }
    // SPENT ONCE, before anything is written (header).
    const spent: Json = await this.deps.claims.claim({
      scope: CHALLENGE_SCOPE, value: String(held.nonce),
      ttlMs: Math.max(1000, Number(held.expiresAt) - at + 60000) });
    if (!spent.ok) {
      log.debug("Leaving OpenPgpKeys.register(). Spent elsewhere.");
      return refused(this.refuse('STS-OPENPGP-0012', spent.reason === 'used'
        ? 'That challenge was already used: ask for a new one.'
        : 'The challenge could not be spent (the store did not answer); ' +
          'try again.'));
    }
    challenges.delete(holder);
    const d = key.description;
    const before = p.fingerprint;
    const info = {
      fingerprint: d.fingerprint, version: d.version,
      algorithm: OpenPgpKeys.algorithmText(d.primary),
      signing: d.signing ? OpenPgpKeys.algorithmText(d.signing) : '',
      encryption: d.encryption ? OpenPgpKeys.algorithmText(d.encryption)
                               : '',
      encryptionFingerprint: d.encryption ? d.encryption.fingerprint : '',
      userIds: matching.map(function (u: Json) {
        return String(u.text);
      }),
      // Every address a valid user id of the key names: what the key may be
      // used for (`keyNames()`), so mail and the Web Key Directory never
      // use it for an address it does not belong to.
      addresses: key.description.users.filter(function (u: Json) {
        return u.valid && u.email;
      }).map(function (u: Json) {
        return String(u.email).trim().toLowerCase();
      }).filter(function (a: string, i: number, all: string[]) {
        return all.indexOf(a) === i;
      }),
      created: d.created, expiresAt: d.expiresAt,
      registeredAt: new Date(at).toISOString(), registeredBy: actor,
      via: via,
      // The person's publication choice survives a new key; it is theirs.
      wkd: !!(p.info && p.info.wkd),
      // Nothing here is hardware-bound (header): the server cannot see a
      // card, so it says so rather than leaving a reader to wonder.
      hardware: false
    };
    const written = this.write(p, ATTRIBUTES.key, [key.armored]) &&
      this.write(p, ATTRIBUTES.fingerprint, [d.fingerprint]) &&
      this.write(p, ATTRIBUTES.info, [JSON.stringify(info)]);
    if (!written) {
      log.debug("Leaving OpenPgpKeys.register(). Not written.");
      return refused(this.refuse('STS-OPENPGP-0019', 'The key verified but ' +
        'could not be written to ' + p.username + '\'s entry.'));
    }
    // THE CLASSICAL KEY KEPT BESIDE THE POST-QUANTUM ONE (#2009 P2, rcbj's
    // D3). Only where the caller asks (`keepClassicalDays`, the post-login
    // mail-encryption activity's `keepClassical`), the key replaced has a
    // classical encryption key and the new one a post-quantum one: then the
    // old key goes to the second slot until `keptUntil`, published in the
    // Web Key Directory with the new one, and mail from this service goes to
    // the new one at once (`encryptionFor()` reads only the first slot).
    // Any other registration leaves a kept key where it is, unless it IS
    // that key coming back, which ends the keeping.
    const keepDays = ctx && ctx.keepClassicalDays !== undefined
      ? Number(ctx.keepClassicalDays) : -1;
    // The new key IS registered by now, so a kept key that could not be
    // written is said (STS-OPENPGP-0031) and the registration stands: the
    // old key is then simply replaced, today's one-key rule.
    const keptUntil = await this.keepClassical(p, info, keepDays, at, actor,
                                               via);
    // A CHOICE OF openpgp WITH NO ENCRYPTION KEY NOW is put back to none,
    // and the page says so: mail cannot be encrypted to a key that has no
    // encryption subkey.
    let choiceReset = false;
    if (p.mailEncryption === 'openpgp' && !d.encryption) {
      choiceReset = this.write(p, ATTRIBUTES.mailEncryption, ['none']);
    }
    await this.republish(p.username, holder, p.mail, info.wkd,
                         d.fingerprint);
    this.recordAudit('openpgp.key-registered', actor, p.username,
      'an OpenPGP key (' + d.fingerprint + ') was registered for ' +
      p.username + (before ? ', replacing ' + before : ''),
      { fingerprint: d.fingerprint, version: String(d.version),
        algorithm: info.algorithm, encryption: info.encryption, via: via,
        replaced: before || '' });
    log.debug("Leaving OpenPgpKeys.register(). " + d.fingerprint);
    return { ok: true, fingerprint: d.fingerprint, replaced: before || '',
             choiceReset: choiceReset,
             postQuantum: OpenPgpKeys.encryptionIsPq(info),
             classicalKeptUntil: keptUntil };
  }

  // THE SECOND SLOT (#2009 P2, rcbj's D3), written after the new key: the
  // replaced key, armored, and what is drawn about it, and the row the
  // retirement job walks. `days` below 0 means the caller did not ask. The
  // answer is when the kept key goes ('' for none kept); a write that
  // fails is said and answers ''.
  private async keepClassical(p: Json, info: Json, days: number, at: number,
                              actor: string, via: string): Promise<string> {
    const { log, errorCodes: codes } = this.deps;
    log.debug("Entering OpenPgpKeys.keepClassical(). " + days);
    const holder = this.holderOf(p.username);
    const wasClassical = !!p.key && !OpenPgpKeys.encryptionIsPq(p.info);
    const keptFingerprint = String((p.classicalInfo &&
                                    p.classicalInfo.fingerprint) || '');
    if (days < 0 || !wasClassical || !OpenPgpKeys.encryptionIsPq(info) ||
        days === 0) {
      // NOT KEPT. A kept key the person registered again ends the keeping:
      // it is the first slot's key now.
      if (p.classicalKey && keptFingerprint &&
          keptFingerprint === String(info.fingerprint)) {
        this.write(p, ATTRIBUTES.classicalKey, []);
        this.write(p, ATTRIBUTES.classicalInfo, []);
        if (holder) {
          classicalKept.delete(holder);
        }
      }
      log.debug("Leaving OpenPgpKeys.keepClassical(). Not kept.");
      return '';
    }
    const until = new Date(at + days * 24 * 60 * 60 * 1000).toISOString();
    const kept = {
      fingerprint: p.fingerprint,
      algorithm: String((p.info && p.info.algorithm) || ''),
      encryption: String((p.info && p.info.encryption) || ''),
      replacedBy: String(info.fingerprint),
      replacedAt: new Date(at).toISOString(),
      keptUntil: until
    };
    const written = this.write(p, ATTRIBUTES.classicalKey, [p.key]) &&
      this.write(p, ATTRIBUTES.classicalInfo, [JSON.stringify(kept)]);
    if (!written || !holder) {
      log.error(codes.tag('STS-OPENPGP-0031') + 'openpgp: the classical ' +
                'key ' + p.fingerprint + ' of ' + p.username + ' could ' +
                'not be kept beside the post-quantum key that replaced it; ' +
                'it is replaced, as a registration replaces a key.');
      this.write(p, ATTRIBUTES.classicalKey, []);
      this.write(p, ATTRIBUTES.classicalInfo, []);
      log.debug("Leaving OpenPgpKeys.keepClassical(). Not written.");
      return '';
    }
    classicalKept.set(holder, { keptUntil: Date.parse(until),
                                fingerprint: p.fingerprint });
    this.recordAudit('openpgp.classical-kept', actor, p.username,
      'the classical OpenPGP key ' + p.fingerprint + ' of ' + p.username +
      ' is kept beside the post-quantum key ' + info.fingerprint +
      ' until ' + until, { fingerprint: p.fingerprint,
                           replacedBy: String(info.fingerprint),
                           keptUntil: until, via: via });
    log.debug("Leaving OpenPgpKeys.keepClassical(). Until " + until);
    return until;
  }

  /**
   * Removes a person's kept classical OpenPGP key (#2009 P2): from the
   * entry, and so from the Web Key Directory, with its retirement row.
   *
   * @param username - the person
   * @param ctx - `{ actor, via, reason }`
   * @returns `{ ok, fingerprint }`; `fingerprint` '' where none was kept
   */
  retireClassical(username: string, ctx: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.retireClassical().");
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.retireClassical(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    const holder = this.holderOf(p.username);
    const fingerprint = String((p.classicalInfo &&
                                p.classicalInfo.fingerprint) || '');
    if (!p.classicalKey && !fingerprint) {
      if (holder) {
        classicalKept.delete(holder);
      }
      log.debug("Leaving OpenPgpKeys.retireClassical(). None kept.");
      return { ok: true, fingerprint: '' };
    }
    const removed = this.write(p, ATTRIBUTES.classicalKey, []) &&
      this.write(p, ATTRIBUTES.classicalInfo, []);
    if (!removed) {
      log.debug("Leaving OpenPgpKeys.retireClassical(). Not written.");
      return this.refuse('STS-OPENPGP-0019', 'The kept classical key could ' +
                         'not be removed from ' + p.username + '\'s entry.');
    }
    if (holder) {
      classicalKept.delete(holder);
    }
    this.recordAudit('openpgp.classical-retired',
      String((ctx && ctx.actor) || ''), p.username,
      'the classical OpenPGP key ' + fingerprint + ' of ' + p.username +
      ' was removed' + (ctx && ctx.reason ? ' (' + ctx.reason + ')' : ''),
      { fingerprint: fingerprint, via: String((ctx && ctx.via) || '') });
    log.debug("Leaving OpenPgpKeys.retireClassical(). " + fingerprint);
    return { ok: true, fingerprint: fingerprint };
  }

  /**
   * The retirement job's body in the ambient realm (#2009 P2): every kept
   * classical key whose time has passed is removed. Walks the retirement
   * rows only — never the directory — at most `limit` a run, asking
   * `ctx.stillOwner()` between people. Never throws for one person.
   *
   * @param ctx - the scheduler's run context, or nothing
   * @param limit - the most people one run retires
   * @returns `{ retired, failed, kept, summary }`
   */
  async retireClassicalDueAsync(ctx?: Json, limit?: number): Promise<Json> {
    const { log, now, errorCodes: codes } = this.deps;
    log.debug("Entering OpenPgpKeys.retireClassicalDueAsync().");
    const cap = Number(limit) > 0 ? Number(limit) : 500;
    const due: string[] = [];
    let held = 0;
    const at = now();
    const walk = function (row: Json, key: unknown): boolean {
      if (!row || typeof row !== 'object') {
        return true;
      }
      held += 1;
      if (Number(row.keptUntil) <= at) {
        due.push(String(key));
      }
      return due.length < cap;
    };
    if (typeof (classicalKept as Json).scanAsync === 'function') {
      await (classicalKept as Json).scanAsync(walk);
    } else {
      classicalKept.forEach(function (row: Json, key: unknown): void {
        walk(row, key);
      });
    }
    let retired = 0;
    let failed = 0;
    for (const holder of due) {
      if (ctx && typeof ctx.stillOwner === 'function' && !ctx.stillOwner()) {
        break;
      }
      const name = this.nameOfHolder(holder);
      if (!name) {
        // The person is gone: so is their entry and the key on it.
        classicalKept.delete(holder);
        continue;
      }
      let done: Json = null;
      try {
        done = this.retireClassical(name, {
          actor: '', via: 'post-login.mail-classical-retire',
          reason: 'the time it was kept beside the post-quantum key ended' });
      } catch (e) {
        log.debug("Caught in OpenPgpKeys.retireClassicalDueAsync(): " +
                  ((e && e.message) || e));
        done = { ok: false, error: String((e && e.message) || e) };
      }
      if (done && done.ok) {
        retired += done.fingerprint ? 1 : 0;
      } else {
        failed += 1;
        log.error(codes.tag('STS-OPENPGP-0032') + 'openpgp: the kept ' +
                  'classical key of ' + name + ' could not be removed: ' +
                  String((done && done.error) || ''));
      }
    }
    const out = { retired: retired, failed: failed, kept: held - retired,
                  summary: retired + ' classical OpenPGP key(s) removed' +
                    (failed ? ', ' + failed + ' could not be' : '') + '.' };
    log.debug("Leaving OpenPgpKeys.retireClassicalDueAsync(). " +
              out.summary);
    return failed ? Object.assign(out, { errorCode: 'STS-OPENPGP-0032' })
                  : out;
  }

  /**
   * An algorithm as the page names it: `ed25519`, `ecdsa nistP256`,
   * `rsaEncryptSign 4096`.
   *
   * @param alg - `{ algorithm, curve, bits }`
   * @returns the text
   */
  static algorithmText(alg: Json): string {
    helpers.log.debug("Entering OpenPgpKeys.algorithmText().");
    helpers.log.debug("Leaving OpenPgpKeys.algorithmText().");
    const a = alg || {};
    return String(a.algorithm || '') + (a.curve ? ' ' + a.curve : '') +
      (a.bits ? ' ' + a.bits : '');
  }

  /**
   * Removes a person's OpenPGP key: the three attributes, its publication,
   * and a mail choice of `openpgp`.
   *
   * @param username - the person
   * @param ctx - `{ actor, via, reason }`
   * @returns `{ ok, fingerprint }`, or a coded refusal
   */
  async removeKey(username: string, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.removeKey().");
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.removeKey(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    if (!p.key && !p.fingerprint) {
      log.debug("Leaving OpenPgpKeys.removeKey(). None.");
      return this.refuse('STS-OPENPGP-0015', p.username + ' has no ' +
                         'OpenPGP key registered.');
    }
    // A kept classical key (#2009 P2) goes with the key it was kept beside.
    const holderNow = this.holderOf(p.username);
    if (holderNow) {
      classicalKept.delete(holderNow);
    }
    const written = this.write(p, ATTRIBUTES.key, []) &&
      this.write(p, ATTRIBUTES.fingerprint, []) &&
      this.write(p, ATTRIBUTES.info, []) &&
      (!p.classicalKey ||
       (this.write(p, ATTRIBUTES.classicalKey, []) &&
        this.write(p, ATTRIBUTES.classicalInfo, []))) &&
      (p.mailEncryption !== 'openpgp' ||
       this.write(p, ATTRIBUTES.mailEncryption, ['none']));
    if (!written) {
      log.debug("Leaving OpenPgpKeys.removeKey(). Not written.");
      return this.refuse('STS-OPENPGP-0019', 'The key could not be removed ' +
                         'from ' + p.username + '\'s entry.');
    }
    await this.unpublish(this.holderOf(p.username));
    const actor = String((ctx && ctx.actor) || '');
    this.recordAudit('openpgp.key-removed', actor, p.username,
      'the OpenPGP key ' + p.fingerprint + ' of ' + p.username + ' was ' +
      'removed' + (ctx && ctx.reason ? ' (' + ctx.reason + ')' : ''),
      { fingerprint: p.fingerprint, via: String((ctx && ctx.via) || '') });
    log.debug("Leaving OpenPgpKeys.removeKey().");
    return { ok: true, fingerprint: p.fingerprint };
  }

  // -------------------------------------------------------------------------
  // THE PERSON'S CHOICES: publication and mail encryption.
  // -------------------------------------------------------------------------
  /**
   * Sets whether a person's key is published in the Web Key Directory.
   *
   * @param username - the person
   * @param publish - true to publish
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, published }`, or a coded refusal
   */
  async setPublication(username: string, publish: boolean,
                       ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.setPublication(). " + publish);
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.setPublication(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    if (publish && !p.key) {
      log.debug("Leaving OpenPgpKeys.setPublication(). No key.");
      return this.refuse('STS-OPENPGP-0015', 'Register an OpenPGP key ' +
                         'before publishing it.');
    }
    const info = Object.assign({}, p.info || {}, { wkd: !!publish });
    if (p.key && !this.write(p, ATTRIBUTES.info, [JSON.stringify(info)])) {
      log.debug("Leaving OpenPgpKeys.setPublication(). Not written.");
      return this.refuse('STS-OPENPGP-0019', 'The choice could not be ' +
                         'written to ' + p.username + '\'s entry.');
    }
    const holder = this.holderOf(p.username);
    await this.republish(p.username, holder, p.mail, !!publish,
                         p.fingerprint);
    this.recordAudit('openpgp.publication', String((ctx && ctx.actor) || ''),
      p.username, p.username + (publish ? ' published' : ' withdrew') +
      ' their OpenPGP key ' + (publish ? 'in' : 'from') + ' the Web Key ' +
      'Directory', { fingerprint: p.fingerprint, published: String(!!publish),
                     via: String((ctx && ctx.via) || '') });
    log.debug("Leaving OpenPgpKeys.setPublication().");
    return { ok: true, published: !!publish };
  }

  /**
   * Sets how mail to a person is encrypted: `none`, `openpgp` (their key
   * must have an encryption key) or `smime` (their userSMIMECertificate
   * must hold one that can receive).
   *
   * @param username - the person
   * @param choice - one of MAIL_ENCRYPTION
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, choice }`, or a coded refusal
   */
  setMailEncryption(username: string, choice: string, ctx: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering OpenPgpKeys.setMailEncryption(). " + choice);
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.setMailEncryption(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    const wanted = String(choice || '');
    if (MAIL_ENCRYPTION.indexOf(wanted) < 0) {
      log.debug("Leaving OpenPgpKeys.setMailEncryption(). Unknown.");
      return this.refuse('STS-OPENPGP-0014', 'Unknown mail encryption "' +
        wanted.slice(0, 32) + '". It is one of: ' +
        MAIL_ENCRYPTION.join(', ') + '.');
    }
    if (wanted === 'openpgp' && !(p.key && p.info && p.info.encryption &&
                                  !this.expired(p.info) &&
                                  OpenPgpKeys.keyNames(p.info, p.mail))) {
      log.debug("Leaving OpenPgpKeys.setMailEncryption(). No OpenPGP key.");
      return this.refuse('STS-OPENPGP-0016', p.key
        ? 'The registered OpenPGP key has no encryption key valid now, so ' +
          'mail cannot be encrypted to it.'
        : 'Register an OpenPGP key before choosing OpenPGP for mail.');
    }
    if (wanted === 'smime') {
      const smime = this.deps.crypto.smimeRecipientCertificate(p.smime,
        new Date(now()));
      if (!smime.ok) {
        log.debug("Leaving OpenPgpKeys.setMailEncryption(). No S/MIME.");
        return this.refuse('STS-OPENPGP-0017', String(smime.error) + '.');
      }
    }
    if (!this.write(p, ATTRIBUTES.mailEncryption, [wanted])) {
      log.debug("Leaving OpenPgpKeys.setMailEncryption(). Not written.");
      return this.refuse('STS-OPENPGP-0019', 'The choice could not be ' +
                         'written to ' + p.username + '\'s entry.');
    }
    this.recordAudit('openpgp.mail-encryption',
      String((ctx && ctx.actor) || ''), p.username, 'mail to ' + p.username +
      ' is now ' + (wanted === 'none' ? 'not encrypted' : 'encrypted with ' +
      (wanted === 'openpgp' ? 'OpenPGP' : 'S/MIME')),
      { choice: wanted, was: p.mailEncryption,
        via: String((ctx && ctx.via) || '') });
    log.debug("Leaving OpenPgpKeys.setMailEncryption().");
    return { ok: true, choice: wanted };
  }

  /**
   * Sets a person's S/MIME certificate (`userSMIMECertificate`): one PEM or
   * base64 DER certificate that can receive S/MIME now and names the
   * entry's address (its subjectAltName rfc822Name or the subject's
   * emailAddress).
   *
   * @param username - the person
   * @param certificate - the certificate; empty removes it
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, subject, serial }` or `{ ok, removed }`, or a coded
   *   refusal
   */
  setSmimeCertificate(username: string, certificate: string,
                      ctx: Json): Json {
    const { log, now } = this.deps;
    log.debug("Entering OpenPgpKeys.setSmimeCertificate().");
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.setSmimeCertificate(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    const actor = String((ctx && ctx.actor) || '');
    const via = String((ctx && ctx.via) || '');
    const text = String(certificate || '').trim();
    if (!text) {
      const removed = this.write(p, ATTRIBUTES.smime, []) &&
        this.write(p, 'userSMIMECertificate', []) &&
        (p.mailEncryption !== 'smime' ||
         this.write(p, ATTRIBUTES.mailEncryption, ['none']));
      if (!removed) {
        log.debug("Leaving OpenPgpKeys.setSmimeCertificate(). Not removed.");
        return this.refuse('STS-OPENPGP-0019', 'The certificate could not ' +
                           'be removed from ' + p.username + '\'s entry.');
      }
      this.recordAudit('openpgp.smime-certificate', actor, p.username,
        'the S/MIME certificate of ' + p.username + ' was removed',
        { via: via, removed: 'true' });
      log.debug("Leaving OpenPgpKeys.setSmimeCertificate(). Removed.");
      return { ok: true, removed: true };
    }
    const chosen = this.deps.crypto.smimeRecipientCertificate([text],
      new Date(now()));
    if (!chosen.ok) {
      log.debug("Leaving OpenPgpKeys.setSmimeCertificate(). Unfit.");
      return this.refuse('STS-OPENPGP-0018', String(chosen.error) + '.');
    }
    const wanted = p.mail.toLowerCase();
    if (!wanted || (chosen.emails || []).map(function (e: string) {
      return String(e).toLowerCase();
    }).indexOf(wanted) < 0) {
      log.debug("Leaving OpenPgpKeys.setSmimeCertificate(). Address.");
      return this.refuse('STS-OPENPGP-0018', 'The certificate names ' +
        ((chosen.emails || []).join(', ') || 'no address') + ', not ' +
        (p.mail || 'an address') + ', the address on the entry.');
    }
    const written = this.write(p, 'userSMIMECertificate', []) &&
      this.write(p, ATTRIBUTES.smime, [chosen.der.toString('base64')]);
    if (!written) {
      log.debug("Leaving OpenPgpKeys.setSmimeCertificate(). Not written.");
      return this.refuse('STS-OPENPGP-0019', 'The certificate could not be ' +
                         'written to ' + p.username + '\'s entry.');
    }
    this.recordAudit('openpgp.smime-certificate', actor, p.username,
      'an S/MIME certificate (' + chosen.serial + ') was set for ' +
      p.username, { via: via, serial: String(chosen.serial),
                    subject: String(chosen.subject) });
    log.debug("Leaving OpenPgpKeys.setSmimeCertificate().");
    return { ok: true, subject: chosen.subject, serial: chosen.serial };
  }

  // -------------------------------------------------------------------------
  // AN ML-KEM S/MIME CERTIFICATE THIS REALM ISSUES (#2220).
  //
  // #2009's D4 made an ML-KEM certificate UPLOADED, and left a realm-issued
  // one to a later ticket because a KEM key cannot sign a certification
  // request: there is nothing for the usual proof of possession to check.
  // This is that ticket's route: RFC 9810 (CMP v3) section 5.2.8.3.3's
  // direct method, the challenge-response protocol (written there for a
  // decryption key; section 5.2.8.4 names the KEM case,
  // `KEMKPOPChallengeResp`), for a key that cannot sign:
  //
  //   1. `issueSmimeKemChallenge()` takes the person's ML-KEM public key,
  //      encapsulates to it (`crypto.smimeKemChallenge()`) and answers the
  //      ciphertext. Only the SHA-256 of the shared secret is kept, beside
  //      the key, for `openpgp.challengeLifetimeS`, ONE per person: in the
  //      challenge store the OpenPGP registration uses, under the key
  //      `kem:<entryUUID>` so the two never meet.
  //   2. The person runs `openssl pkeyutl -decap` with their private key
  //      and sends back the 32-octet secret (hex or base64).
  //      `issueSmimeKemCertificate()` compares it in constant time; the
  //      challenge is SPENT whatever the answer (a cluster claim on its
  //      nonce, as a registration's is), so a wrong answer costs a new
  //      challenge rather than a second guess.
  //   3. A match is issued by the realm's EST Issuing CA under the `email`
  //      profile, through `common/cert_enrollment.ts`'s `issue()` — the
  //      enrollment core, so the names come from the entry (its `mail` as
  //      the rfc822Name), the realm's est.allowedProfiles, lifetime and
  //      certificate cap apply, the serial is recorded where OCSP and the
  //      CRL look, and it is audited as any enrollment is. `pki.js`
  //      certifies `keyEncipherment` alone for an ML-KEM key (RFC 9935).
  //   4. The certificate becomes the person's S/MIME certificate through
  //      `setSmimeCertificate()`, unchanged, and is answered with its chain.
  //
  // An uploaded certificate is still taken exactly as before.
  // -------------------------------------------------------------------------
  /**
   * Issues a proof-of-possession challenge for an ML-KEM S/MIME certificate.
   *
   * @param username - the person
   * @param publicKey - the ML-KEM public key, a PEM SubjectPublicKeyInfo
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, challenge: { algorithm, cipherText, expiresAt },
   *   command }`, or a coded refusal
   */
  issueSmimeKemChallenge(username: string, publicKey: string,
                         ctx: Json): Json {
    const { log, crypto: c, now } = this.deps;
    log.debug("Entering OpenPgpKeys.issueSmimeKemChallenge().");
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemChallenge(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    if (!OpenPgpKeys.splitAddress(p.mail).domain) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemChallenge(). No address.");
      return this.refuse('STS-OPENPGP-0006', p.username + '\'s entry has ' +
        'no mail address, and an S/MIME certificate names the address on ' +
        'the entry.');
    }
    if (!c.smimeKemAvailable()) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemChallenge(). No ML-KEM.");
      return this.refuse('STS-OPENPGP-0036', 'This service cannot ' +
        'encapsulate to an ML-KEM key on this runtime, so it cannot ask ' +
        'for the proof of possession an ML-KEM certificate needs.');
    }
    const key: Json = c.smimeKemPublicKeyOf(String(publicKey || ''));
    if (!key.ok) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemChallenge(). The key.");
      return this.refuse('STS-OPENPGP-0035', String(key.error) + '.');
    }
    const holder = this.holderOf(p.username);
    const made: Json = c.smimeKemChallenge(key);
    const issuedAt = now();
    const lifetimeS = Number(this.setting('openpgp.challengeLifetimeS'));
    const row = { kind: 'smime-kem', algorithm: key.name,
                  spkiPem: key.spkiPem, secretDigest: made.secretDigest,
                  cipherText: made.cipherText.toString('base64'),
                  nonce: c.randomBytes(24).toString('base64url'),
                  issuedAt: issuedAt,
                  expiresAt: issuedAt + lifetimeS * 1000,
                  actor: String((ctx && ctx.actor) || ''),
                  via: String((ctx && ctx.via) || '') };
    challenges.set(OpenPgpKeys.kemHolderKey(holder), row);
    this.recordAudit('openpgp.smime-kem-challenge', row.actor, p.username,
      'an ' + key.name + ' S/MIME proof-of-possession challenge was issued ' +
      'for ' + p.username, { via: row.via, algorithm: key.name,
                             expiresAt: new Date(row.expiresAt)
                               .toISOString() });
    log.debug("Leaving OpenPgpKeys.issueSmimeKemChallenge().");
    return { ok: true, challenge: {
      algorithm: key.name,
      cipherText: made.cipherText.toString('base64'),
      expiresAt: new Date(row.expiresAt).toISOString() },
      command: 'base64 -d > challenge.bin && openssl pkeyutl -decap ' +
               '-inkey mlkem.key -in challenge.bin -secret secret.bin && ' +
               'xxd -p -c 64 secret.bin' };
  }

  /**
   * Issues the ML-KEM S/MIME certificate a person proved possession of, and
   * makes it their S/MIME certificate.
   *
   * @param username - the person
   * @param secret - the shared secret they decapsulated, hex or base64
   * @param ctx - `{ actor, via }`
   * @returns `{ ok, certificate, chain, serial, subject }`, or a coded
   *   refusal
   */
  async issueSmimeKemCertificate(username: string, secret: string,
                                 ctx: Json): Promise<Json> {
    const { log, crypto: c, now, errorCodes: codes } = this.deps;
    log.debug("Entering OpenPgpKeys.issueSmimeKemCertificate().");
    const actor = String((ctx && ctx.actor) || '');
    const via = String((ctx && ctx.via) || '');
    const self = this;
    const refused = function (answer: Json): Json {
      self.recordAudit('openpgp.smime-kem-refused', actor,
        String(username || ''), 'an ML-KEM S/MIME certificate was not ' +
        'issued for ' + String(username || '') + ': ' +
        String(answer.error || ''), { via: via }, 'refused',
        codes.codeOf(answer));
      return answer;
    };
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemCertificate(). Nobody.");
      return this.refuse(this.deps.directory() ? 'STS-OPENPGP-0013'
                                               : 'STS-OPENPGP-0020',
                         'There is no person "' + String(username || '') +
                         '" in this realm.');
    }
    const key = OpenPgpKeys.kemHolderKey(this.holderOf(p.username));
    const held: Json = challenges.get(key);
    const at = now();
    if (!held || held.kind !== 'smime-kem' ||
        !(Number(held.expiresAt) > at)) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemCertificate(). No " +
                "challenge.");
      return refused(this.refuse('STS-OPENPGP-0037', 'There is no ' +
        'outstanding ML-KEM challenge for ' + p.username + ', or it ' +
        'lapsed: ask for a new one.'));
    }
    // SPENT ONCE, WHATEVER THE ANSWER (the block above).
    const spent: Json = await this.deps.claims.claim({
      scope: CHALLENGE_SCOPE, value: String(held.nonce),
      ttlMs: Math.max(1000, Number(held.expiresAt) - at + 60000) });
    challenges.delete(key);
    if (!spent.ok) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemCertificate(). Spent.");
      return refused(this.refuse('STS-OPENPGP-0037', spent.reason === 'used'
        ? 'That challenge was already answered: ask for a new one.'
        : 'The challenge could not be spent (the store did not answer); ' +
          'ask for a new one.'));
    }
    if (!c.smimeKemAnswerMatches(String(held.secretDigest),
                                 String(secret || ''))) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemCertificate(). Wrong " +
                "secret.");
      return refused(this.refuse('STS-OPENPGP-0038', 'That is not the ' +
        'secret this service encapsulated to the ' + String(held.algorithm) +
        ' key: decapsulate the challenge with its private key (openssl ' +
        'pkeyutl -decap) and send the 32-octet secret, hex or base64. The ' +
        'challenge is spent; ask for a new one.'));
    }
    // Lazily: the enrollment core reaches the directory, the PKI and the
    // realm's rules, and this module is loaded long before it.
    const enrollment: Json = require('./cert_enrollment');
    const issued: Json = await enrollment.issue({
      family: 'est', profile: 'email',
      principal: enrollment.sessionPrincipal(p.username, 'portal',
                                             { admin: false }),
      target: { kind: 'person', id: p.username },
      publicKeyPem: String(held.spkiPem),
      requested: { emails: [p.mail] },
      keySource: 'client', keyAlg: String(held.algorithm),
      via: 'the user portal (ML-KEM S/MIME, #2220)'
    });
    if (!issued || !issued.ok) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemCertificate(). Not " +
                "issued.");
      return refused(this.refuse('STS-OPENPGP-0039', 'The realm\'s EST ' +
        'Issuing CA did not issue the certificate: ' +
        String(((issued && issued.errors) || [])[0] ||
               'the authority refused') + '.'));
    }
    // `issue()` answers the record it kept on the entry: the certificate
    // and the chain above it, the Root excluded.
    const record: Json = issued.record || {};
    const pem = String(record.certificatePem || '');
    const set: Json = this.setSmimeCertificate(p.username, pem, ctx);
    if (!set.ok) {
      log.debug("Leaving OpenPgpKeys.issueSmimeKemCertificate(). Not set.");
      return refused(set);
    }
    log.debug("Leaving OpenPgpKeys.issueSmimeKemCertificate(). " +
              set.serial);
    return { ok: true, certificate: pem,
             chain: [pem].concat(record.chainPem || []),
             serial: String(set.serial), subject: String(set.subject),
             algorithm: String(held.algorithm) };
  }

  /**
   * A person's outstanding ML-KEM S/MIME challenge, as the portal draws it:
   * the algorithm, the ciphertext and when it lapses; null when there is
   * none. The secret's digest and the key stay in the store.
   *
   * @param username - the person
   * @returns `{ algorithm, cipherText, expiresAt }`, or null
   */
  smimeKemChallengeOf(username: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering OpenPgpKeys.smimeKemChallengeOf().");
    const holder = this.person(username) ? this.holderOf(username) : '';
    const held: Json = holder
      ? challenges.get(OpenPgpKeys.kemHolderKey(holder)) : null;
    if (!held || held.kind !== 'smime-kem' ||
        !(Number(held.expiresAt) > now())) {
      log.debug("Leaving OpenPgpKeys.smimeKemChallengeOf(). None.");
      return null;
    }
    log.debug("Leaving OpenPgpKeys.smimeKemChallengeOf().");
    return { algorithm: String(held.algorithm),
             cipherText: String(held.cipherText),
             expiresAt: new Date(Number(held.expiresAt)).toISOString() };
  }

  /**
   * The challenge store's key for a person's ML-KEM challenge.
   *
   * @param holder - the person's entryUUID
   * @returns the key
   */
  static kemHolderKey(holder: string): string {
    helpers.log.debug("Entering OpenPgpKeys.kemHolderKey().");
    helpers.log.debug("Leaving OpenPgpKeys.kemHolderKey().");
    return 'kem:' + String(holder || '');
  }

  // -------------------------------------------------------------------------
  // THE PUBLICATION REGISTER (header).
  // -------------------------------------------------------------------------
  private async unpublish(holder: string): Promise<void> {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.unpublish().");
    if (!holder) {
      log.debug("Leaving OpenPgpKeys.unpublish(). Nobody.");
      return;
    }
    let rows: Json[] = [];
    try {
      rows = await published.lookupEntriesAsync('h:' + holder);
    } catch (e) {
      log.debug("Caught in OpenPgpKeys.unpublish(): " +
                ((e && e.message) || e));
      // The register is a pointer the lookup checks against the entry, so
      // a row left behind answers nothing once the entry says otherwise.
      rows = [];
    }
    rows.forEach(function (row: Json): void {
      published.delete(row.key);
    });
    log.debug("Leaving OpenPgpKeys.unpublish(). " + rows.length);
  }

  private async republish(username: string, holder: string, mail: string,
                          publish: boolean,
                          fingerprint: string): Promise<void> {
    const { log, crypto: c, now } = this.deps;
    log.debug("Entering OpenPgpKeys.republish(). " + publish);
    await this.unpublish(holder);
    const split = OpenPgpKeys.splitAddress(mail);
    if (publish && holder && split.local && fingerprint) {
      published.set(split.domain + '/' + c.wkdHash(split.local), {
        holder: holder, fingerprint: fingerprint,
        publishedAt: new Date(now()).toISOString() });
    }
    log.debug("Leaving OpenPgpKeys.republish().");
  }

  /**
   * The domains the ambient realm's Web Key Directory serves:
   * `openpgp.wkdDomains`, or the realm's own DNS domain when that is empty.
   *
   * @returns lower-case domains
   */
  wkdDomains(): string[] {
    const { log, realms: r } = this.deps;
    log.debug("Entering OpenPgpKeys.wkdDomains().");
    const listed = [].concat(this.setting('openpgp.wkdDomains') || [])
      .map(function (d: unknown): string {
        return String(d || '').trim().toLowerCase().replace(/\.$/, '');
      }).filter(Boolean);
    const out = listed.length ? listed
      : [String(r.domainOf(r.current()) || '').toLowerCase()]
        .filter(Boolean);
    log.debug("Leaving OpenPgpKeys.wkdDomains(). " + out.join(','));
    return out;
  }

  /**
   * The realm that answers a Web Key Directory request for a domain: the
   * ambient one when the request named a realm, else the first realm (the
   * default, then by id) that turned the directory on and serves it.
   *
   * @param domain - the mail domain
   * @param named - whether the request carried a realm segment
   * @returns the realm, or null
   */
  realmServing(domain: string, named: boolean): Json {
    const { log, realms: r } = this.deps;
    const self = this;
    log.debug("Entering OpenPgpKeys.realmServing(). " + domain);
    const serves = function (): boolean {
      return !!self.setting('openpgp.wkd') &&
        self.wkdDomains().indexOf(domain) >= 0;
    };
    if (named) {
      const here = serves() ? r.current() : null;
      log.debug("Leaving OpenPgpKeys.realmServing(). Named.");
      return here;
    }
    const all: Json[] = [r.DEFAULT_REALM].concat((r.list() || [])
      .filter(function (one: Json) {
        return one && one.id !== r.DEFAULT_REALM.id;
      }).sort(function (a: Json, b: Json) {
        return String(a.id) < String(b.id) ? -1 : 1;
      }));
    for (const realm of all) {
      if (r.run(realm, serves)) {
        log.debug("Leaving OpenPgpKeys.realmServing(). " + realm.id);
        return realm;
      }
    }
    log.debug("Leaving OpenPgpKeys.realmServing(). None.");
    return null;
  }

  /**
   * Looks a key up in the AMBIENT realm's Web Key Directory: the binary key
   * of the person whose `mail` is `<local>@<domain>`, who opted in, with the
   * published fingerprint.
   *
   * @param domain - the mail domain
   * @param hash - the hashed local part
   * @param local - the `l` parameter, when the client sent it
   * @returns the bytes, or null
   */
  async lookup(domain: string, hash: string,
               local: string): Promise<Buffer | null> {
    const { log, crypto: c } = this.deps;
    log.debug("Entering OpenPgpKeys.lookup().");
    const key = domain + '/' + hash;
    let username = '';
    let row: Json = null;
    try {
      await published.warm([key]);
      row = published.get(key) || null;
    } catch (e) {
      log.debug("Caught in OpenPgpKeys.lookup(): " + ((e && e.message) || e));
      // The register did not answer: the `l` parameter may still find the
      // person (header).
      row = null;
    }
    if (row && row.holder) {
      username = this.nameOfHolder(String(row.holder));
    }
    const dir = this.deps.directory();
    if (!username && local && dir && c.wkdHash(local) === hash) {
      username = String(dir.personByMail(local + '@' + domain) || '');
    }
    const p = username ? this.person(username) : null;
    const split = p ? OpenPgpKeys.splitAddress(p.mail) : null;
    const answers = !!p && !!p.key && !!(p.info && p.info.wkd) &&
      split.domain === domain && c.wkdHash(split.local) === hash &&
      (!row || String(row.fingerprint) === p.fingerprint) &&
      !this.expired(p.info) && OpenPgpKeys.keyNames(p.info, p.mail);
    if (!answers) {
      log.debug("Leaving OpenPgpKeys.lookup(). Nothing published.");
      return null;
    }
    const bytes = await c.openpgpBinaryKey(p.key);
    // THE CLASSICAL KEY KEPT BESIDE IT (#2009 P2, rcbj's D3) is published
    // too, after the post-quantum one, while it is kept: the draft's answer
    // is the binary keys for the address, and several are concatenated. A
    // kept key that does not read is left out, never the answer with it.
    const kept = bytes && this.classicalKept(p)
      ? await c.openpgpBinaryKey(p.classicalKey) : null;
    const out = bytes && kept ? Buffer.concat([bytes, kept]) : bytes;
    log.debug("Leaving OpenPgpKeys.lookup(). " + (out ? (kept ? 'Answered ' +
              'with the kept classical key.' : 'Answered.') : 'Unreadable.'));
    return out;
  }

  // -------------------------------------------------------------------------
  // WHAT THE MAIL CHANNEL ASKS (header point 3).
  // -------------------------------------------------------------------------
  /**
   * How mail to a person of the ambient realm is to be encrypted, when it
   * goes to `address` (their `mail` when that is omitted).
   *
   * A KEY IS USED ONLY FOR AN ADDRESS IT NAMES: an OpenPGP key one of whose
   * valid user ids names the address, an S/MIME certificate naming it.
   * Otherwise the answer is `unbound`, and `common/mail.ts` decides what
   * that means for the message (header point 9 there).
   *
   * @param username - the person
   * @param address - the address the message goes to, or '' for `mail`
   * @returns `{ kind: 'none' }`, `{ kind: 'openpgp', armoredKey,
   *   fingerprint }`, `{ kind: 'smime', certificate (base64 DER), serial }`,
   *   `{ kind: 'unavailable', chosen, why }` for a choice that cannot be
   *   honoured now, or `{ kind: 'unbound', chosen, why }` when the key or
   *   certificate does not name the address
   */
  encryptionFor(username: string, address?: string): Json {
    const { log, now } = this.deps;
    log.debug("Entering OpenPgpKeys.encryptionFor().");
    const p = this.person(username);
    if (!p || p.mailEncryption === 'none') {
      log.debug("Leaving OpenPgpKeys.encryptionFor(). None.");
      return { kind: 'none' };
    }
    const target = String(address || p.mail || '').trim().toLowerCase();
    if (p.mailEncryption === 'openpgp') {
      if (p.key && !OpenPgpKeys.keyNames(p.info, target)) {
        log.debug("Leaving OpenPgpKeys.encryptionFor(). Not this address.");
        return { kind: 'unbound', chosen: 'openpgp',
                 why: 'no valid user id of the registered OpenPGP key ' +
                   'names ' + (target || 'the address') };
      }
      if (!p.key || !(p.info && p.info.encryption) || this.expired(p.info)) {
        log.debug("Leaving OpenPgpKeys.encryptionFor(). OpenPGP unusable.");
        return { kind: 'unavailable', chosen: 'openpgp',
                 why: p.key ? 'the registered OpenPGP key has no ' +
                   'encryption key valid now' : 'no OpenPGP key is ' +
                   'registered' };
      }
      log.debug("Leaving OpenPgpKeys.encryptionFor(). OpenPGP.");
      return { kind: 'openpgp', armoredKey: p.key,
               fingerprint: p.fingerprint };
    }
    const smime = this.deps.crypto.smimeRecipientCertificate(p.smime,
      new Date(now()));
    if (!smime.ok) {
      log.debug("Leaving OpenPgpKeys.encryptionFor(). S/MIME unusable.");
      return { kind: 'unavailable', chosen: 'smime',
               why: String(smime.error) };
    }
    if ([].concat(smime.emails || []).map(function (e: unknown): string {
      return String(e || '').trim().toLowerCase();
    }).indexOf(target) < 0) {
      log.debug("Leaving OpenPgpKeys.encryptionFor(). S/MIME elsewhere.");
      return { kind: 'unbound', chosen: 'smime',
               why: 'the S/MIME certificate does not name ' +
                 (target || 'the address') };
    }
    log.debug("Leaving OpenPgpKeys.encryptionFor(). S/MIME.");
    return { kind: 'smime', certificate: smime.der.toString('base64'),
             serial: String(smime.serial) };
  }

  // -------------------------------------------------------------------------
  // AN ADDRESS THAT CHANGED (header point 4). A key is registered for the
  // entry's `mail` and used only for an address it names; when `mail`
  // changes to one it does not name, the key is RETIRED — off the entry and
  // out of the Web Key Directory, with an audit row saying why — rather
  // than left for the next reader to skip. Registration would refuse it
  // for the new address, so keeping it would keep a key nobody could
  // register now. A key that names the new address too stays, and its
  // publication moves to the new address. An S/MIME choice whose
  // certificate does not name the new address is put back to `none`; the
  // certificate itself is the directory's attribute and is left alone.
  // -------------------------------------------------------------------------
  /**
   * Retires what a person's `mail` change leaves bound to the former
   * address. Called by the directory after the write, in the person's
   * realm.
   *
   * @param username - the person
   * @param former - the address the entry had
   * @param address - the address it has now ('' when removed)
   * @returns `{ ok, retired, moved, smimeReset }`
   */
  async addressChanged(username: string, former: string,
                       address: string): Promise<Json> {
    const { log, errorCodes: codes, now } = this.deps;
    log.debug("Entering OpenPgpKeys.addressChanged().");
    const out: Json = { ok: true, retired: '', moved: false,
                        smimeReset: false };
    const p = this.person(username);
    if (!p) {
      log.debug("Leaving OpenPgpKeys.addressChanged(). Nobody.");
      return out;
    }
    const next = String(address || '').trim();
    const via = 'a directory change';
    if (p.key && OpenPgpKeys.keyNames(p.info, next)) {
      await this.republish(p.username, this.holderOf(p.username), next,
                           !!(p.info && p.info.wkd), p.fingerprint);
      out.moved = true;
    } else if (p.key || p.fingerprint) {
      const removed: Json = await this.removeKey(p.username, {
        actor: '', via: via,
        reason: 'the entry\'s mail changed from ' + String(former || '') +
          ' to ' + (next || 'nothing') + ', which no valid user id of the ' +
          'key names' });
      if (removed.ok) {
        out.retired = String(removed.fingerprint || '');
      } else {
        // The key is still on the entry, and still unused for the new
        // address: `encryptionFor()` and the Web Key Directory ask
        // `keyNames()` at every use. The publication row goes anyway.
        await this.unpublish(this.holderOf(p.username));
        log.error(codes.tag('STS-OPENPGP-0030') + 'openpgp: the mail of ' +
                  p.username + ' changed and its OpenPGP key ' +
                  p.fingerprint + ' could not be retired: ' +
                  String(removed.error || ''));
        out.ok = false;
      }
    }
    if (p.mailEncryption === 'smime') {
      const smime = this.deps.crypto.smimeRecipientCertificate(p.smime,
        new Date(now()));
      const names = smime && smime.ok ? [].concat(smime.emails || [])
        .map(function (e: unknown): string {
          return String(e || '').trim().toLowerCase();
        }) : [];
      if (names.indexOf(next.toLowerCase()) < 0) {
        if (this.write(p, ATTRIBUTES.mailEncryption, ['none'])) {
          out.smimeReset = true;
          this.recordAudit('openpgp.mail-encryption', '', p.username,
            'mail to ' + p.username + ' is now not encrypted: the address ' +
            'changed to ' + (next || 'nothing') + ', which the S/MIME ' +
            'certificate does not name',
            { choice: 'none', was: 'smime', via: via });
        } else {
          log.error(codes.tag('STS-OPENPGP-0030') + 'openpgp: the mail of ' +
                    p.username + ' changed and the S/MIME choice could not ' +
                    'be put back to none.');
          out.ok = false;
        }
      }
    }
    log.debug("Leaving OpenPgpKeys.addressChanged(). " +
              (out.retired ? 'Retired.' : (out.moved ? 'Moved.' : 'Kept.')));
    return out;
  }

  // -------------------------------------------------------------------------
  // THE LOST-KEY RETIRER (header): a token holding a person's OpenPGP key,
  // reported lost, takes the key off their entry and out of the directory.
  // -------------------------------------------------------------------------
  /**
   * Retires an `openpgp` credential of a hardware token reported lost: the
   * key whose fingerprint the credential names is removed from the
   * holder's entry.
   *
   * @param token - the token record
   * @param credential - `{ ref (the fingerprint), holder }`
   * @param ctx - the lost-key act's context, `username` the holder
   * @returns `{ ok, already? }`, or `{ ok: false, errorCode, why }`
   */
  async retireLost(token: Json, credential: Json, ctx: Json): Promise<Json> {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.retireLost().");
    const holderName = credential && credential.holder
      ? this.nameOfHolder(String(credential.holder)) : '';
    const username = holderName || String((ctx && ctx.username) || '');
    const p = username ? this.person(username) : null;
    const wanted = String((credential && credential.ref) || '').toLowerCase()
      .replace(/[^0-9a-f]/g, '');
    if (!p || !p.fingerprint || p.fingerprint !== wanted) {
      // Already gone, or replaced by another key since: nothing on this
      // token is live on the entry, which is what retiring was for.
      log.debug("Leaving OpenPgpKeys.retireLost(). Already gone.");
      return { ok: true, already: true };
    }
    const removed: Json = await this.removeKey(username, {
      actor: String((ctx && ctx.actor) || ''),
      via: String((ctx && ctx.via) || ''),
      reason: 'hardware token ' + String((token && token.vendor) || '') + ' ' +
        String((token && token.serial) || '') + ' reported lost' });
    if (!removed.ok) {
      log.debug("Leaving OpenPgpKeys.retireLost(). Refused.");
      return { ok: false, errorCode: this.deps.errorCodes.codeOf(removed) ||
                 'STS-OPENPGP-0019', why: String(removed.error || '') };
    }
    log.debug("Leaving OpenPgpKeys.retireLost(). Removed.");
    return { ok: true };
  }

  // -------------------------------------------------------------------------
  // THE ROUTES (header point 2).
  // -------------------------------------------------------------------------
  /**
   * Answers one Web Key Directory request: the `policy` file or a key.
   *
   * @param req - the request
   * @param res - the response
   * @param domain - the mail domain
   * @param hash - the hashed local part, or '' for the policy file
   */
  async answer(req: Json, res: Json, domain: string,
               hash: string): Promise<void> {
    const { log, realms: r, errorCodes: codes } = this.deps;
    const self = this;
    log.debug("Entering OpenPgpKeys.answer().");
    res.set('Cache-Control', 'no-store');
    const d = String(domain || '').toLowerCase().replace(/\.$/, '');
    const notFound = function (code: string): void {
      codes.mark(res, code);
      // error-code: none — marked on the line above with the caller's code
      res.status(404).type('text/plain').send('Not found\n');
    };
    if (!/^[a-z0-9.-]{1,253}$/.test(d) || (hash && !WKD_HASH.test(hash))) {
      notFound('STS-OPENPGP-0021');
      log.debug("Leaving OpenPgpKeys.answer(). Malformed.");
      return;
    }
    const realm = this.realmServing(d, !r.isDefault(r.current()) ||
                                       !!r.currentPrefix());
    if (!realm) {
      notFound('STS-OPENPGP-0022');
      log.debug("Leaving OpenPgpKeys.answer(). Not served.");
      return;
    }
    if (!hash) {
      res.status(200).type('text/plain').send('');
      log.debug("Leaving OpenPgpKeys.answer(). The policy file.");
      return;
    }
    const local = typeof req.query.l === 'string'
      ? String(req.query.l).slice(0, 256) : '';
    let bytes: Buffer | null = null;
    try {
      bytes = await r.run(realm, function (): Promise<Buffer | null> {
        return self.lookup(d, hash, local);
      });
    } catch (e) {
      log.error(codes.tag('STS-OPENPGP-0023') + 'openpgp: a Web Key ' +
                'Directory lookup for ' + d + ' failed: ' +
                ((e && e.message) || e));
      codes.mark(res, 'STS-OPENPGP-0023');
      res.status(500).type('text/plain').send('The key could not be read.\n');
      log.debug("Leaving OpenPgpKeys.answer(). Threw.");
      return;
    }
    if (!bytes) {
      notFound('STS-OPENPGP-0024');
      log.debug("Leaving OpenPgpKeys.answer(). No key.");
      return;
    }
    res.status(200).type('application/octet-stream').send(bytes);
    log.debug("Leaving OpenPgpKeys.answer(). A key.");
  }

  /**
   * The direct method's domain: the request's Host, without a port.
   *
   * @param req - the request
   * @returns the lower-case host name
   */
  static hostOf(req: Json): string {
    helpers.log.debug("Entering OpenPgpKeys.hostOf().");
    const host = String((req && (req.hostname || (req.headers &&
                                                  req.headers.host))) || '');
    helpers.log.debug("Leaving OpenPgpKeys.hostOf().");
    return host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  }

  /**
   * Registers the Web Key Directory's four paths on the shared app.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OpenPgpKeys.registerRoutes().");
    const handle = function (req: Json, res: Json, domain: string,
                             hash: string): void {
      self.answer(req, res, domain, hash).catch(function (e: Json): void {
        log.debug("Caught in the Web Key Directory route: " +
                  ((e && e.message) || e));
        // `answer()` sends every response itself; a throw past it is a
        // response already sent or a socket gone.
      });
    };
    // THE ADVANCED METHOD: the domain is in the path.
    app.get('/.well-known/openpgpkey/:domain/hu/:hash',
            function (req: Json, res: Json): void {
              handle(req, res, String(req.params.domain || ''),
                     String(req.params.hash || ''));
            });
    app.get('/.well-known/openpgpkey/:domain/policy',
            function (req: Json, res: Json): void {
              handle(req, res, String(req.params.domain || ''), '');
            });
    // THE DIRECT METHOD: the domain is the host asked.
    app.get('/.well-known/openpgpkey/hu/:hash',
            function (req: Json, res: Json): void {
              handle(req, res, OpenPgpKeys.hostOf(req),
                     String(req.params.hash || ''));
            });
    app.get('/.well-known/openpgpkey/policy',
            function (req: Json, res: Json): void {
              handle(req, res, OpenPgpKeys.hostOf(req), '');
            });
    log.debug("Leaving OpenPgpKeys.registerRoutes().");
  }

  /**
   * Installs the `openpgp` retirer in the hardware token register.
   *
   * @param tokens - the register
   * @returns true when installed
   */
  installRetirer(tokens: Json): boolean {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OpenPgpKeys.installRetirer().");
    const ok = !!tokens && typeof tokens.registerRetirer === 'function' &&
      tokens.registerRetirer('openpgp', {
        label: 'OpenPGP key',
        retire: function (token: Json, c: Json, ctx: Json): Promise<Json> {
          return self.retireLost(token, c, ctx);
        }
      }) === true;
    log.debug("Leaving OpenPgpKeys.installRetirer(). " + ok);
    return ok;
  }

  // THE RULE BETWEEN THE TWO SWITCHES, the passkey lanes' rule
  // (`authn/webauthn_policy.ts`'s `laneWriteRule`) for a key. Both on is a
  // contradiction: pqcOnly accepts a post-quantum key and nothing else,
  // alongside requires a classical key beside it. Refused at the write. A
  // value that arrives from the environment is read with pqcOnly winning
  // (`openpgpRegistrationProblem`).
  /**
   * Refuses a write that would turn on `openpgp.pqcAlongsideClassical`
   * and `openpgp.pqcOnly` together.
   *
   * @param key - the setting being written
   * @param parsed - its parsed value
   * @returns `{ problem, code }`, or null
   */
  static laneWriteRule(key: string, parsed: unknown): Json {
    helpers.log.debug("Entering OpenPgpKeys.laneWriteRule(). " + key);
    const other = key === 'openpgp.pqcAlongsideClassical'
      ? 'openpgp.pqcOnly'
      : (key === 'openpgp.pqcOnly' ? 'openpgp.pqcAlongsideClassical' : '');
    if (!other || parsed !== true || config.value(other) !== true) {
      helpers.log.debug("Leaving OpenPgpKeys.laneWriteRule().");
      return null;
    }
    helpers.log.debug("Leaving OpenPgpKeys.laneWriteRule(). Refused.");
    return { code: 'STS-OPENPGP-0027',
             problem: '"' + key + '" cannot be on while "' + other +
               '" is: post-quantum only accepts a post-quantum key, and ' +
               'a post-quantum key beside a classical one needs both. ' +
               'Turn "' + other + '" off first.' };
  }

  // For the tests: the realm's challenges and publications cleared.
  /**
   * Clears the ambient realm's challenges and publications; tests only.
   */
  forgetForTests(): void {
    const { log } = this.deps;
    log.debug("Entering OpenPgpKeys.forgetForTests().");
    challenges.clear();
    published.clear();
    classicalKept.clear();
    log.debug("Leaving OpenPgpKeys.forgetForTests().");
  }
}

const slot = new InstanceSlot<OpenPgpKeys>(
  'common/openpgp_keys',
  () => new OpenPgpKeys(OpenPgpKeys.defaultDeps()),
  function (instance: OpenPgpKeys): void {
    instance.installRetirer(hardwareTokens);
    // The entry observer's S/MIME handler (#2050).
    entryObserver.register('userSMIMECertificate', {
      changed: function (change: Json): void {
        instance.entryChanged(change);
      }
    });
  },
  helpers.log);

config.addWriteRule(OpenPgpKeys.laneWriteRule);

slot.buildNowUnlessDeferred();

/**
 * A person's OpenPGP key, the Web Key Directory and their mail encryption
 * choice (#1955 P6). A route module: `registerRoutes(app)`.
 * @namespace
 */
export = {
  OpenPgpKeys: OpenPgpKeys,
  MAIL_ENCRYPTION: MAIL_ENCRYPTION,
  ATTRIBUTES: ATTRIBUTES,
  installInstance: (instance: OpenPgpKeys): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  /**
   * Fills the directory's slot; `ldap/ldap_server.js` calls it when it
   * loads.
   *
   * @param hooks - `locate`, `write` and `personByMail`, all three or none
   */
  setDirectory: function (hooks: DirectoryHooks | null): void {
    helpers.log.debug("Entering setDirectory().");
    const whole = !!hooks && typeof hooks.locate === 'function' &&
                  typeof hooks.write === 'function' &&
                  typeof hooks.personByMail === 'function';
    // VALIDATED WHOLE (rule 3e): a directory offering a read and no write
    // would let the page draw a key nobody could register.
    directory = whole ? hooks : null;
    if (hooks && !whole) {
      helpers.log.warn('openpgp: the directory offered an incomplete slot, ' +
                       'so no OpenPGP key can be read or registered.');
    }
    helpers.log.debug("Leaving setDirectory().");
  },
  hasDirectory: function (): boolean {
    helpers.log.debug("Entering hasDirectory().");
    helpers.log.debug("Leaving hasDirectory().");
    return !!directory;
  },
  registerRoutes: slot.forward('registerRoutes'),
  view: slot.forward('view'),
  issueChallenge: slot.forward('issueChallenge'),
  issueSmimeKemChallenge: slot.forward('issueSmimeKemChallenge'),
  issueSmimeKemCertificate: slot.forward('issueSmimeKemCertificate'),
  smimeKemChallengeOf: slot.forward('smimeKemChallengeOf'),
  register: slot.forward('register'),
  removeKey: slot.forward('removeKey'),
  setPublication: slot.forward('setPublication'),
  setMailEncryption: slot.forward('setMailEncryption'),
  setSmimeCertificate: slot.forward('setSmimeCertificate'),
  encryptionFor: slot.forward('encryptionFor'),
  addressChanged: slot.forward('addressChanged'),
  wkdDomains: slot.forward('wkdDomains'),
  lookup: slot.forward('lookup'),
  retireLost: slot.forward('retireLost'),
  encryptionIsPq: OpenPgpKeys.encryptionIsPq,
  classicalKept: slot.forward('classicalKept'),
  retireClassical: slot.forward('retireClassical'),
  retireClassicalDueAsync: slot.forward('retireClassicalDueAsync'),
  person: slot.forward('person'),
  forgetForTests: slot.forward('forgetForTests')
};
