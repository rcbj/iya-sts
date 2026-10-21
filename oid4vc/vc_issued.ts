// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: vc_issued.ts
//
// ---------------------------------------------------------------------------
// THE CREDENTIALS THIS REALM ISSUED FOR A DIRECTORY ENTRY (2026-09-17, #38).
//
// A presentation that verifies may sign somebody in since #38, through
// `/authn/wallet` (`vc_signin.ts`). WHO it signs in is the question this
// register exists to answer, and the credential cannot answer it alone.
//
// **WHY THE CREDENTIAL'S OWN SUBJECT IS NOT ENOUGH.** A credential this issuer
// mints names `sub: <the access token's sub>` (or, for an `ldp_vc`, the
// holder's `did:jwk`). The credential endpoint accepts access tokens it DID
// NOT ISSUE and reads their claims unverified (OID4VCI lets the authorization
// server be somebody else; `oauth-oidc/dpop.ts`'s `presentedAccessToken()`
// says so). A token anybody wrote, carrying `sub: urn:uuid:<alice's
// entryUUID>`, gets a credential SIGNED BY THIS REALM saying it is about alice
// and bound to the writer's key. A sign-in that read the subject off a
// credential with a valid signature would hand alice's session to whoever
// wrote the token.
//
// So the fact that matters is recorded AT ISSUANCE, where it is known and
// nowhere else: this realm's credential endpoint issued this credential, on
// an access token THIS REALM VERIFIED and nobody had disowned, whose subject
// names a directory entry, and which was granted for credential issuance.
// Only a credential in this register may sign anybody in, and the entry it
// signs in is the one the register names.
//
// ---------------------------------------------------------------------------
// TWO KINDS OF ROW, BECAUSE TWO KINDS OF PRESENTATION (2026-09-17, #38's
// follow-ups: every format signs in).
//
//   * **JOSE** — `dc+sd-jwt` and `jwt_vc_json`. Every presentation carries the
//     issuer-signed JWT unchanged, so a row is keyed `jws:<SHA-256 of it>` and
//     names exactly one credential.
//   * **Data Integrity** — `ldp_vc`, a bbs-2023 credential. A presentation is
//     a DERIVED proof, unlinkable to the credential by design, so there is no
//     byte of the credential to look up. What the derived proof DOES carry is
//     the statement naming its subject, the holder's `did:jwk`, signed by
//     this realm — and the holder proves that key on the presentation. So the
//     row is keyed by the HOLDER KEY and the person
//     (`ldp:<jkt>:<SHA-256 of the subject>`), and lists every credential
//     issued to that key for that person, each by the (validFrom,
//     validUntil) pair a sign-in asks the wallet to disclose. That pair is
//     what lets a presented derived proof be told apart from its siblings
//     for revocation, and lets a disown reach the credentials issued before
//     it and not one issued after.
//
// A holder key recorded for TWO people is a sign-in this register refuses to
// resolve: the proof shows the key, and the key names both.
//
// **WHAT IS KEPT, AND WHAT IS NOT.** A row holds the subject, the holder
// key's RFC 7638 thumbprint, the format, the configuration, and per credential
// its issued-register handle (`admin_stats.js`), its status-list entry
// (`vc_status.ts`), when it was issued and its validity window. Never the
// credential and never a claim value.
//
// ---------------------------------------------------------------------------
// DISOWNED (2026-09-17). A credential stops signing anybody in when:
//
//   * an administrator's GLOBAL sign-out — `/admin/logout`,
//     `/admin-api/logout` — or the `wallet-credential` row ticked on
//     `/logout`, ended the row `logout/logout.ts` draws from this register:
//     `disown()` stamps the row, and every credential issued at or before
//     that instant is disowned with it (a credential issued AFTER, on a
//     fresh token, is not). The person's own Global logout on `/logout`
//     does not: that act leaves the credential, and the DID it is bound to,
//     valid;
//   * an administrator revoked its row on `/admin/tokens` (the issued
//     register's mark, read by handle, so a restore undoes it);
//   * its status-list entry is not VALID — revoked or suspended on
//     `/admin/vc/monitor` or by the two acts above, which also set the bit so
//     a verifier elsewhere learns it (`vc_status.ts`);
//   * its HOLDER removed it on `/portal/wallet` (#661, 2026-10-16,
//     `removeForSubject()`): that one credential, stamped removed, its
//     status-list entry INVALID and its issued-register row revoked. The
//     wallet's copy is the holder's to delete: no protocol lets an issuer
//     do it. Since #670 the holder may remove EVERY COPY of one issuance in
//     one act, or one copy alone — see *A BATCH IS ONE ISSUANCE*.
//
// **A BATCH IS ONE ISSUANCE, AND THE REGISTER DOES NOT KEEP IT AS ONE ROW**
// (#670, rcbj 2026-10-17). The issuer advertises
// `batch_credential_issuance.batch_size` (`oid4vci.batchSize`, 4), a wallet
// sends that many proofs, and one Credential Response carries that many
// credentials, each bound to a DIFFERENT holder key (OpenID4VCI 1.0 section
// 8.2) with its own status-list entry. They are not one row: a JOSE row is
// keyed by its credential and an `ldp_vc` row by its holder key, so each copy
// lands on a row of its own. What they DO share is the Credential
// Response's `notification_id`, which the issuer mints once per response and
// section 11 defines as naming the credentials of that response together —
// the specification's own identifier for an issuance, recorded on every
// copy since #661. So `issuancesForSubject()` GROUPS a person's copies by
// it, and a credential recorded without one (before #661) is an issuance of
// its own. The holder key each copy is bound to is the row's `jkt`, the RFC
// 7638 thumbprint of the proof's key, recorded since #38; a DID-bound
// (`ldp_vc`) copy also keeps the holder's `did:jwk` (`holderDid`) since #670.
//
// **WHAT THE WALLET SAID** (#661, 2026-10-16): each credential keeps the
// `notification_id` its Credential Response carried, and the last event the
// wallet sent to the Notification Endpoint with it (OpenID4VCI 1.0 section
// 11, `noteWalletEvent()`), for the holder's history. It disowns nothing.
//
// **An ordinary sign-out disowns nothing here.** `/oauth2/logout`, SAML
// Single Logout, WS-Federation's `wsignout1.0` and the console's and portal's
// Sign out end ONE session through `authn.dropSession()`, which never reaches
// this register — a person who signs out of an application can sign back in
// with the wallet they already hold. `logout/CLAUDE.md` argues it.
//
// **PER TRUST REALM AND PERSISTED.** `realms.map({ persist })`, so every
// process and every node reads one register, and a disown made on one is the
// answer on all of them.
//
// A LIBRARY (rule 3): it registers no route. It requires `common/` libraries
// and `vc_status.ts`, none of which requires anything back, so `vc_issuer.ts`
// (which writes), `vc_verifier.ts` (which reads) and `logout/logout.ts` (which
// disowns) can all require it without a cycle.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import stats = require('../common/admin_stats');
import cacheRegistry = require('../common/cache_registry');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
// THE STATUS LISTS, whose entry for a credential is one of the three ways it
// is disowned. A library that requires nothing in this directory but its
// codec.
import vcStatus = require('./vc_status');
// CAEP credential-change, `verifiable-credential`, for a credential this
// realm issued a person and for one it disowned (#145). A library that sends
// nothing where Shared Signals is not loaded; it requires `helpers` and
// `crypto` and nothing of this family's.
import accountSignals = require('../ssf/account_signals');

// The parts of a `realms.map()` store this module uses.
interface Store {
  get(key: string): any;
  has(key: string): boolean;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
  keys(): Iterator<string>;
  readonly size: number;
}

// One credential on a row.
interface Issued {
  artifactKey: string;
  statusKey: string;
  issuedAt: number;
  validFrom: string;
  validUntil: string;
  expiresAt: number;
  // What a verified key attestation said about the holder key (OpenID4VCI
  // Appendix D.2 values), or empty.
  keyStorage: string[];
  userAuthentication: string[];
  // THE WALLET'S OWN REPORT (OpenID4VCI 1.0 section 11): the
  // `notification_id` the Credential Response carried, and the last event
  // the wallet sent with it, or ''.
  notificationId?: string;
  walletEvent?: string;
  walletEventAt?: number;
  // THE HOLDER REMOVED IT on /portal/wallet: when, and by whom.
  removedAt?: number;
  removedVia?: string;
  // THE HOLDER'S DID, for a DID-bound (`ldp_vc`) credential (#670): the
  // `did:jwk` its subject names — and since #693, in any format, the
  // person's proven DID a configuration bound to it carries. The key itself
  // is the row's `jkt`.
  holderDid?: string;
}

// One credential of a person's history, for `/portal/wallet`.
interface HistoryEntry {
  id: string;
  format: string;
  configId: string;
  issuedAt: number;
  expiresAt: number;
  status: string;
  removedAt: number;
  walletEvent: string;
  walletEventAt: number;
  // The issuance it came in (#670): the group `issuancesForSubject()` files
  // it under, never shown.
  issuance: string;
  // The holder key it is bound to: the RFC 7638 thumbprint, and for a
  // DID-bound credential the DID, or ''.
  keyThumbprint: string;
  holderDid: string;
  // Its index in the realm's status list, or ''.
  statusIndex: string;
}

// One issuance of a person's history (#670): the copies one Credential
// Response carried, each bound to a different key of the wallet's.
interface IssuanceEntry {
  id: string;
  format: string;
  configId: string;
  issuedAt: number;
  expiresAt: number;
  // The copies' state where they share one, else `mixed`.
  status: string;
  // How many copies are in each state.
  counts: { [state: string]: number };
  removedAt: number;
  walletEvent: string;
  walletEventAt: number;
  // Oldest first, as the wallet's proofs were.
  copies: HistoryEntry[];
}

interface VcIssuedDeps {
  log: typeof helpers.log;
  nameForSubject: typeof helpers.nameForSubject;
  subjectForName: typeof helpers.subjectForName;
  jwkThumbprint: typeof stsCrypto.jwkThumbprint;
  artifactRevokedByKey: (key: string) => any;
  artifactByKey: (key: string) => any;
  revokeArtifact: (record: any, via: string) => boolean;
  statusOf: (key: string) => number;
  setStatus: (key: string, value: number, via: string) => boolean;
  store: Store;
  // THE TWO INDEXES (2026-10-17): see `bySubject` and `byNotification`.
  subjectIndex: Store;
  notificationIndex: Store;
  // The register's bound, `oid4vp.signInRegisterMaxEntries` (2026-09-18).
  maxRows: () => number;
}

// The formats a row may describe: every format this issuer issues.
const KEPT_FORMATS = ['dc+sd-jwt', 'jwt_vc_json', 'ldp_vc'];

// How many credentials one Data Integrity row lists. A wallet re-issuing
// every few minutes for a year is the case this bounds; the oldest go first,
// which are the ones nearest expiry.
const MAX_PER_ROW = 64;

// key -> { key, kind, subject, jkt, format, configId, credentials: Issued[],
//          expiresAt, issuedAt, disownedAt, disownedVia }
// PER TRUST REALM; see the header.
// `expiresAt` (#333): the row's `expiresAt`, ms — the latest of its
// credentials', 0 when any has none (kept). A DISOWNED row keeps refusing
// until then, which is why it is not earlier.
const issued = realms.map({ persist: 'vc_issued.credentials',
                            expiresAt: realms.expiryField('expiresAt', 1) });

// THE INDEXES THE HOLDER'S PAGE READS (rcbj, 2026-10-17: "lists are
// maintained as you go rather than ... full table scans that do not scale").
// `/portal/wallet`'s history and Remove asked every row for its subject, and
// the Notification Endpoint every credential for its `notification_id`, on
// each call; both are a lookup now.
//
//   * `bySubject`: digest(subject) -> { keys: [row key, ...], expiresAt }
//   * `byNotification`: notification_id -> { keys: [row key, ...],
//     expiresAt } — every row the response reached, since a batch's copies
//     are rows of their own (#670); an entry from before names one `key`
//
// Written in `record()` and dropped where this module deletes a row
// (`sweep()`, an expired `lookup()`, `forget()`, and the rows the size bound
// evicts in `record()`, read before `cacheRegistry.makeRoom()` takes them).
// **A READER NEVER PRUNES A KEY FOR A ROW IT CANNOT SEE** (2026-10-20): this
// process's copy of a persisted store answers "not here" alike for a row
// that is gone and for one that has not arrived yet (another process's
// write still on its way through the change log, a row the restore could
// not open), and an index entry pruned on such a read was lost for good —
// the person's history read as empty from then on. A key is dropped only
// where this module deleted the row itself, or where the row it names is
// HERE and names another subject or no longer carries the notification.
// `expiresAt` is the rows', for the database's own expiry, which is what
// ends a key left behind. Rows recorded before the indexes existed are
// indexed once per realm (`ensureIndexed()`, marked by `INDEXED_MARK`).
const bySubject = realms.map({ persist: 'vc_issued.bySubject',
                               expiresAt: realms.expiryField('expiresAt', 1) });
const byNotification = realms.map({ persist: 'vc_issued.byNotification',
                                    expiresAt: realms.expiryField('expiresAt',
                                                                  1) });
// The key in `bySubject` that says the realm's rows have been indexed. Not a
// digest, so no subject can collide with it. `-v2` since 2026-10-20: the
// reader pruned a key whose row it could not see until then, so each realm
// is indexed once more, which files every row it holds under its subject
// again (`indexRow()` adds a key only once) and gives back what a pruned
// entry lost. The `-v1` mark is dropped as the scan is marked.
const INDEXED_MARK = '#indexed-v2';
const INDEXED_MARK_BEFORE = '#indexed-v1';

// Described to `/admin/caches` (rule 3ap, #38 follow-ups). It is not a cache:
// it cannot be rebuilt, and a lookup that misses refuses a sign-in — which is
// the replay kind's shape, a register whose entries are security state.
const issuedCount = cacheRegistry.register({
  name: 'oid4vp.sign-in-register',
  title: 'Wallet sign-in register',
  description: 'The credentials this realm issued for a person on an ' +
    'access token it verified, which are the only ones a wallet may sign ' +
    'in with — keyed by a digest of the issuer-signed JWT, or for ldp_vc by ' +
    'the holder key and the person.',
  owner: 'oid4vc/vc_issued.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a presented credential this realm recorded as one that may ' +
    'sign its person in',
  settings: ['oid4vci.credentialLifetimeS',
             'oid4vp.signInRegisterMaxEntries'],
  maxEntries: function (): number {
    return Number(config.value('oid4vp.signInRegisterMaxEntries'));
  },
  bound: 'Enforced: oid4vp.signInRegisterMaxEntries per realm; the row ' +
    'issued first is dropped. That fails CLOSED — a credential with no row ' +
    'signs nobody in.',
  lifetime: function (): string {
    return 'until the last credential on the row expires; a disowned row ' +
      'is kept until then too, so that it goes on refusing.';
  },
  // What `sweep()` drops, in every realm: a row whose last credential has
  // expired (#49 P5).
  eject: cacheRegistry.realmMapEjector(realms, issued,
    function (row: any, key: unknown, now: number): boolean {
      return !!(row && row.expiresAt && row.expiresAt <= now);
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, issued,
      function (row: any, key: unknown): object {
        return { key: cacheRegistry.digestKey(key),
                 validUntil: Number((row && row.expiresAt) || 0) || null,
                 valid: !(row && row.disownedAt) &&
                        !!(row && (!row.expiresAt ||
                                   row.expiresAt > Date.now())),
                 basis: row && row.disownedAt ? 'disowned' : 'time' };
      });
  }
});

/**
 * The credentials this realm issued for a directory entry (#38): the register
 * that answers whom a verified presentation signs in, since the credential's
 * own subject cannot.
 *
 * A row is written only for a person named by an access token this realm
 * verified and granted for credential issuance.
 */
class VcIssued {
  /**
   * The formats a row may describe: `dc+sd-jwt`, `jwt_vc_json` and `ldp_vc`.
   */
  static readonly KEPT_FORMATS = KEPT_FORMATS;
  /**
   * How many credentials one Data Integrity row lists; the oldest go first.
   */
  static readonly MAX_PER_ROW = MAX_PER_ROW;

  /**
   * Builds the register from the modules and store it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: VcIssuedDeps) {
    deps.log.debug("Entering VcIssued.constructor().");
    deps.log.debug("Leaving VcIssued.constructor().");
  }

  // What the composition root passes, from the real modules.
  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): VcIssuedDeps {
    helpers.log.debug("Entering VcIssued.defaultDeps().");
    helpers.log.debug("Leaving VcIssued.defaultDeps().");
    return {
      log: helpers.log,
      nameForSubject: helpers.nameForSubject,
      subjectForName: helpers.subjectForName,
      jwkThumbprint: stsCrypto.jwkThumbprint,
      artifactRevokedByKey: stats.artifactRevokedByKey,
      artifactByKey: stats.artifactByKey,
      revokeArtifact: stats.revokeArtifact,
      statusOf: vcStatus.statusOf,
      setStatus: vcStatus.setStatus,
      store: issued,
      subjectIndex: bySubject,
      notificationIndex: byNotification,
      maxRows: function (): number {
        return Number(config.value('oid4vp.signInRegisterMaxEntries'));
      }
    };
  }

  // The part of a JOSE credential or presentation this register is keyed
  // by: everything before the first `~`, which for an SD-JWT is the
  // issuer-signed JWT and for a plain JWT is the whole of it. Hashed, so the
  // key is not a credential.
  /**
   * Returns the key a JOSE credential or presentation is registered under: a
   * SHA-256 of everything before its first `~`.
   *
   * @param credential - the credential or presentation
   * @returns the digest
   */
  digestOf(credential: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcIssued.digestOf().");
    const jwt = String(credential || '').split('~')[0];
    const digest = stsCrypto.digest('sha256', Buffer.from(jwt, 'ascii'),
                                    'base64url');
    log.debug("Leaving VcIssued.digestOf().");
    return digest;
  }

  private keyForJose(credential: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcIssued.keyForJose().");
    log.debug("Leaving VcIssued.keyForJose().");
    return 'jws:' + this.digestOf(credential);
  }

  private keyForHolder(jkt: string, subject: string): string {
    const { log } = this.deps;
    log.debug("Entering VcIssued.keyForHolder().");
    log.debug("Leaving VcIssued.keyForHolder().");
    return 'ldp:' + jkt + ':' +
           stsCrypto.digest('sha256', String(subject), 'base64url');
  }

  // ---------------------------------------------------------------------------
  // WHICH SUBJECT A VERIFIED ACCESS TOKEN NAMES A PERSON BY, or ''.
  //
  // Asked by the credential endpoint before anything is recorded, and every
  // condition is a reason the credential could otherwise sign in somebody who
  // never asked for it:
  //
  //   * `verified` — the token's signature verified against THIS realm's key
  //     and nobody has disowned it (the caller asks the revocation set). An
  //     unverified token's `sub` is a string its holder wrote.
  //   * the subject is `urn:uuid:` — the one form this service issues for a
  //     person. A client's own id is not a person.
  //   * it names an entry NOW, and that entry's subject is this one — so an
  //     entry deleted between the token and the credential is nobody.
  //   * the token was GRANTED FOR CREDENTIAL ISSUANCE: a scope one of this
  //     issuer's configurations names, or an `openid_credential`
  //     authorization detail. Without this, any access token issued to any
  //     client on a person's behalf could be turned into a credential that
  //     signs that person in, which is a larger power than the person
  //     granted that client.
  // ---------------------------------------------------------------------------
  /**
   * Returns the person an access token names, when a credential issued on it
   * may later sign them in: verified by this realm, a `urn:uuid:` subject
   * naming an entry now, and granted for credential issuance.
   *
   * @param claims - the access token's claims
   * @param verified - whether its signature verified against this realm's key
   *   and it is not disowned
   * @param credentialScopes - the scopes this issuer's configurations name
   * @returns the subject, or '' when none qualifies
   */
  subjectFromToken(claims: any, verified: boolean,
                   credentialScopes: string[]): string {
    const { log, nameForSubject, subjectForName } = this.deps;
    log.debug("Entering VcIssued.subjectFromToken(). verified=" + !!verified);
    const t = claims || {};
    const sub = String(t.sub || '');
    if (!verified) {
      log.debug("Leaving VcIssued.subjectFromToken(). Not a token this realm " +
                "verified.");
      return '';
    }
    if (!/^urn:uuid:/i.test(sub)) {
      log.debug("Leaving VcIssued.subjectFromToken(). Not a person's " +
                "subject.");
      return '';
    }
    const name = nameForSubject(sub);
    if (!name || subjectForName(name) !== sub) {
      log.debug("Leaving VcIssued.subjectFromToken(). The subject names no " +
                "entry.");
      return '';
    }
    const scopes = String(t.scope || '').split(/\s+/).filter(Boolean);
    const byScope = scopes.some(function (one) {
      return credentialScopes.indexOf(one) >= 0;
    });
    const byDetails = [].concat(t.authorization_details || [])
      .some(function (d: any) {
        return !!d && d.type === 'openid_credential';
      });
    if (!byScope && !byDetails) {
      log.debug("Leaving VcIssued.subjectFromToken(). The token was not " +
                "granted for credential issuance.");
      return '';
    }
    log.debug("Leaving VcIssued.subjectFromToken(). " + sub);
    return sub;
  }

  // Records one issued credential and answers the row key, or '' when
  // nothing was kept. Never throws: a register that could not be written
  // costs that credential the ability to sign somebody in, and must not cost
  // the wallet the credential.
  /**
   * Records one issued credential. Never throws: a failure costs the credential
   * the ability to sign somebody in, not the wallet the credential.
   *
   * @param entry - the credential, its format, configuration, subject, holder
   *   key (and DID, for `ldp_vc`), expiry and status and validity details;
   *   `announce: false` sends no CAEP signal, for the second and later copies
   *   of one batch
   * @returns the row key, or '' when nothing was kept
   */
  record(entry: { credential: unknown; format: string; configId: string;
                  subject: string; holderJwk: any; expiresAt: number;
                  artifactKey?: string; statusKey?: string;
                  validFrom?: string; validUntil?: string;
                  keyStorage?: string[];
                  userAuthentication?: string[];
                  notificationId?: string; holderDid?: string;
                  announce?: boolean }): string {
    const { log, store, jwkThumbprint } = this.deps;
    log.debug("Entering VcIssued.record(). format=" + entry.format);
    const format = String(entry.format || '');
    if (KEPT_FORMATS.indexOf(format) < 0 || !entry.subject ||
        !entry.holderJwk || !entry.credential) {
      log.debug("Leaving VcIssued.record(). Nothing to keep.");
      return '';
    }
    let jkt = '';
    try {
      jkt = jwkThumbprint(entry.holderJwk, {});
    } catch (e) {
      log.debug("Caught in VcIssued.record(): " + ((e && e.message) || e));
      // A holder key with no thumbprint cannot be compared at sign-in, so the
      // credential is not kept rather than kept unbound.
      log.debug("Leaving VcIssued.record(). The holder key has no " +
                "thumbprint.");
      return '';
    }
    this.sweep();
    const now = Date.now();
    const one: Issued = {
      artifactKey: String(entry.artifactKey || ''),
      statusKey: String(entry.statusKey || ''),
      issuedAt: now,
      validFrom: String(entry.validFrom || ''),
      validUntil: String(entry.validUntil || ''),
      expiresAt: Number(entry.expiresAt) || 0,
      keyStorage: [].concat(entry.keyStorage || []).map(String),
      userAuthentication: [].concat(entry.userAuthentication || []).map(String),
      notificationId: String(entry.notificationId || ''),
      walletEvent: '',
      walletEventAt: 0,
      removedAt: 0,
      removedVia: '',
      holderDid: String(entry.holderDid || '')
    };
    const ldp = format === 'ldp_vc';
    const key = ldp ? this.keyForHolder(jkt, entry.subject)
                    : this.keyForJose(entry.credential);
    const before = ldp ? store.get(key) : null;
    const credentials: Issued[] = before && Array.isArray(before.credentials)
      ? before.credentials.concat([one]).slice(-MAX_PER_ROW) : [one];
    const expiresAt = credentials.reduce(function (latest, c) {
      return !c.expiresAt || !latest ? 0 : Math.max(latest, c.expiresAt);
    }, one.expiresAt || 0);
    // THE BOUND (oid4vp.signInRegisterMaxEntries), for a NEW row. The row
    // issued first goes, which fails CLOSED: a credential with no row signs
    // nobody in — exactly what disowning one does — so no bound here can
    // let a credential in that should not be.
    if (!before && !store.get(key)) {
      this.makeRoomIndexed();
    }
    // THROUGH THE STORE, whole, so the journal carries the row.
    store.set(key, {
      key: key,
      kind: ldp ? 'holder' : 'jws',
      subject: String(entry.subject),
      jkt: jkt,
      format: format,
      configId: String(entry.configId || ''),
      credentials: credentials,
      expiresAt: expiresAt,
      issuedAt: before ? before.issuedAt : now,
      disownedAt: before ? Number(before.disownedAt) || 0 : 0,
      disownedVia: before ? String(before.disownedVia || '') : ''
    });
    this.indexRow(store.get(key));
    // ONE SIGNAL PER ISSUANCE (#670): the copies of a batch are one
    // credential to the person, so the issuer announces the first only.
    const holder = entry.announce === false ? ''
      : this.deps.nameForSubject(String(entry.subject));
    if (holder) {
      accountSignals.credentialChanged({ username: holder,
        credentialType: 'verifiable-credential', changeType: 'create',
        friendlyName: String(entry.configId || format),
        initiatingEntity: 'user', via: 'OpenID4VCI',
        reasonAdmin: 'A ' + String(entry.configId || format) + ' credential ' +
                     'was issued to ' + holder + '.',
        reasonUser: 'A credential was issued to your wallet.' });
    }
    log.debug("Leaving VcIssued.record(). Kept.");
    return key;
  }

  // The row for a presented JOSE credential, or null — an expired row is
  // removed on the way past.
  /**
   * Returns the row for a presented JOSE credential; an expired row is removed
   * on the way past.
   *
   * @param credential - the presented credential
   * @returns the row, or null
   */
  lookup(credential: unknown): any {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.lookup().");
    const key = this.keyForJose(credential);
    const row = store.get(key);
    if (!row) {
      issuedCount.miss();
      log.debug("Leaving VcIssued.lookup(). Not issued here for an entry.");
      return null;
    }
    if (row.expiresAt && row.expiresAt <= Date.now()) {
      store.delete(key);
      this.unindexRow(row);
      issuedCount.miss();
      log.debug("Leaving VcIssued.lookup(). Expired.");
      return null;
    }
    issuedCount.hit();
    log.debug("Leaving VcIssued.lookup(). Found.");
    return row;
  }

  // The live Data Integrity rows for one holder key, whoever they name.
  /**
   * Returns the live Data Integrity rows for one holder key.
   *
   * @param jkt - the holder key's JWK thumbprint
   * @returns the rows
   */
  lookupHolder(jkt: string): any[] {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.lookupHolder().");
    const now = Date.now();
    const out: any[] = [];
    store.forEach(function (row) {
      if (row && row.kind === 'holder' && row.jkt === String(jkt || '') &&
          (!row.expiresAt || row.expiresAt > now)) {
        out.push(row);
      }
    });
    if (out.length) {
      issuedCount.hit();
    } else {
      issuedCount.miss();
    }
    log.debug("Leaving VcIssued.lookupHolder(). " + out.length + " row(s).");
    return out;
  }

  // The credentials on a row a presentation could be, for a Data Integrity
  // row the ones whose disclosed validity window matches. An empty window
  // matches nothing: a sign-in asks the wallet for it.
  /**
   * Returns the credentials on a row a presentation could be: for a Data
   * Integrity row, those whose disclosed validity window matches. An empty
   * window matches nothing.
   *
   * @param row - the row
   * @param window - the presentation's disclosed `validFrom` and `validUntil`
   * @returns the candidate credentials
   */
  credentialsMatching(row: any, window?: { validFrom?: string;
                                            validUntil?: string }): Issued[] {
    const { log } = this.deps;
    log.debug("Entering VcIssued.credentialsMatching().");
    const list: Issued[] = [].concat((row && row.credentials) || []);
    if (!row || row.kind !== 'holder') {
      log.debug("Leaving VcIssued.credentialsMatching(). The one credential.");
      return list;
    }
    const w = window || {};
    const wanted = list.filter(function (c) {
      return !!w.validFrom && !!w.validUntil &&
             c.validFrom === String(w.validFrom) &&
             c.validUntil === String(w.validUntil);
    });
    log.debug("Leaving VcIssued.credentialsMatching(). " + wanted.length +
              " of " + list.length + ".");
    return wanted;
  }

  // ---------------------------------------------------------------------------
  // WHY THESE CREDENTIALS SIGN NOBODY IN ANY MORE, or ''. See the header for
  // the three acts. Asked of the credentials a presentation COULD be; for a
  // Data Integrity row those are every sibling with the same validity window,
  // and any one of them disowned disowns the presentation, because nothing in
  // an unlinkable proof says which sibling it came from.
  // ---------------------------------------------------------------------------
  /**
   * Says why these credentials sign nobody in any more; any one candidate
   * disowned disowns the presentation.
   *
   * @param row - the row
   * @param candidates - the credentials the presentation could be
   * @returns the reason, or ''
   */
  disownedReason(row: any, candidates: Issued[]): string {
    const { log, artifactRevokedByKey, statusOf } = this.deps;
    log.debug("Entering VcIssued.disownedReason().");
    const disownedAt = Number((row && row.disownedAt) || 0);
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i];
      if (disownedAt && c.issuedAt <= disownedAt) {
        log.debug("Leaving VcIssued.disownedReason(). Signed out.");
        return 'a global sign-out (' + (row.disownedVia || 'unstated') +
          ') disowned the credentials issued to this wallet for this ' +
          'person before ' + new Date(disownedAt).toISOString();
      }
      if (c.removedAt) {
        log.debug("Leaving VcIssued.disownedReason(). Removed.");
        return 'its holder removed it (' + (c.removedVia || 'unstated') + ')';
      }
      const mark = c.artifactKey ? artifactRevokedByKey(c.artifactKey) : null;
      if (mark) {
        log.debug("Leaving VcIssued.disownedReason(). Revoked.");
        return 'it was revoked in this service\'s issued register (' +
          (mark.via || 'unstated') + ')';
      }
      const status = c.statusKey ? statusOf(c.statusKey) : 0;
      if (status) {
        log.debug("Leaving VcIssued.disownedReason(). Status " + status + ".");
        return 'its status list entry says ' +
          (status === 2 ? 'SUSPENDED' : status === 1 ? 'INVALID' :
            'status ' + status);
      }
    }
    log.debug("Leaving VcIssued.disownedReason(). Not disowned.");
    return '';
  }

  // ---------------------------------------------------------------------------
  // THE ROWS ONE PERSON HAS, for `logout/logout.ts`'s `wallet-credential`
  // family: the live ones whose newest credential is not disowned. `null`
  // answers every person's, for a caller that files them itself.
  // ---------------------------------------------------------------------------
  /**
   * Returns the live rows one person has whose newest credential is not
   * disowned, for the wallet-credential family of `logout`.
   *
   * @param subject - the person's subject, or null for everyone's
   * @returns the rows
   */
  rowsForSubject(subject: string | null): any[] {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.rowsForSubject().");
    const now = Date.now();
    const out: any[] = [];
    const consider = (row: any): void => {
      if (!row || (subject !== null && row.subject !== String(subject)) ||
          (row.expiresAt && row.expiresAt <= now)) {
        return;
      }
      const newest = [].concat(row.credentials || []).slice(-1);
      if (this.disownedReason(row, newest)) {
        return;
      }
      out.push(row);
    };
    // One person's through the index; everyone's (`null`) is every row by
    // definition.
    if (subject === null) {
      store.forEach(consider);
    } else {
      this.rowsOfSubject(String(subject)).forEach(consider);
    }
    log.debug("Leaving VcIssued.rowsForSubject(). " + out.length + ".");
    return out;
  }

  // One row by key, or null.
  /**
   * Returns one row by key.
   *
   * @param key - the row key
   * @returns the row, or null
   */
  rowByKey(key: unknown): any {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.rowByKey().");
    log.debug("Leaving VcIssued.rowByKey().");
    return store.get(String(key || '')) || null;
  }

  // ---------------------------------------------------------------------------
  // DISOWN A ROW: every credential on it issued up to now stops signing
  // anybody in, and each one's status-list bit is set INVALID so a verifier
  // elsewhere learns it too. Answers whether anything changed.
  // ---------------------------------------------------------------------------
  /**
   * Disowns a row: every credential on it issued up to now stops signing
   * anybody in, and each one's status-list bit is set invalid.
   *
   * @param key - the row key
   * @param via - who or what disowned it
   * @returns true when anything changed
   */
  disown(key: unknown, via: string): boolean {
    const { log, store, setStatus } = this.deps;
    log.debug("Entering VcIssued.disown().");
    const row = store.get(String(key || ''));
    if (!row) {
      log.debug("Leaving VcIssued.disown(). No such row.");
      return false;
    }
    const now = Date.now();
    row.disownedAt = now;
    row.disownedVia = String(via || 'unstated');
    store.set(String(key), row);
    [].concat(row.credentials || []).forEach(function (c: Issued) {
      if (c.statusKey && c.issuedAt <= now) {
        setStatus(c.statusKey, 1, row.disownedVia);
      }
    });
    log.info('oid4vp-signin: the wallet credentials on row ' +
             cacheRegistry.digestKey(key) + ' were disowned (' +
             row.disownedVia + ').');
    const holder = this.deps.nameForSubject(String(row.subject || ''));
    if (holder) {
      accountSignals.credentialChanged({ username: holder,
        credentialType: 'verifiable-credential', changeType: 'revoke',
        initiatingEntity: 'system', via: row.disownedVia,
        reasonAdmin: 'The wallet credentials this realm issued ' + holder +
                     ' were disowned (' + row.disownedVia + ').',
        reasonUser: 'The credentials in your wallet from this service were ' +
                    'revoked.' });
    }
    log.debug("Leaving VcIssued.disown(). Disowned.");
    return true;
  }

  // ---------------------------------------------------------------------------
  // ONE PERSON'S HISTORY, for `/portal/wallet` (#661, 2026-10-16): every
  // credential still on a row of theirs, newest first, each with its state
  // and the wallet's last report. A row goes when its last credential
  // expires, so this is what the register still holds, not every credential
  // ever issued. Since #670 the page reads it through
  // `issuancesForSubject()`, which groups it; this is the copies.
  //
  // `id` is a digest of the row and the credential, never the row key: a
  // JOSE row's key is a digest of the credential itself.
  // ---------------------------------------------------------------------------
  /**
   * Returns every credential still recorded for one person, newest first.
   *
   * @param subject - the person's `urn:uuid:` subject
   * @returns the history, one entry per credential
   */
  historyForSubject(subject: string): HistoryEntry[] {
    const { log } = this.deps;
    log.debug("Entering VcIssued.historyForSubject().");
    const out = this.copiesOfSubject(String(subject || ''))
      .map(function (one) {
        return one.entry;
      });
    out.sort(function (a, b) {
      return b.issuedAt - a.issuedAt;
    });
    log.debug("Leaving VcIssued.historyForSubject(). " + out.length + ".");
    return out;
  }

  // ---------------------------------------------------------------------------
  // ONE PERSON'S ISSUANCES (#670, rcbj 2026-10-17): the copies grouped by the
  // Credential Response they came in (the header's *A BATCH IS ONE
  // ISSUANCE*), newest issuance first and its copies oldest first, which is
  // the order the wallet's proofs were in. An issuance's state is its
  // copies' where they agree and `mixed` where they do not, with how many
  // are in each; `/portal/wallet` pages these, so a page counts issuances.
  //
  // An issuance's `id` is a digest of a different string from a copy's, so
  // the two kinds of id cannot be one another and `removeForSubject()` can
  // take either.
  // ---------------------------------------------------------------------------
  /**
   * Returns one person's issuances, newest first: each the copies one
   * Credential Response carried, bound to different keys of the wallet's.
   *
   * @param subject - the person's `urn:uuid:` subject
   * @returns the issuances
   */
  issuancesForSubject(subject: string): IssuanceEntry[] {
    const { log } = this.deps;
    log.debug("Entering VcIssued.issuancesForSubject().");
    const groups: { [key: string]: IssuanceEntry } = {};
    const order: string[] = [];
    this.copiesOfSubject(String(subject || '')).forEach((one) => {
      const e = one.entry;
      let group = groups[e.issuance];
      if (!group) {
        group = { id: this.issuanceId(e.issuance), format: e.format,
                  configId: e.configId, issuedAt: e.issuedAt,
                  expiresAt: e.expiresAt, status: '', counts: {},
                  removedAt: 0, walletEvent: '', walletEventAt: 0,
                  copies: [] };
        groups[e.issuance] = group;
        order.push(e.issuance);
      }
      group.copies.push(e);
      group.issuedAt = Math.min(group.issuedAt, e.issuedAt);
      // The latest expiry, and none where any copy has none.
      group.expiresAt = !group.expiresAt || !e.expiresAt ? 0
        : Math.max(group.expiresAt, e.expiresAt);
      group.counts[e.status] = (group.counts[e.status] || 0) + 1;
      group.removedAt = Math.max(group.removedAt, e.removedAt);
      if (e.walletEventAt > group.walletEventAt) {
        group.walletEvent = e.walletEvent;
        group.walletEventAt = e.walletEventAt;
      }
    });
    const out = order.map(function (key) {
      const group = groups[key];
      const states = Object.keys(group.counts);
      group.status = states.length === 1 ? states[0] : 'mixed';
      // The copies keep the order they were recorded in, which a sort on
      // the same millisecond would not promise.
      group.copies = group.copies.map(function (c, i) {
        return { c: c, i: i };
      }).sort(function (a, b) {
        return (a.c.issuedAt - b.c.issuedAt) || (a.i - b.i);
      }).map(function (one) {
        return one.c;
      });
      return group;
    });
    out.sort(function (a, b) {
      return b.issuedAt - a.issuedAt;
    });
    log.debug("Leaving VcIssued.issuancesForSubject(). " + out.length + ".");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE HOLDER REMOVES A CREDENTIAL (#661, 2026-10-16; every copy or one,
  // #670). OpenID4VP and OpenID4VCI give an issuer no way to delete a
  // credential from a wallet, so removing is this service's half: each copy
  // removed has its status-list entry set INVALID (final, and what a
  // verifier elsewhere reads), its issued-register row marked revoked, and
  // is stamped removed, which `disownedReason()` refuses at sign-in. Only the
  // credentials named — for an `ldp_vc` row, not its siblings, which
  // `disown()` would take with it. The holder deletes the wallet's copies
  // themselves.
  //
  // `id` is a COPY's (`historyForSubject()`, an issuance's `copies[].id`),
  // which removes that copy alone, or an ISSUANCE's
  // (`issuancesForSubject()`), which removes every copy of it still good.
  // One act, so ONE CAEP signal, whatever the number of copies.
  //
  // The subject is the caller's, never a parameter (`account-api/CLAUDE.md`):
  // an id that is not on one of THEIR rows is refused as unknown, whoever's
  // it is.
  // ---------------------------------------------------------------------------
  /**
   * Removes one of a person's credentials, or every copy of one issuance:
   * each copy's status-list entry INVALID, its issued-register row revoked,
   * and the copy refused at sign-in.
   *
   * @param subject - the person's `urn:uuid:` subject
   * @param id - a copy's id, or an issuance's, from `issuancesForSubject()`
   * @param via - who removed it, and where
   * @returns `{ ok, already, scope, removed, copies }`, or
   *   `{ ok: false, error }`
   */
  removeForSubject(subject: string, id: string,
                   via: string): { ok: boolean; already?: boolean;
                                   scope?: string; removed?: number;
                                   copies?: number; error?: string } {
    const { log, store, setStatus, artifactByKey, revokeArtifact } = this.deps;
    log.debug("Entering VcIssued.removeForSubject().");
    const wanted = String(id || '');
    const mine = this.copiesOfSubject(String(subject || ''));
    let scope = 'copy';
    let targets = mine.filter(function (one) {
      return one.entry.id === wanted;
    });
    if (!targets.length) {
      scope = 'issuance';
      targets = mine.filter((one) => {
        return this.issuanceId(one.entry.issuance) === wanted;
      });
    }
    if (!wanted || !targets.length) {
      log.debug("Leaving VcIssued.removeForSubject(). Not one of theirs.");
      return { ok: false, error: 'You have no credential with that id. The ' +
        'list on /portal/wallet shows the ones this service still records ' +
        'for you.' };
    }
    const fresh = targets.filter(function (one) {
      return !one.c.removedAt;
    });
    if (!fresh.length) {
      log.debug("Leaving VcIssued.removeForSubject(). Already removed.");
      return { ok: true, already: true, scope: scope, removed: 0,
               copies: targets.length };
    }
    const why = String(via || 'unstated');
    const now = Date.now();
    const touched: { [key: string]: any } = {};
    fresh.forEach(function (one) {
      one.c.removedAt = now;
      one.c.removedVia = why;
      touched[String(one.row.key)] = one.row;
    });
    // THROUGH THE STORE, whole, so the journal carries each row once.
    Object.keys(touched).forEach(function (key) {
      store.set(key, touched[key]);
    });
    fresh.forEach(function (one) {
      if (one.c.statusKey) {
        setStatus(one.c.statusKey, 1, why);
      }
      if (one.c.artifactKey) {
        const artifact = artifactByKey(one.c.artifactKey);
        if (artifact) {
          revokeArtifact(artifact, why);
        }
      }
    });
    const row = fresh[0].row;
    log.info('oid4vp-signin: ' + fresh.length + ' credential(s) on ' +
             Object.keys(touched).length + ' row(s), the first ' +
             cacheRegistry.digestKey(row.key) + ', were removed by their ' +
             'holder (' + why + ').');
    const holder = this.deps.nameForSubject(String(row.subject || ''));
    if (holder) {
      const what = String(row.configId || row.format);
      accountSignals.credentialChanged({ username: holder,
        credentialType: 'verifiable-credential', changeType: 'revoke',
        friendlyName: what,
        initiatingEntity: 'user', via: why,
        reasonAdmin: holder + ' removed ' + (fresh.length > 1
          ? fresh.length + ' copies of a ' : 'a ') + what + ' credential ' +
          'this realm issued them (' + why + ').',
        reasonUser: 'You removed a credential this service issued to your ' +
                    'wallet.' });
    }
    log.debug("Leaving VcIssued.removeForSubject(). Removed " + fresh.length +
              ".");
    return { ok: true, already: false, scope: scope, removed: fresh.length,
             copies: targets.length };
  }

  // ---------------------------------------------------------------------------
  // WHAT THE WALLET REPORTED (OpenID4VCI 1.0 section 11): stamped on every
  // credential the Credential Response with this `notification_id` carried.
  // It is the wallet's word and changes nothing else — a wallet that deleted
  // its copy has not revoked anything, and one that says it accepted a
  // credential cannot reinstate one.
  //
  // EVERY ROW THE RESPONSE REACHED (#670): a batch's copies are on rows of
  // their own, so the index names each of them (`keys`); an entry written
  // before then names one (`key`), and is read as a list of one.
  // ---------------------------------------------------------------------------
  /**
   * Records a wallet's notification event on the credentials it names.
   *
   * @param notificationId - the Credential Response's `notification_id`
   * @param event - `credential_accepted`, `credential_failure` or
   *   `credential_deleted`
   * @returns how many credentials it was recorded on
   */
  noteWalletEvent(notificationId: string, event: string): number {
    const { log, store, notificationIndex } = this.deps;
    log.debug("Entering VcIssued.noteWalletEvent().");
    const id = String(notificationId || '');
    let count = 0;
    if (!id) {
      log.debug("Leaving VcIssued.noteWalletEvent(). No id.");
      return 0;
    }
    this.ensureIndexed();
    const now = Date.now();
    const entry = notificationIndex.get(id);
    const keys = this.keysOf(entry);
    const live: string[] = [];
    let failures = 0;
    let error: unknown = '';
    keys.forEach((key) => {
      const read = this.readRow(key);
      // A ROW NOT HERE, OR NOT READABLE, KEEPS ITS KEY: the index's header
      // comment says why.
      if (read.failed || !read.row) {
        failures += read.failed ? 1 : 0;
        error = read.failed ? read.error : error;
        live.push(key);
        return;
      }
      const row = read.row;
      let here = 0;
      [].concat(row.credentials || []).forEach(function (c: Issued) {
        if (c.notificationId === id) {
          c.walletEvent = String(event || '');
          c.walletEventAt = now;
          here += 1;
        }
      });
      // A row that is here and no longer carries the notification (its
      // oldest credentials went at MAX_PER_ROW) is pruned: a fact about the
      // row.
      if (here) {
        live.push(key);
        store.set(key, row);
        count += here;
      }
    });
    this.reportUnreadable('a wallet\'s notification names', failures, error);
    if (entry && live.length !== keys.length) {
      if (live.length) {
        notificationIndex.set(id, { keys: live,
                                    expiresAt: entry.expiresAt || 0 });
      } else {
        notificationIndex.delete(id);
      }
    }
    log.debug("Leaving VcIssued.noteWalletEvent(). " + count + ".");
    return count;
  }

  // ---------------------------------------------------------------------------
  // THE INDEXES (2026-10-17): kept as rows are written and dropped, so a
  // person's rows and a notification's row are a lookup, never a scan.
  // ---------------------------------------------------------------------------
  private subjectKey(subject: string): string {
    return stsCrypto.digest('sha256', String(subject), 'base64url');
  }

  // Files a row under its subject, and each credential's notification_id.
  private indexRow(row: any): void {
    const { subjectIndex, notificationIndex } = this.deps;
    if (!row || !row.key || !row.subject) {
      return;
    }
    const k = this.subjectKey(row.subject);
    const entry = subjectIndex.get(k) || { keys: [], expiresAt: 0 };
    const keys: string[] = [].concat(entry.keys || []);
    if (keys.indexOf(String(row.key)) < 0) {
      keys.push(String(row.key));
    }
    // The latest expiry of the rows it names, 0 while any never expires —
    // a row's own rule (`record()`).
    const expiresAt = !entry.keys || !entry.keys.length
      ? Number(row.expiresAt) || 0
      : (!entry.expiresAt || !row.expiresAt ? 0
        : Math.max(Number(entry.expiresAt), Number(row.expiresAt)));
    subjectIndex.set(k, { keys: keys, expiresAt: expiresAt });
    // EVERY ROW A RESPONSE REACHED (#670): a batch's copies are on rows of
    // their own and share the response's `notification_id`.
    [].concat(row.credentials || []).forEach((c: Issued) => {
      if (!c.notificationId) {
        return;
      }
      const was = notificationIndex.get(c.notificationId);
      const named = this.keysOf(was);
      if (named.indexOf(String(row.key)) >= 0) {
        return;
      }
      const at = Number(c.expiresAt) || 0;
      notificationIndex.set(c.notificationId,
                            { keys: named.concat([String(row.key)]),
                              expiresAt: !was ? at
                                : (!was.expiresAt || !at ? 0
                                  : Math.max(Number(was.expiresAt), at)) });
    });
  }

  // The row keys a notification index entry names: `keys`, or the one `key`
  // an entry written before #670 carries.
  private keysOf(entry: any): string[] {
    const { log } = this.deps;
    log.debug("Entering VcIssued.keysOf().");
    if (!entry) {
      log.debug("Leaving VcIssued.keysOf(). No entry.");
      return [];
    }
    if (Array.isArray(entry.keys)) {
      log.debug("Leaving VcIssued.keysOf().");
      return entry.keys.map(String);
    }
    log.debug("Leaving VcIssued.keysOf(). An entry from before #670.");
    return entry.key ? [String(entry.key)] : [];
  }

  // Takes a deleted row out of both indexes.
  private unindexRow(row: any): void {
    const { subjectIndex, notificationIndex } = this.deps;
    if (!row || !row.key) {
      return;
    }
    if (row.subject) {
      const k = this.subjectKey(row.subject);
      const entry = subjectIndex.get(k);
      if (entry) {
        const keys = [].concat(entry.keys || []).filter(function (one) {
          return one !== String(row.key);
        });
        if (keys.length) {
          subjectIndex.set(k, { keys: keys, expiresAt: entry.expiresAt });
        } else {
          subjectIndex.delete(k);
        }
      }
    }
    [].concat(row.credentials || []).forEach((c: Issued) => {
      const entry = c.notificationId ? notificationIndex.get(c.notificationId)
                                     : null;
      const named = this.keysOf(entry);
      if (named.indexOf(String(row.key)) < 0) {
        return;
      }
      const left = named.filter(function (one) {
        return one !== String(row.key);
      });
      if (left.length) {
        notificationIndex.set(c.notificationId,
                              { keys: left, expiresAt: entry.expiresAt });
      } else {
        notificationIndex.delete(c.notificationId);
      }
    });
  }

  // THE SIZE BOUND, WITH THE INDEXES KEPT. `makeRoom()` deletes the oldest
  // rows without saying which, so the rows it can take — the first
  // `size - limit + 1` in the store's order, which is the order it deletes
  // in — are read first, and each one no longer in this process's store
  // once it returns leaves both indexes: the one place a row's absence is a
  // FACT, because this process has just deleted it.
  private makeRoomIndexed(): void {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.makeRoomIndexed().");
    const limit = Number(this.deps.maxRows());
    const over = isFinite(limit) && limit > 0 ? store.size - limit + 1 : 0;
    const candidates: any[] = [];
    if (over > 0) {
      const keys = store.keys();
      for (let i = 0; i < over; i += 1) {
        const next = keys.next();
        if (next.done) {
          break;
        }
        candidates.push({ key: next.value, row: store.get(next.value) });
      }
    }
    cacheRegistry.makeRoom(store, limit, { counter: issuedCount });
    let unindexed = 0;
    candidates.forEach((one) => {
      if (one.row && !store.has(one.key)) {
        this.unindexRow(one.row);
        unindexed += 1;
      }
    });
    log.debug("Leaving VcIssued.makeRoomIndexed(). " + unindexed +
              " evicted.");
  }

  // One row of the register, or what kept it from being read: `failed`
  // where the store threw, which a reader must not take for a row that is
  // gone (STS-VC-0151 at the reader, once per read).
  private readRow(key: string): { row: any; failed: boolean;
                                  error: unknown } {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.readRow().");
    try {
      const row = store.get(key);
      log.debug("Leaving VcIssued.readRow().");
      return { row: row, failed: false, error: '' };
    } catch (e) {
      log.debug("Caught in VcIssued.readRow(): " + ((e && e.message) || e));
      log.debug("Leaving VcIssued.readRow(). The store threw.");
      return { row: null, failed: true, error: (e && e.message) || e };
    }
  }

  // Says, once per read, that some of an index entry's rows could not be
  // read and the entry was left as it was.
  private reportUnreadable(which: string, failures: number,
                           error: unknown): void {
    const { log } = this.deps;
    log.debug("Entering VcIssued.reportUnreadable().");
    if (failures) {
      log.error(errorCodes.tag('STS-VC-0151') + 'vc_issued: ' + failures +
                ' row(s) ' + which + ' could not be read from the issued ' +
                'register, and the index entry naming them was left as it ' +
                'was: ' + String(error));
    }
    log.debug("Leaving VcIssued.reportUnreadable().");
  }

  // One person's rows through the index. A key whose row this process does
  // not hold, or could not read, is SKIPPED AND KEPT (the index's header
  // comment says why); only a row that is here and names another subject is
  // pruned, which is a fact about the row rather than about this process's
  // view of the store.
  private rowsOfSubject(subject: string): any[] {
    const { log, subjectIndex } = this.deps;
    log.debug("Entering VcIssued.rowsOfSubject().");
    if (!subject) {
      log.debug("Leaving VcIssued.rowsOfSubject(). No subject.");
      return [];
    }
    this.ensureIndexed();
    const k = this.subjectKey(subject);
    const entry = subjectIndex.get(k);
    if (!entry) {
      log.debug("Leaving VcIssued.rowsOfSubject(). Not indexed.");
      return [];
    }
    const rows: any[] = [];
    const kept: string[] = [];
    let missing = 0;
    let failures = 0;
    let error: unknown = '';
    [].concat(entry.keys || []).forEach((key: string) => {
      const read = this.readRow(key);
      if (read.failed) {
        failures += 1;
        error = read.error;
        kept.push(key);
        return;
      }
      if (!read.row) {
        missing += 1;
        kept.push(key);
        return;
      }
      if (read.row.subject === subject) {
        rows.push(read.row);
        kept.push(key);
      }
    });
    this.reportUnreadable('of one person\'s history', failures, error);
    if (kept.length !== (entry.keys || []).length) {
      if (kept.length) {
        subjectIndex.set(k, { keys: kept, expiresAt: entry.expiresAt });
      } else {
        subjectIndex.delete(k);
      }
    }
    log.debug("Leaving VcIssued.rowsOfSubject(). " + rows.length +
              " row(s), " + missing + " not here, " + failures +
              " unreadable.");
    return rows;
  }

  // ONCE PER REALM, the rows recorded before the indexes existed: the one
  // scan, marked in the index's own store so no process repeats it.
  private ensureIndexed(): void {
    const { log, store, subjectIndex } = this.deps;
    if (subjectIndex.get(INDEXED_MARK)) {
      return;
    }
    log.debug("Entering VcIssued.ensureIndexed(). Indexing the register.");
    let count = 0;
    store.forEach((row) => {
      this.indexRow(row);
      count += 1;
    });
    subjectIndex.set(INDEXED_MARK, { at: Date.now(), expiresAt: 0 });
    if (subjectIndex.get(INDEXED_MARK_BEFORE)) {
      subjectIndex.delete(INDEXED_MARK_BEFORE);
    }
    log.debug("Leaving VcIssued.ensureIndexed(). " + count + " row(s).");
  }

  // ONE PERSON'S COPIES, each with its row and its history entry, in the
  // order they were recorded: rows as the subject index lists them, and
  // credentials as each row lists them.
  private copiesOfSubject(subject: string): { row: any; c: Issued;
                                              entry: HistoryEntry }[] {
    const { log } = this.deps;
    log.debug("Entering VcIssued.copiesOfSubject().");
    const now = Date.now();
    const out: { row: any; c: Issued; entry: HistoryEntry }[] = [];
    this.rowsOfSubject(subject).forEach((row) => {
      [].concat(row.credentials || []).forEach((c: Issued) => {
        const id = this.credentialId(row, c);
        out.push({ row: row, c: c, entry: {
          id: id, format: String(row.format),
          configId: String(row.configId || ''),
          issuedAt: Number(c.issuedAt) || 0,
          expiresAt: Number(c.expiresAt) || 0,
          status: this.stateOf(row, c, now),
          removedAt: Number(c.removedAt) || 0,
          walletEvent: String(c.walletEvent || ''),
          walletEventAt: Number(c.walletEventAt) || 0,
          // THE ISSUANCE: the response's `notification_id`, and for a
          // credential recorded without one (before #661) itself alone.
          issuance: c.notificationId ? 'n:' + c.notificationId : 'c:' + id,
          keyThumbprint: String(row.jkt || ''),
          holderDid: String(c.holderDid || ''),
          statusIndex: String(c.statusKey || '') } });
      });
    });
    log.debug("Leaving VcIssued.copiesOfSubject(). " + out.length + ".");
    return out;
  }

  // An issuance's id: a digest of a different string from any copy's, so the
  // two cannot be one another.
  private issuanceId(issuance: string): string {
    const { log } = this.deps;
    log.debug("Entering VcIssued.issuanceId().");
    log.debug("Leaving VcIssued.issuanceId().");
    return stsCrypto.digest('sha256', 'issuance|' + String(issuance),
                            'base64url').slice(0, 22);
  }

  // A credential's id in a person's history: a digest of its row and its
  // place on it, so it says nothing about the credential.
  private credentialId(row: any, c: Issued): string {
    return stsCrypto.digest('sha256', String(row.key) + '|' +
                            String(c.issuedAt) + '|' + String(c.statusKey ||
                            c.artifactKey || ''), 'base64url').slice(0, 22);
  }

  // A credential's state, for a person's history: `removed` (by them),
  // `signed-out` (a global sign-out disowned it), `revoked` (an
  // administrator, or its status entry INVALID), `suspended`, `expired` or
  // `valid` — the first that applies.
  private stateOf(row: any, c: Issued, now: number): string {
    const { artifactRevokedByKey, statusOf } = this.deps;
    if (c.removedAt) {
      return 'removed';
    }
    const disownedAt = Number((row && row.disownedAt) || 0);
    if (disownedAt && c.issuedAt <= disownedAt) {
      return 'signed-out';
    }
    if (c.artifactKey && artifactRevokedByKey(c.artifactKey)) {
      return 'revoked';
    }
    const status = c.statusKey ? statusOf(c.statusKey) : 0;
    if (status === 2) {
      return 'suspended';
    }
    if (status) {
      return 'revoked';
    }
    if (c.expiresAt && c.expiresAt <= now) {
      return 'expired';
    }
    return 'valid';
  }

  // Takes one JOSE credential out of the sign-in path, for a test.
  /**
   * Takes one JOSE credential out of the sign-in path, for a test.
   *
   * @param credential - the credential
   * @returns true when there was a row
   */
  forget(credential: unknown): boolean {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.forget().");
    const key = this.keyForJose(credential);
    const row = store.get(key);
    const gone = store.delete(key);
    if (row) {
      this.unindexRow(row);
    }
    log.debug("Leaving VcIssued.forget(). " + gone);
    return gone;
  }

  // How many rows the ambient realm holds, for the tests and the console.
  /**
   * Returns how many rows the ambient realm holds.
   *
   * @returns the count
   */
  size(): number {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.size().");
    log.debug("Leaving VcIssued.size().");
    return store.size;
  }

  private sweep(): void {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.sweep().");
    const now = Date.now();
    const stale: any[] = [];
    store.forEach(function (row, key) {
      if (row && row.expiresAt && row.expiresAt <= now) {
        stale.push({ key: key, row: row });
      }
    });
    stale.forEach((one) => {
      store.delete(one.key);
      this.unindexRow(one.row);
    });
    log.debug("Leaving VcIssued.sweep(). " + stale.length + " expired.");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — `vc_configs.ts`'s
// arrangement: the exports are FACADES forwarding to the instance the root
// installs, and a process without the root builds a default at load.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcIssued>(
  'oid4vc/vc_issued',
  () => new VcIssued(VcIssued.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading any module on the pattern does.
slot.buildNowUnlessDeferred();

/**
 * The credentials this realm issued for a directory entry: the register a
 * wallet sign-in asks whom a presentation signs in.
 *
 * @namespace
 */
export = {
  VcIssued: VcIssued,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: VcIssued): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  KEPT_FORMATS: VcIssued.KEPT_FORMATS,
  digestOf: slot.forward('digestOf'),
  subjectFromToken: slot.forward('subjectFromToken'),
  record: slot.forward('record'),
  lookup: slot.forward('lookup'),
  lookupHolder: slot.forward('lookupHolder'),
  credentialsMatching: slot.forward('credentialsMatching'),
  disownedReason: slot.forward('disownedReason'),
  rowsForSubject: slot.forward('rowsForSubject'),
  rowByKey: slot.forward('rowByKey'),
  disown: slot.forward('disown'),
  historyForSubject: slot.forward('historyForSubject'),
  issuancesForSubject: slot.forward('issuancesForSubject'),
  removeForSubject: slot.forward('removeForSubject'),
  noteWalletEvent: slot.forward('noteWalletEvent'),
  forget: slot.forward('forget'),
  size: slot.forward('size')
};
