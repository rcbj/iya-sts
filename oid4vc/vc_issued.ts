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
//   * a GLOBAL sign-out — `/logout`, `/admin/logout`, `/admin-api/logout` —
//     ended the `wallet-credential` row `logout/logout.ts` draws from this
//     register: `disown()` stamps the row, and every credential issued at or
//     before that instant is disowned with it (a credential issued AFTER, on
//     a fresh token, is not — which is what lets a person who signed out
//     everywhere enrol a wallet again);
//   * an administrator revoked its row on `/admin/tokens` (the issued
//     register's mark, read by handle, so a restore undoes it);
//   * its status-list entry is not VALID — revoked or suspended on
//     `/admin/vc-status` or by the two acts above, which also set the bit so
//     a verifier elsewhere learns it (`vc_status.ts`).
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

import crypto = require('crypto');
import helpers = require('../common/helpers');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import stats = require('../common/admin_stats');
import cacheRegistry = require('../common/cache_registry');
import config = require('../common/config');
import InstanceSlot = require('../common/instance_slot');
// THE STATUS LISTS, whose entry for a credential is one of the three ways it
// is disowned. A library that requires nothing in this directory but its
// codec.
import vcStatus = require('./vc_status');

// The parts of a `realms.map()` store this module uses.
interface Store {
  get(key: string): any;
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
}

interface VcIssuedDeps {
  log: typeof helpers.log;
  nameForSubject: typeof helpers.nameForSubject;
  subjectForName: typeof helpers.subjectForName;
  jwkThumbprint: typeof stsCrypto.jwkThumbprint;
  artifactRevokedByKey: (key: string) => any;
  statusOf: (key: string) => number;
  setStatus: (key: string, value: number, via: string) => boolean;
  store: Store;
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
const issued = realms.map({ persist: 'vc_issued.credentials' });

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

class VcIssued {
  static readonly KEPT_FORMATS = KEPT_FORMATS;
  static readonly MAX_PER_ROW = MAX_PER_ROW;

  constructor(private readonly deps: VcIssuedDeps) {
    deps.log.debug("Entering VcIssued.constructor().");
    deps.log.debug("Leaving VcIssued.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): VcIssuedDeps {
    helpers.log.debug("Entering VcIssued.defaultDeps().");
    helpers.log.debug("Leaving VcIssued.defaultDeps().");
    return {
      log: helpers.log,
      nameForSubject: helpers.nameForSubject,
      subjectForName: helpers.subjectForName,
      jwkThumbprint: stsCrypto.jwkThumbprint,
      artifactRevokedByKey: stats.artifactRevokedByKey,
      statusOf: vcStatus.statusOf,
      setStatus: vcStatus.setStatus,
      store: issued,
      maxRows: function (): number {
        return Number(config.value('oid4vp.signInRegisterMaxEntries'));
      }
    };
  }

  // The part of a JOSE credential or presentation this register is keyed
  // by: everything before the first `~`, which for an SD-JWT is the
  // issuer-signed JWT and for a plain JWT is the whole of it. Hashed, so the
  // key is not a credential.
  digestOf(credential: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcIssued.digestOf().");
    const jwt = String(credential || '').split('~')[0];
    const digest = crypto.createHash('sha256').update(jwt, 'ascii')
      .digest('base64url');
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
    return 'ldp:' + jkt + ':' + crypto.createHash('sha256')
      .update(String(subject), 'utf8').digest('base64url');
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
  record(entry: { credential: unknown; format: string; configId: string;
                  subject: string; holderJwk: any; expiresAt: number;
                  artifactKey?: string; statusKey?: string;
                  validFrom?: string; validUntil?: string;
                  keyStorage?: string[];
                  userAuthentication?: string[] }): string {
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
      userAuthentication: [].concat(entry.userAuthentication || []).map(String)
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
      cacheRegistry.makeRoom(store, this.deps.maxRows(),
                             { counter: issuedCount });
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
    log.debug("Leaving VcIssued.record(). Kept.");
    return key;
  }

  // The row for a presented JOSE credential, or null — an expired row is
  // removed on the way past.
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
      issuedCount.miss();
      log.debug("Leaving VcIssued.lookup(). Expired.");
      return null;
    }
    issuedCount.hit();
    log.debug("Leaving VcIssued.lookup(). Found.");
    return row;
  }

  // The live Data Integrity rows for one holder key, whoever they name.
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
  rowsForSubject(subject: string | null): any[] {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.rowsForSubject().");
    const now = Date.now();
    const out: any[] = [];
    store.forEach((row) => {
      if (!row || (subject !== null && row.subject !== String(subject)) ||
          (row.expiresAt && row.expiresAt <= now)) {
        return;
      }
      const newest = [].concat(row.credentials || []).slice(-1);
      if (this.disownedReason(row, newest)) {
        return;
      }
      out.push(row);
    });
    log.debug("Leaving VcIssued.rowsForSubject(). " + out.length + ".");
    return out;
  }

  // One row by key, or null.
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
    log.debug("Leaving VcIssued.disown(). Disowned.");
    return true;
  }

  // Takes one JOSE credential out of the sign-in path, for a test.
  forget(credential: unknown): boolean {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.forget().");
    const gone = store.delete(this.keyForJose(credential));
    log.debug("Leaving VcIssued.forget(). " + gone);
    return gone;
  }

  // How many rows the ambient realm holds, for the tests and the console.
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
    const stale: string[] = [];
    store.forEach(function (row, key) {
      if (row && row.expiresAt && row.expiresAt <= now) {
        stale.push(key);
      }
    });
    stale.forEach(function (key) {
      store.delete(key);
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

export = {
  VcIssued: VcIssued,
  installInstance: (instance: VcIssued): void => slot.install(instance),
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
  forget: slot.forward('forget'),
  size: slot.forward('size')
};
