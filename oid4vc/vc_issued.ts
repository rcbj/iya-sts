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
// **WHY THE CREDENTIAL'S OWN `sub` IS NOT ENOUGH.** An SD-JWT VC this issuer
// mints says `sub: <the access token's sub>`, and since 2026-09-14 that is
// `urn:uuid:<entryUUID>` for a person this service authenticated — exactly
// the stable, non-invented reference `authn/CLAUDE.md` says a subject is. But
// the credential endpoint accepts access tokens it DID NOT ISSUE and reads
// their claims unverified (OID4VCI lets the authorization server be somebody
// else; `oauth-oidc/dpop.ts`'s `presentedAccessToken()` says so). A token
// anybody wrote, carrying `sub: urn:uuid:<alice's entryUUID>`, gets a
// credential SIGNED BY THIS REALM saying it is about alice and bound to the
// writer's key. The signature on that credential is real and says nothing
// about whether alice ever asked for it. A sign-in that read `sub` off a
// credential with a valid signature would hand alice's session to whoever
// wrote the token.
//
// So the fact that matters is recorded AT ISSUANCE, where it is known and
// nowhere else: this realm's credential endpoint issued this credential, on
// an access token THIS REALM VERIFIED, whose subject names a directory entry,
// and which was granted for credential issuance. Only a credential in this
// register may sign anybody in, and the entry it signs in is the one the
// register names — read back through the subject resolver at sign-in, so an
// entry deleted since (and a name re-created under a NEW entryUUID) signs
// nobody in.
//
// **WHAT IS KEPT, AND WHAT IS NOT.** A row is keyed by the SHA-256 of the
// issuer-signed JWT — the part of an SD-JWT before its first `~` — which is
// the one part every presentation of that credential carries unchanged,
// whatever the holder chose to disclose. The row holds the subject, the
// holder key's RFC 7638 thumbprint, the format, the configuration and the
// expiry. Never the credential and never a claim value: a copy of this store
// is a list of digests and subjects, not a list of credentials.
//
// **ONLY THE JOSE FORMATS ARE KEPT.** An `ldp_vc` is presented as a bbs-2023
// DERIVED proof, which is unlinkable to the credential by design — there is
// no byte of the issued credential in a presentation to look up — and it has
// no holder binding, so it could not sign anybody in even if it could be
// found. `jwt_vc_json` is kept, though `vc_signin.ts` asks for `dc+sd-jwt`
// only; that module's header says why.
//
// **THERE IS NO STATUS LIST, AND THIS IS THE CLOSEST THING.** The issuer
// publishes no Token Status List or revocation mechanism for a credential. A
// row lives as long as the credential it describes and is swept when that
// has expired; `forget()` removes one, which is how a test or a future
// revocation takes a credential out of the sign-in path without touching the
// credential.
//
// **PER TRUST REALM AND PERSISTED.** `realms.map({ persist })`, so a
// credential another realm issued is never in this realm's partition (its
// signature would not verify here either — two checks, on purpose), and in
// product mode a credential issued before a restart still signs its holder in
// after it, because the realm's signing key is kept too. In development mode
// the keys are regenerated on every start, every earlier credential stops
// verifying, and the rows they left behind are harmless until swept.
//
// A LIBRARY (rule 3): it registers no route, and it requires only `common/`
// leaves (`helpers`, `realms`, `crypto`, `instance_slot`) — none of which
// requires anything in this directory — so `vc_issuer.ts` (which writes) and
// `vc_verifier.ts` (which reads) can both require it without a cycle.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import InstanceSlot = require('../common/instance_slot');

// The parts of a `realms.map()` store this module uses.
interface Store {
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
  readonly size: number;
}

interface VcIssuedDeps {
  log: typeof helpers.log;
  nameForSubject: typeof helpers.nameForSubject;
  subjectForName: typeof helpers.subjectForName;
  jwkThumbprint: typeof stsCrypto.jwkThumbprint;
  store: Store;
}

// The formats a row may describe; see the header for why `ldp_vc` is not one.
const KEPT_FORMATS = ['dc+sd-jwt', 'jwt_vc_json'];

// digest of the issuer-signed JWT -> { subject, jkt, format, configId,
// expiresAt, issuedAt }. PER TRUST REALM; see the header.
const issued = realms.map({ persist: 'vc_issued.credentials' });

class VcIssued {
  static readonly KEPT_FORMATS = KEPT_FORMATS;

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
      store: issued
    };
  }

  // The part of a credential or a presentation this register is keyed by:
  // everything before the first `~`, which for an SD-JWT is the issuer-signed
  // JWT and for a plain JWT is the whole of it. Hashed, so the key is not a
  // credential.
  digestOf(credential: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcIssued.digestOf().");
    const jwt = String(credential || '').split('~')[0];
    const digest = crypto.createHash('sha256').update(jwt, 'ascii')
      .digest('base64url');
    log.debug("Leaving VcIssued.digestOf().");
    return digest;
  }

  // ---------------------------------------------------------------------------
  // WHICH SUBJECT A VERIFIED ACCESS TOKEN NAMES A PERSON BY, or ''.
  //
  // Asked by the credential endpoint before anything is recorded, and every
  // condition is a reason the credential could otherwise sign in somebody who
  // never asked for it:
  //
  //   * `verified` — the token's signature verified against THIS realm's key.
  //     An unverified token's `sub` is a string its holder wrote.
  //   * the subject is `urn:uuid:` — the one form this service issues for a
  //     person. The legacy `urn:sts:user:<name>` is name-derived, which is the
  //     account-recycling hole the stable subject was made to close, and a
  //     client's own id is not a person.
  //   * it names an entry NOW, and that entry's subject is this one — so an
  //     entry deleted between the token and the credential is nobody.
  //   * the token was GRANTED FOR CREDENTIAL ISSUANCE: a scope one of this
  //     issuer's configurations names, or an `openid_credential`
  //     authorization detail. Without this, any access token issued to any
  //     client on a person's behalf — for a calendar, say — could be turned
  //     into a credential that signs that person in, which is a larger power
  //     than the person granted that client.
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

  // Records one issued credential. Never throws: a register that could not be
  // written costs that credential the ability to sign somebody in, and must
  // not cost the wallet the credential.
  record(entry: { credential: unknown; format: string; configId: string;
                  subject: string; holderJwk: any;
                  expiresAt: number }): boolean {
    const { log, store, jwkThumbprint } = this.deps;
    log.debug("Entering VcIssued.record(). format=" + entry.format);
    if (KEPT_FORMATS.indexOf(String(entry.format)) < 0 || !entry.subject ||
        !entry.holderJwk || !entry.credential) {
      log.debug("Leaving VcIssued.record(). Nothing to keep.");
      return false;
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
      return false;
    }
    this.sweep();
    store.set(this.digestOf(entry.credential), {
      subject: String(entry.subject),
      jkt: jkt,
      format: String(entry.format),
      configId: String(entry.configId || ''),
      expiresAt: Number(entry.expiresAt) || 0,
      issuedAt: Date.now()
    });
    log.debug("Leaving VcIssued.record(). Kept.");
    return true;
  }

  // The row for a presented credential, or null — an expired row is removed
  // on the way past.
  lookup(credential: unknown): any {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.lookup().");
    const key = this.digestOf(credential);
    const row = store.get(key);
    if (!row) {
      log.debug("Leaving VcIssued.lookup(). Not issued here for an entry.");
      return null;
    }
    if (row.expiresAt && row.expiresAt <= Date.now()) {
      store.delete(key);
      log.debug("Leaving VcIssued.lookup(). Expired.");
      return null;
    }
    log.debug("Leaving VcIssued.lookup(). Found.");
    return row;
  }

  // Takes one credential out of the sign-in path.
  forget(credential: unknown): boolean {
    const { log, store } = this.deps;
    log.debug("Entering VcIssued.forget().");
    const gone = store.delete(this.digestOf(credential));
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
  forget: slot.forward('forget'),
  size: slot.forward('size')
};
