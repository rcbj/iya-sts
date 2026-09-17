'use strict';
//
// File: gnap_store.ts
//
// ---------------------------------------------------------------------------
// EVERYTHING GNAP MINTS, PER TRUST REALM, IN ONE PLACE.
//
// RFC 9767 section 2.1.13 describes the model this file keeps: a GRANT is the
// tuple of the AS, the client instance, the resource owner(s), the rights and
// a state (RFC 9635 section 1.5: processing, pending, approved, finalized), and
// every access token hangs off the grant that issued it. So the grant is the
// record and everything else is an INDEX onto it: the continuation access
// token, the interaction start URIs and user codes, the interaction reference,
// the access tokens and their management tokens.
//
// **EACH STORE IS PER REALM AT ITS DECLARATION**, which is the rule
// common/CLAUDE.md states and `tests/realm_isolation.js` guards. A grant made
// in `/realm/acme` is acme's authorization server's, and a continuation token
// from it presented to the default realm must find NOTHING — not a grant it is
// refused for, nothing — because the two realms are two logical identity
// services.
//
// **EACH STORE IS DECLARED WITH `persist`**, so in product mode on a postgres
// store it survives a restart and replicates between request workers — the
// minted-row rule of persistence/CLAUDE.md. That has three consequences this
// file honours everywhere:
//
//   * **a row is JSON.** No KeyObject, no Buffer. A key is stored as the
//     object the client sent and re-described by `gnap_keys.ts` on read.
//   * **an in-place edit is re-set.** The journal sees set/delete/clear and
//     nothing else, so `saveGrant()` and `saveToken()` exist and every
//     mutation goes through them — a grant moved to `approved` in place and
//     never re-set would be persisted pending.
//   * **no bearer credential is a key.** Every token VALUE is indexed by its
//     SHA-256, the rule `vc_offers.deferredAccessTokens` set: a dump of the
//     store is then not a list of working tokens.
//
// Expiry is checked on READ rather than by a timer: a timer runs in every
// request worker, and a sweep that raced a lookup in another process would be
// a grant that exists in one and not the other for no reason anybody could
// see. A row past its life reads as absent, and `prune()` removes the dead
// ones opportunistically when something new is written.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapStore` takes the logger, the two helpers it uses, the cluster
// claim store, the error-code table and its twelve stores through its
// constructor. The stores are still declared at module scope, one
// `realms.map()` each, because a store becomes per realm at its declaration
// (`tests/realm_isolation.js`). The module still exports its old names as
// FACADES forwarding to the instance the composition root builds (#50, R2),
// for the unconverted modules that require it, and still provides the
// `gnap.once` capability at load, which needs no instance. A process that
// loads this module without the root builds a default instance when the module
// loads.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
// THE CLUSTER CLAIM (2026-09-14, #46) — see spend() below. A LIBRARY that
// registers no route and requires persistence lazily, so this file stays a
// leaf of the family.
import clusterClaims = require('../cluster/cluster_claims');
import capabilities = require('../cluster/cluster_capabilities');
import errorCodes = require('../common/error_codes');
import cacheRegistry = require('../common/cache_registry');

// The parts of a `realms.map()` store this module uses. Rows are JSON
// (header), so `any`.
interface Store {
  has(key: string): boolean;
  get(key: string): any;
  set(key: string, value: any): unknown;
  delete(key: string): boolean;
  forEach(fn: (value: any, key: string) => void): void;
}

interface GnapStores {
  grants: Store;
  continuations: Store;
  interactions: Store;
  userCodes: Store;
  tokens: Store;
  tokenValues: Store;
  manageValues: Store;
  manageHandles: Store;
  instances: Store;
  userRefs: Store;
  resources: Store;
  replay: Store;
}

interface GnapStoreDeps {
  log: {
    debug(message: string): void;
    warn(message: string): void;
    error(message: string): void;
  };
  randomId(bytes: number): string;
  nowSec(): number;
  clusterClaims: {
    claim(ask: object): Promise<any>;
    release(handle: unknown): any;
  };
  errorCodes: { tag(code: string): string };
  stores: GnapStores;
}

const grants = realms.map({ persist: 'gnap.grants' });
const continuations = realms.map({ persist: 'gnap.continuations' });
const interactions = realms.map({ persist: 'gnap.interactions' });
const userCodes = realms.map({ persist: 'gnap.userCodes' });
const tokens = realms.map({ persist: 'gnap.tokens' });
const tokenValues = realms.map({ persist: 'gnap.tokenValues' });
const manageValues = realms.map({ persist: 'gnap.manageValues' });
const manageHandles = realms.map({ persist: 'gnap.manageHandles' });
const instances = realms.map({ persist: 'gnap.instances' });
const userRefs = realms.map({ persist: 'gnap.userRefs' });
const resources = realms.map({ persist: 'gnap.resources' });
// THE REPLAY CACHE for httpsig nonces and JWS proofs (RFC 9635 section 7.3.1:
// "the verifier MUST determine that the nonce value is unique within a
// reasonably short time period"). Persisted for the reason the DPoP replay
// cache is: across request workers a proof refused by one and accepted by
// another is the replay the cache exists to stop.
const replay = realms.map({ persist: 'gnap.replay' });

// Described to `/admin/caches` (#74, rule 3ap). The key is already a digest
// of the signature; `until` is in seconds.
const replayCount = cacheRegistry.register({
  name: 'gnap.signatures',
  title: 'GNAP signatures',
  description: 'Each signed GNAP request accepted (HTTP message signatures ' +
    'and attached or detached JWS), so a captured request cannot be sent ' +
    'again.',
  owner: 'gnap/gnap_store.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a signature already seen, so the request was refused',
  settings: ['gnap.signatureMaxAgeS'],
  maxEntries: function (): null {
    return null;
  },
  lifetime: function (): string {
    return 'Twice gnap.signatureMaxAgeS after it was seen. No size limit: ' +
      'pruned by time only.';
  },
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, replay,
      function (seen: any, key: unknown): object {
        return { key: String(key).slice(0, 16) + '…',
                 validUntil: Number(seen && seen.until) * 1000 };
      });
  }
});

// Grant states, RFC 9635 section 1.5.
const STATE = { PROCESSING: 'processing', PENDING: 'pending',
                APPROVED: 'approved',
                FINALIZED: 'finalized' };

// ---------------------------------------------------------------------------
// SPENDING A SINGLE-USE VALUE ACROSS THE CLUSTER — the two lifetimes; see
// spend() below.
// ---------------------------------------------------------------------------
const CLAIM_SKEW_S = 60;
const UNBOUNDED_LIFETIME_S = 24 * 60 * 60;

class GnapStore {
  static readonly STATE = STATE;

  constructor(private readonly deps: GnapStoreDeps) {
    deps.log.debug("Entering GnapStore.constructor().");
    deps.log.debug("Leaving GnapStore.constructor().");
  }

  digest(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering GnapStore.digest().");
    log.debug("Leaving GnapStore.digest().");
    return nodeCrypto.createHash('sha256')
                     .update(String(value), 'utf8')
                     .digest('base64url');
  }

  // A value of the given length made of unreserved characters (RFC 3986
  // section 2.3). base64url is exactly that alphabet, which is why every GNAP
  // artifact here is one: section 4.2 requires it of the interaction reference
  // and section 3.2.1's token68 is satisfied by it for every token.
  mint(bytes?: number): string {
    const { log, randomId } = this.deps;
    log.debug("Entering GnapStore.mint().");
    log.debug("Leaving GnapStore.mint().");
    return randomId(bytes || 24);
  }

  // -------------------------------------------------------------------------
  // GRANTS.
  // -------------------------------------------------------------------------
  newGrant(fields?: object): any {
    const { log, nowSec } = this.deps;
    const { grants } = this.deps.stores;
    log.debug("Entering GnapStore.newGrant().");
    const now = nowSec();
    const grant = Object.assign({
      id: this.mint(18),
      state: STATE.PROCESSING,
      createdAt: now,
      updatedAt: now,
      expiresAt: null,
      tokens: [],
      history: []
    }, fields || {});
    grants.set(grant.id, grant);
    this.prune();
    log.debug("Leaving GnapStore.newGrant(). id=" + grant.id);
    return grant;
  }

  getGrant(id: string): any {
    const { log } = this.deps;
    const { grants } = this.deps.stores;
    log.debug("Entering GnapStore.getGrant().");
    if (!id || !grants.has(id)) {
      log.debug("Leaving GnapStore.getGrant().");
      return null;
    }
    log.debug("Leaving GnapStore.getGrant().");
    return grants.get(id);
  }

  // Every change to a grant passes through here, because the journal only
  // sees a set (header). `note` goes onto the grant's own history, which the
  // console shows: a grant is a state machine and a reader debugging a client
  // wants the transitions, not the final state.
  saveGrant(grant: any, note?: unknown): any {
    const { log, nowSec } = this.deps;
    const { grants } = this.deps.stores;
    log.debug("Entering GnapStore.saveGrant().");
    grant.updatedAt = nowSec();
    if (note) {
      grant.history = (grant.history || []).concat(
          [{ at: grant.updatedAt, state: grant.state,
             note: String(note).slice(0, 200) }])
        .slice(-40);
    }
    grants.set(grant.id, grant);
    log.debug("Leaving GnapStore.saveGrant().");
    return grant;
  }

  listGrants(): any[] {
    const { log } = this.deps;
    const { grants } = this.deps.stores;
    log.debug("Entering GnapStore.listGrants().");
    const out = [];
    grants.forEach(function (grant) {
      out.push(grant);
    });
    log.debug("Leaving GnapStore.listGrants().");
    return out.sort(function (a, b) {
      return b.updatedAt - a.updatedAt;
    });
  }

  deleteGrant(id: string): void {
    const { log } = this.deps;
    const { grants } = this.deps.stores;
    log.debug("Entering GnapStore.deleteGrant().");
    grants.delete(id);
    log.debug("Leaving GnapStore.deleteGrant().");
  }

  // -------------------------------------------------------------------------
  // CONTINUATION ACCESS TOKENS (section 3.1). One live value per grant:
  // section 5 says the new token SHOULD invalidate the previous one, and this
  // service always does, so an old continuation token read from a log cannot
  // be replayed after the client has used its successor.
  // -------------------------------------------------------------------------
  issueContinuation(grant: any): string {
    const { log, nowSec } = this.deps;
    const { continuations } = this.deps.stores;
    log.debug("Entering GnapStore.issueContinuation(). grant=" + grant.id);
    if (grant.continuationHash) {
      continuations.delete(grant.continuationHash);
    }
    const value = this.mint(24);
    grant.continuationHash = this.digest(value);
    continuations.set(grant.continuationHash,
                      { grantId: grant.id, issuedAt: nowSec() });
    log.debug("Leaving GnapStore.issueContinuation().");
    return value;
  }

  grantByContinuation(value: unknown): any {
    const { log } = this.deps;
    const { continuations } = this.deps.stores;
    log.debug("Entering GnapStore.grantByContinuation().");
    const row = continuations.get(this.digest(value));
    log.debug("Leaving GnapStore.grantByContinuation().");
    return row ? this.getGrant(row.grantId) : null;
  }

  dropContinuation(grant: any): void {
    const { log } = this.deps;
    const { continuations } = this.deps.stores;
    log.debug("Entering GnapStore.dropContinuation().");
    if (grant.continuationHash) {
      continuations.delete(grant.continuationHash);
      grant.continuationHash = null;
    }
    log.debug("Leaving GnapStore.dropContinuation().");
  }

  // -------------------------------------------------------------------------
  // INTERACTION START HANDLES: the unique path segment of a redirect or app
  // URI, and a user code. Both are ONE-TIME-USE and short-lived (section 4);
  // the grant holds the expiry and the "which mode was used" state, and these
  // rows are only the lookup.
  // -------------------------------------------------------------------------
  putInteraction(id: string, grantId: string): void {
    const { log, nowSec } = this.deps;
    const { interactions } = this.deps.stores;
    log.debug("Entering GnapStore.putInteraction().");
    interactions.set(id, { grantId: grantId, at: nowSec() });
    log.debug("Leaving GnapStore.putInteraction().");
  }

  grantByInteraction(id: string): any {
    const { log } = this.deps;
    const { interactions } = this.deps.stores;
    log.debug("Entering GnapStore.grantByInteraction().");
    const row = id ? interactions.get(id) : null;
    log.debug("Leaving GnapStore.grantByInteraction().");
    return row ? this.getGrant(row.grantId) : null;
  }

  dropInteraction(id: string): void {
    const { log } = this.deps;
    const { interactions } = this.deps.stores;
    log.debug("Entering GnapStore.dropInteraction().");
    interactions.delete(id);
    log.debug("Leaving GnapStore.dropInteraction().");
  }

  putUserCode(code: string, grantId: string): void {
    const { log, nowSec } = this.deps;
    const { userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.putUserCode().");
    userCodes.set(code, { grantId: grantId, at: nowSec() });
    log.debug("Leaving GnapStore.putUserCode().");
  }

  grantByUserCode(code: string): any {
    const { log } = this.deps;
    const { userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.grantByUserCode().");
    const row = code ? userCodes.get(code) : null;
    log.debug("Leaving GnapStore.grantByUserCode().");
    return row ? this.getGrant(row.grantId) : null;
  }

  dropUserCode(code: string): void {
    const { log } = this.deps;
    const { userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.dropUserCode().");
    userCodes.delete(code);
    log.debug("Leaving GnapStore.dropUserCode().");
  }

  userCodeTaken(code: string): boolean {
    const { log } = this.deps;
    const { userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.userCodeTaken().");
    log.debug("Leaving GnapStore.userCodeTaken().");
    return userCodes.has(code);
  }

  // -------------------------------------------------------------------------
  // ACCESS TOKENS (section 3.2) and their MANAGEMENT tokens (section 6).
  //
  // A token record is the RFC 9767 section 2.1 model plus the bookkeeping the
  // AS needs: the grant, the management handle and hash, the format, and
  // whether it is revoked. It is keyed by `jti` and indexed by the SHA-256 of
  // its value, so that introspection of any of the five formats is one lookup
  // — including the three whose value a self-contained verifier could also
  // read.
  // -------------------------------------------------------------------------
  putToken(record: any, value: unknown): any {
    const { log } = this.deps;
    const { tokens, tokenValues } = this.deps.stores;
    log.debug("Entering GnapStore.putToken(). jti=" + record.jti);
    record.valueHash = this.digest(value);
    tokens.set(record.jti, record);
    tokenValues.set(record.valueHash, { jti: record.jti });
    log.debug("Leaving GnapStore.putToken().");
    return record;
  }

  saveToken(record: any): any {
    const { log } = this.deps;
    const { tokens } = this.deps.stores;
    log.debug("Entering GnapStore.saveToken().");
    tokens.set(record.jti, record);
    log.debug("Leaving GnapStore.saveToken().");
    return record;
  }

  tokenByJti(jti: string): any {
    const { log } = this.deps;
    const { tokens } = this.deps.stores;
    log.debug("Entering GnapStore.tokenByJti().");
    log.debug("Leaving GnapStore.tokenByJti().");
    return jti ? (tokens.get(jti) || null) : null;
  }

  tokenByValue(value: unknown): any {
    const { log } = this.deps;
    const { tokenValues } = this.deps.stores;
    log.debug("Entering GnapStore.tokenByValue().");
    const row = value ? tokenValues.get(this.digest(value)) : null;
    log.debug("Leaving GnapStore.tokenByValue().");
    return row ? this.tokenByJti(row.jti) : null;
  }

  listTokens(): any[] {
    const { log } = this.deps;
    const { tokens } = this.deps.stores;
    log.debug("Entering GnapStore.listTokens().");
    const out = [];
    tokens.forEach(function (record) {
      out.push(record);
    });
    log.debug("Leaving GnapStore.listTokens().");
    return out;
  }

  // The management URI's handle and its access token (section 3.2.1). The
  // handle is NOT the token (the URI "MUST NOT include the value of the access
  // token being managed or the value of the access token used to protect the
  // URI").
  issueManagement(record: any): string {
    const { log } = this.deps;
    const { manageValues, manageHandles } = this.deps.stores;
    log.debug("Entering GnapStore.issueManagement(). jti=" + record.jti);
    if (record.manageHash) {
      manageValues.delete(record.manageHash);
    }
    if (!record.manageHandle) {
      record.manageHandle = this.mint(12);
      manageHandles.set(record.manageHandle, { jti: record.jti });
    }
    const value = this.mint(24);
    record.manageHash = this.digest(value);
    manageValues.set(record.manageHash, { jti: record.jti });
    log.debug("Leaving GnapStore.issueManagement().");
    return value;
  }

  // A rotated token takes its management handle with it — section 6.1: "the
  // value of this URI MAY be different from the URI used by the client
  // instance". This service keeps the URI and moves the handle onto the new
  // record, which is the arrangement a client can least get wrong.
  moveManagement(from: any, to: any): void {
    const { log } = this.deps;
    const { manageValues, manageHandles } = this.deps.stores;
    log.debug("Entering GnapStore.moveManagement().");
    if (from.manageHandle) {
      to.manageHandle = from.manageHandle;
      manageHandles.set(to.manageHandle, { jti: to.jti });
      from.manageHandle = null;
    }
    if (from.manageHash) {
      manageValues.delete(from.manageHash);
      from.manageHash = null;
    }
    log.debug("Leaving GnapStore.moveManagement().");
  }

  tokenByManagement(handle: string, value: unknown): any {
    const { log } = this.deps;
    const { manageValues, manageHandles } = this.deps.stores;
    log.debug("Entering GnapStore.tokenByManagement().");
    const byHandle = handle ? manageHandles.get(handle) : null;
    const byValue = value ? manageValues.get(this.digest(value)) : null;
    if (!byHandle || !byValue || byHandle.jti !== byValue.jti) {
      log.debug("Leaving GnapStore.tokenByManagement().");
      // Section 6: "The AS MUST uniquely identify the token being managed
      // from the token management URI, the token management access token, or
      // a combination of both." This service requires BOTH to agree, so a
      // management token for one of a client's tokens cannot rotate another.
      return null;
    }
    log.debug("Leaving GnapStore.tokenByManagement().");
    return this.tokenByJti(byHandle.jti);
  }

  dropManagement(record: any): void {
    const { log } = this.deps;
    const { manageValues, manageHandles } = this.deps.stores;
    log.debug("Entering GnapStore.dropManagement().");
    if (record.manageHandle) {
      manageHandles.delete(record.manageHandle);
    }
    if (record.manageHash) {
      manageValues.delete(record.manageHash);
    }
    record.manageHandle = null;
    record.manageHash = null;
    log.debug("Leaving GnapStore.dropManagement().");
  }

  // -------------------------------------------------------------------------
  // DYNAMIC INSTANCE IDENTIFIERS (section 3.5) and USER REFERENCES (section
  // 2.4.1). Both are secrets the client holds, so both are indexed by digest.
  // -------------------------------------------------------------------------
  putInstance(instanceId: unknown, fields?: object): void {
    const { log, nowSec } = this.deps;
    const { instances } = this.deps.stores;
    log.debug("Entering GnapStore.putInstance().");
    instances.set(this.digest(instanceId),
                  Object.assign({ createdAt: nowSec() }, fields));
    log.debug("Leaving GnapStore.putInstance().");
  }

  instanceById(instanceId: unknown): any {
    const { log } = this.deps;
    const { instances } = this.deps.stores;
    log.debug("Entering GnapStore.instanceById().");
    log.debug("Leaving GnapStore.instanceById().");
    return instanceId ?
      (instances.get(this.digest(instanceId)) || null) : null;
  }

  putUserRef(reference: unknown, fields?: object): void {
    const { log, nowSec } = this.deps;
    const { userRefs } = this.deps.stores;
    log.debug("Entering GnapStore.putUserRef().");
    userRefs.set(this.digest(reference),
                 Object.assign({ createdAt: nowSec() }, fields));
    log.debug("Leaving GnapStore.putUserRef().");
  }

  userByRef(reference: unknown): any {
    const { log } = this.deps;
    const { userRefs } = this.deps.stores;
    log.debug("Entering GnapStore.userByRef().");
    log.debug("Leaving GnapStore.userByRef().");
    return reference ?
      (userRefs.get(this.digest(reference)) || null) : null;
  }

  // -------------------------------------------------------------------------
  // REGISTERED RESOURCE SETS (RFC 9767 section 3.4). Keyed by the reference
  // the AS hands back; section 3.4 lets the AS return the SAME reference for a
  // set registered again, which is what `canonical` makes possible.
  // -------------------------------------------------------------------------
  putResource(reference: string, fields?: object): any {
    const { log, nowSec } = this.deps;
    const { resources } = this.deps.stores;
    log.debug("Entering GnapStore.putResource().");
    resources.set(reference,
                  Object.assign({ reference: reference, createdAt: nowSec() },
                                fields));
    log.debug("Leaving GnapStore.putResource().");
    return resources.get(reference);
  }

  resourceByReference(reference: string): any {
    const { log } = this.deps;
    const { resources } = this.deps.stores;
    log.debug("Entering GnapStore.resourceByReference().");
    log.debug("Leaving GnapStore.resourceByReference().");
    return reference ? (resources.get(reference) || null) : null;
  }

  resourceByCanonical(canonical: unknown, rsIdentity: unknown): any {
    const { log } = this.deps;
    const { resources } = this.deps.stores;
    log.debug("Entering GnapStore.resourceByCanonical().");
    let found = null;
    resources.forEach(function (row) {
      if (!found && row.canonical === canonical &&
          row.rsIdentity === rsIdentity) {
        found = row;
      }
    });
    log.debug("Leaving GnapStore.resourceByCanonical().");
    return found;
  }

  listResources(): any[] {
    const { log } = this.deps;
    const { resources } = this.deps.stores;
    log.debug("Entering GnapStore.listResources().");
    const out = [];
    resources.forEach(function (row) {
      out.push(row);
    });
    log.debug("Leaving GnapStore.listResources().");
    return out.sort(function (a, b) {
      return b.createdAt - a.createdAt;
    });
  }

  deleteResource(reference: string): boolean {
    const { log } = this.deps;
    const { resources } = this.deps.stores;
    log.debug("Entering GnapStore.deleteResource().");
    log.debug("Leaving GnapStore.deleteResource().");
    return resources.delete(reference);
  }

  // -------------------------------------------------------------------------
  // REPLAY. `remember(key, lifetimeS)` answers true the first time and false
  // for a repeat within the window, which is the whole contract a verifier
  // needs.
  // -------------------------------------------------------------------------
  remember(key: unknown, lifetimeS?: unknown): boolean {
    const { log, nowSec } = this.deps;
    const { replay } = this.deps.stores;
    log.debug("Entering GnapStore.remember().");
    const now = nowSec();
    const hashed = this.digest(key);
    const seen = replay.get(hashed);
    if (seen && seen.until > now) {
      replayCount.hit();
      log.debug("Leaving GnapStore.remember().");
      return false;
    }
    replayCount.miss();
    replay.set(hashed, { until: now + Math.max(1, Number(lifetimeS) || 1) });
    log.debug("Leaving GnapStore.remember().");
    return true;
  }

  // -------------------------------------------------------------------------
  // SPENDING A SINGLE-USE VALUE ACROSS THE CLUSTER (2026-09-14, #46).
  //
  // Every one-time value in this family — a continuation access token, an
  // interaction reference, an interaction start link, a user code, a token
  // management access token, a key proof — is spent in THIS file's maps,
  // which are `realms.map({ persist })`: once in one process, and a
  // replicated write in several. Two requests carrying one value, landing on
  // two nodes inside the replication window, both found it live and both
  // were answered — two continuations issuing two successor tokens for one
  // grant, two rotations of one access token, a signature nonce accepted
  // twice (RFC 9635 section 7.3.1 says MUST be unique).
  //
  // So each caller keeps its in-memory check first, exactly as it was, and
  // then asks `spend(kind, value, lifetimeS)` before acting: one
  // `cluster_claims.claim()` in the scope `gnap.<kind>`, which exactly one
  // caller on any node wins. On a store that cannot be shared the claim is
  // this process's memory, which is as atomic as the maps it sits beside.
  //
  // The lifetime is the value's own — `lifetimeS` — plus CLAIM_SKEW_S for
  // clocks that disagree. A value with no expiry of its own (a continuation or
  // management token lives until it is used) is claimed for
  // UNBOUNDED_LIFETIME_S: the claim has to outlive only the window in which
  // another node could still hold the value, and a day is far past every
  // replication delay, including a transaction the change log gives up on
  // after ten minutes.
  //
  // Resolves to `{ ok: true, handle }`, or `{ ok: false, reason, errorCode }`
  // where `reason` is `used` (the caller refuses with the protocol's own error
  // and `usedCode`) or `store` (STS-GNAP-0716, fail closed). It never rejects.
  // -------------------------------------------------------------------------
  spend(kind: string, value: unknown, lifetimeS?: unknown,
        usedCode?: string): Promise<any> {
    const { log, clusterClaims, errorCodes } = this.deps;
    log.debug("Entering GnapStore.spend(). kind=" + kind);
    const seconds = Number(lifetimeS);
    const ttlS = (Number.isFinite(seconds) && seconds > 0 ? seconds :
                  UNBOUNDED_LIFETIME_S) + CLAIM_SKEW_S;
    log.debug("Leaving GnapStore.spend(). Asking the claim store.");
    return clusterClaims.claim({ scope: 'gnap.' + kind, value: value,
                                 ttlMs: ttlS * 1000 })
      .then(function (claimed) {
        log.debug("Entering GnapStore.spend()'s answer.");
        if (claimed.ok) {
          log.debug("Leaving GnapStore.spend()'s answer. Spent here.");
          return claimed;
        }
        if (claimed.reason === 'used') {
          log.warn(errorCodes.tag(usedCode) + 'gnap: a single-use value ("' +
                   kind + '") this process still accepted was ALREADY ' +
                   'SPENT, on this node or another against the same store. ' +
                   'Refused.');
          log.debug("Leaving GnapStore.spend()'s answer. Used.");
          return { ok: false, reason: 'used', errorCode: usedCode };
        }
        log.error(errorCodes.tag('STS-GNAP-0716') + 'gnap: whether a ' +
                  'single-use value ("' + kind + '") was already spent ' +
                  'could not be asked of the claim store (' +
                  (claimed.why || 'no reason given') + '). It is refused.');
        log.debug("Leaving GnapStore.spend()'s answer. Store unavailable.");
        return { ok: false, reason: 'store', errorCode: 'STS-GNAP-0716' };
      });
  }

  // Gives a claim back when what it guarded did not happen — see the callers,
  // which release only where the value is still live in this process's map.
  unspend(handle: unknown): any {
    const { log, clusterClaims } = this.deps;
    log.debug("Entering GnapStore.unspend().");
    log.debug("Leaving GnapStore.unspend().");
    return clusterClaims.release(handle);
  }

  // -------------------------------------------------------------------------
  // OPPORTUNISTIC PRUNE of rows that can no longer be used. Bounded work per
  // call, so a store with a large backlog is cleaned over several writes
  // rather than stalling one.
  // -------------------------------------------------------------------------
  prune(): void {
    const { log, nowSec } = this.deps;
    const { replay, grants, continuations } = this.deps.stores;
    log.debug("Entering GnapStore.prune().");
    const now = nowSec();
    let budget = 200;
    replay.forEach(function (row, key) {
      if (budget > 0 && row.until <= now) {
        replay.delete(key);
        budget -= 1;
      }
    });
    grants.forEach(function (grant, id) {
      if (budget <= 0) {
        return;
      }
      // A FINALIZED grant is kept for a day so the console can show what
      // happened to it; a pending one past its life is simply gone.
      const finalizedLongAgo = grant.state === STATE.FINALIZED &&
                               grant.updatedAt < now - 86400;
      const pendingExpired = grant.state !== STATE.APPROVED &&
        grant.state !== STATE.FINALIZED &&
        grant.expiresAt && grant.expiresAt < now - 3600;
      if (finalizedLongAgo || pendingExpired) {
        if (grant.continuationHash) {
          continuations.delete(grant.continuationHash);
        }
        grants.delete(id);
        budget -= 1;
      }
    });
    log.debug("Leaving GnapStore.prune().");
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before. The stores are the module-scope
  // ones.
  static defaultDeps(): GnapStoreDeps {
    helpers.log.debug("Entering GnapStore.defaultDeps().");
    helpers.log.debug("Leaving GnapStore.defaultDeps().");
    return {
      log: helpers.log,
      randomId: helpers.randomId,
      nowSec: helpers.nowSec,
      clusterClaims: clusterClaims,
      errorCodes: errorCodes,
      stores: {
        grants: grants,
        continuations: continuations,
        interactions: interactions,
        userCodes: userCodes,
        tokens: tokens,
        tokenValues: tokenValues,
        manageValues: manageValues,
        manageHandles: manageHandles,
        instances: instances,
        userRefs: userRefs,
        resources: resources,
        replay: replay
      }
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapStore>(
  'gnap/gnap_store',
  () => new GnapStore(GnapStore.defaultDeps()),
  null,
  helpers.log);

// #46: every GNAP single-use value is spent once across the cluster — the
// helper above, called from gnap_grants.ts, gnap_interact.ts, gnap_proof.ts
// and gnap_rs.ts. Provided here because the capability row names this file.
capabilities.provide('gnap.once');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  GnapStore: GnapStore,
  installInstance: (instance: GnapStore): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  STATE: GnapStore.STATE,
  spend: slot.forward('spend'),
  unspend: slot.forward('unspend'),
  digest: slot.forward('digest'),
  mint: slot.forward('mint'),
  newGrant: slot.forward('newGrant'),
  getGrant: slot.forward('getGrant'),
  saveGrant: slot.forward('saveGrant'),
  listGrants: slot.forward('listGrants'),
  deleteGrant: slot.forward('deleteGrant'),
  issueContinuation: slot.forward('issueContinuation'),
  grantByContinuation: slot.forward('grantByContinuation'),
  dropContinuation: slot.forward('dropContinuation'),
  putInteraction: slot.forward('putInteraction'),
  grantByInteraction: slot.forward('grantByInteraction'),
  dropInteraction: slot.forward('dropInteraction'),
  putUserCode: slot.forward('putUserCode'),
  grantByUserCode: slot.forward('grantByUserCode'),
  dropUserCode: slot.forward('dropUserCode'),
  userCodeTaken: slot.forward('userCodeTaken'),
  putToken: slot.forward('putToken'),
  saveToken: slot.forward('saveToken'),
  tokenByJti: slot.forward('tokenByJti'),
  tokenByValue: slot.forward('tokenByValue'),
  listTokens: slot.forward('listTokens'),
  issueManagement: slot.forward('issueManagement'),
  moveManagement: slot.forward('moveManagement'),
  tokenByManagement: slot.forward('tokenByManagement'),
  dropManagement: slot.forward('dropManagement'),
  putInstance: slot.forward('putInstance'),
  instanceById: slot.forward('instanceById'),
  putUserRef: slot.forward('putUserRef'),
  userByRef: slot.forward('userByRef'),
  putResource: slot.forward('putResource'),
  resourceByReference: slot.forward('resourceByReference'),
  resourceByCanonical: slot.forward('resourceByCanonical'),
  listResources: slot.forward('listResources'),
  deleteResource: slot.forward('deleteResource'),
  remember: slot.forward('remember'),
  prune: slot.forward('prune')
};
