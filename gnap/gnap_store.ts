// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
import config = require('../common/config');
import cellLocator = require('../common/cell_locator');

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
  // The replay history's bound, `gnap.replayCacheSize` (2026-09-18).
  replayBound: () => number;
}

// `expiresAt` (#333): prune()'s rule, in epoch SECONDS — a FINALIZED grant
// a day after it last moved, a grant neither approved nor finalized an hour
// past its interaction's expiry. An APPROVED grant never expires here.
const grants = realms.map({
  persist: 'gnap.grants',
  // A hot path (every row a flush writes): no Entering/Leaving pair.
  expiresAt: function (grant: any): number | null {
    if (!grant || typeof grant !== 'object') {
      return null;
    }
    if (grant.state === STATE.FINALIZED) {
      const moved = Number(grant.updatedAt);
      return moved > 0 ? (moved + 86400) * 1000 : null;
    }
    const until = Number(grant.expiresAt);
    return grant.state !== STATE.APPROVED && until > 0
      ? (until + 3600) * 1000 : null;
  }
});
const continuations = realms.map({ persist: 'gnap.continuations',
                                   retain: 'age' });
const interactions = realms.map({ persist: 'gnap.interactions',
                                  retain: 'age' });
const userCodes = realms.map({ persist: 'gnap.userCodes', retain: 'age' });
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
const replay = realms.map({ persist: 'gnap.replay', retain: 'age',
                            // #333: its `until`, epoch seconds.
                            expiresAt: realms.expiryField('until', 1000) });

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
  settings: ['gnap.signatureMaxAgeS', 'gnap.replayCacheSize'],
  maxEntries: function (): number {
    return Number(config.value('gnap.replayCacheSize'));
  },
  bound: 'Enforced: gnap.replayCacheSize live signatures per realm. A full ' +
    'history REFUSES the next signed request (STS-GNAP-0718) rather than ' +
    'forget a live one, which would reopen its replay.',
  lifetime: function (): string {
    return 'Twice gnap.signatureMaxAgeS after it was seen.';
  },
  // The rows `rememberOutcome()`'s makeRoom() already treats as expired
  // (#49 P5).
  eject: cacheRegistry.realmMapEjector(realms, replay,
    function (row: any, key: unknown, now: number): boolean {
      return !row || Number(row.until) <= Math.floor(now / 1000);
    }),
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

/**
 * Everything GNAP mints, per trust realm, in one place: the grant as the
 * record, and the continuation tokens, interaction handles, user codes, access
 * and management tokens, instances, user references, resource sets and replay
 * history as indexes onto it.
 *
 * Each store is per realm at its declaration.
 */
class GnapStore {
  /**
   * The grant states of RFC 9635 section 1.5: processing, pending, approved and
   * finalized.
   */
  static readonly STATE = STATE;

  /**
   * Builds the store over the per-realm maps it is given.
   *
   * @param deps - the modules and stores the composition root passes
   */
  constructor(private readonly deps: GnapStoreDeps) {
    deps.log.debug("Entering GnapStore.constructor().");
    deps.log.debug("Leaving GnapStore.constructor().");
  }

  /**
   * Returns the SHA-256 of a value, base64url-encoded — how every secret a
   * client holds is indexed.
   *
   * @param value - the value
   * @returns the digest
   */
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
  /**
   * Mints a random base64url value, the alphabet every GNAP artifact here uses.
   *
   * @param bytes - how many random bytes (24 by default)
   * @returns the value
   */
  mint(bytes?: number): string {
    const { log, randomId } = this.deps;
    log.debug("Entering GnapStore.mint().");
    log.debug("Leaving GnapStore.mint().");
    return randomId(bytes || 24);
  }

  // A HANDLE SOMEBODY PRESENTS LATER, POSSIBLY TO ANOTHER CELL (#98 D10):
  // `mint()` with the minting cell's keyed tag appended
  // (`common/cell_locator.ts`), so whichever cell it reaches can send the
  // request to the one that holds it. Still base64url — twelve characters
  // longer — so section 4.2's unreserved alphabet and every `vt.base64url`
  // path check hold. In single-cell mode it is `mint()` exactly.
  //
  // Stamped: the grant id (the continuation URI's last segment), the
  // interaction start and approval handles (the `redirect` / `app` URIs and
  // `/gnap/approve/…`), the management handle (the management URI), an
  // access token's `jti` (read at the edge from a `jwt-signed` token), and an
  // instance identifier (a later request's `client` or `resource_server`).
  // NOT stamped: a user code (a person types it; `gnap_cells.ts` asks the
  // other cells), an opaque user reference (deterministic per person by
  // design), a continuation token and the finish nonces and interaction
  // reference (each travels with a URI that is stamped already), and a
  // resource set reference (the global tier's — `persistence/tiers.js`).
  /**
   * Mints a random base64url handle stamped with this cell's locator.
   *
   * @param bytes - how many random bytes (24 by default)
   * @returns the value, with the cell's twelve-character tag in multi-cell
   *   mode
   */
  handle(bytes?: number): string {
    const { log } = this.deps;
    log.debug("Entering GnapStore.handle().");
    log.debug("Leaving GnapStore.handle().");
    return cellLocator.stamp(this.mint(bytes));
  }

  // -------------------------------------------------------------------------
  // GRANTS.
  // -------------------------------------------------------------------------
  /**
   * Creates a grant in the processing state, with the given fields over the
   * defaults, and stores it.
   *
   * @param fields - the grant's fields
   * @returns the grant
   */
  newGrant(fields?: object): any {
    const { log, nowSec } = this.deps;
    const { grants } = this.deps.stores;
    log.debug("Entering GnapStore.newGrant().");
    const now = nowSec();
    const grant = Object.assign({
      id: this.handle(18),
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

  /**
   * Returns a grant by its identifier.
   *
   * @param id - the grant's identifier
   * @returns the grant, or null
   */
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
  /**
   * Saves a changed grant — every change to one passes through here — and
   * appends `note` to its history.
   *
   * @param grant - the grant
   * @param note - the transition to record
   * @returns the grant
   */
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

  /**
   * Lists the realm's grants, most recently updated first.
   *
   * @returns the grants
   */
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

  /**
   * Deletes a grant.
   *
   * @param id - the grant's identifier
   */
  deleteGrant(id: string): void {
    const { log } = this.deps;
    const { grants } = this.deps.stores;
    log.debug("Entering GnapStore.deleteGrant().");
    grants.delete(id);
    log.debug("Leaving GnapStore.deleteGrant().");
  }

  // -------------------------------------------------------------------------
  // A GRANT MOVED BETWEEN CELLS (#98 D9, `gnap_cells.ts`). A grant still
  // waiting for its resource owner is handed to the cell the browser is
  // pinned to, with the rows that find it — its continuation token, its
  // interaction handles and its user codes — and forgotten here. Only a grant
  // that has issued nothing moves: tokens, management handles and the
  // consent they rest on stay in the cell that minted them.
  // -------------------------------------------------------------------------
  /**
   * Gathers a grant and the rows that find it, for another cell to adopt.
   *
   * @param grant - the grant
   * @returns `{ grant, continuation, interactions, userCodes }`
   */
  exportGrant(grant: any): any {
    const { log } = this.deps;
    const { continuations, interactions, userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.exportGrant(). grant=" + grant.id);
    const out: any = { grant: grant, continuation: null, interactions: {},
                       userCodes: {} };
    if (grant.continuationHash && continuations.has(grant.continuationHash)) {
      out.continuation = { hash: grant.continuationHash,
                           row: continuations.get(grant.continuationHash) };
    }
    interactions.forEach(function (row, key) {
      if (row && row.grantId === grant.id) {
        out.interactions[key] = row;
      }
    });
    userCodes.forEach(function (row, key) {
      if (row && row.grantId === grant.id) {
        out.userCodes[key] = row;
      }
    });
    log.debug("Leaving GnapStore.exportGrant().");
    return out;
  }

  /**
   * Stores a grant another cell handed over, with the rows that find it.
   *
   * @param bundle - what `exportGrant()` gathered
   * @returns the grant
   */
  importGrant(bundle: any): any {
    const { log } = this.deps;
    const { grants, continuations, interactions,
            userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.importGrant().");
    const grant = bundle.grant;
    grants.set(grant.id, grant);
    if (bundle.continuation && bundle.continuation.hash) {
      continuations.set(String(bundle.continuation.hash),
                        bundle.continuation.row);
    }
    Object.keys(bundle.interactions || {}).forEach(function (key) {
      interactions.set(key, bundle.interactions[key]);
    });
    Object.keys(bundle.userCodes || {}).forEach(function (key) {
      userCodes.set(key, bundle.userCodes[key]);
    });
    log.debug("Leaving GnapStore.importGrant(). grant=" + grant.id);
    return grant;
  }

  /**
   * Forgets a grant handed to another cell, and every row that found it.
   *
   * @param bundle - what `exportGrant()` gathered for it
   */
  forgetGrant(bundle: any): void {
    const { log } = this.deps;
    const { grants, continuations, interactions,
            userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.forgetGrant().");
    if (bundle.continuation && bundle.continuation.hash) {
      continuations.delete(String(bundle.continuation.hash));
    }
    Object.keys(bundle.interactions || {}).forEach(function (key) {
      interactions.delete(key);
    });
    Object.keys(bundle.userCodes || {}).forEach(function (key) {
      userCodes.delete(key);
    });
    grants.delete(bundle.grant.id);
    log.debug("Leaving GnapStore.forgetGrant().");
  }

  /**
   * Tells whether this cell holds an access token, by the digest of its
   * value — what another cell asks (`gnap_cells.ts`).
   *
   * @param valueDigest - `digest()` of the token's value
   * @returns true when it is held here
   */
  holdsTokenDigest(valueDigest: string): boolean {
    const { log } = this.deps;
    const { tokenValues } = this.deps.stores;
    log.debug("Entering GnapStore.holdsTokenDigest().");
    log.debug("Leaving GnapStore.holdsTokenDigest().");
    return !!valueDigest && tokenValues.has(String(valueDigest));
  }

  /**
   * Tells whether this cell holds a user reference, by its digest — what
   * another cell asks (`gnap_cells.ts`); the references are indexed so.
   *
   * @param referenceDigest - `digest()` of the reference
   * @returns true when it is held here
   */
  holdsUserRefDigest(referenceDigest: string): boolean {
    const { log } = this.deps;
    const { userRefs } = this.deps.stores;
    log.debug("Entering GnapStore.holdsUserRefDigest().");
    log.debug("Leaving GnapStore.holdsUserRefDigest().");
    return !!referenceDigest && userRefs.has(String(referenceDigest));
  }

  // -------------------------------------------------------------------------
  // CONTINUATION ACCESS TOKENS (section 3.1). One live value per grant:
  // section 5 says the new token SHOULD invalidate the previous one, and this
  // service always does, so an old continuation token read from a log cannot
  // be replayed after the client has used its successor.
  // -------------------------------------------------------------------------
  /**
   * Issues a grant's continuation access token (section 3.1), invalidating the
   * previous one: one live value per grant.
   *
   * @param grant - the grant
   * @returns the new token's value
   */
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

  /**
   * Returns the grant a continuation access token belongs to.
   *
   * @param value - the presented token
   * @returns the grant, or null
   */
  grantByContinuation(value: unknown): any {
    const { log } = this.deps;
    const { continuations } = this.deps.stores;
    log.debug("Entering GnapStore.grantByContinuation().");
    const row = continuations.get(this.digest(value));
    log.debug("Leaving GnapStore.grantByContinuation().");
    return row ? this.getGrant(row.grantId) : null;
  }

  /**
   * Invalidates a grant's continuation access token.
   *
   * @param grant - the grant
   */
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
  /**
   * Records an interaction start handle — the unique path segment of a redirect
   * or app URI — for a grant.
   *
   * @param id - the handle
   * @param grantId - the grant's identifier
   */
  putInteraction(id: string, grantId: string): void {
    const { log, nowSec } = this.deps;
    const { interactions } = this.deps.stores;
    log.debug("Entering GnapStore.putInteraction().");
    interactions.set(id, { grantId: grantId, at: nowSec() });
    log.debug("Leaving GnapStore.putInteraction().");
  }

  /**
   * Returns the grant an interaction start handle belongs to.
   *
   * @param id - the handle
   * @returns the grant, or null
   */
  grantByInteraction(id: string): any {
    const { log } = this.deps;
    const { interactions } = this.deps.stores;
    log.debug("Entering GnapStore.grantByInteraction().");
    const row = id ? interactions.get(id) : null;
    log.debug("Leaving GnapStore.grantByInteraction().");
    return row ? this.getGrant(row.grantId) : null;
  }

  /**
   * Removes an interaction start handle; each is one-time-use.
   *
   * @param id - the handle
   */
  dropInteraction(id: string): void {
    const { log } = this.deps;
    const { interactions } = this.deps.stores;
    log.debug("Entering GnapStore.dropInteraction().");
    interactions.delete(id);
    log.debug("Leaving GnapStore.dropInteraction().");
  }

  /**
   * Records a user code for a grant.
   *
   * @param code - the user code
   * @param grantId - the grant's identifier
   */
  putUserCode(code: string, grantId: string): void {
    const { log, nowSec } = this.deps;
    const { userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.putUserCode().");
    userCodes.set(code, { grantId: grantId, at: nowSec() });
    log.debug("Leaving GnapStore.putUserCode().");
  }

  /**
   * Returns the grant a user code belongs to.
   *
   * @param code - the user code
   * @returns the grant, or null
   */
  grantByUserCode(code: string): any {
    const { log } = this.deps;
    const { userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.grantByUserCode().");
    const row = code ? userCodes.get(code) : null;
    log.debug("Leaving GnapStore.grantByUserCode().");
    return row ? this.getGrant(row.grantId) : null;
  }

  /**
   * Removes a user code; each is one-time-use.
   *
   * @param code - the user code
   */
  dropUserCode(code: string): void {
    const { log } = this.deps;
    const { userCodes } = this.deps.stores;
    log.debug("Entering GnapStore.dropUserCode().");
    userCodes.delete(code);
    log.debug("Leaving GnapStore.dropUserCode().");
  }

  /**
   * Says whether a user code is already in use.
   *
   * @param code - the user code
   * @returns true when taken
   */
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
  /**
   * Stores an access token's record, keyed by `jti` and indexed by the digest
   * of its value, so introspection of any format is one lookup.
   *
   * @param record - the token record
   * @param value - the token's value
   * @returns the record
   */
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

  /**
   * Saves a changed access token record.
   *
   * @param record - the token record
   * @returns the record
   */
  saveToken(record: any): any {
    const { log } = this.deps;
    const { tokens } = this.deps.stores;
    log.debug("Entering GnapStore.saveToken().");
    tokens.set(record.jti, record);
    log.debug("Leaving GnapStore.saveToken().");
    return record;
  }

  /**
   * Returns an access token's record by its identifier.
   *
   * @param jti - the token identifier
   * @returns the record, or nothing when there is none
   */
  tokenByJti(jti: string): any {
    const { log } = this.deps;
    const { tokens } = this.deps.stores;
    log.debug("Entering GnapStore.tokenByJti().");
    log.debug("Leaving GnapStore.tokenByJti().");
    return jti ? (tokens.get(jti) || null) : null;
  }

  /**
   * Returns an access token's record by its value.
   *
   * @param value - the presented token value
   * @returns the record, or null
   */
  tokenByValue(value: unknown): any {
    const { log } = this.deps;
    const { tokenValues } = this.deps.stores;
    log.debug("Entering GnapStore.tokenByValue().");
    const row = value ? tokenValues.get(this.digest(value)) : null;
    log.debug("Leaving GnapStore.tokenByValue().");
    return row ? this.tokenByJti(row.jti) : null;
  }

  /**
   * Lists the realm's access token records.
   *
   * @returns the records
   */
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
  /**
   * Issues an access token's management handle and management token (section
   * 3.2.1), replacing any previous management token. The handle is not the
   * token.
   *
   * @param record - the access token's record
   * @returns the management token's value
   */
  issueManagement(record: any): string {
    const { log } = this.deps;
    const { manageValues, manageHandles } = this.deps.stores;
    log.debug("Entering GnapStore.issueManagement(). jti=" + record.jti);
    if (record.manageHash) {
      manageValues.delete(record.manageHash);
    }
    if (!record.manageHandle) {
      record.manageHandle = this.handle(12);
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
  /**
   * Moves a management handle from a rotated token's record onto its successor,
   * so the management URI stays the same (section 6.1).
   *
   * @param from - the old record
   * @param to - the new record
   */
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

  /**
   * Returns the access token record a management handle and management token
   * name, when both agree.
   *
   * @param handle - the handle from the management URI
   * @param value - the presented management token
   * @returns the record, or null
   */
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

  /**
   * Removes an access token's management handle and token.
   *
   * @param record - the access token's record
   */
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
  /**
   * Records a dynamic instance identifier (section 3.5), indexed by digest.
   *
   * @param instanceId - the instance identifier
   * @param fields - what is recorded against it
   */
  putInstance(instanceId: unknown, fields?: object): void {
    const { log, nowSec } = this.deps;
    const { instances } = this.deps.stores;
    log.debug("Entering GnapStore.putInstance().");
    instances.set(this.digest(instanceId),
                  Object.assign({ createdAt: nowSec() }, fields));
    log.debug("Leaving GnapStore.putInstance().");
  }

  /**
   * Returns what is recorded against a dynamic instance identifier.
   *
   * @param instanceId - the instance identifier
   * @returns the record, or null
   */
  instanceById(instanceId: unknown): any {
    const { log } = this.deps;
    const { instances } = this.deps.stores;
    log.debug("Entering GnapStore.instanceById().");
    log.debug("Leaving GnapStore.instanceById().");
    return instanceId ?
      (instances.get(this.digest(instanceId)) || null) : null;
  }

  /**
   * Records a user reference (section 2.4.1), indexed by digest.
   *
   * @param reference - the reference
   * @param fields - what is recorded against it
   */
  putUserRef(reference: unknown, fields?: object): void {
    const { log, nowSec } = this.deps;
    const { userRefs } = this.deps.stores;
    log.debug("Entering GnapStore.putUserRef().");
    userRefs.set(this.digest(reference),
                 Object.assign({ createdAt: nowSec() }, fields));
    log.debug("Leaving GnapStore.putUserRef().");
  }

  /**
   * Returns what is recorded against a user reference.
   *
   * @param reference - the reference
   * @returns the record, or null
   */
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
  /**
   * Records a registered resource set (RFC 9767 section 3.4) under its
   * reference.
   *
   * @param reference - the reference handed back
   * @param fields - the set's fields, including its `canonical` form
   * @returns the stored row
   */
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

  /**
   * Returns a registered resource set by its reference.
   *
   * @param reference - the reference
   * @returns the row, or null
   */
  resourceByReference(reference: string): any {
    const { log } = this.deps;
    const { resources } = this.deps.stores;
    log.debug("Entering GnapStore.resourceByReference().");
    log.debug("Leaving GnapStore.resourceByReference().");
    return reference ? (resources.get(reference) || null) : null;
  }

  /**
   * Returns the resource set a resource server already registered with the same
   * canonical form, so the same reference can be handed back.
   *
   * @param canonical - the set's canonical form
   * @param rsIdentity - the resource server
   * @returns the row, or null
   */
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

  /**
   * Lists the realm's registered resource sets, newest first.
   *
   * @returns the rows
   */
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

  /**
   * Deletes a registered resource set.
   *
   * @param reference - the reference
   * @returns true when there was one to delete
   */
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
  // needs. `rememberOutcome()` is the same with the third answer a BOUNDED
  // history has (2026-09-18): 'full' — the history holds gnap.replayCacheSize
  // live signatures and refuses rather than forget one. A verifier that asks
  // `remember()` still refuses a full history, as a replay; the two in
  // `gnap_proof.ts` ask for the outcome so the refusal is named for what it
  // is (STS-GNAP-0718).
  // -------------------------------------------------------------------------
  /**
   * Records a replay key: true the first time, false for a repeat within the
   * window, or when the bounded history is full.
   *
   * @param key - the value to remember
   * @param lifetimeS - how long, in seconds
   * @returns true when new
   */
  remember(key: unknown, lifetimeS?: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapStore.remember().");
    log.debug("Leaving GnapStore.remember().");
    return this.rememberOutcome(key, lifetimeS) === 'new';
  }

  /**
   * Records a replay key and names the outcome: `new`, `seen`, or `full` when
   * the bounded history refuses rather than forget one.
   *
   * @param key - the value to remember
   * @param lifetimeS - how long, in seconds
   * @returns the outcome
   */
  rememberOutcome(key: unknown, lifetimeS?: unknown): 'new' | 'seen' | 'full' {
    const { log, nowSec, replayBound } = this.deps;
    const { replay } = this.deps.stores;
    log.debug("Entering GnapStore.rememberOutcome().");
    const now = nowSec();
    const hashed = this.digest(key);
    const seen = replay.get(hashed);
    if (seen && seen.until > now) {
      replayCount.hit();
      log.debug("Leaving GnapStore.rememberOutcome(). Seen.");
      return 'seen';
    }
    replayCount.miss();
    if (!seen) {
      const room = cacheRegistry.makeRoom(replay, replayBound(), {
        policy: 'refuse', counter: replayCount, name: 'gnap.signatures',
        setting: 'gnap.replayCacheSize',
        expired: function (row: any): boolean {
          return !row || row.until <= now;
        }
      });
      if (!room.ok) {
        log.debug("Leaving GnapStore.rememberOutcome(). Full.");
        return 'full';
      }
    }
    replay.set(hashed, { until: now + Math.max(1, Number(lifetimeS) || 1) });
    log.debug("Leaving GnapStore.rememberOutcome(). New.");
    return 'new';
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
  /**
   * Claims a value once across the cluster before acting on it (`gnap.<kind>`
   * scope), for the value's lifetime plus a skew.
   *
   * Never rejects.
   *
   * @param kind - what the value is
   * @param value - the value
   * @param lifetimeS - its lifetime, in seconds; unbounded values get a day
   * @param usedCode - the error code of a value already spent
   * @returns `{ ok: true, handle }`, or `{ ok: false, reason, errorCode }` with
   *   `reason` `used` or `store`
   */
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
  /**
   * Gives a claim back when what it guarded did not happen.
   *
   * @param handle - the claim's handle
   * @returns the release's result
   */
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
  /**
   * Prunes rows that can no longer be used, with bounded work per call.
   */
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
  /**
   * Returns the real modules and the module-scope stores the instance was built
   * from before the composition root (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapStoreDeps {
    helpers.log.debug("Entering GnapStore.defaultDeps().");
    helpers.log.debug("Leaving GnapStore.defaultDeps().");
    return {
      log: helpers.log,
      randomId: helpers.randomId,
      nowSec: helpers.nowSec,
      clusterClaims: clusterClaims,
      errorCodes: errorCodes,
      replayBound: function (): number {
        return Number(config.value('gnap.replayCacheSize'));
      },
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

/**
 * Everything GNAP mints, per trust realm, in one place: grants and every index
 * onto them.
 *
 * @namespace
 */
export = {
  GnapStore: GnapStore,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapStore): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  STATE: GnapStore.STATE,
  spend: slot.forward('spend'),
  unspend: slot.forward('unspend'),
  digest: slot.forward('digest'),
  mint: slot.forward('mint'),
  handle: slot.forward('handle'),
  exportGrant: slot.forward('exportGrant'),
  importGrant: slot.forward('importGrant'),
  forgetGrant: slot.forward('forgetGrant'),
  holdsTokenDigest: slot.forward('holdsTokenDigest'),
  holdsUserRefDigest: slot.forward('holdsUserRefDigest'),
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
  rememberOutcome: slot.forward('rememberOutcome'),
  prune: slot.forward('prune')
};
