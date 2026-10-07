// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: access_token_status.ts
//
// ---------------------------------------------------------------------------
// THE ACCESS-TOKEN STATUS LIST (#432 phase 2, rcbj's decision 4, 2026-10-03).
//
// A resource server that checks an access token ON ITS OWN — verifies the JWS
// against /oauth2/jwks and reads the claims — could not see a revocation
// until this file: RFC 9767 section 6.3 leaves it introspection or nothing,
// and RFC 9068 says the same of an OAuth JWT access token. The Token Status
// List draft (draft-ietf-oauth-status-list-21) names exactly this case in its
// section 1.1 ("to manage the statuses of issued access tokens"), and this
// service already speaks it for credentials (`oid4vc/vc_status.ts`).
//
// **ONE LIST PER TRUST REALM, FOR BOTH PROTOCOLS.** rcbj's decision 4 on #432:
// GNAP's two JWT formats (`jwt-signed`, `jwt-encrypted`) and every OAuth RFC
// 9068 access token carry `status: { status_list: { idx, uri } }` (section
// 6.1) naming a position in the SAME list. A resource server that accepts
// both kinds of token fetches one document; the realm publishes one count of
// live access tokens rather than two that could be compared.
//
// **THE PATH IS NEUTRAL, `/status-lists/access-tokens`**, with the section 9
// aggregation at `/status-lists`. Not under `/oauth2/`, because half of what
// it describes is GNAP's and a GNAP resource server has no reason to look
// there; not under `/gnap/` for the mirror-image reason; and not beside the
// credential lists under `/oid4vci/`, which are the credential issuer's and
// signed with ITS key. One list per realm also means one URI per realm: a
// named authorization server's tokens (`/{as}/oauth2/token`) name the same
// list, because decision 4 is per realm, not per authorization server.
//
// **ADVERTISED where each kind of resource server looks**: the authorization
// server's metadata member `status_list_aggregation_endpoint`, which section
// 9.1 RECOMMENDS for an issuer that is an OAuth authorization server, and the
// same member in GNAP's RS-facing discovery document (RFC 9767 section 3.1),
// where it is NOT a registered field and is documented as this service's own.
//
// **WHAT A BIT SAYS IS COMPUTED, NOT STORED TWICE** — `vc_status.ts`'s rule.
// A row keeps the token's `jti`, which protocol minted it and when it
// expires; the bit is INVALID when the ONE revocation register
// (`admin_stats.isRevoked()`, which every OAuth door and every GNAP JWT
// revocation writes, and which is global across cells) says the jti is
// revoked, or — for a GNAP token — when the grant engine's own record of it
// says revoked (a revocation the register forgot at `oauth2.maxRevokedJtis`
// is still on the record, and GNAP's introspection reads both). A token past
// its `exp` is INVALID too, and its index is free again. So `/oauth2/revoke`,
// a GNAP manage-URI DELETE, a rotation, a grant revoked by anybody,
// `/admin/tokens` and a global sign-out all reach the list without a line of
// their own.
//
// **ONE BIT PER TOKEN.** An access token is VALID or INVALID; nothing here
// suspends one (section 7.1's SUSPENDED is for a credential that may come
// back). **2^20 INDEXES PER REALM**: an access token lives minutes, not years,
// so the live population is the issuance rate times the lifetime, and a
// million positions is 128 KiB before compression and almost nothing after —
// while a list as small as the credential lists' 131,072 would be filled by a
// busy realm in an hour. A list with no free index REFUSES to mint
// (STS-OAUTH-0817) rather than reuse a live position, which section 13.3
// forbids.
//
// **INDEXES ARE RANDOM AND CLAIMED ACROSS THE CLUSTER** (section 13.2: an
// index that counts up says how many tokens came before), through
// `cluster/cluster_claims.js`, for as long as the token lives. `allocate()`
// is that; `allocateInProcess()` is the same claim answered synchronously
// where this process holds no shared claims table, for the one caller that
// must stay synchronous — and it answers null where there IS a table, so a
// token is never minted on an index nobody else was asked about.
//
// **THE SIGNER is the realm's RS256 key under the `access-token` use case** —
// the key a GNAP JWT and every OAuth access token not given another algorithm
// is signed with, so a resource server resolves one key for the token and its
// list (section 11.3), from the /oauth2/jwks it already reads.
//
// **CACHE-CONTROL** is `max-age` equal to the `ttl`, as `vc_status.ts` argues:
// the draft puts the caching instruction in the token (section 8.2), and a
// list describes no key. `oauth2.accessTokenStatusListTtlS` is therefore how
// long a revocation can take to reach a resource server that checks on its
// own — 60 seconds by default, where the credential lists say 300, because a
// revoked access token is in use NOW.
//
// **A ROUTE MODULE AND A LIBRARY**, `vc_status.ts`'s shape. `oauth2.ts` and
// `gnap/gnap_tokens.ts` require it; it requires `common/` libraries, the
// codec (`oid4vc/vc_status_codec.ts`, a library that requires only `common/`
// leaves — reused, not written twice) and the cluster claims, and reaches the
// GNAP token store LAZILY, so nothing it loads can close a cycle back.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import config = require('../common/config');
import realms = require('../common/realms');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import stats = require('../common/admin_stats');
import cacheRegistry = require('../common/cache_registry');
import InstanceSlot = require('../common/instance_slot');
import clusterClaims = require('../cluster/cluster_claims');
import codec = require('../oid4vc/vc_status_codec');

type RouteApp = typeof app;

/**
 * The number of indexes in a realm's access-token status list.
 */
const LIST_SIZE = 1048576;
// One bit: VALID or INVALID (section 4.1 permits 1, 2, 4 or 8).
const BITS = 1;
/**
 * The VALID status value.
 */
const VALID = 0;
/**
 * The INVALID status value.
 */
const INVALID = 1;

/**
 * The path of the realm's access-token status list.
 */
const LIST_PATH = '/status-lists/access-tokens';
/**
 * The path of the Status List Aggregation (section 9).
 */
const AGGREGATION_PATH = '/status-lists';

/**
 * The media type of a Status List Token in JWT form.
 */
const JWT_TYPE = 'application/statuslist+jwt';
/**
 * The media type of a Status List Token in CWT form.
 */
const CWT_TYPE = 'application/statuslist+cwt';

/**
 * The kinds of access token the list describes.
 */
const KINDS = ['oauth', 'gnap'];

// A claim outlives the token by the skew the other single-use values allow.
const CLAIM_SKEW_MS = 60 * 1000;
const ALLOCATION_ATTEMPTS = 32;

// idx -> { jti, kind, expiresAt (ms), allocatedAt (ms) }
// PER TRUST REALM, persisted, and GLOBAL across cells
// (`persistence/tiers.js`): one list per realm, which every cell publishes,
// and a token revoked in one cell must read INVALID at every other.
const entries = realms.map({ persist: 'access_token_status.entries' });

// realm|form -> { digest, token, signedAt, ttlMs }: the last list this
// process signed, re-signed when the bits change or it is half-way to its
// ttl. PER PROCESS; a few rows per realm.
const signedLists = new Map<string, any>();
const MAX_SIGNED = 1024;

const entriesCount = cacheRegistry.register({
  name: 'oauth2.access-token-status',
  title: 'Access-token status entries',
  description: 'Each live access token\'s index in this realm\'s ' +
    'access-token status list — OAuth RFC 9068 tokens and GNAP\'s two JWT ' +
    'formats — with its jti, so the bit can be computed from the ' +
    'revocation register.',
  owner: 'oauth-oidc/access_token_status.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a token\'s status was found here',
  settings: ['oauth2.accessTokenTtlS', 'gnap.accessTokenLifetimeS'],
  maxEntries: function (): number {
    return LIST_SIZE;
  },
  bound: 'Enforced: the list holds ' + LIST_SIZE + ' indexes per realm; a ' +
    'list with no free index REFUSES to mint the access token ' +
    '(STS-OAUTH-0817) rather than reuse a live one.',
  lifetime: function (): string {
    return 'as long as the access token it describes; its index is free ' +
      'again after that.';
  },
  // A token past its expiry, whose index `allocate()` already treats as free
  // and whose bit reads INVALID on `exp` alone — ejecting it changes nothing
  // a resource server may rely on (#49 P5's job, `caches.eject-expired`).
  eject: cacheRegistry.realmMapEjector(realms, entries,
    function (row: any, idx: unknown, now: number): boolean {
      return !!(row && row.expiresAt && row.expiresAt <= now);
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, entries,
      function (row: any, idx: unknown): object {
        return { key: 'idx:' + String(idx),
                 validUntil: Number((row && row.expiresAt) || 0) || null };
      });
  }
});

const signedCount = cacheRegistry.register({
  name: 'oauth2.access-token-status-lists',
  title: 'Signed access-token status lists',
  description: 'The last access-token Status List Token this process ' +
    'signed for each realm, reused while the list has not changed.',
  owner: 'oauth-oidc/access_token_status.ts',
  scope: 'process',
  kind: 'cache',
  persisted: false,
  hitMeaning: 'a list was served without signing it again',
  settings: ['oauth2.accessTokenStatusListTtlS'],
  maxEntries: function (): number {
    return MAX_SIGNED;
  },
  bound: 'Enforced: ' + MAX_SIGNED + ' signed lists for the process, the ' +
    'oldest dropped and signed again when next asked for.',
  lifetime: function (): string {
    return 'until the list changes, or half of ' +
      'oauth2.accessTokenStatusListTtlS.';
  },
  eject: cacheRegistry.mapEjector(signedLists,
    function (row: any, key: unknown, now: number): boolean {
      return !(row && now - Number(row.signedAt) < Number(row.ttlMs) / 2);
    }),
  entries: function (): unknown[] {
    const out: unknown[] = [];
    signedLists.forEach(function (row, key) {
      out.push({ realm: String(key).split('|')[0], key: String(key),
                 validUntil: row.signedAt + row.ttlMs / 2 });
    });
    return out;
  }
});

interface AccessTokenStatusDeps {
  log: typeof helpers.log;
  config: { value(key: string): any };
  realms: typeof realms;
  stsCrypto: typeof stsCrypto;
  errorCodes: typeof errorCodes;
  isRevoked: (jti: string) => boolean;
  // Whether the GNAP grant engine's own record of a token says revoked;
  // reached lazily, because `gnap/` requires this module.
  gnapRecordRevoked: (jti: string) => boolean;
  signingKeyForAsync: typeof helpers.signingKeyForAsync;
  publishedKidFor: typeof helpers.publishedKidFor;
  certificateHeaderFor: typeof helpers.certificateHeaderFor;
  STS: typeof helpers.STS;
  baseUrlOf: typeof helpers.baseUrlOf;
  pinnedBaseUrl: () => string;
  clusterClaims: typeof clusterClaims;
  entries: any;
  now: () => number;
}

/**
 * A reference an access token carries: `status.status_list` (section 6.1).
 */
interface StatusReference {
  idx: number;
  uri: string;
}

/**
 * The access-token status list: one per realm, describing every OAuth RFC 9068
 * access token and every GNAP `jwt-signed` / `jwt-encrypted` token, its bit
 * computed from the revocation register.
 */
class AccessTokenStatus {
  /**
   * The number of indexes in a realm's list.
   */
  static readonly LIST_SIZE = LIST_SIZE;
  /**
   * Bits per token.
   */
  static readonly BITS = BITS;
  /**
   * The path of the realm's list.
   */
  static readonly LIST_PATH = LIST_PATH;
  /**
   * The path of the aggregation.
   */
  static readonly AGGREGATION_PATH = AGGREGATION_PATH;
  /**
   * The VALID status value.
   */
  static readonly VALID = VALID;
  /**
   * The INVALID status value.
   */
  static readonly INVALID = INVALID;

  /**
   * Builds the list from the modules and stores it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: AccessTokenStatusDeps) {
    deps.log.debug("Entering AccessTokenStatus.constructor().");
    deps.log.debug("Leaving AccessTokenStatus.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): AccessTokenStatusDeps {
    helpers.log.debug("Entering AccessTokenStatus.defaultDeps().");
    helpers.log.debug("Leaving AccessTokenStatus.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      isRevoked: stats.isRevoked,
      gnapRecordRevoked: function gnapRecordRevoked(jti: string): boolean {
        helpers.log.debug("Entering gnapRecordRevoked().");
        let record = null;
        try {
          record = require('../gnap/gnap_store').tokenByJti(jti);
        } catch (e) {
          helpers.log.debug("Caught in gnapRecordRevoked(): " +
                            ((e && e.message) || e));
          // No GNAP store in this process (an in-process test of the OAuth
          // half): the revocation register is then the whole answer.
          record = null;
        }
        helpers.log.debug("Leaving gnapRecordRevoked().");
        return !!(record && record.revoked);
      },
      signingKeyForAsync: helpers.signingKeyForAsync,
      publishedKidFor: helpers.publishedKidFor,
      certificateHeaderFor: helpers.certificateHeaderFor,
      STS: helpers.STS,
      baseUrlOf: helpers.baseUrlOf,
      pinnedBaseUrl: helpers.pinnedBaseUrl,
      clusterClaims: clusterClaims,
      entries: entries,
      now: function now(): number {
        return Date.now();
      }
    };
  }

  private ttlSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering AccessTokenStatus.ttlSeconds().");
    const s = Number(config.value('oauth2.accessTokenStatusListTtlS'));
    log.debug("Leaving AccessTokenStatus.ttlSeconds().");
    return isFinite(s) && s > 0 ? Math.floor(s) : 60;
  }

  private lifetimeSeconds(): number {
    const { log, config } = this.deps;
    log.debug("Entering AccessTokenStatus.lifetimeSeconds().");
    const s = Number(config.value('oauth2.accessTokenStatusListLifetimeS'));
    log.debug("Leaving AccessTokenStatus.lifetimeSeconds().");
    return isFinite(s) && s > 0 ? Math.floor(s) : 3600;
  }

  // THE REALM'S BASE FROM ANY BASE UNDER IT. A named authorization server's
  // base is `<realm base>/<id>`, and a token minted there names the realm's
  // one list; so the list's URI is the pinned public base (or the origin of
  // the base it was handed) plus the AMBIENT realm's prefix — which is how
  // `helpers.baseUrlOf()` builds a realm base in the first place, and needs
  // no request (a CIBA push mints from the scheduler).
  /**
   * Returns the realm's base URL from any base URL under it — a named
   * authorization server's included.
   *
   * @param anyBase - a base URL in the ambient realm
   * @returns the realm's base URL
   */
  realmBaseOf(anyBase: string): string {
    const { log, realms, pinnedBaseUrl } = this.deps;
    log.debug("Entering AccessTokenStatus.realmBaseOf().");
    let origin = pinnedBaseUrl();
    if (!origin) {
      try {
        origin = new URL(String(anyBase)).origin;
      } catch (e) {
        log.debug("Caught in AccessTokenStatus.realmBaseOf(): " +
                  ((e && e.message) || e));
        origin = String(anyBase || '').replace(/\/+$/, '');
      }
    }
    log.debug("Leaving AccessTokenStatus.realmBaseOf().");
    return origin + realms.currentPrefix();
  }

  /**
   * Returns the URI of the ambient realm's list.
   *
   * @param anyBase - a base URL in the ambient realm
   * @returns the list's URI
   */
  listUri(anyBase: string): string {
    const { log } = this.deps;
    log.debug("Entering AccessTokenStatus.listUri().");
    log.debug("Leaving AccessTokenStatus.listUri().");
    return this.realmBaseOf(anyBase) + LIST_PATH;
  }

  /**
   * Returns the URI of the ambient realm's aggregation.
   *
   * @param anyBase - a base URL in the ambient realm
   * @returns the aggregation's URI
   */
  aggregationUri(anyBase: string): string {
    const { log } = this.deps;
    log.debug("Entering AccessTokenStatus.aggregationUri().");
    log.debug("Leaving AccessTokenStatus.aggregationUri().");
    return this.realmBaseOf(anyBase) + AGGREGATION_PATH;
  }

  // The checks both allocators make before claiming anything.
  private wanted(opts: { jti: string; kind: string; expiresAt: number }):
      { expiresAt: number } {
    const { log, now } = this.deps;
    log.debug("Entering AccessTokenStatus.wanted().");
    if (!opts || !opts.jti || KINDS.indexOf(String(opts.kind)) < 0) {
      log.debug("Leaving AccessTokenStatus.wanted(). Malformed.");
      throw new Error('an access-token status index is allocated for a jti ' +
                      'and one of ' + KINDS.join(', '));
    }
    const expiresAt = Number(opts.expiresAt) > now()
      ? Number(opts.expiresAt) : now() + 3600 * 1000;
    log.debug("Leaving AccessTokenStatus.wanted().");
    return { expiresAt: expiresAt };
  }

  // Records the row for a claimed index and answers the reference.
  private take(idx: number, opts: { jti: string; kind: string; base: string },
               expiresAt: number): StatusReference {
    const { log, entries, now } = this.deps;
    log.debug("Entering AccessTokenStatus.take(). idx=" + idx);
    entries.set(String(idx), { jti: String(opts.jti), kind: String(opts.kind),
                               expiresAt: expiresAt, allocatedAt: now() });
    log.debug("Leaving AccessTokenStatus.take().");
    return { idx: idx, uri: this.listUri(opts.base) };
  }

  // Whether this process's copy of the list holds the index for a live
  // token. The claim decides; this only spares it an index known to be taken.
  private freeLocally(idx: number): boolean {
    const { log, entries, now } = this.deps;
    log.debug("Entering AccessTokenStatus.freeLocally().");
    const held = entries.get(String(idx));
    log.debug("Leaving AccessTokenStatus.freeLocally().");
    return !(held && (!held.expiresAt || held.expiresAt > now()));
  }

  private full(): Error {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessTokenStatus.full().");
    log.error(errorCodes.tag('STS-OAUTH-0817') + 'access_token_status: no ' +
              'free index was found in ' + ALLOCATION_ATTEMPTS + ' ' +
              'attempts; the list of ' + LIST_SIZE + ' is nearly full, so ' +
              'the access token is not minted.');
    const e: any = new Error('no access-token status index could be ' +
                             'allocated: the list is full');
    log.debug("Leaving AccessTokenStatus.full().");
    return errorCodes.mark(e, 'STS-OAUTH-0817');
  }

  // ---------------------------------------------------------------------------
  // ALLOCATE an index for an access token about to be signed.
  // ---------------------------------------------------------------------------
  /**
   * Allocates an index for an access token about to be signed, claimed across
   * the cluster for as long as the token lives.
   *
   * @param opts - `jti`, `kind` (`oauth` or `gnap`), `expiresAt` (ms) and
   *   `base` (any base URL in the ambient realm)
   * @returns the reference the token carries in `status.status_list`
   * @throws Error marked STS-OAUTH-0816 when the claim store cannot be asked,
   *   STS-OAUTH-0817 when the list is full
   */
  async allocate(opts: { jti: string; kind: string; expiresAt: number;
                         base: string }): Promise<StatusReference> {
    const { log, clusterClaims, errorCodes, now } = this.deps;
    log.debug("Entering AccessTokenStatus.allocate(). kind=" + opts.kind);
    const { expiresAt } = this.wanted(opts);
    for (let attempt = 0; attempt < ALLOCATION_ATTEMPTS; attempt++) {
      const idx = stsCrypto.randomInt(0, LIST_SIZE);
      if (!this.freeLocally(idx)) {
        continue;
      }
      const claimed = await clusterClaims.claim({
        scope: 'oauth2.access-token-status-index', value: String(idx),
        ttlMs: Math.max(0, expiresAt - now()) + CLAIM_SKEW_MS });
      if (!claimed.ok) {
        if (claimed.reason !== 'used') {
          log.error(errorCodes.tag('STS-OAUTH-0816') + 'access_token_status: ' +
                    'the claim store could not be asked for an index (' +
                    (claimed.why || 'no reason given') + '), so the access ' +
                    'token is not minted.');
          log.debug("Leaving AccessTokenStatus.allocate(). The store failed.");
          const e: any = new Error('no access-token status index could be ' +
                                   'allocated: the claim store could not be ' +
                                   'asked');
          throw errorCodes.mark(e, 'STS-OAUTH-0816');
        }
        continue;
      }
      const ref = this.take(idx, opts, expiresAt);
      log.debug("Leaving AccessTokenStatus.allocate(). idx=" + idx + ".");
      return ref;
    }
    log.debug("Leaving AccessTokenStatus.allocate(). Full.");
    throw this.full();
  }

  // THE SAME CLAIM, SYNCHRONOUSLY, where it can be: `claimInProcess()`
  // answers exactly what `claim()` would when this process holds no shared
  // claims table, and null when it does — and then this answers null too, so
  // the caller must go the asynchronous way rather than mint on an index no
  // other node was asked about.
  /**
   * Allocates an index synchronously when this process holds no shared claims
   * table; answers null when one is configured.
   *
   * @param opts - as for `allocate()`
   * @returns the reference, or null when the caller must `allocate()`
   * @throws Error marked STS-OAUTH-0816 or STS-OAUTH-0817, as `allocate()`
   */
  allocateInProcess(opts: { jti: string; kind: string; expiresAt: number;
                            base: string }): StatusReference | null {
    const { log, clusterClaims, errorCodes, now } = this.deps;
    log.debug("Entering AccessTokenStatus.allocateInProcess(). kind=" +
              opts.kind);
    const { expiresAt } = this.wanted(opts);
    for (let attempt = 0; attempt < ALLOCATION_ATTEMPTS; attempt++) {
      const idx = stsCrypto.randomInt(0, LIST_SIZE);
      if (!this.freeLocally(idx)) {
        continue;
      }
      const claimed = clusterClaims.claimInProcess({
        scope: 'oauth2.access-token-status-index', value: String(idx),
        ttlMs: Math.max(0, expiresAt - now()) + CLAIM_SKEW_MS });
      if (claimed === null) {
        log.debug("Leaving AccessTokenStatus.allocateInProcess(). A shared " +
                  "table: allocate() instead.");
        return null;
      }
      if (!claimed.ok) {
        if (claimed.reason !== 'used') {
          log.error(errorCodes.tag('STS-OAUTH-0816') + 'access_token_status: ' +
                    'the claim store could not be asked for an index (' +
                    (claimed.why || 'no reason given') + ').');
          log.debug("Leaving AccessTokenStatus.allocateInProcess(). The " +
                    "store failed.");
          const e: any = new Error('no access-token status index could be ' +
                                   'allocated: the claim store could not be ' +
                                   'asked');
          throw errorCodes.mark(e, 'STS-OAUTH-0816');
        }
        continue;
      }
      const ref = this.take(idx, opts, expiresAt);
      log.debug("Leaving AccessTokenStatus.allocateInProcess(). idx=" + idx +
                ".");
      return ref;
    }
    log.debug("Leaving AccessTokenStatus.allocateInProcess(). Full.");
    throw this.full();
  }

  // THE EFFECTIVE STATUS OF ONE INDEX: see the header. An unknown index is
  // INVALID — no live token holds it.
  /**
   * Returns an index's effective status, computed from the revocation
   * register (and, for a GNAP token, its record); an unknown or expired index
   * is INVALID.
   *
   * @param idx - the index
   * @returns VALID (0) or INVALID (1)
   */
  statusOf(idx: unknown): number {
    const { log, entries, isRevoked, gnapRecordRevoked, now } = this.deps;
    log.debug("Entering AccessTokenStatus.statusOf().");
    const row = entries.get(String(idx));
    if (!row) {
      entriesCount.miss();
      log.debug("Leaving AccessTokenStatus.statusOf(). No such entry.");
      return INVALID;
    }
    entriesCount.hit();
    if (row.expiresAt && row.expiresAt <= now()) {
      log.debug("Leaving AccessTokenStatus.statusOf(). Expired.");
      return INVALID;
    }
    if (isRevoked(row.jti)) {
      log.debug("Leaving AccessTokenStatus.statusOf(). Revoked.");
      return INVALID;
    }
    if (row.kind === 'gnap' && gnapRecordRevoked(row.jti)) {
      log.debug("Leaving AccessTokenStatus.statusOf(). Revoked on its GNAP " +
                "record.");
      return INVALID;
    }
    log.debug("Leaving AccessTokenStatus.statusOf(). Valid.");
    return VALID;
  }

  /**
   * Returns the status of the token with a jti, for the console and the
   * tests: its index and its effective value, or null when it has none.
   *
   * @param jti - the token's jti
   * @returns `{ idx, status }`, or null
   */
  statusOfJti(jti: string): { idx: number; status: number } | null {
    const { log, entries } = this.deps;
    log.debug("Entering AccessTokenStatus.statusOfJti().");
    let found: { idx: number; status: number } | null = null;
    entries.forEach((row: any, idx: string) => {
      if (!found && row && row.jti === String(jti)) {
        found = { idx: Number(idx), status: this.statusOf(idx) };
      }
    });
    log.debug("Leaving AccessTokenStatus.statusOfJti().");
    return found;
  }

  // The packed values of the ambient realm's list. Only INVALID bits of LIVE
  // rows are set: an expired row is an index nobody holds, and section 13.3's
  // default for an index nobody holds is VALID (0x00) — a resource server
  // rejects the expired token on its own `exp`.
  private listBytes(): Buffer {
    const { log, entries, now } = this.deps;
    log.debug("Entering AccessTokenStatus.listBytes().");
    const values: number[] = [];
    const t = now();
    entries.forEach((row: any, idx: string) => {
      if (row && row.expiresAt && row.expiresAt <= t) {
        return;
      }
      if (this.statusOf(idx) !== VALID) {
        values[Number(idx)] = INVALID;
      }
    });
    const bytes = codec.packTsl(values, BITS, LIST_SIZE);
    log.debug("Leaving AccessTokenStatus.listBytes().");
    return bytes;
  }

  /**
   * Counts the ambient realm's live entries and how many read INVALID.
   *
   * @returns `{ size, bits, live, invalid }`
   */
  counts(): { size: number; bits: number; live: number; invalid: number } {
    const { log, entries, now } = this.deps;
    log.debug("Entering AccessTokenStatus.counts().");
    let live = 0;
    let invalid = 0;
    const t = now();
    entries.forEach((row: any, idx: string) => {
      if (row && row.expiresAt && row.expiresAt <= t) {
        return;
      }
      live += 1;
      if (this.statusOf(idx) !== VALID) {
        invalid += 1;
      }
    });
    log.debug("Leaving AccessTokenStatus.counts().");
    return { size: LIST_SIZE, bits: BITS, live: live, invalid: invalid };
  }

  // The key the list is signed with: see the header.
  private async signerAsync(): Promise<{ alg: string; key: any; kid: string;
                                         headerKid: string }> {
    const { log, STS, signingKeyForAsync, publishedKidFor } = this.deps;
    log.debug("Entering AccessTokenStatus.signerAsync().");
    const signer = await signingKeyForAsync('RS256', 'access-token');
    if (signer.kid === STS.kid) {
      log.debug("Leaving AccessTokenStatus.signerAsync(). The realm key.");
      return { alg: 'RS256', key: STS.privateKey, kid: STS.kid,
               headerKid: publishedKidFor(STS.kid) };
    }
    log.debug("Leaving AccessTokenStatus.signerAsync(). A pinned or group " +
              "key.");
    return { alg: 'RS256', key: signer.key, kid: signer.kid,
             headerKid: publishedKidFor(signer.kid) };
  }

  // One cached signed list, or a slot to sign into.
  private reuse(form: string, bytes: Buffer): any {
    const { log, realms, now } = this.deps;
    log.debug("Entering AccessTokenStatus.reuse(). " + form);
    const key = realms.currentId() + '|' + form;
    const digest = stsCrypto.digest('sha256', bytes, 'hex');
    const held = signedLists.get(key);
    if (held && held.digest === digest &&
        now() - held.signedAt < held.ttlMs / 2) {
      signedCount.hit();
      log.debug("Leaving AccessTokenStatus.reuse(). Reused.");
      return held;
    }
    signedCount.miss();
    log.debug("Leaving AccessTokenStatus.reuse(). Sign again.");
    return { key: key, digest: digest, token: null };
  }

  private remember(slot: any, token: any): void {
    const { log, now } = this.deps;
    log.debug("Entering AccessTokenStatus.remember().");
    if (!signedLists.has(slot.key)) {
      cacheRegistry.makeRoom(signedLists, MAX_SIGNED,
                             { counter: signedCount });
    }
    signedLists.set(slot.key, { digest: slot.digest, token: token,
                                signedAt: now(),
                                ttlMs: this.ttlSeconds() * 1000 });
    log.debug("Leaving AccessTokenStatus.remember().");
  }

  /**
   * Builds the Status List Token in JWT form (section 5.1).
   *
   * @param req - the request, for the list's URI
   * @returns the signed JWT
   */
  async listJwt(req: any): Promise<string> {
    const { log, stsCrypto, certificateHeaderFor, baseUrlOf, now } =
      this.deps;
    log.debug("Entering AccessTokenStatus.listJwt().");
    const bytes = this.listBytes();
    const slot = this.reuse('jwt', bytes);
    if (slot.token) {
      log.debug("Leaving AccessTokenStatus.listJwt(). Reused.");
      return slot.token;
    }
    const signer = await this.signerAsync();
    const iat = Math.floor(now() / 1000);
    const base = baseUrlOf(req);
    const payload = codec.statusListJwtPayload({
      sub: this.listUri(base), iat: iat, exp: iat + this.lifetimeSeconds(),
      ttl: this.ttlSeconds(), bits: BITS, bytes: bytes,
      aggregationUri: this.aggregationUri(base) });
    const token = await stsCrypto.signJwsAsync(payload, signer.key, {
      algorithm: signer.alg,
      header: Object.assign(certificateHeaderFor('access-token', signer.alg,
                                                 signer.kid),
                            { alg: signer.alg, typ: 'statuslist+jwt',
                              kid: signer.headerKid })
    });
    this.remember(slot, token);
    log.debug("Leaving AccessTokenStatus.listJwt().");
    return token;
  }

  /**
   * Builds the Status List Token in CWT form (section 5.2).
   *
   * @param req - the request, for the list's URI
   * @returns the CWT bytes
   */
  async listCwt(req: any): Promise<Buffer> {
    const { log, baseUrlOf, now } = this.deps;
    log.debug("Entering AccessTokenStatus.listCwt().");
    const bytes = this.listBytes();
    const slot = this.reuse('cwt', bytes);
    if (slot.token) {
      log.debug("Leaving AccessTokenStatus.listCwt(). Reused.");
      return slot.token;
    }
    const signer = await this.signerAsync();
    const iat = Math.floor(now() / 1000);
    const base = baseUrlOf(req);
    const token = await codec.statusListCwtAsync({
      sub: this.listUri(base), iat: iat, exp: iat + this.lifetimeSeconds(),
      ttl: this.ttlSeconds(), bits: BITS, bytes: bytes,
      aggregationUri: this.aggregationUri(base),
      key: signer.key, alg: signer.alg, kid: signer.headerKid });
    this.remember(slot, token);
    log.debug("Leaving AccessTokenStatus.listCwt().");
    return token;
  }

  // ---------------------------------------------------------------------------
  // THE ROUTES.
  // ---------------------------------------------------------------------------
  private failed(res: any, e: any): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessTokenStatus.failed().");
    log.error(errorCodes.tag('STS-OAUTH-0818') + 'access_token_status: the ' +
              'access-token status list could not be served: ' +
              ((e && (e.stack || e.message)) || e));
    if (!res.headersSent) {
      errorCodes.mark(res, 'STS-OAUTH-0818');
      res.status(500).type('text/plain').send('The access-token status ' +
                                              'list could not be built.\n');
    }
    log.debug("Leaving AccessTokenStatus.failed().");
  }

  // Section 8.4's `time` asks for a historical list, which is not kept: 501,
  // as the draft says a server that does not support it SHOULD answer.
  private historical(req: any, res: any): boolean {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AccessTokenStatus.historical().");
    if (req.query && req.query.time !== undefined) {
      errorCodes.mark(res, 'STS-OAUTH-0819');
      res.status(501).type('text/plain').send('This authorization server ' +
        'keeps no historical access-token status lists ' +
        '(draft-ietf-oauth-status-list section 8.4).\n');
      log.debug("Leaving AccessTokenStatus.historical(). Refused.");
      return true;
    }
    log.debug("Leaving AccessTokenStatus.historical().");
    return false;
  }

  /**
   * Registers the list and the aggregation.
   *
   * Called by `common/protocol_stack.ts`, just after the authorization
   * server's own routes.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: RouteApp): void {
    const { log, baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering AccessTokenStatus.registerRoutes().");
    app.get(LIST_PATH, function (req, res) {
      log.debug('Entering GET ' + LIST_PATH + '.');
      if (self.historical(req, res)) {
        log.debug('Leaving GET ' + LIST_PATH + '. Historical.');
        return;
      }
      // Section 8.1: the JWT unless `Accept` names the CWT ahead of it.
      const accept = String(req.headers.accept || '');
      const cwt = accept.indexOf(CWT_TYPE) >= 0 &&
        (accept.indexOf(JWT_TYPE) < 0 ||
         accept.indexOf(CWT_TYPE) < accept.indexOf(JWT_TYPE));
      const work: Promise<any> = cwt ? self.listCwt(req) : self.listJwt(req);
      work.then(function (token: any) {
        res.status(200).set('Content-Type', cwt ? CWT_TYPE : JWT_TYPE)
          .set('Cache-Control', 'max-age=' + self.ttlSeconds())
          .set('Vary', 'Accept')
          .send(token);
        log.debug('Leaving GET ' + LIST_PATH + '.');
      }).catch(function (e: any) {
        log.debug("Caught in AccessTokenStatus.registerRoutes(): " +
                  ((e && e.message) || e));
        self.failed(res, e);
      });
    });
    app.get(AGGREGATION_PATH, function (req, res) {
      log.debug('Entering GET ' + AGGREGATION_PATH + '.');
      res.status(200).type('application/json')
        .set('Cache-Control', 'max-age=' + self.ttlSeconds())
        .send(JSON.stringify({
          status_lists: [self.listUri(baseUrlOf(req))] }));
      log.debug('Leaving GET ' + AGGREGATION_PATH + '.');
    });
    log.debug("Leaving AccessTokenStatus.registerRoutes().");
  }
}

const slot = new InstanceSlot<AccessTokenStatus>(
  'oauth-oidc/access_token_status',
  () => new AccessTokenStatus(AccessTokenStatus.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The access-token status list: one per realm, for OAuth RFC 9068 tokens and
 * GNAP's two JWT formats.
 *
 * @namespace
 */
export = {
  AccessTokenStatus: AccessTokenStatus,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: AccessTokenStatus): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  LIST_SIZE: LIST_SIZE,
  BITS: BITS,
  LIST_PATH: LIST_PATH,
  AGGREGATION_PATH: AGGREGATION_PATH,
  VALID: VALID,
  INVALID: INVALID,
  JWT_TYPE: JWT_TYPE,
  CWT_TYPE: CWT_TYPE,
  realmBaseOf: slot.forward('realmBaseOf'),
  listUri: slot.forward('listUri'),
  aggregationUri: slot.forward('aggregationUri'),
  allocate: slot.forward('allocate'),
  allocateInProcess: slot.forward('allocateInProcess'),
  statusOf: slot.forward('statusOf'),
  statusOfJti: slot.forward('statusOfJti'),
  counts: slot.forward('counts'),
  listJwt: slot.forward('listJwt'),
  listCwt: slot.forward('listCwt')
};
