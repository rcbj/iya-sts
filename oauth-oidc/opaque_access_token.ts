// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: opaque_access_token.ts
//
// ===========================================================================
// AN OPAQUE OAUTH ACCESS TOKEN, OFF BY DEFAULT (#501).
//
// The default access token is an RFC 9068 JWT (`oauth2.accessTokenFormat` is
// `jwt`). `opaque` makes a NEW access token a 256-bit handle instead: 32
// bytes from `crypto.randomBytes`, base64url, no padding and no `.`. The
// claims stay in this realm. The client carries only the handle. Refresh
// tokens stay nested JWTs. ID tokens stay JWTs.
//
// **THE HANDLE IS NEVER STORED AND NEVER LOGGED.** The store key is
// `crypto.credentialDigest` (SHA-256, base64url). A heap snapshot, a
// replicated row or a log line yields nothing that can be presented. A
// lookup hashes whatever was presented and asks the store: there is no
// length check and no charset check before the hash, so a partial guess
// learns nothing a complete miss does not.
//
// **A MISS AND A HIT ARE DIFFERENT DOORS.** `lookup()` does not rate-limit
// and does not read the setting. An empty string or anything containing `.`
// is `not-opaque` (a JWT, including one issued before the setting changed).
// A hash miss is `unknown`. An expired row is deleted and answered
// `inactive`/`expired`, with a copy of the claims so the caller can still
// name the time. A row with `revokedAt`, or a jti `admin_stats.isRevoked`
// already holds, is `inactive`/`revoked`. Anything else is `active`.
// `resolve()` is `lookup()` plus, only when the realm currently issues
// opaque tokens and the answer is `unknown`, one miss in the shared bucket
// `oauth2.opaque-access-token`. A success, a JWT, and a known expired or
// revoked token are not counted. `noteMiss()` itself returns null when the
// realm does not issue opaque tokens, and it counts in whatever realm is
// ambient when it is called — the admin door enters that realm itself.
//
// **THE CAP REFUSES.** `oauth2.maxOpaqueAccessTokens` is the ceiling. A
// mint that would pass it drops expired rows first and then throws
// STS-OAUTH-0979. A live token is not evicted to make room. Three draws
// that all collide throw STS-OAUTH-0984; the handle is 256 bits, so that
// is a broken generator rather than a full store.
//
// **NO NEW SCHEDULER JOB.** Expiry is `expiresAt` on the row (so
// `persistence.minted-expiry-purge` takes it), a delete at read time, the
// cap at insert, and `cacheRegistry.realmMapEjector` (so
// `caches.eject-expired` takes it). The read-time check is the correctness
// one; the job is housekeeping.
//
// **CELL, NOT GLOBAL, AND NOT ON DEMAND.** The jti is already stamped to
// the minting cell. The cell's database is what that cell's nodes share, so
// the row is `oauth2.opaqueAccessTokens` on the cell tier. The store is not
// on demand: a jti-only caller (`keysForJti`) must find the row from the
// index without a second read, and the cap walks the ambient partition.
// Tombstones are safe because a key is a random digest and is never written
// again after it is deleted. `mergeRow` keeps this node's claims and only
// raises `revokedAt`, so a replica that has not heard of a revocation
// cannot clear one, and merging the answer with either side again is the
// answer.
//
// **`signJwt` IS NOT CALLED.** It logs the compact JWS. `mint()` asks
// `admin_stats.recordJwt` with an empty signed string, so /admin/tokens and
// `isRevoked(jti)` still see the token, and the registry stores the length
// of that string rather than a secret. `admin_stats` is required inside
// `mint` and inside the revocation check, not here: it requires federation,
// and a top-level require from a library `dpop` and `oauth2` require would
// close that cycle. If `recordJwt` throws, the row is deleted and the error
// is rethrown, so a token the registry does not know is not handed out.
//
// **IT IS A LIBRARY (rule 3).** It registers no route. It requires
// `helpers`, `instance_slot`, `config`, `crypto`, `error_codes`, `realms`,
// `websecurity` and `cache_registry`, none of which requires it back.
// `dpop`, `oauth2`, `admin_api` and the debugger may require it. The
// account API reaches it lazily, because that module loads before `oauth2`.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50). `OpaqueAccessToken` takes the logger, the
// settings, `crypto`, the error codes and `websecurity` through its
// constructor. The store is MODULE-LEVEL, not a field: two instances would
// still share it, which is what a per-realm partition already is, and the
// cache descriptor is registered when the module loads, before the
// composition root installs the instance. The module exports the methods as
// FACADES over the instance the root builds (R2).
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import websecurity = require('../common/websecurity');
import cacheRegistry = require('../common/cache_registry');

// A JSON-shaped value: a token's claims, an issuance context.
type Json = any;

// What lookup() and resolve() answer. `limited` is resolve() only.
interface HandleLookup {
  kind: 'not-opaque' | 'unknown' | 'inactive' | 'active' | 'limited';
  why?: 'expired' | 'revoked';
  claims?: Json;
  retryAfterS?: number;
}

interface OpaqueAccessTokenDeps {
  log: typeof helpers.log;
  config: { value(key: string): Json };
  stsCrypto: { credentialDigest(value: unknown): string;
               randomBytes(size: number): { toString(enc: string): string } };
  errorCodes: typeof errorCodes;
  websecurity: { attempt(what: string, req: Json, identity?: unknown): Json };
}

// 32 bytes is 256 bits. base64url of that is 43 characters, no padding,
// and the alphabet has no `.`, which is what tells a handle from a JWT.
const HANDLE_BYTES = 32;

// A draw that collides is reminted. Three collisions is STS-OAUTH-0984,
// not the cap (STS-OAUTH-0979).
const COLLISION_TRIES = 3;

// One bucket for every door that is offered a handle it does not hold:
// presentation, introspection and revocation. Successes are not counted.
const BUCKET = 'oauth2.opaque-access-token';

// The token register, reached lazily. See the header: a top-level require
// would close a cycle through federation.
interface TokenRegister {
  recordJwt(payload: Json, signed: string, context: Json): void;
  isRevoked(jti: string): boolean;
}

const log = helpers.log;

// Hot path: every set. No Entering/Leaving pair — two lines per stored
// token would drown the log.
function indexByJti(row: Json): string[] {
  return row && row.jti ? [String(row.jti)] : [];
}

// Replication, not a request. Keeps this node's claims and only raises
// revokedAt: a replica with revokedAt 0 must not clear a revocation, and
// copying the other node's claims would not converge.
function mergeRevocation(mine: Json, theirs: Json): Json {
  log.debug("Entering mergeRevocation().");
  if (!mine || typeof mine !== 'object') {
    log.debug("Leaving mergeRevocation().");
    return mine || theirs;
  }
  const mineAt = Number(mine.revokedAt) || 0;
  const theirsAt = Number(theirs && theirs.revokedAt) || 0;
  log.debug("Leaving mergeRevocation().");
  return Object.assign({}, mine, {
    revokedAt: Math.max(mineAt, theirsAt)
  });
}

// Digest -> { claims, revokedAt, exp (unix seconds), jti }. The handle is
// not a field. Per realm, cell-tier (`persistence/tiers.js`), tombstoned.
const tokens: Json = realms.map({
  persist: 'oauth2.opaqueAccessTokens',
  tombstone: true,
  expiresAt: realms.expiryField('exp', 1000),
  indexBy: indexByJti,
  mergeRow: mergeRevocation
});

const opaqueCount = cacheRegistry.register({
  name: 'oauth2.opaque-access-tokens',
  title: 'Opaque access tokens',
  description: 'The claims of each opaque access token this realm has ' +
    'issued, keyed by the SHA-256 of its handle. The handle itself is ' +
    'not stored.',
  owner: 'oauth-oidc/opaque_access_token.ts',
  scope: 'realm',
  kind: 'replay',
  persisted: true,
  hitMeaning: 'a handle was found by its digest',
  settings: ['oauth2.maxOpaqueAccessTokens', 'oauth2.accessTokenFormat'],
  maxEntries: function (): number {
    return Number(config.value('oauth2.maxOpaqueAccessTokens'));
  },
  bound: 'Enforced: a full store refuses the mint (STS-OAUTH-0979) ' +
    'rather than evicting a live token. The ceiling is ' +
    'oauth2.maxOpaqueAccessTokens.',
  lifetime: function (): string {
    return 'until the access token\'s exp; an expired row is deleted ' +
      'when it is read and by caches.eject-expired.';
  },
  eject: cacheRegistry.realmMapEjector(realms, tokens,
    function (row: Json, key: unknown, now: number): boolean {
      const exp = Number(row && row.exp);
      return exp > 0 && exp * 1000 <= now;
    }),
  entries: function (): unknown[] {
    return cacheRegistry.realmMapRows(realms, tokens,
      function (row: Json, key: unknown): Json {
        const exp = Number(row && row.exp);
        return {
          key: cacheRegistry.digestKey(String(key)),
          jti: String((row && row.jti) || ''),
          validUntil: exp > 0 ? exp * 1000 : null
        };
      });
  }
});

/**
 * Mints, resolves and revokes opaque OAuth access tokens for the ambient
 * realm. The default format stays an RFC 9068 JWT.
 */
class OpaqueAccessToken {
  /**
   * Builds the module from its dependencies. The store is module-level;
   * see the file header.
   *
   * @param deps - the logger, settings, crypto, error codes and the
   *   rate-limit door
   */
  constructor(private readonly deps: OpaqueAccessTokenDeps) {
    deps.log.debug("Entering OpaqueAccessToken.constructor().");
    deps.log.debug("Leaving OpaqueAccessToken.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): OpaqueAccessTokenDeps {
    helpers.log.debug("Entering OpaqueAccessToken.defaultDeps().");
    helpers.log.debug("Leaving OpaqueAccessToken.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      stsCrypto: stsCrypto,
      errorCodes: errorCodes,
      websecurity: websecurity
    };
  }

  // A thrown refusal carrying its error code, so a caller can mark the
  // response from it and nothing that serialises the error sees the code.
  private refusal(code: string, message: string): Error {
    const { log, errorCodes } = this.deps;
    log.debug("Entering OpaqueAccessToken.refusal().");
    const err = new Error(message);
    err.name = 'OpaqueAccessTokenError';
    errorCodes.mark(err, code);
    log.debug("Leaving OpaqueAccessToken.refusal().");
    return err;
  }

  // The register, required here rather than above. See the header.
  private tokenRegister(): TokenRegister {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.tokenRegister().");
    const register = require('../common/admin_stats');
    log.debug("Leaving OpaqueAccessToken.tokenRegister().");
    return register;
  }

  private counts(): { hit(): void; miss(): void; refused(): void } {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.counts().");
    log.debug("Leaving OpaqueAccessToken.counts().");
    return opaqueCount;
  }

  private copyOf(value: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.copyOf().");
    const out = JSON.parse(JSON.stringify(value == null ? {} : value));
    log.debug("Leaving OpaqueAccessToken.copyOf().");
    return out;
  }

  // Hashes the presented string. The value is not logged; credentialDigest
  // does not log it either.
  private digest(presented: string): string {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering OpaqueAccessToken.digest().");
    const key = stsCrypto.credentialDigest(presented);
    log.debug("Leaving OpaqueAccessToken.digest().");
    return key;
  }

  private maxTokens(): number {
    const { log, config } = this.deps;
    log.debug("Entering OpaqueAccessToken.maxTokens().");
    const n = Number(config.value('oauth2.maxOpaqueAccessTokens'));
    log.debug("Leaving OpaqueAccessToken.maxTokens(). " + n);
    return n;
  }

  // Drops expired rows of the AMBIENT partition so a mint can use a slot
  // an expired token still occupies. The cache ejector walks every realm;
  // a mint only has to make room in the realm it is writing.
  private ejectExpiredAmbient(): void {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.ejectExpiredAmbient().");
    const now = Date.now();
    const gone: string[] = [];
    tokens.forEach(function (row: Json, key: string): void {
      const exp = Number(row && row.exp);
      if (exp > 0 && exp * 1000 <= now) {
        gone.push(String(key));
      }
    });
    gone.forEach(function (key: string): void {
      tokens.delete(key);
    });
    log.debug("Leaving OpaqueAccessToken.ejectExpiredAmbient(). " +
              gone.length);
  }

  private roomForOne(): void {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.roomForOne().");
    const cap = this.maxTokens();
    if (tokens.size < cap) {
      log.debug("Leaving OpaqueAccessToken.roomForOne(). Room.");
      return;
    }
    this.ejectExpiredAmbient();
    if (tokens.size < cap) {
      log.debug("Leaving OpaqueAccessToken.roomForOne(). After expiry.");
      return;
    }
    this.counts().refused();
    const err = this.refusal('STS-OAUTH-0979',
      'The opaque access-token store is full (' + cap +
      '); a live token was not evicted.');
    log.debug("Leaving OpaqueAccessToken.roomForOne(). Full.");
    throw err;
  }

  // 256 bits, reminted when the digest is already a key. The handle is
  // not logged.
  private drawHandle(): { handle: string; key: string } {
    const { log, stsCrypto, errorCodes } = this.deps;
    log.debug("Entering OpaqueAccessToken.drawHandle().");
    let i = 0;
    while (i < COLLISION_TRIES) {
      i += 1;
      const handle = stsCrypto.randomBytes(HANDLE_BYTES)
        .toString('base64url');
      const key = this.digest(handle);
      if (!tokens.has(key)) {
        log.debug("Leaving OpaqueAccessToken.drawHandle(). Drawn.");
        return { handle: handle, key: key };
      }
      log.debug("OpaqueAccessToken.drawHandle(): a draw collided.");
    }
    log.error(errorCodes.tag('STS-OAUTH-0984') +
              'an opaque access token handle collided with one already ' +
              'stored after three draws');
    log.debug("Leaving OpaqueAccessToken.drawHandle(). Collided.");
    throw this.refusal('STS-OAUTH-0984',
      'an opaque access token handle collided with one already stored ' +
      'after three draws');
  }

  /**
   * Whether the ambient realm mints opaque access tokens. Read on each
   * call: the setting is runtime and per realm.
   *
   * @returns true when `oauth2.accessTokenFormat` is `opaque`
   */
  issuesOpaque(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering OpaqueAccessToken.issuesOpaque().");
    const on = config.value('oauth2.accessTokenFormat') === 'opaque';
    log.debug("Leaving OpaqueAccessToken.issuesOpaque(). " + on);
    return on;
  }

  /**
   * Resolves a presented string against the ambient realm's store. Does
   * not rate-limit and does not read the format setting.
   *
   * @param token - the presented access token
   * @returns `not-opaque`, `unknown`, `inactive` (with `why`) or `active`
   */
  lookup(token: string): HandleLookup {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.lookup().");
    const presented = String(token || '');
    if (!presented || presented.indexOf('.') >= 0) {
      log.debug("Leaving OpaqueAccessToken.lookup(). Not opaque.");
      return { kind: 'not-opaque' };
    }
    const key = this.digest(presented);
    const row = tokens.get(key);
    if (!row) {
      this.counts().miss();
      log.debug("Leaving OpaqueAccessToken.lookup(). Unknown.");
      return { kind: 'unknown' };
    }
    const claims = this.copyOf(row.claims);
    const jti = String((claims && claims.jti) || row.jti || '');
    const exp = Number(row.exp);
    if (exp > 0 && exp * 1000 <= Date.now()) {
      tokens.delete(key);
      this.counts().hit();
      log.debug("Leaving OpaqueAccessToken.lookup(). Expired. jti=" + jti);
      return { kind: 'inactive', why: 'expired', claims: claims };
    }
    let revoked = Number(row.revokedAt) > 0;
    if (!revoked && jti) {
      revoked = !!this.tokenRegister().isRevoked(jti);
    }
    if (revoked) {
      this.counts().hit();
      log.debug("Leaving OpaqueAccessToken.lookup(). Revoked. jti=" + jti);
      return { kind: 'inactive', why: 'revoked', claims: claims };
    }
    this.counts().hit();
    log.debug("Leaving OpaqueAccessToken.lookup(). Active. jti=" + jti);
    return { kind: 'active', claims: claims };
  }

  /**
   * Counts one unknown handle from this address, only while the ambient
   * realm issues opaque tokens.
   *
   * @param req - the request, for its address
   * @returns null when the attempt is allowed or the realm does not issue
   *   opaque tokens, or `{ retryAfterS }` when the address is over the
   *   limit
   */
  noteMiss(req: Json): { retryAfterS: number } | null {
    const { log, websecurity } = this.deps;
    log.debug("Entering OpaqueAccessToken.noteMiss().");
    if (!this.issuesOpaque()) {
      log.debug("Leaving OpaqueAccessToken.noteMiss(). Not issuing.");
      return null;
    }
    const answer = websecurity.attempt(BUCKET, req);
    if (answer && answer.ok === false) {
      log.debug("Leaving OpaqueAccessToken.noteMiss(). Limited.");
      return { retryAfterS: Number(answer.retryAfterS) || 1 };
    }
    log.debug("Leaving OpaqueAccessToken.noteMiss(). Counted.");
    return null;
  }

  /**
   * `lookup()`, and when that is `unknown` in a realm that issues opaque
   * tokens, one miss against the shared bucket.
   *
   * @param token - the presented access token
   * @param req - the request, for its address
   * @returns the lookup, or `limited` with `retryAfterS`
   */
  resolve(token: string, req: Json): HandleLookup {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.resolve().");
    const found = this.lookup(token);
    if (found.kind === 'unknown' && this.issuesOpaque()) {
      const limited = this.noteMiss(req);
      if (limited) {
        log.debug("Leaving OpaqueAccessToken.resolve(). Limited.");
        return { kind: 'limited', retryAfterS: limited.retryAfterS };
      }
    }
    log.debug("Leaving OpaqueAccessToken.resolve(). " + found.kind);
    return found;
  }

  /**
   * Stores `payload` under a fresh handle and records it with the token
   * register. The handle is the return value and is not logged.
   *
   * @param payload - the access-token claims `accessTokenUnsigned` built
   * @param context - the issuance context `recordJwt` keeps
   * @returns the handle
   * @throws Error marked STS-OAUTH-0979 when the cap is full, or
   *   STS-OAUTH-0984 when three draws collide
   */
  mint(payload: Json, context: Json): string {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.mint().");
    let drawn: { handle: string; key: string };
    try {
      this.roomForOne();
      drawn = this.drawHandle();
    } catch (e) {
      log.debug("Caught in OpaqueAccessToken.mint(): " +
                ((e && e.message) || e));
      log.debug("Leaving OpaqueAccessToken.mint(). Refused.");
      throw e;
    }
    const claims = this.copyOf(payload || {});
    const jti = String(claims.jti || '');
    tokens.set(drawn.key, {
      claims: claims,
      revokedAt: 0,
      exp: Number(claims.exp) || 0,
      jti: jti
    });
    try {
      this.tokenRegister().recordJwt(this.copyOf(claims), '',
                                     context || {});
    } catch (e) {
      log.debug("Caught in OpaqueAccessToken.mint(): " +
                ((e && e.message) || e));
      tokens.delete(drawn.key);
      log.debug("Leaving OpaqueAccessToken.mint(). The register refused.");
      throw e;
    }
    log.debug("Leaving OpaqueAccessToken.mint(). jti=" + jti);
    return drawn.handle;
  }

  /**
   * The jti of a stored handle, including one that is expired or revoked.
   * Empty when the string is not a stored handle.
   *
   * @param token - the handle
   * @returns the jti, or ''
   */
  jtiOf(token: string): string {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.jtiOf().");
    const found = this.lookup(token);
    if (found.kind !== 'active' && found.kind !== 'inactive') {
      log.debug("Leaving OpaqueAccessToken.jtiOf(). None.");
      return '';
    }
    const jti = String((found.claims && found.claims.jti) || '');
    log.debug("Leaving OpaqueAccessToken.jtiOf(). " + jti);
    return jti;
  }

  /**
   * `exp` minus `iat` of a stored handle, or 0 when it is not one or the
   * difference is not positive.
   *
   * @param token - the handle
   * @returns the lifetime in seconds, or 0
   */
  lifetimeSeconds(token: string): number {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.lifetimeSeconds().");
    const found = this.lookup(token);
    if (found.kind !== 'active' && found.kind !== 'inactive') {
      log.debug("Leaving OpaqueAccessToken.lifetimeSeconds(). None.");
      return 0;
    }
    const claims = found.claims || {};
    const life = Number(claims.exp) - Number(claims.iat);
    const out = life > 0 ? life : 0;
    log.debug("Leaving OpaqueAccessToken.lifetimeSeconds(). " + out);
    return out;
  }

  /**
   * Sets `revokedAt` on the stored row. A missing row is left alone: a
   * tombstone refuses a later write of a deleted key.
   *
   * @param token - the handle
   * @returns whether a row was updated
   */
  markRevoked(token: string): boolean {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.markRevoked().");
    const presented = String(token || '');
    if (!presented || presented.indexOf('.') >= 0) {
      log.debug("Leaving OpaqueAccessToken.markRevoked(). Not opaque.");
      return false;
    }
    const key = this.digest(presented);
    const row = tokens.get(key);
    if (!row) {
      log.debug("Leaving OpaqueAccessToken.markRevoked(). Absent.");
      return false;
    }
    const next = this.copyOf(row);
    next.revokedAt = Date.now();
    tokens.set(key, next);
    log.debug("Leaving OpaqueAccessToken.markRevoked(). jti=" +
              String(next.jti || ''));
    return true;
  }

  /**
   * Deletes the row for a handle. Used when recording the token fails, and
   * by tests.
   *
   * @param token - the handle
   * @returns whether a row was deleted
   */
  discard(token: string): boolean {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.discard().");
    const presented = String(token || '');
    if (!presented || presented.indexOf('.') >= 0) {
      log.debug("Leaving OpaqueAccessToken.discard(). Not opaque.");
      return false;
    }
    const gone = !!tokens.delete(this.digest(presented));
    log.debug("Leaving OpaqueAccessToken.discard(). " + gone);
    return gone;
  }

  /**
   * A copy of the stored row, or null. The row has no handle in it.
   *
   * @param token - the handle
   * @returns the row, or null
   */
  rowOf(token: string): Json {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.rowOf().");
    const presented = String(token || '');
    if (!presented || presented.indexOf('.') >= 0) {
      log.debug("Leaving OpaqueAccessToken.rowOf(). Not opaque.");
      return null;
    }
    const row = tokens.get(this.digest(presented));
    log.debug("Leaving OpaqueAccessToken.rowOf(). " +
              (row ? 'held' : 'absent'));
    return row ? this.copyOf(row) : null;
  }

  /**
   * The store keys filed under a jti. They are digests, not handles.
   *
   * @param jti - the token's jti
   * @returns the keys, possibly empty
   */
  keysForJti(jti: string): string[] {
    const { log } = this.deps;
    log.debug("Entering OpaqueAccessToken.keysForJti().");
    const keys = tokens.lookup(String(jti || '')) || [];
    log.debug("Leaving OpaqueAccessToken.keysForJti(). " + keys.length);
    return keys;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own when a root is loading: `common/protocol_stack.ts`
// builds one and calls `installInstance()`. The exports below are FACADES.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<OpaqueAccessToken>(
  'oauth-oidc/opaque_access_token',
  () => new OpaqueAccessToken(OpaqueAccessToken.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Opaque OAuth access tokens, off by default.
 *
 * A library that registers no route. The composition root builds the
 * instance; each function here forwards to it.
 *
 * @namespace
 */
export = {
  OpaqueAccessToken: OpaqueAccessToken,
  /**
   * Installs the instance the composition root built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: OpaqueAccessToken): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  issuesOpaque: slot.forward('issuesOpaque'),
  lookup: slot.forward('lookup'),
  resolve: slot.forward('resolve'),
  noteMiss: slot.forward('noteMiss'),
  mint: slot.forward('mint'),
  jtiOf: slot.forward('jtiOf'),
  lifetimeSeconds: slot.forward('lifetimeSeconds'),
  markRevoked: slot.forward('markRevoked'),
  discard: slot.forward('discard'),
  rowOf: slot.forward('rowOf'),
  keysForJti: slot.forward('keysForJti')
};
