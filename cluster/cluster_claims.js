'use strict';
//
// File: cluster/cluster_claims.js
//
// ===========================================================================
// AN ATOMIC "ONCE" FOR EVERY SINGLE-USE VALUE (2026-09-14, #46).
//
// An authorization code, a SAML artifact, a DPoP `jti`, a TOTP step: each is
// accepted by checking an in-memory map and then deleting or marking the entry.
// In one process that is atomic, because nothing between the check and the
// delete yields. Across processes it is a read, a write, and a change log that
// carries the write to the others a moment later — and inside that moment two
// nodes both accept. Issue #46 section 2 lists fourteen of them.
//
// `claim()` is the one primitive they are all moved onto. On a postgres store it
// is one `INSERT … ON CONFLICT` under the primary key's lock, so every process
// against that store agrees at once: exactly one concurrent caller wins. On any
// other store it is this process's memory, which is exactly as atomic as the map
// it replaces and is correct because a non-postgres store cannot be shared.
//
// ---------------------------------------------------------------------------
// THREE DECISIONS.
//
// * **THE KEY IS A DIGEST, ALWAYS.** A caller hands over the value itself —
//   the code, the artifact handle — and this module stores SHA-256 of the scope
//   and the value. A dump of `sts_cluster_claims` is therefore not a list of
//   redeemable codes, and the table needs no seal.
// * **A CLAIM HAS A LIFETIME AND IT IS THE VALUE'S.** A code lives ten minutes,
//   so its claim lives ten minutes plus the skew the verifier allows; after
//   that the value is refused as expired by its own check, and the claim guards
//   nothing. The lifetime is measured by the DATABASE's clock, so two nodes
//   with skewed clocks agree on when it ends.
// * **FAIL CLOSED.** A store that cannot be asked answers `reason: 'store'`,
//   and every caller refuses the value — a single-use value this service cannot
//   prove unused is not one it may accept. It is `used_assertions.js`'s rule.
//
// ---------------------------------------------------------------------------
// RESERVE, THEN KEEP OR RELEASE. Some values must be spent only if what they
// buy actually happens — a code whose token request fails on `invalid_scope`
// has not been used. `claim()` returns a handle; `release(handle)` gives the
// claim back. A handle the caller never releases is simply kept.
//
// A LIBRARY (rule 3). It requires `persistence.js` LAZILY, inside the calls,
// because the modules that spend single-use values include leaves such as
// `oauth-oidc/dpop.js` that must not join a require cycle by requiring it.
// ===========================================================================

const bunyan = require('bunyan');
const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const capabilities = require('./cluster_capabilities');

const log = bunyan.createLogger({ name: 'sts-cluster-claims' });
config.registerLogger(log);

// How often a database store is swept of expired claims. Idempotent, so every
// node may do it; expired rows are ignored by every read in the meantime.
const PURGE_INTERVAL_MS = 60 * 1000;
// How often this process's memory store is swept, counted in claims.
const MEMORY_SWEEP_EVERY = 256;
// A ceiling on a claim's lifetime, so a caller that passes nonsense cannot make
// a row outlive every value it could guard.
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// scope \0 realm \0 digest -> { reservation, expiresAt }
const memory = new Map();
let claimsSinceSweep = 0;
let lastPurgeAt = 0;

function store() {
  log.debug("Entering store().");
  // LAZY, see the header.
  const persistence = require('../persistence/persistence');
  log.debug("Leaving store().");
  return persistence.clusterStore();
}

function digestOf(scope, value) {
  log.debug("Entering digestOf().");
  const out = nodeCrypto.createHash('sha256')
    .update(String(scope) + '\n' + String(value)).digest('base64url');
  log.debug("Leaving digestOf().");
  return out;
}

function memoryKey(scope, realmId, digest) {
  log.debug("Entering memoryKey().");
  log.debug("Leaving memoryKey().");
  return String(scope) + '\u0000' + String(realmId) + '\u0000' + digest;
}

function sweepMemory(now) {
  log.debug("Entering sweepMemory().");
  let removed = 0;
  memory.forEach(function (row, key) {
    if (row.expiresAt <= now) {
      memory.delete(key);
      removed += 1;
    }
  });
  log.debug("Leaving sweepMemory(). " + removed + " expired.");
}

function maybePurge(theStore) {
  log.debug("Entering maybePurge().");
  const now = Date.now();
  if (now - lastPurgeAt < PURGE_INTERVAL_MS) {
    log.debug("Leaving maybePurge(). Not due.");
    return;
  }
  lastPurgeAt = now;
  Promise.resolve().then(function () {
    return theStore.purgeClaims();
  }).catch(function (e) {
    log.warn(errorCodes.tag('STS-CLUSTER-0015') + 'cluster claims: sweeping ' +
             'expired claims failed: ' + ((e && e.message) || e) + '.');
  });
  log.debug("Leaving maybePurge(). Started.");
}

// ---------------------------------------------------------------------------
// THE CLAIM.
//
//   claim({ scope, value, ttlMs, realm })
//
// `scope` names the kind of value ('oauth.code', 'saml2.artifact'); `value` is
// the value itself and never leaves this function; `ttlMs` is how long it could
// still be valid; `realm` defaults to the ambient one.
//
// Resolves to `{ ok: true, handle }`, `{ ok: false, reason: 'used', existing }`
// or `{ ok: false, reason: 'store', why }`. It never rejects.
// ---------------------------------------------------------------------------
function claim(opts) {
  log.debug("Entering claim().");
  const o = opts || {};
  const scope = String(o.scope || '');
  if (!scope || o.value === undefined || o.value === null || o.value === '') {
    log.debug("Leaving claim(). Malformed.");
    return Promise.resolve({ ok: false, reason: 'store',
      why: 'a claim needs a scope and a value' });
  }
  const realmId = o.realm === undefined ? realms.currentId()
    : String(o.realm || '');
  const ttlMs = Math.min(MAX_TTL_MS,
                         Math.max(1000, Math.floor(Number(o.ttlMs) || 0)));
  const digest = digestOf(scope, o.value);
  const reservation = nodeCrypto.randomBytes(12).toString('base64url');
  const handle = { scope: scope, realm: realmId, key: digest,
                   reservation: reservation };
  const theStore = store();
  if (!theStore) {
    const now = Date.now();
    claimsSinceSweep += 1;
    if (claimsSinceSweep >= MEMORY_SWEEP_EVERY) {
      claimsSinceSweep = 0;
      sweepMemory(now);
    }
    const key = memoryKey(scope, realmId, digest);
    const existing = memory.get(key);
    if (existing && existing.expiresAt > now) {
      log.debug("Leaving claim(). Used, in memory.");
      return Promise.resolve({ ok: false, reason: 'used',
        existing: { claimedAt: existing.claimedAt,
                    expiresAt: existing.expiresAt, origin: 'this process' } });
    }
    // SET BEFORE ANY AWAIT: nothing between the get above and here yields.
    memory.set(key, { reservation: reservation, claimedAt: now,
                      expiresAt: now + ttlMs });
    log.debug("Leaving claim(). Claimed, in memory.");
    return Promise.resolve({ ok: true, handle: handle });
  }
  maybePurge(theStore);
  log.debug("Leaving claim(). Asking the store.");
  return Promise.resolve().then(function () {
    return theStore.claimOnce(scope, realmId, digest,
                              { ttlMs: ttlMs, reservation: reservation });
  }).then(function (answer) {
    if (answer && answer.claimed) {
      return { ok: true, handle: handle };
    }
    return { ok: false, reason: 'used',
             existing: (answer && answer.existing) || null };
  }, function (e) {
    log.error(errorCodes.tag('STS-CLUSTER-0013') + 'cluster claims: the ' +
              'store could not be asked about a "' + scope + '" value: ' +
              ((e && e.message) || e) + '. It is refused.');
    return { ok: false, reason: 'store', why: (e && e.message) || String(e) };
  });
}

// Gives a claim back: what it guarded did not happen. Never rejects.
function release(handle) {
  log.debug("Entering release().");
  if (!handle || !handle.key) {
    log.debug("Leaving release(). No handle.");
    return Promise.resolve(false);
  }
  const theStore = store();
  if (!theStore) {
    const key = memoryKey(handle.scope, handle.realm, handle.key);
    const row = memory.get(key);
    if (row && row.reservation === handle.reservation) {
      memory.delete(key);
      log.debug("Leaving release(). Released, in memory.");
      return Promise.resolve(true);
    }
    log.debug("Leaving release(). Not this claim's.");
    return Promise.resolve(false);
  }
  log.debug("Leaving release(). Asking the store.");
  return Promise.resolve().then(function () {
    return theStore.releaseClaim(handle.scope, handle.realm, handle.key,
                                 handle.reservation);
  }).catch(function (e) {
    log.warn(errorCodes.tag('STS-CLUSTER-0014') + 'cluster claims: releasing ' +
             'a "' + handle.scope + '" claim failed: ' +
             ((e && e.message) || e) + '. It stays held until it expires.');
    return false;
  });
}

// Binds a claim to a response: kept when it finishes 2xx or 3xx, released
// otherwise — the shape `used_assertions.js` gives an assertion. A redirect
// counts as success because the protocols that spend codes in a browser answer
// with one.
function releaseUnlessSucceeded(res, handle) {
  log.debug("Entering releaseUnlessSucceeded().");
  if (!res || typeof res.once !== 'function' || !handle) {
    log.debug("Leaving releaseUnlessSucceeded(). Nothing to bind.");
    return;
  }
  let settled = false;
  res.once('finish', function () {
    if (!settled) {
      settled = true;
      if (!(res.statusCode >= 200 && res.statusCode < 400)) {
        release(handle);
      }
    }
  });
  res.once('close', function () {
    if (!settled) {
      settled = true;
      if (!res.writableEnded) {
        release(handle);
      }
    }
  });
  log.debug("Leaving releaseUnlessSucceeded().");
}

// Whether a live claim exists, without making one.
function isClaimed(opts) {
  log.debug("Entering isClaimed().");
  const o = opts || {};
  const scope = String(o.scope || '');
  const realmId = o.realm === undefined ? realms.currentId()
    : String(o.realm || '');
  const digest = digestOf(scope, o.value);
  const theStore = store();
  if (!theStore) {
    const row = memory.get(memoryKey(scope, realmId, digest));
    log.debug("Leaving isClaimed(). In memory.");
    return Promise.resolve(!!row && row.expiresAt > Date.now());
  }
  log.debug("Leaving isClaimed(). Asking the store.");
  return Promise.resolve().then(function () {
    return theStore.claimHeld(scope, realmId, digest);
  });
}

// For tests.
function reset() {
  log.debug("Entering reset().");
  memory.clear();
  claimsSinceSweep = 0;
  lastPurgeAt = 0;
  log.debug("Leaving reset().");
}

capabilities.provide('cluster.claims');

module.exports = {
  claim: claim,
  release: release,
  releaseUnlessSucceeded: releaseUnlessSucceeded,
  isClaimed: isClaimed,
  digestOf: digestOf,
  reset: reset
};
