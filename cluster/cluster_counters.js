// @ts-check
'use strict';
//
// File: cluster/cluster_counters.js
//
// ===========================================================================
// A VALUE THAT ONLY GOES UP, AGREED BY EVERY NODE (2026-09-14, #46 section 2).
//
// Two credentials in this service are defended by a number that must never go
// backwards:
//
//   * a WebAuthn SIGNATURE COUNTER. An authenticator increments it on every
//     assertion; a relying party that sees a value not above the last one it
//     stored has seen either a replay or a CLONED authenticator (WebAuthn
//     Level 3 section 6.1.1) and must say so;
//   * the last RFC 6238 TIME STEP a person spent. Section 5.2: once a step has
//     been accepted, it and every step before it are spent.
//
// Both lived on the person's directory entry, and on one node that was
// enough: the check and the write are one synchronous run of the event loop.
// Across nodes the entry is a whole row, last writer wins, and a change log
// that reaches the other nodes a moment later. So node A accepting counter 11
// and node B accepting counter 10 at the same moment can leave the entry at
// 10 — the counter went BACKWARDS, and a clone presenting 11 is then accepted
// by everybody. And two nodes both reading "last step 41" both accept step 42.
//
// A CLAIM (`cluster_claims.js`) is the wrong primitive for either, and the
// reason is worth having: a claim says "this exact value, once". It stops the
// SAME counter twice, and it does not stop a lower one after a higher one,
// which is the property both mechanisms are defined by. So this module keeps a
// row per counter and advances it with ONE conditional upsert:
//
//   INSERT … ON CONFLICT DO UPDATE SET value = new WHERE value < new
//
// under the primary key's row lock. Exactly one of two concurrent advances to
// the same value gets a row back; an advance to a lower value gets none; and
// the stored value is the highest anybody was ever given, whatever order the
// commits land in.
//
// ---------------------------------------------------------------------------
// ZERO, AND WHY IT IS NOT A REFUSAL.
//
// WebAuthn Level 3 section 6.1.1 lets an authenticator that keeps no counter
// report 0 for ever — every synced passkey does. So `advance()` to 0 when the
// stored value is 0 (or there is none) is ACCEPTED with `advanced: false`: the
// counter is simply not a defence for that credential, and the caller must
// have another (the WebAuthn door claims the ceremony's challenge). An advance
// to 0 when the stored value is ABOVE 0 is a counter that went backwards and is
// refused like any other.
//
// ---------------------------------------------------------------------------
// THE ENTRY KEEPS ITS COPY, AND STAYS THE FIRST CHECK.
//
// `webauthn.js` checks the counter against the entry and `totp.verify()`
// refuses a step at or below the entry's `lastCounter`, both before this runs:
// a fast refusal that costs no round trip, which on one node is the whole
// defence and across nodes is the common case. This module is what decides
// the RACE, and both callers still write the entry afterwards so a page that
// draws "last used" is right.
//
// ---------------------------------------------------------------------------
// ON A STORE THAT CANNOT BE SHARED it is this process's memory, which is
// exactly as atomic as the entry check it sits behind, and is right because a
// memory or ldif store has one process. A store that cannot be asked answers
// `reason: 'store'` and the caller REFUSES — `cluster_claims.js`'s fail-closed
// rule: a counter this service cannot prove has advanced is not one it may
// accept.
//
// A row is never removed. One per credential ever used — a key's id, an
// enrolment's instant — a few dozen bytes each; `updated_at` is there for the
// day somebody wants to sweep the rows of credentials that no longer exist.
//
// A LIBRARY (rule 3). `persistence.js` is required LAZILY, for
// `cluster_claims.js`'s reason.
// ===========================================================================

const bunyan = require('bunyan');
const nodeCrypto = require('crypto');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({ name: 'sts-cluster-counters' });
config.registerLogger(log);

// scope \0 realm \0 digest -> value
const memory = new Map();

function store() {
  log.debug("Entering store().");
  const persistence = require('../persistence/persistence');
  const candidate = persistence.clusterStore();
  log.debug("Leaving store().");
  // A driver that can claim and not advance is an older driver; it is treated
  // as no shared store rather than as one that cannot be asked, because the
  // two drivers that exist either have both statements or neither.
  return candidate && typeof candidate.advanceCounter === 'function'
    ? candidate : null;
}

function digestOf(scope, key) {
  log.debug("Entering digestOf().");
  const out = nodeCrypto.createHash('sha256')
    .update(String(scope) + '\n' + String(key)).digest('base64url');
  log.debug("Leaving digestOf().");
  return out;
}

function memoryKey(scope, realmId, digest) {
  log.debug("Entering memoryKey().");
  log.debug("Leaving memoryKey().");
  return String(scope) + ' ' + String(realmId) + ' ' + digest;
}

// The verdict from what the store said, one reading for both stores.
function verdictOf(wanted, answer) {
  log.debug("Entering verdictOf().");
  const highest = Number((answer && answer.highest) || 0);
  if (answer && answer.advanced) {
    log.debug("Leaving verdictOf(). Advanced.");
    return { ok: true, advanced: true, highest: highest };
  }
  if (wanted === 0 && highest === 0) {
    log.debug("Leaving verdictOf(). A counter that is always zero.");
    return { ok: true, advanced: false, highest: 0 };
  }
  log.debug("Leaving verdictOf(). Not above " + highest + ".");
  return { ok: false, reason: 'behind', highest: highest };
}

// ---------------------------------------------------------------------------
//   advance({ scope, key, value, realm })
//
// `scope` names the kind of counter ('authn.webauthn-sign-count'); `key` names
// the one counter (a credential id) and is stored as a digest; `value` is what
// the credential presented; `realm` defaults to the ambient one.
//
// Resolves to `{ ok: true, advanced, highest }`,
// `{ ok: false, reason: 'behind', highest }` or
// `{ ok: false, reason: 'store', why }`. It never rejects.
// ---------------------------------------------------------------------------
/**
 * @param {any} opts
 * @returns {Promise<import('../types/cluster').AdvanceResult>}
 */
function advance(opts) {
  log.debug("Entering advance().");
  const o = opts || {};
  const scope = String(o.scope || '');
  const wanted = Math.floor(Number(o.value));
  if (!scope || o.key === undefined || o.key === null || o.key === '' ||
      !Number.isFinite(wanted) || wanted < 0) {
    log.debug("Leaving advance(). Malformed.");
    return Promise.resolve({ ok: false, reason: 'store',
      why: 'a counter needs a scope, a key and a value of 0 or more' });
  }
  const realmId = o.realm === undefined ? realms.currentId()
    : String(o.realm || '');
  const digest = digestOf(scope, o.key);
  const theStore = store();
  if (!theStore) {
    const mkey = memoryKey(scope, realmId, digest);
    const had = memory.has(mkey);
    const current = had ? memory.get(mkey) : 0;
    // SET BEFORE ANY AWAIT: nothing between the read and the write yields.
    const moved = !had || current < wanted;
    if (moved) {
      memory.set(mkey, wanted);
    }
    log.debug("Leaving advance(). In memory.");
    return Promise.resolve(verdictOf(wanted, {
      advanced: moved, highest: moved ? wanted : current }));
  }
  log.debug("Leaving advance(). Asking the store.");
  return Promise.resolve().then(function () {
    return theStore.advanceCounter(scope, realmId, digest, wanted);
  }).then(function (answer) {
    return verdictOf(wanted, answer);
  }, function (e) {
    log.error(errorCodes.tag('STS-CLUSTER-0022') + 'cluster counters: the ' +
              'store could not be asked to advance a "' + scope + '" ' +
              'counter: ' + ((e && e.message) || e) + '. The credential is ' +
              'refused.');
    return { ok: false, reason: 'store', why: (e && e.message) || String(e) };
  });
}

// ===========================================================================
// A COUNT INSIDE A FIXED WINDOW, AGREED BY EVERY NODE (2026-09-14, #46
// section 2).
//
// The rate limiter's buckets were a `realms.sharedMap()` row per bucket —
// `{ count, until }`, read, incremented and written back whole. Replicated,
// that is last writer wins on a counter: two nodes each reading 3 and each
// writing 4 have counted one attempt of two, and a guesser spreading attempts
// over N nodes had roughly N times the budget, because each node also refused
// only on its own view. Neither "only up" (`advance()`) nor "once" (a claim)
// is the property: a window is a count that RESETS. So it is its own table,
// `sts_cluster_windows`, and one conditional upsert
//
//   count = CASE WHEN the window has passed THEN 1 ELSE count + 1 END
//
// under the primary key's row lock, which returns the count THIS attempt made
// — the number the caller decides on, and the same number whichever node
// asked.
//
// **THERE IS NO MEMORY FALLBACK HERE, DELIBERATELY.** `common/websecurity.ts`
// already has one — its own buckets, exactly as they were — and it asks
// `sharesWindows()` before it asks anything else, so a store that cannot share
// leaves the limiter byte-for-byte what it was. A second in-memory window in
// this file would be a second limiter to keep in step with the first.
//
// **A STORE THAT CANNOT BE ASKED ANSWERS `reason: 'store'`**, and what the
// caller does with that is ITS decision (the limiter falls back to its own
// buckets and says so; see there). A row is swept once its window has passed,
// once a minute, by the scheduler job cluster.rate-window-purge (#49 P5).
// ===========================================================================
const WINDOW_PURGE_INTERVAL_MS = 60 * 1000;
// The sweep's scheduler job (#49 P5): see ensureWindowPurgeJob().
const WINDOW_PURGE_JOB = 'cluster.rate-window-purge';
let windowJobRegistered = false;

function windowStore() {
  log.debug("Entering windowStore().");
  const persistence = require('../persistence/persistence');
  const candidate = persistence.clusterStore();
  log.debug("Leaving windowStore().");
  return candidate && typeof candidate.countWindow === 'function' &&
    typeof candidate.peekWindow === 'function' &&
    typeof candidate.clearWindow === 'function' ? candidate : null;
}

// Is there a store every process shares a window in? Synchronous, so a caller
// can choose its path before it has to become asynchronous at all.
function sharesWindows() {
  log.debug("Entering sharesWindows().");
  const out = !!windowStore();
  log.debug("Leaving sharesWindows().");
  return out;
}

// THE SWEEP IS A SCHEDULER JOB (#49 P5): `cluster.rate-window-purge`, a
// CLUSTER job every WINDOW_PURGE_INTERVAL_MS — the windows are one table
// every process shares. It was piggy-backed on the next count in every
// process. Registered at the first count against a shared store, lazily for
// `cluster_claims.js`'s reason.
function ensureWindowPurgeJob(schedulerInstance) {
  log.debug("Entering ensureWindowPurgeJob().");
  if (windowJobRegistered) {
    log.debug("Leaving ensureWindowPurgeJob(). Registered.");
    return;
  }
  // **REGISTERED WHEN THE SCHEDULER LOADS, IN EVERY PROCESS (2026-09-22)**,
  // for `cluster_claims.js`'s reason and by the same route: it was registered
  // at a process's first COUNT against a shared store, so a process that had
  // counted nothing did not list it — and `/admin/scheduler` (a surface
  // worker) and `GET /admin-api/scheduler` (a protocol worker) answered with
  // different job lists, which `sts_scheduler` found in `single-node` twice,
  // once per lazily-registered job. `cluster/scheduler.ts` calls this with
  // ITSELF at the end of its own module; the first-count call stays and finds
  // the job registered.
  const scheduler = schedulerInstance || require('./scheduler');
  // NOT LATCHED BEFORE THE REGISTRATION HAPPENS. The guard used to be set on
  // the way in, so a call that reached a half-built scheduler through the
  // require above — this module and that one can be loaded in either order —
  // marked the job registered while registering nothing, and no later call
  // could put it right.
  if (!scheduler || typeof scheduler.register !== 'function') {
    log.debug("Leaving ensureWindowPurgeJob(). No scheduler yet.");
    return;
  }
  windowJobRegistered = true;
  if (scheduler.job(WINDOW_PURGE_JOB)) {
    log.debug("Leaving ensureWindowPurgeJob(). Registered elsewhere.");
    return;
  }
  scheduler.register({
    id: WINDOW_PURGE_JOB,
    title: 'Finished rate-limit windows sweep',
    describe: 'Deletes the rate-limit windows that have passed from the ' +
              'table every node shares.',
    owner: 'cluster/cluster_counters.js',
    everyMs: function () {
      return WINDOW_PURGE_INTERVAL_MS;
    },
    off: function () {
      const theStore = windowStore();
      return theStore && typeof theStore.purgeWindows === 'function' ? ''
        : 'no shared rate-limit windows in this process';
    },
    run: function () {
      return Promise.resolve().then(function () {
        return windowStore().purgeWindows();
      }).then(function (removed) {
        return { removed: Number(removed) || 0 };
      }, function (e) {
        log.warn(errorCodes.tag('STS-CLUSTER-0024') + 'cluster counters: ' +
                 'sweeping finished rate-limit windows failed: ' +
                 ((e && e.message) || e) + '.');
        throw e;
      });
    }
  });
  log.debug("Leaving ensureWindowPurgeJob().");
}

// The shape every window call is checked against, one place.
function windowArgs(opts) {
  log.debug("Entering windowArgs().");
  const o = opts || {};
  const scope = String(o.scope || '');
  if (!scope || o.key === undefined || o.key === null || o.key === '') {
    log.debug("Leaving windowArgs(). Malformed.");
    return null;
  }
  log.debug("Leaving windowArgs().");
  return { scope: scope,
           realm: o.realm === undefined ? '' : String(o.realm || ''),
           digest: digestOf(scope, o.key),
           windowMs: Math.max(1, Math.floor(Number(o.windowMs) || 0)) };
}

// A failure of the store, one sentence for the three calls.
function windowFailure(what, scope, e) {
  log.debug("Entering windowFailure().");
  log.warn(errorCodes.tag('STS-CLUSTER-0023') + 'cluster counters: the ' +
           'store could not be asked to ' + what + ' a "' + scope + '" ' +
           'window: ' + ((e && e.message) || e) + '.');
  log.debug("Leaving windowFailure().");
  return { ok: false, reason: 'store', why: (e && e.message) || String(e) };
}

// ---------------------------------------------------------------------------
//   countInWindow({ scope, key, windowMs, realm })
//
// Counts one attempt. `realm` defaults to '' — a limiter bucket is not per
// realm (websecurity.js says why). Resolves `{ ok: true, count, remainingMs }`
// or `{ ok: false, reason: 'store' | 'unshared', why }`. Never rejects.
// ---------------------------------------------------------------------------
/**
 * @param {any} opts
 * @returns {Promise<import('../types/cluster').WindowResult>}
 */
function countInWindow(opts) {
  log.debug("Entering countInWindow().");
  const args = windowArgs(opts);
  const theStore = windowStore();
  if (!args || !theStore) {
    log.debug("Leaving countInWindow(). Nothing to count in.");
    return Promise.resolve({ ok: false,
      reason: args ? 'unshared' : 'store',
      why: args ? 'no shared store' : 'a window needs a scope and a key' });
  }
  ensureWindowPurgeJob();
  log.debug("Leaving countInWindow(). Asking the store.");
  return Promise.resolve().then(function () {
    return theStore.countWindow(args.scope, args.realm, args.digest,
                                args.windowMs);
  }).then(function (answer) {
    return { ok: true, count: Number(answer.count) || 0,
             remainingMs: Number(answer.remainingMs) || 0 };
  }, function (e) {
    return windowFailure('count in', args.scope, e);
  });
}

// The count of a window, counting nothing.
/**
 * @param {any} opts
 * @returns {Promise<import('../types/cluster').WindowResult>}
 */
function peekWindow(opts) {
  log.debug("Entering peekWindow().");
  const args = windowArgs(opts);
  const theStore = windowStore();
  if (!args || !theStore) {
    log.debug("Leaving peekWindow(). Nothing to read.");
    return Promise.resolve({ ok: false,
      reason: args ? 'unshared' : 'store',
      why: args ? 'no shared store' : 'a window needs a scope and a key' });
  }
  log.debug("Leaving peekWindow(). Asking the store.");
  return Promise.resolve().then(function () {
    return theStore.peekWindow(args.scope, args.realm, args.digest);
  }).then(function (answer) {
    return { ok: true, count: Number(answer.count) || 0,
             remainingMs: Number(answer.remainingMs) || 0 };
  }, function (e) {
    return windowFailure('read', args.scope, e);
  });
}

// Forgets a window — a success clearing its bucket.
function clearWindow(opts) {
  log.debug("Entering clearWindow().");
  const args = windowArgs(opts);
  const theStore = windowStore();
  if (!args || !theStore) {
    log.debug("Leaving clearWindow(). Nothing to clear.");
    return Promise.resolve({ ok: false,
      reason: args ? 'unshared' : 'store',
      why: args ? 'no shared store' : 'a window needs a scope and a key' });
  }
  log.debug("Leaving clearWindow(). Asking the store.");
  return Promise.resolve().then(function () {
    return theStore.clearWindow(args.scope, args.realm, args.digest);
  }).then(function () {
    return { ok: true };
  }, function (e) {
    return windowFailure('clear', args.scope, e);
  });
}

// For tests: forget this process's memory store.
function reset() {
  log.debug("Entering reset().");
  memory.clear();
  log.debug("Leaving reset().");
}

module.exports = {
  advance: advance,
  sharesWindows: sharesWindows,
  countInWindow: countInWindow,
  peekWindow: peekWindow,
  clearWindow: clearWindow,
  digestOf: digestOf,
  // Exported for `cluster/scheduler.ts`, which registers this job at its own
  // load so that every process lists it — see the function's own comment.
  ensureWindowPurgeJob: ensureWindowPurgeJob,
  reset: reset
};
