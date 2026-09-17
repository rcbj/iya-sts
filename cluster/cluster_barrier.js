// @ts-check
'use strict';
//
// File: cluster/cluster_barrier.js
//
// ===========================================================================
// READ-YOUR-WRITE BETWEEN NODES (2026-09-14, #46).
//
// Inside one container, `workers.readYourWrite` works because the front process
// sees every request: it hands out a ticket per request, a worker announces the
// tickets its commit covered, and a reader waits for the tickets below it
// (`common/request_pool.js`). No process sees another CONTAINER's requests, so
// none of that crosses a node boundary — and issue #46 section 5 is what it
// costs: a code minted on A and redeemed on B is "unknown", a sign-in on A is a
// sign-in B has not heard of, an acknowledged SET is delivered again by B.
//
// Two rules close it, and only in active-active mode, because only there does a
// second node answer requests at all:
//
//   1. **A REQUEST IS SERVED AFTER ITS NODE HAS APPLIED EVERYTHING COMMITTED
//      BEFORE IT ARRIVED.** The serving process reads the change log's head
//      (`latestBlockingChangeSeq()`) and pulls until it has applied it, using
//      the same `syncNow()` the in-container barrier uses. Concurrent requests
//      share one read of the head when they arrived before it was taken — a
//      read taken before a request arrived cannot stand in for one taken after.
//   2. **A REQUEST THAT WROTE IS ANSWERED ONLY ONCE ITS WRITES HAVE COMMITTED.**
//      Without this rule 1 is a race: A answers the redirect, the browser is at
//      B before A's flush lands, and B's read of the head does not include it.
//      `res.end()` is held until the directory flush and the minted flush have
//      both committed.
//
// **RULE 2 IS THE ONE `request_worker.js` REJECTED FOR ONE CONTAINER, AND THE
// REASON IT CAN BE TAKEN BACK HERE IS WORTH HAVING.** Awaiting the flush before
// answering was "correct and unaffordable" on 2026-09-07 because the flush then
// diffed the whole directory per request. The journalled flush (2026-09-08)
// names the DNs that moved, so a commit is the cost of the rows written, and
// that is the price of a second node being able to see them.
//
// **WHAT IT DOES NOT DO.** It does not make two CONCURRENT requests
// serialisable: two redemptions of one code racing on two nodes both see the
// code. That is `cluster_claims.js`'s job. This is what makes a SEQUENTIAL flow
// — mint here, use there — behave as it does on one node.
//
// A LIBRARY with a middleware, installed by `common/app.js` directly below the
// request pool's, so it runs in whichever process SERVES the request and never
// in a front process that only proxies it. `persistence.js` is required lazily:
// app.js is #2 in the require order and must not pull the store module ahead of
// #4a.
// ===========================================================================

const bunyan = require('bunyan');
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const capabilities = require('./cluster_capabilities');

const log = bunyan.createLogger({ name: 'sts-cluster-barrier' });
config.registerLogger(log);

// The next barrier NOT YET STARTED, which every request arriving before it
// starts may share. See rule 1.
let pending = null;

// Counters for /admin/cluster.
// The write position a request arrived at, on its response.
const ARRIVAL = Symbol('sts.clusterBarrier.arrival');
// A barrier this request has already been through, on the request: the realm
// middleware runs one for a path naming a realm not yet here (common/app.js).
const SYNCED = Symbol('sts.clusterBarrier.synced');

const stats = { requests: 0, caughtUp: 0, gaveUp: 0, heldForCommit: 0,
                answeredUnheld: 0, commitFailures: 0, totalWaitMs: 0,
                totalHoldMs: 0 };

function persistence() {
  log.debug("Entering persistence().");
  log.debug("Leaving persistence().");
  return require('../persistence/persistence');
}

function active() {
  log.debug("Entering active().");
  const cluster = require('./cluster');
  log.debug("Leaving active().");
  return cluster.isActiveActive() && cluster.enabled();
}

// One barrier for every request that arrived before it started.
function syncShared() {
  log.debug("Entering syncShared().");
  if (pending && !pending.started) {
    log.debug("Leaving syncShared(). Sharing one not yet started.");
    return pending.promise;
  }
  const next = { started: false, promise: null };
  next.promise = new Promise(function (resolve) {
    setImmediate(function () {
      next.started = true;
      if (pending === next) {
        pending = null;
      }
      Promise.resolve().then(function () {
        return persistence().syncNow();
      }).then(resolve, function (e) {
        log.debug("Caught in syncShared(): " + ((e && e.message) || e));
        resolve({ caughtUp: false, error: (e && e.message) || String(e) });
      });
    });
  });
  pending = next;
  log.debug("Leaving syncShared(). A new barrier.");
  return next.promise;
}

// ---------------------------------------------------------------------------
// RULE 2: hold `res.end()` until THIS REQUEST'S writes commit.
//
// **IT HELD FOR ANY WRITE THE PROCESS HAD PENDING, AND THAT WAS NEARLY EVERY
// REQUEST (2026-09-14).** The test was `pendingWrites()` — a dirty bit, a
// journal, a flush timer or a flush in flight, anywhere in the process — and
// the call log records each request's statistics and audit row from its
// `finish` event, AFTER the response, so the flush they schedule was still in
// flight when the NEXT request answered. Measured on one active-active node:
// 1,705 of 1,706 requests held, a discovery document that answers in 1ms
// taking 23ms to 66ms, each waiting for the previous request's audit ring.
//
// So a request reads the store's write position when it arrives and again
// when it answers. Unchanged: nothing was written while it was handled, and it
// is answered at once. Moved: it is held until everything up to the second
// reading has committed — `persistence.commitThrough()`, which waits for the
// one flush in flight that covers it rather than whatever is queued behind.
// The position is process-wide, so a request that merely overlapped another's
// write waits for that too: conservative, never wrong, and cheap when the
// write is already in the flush.
//
// A persistence module without positions (a test double) gets the old rule.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// THE CALL LOG'S OWN ROWS (2026-09-14, #46).
//
// `common/app.js` records every call — a statistics tally and an audit row —
// in `end()`, just before this module's `end()` runs, and tells this module
// where the store's write position was before it did (`callLogStarts`) and
// whether the row it recorded is a REFUSAL (`callLogRecorded`). The barrier
// then asks two questions rather than one:
//
//   * DID THE REQUEST WRITE, the call log apart? Held, and its call-log rows
//     ride the same commit at no extra cost — they are in the journal the
//     flush takes.
//   * IF NOT, IS ITS ROW A REFUSAL? Held for that row's commit, so a refusal
//     answered by node A is in the audit log node B serves next: the
//     `admin_api` job's refused `POST /healthcheck`, read back from the other
//     node, which failed when the row was recorded after the response.
//
// **A SUCCESSFUL CALL THAT WROTE NOTHING ELSE IS NOT HELD FOR ITS ROW**, and
// that is the cost argument. Nearly every request has an audit row, so holding
// for it would make every read in the service pay a transaction — measured,
// that was the difference between a discovery document at 3ms and at 23-66ms
// on active-active nodes, and a read at 7ms and at 65ms. The row still commits
// within one flush and still reaches every node's next pull, and the counters
// beside it were never waited for (see the driver's latestBlockingChangeSeq
// note on 224 barrier timeouts). What a success row does not get is rule 2's
// promise, and it is the one row nobody acts on: a refusal is the row a person
// or a job goes to the other node to find.
// ---------------------------------------------------------------------------
const CALL_LOG = Symbol('sts.clusterBarrier.callLog');

function callLogStarts(res) {
  log.debug("Entering callLogStarts().");
  if (!res || !res[ARRIVAL]) {
    log.debug("Leaving callLogStarts(). Not held by this barrier.");
    return;
  }
  const store = persistence();
  res[CALL_LOG] = { before: store.writeGeneration(), mustCommit: false };
  log.debug("Leaving callLogStarts().");
}

function callLogRecorded(res, refused) {
  log.debug("Entering callLogRecorded().");
  if (res && res[CALL_LOG]) {
    res[CALL_LOG].mustCommit = !!refused;
  }
  log.debug("Leaving callLogRecorded().");
}

// ---------------------------------------------------------------------------
// A DECISION COUNTED IS NOT A WRITE (2026-09-15, #46).
//
// The minted position less the keys journalled into a store declared
// `observation: true` — `xacml_monitor.js`'s counters, which the access PEP
// moves on every console, portal and `/admin-api` request. Those rows are
// journalled and flushed so every node's monitor adds up (they were not, and
// the suite's `cluster` mode read two totals for one service), but a request
// whose only row is a tally is answered at once, exactly as the call log's
// success row is: rcbj's decision 6. A request that wrote anything else is held
// and `commitThrough(now)` below takes its tallies in the same commit, because
// `now` is the whole position. The count is process-wide, like the position:
// two overlapping requests can only make this hold MORE, never less.
// ---------------------------------------------------------------------------
function mintedWrites(position) {
  log.debug("Entering mintedWrites().");
  log.debug("Leaving mintedWrites().");
  return (Number(position.minted) || 0) - (Number(position.observed) || 0);
}

function holdUntilCommitted(res, arrival) {
  log.debug("Entering holdUntilCommitted().");
  const end = res.end;
  res.end = function () {
    log.debug("Entering end().");
    const args = arguments;
    res.end = end;
    const store = persistence();
    const positioned = arrival && typeof store.writeGeneration === 'function' &&
                       typeof store.commitThrough === 'function';
    const now = positioned ? store.writeGeneration() : null;
    const logged = positioned ? res[CALL_LOG] : null;
    // The position before the call log recorded, where it did: what moved
    // after it is the call log's own rows, held only for a refusal.
    const handled = logged ? logged.before : now;
    const wrote = positioned
      ? (handled.directory !== arrival.directory ||
         mintedWrites(handled) !== mintedWrites(arrival) ||
         (logged && logged.mustCommit) ||
         (typeof store.keysPending === 'function' && store.keysPending()))
      : store.pendingWrites();
    if (!wrote) {
      stats.answeredUnheld += 1;
      log.debug("Leaving end(). Nothing written while it was handled.");
      return end.apply(res, args);
    }
    const began = Date.now();
    stats.heldForCommit += 1;
    const committing = positioned
      ? Promise.resolve().then(function () { return store.commitThrough(now); })
      : Promise.all([
        Promise.resolve().then(function () { return store.flush(); }),
        Promise.resolve().then(function () { return store.flushMinted(); })
      ]);
    committing.then(function (results) {
      const failed = (results || []).filter(function (one) {
        return one && one.error;
      });
      if (failed.length) {
        stats.commitFailures += 1;
        log.error(errorCodes.tag('STS-CLUSTER-0019') + 'cluster barrier: a ' +
                  'response held for its writes could not commit them (' +
                  failed.map(function (one) { return one.error; }).join('; ') +
                  '); it is sent, and another node may not see them until ' +
                  'the retry lands.');
      }
    }, function (e) {
      stats.commitFailures += 1;
      log.error(errorCodes.tag('STS-CLUSTER-0019') + 'cluster barrier: the ' +
                'commit a response was held for failed: ' +
                ((e && e.message) || e) + '; it is sent anyway.');
    }).then(function () {
      stats.totalHoldMs += Date.now() - began;
      end.apply(res, args);
    });
    log.debug("Leaving end(). Held for the commit.");
    return res;
  };
  log.debug("Leaving holdUntilCommitted().");
}

// For common/app.js's realm middleware, which runs above this one.
function isActive() {
  log.debug("Entering isActive().");
  log.debug("Leaving isActive().");
  return active();
}

// That middleware caught this request up already: rule 1 is met by the barrier
// it ran — it started after the request arrived — so this one does not run
// another.
function markSynced(req, answer) {
  log.debug("Entering markSynced().");
  if (req) {
    req[SYNCED] = answer || { caughtUp: false };
  }
  log.debug("Leaving markSynced().");
}

function middleware() {
  log.debug("Entering middleware().");
  log.debug("Leaving middleware().");
  return function clusterBarrier(req, res, next) {
    log.debug("Entering clusterBarrier().");
    if (!active()) {
      log.debug("Leaving clusterBarrier(). Not active-active.");
      next();
      return;
    }
    stats.requests += 1;
    const began = Date.now();
    const store = persistence();
    const arrival = typeof store.writeGeneration === 'function'
      ? store.writeGeneration() : null;
    res[ARRIVAL] = arrival;
    holdUntilCommitted(res, arrival);
    const synced = req[SYNCED]
      ? Promise.resolve(req[SYNCED]) : syncShared();
    synced.then(function (answer) {
      stats.totalWaitMs += Date.now() - began;
      if (answer && answer.caughtUp) {
        stats.caughtUp += 1;
      } else if (answer && answer.coordinating !== false) {
        stats.gaveUp += 1;
        log.warn(errorCodes.tag('STS-CLUSTER-0018') + 'cluster barrier: ' +
                 req.method + ' ' + String(req.originalUrl || req.url)
                   .split('?')[0] + ' is served before this node caught up ' +
                 'with the others (' + JSON.stringify(answer) + ').');
      }
      log.debug("Leaving clusterBarrier().");
      next();
    });
  };
}

function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return Object.assign({ active: active() }, stats, {
    meanWaitMs: stats.requests ? stats.totalWaitMs / stats.requests : 0,
    meanHoldMs: stats.heldForCommit
      ? stats.totalHoldMs / stats.heldForCommit : 0
  });
}

// At require time; see cluster.js's note on why a capability is the code.
capabilities.provide('cluster.read-barrier');

module.exports = {
  middleware: middleware,
  syncShared: syncShared,
  holdUntilCommitted: holdUntilCommitted,
  callLogStarts: callLogStarts,
  isActive: isActive,
  markSynced: markSynced,
  callLogRecorded: callLogRecorded,
  report: report
};
