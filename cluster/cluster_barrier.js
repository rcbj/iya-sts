// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

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
// **AND SINCE 2026-09-29 (#351) RULE 2 IS NOT A CLUSTER RULE.** It holds in
// every process whose store is a database (`persistence.answersAfterCommit()`),
// one node or many, and a commit that FAILS is answered 503 with Retry-After
// in place of the success — never the 2xx the handler wrote. A worker on
// testidp answered ~600 SCIM deletes 204 while their write was deferred
// (STS-STORE-0002), exited on a lost origin before the retry, and the people
// came back from the database; a response sent before its commit is an
// acknowledgement the process can lose, whatever the node count. Rule 1 —
// catching up with other nodes — is still active-active only, because only
// there does another node write. The same rule reaches an LDAP operation
// through `answerAfterCommit()` below, which `ldap/ldap_server.js` wraps
// every handler in at registration.
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
                totalHoldMs: 0, refusedForCommit: 0, heldForBacklog: 0,
                ldapHeldForCommit: 0, ldapRefusedForCommit: 0 };

// ---------------------------------------------------------------------------
// WHAT A REFUSED COMMIT IS ANSWERED WITH (#351).
//
// 503 and `Retry-After`: RFC 9110 section 15.6.4 — "temporarily unable to
// handle the request … likely to be alleviated after some delay" — which is
// exactly a store that refused one transaction. RETRY_AFTER_S is the pool's
// own connection wait (`persistence_postgres.js`, `connectionTimeoutMillis`),
// the shortest time in which a starved pool can be expected to have a
// connection again; the store's own retry of the write starts sooner.
//
// **THE HANDLER'S RESPONSE IS DISCARDED WHOLE**: its body, its `Location`,
// its `Set-Cookie`, its `Content-*` — a redirect to a page that assumes the
// write, or a session cookie for a session the store does not hold, is a
// success by another name. What survives is the headers every response
// carries for its own safety (the CSP and its companions, HSTS, CORS so a
// page's script can read the 503 at all). The body is RFC 6749's
// `temporarily_unavailable`, the one error code a family here already
// defines for this condition, and harmless to every other client; it names
// no error code — codes are recorded, never sent.
//
// **A RESPONSE WHOSE HEADERS ALREADY LEFT CANNOT BE TURNED INTO A 503**: a
// handler that streamed (`res.write()`) or called `writeHead()` itself. Four
// routes write, and none of them writes to the store; for one that ever
// does, the connection is DESTROYED rather than completed, so the client
// sees a failed exchange and never a finished success.
// ---------------------------------------------------------------------------
const RETRY_AFTER_S = 5;
const KEPT_ON_REFUSAL = /^(content-security-policy|x-content-type-options|x-frame-options|referrer-policy|strict-transport-security|access-control-.*|vary|cross-origin-.*|permissions-policy)$/i;
const REFUSED_BODY = JSON.stringify({
  error: 'temporarily_unavailable',
  error_description: 'The change could not be committed to the store. ' +
    'Nothing was confirmed; try again.'
});
// The call log's hook, per response: `common/app.js` records the refusal as
// the row the operator reads, because the row it recorded a moment earlier
// carried the handler's status.
const ON_REFUSED = Symbol('sts.clusterBarrier.onRefused');

// Methods that change something, by RFC 9110 section 9.2.1's definition of
// safe. A request with one of them is held while a refused write is still
// waiting for its retry (`persistence.commitBacklog()`), even when it wrote
// nothing itself.
const UNSAFE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

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

// Whether rule 2 applies in this process: active-active, or a store that a
// writing response waits for (#351).
function holds() {
  log.debug("Entering holds().");
  const store = persistence();
  const answer = active() ||
    (typeof store.answersAfterCommit === 'function' &&
     !!store.answersAfterCommit());
  log.debug("Leaving holds(). " + answer);
  return answer;
}

// The failures among a commit's answers.
function failuresOf(results) {
  log.debug("Entering failuresOf().");
  log.debug("Leaving failuresOf().");
  return (results || []).filter(function (one) {
    return one && one.error;
  });
}

// The commit a held answer waits for, as a promise of its failures' texts —
// never a rejection. `now` is the position to commit through, or null for a
// persistence module without positions (a test double).
function commitFailures(store, now) {
  log.debug("Entering commitFailures().");
  const committing = now
    ? Promise.resolve().then(function () { return store.commitThrough(now); })
    : Promise.all([
      Promise.resolve().then(function () { return store.flush(); }),
      Promise.resolve().then(function () { return store.flushMinted(); })
    ]);
  log.debug("Leaving commitFailures().");
  return committing.then(function (results) {
    return failuresOf(results).map(function (one) {
      return String(one.error);
    });
  }, function (e) {
    log.debug("Caught in commitFailures(): " + ((e && e.message) || e));
    return [String((e && e.message) || e)];
  });
}

/**
 * Answers a held response with 503 in place of what its handler wrote, or
 * destroys it when its headers have already gone.
 *
 * @param res - the response
 * @param end - the response's own `end()`
 * @returns the response
 */
function refuseForCommit(res, end) {
  log.debug("Entering refuseForCommit().");
  errorCodes.mark(res, 'STS-STORE-0066');
  stats.refusedForCommit += 1;
  if (res.headersSent) {
    log.debug("Leaving refuseForCommit(). Headers gone; destroyed.");
    res.destroy();
    return res;
  }
  res.getHeaderNames().forEach(function (name) {
    if (!KEPT_ON_REFUSAL.test(name)) {
      res.removeHeader(name);
    }
  });
  res.statusCode = 503;
  res.statusMessage = 'Service Unavailable';
  res.setHeader('Retry-After', String(RETRY_AFTER_S));
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  const hook = res[ON_REFUSED];
  if (typeof hook === 'function') {
    try {
      hook();
    } catch (e) {
      // The row is the operator's; the refusal is the client's, and a row
      // that could not be written must not cost the client its answer. The
      // log line above carries the code either way.
      log.debug("Caught in refuseForCommit(): " + ((e && e.message) || e));
    }
  }
  const head = res.req && res.req.method === 'HEAD';
  res.setHeader('Content-Length', head ? '0'
    : String(Buffer.byteLength(REFUSED_BODY)));
  log.debug("Leaving refuseForCommit().");
  return head ? end.call(res) : end.call(res, REFUSED_BODY);
}

/**
 * Installs the call log's hook for a refused commit on one response: it is
 * called after the status is 503 and the code is marked, so the row it
 * records says what the client was answered.
 *
 * @param res - the response
 * @param fn - the hook
 */
function onCommitRefused(res, fn) {
  log.debug("Entering onCommitRefused().");
  if (res && typeof fn === 'function') {
    res[ON_REFUSED] = fn;
  }
  log.debug("Leaving onCommitRefused().");
}

// One barrier for every request that arrived before it started.
/**
 * Pulls the change log until this process has applied everything committed
 * before the call; every caller arriving before the pull starts shares it.
 *
 * @returns a promise of the `syncNow()` answer, or `{ caughtUp: false,
 *   error }`; it never rejects
 */
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

/**
 * Records the store's write position before `common/app.js` writes the call
 * log's rows, so those rows can be told apart from the request's own writes.
 *
 * @param res - the response, if this barrier holds it
 */
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

/**
 * Says whether the call-log row just recorded is a refusal, which holds the
 * response for that row's commit.
 *
 * @param res - the response
 * @param refused - true for a refusal
 */
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

/**
 * Wraps `res.end()` so that a response whose request wrote anything is sent
 * only once those writes have committed; one that wrote nothing is sent at
 * once, and one whose commit FAILED is answered 503 instead (#351).
 *
 * @param res - the response
 * @param arrival - the store's write position when the request arrived, or
 *   null for a persistence module without positions
 * @param req - the request, whose method decides whether a refused write
 *   still waiting for its retry holds it too; optional
 */
function holdUntilCommitted(res, arrival, req) {
  log.debug("Entering holdUntilCommitted().");
  const end = res.end;
  const method = String((req && req.method) || '').toUpperCase();
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
    // A WRITING METHOD WHILE A REFUSED WRITE WAITS FOR ITS RETRY (#351) is
    // held for it: see `persistence.commitBacklog()`.
    const backlog = positioned && UNSAFE_METHODS.indexOf(method) >= 0 &&
      typeof store.commitBacklog === 'function' && !!store.commitBacklog();
    const wrote = positioned
      ? (handled.directory !== arrival.directory ||
         mintedWrites(handled) !== mintedWrites(arrival) ||
         (logged && logged.mustCommit) ||
         (typeof store.keysPending === 'function' && store.keysPending()) ||
         backlog)
      : store.pendingWrites();
    if (!wrote) {
      stats.answeredUnheld += 1;
      log.debug("Leaving end(). Nothing written while it was handled.");
      return end.apply(res, args);
    }
    const began = Date.now();
    stats.heldForCommit += 1;
    if (backlog) {
      stats.heldForBacklog += 1;
    }
    commitFailures(store, now).then(function (failed) {
      stats.totalHoldMs += Date.now() - began;
      if (!failed.length) {
        end.apply(res, args);
        return;
      }
      stats.commitFailures += 1;
      const url = res.req ? res.req.method + ' ' +
        String(res.req.originalUrl || res.req.url || '').split('?')[0] : '';
      log.error(errorCodes.tag('STS-STORE-0066') + 'persistence: ' +
                (url || 'a response') + ' changed the store and the commit ' +
                'of that change failed (' + failed.join('; ') + '); it is ' +
                'answered 503 instead of its success. The change is still ' +
                'in memory and its write is retried.');
      refuseForCommit(res, end);
    });
    log.debug("Leaving end(). Held for the commit.");
    return res;
  };
  log.debug("Leaving holdUntilCommitted().");
}

// ---------------------------------------------------------------------------
// RULE 2 FOR AN LDAP OPERATION (2026-09-29, #351).
//
// `ldap/ldap_server.js` wraps every handler in this at registration, INSIDE
// what `LOCAL_HANDLERS` holds, so it runs wherever the handler runs — the
// process holding the socket, or the request worker the operation was
// dispatched to — and holds that process's writes, which are the ones the
// operation made.
//
// An LDAP response is `res.end()` and a handler's `next()`, and both are
// held: `end()` until the commit, and a `next()` the handler called after
// it until the result has gone, so the worker's `performOperation()` (which
// reads the outcome when `next()` is called) sees the held result and not an
// operation that "ended nothing". `req.stsAsyncOperation` says so, as the
// asynchronous bind does. A handler that never calls `next()` gets one call
// once the result has gone, which is ldapjs's no-op past the last handler.
//
// **A FAILED COMMIT IS `unavailable` (52), NOT `busy` (51).** RFC 4511
// section 4.1.9: busy is "too busy to perform the request"; unavailable is
// "a subsystem necessary to complete the operation is offline" — and the
// store that refused the transaction is exactly that subsystem, whatever
// refused it (a starved pool, a fence, a database that went away). A worker
// that dies mid-operation is already answered 52 (`ldap/CLAUDE.md`, *A
// rejection is a refusal and never a second attempt*), so a client sees one
// result code for "the change may not have landed". Both are transient to
// every LDAP client that retries; 52 is the one that is true.
//
// **READS ARE HELD ONLY FOR WHAT THEY CHANGED IN THE DIRECTORY OR THE KEYS**,
// never for the audit and counter rows a search or compare leaves: the HTTP
// call log's success row, which is not held either (see above), for the
// same cost argument — a transaction on every read. A bind is held for all
// it wrote: a sign-in's rows are the ones somebody goes looking for.
// ---------------------------------------------------------------------------
const LDAP_WRITES = ['add', 'del', 'delete', 'modify', 'modifyDN'];
const LDAP_READS = ['search', 'compare'];

/**
 * Wraps an LDAP handler so that its result is sent only once the writes it
 * made have committed, and an error made by `refusal` is sent instead when
 * that commit fails.
 *
 * @param operation - the operation's name (`add`, `search`, …)
 * @param handler - the ldapjs handler
 * @param refusal - builds the error sent in place of a result whose commit
 *   failed, from a message
 * @returns the wrapped handler
 */
function answerAfterCommit(operation, handler, refusal) {
  log.debug("Entering answerAfterCommit(). " + operation);
  const writing = LDAP_WRITES.indexOf(operation) >= 0;
  const reading = LDAP_READS.indexOf(operation) >= 0;
  log.debug("Leaving answerAfterCommit().");
  return function answeredAfterCommit(req, res, next) {
    log.debug("Entering answeredAfterCommit(). " + operation);
    const store = persistence();
    if (typeof store.answersAfterCommit !== 'function' ||
        !store.answersAfterCommit() ||
        typeof store.writeGeneration !== 'function' ||
        typeof store.commitThrough !== 'function') {
      log.debug("Leaving answeredAfterCommit(). Not held here.");
      return handler(req, res, next);
    }
    const arrival = store.writeGeneration();
    const end = res.end;
    let held = false;
    let nextArgs = null;
    res.end = function () {
      log.debug("Entering the held end(). " + operation);
      const args = arguments;
      res.end = end;
      const now = store.writeGeneration();
      const backlog = writing && typeof store.commitBacklog === 'function' &&
        !!store.commitBacklog();
      const wrote = now.directory !== arrival.directory ||
        (!reading && mintedWrites(now) !== mintedWrites(arrival)) ||
        (typeof store.keysPending === 'function' && store.keysPending()) ||
        backlog;
      if (!wrote) {
        log.debug("Leaving the held end(). Nothing written.");
        return end.apply(res, args);
      }
      held = true;
      req.stsAsyncOperation = true;
      stats.ldapHeldForCommit += 1;
      if (backlog) {
        stats.heldForBacklog += 1;
      }
      commitFailures(store, now).then(function (failed) {
        if (!failed.length) {
          end.apply(res, args);
          next.apply(null, nextArgs || []);
          return;
        }
        stats.ldapRefusedForCommit += 1;
        stats.commitFailures += 1;
        log.error(errorCodes.tag('STS-STORE-0067') + 'persistence: an LDAP ' +
                  operation + ' changed the store and the commit of that ' +
                  'change failed (' + failed.join('; ') + '); it is ' +
                  'answered unavailable (52) instead of its result. The ' +
                  'change is still in memory and its write is retried.');
        next(refusal('The change could not be committed to the store. ' +
                     'Nothing was confirmed; try again.'));
      });
      log.debug("Leaving the held end(). Held for the commit.");
      return undefined;
    };
    log.debug("Leaving answeredAfterCommit().");
    return handler(req, res, function () {
      if (held) {
        nextArgs = Array.prototype.slice.call(arguments);
        return undefined;
      }
      return next.apply(null, arguments);
    });
  };
}

// RULE 2 FOR A MESSAGE THIS NODE SENDS (2026-09-27). What rule 2 does for a
// response, for an outbound delivery: in active-active mode it resolves once
// everything this process has written so far has committed. A Command Token
// carries a `callback_token` minted in memory a moment earlier; sent before
// that commit, the relying party's callback could reach the OTHER node, whose
// barrier caught it up to the change log's head — which did not include the
// token — and was refused 401 (`sts_provider_commands` in the cluster mode).
// Outside active-active it resolves at once. It never rejects: a commit that
// fails is logged and the message goes, as a held response does.
/**
 * Waits, in active-active mode, until everything this process has written so
 * far has committed, so an outbound message cannot reach another node first.
 *
 * @returns a promise of true when a commit was waited for, false outside
 *   active-active mode; it never rejects
 */
function commitBeforeSending() {
  log.debug("Entering commitBeforeSending().");
  if (!active()) {
    log.debug("Leaving commitBeforeSending(). Not active-active.");
    return Promise.resolve(false);
  }
  const store = persistence();
  if (typeof store.commitThrough !== 'function' ||
      typeof store.writeGeneration !== 'function') {
    log.debug("Leaving commitBeforeSending(). No positioned commit.");
    return Promise.resolve(false);
  }
  const target = store.writeGeneration();
  log.debug("Leaving commitBeforeSending(). Committing.");
  return Promise.resolve().then(function () {
    return store.commitThrough(target);
  }).then(function (results) {
    const failed = (results || []).filter(function (one) {
      return one && one.error;
    });
    if (failed.length) {
      stats.commitFailures += 1;
      log.error(errorCodes.tag('STS-CLUSTER-0019') + 'cluster barrier: a ' +
                'message held for this node\'s writes could not commit them (' +
                failed.map(function (one) { return one.error; }).join('; ') +
                '); it is sent, and another node may not see them until ' +
                'the retry lands.');
    }
    return true;
  }, function (e) {
    stats.commitFailures += 1;
    log.error(errorCodes.tag('STS-CLUSTER-0019') + 'cluster barrier: the ' +
              'commit a message was held for failed: ' +
              ((e && e.message) || e) + '; it is sent anyway.');
    return true;
  });
}

// For common/app.js's realm middleware, which runs above this one.
/**
 * Says whether the barrier applies: active-active mode with clustering on.
 *
 * @returns true when requests are held to the barrier
 */
function isActive() {
  log.debug("Entering isActive().");
  log.debug("Leaving isActive().");
  return active();
}

// That middleware caught this request up already: rule 1 is met by the barrier
// it ran — it started after the request arrived — so this one does not run
// another.
/**
 * Records that a request has already been caught up (by the realm middleware),
 * so the barrier does not run another pull for it.
 *
 * @param req - the request
 * @param answer - the pull's answer
 */
function markSynced(req, answer) {
  log.debug("Entering markSynced().");
  if (req) {
    req[SYNCED] = answer || { caughtUp: false };
  }
  log.debug("Leaving markSynced().");
}

/**
 * Builds the express middleware that applies both rules to every request in
 * active-active mode: catch up with the change log before serving, and hold
 * the answer until the request's writes commit.
 *
 * @returns the middleware
 */
function middleware() {
  log.debug("Entering middleware().");
  log.debug("Leaving middleware().");
  return function clusterBarrier(req, res, next) {
    log.debug("Entering clusterBarrier().");
    if (!holds()) {
      log.debug("Leaving clusterBarrier(). Neither rule applies.");
      next();
      return;
    }
    const store = persistence();
    const arrival = typeof store.writeGeneration === 'function'
      ? store.writeGeneration() : null;
    res[ARRIVAL] = arrival;
    holdUntilCommitted(res, arrival, req);
    // RULE 1 IS STILL A CLUSTER RULE: one node has nobody to catch up with.
    if (!active()) {
      log.debug("Leaving clusterBarrier(). Rule 2 only.");
      next();
      return;
    }
    stats.requests += 1;
    const began = Date.now();
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

/**
 * Reports the barrier's counters for `/admin/cluster`.
 *
 * @returns whether it is active, the counts, and the mean wait and hold times
 */
function report() {
  log.debug("Entering report().");
  log.debug("Leaving report().");
  return Object.assign({ active: active(), holds: holds() }, stats, {
    meanWaitMs: stats.requests ? stats.totalWaitMs / stats.requests : 0,
    meanHoldMs: stats.heldForCommit
      ? stats.totalHoldMs / stats.heldForCommit : 0
  });
}

// At require time; see cluster.js's note on why a capability is the code.
capabilities.provide('cluster.read-barrier');

/**
 * Read-your-write between nodes (#46): in active-active mode a request is
 * served only after its node has applied everything committed before it
 * arrived, and answered only once its own writes have committed.
 *
 * Installed by `common/app.js` below the request pool's middleware.
 * @namespace
 */
module.exports = {
  middleware: middleware,
  syncShared: syncShared,
  holdUntilCommitted: holdUntilCommitted,
  answerAfterCommit: answerAfterCommit,
  onCommitRefused: onCommitRefused,
  commitBeforeSending: commitBeforeSending,
  callLogStarts: callLogStarts,
  isActive: isActive,
  markSynced: markSynced,
  callLogRecorded: callLogRecorded,
  report: report
};
