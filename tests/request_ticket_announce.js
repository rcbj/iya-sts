// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_ticket_announce.js
//
// ===========================================================================
// AN ANSWERED TICKET WHOSE ANNOUNCEMENT WAITED FOR A FLUSH THE WORKER COULD
// NOT FINISH (#620, 2026-10-14).
//
// Under the 2026-10-14 LDAPS bulk load on 8081 (two protocol workers,
// `workers.readYourWrite` on, postgres) `common/request_pool.js` dropped six
// tickets in forty minutes with STS-WORKER-0008: each had been answered for
// more than thirty seconds with no worker reporting its commit, and until it
// went every read served by the OTHER worker waited the full 2,000 ms bound
// (STS-WORKER-0007).
//
// The worker's commit announcement (`common/commit_announcer.ts`) named a
// ticket only once a flush AFTER the answer had finished — even though, on a
// postgres store, the answer itself had already waited for the commit
// (`cluster/cluster_barrier.js`, rule 2, #351). So a ticket whose write was in
// the store stayed armed for as long as that later flush took, or for as long
// as the worker's event loop was blocked before it could complete it: worker 2
// was blocked for about a minute around the first of the six (STS-WORKER-0027
// twice, STS-STORE-0068 61.7 s).
//
// This file drives the REAL announcer against the REAL pool bookkeeping, with
// a store whose flush never settles — which is what a blocked worker or a
// stuck flush looks like from the front process — and the announcement handed
// straight to `receiveCommitted()`, which is what the channel does:
//
//   1. a store that does NOT hold answers for their commit (ldif, memory): the
//      ticket still waits for the flush, and is dropped at thirty seconds —
//      the defect, kept as the control, because there the flush is the only
//      thing that knows the write landed;
//   2. a store that does (postgres): the same operation's ticket is cleared
//      in the tick it is answered, nothing is reaped, and a reader on the
//      other worker does not wait — the fix;
//   3. the announcement says `wrote` truthfully, so the generation moves for
//      a committed row and only for one;
//   4. a handler that THREW is not announced early: it may have stopped
//      inside a write nothing held, so it waits for the flush, as before;
//   5. what STS-WORKER-0008 now says about a dropped ticket tells a silent
//      worker from one that announced since and never named it.
//
// In process and over integers, on `tests/request_barrier.js`' argument: the
// decision is bookkeeping, and the failure is visible over HTTP only as
// latency.
// ===========================================================================

const pool = require('../common/request_pool');
const CommitAnnouncer = require('../common/commit_announcer');

const log = require('bunyan').createLogger({ name: 'request_ticket_announce',
  level: process.env.LOG_LEVEL || 'info' });

// `workers.readYourWrite` on for the body, and restored after it AWAITS —
// `tests/request_barrier.js`' withReadYourWrite() says what not awaiting cost.
async function withReadYourWrite(fn) {
  log.debug("Entering withReadYourWrite().");
  const had = process.env.STS_WORKERS_READ_YOUR_WRITE;
  process.env.STS_WORKERS_READ_YOUR_WRITE = 'true';
  try {
    log.debug("Leaving withReadYourWrite().");
    return await fn();
  } finally {
    if (had === undefined) {
      delete process.env.STS_WORKERS_READ_YOUR_WRITE;
    } else {
      process.env.STS_WORKERS_READ_YOUR_WRITE = had;
    }
  }
}

// A worker entry: what the barrier touches of one.
function worker(pid) {
  log.debug("Entering worker().");
  log.debug("Leaving worker().");
  return { pid: pid, pool: 'protocol', tickets: new Set(), inFlight: 0 };
}

// A store whose flush the test settles, or never does. `answers` is what
// `answersAfterCommit()` says; `rows` is the committed change-row count.
function store(answers) {
  log.debug("Entering store().");
  const flushes = [];
  const s = {
    rows: 0,
    flushes: flushes,
    flush: function () {
      log.debug("Entering store flush().");
      log.debug("Leaving store flush().");
      return new Promise(function (resolve) {
        flushes.push(resolve);
      });
    },
    flushMinted: function () {
      log.debug("Entering store flushMinted().");
      log.debug("Leaving store flushMinted().");
      return Promise.resolve({ written: false });
    },
    changeRowsWritten: function () {
      log.debug("Entering store changeRowsWritten().");
      log.debug("Leaving store changeRowsWritten().");
      return s.rows;
    },
    answersAfterCommit: function () {
      log.debug("Entering store answersAfterCommit().");
      log.debug("Leaving store answersAfterCommit().");
      return answers;
    }
  };
  log.debug("Leaving store().");
  return s;
}

// The announcer a worker builds, with its channel replaced by the pool's own
// receiving end for `entry` — which is all the channel does.
function announcerFor(entry, persistence) {
  log.debug("Entering announcerFor().");
  log.debug("Leaving announcerFor().");
  return new CommitAnnouncer({
    log: log,
    config: { value: function (key) {
      return key === 'workers.readYourWrite' ? true : undefined;
    } },
    errorCodes: { tag: function (code) {
      return '[' + code + '] ';
    } },
    persistence: persistence,
    send: function (message) {
      pool.receiveCommitted(entry, message.committed);
    }
  });
}

// How long a reader served by `servedBy` waited, in ms.
async function waitedFor(servedBy) {
  log.debug("Entering waitedFor().");
  const at = Date.now();
  await pool.awaitCommitConfirmations(servedBy);
  log.debug("Leaving waitedFor().");
  return Date.now() - at;
}

// Lets every queued promise callback run.
function settle() {
  log.debug("Entering settle().");
  log.debug("Leaving settle().");
  return new Promise(function (resolve) {
    setImmediate(resolve);
  });
}

// ---------------------------------------------------------------------------
// 1. THE CONTROL: AN ANSWER NOT HELD FOR ITS COMMIT WAITS FOR THE FLUSH.
//
// This is the path every ticket took before #620. The LDAP add is answered,
// the front process arms the ticket, the flush never finishes — and at thirty
// seconds the safety net drops it. That drop IS the defect on a postgres
// store; on one that does not hold answers it is still the only safe thing,
// because nothing but the flush knows the write landed.
// ---------------------------------------------------------------------------
async function checkAnUnheldAnswerWaitsForTheFlush(t) {
  log.debug("Entering checkAnUnheldAnswerWaitsForTheFlush().");
  t.log.info('=== an answer not held for its commit waits for the flush ===');
  pool.reset();
  const a = worker(701);
  await withReadYourWrite(async function () {
    const persistence = store(false);
    const announcer = announcerFor(a, persistence);
    const ticket = pool.dispatchTicket(a, 'operation ldap.add');
    // The worker: the handler settled, the answer goes out.
    persistence.rows += 10;
    announcer.noteOperationFinished(ticket, true);
    // The front process: the answer arrives and arms the ticket.
    pool.ticketFinished(a, ticket);
    await settle();
    t.equal(pool.stats().tickets.finished, 1,
            'the ticket is armed and waits for the flush',
            'nothing but the flush can say an unheld write landed');
    pool.reapStuckTickets(ticket, Date.now() + 31000);
    t.equal(pool.stats().tickets.reaped, 1,
            'and with the flush stuck it is dropped at thirty seconds',
            'this is STS-WORKER-0008 — the drop #620 was about');
  });
  pool.reset();
  log.debug("Leaving checkAnUnheldAnswerWaitsForTheFlush().");
}

// ---------------------------------------------------------------------------
// 2. THE FIX: AN ANSWER HELD FOR ITS COMMIT IS ANNOUNCED WITH IT.
//
// The same operation, the same stuck flush, on a store that holds a writing
// answer until its commit. The announcement goes out in the tick the handler
// settles — BEFORE the answer, on the same channel — so the front process
// clears the ticket first and its arming is a no-op. Asserted in both orders,
// because over HTTP the answer and the announcement travel on different
// sockets and either may arrive first.
// ---------------------------------------------------------------------------
async function checkAHeldAnswerIsAnnouncedWithIt(t) {
  log.debug("Entering checkAHeldAnswerIsAnnouncedWithIt().");
  t.log.info('=== an answer held for its commit is announced with it ===');
  pool.reset();
  const a = worker(711);
  const b = worker(712);
  await withReadYourWrite(async function () {
    const persistence = store(true);
    const announcer = announcerFor(a, persistence);

    const first = pool.dispatchTicket(a, 'operation ldap.add');
    persistence.rows += 10;
    announcer.noteOperationFinished(first, true);
    pool.ticketFinished(a, first);
    t.equal(pool.stats().tickets.outstanding, 0,
            'announced before its answer arrives, it is never armed',
            'still outstanding: ' + JSON.stringify(pool.stats().tickets));

    const second = pool.dispatchTicket(a, 'POST /scim/v2/Users');
    pool.ticketFinished(a, second);
    persistence.rows += 3;
    t.check(announcer.announceAnswered(second) === true,
            'a finished HTTP response is announced at once',
            'announceAnswered() refused on a store that holds answers');
    t.equal(pool.stats().tickets.outstanding, 0,
            'and an armed ticket is cleared by it');

    pool.reapStuckTickets(second, Date.now() + 31000);
    t.equal(pool.stats().tickets.reaped, 0,
            'so thirty seconds of a stuck flush drops nothing',
            'before #620 both tickets waited for that flush');
    t.check(await waitedFor(b) < 500,
            'and a reader on the other worker does not wait',
            'it waited the 2,000 ms bound for every read before #620');
    t.check(persistence.flushes.length > 0,
            'while the flush-gated announcement still runs beside it',
            'it is what moves the generation for rows no answer is held for');
  });
  pool.reset();
  log.debug("Leaving checkAHeldAnswerIsAnnouncedWithIt().");
}

// ---------------------------------------------------------------------------
// 3. `wrote` IS THE TRUTH, BECAUSE A CLEARED TICKET RELEASES A READER.
//
// The generation is what sends the released reader through a sync. An
// announcement that cleared the ticket and said nothing was written would
// release it into a worker that has not fetched the row.
// ---------------------------------------------------------------------------
async function checkWroteIsTheTruth(t) {
  log.debug("Entering checkWroteIsTheTruth().");
  t.log.info('=== the early announcement says whether a row committed ===');
  pool.reset();
  const a = worker(721);
  await withReadYourWrite(async function () {
    const persistence = store(true);
    const announcer = announcerFor(a, persistence);
    const before = pool.stats().generation;

    const read = pool.dispatchTicket(a, 'operation ldap.search');
    announcer.noteOperationFinished(read, true);
    t.equal(pool.stats().generation, before,
            'an answer that committed nothing does not move the generation',
            'moving it would mark every other worker stale for nothing');

    const add = pool.dispatchTicket(a, 'operation ldap.add');
    persistence.rows += 10;
    announcer.noteOperationFinished(add, true);
    t.equal(pool.stats().generation, before + 1,
            'an answer that committed rows moves it, once',
            'a reader released by the cleared ticket must be synced');
  });
  pool.reset();
  log.debug("Leaving checkWroteIsTheTruth().");
}

// ---------------------------------------------------------------------------
// 4. A HANDLER THAT THREW IS NOT ANNOUNCED EARLY.
//
// It may have stopped inside a write that nothing held, so its ticket waits
// for the flush — and is cleared when that flush does finish.
// ---------------------------------------------------------------------------
async function checkAThrownHandlerWaitsForTheFlush(t) {
  log.debug("Entering checkAThrownHandlerWaitsForTheFlush().");
  t.log.info('=== a handler that threw waits for the flush ===');
  pool.reset();
  const a = worker(731);
  await withReadYourWrite(async function () {
    const persistence = store(true);
    const announcer = announcerFor(a, persistence);
    const ticket = pool.dispatchTicket(a, 'operation ldap.modify');
    announcer.noteOperationFinished(ticket, false);
    pool.ticketFinished(a, ticket);
    await settle();
    t.equal(pool.stats().tickets.finished, 1,
            'its ticket stays armed while the flush runs');
    persistence.flushes.forEach(function (resolve) {
      resolve({ written: true });
    });
    await settle();
    t.equal(pool.stats().tickets.outstanding, 0,
            'and the flush, once it finishes, clears it',
            'still outstanding: ' + JSON.stringify(pool.stats().tickets));
  });
  pool.reset();
  log.debug("Leaving checkAThrownHandlerWaitsForTheFlush().");
}

// ---------------------------------------------------------------------------
// 5. WHAT STS-WORKER-0008 SAYS ABOUT A DROPPED TICKET.
//
// It used to say how many. It now says what each was, which worker answered
// it and when — and whether that worker has announced anything since, which
// is what tells a STALLED worker (or a stuck flush) from a LOST announcement.
// ---------------------------------------------------------------------------
async function checkTheDropSaysWhichCause(t) {
  log.debug("Entering checkTheDropSaysWhichCause().");
  t.log.info('=== a dropped ticket is described ===');
  pool.reset();
  const a = worker(741);
  await withReadYourWrite(async function () {
    const stalled = pool.dispatchTicket(a, 'GET /admin-api/status');
    pool.ticketFinished(a, stalled);
    const said = pool.describeTicket(stalled, Date.now() + 31000);
    t.check(/GET \/admin-api\/status/.test(said) && /worker 741/.test(said) &&
            /STALLED/.test(said),
            'a worker silent since the answer is reported as stalled',
            'said: ' + said);

    const other = pool.dispatchTicket(a, 'operation ldap.add');
    pool.ticketFinished(a, other);
    pool.receiveCommitted(a, { wrote: false, tickets: [other] });
    const lost = pool.describeTicket(stalled, Date.now() + 31000);
    t.check(/LOST/.test(lost) && /1 commit/.test(lost),
            'one that announced since without naming it is reported as lost',
            'said: ' + lost);
  });
  pool.reset();
  log.debug("Leaving checkTheDropSaysWhichCause().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkAnUnheldAnswerWaitsForTheFlush(t);
  await checkAHeldAnswerIsAnnouncedWithIt(t);
  await checkWroteIsTheTruth(t);
  await checkAThrownHandlerWaitsForTheFlush(t);
  await checkTheDropSaysWhichCause(t);
  // The pool is process-wide module state; nothing armed here may outlive it.
  pool.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_ticket_announce',
  describe: 'that a worker announces a ticket whose answer was held for its ' +
            'commit in the same tick, so a stuck flush or a blocked worker ' +
            'cannot keep it armed until STS-WORKER-0008 drops it (#620)',
  run: run
};
