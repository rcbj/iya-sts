'use strict';
//
// File: front_process_writes.js
//
// ===========================================================================
// THE FRONT PROCESS WRITES TOO, AND FOR TWO DAYS NOTHING TOLD THE WORKERS.
//
// `common/request_pool.js` keeps a GENERATION. A worker carries the one it has
// caught up to, and a request dispatched to a worker that is behind waits at a
// barrier while that worker pulls. It is what makes `workers.readYourWrite`
// mean anything: 20 of 40 callers could not read their own write without it, 0
// of 40 with it.
//
// The generation moved in exactly one place — `receiveCommitted()`, on a
// WORKER's announcement that its flush had committed. That is the whole story
// for anything arriving on the dispatched HTTP port, and this service answers
// on five more socket families that are never dispatched at all, because they
// are not `app`:
//
//   * the two TLS listeners, which have a handler of their own in
//     `tls/tls_server.js` rather than going through express;
//   * the directory, on 389 and 636;
//   * the KDC, on TCP and UDP 88;
//   * SPIFFE's two gRPC surfaces.
//
// Everything minted on those is written by the front process, and no worker was
// ever marked stale for it.
//
// ---------------------------------------------------------------------------
// THE FAILURE IT PRODUCED, WHICH IS WHY THIS FILE IS NOT ABOUT AN ABSTRACTION.
//
// A verified client certificate on 9443 starts a sign-on session (2026-09-05).
// In `dispatch` mode the session is minted in the front process and `/logout`
// is answered by a WORKER, whose own copy of the session store had never heard
// of it — so a global sign-out reported that it had ended everything and left a
// live way in. `sts_global_logout` caught it as "8 were live and 1 still are",
// naming a client certificate on the required-client-certificate listener.
//
// **IT IS INTERMITTENT BY CONSTRUCTION, WHICH IS THE ARGUMENT FOR TESTING IT
// HERE.** The worker does get there in the end — the replication poll is five
// seconds — so whether the sign-out is correct depends on how long the run took
// to reach it. It failed once in a three-mode run and passed when the same job
// was run alone, which is the least useful shape of evidence there is. The
// decision underneath it is a comparison of two integers, and that is what is
// asserted below.
//
// ---------------------------------------------------------------------------
// WHY THE COUNT IS PASSED IN RATHER THAN READ.
//
// `noteLocalWrites()` takes the number of change rows this process has
// committed instead of asking `persistence.changeRowsWritten()` itself, and
// the caller in `dispatch()` does the asking. That is what lets this file drive
// the decision with no store, no fork and no socket — and the decision is the
// part that was wrong. What a store would add here is a test of `persistence`,
// which `tests/replication.js` already is.
// ===========================================================================

const pool = require('../common/request_pool');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'front_process_writes',
  level: process.env.LOG_LEVEL || 'info' });

// `workers.readYourWrite` is process-wide and every later file in this run
// reads through it — see tests/CLAUDE.md's rule about process-wide state.
function withReadYourWrite(on, fn) {
  log.debug("Entering withReadYourWrite().");
  const had = process.env.STS_WORKERS_READ_YOUR_WRITE;
  process.env.STS_WORKERS_READ_YOUR_WRITE = on ? 'true' : 'false';
  try {
    log.debug("Leaving withReadYourWrite().");
    return fn();
  } finally {
    if (had === undefined) {
      delete process.env.STS_WORKERS_READ_YOUR_WRITE;
    } else {
      process.env.STS_WORKERS_READ_YOUR_WRITE = had;
    }
  }
}

function generation() {
  log.debug("Entering generation().");
  log.debug("Leaving generation().");
  return pool.stats().generation;
}

// ---------------------------------------------------------------------------
// 1. THE FIRST SAMPLE BUMPS NOTHING.
//
// This process writes plenty on the way up — it seeds a directory, a realm
// registry and three of its own applications — and all of it is in the store
// before a worker is forked. A bump for that would send every worker through a
// barrier on its first request to fetch what it was born holding.
// ---------------------------------------------------------------------------
function checkTheFirstSampleIsABaseline(t) {
  log.debug("Entering checkTheFirstSampleIsABaseline().");
  t.log.info('=== the first sample is a baseline, not a change ===');

  withReadYourWrite(true, function () {
    const before = generation();
    const moved = pool.noteLocalWrites(4096);
    t.check(moved === false,
            'the first count this pool is shown moves nothing',
            'it is a baseline: everything written on the way up is already ' +
            'in every worker, and a bump would be a barrier for nothing');
    t.check(generation() === before,
            'and the generation is where it was',
            'expected ' + before + ', got ' + generation());
  });
  log.debug("Leaving checkTheFirstSampleIsABaseline().");
}

// ---------------------------------------------------------------------------
// 2. A WRITE BY THIS PROCESS MOVES IT, AND ONLY A WRITE DOES.
//
// The defect exactly: the count grows because the front process committed
// something a worker has not got, and every worker must catch up before it
// answers again. A count that has NOT grown must move nothing — the generation
// is read on every dispatched request, and a bump per request would put every
// request through a barrier, which is the cost `receiveCommitted()` refuses for
// the same reason.
// ---------------------------------------------------------------------------
function checkAWriteMovesIt(t) {
  log.debug("Entering checkAWriteMovesIt().");
  t.log.info('=== a write by this process moves the generation ===');

  withReadYourWrite(true, function () {
    // THE BASELINE IS MODULE STATE AND SECTION 1 HAS ALREADY SET ONE, which is
    // exactly how the pool behaves in a live process: one baseline, for the
    // life of the process, moving forward with the store's own count. So the
    // numbers here CLIMB from section 1's rather than starting again — a test
    // that reset them would be asserting against a pool nobody runs.
    pool.noteLocalWrites(10000);
    const base = generation();

    t.check(pool.noteLocalWrites(10001) === true,
            'one more committed change row moves the generation',
            'this is the sign-out that left a session behind: the session ' +
            'was minted on a socket only this process holds, and nothing ' +
            'told the worker that answers /logout');
    t.check(generation() === base + 1,
            'by exactly one',
            'expected ' + (base + 1) + ', got ' + generation());

    const held = generation();
    t.check(pool.noteLocalWrites(10001) === false,
            'the same count again moves nothing',
            'the generation is read on every dispatched request, so a bump ' +
            'per request would be a barrier per request');
    t.check(pool.noteLocalWrites(3) === false,
            'and a count that went BACKWARDS moves nothing',
            'a store that was reopened, or a driver that counts per ' +
            'connection: going backwards is not a write and must not be ' +
            'reported as one');
    t.check(generation() === held,
            'so the generation is unchanged by either',
            'expected ' + held + ', got ' + generation());

    t.check(pool.noteLocalWrites(20000) === true,
            'and a jump of many rows moves it once',
            'a burst — an LDAP bulk load over 389, which is this process ' +
            'too — is one catch-up and not ninety');
  });
  log.debug("Leaving checkAWriteMovesIt().");
}

// ---------------------------------------------------------------------------
// 3. WITH THE BARRIER OFF, NOTHING MOVES AT ALL.
//
// `workers.readYourWrite` is OFF by default, because that is the behaviour that
// existed before it and whether the wait is worth it is a question about the
// callers. A generation that moved anyway would be a cost paid by every
// deployment that had said no — and `receiveCommitted()` returns early for the
// same reason, so this is the same rule read from the other end.
// ---------------------------------------------------------------------------
function checkTheSwitchIsHonoured(t) {
  log.debug("Entering checkTheSwitchIsHonoured().");
  t.log.info('=== with read-your-write off, nothing moves ===');

  withReadYourWrite(false, function () {
    const before = generation();
    const moved = pool.noteLocalWrites(999999);
    t.check(moved === false,
            'a write moves nothing while the barrier is off',
            'the generation is only consulted under workers.readYourWrite, ' +
            'and moving it there would be a cost paid by a deployment that ' +
            'said no');
    t.check(generation() === before,
            'and the generation is where it was',
            'expected ' + before + ', got ' + generation());
  });
  log.debug("Leaving checkTheSwitchIsHonoured().");
}

function run(t) {
  log.debug("Entering run().");
  checkTheFirstSampleIsABaseline(t);
  checkAWriteMovesIt(t);
  checkTheSwitchIsHonoured(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'front_process_writes',
  describe: 'that a write by the process holding the undispatched sockets ' +
            'marks every request worker stale, so a sign-out cannot miss a ' +
            'session minted on one of them',
  run: run
};
