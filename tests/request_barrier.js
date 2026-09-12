'use strict';
//
// File: request_barrier.js
//
// ===========================================================================
// A 502 HELD EVERY READER IN THE SERVICE FOR THE LIFE OF THE PROCESS.
//
// `common/request_pool.js`'s read barrier is bookkeeping over integers. Every
// dispatched request takes a TICKET; the ticket ARMS when this process has
// finished piping that response out; it CLEARS when the worker that answered
// it announces that its flush covered it. A reader waits until every armed
// ticket at or below the number it arrived at has cleared, and gives up after
// 2,000ms.
//
// ---------------------------------------------------------------------------
// THE DEFECT, WHICH IS ONE LINE AND IS PERMANENT.
//
// `proxy()` called `finish()` from `upstream.on('error')` — the path taken
// when the worker never answered at all, and the path on which the client is
// handed a 502. `finish()` ARMED the ticket. The worker, which in that case
// never ran the handler, announces nothing, ever. So the ticket sat armed for
// the life of the process and **every read after it waited the full 2,000ms
// and then served stale anyway**.
//
// It is a cliff rather than a slope, and the run that found it makes the shape
// plain: a service 41 minutes idle with 5,521 stuck tickets, a
// `GET /admin-api/ldap/directory?per=1` taking 2.6s, and four bulk-load jobs
// failing outright — not on an assertion but on a 10-second CONNECT timeout,
// because that is shorter than the queue those waits build. The SCIM job got
// through 536 of 5,000 creates in 405 seconds; the same job in the same suite's
// single-process mode takes 93 for all 5,000.
//
// **NOTHING COULD SEE IT.** The service answered every request correctly. The
// only signal was a warning line that says "serving without it", which is the
// line it prints when the mechanism is working as designed and a flush is
// merely slow. `pool.stats().tickets` exists now so that the state has a name.
//
// ---------------------------------------------------------------------------
// WHY IT IS ASSERTED HERE AND NOT OVER HTTP.
//
// `tests/front_process_writes.js`'s argument word for word: the decision is
// integers, and the integers are the part that was wrong. Starting a real pool
// would test node's unix-socket proxying, which is not what wedged — and the
// failure only becomes visible over HTTP as latency, which is the one thing a
// suite cannot assert without becoming flaky.
// ===========================================================================

const pool = require('../common/request_pool');

// `workers.readYourWrite` is process-wide and every later file in this run
// reads through it — see tests/CLAUDE.md's rule about process-wide state.
//
// **IT AWAITS, WHERE tests/front_process_writes.js's VERSION DOES NOT, AND
// COPYING THAT ONE COST TWENTY MINUTES.** Every section here is `async`, so a
// plain `try { return fn(); } finally { ... }` restores the variable the moment
// the callback hands back its PROMISE — which is before its first `await` has
// run. The barrier then reads the setting as OFF for the whole body and every
// assertion about waiting passes vacuously in the wrong direction.
async function withReadYourWrite(on, fn) {
  const had = process.env.STS_WORKERS_READ_YOUR_WRITE;
  process.env.STS_WORKERS_READ_YOUR_WRITE = on ? 'true' : 'false';
  try {
    return await fn();
  } finally {
    if (had === undefined) {
      delete process.env.STS_WORKERS_READ_YOUR_WRITE;
    } else {
      process.env.STS_WORKERS_READ_YOUR_WRITE = had;
    }
  }
}

// A worker entry, which is all the barrier ever touches of one: a pid to name
// it by and the set of tickets it owes. The real thing carries a socket, a
// child process and a generation, and none of those is reachable from here.
function worker(pid) {
  return { pid: pid, tickets: new Set() };
}

// How long `awaitCommitConfirmations()` actually took, in ms. A reader that is
// not blocked resolves in the same tick; a blocked one waits the 2,000ms bound.
// The threshold below is 500ms rather than anything tighter because this is a
// timer and the runner may be sharing a machine with a container build.
async function waitedFor(servedBy) {
  const at = Date.now();
  await pool.awaitCommitConfirmations(servedBy);
  return Date.now() - at;
}

// ---------------------------------------------------------------------------
// 1. THE MECHANISM, WORKING: AN ARMED TICKET BLOCKS AND A COMMIT RELEASES.
//
// Asserted first so that what follows is a departure from something known
// rather than from an assumption. Two workers, because a worker is never made
// to wait for its OWN answered writes — those are in its memory already, which
// is the 2026-09-08 exemption in blockedBelow().
// ---------------------------------------------------------------------------
async function checkAnArmedTicketBlocksUntilItCommits(t) {
  t.log.info('=== an armed ticket blocks a reader on another worker ===');

  pool.reset();
  const a = worker(101);
  const b = worker(102);

  await withReadYourWrite(true, async function () {
    const ticket = pool.dispatchTicket(a);
    t.check(typeof ticket === 'number' && ticket > 0,
            'a dispatched request takes a ticket',
            'got ' + JSON.stringify(ticket));

    t.check(await waitedFor(b) < 500,
            'a reader arriving while it is still IN FLIGHT does not wait',
            'a request that has not been answered has been acknowledged to ' +
            'nobody, so nothing can be depending on having seen it');

    pool.ticketFinished(a, ticket);
    t.check(await waitedFor(b) >= 1900,
            'a reader arriving once it has been ANSWERED waits',
            'this is the whole of read-your-write: worker B must not report ' +
            'on a write worker A has answered and not yet flushed');

    t.check(await waitedFor(a) < 500,
            'but the worker that answered it does not wait for itself',
            'the write is in A’s own memory whether or not it has been ' +
            'flushed, and waiting for it is what made a sequential client pay ' +
            'a commit round trip per request');

    pool.receiveCommitted(a, { wrote: true, tickets: [ticket] });
    t.check(await waitedFor(b) < 500,
            'and the worker’s commit announcement releases it',
            'still blocked: ' + JSON.stringify(pool.stats().tickets));
    t.equal(pool.stats().tickets.outstanding, 0,
            'with nothing left outstanding');
  });
}

// ---------------------------------------------------------------------------
// 2. THE DEFECT: A TICKET THE WORKER NEVER ANSWERED MUST NOT ARM.
//
// This is the regression. Before the fix the second assertion below was the
// state the service stayed in for ever.
// ---------------------------------------------------------------------------
async function checkAnUnansweredRequestReleasesItsTicket(t) {
  t.log.info('=== a request the worker never answered releases its ticket ===');

  pool.reset();
  const a = worker(201);
  const b = worker(202);

  await withReadYourWrite(true, async function () {
    const ticket = pool.dispatchTicket(a);
    // What `proxy()` does now on `upstream.on('error')` with nothing answered:
    // the client is handed a 502 and the ticket goes back.
    pool.ticketAbandoned(a, ticket);

    t.equal(pool.stats().tickets.outstanding, 0,
            'the ticket is gone rather than armed');
    t.check(await waitedFor(b) < 500,
            'so a reader on another worker is not blocked by it',
            'THE WEDGE: the worker never ran the handler, so it will never ' +
            'announce this ticket — arming it made every read in the ' +
            'service wait the full 2,000ms bound and then serve stale, for ' +
            'the life of the process');

    t.check(pool.receiveCommitted(a, { wrote: true, tickets: [ticket] }) ===
              undefined,
            'and a late announcement for it is harmless',
            'the worker may have run the handler and failed on the way back; ' +
            'receiveCommitted() skips a ticket the entry no longer owns');
    t.equal(pool.stats().tickets.outstanding, 0,
            'nothing having come back into the set');
  });
}

// ---------------------------------------------------------------------------
// 3. THE SAFETY NET: A TICKET ALREADY GIVEN UP ON IS REAPED.
//
// Section 2 closes the one leak this run found. It cannot be the last: every
// path where this process finishes a response and the worker never announces
// it produces the same permanent wedge. So a wait that TIMES OUT drops what it
// timed out on, and the argument is one sentence — that reader was served
// without those tickets and so will every reader after it, so keeping them
// changes no answer and costs each one the full bound.
//
// The reaper's own age threshold is thirty seconds, which is far above the
// bound on purpose: a flush during a bulk load genuinely can take seconds, and
// a ticket reaped while its flush is merely slow would release a reader early.
// That threshold is what this section drives against, and it is why the
// assertion here is that a FRESH stuck ticket survives its first timeout.
// ---------------------------------------------------------------------------
async function checkAFreshTicketSurvivesItsFirstTimeout(t) {
  t.log.info('=== a ticket that is merely slow is not reaped ===');

  pool.reset();
  const a = worker(301);
  const b = worker(302);

  await withReadYourWrite(true, async function () {
    const ticket = pool.dispatchTicket(a);
    pool.ticketFinished(a, ticket);

    t.check(await waitedFor(b) >= 1900,
            'a reader waits the bound and gives up',
            'expected the 2,000ms timeout');
    t.equal(pool.stats().tickets.reaped, 0,
            'and nothing is reaped on that timeout',
            'a flush that has been running for two seconds is slow rather ' +
            'than lost — persistence.flush() diffs the whole directory, ' +
            'and reaping here would release the next reader early for real');
    t.equal(pool.stats().tickets.outstanding, 1,
            'the ticket still being outstanding');

    pool.receiveCommitted(a, { wrote: true, tickets: [ticket] });
    t.equal(pool.stats().tickets.outstanding, 0,
            'and a slow announcement still clears it when it arrives');
  });
}

// ---------------------------------------------------------------------------
// 4. WITH THE BARRIER OFF, NONE OF THIS HAPPENS AT ALL.
//
// `workers.readYourWrite` is off by default. A ticket taken there would be a
// cost paid by a deployment that said no — and, worse, one that nothing would
// ever clear, because the pool's own clearing path returns early too.
// ---------------------------------------------------------------------------
async function checkTheSwitchIsHonoured(t) {
  t.log.info('=== with read-your-write off, no ticket is taken ===');

  pool.reset();
  const a = worker(401);

  await withReadYourWrite(false, async function () {
    t.check(pool.dispatchTicket(a) === undefined,
            'a dispatched request takes no ticket',
            'got ' + JSON.stringify(pool.dispatchTicket(a)));
    t.equal(pool.stats().tickets.outstanding, 0,
            'so nothing is outstanding');
    t.check(await waitedFor(a) < 500,
            'and no reader ever waits',
            'the barrier is the whole cost of the setting and it is off');
  });
}

// ---------------------------------------------------------------------------
// 5. AND A TICKET THAT IS LONG PAST EXPLAINING IS REAPED.
//
// The other half of section 3. Thirty seconds after a response was answered,
// a worker that has not announced it is not slow — it has lost the
// announcement — and every read since has been served without that ticket
// after paying the full bound for it. So it goes, loudly: `reaped` is on
// `pool.stats().tickets` and the log line names the cause, because the whole
// lesson of this file is that a leak here is invisible from outside.
//
// The clock is passed in rather than waited for. Thirty seconds of a test run
// to assert one comparison is thirty seconds nobody spends.
// ---------------------------------------------------------------------------
async function checkAStuckTicketIsReaped(t) {
  t.log.info('=== a ticket nothing has explained for 30s is reaped ===');

  pool.reset();
  const a = worker(501);
  const b = worker(502);

  await withReadYourWrite(true, async function () {
    const ticket = pool.dispatchTicket(a);
    pool.ticketFinished(a, ticket);

    pool.reapStuckTickets(ticket, Date.now() + 29000);
    t.equal(pool.stats().tickets.outstanding, 1,
            'at 29s it is still held',
            'the threshold is 30s and being under it must mean under it');

    pool.reapStuckTickets(ticket, Date.now() + 31000);
    t.equal(pool.stats().tickets.reaped, 1,
            'at 31s it is reaped');
    t.equal(pool.stats().tickets.outstanding, 0,
            'and is out of the set');
    t.check(await waitedFor(b) < 500,
            'so the next reader does not pay the bound for it',
            'that reader would have been served without it anyway — reaping ' +
            'changes no answer, only how long the next one waits for it');
  });
}

async function run(t) {
  await checkAnArmedTicketBlocksUntilItCommits(t);
  await checkAnUnansweredRequestReleasesItsTicket(t);
  await checkAFreshTicketSurvivesItsFirstTimeout(t);
  await checkAStuckTicketIsReaped(t);
  await checkTheSwitchIsHonoured(t);
  // THE POOL IS PROCESS-WIDE MODULE STATE AND THIS FILE ARMED TICKETS IN IT.
  // Left behind, they would make every later file's reader wait the bound.
  pool.reset();
}

module.exports = {
  name: 'request_barrier',
  describe: 'that a request no worker answered releases its read-barrier ' +
            'ticket, so a 502 cannot wedge every reader in the service for ' +
            'the life of the process',
  run: run
};
