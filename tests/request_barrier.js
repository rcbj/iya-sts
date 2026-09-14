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

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'request_barrier',
  level: process.env.LOG_LEVEL || 'info' });

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
  log.debug("Entering withReadYourWrite().");
  const had = process.env.STS_WORKERS_READ_YOUR_WRITE;
  process.env.STS_WORKERS_READ_YOUR_WRITE = on ? 'true' : 'false';
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

// A worker entry, which is all the barrier ever touches of one: a pid to name
// it by and the set of tickets it owes. The real thing carries a socket, a
// child process and a generation, and none of those is reachable from here.
function worker(pid) {
  log.debug("Entering worker().");
  log.debug("Leaving worker().");
  return { pid: pid, tickets: new Set() };
}

// How long `awaitCommitConfirmations()` actually took, in ms. A reader that is
// not blocked resolves in the same tick; a blocked one waits the 2,000ms bound.
// The threshold below is 500ms rather than anything tighter because this is a
// timer and the runner may be sharing a machine with a container build.
async function waitedFor(servedBy) {
  log.debug("Entering waitedFor().");
  const at = Date.now();
  await pool.awaitCommitConfirmations(servedBy);
  log.debug("Leaving waitedFor().");
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
  log.debug("Entering checkAnArmedTicketBlocksUntilItCommits().");
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
            'flushed, and waiting for it is what made a sequential client ' +
            'pay a commit round trip per request');

    pool.receiveCommitted(a, { wrote: true, tickets: [ticket] });
    t.check(await waitedFor(b) < 500,
            'and the worker’s commit announcement releases it',
            'still blocked: ' + JSON.stringify(pool.stats().tickets));
    t.equal(pool.stats().tickets.outstanding, 0,
            'with nothing left outstanding');
  });
  log.debug("Leaving checkAnArmedTicketBlocksUntilItCommits().");
}

// ---------------------------------------------------------------------------
// 2. THE DEFECT: A TICKET THE WORKER NEVER ANSWERED MUST NOT ARM.
//
// This is the regression. Before the fix the second assertion below was the
// state the service stayed in for ever.
// ---------------------------------------------------------------------------
async function checkAnUnansweredRequestReleasesItsTicket(t) {
  log.debug("Entering checkAnUnansweredRequestReleasesItsTicket().");
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
  log.debug("Leaving checkAnUnansweredRequestReleasesItsTicket().");
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
  log.debug("Entering checkAFreshTicketSurvivesItsFirstTimeout().");
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
  log.debug("Leaving checkAFreshTicketSurvivesItsFirstTimeout().");
}

// ---------------------------------------------------------------------------
// 4. WITH THE BARRIER OFF, NONE OF THIS HAPPENS AT ALL.
//
// `workers.readYourWrite` is off by default. A ticket taken there would be a
// cost paid by a deployment that said no — and, worse, one that nothing would
// ever clear, because the pool's own clearing path returns early too.
// ---------------------------------------------------------------------------
async function checkTheSwitchIsHonoured(t) {
  log.debug("Entering checkTheSwitchIsHonoured().");
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
  log.debug("Leaving checkTheSwitchIsHonoured().");
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
  log.debug("Entering checkAStuckTicketIsReaped().");
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
  log.debug("Leaving checkAStuckTicketIsReaped().");
}

// ---------------------------------------------------------------------------
// 6. A READER THAT TIMED OUT LEAVES THE LIST, AND A RELEASE DOES NOT WALK THE
//    REQUESTS IN FLIGHT ONCE PER WAITER (2026-09-13).
//
// The wedge behind `sts_directory_bulk_load_scim`'s `fetch failed` on the
// dispatch run of 2026-09-13. A waiter that gave up at the 2,000ms bound was
// resolved and LEFT in the list for as long as its tickets stayed armed, and
// every release walked each one against the whole outstanding set. Measured
// before the fix with this section's own numbers: one receiveCommitted() took
// 980ms of synchronous CPU, and a dispatched service receives several a second.
//
// Counts are asserted rather than a latency alone — `waiters` on stats() is
// the leak itself — and the latency bound beside them is fifty times the
// fixed cost, so a shared machine cannot make it flaky and the quadratic
// cannot hide under it.
// ---------------------------------------------------------------------------
async function checkTimedOutWaitersLeaveTheList(t) {
  log.debug("Entering checkTimedOutWaitersLeaveTheList().");
  t.log.info('=== a reader that timed out is not walked by every release ===');

  pool.reset();
  const a = worker(601);
  const b = worker(602);

  await withReadYourWrite(true, async function () {
    const armed = [];
    for (let i = 0; i < 6000; i += 1) {
      const ticket = pool.dispatchTicket(a);
      if (i < 300) {
        pool.ticketFinished(a, ticket);
        armed.push(ticket);
      }
    }
    const readers = [];
    for (let i = 0; i < 10000; i += 1) {
      readers.push(pool.awaitCommitConfirmations(b));
    }
    t.equal(pool.stats().tickets.waiters, 10000,
            'ten thousand readers are held behind 300 answered writes');

    await Promise.all(readers);
    t.equal(pool.stats().tickets.waiters, 0,
            'and once they have given up none of them is still held',
            'THE LEAK: a waiter that timed out stayed in the list for as ' +
            'long as its tickets were armed, and every release walked it ' +
            'again');

    const at = Date.now();
    pool.receiveCommitted(a, { wrote: true, tickets: [armed[299]] });
    const took = Date.now() - at;
    t.check(took < 100,
            'so a commit announcement costs what it did with nobody waiting',
            'took ' + took + 'ms; before the fix this was 980ms of blocked ' +
            'event loop per announcement');

    // AND THE LIVE CASE, which the leak was not needed for: readers still
    // inside their bound, spread over three workers, released by fifty
    // announcements. One walk of the finished set per worker per release.
    pool.reset();
    const ws = [worker(611), worker(612), worker(613)];
    const answered = [];
    for (let i = 0; i < 6000; i += 1) {
      const entry = ws[i % 3];
      const ticket = pool.dispatchTicket(entry);
      if (i < 900) {
        pool.ticketFinished(entry, ticket);
        answered.push([entry, ticket]);
      }
    }
    const live = [];
    for (let i = 0; i < 10000; i += 1) {
      live.push(pool.awaitCommitConfirmations(ws[i % 3]));
    }
    const started = Date.now();
    for (let k = 0; k < 50; k += 1) {
      pool.receiveCommitted(answered[k][0],
                            { wrote: true, tickets: [answered[k][1]] });
    }
    const fifty = Date.now() - started;
    t.check(fifty < 1000,
            'fifty announcements against ten thousand live readers stay cheap',
            'took ' + fifty + 'ms');
    await Promise.all(live);
    t.equal(pool.stats().tickets.waiters, 0,
            'and those readers leave the list too when they give up');
  });
  log.debug("Leaving checkTimedOutWaitersLeaveTheList().");
}

// A worker entry with a channel, for the sync rounds: `sent` is every message
// the pool handed the worker, which is the number this section is about.
function syncingWorker(pid) {
  log.debug("Entering syncingWorker().");
  const entry = worker(pid);
  entry.generation = 0;
  entry.sent = [];
  entry.child = {
    send: function (message) {
      log.debug("Entering send().");
      entry.sent.push(message);
      log.debug("Leaving send().");
    }
  };
  log.debug("Leaving syncingWorker().");
  return entry;
}

// ---------------------------------------------------------------------------
// 7. ONE SYNC ROUND PER WORKER, SHARED BY THE READERS IT COVERS (2026-09-13).
//
// Every reader used to send its own sync, and each is a database round trip in
// the worker. The same run held 5,759 outstanding at one worker. What may be
// shared is decided by the generation: a reader wanting no more than the
// running round asked for takes its answer; a reader wanting more waits for
// ONE queued round, which asks for the highest generation wanted meanwhile.
// ---------------------------------------------------------------------------
async function checkSyncRoundsAreShared(t) {
  log.debug("Entering checkSyncRoundsAreShared().");
  t.log.info('=== readers behind one worker share one sync round ===');

  pool.reset();
  const w = syncingWorker(701);

  const covered = [];
  for (let i = 0; i < 1000; i += 1) {
    covered.push(pool.barrier(w, 5));
  }
  t.equal(w.sent.length, 1,
          'a thousand readers wanting generation 5 send ONE sync',
          'sent ' + w.sent.length);

  const later = [];
  for (let i = 0; i < 500; i += 1) {
    later.push(pool.barrier(w, 6 + (i % 3)));
  }
  t.equal(w.sent.length, 1,
          'readers wanting more queue behind it rather than sending their own',
          'sent ' + w.sent.length);

  pool.receiveSync(w, { sync: true, id: w.sent[0].id, ok: true });
  const first = await Promise.all(covered);
  t.check(first.every(Boolean),
          'the answer releases every reader the round covered', '');
  t.equal(w.generation, 5,
          'and stamps the generation the round was ASKED for');

  await new Promise(function (resolve) { setImmediate(resolve); });
  t.equal(w.sent.length, 2,
          'then exactly one more round is sent for the readers behind it',
          'sent ' + w.sent.length);
  pool.receiveSync(w, { sync: true, id: w.sent[1].id, ok: true });
  const second = await Promise.all(later);
  t.check(second.every(Boolean), 'which releases all of them', '');
  t.equal(w.generation, 8,
          'at the highest generation any of them wanted',
          'a reader wanting 8 must not be released by a round asked for 6');

  t.check(await pool.barrier(w, 8) === true && w.sent.length === 2,
          'and a reader the worker is already current for sends nothing', '');

  // A ROUND THAT SETTLES LATE MUST NOT MOVE THE GENERATION BACKWARDS.
  const old = pool.barrier(w, 9);
  const oldId = w.sent[w.sent.length - 1].id;
  w.generation = 12;
  pool.receiveSync(w, { sync: true, id: oldId, ok: true });
  await old;
  t.equal(w.generation, 12,
          'a round asked for 9 that answers after 12 leaves the worker at 12');
  pool.reset();
  log.debug("Leaving checkSyncRoundsAreShared().");
}

// ---------------------------------------------------------------------------
// 8. A CLIENT THAT GIVES UP RELEASES ITS PLACE (2026-09-13).
//
// `aborted` is emitted only for a request whose body was cut short. A client
// that sent everything and then stopped waiting — a loopback SSF push at its
// `ssf.pushTimeoutMs` — emits only `close` on the response, and proxy() did
// not listen for it: the request stayed queued behind `workers.maxSockets`,
// counted in `inFlight`, and was delivered to a worker minutes later.
//
// Real sockets and no mock of http: an express app in front, a unix socket
// behind that never answers, and an agent with room for ONE connection, so the
// second request is the one queued.
// ---------------------------------------------------------------------------
async function checkAClientThatLeavesReleasesItsPlace(t) {
  log.debug("Entering checkAClientThatLeavesReleasesItsPlace().");
  t.log.info('=== a client that gives up releases its queued request ===');

  const http = require('http');
  const os = require('os');
  const path = require('path');
  const fs = require('fs');
  const express = require('express');

  pool.reset();
  const socketPath = path.join(os.tmpdir(), 'sts-barrier-' + process.pid +
                               '-' + Date.now() + '.sock');
  const arrived = [];
  const upstreamServer = http.createServer(function (req) {
    // Never answers. Records what arrived and when it was let go.
    const one = { url: req.url, closed: false };
    arrived.push(one);
    req.resume();
    req.on('close', function () {
      one.closed = true;
    });
  });
  await new Promise(function (resolve) {
    upstreamServer.listen(socketPath, resolve);
  });
  const entry = { pid: 801, socket: socketPath, tickets: new Set(),
                  agent: new http.Agent({ keepAlive: false, maxSockets: 1 }),
                  inFlight: 0, served: 0, generation: 0 };

  await withReadYourWrite(true, async function () {
    const app = express();
    const tickets = {};
    app.use(function (req, res) {
      const ticket = pool.dispatchTicket(entry);
      tickets[req.url] = ticket;
      pool.proxy(entry, req, res, 0, ticket);
    });
    const front = http.createServer(app);
    await new Promise(function (resolve) {
      front.listen(0, '127.0.0.1', resolve);
    });
    const port = front.address().port;

    function send(url) {
      log.debug("Entering send().");
      const req = http.request({ host: '127.0.0.1', port: port, path: url,
                                 method: 'POST',
                                 headers: { 'Content-Type': 'text/plain' } });
      req.on('error', function (e) {
        log.debug("Caught in send(): " + ((e && e.message) || e));
      });
      req.end('body');
      log.debug("Leaving send().");
      return req;
    }
    const sleep = function (ms) {
      log.debug("Entering sleep().");
      log.debug("Leaving sleep().");
      return new Promise(function (resolve) { setTimeout(resolve, ms); });
    };

    const first = send('/scim/v2/Users?first');
    await sleep(150);
    const second = send('/scim/v2/Users?second');
    await sleep(150);
    t.equal(entry.inFlight, 2, 'two requests are in flight');
    t.equal(arrived.length, 1,
            'and the second is queued behind the one-connection agent');

    second.destroy();
    await sleep(150);
    t.equal(entry.inFlight, 1,
            'the queued request whose client left is no longer in flight',
            'before the fix it stayed counted, steering leastLoaded() away ' +
            'from a worker for work nobody wanted');
    t.equal(pool.stats().tickets.outstanding, 1,
            'and its ticket went back, leaving only the first request’s');
    t.equal(pool.stats().tickets.finished, 0,
            'rather than being armed — it was answered to nobody');

    first.destroy();
    await sleep(150);
    t.equal(entry.inFlight, 0,
            'the request a worker was holding is released too');
    t.check(arrived[0] && arrived[0].closed,
            'and the worker sees its connection end', '');
    await sleep(150);
    t.equal(arrived.length, 1,
            'the abandoned queued request is never delivered to the worker',
            'delivered: ' + JSON.stringify(arrived.map(function (one) {
              return one.url;
            })));
    t.equal(pool.stats().tickets.outstanding, 0,
            'and nothing is left outstanding');

    await new Promise(function (resolve) { front.close(resolve); });
  });
  entry.agent.destroy();
  await new Promise(function (resolve) { upstreamServer.close(resolve); });
  try {
    fs.unlinkSync(socketPath);
  } catch (e) {
    log.debug("Caught in checkAClientThatLeavesReleasesItsPlace(): " +
              ((e && e.message) || e));
  }
  log.debug("Leaving checkAClientThatLeavesReleasesItsPlace().");
}

// ---------------------------------------------------------------------------
// 9. A WORKER ANNOUNCING ITS OWN WRITE IS NOT MARKED CURRENT FOR ANOTHER'S
//    (2026-09-13).
//
// receiveCommitted() stamped the announcing worker with the new generation
// whatever it had been, which is right for its own write and wrong for every
// earlier write it was never synced for. The worker answering most writes —
// every `/admin-api` call carrying the run's one token lands on one — is the
// worker that announces most often, so its reads skipped the barrier most
// often. Found by the `sts_global_logout` investigation.
// ---------------------------------------------------------------------------
async function checkABehindWorkerStaysBehind(t) {
  log.debug("Entering checkABehindWorkerStaysBehind().");
  t.log.info('=== an announcement does not make a stale worker current ===');

  pool.reset();
  await withReadYourWrite(true, async function () {
    const a = syncingWorker(901);
    const b = syncingWorker(902);

    pool.receiveCommitted(a, { wrote: true, tickets: [] });
    t.equal(a.generation, 1,
            'a worker that was current and announces a write stays current');
    t.equal(b.generation, 0, 'and the other worker is now behind');

    pool.receiveCommitted(b, { wrote: true, tickets: [] });
    t.equal(pool.stats().generation, 2, 'the generation moves for its write');
    t.equal(b.generation, 0,
            'but the behind worker is NOT marked current by announcing it',
            'it holds its own write in memory and has never fetched the ' +
            'other worker’s');

    const read = pool.barrier(b, pool.stats().generation);
    t.equal(b.sent.length, 1,
            'so its next read goes through a barrier', 'sent ' +
            b.sent.length);
    pool.receiveSync(b, { sync: true, id: b.sent[0].id, ok: true });
    t.check(await read === true, 'which catches it up', '');
    t.equal(b.generation, 2, 'to the generation the read wanted');
  });
  pool.reset();
  log.debug("Leaving checkABehindWorkerStaysBehind().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkAnArmedTicketBlocksUntilItCommits(t);
  await checkAnUnansweredRequestReleasesItsTicket(t);
  await checkAFreshTicketSurvivesItsFirstTimeout(t);
  await checkAStuckTicketIsReaped(t);
  await checkTheSwitchIsHonoured(t);
  await checkTimedOutWaitersLeaveTheList(t);
  await checkSyncRoundsAreShared(t);
  await checkAClientThatLeavesReleasesItsPlace(t);
  await checkABehindWorkerStaysBehind(t);
  // THE POOL IS PROCESS-WIDE MODULE STATE AND THIS FILE ARMED TICKETS IN IT.
  // Left behind, they would make every later file's reader wait the bound.
  pool.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_barrier',
  describe: 'that a request no worker answered releases its read-barrier ' +
            'ticket, so a 502 cannot wedge every reader in the service for ' +
            'the life of the process',
  run: run
};
