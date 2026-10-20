// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_worker_replacement.js
//
// ===========================================================================
// A REQUEST WORKER THAT DIES IS REPLACED (2026-09-26).
//
// `common/request_pool.js` forked its workers once, in start(), and reap()
// never forked again: a worker that crashed, was OOM-killed or was sent a
// SIGKILL left the pool a worker short for the life of the process, and when
// the last one went every request was served on the front process's one
// thread. rcbj met it more than once. reap() now forks a replacement into the
// dead worker's pool and slot — not while the pool is stopping, not once it
// has given up, except during that give-up's cool-down try, and never past
// the configured size — and a worker that reports it could not start is ended
// so that it goes through the same path, bounded by QUICK_EXIT_LIMIT failed
// starts in a row. The give-up then waits workers.giveUpRetryMs and tries one
// worker; one that comes up refills the pool, and 0 stays given up (#333).
//
// The decision is asserted directly (section 1). The rest drives the REAL
// fork() and reap() with real worker THREADS (#364: a worker is a
// `worker_threads` Worker of the front process, and fork() still names the
// act), running a STUB worker this file writes to the temp directory: it
// answers the same channel — `begin` in, `ready` out, an HTTP server on the
// socket it is given — without loading the protocol stack, which is not what
// is being tested. A worker "killed" is a thread terminated: `kill()` is
// `terminate()` since #364, and a thread receives no signal.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const pool = require('../common/request_pool');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'request_worker_replacement',
  level: process.env.LOG_LEVEL || 'info' });

const PROTO = pool.PROTOCOL_POOL;
const SURFACES = pool.SURFACE_POOL;

// The stub, a WORKER THREAD since #364 as the real worker is. It speaks the
// thread's channel — `parentPort`, which is what WorkerChannel wraps — and
// answers its `threadId`, the id the pool names a worker by now that every
// thread has the process's pid. STUB_MODE=fail answers `ready: false`, as a
// worker whose state could not be brought up does; anything else listens and
// says ready, after STUB_DELAY_MS when that is set (a slow start, for the
// start gate). GET /die makes it exit on its own, as a crash does:
// `process.exit()` in a thread ends the thread and nothing else. `stop` is
// what a drain sends.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "const wt = require('worker_threads');",
  "wt.parentPort.on('message', function (m) {",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (!m || !m.begin) { return; }",
  "  if (process.env.STUB_MODE === 'fail') {",
  "    wt.parentPort.postMessage({ ready: false,",
  "                                error: 'the stub cannot start' });",
  "    return;",
  "  }",
  "  const server = http.createServer(function (req, res) {",
  "    if (req.url === '/die') { process.exit(3); }",
  "    res.end(String(wt.threadId));",
  "  });",
  "  const delay = Number(process.env.STUB_DELAY_MS) || 0;",
  "  setTimeout(function () {",
  "    server.listen(m.socket, function () {",
  "      wt.parentPort.postMessage({ ready: true });",
  "    });",
  "  }, delay);",
  "});",
  ""
].join('\n');

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// Polls `test` until it answers true or `ms` passes; answers the last value.
async function waitFor(test, ms) {
  log.debug("Entering waitFor().");
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (test()) {
      log.debug("Leaving waitFor(). Met.");
      return true;
    }
    await sleep(50);
  }
  log.debug("Leaving waitFor(). Timed out.");
  return !!test();
}

function ready(poolName) {
  log.debug("Entering ready().");
  log.debug("Leaving ready().");
  return pool.workerTable().filter(function (one) {
    return one.pool === poolName && one.ready;
  });
}

function statsOf(poolName) {
  log.debug("Entering statsOf().");
  log.debug("Leaving statsOf().");
  return pool.stats().pools.filter(function (one) {
    return one.pool === poolName;
  })[0];
}

// GET / on a worker's own socket answers its threadId, which is the pool's
// `pid` for it (#364).
function ask(entry, urlPath) {
  log.debug("Entering ask().");
  log.debug("Leaving ask().");
  return new Promise(function (resolve) {
    const req = http.request({ socketPath: entry.socket, path: urlPath || '/',
                               agent: false }, function (answer) {
      let text = '';
      answer.on('data', function (chunk) {
        text += chunk;
      });
      answer.on('end', function () {
        resolve(text);
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in ask(): " + ((e && e.message) || e));
      resolve('');
    });
    req.end();
  });
}

// Runs `fn` with the pool sized at `count` workers and forking the stub in
// `mode`, and leaves the pool stopped and reset whatever happens.
async function withStubPool(stubPath, count, mode, fn, extra) {
  log.debug("Entering withStubPool().");
  const had = { count: process.env.STS_WORKERS_REQUEST_COUNT,
                mode: process.env.STUB_MODE };
  // Further variables for this case alone (#342: the stub's delay and the
  // start gate's width), put back as they were below.
  const more = extra || {};
  const hadMore = {};
  Object.keys(more).forEach(function (name) {
    hadMore[name] = process.env[name];
    process.env[name] = more[name];
  });
  process.env.STS_WORKERS_REQUEST_COUNT = String(count);
  process.env.STUB_MODE = mode;
  pool.reset();
  pool.useWorkerModule(stubPath);
  try {
    await fn();
  } finally {
    await pool.stop(3000);
    pool.reset();
    if (had.count === undefined) {
      delete process.env.STS_WORKERS_REQUEST_COUNT;
    } else {
      process.env.STS_WORKERS_REQUEST_COUNT = had.count;
    }
    if (had.mode === undefined) {
      delete process.env.STUB_MODE;
    } else {
      process.env.STUB_MODE = had.mode;
    }
    Object.keys(hadMore).forEach(function (name) {
      if (hadMore[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = hadMore[name];
      }
    });
  }
  log.debug("Leaving withStubPool().");
}

// ---------------------------------------------------------------------------
// 1. THE DECISION.
// ---------------------------------------------------------------------------
function checkTheDecision(t) {
  log.debug("Entering checkTheDecision().");
  t.log.info('=== which dead worker is replaced, and into which slot ===');
  const dead = { pid: 1, pool: PROTO, slot: 1 };
  const a = { pid: 2, pool: PROTO, slot: 0 };
  const b = { pid: 3, pool: PROTO, slot: 2 };
  const s = { pid: 4, pool: SURFACES, slot: 0 };

  let plan = pool.replacementFor(dead, [a, dead, b, s],
    { stopped: false, givenUp: false, wanted: 3 });
  t.check(plan.replace && plan.pool === PROTO && plan.slot === 1,
          'a dead worker in a pool short of its size is replaced into ITS ' +
          'slot', JSON.stringify(plan));

  plan = pool.replacementFor(dead, [a, dead, b],
    { stopped: true, givenUp: false, wanted: 3 });
  t.check(!plan.replace, 'nothing is forked while the pool is stopping',
          JSON.stringify(plan));

  plan = pool.replacementFor(dead, [a, dead, b],
    { stopped: false, givenUp: true, wanted: 3 });
  t.check(!plan.replace, 'nor once the pool has given up on its workers',
          JSON.stringify(plan));

  plan = pool.replacementFor(dead, [a, dead, b],
    { stopped: false, givenUp: true, probing: true, wanted: 3 });
  t.check(plan.replace && plan.pool === PROTO && plan.slot === 1,
          'a cool-down try may replace a worker while the pool is still ' +
          'given up', JSON.stringify(plan));

  plan = pool.replacementFor(dead, [a, dead, b],
    { stopped: false, givenUp: false, wanted: 2 });
  t.check(!plan.replace,
          'nor past the configured size, counting only the living',
          JSON.stringify(plan));

  plan = pool.replacementFor({ pid: 5, pool: PROTO, slot: null }, [a, b],
    { stopped: false, givenUp: false, wanted: 3 });
  t.check(plan.replace && plan.slot === 1,
          'a worker with no slot is given the first free one',
          JSON.stringify(plan));

  plan = pool.replacementFor({ pid: 6, pool: SURFACES, slot: 0 }, [a, b, s],
    { stopped: false, givenUp: false, wanted: 1 });
  t.check(!plan.replace,
          'the surface pool is sized on its own, and a slot another living ' +
          'worker holds is not handed out twice', JSON.stringify(plan));
  log.debug("Leaving checkTheDecision().");
}

// The cool-down's wait, as a decision: the setting, doubled, capped at an
// hour, and 0 meaning it does not try again.
function checkGiveUpRetryDelay(t) {
  log.debug("Entering checkGiveUpRetryDelay().");
  t.log.info('=== the give-up cool-down doubles, and 0 does not retry ===');
  t.equal(pool.giveUpRetryDelay(0, 300000), 300000,
          'the first wait is workers.giveUpRetryMs itself');
  t.equal(pool.giveUpRetryDelay(1, 300000), 600000,
          'the next wait is twice that');
  t.equal(pool.giveUpRetryDelay(2, 300000), 1200000, 'and twice again');
  t.equal(pool.giveUpRetryDelay(3, 300000), 2400000, 'and once more');
  t.equal(pool.giveUpRetryDelay(4, 300000), 3600000,
          'then an hour, which 16 times five minutes would pass');
  t.equal(pool.giveUpRetryDelay(6, 300000), 3600000,
          'and the hour is the ceiling after that too');
  t.equal(pool.giveUpRetryDelay(0, 0), 0,
          '0 does not retry, on the first wait');
  t.equal(pool.giveUpRetryDelay(3, 0), 0, 'nor on a later one');
  log.debug("Leaving checkGiveUpRetryDelay().");
}

// ---------------------------------------------------------------------------
// 2. A WORKER KILLED, AND A WORKER THAT EXITS ON ITS OWN, ARE REPLACED.
// ---------------------------------------------------------------------------
async function checkADeadWorkerIsReplaced(t, stubPath) {
  log.debug("Entering checkADeadWorkerIsReplaced().");
  t.log.info('=== a worker that dies is replaced in its slot ===');
  await withStubPool(stubPath, 2, 'ok', async function () {
    pool.fork(PROTO, 0);
    pool.fork(PROTO, 1);
    t.check(await waitFor(function () { return ready(PROTO).length === 2; },
                          10000), 'two stub workers come up', '');
    const first = ready(PROTO).filter(function (one) {
      return one.slot === 0;
    })[0];

    t.equal(await ask(first), String(first.pid),
            'a worker is named by its threadId: the stub answers the id the ' +
            'pool holds for it');
    first.child.kill();
    t.check(await waitFor(function () {
      const now = ready(PROTO);
      return now.length === 2 && now.every(function (one) {
        return one.pid !== first.pid;
      });
    }, 10000), 'a terminated worker thread is replaced, and the pool is ' +
    'back to two',
    JSON.stringify(ready(PROTO).map(function (one) { return one.pid; })));
    const replacement = ready(PROTO).filter(function (one) {
      return one.slot === 0;
    })[0];
    t.check(!!replacement && replacement.pid !== first.pid,
            'in the dead worker\'s slot', '');
    t.equal(await ask(replacement), String(replacement.pid),
            'and it answers on its own socket');
    t.equal(statsOf(PROTO).replaced, 1, 'stats() counts one replacement');

    const second = ready(PROTO).filter(function (one) {
      return one.slot === 1;
    })[0];
    await ask(second, '/die');
    t.check(await waitFor(function () {
      const now = ready(PROTO);
      return now.length === 2 && now.every(function (one) {
        return one.pid !== second.pid;
      });
    }, 10000), 'a worker that exits on its own is replaced too', '');
    t.equal(statsOf(PROTO).replaced, 2, 'two replacements counted');
    t.equal(pool.workerTable().length, 2,
            'and the table holds exactly the configured two');
  });
  log.debug("Leaving checkADeadWorkerIsReplaced().");
}

// ---------------------------------------------------------------------------
// 3. A DRAIN REPLACES NOTHING.
// ---------------------------------------------------------------------------
async function checkStoppingReplacesNothing(t, stubPath) {
  log.debug("Entering checkStoppingReplacesNothing().");
  t.log.info('=== stop() drains without forking replacements ===');
  await withStubPool(stubPath, 1, 'ok', async function () {
    pool.fork(PROTO, 0);
    t.check(await waitFor(function () { return ready(PROTO).length === 1; },
                          10000), 'one stub worker comes up', '');
    const one = ready(PROTO)[0];
    await pool.stop(3000);
    await sleep(500);
    t.equal(pool.workerTable().length, 0,
            'after stop() no worker is left and none was forked');
    t.check(one.child.exitCode === 0 && one.child.signalCode === null,
            'and the worker thread it drained has exited on its own, with ' +
            'code 0 and no signal (a thread receives none)',
            JSON.stringify({ exitCode: one.child.exitCode,
                             signalCode: one.child.signalCode }));
  });
  log.debug("Leaving checkStoppingReplacesNothing().");
}

// ---------------------------------------------------------------------------
// 4. A WORKER THAT CANNOT START IS ENDED AND REPLACED — AND AFTER
//    QUICK_EXIT_LIMIT IN A ROW THE POOL GIVES UP RATHER THAN FORK FOR EVER.
// ---------------------------------------------------------------------------
async function checkAFailedStartIsBounded(t, stubPath) {
  log.debug("Entering checkAFailedStartIsBounded().");
  t.log.info('=== a worker that cannot start is retried, and then given ' +
             'up on ===');
  await withStubPool(stubPath, 1, 'fail', async function () {
    const pids = [];
    pids.push(pool.fork(PROTO, 0).pid);
    t.check(await waitFor(function () { return statsOf(PROTO).gaveUp; },
                          15000),
            'the pool gives up on a worker that can never start', '');
    await sleep(500);
    t.equal(statsOf(PROTO).replaced, 2,
            'after the first fork and two replacements — three failed ' +
            'starts in a row');
    t.equal(pool.workerTable().length, 0,
            'and nothing is left running or being forked');
    t.equal(statsOf(PROTO).giveUpRetryMs, 0,
            'workers.giveUpRetryMs 0 arms no cool-down');
    t.equal(statsOf(PROTO).giveUpAttempt, 0,
            'and no attempt is counted');
    t.check(pids[0] && pool.workerTable().every(function (one) {
      return one.pid !== pids[0];
    }), 'the worker that said it could not start was ended rather than ' +
        'left holding its place', '');
  }, { STS_WORKERS_GIVE_UP_RETRY_MS: '0' });
  log.debug("Leaving checkAFailedStartIsBounded().");
}

// ---------------------------------------------------------------------------
// A GIVE-UP IS NOT FOR THE LIFE OF THE PROCESS (#333). One worker is tried
// after the cool-down, and routing stays given up until it is ready. A try
// that also fails waits twice as long.
// ---------------------------------------------------------------------------
async function checkAPoolRetriesAfterGivingUp(t, stubPath) {
  log.debug("Entering checkAPoolRetriesAfterGivingUp().");
  t.log.info('=== a pool that gave up tries one worker after the ' +
             'cool-down and refills ===');
  await withStubPool(stubPath, 2, 'fail', async function () {
    pool.fork(PROTO, 0);
    t.check(await waitFor(function () {
      return statsOf(PROTO).gaveUp;
    }, 15000), 'the pool gives up', '');
    // THE NEXT FORK COPIES THE ENVIRONMENT. The workers that failed already
    // hold `fail`; the one the cool-down forks reads this.
    process.env.STUB_MODE = 'ok';
    const waiting = statsOf(PROTO);
    t.equal(pool.workerTable().length, 0, 'nothing is left running');
    t.check(waiting.giveUpRetryMs > 0 && waiting.giveUpRetryMs <= 500,
            'the cool-down is the setting, and short enough to wait for',
            String(waiting.giveUpRetryMs));
    t.equal(waiting.giveUpProbing, false,
            'routing stays given up while the cool-down runs');
    t.check(await waitFor(function () {
      return ready(PROTO).length === 2 && !statsOf(PROTO).gaveUp;
    }, 10000), 'one worker coming up clears the give-up and the pool ' +
               'refills',
               JSON.stringify({ ready: ready(PROTO).length,
                                gaveUp: statsOf(PROTO).gaveUp }));
    t.equal(statsOf(PROTO).giveUpAttempt, 0,
            'a worker that comes up clears the backoff');
  }, { STS_WORKERS_GIVE_UP_RETRY_MS: '400' });

  t.log.info('=== a cool-down whose try also fails waits longer ===');
  await withStubPool(stubPath, 1, 'fail', async function () {
    pool.fork(PROTO, 0);
    t.check(await waitFor(function () {
      return statsOf(PROTO).giveUpAttempt === 1;
    }, 10000), 'a try that fails arms the doubled wait',
               JSON.stringify(statsOf(PROTO)));
    const again = statsOf(PROTO);
    t.check(again.gaveUp && again.giveUpRetryMs > 450 &&
            again.giveUpRetryMs <= 650,
            'the second wait is about twice the 300ms setting',
            String(again.giveUpRetryMs));
    t.equal(pool.workerTable().length, 0,
            'and the pool is not forking while it waits');
  }, { STS_WORKERS_GIVE_UP_RETRY_MS: '300' });
  log.debug("Leaving checkAPoolRetriesAfterGivingUp().");
}

// ---------------------------------------------------------------------------
// 5. WORKERS START ONE AT A TIME (#342), and replacements wait their turn.
//
// Each stub takes STUB_DELAY_MS to say it is ready. With the gate at 1 no
// worker may be forked before the one ahead of it has settled; at 2, two may
// be starting and never three. `stats().starts.starting` is sampled every few
// milliseconds for the peak, and each fork's own `startedAt` is compared with
// the moment the one ahead of it settled.
// ---------------------------------------------------------------------------
async function forkThroughTheGate(count) {
  log.debug("Entering forkThroughTheGate().");
  let peak = 0;
  const sampler = setInterval(function () {
    peak = Math.max(peak, pool.stats().starts.starting);
  }, 5);
  const settledAt = [];
  const entries = [];
  const all = [];
  for (let i = 0; i < count; i++) {
    all.push(pool.queueFork(PROTO, i).then(function (entry) {
      settledAt[i] = Date.now();
      entries[i] = entry;
      return entry;
    }));
  }
  const queuedNow = pool.stats().starts.queued;
  await Promise.all(all);
  clearInterval(sampler);
  log.debug("Leaving forkThroughTheGate().");
  return { peak: peak, settledAt: settledAt, entries: entries,
           queuedNow: queuedNow };
}

async function checkWorkersStartOneAtATime(t, stubPath) {
  log.debug("Entering checkWorkersStartOneAtATime().");
  t.log.info('=== workers are forked one at a time (#342) ===');

  const order = pool.startOrder([{ pool: PROTO, slot: 0 },
                                 { pool: PROTO, slot: 1 },
                                 { pool: PROTO, slot: 2 },
                                 { pool: SURFACES, slot: 0 },
                                 { pool: SURFACES, slot: 1 }]);
  t.equal(order.map(function (one) {
    return one.pool[0] + one.slot;
  }).join(','), 'p0,s0,p1,s1,p2',
  'the initial workers are queued interleaved, so that each pool has its ' +
  'first worker as early as possible');

  await withStubPool(stubPath, 3, 'ok', async function () {
    t.equal(pool.stats().starts.concurrency, 1,
            'workers.startConcurrency 1 is a gate one wide');
    const got = await forkThroughTheGate(3);
    t.equal(got.queuedNow, 2,
            'queued three: one is forked at once and two wait behind it');
    t.equal(got.peak, 1, 'never more than one worker starting at a time');
    t.check(got.entries.every(Boolean), 'all three came up', '');
    // THE FORK TIMES, NOT THE SETTLE TIMES THIS FILE SAW: the gate forks
    // the next worker in the same callback that settles the one ahead, a
    // microtask before this file's own `then` runs, so a settle time
    // recorded here is a millisecond late. Each stub takes 300ms to say it
    // is ready, so a serial gate puts at least that between two forks.
    let serial = true;
    for (let i = 1; i < 3; i++) {
      if (!(got.entries[i].startedAt - got.entries[i - 1].startedAt >= 290)) {
        serial = false;
      }
    }
    t.check(serial, 'each worker was forked only after the one ahead of it ' +
            'reported ready', JSON.stringify({
      startedAt: got.entries.map(function (one) { return one.startedAt; }),
      settledAt: got.settledAt }));

    // TWO DEATHS AT ONCE, as two threads out of heap at once would be: the
    // replacements go through the same gate rather than starting together.
    const before = pool.stats().pools[0].replaced;
    let peak = 0;
    const sampler = setInterval(function () {
      peak = Math.max(peak, pool.stats().starts.starting);
    }, 5);
    const doomed = ready(PROTO).slice(0, 2);
    doomed.forEach(function (one) {
      one.child.kill();
    });
    const back = await waitFor(function () {
      const now = ready(PROTO);
      return now.length === 3 && now.every(function (one) {
        return doomed.indexOf(one) < 0;
      });
    }, 15000);
    clearInterval(sampler);
    t.check(back, 'both terminated workers are replaced', '');
    t.equal(pool.stats().pools[0].replaced - before, 2,
            'two replacements, not more');
    t.equal(peak, 1, 'and they started one at a time too');
    t.equal(pool.workerTable().length, 3,
            'the table holds exactly the configured three');
  }, { STUB_DELAY_MS: '300', STS_WORKERS_START_CONCURRENCY: '1' });

  await withStubPool(stubPath, 4, 'ok', async function () {
    const got = await forkThroughTheGate(4);
    t.equal(pool.stats().starts.concurrency, 2,
            'workers.startConcurrency is read from the setting');
    t.equal(got.peak, 2, 'at 2, two workers start together and never three');
  }, { STUB_DELAY_MS: '300', STS_WORKERS_START_CONCURRENCY: '2' });

  await withStubPool(stubPath, 3, 'ok', async function () {
    pool.queueFork(PROTO, 0);
    const second = pool.queueFork(PROTO, 1);
    const third = pool.queueFork(PROTO, 2);
    await pool.stop(3000);
    t.equal(await second, null, 'stop() drops a queued fork');
    t.equal(await third, null, 'every one of them');
    await sleep(500);
    t.equal(pool.workerTable().length, 0, 'and nothing is left running');
  }, { STUB_DELAY_MS: '300' });
  log.debug("Leaving checkWorkersStartOneAtATime().");
}

// ---------------------------------------------------------------------------
// AS MANY AT ONCE AS THE NODE'S MEMORY HOLDS (#639): the default,
// `workers.startConcurrency` 0. The width as a decision over its inputs,
// then the gate with stubs: the first alone and measured, the rest together
// (a stub's start costs next to nothing, so the floor prices it, and the
// machine running this has room for more than three of those).
// ---------------------------------------------------------------------------
async function checkWorkersStartAsMemoryAllows(t, stubPath) {
  log.debug("Entering checkWorkersStartAsMemoryAllows().");
  t.log.info('=== workers start as many at once as memory holds (#639) ===');
  const MiB = 1024 * 1024;
  const width = pool.startWidthFor;
  t.equal(width({ perStartBytes: 400 * MiB, limitBytes: 0, rssBytes: 0,
                  availableBytes: 40 * 1024 * MiB }), 58,
          'with no limit: the available memory less 15%, at one and a half ' +
          'measured starts each (40 GiB, 400 MiB a start: 58)');
  t.equal(width({ perStartBytes: 400 * MiB, limitBytes: 4096 * MiB,
                  rssBytes: 1400 * MiB, availableBytes: 40 * 1024 * MiB }),
          3, 'with a 4 GiB limit and 1.4 GiB held: (4096 - 1400 - 614) / ' +
          '600 = 3, whatever the host has');
  t.equal(width({ perStartBytes: 400 * MiB, limitBytes: 2048 * MiB,
                  rssBytes: 1900 * MiB, availableBytes: 0 }), 1,
          'never fewer than one, when the room is gone');
  t.equal(width({ perStartBytes: 1, limitBytes: 0, rssBytes: 0,
                  availableBytes: 1024 * 1024 * MiB }), 64,
          'never more than 64, and a start is priced at 128 MiB at least');

  await withStubPool(stubPath, 4, 'ok', async function () {
    t.check(pool.stats().starts.automatic === true &&
            pool.stats().starts.concurrency === 1,
            'the default is the automatic width, one until a start is ' +
            'measured', JSON.stringify(pool.stats().starts));
    const got = await forkThroughTheGate(4);
    t.check(got.entries.every(Boolean), 'all four came up', '');
    t.check(got.entries[1].startedAt - got.entries[0].startedAt >= 290,
            'the first started alone, and was measured',
            JSON.stringify(got.entries.map(function (one) {
              return one.startedAt;
            })));
    const starts = pool.stats().starts;
    t.check(starts.measuredStartMb >= 128 && starts.concurrency >= 3,
            'its start priced (at least the floor) and the gate widened to ' +
            'what the memory holds', JSON.stringify(starts));
    t.check(got.peak >= 2 && got.peak <= 3,
            'and the other three started together', String(got.peak));
    t.check(got.entries[3].startedAt - got.entries[1].startedAt < 200,
            'forked within one stub\'s start of each other',
            JSON.stringify(got.entries.map(function (one) {
              return one.startedAt;
            })));
  }, { STUB_DELAY_MS: '300' });
  log.debug("Leaving checkWorkersStartAsMemoryAllows().");
}

async function run(t) {
  log.debug("Entering run().");
  checkTheDecision(t);
  checkGiveUpRetryDelay(t);
  const stubPath = path.join(os.tmpdir(), 'sts-stub-worker-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, STUB);
  try {
    await checkADeadWorkerIsReplaced(t, stubPath);
    await checkStoppingReplacesNothing(t, stubPath);
    await checkAFailedStartIsBounded(t, stubPath);
    await checkAPoolRetriesAfterGivingUp(t, stubPath);
    await checkWorkersStartOneAtATime(t, stubPath);
    await checkWorkersStartAsMemoryAllows(t, stubPath);
  } finally {
    try {
      fs.unlinkSync(stubPath);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    pool.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_worker_replacement',
  describe: 'that a request worker thread which dies is replaced in its ' +
            'pool and slot, not while stopping, not past the configured ' +
            'size, and a worker that cannot start is ended and retried a ' +
            'bounded number of times before a cool-down tries one again ' +
            '(#333), and that workers are started one at a time (#342)',
  run: run
};
