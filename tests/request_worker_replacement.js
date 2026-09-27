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
// has given up, never past the configured size — and a worker that reports it
// could not start is ended so that it goes through the same path, bounded by
// QUICK_EXIT_LIMIT failed starts in a row.
//
// The decision is asserted directly (section 1). The rest drives the REAL
// fork() and reap() with real child processes, running a STUB worker this
// file writes to the temp directory: it answers the same channel — `begin`
// in, `ready` out, an HTTP server on the socket it is given — without loading
// the protocol stack, which is not what is being tested.
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

// The stub. STUB_MODE=fail answers `ready: false`, as a worker whose state
// could not be brought up does; anything else listens and says ready. GET
// /die makes it exit on its own, as a crash does.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "process.on('message', function (m) {",
  "  if (!m || !m.begin) { return; }",
  "  if (process.env.STUB_MODE === 'fail') {",
  "    process.send({ ready: false, error: 'the stub cannot start' });",
  "    return;",
  "  }",
  "  const server = http.createServer(function (req, res) {",
  "    if (req.url === '/die') { process.exit(3); }",
  "    res.end(String(process.pid));",
  "  });",
  "  server.listen(m.socket, function () { process.send({ ready: true }); });",
  "});",
  "process.on('disconnect', function () { process.exit(0); });",
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

// GET / on a worker's own socket answers its pid.
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
async function withStubPool(stubPath, count, mode, fn) {
  log.debug("Entering withStubPool().");
  const had = { count: process.env.STS_WORKERS_REQUEST_COUNT,
                mode: process.env.STUB_MODE };
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

    first.child.kill('SIGKILL');
    t.check(await waitFor(function () {
      const now = ready(PROTO);
      return now.length === 2 && now.every(function (one) {
        return one.pid !== first.pid;
      });
    }, 10000), 'a SIGKILLed worker is replaced, and the pool is back to two',
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
    t.check(one.child.exitCode !== null || one.child.signalCode !== null,
            'and the worker it drained has exited', '');
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
    t.check(pids[0] && pool.workerTable().every(function (one) {
      return one.pid !== pids[0];
    }), 'the worker that said it could not start was ended rather than ' +
        'left holding its place', '');
  });
  log.debug("Leaving checkAFailedStartIsBounded().");
}

async function run(t) {
  log.debug("Entering run().");
  checkTheDecision(t);
  const stubPath = path.join(os.tmpdir(), 'sts-stub-worker-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, STUB);
  try {
    await checkADeadWorkerIsReplaced(t, stubPath);
    await checkStoppingReplacesNothing(t, stubPath);
    await checkAFailedStartIsBounded(t, stubPath);
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
  describe: 'that a request worker which dies is replaced in its pool and ' +
            'slot, not while stopping, not past the configured size, and a ' +
            'worker that cannot start is ended and retried a bounded number ' +
            'of times',
  run: run
};
