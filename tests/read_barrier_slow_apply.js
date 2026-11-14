// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: read_barrier_slow_apply.js
//
// ===========================================================================
// A READ BARRIER BEHIND A SLOW APPLY IS WAITED OUT OR REFUSED, AND NEVER
// ANSWERED STALE (2026-11-14).
//
// GitHub Actions run 43622250478, single-node, a runner slower than the
// laptop: one request worker spent 7 to 22 s applying a global logout's
// 8,000 minted rows, and in those two minutes two protocol jobs were answered
// WRONGLY — `sts_realm_administrators` a 404 for a realm created a moment
// before, `sts_scope_policy` a SCIM 403 for a scope declared a moment before.
// The service log had fifteen STS-WORKER-0027 / STS-STORE-0039 pairs, each
// saying "the request is being served from what that worker has".
//
// Two paths served stale, and this file holds both shut:
//
//   1. **THE ROUND THAT SAID IT WAS STILL BEHIND.** The worker answers a sync
//      round with `persistence.syncNow()`'s result, which gives up at its own
//      4,600 ms deadline with `caughtUp: false` — and the front read only
//      `ok`, so it STAMPED the worker current and proxied the request to a
//      copy that did not yet hold the write. No warning at all.
//   2. **THE ROUND THAT NEVER CAME BACK.** A worker whose event loop is
//      blocked cannot answer; at 5,000 ms the front gave up and proxied
//      anyway.
//
// Now a reader asks round after round for up to `workers.readBarrierTimeoutMs`
// and is then refused with a 503 (STS-WORKER-0053).
//
// WHY IN PROCESS, AND WITH WHAT IS REAL. The replication instance is the real
// `persistence_replication.js` over a stub change log, with an applier whose
// `prepare` is slower than syncNow()'s deadline — the shape of the CI pull,
// whose time went outside the per-kind row timings. The "worker" is the real
// `request_pool.proxy()` speaking HTTP over a unix socket to a server that
// answers from the copy the applier writes, and its sync channel does what
// `request_worker.ts`'s handleSync() does: syncNow(), then the answer. So the
// thing asserted is the answer a client would read, not a flag.
// ===========================================================================

delete process.env.CONFIG_FILE;

const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');

const pool = require('../common/request_pool');
const replication = require('../persistence/persistence_replication');

const log = require('bunyan').createLogger({ name: 'read_barrier_slow_apply',
  level: process.env.LOG_LEVEL || 'info' });

const sleep = function (ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
};

// The environment for the length of `fn`, AWAITED — tests/request_barrier.js'
// withReadYourWrite() says what restoring before the first await costs.
async function withEnv(vars, fn) {
  log.debug("Entering withEnv().");
  const had = {};
  Object.keys(vars).forEach(function (k) {
    had[k] = process.env[k];
    process.env[k] = vars[k];
  });
  try {
    log.debug("Leaving withEnv().");
    return await fn();
  } finally {
    Object.keys(vars).forEach(function (k) {
      if (had[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = had[k];
      }
    });
  }
}

// A change log and nothing else, tests/replication.js' fakeDriver().
function fakeDriver(me) {
  log.debug("Entering fakeDriver().");
  const rows = [];
  let seq = 0;
  log.debug("Leaving fakeDriver().");
  return {
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return me;
    },
    write: function (origin, kind, key) {
      log.debug("Entering write().");
      seq++;
      rows.push({ seq: seq, origin: origin, kind: kind, realm: '', key: key });
      log.debug("Leaving write().");
      return seq;
    },
    latestChangeSeq: function () {
      log.debug("Entering latestChangeSeq().");
      log.debug("Leaving latestChangeSeq().");
      return Promise.resolve(seq);
    },
    changesSince: function (after, limit) {
      log.debug("Entering changesSince().");
      log.debug("Leaving changesSince().");
      return Promise.resolve(rows.filter(function (row) {
        return row.seq > after;
      }).slice(0, limit));
    },
    changeCeiling: function () {
      log.debug("Entering changeCeiling().");
      log.debug("Leaving changeCeiling().");
      return Promise.resolve(seq);
    }
  };
}

// A worker: an HTTP server on a unix socket answering what its COPY holds,
// and a sync channel that answers as request_worker.ts's handleSync() does —
// unless `answers` is false, which is a worker whose loop is blocked.
async function startWorker(pid, copy, answers) {
  log.debug("Entering startWorker().");
  const socketPath = path.join(os.tmpdir(), 'sts-slow-apply-' + process.pid +
                               '-' + pid + '-' + Date.now() + '.sock');
  const served = [];
  const server = http.createServer(function (req, res) {
    served.push(req.url);
    req.resume();
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ value: copy.get('cn=app') || null }));
  });
  await new Promise(function (resolve) {
    server.listen(socketPath, resolve);
  });
  const entry = { pid: pid, socket: socketPath, tickets: new Set(),
                  agent: new http.Agent({ keepAlive: false, maxSockets: 4 }),
                  inFlight: 0, served: 0, generation: 0, syncs: 0 };
  entry.child = {
    send: function (message) {
      log.debug("Entering send().");
      if (message && message.sync) {
        entry.syncs += 1;
        if (answers) {
          replication.syncNow().then(function (state) {
            pool.receiveSync(entry, { sync: true, id: message.id, ok: true,
                                      applied: state.applied,
                                      caughtUp: state.caughtUp,
                                      coordinating: state.coordinating });
          });
        }
      }
      log.debug("Leaving send().");
    }
  };
  log.debug("Leaving startWorker().");
  return {
    entry: entry, served: served,
    stop: async function () {
      entry.agent.destroy();
      await new Promise(function (resolve) { server.close(resolve); });
      try {
        fs.unlinkSync(socketPath);
      } catch (e) {
        log.debug("Caught in stop(): " + ((e && e.message) || e));
      }
    }
  };
}

// A front process: every request takes a ticket and goes through the
// barrier for generation `wanted`, as the middleware's waitThenProxy() does.
async function startFront(entry, wanted) {
  log.debug("Entering startFront().");
  const express = require('express');
  const app = express();
  app.use(function (req, res) {
    const ticket = pool.dispatchTicket(entry, 'GET ' + req.url);
    const timing = { arrived: Date.now(), ticketDone: Date.now(),
                     barrierDone: 0 };
    pool.proxyAfterBarrier(entry, req, res, wanted, ticket, timing);
  });
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  log.debug("Leaving startFront().");
  return server;
}

// One GET, answered as `{ status, retryAfter, body }`.
function get(port, url) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return new Promise(function (resolve, reject) {
    const req = http.get({ host: '127.0.0.1', port: port, path: url },
      function (res) {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', function (chunk) { body += chunk; });
        res.on('end', function () {
          resolve({ status: res.statusCode,
                    retryAfter: res.headers['retry-after'], body: body });
        });
      });
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// 1. A WORKER STILL APPLYING WHEN ITS syncNow() GIVES UP IS WAITED FOR, AND
//    THE ANSWER IS THE NEW VALUE.
// ---------------------------------------------------------------------------
async function checkASlowApplyIsWaitedOut(t) {
  log.debug("Entering checkASlowApplyIsWaitedOut().");
  t.log.info('=== a barrier behind a slow apply waits for it ===');
  pool.reset();
  replication.reset();
  const store = new Map([['cn=app', 'scope-declared']]);
  const copy = new Map([['cn=app', 'stale-copy']]);
  const driver = fakeDriver('worker');
  // SLOWER THAN syncNow()'s 4,600 ms DEADLINE, AND ASYNCHRONOUS — the loop is
  // free, so the worker DOES answer its round, `ok` and `caughtUp: false`.
  const PREPARE_MS = 6500;
  const directory = Object.assign(function (change) {
    log.debug("Entering directory().");
    copy.set(change.key, store.get(change.key));
    log.debug("Leaving directory().");
  }, {
    prepare: function () {
      log.debug("Entering prepare().");
      log.debug("Leaving prepare().");
      return sleep(PREPARE_MS);
    }
  });
  await replication.start(driver, { directory: directory });
  const worker = await startWorker(911, copy, true);
  const front = await startFront(worker.entry, 1);
  try {
    driver.write('another-worker', 'directory', 'cn=app');
    // The pull begins; its page's prepare holds it for 6.5 s.
    const pulling = replication.pull();
    const began = Date.now();
    const answer = get(front.address().port, '/realm/new/oauth2/authorize');
    await sleep(3000);
    const midway = replication.pullCostText();
    t.check(/preparing "directory" rows for \d+ ms/.test(midway) &&
            /of the applying, \d+ ms in the rows, (\d+) ms preparing/
              .test(midway),
            'the STS-STORE-0039 breakdown names the prepare the time is ' +
            'going to', midway);
    // Near the end of the prepare, the parts of the applying time add up:
    // the prepare is the time, and little is left unaccounted. (Read while
    // the pull is in flight: the barrier's own pull replaces it after.)
    await sleep(PREPARE_MS - 3000 - 600);
    const late = replication.pullCostText();
    const parts = /(\d+) ms applying.*of the applying, (\d+) ms in the rows, (\d+) ms preparing.*, (\d+) ms waiting for \d+ turn.*, (\d+) ms otherwise/
      .exec(late);
    t.check(!!parts && Number(parts[3]) >= PREPARE_MS - 1000 &&
            Number(parts[5]) < 500,
            'and the parts add up: the prepare is the time, and little is ' +
            'left unaccounted', late);
    const got = await answer;
    const took = Date.now() - began;
    await pulling;
    t.equal(got.status, 200, 'the request is answered, not refused');
    t.equal(JSON.parse(got.body || '{}').value, 'scope-declared',
            'WITH THE NEW VALUE: the worker was not stamped current by a ' +
            'round that said `caughtUp: false`',
            'before 2026-11-14 the round answered at 4.6 s as `ok` and the ' +
            'request was served "stale-copy"');
    t.check(took >= PREPARE_MS - 200,
            'it waited for the apply rather than the old 5 s bound',
            'took ' + took + ' ms');
    t.check(worker.entry.syncs >= 2,
            'a round that came back behind was followed by another',
            'syncs: ' + worker.entry.syncs);
    t.check(pool.stats().barrier.roundsMissed >= 1 &&
            pool.stats().barrier.refused === 0,
            'stats() counts the missed round and no refusal',
            JSON.stringify(pool.stats().barrier));
  } finally {
    await new Promise(function (resolve) { front.close(resolve); });
    await worker.stop();
    replication.reset();
    pool.reset();
  }
  log.debug("Leaving checkASlowApplyIsWaitedOut().");
}

// ---------------------------------------------------------------------------
// 2. A WORKER THAT NEVER CATCHES UP IS REFUSED, AND NOTHING REACHES IT.
// ---------------------------------------------------------------------------
async function checkANeverCurrentWorkerIsRefused(t) {
  log.debug("Entering checkANeverCurrentWorkerIsRefused().");
  t.log.info('=== a worker that never catches up is refused, not served ===');
  pool.reset();
  const copy = new Map([['cn=app', 'stale-copy']]);
  // `answers` false: a worker whose event loop is blocked by the apply.
  const worker = await startWorker(912, copy, false);
  const front = await startFront(worker.entry, 1);
  try {
    const began = Date.now();
    const got = await get(front.address().port, '/scim/v2/Users');
    const took = Date.now() - began;
    t.equal(got.status, 503, 'the request is refused with a 503',
            'got ' + got.status + ' ' + got.body);
    t.equal(got.retryAfter, '5', 'carrying Retry-After');
    t.check(got.body.indexOf('stale-copy') < 0 && worker.served.length === 0,
            'and the behind worker was never asked: no stale answer',
            'served: ' + JSON.stringify(worker.served));
    t.check(took >= 1900 && took < 6000,
            'after workers.readBarrierTimeoutMs, not the old 5 s',
            'took ' + took + ' ms');
    t.equal(pool.stats().tickets.outstanding, 0,
            'and its ticket went back, since nothing was written');
    t.equal(pool.stats().barrier.refused, 1, 'stats() counts the refusal');
  } finally {
    await new Promise(function (resolve) { front.close(resolve); });
    await worker.stop();
    pool.reset();
  }
  log.debug("Leaving checkANeverCurrentWorkerIsRefused().");
}

// ---------------------------------------------------------------------------
// 3. THE FRONT PROCESS'S OWN CATCH-UP, AND WHAT A ROUND'S ANSWER MEANS.
// ---------------------------------------------------------------------------
async function checkTheFrontsCatchUp(t) {
  log.debug("Entering checkTheFrontsCatchUp().");
  t.log.info('=== the front process asks again, then refuses ===');
  let calls = 0;
  const behindTwice = { syncNow: function () {
    calls += 1;
    return Promise.resolve({ caughtUp: calls > 2, coordinating: true });
  } };
  t.check(await pool.catchUpHere(behindTwice) === true && calls === 3,
          'a catch-up that says it is behind is asked again until it is not',
          'calls: ' + calls);
  const never = { syncNow: function () {
    return Promise.resolve({ caughtUp: false, coordinating: true });
  } };
  const began = Date.now();
  t.check(await pool.catchUpHere(never) === false,
          'and one that never catches up answers false — the refusal',
          'took ' + (Date.now() - began) + ' ms');
  const alone = { syncNow: function () {
    return Promise.resolve({ caughtUp: false, coordinating: false });
  } };
  t.check(await pool.catchUpHere(alone) === true,
          'a store that does not coordinate has nothing to catch up with', '');
  t.check(pool.roundCaughtUp({ ok: true }) &&
          pool.roundCaughtUp({ ok: true, caughtUp: true }) &&
          pool.roundCaughtUp({ ok: true, caughtUp: false,
                               coordinating: false }) &&
          !pool.roundCaughtUp({ ok: true, caughtUp: false,
                                coordinating: true }) &&
          !pool.roundCaughtUp({ ok: false, caughtUp: true }),
          'a round counts only when the worker says it caught up', '');
  log.debug("Leaving checkTheFrontsCatchUp().");
}

async function run(t) {
  log.debug("Entering run().");
  await withEnv({ STS_PERSISTENCE_COORDINATE: 'true',
                  STS_WORKERS_READ_YOUR_WRITE: 'true',
                  STS_WORKERS_READ_BARRIER_TIMEOUT_MS: '20000' },
  async function () {
    await checkASlowApplyIsWaitedOut(t);
  });
  await withEnv({ STS_WORKERS_READ_YOUR_WRITE: 'true',
                  STS_WORKERS_READ_BARRIER_TIMEOUT_MS: '2000' },
  async function () {
    await checkANeverCurrentWorkerIsRefused(t);
    await checkTheFrontsCatchUp(t);
  });
  // Process-wide module state, left as every later file expects it.
  pool.reset();
  replication.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'read_barrier_slow_apply',
  describe: 'that a read barrier behind a slow change-log apply waits for ' +
            'the worker to catch up and, past workers.readBarrierTimeoutMs, ' +
            'refuses with a 503 rather than answering from a stale copy',
  run: run
};
