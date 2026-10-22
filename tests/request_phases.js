// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: request_phases.js
//
// ===========================================================================
// WHERE A DISPATCHED REQUEST'S TIME GOES (2026-10-22, #820).
//
// `common/request_phases.js` keeps a one-minute window of each route's
// phases; the front process times the ticket and barrier waits and the round
// trip, the worker's commit barrier reports its handler, commit hold and the
// time its loop was blocked in synchronous store reads.
//
//   Q1. a route is the method and two path segments, without a realm or a
//       query;
//   Q2. the worker's header encodes and decodes, and anything else is none;
//   Q3. the window closes on the first record after it ends, and reports
//       each phase's p50, p95 and mean; a phase no request reported is
//       absent; past the route cap a new path is counted as `other`;
//   Q4. a real one-worker pool: the front asks the worker, the worker's
//       answer reaches the client WITHOUT the phases header, and the window
//       carries the worker's numbers and the front's waits;
//   Q5. a client's own question is not passed to the worker as its own: the
//       front replaces it;
//   Q6. in a worker thread, the commit barrier answers the question with the
//       handler's time and the time blocked in store reads meanwhile, and a
//       request the front did not ask about carries nothing.
// ===========================================================================

const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const express = require('express');
const workerThreads = require('worker_threads');
const pool = require('../common/request_pool');
const phases = require('../common/request_phases');

const log = require('bunyan').createLogger({
  name: 'request_phases',
  level: process.env.LOG_LEVEL || 'info' });

async function withEnv(vars, fn) {
  log.debug("Entering withEnv().");
  const had = {};
  Object.keys(vars).forEach(function (name) {
    had[name] = process.env[name];
    process.env[name] = vars[name];
  });
  try {
    log.debug("Leaving withEnv().");
    return await fn();
  } finally {
    Object.keys(had).forEach(function (name) {
      if (had[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = had[name];
      }
    });
  }
}

function checkTheModule(t) {
  log.debug("Entering checkTheModule().");
  t.equal(phases.routeOf('post', '/realm/acme/oauth2/token?x=1'),
          'POST /oauth2/token',
          'Q1. a route is the method and two segments, realm and query off');
  t.equal(phases.routeOf('GET', '/admin-api/users/alice/devices'),
          'GET /admin-api/users', 'Q1. and only two segments');
  const value = phases.encode(40.4, 25, 7);
  const back = phases.decode(value);
  t.check(value === 'h=40;c=25;b=7' && back && back.handler === 40 &&
          back.commit === 25 && back.bridge === 7 &&
          phases.decode('h=1;c=x;b=2') === null && phases.decode('') === null,
          'Q2. the worker\'s header round-trips, and anything else is none',
          JSON.stringify({ value: value, back: back }));

  phases.reset();
  const t0 = Date.now();
  for (let i = 1; i <= 100; i++) {
    phases.record('POST /oauth2/token', { ticket: 0, barrier: i, total: i * 2 },
                  t0 + i);
  }
  const before = phases.stats();
  phases.record('GET /x', { total: 1 }, t0 + phases.WINDOW_MS + 5);
  const closed = phases.stats();
  const one = closed && closed.routes['POST /oauth2/token'];
  t.check(before === null && one && one.n === 100 &&
          one.barrier.p50 === 51 && one.barrier.p95 === 96 &&
          one.barrier.mean === 51 && one.total.p95 === 192 &&
          one.handler === undefined && !closed.routes['GET /x'],
          'Q3. the window closes on the first record after it, with p50, ' +
          'p95 and mean per phase, and none for a phase nobody reported',
          JSON.stringify(closed));
  phases.reset();
  for (let i = 0; i < 70; i++) {
    phases.record('GET /r' + i, { total: 1 }, t0 + 1);
  }
  phases.record('GET /z', { total: 1 }, t0 + phases.WINDOW_MS + 5);
  const capped = phases.stats();
  t.check(capped && capped.routes.other && capped.routes.other.n === 6,
          'Q3. past the route cap a new path is counted as other',
          JSON.stringify(Object.keys((capped && capped.routes) || {})));
  log.debug("Leaving checkTheModule().");
}

// A worker THREAD that speaks the pool's channel (`begin` in, `ready` out)
// and answers every request after 60 ms with the phases a worker would
// report, echoing the question it was asked.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "const wt = require('worker_threads');",
  "wt.parentPort.on('message', function (m) {",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (!m || !m.begin) { return; }",
  "  const server = http.createServer(function (req, res) {",
  "    setTimeout(function () {",
  "      res.setHeader('x-sts-pool-phases', 'h=40;c=15;b=7');",
  "      res.setHeader('x-asked', String(req.headers[" +
    "'x-sts-pool-phases-wanted'] || ''));",
  "      res.end('ok');",
  "    }, 60);",
  "  });",
  "  server.listen(m.socket, function () {",
  "    wt.parentPort.postMessage({ ready: true });",
  "  });",
  "});",
  ""
].join('\n');

function get(port, urlPath, headers) {
  log.debug("Entering get().");
  log.debug("Leaving get().");
  return new Promise(function (resolve) {
    const req = http.get({ host: '127.0.0.1', port: port, path: urlPath,
                           agent: false, headers: headers || {} },
                         function (answer) {
      let text = '';
      answer.on('data', function (chunk) {
        text += chunk;
      });
      answer.on('end', function () {
        resolve({ status: answer.statusCode, headers: answer.headers,
                  text: text });
      });
    });
    req.on('error', function (e) {
      log.debug("Caught in get(): " + ((e && e.message) || e));
      resolve({ status: 0, headers: {}, text: String(e && e.message) });
    });
  });
}

async function checkThePool(t) {
  log.debug("Entering checkThePool().");
  const stubPath = path.join(os.tmpdir(), 'sts-phases-stub-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, STUB);
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '1',
                  STS_WORKERS_DISPATCH: '*',
                  STS_WORKERS_READ_YOUR_WRITE: 'false' }, async function () {
    pool.reset();
    phases.reset();
    pool.useWorkerModule(stubPath);
    let front = null;
    try {
      const entry = await pool.queueFork(pool.PROTOCOL_POOL, 0);
      t.check(entry && entry.ready, 'the stub worker is up', '');
      const app = express();
      app.use(pool.middleware());
      front = http.createServer(app);
      await new Promise(function (resolve) {
        front.listen(0, '127.0.0.1', resolve);
      });
      const port = front.address().port;
      const answers = [];
      for (let i = 0; i < 5; i++) {
        answers.push(await get(port, '/oauth2/userinfo',
          { 'x-sts-pool-phases-wanted': 'a client asking' }));
      }
      phases.record('GET /close', { total: 0 },
                    Date.now() + phases.WINDOW_MS + 5);
      const window = phases.stats();
      const route = window && window.routes['GET /oauth2/userinfo'];
      t.check(answers.every(function (one) {
        return one.status === 200 &&
          one.headers['x-sts-pool-phases'] === undefined;
      }), 'Q4. the worker\'s phases do not reach the client',
              JSON.stringify(answers[0] && answers[0].headers));
      t.check(answers.every(function (one) {
        return one.headers['x-asked'] === '1';
      }), 'Q5. the worker is asked by the front, not by the client',
              JSON.stringify(answers.map(function (one) {
                return one.headers['x-asked'];
              })));
      t.check(route && route.n === 5 && route.handler.p50 === 40 &&
              route.commit.p50 === 15 && route.bridge.p50 === 7 &&
              route.ticket.p50 === 0 && route.barrier.p50 === 0 &&
              route.queue.p50 >= 0 && route.total.p50 >= 55,
              'Q4. the window carries the worker\'s numbers and the ' +
              'front\'s waits and round trip', JSON.stringify(route));
      t.check(pool.stats().phases === window,
              'Q4. and the pool\'s stats() reports it', '');
    } finally {
      if (front) {
        front.closeAllConnections();
        await new Promise(function (resolve) {
          front.close(resolve);
        });
      }
      await pool.stop(3000);
      pool.reset();
      phases.reset();
      try {
        fs.unlinkSync(stubPath);
      } catch (e) {
        log.debug("Caught in checkThePool(): " + ((e && e.message) || e));
      }
    }
  });
  log.debug("Leaving checkThePool().");
}

// Runs in a worker thread: the commit barrier's half, on a stand-in
// response, in a process with no store positions (so nothing is held).
const WORKER_HALF = [
  "'use strict';",
  "const wt = require('worker_threads');",
  "const root = wt.workerData.root;",
  "const barrier = require(root + '/cluster/cluster_barrier');",
  "const phases = require(root + '/common/request_phases');",
  "function fake() {",
  "  const res = { headersSent: false, headers: {}, ended: false };",
  "  res.setHeader = function (n, v) { res.headers[n] = v; };",
  "  res.end = function () { res.ended = true; return res; };",
  "  return res;",
  "}",
  "const asked = { headers: { 'x-sts-pool-phases-wanted': '1' } };",
  "const a = fake();",
  "barrier.stampPhases(asked, a);",
  "barrier.holdUntilCommitted(a, null, asked);",
  "const b = fake();",
  "barrier.stampPhases({ headers: {} }, b);",
  "barrier.holdUntilCommitted(b, null, { headers: {} });",
  "setTimeout(function () {",
  "  phases.noteBlocked(9);",
  "  a.end('x');",
  "  b.end('y');",
  "  wt.parentPort.postMessage({ a: a.headers, aEnded: a.ended,",
  "                              b: b.headers, bEnded: b.ended });",
  "}, 50);",
  ""
].join('\n');

async function checkTheWorkerHalf(t) {
  log.debug("Entering checkTheWorkerHalf().");
  const answer = await new Promise(function (resolve) {
    const worker = new workerThreads.Worker(WORKER_HALF, {
      eval: true, workerData: { root: path.join(__dirname, '..') } });
    worker.once('message', function (m) {
      resolve(m);
      worker.terminate();
    });
    worker.once('error', function (e) {
      log.debug("Caught in checkTheWorkerHalf(): " + ((e && e.message) || e));
      resolve({ error: String((e && e.stack) || e) });
    });
  });
  const reported = phases.decode(answer.a && answer.a['x-sts-pool-phases']);
  t.check(answer.aEnded && reported && reported.handler >= 45 &&
          reported.commit <= 5 && reported.bridge === 9,
          'Q6. a worker answers the front\'s question with the handler\'s ' +
          'time and the time blocked in store reads meanwhile',
          JSON.stringify(answer));
  t.check(answer.bEnded && answer.b &&
          answer.b['x-sts-pool-phases'] === undefined,
          'Q6. and a request nobody asked about carries nothing',
          JSON.stringify(answer.b));
  log.debug("Leaving checkTheWorkerHalf().");
}

async function run(t) {
  log.debug("Entering run().");
  checkTheModule(t);
  await checkThePool(t);
  await checkTheWorkerHalf(t);
  pool.reset();
  phases.reset();
  log.debug("Leaving run().");
}

module.exports = {
  name: 'request_phases',
  describe: 'where a dispatched request\'s time goes: the front\'s waits, ' +
            'the worker\'s handler, commit hold and blocked store reads, ' +
            'summarised per route per minute (#820)',
  run: run
};
