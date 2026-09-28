// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: worker_pools_page.js
//
// ===========================================================================
// MONITORING → WORKER POOLS (#327): THE NUMBERS, AND WHERE THEY COME FROM.
//
// `admin-ui/worker_pools_admin.ts` draws three pools from their own modules,
// and #327 added to each module what it had never counted. Six claims:
//
//   1. THE POST-QUANTUM POOL COUNTS its first fork (the lazy pool's initial
//      size), each job's time, a crash (a worker SIGKILLed under it) apart
//      from a retirement (a lowered `workers.count`), and a job computed in
//      process — driving the REAL `common/worker_pool.js` with real children
//      and a cheap `scrypt.derive`.
//   2. A REQUEST POOL COUNTS its forks, a crash apart from a stop, and the
//      time from dispatch to answer of a request `proxy()` really streamed —
//      the REAL fork(), reap() and proxy() over a STUB worker, as
//      `tests/request_worker_replacement.js` does.
//   3. THE PAGE ASKS EACH REQUEST WORKER for its own post-quantum pool, and a
//      worker that does not answer is drawn as not having answered rather
//      than holding the page.
//   4. A POOL THAT IS OFF SAYS SO IN WORDS — the page and its JSON.
//   5. The page and the API are PINNED to the front process
//      (`NEVER_DISPATCHED`) even with `workers.dispatch=*`.
//   6. It is a SERVICE page: a realm's own administrator is refused it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const express = require('express');
const config = require('../common/config');
const requestPool = require('../common/request_pool');
const workerPool = require('../common/worker_pool');
const app = require('../common/app');
// Loading a module registers nothing since #50's R1, so the page's route is
// registered here. The console shell comes first, as in the composition root.
require('../admin-ui/admin').registerRoutes(app);
const workerPoolsAdmin = require('../admin-ui/worker_pools_admin');
workerPoolsAdmin.registerRoutes(app);
const adminScope = require('../admin-ui/admin_scope');

const log = require('bunyan').createLogger({
  name: 'worker_pools_page',
  level: process.env.LOG_LEVEL || 'info' });

const PROTO = requestPool.PROTOCOL_POOL;

// The stub request worker: `begin` in, `ready` out, an HTTP server on the
// socket it is given; GET / answers its pid after 30ms, so a response time is
// something to measure. It answers `{ poolStatus }` with a fixed
// post-quantum pool of its own — unless STUB_MODE=mute, which is a worker
// that never answers the question — and exits when a drain says `stop`.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "process.on('message', function (m) {",
  "  if (m && m.poolStatus) {",
  "    if (process.env.STUB_MODE === 'mute') { return; }",
  "    process.send({ poolStatus: true, id: m.id, pq: {",
  "      configured: 2, running: 1, busy: 0, free: 1, gaveUp: false,",
  "      averageJobMs: 10, counts: { forked: 1, firstForked: 1,",
  "      firstForkAt: 1, crashed: 0, retired: 0, failedStarts: 0,",
  "      jobs: 4, failed: 0, timedOut: 0, jobMs: 40, maxJobMs: 20,",
  "      inProcess: 0, inProcessMs: 0 } } });",
  "    return;",
  "  }",
  "  if (m && m.stop) { process.exit(0); }",
  "  if (!m || !m.begin) { return; }",
  "  const server = http.createServer(function (req, res) {",
  "    setTimeout(function () { res.end(String(process.pid)); }, 30);",
  "  });",
  "  server.listen(m.socket, function () { process.send({ ready: true }); });",
  "});",
  "process.on('disconnect', function () { process.exit(0); });",
  ""
].join('\n');

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

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

function poolOf(json, id) {
  log.debug("Entering poolOf().");
  log.debug("Leaving poolOf().");
  return json.pools.filter(function (one) {
    return one.id === id;
  })[0];
}

function protoStats() {
  log.debug("Entering protoStats().");
  log.debug("Leaving protoStats().");
  return requestPool.stats().pools.filter(function (one) {
    return one.pool === PROTO;
  })[0];
}

function readyProto() {
  log.debug("Entering readyProto().");
  log.debug("Leaving readyProto().");
  return requestPool.workerTable().filter(function (one) {
    return one.pool === PROTO && one.ready;
  });
}

// An environment variable set for the length of `fn` and put back after,
// whatever happens — these are process-wide, and every later file in the
// run reads through them (tests/CLAUDE.md).
async function withEnv(values, fn) {
  log.debug("Entering withEnv().");
  const had = {};
  Object.keys(values).forEach(function (key) {
    had[key] = process.env[key];
    process.env[key] = values[key];
  });
  try {
    await fn();
  } finally {
    Object.keys(had).forEach(function (key) {
      if (had[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = had[key];
      }
    });
  }
  log.debug("Leaving withEnv().");
}

// The page's handler, called below the console gate with a request carrying
// only a query, as tests/cache_registry.js does. Answers the body sent.
function draw(query) {
  log.debug("Entering draw().");
  const layer = (app._router.stack || []).filter(function (one) {
    return one.route && one.route.path === '/admin/worker-pools' &&
           one.route.methods.get;
  })[0];
  if (!layer) {
    log.debug("Leaving draw(). No route.");
    return Promise.resolve(null);
  }
  return new Promise(function (resolve) {
    const res = {
      statusCode: 200,
      set: function () {
        return this;
      },
      status: function (code) {
        this.statusCode = code;
        return this;
      },
      type: function () {
        return this;
      },
      send: function (text) {
        resolve({ status: this.statusCode, body: String(text) });
        return this;
      },
      json: function (value) {
        resolve({ status: this.statusCode, body: JSON.stringify(value) });
        return this;
      },
      get: function () {
        return undefined;
      },
      getHeader: function () {
        return undefined;
      },
      setHeader: function () {
        return undefined;
      },
      locals: {}
    };
    const req = { query: query, headers: {}, method: 'GET', cookies: {},
                  url: '/admin/worker-pools',
                  originalUrl: '/admin/worker-pools',
                  path: '/admin/worker-pools',
                  get: function () {
                    return '';
                  } };
    layer.route.stack[0].handle(req, res, function (e) {
      log.debug("The page's handler called next(): " +
                ((e && e.message) || e));
      resolve(null);
    });
    log.debug("Leaving draw().");
  });
}

// ---------------------------------------------------------------------------
// 1. THE POST-QUANTUM POOL'S COUNTERS, WITH REAL CHILDREN.
// ---------------------------------------------------------------------------
function scryptJob() {
  log.debug("Entering scryptJob().");
  log.debug("Leaving scryptJob().");
  return { plaintext: 'worker-pools', salt: Buffer.from('0123456789abcdef'),
           keylen: 16, N: 1024, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
}

async function checkThePqPool(t) {
  log.debug("Entering checkThePqPool().");
  t.log.info('=== 1. the post-quantum pool counts forks, jobs, crashes, ' +
             'retirements and in-process jobs ===');
  // Whatever an earlier file in the run left forked is drained first, so
  // the first job here is the pool's first fork.
  await workerPool.stop(3000);
  workerPool.reset();
  config.setOverride('workers.count', '1');
  try {
    await workerPool.run('scrypt.derive', scryptJob());
    let s = workerPool.stats();
    t.equal(s.counts.forked, 1, 'the first job forks the one worker');
    t.equal(s.counts.firstForked, 1,
            'and that first fork is the lazy pool\'s initial size');
    t.check(s.counts.firstForkAt > 0, 'with when it happened',
            String(s.counts.firstForkAt));
    t.equal(s.counts.jobs, 1, 'one job answered by a worker');
    t.check(typeof s.averageJobMs === 'number' && s.averageJobMs >= 0,
            'and its time is averaged', String(s.averageJobMs));
    t.equal(s.busy + s.free, s.running, 'busy and free add up to running');

    const pid = s.workers[0].pid;
    process.kill(pid, 'SIGKILL');
    t.check(await waitFor(function () {
      return workerPool.stats().counts.crashed === 1;
    }, 10000), 'a worker SIGKILLed under the pool is counted as a crash',
    JSON.stringify(workerPool.stats().counts));
    await workerPool.run('scrypt.derive', scryptJob());
    s = workerPool.stats();
    t.equal(s.counts.forked, 2, 'the next job forks its replacement');
    t.equal(s.counts.firstForked, 1,
            'which does not change the initial size');

    config.setOverride('workers.count', '0');
    await workerPool.run('scrypt.derive', scryptJob());
    t.check(await waitFor(function () {
      return workerPool.stats().counts.retired === 1;
    }, 10000), 'lowering workers.count retires the worker, and that is ' +
       'counted as retired, not crashed',
    JSON.stringify(workerPool.stats().counts));
    s = workerPool.stats();
    t.equal(s.counts.crashed, 1, 'the crash count is unchanged by it');
    t.equal(s.counts.inProcess, 1,
            'and the job with no worker was computed in process, counted');
  } finally {
    config.clearOverride('workers.count');
    await workerPool.stop(3000);
    workerPool.reset();
  }
  log.debug("Leaving checkThePqPool().");
}

// ---------------------------------------------------------------------------
// 2. A REQUEST POOL'S COUNTERS, WITH STUB WORKERS AND THE REAL PROXY.
// ---------------------------------------------------------------------------
function proxyThrough(entry) {
  log.debug("Entering proxyThrough().");
  return new Promise(function (resolve) {
    // An express app in front, as the service has: proxy() answers through
    // express's response (`res.status()`), not a bare http one.
    const frontApp = express();
    frontApp.use(function (req, res) {
      requestPool.proxy(entry, req, res, 0, 0);
    });
    const front = http.createServer(frontApp);
    front.listen(0, '127.0.0.1', function () {
      const port = front.address().port;
      http.get({ host: '127.0.0.1', port: port, path: '/', agent: false },
        function (answer) {
          let text = '';
          answer.on('data', function (chunk) {
            text += chunk;
          });
          answer.on('end', function () {
            front.close();
            resolve(text);
          });
        }).on('error', function (e) {
        log.debug("Caught in proxyThrough(): " + ((e && e.message) || e));
        front.close();
        resolve('');
      });
    });
    log.debug("Leaving proxyThrough().");
  });
}

async function checkARequestPool(t, stubPath) {
  log.debug("Entering checkARequestPool().");
  t.log.info('=== 2. a request pool counts forks, crashes, stops and ' +
             'response times ===');
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '2', STUB_MODE: 'ok' },
    async function () {
      requestPool.reset();
      requestPool.useWorkerModule(stubPath);
      try {
        requestPool.fork(PROTO, 0);
        requestPool.fork(PROTO, 1);
        t.check(await waitFor(function () {
          return readyProto().length === 2;
        }, 10000), 'two stub workers come up', '');
        let s = protoStats();
        t.equal(s.history.forked, 2, 'two forks counted');
        t.equal(s.busy, 0, 'none busy');
        t.equal(s.free, 2, 'both free');
        t.equal(s.averageMs, null,
                'no response time before anything was answered');

        const entry = readyProto()[0];
        const body = await proxyThrough(entry);
        t.equal(body, String(entry.pid), 'a request proxied to a worker is ' +
                'answered by it');
        s = protoStats();
        t.equal(s.history.answered, 1, 'and counted as answered');
        t.check(s.averageMs >= 25 && s.recentAverageMs >= 25,
                'with its time from dispatch to answer (the stub waits 30ms)',
                JSON.stringify({ averageMs: s.averageMs,
                                 recentAverageMs: s.recentAverageMs }));

        // The worker that served the request: one that served nothing within
        // QUICK_EXIT_MS of its fork is a failed start by the pool's own rule.
        entry.child.kill('SIGKILL');
        t.check(await waitFor(function () {
          return protoStats().history.crashed === 1 &&
                 readyProto().length === 2;
        }, 10000), 'a SIGKILLed worker is a crash, and is replaced',
        JSON.stringify(protoStats().history));
        s = protoStats();
        t.equal(s.replaced, 1, 'one replacement');
        t.equal(s.history.forked, 3, 'three forks in all');
        t.equal(s.history.failedStarts, 0,
                'a worker that was serving is not a failed start');

        await requestPool.stop(3000);
        s = protoStats();
        t.equal(s.history.stoppedExits, 2,
                'the two a drain stopped are counted as stopped');
        t.equal(s.history.crashed, 1, 'and not as crashes');
      } finally {
        await requestPool.stop(3000);
        requestPool.reset();
      }
    });
  log.debug("Leaving checkARequestPool().");
}

// ---------------------------------------------------------------------------
// 3. THE PAGE ASKS EACH WORKER FOR ITS OWN POST-QUANTUM POOL.
// ---------------------------------------------------------------------------
async function checkThePageAsksTheWorkers(t, stubPath) {
  log.debug("Entering checkThePageAsksTheWorkers().");
  t.log.info('=== 3. the page reports each request worker\'s own ' +
             'post-quantum pool ===');
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '2', STUB_MODE: 'ok' },
    async function () {
      requestPool.reset();
      requestPool.useWorkerModule(stubPath);
      try {
        requestPool.fork(PROTO, 0);
        requestPool.fork(PROTO, 1);
        t.check(await waitFor(function () {
          return readyProto().length === 2;
        }, 10000), 'two stub workers come up', '');
        const json = await workerPoolsAdmin.workerPoolsView();
        const request = poolOf(json, 'request');
        t.equal(request.currentWorkers, 2, 'the request pool has two workers');
        t.equal(request.maxWorkers, 2, 'its maximum is the configured two');
        t.equal(request.state, 'not-dispatching',
                'and with workers.dispatch empty it says it is idle by ' +
                'configuration');
        t.equal(request.workers.length, 2, 'each worker is listed');
        const pq = poolOf(json, 'post-quantum');
        t.equal(pq.processes.length, 3,
                'the post-quantum pool has a row for the front process and ' +
                'for each worker that answered');
        t.equal(pq.unanswered.length, 0, 'and none failed to answer');
        t.check(pq.responseTime.jobs >= 8 && pq.currentWorkers >= 2,
                'its totals include the workers\' own pools',
                JSON.stringify(pq.responseTime));
      } finally {
        await requestPool.stop(3000);
        requestPool.reset();
      }
    });
  await withEnv({ STS_WORKERS_REQUEST_COUNT: '1', STUB_MODE: 'mute' },
    async function () {
      requestPool.reset();
      requestPool.useWorkerModule(stubPath);
      try {
        requestPool.fork(PROTO, 0);
        t.check(await waitFor(function () {
          return readyProto().length === 1;
        }, 10000), 'a worker that will not answer comes up', '');
        const began = Date.now();
        const json = await workerPoolsAdmin.workerPoolsView();
        const pq = poolOf(json, 'post-quantum');
        t.check(Date.now() - began < 5000,
                'the page does not wait on it past its bound',
                String(Date.now() - began));
        t.equal(pq.unanswered.length, 1,
                'and it is listed as not having answered');
      } finally {
        await requestPool.stop(3000);
        requestPool.reset();
      }
    });
  log.debug("Leaving checkThePageAsksTheWorkers().");
}

// ---------------------------------------------------------------------------
// 4. A POOL THAT IS OFF SAYS SO.
// ---------------------------------------------------------------------------
async function checkOffIsSaid(t) {
  log.debug("Entering checkOffIsSaid().");
  t.log.info('=== 4. a pool that is off says so, in the JSON and on the ' +
             'page ===');
  requestPool.reset();
  workerPool.reset();
  config.setOverride('workers.count', '0');
  try {
    const json = await workerPoolsAdmin.workerPoolsView();
    ['request', 'surface', 'post-quantum'].forEach(function (id) {
      const p = poolOf(json, id);
      t.check(!!p && p.state === 'off' && /^Off:/.test(p.stateText),
              'the ' + id + ' pool is off and says so in a sentence',
              p ? p.state + ': ' + p.stateText : 'missing');
    });
    t.equal(json.scope, 'node', 'the figures are said to be the node\'s');
    t.check(json.pid === process.pid && !!json.host,
            'naming the process and host that drew them', '');
    const page = await draw({});
    t.check(!!page && /Off: workers\.requestCount is 0/.test(page.body) &&
            /Off: workers\.surfaceCount is 0/.test(page.body) &&
            /Off: workers\.count is 0/.test(page.body),
            'the page says each pool is off rather than drawing zeros',
            page ? page.body.slice(0, 300) : 'no page');
    const asJson = await draw({ format: 'json' });
    t.check(!!asJson && JSON.parse(asJson.body).pools.length === 3,
            '?format=json answers the same three pools', '');
  } finally {
    config.clearOverride('workers.count');
  }
  // Not forked yet is a different sentence from off.
  workerPool.reset();
  config.setOverride('workers.count', '2');
  try {
    const json = await workerPoolsAdmin.workerPoolsView();
    const pq = poolOf(json, 'post-quantum');
    t.equal(pq.state, 'not-forked',
            'a lazy pool with no job yet says it has not forked');
  } finally {
    config.clearOverride('workers.count');
  }
  log.debug("Leaving checkOffIsSaid().");
}

// ---------------------------------------------------------------------------
// 5 AND 6. PINNED TO THE FRONT PROCESS, AND A SERVICE PAGE.
// ---------------------------------------------------------------------------
async function checkPinnedAndScoped(t) {
  log.debug("Entering checkPinnedAndScoped().");
  t.log.info('=== 5. pinned to the front process; 6. refused to a realm ' +
             'administrator ===');
  await withEnv({ STS_WORKERS_DISPATCH: '*' }, async function () {
    t.check(requestPool.dispatched('/admin/caches') === true,
            'with workers.dispatch=* the console is dispatched', '');
    t.check(requestPool.dispatched('/admin/worker-pools') === false &&
            requestPool.dispatched('/realm/acme/admin/worker-pools') ===
              false &&
            requestPool.dispatched('/admin-api/worker-pools') === false,
            'but the worker pools page and its API are answered by the ' +
            'front process, which holds the pools', '');
  });
  t.check(adminScope.pageIsService('/admin/worker-pools'),
          '/admin/worker-pools is a service page', '');
  const refusal = adminScope.refusalFor(
    { authority: 'realm', identityRealm: 'acme' }, '/admin/worker-pools',
    null, {});
  t.check(!!refusal && refusal.reason === 'service_page',
          'a realm administrator is refused it',
          JSON.stringify(refusal));
  log.debug("Leaving checkPinnedAndScoped().");
}

async function run(t) {
  log.debug("Entering run().");
  const stubPath = path.join(os.tmpdir(), 'sts-stub-pools-' + process.pid +
                             '.js');
  fs.writeFileSync(stubPath, STUB);
  try {
    await checkThePqPool(t);
    await checkARequestPool(t, stubPath);
    await checkThePageAsksTheWorkers(t, stubPath);
    await checkOffIsSaid(t);
    await checkPinnedAndScoped(t);
  } finally {
    try {
      fs.unlinkSync(stubPath);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    requestPool.reset();
    workerPool.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'worker_pools_page',
  describe: 'Monitoring → Worker Pools (#327): what each pool counts — forks, ' +
            'crashes apart from stops, response times, the initial size — ' +
            'each request worker\'s own post-quantum pool asked for, a pool ' +
            'that is off saying so, pinned to the front process, and ' +
            'refused to a realm administrator',
  run: run
};
