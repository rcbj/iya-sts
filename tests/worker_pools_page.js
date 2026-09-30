// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: worker_pools_page.js
//
// ===========================================================================
// MONITORING → WORKER POOLS (#327): THE NUMBERS, AND WHERE THEY COME FROM.
//
// `admin-ui/worker_pools_admin.ts` draws two pools from their own module,
// and #327 added to it what it had never counted. Five claims, numbered as
// they were: the first, the post-quantum pool's counters, went with that
// pool in #363 — post-quantum signing and scrypt run on libuv's thread pool
// now, and there is no pool of processes to count.
//
//   2. A REQUEST POOL COUNTS its forks, a crash apart from a stop, and the
//      time from dispatch to answer of a request `proxy()` really streamed —
//      the REAL fork(), reap() and proxy() over a STUB worker, as
//      `tests/request_worker_replacement.js` does.
//   3. THE PAGE DRAWS EACH REQUEST WORKER from the pool's own table, asks
//      no worker anything — a worker that would not answer does not hold
//      the page — and has no post-quantum section.
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
const requestPool = require('../common/request_pool');
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
// something to measure. It answers `{ poolStatus }` — unless STUB_MODE=mute,
// which is a worker that never answers the question — and exits when a drain
// says `stop`.
const STUB = [
  "'use strict';",
  "const http = require('http');",
  "process.on('message', function (m) {",
  "  if (m && m.poolStatus) {",
  "    if (process.env.STUB_MODE === 'mute') { return; }",
  "    process.send({ poolStatus: true, id: m.id, pid: process.pid,",
  "                   memory: process.memoryUsage() });",
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
// 3. THE PAGE DRAWS EACH WORKER, AND ASKS NONE OF THEM ANYTHING.
// ---------------------------------------------------------------------------
async function checkThePageDrawsTheWorkers(t, stubPath) {
  log.debug("Entering checkThePageDrawsTheWorkers().");
  t.log.info('=== 3. the page draws each request worker, asks none, and ' +
             'has no post-quantum pool ===');
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
        t.check(json.pools.length === 2 && !poolOf(json, 'post-quantum'),
                'and there are two pools, none of them post-quantum (#363)',
                JSON.stringify(json.pools.map(function (one) {
                  return one.id;
                })));
        t.check(/libuv/.test(json.scopeText),
                'the page says where post-quantum signing went',
                json.scopeText);
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
        t.check(Date.now() - began < 900,
                'the page does not wait on it, since it asks it nothing',
                String(Date.now() - began));
        t.equal(poolOf(json, 'request').workers.length, 1,
                'and it is drawn from the pool\'s own table');
      } finally {
        await requestPool.stop(3000);
        requestPool.reset();
      }
    });
  log.debug("Leaving checkThePageDrawsTheWorkers().");
}

// ---------------------------------------------------------------------------
// 4. A POOL THAT IS OFF SAYS SO.
// ---------------------------------------------------------------------------
async function checkOffIsSaid(t) {
  log.debug("Entering checkOffIsSaid().");
  t.log.info('=== 4. a pool that is off says so, in the JSON and on the ' +
             'page ===');
  requestPool.reset();
  const json = await workerPoolsAdmin.workerPoolsView();
  ['request', 'surface'].forEach(function (id) {
    const p = poolOf(json, id);
    t.check(!!p && p.state === 'off' && /^Off:/.test(p.stateText),
            'the ' + id + ' pool is off and says so in a sentence',
            p ? p.state + ': ' + p.stateText : 'missing');
  });
  t.equal(json.scope, 'node', 'the figures are said to be the node\'s');
  t.check(json.pid === process.pid && !!json.node && !('host' in json),
          'naming the process and node that drew them, by name and not ' +
          'by host (#332)', '');
  const page = await draw({});
  t.check(!!page && /Off: workers\.requestCount is 0/.test(page.body) &&
          /Off: workers\.surfaceCount is 0/.test(page.body),
          'the page says each pool is off rather than drawing zeros',
          page ? page.body.slice(0, 300) : 'no page');
  t.check(!!page && !/workers\.count\b/.test(page.body) &&
          !/Post-quantum pool/.test(page.body),
          'and names no post-quantum pool or its setting (#363)', '');
  const asJson = await draw({ format: 'json' });
  t.check(!!asJson && JSON.parse(asJson.body).pools.length === 2,
          '?format=json answers the same two pools', '');
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
    await checkARequestPool(t, stubPath);
    await checkThePageDrawsTheWorkers(t, stubPath);
    await checkOffIsSaid(t);
    await checkPinnedAndScoped(t);
  } finally {
    try {
      fs.unlinkSync(stubPath);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    requestPool.reset();
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'worker_pools_page',
  describe: 'Monitoring → Worker Pools (#327): what each pool counts — forks, ' +
            'crashes apart from stops, response times, the initial size — ' +
            'each request worker drawn and none asked, no post-quantum ' +
            'pool (#363), a pool that is off saying so, pinned to the ' +
            'front process, and refused to a realm administrator',
  run: run
};
