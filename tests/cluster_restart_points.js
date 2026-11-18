// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cluster_restart_points.js
//
// ===========================================================================
// THE CLUSTER IS RESTARTED WHERE THE MODE SAYS, WITH NO JOB RUNNING, AND A
// RESTART THAT DID NOT COME BACK IS A FAILURE (2026-11-18, rcbj: "Restart the
// cluster a couple of times during the test run").
//
// The restart itself is the launcher's (`run-tests.sh`,
// `clusterRestartBroker()`) and is not something an in-process file can do;
// what is here is everything around it that decides whether the run means
// anything (tests/CLAUDE.md, *The cluster restarted during the run*):
//
//   A. `run-report.js`'s schedule: with STS_TEST_RESTART_POINTS=2 over nine
//      protocol jobs in two lanes, the restart is asked for twice, after the
//      third and the sixth job, and at each NO job is running — the lanes
//      have drained; with 0 it is never asked for.
//   B. `tools/cluster-restart.js` with no broker listening goes on without a
//      restart and says so (`skipped`), rather than waiting for an answer
//      nobody will write.
//   C. With a broker that answers: the request is written, the answer read,
//      every node is waited for as a live member, and each node's memory is
//      read before and after (`/admin-api/node-health`).
//   D. A broker that answers `ok: false` is a FAILED restart.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const log = require('bunyan').createLogger({ name: 'cluster_restart_points',
  level: process.env.LOG_LEVEL || 'info' });

const runReport = require('./tools/run-report');
const clusterRestart = require('./tools/cluster-restart');

// A stand-in for the service: the two management-API reads the tool makes.
function fakeService() {
  log.debug("Entering fakeService().");
  const server = http.createServer(function (req, res) {
    res.setHeader('content-type', 'application/json');
    if (req.url.indexOf('/admin-api/node-health') === 0) {
      res.end(JSON.stringify({ node: 'node-a',
        memory: { currentBytes: 2 * 1048576 * 1024, anonBytes: 1048576 },
        processes: { rows: [{ role: 'front process', threadId: null,
                              rssBytes: 1048576, heapUsedBytes: 5242880,
                              heapTotalBytes: 10485760 }] } }));
      return;
    }
    if (req.url.indexOf('/admin-api/cluster') === 0) {
      res.end(JSON.stringify({ status: { databaseNow: 1000,
        nodes: [{ nodeId: 'node-a', expiresAt: 2000 }] } }));
      return;
    }
    res.statusCode = 404;
    res.end('{}');
  });
  log.debug("Leaving fakeService().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

// A broker that answers each request in `dir` with `answer`.
function fakeBroker(dir, answer) {
  log.debug("Entering fakeBroker().");
  fs.writeFileSync(path.join(dir, 'broker.ready'), '');
  const timer = setInterval(function () {
    fs.readdirSync(dir).forEach(function (name) {
      const m = /^request-(\d+)\.json$/.exec(name);
      if (m && !fs.existsSync(path.join(dir, 'done-' + m[1] + '.json'))) {
        fs.writeFileSync(path.join(dir, 'done-' + m[1] + '.json'),
                         JSON.stringify(Object.assign({ k: Number(m[1]) },
                                                      answer)));
      }
    });
  }, 50);
  log.debug("Leaving fakeBroker().");
  return timer;
}

async function schedule(t) {
  log.debug("Entering schedule().");
  t.log.info('=== A. where the restarts fall ===');
  const jobs = [];
  for (let i = 0; i < 9; i++) {
    jobs.push({ name: 'job' + i, suite: 'protocol',
                lane: i % 2 ? 'main' : 'other' });
  }
  let running = 0;
  const order = [];
  const runOne = async function (job) {
    log.debug("Entering runOne().");
    running += 1;
    order.push(job.name);
    await new Promise(function (resolve) {
      setTimeout(resolve, 5);
    });
    running -= 1;
    log.debug("Leaving runOne().");
    return { name: job.name, status: 'passed', assertions: [] };
  };
  const asked = [];
  await runReport.runScheduled(jobs, runOne, {
    serial: false, unitConcurrency: 1, restartPoints: 2,
    restart: async function (k, of) {
      log.debug("Entering restart().");
      asked.push({ k: k, of: of, running: running, done: order.length });
      log.debug("Leaving restart().");
    }
  });
  t.check(asked.length === 2 && asked[0].k === 1 && asked[1].k === 2 &&
          asked[0].of === 2 && asked[0].done === 3 && asked[1].done === 6,
          'A. two restart points over nine jobs fall after the third and ' +
          'the sixth', JSON.stringify(asked));
  t.check(asked.every(function (one) {
    return one.running === 0;
  }), 'A. and at each no job is running: the lanes have drained',
          JSON.stringify(asked));
  let none = 0;
  await runReport.runScheduled(jobs, runOne, {
    serial: false, unitConcurrency: 1, restartPoints: 0,
    restart: async function () {
      log.debug("Entering restart().");
      none += 1;
      log.debug("Leaving restart().");
    }
  });
  t.check(none === 0, 'A. with no restart points the cluster is never ' +
          'restarted', String(none));
  log.debug("Leaving schedule().");
}

async function tool(t) {
  log.debug("Entering tool().");
  const server = await fakeService();
  const url = 'http://127.0.0.1:' + server.address().port;
  const tokenFor = async function () {
    log.debug("Entering tokenFor().");
    log.debug("Leaving tokenFor().");
    return 'token';
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cluster-restart-'));
  let timer = null;
  try {
    t.log.info('=== B. no broker ===');
    const alone = await clusterRestart.restart({ k: 1, of: 2, dir: dir,
      url: url, nodes: 1, tokenFor: tokenFor, log: log });
    t.check(alone.ok && alone.skipped && !fs.existsSync(path.join(dir,
      'request-1.json')), 'B. with no broker the run goes on without a ' +
      'restart, and says so', JSON.stringify(alone));

    t.log.info('=== C. a broker that restarts ===');
    timer = fakeBroker(dir, { ok: true, before: [], after: [] });
    const done = await clusterRestart.restart({ k: 1, of: 2, dir: dir,
      url: url, nodes: 1, tokenFor: tokenFor, log: log });
    t.check(done.ok && !done.skipped && done.containers &&
            done.before['node-a'] && done.after['node-a'] &&
            done.after['node-a'].isolates.length === 1 &&
            done.after['node-a'].cgroupMb === 2048,
            'C. the broker\'s answer is read, the node is live again, and ' +
            'its memory is recorded before and after', JSON.stringify(done));
    clearInterval(timer);

    t.log.info('=== D. a broker that could not ===');
    timer = fakeBroker(dir, { ok: false, why: 'sts was not healthy' });
    const failed = await clusterRestart.restart({ k: 2, of: 2, dir: dir,
      url: url, nodes: 1, tokenFor: tokenFor, log: log });
    t.check(!failed.ok && /not healthy/.test(failed.why),
            'D. a broker that could not restart a node is a failed restart',
            JSON.stringify(failed));
  } finally {
    if (timer) {
      clearInterval(timer);
    }
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving tool().");
}

async function run(t) {
  log.debug("Entering run().");
  await schedule(t);
  await tool(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_restart_points',
  describe: 'The cluster mode\'s restarts fall where STS_TEST_RESTART_POINTS ' +
            'says, with no job running; no broker means no restart, and a ' +
            'restart that did not come back is a failure (2026-11-18)',
  run: run
};
