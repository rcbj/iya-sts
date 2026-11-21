// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// ===========================================================================
// tests/tools/cluster-restart.js — THE CLUSTER RESTARTED PART WAY THROUGH A
// RUN, FROM THE RUNNER'S SIDE (rcbj, 2026-11-18: "Restart the cluster a
// couple of times during the test run").
//
// **WHY.** The cluster mode is the one mode that ran its runner into swap:
// two product nodes of five isolates each, every realm the suite made held in
// all ten, for the whole of an eighty-minute run (tests/CLAUDE.md, *The
// cluster restarted during the run*). A restart puts every node back to what
// the store holds, which is both a footprint the rest of the run starts from
// and a test in itself: product persistence has to carry every realm, key,
// session and token across it, and a job after the restart that fails where
// it passed before is a persistence finding.
//
// **WHO DOES WHAT.** The runner is a container with no docker of its own, so
// the restart itself is the launcher's: `run-tests.sh`'s
// `clusterRestartBroker()` watches `STS_TEST_RESTART_DIR` (a directory of
// the bind-mounted report tree) for `request-<k>.json`, restarts each node in
// turn through its bounded docker calls, waits for each to be healthy, and
// answers `done-<k>.json` with each container's memory before and after.
// This file writes the request when `run-report.js` has drained the lanes,
// waits for the answer, waits until every node is a live member again, and
// reads each node's own memory (`/admin-api/node-health`: every isolate's
// heap, which no `docker stats` can see) before and after.
//
// **NO BROKER, NO RESTART.** `broker.ready` is written by the launcher when
// it starts listening; a run without it — a hand-run `run-report.js`, an AWS
// target — is told so once per point and goes on. A restart that was asked
// for and did not come back is a FAILURE of the run (`run-report.js`): every
// job after it would be measuring a cluster that is not the mode's.
// ===========================================================================

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const serviceTrust = require('./service_trust');

const log = require('bunyan').createLogger({ name: 'cluster-restart',
  level: process.env.LOG_LEVEL || 'info' });

/**
 * Resolves after `ms`. A pause between polls of a file and of the cluster,
 * inside one bounded wait.
 *
 * @param {number} ms - how long
 * @returns {Promise<void>} when it has passed
 */
function pause(ms) {
  log.debug('Entering pause().');
  return new Promise(function (resolve) {
    setTimeout(function () {
      log.debug('Leaving pause().');
      resolve();
    }, ms);
  });
}

/**
 * One GET on a NEW connection (`agent: false`), so the balancer may hand it
 * to either node. The certificate is the run's own, as admin-api-token.js
 * argues for the same service.
 *
 * @param {string} url - where
 * @param {string} token - the bearer token
 * @returns {Promise<{status: number, json: object|null}>} the answer
 */
function getJson(url, token) {
  log.debug('Entering getJson().');
  return new Promise(function (resolve) {
    const u = new URL(url);
    const mod = u.protocol === 'http:' ? http : https;
    // Verified against the chain the runner fetched (useBundle() in
    // run-report.js): this carries the run's management-API token.
    let ca;
    try {
      ca = u.protocol === 'http:' ? undefined : serviceTrust.trustedCa();
    } catch (e) {
      log.debug('Caught in getJson(): ' + ((e && e.message) || e));
      log.debug('Leaving getJson(). No truststore.');
      resolve({ status: 0, json: null });
      return;
    }
    const req = mod.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method: 'GET', agent: false, ca: ca,
      timeout: 30000,
      headers: { authorization: 'Bearer ' + token }
    }, function (res) {
      let text = '';
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch (e) {
          log.debug('Caught in getJson(): ' + ((e && e.message) || e));
          json = null;
        }
        log.debug('Leaving getJson().');
        resolve({ status: res.statusCode, json: json });
      });
    });
    req.on('timeout', function () {
      req.destroy(new Error('no answer within 30s'));
    });
    req.on('error', function (e) {
      log.debug('Caught in getJson(): ' + ((e && e.message) || e));
      log.debug('Leaving getJson(). No answer.');
      resolve({ status: 0, json: null });
    });
    req.end();
  });
}

/**
 * Megabytes, one decimal.
 *
 * @param {number} bytes - the bytes
 * @returns {number} the megabytes
 */
function mb(bytes) {
  log.debug('Entering mb().');
  log.debug('Leaving mb().');
  return Math.round((Number(bytes) || 0) / 104857.6) / 10;
}

/**
 * Every node's own memory, as `/admin-api/node-health` draws it: the
 * container's cgroup figure and each isolate's heap. Asked on new
 * connections until `nodes` different nodes have answered or the tries run
 * out; a node that never answered is simply absent.
 *
 * @param {string} url - the service (the balancer, in the cluster mode)
 * @param {string} token - an /admin-api token
 * @param {number} nodes - how many nodes to expect
 * @returns {Promise<object>} node name to `{ cgroupMb, anonMb, isolates }`
 */
async function nodeMemory(url, token, nodes) {
  log.debug('Entering nodeMemory().');
  const out = {};
  for (let i = 0; i < Math.max(4, nodes * 6) &&
       Object.keys(out).length < nodes; i++) {
    const r = await getJson(url + '/admin-api/node-health', token);
    const j = r.json;
    if (r.status !== 200 || !j || !j.node || out[j.node]) {
      continue;
    }
    out[j.node] = {
      cgroupMb: mb(j.memory && j.memory.currentBytes),
      anonMb: mb(j.memory && j.memory.anonBytes),
      isolates: ((j.processes && j.processes.rows) || [])
        .map(function (row) {
          return { role: row.role, threadId: row.threadId,
                   rssMb: mb(row.rssBytes),
                   heapUsedMb: mb(row.heapUsedBytes),
                   heapTotalMb: mb(row.heapTotalBytes) };
        })
    };
  }
  log.debug('Leaving nodeMemory(). ' + Object.keys(out).length + ' node(s).');
  return out;
}

/**
 * Waits until `nodes` members are live by the database's clock (the rule
 * sts_cluster_alternation.js holds) and the service answers, or the bound
 * passes. Answers whether it got there.
 *
 * @param {string} url - the service
 * @param {Function} tokenFor - mints an /admin-api token for a base URL
 * @param {number} nodes - how many live members to wait for
 * @param {number} boundMs - the bound
 * @returns {Promise<boolean>} whether every node is live
 */
async function waitForMembers(url, tokenFor, nodes, boundMs) {
  log.debug('Entering waitForMembers().');
  const until = Date.now() + boundMs;
  while (Date.now() < until) {
    let token = '';
    try {
      token = await tokenFor(url);
    } catch (e) {
      // The token endpoint is the first thing a restarted node answers
      // wrongly or not at all; asked again on the next pass.
      log.debug('Caught in waitForMembers(): ' + ((e && e.message) || e));
      token = '';
    }
    if (token) {
      const r = await getJson(url + '/admin-api/cluster', token);
      const report = (r.json && r.json.status) || {};
      const live = (report.nodes || []).filter(function (n) {
        return n && !n.leftAt &&
          Number(n.expiresAt) > Number(report.databaseNow);
      });
      if (r.status === 200 && (nodes < 2 || live.length >= nodes)) {
        log.debug('Leaving waitForMembers(). Live.');
        return true;
      }
    }
    await pause(2000);
  }
  log.debug('Leaving waitForMembers(). The bound passed.');
  return false;
}

/**
 * One restart: the request to the launcher, its answer, the cluster back,
 * and every node's memory either side. Never throws; answers `{ k, of, ok,
 * skipped, why, ms, before, after, containers }`.
 *
 * @param {object} args - `{ k, of, dir, url, nodes, tokenFor, log }`
 * @returns {Promise<object>} the record of the restart
 */
async function restart(args) {
  log.debug('Entering restart(). ' + args.k + ' of ' + args.of);
  const say = args.log || log;
  const started = Date.now();
  const record = { k: args.k, of: args.of, ok: false, skipped: false,
                   why: '', ms: 0, before: {}, after: {}, containers: null };
  if (!args.dir || !fs.existsSync(path.join(args.dir, 'broker.ready'))) {
    record.ok = true;
    record.skipped = true;
    record.why = 'no launcher is listening for a restart (' +
      (args.dir || 'STS_TEST_RESTART_DIR is unset') + '), so the cluster ' +
      'was not restarted';
    say.warn('cluster restart ' + args.k + ' of ' + args.of + ' skipped: ' +
             record.why);
    log.debug('Leaving restart(). No broker.');
    return record;
  }
  const boundMs = (Number(process.env.STS_TEST_RESTART_BOUND_S) || 900) *
    1000;
  try {
    record.before = await nodeMemory(args.url, await args.tokenFor(args.url),
                                     args.nodes);
  } catch (e) {
    log.debug('Caught in restart(): ' + ((e && e.message) || e));
    record.before = {};
  }
  say.info('cluster restart ' + args.k + ' of ' + args.of + ': no job is ' +
           'running; asking the launcher to restart every node. Before: ' +
           summary(record.before));
  const request = path.join(args.dir, 'request-' + args.k + '.json');
  const done = path.join(args.dir, 'done-' + args.k + '.json');
  fs.writeFileSync(request + '.tmp', JSON.stringify({ k: args.k,
    of: args.of, at: new Date().toISOString() }) + '\n');
  fs.renameSync(request + '.tmp', request);
  const until = Date.now() + boundMs;
  let answer = null;
  while (Date.now() < until && !answer) {
    if (fs.existsSync(done)) {
      try {
        answer = JSON.parse(fs.readFileSync(done, 'utf8'));
      } catch (e) {
        log.debug('Caught in restart(): ' + ((e && e.message) || e));
        answer = { ok: false, why: 'its answer could not be read' };
      }
    } else {
      await pause(2000);
    }
  }
  if (!answer) {
    record.why = 'the launcher did not answer within ' + (boundMs / 1000) +
      's';
  } else if (!answer.ok) {
    record.why = 'the launcher could not restart it: ' + (answer.why || '');
    record.containers = answer;
  } else {
    record.containers = answer;
    const back = await waitForMembers(args.url, args.tokenFor, args.nodes,
                                      Math.max(60000, until - Date.now()));
    if (!back) {
      record.why = 'every node restarted and they were not all live ' +
        'members again within the bound';
    } else {
      record.ok = true;
      try {
        record.after = await nodeMemory(args.url,
                                        await args.tokenFor(args.url),
                                        args.nodes);
      } catch (e) {
        log.debug('Caught in restart(): ' + ((e && e.message) || e));
        record.after = {};
      }
    }
  }
  record.ms = Date.now() - started;
  if (record.ok) {
    say.info('cluster restart ' + args.k + ' of ' + args.of + ' done in ' +
             Math.round(record.ms / 1000) + 's. After: ' +
             summary(record.after));
  } else {
    say.error('cluster restart ' + args.k + ' of ' + args.of + ' FAILED: ' +
              record.why);
  }
  log.debug('Leaving restart().');
  return record;
}

/**
 * One line per node: its cgroup figure and the sum of its isolates' heaps.
 *
 * @param {object} nodes - what nodeMemory() answered
 * @returns {string} the line
 */
function summary(nodes) {
  log.debug('Entering summary().');
  const names = Object.keys(nodes || {}).sort();
  if (!names.length) {
    log.debug('Leaving summary(). None.');
    return '(no node answered)';
  }
  log.debug('Leaving summary().');
  return names.map(function (name) {
    const one = nodes[name];
    const heap = one.isolates.reduce(function (s, row) {
      return s + row.heapUsedMb;
    }, 0);
    return name + ' ' + one.cgroupMb + ' MB (heap ' +
      Math.round(heap) + ' MB in ' + one.isolates.length + ' isolate(s))';
  }).join('; ');
}

module.exports = { restart, nodeMemory, summary };
