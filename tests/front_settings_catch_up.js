// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: front_settings_catch_up.js
//
// ===========================================================================
// THE FRONT PROCESS CATCHES UP ON A SETTINGS WRITE (found in #2019; rcbj,
// 2026-11-23: "catch up on change"). `persistence/persistence.js`'s *THE
// SETTINGS GENERATION* argues it; this holds each half in process:
//
//   A. the header is spelt alike by the worker and the pool;
//   B. a worker's answer is marked `x-sts-pool-settings` when the settings
//      generation moved while it was answered, and not otherwise — over a
//      real HTTP server, `res.end()` and `res.writeHead()` alike;
//   C. the front holds a marked answer until its catch-up resolves, and
//      forwards an unmarked one at once; answers marked while a catch-up
//      runs share ONE queued catch-up that starts after it; a catch-up that
//      runs out still forwards the answer;
//   D. `syncSettingsNow()` reports behind when the log is behind, and a
//      worker's `{ settingsCommitted }` wakes the front's pull
//      (`nudgeSettingsPull()`, the change log's `wake()`);
//   E. in a CHILD over a real `ldif` store (its own process, so no other
//      file's store is touched): a process-wide setting and a realm's
//      override each move the generation, a directory-free flush of them
//      announces `{ settingsCommitted }` on the worker channel once it has
//      written, and nothing else moves it.
//
// What it does not hold: a real worker thread and a real store together,
// which `tests/protocol/sts_cert_sign_in_profiles.js` E1/E3 drive over HTTP.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'front_settings_catch_up',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// A server whose one handler is given the answer; resolves with the headers
// a client received.
function answerOnce(handler) {
  log.debug("Entering answerOnce().");
  return new Promise(function (resolve, reject) {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', function () {
      http.get({ host: '127.0.0.1', port: server.address().port, path: '/' },
        function (res) {
          res.resume();
          res.on('end', function () {
            server.close();
            resolve(res.headers);
          });
        }).on('error', function (e) {
        server.close();
        reject(e);
      });
    });
  }).then(function (headers) {
    log.debug("Leaving answerOnce().");
    return headers;
  });
}

async function checkMarking(t, worker, pool) {
  log.debug("Entering checkMarking().");
  t.check(worker.SETTINGS_HEADER === pool.SETTINGS_HEADER &&
          worker.SETTINGS_HEADER === 'x-sts-pool-settings',
          'A1. the worker and the pool spell the settings header alike',
          worker.SETTINGS_HEADER + ' / ' + pool.SETTINGS_HEADER);
  const RequestWorker = worker.RequestWorker;
  let gen = 5;
  const store = { settingsGeneration: function () {
    return gen;
  } };
  const moved = await answerOnce(function (req, res) {
    RequestWorker.markSettingsAnswer(res, store);
    gen++;
    res.end('ok');
  });
  t.check(moved['x-sts-pool-settings'] === '1',
          'B1. an answer during which the settings generation moved is ' +
          'marked (res.end())', JSON.stringify(moved));
  const still = await answerOnce(function (req, res) {
    RequestWorker.markSettingsAnswer(res, store);
    res.end('ok');
  });
  t.check(still['x-sts-pool-settings'] === undefined,
          'B2. an answer during which it did not move is not marked',
          JSON.stringify(still));
  const explicit = await answerOnce(function (req, res) {
    RequestWorker.markSettingsAnswer(res, store);
    gen++;
    res.writeHead(201, { 'content-type': 'text/plain' });
    res.end('ok');
  });
  t.check(explicit['x-sts-pool-settings'] === '1' &&
          explicit['content-type'] === 'text/plain',
          'B3. an explicit writeHead() with headers of its own is marked too',
          JSON.stringify(explicit));
  log.debug("Leaving checkMarking().");
}

async function checkHolding(t, pool, persistence) {
  log.debug("Entering checkHolding().");
  const saved = persistence.syncSettingsNow;
  const asked = [];
  try {
    persistence.syncSettingsNow = function () {
      return new Promise(function (resolve) {
        asked.push(resolve);
      });
    };
    const forwarded = [];
    const onAnswer = function (answer) {
      forwarded.push(answer.name);
    };
    pool.holdForSettings({ name: 'plain', headers: {} }, onAnswer, '/p');
    t.check(forwarded.join() === 'plain' && asked.length === 0,
            'C1. an unmarked answer is forwarded at once, with no catch-up');
    const marked = { 'x-sts-pool-settings': '1' };
    pool.holdForSettings({ name: 'm1', headers: marked }, onAnswer, '/m');
    await Promise.resolve();
    await Promise.resolve();
    t.check(forwarded.join() === 'plain' && asked.length === 1,
            'C2. a marked answer waits for the front\'s catch-up',
            JSON.stringify({ forwarded: forwarded, asked: asked.length }));
    pool.holdForSettings({ name: 'm2', headers: marked }, onAnswer, '/m');
    pool.holdForSettings({ name: 'm3', headers: marked }, onAnswer, '/m');
    await new Promise(setImmediate);
    t.check(asked.length === 1,
            'C3. answers marked while a catch-up runs start none of their own');
    asked[0]({ caughtUp: true, coordinating: true });
    await new Promise(setImmediate);
    t.check(forwarded.join() === 'plain,m1' && asked.length === 2,
            'C4. the first answer goes once its catch-up is done, and the ' +
            'two that arrived meanwhile share ONE catch-up started after it',
            JSON.stringify({ forwarded: forwarded, asked: asked.length }));
    asked[1]({ caughtUp: false, coordinating: true });
    await new Promise(setImmediate);
    t.check(forwarded.join() === 'plain,m1,m2,m3' && asked.length === 2,
            'C5. a catch-up that runs out still forwards what waited on it ' +
            '(STS-WORKER-0058)', JSON.stringify(forwarded));
  } finally {
    persistence.syncSettingsNow = saved;
  }
  log.debug("Leaving checkHolding().");
}

async function checkPulls(t, pool, persistence) {
  log.debug("Entering checkPulls().");
  const replication = require('../persistence/persistence_replication');
  const savedSync = replication.syncNow;
  const savedWake = replication.wake;
  let woken = 0;
  try {
    replication.syncNow = function () {
      return Promise.resolve({ caughtUp: false, coordinating: true });
    };
    replication.wake = function () {
      woken++;
    };
    const behind = await persistence.syncSettingsNow();
    t.check(behind.caughtUp === false && behind.coordinating === true,
            'D1. syncSettingsNow() says behind when the log is behind',
            JSON.stringify(behind));
    replication.syncNow = function () {
      return Promise.resolve({ caughtUp: false, coordinating: false });
    };
    const off = await persistence.syncSettingsNow();
    t.check(off.caughtUp === true && off.coordinating === false,
            'D2. with nothing to coordinate there is nothing to catch up on',
            JSON.stringify(off));
    const before = pool.settingsCatchUpCounts().nudges;
    pool.receiveSettingsCommitted();
    t.check(woken === 1 && pool.settingsCatchUpCounts().nudges === before + 1,
            'D3. a worker\'s settingsCommitted wakes this process\'s pull now',
            'woken ' + woken);
  } finally {
    replication.syncNow = savedSync;
    replication.wake = savedWake;
  }
  log.debug("Leaving checkPulls().");
}

// THE CHILD: a real ldif store, the channel's send() replaced.
function childMain() {
  const out = process.env.FS_OUT;
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what, detail: detail || '' });
  };
  process.env.STS_PERSISTENCE_MODE = 'ldif';
  process.env.STS_PERSISTENCE_DATA_DIR = process.env.FS_DIR;
  process.env.STS_PERSISTENCE_APPCONFIG = 'true';
  process.env.STS_PERSISTENCE_REALMS = 'true';
  process.env.STS_PERSISTENCE_WRITE_DELAY = '0';
  const root = process.env.FS_ROOT;
  const channel = require(root + '/common/worker_channel');
  const sent = [];
  channel.send = function (message) {
    sent.push(message);
  };
  const config = require(root + '/common/config');
  const realms = require(root + '/common/realms');
  const persistence = require(root + '/persistence/persistence');
  persistence.setDirectory({
    realmEntries: function () {
      return [];
    },
    replaceRealm: function () {
      return undefined;
    }
  });
  (async function () {
    await persistence.start();
    note(persistence.enabled(), 'E0. the ldif store opened',
         String(persistence.status().lastError || ''));
    await persistence.flush();
    sent.length = 0;
    const g0 = persistence.settingsGeneration();
    await persistence.flush();
    note(persistence.settingsGeneration() === g0 && !sent.some(function (m) {
      return m && m.settingsCommitted;
    }), 'E1. a flush with no realm or settings change moves nothing and ' +
         'announces nothing', JSON.stringify(sent));
    const set = config.setOverride('tls.trustedProxyAddresses',
                                   '10.20.0.0/24');
    const g1 = persistence.settingsGeneration();
    note(set && set.ok !== false && g1 > g0,
         'E2. a process-wide setting moves the settings generation',
         JSON.stringify({ set: set, g0: g0, g1: g1 }));
    await persistence.flush();
    note(sent.filter(function (m) {
      return m && m.settingsCommitted;
    }).length >= 1, 'E3. its flush announces settingsCommitted on the ' +
         'worker channel once it has written', JSON.stringify(sent));
    sent.length = 0;
    const made = realms.create({ id: 'fscu', name: 'fscu',
                                 description: 'front_settings_catch_up' });
    note(made && made.ok, 'E4a. a realm of its own', JSON.stringify(made));
    await persistence.flush();
    sent.length = 0;
    const g2 = persistence.settingsGeneration();
    const realmSet = realms.run('fscu', function () {
      return config.setOverride('tls.trustedProxyAddresses', '10.30.0.0/24');
    });
    const g3 = persistence.settingsGeneration();
    await persistence.flush();
    note(realmSet && realmSet.ok !== false && g3 > g2 &&
         sent.some(function (m) {
           return m && m.settingsCommitted;
         }), 'E4. a realm\'s override moves it too, and its flush announces',
         JSON.stringify({ realmSet: realmSet, g2: g2, g3: g3, sent: sent }));
    realms.remove('fscu');
    config.clearOverride('tls.trustedProxyAddresses');
    await persistence.stop();
  })().catch(function (e) {
    note(false, 'the child ran to the end', String((e && e.stack) || e));
  }).then(function () {
    fs.writeFileSync(out, JSON.stringify(findings));
    process.exit(0);
  });
}

function runChild() {
  log.debug("Entering runChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-fscu-'));
  const out = path.join(dir, 'findings.json');
  fs.mkdirSync(path.join(dir, 'store'));
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_(?!TEST_)|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', FS_ROOT: ROOT,
                                  FS_OUT: out,
                                  FS_DIR: path.join(dir, 'store') }),
      encoding: 'utf8', timeout: 120000, cwd: ROOT });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
  }
  log.debug("Leaving runChild().");
  return { findings: findings, result: result };
}

async function run(t) {
  log.debug("Entering run().");
  const pool = require('../common/request_pool');
  const worker = require('../common/request_worker');
  const persistence = require('../persistence/persistence');
  await checkMarking(t, worker, pool);
  await checkHolding(t, pool, persistence);
  await checkPulls(t, pool, persistence);
  const got = runChild();
  if (t.check(Array.isArray(got.findings), 'E: the child process reported ' +
              'its findings', 'exit ' + got.result.status + ' ' +
              String(got.result.stderr || '').slice(-1500))) {
    got.findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'front_settings_catch_up',
  describe: 'a settings write made in a request worker is caught up by the ' +
            'front process before its answer is forwarded, and its commit ' +
            'wakes the front\'s pull (#2019, "catch up on change")',
  run: run
};
