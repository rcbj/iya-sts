// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: worker_minted_restore.js
//
// ===========================================================================
// A REQUEST WORKER DOES NOT READ BACK WHAT ONLY THE FRONT ANSWERS FROM (#617).
//
// On 8081 every process — the front and each request worker — restored the
// same 52,234 minted rows at every start, and 42,740 of them were
// `scheduler.runs`: the run history, read whole by /admin/scheduler and its
// API and by nothing else. A store declares `restoreInWorkers: false`
// (`common/realms.js`); a request worker's restore leaves its rows out of the
// query and out of the loop, and the scheduler's page and API are pinned to
// the front process, which restores everything as before. This holds:
//
//   1. the FRONT process restores every store, the declared one included,
//      and asks the store for no exclusion;
//   2. a REQUEST WORKER asks the store to leave the declared store's rows out
//      (`skipHandles`), restores every other store, and restores none of the
//      declared one's rows even from a driver that ignored the exclusion;
//   3. a worker that skipped the history still writes its own rows to it;
//   4. `scheduler.runs` is the store that declares it, and /admin/scheduler
//      and /admin-api/scheduler stay in the front process whatever
//      `workers.dispatch` says — the page reads what a worker no longer has.
//
// In process, over a driver that keeps rows in a Map and applies the same
// WHERE the postgres driver's query does.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'worker_minted_restore',
  level: process.env.LOG_LEVEL || 'info' });

const HISTORY = 'test.w617.history';
const SESSIONS = 'test.w617.sessions';

// A driver that keeps rows; `honour` false ignores `skipHandles`, which is
// what a driver written before #617 would do.
function mapDriver(honour) {
  log.debug("Entering mapDriver().");
  const rows = new Map();
  log.debug("Leaving mapDriver().");
  return {
    rows: rows,
    lastFilter: null,
    origin: function () {
      log.debug("Entering origin().");
      log.debug("Leaving origin().");
      return 'w617-origin';
    },
    loadMinted: function (filter) {
      log.debug("Entering loadMinted().");
      this.lastFilter = filter;
      const skip = honour ? (filter.skipHandles || []) : [];
      const out = Array.from(rows.values()).filter(function (row) {
        return filter.realms.indexOf(row.realm) >= 0 &&
          skip.indexOf(row.handle) < 0;
      });
      log.debug("Leaving loadMinted().");
      return Promise.resolve(out);
    },
    purgeExpiredMinted: function () {
      log.debug("Entering purgeExpiredMinted().");
      log.debug("Leaving purgeExpiredMinted().");
      return Promise.resolve(0);
    },
    saveMinted: function (upserts, deletes) {
      log.debug("Entering saveMinted().");
      upserts.forEach(function (row) {
        rows.set(row.handle + '\u0000' + row.realm + '\u0000' + row.key,
                 { handle: row.handle, realm: row.realm, key: row.key,
                   keySealed: row.keySealed || '', body: row.body,
                   writtenAt: Date.now(), expiresAt: null });
      });
      deletes.forEach(function (row) {
        rows.delete(row.handle + '\u0000' + row.realm + '\u0000' + row.key);
      });
      log.debug("Leaving saveMinted().");
      return Promise.resolve();
    },
    readMinted: function () {
      log.debug("Entering readMinted().");
      log.debug("Leaving readMinted().");
      return Promise.resolve(null);
    },
    purgeMinted: function () {
      log.debug("Entering purgeMinted().");
      log.debug("Leaving purgeMinted().");
      return Promise.resolve(0);
    }
  };
}

// Restores into empty stores as a front process or as a worker.
async function restoreAs(worker, minted, driver, stores) {
  log.debug("Entering restoreAs().");
  const had = process.env.STS_REQUEST_WORKER;
  stores.forEach(function (store) {
    store.clear();
  });
  minted.reset();
  minted.setDriver(driver, 'postgres');
  try {
    if (worker) {
      process.env.STS_REQUEST_WORKER = '1';
    } else {
      delete process.env.STS_REQUEST_WORKER;
    }
    log.debug("Leaving restoreAs().");
    return await minted.restore();
  } finally {
    if (had === undefined) {
      delete process.env.STS_REQUEST_WORKER;
    } else {
      process.env.STS_REQUEST_WORKER = had;
    }
  }
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-w617-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  const saved = {};
  ['STS_KEYS_SOURCE', 'STS_KEYS_KEK_PROVIDER', 'STS_KEYS_KEK_FILE']
    .forEach(function (name) {
      saved[name] = process.env[name];
    });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  const config = require('../common/config');
  const realms = require('../common/realms');
  const keystore = require('../common/keystore');
  const minted = require('../persistence/persistence_minted');
  try {
    keystore.reset();
    keystore.setStore({
      loadKeys: function () {
        log.debug("Entering loadKeys().");
        log.debug("Leaving loadKeys().");
        return Promise.resolve([]);
      },
      saveKeys: function () {
        log.debug("Entering saveKeys().");
        log.debug("Leaving saveKeys().");
        return Promise.resolve();
      },
      deleteKeys: function () {
        log.debug("Entering deleteKeys().");
        log.debug("Leaving deleteKeys().");
        return Promise.resolve();
      }
    });
    await keystore.start();
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);

    const history = realms.map({ persist: HISTORY, restoreInWorkers: false });
    const sessions = realms.map({ persist: SESSIONS });
    const stores = [history, sessions];
    const driver = mapDriver(true);
    minted.reset();
    minted.setDriver(driver, 'postgres');
    for (let i = 0; i < 40; i++) {
      history.set('run-' + i, { n: i, state: 'succeeded' });
    }
    for (let i = 0; i < 5; i++) {
      sessions.set('sid-' + i, { n: i });
    }
    await minted.flush();
    t.equal(driver.rows.size, 45, 'the rows are in the store');

    t.log.info('=== 1. the front process restores everything ===');
    await restoreAs(false, minted, driver, stores);
    t.check(history.size === 40 && sessions.size === 5 &&
            (driver.lastFilter.skipHandles || []).length === 0,
            'the front restores the history and the sessions, and asks for ' +
            'no exclusion', JSON.stringify({ history: history.size,
              sessions: sessions.size, skip: driver.lastFilter.skipHandles }));

    t.log.info('=== 2. a request worker leaves the history out ===');
    await restoreAs(true, minted, driver, stores);
    t.check(history.size === 0 && sessions.size === 5 &&
            driver.lastFilter.skipHandles.indexOf(HISTORY) >= 0 &&
            driver.lastFilter.skipHandles.indexOf(SESSIONS) < 0,
            'a worker asks the store to leave the declared store out, and ' +
            'restores every other store', JSON.stringify({
              history: history.size, sessions: sessions.size,
              skip: driver.lastFilter.skipHandles }));
    const ignoring = mapDriver(false);
    driver.rows.forEach(function (row, key) {
      ignoring.rows.set(key, row);
    });
    await restoreAs(true, minted, ignoring, stores);
    t.check(history.size === 0 && sessions.size === 5,
            'and restores none of its rows even from a driver that returned ' +
            'them anyway', JSON.stringify({ history: history.size,
              sessions: sessions.size }));

    t.log.info('=== 3. a worker still writes its own rows ===');
    minted.reset();
    minted.setDriver(driver, 'postgres');
    history.set('run-worker', { n: 99, state: 'succeeded' });
    await minted.flush();
    const written = Array.from(driver.rows.values()).filter(function (row) {
      return row.handle === HISTORY;
    }).length;
    t.equal(written, 41, 'a run row a worker writes reaches the store');

    t.log.info('=== 4. the scheduler\'s history, and its page ===');
    require('../cluster/scheduler');
    const runs = realms.handleFor('scheduler.runs');
    t.check(!!runs && runs.restoreInWorkers === false,
            'scheduler.runs is the store a request worker does not restore',
            JSON.stringify(runs ? { restoreInWorkers: runs.restoreInWorkers }
                                : null));
    const pool = require('../common/request_pool');
    const hadDispatch = process.env.STS_WORKERS_DISPATCH;
    process.env.STS_WORKERS_DISPATCH = '*';
    try {
      ['/admin/scheduler', '/admin-api/scheduler',
       '/admin-api/scheduler/run', '/realm/acme/admin-api/scheduler']
        .forEach(function (url) {
          t.check(pool.dispatched(url) === false,
                  url + ' stays in the front process, which restored the ' +
                  'history', String(pool.dispatched(url)));
        });
      t.check(pool.dispatched('/admin-api/config') === true,
              'while the rest of the console is still dispatched',
              String(pool.dispatched('/admin-api/config')));
    } finally {
      if (hadDispatch === undefined) {
        delete process.env.STS_WORKERS_DISPATCH;
      } else {
        process.env.STS_WORKERS_DISPATCH = hadDispatch;
      }
    }
  } finally {
    minted.reset();
    config.clearOverride('global.mode');
    config.clearOverride('persistence.minted');
    Object.keys(saved).forEach(function (name) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    });
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'worker_minted_restore',
  describe: 'a request worker does not restore a store only the front ' +
            'process answers from (scheduler.runs), and the scheduler\'s ' +
            'page and API stay in the front process (#617)',
  run: run
};
