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
//      and asks the store for no exclusion (this section runs before
//      `scheduler.runs` is declared, so its null-expiry list is empty);
//   2. a REQUEST WORKER asks the store to leave the declared store's rows out
//      (`skipHandles`), restores every other store, and restores none of the
//      declared one's rows even from a driver that ignored the exclusion;
//   3. a worker that skipped the history still writes its own rows to it;
//   4. `scheduler.runs` is the store that declares it, and /admin/scheduler
//      and /admin-api/scheduler stay in the front process whatever
//      `workers.dispatch` says — the page reads what a worker no longer has;
//   5. the front still restores a null-expiry operational row of
//      `scheduler.runs`, and does not restore a finished interval run
//      (#883). Workers still skip the whole handle.
//
// In process, over a driver that keeps rows in a Map. It applies the
// postgres `skipHandles` clause. It does not apply the null-expiry clause:
// section 5 is the restore loop dropping an expiring `scheduler.runs` row
// a driver returned anyway.
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
                   writtenAt: Date.now(),
                   expiresAt: row.expiresAt == null ? null
                     : Number(row.expiresAt) });
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
  ['STS_KEYS_SOURCE', 'STS_KEYS_KEK_PROVIDER', 'STS_KEYS_KEK_FILE',
   'STS_AUTHN_SESSION_WINDOW']
    .forEach(function (name) {
      saved[name] = process.env[name];
    });
  process.env.STS_KEYS_SOURCE = 'persisted';
  // THE SESSION WINDOW OFF (#350): this is about the run history's
  // exclusion, and with minted persistence on and a digest key the default
  // `auto` would leave `authn.sessions` out of the restore as well
  // (`tests/session_window.js` holds that half).
  process.env.STS_AUTHN_SESSION_WINDOW = 'off';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
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
    t.check(!!runs && runs.restoreInWorkers === false &&
            runs.restoreExpiring === false &&
            typeof runs.sortOf === 'function',
            'scheduler.runs is the store a request worker does not restore, ' +
            'and the front does not restore an expiring row of it (#883)',
            JSON.stringify(runs ? { restoreInWorkers: runs.restoreInWorkers,
                                    restoreExpiring: runs.restoreExpiring,
                                    sortOf: typeof runs.sortOf } : null));
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

    t.log.info('=== 5. the front restores no expiring run (#883) ===');
    const mod = require('../cluster/scheduler');
    const fresh = mapDriver(true);
    minted.reset();
    minted.setDriver(fresh, 'postgres');
    const leader = { runId: 'leader', kind: 'leader', state: 'leading' };
    const done = { runId: 's-883-done', kind: 'run',
                   jobId: 'scheduler.history', realm: 'default',
                   trigger: 'schedule', state: 'succeeded',
                   endedAt: Date.now(), startedAt: Date.now() - 1000,
                   queuedAt: Date.now() - 2000 };
    mod.runStore.set('leader', leader);
    mod.runStore.set('s-883-done', done);
    await minted.flush();
    const storedRows = Array.from(fresh.rows.values()).filter(
      function (row) {
        return row.handle === 'scheduler.runs';
      });
    t.check(storedRows.length === 2 &&
            storedRows.some(function (row) {
              return row.expiresAt == null;
            }) &&
            storedRows.some(function (row) {
              return row.expiresAt != null;
            }),
            'the flush kept a null expiry and an expiry',
            JSON.stringify(storedRows.map(function (row) {
              return row.expiresAt;
            })));
    await restoreAs(false, minted, fresh, [mod.runStore]);
    t.check(!!mod.runStore.get('leader') && !mod.runStore.get('s-883-done'),
            'the front restores the leader and not a finished interval run',
            JSON.stringify({
              leader: !!mod.runStore.get('leader'),
              done: !!mod.runStore.get('s-883-done') }));
    t.check((fresh.lastFilter.nullExpiryHandles || [])
              .indexOf('scheduler.runs') >= 0,
            'and asks the store to leave expiring scheduler.runs rows out',
            JSON.stringify(fresh.lastFilter &&
                           fresh.lastFilter.nullExpiryHandles));
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
            'process answers from (scheduler.runs), the scheduler\'s page ' +
            'and API stay in the front process (#617), and the front does ' +
            'not restore an expiring run (#883)',
  run: run
};
