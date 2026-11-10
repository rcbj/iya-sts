// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: replication_restore_floor.js
//
// ===========================================================================
// THE TWO CHANGE LOGS START FROM THE HEADS TAKEN WHEN THE STORE OPENED (#619).
//
// `coordinate()` used to read each log's head after the restore and treat
// everything at or below it as already applied. A change committed after a
// table was read and before that call was in neither place. The cell log's
// head has been sampled at open since #804. The global log, present only
// when `cells.id` is set, was still read at `coordinate()`. The two sequence
// numbers are not one number: the global follower must not be given the
// cell's seq, and the session-index floor is a cell seq too.
//
// In a child, because it opens two databases through the whole of `start()`
// and then `coordinate()`. The parent process stays in whatever mode the
// suite started it in.
// ===========================================================================

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'replication-restore-floor',
  level: process.env.LOG_LEVEL || 'info' });

const CHILD_FLAG = 'STS_TEST_REPLICATION_FLOOR_CHILD';

function rowsOf(list) {
  log.debug("Entering rowsOf().");
  log.debug("Leaving rowsOf().");
  return Promise.resolve({ rows: list, rowCount: list.length });
}

function makeLog() {
  log.debug("Entering makeLog().");
  const db = { log: [], maxes: [] };
  db.query = function answer(sql, params) {
    log.debug("Entering answer().");
    const text = String((sql && sql.text) || sql).replace(/\s+/g, ' ').trim();
    const bound = params || (sql && sql.values) || [];
    let out = null;
    if (/^SELECT to_regclass/.test(text)) {
      const one = {};
      for (let i = 0; i < 200; i++) {
        one['o' + i] = 'present';
      }
      out = rowsOf([one]);
    } else if ((/SELECT COALESCE\(MAX\(seq\), 0\) AS seq FROM sts_changes/
                 .test(text) ||
               /sts:(latestChangeSeq|changeCeiling) /.test(text))) {
      db.maxes.push(db.log.length);
      if (db.openedAt === undefined) {
        db.openedAt = db.log.length;
      }
      out = rowsOf([{ seq: db.log.length }]);
    } else if (/sts:changesSince /.test(text)) {
      const after = Number(bound[0]);
      const limit = Number(bound[1]) || 500;
      out = rowsOf(db.log.filter(function (row) {
        return row.seq > after;
      }).slice(0, limit));
    } else {
      out = rowsOf([]);
    }
    log.debug("Leaving answer().");
    return out;
  };
  log.debug("Leaving makeLog().");
  return db;
}

function databaseFor(settings) {
  log.debug("Entering databaseFor().");
  const url = String((settings && settings.connectionString) || '');
  let db = null;
  if (url.indexOf('/global') >= 0) {
    db = globalDb;
  } else if (url.indexOf('/cell') >= 0) {
    db = cellDb;
  } else {
    throw new Error('a pool named neither database: ' + url);
  }
  log.debug("Leaving databaseFor().");
  return db;
}

let cellDb = null;
let globalDb = null;

function installPools() {
  log.debug("Entering installPools().");
  cellDb = makeLog();
  globalDb = makeLog();
  function FakeClient(settings) {
    this.db = databaseFor(settings);
  }
  FakeClient.prototype.query = function (sql, params) {
    return this.db.query(sql, params);
  };
  FakeClient.prototype.release = function () {
    log.debug("Entering release().");
    log.debug("Leaving release().");
  };
  FakeClient.prototype.on = function () {
    log.debug("Entering on().");
    log.debug("Leaving on().");
    return this;
  };
  FakeClient.prototype.removeListener = function () {
    log.debug("Entering removeListener().");
    log.debug("Leaving removeListener().");
    return this;
  };
  FakeClient.prototype.connect = function () {
    log.debug("Entering connect().");
    log.debug("Leaving connect().");
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    log.debug("Entering end().");
    log.debug("Leaving end().");
    return Promise.resolve();
  };
  function FakePool(settings) {
    this.settings = settings;
    this.db = databaseFor(settings);
  }
  FakePool.prototype.on = function () {
    log.debug("Entering on().");
    log.debug("Leaving on().");
    return this;
  };
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient(this.settings));
  };
  FakePool.prototype.query = function (sql, params) {
    return this.db.query(sql, params);
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  require('./tools/store_double').install({
    Pool: FakePool, Client: FakeClient });
  log.debug("Leaving installPools().");
}

function replaceKeystoreStart(keystore) {
  log.debug("Entering replaceKeystoreStart().");
  // The real module stays loaded. helpers.js calls keystore.onAdopt when
  // the scheduler is required, and checkCells asks persists(), sealed()
  // and hasEphemeralKek(). Only start() is replaced, so this child does
  // not read a key-encryption key or write keys through the double.
  keystore.start = function () {
    log.debug("Entering keystore start().");
    log.debug("Leaving keystore start().");
    return Promise.resolve({ persisting: true, loaded: 0, pki: 0 });
  };
  log.debug("Leaving replaceKeystoreStart().");
}

function seed(db, count) {
  log.debug("Entering seed().");
  for (let i = 0; i < count; i++) {
    db.log.push({ seq: db.log.length + 1, origin: 'another-process',
                  kind: 'appconfig', realm: '', key: 'already-there' });
  }
  log.debug("Leaving seed().");
}

function commitDuringRestore(db) {
  log.debug("Entering commitDuringRestore().");
  db.log.push({ seq: db.log.length + 1, origin: 'another-process',
                kind: 'appconfig', realm: '', key: 'during-restore' });
  log.debug("Leaving commitDuringRestore().");
}

function hookReplication(replication, seen) {
  log.debug("Entering hookReplication().");
  const realStart = replication.start;
  const realCreate = replication.createReplication;
  replication.start = function cellStart(theDriver, theAppliers, from) {
    log.debug("Entering cellStart().");
    seen.cell = arguments.length < 3 ? null : from;
    log.debug("Leaving cellStart().");
    return realStart.apply(this, arguments);
  };
  replication.createReplication = function create(label) {
    log.debug("Entering create().");
    const instance = realCreate.apply(this, arguments);
    if (label === 'global' && instance &&
        typeof instance.start === 'function') {
      const real = instance.start;
      instance.start = function globalStart(theDriver, theAppliers, from) {
        log.debug("Entering globalStart().");
        seen.global = arguments.length < 3 ? null : from;
        log.debug("Leaving globalStart().");
        return real.apply(this, arguments);
      };
    }
    log.debug("Leaving create().");
    return instance;
  };
  log.debug("Leaving hookReplication().");
}

async function childMain() {
  log.debug("Entering childMain().");
  const report = { ok: false, threw: null };
  let persistence = null;
  try {
    installPools();
    seed(cellDb, 5);
    seed(globalDb, 3);
    persistence = require('../persistence/persistence');
    replaceKeystoreStart(require('../common/keystore'));
    persistence.setDirectory({
      realmEntries: function () {
        log.debug("Entering realmEntries().");
        log.debug("Leaving realmEntries().");
        return [];
      },
      replaceRealm: function () {
        log.debug("Entering replaceRealm().");
        log.debug("Leaving replaceRealm().");
      }
    });
    await persistence.start();
    commitDuringRestore(cellDb);
    commitDuringRestore(globalDb);
    const seen = { cell: null, global: null };
    hookReplication(require('../persistence/persistence_replication'), seen);
    await persistence.coordinate();
    report.ok = true;
    report.cellFrom = seen.cell;
    report.globalFrom = seen.global;
    report.cellOpened = cellDb.openedAt;
    report.globalOpened = globalDb.openedAt;
    report.cellHead = cellDb.log.length;
    report.globalHead = globalDb.log.length;
    report.cellMaxes = cellDb.maxes;
    report.globalMaxes = globalDb.maxes;
  } catch (e) {
    log.debug("Caught in childMain(): " + ((e && e.message) || e));
    report.threw = (e && e.stack) || String(e);
    report.cellOpened = cellDb && cellDb.openedAt;
    report.globalOpened = globalDb && globalDb.openedAt;
    report.cellHead = cellDb && cellDb.log.length;
    report.globalHead = globalDb && globalDb.log.length;
    report.cellMaxes = cellDb && cellDb.maxes;
    report.globalMaxes = globalDb && globalDb.maxes;
  }
  if (persistence && typeof persistence.stop === 'function') {
    try {
      await persistence.stop();
    } catch (e) {
      // The report already holds a failed start. Stopping a half-open store
      // is only so the child can exit.
      log.debug("Caught in childMain(): " + ((e && e.message) || e));
    }
  }
  fs.writeFileSync(process.env.PROBE_OUT, JSON.stringify(report));
  log.debug("Leaving childMain().");
  process.exit(0);
}

function inChild(t) {
  log.debug("Entering inChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-floor-'));
  const kek = path.join(dir, 'kek');
  fs.writeFileSync(kek, crypto.randomBytes(32).toString('base64'),
                   { mode: 0o600 });
  const outFile = path.join(dir, 'out.json');
  const env = Object.assign({}, process.env, {
    PROBE_OUT: outFile,
    LOG_LEVEL: 'error',
    STS_PERSISTENCE_MODE: 'postgres',
    STS_PERSISTENCE_COORDINATE: 'true',
    STS_CELL_ID: 'usw2',
    STS_CELL_JURISDICTION: 'us',
    STS_DATABASE_URL: 'postgres://sts:sts@127.0.0.1:5432/cell',
    STS_GLOBAL_DATABASE_URL: 'postgres://sts:sts@127.0.0.1:5432/global',
    STS_PUBLIC_BASE_URL: 'https://idp.example',
    STS_KEYS_SOURCE: 'persisted',
    STS_KEYS_KEK_PROVIDER: 'file',
    STS_SECRETS_ALLOW_LOCAL_SECRETS: 'true',
    STS_KEYS_KEK_FILE: kek,
    STS_CLUSTER_MODE: 'off'
  });
  env[CHILD_FLAG] = '1';
  delete env.CONFIG_FILE;
  delete env.STS_REQUEST_WORKER;
  const child = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: path.join(__dirname, '..'), env: env, encoding: 'utf8',
    timeout: 120000
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inChild(): " + ((e && e.message) || e));
    t.bad('the child reported nothing', 'status ' + child.status + ': ' +
          String(child.stderr || '').slice(-2000));
    log.debug("Leaving inChild().");
    return;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  if (report.threw) {
    t.bad('the child threw', report.threw);
  }
  const detail = JSON.stringify(report);
  t.equal(report.cellFrom, 5,
          'the cell follower starts from the cell log\'s head when the ' +
          'store opened', detail);
  t.check(typeof report.cellFrom === 'number' &&
          report.cellFrom === report.cellOpened &&
          report.cellFrom < report.cellHead,
          'that mark is the head sampled at open, below a change committed ' +
          'on the cell log during the restore', detail);
  t.equal(report.globalFrom, 3,
          'the global follower starts from the global log\'s own head when ' +
          'the store opened', detail);
  t.check(typeof report.globalFrom === 'number' &&
          report.globalFrom === report.globalOpened &&
          report.globalFrom < report.globalHead &&
          report.globalFrom !== report.cellFrom &&
          report.globalFrom !== report.cellHead,
          'that mark is not a cell sequence and is below a change committed ' +
          'on the global log during the restore', detail);
  log.debug("Leaving inChild().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== a cell\'s two followers start from the heads at open ===');
  inChild(t);
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG] === '1') {
  childMain();
}

module.exports = {
  name: 'replication_restore_floor',
  describe: 'a cell\'s two change-log followers start from the heads taken ' +
            'when the store opened, each below a change committed during ' +
            'the restore, and the global seq is not the cell\'s (#619)',
  run: run
};
