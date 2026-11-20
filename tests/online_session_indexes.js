// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: online_session_indexes.js
//
// ===========================================================================
// AN EXISTING 1.0.0 STORE MISSING THE SESSION INDEXES STILL STARTS (#876,
// #882), AND IS NEVER WRITE-LOCKED FOR A BUILD.
//
// `sts_sessions_subject_band` and `sts_sessions_started` arrived after
// release 1.0.0. The driver's open() built a missing one with a plain CREATE
// INDEX inside its own transaction — a SHARE lock holding every session write
// for the build — and the least-privileged role, which does not own the
// table, was refused (STS-STORE-0029), so the 1.1.0 image did not start on a
// 1.0.0 store until the owner had run the upgrade script. Now
// (`persistence/online_indexes.js`):
//
//   A. the model marks exactly those two (and MariaDB's one) `online`, and
//      the driver's concurrent statement is the upgrade script's;
//   B. absent, and the role does not own the table: open() succeeds, issues
//      no CREATE INDEX for them, warns ONCE with STS-STORE-0172 naming
//      postgres/upgrade-1.0.0.sql, records version 32, and the session
//      questions still answer;
//   C. absent, and the role owns the table: open() returns BEFORE the build,
//      which runs on a connection of its own, outside any transaction, as
//      CREATE INDEX CONCURRENTLY, under the advisory lock;
//   D. present and INVALID: dropped concurrently, then built;
//   E. another process holds the lock: nothing is built here;
//   F. the build fails: STS-STORE-0173, and the start is unaffected;
//   G. close() during a build ends the build's connection;
//   H. MariaDB: built in place with WAIT and LOCK=NONE, told (0172) when the
//      account may not alter, 0173 on another failure, and open_mariadb
//      leaves the online index to the driver.
//
// In process, against a `pg` double: every claim is about which statement
// goes where, and on which connection.
// ===========================================================================

const fs = require('fs');
const path = require('path');

const storeDouble = require('./tools/store_double');
const postgres = require('../persistence/persistence_postgres');
const onlineIndexes = require('../persistence/online_indexes');
const schemaMariadb = require('../persistence/schema_mariadb');
const openMariadb = require('../persistence/open_mariadb');

const log = require('bunyan').createLogger({ name: 'online_session_indexes',
  level: process.env.LOG_LEVEL || 'info' });

const ONLINE = ['sts_sessions_subject_band', 'sts_sessions_started'];

// A logger that keeps what it was told at warn and info.
function capturingLog() {
  log.debug("Entering capturingLog().");
  const said = { warn: [], info: [] };
  log.debug("Leaving capturingLog().");
  return {
    said: said,
    debug: function () {},
    trace: function () {},
    error: function () {},
    fatal: function () {},
    info: function (m) { said.info.push(String(m)); },
    warn: function (m) { said.warn.push(String(m)); }
  };
}

// A pg double. `scenario` says what the catalogue holds:
//   absent: names to_regclass reports missing
//   invalid: names pg_index reports not valid
//   owner: whether the role owns sts_sessions
//   lock: what pg_try_advisory_lock answers
//   hold: a promise each CONCURRENTLY statement waits for
//   failBuild: an error the CONCURRENTLY statement rejects with
function fakePg(scenario) {
  log.debug("Entering fakePg().");
  const record = { pool: [], dedicated: [], dedicatedEnded: 0 };
  function answer(sql, params) {
    if (/^SELECT to_regclass\(\$1\) AS o0/.test(sql)) {
      const row = {};
      params.forEach(function (name, i) {
        row['o' + i] = (scenario.absent || []).indexOf(name) >= 0
          ? null : name;
      });
      return [row];
    }
    if (/information_schema\.columns/.test(sql)) {
      const present = [];
      for (let i = 0; i < params.length; i += 2) {
        present.push({ table_name: params[i], column_name: params[i + 1] });
      }
      return present;
    }
    if (/NOT i\.indisvalid/.test(sql)) {
      return (scenario.invalid || []).map(function (name) {
        return { name: name };
      });
    }
    if (/pg_has_role\(current_user, c\.relowner/.test(sql)) {
      return [{ name: 'sts_sessions', owner: scenario.owner === true }];
    }
    if (/pg_try_advisory_lock/.test(sql)) {
      return [{ got: scenario.lock !== false }];
    }
    if (/SELECT i\.indisvalid AS valid/.test(sql)) {
      if ((scenario.invalid || []).indexOf(params[0]) >= 0) {
        return [{ valid: false }];
      }
      return (scenario.absent || []).indexOf(params[0]) >= 0
        ? [] : [{ valid: true }];
    }
    return undefined;
  }
  function reply(list, sql, params) {
    list.push({ sql: String(sql), params: params || [] });
    const rows = answer(String(sql), params || []);
    return Promise.resolve({ rows: rows || [], rowCount: (rows || []).length });
  }
  function PoolClient() {}
  PoolClient.prototype.query = function (sql, params) {
    return reply(record.pool, sql, params);
  };
  PoolClient.prototype.release = function () {};
  PoolClient.prototype.on = function () {};
  PoolClient.prototype.removeListener = function () {};
  function BuildClient() {}
  BuildClient.prototype.on = function () {};
  BuildClient.prototype.removeListener = function () {};
  BuildClient.prototype.connect = function () { return Promise.resolve(); };
  BuildClient.prototype.end = function () {
    record.dedicatedEnded += 1;
    return Promise.resolve();
  };
  BuildClient.prototype.query = function (sql, params) {
    if (/CONCURRENTLY IF NOT EXISTS/.test(String(sql))) {
      record.dedicated.push({ sql: String(sql), params: params || [] });
      return Promise.resolve(scenario.hold).then(function () {
        if (scenario.failBuild) {
          throw scenario.failBuild;
        }
        return { rows: [], rowCount: 0 };
      });
    }
    return reply(record.dedicated, sql, params);
  };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new PoolClient());
  };
  FakePool.prototype.query = function (sql, params) {
    return reply(record.pool, sql, params);
  };
  FakePool.prototype.end = function () { return Promise.resolve(); };
  FakePool.prototype.dedicated = function () { return new BuildClient(); };
  log.debug("Leaving fakePg().");
  return { fakes: { Pool: FakePool, Client: BuildClient }, record: record };
}

function driverOver(scenario, logger) {
  log.debug("Entering driverOver().");
  const pg = fakePg(scenario);
  const restore = storeDouble.install(pg.fakes);
  try {
    log.debug("Leaving driverOver().");
    return { driver: postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts', log: logger }),
             record: pg.record };
  } finally {
    restore();
  }
}

function onlineCreates(list) {
  log.debug("Entering onlineCreates().");
  log.debug("Leaving onlineCreates().");
  return list.filter(function (s) {
    return /^CREATE INDEX/i.test(s.sql) && ONLINE.some(function (name) {
      return s.sql.indexOf(name) >= 0;
    });
  });
}

function model(t) {
  log.debug("Entering model().");
  t.log.info('=== A. the model marks the indexes online ===');
  const online = onlineIndexes.onlineObjects(postgres.SCHEMA_OBJECTS)
    .map(function (o) { return o.name; }).sort();
  t.equal(JSON.stringify(online), JSON.stringify(ONLINE.slice().sort()),
          'A1. PostgreSQL\'s online indexes are exactly the two added after ' +
          'release 1.0.0');
  const maria = onlineIndexes.onlineObjects(schemaMariadb.SCHEMA_OBJECTS)
    .map(function (o) { return o.name; });
  t.equal(JSON.stringify(maria), JSON.stringify(['sts_sessions_started']),
          'A2. MariaDB\'s online index is sts_sessions_started');
  const upgrade = fs.readFileSync(path.join(__dirname, '..', 'postgres',
    'upgrade-1.0.0.sql'), 'utf8').replace(/\s+/g, ' ');
  onlineIndexes.onlineObjects(postgres.SCHEMA_OBJECTS).forEach(function (o) {
    const concurrent = onlineIndexes.concurrentStatement(o.statement)
      .replace(/\s+/g, ' ');
    t.check(/^CREATE INDEX CONCURRENTLY IF NOT EXISTS /.test(concurrent) &&
            upgrade.indexOf(concurrent) >= 0,
            'A3. the driver\'s concurrent ' + o.name + ' is the upgrade ' +
            'script\'s statement', concurrent);
  });
  t.equal(onlineIndexes.tableOf(postgres.SCHEMA_OBJECTS.filter(function (o) {
    return o.name === 'sts_sessions_subject_band';
  })[0].statement), 'sts_sessions', 'A4. the table is read off the statement');
  log.debug("Leaving model().");
}

async function notOwner(t) {
  log.debug("Entering notOwner().");
  t.log.info('=== B. absent, and this role does not own the table ===');
  const logger = capturingLog();
  const { driver, record } = driverOver({ absent: ONLINE, owner: false },
                                        logger);
  let refused = null;
  try {
    await driver.open();
  } catch (e) {
    log.debug("Caught in notOwner(): " + ((e && e.message) || e));
    refused = e;
  }
  t.check(refused === null, 'B1. the store opens',
          refused && refused.message);
  const settled = await driver.onlineIndexes();
  t.equal(onlineCreates(record.pool).length + onlineCreates(
    record.dedicated).length, 0,
  'B2. no CREATE INDEX is issued for either index');
  const tagged = logger.said.warn.filter(function (m) {
    return /STS-STORE-0172/.test(m);
  });
  t.equal(tagged.length, 1, 'B3. one warning, STS-STORE-0172');
  t.check(tagged.length === 1 && /postgres\/upgrade-1\.0\.0\.sql/.test(
    tagged[0]) && ONLINE.every(function (name) {
    return tagged[0].indexOf(name) >= 0;
  }), 'B4. naming both indexes and postgres/upgrade-1.0.0.sql', tagged[0]);
  t.check(settled && settled.told && settled.told.length === 2 &&
          settled.built.length === 0, 'B5. the settlement says told, not ' +
          'built', JSON.stringify(settled));
  t.check(record.pool.some(function (s) {
    return /INSERT INTO sts_schema/.test(s.sql) && s.params[0] === 32;
  }), 'B6. schema version 32 is recorded');
  t.check(!record.pool.some(function (s) {
    return /CONCURRENTLY/.test(s.sql);
  }) && record.dedicated.length === 0,
  'B7. no build connection is opened');
  const page = await driver.sessionIndexQuery('session.livePage',
    ['', 0, '', '', '', '', 10, 0]);
  const over = await driver.sessionIndexQuery('session.overCapRows',
    ['', 'A', 'B', 3, 10]);
  t.check(Array.isArray(page) || (page && typeof page === 'object'),
          'B8. the newest-first page still answers', JSON.stringify(page));
  t.check(Array.isArray(over) || (over && typeof over === 'object'),
          'B9. the per-person cap\'s band still answers', JSON.stringify(over));
  await driver.close();
  log.debug("Leaving notOwner().");
}

async function owner(t) {
  log.debug("Entering owner().");
  t.log.info('=== C. absent, and this role owns the table ===');
  const logger = capturingLog();
  let release = null;
  const hold = new Promise(function (resolve) { release = resolve; });
  const { driver, record } = driverOver({ absent: ONLINE, owner: true,
                                          hold: hold }, logger);
  await driver.open();
  // The build is held at its first CONCURRENTLY statement; open() is done.
  await new Promise(function (resolve) { setImmediate(resolve); });
  t.equal(onlineCreates(record.pool).length, 0,
          'C1. nothing is built on the pool, nor in open()\'s transaction');
  t.check(record.pool.some(function (s) {
    return /INSERT INTO sts_schema/.test(s.sql);
  }), 'C2. open() finished (the version row is written) while the build ' +
          'is still held');
  const ordered = record.dedicated.map(function (s) { return s.sql; });
  const lockAt = ordered.findIndex(function (sql) {
    return /pg_try_advisory_lock/.test(sql);
  });
  const firstBuild = ordered.findIndex(function (sql) {
    return /^CREATE INDEX CONCURRENTLY IF NOT EXISTS /.test(sql);
  });
  t.check(lockAt >= 0 && firstBuild > lockAt,
          'C3. on its own connection, the advisory lock then CREATE INDEX ' +
          'CONCURRENTLY', ordered.join(' | '));
  t.check(!ordered.some(function (sql) {
    return /^(BEGIN|START TRANSACTION)/i.test(sql);
  }), 'C4. outside any transaction');
  release();
  const settled = await driver.onlineIndexes();
  const builds = record.dedicated.filter(function (s) {
    return /^CREATE INDEX CONCURRENTLY IF NOT EXISTS /.test(s.sql);
  });
  t.equal(builds.length, 2, 'C5. both indexes are built');
  t.check(settled.built.length === 2 && record.dedicatedEnded === 1,
          'C6. the settlement names both and the connection is ended',
          JSON.stringify(settled));
  t.check(!logger.said.warn.some(function (m) {
    return /STS-STORE-017[23]/.test(m);
  }), 'C7. and nothing is warned');
  await driver.close();
  log.debug("Leaving owner().");
}

async function invalidIndex(t) {
  log.debug("Entering invalidIndex().");
  t.log.info('=== D. present but invalid, owner ===');
  const logger = capturingLog();
  const { driver, record } = driverOver({
    absent: [], invalid: ['sts_sessions_started'], owner: true }, logger);
  await driver.open();
  await driver.onlineIndexes();
  const ordered = record.dedicated.map(function (s) { return s.sql; });
  const dropAt = ordered.indexOf(
    'DROP INDEX CONCURRENTLY IF EXISTS sts_sessions_started');
  const buildAt = ordered.findIndex(function (sql) {
    return /^CREATE INDEX CONCURRENTLY IF NOT EXISTS sts_sessions_started /
      .test(sql);
  });
  t.check(dropAt >= 0 && buildAt > dropAt,
          'D1. the invalid index is dropped concurrently, then built',
          ordered.join(' | '));
  t.check(!ordered.some(function (sql) {
    return /sts_sessions_subject_band/.test(sql) && /^CREATE|^DROP/.test(sql);
  }), 'D2. the valid one is left alone');
  const told = capturingLog();
  const notOwned = driverOver({ absent: [],
    invalid: ['sts_sessions_started'], owner: false }, told);
  await notOwned.driver.open();
  await notOwned.driver.onlineIndexes();
  t.check(told.said.warn.some(function (m) {
    return /STS-STORE-0172/.test(m) && /sts_sessions_started \(invalid\)/
      .test(m);
  }) && notOwned.record.dedicated.length === 0,
  'D3. an invalid index a non-owner cannot rebuild is told, as invalid');
  await driver.close();
  await notOwned.driver.close();
  log.debug("Leaving invalidIndex().");
}

async function lockAndFailure(t) {
  log.debug("Entering lockAndFailure().");
  t.log.info('=== E. another process builds; F. a build fails ===');
  const busy = driverOver({ absent: ONLINE, owner: true, lock: false },
                          capturingLog());
  await busy.driver.open();
  const settled = await busy.driver.onlineIndexes();
  t.check(!busy.record.dedicated.some(function (s) {
    return /CONCURRENTLY/.test(s.sql);
  }) && settled.built.length === 0 && busy.record.dedicatedEnded === 1,
  'E1. without the lock nothing is built, and the connection is ended');
  await busy.driver.close();
  const logger = capturingLog();
  const failing = driverOver({ absent: ONLINE, owner: true,
    failBuild: Object.assign(new Error('canceling statement'),
                             { code: '57014' }) }, logger);
  let refused = null;
  try {
    await failing.driver.open();
  } catch (e) {
    log.debug("Caught in lockAndFailure(): " + ((e && e.message) || e));
    refused = e;
  }
  await failing.driver.onlineIndexes();
  t.check(refused === null, 'F1. a failing build does not fail the start');
  t.check(logger.said.warn.filter(function (m) {
    return /STS-STORE-0173/.test(m);
  }).length === 1, 'F2. it is warned once, STS-STORE-0173',
  logger.said.warn.join(' | '));
  t.equal(failing.record.dedicatedEnded, 1, 'F3. its connection is ended');
  await failing.driver.close();
  log.debug("Leaving lockAndFailure().");
}

async function closeDuringBuild(t) {
  log.debug("Entering closeDuringBuild().");
  t.log.info('=== G. close() during a build ===');
  const hold = new Promise(function () {});
  const { driver, record } = driverOver({ absent: ONLINE, owner: true,
                                          hold: hold }, capturingLog());
  await driver.open();
  await new Promise(function (resolve) { setImmediate(resolve); });
  await driver.close();
  t.equal(record.dedicatedEnded, 1,
          'G1. close() ends the build\'s connection, cancelling the build');
  log.debug("Leaving closeDuringBuild().");
}

async function mariadb(t) {
  log.debug("Entering mariadb().");
  t.log.info('=== H. MariaDB ===');
  const started = schemaMariadb.SCHEMA_OBJECTS.filter(function (o) {
    return o.name === 'sts_sessions_started';
  })[0];
  const alter = onlineIndexes.mariadbOnlineStatement(started.statement);
  t.check(/^ALTER TABLE sts_sessions WAIT 5 ADD INDEX IF NOT EXISTS sts_sessions_started \(realm, started_at DESC, `key`\), ALGORITHM=INPLACE, LOCK=NONE$/
    .test(alter), 'H1. built in place, bounded, without blocking writers',
  alter);
  const sent = [];
  const okPool = { query: function (sql) {
    sent.push(sql);
    return Promise.resolve({ rows: [] });
  } };
  const built = await onlineIndexes.settleMariadb(okPool, capturingLog(),
                                                  [started]);
  t.check(built.built.length === 1 && sent[0] === alter,
          'H2. the statement is sent and the index named built');
  const deniedLog = capturingLog();
  const denied = await onlineIndexes.settleMariadb({ query: function () {
    return Promise.reject(Object.assign(new Error('ALTER command denied'),
                                        { errno: 1142 }));
  } }, deniedLog, [started]);
  t.check(denied.told.length === 1 && deniedLog.said.warn.some(function (m) {
    return /STS-STORE-0172/.test(m) && /mariadb\/upgrade-1\.0\.0\.sql/.test(m);
  }), 'H3. an account that may not alter is told, naming ' +
          'mariadb/upgrade-1.0.0.sql');
  const failLog = capturingLog();
  const failed = await onlineIndexes.settleMariadb({ query: function () {
    return Promise.reject(Object.assign(new Error('Lock wait timeout'),
                                        { errno: 1205 }));
  } }, failLog, [started]);
  t.check(failed.failed.length === 1 && failLog.said.warn.some(function (m) {
    return /STS-STORE-0173/.test(m);
  }), 'H4. another failure is STS-STORE-0173');
  // open_mariadb with every object present but the online one.
  const issued = [];
  const pool = { query: function (sql) {
    issued.push(String(sql));
    if (/information_schema\.TABLES/.test(sql)) {
      return Promise.resolve({ rows: schemaMariadb.TABLES.map(function (n) {
        return { name: n };
      }) });
    }
    if (/information_schema\.STATISTICS/.test(sql)) {
      return Promise.resolve({ rows: schemaMariadb.SCHEMA_OBJECTS
        .filter(function (o) {
          return !/^CREATE TABLE/i.test(o.statement) &&
            o.name !== 'sts_sessions_started';
        }).map(function (o) {
          return { tbl: openMariadb.indexTable(o.statement), name: o.name };
        }) });
    }
    return Promise.resolve({ rows: [] });
  } };
  const owed = [];
  const created = await openMariadb.open(pool, capturingLog(), owed);
  t.check(created.length === 0 && owed.length === 1 &&
          owed[0].name === 'sts_sessions_started' && !issued.some(function (s) {
    return /sts_sessions_started/.test(s);
  }), 'H5. open_mariadb leaves the online index to the driver',
  JSON.stringify({ created: created, owed: owed.map(function (o) {
    return o.name;
  }) }));
  log.debug("Leaving mariadb().");
}

async function run(t) {
  log.debug("Entering run().");
  model(t);
  await notOwner(t);
  await owner(t);
  await invalidIndex(t);
  await lockAndFailure(t);
  await closeDuringBuild(t);
  await mariadb(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'online_session_indexes',
  describe: 'an index added after 1.0.0 never blocks or refuses a start: ' +
    'told to a non-owner, built concurrently by an owner (#876, #882)',
  run: run
};
