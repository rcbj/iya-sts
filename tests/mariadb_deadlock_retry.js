// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/mariadb_deadlock_retry.js
// ===========================================================================
// A MARIADB DEADLOCK ON THE MINTED FLUSH IS RUN AGAIN, AND THE FLUSH NO
// LONGER SCANS THE TABLE INTO ONE (2026-11-14).
//
// GitHub Actions run 43642810770, mode (mariadb): 3719 store transactions
// were rolled back by InnoDB with "Deadlock found when trying to get lock"
// (ER_LOCK_DEADLOCK, 1213) and run again; 104 minted flushes ran out of
// their retries (STS-STORE-0021) and the requests whose rows were in them
// were answered 503 (STS-STORE-0066) — sts_fapi2, sts_route_inputs,
// sts_webauthn_second_factor, sts_fga and the three directory bulk loads.
// The cause was the statements, not the retry: MariaDB 11.8 plans a
// single-table DELETE or UPDATE whose WHERE is a ONE-tuple row constructor
// IN — `(handle, realm, key) IN ((?, ?, ?))`, what Knex spells for a flush
// that removes one session, one key's index rows or one claim — as a full
// table scan (EXPLAIN `type ALL`), and a scanning write at READ COMMITTED
// waits on every row any other flush holds. Named by column equalities the
// same rows are a range on the key (`sql_dialect.js`, `whereKeys()`).
//
// In process, against a store double the driver is built over with
// `engine: 'mariadb'` (`tools/store_double.js`), through `saveMinted()`,
// which on MariaDB is the portable flush inside `withTransaction()`
// (`persistence_postgres.js`, `flushMintedPortable()`):
//
//   A. two deadlocks (1213) on the flush's DELETE, then a commit: the flush
//      succeeds and BEGIN was sent three times — each attempt a whole
//      transaction, rolled back and begun again, and the change row
//      written once, by the attempt that committed;
//   B. a lock-wait timeout (1205) is run again the same way;
//   C. a deadlock that never clears fails after the first try and three
//      retries, with the database's errno;
//   D. a permanent error (a strict-mode refusal, 1406) fails at once, in
//      one transaction — the bisect above the driver (#1347) isolates it;
//   E. every key-named DELETE the MariaDB flush sends names its rows by
//      column equalities, never by a row constructor IN, and a releaseClaims
//      DELETE the same; PostgreSQL's text keeps the row constructor.
// ===========================================================================

delete process.env.CONFIG_FILE;

const storeDouble = require('./tools/store_double');
const sqlDialect = require('../persistence/sql_dialect');
const postgres = require('../persistence/persistence_postgres');

const log = require('bunyan').createLogger({
  name: 'mariadb_deadlock_retry',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// The errors `mysql2` rejects with, as `knex_store.js` hands them on.
const ERRORS = {
  1213: ['ER_LOCK_DEADLOCK', 'Deadlock found when trying to get lock; ' +
         'try restarting transaction'],
  1205: ['ER_LOCK_WAIT_TIMEOUT', 'Lock wait timeout exceeded; try ' +
         'restarting transaction'],
  1406: ['ER_DATA_TOO_LONG', 'Data too long for column \'body\' at row 1']
};

// A MariaDB double: every statement is recorded; the one whose name is
// `plan.at` fails `plan.failures` times with `plan.errno`; an INSERT
// answers every row affected, a SELECT no rows.
function fakeMariadb(sent, plan) {
  log.debug("Entering fakeMariadb().");
  function reply(sql, values) {
    const text = String(sql && sql.text !== undefined ? sql.text : sql);
    sent.push({ text: text, values: values || [] });
    if (plan.failures > 0 && text.indexOf('/* sts:' + plan.at + ' */') >= 0) {
      plan.failures -= 1;
      const e = /** @type {any} */ (new Error(ERRORS[plan.errno][1]));
      e.code = ERRORS[plan.errno][0];
      e.errno = plan.errno;
      return Promise.reject(e);
    }
    if (/^\s*select/i.test(text)) {
      return Promise.resolve({ rows: [], rowCount: 0 });
    }
    const n = /^\s*insert/i.test(text)
      ? Math.max(1, (text.match(/\),\s*\(/g) || []).length + 1) : 1;
    return Promise.resolve({ rows: [], rowCount: n, affectedRows: n,
                             insertId: 1 });
  }
  function FakeClient() {}
  FakeClient.prototype.query = reply;
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () {
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = reply;
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  log.debug("Leaving fakeMariadb().");
  return { Pool: FakePool, Client: FakeClient };
}

function driverWith(sent, plan) {
  log.debug("Entering driverWith().");
  const restore = storeDouble.install(fakeMariadb(sent, plan));
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({
      url: 'mysql://sts_app@localhost:3306/sts', engine: 'mariadb',
      log: QUIET });
  } finally {
    restore();
  }
}

function count(sent, pattern) {
  log.debug("Entering count().");
  log.debug("Leaving count().");
  return sent.filter(function (one) {
    return pattern.test(one.text);
  }).length;
}

// One upsert and one delete of a session: the delete is the statement a
// one-key flush sends as `flush.delete`, and its session row's removal.
async function flushOnce(driver) {
  log.debug("Entering flushOnce().");
  try {
    const out = await driver.saveMinted([
      { handle: 'test.plain', realm: 'default', key: 'p1', body: 'P',
        journalKey: 'p1', keySealed: '' }
    ], [
      { handle: 'test.gone', realm: 'default', key: 'd1', journalKey: 'd1',
        keySealed: '' }
    ]);
    log.debug("Leaving flushOnce().");
    return { out: out };
  } catch (e) {
    log.debug("Caught in flushOnce(): " + ((e && e.message) || e));
    log.debug("Leaving flushOnce(). Failed.");
    return { error: e };
  }
}

const BEGIN = /^\s*BEGIN/i;
const CHANGES = /\/\* sts:minted\.flush\.changes \*\//;

async function sections(t) {
  log.debug("Entering sections().");
  t.log.info('=== A. a deadlock on the flush is run again ===');
  const a = [];
  const saved = await flushOnce(driverWith(a, { at: 'minted.flush.delete',
                                                failures: 2, errno: 1213 }));
  t.check(!saved.error, 'A1. the flush succeeds after two deadlocks',
          saved.error ? saved.error.message : '');
  t.equal(count(a, BEGIN), 3, 'A2. each attempt was a whole transaction ' +
          '(BEGIN three times)');
  t.equal(count(a, /^\s*ROLLBACK/i), 2, 'A3. the two deadlocked attempts ' +
          'were rolled back');
  t.equal(count(a, CHANGES), 1, 'A4. the change rows were written by the ' +
          'attempt that committed, once');

  t.log.info('=== B. a lock-wait timeout is run again ===');
  const b = [];
  const waited = await flushOnce(driverWith(b, { at: 'minted.flush.delete',
                                                 failures: 1, errno: 1205 }));
  t.check(!waited.error, 'B1. the flush succeeds after a lock-wait timeout',
          waited.error ? waited.error.message : '');
  t.equal(count(b, BEGIN), 2, 'B2. in two transactions');

  t.log.info('=== C. a deadlock that never clears fails ===');
  const c = [];
  const gaveUp = await flushOnce(driverWith(c, { at: 'minted.flush.delete',
                                                 failures: 100,
                                                 errno: 1213 }));
  t.check(gaveUp.error && gaveUp.error.errno === 1213,
          'C1. the flush fails with the database\'s deadlock errno',
          gaveUp.error ? String(gaveUp.error.errno) : 'it succeeded');
  t.equal(count(c, BEGIN), 4, 'C2. after the first try and three retries');

  t.log.info('=== D. a permanent error is not retried ===');
  const d = [];
  const refused = await flushOnce(driverWith(d, { at: 'minted.flush.upsert',
                                                  failures: 100,
                                                  errno: 1406 }));
  t.check(refused.error && refused.error.errno === 1406,
          'D1. a strict-mode data refusal fails at once',
          refused.error ? String(refused.error.errno) : 'it succeeded');
  t.equal(count(d, BEGIN), 1, 'D2. in one transaction');

  t.log.info('=== E. no key-named DELETE is a row constructor IN ===');
  const deletes = a.filter(function (one) {
    return /^\s*delete/i.test(one.text);
  });
  const tupleIn = /\(\s*`[a-z_]+`\s*,[^)]*\)\s+in\s+\(\s*\(/i;
  t.check(deletes.length >= 2 && deletes.every(function (one) {
    return !tupleIn.test(one.text);
  }), 'E1. the MariaDB flush\'s DELETEs name their rows by column ' +
          'equalities (a one-tuple row constructor IN is a table scan there)',
          deletes.map(function (one) { return one.text; }).join(' | '));
  t.check(deletes.some(function (one) {
    return /\/\* sts:minted\.flush\.delete \*\//.test(one.text) &&
      /`handle` = \? and `realm` = \? and `key` = \?/i.test(one.text);
  }), 'E2. the minted DELETE is `handle = ? and realm = ? and key = ?`',
          deletes.map(function (one) { return one.text; }).join(' | '));
  const maria = sqlDialect.create('mariadb');
  const pg = sqlDialect.create('postgres');
  const claims = function (dialect, tuples) {
    return dialect.compile('releaseClaims',
      dialect.whereKeys(dialect.kx('sts_cluster_claims'),
                        ['scope', 'realm', 'key', 'reservation'],
                        tuples).del()).text;
  };
  const one = [['origin', '', 'k5', 'r']];
  const two = [['origin', '', 'k5', 'r'], ['origin', '', 'k6', 'r']];
  t.check(!tupleIn.test(claims(maria, one)) &&
          /\) or \(/i.test(claims(maria, two)),
          'E3. a claims DELETE on MariaDB is equalities, OR\'d per row',
          claims(maria, two));
  t.check(/\("scope", "realm", "key", "reservation"\) in \(/i
    .test(claims(pg, one)), 'E4. PostgreSQL\'s text keeps the row ' +
          'constructor', claims(pg, one));
  const none = maria.compile('releaseClaims',
    maria.whereKeys(maria.kx('sts_cluster_claims'),
                    ['scope', 'realm', 'key', 'reservation'], []).del());
  t.check(/where 1 = \?/i.test(none.text) && none.values.length === 1 &&
          Number(none.values[0]) === 0,
          'E5. an empty list matches nothing, `1 = 0` (an empty OR would ' +
          'match every row)', none.text + ' ' + JSON.stringify(none.values));
  log.debug("Leaving sections().");
}

async function run(t) {
  log.debug("Entering run().");
  await sections(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'mariadb_deadlock_retry',
  describe: 'a MariaDB deadlock or lock-wait timeout on the minted flush ' +
            'is run again, three times at most; a permanent error is not; ' +
            'and no key-named DELETE is a row-constructor IN, which MariaDB ' +
            'plans as a table scan',
  run: run
};
