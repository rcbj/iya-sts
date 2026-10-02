// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/postgres_deadlock_retry.js
// ===========================================================================
// A DEADLOCKED TRANSACTION IS RUN AGAIN, NOT ANSWERED (2026-10-02).
//
// PostgreSQL ends one of two transactions that wait on each other with
// SQLSTATE 40P01 and rolls it back whole; a serialization failure is 40001.
// The postgres driver's `withTransaction()` handed that error to its caller,
// and a request whose change was in the flush was answered 503 — in CI run
// 36986913696's cluster job, the console's back-channel token request, so
// `sts_node_health` failed on a sign-in that had done nothing wrong. It runs
// the transaction again now, from BEGIN, up to three more times.
//
// In process, against a `pg` whose COMMIT fails as told (the driver is built
// with that `pg` in the require cache, as `maintenance_connect_retry.js`
// does), through `saveKeys()`, one of the driver's ordinary writes:
//
//   A. two deadlocks, then a commit: the write succeeds, and BEGIN was sent
//      three times — each attempt a whole transaction;
//   B. a serialization failure is retried the same way;
//   C. a deadlock that never clears fails after the first try and three
//      retries, with the database's code;
//   D. any other error (a unique violation) fails at once, sent once.
// ===========================================================================

const bunyan = require('bunyan');
const postgres = require('../persistence/persistence_postgres');

const log = bunyan.createLogger({
  name: 'postgres_deadlock_retry',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// A `pg` whose COMMIT fails `plan.failures` times with `plan.code`.
function fakePg(statements, plan) {
  function reply(sql) {
    statements.push(String(sql));
    if (/^COMMIT/.test(String(sql)) && plan.failures > 0) {
      plan.failures -= 1;
      const e = new Error(plan.code === '40P01' ? 'deadlock detected'
        : plan.code === '40001' ? 'could not serialize access'
          : 'duplicate key value violates unique constraint');
      e.code = plan.code;
      return Promise.reject(e);
    }
    return Promise.resolve({ rows: [], rowCount: 1 });
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
  return { Pool: FakePool, Client: FakeClient };
}

function driverWith(statements, plan) {
  log.debug("Entering driverWith().");
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: fakePg(statements, plan) };
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts', log: QUIET });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
}

function begins(statements) {
  log.debug("Entering begins().");
  log.debug("Leaving begins().");
  return statements.filter(function (sql) {
    return /^BEGIN/.test(sql);
  }).length;
}

async function attempt(driver) {
  log.debug("Entering attempt().");
  try {
    const out = await driver.saveKeys('deadlock-test', 'sealed-blob');
    log.debug("Leaving attempt().");
    return { out: out };
  } catch (e) {
    log.debug("Caught in attempt(): " + ((e && e.message) || e));
    log.debug("Leaving attempt().");
    return { error: e };
  }
}

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. a deadlock is run again ===');
  const a = [];
  const saved = await attempt(driverWith(a, { failures: 2, code: '40P01' }));
  t.check(!saved.error, 'A1. the write succeeds after two deadlocks',
          saved.error ? saved.error.message : '');
  t.equal(begins(a), 3, 'A2. each attempt was a whole transaction (BEGIN ' +
          'three times)');

  t.log.info('=== B. a serialization failure is run again ===');
  const b = [];
  const again = await attempt(driverWith(b, { failures: 1, code: '40001' }));
  t.check(!again.error, 'B1. the write succeeds after a serialization ' +
          'failure', again.error ? again.error.message : '');
  t.equal(begins(b), 2, 'B2. in two transactions');

  t.log.info('=== C. a deadlock that never clears fails ===');
  const c = [];
  const gaveUp = await attempt(driverWith(c, { failures: 100,
                                               code: '40P01' }));
  t.check(gaveUp.error && gaveUp.error.code === '40P01',
          'C1. the write fails with the database\'s deadlock code',
          gaveUp.error ? gaveUp.error.code : 'it succeeded');
  t.equal(begins(c), 4, 'C2. after the first try and three retries');

  t.log.info('=== D. any other error is not retried ===');
  const d = [];
  const refused = await attempt(driverWith(d, { failures: 1,
                                                code: '23505' }));
  t.check(refused.error && refused.error.code === '23505',
          'D1. a unique violation fails at once',
          refused.error ? refused.error.code : 'it succeeded');
  t.equal(begins(d), 1, 'D2. in one transaction');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'postgres_deadlock_retry',
  describe: 'a deadlocked or unserializable transaction is run again, up to ' +
            'three times; any other error is not',
  run: run
};
