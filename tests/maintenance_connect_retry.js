// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: maintenance_connect_retry.js
//
// ===========================================================================
// A MAINTENANCE PASS WAITS FOR A DATABASE CONNECTION RATHER THAN FAILING ON
// THE FIRST ONE IT CANNOT GET (2026-10-02).
//
// The postgres pool gives up on a connection after five seconds, which is
// right for a request (answered 503 rather than left hanging) and wrong for
// the re-encryption pass and the data-key count: one query that met a full
// pool failed the whole pass (`keys.data-key-reencrypt`, sts_data_keys in
// single-node beside the bulk loads, locally and in CI run 36967212793).
//
//   A. a count whose first two queries time out connecting answers, after
//      trying again;
//   B. any other error is not retried;
//   C. a connect timeout that never clears fails after four retries.
//
// Against a `pg` that records statements (`directory_queries.js`'s). It
// waits out the retry delays — about ten seconds in all.
// ===========================================================================

const postgres = require('../persistence/persistence_postgres');

const log = require('bunyan').createLogger({
  name: 'maintenance_connect_retry',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

const TIMEOUT = 'timeout exceeded when trying to connect';

// A `pg` whose count query fails `plan` times with `message` first.
function fakePg(statements, plan) {
  function reply(sql, params) {
    statements.push(String(sql));
    if (/count\(\*\)/.test(String(sql)) && plan.failures > 0) {
      plan.failures -= 1;
      return Promise.reject(new Error(plan.message));
    }
    const rows = /count\(\*\)/.test(String(sql)) ? [{ n: 7 }] : [];
    if (!plan.delayMs || !/count\(\*\)/.test(String(sql))) {
      return Promise.resolve({ rows: rows, rowCount: rows.length });
    }
    // In flight for a moment, so how many run at once can be seen.
    plan.inFlight = (plan.inFlight || 0) + 1;
    plan.peak = Math.max(plan.peak || 0, plan.inFlight);
    return new Promise(function (resolve) {
      setTimeout(function () {
        plan.inFlight -= 1;
        resolve({ rows: rows, rowCount: rows.length });
      }, plan.delayMs);
    });
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

function counts(statements) {
  log.debug("Entering counts().");
  log.debug("Leaving counts().");
  return statements.filter(function (sql) {
    return /count\(\*\)/.test(sql);
  }).length;
}

async function attempt(driver) {
  log.debug("Entering attempt().");
  try {
    const out = await driver.countSealed(['dek-1']);
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

  t.log.info('=== A. a connect timeout is waited out ===');
  const a = [];
  const answered = await attempt(driverWith(a, { failures: 2,
                                                 message: TIMEOUT }));
  t.check(!answered.error && answered.out && answered.out['dek-1'] === 7,
          'A1. the count answers after two connect timeouts',
          answered.error ? answered.error.message : answered.out);
  t.equal(counts(a), 3, 'A2. its query was asked three times');

  t.log.info('=== B. any other error is not retried ===');
  const b = [];
  const refused = await attempt(driverWith(b, { failures: 1,
                                                message: 'syntax error' }));
  t.check(refused.error && /syntax error/.test(refused.error.message),
          'B1. another error fails the count at once',
          refused.error ? refused.error.message : refused.out);
  t.equal(counts(b), 1, 'B2. and its query was asked once');

  t.log.info('=== C. a timeout that never clears fails, after four ===');
  const c = [];
  const gaveUp = await attempt(driverWith(c, { failures: 100,
                                               message: TIMEOUT }));
  t.check(gaveUp.error && /timeout exceeded/.test(gaveUp.error.message),
          'C1. the count fails with the connect timeout',
          gaveUp.error ? gaveUp.error.message : gaveUp.out);
  t.equal(counts(c), 5, 'C2. after the first try and four retries');

  // A count over many keys was hundreds of queries at once, which took every
  // connection in the pool and starved the re-encryption pass beside it
  // (sts_data_keys in single-node, CI runs 36986913696 and 36997679067).
  t.log.info('=== D. a count over many keys runs two queries at a time ===');
  const d = [];
  const plan = { failures: 0, message: '', delayMs: 15 };
  const ids = [];
  for (let i = 0; i < 40; i++) {
    ids.push('dek-' + i);
  }
  const many = await driverWith(d, plan).countSealed(ids);
  t.check(Object.keys(many).length === 40 && ids.every(function (id) {
    return many[id] === 7;
  }), 'D1. every key is counted', JSON.stringify(many).slice(0, 200));
  t.check(plan.peak >= 1 && plan.peak <= 2,
          'D2. no more than two of its queries were in flight at once',
          'peak ' + plan.peak);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'maintenance_connect_retry',
  describe: 'a maintenance pass waits for a database connection rather ' +
            'than failing on the first it cannot get',
  run: run
};
