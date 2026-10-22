// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: postgres_tally_commit.js
//
// ===========================================================================
// COUNTERS COMMIT WITHOUT WAITING FOR THE LOG FLUSH; RECORDS DO (2026-10-22,
// #820).
//
// On 8081 a sign-in made about eleven committing transactions, and postgres
// flushes its log one fsync at a time: that was the sign-in rate's ceiling.
// About half were counters — the shared rate-limit windows and the risk
// engine's tallies — which now go through a pool whose connections set
// `synchronous_commit = off`.
//
//   T1. the shared rate-limit window count and clear go to that pool;
//   T2. the risk engine's counts, assessments (recorded, settled, amended),
//       subjects, session context and failures go to it;
//   T3. a flush of minted rows, and the risk engine's action claim, do not.
//
// A `pg` double records the connection options each statement ran on
// (`tests/tools/store_double.js`).
// ===========================================================================

const storeDouble = require('./tools/store_double');

const postgres = require('../persistence/persistence_postgres');

const log = require('bunyan').createLogger({
  name: 'postgres_tally_commit',
  level: process.env.LOG_LEVEL || 'info' });

const ASYNC = '-c synchronous_commit=off';

// A `pg` that connects to nothing and remembers every statement, with the
// options of the connection it was handed to.
function fakePg(statements) {
  log.debug("Entering fakePg().");
  function FakeClient(config) {
    this.options = (config && config.options) || '';
  }
  FakeClient.prototype.query = function (sql, params) {
    statements.push({ sql: String(sql && sql.text ? sql.text : sql),
                      params: params || [], options: this.options });
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function (callback) {
    if (typeof callback === 'function') {
      callback(null, this);
      return undefined;
    }
    return Promise.resolve(this);
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };

  function FakePool(config) {
    this.config = config || {};
  }
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient(this.config));
  };
  FakePool.prototype.query = function (sql, params) {
    return new FakeClient(this.config).query(sql, params);
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  log.debug("Leaving fakePg().");
  return { Pool: FakePool, Client: FakeClient };
}

function driverWith(statements) {
  log.debug("Entering driverWith().");
  const restore = storeDouble.install(fakePg(statements));
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} }
    });
  } finally {
    restore();
  }
}

// The options of the connection the last statement matching `re` ran on.
function optionsOf(statements, re) {
  log.debug("Entering optionsOf().");
  const hits = statements.filter(function (one) {
    return re.test(one.sql);
  });
  log.debug("Leaving optionsOf().");
  return hits.length ? hits[hits.length - 1].options : null;
}

async function run(t) {
  log.debug("Entering run().");
  const statements = [];
  const driver = driverWith(statements);
  const settle = async function (fn) {
    try {
      await fn();
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  };

  await settle(function () {
    return driver.countWindow('rw', 'default', 'k', 60000);
  });
  await settle(function () {
    return driver.clearWindow('rw', 'default', 'k');
  });
  t.check(optionsOf(statements, /INSERT INTO sts_cluster_windows/) === ASYNC &&
          optionsOf(statements, /DELETE FROM sts_cluster_windows/) === ASYNC,
          'T1. the shared rate-limit window count and clear commit ' +
          'asynchronously', JSON.stringify(statements.map(function (one) {
            return one.options + ' ' + one.sql.slice(0, 40);
          })));

  statements.length = 0;
  const assessment = { realm: 'default', id: 'a1', at: 1, phase: 'p',
                       door: 'd', subject: 's', signals: {}, score: 0 };
  await settle(function () {
    return driver.riskIncrementCounts('default',
      [{ subject: 's', feature: 'f', value: 'v' }], 1);
  });
  await settle(function () {
    return driver.riskRecordAssessment(assessment);
  });
  await settle(function () {
    return driver.riskSettleAssessment(assessment);
  });
  await settle(function () {
    return driver.riskAmendAssessment(assessment);
  });
  await settle(function () {
    return driver.riskUpsertSubject({ realm: 'default', subject: 's',
                                      score: 0, level: 'low' });
  });
  await settle(function () {
    return driver.riskUpsertSessionContext({ realm: 'default',
                                             sessionId: 'x', subject: 's' });
  });
  await settle(function () {
    return driver.riskRecordFailure({ realm: 'default', at: 1, door: 'd' });
  });
  const tallies = [/INSERT INTO sts_risk_feature_counts/,
                   /INSERT INTO sts_risk_assessments/,
                   /UPDATE sts_risk_assessments SET decision/,
                   /UPDATE sts_risk_assessments SET signals/,
                   /INSERT INTO sts_risk_subjects/,
                   /INSERT INTO sts_risk_session_context/,
                   /INSERT INTO sts_risk_failures/];
  const seen = tallies.map(function (re) {
    return optionsOf(statements, re);
  });
  t.check(seen.every(function (one) {
    return one === ASYNC;
  }), 'T2. the risk engine\'s tallies commit asynchronously',
          JSON.stringify(seen));

  statements.length = 0;
  await settle(function () {
    return driver.saveMinted([{ handle: 'authn.sessions', realm: 'default',
                                key: 'sid', body: 'x' }], []);
  });
  await settle(function () {
    return driver.riskClaimAction('default', 's', 'notify', 'a1');
  });
  const durable = statements.filter(function (one) {
    return /sts_minted|sts_risk_subjects SET actions/.test(one.sql);
  });
  t.check(durable.length > 0 && durable.every(function (one) {
    return one.options !== ASYNC;
  }), 'T3. minted rows and an action claim stay durable at commit',
          JSON.stringify(durable.map(function (one) {
            return (one.options || 'sync') + ' ' + one.sql.slice(0, 40);
          })));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'postgres_tally_commit',
  describe: 'rate-limit windows and risk tallies commit with ' +
            'synchronous_commit off; records stay durable at commit (#820)',
  run: run
};
