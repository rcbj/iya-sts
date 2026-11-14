// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: tests/postgres_key_write_slots.js
// ===========================================================================
// KEY-ROW WRITES NEVER HOLD THE WHOLE POOL (2026-11-10, #1590).
//
// `mergeKeys()` is a transaction that holds its `sts_keys` row FOR UPDATE
// while the caller's merge runs. In the fuzz run on 39c8248c8, a
// certificate-authority rebuild storm queued several of them on one hot
// row's lock, each keeping its pooled connection, until a flush could not get
// one within 5 s (STS-STORE-0002) and its requests were answered 503
// (STS-STORE-0066). The driver now runs at most `pool size - 2` key-row
// transactions at once (never fewer than one), so two connections are always
// left for the flushes and the change-log pull.
//
// In process, against a `pg` whose `SELECT … FOR UPDATE` on sts_keys does not
// answer until the test releases it, as a row lock held elsewhere would:
//
//   A. six concurrent mergeKeys() with the default pool of four: at most two
//      transactions are open while the lock is held, and all six commit
//      once it is released, each with its own merge;
//   B. with a pool of eight, six are open at once (eight less two);
//   C. a merge that throws gives its slot back, so the writes behind it
//      still run.
// ===========================================================================

const storeDouble = require('./tools/store_double');
const bunyan = require('bunyan');
const postgres = require('../persistence/persistence_postgres');

const log = bunyan.createLogger({
  name: 'postgres_key_write_slots',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// A `pg` that counts open transactions and holds every key-row lock read
// until `state.release()` is called.
function fakePg(state) {
  const held = [];
  state.open = 0;
  state.maxOpen = 0;
  state.release = function () {
    log.debug("Entering release().");
    state.released = true;
    held.splice(0).forEach(function (go) {
      go();
    });
    log.debug("Leaving release().");
  };
  function reply(sql) {
    const text = String(sql);
    if (/^BEGIN/.test(text)) {
      state.open += 1;
      state.maxOpen = Math.max(state.maxOpen, state.open);
    } else if (/^(COMMIT|ROLLBACK)/.test(text)) {
      state.open -= 1;
    } else if (/FROM sts_keys WHERE realm = \$1 FOR UPDATE/.test(text)) {
      const answer = { rows: [{ material: 'stored' }], rowCount: 1 };
      if (state.released) {
        return Promise.resolve(answer);
      }
      return new Promise(function (resolve) {
        held.push(function () {
          resolve(answer);
        });
      });
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

function driverWith(state, poolMax) {
  log.debug("Entering driverWith().");
  const restore = storeDouble.install(fakePg(state));
  try {
    const options = { url: 'postgres://sts_app@localhost:5432/sts',
                      log: QUIET };
    if (poolMax) {
      options.poolMax = poolMax;
    }
    log.debug("Leaving driverWith().");
    return postgres.create(options);
  } finally {
    restore();
  }
}

// Lets every pending promise turn run before the next look.
function turns(n) {
  log.debug("Entering turns().");
  let chain = Promise.resolve();
  for (let i = 0; i < n; i++) {
    chain = chain.then(function () {
      return new Promise(function (resolve) {
        setImmediate(resolve);
      });
    });
  }
  log.debug("Leaving turns().");
  return chain;
}

async function concurrent(t, label, poolMax, count, expectedOpen) {
  log.debug("Entering concurrent().");
  const state = {};
  const driver = driverWith(state, poolMax);
  const merged = [];
  const writes = [];
  for (let i = 0; i < count; i++) {
    writes.push(driver.mergeKeys('realm-' + i, 'cipher', function (current) {
      merged.push(current);
      return 'written-' + i;
    }));
  }
  await turns(20);
  t.equal(state.maxOpen, expectedOpen, label + '1. with a pool of ' +
          (poolMax || 4) + ', ' + expectedOpen + ' key-row transaction(s) ' +
          'are open while the row lock is held, of ' + count + ' asked');
  state.release();
  const outcomes = await Promise.all(writes);
  t.check(outcomes.every(function (one) {
    return one && one.written === true;
  }) && merged.length === count && state.open === 0,
  label + '2. once the lock is released every write commits, each with ' +
  'its own merge', JSON.stringify({ merged: merged.length,
                                    open: state.open }));
  log.debug("Leaving concurrent().");
}

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. the default pool of four leaves two connections ===');
  await concurrent(t, 'A', 0, 6, 2);

  t.log.info('=== B. a pool of eight allows six ===');
  await concurrent(t, 'B', 8, 6, 6);

  t.log.info('=== C. a merge that throws gives its slot back ===');
  const state = {};
  const driver = driverWith(state, 0);
  state.release();
  const thrown = await driver.mergeKeys('bad', 'cipher', function () {
    throw new Error('the merge failed');
  }).then(function () {
    return null;
  }, function (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    return e;
  });
  const after = await Promise.all([1, 2, 3].map(function (i) {
    return driver.mergeKeys('good-' + i, 'cipher', function () {
      return 'written';
    });
  }));
  t.check(thrown && after.every(function (one) {
    return one && one.written === true;
  }), 'C1. the merge\'s error reaches its caller, and three writes after ' +
  'it all commit', thrown ? thrown.message : 'it did not throw');

  log.debug("Leaving run().");
}

module.exports = {
  name: 'postgres_key_write_slots',
  describe: 'key-row transactions never hold every pooled connection: at ' +
            'most pool size - 2 run at once, and every write still commits',
  run: run
};
