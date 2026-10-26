// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_flush_statements.js
//
// ===========================================================================
// THE DIRECTORY FLUSH WRITES ONE STATEMENT PER KIND, NOT ONE PER ROW
// (2026-10-21).
//
// `saveDirectory()` sent an INSERT or an UPDATE for every entry and a DELETE
// for every removal, each a round trip inside the transaction a request's
// answer waits for — #789's measurement for `saveMinted()`, and a password
// write touches several entries.
//
//   F1. thirty blind rows, twenty new merged ones and ten removals are ONE
//       lock, ONE insert and ONE delete — no per-row statement;
//   F2. the insert carries every row in primary-key order, merged and blind
//       together, and names only the blind ones as allowed to update;
//   F3. a merged insert that meets a row another node committed is looked
//       at again AFTER the flush commits, in a transaction that locks only
//       that row (#447);
//   F4. a key written twice in one flush is written once, as its last row;
//   F5. two lost rows are merged in primary-key order, each in its own
//       transaction, and the flush itself takes no single-row lock (#447).
//
// Against a `pg` that records statements (`directory_unopenable_rows.js`'s
// shape). The lock finds no rows, so every merged row is a new one.
// ===========================================================================

const storeDouble = require('./tools/store_double');
const postgres = require('../persistence/persistence_postgres');

const log = require('bunyan').createLogger({
  name: 'directory_flush_statements',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

const REALM = 'dfs';

// A `pg` that remembers every statement. A set-based INSERT answers every
// row it was given as written, except the ids in `refuse`.
function fakePg(statements, refuse) {
  function reply(sql, params) {
    const text = String(sql);
    const p = params || [];
    statements.push({ sql: text, params: p });
    if (/^INSERT INTO sts_ldap_entries/.test(text) && Array.isArray(p[0])) {
      const written = [];
      p[0].forEach(function (r, i) {
        if (!refuse.has(r + '\n' + p[1][i])) {
          written.push({ realm: r, dn_key: p[1][i] });
        }
      });
      return Promise.resolve({ rows: written, rowCount: written.length });
    }
    if (/^INSERT INTO sts_ldap_entries/.test(text)) {
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
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

function driverWith(statements, refuse) {
  log.debug("Entering driverWith().");
  const restore = storeDouble.install(fakePg(statements, refuse || new Set()));
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts', log: QUIET });
  } finally {
    restore();
  }
}

function count(statements, pattern) {
  log.debug("Entering count().");
  log.debug("Leaving count().");
  return statements.filter(function (one) {
    return pattern.test(one.sql);
  }).length;
}

// The statements of each BEGIN…COMMIT, in order. A lock taken out of key
// order is one that shares a transaction with a lock on a different row.
function transactionsOf(statements) {
  log.debug("Entering transactionsOf().");
  const txns = [];
  let current = null;
  statements.forEach(function (one) {
    const sql = String(one.sql).replace(/\s+/g, ' ').trim();
    if (sql === 'BEGIN') {
      current = [];
      return;
    }
    if (sql === 'COMMIT' || sql === 'ROLLBACK') {
      if (current) {
        txns.push(current);
      }
      current = null;
      return;
    }
    if (current) {
      current.push(one);
    }
  });
  log.debug("Leaving transactionsOf().");
  return txns;
}

function keyOf(i) {
  log.debug("Entering keyOf().");
  log.debug("Leaving keyOf().");
  return 'uid=p' + String(i).padStart(3, '0') + ',ou=people,dc=dfs';
}

function upsert(i, merged, note) {
  log.debug("Entering upsert().");
  const row = { realm: REALM, key: keyOf(i), json: '{}',
                entry: { dn: keyOf(i),
                         attributes: { uid: ['p' + i],
                                       description: [note || 'x'] } } };
  if (merged) {
    row.base = null;
  }
  log.debug("Leaving upsert().");
  return row;
}

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== F1/F2. sixty rows, four statements ===');
  const statements = [];
  const upserts = [];
  // Interleaved, so the order the insert carries is a sort and not luck.
  for (let i = 0; i < 50; i++) {
    upserts.push(upsert(49 - i, i % 5 < 2));
  }
  const deletes = [];
  for (let i = 100; i < 110; i++) {
    deletes.push({ realm: REALM, key: keyOf(i) });
  }
  await driverWith(statements).saveDirectory({
    upserts: upserts, deletes: deletes, touched: [REALM], removedRealms: [],
    all: null });
  const writing = statements.filter(function (one) {
    return /sts_ldap_entries/.test(one.sql);
  });
  t.check(count(writing, /FOR UPDATE/) === 1 &&
          count(writing, /^INSERT INTO sts_ldap_entries/) === 1 &&
          count(writing, /^UPDATE sts_ldap_entries/) === 0 &&
          count(writing, /^DELETE FROM sts_ldap_entries/) === 1,
          'F1. fifty upserts and ten removals are one lock, one insert and ' +
          'one delete', writing.map(function (one) {
            return one.sql.slice(0, 40);
          }).join(' | '));
  const insert = writing.filter(function (one) {
    return /^INSERT INTO sts_ldap_entries/.test(one.sql);
  })[0];
  const keys = insert && Array.isArray(insert.params[1]) ?
    insert.params[1] : [];
  const sorted = keys.slice(0).sort();
  t.check(keys.length === 50 && keys.every(function (k, i) {
    return k === sorted[i];
  }) && /ORDER BY u\.r, u\.k/.test(insert.sql),
          'F2. the insert carries all fifty in primary-key order, merged ' +
          'and blind together', JSON.stringify(keys.slice(0, 3)));
  t.check(insert && Array.isArray(insert.params[14]) &&
          insert.params[14].length === 30 &&
          insert.params[14].every(function (id) {
            const i = Number(/p(\d+)/.exec(id)[1]);
            return (49 - i) % 5 >= 2;
          }),
          'F2. and names only the thirty blind rows as allowed to update a ' +
          'row it meets', insert && insert.params[14].length);
  const lock = writing.filter(function (one) {
    return /FOR UPDATE/.test(one.sql);
  })[0];
  t.check(lock && lock.params[1].length === 60,
          'F2. the one lock covers every row the flush touches, blind ones ' +
          'included', lock && lock.params[1].length);

  t.log.info('=== F3. a merged insert that meets a row ===');
  const raced = [];
  await driverWith(raced, new Set([REALM + '\n' + keyOf(7)])).saveDirectory({
    upserts: [upsert(6, true), upsert(7, true), upsert(8, false)],
    deletes: [], touched: [REALM], removedRealms: [], all: null });
  const racedTxns = transactionsOf(raced);
  const flushLocks = (racedTxns[0] || []).filter(function (one) {
    return /WHERE realm = \$1 AND dn_key = \$2 FOR UPDATE/.test(one.sql);
  });
  const later = racedTxns.slice(1);
  const second = later.length === 1 ? later[0].filter(function (one) {
    return /WHERE realm = \$1 AND dn_key = \$2 FOR UPDATE/.test(one.sql);
  }) : [];
  const alone = later.length === 1 ? later[0].filter(function (one) {
    return /^(INSERT INTO|UPDATE) sts_ldap_entries/.test(one.sql) &&
           !Array.isArray(one.params[0]);
  }) : [];
  const laterKeys = later.length === 1 ? later[0].filter(function (one) {
    return /sts_ldap_entries/.test(one.sql);
  }).map(function (one) {
    return one.params[1];
  }) : [];
  t.check(flushLocks.length === 0 && later.length === 1 &&
          second.length === 1 && second[0].params[1] === keyOf(7) &&
          alone.length === 1 && alone[0].params[1] === keyOf(7) &&
          laterKeys.every(function (key) {
            return key === keyOf(7);
          }),
          'F3. after the flush commits it is locked alone and written',
          JSON.stringify([flushLocks.length, later.length, second.length,
                          alone.length]));

  t.log.info('=== F4. a key written twice ===');
  const twice = [];
  await driverWith(twice).saveDirectory({
    upserts: [upsert(3, false, 'first'), upsert(3, false, 'last')],
    deletes: [], touched: [REALM], removedRealms: [], all: null });
  const once = twice.filter(function (one) {
    return /^INSERT INTO sts_ldap_entries/.test(one.sql);
  });
  t.check(once.length === 1 && once[0].params[1].length === 1 &&
          once[0].params[2][0] === keyOf(3) &&
          once[0].params[3][0].indexOf('first') < 0 &&
          once[0].params[3][0].indexOf('last') >= 0,
          'F4. it is written once, as its last row',
          once.length && once[0].params[1].length);

  t.log.info('=== F5. two lost rows, in key order, after the flush ===');
  const crossed = [];
  await driverWith(crossed, new Set([
    REALM + '\n' + keyOf(20), REALM + '\n' + keyOf(3)
  ])).saveDirectory({
    upserts: [upsert(20, true), upsert(3, true), upsert(4, true)],
    deletes: [], touched: [REALM], removedRealms: [], all: null });
  const crossedTxns = transactionsOf(crossed);
  const crossedFlush = crossedTxns[0] || [];
  const singleInFlush = crossedFlush.filter(function (one) {
    return /WHERE realm = \$1 AND dn_key = \$2 FOR UPDATE/.test(one.sql);
  });
  const orderedLock = crossedFlush.filter(function (one) {
    return /ORDER BY realm, dn_key FOR UPDATE/.test(one.sql);
  });
  const lockKeys = orderedLock.length === 1 &&
      Array.isArray(orderedLock[0].params[1]) ?
    orderedLock[0].params[1] : [];
  const sortedLock = lockKeys.slice(0).sort();
  const follow = crossedTxns.slice(1).map(function (txn) {
    const locks = txn.filter(function (one) {
      return /WHERE realm = \$1 AND dn_key = \$2 FOR UPDATE/.test(one.sql);
    });
    const directory = txn.filter(function (one) {
      return /sts_ldap_entries/.test(one.sql);
    });
    return { locks: locks, directory: directory };
  });
  const followKeys = follow.map(function (one) {
    return one.locks.length === 1 ? one.locks[0].params[1] : null;
  });
  t.check(singleInFlush.length === 0 && orderedLock.length === 1 &&
          lockKeys.length === 3 && lockKeys.every(function (key, i) {
            return key === sortedLock[i];
          }) && follow.length === 2 &&
          followKeys[0] === keyOf(3) && followKeys[1] === keyOf(20) &&
          follow.every(function (one) {
            return one.locks.length === 1 && one.directory.every(
              function (statement) {
                return statement.params[1] === one.locks[0].params[1];
              });
          }),
          'F5. the flush locks in key order and each lost row is merged ' +
          'afterwards, alone, lower key first',
          JSON.stringify(followKeys));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_flush_statements',
  describe: 'the directory flush writes one statement per kind, not one per ' +
            'row: one lock, one insert, one update, one delete',
  run: run
};
