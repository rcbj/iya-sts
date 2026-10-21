// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: postgres_minted_writes.js
//
// ===========================================================================
// THE POSTGRES DRIVER'S MINTED WRITE, AGAINST A `pg` THAT RECORDS STATEMENTS
// (2026-09-12).
//
// A dispatched run of the whole suite left one request worker at 5.6 GB with
// every sample of a CPU profile inside `persistence_minted.js`'s `note()`, and
// the read barrier stalled behind it so badly that the SCIM bulk load was
// killed at thirty minutes. Three things in two files did it, in sequence:
//
//   1. `saveMinted()` issued its statements in journal order — upserts, then
//      deletes — so two workers flushing overlapping rows took row locks in
//      opposite orders: `deadlock detected`, about a hundred and twelve times.
//   2. every failed flush put its keys back and the next one was bigger, until
//      `recordChanges()`'s single INSERT passed 65,535 bind parameters and the
//      protocol's 16-bit count wrapped (`bind message has 63088 parameter
//      formats but 0 parameters`).
//   3. and the retry re-noted the STORED form of an `own` store's key, which is
//      `tests/minted_persistence.js` section 5a's half.
//
// This file holds the first two. Neither can be seen without a database or a
// driver double: both are about the ORDER and the SHAPE of SQL statements, and
// `tests/postgres_schema.js` reads only the DDL. The door to the store
// (`persistence/knex_store.js`, #326) is required lazily inside the driver's
// `create()`, so a module placed in the require cache for the length of one
// `create()` call is the whole of the double (`tests/tools/store_double.js`).
// ===========================================================================

const storeDouble = require('./tools/store_double');
const path = require('path');

const postgres = require('../persistence/persistence_postgres');

// A `pg` that connects to nothing and remembers every statement it was handed.
function fakePg(statements) {
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    statements.push({ sql: String(sql), params: params || [] });
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakeClient.prototype.release = function () {};
  FakeClient.prototype.on = function () {};
  FakeClient.prototype.removeListener = function () {};
  FakeClient.prototype.connect = function () { return Promise.resolve(); };
  FakeClient.prototype.end = function () { return Promise.resolve(); };

  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = FakeClient.prototype.query;
  FakePool.prototype.end = function () { return Promise.resolve(); };
  return { Pool: FakePool, Client: FakeClient };
}

// Build a driver with the fake in the place of its door to the store
// (`knex_store.js`, #326), and take the fake out again before anything else
// in this process can require the real one.
function driverWith(statements) {
  const restore = storeDouble.install(fakePg(statements));
  try {
    return postgres.create({
      url: 'postgres://sts_app@localhost:5432/sts',
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} }
    });
  } finally {
    restore();
  }
}

function mintedStatements(statements) {
  return statements.filter(function (one) {
    return /sts_minted/.test(one.sql) && !/^SELECT/i.test(one.sql.trim());
  });
}

async function run(t) {
  t.log.info('=== A. one lock order for every transaction ===');
  const statements = [];
  const driver = driverWith(statements);

  // Upserts and deletes deliberately out of order, and a delete that sorts
  // BETWEEN two upserts — the shape that deadlocked: one worker upserting b
  // and deleting a, another upserting a and deleting b.
  const upserts = [
    { handle: 'oauth2.authzCodes', realm: 'default', key: 'zz', body: 'x' },
    { handle: 'authn.sessions', realm: 'default', key: 'sid-b', body: 'x' },
    { handle: 'authn.sessions', realm: 'acme', key: 'sid-a', body: 'x' }
  ];
  const deletes = [
    { handle: 'authn.sessions', realm: 'default', key: 'sid-a' },
    { handle: 'admin_stats.calls', realm: 'default', key: 'k' }
  ];
  await driver.saveMinted(upserts, deletes);

  // SINCE 2026-10-21 A FLUSH IS SET-BASED: one SELECT … FOR UPDATE over
  // every row it touches, in (handle, realm, key) order, takes every lock
  // before any write — so the order two concurrent flushes take them in is
  // still the one order — and each kind of write is one statement whose
  // parameters are arrays over its rows.
  const zip = function (one) {
    return (one.params[0] || []).map(function (h, i) {
      return [h, one.params[1][i], one.params[2][i]].join('/');
    });
  };
  const lock = statements.filter(function (one) {
    return /^SELECT handle, realm, key, body FROM sts_minted/.test(one.sql) &&
      /FOR UPDATE/.test(one.sql);
  })[0];
  const sorted = 'admin_stats.calls/default/k authn.sessions/acme/sid-a ' +
    'authn.sessions/default/sid-a authn.sessions/default/sid-b ' +
    'oauth2.authzCodes/default/zz';
  t.equal(lock ? zip(lock).join(' ') : '(no lock statement)', sorted,
          'every row lock is taken in (handle, realm, key) order, upserts ' +
          'and deletes interleaved, in ONE statement before any write — the ' +
          'order two concurrent flushes must agree on for a deadlock between ' +
          'them to be impossible rather than rare');
  t.check(lock && statements.indexOf(lock) <
          statements.findIndex(function (one) {
            return /^(INSERT|DELETE)/.test(one.sql) && /sts_minted/.test(
              one.sql);
          }), 'and it comes before the first write');
  const deleted = new Set();
  mintedStatements(statements).forEach(function (one) {
    if (/^\s*DELETE/i.test(one.sql)) {
      zip(one).forEach(function (id) { deleted.add(id); });
    }
  });
  const kinds = sorted.split(' ').map(function (id) {
    return deleted.has(id) ? 'D' : 'U';
  }).join('');
  t.equal(kinds, 'DUDUU',
          'and each row still gets the statement it was handed: a delete ' +
          'stays a delete when it sorts between two upserts');
  t.check(mintedStatements(statements).length <= 3,
          'in a handful of statements rather than one per row',
          mintedStatements(statements).length);
  t.check(/^BEGIN$/.test((statements[0] || {}).sql) &&
          statements.some(function (one) { return one.sql === 'COMMIT'; }),
          'inside one transaction, as before');

  t.log.info('=== B. the change log is chunked under the bind limit ===');
  statements.length = 0;
  const many = [];
  for (let i = 0; i < 17000; i++) {
    many.push({ handle: 'audit.events', realm: 'default',
                key: 'k' + String(i).padStart(5, '0'), body: 'x', own: true });
  }
  await driver.saveMinted(many, []);
  const changeInserts = statements.filter(function (one) {
    return /INSERT INTO sts_changes/.test(one.sql);
  });
  const rowsLogged = changeInserts.reduce(function (sum, one) {
    return sum + one.params.length / 4;
  }, 0);
  t.equal(rowsLogged, 17000,
          'every minted row still gets its change-log row');
  t.check(changeInserts.length > 1 && changeInserts.every(function (one) {
            return one.params.length <= 65535;
          }),
          'AND NO STATEMENT CARRIES MORE THAN 65,535 PARAMETERS. At four a ' +
          'row, 17,000 rows in one INSERT is 68,000 — which the protocol\'s ' +
          '16-bit count wraps, and PostgreSQL refuses as "bind message has N ' +
          'parameter formats but 0 parameters"',
          changeInserts.map(function (one) {
            return one.params.length;
          }).join(', '));

  // The path is reported so a failure names the file it is about.
  t.log.info('driver: ' + path.relative(process.cwd(),
    require.resolve('../persistence/persistence_postgres')));
}

module.exports = {
  name: 'postgres_minted_writes',
  describe: 'the postgres driver takes minted row locks in one order and ' +
            'chunks the change log under the bind-parameter limit',
  run: run
};
