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
//
// SINCE 2026-10-22 (#820) A FLUSH IS ONE STATEMENT, MINTED_FLUSH, so the two
// claims are read off it: its `lock_*` arrays in (handle, realm, key) order
// with upserts and deletes interleaved, the statement locking every row
// (`lk`) before anything reads `ok` — and every write reads `ok`, which reads
// the lock's count — and the change log as ARRAYS, so a flush of any size is
// the layout's fixed number of bind parameters. The statement is played by
// `tests/tools/minted_flush_double.js`, so the driver is answered as by a
// database; `tests/minted_flush_one_statement.js` counts the round trips.
// ===========================================================================

const storeDouble = require('./tools/store_double');
const flushDouble = require('./tools/minted_flush_double');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'postgres_minted_writes',
  level: process.env.LOG_LEVEL || 'info' });

const postgres = require('../persistence/persistence_postgres');

// A `pg` that connects to nothing, remembers every statement it was handed,
// and plays the minted flush against Maps.
function fakePg(statements) {
  log.debug("Entering fakePg().");
  const db = flushDouble.state();
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    const flush = flushDouble.isFlush(sql);
    statements.push({ sql: String(flush ? sql.text : sql),
                      params: flush ? sql.values : (params || []),
                      flush: flush });
    if (flush) {
      return Promise.resolve(flushDouble.play(db, sql));
    }
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
  log.debug("Leaving fakePg().");
  return { Pool: FakePool, Client: FakeClient };
}

// Build a driver with the fake in the place of its door to the store
// (`knex_store.js`, #326), and take the fake out again before anything else
// in this process can require the real one.
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

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. one lock order for every flush ===');
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

  const flushes = statements.filter(function (one) { return one.flush; });
  t.equal(flushes.length, 1, 'the flush is ONE statement (#820)');
  const p = flushes.length ? flushDouble.named(null, flushes[0].params) : {};
  const zip = function (prefix) {
    return (p[prefix + '_h'] || []).map(function (h, i) {
      return [h, p[prefix + '_r'][i], p[prefix + '_k'][i]].join('/');
    });
  };
  const sorted = 'admin_stats.calls/default/k authn.sessions/acme/sid-a ' +
    'authn.sessions/default/sid-a authn.sessions/default/sid-b ' +
    'oauth2.authzCodes/default/zz';
  t.equal(zip('lock').join(' '), sorted,
          'every row is locked in (handle, realm, key) order, upserts and ' +
          'deletes interleaved — the order two concurrent flushes must agree ' +
          'on for a deadlock between them to be impossible rather than rare');
  const text = postgres.MINTED_FLUSH;
  const at = function (s) { return text.indexOf(s); };
  t.check(/lk AS MATERIALIZED \(SELECT handle, realm, key, body FROM sts_minted .* ORDER BY handle, realm, key FOR UPDATE\)/
            .test(text),
          'the statement locks those rows FOR UPDATE in that order (`lk`)');
  t.check(at('lk AS MATERIALIZED') >= 0 &&
          /lkn AS MATERIALIZED \(SELECT count\(\*\) AS n FROM lk\)/
            .test(text) &&
          /ok AS MATERIALIZED \(SELECT f\.ok AND c\.bad = 0 AND l\.n >= 0 AS go FROM fence f CROSS JOIN chk c CROSS JOIN lkn l\)/
            .test(text),
          'and `ok` reads the lock to its end (`lkn`) before it answers');
  const writers = ['ins AS (INSERT INTO sts_minted',
                   'del AS (DELETE FROM sts_minted',
                   'ses AS (INSERT INTO sts_sessions',
                   'sdel AS (DELETE FROM sts_sessions',
                   'ixd AS (DELETE FROM sts_minted_index',
                   'ixi AS (INSERT INTO sts_minted_index',
                   'chg AS (INSERT INTO sts_changes'];
  const gated = writers.every(function (w) {
    const start = at(w);
    const next = text.indexOf(' AS (', start + w.length);
    const body = text.slice(start, next < 0 ? text.length : next);
    return start > at('lk AS MATERIALIZED') &&
      body.indexOf('(SELECT go FROM ok)') > 0;
  });
  t.check(gated, 'and NOTHING IS WRITTEN BEFORE THE LOCKS: every write ' +
          'reads `ok`');
  t.check(/ORDER BY u\.h, u\.r, u\.k ON CONFLICT/.test(text),
          'and the upserts — a new key is locked by its insert — go in the ' +
          'same order, in one INSERT');
  const deleted = new Set(zip('del'));
  const kinds = sorted.split(' ').map(function (id) {
    return deleted.has(id) ? 'D' : 'U';
  }).join('');
  t.equal(kinds, 'DUDUU',
          'and each row still gets the write it was handed: a delete ' +
          'stays a delete when it sorts between two upserts');
  t.check(!statements.some(function (one) {
    return /^(BEGIN|COMMIT)$/.test(one.sql);
  }), 'with no BEGIN and no COMMIT: one statement is its own transaction');

  t.log.info('=== B. the change log is arrays, under the bind limit ===');
  statements.length = 0;
  const many = [];
  for (let i = 0; i < 17000; i++) {
    many.push({ handle: 'audit.events', realm: 'default',
                key: 'k' + String(i).padStart(5, '0'), body: 'x', own: true });
  }
  await driver.saveMinted(many, []);
  const big = statements.filter(function (one) { return one.flush; });
  const q = big.length ? flushDouble.named(null, big[0].params) : {};
  t.equal((q.chg_kind || []).length, 17000,
          'every minted row still gets its change-log row');
  t.check(big.length === 1 && big[0].params.length ===
            postgres.MINTED_FLUSH_LAYOUT.length &&
          big[0].params.length <= 65535,
          'AND THE STATEMENT CARRIES THE LAYOUT\'S FIXED NUMBER OF ' +
          'PARAMETERS, whatever the rows. 17,000 rows at four a row was ' +
          '68,000 — which the protocol\'s 16-bit count wraps, and ' +
          'PostgreSQL refuses as "bind message has N parameter formats but 0 ' +
          'parameters"',
          big.map(function (one) {
            return one.params.length;
          }).join(', '));

  // The path is reported so a failure names the file it is about.
  t.log.info('driver: ' + path.relative(process.cwd(),
    require.resolve('../persistence/persistence_postgres')));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'postgres_minted_writes',
  describe: 'the postgres driver takes minted row locks in one order before ' +
            'any write and sends the change log as arrays',
  run: run
};
