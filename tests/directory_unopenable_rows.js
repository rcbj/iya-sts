// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_unopenable_rows.js
//
// ===========================================================================
// A DIRECTORY ROW THIS PROCESS CANNOT OPEN DOES NOT STOP A FLUSH THAT ONLY
// DELETES IT, AND A MERGE THAT MEETS ONE TRIES ONCE MORE (2026-10-02).
//
// `saveDirectory()` locks every row a flush touches and opened each one it
// locked. A removed realm's rows are deleted after its data keys went with
// it, so the open threw STS-STORE-0072, the whole flush rolled back, and the
// removal was answered 503 — the full run on 1a925cc0, single-node:
// sts_scheduler (a removed realm) and sts_xml_schema_validation (a realm a
// moment old, whose `directory` key another worker thread had made).
//
//   A. a flush that DELETES a row that does not open commits, and the
//      DELETE is issued;
//   B. a flush that MERGES into a row that does not open is tried twice —
//      once more after the data-key rows are read again — and then refused
//      with STS-STORE-0072, never written over.
//
// Against a `pg` that records statements (`directory_queries.js`'s), so the
// order of statements is what is asserted. Nothing here is sealed: a value
// that is not a version-2 envelope does not open, which is the state.
// ===========================================================================

const postgres = require('../persistence/persistence_postgres');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'directory_unopenable_rows',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

const REALM = 'gone';
const KEY = 'cn=acme,ou=crl,dc=gone,dc=example,dc=net';

// A `pg` that remembers every statement and answers a locking SELECT with
// one row whose blob does not open.
function fakePg(statements) {
  function reply(sql, params) {
    statements.push({ sql: String(sql), params: params || [] });
    const rows = /FOR UPDATE/.test(String(sql)) ?
      [{ realm: REALM, dn_key: KEY, dn: KEY, attrs: 'not-an-envelope',
         origin: null, created_at: null, modified_at: null }] : [];
    return Promise.resolve({ rows: rows, rowCount: rows.length });
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

function driverWith(statements) {
  log.debug("Entering driverWith().");
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: fakePg(statements) };
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

function count(statements, pattern) {
  log.debug("Entering count().");
  log.debug("Leaving count().");
  return statements.filter(function (one) {
    return pattern.test(one.sql);
  }).length;
}

async function run(t) {
  log.debug("Entering run().");

  t.log.info('=== A. a delete of a row that does not open ===');
  const deleting = [];
  let failure = null;
  try {
    await driverWith(deleting).saveDirectory({
      upserts: [], deletes: [{ realm: REALM, key: KEY }],
      touched: [REALM], removedRealms: [], all: null });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    failure = e;
  }
  t.check(!failure, 'A1. the flush commits although the locked row does ' +
          'not open', failure && failure.message);
  t.check(count(deleting, /DELETE FROM sts_ldap_entries WHERE realm = \$1 AND dn_key/) === 1,
          'A2. the DELETE is issued',
          deleting.map(function (one) {
            return one.sql.slice(0, 60);
          }).join(' | '));

  t.log.info('=== B. a merge into a row that does not open ===');
  const merging = [];
  failure = null;
  try {
    await driverWith(merging).saveDirectory({
      upserts: [{ realm: REALM, key: KEY, base: null,
                  json: '{}', entry: { dn: KEY,
                                       attributes: { cn: ['acme'] } } }],
      deletes: [], touched: [REALM], removedRealms: [], all: null });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    failure = e;
  }
  t.equal(failure && errorCodes.codeOf(failure), 'STS-STORE-0072',
          'B1. it is refused with STS-STORE-0072');
  t.equal(count(merging, /FOR UPDATE/), 2,
          'B2. it was tried twice: once more after the data-key rows were ' +
          'read again');
  t.equal(count(merging, /INSERT INTO sts_ldap_entries|UPDATE sts_ldap_entries/), 0,
          'B3. nothing was written over the row it could not read');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_unopenable_rows',
  describe: 'a directory row that will not open stops no delete, and a ' +
            'merge into one is tried once more',
  run: run
};
