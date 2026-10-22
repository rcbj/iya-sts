// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: minted_sort_at.js
//
// ===========================================================================
// THE NEWEST ROWS OF AN ON-DEMAND STORE, BY AN INDEX ROW (2026-10-22, #820).
//
// Monitoring → Tokens asked `minted.newest`, which sorted the store's whole
// partition by `sts_minted.written_at` — a column with only a BRIN, and which
// may carry no btree (#630: it changes on every write, so any btree on it
// makes every update of `sts_minted` non-HOT). 13-14 s a page on 8081. A store
// now declares `sortBy`, and its value is written on ONE more
// `sts_minted_index` row per stored row (`sort_at`, schema version 25).
//
//   A. the driver: the sort row is written with the store's value beside the
//      row's other index rows, and goes with them when the row is rewritten
//      or deleted; a row with no value writes none; the backfill and the
//      completion mark send `sort_at` too;
//   B. the flush: a store with `sortBy` hands the driver its value, one with
//      none hands none, a hook that throws or answers no number hands none,
//      an unchanged row writes nothing and a moved value rewrites, and a
//      delete of a sorted-only store takes its index rows;
//   C. `minted.newest` orders by `sort_at` through the partial index's own
//      predicate, and never by `written_at`;
//   D. the token register declares `sortBy` as when a token was issued.
//
// A `pg` double records the statements (`tests/tools/store_double.js`);
// `tests/postgres_tally_commit.js`'s arrangement. What it cannot see — the
// planner and the collation — was checked against a real postgres when this
// was written (persistence/CLAUDE.md, *The newest rows by an index*).
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const storeDouble = require('./tools/store_double');
const flushDouble = require('./tools/minted_flush_double');

const config = require('../common/config');
const realms = require('../common/realms');
const keystore = require('../common/keystore');
const stats = require('../common/admin_stats');
const minted = require('../persistence/persistence_minted');
const postgres = require('../persistence/persistence_postgres');
const queries = require('../persistence/minted_queries');

const log = require('bunyan').createLogger({
  name: 'minted_sort_at',
  level: process.env.LOG_LEVEL || 'info' });

const REALM = 'minted-sort-at';
const SORT = queries.SORT_INDEX_KEY;

// A `pg` that connects to nothing and remembers every statement. The minted
// flush is one statement since #820 (MINTED_FLUSH), played against Maps by
// `tools/minted_flush_double.js` and recorded as `MINTED_FLUSH` with its
// parameters by name.
function fakePg(statements) {
  log.debug("Entering fakePg().");
  function FakeClient() {}
  FakeClient.prototype.query = function (sql, params) {
    if (flushDouble.isFlush(sql)) {
      statements.push({ sql: 'MINTED_FLUSH',
                        params: flushDouble.named(sql) });
      return Promise.resolve(flushDouble.play(flushDouble.state(), sql));
    }
    statements.push({ sql: String(sql && sql.text ? sql.text : sql),
                      params: params || [] });
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
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.query = function (sql, params) {
    return new FakeClient().query(sql, params);
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

// The index rows one statement files, as objects: the minted flush's
// `ixnew_*` arrays (#820), or an INSERT INTO sts_minted_index's (the backfill
// and the completion mark).
function filedBy(statement) {
  log.debug("Entering filedBy().");
  const p = statement.params;
  if (statement.sql === 'MINTED_FLUSH') {
    log.debug("Leaving filedBy(). The flush.");
    return (p.ixnew_h || []).map(function (handle, i) {
      return { handle: handle, realm: p.ixnew_r[i], indexKey: p.ixnew_i[i],
               key: p.ixnew_k[i], sortAt: p.ixnew_s[i] };
    });
  }
  const out = (p[0] || []).map(function (handle, i) {
    return { handle: handle, realm: p[1][i], indexKey: p[2][i], key: p[3][i],
             sortAt: p[4] ? p[4][i] : undefined };
  });
  log.debug("Leaving filedBy().");
  return out;
}

function inserts(statements) {
  log.debug("Entering inserts().");
  log.debug("Leaving inserts().");
  return statements.filter(function (one) {
    return /^INSERT INTO sts_minted_index /.test(one.sql) ||
      (one.sql === 'MINTED_FLUSH' && (one.params.ixnew_h || []).length > 0);
  });
}

// The rows whose index rows a flush replaces or drops, as the old DELETE's
// three arrays: handles, realms, keys.
function deletes(statements) {
  log.debug("Entering deletes().");
  log.debug("Leaving deletes().");
  return statements.filter(function (one) {
    return one.sql === 'MINTED_FLUSH' &&
      (one.params.ixup_h || []).concat(one.params.ixgone_h || []).length > 0;
  }).map(function (one) {
    const p = one.params;
    return { statement: one,
             params: [p.ixup_h.concat(p.ixgone_h), p.ixup_r.concat(p.ixgone_r),
                      p.ixup_k.concat(p.ixgone_k)] };
  });
}

async function driverHalf(t) {
  log.debug("Entering driverHalf().");
  t.log.info('=== A. the driver writes and deletes the sort row ===');
  const statements = [];
  const driver = driverWith(statements);
  await driver.saveMinted([
    { handle: 'admin_stats.tokens', realm: 'r', key: 'k1', body: 'b',
      lookups: ['digest-u', 'digest-s'], sortAt: 1760000000123 },
    { handle: 'oauth2_bcp.refreshTokens', realm: 'r', key: 'k2', body: 'b',
      lookups: ['digest-f'], sortAt: null }
  ], []);
  const ins = inserts(statements);
  t.equal(ins.length, 1, 'A1. one statement files every index row');
  const filed = ins.length ? filedBy(ins[0]) : [];
  const sortRows = filed.filter(function (one) {
    return one.indexKey === SORT;
  });
  t.equal(sortRows.length, 1,
          'A2. exactly one sort row, for the row that has a value',
          JSON.stringify(filed));
  t.check(sortRows.length === 1 && sortRows[0].handle ===
          'admin_stats.tokens' && sortRows[0].key === 'k1' &&
          sortRows[0].sortAt === 1760000000123,
          'A3. carrying the store\'s value as sort_at, under the row\'s key',
          JSON.stringify(sortRows));
  t.check(filed.filter(function (one) {
    return one.indexKey !== SORT;
  }).every(function (one) {
    return one.sortAt === null;
  }), 'A4. every other index row has sort_at NULL', JSON.stringify(filed));
  t.check(/ixi AS \(INSERT INTO sts_minted_index \(handle, realm, index_key, key, sort_at\)/
            .test(postgres.MINTED_FLUSH) &&
          /DO UPDATE SET sort_at = EXCLUDED\.sort_at WHERE sts_minted_index\.sort_at IS DISTINCT FROM EXCLUDED\.sort_at/
            .test(postgres.MINTED_FLUSH),
          'A5. the flush names the sort_at column, and a sort row filed ' +
          'again with a moved value is updated in place');
  const del = deletes(statements);
  t.check(del.length === 1 && del[0].params[2].indexOf('k1') >= 0 &&
          del[0].params[2].indexOf('k2') >= 0 &&
          del[0].statement === ins[0],
          'A6. the row\'s old index rows, its sort row among them, are ' +
          'replaced in the same statement',
          JSON.stringify(del.map(function (one) { return one.params; })));

  statements.length = 0;
  await driver.saveMinted([
    { handle: 'oauth2_bcp.refreshTokens', realm: 'r', key: 'k3', body: 'b',
      lookups: ['digest-f'] }
  ], []);
  t.check(inserts(statements).every(function (one) {
    return filedBy(one).every(function (row) {
      return row.indexKey !== SORT && row.sortAt === null;
    });
  }) && inserts(statements).length === 1,
          'A7. a row from a store with no sortBy writes no sort row');

  statements.length = 0;
  await driver.saveMinted([], [
    { handle: 'admin_stats.tokens', realm: 'r', key: 'k1', indexed: true }
  ]);
  const gone = deletes(statements);
  t.check(gone.length === 1 && gone[0].params[0][0] ===
          'admin_stats.tokens' && gone[0].params[2][0] === 'k1' &&
          inserts(statements).length === 0,
          'A8. a deleted row loses every index row, the sort row included, ' +
          'and none is written', JSON.stringify(statements.map(function (s) {
            return s.sql.slice(0, 40);
          })));

  statements.length = 0;
  await driver.writeMintedIndex([
    { handle: 'admin_stats.tokens', realm: 'r', indexKey: 'digest-u',
      key: 'k4' },
    { handle: 'admin_stats.tokens', realm: 'r', indexKey: SORT, key: 'k4',
      sortAt: 42 }
  ]);
  const back = inserts(statements);
  t.check(back.length === 1 && JSON.stringify(back[0].params[4]) ===
          '[null,42]',
          'A9. the backfill files a sort row with its value',
          back.length && JSON.stringify(back[0].params));
  statements.length = 0;
  await driver.markMintedIndexed('admin_stats.tokens');
  t.check(inserts(statements).length === 1 &&
          JSON.stringify(inserts(statements)[0].params[4]) === '[null]',
          'A10. and the completion mark sends a NULL sort_at');
  log.debug("Leaving driverHalf().");
}

async function armKeystore(dir) {
  log.debug("Entering armKeystore().");
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  keystore.reset();
  keystore.setStore({
    loadKeys: function () {
      return Promise.resolve([]);
    },
    saveKeys: function () {
      return Promise.resolve();
    },
    deleteKeys: function () {
      return Promise.resolve();
    }
  });
  await keystore.start();
  log.debug("Leaving armKeystore().");
}

function disarmKeystore() {
  log.debug("Entering disarmKeystore().");
  delete process.env.STS_KEYS_SOURCE;
  delete process.env.STS_KEYS_KEK_PROVIDER;
  delete process.env.STS_KEYS_KEK_FILE;
  keystore.reset();
  log.debug("Leaving disarmKeystore().");
}

// A driver that keeps what each flush handed it.
function capturing(seen) {
  log.debug("Entering capturing().");
  log.debug("Leaving capturing().");
  return {
    loadMinted: function () {
      return Promise.resolve([]);
    },
    readMinted: function () {
      return Promise.resolve(null);
    },
    origin: function () {
      return 'minted-sort-at-origin';
    },
    saveMinted: function (upserts, removed) {
      upserts.forEach(function (one) {
        seen.push({ op: 'upsert', handle: one.handle, journalKey:
                    one.journalKey, lookups: one.lookups,
                    sortAt: one.sortAt });
      });
      (removed || []).forEach(function (one) {
        seen.push({ op: 'delete', handle: one.handle, journalKey:
                    one.journalKey, indexed: one.indexed });
      });
      return Promise.resolve({ refused: [], merged: [] });
    }
  };
}

async function flushHalf(t) {
  log.debug("Entering flushHalf().");
  t.log.info('=== B. the flush hands the driver the store\'s sort value ===');
  const both = realms.map({ persist: 'test.minted-sort-at.both',
    onDemand: { maxEntries: 10 },
    indexBy: function (value) {
      return value && value.owner ? ['o:' + value.owner] : [];
    },
    sortBy: function (value) {
      if (value && value.boom) {
        throw new Error('a hook that throws');
      }
      return value ? value.at : null;
    } });
  const sortedOnly = realms.map({ persist: 'test.minted-sort-at.sorted',
    onDemand: { maxEntries: 10 },
    sortBy: function (value) {
      return value ? value.at : null;
    } });
  const plain = realms.map({ persist: 'test.minted-sort-at.plain',
    onDemand: { maxEntries: 10 },
    indexBy: function (value) {
      return value && value.owner ? ['o:' + value.owner] : [];
    } });
  const seen = [];
  minted.reset();
  minted.endPrefetch();
  t.check(minted.setDriver(capturing(seen), 'postgres'),
          'B0. the capturing driver is installed');
  const of = function (handle, key) {
    return seen.filter(function (one) {
      return one.handle === handle && one.journalKey === key;
    });
  };

  both.set('t1', { owner: 'alice', at: 1000.7 });
  sortedOnly.set('s1', { at: 2000 });
  plain.set('p1', { owner: 'bob' });
  await minted.flush();
  const t1 = of('test.minted-sort-at.both', 't1')[0] || {};
  t.check(t1.sortAt === 1000 && Array.isArray(t1.lookups) &&
          t1.lookups.length === 1,
          'B1. a store with sortBy hands its value, as a whole number, ' +
          'beside its index keys', JSON.stringify(t1));
  const s1 = of('test.minted-sort-at.sorted', 's1')[0] || {};
  t.check(s1.sortAt === 2000 && Array.isArray(s1.lookups) &&
          s1.lookups.length === 0,
          'B2. a store with sortBy and no indexBy hands an empty key list, ' +
          'so its sort row is still replaced', JSON.stringify(s1));
  const p1 = of('test.minted-sort-at.plain', 'p1')[0] || {};
  t.check(p1.sortAt === null && Array.isArray(p1.lookups),
          'B3. a store with no sortBy hands no value', JSON.stringify(p1));

  seen.length = 0;
  both.set('t1', { owner: 'alice', at: 1000.2, n: 2 });
  await minted.flush();
  t.check((of('test.minted-sort-at.both', 't1')[0] || {}).lookups === null,
          'B4. a rewrite filed exactly as it was writes no index rows',
          JSON.stringify(seen));

  seen.length = 0;
  both.set('t1', { owner: 'alice', at: 3000 });
  await minted.flush();
  const moved = of('test.minted-sort-at.both', 't1')[0] || {};
  t.check(moved.sortAt === 3000 && Array.isArray(moved.lookups) &&
          moved.lookups.length === 1,
          'B5. a moved sort value under the same index keys rewrites them',
          JSON.stringify(moved));

  seen.length = 0;
  both.set('t2', { owner: 'carol', boom: true });
  both.set('t3', { owner: 'carol', at: 'soon' });
  await minted.flush();
  t.check((of('test.minted-sort-at.both', 't2')[0] || {}).sortAt === null &&
          (of('test.minted-sort-at.both', 't3')[0] || {}).sortAt === null,
          'B6. a hook that throws, or answers no number, hands no value and ' +
          'fails nothing', JSON.stringify(seen));

  seen.length = 0;
  sortedOnly.delete('s1');
  plain.delete('p1');
  await minted.flush();
  t.check((of('test.minted-sort-at.sorted', 's1')[0] || {}).indexed === true,
          'B7. a delete from a store with only sortBy takes its index rows',
          JSON.stringify(seen));
  t.check((of('test.minted-sort-at.plain', 'p1')[0] || {}).indexed === true,
          'B8. and an indexBy store\'s delete still does');

  both.realmMap().clear();
  sortedOnly.realmMap().clear();
  plain.realmMap().clear();
  await minted.flush();
  log.debug("Leaving flushHalf().");
}

function queryHalf(t) {
  log.debug("Entering queryHalf().");
  t.log.info('=== C. minted.newest orders by the sort row ===');
  const built = queries.build('minted.newest',
                              ['admin_stats.tokens', 'default', 5, 500]);
  t.check(/FROM sts_minted_index i CROSS JOIN LATERAL \(SELECT /.test(
    built.text) && /LIMIT 1\) m WHERE i\.handle = \$1/.test(built.text),
          'C1. it walks the index and reads each row through a LATERAL ' +
          'LIMIT 1, so no plan can turn it into a join', built.text);
  t.check(/ORDER BY i\.sort_at DESC, i\.key DESC LIMIT \$5/.test(built.text),
          'C2. ordered by sort_at, newest first, then the key');
  t.check(/i\.sort_at IS NOT NULL/.test(built.text),
          'C3. repeating the partial index\'s predicate, so a generic plan ' +
          'can use it');
  t.check(!/written_at/.test(built.text),
          'C4. and never by written_at, which only a BRIN covers');
  t.check(/x\.body <> \$3/.test(built.text) &&
          /x\.expires_at IS NULL OR x\.expires_at > \$4/.test(built.text),
          'C5. still leaving tombstones and expired rows out');
  t.check(SORT.indexOf('$') >= 0 && SORT !== '$index-complete$',
          'C6. the sort row\'s index key is no digest and not the mark');
  const index = postgres.SCHEMA_OBJECTS.filter(function (one) {
    return one.name === 'sts_minted_index_sort';
  })[0];
  t.check(!!index && index.afterColumns === true &&
          /\(handle, realm, sort_at DESC, key DESC\) WHERE sort_at IS NOT NULL/
            .test(index.statement),
          'C7. the partial index is in the schema, after the columns',
          index && index.statement);
  log.debug("Leaving queryHalf().");
}

function registerHalf(t) {
  log.debug("Entering registerHalf().");
  t.log.info('=== D. the token register declares its sort value ===');
  const declared = realms.handleFor('admin_stats.tokens');
  t.check(!!declared && typeof declared.sortOf === 'function',
          'D1. admin_stats.tokens declares sortBy');
  if (declared && typeof declared.sortOf === 'function') {
    t.equal(declared.sortOf({ issuedAt: 1760000000456, iat: 1760000000 }),
            1760000000456, 'D2. by when the token was issued, in ms');
    t.equal(declared.sortOf({ iat: 1760000000 }), 1760000000000,
            'D3. or by its iat where no issue time was recorded');
    t.equal(declared.sortOf({}), null, 'D4. and none for neither');
  }
  t.check(typeof stats.issuedSetsAsync === 'function',
          'D5. the register is loaded');
  log.debug("Leaving registerHalf().");
}

async function run(t) {
  log.debug("Entering run().");
  await driverHalf(t);
  queryHalf(t);
  registerHalf(t);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-minted-sort-at-'));
  const made = realms.create({ id: REALM, name: REALM,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + REALM + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  let armed = false;
  try {
    await armKeystore(dir);
    armed = true;
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    await realms.run(made.realm, function () {
      return flushHalf(t);
    });
  } finally {
    try {
      config.clearOverride('global.mode');
      config.clearOverride('persistence.minted');
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
    realms.remove(REALM);
    if (armed) {
      disarmKeystore();
    }
    minted.reset();
    minted.endPrefetch();
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'minted_sort_at',
  describe: 'an on-demand store\'s sortBy value is one more index row, ' +
            'written and deleted with the row, and minted.newest walks it ' +
            '(#820)',
  run: run
};
