// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: data_key_index.js
//
// ===========================================================================
// THE DIRECTORY'S DATA-KEY INDEX (#623, schema version 17): the re-encryption
// job and the data-key count never walk the directory.
//
// Until #623 both jobs walked every `sts_ldap_entries` row and opened each on
// the front process to find the data keys inside it — on 8081, at 1.5M
// entries, about 90 s of the thread every hour while any key was superseded,
// re-sealing nothing. Now every writer records the keys an entry holds
// values under in `dek_keys`, triggers keep `sts_ldap_dek_counts`, and what is
// left to open is an entry written before the column existed, once.
// COUNTED, NOT TIMED — every statement the driver sends is recorded by a fake
// `pg`, and a statement reading `sts_ldap_entries` without naming
// `dek_keys` is a walk:
//
//   A. `dekKeysOf()`: the blob's key once, each inner value's key once per
//      value, and only the blob's for a blob that did not open;
//   B. a write records them: the flush's INSERT carries `dek_keys`;
//   C. the count reads the counters and no entry; it is REFUSED
//      (STS-STORE-0080) while an entry's keys are not known;
//   D. the re-seal reads only the entries whose `dek_keys` name a key it was
//      given, and writes their new keys with them;
//   E. the index's catch-up opens only the entries whose keys are not known,
//      sets them compare-and-set, and stops at its budget;
//   F. with STS_TEST_POSTGRES_URL, against a real database: the triggers
//      keep every key's counter equal to a fresh sum, through inserts,
//      updates, the catch-up's NULL-to-keys, deletes and a rollback.
// ===========================================================================

delete process.env.CONFIG_FILE;

const postgres = require('../persistence/persistence_postgres');
const codec = require('../persistence/directory_codec');

const log = require('bunyan').createLogger({ name: 'data_key_index',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// Two sealed-looking values: the shape `keystore.seal()` writes, under the
// keys `dekAAAAAAA` and `dekBBBBBBB`.
const UNDER_A = '$aesgcm$2$dekAAAAAAA$aXY=$dGFn$Ym9keQ==';
const UNDER_B = '$aessiv$2$dekBBBBBBB$aXY=$dGFn$Ym9keQ==';

// A `pg` that remembers every statement and answers through `answer()`.
function fakePg(statements, answer) {
  log.debug("Entering fakePg().");
  function reply(sql, params) {
    statements.push({ sql: String(sql), params: params || [] });
    const rows = answer ? answer(String(sql), params || []) : undefined;
    return Promise.resolve({ rows: rows || [], rowCount: (rows || []).length });
  }
  function FakeClient() {}
  FakeClient.prototype.query = reply;
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
  FakePool.prototype.query = reply;
  FakePool.prototype.end = function () { return Promise.resolve(); };
  log.debug("Leaving fakePg().");
  return { Pool: FakePool, Client: FakeClient };
}

function driverWith(statements, answer) {
  log.debug("Entering driverWith().");
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: fakePg(statements, answer) };
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({ url: 'postgres://sts@localhost:5432/sts',
                             log: QUIET });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
}

// The statements that read directory rows without the index: walks.
function walksIn(statements) {
  log.debug("Entering walksIn().");
  log.debug("Leaving walksIn().");
  return statements.filter(function (one) {
    return /FROM sts_ldap_entries/.test(one.sql) &&
      !/dek_keys (\?\||IS NULL)/.test(one.sql);
  });
}

// A refusal's code, or '' when the promise resolved.
function codeOf(promise) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return promise.then(function () {
    return '';
  }, function (e) {
    log.debug("Caught in codeOf(): " + ((e && e.message) || e));
    return require('../common/error_codes').codeOf(e) ||
      String((e && e.message) || e);
  });
}

function theKeys(t) {
  log.debug("Entering theKeys().");
  t.log.info('=== A. the keys an entry holds values under ===');
  const attrs = { uid: ['ann'], ststotpsecret: [UNDER_A],
                  krb5key: [UNDER_B, UNDER_B] };
  t.equal(JSON.stringify(codec.dekKeysOf(attrs, attrs)),
          JSON.stringify({ dekAAAAAAA: 1, dekBBBBBBB: 2 }),
          'A1. a plain entry: each inner value\'s key, once per value');
  const blob = '$aessiv$2$dekDirDirDir$aXY=$dGFn$Ym9keQ==';
  t.equal(JSON.stringify(codec.dekKeysOf(attrs, blob)),
          JSON.stringify({ dekDirDirDir: 1, dekAAAAAAA: 1, dekBBBBBBB: 2 }),
          'A2. a sealed entry: the blob\'s key too');
  t.equal(JSON.stringify(codec.dekKeysOf(null, blob)),
          JSON.stringify({ dekDirDirDir: 1 }),
          'A3. a blob that did not open: its own key only');
  t.equal(JSON.stringify(codec.dekKeysOf({ uid: ['bob'] }, { uid: ['bob'] })),
          '{}', 'A4. an entry holding nothing sealed: none');
  log.debug("Leaving theKeys().");
}

async function theWrite(t) {
  log.debug("Entering theWrite().");
  t.log.info('=== B. a write records them ===');
  const statements = [];
  const driver = driverWith(statements, function () {
    return undefined;
  });
  await driver.saveDirectory({
    upserts: [{ realm: 'default', key: 'uid=ann,ou=users,dc=example,dc=com',
                entry: { dn: 'uid=ann,ou=users,dc=example,dc=com',
                         attributes: { uid: ['ann'],
                                       ststotpsecret: [UNDER_A] } } }],
    deletes: [], removedRealms: [] });
  const insert = statements.filter(function (one) {
    return /^INSERT INTO sts_ldap_entries/.test(one.sql);
  })[0];
  t.check(insert && /dek_keys/.test(insert.sql) &&
          JSON.parse(insert.params[13]).dekAAAAAAA === 1,
          'B1. the flush writes the entry\'s data keys beside it',
          insert && insert.params[13]);
  log.debug("Leaving theWrite().");
}

async function theCount(t) {
  log.debug("Entering theCount().");
  t.log.info('=== C. the count reads the counters, never an entry ===');
  let unknown = false;
  const statements = [];
  const driver = driverWith(statements, function (sql) {
    if (/SELECT 1 AS remain/.test(sql)) {
      return unknown ? [{ remain: 1 }] : [];
    }
    if (/FROM sts_ldap_dek_counts/.test(sql)) {
      return [{ dek_id: 'dekAAAAAAA', n: '7' }];
    }
    if (/AS n$/.test(sql.trim()) || /count\(\*\)/.test(sql)) {
      return [{ n: 2 }];
    }
    return undefined;
  });
  const counts = await driver.countSealed(['dekAAAAAAA']);
  t.check(counts.dekAAAAAAA === 9,
          'C1. countSealed(): the other tables\' LIKE count and the ' +
          'directory\'s kept counter', JSON.stringify(counts));
  const all = await driver.countAllSealed();
  t.check(all.dekAAAAAAA >= 7, 'C2. countAllSealed() too', JSON.stringify(all));
  const walks = walksIn(statements);
  t.equal(walks.length, 0, 'C3. NO STATEMENT READ AN ENTRY: the directory ' +
          'is counted from sts_ldap_dek_counts (it was every row, opened)',
          JSON.stringify(walks.map(function (one) { return one.sql; })));
  unknown = true;
  t.equal(await codeOf(driver.countSealed(['dekAAAAAAA'])), 'STS-STORE-0080',
          'C4. while an entry\'s keys are not known, the count is refused ' +
          'rather than given short');
  t.equal(await codeOf(driver.countAllSealed()), 'STS-STORE-0080',
          'C5. both counts');
  log.debug("Leaving theCount().");
}

async function theReseal(t) {
  log.debug("Entering theReseal().");
  t.log.info('=== D. the re-seal reads only the entries naming the keys ===');
  const statements = [];
  let served = false;
  const driver = driverWith(statements, function (sql) {
    if (/FROM sts_ldap_entries WHERE dek_keys \?\|/.test(sql) && !served) {
      served = true;
      return [{ realm: 'default', dn_key: 'uid=ann,ou=users,dc=x',
                dn: 'uid=ann,ou=users,dc=x',
                attrs: { uid: ['ann'], ststotpsecret: [UNDER_A] } }];
    }
    if (/^UPDATE sts_ldap_entries/.test(sql)) {
      return [{}];
    }
    return undefined;
  });
  const tally = await driver.resealSealed(['dekAAAAAAA'], function (value) {
    return value.indexOf('$dekAAAAAAA$') > 0
      ? value.replace('$dekAAAAAAA$', '$dekCCCCCCC$') : null;
  }, { limit: 500 });
  const reads = statements.filter(function (one) {
    return /FROM sts_ldap_entries/.test(one.sql);
  });
  t.check(reads.length >= 1 && reads.every(function (one) {
    return /dek_keys \?\| \$1/.test(one.sql) &&
      JSON.stringify(one.params[0]) === '["dekAAAAAAA"]';
  }), 'D1. every read of the directory asks for the entries whose ' +
     'dek_keys name the key (was: every row of the store)',
          JSON.stringify(reads.map(function (one) { return one.sql; })));
  t.equal(walksIn(statements).length, 0, 'D2. and no statement walks');
  const update = statements.filter(function (one) {
    return /^UPDATE sts_ldap_entries/.test(one.sql);
  })[0];
  t.check(tally.entries === 1 && update && /dek_keys = \$5/.test(update.sql) &&
          JSON.parse(update.params[4]).dekCCCCCCC === 1 &&
          !JSON.parse(update.params[4]).dekAAAAAAA,
          'D3. the entry is re-sealed and its new keys written with it',
          JSON.stringify({ tally: tally, keys: update && update.params[4] }));
  log.debug("Leaving theReseal().");
}

async function theCatchUp(t) {
  log.debug("Entering theCatchUp().");
  t.log.info('=== E. the catch-up opens only entries with no keys ===');
  const statements = [];
  let pages = 0;
  const page = function (from) {
    const rows = [];
    for (let i = 0; i < 500; i++) {
      rows.push({ realm: 'default', dn_key: 'uid=p' + (from + i),
                  attrs: { uid: ['p'], ststotpsecret: [UNDER_A] } });
    }
    return rows;
  };
  const driver = driverWith(statements, function (sql) {
    if (/SELECT 1 AS remain/.test(sql)) {
      return [{ remain: 1 }];
    }
    if (/WHERE dek_keys IS NULL AND \(realm, dn_key\) >/.test(sql)) {
      pages += 1;
      return page(pages * 1000);
    }
    if (/^UPDATE sts_ldap_entries AS e SET dek_keys/.test(sql)) {
      return page(0);
    }
    return undefined;
  });
  const done = await driver.indexSealed({ budgetMs: 0 });
  t.check(done.indexed === 0 && pages === 0 && done.remaining === true,
          'E1. a budget of nothing opens nothing, and says more remain',
          JSON.stringify({ done: done, pages: pages }));
  const some = await driver.indexSealed({ budgetMs: 50 });
  const updates = statements.filter(function (one) {
    return /^UPDATE sts_ldap_entries AS e SET dek_keys/.test(one.sql);
  });
  t.check(some.indexed >= 500 && pages === updates.length &&
          updates.every(function (one) {
            return /e\.dek_keys IS NULL AND e\.attrs = u\.a::jsonb/
              .test(one.sql) &&
              JSON.parse(one.params[3][0]).dekAAAAAAA === 1;
          }), 'E2. each page read through the partial index is given its ' +
          'keys, compare-and-set (still NULL, same blob)',
          JSON.stringify({ indexed: some.indexed, pages: pages }));
  t.equal(walksIn(statements).length, 0,
          'E3. and nothing else of the directory is read');
  log.debug("Leaving theCatchUp().");
}

// F. A REAL DATABASE, when one is named: the per-key counters stay exact.
async function realDatabase(t) {
  log.debug("Entering realDatabase().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== F. skipped: STS_TEST_POSTGRES_URL names no database ' +
               '(the in-process suite has none) ===');
    log.debug("Leaving realDatabase(). Skipped.");
    return;
  }
  t.log.info('=== F. against ' + url.replace(/:[^:@/]*@/, ':***@') + ' ===');
  const pg = require('pg');
  const schema = 'deks_' + process.pid;
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  try {
    await admin.query('CREATE SCHEMA ' + schema);
    await admin.query('SET search_path TO ' + schema);
    for (const object of postgres.SCHEMA_OBJECTS) {
      if (object.name === 'sts_ldap_entries' ||
          /^sts_ldap_(count|dek)/.test(object.name) ||
          /^sts_ldap_entries_dek/.test(object.name)) {
        await admin.query(object.statement);
      }
    }
    // Rows from before the column was written: NULL, and one with keys
    // already, which the counters must start from.
    await admin.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs, dek_keys) ' +
      'SELECT \'default\', \'uid=old\' || i, \'x\', \'{}\'::jsonb, CASE ' +
      'WHEN i % 2 = 0 THEN NULL ELSE \'{"dekAAAAAAA": 1}\'::jsonb END FROM ' +
      'generate_series(1, 200) AS i');
    await admin.query('BEGIN');
    for (const one of postgres.SCHEMA_ROUTINES) {
      await admin.query(one.statement);
    }
    await admin.query(postgres.LOCK_FOR_BACKFILL);
    await admin.query(postgres.COUNTS_BACKFILL);
    await admin.query(postgres.DEK_COUNTS_BACKFILL);
    await admin.query('COMMIT');
    const verify = async function (what) {
      const wrong = await admin.query(
        'SELECT coalesce(c.dek_id, x.k) AS id, c.n AS kept, x.n AS summed ' +
        'FROM (SELECT dek_id, sum(n) AS n FROM sts_ldap_dek_counts GROUP ' +
        'BY dek_id HAVING sum(n) <> 0) AS c ' +
        'FULL JOIN (SELECT d.key AS k, sum(d.value::bigint) AS n FROM ' +
        'sts_ldap_entries AS e CROSS JOIN LATERAL jsonb_each_text(' +
        'e.dek_keys) AS d WHERE e.dek_keys IS NOT NULL GROUP BY d.key) AS x ' +
        'ON c.dek_id = x.k WHERE c.n IS DISTINCT FROM x.n');
      const left = await admin.query(
        'SELECT count(*)::int AS n FROM sts_ldap_dek_deltas');
      t.check(wrong.rows.length === 0 && left.rows[0].n === 0,
              what + ': every key\'s counter equals a fresh sum, no delta ' +
              'left', JSON.stringify({ wrong: wrong.rows.slice(0, 5),
                                       deltas: left.rows[0].n }));
    };
    await verify('F1. the counters started from the rows with keys');
    await admin.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
      'attrs, dek_keys) SELECT \'default\', \'uid=new\' || i, \'x\', ' +
      '\'{}\', \'{"dekAAAAAAA": 1, "dekBBBBBBB": 2}\' FROM ' +
      'generate_series(1, 50) AS i');
    await verify('F2. after an insert');
    await admin.query('UPDATE sts_ldap_entries SET dek_keys = ' +
      '\'{"dekCCCCCCC": 1}\' WHERE dn_key LIKE \'uid=new1%\'');
    await verify('F3. after a re-seal moved some to another key');
    await admin.query('UPDATE sts_ldap_entries SET dek_keys = ' +
      '\'{"dekAAAAAAA": 3}\' WHERE dek_keys IS NULL');
    await verify('F4. after the catch-up gave the NULL rows their keys');
    await admin.query('BEGIN');
    await admin.query('DELETE FROM sts_ldap_entries WHERE dn_key LIKE ' +
                      '\'uid=old1%\'');
    await admin.query('ROLLBACK');
    await verify('F5. after a rolled-back delete');
    await admin.query('DELETE FROM sts_ldap_entries WHERE dn_key LIKE ' +
                      '\'uid=new%\'');
    await verify('F6. after a delete');
    // The key's shards summed (#630): one shard alone is not a count.
    const zero = await admin.query('SELECT sum(n) AS n FROM ' +
                                   'sts_ldap_dek_counts WHERE dek_id = ' +
                                   '\'dekBBBBBBB\'');
    t.equal(Number((zero.rows[0] || {}).n || 0), 0,
            'F7. a key nothing holds a value under any more counts 0');
  } finally {
    await admin.query('DROP SCHEMA ' + schema + ' CASCADE').catch(
      function (e) {
        log.debug("Caught in realDatabase(): " + ((e && e.message) || e));
      });
    await admin.end();
  }
  log.debug("Leaving realDatabase().");
}

async function run(t) {
  log.debug("Entering run().");
  theKeys(t);
  await theWrite(t);
  await theCount(t);
  await theReseal(t);
  await theCatchUp(t);
  await realDatabase(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'data_key_index',
  describe: 'the directory\'s data-key index (#623): every write records ' +
            'the keys an entry holds values under, the count reads kept ' +
            'counters and is refused while an entry\'s keys are unknown, ' +
            'the re-seal reads only the entries naming its keys, and no ' +
            'statement walks the directory',
  run: run
};
