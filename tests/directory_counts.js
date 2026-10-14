// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_counts.js
//
// ===========================================================================
// THE DIRECTORY'S COUNTS ARE READ, NOT COUNTED (#618, 2026-10-14).
//
// A windowed worker asked the store `count(*)` — linear in the realm's rows —
// for `ldap.maxEntries` (`capCount()` / `sizeIn()` / `exactCount()`), a
// container's headline (`recentCountUnder()` / `countUnder()`) and the
// credential tiles (`countHolding()`). Each is now one read of
// `sts_ldap_counts`, which the database's triggers keep in the transaction
// that wrote (`persistence_postgres.js`, SCHEMA_ROUTINES).
//
//   A. THE STATEMENTS: `count` and `countHolding` read the counter table and
//      nothing of `sts_ldap_entries`, with no `count(`; an attribute outside
//      COUNTED_ATTRIBUTES is still counted (said, not hidden), and the
//      trigger functions name exactly COUNTED_ATTRIBUTES.
//   B. THE WINDOW: every count it answers costs ONE store question, built
//      with no `count(` in it, and the window's own unwritten net is added
//      exactly as before — a create and a delete here move the answer, a
//      change in flight does not.
//   C. THE DRIVER'S open(): against a store with none of it, the functions
//      are created before the triggers, and the counters are started ONCE
//      under the lock — the one count of the directory there is; against a
//      store that has them, nothing is created, locked or counted.
//   D. AGAINST A REAL POSTGRES, only when STS_TEST_POSTGRES_URL names one the
//      test may build a schema in (an owner): rows written before the
//      counters exist are counted once, then eight concurrent connections
//      insert, upsert, update, delete, roll back and roll back to a
//      savepoint, and every counter equals a fresh count with no delta left
//      behind. Skipped (and said) otherwise; the in-process suite has no
//      database.
// ===========================================================================

const postgres = require('../persistence/persistence_postgres');
const queries = require('../persistence/directory_queries');

const log = require('bunyan').createLogger({ name: 'directory_counts',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;
const DEVICES = 'ou=devices,' + BASE;

function statementsShape(t) {
  log.debug("Entering statementsShape().");
  t.log.info('=== A. the statements ===');
  [queries.count('default', ''), queries.count('default', USERS),
   queries.countHolding('default', USERS, 'userPassword')]
    .forEach(function (one, i) {
      t.check(/FROM sts_ldap_counts/.test(one.text) &&
              !/count\(/i.test(one.text) &&
              !/sts_ldap_entries/.test(one.text),
              'A' + (i + 1) + '. read from the counters, no count(, nothing ' +
              'of sts_ldap_entries', one.text);
    });
  t.equal(queries.countHolding('default', USERS, 'userPassword').values[2],
          'userpassword', 'A4. the attribute is asked lower-cased, as ' +
          'attr_names holds it');
  const other = queries.countHolding('default', USERS, 'stsTotpCredential');
  t.check(/count\(\*\)/.test(other.text) && /sts_ldap_entries/.test(
    other.text), 'A5. an attribute no counter keeps is COUNTED, as before ' +
    '— the one linear path left, and no caller takes it', other.text);
  // #618's own functions: #623's per-data-key ones count no attribute.
  const functions = postgres.SCHEMA_ROUTINES.filter(function (one) {
    return one.kind === 'function' && /^sts_ldap_count_/.test(one.name);
  }).map(function (one) { return one.statement; }).join('\n');
  const named = (functions.match(/'[a-z]+'/g) || []).map(function (q) {
    return q.slice(1, -1);
  }).filter(function (word) {
    return ['insert', 'delete', 'update'].indexOf(word.toLowerCase()) < 0;
  });
  t.equal(JSON.stringify(Array.from(new Set(named)).sort()),
          JSON.stringify(queries.COUNTED_ATTRIBUTES.slice(0).sort()),
          'A6. the trigger functions count exactly COUNTED_ATTRIBUTES');
  t.check(/count\(\*\)/.test(postgres.COUNTS_BACKFILL) &&
          /NOT EXISTS \(SELECT 1 FROM sts_ldap_counts\)/.test(
            postgres.COUNTS_BACKFILL),
          'A7. the one count of the directory runs only while the ' +
          'counters hold nothing');
  log.debug("Leaving statementsShape().");
}

// A window over a store whose counters are a Map, recording every question.
function countedWindow(counters) {
  log.debug("Entering countedWindow().");
  const DirectoryWindow = require('../ldap/directory_window');
  const asked = [];
  const w = new DirectoryWindow({
    currentId: function () { return 'default'; },
    onRemove: function () {},
    windowedContainers: function () { return [USERS, DEVICES]; },
    fromRow: function (realmId, r) { return r; },
    maxEntries: function () { return 100; },
    onTouched: function () {}
  });
  w.attach({
    query: function (name, args) {
      const statement = queries.build(name, args);
      asked.push({ name: name, text: statement.text });
      if (name === 'count') {
        return counters.get(args[1] + '|') || 0;
      }
      if (name === 'countHolding') {
        return { n: counters.get(args[1] + '|') || 0,
                 holding: counters.get(args[1] + '|' +
                                       String(args[2]).toLowerCase()) || 0 };
      }
      if (name === 'byKeys') {
        return [];
      }
      throw new Error('this store answers no ' + name);
    }
  });
  log.debug("Leaving countedWindow().");
  return { w: w, asked: asked };
}

function theWindow(t) {
  log.debug("Entering theWindow().");
  t.log.info('=== B. the window asks one counter per count ===');
  const counters = new Map([[USERS + '|', 200000000],
                            [USERS + '|userpassword', 150000000],
                            [DEVICES + '|', 1000]]);
  const o = countedWindow(counters);
  const once = function (what, fn, expected) {
    const before = o.asked.length;
    const answer = fn();
    const mine = o.asked.slice(before);
    t.check(mine.length === 1 && !/count\(/i.test(mine[0].text),
            what + ': one store question, a counter read with no count(',
            JSON.stringify(mine));
    if (expected !== undefined) {
      t.equal(JSON.stringify(answer), JSON.stringify(expected),
              what + ': the answer');
    }
  };
  once('B1. countUnder(ou=users)', function () {
    return o.w.countUnder('default', USERS);
  }, 200000000);
  once('B2. countHolding(ou=users, userpassword)', function () {
    return o.w.countHolding('default', USERS, 'userpassword');
  }, { n: 200000000, holding: 150000000 });
  once('B3. recentCountUnder(ou=devices)', function () {
    return o.w.recentCountUnder('default', DEVICES);
  }, 1000);
  const before = o.asked.length;
  t.equal(o.w.capCount('default'), 200001000,
          'B4. capCount() is the realm\'s two windowed containers');
  t.equal(o.asked.length - before, 2, 'B4. one counter per container',
          JSON.stringify(o.asked.slice(before)));
  // THE NET: a create and a delete here, not yet written, move every answer.
  o.w.setIn('default', 'uid=new,' + USERS,
            { dn: 'uid=new,' + USERS,
              attributes: { userpassword: ['{SCRYPT}x'] } });
  t.equal(o.w.countUnder('default', USERS), 200000001,
          'B5. a create not yet written is added to the store\'s count');
  t.equal(JSON.stringify(o.w.countHolding('default', USERS, 'userpassword')),
          JSON.stringify({ n: 200000001, holding: 150000001 }),
          'B6. and to the holders, by what the entry holds');
  t.equal(o.w.recentCountUnder('default', USERS), 200000001,
          'B7. recentCountUnder() reads the same');
  t.equal(o.w.capCount('default'), 200001001,
          'B8. and capCount() moves with it at once');
  // ANOTHER PROCESS'S CHANGE DROPS THE HELD COUNT (2026-10-14): the store
  // moves (a device removed elsewhere), the held reading stays for ten
  // seconds — unless the applier says a key under the container changed.
  counters.set(DEVICES + '|', 999);
  t.equal(o.w.recentCountUnder('default', DEVICES), 1000,
          'B10. a held count does not see the store move by itself');
  o.w.dropCountsAbove('default', 'cn=elsewhere,ou=groups,dc=example,dc=com');
  o.w.dropCountsAbove('other', 'cn=d1,' + DEVICES);
  t.equal(o.w.recentCountUnder('default', DEVICES), 1000,
          'B11. a change in another container or another realm keeps it');
  o.w.dropCountsAbove('default', 'cn=d1,' + DEVICES);
  t.equal(o.w.recentCountUnder('default', DEVICES), 999,
          'B12. a change under the container drops it, and it is read again');
  t.check(o.asked.every(function (one) {
    return !/count\(/i.test(one.text);
  }), 'B9. NO QUESTION THE WINDOW ASKED WAS A COUNT', String(o.asked.length));
  log.debug("Leaving theWindow().");
}

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

async function theOpen(t) {
  log.debug("Entering theOpen().");
  t.log.info('=== C. open() starts the counters once ===');
  const names = postgres.SCHEMA_ROUTINES.map(function (one) {
    return one.name;
  });
  const runOpen = async function (present) {
    const statements = [];
    const driver = driverWith(statements, function (sql) {
      if (/pg_trigger/.test(sql)) {
        return present ? names.map(function (name) {
          return { name: name };
        }) : [];
      }
      if (/to_regclass/.test(sql)) {
        return [{}];
      }
      return undefined;
    });
    await driver.open();
    return statements.map(function (s) { return s.sql; });
  };
  const fresh = await runOpen(false);
  const at = function (list, re) {
    return list.findIndex(function (sql) { return re.test(sql); });
  };
  const lastFunction = fresh.map(function (sql) {
    return /^CREATE OR REPLACE FUNCTION/.test(sql);
  }).lastIndexOf(true);
  const firstTrigger = at(fresh, /^CREATE (OR REPLACE |CONSTRAINT )*TRIGGER/);
  const lock = at(fresh, /^LOCK TABLE sts_ldap_entries/);
  const backfill = at(fresh, /^INSERT INTO sts_ldap_counts/);
  t.check(lastFunction >= 0 && firstTrigger > lastFunction &&
          lock > firstTrigger && backfill > lock,
          'C1. on a store without them: functions, then triggers, then the ' +
          'lock, then the one count', JSON.stringify({
            lastFunction: lastFunction, firstTrigger: firstTrigger,
            lock: lock, backfill: backfill }));
  t.equal(fresh.filter(function (sql) {
    return /count\(\*\)/.test(sql) && /sts_ldap_entries/.test(sql) &&
      !/^CREATE/.test(sql);
  }).length, 1, 'C2. and the directory is counted exactly once');
  t.equal(fresh.filter(function (sql) {
    return /TRIGGER/.test(sql) && /^CREATE/.test(sql);
  }).length, postgres.SCHEMA_ROUTINES.filter(function (one) {
    return one.kind === 'trigger';
  }).length, 'C3. every trigger is created');
  const again = await runOpen(true);
  t.check(!again.some(function (sql) {
    return /^CREATE OR REPLACE FUNCTION|TRIGGER|^LOCK TABLE|INSERT INTO sts_ldap_counts/
      .test(sql);
  }), 'C4. on a store that has them: nothing created, locked or counted',
          JSON.stringify(again.filter(function (sql) {
            return /TRIGGER|LOCK|sts_ldap_counts/.test(sql);
          })));
  log.debug("Leaving theOpen().");
}

// D. A REAL DATABASE, when one is named.
async function realDatabase(t) {
  log.debug("Entering realDatabase().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== D. skipped: STS_TEST_POSTGRES_URL names no database ' +
               '(the in-process suite has none) ===');
    log.debug("Leaving realDatabase(). Skipped.");
    return;
  }
  t.log.info('=== D. against ' + url.replace(/:[^:@/]*@/, ':***@') + ' ===');
  const pg = require('pg');
  const schema = 'counts_' + process.pid;
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  const clients = [];
  try {
    await admin.query('CREATE SCHEMA ' + schema);
    await admin.query('SET search_path TO ' + schema);
    const entries = postgres.SCHEMA_OBJECTS.filter(function (o) {
      return o.name === 'sts_ldap_entries';
    })[0];
    await admin.query(entries.statement);
    // Rows that exist BEFORE the counters do.
    await admin.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs, attr_names) ' +
      'SELECT \'default\', \'uid=p\' || i || \',' + USERS + '\', \'x\', ' +
      '\'{}\'::jsonb, CASE WHEN i % 3 = 0 THEN \'["userpassword"]\'::jsonb ' +
      'ELSE \'[]\'::jsonb END FROM generate_series(1, 3000) AS i');
    await admin.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
                      'attrs) VALUES (\'default\', $1, \'x\', \'{}\'), ' +
                      '(\'default\', $2, \'x\', \'{}\')', [BASE, USERS]);
    for (const object of postgres.SCHEMA_OBJECTS) {
      // #618's tables, and #623's per-data-key ones its triggers write.
      if (/^sts_ldap_(count|dek)/.test(object.name)) {
        await admin.query(object.statement);
      }
    }
    await admin.query('BEGIN');
    for (const one of postgres.SCHEMA_ROUTINES) {
      await admin.query(one.statement);
    }
    await admin.query(postgres.LOCK_FOR_BACKFILL);
    await admin.query(postgres.COUNTS_BACKFILL);
    await admin.query('COMMIT');
    const verify = async function (what) {
      const wrong = await admin.query(
        'SELECT coalesce(c.base_key, x.base_key) AS base, ' +
        'coalesce(c.attribute, x.attribute) AS attr, c.n AS kept, ' +
        'x.n AS counted FROM (SELECT realm, base_key, attribute, n FROM ' +
        'sts_ldap_counts WHERE n <> 0) AS c FULL JOIN (SELECT e.realm, ' +
        'b.base_key, a.attribute, count(*) AS n FROM sts_ldap_entries AS e ' +
        'CROSS JOIN LATERAL sts_ldap_count_bases(e.parent_key) AS ' +
        'b(base_key) CROSS JOIN LATERAL (SELECT \'\' AS attribute UNION ALL ' +
        'SELECT \'userpassword\' WHERE e.attr_names ? \'userpassword\') AS a ' +
        'GROUP BY 1, 2, 3) AS x USING (realm, base_key, attribute) WHERE ' +
        'c.n IS DISTINCT FROM x.n');
      const left = await admin.query(
        'SELECT count(*)::int AS n FROM sts_ldap_count_deltas');
      t.check(wrong.rows.length === 0 && left.rows[0].n === 0,
              what + ': every counter equals a fresh count, no delta left',
              JSON.stringify({ wrong: wrong.rows.slice(0, 5),
                               deltas: left.rows[0].n }));
    };
    await verify('D1. the counters started from rows already there');
    const n = await admin.query(queries.count('default', USERS).text,
                                queries.count('default', USERS).values);
    t.equal(Number(n.rows[0].n), 3000, 'D2. count() reads 3,000 people');
    // EIGHT CONNECTIONS AT ONCE.
    for (let i = 0; i < 8; i++) {
      const c = new pg.Client({ connectionString: url });
      await c.connect();
      await c.query('SET search_path TO ' + schema);
      clients.push(c);
    }
    const work = async function (c, id) {
      for (let k = 0; k < 40; k++) {
        const kind = (id + k) % 6;
        const dn = 'uid=w' + id + 'k' + k + ',' + USERS;
        try {
          await c.query('BEGIN');
          if (kind === 0) {
            await c.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
              'attrs, attr_names) SELECT \'default\', \'uid=w' + id + 'k' +
              k + 'n\' || i || \',' + USERS + '\', \'x\', \'{}\', CASE WHEN ' +
              'i % 2 = 0 THEN \'["userpassword"]\'::jsonb ELSE \'[]\'::jsonb ' +
              'END FROM generate_series(1, 10) AS i');
            await c.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
              'attrs) VALUES (\'acme\', $1, \'x\', \'{}\')',
              ['uid=w' + id + 'k' + k + ',ou=devices,dc=acme,dc=com']);
          } else if (kind === 1) {
            await c.query('DELETE FROM sts_ldap_entries WHERE realm = ' +
              '\'default\' AND dn_key IN (SELECT dn_key FROM ' +
              'sts_ldap_entries WHERE parent_key = $1 ORDER BY random() ' +
              'LIMIT 4)', [USERS]);
          } else if (kind === 2) {
            await c.query('UPDATE sts_ldap_entries SET attr_names = CASE ' +
              'WHEN attr_names ? \'userpassword\' THEN \'[]\'::jsonb ELSE ' +
              '\'["userpassword"]\'::jsonb END WHERE realm = \'default\' AND ' +
              'dn_key IN (SELECT dn_key FROM sts_ldap_entries WHERE ' +
              'parent_key = $1 ORDER BY random() LIMIT 5)', [USERS]);
          } else if (kind === 3) {
            await c.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
              'attrs, attr_names) VALUES (\'default\', $1, \'y\', \'{}\', ' +
              '\'["userpassword"]\') ON CONFLICT (realm, dn_key) DO UPDATE ' +
              'SET dn = EXCLUDED.dn, attr_names = EXCLUDED.attr_names',
              ['uid=p' + (1 + ((id * 41 + k * 7) % 3000)) + ',' + USERS]);
          } else if (kind === 4) {
            await c.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
              'attrs) VALUES (\'default\', $1, \'x\', \'{}\')', [dn]);
            await c.query('ROLLBACK');
            continue;
          } else {
            await c.query('SAVEPOINT a');
            await c.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
              'attrs) VALUES (\'default\', $1, \'x\', \'{}\')', [dn + 's']);
            await c.query('ROLLBACK TO SAVEPOINT a');
            await c.query('INSERT INTO sts_ldap_entries (realm, dn_key, dn, ' +
              'attrs, attr_names) VALUES (\'default\', $1, \'x\', \'{}\', ' +
              '\'["userpassword"]\')', [dn + 't']);
          }
          await c.query('COMMIT');
        } catch (e) {
          log.debug("Caught in work(): " + ((e && e.message) || e));
          // A deadlock or a lost race between two random picks: rolled back
          // whole, which is a case the counters must survive too.
          await c.query('ROLLBACK').catch(function (e2) {
            log.debug("Caught in work(): " + ((e2 && e2.message) || e2));
          });
        }
      }
    };
    await Promise.all(clients.map(function (c, i) {
      return work(c, i);
    }));
    await verify('D3. after eight concurrent connections wrote, deleted, ' +
                 'upserted, rolled back');
    await admin.query('DELETE FROM sts_ldap_entries WHERE realm = \'acme\'');
    await verify('D4. after a realm\'s rows were deleted');
  } finally {
    for (const c of clients) {
      await c.end().catch(function (e) {
        log.debug("Caught in realDatabase(): " + ((e && e.message) || e));
      });
    }
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
  statementsShape(t);
  theWindow(t);
  await theOpen(t);
  await realDatabase(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_counts',
  describe: 'the directory\'s counts are counter rows the database keeps ' +
            '(#618): no count( on a runtime path, the window\'s net kept, ' +
            'the counters started once under a lock, and (with a database) ' +
            'exact under concurrent writers',
  run: run
};
