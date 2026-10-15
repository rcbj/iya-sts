// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_resident_walk.js
//
// ===========================================================================
// A WINDOWED WORKER'S START, AND A SUBTREE PAGE, READ THROUGH THE PARENT
// INDEX (#638, 2026-10-14).
//
// `residentOnly()` — every entry except those strictly under the windowed
// containers — was one statement testing `right(dn_key, …)` of every row,
// which no index narrows: minutes at 50M entries with nothing listening.
// `page()`, `keysUnder()` and `namesUnder()` under a base tested the same
// suffix, so a page under a sparse container read the realm. Each now reads
// the table's DISTINCT parents with a loose index scan of `(realm,
// parent_key, …)`, keeps those at or under nothing windowed (or at or under
// the base), and reads each kept parent's rows as one range of the index
// (`persistence/directory_queries.js`, *A subtree is read through its
// parents*).
//
//   A. THE STATEMENTS: a recursive CTE whose step is one `(realm,
//      parent_key) >` descent; the rows read by `parent_key =` a kept
//      parent, in a LATERAL the planner cannot turn into a scan; no
//      `right(` of a row's `dn_key` anywhere; the restore's values and
//      order unchanged. The pages: the same, the base itself added when
//      asked, the limit inside and out, and the empty base — where the
//      identity below does not hold — still the old suffix.
//   B. THE IDENTITY, on a fixture with orphans, several roots, a realm
//      nobody listed, nested containers, a child of a person, a look-alike
//      suffix and a `%` in a DN: a key is strictly under C exactly when its
//      `parent_key` (computed as the column computes it) is C or under C —
//      so the parents scan, modelled, keeps exactly the old statement's
//      rows; and for '' it does NOT, which is why '' keeps the suffix.
//   C. THE DRIVER'S DOOR: `directoryQuery('residentOnly')` runs exactly the
//      builder's statement and answers rows in the directory's shape, which
//      `persistence.js`' `loadDirectoryRows()` groups by realm.
//   D. AGAINST A REAL POSTGRES, only when STS_TEST_POSTGRES_URL names one the
//      test may build a schema in: the fixture plus PEOPLE people, the old
//      statements and the new run side by side — the same rows in the same
//      order, for the restore and for every page — and the new restore's
//      plan reads no row of the table by a sequential scan and touches
//      buffers in proportion to the resident set, not the table. Skipped
//      (and said) otherwise; the in-process suite has no database.
// ===========================================================================

const postgres = require('../persistence/persistence_postgres');
const queries = require('../persistence/directory_queries');

const log = require('bunyan').createLogger({ name: 'directory_resident_walk',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;
const DEVICES = 'ou=devices,' + BASE;
const ACME = 'dc=acme,dc=test';

// How many people D writes under each windowed `ou=users`: enough that a
// scan of them is visible in the buffers, few enough for a test.
const PEOPLE = Number(process.env.STS_TEST_RESIDENT_PEOPLE || 30000);

// THE OLD STATEMENTS, as they were on develop before #638, to run beside the
// new ones in D. Kept here as text: they are the specification of the
// answer, and they are what the new statements must agree with.
const OLD_RESIDENT = 'SELECT ' + queries.COLUMNS + ' FROM sts_ldap_entries ' +
  'e WHERE NOT EXISTS (SELECT 1 FROM unnest($1::text[], $2::text[]) AS ' +
  'w(r, c) WHERE w.r = e.realm AND right(e.dn_key, length(w.c) + 1) = ' +
  '\',\' || w.c) ORDER BY realm, dn_key';

function oldPage(columns, self) {
  log.debug("Entering oldPage().");
  const strict = 'right(dn_key, $5) = \',\' || $2';
  log.debug("Leaving oldPage().");
  return 'SELECT ' + columns + ' FROM sts_ldap_entries WHERE realm = $1 ' +
         'AND ' + (self ? '(dn_key = $2 OR ' + strict + ')' : strict) +
         ' AND dn_key > $3 ORDER BY dn_key LIMIT $4';
}

// `parent_key` as the generated column computes it: everything after the
// first comma, '' when there is none.
function parentOf(key) {
  log.debug("Entering parentOf().");
  const at = key.indexOf(',');
  log.debug("Leaving parentOf().");
  return at < 0 ? '' : key.slice(at + 1);
}

// The fixture's keys, by realm: resident structure, the edge cases, and a
// few windowed people and devices. D adds PEOPLE more.
function fixture() {
  log.debug("Entering fixture().");
  const rows = [];
  const add = function (realm, key) {
    rows.push({ realm: realm, key: key });
  };
  [['default', BASE], ['acme', ACME]].forEach(function (pair) {
    const realm = pair[0];
    const base = pair[1];
    add(realm, base);
    ['users', 'devices', 'groups', 'applications', 'policies',
     '100%_off'].forEach(function (c) {
      add(realm, 'ou=' + c + ',' + base);
      if (c !== 'users' && c !== 'devices') {
        for (let i = 1; i <= 5; i++) {
          add(realm, 'cn=item' + i + ',ou=' + c + ',' + base);
        }
      }
    });
    for (let i = 1; i <= 7; i++) {
      add(realm, 'uid=p' + i + ',ou=users,' + base);
      add(realm, 'cn=d' + i + ',ou=devices,' + base);
    }
    // A group directly under ou=users: windowed like a person.
    add(realm, 'cn=team,ou=users,' + base);
  });
  // Nested resident containers.
  for (let i = 1; i <= 3; i++) {
    add('default', 'cn=sub' + i + ',cn=item1,ou=groups,' + BASE);
    add('default', 'cn=leaf,cn=sub' + i + ',cn=item1,ou=groups,' + BASE);
  }
  // THE EDGE CASES. Each is a row the old statement answered (or left out)
  // by its key alone, whatever exists above it.
  add('default', 'cn=schema');                              // no comma
  add('default', 'cn=orphan,ou=gone,' + BASE);              // parent missing
  add('default', 'cn=deep,cn=orphan2,ou=gone2,' + BASE);    // two missing
  add('default', 'uid=lost,ou=missing,' + USERS);           // orphan, windowed
  add('default', 'cn=child,uid=p5,' + USERS);               // a person's child
  add('default', 'uid=a,xou=users,' + BASE);                // look-alike
  add('default', 'ou=users,' + BASE + 'x');                 // not the container
  add('default', 'uid=z,ou=users,' + BASE + 'x');           // under it
  add('default', 'o=other,c=us');                           // a second root
  add('default', 'a,');                                     // a trailing comma
  add('ghost', 'cn=a,dc=ghost');                            // nobody lists it
  add('ghost', 'uid=b,ou=users,dc=ghost');                  // not windowed
  log.debug("Leaving fixture().");
  return rows;
}

// The windowed containers the fixture's workers would name.
function windowedList() {
  log.debug("Entering windowedList().");
  log.debug("Leaving windowedList().");
  return [{ realm: 'default', baseKey: USERS },
          { realm: 'default', baseKey: DEVICES },
          { realm: 'acme', baseKey: 'ou=users,' + ACME },
          { realm: 'acme', baseKey: 'ou=devices,' + ACME }];
}

// A. THE STATEMENTS.
function statements(t) {
  log.debug("Entering statements().");
  t.log.info('=== A. the statements ===');
  const list = windowedList();
  const r = queries.residentOnly(list);
  t.check(/^WITH RECURSIVE parents\(realm, parent_key\) AS/.test(r.text),
          'A1. the restore starts from the table\'s distinct parents, a ' +
          'recursive CTE', r.text);
  t.check(/\(e\.realm, e\.parent_key\) > \(p\.realm, p\.parent_key\) ORDER BY e\.realm, e\.parent_key LIMIT 1/
    .test(r.text),
          'A2. each step of it is ONE descent of the parent index: the next ' +
          '(realm, parent_key) after the last, LIMIT 1', r.text);
  t.check(!/right\(e\.dn_key/.test(r.text) && !/right\(dn_key/.test(r.text),
          'A3. no row\'s dn_key is tested by suffix: only the distinct ' +
          'parents are', r.text);
  t.check(/p\.parent_key = w\.c OR right\(p\.parent_key, length\(w\.c\) \+ 1\) = ',' \|\| w\.c/
    .test(r.text),
          'A4. a parent is dropped when it IS a windowed container or is ' +
          'under one, per realm', r.text);
  t.check(/CROSS JOIN LATERAL \(SELECT realm, dn_key, dn, attrs, origin, created_at, modified_at FROM sts_ldap_entries e WHERE e\.realm = k\.realm AND e\.parent_key = k\.parent_key ORDER BY e\.dn_key\) AS x ORDER BY x\.realm, x\.dn_key$/
    .test(r.text),
          'A5. each kept parent\'s rows are read by parent_key in a LATERAL ' +
          'with its own ORDER BY (which the planner cannot pull up into a ' +
          'hash join over the table), and the answer is in (realm, dn_key) ' +
          'order as before', r.text);
  t.equal(JSON.stringify(r.values),
          JSON.stringify([['default', 'default', 'acme', 'acme'],
                          [USERS, DEVICES, 'ou=users,' + ACME,
                           'ou=devices,' + ACME]]),
          'A6. the values are the realms and containers, as before');
  const pages = [
    ['page', queries.page('default', DEVICES, 'cn=d1,' + DEVICES, 50)],
    ['keysUnder', queries.keysUnder('default', USERS, '', 10)],
    ['namesUnder', queries.namesUnder('default', USERS, 'uid=a', 10)]
  ];
  pages.forEach(function (pair, i) {
    const text = pair[1].text;
    t.check(/^WITH RECURSIVE parents\(parent_key\) AS/.test(text) &&
            /e\.realm = \$1 AND e\.parent_key > p\.parent_key ORDER BY e\.parent_key LIMIT 1/
              .test(text) &&
            /parent_key = \$2 OR right\(parent_key, \$5\) = ',' \|\| \$2/
              .test(text) &&
            /e\.parent_key = u\.parent_key AND e\.dn_key > \$3 ORDER BY e\.dn_key LIMIT \$4\) AS x/
              .test(text) &&
            / ORDER BY dn_key LIMIT \$4$/.test(text) &&
            !/right\(dn_key/.test(text) && !/LIKE/i.test(text),
            'A7.' + (i + 1) + '. ' + pair[0] + ' reads the realm\'s ' +
            'parents, keeps the base and those under it, and reads at most ' +
            'a page of each in key order', text);
  });
  const self = queries.page('default', 'uid=p5,' + USERS, '', 10,
                            { self: true });
  t.check(/UNION ALL SELECT .* FROM sts_ldap_entries WHERE realm = \$1 AND dn_key = \$2 AND dn_key > \$3\) AS s/
    .test(self.text),
          'A8. a page that includes its base reads the base by key', self.text);
  t.equal(JSON.stringify(queries.page('default', USERS, 'x', 20000).values),
          JSON.stringify(['default', USERS, 'x', queries.MAX_PAGE,
                          USERS.length + 1]),
          'A9. a page\'s values are as before, bounded at MAX_PAGE');
  const empty = queries.page('default', '', '', 10);
  t.check(/right\(dn_key, \$5\) = ',' \|\| \$2/.test(empty.text) &&
          !/WITH RECURSIVE/.test(empty.text),
          'A10. the empty base keeps the old suffix (see B5)', empty.text);
  const one = queries.page('default', USERS, '', 10, { oneLevel: true });
  t.check(/^SELECT .* WHERE realm = \$1 AND parent_key = \$2 AND dn_key > \$3 ORDER BY dn_key LIMIT \$4$/
    .test(one.text) && one.values.length === 4,
          'A11. a one-level page is still parent_key, unchanged', one.text);
  log.debug("Leaving statements().");
}

// B. THE IDENTITY, modelled in JavaScript over the fixture.
function identity(t) {
  log.debug("Entering identity().");
  t.log.info('=== B. the identity ===');
  const rows = fixture();
  const list = windowedList();
  // The OLD statement's answer: a row's key alone, tested by suffix.
  const strictlyUnder = function (key, c) {
    return key.length > c.length && key.endsWith(',' + c);
  };
  const oldKept = rows.filter(function (row) {
    return !list.some(function (w) {
      return w.realm === row.realm && strictlyUnder(row.key, w.baseKey);
    });
  });
  // The NEW statement's answer, as it is computed: the distinct parents in
  // order, the windowed ones dropped, each kept parent's rows.
  const parents = Array.from(new Set(rows.map(function (row) {
    return row.realm + '\n' + parentOf(row.key);
  }))).sort();
  const kept = new Set(parents.filter(function (one) {
    const realm = one.split('\n')[0];
    const p = one.split('\n')[1];
    return !list.some(function (w) {
      return w.realm === realm &&
        (p === w.baseKey || p.endsWith(',' + w.baseKey));
    });
  }));
  const newKept = rows.filter(function (row) {
    return kept.has(row.realm + '\n' + parentOf(row.key));
  });
  const keyOf = function (row) {
    return row.realm + '|' + row.key;
  };
  const sorted = function (some) {
    return some.map(keyOf).sort();
  };
  t.equal(JSON.stringify(sorted(newKept)), JSON.stringify(sorted(oldKept)),
          'B1. the parents scan keeps exactly the old statement\'s rows (' +
          oldKept.length + ' of ' + rows.length + ')');
  const has = function (some, realm, key) {
    return some.some(function (row) {
      return row.realm === realm && row.key === key;
    });
  };
  t.check(has(newKept, 'default', 'cn=orphan,ou=gone,' + BASE) &&
          has(newKept, 'default', 'cn=deep,cn=orphan2,ou=gone2,' + BASE) &&
          has(newKept, 'default', 'cn=schema') &&
          has(newKept, 'default', 'o=other,c=us') &&
          has(newKept, 'ghost', 'uid=b,ou=users,dc=ghost') &&
          has(newKept, 'default', USERS) && has(newKept, 'default', BASE),
          'B2. orphans, a key with no comma, a second root, a realm nobody ' +
          'listed, the windowed container itself and the realm\'s base are ' +
          'restored — a walk down from the base would have missed the first ' +
          'four');
  t.check(!has(newKept, 'default', 'uid=lost,ou=missing,' + USERS) &&
          !has(newKept, 'default', 'cn=child,uid=p5,' + USERS) &&
          !has(newKept, 'default', 'cn=team,' + USERS),
          'B3. an orphan under a windowed container, a person\'s child and a ' +
          'group under ou=users are left out, as the suffix left them out');
  t.check(has(newKept, 'default', 'uid=a,xou=users,' + BASE) &&
          has(newKept, 'default', 'uid=z,ou=users,' + BASE + 'x'),
          'B4. a look-alike of a container\'s name is not the container');
  // THE IDENTITY ITSELF, for every key and every non-empty base the fixture
  // holds; and its one exception.
  const bases = Array.from(new Set(rows.map(function (row) {
    return row.key;
  }))).concat(['ou=gone,' + BASE, 'ou=missing,' + USERS]);
  let wrong = [];
  bases.forEach(function (b) {
    rows.forEach(function (row) {
      const p = parentOf(row.key);
      if (strictlyUnder(row.key, b) !== (p === b || p.endsWith(',' + b))) {
        wrong.push(row.key + ' / ' + b);
      }
    });
  });
  t.equal(wrong.join('; '), '',
          'B5. for every non-empty base B, a key is strictly under B ' +
          'exactly when its parent_key is B or under B (' + bases.length +
          ' bases x ' + rows.length + ' keys)');
  wrong = rows.filter(function (row) {
    const p = parentOf(row.key);
    return strictlyUnder(row.key, '') !== (p === '' || p.endsWith(','));
  }).map(function (row) { return row.key; });
  t.check(wrong.length > 0,
          'B6. for the base \'\' the identity FAILS (a key with no comma has ' +
          'parent_key \'\'), which is why A10 keeps the suffix there',
          wrong.join(', '));
  log.debug("Leaving identity().");
}

// A `pg` that remembers every statement and answers through `answer`.
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
  FakeClient.prototype.connect = function () {
    return Promise.resolve();
  };
  FakeClient.prototype.end = function () {
    return Promise.resolve();
  };
  function FakePool() {}
  FakePool.prototype.query = reply;
  FakePool.prototype.connect = function () {
    return Promise.resolve(new FakeClient());
  };
  FakePool.prototype.on = function () {};
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  log.debug("Leaving fakePg().");
  return { Pool: FakePool, Client: FakeClient };
}

// C. THE DRIVER'S DOOR.
async function driverDoor(t) {
  log.debug("Entering driverDoor().");
  t.log.info('=== C. the driver\'s door ===');
  const statements = [];
  const row = { realm: 'default', dn_key: BASE, dn: 'dc=Example,dc=com',
                attrs: { dc: ['example'] }, origin: 'seed',
                created_at: '20261014000000Z', modified_at: null };
  // The driver requires `pg` when it is made: the recording one is put in
  // the cache for that, and the real one put back.
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
    exports: fakePg(statements, function (sql) {
      return /WITH RECURSIVE parents\(realm, parent_key\)/.test(sql)
        ? [row] : [];
    }) };
  let driver = null;
  try {
    driver = postgres.create({ url: 'postgres://sts_app@localhost:5432/sts',
                               log: QUIET });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
  const list = windowedList();
  const answer = await driver.directoryQuery('residentOnly', [list]);
  const sent = statements.filter(function (s) {
    return /WITH RECURSIVE parents\(realm, parent_key\)/.test(s.sql);
  });
  t.check(sent.length === 1 &&
          sent[0].sql === queries.residentOnly(list).text &&
          JSON.stringify(sent[0].params) ===
            JSON.stringify(queries.residentOnly(list).values),
          'C1. directoryQuery(\'residentOnly\') sends exactly the builder\'s ' +
          'statement, once', JSON.stringify(statements.map(function (s) {
            return s.sql.slice(0, 60);
          })));
  t.check(Array.isArray(answer) && answer.length === 1 &&
          answer[0].realm === 'default' && answer[0].key === BASE &&
          answer[0].entry.dn === 'dc=Example,dc=com' &&
          answer[0].entry.origin === 'seed',
          'C2. the rows come back { realm, key, entry }, which ' +
          'loadDirectoryRows() groups by realm', JSON.stringify(answer));
  log.debug("Leaving driverDoor().");
}

// The buffers a plan touched, summed over its top node (shared hit + read).
function buffersOf(plan) {
  log.debug("Entering buffersOf().");
  log.debug("Leaving buffersOf().");
  return Number(plan['Shared Hit Blocks'] || 0) +
         Number(plan['Shared Read Blocks'] || 0);
}

// Every node of a plan, flattened.
function nodesOf(plan, out) {
  log.debug("Entering nodesOf().");
  const list = out || [];
  list.push(plan);
  (plan.Plans || []).forEach(function (child) {
    nodesOf(child, list);
  });
  log.debug("Leaving nodesOf().");
  return list;
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
  const schema = 'resident_' + process.pid;
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  try {
    await admin.query('CREATE SCHEMA ' + schema);
    await admin.query('SET search_path TO ' + schema);
    for (const object of postgres.SCHEMA_OBJECTS) {
      if (object.name === 'sts_ldap_entries' ||
          object.name === 'sts_ldap_entries_parent' ||
          object.name === 'sts_ldap_entries_rdn') {
        await admin.query(object.statement);
      }
    }
    const rows = fixture();
    await admin.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs) SELECT r, ' +
      'k, k, jsonb_build_object(\'k\', k) FROM unnest($1::text[], ' +
      '$2::text[]) AS f(r, k)',
      [rows.map(function (row) { return row.realm; }),
       rows.map(function (row) { return row.key; })]);
    // The windowed bulk: people and devices, each with a sealed-sized blob.
    await admin.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs) SELECT ' +
      'r, \'uid=bulk\' || i || \',ou=users,\' || b, \'x\', ' +
      'jsonb_build_object(\'blob\', repeat(\'b\', 600)) FROM (VALUES ' +
      '(\'default\', $1), (\'acme\', $2)) AS v(r, b), generate_series(1, ' +
      '$3::int) AS i', [BASE, ACME, PEOPLE]);
    await admin.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs) SELECT ' +
      '\'default\', \'cn=bulk\' || i || \',\' || $1, \'x\', \'{}\'::jsonb ' +
      'FROM generate_series(1, $2::int) AS i', [DEVICES, PEOPLE / 10]);
    await admin.query('ANALYZE sts_ldap_entries');
    const total = Number((await admin.query(
      'SELECT count(*) AS n FROM sts_ldap_entries')).rows[0].n);
    // THE RESTORE: old and new, row for row.
    const r = queries.residentOnly(windowedList());
    const before = await admin.query(OLD_RESIDENT, r.values);
    const after = await admin.query(r.text, r.values);
    const keysOf = function (result) {
      return result.rows.map(function (row) {
        return row.realm + '|' + row.dn_key + '|' + row.dn + '|' +
          JSON.stringify(row.attrs);
      });
    };
    t.check(after.rows.length > 0 &&
            JSON.stringify(keysOf(after)) === JSON.stringify(keysOf(before)),
            'D1. the new restore answers the old statement\'s rows, in its ' +
            'order (' + after.rows.length + ' of ' + total + ')',
            before.rows.length + ' / ' + after.rows.length);
    t.check(JSON.stringify(Object.keys(after.rows[0] || {})) ===
            JSON.stringify(Object.keys(before.rows[0] || {})),
            'D2. with the same columns, in the same order');
    // THE PLAN: no sequential scan of the table, and buffers that follow
    // the resident set rather than the table.
    await admin.query('SET jit = off');
    const explain = async function (text, values) {
      const e = await admin.query('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' +
                                  text, values);
      return e.rows[0]['QUERY PLAN'][0].Plan;
    };
    const planNew = await explain(r.text, r.values);
    const planOld = await explain(OLD_RESIDENT, r.values);
    const scans = nodesOf(planNew).filter(function (node) {
      return node['Relation Name'] === 'sts_ldap_entries' &&
        node['Node Type'] === 'Seq Scan';
    });
    t.check(scans.length === 0,
            'D3. the restore reads sts_ldap_entries by no sequential scan',
            JSON.stringify(nodesOf(planNew).map(function (node) {
              return node['Node Type'] + ':' + (node['Index Name'] || '');
            })));
    const usedIndexes = nodesOf(planNew).map(function (node) {
      return node['Index Name'] || '';
    }).filter(Boolean);
    t.check(usedIndexes.length > 0 && usedIndexes.every(function (name) {
      return name === 'sts_ldap_entries_parent' ||
        name === 'sts_ldap_entries_rdn';
    }), 'D4. every index it reads leads with (realm, parent_key)',
            usedIndexes.join(', '));
    const bNew = buffersOf(planNew);
    const bOld = buffersOf(planOld);
    t.check(bNew < 20 * after.rows.length + 500 && bNew * 5 < bOld,
            'D5. the restore touched ' + bNew + ' buffers for ' +
            after.rows.length + ' resident rows (the old: ' + bOld + ' for ' +
            total + ' rows in the table)');
    t.log.info('D. restore: old ' + planOld['Actual Total Time'] + ' ms, ' +
               bOld + ' buffers; new ' + planNew['Actual Total Time'] +
               ' ms, ' + bNew + ' buffers');
    // THE PAGES: old and new, row for row, over every base that matters.
    const cases = [
      [USERS, '', 500, null], [USERS, 'uid=bulk2000,' + USERS, 500, null],
      [DEVICES, '', 1000, null], [DEVICES, 'cn=d7,' + DEVICES, 1000, null],
      [BASE, '', 1000, null], ['ou=groups,' + BASE, '', 1000, null],
      ['cn=item1,ou=groups,' + BASE, '', 10, { self: true }],
      ['uid=p5,' + USERS, '', 10, { self: true }],
      ['ou=gone2,' + BASE, '', 10, null], ['ou=nobody,' + BASE, '', 10, null],
      ['ou=100%_off,' + BASE, '', 10, null], ['dc=ghost', '', 10, null],
      ['', '', 10, null]
    ];
    for (const one of cases) {
      const realm = one[0] === 'dc=ghost' ? 'ghost' : 'default';
      const built = [
        ['page', queries.page(realm, one[0], one[1], one[2], one[3]),
         oldPage(queries.COLUMNS, !!(one[3] && one[3].self))],
        ['keysUnder', queries.keysUnder(realm, one[0], one[1], one[2]),
         oldPage('dn_key, dn', false)],
        ['namesUnder', queries.namesUnder(realm, one[0], one[1], one[2]),
         oldPage('dn_key, dn, origin, attrs', false)]
      ];
      for (const b of built) {
        const o = await admin.query(b[2], b[1].values);
        const n = await admin.query(b[1].text, b[1].values);
        t.check(JSON.stringify(n.rows) === JSON.stringify(o.rows),
                'D6. ' + b[0] + ' under "' + one[0] + '" after "' + one[1] +
                '" answers the old statement\'s ' + o.rows.length +
                ' row(s), in order', n.rows.length + ' vs ' + o.rows.length);
      }
    }
    // A SPARSE PAGE: past the last device, so the answer is empty. The old
    // statement read the realm's keys after the cursor to find that out —
    // every person among them; the new one reads the parents and one empty
    // range.
    const sparse = queries.page('default', DEVICES, 'cn=d7,' + DEVICES, 500);
    const planSparse = await explain(sparse.text, sparse.values);
    const planSparseOld = await explain(oldPage(queries.COLUMNS, false),
                                        sparse.values);
    const bSparse = buffersOf(planSparse);
    const bSparseOld = buffersOf(planSparseOld);
    t.check(planSparse['Actual Rows'] === 0 && bSparse < 200 &&
            bSparse * 10 < bSparseOld,
            'D7. an empty page under ou=devices touched ' + bSparse +
            ' buffers (the old: ' + bSparseOld + ') beside ' + total +
            ' rows in the table');
    const full = queries.page('default', DEVICES, '', 1000);
    const planFull = await explain(full.text, full.values);
    const bFull = buffersOf(planFull);
    t.check(planFull['Actual Rows'] === 1000 && bFull < 1000 + 400,
            'D8. a full page of 1,000 under ou=devices touched ' + bFull +
            ' buffers: the parents and the rows answered');
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
  statements(t);
  identity(t);
  await driverDoor(t);
  await realDatabase(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_resident_walk',
  describe: 'a windowed worker\'s start and a subtree page read through the ' +
            'parent index\'s distinct parents (#638): no suffix test of ' +
            'every row, the old answers row for row (with a database)',
  run: run
};
