// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_parent_statistics.js
//
// ===========================================================================
// THE DIRECTORY'S STATEMENTS PLANNED WHEN ANALYZE SAW ONE PARENT (#639,
// 2026-10-15).
//
// At 50.2M entries ANALYZE's sample of `sts_ldap_entries` held one
// `parent_key` — 50M of the rows are under one `ou=users` — so `pg_stats`
// said `n_distinct = 1`, and a parent the planner could not see (a
// LATERAL's) was estimated as the whole realm. #638's resident restore was
// then planned on the primary key `(realm, dn_key)` with `parent_key` as a
// filter: the realm, once per kept parent, at every start. Two fixes, and
// this test holds both on a REAL postgres:
//
//   * the statements read a parent's rows as a walk of the parent index,
//     one descent a row (`directory_queries.childrenRange()`), which no
//     other path serves without sorting what follows, whatever the
//     statistics say;
//   * schema version 20 sets `parent_key`'s `n_distinct` by hand
//     (SCHEMA_UPGRADES' `sts_ldap_entries_parent_ndistinct`).
//
//   A. THE STEP, in process: advisory, owed while the column's attoptions
//      lack the value, ALTER then ANALYZE of the one column.
//   B. THE TRAP, reproduced, only when STS_TEST_POSTGRES_URL names a
//      database the test may build a schema in: PEOPLE people under one
//      container and about forty rows anywhere else, the two columns'
//      statistics target at 1 (a sample of 300 rows — what 30,000 is beside
//      50M), ANALYZE until `n_distinct` is 1. #638's statements, kept here as
//      text, ARE planned on the primary key: the fixture shows the bug.
//   C. EVERY STATEMENT THAT READS BY `parent_key`, planned under that trap:
//      the restore, a one-level page (under a sparse container and under the
//      big one, after a cursor), a subtree page, `keysUnder`, `namesUnder`,
//      `hasChild` of a group and of a person, `byName`, `withNames` and
//      `byAttribute` under a parent, an `rdnPage` (plain, after a cursor,
//      and with a needle) and a `containerPage` (the first page and an
//      offset) —
//      no sequential scan, no primary key or realm index on the table; the
//      restore's and the pages' rows through the parent index, and an
//      `rdnPage` through `sts_ldap_entries_rdn`.
//   D. THE UPGRADE: the driver's step run as written; `n_distinct` is
//      100,000, the probe no longer owes it, and every statement of C — and
//      #638's old restore, which the override alone puts right — reads the
//      index that statement names (the parent index, or the rdn index).
//   E. A RESIDENT CONTAINER LARGER THAN A PAGE, written after the ANALYZE
//      (as an import leaves it): the restore answers #638's old statement's
//      rows, in its order, and its buffers follow the rows it answers.
// ===========================================================================

const postgres = require('../persistence/persistence_postgres');
const queries = require('../persistence/directory_queries');

const log = require('bunyan').createLogger({
  name: 'directory_parent_statistics',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;
const DEVICES = 'ou=devices,' + BASE;
const GROUPS = 'ou=groups,' + BASE;
const ACME = 'dc=acme,dc=test';

// The people under the one big container. 300,000 is the figure the issue
// names; enough that a scan of them is a plan the planner prices as the
// table.
const PEOPLE = Number(process.env.STS_TEST_PARENT_PEOPLE || 300000);
// Groups written after the ANALYZE in E: more than a page.
const LATE_GROUPS = 2500;

// #638'S STATEMENTS, as they were on develop before #639: the restore's
// LATERAL by equality, which the trap plans on the primary key.
const OLD_RESIDENT = 'WITH RECURSIVE parents(realm, parent_key) AS ((SELECT ' +
  'realm, parent_key FROM sts_ldap_entries ORDER BY realm, parent_key LIMIT ' +
  '1) UNION ALL SELECT n.realm, n.parent_key FROM parents p CROSS JOIN ' +
  'LATERAL (SELECT e.realm, e.parent_key FROM sts_ldap_entries e WHERE ' +
  '(e.realm, e.parent_key) > (p.realm, p.parent_key) ORDER BY e.realm, ' +
  'e.parent_key LIMIT 1) AS n), kept AS (SELECT p.realm, p.parent_key FROM ' +
  'parents p WHERE NOT EXISTS (SELECT 1 FROM unnest($1::text[], ' +
  '$2::text[]) AS w(r, c) WHERE w.r = p.realm AND (p.parent_key = w.c OR ' +
  'right(p.parent_key, length(w.c) + 1) = \',\' || w.c))) SELECT x.* FROM ' +
  'kept k CROSS JOIN LATERAL (SELECT ' + queries.COLUMNS + ' FROM ' +
  'sts_ldap_entries e WHERE e.realm = k.realm AND e.parent_key = ' +
  'k.parent_key ORDER BY e.dn_key) AS x ORDER BY x.realm, x.dn_key';

// And its subtree page's LATERAL, a page of each parent by equality.
const OLD_SUBTREE = 'WITH RECURSIVE parents(parent_key) AS ((SELECT ' +
  'parent_key FROM sts_ldap_entries WHERE realm = $1 ORDER BY parent_key ' +
  'LIMIT 1) UNION ALL SELECT n.parent_key FROM parents p CROSS JOIN LATERAL ' +
  '(SELECT e.parent_key FROM sts_ldap_entries e WHERE e.realm = $1 AND ' +
  'e.parent_key > p.parent_key ORDER BY e.parent_key LIMIT 1) AS n), under ' +
  'AS (SELECT parent_key FROM parents WHERE parent_key = $2 OR ' +
  'right(parent_key, $5) = \',\' || $2) SELECT ' + queries.COLUMNS +
  ' FROM (SELECT x.* FROM under u CROSS JOIN LATERAL (SELECT ' +
  queries.COLUMNS + ' FROM sts_ldap_entries e WHERE e.realm = $1 AND ' +
  'e.parent_key = u.parent_key AND e.dn_key > $3 ORDER BY e.dn_key LIMIT ' +
  '$4) AS x) AS s ORDER BY dn_key LIMIT $4';

// The windowed containers a worker of the fixture names.
function windowedList() {
  log.debug("Entering windowedList().");
  log.debug("Leaving windowedList().");
  return [{ realm: 'default', baseKey: USERS },
          { realm: 'default', baseKey: DEVICES },
          { realm: 'acme', baseKey: 'ou=users,' + ACME },
          { realm: 'acme', baseKey: 'ou=devices,' + ACME }];
}

// The resident handful: about forty rows outside the big container.
function handful() {
  log.debug("Entering handful().");
  const rows = [];
  [['default', BASE], ['acme', ACME]].forEach(function (pair) {
    const base = pair[1];
    rows.push([pair[0], base]);
    ['users', 'devices', 'groups', 'applications'].forEach(function (c) {
      rows.push([pair[0], 'ou=' + c + ',' + base]);
    });
    for (let i = 1; i <= 3; i++) {
      rows.push([pair[0], 'cn=g' + i + ',ou=groups,' + base]);
      rows.push([pair[0], 'cn=a' + i + ',ou=applications,' + base]);
      rows.push([pair[0], 'cn=d' + i + ',ou=devices,' + base]);
    }
    rows.push([pair[0], 'uid=p1,ou=users,' + base]);
  });
  log.debug("Leaving handful(). " + rows.length + " rows.");
  return rows;
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

// The scans of `sts_ldap_entries` in a plan, `Node Type:Index Name`.
function scansOf(plan) {
  log.debug("Entering scansOf().");
  log.debug("Leaving scansOf().");
  return nodesOf(plan).filter(function (node) {
    return node['Relation Name'] === 'sts_ldap_entries';
  }).map(function (node) {
    return node['Node Type'] + ':' + (node['Index Name'] || '');
  });
}

// A scan that reads the table or a realm whole to answer for one parent.
function wholeRealmScans(scans) {
  log.debug("Entering wholeRealmScans().");
  log.debug("Leaving wholeRealmScans().");
  return scans.filter(function (scan) {
    return /^Seq Scan/.test(scan) ||
      /:sts_ldap_entries_pkey$/.test(scan) ||
      /:sts_ldap_entries_realm$/.test(scan);
  });
}

// A. THE STEP.
function theStep(t) {
  log.debug("Entering theStep().");
  t.log.info('=== A. the step ===');
  const step = (postgres.SCHEMA_UPGRADES || []).filter(function (one) {
    return one.name === 'sts_ldap_entries_parent_ndistinct';
  })[0];
  t.check(!!step, 'A1. the driver owes sts_ldap_entries_parent_ndistinct');
  if (!step) {
    log.debug("Leaving theStep(). No step.");
    return;
  }
  t.check(step.advisory === true && step.table === 'sts_ldap_entries',
          'A2. an advisory step on sts_ldap_entries: a cost, never a wrong ' +
          'answer, since the statements no longer depend on it');
  t.equal(JSON.stringify(step.statements),
          JSON.stringify(['ALTER TABLE sts_ldap_entries ALTER COLUMN ' +
                          'parent_key SET (n_distinct=100000)',
                          'ANALYZE sts_ldap_entries (parent_key)']),
          'A3. it sets the column\'s n_distinct, then analyzes that column');
  t.check(/pg_attribute/.test(step.when) &&
          /a\.attname = 'parent_key'/.test(step.when) &&
          /'n_distinct=100000'/.test(step.when),
          'A4. and is owed while the column\'s attoptions lack the value',
          step.when);
  t.check(postgres.SCHEMA_VERSION >= 20,
          'A5. schema version 20 or later (20 set n_distinct)');
  log.debug("Leaving theStep().");
}

// The plans of every statement C and D check, by name.
function statementsToPlan() {
  log.debug("Entering statementsToPlan().");
  const list = windowedList();
  log.debug("Leaving statementsToPlan().");
  return [
    ['residentOnly', queries.residentOnly(list), true],
    ['page one level, a sparse container',
     queries.page('default', GROUPS, '', 1000, { oneLevel: true }), true],
    ['page one level, the big container after a cursor',
     queries.page('default', USERS, 'uid=u500,' + USERS, 1000,
                  { oneLevel: true }), true],
    ['page under the base', queries.page('default', BASE, '', 1000), true],
    ['page under a sparse container',
     queries.page('default', GROUPS, '', 1000), true],
    ['keysUnder the base', queries.keysUnder('default', BASE, '', 1000),
     true],
    ['namesUnder ou=devices',
     queries.namesUnder('default', DEVICES, '', 1000), true],
    ['hasChild of a group',
     queries.hasChild('default', 'cn=g1,' + GROUPS), false],
    // A LEAF, the question every LDAP delete and rename asks (#636): no row
    // answers it, so a plan that reads candidates reads them all. (Asked of
    // the big container it is answered by the first row of any plan.)
    ['hasChild of a person', queries.hasChild('default', 'uid=u77,' + USERS),
     false],
    ['byName under the big container',
     queries.byName('default', USERS, 'u77'), false],
    ['withNames under the big container',
     queries.withNames('default', USERS, ['u77', 'u78']), false],
    ['byAttribute under ou=devices',
     queries.byAttribute('default', 'stsdeviceid', 'x', 10, DEVICES), false],
    // #359. The rdn index has no dn_key, so these must not be asked to
    // read the parent index. `rdnCount` is a count, not a walk, and is
    // not planned here.
    ['rdnPage of the big container',
     queries.rdnPage('default', USERS, '', 1000), 'rdn'],
    ['rdnPage after a cursor',
     queries.rdnPage('default', USERS, 'u500', 1000), 'rdn'],
    ['rdnPage containing a needle',
     queries.rdnPage('default', USERS, '', 100, { needle: 'u5' }), 'rdn'],
    ['containerPage, the first page',
     queries.containerPage('default', DEVICES, 0, 1000), true],
    ['containerPage, an offset',
     queries.containerPage('default', DEVICES, 50, 100), true]
  ];
}

// C and D: plans every statement, checking that none reads the realm whole
// and that those that read a parent's rows read the parent index.
async function planAll(t, db, label) {
  log.debug("Entering planAll(). " + label);
  for (const one of statementsToPlan()) {
    const e = await db.query('EXPLAIN (FORMAT JSON) ' + one[1].text,
                             one[1].values);
    const scans = scansOf(e.rows[0]['QUERY PLAN'][0].Plan);
    t.check(scans.length > 0 && wholeRealmScans(scans).length === 0,
            label + '. ' + one[0] + ': no sequential scan, no primary key ' +
            'or realm index on the table', scans.join(', '));
    if (one[2] === true) {
      t.check(scans.indexOf('Index Scan:sts_ldap_entries_parent') >= 0,
              label + '. ' + one[0] + ': the rows through the parent index',
              scans.join(', '));
    } else if (one[2] === 'rdn') {
      t.check(scans.indexOf('Index Scan:sts_ldap_entries_rdn') >= 0,
              label + '. ' + one[0] + ': the rows through the rdn index',
              scans.join(', '));
    }
  }
  log.debug("Leaving planAll().");
}

// The scans of one statement's plan.
async function planOf(db, text, values) {
  log.debug("Entering planOf().");
  const e = await db.query('EXPLAIN (FORMAT JSON) ' + text, values);
  log.debug("Leaving planOf().");
  return scansOf(e.rows[0]['QUERY PLAN'][0].Plan);
}

// What pg_stats says of a column.
async function distinctOf(db, schema, column) {
  log.debug("Entering distinctOf(). " + column);
  const r = await db.query('SELECT n_distinct FROM pg_stats WHERE ' +
                           'schemaname = $1 AND tablename = ' +
                           '\'sts_ldap_entries\' AND attname = $2',
                           [schema, column]);
  log.debug("Leaving distinctOf().");
  return r.rows.length ? Number(r.rows[0].n_distinct) : NaN;
}

// B to E, against a real database.
async function realDatabase(t) {
  log.debug("Entering realDatabase().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== B-E. skipped: STS_TEST_POSTGRES_URL names no database ' +
               '(the in-process suite has none) ===');
    log.debug("Leaving realDatabase(). Skipped.");
    return;
  }
  t.log.info('=== B. the trap, against ' +
             url.replace(/:[^:@/]*@/, ':***@') + ' ===');
  // Through the service's one door to PostgreSQL (#326): a connection
  // Knex makes, outside any pool, where a `pg.Client` was.
  const knexStore = require('../persistence/knex_store');
  const schema = 'parents_' + process.pid;
  const db = knexStore.openConnection({ connectionString: url });
  await db.connect();
  try {
    await db.query('CREATE SCHEMA ' + schema);
    await db.query('SET search_path TO ' + schema);
    // The table and EVERY index on it, so each is a plan the planner may
    // choose.
    for (const object of postgres.SCHEMA_OBJECTS) {
      if (object.name === 'sts_ldap_entries' ||
          /ON sts_ldap_entries /.test(object.statement)) {
        await db.query(object.statement);
      }
    }
    const few = handful();
    await db.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs) SELECT r, k, ' +
      'k, \'{}\'::jsonb FROM unnest($1::text[], $2::text[]) AS f(r, k)',
      [few.map(function (row) { return row[0]; }),
       few.map(function (row) { return row[1]; })]);
    await db.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs) SELECT ' +
      '\'default\', \'uid=u\' || i || \',\' || $1, \'x\', ' +
      'jsonb_build_object(\'blob\', repeat(\'b\', 300)) FROM ' +
      'generate_series(2, $2::int) AS i', [USERS, PEOPLE]);
    // A SAMPLE OF 300 ROWS: the sample size is 300 times the largest
    // statistics target of the columns analyzed, so these two at 1 and
    // ANALYZE of them alone. Forty rows beside PEOPLE are what 50M was
    // beside 30,000; the sample can still catch one, so it is taken again
    // until it does not.
    await db.query('ALTER TABLE sts_ldap_entries ALTER COLUMN parent_key ' +
                   'SET STATISTICS 1');
    await db.query('ALTER TABLE sts_ldap_entries ALTER COLUMN realm SET ' +
                   'STATISTICS 1');
    let tries = 0;
    let seen = NaN;
    do {
      await db.query('ANALYZE sts_ldap_entries');
      await db.query('ANALYZE sts_ldap_entries (realm, parent_key)');
      seen = await distinctOf(db, schema, 'parent_key');
      tries += 1;
    } while (seen !== 1 && tries < 10);
    t.equal(seen, 1, 'B1. ANALYZE saw one parent: n_distinct = 1, as at ' +
            '50.2M (' + tries + ' sample(s))');
    const oldScans = await planOf(db, OLD_RESIDENT,
                                  queries.residentOnly(windowedList())
                                    .values.slice(0, 2));
    t.check(oldScans.indexOf('Index Scan:sts_ldap_entries_pkey') >= 0,
            'B2. #638\'s restore IS planned on the primary key here: the ' +
            'fixture shows the bug', oldScans.join(', '));
    const oldPage = await planOf(db, OLD_SUBTREE,
                                 queries.page('default', GROUPS, '', 1000)
                                   .values);
    t.check(wholeRealmScans(oldPage).length > 0,
            'B3. and so is its subtree page', oldPage.join(', '));

    t.log.info('=== C. every statement, under the trap ===');
    await planAll(t, db, 'C');

    t.log.info('=== D. the upgrade ===');
    const step = postgres.SCHEMA_UPGRADES.filter(function (one) {
      return one.name === 'sts_ldap_entries_parent_ndistinct';
    })[0];
    const owedBefore = (await db.query('SELECT (' + step.when + ') AS owed'))
      .rows[0].owed;
    for (const statement of step.statements) {
      await db.query(statement);
    }
    const owedAfter = (await db.query('SELECT (' + step.when + ') AS owed'))
      .rows[0].owed;
    t.check(owedBefore === true && owedAfter === false,
            'D1. the step is owed before it runs and not after');
    t.equal(await distinctOf(db, schema, 'parent_key'), 100000,
            'D2. pg_stats now says n_distinct = 100000 for parent_key');
    await planAll(t, db, 'D');
    const healed = await planOf(db, OLD_RESIDENT,
                                queries.residentOnly(windowedList())
                                  .values.slice(0, 2));
    t.check(wholeRealmScans(healed).length === 0 &&
            healed.indexOf('Index Scan:sts_ldap_entries_parent') >= 0,
            'D3. and the override alone puts #638\'s restore right',
            healed.join(', '));

    t.log.info('=== E. a resident container larger than a page ===');
    await db.query(
      'INSERT INTO sts_ldap_entries (realm, dn_key, dn, attrs) SELECT ' +
      '\'default\', \'cn=late\' || i || \',\' || $1, \'x\', \'{}\'::jsonb ' +
      'FROM generate_series(1, $2::int) AS i', [GROUPS, LATE_GROUPS]);
    const r = queries.residentOnly(windowedList());
    const got = await db.query(r.text, r.values);
    const old = await db.query(OLD_RESIDENT, r.values);
    const keysOf = function (rows) {
      return rows.map(function (row) {
        return row.realm + '|' + row.dn_key + '|' + JSON.stringify(row.attrs);
      });
    };
    t.check(got.rows.length === old.rows.length &&
            JSON.stringify(keysOf(got.rows)) ===
              JSON.stringify(keysOf(old.rows)),
            'E1. the restore answers #638\'s rows, in its order, a resident ' +
            'container of ' + (3 + LATE_GROUPS) + ' included (' +
            got.rows.length + ' rows)', got.rows.length + ' vs ' +
            old.rows.length);
    const e = await db.query('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' +
                             r.text, r.values);
    const plan = e.rows[0]['QUERY PLAN'][0].Plan;
    const buffers = Number(plan['Shared Hit Blocks'] || 0) +
      Number(plan['Shared Read Blocks'] || 0);
    t.check(buffers < 12 * got.rows.length + 500,
            'E2. and touched ' + buffers + ' buffers for ' + got.rows.length +
            ' rows beside ' + PEOPLE + ' people: a descent a row, not the ' +
            'realm', String(buffers));
  } finally {
    await db.query('DROP SCHEMA ' + schema + ' CASCADE').catch(
      function (e) {
        log.debug("Caught in realDatabase(): " + ((e && e.message) || e));
      });
    await db.end();
  }
  log.debug("Leaving realDatabase().");
}

async function run(t) {
  log.debug("Entering run().");
  theStep(t);
  await realDatabase(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_parent_statistics',
  describe: 'the directory\'s statements planned when ANALYZE saw one ' +
            'parent (#639): every read by parent_key through the parent ' +
            'index with and without schema version 20\'s n_distinct ' +
            '(with a database)',
  run: run
};
