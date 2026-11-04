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
//      and with a needle), a `containerPage` (the first page and an
//      offset) and a needle's capped `rdnCount` (#1308) —
//      no sequential scan, no primary key or realm index on the table; the
//      restore's and the pages' rows through the parent index, and an
//      `rdnPage` through `sts_ldap_entries_rdn`. A two-character needle's
//      count may scan the table, which here is the parent (#1310).
//   D. THE UPGRADE: the driver's step run as written; `n_distinct` is
//      100,000, the probe no longer owes it, and every statement of C — and
//      #638's old restore, which the override alone puts right — reads the
//      index that statement names (the parent index, or the rdn index).
//   E. A RESIDENT CONTAINER LARGER THAN A PAGE, written after the ANALYZE
//      (as an import leaves it): the restore answers #638's old statement's
//      rows, in its order, and its buffers follow the rows it answers.
//   F. A SELECTIVE NEEDLE IS AN INDEX PROBE (#1310): in A, which needles
//      and pages take the trigram statements; in C and D, a selective
//      needle's count, and its page when the count says its matches are
//      few, read `sts_ldap_entries_uid_trgm`, and a page with many matches
//      still walks the rdn index; in F, run, the count and the page answer
//      what #1308's `position()` statements answer, in a small fraction of
//      their buffers.
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

// The scans of `sts_ldap_entries` in a plan, `Node Type:Index Name`: the
// table's nodes and the index nodes under them (a bitmap index scan names
// no relation, only its index, #1310).
function scansOf(plan) {
  log.debug("Entering scansOf().");
  log.debug("Leaving scansOf().");
  return nodesOf(plan).filter(function (node) {
    return node['Relation Name'] === 'sts_ldap_entries' ||
      /^sts_ldap_entries/.test(String(node['Index Name'] || ''));
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
  // #1310, which needles the trigram statements are asked for.
  t.check(queries.needleIndexed(USERS, 'u29') &&
          queries.needleIndexed(USERS, 'a.b12c') &&
          !queries.needleIndexed(USERS, 'u5') &&
          !queries.needleIndexed(USERS, 'a.b.c') &&
          !queries.needleIndexed(USERS, '\u00e9\u00e8\u00e0') &&
          !queries.needleIndexed(GROUPS, 'u29'),
          'A6. the trigram statements are asked under ou=users for a ' +
          'needle with three ASCII letters or digits in a row, and for no ' +
          'other (#1310)');
  const count = queries.rdnCount('default', USERS, 'U29%_\\');
  t.check(/^WITH m AS MATERIALIZED \(SELECT 1 AS one FROM sts_ldap_entries/
            .test(count.text) &&
          count.text.indexOf(queries.USERS_PARENT + ' AND rdn_value LIKE ' +
                             '$3 ESCAPE \'\\\')') > 0 &&
          /FROM m LIMIT \$4\) AS matched$/.test(count.text) &&
          count.values[2] === '%u29\\%\\_\\\\%' &&
          count.values[3] === queries.RDN_COUNT_CAP + 1,
          'A7. such a count is fenced, repeats the index\'s condition, ' +
          'escapes the needle\'s wildcards and keeps #1308\'s cap',
          JSON.stringify(count));
  const few = queries.rdnPage('default', USERS, '', 100,
                              { needle: 'u29', offset: 20, matched: 40,
                                total: 1000 });
  t.check(/ORDER BY rdn_value, dn_key LIMIT \$5 OFFSET \$6$/
            .test(few.text) && /LIKE \$4 ESCAPE/.test(few.text) &&
          few.values[4] === 100 && few.values[5] === 20,
          'A8. a page whose matches are few is read by them, sorted, the ' +
          'offset kept', JSON.stringify(few));
  const walked = function (o) {
    return /WITH RECURSIVE walk/.test(queries.rdnPage('default', USERS, '',
      100, Object.assign({ needle: 'u29', offset: 0 }, o)).text);
  };
  t.check(walked({}) && walked({ matched: 1000, total: 1000 }) &&
          walked({ matched: 40, total: 1000, countCapped: true }) &&
          walked({ matched: queries.RDN_COUNT_CAP + 1, total: 1e12 }) &&
          !walked({ matched: 0, total: 0 }) &&
          !walked({ matched: 316, total: 1000 }) &&
          walked({ matched: 317, total: 1000 }),
          'A9. and a page without a count, with many matches or with a ' +
          'capped count is walked: matched squared against walk times total');
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
    // read the parent index. `rdnCount` is a count, not a walk: since
    // #1308 it is capped by a LIMIT, which lets a planner prefer a scan
    // that finds the first rows soonest, so it is held to the rule every
    // statement here is — no sequential scan, no primary key — and to no
    // particular index.
    // A needle of two characters has no trigram, so its count reads the
    // parent's children (#1310): here they are all but forty rows of the
    // table, and a sequential scan IS that read — the realm's other
    // indexes and the primary key are still refused.
    ['rdnCount containing a needle, capped',
     queries.rdnCount('default', USERS, 'u5'), 'children'],
    ['rdnPage of the big container',
     queries.rdnPage('default', USERS, '', 1000), 'rdn'],
    ['rdnPage after a cursor',
     queries.rdnPage('default', USERS, 'u500', 1000), 'rdn'],
    ['rdnPage containing a needle',
     queries.rdnPage('default', USERS, '', 100, { needle: 'u5' }), 'rdn'],
    // #1310: a needle of three digits or more is asked of the trigram
    // index. `u29999` is eleven people of PEOPLE; `u10` about one in
    // twenty-seven, too many for its page to be read by its matches.
    ['rdnCount, a selective needle',
     queries.rdnCount('default', USERS, 'u29999'), 'trgm'],
    ['rdnPage, a selective needle read by its matches',
     queries.rdnPage('default', USERS, '', 100,
                     { needle: 'u29999', matched: 11, total: PEOPLE }),
     'trgm'],
    ['rdnCount, a broad needle of three characters',
     queries.rdnCount('default', USERS, 'u10'), false],
    ['rdnPage, a broad needle, walked',
     queries.rdnPage('default', USERS, '', 100,
                     { needle: 'u10', matched: Math.floor(PEOPLE / 27),
                       total: PEOPLE }), 'rdn'],
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
    const refused = wholeRealmScans(scans).filter(function (scan) {
      return one[2] !== 'children' || !/^Seq Scan/.test(scan);
    });
    t.check(scans.length > 0 && refused.length === 0,
            label + '. ' + one[0] + (one[2] === 'children'
              ? ': no primary key or realm index on the table'
              : ': no sequential scan, no primary key or realm index on ' +
                'the table'), scans.join(', '));
    if (one[2] === true) {
      t.check(scans.indexOf('Index Scan:sts_ldap_entries_parent') >= 0,
              label + '. ' + one[0] + ': the rows through the parent index',
              scans.join(', '));
    } else if (one[2] === 'rdn') {
      t.check(scans.indexOf('Index Scan:sts_ldap_entries_rdn') >= 0,
              label + '. ' + one[0] + ': the rows through the rdn index',
              scans.join(', '));
    } else if (one[2] === 'trgm') {
      t.check(scans.indexOf('Bitmap Index Scan:sts_ldap_entries_uid_trgm') >=
              0 && scans.indexOf('Index Scan:sts_ldap_entries_rdn') < 0 &&
              scans.indexOf('Index Only Scan:sts_ldap_entries_rdn') < 0,
              label + '. ' + one[0] + ': the matches through the trigram ' +
              'index, not a read of the children (#1310)',
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
    // `sts_ldap_entries_uid_trgm`'s operator class is `pg_trgm`'s: made
    // where the database's default path puts it, unless it is there
    // already, and that schema kept on this test's path.
    await db.query('CREATE EXTENSION IF NOT EXISTS pg_trgm');
    const trgm = (await db.query('SELECT n.nspname AS s FROM pg_extension ' +
      'x JOIN pg_namespace n ON n.oid = x.extnamespace WHERE x.extname = ' +
      '\'pg_trgm\'')).rows[0].s;
    await db.query('SET search_path TO ' + schema + ', "' + trgm + '"');
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

    t.log.info('=== F. a selective needle, run (#1310) ===');
    await selectiveNeedle(t, db);
  } finally {
    await db.query('DROP SCHEMA ' + schema + ' CASCADE').catch(
      function (e) {
        log.debug("Caught in realDatabase(): " + ((e && e.message) || e));
      });
    await db.end();
  }
  log.debug("Leaving realDatabase().");
}

// The buffers a statement touched, and its rows.
async function ranWith(db, statement) {
  log.debug("Entering ranWith().");
  const e = await db.query('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' +
                           statement.text, statement.values);
  const plan = e.rows[0]['QUERY PLAN'][0].Plan;
  const rows = await db.query(statement.text, statement.values);
  log.debug("Leaving ranWith().");
  return { buffers: Number(plan['Shared Hit Blocks'] || 0) +
                    Number(plan['Shared Read Blocks'] || 0),
           rows: rows.rows };
}

// F: the selective needle's count and page, run, against #1308's
// statements for the same needle — the count kept here as text, and the
// page the walk the builder still sends when no count is given.
async function selectiveNeedle(t, db) {
  log.debug("Entering selectiveNeedle().");
  const needle = 'u29999';
  const oldCount = { text: 'SELECT count(*)::bigint AS n FROM (SELECT 1 ' +
    'AS one FROM sts_ldap_entries WHERE realm = $1 AND parent_key = $2 AND ' +
    'position($3 in rdn_value) > 0 LIMIT $4) AS matched',
    values: ['default', USERS, needle, queries.RDN_COUNT_CAP + 1] };
  const count = await ranWith(db, queries.rdnCount('default', USERS,
                                                   needle));
  const old = await ranWith(db, oldCount);
  const n = Number(count.rows[0].n);
  t.check(n === Number(old.rows[0].n) && n > 5,
          'F1. the count answers what #1308\'s statement answers (' + n +
          ')', n + ' vs ' + old.rows[0].n);
  t.check(count.buffers * 20 < old.buffers,
          'F2. in ' + count.buffers + ' buffers to its ' + old.buffers +
          ': the matches, not the ' + PEOPLE + ' children',
          count.buffers + ' vs ' + old.buffers);
  const page = await ranWith(db, queries.rdnPage('default', USERS, '', 5,
    { needle: needle, offset: 3, matched: n, total: PEOPLE }));
  const walkedPage = await ranWith(db, queries.rdnPage('default', USERS, '',
    5, { needle: needle, offset: 3 }));
  const rdns = function (rows) {
    return rows.map(function (row) {
      return row.rdn_value;
    }).join(',');
  };
  t.check(page.rows.length === 5 &&
          rdns(page.rows) === rdns(walkedPage.rows),
          'F3. the page read by its matches is the walk\'s page, in its ' +
          'order, the offset kept', rdns(page.rows) + ' vs ' +
          rdns(walkedPage.rows));
  t.check(page.buffers * 20 < walkedPage.buffers,
          'F4. in ' + page.buffers + ' buffers to the walk\'s ' +
          walkedPage.buffers, page.buffers + ' vs ' + walkedPage.buffers);
  log.debug("Leaving selectiveNeedle().");
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
            'index with and without schema version 20\'s n_distinct, and a ' +
            'selective needle through the trigram index (#1310) (with a ' +
            'database)',
  run: run
};
