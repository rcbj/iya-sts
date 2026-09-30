// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: directory_queries.js
//
// ===========================================================================
// THE DIRECTORY'S LOOKUPS AS SQL, AND SCHEMA VERSION 13 (#349 phase 2,
// 2026-09-29).
//
// `npm test` has no PostgreSQL, so what is held here is everything that can
// be believed without one, against a `pg` that records statements:
//
//   A. THE BUILDERS: every query names its realm, reads the generated column
//      its lookup needs, compares a name, a mail address and a UUID
//      lower-cased as a JSON array for `@>`, never lets a `%` in a DN become
//      a wildcard, bounds a page at 1,000, and refuses a query it does not
//      know. `answerOf()` shapes rows as `readEntry()` always did.
//   B. THE DRIVER'S DOOR: `directoryQuery()` runs exactly the builder's
//      statement on the READ pool and answers in the directory's shape; an
//      unknown query is a rejection, not a statement.
//   C. THE SCHEMA: version 13; the five generated columns are in the CREATE
//      TABLE and in SCHEMA_COLUMNS as the same definition; the six indexes
//      wait for the column step (`afterColumns`), and against an OLD table
//      `open()` issues every ALTER before any of them.
//   D. THE BRIDGE'S CONNECTION: the read side's options, the sslmode taken
//      out of the URL and turned into the one `ssl` option.
//
// WHAT NEEDS A REAL POSTGRES (on #349): that each generated expression is
// accepted as immutable and computes what `ldap_server.js` computes, that the
// indexes are used, and every query's result against real rows.
// ===========================================================================

const postgres = require('../persistence/persistence_postgres');
const queries = require('../persistence/directory_queries');

const log = require('bunyan').createLogger({ name: 'directory_queries',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// A `pg` that remembers every statement and answers through `answer(sql,
// params)`, which returns the rows (or undefined for none).
function fakePg(statements, answer) {
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
  return { Pool: FakePool, Client: FakeClient };
}

function driverWith(statements, answer, url) {
  log.debug("Entering driverWith().");
  const pgPath = require.resolve('pg');
  const previous = require.cache[pgPath];
  require.cache[pgPath] = { id: pgPath, filename: pgPath, loaded: true,
                            exports: fakePg(statements, answer) };
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({
      url: url || 'postgres://sts_app@localhost:5432/sts', log: QUIET });
  } finally {
    if (previous) {
      require.cache[pgPath] = previous;
    } else {
      delete require.cache[pgPath];
    }
  }
}

function builders(t) {
  log.debug("Entering builders().");
  t.log.info('=== A. the builders ===');
  const users = 'ou=users,dc=example,dc=com';
  const n = queries.byName('acme', users, '  Alice ');
  t.check(/parent_key = \$2/.test(n.text) && /name_keys @> \$3::jsonb/.test(
    n.text) && /rdn_value = \$4/.test(n.text) && /realm = \$1/.test(n.text),
          'A1. byName reads parent_key, name_keys and rdn_value, in the realm',
          n.text);
  t.equal(JSON.stringify(n.values),
          JSON.stringify(['acme', users, '["alice"]', 'alice']),
          'A2. the name is trimmed and lower-cased, as a JSON array for @>');
  t.check(/ORDER BY dn_key/.test(n.text),
          'A3. first by key wins, as a restored process\'s index did');
  const u = queries.byUuid('', 'ABCD-1');
  t.check(/uuid_keys @> \$2::jsonb/.test(u.text) &&
          u.values[1] === '["abcd-1"]',
          'A4. byUuid compares lower-cased against uuid_keys', u.values[1]);
  const m = queries.byMail('default', 'Bob@Example.COM', 5);
  t.check(/mail_keys @> \$2::jsonb/.test(m.text) &&
          m.values[1] === '["bob@example.com"]' && m.values[2] === 5,
          'A5. byMail lower-cases and carries its limit',
          JSON.stringify(m.values));
  const a = queries.byAttribute('default', 'DIDSubject', 'did:key:Z6', 3);
  t.equal(a.values[1], '{"didsubject":["did:key:Z6"]}',
          'A6. byAttribute keeps the value as written and lower-cases only ' +
          'the attribute name, as the store holds it');
  const p = queries.page('default', 'ou=100%_off,dc=x', 'uid=a', 50000);
  t.check(!/LIKE/i.test(p.text) && /right\(dn_key, \$5\)/.test(p.text) &&
          p.values[4] === 'ou=100%_off,dc=x'.length + 1,
          'A7. a subtree is compared with right(), so % and _ in a DN are ' +
          'not wildcards', p.text);
  t.equal(p.values[3], queries.MAX_PAGE,
          'A8. a page is bounded at ' + queries.MAX_PAGE + ' rows');
  const one = queries.page('default', users, '', 10, { oneLevel: true });
  t.check(/parent_key = \$2/.test(one.text) && one.values.length === 4,
          'A9. a one-level page reads parent_key', one.text);
  const self = queries.page('default', users, '', 10, { self: true });
  t.check(/dn_key = \$2 OR/.test(self.text),
          'A10. a page may include the base itself');
  t.check(/count\(\*\)/.test(queries.count('r', '').text) &&
          queries.count('r', '').values.length === 1,
          'A11. count with no base counts the realm');
  t.check(/right\(dn_key, \$3\)/.test(queries.count('r', users).text),
          'A12. count under a base counts strictly under it');
  const r = queries.residentOnly([{ realm: 'default', baseKey: users },
                                  { realm: 'acme', baseKey: 'ou=devices,x' }]);
  t.check(/NOT EXISTS/.test(r.text) &&
          JSON.stringify(r.values) === JSON.stringify(
            [['default', 'acme'], [users, 'ou=devices,x']]),
          'A13. residentOnly leaves out what is strictly under each windowed ' +
          'container, per realm', JSON.stringify(r.values));
  const cls = queries.classesUnder('r', users, ['groupOfNames', 'posixGroup']);
  t.check(/class_keys \?\| \$3::text\[\]/.test(cls.text) &&
          JSON.stringify(cls.values[2]) === '["groupofnames","posixgroup"]',
          'A12b. classesUnder asks class_keys for any of the classes, ' +
          'lower-cased', cls.text);
  const names = queries.namesUnder('r', users, 'uid=a', 10);
  t.check(/SELECT dn_key, dn, origin, attrs->'uid'->>0 AS uid/.test(
    names.text) && !/attrs,/.test(names.text),
          'A12c. namesUnder reads the key, the DN, the origin and the first ' +
          'uid, and never the entry', names.text);
  t.equal(JSON.stringify(queries.answerOf('namesUnder',
    [{ dn_key: 'k', dn: 'D', origin: null, uid: null }])),
          '[{"key":"k","dn":"D","origin":"","uid":""}]',
          'A12d. a name row is { key, dn, origin, uid }');
  let threw = false;
  try {
    queries.build('dropTables', []);
  } catch (e) {
    log.debug("Caught in builders(): " + e.message);
    threw = true;
  }
  t.check(threw, 'A14. an unknown query is refused by name');
  const row = { realm: 'default', dn_key: 'uid=a,ou=users',
                dn: 'uid=A,ou=Users', attrs: { uid: ['A'] }, origin: 'seed',
                created_at: '20260929000000Z', modified_at: null };
  const shaped = queries.answerOf('byKeys', [row])[0];
  t.check(shaped.key === 'uid=a,ou=users' && shaped.entry.dn ===
          'uid=A,ou=Users' && shaped.entry.modifiedAt === '20260929000000Z',
          'A15. a row is { realm, key, entry } in the directory\'s shape, ' +
          'modifiedAt falling back to createdAt', JSON.stringify(shaped));
  t.equal(queries.answerOf('count', [{ n: '42' }]), 42,
          'A16. a count answers a number');
  t.equal(queries.answerOf('hasChild', []), false,
          'A17. hasChild answers a boolean');
  log.debug("Leaving builders().");
}

async function driverDoor(t) {
  log.debug("Entering driverDoor().");
  t.log.info('=== B. the driver\'s door ===');
  const statements = [];
  const driver = driverWith(statements, function (sql) {
    if (/name_keys/.test(sql)) {
      return [{ realm: 'default', dn_key: 'uid=alice,ou=users,dc=x',
                dn: 'uid=alice,ou=users,dc=x', attrs: { uid: ['alice'] },
                origin: 'seed', created_at: 'c', modified_at: 'm' }];
    }
    if (/count\(\*\)/.test(sql)) {
      return [{ n: 7 }];
    }
    return undefined;
  });
  const found = await driver.directoryQuery('byName',
                                             ['default', 'ou=users,dc=x',
                                              'Alice']);
  const expected = queries.byName('default', 'ou=users,dc=x', 'Alice');
  const ran = statements[statements.length - 1];
  t.check(ran && ran.sql === expected.text &&
          JSON.stringify(ran.params) === JSON.stringify(expected.values),
          'B1. directoryQuery runs exactly the builder\'s statement');
  t.check(found.length === 1 && found[0].entry.attributes.uid[0] === 'alice',
          'B2. and answers in the directory\'s shape', JSON.stringify(found));
  t.equal(await driver.directoryQuery('count', ['default', '']), 7,
          'B3. a count answers a number');
  let rejected = false;
  const before = statements.length;
  await driver.directoryQuery('nope', []).catch(function (e) {
    log.debug("Caught in driverDoor(): " + e.message);
    rejected = true;
  });
  t.check(rejected && statements.length === before,
          'B4. an unknown query is a rejection and sends no statement');
  log.debug("Leaving driverDoor().");
}

async function schema(t) {
  log.debug("Entering schema().");
  t.log.info('=== C. schema version 13 ===');
  t.equal(postgres.SCHEMA_VERSION, 13,
          'C1. the driver writes schema version 13 (12 is #333\'s)');
  const table = postgres.SCHEMA_OBJECTS.filter(function (o) {
    return o.name === 'sts_ldap_entries';
  })[0];
  const columns = postgres.SCHEMA_COLUMNS.filter(function (c) {
    return c.table === 'sts_ldap_entries';
  });
  const names = ['parent_key', 'rdn_value', 'name_keys', 'mail_keys',
                 'uuid_keys', 'class_keys'];
  t.equal(columns.map(function (c) { return c.column; }).join(','),
          names.join(','), 'C2. SCHEMA_COLUMNS adds the six lookup columns');
  columns.forEach(function (c) {
    const definition = c.statement.replace(
      'ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS ', '');
    t.check(table.statement.indexOf(definition) >= 0 &&
            /GENERATED ALWAYS AS .* STORED$/.test(definition),
            'C3. ' + c.column + ' is one GENERATED … STORED definition, in ' +
            'the CREATE TABLE and the ALTER alike');
  });
  const indexes = postgres.SCHEMA_OBJECTS.filter(function (o) {
    return /^sts_ldap_entries_(parent|rdn|names|mails|uuids|attrs|classes)$/
      .test(o.name);
  });
  t.check(indexes.length === 7 && indexes.every(function (o) {
    return o.afterColumns === true;
  }), 'C4. the seven lookup indexes wait for the column step',
          indexes.map(function (o) { return o.name; }).join(', '));

  // AN OLD TABLE: every object present except the six indexes, and the
  // information schema listing none of the five columns.
  const statements = [];
  const driver = driverWith(statements, function (sql, params) {
    if (/to_regclass/.test(sql)) {
      const row = {};
      params.forEach(function (name, i) {
        row['o' + i] =
          /^sts_ldap_entries_(parent|rdn|names|mails|uuids|attrs|classes)$/
            .test(name) ? null : name;
      });
      return [row];
    }
    if (/information_schema\.columns/.test(sql)) {
      const present = [];
      for (let i = 0; i < params.length; i += 2) {
        if (params[i] !== 'sts_ldap_entries') {
          present.push({ table_name: params[i], column_name: params[i + 1] });
        }
      }
      return present;
    }
    return undefined;
  });
  await driver.open();
  const ddl = statements.map(function (s) {
    return s.sql;
  }).filter(function (sql) {
    return /^(ALTER TABLE|CREATE INDEX)/.test(sql);
  });
  const lastAlter = ddl.map(function (sql) {
    return /^ALTER/.test(sql);
  }).lastIndexOf(true);
  const firstIndex = ddl.findIndex(function (sql) {
    return /^CREATE INDEX/.test(sql);
  });
  t.check(ddl.length === 13 && lastAlter === 5 && firstIndex === 6,
          'C5. against an old table open() adds the six columns, THEN ' +
          'builds the seven indexes', ddl.map(function (sql) {
            return sql.slice(0, 60);
          }).join(' | '));
  t.check(statements.some(function (s) {
    return /INSERT INTO sts_schema/.test(s.sql) && s.params[0] === 13;
  }), 'C6. and records version 13');
  log.debug("Leaving schema().");
}

function bridgeConnection(t) {
  log.debug("Entering bridgeConnection().");
  t.log.info('=== D. what the bridge dials ===');
  const driver = driverWith(
    [], null, 'postgres://sts_app:pw@db:5432/sts?sslmode=require');
  const o = driver.bridgeConnection();
  t.check(o && !/sslmode/.test(o.connectionString) && o.ssl &&
          typeof o.ssl.rejectUnauthorized === 'boolean',
          'D1. the read side\'s options, the sslmode made the one ssl option',
          JSON.stringify({ url: o && o.connectionString, ssl: o && o.ssl }));
  const plain = driverWith([], null, 'postgres://sts_app@db:5432/sts')
    .bridgeConnection();
  t.check(plain.ssl === undefined,
          'D2. no sslmode, no ssl option — the driver\'s one rule');
  log.debug("Leaving bridgeConnection().");
}

async function run(t) {
  log.debug("Entering run().");
  builders(t);
  await driverDoor(t);
  await schema(t);
  bridgeConnection(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_queries',
  describe: 'the directory lookups as SQL (#349): the builders, the ' +
            'driver\'s door, schema version 13\'s columns and index order, ' +
            'and what the bridge dials',
  run: run
};
