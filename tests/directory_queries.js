// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//      out of the URL and turned into the one `ssl` option; and verify-ca's
//      host-name exemption carried as data a thread can be handed.
//
// WHAT NEEDS A REAL POSTGRES (on #349): that each generated expression is
// accepted as immutable and computes what `ldap_server.js` computes, that the
// indexes are used, and every query's result against real rows.
// ===========================================================================

const storeDouble = require('./tools/store_double');
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
  const restore = storeDouble.install(fakePg(statements, answer));
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({
      url: url || 'postgres://sts_app@localhost:5432/sts', log: QUIET });
  } finally {
    restore();
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
  // A RAW value (no codec on this thread) is put in the keyless lookup form
  // `<kind>\n<value>` the codec writes where nothing seals (#391 phase 6).
  t.equal(JSON.stringify(n.values),
          JSON.stringify(['acme', users, JSON.stringify(['name\nalice']),
                          'alice']),
          'A2. the name is trimmed and lower-cased, in its lookup form, as a ' +
          'JSON array for @>');
  const k = queries.byName('acme', users, { key: 'DIGEST', rdn: 'alice' });
  t.equal(JSON.stringify(k.values),
          JSON.stringify(['acme', users, '["DIGEST"]', 'alice']),
          'A2b. a value the codec keyed is looked up as it came, and the RDN ' +
          '(the DN\'s, readable) as given');
  t.check(/ORDER BY dn_key/.test(n.text),
          'A3. first by key wins, as a restored process\'s index did');
  const u = queries.byUuid('', 'ABCD-1');
  t.check(/uuid_keys @> \$2::jsonb/.test(u.text) &&
          u.values[1] === JSON.stringify(['uuid\nabcd-1']),
          'A4. byUuid compares lower-cased against uuid_keys', u.values[1]);
  const m = queries.byMail('default', 'Bob@Example.COM', 5);
  t.check(/mail_keys @> \$2::jsonb/.test(m.text) &&
          m.values[1] === JSON.stringify(['mail\nbob@example.com']) &&
          m.values[2] === 5,
          'A5. byMail lower-cases and carries its limit',
          JSON.stringify(m.values));
  const a = queries.byAttribute('default', 'DIDSubject', 'did:key:Z6', 3);
  t.check(/value_keys @> \$2::jsonb/.test(a.text) &&
          a.values[1] === JSON.stringify(['attr:didsubject\ndid:key:Z6']),
          'A6. byAttribute asks value_keys, keeping the value as written and ' +
          'lower-casing only the attribute name', JSON.stringify(a.values));
  const p = queries.page('default', 'ou=100%_off,dc=x', 'uid=a', 50000);
  // Since #638 the suffix is asked of the realm's distinct PARENTS, not of
  // every row (`tests/directory_resident_walk.js`).
  t.check(!/LIKE/i.test(p.text) &&
          /right\(parent_key, \$5\) = ',' \|\| \$2/.test(p.text) &&
          p.values[4] === 'ou=100%_off,dc=x'.length + 1,
          'A7. a subtree is compared with right(), so % and _ in a DN are ' +
          'not wildcards', p.text);
  t.equal(p.values[3], queries.MAX_PAGE,
          'A8. a page is bounded at ' + queries.MAX_PAGE + ' rows');
  const one = queries.page('default', users, '', 10, { oneLevel: true });
  t.check(/\(e\.realm, e\.parent_key, e\.dn_key\) > \(\$1, \$2, \$3\)/
    .test(one.text) && /f\.within = \$2/.test(one.text) &&
          one.values.length === 4,
          'A9. a one-level page reads parent_key, as a walk of the parent ' +
          'index (#639)', one.text);
  const self = queries.page('default', users, '', 10, { self: true });
  t.check(/AND dn_key = \$2 AND dn_key > \$3/.test(self.text),
          'A10. a page may include the base itself', self.text);
  // Since #618 a count is READ from the counter the triggers keep — no
  // `count(*)`, and nothing of `sts_ldap_entries` is touched.
  const realmCount = queries.count('r', '');
  t.check(/FROM sts_ldap_counts/.test(realmCount.text) &&
          !/count\(/i.test(realmCount.text) &&
          !/sts_ldap_entries/.test(realmCount.text) &&
          JSON.stringify(realmCount.values) === JSON.stringify(['r', '']),
          'A11. count with no base reads the realm\'s counter (base \'\')',
          realmCount.text);
  const underCount = queries.count('r', users);
  t.check(/base_key = \$2/.test(underCount.text) &&
          !/count\(/i.test(underCount.text) &&
          underCount.values[1] === users,
          'A12. count under a base reads that base\'s counter',
          underCount.text);
  const r = queries.residentOnly([{ realm: 'default', baseKey: users },
                                  { realm: 'acme', baseKey: 'ou=devices,x' }]);
  t.check(/NOT EXISTS/.test(r.text) &&
          JSON.stringify(r.values) === JSON.stringify(
            [['default', 'acme'], [users, 'ou=devices,x']]),
          'A13. residentOnly leaves out what is strictly under each windowed ' +
          'container, per realm', JSON.stringify(r.values));
  // A13b (2026-10-21): `withUuids` is planned without JIT. Its estimate of
  // `@> ANY` is thousands of times the rows the GIN index answers, so it
  // was compiled at every call: 106 ms against 17 ms without, on 8081.
  const uu = queries.withUuids('default', ['a', 'b']);
  t.check(uu.jitOff === true && /uuid_keys @> ANY/.test(uu.text),
          'A13b. withUuids asks the driver to plan it without JIT',
          JSON.stringify({ jitOff: uu.jitOff }));
  const cls = queries.classesUnder('r', users, ['groupOfNames', 'posixGroup']);
  t.check(/class_keys \?\| \$3::text\[\] AND class_keys <> '\[\]'::jsonb/
    .test(cls.text) &&
          JSON.stringify(cls.values[2]) ===
            JSON.stringify(['class\ngroupofnames', 'class\nposixgroup']),
          'A12b. classesUnder asks class_keys for any of the classes, ' +
          'lower-cased, with the partial index\'s predicate (#618)', cls.text);
  const names = queries.namesUnder('r', users, 'uid=a', 10);
  // The entry is a sealed blob since #391 phase 6: its `uid` is read out of
  // it by the codec on the thread that holds the keys.
  t.check(/SELECT dn_key, dn, origin, attrs FROM/.test(names.text),
          'A12c. namesUnder reads the key, the DN, the origin and the blob ' +
          'the first uid is read out of', names.text);
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
  const rdn = queries.rdnPage('default', users, 'alice', 20);
  t.check(/\(e\.realm, e\.parent_key, e\.rdn_value\) > \(\$1, \$2, \$3\)/
      .test(rdn.text) &&
          /ORDER BY e\.realm, e\.parent_key, e\.rdn_value/.test(rdn.text) &&
          /ORDER BY rdn_value OFFSET/.test(rdn.text) &&
          !/position\(/.test(rdn.text) &&
          rdn.values[3] === 20 && rdn.values[4] === 0,
          'A18. rdnPage walks the rdn index after the cursor, and an empty ' +
          'needle adds no predicate', rdn.text);
  const searched = queries.rdnPage('default', users, '', 10,
                                   { needle: 'Al', offset: 5 });
  t.check(/position\(\$4 in e\.rdn_value\) > 0/.test(searched.text) &&
          searched.values[3] === 'al' && searched.values[4] === 15 &&
          searched.values[5] === 5,
          'A19. a needle is position() inside the walk, lower-cased, and ' +
          'the offset is applied after it', JSON.stringify(searched.values));
  const box = queries.containerPage('default',
                                    'ou=devices,dc=example,dc=com', 50, 10);
  t.check(box.text.indexOf("($1, $2, '')") >= 0 &&
          /OFFSET \$4/.test(box.text) &&
          box.values[2] === 60 && box.values[3] === 50,
          'A20. containerPage walks from the empty key and drops the offset',
          box.text);
  const withRdn = queries.answerOf('rdnPage',
    [Object.assign({ rdn_value: 'a' }, row)])[0];
  t.check(withRdn.key === 'uid=a,ou=users' && withRdn.rdn === 'a',
          'A21. rdnPage answers the row plus its rdn',
          JSON.stringify(withRdn));
  t.equal(queries.answerOf('rdnCount', [{ n: '7' }]), 7,
          'A22. rdnCount answers a number');
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
    // A counter read since #618, no longer a count(*).
    if (/FROM sts_ldap_counts/.test(sql)) {
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
  t.log.info('=== C. schema version 26 ===');
  t.equal(postgres.SCHEMA_VERSION, 26,
          'C1. the driver writes schema version 26 (#222, #391 phase 6, ' +
          '#432 phase 5, #618, #623, #630, #639, #350, #754, the uid ' +
          'trigram index, #820\'s sts_minted_index and its sort_at, #956)');
  const table = postgres.SCHEMA_OBJECTS.filter(function (o) {
    return o.name === 'sts_ldap_entries';
  })[0];
  const columns = postgres.SCHEMA_COLUMNS.filter(function (c) {
    return c.table === 'sts_ldap_entries';
  });
  const names = ['parent_key', 'rdn_value', 'name_keys', 'mail_keys',
                 'uuid_keys', 'class_keys', 'value_keys', 'attr_names',
                 'dek_keys'];
  t.equal(columns.map(function (c) { return c.column; }).join(','),
          names.join(','), 'C2. SCHEMA_COLUMNS adds the eight lookup ' +
          'columns, and the data keys (#623)');
  // `dek_keys` (#623) is NULLABLE with no default: NULL is an entry whose
  // keys are not yet known, which '{}' would claim it held none of.
  const dekKeys = columns.filter(function (c) {
    return c.column === 'dek_keys';
  })[0];
  t.check(dekKeys && /ADD COLUMN IF NOT EXISTS dek_keys jsonb$/
    .test(dekKeys.statement) &&
          table.statement.indexOf('dek_keys jsonb,') >= 0,
          'C2b. dek_keys is a nullable jsonb with no default, in the CREATE ' +
          'TABLE and the ALTER alike', dekKeys && dekKeys.statement);
  columns.filter(function (c) {
    return c.column !== 'dek_keys';
  }).forEach(function (c) {
    const definition = c.statement.replace(
      'ALTER TABLE sts_ldap_entries ADD COLUMN IF NOT EXISTS ', '');
    // Only the two read from the DN are generated since #391 phase 6; the
    // value lookups are written by the service beside the sealed blob.
    const generated = c.column === 'parent_key' || c.column === 'rdn_value';
    t.check(table.statement.indexOf(definition) >= 0 &&
            (generated ? /GENERATED ALWAYS AS .* STORED$/.test(definition)
                       : /^\w+ jsonb NOT NULL DEFAULT '\[\]'::jsonb$/
                         .test(definition)),
            'C3. ' + c.column + ' is one ' + (generated
              ? 'GENERATED … STORED' : 'written jsonb') + ' definition, in ' +
            'the CREATE TABLE and the ALTER alike', definition);
  });
  const INDEXES = /^sts_ldap_entries_(parent|rdn|names|mails|uuids|values|asked_names|group_classes|uid_trgm)$/;
  const indexes = postgres.SCHEMA_OBJECTS.filter(function (o) {
    return INDEXES.test(o.name);
  });
  t.check(indexes.length === 9 && indexes.every(function (o) {
    return o.afterColumns === true;
  }), 'C4. the nine lookup indexes wait for the column step',
          indexes.map(function (o) { return o.name; }).join(', '));
  t.check(!postgres.SCHEMA_OBJECTS.some(function (o) {
    return o.name === 'sts_ldap_entries_attrs';
  }), 'C4b. and nothing indexes `attrs`, a sealed blob');

  // AN OLD TABLE: every object present except the six indexes, and the
  // information schema listing none of the five columns.
  const statements = [];
  const driver = driverWith(statements, function (sql, params) {
    if (/to_regclass/.test(sql)) {
      const row = {};
      params.forEach(function (name, i) {
        row['o' + i] = INDEXES.test(name) ? null : name;
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
  // The ninth index is the uid trigram index (schema version 23), whose
  // extension is created just before it.
  const extensionAt = statements.findIndex(function (s) {
    return /^CREATE EXTENSION IF NOT EXISTS pg_trgm$/.test(s.sql);
  });
  const trigramAt = statements.findIndex(function (s) {
    return /^CREATE INDEX IF NOT EXISTS sts_ldap_entries_uid_trgm /
      .test(s.sql);
  });
  t.check(extensionAt >= 0 && trigramAt === extensionAt + 1,
          'C5-ii. and creates pg_trgm just before the trigram index',
          extensionAt + ' ' + trigramAt);
  t.check(ddl.length === 18 && lastAlter === 8 && firstIndex === 9,
          'C5. against an old table open() adds the nine columns, THEN ' +
          'builds the nine indexes', ddl.map(function (sql) {
            return sql.slice(0, 60);
          }).join(' | '));
  t.check(statements.some(function (s) {
    return /INSERT INTO sts_schema/.test(s.sql) && s.params[0] === 26;
  }), 'C6. and records version 26');
  // THE TWO INDEXES VERSION 18 REPLACED (#618) are dropped where the
  // catalogue still lists them, after the indexes that replace them.
  const retired = [];
  const dropping = driverWith(retired, function (sql) {
    if (/to_regclass/.test(sql)) {
      return [{}];
    }
    if (/FROM pg_class c JOIN pg_namespace/.test(sql)) {
      return [{ name: 'sts_ldap_entries_attr_names' }];
    }
    return undefined;
  });
  await dropping.open();
  const order = retired.map(function (s) {
    return s.sql;
  });
  const dropAt = order.indexOf(
    'DROP INDEX IF EXISTS sts_ldap_entries_attr_names');
  const askedAt = order.findIndex(function (sql) {
    return /^CREATE INDEX IF NOT EXISTS sts_ldap_entries_asked_names /
      .test(sql);
  });
  t.check(dropAt > askedAt && askedAt >= 0 && !order.some(function (sql) {
    return /DROP INDEX IF EXISTS sts_ldap_entries_classes/.test(sql);
  }), 'C7. a retired index still in the catalogue is dropped after its ' +
          'replacement is built, and one that is not is left alone',
          JSON.stringify({ dropAt: dropAt, askedAt: askedAt }));
    // AN INDEX STILL TAKING ITS INSERTS THROUGH A PENDING LIST (#618) is
  // switched and flushed; one already switched is left alone.
  const switched = [];
  const switching = driverWith(switched, function (sql) {
    if (/to_regclass/.test(sql)) {
      return [{}];
    }
    if (/c\.reloptions AS options/.test(sql)) {
      return [{ name: 'sts_ldap_entries_names', options: null },
              { name: 'sts_ldap_entries_uuids',
                options: ['fastupdate=off'] }];
    }
    return undefined;
  });
  await switching.open();
  const issued = switched.map(function (s) {
    return s.sql;
  });
  const alterNames = issued.indexOf(
    'ALTER INDEX sts_ldap_entries_names SET (fastupdate = off)');
  t.check(alterNames >= 0 && issued[alterNames + 1] ===
            'SELECT gin_clean_pending_list(\'sts_ldap_entries_names\'' +
            '::regclass)' &&
          !issued.some(function (sql) {
            return /ALTER INDEX sts_ldap_entries_uuids/.test(sql);
          }),
          'C8. an index without fastupdate off is switched and its pending ' +
          'list flushed; one with it is left alone',
          JSON.stringify(issued.filter(function (sql) {
            return /ALTER INDEX|gin_clean/.test(sql);
          })));
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
  // #273: postgres is never dialled in the clear, so a URL with no sslmode
  // means require and carries the same ssl option D1's does.
  t.check(plain && !/sslmode/.test(plain.connectionString) && plain.ssl &&
          typeof plain.ssl.rejectUnauthorized === 'boolean',
          'D2. no sslmode means require (#273): the ssl option is there too',
          JSON.stringify({ url: plain && plain.connectionString,
                           ssl: plain && plain.ssl }));
  // #543 round 2: verify-ca's ssl option holds a function, which cannot be
  // posted to the thread, so the bridge says it as data — and the whole
  // answer survives structured cloning, as a Worker's workerData must.
  const ca = driverWith(
    [], null, 'postgres://sts_app@db:5432/sts?sslmode=verify-ca')
    .bridgeConnection();
  let cloned = null;
  try {
    cloned = structuredClone(ca);
  } catch (e) {
    log.debug("Caught in bridgeConnection(): " + ((e && e.message) || e));
  }
  t.check(cloned && cloned.ssl && cloned.ssl.rejectUnauthorized === true &&
          cloned.ssl.hostnameUnchecked === true &&
          cloned.ssl.checkServerIdentity === undefined,
          'D3. verify-ca reaches the bridge as data: the chain verified, ' +
          'the host name marked unchecked, and nothing uncloneable',
          JSON.stringify(ca && ca.ssl));
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
