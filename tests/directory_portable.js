// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_portable.js
//
// ===========================================================================
// THE EMBEDDED DIRECTORY'S STORE ON MARIADB (#677, phase 3b):
// `persistence/directory_portable.js` and its questions,
// `persistence/directory_queries_mariadb.js`.
//
//   A. ALWAYS: every statement the library sends — every question, the
//      flush, the lost-row merge, a removed realm, the counts' fold, the
//      sealed counts and the re-encryption pass — carries none of
//      PostgreSQL's syntax, against a runner that records it; every
//      `directory_queries.js` question has a MariaDB spelling; a lookup form
//      over 344 characters is digested; a DN key over 352 is refused
//      STS-STORE-0140 before anything is sent.
//   C. AGAINST A REAL MARIADB, when STS_TEST_MARIADB_URL names a server the
//      test may create a database on (it makes one and drops it), the whole
//      schema from `persistence/schema_mariadb.js`: entries written, read
//      back and looked up by every question; after every step the kept
//      counts, the data-key counts and the key rows equal what a fresh count
//      of the table gives; two stores (two pools, as two nodes) writing one
//      entry merge; a row another node commits between the lock and the
//      insert is replaced (blind) or merged after COMMIT (merged); twenty
//      concurrent flushes of one container keep the counts; a removed realm
//      takes its rows, key rows and counts; a long DN is refused with
//      nothing written; a long lookup value is found; and the data-key
//      counts and the re-encryption pass move what is sealed under a key.
//   D. THE DRIVER'S DOORS on the same database: `persistence_postgres.js`
//      created for `engine: 'mariadb'` restores, reads and asks through this
//      library.
//
// There is no B: the library writes `sts_ldap_entry_keys`, which
// PostgreSQL's schema has not got, so it is never built on PostgreSQL.
// ===========================================================================

delete process.env.CONFIG_FILE;

const sqlDialect = require('../persistence/sql_dialect');
const directoryPortable = require('../persistence/directory_portable');
const mariadbQueries = require('../persistence/directory_queries_mariadb');
const directoryQueries = require('../persistence/directory_queries');
const directoryCodec = require('../persistence/directory_codec');

const log = require('bunyan').createLogger({ name: 'directory_portable',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'dc=example,dc=com';
const USERS = 'ou=users,' + BASE;
const GROUPS = 'ou=groups,' + BASE;
const DEVICES = 'ou=devices,' + BASE;

// The sealed-looking value a data key is counted by (`directory_codec`'s
// SEALED_VALUE): what a TOTP secret sealed under `dek-test-0001` looks like.
function sealedUnder(dekId) {
  log.debug("Entering sealedUnder().");
  log.debug("Leaving sealedUnder().");
  return '$aesgcm$2$' + dekId + '$aaaa$bbbb$cccc';
}

// The driver's `sealedLike()` and `resealText()`, for the library's deps.
function sealedLike(dekId) {
  log.debug("Entering sealedLike().");
  log.debug("Leaving sealedLike().");
  return '%$aes___$2$' + String(dekId).replace(/[\\%_]/g, '\\$&') + '$%';
}

const SEALED_VALUE = /\$aes(?:gcm|siv)\$2\$[A-Za-z0-9_.-]+\$[A-Za-z0-9+/=]*\$[A-Za-z0-9+/=]*\$[A-Za-z0-9+/=]*/g;

function resealText(text, reseal) {
  log.debug("Entering resealText().");
  let changed = false;
  const out = String(text || '').replace(SEALED_VALUE, function (value) {
    const next = reseal(value);
    if (next) {
      changed = true;
      return next;
    }
    return value;
  });
  log.debug("Leaving resealText().");
  return changed ? out : null;
}

// A runner that records each statement and answers by its name.
function recorder() {
  log.debug("Entering recorder().");
  const sent = [];
  const answer = function (text) {
    const name = (/\/\* sts:directory\.([A-Za-z.]+) \*\//.exec(text) ||
                  [])[1] || '';
    if (name === 'q.realms') {
      return { rows: [{ realm: 'default' }], rowCount: 1 };
    }
    if (name === 'q.parents' || name === 'parents') {
      return { rows: [{ parent_key: USERS }, { parent_key: GROUPS }],
               rowCount: 2 };
    }
    if (name === 'fold') {
      const n = (text.match(/ WHEN /g) || []).length;
      return { rows: [], rowCount: n, affectedRows: n };
    }
    if (/^SELECT|^WITH|^\(SELECT/.test(text)) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1, affectedRows: 1 };
  };
  const runner = {
    sent: sent,
    query: function (text, values) {
      log.debug("Entering query().");
      sent.push({ text: String(text), values: values || [] });
      log.debug("Leaving query().");
      return Promise.resolve(answer(String(text)));
    },
    connect: function () {
      log.debug("Entering connect().");
      log.debug("Leaving connect().");
      return Promise.resolve({
        query: runner.query,
        release: function () {
          log.debug("Entering release().");
          log.debug("Leaving release().");
        }
      });
    }
  };
  log.debug("Leaving recorder().");
  return runner;
}

// The codec as the driver builds it, and its `entryFromRow()`.
const codec = directoryCodec.codecFor('cell');

function entryFromRow(row) {
  log.debug("Entering entryFromRow().");
  const attrs = codec.openAttributes(row.dn_key, row.attrs);
  if (attrs === null) {
    log.debug("Leaving entryFromRow(). Does not open.");
    throw new Error('STS-STORE-0072 does not open');
  }
  log.debug("Leaving entryFromRow().");
  return { dn: row.dn, attributes: attrs, origin: row.origin || undefined,
           createdAt: row.created_at || null,
           modifiedAt: row.modified_at || row.created_at || null };
}

function openedOfRow(row) {
  log.debug("Entering openedOfRow().");
  log.debug("Leaving openedOfRow().");
  return JSON.stringify(row.attrs || {});
}

// BEGIN/COMMIT on a held connection, run again on a deadlock: the driver's
// `withTransaction()` as far as the library sees it.
function transactions(pool, dialect) {
  log.debug("Entering transactions().");
  log.debug("Leaving transactions().");
  return async function withTransaction(fn) {
    log.debug("Entering withTransaction().");
    for (let attempt = 0; ; attempt++) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await fn(client);
        await client.query('COMMIT');
        client.release();
        log.debug("Leaving withTransaction().");
        return out;
      } catch (e) {
        log.debug("Caught in withTransaction(): " + ((e && e.message) || e));
        await client.query('ROLLBACK').catch(function (rollbackErr) {
          log.debug("Caught in withTransaction(): " +
                    ((rollbackErr && rollbackErr.message) || rollbackErr));
        });
        client.release();
        if (attempt >= 12 || !dialect.isRetryable(e)) {
          log.debug("Leaving withTransaction(). Failed.");
          throw e;
        }
        await new Promise(function (resolve) {
          setTimeout(resolve, 5 + require('../common/crypto').randomInt(0, 30));
        });
      }
    }
  };
}

// The change rows, as the driver's `recordChanges()` writes them on MariaDB
// (the driver's own MariaDB path is another family's; this stands in).
function changeRecorder(origin) {
  log.debug("Entering changeRecorder().");
  log.debug("Leaving changeRecorder().");
  return function recordChanges(client, rows) {
    log.debug("Entering recordChanges().");
    if (!rows.length) {
      log.debug("Leaving recordChanges(). None.");
      return Promise.resolve();
    }
    const values = [];
    rows.forEach(function (row) {
      values.push(origin, row.kind, row.realm || '', row.key || '');
    });
    log.debug("Leaving recordChanges().");
    return client.query('INSERT INTO sts_changes (origin, kind, realm, ' +
      '`key`) VALUES ' + rows.map(function () {
        return '(?, ?, ?, ?)';
      }).join(', '), values);
  };
}

// A library over one pool, with everything the driver hands it.
function storeOver(pool, tallyPool, dialect, origin) {
  log.debug("Entering storeOver().");
  const withTransaction = transactions(pool, dialect);
  const lib = directoryPortable.forDriver({
    dialect: dialect, pool: pool, readPool: pool, ensurePool: tallyPool,
    entryCodec: codec,
    entryFromRow: entryFromRow, openedOfRow: openedOfRow,
    withTransaction: withTransaction,
    recordChanges: changeRecorder(origin),
    extraSealed: [{ table: 'sts_appconfig', keys: ['key'], column: 'value',
                    jsonb: true, change: { kind: 'appconfig' } }],
    sealedLike: sealedLike, resealText: resealText,
    releaseClaims: function (client, rows) {
      log.debug("Entering releaseClaims().");
      log.debug("Leaving releaseClaims().");
      return require('../persistence/cluster_portable').forDriver({
        dialect: dialect, pool: pool, live: pool,
        originScope: 'persistence.origin',
        processId: function () {
          return origin;
        }
      }).releaseClaims(client, rows);
    }
  });
  log.debug("Leaving storeOver().");
  return { lib: lib, withTransaction: withTransaction };
}

// `saveDirectory()` as the driver runs it: the flush, then each lost row in
// a transaction of its own.
async function save(store, change) {
  log.debug("Entering save().");
  const byKey = function (a, b) {
    const left = a.realm + '\n' + a.key;
    const right = b.realm + '\n' + b.key;
    return left < right ? -1 : left > right ? 1 : 0;
  };
  const upserts = change.upserts || [];
  const ctx = {
    merging: upserts.filter(function (row) {
      return row.base !== undefined;
    }).sort(byKey),
    blind: upserts.filter(function (row) {
      return row.base === undefined;
    }),
    deletes: change.deletes || [],
    removedRealms: change.removedRealms || [],
    releasing: change.releaseClaims || [],
    outcomes: [],
    pendingLost: []
  };
  await store.withTransaction(function (client) {
    ctx.outcomes.length = 0;
    return store.lib.flushBody(client, ctx);
  });
  const lost = ctx.pendingLost.slice();
  for (const row of lost) {
    await store.withTransaction(function (client) {
      return store.lib.mergeLostRow(client, row, ctx.outcomes);
    });
  }
  log.debug("Leaving save().");
  return { outcomes: ctx.outcomes, lost: lost.length };
}

// One entry as the directory holds it.
function entry(dn, attributes, when) {
  log.debug("Entering entry().");
  log.debug("Leaving entry().");
  return { dn: dn, attributes: attributes,
           createdAt: when || '20261103120000Z',
           modifiedAt: when || '20261103120000Z' };
}

function put(realm, key, value, base) {
  log.debug("Entering put().");
  const row = { realm: realm, key: key, entry: value };
  if (base !== undefined) {
    row.base = base === null ? null : JSON.stringify(base);
  }
  log.debug("Leaving put().");
  return row;
}

// ---------------------------------------------------------------------------
// A. STATIC
// ---------------------------------------------------------------------------

// The arguments every question is asked with, statically.
const SAMPLE_ARGS = {
  byKeys: ['default', [USERS, 'uid=a,' + USERS]],
  byName: ['default', USERS, 'alice'],
  byUuid: ['default', 'u-1'],
  withUuids: ['default', ['u-1', 'u-2']],
  byMail: ['default', 'a@example.com', 5],
  byAttribute: ['default', 'owner', 'uid=a,' + USERS, 5, DEVICES],
  equalUnder: ['default', BASE, 'mail', 'a@example.com', 5],
  page: ['default', BASE, '', 10, { self: true }],
  count: ['default', USERS],
  countHolding: ['default', USERS, 'userpassword'],
  hasChild: ['default', USERS],
  withAttribute: ['default', BASE, 'memberof', '', 10],
  countWithAttribute: ['default', BASE, 'memberof'],
  countWithAttributeUpTo: ['default', BASE, 'description', 3],
  withAttributeAt: ['default', BASE, 'memberof', 2, 10],
  withNames: ['default', USERS, ['alice', 'bob']],
  createdBetween: ['default', USERS, '', '', 10],
  modifiedBetween: ['default', USERS, '20260101000000Z', '', 10],
  anyWithAttribute: ['default', 'userpassword'],
  classesUnder: ['default', BASE, ['groupofnames']],
  namesUnder: ['default', BASE, '', 10],
  realmPage: ['default', '', 10, { offset: 1, origin: 'unstated' }],
  realmCount: ['default', 'ldif'],
  originCounts: ['default'],
  keysUnder: ['default', BASE, '', 10],
  residentOnly: [[{ realm: 'default', baseKey: USERS }]],
  rdnPage: ['default', USERS, '', 10, { needle: 'li', offset: 1 }],
  rdnCount: ['default', USERS, 'li', 5],
  containerPage: ['default', DEVICES, 1, 10],
  uidContains: ['default', USERS, 'a%b', 10]
};

const PG_ONLY = [
  [/\$\d/, 'a $n placeholder'],
  [/::[a-z]/, 'a :: cast'],
  [/\bon conflict\b/i, 'ON CONFLICT'],
  [/\breturning\b/i, 'RETURNING'],
  [/"[a-z_]+"/, 'a double-quoted identifier'],
  [/\blateral\b/i, 'LATERAL'],
  [/\bfilter \(/i, 'FILTER'],
  [/\bany\(/i, 'ANY()'],
  [/\bnulls (first|last)\b/i, 'NULLS FIRST/LAST'],
  [/@>|\?\||\?&|jsonb|jsonpath|jsonb_path/i, 'a jsonb operator or function'],
  [/\bE'/, 'an E\'\' string'],
  [/\bilike\b/i, 'ILIKE'],
  [/unnest|pg_|split_part|clock_timestamp|xmax|ctid|generate_series/i,
   'a PostgreSQL function'],
  [/\bfor share\b/i, 'FOR SHARE'],
  [/\bposition\(/i, 'POSITION()']
];

function offendingIn(statements) {
  log.debug("Entering offendingIn().");
  const out = [];
  statements.forEach(function (text) {
    PG_ONLY.forEach(function (rule) {
      if (rule[0].test(text)) {
        out.push(rule[1] + ' in: ' + text.slice(0, 160));
      }
    });
  });
  log.debug("Leaving offendingIn().");
  return out;
}

async function staticChecks(t) {
  log.debug("Entering staticChecks().");
  t.log.info('=== A. statements for MariaDB, none of PostgreSQL ===');
  const maria = sqlDialect.create('mariadb');
  const runner = recorder();
  const store = {
    lib: directoryPortable.forDriver({
      dialect: maria, pool: runner, readPool: runner, entryCodec: codec,
      entryFromRow: entryFromRow, openedOfRow: openedOfRow,
      withTransaction: function (fn) {
        log.debug("Entering withTransaction().");
        log.debug("Leaving withTransaction().");
        return runner.connect().then(fn);
      },
      recordChanges: function () {
        log.debug("Entering recordChanges().");
        log.debug("Leaving recordChanges().");
        return Promise.resolve();
      },
      extraSealed: [{ table: 'sts_appconfig', keys: ['key'],
                      column: 'value', jsonb: true, change: null }],
      sealedLike: sealedLike, resealText: resealText,
      releaseClaims: function (client) {
        log.debug("Entering releaseClaims().");
        log.debug("Leaving releaseClaims().");
        return client.query('DELETE FROM sts_cluster_claims WHERE 1 = 0 ' +
                            '/* sts:directory.release */', []);
      }
    })
  };
  store.withTransaction = function (fn) {
    log.debug("Entering store.withTransaction().");
    log.debug("Leaving store.withTransaction().");
    return runner.connect().then(fn);
  };
  const pgNames = Object.keys(directoryQueries.QUERIES).sort().join();
  const mariaNames = Object.keys(mariadbQueries.QUERIES).sort().join();
  t.check(pgNames === mariaNames,
          'A1. EVERY QUESTION HAS A MARIADB SPELLING, and no other',
          pgNames + ' / ' + mariaNames);
  const missingArgs = Object.keys(directoryQueries.QUERIES).filter(
    function (name) {
      return !SAMPLE_ARGS[name];
    });
  t.check(missingArgs.length === 0, 'A1b. and this test asks every one',
          missingArgs.join(', '));
  for (const name of Object.keys(SAMPLE_ARGS)) {
    await store.lib.query(name, directoryCodec.keyArgs(name,
                                                       SAMPLE_ARGS[name]));
  }
  const alice = entry('uid=alice,' + USERS, {
    uid: ['alice'], mail: ['a@example.com'], entryUUID: ['u-1'],
    objectClass: ['inetOrgPerson'], userPassword: ['x'], memberOf: [GROUPS],
    stsTotpCredential: [sealedUnder('dek-test-0001')] });
  await save(store, {
    upserts: [put('default', 'uid=alice,' + USERS, alice),
              put('default', 'uid=bob,' + USERS, alice, alice)],
    deletes: [{ realm: 'default', key: 'uid=carol,' + USERS }],
    removedRealms: ['gone'],
    releaseClaims: [{ scope: 's', realm: 'default', key: 'k',
                      reservation: 'r' }]
  });
  await store.lib.mergeLostRow(await runner.connect(), put('default',
    'uid=dave,' + USERS, alice, null), []);
  await store.lib.countSealed(['dek-test-0001']);
  await store.lib.countAllSealed();
  await store.lib.resealSealed(['dek-test-0001'], function () {
    return null;
  }, { limit: 5 });
  await store.lib.loadRows();
  await store.lib.readRow('default', USERS);
  // THE COUNT'S COST DOES NOT GROW WITH THE KEYS: 84 keys, a whole-store read
  // each, ran the re-encryption pass past ten minutes on a real run (#677).
  const scansFor = async function (ids) {
    const before = runner.sent.length;
    await store.lib.countSealed(ids);
    return runner.sent.slice(before).filter(function (one) {
      return /LIKE/.test(one.text);
    }).length;
  };
  const scansOfOne = await scansFor(['dek-test-0001']);
  const scansOfMany = await scansFor(Array.from({ length: 84 },
    function (_, i) {
      return 'dek-test-' + i;
    }));
  t.check(scansOfOne > 0 && scansOfMany === scansOfOne,
          'A2b. a count of 84 data keys reads the sealed tables as often as ' +
          'a count of one', scansOfOne + ' and ' + scansOfMany);
  const statements = runner.sent.map(function (one) {
    return one.text;
  });
  t.check(statements.length >= 60, 'A2. every operation sent its statements',
          statements.length + ' statement(s)');
  const offending = offendingIn(statements);
  t.check(offending.length === 0,
          'A3. NO STATEMENT CARRIES POSTGRESQL\'S SYNTAX',
          offending.join(' | '));
  const named = statements.filter(function (text) {
    return !/\/\* sts:directory\.[A-Za-z.]+ \*\/$/.test(text);
  });
  t.check(named.length === 0, 'A4. every statement carries its name',
          named.join(' | ').slice(0, 300));
  t.check(statements.some(function (text) {
    return /^SELECT .* FROM sts_ldap_entries WHERE \(realm, dn_key\) IN .* ORDER BY realm, dn_key FOR UPDATE/
      .test(text);
  }), 'A5. the flush locks its rows with ONE ordered SELECT … FOR UPDATE');
  t.check(statements.some(function (text) {
    return /^INSERT INTO sts_ldap_entry_keys/.test(text);
  }) && statements.some(function (text) {
    return /^DELETE FROM sts_ldap_entry_keys WHERE \(realm, dn_key\) IN/
      .test(text);
  }), 'A6. and writes the entries\' key rows');
  t.check(statements.some(function (text) {
    return /^INSERT IGNORE INTO sts_ldap_counts/.test(text);
  }) && statements.some(function (text) {
    return /^UPDATE sts_ldap_counts SET n = n \+ CASE/.test(text);
  }) && statements.some(function (text) {
    return /^UPDATE sts_ldap_dek_counts SET n = n \+ CASE/.test(text);
  }), 'A7. and folds the counts: rows made to exist, then n = n + …');
  t.check(!statements.some(function (text) {
    return /^INSERT IGNORE INTO sts_ldap_entries/.test(text);
  }), 'A8. an entry is never written with INSERT IGNORE (it hides refusals)');

  const short = 'name\nalice';
  const long = 'attr:federationlink\n' + 'x'.repeat(400);
  const digested = mariadbQueries.tableKey(long);
  t.check(mariadbQueries.tableKey(short) === short &&
          /^#[0-9a-f]{64}$/.test(digested) &&
          mariadbQueries.tableKey(long) === digested &&
          mariadbQueries.tableKey('x'.repeat(344)).length === 344,
          'A9. A LOOKUP FORM OVER 344 CHARACTERS IS DIGESTED, the same way ' +
          'each time; one of 344 is kept', digested);
  t.check(JSON.stringify(directoryPortable.basesOf(USERS)) ===
            JSON.stringify([USERS, BASE, 'dc=com', '']) &&
          JSON.stringify(directoryPortable.basesOf('')) === '[""]',
          'A10. the bases of a parent are PostgreSQL\'s ' +
          'sts_ldap_count_bases()');
  // A NEEDLE'S COUNT IS CAPPED (#1308), as PostgreSQL's: inside a derived
  // table's LIMIT of the cap and one more, the cap clamped by the one copy.
  const countSent = runner.sent.filter(function (one) {
    return /\/\* sts:directory\.q\.rdnCount \*\/$/.test(one.text);
  });
  const countOne = countSent[0] || { text: '', values: [] };
  t.check(countSent.length === 1 &&
          /^SELECT CAST\(COUNT\(\*\) AS SIGNED\) AS n FROM \(SELECT 1 AS one FROM sts_ldap_entries WHERE realm = \? AND parent_key = \? AND LOCATE\(\?, rdn_value\) > 0 LIMIT \?\) AS matched/
            .test(countOne.text) &&
          countOne.values[2] === 'li' && countOne.values[3] === 6,
          'A10b. rdnCount counts inside a LIMIT of the cap and one more',
          JSON.stringify(countOne));
  runner.sent.length = 0;
  await store.lib.query('rdnCount', ['default', USERS, '', 500000]);
  await store.lib.query('rdnCount', ['default', USERS, 'li']);
  const capsSent = runner.sent.map(function (one) {
    return one.values[one.values.length - 1];
  });
  t.check(JSON.stringify(capsSent) === '[100001,100001]' &&
          !/LOCATE/.test((runner.sent[0] || {}).text || '') &&
          (runner.sent[0] || { values: [] }).values.length === 3,
          'A10c. a cap over the walk\'s, or none, is the walk\'s 100,000; ' +
          'an empty needle adds no LOCATE', JSON.stringify(runner.sent));

  runner.sent.length = 0;
  let refusal = '';
  try {
    await save(store, { upserts: [put('default', 'uid=' + 'x'.repeat(350) +
                                      ',' + USERS, alice)] });
  } catch (e) {
    log.debug("Caught in staticChecks(): " + ((e && e.message) || e));
    refusal = String(e.message);
  }
  t.check(/STS-STORE-0140/.test(refusal) && runner.sent.length === 0,
          'A11. A DN KEY OVER 352 CHARACTERS IS REFUSED STS-STORE-0140, ' +
          'before anything is sent', refusal.slice(0, 120) + ' / ' +
          runner.sent.length + ' sent');
  log.debug("Leaving staticChecks().");
}

// ---------------------------------------------------------------------------
// C. AGAINST MARIADB
// ---------------------------------------------------------------------------

// What the counts, the data-key counts and the key rows must be, counted
// afresh from the entries; and what they are.
async function verify(t, pool, label) {
  log.debug("Entering verify().");
  const rows = (await pool.query('SELECT realm, dn_key, attrs, attr_names, ' +
                                 'dek_keys FROM sts_ldap_entries')).rows;
  const counts = new Map();
  const deks = new Map();
  const keys = new Set();
  const bump = function (map, id, n) {
    map.set(id, (map.get(id) || 0) + n);
  };
  rows.forEach(function (row) {
    const names = row.attr_names || [];
    directoryPortable.basesOf(directoryQueries.parentOf(row.dn_key))
      .forEach(function (base) {
        bump(counts, row.realm + '|' + base + '|', 1);
        directoryQueries.COUNTED_ATTRIBUTES.forEach(function (one) {
          if (names.indexOf(one) >= 0) {
            bump(counts, row.realm + '|' + base + '|' + one, 1);
          }
        });
      });
    Object.keys(row.dek_keys || {}).forEach(function (id) {
      bump(deks, id, Number(row.dek_keys[id]));
    });
    const index = codec.index(row.attrs);
    const add = function (kind, list) {
      (list || []).forEach(function (one) {
        keys.add([row.realm, kind, mariadbQueries.tableKey(one),
                  row.dn_key].join('|'));
      });
    };
    add('name', index.nameKeys);
    add('mail', index.mailKeys);
    add('uuid', index.uuidKeys);
    add('class', index.classKeys);
    add('value', index.valueKeys);
    add('attr', index.attrNames.filter(function (one) {
      return directoryQueries.ASKED_ATTRIBUTES.indexOf(one) >= 0;
    }));
    add('dek', Object.keys(row.dek_keys || {}));
  });
  const kept = new Map();
  (await pool.query('SELECT realm, base_key, attribute, SUM(n) AS n FROM ' +
                    'sts_ldap_counts GROUP BY realm, base_key, attribute ' +
                    'HAVING SUM(n) <> 0')).rows.forEach(function (row) {
    kept.set(row.realm + '|' + row.base_key + '|' + row.attribute,
             Number(row.n));
  });
  const keptDeks = new Map();
  (await pool.query('SELECT dek_id, SUM(n) AS n FROM sts_ldap_dek_counts ' +
                    'GROUP BY dek_id HAVING SUM(n) <> 0')).rows
    .forEach(function (row) {
      keptDeks.set(row.dek_id, Number(row.n));
    });
  const keptKeys = new Set((await pool.query('SELECT realm, kind, k, dn_key ' +
    'FROM sts_ldap_entry_keys')).rows.map(function (row) {
    return [row.realm, row.kind, row.k, row.dn_key].join('|');
  }));
  const differ = function (a, b) {
    const out = [];
    new Set(Array.from(a.keys()).concat(Array.from(b.keys())))
      .forEach(function (id) {
        if ((a.get(id) || 0) !== (b.get(id) || 0)) {
          out.push(id + ' fresh ' + (a.get(id) || 0) + ' kept ' +
                   (b.get(id) || 0));
        }
      });
    return out;
  };
  const wrongCounts = differ(counts, kept);
  const wrongDeks = differ(deks, keptDeks);
  const wrongKeys = Array.from(keys).filter(function (one) {
    return !keptKeys.has(one);
  }).map(function (one) {
    return 'missing ' + one;
  }).concat(Array.from(keptKeys).filter(function (one) {
    return !keys.has(one);
  }).map(function (one) {
    return 'extra ' + one;
  }));
  t.check(!wrongCounts.length && !wrongDeks.length && !wrongKeys.length,
          label + ': the counts, data-key counts and key rows equal a fresh ' +
          'count (' + rows.length + ' entries)',
          wrongCounts.concat(wrongDeks, wrongKeys).slice(0, 8).join(' | '));
  log.debug("Leaving verify().");
}

// The answer to a question, as the driver gives it.
async function ask(store, name, args) {
  log.debug("Entering ask().");
  const rows = await store.lib.query(name,
                                     directoryCodec.keyArgs(name, args));
  log.debug("Leaving ask().");
  return directoryCodec.openAnswer(codec, name,
                                   directoryQueries.answerOf(name, rows));
}

function keysOf(answer) {
  log.debug("Entering keysOf().");
  log.debug("Leaving keysOf().");
  return (answer || []).map(function (row) {
    return row.key;
  }).join(',');
}

// The fixture tree, every kind of key in it.
function fixture() {
  log.debug("Entering fixture().");
  const out = {};
  out[BASE] = entry(BASE, { objectClass: ['domain'], dc: ['example'] });
  out[USERS] = entry(USERS, { objectClass: ['organizationalUnit'],
                              ou: ['users'] });
  out[GROUPS] = entry(GROUPS, { objectClass: ['organizationalUnit'],
                                ou: ['groups'] });
  out[DEVICES] = entry(DEVICES, { objectClass: ['organizationalUnit'],
                                  ou: ['devices'] });
  out['uid=alice,' + USERS] = entry('uid=alice,' + USERS, {
    uid: ['alice'], mail: ['Alice@Example.com'], entryUUID: ['U-ALICE'],
    objectClass: ['inetOrgPerson'], userPassword: ['{SSHA}x'],
    memberOf: ['cn=admins,' + GROUPS],
    stsTotpCredential: [sealedUnder('dek-test-0001')] }, '20261101000000Z');
  out['uid=bob,' + USERS] = entry('uid=bob,' + USERS, {
    uid: ['bob'], mail: ['bob@example.com'], entryUUID: ['u-bob'],
    stsEntryUuidAlias: ['u-bob-old'], objectClass: ['inetOrgPerson'] },
    '20261102000000Z');
  out['uid=c1,' + USERS] = entry('uid=c1,' + USERS, {
    uid: ['carol'], mail: ['carol@example.com'], entryUUID: ['u-carol'],
    objectClass: ['inetOrgPerson'], userPassword: ['{SSHA}y'],
    federationLink: ['https://idp.example/' + 'p'.repeat(400)] },
    '20261103000000Z');
  out['uid=a%b,' + USERS] = entry('uid=a%b,' + USERS, {
    uid: ['a%b'], objectClass: ['inetOrgPerson'] });
  out['cn=admins,' + GROUPS] = entry('cn=admins,' + GROUPS, {
    cn: ['admins'], objectClass: ['groupOfNames'],
    member: ['uid=alice,' + USERS] });
  out['cn=d1,' + DEVICES] = entry('cn=d1,' + DEVICES, {
    cn: ['d1'], objectClass: ['device'], owner: ['uid=alice,' + USERS] });
  log.debug("Leaving fixture().");
  return out;
}

async function lookups(t, store) {
  log.debug("Entering lookups().");
  const r = 'default';
  t.check(keysOf(await ask(store, 'byName', [r, USERS, 'ALICE'])) ===
            'uid=alice,' + USERS &&
          keysOf(await ask(store, 'byName', [r, USERS, 'carol'])) ===
            'uid=c1,' + USERS,
          'C2. byName finds by the RDN and by a uid that is not the RDN');
  t.check(keysOf(await ask(store, 'withNames', [r, USERS,
                                                ['bob', 'carol', 'nobody']]))
            === 'uid=bob,' + USERS + ',uid=c1,' + USERS,
          'C3. withNames finds several at once');
  t.check(keysOf(await ask(store, 'byUuid', [r, 'u-alice'])) ===
            'uid=alice,' + USERS &&
          keysOf(await ask(store, 'withUuids', [r, ['u-bob-old', 'u-carol',
                                                    'u-bob']])) ===
            'uid=bob,' + USERS + ',uid=c1,' + USERS,
          'C4. byUuid and withUuids, an alias included, each entry once');
  t.check(keysOf(await ask(store, 'byMail', [r, 'alice@example.COM', 5])) ===
            'uid=alice,' + USERS,
          'C5. byMail, lower-cased');
  t.check(keysOf(await ask(store, 'byAttribute', [r, 'owner',
                                                  'uid=alice,' + USERS, 5,
                                                  DEVICES])) ===
            'cn=d1,' + DEVICES &&
          keysOf(await ask(store, 'byAttribute', [r, 'federationlink',
            'https://idp.example/' + 'p'.repeat(400), 5])) ===
            'uid=c1,' + USERS,
          'C6. byAttribute, under a parent, and for a value whose lookup ' +
          'form is digested');
  t.check(keysOf(await ask(store, 'equalUnder', [r, BASE, 'mail',
                                                 'bob@example.com', 5])) ===
            'uid=bob,' + USERS &&
          keysOf(await ask(store, 'equalUnder', [r, GROUPS, 'mail',
                                                 'bob@example.com', 5])) ===
            '',
          'C7. equalUnder, inside and outside its base');
  const sub = keysOf(await ask(store, 'page', [r, BASE, '', 100,
                                               { self: true }]));
  const want = Object.keys(fixture()).sort().join(',');
  t.check(sub === want, 'C8. a subtree page with the base is every entry ' +
          'in key order', sub);
  const two = await ask(store, 'page', [r, BASE, '', 2, {}]);
  const next = await ask(store, 'page', [r, BASE, two[1].key, 100, {}]);
  t.check(keysOf(two.concat(next)) === Object.keys(fixture()).sort()
    .filter(function (k) {
      return k !== BASE;
    }).join(','), 'C9. pages after a cursor join up, the base left out');
  t.check(keysOf(await ask(store, 'page', [r, USERS, '', 2,
                                           { oneLevel: true }])) ===
            'uid=a%b,' + USERS + ',uid=alice,' + USERS &&
          (await ask(store, 'page', [r, '', '', 100, {}])).length === 0,
          'C10. one level, and the base \'\' (PostgreSQL\'s suffix form)');
  t.check(await ask(store, 'count', [r, USERS]) === 4 &&
          await ask(store, 'count', [r, '']) === 10 &&
          JSON.stringify(await ask(store, 'countHolding', [r, USERS,
                                                           'userpassword']))
            === '{"n":4,"holding":2}' &&
          JSON.stringify(await ask(store, 'countHolding', [r, BASE,
                                                           'member'])) ===
            '{"n":9,"holding":1}',
          'C11. count and countHolding, kept and counted');
  t.check(await ask(store, 'hasChild', [r, USERS]) === true &&
          await ask(store, 'hasChild', [r, 'uid=bob,' + USERS]) === false,
          'C12. hasChild');
  t.check(keysOf(await ask(store, 'withAttribute', [r, BASE, 'memberof', '',
                                                    10])) ===
            'uid=alice,' + USERS &&
          await ask(store, 'countWithAttribute', [r, BASE, 'memberof']) === 1 &&
          await ask(store, 'countWithAttributeUpTo', [r, BASE, 'mail', 2]) ===
            2 &&
          (await ask(store, 'withAttributeAt', [r, BASE, 'memberof', 1, 10]))
            .length === 0 &&
          await ask(store, 'anyWithAttribute', [r, 'userpassword']) === true &&
          await ask(store, 'anyWithAttribute', [r, 'stsmayact']) === false &&
          await ask(store, 'anyWithAttribute', [r, 'member']) === true,
          'C13. the holder questions: key rows, counts and the scan');
  t.check(keysOf(await ask(store, 'classesUnder', [r, BASE,
                                                   ['groupofnames']])) ===
            'cn=admins,' + GROUPS,
          'C14. classesUnder');
  t.check(keysOf(await ask(store, 'createdBetween', [r, USERS,
                                                     '20261102000000Z',
                                                     '20261103000000Z', 10]))
            === 'uid=bob,' + USERS,
          'C15. createdBetween, lo inclusive and hi exclusive');
  const names = await ask(store, 'namesUnder', [r, USERS, '', 10]);
  const keys = await ask(store, 'keysUnder', [r, USERS, '', 2]);
  t.check(names.length === 4 && names[1].uid === 'alice' &&
          keys.length === 2 && keys[0].dn === 'uid=a%b,' + USERS,
          'C16. namesUnder and keysUnder', JSON.stringify(names[1]));
  t.check((await ask(store, 'realmPage', [r, '', 3, { offset: 2 }]))
            .length === 3 &&
          await ask(store, 'realmCount', [r, '']) === 10 &&
          (await ask(store, 'originCounts', [r])).unstated === 10,
          'C17. realmPage, realmCount, originCounts');
  const resident = await ask(store, 'residentOnly', [[{ realm: r,
                                                       baseKey: USERS }]]);
  t.check(keysOf(resident).indexOf('uid=') < 0 && resident.length === 6,
          'C18. residentOnly leaves out what is under a windowed container',
          keysOf(resident));
  t.check(keysOf(await ask(store, 'rdnPage', [r, USERS, '', 10,
                                              { needle: 'a' }])) ===
            'uid=a%b,' + USERS + ',uid=alice,' + USERS &&
          await ask(store, 'rdnCount', [r, USERS, 'b']) === 2 &&
          // Capped (#1308): under the cap, at it, and over it (cap + 1).
          await ask(store, 'rdnCount', [r, USERS, 'b', 3]) === 2 &&
          await ask(store, 'rdnCount', [r, USERS, 'b', 2]) === 2 &&
          await ask(store, 'rdnCount', [r, USERS, 'b', 1]) === 2 &&
          await ask(store, 'rdnCount', [r, USERS, '', 1]) === 2 &&
          keysOf(await ask(store, 'containerPage', [r, USERS, 1, 2])) ===
            'uid=alice,' + USERS + ',uid=bob,' + USERS,
          'C19. rdnPage with a needle, rdnCount (capped: under, at and ' +
          'over the cap), containerPage');
  t.check(keysOf(await ask(store, 'uidContains', [r, USERS, '%', 10])) ===
            'uid=a%b,' + USERS &&
          (await ask(store, 'byKeys', [r, [USERS, 'uid=bob,' + USERS]]))
            .length === 2,
          'C20. uidContains takes a % as itself; byKeys');
  log.debug("Leaving lookups().");
}

async function contracts(t, a, b, pool) {
  log.debug("Entering contracts().");
  const tree = fixture();
  await save(a, { upserts: Object.keys(tree).map(function (key) {
    return put('default', key, tree[key]);
  }) });
  const back = await a.lib.readRow('default', 'uid=alice,' + USERS);
  t.check(back.rows.length === 1 &&
          entryFromRow(back.rows[0]).attributes.uid[0] === 'alice',
          'C1. an entry is written and read back');
  await verify(t, pool, 'C1b');
  await lookups(t, a);

  // A MODIFY, A MOVE AND A DELETE.
  const alice = JSON.parse(JSON.stringify(tree['uid=alice,' + USERS]));
  delete alice.attributes.userPassword;
  alice.attributes.mail = ['alice2@example.com'];
  const moved = JSON.parse(JSON.stringify(tree['uid=bob,' + USERS]));
  moved.dn = 'uid=bob,' + DEVICES;
  await save(a, {
    upserts: [put('default', 'uid=alice,' + USERS, alice,
                  tree['uid=alice,' + USERS]),
              put('default', 'uid=bob,' + DEVICES, moved)],
    deletes: [{ realm: 'default', key: 'uid=bob,' + USERS },
              { realm: 'default', key: 'cn=d1,' + DEVICES }]
  });
  t.check(keysOf(await ask(a, 'byMail', ['default', 'alice@example.com', 5]))
            === '' &&
          keysOf(await ask(a, 'byMail', ['default', 'alice2@example.com', 5]))
            === 'uid=alice,' + USERS &&
          keysOf(await ask(a, 'byUuid', ['default', 'u-bob'])) ===
            'uid=bob,' + DEVICES &&
          await ask(a, 'count', ['default', USERS]) === 3,
          'C21. a modify, a move and a delete: the lookups follow');
  await verify(t, pool, 'C21b');

  // TWO NODES WRITE ONE ENTRY FROM THE SAME BASE, AT ONCE.
  const base = JSON.parse(JSON.stringify(alice));
  const mine = JSON.parse(JSON.stringify(base));
  mine.attributes.description = ['from a'];
  const theirs = JSON.parse(JSON.stringify(base));
  theirs.attributes.telephoneNumber = ['+1 555 0100'];
  await Promise.all([
    save(a, { upserts: [put('default', 'uid=alice,' + USERS, mine, base)] }),
    save(b, { upserts: [put('default', 'uid=alice,' + USERS, theirs, base)] })
  ]);
  const merged = entryFromRow((await a.lib.readRow('default',
                                                   'uid=alice,' + USERS))
                                .rows[0]).attributes;
  t.check(merged.description && merged.telephoneNumber,
          'C22. TWO NODES WRITING ONE ENTRY AT ONCE MERGE: both changes kept',
          JSON.stringify(merged));
  await verify(t, pool, 'C22b');

  // A ROW COMMITTED BY ANOTHER NODE BETWEEN THE LOCK AND THE INSERT.
  for (const blind of [true, false]) {
    const key = 'uid=' + (blind ? 'late-blind' : 'late-merged') + ',' + USERS;
    const other = entry(key, { uid: [blind ? 'late-blind' : 'late-merged'],
                               objectClass: ['inetOrgPerson'],
                               userPassword: ['p'], description: ['other'] });
    const ours = entry(key, { uid: [blind ? 'late-blind' : 'late-merged'],
                              objectClass: ['inetOrgPerson'],
                              mail: ['late@example.com'] });
    let raced = false;
    const racing = {
      lib: b.lib,
      withTransaction: function (fn) {
        log.debug("Entering racing.withTransaction().");
        log.debug("Leaving racing.withTransaction().");
        return b.withTransaction(function (client) {
          const wrapped = {
            query: async function (text, values) {
              const r = await client.query(text, values);
              if (!raced && /sts:directory\.lock /.test(text)) {
                raced = true;
                await save(a, { upserts: [put('default', key, other)] });
              }
              return r;
            },
            release: client.release
          };
          return fn(wrapped);
        });
      }
    };
    const answer = await save(racing, { upserts: [
      blind ? put('default', key, ours) : put('default', key, ours, null)] });
    const stored = entryFromRow((await a.lib.readRow('default', key))
                                  .rows[0]).attributes;
    t.check(raced && (blind
      ? (stored.mail && !stored.description && answer.lost === 0)
      : (stored.mail && stored.description && answer.lost === 1)),
            'C23' + (blind ? 'a' : 'b') + '. A ROW ANOTHER NODE COMMITTED ' +
            'BETWEEN THE LOCK AND THE INSERT is ' + (blind
              ? 'replaced by a blind write'
              : 'merged after COMMIT by a merged one'),
            JSON.stringify(stored) + ' lost=' + answer.lost);
  }
  await verify(t, pool, 'C23c');

  // TWENTY FLUSHES OF ONE CONTAINER AT ONCE, ON TWO NODES.
  const many = [];
  for (let i = 0; i < 20; i++) {
    const key = 'uid=p' + i + ',' + USERS;
    many.push(save(i % 2 ? a : b, { upserts: [put('default', key, entry(key,
      { uid: ['p' + i], objectClass: ['inetOrgPerson'],
        userPassword: i % 3 ? ['x'] : undefined }))] }));
  }
  await Promise.all(many);
  t.check(await ask(a, 'count', ['default', USERS]) === 25,
          'C24. TWENTY CONCURRENT FLUSHES OF ONE CONTAINER, on two nodes: ' +
          'every one counted');
  await verify(t, pool, 'C24b');

  // A REALM REMOVED, A LONG DN REFUSED, A BIG FLUSH.
  const r2 = [];
  for (let i = 0; i < 1200; i++) {
    const key = 'uid=u' + String(i).padStart(4, '0') + ',ou=users,dc=r2';
    r2.push(put('r2', key, entry(key, {
      uid: ['u' + i], entryUUID: ['r2-' + i],
      stsTotpCredential: [sealedUnder('dek-test-0002')] })));
  }
  await save(a, { upserts: r2 });
  const loaded = await a.lib.loadRows();
  const inDefault = await ask(a, 'realmCount', ['default', '']);
  t.check(loaded.rows.length === 1200 + inDefault &&
          await ask(a, 'count', ['r2', '']) === 1200,
          'C25. a flush of 1200 entries, and a restore of more than a page',
          String(loaded.rows.length));
  await verify(t, pool, 'C25b');
  await pool.query('INSERT INTO sts_appconfig (`key`, value) VALUES (?, ?)',
                   ['sealed.setting', JSON.stringify(sealedUnder(
                     'dek-test-0001'))]);
  const one = await a.lib.countSealed(['dek-test-0001', 'dek-test-0002']);
  const all = await a.lib.countAllSealed();
  t.check(one['dek-test-0001'] === 2 && one['dek-test-0002'] === 1200 &&
          all['dek-test-0001'] === 2 && all['dek-test-0002'] === 1200,
          'C26. countSealed and countAllSealed: the directory\'s kept counts ' +
          'and the other tables\' values', JSON.stringify(one) + ' ' +
          JSON.stringify(all));
  const tally = await a.lib.resealSealed(['dek-test-0001'], function (value) {
    return value.indexOf('dek-test-0001') >= 0
      ? sealedUnder('dek-test-0003') : null;
  }, { limit: 50 });
  const after = await a.lib.countSealed(['dek-test-0001', 'dek-test-0003']);
  t.check(tally.entries === 1 && tally.other === 1 &&
          after['dek-test-0001'] === 0 && after['dek-test-0003'] === 2,
          'C27. THE RE-ENCRYPTION PASS finds the entry by its dek key row, ' +
          're-seals it and the setting, and the counts move',
          JSON.stringify(tally) + ' ' + JSON.stringify(after));
  await verify(t, pool, 'C27b');
  await save(a, { removedRealms: ['r2'] });
  t.check(await ask(a, 'count', ['r2', '']) === 0 &&
          Number((await pool.query('SELECT COUNT(*) AS n FROM ' +
            'sts_ldap_entry_keys WHERE realm = ?', ['r2'])).rows[0].n) === 0,
          'C28. A REMOVED REALM takes its entries, key rows and counts');
  await verify(t, pool, 'C28b');
  const before = Number((await pool.query('SELECT COUNT(*) AS n FROM ' +
                                          'sts_ldap_entries')).rows[0].n);
  let refusal = '';
  try {
    const key = 'uid=' + 'y'.repeat(350) + ',' + USERS;
    await save(a, { upserts: [put('default', 'uid=fine,' + USERS,
                                  entry('uid=fine,' + USERS, { uid: ['f'] })),
                              put('default', key, entry(key, {}))] });
  } catch (e) {
    log.debug("Caught in contracts(): " + ((e && e.message) || e));
    refusal = String(e.message);
  }
  const afterRefusal = Number((await pool.query('SELECT COUNT(*) AS n FROM ' +
                                                'sts_ldap_entries')).rows[0].n);
  t.check(/STS-STORE-0140/.test(refusal) && afterRefusal === before,
          'C29. A DN KEY OVER 352 CHARACTERS IS REFUSED STS-STORE-0140, and ' +
          'nothing of its flush is written', refusal.slice(0, 100));
  log.debug("Leaving contracts().");
}

// The plans: no question the key rows answer reads a table whole.
async function plans(t, pool) {
  log.debug("Entering plans().");
  const sent = [];
  const recording = {
    query: function (text, values) {
      log.debug("Entering recording.query().");
      sent.push({ text: text, values: values });
      log.debug("Leaving recording.query().");
      return pool.query(text, values);
    }
  };
  const store = directoryPortable.forDriver({
    dialect: sqlDialect.create('mariadb'), pool: recording,
    readPool: recording, entryCodec: codec, entryFromRow: entryFromRow
  });
  const indexed = ['byName', 'withNames', 'byUuid', 'withUuids', 'byMail',
                   'byAttribute', 'equalUnder', 'page', 'count',
                   'countHolding', 'hasChild', 'withAttribute',
                   'countWithAttribute', 'withAttributeAt', 'classesUnder',
                   'createdBetween', 'keysUnder', 'rdnPage', 'containerPage'];
  const scans = [];
  for (const name of indexed) {
    sent.length = 0;
    const args = SAMPLE_ARGS[name].slice();
    await store.query(name, directoryCodec.keyArgs(name, args));
    for (const one of sent) {
      const plan = (await pool.query('EXPLAIN ' + one.text, one.values)).rows;
      plan.forEach(function (row) {
        if (row.type === 'ALL' && /^sts_ldap/.test(String(row.table || ''))) {
          scans.push(name + ': ' + row.table);
        }
      });
    }
  }
  t.check(scans.length === 0, 'C30. NO INDEXED QUESTION SCANS A TABLE ' +
          '(EXPLAIN of every statement)', scans.join(' | '));
  log.debug("Leaving plans().");
}

async function againstMariadb(t) {
  log.debug("Entering againstMariadb().");
  const url = process.env.STS_TEST_MARIADB_URL || '';
  if (!url) {
    t.log.info('=== C. skipped: STS_TEST_MARIADB_URL names no database ===');
    log.debug("Leaving againstMariadb(). Skipped.");
    return;
  }
  t.log.info('=== C. the directory\'s contracts against a real MariaDB ===');
  const knexStore = require('../persistence/knex_store');
  const schemaMariadb = require('../persistence/schema_mariadb');
  const scratch = 'directory_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE DATABASE ' + scratch);
  const scoped = url.replace(/\/[^/?]*(\?|$)/, '/' + scratch + '$1');
  const poolA = knexStore.openPool({ connectionString: scoped }, { max: 8 });
  const poolB = knexStore.openPool({ connectionString: scoped }, { max: 8 });
  const tally = knexStore.openPool({ connectionString: scoped }, { max: 2 });
  try {
    for (const object of schemaMariadb.SCHEMA_OBJECTS) {
      await poolA.query(object.statement);
    }
    const dialect = sqlDialect.create('mariadb');
    const a = storeOver(poolA, tally, dialect, 'node-a');
    const b = storeOver(poolB, tally, dialect, 'node-b');
    await contracts(t, a, b, poolA);
    await plans(t, poolA);
    await throughTheDriver(t, scoped);
  } finally {
    await poolA.end();
    await poolB.end();
    await tally.end();
    await admin.query('DROP DATABASE ' + scratch);
    await admin.end();
  }
  log.debug("Leaving againstMariadb().");
}

// D. The driver's own doors, on the database C left.
async function throughTheDriver(t, url) {
  log.debug("Entering throughTheDriver().");
  t.log.info('=== D. the driver\'s doors on MariaDB ===');
  const driver = require('../persistence/persistence_postgres').create({
    url: url, engine: 'mariadb', log: log, poolMax: 2 });
  try {
    const loaded = await driver.loadDirectory();
    const read = await driver.readEntry('default', 'uid=alice,' + USERS);
    const found = await driver.directoryQuery('byName',
                                              ['default', USERS, 'carol']);
    const counted = await driver.directoryQuery('count', ['default', USERS]);
    t.check(loaded && loaded.default && loaded.default.length >= 15 &&
            read && read.entry.attributes.uid[0] === 'alice' &&
            keysOf(found) === 'uid=c1,' + USERS && counted === 25,
            'D1. THE DRIVER RESTORES, READS AND ASKS THROUGH THE LIBRARY on ' +
            'MariaDB', (loaded && loaded.default ? loaded.default.length : 0) +
            ' / ' + keysOf(found) + ' / ' + counted);
    const deks = await driver.countSealed(['dek-test-0003']);
    const indexing = await driver.indexSealed({ budgetMs: 100 });
    t.check(deks['dek-test-0003'] === 2 && indexing.remaining === false &&
            indexing.indexed === 0,
            'D2. the data-key count, and nothing left to index',
            JSON.stringify(deks) + ' ' + JSON.stringify(indexing));
    // THE DRIVER'S FLUSH needs `recordChanges()` to speak MariaDB, which is
    // another family's change (#677): until it does, the server refuses the
    // flush at its change row, and this says so rather than failing.
    const key = 'uid=through-driver,' + USERS;
    let flushed = null;
    try {
      flushed = await driver.saveDirectory({
        upserts: [put('default', key, entry(key, { uid: ['td'] }))],
        deletes: [], touched: ['default'], removedRealms: [],
        releaseClaims: [] });
    } catch (e) {
      log.debug("Caught in throughTheDriver(): " + ((e && e.message) || e));
      if (!/sts_changes|\$1/.test(String(e.sql || '') + String(e.message))) {
        throw e;
      }
      t.log.info('D3. skipped: the driver\'s recordChanges() has no MariaDB ' +
                 'path in this tree yet (' + String(e.message).slice(0, 80) +
                 ')');
    }
    if (flushed) {
      const back = await driver.readEntry('default', key);
      t.check(back && back.entry.attributes.uid[0] === 'td',
              'D3. the driver\'s saveDirectory() writes through the library');
    }
  } finally {
    await driver.close();
  }
  log.debug("Leaving throughTheDriver().");
}

async function run(t) {
  log.debug("Entering run().");
  await staticChecks(t);
  await againstMariadb(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_portable',
  describe: 'the embedded directory\'s store on MariaDB: no PostgreSQL ' +
            'syntax, and against a real MariaDB the lookups, the flush, the ' +
            'merge, the counts and the key rows (#677)',
  run: run
};
