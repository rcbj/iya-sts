// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: granting_index_backfill.js
//
// ===========================================================================
// THE `grantinggroup` KEYS OF ENTRIES WRITTEN BEFORE #1306, ONCE (#1311):
// `persistence/granting_index_backfill.js` and its statements in the
// PostgreSQL driver and the MariaDB directory library.
//
// Each engine's statements run against a double that KEEPS a small table —
// `sts_ldap_entries` (and on MariaDB `sts_ldap_entry_keys`) and the
// `sts_minted_index` rows the walk keeps — so what is asserted is what the
// store would answer, through the same `directoryQuery('byAttribute')` /
// `query('byAttribute')` federated provisioning asks (#1306):
//
//   P. POSTGRESQL. An entry written WITHOUT the key (a role's
//      `roleMemberGroup`, a service account's `stsServiceAccountOwner` as a
//      DN in another case and spacing — the pre-#1306 row) is not found by
//      the store question before the walk and is found after; a run stopped
//      by its ownership leaves a cursor and the next resumes after it,
//      reading no page twice; the mark is written and the cursor removed;
//      a second run reads the mark and nothing else; only the rows naming a
//      granting attribute have their attributes handed back, and only the
//      rows whose keys differ are written; a writer that changed an entry
//      between the read and the write wins (compare-and-set); a run that
//      fails mid-walk resumes from the last page it finished; a store
//      holding no granting entry finishes at once.
//   M. MARIADB. The same over the library's statements: the `value` key rows
//      of a legacy entry are replaced (its `uid` key kept, its new
//      `grantinggroup` keys added), the store question finds it after and
//      not before, and the mark stops a second run.
//   J. THE JOB: registered once as a cluster job with no `onFront`, its run
//      answering that there is no database where the store is not one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const storeDouble = require('./tools/store_double');
const postgres = require('../persistence/persistence_postgres');
const codec = require('../persistence/directory_codec');
const backfill = require('../persistence/granting_index_backfill');
const directoryPortable = require('../persistence/directory_portable');
const mariadbQueries = require('../persistence/directory_queries_mariadb');
const sqlDialect = require('../persistence/sql_dialect');

const log = require('bunyan').createLogger({ name: 'granting_index_backfill',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

const REALM = 'acme';
// The key rows' columns joined: a lookup form holds a newline.
const SEP = '\u0001';
const BASE = 'dc=acme,dc=example';

// ---------------------------------------------------------------------------
// THE TABLE THE DOUBLES KEEP
// ---------------------------------------------------------------------------

function table() {
  log.debug("Entering table().");
  log.debug("Leaving table().");
  return { entries: new Map(), keys: new Set(), minted: new Map(),
           pages: [], writes: 0, statements: [] };
}

function rowId(realm, dnKey) {
  log.debug("Entering rowId().");
  log.debug("Leaving rowId().");
  return String(realm) + '\n' + String(dnKey);
}

// An entry as a writer of this build stores it, or — `legacy` — as one
// before #1306 did: every `value_keys` key but its `grantinggroup` ones.
function seed(db, dn, attrs, legacy) {
  log.debug("Entering seed().");
  const dnKey = dn.split(',').map(function (part) {
    return part.trim().toLowerCase();
  }).join(',');
  const granting = codec.grantingGroupKeysOf(attrs).map(function (one) {
    return codec.lookupOf('attr:grantinggroup', one);
  });
  const valueKeys = codec.indexOf(attrs).valueKeys.filter(function (one) {
    return !legacy || granting.indexOf(one) < 0;
  });
  db.entries.set(rowId(REALM, dnKey), {
    realm: REALM, dn_key: dnKey, dn: dn, attrs: attrs,
    value_keys: valueKeys,
    attr_names: Object.keys(attrs).map(function (one) {
      return one.toLowerCase();
    })
  });
  valueKeys.forEach(function (one) {
    db.keys.add([REALM, 'value', mariadbQueries.tableKey(one), dnKey]
      .join(SEP));
  });
  log.debug("Leaving seed().");
  return dnKey;
}

// The directory a test starts from: one role and one service account
// written before #1306, one owned group written after it, and people.
function seeded(db, people) {
  log.debug("Entering seeded().");
  const out = {
    role: seed(db, 'cn=auditors,ou=roles,' + BASE,
               { objectClass: ['stsRole'], cn: ['auditors'],
                 roleMemberGroup: ['Admins'] }, true),
    account: seed(db, 'uid=svc-backup,ou=users,' + BASE,
                  { objectClass: ['inetOrgPerson'], uid: ['svc-backup'],
                    stsServiceAccountOwner: ['CN=Ops , ou=Groups,' + BASE] },
                  true),
    modern: seed(db, 'cn=team,ou=groups,' + BASE,
                 { objectClass: ['groupOfNames'], cn: ['team'],
                   owner: ['cn=leads,ou=groups,' + BASE] }, false)
  };
  for (let i = 0; i < people; i++) {
    seed(db, 'uid=p' + String(i).padStart(3, '0') + ',ou=users,' + BASE,
         { objectClass: ['inetOrgPerson'], uid: ['p' + i] }, false);
  }
  log.debug("Leaving seeded().");
  return out;
}

function sortedEntries(db) {
  log.debug("Entering sortedEntries().");
  log.debug("Leaving sortedEntries().");
  return Array.from(db.entries.values()).sort(function (a, b) {
    const left = rowId(a.realm, a.dn_key);
    const right = rowId(b.realm, b.dn_key);
    return left < right ? -1 : (left > right ? 1 : 0);
  });
}

function after(row, realm, dnKey) {
  log.debug("Entering after().");
  log.debug("Leaving after().");
  return row.realm > realm || (row.realm === realm && row.dn_key > dnKey);
}

function overlaps(names, wanted) {
  log.debug("Entering overlaps().");
  log.debug("Leaving overlaps().");
  return names.some(function (one) {
    return wanted.indexOf(one) >= 0;
  });
}

function mintedKey(handle, indexKey, key) {
  log.debug("Entering mintedKey().");
  log.debug("Leaving mintedKey().");
  return [handle, '', indexKey, key].join('\n');
}

function mintedRows(db, handle, indexKeys) {
  log.debug("Entering mintedRows().");
  const out = [];
  db.minted.forEach(function (row) {
    if (row.handle === handle && indexKeys.indexOf(row.index_key) >= 0) {
      out.push({ index_key: row.index_key, key: row.key });
    }
  });
  log.debug("Leaving mintedRows().");
  return out;
}

function deleteMinted(db, handle, indexKey, keep) {
  log.debug("Entering deleteMinted().");
  Array.from(db.minted.keys()).forEach(function (id) {
    const row = db.minted.get(id);
    if (row.handle === handle && row.index_key === indexKey &&
        row.key !== keep) {
      db.minted.delete(id);
    }
  });
  log.debug("Leaving deleteMinted().");
}

function insertMinted(db, handle, indexKey, key) {
  log.debug("Entering insertMinted().");
  db.minted.set(mintedKey(handle, indexKey, key),
                { handle: handle, index_key: indexKey, key: key });
  log.debug("Leaving insertMinted().");
}

function entryRow(one) {
  log.debug("Entering entryRow().");
  log.debug("Leaving entryRow().");
  return { realm: one.realm, dn_key: one.dn_key, dn: one.dn,
           attrs: one.attrs, origin: null, created_at: null,
           modified_at: null };
}

// ---------------------------------------------------------------------------
// POSTGRESQL'S DOUBLE: the driver's statements, answered from the table.
// `hooks.page(n)` may throw (a failing store); `hooks.beforeWrite()` may
// change an entry (another writer).
// ---------------------------------------------------------------------------

function pgAnswer(db, hooks, sql, params) {
  log.debug("Entering pgAnswer().");
  db.statements.push(sql);
  let rows = [];
  let count = 0;
  if (/FROM sts_minted_index WHERE handle = \$1 AND realm = '' AND index_key = ANY/
    .test(sql)) {
    rows = mintedRows(db, params[0], params[1]);
  } else if (/^SELECT realm, dn_key, CASE WHEN attr_names \?\| \$3::text\[\]/
    .test(sql)) {
    db.pages.push({ realm: params[0], dnKey: params[1] });
    if (hooks.page) {
      hooks.page(db.pages.length);
    }
    rows = sortedEntries(db).filter(function (one) {
      return after(one, params[0], params[1]);
    }).slice(0, params[3]).map(function (one) {
      const wanted = overlaps(one.attr_names, params[2]);
      return { realm: one.realm, dn_key: one.dn_key,
               attrs: wanted ? one.attrs : null,
               value_keys: wanted ? one.value_keys.slice() : null };
    });
  } else if (/^UPDATE sts_ldap_entries AS e SET value_keys = u\.v::jsonb/
    .test(sql)) {
    if (hooks.beforeWrite) {
      hooks.beforeWrite(db);
    }
    params[0].forEach(function (realm, i) {
      const one = db.entries.get(rowId(realm, params[1][i]));
      if (one && JSON.stringify(one.attrs) === params[2][i]) {
        one.value_keys = JSON.parse(params[3][i]);
        count += 1;
      }
    });
    db.writes += count;
  } else if (/^DELETE FROM sts_minted_index WHERE handle = \$1/.test(sql)) {
    deleteMinted(db, params[0], params[1], null);
  } else if (/^INSERT INTO sts_minted_index \(handle, realm, index_key, key\) VALUES \(\$1, '', \$2, \$2\)/
    .test(sql)) {
    insertMinted(db, params[0], params[1], params[1]);
  } else if (/^INSERT INTO sts_minted_index \(handle, realm, index_key, key\) VALUES \(\$1, '', \$2, \$3\)/
    .test(sql)) {
    insertMinted(db, params[0], params[1], params[2]);
  } else if (/value_keys @> \$2::jsonb/.test(sql)) {
    const wanted = JSON.parse(params[1]);
    rows = sortedEntries(db).filter(function (one) {
      return one.realm === params[0] && wanted.every(function (k) {
        return one.value_keys.indexOf(k) >= 0;
      });
    }).slice(0, params[2]).map(entryRow);
  }
  log.debug("Leaving pgAnswer().");
  return { rows: rows, rowCount: count || rows.length };
}

function pgDriver(db, hooks) {
  log.debug("Entering pgDriver().");
  function reply(sql, params) {
    log.debug("Entering reply().");
    try {
      log.debug("Leaving reply().");
      return Promise.resolve(pgAnswer(db, hooks, String(sql), params || []));
    } catch (e) {
      log.debug("Caught in reply(): " + ((e && e.message) || e));
      log.debug("Leaving reply(). Refused.");
      return Promise.reject(e);
    }
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
  const restore = storeDouble.install({ Pool: FakePool, Client: FakeClient });
  try {
    log.debug("Leaving pgDriver().");
    return postgres.create({ url: 'postgres://sts@localhost:5432/sts',
                             log: QUIET });
  } finally {
    restore();
  }
}

// The store question #1306 asks, through the driver: is this name or DN
// named by a granting attribute of some entry?
function pgAsks(driver, key) {
  log.debug("Entering pgAsks().");
  log.debug("Leaving pgAsks().");
  return driver.directoryQuery('byAttribute',
                               [REALM, 'grantinggroup', key, 1])
    .then(function (rows) {
      return (rows || []).map(function (row) {
        return row.key || row.dn_key || (row.entry && row.entry.dn);
      });
    });
}

// A stillOwner() that answers yes `n` times, then no.
function ownerFor(n) {
  log.debug("Entering ownerFor().");
  let asked = 0;
  log.debug("Leaving ownerFor().");
  return function () {
    asked += 1;
    return asked <= n;
  };
}

async function postgresCases(t) {
  log.debug("Entering postgresCases().");
  t.log.info('=== P. PostgreSQL: the legacy entries keyed, once ===');
  const db = table();
  const keys = seeded(db, 10);
  const total = db.entries.size;
  const driver = pgDriver(db, {});
  const opsDn = 'cn=ops,ou=groups,' + BASE;
  const before = await Promise.all([pgAsks(driver, 'admins'),
                                    pgAsks(driver, opsDn),
                                    pgAsks(driver, 'cn=leads,ou=groups,' +
                                           BASE)]);
  t.check(!before[0].length && !before[1].length && before[2].length === 1,
          'P1. before the walk the store question misses the role and the ' +
          'service account written without the key, and finds the entry ' +
          'written with it', JSON.stringify(before));

  const first = await driver.indexGrantingKeys({ budgetMs: 60000, page: 3,
                                                 stillOwner: ownerFor(2) });
  const cursor = mintedRows(db, backfill.HANDLE, [backfill.CURSOR_KEY]);
  t.check(first.stopped && !first.complete && first.examined === 6 &&
          db.pages.length === 2 && cursor.length === 1 &&
          !mintedRows(db, backfill.HANDLE, [backfill.MARK_KEY]).length,
          'P2. a run whose ownership ends stops at a page boundary, not ' +
          'complete, its cursor written and no mark',
          JSON.stringify({ first: first, cursor: cursor }));
  const resumedFrom = backfill.cursorOf(cursor[0].key);

  const pagesBefore = db.pages.length;
  const second = await driver.indexGrantingKeys({ budgetMs: 60000,
                                                  page: 3 });
  t.check(second.complete && !second.already &&
          second.examined === total - 6 &&
          db.pages[pagesBefore].realm === resumedFrom.realm &&
          db.pages[pagesBefore].dnKey === resumedFrom.dnKey,
          'P3. the next run resumes after the cursor and reads no row twice',
          JSON.stringify({ second: second, total: total,
                           from: db.pages[pagesBefore] }));
  t.check(first.candidates + second.candidates === 3 &&
          db.writes === 2 && first.written + second.written === 2,
          'P4. only the three rows naming a granting attribute are opened, ' +
          'and only the two whose keys differ are written',
          JSON.stringify({ writes: db.writes, first: first.candidates,
                           second: second.candidates }));
  t.check(mintedRows(db, backfill.HANDLE, [backfill.MARK_KEY]).length ===
          1 && !mintedRows(db, backfill.HANDLE,
                           [backfill.CURSOR_KEY]).length,
          'P5. the mark is written and the cursor removed');
  const afterwards = await Promise.all([pgAsks(driver, 'admins'),
                                        pgAsks(driver, opsDn)]);
  t.check(afterwards[0][0] === keys.role && afterwards[1][0] === keys.account,
          'P6. after it the store question finds the role by its member ' +
          'group\'s name and the service account by the DN it names in ' +
          'another case and spacing', JSON.stringify(afterwards));

  const pagesThen = db.pages.length;
  const statementsThen = db.statements.length;
  const third = await driver.indexGrantingKeys({ budgetMs: 60000, page: 3 });
  t.check(third.complete && third.already && third.examined === 0 &&
          db.pages.length === pagesThen &&
          db.statements.length === statementsThen + 1,
          'P7. the mark stops a second run: one read of it, no page',
          JSON.stringify({ third: third,
                           statements: db.statements.slice(statementsThen) }));
  log.debug("Leaving postgresCases().");
}

async function postgresContention(t) {
  log.debug("Entering postgresContention().");
  t.log.info('=== P. PostgreSQL: another writer, a failing store, an ' +
             'empty one ===');
  const db = table();
  const keys = seeded(db, 0);
  const driver = pgDriver(db, {
    beforeWrite: function (inside) {
      // Another process rewrites the role between the page and the write,
      // with its keys, as a writer of this build does.
      const role = inside.entries.get(rowId(REALM, keys.role));
      role.attrs = Object.assign({}, role.attrs,
                                 { description: ['changed'] });
      role.value_keys = codec.indexOf(role.attrs).valueKeys;
    }
  });
  const done = await driver.indexGrantingKeys({ budgetMs: 60000 });
  const role = db.entries.get(rowId(REALM, keys.role));
  t.check(done.complete && done.written === 1 &&
          role.attrs.description[0] === 'changed' &&
          backfill.sameKeys(role.value_keys,
                            codec.indexOf(role.attrs).valueKeys),
          'P8. a writer that changed an entry between the read and the ' +
          'write wins: compare-and-set on the blob, its keys untouched',
          JSON.stringify(done));

  const failing = table();
  seeded(failing, 10);
  let failOnce = true;
  const flaky = pgDriver(failing, {
    page: function (n) {
      if (n === 3 && failOnce) {
        failOnce = false;
        throw new Error('the store went away');
      }
    }
  });
  let thrown = '';
  try {
    await flaky.indexGrantingKeys({ budgetMs: 60000, page: 3 });
  } catch (e) {
    log.debug("Caught in postgresContention(): " + ((e && e.message) || e));
    thrown = String((e && e.message) || e);
  }
  const saved = mintedRows(failing, backfill.HANDLE, [backfill.CURSOR_KEY]);
  const resumed = await flaky.indexGrantingKeys({ budgetMs: 60000,
                                                 page: 3 });
  t.check(/went away/.test(thrown) && saved.length === 1 &&
          resumed.complete && resumed.examined === failing.entries.size - 6 &&
          failing.pages[3].dnKey === backfill.cursorOf(saved[0].key).dnKey,
          'P9. a run that fails mid-walk keeps the pages it finished, and ' +
          'the next resumes after the last of them',
          JSON.stringify({ thrown: thrown, resumed: resumed }));

  const empty = table();
  for (let i = 0; i < 4; i++) {
    seed(empty, 'uid=q' + i + ',ou=users,' + BASE,
         { objectClass: ['inetOrgPerson'], uid: ['q' + i] }, false);
  }
  const plain = pgDriver(empty, {});
  const once = await plain.indexGrantingKeys({ budgetMs: 60000 });
  t.check(once.complete && once.candidates === 0 && once.written === 0 &&
          empty.pages.length === 1 &&
          mintedRows(empty, backfill.HANDLE, [backfill.MARK_KEY]).length ===
          1, 'P10. a store holding no granting entry finishes at once: one ' +
          'page, nothing opened, the mark written', JSON.stringify(once));
  log.debug("Leaving postgresContention().");
}

// ---------------------------------------------------------------------------
// MARIADB'S DOUBLE: the library's statements, by the name it sends them
// under (`/* sts:directory.<name> */`).
// ---------------------------------------------------------------------------

function mariaAnswer(db, text, values) {
  log.debug("Entering mariaAnswer().");
  db.statements.push(text);
  const name = (/\/\* sts:directory\.([A-Za-z.]+) \*\//.exec(text) ||
                [])[1] || '';
  let rows = [];
  let count = 0;
  if (name === 'granting.state') {
    rows = mintedRows(db, values[0], [values[1], values[2]]);
  } else if (name === 'granting.page') {
    const wanted = JSON.parse(values[0]);
    const cursor = values.length > 3
      ? { realm: values[2], dnKey: values[4] } : null;
    db.pages.push(cursor);
    rows = sortedEntries(db).filter(function (one) {
      return !cursor || after(one, cursor.realm, cursor.dnKey);
    }).slice(0, values[values.length - 1]).map(function (one) {
      const hit = overlaps(one.attr_names, wanted);
      // MariaDB answers JSON as text.
      return { realm: one.realm, dn_key: one.dn_key,
               attrs: hit ? JSON.stringify(one.attrs) : null,
               value_keys: hit ? JSON.stringify(one.value_keys) : null };
    });
  } else if (name === 'granting.lock') {
    for (let i = 0; i < values.length; i += 2) {
      const one = db.entries.get(rowId(values[i], values[i + 1]));
      if (one) {
        rows.push({ realm: one.realm, dn_key: one.dn_key,
                    attrs: JSON.stringify(one.attrs) });
      }
    }
  } else if (name === 'granting.write') {
    const one = db.entries.get(rowId(values[1], values[2]));
    one.value_keys = JSON.parse(values[0]);
    db.writes += 1;
    count = 1;
  } else if (name === 'granting.keys.delete') {
    Array.from(db.keys).forEach(function (id) {
      const parts = id.split(SEP);
      if (parts[0] === values[0] && parts[1] === 'value' &&
          parts[3] === values[1]) {
        db.keys.delete(id);
      }
    });
  } else if (name === 'granting.keys.insert') {
    for (let i = 0; i < values.length; i += 4) {
      db.keys.add([values[i], values[i + 1], values[i + 2], values[i + 3]]
        .join(SEP));
    }
  } else if (name === 'granting.mark') {
    insertMinted(db, values[0], values[1], values[2]);
  } else if (name === 'granting.unmark') {
    deleteMinted(db, values[0], values[1], values[2]);
  } else if (name === 'q.byAttribute') {
    const realm = values[0];
    const kind = values[1];
    const ks = values.slice(2, values.length - 2);
    rows = sortedEntries(db).filter(function (one) {
      return one.realm === realm && ks.some(function (k) {
        return db.keys.has([realm, kind, k, one.dn_key].join(SEP));
      });
    }).slice(0, values[values.length - 1]).map(function (one) {
      return Object.assign(entryRow(one),
                           { attrs: JSON.stringify(one.attrs) });
    });
  }
  log.debug("Leaving mariaAnswer().");
  return { rows: rows, rowCount: count || rows.length, affectedRows: count };
}

function mariaLibrary(db) {
  log.debug("Entering mariaLibrary().");
  const runner = {
    query: function (text, values) {
      log.debug("Entering query().");
      log.debug("Leaving query().");
      return Promise.resolve(mariaAnswer(db, String(text), values || []));
    }
  };
  const entryCodec = codec.codecFor('cell');
  const lib = directoryPortable.forDriver({
    dialect: sqlDialect.create('mariadb'), pool: runner, readPool: runner,
    entryCodec: entryCodec,
    entryFromRow: function () {
      log.debug("Entering entryFromRow().");
      log.debug("Leaving entryFromRow().");
      return null;
    },
    openedOfRow: function (row) {
      log.debug("Entering openedOfRow().");
      log.debug("Leaving openedOfRow().");
      return JSON.stringify(row.attrs || {});
    },
    withTransaction: function (fn) {
      log.debug("Entering withTransaction().");
      log.debug("Leaving withTransaction().");
      return Promise.resolve(fn(runner));
    },
    recordChanges: function () {
      log.debug("Entering recordChanges().");
      log.debug("Leaving recordChanges().");
      return Promise.resolve();
    }
  });
  log.debug("Leaving mariaLibrary().");
  return {
    lib: lib,
    run: function (options) {
      log.debug("Entering run().");
      log.debug("Leaving run().");
      return backfill.walk(lib.grantingOps, options);
    },
    asks: function (key) {
      log.debug("Entering asks().");
      log.debug("Leaving asks().");
      return lib.query('byAttribute', codec.keyArgs('byAttribute',
        [REALM, 'grantinggroup', key, 1])).then(function (rows) {
        return (rows || []).map(function (row) {
          return row.dn_key;
        });
      });
    }
  };
}

function valueKeyRows(db, dnKey) {
  log.debug("Entering valueKeyRows().");
  log.debug("Leaving valueKeyRows().");
  return Array.from(db.keys).filter(function (id) {
    const parts = id.split(SEP);
    return parts[1] === 'value' && parts[3] === dnKey;
  }).map(function (id) {
    return id.split(SEP)[2];
  }).sort();
}

async function mariadbCases(t) {
  log.debug("Entering mariadbCases().");
  t.log.info('=== M. MariaDB: the value key rows replaced, once ===');
  const db = table();
  const keys = seeded(db, 5);
  const store = mariaLibrary(db);
  const before = await store.asks('admins');
  const uidKey = mariadbQueries.tableKey(codec.lookupOf('attr:uid',
                                                        'svc-backup'));
  const accountBefore = valueKeyRows(db, keys.account);
  const done = await store.run({ budgetMs: 60000, page: 3 });
  const afterwards = await Promise.all([
    store.asks('admins'), store.asks('cn=ops,ou=groups,' + BASE)]);
  const accountAfter = valueKeyRows(db, keys.account);
  t.check(!before.length && afterwards[0][0] === keys.role &&
          afterwards[1][0] === keys.account,
          'M1. the store question misses the legacy entries before the ' +
          'walk and finds them after', JSON.stringify({ before: before,
                                                       after: afterwards }));
  t.check(done.complete && db.writes === 2 &&
          accountBefore.indexOf(uidKey) >= 0 &&
          accountAfter.indexOf(uidKey) >= 0 &&
          accountAfter.length > accountBefore.length &&
          backfill.sameKeys(db.entries.get(rowId(REALM,
                                                 keys.account)).value_keys,
                            accountAfter.map(String)),
          'M2. a legacy entry\'s value key rows are replaced by all its ' +
          'keys (its uid kept, its grantinggroup keys added) and its ' +
          'value_keys column with them; only the two legacy entries written',
          JSON.stringify({ done: done, before: accountBefore,
                           after: accountAfter }));
  const pagesThen = db.pages.length;
  const again = await store.run({ budgetMs: 60000, page: 3 });
  t.check(again.already && db.pages.length === pagesThen &&
          mintedRows(db, backfill.HANDLE, [backfill.MARK_KEY]).length ===
          1 && !mintedRows(db, backfill.HANDLE,
                           [backfill.CURSOR_KEY]).length,
          'M3. the mark is written, the cursor gone, and a second run reads ' +
          'no page', JSON.stringify(again));
  log.debug("Leaving mariadbCases().");
}

// ---------------------------------------------------------------------------
// J. THE JOB
// ---------------------------------------------------------------------------

async function theJob(t) {
  log.debug("Entering theJob().");
  t.log.info('=== J. the job ===');
  const registered = [];
  const scheduler = {
    job: function (id) {
      log.debug("Entering job().");
      log.debug("Leaving job().");
      return registered.filter(function (one) {
        return one.id === id;
      })[0] || null;
    },
    register: function (spec) {
      log.debug("Entering register().");
      registered.push(spec);
      log.debug("Leaving register().");
    }
  };
  backfill.reset();
  const first = backfill.install(scheduler);
  const second = backfill.install(scheduler);
  const spec = registered[0] || {};
  t.check(first && !second && registered.length === 1 &&
          spec.id === backfill.JOB && spec.kind === 'cluster' &&
          spec.scope === 'service' && spec.onFront === undefined &&
          typeof spec.everyMs === 'function' && spec.everyMs() > 0 &&
          spec.manual === true,
          'J1. one cluster job, service-wide, its body free to run in a ' +
          'request worker', JSON.stringify({ id: spec.id, kind: spec.kind }));
  const ran = await spec.run({ stillOwner: function () {
    return true;
  } });
  t.check(/not kept in a database/.test(String(ran && ran.summary)) &&
          /not kept in a database/.test(spec.off()),
          'J2. where the store is not a database it is off and its run ' +
          'says why', JSON.stringify(ran));
  backfill.reset();
  log.debug("Leaving theJob().");
}

async function run(t) {
  log.debug("Entering run().");
  await postgresCases(t);
  await postgresContention(t);
  await mariadbCases(t);
  await theJob(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'granting_index_backfill',
  describe: 'the one-time grantinggroup key backfill (#1311): a pre-#1306 ' +
            'entry is found by the store question only after it, on ' +
            'PostgreSQL and MariaDB; the mark stops a second run; an ' +
            'interrupted or failed run resumes after its cursor; a store ' +
            'with no granting entry finishes at once',
  run: run
};
