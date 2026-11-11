// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: minted_portable.js
//
// ===========================================================================
// WHAT THIS SERVICE MINTS, ON A SECOND ENGINE (#677, phase 3b).
//
//   A. ALWAYS: every statement `persistence/minted_portable.js` sends, and
//      every MariaDB spelling of `minted_queries.js` and `session_queries.js`,
//      compiled for MariaDB, carries none of PostgreSQL's syntax; and the
//      PostgreSQL text of those two modules is what it was.
//   B. AGAINST A REAL POSTGRESQL (STS_TEST_POSTGRES_URL; a schema of the
//      test's own, made by the driver's open() and dropped), the driver under
//      `persistence.sqlDialect=portable`, so the library runs on the
//      reference engine.
//   C. AGAINST A REAL MARIADB (STS_TEST_MARIADB_URL; a database of the
//      test's own, its tables from `persistence/schema_mariadb.js`), the
//      driver with `engine: 'mariadb'`.
//
// B and C are one set of contracts, through the WHOLE driver
// (`persistence_postgres.create()`) and, where a row's shape matters, the
// real minted module (`persistence_minted.js`) over it: a session written,
// read back and indexed; tombstoned, its index row gone, and NOT put back by
// an older write from a second driver instance; a merged row merged with
// the stored body under the lock; an index filed, refiled and removed; the
// fence refusing a flush before it writes; the expiry purge bounded per
// call; a value too long for its MariaDB column refused; and two drivers
// flushing overlapping keys concurrently, every flush committed; and a flush
// longer than one statement should carry (one Global logout of a person
// holding 3789 tokens made 8894 rows, and PostgreSQL refused the lock's list
// with "stack depth limit exceeded" on every retry), written and removed whole.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const sqlDialect = require('../persistence/sql_dialect');
const mintedPortable = require('../persistence/minted_portable');
const mintedQueries = require('../persistence/minted_queries');
const sessionQueries = require('../persistence/session_queries');

const log = require('bunyan').createLogger({ name: 'minted_portable',
  level: process.env.LOG_LEVEL || 'info' });

const TOMBSTONE = '$tombstone$1';
const PG_ONLY = [
  [/\$\d/, 'a $n placeholder'],
  [/::[a-z]/, 'a :: cast'],
  [/\bon conflict\b/i, 'ON CONFLICT'],
  [/\breturning\b/i, 'RETURNING'],
  [/"[a-z_]+"/, 'a double-quoted identifier'],
  [/unnest|to_timestamp|extract\(epoch|ctid|\bANY\(|FILTER \(|LATERAL|json_agg|IS DISTINCT FROM/i,
   'a PostgreSQL function or clause'],
  [/\bfor share\b/i, 'FOR SHARE']
];

// A runner that records each statement and answers what a database would
// for an empty store, every write touching one row.
function recorder() {
  log.debug("Entering recorder().");
  const sent = [];
  const runner = {
    sent: sent,
    query: function (text, values) {
      log.debug("Entering query().");
      sent.push({ text: String(text), values: values || [] });
      log.debug("Leaving query().");
      return Promise.resolve(/^(select|explain)/i.test(String(text))
        ? { rows: [], rowCount: 0 } : { rows: [], rowCount: 1 });
    }
  };
  log.debug("Leaving recorder().");
  return runner;
}

// The flush's named parameters for a small plan of every kind of row.
function sampleNamed() {
  log.debug("Entering sampleNamed().");
  log.debug("Leaving sampleNamed().");
  return {
    up_h: ['authn.sessions', 'x'], up_r: ['d', 'd'], up_k: ['s1', 'k1'],
    up_body: ['b1', 'b2'], up_expires: [null, 5], up_sealed: ['', ''],
    plain_h: ['x'], plain_r: ['d'], plain_k: ['k1'],
    del_h: ['x'], del_r: ['d'], del_k: ['k2'],
    ses_realm: ['d'], ses_key: ['s1'], ses_expires: [null],
    ses_last_seen: [1], ses_started: [1], ses_subject: ['s'],
    ses_username: ['u'], ses_chosen: [true], ses_authenticated: [true],
    ses_kind: ['sign-on'], ses_rp_surface: [''], ses_parent: [''],
    ses_backs_console: [false], ses_credential: [''], ses_partner: [''],
    sesdel_realm: ['d'], sesdel_key: ['s9'],
    ixup_h: ['x'], ixup_r: ['d'], ixup_k: ['k1'],
    ixgone_h: ['x'], ixgone_r: ['d'], ixgone_k: ['k2'],
    ixnew_h: ['x'], ixnew_r: ['d'], ixnew_i: ['i1'], ixnew_k: ['k1'],
    ixnew_s: [null],
    origin: 'o', chg_kind: ['minted', 'minted'], chg_realm: ['d', 'd'],
    chg_key: ['a.b', 'c.d'], chg_h: ['x', null], chg_r: ['d', null],
    chg_k: ['k1', null]
  };
}

// Every library operation once.
async function exercise(ops, runner) {
  log.debug("Entering exercise().");
  await ops.flush(runner, [{ handle: 'x', realm: 'd', key: 'k1' }],
                  function () {
                    return { resolved: {}, named: sampleNamed() };
                  });
  await ops.loadMinted({ realms: ['d'], nowMs: 1, staleBefore: 5,
                         ageHandles: ['x'], skipHandles: ['y'] });
  await ops.loadMintedKeys(['x'], ['d'], 1);
  await ops.readMintedMany(runner, [{ handle: 'x', realm: 'd', key: 'k' }]);
  await ops.readMinted('x', 'd', 'k');
  await ops.mintedIndexComplete(['x']);
  await ops.insertIndex([{ handle: 'x', realm: 'd', index_key: 'i',
                           key: 'k', sort_at: null }]);
  await ops.markMintedIndexed('x');
  await ops.backfillExpiryBatch('x', 1000, 10);
  await ops.readSessionIndex('d', 'k');
  await ops.upsertSession(runner, ['d', 'k', null, 0, 0, '', '', true, true,
                                   '', '', '', false, '', '']);
  await ops.deleteSession(runner, 'd', 'k');
  await ops.sessionIndexDone();
  await ops.loadSessionBodies('', '', 10);
  await ops.lockSessionBody(runner, 'd', 'k');
  await ops.sweepSessionIndex(runner);
  await ops.purgeTombstones(1);
  await ops.purgeMinted(1);
  await ops.purgeExpiredMinted('expired', { nowMs: 1 }, 10);
  await ops.purgeExpiredMinted('stale', { handles: ['x'], staleBeforeMs: 1 },
                               10);
  await ops.purgeExpiredMinted('orphan', { orphanBeforeMs: 1,
                                           defaultRealm: 'd' }, 10);
  await ops.purgeExpiredMinted('orphan', { orphanBeforeMs: 1,
                                           defaultRealm: 'd',
                                           realms: ['a'] }, 10);
  log.debug("Leaving exercise().");
}

function opsOver(dialect, runner) {
  log.debug("Entering opsOver().");
  log.debug("Leaving opsOver().");
  return mintedPortable.create({
    dialect: dialect, pool: runner, readPool: runner, tombstone: TOMBSTONE,
    indexMark: '$index-complete$',
    sessionMark: { realm: '', key: '$session-index-complete$' }
  });
}

// Every query name of the two builder modules, with arguments of each shape.
const MINTED_NAMES = [
  ['minted.read', ['h', 'r', 'k']], ['minted.page', ['h', 'r', '', 1]],
  ['minted.byIndex', ['h', 'r', 'i']], ['minted.newest', ['h', 'r', 1, 5]],
  ['minted.count', ['h', 'r', 1]], ['minted.estimate', ['h', 'r']]
];
const SESSION_NAMES = [
  ['session.read', ['r', 'k']], ['session.count', ['r']],
  ['session.exists', ['r', 'k']], ['session.oldest', ['r', 's']],
  ['session.expired', ['r', 1, 1]], ['session.subjectRows', ['r', '', '']],
  ['session.overCapRows', ['r', 2, 10]], ['session.children', ['r', 'p']],
  ['session.credential', ['r', 'c']], ['session.username', ['r', 'u']],
  ['session.subject', ['r', 's']], ['session.page', ['r', '', 10]],
  ['session.surface', ['r', 's']], ['session.partner', ['r', 'p']],
  ['session.liveSubjects', ['r', 1]],
  ['session.liveByUsername', ['r', ['u1', 'u2'], 1]],
  ['session.liveTotals', ['r', 1, '', '', '', -1]],
  ['session.livePage', ['r', 1, '', '', '', -1, 10, 0]]
];

// The named parameters of a flush of `n` plain rows, each indexed and a
// session, and of `n` deletes of the same kinds.
function longNamed(n) {
  log.debug("Entering longNamed().");
  const named = { origin: 'o' };
  ['up_h', 'up_r', 'up_k', 'up_body', 'up_expires', 'up_sealed', 'plain_h',
   'plain_r', 'plain_k', 'del_h', 'del_r', 'del_k', 'ses_realm', 'ses_key',
   'ses_expires', 'ses_last_seen', 'ses_started', 'ses_subject',
   'ses_username', 'ses_chosen', 'ses_authenticated', 'ses_kind',
   'ses_rp_surface', 'ses_parent', 'ses_backs_console', 'ses_credential',
   'ses_partner', 'sesdel_realm', 'sesdel_key', 'ixup_h', 'ixup_r', 'ixup_k',
   'ixgone_h', 'ixgone_r', 'ixgone_k', 'ixnew_h', 'ixnew_r', 'ixnew_i',
   'ixnew_k', 'ixnew_s'].forEach(function (name) {
    named[name] = [];
  });
  for (let i = 0; i < n; i++) {
    const key = 'k' + String(i).padStart(6, '0');
    const gone = 'g' + String(i).padStart(6, '0');
    named.up_h.push('authn.sessions');
    named.up_r.push('d');
    named.up_k.push(key);
    named.up_body.push('b');
    named.up_expires.push(null);
    named.up_sealed.push('');
    named.plain_h.push('authn.sessions');
    named.plain_r.push('d');
    named.plain_k.push(key);
    named.del_h.push('authn.sessions');
    named.del_r.push('d');
    named.del_k.push(gone);
    named.ses_realm.push('d');
    named.ses_key.push(key);
    named.ses_expires.push(null);
    named.ses_last_seen.push(1);
    named.ses_started.push(1);
    named.ses_subject.push('s');
    named.ses_username.push('u');
    named.ses_chosen.push(true);
    named.ses_authenticated.push(true);
    named.ses_kind.push('sign-on');
    named.ses_rp_surface.push('');
    named.ses_parent.push('');
    named.ses_backs_console.push(false);
    named.ses_credential.push('');
    named.ses_partner.push('');
    named.sesdel_realm.push('d');
    named.sesdel_key.push(gone);
    named.ixup_h.push('authn.sessions');
    named.ixup_r.push('d');
    named.ixup_k.push(key);
    named.ixgone_h.push('authn.sessions');
    named.ixgone_r.push('d');
    named.ixgone_k.push(gone);
    ['i1', 'i2'].forEach(function (indexKey) {
      named.ixnew_h.push('authn.sessions');
      named.ixnew_r.push('d');
      named.ixnew_i.push(indexKey);
      named.ixnew_k.push(key);
      named.ixnew_s.push(null);
    });
  }
  log.debug("Leaving longNamed().");
  return named;
}

// A FLUSH LONGER THAN ONE STATEMENT, on both engines' text: no statement holds
// more than a bounded number of parameters, each list is covered exactly once,
// and the lock's chunks keep the lock order.
async function longFlushChecks(t) {
  log.debug("Entering longFlushChecks().");
  const N = 1300;
  const LIMIT = 500;
  const engines = ['mariadb', 'postgres'];
  for (const engine of engines) {
    const runner = recorder();
    const ops = opsOver(sqlDialect.create(engine), runner);
    const named = longNamed(N);
    const touched = [];
    named.del_k.concat(named.up_k).sort().forEach(function (key) {
      touched.push({ handle: 'authn.sessions', realm: 'd', key: key });
    });
    await ops.flush(runner, touched, function () {
      return { resolved: {}, named: named };
    });
    const called = function (name) {
      return runner.sent.filter(function (one) {
        return one.text.indexOf('sts:minted.flush.' + name + ' ') >= 0;
      });
    };
    const lockKeys = [];
    called('lock').forEach(function (one) {
      for (let i = 2; i < one.values.length; i += 3) {
        lockKeys.push(one.values[i]);
      }
    });
    const inOrder = lockKeys.every(function (key, i) {
      return key === touched[i].key;
    });
    t.check(lockKeys.length === touched.length && inOrder &&
            called('lock').length === Math.ceil(touched.length / LIMIT),
            'A10 (' + engine + '). a long flush\'s lock is several ' +
            'statements, every key once, in the one lock order',
            called('lock').length + ' statement(s), ' + lockKeys.length +
            ' key(s)');
    const expected = { upsert: [N, 6], delete: [N, 3], sessions: [N, 15],
                       sessionsGone: [N, 2], indexFile: [2 * N, 5] };
    const wrong = [];
    Object.keys(expected).forEach(function (name) {
      const rows = expected[name][0];
      const statements = called(name);
      if (statements.length !== Math.ceil(rows / LIMIT)) {
        wrong.push(name + ': ' + statements.length + ' statement(s)');
      }
      if (statements.some(function (one) {
        return one.values.length > LIMIT * (expected[name][1] + 12);
      })) {
        wrong.push(name + ': too many parameters');
      }
    });
    t.check(wrong.length === 0,
            'A11 (' + engine + '). each write of a long flush is cut to ' +
            LIMIT + ' rows a statement', wrong.join('; '));
    const clears = called('indexClear');
    const kept = clears.reduce(function (sum, one) {
      return sum + one.values.length;
    }, 0);
    // Every clear row's three values and each filed row's four, once: a
    // statement carrying the whole filed list would multiply this. A chunk
    // with nothing filed (only removed bodies) holds Knex's empty NOT IN,
    // `1 = ?`, one value more; those are chunks 4 to 6 of 6 here.
    t.check(clears.length === Math.ceil(2 * N / LIMIT) &&
            kept === 3 * 2 * N + 4 * 2 * N + 3,
            'A12 (' + engine + '). the index clear keeps only the filed ' +
            'rows of each statement\'s own bodies',
            clears.length + ' statement(s), ' + kept + ' parameter(s)');
  }
  log.debug("Leaving longFlushChecks().");
}

async function staticChecks(t) {
  log.debug("Entering staticChecks().");
  t.log.info('=== A. compiled for MariaDB, none of PostgreSQL ===');
  const runner = recorder();
  await exercise(opsOver(sqlDialect.create('mariadb'), runner), runner);
  const statements = runner.sent.map(function (one) {
    return one.text;
  });
  const texts = statements.concat(MINTED_NAMES.map(function (one) {
    return mintedQueries.build(one[0], one[1], 'mariadb').text;
  }), SESSION_NAMES.map(function (one) {
    return sessionQueries.build(one[0], one[1], 'mariadb').text;
  }));
  t.check(statements.length >= 30,
          'A1. every library operation sent its statements',
          statements.length + ' statement(s)');
  const offending = [];
  texts.forEach(function (text) {
    PG_ONLY.forEach(function (rule) {
      if (rule[0].test(text)) {
        offending.push(rule[1] + ' in: ' + text.slice(0, 160));
      }
    });
  });
  t.check(offending.length === 0,
          'A2. NO STATEMENT OF THE FAMILY CARRIES POSTGRESQL\'S SYNTAX on ' +
          'MariaDB', offending.join(' | '));
  t.check(statements.some(function (text) {
    return /^delete from `sts_minted` where .* limit \? \/\* sts:minted\.purgeExpired\.expired/
      .test(text);
  }), 'A3. the expiry purge\'s batch is DELETE … LIMIT on MariaDB');
  t.check(/^select `handle`, `realm`, `key`, `body` from `sts_minted` where \(`handle`, `realm`, `key`\) in \(\(\?, \?, \?\)\) order by `handle` asc, `realm` asc, `key` asc for update/
            .test(statements[0]),
          'A4. a flush first locks every existing row it touches, in ' +
          '(handle, realm, key) order', statements[0]);
  const marks = runner.sent.map(function (one) {
    return (/sts:minted\.([A-Za-z.]+)/.exec(one.text) || [])[1];
  });
  const at = function (name) {
    return marks.indexOf(name);
  };
  t.check(at('flush.lock') < at('flush.upsert') &&
          at('flush.upsert') < at('flush.delete') &&
          at('flush.delete') < at('flush.sessions') &&
          at('flush.sessions') < at('flush.indexClear') &&
          at('flush.indexClear') < at('flush.indexFile') &&
          at('flush.indexFile') < at('flush.changes'),
          'A5. the lock, then the bodies, then the side tables and the ' +
          'change log', marks.slice(0, 10).join(' '));
  // THE POSTGRESQL TEXT IS WHAT IT WAS: no engine is PostgreSQL's spelling.
  const same = MINTED_NAMES.concat(SESSION_NAMES).every(function (one) {
    const queries = /^minted/.test(one[0]) ? mintedQueries : sessionQueries;
    const bare = queries.build(one[0], one[1]);
    const named = queries.build(one[0], one[1], 'postgres');
    return bare.text === named.text &&
      JSON.stringify(bare.values) === JSON.stringify(named.values) &&
      /\$1/.test(bare.text);
  });
  t.check(same, 'A6. without an engine (the bridge\'s thread) and for ' +
          'PostgreSQL the builders answer PostgreSQL\'s text, unchanged');
  const twice = sessionQueries.build('session.overCapRows', ['r', 2, 10],
                                     'mariadb');
  const many = sessionQueries.build('session.liveByUsername',
                                    ['r', ['u1', 'u2'], 9], 'mariadb');
  const none = sessionQueries.build('session.liveByUsername', ['r', [], 9],
                                    'mariadb');
  t.check(JSON.stringify(twice.values) === '["r","r",2,10]' &&
          /IN \(\?, \?\)/.test(many.text) &&
          JSON.stringify(many.values) === '["r","u1","u2",9]' &&
          /IN \(NULL\)/.test(none.text),
          'A7. a parameter used twice is bound twice, and an array is one ' +
          'placeholder per element (none matches nothing)',
          JSON.stringify([twice.values, many.values, none.text]));
  const estimate = mintedQueries.answerOf('minted.estimate', [{
    EXPLAIN: JSON.stringify({ query_block: { select_id: 1, table: {
      table_name: 'sts_minted', rows: 4321 } } }) }]);
  t.check(estimate === 4321, 'A8. MariaDB\'s EXPLAIN FORMAT=JSON estimate ' +
          'is read', String(estimate));
  const pgRunner = recorder();
  await exercise(opsOver(sqlDialect.create('postgres'), pgRunner), pgRunner);
  t.check(pgRunner.sent.some(function (one) {
    return /on conflict \("handle", "realm", "key"\) do nothing/
      .test(one.text);
  }), 'A9. on PostgreSQL a new key is INSERT … ON CONFLICT DO NOTHING ' +
          '(the portable mode)', String(pgRunner.sent.length));
  await longFlushChecks(t);
  log.debug("Leaving staticChecks().");
}

// ---------------------------------------------------------------------------
// THE REAL MODULE'S SETUP: a key-encryption key through the keystore's own
// start path (`tests/minted_persistence.js`' armKeystore()), product mode,
// minted persistence on.
// ---------------------------------------------------------------------------
async function armKeystore(dir) {
  log.debug("Entering armKeystore().");
  const keystore = require('../common/keystore');
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  keystore.reset();
  keystore.setStore({
    loadKeys: function () {
      log.debug("Entering loadKeys().");
      log.debug("Leaving loadKeys().");
      return Promise.resolve([]);
    },
    saveKeys: function () {
      log.debug("Entering saveKeys().");
      log.debug("Leaving saveKeys().");
      return Promise.resolve();
    },
    deleteKeys: function () {
      log.debug("Entering deleteKeys().");
      log.debug("Leaving deleteKeys().");
      return Promise.resolve();
    }
  });
  await keystore.start();
  log.debug("Leaving armKeystore().");
}

// The stores the real module flushes, declared once for both engines.
let stores = null;

function declareStores() {
  log.debug("Entering declareStores().");
  if (stores) {
    log.debug("Leaving declareStores(). Declared.");
    return stores;
  }
  const realms = require('../common/realms');
  // THE SERVICE'S OWN SESSION STORE MAY BE DECLARED ALREADY: in a run of
  // several test files `authn/authn.ts` may have been loaded, and the first
  // declaration of a handle is the one the module flushes. Then this file's
  // session rows are written through the driver directly, shaped as the
  // module shapes them (`sessionRow()` below), and the merging store alone
  // goes through the module.
  const taken = !!realms.handleFor('authn.sessions');
  stores = {
    sessions: taken ? null : realms.map({
      persist: 'authn.sessions', tombstone: true,
      indexOf: function (value) {
        log.debug("Entering indexOf().");
        log.debug("Leaving indexOf().");
        return { expiresAt: null, lastSeenAt: Number(value.seen) || 1,
                 startedAt: 1, subjectKey: 'subject-' + value.user,
                 usernameKey: 'user-' + value.user, chosen: true,
                 authenticated: true, kind: 'sign-on', rpSurface: '',
                 parentKey: '', backsConsole: false, credentialKey: '',
                 partnerRelationship: '' };
      }
    }),
    lists: realms.map({
      persist: 'test.lists', tombstone: true,
      mergeRow: function (mine, theirs) {
        log.debug("Entering mergeRow().");
        const union = Array.from(new Set([].concat(theirs.list || [],
                                                   mine.list || []))).sort();
        log.debug("Leaving mergeRow().");
        return { list: union };
      }
    })
  };
  log.debug("Leaving declareStores().");
  return stores;
}

// A driver over `url`: the whole of `persistence_postgres.create()`.
function driverFor(url, engine) {
  log.debug("Entering driverFor(). " + engine);
  const postgres = require('../persistence/persistence_postgres');
  log.debug("Leaving driverFor().");
  return postgres.create({
    url: url, engine: engine, verifyTls: false,
    sqlDialect: engine === 'postgres' ? 'portable' : undefined,
    log: require('bunyan').createLogger({ name: 'minted_portable_driver',
      level: process.env.LOG_LEVEL || 'warn' })
  });
}

async function contracts(t, label, url, engine, sql) {
  log.debug("Entering contracts(). " + engine);
  const config = require('../common/config');
  const keystore = require('../common/keystore');
  const minted = require('../persistence/persistence_minted');
  const KEY = engine === 'mariadb' ? '`key`' : 'key';
  const s = declareStores();
  const a = driverFor(url, engine);
  const b = driverFor(url, engine);
  const ids = engine + '-' + process.pid;
  try {
    config.setOverride('global.mode', 'product');
    config.setOverride('persistence.minted', true);
    minted.reset();
    minted.setDriver(a, engine);
    if (engine === 'mariadb') {
      // NO BRIDGE ON MARIADB, AND THE STORES THAT NEED ONE ARE HELD WHOLE.
      t.check(typeof a.bridgeConnection !== 'function' &&
              minted.lendsNoBridge() === true &&
              require('../authn/session_window').active() === false,
              label + '0. the driver lends no bridge and says so, and the ' +
              'session window is off (sessions are held whole)');
    }
    // ---- a session written, read back and indexed ---------------------
    const sid = 'sid-' + ids;
    const sessionValue = { user: 'alice', seen: 7 };
    const sessionRow = function (gone) {
      const base = { handle: 'authn.sessions', realm: 'default', key: sid,
                     keySealed: '', tombstone: true };
      return gone ? base : Object.assign(base, {
        body: keystore.seal(JSON.stringify(sessionValue), 'minted-rows'),
        expiresAt: null,
        index: { expiresAt: null, lastSeenAt: 7, startedAt: 1,
                 subjectKey: 'subject-alice', usernameKey: 'user-alice',
                 chosen: true, authenticated: true, kind: 'sign-on' } });
    };
    if (s.sessions) {
      s.sessions.set(sid, sessionValue);
      await minted.flush();
    } else {
      await a.saveMinted([sessionRow(false)], []);
    }
    const row = (await sql('SELECT handle, realm, ' + KEY + ', body, ' +
                           'key_sealed FROM sts_minted WHERE handle = ' +
                           '\'authn.sessions\'')).rows[0];
    const back = row ? await a.readMinted('authn.sessions', row.realm,
                                          row.key) : null;
    const opened = back ? keystore.open(back.body, 'minted-rows') : null;
    const indexRow = row ? (await sql('SELECT subject_key, chosen, ' +
                                      'last_seen_at FROM sts_sessions WHERE ' +
                                      'realm = \'' + row.realm + '\'')).rows
      : [];
    t.check(!!row && opened && JSON.parse(opened).user === 'alice' &&
            back.writtenAt > 0 && indexRow.length === 1 &&
            indexRow[0].subject_key === 'subject-alice' &&
            Number(indexRow[0].last_seen_at) === 7,
            label + '1. a session flushed by the real module is read back ' +
            'sealed, and its index row written in the same flush',
            JSON.stringify([!!row, indexRow]));
    const changes = await sql('SELECT origin, kind FROM sts_changes');
    t.check(changes.rows.some(function (c) {
      return c.origin === a.origin() && c.kind === 'minted';
    }) && a.changeRowsWritten() >= 1,
            label + '2. the change row is written in the flush and counted ' +
            'at its COMMIT', JSON.stringify([changes.rows.length,
                                             a.changeRowsWritten()]));
    const restored = await a.loadMinted({ realms: [row.realm],
                                          nowMs: Date.now() });
    const keysOf = await a.loadMintedKeys(['authn.sessions'], [row.realm],
                                          Date.now());
    const many = await a.readMintedMany([{ handle: 'authn.sessions',
                                           realm: row.realm, key: row.key },
                                         { handle: 'authn.sessions',
                                           realm: row.realm, key: 'none' }]);
    t.check(restored.length === 1 && restored[0].body === row.body &&
            restored[0].writtenAt > 0 && keysOf.length === 1 &&
            many.length === 1,
            label + '3. the restore read, the resident keys and the batch ' +
            'read find the row', JSON.stringify([restored.length,
                                                 keysOf.length,
                                                 many.length]));
    // ---- tombstoned, and not resurrected by an older write --------------
    if (s.sessions) {
      s.sessions.delete(sid);
      await minted.flush();
    } else {
      await a.saveMinted([], [sessionRow(true)]);
    }
    const ended = (await sql('SELECT body FROM sts_minted WHERE handle = ' +
                             '\'authn.sessions\'')).rows[0];
    const indexGone = (await sql('SELECT 1 FROM sts_sessions WHERE realm = ' +
                                 '\'' + row.realm + '\'')).rows.length;
    t.check(ended && ended.body === TOMBSTONE && indexGone === 0 &&
            (await a.readMinted('authn.sessions', row.realm, row.key)) ===
            null,
            label + '4. an ended session leaves a tombstone, its index row ' +
            'is gone, and a read finds nothing',
            JSON.stringify([ended, indexGone]));
    const bChanges = b.changeRowsWritten();
    const stale = await b.saveMinted([{
      handle: 'authn.sessions', realm: row.realm, key: row.key,
      keySealed: row.key_sealed, body: row.body, tombstone: true,
      expiresAt: null, index: { lastSeenAt: 9, startedAt: 1,
                                subjectKey: 'subject-alice', chosen: true,
                                authenticated: true, kind: 'sign-on' }
    }], []);
    const still = (await sql('SELECT body FROM sts_minted WHERE handle = ' +
                             '\'authn.sessions\'')).rows[0];
    const noIndex = (await sql('SELECT 1 FROM sts_sessions WHERE realm = ' +
                               '\'' + row.realm + '\'')).rows.length;
    t.check(stale.refused.length === 1 && still.body === TOMBSTONE &&
            noIndex === 0 && b.changeRowsWritten() === bChanges,
            label + '5. AN OLDER WRITE FROM A SECOND DRIVER DOES NOT PUT ' +
            'THE SESSION BACK: refused, the tombstone kept, no index row, ' +
            'no change row', JSON.stringify([stale.refused.length,
                                             still.body, noIndex]));
    // ---- a merged row -------------------------------------------------
    const lk = 'list-' + ids;
    s.lists.set(lk, { list: ['a'] });
    await minted.flush();
    const bodyA = (await sql('SELECT body FROM sts_minted WHERE handle = ' +
                             '\'test.lists\'')).rows[0].body;
    s.lists.set(lk, { list: ['b'] });
    await minted.flush();
    // Another node's write: the stored body goes back to the one holding
    // `a`, while this process holds `b`.
    await sql('UPDATE sts_minted SET body = \'' + bodyA + '\' WHERE ' +
              'handle = \'test.lists\'');
    s.lists.set(lk, { list: ['b', 'c'] });
    await minted.flush();
    const mergedBody = (await sql('SELECT body FROM sts_minted WHERE ' +
                                  'handle = \'test.lists\'')).rows[0].body;
    const merged = JSON.parse(keystore.open(mergedBody, 'minted-rows'));
    t.check(merged.list.join() === 'a,b,c' &&
            JSON.stringify(s.lists.get(lk)) === JSON.stringify(merged),
            label + '6. A MERGING ROW IS MERGED WITH THE STORED BODY UNDER ' +
            'THE LOCK, and this process takes the merge',
            JSON.stringify([merged, s.lists.get(lk)]));
    // ---- the minted index -----------------------------------------------
    const ix = { handle: 'test.ix', realm: 'r1', key: 'k-' + ids,
                 keySealed: '', body: 'b1', expiresAt: null,
                 lookups: ['ix1', 'ix2'], sortAt: 5 };
    await b.saveMinted([ix], []);
    const indexRows = function (r) {
      return r.rows.map(function (one) {
        return one.index_key + ':' + (one.sort_at === null ? ''
          : Number(one.sort_at));
      }).sort().join();
    };
    const filed = await sql('SELECT index_key, sort_at FROM ' +
                            'sts_minted_index WHERE handle = \'test.ix\'');
    await b.saveMinted([Object.assign({}, ix, { body: 'b2',
                                                lookups: ['ix2'],
                                                sortAt: 9 })], []);
    const refiled = await sql('SELECT index_key, sort_at FROM ' +
                              'sts_minted_index WHERE handle = ' +
                              '\'test.ix\'');
    const byIndex = await a.mintedQuery('minted.byIndex',
                                        ['test.ix', 'r1', 'ix2']);
    const newest = await a.mintedQuery('minted.newest',
                                       ['test.ix', 'r1', Date.now(), 10]);
    const count = await a.mintedQuery('minted.count',
                                      ['test.ix', 'r1', Date.now()]);
    const page = await a.mintedQuery('minted.page',
                                     ['test.ix', 'r1', '', Date.now()]);
    const one = await a.mintedQuery('minted.read',
                                    ['test.ix', 'r1', ix.key]);
    const estimate = await a.mintedQuery('minted.estimate',
                                         ['test.ix', 'r1']);
    t.check(indexRows(filed) === '$sort$:5,ix1:,ix2:' &&
            indexRows(refiled) === '$sort$:9,ix2:' &&
            byIndex.length === 1 && byIndex[0].body === 'b2' &&
            newest.length === 1 && count === 1 && page.length === 1 &&
            one && one.body === 'b2' &&
            (estimate === null || typeof estimate === 'number'),
            label + '7. an index is filed, refiled (the sort row updated in ' +
            'place, the dropped key removed) and asked on the read pool',
            JSON.stringify([indexRows(filed), indexRows(refiled),
                            byIndex.length,
                            newest.length, count, page.length, estimate]));
    await b.saveMinted([], [{ handle: 'test.ix', realm: 'r1', key: ix.key,
                              keySealed: '', indexed: true }]);
    const unfiled = await sql('SELECT 1 FROM sts_minted_index WHERE ' +
                              'handle = \'test.ix\'');
    await a.writeMintedIndex([{ handle: 'test.ix2', realm: 'r1',
                                indexKey: 'i', key: 'k', sortAt: null }]);
    await a.writeMintedIndex([{ handle: 'test.ix2', realm: 'r1',
                                indexKey: 'i', key: 'k', sortAt: null }]);
    const before = await a.mintedIndexComplete(['test.ix2']);
    await a.markMintedIndexed('test.ix2');
    await a.markMintedIndexed('test.ix2');
    const after = await a.mintedIndexComplete(['test.ix2', 'test.ix']);
    t.check(unfiled.rows.length === 0 && before.length === 0 &&
            after.join() === 'test.ix2',
            label + '8. a deleted row\'s index rows go; an index row and ' +
            'the completion mark are filed once',
            JSON.stringify([unfiled.rows.length, before, after]));
    // ---- the session index's own doors ----------------------------------
    const index = { expiresAt: null, lastSeenAt: 3, startedAt: 2,
                    subjectKey: 'sub', usernameKey: 'usr', chosen: true,
                    authenticated: false, kind: 'keyed', rpSurface: '',
                    parentKey: '', backsConsole: false, credentialKey: 'c',
                    partnerRelationship: '' };
    await a.writeSessionIndex('r2', 'k2', index);
    await a.writeSessionIndex('r2', 'k2', index);
    const queried = {};
    for (const one of SESSION_NAMES) {
      const args = one[1].slice(0);
      args[0] = 'r2';
      queried[one[0]] = await a.sessionIndexQuery(one[0], args);
    }
    t.check(queried['session.count'].n === 1 &&
            queried['session.exists'].hit === false &&
            queried['session.credential'].join() === 'k2' &&
            queried['session.liveTotals'].unauthenticated === 1 &&
            queried['session.livePage'].join() === 'k2' &&
            queried['session.liveSubjects'].n === 1,
            label + '9. a repaired index row is written once and every ' +
            'session question is answered by the store',
            JSON.stringify(queried));
    const doneBefore = await a.sessionIndexDone();
    await b.saveMinted([{ handle: 'authn.sessions', realm: 'r2', key: 'k3',
                          keySealed: '', body: 'sealed-k3', expiresAt: null,
                          tombstone: true }], []);
    const bodies = await a.loadSessionBodies('', '', 10);
    await a.writeSessionIndexes([{ realm: 'r2', key: 'k3', body: 'sealed-k3',
                                   index: index }], true);
    const swept = await sql('SELECT realm, ' + KEY + ' FROM sts_sessions ' +
                            'ORDER BY realm, ' + KEY);
    const doneAfter = await a.sessionIndexDone();
    await a.deleteSessionIndex('r2', 'k3');
    const deleted = await sql('SELECT 1 FROM sts_sessions WHERE realm = ' +
                              '\'r2\'');
    t.check(!doneBefore && doneAfter && bodies.some(function (r) {
      return r.key === 'k3';
    }) && swept.rows.map(function (r) {
      return r.realm + '/' + r.key;
    }).join() === '/$session-index-complete$,r2/k3' &&
            deleted.rows.length === 0,
            label + '10. a backfill page indexes the body it locked, sweeps ' +
            'the index row with no body and commits the mark; a repair ' +
            'deletes', JSON.stringify([doneBefore, doneAfter, swept.rows]));
    // ---- the fence comes first ------------------------------------------
    b.setFence(function () {
      return { nodeId: 'ghost-node', leases: [] };
    }, function () {
      log.debug("Entering onFenced().");
      log.debug("Leaving onFenced().");
    });
    let fencedErr = null;
    try {
      await b.saveMinted([{ handle: 'test.fence', realm: 'r1', key: 'f',
                            keySealed: '', body: 'x', expiresAt: null }], []);
    } catch (e) {
      log.debug("Caught in contracts(): " + ((e && e.message) || e));
      fencedErr = e;
    }
    b.setFence(null, null);
    const fencedRows = await sql('SELECT 1 FROM sts_minted WHERE handle = ' +
                                 '\'test.fence\'');
    t.check(!!fencedErr && fencedErr.fenced === true &&
            fencedRows.rows.length === 0,
            label + '11. a flush whose fence does not hold writes nothing',
            String(fencedErr && fencedErr.message));
    // ---- purges, bounded per call ---------------------------------------
    const past = Date.now() - 60000;
    const expired = [];
    for (let i = 0; i < 7; i++) {
      expired.push({ handle: 'test.exp', realm: 'r1', key: 'e' + i,
                     keySealed: '', body: 'x', expiresAt: past });
    }
    await b.saveMinted(expired, []);
    const batches = [];
    for (let i = 0; i < 4; i++) {
      batches.push(await a.purgeExpiredMinted('expired',
                                              { nowMs: Date.now(),
                                                limit: 3 }));
    }
    await b.saveMinted([{ handle: 'test.stale', realm: 'r1', key: 's',
                          keySealed: '', body: 'x', expiresAt: null },
                        { handle: 'test.orphan', realm: 'gone-realm',
                          key: 'o', keySealed: '', body: 'x',
                          expiresAt: null }], []);
    const future = Date.now() + 60000;
    const stalePurged = await a.purgeExpiredMinted('stale', {
      handles: ['test.stale'], staleBeforeMs: future, limit: 10 });
    const orphanPurged = await a.purgeExpiredMinted('orphan', {
      defaultRealm: 'default', orphanBeforeMs: future, limit: 10,
      realms: ['r1', 'r2'] });
    const orphanByTable = await a.purgeExpiredMinted('orphan', {
      defaultRealm: 'default', orphanBeforeMs: future, limit: 10 });
    const tombs = await a.purgeTombstones(future);
    t.check(batches.join() === '3,3,1,0' && stalePurged === 1 &&
            orphanPurged === 1 && orphanByTable >= 1 && tombs >= 1,
            label + '12. the expiry purge deletes at most its limit a call; ' +
            'the stale, orphan and tombstone purges each find theirs',
            JSON.stringify([batches, stalePurged, orphanPurged,
                            orphanByTable, tombs]));
    await b.saveMinted([{ handle: 'test.legacy', realm: 'r1', key: 'l',
                          keySealed: '', body: 'x', expiresAt: null }], []);
    const backfilled = await a.backfillMintedExpiry('test.legacy', 1000);
    const legacy = (await sql('SELECT expires_at FROM sts_minted WHERE ' +
                              'handle = \'test.legacy\'')).rows[0];
    t.check(backfilled === 1 && Number(legacy.expires_at) > 1000,
            label + '13. a legacy row is given its expiry from when it was ' +
            'written', JSON.stringify([backfilled, legacy]));
    // ---- a value too long for MariaDB -----------------------------------
    if (engine === 'mariadb') {
      let tooLong = null;
      try {
        await b.saveMinted([{ handle: 'test.long', realm: 'r1',
                              key: 'k'.repeat(600), keySealed: '',
                              body: 'x', expiresAt: null }], []);
      } catch (e) {
        log.debug("Caught in contracts(): " + ((e && e.message) || e));
        tooLong = e;
      }
      t.check(!!tooLong && /STS-STORE-0120/.test(String(tooLong.message)),
              label + '14. A KEY TOO LONG FOR ITS MARIADB COLUMN IS ' +
              'REFUSED, not truncated', String(tooLong && tooLong.message));
    }
    // ---- two drivers, overlapping keys, at once --------------------------
    const flushes = [];
    let failed = 0;
    const racer = function (driver, n) {
      const ups = [];
      const dels = [];
      for (let i = 0; i < 12; i++) {
        const k = 'race-' + ((n * 7 + i * 3) % 20);
        const kind = (n + i) % 5;
        if (kind === 4) {
          dels.push({ handle: 'test.race', realm: 'r1', key: k,
                      keySealed: '', tombstone: true });
        } else {
          ups.push({ handle: kind % 2 ? 'test.race' : 'test.plain',
                     realm: 'r1', key: k, keySealed: '',
                     body: 'n' + n + 'i' + i, expiresAt: null,
                     tombstone: kind % 2 === 1 });
        }
      }
      return driver.saveMinted(ups, dels).catch(function (e) {
        log.debug("Caught in racer(): " + ((e && e.message) || e));
        failed++;
      });
    };
    for (let n = 0; n < 24; n++) {
      flushes.push(racer(n % 2 ? a : b, n));
    }
    await Promise.all(flushes);
    const raced = await sql('SELECT count(*) AS n FROM sts_minted WHERE ' +
                            'handle IN (\'test.race\', \'test.plain\')');
    t.check(failed === 0 && Number(raced.rows[0].n) > 0,
            label + '15. TWENTY-FOUR CONCURRENT FLUSHES FROM TWO DRIVERS ' +
            'OVER OVERLAPPING KEYS ALL COMMIT (a deadlock is run again)',
            failed + ' failed, ' + raced.rows[0].n + ' row(s)');
    const purged = await a.purgeMinted(future);
    t.check(purged > 0, label + '16. purgeMinted removes every row written ' +
            'before the instant', String(purged));
    // ---- a flush far longer than one statement ------------------------
    const LONG = 9000;
    const longRows = [];
    for (let i = 0; i < LONG; i++) {
      longRows.push({ handle: 'test.plain', realm: 'r2', key: 'long-' + i,
                      keySealed: '', body: 'b' + i, expiresAt: null,
                      tombstone: false, lookups: ['ix1', 'ix2'], sortAt: i });
    }
    await a.saveMinted(longRows, []);
    const longWritten = await sql('SELECT count(*) AS n FROM sts_minted ' +
                                  'WHERE realm = \'r2\'');
    await a.saveMinted([], longRows.map(function (row) {
      return { handle: row.handle, realm: row.realm, key: row.key,
               keySealed: '', tombstone: false };
    }));
    const longLeft = await sql('SELECT count(*) AS n FROM sts_minted ' +
                               'WHERE realm = \'r2\'');
    t.check(Number(longWritten.rows[0].n) === LONG &&
            Number(longLeft.rows[0].n) === 0,
            label + '17. A FLUSH OF ' + LONG + ' ROWS COMMITS, AND ONE ' +
            'REMOVING THEM (the lock\'s list once failed every retry)',
            longWritten.rows[0].n + ' written, ' + longLeft.rows[0].n +
            ' left');
  } finally {
    minted.reset();
    await a.close();
    await b.close();
  }
  log.debug("Leaving contracts().");
}

async function againstPostgres(t) {
  log.debug("Entering againstPostgres().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== B. skipped: STS_TEST_POSTGRES_URL names no database ===');
    log.debug("Leaving againstPostgres(). Skipped.");
    return;
  }
  t.log.info('=== B. the driver, portable, against a real PostgreSQL ===');
  const knexStore = require('../persistence/knex_store');
  const schema = 'minted_portable_' + process.pid;
  const admin = knexStore.openConnection({
    connectionString: url, ssl: { rejectUnauthorized: false } });
  await admin.connect();
  await admin.query('CREATE SCHEMA ' + schema);
  const scoped = url + (url.indexOf('?') >= 0 ? '&' : '?') +
    'options=' + encodeURIComponent('-c search_path=' + schema);
  try {
    const opener = driverFor(scoped, 'postgres');
    await opener.open();
    await opener.close();
    await contracts(t, 'B', scoped, 'postgres', function (text) {
      return admin.query('SET search_path = ' + schema).then(function () {
        return admin.query(text);
      });
    });
  } finally {
    await admin.query('DROP SCHEMA ' + schema + ' CASCADE');
    await admin.end();
  }
  log.debug("Leaving againstPostgres().");
}

async function againstMariadb(t) {
  log.debug("Entering againstMariadb().");
  const url = process.env.STS_TEST_MARIADB_URL || '';
  if (!url) {
    t.log.info('=== C. skipped: STS_TEST_MARIADB_URL names no database ===');
    log.debug("Leaving againstMariadb(). Skipped.");
    return;
  }
  t.log.info('=== C. the driver against a real MariaDB ===');
  const knexStore = require('../persistence/knex_store');
  const schemaMariadb = require('../persistence/schema_mariadb');
  const scratch = 'minted_portable_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE DATABASE ' + scratch);
  const scoped = url.replace(/\/[^/?]*(\?|$)/, '/' + scratch + '$1');
  const pool = knexStore.openPool({ connectionString: scoped }, { max: 2 });
  try {
    for (const object of schemaMariadb.SCHEMA_OBJECTS) {
      await pool.query(object.statement);
    }
    await contracts(t, 'C', scoped, 'mariadb', function (text) {
      return pool.query(text);
    });
  } finally {
    await pool.end();
    await admin.query('DROP DATABASE ' + scratch);
    await admin.end();
  }
  log.debug("Leaving againstMariadb().");
}

async function run(t) {
  log.debug("Entering run().");
  await staticChecks(t);
  if (process.env.STS_TEST_POSTGRES_URL || process.env.STS_TEST_MARIADB_URL) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-minted-portable-'));
    try {
      await armKeystore(dir);
      await againstPostgres(t);
      await againstMariadb(t);
    } finally {
      delete process.env.STS_KEYS_SOURCE;
      delete process.env.STS_KEYS_KEK_PROVIDER;
      delete process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS;
      delete process.env.STS_KEYS_KEK_FILE;
      require('../common/keystore').reset();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'minted_portable',
  describe: 'what this service mints, on MariaDB: no PostgreSQL syntax, and ' +
            'the minted flush\'s and the session index\'s contracts kept ' +
            'against a real database (#677)',
  run: run
};
