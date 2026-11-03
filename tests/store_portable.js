// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: store_portable.js
//
// ===========================================================================
// THE SMALLER TABLES' PORTABLE STATEMENTS (#677): THE NATIVE CONTRACTS, IN
// SQL A SECOND ENGINE RUNS.
//
//   A. ALWAYS: every operation of `persistence/store_portable.js`, compiled
//      for MariaDB, carries none of PostgreSQL's syntax — no `$n`, no `::`
//      cast, no `ON CONFLICT`, no `RETURNING`, no double-quoted identifier,
//      no jsonb operator, no `strpos`, no CTE — and `key` is back-quoted.
//      Driven against a runner that records what it is sent.
//   B. AGAINST A REAL POSTGRESQL, when STS_TEST_POSTGRES_URL names one the
//      test may create a schema in: the library runs there unchanged
//      (`persistence.sqlDialect=portable`), so every contract is held there
//      too.
//   C. THE SAME CONTRACTS AGAINST A REAL MARIADB, when STS_TEST_MARIADB_URL
//      names a server the test may create a database on (it makes one and
//      drops it), its tables from `persistence/schema_mariadb.js` — and the
//      races the contracts exist for: twenty-five concurrent claims of one
//      assertion, one accepted; ten concurrent merges into one key row, ten
//      merged; ten concurrent override deltas on one realm, ten kept; ten
//      concurrent change-row transactions, one dense run of numbers.
//   D. THROUGH THE DRIVER ON MARIADB, with the same URL: the postgres
//      driver built with `engine: 'mariadb'` sends this family through the
//      library, inside its own fenced transactions, and its
//      `recordChanges()` writes the change rows in them and counts them.
// ===========================================================================

delete process.env.CONFIG_FILE;

const sqlDialect = require('../persistence/sql_dialect');
const storePortable = require('../persistence/store_portable');

const log = require('bunyan').createLogger({ name: 'store_portable',
  level: process.env.LOG_LEVEL || 'info' });

const TABLES = ['sts_realms', 'sts_appconfig', 'sts_keys', 'sts_changes',
                'sts_node_snapshots', 'sts_used_assertions',
                'sts_report_artifacts', 'sts_report_artifact_pieces'];

// PostgreSQL's tables, as `postgres/schema.sql` builds them.
const PG_TABLES = [
  'CREATE TABLE sts_realms (id text PRIMARY KEY, name text, description ' +
    'text, created_at bigint, overrides jsonb NOT NULL DEFAULT ' +
    '\'{}\'::jsonb, domain text, retiring_at bigint)',
  'CREATE TABLE sts_appconfig (key text PRIMARY KEY, value jsonb NOT NULL)',
  'CREATE TABLE sts_keys (realm text PRIMARY KEY, material text NOT NULL, ' +
    'written_at timestamptz NOT NULL DEFAULT now())',
  'CREATE TABLE sts_changes (seq bigserial PRIMARY KEY, origin text NOT ' +
    'NULL, kind text NOT NULL, realm text NOT NULL DEFAULT \'\', key text ' +
    'NOT NULL DEFAULT \'\', at timestamptz NOT NULL DEFAULT now())',
  'CREATE TABLE sts_node_snapshots (name text PRIMARY KEY, node_id text ' +
    'NOT NULL DEFAULT \'\', taken_at bigint NOT NULL, body jsonb NOT NULL ' +
    'DEFAULT \'{}\'::jsonb)',
  'CREATE TABLE sts_used_assertions (realm text NOT NULL, key text NOT ' +
    'NULL, format text NOT NULL, used_as text NOT NULL, issuer text NOT ' +
    'NULL, identifier text NOT NULL, client_id text NOT NULL DEFAULT \'\', ' +
    'subject text NOT NULL DEFAULT \'\', state text NOT NULL, reservation ' +
    'text NOT NULL, origin text NOT NULL DEFAULT \'\', used_at bigint NOT ' +
    'NULL, spent_at bigint NOT NULL DEFAULT 0, expires_at bigint NOT NULL, ' +
    'PRIMARY KEY (realm, key))',
  'CREATE TABLE sts_report_artifacts (realm text NOT NULL, job_id text NOT ' +
    'NULL, bytes bytea NOT NULL, sha256 text NOT NULL, media_type text NOT ' +
    'NULL, created_at bigint NOT NULL, PRIMARY KEY (realm, job_id))',
  'CREATE TABLE sts_report_artifact_pieces (realm text NOT NULL, job_id ' +
    'text NOT NULL, seq int NOT NULL, bytes bytea NOT NULL, PRIMARY KEY ' +
    '(realm, job_id, seq))'
];

/**
 * The library over a pool, with the driver's transaction helpers played
 * by plain BEGIN/COMMIT on a held connection, and change rows written
 * through the library's own `insertChanges()` as the driver's
 * `recordChanges()` does.
 */
function opsOver(dialect, pool, origin) {
  log.debug("Entering opsOver().");
  let ops = null;
  const transaction = function (fn) {
    return pool.connect().then(function (client) {
      return client.query('BEGIN').then(function () {
        return fn(client);
      }).then(function (result) {
        return client.query('COMMIT').then(function () {
          client.release();
          return result;
        });
      }, function (err) {
        return client.query('ROLLBACK').then(function () {
          client.release();
          throw err;
        });
      });
    });
  };
  ops = storePortable.create({
    dialect: dialect, pool: pool, readPool: pool,
    withTransaction: transaction, transactionOnce: transaction,
    recordChanges: function (client, rows) {
      log.debug("Entering recordChanges().");
      log.debug("Leaving recordChanges().");
      return ops.insertChanges(client, origin || 'proc-1', rows);
    },
    processId: function () {
      log.debug("Entering processId().");
      log.debug("Leaving processId().");
      return origin || 'proc-1';
    }
  });
  log.debug("Leaving opsOver().");
  return ops;
}

// A runner that records each statement and answers by its name.
function recorder() {
  log.debug("Entering recorder().");
  const sent = [];
  const answer = function (text) {
    const name = (/\/\* sts:store\.([A-Za-z.]+) \*\//.exec(text) || [])[1] ||
      '';
    if (name === 'mergeKeys.lock') {
      return { rows: [{ material: 'old' }], rowCount: 1 };
    }
    if (name === 'purgeNodeSnapshots.read') {
      return { rows: [{ name: 'gone', taken_at: '1' }], rowCount: 1 };
    }
    if (name === 'saveRealms.lock') {
      return { rows: [{ overrides: '{"a":1}', created_at: null,
                        domain: null, retiring_at: null }], rowCount: 1 };
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

async function* piecesOf(list) {
  for (const one of list) {
    yield one;
  }
}

// Every operation once.
async function exercise(ops) {
  log.debug("Entering exercise().");
  await ops.loadRealms();
  await ops.saveRealms([{ row: { id: 'r', name: 'n', overrides: {} },
                          name: true, description: false, set: { b: 2 },
                          cleared: ['a'], whole: false }], ['gone']);
  await ops.loadOverrides();
  await ops.saveOverrides({ x: 'true' }, ['y']);
  await ops.loadKeys();
  await ops.loadKey('r');
  await ops.saveKeys('r', 'sealed');
  await ops.deleteKeys('r');
  await ops.mergeKeys('r', function (current) {
    return current + '+';
  });
  await ops.latestBlockingChangeSeq();
  await ops.purgeChanges(10);
  await ops.putNodeSnapshot('n', 'node-1', { a: 1 });
  await ops.purgeNodeSnapshots(1000, ['n']);
  await ops.nodeSnapshots();
  await ops.claimUsedAssertion(assertion('k'), { now: 5, cap: 10 });
  await ops.settleUsedAssertion('r', 'k', 'res', true, 6);
  await ops.settleUsedAssertion('r', 'k', 'res', false, 6);
  await ops.findUsedAssertion('r', 'k', 5);
  await ops.listUsedAssertions('r', { now: 5, format: 'jwt', use: 'grant',
                                      state: 'spent', q: 'Ab%' });
  await ops.purgeUsedAssertions(5);
  await ops.removeUsedAssertions('r');
  await ops.putReportArtifact({ realm: 'r', jobId: 'j', bytes:
                                Buffer.from([0, 255]), sha256: 's',
                                mediaType: 'text/csv', createdAt: 1 });
  await ops.putReportArtifactPieces({ realm: 'r', jobId: 'j', prefix: 'p:',
                                      size: 2, sha256: 's',
                                      mediaType: 'text/csv', createdAt: 1 },
                                    piecesOf([Buffer.from([1])]));
  await ops.getReportArtifactPiece({ realm: 'r', jobId: 'j', seq: 0 });
  await ops.getReportArtifact({ realm: 'r', jobId: 'j' });
  await ops.deleteReportArtifact({ realm: 'r', jobId: 'j' });
  log.debug("Leaving exercise().");
}

function assertion(key, over) {
  log.debug("Entering assertion().");
  log.debug("Leaving assertion().");
  return Object.assign({
    realm: 'r', key: key, format: 'jwt', use: 'grant', issuer: 'Issuer-A',
    identifier: 'jti-' + key, clientId: 'client', subject: 'sub',
    state: 'reserved', reservation: 'res-' + key, origin: 'proc-1',
    usedAt: 1000, spentAt: 0, expiresAt: 10000
  }, over || {});
}

async function staticChecks(t) {
  log.debug("Entering staticChecks().");
  t.log.info('=== A. compiled for MariaDB, none of PostgreSQL ===');
  const maria = sqlDialect.create('mariadb');
  const runner = recorder();
  await exercise(opsOver(maria, runner));
  const statements = runner.sent.map(function (one) {
    return one.text;
  }).filter(function (text) {
    return !/^(BEGIN|COMMIT|ROLLBACK)$/.test(text);
  });
  const names = {};
  statements.forEach(function (text) {
    const name = (/sts:store\.([A-Za-z.]+)/.exec(text) || [])[1];
    if (name) {
      names[name] = true;
    }
  });
  t.check(Object.keys(names).length >= 39,
          'A1. every operation sent its statements',
          Object.keys(names).length + ' distinct statement(s): ' +
          Object.keys(names).join(' '));
  const pgOnly = [
    [/\$\d/, 'a $n placeholder'],
    [/::[a-z]/, 'a :: cast'],
    [/\bon conflict\b/i, 'ON CONFLICT'],
    [/\breturning\b/i, 'RETURNING'],
    [/"[a-z_]+"/, 'a double-quoted identifier'],
    [/\bnulls first\b/i, 'NULLS FIRST'],
    [/\bstrpos\b|\bunnest\b|\bANY\(|clock_timestamp|\binterval '/i,
     'a PostgreSQL function'],
    [/\bwith\s+[a-z_]+\s+as\s*\(/i, 'a CTE'],
    [/\?\||->>|@>/, 'a jsonb operator'],
    [/(^|[^`])\bkey\b(?!`)/, 'an unquoted `key`']
  ];
  const offending = [];
  statements.forEach(function (text) {
    const body = text.replace(/\/\* sts:[^*]+\*\//, '')
      .replace(/on duplicate key update/g, '');
    pgOnly.forEach(function (rule) {
      if (rule[0].test(body)) {
        offending.push(rule[1] + ' in: ' + text.slice(0, 160));
      }
    });
  });
  t.check(offending.length === 0,
          'A2. NO STATEMENT CARRIES POSTGRESQL\'S SYNTAX',
          offending.join(' | '));
  t.check(statements.some(function (text) {
    return /^insert ignore into `sts_used_assertions`/.test(text);
  }), 'A3. a claim is an INSERT IGNORE on MariaDB');
  t.check(statements.some(function (text) {
    return /`sts_keys` where `realm` = \? for update/.test(text);
  }) && statements.some(function (text) {
    return /`sts_realms` where `id` = \? for update/.test(text);
  }), 'A4. a merge reads its row FOR UPDATE first');
  const update = runner.sent.filter(function (one) {
    return /sts:store\.saveRealms\.update/.test(one.text);
  })[0];
  t.check(!!update && update.values.indexOf('{"a":1}') < 0 &&
          update.values.indexOf('{"b":2}') >= 0,
          'A5. the override delta is merged in JavaScript: the cleared key ' +
          'removed, the set one added', JSON.stringify(update));
  let refused = null;
  try {
    await opsOver(maria, recorder()).claimUsedAssertion(
      assertion('k', { realm: 'x'.repeat(65) }), { now: 1, cap: 9 });
  } catch (e) {
    refused = e;
  }
  t.check(!!refused && /STS-STORE-0100/.test(String(refused.message)),
          'A6. a value longer than its MariaDB key column is refused, not ' +
          'truncated', refused && refused.message);
  const pg = sqlDialect.create('postgres');
  const pgRunner = recorder();
  await exercise(opsOver(pg, pgRunner));
  t.check(pgRunner.sent.some(function (one) {
    return /on conflict \("realm", "key"\) do nothing/.test(one.text);
  }), 'A7. on PostgreSQL the same claim is INSERT … ON CONFLICT DO NOTHING');
  log.debug("Leaving staticChecks().");
}

async function contracts(t, ops, pool, dialect, label) {
  log.debug("Entering contracts().");
  const KEY = dialect.engine === 'mariadb' ? '`key`' : 'key';
  const changes = async function (kind) {
    const r = await pool.query('SELECT count(*) AS n FROM sts_changes ' +
                               'WHERE kind = \'' + kind + '\'');
    return Number(r.rows[0].n);
  };
  // ---- realms ---------------------------------------------------------
  t.check(await ops.loadRealms() === null, label + '1. no realm is null');
  await ops.saveRealms([
    { row: { id: 'b', name: 'B', description: 'd', createdAt: 20,
             overrides: { a: 1, b: 2 }, domain: 'b.example' },
      name: true, description: true, set: {}, cleared: [], whole: true },
    { row: { id: 'a', name: 'A', createdAt: 10, overrides: {} },
      name: true, description: true, set: {}, cleared: [], whole: true },
    { row: { id: 'z', name: 'Z', createdAt: null, overrides: {} },
      name: true, description: true, set: {}, cleared: [], whole: true }
  ], []);
  let realms = await ops.loadRealms();
  t.check(realms.map(function (r) { return r.id; }).join() === 'z,a,b' &&
          realms[2].createdAt === 20 && realms[2].overrides.b === 2 &&
          realms[0].createdAt === null && await changes('realms') === 1,
          label + '2. realms come back never-dated first, then oldest, ' +
          'with their overrides, and one change row',
          JSON.stringify(realms));
  await ops.saveRealms([
    { row: { id: 'b', name: 'ignored', description: 'D2', createdAt: 99,
             overrides: { q: 0 }, domain: 'other', retiringSince: 77 },
      name: false, description: true, set: { c: 3, b: 'two' },
      cleared: ['a'], whole: false }
  ], ['a']);
  realms = await ops.loadRealms();
  const b = realms.filter(function (r) { return r.id === 'b'; })[0];
  t.check(realms.length === 2 && b.name === 'B' && b.description === 'D2' &&
          b.createdAt === 20 && b.domain === 'b.example' &&
          b.retiringSince === 77 &&
          JSON.stringify(b.overrides) === '{"b":"two","c":3}',
          label + '3. a delta keeps the name it was not given, the domain ' +
          'and creation time, sets the retiring mark once, removes the ' +
          'cleared override and merges the set ones; a removed realm goes',
          JSON.stringify(realms));
  const racers = [];
  for (let i = 0; i < 10; i++) {
    const set = {};
    set['k' + i] = i;
    racers.push(ops.saveRealms([{ row: { id: 'b', overrides: {} },
                                  name: false, description: false,
                                  set: set, cleared: [], whole: false }],
                               []));
  }
  await Promise.all(racers);
  realms = await ops.loadRealms();
  const merged = realms.filter(function (r) { return r.id === 'b'; })[0];
  t.check(Object.keys(merged.overrides).length === 12,
          label + '4. TEN CONCURRENT OVERRIDE DELTAS ON ONE REALM: EVERY ' +
          'ONE KEPT (the merge is under the row lock)',
          JSON.stringify(merged.overrides));
  const fresh = [];
  for (let i = 0; i < 6; i++) {
    const set = {};
    set['n' + i] = i;
    fresh.push(ops.saveRealms([{ row: { id: 'new', overrides: set },
                                 name: true, description: true, set: set,
                                 cleared: [], whole: false }], []));
  }
  await Promise.all(fresh);
  realms = await ops.loadRealms();
  const made = realms.filter(function (r) { return r.id === 'new'; })[0];
  t.check(!!made && Object.keys(made.overrides).length === 6,
          label + '5. six concurrent first writes of a new realm: one ' +
          'inserts, the rest merge into it', JSON.stringify(made));
  // ---- overrides ------------------------------------------------------
  t.check(await ops.loadOverrides() === null, label + '6. no override is ' +
          'null');
  await ops.saveOverrides({ s: 'true', t: true, u: { deep: [1] } }, []);
  await ops.saveOverrides({ s: 'false' }, ['t']);
  const overrides = await ops.loadOverrides();
  t.check(overrides.s === 'false' && !('t' in overrides) &&
          overrides.u.deep[0] === 1 && Object.keys(overrides).length === 2,
          label + '7. overrides round-trip raw, a set replaces and a clear ' +
          'removes', JSON.stringify(overrides));
  // ---- keys -----------------------------------------------------------
  await ops.saveKeys('r1', 'one');
  await ops.saveKeys('r1', 'two');
  await ops.saveKeys('r2', 'x');
  const keys = await ops.loadKeys();
  const keysBefore = await changes('keys');
  await ops.deleteKeys('nobody');
  const noChange = await changes('keys');
  await ops.deleteKeys('r2');
  t.check(keys.length === 2 && await ops.loadKey('r1') === 'two' &&
          await ops.loadKey('r2') === null && keysBefore === 3 &&
          noChange === 3 && await changes('keys') === 4,
          label + '8. keys upsert, load and delete, a change row each, and ' +
          'none for a delete of nothing', JSON.stringify(keys));
  const unmoved = await ops.mergeKeys('r1', function (current) {
    return current;
  });
  t.check(!unmoved.written && await changes('keys') === 4,
          label + '9. a merge that moves nothing writes nothing',
          JSON.stringify(unmoved));
  const merges = [];
  for (let i = 0; i < 10; i++) {
    merges.push(ops.mergeKeys('m', function (current) {
      return (current || '') + '|' + i;
    }));
  }
  const mergeAnswers = await Promise.all(merges);
  const material = await ops.loadKey('m');
  const parts = String(material).split('|').filter(Boolean).sort();
  t.check(parts.length === 10 && mergeAnswers.filter(function (a) {
    return a.inserted;
  }).length === 1 && await changes('keys') === 14,
          label + '10. TEN CONCURRENT MERGES INTO ONE NEW KEY ROW: ONE ' +
          'INSERTS, NINE MERGE UNDER THE LOCK, NONE IS LOST', material);
  // ---- the change log -------------------------------------------------
  const before = await pool.query('SELECT COALESCE(MAX(seq), 0) AS s FROM ' +
                                  'sts_changes');
  const start = Number(before.rows[0].s);
  const writers = [];
  for (let i = 0; i < 10; i++) {
    writers.push(pool.connect().then(async function (client) {
      await client.query('BEGIN');
      const rows = [];
      for (let j = 0; j < 50; j++) {
        rows.push({ kind: 'test', realm: 'w' + i, key: 'k' + j });
      }
      await ops.insertChanges(client, 'writer-' + i, rows.slice(0, 25));
      await ops.insertChanges(client, 'writer-' + i, rows.slice(25));
      await client.query('COMMIT');
      client.release();
    }));
  }
  await Promise.all(writers);
  const logged = await pool.query('SELECT seq, origin, ' + KEY + ' AS k ' +
                                  'FROM sts_changes WHERE seq > ' + start +
                                  ' ORDER BY seq');
  const seqs = logged.rows.map(function (r) { return Number(r.seq); });
  const dense = seqs.length === 500 && seqs.every(function (s, i) {
    return s === start + 1 + i;
  });
  // Each statement's rows are one consecutive run — on MariaDB, whose
  // `innodb_autoinc_lock_mode` 1 numbers a multi-row INSERT as a block.
  // PostgreSQL's `nextval()` is per row, so two concurrent statements'
  // numbers interleave there: dense, and not consecutive per statement.
  const runs = {};
  logged.rows.forEach(function (r) {
    const id = r.origin + '/' + (Number(String(r.k).slice(1)) < 25 ? 0 : 1);
    (runs[id] = runs[id] || []).push(Number(r.seq));
  });
  const consecutive = Object.keys(runs).every(function (id) {
    const list = runs[id];
    return list.length === 25 &&
      (dialect.engine !== 'mariadb' || list[24] - list[0] === 24);
  });
  t.check(dense && consecutive,
          label + '11. TEN CONCURRENT TRANSACTIONS OF CHANGE ROWS: ONE ' +
          'DENSE RUN OF NUMBERS' + (dialect.engine === 'mariadb'
            ? ', EACH STATEMENT\'S ROWS CONSECUTIVE' : ''),
          seqs.length + ' rows, ' + seqs[0] + '..' + seqs[seqs.length - 1]);
  await pool.query('INSERT INTO sts_changes (origin, kind) VALUES ' +
                   '(\'other\', \'minted-own\'), (\'proc-1\', \'keys\')');
  const blocking = await ops.latestBlockingChangeSeq();
  t.check(blocking === seqs[seqs.length - 1],
          label + '12. the blocking seq skips this process\'s own rows and ' +
          'minted-own ones', String(blocking));
  const below = await pool.query('SELECT count(*) AS n FROM sts_changes ' +
                                 'WHERE seq <= ' + start);
  const purged = await ops.purgeChanges(start + 1);
  const purgedLeft = await pool.query('SELECT min(seq) AS s FROM ' +
                                      'sts_changes');
  t.check(purged === Number(below.rows[0].n) &&
          Number(purgedLeft.rows[0].s) === start + 1,
          label + '13. a purge deletes below its bound and says how many',
          purged + ' purged');
  // ---- node snapshots -------------------------------------------------
  await ops.putNodeSnapshot('n1', 'node-1', { v: 1 });
  await ops.putNodeSnapshot('n1', 'node-1', { v: 2 });
  await ops.putNodeSnapshot('n2', 'node-2', { v: 3 });
  await ops.putNodeSnapshot('n3', 'node-3', { v: 4 });
  await pool.query('UPDATE sts_node_snapshots SET taken_at = 5 WHERE name ' +
                   'IN (\'n2\', \'n3\')');
  const snaps = await ops.nodeSnapshots();
  const gone = await ops.purgeNodeSnapshots(60000, ['n1', 'n3']);
  const after = await ops.nodeSnapshots();
  t.check(snaps.rows.length === 3 && snaps.rows[0].body.v === 2 &&
          snaps.now > 1e12 && snaps.rows[0].takenAt > 1e12 &&
          gone.length === 1 && gone[0].name === 'n2' &&
          gone[0].takenAt === 5 &&
          after.rows.map(function (r) { return r.name; }).join() === 'n1,n3',
          label + '14. a snapshot is upserted at the database clock; a ' +
          'purge deletes and answers exactly the old rows not kept',
          JSON.stringify([snaps, gone, after.rows.length]));
  // ---- used assertions ------------------------------------------------
  const first = await ops.claimUsedAssertion(assertion('a1'),
                                             { now: 2000, cap: 100 });
  const replay = await ops.claimUsedAssertion(assertion('a1',
    { reservation: 'other' }), { now: 2000, cap: 100 });
  t.check(first.claimed && !replay.claimed && replay.existing &&
          replay.existing.identifier === 'jti-a1' && replay.live === 1,
          label + '15. an assertion is claimed once and refused after, ' +
          'with the row that holds it', JSON.stringify([first, replay]));
  const race = [];
  for (let i = 0; i < 25; i++) {
    race.push(ops.claimUsedAssertion(assertion('race',
      { reservation: 'r' + i }), { now: 2000, cap: 100 }));
  }
  const raced = await Promise.all(race);
  t.check(raced.filter(function (a) { return a.claimed; }).length === 1,
          label + '16. TWENTY-FIVE CONCURRENT CLAIMS OF ONE ASSERTION: ONE ' +
          'ACCEPTED', raced.filter(function (a) {
            return a.claimed;
          }).length + ' accepted');
  const reuse = await ops.claimUsedAssertion(assertion('a1',
    { reservation: 'later', usedAt: 20000, expiresAt: 30000 }),
  { now: 20000, cap: 100 });
  const full = await ops.claimUsedAssertion(assertion('a2'),
                                            { now: 20000, cap: 1 });
  t.check(reuse.claimed && !full.claimed && full.existing === null &&
          full.live === 1,
          label + '17. an expired row is replaced; a full realm refuses ' +
          'with no row', JSON.stringify([reuse, full]));
  const spent = await ops.settleUsedAssertion('r', 'a1', 'later', true,
                                              20001);
  const wrong = await ops.settleUsedAssertion('r', 'a1', 'nobody', true,
                                              20001);
  const keptSpent = await ops.settleUsedAssertion('r', 'a1', 'later', false,
                                                  0);
  const found = await ops.findUsedAssertion('r', 'a1', 20000);
  t.check(spent === 1 && wrong === 0 && keptSpent === 0 && found &&
          found.state === 'spent' && found.spentAt === 20001,
          label + '18. a settle is pinned to its reservation, and a spent ' +
          'row is not released', JSON.stringify([spent, wrong, keptSpent,
                                                found]));
  await ops.claimUsedAssertion(assertion('pct', { identifier: '50%_OFF',
    issuer: 'Other', usedAt: 20002, expiresAt: 30000 }),
  { now: 20000, cap: 100 });
  const listed = await ops.listUsedAssertions('r', { now: 20000,
                                                     q: '50%_off' });
  const all = await ops.listUsedAssertions('r', { now: 20000, limit: 1 });
  const byState = await ops.listUsedAssertions('r', { now: 20000,
                                                      state: 'spent' });
  t.check(listed.total === 1 && listed.rows[0].identifier === '50%_OFF' &&
          all.rows.length === 1 && all.rows[0].identifier === '50%_OFF' &&
          all.total === 2 && all.live === 2 && byState.total === 1,
          label + '19. the list searches case-blind by substring (a % is a ' +
          'character), newest first, with its counts',
          JSON.stringify([listed, all.total, all.live, byState.total]));
  const swept = await ops.purgeUsedAssertions(20000);
  const removed = await ops.removeUsedAssertions('r');
  t.check(swept === 1 && removed === 2,
          label + '20. the sweep takes the expired rows and a realm\'s ' +
          'removal the rest', JSON.stringify([swept, removed]));
  // ---- report artifacts ----------------------------------------------
  const bytes = Buffer.from([0, 1, 2, 255, 39, 92, 34]);
  await ops.putReportArtifact({ realm: 'r', jobId: 'j1', bytes: bytes,
                                sha256: 'h1', mediaType: 'text/csv',
                                createdAt: 5 });
  await ops.putReportArtifact({ realm: 'r', jobId: 'j1', bytes: bytes,
                                sha256: 'h2', mediaType: 'text/csv',
                                createdAt: 6 });
  const artifact = await ops.getReportArtifact({ realm: 'r', jobId: 'j1' });
  t.check(artifact && Buffer.compare(artifact.bytes, bytes) === 0 &&
          artifact.sha256 === 'h2' && artifact.createdAt === 6,
          label + '21. an artifact\'s bytes round-trip exactly and a retry ' +
          'replaces it', JSON.stringify(artifact));
  const count = await ops.putReportArtifactPieces({
    realm: 'r', jobId: 'j2', prefix: 'pieces:', size: 4, sha256: 'h',
    mediaType: 'text/csv', createdAt: 7
  }, piecesOf([Buffer.from([0, 9]), Buffer.from([255, 0])]));
  const piece = await ops.getReportArtifactPiece({ realm: 'r', jobId: 'j2',
                                                   seq: 1 });
  const marker = await ops.getReportArtifact({ realm: 'r', jobId: 'j2' });
  await ops.deleteReportArtifact({ realm: 'r', jobId: 'j2' });
  const leftPieces = await pool.query('SELECT count(*) AS n FROM ' +
                                      'sts_report_artifact_pieces');
  t.check(count === 2 && Buffer.compare(piece, Buffer.from([255, 0])) === 0 &&
          marker.bytes.toString('utf8') === 'pieces:2:4' &&
          await ops.getReportArtifact({ realm: 'r', jobId: 'j2' }) === null &&
          Number(leftPieces.rows[0].n) === 0,
          label + '22. pieces and their row are written in one transaction ' +
          'and deleted together', JSON.stringify([count, marker &&
                                                 marker.bytes.toString()]));
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
  t.log.info('=== B. the contracts against a real PostgreSQL ===');
  const knexStore = require('../persistence/knex_store');
  const schema = 'store_portable_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE SCHEMA ' + schema);
  const scoped = url + (url.indexOf('?') >= 0 ? '&' : '?') +
    'options=' + encodeURIComponent('-c search_path=' + schema);
  const pool = knexStore.openPool({ connectionString: scoped }, { max: 12 });
  try {
    for (const ddl of PG_TABLES) {
      await pool.query(ddl);
    }
    const dialect = sqlDialect.create('postgres');
    await contracts(t, opsOver(dialect, pool), pool, dialect, 'B');
  } finally {
    await pool.end();
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
  t.log.info('=== C. the same contracts against a real MariaDB ===');
  const knexStore = require('../persistence/knex_store');
  const schemaMariadb = require('../persistence/schema_mariadb');
  const scratch = 'store_portable_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE DATABASE ' + scratch);
  const scoped = url.replace(/\/[^/?]*(\?|$)/, '/' + scratch + '$1');
  const pool = knexStore.openPool({ connectionString: scoped }, { max: 12 });
  try {
    for (const object of schemaMariadb.SCHEMA_OBJECTS) {
      if (TABLES.indexOf(object.name) >= 0) {
        await pool.query(object.statement);
      }
    }
    const modes = await pool.query('SELECT @@innodb_autoinc_lock_mode AS m, ' +
                                   '@@auto_increment_increment AS i');
    t.check(Number(modes.rows[0].m) === 1 && Number(modes.rows[0].i) === 1,
            'C0. the server numbers a multi-row INSERT consecutively ' +
            '(innodb_autoinc_lock_mode 1, increment 1)',
            JSON.stringify(modes.rows[0]));
    const dialect = sqlDialect.create('mariadb');
    const ops = opsOver(dialect, pool);
    await contracts(t, ops, pool, dialect, 'C');
    let refused = null;
    try {
      await ops.mergeKeys('x'.repeat(65), function () {
        return 'm';
      });
    } catch (e) {
      refused = e;
    }
    t.check(!!refused && /STS-STORE-0100/.test(String(refused.message)),
            'C23. a realm longer than its column is refused, never ' +
            'truncated by INSERT IGNORE', refused && refused.message);
  } finally {
    await pool.end();
    await admin.query('DROP DATABASE ' + scratch);
    await admin.end();
  }
  log.debug("Leaving againstMariadb().");
}

async function throughDriver(t) {
  log.debug("Entering throughDriver().");
  const url = process.env.STS_TEST_MARIADB_URL || '';
  if (!url) {
    t.log.info('=== D. skipped: STS_TEST_MARIADB_URL names no database ===');
    log.debug("Leaving throughDriver(). Skipped.");
    return;
  }
  t.log.info('=== D. through the driver, on MariaDB ===');
  const knexStore = require('../persistence/knex_store');
  const schemaMariadb = require('../persistence/schema_mariadb');
  const driverModule = require('../persistence/persistence_postgres');
  const scratch = 'store_driver_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE DATABASE ' + scratch);
  const scoped = url.replace(/\/[^/?]*(\?|$)/, '/' + scratch + '$1');
  const pool = knexStore.openPool({ connectionString: scoped }, { max: 2 });
  let driver = null;
  try {
    for (const object of schemaMariadb.SCHEMA_OBJECTS) {
      if (TABLES.indexOf(object.name) >= 0) {
        await pool.query(object.statement);
      }
    }
    driver = driverModule.create({
      url: scoped + (scoped.indexOf('?') >= 0 ? '&' : '?') +
        'sslmode=require',
      log: log, verifyTls: false, tlsCa: '', poolMax: 4, engine: 'mariadb'
    });
    const mark = driver.committedMark();
    await driver.saveRealms(null, { removed: [], upserts: [{
      row: { id: 'r', name: 'R', createdAt: 1, overrides: { a: 1 } },
      name: true, description: true, set: { a: 1 }, cleared: [],
      whole: true }] });
    await driver.saveRealms(null, { removed: [], upserts: [{
      row: { id: 'r', overrides: {} }, name: false, description: false,
      set: { b: 2 }, cleared: ['a'], whole: false }] });
    await driver.saveOverrides(null, { set: { 'x.y': 'true' },
                                       cleared: [] });
    await driver.saveKeys('r', 'k1');
    const merged = await driver.mergeKeys('r', 'unused', function (c) {
      return c + '+';
    });
    const claimed = await driver.claimUsedAssertion(assertion('d'),
                                                    { now: 2, cap: 10 });
    const realms = await driver.loadRealms();
    const since = driver.committedSince(mark);
    const logged = await pool.query('SELECT seq, kind FROM sts_changes ' +
                                    'ORDER BY seq');
    t.check(JSON.stringify(realms[0].overrides) === '{"b":2}' &&
            merged.material === 'k1+' && claimed.claimed &&
            (await driver.loadOverrides())['x.y'] === 'true' &&
            await driver.replicaLagMs() === null &&
            logged.rows.map(function (r) {
              return r.kind;
            }).join() === 'realms,realms,appconfig,keys,keys' &&
            since.other === true,
            'D1. the driver on MariaDB sends this family through the ' +
            'library, and its change rows are written in its transactions ' +
            'and counted at their commit', JSON.stringify([realms, merged,
                                                          logged.rows]));
  } finally {
    if (driver && typeof driver.close === 'function') {
      await driver.close();
    }
    await pool.end();
    await admin.query('DROP DATABASE ' + scratch);
    await admin.end();
  }
  log.debug("Leaving throughDriver().");
}

async function run(t) {
  log.debug("Entering run().");
  await staticChecks(t);
  await againstPostgres(t);
  await againstMariadb(t);
  await throughDriver(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'store_portable',
  describe: 'the smaller tables\' portable statements: no PostgreSQL ' +
            'syntax on MariaDB, and the native contracts kept against a ' +
            'real database of either engine (#677)',
  run: run
};
