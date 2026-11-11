// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cluster_portable.js
//
// ===========================================================================
// THE CLUSTER'S PORTABLE STATEMENTS (#677): THE SAME CONTRACTS, IN SQL A
// SECOND ENGINE RUNS.
//
//   A. ALWAYS: every portable operation, compiled for MariaDB, carries none
//      of PostgreSQL's syntax — no `$n`, no `::` cast, no `ON CONFLICT`, no
//      `RETURNING`, no double-quoted identifier, no advisory lock. Driven
//      against a runner that records what it is sent and answers what each
//      statement would.
//   C. THE SAME CONTRACTS AGAINST A REAL MARIADB, when STS_TEST_MARIADB_URL
//      names a server the test may create a database on (it makes one and
//      drops it), its tables from `persistence/schema_mariadb.js`.
//   B. AGAINST A REAL DATABASE, only when STS_TEST_POSTGRES_URL names one the
//      test may create tables in (a scratch database: it creates the cluster
//      tables it needs in a schema of its own and drops it): every contract
//      the native statements keep, and the races that make them contracts —
//      twenty concurrent claims of one key, one winner; forty concurrent
//      window counts, forty distinct counts; a counter raised concurrently
//      ends at the highest value; a partial claimMany leaves nothing.
// ===========================================================================

delete process.env.CONFIG_FILE;

const sqlDialect = require('../persistence/sql_dialect');
const clusterPortable = require('../persistence/cluster_portable');

const log = require('bunyan').createLogger({ name: 'cluster_portable',
  level: process.env.LOG_LEVEL || 'info' });

const ORIGIN_SCOPE = 'persistence.origin';

// A runner that records each statement and answers by its name.
function recorder() {
  log.debug("Entering recorder().");
  const sent = [];
  const answer = function (text) {
    const name = (/\/\* sts:portable\.([A-Za-z.]+) \*\//.exec(text) || [])[1] ||
      '';
    if (/\.read$|\.holder$|\.highest$|\.held$|\.low$|\.when$|Fence$|nodeLive$|\.gone$|lock\.take$/
          .test(name)) {
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

// Every operation once, against `ops`.
async function exercise(ops) {
  log.debug("Entering exercise().");
  const held = { key: 'n:node:front', reservation: 'r1' };
  await ops.claimOnce('s', '', 'k', { ttlMs: 1000, reservation: 'r1' });
  await ops.claimMany([{ scope: 's', key: 'b' }, { scope: 's', key: 'a' }],
                      '', { ttlMs: 1000, reservation: 'r2' });
  await ops.releaseClaims(ops.__pool,
    [{ scope: 's', realm: '', key: 'a', reservation: 'r2' }]);
  await ops.takeOverFromGone('n:node:front', 'r3', 'x@node-2', 'node-1',
                             30000);
  const client = await ops.__pool.connect();
  await ops.originFence(client, held);
  await ops.nodeFence(client, 'node-1');
  await ops.leaseFence(client, 'node-1', [{ name: 'service', token: 3 }]);
  await ops.serialize(client, 'cluster.join');
  await ops.heartbeat('node-1', 10000, { a: 1 });
  await ops.leaveCluster('node-1');
  await ops.acquireLease('service', 'node-1', 10000);
  await ops.advanceCounter('webauthn', '', 'cred', 7);
  await ops.countWindow('rl', '', 'ip', 60000);
  await ops.spendBudget('gnap', '', 'g', 1, '5', 1, '10', 3, 99999);
  await ops.reportChangeReader(12, 'node-1');
  await ops.purgeChangeLog({ readerTtlMs: 60000, retentionMs: 3600000 });
  log.debug("Leaving exercise().");
}

function opsOver(dialect, runner) {
  log.debug("Entering opsOver().");
  const ops = clusterPortable.create({
    dialect: dialect, pool: runner, tallyPool: runner, live: runner,
    originScope: ORIGIN_SCOPE,
    processId: function () {
      log.debug("Entering processId().");
      log.debug("Leaving processId().");
      return 'proc-1';
    }
  });
  ops.__pool = runner;
  log.debug("Leaving opsOver().");
  return ops;
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
  t.check(statements.length >= 25,
          'A1. every operation sent its statements', statements.length +
          ' statement(s)');
  const pgOnly = [
    [/\$\d/, 'a $n placeholder'],
    [/::[a-z]/, 'a :: cast'],
    [/\bon conflict\b/i, 'ON CONFLICT'],
    [/\breturning\b/i, 'RETURNING'],
    [/"[a-z_]+"/, 'a double-quoted identifier'],
    [/pg_advisory|pg_notify|split_part|unnest|xmax|clock_timestamp/i,
     'a PostgreSQL function'],
    [/\bfor share\b/i, 'FOR SHARE (MariaDB spells it LOCK IN SHARE MODE)']
  ];
  const offending = [];
  statements.forEach(function (text) {
    pgOnly.forEach(function (rule) {
      if (rule[0].test(text)) {
        offending.push(rule[1] + ' in: ' + text.slice(0, 160));
      }
    });
  });
  t.check(offending.length === 0,
          'A2. NO STATEMENT CARRIES POSTGRESQL\'S SYNTAX', offending.join(
            ' | '));
  t.check(statements.some(function (text) {
    return /^insert ignore into `sts_cluster_claims`/.test(text);
  }), 'A3. a claim is an INSERT IGNORE on MariaDB');
  t.check(statements.some(function (text) {
    return /lock in share mode/.test(text);
  }) && statements.some(function (text) {
    return /`sts_cluster_locks`.* for update/.test(text);
  }), 'A4. the fences share-lock and the join lock is a row FOR UPDATE');
  const lease = statements.filter(function (text) {
    return /sts:portable\.acquireLease\.renew/.test(text);
  })[0] || '';
  t.check(lease.indexOf('`token` =') >= 0 &&
          lease.indexOf('`token` =') < lease.indexOf('`holder` = ?,') ||
          /`expires_at` = [^,]+, `holder` = \? where/.test(lease),
          'A5. the lease\'s holder is assigned LAST, after the CASEs that ' +
          'read it (MariaDB reads an earlier assignment\'s new value)', lease);
  const pg = sqlDialect.create('postgres');
  const pgRunner = recorder();
  await exercise(opsOver(pg, pgRunner));
  t.check(pgRunner.sent.some(function (one) {
    return /on conflict \("scope", "realm", "key"\) do nothing/.test(one.text);
  }), 'A6. on PostgreSQL the same claim is INSERT … ON CONFLICT DO NOTHING');
  log.debug("Leaving staticChecks().");
}

// The cluster tables, in a schema of the test's own.
const TABLES = [
  'CREATE TABLE sts_cluster_claims (scope text NOT NULL, realm text NOT ' +
    'NULL, key text NOT NULL, reservation text NOT NULL, origin text NOT ' +
    'NULL DEFAULT \'\', claimed_at bigint NOT NULL, expires_at bigint NOT ' +
    'NULL, PRIMARY KEY (scope, realm, key))',
  'CREATE TABLE sts_cluster_nodes (node_id text PRIMARY KEY, name text NOT ' +
    'NULL DEFAULT \'\', mode text NOT NULL DEFAULT \'\', version text NOT ' +
    'NULL DEFAULT \'\', fingerprint text NOT NULL DEFAULT \'\', started_at ' +
    'bigint NOT NULL DEFAULT 0, heartbeat_at bigint NOT NULL DEFAULT 0, ' +
    'expires_at bigint NOT NULL, left_at bigint NOT NULL DEFAULT 0, info ' +
    'jsonb NOT NULL DEFAULT \'{}\')',
  'CREATE TABLE sts_cluster_leases (name text PRIMARY KEY, holder text NOT ' +
    'NULL, token bigint NOT NULL, acquired_at bigint NOT NULL, expires_at ' +
    'bigint NOT NULL)',
  'CREATE TABLE sts_cluster_counters (scope text NOT NULL, realm text NOT ' +
    'NULL, key text NOT NULL, value bigint NOT NULL, origin text NOT NULL ' +
    'DEFAULT \'\', updated_at bigint NOT NULL, PRIMARY KEY (scope, realm, ' +
    'key))',
  'CREATE TABLE sts_cluster_windows (scope text NOT NULL, realm text NOT ' +
    'NULL, key text NOT NULL, count bigint NOT NULL, window_ends_at bigint ' +
    'NOT NULL, origin text NOT NULL DEFAULT \'\', PRIMARY KEY (scope, ' +
    'realm, key))',
  'CREATE TABLE sts_cluster_budgets (scope text NOT NULL, realm text NOT ' +
    'NULL, key text NOT NULL, period bigint NOT NULL, amount bigint NOT ' +
    'NULL, count bigint NOT NULL, origin text NOT NULL DEFAULT \'\', ' +
    'expires_at bigint NOT NULL, updated_at bigint NOT NULL, PRIMARY KEY ' +
    '(scope, realm, key))',
  'CREATE TABLE sts_change_readers (origin text PRIMARY KEY, node_id text ' +
    'NOT NULL DEFAULT \'\', applied bigint NOT NULL, started_at bigint NOT ' +
    'NULL, reported_at bigint NOT NULL)',
  'CREATE TABLE sts_changes (seq bigserial PRIMARY KEY, origin text NOT ' +
    'NULL, kind text NOT NULL, realm text NOT NULL DEFAULT \'\', key text ' +
    'NOT NULL DEFAULT \'\', at timestamptz NOT NULL DEFAULT now())',
  'CREATE TABLE sts_cluster_locks (name text PRIMARY KEY)'
];

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
  const schema = 'portable_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE SCHEMA ' + schema);
  const scoped = url + (url.indexOf('?') >= 0 ? '&' : '?') +
    'options=' + encodeURIComponent('-c search_path=' + schema);
  const pool = knexStore.openPool({ connectionString: scoped }, { max: 8 });
  try {
    for (const ddl of TABLES) {
      await pool.query(ddl);
    }
    const dialect = sqlDialect.create('postgres');
    const ops = clusterPortable.create({
      dialect: dialect, pool: pool, tallyPool: pool, live: pool,
      originScope: ORIGIN_SCOPE,
      processId: function () {
        log.debug("Entering processId().");
        log.debug("Leaving processId().");
        return 'proc-1';
      }
    });
    await contracts(t, ops, pool, dialect);
  } finally {
    await pool.end();
    await admin.query('DROP SCHEMA ' + schema + ' CASCADE');
    await admin.end();
  }
  log.debug("Leaving againstPostgres().");
}

async function contracts(t, ops, pool, dialect) {
  log.debug("Entering contracts().");
  // `key` is a reserved word in MariaDB.
  const KEY = dialect.engine === 'mariadb' ? '`key`' : 'key';
  // ---- claims --------------------------------------------------------
  const one = await ops.claimOnce('s', '', 'k', { ttlMs: 60000,
                                                   reservation: 'r1' });
  const two = await ops.claimOnce('s', '', 'k', { ttlMs: 60000,
                                                   reservation: 'r2' });
  t.check(one.claimed && !two.claimed && two.existing,
          'B1. a live claim is won once and refused after, with its holder',
          JSON.stringify([one, two]));
  await pool.query('UPDATE sts_cluster_claims SET expires_at = 1');
  const three = await ops.claimOnce('s', '', 'k', { ttlMs: 60000,
                                                     reservation: 'r3' });
  t.check(three.claimed, 'B2. an EXPIRED claim is taken over',
          JSON.stringify(three));
  const racers = [];
  for (let i = 0; i < 20; i++) {
    racers.push(ops.claimOnce('race', '', 'k', { ttlMs: 60000,
                                                  reservation: 'q' + i }));
  }
  const raced = await Promise.all(racers);
  t.check(raced.filter(function (a) { return a.claimed; }).length === 1,
          'B3. TWENTY CONCURRENT CLAIMS OF ONE KEY: ONE WINNER',
          raced.filter(function (a) { return a.claimed; }).length + ' won');
  const many = await ops.claimMany([{ scope: 'm', key: 'b' },
                                    { scope: 'm', key: 'a' }], '',
                                   { ttlMs: 60000, reservation: 'many1' });
  const overlap = await ops.claimMany([{ scope: 'm', key: 'c' },
                                       { scope: 'm', key: 'a' }], '',
                                      { ttlMs: 60000, reservation: 'many2' });
  const leftC = await pool.query('SELECT 1 FROM sts_cluster_claims WHERE ' +
                                 'scope = \'m\' AND ' + KEY + ' = \'c\'');
  t.check(many.claimed && !overlap.claimed && overlap.refused === 1 &&
          overlap.partial === true && leftC.rows.length === 0,
          'B4. claimMany is all or none: an overlapping set is refused at ' +
          'its first held row and the row it did take is rolled back',
          JSON.stringify([many, overlap, leftC.rows.length]));
  await ops.releaseClaims(pool, [{ scope: 'm', realm: '', key: 'a',
                                   reservation: 'many1' },
                                 { scope: 'm', realm: '', key: 'b',
                                   reservation: 'wrong' }]);
  const kept = await pool.query('SELECT ' + KEY + ' FROM sts_cluster_claims ' +
                                'WHERE scope = \'m\' ORDER BY ' + KEY);
  t.check(kept.rows.map(function (r) { return r.key; }).join() === 'b',
          'B5. a release is pinned to its reservation',
          JSON.stringify(kept.rows));
  // ---- membership, leases, fences, join ------------------------------
  const node = function (id) {
    return '(\'' + id + '\', \'active-active\', 0, 0, ' + dialect.nowText +
      ' + 60000)';
  };
  await pool.query('INSERT INTO sts_cluster_nodes (node_id, mode, ' +
                   'started_at, heartbeat_at, expires_at) VALUES ' +
                   node('node-1') + ', ' + node('node-2'));
  const l1 = await ops.acquireLease('service', 'node-1', 60000);
  const l2 = await ops.acquireLease('service', 'node-2', 60000);
  const l1again = await ops.acquireLease('service', 'node-1', 60000);
  t.check(l1.held && l1.token === 1 && !l2.held && l2.holder === 'node-1' &&
          l1again.held && l1again.token === 1,
          'B6. a lease is taken, refused to another node, and renewed by ' +
          'its holder under the same token', JSON.stringify([l1, l2, l1again]));
  await pool.query('UPDATE sts_cluster_leases SET expires_at = 1');
  const l2take = await ops.acquireLease('service', 'node-2', 60000);
  t.check(l2take.held && l2take.token === 2,
          'B7. an expired lease is taken over with a NEW token — the holder ' +
          'is assigned after the CASE that reads it', JSON.stringify(l2take));
  const beat = await ops.heartbeat('node-2', 60000, { up: true });
  const deadBeat = await ops.heartbeat('node-9', 60000, null);
  t.check(beat.alive && beat.leases.length === 1 &&
          beat.leases[0].token === 2 && !deadBeat.alive,
          'B8. a heartbeat renews the node and reports its leases; an ' +
          'unknown node is not alive', JSON.stringify([beat, deadBeat]));
  const client = await pool.connect();
  await client.query('BEGIN');
  const fenceLeases = await ops.leaseFence(client, 'node-2',
    [{ name: 'service', token: 2 }, { name: 'service', token: 1 }]);
  const fenceNode = await ops.nodeFence(client, 'node-2');
  await client.query('COMMIT');
  client.release();
  t.check(fenceLeases.join() === 'service' && fenceNode,
          'B9. the lease fence keeps only the token still held',
          JSON.stringify(fenceLeases));
  const order = [];
  const joiner = function (name, holdMs) {
    return pool.connect().then(function (c) {
      return c.query('BEGIN').then(function () {
        return ops.serialize(c, 'cluster.join');
      }).then(function () {
        order.push(name + '+');
        return new Promise(function (resolve) {
          setTimeout(resolve, holdMs);
        });
      }).then(function () {
        order.push(name + '-');
        return c.query('COMMIT');
      }).then(function () {
        c.release();
      });
    });
  };
  await Promise.all([joiner('a', 150), joiner('b', 10)]);
  t.check(/^(a\+,a-,b\+,b-|b\+,b-,a\+,a-)$/.test(order.join()),
          'B10. THE JOIN LOCK SERIALISES: the second joiner waits for the ' +
          'first to commit', order.join());
  await ops.leaveCluster('node-2');
  const after = await ops.heartbeat('node-2', 60000, null);
  t.check(!after.alive, 'B11. a node that left is not alive',
          JSON.stringify(after));
  // ---- counters, windows, budgets -------------------------------------
  const up = await ops.advanceCounter('c', '', 'k', 10);
  const down = await ops.advanceCounter('c', '', 'k', 5);
  t.check(up.advanced && !down.advanced && down.highest === 10,
          'B12. a counter only rises', JSON.stringify([up, down]));
  const values = [];
  for (let i = 11; i <= 40; i++) {
    values.push(ops.advanceCounter('c', '', 'race', i));
  }
  await Promise.all(values);
  const top = await pool.query('SELECT value FROM sts_cluster_counters ' +
                               'WHERE ' + KEY + ' = \'race\'');
  t.check(Number(top.rows[0].value) === 40,
          'B13. thirty concurrent raises end at the highest',
          JSON.stringify(top.rows));
  const counts = [];
  for (let i = 0; i < 40; i++) {
    counts.push(ops.countWindow('rl', '', 'ip', 60000));
  }
  const windows = (await Promise.all(counts)).map(function (w) {
    return w.count;
  }).sort(function (a, b) { return a - b; });
  t.check(windows.join() === Array.from({ length: 40 }, function (_, i) {
    return i + 1;
  }).join(), 'B14. FORTY CONCURRENT COUNTS IN ONE WINDOW ARE ONE TO FORTY, ' +
          'each distinct', windows.join());
  await pool.query('UPDATE sts_cluster_windows SET window_ends_at = 1');
  const fresh = await ops.countWindow('rl', '', 'ip', 60000);
  t.check(fresh.count === 1 && fresh.remainingMs > 50000,
          'B15. an ended window starts again at one', JSON.stringify(fresh));
  const b1 = await ops.spendBudget('g', '', 'k', 1, '6', 1, '10', 2, 1000);
  const b2 = await ops.spendBudget('g', '', 'k', 1, '5', 1, '10', 2, 1000);
  const b3 = await ops.spendBudget('g', '', 'k', 2, '5', 1, '10', 2, 2000);
  const b4 = await ops.spendBudget('g', '', 'k', 1, '1', 1, '10', 2, 1000);
  t.check(b1 && b1.amount === '6' && b2 === null && b3 &&
          b3.amount === '5' && b4 === null,
          'B16. a budget adds within its period, refuses past its limit, ' +
          'resets in a newer period and never writes an older one',
          JSON.stringify([b1, b2, b3, b4]));
  // ---- the change log's readers --------------------------------------
  const first = await ops.reportChangeReader(5, 'node-1');
  const again = await ops.reportChangeReader(3, 'node-1');
  const mark = await pool.query('SELECT applied FROM sts_change_readers');
  t.check(first.inserted && !again.inserted &&
          Number(mark.rows[0].applied) === 5,
          'B17. a reader\'s mark is inserted once and never moves back',
          JSON.stringify([first, again, mark.rows]));
  const twoHoursAgo = dialect.engine === 'mariadb'
    ? 'NOW(6) - INTERVAL 2 HOUR' : 'now() - interval \'2 hours\'';
  const old = '(\'o\', \'k\', ' + twoHoursAgo + ')';
  await pool.query('INSERT INTO sts_changes (origin, kind, at) VALUES ' +
                   [old, old, old, old, old, old].join(', '));
  const trim = await ops.purgeChangeLog({ readerTtlMs: 600000,
                                          retentionMs: 3600000 });
  const leftRows = await pool.query('SELECT seq FROM sts_changes ORDER BY ' +
                                    'seq');
  t.check(trim.bound === 5 && trim.trimmed === 4 &&
          leftRows.rows.map(function (r) { return Number(r.seq); }).join() ===
          '5,6',
          'B18. the trim removes only what is below the lowest live mark and ' +
          'older than the retention', JSON.stringify([trim, leftRows.rows]));
  log.debug("Leaving contracts().");
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
  const scratch = 'portable_' + process.pid;
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  await admin.query('CREATE DATABASE ' + scratch);
  const scoped = url.replace(/\/[^/?]*(\?|$)/, '/' + scratch + '$1');
  const pool = knexStore.openPool({ connectionString: scoped }, { max: 8 });
  try {
    const wanted = ['sts_cluster_claims', 'sts_cluster_nodes',
                    'sts_cluster_leases', 'sts_cluster_counters',
                    'sts_cluster_windows', 'sts_cluster_budgets',
                    'sts_change_readers', 'sts_changes', 'sts_cluster_locks'];
    for (const object of schemaMariadb.SCHEMA_OBJECTS) {
      if (wanted.indexOf(object.name) >= 0) {
        await pool.query(object.statement);
      }
    }
    const dialect = sqlDialect.create('mariadb');
    const ops = clusterPortable.create({
      dialect: dialect, pool: pool, tallyPool: pool, live: pool,
      originScope: ORIGIN_SCOPE,
      processId: function () {
        log.debug("Entering processId().");
        log.debug("Leaving processId().");
        return 'proc-1';
      }
    });
    await contracts(t, ops, pool, dialect);
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
  await againstPostgres(t);
  await againstMariadb(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_portable',
  describe: 'the cluster\'s portable statements: no PostgreSQL syntax on ' +
            'MariaDB, and the native contracts kept against a real ' +
            'database (#677)',
  run: run
};
