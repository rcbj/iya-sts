// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: cluster_heartbeat_lock.js
//
// ===========================================================================
// A HEARTBEAT THAT CANNOT HANG BEHIND A FENCE (#770).
//
//   A. ALWAYS. The next beat is armed when the previous fires. A renewal
//      that never settles is one heartbeat, logged as not having landed
//      (STS-CLUSTER-0003), and the beat after it starts once that one
//      settles. Inside the lifetime the process does not exit.
//   B. AGAINST POSTGRESQL, when STS_TEST_POSTGRES_URL names one. A share
//      lock on the fence's lock row does not delay the heartbeat or the
//      origin renewal. A share lock on the lease row itself does, and the
//      heartbeat rejects inside its bound instead of answering that the
//      membership is dead.
// ===========================================================================

delete process.env.CONFIG_FILE;

const cluster = require('../cluster/cluster');
const log = require('bunyan').createLogger({ name: 'cluster_heartbeat_lock',
  level: process.env.LOG_LEVEL || 'info' });

const VARIED = ['STS_CLUSTER_MODE', 'STS_MODE', 'STS_PERSISTENCE_MODE',
                'STS_CLUSTER_HEARTBEAT_MS', 'STS_CLUSTER_NODE_TTL_MS',
                'STS_AUTHN_ALLOW_OPTIONAL_SECOND_FACTOR',
                'STS_ADMIN_LOG_BOOTSTRAP_PASSWORD',
                'STS_OAUTH2_ALLOW_CONFIDENTIAL_WITHOUT_PKCE',
                'STS_CRYPTO_ALLOW_LEGACY_HASHES',
                'STS_SECURITY_ALLOW_UNSCOPED_PEOPLE',
                'STS_ADMIN_ALLOW_DEFAULT_USERNAME'];
const saved = {};

function setEnv(values) {
  log.debug("Entering setEnv().");
  VARIED.forEach(function (name) {
    if (!(name in saved)) {
      saved[name] = process.env[name];
    }
    if (values && Object.prototype.hasOwnProperty.call(values, name)) {
      process.env[name] = values[name];
    } else {
      delete process.env[name];
    }
  });
  log.debug("Leaving setEnv().");
}

function restoreEnv() {
  log.debug("Entering restoreEnv().");
  Object.keys(saved).forEach(function (name) {
    if (saved[name] === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = saved[name];
    }
  });
  log.debug("Leaving restoreEnv().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function productEnv() {
  log.debug("Entering productEnv().");
  log.debug("Leaving productEnv().");
  return {
    STS_MODE: 'product',
    STS_PERSISTENCE_MODE: 'postgres',
    STS_CLUSTER_HEARTBEAT_MS: '250',
    STS_CLUSTER_NODE_TTL_MS: '10000',
    STS_AUTHN_ALLOW_OPTIONAL_SECOND_FACTOR: 'true',
    STS_ADMIN_LOG_BOOTSTRAP_PASSWORD: 'true',
    STS_OAUTH2_ALLOW_CONFIDENTIAL_WITHOUT_PKCE: 'true',
    STS_CRYPTO_ALLOW_LEGACY_HASHES: 'true',
    STS_SECURITY_ALLOW_UNSCOPED_PEOPLE: 'true',
    STS_ADMIN_ALLOW_DEFAULT_USERNAME: 'true'
  };
}

function clusterDriver(script) {
  log.debug("Entering clusterDriver().");
  const s = script || {};
  log.debug("Leaving clusterDriver().");
  return {
    joinCluster: function () {
      log.debug("Entering joinCluster().");
      log.debug("Leaving joinCluster().");
      return Promise.resolve({ joined: true, differing: [], live: 0 });
    },
    acquireLease: function () {
      log.debug("Entering acquireLease().");
      log.debug("Leaving acquireLease().");
      return Promise.resolve({ held: true, token: 7 });
    },
    heartbeat: function () {
      log.debug("Entering heartbeat().");
      log.debug("Leaving heartbeat().");
      return s.heartbeat ? s.heartbeat() : Promise.resolve({
        alive: true, leases: [{ name: 'service', token: 7 }] });
    },
    agreeFingerprint: function () {
      log.debug("Entering agreeFingerprint().");
      log.debug("Leaving agreeFingerprint().");
      return Promise.resolve({ differing: [] });
    },
    leaveCluster: function () {
      log.debug("Entering leaveCluster().");
      log.debug("Leaving leaveCluster().");
      return Promise.resolve(true);
    }
  };
}

async function scheduling(t) {
  log.debug("Entering scheduling().");
  t.log.info('=== A. a heartbeat that has not finished is still seen ===');
  setEnv(productEnv());
  const exits = [];
  cluster.reset({ exit: function (code) { exits.push(String(code)); } });
  let calls = 0;
  let settle = null;
  const driver = clusterDriver({
    heartbeat: function () {
      calls += 1;
      if (calls === 1) {
        return new Promise(function (resolve, reject) {
          settle = { resolve: resolve, reject: reject };
        });
      }
      return Promise.resolve({
        alive: true, leases: [{ name: 'service', token: 7 }] });
    }
  });
  try {
    await cluster.gate(driver);
    await sleep(1500);
    const pending = String((cluster.status() || {}).lastHeartbeatError || '');
    t.equal(exits.length, 0,
            'a renewal that has not finished does not exit inside the ' +
            'lifetime');
    t.equal(calls, 1,
            'a second beat is not started while the first is still running');
    t.check(/not finished/.test(pending),
            'the unsettled renewal is logged as a heartbeat that did not ' +
            'land', pending);
    settle.reject(new Error('the renewal was cancelled'));
    await sleep(600);
    t.equal(exits.length, 0,
            'one rejected beat inside the lifetime does not exit');
    t.check(calls >= 2,
            'the next tick starts another beat once the hung one settled',
            String(calls));
  } finally {
    if (settle) {
      settle.reject(new Error('the test finished'));
      settle = null;
    }
    await sleep(30);
    cluster.reset({ exit: function () {} });
    restoreEnv();
  }
  log.debug("Leaving scheduling().");
}

// The four tables the heartbeat, the lease and the origin claim touch.
const DDL = [
  'CREATE TABLE sts_cluster_nodes (node_id text PRIMARY KEY, name text ' +
    'NOT NULL DEFAULT \'\', mode text NOT NULL DEFAULT \'\', version text ' +
    'NOT NULL DEFAULT \'\', fingerprint text NOT NULL DEFAULT \'\', ' +
    'started_at bigint NOT NULL DEFAULT 0, heartbeat_at bigint NOT NULL ' +
    'DEFAULT 0, expires_at bigint NOT NULL, left_at bigint NOT NULL ' +
    'DEFAULT 0, info jsonb NOT NULL DEFAULT \'{}\')',
  'CREATE TABLE sts_cluster_leases (name text PRIMARY KEY, holder text ' +
    'NOT NULL, token bigint NOT NULL, acquired_at bigint NOT NULL, ' +
    'expires_at bigint NOT NULL)',
  'CREATE TABLE sts_cluster_claims (scope text NOT NULL, realm text NOT ' +
    'NULL, key text NOT NULL, reservation text NOT NULL, origin text NOT ' +
    'NULL DEFAULT \'\', claimed_at bigint NOT NULL, expires_at bigint NOT ' +
    'NULL, PRIMARY KEY (scope, realm, key))',
  'CREATE TABLE sts_cluster_locks (name text PRIMARY KEY)'
];

function qualify(schema, statement) {
  log.debug("Entering qualify().");
  log.debug("Leaving qualify().");
  return statement.replace(/CREATE TABLE /g, 'CREATE TABLE ' + schema + '.');
}

async function holdShare(pool, sql, params) {
  log.debug("Entering holdShare().");
  const client = await pool.connect();
  await client.query('BEGIN');
  await client.query(sql, params);
  log.debug("Leaving holdShare().");
  return client;
}

async function rollback(client) {
  log.debug("Entering rollback().");
  if (client) {
    try {
      await client.query('ROLLBACK');
    } catch (e) {
      log.debug("Caught in rollback(): " + ((e && e.message) || e));
    }
    client.release();
  }
  log.debug("Leaving rollback().");
}

async function againstPostgres(t) {
  log.debug("Entering againstPostgres().");
  const url = process.env.STS_TEST_POSTGRES_URL || '';
  if (!url) {
    t.log.info('=== B. skipped: STS_TEST_POSTGRES_URL names no database ===');
    log.debug("Leaving againstPostgres(). Skipped.");
    return;
  }
  t.log.info('=== B. the heartbeat does not queue behind the fence ===');
  const postgres = require('../persistence/persistence_postgres');
  const knexStore = require('../persistence/knex_store');
  const schema = 'hb770_' + process.pid + '_' + Date.now();
  const nodeId = 'hb770-' + process.pid + '-' + Date.now();
  const lease = 'hb770lease';
  const scoped = url + (url.indexOf('?') >= 0 ? '&' : '?') +
    'options=' + encodeURIComponent('-c search_path=' + schema);
  const dialled = postgres.dialOptions(scoped, false, '');
  if (dialled.refused) {
    throw new Error('the scratch URL was refused: ' + dialled.refused);
  }
  const admin = knexStore.openConnection({ connectionString: url });
  await admin.connect();
  const probe = knexStore.openPool({
    connectionString: dialled.connectionString, ssl: dialled.ssl
  }, { max: 4 });
  let driver = null;
  let holder = null;
  try {
    await admin.query('CREATE SCHEMA ' + schema);
    for (const statement of DDL) {
      await admin.query(qualify(schema, statement));
    }
    const shown = await probe.query('SHOW search_path');
    const path = String((shown.rows[0] || {}).search_path || '');
    if (path.indexOf(schema) < 0) {
      throw new Error('search_path is "' + path + '", which does not ' +
                      'include ' + schema);
    }
    await probe.query(
      'INSERT INTO sts_cluster_nodes (node_id, mode, started_at, ' +
      'heartbeat_at, expires_at) VALUES ($1, \'active-passive\', ' +
      '(extract(epoch from clock_timestamp()) * 1000)::bigint, ' +
      '(extract(epoch from clock_timestamp()) * 1000)::bigint, ' +
      '(extract(epoch from clock_timestamp()) * 1000)::bigint + 120000)',
      [nodeId]);
    driver = postgres.create({
      url: scoped,
      log: { debug: function () {}, info: function () {},
             warn: function () {}, error: function () {} }
    });
    const acquired = await driver.acquireLease(lease, nodeId, 60000);
    t.check(acquired.held === true,
            'B1. the node takes the lease', JSON.stringify(acquired));
    const lockName = 'fence:lease:' + lease + ':' + acquired.token;
    const before = await probe.query(
      'SELECT expires_at FROM sts_cluster_leases WHERE name = $1', [lease]);
    holder = await holdShare(probe,
      'SELECT name FROM sts_cluster_locks WHERE name = $1 FOR SHARE',
      [lockName]);
    const started = Date.now();
    const beat = await driver.heartbeat(nodeId, 6000, { up: true });
    const waited = Date.now() - started;
    const after = await probe.query(
      'SELECT expires_at FROM sts_cluster_leases WHERE name = $1', [lease]);
    t.check(beat && beat.alive === true && waited < 1500 &&
            Number(after.rows[0].expires_at) !==
              Number(before.rows[0].expires_at),
            'B2. a share lock on the fence row does not delay the ' +
            'heartbeat, and the lease expiry moves',
            JSON.stringify({ waited: waited, beat: beat }));
    await rollback(holder);
    holder = null;

    const adopted = await driver.adoptOrigin({
      name: nodeId + ':front', ttlMs: 60000, waitMs: 0, nodeId: nodeId
    });
    t.check(adopted.adopted === true,
            'B3. the process takes its origin', JSON.stringify(adopted));
    const claim = await probe.query(
      'SELECT key, reservation FROM sts_cluster_claims WHERE scope = $1',
      ['persistence.origin']);
    const row = claim.rows[0];
    const originLock = 'fence:origin:' + row.key + ':' + row.reservation;
    const originBefore = await probe.query(
      'SELECT expires_at FROM sts_cluster_claims WHERE scope = $1',
      ['persistence.origin']);
    holder = await holdShare(probe,
      'SELECT name FROM sts_cluster_locks WHERE name = $1 FOR SHARE',
      [originLock]);
    const renewStarted = Date.now();
    const renewed = await driver.renewOrigin(60000);
    const renewWaited = Date.now() - renewStarted;
    const originAfter = await probe.query(
      'SELECT expires_at FROM sts_cluster_claims WHERE scope = $1',
      ['persistence.origin']);
    t.check(renewed === true && renewWaited < 1500 &&
            Number(originAfter.rows[0].expires_at) !==
              Number(originBefore.rows[0].expires_at),
            'B4. a share lock on the origin\'s fence row does not delay ' +
            'the renewal',
            JSON.stringify({ waited: renewWaited, renewed: renewed }));
    await rollback(holder);
    holder = null;

    holder = await holdShare(probe,
      'SELECT name FROM sts_cluster_leases WHERE name = $1 FOR SHARE',
      [lease]);
    const blockedAt = Date.now();
    let rejected = null;
    try {
      rejected = await driver.heartbeat(nodeId, 6000, null);
    } catch (e) {
      rejected = e;
    }
    const blocked = Date.now() - blockedAt;
    const code = rejected && rejected.code ? String(rejected.code) : '';
    t.check(rejected instanceof Error && /^(55P03|57014)$/.test(code) &&
            blocked < 4000,
            'B5. a share lock on the lease row rejects the heartbeat ' +
            'inside its bound, and the answer is not a dead membership',
            JSON.stringify({
              blocked: blocked, code: code,
              alive: rejected && rejected.alive,
              message: rejected && rejected.message
            }));
  } finally {
    await rollback(holder);
    if (driver) {
      try {
        await driver.close();
      } catch (e) {
        log.debug("Caught in againstPostgres(): " + ((e && e.message) || e));
      }
    }
    try {
      const leaked = await admin.query(
        'SELECT node_id FROM public.sts_cluster_nodes WHERE node_id = $1',
        [nodeId]);
      if (leaked.rows.length) {
        await admin.query(
          'DELETE FROM public.sts_cluster_leases WHERE holder = $1',
          [nodeId]);
        await admin.query(
          'DELETE FROM public.sts_cluster_nodes WHERE node_id = $1',
          [nodeId]);
        t.check(false,
                'the scratch schema was not used; rows in public were ' +
                'removed', nodeId);
      }
    } catch (e) {
      if (!(e && e.code === '42P01')) {
        log.debug("Caught in againstPostgres(): " + ((e && e.message) || e));
        throw e;
      }
    }
    await probe.end();
    await admin.query('DROP SCHEMA ' + schema + ' CASCADE');
    await admin.end();
  }
  log.debug("Leaving againstPostgres().");
}

async function run(t) {
  log.debug("Entering run().");
  await scheduling(t);
  await againstPostgres(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'cluster_heartbeat_lock',
  describe: 'a heartbeat does not hang behind a fence\'s share lock (#770)',
  run: run
};
