// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// @ts-check
'use strict';

// ===========================================================================
// THE CLIENT CERTIFICATE THE DATABASE CONNECTION PRESENTS (#2254, ASVS 5.0.0
// 12.3.5).
//
// `persistence.databaseTlsClientCertFile` and `…KeyFile` name a PEM
// certificate and its key, and every dialler presents them. This file holds
// the service to that:
//
//   A. OFF BY DEFAULT. Both empty, `databaseTlsClient()` is null and the
//      `ssl` option carries no `cert` and no `key`: today's connection.
//   B. APPLIED TO EVERY DIALLER. `databaseTlsClient()` answers the pair;
//      `dialOptions()` puts it on `ssl` for PostgreSQL and MariaDB; a driver
//      built with it hands it to its pools and to the directory bridge's
//      thread (and verify-ca's rewritten options survive structured
//      cloning); `databaseConnection()` hands it to the out-of-process
//      tools; and Knex's own connection settings carry it for both engines.
//   C. REFUSED WHEN UNUSABLE, under STS-STORE-0180: one of the two set
//      without the other, a file that does not exist, a key that is not the
//      certificate's, an encrypted key, a file with no certificate — from
//      `databaseTlsClient()` and as `databaseConnection()`'s rejection.
//   D. READ AGAIN. A renewed pair on disk reaches every driver that presents
//      it, once; an unchanged one is not handed again; a broken one changes
//      nothing (STS-STORE-0181). The driver's `useClientCertificate()` hands
//      the new options to its writer's pools through `StorePool.setSsl()`,
//      which replaces Knex's connection settings for new connections.
//   E. SAID. `describeDatabase()` reports `clientCertificate` and the file,
//      and its Transport sentence says it; an unusable pair is NOT DIALLED.
//   F. A REAL POSTGRESQL, when STS_TEST_PG_CLIENT_CERT_URL names one that
//      requires a client certificate for its user (pg_hba `cert`): the
//      connection opens with the pair and is refused without it. The
//      variables are set by whoever started that database
//      (postgres/generate-tls.sh's POSTGRES_CLIENT_CERT makes one); skipped
//      otherwise.
//   G. A REAL MARIADB, when STS_TEST_MARIADB_CLIENT_CERT_URL names one whose
//      user is `REQUIRE X509`: the same, over the MariaDB engine.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): every case but F
// chooses how the process was started and none needs a database. The key
// material is MADE HERE, at run time (no key material in git).
// ===========================================================================

delete process.env.CONFIG_FILE;

const storeDouble = require('./tools/store_double');
const fs = require('fs');
const os = require('os');
const path = require('path');

const persistence = require('../persistence/persistence');
const postgres = require('../persistence/persistence_postgres');
const knexStore = require('../persistence/knex_store');
const stsCrypto = require('../common/crypto');

const log = require('bunyan').createLogger({
  name: 'database_client_certificate',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// Every setting this file moves is restart-only, so it moves through the
// environment, which `config.value()` reads on every call.
const VARS = ['STS_DATABASE_TLS_CLIENT_CERT_FILE',
              'STS_DATABASE_TLS_CLIENT_KEY_FILE',
              'STS_DATABASE_TLS_CA_FILE', 'STS_DATABASE_URL',
              'STS_DATABASE_PASSWORD_PROVIDER'];

function withEnvironment(values, fn) {
  log.debug("Entering withEnvironment().");
  const before = {};
  VARS.forEach(function (name) {
    before[name] = process.env[name];
    delete process.env[name];
  });
  Object.keys(values).forEach(function (name) {
    process.env[name] = values[name];
  });
  log.debug("Leaving withEnvironment().");
  return Promise.resolve()
    .then(fn)
    .finally(function () {
      VARS.forEach(function (name) {
        if (before[name] === undefined) {
          delete process.env[name];
        } else {
          process.env[name] = before[name];
        }
      });
    });
}

// What a call threw, or a promise rejected with, as text; '' when it did not.
async function refusalOf(fn) {
  log.debug("Entering refusalOf().");
  try {
    await fn();
  } catch (e) {
    log.debug("Caught in refusalOf(): " + ((e && e.message) || e));
    log.debug("Leaving refusalOf(). Refused.");
    return String((e && e.message) || e);
  }
  log.debug("Leaving refusalOf(). Did not refuse.");
  return '';
}

// A driver over stand-in pools that record every `setSsl()`; nothing is
// dialled.
function driverWith(url, tlsClient, pools) {
  log.debug("Entering driverWith().");
  function FakePool(settings) {
    this.settings = settings;
    this.ssls = [];
    pools.push(this);
  }
  FakePool.prototype.on = function () {};
  FakePool.prototype.query = function () {
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  FakePool.prototype.setSsl = function (ssl) {
    this.ssls.push(ssl);
  };
  FakePool.prototype.setConnectionString = function () {};
  FakePool.prototype.onCreateFailure = function () {};
  const restore = storeDouble.install({ Pool: FakePool,
                                        Client: function () {} });
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({ url: url, log: QUIET, verifyTls: true,
                             tlsCa: '', tlsClient: tlsClient });
  } finally {
    restore();
  }
}

// A fresh pair in `dir`, named `name`.crt and `name`.key.
function pairIn(dir, name, cn) {
  log.debug("Entering pairIn().");
  const made = stsCrypto.selfSignedRsaCertificate({ commonName: cn });
  const certFile = path.join(dir, name + '.crt');
  const keyFile = path.join(dir, name + '.key');
  fs.writeFileSync(certFile, made.certPem);
  fs.writeFileSync(keyFile, made.privateKeyPem, { mode: 0o600 });
  log.debug("Leaving pairIn().");
  return { made: made, certFile: certFile, keyFile: keyFile };
}

async function offByDefault(t) {
  log.debug("Entering offByDefault().");
  await withEnvironment({}, async function () {
    t.equal(persistence.databaseTlsClient(), null,
            'A. with both settings empty there is no client certificate');
    const dial = postgres.dialOptions('postgres://db/sts?sslmode=require',
                                      true, '');
    t.check(!('cert' in dial.ssl) && !('key' in dial.ssl),
            'and the ssl option carries no cert and no key: the ' +
            'password-only connection of every release before',
            JSON.stringify(Object.keys(dial.ssl)));
    const connection = await persistence.databaseConnection();
    t.equal(connection.tlsClient, null,
            'and databaseConnection() hands a tool no pair');
  });
  log.debug("Leaving offByDefault().");
}

async function applied(t, pair) {
  log.debug("Entering applied().");
  const env = { STS_DATABASE_TLS_CLIENT_CERT_FILE: pair.certFile,
                STS_DATABASE_TLS_CLIENT_KEY_FILE: pair.keyFile,
                STS_DATABASE_URL: 'postgres://sts_app@postgres:5432/sts' +
                                  '?sslmode=verify-full' };
  await withEnvironment(env, async function () {
    const read = persistence.databaseTlsClient();
    t.check(read && /-----BEGIN CERTIFICATE-----/.test(read.cert) &&
            read.key === pair.made.privateKeyPem &&
            read.certFile === pair.certFile,
            'B. databaseTlsClient() answers the certificate and the key ' +
            'the files hold');
    const client = { cert: read.cert, key: read.key };
    const dial = postgres.dialOptions(
      'postgres://sts_app@postgres/sts?sslmode=verify-full', true, '',
      'postgres', client);
    t.check(dial.ssl.cert === read.cert && dial.ssl.key === read.key &&
            dial.verifyHostname === true,
            'dialOptions() puts them on the ssl option as cert and key, ' +
            'beside the server verification it always did');
    const maria = postgres.dialOptions('mariadb://sts_app@db/sts', true, '',
                                       'mariadb', client);
    t.check(maria.ssl.cert === read.cert && maria.ssl.key === read.key,
            'and for a MariaDB string too');
    const pools = [];
    const driver = driverWith(
      'postgres://sts_app@postgres:5432/sts?sslmode=verify-full', client,
      pools);
    t.check(pools.length >= 2 && pools.every(function (p) {
      return p.settings.ssl && p.settings.ssl.cert === read.cert &&
             p.settings.ssl.key === read.key;
    }), 'a driver built with them dials every pool it opens with them ' +
        '(the writer\'s, the tally pool), and so every connection those ' +
        'pools make, the LISTEN and liveness ones included',
    String(pools.length));
    t.equal(driver.presentsClientCertificate(), true,
            'and says it presents one');
    const bridged = driver.bridgeConnection();
    t.check(bridged.ssl && bridged.ssl.cert === read.cert &&
            bridged.ssl.key === read.key && bridged.ssl.checkHost ===
            'postgres' && bridged.ssl.checkServerIdentity === undefined,
            'it hands the pair to the directory bridge\'s thread as data');
    t.check(knexStore.restoredSsl(bridged.ssl).cert === read.cert &&
            knexStore.restoredSsl(bridged.ssl).key === read.key,
            'and the thread\'s restoredSsl() keeps it');
    const caBridged = driverWith(
      'postgres://sts_app@postgres:5432/sts?sslmode=verify-ca', client,
      []).bridgeConnection();
    let cloned = null;
    try {
      cloned = structuredClone(caBridged);
    } catch (e) {
      log.debug("Caught in applied(): " + ((e && e.message) || e));
    }
    t.check(cloned && cloned.ssl && cloned.ssl.cert === read.cert &&
            cloned.ssl.hostnameUnchecked === true,
            'and for verify-ca, whose options are rewritten for the ' +
            'thread, the pair survives the rewrite and structured cloning');
    const connection = await persistence.databaseConnection();
    t.check(connection.tlsClient && connection.tlsClient.cert ===
            read.cert && connection.tlsClient.key === read.key,
            'databaseConnection() hands the pair to a process that is not ' +
            'the service (the risk loader, cell_convert, the bulk import)');

    // Knex's own connection settings, for both engines, and setSsl().
    for (const url of ['postgres://sts_app@db:5432/sts',
                       'mariadb://sts_app@db:3306/sts']) {
      const engine = /^mariadb/.test(url) ? 'mariadb' : 'postgres';
      let pool = null;
      try {
        pool = knexStore.openPool({ connectionString: url,
                                    ssl: postgres.dialOptions(url, true, '',
                                      engine, client).ssl },
                                  { max: 1 });
      } catch (e) {
        log.debug("Caught in applied(): " + ((e && e.message) || e));
        t.log.info('B. ' + engine + ': its driver is not installed here (' +
                   ((e && e.message) || e) + '); its settings are not ' +
                   'asserted');
        continue;
      }
      const held = pool.knex.client.connectionSettings;
      t.check(held && held.ssl && held.ssl.cert === read.cert &&
              held.ssl.key === read.key,
              'Knex dials a new ' + engine + ' connection with the cert ' +
              'and key on its ssl option');
      const renewed = pairIn(path.dirname(pair.certFile), 'renewed-' +
                             engine, 'sts_app');
      pool.setSsl(postgres.dialOptions(url, true, '', engine,
        { cert: renewed.made.certPem, key: renewed.made.privateKeyPem })
        .ssl);
      const after = pool.knex.client.connectionSettings;
      t.check(after.ssl.cert === renewed.made.certPem &&
              after.ssl.key === renewed.made.privateKeyPem &&
              (engine === 'mariadb' ? after.user === 'sts_app'
                : after.connectionString === url),
              'and after setSsl() the next ' + engine + ' connection ' +
              'presents the renewed pair, with the rest of its settings ' +
              'kept');
      await pool.end();
    }
  });
  log.debug("Leaving applied().");
}

async function refusals(t, dir, pair) {
  log.debug("Entering refusals().");
  const other = pairIn(dir, 'other', 'someone-else');
  const encrypted = path.join(dir, 'encrypted.key');
  fs.writeFileSync(encrypted, '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
                   'AAAA\n-----END ENCRYPTED PRIVATE KEY-----\n');
  const notACert = path.join(dir, 'not-a-cert.pem');
  fs.writeFileSync(notACert, pair.made.privateKeyPem);
  const cases = [
    ['only the certificate set', { STS_DATABASE_TLS_CLIENT_CERT_FILE:
                                     pair.certFile }, /is not; a certificate/],
    ['only the key set', { STS_DATABASE_TLS_CLIENT_KEY_FILE: pair.keyFile },
     /is not; a certificate/],
    ['a certificate file that does not exist',
     { STS_DATABASE_TLS_CLIENT_CERT_FILE: path.join(dir, 'missing.crt'),
       STS_DATABASE_TLS_CLIENT_KEY_FILE: pair.keyFile },
     /cannot be read \(ENOENT\)/],
    ['a key that is not the certificate\'s',
     { STS_DATABASE_TLS_CLIENT_CERT_FILE: pair.certFile,
       STS_DATABASE_TLS_CLIENT_KEY_FILE: other.keyFile },
     /is not the private half of the certificate/],
    ['an encrypted key',
     { STS_DATABASE_TLS_CLIENT_CERT_FILE: pair.certFile,
       STS_DATABASE_TLS_CLIENT_KEY_FILE: encrypted },
     /the private key is encrypted/],
    ['a certificate file holding no certificate',
     { STS_DATABASE_TLS_CLIENT_CERT_FILE: notACert,
       STS_DATABASE_TLS_CLIENT_KEY_FILE: pair.keyFile },
     /holds no PEM CERTIFICATE block/]
  ];
  for (const one of cases) {
    await withEnvironment(Object.assign({
      STS_DATABASE_URL: 'postgres://sts_app@postgres/sts' }, one[1]),
    async function () {
      const why = await refusalOf(function () {
        return persistence.databaseTlsClient();
      });
      t.check(/STS-STORE-0180/.test(why) && one[2].test(why),
              'C. ' + one[0] + ' is refused under STS-STORE-0180, saying ' +
              'why', why);
      const rejected = await refusalOf(function () {
        return persistence.databaseConnection();
      });
      t.check(/STS-STORE-0180/.test(rejected),
              'and databaseConnection() rejects with it');
    });
  }
  log.debug("Leaving refusals().");
}

async function rotation(t, dir) {
  log.debug("Entering rotation().");
  const live = pairIn(dir, 'live', 'sts_app');
  const env = { STS_DATABASE_TLS_CLIENT_CERT_FILE: live.certFile,
                STS_DATABASE_TLS_CLIENT_KEY_FILE: live.keyFile };
  await withEnvironment(env, async function () {
    const first = persistence.databaseTlsClient();
    const given = [[], []];
    const doubles = given.map(function (seen) {
      return { useClientCertificate: function (pair) {
        seen.push(pair);
        return { ok: true };
      } };
    });
    persistence.setCertificateDriversForTest(doubles,
                                             first.cert + first.key);
    const unchanged = await persistence.refreshDatabaseCertificate('a test');
    t.check(unchanged.read && !unchanged.changed && given[0].length === 0,
            'D. an unchanged pair on disk is read and handed to nobody');
    const renewed = stsCrypto.selfSignedRsaCertificate({
      commonName: 'sts_app' });
    fs.writeFileSync(live.certFile, renewed.certPem);
    fs.writeFileSync(live.keyFile, renewed.privateKeyPem);
    const changed = await persistence.refreshDatabaseCertificate('a test');
    t.check(changed.changed && given.every(function (seen) {
      return seen.length === 1 &&
        seen[0].key === renewed.privateKeyPem &&
        seen[0].cert.indexOf(renewed.certB64.slice(0, 64)) >= 0;
    }), 'a renewed pair written over the files is handed to every driver ' +
        'that presents it (this database\'s and the global tier\'s)');
    const again = await persistence.refreshDatabaseCertificate('a test');
    t.check(!again.changed && given[0].length === 1,
            'and only once');
    const stranger = stsCrypto.selfSignedRsaCertificate({
      commonName: 'stranger' });
    fs.writeFileSync(live.keyFile, stranger.privateKeyPem);
    const broken = await refusalOf(function () {
      return persistence.refreshDatabaseCertificate('a test');
    });
    t.check(/STS-STORE-0180/.test(broken) && given[0].length === 1,
            'a pair that no longer holds together is refused and changes ' +
            'nothing: the drivers keep presenting the one they hold ' +
            '(logged under STS-STORE-0181)', broken);
    persistence.setCertificateDriversForTest([], '');

    // The driver's own half: the new options reach its pools.
    const pools = [];
    const driver = driverWith('postgres://sts_app@postgres/sts', {
      cert: first.cert, key: first.key }, pools);
    const used = driver.useClientCertificate({ cert: renewed.certPem,
                                               key: renewed.privateKeyPem });
    t.check(used.ok && pools.length >= 2 && pools.every(function (p) {
      return p.ssls.length === 1 && p.ssls[0].cert === renewed.certPem &&
             p.ssls[0].key === renewed.privateKeyPem &&
             p.ssls[0].rejectUnauthorized === true;
    }), 'the driver\'s useClientCertificate() hands every pool of the ' +
        'writer the renewed pair, with the server verification unchanged');
    t.check(driver.bridgeConnection().ssl.cert === renewed.certPem,
            'and a bridge thread started after it is handed the renewed ' +
            'pair');
  });
  log.debug("Leaving rotation().");
}

async function said(t, pair) {
  log.debug("Entering said().");
  await withEnvironment({
    STS_DATABASE_TLS_CLIENT_CERT_FILE: pair.certFile,
    STS_DATABASE_TLS_CLIENT_KEY_FILE: pair.keyFile,
    STS_DATABASE_URL: 'postgres://sts_app@postgres/sts?sslmode=verify-full'
  }, async function () {
    const report = persistence.describeDatabase();
    t.check(report && report.clientCertificate === true &&
            report.clientCertificateFile === pair.certFile &&
            /authenticates to the database with the client certificate/
              .test(report.tls),
            'E. the database\'s status reports the client certificate and ' +
            'its file, and the Transport sentence says it',
            report && report.tls);
    const credential = persistence.databaseCredential();
    t.check(credential && typeof credential.database === 'boolean' &&
            typeof credential.certificate === 'boolean' &&
            typeof credential.password === 'boolean',
            'databaseCredential() answers the three facts /admin/mode ' +
            'draws', JSON.stringify(credential));
  });
  await withEnvironment({
    STS_DATABASE_TLS_CLIENT_CERT_FILE: pair.certFile,
    STS_DATABASE_URL: 'postgres://sts_app@postgres/sts'
  }, async function () {
    const report = persistence.describeDatabase();
    t.check(report && report.clientCertificate === false &&
            report.encrypted === false && /^NOT DIALLED/.test(report.tls),
            'and an unusable pair is said to stop the start, never thrown ' +
            'from the report', report && report.tls);
  });
  log.debug("Leaving said().");
}

async function realPostgres(t) {
  log.debug("Entering realPostgres().");
  const url = process.env.STS_TEST_PG_CLIENT_CERT_URL || '';
  if (!url) {
    t.log.info('=== F. skipped: STS_TEST_PG_CLIENT_CERT_URL names no ' +
               'database ===');
    log.debug("Leaving realPostgres(). Skipped.");
    return;
  }
  t.log.info('=== F. a real PostgreSQL that requires a client ' +
             'certificate ===');
  const env = {
    STS_DATABASE_URL: url,
    STS_DATABASE_TLS_CA_FILE: process.env.STS_TEST_PG_CA_FILE || '',
    STS_DATABASE_TLS_CLIENT_CERT_FILE:
      process.env.STS_TEST_PG_CLIENT_CERT_FILE || '',
    STS_DATABASE_TLS_CLIENT_KEY_FILE:
      process.env.STS_TEST_PG_CLIENT_KEY_FILE || ''
  };
  await withEnvironment(env, async function () {
    require('../common/outbound_tls').installProcessWide();
    const connection = await persistence.databaseConnection();
    t.check(connection.tlsClient && connection.tlsCa,
            'F. databaseConnection() reads the pair and the server\'s CA');
    const ask = async function (client) {
      log.debug("Entering ask().");
      const dial = postgres.dialOptions(connection.url, connection.verifyTls,
                                        connection.tlsCa, 'postgres',
                                        client);
      const pool = knexStore.openPool({ connectionString:
                                          dial.connectionString,
                                        ssl: dial.ssl,
                                        connectionTimeoutMillis: 10000 },
                                      { max: 1 });
      try {
        const r = await pool.query('SELECT current_user AS who');
        log.debug("Leaving ask().");
        return { who: String(((r.rows || [])[0] || {}).who || ''),
                 error: '' };
      } catch (e) {
        log.debug("Caught in ask(): " + ((e && e.message) || e));
        log.debug("Leaving ask(). Refused.");
        return { who: '', error: String((e && e.message) || e) };
      } finally {
        await pool.end();
      }
    };
    const user = decodeURIComponent(new URL(url).username);
    const withPair = await ask(connection.tlsClient);
    t.check(withPair.who === user,
            'with the client certificate the connection opens, as ' + user +
            ', with no password in the string',
            withPair.who || withPair.error);
    const without = await ask(null);
    t.check(!without.who && /certificate|pg_hba|authentication/i
      .test(without.error),
            'and without it the database refuses the connection',
            without.error);
    // The driver itself, opened the way openStore() opens it.
    const driver = postgres.create({ url: connection.url, log: QUIET,
                                     verifyTls: connection.verifyTls,
                                     tlsCa: connection.tlsCa,
                                     tlsClient: connection.tlsClient,
                                     poolMax: 4 });
    const opened = await refusalOf(function () {
      return driver.open();
    });
    t.equal(opened, '', 'and the store driver opens over that connection ' +
            '(its pools, its LISTEN client)');
    await refusalOf(function () {
      return driver.close ? driver.close() : null;
    });
  });
  log.debug("Leaving realPostgres().");
}

async function realMariadb(t) {
  log.debug("Entering realMariadb().");
  const url = process.env.STS_TEST_MARIADB_CLIENT_CERT_URL || '';
  if (!url) {
    t.log.info('=== G. skipped: STS_TEST_MARIADB_CLIENT_CERT_URL names no ' +
               'database ===');
    log.debug("Leaving realMariadb(). Skipped.");
    return;
  }
  t.log.info('=== G. a real MariaDB whose user REQUIRES X509 ===');
  const env = {
    STS_DATABASE_TLS_CLIENT_CERT_FILE:
      process.env.STS_TEST_MARIADB_CLIENT_CERT_FILE || '',
    STS_DATABASE_TLS_CLIENT_KEY_FILE:
      process.env.STS_TEST_MARIADB_CLIENT_KEY_FILE || ''
  };
  await withEnvironment(env, async function () {
    require('../common/outbound_tls').installProcessWide();
    const client = persistence.databaseTlsClient();
    const ca = fs.readFileSync(process.env.STS_TEST_MARIADB_CA_FILE || '',
                               'utf8');
    const ask = async function (pair) {
      log.debug("Entering ask().");
      const dial = postgres.dialOptions(url, true, ca, 'mariadb', pair);
      let pool = null;
      try {
        pool = knexStore.openPool({ connectionString: dial.connectionString,
                                    ssl: dial.ssl,
                                    connectionTimeoutMillis: 10000 },
                                  { max: 1 });
      } catch (e) {
        log.debug("Caught in ask(): " + ((e && e.message) || e));
        log.debug("Leaving ask(). No driver.");
        return { who: '', error: 'mysql2 is not installed here: ' +
                 ((e && e.message) || e) };
      }
      try {
        const r = await pool.query('SELECT CURRENT_USER() AS who');
        log.debug("Leaving ask().");
        return { who: String(((r.rows || [])[0] || {}).who || ''),
                 error: '' };
      } catch (e) {
        log.debug("Caught in ask(): " + ((e && e.message) || e));
        log.debug("Leaving ask(). Refused.");
        return { who: '', error: String((e && e.message) || e) };
      } finally {
        await pool.end();
      }
    };
    const user = decodeURIComponent(new URL(url).username);
    const withPair = await ask(client ? { cert: client.cert,
                                          key: client.key } : null);
    t.check(withPair.who.indexOf(user + '@') === 0,
            'G. with the client certificate the MariaDB connection opens, ' +
            'as ' + user + ', with no password in the string',
            withPair.who || withPair.error);
    const without = await ask(null);
    t.check(!without.who && /denied/i.test(without.error),
            'and without it MariaDB refuses the login', without.error);
  });
  log.debug("Leaving realMariadb().");
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-db-client-cert-'));
  try {
    const pair = pairIn(dir, 'client', 'sts_app');
    await offByDefault(t);
    await applied(t, pair);
    await refusals(t, dir, pair);
    await rotation(t, dir);
    await said(t, pair);
    await realPostgres(t);
    await realMariadb(t);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'database_client_certificate',
  describe: 'the database connection presents the client certificate ' +
            'persistence.databaseTlsClientCertFile names, from every ' +
            'dialler and for both engines; an unusable pair is refused at ' +
            'start under STS-STORE-0180; a renewed one is read again ' +
            'without a restart; and the status reports it',
  run: run
};
