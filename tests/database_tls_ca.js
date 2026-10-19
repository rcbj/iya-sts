// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// @ts-check
'use strict';

// ===========================================================================
// THE DATABASE'S OWN TRUST ANCHOR, AND VERIFICATION BY DEFAULT (2026-10-12).
//
// rcbj's decision: the PostgreSQL server's certificate is verified BY
// DEFAULT, in every mode (`persistence.databaseTlsRejectUnauthorized` is
// true). The compose stack's certificate is self-signed inside the postgres
// container, so the stack hands it to the service read-only and names it in
// `persistence.databaseTlsCaFile` — a PEM file trusted for the database
// connections ONLY, in place of the default trust store for them. This file
// holds the service to that:
//
//   A. THE DEFAULT IS ON. With nothing set, `verifiesDatabaseTls()` is true
//      and a string with no sslmode, or `require`, verifies the chain and
//      the host name.
//   B. THE CA FILE IS APPLIED. `databaseTlsCa()` answers the file's
//      certificates; `dialOptions()` puts them on the `ssl` option as `ca`;
//      a driver built with them hands them to its read pool and to the
//      directory bridge's thread — for verify-ca too, where the bridge's
//      options are rewritten as data — and the bridge's answer survives
//      structured cloning, as a Worker's data must; and
//      `databaseConnection()` hands them to a process that is not the
//      service (the risk loader, `cell_convert`). A DIRECTORY is read too,
//      every `.crt` and `.pem` in it — the cells stack's databases share
//      their certificates in one, as `<CN>.crt`.
//   C. A FILE NAMED AND UNUSABLE IS REFUSED under STS-STORE-0079: a path
//      that does not exist, and a file holding no certificate (a private
//      key named by mistake), both from `databaseTlsCa()` and as the
//      rejection of `databaseConnection()`.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): every case chooses how
// the process was started — which file, which setting — and none needs a
// database: what is asserted is what `pg` would be GIVEN. A real handshake
// against the compose stack's certificate through the shared file is every
// postgres mode of `run-tests.sh`, which cannot start otherwise.
//
// The certificate is MADE HERE, at run time (no key material in git), with
// the service's own `common/crypto.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const storeDouble = require('./tools/store_double');
const fs = require('fs');
const os = require('os');
const path = require('path');

const persistence = require('../persistence/persistence');
const postgres = require('../persistence/persistence_postgres');
const stsCrypto = require('../common/crypto');

const log = require('bunyan').createLogger({ name: 'database_tls_ca',
  level: process.env.LOG_LEVEL || 'info' });

const QUIET = { debug: function () {}, info: function () {},
                warn: function () {}, error: function () {} };

// Every setting this file moves is restart-only, so it moves through the
// environment, which `config.value()` reads on every call.
const VARS = ['STS_DATABASE_TLS_REJECT_UNAUTHORIZED',
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

// A driver over a stand-in `pg`, for what it hands the bridge; nothing is
// dialled.
function driverWith(url, tlsCa) {
  log.debug("Entering driverWith().");
  function FakePool() {}
  FakePool.prototype.on = function () {};
  FakePool.prototype.query = function () {
    return Promise.resolve({ rows: [], rowCount: 0 });
  };
  FakePool.prototype.end = function () {
    return Promise.resolve();
  };
  const restore = storeDouble.install({ Pool: FakePool,
                                        Client: function () {} });
  try {
    log.debug("Leaving driverWith().");
    return postgres.create({ url: url, log: QUIET, verifyTls: true,
                             tlsCa: tlsCa });
  } finally {
    restore();
  }
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-db-tls-ca-'));
  const made = stsCrypto.selfSignedRsaCertificate({ commonName: 'postgres' });
  const caFile = path.join(dir, 'server.crt');
  const keyFile = path.join(dir, 'server.key');
  fs.writeFileSync(caFile, made.certPem);
  fs.writeFileSync(keyFile, made.privateKeyPem, { mode: 0o600 });
  const url = 'postgres://sts_app@postgres:5432/sts?sslmode=require';

  try {
    // -------------------------------------------------------------------
    // A. THE DEFAULT IS ON.
    // -------------------------------------------------------------------
    await withEnvironment({}, async function () {
      t.equal(persistence.verifiesDatabaseTls(), true,
              'A. with nothing set, the database server\'s certificate is ' +
              'verified (persistence.databaseTlsRejectUnauthorized ' +
              'defaults to true, in every mode)');
      t.equal(persistence.databaseTlsCa(), '',
              'and with persistence.databaseTlsCaFile empty there are no ' +
              'trust anchors of the database\'s own');
      const dial = postgres.dialOptions(
        'postgres://db/sts?sslmode=require', persistence.verifiesDatabaseTls(),
        persistence.databaseTlsCa());
      t.check(dial.verifyChain && dial.verifyHostname &&
              dial.ssl.rejectUnauthorized === true && !('ca' in dial.ssl),
              'so require verifies the chain and the host name against ' +
              'the default trust store', JSON.stringify(dial.ssl));
    });

    // -------------------------------------------------------------------
    // B. THE CA FILE IS APPLIED.
    // -------------------------------------------------------------------
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: caFile,
                            STS_DATABASE_URL: url },
    async function () {
      const pem = persistence.databaseTlsCa();
      t.check(/-----BEGIN CERTIFICATE-----/.test(pem) &&
              pem.indexOf(made.certB64.slice(0, 64)) >= 0,
              'B. databaseTlsCa() answers the certificate the file holds');
      const dial = postgres.dialOptions(url, true, pem);
      t.check(dial.ssl.ca === pem && dial.ssl.rejectUnauthorized === true,
              'dialOptions() puts it on the ssl option as ca, in place of ' +
              'the default trust store for that connection');
      const full = postgres.dialOptions(
        'postgres://postgres/sts?sslmode=verify-full', false, pem);
      t.check(full.ssl.ca === pem && full.verifyHostname === true,
              'and for verify-full too, the mode the compose stack dials');
      const bridged = driverWith(url, pem).bridgeConnection();
      t.equal(bridged.ssl && bridged.ssl.ca, pem,
              'a driver built with it hands it to the directory bridge\'s ' +
              'thread');
      const caBridged = driverWith(
        'postgres://sts_app@postgres:5432/sts?sslmode=verify-ca', pem)
        .bridgeConnection();
      let cloned = null;
      try {
        cloned = structuredClone(caBridged);
      } catch (e) {
        log.debug("Caught in run(): " + ((e && e.message) || e));
      }
      t.check(cloned && cloned.ssl && cloned.ssl.ca === pem &&
              cloned.ssl.hostnameUnchecked === true,
              'and for verify-ca, whose options are rewritten as data for ' +
              'the thread, the trust anchors survive the rewrite and ' +
              'structured cloning', JSON.stringify(caBridged &&
                caBridged.ssl && Object.keys(caBridged.ssl)));
      const connection = await persistence.databaseConnection();
      t.equal(connection.tlsCa, pem,
              'databaseConnection() hands them to a process that is not ' +
              'the service (the risk loader, cell_convert)');
      t.equal(connection.verifyTls, true, 'with verifyTls: true');
    });
    const shared = path.join(dir, 'shared');
    const other = stsCrypto.selfSignedRsaCertificate({
      commonName: 'postgres-global' });
    fs.mkdirSync(shared);
    fs.writeFileSync(path.join(shared, 'postgres.crt'), made.certPem);
    fs.writeFileSync(path.join(shared, 'postgres-global.crt'), other.certPem);
    fs.writeFileSync(path.join(shared, '.postgres-cellb.crt.tmp'),
                     'half a certificate');
    fs.writeFileSync(path.join(shared, 'README'), 'not a certificate');
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: shared },
    async function () {
      const pem = persistence.databaseTlsCa();
      t.check(pem.indexOf(made.certB64.slice(0, 64)) >= 0 &&
              pem.indexOf(other.certB64.slice(0, 64)) >= 0 &&
              (pem.match(/-----BEGIN CERTIFICATE-----/g) || []).length === 2,
              'a directory is read: both databases\' certificates, and ' +
              'neither the hidden temporary file nor the README');
    });

    // -------------------------------------------------------------------
    // C. A FILE NAMED AND UNUSABLE IS REFUSED, STS-STORE-0079.
    // -------------------------------------------------------------------
    const missing = path.join(dir, 'no-such.crt');
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: missing,
                            STS_DATABASE_URL: url },
    async function () {
      const why = await refusalOf(function () {
        return persistence.databaseTlsCa();
      });
      t.check(/\[STS-STORE-0079\]/.test(why) && why.indexOf(missing) >= 0,
              'C. a file that does not exist is refused under ' +
              'STS-STORE-0079, naming it', why);
      const rejected = await refusalOf(function () {
        return persistence.databaseConnection();
      });
      t.check(/\[STS-STORE-0079\]/.test(rejected),
              'and databaseConnection() rejects with it, so a tool does ' +
              'not dial with a trust anchor nobody chose', rejected);
    });
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: keyFile,
                            STS_DATABASE_URL: url },
    async function () {
      const why = await refusalOf(function () {
        return persistence.databaseTlsCa();
      });
      t.check(/\[STS-STORE-0079\]/.test(why) &&
              /holds no PEM certificate/.test(why),
              'a file holding no certificate (a private key named by ' +
              'mistake) is refused under STS-STORE-0079 too', why);
    });
    const empty = path.join(dir, 'empty');
    fs.mkdirSync(empty);
    await withEnvironment({ STS_DATABASE_TLS_CA_FILE: empty },
    async function () {
      const why = await refusalOf(function () {
        return persistence.databaseTlsCa();
      });
      t.check(/\[STS-STORE-0079\]/.test(why),
              'and so is a directory with no certificate in it', why);
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'database_tls_ca',
  describe: 'the database certificate is verified by default, ' +
            'persistence.databaseTlsCaFile is applied to every dialler ' +
            '(the pools, the bridge\'s thread, the out-of-process tools), ' +
            'and a file named and unusable is refused under STS-STORE-0079',
  run: run
};
