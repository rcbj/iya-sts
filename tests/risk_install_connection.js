'use strict';
//
// File: risk_install_connection.js
//
// ===========================================================================
// THE INSTALL-TIME RISK LOADER DIALS THE DATABASE THE WAY THE SERVICE DOES
// (#213, 2026-09-26).
//
// `risk/risk_install.ts` connected with `STS_DATABASE_URL` and nothing else.
// Every stack this repository ships keeps the database password out of that
// URL — in OpenBao, or AWS Secrets Manager — so the loader could not sign in
// on the one occasion it exists for, a new deployment's first install, and it
// never verified the server's certificate even where the service was told
// to. It now takes its connection from `persistence.databaseConnection()`,
// the service's own code. This file holds it to that:
//
//   A. A PROVIDER'S PASSWORD REACHES THE DRIVER. With the password in a file
//      provider and none in the URL, what the loader hands the driver is the
//      URL with the password in it — asserted through `pg`'s OWN parser, for
//      a password made of the characters that break a naive injection
//      (`%`, `&`, `+`, `@`, `:`, `/`, `#`), so the encoding round-trips.
//   B. `verifyTls` FOLLOWS `persistence.databaseTlsRejectUnauthorized`, off
//      and on — and `run()` really PASSES it (and the URL) to
//      `persistence_postgres.create()`, caught at that call with a stand-in
//      driver, so a loader that computed the options and then built its own
//      would fail here.
//   C. NO PROVIDER: a password written into `STS_DATABASE_URL` is dialled
//      byte for byte, for a throwaway database.
//   D. A PROVIDER CONFIGURED AND UNREADABLE is STS-RISK-0040, with the
//      provider's reason, and `run()` imports nothing and exits non-zero.
//   E. NO DATABASE NAMED — no `STS_DATABASE_URL` and not on postgres — is
//      STS-RISK-0012 rather than a dial of the development default.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): every case chooses how
// the process was started — which provider, which file, which setting — and
// three are about a value that must never leave this process. The loader
// against a REAL OpenBao-backed database is `run-tests.sh`'s risk-install
// step, in the single-node and cluster modes.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const { RiskInstall } = require('../risk/risk_install');
const persistencePostgres = require('../persistence/persistence_postgres');
// `pg`'s own connection-string reader: the code that will really read the
// string (tests/database_password.js argues it).
const ConnectionParameters = require('pg/lib/connection-parameters.js');

const log = require('bunyan').createLogger({ name: 'risk_install_connection',
  level: process.env.LOG_LEVEL || 'info' });

// Every setting this file moves is restart-only, so it moves through the
// environment, which `config.value()` reads on every call.
const VARS = ['STS_KEYS_KEK_PROVIDER', 'STS_KEYS_KEK_FILE', 'STS_KEYS_KEK_REF',
              'STS_KEYS_KEK_FIELD', 'STS_DATABASE_PASSWORD_PROVIDER',
              'STS_DATABASE_PASSWORD_REF', 'STS_DATABASE_PASSWORD_FIELD',
              'STS_DATABASE_URL', 'STS_DATABASE_TLS_REJECT_UNAUTHORIZED',
              'STS_PERSISTENCE_MODE', 'STS_KEYS_KEK_VAULT',
              'STS_KEYS_KEK_REGION', 'STS_KEYS_KEK_TOKEN',
              'STS_DATABASE_PASSWORD_VAULT', 'STS_DATABASE_PASSWORD_REGION',
              'STS_DATABASE_PASSWORD_TOKEN'];

// The characters that have broken a password injected into a URL: `%`, `&`
// and `+` (which `URL.password =` leaves alone and `pg` then decodes), and
// the URL's own delimiters.
const HOSTILE_PASSWORD = 'p%41ss&w+rd@h:st/x#y?z 100%';

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

function passwordPgSees(url) {
  log.debug("Entering passwordPgSees().");
  log.debug("Leaving passwordPgSees().");
  return new ConnectionParameters({ connectionString: url }).password;
}

// What a promise rejected with, as text; '' when it resolved.
async function refusalOf(promise) {
  log.debug("Entering refusalOf().");
  try {
    await promise;
  } catch (e) {
    log.debug("Caught in refusalOf(): " + ((e && e.message) || e));
    log.debug("Leaving refusalOf(). Refused.");
    return String((e && e.message) || e);
  }
  log.debug("Leaving refusalOf(). Resolved.");
  return '';
}

// run() with `persistence_postgres.create()` replaced by a stand-in that
// records what it was given and whose open() stops the run there, and with
// stderr captured. Answers { created, error, stderr, failed }.
async function runCapturing(manifest) {
  log.debug("Entering runCapturing().");
  const originalCreate = persistencePostgres.create;
  const originalWrite = process.stderr.write;
  const out = { created: null, error: '', stderr: '', failed: 0 };
  persistencePostgres.create = function (options) {
    out.created = options;
    return {
      open: function () {
        return Promise.reject(new Error('stand-in driver: not dialled'));
      },
      close: function () {
        return Promise.resolve();
      }
    };
  };
  process.stderr.write = function (chunk) {
    out.stderr += String(chunk);
    return true;
  };
  try {
    out.failed = await RiskInstall.run({ manifest: manifest,
                                         accepted: ['operator'],
                                         dryRun: false });
  } catch (e) {
    log.debug("Caught in runCapturing(): " + ((e && e.message) || e));
    out.error = String((e && e.message) || e);
  } finally {
    persistencePostgres.create = originalCreate;
    process.stderr.write = originalWrite;
  }
  log.debug("Leaving runCapturing().");
  return out;
}

async function run(t) {
  log.debug("Entering run().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-risk-install-'));
  const rawKey = path.join(dir, 'kek');
  const own = path.join(dir, 'db-password');
  const manifest = path.join(dir, 'datasets.json');
  fs.writeFileSync(rawKey, nodeCrypto.randomBytes(32).toString('base64'),
                   { mode: 0o600 });
  fs.writeFileSync(own, HOSTILE_PASSWORD + '\n', { mode: 0o600 });
  // A synthetic operator list in the RFC 5737 documentation range; the run
  // below stops at the stand-in driver, so it is never read.
  fs.writeFileSync(path.join(dir, 'synthetic-deny.txt'), '198.51.100.0/24\n');
  fs.writeFileSync(manifest, JSON.stringify({ datasets: [
    { dataset: 'iplist.operator-deny', format: 'ip-list',
      file: path.join(dir, 'synthetic-deny.txt'), version: 'synthetic-1' }
  ] }));
  const provider = {
    STS_KEYS_KEK_PROVIDER: 'file',
    STS_KEYS_KEK_FILE: rawKey,
    STS_DATABASE_PASSWORD_PROVIDER: 'file',
    STS_DATABASE_PASSWORD_REF: own,
    STS_DATABASE_URL: 'postgres://sts_app@db.example:5432/sts?sslmode=require'
  };

  try {
    // -------------------------------------------------------------------
    // A. THE PROVIDER'S PASSWORD, INJECTED, AND ROUND-TRIPPED.
    // -------------------------------------------------------------------
    await withEnvironment(provider, async function () {
      const options = await RiskInstall.driverOptions();
      t.equal(passwordPgSees(options.url), HOSTILE_PASSWORD,
              'A. with the password in a provider and none in ' +
              'STS_DATABASE_URL, the URL the loader hands the driver carries ' +
              'it — and `pg`\'s own parser reads back every byte of a ' +
              'password made of %, &, +, @, :, /, # and ?, so the injection ' +
              'is the encoded one the service uses');
      t.check(options.url.indexOf('db.example:5432/sts') >= 0 &&
              options.url.indexOf('sslmode=require') >= 0,
              'with the host, the database and sslmode untouched',
              options.url.replace(/:[^:@/]*@/, ':***@'));
      t.equal(options.verifyTls, false,
              'B. and with persistence.databaseTlsRejectUnauthorized at its ' +
              'default (off) verifyTls is false, as the service\'s is');
      t.check(options.log && typeof options.log.debug === 'function',
              'and the driver is given a logger, as the service gives it');
    });

    // -------------------------------------------------------------------
    // B. verifyTls ON, AND run() PASSES WHAT driverOptions() MADE.
    // -------------------------------------------------------------------
    await withEnvironment(Object.assign({
      STS_DATABASE_TLS_REJECT_UNAUTHORIZED: 'true' }, provider),
    async function () {
      t.equal((await RiskInstall.driverOptions()).verifyTls, true,
              'B. with persistence.databaseTlsRejectUnauthorized on, ' +
              'verifyTls is true — the loader verifies the database ' +
              'server\'s certificate exactly when the service does, where it ' +
              'never ' +
              'did before #213');
      const r = await runCapturing(manifest);
      t.check(r.created, 'run() builds its driver through ' +
              'persistence_postgres.create()', r.error || r.stderr);
      t.equal(r.created && r.created.verifyTls, true,
              'and passes it verifyTls: true');
      t.equal(r.created && passwordPgSees(r.created.url), HOSTILE_PASSWORD,
              'and the URL with the provider\'s password in it');
      t.check(/stand-in driver/.test(r.error),
              'and then opens it (the stand-in stops the run there)',
              r.error.slice(0, 120));
    });

    // -------------------------------------------------------------------
    // C. NO PROVIDER: THE URL AS WRITTEN.
    // -------------------------------------------------------------------
    await withEnvironment({
      STS_DATABASE_URL: 'postgres://sts:in-the-url@localhost:5432/sts'
    }, async function () {
      const options = await RiskInstall.driverOptions();
      t.equal(options.url, 'postgres://sts:in-the-url@localhost:5432/sts',
              'C. with no provider configured a password written into ' +
              'STS_DATABASE_URL is dialled byte for byte — the throwaway ' +
              'database keeps working');
    });

    // -------------------------------------------------------------------
    // D. A PROVIDER CONFIGURED AND UNREADABLE.
    // -------------------------------------------------------------------
    await withEnvironment(Object.assign({}, provider, {
      STS_DATABASE_PASSWORD_REF: path.join(dir, 'no-such-file')
    }), async function () {
      const refusal = await refusalOf(RiskInstall.driverOptions());
      t.check(refusal.indexOf('STS-RISK-0040') >= 0,
              'D. a provider that is configured and cannot be read is ' +
              'STS-RISK-0040', refusal.slice(0, 160));
      t.check(/no-such-file|ENOENT|could not/i.test(refusal),
              'with the provider\'s own reason carried', refusal.slice(0, 240));
      const r = await runCapturing(manifest);
      t.equal(r.created, null,
              'and run() builds no driver — nothing is dialled without the ' +
              'password somebody configured');
      t.check(r.failed > 0 && r.stderr.indexOf('STS-RISK-0040') >= 0,
              'it reports the refusal and answers non-zero, which is the ' +
              'loader\'s exit code', r.stderr.slice(0, 160));
    });

    // -------------------------------------------------------------------
    // E. NO DATABASE NAMED.
    // -------------------------------------------------------------------
    await withEnvironment({ STS_PERSISTENCE_MODE: 'memory' },
      async function () {
        const refusal = await refusalOf(RiskInstall.driverOptions());
        t.check(refusal.indexOf('STS-RISK-0012') >= 0 &&
                /STS_DATABASE_URL/.test(refusal),
                'E. with no STS_DATABASE_URL and persistence.mode not ' +
                'postgres the loader refuses with STS-RISK-0012 and says ' +
                'how to name the database, rather than dialling the ' +
                'development default', refusal.slice(0, 160));
      });
    await withEnvironment({ STS_PERSISTENCE_MODE: 'postgres' },
      async function () {
        const options = await RiskInstall.driverOptions();
        t.check(/^postgres:\/\//.test(options.url),
                'E. and on postgres with no STS_DATABASE_URL it takes ' +
                'persistence.databaseUrl, as the service does');
      });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'risk_install_connection',
  describe: 'the install-time risk loader dials the database the way the ' +
            'service does (#213): the provider\'s password injected and ' +
            'round-tripped through pg\'s parser, verifyTls followed and ' +
            'passed, a URL password kept, an unreadable provider ' +
            'STS-RISK-0040, no database named STS-RISK-0012',
  run: run
};
