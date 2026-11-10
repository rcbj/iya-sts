// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/asvs_secret_store.js
//
// ASVS 5.0.0 13.3.1: in product mode the key-encryption key comes from a
// secret store or a key management service, and the database password from a
// secret store. A file, or a password in the connection string, stops the
// service unless secrets.allowLocalSecrets is on. Development accepts both.

const fs = require('fs');
const os = require('os');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const VARS = ['STS_KEYS_KEK_PROVIDER', 'STS_KEYS_KEK_FILE',
              'STS_SECRETS_ALLOW_LOCAL_SECRETS', 'STS_DATABASE_URL',
              'STS_DATABASE_PASSWORD_PROVIDER'];

async function outcome(promise) {
  try {
    await promise;
    return 'ok';
  } catch (e) {
    return String((e && e.message) || e);
  }
}

async function run(t) {
  const config = require(ROOT + '/common/config');
  const secrets = require(ROOT + '/common/secrets');
  const persistence = require(ROOT + '/persistence/persistence');
  const saved = {};
  VARS.forEach(function (name) {
    saved[name] = process.env[name];
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-store-'));
  const kekFile = path.join(dir, 'kek');
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { encoding: 'utf8', mode: 0o600 });
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  delete process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS;
  delete process.env.STS_DATABASE_PASSWORD_PROVIDER;
  config.setOverride('global.mode', 'product');
  try {
    t.check(/STS-KEYS-0197/.test(await outcome(secrets.readKek())),
            'product refuses a key-encryption key in a file');
    process.env.STS_DATABASE_URL =
      'postgres://sts_app:an-unguessable-one@db:5432/sts';
    t.check(/STS-STORE-0171/.test(
              await outcome(persistence.resolveDatabaseUrl())),
            'and a database password written into the connection string');
    process.env.STS_DATABASE_URL = 'postgres://sts_app@db:5432/sts';
    t.equal(await outcome(persistence.resolveDatabaseUrl()), 'ok',
            'but not a connection string that carries no password');
    process.env.STS_DATABASE_PASSWORD_PROVIDER = 'file';
    t.check(/STS-STORE-0171/.test(
              await outcome(persistence.resolveDatabaseUrl())),
            'and refuses the file provider for the database password');
    delete process.env.STS_DATABASE_PASSWORD_PROVIDER;

    process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
    t.equal(await outcome(secrets.readKek()), 'ok',
            'secrets.allowLocalSecrets accepts the file');
    process.env.STS_DATABASE_URL =
      'postgres://sts_app:an-unguessable-one@db:5432/sts';
    t.equal(await outcome(persistence.resolveDatabaseUrl()), 'ok',
            'and the password in the connection string');
    delete process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS;

    config.setOverride('global.mode', 'development');
    t.equal(await outcome(secrets.readKek()), 'ok',
            'development accepts the file whatever the setting says');
  } finally {
    config.clearOverride('global.mode');
    VARS.forEach(function (name) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = {
  name: 'asvs_secret_store',
  describe: 'product mode takes its key-encryption key and database ' +
            'password from a secret store (ASVS 5.0.0 13.3.1)',
  run: run
};
