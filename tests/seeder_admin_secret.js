// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: seeder_admin_secret.js
//
// ===========================================================================
// THE MANAGEMENT API SECRET THE OPENBAO SEEDER GENERATES IS 64 CHARACTERS OF
// BASE64URL (#1212, 2026-10-30).
//
// `openbao/seed.js` stores `adminApiClientSecret` in `secret/sts-admin` when
// nobody pins `ADMIN_API_CLIENT_SECRET`, and that value is `sts-api-client`'s
// secret in the default realm. It was 24 letters and digits; it is now the
// shape `applications.mintClientSecret()` gives every other client secret at
// the default `oauth2.registeredSecretBytes`.
//
// 1 requires the seeder, which runs nothing unless executed, and asks its
// generator for several values: each is 64 characters of base64url, decodes
// to 48 bytes, and no two are equal. 2 holds the generator's length to the
// setting's default, so the two cannot drift apart unnoticed.
// ===========================================================================

const seeder = require('../openbao/seed');
const config = require('../common/config');

const log = require('bunyan').createLogger({ name: 'seeder_admin_secret_test',
  level: process.env.LOG_LEVEL || 'info' });

function checkTheShape(t) {
  log.debug("Entering checkTheShape().");
  t.log.info('=== 1. a generated secret is 64 characters of base64url ===');
  const seen = new Set();
  for (let i = 0; i < 20; i++) {
    const value = seeder.generatedClientSecret();
    t.check(typeof value === 'string' && value.length === 64,
            'a generated secret is 64 characters', String(value.length));
    t.check(/^[A-Za-z0-9_-]+$/.test(value),
            'a generated secret is base64url, unpadded', value);
    t.check(Buffer.from(value, 'base64url').length === 48,
            'a generated secret decodes to 48 random bytes', '');
    seen.add(value);
  }
  t.check(seen.size === 20, 'twenty generated secrets are all different',
          String(seen.size));
  log.debug("Leaving checkTheShape().");
}

function checkTheSetting(t) {
  log.debug("Entering checkTheSetting().");
  t.log.info('=== 2. the length is the client secret setting\'s default ===');
  const row = config.SETTINGS.filter(function (one) {
    return one.key === 'oauth2.registeredSecretBytes';
  })[0];
  const bytes = Buffer.from(seeder.generatedClientSecret(), 'base64url')
    .length;
  t.check(row && Number(row.dflt) === bytes,
          'the seeder generates oauth2.registeredSecretBytes\' default ' +
          'number of bytes', String(row && row.dflt) + ' vs ' + bytes);
  log.debug("Leaving checkTheSetting().");
}

async function run(t) {
  log.debug("Entering run().");
  checkTheShape(t);
  checkTheSetting(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'seeder_admin_secret',
  describe: 'that the OpenBao seeder generates the management API secret as ' +
            '48 random bytes, base64url — 64 characters, the shape of every ' +
            'other client secret (#1212)',
  run: run
};
