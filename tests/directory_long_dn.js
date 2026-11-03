// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: directory_long_dn.js
//
// ===========================================================================
// A DN THE STORE CANNOT HOLD IS REFUSED AT THE DOOR (#677).
//
// MariaDB's directory key holds 352 characters of normalised DN (InnoDB's
// 3072-byte key over realm, parent and DN). The flush refuses a longer one
// (STS-STORE-0140) — but by then the entry is in memory, and every later
// flush carries it and is refused again. So the doors that make an entry ask
// first (`persistence.dnKeyRefusal()`), and refuse with STS-LDAP-0204:
//
//   A. the limits: none on PostgreSQL, memory or ldif; on MariaDB 352
//      characters of DN key (counted as characters, not bytes) and 64 of
//      realm id;
//   B. `createUser()` (the console, the management API, SCIM) refuses a
//      username long enough to cross it, and writes nothing;
//   C. the LDAP add and rename ask the same question (read from the source:
//      both handlers call it with the DN they would create).
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const realms = require('../common/realms');
const persistence = require('../persistence/persistence');
const ldap = require('../ldap/ldap_server');

const log = require('bunyan').createLogger({ name: 'directory_long_dn',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== A. the limits ===');
  const at = function (n) {
    log.debug("Entering at().");
    log.debug("Leaving at().");
    return 'uid=' + 'x'.repeat(Math.max(0, n - 4));
  };
  t.check(persistence.dnKeyRefusalFor('postgres', '', at(5000)) === null &&
          persistence.dnKeyRefusalFor('memory', '', at(5000)) === null &&
          persistence.dnKeyRefusalFor('ldif', '', at(5000)) === null,
          'A1. PostgreSQL, memory and ldif hold any DN');
  t.check(persistence.dnKeyRefusalFor('mariadb', '', at(352)) === null,
          'A2. MariaDB holds a DN key of exactly 352 characters');
  t.check(/352/.test(String(persistence.dnKeyRefusalFor('mariadb', '',
                                                         at(353)))),
          'A3. and refuses 353, naming the limit');
  t.check(persistence.dnKeyRefusalFor('mariadb', '',
                                      'uid=' + 'é'.repeat(348)) === null,
          'A4. the limit is in CHARACTERS, as the column is: 348 accented ' +
          'letters (696 bytes of UTF-8) fit');
  t.check(persistence.dnKeyRefusalFor('mariadb', 'r'.repeat(65), 'uid=a') !==
            null &&
          persistence.dnKeyRefusalFor('mariadb', 'r'.repeat(64), 'uid=a') ===
            null,
          'A5. a realm id over 64 characters is refused too');
  t.check(persistence.dnKeyRefusal('', at(5000)) === null,
          'A6. this process\'s store (memory here) refuses nothing');

  t.log.info('=== B. createUser() asks first ===');
  const saved = persistence.dnKeyRefusal;
  const longName = 'longdn-' + 'n'.repeat(400);
  let answer = null;
  try {
    persistence.dnKeyRefusal = function (realmId, dnKey) {
      log.debug("Entering dnKeyRefusal() (the test's).");
      log.debug("Leaving dnKeyRefusal() (the test's).");
      return persistence.dnKeyRefusalFor('mariadb', realmId, dnKey);
    };
    answer = realms.run('', function () {
      return ldap.createUser(longName, { invent: false });
    });
  } finally {
    persistence.dnKeyRefusal = saved;
  }
  const errorCodes = require('../common/error_codes');
  t.check(answer && answer.ok === false &&
          errorCodes.codeOf(answer) === 'STS-LDAP-0204' &&
          /shorter username/.test(String((answer.errors || [])[0])),
          'B1. A USERNAME TOO LONG FOR THE STORE IS REFUSED STS-LDAP-0204, ' +
          'saying to choose a shorter one', JSON.stringify(answer).slice(0,
                                                                        300));
  const made = realms.run('', function () {
    return ldap.existingUserEntry(longName);
  });
  t.check(!made, 'B2. and nothing was written', String(!!made));

  t.log.info('=== C. the LDAP add and rename ask the same question ===');
  const source = fs.readFileSync(path.join(__dirname, '..', 'ldap',
                                           'ldap_server.js'), 'utf8');
  t.check(/persistence\.dnKeyRefusal\(realms\.currentId\(\),\s*normalizeDn\(dn\)\)/
            .test(source),
          'C1. the LDAP add asks about the DN it would create');
  t.check(/persistence\.dnKeyRefusal\(realms\.currentId\(\),\s*normalizeDn\(target\)\)/
            .test(source),
          'C2. the rename asks about the NEW DN');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'directory_long_dn',
  describe: 'a DN the store cannot hold is refused at the door, before it is ' +
            'in memory (#677)',
  run: run
};
