// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pki_branch_removed_mid_certify.js
//
// ===========================================================================
// A CERTIFICATE AUTHORITY REMOVED WHILE ITS KEYS ARE BEING CERTIFIED (#1472).
//
// `certifyPqKeys()` promises to answer and not throw. It checks for the branch
// once, before its loop, and reads the row again after each `await`, and that
// second read threw when the fuzz run removed the default realm's authority
// mid-loop. This hands it a row that has lost its Issuing CAs by the second
// read, which only a double of the keystore can time.
// ===========================================================================

delete process.env.CONFIG_FILE;

const pki = require('../common/pki');
const keystore = require('../common/keystore');
const pqJose = require('../common/pq_jose');

const log = require('bunyan').createLogger({
  name: 'pki_branch_removed_mid_certify',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  const made = pqJose.generate('ML-DSA-44');
  const publicJwk = { kty: 'AKP', alg: 'ML-DSA-44', kid: 'mid-certify',
                      pub: made.pub.toString('base64url') };
  const real = keystore.pkiFor;
  let reads = 0;
  keystore.pkiFor = function () {
    reads += 1;
    return reads === 1 ? { issuing: { jose: { certificatePem: 'x' } } } : {};
  };
  let answer = null;
  let thrown = null;
  try {
    answer = await pki.certifyPqKeys('', [
      { alg: 'ML-DSA-44', publicJwk: publicJwk }], []);
  } catch (e) {
    thrown = e;
  } finally {
    keystore.pkiFor = real;
  }
  t.check(!thrown, 'a branch removed during the loop does not throw',
          thrown && thrown.message);
  t.check(reads > 1, 'the row was read again after the first check',
          String(reads));
  t.check(!!answer && (answer.ok === false ||
                       (answer.failed || []).length === 1),
          'and the key is reported as not certified', JSON.stringify(answer));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pki_branch_removed_mid_certify',
  describe: 'a certificate authority removed while its post-quantum keys ' +
            'are being certified is an answer and not a 500',
  run: run
};
