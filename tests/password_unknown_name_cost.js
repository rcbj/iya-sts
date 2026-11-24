// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: password_unknown_name_cost.js
//
// ===========================================================================
// A REFUSAL THAT NEEDED NO COMPARISON COSTS ONE ANYWAY (#2136, ASVS 5.0.0
// 6.3.8 and 11.2.4).
//
// `Credentials.verifyPrepare()` answered "nobody by that name" at once, while
// a wrong password for a real person cost a whole derivation, so the response
// time said which accounts exist. Both doors now verify the presented
// password against `crypto.decoyPasswordHash()` and discard the result.
//
// Timing is NOT measured here — it flakes. What is held is that the decoy
// derivation RUNS, and on the right thread, by counting the calls to
// `crypto.verifySecret()` and `crypto.verifySecretAsync()` and the hash each
// was handed. A Credentials instance of its own, over a stub directory and a
// `mode` that says product, so nothing else in the process is touched:
//
//   A. THE DECOY: one hash per spec per process, at the policy's parameters,
//      matching no password.
//   B. NOBODY BY THAT NAME, `verify()`: refused as before (no-credential,
//      STS-AUTHN-0052), after one `verifySecret()` against the decoy.
//   C. THE SAME, `verifyAsync()`: one `verifySecretAsync()` against the
//      decoy and no `verifySecret()` — the derivation stays off the loop.
//   D. A STORED VALUE THIS SERVICE CANNOT READ (STS-AUTHN-0053) and a
//      DISABLED ACCOUNT: the same decoy, on both doors.
//   E. THE CONTROL: a real person's wrong password is one comparison against
//      their own hash, and no decoy.
//   F. DEVELOPMENT MODE compares nothing, decoy included.
// ===========================================================================

delete process.env.CONFIG_FILE;

const stsCrypto = require('../common/crypto');
const credentialsModule = require('../common/credentials');
const passwordPolicy = require('../common/password_policy');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'password_unknown_name_cost',
  level: process.env.LOG_LEVEL || 'info' });

// Made up here.
const PERSON = 'puc-alice';
const DISABLED = 'puc-bob';
const UNREADABLE = 'puc-carol';
const NOBODY = 'puc-nobody-' + Date.now().toString(36);
const RIGHT = 'Puc-Right-Passphrase-71';
const WRONG = 'Puc-Wrong-Passphrase-72';

async function run(t) {
  log.debug("Entering run().");
  const Credentials = credentialsModule.Credentials;
  const spec = passwordPolicy.hashSpec(passwordPolicy.profileFor(NOBODY));

  // --- A. the decoy --------------------------------------------------------
  const decoy = stsCrypto.decoyPasswordHash(spec);
  t.check(stsCrypto.isHashedSecret(decoy) &&
          stsCrypto.decoyPasswordHash(spec) === decoy,
          'A1. the decoy is a password hash, made once per spec');
  t.check(stsCrypto.storedSecretMatchesSpec(decoy, spec),
          'A2. at the parameters the password policy writes now',
          JSON.stringify(stsCrypto.storedSecretParameters(decoy)));
  t.check(!stsCrypto.verifySecret(WRONG, decoy) &&
          !stsCrypto.verifySecret('', decoy),
          'A3. and no password matches it');

  // A crypto that counts, and a mode that can be switched.
  const calls = [];
  const spy = Object.create(stsCrypto);
  spy.verifySecret = function (plaintext, stored) {
    calls.push({ door: 'sync', stored: stored });
    return stsCrypto.verifySecret(plaintext, stored);
  };
  spy.verifySecretAsync = function (plaintext, stored) {
    calls.push({ door: 'async', stored: stored });
    return stsCrypto.verifySecretAsync(plaintext, stored);
  };
  let product = true;
  const defaults = Credentials.defaultDeps();
  const mode = Object.create(defaults.mode);
  mode.verifiesCredentials = function () {
    return product;
  };
  const real = stsCrypto.hashPassword(RIGHT, spec);
  const stored = {};
  stored[PERSON] = real;
  stored[DISABLED] = stsCrypto.hashPassword(RIGHT, spec);
  stored[UNREADABLE] = 'plaintext-' + RIGHT;
  const instance = new Credentials(Object.assign({}, defaults,
    { crypto: spy, mode: mode }));
  t.check(instance.setDirectory({
    readPassword: function (name) {
      return stored[name] || '';
    },
    writePassword: function () {
      return false;
    },
    readAccountDisabled: function (name) {
      return name === DISABLED;
    }
  }), 'precondition: the stub directory is installed');

  const decoyCalls = function (door) {
    return calls.filter(function (one) {
      return one.door === door && one.stored === decoy;
    }).length;
  };
  const askedOnce = function (door) {
    return calls.length === 1 && decoyCalls(door) === 1;
  };

  // --- B. nobody by that name, verify() ------------------------------------
  calls.length = 0;
  let answer = instance.verify(NOBODY, WRONG, { via: 'the test' });
  t.check(!answer.ok && answer.reason === 'no-credential' &&
          errorCodes.codeOf(answer) === 'STS-AUTHN-0052',
          'B1. nobody by that name is refused as before (no-credential, ' +
          'STS-AUTHN-0052)', answer.reason + ' ' + errorCodes.codeOf(answer));
  t.check(askedOnce('sync'),
          'B2. after one verifySecret() against the decoy',
          JSON.stringify(calls.map(function (one) {
            return one.door + (one.stored === decoy ? ' decoy' : ' other');
          })));

  // --- C. the same, verifyAsync() ------------------------------------------
  calls.length = 0;
  answer = await instance.verifyAsync(NOBODY, WRONG, { via: 'the test' });
  t.check(!answer.ok && answer.reason === 'no-credential' &&
          errorCodes.codeOf(answer) === 'STS-AUTHN-0052',
          'C1. verifyAsync() refuses nobody by that name as before',
          answer.reason);
  t.check(askedOnce('async'),
          'C2. after one verifySecretAsync() against the decoy, and no ' +
          'verifySecret() on the event loop', JSON.stringify(calls.length));

  // --- D. an unreadable stored value, and a disabled account ---------------
  calls.length = 0;
  answer = instance.verify(UNREADABLE, WRONG, { via: 'the test' });
  t.check(!answer.ok && answer.reason === 'unreadable-credential' &&
          askedOnce('sync'),
          'D1. an unreadable stored value: refused as before, after the decoy',
          answer.reason + ' ' + calls.length);
  calls.length = 0;
  answer = await instance.verifyAsync(UNREADABLE, WRONG, { via: 'the test' });
  t.check(!answer.ok && answer.reason === 'unreadable-credential' &&
          askedOnce('async'),
          'D2. and on the asynchronous door', answer.reason);
  calls.length = 0;
  answer = instance.verify(DISABLED, RIGHT, { via: 'the test' });
  const disabledReason = answer.reason;
  t.check(!answer.ok && askedOnce('sync'),
          'D3. a disabled account: refused as before, after the decoy',
          answer.reason + ' ' + calls.length);
  calls.length = 0;
  answer = await instance.verifyAsync(DISABLED, RIGHT, { via: 'the test' });
  t.check(!answer.ok && answer.reason === disabledReason &&
          askedOnce('async'),
          'D4. and on the asynchronous door', answer.reason);

  // --- E. the control ------------------------------------------------------
  calls.length = 0;
  answer = instance.verify(PERSON, WRONG, { via: 'the test' });
  t.check(!answer.ok && calls.length === 1 && calls[0].stored === real,
          'E1. a real person\'s wrong password is one comparison against ' +
          'their own hash, and no decoy', answer.reason + ' ' + calls.length);
  calls.length = 0;
  answer = await instance.verifyAsync(PERSON, WRONG, { via: 'the test' });
  t.check(!answer.ok && calls.length === 1 && calls[0].stored === real &&
          calls[0].door === 'async',
          'E2. and the same on the asynchronous door', answer.reason);

  // --- F. development mode -------------------------------------------------
  product = false;
  calls.length = 0;
  answer = instance.verify(NOBODY, WRONG, { via: 'the test' });
  const asyncAnswer = await instance.verifyAsync(DISABLED, WRONG,
                                                 { via: 'the test' });
  t.check(answer.ok && answer.reason === 'development-mode' &&
          !asyncAnswer.ok && calls.length === 0,
          'F1. development mode compares nothing, decoy included',
          answer.reason + ' ' + asyncAnswer.reason + ' ' + calls.length);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'password_unknown_name_cost',
  describe: 'a password refusal that needed no comparison (nobody by that ' +
            'name, an unreadable stored value, a disabled account) still ' +
            'verifies against a decoy hash, on both doors (#2136)',
  run: run
};
