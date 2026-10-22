// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: password_argon2id.js
//
// ===========================================================================
// ARGON2ID FOR A PERSON'S PASSWORD, AND THE UPGRADE ON SIGN-IN
// (2026-10-22, #847).
//
// rcbj's four decisions on #847, each held here:
//
//   1. argon2id, through node's own `crypto.argon2()` / `argon2Sync()`, at
//      OWASP's minimum (m=19456 KiB, t=2, p=1), in the PHC string form.
//   2. The password policy names the algorithm and both algorithms'
//      parameters; no bound is below OWASP's minimum; scrypt stays
//      selectable.
//   3. Every OTHER secret stays scrypt (`hashSecret()`), and every stored
//      form keeps verifying.
//   4. A verified password whose stored hash is not the policy's algorithm
//      AND parameters is hashed again and written back — a parameter change
//      counts as much as an algorithm change.
//
// THE DEFAULT IS scrypt AGAIN SINCE 2026-10-22 (rcbj, #820): "Make the
// default scrypt hashes, but keep argon2id as a supported option." The
// default is scrypt at N=2^15, r=8, p=1, the pre-#847 parameters, so
// decision 1 holds for argon2id only where a policy selects it, and the
// sections below select it explicitly where they need it. OWASP's scrypt
// table is no longer a floor: `passwordHashSpec()` takes p as asked and the
// policy saves 2^15 with p=1, its own default. #872 restores both checks.
// Rule 4 is unchanged, so a person holding an argon2id hash is hashed again
// with scrypt at their next sign-in under the default (section F).
//
// Sections:
//   A. crypto: the default, the round trip, scrypt and argon2id side by
//      side, argon2id's floors, scrypt's p taken as asked.
//   B. the policy's seven rows and their bounds.
//   C. the upgrade on sign-in: an algorithm change, a parameter change, both
//      doors; nothing for a wrong password or in development.
//   D. a history holding both forms.
//   E. the console's view and the management API's request schema carry the
//      same rows (rule 7).
//   F. an argon2id hash rehashed to the scrypt default at sign-in.
//
// In process for `password_policy.js`'s reason: what a hash was written under
// is in the stored value, which no endpoint returns.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const crypto = require('../common/crypto');
const credentials = require('../common/credentials');
const passwordPolicy = require('../common/password_policy');
const ldap = require('../ldap/ldap_server');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({ name: 'password_argon2id',
  level: process.env.LOG_LEVEL || 'info' });

// The PHC string at OWASP's minimum: salt and hash in base64, no padding.
// It is argon2id's default, the hash a policy naming argon2id writes.
const ARGON2_DEFAULT =
  /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/;

// The DEFAULT password hash (#820): scrypt at N=2^15, r=8, p=1.
const SCRYPT_DEFAULT = /^\$scrypt\$32768\$8\$1\$/;

// argon2id at OWASP's minimum, named, since it is no longer the default.
const ARGON2 = { algorithm: 'argon2id' };

// Every row of the profile at its built-in value, with `changes` over it.
function profileWith(changes) {
  log.debug("Entering profileWith().");
  log.debug("Leaving profileWith().");
  return Object.assign({}, passwordPolicy.DEFAULTS, changes || {});
}

// The person's stored hash.
function storedOf(username) {
  log.debug("Entering storedOf().");
  const view = ldap.objectFor(username);
  const attributes = (view && view.entry && view.entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === 'userpassword';
  })[0];
  log.debug("Leaving storedOf().");
  return key ? String([].concat(attributes[key])[0]) : '';
}

function historyOf(username) {
  log.debug("Entering historyOf().");
  const view = ldap.objectFor(username);
  const attributes = (view && view.entry && view.entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === 'pwdhistory';
  })[0];
  log.debug("Leaving historyOf().");
  return key ? [].concat(attributes[key]).map(String) : [];
}

// A product-mode run of `fn`, the setting put back however it ends.
async function inProduct(fn) {
  log.debug("Entering inProduct().");
  config.setOverride('global.mode', 'product');
  config.setOverride('risk.breachCheck', 'off');
  try {
    return await fn();
  } finally {
    config.clearOverride('global.mode');
    config.clearOverride('risk.breachCheck');
    log.debug("Leaving inProduct().");
  }
}

function msOf(fn) {
  log.debug("Entering msOf().");
  const started = process.hrtime.bigint();
  fn();
  log.debug("Leaving msOf().");
  return Number(process.hrtime.bigint() - started) / 1e6;
}

// ---------------------------------------------------------------------------
// A. crypto.
// ---------------------------------------------------------------------------
async function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. argon2id and scrypt side by side ===');
  t.check(crypto.argon2Available(),
          'A0. this runtime has node\'s argon2 (node 24.7 and later)',
          process.version);
  const unnamed = crypto.hashPassword('Default-Passw0rd!');
  t.check(SCRYPT_DEFAULT.test(unnamed) &&
          crypto.verifySecret('Default-Passw0rd!', unnamed),
          'A1. a password hashed with no spec is scrypt at 2^15, r=8, p=1 ' +
          '(the pre-#847 default, #820), and verifies',
          unnamed.slice(0, 24));
  const argon = crypto.hashPassword('Argon-Passw0rd!', ARGON2);
  t.check(ARGON2_DEFAULT.test(argon),
          'A1b. argon2id, asked for, is at OWASP\'s minimum in the PHC ' +
          'string form', argon.slice(0, 40));
  t.check(crypto.verifySecret('Argon-Passw0rd!', argon) &&
          !crypto.verifySecret('argon-passw0rd!', argon),
          'A2. it verifies the right password and refuses a wrong one');
  t.check(await crypto.verifySecretAsync('Argon-Passw0rd!', argon) &&
          !(await crypto.verifySecretAsync('nope', argon)),
          'A3. and the asynchronous door agrees');
  const asyncArgon = await crypto.hashPasswordAsync('Async-Passw0rd!',
    { algorithm: 'argon2id' });
  t.check(ARGON2_DEFAULT.test(asyncArgon) &&
          crypto.verifySecret('Async-Passw0rd!', asyncArgon),
          'A4. the asynchronous hash writes the same form, and the ' +
          'synchronous door verifies it', asyncArgon.slice(0, 40));
  const scrypted = crypto.hashPassword('Scrypt-Passw0rd!',
    { algorithm: 'scrypt', logN: 17, r: 8, p: 1 });
  t.check(/^\$scrypt\$131072\$8\$1\$/.test(scrypted) &&
          crypto.verifySecret('Scrypt-Passw0rd!', scrypted),
          'A5. scrypt stays selectable, at the policy\'s parameters',
          scrypted.slice(0, 24));
  const legacy = crypto.hashSecret('Legacy-Passw0rd!');
  t.check(/^\$scrypt\$32768\$8\$1\$/.test(legacy) &&
          crypto.verifySecret('Legacy-Passw0rd!', legacy),
          'A6. hashSecret() — every non-password secret — is still scrypt ' +
          'at 2^15, and a hash it wrote still verifies', legacy.slice(0, 24));
  t.check(crypto.isHashedSecret(argon) && crypto.isHashedSecret(legacy) &&
          !crypto.isHashedSecret('plain'),
          'A7. isHashedSecret() knows both forms and nothing else');
  // THE FLOORS, IN crypto.js: a spec below OWASP is raised to it.
  const low = crypto.passwordHashSpec({ algorithm: 'argon2id', memory: 1024,
                                        passes: 1, parallelism: 1 });
  t.check(low.memory === 19456 && low.passes === 2,
          'A8. an argon2id spec below OWASP\'s minimum is raised to it, ' +
          'whatever reached this file', JSON.stringify(low));
  // OWASP's scrypt table is not a floor while the default is below it
  // (#820; #872 restores it): p is the one asked for.
  const thin = crypto.passwordHashSpec({ algorithm: 'scrypt', logN: 14, r: 8,
                                         p: 1 });
  const wide = crypto.passwordHashSpec({ algorithm: 'scrypt', logN: 14, r: 8,
                                         p: 4 });
  t.check(thin.logN === 14 && thin.p === 1 && wide.p === 4,
          'A9. scrypt\'s parallelism is taken as asked (1 and 4 at 2^14), ' +
          'not raised to OWASP\'s table', JSON.stringify([thin, wide]));
  t.check(crypto.storedSecretMatchesSpec(argon, { algorithm: 'argon2id' }) &&
          !crypto.storedSecretMatchesSpec(argon, { algorithm: 'argon2id',
                                                   memory: 20480 }) &&
          !crypto.storedSecretMatchesSpec(legacy, { algorithm: 'argon2id' }) &&
          crypto.storedSecretMatchesSpec(legacy, null) &&
          !crypto.storedSecretMatchesSpec(argon, null) &&
          !crypto.storedSecretMatchesSpec(legacy, { algorithm: 'scrypt',
                                                    logN: 16 }),
          'A10. storedSecretMatchesSpec() reads the algorithm AND every ' +
          'parameter, and a scrypt hash at 2^15 already is the default');
  // A tampered parameter must not verify.
  const tampered = argon.replace('m=19456', 'm=19457');
  t.check(!crypto.verifySecret('Argon-Passw0rd!', tampered),
          'A11. a stored form whose parameters were edited does not verify');
  // THE COST, logged for the record (#847's report), asserted nothing.
  const argonMs = msOf(function () {
    crypto.hashPassword('Timing-Passw0rd!', ARGON2);
  });
  const defaultMs = msOf(function () {
    crypto.hashPassword('Timing-Passw0rd!');
  });
  const scrypt15Ms = msOf(function () {
    crypto.hashPassword('Timing-Passw0rd!', { algorithm: 'scrypt', logN: 15,
                                              r: 8, p: 3 });
  });
  const scrypt17Ms = msOf(function () {
    crypto.hashPassword('Timing-Passw0rd!', { algorithm: 'scrypt', logN: 17,
                                              r: 8, p: 1 });
  });
  const secretMs = msOf(function () {
    crypto.hashSecret('Timing-Passw0rd!');
  });
  t.log.info({ passwordDefaultScrypt15p1Ms: defaultMs,
               argon2idMinimumMs: argonMs, scrypt15p3Ms: scrypt15Ms,
               scrypt17p1Ms: scrypt17Ms, hashSecretScrypt15p1Ms: secretMs },
             'COST of one hash on this machine (information only)');
  log.debug("Leaving sectionA().");
}

// ---------------------------------------------------------------------------
// B. the policy's rows.
// ---------------------------------------------------------------------------
function sectionB(t) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. the seven rows and their bounds ===');
  passwordPolicy.reset('default');
  const built = passwordPolicy.read('default');
  t.check(built.hashAlgorithm === 'scrypt' && built.argon2Memory === 19456 &&
          built.argon2Iterations === 2 && built.argon2Parallelism === 1 &&
          built.scryptLogN === 15 && built.scryptBlockSize === 8 &&
          built.scryptParallelism === 1,
          'B1. the built-in profile is scrypt at 2^15, r=8, p=1 (#820), ' +
          'with argon2id\'s rows at m=19456, t=2, p=1',
          JSON.stringify(built));
  t.equal(JSON.stringify(passwordPolicy.hashSpec(built)),
          JSON.stringify({ algorithm: 'scrypt', logN: 15, r: 8, p: 1 }),
          'B2. hashSpec() answers it in crypto.js\'s shape');
  t.equal(JSON.stringify(passwordPolicy.hashSpec(
            profileWith({ hashAlgorithm: 'argon2id' }))),
          JSON.stringify({ algorithm: 'argon2id', memory: 19456, passes: 2,
                           parallelism: 1 }),
          'B2b. and argon2id, selected, in its own');
  const below = [
    ['argon2Memory', 19455], ['argon2Iterations', 1],
    ['argon2Parallelism', 0], ['scryptLogN', 12], ['scryptBlockSize', 7],
    ['hashAlgorithm', 'bcrypt']
  ];
  below.forEach(function (pair) {
    const change = {};
    change[pair[0]] = pair[1];
    const saved = passwordPolicy.save('default', profileWith(change));
    t.check(!saved.ok,
            'B3. ' + pair[0] + ' = ' + pair[1] + ' is refused',
            JSON.stringify(saved.errors || saved));
  });
  // Below OWASP's table and SAVED: it is the default (#820), and a policy
  // must be able to save its own default. #872 brings the refusal back.
  const pair = passwordPolicy.save('default', profileWith(
    { hashAlgorithm: 'scrypt', scryptLogN: 15, scryptParallelism: 1 }));
  const pairRead = passwordPolicy.read('default');
  t.check(pair.ok && pairRead.scryptLogN === 15 &&
          pairRead.scryptParallelism === 1,
          'B4. scrypt at 2^15 with p=1, the default, is saved although it ' +
          'is below OWASP\'s table', JSON.stringify(pair.errors));
  const thinner = passwordPolicy.save('default', profileWith(
    { hashAlgorithm: 'scrypt', scryptLogN: 13, scryptParallelism: 1 }));
  t.check(thinner.ok,
          'B4b. and so is 2^13 with p=1: the table is not enforced until ' +
          '#872', JSON.stringify(thinner.errors));
  const fine = passwordPolicy.save('default', profileWith(
    { hashAlgorithm: 'scrypt', scryptLogN: 15, scryptParallelism: 3 }));
  t.check(fine.ok && passwordPolicy.read('default').hashAlgorithm === 'scrypt',
          'B5. scrypt at 2^15 with p=3 is saved',
          JSON.stringify(fine.errors));
  // OPTIONAL: a save written before the rows existed keeps them.
  const old = {};
  ['minLength', 'history', 'minSymbols', 'requireUppercase', 'requireDigit',
   'generatedLength'].forEach(function (key) {
    old[key] = passwordPolicy.DEFAULTS[key];
  });
  const kept = passwordPolicy.save('default', old);
  const after = passwordPolicy.read('default');
  t.check(kept.ok && after.hashAlgorithm === 'scrypt' &&
          after.scryptLogN === 15 && after.scryptParallelism === 3,
          'B6. a save naming only the six composition rows keeps the hash ' +
          'rows in force rather than resetting them',
          JSON.stringify(kept.errors));
  passwordPolicy.reset('default');
  log.debug("Leaving sectionB().");
}

// ---------------------------------------------------------------------------
// C. the upgrade on sign-in.
// ---------------------------------------------------------------------------
async function sectionC(t) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. the upgrade on a verified sign-in ===');
  const who = 'argon2id-upgrade-probe';
  const password = 'Upgrade-Passw0rd!';
  ldap.createUser(who, {});
  await inProduct(async function () {
    passwordPolicy.save('default', profileWith(
      { hashAlgorithm: 'scrypt', history: 0 }));
    t.check(credentials.setPassword(who, password).ok,
            'C0. a password is set while the policy says scrypt');
    const scrypted = storedOf(who);
    t.check(SCRYPT_DEFAULT.test(scrypted),
            'C1. and is stored as scrypt at the policy\'s 2^15, r=8, p=1',
            scrypted.slice(0, 24));
    const historyBefore = historyOf(who).join('|');

    passwordPolicy.save('default', profileWith(
      { history: 0, hashAlgorithm: 'argon2id' }));
    const wrong = credentials.verify(who, 'Not-The-Passw0rd!');
    t.check(!wrong.ok && storedOf(who) === scrypted,
            'C2. a WRONG password upgrades nothing');
    const right = credentials.verify(who, password);
    const upgraded = storedOf(who);
    t.check(right.ok && ARGON2_DEFAULT.test(upgraded),
            'C3. the policy moved to argon2id: the next verified sign-in ' +
            'writes an argon2id hash in its place', upgraded.slice(0, 40));
    t.check(crypto.verifySecret(password, upgraded) &&
            credentials.verify(who, password).ok,
            'C4. which verifies, and the next sign-in still signs in');
    t.check(storedOf(who) === upgraded,
            'C5. and a sign-in under a hash already in force writes nothing');
    t.equal(historyOf(who).join('|'), historyBefore,
            'C6. pwdHistory is untouched: the password did not change');

    // A PARAMETER change counts (rcbj's decision 4).
    passwordPolicy.save('default', profileWith(
      { history: 0, hashAlgorithm: 'argon2id', argon2Memory: 20480 }));
    const viaAsync = await credentials.verifyAsync(who, password);
    const raised = storedOf(who);
    t.check(viaAsync.ok &&
            /^\$argon2id\$v=19\$m=20480,t=2,p=1\$/.test(raised),
            'C7. a PARAMETER change in the same algorithm is upgraded too, ' +
            'and through the asynchronous door', raised.slice(0, 40));

    // Back to scrypt: the upgrade goes either way.
    passwordPolicy.save('default', profileWith({ history: 0,
      hashAlgorithm: 'scrypt', scryptLogN: 16, scryptParallelism: 2 }));
    t.check(credentials.verify(who, password).ok &&
            /^\$scrypt\$65536\$8\$2\$/.test(storedOf(who)),
            'C8. and a move back to scrypt is upgraded to scrypt\'s ' +
            'parameters', storedOf(who).slice(0, 24));

    // Compare and set: a hash changed under the upgrade is not overwritten.
    passwordPolicy.save('default', profileWith({ history: 0 }));
    const held = storedOf(who);
    t.check(credentials.setPassword(who, 'Another-Passw0rd!').ok,
            'C9. (the password is changed meanwhile)');
    const newer = storedOf(who);
    t.check(credentials.upgradeHash(who, password, held) === false &&
            storedOf(who) === newer,
            'C10. an upgrade of a hash the entry no longer holds is dropped ' +
            '— the newer password stands');
    passwordPolicy.reset('default');
  });

  // Development checks no password, so nothing is upgraded there.
  passwordPolicy.save('default', profileWith({ hashAlgorithm: 'scrypt' }));
  credentials.setPassword(who, password);
  const devStored = storedOf(who);
  passwordPolicy.reset('default');
  const dev = credentials.verify(who, password);
  t.check(dev.ok && storedOf(who) === devStored &&
          /^\$scrypt\$/.test(devStored),
          'C11. DEVELOPMENT mode verifies nothing, so it never rewrites a ' +
          'hash — whatever was typed would have become the password',
          dev.reason);
  log.debug("Leaving sectionC().");
}

// ---------------------------------------------------------------------------
// D. a history of both forms.
// ---------------------------------------------------------------------------
async function sectionD(t) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. a history holding both forms ===');
  const who = 'argon2id-history-probe';
  ldap.createUser(who, {});
  await inProduct(async function () {
    passwordPolicy.save('default', profileWith({ hashAlgorithm: 'scrypt',
                                                 history: 3 }));
    t.check(credentials.setPassword(who, 'First-Passw0rd!').ok,
            'D0. a first password, stored as scrypt');
    passwordPolicy.save('default', profileWith(
      { hashAlgorithm: 'argon2id', history: 3 }));
    t.check(credentials.setPassword(who, 'Second-Passw0rd!').ok &&
            ARGON2_DEFAULT.test(storedOf(who)),
            'D1. a second, stored as argon2id once the policy selects it');
    t.check(credentials.setPassword(who, 'Third-Passw0rd!').ok,
            'D2. a third');
    const history = historyOf(who);
    t.check(history.some(function (one) { return /#\$scrypt\$/.test(one); }) &&
            history.some(function (one) { return /#\$argon2id\$/.test(one); }),
            'D3. pwdHistory holds a scrypt hash and an argon2id hash, each ' +
            'kept in the form it was stored in', history.join(' | ')
              .replace(/\$[A-Za-z0-9+/]{20,}/g, '…'));
    const again1 = credentials.setPassword(who, 'First-Passw0rd!');
    const again2 = credentials.setPassword(who, 'Second-Passw0rd!');
    t.check(!again1.ok && !again2.ok,
            'D4. and both are refused as remembered — each verified by its ' +
            'own form', JSON.stringify([again1.reason, again2.reason]));
    passwordPolicy.reset('default');
  });
  log.debug("Leaving sectionD().");
}

// ---------------------------------------------------------------------------
// E. the console's view and the API's schema (rule 7).
// ---------------------------------------------------------------------------
function sectionE(t) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. the console and the management API carry the rows ===');
  const rows = ['hashAlgorithm', 'argon2Memory', 'argon2Iterations',
                'argon2Parallelism', 'scryptLogN', 'scryptBlockSize',
                'scryptParallelism'];
  const view = adminViews.policiesView({});
  const fields = ((view && view.password && view.password.fields) || [])
    .map(function (one) { return one.key; });
  t.check(rows.every(function (key) { return fields.indexOf(key) >= 0; }),
          'E1. the Policies page\'s view draws the seven rows',
          fields.join(', '));
  const adminApi = require('../mgmt-api/admin_api');
  let schema = null;
  adminApi.ROUTES.forEach(function (entry) {
    (entry.actions || []).forEach(function (one) {
      if (one.action === 'save-password-policy') {
        schema = one.requestBody || {};
      }
    });
  });
  const properties = (schema && schema.properties) || {};
  const required = (schema && schema.required) || [];
  t.check(!!schema && rows.every(function (key) {
            return !!properties[key] && required.indexOf(key) < 0;
          }),
          'E2. save-password-policy takes the seven rows, none of them ' +
          'required', JSON.stringify(Object.keys(properties)));
  t.check(JSON.stringify((properties.hashAlgorithm || {}).enum) ===
          JSON.stringify(['scrypt', 'argon2id']),
          'E3. and the algorithm is a closed set of two, scrypt first',
          JSON.stringify(properties.hashAlgorithm));
  const memory = (properties.argon2Memory || {}).oneOf || [];
  t.check(memory.some(function (one) { return one.minimum === 19456; }),
          'E4. and the memory row\'s minimum is OWASP\'s 19456 KiB',
          JSON.stringify(memory));
  log.debug("Leaving sectionE().");
}

// ---------------------------------------------------------------------------
// F. an argon2id hash under the scrypt default.
// ---------------------------------------------------------------------------
// A person whose password was stored as argon2id (by #847's default, or a
// policy that selected it) signs in under the scrypt default. Rule 4 is
// "different from the policy", not "weaker", so the sign-in succeeds and the
// stored hash becomes scrypt at 2^15, r=8, p=1 (#820, deliberately).
async function sectionF(t) {
  log.debug("Entering sectionF().");
  t.log.info('=== F. argon2id rehashed to the scrypt default ===');
  const who = 'argon2id-to-scrypt-probe';
  const password = 'Default-Again-Passw0rd!';
  ldap.createUser(who, {});
  await inProduct(async function () {
    passwordPolicy.save('default', profileWith(
      { hashAlgorithm: 'argon2id', history: 0 }));
    t.check(credentials.setPassword(who, password).ok &&
            ARGON2_DEFAULT.test(storedOf(who)),
            'F0. a password is stored as argon2id while the policy selects it',
            storedOf(who).slice(0, 40));
    passwordPolicy.reset('default');
    t.equal(passwordPolicy.read('default').hashAlgorithm, 'scrypt',
            'F1. the policy is back at its default, scrypt');
    const signIn = credentials.verify(who, password);
    const after = storedOf(who);
    t.check(signIn.ok, 'F2. the sign-in succeeds', signIn.reason);
    t.check(SCRYPT_DEFAULT.test(after) &&
            crypto.storedSecretMatchesSpec(after, null),
            'F3. and the stored hash is now scrypt at 2^15, r=8, p=1',
            after.slice(0, 24));
    t.check(crypto.verifySecret(password, after) &&
            credentials.verify(who, password).ok &&
            storedOf(who) === after,
            'F4. it verifies, and the next sign-in writes nothing');

    // The same through the asynchronous door.
    passwordPolicy.save('default', profileWith(
      { hashAlgorithm: 'argon2id', history: 0 }));
    credentials.setPassword(who, password);
    passwordPolicy.reset('default');
    const viaAsync = await credentials.verifyAsync(who, password);
    t.check(viaAsync.ok && SCRYPT_DEFAULT.test(storedOf(who)),
            'F5. and through the asynchronous door too',
            storedOf(who).slice(0, 24));
    passwordPolicy.reset('default');
  });
  log.debug("Leaving sectionF().");
}

module.exports = {
  name: 'password_argon2id',
  describe: 'a person\'s password hash (#847, #820): scrypt at 2^15 ' +
            'by default and argon2id when selected, the password policy\'s ' +
            'hash rows and their bounds, the upgrade at a verified sign-in ' +
            'for an algorithm or a parameter change, a history of both ' +
            'forms, the console and API carrying the rows, and an argon2id ' +
            'hash rehashed to the scrypt default',
  run: async function (t) {
    log.debug("Entering run().");
    try {
      await sectionA(t);
      sectionB(t);
      await sectionC(t);
      await sectionD(t);
      sectionE(t);
      await sectionF(t);
    } finally {
      passwordPolicy.reset('default');
    }
    log.debug("Leaving run().");
  }
};
