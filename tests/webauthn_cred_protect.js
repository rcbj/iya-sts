// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/webauthn_cred_protect.js
//
// ===========================================================================
// CTAP 2.1's credProtect, ASKED AND HELD BY THE PASSKEY POLICY (#1955 P7).
//
//   C1. OFF BY DEFAULT: a registration's options carry no credProtect, and
//       the browser runtime makes no extension of it — the options are what
//       they were.
//   C2. A LEVEL ASKED: the profile's credProtect reaches the options as
//       `credentialProtectionPolicy`, and `enforceCredProtect` as
//       `enforceCredentialProtectionPolicy`; `WebWebAuthn.
//       creationExtensions()` turns both into `extensions`.
//   C3. A SAVE ENFORCING NO LEVEL is refused (STS-AUTHN-0560).
//   C4. THE OUTPUT READ: a registration whose authenticator data carries the
//       extension (the ED flag and a CBOR map) is parsed and its level
//       reported; without one, none.
//   C5. THE ENFORCE REFUSAL, decided by the issuance policy: a reported
//       level below the enforced one — and none reported, which is level 1
//       — is refused (STS-AUTHN-0559, reason `cred-protect`); the level
//       itself or a higher one is not; and with enforcement off nothing is
//       refused. The strict reading (`passkey_rules.js`) agrees each time.
//   C6. THE ONE WRITER: `credentials.addKey()` refuses a key reporting a
//       lower level, and records the level of one it writes.
//
// IN PROCESS: the policy is a library over the directory, and a realm is
// created and removed here.
// ===========================================================================

delete process.env.CONFIG_FILE;

const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const passkeyPolicy = require('../common/passkey_policy');
const passkeyRules = require('../common/passkey_rules');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const webauthnPolicy = require('../authn/webauthn_policy');
const webauthn = require('../authn/webauthn');
const WebWebAuthn = require('../common/web_webauthn');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({ name: 'webauthn_cred_protect',
  level: process.env.LOG_LEVEL || 'info' });

/**
 * Every field at its built-in value, with the given ones over them.
 *
 * @param {object} [fields] - the fields to change
 * @returns {object} the profile as a save takes it
 */
function withDefaults(fields) {
  log.debug('Entering withDefaults().');
  log.debug('Leaving withDefaults().');
  return Object.assign({}, passkeyPolicy.DEFAULTS, fields || {});
}

/**
 * Runs `fn` in a realm of its own, removed afterwards.
 *
 * @param {object} t - the test context
 * @param {Function} fn - what to run
 * @returns {Promise<void>} when it has run
 */
async function inRealm(t, fn) {
  log.debug('Entering inRealm().');
  const id = 'cred-protect-' + require('crypto').randomBytes(3)
    .toString('hex');
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving inRealm(). Not created.');
    return;
  }
  try {
    await realms.run(made.realm, function () {
      return fn(made.realm);
    });
  } finally {
    realms.remove(id);
  }
  log.debug('Leaving inRealm().');
}

/**
 * C1 to C3: the options, per profile, and the save refusal.
 *
 * @param {object} t - the test context
 * @returns {void}
 */
function options(t) {
  log.debug('Entering options().');
  const plain = webauthnPolicy.creationOptions('localhost', 'security-key');
  t.check(plain.credProtect === undefined &&
          WebWebAuthn.creationExtensions({ credProtect: undefined }) ===
            undefined &&
          passkeyPolicy.DEFAULTS.credProtect === 'none' &&
          passkeyPolicy.DEFAULTS.enforceCredProtect === false,
          'C1. off by default: no credProtect in the options, and no ' +
          'extension made of none', JSON.stringify(plain));
  const asked = passkeyPolicy.save('default', withDefaults({
    credProtect: 'userVerificationOptionalWithCredentialIDList' }));
  const level2 = webauthnPolicy.creationOptions('localhost', 'security-key');
  const enforced = passkeyPolicy.save('default', withDefaults({
    credProtect: 'userVerificationRequired', enforceCredProtect: true }));
  const level3 = webauthnPolicy.creationOptions('localhost', 'security-key');
  const ext = WebWebAuthn.creationExtensions(level3);
  t.check(asked.ok && enforced.ok &&
          level2.credProtect.credentialProtectionPolicy ===
            'userVerificationOptionalWithCredentialIDList' &&
          level2.credProtect.enforceCredentialProtectionPolicy === false &&
          level3.credProtect.credentialProtectionPolicy ===
            'userVerificationRequired' &&
          level3.credProtect.enforceCredentialProtectionPolicy === true &&
          ext.credentialProtectionPolicy === 'userVerificationRequired' &&
          ext.enforceCredentialProtectionPolicy === true &&
          ext.credProps === true,
          'C2. the level and the enforcement reach the options, and the ' +
          'runtime makes them the client extension inputs',
          JSON.stringify([asked.errors, enforced.errors, level2.credProtect,
                          level3.credProtect, ext]));
  const nothing = passkeyPolicy.save('default', withDefaults({
    credProtect: 'none', enforceCredProtect: true }));
  t.check(!nothing.ok && errorCodes.codeOf(nothing) === 'STS-AUTHN-0560',
          'C3. enforcing credProtect with none asked for is refused ' +
          '(STS-AUTHN-0560)', JSON.stringify(nothing.errors));
  log.debug('Leaving options().');
}

/**
 * C4: the extension output parsed out of the authenticator data.
 *
 * @param {object} t - the test context
 * @returns {Promise<void>} when checked
 */
async function parsed(t) {
  log.debug('Entering parsed().');
  const withExt = await kit.ceremony({
    extensions: new Map([['credProtect', 3]]) });
  const made = webauthn.verifyRegistration(withExt.input(kit.none()));
  const without = await kit.ceremony({});
  const plain = webauthn.verifyRegistration(without.input(kit.none()));
  t.check(made.ok && made.flags.ed === true &&
          made.extensions && made.extensions.credProtect === 3 &&
          credentials.reportedCredProtect(made) === 3 &&
          plain.ok && plain.extensions === null &&
          credentials.reportedCredProtect(plain) === null &&
          passkeyPolicy.reportedCredProtect({ credProtect: 4 }) === null,
          'C4. the authenticator data\'s credProtect output is read, and ' +
          'its absence (or a level CTAP does not define) is none',
          JSON.stringify([made.failed, made.extensions, plain.failed]));
  log.debug('Leaving parsed().');
}

/**
 * C5: the refusal, by the issuance policy and by the strict reading.
 *
 * @param {object} t - the test context
 * @returns {void}
 */
function refusals(t) {
  log.debug('Entering refusals().');
  const profile = passkeyPolicy.read();
  const ask = function (reported) {
    log.debug('Entering refusals() ask().');
    const refused = passkeyPolicy.refusalFor('registration',
      { username: 'cp-person', credProtect: reported }, profile);
    const strict = passkeyRules.strictReading(passkeyPolicy.question(
      'registration', { username: 'cp-person', credProtect: reported },
      profile));
    log.debug('Leaving refusals() ask().');
    return { code: refused ? refused.code : '',
             reason: refused ? refused.reason : '',
             strict: strict.code };
  };
  const two = ask(2);
  const none = ask(null);
  const three = ask(3);
  t.check(two.code === 'STS-AUTHN-0559' && two.reason === 'cred-protect' &&
          two.strict === 'STS-AUTHN-0559' &&
          none.code === 'STS-AUTHN-0559' && none.strict === 'STS-AUTHN-0559' &&
          three.code === '' && three.strict === '',
          'C5. enforced at level 3: level 2 and none reported are refused ' +
          '(STS-AUTHN-0559), level 3 is not, and the strict reading agrees',
          JSON.stringify([two, none, three]));
  const relaxed = passkeyPolicy.save('default', withDefaults({
    credProtect: 'userVerificationRequired', enforceCredProtect: false }));
  const loose = passkeyPolicy.refusalFor('registration',
    { username: 'cp-person', credProtect: 1 }, passkeyPolicy.read());
  t.check(relaxed.ok && loose === null,
          'C5b. asked but not enforced, a lower level is recorded and not ' +
          'refused', JSON.stringify(loose));
  log.debug('Leaving refusals().');
}

/**
 * C6: the one writer refuses and records.
 *
 * @param {object} t - the test context
 * @returns {void}
 */
function writer(t) {
  log.debug('Entering writer().');
  const enforced = passkeyPolicy.save('default', withDefaults({
    credProtect: 'userVerificationOptionalWithCredentialIDList',
    enforceCredProtect: true }));
  const name = 'cp-' + require('crypto').randomBytes(3).toString('hex');
  ldap.createUser(name, { invent: false });
  // A trusted attestation: while the level is enforced it must be proven
  // (the #1955 review), and only a trusted attestation vouches for it.
  const key = function (id, level, untrusted) {
    log.debug('Entering writer() key().');
    log.debug('Leaving writer() key().');
    return credentials.addKey(name, { credentialId: id,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      algorithm: 'ES256', coseAlg: -7, credProtect: level,
      attestation: untrusted ? undefined
        : { verified: true, trusted: true, format: 'packed',
            type: 'basic', anchor: 'configured', checkedAt: Date.now() } });
  };
  const low = key('cp-low', 1);
  const unproven = key('cp-unproven', 3, true);
  t.check(unproven.ok === false && errorCodes.codeOf(unproven) ===
          'STS-AUTHN-0559',
          'C6a. A LEVEL WITH NO TRUSTED ATTESTATION BEHIND IT IS NO PROOF: ' +
          'it counts as level 1 while the level is enforced',
          JSON.stringify(unproven));
  const imported = credentials.addKey(name, { credentialId: 'cp-u2f',
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
    algorithm: 'ES256', coseAlg: -7, appid: 'https://u2f.example' });
  t.equal(errorCodes.codeOf(imported), 'STS-AUTHN-0580',
          'C6b. an imported U2F key is refused while the level is enforced');
  const ok = key('cp-ok', 3);
  const held = credentials.keysOf(name);
  const written = held.filter(function (one) {
    return one.credentialId === 'cp-ok';
  })[0] || {};
  t.check(enforced.ok && low.ok === false &&
          errorCodes.codeOf(low) === 'STS-AUTHN-0559' &&
          low.reason === 'cred-protect' && ok.ok &&
          written.credProtect === 3 &&
          !held.some(function (one) {
            return one.credentialId === 'cp-low';
          }),
          'C6. addKey() refuses a key below the enforced level and records ' +
          'the level of the one it writes',
          JSON.stringify([enforced.errors, low, ok.errors, written]));
  log.debug('Leaving writer().');
}

module.exports = {
  name: 'webauthn credProtect',
  describe: 'CTAP 2.1 credProtect (#1955 P7): off by default, asked and ' +
            'enforced as the passkey policy says, read out of the ' +
            'authenticator data, refused by the issuance policy below the ' +
            'enforced level, and recorded on the key',
  run: async function (t) {
    log.debug('Entering run().');
    void ldap;
    await inRealm(t, async function () {
      try {
        options(t);
        await parsed(t);
        refusals(t);
        writer(t);
      } finally {
        passkeyPolicy.reset('default');
      }
    });
    log.debug('Leaving run().');
  }
};
