// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_enterprise_serial.js
//
// ===========================================================================
// A SECURITY KEY'S SERIAL BOUND TO THE PERSON ENROLLING IT (#532): the
// passkey policy's `enterpriseSerialAttribute`.
//
//   1. `pki.attestationDeviceSerial()` reads a serial from the subject's
//      serialNumber, and from Yubico's serial extension, and finds none in a
//      certificate with neither.
//   2. The attribute set demands a TRUSTED statement, as an AAGUID list
//      does, and a packed attestation under a trusted anchor records the
//      serial its certificate names — both places.
//   3. `credentials.addKey()`, the one writer, takes a key whose serial is
//      one of the person's values (case and spaces aside), and refuses one
//      that is not (STS-AUTHN-0320) and one that names none
//      (STS-AUTHN-0321); with the attribute empty nothing is checked.
//   4. The directory hook never answers a secret attribute.
//
// The certificates are made at run time by `webauthn_attestation_kit.js`;
// no key material is in this repository.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const passkeyPolicy = require('../common/passkey_policy');
const credentials = require('../common/credentials');
const pki = require('../common/pki');
const ldap = require('../ldap/ldap_server');
const webauthn = require('../authn/webauthn');
const webauthnPolicy = require('../authn/webauthn_policy');
const attestation = require('../authn/webauthn_attestation');
const kit = require('./webauthn_attestation_kit');

const log = require('bunyan').createLogger({
  name: 'passkey_enterprise_serial', level: process.env.LOG_LEVEL || 'info' });

function withAttribute(name) {
  log.debug('Entering withAttribute().');
  log.debug('Leaving withAttribute().');
  return passkeyPolicy.save('default', Object.assign({},
    passkeyPolicy.DEFAULTS, { enterpriseSerialAttribute: name }));
}

async function certificates(t) {
  log.debug('Entering certificates().');
  const root = await kit.root('Serial Vendor');
  const ctx = await kit.ceremony({});
  const named = await kit.packed(ctx, root, null, null,
                                 { subject: 'SN-0042-A' });
  const yubico = await kit.packed(ctx, root, null, null, { yubico: 18273645 });
  const plain = await kit.packed(ctx, root);
  const a = pki.attestationDeviceSerial(named.leaf.der);
  const b = pki.attestationDeviceSerial(yubico.leaf.der);
  t.check(a && a.serial === 'SN-0042-A' &&
          a.source === 'subject-serialNumber' &&
          b && b.serial === '18273645' && b.source === 'yubico-extension' &&
          pki.attestationDeviceSerial(plain.leaf.der) === null &&
          pki.attestationDeviceSerial(Buffer.from('not a certificate')) ===
            null,
          '1. a serial is read from the subject\'s serialNumber and from ' +
          'Yubico\'s extension, and none from a certificate with neither',
          JSON.stringify([a, b]));
  log.debug('Leaving certificates().');
  return root;
}

async function recorded(t, root) {
  log.debug('Entering recorded().');
  withAttribute('serialNumber');
  config.setOverride('webauthn.attestationPolicy', 'verify-if-present');
  config.setOverride('webauthn.attestationTrustAnchors', root.pem);
  try {
    t.check(webauthnPolicy.attestationSettings().demandsTrust === true &&
            /binds security-key serials/.test(
              attestation.WebauthnAttestation.demandedBy(
                webauthnPolicy.attestationSettings())),
            '2. the attribute set demands a trusted statement, and says so');
    const assessed = async function (serial) {
      log.debug('Entering recorded() assessed().');
      const ctx = await kit.ceremony({});
      const made = await kit.packed(ctx, root, null, null, serial);
      const verdict = webauthn.verifyRegistration(ctx.input(made));
      const out = await attestation.assess(verdict);
      log.debug('Leaving recorded() assessed().');
      return out;
    };
    const one = await assessed({ subject: 'SN-77' });
    const two = await assessed({ yubico: 5550001 });
    t.check(one.ok && one.attestation.trusted === true &&
            one.attestation.deviceSerial === 'SN-77' &&
            two.ok && two.attestation.deviceSerial === '5550001' &&
            two.attestation.deviceSerialSource === 'yubico-extension',
            '2b. a trusted packed attestation records the serial its ' +
            'certificate names, from either place',
            JSON.stringify([one.attestation, two.attestation]));
  } finally {
    config.clearOverride('webauthn.attestationPolicy');
    config.clearOverride('webauthn.attestationTrustAnchors');
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving recorded().');
}

function bound(t) {
  log.debug('Entering bound().');
  const name = 'pes-' + require('crypto').randomBytes(3).toString('hex');
  ldap.createUser(name, { invent: false });
  const real = passkeyPolicy.directoryInstalled();
  // The person's serials, as the directory hook would answer them.
  passkeyPolicy.setDirectory(Object.assign({}, real, {
    personAttributeValues: function (who, attribute) {
      log.debug('Entering personAttributeValues() (test).');
      log.debug('Leaving personAttributeValues() (test).');
      return who === name && attribute === 'serialNumber'
        ? ['5550001', ' sn-abc '] : [];
    } }));
  let n = 0;
  const add = function (serial) {
    log.debug('Entering bound() add().');
    n += 1;
    const out = credentials.addKey(name, {
      credentialId: 'pes-cred-' + n,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      attestation: serial === undefined ? { trusted: true }
        : { trusted: true, deviceSerial: serial } }, 'mfa');
    log.debug('Leaving bound() add().');
    return out;
  };
  try {
    t.check(add(undefined).ok, '3. with the attribute empty, nothing is ' +
            'checked');
    withAttribute('serialNumber');
    const mine = add('5550001');
    const cased = add('SN-ABC');
    const other = add('9990009');
    const none = add(undefined);
    t.check(mine.ok && cased.ok,
            '3b. a serial among the person\'s values registers (case and ' +
            'spaces aside)', JSON.stringify([mine.errors, cased.errors]));
    t.check(!other.ok && errorCodes.codeOf(other) === 'STS-AUTHN-0320' &&
            other.reason === 'device-serial' &&
            /not one issued to you/.test((other.errors || []).join(' ')),
            '3c. one that is not the person\'s is refused (STS-AUTHN-0320)',
            JSON.stringify(other));
    t.check(!none.ok && errorCodes.codeOf(none) === 'STS-AUTHN-0321',
            '3d. one that names no serial is refused (STS-AUTHN-0321)',
            JSON.stringify(none));
  } finally {
    passkeyPolicy.setDirectory(real);
    passkeyPolicy.reset('default');
  }
  const hook = real && real.personAttributeValues;
  t.check(typeof hook === 'function' &&
          hook.call(real, name, 'userPassword').length === 0 &&
          hook.call(real, name, 'stsTotpCredential').length === 0 &&
          hook.call(real, name, 'uid').indexOf(name) >= 0,
          '4. the directory hook answers an ordinary attribute and never a ' +
          'secret one');
  log.debug('Leaving bound().');
}

module.exports = {
  name: 'passkey_enterprise_serial',
  describe: 'a security key\'s enterprise attestation serial bound to the ' +
            'person enrolling it (#532)',
  run: async function (t) {
    log.debug('Entering run().');
    const root = await certificates(t);
    await recorded(t, root);
    bound(t);
    log.debug('Leaving run().');
  }
};
