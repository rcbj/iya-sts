// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_management.js
//
// ===========================================================================
// THE PASSKEY PAGES' CREDENTIAL LAYER (#470, 2026-10-06), in process.
//
// `/portal/keys` was rebuilt to the passkey management guidelines, and what
// it draws comes from a handful of functions in `common/credentials.ts`.
// Each is asserted here directly, because the cases that matter are ones a
// protocol job cannot build:
//
//   A. `keyGroup()`: the backup eligibility flag decides FIRST — a synced
//      passkey reached over hybrid is cross-platform and still "on your
//      devices" — then the attachment, then, for a key that recorded no
//      attachment, its transports.
//   B. `keyProvider()` / `defaultKeyName()` / `keyName()`: a recorded
//      provider is used as recorded (MDS's word stays MDS's); a key enrolled
//      before #470 is named by its attestation's model, else the table; the
//      old default labels ("security key", "this device", "security key
//      (ES256)") read as the default name, and a person's own label is kept.
//   C. `authn/passkey_providers.ts`: the table's names, either case, with or
//      without hyphens, and nothing for an AAGUID it does not know.
//   D. `keyProviderFor()` with no MDS BLOB loaded names by the table.
//   E. `addKey()` keeps BE, BS, transports, discoverable and userVerified,
//      and defaults the label to the provider's or the group's name.
//   F. `renameKey()`: the caller's OWN key only (the A01 rule `removeKey()`
//      keeps), at most 60 characters, no control characters, and an empty
//      name restores the default.
//   G. `noteKeyUsed()`: Last used is recorded, BS follows each assertion,
//      and BE is filled in once for a key that recorded none.
//   H. `transportsOf()` / `discoverableOf()` read the browser's answer and
//      keep nothing that is not a transport name.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'passkey_management',
  level: process.env.LOG_LEVEL || 'info' });

async function run(t) {
  log.debug("Entering run().");
  require('../common/app');
  require('../authn/authn');
  require('../ldap/ldap_server');
  const credentials = require('../common/credentials');
  const providers = require('../authn/passkey_providers');
  const stats = require('../common/admin_stats');
  const C = credentials.Credentials;

  const GPM = 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4';

  // --- A ---------------------------------------------------------------
  t.log.info('=== A. which group a passkey is listed under ===');
  t.equal(C.keyGroup({ backupEligible: true, attachment: 'cross-platform' }),
          'device', 'A. a backup-eligible passkey reached over hybrid ' +
          '(cross-platform) is on your devices — BE decides first');
  t.equal(C.keyGroup({ backupEligible: false, attachment: 'platform' }),
          'device', 'A. a device-bound platform passkey (Windows Hello) is ' +
          'on your devices');
  t.equal(C.keyGroup({ backupEligible: false, attachment: 'cross-platform' }),
          'security-key', 'A. a cross-platform passkey that cannot be ' +
          'backed up is on a security key');
  t.equal(C.keyGroup({ attachment: '', transports: ['usb', 'nfc'] }),
          'security-key', 'A. with no attachment recorded, transports that ' +
          'are all roaming make it a security key');
  t.equal(C.keyGroup({ attachment: '', transports: ['internal'] }), 'device',
          'A. and an internal transport makes it a device');
  t.equal(C.keyGroup({}), 'device',
          'A. a key that recorded nothing is on your devices');

  // --- B ---------------------------------------------------------------
  t.log.info('=== B. who made it, and what it is called ===');
  t.equal(C.keyProvider({ provider: 'YubiKey 5 NFC', providerSource: 'mds',
                          aaguid: GPM }), 'YubiKey 5 NFC',
          'B. a recorded MDS name is used as recorded, never the table\'s');
  t.equal(C.keyProvider({ provider: '', providerSource: 'mds',
                          aaguid: GPM }), '',
          'B. MDS answering nothing is nothing, even for an AAGUID the ' +
          'table knows — where MDS is loaded it alone names');
  t.equal(C.keyProvider({ aaguid: GPM }), 'Google Password Manager',
          'B. a key enrolled before #470 is named by the table');
  t.equal(C.keyProvider({ aaguid: GPM, attestation: { model: 'From MDS' } }),
          'From MDS', 'B. ... after the model its attestation recorded');
  t.equal(C.defaultKeyName({ attachment: 'cross-platform',
                             backupEligible: false }), 'Security key',
          'B. an unknown security key is called "Security key"');
  t.equal(C.defaultKeyName({ attachment: 'platform' }), 'Passkey',
          'B. an unknown passkey on a device is called "Passkey"');
  ['security key', 'this device', 'security key (ES256)', ''].forEach(
    function (old) {
      t.equal(C.keyName({ label: old, aaguid: GPM }),
              'Google Password Manager',
              'B. the old default label "' + old + '" reads as the default ' +
              'name');
    });
  t.equal(C.keyName({ label: 'Work laptop', aaguid: GPM }), 'Work laptop',
          'B. a person\'s own name is kept');

  // --- C ---------------------------------------------------------------
  t.log.info('=== C. the credential-manager table ===');
  t.equal(providers.nameOf(GPM.toUpperCase()), 'Google Password Manager',
          'C. an AAGUID in upper case');
  t.equal(providers.nameOf(GPM.replace(/-/g, '')), 'Google Password Manager',
          'C. and without hyphens');
  t.equal(providers.nameOf('fbfc3007-154e-4ecc-8c0b-6e020557d7bd'),
          'iCloud Keychain', 'C. iCloud Keychain');
  t.equal(providers.nameOf('00000000-0000-0000-0000-000000000000'), '',
          'C. nothing for the all-zero AAGUID');
  t.equal(providers.nameOf('not an aaguid'), '', 'C. nothing for garbage');

  // --- D ---------------------------------------------------------------
  t.log.info('=== D. which source names a new key ===');
  const named = await C.keyProviderFor(GPM, null);
  t.check(named.providerSource === 'table' &&
          named.provider === 'Google Password Manager',
          'D. with no MDS BLOB loaded, the table names it',
          JSON.stringify(named));
  const unnamed = await C.keyProviderFor('0'.repeat(32), null);
  t.check(unnamed.providerSource === '' && unnamed.provider === '',
          'D. and an AAGUID nobody knows is named by nobody',
          JSON.stringify(unnamed));

  // --- E ---------------------------------------------------------------
  t.log.info('=== E. what a stored key keeps ===');
  const alice = 'passkey-alice-' + nodeCrypto.randomBytes(3).toString('hex');
  const mallory = 'passkey-mallory-' +
                  nodeCrypto.randomBytes(3).toString('hex');
  [alice, mallory].forEach(function (name) {
    stats.recordAuthentication({ presented: name, protocol: 'test',
                                 method: 'a fixture' });
    credentials.setPassword(name, name + '-password');
  });
  const jwk = { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' };
  t.equal(credentials.addKey(alice, {
    credentialId: 'alice-synced', publicKeyJwk: jwk, signCount: 0,
    attachment: 'cross-platform', aaguid: GPM.replace(/-/g, ''),
    backupEligible: true, backupState: true,
    transports: ['hybrid', 'internal', 'not a transport!'],
    discoverable: true, userVerified: true,
    provider: 'Google Password Manager', providerSource: 'table'
  }, 'mfa').ok, true, 'E. a synced passkey is added');
  t.equal(credentials.addKey(alice, {
    credentialId: 'alice-yubikey', publicKeyJwk: jwk, signCount: 0,
    attachment: 'cross-platform', backupEligible: false, backupState: false,
    transports: ['usb'], discoverable: false
  }, 'mfa').ok, true, 'E. and a security key');
  t.equal(credentials.addKey(mallory, {
    credentialId: 'mallory-key', publicKeyJwk: jwk, signCount: 0
  }, 'mfa').ok, true, 'E. mallory holds one of her own');
  const held = credentials.keysOf(alice);
  const synced = held.filter(function (k) {
    return k.credentialId === 'alice-synced';
  })[0] || {};
  const yubi = held.filter(function (k) {
    return k.credentialId === 'alice-yubikey';
  })[0] || {};
  t.check(synced.backupEligible === true && synced.backupState === true &&
          synced.discoverable === true && synced.userVerified === true &&
          JSON.stringify(synced.transports) === '["hybrid","internal"]',
          'E. BE, BS, discoverable, userVerified and the transports are ' +
          'kept, and a value that is not a transport name is dropped',
          JSON.stringify(synced));
  t.equal(synced.label, 'Google Password Manager',
          'E. the label defaults to the provider\'s name');
  t.equal(yubi.label, 'Security key',
          'E. and to the group\'s name where no provider is known');

  // --- F ---------------------------------------------------------------
  t.log.info('=== F. renaming ===');
  const stolen = credentials.renameKey(mallory, 'alice-synced', 'mine now');
  t.check(!stolen.ok, 'F. mallory cannot rename ALICE\'s passkey by its id',
          JSON.stringify(stolen));
  t.equal(C.keyName(credentials.keysOf(alice).filter(function (k) {
    return k.credentialId === 'alice-synced';
  })[0]), 'Google Password Manager', 'F. and alice\'s passkey kept its name');
  t.check(!credentials.renameKey(alice, 'alice-synced', 'x'.repeat(61)).ok,
          'F. a name over 60 characters is refused');
  t.check(!credentials.renameKey(alice, 'alice-synced', 'tab\there').ok,
          'F. a name with a control character is refused');
  const renamed = credentials.renameKey(alice, 'alice-synced',
                                        '  Work phone  ');
  t.check(renamed.ok && renamed.label === 'Work phone' &&
          renamed.previous === 'Google Password Manager',
          'F. a rename is trimmed and says what it was before',
          JSON.stringify(renamed));
  const restored = credentials.renameKey(alice, 'alice-synced', '');
  t.check(restored.ok && restored.label === 'Google Password Manager',
          'F. an empty name restores the default', JSON.stringify(restored));

  // --- G ---------------------------------------------------------------
  t.log.info('=== G. using one ===');
  const before = Date.now();
  credentials.noteKeyUsed(alice, 'alice-synced', 1,
                          { be: true, bs: false, up: true });
  const used = credentials.keysOf(alice).filter(function (k) {
    return k.credentialId === 'alice-synced';
  })[0] || {};
  t.check(used.lastUsedAt >= before, 'G. Last used is recorded',
          JSON.stringify(used));
  t.equal(used.backupState, false, 'G. BS follows the assertion — it can ' +
          'change after enrolment (WebAuthn Level 3 section 6.1.3)');
  credentials.noteKeyUsed(mallory, 'mallory-key', 1, { be: true, bs: true });
  const filled = credentials.keysOf(mallory)[0] || {};
  t.check(filled.backupEligible === true && filled.backupState === true,
          'G. a key that recorded no BE has it filled in from an assertion',
          JSON.stringify(filled));
  credentials.noteKeyUsed(mallory, 'mallory-key', 2, { be: false, bs: false });
  t.equal((credentials.keysOf(mallory)[0] || {}).backupEligible, true,
          'G. and BE, once known, is never rewritten — it cannot change');

  // --- H ---------------------------------------------------------------
  t.log.info('=== H. reading the browser\'s answer ===');
  t.equal(JSON.stringify(C.transportsOf({ response: {
    transports: ['usb', 'NOT VALID', 'nfc'] } })), '["usb","nfc"]',
          'H. the transports, without anything that is not one');
  t.equal(JSON.stringify(C.transportsOf({ response: {} })), '[]',
          'H. none when the browser said none');
  t.equal(C.discoverableOf({ clientExtensionResults: {
    credProps: { rk: true } } }), true, 'H. credProps rk true');
  t.equal(C.discoverableOf({}), null, 'H. null where the browser did not say');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'passkey management',
  describe: 'the passkey pages\' credential layer (#470): groups, providers, ' +
            'names, renaming, last used and the backup flags',
  run: run
};
