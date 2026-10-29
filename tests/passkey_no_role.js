// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_no_role.js
//
// ===========================================================================
// A PASSKEY CARRIES NO ROLE (#1135, 2026-10-29).
//
// Until #1135 every key was enrolled in a ROLE — `primary`, a way in on its
// own, or `mfa`, a second factor beside a password — and the person was
// asked which at every enrolment. The question is gone: a passkey is
// registered and nothing else is asked, and how it is used is the REALM'S
// to say at each sign-in — `webauthn.primaryAllowed`, `webauthn.mfaAllowed`
// and the authentication policy's `passkey` and `securityKey` rows, asked
// by `webauthnPolicy.useAllowed()` for every key alike (the named
// authentication policy an application names, `appAuthnPolicy` — its own
// `appAuthnMechanism` / `appMfaMechanism` until #1148 — may narrow it
// further at a browser sign-in; that layer is the issuance policy's and is
// not asked here).
//
//   A. Enrolment asks no role and stores none: `beginKeyEnrolment()` given
//      the old `role` option answers none, `addKey()` writes none, and a
//      `role` a stored value still carries is not seen through `keysOf()`.
//   B. One key answers both steps: `keyForAssertion()` finds the same key
//      for a passwordless pick (`primary`) and a second-factor pick (`mfa`).
//   C. The realm decides: with `webauthn.primaryAllowed` off that key is
//      refused as a first factor (STS-AUTHN-0045) and still accepted as a
//      second; with `webauthn.mfaAllowed` off the reverse (STS-AUTHN-0046);
//      with both off a new enrolment is refused (STS-AUTHN-0531).
//   D. Holding a key is holding a second factor where the realm lets a key
//      be one: `mechanismsFor()` and `secondFactorDemand()` say so for a
//      person with a password and any key, product mode's password-only
//      door refuses the bare password (STS-AUTHN-0213), and with
//      `webauthn.mfaAllowed` off neither says so and the door admits it.
//   E. The last way in: removing the only key of a person with no password
//      is refused (STS-AUTHN-0070) while a key may sign in on its own, and
//      allowed while it may not, there being no way in to lose.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): every claim is about
// what the credential layer and the sign-in DECIDE, at the one writer and
// the one picker; the HTTP halves are `tests/protocol/`'s jobs, which drive
// real ceremonies through the doors.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const config = require('../common/config');
const credentials = require('../common/credentials');
const errorCodes = require('../common/error_codes');
const websecurity = require('../common/websecurity');
const policy = require('../authn/webauthn_policy');
const ldap = require('../ldap/ldap_server');
const authn = require('../authn/authn');

const log = require('bunyan').createLogger({ name: 'passkey_no_role',
  level: process.env.LOG_LEVEL || 'info' });

const STAMP = Date.now().toString(36);
const PASSWORD = 'Pnr-' + STAMP + '-Correct.Horse.Battery.Staple.42';

// Settings for the duration of one call, each RESET afterwards rather than
// written back, for the reason `webauthn_policy.js` gives: a setting that
// had no override before must end with none.
function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, pairs[key]);
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

// A key as `credentials.addKey()` takes it. Its public key is a placeholder:
// nothing here verifies a signature, only which key is picked and allowed.
function aKey(id, extra) {
  log.debug("Entering aKey().");
  const out = Object.assign({ credentialId: id,
    publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    signCount: 0, label: id }, extra || {});
  log.debug("Leaving aKey().");
  return out;
}

function somebody(slug, password) {
  log.debug("Entering somebody().");
  const name = 'pnr-' + slug + '-' + STAMP;
  ldap.createUser(name, { invent: false });
  if (password) {
    credentials.setPassword(name, PASSWORD);
  }
  log.debug("Leaving somebody().");
  return name;
}

function enrolment(t) {
  log.debug("Entering enrolment().");
  t.log.info('=== A. enrolment asks no role and stores none ===');
  const ann = somebody('ann', true);
  // The OLD option, as a caller from before #1135 would still send it.
  const begun = credentials.beginKeyEnrolment(ann, { role: 'mfa' });
  t.check(begun.ok === true && !('role' in begun),
    'A1. an enrolment begins with the old role option and answers no role',
    JSON.stringify(Object.keys(begun || {})));
  credentials.abandonKeyEnrolment(ann);
  const added = credentials.addKey(ann, aKey('pnr-ann-1', { role: 'mfa' }));
  t.check(added.ok === true && !('role' in added),
    'A2. addKey() writes a key with no role argument and answers no role',
    JSON.stringify(added));
  const stored = credentials.keysOf(ann)[0] || {};
  t.check(stored.credentialId === 'pnr-ann-1' && !('role' in stored),
    'A3. and the stored key carries none, though the credential handed in ' +
    'named one', JSON.stringify(stored));
  // A VALUE WRITTEN BEFORE #1135, as the directory still holds it: the role
  // is dropped where the value becomes a key, so no reader sees one.
  const legacy = somebody('legacy', true);
  const entry = ldap.existingUserEntry(legacy);
  entry.attributes.stswebauthncredential = [JSON.stringify(
    aKey('pnr-legacy-1', { role: 'primary' }))];
  const read = credentials.keysOf(legacy);
  t.check(read.length === 1 && read[0].credentialId === 'pnr-legacy-1' &&
          !('role' in read[0]),
    'A4. a stored legacy role is not visible from keysOf()',
    JSON.stringify(read));
  t.check(credentials.USES.join(',') === 'primary,mfa',
    'A5. what is left of the two roles is the two USES a key may answer, ' +
    'asked of the realm', credentials.USES.join(','));
  log.debug("Leaving enrolment().");
  return { ann: ann, legacy: legacy };
}

function bothSteps(t, who) {
  log.debug("Entering bothSteps().");
  t.log.info('=== B. one key answers both steps ===');
  const first = authn.keyForAssertion(who.ann, 'primary', 'pnr-ann-1');
  const second = authn.keyForAssertion(who.ann, 'mfa', 'pnr-ann-1');
  t.check(!!first.key && first.key.credentialId === 'pnr-ann-1',
    'B1. the key answers a passwordless pick', first.why);
  t.check(!!second.key && second.key.credentialId === 'pnr-ann-1',
    'B2. and the SAME key answers a second-factor pick — until #1135 a key ' +
    'answered only the step its role named', second.why);
  const legacyMfa = authn.keyForAssertion(who.legacy, 'mfa', 'pnr-legacy-1');
  t.check(!!legacyMfa.key,
    'B3. a key stored as `primary` before #1135 answers the second step ' +
    'too: the stored role decides nothing', legacyMfa.why);
  log.debug("Leaving bothSteps().");
}

function realmDecides(t, who) {
  log.debug("Entering realmDecides().");
  t.log.info('=== C. the realm decides how a key is used ===');
  withSettings({ 'webauthn.primaryAllowed': false }, function () {
    const first = authn.keyForAssertion(who.ann, 'primary', 'pnr-ann-1');
    const second = authn.keyForAssertion(who.ann, 'mfa', 'pnr-ann-1');
    t.check(!first.key && errorCodes.codeOf(first) === 'STS-AUTHN-0045',
      'C1. with webauthn.primaryAllowed off the key is refused as a first ' +
      'factor, STS-AUTHN-0045', errorCodes.codeOf(first) + ' ' + first.why);
    t.check(!!second.key,
      'C2. and still accepted as a second factor', second.why);
    const added = credentials.addKey(who.ann, aKey('pnr-ann-2'));
    t.check(added.ok === true,
      'C3. and a new key is still enrolled, because it may be the second ' +
      'factor', JSON.stringify(added.errors || []));
  });
  withSettings({ 'webauthn.mfaAllowed': false }, function () {
    const first = authn.keyForAssertion(who.ann, 'primary', 'pnr-ann-1');
    const second = authn.keyForAssertion(who.ann, 'mfa', 'pnr-ann-1');
    t.check(!second.key && errorCodes.codeOf(second) === 'STS-AUTHN-0046',
      'C4. with webauthn.mfaAllowed off the key is refused as a second ' +
      'factor, STS-AUTHN-0046', errorCodes.codeOf(second) + ' ' + second.why);
    t.check(!!first.key,
      'C5. and still accepted as a first factor', first.why);
  });
  withSettings({ 'webauthn.primaryAllowed': false,
                 'webauthn.mfaAllowed': false }, function () {
    const asked = policy.enrolmentAllowed();
    const added = credentials.addKey(who.ann, aKey('pnr-ann-never'));
    const begun = credentials.beginKeyEnrolment(who.ann, {});
    t.check(!asked.ok && errorCodes.codeOf(asked) === 'STS-AUTHN-0531',
      'C6. with both uses refused no key may be enrolled, STS-AUTHN-0531',
      errorCodes.codeOf(asked) + ' ' + asked.why);
    t.check(!added.ok && errorCodes.codeOf(added) === 'STS-AUTHN-0531',
      'C7. refused at the one writer', JSON.stringify(added.errors || []));
    t.check(!begun.ok && errorCodes.codeOf(begun) === 'STS-AUTHN-0531',
      'C8. and at the start of an enrolment',
      JSON.stringify(begun.errors || []));
    t.check(!credentials.keysOf(who.ann).some(function (one) {
      return one.credentialId === 'pnr-ann-never';
    }), 'C9. and nothing was written');
  });
  log.debug("Leaving realmDecides().");
}

function secondFactor(t) {
  log.debug("Entering secondFactor().");
  t.log.info('=== D. holding any key is holding a second factor ===');
  const bea = somebody('bea', true);
  credentials.addKey(bea, aKey('pnr-bea-1'));
  const m = credentials.mechanismsFor(bea);
  const d = credentials.secondFactorDemand(bea);
  t.check(m.mfaRequired === true && m.secondFactor === 'webauthn' &&
          m.mfaKeys === 1 && m.primaryKeys === 1 && m.keys.length === 1,
    'D1. a person with a password and a key holds a second factor, and the ' +
    'one key is counted by both uses it may answer',
    JSON.stringify({ mfaRequired: m.mfaRequired, secondFactor:
      m.secondFactor, mfaKeys: m.mfaKeys, primaryKeys: m.primaryKeys }));
  t.check(d.person && d.key && d.holds && d.needed,
    'D2. and secondFactorDemand() says the same, so the doors that cannot ' +
    'ask for one agree with the screen that can', JSON.stringify(d));
  websecurity.reset();
  withSettings({ 'global.mode': 'product' }, function () {
    const refused = credentials.verify(bea, PASSWORD,
      { via: 'test ldap', door: 'ldap' });
    t.check(refused.ok === false &&
            errorCodes.codeOf(refused) === 'STS-AUTHN-0213',
      'D3. product mode\'s password-only door refuses the bare password of ' +
      'a person holding any key, STS-AUTHN-0213', JSON.stringify(refused));
  });
  withSettings({ 'webauthn.mfaAllowed': false }, function () {
    const off = credentials.mechanismsFor(bea);
    const offDemand = credentials.secondFactorDemand(bea);
    t.check(off.mfaRequired === false && off.mfaKeys === 0 &&
            off.primaryKeys === 1 && !offDemand.key && !offDemand.needed,
      'D4. where the realm does not let a key be a second factor, holding ' +
      'one is not holding a second factor',
      JSON.stringify({ mfaRequired: off.mfaRequired, mfaKeys: off.mfaKeys,
                       demand: offDemand }));
  });
  websecurity.reset();
  withSettings({ 'global.mode': 'product', 'webauthn.mfaAllowed': false },
    function () {
      const admitted = credentials.verify(bea, PASSWORD,
        { via: 'test ldap', door: 'ldap' });
      t.check(admitted.ok === true,
        'D5. and the password-only door admits the password there',
        JSON.stringify(admitted));
    });
  log.debug("Leaving secondFactor().");
}

function lastWayIn(t) {
  log.debug("Entering lastWayIn().");
  t.log.info('=== E. the last way in ===');
  const cy = somebody('cy', false);
  credentials.addKey(cy, aKey('pnr-cy-1'));
  const refused = credentials.removeKey(cy, 'pnr-cy-1');
  t.check(!refused.ok && errorCodes.codeOf(refused) === 'STS-AUTHN-0070',
    'E1. removing the only key of a person with no password is refused ' +
    'while a key may sign in on its own, STS-AUTHN-0070',
    JSON.stringify(refused.errors || []));
  t.equal(credentials.keysOf(cy).length, 1, 'E2. and the key is still there');
  const removed = withSettings({ 'webauthn.primaryAllowed': false },
    function () {
      return credentials.removeKey(cy, 'pnr-cy-1');
    });
  t.check(removed.ok === true && removed.remaining === 0,
    'E3. and allowed while a key may not sign anybody in on its own: there ' +
    'it is no way in to lose', JSON.stringify(removed));
  log.debug("Leaving lastWayIn().");
}

function run(t) {
  log.debug("Entering run().");
  const who = enrolment(t);
  bothSteps(t, who);
  realmDecides(t, who);
  secondFactor(t);
  lastWayIn(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'passkey no role',
  describe: 'a passkey carries no role (#1135): enrolment asks none and ' +
            'stores none, one key answers both steps, the realm\'s ' +
            'primaryAllowed and mfaAllowed decide each use at the sign-in, ' +
            'holding any key is holding a second factor where a key may be ' +
            'one, and the last-way-in guard asks the realm',
  run: run
};
