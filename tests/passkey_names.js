// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_names.js
//
// ===========================================================================
// THE NAMES A PASSKEY PROMPT SHOWS (#533): the passkey policy's
// `userDisplayName`, `rpNameExtras` and `credentialLabel`.
//
//   1. `displaySafe()`: control and bidirectional-formatting characters
//      removed, whitespace collapsed, 64 characters at most.
//   2. `userDisplayName`: each attribute order, with gaps — the first group
//      whose every attribute has a value wins, values joined; none, the
//      door's own name; a hostile value made safe.
//   3. `rpNameExtras`: the realm's name and/or the organisation appended to
//      rp.name in the registration options, and nothing while `none`.
//   4. `credentialLabel`: a new key labelled from it with {provider} and
//      {kind} filled in; empty, the default name; the owner's rename stays.
//   5. A save refuses seven groups, a bad attribute name, a group of four
//      and a label with control characters.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const passkeyPolicy = require('../common/passkey_policy');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const webauthnPolicy = require('../authn/webauthn_policy');

const log = require('bunyan').createLogger({ name: 'passkey_names',
  level: process.env.LOG_LEVEL || 'info' });

function save(fields) {
  log.debug('Entering save().');
  log.debug('Leaving save().');
  return passkeyPolicy.save('default', Object.assign({},
    passkeyPolicy.DEFAULTS, fields));
}

function safe(t) {
  log.debug('Entering safe().');
  const s = passkeyPolicy.displaySafe;
  t.check(s('Ada\u0007 ‮Lovelace‬‏', 64) === 'Ada Lovelace' &&
          s('  a\n\tb  ', 64) === 'a b' &&
          s('x'.repeat(80), 64).length === 64 &&
          s(null, 64) === '',
          '1. control and direction-changing characters go, whitespace ' +
          'collapses, 64 characters at most',
          JSON.stringify(s('Ada\u0007 ‮Lovelace‬‏', 64)));
  log.debug('Leaving safe().');
}

function displayNames(t) {
  log.debug('Entering displayNames().');
  const real = passkeyPolicy.directoryInstalled();
  const entry = { displayName: [], givenName: ['Grace'], sn: ['Hopper'],
                  cn: ['G. Hopper'], mail: ['grace@example.test'],
                  title: ['‮evil.example\u0000 bank login'] };
  passkeyPolicy.setDirectory(Object.assign({}, real, {
    personAttributeValues: function (who, attribute) {
      log.debug('Entering personAttributeValues() (test).');
      log.debug('Leaving personAttributeValues() (test).');
      return who === 'grace' ? (entry[attribute] || []) : [];
    } }));
  const named = function (list) {
    log.debug('Entering displayNames() named().');
    save({ userDisplayName: list });
    const out = passkeyPolicy.displayNameFor('grace', 'the door\'s name');
    log.debug('Leaving displayNames() named().');
    return out;
  };
  try {
    t.check(named('') === 'the door\'s name',
            '2. empty: the door\'s own name, as before');
    t.check(named('displayName, givenName sn, cn') === 'Grace Hopper',
            '2b. a gap is skipped, and a group joins its values',
            named('displayName, givenName sn, cn'));
    t.check(named('displayName, givenName displayName, cn') === 'G. Hopper',
            '2c. a group with one attribute missing is skipped whole',
            named('displayName, givenName displayName, cn'));
    t.check(named('displayName, mail') === 'grace@example.test',
            '2d. the first with a value, in order');
    t.check(named('title') === 'evil.example bank login',
            '2e. a hostile value is made safe: no direction override, no ' +
            'control character', JSON.stringify(named('title')));
    t.check(named('displayName') === 'the door\'s name',
            '2f. none with a value: the door\'s own name');
  } finally {
    passkeyPolicy.setDirectory(real);
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving displayNames().');
}

function rpNames(t) {
  log.debug('Entering rpNames().');
  const id = 'pkn-' + require('crypto').randomBytes(3).toString('hex');
  const made = realms.create({ id: id, name: 'Acme Staff',
                               description: 'Created by ' + __filename });
  config.setOverride('webauthn.rpName', 'Example Login');
  try {
    realms.run(made.realm, function () {
      log.debug('Entering rpNames() in the realm.');
      config.setOverride('saml.organizationName', 'Acme Corp');
      try {
        const name = function (extras) {
          log.debug('Entering rpNames() name().');
          save({ rpNameExtras: extras });
          const out = webauthnPolicy.creationOptions('localhost', 'passkey')
            .rp.name;
          log.debug('Leaving rpNames() name().');
          return out;
        };
        t.check(name('none') === 'Example Login' &&
                name('realm') === 'Example Login — Acme Staff' &&
                name('organisation') === 'Example Login — Acme Corp' &&
                name('realm-and-organisation') ===
                  'Example Login — Acme Staff — Acme Corp',
                '3. rp.name with none, the realm, the organisation and both',
                name('realm-and-organisation'));
      } finally {
        passkeyPolicy.reset('default');
        config.clearOverride('saml.organizationName');
      }
      log.debug('Leaving rpNames() in the realm.');
    });
  } finally {
    config.clearOverride('webauthn.rpName');
    realms.remove(id);
  }
  log.debug('Leaving rpNames().');
}

function labels(t) {
  log.debug('Entering labels().');
  const name = 'pkn-' + require('crypto').randomBytes(3).toString('hex');
  ldap.createUser(name, { invent: false });
  let n = 0;
  const add = function (group) {
    log.debug('Entering labels() add().');
    n += 1;
    const id = 'pkn-cred-' + n;
    credentials.addKey(name, { credentialId: id,
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' },
      transports: group === 'security-key' ? ['usb'] : ['internal'],
      attachment: group === 'security-key' ? 'cross-platform' : 'platform' },
      'mfa');
    log.debug('Leaving labels() add().');
    return credentials.keysOf(name).filter(function (one) {
      return one.credentialId === id;
    })[0] || {};
  };
  try {
    const plain = add('device');
    save({ credentialLabel: 'Work {kind}' });
    const labelled = add('device');
    const renamed = credentials.renameKey(name, labelled.credentialId,
                                          'My laptop');
    const after = credentials.keysOf(name).filter(function (one) {
      return one.credentialId === labelled.credentialId;
    })[0] || {};
    t.check(plain.label && plain.label !== 'Work Passkey' &&
            labelled.label === 'Work Passkey' &&
            renamed && renamed.ok !== false && after.label === 'My laptop',
            '4. a new key is labelled from the policy, {kind} filled in; ' +
            'empty gives the default; the owner\'s rename stays',
            JSON.stringify([plain.label, labelled.label, after.label]));
  } finally {
    passkeyPolicy.reset('default');
  }
  log.debug('Leaving labels().');
}

function refused(t) {
  log.debug('Entering refused().');
  const many = save({ userDisplayName: 'a, b, c, d, e, f, g' });
  const badName = save({ userDisplayName: 'displayName, 9lives' });
  const four = save({ userDisplayName: 'a b c d' });
  const control = save({ credentialLabel: 'Key\u0007' });
  passkeyPolicy.reset('default');
  t.check([many, badName, four, control].every(function (one) {
    return !one.ok && errorCodes.codeOf(one) === 'STS-AUTHN-0309';
  }), '5. seven groups, a bad name, a group of four and a label with a ' +
      'control character are refused at save',
          JSON.stringify([many.errors, badName.errors, four.errors,
                          control.errors]));
  log.debug('Leaving refused().');
}

module.exports = {
  name: 'passkey_names',
  describe: 'the names a passkey prompt and a new key show: the user\'s ' +
            'display name, rp.name\'s extras and the credential label ' +
            '(#533)',
  run: function (t) {
    log.debug('Entering run().');
    safe(t);
    displayNames(t);
    rpNames(t);
    labels(t);
    refused(t);
    log.debug('Leaving run().');
  }
};
