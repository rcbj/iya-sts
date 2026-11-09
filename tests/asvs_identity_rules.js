// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/asvs_identity_rules.js
//
// Two rules about proving who somebody is. A second factor is cleared only
// with a statement of how the person was verified (#1504), and a password may
// not contain a word that identifies the organization or service (#1505).

const path = require('path');

delete process.env.CONFIG_FILE;

const ROOT = path.join(__dirname, '..');

function withSettings(config, pairs, fn) {
  const keys = Object.keys(pairs);
  keys.forEach(function (key) {
    config.setOverride(key, pairs[key]);
  });
  const done = function () {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  };
  return Promise.resolve().then(fn).then(function (out) {
    done();
    return out;
  }, function (e) {
    done();
    throw e;
  });
}

async function run(t) {
  const config = require(ROOT + '/common/config');
  const actions = require(ROOT + '/admin-core/admin_actions');
  const policy = require(ROOT + '/common/password_policy');
  const ctx = { actor: 'tester', via: 'console' };
  const refusedForEvidence = async function (action, body) {
    const answer = await actions.usersAction(
      Object.assign({ action: action }, body), ctx);
    return JSON.stringify(answer || {}).indexOf('`evidence`') >= 0;
  };
  const ACTIONS = ['clear-totp', 'clear-key', 'clear-backup-codes',
    'clear-email-factor'];

  await withSettings(config, { 'global.mode': 'product' }, async function () {
    for (const action of ACTIONS) {
      t.equal(await refusedForEvidence(action, { user: 'nobody-x' }), true,
              'product: ' + action + ' is refused with no evidence');
      t.equal(await refusedForEvidence(action,
        { user: 'nobody-x', evidence: 'short' }), true,
              'product: ' + action + ' is refused with too little evidence');
      t.equal(await refusedForEvidence(action,
        { user: 'nobody-x', evidence: 'video call, passport checked' }), false,
              'product: ' + action + ' goes on with a statement');
    }
  });
  for (const action of ACTIONS) {
    t.equal(await refusedForEvidence(action, { user: 'nobody-x' }), false,
            'development: ' + action + ' asks for no statement');
  }

  // #1520: ending every session is one instant, read when a session is.
  const authn = require(ROOT + '/authn/authn');
  const started = { startedAt: Date.now() - 1000, expires: Date.now() + 60000 };
  t.equal(authn.sessionEnded(started), '', 'a live session is live');
  config.setOverride('authn.sessionsEndedBefore', String(Date.now()));
  t.equal(authn.sessionEnded(started), 'expired',
          'a session from before the instant has ended');
  t.equal(authn.sessionEnded({ startedAt: Date.now() + 5000,
                               expires: Date.now() + 60000 }), '',
          'one started after it has not');
  config.clearOverride('authn.sessionsEndedBefore');

  const words = function (password) {
    return policy.problemsWith(password, { minLength: 12, history: 0 })
      .filter(function (one) {
        return one.indexOf('known by') >= 0;
      }).length;
  };
  await withSettings(config, { 'security.passwordContextWords': 'Acme,xy' },
                     function () {
      t.equal(words('correct horse battery staple'), 0,
              'an ordinary passphrase passes');
      t.equal(words('my-acme-password-long'), 1, 'a listed word is refused');
      t.equal(words('MY ACME PASSWORD LONG'), 1, 'whatever its case');
      t.equal(words('a-c-m-e-password-long'), 1, 'or its punctuation');
      t.equal(words('@cm3 password long enough'), 1, 'or its letter swaps');
      t.equal(words('oxygen xylophone xy words'), 0,
              'a word under four letters is not looked for');
      t.equal(words('the iya-sts service password'), 1,
              'the service\'s own name is always refused');
      t.equal(words('iyasts-service-password'), 1,
              'with or without its punctuation');
    });
}

module.exports = {
  name: 'asvs_identity_rules',
  describe: 'evidence to clear a second factor, and context-specific words',
  run: run
};
