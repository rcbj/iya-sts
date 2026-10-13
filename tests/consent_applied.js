// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/consent_applied.js
//
// ---------------------------------------------------------------------------
// THE GLOBAL CONSENTS APPLIED FOR A PERSON (#537). A global consent writes
// nothing about anybody, so `/portal/consents` had nothing to list for an
// application whose scopes an administrator agreed to for everyone. The
// authorization endpoint now calls `consent.noteApplied()` with the scopes a
// global consent answered, and the page draws `consent.appliedConsentsOf()`.
// This file holds the two functions to what the page relies on:
//
//   1. A SCOPE IS RECORDED ONCE: the first sign-in writes it
//      (`oauthConsentApplied`, `oauthConsent`'s grammar), a second writes
//      nothing, and a new scope is added beside it.
//   2. ONLY WHAT STILL STANDS IS LISTED: a scope the application no longer
//      carries a global consent for is not listed (and is not deleted — it
//      comes back if the consent does), and one the person has also agreed to
//      themselves is theirs and is listed there instead.
//   3. NOTHING IS WRITTEN FOR NOBODY: no scopes, no client, a person with no
//      entry — each answers without writing and without throwing.
//
// In process, through the two functions: the over-HTTP half — a real sign-in
// recording it and the portal drawing it — is section f of
// `tests/vendored/sts_consent_withdrawal.js`.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const consent = require('../common/consent');

const log = require('bunyan').createLogger({ name: 'consent_applied',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'cap' + process.pid;
const CLIENT = TAG + '-client';
const PERSON = TAG + '-person';

function stored() {
  log.debug('Entering stored().');
  const dir = consent.directoryInstalled();
  const found = (dir && dir.appliedConsentsOf
    ? dir.appliedConsentsOf(PERSON) : null) || {};
  log.debug('Leaving stored().');
  return (found.values || []).slice(0);
}

function listed() {
  log.debug('Entering listed().');
  const rows = consent.appliedConsentsOf(PERSON).filter(function (one) {
    return one.client === CLIENT;
  }).map(function (one) {
    return one.scope;
  }).sort();
  log.debug('Leaving listed().');
  return rows;
}

function run(t) {
  log.debug('Entering run().');
  applications.createApplication({ identifier: CLIENT, protocols: ['oauth2'],
    fields: { oauthClientId: CLIENT } });
  ldap.createUser(PERSON, { invent: false });
  consent.grantGlobal(CLIENT, 'openid', 'consent_applied');
  consent.grantGlobal(CLIENT, 'profile', 'consent_applied');

  // --- 1. Recorded once --------------------------------------------------
  const first = consent.noteApplied(PERSON, CLIENT, ['openid', 'profile']);
  const afterFirst = stored();
  t.check(first.stored && first.scopes.join(' ') === 'openid profile' &&
          afterFirst.length === 2 &&
          afterFirst.every(function (v) {
            return /^\d{14}Z \S+ /.test(v) && v.endsWith(' ' + CLIENT);
          }),
          '1a. the first sign-in records each scope once, in oauthConsent\'s ' +
          'grammar', JSON.stringify({ first: first, stored: afterFirst }));
  const second = consent.noteApplied(PERSON, CLIENT, ['openid', 'profile']);
  t.check(!second.stored && stored().length === 2,
          '1b. a second sign-in writes nothing', JSON.stringify(second));
  consent.grantGlobal(CLIENT, 'email', 'consent_applied');
  const third = consent.noteApplied(PERSON, CLIENT,
                                    ['openid', 'profile', 'email']);
  t.check(third.stored && third.scopes.join(' ') === 'email' &&
          stored().length === 3,
          '1c. a new scope is added beside the ones already recorded',
          JSON.stringify(third));
  t.check(listed().join(' ') === 'email openid profile',
          '1d. and all three are listed while the consent stands',
          JSON.stringify(listed()));

  // --- 2. Only what still stands ------------------------------------------
  consent.revokeGlobal(CLIENT, 'email', 'consent_applied');
  t.check(listed().join(' ') === 'openid profile' && stored().length === 3,
          '2a. a scope no longer under global consent is not listed, and its ' +
          'record is kept', JSON.stringify({ listed: listed(),
                                             stored: stored() }));
  consent.grantGlobal(CLIENT, 'email', 'consent_applied');
  t.check(listed().join(' ') === 'email openid profile',
          '2b. and it is listed again when the consent comes back',
          JSON.stringify(listed()));
  consent.record(PERSON, CLIENT, ['profile'], 'consent_applied');
  t.check(listed().join(' ') === 'email openid',
          '2c. a scope the person agreed to themselves is theirs, and is not ' +
          'listed as administrative', JSON.stringify(listed()));

  // --- 3. Nothing written for nobody --------------------------------------
  const before = stored().length;
  const none = [consent.noteApplied(PERSON, CLIENT, []),
                consent.noteApplied(PERSON, '', ['openid']),
                consent.noteApplied(TAG + '-nobody', CLIENT, ['openid'])];
  t.check(none.every(function (one) {
    return one.ok && !one.stored;
  }) && stored().length === before,
          '3. no scopes, no client or nobody: nothing written, nothing thrown',
          JSON.stringify(none));
  log.debug('Leaving run().');
}

module.exports = {
  name: 'consent_applied',
  describe: 'the global consents applied for a person (#537): recorded once ' +
            'per application and scope, and listed only while they stand',
  run: run
};
