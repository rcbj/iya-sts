// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_reveal_secret.js
//
// ---------------------------------------------------------------------------
// ONE CREDENTIAL'S VALUE, ON DEMAND (#446, rcbj 2026-10-05).
//
// No `/admin-api` GET carries a credential, so the application page's folds
// ask `reveal-secret` for the one value they open. What is held here:
//
//   1. It hands back a client secret by its id, and the registration access
//      token by name.
//   2. It refuses an id the application does not hold, a token it does not
//      hold, and an application nobody recorded — STS-ADMIN-0842.
//   3. It writes an audit row naming what was revealed and never the value.
//   4. The application's GET answer still carries no value.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const audit = require('../common/audit');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'application_reveal_secret',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'reveal-secret-app-' + process.pid;

function run(t) {
  log.debug("Entering run().");
  const secret = applications.mintClientSecret();
  const created = adminActions.applicationsAction({
    action: 'create', identifier: ID,
    'field.oauthClientId': ID,
    'field.oauthClientSecret': secret
  }, ['oauth2']);
  t.check(created && created.ok === true, '0. the application is made',
          JSON.stringify(created && (created.errors || created.ok)));
  const entry = applications.get(ID);
  const records = applications.clientSecretRecordsOf(entry.fields);
  const id = records.length ? records[0].id : '';

  const shown = adminActions.applicationsAction({
    action: 'reveal-secret', application: ID, secret: id }, []);
  t.check(shown && shown.ok === true && shown.value === secret &&
          shown.secret === id,
          '1a. a client secret is revealed by its id',
          JSON.stringify(shown && (shown.errors || shown.secret)));

  const token = adminActions.applicationsAction({
    action: 'reveal-secret', application: ID,
    secret: 'registration-access-token' }, []);
  t.check(token && token.ok === false &&
          errorCodes.codeOf(token) === 'STS-ADMIN-0842',
          '2a. an application with no registration access token has none ' +
          'to reveal', JSON.stringify(token && token.errors));

  const unknown = adminActions.applicationsAction({
    action: 'reveal-secret', application: ID, secret: 'cs-not-there' }, []);
  t.check(unknown && unknown.ok === false &&
          errorCodes.codeOf(unknown) === 'STS-ADMIN-0842',
          '2b. an id the application does not hold is refused',
          JSON.stringify(unknown && unknown.errors));

  const nobody = adminActions.applicationsAction({
    action: 'reveal-secret', application: ID + '-nobody', secret: id }, []);
  t.check(nobody && nobody.ok === false &&
          errorCodes.codeOf(nobody) === 'STS-ADMIN-0842',
          '2c. so is an application nobody recorded',
          JSON.stringify(nobody && nobody.errors));

  const rows = audit.list().filter(function (row) {
    return row.action === 'application.secret-revealed' &&
           row.target === ID;
  });
  t.check(rows.length === 1 &&
          JSON.stringify(rows[0]).indexOf(secret) < 0 &&
          JSON.stringify(rows[0]).indexOf(id) >= 0,
          '3. the reveal is audited, naming the secret and never its value',
          rows.length + ' row(s)');

  const answer = adminViews.applicationDetailJson({ query: {} }, ID).json;
  const where = [];
  (function walk(value, at) {
    if (typeof value === 'string' && value.indexOf(secret) >= 0) {
      where.push(at);
    } else if (value && typeof value === 'object') {
      Object.keys(value).forEach(function (key) {
        walk(value[key], at + '.' + key);
      });
    }
  })(answer, 'answer');
  t.check(where.length === 0,
          '4. the application\'s GET answer still carries no secret value',
          where.join(', '));
  const list = adminViews.applicationsListJson({ query: { q: ID } }).json;
  t.check(JSON.stringify(list).indexOf(secret) < 0 &&
          list.applications.length === 1,
          '4b. nor does the list\'s');

  adminActions.applicationsAction({ action: 'forget', application: ID });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application reveal secret',
  describe: 'reveal-secret: a client secret by its id or the registration ' +
            'access token, refused for what is not held, audited without ' +
            'the value, and never in a GET',
  run: run
};
