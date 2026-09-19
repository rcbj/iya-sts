'use strict';
//
// File: tests/application_generate_secret.js
//
// ---------------------------------------------------------------------------
// GENERATE SECRET ON /admin/applications/new (2026-09-18).
//
// A button beside `oauthClientSecret` on the create form mints a client
// secret for an application that does not exist yet. The console ships no
// script, so the button is a submit with a `formaction`: the whole form goes
// to `POST /admin/applications/new` with `action=generate-secret`, and the
// page is drawn again with every box as it was and the new secret in the
// secret box. The secret comes from `applications.mintClientSecret()` — the
// one definition of a client secret, shared with `regenerate-secret` and
// `POST /oauth2/register` — through an action that WRITES NOTHING.
//
// What is held here, through the functions the console's forms post to:
//
//   1. `mintClientSecret()`: `oauth2.registeredSecretBytes` bytes, base64url,
//      and a different value every call.
//   2. `generate-secret` names no application, hands back a secret and
//      leaves the registry as it was.
//   3. A create carrying that secret, with OAuth 2.0 ticked and no method
//      named, is recorded as `client_secret_basic` — the method under which
//      the token endpoint takes the secret by a Basic header or a
//      `client_secret` form parameter alike.
//   4. The realm link rewrite reaches `formaction`, which it did not: the
//      button — and the two other `formaction` buttons in the console —
//      posted to the default realm from inside any other.
//
// The HTML is not rendered here, for `application_cors_field.js`'s reason:
// requiring the console runs its load-time wiring in `run.js`'s one process.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const app = require('../common/app');
const config = require('../common/config');

const log = require('bunyan').createLogger({
  name: 'application_generate_secret',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'generate-secret-app-' + process.pid;

function run(t) {
  log.debug("Entering run().");

  // --- 1. What a minted secret is ----------------------------------------
  const bytes = Number(config.value('oauth2.registeredSecretBytes')) || 24;
  const one = applications.mintClientSecret();
  const two = applications.mintClientSecret();
  t.check(/^[A-Za-z0-9_-]+$/.test(one) &&
          Buffer.from(one, 'base64url').length === bytes,
          '1a. a minted secret is oauth2.registeredSecretBytes random bytes, ' +
          'base64url', one.length + ' characters for ' + bytes + ' bytes');
  t.check(one !== two, '1b. and no two are alike');

  // --- 2. The action writes nothing --------------------------------------
  const before = applications.list().length;
  const generated = adminActions.applicationsAction({
    action: 'generate-secret' }, []);
  t.check(generated && generated.ok === true &&
          typeof generated.clientSecret === 'string' &&
          Buffer.from(generated.clientSecret, 'base64url').length === bytes,
          '2a. generate-secret needs no application and hands back a secret',
          JSON.stringify(generated && (generated.errors || generated.ok)));
  t.equal(applications.list().length, before,
          '2b. and writes nothing to the registry');

  // --- 3. The create that carries it -------------------------------------
  const created = adminActions.applicationsAction({
    action: 'create', identifier: ID,
    'field.oauthClientId': ID,
    'field.oauthClientSecret': generated.clientSecret
  }, ['oauth2']);
  const entry = applications.get(ID);
  const first = function (value) {
    return String([].concat(value === undefined ? [] : value)[0] || '');
  };
  t.check(created && created.ok === true && entry &&
          first(entry.fields.oauthClientSecret) === generated.clientSecret,
          '3a. a create carrying the generated secret stores it',
          JSON.stringify(created && (created.errors || created.ok)));
  t.equal(first(entry && entry.fields.oauthTokenEndpointAuthMethod),
          'client_secret_basic',
          '3b. and, naming no method, is recorded as client_secret_basic');

  // --- 4. The realm rewrite reaches formaction ---------------------------
  const rewritten = app.withRealmLinks(
      '<form action="/admin/applications"><button ' +
      'formaction="/admin/applications/new">Generate Secret</button>' +
      '<a href="//elsewhere.example/">x</a></form>', '/realm/acme');
  t.check(rewritten.indexOf(
              'formaction="/realm/acme/admin/applications/new"') >= 0 &&
          rewritten.indexOf('action="/realm/acme/admin/applications"') >= 0,
          '4a. a formaction is given the realm prefix, as an action is',
          rewritten);
  t.check(rewritten.indexOf('href="//elsewhere.example/"') >= 0,
          '4b. and a protocol-relative link is still left alone', rewritten);

  adminActions.applicationsAction({ action: 'forget', application: ID });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application generate secret',
  describe: 'Generate Secret on /admin/applications/new: one definition of ' +
            'a client secret, an action that writes nothing, ' +
            'client_secret_basic on the create, and formaction under a realm',
  run: run
};
