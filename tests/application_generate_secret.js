// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
//   5. THE FIRST SECRET'S LIFETIME (#394). A create's `lifetimeDays` is
//      stamped on the secret's record as its expiry, for a generated secret
//      and a typed one. Empty takes `oauth2.clientSecretLifetimeDays`, and 0
//      never expires. A lifetime outside 0..730 is refused `STS-REG-0359`.
//      One with no secret, or with a whole record that keeps its own
//      expiry, is refused `STS-REG-0360`. Neither refusal creates anything.
//      The form draws the field beside Generate Secret, with the add form's
//      name, range and the setting as its placeholder.
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
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'application_generate_secret',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'generate-secret-app-' + process.pid;

function run(t) {
  log.debug("Entering run().");

  // --- 1. What a minted secret is ----------------------------------------
  const bytes = Number(config.value('oauth2.registeredSecretBytes'));
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
  // The entry holds the secret as a RECORD (2026-10-01): read it back the
  // way every verifier does.
  const stored = entry ? applications.primaryClientSecretOf(entry.fields)
                       : null;
  t.check(created && created.ok === true && stored &&
          stored.secret === generated.clientSecret,
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

  // --- 5. The first secret's lifetime (#394) -----------------------------
  // A default of 7 days, so that empty, 0 and a given lifetime each give a
  // different expiry.
  config.setOverride('oauth2.clientSecretLifetimeDays', 7);
  try {
    lifetimeChecks(t);
  } finally {
    config.clearOverride('oauth2.clientSecretLifetimeDays');
  }
  log.debug("Leaving run().");
}

// Section 5: a create's `lifetimeDays`, through the door the console and
// `POST /admin-api/applications/create` post to.
function lifetimeChecks(t) {
  log.debug("Entering lifetimeChecks().");
  const DAY = 86400;
  const create = function (suffix, secret, lifetimeDays) {
    const body = { action: 'create', identifier: ID + '-' + suffix,
                   'field.oauthClientId': ID + '-' + suffix };
    if (secret !== undefined) {
      body['field.oauthClientSecret'] = secret;
    }
    if (lifetimeDays !== undefined) {
      body.lifetimeDays = lifetimeDays;
    }
    return adminActions.applicationsAction(body, ['oauth2']);
  };
  const recordOf = function (suffix) {
    const entry = applications.get(ID + '-' + suffix);
    return entry ? applications.primaryClientSecretOf(entry.fields) : null;
  };
  const forget = function (suffix) {
    adminActions.applicationsAction({ action: 'forget',
                                      application: ID + '-' + suffix });
  };

  // 5a. A generated secret, 30 days.
  const minted = adminActions.applicationsAction({
    action: 'generate-secret' }, []).clientSecret;
  const a = create('gen30', minted, '30');
  const ra = recordOf('gen30');
  t.check(a && a.ok === true && ra && ra.secret === minted &&
          ra.expiresAt === ra.createdAt + 30 * DAY,
          '5a. a generated secret created with lifetimeDays 30 expires 30 ' +
          'days after it was made',
          JSON.stringify(a && (a.errors || ra)));
  forget('gen30');

  // 5b. A typed secret, 0: never, whatever the setting says.
  const b = create('typed0', 'a-typed-secret-' + process.pid, 0);
  const rb = recordOf('typed0');
  t.check(b && b.ok === true && rb && rb.expiresAt === 0,
          '5b. a typed secret created with lifetimeDays 0 never expires, ' +
          'over a setting of 7',
          JSON.stringify(b && (b.errors || rb)));
  forget('typed0');

  // 5c. Empty: the setting.
  const c = create('empty', 'another-typed-secret-' + process.pid, '');
  const rc = recordOf('empty');
  t.check(c && c.ok === true && rc &&
          rc.expiresAt === rc.createdAt + 7 * DAY,
          '5c. an empty lifetime takes oauth2.clientSecretLifetimeDays',
          JSON.stringify(c && (c.errors || rc)));
  forget('empty');

  // 5d. Out of range, or not a whole number of days.
  ['731', '-1', '1.5', 'soon'].forEach(function (bad) {
    const refused = create('bad', 'secret-' + process.pid, bad);
    t.check(refused && refused.ok === false &&
            errorCodes.codeOf(refused) === 'STS-REG-0359' &&
            !applications.get(ID + '-bad'),
            '5d. lifetimeDays ' + JSON.stringify(bad) + ' is refused ' +
            'STS-REG-0359 and nothing is created',
            JSON.stringify(refused) + ' ' + errorCodes.codeOf(refused));
    forget('bad');
  });

  // 5e. A lifetime with no secret to stamp.
  const e = create('nosecret', undefined, '30');
  t.check(e && e.ok === false &&
          errorCodes.codeOf(e) === 'STS-REG-0360' &&
          !applications.get(ID + '-nosecret'),
          '5e. a lifetime with no client secret is refused STS-REG-0360',
          JSON.stringify(e) + ' ' + errorCodes.codeOf(e));
  forget('nosecret');

  // 5f. A whole record keeps its own expiry, so a lifetime beside it is
  // refused rather than silently dropped.
  const whole = JSON.stringify({ id: 'cs-000000000001',
    secret: 'whole-record-' + process.pid, created: 1700000000,
    expires: 0, description: '' });
  const f = create('whole', whole, '30');
  t.check(f && f.ok === false &&
          errorCodes.codeOf(f) === 'STS-REG-0360' &&
          !applications.get(ID + '-whole'),
          '5f. a lifetime beside a whole secret record is refused ' +
          'STS-REG-0360',
          JSON.stringify(f) + ' ' + errorCodes.codeOf(f));
  forget('whole');

  // 5g. The form's field: the add form's name and range, the setting as
  // its placeholder, and a redraw's value kept.
  const WebKit = require('../admin-ui/web_kit');
  const page = require('../admin-ui/web_applications');
  const drawn = page.newSecretLifetime(7, '45', WebKit.context().t);
  t.check(/name="lifetimeDays"/.test(drawn) && /min="0"/.test(drawn) &&
          /max="730"/.test(drawn) && /placeholder="7"/.test(drawn) &&
          /value="45"/.test(drawn) &&
          drawn.indexOf('oauth2.clientSecretLifetimeDays') >= 0,
          '5g. the create form draws lifetimeDays, 0 to 730, placeholder ' +
          'the setting, keeping a redraw\'s value', drawn);
  log.debug("Leaving lifetimeChecks().");
}

module.exports = {
  name: 'application generate secret',
  describe: 'Generate Secret on /admin/applications/new: one definition of ' +
            'a client secret, an action that writes nothing, ' +
            'client_secret_basic on the create, formaction under a realm, ' +
            'and the first secret\'s lifetime (#394)',
  run: run
};
