'use strict';
//
// File: tests/application_cors_field.js
//
// ---------------------------------------------------------------------------
// `appCorsOrigin` ON THE CREATE FORM AND ON THE APPLICATION'S PAGE
// (2026-09-18).
//
// The attribute configures CORS on every endpoint this service publishes
// (`common/cors.js`). It was accepted by `createApplication()` and by the
// management API, and drawn by nothing on /admin/applications/new, because
// that form draws one section per ROLE out of
// `applications.declarationAttributes()` and the attribute was not in that
// list. It is now, as the one row that belongs to every family.
//
// What is held here, through the functions the console's forms post to
// (`adminActions.applicationsAction()`) and the document the API publishes
// (`adminViews.newApplicationJson()`):
//
//   1. THE ROW: role `cors`, no families and `everyFamily`, so the form's
//      section is unconditional and the API publishes it.
//   2. A CREATE with origins on several lines and NO family declared: the
//      origins are stored normalised and de-duplicated, because CORS is not a
//      property of one protocol.
//   3. A value that is not an origin refuses the whole create (STS-REG-0150).
//   4. THE PAGE'S EDITOR: add one, remove one by the value as stored — the
//      two actions its Add box and per-row Remove buttons post.
//   5. What CORS itself reads for that client is the list just written.
//
// The HTML of the two pages is not rendered here: requiring the console runs
// its load-time wiring in `run.js`'s one process. That every role has a
// section on the form is `tests/application_form_roles.js`'s job, and it
// fails if the `cors` role loses its section.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');

const log = require('bunyan').createLogger({ name: 'application_cors_field',
  level: process.env.LOG_LEVEL || 'info' });

const ID = 'cors-field-app-' + process.pid;

function run(t) {
  log.debug("Entering run().");

  // --- 1. The row --------------------------------------------------------
  const row = applications.declarationAttributes().filter(function (one) {
    return one.attribute === 'appCorsOrigin';
  })[0];
  t.check(row && row.role === 'cors' && row.kind === 'multi' &&
          row.everyFamily === true && row.families.length === 0,
          '1a. appCorsOrigin is a declaration of its own role, belonging to ' +
          'every family rather than to none',
          JSON.stringify(row && { role: row.role, kind: row.kind,
                                  every: row.everyFamily,
                                  families: row.families.length }));
  const published = adminViews.newApplicationJson({}).declarations || [];
  t.check(published.some(function (one) {
    return one.attribute === 'appCorsOrigin';
  }), '1b. and GET /admin-api/applications/new publishes it, from the same ' +
      'list the form draws');

  // --- 2. Create, several lines, no family -------------------------------
  const created = adminActions.applicationsAction({
    action: 'create', identifier: ID,
    'field.appCorsOrigin': 'HTTPS://App.CorsField.example:443\n' +
                           'https://app.corsfield.example\n' +
                           'http://localhost:5173'
  }, []);
  t.check(created && created.ok === true,
          '2a. a create carrying CORS origins and declaring NO family is ' +
          'accepted — the attribute is not family-scoped',
          JSON.stringify(created && (created.errors || created.ok)));
  const stored = applications.corsOriginsOf(applications.get(ID) || {});
  t.equal(JSON.stringify(stored),
          JSON.stringify(['https://app.corsfield.example',
                          'http://localhost:5173']),
          '2b. stored normalised and de-duplicated: two spellings of one ' +
          'origin are one value, and a non-default port is kept');

  // --- 3. Not an origin --------------------------------------------------
  const refused = adminActions.applicationsAction({
    action: 'create', identifier: ID + '-bad',
    'field.appCorsOrigin': 'https://ok.corsfield.example\n' +
                           'https://has.a.path.example/callback'
  }, []);
  t.check(refused && refused.ok === false && !applications.get(ID + '-bad'),
          '3a. one value that is not an origin refuses the WHOLE create ' +
          'rather than writing the rest',
          JSON.stringify(refused && refused.errors));
  t.check(refused && /appCorsOrigin/.test((refused.errors || []).join(' ')),
          '3b. and the refusal names the attribute',
          (refused && refused.errors || []).join(' '));

  // --- 4. The page's editor: add, then remove by the stored value ---------
  const added = adminActions.applicationsAction({
    action: 'add', application: ID, attribute: 'appCorsOrigin',
    value: 'HTTPS://Third.CorsField.example' });
  t.check(added && added.ok === true &&
          applications.corsOriginsOf(applications.get(ID))
            .indexOf('https://third.corsfield.example') >= 0,
          '4a. the page\'s Add box adds one origin, normalised',
          JSON.stringify(added && (added.errors || added.ok)));
  const badAdd = adminActions.applicationsAction({
    action: 'add', application: ID, attribute: 'appCorsOrigin',
    value: 'https://*.corsfield.example' });
  t.check(badAdd && badAdd.ok === false,
          '4b. and refuses a wildcard, which is not an origin',
          JSON.stringify(badAdd && badAdd.errors));
  const removed = adminActions.applicationsAction({
    action: 'remove', application: ID, attribute: 'appCorsOrigin',
    value: 'http://localhost:5173' });
  const after = applications.corsOriginsOf(applications.get(ID));
  t.check(removed && removed.ok === true &&
          after.indexOf('http://localhost:5173') < 0 &&
          after.indexOf('https://app.corsfield.example') >= 0,
          '4c. a row\'s Remove button takes that one origin off and leaves ' +
          'the others', JSON.stringify(after));

  // --- 5. What CORS reads ------------------------------------------------
  // For a request that names a CLIENT, `common/cors.js` looks the name up in
  // the identifier attributes that kind of name lives in — `oauthClientId` for
  // a client_id — so this is an OAuth client, created through the same form
  // path with its origins in the same field.
  const CLIENT = ID + '-client';
  const client = adminActions.applicationsAction({
    action: 'create', identifier: CLIENT,
    'field.oauthClientId': CLIENT,
    'field.appCorsOrigin': 'https://Spa.CorsField.example\n' +
                           'https://admin.corsfield.example:8443'
  }, ['oauth2']);
  const forClient = applications.corsOriginsForClient(CLIENT,
                                                      ['oauthClientId']);
  t.check(client && client.ok === true && forClient && forClient.known &&
          JSON.stringify(forClient.origins) ===
            JSON.stringify(['https://spa.corsfield.example',
                            'https://admin.corsfield.example:8443']),
          '5a. what common/cors.js reads for a request naming this client_id ' +
          'is exactly the list typed into the form', JSON.stringify(forClient));
  t.check(applications.corsOriginsOfRealm()
            .indexOf('https://spa.corsfield.example') >= 0,
          '5b. and a request naming NO client — discovery, a JWKS, a ' +
          'preflight — is answered for it too, from the realm\'s union');

  adminActions.applicationsAction({ action: 'forget', application: ID });
  adminActions.applicationsAction({ action: 'forget', application: CLIENT });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application CORS field',
  describe: 'appCorsOrigin on /admin/applications/new and on an ' +
            'application\'s page: one list for the form and the API, ' +
            'normalised, refused when not an origin, added and removed ' +
            'value by value',
  run: run
};
