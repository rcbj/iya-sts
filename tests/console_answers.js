// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/console_answers.js
//
// ---------------------------------------------------------------------------
// WHAT A FORM'S ANSWER DRAWS IN THE STATIC CONSOLE (#446, 2026-10-05).
//
// `admin-ui/web_answers.ts` draws the three kinds of answer the deleted
// console handlers answered with a page, and `web_runtime.ts`'s
// `shapeFields()` sends a form as the operation's schema takes it. Both are
// pure, so they are held here without a server:
//
//   A. A round trip — "+", a bin, a view switch on the four field grids — is
//      recognised, and nothing else is: those forms' hidden `action` is the
//      write, so a press missed here would create or save.
//   B. A round trip draws the form again with every box as it was.
//   C. A secret shown once is drawn, and an answer without one is not.
//   D. A refused create comes back to its form with the reasons; the
//      workbench's next draft and a generated secret go into their forms;
//      Fill never overwrites what was typed.
//   E. `shapeFields()` keeps the field grid's `field.<attribute>.<n>` boxes
//      a schema names by pattern, and carries a column of checkboxes named
//      `attribute` into the `attributes` list an operation takes.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const WebAnswers = require('../admin-ui/web_answers');
const ConsoleRuntime = require('../admin-ui/web_runtime');

const log = require('bunyan').createLogger({
  name: 'console_answers', level: process.env.LOG_LEVEL || 'info' });

function checkRoundTrips(t) {
  log.debug("Entering checkRoundTrips().");
  t.log.info('=== A, B. the round trips ===');
  const pages = ['/admin/users/new', '/admin/users/edit',
                 '/admin/applications/new', '/admin/applications/edit'];
  t.check(pages.every(function (page) {
    return ['grow', 'drop', 'switchview'].every(function (name) {
      const fields = { action: 'create' };
      fields[name] = 'x';
      return WebAnswers.isRoundTrip(page, fields);
    });
  }), 'A1. "+", a bin and a view switch are round trips on all four forms');
  t.check(!WebAnswers.isRoundTrip('/admin/users/new',
                                  { action: 'create', username: 'a' }) &&
          !WebAnswers.isRoundTrip('/admin/groups', { grow: 'x' }),
          'A2. a create is not one, nor a press on another page');
  const drawn = WebAnswers.roundTrip('/admin/users/new',
    { username: 'ann', credential: 'password', switchview: 'advanced',
      'field.mail.0': 'ann@example.test' },
    { username: '', credential: 'none', fields: [] });
  t.check(drawn.username === 'ann' && drawn.credential === 'password' &&
          drawn.prefill.view === 'advanced' &&
          drawn.prefill.draft['field.mail.0'] === 'ann@example.test',
          'B1. the new-user form comes back in the view asked for, with ' +
          'every box as it was', JSON.stringify(drawn.prefill));
  const app = WebAnswers.roundTrip('/admin/applications/new',
    { protocol: ['vc', 'oauth2'], grow: 'oauthRedirectUri', view: 'simple' },
    { familyChoices: [{ id: 'vc', families: ['oid4vci', 'oid4vp'] },
                      { id: 'oauth2', families: ['oauth2'] }],
      state: { loaded: { url: 'https://rs.example' } } });
  t.check(app.state.protocols.join(',') === 'oid4vci,oid4vp,oauth2' &&
          app.state.loaded.url === 'https://rs.example' &&
          app.state.tab === 'fields',
          'B2. the new-application form keeps its families — a combined ' +
          'choice as the families it names — and a document it loaded',
          JSON.stringify(app.state));
  const edit = WebAnswers.roundTrip('/admin/users/edit',
    { user: 'ann', drop: 'title.1' }, { page: {} });
  t.check(edit.state && edit.state.draft.drop === 'title.1',
          'B3. a person\'s grid comes back as it was posted');
  log.debug("Leaving checkRoundTrips().");
}

function checkOnce(t) {
  log.debug("Entering checkOnce().");
  t.log.info('=== C. a secret shown once ===');
  const env = { back: '/admin/users?user=ann', base: 'https://sts.test',
                realmRoot: 'https://sts.test' };
  const reset = WebAnswers.once('/admin/users', 'reset-password', {},
    { ok: true, username: 'ann', password: 'Generated-1!', forcedChange: true,
      message: 'Reset.' }, env);
  t.check(reset && reset.html.indexOf('Generated-1!') >= 0 &&
          reset.html.indexOf('/admin/users?user=ann') >= 0,
          'C1. a reset password is drawn once, with the way back');
  const created = WebAnswers.once('/admin/users/new', 'create', {},
    { ok: true, username: 'bo', dn: 'uid=bo,ou=users', message: 'Made.',
      activationUrl: '/portal/activate?t=1',
      activationLink: 'https://public.test/portal/activate?t=1',
      entry: { attributes: { userpassword: ['$scrypt$x'], cn: ['Bo'] } } },
    env);
  t.check(created && created.html.indexOf(
            'https://public.test/portal/activate?t=1') >= 0 &&
          created.html.indexOf('$scrypt$x') < 0,
          'C2. a created person\'s activation link is the absolute one the ' +
          'operation built, and the verifier is named, not printed');
  const keytab = WebAnswers.once('/admin/kerberos/principals', 'create',
    {}, { ok: true, principal: 'HTTP/x@R', kvno: 2, etypes: [18],
          keytab: 'BQIAAA', keytabFilename: 'x.keytab', message: 'Made.' },
    env);
  t.check(keytab && /data:application\/octet-stream;base64,BQIAAA/
    .test(keytab.html), 'C3. a keytab is drawn once, as a download');
  const eab = WebAnswers.once('/admin/acme', 'create-eab', {},
    { ok: true, kid: 'k', hmacKey: 'h'.repeat(43), certbot: 'certbot …' },
    env);
  t.check(eab && eab.html.indexOf('h'.repeat(43)) >= 0,
          'C4. an EAB key is drawn once');
  t.check(WebAnswers.once('/admin/users', 'disable', {},
                          { ok: true, message: 'Disabled.' }, env) === null &&
          WebAnswers.once('/admin/users', 'reset-password', {},
                          { ok: false, password: 'x' }, env) === null,
          'C5. an answer with no secret, or a refusal, is not');
  log.debug("Leaving checkOnce().");
}

function checkRedraws(t) {
  log.debug("Entering checkRedraws().");
  t.log.info('=== D. redraws from an answer ===');
  const refused = WebAnswers.redraw('/admin/users/new', 'create',
    { username: 'ann', 'field.cn.0': 'Ann' },
    { ok: false, errors: ['The name is taken.'] }, { fields: [] });
  t.check(refused && /Nobody was created/.test(refused.banner) &&
          /The name is taken/.test(refused.banner) &&
          refused.json.prefill.draft['field.cn.0'] === 'Ann',
          'D1. a refused create comes back with its reasons and its boxes');
  const pane = WebAnswers.redraw('/admin/pki/certificate', 'generate-keys',
    {}, { ok: true, why: 'Generated.', workbench: { draft: { a: 1 } } },
    { workbench: { draft: {} }, persons: [] });
  t.check(pane && pane.json.workbench.draft.a === 1 &&
          /Generated/.test(pane.banner),
          'D2. the workbench is drawn with the draft its action answered');
  const secret = WebAnswers.redraw('/admin/applications/new',
    'generate-secret', { 'field.oauthTokenEndpointAuthMethod.0': 'none' },
    { ok: true, clientSecret: 's3cret' }, { familyChoices: [] });
  t.check(secret && secret.json.state.draft['field.oauthClientSecret'] ===
            's3cret' &&
          secret.json.state.draft['field.oauthTokenEndpointAuthMethod.0'] ===
            'client_secret_basic',
          'D3. a generated secret goes into its box, with client_secret_basic ' +
          'where only none was ticked');
  const filled = WebAnswers.filled(
    { username: 'ann', 'field.cn.0': 'Typed' },
    { invented: { cn: 'Invented', sn: 'Example' } }, { fields: [] });
  t.check(filled.json.prefill.fields.cn[0] === 'Typed' &&
          filled.json.prefill.fields.sn[0] === 'Example',
          'D4. Fill fills the empty boxes and keeps what was typed',
          JSON.stringify(filled.json.prefill.fields));
  t.check(WebAnswers.redraw('/admin/groups', 'create', {},
                            { ok: true }, {}) === null,
          'D5. an ordinary act is a notice, not a redraw');
  log.debug("Leaving checkRedraws().");
}

function checkShaping(t) {
  log.debug("Entering checkShaping().");
  t.log.info('=== E. what a form sends ===');
  const runtime = new ConsoleRuntime({ location: { pathname: '/admin' } });
  runtime.spec = {};
  const grid = runtime.shapeFields(
    { user: 'ann', 'field.cn.0': 'Ann', 'field.title': 'A\nB',
      present: 'cn title', group: 'identity', back: '/admin/users' },
    { type: 'object',
      properties: { user: { type: 'string' }, fields: { type: 'object' },
                    present: { type: ['string', 'array'],
                               items: { type: 'string' } } },
      patternProperties: { '^field\\.': { type: ['string', 'array'],
                                          items: { type: 'string' } } },
      additionalProperties: false });
  t.check(grid['field.cn.0'] === 'Ann' && grid['field.title'] === 'A\nB' &&
          grid.present === 'cn title' && grid.group === undefined &&
          grid.back === undefined,
          'E1. the grid\'s boxes are sent as typed, and what only the old ' +
          'console read is left out', JSON.stringify(grid));
  const listed = runtime.shapeFields(
    { attribute: ['givenName', 'sn'] },
    { type: 'object',
      properties: { attributes: { type: 'array', items: { type: 'string' } } },
      additionalProperties: false });
  t.check(JSON.stringify(listed.attributes) === '["givenName","sn"]',
          'E2. a column of `attribute` boxes is the `attributes` list',
          JSON.stringify(listed));
  const one = runtime.shapeFields(
    { attribute: 'givenName' },
    { type: 'object',
      properties: { attributes: { type: 'array', items: { type: 'string' } } },
      additionalProperties: false });
  t.check(JSON.stringify(one.attributes) === '["givenName"]',
          'E3. and one ticked box is a list of one');
  log.debug("Leaving checkShaping().");
}

function run(t) {
  log.debug("Entering run().");
  checkRoundTrips(t);
  checkOnce(t);
  checkRedraws(t);
  checkShaping(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console answers',
  describe: 'web_answers.ts draws round trips, secrets shown once and ' +
            'redraws from an answer; shapeFields() keeps the field grid and ' +
            'carries a checkbox column into its list member',
  run: run
};
