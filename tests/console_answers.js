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
//      An act that lands elsewhere — a group acted on, a new application —
//      names where (C6).
//   D. A refused create comes back to its form with the reasons; the
//      workbench's next draft and a generated secret go into their forms;
//      Fill never overwrites what was typed.
//   E. `shapeFields()` keeps the field grid's `field.<attribute>.<n>` boxes
//      a schema names by pattern, and carries a column of checkboxes named
//      `attribute` into the `attributes` list an operation takes.
//   F. `revealActiveNav()` scrolls the sidebar's own nav so the active tab
//      is in its middle after a page is drawn in place, and leaves a page
//      with no nav or no active tab alone (2026-10-08).
//   G. THE SIDEBAR'S SECTIONS, ONE OPEN AT A TIME (#750): every section is a
//      `<details>` sharing one `name`. The shell draws one open only when
//      handed its key. A fresh runtime has not chosen, and its first drawing
//      opens the section that holds the page — a reload shows that list
//      open, a page inside a group included — and remembers it. A section
//      the reader then closes stays closed on the next drawing.
//      `onNavToggle()` records an opening, forgets a closing and closes the
//      others where a browser does not; and `revealActiveNav()` leaves a
//      closed section's hidden tab alone.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const WebAnswers = require('../admin-ui/web_answers');
const ConsoleRuntime = require('../admin-ui/web_runtime');
const WebShell = require('../admin-ui/web_shell');

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
  const dn = 'cn=ops,ou=groups,dc=example,dc=net';
  const madeGroup = WebAnswers.landing('/admin/groups', 'create',
    { ok: true, dn: dn }, '/admin/groups?q=op');
  const madeApp = WebAnswers.landing('/admin/applications/new', 'create',
    { ok: true, application: { identifier: 'urn:example:crm' } },
    '/admin/applications/new');
  t.check(madeGroup === '/admin/groups?q=op&group=' + encodeURIComponent(dn)
            .replace(/%20/g, '+') &&
          madeApp === '/admin/applications?application=' +
            encodeURIComponent('urn:example:crm') &&
          WebAnswers.landing('/admin/groups', 'create',
                             { ok: false, dn: dn }, '/admin/groups') === null &&
          WebAnswers.landing('/admin/users', 'disable', { ok: true, dn: dn },
                             '/admin/users') === null,
          'C6. a group acted on lands on the group, a new application on its ' +
          'entry, keeping the list view; a refusal and any other act stay put',
          JSON.stringify([madeGroup, madeApp]));
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
          refused.json.prefill.draft['field.cn.0'] === 'Ann' &&
          /^<div class="flash"/.test(refused.banner),
          'D1. a refused create comes back with its reasons and its boxes, ' +
          'the reasons in the floating banner (#1066)');
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
  // E4. AN UNTICKED BOX IS `false` WHERE THE OPERATION TAKES A BOOLEAN
  // (2026-10-12): Directory → Policies' passkey profile is saved whole, and
  // unticking "Allow a passkey sign-in with no username" sent nothing and
  // was refused. A box ticked under the same name, a member the schema
  // does not name, and a member that is not only a boolean are left alone.
  const form = { querySelectorAll: function () {
    return [{ name: 'allowUsernameless', checked: false },
            { name: 'enforcePinLength', checked: true },
            { name: 'pair', checked: false }, { name: 'pair', checked: true },
            { name: 'unknown', checked: false },
            { name: 'loose', checked: false },
            { name: 'either', checked: false },
            { name: 'text', checked: false },
            { name: 'off', checked: false, disabled: true }];
  } };
  const unticked = ConsoleRuntime.uncheckedBoxes(form);
  const policy = runtime.shapeFields(
    { enforcePinLength: 'true', pair: 'on' },
    { type: 'object',
      properties: { allowUsernameless: { type: 'boolean' },
                    enforcePinLength: { type: 'boolean' },
                    pair: { type: 'boolean' },
                    loose: { type: ['boolean', 'string'] },
                    either: { oneOf: [{ type: 'boolean' },
                                      { type: 'string' }] },
                    text: { type: 'string' },
                    off: { type: 'boolean' } },
      additionalProperties: false }, unticked);
  // `either` is how the policy kinds declare a yes/no field (a boolean or
  // a `TRUE`/`FALSE` string): the first version of this missed it, and the
  // passkey profile was still refused.
  t.check(JSON.stringify(unticked) === '["allowUsernameless","unknown",' +
          '"loose","either","text","off"]' && policy.allowUsernameless === false &&
          policy.enforcePinLength === true && policy.pair === true &&
          policy.loose === false && policy.either === false &&
          policy.off === false &&
          !('unknown' in policy) && !('text' in policy),
          'E4. an unticked box is sent as false where the operation takes ' +
          'a boolean (in its type or a oneOf branch), and nothing else is', JSON.stringify({ unticked: unticked,
                                                            policy: policy }));
  log.debug("Leaving checkShaping().");
}

// A nav 400px tall holding 2000px of tabs, scrolled to the top as a page
// drawn by `innerHTML` leaves it, with the active tab 1500px down.
function checkNavReveal(t) {
  log.debug("Entering checkNavReveal().");
  const box = function (top, height) {
    return function () {
      return { top: top, height: height };
    };
  };
  const nav = { scrollTop: 0, clientHeight: 400 };
  const here = { getBoundingClientRect: box(100 + 1500, 20) };
  nav.getBoundingClientRect = box(100, 400);
  nav.querySelector = function (selector) {
    return selector === '.here' ? here : null;
  };
  const doc = {
    querySelector: function (selector) {
      return selector === 'aside.side nav' ? nav : null;
    }
  };
  new ConsoleRuntime({ location: { pathname: '/admin' }, document: doc })
    .revealActiveNav();
  t.check(nav.scrollTop === 1500 - (400 - 20) / 2,
          'F1. the active tab is scrolled to the middle of the nav',
          'scrollTop ' + nav.scrollTop);
  const top = { scrollTop: 0, clientHeight: 400,
                getBoundingClientRect: box(100, 400) };
  top.querySelector = function () {
    return { getBoundingClientRect: box(110, 20) };
  };
  new ConsoleRuntime({ location: { pathname: '/admin' },
                       document: { querySelector: function () {
                         return top;
                       } } }).revealActiveNav();
  t.check(top.scrollTop === 0,
          'F2. a tab near the top never scrolls the nav past its start',
          'scrollTop ' + top.scrollTop);
  let threw = '';
  try {
    new ConsoleRuntime({ location: { pathname: '/admin' },
                         document: { querySelector: function () {
                           return null;
                         } } }).revealActiveNav();
    new ConsoleRuntime({ location: { pathname: '/admin' } }).revealActiveNav();
  } catch (e) {
    threw = String((e && e.message) || e);
  }
  t.check(threw === '', 'F3. no nav, or no document, is left alone', threw);
  // F4 is the source: every page the runtime draws (`draw()`) asks it, or a
  // method held correct above is one nothing calls.
  const source = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'admin-ui', 'web_runtime.ts'),
    'utf8');
  const drawBody = source.slice(source.indexOf('this.loadPageScripts();'),
                                source.indexOf('revealActiveNav(): void'));
  t.check(/this\.revealActiveNav\(\);/.test(drawBody),
          'F4. draw() reveals the active tab after the page is in place',
          'not called from draw()');
  log.debug("Leaving checkNavReveal().");
}

// Three sections the way the shell answer carries them, one holding a group,
// and the page being drawn in the second.
const NAV_SHELL = {
  gate: { session: true, username: 'alice' },
  sections: [
    { title: 'Overview', what: 'The start.',
      items: [{ path: '/admin', label: 'Overview' }] },
    { title: 'Directory', what: 'People.',
      items: [{ path: '/admin/users', label: 'Users' },
              { path: '/admin/groups', label: 'Groups' }] },
    { title: 'Server configuration', what: 'The process.',
      items: [{ title: 'Keys', what: 'Key pairs.',
                items: [{ path: '/admin/keys', label: 'Key pairs' }] }] }
  ],
  realm: { id: '', name: 'Default' }, navLabels: {}, version: {},
  persistence: {}, portalHref: '/portal' };

// Every `<details ...>` opening tag of the sidebar, by its section's key.
function navSections(html) {
  const found = {};
  const re = /<details class="navsec([^"]*)" name="([^"]*)" data-section="([^"]*)"([^>]*)>/g;
  let m = re.exec(html);
  while (m) {
    found[m[3]] = { current: / current/.test(m[1]), name: m[2],
                    open: / open/.test(m[4]) };
    m = re.exec(html);
  }
  return found;
}

// A stand-in for one section's `<details>`, enough for onNavToggle().
function fakeSection(key, open) {
  return {
    open: open,
    classList: { contains: function (name) {
      return name === 'navsec';
    } },
    getAttribute: function (name) {
      return name === 'data-section' ? key : null;
    }
  };
}

function checkNavSections(t) {
  log.debug("Entering checkNavSections().");
  t.log.info('=== G. the sidebar\'s sections ===');
  const page = { title: 'Users', active: '/admin/users', up: null,
                 inner: '<p>x</p>', path: '/admin/users' };
  const fresh = WebShell.frame(NAV_SHELL, page);
  const drawn = navSections(fresh);
  const keys = Object.keys(drawn);
  t.check(keys.join(',') === 'overview,directory,server-configuration' &&
          keys.every(function (key) {
            return drawn[key].name === WebShell.NAV_GROUP &&
                   !drawn[key].open;
          }) && !/<p class="navhead"/.test(fresh) &&
          (fresh.match(/<summary class="navhead"/g) || []).length === 3,
          'G1. every section is a <details> of one named group, its heading '
          + 'the <summary>, and on a fresh load none is open',
          JSON.stringify(drawn));
  t.check(drawn.directory.current && !drawn.overview.current &&
          !drawn['server-configuration'].current &&
          /<span class="here"[^>]*aria-current="page">Users<\/span>/
            .test(fresh),
          'G2. the closed section holding the page is marked current, and '
          + 'the page\'s own entry inside it still is',
          JSON.stringify(drawn));
  const opened = navSections(WebShell.frame(NAV_SHELL, Object.assign({},
    page, { openSection: 'server-configuration' })));
  t.check(opened['server-configuration'].open && !opened.directory.open &&
          !opened.overview.open && opened.directory.current,
          'G3. the section the reader opened is the one drawn open, on a '
          + 'page in another section',
          JSON.stringify(opened));
  // THE RUNTIME'S HALF: what a `toggle` records, and the one-open rule
  // where the browser's `name` does not give it.
  const directory = fakeSection('directory', true);
  const overview = fakeSection('overview', true);
  const rt = new ConsoleRuntime({ location: { pathname: '/admin' },
    document: { querySelectorAll: function (selector) {
      return selector === 'aside.side details.navsec[open]'
        ? [overview, directory].filter(function (one) {
          return one.open;
        }) : [];
    } } });
  t.check(rt.openSection === null,
          'G4. a runtime has not chosen a section yet', rt.openSection);
  t.check(WebShell.sectionKeyOf(NAV_SHELL.sections, '/admin/users') ===
          'directory' &&
          WebShell.sectionKeyOf(NAV_SHELL.sections, '/admin/keys') ===
          'server-configuration' &&
          WebShell.sectionKeyOf(NAV_SHELL.sections, '/admin/nope') === '' &&
          WebShell.sectionKeyOf(null, '/admin/users') === '',
          'G4a. the section key is the one holding the page, a group ' +
          'included, and a page in none has none');
  const body = {};
  const freshRt = new ConsoleRuntime({
    location: { pathname: '/admin/users', search: '', hash: '' },
    document: {
      body: body,
      querySelectorAll: function () { return []; },
      querySelector: function () { return null; },
      getElementById: function () { return null; }
    }
  });
  freshRt.shell = NAV_SHELL;
  freshRt.draw('Users', '/admin/users', '<p>x</p>', null);
  const reloaded = navSections(body.innerHTML);
  t.check(freshRt.openSection === 'directory' && reloaded.directory.open &&
          !reloaded.overview.open &&
          !reloaded['server-configuration'].open,
          'G4b. a reload opens the section that holds the page',
          freshRt.openSection + ' ' + JSON.stringify(reloaded));
  freshRt.onNavToggle(fakeSection('directory', false));
  freshRt.draw('Users', '/admin/users', '<p>x</p>', null);
  const stayed = navSections(body.innerHTML);
  t.check(freshRt.openSection === '' && !stayed.directory.open &&
          !stayed.overview.open,
          'G4c. a section the reader closed stays closed on the next ' +
          'drawing',
          freshRt.openSection + ' ' + JSON.stringify(stayed));
  rt.onNavToggle(directory);
  t.check(rt.openSection === 'directory' && overview.open === false &&
          directory.open === true,
          'G5. opening a section records it and closes any other',
          rt.openSection + ' ' + overview.open);
  rt.onNavToggle(overview);
  t.check(rt.openSection === 'directory',
          'G6. the close of another section does not forget the open one',
          rt.openSection);
  directory.open = false;
  rt.onNavToggle(directory);
  t.check(rt.openSection === '',
          'G7. closing the open section forgets it', rt.openSection);
  rt.onNavToggle({ open: true, classList: { contains: function () {
    return false;
  } }, getAttribute: function () {
    return 'usermenu';
  } });
  rt.onNavToggle(null);
  t.check(rt.openSection === '',
          'G8. a <details> outside the sidebar, or none, is ignored',
          rt.openSection);
  // F4's way: the source wires what is held above, or it is held for
  // nothing.
  const source = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'admin-ui', 'web_runtime.ts'),
    'utf8');
  t.check(/openSection: this\.openSection/.test(source) &&
          /addEventListener\('toggle', function \(event\) \{\s*self\.onNavToggle\(event && event\.target\);\s*\}, true\)/
            .test(source),
          'G9. draw() hands the open section to the shell, and start() '
          + 'catches every toggle in the capture phase',
          'not wired');
  // A CLOSED SECTION'S TAB HAS NO BOX: the open section's heading is what
  // is centred, and with none open nothing moves.
  const box = function (top, height) {
    return function () {
      return { top: top, height: height };
    };
  };
  const heading = { getBoundingClientRect: box(100 + 900, 20) };
  const hidden = { getBoundingClientRect: box(0, 0),
                   closest: function (selector) {
                     return selector === 'details:not([open])' ? {} : null;
                   } };
  const navWith = function (openHeading) {
    const nav = { scrollTop: 0, clientHeight: 400,
                  getBoundingClientRect: box(100, 400) };
    nav.querySelector = function (selector) {
      if (selector === '.here') {
        return hidden;
      }
      return selector === 'details[open] > summary' ? openHeading : null;
    };
    return nav;
  };
  const withOpen = navWith(heading);
  const withNone = navWith(null);
  [withOpen, withNone].forEach(function (nav) {
    new ConsoleRuntime({ location: { pathname: '/admin' },
                         document: { querySelector: function () {
                           return nav;
                         } } }).revealActiveNav();
  });
  t.check(withOpen.scrollTop === 900 - (400 - 20) / 2 &&
          withNone.scrollTop === 0,
          'G10. a tab in a closed section is not scrolled to; the open '
          + 'section\'s heading is, and with none open nothing moves',
          withOpen.scrollTop + ' ' + withNone.scrollTop);
  log.debug("Leaving checkNavSections().");
}

function run(t) {
  log.debug("Entering run().");
  checkRoundTrips(t);
  checkOnce(t);
  checkRedraws(t);
  checkShaping(t);
  checkNavReveal(t);
  checkNavSections(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'console answers',
  describe: 'web_answers.ts draws round trips, secrets shown once and ' +
            'redraws from an answer; shapeFields() keeps the field grid and ' +
            'carries a checkbox column into its list member; the sidebar ' +
            'opens the section that holds the page on a fresh load, and ' +
            'one section at a time after that',
  run: run
};
