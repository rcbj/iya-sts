// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authzen_admin.js
//
// ---------------------------------------------------------------------------
// THE AUTHZEN TAB AND ITS /admin-api TWIN (#563 phase 3, #1162).
//
// `authzen/authzen_admin.ts` is what both draw from and act through (rule 7),
// so its view and acts are held here in process, with the whole stack in a
// child process (`stored_certificates.js`'s reason):
//
//   V. THE VIEW: the realm's API object, the AuthZEN settings and no
//      others, an empty catalogue, the group's members with their scopes.
//   C. THE CATALOGUE ACTS: a row added, the same property replaced rather
//      than doubled, the reserved identifiers refused at this door too, a row
//      removed, and one that is not there refused.
//   S. THE SCOPE: a person's (the directory slot's write), an application's
//      (the registry's), read back by the AuthZEN caller checks exactly as a
//      request reads it; nobody and too many refused.
//   R. THE OPERATIONS: GET /admin-api/xacml/authzen and its three actions,
//      mirroring the tab.
//   D. THE TAB: drawn from the view, its forms posting to the tab.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_AUTHZEN_ADMIN_CHILD';
const MARK = 'AUTHZEN-ADMIN-CHILD ';
const REALM = 'azadmin';

const log = require('bunyan').createLogger({ name: 'authzen_admin',
  level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const keystore = require(ROOT + '/common/keystore');
  const realms = require(ROOT + '/common/realms');
  const config = require(ROOT + '/common/config');
  const applications = require(ROOT + '/common/applications');
  const errorCodes = require(ROOT + '/common/error_codes');
  const ldap = require(ROOT + '/ldap/ldap_server');
  const adminActions = require(ROOT + '/admin-core/admin_actions');
  const admin = require(ROOT + '/authzen/authzen_admin');
  const api = require(ROOT + '/mgmt-api/authzen_api');
  const callers = require(ROOT + '/authzen/authzen_caller');
  const XacmlPage = require(ROOT + '/xacml/web_xacml');
  const kit = require(ROOT + '/admin-ui/web_kit');

  await keystore.start();
  if (!realms.get(REALM)) {
    realms.create({ id: REALM, name: REALM });
  }
  const inRealm = function (fn) {
    log.debug("Entering inRealm().");
    log.debug("Leaving inRealm().");
    return realms.run(realms.get(REALM), fn);
  };
  const who = { actor: 'test', via: 'test' };
  const group = String(config.value('roles.authzenPepGroup'));

  inRealm(function () {
    ldap.createUser('azadm-pep', { invent: false });
    adminActions.groupsAction({ action: 'add-member', group: group,
                                member: 'azadm-pep' });
    applications.createApplication({ identifier: 'azadm-client',
      protocols: ['oauth2'], fields: { oauthClientId: 'azadm-client' } });
  });

  // -------------------------------------------------------------------------
  // V. THE VIEW
  // -------------------------------------------------------------------------
  let view = inRealm(function () {
    return admin.view({});
  });
  const groups = ((view.settings || {}).groups || []).map(function (one) {
    return one.group;
  });
  t.check(view.apiObject && view.catalogue.rows.length === 0 &&
          view.callerAuthentication === 'mtls' &&
          groups.join() === 'AuthZEN',
          'V1. the view carries the realm\'s API object, an empty ' +
          'catalogue, mtls as the default door, and the AuthZEN settings ' +
          'alone', JSON.stringify({ apiObject: view.apiObject,
                                     door: view.callerAuthentication,
                                     groups: groups }));
  t.check(view.callers.length === 1 && view.callers[0].name === 'azadm-pep' &&
          view.callers[0].applications.length === 0,
          'V2. the group\'s member is listed, scoped to nothing',
          JSON.stringify(view.callers));

  // -------------------------------------------------------------------------
  // C. THE CATALOGUE ACTS
  // -------------------------------------------------------------------------
  const act = function (body) {
    log.debug("Entering act().");
    log.debug("Leaving act().");
    return inRealm(function () {
      return admin.act(body, who);
    });
  };
  let r = act({ action: 'set-attribute', object: 'resource',
                property: 'classification',
                attributeId: 'urn:example:classification' });
  t.check(r.ok && !r.replaced, 'C1. set-attribute adds a row',
          JSON.stringify(r));
  r = act({ action: 'set-attribute', object: 'resource',
            property: 'classification', attributeId: 'urn:example:class',
            dataType: 'string', multiplicity: 'bag' });
  view = inRealm(function () {
    return admin.view({});
  });
  t.check(r.ok && r.replaced && view.catalogue.rows.length === 1 &&
          view.catalogue.rows[0].attributeId === 'urn:example:class' &&
          view.catalogue.rows[0].multiplicity === 'bag',
          'C2. the same property is replaced, never doubled',
          JSON.stringify(view.catalogue.rows));
  r = act({ action: 'set-attribute', object: 'subject', property: 'roles',
            attributeId: 'urn:sts:xacml:role' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHZEN-0011',
          'C3. a row onto a reserved identifier is refused here too ' +
          '(STS-AUTHZEN-0011)', JSON.stringify(r));
  r = act({ action: 'set-attribute', object: 'subject', property: 'dept',
            attributeId: 'departmentNumber' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHZEN-0012',
          'C4. and a bare directory name in a subject category ' +
          '(STS-AUTHZEN-0012)', JSON.stringify(r));
  r = act({ action: 'frobnicate' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHZEN-0030',
          'C5. an action the tab does not have is refused (STS-AUTHZEN-0030)',
          JSON.stringify(r));
  r = act({ action: 'remove-attribute', object: 'resource',
            property: 'classification' });
  const again = act({ action: 'remove-attribute', object: 'resource',
                      property: 'classification' });
  t.check(r.ok && !again.ok &&
          errorCodes.codeOf(again) === 'STS-AUTHZEN-0031',
          'C6. remove-attribute takes the row off, and a row that is not ' +
          'there is refused (STS-AUTHZEN-0031)', JSON.stringify([r, again]));

  // -------------------------------------------------------------------------
  // S. THE SCOPE
  // -------------------------------------------------------------------------
  const checker = new callers.AuthzenCaller(
    callers.AuthzenCaller.defaultDeps());
  r = act({ action: 'set-scope', caller: 'azadm-pep',
            applications: 'todo-app, wiki' });
  const pepDn = inRealm(function () {
    return ldap.locateEntry('azadm-pep').stored.dn;
  });
  const personScope = inRealm(function () {
    return checker.scopeOf({ kind: 'entry', name: pepDn });
  });
  t.check(r.ok && personScope.join() === 'todo-app,wiki',
          'S1. a person\'s scope is written onto the entry and read back ' +
          'as a request reads it', JSON.stringify([r, personScope]));
  r = act({ action: 'set-scope', caller: 'azadm-client',
            applications: ['billing'] });
  const appScope = inRealm(function () {
    return checker.scopeOf({ kind: 'application', name: 'azadm-client',
                             identifier: 'azadm-client',
                             clientId: 'azadm-client' });
  });
  t.check(r.ok && appScope.indexOf('billing') >= 0 &&
          appScope.indexOf('azadm-client') >= 0,
          'S2. an application\'s is written onto its entry, and its own ' +
          'identifier is always in it', JSON.stringify([r, appScope]));
  r = act({ action: 'set-scope', caller: 'azadm-pep', applications: '' });
  const cleared = inRealm(function () {
    return checker.scopeOf({ kind: 'entry', name: pepDn });
  });
  t.check(r.ok && cleared.length === 0, 'S3. an empty scope clears it',
          JSON.stringify(cleared));
  r = act({ action: 'set-scope', caller: 'azadm-nobody',
            applications: 'x' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHZEN-0033',
          'S4. a caller nobody is refused (STS-AUTHZEN-0033)',
          JSON.stringify(r));
  const many = [];
  for (let i = 0; i < 70; i += 1) {
    many.push('app-' + i);
  }
  r = act({ action: 'set-scope', caller: 'azadm-pep', applications: many });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHZEN-0032',
          'S5. more than 64 applications is refused (STS-AUTHZEN-0032)',
          JSON.stringify(r).slice(0, 300));

  // -------------------------------------------------------------------------
  // R. THE OPERATIONS
  // -------------------------------------------------------------------------
  const routes = api.ROUTES;
  const get = routes.filter(function (one) {
    return one.method === 'GET' && one.path === '/admin-api/xacml/authzen';
  })[0];
  const post = routes.filter(function (one) {
    return one.method === 'POST' &&
           one.route === '/admin-api/xacml/authzen/:action';
  })[0];
  t.check(get && post && /xacml-tab-authzen/.test(post.mirrors) &&
          post.actions.map(function (one) {
            return one.action;
          }).join() === admin.ACTIONS.join(),
          'R1. GET /admin-api/xacml/authzen and its three actions mirror ' +
          'the tab', JSON.stringify(routes.map(function (one) {
            return one.method + ' ' + (one.path || one.route);
          })));

  // -------------------------------------------------------------------------
  // D. THE TAB
  // -------------------------------------------------------------------------
  act({ action: 'set-attribute', object: 'resource',
        property: 'classification',
        attributeId: 'urn:example:classification' });
  view = inRealm(function () {
    return admin.view({});
  });
  const html = XacmlPage.authzenBody(kit.context({}, true), view);
  t.check(html.indexOf('action="/admin/xacml/authzen"') >= 0 &&
          html.indexOf('urn:example:classification') >= 0 &&
          html.indexOf('name="action" value="set-scope"') >= 0,
          'D1. the tab draws the catalogue and its forms post to the tab ' +
          '(/admin/xacml/authzen, moved onto #xacml-tab-authzen)',
          html.slice(0, 300));
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = 'fatal';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-1500) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the AuthZEN tab and /admin-api/xacml/authzen (#1162) ===');
  const got = spawnChild();
  if (got.error) {
    t.bad('the child did not run', got.error);
    log.debug("Leaving run(). No child.");
    return;
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env[CHILD_FLAG]) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'authzen_admin',
  describe: 'the AuthZEN tab and /admin-api/xacml/authzen (#563): the view, ' +
            'the catalogue acts and their refusals, the application scope ' +
            'of a person and an application, the operations and the tab',
  run: run
};
