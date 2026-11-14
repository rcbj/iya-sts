// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: permission_claims.js
//
// ---------------------------------------------------------------------------
// CLAIMS MAPPED TO A RESOURCE SERVER'S OWN SCOPES (2026-10-09).
//
// A resource server maps each permission it exposes (`oauthPermission`) to
// catalogue attributes (`oauthPermissionClaims`, its Scope claims tab). An
// access token addressed to it on which a permission was granted carries
// those claims — and granting the permission is the grant of them, a
// standard OpenID Connect claim included. Asserted, in a CHILD PROCESS that
// loads the stack, through the actions the tab and `/admin-api` call and
// through `oauth2.tokenSet()`:
//
//   A. the refusals (STS-REG-0344): a permission it does not expose, an
//      attribute the catalogue does not hold, an application not declared
//      for OAuth, and a stored value that is not a JSON object;
//   B. a granted permission carries its claims — `email` without the
//      `email` scope among them — and one not granted carries none;
//   C. a permission that maps nothing, and a cleared mapping, carry none;
//   D. a mapping for a permission it no longer exposes is listed as stale
//      and carries nothing;
//   E. the view model and the tab's markup.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({
  name: 'permission_claims',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.PC_ROOT;
  const OUT = process.env.PC_OUT;
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  (async function () {
    require(ROOT + '/common/protocol_stack');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const views = require(ROOT + '/admin-core/admin_views');
    const page = require(ROOT + '/admin-ui/web_applications');
    const errorCodes = require(ROOT + '/common/error_codes');
    const BASE = 'https://sts.test';
    const HR = 'https://hr.pc.test/';
    const claimsOf = function (token) {
      return JSON.parse(Buffer.from(String(token).split('.')[1],
                                    'base64url').toString('utf8'));
    };
    const stamp = String(Date.now()).slice(-6);
    const realm = realms.create({ id: 'pc-' + stamp, name: 'pc' }).realm;
    await realms.run(realm, async function () {
      const act = function (body) {
        return actions.applicationsAction(body, [], {});
      };
      const code = function (answer) {
        return errorCodes.codeOf(answer);
      };
      applications.createApplication({ identifier: 'pc-api',
        protocols: ['oauth2'],
        fields: { oauthPermissionBaseUri: HR,
                  oauthPermission: ['hr.read|Read HR data', 'hr.admin'] } });
      applications.createApplication({ identifier: 'pc-web',
        protocols: ['oauth2', 'oidc'],
        fields: { oauthDelegatedPermission: [HR + 'hr.read',
                                             HR + 'hr.admin'] } });
      applications.createApplication({ identifier: 'pc-sp',
        protocols: ['saml2'], fields: {} });

      // --- A. The refusals ----------------------------------------------
      const notExposed = act({ action: 'set-permission-claims',
        application: 'pc-api', permission: 'hr.write',
        attributes: ['mail'] });
      const unknownAttr = act({ action: 'set-permission-claims',
        application: 'pc-api', permission: 'hr.read',
        attributes: ['nope'] });
      const notOauth = act({ action: 'set-permission-claims',
        application: 'pc-sp', permission: 'hr.read', attributes: [] });
      const notAnObject = applications.updateApplication('pc-api',
        { mode: 'set', attribute: 'oauthPermissionClaims',
          value: '["mail"]' });
      const notItsOwn = applications.updateApplication('pc-api',
        { mode: 'set', attribute: 'oauthPermissionClaims',
          value: '{"hr.write":["mail"]}' });
      note(code(notExposed) === 'STS-REG-0344' &&
           code(unknownAttr) === 'STS-REG-0344' &&
           code(notOauth) === 'STS-REG-0344' &&
           code(notAnObject) === 'STS-REG-0344' &&
           code(notItsOwn) === 'STS-REG-0344',
           'A1. a permission it does not expose, an unknown attribute, an ' +
           'application not declared for OAuth, a value that is not an ' +
           'object and an object naming another permission are refused',
           JSON.stringify([code(notExposed), code(unknownAttr),
                           code(notOauth), code(notAnObject),
                           code(notItsOwn)]));

      // --- B. A granted permission carries its claims ---------------------
      const set = act({ action: 'set-permission-claims',
        application: 'pc-api', permission: 'hr.read',
        attributes: ['mail', 'givenName'] });
      const issue = async function (scope, audience) {
        const body = await oauth2.tokenSet(BASE, {
          client_id: 'pc-web', grant: 'authorization_code', scope: scope,
          audience: audience, username: 'alice',
          user: { username: 'alice', sub: 'urn:uuid:pc-alice' } });
        return claimsOf(body.access_token);
      };
      const granted = await issue(HR + 'hr.read');
      note(set.ok && granted.aud === HR &&
           typeof granted.email === 'string' && granted.email.length > 0 &&
           typeof granted.given_name === 'string' &&
           granted.name === undefined,
           'B1. hr.read granted: its email and given_name are in — without ' +
           'the email or profile scope — and nothing it does not map',
           JSON.stringify([set.errors, granted]));
      const other = await issue(HR + 'hr.admin');
      note(other.aud === HR && other.email === undefined &&
           other.given_name === undefined,
           'B2. hr.admin granted, which maps nothing: none',
           JSON.stringify(other));
      const notAsked = await issue('', [HR]);
      note(notAsked.email === undefined && notAsked.given_name === undefined,
           'B3. a token for the resource server with no permission granted: ' +
           'none', JSON.stringify(notAsked));

      // --- C. Cleared -----------------------------------------------------
      const cleared = act({ action: 'clear-permission-claims',
        application: 'pc-api', permission: 'hr.read' });
      const after = await issue(HR + 'hr.read');
      note(cleared.ok && after.email === undefined &&
           [].concat(applications.get('pc-api').fields
             .oauthPermissionClaims || []).join('') === '',
           'C1. clearing the only mapping empties the attribute, and the ' +
           'permission carries none', JSON.stringify([cleared.errors, after]));

      // --- D. A permission no longer exposed -------------------------------
      act({ action: 'set-permission-claims', application: 'pc-api',
            permission: 'hr.admin', attributes: ['mail'] });
      applications.updateApplication('pc-api',
        { mode: 'remove', attribute: 'oauthPermission', value: 'hr.admin' });
      const state = views.applicationPermissionClaimsState(
        applications.get('pc-api'));
      note(state.stale.join() === 'hr.admin' &&
           state.permissions.map(function (p) { return p.name; }).join() ===
             'hr.read',
           'D1. a mapping for a permission it no longer exposes is stale',
           JSON.stringify(state.stale));

      // --- E. The view model and the tab ----------------------------------
      act({ action: 'set-permission-claims', application: 'pc-api',
            permission: 'hr.read', attributes: ['givenName'] });
      const model = views.applicationPermissionClaimsState(
        applications.get('pc-api'));
      const read = model.permissions[0];
      note(read.name === 'hr.read' && read.description === 'Read HR data' &&
           read.id === HR + 'hr.read' &&
           read.attributes.join() === 'givenName' &&
           model.stale.length === 0 && model.catalogue.length > 5,
           'E1. the model: each permission, its identifier and attributes; ' +
           'the save dropped the stale mapping', JSON.stringify(model));
      const row = { identifier: 'pc-api', page: { permissionClaims: model } };
      const ctxOf = require(ROOT + '/admin-ui/web_kit').context;
      const html = page.applicationScopeClaimsSection(ctxOf({}, true), row,
                                                      '');
      note(/name="attributes" value="givenName" checked/.test(html) &&
           !/name="attributes" value="mail" checked/.test(html) &&
           html.indexOf('set-permission-claims') >= 0 &&
           html.indexOf('clear-permission-claims') >= 0 &&
           html.indexOf(HR + 'hr.read') >= 0,
           'E2. the markup: the mapped box ticked, Save and Clear',
           html.slice(0, 400));
      const readOnly = page.applicationScopeClaimsSection(ctxOf({}, false),
                                                          row, '');
      note(readOnly.indexOf('<input type="checkbox"') < 0 &&
           readOnly.indexOf('set-permission-claims') < 0,
           'E3. a reader without write sees no form');
      const none = page.applicationScopeClaimsSection(ctxOf({}, true),
        { identifier: 'x', page: { permissionClaims: { permissions: [],
          stale: [], catalogue: [] } } }, '');
      note(/exposes no permission/.test(none),
           'E4. an application exposing no permission is told where to ' +
           'define one');
    });
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'permission-claims-' + process.pid +
                        '-' + require('crypto').randomBytes(8)
                          .toString('hex') + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', PC_ROOT: ROOT, PC_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'permission_claims',
  describe: 'claims mapped to a resource server\'s own scopes: the Scope ' +
            'claims tab\'s actions and refusals, a granted permission ' +
            'carrying its claims as their grant, and the tab\'s model and ' +
            'markup',
  run: run
};
