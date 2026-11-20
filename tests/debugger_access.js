// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: debugger_access.js
//
// ===========================================================================
// WHO MAY USE THE EMBEDDED DEBUGGER, AND WHAT ITS API MAY DIAL (2026-09-13;
// rewritten for #1717, 2026-11-13).
//
// Five claims:
//
//   A. ONE APPLICATION: the client id is one spelling in `debugger_access.ts`,
//      `common/applications.js`'s seed and `common/oidc_rp.ts`'s surface; the
//      seeded entry is a confidential client asking for the OpenID Connect
//      scopes and nothing of a debugger api; and no entry defines the retired
//      permission;
//   B. RETIREMENT: an install seeded before #1717 has its seeded
//      `sts-debugger-api` row deleted and the seeded client's grant of the
//      permission taken off — and a row an operator made by hand is left
//      alone;
//   C. `isAdministrator()`, which the gate asks on every request, refuses the
//      empty roster (even though the console is open then), a person holding
//      no role, an application and an unauthenticated subject — and the
//      POLICY CANNOT WIDEN IT: there is no XACML decider loaded here, so
//      `access_gate.js` answers "allowed" to everything, and a subject holding
//      neither console role is refused anyway;
//   D. nothing narrows a debugger permission at issuance any more: `oauth2.ts`
//      no longer requires this module, and the scope policy protects no such
//      scope;
//   E. in product mode the api child's allow-list is this service's own
//      addresses plus `debugger.allowedDestinations`, and an entry that is not
//      a CIDR range is left out and reported rather than widened.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS. B and C need registry rows and a roster a running stack
// cannot be put into without editing its directory; D is a property of the
// source; E needs product mode and a setting that is restart-only.
// ===========================================================================

delete process.env.CONFIG_FILE;
process.env.STS_DEBUGGER_ALLOWED_DESTINATIONS = '203.0.113.0/24,not-a-range';

const fs = require('fs');
const path = require('path');
const config = require('../common/config');
const realms = require('../common/realms');
const applications = require('../common/applications');
// Fills the directory slots and seeds the internal applications.
require('../ldap/ldap_server');
const adminRbac = require('../admin-ui/admin_rbac');
const oidcRp = require('../common/oidc_rp');
const access = require('../debugger/debugger_access');
const scopePolicy = require('../common/scope_policy');
const apiProcess = require('../debugger/debugger_api_process');

const log = require('bunyan').createLogger({ name: 'debugger_access',
  level: process.env.LOG_LEVEL || 'info' });

function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function inDefault(fn) {
  log.debug("Entering inDefault().");
  log.debug("Leaving inDefault().");
  return realms.run(realms.get(realms.DEFAULT_ID), fn);
}

async function run(t) {
  log.debug("Entering run().");
  const retired = 'urn:sts:debugger-api:debugger';

  // -------------------------------------------------------------------------
  t.log.info('=== A. one application ===');
  const appsSource = fs.readFileSync(path.join(__dirname, '..', 'common',
                                               'applications.js'), 'utf8');
  t.check(appsSource.indexOf("identifier: '" + access.UI_CLIENT_ID + "'") >=
            0,
          'common/applications.js seeds the client the debugger checks');
  const surface = oidcRp.surfaceOf('debugger');
  t.equal(surface.clientId, access.UI_CLIENT_ID,
          'the oidc_rp surface signs in as the seeded client');
  t.equal(JSON.stringify(surface.scopes),
          JSON.stringify(['openid', 'profile', 'email', 'offline_access']),
          'and asks for the OpenID Connect scopes and no debugger api ' +
          'permission');
  inDefault(function () {
    t.check(!applications.forPermission(retired),
            'no entry defines the retired debugger api permission');
    const ui = applications.clientConfigOf(access.UI_CLIENT_ID);
    t.check(ui && ui.registered &&
            (ui.redirect_uris || []).some(function (uri) {
              return /\/_sts\/callback$/.test(uri);
            }),
            'the client\'s sign-in callback is on the debugger listener',
            JSON.stringify(ui && ui.redirect_uris));
    t.equal(ui && ui.token_endpoint_auth_method, 'private_key_jwt',
            'and it is a CONFIDENTIAL client, so its tokens stay on this ' +
            'service');
    t.check(!applications.get(access.RETIRED_API_IDENTIFIER),
            'and there is no separate debugger api application');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== B. an install seeded before #1717 ===');
  inDefault(function () {
    applications.deleteApplication(access.UI_CLIENT_ID, { actor: 'test' });
    // THE TWO ROWS AS THEY WERE SEEDED, by the seed's own writer.
    applications.seedInternalApplication({
      identifier: access.RETIRED_API_IDENTIFIER,
      name: 'Protocol debugger api', kinds: ['oauth2-client'],
      protocols: ['OAuth 2.0'], realmScope: 'default',
      description: 'seeded at startup (test)',
      attributes: { oauthPermissionBaseUri: 'urn:sts:debugger-api:',
                    oauthPermission: ['debugger|Use the debugger'] },
      registration: { client_id: access.RETIRED_API_IDENTIFIER,
                      client_name: 'Protocol debugger api',
                      redirect_uris: [], grant_types: [],
                      response_types: [], scope: '',
                      token_endpoint_auth_method: 'client_secret_basic' } });
    applications.seedInternalApplication({
      identifier: access.UI_CLIENT_ID,
      name: 'Protocol debugger',
      kinds: ['oauth2-client', 'oidc-relying-party'],
      protocols: ['OAuth 2.0 / OIDC'], realmScope: 'default',
      description: 'seeded at startup (test)',
      attributes: { oauthDelegatedPermission: [retired],
                    oauthGlobalConsent: ['openid', 'profile', 'email',
                                         'offline_access', retired] },
      registration: { client_id: access.UI_CLIENT_ID,
                      client_name: 'Protocol debugger',
                      redirect_uris: ['https://localhost:8444/_sts/callback'],
                      grant_types: ['authorization_code', 'refresh_token'],
                      response_types: ['code'],
                      scope: 'openid profile email offline_access ' + retired,
                      token_endpoint_auth_method: 'private_key_jwt' } });
    t.check(!!applications.forPermission(retired) &&
            applications.holdsPermission(access.UI_CLIENT_ID, retired),
            'the precondition: the old api row defines the permission and ' +
            'the client holds it');
    const changed = applications.retireDebuggerApiApplication();
    t.equal(changed, 2, 'both seeded rows are changed');
    t.check(!applications.get(access.RETIRED_API_IDENTIFIER) &&
            !applications.forPermission(retired),
            'the seeded api row is gone, and the permission with it');
    t.check(!applications.holdsPermission(access.UI_CLIENT_ID, retired),
            'and the client no longer holds a grant of it');
    const ui = applications.clientConfigOf(access.UI_CLIENT_ID);
    t.check(ui && String(ui.scope || '').indexOf(retired) < 0,
            'nor declares it', JSON.stringify(ui && ui.scope));
    t.equal(applications.retireDebuggerApiApplication(), 0,
            'and a second start finds nothing to do');
    // A ROW AN OPERATOR MADE under the old name is theirs.
    const made = applications.createApplication({
      identifier: access.RETIRED_API_IDENTIFIER, name: 'Hand made',
      kind: 'oauth2-client', protocols: ['oauth2'],
      fields: { oauthPermissionBaseUri: 'urn:sts:debugger-api:' } });
    t.check(made && made.ok !== false, 'an operator makes a row by hand',
            JSON.stringify(made && made.errors));
    applications.retireDebuggerApiApplication();
    t.check(!!applications.get(access.RETIRED_API_IDENTIFIER),
            'and the retirement leaves it alone');
    applications.deleteApplication(access.RETIRED_API_IDENTIFIER,
                                   { actor: 'test' });
    // Back to what this install seeds now.
    applications.deleteApplication(access.UI_CLIENT_ID, { actor: 'test' });
    applications.seedInternalApplications({ scope: 'default' });
    t.check(!!applications.get(access.UI_CLIENT_ID),
            'the current seed is restored');
  });

  // -------------------------------------------------------------------------
  t.log.info('=== C. isAdministrator(), with an empty and a real roster ===');
  // THE EMPTY ROSTER FIRST, with the console's rule ON: everybody who signs in
  // then holds both console roles, and the debugger must refuse them anyway —
  // rcbj, 2026-09-13. Asserted against the console's own answer, so the
  // refusal is shown to be the debugger's and not a roster that happened to
  // grant nothing.
  withSettings({ 'admin.openWhenEmpty': 'true' }, function () {
    inDefault(function () {
      const consoleRoles = adminRbac.rolesOf('carol');
      t.check(consoleRoles.open === true && consoleRoles.write === true,
              'the precondition: with the roster empty the CONSOLE treats ' +
              'carol as holding Admin Write', JSON.stringify(consoleRoles));
      const answer = access.isAdministrator({ kind: 'user', name: 'carol',
                                              authenticated: true });
      t.check(!answer.allowed && answer.code === 'STS-DBG-0024',
              'and the DEBUGGER refuses her with the empty-roster code — ' +
              'nobody is an administrator of it until somebody is in a group',
              JSON.stringify(answer));
    });
  });
  await withSettings({ 'admin.openWhenEmpty': 'false' }, async function () {
    inDefault(function () {
      t.check(adminRbac.rosterEmpty(),
              'the roster starts empty, which is what makes the next ' +
              'refusal about roles and not about a grant somebody left');
      t.check(!access.isAdministrator({ kind: 'user', name: 'bob',
                                        authenticated: true }).allowed,
              'a person holding no console role is refused — and this ' +
              'process has NO XACML decider, so the policy layer would have ' +
              'said yes to anything');
    });
    const granted = inDefault(function () {
      return adminRbac.grant('alice', 'read', { via: 'test', actor: 'test' });
    });
    t.check(granted && granted.ok !== false,
            'alice is granted Admin Read', JSON.stringify(granted));
    try {
      inDefault(function () {
        t.check(access.isAdministrator({ kind: 'user', name: 'alice',
                                         authenticated: true }).allowed,
                'a console administrator is allowed');
        t.check(!access.isAdministrator({ kind: 'user', name: 'bob',
                                          authenticated: true }).allowed,
                'and somebody else is still refused once a roster exists');
        t.check(!access.isAdministrator({ kind: 'application',
                                          name: 'alice',
                                          authenticated: true }).allowed,
                'an APPLICATION is refused even under an administrator\'s ' +
                'name — people only');
        t.check(!access.isAdministrator({ kind: 'user', name: 'alice',
                                          authenticated: false }).allowed,
                'an administrator who did not authenticate is refused');
      });
    } finally {
      inDefault(function () {
        adminRbac.revoke('alice', 'read', { via: 'test', actor: 'test' });
      });
    }
  });

  // -------------------------------------------------------------------------
  t.log.info('=== D. nothing narrows a debugger permission at issuance ===');
  const oauthSource = fs.readFileSync(path.join(__dirname, '..', 'oauth-oidc',
                                                'oauth2.ts'), 'utf8');
  t.check(oauthSource.indexOf('debugger_access') < 0 &&
          oauthSource.indexOf('debuggerAccess') < 0,
          'oauth2.ts no longer requires debugger_access: the debugger is ' +
          'decided at its gate, not by what a token carries');
  t.check(scopePolicy.protectedScopes().indexOf(retired) < 0,
          'and the scope policy protects no debugger api permission');

  // -------------------------------------------------------------------------
  t.log.info('=== E. the api child\'s allow-list ===');
  t.equal(apiProcess.cidrOrNull('10.1.2.3/32'), '10.1.2.3/32',
          'a CIDR range is a range');
  t.equal(apiProcess.cidrOrNull('10.1.2.3'), null,
          'a bare address is refused rather than widened');
  t.equal(apiProcess.cidrOrNull('10.0.0.0/33'), null,
          'a prefix past the family\'s width is refused');
  t.equal(apiProcess.cidrOrNull('::1/128'), '::1/128', 'IPv6 too');
  const dev = await apiProcess.computeAllowedRanges();
  t.equal(JSON.stringify(dev), '[]',
          'development mode hands the api no allow-list');
  await withSettings({ 'global.mode': 'product' }, async function () {
    const product = await apiProcess.computeAllowedRanges();
    t.check(product.indexOf('127.0.0.0/8') >= 0 &&
            product.indexOf('::1/128') >= 0,
            'product mode allows this service\'s loopback addresses',
            JSON.stringify(product));
    t.check(product.indexOf('203.0.113.0/24') >= 0,
            'and debugger.allowedDestinations', JSON.stringify(product));
    t.check(product.indexOf('not-a-range') < 0 &&
            apiProcess.status().allowListProblems.indexOf('not-a-range') >= 0,
            'and an entry that is not a range is LEFT OUT and reported',
            JSON.stringify(apiProcess.status().allowListProblems));
    t.check(product.indexOf('0.0.0.0/0') < 0 && product.every(function (r) {
      return /\/(8|24|32|128)$/.test(r);
    }), 'and nothing wider than what was named', JSON.stringify(product));
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'debugger_access',
  describe: 'the embedded debugger is one confidential client, the retired ' +
            'api row is removed from an old install, only console ' +
            'administrators pass whatever the policy layer says, and the ' +
            'api child\'s allow-list',
  run: run
};
