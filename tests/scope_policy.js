// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scope_policy.js
//
// ===========================================================================
// WHICH SCOPES A CLIENT MAY BE ISSUED (#110, 2026-09-22).
//
// Five claims, each about `common/scope_policy.ts` and the two places
// `oauth-oidc/oauth2.ts` asks it:
//
//   A. THIS SERVICE'S OWN PROTECTED SCOPES — admin:*, report:use and
//      report:admin, the SCIM scopes (by
//      their SETTINGS, not their default spelling), the Shared Signals
//      scopes (the settings PLUS ssf.read and ssf.manage, which stay
//      protected when a setting is renamed; ssf:read and ssf:write are not
//      Shared Signals scopes, #334),
//      the debugger permission — are refused to a client that does not
//      declare them, IN BOTH MODES, and allowed to one that does; and the
//      seeded clients declare what they use. sts-report declares the two
//      report scopes in every realm, and no resource application defines
//      them as delegated permissions any more (#1030).
//   B. EVERY OTHER SCOPE is issued freely in development, and in product only
//      when the client's `oauthAllowedScope` lists it — or, with no list, when
//      it is in the documented default set; a scope naming an application or
//      a delegated permission is not judged here.
//   C. `tokenSet()` NARROWS — a refresh and an exchange carrying a scope the
//      client may no longer have are issued without it, the `scope` member
//      says so, and an audit row records it.
//   D. DELEGATED PERMISSIONS ARE ENFORCED IN PRODUCT whatever
//      `oauth2.delegatedPermissionsEnforced` says, and in development only
//      when it is on.
//   E. The debugger permission is spelt the same here as in
//      `debugger/debugger_access.ts`.
//   F. FOR THIS SERVICE'S THREE APIS A DELEGATED PERMISSION GRANT IS THE
//      DECLARATION (#1141): an admin, owner, account or report word listed
//      in oauthAllowedScope no
//      longer declares it, a delegated permission grant on the API's object
//      does, and the seeded clients hold the delegated permission grants
//      they use.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS. The truth table needs both modes and a realm's settings in
// one run, and C needs a grant carrying its scope from earlier — which over
// HTTP is a refresh token minted before an allowance was removed. The HTTP
// half — the refusals at the endpoints and the resource servers' re-check —
// is `tests/protocol/sts_scope_policy.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const applications = require('../common/applications');
// Fills the directory slots and seeds the internal applications.
require('../ldap/ldap_server');
const audit = require('../common/audit');
const scopePolicy = require('../common/scope_policy');
const oauth2 = require('../oauth-oidc/oauth2');
const debuggerAccess = require('../debugger/debugger_access');
const realms = require('../common/realms');

const log = require('bunyan').createLogger({ name: 'scope_policy',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'https://sts.scope-policy.test';

async function withSettings(pairs, fn) {
  log.debug("Entering withSettings().");
  const keys = Object.keys(pairs);
  try {
    keys.forEach(function (key) {
      config.setOverride(key, String(pairs[key]));
    });
    log.debug("Leaving withSettings().");
    return await fn();
  } finally {
    keys.forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

function codeOf(refusal) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return refusal ? refusal.code : null;
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const part = String(jwt || '').split('.')[1] || '';
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

function makeApplications(t) {
  log.debug("Entering makeApplications().");
  const made = [
    applications.createApplication({ identifier: 'sp-declared',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'sp-declared',
                oauthAllowedScope: ['openid', 'api:read', 'scim:write'] } }),
    applications.createApplication({ identifier: 'sp-bare',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'sp-bare' } }),
    applications.createApplication({ identifier: 'sp-api',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'sp-api',
                oauthPermissionBaseUri: 'https://sp-api.example/',
                oauthPermission: ['write'] } })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the three applications were created',
          JSON.stringify(made));
  const bad = applications.updateApplication('sp-bare', {
    attribute: 'oauthAllowedScope', mode: 'add', value: 'has space' });
  t.check(!bad.ok, 'a declared scope that is not a scope token is refused',
          JSON.stringify(bad));
  log.debug("Leaving makeApplications().");
}

function claimA(t) {
  log.debug("Entering claimA().");
  t.log.info('=== A. the protected scopes, in both modes ===');
  ['development', 'product'].forEach(function (m) {
    config.setOverride('global.mode', m);
    try {
      t.equal(codeOf(scopePolicy.refusal('admin:write', 'sp-bare')),
              'STS-OAUTH-0577', m + ': admin:write to a client that does ' +
              'not declare it is refused STS-OAUTH-0577');
      t.equal(codeOf(scopePolicy.refusal('scim:read', 'sp-declared')),
              'STS-OAUTH-0577', m + ': scim:read is refused to a client ' +
              'declaring only scim:write');
      t.equal(codeOf(scopePolicy.refusal('scim:write', 'sp-declared')),
              null, m + ': and scim:write, which it declares, is allowed');
      t.equal(codeOf(scopePolicy.refusal('ssf.manage', '')), 'STS-OAUTH-0577',
              m + ': a request naming no client cannot have ssf.manage');
      t.equal(codeOf(scopePolicy.refusal(debuggerAccess.PERMISSION_ID,
                                         'sp-bare')),
              'STS-OAUTH-0577', m + ': nor the debugger permission');
    } finally {
      config.clearOverride('global.mode');
    }
  });
  t.check(scopePolicy.declares('sts-api-client', 'admin:read') &&
          scopePolicy.declares('sts-api-client', 'admin:write'),
          'the seeded sts-api-client declares both admin scopes');
  t.check(scopePolicy.declares('sts-admin-console', 'admin:write'),
          'and so does sts-admin-console, whose explorer mints admin tokens');
  t.check(scopePolicy.isProtected('report:use') &&
          scopePolicy.isProtected('report:admin'),
          'report:use and report:admin are protected, like admin:read and ' +
          'admin:write');
  t.check(scopePolicy.declares('sts-report', 'report:use') &&
          scopePolicy.declares('sts-report', 'report:admin'),
          'the seeded sts-report declares both report scopes');
  t.equal(codeOf(scopePolicy.refusal('report:use', 'sts-report')), null,
          'report:use is allowed to the client that declares it');
  t.equal(codeOf(scopePolicy.refusal('report:admin', 'sp-bare')),
          'STS-OAUTH-0577',
          'report:admin is refused to a client that does not declare it');
  // THE DELEGATED GRANT IS GONE (#1030): no resource application defines
  // the two words, and sts-report holds no grant — the browser asks for
  // the bare words with `resource`, which never consulted one.
  // THE IDENTIFIER CAME BACK AS THE REPORTS API'S RESOURCE OBJECT (#1139),
  // AND THE DELEGATED PERMISSION GRANT CAME BACK AS THE CLIENT'S HALF
  // (#1141): sts-report-api
  // defines both words under urn:sts:report-api:, sts-report holds delegated
  // permission grants of both, and since #1141 a bare word with `resource`
  // DOES consult the delegated permission grant
  // (`scope_policy.ts`'s `declares()`), which is what #1030 found missing.
  const reportApi = applications.get('sts-report-api');
  const reportClient = applications.get('sts-report');
  const held = [].concat((reportClient && reportClient.fields || {})
    .oauthDelegatedPermission || []);
  t.check(!!reportApi &&
          reportApi.kinds.indexOf('oauth2-resource-server') >= 0 &&
          String((reportApi.fields || {}).oauthPermissionBaseUri) ===
            'urn:sts:report-api:' &&
          held.indexOf('urn:sts:report-api:report:use') >= 0 &&
          held.indexOf('urn:sts:report-api:report:admin') >= 0,
          'sts-report-api defines the report permissions and sts-report ' +
          'holds delegated permission grants of both (#1141)',
          JSON.stringify([reportApi && reportApi.fields, held]));
  const made = realms.get('report-api-seed') ||
    realms.create({ id: 'report-api-seed', name: 'report-api-seed' });
  t.check(made && (made.ok || made.id),
          'a realm can be created to see the every-realm seed',
          JSON.stringify(made));
  realms.run(realms.get('report-api-seed'), function () {
    t.check(!!applications.get('sts-report') &&
            !!applications.get('sts-report-api') &&
            !applications.get('sts-debugger-api'),
            'a new realm gets the reports client and the reports API\'s ' +
            'resource object (#1139), and not the debugger');
    t.check(scopePolicy.declares('sts-report', 'report:use') &&
            scopePolicy.declares('sts-report', 'report:admin'),
            'and that realm\'s sts-report declares both report scopes');
  });
  config.setOverride('scim.scopeWrite', 'prov:write');
  try {
    t.check(scopePolicy.isProtected('prov:write') &&
            !scopePolicy.isProtected('scim:write'),
            'the SCIM scope is protected by its SETTING\'s name, not its ' +
            'default spelling');
  } finally {
    config.clearOverride('scim.scopeWrite');
  }
  t.check(oauth2.protectedScopes().indexOf('ssf.read') >= 0 &&
          oauth2.protectedScopes().indexOf('ssf.manage') >= 0 &&
          oauth2.protectedScopes().indexOf('ssf:read') < 0,
          'oauth2.ts asks the same list: the profile names, and not ssf:read');
  t.check(scopePolicy.isProtected('ssf.read') &&
          scopePolicy.isProtected('ssf.manage') &&
          !scopePolicy.isProtected('ssf:read') &&
          !scopePolicy.isProtected('ssf:write'),
          'ssf.read and ssf.manage are protected, and ssf:read and ' +
          'ssf:write are not');
  config.setOverride('ssf.authScopeRead', 'custom:read');
  try {
    t.check(scopePolicy.isProtected('custom:read') &&
            scopePolicy.isProtected('ssf.read') &&
            scopePolicy.isProtected('ssf.manage') &&
            !scopePolicy.isProtected('ssf:read'),
            'renaming ssf.authScopeRead adds a name and unprotects neither ' +
            'fixed name');
  } finally {
    config.clearOverride('ssf.authScopeRead');
  }
  log.debug("Leaving claimA().");
}

function claimB(t) {
  log.debug("Entering claimB().");
  t.log.info('=== B. every other scope ===');
  t.equal(codeOf(scopePolicy.refusal('anything:custom', 'sp-bare')), null,
          'development: an undeclared custom scope is issued');
  t.equal(codeOf(scopePolicy.refusal('ssf:write', '')), null,
          'development: ssf:write is an ordinary scope and is issued');
  config.setOverride('global.mode', 'product');
  try {
    t.equal(codeOf(scopePolicy.refusal('openid profile email', 'sp-bare')),
            null, 'product, no list: OIDC scopes are the default set');
    t.equal(codeOf(scopePolicy.refusal('anything:custom', 'sp-bare')),
            'STS-OAUTH-0578', 'product, no list: a custom scope is refused ' +
            'STS-OAUTH-0578');
    t.equal(codeOf(scopePolicy.refusal('ssf:write', '')), 'STS-OAUTH-0578',
            'product, no list: ssf:write is not a default scope');
    t.equal(codeOf(scopePolicy.refusal('vc:scope', 'sp-bare',
                                       { defaults: ['vc:scope'] })), null,
            'product, no list: the caller\'s defaults (OpenID4VCI) are in ' +
            'the set');
    t.equal(codeOf(scopePolicy.refusal('openid api:read', 'sp-declared')),
            null, 'product, a list: what it lists is issued');
    t.equal(codeOf(scopePolicy.refusal('profile', 'sp-declared')),
            'STS-OAUTH-0578', 'product, a list: the default set does not ' +
            'apply — profile is not on it');
    t.equal(codeOf(scopePolicy.refusal('https://sp-api.example/write sp-api',
                                       'sp-bare')), null,
            'product: a permission and another application\'s client_id ' +
            'keep their own rules');
    const refused = oauth2.scopeRefusal('anything:custom', 'sp-bare');
    t.check(refused && refused.error === 'invalid_scope' &&
            /oauthAllowedScope/.test(refused.description),
            'oauth2.scopeRefusal() answers invalid_scope and names the ' +
            'attribute', JSON.stringify(refused));
  } finally {
    config.clearOverride('global.mode');
  }
  log.debug("Leaving claimB().");
}

async function claimC(t) {
  log.debug("Entering claimC().");
  t.log.info('=== C. tokenSet() narrows a grant carrying its scope ===');
  const refreshed = await oauth2.tokenSet(BASE, {
    client_id: 'sp-declared', grant: 'refresh_token', withRefresh: false,
    scope: 'api:read admin:write', sub: 'sp-user', username: 'sp-user',
    user: { username: 'sp-user', sub: 'sp-user' } });
  t.equal(refreshed.scope, 'api:read',
          'a refresh carrying admin:write from a client that does not ' +
          'declare it is issued without it, and `scope` says so');
  t.equal(claimsOf(refreshed.access_token).scope, 'api:read',
          'and the access token does not carry it');
  // Newest first, and the only row of its kind this file writes.
  const rows = audit.list().filter(function (row) {
    return row.errorCode === 'STS-OAUTH-0579' &&
           JSON.stringify(row).indexOf('sp-declared') >= 0;
  });
  t.check(rows.length === 1 && /admin:write/.test(JSON.stringify(rows[0])),
          'one audit row records what was taken off (STS-OAUTH-0579)',
          JSON.stringify(rows));
  await withSettings({ 'global.mode': 'product' }, async function () {
    const exchanged = await oauth2.tokenSet(BASE, {
      client_id: 'sp-declared', withRefresh: false,
      grant: 'urn:ietf:params:oauth:grant-type:token-exchange',
      scope: 'api:read other:inherited', sub: 'sp-user',
      username: 'sp-user', user: { username: 'sp-user', sub: 'sp-user' } });
    t.equal(exchanged.scope, 'api:read', 'product: an exchange inheriting ' +
            'a scope the client never declared is issued without it');
  });
  const untouched = await oauth2.tokenSet(BASE, {
    client_id: 'sp-bare', grant: 'client_credentials', withRefresh: false,
    scope: 'anything:custom', sub: 'sp-bare', username: 'sp-bare',
    user: { username: 'sp-bare', sub: 'sp-bare' } });
  t.equal(untouched.scope, 'anything:custom',
          'development: an ordinary undeclared scope is left alone');
  log.debug("Leaving claimC().");
}

function claimD(t) {
  log.debug("Entering claimD().");
  t.log.info('=== D. delegated permissions ===');
  const asked = 'https://sp-api.example/write';
  t.equal(oauth2.permissionRefusal(asked, 'sp-bare'), '',
          'development, setting off: an ungranted permission is honoured');
  config.setOverride('oauth2.delegatedPermissionsEnforced', 'true');
  try {
    t.check(!!oauth2.permissionRefusal(asked, 'sp-bare'),
            'development, setting on: it is refused');
  } finally {
    config.clearOverride('oauth2.delegatedPermissionsEnforced');
  }
  config.setOverride('global.mode', 'product');
  try {
    const refused = oauth2.permissionRefusal(asked, 'sp-bare');
    t.check(!!refused && /Product mode/.test(refused),
            'product, setting off: it is refused all the same', refused);
  } finally {
    config.clearOverride('global.mode');
  }
  log.debug("Leaving claimD().");
}

// F (#1141): for this service's three APIs a delegated permission grant on
// the API's object is the client's half, and oauthAllowedScope is not.
function claimF(t) {
  log.debug("Entering claimF().");
  t.log.info('=== F. a delegated permission grant is the declaration for ' +
             'an API scope ===');
  const made = [
    applications.createApplication({ identifier: 'sp-listed',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'sp-listed',
                oauthAllowedScope: ['openid', 'admin:read', 'report:use',
                                    'account:manage'] } }),
    applications.createApplication({ identifier: 'sp-delegated',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'sp-delegated',
                oauthAllowedScope: ['openid'],
                oauthDelegatedPermission: ['urn:sts:admin-api:admin:read',
                  'urn:sts:report-api:report:use',
                  'urn:sts:account-api:account:manage'] } })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: a listing client and one holding delegated ' +
          'permission grants',
          JSON.stringify(made));
  ['admin:read', 'report:use', 'account:manage'].forEach(function (one) {
    t.check(!scopePolicy.declares('sp-listed', one) &&
            codeOf(scopePolicy.refusal(one, 'sp-listed')) ===
              'STS-OAUTH-0577',
            'F. listing ' + one + ' in oauthAllowedScope no longer declares ' +
            'it: refused STS-OAUTH-0577');
    t.check(scopePolicy.declares('sp-delegated', one) &&
            codeOf(scopePolicy.refusal(one, 'sp-delegated')) === null,
            'F. a delegated permission grant of ' + one + ' on its API\'s ' +
            'object declares it');
  });
  t.check(!scopePolicy.declares('sp-delegated', 'admin:write') &&
          !scopePolicy.declares('sp-delegated', 'report:admin'),
          'F. a delegated permission grant declares the permission it names ' +
          'and no other');
  const listed = scopePolicy.declaredScopes('sp-listed') || [];
  t.check(listed.join() === 'openid',
          'F. declaredScopes() leaves the words a delegated permission grant ' +
          'governs off the list',
          JSON.stringify(listed));
  const apiOf = function (scope) {
    log.debug("Entering apiOf().");
    log.debug("Leaving apiOf().");
    return scopePolicy.delegatedPermissionApiOf(scope);
  };
  t.check(apiOf('owner:write') === 'sts-management-api' &&
          apiOf('account:manage') === 'sts-account-api' &&
          apiOf('report:admin') === 'sts-report-api' &&
          apiOf('scim:write') === '',
          'F. each word a delegated permission grant governs belongs to its ' +
          'API, and the SCIM scopes are not among them');
  t.check(['sts-admin-console', 'sts-user-portal', 'sts-report',
           'sts-api-client'].every(function (id) {
    return (scopePolicy.declaredScopes(id) || []).every(function (one) {
      return !scopePolicy.delegatedPermissionApiOf(one);
    });
  }) && scopePolicy.declares('sts-user-portal', 'account:manage') &&
          scopePolicy.declares('sts-user-portal', 'owner:write') &&
          scopePolicy.declares('sts-admin-console', 'admin:console') &&
          scopePolicy.declares('sts-api-client', 'report:use') &&
          !scopePolicy.declares('sts-api-client', 'report:admin'),
          'F. the seeded clients list none of these words and hold the ' +
          'delegated permission grants they use');
  log.debug("Leaving claimF().");
}

async function run(t) {
  log.debug("Entering run().");
  makeApplications(t);
  claimA(t);
  claimB(t);
  await claimC(t);
  claimD(t);
  claimF(t);
  t.log.info('=== E. one spelling ===');
  t.equal(scopePolicy.DEBUGGER_PERMISSION, debuggerAccess.PERMISSION_ID,
          'the debugger permission is spelt as debugger_access.ts spells it');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'scope_policy',
  describe: 'a scope is tied to the client: protected scopes in both modes, ' +
            'every other scope in product, the tokenSet() backstop, and ' +
            'delegated permissions enforced in product',
  run: run
};
