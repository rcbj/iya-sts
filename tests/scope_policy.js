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
//   A. THIS SERVICE'S OWN PROTECTED SCOPES — admin:*, the SCIM and Shared
//      Signals scopes (by their SETTINGS, not their default spelling), the
//      debugger permission — are refused to a client that does not declare
//      them, IN BOTH MODES, and allowed to one that does; and the seeded
//      clients declare what they use.
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
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS. The truth table needs both modes and a realm's settings in
// one run, and C needs a grant carrying its scope from earlier — which over
// HTTP is a refresh token minted before an allowance was removed. The HTTP
// half — the refusals at the endpoints and the resource servers' re-check —
// is `tests/vendored/sts_scope_policy.js`.
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
      t.equal(codeOf(scopePolicy.refusal('ssf:write', '')), 'STS-OAUTH-0577',
              m + ': a request naming no client cannot have ssf:write');
      t.equal(codeOf(scopePolicy.refusal(debuggerAccess.PERMISSION_ID,
                                         'sp-bare')),
              'STS-OAUTH-0577', m + ': nor the debugger permission');
    } finally {
      config.clearOverride('global.mode');
    }
  });
  t.check(scopePolicy.declares('sts-management-api', 'admin:read') &&
          scopePolicy.declares('sts-management-api', 'admin:write'),
          'the seeded sts-management-api declares both admin scopes');
  t.check(scopePolicy.declares('sts-admin-console', 'admin:write'),
          'and so does sts-admin-console, whose explorer mints admin tokens');
  config.setOverride('scim.scopeWrite', 'prov:write');
  try {
    t.check(scopePolicy.isProtected('prov:write') &&
            !scopePolicy.isProtected('scim:write'),
            'the SCIM scope is protected by its SETTING\'s name, not its ' +
            'default spelling');
  } finally {
    config.clearOverride('scim.scopeWrite');
  }
  t.check(oauth2.protectedScopes().indexOf('ssf:read') >= 0,
          'oauth2.ts asks the same list');
  log.debug("Leaving claimA().");
}

function claimB(t) {
  log.debug("Entering claimB().");
  t.log.info('=== B. every other scope ===');
  t.equal(codeOf(scopePolicy.refusal('anything:custom', 'sp-bare')), null,
          'development: an undeclared custom scope is issued');
  config.setOverride('global.mode', 'product');
  try {
    t.equal(codeOf(scopePolicy.refusal('openid profile email', 'sp-bare')),
            null, 'product, no list: OIDC scopes are the default set');
    t.equal(codeOf(scopePolicy.refusal('anything:custom', 'sp-bare')),
            'STS-OAUTH-0578', 'product, no list: a custom scope is refused ' +
            'STS-OAUTH-0578');
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

async function run(t) {
  log.debug("Entering run().");
  makeApplications(t);
  claimA(t);
  claimB(t);
  await claimC(t);
  claimD(t);
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
