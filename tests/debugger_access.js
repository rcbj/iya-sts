'use strict';
//
// File: debugger_access.js
//
// ===========================================================================
// WHO MAY BE GRANTED THE EMBEDDED DEBUGGER'S PERMISSION, AND WHAT ITS API MAY
// DIAL (2026-09-13).
//
// Five claims:
//
//   A. the permission, the client id and the resource identifier are ONE
//      spelling in the three files that write them — `debugger_access.js`,
//      `common/applications.js`'s seed and `common/oidc_rp.ts`'s surface — and
//      the seeded entries define and grant it;
//   B. `narrowScope()` takes the permission off for somebody who is not a
//      console administrator, for an application, for an unauthenticated
//      subject and in any realm but the default one, and leaves every other
//      scope value exactly as it was;
//   C. the POLICY CANNOT WIDEN IT: with no XACML decider loaded —
//      `access_gate.js` then answers "allowed" to everything — a subject
//      holding neither console role is still refused;
//   D. `oauth2.js` asks it at both places a scope is granted: the authorization
//      endpoint and `tokenSet()`, which every grant mints through;
//   E. in product mode the api child's allow-list is this service's own
//      addresses plus `debugger.allowedDestinations`, and an entry that is not
//      a CIDR range is left out and reported rather than widened.
//
// ---------------------------------------------------------------------------
// WHY IN PROCESS. B and C are about a SCOPE BEING ABSENT from a grant, for a
// roster and a mode a running stack cannot be put into without editing its
// directory; D is a property of the source; E needs product mode and a
// setting that is restart-only.
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
  const id = access.PERMISSION_ID;

  // -------------------------------------------------------------------------
  t.log.info('=== A. one spelling, and the seeded entries ===');
  t.equal(id, 'urn:sts:debugger-api:debugger', 'the permission identifier');
  const appsSource = fs.readFileSync(path.join(__dirname, '..', 'common',
                                               'applications.js'), 'utf8');
  t.check(appsSource.indexOf("'" + id + "'") >= 0 &&
          appsSource.indexOf("'" + access.PERMISSION_BASE + "'") >= 0 &&
          appsSource.indexOf("'" + access.UI_CLIENT_ID + "'") >= 0 &&
          appsSource.indexOf("'" + access.API_IDENTIFIER + "'") >= 0,
          'common/applications.js seeds the same permission, base, client ' +
          'and resource the debugger checks');
  const surface = oidcRp.surfaceOf('debugger');
  t.equal(surface.clientId, access.UI_CLIENT_ID,
          'the oidc_rp surface signs in as the seeded client');
  t.check(surface.scopes.indexOf(id) >= 0,
          'and asks for the permission', JSON.stringify(surface.scopes));
  inDefault(function () {
    const found = applications.forPermission(id);
    t.check(found && found.identifier === access.API_IDENTIFIER &&
            found.baseUri === access.PERMISSION_BASE,
            'the seeded api entry DEFINES the permission, under a URN base ' +
            'that becomes the token\'s audience',
            JSON.stringify(found && { identifier: found.identifier,
                                      baseUri: found.baseUri }));
    t.check(applications.holdsPermission(access.UI_CLIENT_ID, id),
            'and the seeded UI entry is GRANTED it — the application-to-' +
            'permission mapping');
    const ui = applications.clientConfigOf(access.UI_CLIENT_ID);
    t.check(ui && ui.registered &&
            (ui.redirect_uris || []).some(function (uri) {
              return /\/_sts\/callback$/.test(uri);
            }),
            'with its sign-in callback on the debugger listener',
            JSON.stringify(ui && ui.redirect_uris));
  });

  // -------------------------------------------------------------------------
  t.log.info('=== B and C. narrowing, with an empty and a real roster ===');
  const scope = 'openid profile ' + id + ' email';
  const narrowed = 'openid profile email';
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
      t.equal(access.narrowScope(scope, { kind: 'user', name: 'carol',
                                          authenticated: true }, {}),
              narrowed,
              'so the authorization server leaves the permission off her ' +
              'token');
    });
  });
  await withSettings({ 'admin.openWhenEmpty': 'false' }, async function () {
    inDefault(function () {
      t.check(adminRbac.rosterEmpty(),
              'the roster starts empty, which is what makes the next ' +
              'refusal about roles and not about a grant somebody left');
      t.equal(access.narrowScope(scope, { kind: 'user', name: 'bob',
                                          authenticated: true }, {}),
              narrowed,
              'C: a person holding no console role loses the permission — ' +
              'and this process has NO XACML decider, so the policy layer ' +
              'would have said yes to anything');
    });
    const granted = inDefault(function () {
      return adminRbac.grant('alice', 'read', { via: 'test', actor: 'test' });
    });
    t.check(granted && granted.ok !== false,
            'alice is granted Admin Read', JSON.stringify(granted));
    try {
      inDefault(function () {
        t.equal(access.narrowScope(scope, { kind: 'user', name: 'alice',
                                            authenticated: true }, {}),
                scope,
                'B: a console administrator keeps the whole scope, in its ' +
                'order');
        t.equal(access.narrowScope(scope, { kind: 'user', name: 'bob',
                                            authenticated: true }, {}),
                narrowed,
                'and somebody else still loses it once a roster exists');
        t.equal(access.narrowScope(scope, { kind: 'application',
                                            name: 'alice',
                                            authenticated: true }, {}),
                narrowed,
                'an APPLICATION loses it even under an administrator\'s ' +
                'name — people only');
        t.equal(access.narrowScope(scope, { kind: 'user', name: 'alice',
                                            authenticated: false }, {}),
                narrowed,
                'an administrator who did not authenticate loses it');
        t.equal(access.narrowScope('openid profile', { kind: 'user',
                                                       name: 'bob' }, {}),
                'openid profile',
                'a scope that does not name the permission is untouched');
        t.check(access.isAdministrator({ kind: 'user', name: 'alice' })
                  .allowed,
                'isAdministrator() agrees for the gate');
      });
      // AN AMBIENT REALM AND NOT A CREATED ONE: creating a realm fires
      // `pki.js`'s watcher, which builds the service Root in the background,
      // and a later file in this process (tests/pki.js) builds its own Root
      // and asserts on its subject. The rule reads `realms.currentId()` and
      // nothing else, so an ambient record is the whole of what it needs.
      realms.run({ id: 'dbgtest', name: 'dbgtest' }, function () {
        t.equal(access.narrowScope(scope, { kind: 'user', name: 'alice',
                                            authenticated: true }, {}),
                narrowed,
                'in any realm but the default one the permission is taken ' +
                'off — a person there who shares an administrator\'s name ' +
                'is somebody else');
      });
    } finally {
      inDefault(function () {
        adminRbac.revoke('alice', 'read', { via: 'test', actor: 'test' });
      });
    }
  });

  // -------------------------------------------------------------------------
  t.log.info('=== D. oauth2.js asks at both grant points ===');
  const oauthSource = fs.readFileSync(path.join(__dirname, '..', 'oauth-oidc',
                                                'oauth2.ts'), 'utf8');
  const tokenSetBody = oauthSource.slice(oauthSource.indexOf(
    'async tokenSet('), oauthSource.indexOf(
    'async tokenSet(') + 4000);
  t.check(/debuggerAccess\.narrowScope\(\s*opts\.scope/.test(tokenSetBody) &&
          tokenSetBody.indexOf('debuggerAccess.narrowScope') <
            tokenSetBody.indexOf('accessTokenPlan('),
          'tokenSet() narrows opts.scope before the access token plan reads ' +
          'it, so no grant mints the permission for somebody who may not ' +
          'hold it');
  const responseBody = oauthSource.slice(oauthSource.indexOf(
    'async issueAuthorizationResponse('), oauthSource.indexOf(
    'async issueAuthorizationResponse(') + 3000);
  t.check(/const scope = debuggerAccess\.narrowScope\(/.test(responseBody),
          'and the authorization endpoint narrows before a code carries it');

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
  describe: 'the embedded debugger\'s permission: one spelling, issued to ' +
            'console administrators only whatever the policy layer says, ' +
            'narrowed at both grant points, and the api child\'s allow-list',
  run: run
};
