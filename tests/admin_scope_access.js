// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: admin_scope_access.js
//
// ===========================================================================
// admin:read AND admin:write GO WITH THE PERSON'S CONSOLE ROLES (#302, part
// A of #88, 2026-09-27).
//
// Claims, each about `mgmt-api/admin_scope_access.ts` and the backstop in
// `oauth-oidc/oauth2.ts`'s `tokenSet()`:
//
//   A. While the realm's console is OPEN (development, empty roster), a
//      person is issued both — the console admits them, and rule 7 makes the
//      API its machine door.
//   B. Once the roster names somebody, a person holding no role is issued
//      neither, a holder of Admin Read only `admin:read`, a holder of Admin
//      Write both; the rest of the scope is untouched, and one audit row
//      (STS-ADMIN-0821) records what was taken off.
//   C. A request asking for NOTHING but admin scopes the person may not hold
//      is refused `invalid_scope` (STS-ADMIN-0822, #88 decision 2).
//   D. An application (`client_credentials`) is left alone until #303.
//   E. The roster asked is the AMBIENT realm's, a subject who did not
//      authenticate holds nothing, and the bootstrap administrator before
//      its claim is not issued them (stubbed roster).
//   F. `/admin-api`'s re-check: a person's token keeps only the admin scopes
//      their roles authorize NOW, in the realm that issued it; a client's own
//      token (both spellings of its `sub`) passes through.
//
// ---------------------------------------------------------------------------
// IN A THROWAWAY REALM, because `run.js` runs every file in one process and
// the default realm's roster is shared: a grant there would close the
// console for every file after this one. A realm's roster is its own (#32).
// The authorization endpoint's half — the redirect with invalid_scope — is
// the same `narrowScope()` answer and is left to the HTTP suite.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const applications = require('../common/applications');
// Fills the directory slots, and so the roster's.
const ldap = require('../ldap/ldap_server');
const audit = require('../common/audit');
const adminRbac = require('../admin-ui/admin_rbac');
const oauth2 = require('../oauth-oidc/oauth2');
const adminScopeAccess = require('../mgmt-api/admin_scope_access');

const log = require('bunyan').createLogger({ name: 'admin_scope_access',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'https://sts.admin-scope-access.test';
const RUN = nodeCrypto.randomBytes(3).toString('hex');
const CLIENT = 'asa-client-' + RUN;
const ASKED = 'openid admin:read admin:write';

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const part = String(jwt || '').split('.')[1] || '';
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

// A refresh for `name`: a grant carrying its scope from earlier, which is
// what reaches tokenSet() without the authorization endpoint's narrowing.
function refresh(name, scope) {
  log.debug("Entering refresh(). " + name);
  log.debug("Leaving refresh().");
  return oauth2.tokenSet(BASE, {
    client_id: CLIENT, grant: 'refresh_token', withRefresh: false,
    scope: scope, sub: name, username: name,
    user: { username: name, sub: name } });
}

function narrowedRows(name) {
  log.debug("Entering narrowedRows().");
  log.debug("Leaving narrowedRows().");
  return audit.list().filter(function (row) {
    return row.errorCode === adminScopeAccess.NARROWED_CODE &&
           row.actor === name;
  });
}

async function inRealm(t, realm) {
  log.debug("Entering inRealm().");
  const made = applications.createApplication({ identifier: CLIENT,
    protocols: ['oauth2'],
    fields: { oauthClientId: CLIENT,
              oauthAllowedScope: ['openid', 'admin:read', 'admin:write'] } });
  t.check(made && made.ok, 'precondition: the client declares both scopes',
          JSON.stringify(made));
  const NOBODY = 'asa-nobody-' + RUN;
  const READER = 'asa-reader-' + RUN;
  const WRITER = 'asa-writer-' + RUN;
  [NOBODY, READER, WRITER].forEach(function (name) {
    ldap.createUser(name, { invent: false, attributes: {} });
  });

  t.log.info('=== A. the open console ===');
  const open = await refresh(NOBODY, ASKED);
  t.equal(open.scope, ASKED,
          'A1. with nobody on the realm\'s roster, a person is issued both');

  t.log.info('=== B. the roster decides ===');
  const g1 = adminRbac.grant(WRITER, 'write', { via: 'test', realm: realm.id });
  const g2 = adminRbac.grant(READER, 'read', { via: 'test', realm: realm.id });
  t.check(g1 && g1.ok && g2 && g2.ok, 'precondition: the two grants took',
          JSON.stringify([g1, g2]));
  const nobody = await refresh(NOBODY, ASKED);
  t.equal(nobody.scope, 'openid',
          'B1. a person holding no role is issued neither admin scope');
  t.equal(claimsOf(nobody.access_token).scope, 'openid',
          'B2. and the access token does not carry them');
  const rows = narrowedRows(NOBODY);
  t.check(rows.length === 1 && /admin:read admin:write/.test(
    JSON.stringify(rows[0].detail || rows[0])),
          'B3. one audit row records what was taken off (STS-ADMIN-0821)',
          JSON.stringify(rows));
  const reader = await refresh(READER, ASKED);
  t.equal(reader.scope, 'openid admin:read',
          'B4. Admin Read is issued admin:read and not admin:write');
  const writer = await refresh(WRITER, ASKED);
  t.equal(writer.scope, ASKED,
          'B5. Admin Write (which implies Admin Read) is issued both');

  t.log.info('=== C. nothing left ===');
  let refused = null;
  try {
    await refresh(READER, 'admin:write');
  } catch (e) {
    log.debug("Caught in inRealm(): " + ((e && e.message) || e));
    refused = e;
  }
  t.check(!!refused && refused.name === 'AccessTokenRefused' &&
          refused.refusal.error === 'invalid_scope',
          'C1. only admin:write, for a holder of Admin Read, is invalid_scope',
          refused ? refused.name + ' ' + JSON.stringify(refused.refusal)
                  : 'not refused');

  t.log.info('=== D. an application ===');
  const machine = adminScopeAccess.narrowScope(ASKED,
    { kind: 'application', name: CLIENT, authenticated: true },
    { clientId: CLIENT, grant: 'client_credentials' });
  t.equal(machine.scope, ASKED,
          'D1. a client_credentials subject is left alone (#303 decides it)');

  t.log.info('=== E. the realm, and the unauthenticated ===');
  const unauthenticated = adminScopeAccess.narrowScope(ASKED,
    { kind: 'user', name: WRITER, authenticated: false }, {});
  t.equal(unauthenticated.scope, 'openid',
          'E1. a subject who did not authenticate holds nothing');

  t.log.info('=== F. the re-check on every call ===');
  const both = ['admin:read', 'admin:write'];
  const person = function (name) {
    return { sub: 'urn:uuid:' + name, username: name, client_id: CLIENT };
  };
  // Asked from the DEFAULT realm, naming the throwaway one as the token's:
  // the roster asked is the issuing realm's, not the one the call is in.
  const fromDefault = function (fn) {
    return realms.run(realms.get(realms.DEFAULT_ID), fn);
  };
  const r1 = fromDefault(function () {
    return adminScopeAccess.recheck(person(READER), both, realm.id);
  });
  t.check(r1.kept.join(' ') === 'admin:read' &&
          r1.withdrawn.join(' ') === 'admin:write',
          'F1. a holder of Admin Read keeps admin:read and loses admin:write',
          JSON.stringify(r1));
  adminRbac.revoke(READER, 'read', { via: 'test', realm: realm.id });
  const r2 = fromDefault(function () {
    return adminScopeAccess.recheck(person(READER), both, realm.id);
  });
  t.check(r2.kept.length === 0 && r2.withdrawn.length === 2,
          'F2. once the role is revoked, the token they already hold loses both',
          JSON.stringify(r2));
  const r3 = adminScopeAccess.recheck(person(WRITER), both, realm.id);
  t.equal(r3.kept.join(' '), 'admin:read admin:write',
          'F3. a holder of Admin Write keeps both');
  const bare = adminScopeAccess.recheck(
    { sub: CLIENT, client_id: CLIENT, username: CLIENT }, both, realm.id);
  const urn = adminScopeAccess.recheck(
    { sub: 'urn:sts:client:' + CLIENT, client_id: CLIENT }, both, realm.id);
  t.check(bare.kept.length === 2 && urn.kept.length === 2,
          'F4. a client\'s own token passes through, in either spelling of ' +
          'its subject', JSON.stringify([bare, urn]));
  log.debug("Leaving inRealm().");
}

// The roster stubbed, for the two answers a live directory cannot give in
// one process without seeding the default realm.
function stubbed(t) {
  log.debug("Entering stubbed().");
  const asked = [];
  const make = function (answer) {
    return new adminScopeAccess.AdminScopeAccess({
      log: log, realms: realms, audit: audit,
      adminRbac: /** @type {any} */ ({
        rolesOf: function (name, realmId) {
          asked.push(realmId);
          return answer;
        } }) });
  };
  const pending = make({ read: true, write: true, roles: ['read', 'write'],
                         claimPending: true });
  const out = pending.narrowScope(ASKED,
    { kind: 'user', name: 'admin', authenticated: true }, {});
  t.equal(out.scope, 'openid',
          'E2. the bootstrap administrator before its claim is issued neither');
  t.check(/claimed/.test(out.why), 'E3. and the reason says so', out.why);
  t.equal(asked[0], realms.currentId(),
          'E4. the roster asked is the ambient realm\'s');
  log.debug("Leaving stubbed().");
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.create({ id: 'asa-' + RUN,
                                name: 'admin scope access ' + RUN }).realm;
  await realms.run(realm, async function () {
    await inRealm(t, realm);
    stubbed(t);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin_scope_access',
  describe: 'admin:read and admin:write are issued to a person only as far ' +
            'as their console roles in the realm go (#302)',
  run: run
};
