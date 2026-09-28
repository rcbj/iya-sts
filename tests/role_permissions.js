// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: role_permissions.js
//
// ===========================================================================
// A SCOPE IS A REQUEST; A ROLE IS WHAT AUTHORIZES IT (#302, #303 — parts A
// and B of #88, 2026-09-27).
//
// Claims, about `common/role_permissions.ts`, `common/roles.js`'s console
// roles and `rolePermission`, `common/applications.js`'s
// `oauthRoleGatedPermission`, the role actions, the `tokenSet()` backstop and
// the XACML PIP's role designator:
//
//   A. THE CONSOLE ROLES. A realm is seeded with ADMIN_READ and ADMIN_WRITE,
//      configured, each held by sts-management-api and authorizing its own
//      admin scope; people and groups cannot be written onto them, their
//      permission cannot be changed, and they cannot be deleted.
//   B. A PERSON AND admin:*. While the realm's console is open, both; once
//      the roster names somebody, a person with no role is issued neither,
//      Admin Read admin:read only, Admin Write both — one audit row
//      (STS-ADMIN-0821) for what was taken off, and invalid_scope when
//      nothing else was asked for.
//   C. AN APPLICATION AND admin:*. A client that is not in the roles is
//      issued neither on client_credentials, whatever it declares; added to
//      ADMIN_READ, admin:read.
//   D. A GATED APPLICATION PERMISSION. Ungated, issued as before; gated,
//      only to a holder of a role naming it, person or application. The
//      actions refuse a native permission, an undefined one and a console
//      role, and oauthRoleGatedPermission refuses a name the entry does not
//      define.
//   E. HELD ∩ CARRIED. effectiveRoles() keeps a held role only where the
//      token carries what it authorizes, and reports a carried gated
//      permission no held role authorizes any longer — for a person's token
//      and a client's, in the realm that issued it.
//   F. THE PIP. The role designator answers a person's and an application's
//      configured roles, told apart by the subject-kind attribute, and the
//      bootstrap administrator before its claim holds no console role
//      (stubbed roster).
//   G. THE POLICY DECIDES (#304, part C of #88). The issuance request carries
//      the requested scopes, the client, the grant type and the protocol; a
//      scope's verdict comes out of the issuance policy's obligation — an
//      operator's own rule can drop an ungated scope with its own code — and
//      where no verdict comes (an override built without the scope rules,
//      xacml.enabled off) the BUILT-IN policy decides, so gating never
//      switches off — and with no decider at all the gate evaluates the
//      built-in policy itself (#305).
//
// IN A THROWAWAY REALM, for the reason #302's test was: `run.js` runs every
// file in one process, and a grant on the default realm's roster would
// close the console for every file after this one.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const applications = require('../common/applications');
// Fills the directory slots, and so the roster's and the role register's.
const ldap = require('../ldap/ldap_server');
const audit = require('../common/audit');
const roles = require('../common/roles');
const adminRbac = require('../admin-ui/admin_rbac');
const adminActions = require('../admin-core/admin_actions');
const oauth2 = require('../oauth-oidc/oauth2');
const rolePermissions = require('../common/role_permissions');
const pip = require('../xacml/xacml_pip');
const model = require('../xacml/xacml_model');
const datatypes = require('../xacml/xacml_datatypes');
const gate = require('../common/issuance_gate');
const config = require('../common/config');
const xacmlStore = require('../xacml/xacml_store');
const xml = require('../xacml/xacml_xml');
const templates = require('../xacml/xacml_templates');
// THE ISSUANCE PEP, which the per-scope question is answered by since #304.
// Requiring it installs it as the gate's decider; `run()` puts back whatever
// was there, because every file in `run.js`'s one process shares the gate.
const deciderBefore = gate.deciderInstalled();
const rolePep = require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'role_permissions',
  level: process.env.LOG_LEVEL || 'info' });

const BASE = 'https://sts.role-permissions.test';
const RUN = nodeCrypto.randomBytes(3).toString('hex');
const CLIENT = 'rp-client-' + RUN;
const MACHINE = 'rp-machine-' + RUN;
const RESOURCE = 'rp-api-' + RUN;
const RESOURCE_BASE = 'https://rp-api-' + RUN + '.example/';
const PERMISSION = RESOURCE_BASE + 'read';
const ADMIN = 'openid admin:read admin:write';

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  const part = String(jwt || '').split('.')[1] || '';
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

// A refresh for a person: a grant carrying its scope from earlier, which is
// what reaches tokenSet() without the authorization endpoint's narrowing.
function refresh(name, scope) {
  log.debug("Entering refresh(). " + name);
  log.debug("Leaving refresh().");
  return oauth2.tokenSet(BASE, {
    client_id: CLIENT, grant: 'refresh_token', withRefresh: false,
    scope: scope, sub: name, username: name,
    user: { username: name, sub: name } });
}

// client_credentials for an application: the client is the subject.
function machineToken(clientId, scope) {
  log.debug("Entering machineToken(). " + clientId);
  log.debug("Leaving machineToken().");
  return oauth2.tokenSet(BASE, {
    client_id: clientId, grant: 'client_credentials', withRefresh: false,
    clientAuthenticated: true, scope: scope, sub: clientId,
    username: clientId, user: { username: clientId, sub: clientId } });
}

async function refusedWith(fn) {
  log.debug("Entering refusedWith().");
  try {
    await fn();
  } catch (e) {
    log.debug("Caught in refusedWith(): " + ((e && e.message) || e));
    log.debug("Leaving refusedWith(). Refused.");
    return e;
  }
  log.debug("Leaving refusedWith(). Not refused.");
  return null;
}

function action(body) {
  log.debug("Entering action(). " + body.action);
  log.debug("Leaving action().");
  return adminActions.rolesAction(body, { actor: 'test', via: 'test' });
}

function narrowedRows(actor) {
  log.debug("Entering narrowedRows().");
  log.debug("Leaving narrowedRows().");
  return audit.list().filter(function (row) {
    return row.errorCode === rolePermissions.NARROWED_CODE &&
           row.actor === actor;
  });
}

function setUp(t) {
  log.debug("Entering setUp().");
  const made = [
    applications.createApplication({ identifier: CLIENT,
      protocols: ['oauth2'],
      fields: { oauthClientId: CLIENT,
                oauthAllowedScope: ['openid', 'admin:read', 'admin:write',
                                    PERMISSION] } }),
    applications.createApplication({ identifier: MACHINE,
      protocols: ['oauth2'],
      fields: { oauthClientId: MACHINE,
                oauthAllowedScope: ['admin:read', 'admin:write',
                                    PERMISSION] } }),
    applications.createApplication({ identifier: RESOURCE,
      protocols: ['oauth2'],
      fields: { oauthClientId: RESOURCE,
                oauthPermissionBaseUri: RESOURCE_BASE,
                oauthPermission: ['read', 'write'] } })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the two clients and the resource were created',
          JSON.stringify(made));
  log.debug("Leaving setUp().");
}

function consoleRoles(t) {
  log.debug("Entering consoleRoles().");
  t.log.info('=== A. the console roles ===');
  const rows = roles.all().filter(function (row) {
    return row.console;
  });
  t.equal(rows.map(function (row) { return row.name; }).sort().join(','),
          'ADMIN_READ,ADMIN_WRITE',
          'A1. the realm was seeded with the two console roles');
  t.check(rows.every(function (row) {
    return row.applications.indexOf('sts-management-api') >= 0 &&
           row.permissions.join() === (row.name === 'ADMIN_READ'
             ? 'admin:read' : 'admin:write');
  }), 'A2. each is held by sts-management-api and authorizes its own scope',
          JSON.stringify(rows));
  t.check(!roles.isBuiltIn('ADMIN_READ') && !roles.isBuiltIn('ADMIN_WRITE'),
          'A3. and neither is a built-in any longer');
  const person = action({ action: 'add-member', role: 'ADMIN_WRITE',
                          kind: 'user', member: 'rp-somebody' });
  t.check(!person.ok && /roster/.test(JSON.stringify(person)),
          'A4. a person cannot be written onto a console role here',
          JSON.stringify(person));
  const removed = action({ action: 'delete-role', role: 'ADMIN_READ' });
  t.check(!removed.ok, 'A5. a console role cannot be deleted',
          JSON.stringify(removed));
  const repermitted = action({ action: 'add-permission', role: 'ADMIN_READ',
                               permission: PERMISSION });
  t.check(!repermitted.ok, 'A6. and its permission cannot be changed',
          JSON.stringify(repermitted));
  log.debug("Leaving consoleRoles().");
}

async function people(t, realm, names) {
  log.debug("Entering people().");
  t.log.info('=== B. a person and admin:* ===');
  const open = await refresh(names.nobody, ADMIN);
  t.equal(open.scope, ADMIN,
          'B1. with nobody on the realm\'s roster, a person is issued both');
  adminRbac.grant(names.writer, 'write', { via: 'test', realm: realm.id });
  adminRbac.grant(names.reader, 'read', { via: 'test', realm: realm.id });
  const nobody = await refresh(names.nobody, ADMIN);
  t.equal(nobody.scope, 'openid',
          'B2. once the roster names somebody, a person with no role is ' +
          'issued neither');
  t.equal(claimsOf(nobody.access_token).scope, 'openid',
          'B3. and the access token does not carry them');
  t.check(narrowedRows(names.nobody).length === 1,
          'B4. one audit row records what was taken off (STS-ADMIN-0821)',
          JSON.stringify(narrowedRows(names.nobody)));
  t.equal((await refresh(names.reader, ADMIN)).scope, 'openid admin:read',
          'B5. Admin Read is issued admin:read and not admin:write');
  t.equal((await refresh(names.writer, ADMIN)).scope, ADMIN,
          'B6. Admin Write (which implies Admin Read) is issued both');
  const refused = await refusedWith(function () {
    return refresh(names.reader, 'admin:write');
  });
  t.check(!!refused && refused.name === 'AccessTokenRefused' &&
          refused.refusal.error === 'invalid_scope',
          'B7. only admin:write, for a holder of Admin Read, is invalid_scope',
          refused ? JSON.stringify(refused.refusal) : 'not refused');
  log.debug("Leaving people().");
}

async function machines(t) {
  log.debug("Entering machines().");
  t.log.info('=== C. an application and admin:* ===');
  const refused = await refusedWith(function () {
    return machineToken(MACHINE, 'admin:read admin:write');
  });
  t.check(!!refused && refused.refusal &&
          refused.refusal.error === 'invalid_scope',
          'C1. a client that declares both but holds neither role is ' +
          'issued neither', refused ? JSON.stringify(refused.refusal) : '');
  t.check(action({ action: 'add-member', role: 'ADMIN_READ',
                   kind: 'application', member: MACHINE }).ok,
          'precondition: the client was added to ADMIN_READ');
  const read = await machineToken(MACHINE, 'admin:read admin:write');
  t.equal(read.scope, 'admin:read',
          'C2. in ADMIN_READ, it is issued admin:read and not admin:write');
  const seeded = await machineToken('sts-management-api',
                                    'admin:read admin:write');
  t.equal(seeded.scope, 'admin:read admin:write',
          'C3. the seeded management client, in both, is issued both');
  log.debug("Leaving machines().");
}

async function gatedPermission(t, names) {
  log.debug("Entering gatedPermission().");
  t.log.info('=== D. a gated application permission ===');
  const ungated = await refresh(names.nobody, 'openid ' + PERMISSION);
  t.check(String(ungated.scope).indexOf('read') >= 0,
          'D1. ungated, it is issued as it always was', ungated.scope);
  const badGate = applications.updateApplication(RESOURCE, {
    attribute: 'oauthRoleGatedPermission', mode: 'add', value: 'delete' });
  t.check(!badGate.ok, 'D2. gating a name the resource does not define is ' +
          'refused (STS-REG-0090)', JSON.stringify(badGate));
  t.check(applications.updateApplication(RESOURCE, {
    attribute: 'oauthRoleGatedPermission', mode: 'add', value: 'read' }).ok,
          'precondition: the resource gates read');
  t.check(rolePermissions.isGated(PERMISSION) &&
          !rolePermissions.isGated(RESOURCE_BASE + 'write'),
          'D3. read is gated and write is not');
  const personRefused = await refusedWith(function () {
    return refresh(names.nobody, PERMISSION);
  });
  t.check(!!personRefused && personRefused.refusal.error === 'invalid_scope',
          'D4. gated, a person holding no role naming it is refused',
          personRefused ? JSON.stringify(personRefused.refusal) : '');
  t.check(action({ action: 'create-role', role: 'rp-readers-' + RUN }).ok &&
          action({ action: 'add-member', role: 'rp-readers-' + RUN,
                   kind: 'user', member: names.nobody }).ok &&
          action({ action: 'add-member', role: 'rp-readers-' + RUN,
                   kind: 'application', member: MACHINE }).ok,
          'precondition: a role holding the person and the client');
  const native = action({ action: 'add-permission',
                          role: 'rp-readers-' + RUN, permission: 'admin:read' });
  t.check(!native.ok, 'D5. a native permission cannot be put on an ' +
          'ordinary role', JSON.stringify(native));
  const undefinedOne = action({ action: 'add-permission',
                                role: 'rp-readers-' + RUN,
                                permission: RESOURCE_BASE + 'delete' });
  t.check(!undefinedOne.ok, 'D6. nor a permission nobody defines',
          JSON.stringify(undefinedOne));
  const added = action({ action: 'add-permission', role: 'rp-readers-' + RUN,
                         permission: PERMISSION });
  t.check(added.ok && added.gated === true,
          'D7. a defined, gated permission is authorized', JSON.stringify(added));
  t.check(action({ action: 'describe-role', role: 'rp-readers-' + RUN,
                   description: 'readers' }).ok &&
          roles.read('rp-readers-' + RUN).permissions.join() === PERMISSION,
          'D8. and editing the role\'s description keeps it');
  const person = await refresh(names.nobody, 'openid ' + PERMISSION);
  t.check(String(person.scope).indexOf('read') >= 0,
          'D9. holding the role, the person is issued it', person.scope);
  const machine = await machineToken(MACHINE, PERMISSION);
  t.check(String(machine.scope).indexOf('read') >= 0,
          'D10. and so is the client, on client_credentials', machine.scope);
  log.debug("Leaving gatedPermission().");
}

function heldAndCarried(t, realm, names) {
  log.debug("Entering heldAndCarried().");
  t.log.info('=== E. held ∩ carried ===');
  // Asked from the DEFAULT realm, naming the throwaway one as the token's:
  // the roles asked are the issuing realm's.
  const fromDefault = function (fn) {
    return realms.run(realms.get(realms.DEFAULT_ID), fn);
  };
  const person = function (name) {
    return { sub: 'urn:uuid:' + name, username: name, client_id: CLIENT };
  };
  const writerReadOnly = fromDefault(function () {
    return rolePermissions.effectiveRoles(person(names.writer),
                                          ['admin:read'], realm.id);
  });
  t.check(writerReadOnly.roles.indexOf('ADMIN_READ') >= 0 &&
          writerReadOnly.roles.indexOf('ADMIN_WRITE') < 0,
          'E1. Admin Write\'s token carrying only admin:read is ADMIN_READ ' +
          'and not ADMIN_WRITE', JSON.stringify(writerReadOnly));
  adminRbac.revoke(names.reader, 'read', { via: 'test', realm: realm.id });
  const revoked = fromDefault(function () {
    return rolePermissions.effectiveRoles(person(names.reader),
                                          ['admin:read'], realm.id);
  });
  t.check(revoked.roles.indexOf('ADMIN_READ') < 0 &&
          revoked.withdrawn.join() === 'admin:read',
          'E2. a person whose role was revoked loses it on the token they ' +
          'already hold', JSON.stringify(revoked));
  const client = rolePermissions.effectiveRoles(
    { sub: MACHINE, client_id: MACHINE }, ['admin:read'], realm.id);
  t.check(client.subject.kind === 'application' &&
          client.roles.indexOf('ADMIN_READ') >= 0,
          'E3. a client\'s own token is decided on the client\'s roles',
          JSON.stringify(client));
  const urn = rolePermissions.effectiveRoles(
    { sub: 'urn:sts:client:' + MACHINE, client_id: MACHINE },
    ['admin:write'], realm.id);
  t.check(urn.withdrawn.join() === 'admin:write',
          'E4. in either spelling of its subject, and a scope its roles do ' +
          'not authorize is withdrawn', JSON.stringify(urn));
  log.debug("Leaving heldAndCarried().");
}

function pipRoles(t, names) {
  log.debug("Entering pipRoles().");
  t.log.info('=== F. the PIP role designator ===');
  const request = function (name, kind) {
    const attributes = [{ attributeId: model.ATTRIBUTE.SUBJECT_ID,
                          values: [{ type: model.TYPE.STRING,
                                     lexical: name }] }];
    if (kind) {
      attributes.push({ attributeId: pip.SUBJECT_KIND_ATTRIBUTE,
                        values: [{ type: model.TYPE.STRING,
                                   lexical: kind }] });
    }
    return { categories: [{ category: model.CATEGORY.ACCESS_SUBJECT,
                            attributes: attributes }] };
  };
  const designator = { category: model.CATEGORY.ACCESS_SUBJECT,
                       attributeId: pip.ROLE_ATTRIBUTE,
                       dataType: model.TYPE.STRING };
  const answer = function (req) {
    return pip.resolverFor(req)(designator).map(function (one) {
      return datatypes.writeValue(model.TYPE.STRING, one);
    }).sort().join(',');
  };
  t.equal(answer(request(names.writer)),
          ['ADMIN_READ', 'ADMIN_WRITE'].join(','),
          'F1. a person\'s configured roles, the console ones from the roster');
  t.equal(answer(request(MACHINE, 'application')),
          ['ADMIN_READ', 'rp-readers-' + RUN].sort().join(','),
          'F2. an application\'s, when the request says it is one');
  t.equal(answer(request(MACHINE)), '',
          'F3. and the same name as a person holds nothing');
  const pending = new rolePermissions.RolePermissions(Object.assign(
    rolePermissions.RolePermissions.defaultDeps(), {
      adminRbac: /** @type {any} */ ({
        rolesOf: function () {
          return { read: true, write: true, claimPending: true };
        } }) }));
  const held = pending.heldRoles({ kind: 'user', name: 'admin',
                                  authenticated: true });
  t.check(held.configured.indexOf('ADMIN_READ') < 0 &&
          /claimed/.test(held.why),
          'F4. the bootstrap administrator before its claim holds no ' +
          'console role (stubbed roster)', JSON.stringify(held));
  log.debug("Leaving pipRoles().");
}

// THE ISSUANCE POLICY OVERRIDE in this realm, written and removed.
function writeIssuancePolicy(policy) {
  log.debug("Entering writeIssuancePolicy().");
  const name = rolePep.issuancePolicyName();
  const written = xacmlStore.write(name, xml.writePolicy(policy),
                                   { enabled: true });
  log.debug("Leaving writeIssuancePolicy().");
  return written;
}

async function thePolicyDecides(t, names) {
  log.debug("Entering thePolicyDecides().");
  t.log.info('=== G. the policy decides (#304) ===');
  const B = templates.PolicyBuilders;
  const F1 = 'urn:oasis:names:tc:xacml:1.0:function:';
  const request = rolePep.buildRequest({
    application: CLIENT, kind: 'issue-access-token',
    subject: { kind: 'user', name: names.writer, authenticated: true },
    scopes: ['openid', 'admin:read'], client: CLIENT,
    grantType: 'refresh_token', protocol: 'OAuth 2.0' }, [], [], []);
  const valuesOf = function (category, id) {
    const found = request.categories.filter(function (one) {
      return one.category === category;
    })[0];
    const attr = found && found.attributes.filter(function (one) {
      return one.attributeId === id;
    })[0];
    return attr ? attr.values.map(function (v) { return v.lexical; })
                        .join(' ') : '';
  };
  const V = require('../xacml/xacml_request').VOCABULARY;
  t.check(valuesOf(model.CATEGORY.ACTION, V.REQUESTED_SCOPE) ===
            'openid admin:read' &&
          valuesOf(model.CATEGORY.ACCESS_SUBJECT, V.CLIENT_ID) === CLIENT &&
          valuesOf(model.CATEGORY.ENVIRONMENT, V.GRANT_TYPE) ===
            'refresh_token' &&
          valuesOf(model.CATEGORY.ENVIRONMENT, V.PROTOCOL) === 'OAuth 2.0',
          'G1. the issuance request carries the requested scopes, the ' +
          'client, the grant type and the protocol', JSON.stringify(request));

  // AN OPERATOR'S OWN RULE: the built-in document with one more Deny,
  // dropping `profile` (which nothing gates) with a code of the operator's.
  const built = templates.build('role-issuance', {},
                                { name: rolePep.issuancePolicyName() });
  const S = templates.SCOPE_ATTRIBUTE;
  built.policy.rules.unshift({
    id: built.policy.id + ':rule:operator-drops-profile',
    effect: model.EFFECT.DENY,
    description: 'An operator\'s rule: never issue profile here.',
    target: B.targetOf([[
      B.match(F1 + 'string-equal', B.value(model.TYPE.STRING, S.ACTION),
              B.designator(model.CATEGORY.ACTION, model.ATTRIBUTE.ACTION_ID,
                           model.TYPE.STRING))],
      [B.match(F1 + 'string-equal', B.value(model.TYPE.STRING, 'profile'),
               B.designator(model.CATEGORY.RESOURCE,
                            model.ATTRIBUTE.RESOURCE_ID,
                            model.TYPE.STRING))]]),
    condition: null,
    obligations: [{ id: S.OBLIGATION, on: model.EFFECT.DENY,
      assignments: [
        { attributeId: S.VERDICT, category: null, issuer: null,
          expression: B.value(model.TYPE.STRING, 'drop') },
        { attributeId: S.CODE, category: null, issuer: null,
          expression: B.value(model.TYPE.STRING, 'STS-ADMIN-0821') }] }],
    advice: []
  });
  t.check(writeIssuancePolicy(built.policy).ok,
          'precondition: the operator\'s policy was written');
  const operated = rolePermissions.narrowScope('openid profile admin:read',
    { kind: 'user', name: names.writer, authenticated: true },
    { clientId: CLIENT, grant: 'refresh_token' });
  t.equal(operated.scope, 'openid admin:read',
          'G2. an operator\'s rule drops an ungated scope: the policy, not ' +
          'code, decided it');

  // AN OVERRIDE WITH NO SCOPE RULES: the built-in one decides instead.
  const bare = templates.build('role-issuance', { decideScopes: 'no' },
                               { name: rolePep.issuancePolicyName() });
  t.check(writeIssuancePolicy(bare.policy).ok,
          'precondition: an override without the scope rules was written');
  const fellBack = rolePermissions.narrowScope('openid admin:read',
    { kind: 'user', name: names.nobody, authenticated: true },
    { clientId: CLIENT, grant: 'refresh_token' });
  t.equal(fellBack.scope, 'openid',
          'G3. an override with no scope rules does not switch gating off: ' +
          'the built-in policy dropped the gated scope');
  xacmlStore.remove(rolePep.issuancePolicyName());

  config.setOverride('xacml.enabled', false);
  try {
    const off = rolePermissions.narrowScope('openid admin:read',
      { kind: 'user', name: names.nobody, authenticated: true },
      { clientId: CLIENT, grant: 'refresh_token' });
    t.equal(off.scope, 'openid',
            'G4. with xacml.enabled off the built-in policy still decides');
  } finally {
    config.clearOverride('xacml.enabled');
  }

  const installed = gate.deciderInstalled();
  gate.setDecider(null);
  try {
    const none = rolePermissions.narrowScope('openid admin:read',
      { kind: 'user', name: names.writer, authenticated: true },
      { clientId: CLIENT, grant: 'refresh_token' });
    // #305: with no decider the GATE evaluates the built-in policy itself
    // (rcbj's decision), so a holder keeps what the rule gives them.
    t.equal(none.scope, 'openid admin:read',
            'G5. with no decider at all the built-in policy still decides: ' +
            'a holder of Admin Write keeps admin:read');
  } finally {
    gate.setDecider(installed);
  }
  log.debug("Leaving thePolicyDecides().");
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.create({ id: 'rp-' + RUN,
                                name: 'role permissions ' + RUN }).realm;
  const names = { nobody: 'rp-nobody-' + RUN, reader: 'rp-reader-' + RUN,
                  writer: 'rp-writer-' + RUN };
  await realms.run(realm, async function () {
    Object.keys(names).forEach(function (key) {
      ldap.createUser(names[key], { invent: false, attributes: {} });
    });
    setUp(t);
    consoleRoles(t);
    await people(t, realm, names);
    await machines(t);
    await gatedPermission(t, names);
    heldAndCarried(t, realm, names);
    pipRoles(t, names);
    try {
      await thePolicyDecides(t, names);
    } finally {
      gate.setDecider(deciderBefore);
    }
  });
  // THE THROWAWAY REALM GOES WITH THE FILE, as the other in-process files'
  // do: every file in `run.js` shares one directory and its entry cap, and a
  // realm left here is a whole seeded subtree the later files cannot use.
  realms.remove(realm.id);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'role_permissions',
  describe: 'a scope is a request and a role authorizes it: the console ' +
            'roles, a gated application permission, held ∩ carried and ' +
            'the PIP role designator (#302, #303)',
  run: run
};
