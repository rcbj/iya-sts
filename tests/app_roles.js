// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: app_roles.js
//
// ===========================================================================
// ROLES THAT BELONG TO ONE APPLICATION (#310, a follow-up to #88,
// 2026-09-28) — Entra-style app roles, on rcbj's three decisions: a role
// entry scoped by `roleApplication`; named `<role>@<application>`, unique per
// application; a token for application X carries the realm-wide roles and
// X's, never another application's.
//
//   A. NAMING. Two applications may each have a `reader`; a realm-wide name
//      with the separator is refused, and so is an application nobody
//      registered.
//   B. RESOLUTION. For payroll, a member of reader@payroll holds `reader`
//      (and every realm-wide role); for hr, not — and hr's `reader` is not
//      payroll's.
//   C. THE CLAIM. An ID Token for payroll carries `reader`; one for hr does
//      not; the realm-wide role is in both.
//   D. THE REQUIREMENT. payroll requiring `reader` admits its own reader
//      and refuses hr's.
//   E. THE PIP answers an application's role by its full name.
//   F. PERMISSIONS. An application's role authorizes its own application's
//      permissions and not another's; editing it keeps its application; the
//      register knows a requirement one of its roles meets.
//   H. THE ROLES TAB'S REQUIREMENT SECTION (#458). The application page's
//      Configuration grid no longer draws appRequiredRole (the new-
//      application form still does); the page's roles state carries each
//      required role with what it resolves to — this application's own,
//      or nothing — and offers the realm's roles but EVERYBODY and never
//      another application's; and the section's two forms, the `add` and
//      `remove` application actions, write the list.
//
// IN A THROWAWAY REALM, removed at the end (see role_permissions.js).
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const roles = require('../common/roles');
const stats = require('../common/admin_stats');
const gate = require('../common/issuance_gate');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const pip = require('../xacml/xacml_pip');
const model = require('../xacml/xacml_model');
const datatypes = require('../xacml/xacml_datatypes');
const deciderBefore = gate.deciderInstalled();
const rolePep = require('../xacml/xacml_role_pep');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'app_roles',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const PAYROLL = 'payroll-' + RUN;
const HR = 'hr-' + RUN;
const ALICE = 'ar-alice-' + RUN;
const BOB = 'ar-bob-' + RUN;
const STAFF = 'ar-staff-' + RUN;

function action(body) {
  log.debug("Entering action(). " + body.action);
  log.debug("Leaving action().");
  return adminActions.rolesAction(body, { actor: 'test', via: 'test' });
}

function claimRoles(audience, username) {
  log.debug("Entering claimRoles().");
  const claims = stats.jwtClaims('id_token',
                                 { username: username, audience: audience });
  log.debug("Leaving claimRoles().");
  return (claims.roles || []).slice(0).sort().join(',');
}

function setUp(t) {
  log.debug("Entering setUp().");
  const made = [PAYROLL, HR].map(function (id) {
    return applications.createApplication({ identifier: id,
      protocols: ['oauth2'],
      fields: { oauthClientId: id,
                oauthPermissionBaseUri: 'https://' + id + '.example/',
                oauthPermission: ['read'] } });
  });
  [ALICE, BOB].forEach(function (name) {
    ldap.createUser(name, { invent: false, attributes: {} });
  });
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: payroll and hr were registered', JSON.stringify(made));
  log.debug("Leaving setUp().");
}

function naming(t) {
  log.debug("Entering naming().");
  t.log.info('=== A. naming ===');
  t.check(action({ action: 'create-role', role: 'reader',
                   application: PAYROLL }).ok &&
          action({ action: 'create-role', role: 'reader',
                   application: HR }).ok &&
          action({ action: 'create-role', role: STAFF }).ok,
          'A1. payroll and hr each have a `reader`, beside a realm-wide role');
  const payrollReader = roles.read('reader@' + PAYROLL);
  t.check(!!payrollReader && payrollReader.application === PAYROLL &&
          payrollReader.localName === 'reader',
          'A2. registered as reader@payroll, belonging to payroll',
          JSON.stringify(payrollReader));
  t.check(!action({ action: 'create-role', role: 'x@' + PAYROLL }).ok,
          'A3. a realm-wide role\'s name may not contain the separator');
  t.check(!action({ action: 'create-role', role: 'reader',
                    application: 'nobody-' + RUN }).ok,
          'A4. nor may a role be made for an application nobody registered');
  t.check(action({ action: 'add-member', role: 'reader@' + PAYROLL,
                   kind: 'user', member: ALICE }).ok &&
          action({ action: 'add-member', role: 'reader@' + HR,
                   kind: 'user', member: BOB }).ok &&
          action({ action: 'add-member', role: STAFF, kind: 'user',
                   member: ALICE }).ok &&
          action({ action: 'add-member', role: STAFF, kind: 'user',
                   member: BOB }).ok,
          'precondition: alice reads payroll, bob reads hr, both are staff');
  log.debug("Leaving naming().");
}

function resolution(t) {
  log.debug("Entering resolution().");
  t.log.info('=== B. resolution ===');
  const held = function (name, application) {
    return roles.rolesOf({ kind: 'user', name: name, authenticated: true,
                           application: application })
      .filter(function (one) { return !roles.isBuiltIn(one); }).sort()
      .join(',');
  };
  t.equal(held(ALICE, PAYROLL), [STAFF, 'reader'].sort().join(','),
          'B1. for payroll, alice holds its reader and the realm-wide role');
  t.equal(held(ALICE, HR), STAFF,
          'B2. for hr, alice holds only the realm-wide role');
  t.equal(held(BOB, PAYROLL), STAFF,
          'B3. and bob, hr\'s reader, is not payroll\'s reader');
  t.equal(held(ALICE, ''), STAFF,
          'B4. for no application, only realm-wide roles');
  log.debug("Leaving resolution().");
}

function theClaim(t) {
  log.debug("Entering theClaim().");
  t.log.info('=== C. the claim ===');
  t.equal(claimRoles(PAYROLL, ALICE), [STAFF, 'reader'].sort().join(','),
          'C1. an ID Token for payroll carries payroll\'s reader');
  t.equal(claimRoles(HR, ALICE), STAFF,
          'C2. one for hr does not — never another application\'s role');
  log.debug("Leaving theClaim().");
}

function theRequirement(t) {
  log.debug("Entering theRequirement().");
  t.log.info('=== D. the requirement ===');
  t.check(applications.updateApplication(PAYROLL, {
    attribute: 'appRequiredRole', mode: 'add', value: 'reader' }).ok,
          'precondition: payroll requires reader');
  const ask = function (name) {
    return gate.check({ application: PAYROLL,
                        kind: gate.ISSUANCE.ACCESS_TOKEN,
                        subject: { kind: 'user', name: name,
                                   authenticated: true } });
  };
  const alice = ask(ALICE);
  const bob = ask(BOB);
  t.check(alice.allowed && !bob.allowed,
          'D1. payroll\'s requirement admits its own reader and refuses ' +
          'hr\'s', JSON.stringify({ alice: alice.why, bob: bob.why }));
  log.debug("Leaving theRequirement().");
}

function thePip(t) {
  log.debug("Entering thePip().");
  t.log.info('=== E. the PIP ===');
  const request = { categories: [{ category: model.CATEGORY.ACCESS_SUBJECT,
    attributes: [{ attributeId: model.ATTRIBUTE.SUBJECT_ID,
                   values: [{ type: model.TYPE.STRING, lexical: ALICE }] }] }] };
  const answered = pip.resolverFor(request)({
    category: model.CATEGORY.ACCESS_SUBJECT,
    attributeId: pip.ROLE_ATTRIBUTE, dataType: model.TYPE.STRING })
    .map(function (one) {
      return datatypes.writeValue(model.TYPE.STRING, one);
    });
  t.check(answered.indexOf('reader@' + PAYROLL) >= 0 &&
          answered.indexOf(STAFF) >= 0,
          'E1. the PIP answers an application\'s role by its full name',
          answered.join(','));
  log.debug("Leaving thePip().");
}

function permissions(t) {
  log.debug("Entering permissions().");
  t.log.info('=== F. permissions and edits ===');
  const own = action({ action: 'add-permission', role: 'reader@' + PAYROLL,
                       permission: 'https://' + PAYROLL + '.example/read' });
  const other = action({ action: 'add-permission', role: 'reader@' + PAYROLL,
                         permission: 'https://' + HR + '.example/read' });
  t.check(own.ok && !other.ok,
          'F1. an application\'s role authorizes its own application\'s ' +
          'permission and not another\'s', JSON.stringify([own, other]));
  t.check(action({ action: 'describe-role', role: 'reader@' + PAYROLL,
                   description: 'reads payroll' }).ok &&
          roles.read('reader@' + PAYROLL).application === PAYROLL,
          'F2. editing it keeps its application');
  t.check(applications.updateApplication(HR, {
    attribute: 'appRequiredRole', mode: 'add', value: 'writer' }).ok,
          'precondition: hr requires writer, which nothing defines');
  const register = adminViews.rolesRegister();
  const payroll = register.requiring.filter(function (row) {
    return row.application === PAYROLL;
  })[0];
  const hr = register.requiring.filter(function (row) {
    return row.application === HR;
  })[0];
  t.check(!!payroll && payroll.unknown.length === 0 && !!hr &&
          hr.unknown.join() === 'writer',
          'F3. the register knows payroll\'s reader meets its requirement, ' +
          'and that nothing meets hr\'s writer',
          JSON.stringify([payroll, hr]));
  log.debug("Leaving permissions().");
}

// G. APPLICATION PERMISSIONS (#93): who may hold a role, its display name and
// stable id, and the roles an application holds read from its own side.
function applicationPermissions(t) {
  log.debug("Entering applicationPermissions().");
  t.log.info('=== G. application permissions (#93) ===');
  const MACHINES = 'ar-machines-' + RUN;
  const PEOPLE = 'ar-people-' + RUN;
  const codeOf = function (result) {
    return errorCodes.codeOf(result) || '';
  };
  const made = action({ action: 'create-role', role: MACHINES,
                        displayName: 'Batch machines',
                        memberTypes: ['application'] });
  const madeRow = roles.read(MACHINES);
  t.check(made.ok && madeRow && madeRow.displayName === 'Batch machines' &&
          madeRow.memberTypes.join() === 'application' &&
          /^[0-9a-f-]{36}$/.test(madeRow.id),
          'G1. a role is made with a display name, applications only, and ' +
          'an entryUUID id', JSON.stringify(madeRow));
  const person = action({ action: 'add-member', role: MACHINES, kind: 'user',
                          member: ALICE });
  t.check(!person.ok && codeOf(person) === 'STS-XACML-0082',
          'G2. a person is refused on an applications-only role',
          JSON.stringify(person) + ' ' + codeOf(person));
  const group = action({ action: 'add-member', role: MACHINES, kind: 'group',
                         member: 'developers' });
  t.check(!group.ok && codeOf(group) === 'STS-XACML-0082',
          'G3. and so is a group', codeOf(group));
  t.check(action({ action: 'add-member', role: MACHINES, kind: 'application',
                   member: HR }).ok &&
          action({ action: 'add-permission', role: MACHINES,
                   permission: 'https://' + PAYROLL + '.example/read' }).ok,
          'G4. an application is added, and a permission beside it');
  const kept = roles.read(MACHINES);
  t.check(kept.displayName === 'Batch machines' &&
          kept.memberTypes.join() === 'application' && kept.id === madeRow.id,
          'G5. add-member and add-permission keep the display name, the ' +
          'member types and the id', JSON.stringify(kept));
  const narrowing = action({ action: 'describe-role', role: MACHINES,
                             description: 'batch', memberTypes: ['user'] });
  t.check(!narrowing.ok && codeOf(narrowing) === 'STS-XACML-0082' &&
          roles.read(MACHINES).memberTypes.join() === 'application',
          'G6. restricting it to people while an application holds it is ' +
          'refused, and nothing changes', codeOf(narrowing));
  const described = action({ action: 'describe-role', role: MACHINES,
                             description: 'batch jobs' });
  const afterDescribe = roles.read(MACHINES);
  t.check(described.ok && afterDescribe.description === 'batch jobs' &&
          afterDescribe.displayName === 'Batch machines' &&
          afterDescribe.memberTypes.join() === 'application',
          'G7. describe-role with only a description keeps the display name ' +
          'and member types', JSON.stringify(afterDescribe));
  const unknown = action({ action: 'create-role', role: 'ar-odd-' + RUN,
                          memberTypes: ['robot'] });
  t.check(!unknown.ok && codeOf(unknown) === 'STS-XACML-0081',
          'G8. an unknown member type is refused', codeOf(unknown));
  const consoleRole = action({ action: 'describe-role', role: 'ADMIN_READ',
                              memberTypes: ['application'] });
  t.check(!consoleRole.ok && codeOf(consoleRole) === 'STS-XACML-0083',
          'G9. a console role cannot be restricted', codeOf(consoleRole));
  t.check(action({ action: 'create-role', role: PEOPLE,
                   memberTypes: ['user'] }).ok,
          'precondition: a people-only role');
  const state = adminViews.applicationRolesState(HR);
  const held = state.held.filter(function (one) {
    return one.name === MACHINES;
  })[0];
  t.check(!!held && held.displayName === 'Batch machines' &&
          held.id === madeRow.id && held.carriedAs === MACHINES &&
          held.application === '',
          'G10. the application\'s page lists the role it holds, realm-wide, ' +
          'with its label and id', JSON.stringify(state.held));
  t.check(state.offerable.indexOf(PEOPLE) < 0 &&
          state.offerable.indexOf(MACHINES) < 0 &&
          state.offerable.indexOf(STAFF) >= 0,
          'G11. it is offered neither a people-only role nor one it holds, ' +
          'and is offered an unrestricted one',
          JSON.stringify(state.offerable));
  const detail = adminViews.applicationDetailJson({ query: {} }, HR);
  t.check(detail.json.applicationRoles &&
          detail.json.applicationRoles.held.some(function (one) {
            return one.name === MACHINES;
          }),
          'G12. and GET /admin-api/applications?application= carries the ' +
          'same, as applicationRoles');
  log.debug("Leaving applicationPermissions().");
}

function requirementSection(t) {
  log.debug("Entering requirementSection().");
  t.log.info('=== H. the Roles tab\'s requirement section (#458) ===');
  const req = { query: {}, headers: { host: 'localhost:8081' },
                protocol: 'https', get: function () { return ''; } };
  const detail = adminViews.applicationDetailJson(req, PAYROLL);
  const page = detail && detail.json && detail.json.page;
  const gridHas = !!page && page.config.fields.some(function (one) {
    return one.attribute === 'appRequiredRole';
  });
  t.check(!!page && !gridHas,
          'H1. the application page\'s Configuration grid does not draw ' +
          'appRequiredRole');
  t.check((adminViews.newApplicationJson({}).fields || [])
    .some(function (one) {
      return one.attribute === 'appRequiredRole';
    }), 'H2. the new-application form still offers it, having no Roles ' +
        'tab');
  const payroll = page.roles;
  t.check(payroll.required.length === 1 &&
          payroll.required[0].name === 'reader' &&
          payroll.required[0].resolves === 'application' &&
          payroll.required[0].role === 'reader@' + PAYROLL &&
          JSON.stringify(detail.json.applicationRoles.required) ===
            JSON.stringify(payroll.required),
          'H3. the page and the API both carry payroll\'s requirement, ' +
          'resolved to its own reader', JSON.stringify(payroll.required));
  t.check(payroll.requirable.indexOf(STAFF) >= 0 &&
          payroll.requirable.indexOf('ALL_AUTHENTICATED_USERS') >= 0 &&
          payroll.requirable.indexOf('EVERYBODY') < 0 &&
          payroll.requirable.indexOf('reader') < 0 &&
          payroll.requirable.indexOf('reader@' + HR) < 0,
          'H4. it is offered the realm-wide and built-in roles, but not ' +
          'EVERYBODY, not what it already requires and never another ' +
          'application\'s role', JSON.stringify(payroll.requirable));
  const hr = adminViews.applicationRolesState(HR);
  t.check(hr.required.length === 1 && hr.required[0].name === 'writer' &&
          hr.required[0].resolves === 'none' &&
          hr.requirable.indexOf('reader') >= 0,
          'H5. hr\'s writer, which nothing defines, resolves to nothing; ' +
          'its own reader is offered by its name inside it',
          JSON.stringify(hr));
  const added = adminActions.applicationsAction({
    action: 'add', application: HR, attribute: 'appRequiredRole',
    value: STAFF });
  const removed = adminActions.applicationsAction({
    action: 'remove', application: HR, attribute: 'appRequiredRole',
    value: 'writer' });
  t.check(added && added.ok && removed && removed.ok &&
          applications.requiredRolesOf(HR).join() === STAFF,
          'H6. the section\'s Require and Remove write appRequiredRole',
          JSON.stringify(applications.requiredRolesOf(HR)));
  const after = adminViews.applicationRolesState(HR);
  t.check(after.required.length === 1 &&
          after.required[0].resolves === 'realm' &&
          after.requirable.indexOf(STAFF) < 0,
          'H7. and the section then shows the realm-wide role, no longer ' +
          'offered', JSON.stringify(after.required));
  t.check(adminActions.applicationsAction({
    action: 'remove', application: HR, attribute: 'appRequiredRole',
    value: STAFF }).ok &&
          adminViews.applicationRolesState(HR).required.length === 0 &&
          applications.requiredRolesOf(HR).join() ===
            roles.DEFAULT_REQUIRED_ROLE,
          'H8. removing the last leaves it requiring nothing, which is ' +
          'everybody');
  log.debug("Leaving requirementSection().");
}

async function run(t) {
  log.debug("Entering run().");
  gate.setDecider(rolePep.decide);
  const realm = realms.create({ id: 'ar-' + RUN,
                                name: 'app roles ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      setUp(t);
      naming(t);
      resolution(t);
      theClaim(t);
      theRequirement(t);
      thePip(t);
      permissions(t);
      applicationPermissions(t);
      requirementSection(t);
    });
  } finally {
    // THE STATE THE REQUIRE LEFT, not an empty slot: requiring the issuance
    // PEP arms the gate once, for the whole process, and the files after
    // this one rely on it being armed.
    gate.setDecider(deciderBefore || rolePep.decide);
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'app_roles',
  describe: 'roles that belong to one application: naming, resolution per ' +
            'application, the claim, the requirement, the PIP and ' +
            'permissions (#310); member types, display name, id and the ' +
            'application\'s own roles (#93); the Roles tab\'s ' +
            'requirement section (#458)',
  run: run
};
