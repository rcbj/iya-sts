// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for. Its level is LOG_LEVEL, which is also
// what the harness's assertion logger reads.
const log = require('bunyan').createLogger({ name: 'owner_administration',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: owner_administration.js
//
// ===========================================================================
// AN OWNER ADMINISTERS WHAT THEY OWN, AND NOTHING ELSE (#607, 2026-10-13).
//
// rcbj: a person who owns a role, a group, a service account or an
// application may update it from the user portal, through `/admin-api` with
// `owner:read` and `owner:write`; the check that the person IS an owner of
// the object is XACML policy, in one place. Claims:
//
//   A. THE OWNER RULE. The access-control policy's second rule permits an
//      owner — directly or through a group — the actions its kind allows,
//      and refuses: a person who is not an owner; an object closed to its
//      owners, or one the PIP cannot answer for; an action its kind does
//      not allow; a write on a read-only token; an application attribute
//      outside the list; the last owner taken off. An administrator is
//      decided exactly as before, and a question with no object cannot be
//      permitted by the owner rule.
//   B. THE PARAMETERS. `permitOwnerAdministration: no` builds the first rule
//      alone; a narrower action list is honoured.
//   C. PROTECTED (`common/ownership.ts`). Native and built-in roles, a role
//      authorizing a protected permission, the groups this service grants
//      through and their members of such roles, this service's own
//      applications and one declaring a protected scope, a service account
//      holding a protected role, and the administrator's mark — each a
//      reason; an ordinary object none. A register that cannot be read
//      leaves the object closed.
//   E. THE CONSOLE'S CHECKBOX (rcbj, 2026-10-13). Each Owners tab draws the
//      administrator's mark as a checkbox posting `set-protected`, which
//      resolves on all four tabs to POST /admin-api/ownership/set-protected;
//      the reasons no box opens are listed under it; a read-only reader gets
//      no form; and the page is drawn again in place with the new mark.
//   D. THE OWNER ROLES. OWNER_READ and OWNER_WRITE are built in, authorize
//      their permissions, are gated, and are held — computed — by a person
//      who owns something and by nobody else; held ∩ carried keeps only
//      the one the token carries.
//
// WHY IN PROCESS (tests/CLAUDE.md's first question): the claims are about a
// decision and a register's facts, and every combination — owner or not,
// protected or not, each action — is reachable only by building the question
// directly. The ownership register is a stub here, so the decisions do not
// depend on a directory; `sts_portal_owner_edits` drives the same rule end
// to end.
// ===========================================================================

delete process.env.CONFIG_FILE;

const PERSON_DN = 'uid=olive,ou=users,dc=example,dc=com';
const GROUP_DN = 'cn=olives-team,ou=groups,dc=example,dc=com';
const OTHER_DN = 'uid=mallory,ou=users,dc=example,dc=com';

// The ownership register the PIP reads, stubbed: the objects by kind and
// name, and who olive is as an owner.
function stubOwnership(objects) {
  log.debug("Entering stubOwnership().");
  log.debug("Leaving stubOwnership().");
  return {
    objectOf: function (kind, name) {
      log.debug("Entering objectOf().");
      const found = objects[kind + '/' + name];
      log.debug("Leaving objectOf().");
      return found ? Object.assign({ found: true, kind: kind, name: name },
                                   found)
                   : { found: false, kind: kind, name: name, owners: [],
                       protected: false, reasons: [] };
    },
    identityOf: function (person) {
      log.debug("Entering identityOf().");
      log.debug("Leaving identityOf().");
      return { keys: person === 'olive'
        ? [PERSON_DN.toLowerCase(), GROUP_DN.toLowerCase()] : [] };
    }
  };
}

const OBJECTS = {
  'role/staff': { owners: [PERSON_DN], protected: false },
  'role/two-owners': { owners: [PERSON_DN, OTHER_DN], protected: false },
  'role/admins-only': { owners: [PERSON_DN], protected: true,
                        reasons: ['it is a native role of this service'] },
  'group/olives-team-owned': { owners: [GROUP_DN.toUpperCase()],
                               protected: false },
  'group/someone-elses': { owners: [OTHER_DN], protected: false },
  'application/payroll': { owners: [PERSON_DN, OTHER_DN],
                           protected: false },
  'service-account/svc-backup': { owners: [PERSON_DN, GROUP_DN],
                                  protected: false }
};

// The access PEP, over a PIP whose ownership register is the stub, and the
// policy built from the template with `answers`.
function pepWith(answers) {
  log.debug("Entering pepWith().");
  const accessPep = require('../xacml/xacml_access_pep');
  const pipModule = require('../xacml/xacml_pip');
  const templates = require('../xacml/xacml_templates');
  const pip = new pipModule.XacmlPip(Object.assign(
    pipModule.XacmlPip.defaultDeps(), {
      ownership: function () {
        return stubOwnership(OBJECTS);
      } }));
  const pep = new accessPep.XacmlAccessPep(Object.assign(
    accessPep.XacmlAccessPep.defaultDeps(), { pip: pip }));
  // The policy this test means, built from the template with `answers`,
  // rather than whatever this process's repository would hand the PEP.
  const built = templates.build('access-control', answers || {},
                                { idBase: 'urn:sts:test:access-control' });
  pep.accessPolicy = function () {
    return { policy: built.policy, name: 'test', builtIn: true };
  };
  log.debug("Leaving pepWith().");
  return pep;
}

// One question, as the management API's gate asks it on an owner's token.
function ownerQuestion(kind, id, action, opts) {
  log.debug("Entering ownerQuestion().");
  const o = opts || {};
  const read = action === 'read';
  log.debug("Leaving ownerQuestion().");
  return {
    resource: 'management-api', action: read ? 'read' : 'write',
    requiredRoles: [read ? 'ADMIN_READ' : 'ADMIN_WRITE'],
    subject: { name: 'sts-user-portal', authenticated: true,
               roles: o.roles || ['OWNER_READ', 'OWNER_WRITE'],
               sessionId: null },
    ownedObject: { kind: kind, id: id, action: action,
                   attributes: o.attributes || [],
                   requiredRole: read ? 'OWNER_READ' : 'OWNER_WRITE',
                   person: o.person || 'olive' }
  };
}

function theOwnerRule(t) {
  log.debug("Entering theOwnerRule().");
  t.log.info('=== A. the owner rule ===');
  const pep = pepWith(null);
  const allowed = function (question) {
    return pep.decide(question).allowed;
  };
  t.equal(allowed(ownerQuestion('role', 'staff', 'add-member')), true,
          'A1. an owner may add a member to a role they own');
  t.equal(allowed(ownerQuestion('role', 'staff', 'read')), true,
          'A2. and read it');
  t.equal(allowed(ownerQuestion('group', 'olives-team-owned',
                                'add-member')), true,
          'A3. an owner through a group they are in, the DN compared ' +
          'without regard to case');
  t.equal(allowed(ownerQuestion('group', 'someone-elses', 'add-member')),
          false, 'A4. a person who is not an owner is refused');
  t.equal(allowed(ownerQuestion('role', 'staff', 'add-member',
                                { person: 'mallory' })), false,
          'A5. and so is the same object asked for somebody else');
  t.equal(allowed(ownerQuestion('role', 'admins-only', 'add-member')), false,
          'A6. an object closed to its owners is refused to its owner');
  t.equal(allowed(ownerQuestion('role', 'no-such-role', 'read')), false,
          'A7. an object the PIP cannot answer for stays closed');
  t.equal(allowed(ownerQuestion('role', 'staff', 'delete-role')), false,
          'A8. an action its kind does not allow an owner is refused');
  t.equal(allowed(ownerQuestion('role', 'staff', 'add-permission')), false,
          'A9. add-permission among them: an owner cannot make the role ' +
          'authorize more');
  t.equal(allowed(ownerQuestion('role', 'staff', 'add-member',
                                { roles: ['OWNER_READ'] })), false,
          'A10. a write on a token that carries only owner:read is refused');
  t.equal(allowed(ownerQuestion('role', 'staff', 'remove-owner')), false,
          'A11. the last owner cannot be taken off by an owner');
  t.equal(allowed(ownerQuestion('role', 'two-owners', 'remove-owner')), true,
          'A12. one of two can');
  t.equal(allowed(ownerQuestion('service-account', 'svc-backup',
                                'remove-service-account-owner')), true,
          'A13. a service account\'s owner action, with two owners');
  t.equal(allowed(ownerQuestion('service-account', 'svc-backup',
                                'set-service-account')), false,
          'A14. set-service-account is not an owner\'s');
  t.equal(allowed(ownerQuestion('application', 'payroll', 'update-fields',
                                { attributes: ['oauthRedirectUri',
                                               'description'] })), true,
          'A15. an application owner writes the attributes on the list');
  t.equal(allowed(ownerQuestion('application', 'payroll', 'update-fields',
                                { attributes: ['oauthRedirectUri',
                                               'oauthAllowedScope'] })),
          false, 'A16. and not when ANY attribute is off it — its scopes');
  t.equal(allowed(ownerQuestion('application', 'payroll', 'reveal-secret')),
          false, 'A17. reveal-secret is not an owner\'s');
  t.equal(allowed(ownerQuestion('application', 'payroll',
                                'regenerate-secret')), true,
          'A18. regenerate-secret is');
  const admin = pep.decide({
    resource: 'management-api', action: 'write',
    requiredRoles: ['ADMIN_WRITE'],
    subject: { name: 'sts-admin-console', authenticated: true,
               roles: ['ADMIN_WRITE'], sessionId: null } });
  t.equal(admin.allowed, true,
          'A19. an administrator is decided by the first rule, as before');
  const noObject = ownerQuestion('role', 'staff', 'add-member');
  delete noObject.ownedObject;
  t.equal(allowed(noObject), false,
          'A20. an owner\'s roles with no object named reach nothing');
  log.debug("Leaving theOwnerRule().");
}

function theParameters(t) {
  log.debug("Entering theParameters().");
  t.log.info('=== B. the parameters ===');
  const off = pepWith({ permitOwnerAdministration: 'no' });
  t.equal(off.decide(ownerQuestion('role', 'staff', 'add-member')).allowed,
          false, 'B1. permitOwnerAdministration: no builds no owner rule');
  const narrow = pepWith({ ownerRoleActions: 'read' });
  t.equal(narrow.decide(ownerQuestion('role', 'staff', 'add-member'))
            .allowed, false,
          'B2. a narrower action list is honoured');
  t.equal(narrow.decide(ownerQuestion('role', 'staff', 'read')).allowed,
          true, 'B3. and what it still lists is permitted');
  log.debug("Leaving theParameters().");
}

// `common/ownership.ts` over stub registers.
function ownershipOver(registers) {
  log.debug("Entering ownershipOver().");
  const ownership = require('../common/ownership');
  const roles = require('../common/roles');
  const deps = Object.assign(ownership.Ownership.defaultDeps(), {
    config: function () {
      return { value: function (key) {
        return { 'admin.readGroup': 'admin-read',
                 'admin.writeGroup': 'admin-write',
                 'roles.remotePepGroup': 'remote-peps',
                 'roles.xacmlUserGroup': 'xacml-users' }[key] || '';
      } };
    },
    roles: function () {
      return Object.assign(Object.create(roles), {
        all: function () {
          return registers.roles;
        },
        read: function (name) {
          return registers.roles.filter(function (one) {
            return one.name === name;
          })[0] || null;
        },
        rolesOf: function (who) {
          return registers.held[who.name] || [];
        } });
    },
    ldap: function () {
      return {
        groupOwnership: function (name) {
          return registers.groups[name] || null;
        },
        groupsOfUser: function () {
          return { entryFound: true, dn: PERSON_DN,
                   groups: [{ dn: GROUP_DN, cn: 'olives-team' }] };
        },
        groupsOwnedBy: function () {
          return registers.groupsOwned || [];
        } };
    },
    applications: function () {
      return {
        isInternalIdentifier: function (id) {
          return id === 'sts-user-portal';
        },
        ownerProtected: function (id) {
          return id === 'marked-app';
        },
        list: function () {
          return registers.applications || [];
        } };
    },
    serviceAccounts: function () {
      return { of: function (name) {
        return registers.accounts[name] || null;
      }, list: function () {
        return [];
      } };
    },
    scopePolicy: function () {
      return {
        protectedScopes: function () {
          return ['admin:read', 'admin:write', 'scim:write'];
        },
        declaredScopes: function (id) {
          return id === 'scim-feeder' ? ['scim:write', 'openid'] : null;
        },
        // The scopes a delegated permission grant declares (#1141).
        grantedScopes: function () {
          return [];
        } };
    }
  });
  log.debug("Leaving ownershipOver().");
  return new ownership.Ownership(deps);
}

function protectedObjects(t) {
  log.debug("Entering protectedObjects().");
  t.log.info('=== C. protected (common/ownership.ts) ===');
  const register = {
    roles: [
      { name: 'ADMIN_WRITE', native: true, permissions: ['admin:write'],
        groups: ['admin-write'], applications: [], owners: [] },
      { name: 'scim-writers', native: false, permissions: ['scim:write'],
        groups: ['scim-team'], applications: ['scim-bot'], owners: [] },
      { name: 'staff', native: false, permissions: [], groups: [],
        applications: [], owners: [PERSON_DN] },
      { name: 'marked', native: false, permissions: [], groups: [],
        applications: [], owners: [PERSON_DN], ownerProtected: true }
    ],
    groups: {
      'admin-write': { dn: 'cn=admin-write,ou=groups,dc=example,dc=com',
                       cn: 'admin-write', owners: [] },
      'scim-team': { dn: 'cn=scim-team,ou=groups,dc=example,dc=com',
                     cn: 'scim-team', owners: [] },
      'readers': { dn: 'cn=readers,ou=groups,dc=example,dc=com',
                   cn: 'readers', owners: [], ownerProtected: false },
      'marked-group': { dn: 'cn=marked-group,ou=groups,dc=example,dc=com',
                        cn: 'marked-group', owners: [],
                        ownerProtected: true }
    },
    accounts: {
      'svc-admin': { username: 'svc-admin', owners: [] },
      'svc-plain': { username: 'svc-plain', owners: [] },
      'svc-marked': { username: 'svc-marked', owners: [],
                      ownerProtected: true }
    },
    held: { 'svc-admin': ['EVERYBODY', 'ADMIN_WRITE'],
            'svc-plain': ['EVERYBODY', 'staff'] }
  };
  const o = ownershipOver(register);
  const closed = function (kind, name) {
    return o.protectionOf(kind, name).length > 0;
  };
  t.check(closed('role', 'ADMIN_WRITE'), 'C1. a native role is closed');
  t.check(closed('role', 'EVERYBODY'), 'C2. a built-in role is closed');
  t.check(closed('role', 'scim-writers'),
          'C3. a role authorizing a protected permission is closed');
  t.check(!closed('role', 'staff'), 'C4. an ordinary role is open');
  t.check(closed('role', 'marked'), 'C5. a role an administrator marked is ' +
          'closed');
  t.check(closed('group', 'admin-write'),
          'C6. a console roster group is closed');
  t.check(closed('group', 'scim-team'),
          'C7. a group that is a member of a protected role is closed');
  t.check(!closed('group', 'readers'), 'C8. an ordinary group is open');
  t.check(closed('group', 'marked-group'), 'C9. a marked group is closed');
  t.check(closed('application', 'sts-user-portal'),
          'C10. this service\'s own application is closed');
  t.check(closed('application', 'scim-bot'),
          'C11. an application that is a member of a protected role is ' +
          'closed');
  t.check(closed('application', 'scim-feeder'),
          'C12. an application declaring a protected scope is closed');
  t.check(closed('application', 'marked-app'),
          'C13. a marked application is closed');
  t.check(!closed('application', 'payroll'),
          'C14. an ordinary application is open');
  t.check(closed('service-account', 'svc-admin'),
          'C15. a service account holding a protected role is closed');
  t.check(!closed('service-account', 'svc-plain'),
          'C16. one holding an ordinary role is open');
  t.check(closed('service-account', 'svc-marked'),
          'C17. a marked service account is closed');
  const broken = ownershipOver(Object.assign({}, register, {
    roles: null }));
  t.check(broken.protectionOf('role', 'staff').length > 0,
          'C18. a register that cannot be read leaves the object closed');
  t.check(o.identityOf('olive').keys.indexOf(GROUP_DN.toLowerCase()) >= 0,
          'C19. who a person is as an owner: their DN and their groups\'');
  log.debug("Leaving protectedObjects().");
}

function theOwnerRoles(t) {
  log.debug("Entering theOwnerRoles().");
  t.log.info('=== D. the owner roles ===');
  const roles = require('../common/roles');
  const rolePermissions = require('../common/role_permissions');
  t.check(roles.isBuiltIn('OWNER_READ') && roles.isBuiltIn('OWNER_WRITE'),
          'D1. OWNER_READ and OWNER_WRITE are built in');
  t.equal(roles.OWNER_ROLES.map(function (one) {
    return one.name + '=' + one.permission;
  }).join(','), 'OWNER_READ=owner:read,OWNER_WRITE=owner:write',
          'D2. each authorizes its own permission');
  t.check(rolePermissions.isGated('owner:read') &&
          rolePermissions.isGated('owner:write'),
          'D3. both permissions are gated');
  const withOwns = function (owns) {
    return new rolePermissions.RolePermissions(Object.assign(
      rolePermissions.RolePermissions.defaultDeps(), {
        adminRbac: /** @type {any} */ ({ rolesOf: function () {
          return { read: false, write: false };
        } }),
        ownsAnything: function () {
          return owns;
        } }));
  };
  const owner = withOwns(true).heldRoles({ kind: 'user', name: 'olive',
                                          authenticated: true });
  t.check(owner.configured.indexOf('OWNER_READ') >= 0 &&
          owner.configured.indexOf('OWNER_WRITE') >= 0,
          'D4. a person who owns something holds both', JSON.stringify(owner));
  const nobody = withOwns(false).heldRoles({ kind: 'user', name: 'olive',
                                            authenticated: true });
  t.check(nobody.configured.indexOf('OWNER_READ') < 0,
          'D5. a person who owns nothing holds neither',
          JSON.stringify(nobody));
  const app = withOwns(true).heldRoles({ kind: 'application',
                                        name: 'payroll',
                                        authenticated: true });
  t.check(app.configured.indexOf('OWNER_WRITE') < 0,
          'D6. an application holds neither, whatever it owns');
  t.check(roles.rolesOf({ kind: 'user', name: 'olive', authenticated: true })
            .indexOf('OWNER_WRITE') < 0,
          'D7. rolesOf() — the roles claim, the issuance PEP — never ' +
          'carries them unless told the person owns something');
  const effective = withOwns(true).effectiveRoles(
    { sub: 'olive', username: 'olive', client_id: 'sts-user-portal' },
    ['owner:read'], 'default');
  t.check(effective.roles.indexOf('OWNER_READ') >= 0 &&
          effective.roles.indexOf('OWNER_WRITE') < 0,
          'D8. held ∩ carried: an owner:read token is OWNER_READ only',
          JSON.stringify(effective));
  log.debug("Leaving theOwnerRoles().");
}

function theConsoleCheckbox(t) {
  log.debug("Entering theConsoleCheckbox().");
  t.log.info('=== E. the console\'s checkbox ===');
  const GroupsPage = require('../admin-ui/web_groups');
  const WebForms = require('../admin-ui/web_forms');
  const WebAnswers = require('../admin-ui/web_answers');
  const kit = require('../admin-ui/web_kit');
  const adminApi = require('../mgmt-api/admin_api');
  const tr = kit.context().t;
  const MARK = 'an administrator closed it to its owners';
  const draw = function (ownership, write) {
    return GroupsPage.ownerProtectionSection(tr, ownership, {
      route: '/admin/roles/owners', id: 'role-owners', kind: 'role',
      name: 'staff', back: '/admin/roles', write: write, state: {} });
  };
  const open = draw({ marked: false, protected: false, reasons: [] }, true);
  t.check(open.indexOf('name="action" value="set-protected"') >= 0 &&
          open.indexOf('name="kind" value="role"') >= 0 &&
          open.indexOf('name="protected" value="true">') >= 0,
          'E1. an open role draws the checkbox unticked, posting ' +
          'set-protected', open);
  const marked = draw({ marked: true, protected: true, reasons: [MARK] },
                      true);
  t.check(marked.indexOf('value="true" checked') >= 0 &&
          marked.indexOf(MARK) < 0,
          'E2. a marked one draws it ticked, and the mark is not listed as ' +
          'a reason', marked);
  const native = draw({ marked: false, protected: true,
                        reasons: ['it is a native role of this service'] },
                      true);
  t.check(native.indexOf('it is a native role of this service') >= 0,
          'E3. a reason no box opens is listed under it', native);
  t.check(draw({ marked: true, protected: true, reasons: [MARK] }, false)
            .indexOf('<form') < 0,
          'E4. a reader without Admin Write gets no form');
  const row = adminApi.ROUTES.filter(function (one) {
    return one.route === '/admin-api/ownership/:action';
  })[0];
  const table = WebForms.table([{ method: 'POST',
    path: '/admin-api/ownership/set-protected', mirrors: row.mirrors }]);
  t.check(['/admin/roles/owners', '/admin/groups/owners',
           '/admin/applications/owners', '/admin/users/service-account']
    .every(function (page) {
      return WebForms.resolve(table, page + '#x-protection',
                              'set-protected') ===
        '/admin-api/ownership/set-protected';
    }), 'E5. on all four tabs the form resolves to ' +
        'POST /admin-api/ownership/set-protected', row.mirrors);
  const before = { role: { name: 'staff', ownership: { marked: false,
    protected: true, reasons: ['it is a native role of this service'] } } };
  const after = WebAnswers.redraw('/admin/roles/owners', 'set-protected',
    {}, { ok: true, ownerProtected: true, message: 'closed' }, before, tr);
  const now = after.json.role.ownership;
  t.check(now.marked === true && now.reasons.indexOf(MARK) >= 0 &&
          now.reasons.length === 2 &&
          after.json.state.ownerProtection.notice === 'closed',
          'E6. the page is drawn again in place with the mark the answer ' +
          'holds', JSON.stringify(after.json));
  log.debug("Leaving theConsoleCheckbox().");
}

function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  config.setOverride('xacml.enforceAccess', 'true');
  try {
    theOwnerRule(t);
    theParameters(t);
    protectedObjects(t);
    theOwnerRoles(t);
    theConsoleCheckbox(t);
  } finally {
    // CLEARED RATHER THAN WRITTEN BACK: tests/access_policy.js's reason.
    config.clearOverride('xacml.enforceAccess');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'owner administration',
  describe: 'an owner administers what they own through /admin-api, ' +
            'decided by the access-control policy\'s owner rule (#607)',
  run: run
};
