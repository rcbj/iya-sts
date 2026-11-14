// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: security_admin.js
//
// ---------------------------------------------------------------------------
// THE SECURITY ADMINISTRATOR (#645, 2026-11-02), IN PROCESS.
//
// rcbj: "only a security administrator can modify policy object". What this
// file holds, each section against the module that decides it:
//
//   A. the role tables — the roster's third role implies read and not write
//      (`admin-ui/admin_rbac.ts`), SECURITY_ADMIN authorizes admin:security
//      (`common/roles.js`), and admin:security is a protected admin scope
//      (`common/scope_policy.ts`);
//   B. the classifier, `common/security_operations.ts`, over stub hooks: the
//      four kinds of change, and what is NOT one — a reference posted
//      unchanged, a GET, Admin Write's ordinary writes;
//   C. the roster in a throwaway realm: a holder holds read and security and
//      not write, the open window in a trust realm hands out read and write
//      only, a realm's bootstrap administrator is not seeded into the role,
//      and the two readers the gate asks;
//   D. issuance: held ∩ carried — a holder's token carrying admin:security is
//      SECURITY_ADMIN, an Admin Write holder's is not.
//
// The HTTP half — the gate refusing Admin Write a policy save, with
// xacml.enforceAccess off too — is `tests/protocol/sts_security_admin.js`.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const ldap = require('../ldap/ldap_server');
const roles = require('../common/roles');
const adminRbac = require('../admin-ui/admin_rbac');
const rolePermissions = require('../common/role_permissions');
const scopePolicy = require('../common/scope_policy');
const config = require('../common/config');
const SecurityOperations = require('../common/security_operations');
const PolicyKinds = require('../admin-core/policy_kinds');

const log = require('bunyan').createLogger({ name: 'security_admin',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');

// THE STUB THE CLASSIFIER READS THROUGH: who holds the role, and what each
// object holds now. Named so a reader can see every fixture in one place.
const HOLDER = 'sa-holder';
const ORDINARY = 'sa-ordinary';
const APP = 'sa-app';
const GROUP = 'sa-group';
const NAMED = 'strict';

function hooks() {
  log.debug("Entering hooks().");
  log.debug("Leaving hooks().");
  return {
    securityGroup: function () {
      return 'security-admin';
    },
    holdsSecurity: function (name) {
      return name === HOLDER;
    },
    applicationValues: function (identifier, attribute) {
      return identifier === APP && /^apppasswordpolicy$/i.test(attribute)
        ? [NAMED] : [];
    },
    personValues: function (name, attribute) {
      return /^stsserviceaccountpolicy$/i.test(attribute) ? [NAMED] : [];
    },
    groupValues: function (group, attribute) {
      return group === GROUP && /^stspasswordpolicy$/i.test(attribute)
        ? [NAMED] : [];
    },
    fieldsCoveredBy: function (body) {
      return Object.keys(body || {}).filter(function (key) {
        return key.indexOf('field.') === 0;
      }).map(function (key) {
        return key.slice('field.'.length).replace(/\.\d+$/, '');
      });
    }
  };
}

function kindOf(method, path, action, body) {
  log.debug("Entering kindOf(). " + path + " " + action);
  const change = SecurityOperations.classify(
    { method: method, path: path, action: action, body: body || {} },
    hooks());
  log.debug("Leaving kindOf().");
  return change ? change.kind : null;
}

function tables(t) {
  log.debug("Entering tables().");
  t.log.info('=== A. the role tables ===');
  const role = adminRbac.ROLES.filter(function (row) {
    return row.id === 'security';
  })[0];
  t.check(!!role && role.setting === 'admin.securityGroup' &&
          role.implies.join() === 'read',
          'A1. the roster\'s third role is Security Administrator, over ' +
          'admin.securityGroup, implying read and NOT write',
          JSON.stringify(role));
  const registered = roles.CONSOLE_ROLES.filter(function (row) {
    return row.name === 'SECURITY_ADMIN';
  })[0];
  const reader = roles.CONSOLE_ROLES.filter(function (row) {
    return row.name === 'ADMIN_READ';
  })[0];
  t.check(!!registered && registered.permission === 'admin:security' &&
          registered.consoleRole === 'security' &&
          registered.groupSettings.join() === 'admin.securityGroup' &&
          registered.seedApplications.indexOf('sts-api-client') >= 0,
          'A2. SECURITY_ADMIN authorizes admin:security, is held through ' +
          'the role\'s group, and seeds sts-api-client (rcbj\'s decision)',
          JSON.stringify(registered));
  t.check(reader.groupSettings.indexOf('admin.securityGroup') >= 0,
          'A3. ADMIN_READ is held through the security group too, because ' +
          'the role implies read', JSON.stringify(reader.groupSettings));
  t.check(scopePolicy.ADMIN_SCOPES.indexOf('admin:security') >= 0,
          'A4. admin:security is a protected admin scope, held to the ' +
          'client that declares it', scopePolicy.ADMIN_SCOPES.join(' '));
  t.equal(String(config.value('admin.securityGroup')), 'security-admin',
          'A5. the group is security-admin by default');
  log.debug("Leaving tables().");
}

function classifier(t) {
  log.debug("Entering classifier().");
  t.log.info('=== B. the classifier ===');
  const password = PolicyKinds.byId('password');
  const save = PolicyKinds.saveAction(password);
  const reset = PolicyKinds.resetAction(password);
  t.equal(kindOf('POST', '/admin/policies', save), 'policy',
          'B1. a Directory → Policies save is a policy change');
  t.equal(kindOf('POST', '/admin/policies', reset), 'policy',
          'B2. and a reset');
  t.equal(kindOf('GET', '/admin/policies', save), null,
          'B3. a GET is never one');
  t.equal(kindOf('POST', '/admin/policies', 'no-such-action'), null,
          'B4. an action no kind answers is not one');
  // EVERY KIND, so a kind registered tomorrow is covered with no edit.
  const uncovered = PolicyKinds.list().filter(function (kind) {
    return kindOf('POST', '/admin/policies',
                  PolicyKinds.saveAction(kind)) !== 'policy';
  });
  t.check(uncovered.length === 0,
          'B5. every registered kind\'s save is covered',
          uncovered.map(function (kind) { return kind.id; }).join(', '));

  t.equal(kindOf('POST', '/admin/config', 'set',
                 { key: 'admin.securityGroup', value: 'x' }), 'role',
          'B6. setting admin.securityGroup grants the role');
  t.equal(kindOf('POST', '/admin/config', 'set-many',
                 { 'admin.securityGroup': 'x' }), 'role',
          'B7. in a set-many too');
  t.equal(kindOf('POST', '/admin/config', 'set',
                 { key: 'admin.writeGroup', value: 'x' }), null,
          'B8. another setting is Admin Write\'s');
  t.equal(kindOf('POST', '/admin/rbac', 'grant',
                 { username: 'x', role: 'security' }), 'role',
          'B9. a roster grant of the role');
  t.equal(kindOf('POST', '/admin/rbac', 'revoke',
                 { username: 'x', role: 'security' }), 'role',
          'B10. and a revoke');
  t.equal(kindOf('POST', '/admin/rbac', 'grant',
                 { username: 'x', role: 'write' }), null,
          'B11. a grant of Admin Write is Admin Write\'s');
  t.equal(kindOf('POST', '/admin/roles', 'add-member',
                 { role: 'SECURITY_ADMIN', member: 'x' }), 'role',
          'B12. a member added to SECURITY_ADMIN');
  t.equal(kindOf('POST', '/admin/roles', 'add-member',
                 { role: 'ADMIN_WRITE', member: 'x' }), null,
          'B13. to another role, not');
  t.equal(kindOf('POST', '/admin/groups', 'add-member',
                 { group: 'Security-Admin', member: 'x' }), 'role',
          'B14. a member added to the role\'s group, in any case');
  t.equal(kindOf('POST', '/admin/groups', 'add-member',
                 { group: 'developers', member: 'x' }), null,
          'B15. to another group, not');

  t.equal(kindOf('POST', '/admin/groups', 'set-policy',
                 { group: GROUP, attribute: 'stsPasswordPolicy',
                   policy: 'other' }), 'reference',
          'B16. a group naming another password policy');
  t.equal(kindOf('POST', '/admin/groups', 'set-policy',
                 { group: GROUP, attribute: 'stsPasswordPolicy',
                   policy: NAMED.toUpperCase() }), null,
          'B17. naming the one it names already changes nothing');
  t.equal(kindOf('POST', '/admin/applications', 'set',
                 { application: APP, attribute: 'appPasswordPolicy',
                   value: 'other' }), 'reference',
          'B18. an application naming another password policy');
  t.equal(kindOf('POST', '/admin/applications', 'set',
                 { application: 'sa-plain', attribute: 'appPasswordPolicy',
                   value: 'default' }), null,
          'B19. `default` where it names none is no change');
  t.equal(kindOf('POST', '/admin/applications', 'update-fields',
                 { application: APP, 'field.appPasswordPolicy': NAMED,
                   'field.appHomePageUrl': 'https://x.example/' }), null,
          'B20. a grid Save that posts the reference unchanged is Admin ' +
          'Write\'s — the grid posts every field');
  t.equal(kindOf('POST', '/admin/applications', 'update-fields',
                 { application: APP, 'field.appPasswordPolicy': '' }),
          'reference', 'B21. clearing it is a change');
  t.equal(kindOf('POST', '/admin/applications', 'import-ldif',
                 { file: 'dn: cn=x,ou=applications,dc=x\n' +
                         'appIdentifier: x\nappPasswordPolicy: strict\n' }),
          'reference', 'B22. an LDIF file naming a policy');
  t.equal(kindOf('POST', '/admin/applications', 'import-ldif',
                 { file: 'dn: cn=x,ou=applications,dc=x\n' +
                         'appIdentifier: x\n' }), null,
          'B23. one naming none is not');

  t.equal(kindOf('POST', '/admin/users', 'create',
                 { username: 'new', 'field.stsServiceAccountPolicy': '' }),
          null, 'B24. a create posting the field empty names nothing');
  t.equal(kindOf('POST', '/admin/users', 'create',
                 { username: 'new', 'field.stsServiceAccountPolicy': NAMED }),
          'reference', 'B25. a create naming a policy');
  t.equal(kindOf('POST', '/admin/users', 'update-fields',
                 { user: ORDINARY, 'field.stsServiceAccountPolicy': NAMED,
                   'field.mail': 'x@example.com' }), null,
          'B26. a person Save posting the reference unchanged is Admin ' +
          'Write\'s');
  t.equal(kindOf('POST', '/admin/users', 'reset-password',
                 { user: HOLDER }), 'holder',
          'B27. a holder\'s password reset');
  t.equal(kindOf('POST', '/admin/users', 'reset-password',
                 { user: ORDINARY }), null,
          'B28. anybody else\'s is Admin Write\'s');
  t.equal(kindOf('POST', '/admin/mfa', 'clear-totp', { user: HOLDER }),
          'holder', 'B29. a holder\'s cleared factor');
  t.equal(kindOf('POST', '/admin/pki', 'issue',
                 { target: 'person', identifier: HOLDER }), 'holder',
          'B30. a certificate issued in a holder\'s name');
  t.equal(kindOf('POST', '/admin/pki', 'issue',
                 { target: 'application', identifier: HOLDER }), null,
          'B31. an application\'s is not');
  t.equal(kindOf('POST', '/admin/xacml', 'save-policy', {}), null,
          'B32. an XACML policy stays Admin Write\'s (rcbj\'s decision)');
  log.debug("Leaving classifier().");
}

function roster(t, realm) {
  log.debug("Entering roster().");
  t.log.info('=== C. the roster ===');
  const ownWindow = adminRbac.rolesOf('sa-anybody-' + RUN, realm.id);
  t.check(ownWindow.open !== true ||
          ownWindow.roles.indexOf('security') < 0,
          'C1. a trust realm\'s open window hands out read and write, and ' +
          'not the Security Administrator\'s role',
          JSON.stringify(ownWindow.roles));
  const holder = 'sa-holder-' + RUN;
  const writer = 'sa-writer-' + RUN;
  realms.run(realm, function () {
    ldap.createUser(holder, { invent: false, attributes: {} });
    ldap.createUser(writer, { invent: false, attributes: {} });
  });
  const granted = adminRbac.grant(holder, 'security',
                                  { via: 'test', realm: realm.id });
  adminRbac.grant(writer, 'write', { via: 'test', realm: realm.id });
  t.check(granted.ok, 'precondition: the role was granted',
          JSON.stringify(granted));
  const held = adminRbac.rolesOf(holder, realm.id);
  t.check(held.security === true && held.read === true &&
          held.write === false &&
          held.roles.indexOf('security') >= 0 &&
          held.roles.indexOf('write') < 0,
          'C2. a holder holds read and security, and not write',
          JSON.stringify(held));
  t.check(adminRbac.holdsSecurity(holder, realm.id) === true &&
          adminRbac.holdsSecurity(writer, realm.id) === false,
          'C3. holdsSecurity() answers for the holder and not for Admin ' +
          'Write');
  t.check(adminRbac.holdsSecurity(holder, realms.DEFAULT_ID) === false,
          'C4. and only in the realm whose roster holds it');
  const seeded = adminRbac.seedBootstrapAdministrator(realm.id);
  const boot = adminRbac.rolesOf(
    String(config.value('admin.bootstrapUsername')), realm.id);
  t.check(seeded.securitySeeded !== true && boot.security !== true &&
          boot.write === true,
          'C5. a realm\'s bootstrap administrator gets Admin Read and ' +
          'Admin Write and NOT the Security Administrator\'s role ' +
          '(rcbj\'s decision)', JSON.stringify({ seeded: seeded,
                                                  roles: boot.roles }));
  realms.run(realm, function () {
    ldap.createUser('sa-named-' + RUN, { invent: false,
      attributes: { description: ['one'] } });
  });
  t.equal(adminRbac.personValues('sa-named-' + RUN, 'DESCRIPTION',
                                 realm.id).join(), 'one',
          'C6. personValues() reads an attribute, its name in any case');
  const groupDn = adminRbac.rosterFor('security', realm.id).dn;
  t.check(adminRbac.groupValues('security-admin', 'cn', realm.id)
            .join().toLowerCase() === 'security-admin',
          'C7. groupValues() reads the role\'s group', groupDn);
  log.debug("Leaving roster().");
  return { holder: holder, writer: writer };
}

function issuance(t, realm, names) {
  log.debug("Entering issuance().");
  t.log.info('=== D. held ∩ carried ===');
  const person = function (name) {
    return { sub: 'urn:uuid:' + name, username: name,
             client_id: 'sts-admin-console' };
  };
  const fromDefault = function (fn) {
    return realms.run(realms.get(realms.DEFAULT_ID), fn);
  };
  const holder = fromDefault(function () {
    return rolePermissions.effectiveRoles(person(names.holder),
      ['admin:read', 'admin:security'], realm.id);
  });
  t.check(holder.roles.indexOf('SECURITY_ADMIN') >= 0 &&
          holder.roles.indexOf('ADMIN_READ') >= 0 &&
          holder.withdrawn.length === 0,
          'D1. a holder\'s token carrying admin:security is SECURITY_ADMIN, ' +
          'and admin:read stands', JSON.stringify(holder));
  const writer = fromDefault(function () {
    return rolePermissions.effectiveRoles(person(names.writer),
      ['admin:write', 'admin:security'], realm.id);
  });
  t.check(writer.roles.indexOf('SECURITY_ADMIN') < 0 &&
          writer.withdrawn.indexOf('admin:security') >= 0 &&
          writer.roles.indexOf('ADMIN_WRITE') >= 0,
          'D2. Admin Write\'s token is not SECURITY_ADMIN: admin:security ' +
          'is withdrawn', JSON.stringify(writer));
  log.debug("Leaving issuance().");
}

async function run(t) {
  log.debug("Entering run().");
  tables(t);
  classifier(t);
  const realm = realms.create({ id: 'sa-' + RUN,
                                name: 'security admin ' + RUN }).realm;
  try {
    const names = roster(t, realm);
    issuance(t, realm, names);
  } finally {
    // The throwaway realm goes with the file, as role_permissions.js's does.
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'security_admin',
  describe: 'the Security Administrator (#645): the role tables, the ' +
            'classifier of security changes, the roster and held ∩ carried',
  run: run
};
