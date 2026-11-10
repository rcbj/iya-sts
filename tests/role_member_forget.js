// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: role_member_forget.js
//
// ===========================================================================
// A DELETED MEMBER HOLDS NOTHING, AND NEITHER DOES ITS NAMESAKE (2026-11-10).
//
// A role names its members by username, group name and application
// identifier, and deleting the thing a name named left the name on the role:
// the next application made under a forgotten client's identifier held its
// ADMIN_READ from its first request. `roles.forgetMember()` takes the name out
// wherever each is deleted.
//
//   A. AN APPLICATION forgotten through the console's action leaves its
//      configured role and ADMIN_READ; one made again under its identifier
//      holds neither; another application on the same role keeps it.
//   B. AN APPLICATION deleted through `applications.deleteApplication()`
//      directly, the other door to the same entry, does the same.
//   C. A PERSON deleted (the SCIM door, `deletePerson()`) leaves the role, and
//      somebody made again under the username does not hold it.
//   D. A GROUP deleted (`deleteGroupEntry()`) leaves the role.
//   E. The failure has its code in the table.
//
// IN A THROWAWAY REALM, removed at the end (app_roles.js's arrangement).
// ===========================================================================
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const roles = require('../common/roles');
const adminActions = require('../admin-core/admin_actions');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'role_member_forget',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ROLE = 'rmf-role-' + RUN;
const APP = 'rmf-app-' + RUN;
const OTHER = 'rmf-other-' + RUN;
const DIRECT = 'rmf-direct-' + RUN;
const PERSON = 'rmf-person-' + RUN;
const GROUP = 'rmf-group-' + RUN;

function rolesAction(body) {
  log.debug("Entering rolesAction(). " + body.action);
  log.debug("Leaving rolesAction().");
  return adminActions.rolesAction(body, { actor: 'test', via: 'test' });
}

function makeApplication(id) {
  log.debug("Entering makeApplication(). " + id);
  const made = applications.createApplication({ identifier: id,
    protocols: ['oauth2'], fields: { oauthClientId: id } });
  log.debug("Leaving makeApplication().");
  return made;
}

// The role's three member lists, lower-cased, as one string per list.
function members(name) {
  log.debug("Entering members(). " + name);
  const row = roles.read(name) || {};
  const one = function (list) {
    log.debug("Entering one().");
    log.debug("Leaving one().");
    return (list || []).map(function (x) {
      return String(x).toLowerCase();
    });
  };
  log.debug("Leaving members().");
  return { users: one(row.users), groups: one(row.groups),
           applications: one(row.applications) };
}

function setUp(t) {
  log.debug("Entering setUp().");
  const apps = [APP, OTHER, DIRECT].map(makeApplication);
  const person = ldap.createUser(PERSON, { invent: false, attributes: {} });
  const group = ldap.createGroup(GROUP, { members: [] });
  const role = rolesAction({ action: 'create-role', role: ROLE });
  const adds = [
    { kind: 'application', member: APP },
    { kind: 'application', member: OTHER },
    { kind: 'application', member: DIRECT },
    { kind: 'user', member: PERSON },
    { kind: 'group', member: GROUP }
  ].map(function (one) {
    return rolesAction({ action: 'add-member', role: ROLE, kind: one.kind,
                         member: one.member });
  });
  const console = rolesAction({ action: 'add-member', role: 'ADMIN_READ',
                                kind: 'application', member: APP });
  t.check(apps.every(function (one) {
    return one && one.ok;
  }) && !!person && group && group.ok && role.ok &&
          adds.every(function (one) {
            return one.ok;
          }) && console.ok,
          'precondition: three applications, a person and a group hold the ' +
          'role, and the first application holds ADMIN_READ too',
          JSON.stringify({ apps: apps, group: group, role: role, adds: adds,
                           console: console }));
  log.debug("Leaving setUp().");
  return { personDn: typeof person === 'string' ? person
                                                : (person && person.dn),
           groupDn: group && group.dn };
}

function anApplication(t) {
  log.debug("Entering anApplication().");
  t.log.info('=== A. an application forgotten through the console ===');
  const forgot = adminActions.applicationsAction({ action: 'forget',
    application: APP }, ['oauth2'], { actor: 'test' });
  t.check(forgot && forgot.ok, 'A1. the application is forgotten',
          JSON.stringify(forgot));
  t.check(members(ROLE).applications.indexOf(APP) < 0 &&
          members('ADMIN_READ').applications.indexOf(APP) < 0,
          'A2. it is out of its configured role and out of ADMIN_READ',
          JSON.stringify([members(ROLE), members('ADMIN_READ')]));
  t.check(members(ROLE).applications.indexOf(OTHER) >= 0,
          'A3. the other application on the role keeps it',
          JSON.stringify(members(ROLE)));
  const again = makeApplication(APP);
  t.check(again && again.ok && members(ROLE).applications.indexOf(APP) < 0 &&
          members('ADMIN_READ').applications.indexOf(APP) < 0,
          'A4. one made again under its identifier holds neither',
          JSON.stringify([again, members(ROLE), members('ADMIN_READ')]));
  log.debug("Leaving anApplication().");
}

function theOtherDoor(t) {
  log.debug("Entering theOtherDoor().");
  t.log.info('=== B. an application deleted through the registry ===');
  const gone = applications.deleteApplication(DIRECT, { actor: 'test' });
  t.check(gone && gone.ok && members(ROLE).applications.indexOf(DIRECT) < 0,
          'B1. deleteApplication() takes it out of the role as well',
          JSON.stringify([gone, members(ROLE)]));
  log.debug("Leaving theOtherDoor().");
}

function aPerson(t, made) {
  log.debug("Entering aPerson().");
  t.log.info('=== C. a person deleted ===');
  const gone = ldap.deletePerson(made.personDn, { door: 'the test' });
  t.check(gone && gone.ok && members(ROLE).users.indexOf(PERSON) < 0,
          'C1. a deleted person is out of the role',
          JSON.stringify([gone, members(ROLE)]));
  const again = ldap.createUser(PERSON, { invent: false, attributes: {} });
  t.check(!!again && members(ROLE).users.indexOf(PERSON) < 0,
          'C2. somebody made again under the username does not hold it',
          JSON.stringify(members(ROLE)));
  log.debug("Leaving aPerson().");
}

function aGroup(t, made) {
  log.debug("Entering aGroup().");
  t.log.info('=== D. a group deleted ===');
  const gone = ldap.deleteGroupEntry(made.groupDn);
  t.check(gone && gone.ok && members(ROLE).groups.indexOf(GROUP) < 0,
          'D1. a deleted group is out of the role',
          JSON.stringify([gone, members(ROLE)]));
  log.debug("Leaving aGroup().");
}

function theCode(t) {
  log.debug("Entering theCode().");
  t.check(!!errorCodes.lookup ? !!errorCodes.lookup('STS-ADMIN-0919')
    : errorCodes.CODES.some(function (one) {
      return one.code === 'STS-ADMIN-0919';
    }), 'E1. STS-ADMIN-0919 is in the table');
  log.debug("Leaving theCode().");
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.create({ id: 'rmf-' + RUN,
                                name: 'role member forget ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      const made = setUp(t);
      anApplication(t);
      theOtherDoor(t);
      aPerson(t, made);
      aGroup(t, made);
      theCode(t);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'role_member_forget',
  describe: 'a deleted application, person or group is taken out of every ' +
            'role that named it, so nothing made again under its name ' +
            'inherits the role (2026-11-10)',
  run: run
};
