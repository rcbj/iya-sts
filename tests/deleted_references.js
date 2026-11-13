// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: deleted_references.js
//
// ===========================================================================
// A DELETED CLIENT CONFERS NOTHING, AND A DELETED OWNER OWNS NOTHING
// (2026-11-13, the review of #1612's PR #1613).
//
// rcbj's rule on #1612: a deleted application, person or group leaves every
// role and group that named it, so a namesake made later inherits nothing.
// `role_member_forget.js` holds the member lists. Two other kinds of
// reference were left behind, and this file holds both:
//
//   A. A ROLE'S `roleConferredBy`. forgetMember() wrote each role back
//      without naming it, which write() reads as "keep what is there", so a
//      deleted application's identifier stayed and the next application
//      registered under it — in development, whoever presents the
//      client_id — conferred the role on everybody signing in through it.
//      Deleted and made again under the same identifier, it confers nothing;
//      another client conferring the same role keeps it; a `roles.unconfer`
//      row is written.
//   B. THE OWNERS (#604, #603, #600), which under #607 are issued
//      owner:write: a person who owned a group, a role, an application and
//      a service account, deleted and made again at the same DN, owns none
//      of them; a `roles.remove-owner`, `group.remove-owner`,
//      `application.remove-owner` and `admin.service-account.owner-removed`
//      row says so; a co-owner is kept.
//   C. A GROUP that owned a role and a group, deleted and made again under
//      the same cn, owns neither.
//   D. A RENAME CARRIES OWNERSHIP: a person renamed by an LDAP modifyDN
//      (deleteOldRdn) owns the same four things under the new DN, and
//      nothing names the old one.
//   E. The three codes are in the table.
//
// IN A THROWAWAY REALM, removed at the end (role_member_forget.js's
// arrangement).
// ===========================================================================
delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const realms = require('../common/realms');
const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const roles = require('../common/roles');
const audit = require('../common/audit');
const serviceAccounts = require('../common/service_accounts');
const adminActions = require('../admin-core/admin_actions');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({ name: 'deleted_references',
  level: process.env.LOG_LEVEL || 'info' });

const RUN = nodeCrypto.randomBytes(3).toString('hex');

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

function dnOf(made) {
  log.debug("Entering dnOf().");
  log.debug("Leaving dnOf().");
  return typeof made === 'string' ? made : String((made && made.dn) || '');
}

function key(dn) {
  log.debug("Entering key().");
  log.debug("Leaving key().");
  return String(dn || '').trim().toLowerCase().replace(/\s*,\s*/g, ',');
}

// Whether a list of owner DNs (strings or `{ dn }`) names `dn`.
function names(list, dn) {
  log.debug("Entering names().");
  const wanted = key(dn);
  const found = (list || []).some(function (one) {
    return key(typeof one === 'string' ? one : one && one.dn) === wanted;
  });
  log.debug("Leaving names(). " + found);
  return found;
}

// What each of the four registers says a group, a role, an application and a
// service account are owned by.
function ownersNow(things) {
  log.debug("Entering ownersNow().");
  const group = ldap.groupOwnership(things.group) || {};
  const role = roles.read(things.role) || {};
  const app = applications.ownersOf(things.app);
  const account = serviceAccounts.of(things.account) || {};
  log.debug("Leaving ownersNow().");
  return { group: group.owners || [], role: role.owners || [],
           app: app || [], account: account.owners || [] };
}

// The audit rows of one action since a mark (`at` is milliseconds).
function rowsOf(action, since) {
  log.debug("Entering rowsOf(). " + action);
  const rows = audit.list().filter(function (row) {
    return row.action === action && Number(row.at) >= since;
  });
  log.debug("Leaving rowsOf(). " + rows.length);
  return rows;
}

// A group, a role, an application and a service account, each owned by
// `ownerDn` (and the group and role by `coOwnerDn` as well, when given).
function ownedThings(t, label, ownerDn, coOwnerDn) {
  log.debug("Entering ownedThings(). " + label);
  const things = { group: 'dr-' + label + '-group-' + RUN,
                   role: 'dr-' + label + '-role-' + RUN,
                   app: 'dr-' + label + '-app-' + RUN,
                   account: 'dr-' + label + '-sa-' + RUN };
  const group = ldap.createGroup(things.group, { members: [] });
  const role = rolesAction({ action: 'create-role', role: things.role });
  const app = makeApplication(things.app);
  const person = ldap.createUser(things.account,
                                 { invent: false, attributes: {} });
  const owners = [ownerDn].concat(coOwnerDn ? [coOwnerDn] : []);
  const adds = [];
  owners.forEach(function (dn) {
    adds.push(ldap.addGroupOwner(things.group, dn, { actor: 'test' }));
    adds.push(rolesAction({ action: 'add-owner', role: things.role,
                            owner: dn }));
  });
  adds.push(applications.addOwner(things.app, ownerDn));
  adds.push(serviceAccounts.set(things.account, { serviceAccount: true,
                                                  owners: owners }));
  const now = ownersNow(things);
  t.check(group.ok && role.ok && app.ok && !!dnOf(person) &&
          adds.every(function (one) {
            return one && one.ok;
          }) && names(now.group, ownerDn) && names(now.role, ownerDn) &&
          names(now.app, ownerDn) && names(now.account, ownerDn),
          'precondition (' + label + '): ' + ownerDn + ' owns a group, a ' +
          'role, an application and a service account',
          JSON.stringify({ adds: adds, now: now }));
  log.debug("Leaving ownedThings().");
  return things;
}

function conferral(t) {
  log.debug("Entering conferral().");
  t.log.info('=== A. a deleted client confers nothing ===');
  const role = 'dr-conferred-' + RUN;
  const app = 'dr-confers-' + RUN;
  const other = 'dr-confers-too-' + RUN;
  const made = [makeApplication(app), makeApplication(other),
    rolesAction({ action: 'create-role', role: role }),
    rolesAction({ action: 'add-conferring-client', role: role, client: app }),
    rolesAction({ action: 'add-conferring-client', role: role,
                  client: other })];
  t.check(made.every(function (one) {
    return one && one.ok;
  }) && roles.conferredBy(app).indexOf(role) >= 0,
          'precondition: two applications confer the role',
          JSON.stringify(made));
  const since = Date.now();
  const forgot = adminActions.applicationsAction({ action: 'forget',
    application: app }, ['oauth2'], { actor: 'test' });
  const row = roles.read(role) || {};
  t.check(forgot && forgot.ok &&
          (row.conferredBy || []).indexOf(app) < 0 &&
          roles.conferredBy(app).length === 0,
          'A1. the forgotten application is off the role\'s conferring ' +
          'clients', JSON.stringify([forgot, row.conferredBy]));
  t.check((row.conferredBy || []).indexOf(other) >= 0 &&
          roles.conferredBy(other).indexOf(role) >= 0,
          'A2. the other client conferring the role keeps it',
          JSON.stringify(row.conferredBy));
  const again = makeApplication(app);
  t.check(again && again.ok && roles.conferredBy(app).length === 0,
          'A3. an application made again under its identifier confers ' +
          'nothing', JSON.stringify([again, roles.conferredBy(app)]));
  const unconfer = rowsOf('roles.unconfer', since).filter(function (one) {
    return String(one.target) === app;
  });
  t.check(unconfer.length === 1,
          'A4. one roles.unconfer row names the deleted application',
          JSON.stringify(unconfer));
  // The other door to the same entry, the registry's own delete.
  rolesAction({ action: 'add-conferring-client', role: role, client: app });
  const gone = applications.deleteApplication(app, { actor: 'test' });
  t.check(gone && gone.ok && roles.conferredBy(app).length === 0,
          'A5. deleteApplication() takes it off as well',
          JSON.stringify([gone, (roles.read(role) || {}).conferredBy]));
  log.debug("Leaving conferral().");
}

function aPerson(t) {
  log.debug("Entering aPerson().");
  t.log.info('=== B. a deleted person owns nothing ===');
  const name = 'dr-owner-' + RUN;
  const co = 'dr-co-owner-' + RUN;
  const ownerDn = dnOf(ldap.createUser(name, { invent: false,
                                               attributes: {} }));
  const coDn = dnOf(ldap.createUser(co, { invent: false, attributes: {} }));
  const things = ownedThings(t, 'person', ownerDn, coDn);
  const since = Date.now();
  const gone = ldap.deletePerson(ownerDn, { door: 'the test' });
  const after = ownersNow(things);
  t.check(gone && gone.ok && !names(after.group, ownerDn) &&
          !names(after.role, ownerDn) && !names(after.app, ownerDn) &&
          !names(after.account, ownerDn),
          'B1. the deleted person is off the owners of the group, the ' +
          'role, the application and the service account',
          JSON.stringify([gone, after]));
  t.check(names(after.group, coDn) && names(after.role, coDn) &&
          names(after.account, coDn),
          'B2. the co-owner is kept on each', JSON.stringify(after));
  const again = dnOf(ldap.createUser(name, { invent: false,
                                             attributes: {} }));
  const now = ownersNow(things);
  t.check(key(again) === key(ownerDn) && !names(now.group, again) &&
          !names(now.role, again) && !names(now.app, again) &&
          !names(now.account, again),
          'B3. somebody made again at the same DN owns none of them',
          JSON.stringify([again, now]));
  t.check(ldap.groupsOwnedBy([again]).length === 0,
          'B4. and the portal\'s Resources I own finds no group for them',
          JSON.stringify(ldap.groupsOwnedBy([again])));
  const rows = ['roles.remove-owner', 'group.remove-owner',
                'application.remove-owner',
                'admin.service-account.owner-removed'].map(function (one) {
    return rowsOf(one, since).length;
  });
  t.check(rows.every(function (n) {
    return n >= 1;
  }), 'B5. each removal is audited under its remove-owner action',
          JSON.stringify(rows));
  log.debug("Leaving aPerson().");
}

function aGroup(t) {
  log.debug("Entering aGroup().");
  t.log.info('=== C. a deleted group owns nothing ===');
  const name = 'dr-owner-group-' + RUN;
  const made = ldap.createGroup(name, { members: [] });
  const groupDn = made && made.dn;
  const owned = 'dr-owned-group-' + RUN;
  const role = 'dr-owned-role-' + RUN;
  const setUp = [ldap.createGroup(owned, { members: [] }),
    rolesAction({ action: 'create-role', role: role }),
    ldap.addGroupOwner(owned, groupDn, { actor: 'test' }),
    rolesAction({ action: 'add-owner', role: role, owner: groupDn })];
  t.check(made && made.ok && setUp.every(function (one) {
    return one && one.ok;
  }), 'precondition: a group owns a group and a role',
          JSON.stringify(setUp));
  const gone = ldap.deleteGroupEntry(groupDn);
  ldap.createGroup(name, { members: [] });
  const groupOwners = (ldap.groupOwnership(owned) || {}).owners || [];
  const roleOwners = (roles.read(role) || {}).owners || [];
  t.check(gone && gone.ok && !names(groupOwners, groupDn) &&
          !names(roleOwners, groupDn),
          'C1. the deleted group, made again under its cn, owns neither',
          JSON.stringify([gone, groupOwners, roleOwners]));
  log.debug("Leaving aGroup().");
}

// One LDAP operation as the socket would hand it to the directory.
async function ldapOp(operation, fields) {
  log.debug("Entering ldapOp(). " + operation);
  const out = await Promise.resolve(ldap.performOperation(operation,
    Object.assign({ boundDn: 'cn=dr-test', channel: 'ldaps' }, fields)));
  log.debug("Leaving ldapOp().");
  return out || {};
}

async function aRename(t) {
  log.debug("Entering aRename().");
  t.log.info('=== D. a rename carries ownership ===');
  const before = 'dr-before-' + RUN;
  const after = 'dr-after-' + RUN;
  const oldDn = dnOf(ldap.createUser(before, { invent: false,
                                               attributes: {} }));
  const things = ownedThings(t, 'renamed', oldDn, '');
  const renamed = await ldapOp('modifyDN', { dn: oldDn,
    newRdn: 'uid=' + after, newSuperior: '', deleteOldRdn: true });
  const newDn = 'uid=' + after + ',' + ldap.usersDn();
  const now = ownersNow(things);
  t.check(renamed.ok === true && names(now.group, newDn) &&
          names(now.role, newDn) && names(now.app, newDn) &&
          names(now.account, newDn),
          'D1. the renamed person owns all four under the new DN',
          JSON.stringify([renamed, now]));
  t.check(!names(now.group, oldDn) && !names(now.role, oldDn) &&
          !names(now.app, oldDn) && !names(now.account, oldDn),
          'D2. and nothing names the old DN', JSON.stringify(now));
  log.debug("Leaving aRename().");
}

function theCodes(t) {
  log.debug("Entering theCodes().");
  ['STS-ADMIN-0921', 'STS-ADMIN-0922', 'STS-ADMIN-0923']
    .forEach(function (code) {
      t.check(errorCodes.CODES.some(function (one) {
        return one.code === code;
      }), 'E1. ' + code + ' is in the table');
    });
  log.debug("Leaving theCodes().");
}

async function run(t) {
  log.debug("Entering run().");
  const realm = realms.create({ id: 'dr-' + RUN,
                                name: 'deleted references ' + RUN }).realm;
  try {
    await realms.run(realm, async function () {
      conferral(t);
      aPerson(t);
      aGroup(t);
      await aRename(t);
      theCodes(t);
    });
  } finally {
    realms.remove(realm.id);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'deleted_references',
  describe: 'a deleted application confers no role, and a deleted person ' +
            'or group owns nothing, so nothing made again under its name ' +
            'or DN inherits either; a rename carries ownership (2026-11-13, ' +
            '#1612)',
  run: run
};
