// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: remote_pep_service_accounts.js
//
// ===========================================================================
// A REMOTE PEP'S IDENTITY IS A SERVICE ACCOUNT, OWNED BY THE REALM'S
// ADMINISTRATORS (#1760), in process.
//
// rcbj: "The user that a remote PEP uses to map its client cert to and
// connect to the STS needs to be flagged as a service account. The realm
// admin can be listed as the owner." `common/service_accounts.ts`'s
// *A REMOTE PEP'S IDENTITY IS A SERVICE ACCOUNT* argues the design. What is
// held here, each in a throwaway realm:
//
//   A. THE SEED: a realm created through the console's own act seeds
//      `remote-pep-1` into the REMOTE_PEPS group, then its bootstrap
//      administrator, then makes the identity a service account owned by the
//      realm's Admin Write group; asking again changes nothing.
//   B. THE CHOKEPOINT: a person put in the group by the console's add-member
//      becomes one with that owner; a member of another group does not; an
//      account an administrator already owns keeps its owners; a realm with
//      nobody to own it DEFERS (STS-SVCACCT-0051) and writes nothing — even
//      with `requireOwner` off, since a service account always keeps an
//      owner. Nothing here un-makes an account or empties its owners.
//   C. THE DOORS: a browser session as the identity is refused
//      (STS-SVCACCT-0010); the PEP's own gate is not a door (its mTLS
//      registration and pull are `tests/xacml_pep_proxy.js` B1/C1, which run
//      as a service-account identity since #1760, B1s).
//   D. ROTATION: the hourly job skips it — no destination — and fails
//      nothing.
//   E. THE PEP PAGE'S ANSWER: `pepsJson()` carries `identityAccount` with
//      the flag and the owners.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
const serviceAccounts = require('../common/service_accounts');
const ldap = require('../ldap/ldap_server');
const authn = require('../authn/authn');
const adminActions = require('../admin-core/admin_actions');
const rotationModule = require('../common/service_account_rotation');
const peps = require('../xacml/xacml_pep_registry');
const xacmlAdmin = require('../xacml/xacml_admin');

const log = require('bunyan').createLogger({ name: 'remote_pep_svcacct',
  level: process.env.LOG_LEVEL || 'info' });

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + require('crypto').randomBytes(3).toString('hex');
}

function noBrowser() {
  log.debug('Entering noBrowser().');
  log.debug('Leaving noBrowser().');
  return { set: function () {}, req: null };
}

function pepGroup() {
  log.debug('Entering pepGroup().');
  log.debug('Leaving pepGroup().');
  return String(config.value('roles.remotePepGroup'));
}

function person(name) {
  log.debug('Entering person().');
  log.debug('Leaving person().');
  return ldap.createUser(name, { invent: false,
    attributes: { givenName: 'Remote', sn: name,
                  mail: name + '@example.test' } });
}

function ownerDns(facts) {
  log.debug('Entering ownerDns().');
  log.debug('Leaving ownerDns().');
  return ((facts && facts.owners) || []).map(function (one) {
    return String(one.dn).toLowerCase();
  });
}

// A realm made through the console's own create, so the order is the one a
// running service has: the realm's seed, its bootstrap administrator, then
// the designation.
async function withCreatedRealm(t, stem, fn) {
  log.debug('Entering withCreatedRealm(). ' + stem);
  const id = realmId(stem);
  const made = await adminActions.realmsAction({ action: 'create', id: id,
    name: id, description: 'Created by ' + __filename });
  if (!made || made.ok === false || !realms.get(id)) {
    t.bad('could not create the realm "' + id + '"', JSON.stringify(made));
    log.debug('Leaving withCreatedRealm(). Not created.');
    return undefined;
  }
  try {
    log.debug('Leaving withCreatedRealm().');
    return await realms.run(realms.get(id), function () {
      return fn(realms.get(id));
    });
  } finally {
    realms.remove(id);
  }
}

async function withBareRealm(t, stem, fn) {
  log.debug('Entering withBareRealm(). ' + stem);
  const id = realmId(stem);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withBareRealm(). Not created.');
    return undefined;
  }
  try {
    log.debug('Leaving withBareRealm().');
    return await realms.run(made.realm, function () {
      return fn(made.realm);
    });
  } finally {
    realms.remove(id);
  }
}

async function seed(t) {
  log.debug('Entering seed().');
  await withCreatedRealm(t, 'rpsa-seed', function () {
    const writers = ldap.readGroupEntry(ldap.groupDnFor(
      String(config.value('admin.writeGroup'))));
    t.check(!!writers, 'A0. the realm\'s create seeded its Admin Write group ' +
            '(its bootstrap administrator in it)');
    const writersDn = writers ? String(writers.dn).toLowerCase() : '';
    const seeded = ldap.readGroupEntry(ldap.groupDnFor(pepGroup()));
    const members = seeded ? seeded.members.map(function (one) {
      return String(one.dn).toLowerCase();
    }) : [];
    const pep = members.filter(function (dn) {
      return dn.indexOf('cn=remote-pep-1,') === 0;
    })[0];
    t.check(!!pep, 'A1. the realm\'s seed put cn=remote-pep-1 in the ' +
            'REMOTE_PEPS group', JSON.stringify(members));
    const facts = pep ? serviceAccounts.of(pep) : null;
    t.check(!!facts && ownerDns(facts).indexOf(writersDn) >= 0,
            'A2. the seeded PEP identity is a service account owned by the ' +
            'realm\'s Admin Write group', JSON.stringify(facts));
    t.check(!!facts && !facts.destination,
            'A3. it names no push destination: there is no password to push');
    const again = serviceAccounts.designateRemotePeps('a test');
    t.check(again.flagged === 0 && again.already >= 1 &&
            ownerDns(serviceAccounts.of(pep)).length === 1,
            'A4. designating again changes nothing (idempotent)',
            JSON.stringify(again));
  });
  log.debug('Leaving seed().');
}

async function chokepoint(t) {
  log.debug('Entering chokepoint().');
  await withCreatedRealm(t, 'rpsa-join', async function (realm) {
    const writersDn = String(ldap.groupDnFor(
      String(config.value('admin.writeGroup')))).toLowerCase();
    person('rpsa-pep');
    person('rpsa-other');
    person('rpsa-owned');
    person('rpsa-boss');
    t.check(!serviceAccounts.isServiceAccountName('rpsa-pep'),
            'B0. a new person is not a service account');
    const added = adminActions.groupsAction({ action: 'add-member',
      group: pepGroup(), member: 'rpsa-pep' });
    t.check(added && added.ok !== false, 'B1. the console\'s add-member put ' +
            'the person in the REMOTE_PEPS group', JSON.stringify(added));
    const facts = serviceAccounts.of('rpsa-pep');
    t.check(!!facts && ownerDns(facts).indexOf(writersDn) >= 0,
            'B2. GRANTING REMOTE_PEPS made the person a service account ' +
            'owned by the realm\'s Admin Write group', JSON.stringify(facts));
    ldap.createGroup('rpsa-ordinary');
    adminActions.groupsAction({ action: 'add-member',
      group: 'rpsa-ordinary', member: 'rpsa-other' });
    t.check(!serviceAccounts.isServiceAccountName('rpsa-other'),
            'B3. a member of any other group is not made one');
    serviceAccounts.set('rpsa-owned', { serviceAccount: true,
                                        owners: ['rpsa-boss'] });
    adminActions.groupsAction({ action: 'add-member', group: pepGroup(),
                                member: 'rpsa-owned' });
    const kept = ownerDns(serviceAccounts.of('rpsa-owned'));
    t.check(kept.length === 1 && kept[0].indexOf('uid=rpsa-boss,') === 0,
            'B4. an account an administrator already owns keeps its owners',
            JSON.stringify(kept));
    // C. THE DOORS.
    const detail = {};
    const browser = authn.startSession(noBrowser(), 'rpsa-pep', ['pwd'], '1',
                                       'a test', detail);
    t.check(browser === null && detail.refusedWith === 'STS-SVCACCT-0010',
            'C1. a browser sign-in as the PEP identity is refused',
            JSON.stringify(detail));
    // D. ROTATION.
    const rotation = new rotationModule.ServiceAccountRotation(
      rotationModule.ServiceAccountRotation.defaultDeps());
    const done = await rotation.rotateDue(realm.id, {});
    t.check(done.rotated === 0 && done.failed === 0 && done.skipped >= 2,
            'D1. the rotation job skips the PEP identities and fails nothing',
            JSON.stringify(done));
    // E. THE PEP PAGE'S ANSWER.
    const dn = String(facts ? facts.dn : '');
    peps.register({ name: 'rpsa-pep', identity: dn,
                    certificateSubject: 'CN=rpsa-pep', thumbprint: 'test',
                    authenticated: true, bias: 'deny',
                    resource: 'https://example.test/api' });
    const view = xacmlAdmin.pepsJson('rpsa-pep');
    const row = (view.peps || [])[0] || {};
    t.check(!!row.identityAccount && row.identityAccount.serviceAccount ===
            true && row.identityAccount.username === 'rpsa-pep' &&
            ownerDns(row.identityAccount).indexOf(writersDn) >= 0,
            'E1. the PEP page\'s answer marks the identity a service ' +
            'account with its owners', JSON.stringify(row.identityAccount));
  });
  await withBareRealm(t, 'rpsa-none', function () {
    // No create act: no bootstrap administrator and no Admin Write group.
    person('rpsa-orphan');
    const done = serviceAccounts.designateRemotePep('rpsa-orphan', 'a test');
    t.check(done.deferred === true && done.code === 'STS-SVCACCT-0051' &&
            !serviceAccounts.isServiceAccountName('rpsa-orphan'),
            'B5. with nobody to own it, it is ' +
            'DEFERRED and nothing is written', JSON.stringify(done));
    const policy = require('../common/service_account_policy');
    const saved = policy.save('default', Object.assign({}, policy.DEFAULTS,
                                                       { requireOwner: false }));
    try {
      const again = serviceAccounts.designateRemotePep('rpsa-orphan',
                                                       'a test');
      t.check(saved.ok && again.deferred === true &&
              !serviceAccounts.isServiceAccountName('rpsa-orphan'),
              'B6. and with requireOwner OFF it is still deferred: a PEP ' +
              'identity is never a service account without an owner',
              JSON.stringify({ saved: saved.ok, again: again }));
    } finally {
      policy.reset('default');
    }
  });
  log.debug('Leaving chokepoint().');
}

module.exports = {
  name: 'remote PEP service accounts',
  describe: 'A remote PEP\'s identity is a service account owned by the ' +
            'realm\'s Admin Write group (#1760): the seed, the membership ' +
            'chokepoint, the deferral, the browser door, rotation and the ' +
            'PEP page\'s answer',
  run: async function (t) {
    log.debug('Entering run().');
    await seed(t);
    await chokepoint(t);
    log.debug('Leaving run().');
  }
};
