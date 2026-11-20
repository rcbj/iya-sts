// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

const log = require('bunyan').createLogger({ name: 'role_selection',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: role_selection.js
//
// ===========================================================================
// DYNAMIC SELECTABLE ROLES: THE CHOICE AND WHAT A TOKEN CARRIES OF IT
// (#1072, phases P3 to P5).
//
//   S. THE CHOICE (`authn/role_selection.ts`'s validateChoice()): a role not
//      offered — fabricated, or another application's — is refused (0325),
//      two of one exclusive group (0326), a required role left out (0327),
//      a role no longer eligible between the offer and the submit (0328);
//      none chosen of optional roles is a choice; the rows are for the
//      sign-in's application.
//   R. THE READER (selectedFor()): the session's rows for the token's
//      application, each asked of its policy again; another application's
//      choice, an expired session, somebody else's session, an ended one
//      and a role no longer eligible carry nothing — and the last is
//      audited as roles.selection.dropped.
//   E. THE EFFECTIVE ROLE SET (`roles.js`): the roles claim and rolesOf()
//      carry a chosen role only with the session's id and for the
//      application it was chosen for; without the reader, nothing; a
//      member written onto a dynamic role by hand is not a holder; static
//      and group-held roles are unchanged beside it.
//   D. NOTHING IS WRITTEN: choosing changes no role entry and no group.
//
// In process, in a THROWAWAY REALM, the session store stood in for (a
// session is a record `sessionById()` answers).
// ===========================================================================

delete process.env.CONFIG_FILE;

const POLICY_ALFA = [
  'namespace sel {',
  '    attribute kind {',
  '        category = subjectCat',
  '        id = "employeeType"',
  '        type = string',
  '    }',
  '    policy eligible {',
  '        id = "urn:test:sel-eligible"',
  '        apply denyUnlessPermit',
  '        rule operators {',
  '            permit',
  '            target clause kind == "operator"',
  '        }',
  '    }',
  '}'
].join('\n');

// A policy that permits nobody: how a role's eligibility is LOST here.
const NOBODY_ALFA = POLICY_ALFA.replace('"operator"', '"nobody-at-all"')
  .replace('urn:test:sel-eligible', 'urn:test:sel-nobody');

function run(t) {
  log.debug("Entering run().");
  require('../common/config');
  require('../common/app');
  const ldap = require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const roles = require('../common/roles');
  const audit = require('../common/audit');
  const adminActions = require('../admin-core/admin_actions');
  const eligibility = require('../xacml/role_eligibility');
  const selection = require('../authn/role_selection');

  const id = 'sel-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  // THE SESSION STORE, stood in for: the reader asks `sessionById()`.
  const sessions = new Map();
  const instance = new selection.RoleSelection(Object.assign(
    selection.RoleSelection.defaultDeps(), {
      loadAuthn: function () {
        return { sessionById: function (sid) {
          return sessions.get(String(sid)) || null;
        } };
      }
    }));
  const reader = { selectedFor: function (context) {
    return instance.selectedFor(context);
  } };
  const before = roles.selectionReaderInstalled();
  const k = { ldap, errorCodes, roles, audit, eligibility, instance,
              sessions, reader, act: null };
  k.act = function (body) {
    return adminActions.rolesAction(body, { via: 'api', actor: 'tester' });
  };
  try {
    realms.run(made.realm, function () {
      log.debug("Entering realmBody().");
      ldap.createUser('sel-op', { invent: false,
        attributes: { employeeType: ['operator'] } });
      ldap.createUser('sel-clerk', { invent: false,
        attributes: { employeeType: ['clerk'] } });
      k.act({ action: 'create-role', role: 'sel-oncall',
              membershipMode: 'dynamic-selectable',
              exclusiveGroup: 'ops' });
      k.act({ action: 'create-role', role: 'sel-pager',
              membershipMode: 'dynamic-selectable', exclusiveGroup: 'ops' });
      k.act({ action: 'create-role', role: 'sel-must',
              membershipMode: 'dynamic-selectable', selection: 'required' });
      k.act({ action: 'create-role', role: 'sel-static' });
      k.act({ action: 'add-member', role: 'sel-static', kind: 'user',
              member: 'sel-op' });
      ['sel-oncall', 'sel-pager', 'sel-must'].forEach(function (name) {
        eligibility.setPolicy(name, { alfa: POLICY_ALFA });
      });
      sectionS(t, k);
      sectionR(t, k);
      sectionE(t, k);
      log.debug("Leaving realmBody().");
    });
  } finally {
    roles.setSelectionReader(before);
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

// S. The choice, held to the offer and the policy.
function sectionS(t, k) {
  log.debug("Entering sectionS().");
  t.log.info('=== S. the choice ===');
  const { eligibility, instance, roles } = k;
  const offered = eligibility.offer({ username: 'sel-op',
                                      application: 'sel-app' });
  t.check(offered.map(function (one) {
    return one.name;
  }).sort().join(',') === 'sel-must,sel-oncall,sel-pager',
          '(precondition) the operator is offered the three dynamic roles');
  const ask = function (chosen) {
    return instance.validateChoice({ username: 'sel-op',
                                     application: 'sel-app',
                                     offered: offered, chosen: chosen });
  };
  let r = ask(['sel-must', 'admin']);
  t.check(!r.ok && r.code === 'STS-XACML-0325',
          'S1. a fabricated role is refused (0325)', JSON.stringify(r));
  r = ask(['sel-must', 'sel-static']);
  t.check(!r.ok && r.code === 'STS-XACML-0325',
          'S2. a static role the person holds is not choosable (0325)');
  r = ask(['sel-must', 'sel-oncall', 'sel-pager']);
  t.check(!r.ok && r.code === 'STS-XACML-0326',
          'S3. two of one exclusive group are refused (0326)');
  r = ask(['sel-oncall']);
  t.check(!r.ok && r.code === 'STS-XACML-0327',
          'S4. leaving out every required role is refused (0327)');
  r = ask(['sel-must', 'sel-oncall']);
  t.check(r.ok && r.rows.length === 2 && r.rows.every(function (one) {
    return one.application === 'sel-app';
  }), 'S5. a good choice is the rows for the sign-in\'s application',
          JSON.stringify(r));
  // Eligibility lost between the offer and the submit.
  k.eligibility.setPolicy('sel-must', { alfa: NOBODY_ALFA });
  r = ask(['sel-must']);
  t.check(!r.ok && r.code === 'STS-XACML-0328',
          'S6. a role no longer eligible at submit is refused (0328)',
          JSON.stringify(r));
  k.eligibility.setPolicy('sel-must', { alfa: POLICY_ALFA });
  const optionalOnly = offered.filter(function (one) {
    return one.selection !== 'required';
  });
  r = instance.validateChoice({ username: 'sel-op', application: 'sel-app',
                                offered: optionalOnly, chosen: [] });
  t.check(r.ok && r.rows.length === 0,
          'S7. choosing none of optional roles is a choice of none');
  t.check(roles.read('sel-oncall').users.length === 0,
          'S8. nothing was written to the role');
  log.debug("Leaving sectionS().");
}

// R. The reader at issuance.
function sectionR(t, k) {
  log.debug("Entering sectionR().");
  t.log.info('=== R. what an issuance reads ===');
  const { instance, sessions, audit, eligibility } = k;
  const future = Date.now() + 3600 * 1000;
  sessions.set('s1', { id: 's1', user: 'sel-op', expires: future,
    selectedRoles: [{ role: 'sel-oncall', application: 'sel-app', at: 1 },
                    { role: 'sel-must', application: 'other-app', at: 1 }] });
  sessions.set('s2', { id: 's2', user: 'sel-op', expires: Date.now() - 1,
    selectedRoles: [{ role: 'sel-oncall', application: 'sel-app', at: 1 }] });
  let got = instance.selectedFor({ username: 'sel-op', sessionId: 's1',
                                   applications: ['sel-app'] });
  t.check(got.join(',') === 'sel-oncall',
          'R1. the session\'s choice for this application, and not ' +
          'another application\'s', JSON.stringify(got));
  t.equal(instance.selectedFor({ username: 'sel-op', sessionId: 's2',
                                 applications: ['sel-app'] }).length, 0,
          'R2. an expired session carries nothing');
  t.equal(instance.selectedFor({ username: 'sel-clerk', sessionId: 's1',
                                 applications: ['sel-app'] }).length, 0,
          'R3. somebody else\'s session carries nothing');
  t.equal(instance.selectedFor({ username: 'sel-op', sessionId: 'gone',
                                 applications: ['sel-app'] }).length, 0,
          'R4. an ended session (or an offline token past it) carries ' +
          'nothing');
  const since = Date.now() - 1;
  eligibility.setPolicy('sel-oncall', { alfa: NOBODY_ALFA });
  got = instance.selectedFor({ username: 'sel-op', sessionId: 's1',
                               applications: ['sel-app'] });
  const dropped = audit.list().filter(function (row) {
    return row.action === 'roles.selection.dropped' &&
           Number(row.at) >= since && row.target === 'sel-oncall';
  });
  t.check(got.length === 0 && dropped.length >= 1,
          'R5. a role no longer eligible is left off and audited as ' +
          'roles.selection.dropped', JSON.stringify({ got: got,
            dropped: dropped.length }));
  eligibility.setPolicy('sel-oncall', { alfa: POLICY_ALFA });
  log.debug("Leaving sectionR().");
}

// E. The effective role set.
function sectionE(t, k) {
  log.debug("Entering sectionE().");
  t.log.info('=== E. the effective role set ===');
  const { roles, reader, sessions } = k;
  const claimOf = function (extra) {
    const c = roles.claimFor(Object.assign({ kind: 'user', name: 'sel-op',
      authenticated: true, applications: ['sel-app'] }, extra || {}));
    return ((c && c.roles) || []).slice().sort().join(',');
  };
  roles.setSelectionReader(null);
  t.equal(claimOf({ sessionId: 's1' }), 'sel-static',
          'E1. with no reader installed, no dynamic role: only the static ' +
          'one held');
  roles.setSelectionReader(reader);
  t.equal(claimOf({}), 'sel-static',
          'E2. without a session id, no dynamic role');
  t.equal(claimOf({ sessionId: 's1' }), 'sel-oncall,sel-static',
          'E3. with the session, the chosen role beside the static one');
  t.equal(claimOf({ sessionId: 's1', applications: ['other-app'] }),
          'sel-must,sel-static',
          'E4. for another application, that application\'s choice only');
  t.check(roles.rolesOf({ kind: 'user', name: 'sel-op', authenticated: true,
                          application: 'sel-app', sessionId: 's1' })
    .indexOf('sel-oncall') >= 0,
          'E5. rolesOf(), which the issuance policy reads, holds it too');
  // A member put on a dynamic role behind the register's back.
  const row = roles.read('sel-pager');
  roles.directoryInstalled().writeRole('sel-pager', Object.assign({}, {
    objectClass: ['top', 'stsRole'], roleName: 'sel-pager',
    roleMemberUser: ['sel-op'], roleMembershipMode: ['dynamic-selectable'],
    roleEligibilityPolicy: [row.eligibilityPolicy] }));
  t.check(claimOf({}).split(',').indexOf('sel-pager') < 0,
          'E6. a member written onto a dynamic role is not a holder');
  sessions.set('s3', { id: 's3', user: 'sel-op',
                       expires: Date.now() + 3600 * 1000, selectedRoles: [] });
  t.equal(claimOf({ sessionId: 's3' }), 'sel-static',
          'E7. a session that chose nothing carries the static roles as ' +
          'before');
  log.debug("Leaving sectionE().");
}

module.exports = {
  name: 'role selection',
  describe: 'dynamic selectable roles: the choice held to the offer and ' +
            'the policy, what an issuance reads of it, and the effective ' +
            'role set (#1072 P3 to P5)',
  run: run
};
