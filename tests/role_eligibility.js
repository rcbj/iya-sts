// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';

const log = require('bunyan').createLogger({ name: 'role_eligibility',
  level: process.env.LOG_LEVEL || 'info' });
//
// File: role_eligibility.js
//
// ===========================================================================
// DYNAMIC SELECTABLE ROLES: THE DEFINITION AND THE ELIGIBILITY (#1072,
// phases P1 and P2).
//
// A dynamic role is held by nobody and offered at sign-in to whoever its
// own XACML policy permits (rcbj's decisions of 2026-11-20). What this file
// holds, each a lettered section below:
//
//   A. THE DEFINITION. A role is static by default and stays exactly what it
//      was; a dynamic role is made with create-role or set-membership-mode;
//      a dynamic role with a member, a member added to one, a conferring
//      client, a console or native role made dynamic, an unknown mode,
//      selection or exclusive group, and set-selection on a static role are
//      each refused with their code; switching the mode adds and removes
//      nothing.
//   B. THE POLICY. It is set from ALFA, owned (`xacmlRole`), never the root
//      and never in the PolicyIdReference map, refused as the root, kept
//      across a rewrite under the same entry name, and refused for a static
//      role.
//   C. THE DECISION. Only Permit is eligible: a person the policy permits
//      is, one it denies is not (0319), a role with no policy (0313), a
//      disabled policy (0316), a policy that is not the role's own (0315),
//      an application's role asked for another application (0320) and a
//      question naming nobody (0319) are not.
//   D. THE OFFER lists only the eligible, with what the role step shows and
//      nothing of the policy; each decision is audited.
//   E. THE TEST answers with the decision and what was asked.
//   F. DELETE takes the role's own policy with it.
//
// In process, in a THROWAWAY REALM, so ou=policies starts empty and "the
// only enabled policy" root fallback is reachable (`fga_policies.js`'s
// reason).
// ===========================================================================

delete process.env.CONFIG_FILE;

const POLICY_ALFA = [
  'namespace oncall {',
  '    attribute kind {',
  '        category = subjectCat',
  '        id = "employeeType"',
  '        type = string',
  '    }',
  '    policy eligible {',
  '        id = "urn:test:oncall-eligible"',
  '        apply denyUnlessPermit',
  '        rule operators {',
  '            permit',
  '            target clause kind == "operator"',
  '        }',
  '    }',
  '}'
].join('\n');

function run(t) {
  log.debug("Entering run().");
  require('../common/config');
  require('../common/app');
  const ldap = require('../ldap/ldap_server');
  const realms = require('../common/realms');
  const errorCodes = require('../common/error_codes');
  const roles = require('../common/roles');
  const store = require('../xacml/xacml_store');
  const audit = require('../common/audit');
  const adminActions = require('../admin-core/admin_actions');
  const eligibility = require('../xacml/role_eligibility');

  const id = 'dyn-' + Date.now().toString(36);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  t.check(made.ok, 'a trust realm to work in', (made.errors || []).join(' '));
  if (!made.ok) {
    log.debug("Leaving run(). No realm.");
    return;
  }
  const k = { ldap, errorCodes, roles, store, audit, adminActions,
              eligibility, act: null };
  k.act = function (body) {
    log.debug("Entering act().");
    log.debug("Leaving act().");
    return adminActions.rolesAction(body, { via: 'api', actor: 'tester' });
  };
  try {
    realms.run(made.realm, function () {
      log.debug("Entering realmBody().");
      ldap.createUser('dyn-operator', { invent: false,
        attributes: { employeeType: ['operator'] } });
      ldap.createUser('dyn-clerk', { invent: false,
        attributes: { employeeType: ['clerk'] } });
      sectionA(t, k);
      sectionB(t, k);
      sectionC(t, k);
      sectionDtoF(t, k);
      log.debug("Leaving realmBody().");
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

// A. The definition and its rules.
function sectionA(t, k) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. a role, static or dynamic ===');
  const { roles, act, errorCodes } = k;
  let r = act({ action: 'create-role', role: 'dyn-static',
                description: 'A static role' });
  t.check(r.ok && roles.read('dyn-static').membershipMode === 'static' &&
          !roles.isDynamic(roles.read('dyn-static')),
          'A1. a role is static by default', JSON.stringify(r));
  r = act({ action: 'create-role', role: 'oncall',
            membershipMode: 'dynamic-selectable', selection: 'optional',
            exclusiveGroup: 'operations', displayName: 'On call' });
  const oncall = roles.read('oncall');
  t.check(r.ok && roles.isDynamic(oncall) && oncall.selection === 'optional' &&
          oncall.exclusiveGroup === 'operations' &&
          oncall.displayName === 'On call',
          'A2. a dynamic role is made with create-role', JSON.stringify(r));
  t.check(roles.dynamicRoles().map(function (one) {
    return one.name;
  }).join(',') === 'oncall', 'A3. dynamicRoles() lists it and nothing else');
  r = act({ action: 'add-member', role: 'oncall', kind: 'user',
            member: 'dyn-operator' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0304' &&
          roles.read('oncall').users.length === 0,
          'A4. a member cannot be added to a dynamic role (STS-XACML-0304)',
          JSON.stringify(r));
  t.check(act({ action: 'add-member', role: 'dyn-static', kind: 'user',
                member: 'dyn-clerk' }).ok,
          '(precondition) the static role has a member');
  r = act({ action: 'set-membership-mode', role: 'dyn-static',
            mode: 'dynamic-selectable' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0304' &&
          roles.read('dyn-static').users.join() === 'dyn-clerk' &&
          !roles.isDynamic(roles.read('dyn-static')),
          'A5. a role with a member cannot be made dynamic, and keeps it',
          JSON.stringify(r));
  r = act({ action: 'set-membership-mode', role: 'ADMIN_READ',
            mode: 'dynamic-selectable' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0305',
          'A6. a native role cannot be made dynamic (STS-XACML-0305)',
          JSON.stringify(r));
  r = act({ action: 'set-membership-mode', role: 'oncall', mode: 'sometimes' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0303',
          'A7. an unknown mode is refused (STS-XACML-0303)');
  r = act({ action: 'set-selection', role: 'oncall', selection: 'often' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0306',
          'A8. an unknown selection is refused (STS-XACML-0306)');
  r = act({ action: 'set-selection', role: 'oncall',
            exclusiveGroup: 'not a name!' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0307',
          'A9. a malformed exclusive group is refused (STS-XACML-0307)');
  r = act({ action: 'set-selection', role: 'dyn-static',
            selection: 'required' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0309',
          'A10. a static role has no selection (STS-XACML-0309)');
  r = act({ action: 'set-selection', role: 'oncall', selection: 'required' });
  t.check(r.ok && roles.read('oncall').selection === 'required' &&
          roles.read('oncall').exclusiveGroup === 'operations',
          'A11. set-selection changes what it names and keeps the rest',
          JSON.stringify(r));
  r = act({ action: 'describe-role', role: 'oncall',
            description: 'Operations on call' });
  t.check(r.ok && roles.isDynamic(roles.read('oncall')) &&
          roles.read('oncall').selection === 'required',
          'A12. a describe-role keeps the mode and the selection');
  // Back and forth: nothing added or removed either way.
  t.check(act({ action: 'create-role', role: 'dyn-flip',
                displayName: 'Flip' }).ok,
          '(precondition) a role to switch');
  const permsBefore = roles.read('dyn-flip').permissions.join(',') + '|' +
    roles.read('dyn-flip').displayName;
  const there = act({ action: 'set-membership-mode', role: 'dyn-flip',
                      mode: 'dynamic-selectable' });
  const back = act({ action: 'set-membership-mode', role: 'dyn-flip',
                     mode: 'static' });
  t.check(there.ok && back.ok &&
          roles.read('dyn-flip').permissions.join(',') + '|' +
            roles.read('dyn-flip').displayName === permsBefore &&
          roles.read('dyn-flip').users.length === 0 &&
          roles.read('dyn-flip').membershipMode === 'static',
          'A13. switching the mode there and back adds and removes nothing',
          JSON.stringify({ there: there.ok, back: back.ok }));
  act({ action: 'set-selection', role: 'oncall', selection: 'optional' });
  log.debug("Leaving sectionA().");
}

// B. The policy: owned, never the root, never in the map.
function sectionB(t, k) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. the role\'s own policy ===');
  const { roles, store, act, errorCodes } = k;
  let r = act({ action: 'set-eligibility-policy', role: 'dyn-static',
                alfa: POLICY_ALFA });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0312',
          'B1. a static role has no eligibility policy (STS-XACML-0312)');
  r = act({ action: 'set-eligibility-policy', role: 'oncall' });
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-XACML-0321',
          'B2. neither source is refused (STS-XACML-0321)');
  r = act({ action: 'set-eligibility-policy', role: 'oncall',
            alfa: POLICY_ALFA });
  const name = r.policy;
  const row = name ? store.read(name) : null;
  t.check(r.ok && r.created && row && row.role === 'oncall' &&
          !row.application && roles.read('oncall').eligibilityPolicy === name,
          'B3. set from ALFA: written with xacmlRole and named on the role',
          JSON.stringify(r));
  t.check(store.owned(row) && !store.root() &&
          !Object.prototype.hasOwnProperty.call(store.repository(),
                                                 'urn:test:oncall-eligible'),
          'B4. it is owned: not the root (even as the realm\'s only ' +
          'policy) and not in the PolicyIdReference map');
  const asRoot = store.write(name, row.document, { isRoot: true });
  t.check(!asRoot.ok && errorCodes.codeOf(asRoot) === 'STS-XACML-0310',
          'B5. it cannot be made the root (STS-XACML-0310)');
  const edited = store.write(name, row.document, { enabled: true });
  t.check(edited.ok && store.read(name).role === 'oncall',
          'B6. an edit through the store keeps the owner');
  r = act({ action: 'set-eligibility-policy', role: 'oncall',
            alfa: POLICY_ALFA });
  t.check(r.ok && !r.created && r.policy === name,
          'B7. a rewrite keeps the same entry name', JSON.stringify(r));
  log.debug("Leaving sectionB().");
}

// C. The decision: only Permit.
function sectionC(t, k) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. only Permit is eligible ===');
  const { roles, store, act, eligibility } = k;
  let a = eligibility.decide({ role: 'oncall', username: 'dyn-operator',
                               stage: 'offer' });
  t.check(a.eligible === true && a.decision === 'Permit',
          'C1. a person the policy permits is eligible', JSON.stringify(a));
  a = eligibility.decide({ role: 'oncall', username: 'dyn-clerk',
                           stage: 'offer' });
  t.check(a.eligible === false && a.code === 'STS-XACML-0319' &&
          a.decision === 'Deny',
          'C2. a person it denies is not (STS-XACML-0319)', JSON.stringify(a));
  a = eligibility.decide({ role: 'oncall', username: '', stage: 'offer' });
  t.check(!a.eligible && a.code === 'STS-XACML-0319',
          'C3. a question naming nobody is not eligible');
  a = eligibility.decide({ role: 'dyn-static', username: 'dyn-operator' });
  t.check(!a.eligible && a.code === 'STS-XACML-0312',
          'C4. a static role is never offered (STS-XACML-0312)');
  act({ action: 'create-role', role: 'dyn-nopolicy',
        membershipMode: 'dynamic-selectable' });
  a = eligibility.decide({ role: 'dyn-nopolicy', username: 'dyn-operator' });
  t.check(!a.eligible && a.code === 'STS-XACML-0313',
          'C5. a dynamic role with no policy has nobody eligible (0313)');
  const name = roles.read('oncall').eligibilityPolicy;
  const row = store.read(name);
  store.write(name, row.document, { enabled: false });
  a = eligibility.decide({ role: 'oncall', username: 'dyn-operator' });
  t.check(!a.eligible && a.code === 'STS-XACML-0316',
          'C6. a disabled policy makes nobody eligible (0316)');
  store.write(name, row.document, { enabled: true });
  // Not its own: the reference names an entry another role owns.
  act({ action: 'create-role', role: 'dyn-borrower',
        membershipMode: 'dynamic-selectable' });
  const borrower = roles.read('dyn-borrower');
  roles.write('dyn-borrower', Object.assign({}, borrower,
                                            { eligibilityPolicy: name }));
  a = eligibility.decide({ role: 'dyn-borrower', username: 'dyn-operator' });
  t.check(!a.eligible && a.code === 'STS-XACML-0315',
          'C7. a policy that is another role\'s is never adopted (0315)');
  // An application's role, asked for another application.
  roles.write('oncall@dyn-app', { application: 'dyn-app',
                                  membershipMode: 'dynamic-selectable' });
  const appRole = eligibility.setPolicy('oncall@dyn-app',
                                        { alfa: POLICY_ALFA });
  a = eligibility.decide({ role: 'oncall@dyn-app', username: 'dyn-operator',
                           application: 'other-app' });
  const own = eligibility.decide({ role: 'oncall@dyn-app',
                                   username: 'dyn-operator',
                                   application: 'dyn-app' });
  t.check(appRole.ok && !a.eligible && a.code === 'STS-XACML-0320' &&
          own.eligible,
          'C8. an application\'s role is offered only on a sign-in to it ' +
          '(0320)', JSON.stringify({ other: a.code, own: own.eligible }));
  log.debug("Leaving sectionC().");
}

// D, E, F: the offer, the test, the delete.
function sectionDtoF(t, k) {
  log.debug("Entering sectionDtoF().");
  t.log.info('=== D. the offer ===');
  const { roles, store, act, eligibility, audit } = k;
  const offered = eligibility.offer({ username: 'dyn-operator',
                                      application: 'some-app' });
  const names = offered.map(function (one) {
    return one.name;
  });
  t.check(names.join(',') === 'oncall',
          'D1. the offer lists the eligible realm-wide role and not the ' +
          'unconfigured, borrowed or other application\'s ones',
          JSON.stringify(names));
  const row = offered[0] || {};
  t.check(row.displayName === 'On call' && row.selection === 'optional' &&
          row.exclusiveGroup === 'operations' &&
          !Object.prototype.hasOwnProperty.call(row, 'policy') &&
          !Object.prototype.hasOwnProperty.call(row, 'eligibilityPolicy'),
          'D2. each row carries what the step shows and nothing of the ' +
          'policy', JSON.stringify(row));
  t.equal(eligibility.offer({ username: 'dyn-clerk',
                              application: 'some-app' }).length, 0,
          'D3. a person no policy permits is offered nothing');
  const recorded = audit.list().filter(function (one) {
    return one.action === 'roles.eligibility';
  });
  t.check(recorded.some(function (one) {
    return /dyn-operator/.test(String(one.summary || '')) &&
           one.target === 'oncall';
  }) && recorded.some(function (one) {
    return /dyn-clerk/.test(String(one.summary || '')) &&
           one.errorCode === 'STS-XACML-0319';
  }), 'D4. each offer decision is audited as roles.eligibility, a refusal ' +
     'with its code', String(recorded.length));

  t.log.info('=== E. the administrator\'s test ===');
  const tested = eligibility.test('oncall', 'dyn-clerk',
                                  { application: 'some-app' });
  t.check(tested.eligible === false && tested.decision === 'Deny' &&
          tested.code === 'STS-XACML-0319' && tested.asked.stage === 'test',
          'E1. the test says who is not eligible and why, as the PDP ' +
          'decided it', JSON.stringify(tested));

  t.log.info('=== F. delete takes the policy with it ===');
  const policy = roles.read('oncall').eligibilityPolicy;
  const deleted = act({ action: 'delete-role', role: 'oncall' });
  t.check(deleted.ok && !roles.read('oncall') && !store.read(policy),
          'F1. deleting the role removes its own policy', policy);
  log.debug("Leaving sectionDtoF().");
}

module.exports = {
  name: 'role eligibility',
  describe: 'dynamic selectable roles: the definition and its rules, each ' +
            'role\'s own XACML eligibility policy, only Permit eligible ' +
            '(#1072 P1, P2)',
  run: run
};
