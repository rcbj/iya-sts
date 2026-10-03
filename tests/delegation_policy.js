// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: delegation_policy.js
//
// ===========================================================================
// WHO MAY ACT FOR WHOM, AND AS WHAT — THE FACTS FROM THE DIRECTORY (#186).
//
// `tests/exchange_policy.js` holds the issuance policy's exchange rules to a
// truth table and an oracle over facts it builds itself. This file is the
// other half: `common/delegation_policy.ts` GATHERING those facts from real
// entries — applications, people, groups, roles, settings — and asking, in
// BOTH modes (only `enforced` differs, which is development's "would have
// been refused"):
//
//   A. DELEGATION: actor = S, actor = R, resource-based, a third application
//      R accepts by name, no relationship, an actor outside the chain, an
//      audience resolved to the application that registered it;
//   B. IMPERSONATION and THE SEMANTICS: appDelegationSemantics on the actor,
//      the actor's default, a person's stsDelegationSemantics, the realm's
//      delegation.defaultSemantics;
//   C. PROTECTED SUBJECTS: appDelegationSubjectGroup, stsNotDelegated, the
//      console roster, delegation.protectedGroups, appNotDelegated;
//   D. TARGETS: unregistered, none, two;
//   E. THE ACTOR: a person without and with delegation.actorRole, an actor
//      nobody knows;
//   F. may_act: naming somebody else (refused in every mode), naming the
//      actor (standing in for the subject groups);
//   G. SELF: an application for itself, a client for its own audience;
//   H. AUTHORITY: the subject's roles against what S requires;
//   I. A REALM'S OWN POLICY refusing one actor, and saying nothing of others;
//   J. THE PERSON'S HALF: stsMayAct and the may_act claim; mayActNames();
//   K. THE ATTRIBUTES' GRAMMAR (STS-REG-0194) and list() as a register;
//   L. WS-TRUST through `handleRst()`, every refusal a SOAP Fault;
//   N. THE CONSOLE'S DOOR, set-delegation-semantics among the actions.
//
// IN PROCESS, in a throwaway realm, because it is a truth table over two
// modes and a directory. The token endpoint is
// `tests/token_exchange_product.js` and the over-HTTP job
// `tests/vendored/sts_delegation_policy.js`.
// ===========================================================================

delete process.env.CONFIG_FILE;

const config = require('../common/config');
const realms = require('../common/realms');
require('../common/app');
const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const roles = require('../common/roles');
const policy = require('../common/delegation_policy');
const store = require('../xacml/xacml_store');
// Arms `issuance_gate.js`'s decider, the PEP the exchange questions go to.
require('../xacml/xacml_role_pep');

const log = require('bunyan').createLogger({ name: 'delegation_policy',
  level: process.env.LOG_LEVEL || 'info' });

const STAFF = 'dp-staff';
const PROTECTED = 'dp-protected';
const AUDIENCE = 'https://dp-back.example';

// A realm policy refusing every exchange whose actor is `dp-front`, with the
// exchange obligation — and saying nothing about anything else.
const REFUSE_FRONT_POLICY =
  '<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" ' +
  'PolicyId="dp-refuse-front" Version="1.0" RuleCombiningAlgId="' +
  'urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">' +
  '<Target/><Rule RuleId="refuse-dp-front" Effect="Deny"><Target><AnyOf>' +
  '<AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:' +
  'string-equal"><AttributeValue DataType="http://www.w3.org/2001/' +
  'XMLSchema#string">exchange-token</AttributeValue><AttributeDesignator ' +
  'AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" ' +
  'Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" ' +
  'DataType="http://www.w3.org/2001/XMLSchema#string" ' +
  'MustBePresent="false"/></Match><Match MatchId="urn:oasis:names:tc:' +
  'xacml:1.0:function:string-equal"><AttributeValue DataType="http://' +
  'www.w3.org/2001/XMLSchema#string">dp-front</AttributeValue>' +
  '<AttributeDesignator AttributeId="urn:oasis:names:tc:xacml:1.0:' +
  'subject:subject-id" Category="urn:oasis:names:tc:xacml:1.0:' +
  'subject-category:intermediary-subject" DataType="http://www.w3.org/' +
  '2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf>' +
  '</AnyOf></Target><ObligationExpressions><ObligationExpression ' +
  'ObligationId="urn:sts:xacml:obligation:exchange" FulfillOn="Deny">' +
  '<AttributeAssignmentExpression AttributeId="urn:sts:xacml:exchange-' +
  'verdict"><AttributeValue DataType="http://www.w3.org/2001/' +
  'XMLSchema#string">refuse</AttributeValue>' +
  '</AttributeAssignmentExpression><AttributeAssignmentExpression ' +
  'AttributeId="urn:sts:xacml:exchange-refusal"><AttributeValue ' +
  'DataType="http://www.w3.org/2001/XMLSchema#string">policy' +
  '</AttributeValue></AttributeAssignmentExpression>' +
  '<AttributeAssignmentExpression AttributeId="urn:sts:xacml:exchange-' +
  'enforced"><AttributeValue DataType="http://www.w3.org/2001/' +
  'XMLSchema#boolean">true</AttributeValue>' +
  '</AttributeAssignmentExpression></ObligationExpression>' +
  '</ObligationExpressions></Rule></Policy>';

function inMode(m, fn) {
  log.debug("Entering inMode(). " + m);
  config.setOverride('global.mode', m);
  try {
    log.debug("Leaving inMode().");
    return fn();
  } finally {
    config.clearOverride('global.mode');
  }
}

// A token exchange: the subject token was issued for `source`.
function decide(asked) {
  log.debug("Entering decide().");
  log.debug("Leaving decide().");
  return policy.decide(Object.assign({ protocol: 'OAuth 2.0',
    targetKind: 'audience', requested: '' }, asked));
}

function fixtures(t) {
  log.debug("Entering fixtures().");
  ['dp-alice', 'dp-bob', 'dp-carol', 'dp-dave', 'dp-erin', 'dp-frank']
    .forEach(function (name) {
      dir.createUser(name, { invent: false });
    });
  const staff = dir.createGroup(STAFF, { origin: 'test' });
  t.check(staff.ok, 'precondition: the subject group was created',
          JSON.stringify(staff));
  dir.addGroupMember(STAFF, 'dp-alice', { origin: 'test' });
  const roster = String(config.value('admin.writeGroup'));
  dir.createGroup(roster, { origin: 'test' });
  dir.addGroupMember(roster, 'dp-dave', { origin: 'test' });
  dir.createGroup(PROTECTED, { origin: 'test' });
  dir.addGroupMember(PROTECTED, 'dp-erin', { origin: 'test' });
  const app = function (identifier, fields) {
    log.debug("Entering app().");
    log.debug("Leaving app().");
    return applications.createApplication({ identifier: identifier,
      protocols: ['oauth2', 'wstrust'],
      fields: Object.assign({ oauthClientId: identifier }, fields || {}) });
  };
  const made = [
    app('dp-back', { oauthAudience: [AUDIENCE],
                     wstrustAppliesTo: [AUDIENCE] }),
    app('dp-front', { appAllowedToDelegateTo: ['dp-back'] }),
    app('dp-mid', {}),
    app('dp-third', {}),
    app('dp-rbcd-front', {}),
    app('dp-rbcd-back', { appAllowedToActOnBehalfOf: ['dp-rbcd-front'] }),
    app('dp-accepting', { appAllowedToActOnBehalfOf: ['dp-third',
                                                      'dp-carol'] }),
    app('dp-grp-front', { appAllowedToDelegateTo: ['dp-accepting',
                                                   'dp-back'],
                          appDelegationSubjectGroup: [staff.dn] }),
    app('dp-imp', { appAllowedToDelegateTo: ['dp-back'],
                    appDelegationSemantics: ['delegation', 'impersonation'] }),
    app('dp-default-imp', { appAllowedToDelegateTo: ['dp-back'],
                            appDelegationSemantics: ['delegation',
                                                     'impersonation'],
                            appDefaultDelegationSemantics: 'impersonation' }),
    app('dp-svc', { appNotDelegated: 'TRUE' }),
    app('dp-payroll', { appAllowedToDelegateTo: ['dp-back'],
                        appRequiredRole: ['dp-payroll-role'] })
  ];
  t.check(made.every(function (one) { return one && one.ok; }),
          'precondition: the applications were created',
          JSON.stringify(made.filter(function (one) { return !one.ok; })));
  const bob = credentials.setNotDelegated('dp-bob', true);
  t.check(bob.ok, 'precondition: dp-bob carries stsNotDelegated',
          JSON.stringify(bob));
  log.debug("Leaving fixtures().");
  return { staffDn: staff.dn };
}

function truthTable(t, m) {
  log.debug("Entering truthTable(). " + m);
  const enforced = m === 'product';
  const refused = function (d, kind) {
    log.debug("Entering refused().");
    log.debug("Leaving refused().");
    return !d.allowed && d.refusal === kind && d.enforced === enforced;
  };
  const show = JSON.stringify;
  t.log.info('=== the facts from the directory, in ' + m + ' ===');
  inMode(m, function () {
    // A. delegation.
    let d = decide({ actor: 'dp-front', subject: 'dp-alice',
                     source: ['dp-front'], targets: [AUDIENCE] });
    t.check(d.allowed && d.semantics === 'delegation' &&
            d.audience === 'dp-back' &&
            d.targets[0].application === 'dp-back',
            m + ' A1. actor = S, S delegates to R (appAllowedToDelegateTo): ' +
            'a delegation, for R, the audience resolved to its application',
            show(d));
    d = decide({ actor: 'dp-back', subject: 'dp-alice',
                 source: ['dp-front'], targets: ['dp-back'] });
    t.check(d.allowed && d.semantics === 'delegation',
            m + ' A2. actor = R, the token handed on to it', show(d));
    d = decide({ actor: 'dp-rbcd-front', subject: 'dp-alice',
                 source: ['dp-rbcd-front'], targets: ['dp-rbcd-back'] });
    t.check(d.allowed, m + ' A3. resource-based: R accepts S ' +
            '(appAllowedToActOnBehalfOf)', show(d));
    d = decide({ actor: 'dp-third', subject: 'dp-alice',
                 source: ['dp-grp-front'], targets: ['dp-accepting'] });
    t.check(d.allowed, m + ' A4. a third application R accepts by name, S ' +
            'delegating to R', show(d));
    d = decide({ actor: 'dp-mid', subject: 'dp-alice',
                 source: ['dp-mid'], targets: ['dp-back'] });
    t.check(refused(d, 'target'), m + ' A5. no relationship between S and ' +
            'R: refused (target)', show(d));
    d = decide({ actor: 'dp-mid', subject: 'dp-alice',
                 source: ['dp-front'], targets: ['dp-back'] });
    t.check(refused(d, 'target'), m + ' A6. an actor outside the chain: ' +
            'refused (target)', show(d));
    t.check(enforced ? /refused by the delegation policy/.test(
              policy.rowText(d))
                     : /WOULD HAVE BEEN REFUSED/.test(policy.rowText(d)),
            m + ' A7. the row says ' + (enforced ? 'it was refused'
              : 'it would have been refused in product'), policy.rowText(d));

    // B. impersonation and the semantics.
    d = decide({ actor: 'dp-front', subject: 'dp-alice', source: ['dp-front'],
                 targets: ['dp-back'], requested: 'impersonation' });
    t.check(refused(d, 'semantics'), m + ' B1. impersonation by an actor ' +
            'whose appDelegationSemantics is empty: refused (semantics)',
            show(d));
    d = decide({ actor: 'dp-imp', subject: 'dp-alice', source: ['dp-front'],
                 targets: ['dp-back'], requested: 'impersonation' });
    t.check(d.allowed && d.semantics === 'impersonation',
            m + ' B2. allowed where it carries impersonation and reaches R',
            show(d));
    d = decide({ actor: 'dp-default-imp', subject: 'dp-alice',
                 source: ['dp-front'], targets: ['dp-back'] });
    t.check(d.allowed && d.semantics === 'impersonation',
            m + ' B3. no request: the actor\'s default decides', show(d));
    const frank = credentials.setDelegationSemantics('dp-frank',
                                                     ['delegation'], '');
    t.check(frank.ok, 'precondition: dp-frank allows delegation only',
            show(frank));
    d = decide({ actor: 'dp-imp', subject: 'dp-frank', source: ['dp-front'],
                 targets: ['dp-back'], requested: 'impersonation' });
    t.check(refused(d, 'semantics'), m + ' B4. a person allowing delegation ' +
            'only (stsDelegationSemantics) is not impersonated', show(d));
    config.setOverride('delegation.defaultSemantics', 'impersonation');
    try {
      d = decide({ actor: 'dp-imp', subject: 'dp-alice', source: ['dp-front'],
                   targets: ['dp-back'] });
      t.check(d.allowed && d.semantics === 'impersonation',
              m + ' B5. nothing else says: delegation.defaultSemantics ' +
              'decides', show(d));
    } finally {
      config.clearOverride('delegation.defaultSemantics');
    }

    // C. protected subjects.
    d = decide({ actor: 'dp-grp-front', subject: 'dp-carol',
                 source: ['dp-grp-front'], targets: ['dp-back'] });
    t.check(refused(d, 'subject'), m + ' C1. a subject outside the actor\'s ' +
            'appDelegationSubjectGroup', show(d));
    d = decide({ actor: 'dp-grp-front', subject: 'dp-alice',
                 source: ['dp-grp-front'], targets: ['dp-back'] });
    t.check(d.allowed, m + ' C2. ... and a member is allowed', show(d));
    d = decide({ actor: 'dp-front', subject: 'dp-bob', source: ['dp-front'],
                 targets: ['dp-back'] });
    t.check(refused(d, 'subject') && /protected/.test(d.why),
            m + ' C3. a person carrying stsNotDelegated', show(d));
    d = decide({ actor: 'dp-front', subject: 'dp-dave', source: ['dp-front'],
                 targets: ['dp-back'] });
    t.check(refused(d, 'subject'), m + ' C4. a member of the console roster',
            show(d));
    d = decide({ actor: 'dp-front', subject: 'dp-erin', source: ['dp-front'],
                 targets: ['dp-back'] });
    t.check(d.allowed, m + ' C5. dp-erin before her group is protected',
            show(d));
    config.setOverride('delegation.protectedGroups', PROTECTED);
    try {
      d = decide({ actor: 'dp-front', subject: 'dp-erin',
                   source: ['dp-front'], targets: ['dp-back'] });
      t.check(refused(d, 'subject'), m + ' C6. ... and refused once ' +
              'delegation.protectedGroups names it', show(d));
    } finally {
      config.clearOverride('delegation.protectedGroups');
    }
    d = decide({ actor: 'dp-front', subject: 'dp-svc', source: ['dp-front'],
                 targets: ['dp-back'] });
    t.check(refused(d, 'subject'), m + ' C7. an application carrying ' +
            'appNotDelegated', show(d));

    // D. targets.
    d = decide({ actor: 'dp-front', subject: 'dp-alice', source: ['dp-front'],
                 targets: ['https://nowhere.example'] });
    t.check(refused(d, 'unregistered-target'), m + ' D1. a target no ' +
            'application registers', show(d));
    d = decide({ actor: 'dp-mid', subject: 'dp-alice', source: ['dp-front'],
                 targets: [] });
    t.check(refused(d, 'no-target'), m + ' D2. no target, not self', show(d));
    d = decide({ actor: 'dp-front', subject: 'dp-alice', source: ['dp-front'],
                 targets: ['dp-back', AUDIENCE] });
    t.check(refused(d, 'targets'), m + ' D3. two targets', show(d));

    // E. the actor.
    d = decide({ actor: 'dp-carol', subject: 'dp-alice',
                 source: ['dp-grp-front'], targets: ['dp-accepting'] });
    t.check(refused(d, 'intermediary'), m + ' E1. a PERSON without ' +
            'delegation.actorRole', show(d));
    d = decide({ actor: 'nobody-at-all', subject: 'dp-alice',
                 source: ['dp-front'], targets: ['dp-back'] });
    t.check(refused(d, 'intermediary'), m + ' E3. an actor with no entry',
            show(d));

    // F. may_act.
    d = decide({ actor: 'dp-front', subject: 'dp-alice', source: ['dp-front'],
                 targets: ['dp-back'], mayActPresent: true,
                 mayActNamesActor: false });
    t.check(!d.allowed && d.refusal === 'may-act' && d.enforced,
            m + ' F1. may_act naming somebody else: refused, ENFORCED in ' +
            'every mode', show(d));
    d = decide({ actor: 'dp-grp-front', subject: 'dp-carol',
                 source: ['dp-grp-front'], targets: ['dp-back'],
                 mayActPresent: true, mayActNamesActor: true });
    t.check(d.allowed && /may_act/.test(d.authorizedBy),
            m + ' F2. may_act naming the actor stands in for the subject ' +
            'groups', show(d));

    // G. self.
    d = decide({ actor: 'dp-front', subject: 'dp-alice', source: ['dp-front'],
                 targets: [] });
    t.check(d.allowed && d.semantics === 'self' && d.audience === 'dp-front',
            m + ' G1. a client for its own audience, none named: self, for S',
            show(d));
    d = decide({ actor: 'dp-mid', subject: 'dp-mid', source: [],
                 targets: ['dp-mid'] });
    t.check(d.allowed && d.semantics === 'self', m + ' G2. an application ' +
            'exchanging its own token: self', show(d));

    // H. authority.
    d = decide({ actor: 'dp-payroll', subject: 'dp-alice',
                 source: ['dp-payroll'], targets: ['dp-back'] });
    t.check(refused(d, 'authority'), m + ' H1. the subject holds none of ' +
            'the roles S requires', show(d));
  });
  log.debug("Leaving truthTable().");
}

function rolesHeld(t) {
  log.debug("Entering rolesHeld().");
  t.log.info('=== E2, H2: roles change the answer ===');
  const actorRole = String(config.value('delegation.actorRole'));
  let w = roles.write(actorRole, { users: ['dp-carol'], groups: [] });
  t.check(w && w.ok !== false, 'precondition: dp-carol holds ' + actorRole,
          JSON.stringify(w));
  let d = decide({ actor: 'dp-carol', subject: 'dp-alice',
                   source: ['dp-grp-front'], targets: ['dp-accepting'] });
  t.check(d.allowed && d.semantics === 'delegation', 'E2. a PERSON holding ' +
          'delegation.actorRole, accepted by R, may act', JSON.stringify(d));
  w = roles.write('dp-payroll-role', { users: ['dp-alice'], groups: [] });
  t.check(w && w.ok !== false, 'precondition: dp-alice holds the payroll ' +
          'role', JSON.stringify(w));
  d = decide({ actor: 'dp-payroll', subject: 'dp-alice',
               source: ['dp-payroll'], targets: ['dp-back'] });
  t.check(d.allowed, 'H2. holding the role S requires, allowed',
          JSON.stringify(d));
  roles.remove(actorRole);
  roles.remove('dp-payroll-role');
  log.debug("Leaving rolesHeld().");
}

function realmPolicy(t) {
  log.debug("Entering realmPolicy().");
  t.log.info('=== I. a realm\'s own policy ===');
  const written = store.write('dp-refuse-front', REFUSE_FRONT_POLICY,
                              { enabled: true });
  t.check(written && written.ok, 'precondition: the policy was written',
          JSON.stringify(written));
  config.setOverride('xacml.issuancePolicy', 'dp-refuse-front');
  try {
    let d = decide({ actor: 'dp-front', subject: 'dp-alice',
                     source: ['dp-front'], targets: ['dp-back'] });
    t.check(!d.allowed && d.refusal === 'policy' && d.enforced &&
            d.decidedBy === 'policy', 'I1. the realm\'s policy refuses ' +
            'dp-front, and is the one that decided', JSON.stringify(d));
    d = decide({ actor: 'dp-imp', subject: 'dp-alice', source: ['dp-front'],
                 targets: ['dp-back'], requested: 'impersonation' });
    t.check(d.allowed && d.decidedBy === 'built-in', 'I2. it says nothing ' +
            'of another actor, and the built-in policy decides that',
            JSON.stringify(d));
  } finally {
    config.clearOverride('xacml.issuancePolicy');
    store.remove('dp-refuse-front');
  }
  log.debug("Leaving realmPolicy().");
}

function personHalf(t) {
  log.debug("Entering personHalf().");
  t.log.info('=== J. the person\'s half: stsMayAct and may_act ===');
  const carol = credentials.delegationFactsFor('dp-carol');
  const alice = credentials.delegationFactsFor('dp-alice');
  let r = credentials.setMayAct('dp-alice', carol.dn);
  t.check(r.ok, 'J1. a person names another person as their delegate',
          JSON.stringify(r));
  const claim = policy.mayActClaimFor('dp-alice');
  t.check(claim && /^urn:uuid:/.test(claim.sub),
          'J2. and their access tokens\' may_act names that person by their ' +
          'urn:uuid subject', JSON.stringify(claim));
  const frontDn = applications.get('dp-front').dn;
  r = credentials.setMayAct('dp-alice', frontDn);
  t.check(r.ok && policy.mayActClaimFor('dp-alice').sub === 'dp-front',
          'J3. an application is named by its client_id', JSON.stringify(r));
  r = credentials.setMayAct('dp-alice', 'uid=nobody-here,ou=users,dc=x');
  t.check(!r.ok, 'J4. a DN naming nobody is refused', JSON.stringify(r));
  r = credentials.setMayAct('dp-alice', alice.dn);
  t.check(!r.ok, 'J5. and so is the person themselves', JSON.stringify(r));
  r = credentials.setMayAct('dp-alice', '');
  t.check(r.ok && policy.mayActClaimFor('dp-alice') === null,
          'J6. clearing it takes the claim away', JSON.stringify(r));
  t.check(policy.mayActNames({ sub: 'x' }, { sub: 'x' }) &&
          !policy.mayActNames({ sub: 'x' }, { sub: 'y' }) &&
          !policy.mayActNames({ sub: 'x', iss: 'https://a' },
                              { sub: 'x', iss: 'https://b' }) &&
          policy.mayActNames({ sub: 'c' }, { sub: 'urn:sts:client:c',
                                             aliases: ['c'] }),
          'J7. may_act matches on sub, and on iss when it carries one');
  r = credentials.setDelegationSemantics('dp-alice', ['sideways'], '');
  t.check(!r.ok, 'J8. a person\'s semantics are delegation or impersonation',
          JSON.stringify(r));
  // An APPLICATION names its delegate too (#186): appMayAct, a DN.
  r = applications.updateApplication('dp-mid', { attribute: 'appMayAct',
    mode: 'set', value: frontDn });
  t.check(r.ok && policy.mayActClaimFor('dp-mid') &&
          policy.mayActClaimFor('dp-mid').sub === 'dp-front',
          'J9. an application\'s appMayAct puts may_act naming that party on ' +
          'tokens about it', JSON.stringify(policy.mayActClaimFor('dp-mid')));
  r = applications.updateApplication('dp-mid', { attribute: 'appMayAct',
    mode: 'set', value: carol.dn });
  t.check(r.ok && /^urn:uuid:/.test(String((policy.mayActClaimFor('dp-mid') ||
                                            {}).sub)),
          'J10. and a person it names, by their urn:uuid subject',
          JSON.stringify(policy.mayActClaimFor('dp-mid')));
  applications.updateApplication('dp-mid', { attribute: 'appMayAct',
                                             mode: 'set', value: '' });
  t.check(policy.mayActClaimFor('dp-mid') === null,
          'J11. clearing it takes the claim away');
  log.debug("Leaving personHalf().");
}

function grammarAndList(t, fx) {
  log.debug("Entering grammarAndList().");
  t.log.info('=== K. the grammar and the register ===');
  let r = applications.updateApplication('dp-mid', {
    attribute: 'appNotDelegated', mode: 'set', value: 'yes' });
  t.check(!r.ok, 'K1. appNotDelegated must be TRUE or FALSE',
          JSON.stringify(r));
  r = applications.updateApplication('dp-mid', {
    attribute: 'appDelegationSemantics', mode: 'add', value: 'sideways' });
  t.check(!r.ok, 'K2. appDelegationSemantics holds delegation or ' +
          'impersonation', JSON.stringify(r));
  r = applications.updateApplication('dp-mid', {
    attribute: 'appDelegationSubjectGroup', mode: 'add', value: STAFF });
  t.check(!r.ok, 'K3. a subject group is named by its DN', JSON.stringify(r));
  r = applications.updateApplication('dp-mid', {
    attribute: 'appMayAct', mode: 'set', value: 'dp-front' });
  t.check(!r.ok, 'K3b. appMayAct names its delegate by DN', JSON.stringify(r));
  r = applications.updateApplication('dp-mid', {
    attribute: 'appTrustedToImpersonate', mode: 'set', value: 'TRUE' });
  t.check(!r.ok, 'K4. appTrustedToImpersonate is gone: merged into ' +
          'appDelegationSemantics', JSON.stringify(r));
  const listed = policy.list();
  t.check(listed.pairs.some(function (one) {
    return one.intermediary === 'dp-front' && one.target === 'dp-back' &&
           one.mechanism === 'constrained';
  }) && listed.pairs.some(function (one) {
    return one.intermediary === 'dp-rbcd-front' &&
           one.target === 'dp-rbcd-back' && one.mechanism === 'resource-based';
  }), 'K5. list() has a pair for each attribute, set on each end',
          JSON.stringify(listed.pairs));
  t.check(listed.intermediaries.some(function (one) {
    return one.application === 'dp-imp' && one.impersonates &&
           one.semantics.indexOf('impersonation') >= 0;
  }) && listed.intermediaries.some(function (one) {
    return one.application === 'dp-grp-front' &&
           one.subjectGroups.indexOf(fx.staffDn) >= 0;
  }) && listed.intermediaries.some(function (one) {
    return one.application === 'dp-svc' && one.notDelegated;
  }), 'K6. and the applications carrying semantics, a group or ' +
          'appNotDelegated', JSON.stringify(listed.intermediaries));
  t.check(listed.people.some(function (one) {
    return one.username === 'dp-bob' && one.notDelegated;
  }) && listed.people.some(function (one) {
    return one.username === 'dp-frank' &&
           one.semantics.join() === 'delegation';
  }), 'K7. and the people carrying stsNotDelegated or semantics',
          JSON.stringify(listed.people));
  t.check(listed.protectedGroups.indexOf(
    String(config.value('admin.writeGroup'))) >= 0,
          'K8. and names the roster groups it protects');
  log.debug("Leaving grammarAndList().");
}

// An RST whose security header carries `security` and whose body carries
// `body` — one or both delegation elements — for `appliesTo` ('' for none).
// SOAP 1.2 unless `soap11`.
function rst(security, body, appliesTo, soap11, tokenType) {
  log.debug("Entering rst().");
  const soapNs = soap11 ? 'http://schemas.xmlsoap.org/soap/envelope/'
                        : 'http://www.w3.org/2003/05/soap-envelope';
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="' + soapNs + '" ' +
    'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-' +
    'wssecurity-secext-1.0.xsd"><s:Header><wsse:Security>' + security +
    '</wsse:Security></s:Header><s:Body><wst:RequestSecurityToken ' +
    'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">' +
    '<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/' +
    'Issue</wst:RequestType>' + (tokenType ? '<wst:TokenType>' +
      tokenType + '</wst:TokenType>' : '') + (appliesTo
      ? '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
        'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
        '08/addressing"><wsa:Address>' + appliesTo + '</wsa:Address>' +
        '</wsa:EndpointReference></wsp:AppliesTo>' : '') + body +
    '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function wsTrust(t) {
  log.debug("Entering wsTrust().");
  t.log.info('=== L. WS-Trust OnBehalfOf and ActAs ===');
  const wstrust = require('../ws-trust/wstrust');
  const saml2 = require('../saml/saml2');
  const delegation = require('../common/delegation');
  // An assertion about `name`, restricted to `audience` — the delegated
  // token's audience is S.
  const as = function (name, audience) {
    log.debug("Entering as().");
    log.debug("Leaving as().");
    return saml2.buildSamlAssertion(name, audience || 'https://sts.test', 5);
  };
  const actAs = function (assertion) {
    log.debug("Entering actAs().");
    log.debug("Leaving actAs().");
    return '<wst14:ActAs xmlns:wst14="http://docs.oasis-open.org/ws-sx/' +
      'ws-trust/200802">' + assertion + '</wst14:ActAs>';
  };
  const onBehalfOf = function (assertion) {
    log.debug("Entering onBehalfOf().");
    log.debug("Leaving onBehalfOf().");
    return '<wst:OnBehalfOf>' + assertion + '</wst:OnBehalfOf>';
  };
  const ask = function (m, requester, body, appliesTo, soap11, tokenType) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return inMode(m, function () {
      return wstrust.handleRst(rst(as(requester), body, appliesTo, soap11,
                                   tokenType),
                               soap11 ? 'text/xml' : 'application/soap+xml');
    });
  };
  const DELEGATE = /<del:Delegate[^>]*><saml:NameID[^>]*>([^<]+)<\/saml:NameID>/g;
  const delegatesIn = function (body) {
    log.debug("Entering delegatesIn().");
    const out = [];
    let m;
    DELEGATE.lastIndex = 0;
    while ((m = DELEGATE.exec(String(body))) !== null) {
      out.push(m[1]);
    }
    log.debug("Leaving delegatesIn().");
    return out;
  };
  const SUBCODE = /<soap:Subcode><soap:Value xmlns:wst="[^"]+">wst:RequestFailed</;
  let r = ask('product', 'dp-front',
              actAs(as('dp-alice', 'dp-front')), 'dp-back');
  t.equal(r.status, 200, 'L1. product: ActAs (delegation) by S, which ' +
          'delegates to the AppliesTo, is issued', r.body.slice(0, 300));
  t.check(delegatesIn(r.body).join() === 'dp-front' &&
          /xsi:type="del:DelegationRestrictionType"/.test(r.body),
          'L1b. and the assertion NAMES the requester: SAML V2.0\'s ' +
          'Delegation Restriction, one del:Delegate', r.body.slice(0, 1600));
  const allowedRow = delegation.list().filter(function (row) {
    return row.type === 'wstrust-actas';
  })[0];
  t.check(allowedRow && /issuance policy allowed delegation/
    .test(allowedRow.authorizedBy), 'L2. and the act says what allowed it',
          JSON.stringify(allowedRow && allowedRow.authorizedBy));
  r = ask('product', 'dp-front', onBehalfOf(as('dp-alice', 'dp-front')),
          'dp-back');
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0022' &&
          SUBCODE.test(r.body),
          'L3. product: OnBehalfOf (impersonation) by an actor allowing ' +
          'delegation only is a SOAP 1.2 Fault whose Subcode is ' +
          'wst:RequestFailed (STS-WSTRUST-0022)', r.errorCode + ' ' +
          r.body.slice(0, 500));
  r = ask('product', 'dp-front', onBehalfOf(as('dp-alice', 'dp-front')),
          'dp-back', true);
  t.check(/<faultcode xmlns:wst="[^"]+">wst:RequestFailed<\/faultcode>/
            .test(r.body),
          'L4. and over SOAP 1.1 the faultcode itself is wst:RequestFailed',
          r.body.slice(0, 400));
  r = ask('product', 'dp-imp', onBehalfOf(as('dp-alice', 'dp-imp')), AUDIENCE);
  t.equal(r.status, 200, 'L5. product: OnBehalfOf by an actor allowing ' +
          'impersonation, which reaches the AppliesTo, is issued',
          r.errorCode + ' ' + r.body.slice(0, 600));
  t.check(delegatesIn(r.body).length === 0, 'L5b. and an impersonation ' +
          'names nobody', delegatesIn(r.body).join());
  r = ask('product', 'dp-carol', actAs(as('dp-alice', 'dp-grp-front')),
          'dp-accepting');
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0019',
          'L6. product: a PERSON requester without delegation.actorRole ' +
          '(STS-WSTRUST-0019)', r.errorCode + ' ' + r.body.slice(0, 400));
  r = ask('product', 'dp-front', actAs(as('dp-bob', 'dp-front')), 'dp-back');
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0018' &&
          /protected/.test(r.body), 'L7. product: a protected subject ' +
          '(STS-WSTRUST-0018)', r.errorCode + ' ' + r.body.slice(0, 400));
  const refusedRow = delegation.list().filter(function (row) {
    return row.type === 'wstrust-actas';
  })[0];
  t.check(refusedRow && refusedRow.outcome === 'refused' &&
          /protected/.test(refusedRow.reason),
          'L8. and the refusal is an act on /admin/delegation',
          JSON.stringify(refusedRow && [refusedRow.outcome,
                                        refusedRow.reason]));
  r = ask('development', 'dp-front',
          actAs(as('dp-alice', 'dp-front')) +
          onBehalfOf(as('dp-alice', 'dp-front')), 'dp-back');
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0025' &&
          /InvalidRequest/.test(r.body), 'L9. both elements in one ' +
          'request: wst:InvalidRequest, in development too (STS-WSTRUST-0025)',
          r.errorCode + ' ' + r.body.slice(0, 400));
  r = ask('product', 'dp-mid', actAs(as('dp-alice', 'dp-front')), '');
  t.check(r.status === 500 && r.errorCode === 'STS-WSTRUST-0024',
          'L10. no AppliesTo, the requester not S (STS-WSTRUST-0024)',
          r.errorCode + ' ' + r.body.slice(0, 400));
  r = ask('development', 'dp-front', onBehalfOf(as('dp-alice', 'dp-front')),
          'dp-back');
  const devRow = delegation.list().filter(function (row) {
    return row.type === 'wstrust-onbehalfof';
  })[0];
  t.check(r.status === 200 && devRow && devRow.outcome === 'issued' &&
          /WOULD HAVE BEEN REFUSED/.test(devRow.authorizedBy),
          'L11. development issues the same OnBehalfOf and the act says it ' +
          'WOULD have been refused', r.status + ' ' +
          JSON.stringify(devRow && devRow.authorizedBy));
  // ActAs for a JWT: the chain as `act`, and may_act from stsMayAct.
  const front = applications.get('dp-front');
  credentials.setMayAct('dp-alice', front.dn);
  r = ask('product', 'dp-front', actAs(as('dp-alice', 'dp-front')), 'dp-back',
          false, 'urn:ietf:params:oauth:token-type:jwt');
  credentials.setMayAct('dp-alice', '');
  const jwt = (/ValueType="urn:ietf:params:oauth:token-type:jwt">([^<]+)</
    .exec(r.body) || [])[1] || '';
  const claims = jwt ? JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url')
    .toString('utf8')) : {};
  t.check(r.status === 200 && claims.act && claims.act.sub === 'dp-front' &&
          !claims.act.act && claims.may_act &&
          claims.may_act.sub === 'dp-front',
          'L13. an ActAs JWT carries `act` naming the requester, and the ' +
          'subject\'s may_act', r.status + ' ' + JSON.stringify(claims));
  // The register is protocol-independent: the same acts are Monitoring →
  // Delegation's table AND the picture /admin/delegation/map draws.
  const adminViews = require('../admin-core/admin_views');
  const view = adminViews.delegationView({ protocol: 'WS-Trust' });
  const nodes = [].concat(view.graph.nodes || []);
  const edges = [].concat(view.graph.edges || []);
  t.check(view.filtered.length > 0 && edges.length > 0 &&
          nodes.some(function (one) {
            return (one.protocols || []).indexOf('WS-Trust') >= 0 &&
                   one.roles && one.roles.intermediary > 0;
          }),
          'L12. the WS-Trust acts are on Monitoring → Delegation and in its ' +
          'picture: an intermediary box and the lines to it',
          view.filtered.length + ' act(s), ' + nodes.length + ' node(s), ' +
          edges.length + ' edge(s)');
  log.debug("Leaving wsTrust().");
}

function consoleDoor(t) {
  log.debug("Entering consoleDoor().");
  t.log.info('=== N. the console\'s door and the paged view ===');
  const adminActions = require('../admin-core/admin_actions');
  const adminViews = require('../admin-core/admin_views');
  const errorCodes = require('../common/error_codes');
  const ctx = { via: 'console', actor: 'delegation-policy-test' };
  let r = adminActions.usersAction({ action: 'set-not-delegated',
                                     user: 'dp-carol', value: 'true' }, ctx);
  t.check(r.ok && credentials.delegationFactsFor('dp-carol').notDelegated,
          'N1. set-not-delegated writes stsNotDelegated', JSON.stringify(r));
  r = adminActions.usersAction({ action: 'set-not-delegated',
                                 user: 'dp-carol', value: 'false' }, ctx);
  t.check(r.ok && !credentials.delegationFactsFor('dp-carol').notDelegated,
          'N2. and value=false clears it', JSON.stringify(r));
  const aliceDn = credentials.delegationFactsFor('dp-alice').dn;
  r = adminActions.usersAction({ action: 'set-may-act', user: 'dp-carol',
                                 delegate: aliceDn }, ctx);
  t.check(r.ok && credentials.delegationFactsFor('dp-carol').mayAct ===
          aliceDn, 'N3. set-may-act writes stsMayAct', JSON.stringify(r));
  r = adminActions.usersAction({ action: 'set-may-act', user: 'dp-carol',
                                 delegate: 'uid=nobody,ou=users,dc=x' }, ctx);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHN-0227',
          'N4. a delegate naming nobody is refused (STS-AUTHN-0227)',
          JSON.stringify(r) + ' ' + errorCodes.codeOf(r));
  adminActions.usersAction({ action: 'set-may-act', user: 'dp-carol',
                             delegate: '' }, ctx);
  r = adminActions.usersAction({ action: 'set-delegation-semantics',
    user: 'dp-carol', semantics: ['delegation', 'impersonation'],
    'default': 'impersonation' }, ctx);
  const facts = credentials.delegationFactsFor('dp-carol');
  t.check(r.ok && facts.semantics.join() === 'delegation,impersonation' &&
          facts.defaultSemantics === 'impersonation',
          'N5. set-delegation-semantics writes both attributes',
          JSON.stringify(r));
  r = adminActions.usersAction({ action: 'set-delegation-semantics',
    user: 'dp-carol', semantics: 'sideways' }, ctx);
  t.check(!r.ok && errorCodes.codeOf(r) === 'STS-AUTHN-0295',
          'N6. and refuses a value that is neither (STS-AUTHN-0295)',
          JSON.stringify(r) + ' ' + errorCodes.codeOf(r));
  r = adminActions.usersAction({ action: 'set-delegation-semantics',
    user: 'dp-carol', semantics: '' }, ctx);
  t.check(r.ok && credentials.delegationFactsFor('dp-carol').semantics
    .length === 0, 'N7. and an empty set clears them', JSON.stringify(r));
  const view = adminViews.delegationPolicyView({ per: '1' });
  t.check(view.json.pairs.length === 1 && view.json.pairsPaging.pages >= 2 &&
          view.json.peoplePaging && view.json.intermediariesPaging,
          'N8. the view is PAGED, each list on its own parameter',
          JSON.stringify(view.json.pairsPaging));
  log.debug("Leaving consoleDoor().");
}

// EVERYTHING IN A THROWAWAY REALM, removed afterwards: the fixtures put a
// person on the console roster's group, and `tests/run.js` runs every file in
// one process — in the default realm that membership opened the console to
// somebody in `directory_write_authorization.js`, which runs later.
function run(t) {
  log.debug("Entering run().");
  const id = 'dp-' + process.pid;
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug("Leaving run().");
    return;
  }
  try {
    realms.run(made.realm, function () {
      inRealm(t);
    });
  } finally {
    realms.remove(id);
  }
  log.debug("Leaving run().");
}

function inRealm(t) {
  log.debug("Entering inRealm().");
  const fx = fixtures(t);
  truthTable(t, 'development');
  truthTable(t, 'product');
  rolesHeld(t);
  realmPolicy(t);
  personHalf(t);
  grammarAndList(t, fx);
  wsTrust(t);
  consoleDoor(t);
  log.debug("Leaving inRealm().");
}

module.exports = {
  name: 'delegation_policy',
  describe: 'who may act for whom at WS-Trust and the token exchange: the ' +
            'facts gathered from the directory and the issuance policy\'s ' +
            'answer, in both modes (#108, #186)',
  run: run
};
