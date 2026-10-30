// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/authn_policy_by_group.js
//
// ===========================================================================
// A GROUP NAMES ITS AUTHENTICATION POLICY, AND THE NAMED POLICIES COMPETE ON
// PRECEDENCE (#1237, rule 3cx).
//
// rcbj on #1234: what a policy covers names it — the application through
// `appAuthnPolicy` (#1148), a group through `stsAuthnPolicy` — and a named
// policy carries a precedence (`stsAuthnPolicyPrecedence`). For one sign-in
// the policy the application names and the policy each of the person's
// groups names compete; the lowest precedence wins, ties by name, and the
// realm's `default` applies where nothing is named. Before the person is
// known only the application's reference applies. What is held:
//
//   A. THE GROUP'S REFERENCE: `stsAuthnPolicy` is declared, its choices are
//      `default` and the realm's named policies, the group page's act takes
//      one and refuses a name the realm does not hold (STS-LDAP-0195).
//   B. THE RANKING, at `mechanismsFor()` and both `allowedOf()`s: with no
//      person the application's policy; for a member the group's where its
//      precedence is lower; for somebody outside the group the
//      application's; the application's again once the group's precedence
//      is raised above it; a tie goes by name. A bad precedence is refused
//      (STS-AUTHN-0539).
//   C. A REAL READER, the issuance gate: the facts it puts to the policy for
//      a session are the group's lists for a member and the application's
//      for anybody else.
//   D. FAIL CLOSED: a group naming a policy the realm does not hold allows
//      its members no mechanism (STS-AUTHN-0536), and nobody else is
//      touched.
//   E. THE DELETE: a policy a group names is not deleted (STS-AUTHN-0534),
//      and the refusal names the group; once nothing names it, it is.
//   F. THE REPORT SOURCE and THE CONSOLE: the `authMechanisms` rows of the
//      policy a group names, carrying the group; the policies view's named
//      policies with their precedence and the groups naming them, and the
//      markup drawing both.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ldap = require('../ldap/ldap_server');
const authnPolicy = require('../common/authn_policy');
const authnMechanisms = require('../common/authn_mechanisms');
const mfaMechanisms = require('../common/mfa_mechanisms');
const applications = require('../common/applications');
const gate = require('../common/issuance_gate');
const errorCodes = require('../common/error_codes');
const PolicySelection = require('../common/policy_selection');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const sources = require('../report/sources');
// A renderer given no translator draws node's default, which common/i18n.ts
// installs (#539) — English.
require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'authn_policy_by_group',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'apgrp' + process.pid;
const APP = TAG + '-app';
const NAMES = { app: TAG + '-appside', group: TAG + '-groupside',
                gone: TAG + '-gone', groupName: TAG + '-group' };
const PEOPLE = { member: TAG + '-member', outsider: TAG + '-outsider' };

/**
 * Sets an application's `appAuthnPolicy` through the console's act.
 *
 * @param value - the policy's name
 * @returns the act's answer
 */
function point(value) {
  log.debug('Entering point().');
  log.debug('Leaving point().');
  return adminActions.applicationsAction({ action: 'set', application: APP,
    attribute: 'appAuthnPolicy', value: value }, [], {});
}

/**
 * Sets the group's `stsAuthnPolicy` through the group page's act.
 *
 * @param value - the policy's name, or '' to clear it
 * @returns the act's answer
 */
function pointGroup(value) {
  log.debug('Entering pointGroup().');
  log.debug('Leaving pointGroup().');
  return adminActions.groupsAction({ action: 'set-policy',
    group: NAMES.groupName, attribute: 'stsAuthnPolicy', policy: value });
}

/**
 * The application's fields as the registry holds them now.
 *
 * @returns the fields
 */
function appFields() {
  log.debug('Entering appFields().');
  const entry = applications.get(APP);
  log.debug('Leaving appFields().');
  return entry ? entry.fields : null;
}

/**
 * Asks the issuance gate about a password-and-TOTP session for the
 * application, with a decider that records the question and allows it.
 *
 * @param person - the person
 * @returns the question the gate put, or null
 */
function gateQuestion(person) {
  log.debug('Entering gateQuestion().');
  const installed = gate.deciderInstalled();
  let asked = null;
  gate.setDecider(function (question) {
    asked = question;
    return { allowed: true, decision: 'Permit', why: 'recorded', roles: [],
             required: [], policy: 'test' };
  });
  try {
    gate.check({
      application: APP, kind: gate.ISSUANCE.SESSION,
      subject: { kind: 'user', name: person, authenticated: true },
      claims: null, rolesWaived: true, deviceDeferred: true,
      authenticationEvent: { amr: ['pwd', 'otp'], acr: 'mfa',
        authenticated: true, authority: { kind: 'local' },
        context: { credential: { kind: 'totp' } } }
    });
  } finally {
    gate.setDecider(installed);
  }
  log.debug('Leaving gateQuestion().');
  return asked;
}

function references(t) {
  log.debug('Entering references().');
  const declared = PolicySelection.referenceOf('group', 'stsAuthnPolicy');
  t.check(!!declared && declared.choices[0] === 'default' &&
          declared.choices.indexOf(NAMES.app) >= 0 &&
          declared.choices.indexOf(NAMES.group) >= 0,
          'A1. stsAuthnPolicy is declared on a group, its choices default ' +
          'and the realm\'s named policies', JSON.stringify(declared));
  const ok = pointGroup(NAMES.group);
  const ghost = pointGroup(TAG + '-nobody-holds-this');
  t.check(ok && ok.ok === true && ghost && ghost.ok === false &&
          errorCodes.codeOf(ghost) === 'STS-LDAP-0195' &&
          ldap.groupsNamingPolicy('stsAuthnPolicy', NAMES.group)
            .indexOf(NAMES.groupName) >= 0,
          'A2. the group page\'s act names a policy of the realm and ' +
          'refuses one it does not hold (STS-LDAP-0195)',
          JSON.stringify([ok && ok.errors, ghost && ghost.errors]));
  log.debug('Leaving references().');
}

function ranking(t) {
  log.debug('Entering ranking().');
  const fields = appFields();
  const before = authnPolicy.mechanismsFor(fields);
  const member = authnPolicy.mechanismsFor(fields, PEOPLE.member);
  const outsider = authnPolicy.mechanismsFor(fields, PEOPLE.outsider);
  t.check(before.policy === NAMES.app && before.by === 'application' &&
          authnMechanisms.allowedOf(fields).join() === 'webauthn',
          'B1. before the person is known, the application\'s policy ' +
          'applies', JSON.stringify(before));
  t.check(member.policy === NAMES.group && member.by === 'group' &&
          member.holder === NAMES.groupName && member.precedence === 10 &&
          authnMechanisms.allowedOf(fields, PEOPLE.member).join() ===
            'wallet' &&
          mfaMechanisms.allowedOf(fields, PEOPLE.member).join() === 'totp',
          'B2. for a member, the policy the group names outranks the ' +
          'application\'s on a lower precedence, in both allowedOf()s',
          JSON.stringify(member));
  t.check(outsider.policy === NAMES.app && outsider.by === 'application',
          'B3. for somebody outside the group, the application\'s applies',
          JSON.stringify(outsider));
  const raised = authnPolicy.saveNamed(NAMES.group, {
    mechanisms: ['wallet'], secondFactors: ['totp'], precedence: 90 });
  const reverse = authnPolicy.mechanismsFor(appFields(), PEOPLE.member);
  t.check(raised.ok && reverse.policy === NAMES.app &&
          reverse.by === 'application' &&
          authnMechanisms.allowedOf(appFields(), PEOPLE.member).join() ===
            'webauthn',
          'B4. and the reverse: the application\'s policy outranks the ' +
          'group\'s once the group\'s precedence is the higher',
          JSON.stringify(reverse));
  authnPolicy.saveNamed(NAMES.group, {
    mechanisms: ['wallet'], secondFactors: ['totp'], precedence: 50 });
  const tie = authnPolicy.mechanismsFor(appFields(), PEOPLE.member);
  t.check(tie.policy === [NAMES.app, NAMES.group].sort()[0],
          'B5. an equal precedence goes by name', JSON.stringify(tie));
  const bad = authnPolicy.saveNamed(NAMES.group, { precedence: 1001 });
  t.check(!bad.ok && errorCodes.codeOf(bad) === 'STS-AUTHN-0539',
          'B6. a precedence outside 1 to 1000 is refused (STS-AUTHN-0539)',
          JSON.stringify(bad.errors));
  authnPolicy.saveNamed(NAMES.group, {
    mechanisms: ['wallet'], secondFactors: ['totp'], precedence: 10 });
  log.debug('Leaving ranking().');
}

function reader(t) {
  log.debug('Entering reader().');
  const member = gateQuestion(PEOPLE.member);
  const outsider = gateQuestion(PEOPLE.outsider);
  t.check(!!member &&
          JSON.stringify(member.allowedAuthnMechanisms) === '["wallet"]' &&
          JSON.stringify(member.allowedMfaMechanisms) === '["totp"]',
          'C1. the issuance gate puts the group\'s lists to the policy for ' +
          'a member\'s session', JSON.stringify(member && {
            first: member.allowedAuthnMechanisms,
            second: member.allowedMfaMechanisms }));
  t.check(!!outsider &&
          JSON.stringify(outsider.allowedAuthnMechanisms) ===
            '["webauthn"]' &&
          outsider.allowedMfaMechanisms === null,
          'C2. and the application\'s for anybody else (its policy lists ' +
          'no second factor, so none is compared)',
          JSON.stringify(outsider && {
            first: outsider.allowedAuthnMechanisms,
            second: outsider.allowedMfaMechanisms }));
  log.debug('Leaving reader().');
}

function failClosed(t) {
  log.debug('Entering failClosed().');
  // A REFERENCE PAST THE CONSOLE: the register stops answering the policy
  // the group names, as a delete made by hand would leave it.
  const installed = authnPolicy.directoryInstalled();
  authnPolicy.setDirectory(Object.assign({}, installed, {
    allAuthnPolicies: function () {
      return installed.allAuthnPolicies().filter(function (one) {
        return String(one.name).toLowerCase() !== NAMES.group;
      });
    }
  }));
  try {
    const member = authnPolicy.mechanismsFor(appFields(), PEOPLE.member);
    const allowed = authnMechanisms.allowedOf(appFields(), PEOPLE.member);
    const outsider = authnPolicy.mechanismsFor(appFields(),
                                               PEOPLE.outsider);
    t.check(member.missing === true && member.by === 'group' &&
            member.holder === NAMES.groupName &&
            ['password', 'webauthn', 'wallet'].every(function (one) {
              return allowed.indexOf(one) < 0;
            }) &&
            outsider.missing === false && outsider.policy === NAMES.app,
            'D1. a group naming a policy the realm does not hold allows ' +
            'its members no mechanism (STS-AUTHN-0536), and nobody else ' +
            'is touched', JSON.stringify([member, allowed, outsider]));
  } finally {
    authnPolicy.setDirectory(installed);
  }
  log.debug('Leaving failClosed().');
}

function deletes(t) {
  log.debug('Entering deletes().');
  const del = function (name) {
    return adminActions.policiesAction({
      action: 'delete-named-authn-policy', name: name },
      { actor: 'test', via: 'test' });
  };
  const held = del(NAMES.group);
  t.check(!held.ok && errorCodes.codeOf(held) === 'STS-AUTHN-0534' &&
          (held.errors || []).join(' ').indexOf(NAMES.groupName) >= 0 &&
          !!authnPolicy.namedPolicy(NAMES.group),
          'E1. a policy a group names is not deleted (STS-AUTHN-0534), and ' +
          'the refusal names the group', JSON.stringify(held.errors));
  pointGroup('');
  const gone = del(NAMES.group);
  t.check(gone.ok && gone.removed === true &&
          !authnPolicy.namedPolicy(NAMES.group),
          'E2. once nothing names it, it is deleted', JSON.stringify(gone));
  log.debug('Leaving deletes().');
}

function report(t) {
  log.debug('Entering report().');
  const rows = sources.mechanismRows({ passwordPrimary: true },
    [{ identifier: APP, fields: appFields() }],
    [{ group: NAMES.groupName, policy: NAMES.group }]);
  const ofGroup = rows.filter(function (one) {
    return one.group === NAMES.groupName;
  });
  const ofApp = rows.filter(function (one) {
    return one.application === APP;
  });
  t.check(ofGroup.length === 2 && ofGroup.every(function (one) {
    return one.policy === NAMES.group && one.application === '';
  }) && ofGroup.some(function (one) {
    return one.id === 'wallet' && one.type === 'primary';
  }) && ofGroup.some(function (one) {
    return one.id === 'totp' && one.type === 'second';
  }) && ofApp.length === 1 && ofApp[0].id === 'webauthn' &&
          ofApp[0].policy === NAMES.app && ofApp[0].group === '',
          'F1. the authMechanisms source has a row per mechanism of the ' +
          'policy a group names, carrying the group and the policy',
          JSON.stringify(rows.slice(-4)));
  const view = adminViews.policiesView({});
  const ap = view.authn || {};
  const shown = (ap.named || []).filter(function (one) {
    return one.name === NAMES.group;
  })[0];
  t.check(!!shown && shown.precedence === 10 &&
          shown.namedBy.groups.indexOf(NAMES.groupName) >= 0 &&
          ap.references.group === 'stsAuthnPolicy' &&
          view.kinds.filter(function (one) {
            return one.id === 'authn';
          })[0].tabbed === true,
          'F2. the policies view lists a named policy with its precedence ' +
          'and the groups naming it, and the kind is tabbed',
          JSON.stringify(shown));
  const page = require('../admin-ui/web_policies');
  const kit = require('../admin-ui/web_kit');
  const parts = page.namedAuthnPoliciesSection(ap, kit.context({}, true).t);
  t.check(parts.list.indexOf('(precedence 10)') >= 0 &&
          parts.list.indexOf('Named by groups (stsAuthnPolicy)') >= 0 &&
          parts.list.indexOf(NAMES.groupName) >= 0 &&
          /name="precedence" min="1" max="1000" value="100"/
            .test(parts.add),
          'F3. the Named policies sub-tab draws the precedence and the ' +
          'groups naming a policy, and the New policy form a precedence',
          parts.list.slice(0, 400));
  log.debug('Leaving report().');
}

function run(t) {
  log.debug('Entering run().');
  ldap.createUser(PEOPLE.member, { invent: false });
  ldap.createUser(PEOPLE.outsider, { invent: false });
  ldap.createGroup(NAMES.groupName);
  ldap.addGroupMember(NAMES.groupName, PEOPLE.member);
  const created = adminActions.applicationsAction({
    action: 'create', identifier: APP }, ['oauth2']);
  t.check(created && created.ok === true, 'the application is created',
          JSON.stringify(created && created.errors));
  try {
    const saves = [
      authnPolicy.saveNamed(NAMES.app, { mechanisms: ['webauthn'],
                                         secondFactors: [],
                                         precedence: 50 }),
      authnPolicy.saveNamed(NAMES.group, { mechanisms: ['wallet'],
                                           secondFactors: ['totp'],
                                           precedence: 10 })
    ];
    t.check(saves.every(function (one) {
      return one.ok;
    }), 'two named authentication policies are saved, each with a ' +
    'precedence', JSON.stringify(saves.map(function (one) {
      return one.errors;
    })));
    const named = point(NAMES.app);
    t.check(named && named.ok === true,
            'the application names its policy (appAuthnPolicy)',
            JSON.stringify(named && named.errors));
    references(t);
    ranking(t);
    reader(t);
    failClosed(t);
    report(t);
    deletes(t);
  } finally {
    pointGroup('');
    point('default');
    authnPolicy.deleteNamed(NAMES.group, []);
    authnPolicy.deleteNamed(NAMES.app, []);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'authn policy by group',
  describe: 'A group names its authentication policy (stsAuthnPolicy), and ' +
            'the policies an application and a person\'s groups name ' +
            'compete on precedence (#1237)',
  run: run
};
