// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/password_named_policies.js
//
// ===========================================================================
// NAMED PASSWORD POLICIES, NAMED BY AN APPLICATION OR A GROUP (#1236).
//
// An application names its password policy in `appPasswordPolicy`, a group
// in `stsPasswordPolicy`, and a named policy carries every row `default` has
// plus a precedence (rule 3cx). Asserted at the READERS, not at the ranking
// alone:
//
//   A. A named policy saved with its precedence, and refused with a bad name
//      or a bad precedence; both references written through their doors,
//      and a value the realm does not hold refused there.
//   B. The selection: by group, by application, the lower precedence where
//      both name one, `default` for nobody and for a person nothing names.
//   C. At the doors, in PRODUCT mode: `credentials.setPassword()` (the
//      console, `/admin-api`, the portal, activation) and
//      `preparePassword()` (an LDAP write) refuse a group member's password
//      by the group's policy and accept the same password for a person
//      nothing names; the forced change's `application` lets the
//      application's policy decide; the password is HASHED as the selected
//      policy says; the generator and the rules a form prints are the
//      person's.
//   D. A reference to a policy the realm does not hold — a delete made past
//      the console — makes the answer `default` for that person, whatever
//      else names one (STS-AUTHN-0539, fail closed).
//   E. A named policy something names is not deleted (STS-AUTHN-0540); once
//      nothing does, it is. Another realm does not inherit it.
//   F. The console: the Password policy tab is Default / Named policies /
//      New policy, and the view says what names each policy.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ROOT = require('path').join(__dirname, '..');

const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const passwordPolicy = require('../common/password_policy');
const applications = require('../common/applications');
const ldap = require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
// A renderer given no translator draws node's default, which common/i18n.ts
// installs (#539) — English.
require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'password_named_policies', level: process.env.LOG_LEVEL || 'info' });

const TAG = 'pwnp' + process.pid;
const APP = TAG + '-app';
const MEMBER = TAG + '-member';
const LONE = TAG + '-lone';
const GROUP = TAG + '-group';
const OTHER_GROUP = TAG + '-other';
// The policies' names, lower-case as a cn here is.
const STRICT = TAG + '-strict';
const APP_POLICY = TAG + '-app';
const LAX = TAG + '-lax';
const GONE = TAG + '-gone';

// Twelve characters with a symbol, an uppercase letter and a digit: the
// default profile accepts it, a profile asking for twenty does not.
const TWELVE = 'Abcdefgh-12!';
const TWENTY_FOUR = 'Abcdefghijkl-mnopqrst-9!';

/**
 * Saves a named password policy with the defaults and these values.
 *
 * @param name - the policy's name
 * @param values - `precedence`, and any row
 * @returns the save's answer
 */
function named(name, values) {
  log.debug('Entering named().');
  log.debug('Leaving named().');
  return passwordPolicy.save(name, Object.assign({}, passwordPolicy.DEFAULTS,
                                                 values));
}

/**
 * Sets an application's `appPasswordPolicy` through the console's act.
 *
 * @param value - the policy's name
 * @returns the act's answer
 */
function pointApp(value) {
  log.debug('Entering pointApp().');
  log.debug('Leaving pointApp().');
  return adminActions.applicationsAction({ action: 'set',
    application: APP, attribute: 'appPasswordPolicy', value: value },
  [], {});
}

/**
 * Sets a group's `stsPasswordPolicy` through the group page's act.
 *
 * @param group - the group's cn
 * @param value - the policy's name, or '' to clear it
 * @returns the act's answer
 */
function pointGroup(group, value) {
  log.debug('Entering pointGroup().');
  log.debug('Leaving pointGroup().');
  return adminActions.groupsAction({ action: 'set-policy', group: group,
    attribute: 'stsPasswordPolicy', policy: value });
}

/**
 * Runs `fn` with settings overridden, clearing them after.
 *
 * @param pairs - setting → value
 * @param fn - what to run
 * @returns what `fn` answered
 */
function withSettings(pairs, fn) {
  log.debug('Entering withSettings().');
  Object.keys(pairs).forEach(function (key) {
    config.setOverride(key, String(pairs[key]));
  });
  try {
    log.debug('Leaving withSettings().');
    return fn();
  } finally {
    Object.keys(pairs).forEach(function (key) {
      config.clearOverride(key);
    });
  }
}

/**
 * The stored `userPassword` of a person.
 *
 * @param who - the person
 * @returns the stored value
 */
function storedPassword(who) {
  log.debug('Entering storedPassword().');
  const view = ldap.objectFor(who);
  const attributes = (view && view.entry && view.entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === 'userpassword';
  })[0];
  log.debug('Leaving storedPassword().');
  return key ? String([].concat(attributes[key])[0]) : '';
}

function savesAndReferences(t) {
  log.debug('Entering savesAndReferences().');
  const saves = [
    named(STRICT, { precedence: 20, minLength: 20, generatedLength: 32,
                    hashAlgorithm: 'argon2id' }),
    named(APP_POLICY, { precedence: 10, minLength: 16,
                        generatedLength: 24 }),
    named(LAX, { precedence: 30, minLength: 8, minSymbols: 0,
                 requireUppercase: false, requireDigit: false })
  ];
  t.check(saves.every(function (one) {
    return one.ok;
  }) && saves[0].profile.name === STRICT &&
          saves[0].profile.precedence === 20 &&
          saves[0].profile.minLength === 20,
          'A1. named password policies are saved with every row and a ' +
          'precedence', JSON.stringify(saves.map(function (one) {
            return one.errors;
          })));
  const badName = named('Strict!', {});
  const badRank = named(TAG + '-ranked', { precedence: 0 });
  t.check(!badName.ok && errorCodes.codeOf(badName) === 'STS-AUTHN-0107' &&
          !badRank.ok && errorCodes.codeOf(badRank) === 'STS-AUTHN-0108',
          'A2. a bad name, or a precedence out of 1..1000, is refused',
          JSON.stringify([badName.errors, badRank.errors]));
  const listed = passwordPolicy.list().map(function (one) {
    return one.name;
  });
  t.check(listed[0] === 'default' &&
          listed.indexOf(APP_POLICY) < listed.indexOf(STRICT) &&
          listed.indexOf(STRICT) < listed.indexOf(LAX),
          'A3. the list: default, then the named by precedence',
          JSON.stringify(listed));
  const byGroup = pointGroup(GROUP, STRICT);
  const byOther = pointGroup(OTHER_GROUP, LAX);
  const byApp = pointApp(APP_POLICY);
  t.check(byGroup.ok && byOther.ok && byApp.ok,
          'A4. a group and an application name a policy through their doors',
          JSON.stringify([byGroup.errors, byOther.errors, byApp.errors]));
  const wrongApp = pointApp(TAG + '-nonesuch');
  const wrongGroup = pointGroup(GROUP, TAG + '-nonesuch');
  t.check(!wrongApp.ok && !wrongGroup.ok,
          'A5. a name the realm does not hold is refused at either door',
          JSON.stringify([wrongApp.errors, wrongGroup.errors]));
  log.debug('Leaving savesAndReferences().');
}

function selection(t) {
  log.debug('Entering selection().');
  t.check(passwordPolicy.selectionFor(MEMBER, '') === STRICT &&
          passwordPolicy.selectionFor(LONE, '') === 'default' &&
          passwordPolicy.selectionFor(LONE, APP) === APP_POLICY &&
          passwordPolicy.selectionFor(MEMBER, APP) === APP_POLICY &&
          passwordPolicy.selectionFor('', '') === 'default',
          'B1. by group (the lower of two groups\' precedences), by ' +
          'application, the application\'s lower precedence where both ' +
          'name one, and default for nobody');
  named(APP_POLICY, { precedence: 50, minLength: 16, generatedLength: 24 });
  t.check(passwordPolicy.selectionFor(MEMBER, APP) === STRICT,
          'B2. raising the application policy\'s number lets the group\'s win');
  named(APP_POLICY, { precedence: 10, minLength: 16, generatedLength: 24 });
  log.debug('Leaving selection().');
}

function doors(t) {
  log.debug('Entering doors().');
  withSettings({ 'global.mode': 'product', 'risk.breachCheck': 'off' },
               function () {
    const member = credentials.setPassword(MEMBER, TWELVE);
    const lone = credentials.setPassword(LONE, TWELVE);
    t.check(!member.ok && member.reason === 'password-policy' &&
            /profile "pwnp\d+-strict"/.test((member.errors || []).join(' ')) &&
            lone.ok,
            'C1. setPassword() refuses a twelve-character password for the ' +
            'member of a group naming a twenty-character policy, and sets ' +
            'it for a person nothing names',
            JSON.stringify([member.errors, lone.errors]));
    const prepared = credentials.preparePassword(MEMBER, TWELVE, {});
    t.check(!prepared.ok && prepared.reason === 'password-policy',
            'C2. preparePassword(), what an LDAP add or modify asks, refuses ' +
            'it the same way', JSON.stringify(prepared.errors));
    const longer = credentials.setPassword(MEMBER, TWENTY_FOUR);
    t.check(longer.ok && /^\$argon2id\$/.test(storedPassword(MEMBER)),
            'C3. a password the policy accepts is set, and HASHED as that ' +
            'policy says (argon2id)', JSON.stringify(longer.errors) + ' ' +
            storedPassword(MEMBER).slice(0, 12));
    const viaApp = credentials.setPassword(LONE, 'Abcdefghij-12!',
                                           { application: APP });
    t.check(!viaApp.ok &&
            /profile "pwnp\d+-app"/.test((viaApp.errors || []).join(' ')),
            'C4. the forced change at sign-in hands the application in, and ' +
            'the application\'s policy (sixteen) refuses what default ' +
            'would take', JSON.stringify(viaApp.errors));
    const rules = credentials.passwordRules(MEMBER);
    const loneRules = credentials.passwordRules(LONE);
    t.check(rules.profile === STRICT &&
            (rules.rules || [])[0] === 'at least 20 characters' &&
            loneRules.profile === 'default',
            'C5. the rules a form prints (the portal, activation, reset) are ' +
            'the person\'s groups\'', JSON.stringify([rules, loneRules]));
  });
  const generated = credentials.generatePassword(MEMBER);
  t.check(generated.length === 32 &&
          passwordPolicy.problemsWith(generated,
            passwordPolicy.read(STRICT)).length === 0,
          'C6. the generator draws the member\'s policy\'s generated length',
          String(generated.length));
  log.debug('Leaving doors().');
}

function failsClosed(t) {
  log.debug('Entering failsClosed().');
  const saved = named(GONE, { precedence: 1, minLength: 64,
                              generatedLength: 64 });
  ldap.createGroup(TAG + '-gonegroup');
  ldap.addGroupMember(TAG + '-gonegroup', MEMBER);
  const pointed = pointGroup(TAG + '-gonegroup', GONE);
  // A DELETE MADE PAST THE CONSOLE: the directory's own hook, which the
  // policy's refusal does not guard.
  const removed = passwordPolicy.directoryInstalled()
    .deletePasswordPolicy(GONE);
  t.check(saved.ok && pointed.ok && removed &&
          passwordPolicy.selectionFor(MEMBER, '') === 'default' &&
          passwordPolicy.profileFor(MEMBER).name === 'default' &&
          passwordPolicy.selectionFor(LONE, '') === 'default',
          'D1. a group naming a policy the realm does not hold makes the ' +
          'member\'s policy default, though another group names one ' +
          '(fail closed)', JSON.stringify([saved.errors, pointed.errors]));
  pointGroup(TAG + '-gonegroup', '');
  t.check(passwordPolicy.selectionFor(MEMBER, '') === STRICT,
          'D2. once the reference is cleared the ranking stands again');
  log.debug('Leaving failsClosed().');
}

function deletes(t) {
  log.debug('Entering deletes().');
  const held = passwordPolicy.reset(STRICT);
  const heldApp = passwordPolicy.reset(APP_POLICY);
  t.check(!held.ok && errorCodes.codeOf(held) === 'STS-AUTHN-0540' &&
          /pwnp\d+-group/.test(held.errors.join(' ')) &&
          !heldApp.ok && errorCodes.codeOf(heldApp) === 'STS-AUTHN-0540' &&
          held.errors.join(' ').indexOf(GROUP) >= 0 &&
          heldApp.errors.join(' ').indexOf(APP) >= 0,
          'E1. a named policy a group or an application names is not ' +
          'deleted, and the refusal names who', JSON.stringify([held.errors,
                                                               heldApp.errors]));
  const id = TAG + '-realm';
  const made = realms.create({ id: id, name: id,
                              description: 'Created by ' + __filename });
  try {
    const there = realms.run(made.realm, function () {
      log.debug('Entering deletes() in the realm.');
      log.debug('Leaving deletes() in the realm.');
      return passwordPolicy.list().map(function (one) {
        return one.name;
      });
    });
    t.check(JSON.stringify(there) === '["default"]',
            'E2. another realm does not inherit the named policies',
            JSON.stringify(there));
  } finally {
    realms.remove(id);
  }
  log.debug('Leaving deletes().');
}

function consoleTab(t) {
  log.debug('Entering consoleTab().');
  const policies = require(ROOT + '/admin-ui/web_policies');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const view = adminViews.policiesView({});
  const html = policies.body(kit.context(), view);
  const at = function (needle) {
    return html.indexOf(needle);
  };
  t.check(at('id="password-sub-default"') > 0 &&
          at('id="password-sub-named"') > at('id="password-sub-default"') &&
          at('id="password-sub-new"') > at('id="password-sub-named"') &&
          at('id="doors"') > at('id="password-sub-new"'),
          'F1. the Password policy tab is Default, Named policies and New ' +
          'policy, with the doors, history and generator under them');
  const namedPart = html.slice(at('id="password-sub-named"'),
                               at('id="password-sub-new"'));
  t.check(namedPart.indexOf('id="password-profile-' + STRICT + '"') >= 0 &&
          namedPart.indexOf('<code>' + GROUP + '</code>') >= 0 &&
          namedPart.indexOf('stsPasswordPolicy') >= 0 &&
          namedPart.indexOf('<code>' + APP + '</code>') >= 0 &&
          namedPart.indexOf('appPasswordPolicy') >= 0,
          'F2. each named policy is drawn with the groups and applications ' +
          'naming it');
  const pw = view.password || {};
  t.check(JSON.stringify(pw.selectors) === '["precedence"]' &&
          pw.references.application === 'appPasswordPolicy' &&
          pw.references.group === 'stsPasswordPolicy' &&
          Array.isArray(pw.doors),
          'F3. the view says the kind ranks by precedence and what names it',
          JSON.stringify([pw.selectors, pw.references]));
  log.debug('Leaving consoleTab().');
}

function run(t) {
  log.debug('Entering run().');
  ldap.createUser(MEMBER, { invent: false });
  ldap.createUser(LONE, { invent: false });
  ldap.createGroup(GROUP);
  ldap.createGroup(OTHER_GROUP);
  ldap.addGroupMember(GROUP, MEMBER);
  ldap.addGroupMember(OTHER_GROUP, MEMBER);
  const created = applications.createApplication({ identifier: APP,
    protocols: [], fields: {} });
  t.check(!!created && created.ok !== false, 'the application is created',
          JSON.stringify(created && created.errors));
  try {
    savesAndReferences(t);
    selection(t);
    doors(t);
    failsClosed(t);
    deletes(t);
    consoleTab(t);
  } finally {
    pointApp('default');
    pointGroup(GROUP, '');
    pointGroup(OTHER_GROUP, '');
    pointGroup(TAG + '-gonegroup', '');
    [STRICT, APP_POLICY, LAX, GONE].forEach(function (name) {
      passwordPolicy.reset(name);
    });
    const left = passwordPolicy.list().filter(function (one) {
      return one.name.indexOf(TAG) === 0;
    });
    t.check(left.length === 0, 'every named policy this file made is gone',
            JSON.stringify(left.map(function (one) {
              return one.name;
            })));
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'password named policies',
  describe: 'Named password policies an application (appPasswordPolicy) ' +
            'or a group (stsPasswordPolicy) names, selected at every door ' +
            'that sets a password, failing closed to default (#1236)',
  run: run
};
