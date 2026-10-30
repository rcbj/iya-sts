// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_policy_on_application.js
//
// ===========================================================================
// AN APPLICATION AND A GROUP NAME THEIR PASSKEY POLICY; THE POLICY PAGE'S
// SUB-TABS (#609, reshaped by #1235).
//
// #609 drew, on an application's Configuration → Every protocol sub-tab, the
// named passkey policies whose `stsPasskeySelectApplication` named it. rcbj
// reversed the direction on #1234 (2026-10-30): the APPLICATION names its
// policy in `appPasskeyPolicy` and a GROUP in `stsPasskeyPolicy`, as an
// application names its authentication policy (#1148), and a named policy
// keeps only its rows and its precedence. What is held:
//
//   A. THE REFERENCES: `appPasskeyPolicy` takes `default` or a named profile
//      of the realm and refuses any other (STS-REG-0203); its choices are
//      those; a group's `stsPasskeyPolicy` likewise through the group page's
//      act (STS-LDAP-0195), and an attribute no kind declared is refused
//      (STS-LDAP-0194). A sign-in for the application — by its identifier or
//      a client_id — gets the profile it names; the profile a member's group
//      names wins on a lower precedence; a name the realm does not hold
//      selects nothing. The registration offer follows.
//   B. THE CARD'S DATA (`passkeyPolicy.forApplication()`, the application
//      read's `page.passkeyPolicies`) and THE CARD: the profile named, what
//      applies, the group note, a warning for a missing name, no control.
//   C. THE SUB-TABS: Default, Named policies and New policy on the Passkey
//      policy tab; each named profile's heading the card's link target, the
//      applications and groups naming it said above its form, and no
//      application or group box any more; the locale policy not tabbed; the
//      group page's picker.
//   D. THE DELETE: a profile an application or a group names is not deleted
//      (STS-AUTHN-0538); once nothing names it, it is.
//   E. A REFUSED CREATE (#841): the New policy form posts `newProfile`, and
//      a validation failure is drawn again in place, under the form's own
//      key (`passkey-new`). The typed fields stay on that form, the refusal
//      with them, and a typed name that matches a stored profile does not
//      overlay that profile. A refused save of the default profile is not
//      that redraw.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ROOT = require('path').join(__dirname, '..');

const ldap = require('../ldap/ldap_server');
const passkeyPolicy = require('../common/passkey_policy');
const applications = require('../common/applications');
const errorCodes = require('../common/error_codes');
const webauthnPolicy = require('../authn/webauthn_policy');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
// A renderer given no translator draws node's default, which common/i18n.ts
// installs (#539) — English.
require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'passkey_policy_on_application',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'pkapp' + process.pid;
const APP = TAG + '-app';
const CLIENT = TAG + '-Client';
const OTHER = TAG + '-other';
const LONE = TAG + '-lone';

/**
 * Saves a named passkey policy with the defaults and these values.
 *
 * @param name - the profile's name
 * @param values - `precedence`, and any row
 * @returns the save's answer
 */
function named(name, values) {
  log.debug('Entering named().');
  log.debug('Leaving named().');
  return passkeyPolicy.save(name, Object.assign({}, passkeyPolicy.DEFAULTS,
                                                values));
}

/**
 * Sets an application's `appPasskeyPolicy` through the console's act.
 *
 * @param identifier - the application
 * @param value - the profile's name
 * @returns the act's answer
 */
function point(identifier, value) {
  log.debug('Entering point().');
  log.debug('Leaving point().');
  return adminActions.applicationsAction({ action: 'set',
    application: identifier, attribute: 'appPasskeyPolicy', value: value },
  [], {});
}

/**
 * Sets a group's policy reference through the group page's act.
 *
 * @param group - the group's cn
 * @param value - the profile's name
 * @param attribute - optional; `stsPasskeyPolicy` when left out
 * @returns the act's answer
 */
function pointGroup(group, value, attribute) {
  log.debug('Entering pointGroup().');
  log.debug('Leaving pointGroup().');
  return adminActions.groupsAction({ action: 'set-policy', group: group,
    attribute: attribute || 'stsPasskeyPolicy', policy: value });
}

// The directory as installed, kept so `hideGone()` can be undone.
let installed = null;

/**
 * Makes the passkey register stop answering one profile, as a delete made
 * past the console leaves a reference to it.
 *
 * @param name - the profile to hide
 */
function hideGone(name) {
  log.debug('Entering hideGone().');
  installed = passkeyPolicy.directoryInstalled();
  passkeyPolicy.setDirectory(Object.assign({}, installed, {
    allPasskeyPolicies: function () {
      return installed.allPasskeyPolicies().filter(function (one) {
        return String(one.name).toLowerCase() !== name;
      });
    }
  }));
  log.debug('Leaving hideGone().');
}

/**
 * Puts the passkey register back as it was installed.
 */
function unhide() {
  log.debug('Entering unhide().');
  if (installed) {
    passkeyPolicy.setDirectory(installed);
    installed = null;
  }
  log.debug('Leaving unhide().');
}

/**
 * A request for an application's read.
 *
 * @returns the request
 */
function request() {
  log.debug('Entering request().');
  log.debug('Leaving request().');
  return { query: {}, headers: { host: 'localhost:8081' }, protocol: 'https',
           get: function () { return ''; } };
}

/**
 * The application read's answer for one application.
 *
 * @param identifier - the application
 * @returns the JSON
 */
function readOf(identifier) {
  log.debug('Entering readOf().');
  log.debug('Leaving readOf().');
  return adminViews.applicationDetailJson(request(), identifier).json;
}

function references(t, names, people) {
  log.debug('Entering references().');
  const good = point(APP, names.strict);
  const ghost = point(OTHER, TAG + '-ghost');
  t.check(good.ok && !ghost.ok &&
          errorCodes.codeOf(ghost) === 'STS-REG-0203' &&
          [].concat(applications.get(APP).fields.appPasskeyPolicy).join() ===
            names.strict,
          'A1. appPasskeyPolicy takes a named profile of the realm and ' +
          'refuses one it does not hold (STS-REG-0203)',
          JSON.stringify([good.errors, ghost.errors]));
  const row = applications.applicationFields().filter(function (one) {
    return one.attribute === 'appPasskeyPolicy';
  })[0];
  t.check(!!row && row.choices[0] === 'default' &&
          row.choices.indexOf(names.strict) > 0 &&
          row.choices.indexOf(names.group) > 0,
          'A2. its choices are default and the realm\'s named profiles',
          JSON.stringify(row && row.choices));
  const grouped = pointGroup(names.groupName, names.group);
  const badValue = pointGroup(names.groupName, TAG + '-ghost');
  const badAttribute = pointGroup(names.groupName, names.group,
                                  'stsNoSuchPolicy');
  t.check(grouped.ok && grouped.changed === true &&
          !badValue.ok && errorCodes.codeOf(badValue) === 'STS-LDAP-0195' &&
          !badAttribute.ok &&
          errorCodes.codeOf(badAttribute) === 'STS-LDAP-0194',
          'A3. a group names a profile in stsPasskeyPolicy; a name the realm ' +
          'does not hold and an undeclared attribute are refused',
          JSON.stringify([grouped, badValue.errors, badAttribute.errors]));
  t.check(passkeyPolicy.selectionFor('', APP) === names.strict &&
          passkeyPolicy.selectionFor('', CLIENT) === names.strict &&
          passkeyPolicy.selectionFor('', LONE) === 'default',
          'A4. a sign-in naming the application by its identifier or its ' +
          'client_id gets the profile it names; one naming none, default');
  t.check(passkeyPolicy.selectionFor(people.member, APP) === names.group &&
          passkeyPolicy.selectionFor(people.member, LONE) === names.group &&
          passkeyPolicy.selectionFor(people.outsider, APP) === names.strict,
          'A5. the profile a member\'s group names wins on a lower ' +
          'precedence; for anybody else the application\'s applies');
  // A PROFILE GONE FROM UNDER ITS REFERENCE, as a delete by hand leaves
  // it: `other` names a profile the directory then stops answering.
  named(names.gone, { precedence: 1 });
  point(OTHER, names.gone);
  hideGone(names.gone);
  t.check(passkeyPolicy.selectionFor('', OTHER) === 'default' &&
          passkeyPolicy.selectionFor(people.member, OTHER) === names.group,
          'A6. a name the realm does not hold selects nothing ' +
          '(STS-AUTHN-0537): default, or what else names one');
  const offer = webauthnPolicy.registrationOffer({ application: APP });
  t.check(offer.profile === names.strict &&
          offer.mode === 'classical-only' && offer.from === 'profile' &&
          JSON.stringify(offer.algorithms) === '["ES256","RS256"]',
          'A7. the profile the application names supplies its ordered ' +
          'classical-only registration list', JSON.stringify(offer));
  log.debug('Leaving references().');
}

function data(t, names) {
  log.debug('Entering data().');
  const json = readOf(APP);
  const pk = json && json.page ? json.page.passkeyPolicies : null;
  t.check(!!pk && pk.named === names.strict && pk.applies === names.strict &&
          pk.precedence === 50 && pk.missing === false &&
          pk.groupPolicies === 1 &&
          pk.link === '/admin/policies#passkey-profile-' + names.strict,
          'B1. the read says the profile named, what applies, its ' +
          'precedence, the profiles a group names, and links to it',
          JSON.stringify(pk));
  const lone = readOf(LONE).page.passkeyPolicies;
  const gone = readOf(OTHER).page.passkeyPolicies;
  t.check(lone.applies === 'default' && lone.missing === false &&
          gone.missing === true && gone.applies === 'default' &&
          gone.named === names.gone,
          'B2. an application naming none gets default; one naming a ' +
          'profile the realm does not hold says so',
          JSON.stringify([lone, gone]));
  const page = require(ROOT + '/admin-ui/web_applications');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const ctx = kit.context();
  const html = page.applicationPasskeyPolicyCard(json, ctx.t);
  t.check(/id="cfg-every-passkey"/.test(html) &&
          html.indexOf('href="/admin/policies#passkey-profile-' +
                       names.strict + '"') >= 0 &&
          html.indexOf('<strong>' + names.strict + '</strong>') >= 0 &&
          /appPasskeyPolicy/.test(html) && /groups name/.test(html) &&
          !/<form|<input|<button/.test(html),
          'B3. the card says the profile it names, links it, notes the ' +
          'profiles groups name, and holds no control', html.slice(0, 600));
  const missing = page.applicationPasskeyPolicyCard(readOf(OTHER), ctx.t);
  t.check(/<strong>default<\/strong>/.test(page.applicationPasskeyPolicyCard(
    readOf(LONE), ctx.t)) && missing.indexOf(names.gone) >= 0 &&
          /does not hold/.test(missing) &&
          page.applicationPasskeyPolicyCard({ page: {} }, ctx.t) === '',
          'B4. default where none is named, a warning for a missing name, ' +
          'and nothing for an answer without the member');
  const section = page.applicationFieldsSection(ctx, json, '');
  const every = section.indexOf('id="cfg-every"');
  const oauth = section.indexOf('id="cfg-oauth"');
  const at = section.indexOf('id="cfg-every-passkey"');
  t.check(every >= 0 && at > every && (oauth < 0 || at < oauth) &&
          section.indexOf('field.appPasskeyPolicy') > every,
          'B5. the card and the field that is its control are on the Every ' +
          'protocol sub-tab', JSON.stringify({ every: every, at: at }));
  log.debug('Leaving data().');
  return json;
}

function subTabs(t, names) {
  log.debug('Entering subTabs().');
  const policies = require(ROOT + '/admin-ui/web_policies');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const view = adminViews.policiesView({});
  const html = policies.body(kit.context(), view);
  const at = function (needle) {
    return html.indexOf(needle);
  };
  t.check(at('id="passkey-sub-default"') > 0 &&
          at('id="passkey-sub-named"') > at('id="passkey-sub-default"') &&
          at('id="passkey-sub-new"') > at('id="passkey-sub-named"') &&
          at('href="#passkey-sub-default"') > 0 &&
          at('href="#passkey-sub-new"') > 0,
          'C1. the Passkey policy tab is three sub-tabs: Default, Named ' +
          'policies, New policy');
  const named = html.slice(at('id="passkey-sub-named"'),
                           at('id="passkey-sub-new"'));
  t.check(named.indexOf('id="passkey-profile-' + names.strict + '"') >= 0 &&
          named.indexOf('<code>' + APP + '</code>') >= 0 &&
          named.indexOf('appPasskeyPolicy') >= 0 &&
          named.indexOf('<code>' + names.groupName + '</code>') >= 0 &&
          named.indexOf('stsPasskeyPolicy') >= 0 &&
          named.indexOf('name="profile" value="' + names.group + '"') >= 0,
          'C2. each named profile is on Named policies, its heading the ' +
          'card\'s link target, the applications and groups naming it ' +
          'said, and its form');
  t.check(named.indexOf('name="selectApplications"') < 0 &&
          named.indexOf('name="selectGroups"') < 0 &&
          at('fgc-passkey-apps') < 0,
          'C3. no application or group box and no search any more');
  const passkey = view.passkey || {};
  t.check(JSON.stringify(passkey.selectors) === '["precedence"]' &&
          passkey.references.application === 'appPasskeyPolicy' &&
          passkey.references.group === 'stsPasskeyPolicy',
          'C4. the view says the kind ranks by precedence and what names it',
          JSON.stringify([passkey.selectors, passkey.references]));
  t.check(at('id="locale-sub-default"') < 0 && at('id="locale-named"') > 0,
          'C5. the locale policy keeps its named profiles under its default');
  const groups = require(ROOT + '/admin-ui/web_groups');
  const detail = adminViews.groupDetailJson(request(),
                                            ldap.groupDnFor(names.groupName));
  const refs = detail.json.policyReferences || [];
  const mine = refs.filter(function (one) {
    return one.attribute === 'stsPasskeyPolicy';
  })[0];
  const picker = groups.policyPickers(kit.context().t, detail.json.group,
                                      refs, '/admin/groups');
  t.check(!!mine && mine.value === names.group &&
          mine.choices.indexOf(names.strict) >= 0 &&
          /name="action" value="set-policy"/.test(picker) &&
          picker.indexOf('value="' + names.group + '" selected') >= 0,
          'C6. the group page offers a picker for the passkey policy, the ' +
          'profile the group names selected', JSON.stringify(mine));
  log.debug('Leaving subTabs().');
  return { html: html, view: view };
}

function deletes(t, names) {
  log.debug('Entering deletes().');
  const byApp = passkeyPolicy.reset(names.strict);
  const byGroup = passkeyPolicy.reset(names.group);
  t.check(!byApp.ok && errorCodes.codeOf(byApp) === 'STS-AUTHN-0538' &&
          String(byApp.errors).indexOf(APP) >= 0 &&
          !byGroup.ok && errorCodes.codeOf(byGroup) === 'STS-AUTHN-0538' &&
          String(byGroup.errors).indexOf(names.groupName) >= 0,
          'D1. a profile an application or a group names is not deleted, ' +
          'and the refusal names it', JSON.stringify([byApp.errors,
                                                      byGroup.errors]));
  point(APP, 'default');
  pointGroup(names.groupName, '');
  const gone = passkeyPolicy.reset(names.strict);
  const gone2 = passkeyPolicy.reset(names.group);
  t.check(gone.ok && gone.removed === true && gone2.ok &&
          gone2.removed === true,
          'D2. once nothing names it, it is deleted',
          JSON.stringify([gone, gone2]));
  log.debug('Leaving deletes().');
}

// A refused New policy save (#841). The form posts `newProfile`, so the
// draft is the form's (`passkey-new`) even when the typed name is a stored
// profile's.
function refusedNew(t, drawn, names) {
  log.debug('Entering refusedNew().');
  const policies = require(ROOT + '/admin-ui/web_policies');
  const answers = require(ROOT + '/admin-ui/web_answers');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const why = 'The precedence of a named policy is a whole number from 1 ' +
    'to 1000; "0" is not.';
  const fields = {
    action: 'save-passkey-policy', newProfile: '1', profile: names.group,
    precedence: '9', minPinLength: '12', allowUsernameless: 'TRUE',
    backupEligibility: 'disallow' };
  const again = answers.redraw('/admin/policies', 'save-passkey-policy',
                               fields, { ok: false, errors: [why] },
                               drawn.view);
  const kept = again && again.json && again.json.state;
  const draft = kept && kept.policyDrafts && kept.policyDrafts['passkey-new'];
  const said = kept && kept.policySaveErrors &&
    kept.policySaveErrors['passkey-new'];
  t.check(!!again && again.banner === '' && draft === fields &&
          said && said[0] === why,
          'E1. a refused create is drawn again, the posted fields under ' +
          'the New policy form\'s own key, the refusal with them',
          JSON.stringify(kept && kept.policySaveErrors));
  t.check(answers.redraw('/admin/policies', 'save-passkey-policy',
                        { profile: 'default', minPinLength: '12' },
                        { ok: false, errors: [why] }, drawn.view) === null,
          'E2. a refused save of the default profile is not that redraw');
  const bare = answers.redraw('/admin/policies', 'save-passkey-policy',
                              { newProfile: '1', profile: 'kept-name' },
                              { ok: false }, drawn.view);
  t.check(bare && bare.json.state.policySaveErrors['passkey-new'][0] ===
          'Refused.',
          'E3. a refusal that names no error still says it was refused');
  const html = policies.body(kit.context(), again.json);
  const at = html.indexOf('id="passkey-sub-new"');
  const form = html.slice(at, html.indexOf('</form>', at));
  t.check(form.indexOf('name="newProfile" value="1"') >= 0 &&
          form.indexOf('value="' + names.group + '"') >= 0 &&
          /name="precedence" min="1" max="1000" value="9"/.test(form) &&
          /name="minPinLength"[^>]*value="12"/.test(form) &&
          /name="allowUsernameless"[^>]*value="TRUE" checked/.test(form) &&
          /value="disallow" selected/.test(form) &&
          form.indexOf(why) >= 0,
          'E4. the New policy form still holds the name, the precedence, ' +
          'the PIN length, the ticked box, the chosen enum and the refusal');
  const namedAt = html.indexOf('id="passkey-profile-' + names.group + '"');
  const namedForm = html.slice(namedAt, html.indexOf('</form>', namedAt));
  t.check(namedForm.indexOf('value="12"') < 0 &&
          !/name="precedence" min="1" max="1000" value="9"/.test(namedForm),
          'E5. a typed name that matches a stored profile does not overlay ' +
          'that profile\'s form');
  log.debug('Leaving refusedNew().');
}

function run(t) {
  log.debug('Entering run().');
  const names = { strict: TAG + '-strict', group: TAG + '-bygroup',
                  gone: TAG + '-gone', groupName: TAG + '-group' };
  const people = { member: TAG + '-member', outsider: TAG + '-outsider' };
  ldap.createUser(people.member, { invent: false });
  ldap.createUser(people.outsider, { invent: false });
  ldap.createGroup(names.groupName);
  ldap.addGroupMember(names.groupName, people.member);
  const created = adminActions.applicationsAction({
    action: 'create', identifier: APP, 'field.oauthClientId': CLIENT
  }, ['oauth2']);
  adminActions.applicationsAction({ action: 'create', identifier: OTHER },
                                  []);
  adminActions.applicationsAction({ action: 'create', identifier: LONE }, []);
  t.check(created && created.ok === true, 'the application is created',
          JSON.stringify(created && created.errors));
  try {
    const saves = [
      named(names.strict, { precedence: 50,
        registrationAlgorithms: 'ES256,RS256',
        registrationMode: 'classical-only' }),
      named(names.group, { precedence: 10 })
    ];
    t.check(saves.every(function (one) {
      return one.ok;
    }), 'two named profiles are saved, each with a precedence and nothing ' +
    'that selects', JSON.stringify(saves.map(function (one) {
      return one.errors;
    })));
    references(t, names, people);
    data(t, names);
    const drawn = subTabs(t, names);
    refusedNew(t, drawn, names);
    deletes(t, names);
  } finally {
    unhide();
    point(APP, 'default');
    point(OTHER, 'default');
    pointGroup(names.groupName, '');
    passkeyPolicy.reset(names.strict);
    passkeyPolicy.reset(names.group);
    passkeyPolicy.reset(names.gone);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'passkey policy on application',
  describe: 'An application and a group name their passkey policy ' +
            '(appPasskeyPolicy, stsPasskeyPolicy, #1235), shown read-only on ' +
            'the application\'s Every protocol sub-tab, and the Passkey ' +
            'policy tab\'s sub-tabs (#609)',
  run: run
};
