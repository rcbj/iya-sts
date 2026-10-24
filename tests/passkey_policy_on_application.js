// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/passkey_policy_on_application.js
//
// ===========================================================================
// AN APPLICATION'S PASSKEY POLICY, SHOWN ON IT; THE POLICY PAGE'S SEARCH AND
// SUB-TABS (#609).
//
// rcbj's decisions: nothing is stored on the application — the relation is a
// named passkey policy's `stsPasskeySelectApplication` — and the
// application's Configuration → Every protocol sub-tab shows it READ-ONLY;
// the Passkey policy tab of Directory → Policies gets three sub-tabs, and a
// named policy's applications box the field search (#459) that stores an
// application's identifier. What is held:
//
//   A. THE CARD'S DATA (`passkeyPolicy.forApplication()`, and the
//      application read's `page.passkeyPolicies`): several policies naming
//      one application, by its identifier and by a client_id in another
//      case, in precedence order with the lowest marked as applying; one
//      naming another application left out; `default` where none names it;
//      the count of policies selecting by group; selection itself unchanged.
//   B. THE CARD: drawn read-only on the Every protocol sub-tab, each policy
//      linked to its heading on the Policies page, the winner marked, the
//      group note; nothing when the answer has no member.
//   C. THE SUB-TABS: Default, Named policies and New policy on the Passkey
//      policy tab, each named policy's heading the card's link target, what
//      it selects said above its form; the locale policy not tabbed.
//   D. THE SEARCH: the cell and its box under each named form's
//      applications box and the New policy form's, keyed per form; a press
//      on the page read as a field search; the address it asks; Add putting
//      the IDENTIFIER in the box once; a redraw keeping the form's typed
//      values with the results under the box.
// ===========================================================================

delete process.env.CONFIG_FILE;

const ROOT = require('path').join(__dirname, '..');

const ldap = require('../ldap/ldap_server');
const passkeyPolicy = require('../common/passkey_policy');
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
 * Saves a named passkey policy with the defaults and these selectors.
 *
 * @param name - the profile's name
 * @param selectors - `selectApplications`, `selectGroups`, `precedence`
 * @returns the save's answer
 */
function named(name, selectors) {
  log.debug('Entering named().');
  log.debug('Leaving named().');
  return passkeyPolicy.save(name, Object.assign({}, passkeyPolicy.DEFAULTS,
                                                selectors));
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

function data(t, names) {
  log.debug('Entering data().');
  const json = readOf(APP);
  const pk = json && json.page ? json.page.passkeyPolicies : null;
  const order = pk ? pk.policies.map(function (one) {
    return one.name;
  }) : [];
  t.check(!!pk && JSON.stringify(order) ===
            JSON.stringify([names.strict, names.client]),
          'A1. both policies naming the application are listed, lowest ' +
          'precedence first — one by its identifier, one by a client_id in ' +
          'another case — and the one naming another application is not',
          JSON.stringify(pk));
  t.check(!!pk && pk.applies === names.strict &&
          pk.policies[0].applies === true &&
          pk.policies[1].applies === false &&
          pk.policies[0].precedence === 5 &&
          pk.policies[1].precedence === 40,
          'A2. the lowest precedence naming it is marked as the one that ' +
          'applies', JSON.stringify(pk && pk.policies));
  t.check(!!pk && JSON.stringify(pk.policies[1].matched) ===
            JSON.stringify([CLIENT.toUpperCase()]) &&
          JSON.stringify(pk.policies[0].matched) === JSON.stringify([APP]) &&
          pk.names.indexOf(APP) >= 0 && pk.names.indexOf(CLIENT) >= 0,
          'A3. each says the value that named it, and the answer what the ' +
          'application was matched by', JSON.stringify(pk && pk.names));
  t.check(!!pk && pk.policies[0].link ===
            '/admin/policies#passkey-profile-' + names.strict &&
          pk.link === '/admin/policies#passkey',
          'A4. each links to its profile on the Policies page',
          JSON.stringify(pk && pk.policies.map(function (one) {
            return one.link;
          })));
  t.check(!!pk && pk.groupPolicies >= 1 &&
          pk.policies[1].selectGroups.length === 1,
          'A5. the policies selecting by group are counted, and a policy\'s ' +
          'own groups carried', JSON.stringify(pk && pk.groupPolicies));
  const lone = readOf(LONE).page.passkeyPolicies;
  t.check(lone.policies.length === 0 && lone.applies === 'default',
          'A6. an application no policy names gets default',
          JSON.stringify(lone));
  t.check(passkeyPolicy.selectionFor('', APP) === names.strict &&
          passkeyPolicy.selectionFor('', CLIENT) === names.client &&
          passkeyPolicy.selectionFor('', OTHER) === names.other &&
          !!pk && pk.appliesBy[APP] === names.strict &&
          pk.appliesBy[CLIENT] === names.client,
          'A7. selection is as it was, and the answer says per name what a ' +
          'sign-in naming the application by it gets — an OAuth sign-in ' +
          'names the client_id', JSON.stringify(pk && pk.appliesBy));
  log.debug('Leaving data().');
  return json;
}

function card(t, json, names) {
  log.debug('Entering card().');
  const page = require(ROOT + '/admin-ui/web_applications');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const ctx = kit.context();
  const html = page.applicationPasskeyPolicyCard(json, ctx.t);
  t.check(/id="cfg-every-passkey"/.test(html) &&
          html.indexOf('href="/admin/policies#passkey-profile-' +
                       names.strict + '"') >= 0 &&
          html.indexOf('href="/admin/policies#passkey-profile-' +
                       names.client + '"') >= 0 &&
          /class="pk-applies"/.test(html) &&
          !/<form|<input|<button/.test(html) &&
          html.indexOf('<code>' + CLIENT + '</code> gets <strong>' +
                       names.client + '</strong>') >= 0,
          'B1. the card lists both, links each, marks the winner, says what ' +
          'a sign-in naming the client_id gets, and holds no control',
          html.slice(0, 600));
  t.check(/select by group/.test(html) && /<strong>default<\/strong>/
    .test(page.applicationPasskeyPolicyCard(readOf(LONE), ctx.t)),
          'B2. it says a group policy can still win, and names default ' +
          'where nothing names the application');
  t.check(page.applicationPasskeyPolicyCard({ page: {} }, ctx.t) === '',
          'B3. an answer without the member draws nothing');
  const section = page.applicationFieldsSection(ctx, json, '');
  const every = section.indexOf('id="cfg-every"');
  const oauth = section.indexOf('id="cfg-oauth"');
  const at = section.indexOf('id="cfg-every-passkey"');
  t.check(every >= 0 && at > every && (oauth < 0 || at < oauth),
          'B4. it is drawn on the Every protocol sub-tab',
          JSON.stringify({ every: every, at: at, oauth: oauth }));
  log.debug('Leaving card().');
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
          named.indexOf('name="profile" value="' + names.client + '"') >= 0,
          'C2. each named policy is on Named policies, its heading the ' +
          'card\'s link target, what it selects said, and its form');
  const added = html.slice(at('id="passkey-sub-new"'));
  t.check(/name="profile" pattern=/.test(added.slice(0, added.indexOf(
    '</form>'))) && html.slice(at('id="passkey-sub-default"'),
                                at('id="passkey-sub-named"'))
    .indexOf('name="profile" value="default"') >= 0,
          'C3. the New policy form is on its own sub-tab and the default ' +
          'profile\'s on Default');
  t.check(at('id="locale-sub-default"') < 0 && at('id="locale-named"') > 0,
          'C4. the locale policy keeps its named profiles under its default');
  log.debug('Leaving subTabs().');
  return { html: html, view: view };
}

function search(t, drawn, names) {
  log.debug('Entering search().');
  const policies = require(ROOT + '/admin-ui/web_policies');
  const answers = require(ROOT + '/admin-ui/web_answers');
  const kit = require(ROOT + '/admin-ui/web_kit');
  const html = drawn.html;
  const strictKey = 'passkey-apps.' + names.strict;
  t.check(html.indexOf('id="fgc-' + strictKey + '"') >= 0 &&
          html.indexOf('id="fgc-passkey-apps"') >= 0 &&
          html.indexOf('formaction="/admin/policies#fgc-' + strictKey +
                       '"') >= 0 &&
          /class="default-submit"/.test(html) &&
          html.indexOf('id="fgc-locale-apps') < 0,
          'D1. each named passkey form and the New policy form has its own ' +
          'search under its applications box, and a default Save first; ' +
          'the locale policy has none');
  t.check(answers.isFieldSearch('/admin/policies',
                                { fgsearch: strictKey }) &&
          answers.isFieldSearch('/admin/policies',
                                { fgadd: 'passkey-apps|x' }) &&
          !answers.isFieldSearch('/admin/policies',
                                 { action: 'save-passkey-policy' }),
          'D2. a Find or an Add on the page is a field search; a Save is not');
  const asked = answers.fieldSearchOf({ fgadd: strictKey + '|' + OTHER,
                                        ['fgpage.' + strictKey]: '2',
                                        ['fgfind.' + strictKey]: TAG });
  t.check(asked.attribute === strictKey && asked.add === OTHER &&
          asked.page === 2 && asked.query === TAG,
          'D3. the press is read with its key, its query and its value',
          JSON.stringify(asked));
  const box = answers.withListedValue(APP + ', ' + CLIENT, OTHER);
  t.check(box === APP + ', ' + CLIENT + ', ' + OTHER &&
          answers.withListedValue(box, OTHER.toUpperCase()) === box &&
          JSON.stringify(answers.listedValues(' a ,, b\nc ')) ===
            '["a","b","c"]',
          'D4. Add appends the identifier to the box, once, in any case',
          box);
  const where = answers.fieldSearchPath('policy-applications',
                                        { query: TAG, page: 1 },
                                        answers.listedValues(box));
  t.check(/^\/admin-api\/applications\?/.test(where) && /per=5/.test(where) &&
          where.indexOf('exclude=' + encodeURIComponent(OTHER)) > 0,
          'D5. it asks the Applications list, five a page, leaving out what ' +
          'the box names', where);
  const listed = adminViews.applicationsJson(Object.assign(request(), {
    query: { q: TAG, per: '5', page: '1',
             exclude: answers.listedValues(box) } }));
  const found = answers.fieldSearchFound('policy-applications',
                                         { query: TAG, page: 1 }, listed);
  t.check(!found.failed && found.rows.length === 1 &&
          found.rows[0].value === LONE,
          'D6. the results are applications by IDENTIFIER, the ones held ' +
          'left out', JSON.stringify(found));
  const draft = { action: 'save-passkey-policy', profile: names.strict,
                  selectApplications: box, selectGroups: 'typed-group',
                  precedence: '7' };
  const view = Object.assign({}, drawn.view, { state: {
    policyDrafts: { [strictKey]: draft }, finds: { [strictKey]: found } } });
  const again = policies.body(kit.context(), view);
  const cell = again.slice(again.indexOf('id="fgc-' + strictKey + '"'));
  const formOf = again.slice(again.indexOf('id="passkey-profile-' +
                                           names.strict + '"'));
  t.check(/^id="fgc-[^"]*" class="fg-cell fg-search fg-search-open"/
    .test(cell) &&
          cell.indexOf('value="' + strictKey + '|' + LONE + '"') >= 0 &&
          formOf.indexOf('value="' + box + '"') >= 0 &&
          formOf.indexOf('value="typed-group"') >= 0 &&
          /name="precedence" min="1" max="1000" value="7"/.test(formOf),
          'D7. a redraw keeps what the form held — the added identifier in ' +
          'the box — with the results and their Add under it',
          cell.slice(0, 400));
  log.debug('Leaving search().');
}

function run(t) {
  log.debug('Entering run().');
  const names = { strict: TAG + '-strict', client: TAG + '-byclient',
                  other: TAG + '-elsewhere' };
  const group = TAG + '-group';
  ldap.createGroup(group);
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
      named(names.strict, { selectApplications: APP, precedence: 5,
        registrationAlgorithms: 'ES256,RS256',
        registrationMode: 'classical-only' }),
      named(names.client, { selectApplications: CLIENT.toUpperCase(),
                            selectGroups: group, precedence: 40 }),
      named(names.other, { selectApplications: OTHER, precedence: 1 })
    ];
    t.check(saves.every(function (one) {
      return one.ok;
    }), 'three named policies are saved', JSON.stringify(saves.map(
      function (one) {
        return one.errors;
      })));
    const offer = webauthnPolicy.registrationOffer({ application: APP });
    t.check(offer.profile === names.strict &&
            offer.mode === 'classical-only' && offer.from === 'profile' &&
            JSON.stringify(offer.algorithms) === '["ES256","RS256"]',
            'A0. the selected application profile supplies its ordered ' +
            'classical-only registration list',
            JSON.stringify(offer));
    const conflict = named(TAG + '-conflict', {
      registrationAlgorithms: 'ES256',
      registrationMode: 'classical-only',
      postQuantumRequired: 'registration-and-sign-in'
    });
    t.check(!conflict.ok,
            'A0b. classical-only cannot coexist with a profile that requires ' +
            'a post-quantum registration', JSON.stringify(conflict.errors));
    const json = data(t, names);
    card(t, json, names);
    const drawn = subTabs(t, names);
    search(t, drawn, names);
  } finally {
    passkeyPolicy.reset(names.strict);
    passkeyPolicy.reset(names.client);
    passkeyPolicy.reset(names.other);
  }
  log.debug('Leaving run().');
}

module.exports = {
  name: 'passkey policy on application',
  describe: 'An application\'s passkey policies shown read-only on its ' +
            'Every protocol sub-tab, and the Passkey policy tab\'s sub-tabs ' +
            'and application search (#609)',
  run: run
};
