// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_field_search.js
//
// ---------------------------------------------------------------------------
// THE DELEGATION LISTS' SEARCH, AND THE SELF-REFERENCE RULE (#459).
//
// On an application's Configuration tab, *Every protocol*,
// `appAllowedToDelegateTo` and `appAllowedToActOnBehalfOf` search the
// realm's OTHER applications and `appDelegationSubjectGroup` its groups,
// five to a page, through the two list operations the Applications and
// Groups pages draw (`GET /admin-api/applications`, `GET /admin-api/groups`)
// with `per=5` and the new `exclude`. And neither application list may name
// the application it is on (STS-REG-0335).
//
// What is held here:
//
//   1. THE RULE at every door that writes the two lists: a create, an `add`
//      (the API's set-attribute), the grid's `update-fields` — by the
//      identifier, by a client_id the entry answers to and by an audience it
//      registered — and another application's identifier still accepted.
//   2. THE APPLICATION SEARCH'S DATA: `q` as the list page matches, five a
//      page, paging, `exclude` before the paging (the application itself
//      and what the list holds).
//   3. THE GROUP SEARCH'S DATA: the same over groups, `exclude` by DN in any
//      case and spacing.
//   4. THE CONSOLE'S PURE HELPERS (`admin-ui/web_answers.ts`): reading a
//      press, the address it asks, the box an Add makes, the results drawn
//      from the answer; and `WebKit.fieldGridCell()` drawing the search only
//      on the three cells it is offered on.
//
//   5. `appMayAct` (#461): its search over people OR applications, a pick
//      that REPLACES the one value with the entry's DN, the DN each list now
//      carries (`dn` on a users row) resolving to the claim `may_act`
//      makes, and the self-reference rule by DN at a create and a set.
//
// The search runs in the browser through the runtime, and its CSS
// (`:focus-within`) is a browser's; neither is driven here.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
const dir = require('../ldap/ldap_server');
const credentials = require('../common/credentials');
const policy = require('../common/delegation_policy');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const webAnswers = require('../admin-ui/web_answers');
const webKit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({ name: 'application_field_search',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'fsrch' + process.pid;
const ID = TAG + '-self';

/**
 * A request for one of the list operations.
 *
 * @param query - the query
 * @returns the request
 */
function requestWith(query) {
  log.debug("Entering requestWith().");
  log.debug("Leaving requestWith().");
  return { query: query, headers: { host: 'localhost:8081' },
           protocol: 'https', get: function () { return ''; } };
}

/**
 * Whether a refusal carries STS-REG-0335 and names the attribute.
 *
 * @param result - the action's answer
 * @param attribute - the attribute
 * @returns true when it is the self-reference refusal
 */
function selfRefused(result, attribute) {
  log.debug("Entering selfRefused().");
  const text = ((result && result.errors) || []).join(' ');
  log.debug("Leaving selfRefused().");
  return !!result && result.ok === false &&
         text.indexOf(attribute) >= 0 && /names this application itself/
           .test(text);
}

function run(t) {
  log.debug("Entering run().");
  const others = [];
  for (let i = 0; i < 7; i++) {
    others.push(TAG + '-other-' + i);
  }

  // --- 1. The rule ------------------------------------------------------
  const created = adminActions.applicationsAction({
    action: 'create', identifier: ID, 'field.oauthClientId': ID + '-client',
    'field.oauthAudience': 'https://' + TAG + '.example/api'
  }, ['oauth2']);
  t.check(created && created.ok === true, '1a. the application is created',
          JSON.stringify(created && created.errors));
  others.forEach(function (one) {
    adminActions.applicationsAction({ action: 'create', identifier: one,
                                      name: 'Partner ' + one }, []);
  });

  const createSelf = adminActions.applicationsAction({
    action: 'create', identifier: TAG + '-new',
    'field.appAllowedToDelegateTo': TAG + '-new'
  }, []);
  t.check(selfRefused(createSelf, 'appAllowedToDelegateTo') &&
          !applications.get(TAG + '-new'),
          '1b. a create whose appAllowedToDelegateTo names itself is ' +
          'refused, and nothing is created',
          JSON.stringify(createSelf && createSelf.errors));
  const createByClientId = adminActions.applicationsAction({
    action: 'create', identifier: TAG + '-new2',
    'field.oauthClientId': TAG + '-new2-cid',
    'field.appAllowedToActOnBehalfOf': TAG + '-new2-cid'
  }, ['oauth2']);
  t.check(selfRefused(createByClientId, 'appAllowedToActOnBehalfOf'),
          '1c. so is one naming a client_id the same create gives it',
          JSON.stringify(createByClientId && createByClientId.errors));

  ['appAllowedToDelegateTo', 'appAllowedToActOnBehalfOf']
    .forEach(function (attribute) {
      [ID, ID + '-client', 'https://' + TAG + '.example/api']
        .forEach(function (value, n) {
          const added = adminActions.applicationsAction({
            action: 'add', application: ID, attribute: attribute,
            value: value });
          t.check(selfRefused(added, attribute),
                  '1d. an add of ' + attribute + ' naming the application ' +
                  ['by its identifier', 'by its client_id',
                   'by its audience'][n] + ' is refused',
                  JSON.stringify(added && added.errors));
        });
      const grid = adminActions.applicationsAction({
        action: 'update-fields', application: ID,
        present: attribute,
        ['field.' + attribute + '.0']: others[0],
        ['field.' + attribute + '.1']: ID
      });
      const held = [].concat((applications.get(ID) || { fields: {} })
        .fields[attribute] || []);
      t.check(grid && grid.ok === false &&
              /names this application itself/.test(
                (grid.errors || []).join(' ')) &&
              held.indexOf(ID) < 0 && held.indexOf(others[0]) >= 0,
              '1e. the grid\'s Save of ' + attribute + ' refuses the value ' +
              'naming itself and writes the other application',
              JSON.stringify({ errors: grid && grid.errors, held: held }));
    });
  t.check(applications.selfReferenceProblem('appDelegationSubjectGroup',
                                            ID, ID, {}) === '',
          '1f. the rule is the two application lists\' only');

  // --- 2. The application search's data ---------------------------------
  const listed = function (query) {
    return adminViews.applicationsJson(requestWith(query));
  };
  const first = listed({ q: TAG.toUpperCase(), per: '5', page: '1',
                         exclude: [ID, others[0]] });
  const ids = (first.applications || []).map(function (one) {
    return one.identifier;
  });
  t.check(first.matched === 6 && first.applications.length === 5 &&
          first.pages === 2 && ids.indexOf(ID) < 0 &&
          ids.indexOf(others[0]) < 0,
          '2a. q matches as the Applications page does (any case), five to ' +
          'a page, with the application itself and a held value left out ' +
          'BEFORE the paging',
          JSON.stringify({ matched: first.matched, pages: first.pages,
                           ids: ids }));
  const second = listed({ q: TAG, per: '5', page: '2',
                          exclude: [ID, others[0]] });
  t.check(second.page === 2 && second.applications.length === 1 &&
          ids.indexOf(second.applications[0].identifier) < 0,
          '2b. the second page holds the sixth, and no row of the first',
          JSON.stringify(second.applications));
  const single = listed({ q: TAG, per: '5', exclude: ID });
  t.check(single.matched === 7 &&
          JSON.stringify(single.filter.exclude) === JSON.stringify([ID]),
          '2c. one exclude is a string, and the answer says what it left out',
          JSON.stringify(single.filter));

  // --- 3. The group search's data ---------------------------------------
  const groupNames = [];
  for (let i = 0; i < 6; i++) {
    groupNames.push(TAG + '-group-' + i);
    adminActions.groupsAction({ action: 'create', group: TAG + '-group-' + i });
  }
  const allGroups = adminViews.groupsJson(requestWith({ q: TAG }));
  const dns = (allGroups.groups || []).map(function (one) { return one.dn; });
  t.check(dns.length === 6, '3a. the six groups are there',
          JSON.stringify(dns));
  if (dns.length === 6) {
    const odd = dns[0].toUpperCase().replace(/,/g, ', ');
    const page1 = adminViews.groupsJson(requestWith({
      q: TAG.toUpperCase(), per: '5', page: '1', exclude: odd }));
    const shown = (page1.groups || []).map(function (one) {
      return one.dn;
    });
    t.check(page1.matched === 5 && shown.length === 5 && page1.pages === 1 &&
            shown.indexOf(dns[0]) < 0,
            '3b. groups match as the Groups page does, five to a page, a ' +
            'held DN left out however its case and spacing are written',
            JSON.stringify({ matched: page1.matched, shown: shown }));
    const paged = adminViews.groupsJson(requestWith({ q: TAG, per: '5',
                                                      page: '2' }));
    t.check(paged.page === 2 && paged.groups.length === 1,
            '3c. and page two of six holds one',
            JSON.stringify({ page: paged.page, n: paged.groups.length }));
  }

  // --- 4. The console's helpers -----------------------------------------
  const fields = { action: 'update-fields', application: ID,
                   'field.appAllowedToDelegateTo.0': others[0],
                   'fgfind.appAllowedToDelegateTo': '  partner ',
                   'fgpage.appAllowedToDelegateTo': '2' };
  t.check(webAnswers.isFieldSearch('/admin/applications/edit',
            Object.assign({ fgsearch: 'appAllowedToDelegateTo' }, fields)) &&
          !webAnswers.isFieldSearch('/admin/applications/edit', fields) &&
          !webAnswers.isFieldSearch('/admin/users/edit',
            { fgsearch: 'appAllowedToDelegateTo' }),
          '4a. Find, Previous, Next and Add are a field search on the ' +
          'application page only');
  const find = webAnswers.fieldSearchOf(Object.assign(
    { fgsearch: 'appAllowedToDelegateTo' }, fields));
  const next = webAnswers.fieldSearchOf(Object.assign(
    { fgsearch: 'appAllowedToDelegateTo|3' }, fields));
  const add = webAnswers.fieldSearchOf(Object.assign(
    { fgadd: 'appAllowedToDelegateTo|urn:a|b' }, fields));
  t.check(find.attribute === 'appAllowedToDelegateTo' &&
          find.query === 'partner' && find.page === 1 && find.add === '' &&
          next.page === 3 && add.add === 'urn:a|b' && add.page === 2,
          '4b. a press read: Find is page one, Next names its page, an Add ' +
          'keeps the page shown and its value may hold a bar',
          JSON.stringify({ find: find, next: next, add: add }));
  const path = webAnswers.fieldSearchPath('applications', find,
                                          [ID, others[0]]);
  t.check(path === '/admin-api/applications?q=partner&per=5&page=1&' +
                   'exclude=' + ID + '&exclude=' + others[0],
          '4c. it asks GET /admin-api/applications with per=5 and the ' +
          'exclusions', path);
  t.check(webAnswers.fieldSearchPath('groups', { query: '', page: 2 }, [])
            === '/admin-api/groups?per=5&page=2',
          '4d. a group search asks GET /admin-api/groups');
  const withAdd = webAnswers.withValueAdded(fields, 'appAllowedToDelegateTo',
                                            others[1]);
  const again = webAnswers.withValueAdded(withAdd, 'appAllowedToDelegateTo',
                                          others[1]);
  t.check(withAdd['field.appAllowedToDelegateTo.1'] === others[1] &&
          Object.keys(again).length === Object.keys(withAdd).length,
          '4e. an Add is a new box after the held ones, and never a second ' +
          'box holding the same value');
  const found = webAnswers.fieldSearchFound('applications', find, first);
  const groupFound = webAnswers.fieldSearchFound('groups', find,
    adminViews.groupsJson(requestWith({ q: TAG, per: '5' })));
  t.check(found.rows.length === 5 && found.pages === 2 && !found.failed &&
          groupFound.rows.length === 5 &&
          /^cn=/i.test(groupFound.rows[0].value) &&
          webAnswers.fieldSearchFound('groups', find, null).failed === true,
          '4f. results are drawn from the answer: identifiers for ' +
          'applications, DNs for groups, and a failed call says so',
          JSON.stringify({ app: found.rows[0], group: groupFound.rows[0] }));
  const row = function (attribute) {
    return { attribute: attribute, type: 'array', families: [],
             everyFamily: true, what: attribute };
  };
  const opts = { redraw: '/admin/applications/edit',
                 searches: applications.FIELD_SEARCHES,
                 finds: { appDelegationSubjectGroup: groupFound } };
  const groupCell = webKit.fieldGridCell(row('appDelegationSubjectGroup'),
                                         {}, opts);
  const delegateCell = webKit.fieldGridCell(row('appAllowedToDelegateTo'),
                                            {}, opts);
  const plainCell = webKit.fieldGridCell(row('oauthRedirectUri'), {},
                                         opts);
  t.check(/fg-search/.test(groupCell) && /name="fgadd"/.test(groupCell) &&
          (groupCell.match(/name="fgadd"/g) || []).length === 5 &&
          /tabindex="-1"/.test(groupCell) &&
          /data-fg-find="appAllowedToDelegateTo"/.test(delegateCell) &&
          !/name="fgadd"/.test(delegateCell) &&
          !/fg-search|fgfind/.test(plainCell),
          '4g. the grid draws a search on the cells it is offered on — five ' +
          'Adds after a search — and none on any other');
  // #462: a cell holding a search is drawn OPEN by its class, because the
  // redraw a Find makes takes focus with it and `:focus-within` alone
  // closed the cell on the press that filled it.
  t.check(/class="fg-cell fg-search fg-search-open/.test(groupCell) &&
          !/fg-search-open/.test(delegateCell),
          '4g-ii. a cell with results is drawn open (fg-search-open), one ' +
          'without is not (#462)');
  // #462, rcbj: a search that found nothing, an empty query and a failed
  // call keep the cell open too — the box, Find and the line saying so.
  const asCell = function (found) {
    return webKit.fieldGridCell(row('appDelegationSubjectGroup'), {},
      Object.assign({}, opts, { finds: { appDelegationSubjectGroup: found } }));
  };
  const none = asCell(webAnswers.fieldSearchFound('groups',
    { query: 'zzz', page: 1 }, { groups: [], page: 1, pages: 1, matched: 0 }));
  const empty = asCell(webAnswers.fieldSearchFound('groups',
    { query: '', page: 1 }, { groups: [], page: 1, pages: 1, matched: 0 }));
  const failed = asCell(webAnswers.fieldSearchFound('groups',
    { query: 'x', page: 1 }, null));
  t.check(/fg-search-open/.test(none) && /value="zzz"/.test(none) &&
          /No matches for &ldquo;zzz&rdquo;/.test(none) &&
          /name="fgsearch"/.test(none) && !/fg-next/.test(none) &&
          /fg-search-open/.test(empty) && /fg-hint/.test(empty) &&
          /fg-search-open/.test(failed) && /could not be run/.test(failed),
          '4g-iii. no matches, an empty query and a failed call are drawn ' +
          'open, with the query kept and a line saying which (#462)');
  t.check(Object.keys(applications.FIELD_SEARCHES).sort().join(',') ===
            'appAllowedToActOnBehalfOf,appAllowedToDelegateTo,' +
            'appDelegationSubjectGroup,appMayAct' &&
          applications.FIELD_SEARCHES.appMayAct === 'parties',
          '4h. four fields have a search: two lists of applications, one of ' +
          'groups, and appMayAct over people or applications (#461)');

  // --- 5. appMayAct (#461) ---------------------------------------------
  mayAct(t, others[1]);

  // --- Clean up ---------------------------------------------------------
  [ID].concat(others).forEach(function (one) {
    adminActions.applicationsAction({ action: 'forget', application: one });
  });
  // The groups stay: the console has no group delete to call, and they live
  // in this test process's directory only.
  log.debug("Leaving run().");
}

/**
 * The `appMayAct` half (#461): the self-reference rule by DN, the DNs the
 * two lists carry, the claim they resolve to, and the console's helpers.
 *
 * @param t - the runner
 * @param other - another application of the realm
 */
function mayAct(t, other) {
  log.debug("Entering mayAct().");
  const own = applications.get(ID);
  const ownDn = String((own && own.dn) || '');
  const spelled = ownDn.toUpperCase().replace(/,/g, ', ');
  const self = adminActions.applicationsAction({
    action: 'set', application: ID, attribute: 'appMayAct', value: spelled });
  t.check(!!ownDn && selfRefusedDn(self),
          '5a. appMayAct naming the application\'s own entry is refused, ' +
          'however the DN\'s case and spacing are written',
          JSON.stringify({ dn: ownDn, errors: self && self.errors }));
  const container = applications.containerDn();
  const created = adminActions.applicationsAction({
    action: 'create', identifier: TAG + '-ma',
    'field.appMayAct': 'cn=' + TAG + '-ma,' + container
  }, []);
  t.check(selfRefusedDn(created) && !applications.get(TAG + '-ma'),
          '5b. so is a create naming the DN its entry is about to be given',
          JSON.stringify(created && created.errors));

  // A person, found through the users list as the console finds them.
  const username = TAG + '-person';
  dir.createUser(username, { invent: false });
  const people = adminViews.usersJson(requestWith({ q: username, per: '5' }));
  const row = (people.users || []).filter(function (one) {
    return one.key === username || one.name === username;
  })[0];
  const personDn = String((row && row.dn) || '');
  const facts = personDn ? credentials.delegationFactsFor(personDn) : null;
  t.check(!!personDn && !!facts && facts.person === true,
          '5c. a users-list row carries its entry\'s DN, and that DN is ' +
          'the one the delegation reader resolves to a person',
          JSON.stringify({ dn: personDn, person: facts && facts.person }));
  const setPerson = adminActions.applicationsAction({
    action: 'set', application: ID, attribute: 'appMayAct',
    value: personDn });
  const claimPerson = policy.mayActClaimFor(ID);
  t.check(setPerson && setPerson.ok === true && !!claimPerson &&
          claimPerson.sub === facts.sub,
          '5d. appMayAct set to that DN is accepted, and may_act names the ' +
          'person by their urn:uuid subject',
          JSON.stringify({ set: setPerson && setPerson.errors,
                           claim: claimPerson, sub: facts && facts.sub }));
  const apps = adminViews.applicationsJson(requestWith({
    q: other, per: '5', exclude: ID }));
  const otherDn = String(((apps.applications || [])[0] || {}).dn || '');
  const setApp = adminActions.applicationsAction({
    action: 'set', application: ID, attribute: 'appMayAct',
    value: otherDn });
  const claimApp = policy.mayActClaimFor(ID);
  t.check(!!otherDn && setApp && setApp.ok === true && !!claimApp &&
          claimApp.sub === other,
          '5e. an applications-list row\'s DN is accepted too, and may_act ' +
          'names that application',
          JSON.stringify({ dn: otherDn, claim: claimApp }));

  // The console's helpers for a single-valued, two-kind search.
  const fields = { action: 'update-fields', application: ID,
                   'field.appMayAct': personDn,
                   'fgfind.appMayAct': 'x',
                   'fgkind.appMayAct': 'applications' };
  const asked = webAnswers.fieldSearchOf(Object.assign(
    { fgsearch: 'appMayAct' }, fields));
  const askedPeople = webAnswers.fieldSearchOf({ fgsearch: 'appMayAct' });
  t.check(asked.which === 'applications' && askedPeople.which === 'people' &&
          webAnswers.fieldSearchPath('parties', askedPeople, [ID]) ===
            '/admin-api/users?per=5&page=1' &&
          webAnswers.fieldSearchPath('parties', asked, [ID]) ===
            '/admin-api/applications?q=x&per=5&page=1&exclude=' + ID,
          '5f. the toggle picks the list: GET /admin-api/users for people ' +
          '(no exclude), /admin-api/applications for applications, leaving ' +
          'out the application itself');
  const replaced = webAnswers.withValueAdded(fields, 'appMayAct', otherDn);
  t.check(replaced['field.appMayAct'] === otherDn &&
          !Object.keys(replaced).some(function (key) {
            return /^field\.appMayAct\.\d+$/.test(key);
          }),
          '5g. a Use REPLACES the one value rather than adding a box');
  const foundPeople = webAnswers.fieldSearchFound('parties', askedPeople,
                                                  people);
  const foundApps = webAnswers.fieldSearchFound('parties', asked, apps);
  t.check(foundPeople.which === 'people' &&
          foundPeople.rows.some(function (one) {
            return one.kind === 'person' && one.value === personDn;
          }) &&
          foundApps.which === 'applications' &&
          foundApps.rows[0].kind === 'application' &&
          foundApps.rows[0].value === otherDn,
          '5h. the results are labelled by kind and carry the DN to store',
          JSON.stringify({ people: foundPeople.rows, apps: foundApps.rows }));
  const cell = webKit.fieldGridCell({ attribute: 'appMayAct', type: 'string',
                                      families: [], everyFamily: true,
                                      what: 'appMayAct' }, {},
    { redraw: '/admin/applications/edit',
      searches: applications.FIELD_SEARCHES,
      finds: { appMayAct: foundApps } });
  t.check(/fg-search-open/.test(cell) &&
          /name="fgkind\.appMayAct" value="applications" checked/
            .test(cell) &&
          />Use</.test(cell) && !/>Add</.test(cell) &&
          /name="field\.appMayAct"/.test(cell),
          '5i. the single text box draws the search, the toggle as it was ' +
          'asked, and Use rather than Add');
  adminActions.applicationsAction({ action: 'set', application: ID,
                                    attribute: 'appMayAct', value: '' });
  log.debug("Leaving mayAct().");
}

/**
 * Whether a refusal is the appMayAct self-reference (STS-REG-0335).
 *
 * @param result - the action's answer
 * @returns true when it is
 */
function selfRefusedDn(result) {
  log.debug("Entering selfRefusedDn().");
  log.debug("Leaving selfRefusedDn().");
  return !!result && result.ok === false &&
         /appMayAct: .* is this application's own entry/
           .test((result.errors || []).join(' '));
}

module.exports = {
  name: 'application field search',
  describe: 'appAllowedToDelegateTo / appAllowedToActOnBehalfOf may not ' +
            'name the application itself (STS-REG-0335), and the three ' +
            'delegation lists\' search: five a page through the Applications ' +
            'and Groups list operations, with exclude',
  run: run
};
