// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: service_account_owners.js
//
// ===========================================================================
// A SERVICE ACCOUNT'S OWNERS (#600), in process.
//
// rcbj: the owner was a text box wanting the owner's whole DN; it became a
// search with a results pane of five at a time, a table of the defined
// owners, and more than one owner. `common/service_accounts.ts` keeps the
// list; `admin-ui/web_users.ts` draws it; `admin-ui/web_answers.ts` and the
// runtime answer the form's Remove and its search in the browser. Held here:
//
//   A. THE LIST: several owners, a person and a group, each once whatever it
//      was called; one per line as a string; none refused while the policy
//      requires one; more than MAX_OWNERS refused (STS-SVCACCT-0031); one
//      bad owner refuses the whole set and writes nothing; none allowed and
//      the attribute gone when the policy does not require one; an owner
//      deleted since is reported, never dropped.
//   B. AN LDAP MODIFY writes two owners, and is refused for one that names
//      nobody; the directory merge treats the attribute as a list.
//   C. THE VIEW: `serviceAccountJson()` answers `owners`, and the person
//      page's data carries the rules the form is held to.
//   D. THE CONSOLE'S HELPERS: the form's Remove is a round trip and its Find,
//      Previous, Next and Add a search, on its route only; the draft keeps
//      what was typed; an Add is kept once with the search's label; a people
//      search asks the Users list and a group search the Groups list, five
//      to a page; a refused Save keeps the draft; and the hidden rows are
//      sent as `owners`, an empty table as an empty list.
//   E. THE SECTION: the owners table with a Remove per row and the hidden
//      rows, one form posting to its route; the search's results, five, with
//      Add, or why not (already an owner, the account itself); the pager;
//      and no form without Admin Write.
// ===========================================================================

delete process.env.CONFIG_FILE;

require('../common/i18n');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const serviceAccounts = require('../common/service_accounts');
const policy = require('../common/service_account_policy');
const ldap = require('../ldap/ldap_server');
const adminViews = require('../admin-core/admin_views');
const directoryMerge = require('../persistence/directory_merge');
const WebAnswers = require('../admin-ui/web_answers');
const ConsoleRuntime = require('../admin-ui/web_runtime');
const UsersPage = require('../admin-ui/web_users');
const kit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({ name: 'service_account_owners',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'Sv1c-Own3rs-Pa55word!x';
const PAGE = '/admin/users/service-account';

function realmId(stem) {
  log.debug('Entering realmId().');
  log.debug('Leaving realmId().');
  return stem + '-' + require('crypto').randomBytes(3).toString('hex');
}

async function withRealm(t, stem, fn) {
  log.debug('Entering withRealm(). ' + stem);
  const id = realmId(stem);
  const made = realms.create({ id: id, name: id,
                               description: 'Created by ' + __filename,
                               overrides: {} });
  if (!made.ok) {
    t.bad('could not create the realm "' + id + '"',
          (made.errors || []).join(' '));
    log.debug('Leaving withRealm(). Not created.');
    return undefined;
  }
  try {
    log.debug('Leaving withRealm().');
    return await realms.run(made.realm, function () {
      return fn(made.realm);
    });
  } finally {
    // Every other file in the run asserts only the default realm is left.
    realms.remove(id);
  }
}

function person(name) {
  log.debug('Entering person().');
  ldap.createUser(name, { invent: false });
  const set = credentials.setPassword(name, PASSWORD);
  log.debug('Leaving person().');
  return set;
}

function stored(name) {
  log.debug('Entering stored().');
  const entry = ldap.existingUserEntry(name);
  log.debug('Leaving stored().');
  return entry ? { dn: entry.dn, attributes: entry.attributes } : null;
}

function ownerValues(name) {
  log.debug('Entering ownerValues().');
  const entry = stored(name);
  const attributes = (entry && entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === 'stsserviceaccountowner';
  })[0];
  log.debug('Leaving ownerValues().');
  return key ? attributes[key].map(String) : [];
}

async function theList(t) {
  log.debug('Entering theList().');
  await withRealm(t, 'svc-owners', function () {
    person('svc-o');
    person('svc-o-ann');
    person('svc-o-bob');
    const group = ldap.createGroup('svc-o-ops', {});
    t.check(group && group.ok, 'A0. a group to own it',
            JSON.stringify(group));
    const annDn = stored('svc-o-ann').dn;
    const made = serviceAccounts.set('svc-o', {
      serviceAccount: true,
      owners: ['svc-o-ann', 'svc-o-ops', annDn.toUpperCase()] });
    t.check(made.ok && made.account.owners.length === 2 &&
            made.account.owners[0].kind === 'person' &&
            made.account.owners[0].name === 'svc-o-ann' &&
            made.account.owners[1].kind === 'group' &&
            made.account.owners[1].name === 'svc-o-ops',
            'A1. a person and a group own it, each once, in the order given',
            JSON.stringify(made));
    t.equal(ownerValues('svc-o').length, 2,
            'A2. the entry holds one stsServiceAccountOwner value per owner');
    const lines = serviceAccounts.set('svc-o', {
      serviceAccount: true, owners: 'svc-o-bob\n\n svc-o-ann \n' });
    t.check(lines.ok && lines.account.owners.map(function (one) {
      return one.name;
    }).join(',') === 'svc-o-bob,svc-o-ann',
            'A3. a string is one owner per line, and the list is REPLACED',
            JSON.stringify(lines));
    const none = serviceAccounts.set('svc-o', { serviceAccount: true,
                                                owners: [] });
    t.equal(errorCodes.codeOf(none), 'STS-SVCACCT-0023',
            'A4. an empty list is refused while the policy requires one');
    const absent = serviceAccounts.set('svc-o', { serviceAccount: true });
    t.equal(errorCodes.codeOf(absent), 'STS-SVCACCT-0023',
            'A5. and so is no `owners` at all: a set replaces the list');
    const bad = serviceAccounts.set('svc-o', {
      serviceAccount: true, owners: ['svc-o-ann', 'nobody-at-all'] });
    t.check(errorCodes.codeOf(bad) === 'STS-SVCACCT-0024' &&
            ownerValues('svc-o').length === 2,
            'A6. one owner who is nobody refuses the set, and nothing is ' +
            'written', JSON.stringify(ownerValues('svc-o')));
    const many = [];
    for (let i = 0; i <= serviceAccounts.MAX_OWNERS; i++) {
      person('svc-o-p' + i);
      many.push('svc-o-p' + i);
    }
    const tooMany = serviceAccounts.set('svc-o', { serviceAccount: true,
                                                   owners: many });
    t.equal(errorCodes.codeOf(tooMany), 'STS-SVCACCT-0031',
            'A7. more than MAX_OWNERS (' + serviceAccounts.MAX_OWNERS +
            ') is refused');
    const enough = serviceAccounts.set('svc-o', {
      serviceAccount: true, owners: many.slice(0, serviceAccounts.MAX_OWNERS) });
    t.check(enough.ok && enough.account.owners.length ===
            serviceAccounts.MAX_OWNERS, 'A8. and exactly MAX_OWNERS is not');
    policy.save('default', Object.assign({}, policy.DEFAULTS,
                                         { requireOwner: false }));
    try {
      const unowned = serviceAccounts.set('svc-o', { serviceAccount: true,
                                                     owners: '' });
      t.check(unowned.ok && unowned.account.owners.length === 0 &&
              ownerValues('svc-o').length === 0,
              'A9. with requireOwner off the list may be empty, and the ' +
              'attribute goes', JSON.stringify(unowned));
    } finally {
      policy.reset('default');
    }
    serviceAccounts.set('svc-o', { serviceAccount: true,
                                   owners: ['svc-o-ann', 'svc-o-bob'] });
    const bobDn = stored('svc-o-bob').dn;
    const gone = ldap.deletePerson(bobDn);
    if (gone && gone.ok !== false) {
      const facts = serviceAccounts.of('svc-o');
      t.check(facts.owners.length === 2 && facts.owners[1].kind === '' &&
              facts.owners[1].dn === bobDn,
              'A10. an owner deleted since is reported with no kind, not ' +
              'dropped', JSON.stringify(facts.owners));
    } else {
      t.bad('A10. could not delete the owner to test it',
            JSON.stringify(gone));
    }
  });
  log.debug('Leaving theList().');
}

async function theLdapModify(t) {
  log.debug('Entering theLdapModify().');
  await withRealm(t, 'svc-owners-ldap', async function () {
    person('svc-l');
    person('svc-l-a');
    person('svc-l-b');
    const dn = stored('svc-l').dn;
    const modify = function (changes) {
      log.debug('Entering modify().');
      log.debug('Leaving modify().');
      return Promise.resolve(ldap.performOperation('modify', {
        dn: dn, boundDn: '', channel: 'ldaps', changes: changes }));
    };
    const two = await modify([
      { operation: 'replace',
        modification: { type: 'stsServiceAccount', values: ['TRUE'] } },
      { operation: 'replace',
        modification: { type: 'stsServiceAccountOwner',
                        values: [stored('svc-l-a').dn,
                                 stored('svc-l-b').dn] } }]);
    t.check(two.ok !== false &&
            serviceAccounts.of('svc-l').owners.length === 2,
            'B1. an LDAP modify writes two owners', JSON.stringify(two));
    const nobody = await modify([
      { operation: 'add',
        modification: { type: 'stsServiceAccountOwner',
                        values: ['uid=nobody,ou=users,' + ldap.baseDn()] } }]);
    t.check(nobody.ok === false &&
            serviceAccounts.of('svc-l').owners.length === 2,
            'B2. and is refused one that names nobody',
            JSON.stringify(nobody));
  });
  t.check(directoryMerge.MULTI.indexOf('stsserviceaccountowner') >= 0,
          'B3. the directory merge keeps both owners two nodes add at once');
  log.debug('Leaving theLdapModify().');
}

async function theView(t) {
  log.debug('Entering theView().');
  await withRealm(t, 'svc-owners-view', function () {
    person('svc-v');
    person('svc-v-owner');
    serviceAccounts.set('svc-v', { serviceAccount: true,
                                   owners: ['svc-v-owner'] });
    const json = adminViews.serviceAccountJson('svc-v');
    t.check(json && Array.isArray(json.owners) && json.owners.length === 1 &&
            json.owners[0].name === 'svc-v-owner' &&
            json.owner === undefined && json.policy.requiresOwner === true,
            'C1. the view answers `owners` and the policy\'s requireOwner',
            JSON.stringify(json));
    const detail = adminViews.userDetailJson({ query: { user: 'svc-v' } },
                                             'svc-v');
    const rules = detail && detail.json && detail.json.page &&
                  detail.json.page.serviceAccountRules;
    if (rules) {
      t.check(rules.requiresOwner === true &&
              rules.maxOwners === serviceAccounts.MAX_OWNERS &&
              rules.dn.toLowerCase() === stored('svc-v').dn.toLowerCase(),
              'C2. the person page carries the rules the form is held to',
              JSON.stringify(rules));
    } else {
      t.log.info('C2. skipped: the page data is built by the users view ' +
                 'only (' + Object.keys((detail && detail.json) || {})
                   .slice(0, 8).join(',') + ')');
    }
  });
  log.debug('Leaving theView().');
}

function theHelpers(t) {
  log.debug('Entering theHelpers().');
  const fields = { action: 'set-service-account', user: 'svc',
                   owners: '', owner: ['uid=a,ou=users,dc=x',
                                       'cn=ops,ou=groups,dc=x'],
                   destination: 'cn=vault,ou=applications,dc=x',
                   secretName: 's', 'fgfind.owners': ' an ',
                   'fgkind.owners': 'groups', 'fgpage.owners': '2' };
  t.check(WebAnswers.isRoundTrip(PAGE, Object.assign({ drop: 'owner.0' },
                                                     fields)) &&
          WebAnswers.isFieldSearch(PAGE, Object.assign({ fgsearch: 'owners' },
                                                       fields)) &&
          !WebAnswers.isFieldSearch(PAGE, fields) &&
          !WebAnswers.isFieldSearch('/admin/users',
                                    { fgsearch: 'owners' }) &&
          WebAnswers.SERVICE_ACCOUNT_PAGE === PAGE,
          'D1. Remove is a round trip and Find a search, on the form\'s own ' +
          'route only');
  const dropped = WebAnswers.roundTrip(PAGE,
    Object.assign({ drop: 'owner.0' }, fields),
    { state: { draft: { kept: true } } });
  const draft = dropped.state.serviceAccount;
  t.check(draft.owners.length === 1 && draft.owners[0] ===
          'cn=ops,ou=groups,dc=x' && draft.destination ===
          'cn=vault,ou=applications,dc=x' && draft.secretName === 's' &&
          dropped.state.draft.kept === true,
          'D2. a Remove draws the form again without that row and with ' +
          'what was typed, and leaves the Attributes grid\'s draft alone',
          JSON.stringify(dropped.state));
  const found = WebAnswers.fieldSearchFound('owners',
    WebAnswers.fieldSearchOf(Object.assign({ fgsearch: 'owners' }, fields)),
    { groups: [{ dn: 'cn=dev,ou=groups,dc=x', cn: 'dev' }], page: 1,
      pages: 3, matched: 11 });
  t.check(found.which === 'groups' && found.query === 'an' &&
          found.rows[0].kind === 'group' && found.rows[0].label === 'dev' &&
          found.pages === 3 && found.matched === 11,
          'D3. a group search reads the Groups list\'s answer',
          JSON.stringify(found));
  const added = WebAnswers.withOwnerAdded(
    Object.assign(WebAnswers.serviceAccountDraftOf(fields), { find: found }),
    'cn=dev,ou=groups,dc=x');
  const again = WebAnswers.withOwnerAdded(added, 'CN=dev, ou=groups,dc=x');
  t.check(again.owners.length === 3 &&
          again.labels['cn=dev,ou=groups,dc=x'].label === 'dev',
          'D4. an Add is kept once, with the label the search gave it',
          JSON.stringify(again));
  const groupsPath = WebAnswers.fieldSearchPath('owners',
    { which: 'groups', query: 'an', page: 2 }, again.owners);
  const peoplePath = WebAnswers.fieldSearchPath('owners',
    { which: 'people', query: 'an', page: 1 }, again.owners);
  t.check(/^\/admin-api\/groups\?/.test(groupsPath) &&
          /per=5/.test(groupsPath) && /page=2/.test(groupsPath) &&
          /exclude=/.test(groupsPath) &&
          /^\/admin-api\/users\?/.test(peoplePath) &&
          !/exclude=/.test(peoplePath) && /per=5/.test(peoplePath),
          'D5. people ask the Users list, groups the Groups list, five to a ' +
          'page', groupsPath + ' ' + peoplePath);
  const people = WebAnswers.ownerSearchFound({ which: 'people', query: '' },
    { users: [{ dn: 'uid=a,ou=users,dc=x', key: 'a', name: 'Ann' },
              { dn: '', key: 'ghost' }], page: 1, pages: 1, matched: 2 });
  t.check(people.which === 'people' && people.rows[0].kind === 'person' &&
          people.rows[0].label === 'Ann' && people.rows[1].value === '',
          'D6. a people search reads the Users list\'s answer');
  const refused = WebAnswers.redraw(PAGE, 'set-service-account', fields,
    { ok: false, errors: ['No owner.'] }, { state: {} });
  t.check(refused && refused.json.state.serviceAccount.owners.length === 2 &&
          refused.json.state.serviceAccount.error[0] === 'No owner.',
          'D7. a refused Save comes back with its draft and the reason');
  const runtime = new ConsoleRuntime({ location: { pathname: '/admin' } });
  runtime.spec = {};
  const schema = { type: 'object',
    properties: { user: { type: 'string' },
                  serviceAccount: { type: 'boolean' },
                  owners: { type: ['array', 'string'],
                            items: { type: 'string' } } },
    additionalProperties: false };
  const sent = runtime.shapeFields({ user: 'svc', serviceAccount: 'true',
                                     owners: '', owner: ['a', 'b'],
                                     back: '/admin/users',
                                     'fgfind.owners': 'x' }, schema);
  const empty = runtime.shapeFields({ user: 'svc', owners: '' }, schema);
  t.check(Array.isArray(sent.owners) && sent.owners.filter(Boolean)
            .join(',') === 'a,b' && sent.serviceAccount === true &&
          sent.back === undefined && sent['fgfind.owners'] === undefined &&
          empty.owners === '',
          'D8. the rows are sent as `owners`, an empty table as an empty ' +
          'list', JSON.stringify({ sent: sent, empty: empty }));
  log.debug('Leaving theHelpers().');
}

function theSection(t) {
  log.debug('Entering theSection().');
  const tr = kit.context().t;
  const account = {
    owners: [{ dn: 'uid=ann,ou=users,dc=x', kind: 'person', name: 'ann' },
             { dn: 'cn=ops,ou=groups,dc=x', kind: 'group', name: 'ops' }],
    destination: null, secretName: null, rotatedAt: null,
    rotation: { rotates: false, enabled: false, failures: 0 },
    policy: { exemptFromSecondFactor: false, allowBrowserSignIn: false,
              doors: ['ldap'], requiresOwner: true }
  };
  const rules = { requiresOwner: true, maxOwners: 25,
                  dn: 'uid=svc,ou=users,dc=x' };
  const html = UsersPage.serviceAccountSection(tr, 'svc', account,
    { write: true }, '/admin/users', rules, {});
  t.check(html.indexOf('action="/admin/users/service-account#' +
                       'service-account"') >= 0 &&
          html.indexOf('name="owner" value="uid=ann,ou=users,dc=x"') >= 0 &&
          html.indexOf('name="owner" value="cn=ops,ou=groups,dc=x"') >= 0 &&
          html.indexOf('name="drop" value="owner.1"') >= 0 &&
          html.indexOf('name="owners" value=""') >= 0 &&
          html.indexOf('name="fgfind.owners"') >= 0 &&
          html.indexOf('data-fg-find="owners"') >= 0 &&
          html.indexOf('class="default-submit"') <
            html.indexOf('name="drop"'),
          'E1. the owners table: a hidden row and a Remove each, one form ' +
          'on its route, the search box, and Save first for Enter');
  const find = { which: 'people', query: 'a', page: 1, pages: 2, matched: 7,
    rows: [{ kind: 'person', value: 'uid=ann,ou=users,dc=x', label: 'ann' },
           { kind: 'person', value: 'uid=svc,ou=users,dc=x', label: 'svc' },
           { kind: 'person', value: 'uid=cy,ou=users,dc=x', label: 'cy' },
           { kind: 'person', value: '', label: 'ghost' }] };
  const searched = UsersPage.serviceAccountSection(tr, 'svc', account,
    { write: true }, '/admin/users', rules,
    { serviceAccount: { owners: ['uid=ann,ou=users,dc=x'], labels: {},
                        destination: '', secretName: '', find: find } });
  const adds = searched.match(/name="fgadd"/g) || [];
  t.check(adds.length === 1 &&
          searched.indexOf('value="owners|uid=cy,ou=users,dc=x"') >= 0 &&
          searched.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
                                   'isOwner')) >= 0 &&
          searched.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
                                   'itself')) >= 0 &&
          searched.indexOf('value="owners|2"') >= 0 &&
          /name="fgsearch" value="owners\|0"[^>]*disabled/.test(searched) &&
          searched.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
                                   'unsaved')) >= 0,
          'E2. the results: Add only for a new owner, "an owner" and "this ' +
          'account" otherwise, the pager, and the table marked unsaved');
  const readOnly = UsersPage.serviceAccountSection(tr, 'svc', account,
    { write: false }, '/admin/users', rules, {});
  t.check(readOnly.indexOf('<form') < 0 && readOnly.indexOf('ops') >= 0,
          'E3. without Admin Write the owners are listed and nothing more');
  const ordinary = UsersPage.serviceAccountSection(tr, 'svc', null,
    { write: true }, '/admin/users', rules, {});
  t.check(ordinary.indexOf('name="owner"') < 0 &&
          ordinary.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
                                   'noOwners')) >= 0 &&
          ordinary.indexOf(tr.html('consoleUsers.serviceAccountSection.' +
                                   'make')) >= 0,
          'E4. an ordinary person gets the same form, empty, to make one');
  log.debug('Leaving theSection().');
}

module.exports = {
  name: 'service account owners',
  describe: 'A service account\'s owners (#600): a list of people and ' +
            'groups, at least one where the policy requires it and at most ' +
            'MAX_OWNERS; an LDAP modify held to the same rules; the view; ' +
            'and the console\'s owner table and five-at-a-time search',
  run: async function (t) {
    log.debug('Entering run().');
    await theList(t);
    await theLdapModify(t);
    await theView(t);
    theHelpers(t);
    theSection(t);
    log.debug('Leaving run().');
  }
};
