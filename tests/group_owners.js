// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: group_owners.js
//
// ===========================================================================
// A GROUP'S OWNERS (#603), in process.
//
// rcbj: "apply this same owner pattern to Groups. Add an owner tab to
// Directory->Groups, groups tab, group page. Call the primary tab group.
// Call this new tab owners." A group's owners are its RFC 4519 `owner`
// values, each a person or a group of the realm; `ldap/ldap_server.js` adds
// and takes them off one at a time, `admin-core/admin_actions.ts` answers
// the two acts, `admin-ui/web_groups.ts` draws the Owners tab and
// `admin-ui/web_answers.ts` and the runtime answer its search and its acts
// in the browser. Held here:
//
//   A. THE DIRECTORY: a person and a group added by any name they answer
//      to, each once; an owner that names nobody, the group itself, no
//      owner and one past the most are refused with their codes; a remove
//      of a value not listed is refused, and the last owner may go; every
//      other attribute (the members) is kept; the group's view answers
//      `owners` and the list `ownerCount`; an owner deleted since is
//      reported, never dropped.
//   B. THE ACTS: `add-owner` and `remove-owner` through `groupsAction()`
//      answer the owners as they now stand, a refusal carries its codes,
//      and the unknown-action sentence names all four actions.
//   C. THE CONSOLE'S HELPERS: the tab's Find is a search on its own route
//      only; an act draws the page again in place with the answer's owners
//      and the search kept; a refusal says why and changes nothing.
//   D. THE PAGE: two tabs, Group first then Owners; the owners table with a
//      Remove form each; the search's results with an Add that writes, or
//      why not (already an owner, the group itself); no form without Admin
//      Write; and the stylesheet marks both tabs when they are read.
// ===========================================================================

delete process.env.CONFIG_FILE;

require('../common/i18n');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const adminActions = require('../admin-core/admin_actions');
const WebAnswers = require('../admin-ui/web_answers');
const GroupsPage = require('../admin-ui/web_groups');
const kit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({ name: 'group_owners',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'Gr0up-Own3rs-Pa55word!x';
const PAGE = '/admin/groups/owners';

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

function dnOf(name) {
  log.debug('Entering dnOf().');
  const entry = ldap.existingUserEntry(name);
  log.debug('Leaving dnOf().');
  return entry ? entry.dn : '';
}

function ownerValues(groupDn) {
  log.debug('Entering ownerValues().');
  const entry = ldap.readGroupEntry(groupDn);
  const attributes = (entry && entry.attributes) || {};
  const key = Object.keys(attributes).filter(function (one) {
    return one.toLowerCase() === 'owner';
  })[0];
  log.debug('Leaving ownerValues().');
  return key ? attributes[key].map(String) : [];
}

async function theDirectory(t) {
  log.debug('Entering theDirectory().');
  await withRealm(t, 'grp-owners', function () {
    person('go-ann');
    person('go-bo');
    const made = ldap.createGroup('go-team', { origin: 'test',
                                              members: ['go-ann'] });
    const ops = ldap.createGroup('go-ops', { origin: 'test' });
    t.check(made.ok && ops.ok, 'A0. two groups to own and be owners',
            JSON.stringify({ made: made, ops: ops }).slice(0, 300));
    const team = made.dn;

    const ann = ldap.addGroupOwner('go-team', 'go-ann', {});
    const again = ldap.addGroupOwner(team, dnOf('go-ann').toUpperCase(), {});
    const group = ldap.addGroupOwner('go-team', 'go-ops', {});
    t.check(ann.ok && ann.changed === true && again.ok &&
            again.changed === false && group.ok &&
            group.owners.length === 2 &&
            group.owners[0].kind === 'person' &&
            group.owners[1].kind === 'group' &&
            group.owners[1].name === 'go-ops' &&
            ownerValues(team).length === 2,
            'A1. a person and a group are added by any name they answer ' +
            'to, each once', JSON.stringify(group));

    const nobody = ldap.addGroupOwner('go-team', 'go-no-such-one', {});
    const itself = ldap.addGroupOwner('go-team', team, {});
    const none = ldap.addGroupOwner('go-team', '', {});
    const noGroup = ldap.addGroupOwner('go-nothing-here', 'go-ann', {});
    t.check(errorCodes.codeOf(nobody) === 'STS-LDAP-0135' &&
            errorCodes.codeOf(itself) === 'STS-LDAP-0136' &&
            errorCodes.codeOf(none) === 'STS-LDAP-0134' &&
            errorCodes.codeOf(noGroup) === 'STS-LDAP-0050' &&
            ownerValues(team).length === 2,
            'A2. an owner naming nobody, the group itself, no owner and ' +
            'no group are refused and write nothing',
            JSON.stringify([nobody, itself, none, noGroup]).slice(0, 400));

    const members = ldap.readGroupEntry(team).members.length;
    const stranger = ldap.removeGroupOwner('go-team', dnOf('go-bo'), {});
    const off = ldap.removeGroupOwner('go-team', dnOf('go-ann'), {});
    t.check(errorCodes.codeOf(stranger) === 'STS-LDAP-0138' &&
            off.ok && off.owners.length === 1 &&
            off.owners[0].name === 'go-ops' &&
            ldap.readGroupEntry(team).members.length === members &&
            members === 1,
            'A3. a remove of a value not listed is refused; a remove keeps ' +
            'the other owners and the members',
            JSON.stringify({ stranger: stranger, off: off }).slice(0, 400));

    const last = ldap.removeGroupOwner('go-team', ops.dn, {});
    t.check(last.ok && last.owners.length === 0 &&
            ownerValues(team).length === 0,
            'A4. the last owner may go: a group needs none',
            JSON.stringify(last));

    const view = ldap.groupsFor(team);
    ldap.addGroupOwner('go-team', 'go-bo', {});
    const listed = ldap.groupsFor('');
    const row = listed.groups.filter(function (one) {
      return one.dn === team;
    })[0];
    t.check(view.found && Array.isArray(view.group.owners) &&
            view.group.maxOwners === ldap.MAX_GROUP_OWNERS &&
            row && row.ownerCount === 1,
            'A5. the group\'s view answers `owners` and `maxOwners`, the ' +
            'list `ownerCount`', JSON.stringify({ owners: view.group.owners,
                                                row: row }).slice(0, 300));

    ldap.deletePerson(dnOf('go-bo'));
    const after = ldap.groupsFor(team).group.owners;
    t.check(after.length === 1 && after[0].kind === '' &&
            after[0].present === false,
            'A6. an owner deleted since is reported, never dropped',
            JSON.stringify(after));

    const many = [];
    for (let i = 0; i < ldap.MAX_GROUP_OWNERS; i++) {
      ldap.createUser('go-p' + i, { invent: false });
      many.push(ldap.addGroupOwner('go-ops', 'go-p' + i, {}).ok);
    }
    person('go-one-more');
    const over = ldap.addGroupOwner('go-ops', 'go-one-more', {});
    t.check(many.every(Boolean) &&
            errorCodes.codeOf(over) === 'STS-LDAP-0137' &&
            ownerValues(ops.dn).length === ldap.MAX_GROUP_OWNERS,
            'A7. past the most owners a group may name is refused',
            JSON.stringify(over).slice(0, 200));
  });
  log.debug('Leaving theDirectory().');
}

async function theActs(t) {
  log.debug('Entering theActs().');
  await withRealm(t, 'grp-owners-acts', function () {
    person('ga-ann');
    const made = ldap.createGroup('ga-team', { origin: 'test' });
    const added = adminActions.groupsAction({ action: 'add-owner',
      group: made.dn, owner: 'ga-ann', actor: 'an-operator' });
    const removed = adminActions.groupsAction({ action: 'remove-owner',
      group: made.dn, owner: dnOf('ga-ann'), actor: 'an-operator' });
    const refused = adminActions.groupsAction({ action: 'add-owner',
      group: made.dn, owner: 'ga-nobody' });
    const unknown = adminActions.groupsAction({ action: 'no-such' });
    t.check(added.ok && added.owners.length === 1 &&
            /is now an owner of/.test(added.message) &&
            removed.ok && removed.owners.length === 0 &&
            refused.ok === false &&
            // The directory's own code wins (`refusedBy()`): it names the
            // condition, where STS-ADMIN-0852 names only the door.
            errorCodes.codeOf(refused) === 'STS-LDAP-0135' &&
            /create, add-member, add-owner, remove-owner/.test(
              (unknown.errors || []).join(' ')),
            'B1. the two acts answer the owners as they now stand, a ' +
            'refusal carries the directory\'s code, and the refusal ' +
            'sentence names all ' +
            'four actions',
            JSON.stringify({ added: added, removed: removed,
                             refused: refused, unknown: unknown })
              .slice(0, 600));
  });
  log.debug('Leaving theActs().');
}

function theHelpers(t) {
  log.debug('Entering theHelpers().');
  t.check(WebAnswers.GROUP_OWNERS_PAGE === PAGE &&
          WebAnswers.isFieldSearch(PAGE, { fgsearch: 'owners' }) &&
          !WebAnswers.isFieldSearch(PAGE, { action: 'add-owner',
                                            owner: 'x' }) &&
          !WebAnswers.isFieldSearch('/admin/groups', { fgsearch: 'owners' }),
          'C1. the tab\'s Find is a search on its own route only; an Add ' +
          'is an act');
  const find = { kind: 'owners', which: 'people', query: 'a', page: 1,
                 pages: 1, matched: 1, rows: [] };
  const page = { found: true,
                 group: { dn: 'cn=team,ou=groups,dc=x', owners: [] },
                 state: { groupOwners: { find: find } } };
  const owners = [{ dn: 'uid=a,ou=users,dc=x', kind: 'person', name: 'a',
                    present: true }];
  const done = WebAnswers.redraw(PAGE, 'add-owner',
    { group: 'cn=team,ou=groups,dc=x', owner: 'uid=a,ou=users,dc=x' },
    { ok: true, owners: owners, message: 'a is now an owner.' }, page);
  const state = done && done.json.state.groupOwners;
  t.check(done && done.json.group.owners.length === 1 &&
          state.notice === 'a is now an owner.' && state.find &&
          state.find.query === 'a' && done.banner === '' &&
          page.group.owners.length === 0,
          'C2. an act draws the page again in place with the answer\'s ' +
          'owners and the search kept',
          JSON.stringify(done && done.json).slice(0, 400));
  const refused = WebAnswers.redraw(PAGE, 'remove-owner',
    { owner: 'x' }, { ok: false, errors: ['Not an owner.'] }, page);
  const rs = refused && refused.json.state.groupOwners;
  t.check(rs && rs.error[0] === 'Not an owner.' && rs.notice === '' &&
          refused.json.group.owners.length === 0,
          'C3. a refusal says why and changes nothing', JSON.stringify(rs));
  log.debug('Leaving theHelpers().');
}

function thePage(t) {
  log.debug('Entering thePage().');
  const group = {
    dn: 'cn=team,ou=groups,dc=x', cn: 'team', rule: 'placement',
    origin: 'test', createdAt: '', modifiedAt: '', operational: [],
    memberAttributes: ['member'], attributes: {}, members: [],
    memberCount: 0, presentCount: 0, danglingCount: 0, claimed: [],
    owners: [{ dn: 'uid=ann,ou=users,dc=x', kind: 'person', name: 'ann',
               present: true },
             { dn: 'cn=gone,ou=groups,dc=x', kind: '', name: '',
               present: false }],
    maxOwners: 25
  };
  const view = { found: true, group: group, known: {}, canWrite: true,
                 usersDn: 'ou=users,dc=x', groupsDn: 'ou=groups,dc=x',
                 port: 389, adminGroups: {},
                 membersPaging: { total: 0, perPage: 50, page: 1, pages: 1,
                                  param: 'page', noun: 'members' },
                 claimedPaging: { total: 0, perPage: 50, page: 1, pages: 1,
                                  param: 'claimedPage', noun: 'entries' },
                 state: { groupOwners: { find: { which: 'people',
                   query: 'a', page: 1, pages: 2, matched: 7,
                   rows: [{ kind: 'person', value: 'uid=ann,ou=users,dc=x',
                            label: 'ann' },
                          { kind: 'group', value: 'cn=team,ou=groups,dc=x',
                            label: 'team' },
                          { kind: 'person', value: 'uid=cy,ou=users,dc=x',
                            label: 'cy' }] } } } };
  const html = GroupsPage.detail(kit.context({ group: group.dn }, true),
                                 view);
  const tr = kit.context().t;
  const groupTab = html.indexOf('id="gtab-group"');
  const ownersTab = html.indexOf('id="gtab-owners"');
  const removes = html.match(/name="action" value="remove-owner"/g) || [];
  const adds = html.match(/name="owner" value="[^"]*"[^>]*formaction="[^"]*action=add-owner/g) || [];
  t.check(groupTab >= 0 && ownersTab > groupTab &&
          html.indexOf('href="#gtab-group"') <
            html.indexOf('href="#gtab-owners"') &&
          html.indexOf('>' + tr.text('consoleGroups.detail.tabGroup') +
                       '</a>') >= 0 &&
          html.indexOf('>' + tr.text('consoleGroups.detail.tabOwners') +
                       '</a>') >= 0,
          'D1. two tabs, Group first and then Owners');
  t.check(removes.length === 2 && adds.length === 1 &&
          html.indexOf('value="uid=cy,ou=users,dc=x"') >= 0 &&
          html.indexOf(tr.html('consoleGroups.owners.isOwner')) >= 0 &&
          html.indexOf(tr.html('consoleGroups.owners.itself')) >= 0 &&
          html.indexOf('action="/admin/groups/owners#group-owners"') >= 0 &&
          html.indexOf('data-fg-find="owners"') >= 0 &&
          /class="default-submit"[^>]*name="fgsearch" value="owners"/
            .test(html) &&
          html.indexOf('value="owners|2"') >= 0,
          'D2. the owners table with a Remove each, and results whose Add ' +
          'writes, or why not (an owner, the group itself), and the pager');
  const readOnly = GroupsPage.detail(kit.context({ group: group.dn }, false),
                                     view);
  const ownersPart = readOnly.slice(readOnly.indexOf('id="gtab-owners"'));
  t.check(ownersPart.indexOf('remove-owner') < 0 &&
          ownersPart.indexOf('data-fg-find') < 0 &&
          ownersPart.indexOf('uid=ann,ou=users,dc=x') >= 0,
          'D3. without Admin Write the owners are listed and nothing more');
  log.debug('Leaving thePage().');
}

function theStylesheet(t) {
  log.debug('Entering theStylesheet().');
  // THE STYLESHEET NAMES A TAB'S ID to mark it while it is read, since a
  // selector cannot compare a link's href with the targeted id. Asked of the
  // whole stack in a child process, as tests/person_fields.js asks it: this
  // process has loaded modules the composition root must build itself.
  const env = Object.assign({}, process.env);
  delete env.CONFIG_FILE;
  const css = require('child_process').execFileSync(process.execPath, ['-e',
    "require('./common/protocol_stack');" +
    "process.stdout.write(require('./admin-ui/admin').stylesheet());" +
    'process.exit(0);'],
  { cwd: require('path').join(__dirname, '..'), env: env,
    maxBuffer: 64 * 1024 * 1024 }).toString();
  const marked = ['gtab-group', 'gtab-owners'].filter(function (id) {
    return css.indexOf(':has(#' + id + ':target,#' + id + ' :target)' +
                       '>.tabbar a[href="#' + id + '"]') >= 0;
  });
  t.check(marked.length === 2,
          'E1. the stylesheet marks both tabs of a group\'s page when read',
          JSON.stringify(marked));
  log.debug('Leaving theStylesheet().');
}

module.exports = {
  name: 'group owners',
  describe: 'A group\'s owners (#603): people and groups of the realm on ' +
            'its `owner` values, added and taken off one at a time and ' +
            'written at once, on an Owners tab beside the group\'s own',
  run: async function (t) {
    log.debug('Entering run().');
    await theDirectory(t);
    await theActs(t);
    theHelpers(t);
    thePage(t);
    theStylesheet(t);
    log.debug('Leaving run().');
  }
};
