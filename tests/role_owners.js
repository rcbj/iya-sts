// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: role_owners.js
//
// ===========================================================================
// A ROLE'S OWNERS AND ITS PAGE (#604), in process.
//
// rcbj: "add the concept of an owner to roles ... create that [drill-down]
// ... add information about everything we know about the role on this new
// page. Create a second tab on this page called owners. use the same owners
// pattern". A role's owners are the `owner` values on its entry under
// `ou=roles`, each a person or a group of the realm; `common/roles.js` adds
// and takes them off through `write()`, `admin-core/admin_actions.ts`
// answers the two acts, `admin-ui/web_roles.ts` draws the page and its
// Owners tab with `web_groups.ts`'s section. Held here:
//
//   A. THE REGISTER: a person and a group added, each once; an owner that
//      names nobody, no owner and a role that is not there are refused with
//      their codes; a remove of a value not listed is refused; the members,
//      the description and the permissions are kept; a describe-role and an
//      add-member, which write the whole record, keep the owners.
//   B. THE ACTS: `add-owner` and `remove-owner` through `rolesAction()`,
//      a refusal's code, and the unknown-action sentence names both.
//   C. THE CONSOLE'S HELPERS: the tab's Find is a search on its own route;
//      an act draws the page again in place with the answer's owners.
//   D. THE PAGE: the role name in the list links to the role's page; two
//      tabs, Role first then Owners; the role's facts, members and
//      requiring applications; the owners with a Remove each for Admin
//      Write and none without; a role that is not there says so.
//   E. THE STYLESHEET marks both tabs when they are read.
// ===========================================================================

delete process.env.CONFIG_FILE;

require('../common/i18n');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const roles = require('../common/roles');
const adminActions = require('../admin-core/admin_actions');
const WebAnswers = require('../admin-ui/web_answers');
const RolesPage = require('../admin-ui/web_roles');
const kit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({ name: 'role_owners',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'R0le-Own3rs-Pa55word!x';
const PAGE = '/admin/roles/owners';

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

async function theRegister(t) {
  log.debug('Entering theRegister().');
  await withRealm(t, 'role-owners', function () {
    person('ro-ann');
    person('ro-bo');
    const ops = ldap.createGroup('ro-ops', { origin: 'test' });
    const made = adminActions.rolesAction({ action: 'create-role',
      role: 'ro-staff', description: 'Staff' });
    const member = adminActions.rolesAction({ action: 'add-member',
      role: 'ro-staff', kind: 'user', member: 'ro-bo' });
    t.check(made.ok && member.ok && ops.ok, 'A0. a role with a member',
            JSON.stringify({ made: made, member: member }).slice(0, 300));

    const ann = roles.addOwner('ro-staff', 'ro-ann');
    const again = roles.addOwner('ro-staff', dnOf('ro-ann').toUpperCase());
    const group = roles.addOwner('ro-staff', 'ro-ops');
    t.check(ann.ok && ann.changed === true && again.ok &&
            again.changed === false && group.ok &&
            group.owners.length === 2 &&
            group.owners[0].kind === 'person' &&
            group.owners[1].kind === 'group' &&
            group.owners[1].name === 'ro-ops' &&
            roles.read('ro-staff').owners.length === 2,
            'A1. a person and a group are added by any name they answer ' +
            'to, each once', JSON.stringify(group));

    const nobody = roles.addOwner('ro-staff', 'ro-no-such-one');
    const none = roles.addOwner('ro-staff', '');
    const noRole = roles.addOwner('ro-nothing-here', 'ro-ann');
    const stranger = roles.removeOwner('ro-staff', dnOf('ro-bo'));
    t.check(errorCodes.codeOf(nobody) === 'STS-XACML-0174' &&
            errorCodes.codeOf(none) === 'STS-XACML-0173' &&
            errorCodes.codeOf(noRole) === 'STS-XACML-0057' &&
            errorCodes.codeOf(stranger) === 'STS-XACML-0176' &&
            roles.read('ro-staff').owners.length === 2,
            'A2. nobody, no owner, no role and a stranger are refused and ' +
            'write nothing',
            JSON.stringify([nobody, none, noRole, stranger]).slice(0, 400));

    const described = adminActions.rolesAction({ action: 'describe-role',
      role: 'ro-staff', description: 'Staff, described' });
    const another = adminActions.rolesAction({ action: 'add-member',
      role: 'ro-staff', kind: 'user', member: 'ro-ann' });
    const row = roles.read('ro-staff');
    t.check(described.ok && another.ok && row.owners.length === 2 &&
            row.users.length === 2 && row.description === 'Staff, described',
            'A3. a describe-role and an add-member keep the owners',
            JSON.stringify(row).slice(0, 400));

    const off = roles.removeOwner('ro-staff', dnOf('ro-ann'));
    const last = roles.removeOwner('ro-staff', ops.dn);
    t.check(off.ok && off.owners.length === 1 && last.ok &&
            last.owners.length === 0 &&
            roles.read('ro-staff').users.length === 2,
            'A4. a remove keeps the members, and the last owner may go',
            JSON.stringify(last));

    roles.addOwner('ro-staff', 'ro-bo');
    ldap.deletePerson(dnOf('ro-bo'));
    const after = roles.ownersOf(roles.read('ro-staff'));
    const entry = roles.entryOf('ro-staff');
    t.check(after.length === 1 && after[0].kind === '' &&
            after[0].present === false && entry && entry.dn &&
            Object.keys(entry.attributes).some(function (name) {
              return name.toLowerCase() === 'owner';
            }),
            'A5. an owner deleted since is reported, never dropped; the ' +
            'entry carries `owner`', JSON.stringify(after));
  });
  log.debug('Leaving theRegister().');
}

async function theActs(t) {
  log.debug('Entering theActs().');
  await withRealm(t, 'role-owners-acts', function () {
    person('ra-ann');
    adminActions.rolesAction({ action: 'create-role', role: 'ra-staff' });
    const added = adminActions.rolesAction({ action: 'add-owner',
      role: 'ra-staff', owner: 'ra-ann', actor: 'an-operator' });
    const removed = adminActions.rolesAction({ action: 'remove-owner',
      role: 'ra-staff', owner: dnOf('ra-ann'), actor: 'an-operator' });
    const refused = adminActions.rolesAction({ action: 'add-owner',
      role: 'ra-staff', owner: 'ra-nobody' });
    const unknown = adminActions.rolesAction({ action: 'no-such' });
    t.check(added.ok && added.owners.length === 1 &&
            /is now an owner of/.test(added.message) &&
            removed.ok && removed.owners.length === 0 &&
            refused.ok === false &&
            errorCodes.codeOf(refused) === 'STS-XACML-0174' &&
            /add-owner, remove-owner/.test((unknown.errors || []).join(' ')),
            'B1. the two acts answer the owners as they now stand, a ' +
            'refusal carries the register\'s code, and the refusal ' +
            'sentence names both actions',
            JSON.stringify({ added: added, refused: refused,
                             unknown: unknown }).slice(0, 600));
  });
  log.debug('Leaving theActs().');
}

function theHelpers(t) {
  log.debug('Entering theHelpers().');
  t.check(WebAnswers.ROLE_OWNERS_PAGE === PAGE &&
          WebAnswers.isFieldSearch(PAGE, { fgsearch: 'owners' }) &&
          !WebAnswers.isFieldSearch(PAGE, { action: 'add-owner',
                                            owner: 'x' }) &&
          !WebAnswers.isFieldSearch('/admin/roles', { fgsearch: 'owners' }),
          'C1. the tab\'s Find is a search on its own route only');
  const page = { role: { found: true, name: 'staff', owners: [] },
                 state: { roleOwners: { find: { query: 'a' } } } };
  const done = WebAnswers.redraw(PAGE, 'add-owner',
    { role: 'staff', owner: 'uid=a,ou=users,dc=x' },
    { ok: true, owners: [{ dn: 'uid=a,ou=users,dc=x', kind: 'person',
                           name: 'a', present: true }],
      message: 'a is now an owner.' }, page);
  const state = done && done.json.state.roleOwners;
  t.check(done && done.json.role.owners.length === 1 &&
          state.notice === 'a is now an owner.' && state.find.query === 'a' &&
          page.role.owners.length === 0,
          'C2. an act draws the page again in place with the answer\'s ' +
          'owners and the search kept',
          JSON.stringify(done && done.json).slice(0, 400));
  log.debug('Leaving theHelpers().');
}

function thePage(t) {
  log.debug('Entering thePage().');
  const role = {
    found: true, name: 'staff', application: '', localName: 'staff',
    dn: 'cn=staff,ou=roles,dc=x', id: 'abc', displayName: 'Staff',
    memberTypes: [], description: 'For the staff', users: ['ann'],
    groups: ['ops'], applications: ['app1'], conferredBy: [],
    permissions: ['https://api.example/read'], owners: [
      { dn: 'uid=ann,ou=users,dc=x', kind: 'person', name: 'ann',
        present: true }],
    maxOwners: 25, requiredBy: [{ application: 'app1', name: 'App one' }],
    holderCount: 3, canWrite: true, console: false, native: false,
    entry: { dn: 'cn=staff,ou=roles,dc=x', createdAt: '20261012000000Z',
             modifiedAt: '20261012000000Z', operational: [],
             attributes: { cn: ['staff'] } }
  };
  const memberKinds = adminActions.ROLE_MEMBER_KINDS;
  const view = { role: role, memberKinds: memberKinds };
  const html = RolesPage.detail(kit.context({ role: 'staff' }, true), view);
  const tr = kit.context().t;
  t.check(html.indexOf('id="rtab-role"') >= 0 &&
          html.indexOf('id="rtab-owners"') > html.indexOf('id="rtab-role"') &&
          html.indexOf('>' + tr.text('consoleRoles.detail.tabOwners') +
                       '</a>') >= 0,
          'D1. two tabs, Role first and then Owners');
  t.check(html.indexOf('cn=staff,ou=roles,dc=x') >= 0 &&
          html.indexOf('/admin/users?user=ann') >= 0 &&
          html.indexOf('/admin/applications?application=app1') >= 0 &&
          html.indexOf('App one') >= 0 &&
          html.indexOf('https://api.example/read') >= 0,
          'D2. the role\'s facts, members, permissions and requiring ' +
          'applications are drawn');
  t.check((html.match(/name="action" value="remove-owner"/g) || []).length ===
            1 &&
          html.indexOf('action="/admin/roles/owners#role-owners"') >= 0 &&
          html.indexOf('name="role" value="staff"') >= 0,
          'D3. the owners with a Remove each, posting the role by name');
  const readOnly = RolesPage.detail(kit.context({ role: 'staff' }, false),
                                    view);
  t.check(readOnly.indexOf('remove-owner') < 0 &&
          readOnly.indexOf('data-fg-find') < 0,
          'D4. without Admin Write the owners are listed and nothing more');
  const missing = RolesPage.detail(kit.context({ role: 'gone' }, true),
    { role: { found: false, name: 'gone' } });
  t.check(missing.indexOf('rtab-') < 0 && missing.indexOf('gone') >= 0,
          'D5. a role that is not there says so');
  const row = RolesPage.roleRow({ name: 'staff', users: [], groups: [],
    applications: [], permissions: [], conferredBy: [] }, {}, memberKinds);
  t.check(row.indexOf('href="/admin/roles?role=staff"') >= 0,
          'D6. the role\'s name in the list opens its page', row.slice(0, 200));
  log.debug('Leaving thePage().');
}

function theStylesheet(t) {
  log.debug('Entering theStylesheet().');
  const env = Object.assign({}, process.env);
  delete env.CONFIG_FILE;
  const css = require('child_process').execFileSync(process.execPath, ['-e',
    "require('./common/protocol_stack');" +
    "process.stdout.write(require('./admin-ui/admin').stylesheet());" +
    'process.exit(0);'],
  { cwd: require('path').join(__dirname, '..'), env: env,
    maxBuffer: 64 * 1024 * 1024 }).toString();
  const marked = ['rtab-role', 'rtab-owners'].filter(function (id) {
    return css.indexOf(':has(#' + id + ':target,#' + id + ' :target)' +
                       '>.tabbar a[href="#' + id + '"]') >= 0;
  });
  t.check(marked.length === 2,
          'E1. the stylesheet marks both tabs of a role\'s page when read',
          JSON.stringify(marked));
  log.debug('Leaving theStylesheet().');
}

module.exports = {
  name: 'role owners',
  describe: 'A role\'s owners and its page (#604): people and groups of ' +
            'the realm on its `owner` values, added and taken off one at a ' +
            'time, on an Owners tab beside everything known about the role',
  run: async function (t) {
    log.debug('Entering run().');
    await theRegister(t);
    await theActs(t);
    theHelpers(t);
    thePage(t);
    theStylesheet(t);
    log.debug('Leaving run().');
  }
};
