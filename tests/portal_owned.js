// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_owned.js
//
// ===========================================================================
// RESOURCES I OWN (#604), in process.
//
// rcbj: "in the user portal, add a new section called 'Resources I own' in
// the tree view. Add roles, groups, service accounts, and applications. The
// resources listed on each one of these is driven by the owner fields we've
// just defined on these objects." `portal/portal_owned.ts` answers four
// `/account-api` operations and `portal/web_owned.ts` draws them. Held here:
//
//   A. A RESOURCE IS A PERSON'S when an owner value names them, or a group
//      they are in, for each of the four kinds; each row says which; what
//      names somebody else is not listed.
//   B. THE PAGES: four in the column under one section, a table with how
//      each is theirs, and a sentence for none.
//   C. THE OPERATIONS: four GETs under /account-api/owned, each mirroring
//      its portal page, for the person alone.
// ===========================================================================

delete process.env.CONFIG_FILE;

require('../common/i18n');
const realms = require('../common/realms');
const credentials = require('../common/credentials');
const ldap = require('../ldap/ldap_server');
const roles = require('../common/roles');
const applications = require('../common/applications');
const serviceAccounts = require('../common/service_accounts');
const owned = require('../portal/portal_owned');
const OwnedPages = require('../portal/web_owned');
const PortalKit = require('../portal/web_portal_kit');
const kit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({ name: 'portal_owned',
  level: process.env.LOG_LEVEL || 'info' });

const PASSWORD = 'P0rtal-Own3d-Pa55word!x';

async function withRealm(t, stem, fn) {
  log.debug('Entering withRealm(). ' + stem);
  const id = stem + '-' + require('crypto').randomBytes(3).toString('hex');
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

async function theOwnership(t) {
  log.debug('Entering theOwnership().');
  await withRealm(t, 'owned', function () {
    person('po-ann');
    person('po-bo');
    person('po-svc');
    person('po-svc2');
    const team = ldap.createGroup('po-team', { origin: 'test',
                                              members: ['po-ann'] });
    const other = ldap.createGroup('po-other', { origin: 'test' });
    ldap.createGroup('po-bos', { origin: 'test' });
    ldap.addGroupOwner('po-other', 'po-team', {});
    ldap.addGroupOwner('po-bos', 'po-bo', {});
    roles.write('po-staff', { description: 'Staff' });
    roles.write('po-ops', {});
    roles.addOwner('po-staff', 'po-ann');
    roles.addOwner('po-ops', 'po-bo');
    applications.createApplication({ identifier: 'po-app',
                                     kind: 'oauth2-client' });
    applications.addOwner('po-app', 'po-team');
    const sa = serviceAccounts.set('po-svc', { serviceAccount: true,
                                              owners: ['po-ann'] });
    serviceAccounts.set('po-svc2', { serviceAccount: true,
                                     owners: ['po-bo'] });
    const module = new owned.PortalOwned(owned.PortalOwned.defaultDeps());
    const caller = { username: 'po-ann' };
    const views = {};
    owned.KINDS.forEach(function (kind) {
      views[kind] = module.view(kind, caller, 1);
    });
    const names = function (kind) {
      return views[kind].rows.map(function (row) {
        return row.name;
      });
    };
    t.check(team.ok && other.ok && sa.ok !== false &&
            names('roles').join() === 'po-staff' &&
            views.roles.rows[0].via.you === true,
            'A1. a role naming the person is theirs, and says so; one ' +
            'naming somebody else is not', JSON.stringify(views.roles));
    t.check(names('groups').join() === 'po-other' &&
            views.groups.rows[0].via.groups.join() === 'po-team' &&
            views.groups.rows[0].via.you === false,
            'A2. a group owned by a group the person is in is theirs ' +
            'through it', JSON.stringify(views.groups));
    t.check(names('service-accounts').join() === 'po-svc',
            'A3. a service account naming the person is theirs',
            JSON.stringify(views['service-accounts']));
    t.check(names('applications').join() === 'po-app' &&
            views.applications.rows[0].via.groups.join() === 'po-team',
            'A4. an application owned through a group is theirs',
            JSON.stringify(views.applications));
    // THE PERSON'S GROUPS ARE NOT LISTED (rcbj, 2026-10-13): each row's
    // `via` already names the group that makes it theirs.
    t.check(views.roles.groups === undefined &&
            views.roles.paging.total === 1,
            'A5. the view counts the rows and does not list the person\'s ' +
            'groups', JSON.stringify(views.roles));
    const html = OwnedPages.render(views.groups,
      { t: kit.context().t, query: {} });
    const none = OwnedPages.render({ kind: 'roles', rows: [],
                                     paging: { page: 1, pages: 1 } },
                                   { t: kit.context().t, query: {} });
    t.check(html.indexOf('po-other') >= 0 && html.indexOf('po-team') >= 0 &&
            html.indexOf('<table>') >= 0 && none.indexOf('<table>') < 0,
            'B1. a page draws a table of what is owned and how; none says so',
            html.slice(0, 300));
    t.check(html.indexOf('class="pagenav"') >= 0 &&
            none.indexOf('class="pagenav"') >= 0,
            'B2. every page draws its pager, one page or many (rcbj, ' +
            '2026-10-13)', none);
  });
  log.debug('Leaving theOwnership().');
}

function theColumnAndOperations(t) {
  log.debug('Entering theColumnAndOperations().');
  const section = PortalKit.NAV.filter(function (one) {
    return one.key === 'owned';
  })[0];
  t.check(section && section.items.map(function (one) {
    return one.path;
  }).join() === ['roles', 'groups', 'service-accounts', 'applications']
    .map(function (k) {
      return '/portal/owned/' + k;
    }).join() && OwnedPages.PAGES.length === 4,
  'B2. Resources I own is one section of the column, four pages under it');
  const ops = new owned.PortalOwned(owned.PortalOwned.defaultDeps())
    .accountOperations({ BASE: '/account-api', PORTAL: '/portal',
                         json: function () {
                           return null;
                         } });
  t.check(ops.length === 4 && ops.every(function (op) {
    return op.method === 'GET' && op.access === 'person' &&
      op.mirrors === 'GET ' + op.path.replace('/account-api', '/portal');
  }), 'C1. four GETs, each mirroring its page, for the person alone',
  JSON.stringify(ops.map(function (op) {
    return op.path;
  })));
  log.debug('Leaving theColumnAndOperations().');
}

module.exports = {
  name: 'portal owned',
  describe: 'Resources I own (#604): the roles, groups, service accounts ' +
            'and applications whose owners name the person or a group ' +
            'they are in, on four portal pages',
  run: async function (t) {
    log.debug('Entering run().');
    await theOwnership(t);
    theColumnAndOperations(t);
    log.debug('Leaving run().');
  }
};
