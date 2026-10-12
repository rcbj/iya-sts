// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/admin_lists_paging.js
//
// ---------------------------------------------------------------------------
// THE LISTS #313'S SWEEP PAGED, IN PROCESS (2026-10-12).
//
// After #313 paged the Shared Signals streams tables, the rest of the console
// was searched for lists that grow without a bound and were drawn whole. This
// file holds the ones whose view model is reachable in process:
//
//   1. /admin/roles' NARROWED APPLICATIONS on `requiringPage`, a page of them
//      with `requiringPaging`, `counts.requiring` still the whole count, and
//      `rolesPage` and `requiringPage` not moving each other.
//   2. A PAGE PAST THE END CLAMPED to the last.
//   3. A WALK OF EVERY PAGE reading every narrowed application once.
//   4. /admin/sessions' UNAUTHENTICATED SESSIONS answering
//      `unauthenticatedPaging` on `anonymousPage`, when the logout reader is
//      loaded in this process.
//   5. THE PAGING CONTROL each renderer draws for a list longer than a page:
//      /admin/attribute-sources' `sourcesPage`, /admin/secret-destinations'
//      `destinationsPage` and /admin/gnap's `serversPage`, from views built
//      here (their registers need a database, a secret store or a profile
//      store to fill for real).
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const applications = require('../common/applications');
// The directory the application entries are written to.
require('../ldap/ldap_server');
const adminViews = require('../admin-core/admin_views');
const WebKit = require('../admin-ui/web_kit');

const log = require('bunyan').createLogger({ name: 'admin_lists_paging',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'alp' + process.pid;
const APPS = 7;

function narrowed(view) {
  log.debug("Entering narrowed().");
  log.debug("Leaving narrowed().");
  return view.requiring.filter(function (row) {
    return row.application.indexOf(TAG) === 0;
  });
}

function rolesRequiring(t) {
  log.debug("Entering rolesRequiring().");
  const made = [];
  for (let i = 0; i < APPS; i++) {
    const id = TAG + '-app-' + i;
    made.push(applications.createApplication({ identifier: id,
      protocols: ['oauth2'], fields: { oauthClientId: id } }));
    made.push(applications.updateApplication(id, {
      attribute: 'appRequiredRole', mode: 'add', value: TAG + '-role' }));
  }
  t.check(made.every(function (one) {
    return one && one.ok;
  }), 'precondition: the applications were registered and narrowed',
          JSON.stringify(made.filter(function (one) {
            return !(one && one.ok);
          })).slice(0, 300));
  const whole = adminViews.rolesRegister();
  const total = whole.requiring.length;
  t.check(narrowed(whole).length === APPS,
          'precondition: the register lists the ' + APPS + ' narrowed ' +
          'applications', String(narrowed(whole).length));

  const first = adminViews.rolesView({ per: '3' });
  t.check(first.requiring.length === Math.min(3, total) &&
          first.requiringPaging.total === total &&
          first.requiringPaging.param === 'requiringPage' &&
          first.counts.requiring === total,
          '1a. the narrowed applications are one page, on requiringPage, ' +
          'and counts.requiring is the whole count',
          JSON.stringify(first.requiringPaging));
  const moved = adminViews.rolesView({ per: '3', requiringPage: '2' });
  t.check(moved.requiringPaging.page === 2 && moved.paging.page === 1,
          '1b. requiringPage moves the applications and not the roles',
          JSON.stringify({ requiring: moved.requiringPaging.page,
                           roles: moved.paging.page }));
  const rolesMoved = adminViews.rolesView({ per: '3', rolesPage: '2' });
  t.check(rolesMoved.requiringPaging.page === 1,
          '1c. rolesPage leaves the applications on page 1', '');

  const past = adminViews.rolesView({ per: '3', requiringPage: '999' });
  t.check(past.requiringPaging.page === past.requiringPaging.pages,
          '2. a page past the end is the last page',
          JSON.stringify(past.requiringPaging));

  const seen = [];
  for (let page = 1; page <= 100; page++) {
    const one = adminViews.rolesView({ per: '3',
                                       requiringPage: String(page) });
    one.requiring.forEach(function (row) {
      seen.push(row.application);
    });
    if (page >= one.requiringPaging.pages) {
      break;
    }
  }
  const distinct = seen.filter(function (id, i) {
    return seen.indexOf(id) === i;
  });
  t.check(seen.length === total && distinct.length === total,
          '3. walking every page reads every narrowed application once',
          JSON.stringify({ seen: seen.length, total: total }));

  for (let i = 0; i < APPS; i++) {
    applications.deleteApplication(TAG + '-app-' + i);
  }
  log.debug("Leaving rolesRequiring().");
}

function sessionsAnonymous(t) {
  log.debug("Entering sessionsAnonymous().");
  const view = adminViews.sessionsView({ query: { per: '2' } });
  if (!view.installed) {
    t.check(true, '4. (no logout reader in this process; the ' +
                  'unauthenticated paging is drawn by the console job)', '');
    log.debug("Leaving sessionsAnonymous(). Not installed.");
    return;
  }
  t.check(view.json.unauthenticatedPaging &&
          view.json.unauthenticatedPaging.param === 'anonymousPage' &&
          view.json.unauthenticatedSessions.length <=
            view.json.unauthenticatedPaging.perPage &&
          view.json.unauthenticatedPaging.total ===
            view.json.unauthenticatedHeld,
          '4. the unauthenticated sessions are paged on anonymousPage and ' +
          'unauthenticatedHeld counts them all',
          JSON.stringify(view.json.unauthenticatedPaging));
  log.debug("Leaving sessionsAnonymous().");
}

function controls(t) {
  log.debug("Entering controls().");
  const cases = [
    ['/admin/attribute-sources', 'sources'],
    ['/admin/secret-destinations', 'destinations'],
    ['/admin/gnap', 'servers']
  ];
  cases.forEach(function (one) {
    const rows = [];
    for (let i = 0; i < 12; i++) {
      rows.push({ id: 'row-' + i });
    }
    const page = adminViews.pagedRows({ per: '5' }, rows,
      { name: one[1], noun: one[1] });
    const paging = adminViews.pagingJson(page.paging);
    const nav = WebKit.pageNavPair(one[0], { per: '5' }, paging);
    t.check(paging.param === one[1] + 'Page' && page.shown.length === 5 &&
            nav.head.indexOf(one[1] + 'Page=2') >= 0,
            '5. ' + one[0] + ' draws a pager on ' + one[1] + 'Page', '');
  });
  log.debug("Leaving controls().");
}

function run(t) {
  log.debug("Entering run().");
  rolesRequiring(t);
  sessionsAnonymous(t);
  controls(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'admin lists paging',
  describe: 'The lists #313\'s sweep paged: the roles page\'s narrowed ' +
            'applications, the unauthenticated sessions, and the pagers ' +
            'on attribute sources, secret destinations and GNAP',
  run: run
};
