// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: portal_overview_count.js
// ===========================================================================
// THE PORTAL'S "TIMES YOU HAVE SIGNED IN" IS THE REGISTER'S COUNT (#672).
//
// From the portal's first day (2026-09-06) until #672 the Overview said 0
// for everybody. `admin_stats.userDetail()` answers `{ user, tokens,
// artifacts }` and the count is `user.authentications` — the row
// `/admin/users` draws, which was right all along — but the portal read
// `detail.authentications`, a member that shape never had, so
// `Number(undefined || 0)` was the figure on every account page. Nothing
// failed: the page drew a number, the number was a number, and the console
// beside it disagreed quietly.
//
// This file holds the two halves together IN PROCESS, which is the only
// place the SHAPE can be asserted: the view is built from the real register
// after real `recordAuthentication()` calls, so a future change to what
// `userDetail()` answers, or to what the overview reads, fails here on the
// day it is made rather than on the day somebody looks at the page.
// `tests/protocol/sts_portal_sessions.js` asserts the same figure over HTTP
// after a real sign-in — that it is at least one — which is the half that
// needs a running service.
//
// Nothing here binds a listener. The directory is loaded (required) so the
// user observer gives the person an entry, as it does in the service, and
// the subject on the caller is the one the register would resolve.
// ===========================================================================

delete process.env.CONFIG_FILE;

const stats = require('../common/admin_stats');
const helpers = require('../common/helpers');
const dir = require('../ldap/ldap_server');
const overview = require('../portal/account_overview');

const log = require('bunyan').createLogger({
  name: 'portal_overview_count',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'overviewcount' + process.pid;
const USER = TAG + '-user';
const NOBODY = TAG + '-nobody';

/**
 * The caller the account API would hand the overview for a person.
 *
 * @param username - the person
 * @param sessionId - the sign-on session's id
 * @returns the caller
 */
function callerFor(username, sessionId) {
  log.debug("Entering callerFor().");
  const subject = helpers.subjectForName(username);
  const caller = {
    username: username,
    sub: String(subject || ''),
    realm: '',
    clientId: 'sts-user-portal',
    scopes: ['account:manage'],
    expiresAt: null,
    sessionId: sessionId,
    session: { id: sessionId, user: { username: username, sub: subject },
               expires: 0, authenticated: true },
    signOn: null
  };
  log.debug("Leaving callerFor().");
  return caller;
}

/**
 * One recorded sign-in for the person, as the sign-in screen records one.
 *
 * @param username - the person
 * @param sessionId - the sign-on session's id
 */
function signedIn(username, sessionId) {
  log.debug("Entering signedIn().");
  stats.recordAuthentication({
    presented: username, protocol: 'OpenID Connect', method: 'password',
    sessionId: sessionId, amr: ['pwd'], acr: '1'
  });
  log.debug("Leaving signedIn().");
}

function run(t) {
  log.debug("Entering run().");
  t.check(typeof dir.listen === 'function',
          '1. the directory module loaded');
  const page = new overview.AccountOverview(
    overview.AccountOverview.defaultDeps());

  // Three sign-ins, then the view: the figure is the register's, and the
  // register's figure is where `userDetail()` keeps it.
  signedIn(USER, TAG + '-sid-1');
  signedIn(USER, TAG + '-sid-2');
  signedIn(USER, TAG + '-sid-3');
  const detail = stats.userDetail(USER);
  t.check(!!detail && !!detail.user && detail.user.authentications === 3 &&
          detail.authentications === undefined,
          '2. userDetail() keeps the count on its `user` row and nowhere ' +
          'else — the shape the overview must read',
          JSON.stringify({ keys: Object.keys(detail || {}),
                           user: detail && detail.user &&
                                 detail.user.authentications }));

  const view = page.overview(callerFor(USER, TAG + '-sid-3'));
  t.check(view && view.username === USER && view.timesSignedIn === 3,
          '3. the Overview says three times signed in, which is what the ' +
          'register counted (#672: it said 0 for everybody)',
          JSON.stringify({ timesSignedIn: view && view.timesSignedIn,
                           username: view && view.username }));

  // The figure MOVES with the register: one more sign-in is one more on
  // the page, so the page is not reading a snapshot taken at build.
  signedIn(USER, TAG + '-sid-4');
  const again = page.overview(callerFor(USER, TAG + '-sid-4'));
  t.check(again && again.timesSignedIn === 4,
          '4. a fourth sign-in makes it four',
          JSON.stringify({ timesSignedIn: again && again.timesSignedIn }));

  // Somebody the register never saw: `null`, so the page draws no row
  // rather than a zero — the figure the page cannot stand behind is left
  // off, as it always was.
  const unseen = page.overview(callerFor(NOBODY, TAG + '-sid-none'));
  t.check(unseen && unseen.timesSignedIn === null,
          '5. a person with no register row gets null, not 0',
          JSON.stringify({ timesSignedIn: unseen && unseen.timesSignedIn }));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal overview sign-in count',
  describe: 'the portal Overview\'s "Times you have signed in" is the ' +
            'register\'s count for the person, read off the row ' +
            'userDetail() answers (#672)',
  run: run
};
