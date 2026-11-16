// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/user_overview_paging.js
//
// ---------------------------------------------------------------------------
// A PERSON'S PAGE, THREE ASKS OF rcbj's ON 2026-11-16 (#1844).
//
//   1. HOW THEY AUTHENTICATED, on the Overview tab, is paged ten a page,
//      most recent first: the answer's `authenticationHistory` with
//      `authenticationHistoryPaging` (`authenticationHistoryPage`), while
//      `user.events` stays the whole list for a caller of 1.x.
//   2. The Overview table draws that page and a pager that keeps the
//      person and moves `authenticationHistoryPage`.
//   3. THE AUTHENTICATION ATTEMPTS tab is ten a page by default, and a
//      `per` still changes it.
//   4. CREDENTIALS → SELF-ISSUED IDs is framed (`secframe`), as each
//      profile is on Key pairs.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const stats = require('../common/admin_stats');
const adminViews = require('../admin-core/admin_views');
const dir = require('../ldap/ldap_server');
require('../common/i18n');
// Requiring i18n installs the English translator the console renderer uses
// when a test draws a page (#539).

const log = require('bunyan').createLogger({
  name: 'user_overview_paging',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'uovpage' + process.pid;
const USER = TAG + '-user';
const EVENTS = 12;

/**
 * A request for one users read.
 *
 * @param query - the query
 * @returns the request
 */
function requestWith(query) {
  log.debug("Entering requestWith().");
  log.debug("Leaving requestWith().");
  return { query: query || {}, headers: { host: 'localhost:8081' },
           protocol: 'https', get: function () { return ''; } };
}

/**
 * The `?user=` answer.
 *
 * @param query - further query parameters
 * @returns the JSON
 */
function readOf(query) {
  log.debug("Entering readOf().");
  log.debug("Leaving readOf().");
  return adminViews.usersJson(requestWith(Object.assign({ user: USER },
                                                        query || {})));
}

/**
 * The session ids of a list of register events, in order.
 *
 * @param events - the events
 * @returns the ids
 */
function sids(events) {
  log.debug("Entering sids().");
  log.debug("Leaving sids().");
  return (events || []).map(function (one) {
    return String(one.sessionId || '');
  });
}

/**
 * Draws the person's page from an answer.
 *
 * @param query - the page's query
 * @param json - the answer
 * @returns the HTML, or the stack of what threw
 */
function draw(query, json) {
  log.debug("Entering draw().");
  const page = require('../admin-ui/web_users');
  const kit = require('../admin-ui/web_kit');
  try {
    const html = page.detail(kit.context(Object.assign({ user: USER },
                                                       query)), json);
    log.debug("Leaving draw().");
    return html;
  } catch (e) {
    // The assertion that reads the HTML reports the stack.
    log.debug("Caught in draw(): " + ((e && e.message) || e));
    log.debug("Leaving draw(). Threw.");
    return 'THREW ' + ((e && e.stack) || String(e));
  }
}

/**
 * The part of a page between two panel ids.
 *
 * @param html - the page
 * @param from - the first panel's id
 * @param to - the next panel's id
 * @returns the slice, '' when the first is not there
 */
function panel(html, from, to) {
  log.debug("Entering panel().");
  const at = html.indexOf('id="' + from + '"');
  const end = html.indexOf('id="' + to + '"', at + 1);
  log.debug("Leaving panel().");
  return at < 0 ? '' : html.slice(at, end > at ? end : undefined);
}

async function run(t) {
  log.debug("Entering run().");
  // An entry, so the Credentials tab has a store to draw from.
  const created = dir.createUser(USER, { origin: 'test' });
  t.check(typeof dir.listen === 'function' && !!created && !created.error,
          '0. the directory loaded and holds the person',
          JSON.stringify(created && created.error));
  for (let i = 0; i < EVENTS; i++) {
    stats.recordAuthentication({
      presented: USER, protocol: 'OpenID Connect', method: 'password',
      client_id: TAG + '-app', application: TAG + '-app',
      sessionId: TAG + '-sid-' + (100 + i), amr: ['pwd']
    });
  }
  const newestFirst = [];
  for (let i = EVENTS - 1; i >= 0; i--) {
    newestFirst.push(TAG + '-sid-' + (100 + i));
  }

  const first = readOf({});
  const second = readOf({ authenticationHistoryPage: '2' });
  const paging = first.authenticationHistoryPaging || {};
  t.check(first.user.events.length === EVENTS &&
          JSON.stringify(sids(first.authenticationHistory)) ===
            JSON.stringify(newestFirst.slice(0, 10)) &&
          paging.perPage === 10 && paging.pages === 2 &&
          paging.total === EVENTS && paging.page === 1 &&
          paging.param === 'authenticationHistoryPage' &&
          JSON.stringify(sids(second.authenticationHistory)) ===
            JSON.stringify(newestFirst.slice(10)) &&
          second.authenticationHistoryPaging.page === 2 &&
          second.user.events.length === EVENTS,
          '1. How they authenticated is ten a page, newest first, and ' +
          'user.events stays whole',
          JSON.stringify({ paging: paging,
                           shown: sids(first.authenticationHistory) }));

  const html = draw({}, first);
  const overview = panel(html, 'utab-overview', 'utab-authentications');
  const html2 = draw({ authenticationHistoryPage: '2' }, second);
  const overview2 = panel(html2, 'utab-overview', 'utab-authentications');
  t.check(overview.indexOf(newestFirst[0]) >= 0 &&
          overview.indexOf(newestFirst[9]) >= 0 &&
          overview.indexOf(newestFirst[10]) < 0 &&
          overview.indexOf('authenticationHistoryPage=2') >= 0 &&
          overview.indexOf('user=' + encodeURIComponent(USER)) >= 0 &&
          overview2.indexOf(newestFirst[10]) >= 0 &&
          overview2.indexOf(newestFirst[0]) < 0 &&
          overview2.indexOf('authenticationHistoryPage=1') >= 0,
          '2. the Overview table draws the page and a pager that keeps ' +
          'the person',
          JSON.stringify([overview.indexOf(newestFirst[0]),
                          overview.indexOf(newestFirst[9]),
                          overview.indexOf(newestFirst[10]),
                          overview.indexOf('authenticationHistoryPage=2'),
                          overview.indexOf('user=' +
                                           encodeURIComponent(USER)),
                          overview2.indexOf(newestFirst[10]),
                          overview2.indexOf(newestFirst[0]),
                          overview2.indexOf('authenticationHistoryPage=1')]));

  const attempts = first.authenticationEventsPaging || {};
  const widened = readOf({ per: '25' }).authenticationEventsPaging || {};
  t.check(attempts.perPage === 10 &&
          attempts.param === 'authenticationsPage' &&
          first.authenticationEvents.length ===
            Math.min(10, first.authenticationEventsMatched) &&
          widened.perPage === 25,
          '3. Authentication attempts is ten a page by default, and per ' +
          'still changes it',
          JSON.stringify({ attempts: attempts, widened: widened }));

  const selfIssued = panel(html, 'ucred-self-issued', 'ucred-');
  const framedAt = selfIssued.indexOf('<section class="secframe"><h3>');
  t.check(html.indexOf('THREW') !== 0 && framedAt >= 0 &&
          selfIssued.indexOf('Self-issued', framedAt) > framedAt &&
          selfIssued.indexOf('</section>', framedAt) > framedAt,
          '4. Self-issued IDs is framed as a Key pairs profile is',
          selfIssued.slice(0, 400) || html.slice(0, 400));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'user overview paging',
  describe: 'a person\'s How they authenticated and Authentication ' +
            'attempts are ten a page, and Self-issued IDs is framed (#1844)',
  run: run
};
