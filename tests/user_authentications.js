// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/user_authentications.js
//
// ---------------------------------------------------------------------------
// A PERSON'S AUTHENTICATION ATTEMPTS (#955).
//
// Directory → Users → one user gains a tab. The rows are the audit log's,
// for that person only, across every application and protocol.
// `authentication`, `authentication.refused`, `session.refuse` and
// `session.refused` count. `session.reauthenticate` does not.
//
// Recent sign-ins on the portal stays the risk-assessment list. It gains
// an Application column, and its window is
// `audit.authenticationHistoryDays` (thirty by default).
//
// What is held:
//
//   1. THE MATCH is the actor, the presented form, `detail.sub` or
//      `detail.presented`, trimmed and exact. The summary and the target
//      are not read. Another case is not this person. A subject the
//      directory wrote, because the caller passed none, is on every
//      acceptance and refusal for that person, so it matches all of them.
//      No names match nothing.
//   2. ONE PERSON, TWO APPLICATIONS. An acceptance on each application,
//      a refusal, and a `session.refuse` are on the tab. Another person's
//      acceptance is not. A reauthentication is not.
//   3. THE ANSWER. `authenticationEvents` is the list.
//      `user.authentications` stays the count. The list reply and an
//      unknown user have no list. `authenticationsPage` pages it.
//   4. THE TAB, drawn with the audit log's columns, after Overview and
//      before Sessions & tokens. A directory-only person still has it.
//   5. THE DRILL-DOWN WAITS. `getUsers` calls `audit.fresh()` when
//      `user` is set, and the list does not.
//   6. THE PORTAL column is the assessment's `clientId`. The window the
//      engine is asked for is the setting, and thirty when no settings
//      module was handed in.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const audit = require('../common/audit');
const stats = require('../common/admin_stats');
const adminViews = require('../admin-core/admin_views');
const dir = require('../ldap/ldap_server');
const config = require('../common/config');
const i18n = require('../common/i18n');
const signIns = require('../portal/portal_sign_ins');
// Requiring i18n installs the English translator the console renderer uses
// when a test draws a page (#539).

const log = require('bunyan').createLogger({
  name: 'user_authentications',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'userauth' + process.pid;
const USER = TAG + '-user';
const USER2 = TAG + '-user2';
const GUESSED = TAG + '-guessed';
const EMPTY = TAG + '-empty';
const APP = TAG + '-app';
const OTHER = TAG + '-other';
const PASSWORD = 's3cret-' + TAG;
const SUBJECT = 'urn:uuid:' + TAG + '-alien';
const SID_A = TAG + '-sid-a';
const SID_B = TAG + '-sid-b';
const SID_O = TAG + '-sid-o';
const SID_R = TAG + '-sid-r';
const SID_REFUSE = TAG + '-sid-refuse';
const SID_RE = TAG + '-sid-re';
const SID_CASE = TAG + '-sid-case';
const SID_TRIM = TAG + '-sid-trim';
const SID_DECOY = TAG + '-sid-decoy';
const SID_SUB = TAG + '-sid-sub';
const SID_PRES = TAG + '-sid-pres';
const SID_FORM = TAG + '-sid-form';

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
 * @param name - the person
 * @param query - further query parameters
 * @returns the JSON
 */
function readOf(name, query) {
  log.debug("Entering readOf().");
  const asked = Object.assign({ user: name }, query || {});
  log.debug("Leaving readOf().");
  return adminViews.usersJson(requestWith(asked));
}

/**
 * The session ids on a list of audit rows, in the list's order.
 *
 * @param events - audit rows
 * @returns the session ids
 */
function sessionIds(events) {
  log.debug("Entering sessionIds().");
  const ids = (events || []).map(function (row) {
    const detail = (row && row.detail) || {};
    return String(detail.sessionId || '');
  });
  log.debug("Leaving sessionIds().");
  return ids;
}

/**
 * One audit row by the session id in its detail, from the whole log.
 *
 * @param sid - the session id
 * @returns the row, or null
 */
function listedSid(sid) {
  log.debug("Entering listedSid().");
  const found = audit.list().filter(function (row) {
    const detail = (row && row.detail) || {};
    return String(detail.sessionId || '') === sid;
  });
  log.debug("Leaving listedSid().");
  return found[0] || null;
}

/**
 * A quiet logger for a portal module built over a stub.
 *
 * @returns the logger
 */
function quietLog() {
  log.debug("Entering quietLog().");
  log.debug("Leaving quietLog().");
  return { debug: function () {}, info: function () {} };
}

async function run(t) {
  log.debug("Entering run().");
  let set = { ok: false };
  try {
  t.check(typeof dir.listen === 'function',
          '1. the directory module loaded');
  t.check(audit.authenticationEventsForPerson([]).length === 0 &&
          audit.authenticationEventsForPerson(['', '   ']).length === 0 &&
          audit.authenticationEventsForPerson(null).length === 0,
          '2. no names match nothing');

  stats.recordAuthentication({
    presented: USER, protocol: 'OpenID Connect', method: 'password',
    client_id: APP, application: APP, sessionId: SID_A, amr: ['pwd']
  });
  const accepted = listedSid(SID_A);
  const subject = String((accepted && accepted.detail &&
                          accepted.detail.sub) || '');
  t.check(!!accepted && accepted.action === 'authentication' &&
          accepted.actor === USER &&
          accepted.detail.application === APP &&
          stats.userRow(USER).authentications === 1,
          '3. the acceptance is the person, on the first application',
          JSON.stringify(accepted && accepted.detail));

  stats.recordAuthentication({
    presented: USER, protocol: 'SAML 2.0', method: 'bearer',
    application: OTHER, sessionId: SID_B
  });
  stats.recordAuthentication({
    presented: USER2, protocol: 'OpenID Connect', method: 'password',
    application: APP, sessionId: SID_O
  });
  const beforeRefusal = stats.userRow(USER).authentications;
  stats.recordRefusedAuthentication({
    presented: USER, protocol: 'OpenID Connect', method: 'password',
    application: APP, errorCode: 'STS-AUTHN-0054',
    note: 'wrong-password', sessionId: SID_R
  });
  stats.recordRefusedAuthentication({
    presented: GUESSED, protocol: 'OpenID Connect', method: 'password',
    application: APP, errorCode: 'STS-AUTHN-0054',
    note: 'wrong-password', sessionId: TAG + '-sid-guessed'
  });
  t.check(beforeRefusal === 2 &&
          stats.userRow(USER).authentications === 2 &&
          !stats.userRow(GUESSED),
          '4. a refusal does not count and does not create the guessed ' +
          'name',
          JSON.stringify({ before: beforeRefusal,
                           after: stats.userRow(USER).authentications }));

  audit.audit({
    action: 'session.refuse', actor: USER, summary: 'session refused',
    detail: { application: APP, sessionId: SID_REFUSE }
  });
  audit.audit({
    action: 'session.reauthenticate', actor: USER, summary: 'again',
    detail: { application: APP, sessionId: SID_RE }
  });
  audit.audit({
    action: 'authentication', actor: USER.toUpperCase(),
    summary: 'different case',
    detail: { application: APP, sessionId: SID_CASE }
  });
  audit.audit({
    action: 'authentication', actor: 'decoy-' + TAG,
    summary: 'signed in as ' + USER, target: USER,
    detail: { note: USER, sessionId: SID_DECOY, application: APP }
  });
  audit.audit({
    action: 'authentication', actor: 'stranger-' + TAG,
    summary: 'alien subject',
    detail: { sub: SUBJECT, sessionId: SID_SUB, application: APP }
  });
  audit.audit({
    action: 'authentication', actor: '  ' + USER + '  ',
    summary: 'padded actor',
    detail: { application: OTHER, sessionId: SID_TRIM }
  });
  audit.audit({
    action: 'authentication', actor: 'presented-other-' + TAG,
    summary: 'presented',
    detail: { presented: '  ' + USER + '  ', sessionId: SID_PRES,
              application: APP }
  });
  audit.audit({
    action: 'authentication', actor: 'form-other-' + TAG,
    actorForm: '  ' + USER + '  ', summary: 'form',
    detail: { sessionId: SID_FORM, application: OTHER }
  });

  const mine = audit.authenticationEventsForPerson([USER]);
  const mineIds = sessionIds(mine);
  const expected = [SID_FORM, SID_PRES, SID_TRIM, SID_REFUSE, SID_R,
                    SID_B, SID_A];
  t.check(JSON.stringify(mineIds.filter(function (id) {
            return expected.indexOf(id) >= 0 || id === SID_O ||
                   id === SID_RE || id === SID_CASE || id === SID_DECOY ||
                   id === SID_SUB;
          })) === JSON.stringify(expected) &&
          mineIds.indexOf(SID_O) < 0 && mineIds.indexOf(SID_RE) < 0 &&
          mineIds.indexOf(SID_CASE) < 0 && mineIds.indexOf(SID_DECOY) < 0 &&
          mineIds.indexOf(SID_SUB) < 0 &&
          !!listedSid(SID_RE) && !!listedSid(SID_CASE) &&
          !!listedSid(SID_DECOY) && !!listedSid(SID_SUB),
          '5. the match is trimmed and exact, across both applications, ' +
          'and a summary or a target that only contains the name is not',
          JSON.stringify(mineIds));
  const bySubject = subject
    ? sessionIds(audit.authenticationEventsForPerson([subject])) : [];
  const byAlien = sessionIds(audit.authenticationEventsForPerson(
    [SUBJECT]));
  const byPadded = sessionIds(audit.authenticationEventsForPerson(
    ['  ' + USER + '  ']));
  const upperIds = sessionIds(audit.authenticationEventsForPerson(
    [USER.toUpperCase()]));
  const future = Date.now() + (86400000 * 4000);
  const recent = Date.now() - 60000;
  const futureIds = sessionIds(audit.authenticationEventsForPerson(
    [USER], future));
  const recentIds = sessionIds(audit.authenticationEventsForPerson(
    [USER], recent));
  const openIds = sessionIds(audit.authenticationEventsForPerson(
    [USER], 0));
  // The directory subject is written when the caller passes no sub, so the
  // acceptance, the second application's acceptance and the refusal all
  // carry it. The row recorded under another case is that case's own actor.
  const subjectIds = [SID_R, SID_B, SID_A];
  t.check(!!subject &&
          JSON.stringify(bySubject) === JSON.stringify(subjectIds) &&
          bySubject.indexOf(SID_SUB) < 0 &&
          JSON.stringify(byAlien) === JSON.stringify([SID_SUB]) &&
          byPadded.indexOf(SID_A) >= 0 &&
          upperIds.indexOf(SID_CASE) >= 0 &&
          upperIds.indexOf(SID_A) < 0 &&
          futureIds.length === 0 &&
          recentIds.indexOf(SID_A) >= 0 &&
          openIds.indexOf(SID_A) >= 0,
          '6. a subject matches every row that stored it, another case ' +
          'does not, and a since above zero is the window',
          JSON.stringify({ subject: subject, bySubject: bySubject,
                           alien: byAlien, upper: upperIds,
                           future: futureIds.length }));

  const full = readOf(USER);
  const fullIds = sessionIds(full.authenticationEvents);
  t.check(full.known === true &&
          full.user.authentications === 2 &&
          JSON.stringify(fullIds) === JSON.stringify(expected) &&
          full.authenticationEventsMatched === expected.length &&
          full.authenticationEventsPaging.param === 'authenticationsPage' &&
          full.authenticationEventsKnownActors[USER] === true &&
          !full.authenticationEventsKnownActors[GUESSED] &&
          typeof full.authenticationEventsLog.maxEvents === 'number' &&
          typeof full.authenticationEventsLog.dropped === 'number' &&
          fullIds.filter(function (id) {
            return id === SID_A || id === SID_B;
          }).length === 2 &&
          JSON.stringify(full).indexOf(PASSWORD) < 0,
          '7. the drill-down lists this person across both applications ' +
          'and keeps the count',
          JSON.stringify({ count: full.user && full.user.authentications,
                           ids: fullIds,
                           matched: full.authenticationEventsMatched }));

  const page2 = readOf(USER, { per: '1', authenticationsPage: '2' });
  t.check(page2.authenticationEvents.length === 1 &&
          page2.authenticationEvents[0].detail.sessionId === SID_PRES &&
          page2.authenticationEventsMatched === expected.length &&
          page2.authenticationEventsPaging.page === 2 &&
          page2.authenticationEventsPaging.param === 'authenticationsPage' &&
          page2.user.authentications === 2,
          '8. authenticationsPage moves the attempt list and not the count',
          JSON.stringify(page2.authenticationEventsPaging));

  const listed = adminViews.usersJson(requestWith({ q: TAG + '-missing' }));
  const unknown = readOf(TAG + '-missing');
  const other = readOf(USER2);
  t.check(listed.authenticationEvents === undefined &&
          unknown.known === false &&
          unknown.authenticationEvents === undefined &&
          sessionIds(other.authenticationEvents).indexOf(SID_O) >= 0 &&
          sessionIds(other.authenticationEvents).indexOf(SID_A) < 0,
          '9. the list and an unknown user carry no attempt list; the ' +
          'other person has their own event',
          JSON.stringify({ list: listed.authenticationEvents,
                           unknown: unknown.known }));

  const page = require('../admin-ui/web_users');
  const kit = require('../admin-ui/web_kit');
  let html = '';
  let renderError = '';
  try {
    html = page.detail(kit.context({ user: USER }), full);
  } catch (e) {
    // The assertion below reports the stack. A throw here is the page,
    // and the rest of the file still runs.
    log.debug("Caught in run(): " + ((e && e.message) || e));
    renderError = (e && e.stack) || String(e);
  }
  const overview = html.indexOf('id="utab-overview"');
  const attempts = html.indexOf('id="utab-authentications"');
  const activity = html.indexOf('id="utab-activity"');
  const section = attempts >= 0 ? html.slice(attempts, activity) : '';
  const headAt = section.indexOf('<th class="num">#</th>');
  const header = section.slice(headAt, headAt + 800);
  const dropped = full.authenticationEventsLog.dropped === 0
    ? 'None have been dropped.'
    : 'older events have been dropped.';
  t.check(!renderError && overview >= 0 && attempts > overview &&
          activity > attempts &&
          section.indexOf('Authentication attempts') >= 0 &&
          section.indexOf('href="/admin/audit"') >= 0 &&
          section.indexOf(dropped) >= 0 &&
          header.indexOf('When') >= 0 && header.indexOf('Category') >= 0 &&
          header.indexOf('Action') >= 0 && header.indexOf('Outcome') >= 0 &&
          header.indexOf('Actor') >= 0 && header.indexOf('From') >= 0 &&
          header.indexOf('Target') >= 0 &&
          header.indexOf('What happened') >= 0 &&
          header.indexOf('Detail') >= 0 &&
          section.indexOf('<code>authentication</code>') >= 0 &&
          section.indexOf('<code>authentication.refused</code>') >= 0 &&
          section.indexOf('<code>session.refuse</code>') >= 0 &&
          section.indexOf('application=' + APP) >= 0 &&
          section.indexOf('application=' + OTHER) >= 0 &&
          section.indexOf('method=password') >= 0 &&
          section.indexOf(PASSWORD) < 0 &&
          section.indexOf('No authentication attempt by this person') < 0,
          '10. the tab is drawn after Overview, with the audit log\'s ' +
          'columns, both applications, and no password',
          renderError || JSON.stringify({ overview: overview,
            attempts: attempts, activity: activity, headAt: headAt }));

  let pagedHtml = '';
  try {
    pagedHtml = page.detail(kit.context({
      user: USER, per: '1', authenticationsPage: '2'
    }), page2);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    pagedHtml = (e && e.stack) || String(e);
  }
  const pagedAt = pagedHtml.indexOf('id="utab-authentications"');
  const pagedSection = pagedAt >= 0
    ? pagedHtml.slice(pagedAt, pagedHtml.indexOf('id="utab-activity"')) : '';
  t.check(pagedSection.indexOf(SID_PRES) >= 0 &&
          pagedSection.indexOf(SID_FORM) < 0 &&
          pagedSection.indexOf('authenticationsPage=1') >= 0 &&
          pagedSection.indexOf('user=' + encodeURIComponent(USER)) >= 0,
          '11. the pager keeps the user and moves authenticationsPage',
          pagedSection.slice(0, 500));

  const created = dir.createUser(EMPTY, { origin: 'test' });
  const emptyJson = readOf(EMPTY);
  let emptyHtml = '';
  try {
    emptyHtml = page.detail(kit.context({ user: EMPTY }), emptyJson);
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    emptyHtml = (e && e.stack) || String(e);
  }
  t.check(!!created && emptyJson.known === true &&
          emptyJson.user.authentications === 0 &&
          emptyJson.authenticationEvents.length === 0 &&
          emptyHtml.indexOf('id="utab-authentications"') >= 0 &&
          emptyHtml.indexOf('No authentication attempt by this person ' +
                             'is in the audit log.') >= 0,
          '12. a directory-only person still has the tab, and it says ' +
          'the log holds nothing',
          JSON.stringify({ known: emptyJson.known,
                           count: emptyJson.user &&
                                  emptyJson.user.authentications }));

  const apiSrc = fs.readFileSync(path.join(__dirname, '..', 'mgmt-api',
                                            'admin_api.ts'), 'utf8');
  const marker = "operationId: 'getUsers'";
  const start = apiSrc.indexOf(marker);
  const next = apiSrc.indexOf('operationId:', start + marker.length);
  const handler = apiSrc.slice(start, next < 0 ? apiSrc.length : next);
  const freshAt = handler.indexOf('audit.fresh()');
  const listAt = handler.indexOf('if (!named)');
  t.check(start >= 0 && freshAt >= 0 && listAt >= 0 && listAt < freshAt,
          '13. the user drill-down waits for audit.fresh(), and the ' +
          'list does not',
          handler.slice(handler.indexOf('handler:'),
                        handler.indexOf('handler:') + 900));

  const asked = [];
  const engine = {
    view: function (realm, opts) {
      asked.push(opts.days);
      return Promise.resolve({ assessments: { total: 2, rows: [
        { id: 'assess-1', at: 2000, subject: 'sub-' + USER,
          clientId: APP, door: 'oidc', level: 'LOW', city: 'Austin',
          country: 'US' },
        { id: 'assess-2', at: 1000, subject: 'sub-' + USER,
          door: 'saml', level: 'LOW' }
      ] } });
    }
  };
  const caller = { sub: 'sub-' + USER, username: USER,
                   session: { risk: {} } };
  const realms = function () {
    return { currentId: function () { return ''; } };
  };
  const bare = new signIns.PortalSignIns({
    log: quietLog(), realms: realms,
    riskEngine: function () { return engine; }
  });
  const withConfig = new signIns.PortalSignIns({
    log: quietLog(), realms: realms,
    riskEngine: function () { return engine; },
    config: function () { return config; }
  });
    const bareView = await bare.view(caller);
    set = config.setOverride('audit.authenticationHistoryDays', 7);
    const widened = await withConfig.view(caller);
    const pages = require('../portal/web_sign_ins');
    const portalHtml = pages.render(widened, {
      t: i18n.translator(['en']), query: {}
    });
    const appAt = portalHtml.indexOf('>' + APP + '<');
    const dashAt = portalHtml.indexOf('&mdash;');
    t.check(bare.historyDays() === 30 &&
            bareView.rows[0].application === APP &&
            bareView.rows[1].application === '' &&
            asked[0] === 30 &&
            set.ok === true &&
            withConfig.historyDays() === 7 &&
            asked[1] === 7 &&
            widened.days === 7 &&
            portalHtml.indexOf('>Application<') >= 0 &&
            appAt >= 0 && dashAt > appAt,
            '14. Recent sign-ins names the application, and the window ' +
            'is the realm setting',
            JSON.stringify({ asked: asked, set: set,
                             days: widened.days,
                             applications: widened.rows.map(function (row) {
                               return row.application;
                             }) }));
  } finally {
    // A failed assertion must not leave the override for a later file
    // in this process.
    if (set.ok === true) {
      config.clearOverride('audit.authenticationHistoryDays');
    }
    log.debug("Leaving run().");
  }
}

module.exports = {
  name: 'user authentications',
  describe: 'a person\'s Authentication attempts tab lists the audit ' +
            'log\'s attempts for that person, and Recent sign-ins names ' +
            'the application (#955)',
  run: run
};
