// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/application_authentications.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION'S AUTHENTICATION ATTEMPTS (#954).
//
// Directory → Applications → one application gains a tab. The rows are the
// audit log's, not a second store: `authentication` and
// `authentication.refused` are the standard event, and `session.refuse` and
// `session.refused` are included when they name the application.
// `session.reauthenticate` is the acceptance written again and is not.
//
// What is held:
//
//   1. THE ACCEPTANCE'S DETAIL carries `application` beside `client_id`,
//      inside the twelve-key cap. The name is not given to
//      `applications.recordAuthentication()`, so it is not counted twice
//      and it does not create an entry of its own.
//   2. AN ACCEPTANCE WITH NO client_id whose `application` is the entry's
//      client id is on the tab and does not move the count. Another
//      application's event is not on this one.
//   3. A REFUSAL is outcome refused, carries its error code and a reason
//      token, carries no password, creates no user and moves no count.
//   4. THE MATCH is trimmed and exact. A `session.refuse` that names the
//      client id is listed. A `session.reauthenticate` that names the
//      identifier is not. A different case is not. A summary that merely
//      contains the name is not.
//   5. THE ANSWER. `authenticationEvents` is the list. `authentications`
//      stays the count. The list reply and a missing application have no
//      list. `authenticationsPage` pages it.
//   6. THE TAB, drawn with the audit log's columns and one audit row.
//      The console was not driven in a browser; this is the render.
//      The acceptance's method is on the row (`method=`).
//   7. A KERBEROS SPN recorded only as `application` is on the
//      application whose `krb5ServicePrincipalName` is that SPN, with
//      the method, without `detail.client_id`, and without a count.
//   8. THE DRILL-DOWN WAITS. `getApplications` calls `audit.fresh()`
//      when `application` is set, the wait the audit page makes, so a
//      row recorded on another worker is on the tab.
// ---------------------------------------------------------------------------

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');

const applications = require('../common/applications');
const audit = require('../common/audit');
const stats = require('../common/admin_stats');
const adminActions = require('../admin-core/admin_actions');
const adminViews = require('../admin-core/admin_views');
const dir = require('../ldap/ldap_server');
// A renderer given no translator draws node's default, which common/i18n.ts
// installs (#539) — English.
require('../common/i18n');

const log = require('bunyan').createLogger({
  name: 'application_authentications',
  level: process.env.LOG_LEVEL || 'info' });

const TAG = 'appauth' + process.pid;
const APP = TAG + '-app';
const CLIENT = TAG + '-client';
const OTHER = TAG + '-other';
const EMPTY = TAG + '-empty';
const USER = TAG + '-user';
const USER2 = TAG + '-user2';
const GUESSED = TAG + '-guessed';
const PASSWORD = 's3cret-' + TAG;
const SID_A = TAG + '-sid-a';
const SID_B = TAG + '-sid-b';
const SID_O = TAG + '-sid-o';
const SID_R = TAG + '-sid-r';
const SID_REFUSE = TAG + '-sid-refuse';
const SID_RE = TAG + '-sid-re';
const SID_CASE = TAG + '-sid-case';
const SID_TRIM = TAG + '-sid-trim';
const SID_DECOY = TAG + '-sid-decoy';
const KRB = TAG + '-krb';
const SPN = 'HTTP/' + TAG + '.example.com@' + TAG.toUpperCase() + '.EXAMPLE';
const SID_KRB = TAG + '-sid-krb';
const KRB_METHOD = 'TGS-REQ with a TGT (PA-TGS-REQ)';

/**
 * A request for one applications read.
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
 * The `?application=` answer.
 *
 * @param identifier - the application
 * @param query - further query parameters
 * @returns the JSON
 */
function readOf(identifier, query) {
  log.debug("Entering readOf().");
  const asked = Object.assign({ application: identifier }, query || {});
  log.debug("Leaving readOf().");
  return adminViews.applicationsJson(requestWith(asked));
}

/**
 * The application's authentication count, or null when it has no entry.
 *
 * @param identifier - the application
 * @returns the count, or null
 */
function countOf(identifier) {
  log.debug("Entering countOf().");
  const row = applications.get(identifier);
  log.debug("Leaving countOf().");
  return row ? row.authentications : null;
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

function run(t) {
  log.debug("Entering run().");
  // The directory has to be loaded for a create to have an entry. Requiring
  // it is the load. Nothing here binds a listener.
  t.check(typeof dir.listen === 'function',
          '1. the directory module loaded');

  const created = adminActions.applicationsAction({
    action: 'create', identifier: APP, 'field.oauthClientId': CLIENT
  }, ['oauth2']);
  t.check(created && created.ok === true && countOf(APP) === 0 &&
          !applications.get(CLIENT),
          '1a. the application is created with a client id that is not ' +
          'its identifier, and the count is zero',
          JSON.stringify(created && created.errors));
  const other = adminActions.applicationsAction({
    action: 'create', identifier: OTHER, name: 'Other ' + TAG
  }, ['oauth2']);
  const empty = adminActions.applicationsAction({
    action: 'create', identifier: EMPTY, name: 'Empty ' + TAG
  }, []);
  t.check(other && other.ok === true && empty && empty.ok === true,
          '1b. the other application and an empty one are created',
          JSON.stringify({ other: other && other.errors,
                           empty: empty && empty.errors }));

  t.check(stats.recordRefusedAuthentication({ presented: '' }) === null &&
          audit.authenticationEventsFor([]).length === 0 &&
          audit.authenticationEventsFor(['', '   ']).length === 0,
          '2. a refusal with no identity writes nothing, and no names ' +
          'match nothing');

  const before = countOf(APP);
  stats.recordAuthentication({
    presented: USER, protocol: 'OpenID Connect', method: 'password',
    client_id: APP, application: CLIENT, sessionId: SID_A,
    amr: ['pwd'], acr: '1', note: 'grant'
  });
  const accepted = listedSid(SID_A);
  const acceptedKeys = Object.keys((accepted && accepted.detail) || {});
  t.check(!!accepted && accepted.action === 'authentication' &&
          accepted.outcome === 'success' && accepted.channel === 'internal' &&
          accepted.detail.client_id === APP &&
          accepted.detail.application === CLIENT &&
          accepted.detail.note === 'grant' &&
          accepted.detail.authenticationsSoFar === 1 &&
          acceptedKeys.indexOf('(more)') < 0 && acceptedKeys.length <= 12 &&
          countOf(APP) === before + 1 && !applications.get(CLIENT),
          '3. the acceptance names the application beside the client id, ' +
          'stays within twelve detail keys, counts once, and does not ' +
          'create an entry for the client id',
          JSON.stringify({ keys: acceptedKeys, count: countOf(APP),
                           outcome: accepted && accepted.outcome }));

  stats.recordAuthentication({
    presented: USER2, protocol: 'OpenID Connect', method: 'password',
    client_id: '', application: CLIENT, sessionId: SID_B, note: 'screen'
  });
  t.check(countOf(APP) === before + 1 && !applications.get(CLIENT) &&
          !!listedSid(SID_B) &&
          listedSid(SID_B).detail.application === CLIENT &&
          !listedSid(SID_B).detail.client_id,
          '4. an acceptance with no client id and the client id in ' +
          'application is recorded and does not count',
          JSON.stringify(listedSid(SID_B) && listedSid(SID_B).detail));

  stats.recordAuthentication({
    presented: USER, protocol: 'OpenID Connect', method: 'password',
    client_id: OTHER, application: OTHER, sessionId: SID_O
  });
  t.check(!!stats.userRow(USER) && !stats.userRow(GUESSED),
          '5. an accepted name is a user, and the name about to be ' +
          'refused is not');

  const refused = stats.recordRefusedAuthentication({
    presented: GUESSED, protocol: 'OpenID Connect', method: 'password',
    application: CLIENT, errorCode: 'STS-AUTHN-0054',
    note: 'wrong-password', sessionId: SID_R, channel: 'http'
  });
  const refusedText = JSON.stringify(refused || {});
  t.check(!!refused && refused.action === 'authentication.refused' &&
          refused.outcome === 'refused' &&
          refused.errorCode === 'STS-AUTHN-0054' &&
          refused.channel === 'http' &&
          refused.detail.application === CLIENT &&
          refused.detail.note === 'wrong-password' &&
          refused.detail.authenticationsSoFar === undefined &&
          Object.keys(refused.detail).indexOf('(more)') < 0 &&
          refusedText.indexOf(PASSWORD) < 0 &&
          !stats.userRow(GUESSED) && countOf(APP) === before + 1,
          '6. a refusal is refused, names its code and a reason token, ' +
          'holds no password, creates no user and does not count',
          refusedText);

  audit.audit({
    action: 'session.refuse', actor: USER, summary: 'session refused',
    detail: { application: CLIENT, sessionId: SID_REFUSE }
  });
  audit.audit({
    action: 'session.reauthenticate', actor: USER, summary: 'again ' + APP,
    detail: { client_id: APP, application: APP, sessionId: SID_RE }
  });
  audit.audit({
    action: 'authentication', actor: USER,
    summary: 'different case',
    detail: { application: APP.toUpperCase(), sessionId: SID_CASE }
  });
  audit.audit({
    action: 'authentication', actor: USER, summary: 'padded',
    detail: { application: '  ' + APP + '  ', sessionId: SID_TRIM }
  });
  audit.audit({
    action: 'authentication', actor: USER,
    summary: 'signed in to ' + APP,
    detail: { note: APP, client_id: TAG + '-nope', sessionId: SID_DECOY }
  });

  const onApp = audit.authenticationEventsFor([APP]);
  const onClient = audit.authenticationEventsFor([CLIENT]);
  t.check(sessionIds(onApp).indexOf(SID_A) >= 0 &&
          sessionIds(onApp).indexOf(SID_TRIM) >= 0 &&
          sessionIds(onApp).indexOf(SID_B) < 0 &&
          sessionIds(onClient).indexOf(SID_B) >= 0 &&
          sessionIds(onClient).indexOf(SID_R) >= 0 &&
          sessionIds(onClient).indexOf(SID_REFUSE) >= 0 &&
          sessionIds(onApp).indexOf(SID_RE) < 0 &&
          sessionIds(onApp).indexOf(SID_CASE) < 0 &&
          sessionIds(onApp).indexOf(SID_O) < 0 &&
          sessionIds(onApp).indexOf(SID_DECOY) < 0 &&
          !!listedSid(SID_RE) && !!listedSid(SID_CASE) &&
          !!listedSid(SID_DECOY),
          '7. the match is the identifier or the client id, trimmed and ' +
          'exact: a reauthentication, another case, another application ' +
          'and a summary that only contains the name are recorded and ' +
          'not selected',
          JSON.stringify({ app: sessionIds(onApp),
                           client: sessionIds(onClient) }));

  const full = readOf(APP);
  const expected = [SID_TRIM, SID_REFUSE, SID_R, SID_B, SID_A];
  t.check(full.found === true &&
          typeof full.authentications === 'number' &&
          full.authentications === before + 1 &&
          Array.isArray(full.authenticationEvents) &&
          JSON.stringify(sessionIds(full.authenticationEvents)) ===
            JSON.stringify(expected) &&
          full.authenticationEventsMatched === expected.length &&
          full.authenticationEventsPaging.param === 'authenticationsPage' &&
          full.authenticationEventsKnownActors[USER] === true &&
          !full.authenticationEventsKnownActors[GUESSED] &&
          typeof full.authenticationEventsLog.maxEvents === 'number' &&
          typeof full.authenticationEventsLog.dropped === 'number' &&
          typeof full.authenticationEventsLog.held === 'number' &&
          typeof full.authenticationEventsLog.recorded === 'number' &&
          JSON.stringify(full).indexOf(PASSWORD) < 0,
          '8. the drill-down lists those five, newest first, keeps the ' +
          'count a number, and says who has a user page',
          JSON.stringify({ count: full.authentications,
                           ids: sessionIds(full.authenticationEvents),
                           matched: full.authenticationEventsMatched,
                           known: full.authenticationEventsKnownActors }));

  const page2 = readOf(APP, { per: '1', authenticationsPage: '2' });
  t.check(page2.authenticationEvents.length === 1 &&
          page2.authenticationEvents[0].detail.sessionId === SID_REFUSE &&
          page2.authenticationEventsMatched === expected.length &&
          page2.authenticationEventsPaging.page === 2 &&
          page2.authenticationEventsPaging.pages === expected.length &&
          page2.authenticationEventsPaging.param === 'authenticationsPage',
          '9. authenticationsPage moves the attempt list and not its count',
          JSON.stringify(page2.authenticationEventsPaging));

  const listed = adminViews.applicationsJson(requestWith({ q: TAG }));
  const mine = (listed.applications || []).filter(function (row) {
    return row.identifier === APP;
  })[0];
  const missing = adminViews.applicationsJson(requestWith({
    application: TAG + '-missing' }));
  const otherJson = readOf(OTHER);
  t.check(listed.authenticationEvents === undefined &&
          !!mine && mine.authenticationEvents === undefined &&
          typeof mine.authentications === 'number' &&
          missing.found === false &&
          missing.authenticationEvents === undefined &&
          sessionIds(otherJson.authenticationEvents).indexOf(SID_O) >= 0 &&
          sessionIds(otherJson.authenticationEvents).indexOf(SID_A) < 0 &&
          readOf(EMPTY).authenticationEvents.length === 0,
          '10. the list and a missing application carry no attempt list; ' +
          'the other application has its own event and not this one',
          JSON.stringify({ list: listed.authenticationEvents,
                           missing: missing }));

  const page = require('../admin-ui/web_applications');
  const kit = require('../admin-ui/web_kit');
  const ctx = kit.context({ application: APP });
  const html = page.detail(ctx, full);
  const overview = html.indexOf('id="tab-overview"');
  const attempts = html.indexOf('id="tab-authentications"');
  const config = html.indexOf('id="tab-config"');
  const headAt = html.indexOf('<th class="num">#</th>');
  const header = html.slice(headAt, headAt + 800);
  const dropped = full.authenticationEventsLog.dropped === 0
    ? 'None have been dropped.'
    : 'older events have been dropped.';
  t.check(overview >= 0 && attempts > overview && config > attempts &&
          html.indexOf('Authentication attempts') >= 0 &&
          html.indexOf('href="/admin/audit"') >= 0 &&
          html.indexOf(dropped) >= 0 &&
          header.indexOf('When') >= 0 && header.indexOf('Category') >= 0 &&
          header.indexOf('Action') >= 0 && header.indexOf('Outcome') >= 0 &&
          header.indexOf('Actor') >= 0 && header.indexOf('From') >= 0 &&
          header.indexOf('Target') >= 0 &&
          header.indexOf('What happened') >= 0 &&
          header.indexOf('Detail') >= 0 &&
          html.indexOf('<code>authentication</code>') >= 0 &&
          html.indexOf('<code>authentication.refused</code>') >= 0 &&
          html.indexOf('<code>session.refuse</code>') >= 0 &&
          html.indexOf('client_id=' + APP) >= 0 &&
          html.indexOf('application=' + CLIENT) >= 0 &&
          html.indexOf('method=password') >= 0 &&
          html.indexOf('href="/admin/audit?code=STS-AUTHN-0054"') >= 0 &&
          html.indexOf(PASSWORD) < 0 &&
          html.indexOf('No authentication attempt naming this ' +
                       'application') < 0,
          '11. the tab is drawn on every application, with the audit ' +
          'log\'s columns and the standard fields, and the password is ' +
          'not on it',
          JSON.stringify({ overview: overview, attempts: attempts,
                           config: config, headAt: headAt }));

  const pagedHtml = page.detail(kit.context({
    application: APP, per: '1', authenticationsPage: '2'
  }), page2);
  t.check(pagedHtml.indexOf(SID_REFUSE) >= 0 &&
          pagedHtml.indexOf(SID_A) < 0 &&
          pagedHtml.indexOf('authenticationsPage=1') >= 0 &&
          pagedHtml.indexOf('application=' + encodeURIComponent(APP)) >= 0,
          '12. the pager keeps the application and moves ' +
          'authenticationsPage',
          pagedHtml.slice(pagedHtml.indexOf('tab-authentications'),
                          pagedHtml.indexOf('tab-authentications') + 1500));

  const emptyHtml = page.detail(kit.context({ application: EMPTY }),
                                 readOf(EMPTY));
  t.check(emptyHtml.indexOf('id="tab-authentications"') >= 0 &&
          emptyHtml.indexOf('No authentication attempt naming this ' +
                             'application is in the audit log.') >= 0,
          '13. an application with no attempt still has the tab, and ' +
          'the table says so');

  const krbBefore = countOf(KRB);
  const krb = adminActions.applicationsAction({
    action: 'create', identifier: KRB,
    'field.krb5ServicePrincipalName': SPN
  }, ['krb5']);
  stats.recordAuthentication({
    presented: USER, protocol: 'Kerberos v5', method: KRB_METHOD,
    application: SPN, sessionId: SID_KRB,
    note: 'a service ticket was issued'
  });
  const krbRow = listedSid(SID_KRB);
  const krbJson = readOf(KRB);
  const krbHtml = page.detail(kit.context({ application: KRB }), krbJson);
  t.check(krb && krb.ok === true && krbBefore === null &&
          countOf(KRB) === 0 && !!krbRow &&
          krbRow.detail.application === SPN &&
          krbRow.detail.method === KRB_METHOD &&
          !krbRow.detail.client_id &&
          sessionIds(krbJson.authenticationEvents).indexOf(SID_KRB) >= 0 &&
          krbJson.authentications === 0 &&
          krbHtml.indexOf('method=' + KRB_METHOD) >= 0 &&
          krbHtml.indexOf('application=' + SPN) >= 0,
          '14. a Kerberos SPN recorded only as application is on that ' +
          'application, with the method, and is not counted',
          JSON.stringify({ created: krb && krb.errors,
                           detail: krbRow && krbRow.detail,
                           ids: sessionIds(krbJson.authenticationEvents ||
                                           []),
                           count: countOf(KRB) }));

  const apiSrc = fs.readFileSync(path.join(__dirname, '..', 'mgmt-api',
                                            'admin_api.ts'), 'utf8');
  const marker = "operationId: 'getApplications'";
  const start = apiSrc.indexOf(marker);
  const next = apiSrc.indexOf('operationId:', start + marker.length);
  const handler = apiSrc.slice(start, next < 0 ? apiSrc.length : next);
  t.check(start >= 0 && handler.indexOf('audit.fresh()') >= 0 &&
          handler.indexOf('String(one) === \'\'') >= 0,
          '15. the application drill-down waits for audit.fresh(), and ' +
          'the list does not',
          handler.slice(handler.indexOf('handler:'),
                        handler.indexOf('handler:') + 700));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'application authentications',
  describe: 'an application\'s Authentication attempts tab lists the ' +
            'audit log\'s attempts that name it (#954)',
  run: run
};
