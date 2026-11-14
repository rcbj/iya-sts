// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: console_sessions_arrival.js
//
// ===========================================================================
// THE UNAUTHENTICATED TAB SAYS WHAT IT LEAVES OUT (#888).
//
// It lists Continue-without-signing-in sessions. An arrival (kind
// arrival, chosen false) is excluded by liveSessions(), and the empty
// tab used to say every held session had a credential accepted. The
// tab now says an arrival is not listed, whether or not any
// Continue-without session is, and the empty line no longer says that.
// ===========================================================================

const i18n = require('../common/i18n');
const WebKit = require('../admin-ui/web_kit');
const SessionsPage = require('../logout/web_sessions');

const log = require('bunyan').createLogger({
  name: 'console_sessions_arrival',
  level: process.env.LOG_LEVEL || 'info' });

function view(held) {
  log.debug("Entering view().");
  const row = {
    id: 'session:a', family: 'session', kind: 'Browser sign-on session',
    handle: 'a', protocol: 'OAuth 2.0 / OIDC', username: 'anonymous',
    sub: '', sessionId: 'a', startedAt: 0, expiresAt: 0, acr: '',
    amr: [], detail: '', terminable: false, why: '', deviceBound: null,
    accountSet: ''
  };
  log.debug("Leaving view().");
  return {
    installed: true, at: 1, held: 0, matched: 0,
    heldByKind: { session: 0, krb5: 0, ldap: 0 },
    filter: { q: null, protocol: null }, protocols: [], sessions: [],
    paging: { page: 1, pages: 1, perPage: 50,
              firstRow: 0, lastRow: 0 },
    unauthenticatedHeld: held, unauthenticatedKept: false,
    unauthenticatedSessions: held ? [row] : [],
    unauthenticatedPaging: { page: 1, pages: 1, perPage: 50,
                             firstRow: 0, lastRow: 0,
                             param: 'anonymousPage' },
    accountChoices: { enabled: false, counts: {} }
  };
}

function drawn(tag, json) {
  log.debug("Entering drawn().");
  const html = SessionsPage.body(WebKit.context({}, false,
    i18n.translator([tag])), json);
  log.debug("Leaving drawn().");
  return html;
}

function run(t) {
  log.debug("Entering run().");
  const empty = drawn('en', view(0));
  const start = empty.indexOf('data-tab="unauthenticated"');
  const note = empty.indexOf('An arrival session is not listed here.');
  const meta = empty.indexOf('data-metadata');
  t.check(start >= 0 && note > start && meta > note,
          '1. the empty Unauthenticated tab says an arrival is not ' +
          'listed', empty.slice(Math.max(0, start), start + 240));
  t.check(empty.indexOf('had a credential accepted') < 0 &&
          empty.indexOf('None of these.') >= 0 &&
          empty.indexOf('stays empty of them') >= 0,
          '1. the empty line does not say every held session had a ' +
          'credential accepted');
  const full = drawn('en', view(1));
  const note2 = full.indexOf('An arrival session is not listed here.');
  const tab2 = full.indexOf('data-tab="unauthenticated"');
  t.check(note2 > tab2 && full.indexOf('>anonymous<') >= 0 &&
          full.indexOf('None of these.') < 0,
          '1. the note stays when a Continue-without session is listed');
  const on = drawn('en', Object.assign(view(0),
                                        { unauthenticatedKept: true }));
  t.check(on.indexOf('is ON') >= 0 &&
          on.indexOf('An arrival session is not listed here.') >
            on.indexOf('data-tab="unauthenticated"'),
          '1. the note is on the tab when the setting is on');
  ['fr', 'es', 'zh-Hans', 'zh-Hant', 'fil', 'sv'].forEach(function (tag) {
    const html = drawn(tag, view(0));
    const phrase = i18n.translator([tag]).html(
      'consoleSessions.arrivalExcluded');
    const at = html.indexOf('data-tab="unauthenticated"');
    const meta = html.indexOf('data-metadata');
    // A long note folds. A bolded headline becomes the summary and the
    // rest the body, so the catalog string is not one span on the page.
    const headline = /^<strong>([\s\S]*?)<\/strong>/.exec(phrase);
    const title = headline ? headline[1] : '';
    const rest = headline
      ? phrase.slice(headline[0].length).replace(/^\s+/, '') : phrase;
    t.check(phrase.indexOf('arrivalExcluded') < 0 && title.length > 0 &&
            at >= 0 && meta > at &&
            html.indexOf(title) > at && html.indexOf(title) < meta &&
            html.indexOf(rest) > at && html.indexOf(rest) < meta,
            '1. ' + tag + ' draws the arrival note on that tab');
  });
  log.debug("Leaving run().");
}

module.exports = { run: run };
