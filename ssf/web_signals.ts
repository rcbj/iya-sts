// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_signals.ts
//
// ---------------------------------------------------------------------------
// MONITORING → SHARED SIGNALS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Monitoring → Shared Signals from the answer of `GET
// /admin-api/signals`: what this service has transmitted and received, stream
// by stream, and the events themselves.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/signals` in `admin-ui/admin.ts`,
// which still draws the page until the console's cutover by calling this with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * Draws Monitoring → Shared Signals from the answer of `GET
 * /admin-api/signals`: what this service has transmitted and received, stream
 * by stream, and the events themselves.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SignalsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {
    const t = ctx.t;
    const st: any = json.status || {};
    const stream = st.stream;

    const tiles = '<div class="tiles">' +
      kit.tile(json.total, t.text('consoleSignals.tile.delivered')) +
      kit.tile(stream ? stream.caepDelivered : 0,
               t.text('consoleSignals.tile.caep')) +
      kit.tile(stream ? stream.riscDelivered : 0,
               t.text('consoleSignals.tile.risc')) +
      kit.tile(stream ? stream.counters.delivered : 0,
               t.text('consoleSignals.tile.accepted')) +
      kit.tile(stream ? stream.counters.failed : 0,
               t.text('consoleSignals.tile.failed')) +
      kit.tile(stream ? stream.queued : 0,
        t.text('consoleSignals.tile.queued')) +
      '</div>';

    // WHY NOTHING IS HERE, ABOVE THE TABLE AND NOT BELOW IT. An empty inbox
    // has five causes and only one of them is "nothing has happened";
    // `status()` works out which apply and this draws them in the order a
    // reader should check them. It is drawn even when rows ARE present,
    // because a stream that has been paused since this morning explains a
    // page that stops rather than a page that is empty.
    const why = st.why && st.why.length
      ? '<div class="err"><p>' + t.html('consoleSignals.why') +
        '</p><ul>' +
        st.why.map(function (line) {
          return '<li>' + kit.esc(line) + '</li>';
        }).join('') + '</ul></div>'
      : '';

    const streamBlock = stream
      ? '<table>' +
        '<tr><th>' + t.html('consoleSignals.stream.stream') +
        '</th><td><code>' + kit.esc(stream.stream_id) +
        '</code></td></tr><tr><th>' +
        t.html('consoleSignals.stream.audience') + '</th><td><code>' +
        kit.esc(String(stream.aud)) + '</code> ' +
        '<span class="sub">' +
        kit.esc(t.text('consoleSignals.stream.audienceNote')) +
                 '</span></td></tr>' +
        '<tr><th>' + t.html('consoleSignals.stream.issuer') +
        '</th><td><code>' + kit.esc(String(stream.iss)) +
        '</code></td></tr><tr><th>' +
        t.html('consoleSignals.stream.deliveredTo') + '</th><td><code>' +
        kit.esc(stream.endpoint_url) + '</code> <span class="sub">' +
        kit.esc(t.text('consoleSignals.stream.deliveredToNote')) +
        '</span></td></tr>' +
        '<tr><th>' + t.html('consoleSignals.stream.eventTypes') +
        '</th><td>' +
        t.html('consoleSignals.stream.deliveredOf',
               { delivers: String(stream.delivers),
                 requested: String(stream.requested) }) +
        ' <span class="sub">' +
        kit.esc(t.text('consoleSignals.stream.eventTypesNote')) +
        '</span></td></tr>' +
        '<tr><th>' + t.html('consoleSignals.stream.status') +
        '</th><td><span class="' +
        (stream.status === 'enabled' ? '' : 'state-invalid') + '">' +
        kit.esc(stream.status) + '</span> <span class="sub">' +
        kit.esc(stream.statusReason) + '</span></td></tr>' +
        '<tr><th>' + t.html('consoleSignals.stream.lastPush') + '</th><td>' +
        (stream.lastPushAt
          ? kit.esc(stream.lastPushAt) +
            (stream.lastPushError
              ? ' <span class="state-invalid">' +
                kit.esc(stream.lastPushError) +
                '</span>'
              : '')
          : '<span class="sub">' + t.html('consoleSignals.stream.noPush') +
            '</span>') +
        '</td></tr></table>'
      // The link is markup a message cannot carry, so the paragraph is
      // drawn around it (#539).
      : kit.note(t.html('consoleSignals.noStream.before',
                        { realm: st.realm }) +
        '<a href="/admin/ssf">' + t.html('consoleSignals.link.ssf') +
        '</a>' + t.html('consoleSignals.noStream.after'));

    const search = kit.sectionSearchForm({
      path: '/admin/signals', param: 'sigq', pageParam: 'receivedPage',
      query: ctx.query, label: t.text('consoleSignals.find.label'),
      placeholder: t.text('consoleSignals.find.placeholder'),
      what: t.html('consoleSignals.find.what') }, t);

    const nav = kit.pageNavPair('/admin/signals', kit.pageParamsOf(ctx.query),
                                 json.paging.received, t);

    const rows = json.received.map(function (row) {
      return '<tr>' +
        '<td class="sub">' + kit.esc(kit.whenText(Date.parse(row.at))) +
        '</td><td><code>' + kit.esc(row.vocabulary) + '</code> ' +
        kit.esc(row.name) +
        (row.types.length > 1
          ? ' <span class="sub">' +
            t.html('consoleSignals.row.more',
                   { n: String(row.types.length - 1) }) + '</span>'
          : '') +
        '<div class="sub"><code>' + kit.esc(row.types[0] || '(none)') +
        '</code></div></td>' +
        '<td>' + (row.subject
          ? kit.esc(row.subject)
          : '<span class="sub" title="' +
            kit.esc(t.text('consoleSignals.row.noSubject')) +
                     '">&mdash;</span>') + '</td>' +
        '<td>' + (row.verified
          ? '<span title="' + kit.esc(row.verificationNote) +
            '">' + t.html('consoleSignals.row.verified') + '</span>'
          : '<span class="state-invalid" title="' +
            kit.esc(row.verificationNote) + '">' +
            t.html('consoleSignals.row.notVerified') + '</span>') +
        (row.audienceOk
          ? ''
          : '<div class="state-invalid" title="' +
            kit.esc(t.text('consoleSignals.row.wrongAudienceTip',
                           { audience: String(st.audience) })) +
                     '">' + t.html('consoleSignals.row.wrongAudience') +
                     '</div>') +
        (row.correctMediaType
          ? ''
          : '<div class="sub" title="' +
            kit.esc(t.text('consoleSignals.row.mediaTypeTip',
                           { said: String(row.contentType || '(nothing)') })) +
                     '">' + t.html('consoleSignals.row.mediaType') +
                     '</div>') +
        // WHAT THIS CONSOLE DID WITH IT (#62): the signal-response
        // policy's reactions, taken, observed or failed.
        (row.reactions || []).map(function (r) {
          return '<div class="signal-reaction ' +
            (r.failed ? 'state-invalid' : 'sub') + '">' + (r.failed
              ? t.html('consoleSignals.reaction.failed')
              : r.skipped
                ? t.html('consoleSignals.reaction.skipped',
                         { why: r.skipped })
              : (r.observed ? t.html('consoleSignals.reaction.observed')
                            : t.html('consoleSignals.reaction.ended',
                                     { n: String(r.ended) }))) + '</div>';
        }).join('') +
        '</td>' +
        '<td class="sub"><code>' + kit.esc(row.jti) + '</code>' +
        '<div><code>' + kit.esc(row.stream || '') + '</code></div></td>' +
        '<td>' + (Object.keys(row.payload).length
          ? '<details><summary>' +
            kit.esc(t.text('consoleSignals.row.members',
                           { n: String(Object.keys(row.payload).length) })) +
            '</summary><pre>' +
            kit.esc(JSON.stringify(row.payload, null, 2)) +
            '</pre></details>'
          : '<span class="sub" title="' +
            kit.esc(t.text('consoleSignals.row.noMembersTip')) + '">' +
            t.html('consoleSignals.row.noMembers') + '</span>') +
        '</td></tr>';
    }).join('') || '<tr><td colspan="6">' +
      kit.esc(json.filter.received
        ? t.text('consoleSignals.empty.search')
        : t.text('consoleSignals.empty.none')) +
      '</td></tr>';

    const inner = '<h1>' + t.html('consoleSignals.heading') + '</h1><p>' +
      t.html('consoleSignals.intro', { realm: st.realm,
                                       path: st.receivePath }) + '</p>' +
      why +
      tiles +
      // Three links in one paragraph: the words between them are messages
      // of their own (#539).
      kit.note(t.html('consoleSignals.copy.head') + ' ' +
      '<a href="/admin/ssf">' + t.html('consoleSignals.link.ssf') + '</a>' +
      t.html('consoleSignals.copy.ssf') + '<a ' +
      'href="/admin/caep-sessions">' +
      t.html('consoleSignals.link.caepSessions') + '</a>' +
      t.html('consoleSignals.copy.and') + '<a ' +
      'href="/admin/risc-accounts">' +
      t.html('consoleSignals.link.riscAccounts') + '</a>' +
      t.html('consoleSignals.copy.rest')) +

      '<h2>' + t.html('consoleSignals.stream.heading') + '</h2>' +
      streamBlock +

      '<h2 id="find-sigq">' + t.html('consoleSignals.events.heading') +
      '</h2>' +
      search +
      nav.head +
      '<table><tr><th>' + t.html('consoleSignals.th.when') + '</th><th>' +
      t.html('consoleSignals.th.event') + '</th><th>' +
      t.html('consoleSignals.th.subject') + '</th>' +
      '<th>' + t.html('consoleSignals.th.how') + '</th><th>' +
      t.html('consoleSignals.th.identifiers') + '</th><th>' +
      t.html('consoleSignals.th.payload') + '</th></tr>' +
      rows + '</table>' +
      nav.foot +

      // THE ONE CONTROL, and it is drawn only when there is something to
      // clear: a button that would drop nothing is a button somebody presses
      // to find out what it does. The CSRF token is put into this form by
      // `withCsrf()` on the way out, like every other form on this console —
      // rule 8's arrangement, so a page author does neither half.
      (json.total
        ? '<h2>' + t.html('consoleSignals.clear.heading') + '</h2>' +
          kit.note(t.html('consoleSignals.clear.before') + '<a ' +
          'href="/admin/audit">' + t.html('consoleSignals.link.audit') +
          '</a>' + t.html('consoleSignals.clear.after')) +
          '<form method="post" action="/admin/signals">' +
          '<input type="hidden" name="back" value="' +
          kit.esc(kit.queryWith(kit.listViewFromBack('/admin/signals',
                                                   kit.queryOne(ctx.query,
                                                       'back')), {})) +
          '">' +
          '<div class="formrow">' +
          '<input type="hidden" name="action" value="clear">' +
          '<button type="submit" class="secondary" title="' +
          kit.esc(t.text('consoleSignals.clear.tip',
                         { n: String(json.total) })) +
          '">' + t.html('consoleSignals.clear.button') +
          '</button></div></form>'
        : '') +

      kit.note('<a href="/admin/signals?format=json">' +
      t.html('consoleSignals.foot.json') + '</a> &middot; ' +
      '<a href="/admin-api/signals">' + t.html('consoleSignals.foot.api') +
      '</a> &middot; <a href="/admin/ssf">' +
      t.html('consoleSignals.foot.streams') + '</a> &middot; ' +
      '<a href="/portal/signals">' + t.html('consoleSignals.foot.portal') +
      '</a> &middot; <a href="/admin/audit">' +
      t.html('consoleSignals.foot.audit') + '</a>');

    return inner;
  }
}

export = SignalsPage;
