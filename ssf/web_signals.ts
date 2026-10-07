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
    const st: any = json.status || {};
    const stream = st.stream;

    const tiles = '<div class="tiles">' +
      kit.tile(json.total, 'delivered here') +
      kit.tile(stream ? stream.caepDelivered : 0, 'CAEP types') +
      kit.tile(stream ? stream.riscDelivered : 0, 'RISC types') +
      kit.tile(stream ? stream.counters.delivered : 0, 'pushes accepted') +
      kit.tile(stream ? stream.counters.failed : 0, 'pushes failed') +
      kit.tile(stream ? stream.queued : 0, 'still queued') +
      '</div>';

    // WHY NOTHING IS HERE, ABOVE THE TABLE AND NOT BELOW IT. An empty inbox
    // has five causes and only one of them is "nothing has happened";
    // `status()` works out which apply and this draws them in the order a
    // reader should check them. It is drawn even when rows ARE present,
    // because a stream that has been paused since this morning explains a
    // page that stops rather than a page that is empty.
    const why = st.why && st.why.length
      ? '<div class="err"><p><strong>Some or all of this console\'s ' +
        'signals are not arriving.</strong></p><ul>' +
        st.why.map(function (line) {
          return '<li>' + kit.esc(line) + '</li>';
        }).join('') + '</ul></div>'
      : '';

    const streamBlock = stream
      ? '<table>' +
        '<tr><th>Stream</th><td><code>' + kit.esc(stream.stream_id) +
        '</code></td></tr><tr><th>Audience</th><td><code>' +
        kit.esc(String(stream.aud)) + '</code> ' +
        '<span class="sub">' +
        kit.esc('This console checks for this name in every SET\'s aud ' +
                 'and refuses one addressed to anybody else with ' +
                 'invalid_audience — recording it either way, so a ' +
                 'misaddressed event is visible rather than merely absent.') +
                 '</span></td></tr>' +
        '<tr><th>Issuer</th><td><code>' + kit.esc(String(stream.iss)) +
        '</code></td></tr><tr><th>Delivered ' +
        'to</th><td><code>' +
        kit.esc(stream.endpoint_url) + '</code> <span class="sub">' +
        kit.esc('RFC 8935 push, over the loopback interface, with this ' +
                 'service\'s own TLS certificate pinned. It is a real HTTP ' +
                 'request on purpose: handing the event to the page in ' +
                 'process would skip the body, the media type, the ' +
                 'authorization header and the signature.') +
        '</span></td></tr>' +
        '<tr><th>Event types</th><td>' + kit.esc(String(stream.delivers)) +
        ' delivered of ' + kit.esc(String(stream.requested)) + ' ' +
        'requested <span class="sub">' +
        kit.esc('The difference is the intersection SSF 1.0 section 7.1.1 ' +
                 'defines: a type this transmitter does not support is ' +
                 'answered by its absence from events_delivered rather ' +
                 'than by a refusal.') +
        '</span></td></tr>' +
        '<tr><th>Status</th><td><span class="' +
        (stream.status === 'enabled' ? '' : 'state-invalid') + '">' +
        kit.esc(stream.status) + '</span> <span class="sub">' +
        kit.esc(stream.statusReason) + '</span></td></tr>' +
        '<tr><th>Last push</th><td>' +
        (stream.lastPushAt
          ? kit.esc(stream.lastPushAt) +
            (stream.lastPushError
              ? ' <span class="state-invalid">' +
                kit.esc(stream.lastPushError) +
                '</span>'
              : '')
          : '<span class="sub">nothing has been pushed here yet</span>') +
        '</td></tr></table>'
      : kit.note('<strong>There is no stream for this console in the ' +
        '&ldquo;' +
        kit.esc(st.realm) + '&rdquo; realm.</strong> It is seeded at ' +
        'startup and is an ORDINARY stream — if it was paused, narrowed or ' +
        'deleted at <a href="/admin/ssf">Shared Signals</a> or through ' +
        '<code>/admin-api/ssf</code>, it stays that way until a restart. ' +
        'That is the same rule this service\'s seeded application entries ' +
        'follow.');

    const search = kit.sectionSearchForm({
      path: '/admin/signals', param: 'sigq', pageParam: 'receivedPage',
      query: ctx.query, label: 'Find',
      placeholder: 'alice, session-revoked, a jti, a stream id',
      what: 'Over the event name, the type URI, the subject as this ' +
            'receiver read it, the issuer, the audience, the jti and the ' +
            'stream — because a reader arrives holding one of those and ' +
            'does not know which column it is in.' });

    const nav = kit.pageNavPair('/admin/signals', kit.pageParamsOf(ctx.query),
                                 json.paging.received);

    const rows = json.received.map(function (row) {
      return '<tr>' +
        '<td class="sub">' + kit.esc(kit.whenText(Date.parse(row.at))) +
        '</td><td><code>' + kit.esc(row.vocabulary) + '</code> ' +
        kit.esc(row.name) +
        (row.types.length > 1
          ? ' <span class="sub">and ' +
            kit.esc(String(row.types.length - 1)) +
            ' more in the same SET</span>'
          : '') +
        '<div class="sub"><code>' + kit.esc(row.types[0] || '(none)') +
        '</code></div></td>' +
        '<td>' + (row.subject
          ? kit.esc(row.subject)
          : '<span class="sub" title="' +
            kit.esc('SSF\'s own two events are about the STREAM rather ' +
                     'than about anybody, so they carry no subject at all. ' +
                     'Every CAEP and RISC event does.') +
                     '">&mdash;</span>') + '</td>' +
        '<td>' + (row.verified
          ? '<span title="' + kit.esc(row.verificationNote) +
            '">verified</span>'
          : '<span class="state-invalid" title="' +
            kit.esc(row.verificationNote) + '">not verified</span>') +
        (row.audienceOk
          ? ''
          : '<div class="state-invalid" title="' +
            kit.esc('This receiver is "' + String(st.audience) +
                     '" and that name is not in this token\'s aud. It was ' +
                     'refused with invalid_audience and recorded anyway, ' +
                     'because what arrived is the question being asked.') +
                     '">wrong audience</div>') +
        (row.correctMediaType
          ? ''
          : '<div class="sub" title="' +
            kit.esc('RFC 8935 section 2.1 says application/secevent+jwt. ' +
                     'This one said "' +
                     String(row.contentType || '(nothing)') + '". It was ' +
                     'accepted — a receiver that refused would be testing ' +
                     'the transmitter\'s pedantry — and it is said out ' +
                     'loud rather than passed over.') +
                     '">media type</div>') +
        // WHAT THIS CONSOLE DID WITH IT (#62): the signal-response
        // policy's reactions, taken, observed or failed.
        (row.reactions || []).map(function (r) {
          return '<div class="signal-reaction ' +
            (r.failed ? 'state-invalid' : 'sub') + '">' + (r.failed
              ? 'could not end its sessions'
              : r.skipped ? 'ended nothing: ' + kit.esc(r.skipped)
              : (r.observed ? 'would end this console\'s sessions ' +
                              '(development observes)'
                            : 'ended ' + kit.esc(String(r.ended)) +
                              ' console session(s)')) + '</div>';
        }).join('') +
        '</td>' +
        '<td class="sub"><code>' + kit.esc(row.jti) + '</code>' +
        '<div><code>' + kit.esc(row.stream || '') + '</code></div></td>' +
        '<td>' + (Object.keys(row.payload).length
          ? '<details><summary>' +
            kit.esc(String(Object.keys(row.payload).length) + ' member(s)') +
            '</summary><pre>' +
            kit.esc(JSON.stringify(row.payload, null, 2)) +
            '</pre></details>'
          : '<span class="sub" title="' +
            kit.esc('Eleven of RISC\'s fourteen event types have no ' +
                     'payload members at all — the SUBJECT carries the ' +
                     'entire message, which is why a subject naming the ' +
                     'wrong person is a wholly wrong event rather than a ' +
                     'partly wrong one.') + '">no members</span>') +
        '</td></tr>';
    }).join('') || '<tr><td colspan="6">' +
      kit.esc(json.filter.received
        ? 'Nothing delivered here matches that search.'
        : 'Nothing has been delivered to this console yet.') +
      '</td></tr>';

    const inner = '<h1>Signals received</h1><p>Every Security Event Token ' +
      '<strong>delivered to this console</strong> in the ' +
      '&ldquo;' + kit.esc(st.realm) + '&rdquo; realm. This console is a ' +
      'registered Shared Signals receiver: it has a stream of its own, it ' +
      'is POSTed each event over RFC 8935 push at <code>' +
      kit.esc(st.receivePath) + '</code>, and it verifies the signature ' +
      'and the audience before recording anything.</p>' +
      why +
      tiles +
      kit.note('<strong>This is not the transmitter\'s copy.</strong> ' +
      '<a href="/admin/ssf">Shared Signals</a> shows every stream this ' +
      'service holds and what it has SENT on each; <a ' +
      'href="/admin/caep-sessions">CAEP sessions</a> and <a ' +
      'href="/admin/risc-accounts">RISC accounts</a> show what it BELIEVES ' +
      'about a session and an account. This page shows what came back ' +
      'through the door — which is the only one of the four that goes ' +
      'empty when delivery is broken, and is therefore the only one that ' +
      'can tell you it is.') +

      '<h2>This console\'s stream</h2>' +
      streamBlock +

      '<h2 id="find-sigq">Delivered events</h2>' +
      search +
      nav.head +
      '<table><tr><th>When</th><th>Event</th><th>Subject</th>' +
      '<th>How it arrived</th><th>Identifiers</th><th>Payload</th></tr>' +
      rows + '</table>' +
      nav.foot +

      // THE ONE CONTROL, and it is drawn only when there is something to
      // clear: a button that would drop nothing is a button somebody presses
      // to find out what it does. The CSRF token is put into this form by
      // `withCsrf()` on the way out, like every other form on this console —
      // rule 8's arrangement, so a page author does neither half.
      (json.total
        ? '<h2>Clear</h2>' +
          kit.note('This drops what is HELD HERE and nothing else. The ' +
          'stream is untouched and goes on delivering, and the <a ' +
          'href="/admin/audit">audit log</a>\'s record of each delivery ' +
          'cannot be cleared — which is the point of it being the durable ' +
          'half.') +
          '<form method="post" action="/admin/signals">' +
          '<input type="hidden" name="back" value="' +
          kit.esc(kit.queryWith(kit.listViewFromBack('/admin/signals',
                                                   kit.queryOne(ctx.query,
                                                       'back')), {})) +
          '">' +
          '<div class="formrow">' +
          '<input type="hidden" name="action" value="clear">' +
          '<button type="submit" class="secondary" title="' +
          kit.esc('Drops the ' + json.total + ' delivered event(s) held ' +
                   'in this console\'s inbox in this realm.') +
          '">Clear this inbox</button></div></form>'
        : '') +

      kit.note('<a href="/admin/signals?format=json">this page as ' +
      'JSON</a> &middot; <a href="/admin-api/signals">the same over the ' +
      'management API</a> &middot; <a href="/admin/ssf">the streams and ' +
      'the settings</a> &middot; <a href="/portal/signals">what a person ' +
      'sees about themselves</a> &middot; <a href="/admin/audit">the ' +
      'durable record</a>');

    return inner;
  }
}

export = SignalsPage;
