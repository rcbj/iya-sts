// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_ssf.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SHARED SIGNALS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Shared Signals from the answer of `GET /admin-api/ssf`: the
// transmitter's streams, each with its status and the forms that change it,
// and the settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// It was drawn inside the route of `/admin/ssf` in `admin-ui/admin.ts`, which
// still draws the page until the console's cutover by calling this with its
// view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

/**
 * Draws Shared Signals from the answer of `GET /admin-api/ssf`: the
 * transmitter's streams, each with its status and the forms that change it,
 * and the settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SsfPage {
  /**
   * Draws the page's body from its view.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static body(ctx, json) {

    const tiles = '<div class="tiles">' +
      kit.tile(json.streamDetail ? json.streamDetail.length : 0, 'streams') +
      kit.tile((json.streamDetail || []).filter(function (row) {
        return row.status === 'enabled';
      }).length, 'enabled') +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + row.counters.delivered;
      }, 0), 'events delivered') +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + row.counters.failed;
      }, 0), 'deliveries refused') +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + row.queue.length;
      }, 0), 'waiting') +
      kit.tile((json.streamDetail || []).filter(function (row) {
        return row.dead;
      }).length, 'dead streams') +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + (row.deadLetters || []).length;
      }, 0), 'dead letters') +
      kit.tile((json.receivedDetail || []).length, 'received here') +
      '</div>';

    const receivedRows = (json.receivedDetail || []).length
      ? json.receivedDetail.slice(0, 25).map(function (row) {
          return '<tr><td class="sub">' + kit.esc(row.at) + '</td><td>' +
            kit.esc(row.summary ? row.summary.name : '(unreadable)') +
            '</td>' +
            '<td><code>' + kit.esc(row.summary ? row.summary.jti : '') +
            '</code></td>' +
            '<td class="' + (row.verified ? 'state-valid' : 'sub') + '">' +
            kit.esc(row.verified ? 'verified' : 'not verified here') +
            '</td>' +
            '<td class="' + (row.correctMediaType ? 'sub' : 'state-invalid') +
            '"><code>' + kit.esc(row.contentType || '(none)') +
            '</code></td></tr>';
        }).join('')
      : '<tr><td colspan="5">Nothing has been pushed at this ' +
        'service.</td></tr>';

    const inner = (!json.installed
        ? '<div class="err"><strong>Shared Signals is not loaded in this ' +
          'process.</strong> The module registers no routes here, so there ' +
          'is nothing to report. Everything else on this console is ' +
          'unaffected.</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn('<strong>SSF is turned off</strong> ' +
          '(<code>ssf.enabled</code>). The routes are still registered and ' +
          'answer <code>501</code> rather than <code>404</code>, because ' +
          'the feature being off and the URL being wrong are different ' +
          'sentences to a client. The transmitter metadata still answers, ' +
          'so a receiver can discover that this service speaks SSF and is ' +
          'not currently doing it. Turn it back on in the settings at the ' +
          'foot of this page.')
        : '') +

      kit.note('The <strong>Shared Signals Framework</strong> (OpenID SSF ' +
      '1.0, final 2 September 2025) is the one protocol family here that ' +
      'TALKS BACK. Every other family answers a request; this one delivers ' +
      'an event nobody asked for, at the moment it happens, to somebody ' +
      'who agreed in advance to be told. What it solves is that SAML and ' +
      'OpenID Connect authenticate at ONE INSTANT and the relying party ' +
      'then holds a session for hours whatever happens next.') +

      kit.warn('<strong>SSF is the pipe and not the vocabulary.</strong> ' +
      'It defines how two parties agree a stream, who the events are about ' +
      '(RFC 9493), what they travel in (RFC 8417) and how they get there ' +
      '(RFC 8935 push, RFC 8936 poll) &mdash; and exactly TWO events of ' +
      'its own, both about the pipe. The vocabularies are ' +
      '<strong>CAEP</strong> (what happened to a session) and ' +
      '<strong>RISC</strong> (what happened to an account). <strong>CAEP ' +
      'is implemented</strong> &mdash; its eight session event types ' +
      'travel on the streams below, and <a href="/admin/caep">its own ' +
      'page</a> carries the settings, the catalogue and the by-hand emit ' +
      'form while <a href="/admin/caep-sessions">CAEP sessions</a> counts ' +
      'what has been said about whom. RISC is the third part and is not ' +
      'here yet. What changed with CAEP is the sentence this page used to ' +
      'carry next: this service DOES now generate an event on its own, ' +
      'when a session starts, is presented or ends. ' +
      '<code>caep.autoEmit</code> puts the old behaviour back.') +

      tiles +

      (json.installed
        ? '<h2>Discovery</h2>' +
          kit.note('Everything a receiver needs is at <code>' +
          kit.esc(json.metadataUrl || '') + '</code>, which is ' +
          '<strong>never gated</strong>: a receiver has to be able to read ' +
          'what the endpoints are before it can authenticate to one. The ' +
          'issuer is <code>' + kit.esc(json.issuer || '') + '</code> and ' +
          'every SET is signed with <code>' +
          kit.esc(json.signingAlgorithm || '') + '</code>.') +
          kit.note('That algorithm is <code>ssf.signingAlgorithm</code> ' +
          'and it reaches the whole table, <strong>post-quantum ' +
          'included</strong> &mdash; ML-DSA at three sizes, SLH-DSA at ' +
          'two, and the six composite ML-DSA + traditional ones &mdash; ' +
          'because a SET is signed through the same signer every other JWT ' +
          'here goes through. This is the document most worth signing that ' +
          'way: it records that something HAPPENED, RFC 8417 section 4.1.4 ' +
          'forbids it to expire, and it is therefore read long after it ' +
          'was written.')
        : '') +

      (json.installed
        ? '<h2>Streams</h2>' +
          ((json.streamDetail || []).length
            ? json.streamDetail.map(function (row) {
              return SsfPage.ssfStreamCard(row, json);
            }).join('')
            : kit.note('No streams. A receiver creates one by POSTing a ' +
              'Stream Configuration to <code>' +
              kit.esc((json.metadata &&
                        json.metadata.configuration_endpoint) ||
                       '/ssf/stream') + '</code>. There is deliberately no ' +
              '&ldquo;create a stream&rdquo; form here: a stream carries a ' +
              'delivery endpoint THIS SERVICE WILL DIAL, and the one place ' +
              'that URL may come from is a receiver that authenticated and ' +
              'asked &mdash; see <code>ssf/ssf_http.ts</code>.'))
        : '') +

      (json.installed
        ? '<h2>Pushed at this service</h2>' +
          kit.note('The roles reversed. <code>POST /ssf/receive</code> ' +
          'accepts a Security Event Token pushed AT this service, which is ' +
          'what a client acting as the TRANSMITTER sends to. It accepts ' +
          'one whose signature does not verify and reports why &mdash; a ' +
          'receiver that refused could not show anybody what arrived, ' +
          'which is the question being asked. ' +
          '<code>ssf.receiveRequireSignature</code> turns the 400 on.') +
          '<table><tr><th>When</th><th>Event</th><th>jti</th>' +
          '<th>Signature</th><th>Content-Type</th></tr>' + receivedRows +
          '</table>' +
          '<form method="post" action="/admin/ssf"><div class="formrow">' +
          '<input type="hidden" name="action" value="clear-received">' +
          '<button class="secondary">Clear what has been received</button>' +
          '</div></form>'
        : '') +

      SettingsForms.forms(json.settings, '/admin/ssf') +

      kit.note('<a href="/ssf">What this is, for a person</a> &middot; ' +
      '<a href="/admin/ssf?format=json">this page as JSON</a> &middot; ' +
      '<a href="/admin-api/ssf">the same over the management API</a> ' +
      '&middot; <a href="/admin/applications">the receivers, as ' +
      'applications</a>');

    return inner;
  }

  /**
   * Draws one Shared Signals stream as a card: its facts, subjects, queue,
   * dead letters, history, and the forms that act on it.
   *
   * @param row - the stream as the SSF reporter describes it
   * @param json - the page's view, whose `statuses` and `eventTypes` are
   *   the two menus
   * @returns the card as HTML
   */
  static ssfStreamCard(row, json) {
    const subjects = row.subjects.length
      ? row.subjects.map(function (one) {
          return '<tr><td>' + kit.esc(one.text) + '</td><td>' +
            (one.verified ? 'verified' : 'unverified') + '</td><td ' +
              'class="sub">' +
            kit.esc(one.addedAt) + '</td></tr>';
        }).join('')
      : '<tr><td colspan="3">No subjects. What that MEANS is ' +
        '<code>default_subjects</code> on the transmitter metadata: with ALL ' +
        'this stream is about everybody, with NONE about nobody.</td></tr>';
    const queue = row.queue.length
      ? row.queue.map(function (one) {
          return '<tr><td><code>' + kit.esc(one.jti) + '</code></td><td>' +
            kit.esc(one.summary.name) + '</td><td class="sub">' +
            kit.esc(one.queuedAt) + '</td><td class="sub">' +
            kit.esc(one.deliveredAt || 'not yet') + '</td></tr>';
        }).join('')
      : '<tr><td colspan="4">Nothing waiting.</td></tr>';
    const history = row.log.slice(0, 12).map(function (one) {
      return '<tr><td class="sub">' + kit.esc(one.at) + '</td><td>' +
        kit.esc(one.kind) + '</td><td>' + kit.esc(one.text) + '</td></tr>';
    }).join('') || '<tr><td colspan="3">Nothing recorded yet.</td></tr>';
    // THE DEAD-LETTER QUEUE (2026-09-14): what could not be delivered, newest
    // first, with the reason. The first twenty-five; the JSON has them all.
    const dead = row.deadLetters || [];
    const deadRows = dead.length
      ? dead.slice(0, 25).map(function (one) {
          return '<tr><td><code>' + kit.esc(one.jti) + '</code></td><td>' +
            kit.esc(one.summary ? one.summary.name : '') + '</td><td ' +
              'class="sub">' +
            kit.esc(one.deadAt) + '</td><td>' + kit.esc(one.reason) +
            (one.errorCode ? ' <code>' + kit.esc(one.errorCode) + '</code>' :
             '') +
            '</td><td class="sub">' + (one.signed ? 'signed' : 'not signed') +
            '</td></tr>';
        }).join('') + (dead.length > 25
          ? '<tr><td colspan="5">&hellip; and ' + (dead.length - 25) +
            ' more, in this page\'s JSON.</td></tr>' : '')
      : '<tr><td colspan="5">Nothing undeliverable.</td></tr>';

    // The heading carries an id so Monitoring → Shared Signals → Dead letters
    // can link each stream row straight to this card, where its controls are.
    return '<h3 id="stream-' + kit.esc(row.stream_id) + '"><code>' +
      kit.esc(row.stream_id) + '</code> &mdash; ' +
      kit.esc(row.status) + (row.dead
        ? ' <span class="state-invalid">&mdash; DEAD</span>' : '') + '</h3>' +
      (row.dead
        ? '<p class="state-invalid">Declared dead at ' +
          kit.esc(row.deadSince) +
          ': its pushes all failed for <code>ssf.deadStreamTimeoutS</code>. ' +
          'Nothing is pushed to it; its SETs go to the dead-letter queue, ' +
          'and one is pushed as a probe at ' +
          kit.esc(row.nextProbeAt || 'the next ' +
          'sweep') + '. Last failure: ' + kit.esc(row.deadReason) + '</p>'
        : '') +
      '<table class="key">' +
      '<tr><th>Issuer</th><td><code>' + kit.esc(row.iss) +
      '</code></td></tr>' +
      '<tr><th>Audience</th><td><code>' +
      kit.esc(Array.isArray(row.aud) ? row.aud.join(', ') : row.aud) +
      '</code></td></tr>' +
      '<tr><th>Delivery</th><td><code>' + kit.esc(row.delivery.method) +
      '</code>' + (row.delivery.endpoint_url
        ? ' &rarr; <code>' + kit.esc(row.delivery.endpoint_url) + '</code>'
        : '') + '</td></tr>' +
      '<tr><th>Delivers</th><td>' + (row.events_delivered.length
        ? row.events_delivered.map(function (uri) {
            return '<code>' + kit.esc(uri) + '</code>';
          }).join('<br>')
        : 'nothing &mdash; the intersection of what the receiver asked for ' +
          'and what this transmitter supports is empty') + '</td></tr>' +
      '<tr><th>Created</th><td class="sub">' + kit.esc(row.createdAt) + ' ' +
        'by ' +
      kit.esc(row.createdBy || '(unauthenticated)') + '</td></tr>' +
      '<tr><th>Counters</th><td>' + row.counters.queued + ' queued, ' +
      row.counters.delivered + ' delivered, ' + row.counters.failed +
      ' failed, ' + row.counters.acknowledged + ' acknowledged, ' +
      row.counters.receiverErrors + ' refused by the receiver</td></tr>' +
      (row.lastPushError
        ? '<tr><th>Last push</th><td class="state-invalid">' +
          kit.esc(row.lastPushError) + '</td></tr>'
        : '') +
      '</table>' +
      '<h4>Subjects</h4>' +
      '<table><tr><th>Subject</th><th>State</th><th>Added</th></tr>' +
      subjects + '</table>' +
      '<h4>Waiting to be delivered</h4>' +
      '<table><tr><th>jti</th><th>Event</th><th>Queued</th><th>Delivered</th>' +
      '</tr>' + queue + '</table>' +
      '<h4>Dead letters</h4>' +
      kit.note('SETs that could not be delivered, with the reason, kept for ' +
                '<code>ssf.deadLetterRetentionS</code> and then deleted. ' +
                'Nothing resends them. <a href="' +
                kit.esc('/admin/ssf/dead-letters' +
                kit.queryWith({}, { dlstream: row.stream_id })) +
                '#find-dlq">Every ' +
                'one, counted and searchable</a>.') +
      '<table><tr><th>jti</th><th>Event</th><th>Dead since</th><th>Why</th>' +
      '<th></th></tr>' + deadRows + '</table>' +
      '<h4>What has happened on this stream</h4>' +
      '<table><tr><th>When</th><th>What</th><th>Detail</th></tr>' + history +
      '</table>' +
      (row.dead
        ? '<form method="post" action="/admin/ssf"><div class="formrow">' +
          '<input type="hidden" name="stream_id" value="' +
          kit.esc(row.stream_id) +
          '">' +
          '<input type="hidden" name="action" value="revive">' +
          '<button>Revive this stream</button>' +
          '</div></form>'
        : '') +
      (dead.length
        ? '<form method="post" action="/admin/ssf"><div class="formrow">' +
          '<input type="hidden" name="stream_id" value="' +
          kit.esc(row.stream_id) +
          '">' +
          '<input type="hidden" name="action" value="clear-dead-letters">' +
          '<button class="secondary">Drop its dead letters</button>' +
          '</div></form>'
        : '') +
      // A TRANSMITTER-INITIATED VERIFICATION EVENT (#144, SSF 1.0 section
      // 8.1.4), with no state — the receiver did not ask, so there is none to
      // echo. The same act as POST /admin-api/ssf/verify.
      (row.status !== 'disabled'
        ? '<form method="post" action="/admin/ssf"><div class="formrow">' +
          '<input type="hidden" name="stream_id" value="' +
          kit.esc(row.stream_id) +
          '">' +
          '<input type="hidden" name="action" value="verify">' +
          '<button class="secondary">Send a verification event</button>' +
          '</div></form>'
        : '') +
      '<form method="post" action="/admin/ssf"><div class="formrow">' +
      '<input type="hidden" name="stream_id" value="' +
      kit.esc(row.stream_id) +
      '"><input type="hidden" name="action" value="status"><label ' +
      'for="status-' + kit.esc(row.stream_id) +
      '">Set the status</label>' +
      '<select id="status-' + kit.esc(row.stream_id) + '" name="status">' +
      (json.statuses || []).map(function (one) {
        return '<option value="' + kit.esc(one) + '"' +
          (one === row.status ? ' selected' : '') + '>' + kit.esc(one) +
          '</option>';
      }).join('') + '</select>' +
      '<input type="text" name="reason" size="28" placeholder="reason (shown ' +
      'to the receiver)">' +
      '<button>Set status</button>' +
      '</div></form>' +
      '<form method="post" action="/admin/ssf"><div class="formrow">' +
      '<input type="hidden" name="stream_id" value="' +
      kit.esc(row.stream_id) +
      '"><input type="hidden" name="action" value="transmit"><label ' +
      'for="type-' + kit.esc(row.stream_id) +
      '">Transmit an event</label>' +
      '<select id="type-' + kit.esc(row.stream_id) + '" name="type">' +
      (json.eventTypes || [])
        .map(function (one) {
          return '<option value="' + kit.esc(one.uri) + '">' +
                 kit.esc(one.name) +
            (one.offered ? '' : ' (not offered)') + '</option>';
        }).join('') + '</select>' +
      '<input type="text" name="payload" size="30" value="{}" ' +
      'placeholder="the event payload, as JSON">' +
      '<input type="text" name="subject" size="30" ' +
      'placeholder="sub_id, as JSON — optional">' +
      '<button>Transmit</button>' +
      '</div></form>' +
      '<form method="post" action="/admin/ssf"><div class="formrow">' +
      '<input type="hidden" name="stream_id" value="' +
      kit.esc(row.stream_id) +
      '">' +
      '<input type="hidden" name="action" value="delete">' +
      '<button class="secondary">Delete this stream</button>' +
      '</div></form>';
  }
}

export = SsfPage;
