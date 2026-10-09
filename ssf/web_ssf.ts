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
    const t = ctx.t;

    const tiles = '<div class="tiles">' +
      kit.tile(json.streamDetail ? json.streamDetail.length : 0,
        t.text('consoleSsf.tile.stream')) +
      kit.tile((json.streamDetail || []).filter(function (row) {
        return row.status === 'enabled';
      }).length,
        t.text('consoleSsf.tile.enabled')) +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + row.counters.delivered;
      }, 0),
        t.text('consoleSsf.tile.delivered')) +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + row.counters.failed;
      }, 0),
        t.text('consoleSsf.tile.refused')) +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + row.queue.length;
      }, 0),
        t.text('consoleSsf.tile.waiting')) +
      kit.tile((json.streamDetail || []).filter(function (row) {
        return row.dead;
      }).length,
        t.text('consoleSsf.tile.deadStreams')) +
      kit.tile((json.streamDetail || []).reduce(function (n, row) {
        return n + (row.deadLetters || []).length;
      }, 0),
        t.text('consoleSsf.tile.deadLetters')) +
      kit.tile((json.receivedDetail || []).length,
        t.text('consoleSsf.tile.received')) +
      '</div>';

    const receivedRows = (json.receivedDetail || []).length
      ? json.receivedDetail.slice(0, 25).map(function (row) {
          return '<tr><td class="sub">' + kit.esc(row.at) + '</td><td>' +
            kit.esc(row.summary ? row.summary.name
              : t.text('consoleSsf.received.unreadable')) +
            '</td>' +
            '<td><code>' + kit.esc(row.summary ? row.summary.jti : '') +
            '</code></td>' +
            '<td class="' + (row.verified ? 'state-valid' : 'sub') + '">' +
            kit.esc(row.verified ? t.text('consoleSsf.received.verified')
              : t.text('consoleSsf.received.notVerified')) +
            '</td>' +
            '<td class="' + (row.correctMediaType ? 'sub' : 'state-invalid') +
            '"><code>' + kit.esc(row.contentType ||
              t.text('consoleSsf.received.none')) +
            '</code></td></tr>';
        }).join('')
      : '<tr><td colspan="5">' + t.html('consoleSsf.received.nothing') +
        '</td></tr>';

    const inner = (!json.installed
        ? '<div class="err">' + t.html('consoleSsf.notLoaded') + '</div>'
        : '') +
      (json.installed && !json.enabled
        ? kit.warn(t.html('consoleSsf.off'))
        : '') +

      kit.note(t.html('consoleSsf.intro')) +

      // Two links in the paragraph: the words around them are messages of
      // their own (#539).
      kit.warn(t.html('consoleSsf.pipe.before') +
      '<a href="/admin/caep">' + t.html('consoleSsf.pipe.ownPage') + '</a>' +
      t.html('consoleSsf.pipe.middle') +
      '<a href="/admin/caep-sessions">' +
      t.html('consoleSsf.pipe.caepSessions') + '</a>' +
      t.html('consoleSsf.pipe.after')) +

      tiles +

      (json.installed
        ? '<h2>' + t.html('consoleSsf.discovery.heading') + '</h2>' +
          kit.note(t.html('consoleSsf.discovery.where', {
            url: json.metadataUrl || '', issuer: json.issuer || '',
            alg: json.signingAlgorithm || '' })) +
          kit.note(t.html('consoleSsf.discovery.algorithm'))
        : '') +

      (json.installed
        ? '<h2>' + t.html('consoleSsf.streams.heading') + '</h2>' +
          ((json.streamDetail || []).length
            ? json.streamDetail.map(function (row) {
              return SsfPage.ssfStreamCard(row, json, t);
            }).join('')
            : kit.note(t.html('consoleSsf.streams.none', {
              endpoint: (json.metadata &&
                         json.metadata.configuration_endpoint) ||
                        '/ssf/stream' })))
        : '') +

      (json.installed
        ? '<h2>' + t.html('consoleSsf.pushed.heading') + '</h2>' +
          kit.note(t.html('consoleSsf.pushed.note')) +
          '<table><tr><th>' + t.html('consoleSsf.th.when') + '</th><th>' +
          t.html('consoleSsf.th.event') + '</th><th>jti</th>' +
          '<th>' + t.html('consoleSsf.th.signature') +
          '</th><th>Content-Type</th></tr>' + receivedRows +
          '</table>' +
          '<form method="post" action="/admin/ssf"><div class="formrow">' +
          '<input type="hidden" name="action" value="clear-received">' +
          '<button class="secondary">' +
          t.html('consoleSsf.pushed.clear') + '</button>' +
          '</div></form>'
        : '') +

      SettingsForms.forms(json.settings, '/admin/ssf', undefined, t) +

      kit.note('<a href="/ssf">' + t.html('consoleSsf.foot.person') +
      '</a> &middot; ' +
      '<a href="/admin/ssf?format=json">' + t.html('consoleSsf.foot.json') +
      '</a> &middot; ' +
      '<a href="/admin-api/ssf">' + t.html('consoleSsf.foot.api') + '</a> ' +
      '&middot; <a href="/admin/applications">' +
      t.html('consoleSsf.foot.receivers') + '</a>');

    return inner;
  }

  /**
   * Draws one Shared Signals stream as a card: its facts, subjects, queue,
   * dead letters, history, and the forms that act on it.
   *
   * @param row - the stream as the SSF reporter describes it
   * @param json - the page's view, whose `statuses` and `eventTypes` are
   *   the two menus
   * @param t - the page's translator (#539)
   * @returns the card as HTML
   */
  static ssfStreamCard(row, json, t) {
    const subjects = row.subjects.length
      ? row.subjects.map(function (one) {
          return '<tr><td>' + kit.esc(one.text) + '</td><td>' +
            (one.verified ? t.html('consoleSsf.card.verified')
              : t.html('consoleSsf.card.unverified')) + '</td><td ' +
              'class="sub">' +
            kit.esc(one.addedAt) + '</td></tr>';
        }).join('')
      : '<tr><td colspan="3">' + t.html('consoleSsf.card.noSubjects') +
        '</td></tr>';
    const queue = row.queue.length
      ? row.queue.map(function (one) {
          return '<tr><td><code>' + kit.esc(one.jti) + '</code></td><td>' +
            kit.esc(one.summary.name) + '</td><td class="sub">' +
            kit.esc(one.queuedAt) + '</td><td class="sub">' +
            kit.esc(one.deliveredAt || t.text('consoleSsf.card.notYet')) +
            '</td></tr>';
        }).join('')
      : '<tr><td colspan="4">' + t.html('consoleSsf.card.nothingWaiting') +
        '</td></tr>';
    const history = row.log.slice(0, 12).map(function (one) {
      return '<tr><td class="sub">' + kit.esc(one.at) + '</td><td>' +
        kit.esc(one.kind) + '</td><td>' + kit.esc(one.text) + '</td></tr>';
    }).join('') || '<tr><td colspan="3">' +
      t.html('consoleSsf.card.nothingRecorded') + '</td></tr>';
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
            '</td><td class="sub">' + (one.signed
              ? t.html('consoleSsf.card.signed')
              : t.html('consoleSsf.card.notSigned')) +
            '</td></tr>';
        }).join('') + (dead.length > 25
          ? '<tr><td colspan="5">' +
            t.html('consoleSsf.card.more', { n: dead.length - 25 }) +
            '</td></tr>' : '')
      : '<tr><td colspan="5">' +
        t.html('consoleSsf.card.nothingUndeliverable') + '</td></tr>';

    // The heading carries an id so Monitoring → Shared Signals → Dead letters
    // can link each stream row straight to this card, where its controls are.
    return '<h3 id="stream-' + kit.esc(row.stream_id) + '"><code>' +
      kit.esc(row.stream_id) + '</code> &mdash; ' +
      kit.esc(row.status) + (row.dead
        ? ' <span class="state-invalid">' + t.html('consoleSsf.card.dead') +
          '</span>' : '') + '</h3>' +
      (row.dead
        ? '<p class="state-invalid">' +
          t.html('consoleSsf.card.declaredDead', {
            since: row.deadSince,
            probe: row.nextProbeAt || t.text('consoleSsf.card.nextSweep') }) +
          // The failure is the view's own words, in English (#539).
          kit.esc(row.deadReason) + '</p>'
        : '') +
      '<table class="key">' +
      '<tr><th>' + t.html('consoleSsf.card.issuer') + '</th><td><code>' +
      kit.esc(row.iss) +
      '</code></td></tr>' +
      '<tr><th>' + t.html('consoleSsf.card.audience') + '</th><td><code>' +
      kit.esc(Array.isArray(row.aud) ? row.aud.join(', ') : row.aud) +
      '</code></td></tr>' +
      '<tr><th>' + t.html('consoleSsf.card.delivery') + '</th><td><code>' +
      kit.esc(row.delivery.method) +
      '</code>' + (row.delivery.endpoint_url
        ? ' &rarr; <code>' + kit.esc(row.delivery.endpoint_url) + '</code>'
        : '') + '</td></tr>' +
      '<tr><th>' + t.html('consoleSsf.card.delivers') + '</th><td>' +
      (row.events_delivered.length
        ? row.events_delivered.map(function (uri) {
            return '<code>' + kit.esc(uri) + '</code>';
          }).join('<br>')
        : t.html('consoleSsf.card.deliversNothing')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleSsf.card.created') +
      '</th><td class="sub">' +
      t.html('consoleSsf.card.createdBy', {
        at: row.createdAt,
        by: row.createdBy || t.text('consoleSsf.card.unauthenticated') }) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleSsf.card.counters') + '</th><td>' +
      t.html('consoleSsf.card.countersText', {
        queued: row.counters.queued, delivered: row.counters.delivered,
        failed: row.counters.failed, acknowledged: row.counters.acknowledged,
        refused: row.counters.receiverErrors }) + '</td></tr>' +
      (row.lastPushError
        ? '<tr><th>' + t.html('consoleSsf.card.lastPush') +
          '</th><td class="state-invalid">' +
          kit.esc(row.lastPushError) + '</td></tr>'
        : '') +
      '</table>' +
      '<h4>' + t.html('consoleSsf.card.subjects') + '</h4>' +
      '<table><tr><th>' + t.html('consoleSsf.th.subject') + '</th><th>' +
      t.html('consoleSsf.th.state') + '</th><th>' +
      t.html('consoleSsf.th.added') + '</th></tr>' +
      subjects + '</table>' +
      '<h4>' + t.html('consoleSsf.card.waiting') + '</h4>' +
      '<table><tr><th>jti</th><th>' + t.html('consoleSsf.th.event') +
      '</th><th>' + t.html('consoleSsf.th.queued') + '</th><th>' +
      t.html('consoleSsf.th.delivered') + '</th>' +
      '</tr>' + queue + '</table>' +
      '<h4>' + t.html('consoleSsf.card.deadLetters') + '</h4>' +
      // The link is markup a message cannot carry (#539).
      kit.note(t.html('consoleSsf.card.deadNote') + ' <a href="' +
                kit.esc('/admin/ssf/dead-letters' +
                kit.queryWith({}, { dlstream: row.stream_id })) +
                '#find-dlq">' + t.html('consoleSsf.card.deadLink') +
                '</a>.') +
      '<table><tr><th>jti</th><th>' + t.html('consoleSsf.th.event') +
      '</th><th>' + t.html('consoleSsf.th.deadSince') + '</th><th>' +
      t.html('consoleSsf.th.why') + '</th>' +
      '<th></th></tr>' + deadRows + '</table>' +
      '<h4>' + t.html('consoleSsf.card.history') + '</h4>' +
      '<table><tr><th>' + t.html('consoleSsf.th.when') + '</th><th>' +
      t.html('consoleSsf.th.what') + '</th><th>' +
      t.html('consoleSsf.th.detail') + '</th></tr>' + history +
      '</table>' +
      (row.dead
        ? '<form method="post" action="/admin/ssf"><div class="formrow">' +
          '<input type="hidden" name="stream_id" value="' +
          kit.esc(row.stream_id) +
          '">' +
          '<input type="hidden" name="action" value="revive">' +
          '<button>' + t.html('consoleSsf.card.revive') + '</button>' +
          '</div></form>'
        : '') +
      (dead.length
        ? '<form method="post" action="/admin/ssf"><div class="formrow">' +
          '<input type="hidden" name="stream_id" value="' +
          kit.esc(row.stream_id) +
          '">' +
          '<input type="hidden" name="action" value="clear-dead-letters">' +
          '<button class="secondary">' + t.html('consoleSsf.card.dropDead') +
          '</button>' +
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
          '<button class="secondary">' + t.html('consoleSsf.card.verify') +
          '</button>' +
          '</div></form>'
        : '') +
      '<form method="post" action="/admin/ssf"><div class="formrow">' +
      '<input type="hidden" name="stream_id" value="' +
      kit.esc(row.stream_id) +
      '"><input type="hidden" name="action" value="status"><label ' +
      'for="status-' + kit.esc(row.stream_id) +
      '">' + t.html('consoleSsf.card.setTheStatus') + '</label>' +
      '<select id="status-' + kit.esc(row.stream_id) + '" name="status">' +
      (json.statuses || []).map(function (one) {
        return '<option value="' + kit.esc(one) + '"' +
          (one === row.status ? ' selected' : '') + '>' + kit.esc(one) +
          '</option>';
      }).join('') + '</select>' +
      '<input type="text" name="reason" size="28" placeholder="' +
      kit.esc(t.text('consoleSsf.card.reasonPlaceholder')) + '">' +
      '<button>' + t.html('consoleSsf.card.setStatus') + '</button>' +
      '</div></form>' +
      '<form method="post" action="/admin/ssf"><div class="formrow">' +
      '<input type="hidden" name="stream_id" value="' +
      kit.esc(row.stream_id) +
      '"><input type="hidden" name="action" value="transmit"><label ' +
      'for="type-' + kit.esc(row.stream_id) +
      '">' + t.html('consoleSsf.card.transmitAnEvent') + '</label>' +
      '<select id="type-' + kit.esc(row.stream_id) + '" name="type">' +
      (json.eventTypes || [])
        .map(function (one) {
          return '<option value="' + kit.esc(one.uri) + '">' +
                 kit.esc(one.name) +
            (one.offered ? '' : t.html('consoleSsf.card.notOffered')) +
            '</option>';
        }).join('') + '</select>' +
      '<input type="text" name="payload" size="30" value="{}" ' +
      'placeholder="' + kit.esc(t.text('consoleSsf.card.payloadPlaceholder')) +
      '">' +
      '<input type="text" name="subject" size="30" ' +
      'placeholder="' + kit.esc(t.text('consoleSsf.card.subjectPlaceholder')) +
      '">' +
      '<button>' + t.html('consoleSsf.card.transmit') + '</button>' +
      '</div></form>' +
      '<form method="post" action="/admin/ssf"><div class="formrow">' +
      '<input type="hidden" name="stream_id" value="' +
      kit.esc(row.stream_id) +
      '">' +
      '<input type="hidden" name="action" value="delete">' +
      '<button class="secondary">' + t.html('consoleSsf.card.delete') +
      '</button>' +
      '</div></form>';
  }
}

export = SsfPage;
