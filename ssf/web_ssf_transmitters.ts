// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_ssf_transmitters.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS → SHARED SIGNALS TRANSMITTERS, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws the Shared Signals transmitters page from the answer of `GET
// /admin-api/ssf/transmitters`: a card per federation relationship that sends
// Shared Signals, the blocks and locks partners put on people here, and the
// table of what arrived.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `SsfTransmittersAdmin`'s in
// `ssf/ssf_transmitters_admin.ts`, moved with their comments; that module
// still draws the page until the console's cutover, by calling `render()` with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * The console page's path, `/admin/ssf/transmitters`.
 */
const PAGE = '/admin/ssf/transmitters';

/**
 * Draws the Shared Signals transmitters page from the answer of `GET
 * /admin-api/ssf/transmitters`: a card per federation relationship that sends
 * Shared Signals, the blocks and locks partners put on people here, and the
 * table of what arrived.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class SsfTransmittersPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - optional; the render context, whose `t` is the page's
   *   translator (#539). `ssf_transmitters_admin.ts` passes none and gets
   *   the default, English in node.
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return SsfTransmittersPage.body(view, ctx);
  }

  /**
   * Draws the page's body from the report: a card per relationship, the
   * blocks and locks partners put on people here, and the table of what
   * arrived.
   *
   * @param json - `ssf_transmitters.ts`'s report
   * @param ctx - optional; the render context (#539)
   * @returns the HTML
   */
  static body(json: Json, ctx?: Json): string {
    const t = (ctx || kit.context()).t;
    const link = function (id: string): string {
      return '<a href="/admin/federation?relationship=' +
        encodeURIComponent(id) + '#signals"><code>' + esc(id) +
        '</code></a>';
    };
    // The card's relationship is `rel`, not `t` as it was: `t` is the
    // translator (#539).
    const cards = json.relationships.length
      ? json.relationships.map(function (rel: Json): string {
        return '<div class="card" id="relationship-' + esc(rel.relationship) +
          '"><h3>' + link(rel.relationship) + ' <span class="sub">' +
          esc(rel.kind) + ', ' + esc(rel.receiving ? rel.state
            : t.text('consoleSsfTransmitters.notReceiving')) +
          '</span></h3><p>' +
          t.html('consoleSsfTransmitters.card.issuer', {
            issuer: rel.issuer,
            delivery: rel.streamDelivery || rel.delivery,
            hasStream: rel.streamId ? 'yes' : 'no',
            stream: rel.streamId,
            aud: (rel.streamAud || []).join(' ') }) + '</p><p class="sub">' +
          t.html('consoleSsfTransmitters.card.counts', {
            received: rel.counts.received || 0,
            verified: rel.counts.verified || 0,
            refused: rel.counts.refused || 0,
            acted: rel.counts.acted || 0 }) +
          (rel.lastPollAt
            ? t.html('consoleSsfTransmitters.card.lastPoll',
                     { at: rel.lastPollAt, result: rel.lastPollResult })
            : '') +
          (rel.verifiedAt
            ? t.html('consoleSsfTransmitters.card.verifiedAt',
                     { at: rel.verifiedAt })
            : '') +
          (rel.ready ? '' : '<br>' +
            t.html('consoleSsfTransmitters.card.stillToSet',
                   { missing: rel.missing.join(', ') })) +
          (rel.lastError ? '<br><strong>' + esc(rel.lastError) + '</strong>'
                         : '') + '</p></div>';
      }).join('')
      // The link is markup a message cannot carry, so the sentence is
      // drawn around it in two halves (#539).
      : '<p class="sub" id="relationships-none">' +
        t.html('consoleSsfTransmitters.none.before') + '<a ' +
        'href="/admin/federation">' +
        t.html('consoleSsfTransmitters.none.federation') + '</a>' +
        t.html('consoleSsfTransmitters.none.after') + '</p>';
    const blocks = json.blocks.length
      ? '<h3>' + t.html('consoleSsfTransmitters.blocks.heading') +
        '</h3><table><thead><tr><th>' +
        t.html('consoleSsfTransmitters.th.person') + '</th><th>' +
        t.html('consoleSsfTransmitters.th.relationship') + '</th><th>' +
        t.html('consoleSsfTransmitters.th.since') + '</th><th>' +
        t.html('consoleSsfTransmitters.th.event') + '</th></tr>' +
        '</thead><tbody>' + json.blocks.map(function (b: Json): string {
          return '<tr><td>' + esc(b.username) + '</td><td>' +
            link(b.relationship) + '</td><td>' + esc(b.at) + '</td><td>' +
            '<code>' + esc(b.event) + '</code></td></tr>';
        }).join('') + '</tbody></table>'
      : '';
    const locks = json.locks.length
      ? '<h3>' + t.html('consoleSsfTransmitters.locks.heading') +
        '</h3><table><thead><tr><th>' +
        t.html('consoleSsfTransmitters.th.person') + '</th><th>' +
        t.html('consoleSsfTransmitters.th.relationship') + '</th><th>' +
        t.html('consoleSsfTransmitters.th.since') +
        '</th></tr></thead><tbody>' +
        json.locks.map(function (l: Json): string {
          return '<tr><td>' + esc(l.username) + '</td><td>' +
            link(l.relationship) + '</td><td>' + esc(l.at) + '</td></tr>';
        }).join('') + '</tbody></table>'
      : '';
    const received = json.received.length ? json.received.map(function (r:
                                                                       Json) {
      return '<tr><td>' + link(r.relationship) + '</td><td>' +
        esc(r.receivedAt) + ' <span class="sub">' + esc(r.via) + '</span>' +
        '</td><td>' + (r.events || []).map(function (e: string) {
          return '<code>' + esc(String(e).replace(/^.*\//, '')) + '</code>';
        }).join(' ') + '</td><td>' + (r.verified
          ? t.html('consoleSsfTransmitters.verified')
          // A refusal is drawn as the view gives it, in English (#539).
          : '<strong>' + esc(r.refusal || 'unverified') + '</strong>') +
        (r.why ? '<br><span class="sub">' + esc(r.why) + '</span>' : '') +
        '</td><td>' + esc(r.person || '—') + (r.mapping
          ? '<br><span class="sub">' + esc(r.mapping) + '</span>' : '') +
        '</td><td>' + (r.reactions || []).map(function (x: Json) {
          return esc(x.reaction || '—') + (x.done ? ' ✓' : '') +
            (x.observed
              ? t.html('consoleSsfTransmitters.reaction.observed') : '') +
            // #432: how much a signal-revoke-grants revoked, and a reaction
            // the operator's switch skipped.
            (x.revoked !== undefined
              ? t.html('consoleSsfTransmitters.reaction.revoked',
                       { n: String(x.revoked) }) : '') +
            (x.skipped ? ' <span class="sub">' +
              t.html('consoleSsfTransmitters.reaction.skipped',
                     { why: x.skipped }) + '</span>' : '') +
            (x.why ? ' <span class="sub">' + esc(x.why) + '</span>' : '');
        }).join('<br>') + '</td></tr>';
    }).join('') : '<tr><td colspan="6" class="sub">' +
      t.html('consoleSsfTransmitters.nothingArrived') + '</td></tr>';
    return kit.note(t.html('consoleSsfTransmitters.note') +
        (json.observeOnly
          ? ' ' + t.html('consoleSsfTransmitters.note.observeOnly')
          : '')) + cards + blocks + locks +
      '<h3>' + t.html('consoleSsfTransmitters.arrived.heading') +
      '</h3><table><thead><tr><th>' +
      t.html('consoleSsfTransmitters.th.relationship') + '</th><th>' +
      t.html('consoleSsfTransmitters.th.when') + '</th><th>' +
      t.html('consoleSsfTransmitters.th.events') + '</th><th>' +
      t.html('consoleSsfTransmitters.th.verified') + '</th><th>' +
      t.html('consoleSsfTransmitters.th.person') + '</th><th>' +
      t.html('consoleSsfTransmitters.th.reactions') +
      '</th></tr></thead><tbody>' + received + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/ssf/transmitters</code></p>';
  }
}

export = SsfTransmittersPage;
