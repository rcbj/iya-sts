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
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return SsfTransmittersPage.body(view);
  }

  /**
   * Draws the page's body from the report: a card per relationship, the
   * blocks and locks partners put on people here, and the table of what
   * arrived.
   *
   * @param json - `ssf_transmitters.ts`'s report
   * @returns the HTML
   */
  static body(json: Json): string {
    const link = function (id: string): string {
      return '<a href="/admin/federation?relationship=' +
        encodeURIComponent(id) + '#signals"><code>' + esc(id) +
        '</code></a>';
    };
    const cards = json.relationships.length
      ? json.relationships.map(function (t: Json): string {
        return '<div class="card" id="relationship-' + esc(t.relationship) +
          '"><h3>' + link(t.relationship) + ' <span class="sub">' +
          esc(t.kind) + ', ' + esc(t.receiving ? t.state : 'not receiving') +
          '</span></h3><p>Issuer <code>' + esc(t.issuer) + '</code>, ' +
          'delivery <strong>' + esc(t.streamDelivery || t.delivery) +
          '</strong>' + (t.streamId ? ', stream <code>' + esc(t.streamId) +
            '</code> (aud <code>' + esc((t.streamAud || []).join(' ')) +
            '</code>)' : ', no stream yet') + '.</p><p class="sub">' +
          esc(t.counts.received || 0) + ' received, ' +
          esc(t.counts.verified || 0) + ' verified, ' +
          esc(t.counts.refused || 0) + ' refused, ' +
          esc(t.counts.acted || 0) + ' reaction(s)' +
          (t.lastPollAt ? '; last poll ' + esc(t.lastPollAt) + ': ' +
            esc(t.lastPollResult) : '') +
          (t.verifiedAt ? '; verified ' + esc(t.verifiedAt) : '') +
          (t.ready ? '' : '<br>Still to set: ' + esc(t.missing.join(', '))) +
          (t.lastError ? '<br><strong>' + esc(t.lastError) + '</strong>'
                       : '') + '</p></div>';
      }).join('')
      : '<p class="sub" id="relationships-none">No federation relationship ' +
        'in this realm receives its partner\'s Shared Signals. Turn ' +
        '<code>fedSignalsEnabled</code> on for one on <a ' +
        'href="/admin/federation">Federation</a>, or create an ' +
        '<code>ssf</code> relationship for a partner that signs nobody in.' +
        '</p>';
    const blocks = json.blocks.length
      ? '<h3>Sign-ins partners have blocked</h3><table><thead><tr><th>' +
        'Person</th><th>Relationship</th><th>Since</th><th>Event</th></tr>' +
        '</thead><tbody>' + json.blocks.map(function (b: Json): string {
          return '<tr><td>' + esc(b.username) + '</td><td>' +
            link(b.relationship) + '</td><td>' + esc(b.at) + '</td><td>' +
            '<code>' + esc(b.event) + '</code></td></tr>';
        }).join('') + '</tbody></table>'
      : '';
    const locks = json.locks.length
      ? '<h3>Accounts a partner disabled</h3><table><thead><tr><th>Person' +
        '</th><th>Relationship</th><th>Since</th></tr></thead><tbody>' +
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
        }).join(' ') + '</td><td>' + (r.verified ? 'verified'
          : '<strong>' + esc(r.refusal || 'unverified') + '</strong>') +
        (r.why ? '<br><span class="sub">' + esc(r.why) + '</span>' : '') +
        '</td><td>' + esc(r.person || '—') + (r.mapping
          ? '<br><span class="sub">' + esc(r.mapping) + '</span>' : '') +
        '</td><td>' + (r.reactions || []).map(function (x: Json) {
          return esc(x.reaction || '—') + (x.done ? ' ✓' : '') +
            (x.observed ? ' (observed only)' : '') +
            // #432: how much a signal-revoke-grants revoked, and a reaction
            // the operator's switch skipped.
            (x.revoked !== undefined ? ' — ' + esc(String(x.revoked)) +
              ' revoked' : '') +
            (x.skipped ? ' <span class="sub">skipped: ' + esc(x.skipped) +
              '</span>' : '') +
            (x.why ? ' <span class="sub">' + esc(x.why) + '</span>' : '');
        }).join('<br>') + '</td></tr>';
    }).join('') : '<tr><td colspan="6" class="sub">Nothing has arrived.' +
      '</td></tr>';
    return kit.note('<strong>Shared Signals from federation ' +
        'partners.</strong> A partner\'s CAEP and RISC events about the ' +
        'people it signs in — or, from an <code>ssf</code> relationship, ' +
        'about the people and devices it manages — are acted on only when ' +
        'they verified against the keys its SSF configuration names, name ' +
        'this stream\'s audience and a person the relationship links, and ' +
        'then only as the <code>signal-response</code> policy permits. Each ' +
        'stream is configured and acted on from its relationship\'s page.' +
        (json.observeOnly
          ? ' <strong>This realm only records what it would do</strong> ' +
            '(development; <code>ssf.actOnSignalsInDevelopment</code>).'
          : '')) + cards + blocks + locks +
      '<h3>What arrived</h3><table><thead><tr><th>Relationship</th><th>When' +
      '</th><th>Events</th><th>Verified</th><th>Person</th><th>Reactions' +
      '</th></tr></thead><tbody>' + received + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/ssf/transmitters</code></p>';
  }
}

export = SsfTransmittersPage;
