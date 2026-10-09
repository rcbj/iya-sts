// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_vc_status.ts
//
// ---------------------------------------------------------------------------
// MONITORING → CREDENTIAL STATUS, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws Credential status from the answer of `GET /admin-api/vc-status`: where
// this realm's status lists are published, and every credential that carries
// an index in them, with the controls that suspend, reinstate and revoke one.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `VcStatusAdmin`'s in `admin-ui/vc_status_admin.ts`, moved
// with their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * The console path of Verifiable Credentials → Credential status.
 */
const PAGE = '/admin/vc-status';

/**
 * Draws Credential status from the answer of `GET /admin-api/vc-status`: where
 * this realm's status lists are published, and every credential that carries
 * an index in them, with the controls that suspend, reinstate and revoke one.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class VcStatusPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return VcStatusPage.html(ctx, view);
  }

  static html(ctx: Json, json: Json): string {
    const canWrite = ctx.write;
    const t = ctx.t;
    const tiles = '<div class="tiles">' +
      kit.tile(String(json.allocated), t.text('consoleVcStatus.tileIndexed')) +
      kit.tile(String(json.valid), t.text('consoleVcStatus.tileValid')) +
      kit.tile(String(json.suspended),
               t.text('consoleVcStatus.tileSuspended')) +
      kit.tile(String(json.invalid), t.text('consoleVcStatus.tileRevoked')) +
      kit.tile(String(json.size), t.text('consoleVcStatus.tilePerList')) +
      '</div>';
    const where = '<table class="grid"><tbody>' +
      '<tr><th>Token Status List</th><td><a href="' +
      kit.esc(json.tokenStatusList) + '"><code>' +
      kit.esc(json.tokenStatusList) + '</code></a><br><small>' +
      t.html('consoleVcStatus.tokenListFormats', { bits: String(json.bits) }) +
      '</small></td></tr>' +
      '<tr><th>' + t.html('consoleVcStatus.thAggregation') +
      '</th><td><code>' + kit.esc(json.aggregation) +
      '</code></td></tr>' +
      '<tr><th>Bitstring Status Lists</th><td>' +
      json.bitstring.map(function (u: string): string {
        return '<code>' + kit.esc(u) + '</code>';
      }).join('<br>') + '<br><small>application/vc+jwt</small></td></tr>' +
      '<tr><th>' + t.html('consoleVcStatus.thTtl') + '</th><td>' +
      t.html('consoleVcStatus.ttl', { ttl: String(json.ttlS),
                                       lifetime: String(json.lifetimeS) }) +
      '</td></tr>' +
      '</tbody></table>';
    // The Tokens link is markup a message cannot carry (#539), so the
    // sentence is split around it.
    const about = kit.note(
      '<p>' + t.html('consoleVcStatus.about1') + '</p><p>' +
      t.html('consoleVcStatus.about2') + '<a href="/admin/tokens">' +
      t.html('consoleVcStatus.aboutTokensLink') + '</a>' +
      t.html('consoleVcStatus.about3') + '</p>',
      t.text('consoleVcStatus.aboutLabel'));
    const nav = kit.pageNavPair(PAGE, {}, json.rowsPaging);
    const rows = json.rows.map(function (r: Json): string {
      const form = function (action: string, label: string): string {
        return '<form method="post" action="' + PAGE + '" class="inline">' +
          '<input type="hidden" name="idx" value="' + r.idx + '">' +
          '<input type="hidden" name="action" value="' + action + '">' +
          '<button type="submit" id="vc-status-' + action + '-' + r.idx +
          '">' + label + '</button></form>';
      };
      const controls = !canWrite || r.status === 'INVALID' ? '' :
        (r.status === 'SUSPENDED'
          ? form('reinstate', t.html('consoleVcStatus.reinstate'))
          : form('suspend', t.html('consoleVcStatus.suspend'))) +
        form('revoke', t.html('consoleVcStatus.revoke'));
      return '<tr><td class="num">' + r.idx + '</td><td>' +
        kit.esc(r.format) + '<br><small>' + kit.esc(r.configId) +
        '</small></td><td><strong>' + kit.esc(r.status) + '</strong>' +
        (r.status !== r.explicit ? '<br><small>' +
         // The value stays out of the message: `kit.esc()` writes `&apos;`
         // where a message parameter would write `&#39;` (#539).
         t.html('consoleVcStatus.setHere') + kit.esc(r.explicit) +
         '</small>' : '') + '</td><td>' +
        (r.via ? kit.esc(r.via) + '<br><small>' +
         kit.esc(new Date(r.changedAt).toISOString()) + '</small>' : '—') +
        '</td><td><small>' +
        kit.esc(new Date(r.expiresAt).toISOString()) + '</small></td><td>' +
        controls + '</td></tr>';
    }).join('');
    return tiles + about + where + '<h3>' +
      t.html('consoleVcStatus.credentialsHeading') + '</h3>' + nav.head +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleVcStatus.thIndex') + '</th><th>' +
      t.html('consoleVcStatus.thFormat') + '</th>' +
      '<th>' + t.html('consoleVcStatus.thStatus') + '</th><th>' +
      t.html('consoleVcStatus.thChangedBy') + '</th><th>' +
      t.html('consoleVcStatus.thExpires') + '</th><th></th></tr>' +
      '</thead><tbody>' +
      (rows || '<tr><td colspan="6">' + t.html('consoleVcStatus.none') +
       '</td></tr>') + '</tbody></table>' + nav.foot;
  }
}

export = VcStatusPage;
