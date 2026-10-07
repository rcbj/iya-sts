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
    const tiles = '<div class="tiles">' +
      kit.tile(String(json.allocated), 'credentials with an index') +
      kit.tile(String(json.valid), 'valid') +
      kit.tile(String(json.suspended), 'suspended') +
      kit.tile(String(json.invalid), 'revoked') +
      kit.tile(String(json.size), 'indexes per list') +
      '</div>';
    const where = '<table class="grid"><tbody>' +
      '<tr><th>Token Status List</th><td><a href="' +
      kit.esc(json.tokenStatusList) + '"><code>' +
      kit.esc(json.tokenStatusList) + '</code></a><br><small>' +
      'application/statuslist+jwt, or application/statuslist+cwt by ' +
      'Accept; ' + json.bits + ' bits per credential</small></td></tr>' +
      '<tr><th>Aggregation</th><td><code>' + kit.esc(json.aggregation) +
      '</code></td></tr>' +
      '<tr><th>Bitstring Status Lists</th><td>' +
      json.bitstring.map(function (u: string): string {
        return '<code>' + kit.esc(u) + '</code>';
      }).join('<br>') + '<br><small>application/vc+jwt</small></td></tr>' +
      '<tr><th>Time to live</th><td>' + json.ttlS + ' s (<code>' +
      'oid4vci.statusListTtlS</code>); valid for ' + json.lifetimeS +
      ' s (<code>oid4vci.statusListLifetimeS</code>)</td></tr>' +
      '</tbody></table>';
    const about = kit.note(
      '<p>Every credential this realm issues carries its index here: a ' +
      'dc+sd-jwt and a jwt_vc_json in the Token Status List ' +
      '(draft-ietf-oauth-status-list), a jwt_vc_json and an ldp_vc in the ' +
      'two Bitstring Status Lists (W3C). One index, the same in every list. ' +
      'A verifier fetches the list and reads the bit; this service\'s own ' +
      'Verifier reads it directly.</p><p>A credential is shown ' +
      '<strong>INVALID</strong> when it was revoked here, when an ' +
      'administrator revoked it on <a href="/admin/tokens">Tokens</a>, or ' +
      'when a global sign-out disowned it. INVALID is final. ' +
      '<strong>SUSPENDED</strong> can be reinstated. Either stops the ' +
      'credential signing anybody in at <code>/authn/wallet</code>.</p>',
      'What this page is');
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
        (r.status === 'SUSPENDED' ? form('reinstate', 'Reinstate')
                                  : form('suspend', 'Suspend')) +
        form('revoke', 'Revoke');
      return '<tr><td class="num">' + r.idx + '</td><td>' +
        kit.esc(r.format) + '<br><small>' + kit.esc(r.configId) +
        '</small></td><td><strong>' + kit.esc(r.status) + '</strong>' +
        (r.status !== r.explicit ? '<br><small>set here: ' +
         kit.esc(r.explicit) + '</small>' : '') + '</td><td>' +
        (r.via ? kit.esc(r.via) + '<br><small>' +
         kit.esc(new Date(r.changedAt).toISOString()) + '</small>' : '—') +
        '</td><td><small>' +
        kit.esc(new Date(r.expiresAt).toISOString()) + '</small></td><td>' +
        controls + '</td></tr>';
    }).join('');
    return tiles + about + where + '<h3>Credentials</h3>' + nav.head +
      '<table class="grid"><thead><tr><th>Index</th><th>Format</th>' +
      '<th>Status</th><th>Changed by</th><th>Expires</th><th></th></tr>' +
      '</thead><tbody>' +
      (rows || '<tr><td colspan="6">No credential issued here carries a ' +
       'status yet.</td></tr>') + '</tbody></table>' + nav.foot;
  }
}

export = VcStatusPage;
