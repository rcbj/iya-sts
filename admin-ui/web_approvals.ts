// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_approvals.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → PENDING APPROVALS (#2166), DRAWN FROM ITS VIEW ALONE.
//
// Draws `/admin/approvals` from the answer of `GET /admin-api/approvals`:
// whether two-person approval is on and in force, every administrator act
// held for a second administrator with its Approve, Refuse and Withdraw
// buttons, and the table of acts the control holds. The buttons post to
// `/admin/approvals`, which `POST /admin-api/approvals/{action}` mirrors.
// Approve and Refuse are drawn for a held act somebody else asked for, and
// Withdraw for one the reader asked for; the server decides either way.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

const PAGE = '/admin/approvals';

/**
 * Draws Pending approvals from the answer of `GET /admin-api/approvals`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ApprovalsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of `GET /admin-api/approvals`
   * @param ctx - the render context (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const esc = kit.esc.bind(kit);
    const state = view.state || {};
    const you = String(view.you || '').toLowerCase();
    const pending = (view.requests || []).filter(function (one: Json) {
      return one.status === 'pending';
    });
    const tiles = '<div class="tiles">' +
      kit.tile(state.on ? t.text('consoleApprovals.on')
                        : t.text('consoleApprovals.off'),
               t.text('consoleApprovals.tileSetting')) +
      kit.tile(state.inForce ? t.text('consoleApprovals.yes')
                             : t.text('consoleApprovals.no'),
               t.text('consoleApprovals.tileInForce')) +
      kit.tile(String(pending.length), t.text('consoleApprovals.tilePending')) +
      '</div>';
    const about = kit.note('<p>' + t.html('consoleApprovals.about1') +
      '</p><p>' + t.html('consoleApprovals.about2') + '</p><p>' +
      esc(state.why || '') + '</p>', t.text('consoleApprovals.aboutLabel'));
    const button = function (row: Json, action: string, label: string,
                             withReason: boolean): string {
      return '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="' + action + '">' +
        '<input type="hidden" name="id" value="' + esc(row.id) + '">' +
        (withReason ? '<input type="text" name="reason" size="18" ' +
          'placeholder="' + esc(t.text('consoleApprovals.reason')) + '"> '
          : '') +
        '<button type="submit">' + label + '</button></form>';
    };
    const bodyOf = function (row: Json): string {
      const keys = Object.keys(row.body || {});
      return keys.length ? '<small>' + keys.map(function (key: string) {
        const value = row.body[key];
        return '<code>' + esc(key) + '</code>=' + esc(
          typeof value === 'string' ? value : JSON.stringify(value));
      }).join('<br>') + '</small>' : '';
    };
    const rows = (view.requests || []).map(function (row: Json): string {
      const mine = String(row.requester || '').toLowerCase() === you;
      let controls = '';
      if (row.status === 'pending' && ctx.write) {
        controls = mine
          ? button(row, 'withdraw', t.html('consoleApprovals.withdraw'),
                   false)
          : button(row, 'approve', t.html('consoleApprovals.approve'),
                   false) + ' ' +
            button(row, 'refuse', t.html('consoleApprovals.refuse'), true);
      }
      return '<tr id="approval-' + esc(row.id) + '"><td><strong>' +
        esc(row.what) + '</strong><br><small><code>' +
        esc(row.operationId) + '</code> · <code>' + esc(row.id) +
        '</code></small><br>' + bodyOf(row) + '</td><td>' +
        esc(row.requester) + '<br><small>' + esc(row.authority) +
        '</small></td><td><small>' + esc(row.createdAt) + '<br>' +
        esc(row.expiresAt) + '</small></td><td><strong>' +
        esc(row.status) + '</strong>' + (row.decidedBy
          ? '<br><small>' + t.html('consoleApprovals.by',
                                   { who: row.decidedBy }) + '</small>'
          : '') + (row.reason ? '<br><small>' + esc(row.reason) +
                   '</small>' : '') + '</td><td>' + controls + '</td></tr>';
    }).join('');
    const held = '<h2 data-tab="held">' +
      t.html('consoleApprovals.heldHeading') + '</h2>' +
      kit.frame('<table class="grid"><thead><tr><th>' +
      t.html('consoleApprovals.thAct') + '</th><th>' +
      t.html('consoleApprovals.thRequester') + '</th><th>' +
      t.html('consoleApprovals.thWhen') + '</th><th>' +
      t.html('consoleApprovals.thStatus') + '</th><th></th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="5">' +
      t.html('consoleApprovals.empty') + '</td></tr>') + '</tbody></table>');
    const table = '<h2 data-tab="table">' +
      t.html('consoleApprovals.tableHeading') + '</h2>' +
      kit.frame('<p>' + t.html('consoleApprovals.tableLead') + '</p>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleApprovals.thOperation') + '</th><th>' +
      t.html('consoleApprovals.thWhat') + '</th><th>' +
      t.html('consoleApprovals.thConditional') + '</th></tr></thead><tbody>' +
      (view.table || []).map(function (row: Json): string {
        return '<tr><td><code>' + esc(row.operationId) + '</code></td><td>' +
          esc(row.what) + '</td><td>' + (row.conditional
            ? t.html('consoleApprovals.someBodies')
            : t.html('consoleApprovals.always')) + '</td></tr>';
      }).join('') + '</tbody></table>');
    return tiles + about + held + table;
  }
}

export = ApprovalsPage;
