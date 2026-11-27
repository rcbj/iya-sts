// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: admin-ui/web_csp_reports.ts
// ---------------------------------------------------------------------------
// Draws Monitoring > CSP reports (#2164) from its management API answer: the
// Content Security Policy violations browsers reported for this realm's
// pages, counted by directive (`common/csp_reports.ts`), and the forward's
// setting.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

const PAGE = '/admin/csp-reports';

/**
 * Draws CSP reports. A static utility class; it holds no state.
 */
class CspReportsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of `GET /admin-api/csp-reports`
   * @param ctx - the render context; the server's own drawing passes none
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    const context = ctx || kit.context();
    const t = context.t;
    const rows: Json[] = Array.isArray(view.directives) ? view.directives : [];
    const table = rows.length
      ? '<table class="grid"><thead><tr><th>' +
        t.html('consoleCspReports.colDirective') + '</th><th>' +
        t.html('consoleCspReports.colCount') + '</th><th>' +
        t.html('consoleCspReports.colLast') + '</th></tr></thead><tbody>' +
        rows.map(function (row: Json): string {
          return '<tr><td><code>' + kit.esc(row.directive) + '</code></td>' +
            '<td>' + kit.esc(row.count) + '</td><td>' +
            kit.esc(kit.whenText(Date.parse(row.lastAt))) + '</td></tr>';
        }).join('') + '</tbody></table>'
      : '<p>' + t.html('consoleCspReports.none') + '</p>';
    return kit.note('<p>' + t.html('consoleCspReports.intro') + '</p>') +
      '<div class="tiles">' +
      kit.tile(view.total, t.text('consoleCspReports.tileTotal')) +
      kit.tile(rows.length, t.text('consoleCspReports.tileDirectives')) +
      '</div>' +
      '<p>' + t.html('consoleCspReports.since', {
        since: kit.whenText(Date.parse(view.since)) }) + '</p>' +
      kit.frame(table) +
      kit.note('<p>' + t.html('consoleCspReports.limits', {
        path: String(view.path || ''),
        bytes: String(view.maxBodyBytes),
        perMinute: String(view.perAddressPerMinute) }) + '</p>') +
      '<p>' + t.html(view.forwarding ? 'consoleCspReports.forwardOn'
                                     : 'consoleCspReports.forwardOff') +
      (view.notForwarded ? ' ' + t.html('consoleCspReports.notForwarded', {
        count: String(view.notForwarded) }) : '') + '</p>' +
      SettingsForms.forms(view.settings, PAGE, ['CSP reports'], t);
  }
}

export = CspReportsPage;
