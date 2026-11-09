// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: web_config_dump.ts
// ---------------------------------------------------------------------------
// Server configuration -> Configuration dump, drawn from the answer of
// `GET /admin-api/config-dump`. The Download button saves that same answer
// (`ConsoleRuntime.wireViewDownloads()`), so what is saved is what the server
// masked and the browser holds nothing else to leak.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws Configuration dump. A static utility class.
 */
class ConfigDumpPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of `GET /admin-api/config-dump`
   * @param ctx - the render context
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = (ctx || kit.context()).t;
    const realms = view.realms || [];
    const rows = realms.map(function (one: Json): string {
      return '<tr><td>' + kit.esc(one.id) + '</td><td class="num">' +
             one.settings.length + '</td></tr>';
    }).join('');
    const stamp = String(view.generatedAt).replace(/[:.]/g, '-');
    return kit.note(t.html('consoleConfigDump.about')) +
      kit.note(t.html('consoleConfigDump.summary', {
        total: view.settingCount,
        masked: view.masking.maskedValues,
        realms: realms.length })) +
      '<p><button type="button" class="secondary" data-download-view="' +
      kit.esc('iya-sts-config-' + view.realm + '-' + stamp + '.json') + '">' +
      t.html('consoleConfigDump.download') + '</button></p>' +
      (realms.length
        ? '<table><thead><tr><th>' + t.html('consoleConfigDump.thRealm') +
          '</th><th>' + t.html('consoleConfigDump.thOwn') +
          '</th></tr></thead><tbody>' + rows + '</tbody></table>'
        : '');
  }
}

export = ConfigDumpPage;
