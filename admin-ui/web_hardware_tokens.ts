// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_hardware_tokens.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → HARDWARE TOKENS (#1955 P1), drawn in the browser from `GET
// /admin-api/hardware-tokens` (`mgmt-api/hardware_tokens_api.ts`): the
// realm's physical security keys and smart cards, each recorded from its own
// attestation (`common/hardware_tokens.ts`), paged and searched by serial or
// person, with a "Report lost" button on each active one, which posts
// `lost` to `/admin/hardware-tokens` and so reaches `POST
// /admin-api/hardware-tokens/lost` (rule 7).
//
// IN DIRECTORY because its store is somebody's and it is a destination
// (`admin-ui/CLAUDE.md`, the filing rule): the device register's sibling,
// beside it. One tab, the list, framed as every Directory tab is; the lead
// is the Metadata.
//
// A static utility class, on `web_kit.ts`'s terms: it holds no state, logs
// nothing, and is bundled for a browser.
// ---------------------------------------------------------------------------
import WebKit = require('./web_kit');

type Json = any;

const PAGE = '/admin/hardware-tokens';

/**
 * Draws Directory → Hardware tokens from its view.
 */
class HardwareTokensPage {
  /**
   * One token's credentials, a line each.
   *
   * @param t - the translator
   * @param r - the token
   * @returns the HTML
   */
  static credentialsCell(t: Json, r: Json): string {
    const esc = WebKit.esc;
    const list: Json[] = r.credentials || [];
    return list.length ? list.map(function (c: Json): string {
      return '<code>' + esc(c.kind) + '</code> ' +
        esc(c.label || String(c.ref).slice(0, 24)) +
        (c.holder && c.holder !== r.holder
          ? ' <small>(' + esc(c.holder) + ')</small>' : '') +
        (c.smartCard ? ' <small>' +
          t.html('consoleHardwareTokens.smartCard') + '</small>' : '') +
        (c.retired ? ' <strong>' + t.html('consoleHardwareTokens.retired') +
          '</strong>' : '');
    }).join('<br>') : '—';
  }

  /**
   * Draws the page's body.
   *
   * @param view - `GET /admin-api/hardware-tokens`'s answer
   * @param ctx - the render context: the translator, the page's query and
   *   whether the reader may write
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const c = ctx || WebKit.context();
    const t = c.t;
    const v = view || {};
    const esc = WebKit.esc;
    const self = HardwareTokensPage;
    const params: Json = {};
    if (v.q) {
      params.q = v.q;
    }
    if (v.status) {
      params.status = v.status;
    }
    const nav = WebKit.pageNavPair(PAGE, params, v.paging, t);
    const filters = '<form method="get" action="' + PAGE + '">' +
      '<div class="formrow"><label for="hwt-q">' +
      t.html('consoleHardwareTokens.search') + '</label>' +
      '<input type="text" id="hwt-q" name="q" size="24" maxlength="256" ' +
      'value="' + esc(v.q || '') + '"><label for="hwt-status">' +
      t.html('consoleHardwareTokens.status') + '</label>' +
      '<select id="hwt-status" name="status">' +
      ['', 'active', 'lost'].map(function (s: string): string {
        return '<option value="' + s + '"' + (s === (v.status || '')
          ? ' selected' : '') + '>' + (s === 'active'
            ? t.html('consoleHardwareTokens.active')
            : (s === 'lost' ? t.html('consoleHardwareTokens.lost')
                            : t.html('consoleHardwareTokens.any'))) +
          '</option>';
      }).join('') + '</select><button type="submit">' +
      t.html('consoleHardwareTokens.filter') + '</button></div></form>';
    const tokens: Json[] = v.tokens || [];
    const rows = tokens.map(function (r: Json): string {
      const lost = r.status === 'lost';
      return '<tr><td>' + esc(r.model || r.vendor) + '<br><small><code>' +
        esc(r.key) + '</code></small></td><td>' + esc(r.holder || '—') +
        '</td><td>' + esc((r.evidenceSources || []).join(', ')) +
        '</td><td>' + self.credentialsCell(t, r) + '</td><td>' +
        (lost ? t.html('consoleHardwareTokens.lostOn', { at: r.lostAt,
                                                         by: r.lostBy })
              : t.html('consoleHardwareTokens.active')) + '</td><td>' +
        (lost || !c.write ? '' : '<form method="post" action="' + PAGE +
          '" class="inline"><input type="hidden" name="action" ' +
          'value="lost"><input type="hidden" name="key" value="' +
          esc(r.key) + '"><button class="danger" type="submit">' +
          t.html('consoleHardwareTokens.reportLost') + '</button></form>') +
        '</td></tr>';
    }).join('');
    const table = tokens.length
      ? '<table class="grid"><thead><tr><th>' +
        t.html('consoleHardwareTokens.thToken') + '</th><th>' +
        t.html('consoleHardwareTokens.thHolder') + '</th><th>' +
        t.html('consoleHardwareTokens.thEvidence') + '</th><th>' +
        t.html('consoleHardwareTokens.thCredentials') + '</th><th>' +
        t.html('consoleHardwareTokens.thStatus') + '</th><th></th></tr>' +
        '</thead><tbody>' + rows + '</tbody></table>'
      : WebKit.note(t.html('consoleHardwareTokens.none'));
    return WebKit.note(t.html('consoleHardwareTokens.lead'),
                       t.text('consoleHardwareTokens.whatThisIs')) +
      '<h2 data-tab="tokens">' + t.html('console.nav.hardware-tokens') +
      '</h2>' +
      WebKit.frame(filters + (v.capped
        ? WebKit.note(t.html('consoleHardwareTokens.capped')) : '') +
        nav.head + table + nav.foot +
        WebKit.note(t.html('consoleHardwareTokens.lostWhat')));
  }
}

export = HardwareTokensPage;
