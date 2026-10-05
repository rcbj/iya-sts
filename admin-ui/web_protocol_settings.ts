// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_protocol_settings.ts
//
// ---------------------------------------------------------------------------
// THE GENERATED SETTINGS PAGES, DRAWN FROM THEIR VIEWS ALONE (#446,
// 2026-10-05).
//
// Thirteen console pages are rows of `PROTOCOL_SETTINGS_PAGES` in
// `admin-ui/admin.ts` — a lead, warnings, an optional status block, the
// settings forms and a row of links — and one function drew them all. This
// is that function, drawing from what `GET /admin-api/<page>-settings` (and
// `?format=json`) answers: `leadHtml` and `alsoHtml`, which the view carries
// beside their plain text since #446, the settings block and the links.
//
// A STATUS BLOCK (persistence, the cluster, Kerberos pre-authentication and
// the three second-factor mechanisms) is still drawn by the console and
// handed in as `statusHtml`; the page table lists only the pages without
// one until each block is converted.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * Draws one of the generated protocol settings pages from its view.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ProtocolSettingsPage {
  // The page, written once. The settings block is the whole of the second
  // half; everything above it is the row.
  /**
   * Draws a protocol settings page: its prose, its status block when it has
   * one, its settings forms and a row of links.
   *
   * @param view - the page's JSON (`page`, `leadHtml`, `alsoHtml`,
   *   `settings`, `links`)
   * @param ctx - the render context (`WebKit.context()`); unused, taken for
   *   the page table's shape
   * @param statusHtml - optional; the status block, drawn by the console
   * @returns the page body as HTML
   */
  static render(view: Json, ctx?: Json, statusHtml?: string): string {
    return kit.note(view.leadHtml) +
      (view.alsoHtml || []).map(function (text) { return kit.warn(text); })
        .join('') +
      // ABOVE the settings forms, deliberately: what the store is doing right
      // now is what somebody came to this page to find out, and the settings
      // that produced it are the answer to the follow-up question. See the
      // `status` member in protocolSettingsJson().
      (statusHtml || '') +
      SettingsForms.forms(view.settings, view.page) +
      // A `<p class="sub">` AND NOT A `note()`, which is the rule bullet()
      // states for a list item that opens with a link, applied one helper
      // across. A row of links is longer than a line and note() would
      // therefore FOLD it — and the summary of that fold is a truncation of
      // the first two link texts, so the only controls in the row end up
      // behind a summary made of their own words. Every other link row in
      // this console is a `<p class="sub">` for the same reason.
      '<p class="sub">' + (view.links || []).map(function (link) {
        return '<a href="' + kit.esc(link.href) + '">' + kit.esc(link.what) +
               '</a>';
      }).concat(['<a href="' + kit.esc(view.page) +
                 '?format=json">this page as ' +
                                               'JSON</a>',
                 '<a href="/admin/sts-metadata">every endpoint this service ' +
                 'registers</a>']).join(' &middot; ') + '</p>';
  }
}

export = ProtocolSettingsPage;
