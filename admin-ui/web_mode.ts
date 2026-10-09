// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_mode.ts
//
// ---------------------------------------------------------------------------
// SERVER CONFIGURATION → MODE, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// The first console page converted for the static console: the body of
// `/admin/mode`, as a function of the JSON `GET /admin-api/mode` answers and
// of nothing else. It was `ModeAdmin.html()` in `admin-ui/mode_admin.ts` and
// is that function moved, with the console's helpers taken from
// `web_kit.ts` — so it is the same markup, to the byte.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Until the console's cutover `mode_admin.ts` still draws the page, by
// calling `render()` with its view passed through JSON — which is what holds
// this function to drawing from what a caller of the API receives.
//
// It adds no fact, as the page never did: every row is `common/mode.js`'s
// own table, through `mode.report()`.
// ---------------------------------------------------------------------------

import WebKit = require('./web_kit');

type Json = any;

/**
 * Draws Server configuration → Mode from the mode report: the body of
 * `/admin/mode`, as markup.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ModePage {
  // A value as a person reads it: a string as itself, anything else as JSON.
  /**
   * Draws a setting's value: a string as itself, anything else as JSON.
   *
   * @param value - the value
   * @param t - the page's translator (#539)
   * @returns the value as HTML
   */
  static shown(value: unknown, t: Json): string {
    if (typeof value === 'string') {
      return value === '' ? t.html('consoleMode.empty')
                          : '<code>' + WebKit.esc(value) + '</code>';
    }
    return '<code>' + WebKit.esc(JSON.stringify(value)) + '</code>';
  }

  /**
   * Draws the page's body from the mode report.
   *
   * @param json - `GET /admin-api/mode`'s answer
   * @param ctx - optional; the render context (`WebKit.context()`), whose
   *   translator draws the words (#539). `mode_admin.ts` passes none, and
   *   gets the default translator — English in node.
   * @returns the body as HTML
   */
  static render(json: Json, ctx?: Json): string {
    const t = (ctx || WebKit.context()).t;
    const product = !!json.isProduct;
    const ignored = json.developmentOnlySettings.filter(function (
      row: Json): boolean {
      return row.ignored;
    });
    const tiles = '<div class="tiles">' +
      WebKit.tile(json.mode, t.text('consoleMode.tileMode')) +
      WebKit.tile(String(json.requirements.length),
                  t.text('consoleMode.tileRequirements')) +
      WebKit.tile(String(json.developmentOnlySettings.length),
                 t.text('consoleMode.tileDevOnly')) +
      WebKit.tile(String(ignored.length), t.text('consoleMode.tileIgnored')) +
      '</div>';
    // The link is markup a message cannot carry (#539), so the sentence is
    // split around it.
    const about = WebKit.note(
      '<p>' + t.html('consoleMode.about1') + ' ' +
      t.html('consoleMode.about2') + '<a href="/admin/config">' +
      t.html('consoleMode.aboutConfigLink') + '</a>' +
      t.html('consoleMode.about3') + '</p><p>' +
      t.html('consoleMode.about4') + '</p>',
      t.text('consoleMode.aboutLabel'));
    const warning = ignored.length ? WebKit.warn(
      '<p>' + t.html('consoleMode.ignoredLead',
                     { n: String(ignored.length) }) +
      ignored.map(function (row: Json): string {
        return '<code>' + WebKit.esc(row.key) + '</code>';
      }).join(', ') + t.html('consoleMode.ignoredTail') + '</p>') : '';
    const cell = function (text: string, inForce: boolean): string {
      return '<td>' + (inForce ? '<strong>' : '') + WebKit.esc(text) +
        (inForce ? '</strong>' : '') + '</td>';
    };
    const requirements = '<h2>' + t.html('consoleMode.changesHeading') +
      '</h2>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleMode.thRequirement') + '</th>' +
      '<th>' + t.html('consoleMode.thDevelopment') + '</th><th>' +
      t.html('consoleMode.thProduct') + '</th><th>' +
      t.html('consoleMode.thWhere') + '</th></tr></thead>' +
      '<tbody>' + json.requirements.map(function (row: Json): string {
        return '<tr id="requirement-' + WebKit.esc(row.id) + '"><th>' +
          WebKit.esc(row.what) + '<br><small><code>' + WebKit.esc(row.id) +
          '</code></small></th>' + cell(row.development, !product) +
          cell(row.product, product) + '<td><small>' +
          WebKit.esc(row.where || '') + '</small></td></tr>';
      }).join('') + '</tbody></table>';
    const settings = '<h2>' + t.html('consoleMode.devOnlyHeading') + '</h2>' +
      '<p>' + t.html('consoleMode.devOnlyLead') + '</p>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleMode.thSetting') + '</th><th>' +
      t.html('consoleMode.thDevOnlyValues') + '</th><th>' +
      t.html('consoleMode.thStored') + '</th><th>' +
      t.html('consoleMode.thInForce') + '</th><th>' +
      t.html('consoleMode.thWhy') + '</th></tr>' +
      '</thead><tbody>' +
      json.developmentOnlySettings.map(function (row: Json): string {
        return '<tr id="setting-' + WebKit.esc(row.key) + '"><th><code>' +
          WebKit.esc(row.key) + '</code><br><small>' + WebKit.esc(row.group) +
          ' · <code>' + WebKit.esc(row.predicate) + '()</code></small></th>' +
          '<td>' + (row.developmentOnlyValues
            ? row.developmentOnlyValues.map(function (v: unknown): string {
              return ModePage.shown(v, t);
            }).join(', ')
            : t.html('consoleMode.anythingBut') +
              ModePage.shown(row.default, t)) + '</td>' +
          '<td>' + ModePage.shown(row.value, t) + '</td><td>' +
          (row.ignored ? '<strong>' + ModePage.shown(row.inForce, t) +
                         '</strong>' + t.html('consoleMode.ignoredMark')
            : ModePage.shown(row.inForce, t)) +
          '</td><td><small>' + WebKit.esc(row.why) + '</small></td></tr>';
      }).join('') + '</tbody></table>';
    const notYet = '<h2>' + t.html('consoleMode.notYetHeading') + '</h2>' +
      '<ul>' + json.notYet.map(function (row: Json): string {
        return '<li id="not-yet-' + WebKit.esc(row.id) + '">' +
          WebKit.esc(row.what) + '</li>';
      }).join('') + '</ul>';
    return tiles + about + warning + requirements + settings + notYet;
  }
}

export = ModePage;
