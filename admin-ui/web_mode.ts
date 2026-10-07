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
   * @returns the value as HTML
   */
  static shown(value: unknown): string {
    if (typeof value === 'string') {
      return value === '' ? '<em>(empty)</em>'
                          : '<code>' + WebKit.esc(value) + '</code>';
    }
    return '<code>' + WebKit.esc(JSON.stringify(value)) + '</code>';
  }

  /**
   * Draws the page's body from the mode report.
   *
   * @param json - `GET /admin-api/mode`'s answer
   * @returns the body as HTML
   */
  static render(json: Json): string {
    const product = !!json.isProduct;
    const ignored = json.developmentOnlySettings.filter(function (
      row: Json): boolean {
      return row.ignored;
    });
    const tiles = '<div class="tiles">' +
      WebKit.tile(json.mode, 'mode of this realm') +
      WebKit.tile(String(json.requirements.length), 'requirements it changes') +
      WebKit.tile(String(json.developmentOnlySettings.length),
                 'development-only settings') +
      WebKit.tile(String(ignored.length), 'stored and ignored here') +
      '</div>';
    const about = WebKit.note(
      '<p><code>global.mode</code> says what this realm IS: ' +
      '<strong>development</strong>, a mock that exercises a client by ' +
      'saying yes, or <strong>product</strong>, the same protocol ' +
      'implementations with the permissiveness taken out. It is set per ' +
      'trust realm on <a href="/admin/config">Configuration</a> (the Global ' +
      'group); this page changes nothing.</p><p>Every row below is ' +
      '<code>common/mode.js</code>\'s own table, so this page, ' +
      '<code>GET /admin-api/mode</code> and the code cannot disagree. The ' +
      'answer in force here is in bold.</p>',
      'What this page is');
    const warning = ignored.length ? WebKit.warn(
      '<p>' + ignored.length + ' development-only setting' +
      (ignored.length === 1 ? ' is' : 's are') + ' stored in this realm and ' +
      'IGNORED, because it is in product mode: ' +
      ignored.map(function (row: Json): string {
        return '<code>' + WebKit.esc(row.key) + '</code>';
      }).join(', ') + '. Each is read as its default (logged once, ' +
      '<code>STS-CORE-0106</code>) until it is reset.</p>') : '';
    const cell = function (text: string, inForce: boolean): string {
      return '<td>' + (inForce ? '<strong>' : '') + WebKit.esc(text) +
        (inForce ? '</strong>' : '') + '</td>';
    };
    const requirements = '<h2>What the mode changes</h2>' +
      '<table class="grid"><thead><tr><th>Requirement</th>' +
      '<th>Development</th><th>Product</th><th>Where</th></tr></thead>' +
      '<tbody>' + json.requirements.map(function (row: Json): string {
        return '<tr id="requirement-' + WebKit.esc(row.id) + '"><th>' +
          WebKit.esc(row.what) + '<br><small><code>' + WebKit.esc(row.id) +
          '</code></small></th>' + cell(row.development, !product) +
          cell(row.product, product) + '<td><small>' +
          WebKit.esc(row.where || '') + '</small></td></tr>';
      }).join('') + '</tbody></table>';
    const settings = '<h2>Development-only settings</h2>' +
      '<p>A setting marked development-only may hold a value other than ' +
      'its default only while the named predicate of ' +
      '<code>common/mode.js</code> answers yes; in product such a value is ' +
      'refused on write (<code>STS-CORE-0103</code>) and ignored where it ' +
      'is read.</p>' +
      '<table class="grid"><thead><tr><th>Setting</th><th>Development-only ' +
      'values</th><th>Stored here</th><th>In force</th><th>Why</th></tr>' +
      '</thead><tbody>' +
      json.developmentOnlySettings.map(function (row: Json): string {
        return '<tr id="setting-' + WebKit.esc(row.key) + '"><th><code>' +
          WebKit.esc(row.key) + '</code><br><small>' + WebKit.esc(row.group) +
          ' · <code>' + WebKit.esc(row.predicate) + '()</code></small></th>' +
          '<td>' + (row.developmentOnlyValues
            ? row.developmentOnlyValues.map(function (v: unknown): string {
              return ModePage.shown(v);
            }).join(', ')
            : 'anything but ' + ModePage.shown(row.default)) + '</td>' +
          '<td>' + ModePage.shown(row.value) + '</td><td>' +
          (row.ignored ? '<strong>' + ModePage.shown(row.inForce) +
                         '</strong> — ignored' : ModePage.shown(row.inForce)) +
          '</td><td><small>' + WebKit.esc(row.why) + '</small></td></tr>';
      }).join('') + '</tbody></table>';
    const notYet = '<h2>What product mode still does not check</h2>' +
      '<ul>' + json.notYet.map(function (row: Json): string {
        return '<li id="not-yet-' + WebKit.esc(row.id) + '">' +
          WebKit.esc(row.what) + '</li>';
      }).join('') + '</ul>';
    return tiles + about + warning + requirements + settings + notYet;
  }
}

export = ModePage;
