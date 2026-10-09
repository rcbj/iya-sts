// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_debugger.ts
//
// ---------------------------------------------------------------------------
// MONITORING → PROTOCOL DEBUGGER, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws the Protocol debugger page from the answer of `GET
// /admin-api/debugger`: the embedded debugger's listener, its api process,
// what it may dial, and its settings.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `DebuggerAdmin`'s in `debugger/debugger_admin.ts`, moved
// with their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');
import SettingsForms = require('../admin-ui/web_settings');

type Json = any;

const PAGE_PATH = '/admin/debugger';

/**
 * Draws the Protocol debugger page from the answer of `GET
 * /admin-api/debugger`: the embedded debugger's listener, its api process,
 * what it may dial, and its settings.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class DebuggerPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`), whose translator
   *   the page is drawn with (#539); the default context when none is given
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return DebuggerPage.body(view, (ctx || kit.context()).t);
  }

  /**
   * Draws one row of a key/value table.
   *
   * @param label - the heading, escaped here
   * @param value - the cell, as HTML
   * @returns the table row
   */
  static row(label, value) {
    return '<tr><th>' + kit.esc(label) + '</th><td>' + value + '</td></tr>';
  }

  /**
   * Draws a value in a code element, or a muted `none` when it is empty.
   *
   * @param text - the value, escaped here
   * @param t - the page's translator (#539), for the word `none`
   * @returns the HTML
   */
  static code(text, t) {
    return text === null || text === undefined || text === ''
      ? '<span class="muted">' + t.html('consoleDebugger.none') + '</span>'
      : '<code>' + kit.esc(String(text)) + '</code>';
  }

  /**
   * Draws the page body: tiles, an explanation, any startup problem, the
   * listener and api-process tables, and the settings forms.
   *
   * @param json - the view from debuggerView()
   * @param t - the page's translator (#539)
   * @returns the HTML
   */
  static body(json, t) {
    const api = json.api || {};
    // `code()` with this page's translator, for the `.map()` below.
    const code = (text) => this.code(text, t);
    const origin = json.publicBaseUrl ||
                   (json.scheme + '://&lt;this host&gt;:' + json.port);
    const tiles = '<div class="tiles">' +
      kit.tile(json.embedded ? t.text('consoleDebugger.tile.embedded')
                             : t.text('consoleDebugger.tile.off'),
               t.text('consoleDebugger.tile.debugger')) +
      kit.tile(json.listening ? String(json.port)
                              : t.text('consoleDebugger.tile.notBound'),
               t.text('consoleDebugger.tile.listener')) +
      kit.tile(api.state ? String(api.state)
                         : t.text('consoleDebugger.tile.stopped'),
               t.text('consoleDebugger.tile.apiProcess')) +
      kit.tile(api.allowList ? String((api.allowedRanges || []).length)
                             : t.text('consoleDebugger.none'),
               t.text('consoleDebugger.tile.ranges')) +
      '</div>';
    // Split around the three values and the link (#539): a parameter is
    // escaped, so a value drawn as markup by `code()` sits between messages.
    const what = kit.note(
      t.html('consoleDebugger.what.a') + code(json.clientId) +
      t.html('consoleDebugger.what.b') + code(json.audience) +
      t.html('consoleDebugger.what.c') + code(json.permission) +
      t.html('consoleDebugger.what.d') + '<a href="/admin/rbac">' +
      t.html('consoleDebugger.what.link') + '</a>' +
      t.html('consoleDebugger.what.e'));
    const problems = [json.startProblem, json.listenError, api.lastError]
      .filter(Boolean);
    const warning = !json.embedded ? '' : (problems.length
      ? kit.warn(problems.map(kit.esc).join('<br>'), 'Not running')
      : '');
    const listener = '<h2>' + t.html('consoleDebugger.listener.heading') +
      '</h2><table class="kv">' +
      this.row(t.text('consoleDebugger.listener.embedded'),
               code(json.embedded ? 'yes' : 'no') +
               t.html('consoleDebugger.listener.enabledIs') +
               code(json.setting) + t.html('consoleDebugger.listener.in') +
               code(json.mode) + t.html('consoleDebugger.listener.mode')) +
      this.row(t.text('consoleDebugger.listener.port'), code(json.port) +
               (json.listening ? t.html('consoleDebugger.listener.bound') :
                                 t.html('consoleDebugger.listener.notBound'))) +
      this.row(t.text('consoleDebugger.listener.origin'), json.listening
        ? '<code>' + origin + '</code>'
        : '<span class="muted">' +
          t.html('consoleDebugger.listener.notServing') + '</span>') +
      this.row(t.text('consoleDebugger.listener.staticSite'),
               code(json.uiDirectory)) +
      this.row(t.text('consoleDebugger.listener.client'),
               code(json.clientId)) +
      this.row(t.text('consoleDebugger.listener.resource'),
               code(json.resource)) +
      this.row(t.text('consoleDebugger.listener.permission'),
               code(json.permission)) +
      '</table>';
    // The last exit's wording is inside <code> and stays as written (#539).
    const process = '<h2>' + t.html('consoleDebugger.api.heading') +
      '</h2><table class="kv">' +
      this.row(t.text('consoleDebugger.api.state'), code(api.state)) +
      this.row(t.text('consoleDebugger.api.pid'), code(api.pid)) +
      this.row(t.text('consoleDebugger.api.socket'), code(api.socket)) +
      this.row(t.text('consoleDebugger.api.tree'), code(api.apiDirectory)) +
      this.row(t.text('consoleDebugger.api.starts'), code(api.starts)) +
      this.row(t.text('consoleDebugger.api.failures'),
               code(api.consecutiveFailures)) +
      this.row(t.text('consoleDebugger.api.since'), code(api.listeningAt)) +
      this.row(t.text('consoleDebugger.api.lastExit'), api.lastExit
        ? code((api.lastExit.signal ? 'signal ' + api.lastExit.signal
                                    : 'code ' + api.lastExit.code) +
               ' at ' + api.lastExit.at + ' after ' +
               api.lastExit.upSeconds + 's')
        : code('')) +
      this.row(t.text('consoleDebugger.api.mayDial'), api.allowList
        ? (api.allowedRanges || []).map(function (one) {
            return code(one);
          }).join(' ') +
               ((api.allowListProblems || []).length
                 ? '<br>' + kit.warn('Left out, not ranges: ' +
                                       api.allowListProblems.map(kit.esc)
                                         .join(', '),
                                         'debugger.allowedDestinations')
                 : '')
        : t.html('consoleDebugger.api.anything')) +
      '</table>';
    return tiles + what + warning + listener + process +
           '<h2>' + t.html('consoleDebugger.settings') + '</h2>' +
           SettingsForms.forms(json.settings, PAGE_PATH, undefined, t);
  }
}

export = DebuggerPage;
