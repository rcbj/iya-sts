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
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return DebuggerPage.body(view);
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
   * @returns the HTML
   */
  static code(text) {
    return text === null || text === undefined || text === ''
      ? '<span class="muted">none</span>'
      : '<code>' + kit.esc(String(text)) + '</code>';
  }

  /**
   * Draws the page body: tiles, an explanation, any startup problem, the
   * listener and api-process tables, and the settings forms.
   *
   * @param json - the view from debuggerView()
   * @returns the HTML
   */
  static body(json) {
    const api = json.api || {};
    const origin = json.publicBaseUrl ||
                   (json.scheme + '://&lt;this host&gt;:' + json.port);
    const tiles = '<div class="tiles">' +
      kit.tile(json.embedded ? 'embedded' : 'off', 'debugger') +
      kit.tile(json.listening ? String(json.port) : 'not bound', 'listener') +
      kit.tile(String(api.state || 'stopped'), 'api process') +
      kit.tile(api.allowList ? String((api.allowedRanges || []).length)
                               : 'none', 'allow-listed ranges') +
      '</div>';
    const what = kit.note(
      'The identity protocol debugger, served by this process on a listener ' +
      'of its own so that its pages — which carry inline scripts and render ' +
      'tokens from any identity provider — are on an origin other than this ' +
      'console\'s. Its user interface is static files; its api runs as a ' +
      'child process on a unix socket, forwarded at <code>/api</code>. It is ' +
      'signed in to through this service\'s authorization server as ' +
      this.code(json.clientId) + ', and every request needs an access token ' +
      'addressed to ' + this.code(json.audience) + ' carrying ' +
      this.code(json.permission) +
      ' — which the authorization server issues to members of the two groups ' +
      'on <a href="/admin/rbac">Admin roles</a> and leaves off for anybody ' +
      'else. <strong>No setting below opens it.</strong>');
    const problems = [json.startProblem, json.listenError, api.lastError]
      .filter(Boolean);
    const warning = !json.embedded ? '' : (problems.length
      ? kit.warn(problems.map(kit.esc).join('<br>'), 'Not running')
      : '');
    const listener = '<h2>Listener</h2><table class="kv">' +
      this.row('Embedded', this.code(json.embedded ? 'yes' : 'no') + ' — ' +
               'debugger.enabled is ' + this.code(json.setting) + ' in ' +
               this.code(json.mode) + ' mode') +
      this.row('Port', this.code(json.port) + (json.listening ? ' (bound)' :
                                                ' (not bound)')) +
      this.row('Origin', json.listening
        ? '<code>' + origin + '</code>'
        : '<span class="muted">not serving</span>') +
      this.row('Static site', this.code(json.uiDirectory)) +
      this.row('Client', this.code(json.clientId)) +
      this.row('Resource server', this.code(json.resource)) +
      this.row('Permission', this.code(json.permission)) +
      '</table>';
    const process = '<h2>Api process</h2><table class="kv">' +
      this.row('State', this.code(api.state)) +
      this.row('Process id', this.code(api.pid)) +
      this.row('Socket', this.code(api.socket)) +
      this.row('Tree', this.code(api.apiDirectory)) +
      this.row('Starts', this.code(api.starts)) +
      this.row('Failures in a row', this.code(api.consecutiveFailures)) +
      this.row('Listening since', this.code(api.listeningAt)) +
      this.row('Last exit', api.lastExit
        ? this.code((api.lastExit.signal ? 'signal ' + api.lastExit.signal
                                         : 'code ' + api.lastExit.code) +
                    ' at ' + api.lastExit.at + ' after ' +
                    api.lastExit.upSeconds + 's')
        : this.code('')) +
      this.row('May dial', api.allowList
        ? (api.allowedRanges || []).map(this.code.bind(this)).join(' ') +
               ((api.allowListProblems || []).length
                 ? '<br>' + kit.warn('Left out, not ranges: ' +
                                       api.allowListProblems.map(kit.esc)
                                         .join(', '),
                                         'debugger.allowedDestinations')
                 : '')
        : 'anything, private networks included — development mode passes the ' +
               'api no allow-list') +
      '</table>';
    return tiles + what + warning + listener + process +
           '<h2>Settings</h2>' +
           SettingsForms.forms(json.settings, PAGE_PATH);
  }
}

export = DebuggerPage;
