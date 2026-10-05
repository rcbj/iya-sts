// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_provider_commands.ts
//
// ---------------------------------------------------------------------------
// OAUTH 2.0 → PROVIDER COMMANDS AND OUTBOUND DELIVERIES, DRAWN FROM THEIR
// VIEWS ALONE (#446, 2026-10-05).
//
// Draws OpenID Provider Commands from the answer of `GET /admin-api/commands`,
// and Outbound deliveries from that of `GET /admin-api/deliveries`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `ProviderCommandsAdmin`'s in
// `oauth-oidc/provider_commands_admin.ts`, moved with their comments; that
// module still draws the page until the console's cutover, by calling
// `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * The path of the OpenID Provider Commands page.
 */
const PAGE = '/admin/commands';

/**
 * The path of the outbound deliveries page.
 */
const DELIVERIES = '/admin/deliveries';

/**
 * Draws OpenID Provider Commands from the answer of `GET /admin-api/commands`,
 * and Outbound deliveries from that of `GET /admin-api/deliveries`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ProviderCommandsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return ProviderCommandsPage.commandsBody(view);
  }

  // One small form: hidden fields and a button.
  /**
   * Draws one small POST form: hidden fields and a button.
   *
   * @param page - the page the form posts to
   * @param action - the action it names
   * @param fields - the hidden fields, name to value
   * @param label - the button's label
   * @param danger - true to style the button as destructive
   * @returns the HTML
   */
  static form(page: string, action: string, fields: Json, label: string,
              danger?: boolean): string {
    return '<form method="post" action="' + page + '" class="inline">' +
      '<input type="hidden" name="action" value="' + esc(action) + '">' +
      Object.keys(fields).map(function (k: string): string {
        return '<input type="hidden" name="' + esc(k) + '" value="' +
          esc(fields[k]) + '">';
      }).join('') + ' <button type="submit"' +
      (danger ? ' class="danger"' : '') + '>' + esc(label) +
      '</button></form>';
  }

  // A row of the shared queue, for either page.
  /**
   * Draws one row of the shared outbound queue, with a Retry for a dead letter.
   *
   * @param page - the page a Retry posts to
   * @param kind - the delivery kind
   * @param row - the delivery row
   * @returns the HTML table row
   */
  static deliveryRow(page: string, kind: string, row: Json): string {
    const what = row.command ? '<code>' + esc(row.command) + '</code>' +
      (row.username ? ' ' + esc(row.username) : '') :
      (row.mode ? esc(row.mode) + ' ' + esc(row.authReqId || '') :
       'session <code>' + esc(row.sessionId || '') + '</code>');
    return '<tr class="delivery-' + esc(row.state) + '" id="delivery-' +
      esc(row.id) + '"><td><code>' + esc(row.clientId) + '</code></td><td>' +
      what + '</td><td>' + esc(row.state) +
      (row.accountState ? ' → <code>' + esc(row.accountState) + '</code>'
                        : '') +
      (row.awaitingCallback ? ' (a callback to follow)' : '') +
      '<br><span class="sub">' + esc(row.attempts) + ' attempt(s)' +
      (row.status ? ', HTTP ' + esc(row.status) : '') +
      (row.errorCode ? ', <code>' + esc(row.errorCode) + '</code>' : '') +
      '</span>' + (row.why ? '<br><span class="sub">' + esc(row.why) +
                              '</span>' : '') +
      '</td><td class="sub">' + esc(row.queuedAt) + '</td><td>' +
      (row.state === 'dead'
        ? ProviderCommandsPage.form(page, 'retry', { kind: kind,
            delivery: row.id }, 'Retry')
        : '') + '</td></tr>';
  }

  // /admin/commands' body, from `report()`.
  /**
   * Draws `/admin/commands`' body.
   *
   * @param json - `provider_commands.report()`'s answer
   * @returns the HTML
   */
  static commandsBody(json: Json): string {
    const form = ProviderCommandsPage.form;
    const clients = json.clients.length ? json.clients.map(function (c: Json) {
      return '<tr id="command-client-' + esc(c.clientId) + '"><td><code>' +
        esc(c.clientId) + '</code><br>' + esc(c.name) + '</td><td><code>' +
        esc(c.endpoint) + '</code></td><td>' + (c.learned
          ? c.learned.commandsSupported.map(function (one: string) {
              return '<code>' + esc(one) + '</code>';
            }).join(' ') + (c.learned.audSubRequired
              ? '<br><strong>aud_sub required</strong>' : '') +
            '<br><span class="sub">learned ' + esc(c.learned.learnedAt) +
            '</span>'
          : '<span class="sub">not asked yet — send <code>metadata</code>' +
            '</span>') + '</td><td>' +
        form(PAGE, 'send-tenant', { clientId: c.clientId,
                                    command: 'metadata' }, 'Send metadata') +
        '</td></tr>';
    }).join('') : '<tr><td colspan="4" class="sub">No client registered a ' +
      '<code>command_endpoint</code>. It is a registration member ' +
      '(RFC 7591, <code>POST /oauth2/register</code>) and a field on ' +
      '<code>/admin/applications</code>.</td></tr>';
    const clientOptions = json.clients.map(function (c: Json) {
      return '<option>' + esc(c.clientId) + '</option>';
    }).join('');
    const accountOptions = json.accountCommands.reduce(function (acc: string,
                                                                one: string) {
      return acc + '<option>' + esc(one) + '</option><option>' + esc(one) +
        '_async</option>';
    }, '');
    const tenantOptions = json.tenantCommands.map(function (one: string) {
      return '<option>' + esc(one) + '</option>';
    }).join('');
    const send = '<h3>Send a command</h3>' +
      '<form method="post" action="' + PAGE + '" id="command-send-account">' +
      '<input type="hidden" name="action" value="send-account">' +
      '<label>Client <select name="clientId">' + clientOptions +
      '</select></label> <label>Person <input name="username" ' +
      'autocomplete="off"></label> <label>Command <select name="command">' +
      accountOptions + '</select></label> <button type="submit">Send' +
      '</button></form>' +
      '<form method="post" action="' + PAGE + '" id="command-send-tenant">' +
      '<input type="hidden" name="action" value="send-tenant">' +
      '<label>Client <select name="clientId">' + clientOptions +
      '</select></label> <label>Tenant command <select name="command">' +
      tenantOptions + '</select></label> <button type="submit">Start' +
      '</button></form>';
    const accounts = json.accounts.length ? json.accounts.map(function (a:
                                                                     Json) {
      return '<tr><td><code>' + esc(a.clientId) + '</code></td><td>' +
        esc(a.username || '—') + '<br><span class="sub"><code>' +
        esc(a.sub) + '</code></span></td><td><strong>' + esc(a.state) +
        '</strong></td><td><code>' + esc(a.lastCommand) + '</code></td>' +
        '<td class="sub">' + esc(a.updatedAt) + '</td></tr>';
    }).join('') : '<tr><td colspan="5" class="sub">No relying party has ' +
      'reported an account yet.</td></tr>';
    const runs = json.runs.length ? json.runs.map(function (r: Json) {
      return '<tr id="command-run-' + esc(r.id) + '"><td><code>' +
        esc(r.clientId) + '</code></td><td><code>' + esc(r.command) +
        '</code></td><td>' + esc(r.state) + (r.why ? '<br><span ' +
        'class="sub">' + esc(r.why) + '</span>' : '') + '</td><td>' +
        esc(r.accounts) + ' account(s), ' + esc(r.events) + ' event(s)' +
        (r.totalAccounts !== null ? ', total ' + esc(r.totalAccounts) : '') +
        (r.resumes ? ', resumed ' + esc(r.resumes) + '×' : '') +
        '</td><td class="sub">' + esc(r.startedAt) + '</td></tr>';
    }).join('') : '<tr><td colspan="5" class="sub">No tenant command has ' +
      'run.</td></tr>';
    const deliveries = json.deliveries.length
      ? json.deliveries.map(function (row: Json) {
        return ProviderCommandsPage.deliveryRow(PAGE, 'provider-commands',
                                                 row);
      }).join('')
      : '<tr><td colspan="5" class="sub">No command has been sent.</td></tr>';
    return kit.note('<strong>OpenID Provider Commands 1.0.</strong> ' +
        'This service tells a relying party what to do with an account — ' +
        'a signed Command Token POSTed to the <code>command_endpoint</code> ' +
        'it registered. Provider commands are <strong>' +
        (json.enabled ? 'on' : 'off') + '</strong> here ' +
        '(<code>oauth2.providerCommands</code>); automatic commands on a ' +
        'disable, an enable, a delete, a change and a global sign-out are ' +
        '<strong>' + (json.automatic ? 'on' : 'off') + '</strong> ' +
        '(<code>oauth2.commandAutomatic</code>) and go only to a relying ' +
        'party whose metadata answer listed the command. The issuer ' +
        'Command Tokens name is <code id="command-issuer">' +
        esc(json.issuer || '(none known yet)') + '</code>.') +
      '<table><thead><tr><th>Client</th><th>command_endpoint</th>' +
      '<th>Commands it supports</th><th></th></tr></thead><tbody>' +
      clients + '</tbody></table>' + send +
      '<h3>Accounts, as each relying party reported them</h3>' +
      '<table><thead><tr><th>Client</th><th>Person</th><th>State</th>' +
      '<th>Last command</th><th>When</th></tr></thead><tbody>' + accounts +
      '</tbody></table><h3>Tenant runs</h3><table><thead><tr><th>Client' +
      '</th><th>Command</th><th>State</th><th>Progress</th><th>Started' +
      '</th></tr></thead><tbody>' + runs + '</tbody></table>' +
      '<h3>Deliveries</h3><table><thead><tr><th>Client</th><th>Command' +
      '</th><th>State</th><th>Queued</th><th></th></tr></thead><tbody>' +
      deliveries + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/commands</code> · <a href="' + DELIVERIES +
      '">every outbound delivery</a></p>';
  }

  // /admin/deliveries' body, from `outbound.kindReport()`.
  /**
   * Draws `/admin/deliveries`' body.
   *
   * @param ctx - the render context (`WebKit.context()`)
   *   filter in force
   * @param json - `outbound_delivery.kindReport()`'s answer
   * @returns the HTML
   */
  static deliveriesBody(ctx: Json, json: Json): string {
    const state = String(ctx.query.state || '');
    const filter = '<form method="get" action="' + DELIVERIES + '" ' +
      'class="inline"><label>State <select name="state"><option value="">' +
      'every state</option>' + json.states.map(function (s: string) {
        return '<option' + (s === state ? ' selected' : '') + '>' + esc(s) +
          '</option>';
      }).join('') + '</select></label> <button type="submit">Show</button>' +
      '</form>';
    const kinds = json.kinds.map(function (k: Json) {
      const rows = k.rows.length ? k.rows.map(function (row: Json) {
        return ProviderCommandsPage.deliveryRow(DELIVERIES, k.id, row);
      }).join('') : '<tr><td colspan="5" class="sub">Nothing' +
        (state ? ' ' + esc(state) : '') + '.</td></tr>';
      return '<h3 id="kind-' + esc(k.id) + '">' + esc(k.title) + '</h3>' +
        '<p class="sub">' + esc(k.counts.pending) + ' pending, ' +
        esc(k.counts.sent) + ' sent, <strong>' + esc(k.counts.dead) +
        ' dead</strong> · <a href="' + esc(k.page) + '">' + esc(k.page) +
        '</a></p><table><thead><tr><th>Client</th><th>What</th><th>State' +
        '</th><th>Queued</th><th></th></tr></thead><tbody>' + rows +
        '</tbody></table>';
    }).join('');
    return kit.note('<strong>Every outbound delivery</strong> this ' +
        'service POSTs to an address a client registered, on the one ' +
        'durable queue: each is a persisted row, attempted once for the ' +
        'cluster under a claimed lease, retried with backoff when a timeout, ' +
        'a connection failure, 5xx, 408 or 429 makes that worth it, and a ' +
        '<strong>dead letter</strong> otherwise — sent again only when an ' +
        'operator presses Retry, which starts a new generation.') +
      filter + kinds + '<p class="links"><a href="' + DELIVERIES +
      '?format=json">JSON</a> · <code>GET /admin-api/deliveries</code></p>';
  }
}

export = ProviderCommandsPage;
