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
   * @param ctx - the render context; the server-side caller passes none and
   *   is drawn in the default (English) translator (#539)
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    const t = (ctx || kit.context()).t;
    return ProviderCommandsPage.commandsBody(view, t);
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
   * @param t - the page's translator (#539)
   * @returns the HTML table row
   */
  static deliveryRow(page: string, kind: string, row: Json, t: Json): string {
    const what = row.command ? '<code>' + esc(row.command) + '</code>' +
      (row.username ? ' ' + esc(row.username) : '') :
      (row.mode ? esc(row.mode) + ' ' + esc(row.authReqId || '') :
       t.html('consoleProviderCommands.session') + ' <code>' +
       esc(row.sessionId || '') + '</code>');
    return '<tr class="delivery-' + esc(row.state) + '" id="delivery-' +
      esc(row.id) + '"><td><code>' + esc(row.clientId) + '</code></td><td>' +
      what + '</td><td>' + esc(row.state) +
      (row.accountState ? ' → <code>' + esc(row.accountState) + '</code>'
                        : '') +
      (row.awaitingCallback
        ? t.html('consoleProviderCommands.awaitingCallback') : '') +
      '<br><span class="sub">' +
      t.html('consoleProviderCommands.attempts', { n: row.attempts }) +
      (row.status ? ', HTTP ' + esc(row.status) : '') +
      (row.errorCode ? ', <code>' + esc(row.errorCode) + '</code>' : '') +
      '</span>' + (row.why ? '<br><span class="sub">' + esc(row.why) +
                              '</span>' : '') +
      '</td><td class="sub">' + esc(row.queuedAt) + '</td><td>' +
      (row.state === 'dead'
        ? ProviderCommandsPage.form(page, 'retry', { kind: kind,
            delivery: row.id }, t.text('consoleProviderCommands.retry'))
        : '') + '</td></tr>';
  }

  // /admin/commands' body, from `report()`.
  /**
   * Draws `/admin/commands`' body.
   *
   * @param json - `provider_commands.report()`'s answer
   * @param t - the page's translator (#539)
   * @returns the HTML
   */
  static commandsBody(json: Json, t: Json): string {
    const form = ProviderCommandsPage.form;
    const clients = json.clients.length ? json.clients.map(function (c: Json) {
      return '<tr id="command-client-' + esc(c.clientId) + '"><td><code>' +
        esc(c.clientId) + '</code><br>' + esc(c.name) + '</td><td><code>' +
        esc(c.endpoint) + '</code></td><td>' + (c.learned
          ? c.learned.commandsSupported.map(function (one: string) {
              return '<code>' + esc(one) + '</code>';
            }).join(' ') + (c.learned.audSubRequired
              ? '<br><strong>' +
                t.html('consoleProviderCommands.audSubRequired') +
                '</strong>' : '') +
            '<br><span class="sub">' +
            t.html('consoleProviderCommands.learned',
                   { when: c.learned.learnedAt }) +
            '</span>'
          : '<span class="sub">' +
            t.html('consoleProviderCommands.notAsked') + '</span>') +
        '</td><td>' +
        form(PAGE, 'send-tenant', { clientId: c.clientId,
                                    command: 'metadata' },
             t.text('consoleProviderCommands.sendMetadata')) +
        '</td></tr>';
    }).join('') : '<tr><td colspan="4" class="sub">' +
      t.html('consoleProviderCommands.noClients') + '</td></tr>';
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
    const send = '<h3>' + t.html('consoleProviderCommands.sendHeading') +
      '</h3>' +
      '<form method="post" action="' + PAGE + '" id="command-send-account">' +
      '<input type="hidden" name="action" value="send-account">' +
      '<label>' + t.html('consoleProviderCommands.client') +
      ' <select name="clientId">' + clientOptions +
      '</select></label> <label>' + t.html('consoleProviderCommands.person') +
      ' <input name="username" ' +
      'autocomplete="off"></label> <label>' +
      t.html('consoleProviderCommands.command') +
      ' <select name="command">' +
      accountOptions + '</select></label> <button type="submit">' +
      t.html('consoleProviderCommands.send') +
      '</button></form>' +
      '<form method="post" action="' + PAGE + '" id="command-send-tenant">' +
      '<input type="hidden" name="action" value="send-tenant">' +
      '<label>' + t.html('consoleProviderCommands.client') +
      ' <select name="clientId">' + clientOptions +
      '</select></label> <label>' +
      t.html('consoleProviderCommands.tenantCommand') +
      ' <select name="command">' +
      tenantOptions + '</select></label> <button type="submit">' +
      t.html('consoleProviderCommands.start') +
      '</button></form>';
    const accounts = json.accounts.length ? json.accounts.map(function (a:
                                                                     Json) {
      return '<tr><td><code>' + esc(a.clientId) + '</code></td><td>' +
        esc(a.username || '—') + '<br><span class="sub"><code>' +
        esc(a.sub) + '</code></span></td><td><strong>' + esc(a.state) +
        '</strong></td><td><code>' + esc(a.lastCommand) + '</code></td>' +
        '<td class="sub">' + esc(a.updatedAt) + '</td></tr>';
    }).join('') : '<tr><td colspan="5" class="sub">' +
      t.html('consoleProviderCommands.noAccounts') + '</td></tr>';
    const runs = json.runs.length ? json.runs.map(function (r: Json) {
      return '<tr id="command-run-' + esc(r.id) + '"><td><code>' +
        esc(r.clientId) + '</code></td><td><code>' + esc(r.command) +
        '</code></td><td>' + esc(r.state) + (r.why ? '<br><span ' +
        'class="sub">' + esc(r.why) + '</span>' : '') + '</td><td>' +
        t.html('consoleProviderCommands.progress',
               { accounts: r.accounts, events: r.events }) +
        (r.totalAccounts !== null
          ? t.html('consoleProviderCommands.total', { n: r.totalAccounts })
          : '') +
        (r.resumes
          ? t.html('consoleProviderCommands.resumed', { n: r.resumes })
          : '') +
        '</td><td class="sub">' + esc(r.startedAt) + '</td></tr>';
    }).join('') : '<tr><td colspan="5" class="sub">' +
      t.html('consoleProviderCommands.noRuns') + '</td></tr>';
    const deliveries = json.deliveries.length
      ? json.deliveries.map(function (row: Json) {
        return ProviderCommandsPage.deliveryRow(PAGE, 'provider-commands',
                                                 row, t);
      }).join('')
      : '<tr><td colspan="5" class="sub">' +
        t.html('consoleProviderCommands.noDeliveries') + '</td></tr>';
    const th = function (key: string): string {
      return '<th>' + t.html(key) + '</th>';
    };
    // The issuer is a <code> with an id, which a message may not carry, so
    // the note ends in code; `on`/`off` are words of the page, selected by
    // the view's two booleans (#539).
    return kit.note(t.html('consoleProviderCommands.note',
                           { enabled: json.enabled ? 'on' : 'off',
                             automatic: json.automatic ? 'on' : 'off' }) +
        '<code id="command-issuer">' +
        (json.issuer ? esc(json.issuer)
                     : t.html('consoleProviderCommands.noIssuer')) +
        '</code>.') +
      '<table><thead><tr>' + th('consoleProviderCommands.colClient') +
      '<th>command_endpoint</th>' +
      th('consoleProviderCommands.colSupports') +
      '<th></th></tr></thead><tbody>' +
      clients + '</tbody></table>' + send +
      '<h3>' + t.html('consoleProviderCommands.accountsHeading') + '</h3>' +
      '<table><thead><tr>' + th('consoleProviderCommands.colClient') +
      th('consoleProviderCommands.colPerson') +
      th('consoleProviderCommands.colState') +
      th('consoleProviderCommands.colLastCommand') +
      th('consoleProviderCommands.colWhen') + '</tr></thead><tbody>' +
      accounts + '</tbody></table><h3>' +
      t.html('consoleProviderCommands.runsHeading') + '</h3><table><thead>' +
      '<tr>' + th('consoleProviderCommands.colClient') +
      th('consoleProviderCommands.colCommand') +
      th('consoleProviderCommands.colState') +
      th('consoleProviderCommands.colProgress') +
      th('consoleProviderCommands.colStarted') +
      '</tr></thead><tbody>' + runs + '</tbody></table>' +
      '<h3>' + t.html('consoleProviderCommands.deliveriesHeading') +
      '</h3><table><thead><tr>' + th('consoleProviderCommands.colClient') +
      th('consoleProviderCommands.colCommand') +
      th('consoleProviderCommands.colState') +
      th('consoleProviderCommands.colQueued') +
      '<th></th></tr></thead><tbody>' +
      deliveries + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/commands</code> · <a href="' + DELIVERIES +
      '">' + t.html('consoleProviderCommands.everyDelivery') + '</a></p>';
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
    const t = ctx.t;
    const state = String(ctx.query.state || '');
    const filter = '<form method="get" action="' + DELIVERIES + '" ' +
      'class="inline"><label>' + t.html('consoleProviderCommands.state') +
      ' <select name="state"><option value="">' +
      t.html('consoleProviderCommands.everyState') + '</option>' +
      json.states.map(function (s: string) {
        return '<option' + (s === state ? ' selected' : '') + '>' + esc(s) +
          '</option>';
      }).join('') + '</select></label> <button type="submit">' +
      t.html('consoleProviderCommands.show') + '</button>' +
      '</form>';
    const kinds = json.kinds.map(function (k: Json) {
      const rows = k.rows.length ? k.rows.map(function (row: Json) {
        return ProviderCommandsPage.deliveryRow(DELIVERIES, k.id, row, t);
      }).join('') : '<tr><td colspan="5" class="sub">' +
        (state ? t.html('consoleProviderCommands.nothingIn',
                        { state: state })
               : t.html('consoleProviderCommands.nothing')) + '</td></tr>';
      return '<h3 id="kind-' + esc(k.id) + '">' + esc(k.title) + '</h3>' +
        '<p class="sub">' +
        t.html('consoleProviderCommands.counts',
               { pending: k.counts.pending, sent: k.counts.sent,
                 dead: k.counts.dead }) +
        ' · <a href="' + esc(k.page) + '">' + esc(k.page) +
        '</a></p><table><thead><tr><th>' +
        t.html('consoleProviderCommands.colClient') + '</th><th>' +
        t.html('consoleProviderCommands.colWhat') + '</th><th>' +
        t.html('consoleProviderCommands.colState') + '</th><th>' +
        t.html('consoleProviderCommands.colQueued') +
        '</th><th></th></tr></thead><tbody>' + rows +
        '</tbody></table>';
    }).join('');
    return kit.note(t.html('consoleProviderCommands.deliveriesNote')) +
      filter + kinds + '<p class="links"><a href="' + DELIVERIES +
      '?format=json">JSON</a> · <code>GET /admin-api/deliveries</code></p>';
  }
}

export = ProviderCommandsPage;
