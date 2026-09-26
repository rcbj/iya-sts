'use strict';
//
// File: provider_commands_admin.ts
//
// ===========================================================================
// TWO CONSOLE PAGES (#151, 2026-09-26):
//
// **`/admin/commands` — OPENID PROVIDER COMMANDS.** Every client that
// registered a `command_endpoint` and what its `metadata` answer said it
// supports; sending an account command about a person and a tenant command
// about everybody; the account-state register (what each relying party said
// about each person); the tenant runs; the command deliveries with their
// dead letters. Its twin is `/admin-api/commands` (`provider_commands_api.ts`,
// rule 7); both call `provider_commands.ts`'s `report()` and `act()`.
//
// **`/admin/deliveries` — MONITORING → OUTBOUND DELIVERIES.** The shared
// outbound queue (`outbound_delivery.ts`) by kind — Back-Channel Logout
// Tokens, CIBA pings and pushes, OpenID Provider Commands — with each kind's
// counts, its rows, a filter by state, and Retry on a dead letter. Its twin
// is `/admin-api/deliveries`.
//
// Neither shows a token or a body.
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import providerCommands = require('./provider_commands');
import outbound = require('./outbound_delivery');

type Json = any;

const esc = admin.esc;
const PAGE = '/admin/commands';
const DELIVERIES = '/admin/deliveries';

interface ProviderCommandsAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  commands: typeof providerCommands;
  outbound: typeof outbound;
  adminViews: () => Json;
}

class ProviderCommandsAdmin {
  static readonly PAGE = PAGE;
  static readonly DELIVERIES = DELIVERIES;

  constructor(private readonly deps: ProviderCommandsAdminDeps) {
    deps.log.debug("Entering ProviderCommandsAdmin.constructor().");
    deps.log.debug("Leaving ProviderCommandsAdmin.constructor().");
  }

  static defaultDeps(): ProviderCommandsAdminDeps {
    helpers.log.debug("Entering ProviderCommandsAdmin.defaultDeps().");
    helpers.log.debug("Leaving ProviderCommandsAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes, admin: admin,
      commands: providerCommands, outbound: outbound,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering ProviderCommandsAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in ProviderCommandsAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving ProviderCommandsAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // One small form: hidden fields and a button.
  static form(page: string, action: string, fields: Json, label: string,
              danger?: boolean): string {
    helpers.log.debug("Entering ProviderCommandsAdmin.form(). " + action);
    helpers.log.debug("Leaving ProviderCommandsAdmin.form().");
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
  static deliveryRow(page: string, kind: string, row: Json): string {
    helpers.log.debug("Entering ProviderCommandsAdmin.deliveryRow().");
    const what = row.command ? '<code>' + esc(row.command) + '</code>' +
      (row.username ? ' ' + esc(row.username) : '') :
      (row.mode ? esc(row.mode) + ' ' + esc(row.authReqId || '') :
       'session <code>' + esc(row.sessionId || '') + '</code>');
    helpers.log.debug("Leaving ProviderCommandsAdmin.deliveryRow().");
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
        ? ProviderCommandsAdmin.form(page, 'retry', { kind: kind,
            delivery: row.id }, 'Retry')
        : '') + '</td></tr>';
  }

  // /admin/commands' body, from `report()`.
  commandsBody(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering ProviderCommandsAdmin.commandsBody().");
    const form = ProviderCommandsAdmin.form;
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
        return ProviderCommandsAdmin.deliveryRow(PAGE, 'provider-commands',
                                                 row);
      }).join('')
      : '<tr><td colspan="5" class="sub">No command has been sent.</td></tr>';
    log.debug("Leaving ProviderCommandsAdmin.commandsBody().");
    return admin.note('<strong>OpenID Provider Commands 1.0.</strong> ' +
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
  deliveriesBody(json: Json, state: string): string {
    const { log, admin } = this.deps;
    log.debug("Entering ProviderCommandsAdmin.deliveriesBody().");
    const filter = '<form method="get" action="' + DELIVERIES + '" ' +
      'class="inline"><label>State <select name="state"><option value="">' +
      'every state</option>' + json.states.map(function (s: string) {
        return '<option' + (s === state ? ' selected' : '') + '>' + esc(s) +
          '</option>';
      }).join('') + '</select></label> <button type="submit">Show</button>' +
      '</form>';
    const kinds = json.kinds.map(function (k: Json) {
      const rows = k.rows.length ? k.rows.map(function (row: Json) {
        return ProviderCommandsAdmin.deliveryRow(DELIVERIES, k.id, row);
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
    log.debug("Leaving ProviderCommandsAdmin.deliveriesBody().");
    return admin.note('<strong>Every outbound delivery</strong> this ' +
        'service POSTs to an address a client registered, on the one ' +
        'durable queue: each is a persisted row, attempted once for the ' +
        'cluster under a claimed lease, retried with backoff when a timeout, ' +
        'a connection failure, 5xx, 408 or 429 makes that worth it, and a ' +
        '<strong>dead letter</strong> otherwise — sent again only when an ' +
        'operator presses Retry, which starts a new generation.') +
      filter + kinds + '<p class="links"><a href="' + DELIVERIES +
      '?format=json">JSON</a> · <code>GET /admin-api/deliveries</code></p>';
  }

  registerRoutes(app: Json): void {
    const { log, parseBody, admin, commands, errorCodes, outbound,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommandsAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin commands page.");
      const json = commands.report({ q: req.query.q, state: req.query.state });
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.commandsBody(json);
      admin.respond(req, res, json, 'OpenID Provider Commands', PAGE, inner);
      log.debug("Leaving the admin commands page.");
    });
    app.post(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin commands action.");
      let result: Json;
      try {
        const body = parseBody(req) || {};
        result = body.action === 'retry'
          ? outbound.kindRetry(String(body.kind || 'provider-commands'),
                               String(body.delivery || ''),
                               self.actorOf(req))
          : commands.act(body, { via: 'console', actor: self.actorOf(req),
                                 base: baseUrlOf(req) });
      } catch (e: any) {
        log.error(errorCodes.tag('STS-OAUTH-0776') + 'provider commands: a ' +
                  'console action failed: ' + ((e && e.stack) || e));
        result = errorCodes.mark({ ok: false, errors:
          ['The action could not be completed.'] }, 'STS-OAUTH-0776');
      }
      admin.respondToAction(req, res, PAGE, result);
      log.debug("Leaving the admin commands action.");
    });
    app.get(DELIVERIES, function (req: Json, res: Json): void {
      log.debug("Entering the admin deliveries page.");
      const state = String(req.query.state || '');
      const json = outbound.kindReport({ state: state, q: req.query.q,
                                         kind: req.query.kind });
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.deliveriesBody(json, state);
      admin.respond(req, res, json, 'Outbound deliveries', DELIVERIES, inner);
      log.debug("Leaving the admin deliveries page.");
    });
    app.post(DELIVERIES, function (req: Json, res: Json): void {
      log.debug("Entering the admin deliveries action.");
      const body = parseBody(req) || {};
      const result = String(body.action || '') === 'retry'
        ? outbound.kindRetry(String(body.kind || ''),
                             String(body.delivery || ''), self.actorOf(req))
        : errorCodes.mark({ ok: false, errors: ['Unknown action "' +
            String(body.action || '') + '". The 1 is: retry.'] },
            'STS-OAUTH-0774');
      admin.respondToAction(req, res, DELIVERIES, result);
      log.debug("Leaving the admin deliveries action.");
    });
    log.debug("Leaving ProviderCommandsAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<ProviderCommandsAdmin>(
  'oauth-oidc/provider_commands_admin',
  () => new ProviderCommandsAdmin(ProviderCommandsAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  ProviderCommandsAdmin: ProviderCommandsAdmin,
  installInstance: (instance: ProviderCommandsAdmin): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  DELIVERIES: DELIVERIES
};
