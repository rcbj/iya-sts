// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: provider_commands_api.ts
//
// ===========================================================================
// `/admin-api/commands` and `/admin-api/deliveries` (#151, 2026-09-26):
// `/admin/commands` and `/admin/deliveries` for a machine (rule 7). What each
// page draws, and each page's acts — the console's own functions
// (`provider_commands.ts`'s `report()` and `act()`, `outbound_delivery.ts`'s
// `kindReport()` and `kindRetry()`). Never a token or a body. Registers no
// route: `mgmt-api/admin_api.ts` spreads ROUTES into its table.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import ResponseModelKit = require('../common/response_model_kit');

type Req = any;
type Res = any;
type Json = any;

interface ProviderCommandsApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  loadCommands(): Json;
  loadViews(): Json;
  loadOutbound(): Json;
}

const BASE = '/admin-api';

// The closed sets, declared as enums so both doors enforce them (#86).
const ACCOUNT_COMMANDS = ['activate', 'maintain', 'suspend', 'reactivate',
  'archive', 'restore', 'delete', 'audit', 'invalidate', 'migrate'];
const ACCOUNT_ENUM = ACCOUNT_COMMANDS.concat(ACCOUNT_COMMANDS.map(
  function (one: string): string {
    return one + '_async';
  }));
const TENANT_ENUM = ['metadata', 'audit_tenant', 'suspend_tenant',
                     'archive_tenant', 'delete_tenant', 'invalidate_tenant'];

/**
 * The `/admin-api/commands` and `/admin-api/deliveries` operations: what each
 * console page draws and each page's acts, through the console's own functions.
 */
class ProviderCommandsApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, base URL reader, error codes and
   *   lazy loaders of the command module and the outbound queue
   */
  constructor(private readonly deps: ProviderCommandsApiDeps) {
    deps.log.debug("Entering ProviderCommandsApi.constructor().");
    deps.log.debug("Leaving ProviderCommandsApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports, with the
   * modules it serves loaded lazily.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ProviderCommandsApiDeps {
    helpers.log.debug("Entering ProviderCommandsApi.defaultDeps().");
    helpers.log.debug("Leaving ProviderCommandsApi.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes,
      loadCommands: function (): Json {
        return require('./provider_commands');
      },
      loadOutbound: function (): Json {
        return require('./outbound_delivery');
      },
      // The console's paging, required lazily for the modules' reason.
      loadViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: ProviderCommandsApi): void {
    helpers.log.debug("Entering ProviderCommandsApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving ProviderCommandsApi.wire().");
  }

  /**
   * Sends a JSON body with `Cache-Control: no-store`.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body, serialised with indentation
   */
  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering ProviderCommandsApi.sendJson(). status=" + status);
    // Not only at the top: a delivery's row carries one too (#1355).
    const reply = Object.assign({}, ResponseModelKit.actAnswer(res, body));
    delete reply.errorCode;
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving ProviderCommandsApi.sendJson().");
  }

  // ---------------------------------------------------------------------------
  // BOTH PAGES' LISTS, PAGED (#313's sweep, 2026-10-12).
  //
  // `/admin/commands` drew its accounts and deliveries cut at 500 and its
  // runs at 100, silently, and `/admin/deliveries` each kind at 200: a row
  // past the cut could not be reached from the page or from this API. The
  // two reports now answer whole and these two views page them — one
  // parameter per list, one shared `per` — so the page, which is drawn from
  // this answer, and a caller read the same slice. Counts are over the
  // whole lists.
  // ---------------------------------------------------------------------------
  /**
   * The page parameter of one delivery kind's table: its id in camel case,
   * `backchannel-logout` moving on `backchannelLogoutPage`.
   *
   * @param id - the kind's id
   * @returns the parameter's name
   */
  static kindParam(id: string): string {
    helpers.log.debug("Entering ProviderCommandsApi.kindParam().");
    helpers.log.debug("Leaving ProviderCommandsApi.kindParam().");
    return ProviderCommandsApi.kindName(id) + 'Page';
  }

  /**
   * One delivery kind's list name, its id in camel case.
   *
   * @param id - the kind's id
   * @returns the name `pagingOf()` takes
   */
  static kindName(id: string): string {
    helpers.log.debug("Entering ProviderCommandsApi.kindName().");
    helpers.log.debug("Leaving ProviderCommandsApi.kindName().");
    return String(id || '').replace(/-([a-z])/g, function (all: string,
                                                         c: string): string {
      return c.toUpperCase();
    });
  }

  /**
   * Builds `/admin/commands`' answer, each of its four lists one page.
   *
   * @param query - the request's query
   * @returns the report, paged
   */
  commandsView(query: Json): Json {
    const { log, loadCommands, loadViews } = this.deps;
    log.debug("Entering ProviderCommandsApi.commandsView().");
    const views = loadViews();
    const report = loadCommands().report({ q: query.q, state: query.state });
    const out = Object.assign({}, report, {
      // Every client's id, for the two send forms' menus: a menu built from
      // the page would offer only the clients on it.
      clientIds: report.clients.map(function (c: Json): string {
        return c.clientId;
      }),
      listCounts: {}, paging: {}
    });
    ['clients', 'accounts', 'runs', 'deliveries'].forEach(function (name) {
      const page = views.pagedRows(query, report[name] || [],
                                   { name: name, noun: name });
      out[name] = page.shown;
      out.listCounts[name] = (report[name] || []).length;
      out.paging[name] = views.pagingJson(page.paging);
    });
    log.debug("Leaving ProviderCommandsApi.commandsView().");
    return out;
  }

  /**
   * Builds `/admin/deliveries`' answer, each kind's rows one page.
   *
   * @param query - the request's query
   * @returns the kinds, each paged, and the states
   */
  deliveriesView(query: Json): Json {
    const { log, loadOutbound, loadViews } = this.deps;
    log.debug("Entering ProviderCommandsApi.deliveriesView().");
    const views = loadViews();
    const report = loadOutbound().kindReport({ state: query.state,
                                               q: query.q, kind: query.kind });
    const kinds = report.kinds.map(function (k: Json): Json {
      const page = views.pagedRows(query, k.rows || [],
        { name: ProviderCommandsApi.kindName(k.id), noun: 'deliveries' });
      return Object.assign({}, k, { rows: page.shown,
        matched: (k.rows || []).length,
        paging: views.pagingJson(page.paging) });
    });
    log.debug("Leaving ProviderCommandsApi.deliveriesView(). " +
              kinds.length + " kind(s).");
    return Object.assign({}, report, { kinds: kinds });
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadCommands, loadOutbound,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommandsApi.buildRoutes().");
    const answer = function (res: Res, result: Json, code: string): void {
      if (!result.ok) {
        // error-code: none — the act's own code, read off the result
        errorCodes.mark(res, errorCodes.codeOf(result) || code);
      }
      // error-code: none — marked above: the act's own code, or `code`.
      self.sendJson(res, result.ok ? 200 : 400, result);
    };
    const ROUTES = [
      { method: 'GET', path: BASE + '/commands',
        tag: 'OAuth 2.0 / OIDC', operationId: 'getProviderCommands',
        mirrors: 'GET /admin/commands',
        parameters: ['clients', 'accounts', 'runs', 'deliveries']
          .map(function (name: string): Json {
            return { name: name + 'Page', in: 'query', required: false,
                     schema: { type: 'integer', minimum: 1, examples: [1] },
                     description: 'Which page of `' + name + '`. Each list ' +
                       'moves on its own parameter and they share `per`.' };
          }).concat([
            { name: 'state', in: 'query', required: false,
              schema: { type: 'string', maxLength: 16, examples: ['pending'] },
              description: 'Only deliveries in this state: pending, ' +
                           'sent or dead.' },
            { name: 'q', in: 'query', required: false,
              schema: { type: 'string', maxLength: 256, examples: ['alice'] },
              description: 'Narrows the deliveries.' },
            { name: 'per', in: 'query', required: false,
              schema: { type: 'integer', minimum: 1, examples: [10] },
              description: 'Rows per page of each list, capped.' }]),
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API commands endpoint.");
          self.sendJson(res, 200, self.commandsView(req.query || {}));
          log.debug("Leaving the management API commands endpoint.");
        } },

      { method: 'POST', route: BASE + '/commands/:action',
        tag: 'OAuth 2.0 / OIDC', mirrors: 'POST /admin/commands',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API commands action.");
          let result: Json;
          try {
            const body = Object.assign({}, parseBody(req),
              { action: String(req.params.action || '') });
            result = loadCommands().act(body, { via: 'api',
              actor: 'admin-api', base: baseUrlOf(req) });
          } catch (e: any) {
            log.error(errorCodes.tag('STS-OAUTH-0776') + 'provider ' +
                      'commands: an /admin-api action failed: ' +
                      ((e && e.stack) || e));
            result = { ok: false, errors: ['The action could not be ' +
                                           'completed.'] };
          }
          answer(res, result, 'STS-OAUTH-0776');
          log.debug("Leaving the management API commands action. ok=" +
                    result.ok);
        },
        actions: [
          { action: 'send-account', operationId: 'sendAccountCommand'
             },
          { action: 'send-tenant', operationId: 'sendTenantCommand'
             },
          { action: 'retry-delivery', operationId: 'retryCommandDelivery'
             }
        ] },

      { method: 'GET', path: BASE + '/deliveries',
        tag: 'Monitoring', operationId: 'getOutboundDeliveries',
        mirrors: 'GET /admin/deliveries',
        parameters: [
          { name: 'state', in: 'query', required: false,
            schema: { type: 'string', maxLength: 16, examples: ['pending'] },
            description: 'Only deliveries in this state: pending, sent or ' +
                         'dead; empty for every state.' },
          { name: 'kind', in: 'query', required: false,
            schema: { type: 'string', maxLength: 64 },
            description: 'Only this kind.' },
          { name: 'q', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256, examples: ['alice'] },
            description: 'Narrows the deliveries.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [10] },
            description: 'Rows per page of each kind, capped.' }
        ].concat(loadOutbound().KINDS
          .map(ProviderCommandsApi.kindParam)
          .map(function (name: string): Json {
            return { name: name, in: 'query', required: false,
                     schema: { type: 'integer', minimum: 1, examples: [1] },
                     description: 'Which page of one kind\'s rows; each ' +
                       'kind moves on its own parameter, its `paging.param`.' };
          })),
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API deliveries endpoint.");
          self.sendJson(res, 200, self.deliveriesView(req.query || {}));
          log.debug("Leaving the management API deliveries endpoint.");
        } },

      { method: 'POST', route: BASE + '/deliveries/:action',
        tag: 'Monitoring', mirrors: 'POST /admin/deliveries',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API deliveries action.");
          const body = parseBody(req) || {};
          const result = String(req.params.action || '') === 'retry'
            ? loadOutbound().kindRetry(String(body.kind || ''),
                                       String(body.delivery || ''),
                                       'admin-api')
            : { ok: false, errors: ['Unknown action "' +
                String(req.params.action || '') + '". The 1 is: retry.'] };
          answer(res, result, 'STS-OAUTH-0774');
          log.debug("Leaving the management API deliveries action. ok=" +
                    result.ok);
        },
        actions: [
          { action: 'retry', operationId: 'retryOutboundDelivery'
             }
        ] }
    ];
    log.debug("Leaving ProviderCommandsApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<ProviderCommandsApi>(
  'oauth-oidc/provider_commands_api',
  () => new ProviderCommandsApi(ProviderCommandsApi.defaultDeps()),
  ProviderCommandsApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The OpenID Provider Commands and outbound delivery operations of `/admin-api`
 * (#151).
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  ProviderCommandsApi: ProviderCommandsApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: ProviderCommandsApi): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * The installed instance's route table, which `mgmt-api/admin_api.ts` spreads
   * into its own.
   */
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
