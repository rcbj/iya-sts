// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: uma_api.ts
//
// ---------------------------------------------------------------------------
// THE /admin-api/uma OPERATIONS (#1168 phase 6, #1195), mirroring Protocols
// -> UMA (rule 7): what the page draws, its counts, and its nine acts, each
// `uma/uma_console.ts`'s — the console's own, since the static console sends
// its forms here. The page's settings are the configuration resource's, as
// every settings block's are.
//
// An application's OWNERS reach two of these as well (`mgmt-api/admin_api.ts`
// OWNER_OPERATIONS): `GET /uma?owner=<application>`, answered with the owner
// tab alone, and the four `owner-*` acts on that application's document —
// each asked of `access-control`'s owner rule first.
//
// It registers no route: `mgmt-api/admin_api.ts` spreads `ROUTES` into its
// table, as it does the AuthZEN operations'.
// ---------------------------------------------------------------------------

// Types a row of actions by its own actions' operations (#1579).
import ApiRows = require('../common/api_rows');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface UmaApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The page's library, lazily: UMA is built at 23d-ii and this module at
  // 19, and it is only asked inside a handler.
  loadConsole(): Json;
}

const BASE = '/admin-api';

const APPLICATION = { type: 'string', minLength: 1, maxLength: 256,
  description: 'The application\'s identifier.' };
const OWNER = { type: 'string', minLength: 1, maxLength: 256,
  description: 'The application whose document it is; it must carry ' +
               'umaOwnsResources TRUE.' };

/**
 * The `/admin-api/uma` operations: Protocols -> UMA and its acts.
 */
class UmaApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   page's library
   */
  constructor(private readonly deps: UmaApiDeps) {
    deps.log.debug("Entering UmaApi.constructor().");
    deps.log.debug("Leaving UmaApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): UmaApiDeps {
    helpers.log.debug("Entering UmaApi.defaultDeps().");
    helpers.log.debug("Leaving UmaApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadConsole: function (): Json {
        helpers.log.debug("Entering loadConsole().");
        helpers.log.debug("Leaving loadConsole().");
        return require('../uma/uma_console');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: UmaApi): void {
    helpers.log.debug("Entering UmaApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving UmaApi.wire().");
  }

  /**
   * Sends a JSON body with `Cache-Control: no-store`.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body
   */
  // TYPED BY THE OPERATION (#1579): through a handler's response, the
  // answer is held to the model's at a literal 2xx status
  // (`types/api-handlers.d.ts`).
  sendJson<R, S extends number>(res: R, status: S,
           body: IyaApi.AnswerOf<R, S>): void;
  sendJson(res: any, status: number, body: any): void {
    const { log } = this.deps;
    log.debug("Entering UmaApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving UmaApi.sendJson().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the rows
   */
  buildRoutes(): Json[] {
    const self = this;
    const { log, parseBody, loadConsole } = this.deps;
    log.debug("Entering UmaApi.buildRoutes().");
    const ROUTES: IyaApi.AdminRow[] = [
      { method: 'GET', path: BASE + '/uma', tag: 'UMA',
        operationId: 'getUma',
        mirrors: 'GET /admin/uma',
        parameters: [
          { name: 'resourceServer', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Narrows the registered resources to one resource ' +
                         'server.' },
          { name: 'owner', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'A username or application: adds that owner\'s ' +
            'resources, document and waiting requests.' },
          { name: 'resource', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'With `scope`, asks the what-if about this ' +
                         'resource.' },
          { name: 'scope', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The scope the what-if asks about.' },
          { name: 'party', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The requesting party of the what-if.' },
          { name: 'client', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'The client of the what-if.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Rows per page, shared by the four lists.' },
          { name: 'resourcesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `resources` to return.' },
          { name: 'ticketsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `tickets` to return.' },
          { name: 'rptsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `rpts` to return.' },
          { name: 'pendingPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of `pending` to return.' }
        ],
        handler: function (req, res): void {
          log.debug("Entering the management API UMA endpoint.");
          self.sendJson(res, 200, loadConsole().view(req));
          log.debug("Leaving the management API UMA endpoint.");
        } },
      { method: 'GET', path: BASE + '/uma/monitor', tag: 'UMA',
        operationId: 'getUmaMonitor',
        mirrors: 'GET /admin/uma#uma-tab-servers',
        handler: function (req, res): void {
          log.debug("Entering the management API UMA monitor endpoint.");
          self.sendJson(res, 200, loadConsole().monitorView());
          log.debug("Leaving the management API UMA monitor endpoint.");
        } },
      ApiRows.actions({ method: 'POST',
        route: BASE + '/uma/:action', tag: 'UMA',
        mirrors: 'POST /admin/uma',
        handler: function (req, res): void {
          log.debug("Entering the management API UMA action.");
          const body = Object.assign({}, parseBody(req),
            { action: String(req.params.action || '') });
          const verified = req.adminApiCaller || {};
          let result: Json;
          try {
            result = loadConsole().act(body, { via: 'api',
              actor: String(verified.name || body.actor || '') });
          } catch (e) {
            log.error(errorCodes.tag('STS-UMA-0500') + 'uma: an ' +
                      '/admin-api action failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-UMA-0500');
            self.sendJson(res, 500, { ok: false, errors:
                                        ['The action could not be ' +
                                         'completed.'] });
            log.debug("Leaving the management API UMA action. Threw.");
            return;
          }
          if (!result.ok) {
            // error-code: none — the act's own code, read off the result
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-UMA-0500');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API UMA action. ok=" +
                    result.ok);
        },
        actions: [
          { action: 'enable-resource-server',
            operationId: 'enableUmaResourceServer' },
          { action: 'disable-resource-server',
            operationId: 'disableUmaResourceServer' },
          { action: 'set-owns-resources',
            operationId: 'setUmaOwnsResources' },
          { action: 'delete-resource', operationId: 'deleteUmaResource' },
          { action: 'revoke-rpt', operationId: 'revokeUmaRpt' },
          { action: 'owner-share', operationId: 'shareUmaResource' },
          { action: 'owner-unshare', operationId: 'unshareUmaResource' },
          { action: 'owner-approve', operationId: 'approveUmaRequest' },
          { action: 'owner-refuse', operationId: 'refuseUmaRequest' }
        ] })
    ];
    log.debug("Leaving UmaApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<UmaApi>(
  'mgmt-api/uma_api',
  () => new UmaApi(UmaApi.defaultDeps()),
  UmaApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The UMA operations of `/admin-api` (#1195), mirroring Protocols -> UMA.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  UmaApi: UmaApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: UmaApi): void => slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * The installed instance's route table, which `mgmt-api/admin_api.ts`
   * spreads into its own.
   */
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
