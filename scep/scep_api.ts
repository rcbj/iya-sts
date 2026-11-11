// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scep_api.ts
//
// ---------------------------------------------------------------------------
// THE SCEP OPERATIONS OF /admin-api (2026-09-13): three rows, spread into
// `mgmt-api/admin_api.ts`'s ROUTES.
//
//   GET  /admin-api/scep           mirrors GET  /admin/scep
//   GET  /admin-api/scep/monitor   mirrors GET  /admin/scep/monitor
//   POST /admin-api/scep/:action   mirrors POST /admin/scep (six actions)
//
// **IT REGISTERS NO ROUTE AND REQUIRES THE VIEW MODEL LAZILY**, inside each
// handler, exactly as the GNAP rows reach `gnap_console.js`: the management API
// requires this file at 19 in the require order and SCEP is 23g, so a require
// at the top would load `scep_console.ts` — and through it the SCEP family's
// libraries — ahead of where the family is loaded (rule 1).
//
// It cannot use `admin_api.js`'s `sendJson()` or `withAction()`, because that
// module requires THIS one and a require back would close a cycle; the two
// small functions below are the same shape, including the
// `res.locals.protocolEndpoints` member the registration loop computes for a
// GET mirroring a Protocols page.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScepApi` takes the modules it uses through its constructor
// (`ScepApiDeps`). Since #50's R2 the composition root builds the instance
// (`ScepApi.defaultDeps()`) and installs it; the module's old export names are
// FACADES that forward to it, for the JavaScript callers, and a process without
// the root builds a default when the module finishes loading. `ScepApi` is
// exported beside them for the composition root.
//
// **THE TABLES WHOSE ENTRIES CALL THIS MODULE** (`ROUTES`) are built by
// `build…()` methods. Since R2 `wire()` builds the table when the instance is
// installed, and `ROUTES` is a getter over it: `mgmt-api/admin_api.ts` must
// read it only after the root has installed this module's instance (its own
// `wire()` does), or it builds a default here that the root then cannot
// replace.
// ---------------------------------------------------------------------------

// Types a row of actions by its own actions' operations (#1579).
import ApiRows = require('../common/api_rows');
import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');

// THE PROFILE IS DELIBERATELY NOT AN ENUM (#86). It is a closed set, and
// the handler (`common/cert_enrollment.ts`'s checkProfile()) holds it — and
// says WHY for the five it refuses on purpose: `root-ca` is a trust anchor,
// and a caller who asked for one needs that sentence, not "not one of the 9
// values". The validator runs first, so an enum here would replace it; this
// is the one case #86 found where the handler's refusal is the better one.

const BASE = '/admin-api';

// What `ScepApi` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface ScepApiDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadScepConsole(): typeof import('./scep_console');
}

/**
 * The SCEP operations of `/admin-api`: three route rows spread into the
 * management API's table, each answering out of the same view model as the
 * console pages.
 */
class ScepApi {
  /**
   * Builds the operations' owner.
   *
   * @param deps - the logger, the body parser, the error-code table and a lazy
   *   loader of `scep_console`
   */
  constructor(private readonly deps: ScepApiDeps) {
    deps.log.debug("Entering ScepApi.constructor().");
    deps.log.debug("Leaving ScepApi.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the modules the load-time instance is built from
   */
  static defaultDeps(): ScepApiDeps {
    helpers.log.debug("Entering ScepApi.defaultDeps().");
    helpers.log.debug("Leaving ScepApi.defaultDeps().");
    return {
      log: log,
      parseBody: parseBody,
      errorCodes: errorCodes,
      loadScepConsole: function () {
        return require('./scep_console');
      }
    };
  }

  // What loading this module did with its instance before R2, run once
  // for whichever instance is installed (#50, R2).
  /**
   * Builds the installed instance's route table, which the `ROUTES` getter
   * answers.
   *
   * @param instance - the installed instance
   */
  static wire(instance: ScepApi): void {
    helpers.log.debug("Entering ScepApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving ScepApi.wire().");
  }

  /**
   * Sends a JSON reply, uncached, adding the protocol endpoints the
   * registration loop computed to a successful object reply.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the reply
   */
  // TYPED BY THE OPERATION (#1579): through a handler's response, the
  // answer is held to the model's at a literal 2xx status
  // (`types/api-handlers.d.ts`).
  send<R, S extends number>(res: R, status: S,
       body: IyaApi.AnswerOf<R, S>): void;
  send(res: any, status: number, body: any): void {
    const { log } = this.deps;
    log.debug("Entering ScepApi.send(). status=" + status);
    const rows = res.locals && res.locals.protocolEndpoints;
    let reply = body;
    if (rows && status === 200 && body && typeof body === 'object' &&
        !Array.isArray(body)) {
      reply = Object.assign({}, body, { protocolEndpoints: rows });
    }
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving ScepApi.send().");
  }

  /**
   * Returns an OpenAPI schema for an object whose members are not listed.
   *
   * @param description - the schema's description
   * @returns the schema
   */
  openObject(description) {
    const { log } = this.deps;
    log.debug("Entering ScepApi.openObject().");
    log.debug("Leaving ScepApi.openObject().");
    return { type: 'object', additionalProperties: true,
             description: description };
  }

  /**
   * Builds the three route rows: `GET /admin-api/scep`, `GET
   * /admin-api/scep/monitor` and `POST /admin-api/scep/:action`, each with its
   * OpenAPI description and handler.
   *
   * @returns the rows
   */
  buildRoutes() {
    const { log, loadScepConsole, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering ScepApi.buildRoutes().");
    const ROUTES: IyaApi.AdminRow[] = [
      { method: 'GET', path: BASE + '/scep', tag: 'SCEP',
        operationId: 'getScep',
        mirrors: 'GET /admin/cert-issuance',
        parameters: [
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 1000,
                      examples: [10] },
            description: 'Rows per page, for both lists.' },
          { name: 'certificatesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'The page of the enrolled certificates.' },
          { name: 'credentialsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'The page of the challenge passwords.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API SCEP endpoint.");
          const model = loadScepConsole();
          const query = model.queryOf(req);
          if (!query.ok) {
            errorCodes.mark(res, 'STS-SCEP-0060');
            self.send(res, 400, { ok: false, errors: [query.detail] });
            log.debug("Leaving the management API SCEP endpoint. Bad query.");
            return;
          }
          self.send(res, 200, model.scepView(req));
          log.debug("Leaving the management API SCEP endpoint.");
        } },

      { method: 'GET', path: BASE + '/scep/monitor', tag: 'SCEP',
        operationId: 'getScepMonitor',
        mirrors: 'GET /admin/scep/monitor',
        parameters: [
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 1000,
                      examples: [10] },
            description: 'Rows per page of the recent requests.' },
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'The page of the recent requests.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API SCEP monitor endpoint.");
          const model = loadScepConsole();
          const query = model.queryOf(req, 'monitor');
          if (!query.ok) {
            errorCodes.mark(res, 'STS-SCEP-0060');
            self.send(res, 400, { ok: false, errors: [query.detail] });
            log.debug("Leaving the management API SCEP monitor endpoint. Bad.");
            return;
          }
          self.send(res, 200, model.scepMonitorView(req));
          log.debug("Leaving the management API SCEP monitor endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/scep/:action', tag: 'SCEP',
        mirrors: 'POST /admin/scep',
        handler: function (req, res) {
          log.debug("Entering the management API SCEP action endpoint.");
          const model = loadScepConsole();
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          return model.scepAction(body, { via: 'api', actor: 'admin-api',
                                          req: req })
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-SCEP-0061');
              }
              self.send(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API SCEP action endpoint.");
            })
            .catch(function (e) {
              log.error(errorCodes.tag('STS-SCEP-0061') +
                        'scep: an /admin-api ' +
                        'action failed: ' + ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-SCEP-0061');
              self.send(res, 400, { ok: false,
                                    errors:
                                      ['The action could not be completed.'] });
            });
        },
        actions: [
          { action: 'create-challenge', operationId: 'createScepChallenge' },
          { action: 'delete-challenge', operationId: 'deleteScepChallenge' },
          { action: 'reissue-ra', operationId: 'reissueScepRa' },
          { action: 'revoke-certificate', operationId: 'revokeScepCertificate' },
          { action: 'add-host-name', operationId: 'addScepHostName' },
          { action: 'remove-host-name', operationId: 'removeScepHostName' }
        ] })
    ];
    log.debug("Leaving ScepApi.buildRoutes().");
    return ROUTES;
  }
}

// The table `buildRoutes()` made for the installed instance, filled by
// `wire()` and read through the `ROUTES` getter below.
type Routes = ReturnType<ScepApi['buildRoutes']>;
let routes: Routes = null;

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ScepApi>(
  'scep/scep_api',
  () => new ScepApi(ScepApi.defaultDeps()),
  ScepApi.wire,
  helpers.log);

const ENTRY_PROPERTIES = {
  kind: { type: 'string', enum: ['person', 'application'],
          description: 'Whether the entry is a person or an application.' },
  identifier: { type: 'string', maxLength: 256,
                description: 'The username or the application identifier, ' +
                             'in this realm.' }
};

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The SCEP operations of `/admin-api`, mirroring the two SCEP console pages
 * (rule 7).
 *
 * It registers no route; `mgmt-api/admin_api.ts` reads `ROUTES`.
 *
 * @namespace
 */
export = {
  ScepApi: ScepApi,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: ScepApi): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  // A GETTER, so the table is the installed instance's: under the root it is
  // built when the root installs that instance, and `mgmt-api/admin_api.ts`
  // reads it after that.
  /**
   * The route rows of the installed instance.
   */
  get ROUTES(): Routes {
    log.debug("Entering ROUTES().");
    slot.get();
    log.debug("Leaving ROUTES().");
    return routes;
  }
};
