// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: est_api.ts
//
// ---------------------------------------------------------------------------
// THE THREE /admin-api OPERATIONS FOR EST (2026-09-13).
//
// Rows in `mgmt-api/admin_api.ts`'s own shape, spread into its `ROUTES` by the
// integrator, so that the registration loop there — the ajv body schemas, the
// token gate, the OpenAPI document, the `mirrors` join that adds a Protocols
// page's endpoints — treats them exactly as it treats every other operation.
// This file registers no route.
//
// **THE VIEW MODEL IS REQUIRED LAZILY, INSIDE EACH HANDLER** (rule 1): this
// file is required by the management API at 19, and `est_console.ts` is
// loaded with the family at 23f. A lazy require keeps that true by
// construction.
//
// **`issue-server-key` RETURNS A PRIVATE KEY, ONCE, IN THE JSON.** That is the
// operation: a machine that asked this service to generate a key pair has no
// other way to receive it. The reply is `Cache-Control: no-store`, the audit
// row the core writes names the serial and never the key, and the sealed copy
// on the entry is not readable through any view.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `EstApi` takes the modules it uses through its constructor
// (`EstApiDeps`). Since #50's R2 the composition root builds the instance
// (`EstApi.defaultDeps()`) and installs it; the module's old export names are
// FACADES that forward to it, for the JavaScript callers, and a process without
// the root builds a default when the module finishes loading. `EstApi` is
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
// The key algorithm ids an enrollment may name (#86): the vendored registry,
// a leaf that requires nothing of this service.
import keyMaterial = require('../common/crypto_impl/key_material');

// THE PROFILE IS DELIBERATELY NOT AN ENUM (#86). It is a closed set, and
// the handler (`common/cert_enrollment.ts`'s checkProfile()) holds it — and
// says WHY for the five it refuses on purpose: `root-ca` is a trust anchor,
// and a caller who asked for one needs that sentence, not "not one of the 9
// values". The validator runs first, so an enum here would replace it; this
// is the one case #86 found where the handler's refusal is the better one.

const BASE = '/admin-api';

// What `EstApi` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface EstApiDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadEstConsole(): typeof import('./est_console');
}

/**
 * The management API's operations for EST: `GET /admin-api/est`, `GET
 * /admin-api/est/monitor` and `POST /admin-api/est/:action`, as rows
 * `mgmt-api/admin_api.ts` spreads into its table. It registers no route.
 *
 * `issue-server-key` returns a private key once, in the JSON.
 */
class EstApi {
  /**
   * Builds the API from its dependencies.
   *
   * @param deps - the modules it reads, from `EstApi.defaultDeps()` or the
   * composition root
   */
  constructor(private readonly deps: EstApiDeps) {
    deps.log.debug("Entering EstApi.constructor().");
    deps.log.debug("Leaving EstApi.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the real modules the API depends on, as the composition root passes
   * them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): EstApiDeps {
    helpers.log.debug("Entering EstApi.defaultDeps().");
    helpers.log.debug("Leaving EstApi.defaultDeps().");
    return {
      log: log,
      parseBody: parseBody,
      errorCodes: errorCodes,
      loadEstConsole: function () {
        return require('./est_console');
      }
    };
  }

  // What loading this module did with its instance before R2, run once
  // for whichever instance is installed (#50, R2).
  /**
   * Builds the installed instance's route table into the module's `ROUTES`.
   *
   * @param instance - the installed instance
   */
  static wire(instance: EstApi): void {
    helpers.log.debug("Entering EstApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving EstApi.wire().");
  }

  // `admin_api.js`'s `sendJson()`, which is not exported: the same answer, and
  // the same `protocolEndpoints` member for the GET that mirrors a Protocols
  // page (the registration loop computes it onto `res.locals`).
  /**
   * Sends a JSON answer with `Cache-Control: no-store`, adding the Protocols
   * page's endpoints to a successful GET that mirrors one.
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
    log.debug("Entering EstApi.sendJson(). status=" + status);
    let reply = body;
    const rows = res.locals && res.locals.protocolEndpoints;
    if (rows && status === 200 && body && typeof body === 'object' &&
        !Array.isArray(body)) {
      reply = Object.assign({}, body, { protocolEndpoints: rows });
    }
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving EstApi.sendJson().");
  }

  /**
   * Returns the JSON schema of the `kind` property: `person` or `application`.
   *
   * @returns the schema
   */
  kindProperty() {
    const { log } = this.deps;
    log.debug("Entering EstApi.kindProperty().");
    log.debug("Leaving EstApi.kindProperty().");
    return { type: 'string', enum: ['person', 'application'],
             description: 'Whether `identifier` names a person (a username) ' +
                          'or an application (its identifier).' };
  }

  /**
   * Builds the route table: the EST report, the monitor, and the actions
   * `issue-server-key`, `revoke-certificate`, `add-host-name` and
   * `remove-host-name`.
   *
   * @returns the routes
   */
  buildRoutes() {
    const { log, loadEstConsole, parseBody, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering EstApi.buildRoutes().");
    const ROUTES: IyaApi.AdminRow[] = [
      { method: 'GET', path: BASE + '/est', tag: 'EST', operationId: 'getEst',
        parameters: [
          { name: 'certificatesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page of enrolled certificates.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [10] },
            description: 'Rows per page.' }
        ],
        mirrors: 'GET /admin/cert-issuance',
        handler: function (req, res) {
          log.debug("Entering the management API EST endpoint.");
          self.sendJson(res, 200, loadEstConsole().estView(req));
          log.debug("Leaving the management API EST endpoint.");
        } },

      { method: 'GET', path: BASE + '/est/monitor', tag: 'EST',
        operationId: 'getEstMonitor',
        parameters: [
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page of recent requests.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [10] },
            description: 'Rows per page.' }
        ],
        mirrors: 'GET /admin/est/monitor',
        handler: function (req, res) {
          log.debug("Entering the management API EST monitor endpoint.");
          self.sendJson(res, 200, loadEstConsole().estMonitorView(req));
          log.debug("Leaving the management API EST monitor endpoint.");
        } },

      ApiRows.actions({ method: 'POST',
        route: BASE + '/est/:action', tag: 'EST',
        mirrors: 'POST /admin/est',
        handler: function (req, res) {
          log.debug("Entering the management API EST action endpoint.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          loadEstConsole().estAction(body, { via: 'api', req: req })
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res,
                                errorCodes.codeOf(result) || 'STS-EST-0033');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API EST action endpoint. ok=" +
                        !!result.ok);
            }, function (e) {
              log.error(errorCodes.tag('STS-EST-0020') +
                        'est api: the action failed: ' + ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-EST-0020');
              self.sendJson(res, 500,
                            { ok: false, errors: ['The action could not be ' +
                                                            'completed.'] });
              log.debug("Leaving the management API EST action endpoint. " +
                        "Threw.");
            });
        },
        actions: [
          { action: 'issue-server-key', operationId: 'issueEstServerKey' },
          { action: 'revoke-certificate', operationId: 'revokeEstCertificate' },
          { action: 'add-host-name', operationId: 'addEstHostName' },
          { action: 'remove-host-name', operationId: 'removeEstHostName' }
        ] })
    ];
    log.debug("Leaving EstApi.buildRoutes().");
    return ROUTES;
  }
}

// The table `buildRoutes()` made for the installed instance, filled by
// `wire()` and read through the `ROUTES` getter below.
type Routes = ReturnType<EstApi['buildRoutes']>;
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
const slot = new InstanceSlot<EstApi>(
  'est/est_api',
  () => new EstApi(EstApi.defaultDeps()),
  EstApi.wire,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The management API's EST operations.
 *
 * Exports the `EstApi` class, the route table, and facades for the installed
 * instance.
 *
 * @namespace
 */
export = {
  EstApi: EstApi,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: EstApi): void => slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  // A GETTER, so the table is the installed instance's: under the root it is
  // built when the root installs that instance, and `mgmt-api/admin_api.ts`
  // reads it after that.
  /**
   * The route table `mgmt-api/admin_api.ts` spreads into its own.
   */
  get ROUTES(): Routes {
    log.debug("Entering ROUTES().");
    slot.get();
    log.debug("Leaving ROUTES().");
    return routes;
  }
};
