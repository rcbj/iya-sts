// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: acme_api.ts
//
// ---------------------------------------------------------------------------
// THE ACME OPERATIONS OF /admin-api (2026-09-13).
//
// Three operations mirroring the two pages `acme_admin.ts` draws and the six
// controls on the first of them, spread into `mgmt-api/admin_api.ts`'s table by
// the integrator. Both doors call `acme_console.ts` (rule 7).
//
// **THIS FILE REGISTERS NO ROUTE AND REQUIRES ITS VIEW MODEL LAZILY**, inside
// each handler: the management API is 19 in the require order and ACME is 23e,
// so a require at load would have registered every `/enroll/acme` route ahead
// of the management API's own (rule 1). Since #50's R1 requiring the family
// registers nothing — `common/protocol_stack.ts` registers its routes at 23e —
// but it would still load the family and its libraries at 19, ahead of where
// they are loaded. By the time a handler runs, the family has
// long been loaded and the require is a cache hit.
//
// Its `sendJson()` is the management API's, written again because this file
// cannot require that one back (it is the file that requires this): the
// realm's endpoints go on a successful answer to the GET that mirrors the
// Protocols page, which the registration loop computes onto `res.locals`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AcmeApi` takes the modules it uses through its constructor
// (`AcmeApiDeps`). Since #50's R2 the composition root builds the instance
// (`AcmeApi.defaultDeps()`) and installs it; the module's old export names are
// FACADES that forward to it, for the JavaScript callers, and a process without
// the root builds a default when the module finishes loading. `AcmeApi` is
// exported beside them for the composition root.
//
// **THE TABLES WHOSE ENTRIES CALL THIS MODULE** (`ROUTES`) are built by
// `build…()` methods. Since R2 `wire()` builds the table when the instance is
// installed, and `ROUTES` is a getter over it: `mgmt-api/admin_api.ts` must
// read it only after the root has installed this module's instance (its own
// `wire()` does), or it builds a default here that the root then cannot
// replace.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');

const BASE = '/admin-api';

// What `AcmeApi` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface AcmeApiDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadAcmeConsole(): typeof import('./acme_console');
}

/**
 * The ACME operations of `/admin-api`, mirroring the two console pages; both
 * doors call `acme_console.ts`.
 *
 * Registers no route: `mgmt-api/admin_api.ts` spreads its table into its own.
 */
class AcmeApi {
  /**
   * Creates the ACME operations.
   *
   * @param deps - the logger, the body parser, the error-code table and a lazy
   * loader of the console view model
   */
  constructor(private readonly deps: AcmeApiDeps) {
    deps.log.debug("Entering AcmeApi.constructor().");
    deps.log.debug("Leaving AcmeApi.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the dependencies
   */
  static defaultDeps(): AcmeApiDeps {
    helpers.log.debug("Entering AcmeApi.defaultDeps().");
    helpers.log.debug("Leaving AcmeApi.defaultDeps().");
    return {
      log: log,
      parseBody: parseBody,
      errorCodes: errorCodes,
      loadAcmeConsole: function () {
        return require('./acme_console');
      }
    };
  }

  // What loading this module did with its instance before R2, run once
  // for whichever instance is installed (#50, R2).
  /**
   * Builds the route table for the installed instance, the work loading this
   * module did before R2.
   *
   * @param instance - the instance installed
   */
  static wire(instance: AcmeApi): void {
    helpers.log.debug("Entering AcmeApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving AcmeApi.wire().");
  }

  /**
   * Sends a JSON answer, uncached, adding the realm's protocol endpoints to a
   * successful object answer when the registration loop computed them.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the answer
   */
  sendJson(res, status, body) {
    const { log } = this.deps;
    log.debug("Entering AcmeApi.sendJson(). status=" + status);
    const rows = res.locals && res.locals.protocolEndpoints;
    let out = body;
    if (rows && status === 200 && body && typeof body === 'object' &&
        !Array.isArray(body)) {
      out = Object.assign({}, body, { protocolEndpoints: rows });
    }
    // error-code: none — the status is a variable; each refusal below marks
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(out, null, 2));
    log.debug("Leaving AcmeApi.sendJson().");
  }

  /**
   * Returns the ACME console view model, required lazily.
   *
   * @returns the `acme_console` module
   */
  consoleModel() {
    const { log, loadAcmeConsole } = this.deps;
    log.debug("Entering AcmeApi.consoleModel().");
    log.debug("Leaving AcmeApi.consoleModel().");
    return loadAcmeConsole();
  }

  /**
   * Builds the table of ACME operations: method, path, OpenAPI description and
   * handler of each.
   *
   * @returns the operations
   */
  buildRoutes() {
    const { log, parseBody, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AcmeApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/acme', tag: 'ACME',
        operationId: 'getAcme',
        mirrors: 'GET /admin/cert-issuance',
        parameters: [
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 1000,
                      examples: [10] },
            description: 'Rows per page, shared by every list in the reply.' },
          { name: 'credentialsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page of the EAB keys.' },
          { name: 'accountsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page of the accounts.' },
          { name: 'certificatesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page of the certificates.' },
          { name: 'hostNamesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page of the entries with host names.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API ACME endpoint.");
          self.sendJson(res, 200, self.consoleModel().acmeView(req));
          log.debug("Leaving the management API ACME endpoint.");
        } },

      { method: 'GET', path: BASE + '/acme/monitor', tag: 'ACME',
        operationId: 'getAcmeMonitor',
        mirrors: 'GET /admin/acme/monitor',
        parameters: [
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, examples: [1] },
            description: 'Which page of the recent requests.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 1000,
                      examples: [10] },
            description: 'Rows per page.' }
        ],
        handler: function (req, res) {
          log.debug("Entering the management API ACME monitor endpoint.");
          self.sendJson(res, 200, self.consoleModel().acmeMonitorView(req));
          log.debug("Leaving the management API ACME monitor endpoint.");
        } },

      { method: 'POST', route: BASE + '/acme/:action', tag: 'ACME',
        mirrors: 'POST /admin/acme',
        handler: function (req, res) {
          log.debug("Entering the management API ACME action endpoint.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          Promise.resolve(self.consoleModel().acmeAction(body,
                                                         { via: 'api',
                                                             req: req }))
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res,
                                errorCodes.codeOf(result) || 'STS-ACME-0091');
              }
              self.sendJson(res, result.ok ? 200 : 400, result);
            }).catch(function (e) {
              log.error(errorCodes.tag('STS-ACME-0095') +
                        'acme management API ' +
                        'action threw: ' + ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-ACME-0095');
              self.sendJson(res, 500, { ok: false,
                                        errors: ['The action could not be ' +
                                                 'completed.'] });
            });
          log.debug("Leaving the management API ACME action endpoint.");
        },
        actions: [
          { action: 'create-eab', operationId: 'createAcmeEab' },
          { action: 'delete-eab', operationId: 'deleteAcmeEab' },
          { action: 'deactivate-account', operationId: 'deactivateAcmeAccount' },
          { action: 'revoke-certificate', operationId: 'revokeAcmeCertificate' },
          { action: 'add-host-name', operationId: 'addAcmeHostName' },
          { action: 'remove-host-name', operationId: 'removeAcmeHostName' }
        ] }
    ];
    log.debug("Leaving AcmeApi.buildRoutes().");
    return ROUTES;
  }
}

// The table `buildRoutes()` made for the installed instance, filled by
// `wire()` and read through the `ROUTES` getter below.
type Routes = ReturnType<AcmeApi['buildRoutes']>;
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
const slot = new InstanceSlot<AcmeApi>(
  'acme/acme_api',
  () => new AcmeApi(AcmeApi.defaultDeps()),
  AcmeApi.wire,
  helpers.log);

const KIND = { type: 'string', enum: ['person', 'application'],
               description: 'Whether the entry is a person (ou=users) or an ' +
                            'application (ou=applications).' };
const IDENTIFIER = { type: 'string', minLength: 1, maxLength: 256,
                     description: 'The username of a person, or the ' +
                                  'identifier of an application, in this ' +
                                  'realm.' };
const OBJECT = function (description) {
  return { type: 'object', additionalProperties: true,
           description: description };
};

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The ACME operations of the management API.
 *
 * Exports the class and the `ROUTES` table of the instance the composition root
 * built.
 *
 * @namespace
 */
export = {
  AcmeApi: AcmeApi,
  installInstance: (instance: AcmeApi): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // A GETTER, so the table is the installed instance's: under the root it is
  // built when the root installs that instance, and `mgmt-api/admin_api.ts`
  // reads it after that.
  /**
   * The ACME operations table of the installed instance, read by
   * `mgmt-api/admin_api.ts` after the root has installed it.
   */
  get ROUTES(): Routes {
    log.debug("Entering ROUTES().");
    slot.get();
    log.debug("Leaving ROUTES().");
    return routes;
  }
};
