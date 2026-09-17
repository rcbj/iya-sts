'use strict';
//
// File: oauth2_monitor_api.ts
//
// ---------------------------------------------------------------------------
// THE OAUTH 2.0 / OIDC MONITORING OPERATIONS OF /admin-api (2026-09-13).
//
// Two operations mirroring `/admin/oauth2/monitor` and the one control on it,
// spread into `mgmt-api/admin_api.ts`'s table beside ACME's, EST's and SCEP's.
// Both doors call `oauth2_monitor_console.ts` (rule 7).
//
// **THIS FILE REGISTERS NO ROUTE AND REQUIRES ITS VIEW MODEL LAZILY**, inside
// each handler, for `acme/acme_api.ts`'s reason: the model requires
// `admin-core/admin_views.ts`, which may be loaded at 18 or later and nowhere
// earlier. By the time a handler runs the page module has loaded it at 18f and
// the require is a cache hit.
//
// **THE CONTROL IS `POST /admin-api/oauth2/monitor/{action}`** rather than a
// resource of its own, which is this API's convention for a page's controls
// (`/acme/{action}`, `/gnap/{action}`): the resource a withdrawal changes is
// the page's list, so the GET that reads it back is the page's GET — the pair
// `sts_admin_api_operations.js`'s ledger asks for — and an unknown action is
// refused naming the one there is, the sentence the parity walks read.
//
// Its `sendJson()` is the management API's, written again because this file
// cannot require that one back (it is the file that requires this).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `OAuth2MonitorApi` takes the modules it uses through its
// constructor (`OAuth2MonitorApiDeps`), the view model among them as a
// LOADER so it is still required lazily, and the module still exports
// `ROUTES`, for `mgmt-api/admin_api.ts`. Since R2 the composition root builds
// the instance and installs it; `OAuth2MonitorApi.wire()` builds the table
// with `buildRoutes()` for that instance, and `ROUTES` is a getter over it.
// A process without the root builds a default instance, and the table, at
// load, where it was always declared.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface OAuth2MonitorApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // `oauth2_monitor_console.ts`, required when a handler runs.
  loadConsoleModel(): typeof import('./oauth2_monitor_console');
}

const BASE = '/admin-api';

class OAuth2MonitorApi {
  constructor(private readonly deps: OAuth2MonitorApiDeps) {
    deps.log.debug("Entering OAuth2MonitorApi.constructor().");
    deps.log.debug("Leaving OAuth2MonitorApi.constructor().");
  }

  // What the composition root passes: the deps the module built its own
  // instance from before R2 — the view model as a LOADER, so it is still
  // required lazily.
  static defaultDeps(): OAuth2MonitorApiDeps {
    helpers.log.debug("Entering OAuth2MonitorApi.defaultDeps().");
    helpers.log.debug("Leaving OAuth2MonitorApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadConsoleModel: function () {
        return require('./oauth2_monitor_console');
      }
    };
  }

  // The work loading this module did with its own instance before R2: the
  // route table, built once for whichever instance is installed.
  static wire(instance: OAuth2MonitorApi): void {
    helpers.log.debug("Entering OAuth2MonitorApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving OAuth2MonitorApi.wire().");
  }

  // error-code: none — the helper's definition, not a call to it.
  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorApi.sendJson(). status=" + status);
    // error-code: none — the status is a variable; each refusal below marks
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving OAuth2MonitorApi.sendJson().");
  }

  private consoleModel(): typeof import('./oauth2_monitor_console') {
    const { log, loadConsoleModel } = this.deps;
    log.debug("Entering OAuth2MonitorApi.consoleModel().");
    log.debug("Leaving OAuth2MonitorApi.consoleModel().");
    return loadConsoleModel();
  }

  private object(description: string): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorApi.object().");
    log.debug("Leaving OAuth2MonitorApi.object().");
    return { type: 'object', additionalProperties: true,
             description: description };
  }

  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/oauth2/monitor',
        tag: 'OAuth 2.0 / OIDC',
        operationId: 'getOauth2Monitor',
        summary: 'What the authorization server has done in this realm, ' +
                 'by mechanism, with the pushed authorization requests ' +
                 'still held',
        description: 'Everything /admin/oauth2/monitor draws, in SECTIONS ' +
          '— one per mechanism counted, RFC 9126 pushed authorization ' +
          'requests the first. Each section carries its events (the ' +
          'closed vocabulary with a label and a total each), the ' +
          'totals, the OAuth errors returned, one row per client_id ' +
          'with every counter (paged by `clientsPage` and `per`), and ' +
          '— for RFC 9126 — the pushed requests the store still ' +
          'holds, newest first: request_uri, client, authorization ' +
          'server, state, created and expiry, reads, whether and how ' +
          'the client authenticated, form or request object, the ' +
          'redirect_uri and whether section 2.4 let it in ' +
          'unregistered, the DPoP key, and the parameters. That ' +
          'list is paged by `offset` and `limit` (or the ' +
          'console\'s `page` and `per`) ' +
          'and filtered by `state` and `client_id`. RFC 9470\'s ' +
          'step-up is the second section (`stepup`), its clients ' +
          'paged by `stepUpClientsPage`, carrying the requirement ' +
          'this service\'s own resource server enforces ' +
          '(`ownResourceRequirement`) and `acrValuesSupported`. ' +
          'Per trust realm, ' +
          'merged across processes, and with no reset.',
        mirrors: 'GET /admin/oauth2/monitor',
        parameters: [
          { name: 'offset', in: 'query', required: false,
            schema: { type: 'integer', minimum: 0 },
            description: 'Skip this many pushed requests (newest first). ' +
                         'Wins over `page` when both are sent.' },
          { name: 'limit', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 500 },
            description: 'At most this many pushed requests; 50 by ' +
                         'default.' },
          { name: 'state', in: 'query', required: false,
            schema: { type: 'string', enum: ['live', 'spent', 'all'] },
            description: '`live` (not yet spent), `spent` (an ' +
                         'authorization response was issued on it; kept ' +
                         'until it would have expired), or `all`, the ' +
                         'default.' },
          { name: 'client_id', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256 },
            description: 'Only the pushed requests bound to this ' +
                         'client.' },
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'The console\'s spelling: which page of pushed ' +
                         'requests, `per` to a page.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 500 },
            description: 'Rows per page, for `page` and `clientsPage`.' },
          { name: 'clientsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the RFC 9126 section\'s ' +
                         'per-client counter rows.' },
          { name: 'stepUpClientsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the RFC 9470 section\'s ' +
                         'per-client counter rows.' }
        ],
        responseDescription: 'The sections, their counters and the pushed ' +
                             'requests held.',
        responseSchema: self.object(
          'The OAuth 2.0 / OIDC activity in this realm: ' +
          '`since`, `actions`, and `sections` — each with ' +
          '`id`, `title`, `events`, `totals`, `errors`, ' +
          '`clients`, `clientsPaging`, `clientsParam` and, ' +
          'for `par`, `pushedRequests` (`filter`, `total`, ' +
          '`offset`, `limit`, `capacity`, `lifetime_s`, ' +
          '`paging`, `items`), for `stepup`, ' +
          '`ownResourceRequirement` and ' +
          '`acrValuesSupported`.'),
        handler: function (req: Req, res: Res) {
          log.debug("Entering the management API OAuth 2.0 monitor " +
                    "endpoint.");
          const model = self.consoleModel();
          const query = model.checkQuery(req);
          if (!query.ok) {
            errorCodes.mark(res, 'STS-API-0100');
            self.sendJson(res, 400, { ok: false, errors: [query.detail] });
            log.debug("Leaving the management API OAuth 2.0 monitor " +
                      "endpoint. Bad query.");
            return;
          }
          self.sendJson(res, 200, model.monitorView(req));
          log.debug("Leaving the management API OAuth 2.0 monitor " +
                    "endpoint.");
        } },

      { method: 'POST', route: BASE + '/oauth2/monitor/:action',
        tag: 'OAuth 2.0 / OIDC',
        mirrors: 'POST /admin/oauth2/monitor',
        handler: function (req: Req, res: Res) {
          log.debug("Entering the management API OAuth 2.0 monitor " +
                    "action.");
          const body = Object.assign(
            {}, parseBody(req),
            { action: String(req.params.action || '') });
          let result = null;
          try {
            result = self.consoleModel().monitorAction(body, { via: 'api' });
          } catch (e) {
            log.debug("Caught in the management API OAuth 2.0 monitor " +
                      "action: " + ((e && e.message) || e));
            log.error(errorCodes.tag('STS-API-0102') + 'oauth2 monitor ' +
                      'management API action threw: ' +
                      ((e && e.stack) || e));
            errorCodes.mark(res, 'STS-API-0102');
            self.sendJson(res, 500, {
              ok: false, errors: ['The action could not be completed.'] });
            log.debug("Leaving the management API OAuth 2.0 monitor " +
                      "action. Threw.");
            return;
          }
          if (!result.ok) {
            errorCodes.mark(res,
                            errorCodes.codeOf(result) || 'STS-API-0101');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API OAuth 2.0 monitor " +
                    "action. ok=" + result.ok);
        },
        actions: [
          { action: 'delete-pushed-request',
            operationId: 'deletePushedRequest',
            summary: 'Withdraw a pushed authorization request (RFC 9126)',
            description: 'Removes one request_uri from this realm\'s store ' +
              'of pushed authorization requests, live or spent. The ' +
              'authorization endpoint refuses it from then on with ' +
              '400 invalid_request_uri, exactly as it refuses one ' +
              'that expired and was swept; a browser already on the ' +
              'sign-in or consent screen with it is refused when it ' +
              'comes back. Counted as `par.deleted` and written to ' +
              'the audit log. A value not in the ' +
              '`urn:ietf:params:oauth:request_uri:` namespace, or one ' +
              'this realm does not hold, is refused 400.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                request_uri: {
                  type: 'string', minLength: 1, maxLength: 512,
                  description: 'The whole request_uri, as listed ' +
                               'by GET /admin-api/oauth2/monitor.' }
              },
              required: ['request_uri'],
              examples: [{ request_uri: 'urn:ietf:params:oauth:request_uri:' +
                                        'bwc4JK-ESC0w8acc191e-Y1LTC2' }],
              additionalProperties: false
            },
            responseDescription: 'The request_uri withdrawn, the client it ' +
                                 'was bound to and the state it was in.' }
        ] }
    ];
    log.debug("Leaving OAuth2MonitorApi.buildRoutes().");
    return ROUTES;
  }
}

// The table `buildRoutes()` made for the installed instance, filled by
// `wire()`. Read through the `ROUTES` getter below.
let routes: Json[] = [];

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES for the JavaScript that
// still calls this module through `require()` — `ROUTES` a getter over the
// table the instance built; a process that never runs the root gets a
// default instance, built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<OAuth2MonitorApi>(
  'oauth-oidc/oauth2_monitor_api',
  () => new OAuth2MonitorApi(OAuth2MonitorApi.defaultDeps()),
  OAuth2MonitorApi.wire,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  OAuth2MonitorApi: OAuth2MonitorApi,
  installInstance: (instance: OAuth2MonitorApi): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // A GETTER, so the table is the installed instance's: under the root it is
  // built when the root installs that instance, and `mgmt-api/admin_api.ts`
  // reads it after that.
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
