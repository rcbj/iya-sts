'use strict';
//
// File: grant_management_api.ts
//
// ---------------------------------------------------------------------------
// THE GRANT MANAGEMENT OPERATIONS OF /admin-api (#142, 2026-09-24), spread
// into `mgmt-api/admin_api.ts`'s ROUTES:
//
//   GET  /admin-api/grants            mirrors GET  /admin/grants
//   POST /admin-api/grants/:action    mirrors POST /admin/grants
//
// What `/admin/grants` draws, out of the same `grant_management.ts` calls
// (rule 7): every grant the realm holds and the one act, `revoke-grant`.
//
// **IT REGISTERS NO ROUTE AND REQUIRES `grant_management.ts` LAZILY**, for
// `oidfed/oidfed_api.ts`'s reason: the management API requires this file at
// 19 and the library is built at 9, so the require is a cache hit, and a
// lazy one keeps the order a non-question.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface GrantManagementApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  loadGrants(): Json;
}

const BASE = '/admin-api';

class GrantManagementApi {
  constructor(private readonly deps: GrantManagementApiDeps) {
    deps.log.debug("Entering GrantManagementApi.constructor().");
    deps.log.debug("Leaving GrantManagementApi.constructor().");
  }

  static defaultDeps(): GrantManagementApiDeps {
    helpers.log.debug("Entering GrantManagementApi.defaultDeps().");
    helpers.log.debug("Leaving GrantManagementApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadGrants: function (): Json {
        return require('./grant_management');
      }
    };
  }

  static wire(instance: GrantManagementApi): void {
    helpers.log.debug("Entering GrantManagementApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving GrantManagementApi.wire().");
  }

  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering GrantManagementApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving GrantManagementApi.sendJson().");
  }

  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadGrants } = this.deps;
    const self = this;
    log.debug("Entering GrantManagementApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/grants', tag: 'OAuth 2.0 / OIDC',
        operationId: 'getGrants',
        summary: 'The OAuth grants this realm holds (Grant Management for ' +
                 'OAuth 2.0)',
        description: 'Everything /admin/grants draws: every grant a client ' +
          'created, merged or replaced through Grant Management, newest ' +
          'first — its grant_id, client, subject and generation, the ' +
          'grant resource the grant management API answers (scopes and ' +
          'resources, claims, authorization_details, created_at, ' +
          'last_updated, expires_at, updated_by) and how many tokens ' +
          'minted under it this realm still records. Never a token.',
        mirrors: 'GET /admin/grants',
        parameters: [
          { name: 'client_id', in: 'query', required: false,
            schema: { type: 'string', maxLength: 256 },
            description: 'Only this client\'s grants.' }
        ],
        responseDescription: 'The grants.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`grants`: one row per grant.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API grants endpoint.");
          const clientId = String((req.query || {}).client_id || '')
            .slice(0, 256);
          self.sendJson(res, 200,
                        { grants: loadGrants().list(clientId || undefined) });
          log.debug("Leaving the management API grants endpoint.");
        } },

      { method: 'POST', route: BASE + '/grants/:action',
        tag: 'OAuth 2.0 / OIDC', mirrors: 'POST /admin/grants',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API grants action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          let result: Json = null;
          try {
            result = loadGrants().act(body, { via: 'api',
                                              actor: 'admin-api' });
          } catch (e: any) {
            log.error(errorCodes.tag('STS-OAUTH-0674') + 'oauth2: a grants ' +
                      '/admin-api action failed: ' + ((e && e.stack) || e));
            errorCodes.mark(res, 'STS-OAUTH-0674');
            self.sendJson(res, 500, { ok: false, errors:
                                        ['The action could not be ' +
                                         'completed.'] });
            log.debug("Leaving the management API grants action. Threw.");
            return;
          }
          if (!result.ok) {
            // error-code: none — the act's own code, read off the result
            errorCodes.mark(res, errorCodes.codeOf(result) ||
                                 'STS-OAUTH-0673');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API grants action. ok=" +
                    result.ok);
        },
        actions: [
          { action: 'revoke-grant', operationId: 'revokeGrant',
            summary: 'Revoke a grant',
            description: 'What a client\'s DELETE /oauth2/grants/{grant_id} ' +
              'does, done by an administrator: the grant leaves the ' +
              'register, so every refresh token issued under it is ' +
              'refused, and every token this realm recorded under it is ' +
              'revoked. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                grantId: { type: 'string', minLength: 1, maxLength: 128,
                           description: 'The grant_id, as GET ' +
                                        '/admin-api/grants lists it.' }
              },
              required: ['grantId'],
              examples: [{ grantId: 'TSdqirmAxDa0_-DB_1bASQ' }],
              additionalProperties: false
            },
            responseDescription: 'How many tokens were revoked with it.' }
        ] }
    ];
    log.debug("Leaving GrantManagementApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<GrantManagementApi>(
  'oauth-oidc/grant_management_api',
  () => new GrantManagementApi(GrantManagementApi.defaultDeps()),
  GrantManagementApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  GrantManagementApi: GrantManagementApi,
  installInstance: (instance: GrantManagementApi): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
