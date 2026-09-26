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

type Req = any;
type Res = any;
type Json = any;

interface ProviderCommandsApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  loadCommands(): Json;
  loadOutbound(): Json;
}

const BASE = '/admin-api';

class ProviderCommandsApi {
  constructor(private readonly deps: ProviderCommandsApiDeps) {
    deps.log.debug("Entering ProviderCommandsApi.constructor().");
    deps.log.debug("Leaving ProviderCommandsApi.constructor().");
  }

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
      }
    };
  }

  static wire(instance: ProviderCommandsApi): void {
    helpers.log.debug("Entering ProviderCommandsApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving ProviderCommandsApi.wire().");
  }

  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering ProviderCommandsApi.sendJson(). status=" + status);
    const reply = Object.assign({}, body);
    delete reply.errorCode;
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving ProviderCommandsApi.sendJson().");
  }

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
        summary: 'OpenID Provider Commands: the clients, the account ' +
                 'register, the tenant runs and the deliveries',
        description: 'Everything /admin/commands draws: whether commands ' +
          'and automatic commands are on, the issuer Command Tokens name, ' +
          'each client with a command_endpoint and what its metadata ' +
          'answer said it supports, the account-state register (what each ' +
          'relying party said about each person), the tenant runs, and the ' +
          'command deliveries. `state` and `q` narrow the deliveries. Never ' +
          'a token.',
        mirrors: 'GET /admin/commands',
        responseDescription: 'The report.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`enabled`, `automatic`, `issuer`, ' +
                            '`clients`, `accounts`, `runs`, `deliveries`, ' +
                            '`counts`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API commands endpoint.");
          self.sendJson(res, 200, loadCommands().report({
            q: req.query.q, state: req.query.state }));
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
          { action: 'send-account', operationId: 'sendAccountCommand',
            summary: 'Send an account command about one person',
            description: 'One of activate, maintain, suspend, reactivate, ' +
              'archive, restore, delete, audit, invalidate or migrate — or ' +
              'its _async variant — to the client\'s command_endpoint, ' +
              'queued on the shared outbound queue. The answer is recorded ' +
              'in the account register. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                clientId: { type: 'string', maxLength: 512 },
                username: { type: 'string', maxLength: 256 },
                command: { type: 'string', maxLength: 64 }
              },
              required: ['clientId', 'username', 'command'],
              examples: [{ clientId: 'app', username: 'alice',
                           command: 'audit' }],
              additionalProperties: false
            },
            responseDescription: 'The delivery queued.' },
          { action: 'send-tenant', operationId: 'sendTenantCommand',
            summary: 'Send a tenant command',
            description: 'metadata (a JSON answer, recorded as what the ' +
              'client supports), or one of audit_tenant, suspend_tenant, ' +
              'archive_tenant, delete_tenant and invalidate_tenant (a ' +
              'Server-Sent Events stream, read in the background as a run). ' +
              'Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                clientId: { type: 'string', maxLength: 512 },
                command: { type: 'string', maxLength: 64 }
              },
              required: ['clientId', 'command'],
              examples: [{ clientId: 'app', command: 'metadata' }],
              additionalProperties: false
            },
            responseDescription: 'The delivery or run started.' },
          { action: 'retry-delivery', operationId: 'retryCommandDelivery',
            summary: 'Retry a dead command delivery',
            description: 'A new generation: a fresh attempt budget and the ' +
              'client\'s current command_endpoint. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { delivery: { type: 'string', maxLength: 64 } },
              required: ['delivery'], examples: [{ delivery: 'abc123' }],
              additionalProperties: false
            },
            responseDescription: 'The delivery queued again.' }
        ] },

      { method: 'GET', path: BASE + '/deliveries',
        tag: 'Monitoring', operationId: 'getOutboundDeliveries',
        summary: 'Every outbound delivery on the shared queue, by kind',
        description: 'What /admin/deliveries draws: for each kind — ' +
          'backchannel-logout, ciba and provider-commands — its counts by ' +
          'state and its rows, newest first. `state` (pending, sent, dead), ' +
          '`kind` and `q` narrow. Never a token or a body.',
        mirrors: 'GET /admin/deliveries',
        responseDescription: 'The kinds.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`kinds`, `states`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API deliveries endpoint.");
          self.sendJson(res, 200, loadOutbound().kindReport({
            state: req.query.state, q: req.query.q, kind: req.query.kind }));
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
          { action: 'retry', operationId: 'retryOutboundDelivery',
            summary: 'Retry a dead letter of any kind',
            description: 'A new generation of the delivery: a fresh attempt ' +
              'budget and the client\'s current address. Audited by its ' +
              'kind.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                kind: { type: 'string', enum: ['backchannel-logout', 'ciba',
                                               'provider-commands'] },
                delivery: { type: 'string', maxLength: 64 }
              },
              required: ['kind', 'delivery'],
              examples: [{ kind: 'provider-commands', delivery: 'abc123' }],
              additionalProperties: false
            },
            responseDescription: 'The delivery queued again.' }
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

export = {
  ProviderCommandsApi: ProviderCommandsApi,
  installInstance: (instance: ProviderCommandsApi): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
