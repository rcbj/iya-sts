'use strict';
//
// File: claims_providers_api.ts
//
// ===========================================================================
// `/admin-api/claim-providers` (#147, 2026-09-24): /admin/claim-providers for
// a machine (rule 7). The register and every person's link — never a client
// secret or a token — and the four acts, each the console's own. Registers no
// route: `mgmt-api/admin_api.ts` spreads ROUTES into its table.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface ClaimsProvidersApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  loadProviders(): Json;
}

const BASE = '/admin-api';

const PROVIDER_PROPERTIES = {
  id: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,39}$',
        description: 'The provider\'s id in this realm, its `_claim_sources` ' +
                     'key.' },
  name: { type: 'string', maxLength: 200 },
  issuer: { type: 'string', maxLength: 2048,
            description: 'Its OpenID Provider issuer.' },
  discover: { type: 'boolean', description: 'Fill the endpoints left empty ' +
              'from the issuer\'s discovery document.' },
  authorizationEndpoint: { type: 'string', maxLength: 2048 },
  tokenEndpoint: { type: 'string', maxLength: 2048 },
  claimsEndpoint: { type: 'string', maxLength: 2048,
                    description: 'Its UserInfo endpoint.' },
  jwksUri: { type: 'string', maxLength: 2048 },
  clientId: { type: 'string', maxLength: 512,
              description: 'This realm\'s client_id at the provider.' },
  clientSecret: { type: 'string', maxLength: 1024,
                  description: 'Sealed where keys persist; never returned.' },
  authMethod: { type: 'string', enum: ['client_secret_basic',
                                       'client_secret_post', 'none'] },
  scope: { type: 'string', maxLength: 1024 },
  claims: { type: 'array', items: { type: 'string', maxLength: 128 },
            description: 'The claim names it supplies.' },
  delivery: { type: 'string', enum: ['aggregated', 'distributed'] }
};

class ClaimsProvidersApi {
  constructor(private readonly deps: ClaimsProvidersApiDeps) {
    deps.log.debug("Entering ClaimsProvidersApi.constructor().");
    deps.log.debug("Leaving ClaimsProvidersApi.constructor().");
  }

  static defaultDeps(): ClaimsProvidersApiDeps {
    helpers.log.debug("Entering ClaimsProvidersApi.defaultDeps().");
    helpers.log.debug("Leaving ClaimsProvidersApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf,
      errorCodes: errorCodes,
      loadProviders: function (): Json {
        return require('./claims_providers');
      }
    };
  }

  static wire(instance: ClaimsProvidersApi): void {
    helpers.log.debug("Entering ClaimsProvidersApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving ClaimsProvidersApi.wire().");
  }

  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering ClaimsProvidersApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving ClaimsProvidersApi.sendJson().");
  }

  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadProviders,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering ClaimsProvidersApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/claim-providers',
        tag: 'OAuth 2.0 / OIDC', operationId: 'getClaimProviders',
        summary: 'The Claims Providers this realm aggregates claims from, ' +
                 'and every person\'s link (OIDC Core 5.6.2)',
        description: 'Everything /admin/claim-providers draws: each ' +
          'registered provider (issuer, endpoints, client, the claims it ' +
          'supplies, aggregated or distributed, whether a secret is held), ' +
          'the redirect URI to register at a provider, and every link a ' +
          'person made (their subject there, when, the token\'s expiry, ' +
          'whether it is stale). Never a secret or a token.',
        mirrors: 'GET /admin/claim-providers',
        responseDescription: 'The register and the links.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`providers`, `links`, ' +
                                       '`redirectUri`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API claim providers endpoint.");
          const json = loadProviders().view();
          self.sendJson(res, 200, Object.assign({
            redirectUri: baseUrlOf(req) + json.callbackPath }, json));
          log.debug("Leaving the management API claim providers endpoint.");
        } },

      { method: 'POST', route: BASE + '/claim-providers/:action',
        tag: 'OAuth 2.0 / OIDC', mirrors: 'POST /admin/claim-providers',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API claim providers action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          Promise.resolve().then(function (): Json {
            return loadProviders().act(body, { via: 'api',
                                               actor: 'admin-api' });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-OAUTH-0686');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API claim providers action. " +
                      "ok=" + result.ok);
          }, function (e: any): void {
            log.error(errorCodes.tag('STS-OAUTH-0686') + 'oauth2: a Claims ' +
                      'Provider /admin-api action failed: ' +
                      ((e && e.stack) || e));
            errorCodes.mark(res, 'STS-OAUTH-0686');
            self.sendJson(res, 500, { ok: false, errors:
                                        ['The action could not be ' +
                                         'completed.'] });
            log.debug("Leaving the management API claim providers action. " +
                      "Threw.");
          });
        },
        actions: [
          { action: 'add-provider', operationId: 'addClaimProvider',
            summary: 'Register a Claims Provider',
            description: 'A provider this realm aggregates claims from. ' +
              '`discover` fills the endpoints left empty from the issuer\'s ' +
              'discovery document; the secret is sealed. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object', properties: PROVIDER_PROPERTIES,
              required: ['id', 'issuer', 'clientId', 'claims'],
              examples: [{ id: 'bank', issuer: 'https://bank.example',
                           discover: true, clientId: 'iya-sts',
                           clientSecret: 's3cret', claims: ['credit_score'],
                           delivery: 'aggregated' }],
              additionalProperties: false
            },
            responseDescription: 'What was registered.' },
          { action: 'update-provider', operationId: 'updateClaimProvider',
            summary: 'Change a Claims Provider',
            description: 'The members given replace the provider\'s; the ' +
              'secret is kept unless one is given. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object', properties: PROVIDER_PROPERTIES,
              required: ['id'],
              examples: [{ id: 'bank', delivery: 'distributed' }],
              additionalProperties: false
            },
            responseDescription: 'What changed.' },
          { action: 'remove-provider', operationId: 'removeClaimProvider',
            summary: 'Remove a Claims Provider',
            description: 'It leaves the register; people\'s links to it stay ' +
              'on their entries and are never used. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { id: PROVIDER_PROPERTIES.id },
              required: ['id'], examples: [{ id: 'bank' }],
              additionalProperties: false
            },
            responseDescription: 'What was removed.' },
          { action: 'revoke-link', operationId: 'revokeClaimSourceLink',
            summary: 'Revoke a person\'s link to a Claims Provider',
            description: 'Their tokens at that provider are removed from ' +
              'their entry, so its claims are no longer sent. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                username: { type: 'string', maxLength: 256 },
                provider: PROVIDER_PROPERTIES.id
              },
              required: ['username', 'provider'],
              examples: [{ username: 'alice', provider: 'bank' }],
              additionalProperties: false
            },
            responseDescription: 'What was revoked.' }
        ] }
    ];
    log.debug("Leaving ClaimsProvidersApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<ClaimsProvidersApi>(
  'oauth-oidc/claims_providers_api',
  () => new ClaimsProvidersApi(ClaimsProvidersApi.defaultDeps()),
  ClaimsProvidersApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  ClaimsProvidersApi: ClaimsProvidersApi,
  installInstance: (instance: ClaimsProvidersApi): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
