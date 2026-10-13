// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: scim_clients_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/scim/clients OPERATIONS (#552), mirroring Protocols → SCIM's
// Clients tab (rule 7): the outbound SCIM clients as the tab draws them, one
// client's queues and discovery as its page draws them, and the ten acts,
// each `scim/scim_client.ts`'s `act()` — the console's own, since the static
// console sends its forms here.
//
// **NO ANSWER CARRIES A CREDENTIAL.** The view says `passwordSet`,
// `oauthClientSecretSet` and `tlsPrivateKeySet`; the three credentials are
// members an add or a change TAKES and nothing gives back.
//
// It registers no route: `mgmt-api/admin_api.ts` spreads `ROUTES` into its
// table, as it does the secret destinations' operations.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import Rules = require('../scim/scim_client_rules');

type Req = any;
type Res = any;
type Json = any;

interface ScimClientsApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The client, lazily: it is built at 22, after this module and the API.
  loadClients(): Json;
}

const BASE = '/admin-api';

// A client's members, as `add-client` and `update-client` take them. The
// closed sets are `scim_client_rules.ts`'s, so the document cannot offer what
// the client refuses.
function clientProperties(): Json {
  helpers.log.debug("Entering clientProperties().");
  const list = { oneOf: [{ type: 'string', maxLength: 8192 },
                         { type: 'array', maxItems: 256,
                           items: { type: 'string', maxLength: 2048 } }] };
  helpers.log.debug("Leaving clientProperties().");
  return {
    identifier: { type: 'string', minLength: 1, maxLength: 512,
                  description: 'The client\'s application identifier (add ' +
                               'only): the entry it is filed under in ' +
                               'ou=applications.' },
    id: { type: 'string', maxLength: 2048,
          description: 'The client: its identifier or its entry\'s DN.' },
    name: { type: 'string', maxLength: 256,
            description: 'What to call it on a page.' },
    enabled: { type: 'string', enum: ['true', 'false'],
               description: 'Whether changes are pushed. A new client is ' +
                            'off until this says true.' },
    baseUrl: { type: 'string', maxLength: 2048,
               description: 'The service provider\'s SCIM base URI (RFC ' +
                            '7644 section 1.3): https, no user name, no ' +
                            'query.' },
    authMethod: { type: 'string', enum: Rules.AUTH_METHODS.slice(),
                  description: 'basic, oauth2 (client_credentials), or none ' +
                               '(only with a TLS client certificate).' },
    username: { type: 'string', maxLength: 512,
                description: 'basic: the user name.' },
    password: { type: 'string', maxLength: 4096, writeOnly: true,
                description: 'basic: the password, write-only. On a change, ' +
                             'empty keeps the one set.' },
    tokenEndpoint: { type: 'string', maxLength: 2048,
                     description: 'oauth2: the token endpoint.' },
    oauthClientId: { type: 'string', maxLength: 512,
                     description: 'oauth2: the client_id.' },
    oauthClientSecret: { type: 'string', maxLength: 4096, writeOnly: true,
                         description: 'oauth2: the client secret, ' +
                                      'write-only.' },
    oauthClientAuth: { type: 'string', enum: Rules.OAUTH_CLIENT_AUTH.slice(),
                       description: 'oauth2: how the client authenticates ' +
                                    'at the token endpoint.' },
    oauthScope: { type: 'string', maxLength: 1024,
                  description: 'oauth2: the scope asked for, if any.' },
    oauthResource: { type: 'string', maxLength: 2048,
                     description: 'oauth2: an RFC 8707 resource, if any.' },
    tlsSource: { type: 'string', enum: Rules.TLS_SOURCES.slice(),
                 description: 'The TLS client certificate: none, issued ' +
                              '(issue-certificate) or uploaded.' },
    tlsCertificate: { type: 'string', maxLength: 65536,
                      description: 'uploaded: the PEM certificate and its ' +
                                   'chain.' },
    tlsPrivateKey: { type: 'string', maxLength: 65536, writeOnly: true,
                     description: 'uploaded: the PEM private key, ' +
                                  'write-only.' },
    caCertificates: { type: 'string', maxLength: 65536,
                      description: 'PEM certificates trusted for the ' +
                                   'service provider beside the public ' +
                                   'roots.' },
    scopeMode: { type: 'string', enum: Rules.SCOPE_MODES.slice(),
                 description: 'Who is pushed: all, groups, or filter.' },
    scopeGroups: Object.assign({ description: 'groups: the groups whose ' +
                                 'members are pushed, by cn or DN.' }, list),
    scopeFilter: { type: 'string', maxLength: 4096,
                   description: 'filter: an RFC 4515 LDAP filter.' },
    groupMode: { type: 'string', enum: Rules.GROUP_MODES.slice(),
                 description: 'Which groups are pushed: none, selected, ' +
                              'member-groups or all.' },
    groups: Object.assign({ description: 'selected: the groups pushed, by ' +
                            'cn or DN.' }, list),
    deprovision: { type: 'string', enum: Rules.DEPROVISION.slice(),
                   description: 'What leaving the scope does there: ' +
                                'deactivate (active false) or delete.' },
    reconcileMinutes: { type: 'string', pattern: '^[0-9]{1,6}$',
                        description: 'Minutes between scheduled ' +
                                     'reconciliations; 0 is on demand ' +
                                     'only.' },
    jurisdiction: { type: 'string', maxLength: 32,
                    description: 'A service deployed as cells (#553): the ' +
                                 'jurisdiction the service provider is in, ' +
                                 'as the cell map spells one (us, eu, ca). ' +
                                 'Each person\'s home cell asks the ' +
                                 'issuance policy (release-attributes, ' +
                                 'purpose scim-provision) before pushing ' +
                                 'them there; a refusal leaves them out of ' +
                                 'scope. Empty is unknown, which the strict ' +
                                 'default never releases to. Ignored in a ' +
                                 'service that is one cell.' },
    cells: Object.assign({ description: 'A service deployed as cells ' +
                           '(#553): the cells that push to the service ' +
                           'provider, by id; empty is every cell. Ignored ' +
                           'in a service that is one cell.' }, list),
    cell: { type: 'string', maxLength: 64,
            description: 'A service deployed as cells (#553): the cell the ' +
                         'act is sent to. Without it the act goes to every ' +
                         'cell that pushes to the client, and the answer ' +
                         'lists each cell\'s result. Refused in a service ' +
                         'that is one cell.' }
  };
}

/**
 * The `/admin-api/scim/clients` operations: the clients, one client's page
 * and its ten acts, each the console's own.
 */
class ScimClientsApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   client
   */
  constructor(private readonly deps: ScimClientsApiDeps) {
    deps.log.debug("Entering ScimClientsApi.constructor().");
    deps.log.debug("Leaving ScimClientsApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports, with the
   * client loaded lazily.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ScimClientsApiDeps {
    helpers.log.debug("Entering ScimClientsApi.defaultDeps().");
    helpers.log.debug("Leaving ScimClientsApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadClients: function (): Json {
        return require('../scim/scim_client');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: ScimClientsApi): void {
    helpers.log.debug("Entering ScimClientsApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving ScimClientsApi.wire().");
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
    log.debug("Entering ScimClientsApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving ScimClientsApi.sendJson().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadClients } = this.deps;
    const self = this;
    log.debug("Entering ScimClientsApi.buildRoutes().");
    const P = clientProperties();
    const definition = ['name', 'enabled', 'baseUrl', 'authMethod',
                        'username', 'password', 'tokenEndpoint',
                        'oauthClientId', 'oauthClientSecret',
                        'oauthClientAuth', 'oauthScope', 'oauthResource',
                        'tlsSource', 'tlsCertificate', 'tlsPrivateKey',
                        'caCertificates', 'scopeMode', 'scopeGroups',
                        'scopeFilter', 'groupMode', 'groups', 'deprovision',
                        'reconcileMinutes', 'jurisdiction', 'cells'];
    const pick = function (names: string[]): Json {
      const out: Json = {};
      names.forEach(function (name) {
        out[name] = P[name];
      });
      return out;
    };
    const byId = function (extra?: Json): Json {
      return { type: 'object',
               properties: Object.assign({ id: P.id }, extra || {}),
               required: ['id'], examples: [{ id: 'partner-idp' }],
               additionalProperties: false };
    };
    const ROUTES = [
      { method: 'GET', path: BASE + '/scim/clients',
        tag: 'SCIM', operationId: 'getScimClients',
        summary: 'This realm\'s outbound SCIM clients (#552)',
        description: 'Everything Protocols → SCIM → Clients draws: each ' +
          'client (an application entry declared for the scim-client ' +
          'family) with its service provider, authentication, scope, ' +
          'whether it is usable and why not, its queue counts (queued, ' +
          'retrying, dead, sent) and its backoff pause. With `client`, that ' +
          'client\'s page too: its retry queue and dead letters, what its ' +
          'service provider\'s discovery said, and how many resources it ' +
          'has linked. NEVER a credential.',
        mirrors: 'GET /admin/scim',
        parameters: [
          { name: 'client', in: 'query', required: false,
            schema: { type: 'string', maxLength: 512 },
            description: 'One client\'s identifier, for its page.' }
        ],
        responseDescription: 'The clients.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`clients`, `choices`, ' +
                                       '`httpAllowed`, and with `client` ' +
                                       'the client\'s page (`client`, or ' +
                                       '`missing`).' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API SCIM clients endpoint.");
          self.sendJson(res, 200, loadClients().view(req.query || {}));
          log.debug("Leaving the management API SCIM clients endpoint.");
        } },

      { method: 'POST', route: BASE + '/scim/clients/:action',
        tag: 'SCIM', mirrors: 'POST /admin/scim',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API SCIM clients action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          Promise.resolve().then(function (): Json {
            // THE CALLER, which the route wrapper put in the body's
            // `actor` after its schema passed (`nameActor()`, #446).
            return loadClients().act(body, {
              via: 'api', actor: String(body.actor || '') });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-SCIMC-0018');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API SCIM clients action. " +
                      "ok=" + result.ok);
          }, function (e: any): void {
            log.error(errorCodes.tag('STS-SCIMC-0018') + 'scim client: an ' +
                      '/admin-api action failed: ' +
                      ((e && e.message) || e));
            errorCodes.mark(res, 'STS-SCIMC-0018');
            self.sendJson(res, 500, { ok: false, errors:
                                        ['The action could not be ' +
                                         'completed.'] });
            log.debug("Leaving the management API SCIM clients action. " +
                      "Threw.");
          });
        },
        actions: [
          { action: 'add-client', operationId: 'addScimClient',
            summary: 'Add an outbound SCIM client',
            description: 'Creates an application entry declared for the ' +
              'scim-client family, with its service provider, its ' +
              'authentication (credentials sealed and write-only), who and ' +
              'which groups it pushes, and what deprovisioning means. ' +
              'Refused for a base URI that is not https or carries a user ' +
              'name or a query, a closed-set value outside its set, an LDAP ' +
              'filter that does not parse, or certificates that do not. A ' +
              'new client is off until `enabled` is true. Audited, without ' +
              'a credential.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: Object.assign({ identifier: P.identifier },
                                        pick(definition)),
              required: ['identifier'],
              examples: [{ identifier: 'partner-idp', name: 'Partner IdP',
                           baseUrl: 'https://idp.example.com/scim/v2',
                           authMethod: 'oauth2',
                           tokenEndpoint: 'https://idp.example.com/token',
                           oauthClientId: 'iya-sts',
                           oauthClientSecret: '<a secret>',
                           scopeMode: 'groups', scopeGroups: 'staff',
                           groupMode: 'member-groups',
                           deprovision: 'deactivate',
                           reconcileMinutes: '1440', enabled: 'true' }],
              additionalProperties: false
            },
            responseDescription: 'The client as the register now answers ' +
                                 'it.' },
          { action: 'update-client', operationId: 'updateScimClient',
            summary: 'Change an outbound SCIM client',
            description: 'The members given replace the client\'s; the ' +
              'rest are kept, each credential included when none is given. ' +
              'Checked as add-client is. Forgets this process\'s discovery ' +
              'and token. Audited, without a credential.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: Object.assign({ id: P.id }, pick(definition)),
              required: ['id'],
              examples: [{ id: 'partner-idp', enabled: 'false' }],
              additionalProperties: false
            },
            responseDescription: 'The client as the register now answers ' +
                                 'it.' },
          { action: 'remove-client', operationId: 'removeScimClient',
            summary: 'Remove an outbound SCIM client',
            description: 'Deletes its application entry, credentials and ' +
              'all, with its queues, links and backoff state. Nothing at ' +
              'the service provider changes. Audited.',
            requestBodyRequired: true, requestBody: byId(),
            responseDescription: 'What was removed.' },
          { action: 'issue-certificate',
            operationId: 'issueScimClientCertificate',
            summary: 'Issue the client a TLS client certificate',
            description: 'Issues a clientAuth certificate from this realm\'s ' +
              'tls-client Issuing CA to the client\'s application entry, ' +
              'and makes it the certificate the client presents (source ' +
              'issued). The private key is sealed on the entry and never ' +
              'returned; the service provider must trust the service Root. ' +
              'Audited.',
            requestBodyRequired: true, requestBody: byId(),
            responseDescription: 'The certificate\'s subject, serial and ' +
                                 'expiry, and the service Root.' },
          { action: 'test-connection', operationId: 'testScimClient',
            summary: 'Read the service provider\'s configuration',
            description: 'Reads /ServiceProviderConfig and /ResourceTypes ' +
              'afresh and lists one User, with the client\'s own ' +
              'authentication. Writes nothing there.',
            requestBodyRequired: true, requestBody: byId(),
            responseDescription: 'What discovery said, or a coded ' +
                                 'refusal.' },
          { action: 'reconcile', operationId: 'reconcileScimClient',
            summary: 'Reconcile the client now',
            description: 'Queues every person and group in the client\'s ' +
              'scope, and every resource its service provider holds under ' +
              'an externalId of this realm\'s that is no longer in scope; ' +
              'then sends what is due. Audited.',
            requestBodyRequired: true, requestBody: byId(),
            responseDescription: 'How many users and groups were queued, ' +
                                 'and how many to deprovision.' },
          { action: 'deliver-now', operationId: 'deliverScimClientNow',
            summary: 'Lift the client\'s pause and send its queue',
            description: 'Ends the backoff pause and makes every queued ' +
              'and retrying delivery due now. Use it once the service ' +
              'provider is answering again.',
            requestBodyRequired: true, requestBody: byId(),
            responseDescription: '`ok`.' },
          { action: 'retry-delivery', operationId: 'retryScimDelivery',
            summary: 'Retry one dead letter',
            description: 'Queues one dead letter again, by its row id ' +
              '(`<client>|User|<uuid>` or `<client>|Group|<uuid>`); it ' +
              'sends the resource as it is now. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
                           properties: { id: { type: 'string', minLength: 1,
                                               maxLength: 2048,
                                               description: 'The delivery ' +
                                                 'row\'s id.' } },
                           required: ['id'],
                           examples: [{ id: 'partner-idp|User|' +
                             '9f0c3c1e-6a4e-4a8e-9d0b-3a5d2c4b7e10' }],
                           additionalProperties: false },
            responseDescription: '`ok`, or a coded refusal.' },
          { action: 'retry-dead', operationId: 'retryScimDeadLetters',
            summary: 'Retry every dead letter of a client',
            description: 'Queues every dead letter of the client again. ' +
              'Audited.',
            requestBodyRequired: true, requestBody: byId(),
            responseDescription: 'How many were queued.' },
          { action: 'purge-dead', operationId: 'purgeScimDeadLetters',
            summary: 'Purge a client\'s dead letters',
            description: 'Deletes every dead letter of the client. The ' +
              'next change to each resource, or a reconciliation, queues ' +
              'it afresh. Audited.',
            requestBodyRequired: true, requestBody: byId(),
            responseDescription: 'How many were purged.' }
        ] }
    ];
    log.debug("Leaving ScimClientsApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<ScimClientsApi>(
  'mgmt-api/scim_clients_api',
  () => new ScimClientsApi(ScimClientsApi.defaultDeps()),
  ScimClientsApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The outbound SCIM client operations of `/admin-api` (#552), mirroring
 * Protocols → SCIM → Clients.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  ScimClientsApi: ScimClientsApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: ScimClientsApi): void =>
    slot.install(instance),
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
