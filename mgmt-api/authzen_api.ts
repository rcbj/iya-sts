// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_api.ts
//
// ---------------------------------------------------------------------------
// THE /admin-api/xacml/authzen OPERATIONS (#563, phase 3, #1162), mirroring
// the AuthZEN tab of /admin/xacml (rule 7): what the tab draws, and its acts
// (three, and since #1180 the callbacks and the four access request acts),
// each `authzen/authzen_admin.ts`'s `act()` — the console's own, since the
// static console sends its forms here. The tab's settings are the
// configuration resource's, as every settings block's are.
//
// It registers no route: `mgmt-api/admin_api.ts` spreads `ROUTES` into its
// table, as it does the secret destinations' operations.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface AuthzenApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The tab's library, lazily: it is only asked inside a handler.
  loadAdmin(): Json;
}

const BASE = '/admin-api';

// The members a catalogue row takes, as `set-attribute` takes them.
const ROW_PROPERTIES = {
  object: { type: 'string', enum: ['subject', 'resource', 'action',
                                   'context'],
            description: 'The AuthZEN object the property is on.' },
  property: { type: 'string', minLength: 1, maxLength: 400,
              description: 'The property\'s name, or a dotted path into a ' +
                           'nested object (owner.country). For context, the ' +
                           'member\'s name; context.application is ' +
                           'reserved.' },
  attributeId: { type: 'string', minLength: 1, maxLength: 512,
                 description: 'The XACML attribute it is sent as. Never ' +
                              'urn:sts:xacml:*, subject-id, resource-id or ' +
                              'action-id, nor a bare directory name in a ' +
                              'subject category.' },
  category: { type: 'string', maxLength: 128,
              description: 'access-subject, resource, action, environment ' +
                           '(or another XACML category, or its URI); the ' +
                           'object\'s own when empty.' },
  dataType: { type: 'string', maxLength: 128,
              description: 'string, boolean, integer, double, date, ' +
                           'dateTime, time, anyURI, dayTimeDuration, ' +
                           'yearMonthDuration, hexBinary, base64Binary, ' +
                           'rfc822Name, x500Name, dnsName, ipAddress, or the ' +
                           'type\'s URI; string when empty.' },
  multiplicity: { type: 'string', enum: ['single', 'bag'],
                  description: 'single (one value) or bag (a JSON array); ' +
                               'single when left out.' },
  description: { type: 'string', maxLength: 500,
                 description: 'Free text for administrators.' }
};

/**
 * The `/admin-api/xacml/authzen` operations: the AuthZEN tab and its three
 * acts, each the console's own.
 */
class AuthzenApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   tab's library
   */
  constructor(private readonly deps: AuthzenApiDeps) {
    deps.log.debug("Entering AuthzenApi.constructor().");
    deps.log.debug("Leaving AuthzenApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): AuthzenApiDeps {
    helpers.log.debug("Entering AuthzenApi.defaultDeps().");
    helpers.log.debug("Leaving AuthzenApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadAdmin: function (): Json {
        helpers.log.debug("Entering loadAdmin().");
        helpers.log.debug("Leaving loadAdmin().");
        return require('../authzen/authzen_admin');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: AuthzenApi): void {
    helpers.log.debug("Entering AuthzenApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving AuthzenApi.wire().");
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
    log.debug("Entering AuthzenApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AuthzenApi.sendJson().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the rows
   */
  buildRoutes(): Json[] {
    const self = this;
    const { log, parseBody, loadAdmin } = this.deps;
    log.debug("Entering AuthzenApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/xacml/authzen', tag: 'XACML',
        operationId: 'getXacmlAuthzen',
        summary: 'The AuthZEN API: its settings, attribute catalogue and ' +
                 'callers',
        description: 'Everything the AuthZEN tab on /admin/xacml draws: ' +
                     'whether /access/v1 answers in this realm, how its ' +
                     'callers authenticate (authzen.callerAuthentication), ' +
                     'the AuthZEN settings, the attribute catalogue on the ' +
                     'sts-authzen-api object with the vocabulary a row may ' +
                     'use, and the members of roles.authzenPepGroup with ' +
                     'the applications each may ask about and the access ' +
                     'request callback URLs registered for it, and the ' +
                     'realm\'s AuthZEN access requests (#1180). ' +
                     '`?caller=<name or DN>` looks one caller up, in the ' +
                     'group or not.',
        mirrors: 'GET /admin/xacml',
        responseDescription: '`enabled`, `callerAuthentication`, ' +
                             '`settings`, `catalogue` (`rows`, `problems`, ' +
                             'and the choices), `callers`, `looked`, ' +
                             '`accessRequests`.',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API AuthZEN endpoint.");
          self.sendJson(res, 200, loadAdmin().view(req.query || {}));
          log.debug("Leaving the management API AuthZEN endpoint.");
        } },
      { method: 'POST', route: BASE + '/xacml/authzen/:action', tag: 'XACML',
        mirrors: 'POST /admin/xacml#xacml-tab-authzen',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API AuthZEN action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          let result: Json;
          // WHO ACTED is the caller the gate verified (#1180): an access
          // request is decided as that person, with the roles the gate
          // found, so the access-control policy is asked about them.
          const verified = req.adminApiCaller || {};
          try {
            result = loadAdmin().act(body, {
              via: 'api',
              actor: String(verified.name || body.actor || ''),
              roles: Array.isArray(verified.roles) ? verified.roles : [] });
          } catch (e) {
            log.error(errorCodes.tag('STS-AUTHZEN-0034') + 'authzen: an ' +
                      '/admin-api action failed: ' + ((e && e.message) || e));
            errorCodes.mark(res, 'STS-AUTHZEN-0034');
            self.sendJson(res, 500, { ok: false, errors:
                                        ['The action could not be ' +
                                         'completed.'] });
            log.debug("Leaving the management API AuthZEN action. Threw.");
            return;
          }
          if (!result.ok) {
            // error-code: none — the act's own code, read off the result
            errorCodes.mark(res, errorCodes.codeOf(result) ||
                                 'STS-AUTHZEN-0034');
          }
          self.sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API AuthZEN action. ok=" +
                    result.ok);
        },
        actions: [
          { action: 'set-attribute', operationId: 'setAuthzenAttribute',
            summary: 'Add or replace one row of the AuthZEN attribute ' +
                     'catalogue',
            description: 'Writes one authzenAttribute value on the realm\'s ' +
              'sts-authzen-api object, replacing the row for the same ' +
              'object and property. Refused for a row the catalogue\'s ' +
              'grammar refuses (STS-AUTHZEN-0010) and for one mapping onto a ' +
              'reserved identifier (STS-AUTHZEN-0011, 0012): a ' +
              'request-supplied attribute suppresses the PIP. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object', properties: ROW_PROPERTIES,
              required: ['object', 'property', 'attributeId'],
              examples: [{ object: 'resource', property: 'classification',
                           attributeId: 'urn:example:classification' }],
              additionalProperties: false
            },
            responseDescription: 'The row as stored.' },
          { action: 'remove-attribute', operationId: 'removeAuthzenAttribute',
            summary: 'Remove one row of the AuthZEN attribute catalogue',
            description: 'Takes the row for an object and property off. A ' +
              'request carrying that property is refused from then on, as ' +
              'an undeclared property is. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { object: ROW_PROPERTIES.object,
                            property: ROW_PROPERTIES.property },
              required: ['object', 'property'],
              examples: [{ object: 'resource', property: 'classification' }],
              additionalProperties: false
            },
            responseDescription: 'What was removed.' },
          { action: 'set-scope', operationId: 'setAuthzenScope',
            summary: 'Set the applications an AuthZEN caller may ask about',
            description: 'Replaces a caller\'s application scope: ' +
              'stsAuthzenApplication on a person\'s or service account\'s ' +
              'entry, appAuthzenApplication on an application. Empty ' +
              'clears it. Set by an administrator only; a caller never ' +
              'sets its own. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                caller: { type: 'string', minLength: 1, maxLength: 1024,
                          description: 'A username, an application ' +
                                       'identifier, or a DN.' },
                applications: {
                  description: 'The applications, as a list or as one ' +
                               'string separated by commas or spaces.',
                  oneOf: [{ type: 'string', maxLength: 16384 },
                          { type: 'array', maxItems: 64,
                            items: { type: 'string', maxLength: 256 } }] }
              },
              required: ['caller'],
              examples: [{ caller: 'todo-pep',
                           applications: ['todo-app'] }],
              additionalProperties: false
            },
            responseDescription: 'The caller and its scope as it now is.' },
          { action: 'set-callbacks', operationId: 'setAuthzenCallbacks',
            summary: 'Set the access request callback URLs of an AuthZEN ' +
                     'caller',
            description: 'Replaces the callback URLs registered for a ' +
              'caller (#1180): stsAuthzenCallbackUri on a person\'s or ' +
              'service account\'s entry, appAuthzenCallbackUri on an ' +
              'application. An access request\'s callback.endpoint must ' +
              'be one of them exactly; this service never dials a callback ' +
              'URL taken from a request alone. https only, at most eight. ' +
              'Empty clears them. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                caller: { type: 'string', minLength: 1, maxLength: 1024,
                          description: 'A username, an application ' +
                                       'identifier, or a DN.' },
                callbacks: {
                  description: 'The URLs, as a list or as one string ' +
                               'separated by commas or spaces.',
                  oneOf: [{ type: 'string', maxLength: 16384 },
                          { type: 'array', maxItems: 8,
                            items: { type: 'string', maxLength: 2048 } }] }
              },
              required: ['caller'],
              examples: [{ caller: 'todo-pep', callbacks:
                ['https://pep.example.com/callbacks/access-requests'] }],
              additionalProperties: false
            },
            responseDescription: 'The caller and its callbacks as they now ' +
                                 'are.' },
          { action: 'approve-access-request',
            operationId: 'approveAuthzenAccessRequest',
            summary: 'Approve an AuthZEN access request',
            description: 'Approves a pending access request (#1180) as the ' +
              'caller, after the access-control policy (action ' +
              'approve-access-request on resource authzen-access-request) ' +
              'permitted it — refused, among others, for the request\'s ' +
              'own subject. The approval is handed to the PEP, whose next ' +
              'evaluation the realm\'s policy decides afresh. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                request: { type: 'string', minLength: 1, maxLength: 128,
                           description: 'The access request\'s id ' +
                                        '(arq_...).' }
              },
              required: ['request'],
              examples: [{ request: 'arq_EXAMPLE' }],
              additionalProperties: false
            },
            responseDescription: 'The access request as it now is.' },
          { action: 'deny-access-request',
            operationId: 'denyAuthzenAccessRequest',
            summary: 'Deny an AuthZEN access request',
            description: 'Denies a pending access request (#1180) as the ' +
              'caller, asked of the access-control policy as an approval ' +
              'is. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                request: { type: 'string', minLength: 1, maxLength: 128,
                           description: 'The access request\'s id ' +
                                        '(arq_...).' }
              },
              required: ['request'],
              examples: [{ request: 'arq_EXAMPLE' }],
              additionalProperties: false
            },
            responseDescription: 'The access request as it now is.' },
          { action: 'revoke-access-request',
            operationId: 'revokeAuthzenAccessRequest',
            summary: 'Revoke an AuthZEN access request\'s approval',
            description: 'Revokes the approval of an approved access ' +
              'request (#1180), asked of the access-control policy as an ' +
              'approval is: a re-evaluation carrying it is not approved ' +
              'from then on (approval_expired). Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                request: { type: 'string', minLength: 1, maxLength: 128,
                           description: 'The access request\'s id ' +
                                        '(arq_...).' }
              },
              required: ['request'],
              examples: [{ request: 'arq_EXAMPLE' }],
              additionalProperties: false
            },
            responseDescription: 'The access request as it now is.' },
          { action: 'cancel-access-request',
            operationId: 'cancelAuthzenAccessRequest',
            summary: 'Cancel an AuthZEN access request',
            description: 'Cancels a pending access request (#1180) as an ' +
              'administrator; its callback, if it asked for one, is sent. ' +
              'Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                request: { type: 'string', minLength: 1, maxLength: 128,
                           description: 'The access request\'s id ' +
                                        '(arq_...).' }
              },
              required: ['request'],
              examples: [{ request: 'arq_EXAMPLE' }],
              additionalProperties: false
            },
            responseDescription: 'The access request as it now is.' }
        ] }
    ];
    log.debug("Leaving AuthzenApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<AuthzenApi>(
  'mgmt-api/authzen_api',
  () => new AuthzenApi(AuthzenApi.defaultDeps()),
  AuthzenApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The AuthZEN operations of `/admin-api` (#563), mirroring the AuthZEN tab.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  AuthzenApi: AuthzenApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: AuthzenApi): void => slot.install(instance),
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
