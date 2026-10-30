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
  sendJson(res: Res, status: number, body: Json): void {
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
    const ROUTES = [
      { method: 'GET', path: BASE + '/uma', tag: 'UMA',
        operationId: 'getUma',
        summary: 'UMA 2.0: resource servers, resources, tickets, RPTs, ' +
                 'pending approvals, an owner, the what-if, settings',
        description: 'Everything /admin/uma draws: whether UMA answers in ' +
          'this realm, its endpoints, the applications declared for uma ' +
          'with umaOwnsResources and the delegated permission grant a PAT ' +
          'needs, the registered resources (paged, `resourcesPage`; ' +
          'filtered by `resourceServer` and `owner`), the live permission ' +
          'tickets (`ticketsPage`, by the first characters of a hash, never ' +
          'the ticket), the live RPTs (`rptsPage`), the requests waiting for ' +
          'an owner (`pendingPage`), the UMA PEP\'s counts, and the uma.* ' +
          'settings, written through POST /admin-api/config/set-many. ' +
          '`?owner=<username or application>` adds that owner\'s resources, ' +
          'document and waiting requests; an application\'s owner asking ' +
          'about it is answered with that alone. `?resource=&scope=` ' +
          '(with `party` and `client`) adds the what-if: every layer\'s ' +
          'answer for that permission, asked as a dry run that is neither ' +
          'audited nor counted.',
        mirrors: 'GET /admin/uma',
        responseDescription: '`enabled`, `endpoints`, `resourceServers`, ' +
          '`resources`, `tickets`, `rpts`, `pending`, `owner`, `whatIf`, ' +
          '`monitor`, `actions`, `settings`.',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API UMA endpoint.");
          self.sendJson(res, 200, loadConsole().view(req));
          log.debug("Leaving the management API UMA endpoint.");
        } },
      { method: 'GET', path: BASE + '/uma/monitor', tag: 'UMA',
        operationId: 'getUmaMonitor',
        summary: 'The UMA PEP\'s counts and what each resource server holds',
        description: 'The uma row of /admin/xacml/monitor (decisions, ' +
          'allowed, refused, since the process started) and, per resource ' +
          'server, its resources, live tickets, live RPTs and waiting ' +
          'requests. Per trust realm, and with no reset: the durable record ' +
          'is GET /admin-api/audit.',
        mirrors: 'GET /admin/uma#uma-tab-servers',
        responseDescription: '`pep`, `resourceServers`, `totals`.',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API UMA monitor endpoint.");
          self.sendJson(res, 200, loadConsole().monitorView());
          log.debug("Leaving the management API UMA monitor endpoint.");
        } },
      { method: 'POST', route: BASE + '/uma/:action', tag: 'UMA',
        mirrors: 'POST /admin/uma',
        handler: function (req: Req, res: Res): void {
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
            operationId: 'enableUmaResourceServer',
            summary: 'Make an application a UMA resource server',
            description: 'Adds uma to the application\'s appAllowedProtocol ' +
              'and the delegated permission grant of ' +
              'urn:sts:uma-protection-api:uma_protection, which a PAT ' +
              'needs. A value already there is left. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { application: APPLICATION },
              required: ['application'],
              examples: [{ application: 'photos-api' }],
              additionalProperties: false },
            responseDescription: 'The application, and whether it changed.' },
          { action: 'disable-resource-server',
            operationId: 'disableUmaResourceServer',
            summary: 'Stop an application being a UMA resource server',
            description: 'Takes uma and the uma_protection grant off the ' +
              'application, and revokes every live RPT issued for it. Its ' +
              'registered resources stay, unreachable, until it is enabled ' +
              'again or they are deleted. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { application: APPLICATION },
              required: ['application'],
              examples: [{ application: 'photos-api' }],
              additionalProperties: false },
            responseDescription: 'The application, and how many RPTs were ' +
                                 'revoked.' },
          { action: 'set-owns-resources',
            operationId: 'setUmaOwnsResources',
            summary: 'Let an application own UMA resources, or not',
            description: 'Sets umaOwnsResources (rcbj\'s decision 5): TRUE ' +
              'lets a PAT the application obtained as itself register ' +
              'resources it owns; anything else clears it, after which such ' +
              'a PAT is refused (STS-UMA-0105). Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { application: APPLICATION,
                value: { type: 'string', enum: ['TRUE', 'FALSE'],
                         description: 'TRUE, or FALSE to clear it.' } },
              required: ['application', 'value'],
              examples: [{ application: 'photos-api', value: 'TRUE' }],
              additionalProperties: false },
            responseDescription: 'The application and its value now.' },
          { action: 'delete-resource', operationId: 'deleteUmaResource',
            summary: 'Delete a registered UMA resource',
            description: 'Removes the resource as its resource server\'s ' +
              'DELETE would, and revokes every live RPT carrying a ' +
              'permission over it. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { resource: { type: 'string', minLength: 1,
                maxLength: 128, description: 'The resource\'s _id.' } },
              required: ['resource'],
              examples: [{ resource: 'no-such-resource-example' }],
              additionalProperties: false },
            responseDescription: 'The resource, and how many RPTs were ' +
                                 'revoked.' },
          { action: 'revoke-rpt', operationId: 'revokeUmaRpt',
            summary: 'Revoke one RPT',
            description: 'Revokes a live RPT by its jti: introspection ' +
              'answers inactive from then on. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { rpt: { type: 'string', minLength: 1,
                maxLength: 128, description: 'The RPT\'s jti.' } },
              required: ['rpt'],
              examples: [{ rpt: 'no-such-rpt-example' }],
              additionalProperties: false },
            responseDescription: 'The jti, and how many were revoked.' },
          { action: 'owner-share', operationId: 'shareUmaResource',
            summary: 'Share an application\'s resource',
            description: 'Adds a share to the document of an application ' +
              'that owns UMA resources, as a person does on /portal/shared. ' +
              'An application\'s owners may call it under the owner rule. ' +
              'Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: {
                owner: OWNER,
                resource: { type: 'string', maxLength: 128,
                            description: 'The resource\'s _id.' },
                scope: { description: 'The scopes, a list or one string.',
                         oneOf: [{ type: 'string', maxLength: 4096 },
                                 { type: 'array', maxItems: 64,
                                   items: { type: 'string',
                                            maxLength: 256 } }] },
                recipientKind: { type: 'string',
                                 enum: ['person', 'group', 'realm', 'claim'],
                                 description: 'Who it is shared with.' },
                recipient: { type: 'string', maxLength: 1024,
                             description: 'A username, a group, or a ' +
                                          'claim\'s value; nothing for ' +
                                          'realm.' },
                claim: { type: 'string', maxLength: 256,
                         description: 'For a claim share, its name.' },
                expires: { type: 'string', maxLength: 64,
                           description: 'When it ends (a date), or empty.' },
                acr: { type: 'string', maxLength: 256,
                       description: 'An authentication context the ' +
                                    'requesting party must have.' },
                askMe: { type: 'string', maxLength: 8,
                         description: 'on: ask the owner each time.' } },
              required: ['owner', 'resource', 'scope', 'recipientKind'],
              examples: [{ owner: 'photos-api', resource: 'no-such-example',
                           scope: 'view', recipientKind: 'person',
                           recipient: 'alice' }],
              additionalProperties: false },
            responseDescription: 'The share as written.' },
          { action: 'owner-unshare', operationId: 'unshareUmaResource',
            summary: 'Remove a share from an application\'s document',
            description: 'Removes one share and revokes the RPTs it ' +
              'permitted. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { owner: OWNER,
                share: { type: 'string', minLength: 1, maxLength: 128,
                         description: 'The share\'s id.' } },
              required: ['owner', 'share'],
              examples: [{ owner: 'photos-api', share: 'no-such-example' }],
              additionalProperties: false },
            responseDescription: 'What was removed.' },
          { action: 'owner-approve', operationId: 'approveUmaRequest',
            summary: 'Approve a request waiting for an application',
            description: 'Approves a request_submitted waiting for an ' +
              'application that owns resources: a rule for it is written ' +
              'into the document. The client\'s next try with its ticket is ' +
              'decided afresh. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { owner: OWNER,
                pending: { type: 'string', minLength: 1, maxLength: 128,
                           description: 'The waiting request\'s id.' } },
              required: ['owner', 'pending'],
              examples: [{ owner: 'photos-api', pending: 'no-such-example' }],
              additionalProperties: false },
            responseDescription: 'The request as it now is.' },
          { action: 'owner-refuse', operationId: 'refuseUmaRequest',
            summary: 'Refuse a request waiting for an application',
            description: 'Refuses a request_submitted waiting for an ' +
              'application that owns resources. Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object',
              properties: { owner: OWNER,
                pending: { type: 'string', minLength: 1, maxLength: 128,
                           description: 'The waiting request\'s id.' } },
              required: ['owner', 'pending'],
              examples: [{ owner: 'photos-api', pending: 'no-such-example' }],
              additionalProperties: false },
            responseDescription: 'The request as it now is.' }
        ] }
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
