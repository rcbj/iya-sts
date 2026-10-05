// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: attribute_sources_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/attribute-sources OPERATIONS (#94 part C), mirroring
// /admin/attribute-sources (rule 7): the register as the page draws it, and
// its six acts, each `attribute_sources.ts`'s `act()` — the console's own.
//
// It registers no route: `mgmt-api/admin_api.ts` spreads `ROUTES` into its
// table, as it does the Claims Provider operations'.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface AttributeSourcesApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  loadSources(): Json;
  // The page's module, for the one view the page and the GET both answer
  // (#446). Lazily, as `loadSources` is: this module is built before the
  // console's pages are.
  loadPage(): Json;
}

const BASE = '/admin-api';

// A source's members, as `add-source` and `update-source` take them. The
// dialect list is this step's: SQL Server and Oracle arrive with #94's next.
const SOURCE_PROPERTIES = {
  id: { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,62}$',
        description: 'The source\'s id in this realm.' },
  dialect: { type: 'string', enum: ['postgres', 'mysql'],
             description: 'PostgreSQL, or MySQL / MariaDB.' },
  host: { type: 'string', maxLength: 253,
          description: 'The database host; attributeSources.hostPatterns ' +
                       'may narrow it.' },
  port: { type: 'integer', minimum: 1, maximum: 65535 },
  database: { type: 'string', maxLength: 128 },
  user: { type: 'string', maxLength: 128 },
  passwordProvider: { type: 'string',
                      enum: ['none', 'file', 'aws', 'gcp', 'azure', 'vault'],
                      description: 'Where the password is read from, ' +
                                   'through common/secrets.js; never ' +
                                   'stored here.' },
  passwordRef: { type: 'string', maxLength: 1024,
                 description: 'A path (file) or a secret\'s name; empty ' +
                              'is the key-encryption key\'s location.' },
  passwordField: { type: 'string', maxLength: 128,
                   description: 'The field, where the secret is a JSON ' +
                                'object.' },
  caFile: { type: 'string', maxLength: 1024,
            description: 'A PEM file of CA certificates on this service\'s ' +
                         'disk, added to caCertificates. TLS is always ' +
                         'verified.' },
  caCertificates: { type: 'string', maxLength: 65536,
                    description: 'The database\'s trust chain as PEM ' +
                                 'certificates, stored with the source. ' +
                                 'Trusted ALONE unless trustPublicRoots; ' +
                                 'with no chain and no caFile, the public ' +
                                 'roots are used. An empty string clears ' +
                                 'it. A block that does not parse, or an ' +
                                 'expired certificate, is refused.' },
  trustPublicRoots: { type: 'boolean',
                      description: 'Trust node\'s public roots beside ' +
                                   'caCertificates. Off by default.' },
  serverName: { type: 'string', maxLength: 253,
                description: 'The name the certificate is checked against; ' +
                             'the host when empty.' },
  table: { type: 'string', maxLength: 129,
           description: 'A table or view, optionally schema.table.' },
  keyColumn: { type: 'string', maxLength: 63 },
  keyAttribute: { type: 'string', maxLength: 64,
                  description: 'The person\'s attribute the key column ' +
                               'holds (uid, employeeNumber, entryUUID…).' },
  columns: { type: 'object', additionalProperties: { type: 'string' },
             description: '{ "<column>": "<directory attribute>" }. No ' +
                          'attribute this service keeps, no identity or ' +
                          'group membership, no mail; an attribute has one ' +
                          'source.' },
  refresh: { type: 'array',
             items: { type: 'string',
                      enum: ['once', 'sign-in', 'schedule', 'on-demand'] },
             description: 'When a person is read.' },
  scheduleS: { type: 'integer', minimum: 60,
               description: 'The scheduled refresh\'s interval.' },
  timeoutMs: { type: 'integer', minimum: 100, maximum: 30000 },
  onFailure: { type: 'string', enum: ['keep', 'refuse'],
               description: 'keep: the stored values stand and the sign-in ' +
                            'proceeds; refuse: the sign-in is refused.' },
  enabled: { type: 'boolean' }
};

/**
 * The `/admin-api/attribute-sources` operations: the register and its six
 * acts, each the console's own.
 */
class AttributeSourcesApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   register
   */
  constructor(private readonly deps: AttributeSourcesApiDeps) {
    deps.log.debug("Entering AttributeSourcesApi.constructor().");
    deps.log.debug("Leaving AttributeSourcesApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports, with the
   * register loaded lazily.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): AttributeSourcesApiDeps {
    helpers.log.debug("Entering AttributeSourcesApi.defaultDeps().");
    helpers.log.debug("Leaving AttributeSourcesApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadSources: function (): Json {
        return require('./attribute_sources');
      },
      loadPage: function (): Json {
        return require('./attribute_sources_admin');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: AttributeSourcesApi): void {
    helpers.log.debug("Entering AttributeSourcesApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving AttributeSourcesApi.wire().");
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
    log.debug("Entering AttributeSourcesApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving AttributeSourcesApi.sendJson().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadSources,
            loadPage } = this.deps;
    const self = this;
    log.debug("Entering AttributeSourcesApi.buildRoutes().");
    const idOnly = { type: 'object', properties: { id: SOURCE_PROPERTIES.id },
                     required: ['id'], examples: [{ id: 'hr-db' }],
                     additionalProperties: false };
    const ROUTES = [
      { method: 'GET', path: BASE + '/attribute-sources',
        tag: 'Directory', operationId: 'getAttributeSources',
        summary: 'The SQL databases this realm reads people\'s attributes ' +
                 'from (#94)',
        description: 'Everything /admin/attribute-sources draws: each ' +
          'source (its database, the row it reads, the columns it writes ' +
          'onto which attributes, when it reads and what a failure does) ' +
          'with its status, and the rules a definition is held to. Never a ' +
          'password.',
        mirrors: 'GET /admin/attribute-sources',
        responseDescription: 'The register.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`sources`, `dialects`, `modes`, ' +
                                       '`hostPatterns`, `refused`, and ' +
                                       '`settings` — the page\'s settings ' +
                                       'block, as every page that owns ' +
                                       'settings answers it.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API attribute sources " +
                    "endpoint.");
          self.sendJson(res, 200, loadPage().attributeSourcesView());
          log.debug("Leaving the management API attribute sources " +
                    "endpoint.");
        } },

      { method: 'POST', route: BASE + '/attribute-sources/:action',
        tag: 'Directory', mirrors: 'POST /admin/attribute-sources',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API attribute sources action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          Promise.resolve().then(function (): Json {
            return loadSources().act(body, { via: 'api',
                                             actor: 'admin-api' });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-ATTR-0002');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API attribute sources " +
                      "action. ok=" + result.ok);
          }, function (e: any): void {
            log.error(errorCodes.tag('STS-ATTR-0002') + 'attribute sources: ' +
                      'an /admin-api action failed: ' + ((e && e.stack) || e));
            errorCodes.mark(res, 'STS-ATTR-0002');
            self.sendJson(res, 500, { ok: false, errors:
                                        ['The action could not be ' +
                                         'completed.'] });
            log.debug("Leaving the management API attribute sources " +
                      "action. Threw.");
          });
        },
        actions: [
          { action: 'add-source', operationId: 'addAttributeSource',
            summary: 'Add an attribute source',
            description: 'A database this realm reads people\'s attributes ' +
              'from. Refused for an attribute another source writes, one ' +
              'no outside source may write, a host ' +
              'attributeSources.hostPatterns does not allow, or a name ' +
              'that is not an identifier. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object', properties: SOURCE_PROPERTIES,
              required: ['id', 'dialect', 'host', 'database', 'user',
                         'table', 'keyColumn', 'columns'],
              examples: [{ id: 'hr-db', dialect: 'postgres',
                           host: 'db.example.com', database: 'hr',
                           user: 'iya_reader', passwordProvider: 'vault',
                           passwordRef: 'secret/hr-db',
                           table: 'people', keyColumn: 'login',
                           keyAttribute: 'uid',
                           columns: { cost_center: 'costCenter',
                                      grade: 'employeeType' },
                           refresh: ['sign-in', 'schedule'] }],
              additionalProperties: false
            },
            responseDescription: 'The source as stored.' },
          { action: 'update-source', operationId: 'updateAttributeSource',
            summary: 'Change an attribute source',
            description: 'The members given replace the source\'s; the rest ' +
              'are kept. Checked as add-source is. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object', properties: SOURCE_PROPERTIES,
              required: ['id'],
              examples: [{ id: 'hr-db', onFailure: 'refuse' }],
              additionalProperties: false
            },
            responseDescription: 'The source as stored.' },
          { action: 'remove-source', operationId: 'removeAttributeSource',
            summary: 'Remove an attribute source',
            description: 'It leaves the register; what it wrote on people\'s ' +
              'entries stays. Audited.',
            requestBodyRequired: true,
            requestBody: idOnly,
            responseDescription: 'What was removed.' },
          { action: 'test-source', operationId: 'testAttributeSource',
            summary: 'Connect to a source and read one row, writing nothing',
            description: 'Reads the row for a person (by `username`, whose ' +
              'key attribute is used) or for a `key` given outright, and ' +
              'returns it. Nothing is written.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { id: SOURCE_PROPERTIES.id,
                            username: { type: 'string', maxLength: 256 },
                            key: { type: 'string', maxLength: 1024 } },
              required: ['id'],
              examples: [{ id: 'hr-db', username: 'alice' }],
              additionalProperties: false
            },
            responseDescription: '`found` and the `row`.' },
          { action: 'refresh-source', operationId: 'refreshAttributeSource',
            summary: 'Read every person from a source now',
            description: 'Queues the scheduled refresh for this source, ' +
              'which reads the realm\'s people a page at a time. Audited.',
            requestBodyRequired: true,
            requestBody: idOnly,
            responseDescription: 'The scheduler run, in `runId`.' },
          { action: 'refresh-person',
            operationId: 'refreshAttributeSourcePerson',
            summary: 'Read one person from the sources now',
            description: 'From every source that allows on-demand, or the ' +
              'one named by `id`. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { username: { type: 'string', maxLength: 256 },
                            id: SOURCE_PROPERTIES.id },
              required: ['username'],
              examples: [{ username: 'alice' }],
              additionalProperties: false
            },
            responseDescription: 'What changed, and which sources failed.' }
        ] }
    ];
    log.debug("Leaving AttributeSourcesApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<AttributeSourcesApi>(
  'attribute-sources/attribute_sources_api',
  () => new AttributeSourcesApi(AttributeSourcesApi.defaultDeps()),
  AttributeSourcesApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The attribute source operations of `/admin-api` (#94), mirroring
 * `/admin/attribute-sources`.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  AttributeSourcesApi: AttributeSourcesApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: AttributeSourcesApi): void =>
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
