// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: secret_destinations_api.ts
// ---------------------------------------------------------------------------
// THE /admin-api/secret-destinations OPERATIONS (#221 P3), mirroring
// Directory → Secret destinations (rule 7): the register as the page draws
// it, and its four acts, each `common/secret_destinations.ts`'s `act()` —
// the console's own, since the static console sends its forms here.
//
// **NO ANSWER CARRIES A WRITE CREDENTIAL.** The register's view says
// `credentialSet` and the shape a provider takes; the credential is a member
// an add or a change TAKES and nothing gives back (write-only, #221).
//
// It registers no route: `mgmt-api/admin_api.ts` spreads `ROUTES` into its
// table, as it does the attribute source operations'.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface SecretDestinationsApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  // The register, lazily: this module is built with the other API modules,
  // and the register is only asked inside a handler.
  loadDestinations(): Json;
}

const BASE = '/admin-api';

// A destination's members, as `add-destination` and `update-destination`
// take them. The enums are read off `common/secrets.js` when the table is
// built, so the document cannot offer what the push refuses.
function destinationProperties(): Json {
  helpers.log.debug("Entering destinationProperties().");
  const secrets = require('../common/secrets');
  helpers.log.debug("Leaving destinationProperties().");
  return {
    identifier: { type: 'string', minLength: 1, maxLength: 512,
                  description: 'The destination\'s application identifier ' +
                               '(add only): the entry it is filed under in ' +
                               'ou=applications.' },
    id: { type: 'string', maxLength: 2048,
          description: 'The destination: its entry\'s DN, as the register ' +
                       'answers it, or its identifier.' },
    name: { type: 'string', maxLength: 256,
            description: 'What to call it on a page.' },
    provider: { type: 'string', enum: secrets.DESTINATION_PROVIDERS.slice(),
                description: 'aws, gcp, azure, vault, or file (development ' +
                             'mode only).' },
    payload: { type: 'string', enum: secrets.DESTINATION_PAYLOADS.slice(),
               description: 'password (the bare password) or json ' +
                            '({username, password, realm, rotatedAt}).' },
    region: { type: 'string', maxLength: 64,
              description: 'aws: the region.' },
    project: { type: 'string', maxLength: 128,
               description: 'gcp: the project a short secret name is in.' },
    endpoint: { type: 'string', maxLength: 2048,
                description: 'azure: the vault URL; vault: its address. ' +
                             'https only.' },
    mount: { type: 'string', maxLength: 256,
             description: 'vault: the KV version 2 mount; secret when ' +
                          'empty.' },
    field: { type: 'string', maxLength: 128,
             description: 'vault, password payload: the field written; ' +
                          'value when empty.' },
    directory: { type: 'string', maxLength: 1024,
                 description: 'file: the absolute directory a secret name ' +
                              'is a file in.' },
    caCertificates: { type: 'string', maxLength: 65536,
                      description: 'vault: PEM certificates of the CA its ' +
                                   'listener chains to.' },
    credential: { type: 'string', maxLength: 16384, writeOnly: true,
                  description: 'The WRITE credential, write-only: never ' +
                               'returned, drawn or logged. aws: JSON ' +
                               '{accessKeyId, secretAccessKey[, ' +
                               'sessionToken]}; gcp: a service account ' +
                               'key\'s JSON; azure: JSON {tenantId, ' +
                               'clientId, clientSecret}; vault: a token. ' +
                               'On a change, empty keeps the one set.' }
  };
}

/**
 * The `/admin-api/secret-destinations` operations: the register and its four
 * acts, each the console's own.
 */
class SecretDestinationsApi {
  /**
   * Builds the module from its dependencies.
   *
   * @param deps - the logger, body parser, error codes and a loader of the
   *   register
   */
  constructor(private readonly deps: SecretDestinationsApiDeps) {
    deps.log.debug("Entering SecretDestinationsApi.constructor().");
    deps.log.debug("Leaving SecretDestinationsApi.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports, with the
   * register loaded lazily.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): SecretDestinationsApiDeps {
    helpers.log.debug("Entering SecretDestinationsApi.defaultDeps().");
    helpers.log.debug("Leaving SecretDestinationsApi.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      loadDestinations: function (): Json {
        return require('../common/secret_destinations');
      }
    };
  }

  /**
   * Builds the route table for the installed instance.
   *
   * @param instance - the instance installed
   */
  static wire(instance: SecretDestinationsApi): void {
    helpers.log.debug("Entering SecretDestinationsApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving SecretDestinationsApi.wire().");
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
    log.debug("Entering SecretDestinationsApi.sendJson(). status=" + status);
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(body, null, 2));
    log.debug("Leaving SecretDestinationsApi.sendJson().");
  }

  /**
   * Builds the operations' route table, each row carrying its OpenAPI
   * description and its handler.
   *
   * @returns the route rows
   */
  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadDestinations } = this.deps;
    const self = this;
    log.debug("Entering SecretDestinationsApi.buildRoutes().");
    const PROPS = destinationProperties();
    const ROUTES = [
      { method: 'GET', path: BASE + '/secret-destinations',
        tag: 'Directory', operationId: 'getSecretDestinations',
        summary: 'Where this realm pushes service accounts\' rotated ' +
                 'passwords (#221)',
        description: 'Everything Directory → Secret destinations draws: ' +
          'each destination (an application entry declared for the ' +
          'secret-destination family) with its provider, payload, ' +
          'location, whether a write credential is set, and whether it is ' +
          'usable and why not; the providers and payloads offered, and ' +
          'what each provider\'s credential is. NEVER a credential.',
        mirrors: 'GET /admin/secret-destinations',
        responseDescription: 'The register.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`destinations`, `providers`, ' +
                                       '`payloads`, `credentialShapes`, ' +
                                       '`fileAllowed`, `family`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API secret destinations " +
                    "endpoint.");
          self.sendJson(res, 200, loadDestinations().view());
          log.debug("Leaving the management API secret destinations " +
                    "endpoint.");
        } },

      { method: 'POST', route: BASE + '/secret-destinations/:action',
        tag: 'Directory', mirrors: 'POST /admin/secret-destinations',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API secret destinations " +
                    "action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          Promise.resolve().then(function (): Json {
            // THE CALLER, which the route wrapper put in the body's
            // `actor` after its schema passed (`nameActor()`, #446).
            return loadDestinations().act(body, {
              via: 'api', actor: String(body.actor || '') });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-SECDEST-0013');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API secret destinations " +
                      "action. ok=" + result.ok);
          }, function (e: any): void {
            log.error(errorCodes.tag('STS-SECDEST-0013') + 'secret ' +
                      'destinations: an /admin-api action failed: ' +
                      ((e && e.message) || e));
            errorCodes.mark(res, 'STS-SECDEST-0013');
            self.sendJson(res, 500, { ok: false, errors:
                                        ['The action could not be ' +
                                         'completed.'] });
            log.debug("Leaving the management API secret destinations " +
                      "action. Threw.");
          });
        },
        actions: [
          { action: 'add-destination', operationId: 'addSecretDestination',
            summary: 'Add a secret push destination',
            description: 'Creates an application entry declared for the ' +
              'secret-destination family, with its location and its write ' +
              'credential (sealed, write-only). Refused for an unknown ' +
              'provider or payload, a missing location, a credential that ' +
              'is not its provider\'s shape, a plain http address, or a ' +
              'file in product mode. Audited, without the credential.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                identifier: PROPS.identifier, name: PROPS.name,
                provider: PROPS.provider, payload: PROPS.payload,
                region: PROPS.region, project: PROPS.project,
                endpoint: PROPS.endpoint, mount: PROPS.mount,
                field: PROPS.field, directory: PROPS.directory,
                caCertificates: PROPS.caCertificates,
                credential: PROPS.credential },
              required: ['identifier', 'provider'],
              examples: [{ identifier: 'vault-prod', name: 'Production Vault',
                           provider: 'vault', payload: 'json',
                           endpoint: 'https://vault.example.com:8200',
                           mount: 'secret', credential: '<a token>' }],
              additionalProperties: false
            },
            responseDescription: 'The destination as the register now ' +
                                 'answers it.' },
          { action: 'update-destination',
            operationId: 'updateSecretDestination',
            summary: 'Change a secret push destination',
            description: 'The members given replace the destination\'s; the ' +
              'rest are kept, the credential included when none is given. ' +
              'Checked as add-destination is. Audited, without the ' +
              'credential.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                id: PROPS.id, name: PROPS.name,
                provider: PROPS.provider, payload: PROPS.payload,
                region: PROPS.region, project: PROPS.project,
                endpoint: PROPS.endpoint, mount: PROPS.mount,
                field: PROPS.field, directory: PROPS.directory,
                caCertificates: PROPS.caCertificates,
                credential: PROPS.credential },
              required: ['id'],
              examples: [{ id: 'vault-prod', payload: 'password' }],
              additionalProperties: false
            },
            responseDescription: 'The destination as the register now ' +
                                 'answers it.' },
          { action: 'remove-destination',
            operationId: 'removeSecretDestination',
            summary: 'Remove a secret push destination',
            description: 'Deletes its application entry, credential and ' +
              'all. Nothing at the secrets manager changes. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object', properties: { id: PROPS.id },
              required: ['id'], examples: [{ id: 'vault-prod' }],
              additionalProperties: false
            },
            responseDescription: 'What was removed.' },
          { action: 'test-push', operationId: 'testSecretDestination',
            summary: 'Write a canary version to a test secret',
            description: 'Writes a random password nobody uses, as the ' +
              'destination\'s payload, to `secretName` — which must already ' +
              'exist and must be kept for testing: a secret a service ' +
              'account\'s rotation writes is refused. Proves the ' +
              'credential, the address and the secret. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { id: PROPS.id,
                            secretName: { type: 'string', minLength: 1,
                                          maxLength: 512,
                                          description: 'The test secret.' } },
              required: ['id', 'secretName'],
              examples: [{ id: 'vault-prod', secretName: 'sts-push-canary' }],
              additionalProperties: false
            },
            responseDescription: '`ok` and the `version` the store ' +
                                 'answered, or a coded refusal.' }
        ] }
    ];
    log.debug("Leaving SecretDestinationsApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<SecretDestinationsApi>(
  'mgmt-api/secret_destinations_api',
  () => new SecretDestinationsApi(SecretDestinationsApi.defaultDeps()),
  SecretDestinationsApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The secret destination operations of `/admin-api` (#221), mirroring
 * Directory → Secret destinations.
 *
 * It registers no route: the management API spreads `ROUTES` into its table.
 *
 * @namespace
 */
export = {
  SecretDestinationsApi: SecretDestinationsApi,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: SecretDestinationsApi): void =>
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
