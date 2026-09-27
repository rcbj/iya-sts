'use strict';
//
// File: ssf_transmitters_api.ts
//
// ===========================================================================
// `/admin-api/ssf/transmitters` (#153, 2026-09-26): /admin/ssf/transmitters
// for a machine (rule 7) — the foreign transmitters, what arrived and the
// locks, and the page's acts, each the console's own
// (`ssf_transmitters.ts`'s `report()` and `act()`). Never a secret. Registers
// no route: `mgmt-api/admin_api.ts` spreads ROUTES into its table.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');

type Req = any;
type Res = any;
type Json = any;

interface TransmittersApiDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  loadTransmitters(): Json;
}

const BASE = '/admin-api';
const ID = { type: 'string', pattern: '^[a-z0-9][a-z0-9-]{0,39}$',
             description: 'The transmitter\'s id in this realm.' };
const ONE = { type: 'object', properties: { id: ID }, required: ['id'],
              examples: [{ id: 'partner' }], additionalProperties: false };

class SsfTransmittersApi {
  constructor(private readonly deps: TransmittersApiDeps) {
    deps.log.debug("Entering SsfTransmittersApi.constructor().");
    deps.log.debug("Leaving SsfTransmittersApi.constructor().");
  }

  static defaultDeps(): TransmittersApiDeps {
    helpers.log.debug("Entering SsfTransmittersApi.defaultDeps().");
    helpers.log.debug("Leaving SsfTransmittersApi.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes,
      loadTransmitters: function (): Json {
        return require('./ssf_transmitters');
      }
    };
  }

  static wire(instance: SsfTransmittersApi): void {
    helpers.log.debug("Entering SsfTransmittersApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving SsfTransmittersApi.wire().");
  }

  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering SsfTransmittersApi.sendJson(). status=" + status);
    const reply = Object.assign({}, body);
    delete reply.errorCode;
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving SsfTransmittersApi.sendJson().");
  }

  buildRoutes(): Json[] {
    const { log, parseBody, errorCodes, loadTransmitters,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmittersApi.buildRoutes().");
    const simple = function (action: string, operationId: string,
                             summary: string, description: string): Json {
      return { action: action, operationId: operationId, summary: summary,
               description: description, requestBodyRequired: true,
               requestBody: ONE,
               responseDescription: 'The transmitter as it stands.' };
    };
    const ROUTES = [
      { method: 'GET', path: BASE + '/ssf/transmitters',
        tag: 'Shared Signals', operationId: 'getForeignTransmitters',
        summary: 'The foreign SSF transmitters this realm receives from',
        description: 'Everything /admin/ssf/transmitters draws: each ' +
          'transmitter (its issuer, discovered configuration, federation ' +
          'relationship, delivery, stream and counts), every Security ' +
          'Event Token that arrived with whether it verified, the person ' +
          'it named and what it led to, and the account locks a ' +
          'transmitter\'s account-disabled put on people here. Never a ' +
          'secret. `transmitter` narrows what arrived.',
        mirrors: 'GET /admin/ssf/transmitters',
        responseDescription: 'The report.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`transmitters`, `received`, ' +
                                       '`locks`, `observeOnly`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API transmitters endpoint.");
          self.sendJson(res, 200, loadTransmitters().report({
            transmitter: req.query.transmitter }));
          log.debug("Leaving the management API transmitters endpoint.");
        } },

      { method: 'POST', route: BASE + '/ssf/transmitters/:action',
        tag: 'Shared Signals', mirrors: 'POST /admin/ssf/transmitters',
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API transmitters action.");
          const body = Object.assign({}, parseBody(req),
            { action: String(req.params.action || '') });
          Promise.resolve().then(function (): Json {
            return loadTransmitters().act(body, { via: 'api',
              actor: 'admin-api', base: baseUrlOf(req) });
          }).then(function (result: Json): void {
            if (!result.ok) {
              // error-code: none — the act's own code, read off the result
              errorCodes.mark(res, errorCodes.codeOf(result) ||
                                   'STS-SSF-0113');
            }
            self.sendJson(res, result.ok ? 200 : 400, result);
            log.debug("Leaving the management API transmitters action.");
          }, function (e: any): void {
            log.error(errorCodes.tag('STS-SSF-0113') + 'ssf: an ' +
                      '/admin-api transmitter action failed: ' +
                      ((e && e.stack) || e));
            errorCodes.mark(res, 'STS-SSF-0113');
            self.sendJson(res, 500, { ok: false, errors:
              ['The action could not be completed.'] });
          });
        },
        actions: [
          { action: 'add', operationId: 'addForeignTransmitter',
            summary: 'Register a foreign SSF transmitter',
            description: 'Discovers the issuer\'s ' +
              '/.well-known/ssf-configuration (which must name that ' +
              'issuer) and fetches its jwks_uri. `federationId` names the ' +
              'federation relationship whose linked identities its ' +
              'subjects are mapped through. Authenticates to it by client ' +
              'credentials at `tokenEndpoint`, or by `bearer`; the secret ' +
              'is sealed. Audited.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                id: ID,
                issuer: { type: 'string', maxLength: 2048 },
                discoveryUrl: { type: 'string', maxLength: 2048,
                  description: 'Where the configuration document is, when ' +
                               'not at the issuer\'s well-known address.' },
                federationId: { type: 'string', maxLength: 128 },
                delivery: { type: 'string', enum: ['poll', 'push'] },
                eventsRequested: { type: 'array', items: { type: 'string',
                                                           maxLength: 256 } },
                tokenEndpoint: { type: 'string', maxLength: 2048 },
                clientId: { type: 'string', maxLength: 512 },
                clientSecret: { type: 'string', maxLength: 1024 },
                scope: { type: 'string', maxLength: 512 },
                bearer: { type: 'string', maxLength: 8192 }
              },
              required: ['id', 'issuer', 'federationId'],
              examples: [{ id: 'partner', issuer: 'https://idp.example',
                           federationId: 'partner-oidc', delivery: 'poll',
                           tokenEndpoint: 'https://idp.example/token',
                           clientId: 'receiver', clientSecret: 's3cret' }],
              additionalProperties: false
            },
            responseDescription: 'What was registered.' },
          simple('create-stream', 'createForeignStream',
                 'Create this realm\'s stream at the transmitter',
                 'SSF 1.0 section 8.1.1: a poll stream, or a push stream ' +
                 'whose endpoint is /ssf/transmitters/{id}/push with an ' +
                 'authorization header only this realm and the ' +
                 'transmitter know. Audited.'),
          simple('read-stream', 'readForeignStream',
                 'Read the stream\'s configuration from the transmitter',
                 'Refreshes what is held: audience, events, delivery.'),
          { action: 'update-stream', operationId: 'updateForeignStream',
            summary: 'Change the events the stream asks for',
            description: 'A PATCH of events_requested at the transmitter. ' +
                         'Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object', properties: { id: ID,
              eventsRequested: { type: 'array', items: { type: 'string',
                                                         maxLength: 256 } } },
              required: ['id', 'eventsRequested'],
              examples: [{ id: 'partner', eventsRequested: [
                'https://schemas.openid.net/secevent/caep/event-type/' +
                'session-revoked'] }],
              additionalProperties: false },
            responseDescription: 'The transmitter as it stands.' },
          simple('delete-stream', 'deleteForeignStream',
                 'Delete the stream at the transmitter', 'Audited.'),
          { action: 'set-status', operationId: 'setForeignStreamStatus',
            summary: 'Enable, pause or disable the stream',
            description: 'SSF 1.0 section 8.1.2 at the transmitter. ' +
                         'Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object', properties: { id: ID,
              status: { type: 'string', enum: ['enabled', 'paused',
                                               'disabled'] },
              reason: { type: 'string', maxLength: 512 } },
              required: ['id', 'status'],
              examples: [{ id: 'partner', status: 'paused' }],
              additionalProperties: false },
            responseDescription: 'The transmitter as it stands.' },
          { action: 'add-subject', operationId: 'addForeignStreamSubject',
            summary: 'Add a subject to the stream',
            description: 'SSF 1.0 section 8.1.3.2 at the transmitter. ' +
                         'Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object', properties: { id: ID,
              subject: { type: 'object', additionalProperties: true } },
              required: ['id', 'subject'],
              examples: [{ id: 'partner', subject: { format: 'iss_sub',
                iss: 'https://idp.example', sub: '248289761001' } }],
              additionalProperties: false },
            responseDescription: 'The transmitter as it stands.' },
          { action: 'remove-subject',
            operationId: 'removeForeignStreamSubject',
            summary: 'Remove a subject from the stream',
            description: 'SSF 1.0 section 8.1.3.3 at the transmitter. ' +
                         'Audited.',
            requestBodyRequired: true,
            requestBody: { type: 'object', properties: { id: ID,
              subject: { type: 'object', additionalProperties: true } },
              required: ['id', 'subject'],
              examples: [{ id: 'partner', subject: { format: 'iss_sub',
                iss: 'https://idp.example', sub: '248289761001' } }],
              additionalProperties: false },
            responseDescription: 'The transmitter as it stands.' },
          simple('verify', 'verifyForeignStream',
                 'Ask the transmitter for a verification event',
                 'SSF 1.0 section 8.1.4.2: its state is checked when the ' +
                 'event arrives.'),
          simple('poll-now', 'pollForeignStream',
                 'Poll the transmitter now',
                 'RFC 8936, as the ssf.foreign-poll job does.'),
          simple('remove', 'removeForeignTransmitter',
                 'Remove the transmitter',
                 'Its stream is deleted at the transmitter first. Audited.')
        ] }
    ];
    log.debug("Leaving SsfTransmittersApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<SsfTransmittersApi>(
  'ssf/ssf_transmitters_api',
  () => new SsfTransmittersApi(SsfTransmittersApi.defaultDeps()),
  SsfTransmittersApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  SsfTransmittersApi: SsfTransmittersApi,
  installInstance: (instance: SsfTransmittersApi): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
