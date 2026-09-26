'use strict';
//
// File: oidfed_api.ts
//
// ---------------------------------------------------------------------------
// THE OPENID FEDERATION OPERATIONS OF /admin-api (#132, 2026-09-23), spread
// into `mgmt-api/admin_api.ts`'s ROUTES:
//
//   GET  /admin-api/oidfed           mirrors GET  /admin/oidfed
//   POST /admin-api/oidfed/:action   mirrors POST /admin/oidfed
//
// **IT REGISTERS NO ROUTE AND REQUIRES `oidfed.ts` LAZILY**, inside each
// handler, for `scep/scep_api.ts`'s reason: the management API requires this
// file at 19 and the family is loaded at 14b, so the require is a cache hit —
// but a lazy one costs nothing and keeps the order a non-question.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');

type Json = any;

const BASE = '/admin-api';

interface OidfedApiDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  loadOidfed(): Json;
}

const ENTITY = { type: 'string', maxLength: 2048,
                 description: 'An Entity Identifier: an https URL with no ' +
                              'query or fragment.' };
const EVENT_DESCRIPTION = { type: 'string', maxLength: 1000,
  description: 'Recorded as the event_description of the event this act ' +
               'adds to the subordinate\'s history.' };
const INFORMATION_URI = { type: 'string', maxLength: 2048,
  description: 'An http or https URL of a page about the event, recorded ' +
               'as its information_uri.' };
const JSON_TEXT = function (what: string): Json {
  log.debug("Entering JSON_TEXT().");
  log.debug("Leaving JSON_TEXT().");
  return { description: what + ', as a JSON object or its text.' };
};

class OidfedApi {
  constructor(private readonly deps: OidfedApiDeps) {
    deps.log.debug("Entering OidfedApi.constructor().");
    deps.log.debug("Leaving OidfedApi.constructor().");
  }

  static defaultDeps(): OidfedApiDeps {
    helpers.log.debug("Entering OidfedApi.defaultDeps().");
    helpers.log.debug("Leaving OidfedApi.defaultDeps().");
    return {
      log: log, parseBody: parseBody, errorCodes: errorCodes,
      loadOidfed: function (): Json {
        return require('./oidfed');
      }
    };
  }

  static wire(instance: OidfedApi): void {
    helpers.log.debug("Entering OidfedApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving OidfedApi.wire().");
  }

  send(res: Json, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering OidfedApi.send(). status=" + status);
    const rows = res.locals && res.locals.protocolEndpoints;
    let reply = body;
    if (rows && status === 200 && body && typeof body === 'object' &&
        !Array.isArray(body)) {
      reply = Object.assign({}, body, { protocolEndpoints: rows });
    }
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving OidfedApi.send().");
  }

  // One action's row: its body schema from `properties` and `required`.
  action(action: string, operationId: string, summary: string,
         description: string, properties: Json, required: string[],
         example: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OidfedApi.action(). " + action);
    log.debug("Leaving OidfedApi.action().");
    return {
      action: action, operationId: operationId, summary: summary,
      description: description,
      requestBodyRequired: required.length > 0,
      requestBody: { type: 'object', properties: properties,
                     required: required, examples: [example],
                     additionalProperties: false },
      responseDescription: 'What was done, with the record where there is one.'
    };
  }

  buildRoutes(): Json[] {
    const { log, loadOidfed, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering OidfedApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/oidfed', tag: 'OpenID Federation',
        operationId: 'getOidfed',
        summary: 'This realm as an OpenID Federation entity: its role, ' +
                 'Entity Configuration, keys, subordinates, Trust Anchors ' +
                 'and Trust Marks',
        description: 'Everything /admin/oidfed draws, out of the same view ' +
                     'function: the realm\'s Entity Identifier and role ' +
                     '(trust anchor, intermediate or leaf), its authority ' +
                     'hints and federation endpoints, its Federation Entity ' +
                     'Keys (public halves, states and history — never a ' +
                     'private key), the subordinates it vouches for, the ' +
                     'Trust Anchors it trusts, the Trust Mark types it ' +
                     'issues, the marks it has issued and carries, the mark ' +
                     'policies it publishes as a Trust Anchor, the ' +
                     'resolutions it holds, and the claims of its current ' +
                     'Entity Configuration — and, for each subordinate, ' +
                     'whether it is suspended and its event history, the ' +
                     'subordinates it has revoked with theirs (#137), and ' +
                     'the Entity Collection crawl it keeps (#136). The ' +
                     'oidfed.* settings are written through ' +
                     'POST /admin-api/config/set-many.',
        mirrors: 'GET /admin/oidfed',
        parameters: [],
        responseDescription: 'The realm as a federation entity.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: 'This realm as /admin/oidfed draws ' +
                                       'it.' },
        handler: function (req: Json, res: Json): Promise<void> {
          log.debug("Entering the management API OpenID Federation " +
                    "endpoint.");
          return loadOidfed().view(req).then(function (view: Json): void {
            self.send(res, 200, view);
            log.debug("Leaving the management API OpenID Federation " +
                      "endpoint.");
          }).catch(function (e: any): void {
            log.error(errorCodes.tag('STS-OIDFED-0050') + 'oidfed: the ' +
                      '/admin-api view failed: ' + ((e && e.stack) || e));
            errorCodes.mark(res, 'STS-OIDFED-0050');
            self.send(res, 500, { ok: false, errors: ['The view failed.'] });
          });
        } },

      { method: 'POST', route: BASE + '/oidfed/:action',
        tag: 'OpenID Federation', mirrors: 'POST /admin/oidfed',
        handler: function (req: Json, res: Json): Promise<void> {
          log.debug("Entering the management API OpenID Federation action.");
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          return loadOidfed().act(body, { via: 'api', actor: 'admin-api',
                                          req: req })
            .then(function (result: Json): void {
              if (!result.ok) {
                // error-code: none — the act's own code, read off the result
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-OIDFED-0045');
              }
              self.send(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API OpenID Federation " +
                        "action.");
            })
            .catch(function (e: any): void {
              log.error(errorCodes.tag('STS-OIDFED-0050') + 'oidfed: an ' +
                        '/admin-api action failed: ' + ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-OIDFED-0050');
              self.send(res, 400, { ok: false, errors:
                                      ['The action could not be completed.'] });
            });
        },
        actions: [
          this.action('add-subordinate', 'addOidfedSubordinate',
            'Register an entity this realm vouches for',
            'The entity becomes a subordinate: the fetch endpoint issues a ' +
            'Subordinate Statement about it carrying its keys and whatever ' +
            'metadata, metadata policy and constraints are given here. Its ' +
            'keys are given (`jwks`) or read from its own Entity ' +
            'Configuration (`fetchJwks`, through the outbound policy).',
            { entityId: ENTITY,
              jwks: JSON_TEXT('Its JWK Set'),
              fetchJwks: { type: 'boolean', description: 'Read its keys ' +
                           'from its Entity Configuration.' },
              metadata: JSON_TEXT('Metadata overriding its own (3.1.1)'),
              metadataPolicy: JSON_TEXT('A metadata_policy (6.1)'),
              metadataPolicyCrit: { type: 'string', maxLength: 512,
                description: 'Critical additional operators, ' +
                             'comma-separated.' },
              constraints: JSON_TEXT('constraints (6.2)'),
              entityTypes: { type: 'string', maxLength: 512,
                description: 'Its entity types, comma-separated, for the ' +
                             'listing filter; read from its configuration ' +
                             'when fetched.' },
              intermediate: { type: 'boolean',
                              description: 'Whether it is an Intermediate.' },
              eventDescription: EVENT_DESCRIPTION,
              informationUri: INFORMATION_URI },
            ['entityId'],
            { entityId: 'https://rp.example.org', fetchJwks: true }),
          this.action('remove-subordinate', 'removeOidfedSubordinate',
            'Revoke a subordinate',
            'The fetch endpoint no longer answers for it, and its history ' +
            'records the revocation — with the reason and the page given — ' +
            'and is kept (#137).',
            { entityId: ENTITY, reason: EVENT_DESCRIPTION,
              informationUri: INFORMATION_URI }, ['entityId'],
            { entityId: 'https://rp.example.org',
              reason: 'no longer operated' }),
          this.action('suspend-subordinate', 'suspendOidfedSubordinate',
            'Suspend a subordinate',
            'The realm issues no Subordinate Statement about it and lists ' +
            'it nowhere until it is reinstated, so no Trust Chain passes ' +
            'through it; its history records the suspension (#137). A realm ' +
            'of this service beneath the default realm may be suspended too.',
            { entityId: ENTITY, reason: EVENT_DESCRIPTION,
              informationUri: INFORMATION_URI }, ['entityId'],
            { entityId: 'https://rp.example.org',
              reason: 'under investigation' }),
          this.action('reinstate-subordinate', 'reinstateOidfedSubordinate',
            'Reinstate a suspended subordinate',
            'Statements are issued about it again; its history records the ' +
            'reinstatement (#137).',
            { entityId: ENTITY, reason: EVENT_DESCRIPTION,
              informationUri: INFORMATION_URI }, ['entityId'],
            { entityId: 'https://rp.example.org' }),
          this.action('crawl-collection', 'crawlOidfedCollection',
            'Crawl the Entity Collection now',
            'Walks every entity beneath the realm — each resolved to the ' +
            'realm before its own subordinates are listed, fetching from ' +
            'Intermediates outside this service through the outbound ' +
            'policy — and keeps what it finds for the collection endpoint ' +
            '(#136). The entity identifier is taken from this request.',
            {}, [], {}),
          this.action('add-trust-anchor', 'addOidfedTrustAnchor',
            'Trust a Trust Anchor',
            'A Trust Chain may end at it, verified by the keys configured ' +
            'here — given, or read from its Entity Configuration.',
            { entityId: ENTITY, jwks: JSON_TEXT('Its JWK Set'),
              fetchJwks: { type: 'boolean', description: 'Read its keys ' +
                           'from its Entity Configuration.' } },
            ['entityId'],
            { entityId: 'https://anchor.example.org', fetchJwks: true }),
          this.action('remove-trust-anchor', 'removeOidfedTrustAnchor',
            'Stop trusting a Trust Anchor', 'Chains ending at it are refused.',
            { entityId: ENTITY }, ['entityId'],
            { entityId: 'https://anchor.example.org' }),
          this.action('add-mark-type', 'addOidfedMarkType',
            'Issue Trust Marks of a type',
            'Registers a type this realm issues, with its lifetime and, ' +
            'where another entity owns the type, the delegation it issues ' +
            'under (7.2).',
            { type: { type: 'string', maxLength: 2048,
                      description: 'The Trust Mark type identifier, a URL.' },
              lifetimeS: { type: 'integer', minimum: 60,
                           description: 'Seconds each mark lives; ' +
                                        'oidfed.trustMarkLifetimeS when ' +
                                        'absent.' },
              logoUri: { type: 'string', maxLength: 2048 },
              ref: { type: 'string', maxLength: 2048 },
              delegation: { type: 'string', maxLength: 16384,
                            description: 'A trust-mark-delegation+jwt.' } },
            ['type'],
            { type: 'https://federation.example.org/marks/audited',
              lifetimeS: 2592000 }),
          this.action('remove-mark-type', 'removeOidfedMarkType',
            'Stop issuing a Trust Mark type',
            'Marks already issued keep their status.',
            { type: { type: 'string', maxLength: 2048 } }, ['type'],
            { type: 'https://federation.example.org/marks/audited' }),
          this.action('set-mark-policy', 'setOidfedMarkPolicy',
            'As a Trust Anchor: who may issue a type, and who owns it',
            'Published as trust_mark_issuers and trust_mark_owners (3.1.2).',
            { type: { type: 'string', maxLength: 2048 },
              issuers: { type: 'string', maxLength: 8192,
                         description: 'Entity Identifiers, comma-separated; ' +
                                      'none means anybody.' },
              ownerSub: ENTITY, ownerJwks: JSON_TEXT('The owner\'s JWK Set') },
            ['type'],
            { type: 'https://federation.example.org/marks/audited',
              issuers: 'https://tmi.example.org' }),
          this.action('remove-mark-policy', 'removeOidfedMarkPolicy',
            'Remove a Trust Anchor\'s policy for a type',
            'trust_mark_issuers and trust_mark_owners no longer name it; a ' +
            'type the realm issues itself falls back to naming the realm.',
            { type: { type: 'string', maxLength: 2048 } }, ['type'],
            { type: 'https://federation.example.org/marks/audited' }),
          this.action('issue-trust-mark', 'issueOidfedTrustMark',
            'Issue a Trust Mark to an entity',
            'Signed with the realm\'s Federation Entity Key; answered at ' +
            'the Trust Mark endpoint, and handed to the entity\'s realm when ' +
            'it is one of this service\'s.',
            { type: { type: 'string', maxLength: 2048 }, sub: ENTITY },
            ['type', 'sub'],
            { type: 'https://federation.example.org/marks/audited',
              sub: 'https://rp.example.org' }),
          this.action('revoke-trust-mark', 'revokeOidfedTrustMark',
            'Revoke a Trust Mark this realm issued',
            'Its status becomes "revoked" (8.4).',
            { id: { type: 'string', maxLength: 64,
                    description: 'The mark\'s id, from GET ' +
                                 '/admin-api/oidfed.' },
              reason: { type: 'string', maxLength: 256 } },
            ['id'], { id: 'im-0123456789abcdef0123456789abcdef' }),
          this.action('add-held-mark', 'addOidfedHeldMark',
            'Carry a Trust Mark issued to this realm',
            'The Entity Configuration carries it in trust_marks (3.1.2).',
            { trustMark: { type: 'string', maxLength: 16384,
                           description: 'A trust-mark+jwt whose sub is this ' +
                                        'realm.' } },
            ['trustMark'],
            { trustMark: 'eyJ0eXAiOiJ0cnVzdC1tYXJrK2p3dCJ9...' }),
          this.action('remove-held-mark', 'removeOidfedHeldMark',
            'Stop carrying a Trust Mark',
            'The Entity Configuration no longer carries it in trust_marks.',
            { id: { type: 'string', maxLength: 64 } }, ['id'],
            { id: 'hm-0123456789abcdef0123456789abcdef' }),
          this.action('resolve', 'resolveOidfedEntity',
            'Resolve an entity\'s Trust Chain to one of this realm\'s ' +
            'Trust Anchors',
            'Walks its authority_hints, fetching what it must through the ' +
            'outbound policy and within oidfed.maxAuthorityHints, ' +
            'oidfed.maxChainDepth and oidfed.maxFetchesPerResolution, ' +
            'validates the chain, applies its metadata policy and verifies ' +
            'its Trust Marks. The result is what the resolve endpoint ' +
            'answers with afterwards.',
            { sub: ENTITY, trustAnchor: { type: 'string', maxLength: 2048,
              description: 'The anchor to resolve to; any of the realm\'s ' +
                           'when absent.' } },
            ['sub'], { sub: 'https://rp.example.org' }),
          this.action('rotate-key', 'rotateOidfedKey',
            'Rotate the realm\'s Federation Entity Key',
            'Queues a run of oidfed.key-rotate-now. An emergency rotation ' +
            'revokes the current and next keys as compromised; confirm it ' +
            'with confirm: "compromised".',
            { emergency: { type: 'boolean' },
              // The one word an emergency is confirmed with (#86).
              confirm: { type: 'string', maxLength: 32,
                         enum: ['compromised'] } },
            [], {}),
          this.action('revoke-key', 'revokeOidfedKey',
            'Revoke a retired Federation Entity Key',
            'It leaves the published keys and is listed as revoked at the ' +
            'Historical Keys endpoint with the reason (8.7.3).',
            { kid: { type: 'string', maxLength: 128 },
              reason: { type: 'string', enum: ['unspecified', 'compromised',
                                               'superseded'] } },
            ['kid'], { kid: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
                       reason: 'compromised' })
        ] }
    ];
    log.debug("Leaving OidfedApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = null;

const slot = new InstanceSlot<OidfedApi>(
  'oidfed/oidfed_api',
  () => new OidfedApi(OidfedApi.defaultDeps()),
  OidfedApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  OidfedApi: OidfedApi,
  installInstance: (instance: OidfedApi): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  get ROUTES(): Json[] {
    log.debug("Entering ROUTES().");
    slot.get();
    log.debug("Leaving ROUTES().");
    return routes;
  }
};
