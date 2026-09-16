'use strict';
//
// File: scep_api.ts
//
// ---------------------------------------------------------------------------
// THE SCEP OPERATIONS OF /admin-api (2026-09-13): three rows, spread into
// `mgmt-api/admin_api.js`'s ROUTES.
//
//   GET  /admin-api/scep           mirrors GET  /admin/scep
//   GET  /admin-api/scep/monitor   mirrors GET  /admin/scep/monitor
//   POST /admin-api/scep/:action   mirrors POST /admin/scep (six actions)
//
// **IT REGISTERS NO ROUTE AND REQUIRES THE VIEW MODEL LAZILY**, inside each
// handler, exactly as the GNAP rows reach `gnap_console.js`: the management API
// requires this file at 19 in the require order and SCEP is 23g, so a require
// at the top would load `scep_console.ts` — and through it the SCEP family's
// libraries — ahead of where the family is loaded (rule 1).
//
// It cannot use `admin_api.js`'s `sendJson()` or `withAction()`, because that
// module requires THIS one and a require back would close a cycle; the two
// small functions below are the same shape, including the
// `res.locals.protocolEndpoints` member the registration loop computes for a
// GET mirroring a Protocols page.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScepApi` takes the modules it uses through its constructor
// (`ScepApiDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `ScepApi` is exported beside them for the
// composition root.
//
// **THE TABLES WHOSE ENTRIES CALL THIS MODULE** (`ROUTES`) are built by
// `build…()` methods, called at load where each was declared.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import errorCodes = require('../common/error_codes');

const BASE = '/admin-api';

// What `ScepApi` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface ScepApiDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadScepConsole(): typeof import('./scep_console');
}

class ScepApi {
  constructor(private readonly deps: ScepApiDeps) {
    deps.log.debug("Entering ScepApi.constructor().");
    deps.log.debug("Leaving ScepApi.constructor().");
  }

  send(res, status, body) {
    const { log } = this.deps;
    log.debug("Entering ScepApi.send(). status=" + status);
    const rows = res.locals && res.locals.protocolEndpoints;
    let reply = body;
    if (rows && status === 200 && body && typeof body === 'object' &&
        !Array.isArray(body)) {
      reply = Object.assign({}, body, { protocolEndpoints: rows });
    }
    res.status(status).type('application/json').set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving ScepApi.send().");
  }

  openObject(description) {
    const { log } = this.deps;
    log.debug("Entering ScepApi.openObject().");
    log.debug("Leaving ScepApi.openObject().");
    return { type: 'object', additionalProperties: true,
             description: description };
  }

  buildRoutes() {
    const { log, loadScepConsole, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering ScepApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/scep', tag: 'SCEP',
        operationId: 'getScep',
        summary: 'The SCEP server: endpoints, Issuing CA, RA certificate, ' +
                 'profiles, challenges, host names, certificates, settings',
        description: 'Everything /admin/scep draws, out of the same view ' +
                     'function: the absolute endpoint URLs of this realm\'s ' +
                     'SCEP server (RFC 8894) and GetCACaps\' capabilities; ' +
                     'the SCEP Issuing CA and whether the hierarchy is ' +
                     'built; the RA certificate (subject, serial, key ' +
                     'algorithm, expiry, status — never its private key); ' +
                     'the nine profiles with what each needs, whether ' +
                     'scep.allowedProfiles allows it and its SCEP URL, and ' +
                     'the five refused with why; the challenge passwords ' +
                     '(paged, `credentialsPage`; ids and status, never a ' +
                     'secret); the registered host names; the certificates ' +
                     'issued over SCEP (paged, `certificatesPage`); the ' +
                     'documented exceptions; the mode; and the ' +
                     '`scep.*` settings, which are written through POST ' +
                     '/admin-api/config/set-many.',
        mirrors: 'GET /admin/scep',
        parameters: [
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 1000 },
            description: 'Rows per page, for both lists.' },
          { name: 'certificatesPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'The page of the enrolled certificates.' },
          { name: 'credentialsPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'The page of the challenge passwords.' }
        ],
        responseDescription: 'The SCEP server as the page draws it.',
        responseSchema: this.openObject('The SCEP server of this realm, as ' +
                                        '/admin/scep draws it.'),
        handler: function (req, res) {
          log.debug("Entering the management API SCEP endpoint.");
          const model = loadScepConsole();
          const query = model.queryOf(req);
          if (!query.ok) {
            errorCodes.mark(res, 'STS-SCEP-0060');
            self.send(res, 400, { ok: false, errors: [query.detail] });
            log.debug("Leaving the management API SCEP endpoint. Bad query.");
            return;
          }
          self.send(res, 200, model.scepView(req));
          log.debug("Leaving the management API SCEP endpoint.");
        } },

      { method: 'GET', path: BASE + '/scep/monitor', tag: 'SCEP',
        operationId: 'getScepMonitor',
        summary: 'What the SCEP server has done: requests, issuances, ' +
                 'refusals by failInfo and by error code',
        description: 'Everything /admin/scep/monitor draws: the counters ' +
                     'since the process started, per trust realm and added ' +
                     'across processes — requests, issued, refused, revoked, ' +
                     'challenges created; counts by operation (PKIOperation ' +
                     'by messageType), ' +
                     'by RFC 8894 failInfo, by STS error code, by profile ' +
                     'and by principal; and the recent requests (paged). No ' +
                     'reset: the durable record is GET /admin-api/audit.',
        mirrors: 'GET /admin/scep/monitor',
        parameters: [
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1, maximum: 1000 },
            description: 'Rows per page of the recent requests.' },
          { name: 'page', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'The page of the recent requests.' }
        ],
        responseDescription: 'The counters and the recent requests.',
        responseSchema:
          this.openObject('What the SCEP server has done in this realm, as ' +
                                        '/admin/scep/monitor draws it.'),
        handler: function (req, res) {
          log.debug("Entering the management API SCEP monitor endpoint.");
          const model = loadScepConsole();
          const query = model.queryOf(req);
          if (!query.ok) {
            errorCodes.mark(res, 'STS-SCEP-0060');
            self.send(res, 400, { ok: false, errors: [query.detail] });
            log.debug("Leaving the management API SCEP monitor endpoint. Bad.");
            return;
          }
          self.send(res, 200, model.scepMonitorView(req));
          log.debug("Leaving the management API SCEP monitor endpoint.");
        } },

      { method: 'POST', route: BASE + '/scep/:action', tag: 'SCEP',
        mirrors: 'POST /admin/scep',
        handler: function (req, res) {
          log.debug("Entering the management API SCEP action endpoint.");
          const model = loadScepConsole();
          const body = Object.assign({}, parseBody(req),
                                     { action: String(req.params.action ||
                                                      '') });
          return model.scepAction(body, { via: 'api', actor: 'admin-api',
                                          req: req })
            .then(function (result) {
              if (!result.ok) {
                errorCodes.mark(res, errorCodes.codeOf(result) ||
                                     'STS-SCEP-0061');
              }
              self.send(res, result.ok ? 200 : 400, result);
              log.debug("Leaving the management API SCEP action endpoint.");
            })
            .catch(function (e) {
              log.error(errorCodes.tag('STS-SCEP-0061') +
                        'scep: an /admin-api ' +
                        'action failed: ' + ((e && e.stack) || e));
              errorCodes.mark(res, 'STS-SCEP-0061');
              self.send(res, 400, { ok: false,
                                    errors:
                                      ['The action could not be completed.'] });
            });
        },
        actions: [
          { action: 'create-challenge', operationId: 'createScepChallenge',
            summary: 'Create a single-use SCEP challenge password for one ' +
                     'entry and one profile',
            description: 'The challenge authorizes ONE enrollment, AS the ' +
                         'entry it names, for the profile it names (the ' +
                         'default profile when none is given). **It is in ' +
                         'this reply once and never again**: the entry keeps ' +
                         'only its SHA-256. The reply also ' +
                         'carries the SCEP URL for its ' +
                         'profile and a ready-to-paste `sscep` sequence.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: Object.assign({}, ENTRY_PROPERTIES, {
                profile: { type: 'string', maxLength: 64,
                           description:
                             'One of the nine enrollment profiles.' },
                lifetimeS: { type: 'integer', minimum: 60, maximum: 2592000,
                             description: 'Seconds it may wait, at most ' +
                                          'scep.challengeLifetimeS.' }
              }),
              required: ['kind', 'identifier'],
              examples: [{ kind: 'person', identifier: 'no-such-person-example',
                           profile: 'tls-client' }],
              additionalProperties: false
            },
            responseDescription: 'The challenge, once, with its URL.' },
          { action: 'delete-challenge', operationId: 'deleteScepChallenge',
            summary: 'Delete a SCEP challenge password',
            description: 'The challenge stops being redeemable. A ' +
                         'certificate already issued with it is untouched.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: { id: { type: 'string', maxLength: 600,
                                  description: 'The challenge id, from GET ' +
                                               '/admin-api/scep.' } },
              required: ['id'],
              examples: [{ id: 'scep-p-bm9ib2R5-0000000000000000' }],
              additionalProperties: false
            },
            responseDescription: 'The id that was deleted.' },
          { action: 'reissue-ra', operationId: 'reissueScepRa',
            summary: 'Re-issue the SCEP RA certificate',
            description: 'A new RSA key pair (scep.raKeyAlgorithm) certified ' +
                         'by the SCEP Issuing CA; the certificate it ' +
                         'replaces is put on that CA\'s CRL as superseded. ' +
                         'Clients encrypting to the old one are answered ' +
                         'badMessageCheck until they fetch GetCACert again.',
            requestBodyRequired: false,
            requestBody: {
              type: 'object', properties: {}, examples: [{}],
              additionalProperties: false
            },
            responseDescription: 'The RA certificate as it now stands.' },
          { action: 'revoke-certificate', operationId: 'revokeScepCertificate',
            summary: 'Revoke a certificate issued over SCEP',
            description: 'Puts the serial on the SCEP Issuing CA\'s CRL and ' +
                         'OCSP with the RFC 5280 reason given, and marks the ' +
                         'record on the entry revoked.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: {
                serial: { type: 'string', maxLength: 128,
                          description: 'The serial, hexadecimal.' },
                reason: { type: 'string',
                          enum: ['unspecified', 'keyCompromise',
                                 'affiliationChanged', 'superseded',
                                 'cessationOfOperation', 'privilegeWithdrawn'],
                          description: 'The RFC 5280 reason.' }
              },
              required: ['serial'],
              examples: [{ serial: '0badc0de', reason: 'keyCompromise' }],
              additionalProperties: false
            },
            responseDescription: 'The serial and the reason.' },
          { action: 'add-host-name', operationId: 'addScepHostName',
            summary: 'Register a DNS name or IP address on an entry',
            description:
              'A dNSName or iPAddress is issued over any enrollment ' +
                         'protocol only when it is registered on the entry.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: Object.assign({}, ENTRY_PROPERTIES, {
                hostName: { type: 'string', maxLength: 253,
                            description: 'A DNS name or an IP address.' }
              }),
              required: ['kind', 'identifier', 'hostName'],
              examples: [{ kind: 'person', identifier: 'no-such-person-example',
                           hostName: 'device.example.com' }],
              additionalProperties: false
            },
            responseDescription: 'The entry\'s host names now.' },
          { action: 'remove-host-name', operationId: 'removeScepHostName',
            summary: 'Remove a registered host name from an entry',
            description: 'Certificates already issued for it are untouched.',
            requestBodyRequired: true,
            requestBody: {
              type: 'object',
              properties: Object.assign({}, ENTRY_PROPERTIES, {
                hostName: { type: 'string', maxLength: 253,
                            description: 'A DNS name or an IP address.' }
              }),
              required: ['kind', 'identifier', 'hostName'],
              examples: [{ kind: 'person', identifier: 'no-such-person-example',
                           hostName: 'device.example.com' }],
              additionalProperties: false
            },
            responseDescription: 'The entry\'s host names now.' }
        ] }
    ];
    log.debug("Leaving ScepApi.buildRoutes().");
    return ROUTES;
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root exists.
const scepApi = new ScepApi({
  log: log,
  parseBody: parseBody,
  errorCodes: errorCodes,
  loadScepConsole: function () {
    return require('./scep_console');
  }
});

const ENTRY_PROPERTIES = {
  kind: { type: 'string', enum: ['person', 'application'],
          description: 'Whether the entry is a person or an application.' },
  identifier: { type: 'string', maxLength: 256,
                description: 'The username or the application identifier, ' +
                             'in this realm.' }
};

const ROUTES = scepApi.buildRoutes();

export = { ScepApi: ScepApi, ROUTES: ROUTES };
