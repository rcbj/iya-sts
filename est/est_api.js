// @ts-check
'use strict';
//
// File: est_api.js
//
// ---------------------------------------------------------------------------
// THE THREE /admin-api OPERATIONS FOR EST (2026-09-13).
//
// Rows in `mgmt-api/admin_api.js`'s own shape, spread into its `ROUTES` by the
// integrator, so that the registration loop there — the ajv body schemas, the
// token gate, the OpenAPI document, the `mirrors` join that adds a Protocols
// page's endpoints — treats them exactly as it treats every other operation.
// This file registers no route.
//
// **THE VIEW MODEL IS REQUIRED LAZILY, INSIDE EACH HANDLER** (rule 1): this
// file is required by the management API at 19, and `est_console.js` is
// loaded with the family at 23f. A lazy require keeps that true by
// construction.
//
// **`issue-server-key` RETURNS A PRIVATE KEY, ONCE, IN THE JSON.** That is the
// operation: a machine that asked this service to generate a key pair has no
// other way to receive it. The reply is `Cache-Control: no-store`, the audit
// row the core writes names the serial and never the key, and the sealed copy
// on the entry is not readable through any view.
// ---------------------------------------------------------------------------

const { log, parseBody } = require('../common/helpers');
const errorCodes = require('../common/error_codes');

const BASE = '/admin-api';

// `admin_api.js`'s `sendJson()`, which is not exported: the same answer, and
// the same `protocolEndpoints` member for the GET that mirrors a Protocols page
// (the registration loop computes it onto `res.locals`).
function sendJson(res, status, body) {
  log.debug("Entering sendJson(). status=" + status);
  let reply = body;
  const rows = res.locals && res.locals.protocolEndpoints;
  if (rows && status === 200 && body && typeof body === 'object' &&
      !Array.isArray(body)) {
    reply = Object.assign({}, body, { protocolEndpoints: rows });
  }
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(reply, null, 2));
  log.debug("Leaving sendJson().");
}

function kindProperty() {
  log.debug("Entering kindProperty().");
  log.debug("Leaving kindProperty().");
  return { type: 'string', enum: ['person', 'application'],
           description: 'Whether `identifier` names a person (a username) ' +
                        'or an application (its identifier).' };
}

const ROUTES = [
  { method: 'GET', path: BASE + '/est', tag: 'EST', operationId: 'getEst',
    summary: 'The EST server: endpoints, Issuing CA, profiles, host names, ' +
             'enrolled certificates, settings',
    description: 'Everything /admin/est draws. The six RFC 7030 operations ' +
                 'at this realm\'s base URL; the EST Issuing CA and whether ' +
                 'the hierarchy is built; the nine profiles with what each ' +
                 'needs, whether `est.allowedProfiles` allows it and its ' +
                 'labelled URLs; the five profiles never issued over an ' +
                 'enrollment protocol and why; the credentials EST accepts; ' +
                 'the certificate host names registered in the realm; the ' +
                 'certificates enrolled over EST (paged, ' +
                 '`certificatesPage`), ' +
                 'with no private key; the mode note; and the `est.*` ' +
                 'settings, which are written through POST ' +
                 '/admin-api/config/set-many.',
    parameters: [
      { name: 'certificatesPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of enrolled certificates.' },
      { name: 'per', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Rows per page.' }
    ],
    mirrors: 'GET /admin/est',
    responseDescription: 'The EST server as the page draws it.',
    responseSchema: { type: 'object', additionalProperties: true,
                      description: 'The view /admin/est renders.' },
    handler: function (req, res) {
      log.debug("Entering the management API EST endpoint.");
      sendJson(res, 200, require('./est_console').estView(req));
      log.debug("Leaving the management API EST endpoint.");
    } },

  { method: 'GET', path: BASE + '/est/monitor', tag: 'EST',
    operationId: 'getEstMonitor',
    summary: 'What the EST server has done: requests, issuances, refusals',
    description: 'Everything /admin/est/monitor draws: totals of requests, ' +
                 'issued, refused and revoked; the certificates held by ' +
                 'status; counts by operation, profile, principal, error ' +
                 'code and HTTP status; and the most recent requests (paged, ' +
                 '`page`). Per trust realm, across every process, with no ' +
                 'reset: the durable record is GET /admin-api/audit.',
    parameters: [
      { name: 'page', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of recent requests.' },
      { name: 'per', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Rows per page.' }
    ],
    mirrors: 'GET /admin/est/monitor',
    responseDescription: 'The counters and recent requests.',
    responseSchema: { type: 'object', additionalProperties: true,
                      description: 'The view /admin/est/monitor renders.' },
    handler: function (req, res) {
      log.debug("Entering the management API EST monitor endpoint.");
      sendJson(res, 200, require('./est_console').estMonitorView(req));
      log.debug("Leaving the management API EST monitor endpoint.");
    } },

  { method: 'POST', route: BASE + '/est/:action', tag: 'EST',
    mirrors: 'POST /admin/est',
    handler: function (req, res) {
      log.debug("Entering the management API EST action endpoint.");
      const body = Object.assign({}, parseBody(req),
                                 { action: String(req.params.action || '') });
      require('./est_console').estAction(body, { via: 'api', req: req })
        .then(function (result) {
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-EST-0033');
          }
          sendJson(res, result.ok ? 200 : 400, result);
          log.debug("Leaving the management API EST action endpoint. ok=" +
                    !!result.ok);
        }, function (e) {
          log.error(errorCodes.tag('STS-EST-0020') + 'est api: the action ' +
                    'failed: ' + ((e && e.stack) || e));
          errorCodes.mark(res, 'STS-EST-0020');
          sendJson(res, 500, { ok: false, errors: ['The action could not be ' +
                                                   'completed.'] });
          log.debug("Leaving the management API EST action endpoint. Threw.");
        });
    },
    actions: [
      { action: 'issue-server-key', operationId: 'issueEstServerKey',
        summary: 'Issue a certificate with a key pair this service generates',
        description: 'The console\'s /serverkeygen (RFC 7030 section 4.4): ' +
                     'a key pair of `keyAlg` is generated, certified for ' +
                     '`profile` by this realm\'s EST Issuing CA for the ' +
                     'person or application named, written onto that entry ' +
                     'with a sealed copy of the private key, and returned ' +
                     'ONCE as `privateKeyPem`. A KEM key (ML-KEM) is ' +
                     'certified only for key-encipherment.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            kind: kindProperty(),
            identifier: { type: 'string', minLength: 1, maxLength: 256,
                          description: 'The username or application ' +
                                       'identifier.' },
            profile: { type: 'string',
                       description: 'One of the nine profiles; ' +
                                    '`est.defaultProfile` when omitted.' },
            keyAlg: { type: 'string',
                      description: 'A key algorithm id from GET ' +
                                   '/admin-api/est `keyAlgorithms`; ec-p256 ' +
                                   'when omitted.' }
          },
          required: ['kind', 'identifier'],
          examples: [{ kind: 'person', identifier: 'no-such-person-example',
                       profile: 'tls-client', keyAlg: 'ec-p256' }],
          additionalProperties: false
        },
        responseDescription: 'The certificate, its chain and the private ' +
                             'key, once.' },
      { action: 'revoke-certificate', operationId: 'revokeEstCertificate',
        summary: 'Revoke a certificate enrolled over EST',
        description: 'Puts the serial on the EST Issuing CA\'s CRL with the ' +
                     'RFC 5280 reason given (OCSP answers revoked from then ' +
                     'on) and marks the record on the entry.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            serialHex: { type: 'string', minLength: 1, maxLength: 80,
                         description: 'The serial, from GET /admin-api/est.' },
            reason: { type: 'string',
                      enum: ['unspecified', 'keyCompromise', 'cACompromise',
                             'affiliationChanged', 'superseded',
                             'cessationOfOperation', 'certificateHold',
                             'privilegeWithdrawn', 'aACompromise'],
                      description: 'The RFC 5280 section 5.3.1 reason; ' +
                                   'unspecified when omitted.' }
          },
          required: ['serialHex'],
          examples: [{ serialHex: '00', reason: 'keyCompromise' }],
          additionalProperties: false
        },
        responseDescription: 'The serial, the entry and the reason.' },
      { action: 'add-host-name', operationId: 'addEstHostName',
        summary: 'Register a certificate host name on an entry',
        description: 'A dNSName or iPAddress is issued in a certificate — ' +
                     'over ACME, EST or SCEP — only when it is registered on ' +
                     'the entry the certificate names. Adding one already ' +
                     'there changes nothing.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            kind: kindProperty(),
            identifier: { type: 'string', minLength: 1, maxLength: 256,
                          description: 'The username or application ' +
                                       'identifier.' },
            hostName: { type: 'string', minLength: 1, maxLength: 253,
                        description: 'A DNS name or an IP address.' }
          },
          required: ['kind', 'identifier', 'hostName'],
          examples: [{ kind: 'application',
                       identifier: 'no-such-application-example',
                       hostName: 'host.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'The entry\'s host names afterwards.' },
      { action: 'remove-host-name', operationId: 'removeEstHostName',
        summary: 'Remove a certificate host name from an entry',
        description: 'Certificates already issued for the name keep it; the ' +
                     'next request naming it is refused.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            kind: kindProperty(),
            identifier: { type: 'string', minLength: 1, maxLength: 256,
                          description: 'The username or application ' +
                                       'identifier.' },
            hostName: { type: 'string', minLength: 1, maxLength: 253,
                        description: 'The name to remove.' }
          },
          required: ['kind', 'identifier', 'hostName'],
          examples: [{ kind: 'application',
                       identifier: 'no-such-application-example',
                       hostName: 'host.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'The entry\'s host names afterwards.' }
    ] }
];

module.exports = { ROUTES: ROUTES };
