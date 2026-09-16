// @ts-check
'use strict';
//
// File: acme_api.js
//
// ---------------------------------------------------------------------------
// THE ACME OPERATIONS OF /admin-api (2026-09-13).
//
// Three operations mirroring the two pages `acme_admin.js` draws and the six
// controls on the first of them, spread into `mgmt-api/admin_api.js`'s table by
// the integrator. Both doors call `acme_console.js` (rule 7).
//
// **THIS FILE REGISTERS NO ROUTE AND REQUIRES ITS VIEW MODEL LAZILY**, inside
// each handler: the management API is 19 in the require order and ACME is 23e,
// so a require at load would register every `/enroll/acme` route ahead of the
// management API's own (rule 1). By the time a handler runs, the family has
// long been loaded and the require is a cache hit.
//
// Its `sendJson()` is the management API's, written again because this file
// cannot require that one back (it is the file that requires this): the
// realm's endpoints go on a successful answer to the GET that mirrors the
// Protocols page, which the registration loop computes onto `res.locals`.
// ---------------------------------------------------------------------------

const { log, parseBody } = require('../common/helpers');
const errorCodes = require('../common/error_codes');

const BASE = '/admin-api';

function sendJson(res, status, body) {
  log.debug("Entering sendJson(). status=" + status);
  const rows = res.locals && res.locals.protocolEndpoints;
  let out = body;
  if (rows && status === 200 && body && typeof body === 'object' &&
      !Array.isArray(body)) {
    out = Object.assign({}, body, { protocolEndpoints: rows });
  }
  // error-code: none — the status is a variable; each refusal below marks
  res.status(status).type('application/json').set('Cache-Control', 'no-store')
     .send(JSON.stringify(out, null, 2));
  log.debug("Leaving sendJson().");
}

function consoleModel() {
  log.debug("Entering consoleModel().");
  log.debug("Leaving consoleModel().");
  return require('./acme_console');
}

const KIND = { type: 'string', enum: ['person', 'application'],
               description: 'Whether the entry is a person (ou=users) or an ' +
                            'application (ou=applications).' };
const IDENTIFIER = { type: 'string', minLength: 1, maxLength: 256,
                     description: 'The username of a person, or the ' +
                                  'identifier of an application, in this ' +
                                  'realm.' };
const OBJECT = function (description) {
  return { type: 'object', additionalProperties: true,
           description: description };
};

const ROUTES = [
  { method: 'GET', path: BASE + '/acme', tag: 'ACME',
    operationId: 'getAcme',
    summary: 'The ACME server: directory, Issuing CA, profiles, EAB keys, ' +
             'accounts, certificates, host names, settings',
    description: 'Everything /admin/acme draws. The absolute endpoints of ' +
                 'this realm\'s ACME server (RFC 8555) with its directory; ' +
                 'the ACME Issuing CA; the nine certificate profiles with ' +
                 'what each needs and whether acme.allowedProfiles allows ' +
                 'it, and the five never issued over ACME with the reason; ' +
                 'the External Account Binding keys (no key material, paged ' +
                 'by `credentialsPage`); the accounts (paged by ' +
                 '`accountsPage`); the certificates issued over ACME (paged ' +
                 'by `certificatesPage`); the host names registered on ' +
                 'entries (paged by `hostNamesPage`); what development and ' +
                 'product mode change; and the `acme.*` settings, which are ' +
                 'written through POST /admin-api/config/set-many.',
    mirrors: 'GET /admin/acme',
    parameters: [
      { name: 'per', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1, maximum: 1000 },
        description: 'Rows per page, shared by every list in the reply.' },
      { name: 'credentialsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the EAB keys.' },
      { name: 'accountsPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the accounts.' },
      { name: 'certificatesPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the certificates.' },
      { name: 'hostNamesPage', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the entries with host names.' }
    ],
    responseDescription: 'The ACME server as the page draws it.',
    responseSchema: OBJECT('The ACME server in this realm: `directory`, ' +
                           '`endpoints`, `authority`, `profiles`, ' +
                           '`refusedProfiles`, `mode`, `eabKeys`, ' +
                           '`accounts`, `certificates`, `hostNames`, ' +
                           '`settings`.'),
    handler: function (req, res) {
      log.debug("Entering the management API ACME endpoint.");
      sendJson(res, 200, consoleModel().acmeView(req));
      log.debug("Leaving the management API ACME endpoint.");
    } },

  { method: 'GET', path: BASE + '/acme/monitor', tag: 'ACME',
    operationId: 'getAcmeMonitor',
    summary: 'What the ACME server has done in this realm',
    description: 'Everything /admin/acme/monitor draws: requests, ' +
                 'certificates issued and revoked, refusals, accounts bound, ' +
                 'counts by operation, profile, principal, error code and ' +
                 'HTTP status, and the most recent requests (paged by ' +
                 '`page`). Per trust realm, merged across processes, and ' +
                 'with no reset: the durable record is GET /admin-api/audit.',
    mirrors: 'GET /admin/acme/monitor',
    parameters: [
      { name: 'page', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1 },
        description: 'Which page of the recent requests.' },
      { name: 'per', in: 'query', required: false,
        schema: { type: 'integer', minimum: 1, maximum: 1000 },
        description: 'Rows per page.' }
    ],
    responseDescription: 'The totals, the tables and the recent requests.',
    responseSchema: OBJECT('The ACME counters in this realm: `totals`, ' +
                           '`operations`, `profiles`, `principals`, ' +
                           '`errorCodes`, `statuses`, `recent`.'),
    handler: function (req, res) {
      log.debug("Entering the management API ACME monitor endpoint.");
      sendJson(res, 200, consoleModel().acmeMonitorView(req));
      log.debug("Leaving the management API ACME monitor endpoint.");
    } },

  { method: 'POST', route: BASE + '/acme/:action', tag: 'ACME',
    mirrors: 'POST /admin/acme',
    handler: function (req, res) {
      log.debug("Entering the management API ACME action endpoint.");
      const body = Object.assign({}, parseBody(req),
                                 { action: String(req.params.action || '') });
      Promise.resolve(consoleModel().acmeAction(body,
                                                { via: 'api', req: req }))
        .then(function (result) {
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-ACME-0091');
          }
          sendJson(res, result.ok ? 200 : 400, result);
        }).catch(function (e) {
          log.error(errorCodes.tag('STS-ACME-0095') + 'acme management API ' +
                    'action threw: ' + ((e && e.stack) || e));
          errorCodes.mark(res, 'STS-ACME-0095');
          sendJson(res, 500, { ok: false,
                               errors: ['The action could not be ' +
                                        'completed.'] });
        });
      log.debug("Leaving the management API ACME action endpoint.");
    },
    actions: [
      { action: 'create-eab', operationId: 'createAcmeEab',
        summary: 'Issue an External Account Binding key for a person or ' +
                 'application (RFC 8555 section 7.3.4)',
        description: 'Creates an EAB key for ONE entry in this realm and ' +
                     'answers the key id and the HMAC key IN THE CLEAR, ONCE ' +
                     '— the key is stored sealed on the entry and no ' +
                     'operation reads it back. The ACME account a client ' +
                     'registers with it is bound to that entry for life, ' +
                     'which is the administrator\'s path in ACME: a key ' +
                     'created here for somebody else\'s entry. The reply ' +
                     'carries a ready-to-paste certbot line.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            kind: KIND,
            identifier: IDENTIFIER,
            lifetimeS: { type: 'integer', minimum: 60, maximum: 31536000,
                         description: 'How long it may wait before binding ' +
                                      'an account; at most ' +
                                      'acme.eabLifetimeS, which is also the ' +
                                      'default.' }
          },
          required: ['kind', 'identifier'],
          examples: [{ kind: 'person', identifier: 'alice' }],
          additionalProperties: false
        },
        responseDescription: 'The key id, the HMAC key (once), when it ' +
                             'expires, the directory and a certbot line.' },
      { action: 'delete-eab', operationId: 'deleteAcmeEab',
        summary: 'Delete an External Account Binding key',
        description: 'Removes the key from its entry. An account it already ' +
                     'bound keeps its binding; a key not yet used can no ' +
                     'longer bind one.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { kid: { type: 'string', minLength: 1, maxLength: 512,
                               description: 'The key id, from GET ' +
                                            '/admin-api/acme.' } },
          required: ['kid'],
          examples: [{ kid: 'eab-p-YWxpY2U-0123456789abcdef' }],
          additionalProperties: false
        },
        responseDescription: 'The key id that was deleted.' },
      { action: 'deactivate-account', operationId: 'deactivateAcmeAccount',
        summary: 'Deactivate an ACME account (RFC 8555 section 7.3.6)',
        description: 'The account authorizes nothing more — every request ' +
                     'it signs is answered unauthorized — exactly as if the ' +
                     'client had deactivated it itself. Certificates already ' +
                     'issued are untouched; revoke them separately.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: { account: { type: 'string', pattern:
                                     '^[A-Za-z0-9_-]{8,64}$',
                                   description: 'The account id, from GET ' +
                                                '/admin-api/acme.' } },
          required: ['account'],
          examples: [{ account: 'AbCdEfGhIjKlMnOp' }],
          additionalProperties: false
        },
        responseDescription: 'The account as it now stands.' },
      { action: 'revoke-certificate', operationId: 'revokeAcmeCertificate',
        summary: 'Revoke a certificate issued over ACME',
        description: 'Puts the certificate on the ACME Issuing CA\'s CRL ' +
                     '(/pki/crl/{realm}/acme) with the RFC 5280 reason ' +
                     'given, ' +
                     'and its OCSP responder answers revoked. The record on ' +
                     'the entry is marked revoked.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            serial: { type: 'string', minLength: 1, maxLength: 128,
                      pattern: '^[0-9A-Fa-f:]+$',
                      description: 'The serial number in hex.' },
            reason: { type: 'string',
                      enum: ['unspecified', 'keyCompromise', 'cACompromise',
                             'affiliationChanged', 'superseded',
                             'cessationOfOperation', 'certificateHold',
                             'privilegeWithdrawn', 'aACompromise'],
                      description: 'The RFC 5280 reason; unspecified by ' +
                                   'default.' }
          },
          required: ['serial'],
          examples: [{ serial: '0a1b2c3d4e5f', reason: 'keyCompromise' }],
          additionalProperties: false
        },
        responseDescription: 'The serial that was revoked, and the reason.' },
      { action: 'add-host-name', operationId: 'addAcmeHostName',
        summary: 'Register a host name or address on an entry',
        description: 'A dns or ip identifier is authorized for an ACME ' +
                     'account only when it is registered on the entry the ' +
                     'account is bound to; nothing is fetched to prove ' +
                     'control of a name. The same registration serves EST ' +
                     'and SCEP.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            kind: KIND,
            identifier: IDENTIFIER,
            hostName: { type: 'string', minLength: 1, maxLength: 253,
                        description: 'A DNS name (a leading *. is a ' +
                                     'wildcard registered exactly so) or an ' +
                                     'IP address.' }
          },
          required: ['kind', 'identifier', 'hostName'],
          examples: [{ kind: 'application', identifier: 'web1',
                       hostName: 'web1.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'The entry\'s host names as they now stand.' },
      { action: 'remove-host-name', operationId: 'removeAcmeHostName',
        summary: 'Remove a registered host name from an entry',
        description: 'Certificates already issued for it are untouched; a ' +
                     'new order for it is refused rejectedIdentifier.',
        requestBodyRequired: true,
        requestBody: {
          type: 'object',
          properties: {
            kind: KIND,
            identifier: IDENTIFIER,
            hostName: { type: 'string', minLength: 1, maxLength: 253,
                        description: 'The registered name to remove.' }
          },
          required: ['kind', 'identifier', 'hostName'],
          examples: [{ kind: 'application', identifier: 'web1',
                       hostName: 'web1.example.com' }],
          additionalProperties: false
        },
        responseDescription: 'The entry\'s host names as they now stand.' }
    ] }
];

module.exports = { ROUTES: ROUTES };
