// @ts-check
'use strict';
//
// File: acme.js
//
// ---------------------------------------------------------------------------
// THE ACME SERVER (RFC 8555), PER TRUST REALM, AT /enroll/acme (2026-09-13).
//
// An ACME client proves who it is with a key, asks for certificates for
// identifiers, proves control of each identifier, and is handed a certificate
// from this realm's ACME Issuing CA. Three things about THIS server make it
// different from a public CA, and each is a decision rcbj made rather than a
// gap:
//
//   * **AN ACCOUNT IS BOUND TO A DIRECTORY ENTRY FOR LIFE.** `newAccount`
//     REQUIRES an External Account Binding (section 7.3.4) — a MAC key that was
//     issued for ONE person or application, by that person on the portal or by
//     an administrator on the console or `/admin-api`. The account records the
//     entry, and every certificate it is ever issued names that entry and is
//     kept on it. The ADMIN path in ACME is therefore an EAB key an operator
//     created for somebody else's entry; nothing in the protocol lets an
//     account speak for a second entry.
//   * **NO CHALLENGE EVER DIALS OUT.** Section 8's challenges prove control of
//     a name by making the CA fetch something the client put there. This
//     service does not dial an address somebody supplied (the root CLAUDE.md's
//     non-goal row), so an identifier is authorized by the ENTRY instead: a
//     host name an administrator REGISTERED on the entry, the person's own
//     `mail`, the entry's own identifier. Those authorizations are created
//     `valid` and carry one challenge of the type `sts-entry-binding-01`,
//     already `valid`, so a conforming client sees nothing to do; an
//     identifier the entry does not own fails `newOrder` with
//     `rejectedIdentifier` rather than leaving a pending authorization that can
//     never complete.
//   * **EVERYTHING ABOUT THE CERTIFICATE IS `common/cert_enrollment.js`'s.**
//     This module decides the wire format and nothing else: who may be issued
//     what, what the certificate says, where it is kept and how it is revoked
//     are the enrollment core's, shared with EST and SCEP.
//
// The envelope (JWS, nonces, EAB, schemas) is `acme_jws.js`; the state is
// `acme_store.js`; the console and `/admin-api` read `acme_console.js`, which
// `acme_admin.js` draws. `acme/CLAUDE.md` carries the RFC sections, the
// documented exceptions and the traps.
//
// **REQUIRED AT 23e** (`common/protocol_stack.js`), after the console at 18
// whose shell `acme_admin.js` draws with, and after `ldap` at 21 whose slot the
// enrollment core reads entries through. It requires `./acme_admin` itself so
// the family is one line there.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const app = require('../common/app');
const helpers = require('../common/helpers');
const { log } = helpers;
const config = require('../common/config');
const errorCodes = require('../common/error_codes');
const stsCrypto = require('../common/crypto');
const audit = require('../common/audit');
const realms = require('../common/realms');
const core = require('../common/cert_enrollment');
const monitor = require('../common/enrollment_monitor');
const validation = require('../common/validation');
const jws = require('./acme_jws');
const store = require('./acme_store');
// The atomic "once" a finalize is held to across nodes. A LIBRARY that reaches
// `persistence.js` lazily; see the finalize handler.
const claims = require('../cluster/cluster_claims');

const FAMILY = 'acme';
const PREFIX = '/enroll/acme';

// The one challenge type an authorization here carries. Its name says what it
// is: the identifier was bound to the entry by the directory, not proven by a
// fetch. See the header.
const CHALLENGE_TYPE = 'sts-entry-binding-01';

// The identifier types a newOrder may name: RFC 8555's `dns`, RFC 8738's `ip`,
// RFC 8823's `email`, and draft-ietf-acme-device-attest's
// `permanent-identifier`, which here names the entry itself.
const IDENTIFIER_TYPES = ['dns', 'ip', 'email', 'permanent-identifier'];

// What each issued profile is, for the directory's `meta.profiles`
// (draft-ietf-acme-profiles section 3) and the console's profile table.
const PROFILE_DESCRIPTIONS = {
  'tls-server': 'A TLS server certificate (serverAuth) for host names ' +
                'registered on the account\'s entry.',
  'tls-client': 'A TLS client certificate (clientAuth) naming the entry.',
  'tls-server-client': 'serverAuth and clientAuth, for host names ' +
                       'registered on the entry.',
  'digital-signature': 'A signing certificate (digitalSignature, ' +
                       'nonRepudiation) naming the entry.',
  'key-encipherment': 'A key-encipherment certificate naming the entry.',
  'code-signing': 'A code-signing certificate (codeSigning) naming the entry.',
  'email': 'An S/MIME certificate (emailProtection) for the person\'s own ' +
           'mail address.',
  'timestamping': 'A time-stamping authority certificate (timeStamping).',
  'smartcard-logon': 'A smartcard logon certificate carrying the person\'s ' +
                     'user principal name (userPrincipalName, else mail).'
};

// Rows per page of an account's orders list (section 7.1.2.1).
const ORDERS_PER_PAGE = 100;

// A path segment this service minted: base64url, bounded. Anything else in an
// `:id` is a 404 before a store is looked at.
const ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;

const ORDERS_QUERY = validation.z.looseObject({
  page: validation.types.opt(validation.types.integer(1, 100000))
});

// ---------------------------------------------------------------------------
// URLS. Every one absolute, from `baseUrlOf(req)`, so it carries the realm.
// ---------------------------------------------------------------------------
function urlsFor(req) {
  log.debug("Entering urlsFor().");
  const base = helpers.baseUrlOf(req) + PREFIX;
  log.debug("Leaving urlsFor().");
  return {
    base: base,
    directory: base + '/directory',
    newNonce: base + '/new-nonce',
    newAccount: base + '/new-account',
    newOrder: base + '/new-order',
    revokeCert: base + '/revoke-cert',
    keyChange: base + '/key-change',
    renewalInfo: base + '/renewal-info',
    account: function (id) { return base + '/account/' + id; },
    orders: function (id) { return base + '/account/' + id + '/orders'; },
    order: function (id) { return base + '/order/' + id; },
    finalize: function (id) { return base + '/order/' + id + '/finalize'; },
    authz: function (id) { return base + '/authz/' + id; },
    challenge: function (id) { return base + '/challenge/' + id; },
    cert: function (id) { return base + '/cert/' + id; }
  };
}

// ---------------------------------------------------------------------------
// RESPONSES. Every ACME response carries a fresh Replay-Nonce, the `index`
// link to the directory and `Cache-Control: no-store` — the nonce is a
// single-use credential and section 7.2 says a response carrying one must not
// be cached.
// ---------------------------------------------------------------------------
function commonHeaders(ctx) {
  log.debug("Entering commonHeaders().");
  const lifetime = Number(config.value('acme.nonceLifetimeS'));
  ctx.res.set('Replay-Nonce', jws.mintNonce(realms.currentId(), lifetime));
  ctx.res.set('Cache-Control', 'no-store');
  ctx.res.append('Link', '<' + ctx.urls.directory + '>;rel="index"');
  log.debug("Leaving commonHeaders().");
}

function sendJson(ctx, status, body, location) {
  log.debug("Entering sendJson(). status=" + status);
  commonHeaders(ctx);
  if (location) {
    ctx.res.set('Location', location);
  }
  ctx.res.status(status).type('application/json')
     .send(JSON.stringify(body, null, 2));
  log.debug("Leaving sendJson().");
}

function record(ctx, detail) {
  log.debug("Entering record().");
  monitor.record(FAMILY, Object.assign({ operation: ctx.operation,
                                         principal: ctx.principal || null,
                                         target: ctx.target || null },
                                       detail || {}));
  log.debug("Leaving record().");
}

// ---------------------------------------------------------------------------
// THE ONE ERROR RESPONSE (RFC 7807 problem document, section 6.7). The code is
// marked on the response and never written into it; a refusal is counted
// against the caller for the throttle except where the refusal is the ordinary
// course of a conforming client (a stale nonce) or is the throttle itself.
// ---------------------------------------------------------------------------
// error-code: none — the definition of the helper; every call names its code
function acmeProblem(ctx, status, type, code, detail, extra) {
  log.debug("Entering acmeProblem(). type=" + type + " code=" + code);
  const body = Object.assign({ type: jws.ERROR_PREFIX + type,
                               detail: String(detail).slice(0, 2000),
                               status: status }, extra || {});
  if (body.subproblems) {
    body.subproblems = body.subproblems.map(function (one) {
      return Object.assign({}, one, { type: jws.ERROR_PREFIX + one.type });
    });
  }
  const counts = type !== 'badNonce' && type !== 'rateLimited' &&
                 status !== 405;
  if (counts && core.sharesThrottle()) {
    // WHERE THE THROTTLE IS SHARED THE COUNT DECIDES THE ANSWER (2026-09-14):
    // a refusal whose count took the caller past the limit is answered
    // `rateLimited` (RFC 8555 section 6.6) — `core.countFailureShared()`.
    core.countFailureShared(FAMILY, ctx.req, ctx.identity || '')
      .then(function (overLimit) {
        if (!overLimit) {
          sendProblem(ctx, status, code, body);
          return;
        }
        ctx.res.set('Retry-After', String(core.retryAfterOf(overLimit)));
        sendProblem(ctx, 429, 'STS-ENROLL-0061',
                    { type: jws.ERROR_PREFIX + 'rateLimited',
                      detail: overLimit.why, status: 429 });
      });
    log.debug("Leaving acmeProblem(). Counting first.");
    return null;
  }
  if (counts) {
    core.countFailure(FAMILY, ctx.req, ctx.identity || '');
  }
  sendProblem(ctx, status, code, body);
  log.debug("Leaving acmeProblem().");
  return null;
}

// The bytes of a problem document, with the headers every ACME answer carries.
function sendProblem(ctx, status, code, body) {
  log.debug("Entering sendProblem(). status=" + status);
  if (ctx.res.headersSent) {
    // A problem answered while an earlier one was still being counted.
    log.debug("Leaving sendProblem(). Already answered.");
    return;
  }
  // error-code: none — the code is the caller's, forwarded; this is the helper
  record(ctx, { outcome: 'refused', status: status, errorCode: code });
  commonHeaders(ctx);
  errorCodes.mark(ctx.res, code);
  ctx.res.status(status).type('application/problem+json')
     .send(JSON.stringify(body, null, 2));
  log.debug("Leaving sendProblem().");
}

// A refusal object from acme_jws.js or the enrollment core, sent.
function sendRefusal(ctx, refusal, fallbackCode) {
  log.debug("Entering sendRefusal().");
  const code = refusal.code || errorCodes.codeOf(refusal) || fallbackCode;
  const extra = {};
  if (refusal.algorithms) {
    extra.algorithms = refusal.algorithms;
  }
  if (refusal.subproblems) {
    extra.subproblems = refusal.subproblems;
  }
  log.debug("Leaving sendRefusal().");
  // error-code: none — forwards the refusal's own code, or the caller's
  return acmeProblem(ctx, refusal.status || 400, refusal.type || 'malformed',
                     code, refusal.detail || (refusal.errors || [])[0] ||
                     'The request was refused.', extra);
}

// An enrollment-core refusal, in ACME's vocabulary. The core's status is the
// guide and its code is kept, so the audit row names the core's condition.
function coreRefusal(ctx, refusal, fallbackCode) {
  log.debug("Entering coreRefusal().");
  const code = errorCodes.codeOf(refusal) || fallbackCode;
  const sentence = String((refusal.errors || [])[0] || refusal.why ||
                          'The request was refused.');
  let type = 'serverInternal';
  let status = Number(refusal.status) || 500;
  if (/^STS-ENROLL-005[0-6]$/.test(code)) {
    type = 'rejectedIdentifier';
    status = 400;
  } else if (code === 'STS-ENROLL-0031' || code === 'STS-ENROLL-0032') {
    type = 'badPublicKey';
    status = 400;
  } else if (/^STS-ENROLL-003\d$/.test(code)) {
    type = 'badCSR';
    status = 400;
  } else if (/^STS-ENROLL-000[1-3]$/.test(code)) {
    type = 'invalidProfile';
    status = 400;
  } else if (code === 'STS-ENROLL-0061') {
    type = 'rateLimited';
    status = 429;
    ctx.res.set('Retry-After', String(core.retryAfterOf(refusal)));
  } else if (status === 401 || status === 403 || status === 404 ||
             status === 409) {
    type = 'unauthorized';
    status = 403;
  } else if (status === 400) {
    type = 'malformed';
  } else {
    status = status >= 500 ? status : 500;
  }
  log.debug("Leaving coreRefusal(). type=" + type);
  // error-code: none — forwards the core's code, or the caller's fallback
  return acmeProblem(ctx, status, type, code, sentence);
}

// ---------------------------------------------------------------------------
// THE CONTEXT, AND THE THREE CHECKS EVERY ACME REQUEST MAKES BEFORE ANYTHING.
// ---------------------------------------------------------------------------
function contextOf(req, res, operation) {
  log.debug("Entering contextOf().");
  log.debug("Leaving contextOf().");
  return { req: req, res: res, operation: operation, urls: urlsFor(req),
           identity: '', principal: null, target: null };
}

// Turned off, over plain HTTP in product mode, or throttled. Answers true when
// a problem was sent.
function gateRefused(ctx) {
  log.debug("Entering gateRefused().");
  if (config.value('acme.enabled') === false) {
    log.debug("Leaving gateRefused(). Turned off.");
    acmeProblem(ctx, 503, 'serverInternal', 'STS-ACME-0001', 'ACME is ' +
                'turned off in this realm (acme.enabled).');
    return true;
  }
  const transport = core.transportRefusal(ctx.req, FAMILY);
  if (transport) {
    log.debug("Leaving gateRefused(). Not over TLS.");
    coreRefusal(ctx, transport, 'STS-ACME-0002');
    return true;
  }
  // ASYNCHRONOUS SINCE 2026-09-14 (#46): the throttle is the cluster's one
  // budget, which is a round trip. What it answers is unchanged.
  log.debug("Leaving gateRefused(). Asking the throttle.");
  return core.throttledShared(FAMILY, ctx.req, ctx.identity || '')
    .then(function (throttled) {
      if (throttled) {
        coreRefusal(ctx, throttled, 'STS-ACME-0003');
        return true;
      }
      return false;
    });
}

// An exception a handler did not expect is a 500 problem, never a stack trace.
function guarded(operation, handler) {
  log.debug("Entering guarded(). operation=" + operation);
  log.debug("Leaving guarded().");
  return function (req, res) {
    const ctx = contextOf(req, res, operation);
    Promise.resolve().then(function () {
      return gateRefused(ctx);
    }).then(function (refused) {
      if (refused) {
        return null;
      }
      return handler(ctx);
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-ACME-0095') + 'acme: ' + operation +
                ' threw: ' + ((e && e.stack) || e));
      if (!res.headersSent) {
        acmeProblem(ctx, 500, 'serverInternal', 'STS-ACME-0095', 'The ' +
                    'server could not complete the request.');
      }
    });
  };
}

// ---------------------------------------------------------------------------
// A METHOD A RESOURCE DOES NOT ANSWER (section 6.3): 405 with `Allow`, as a
// problem document, rather than Express's `Cannot GET`.
//
// **ONE MIDDLEWARE AFTER THE ROUTES AND NOT A ROUTE PER METHOD**, and the
// reason is `/admin/sts-metadata`: it reads the router, lists every method a
// route registers as an endpoint, and `tests/vendored/sts_metadata.js` asserts
// that no listed method is refused. A `GET` route whose only job is to refuse
// would be a listed method answering 405. A middleware registers no route, so
// the index lists what each resource answers and nothing else.
// ---------------------------------------------------------------------------
const ALLOWED_METHODS = [
  { re: /^\/directory$/, allow: 'GET, HEAD' },
  { re: /^\/new-nonce$/, allow: 'GET, HEAD' },
  { re: /^\/renewal-info\/[^/]+$/, allow: 'GET, HEAD' },
  { re: /^\/(new-account|new-order|revoke-cert|key-change)$/, allow: 'POST' },
  { re: /^\/(account|order|authz|challenge|cert)\/[^/]+$/, allow: 'POST' },
  { re: /^\/account\/[^/]+\/orders$/, allow: 'POST' },
  { re: /^\/order\/[^/]+\/finalize$/, allow: 'POST' }
];

function methodNotAllowed(req, res, next) {
  log.debug("Entering methodNotAllowed(). " + req.method + " " + req.path);
  const row = ALLOWED_METHODS.filter(function (one) {
    return one.re.test(req.path);
  })[0];
  if (!row) {
    log.debug("Leaving methodNotAllowed(). Not an ACME resource.");
    return next();
  }
  const ctx = contextOf(req, res, 'method-not-allowed');
  res.set('Allow', row.allow);
  log.debug("Leaving methodNotAllowed(). 405.");
  return acmeProblem(ctx, 405, 'malformed', 'STS-ACME-0026', 'This ACME ' +
                     'resource answers ' + row.allow + ' (RFC 8555 section ' +
                     '6.3).');
}

// ---------------------------------------------------------------------------
// A SIGNED REQUEST (section 6.2), READ AND AUTHENTICATED.
//
//   spec.key   'jwk' | 'kid' | 'either'
//
// Answers { header, parts, payload, account, jwk } or sends the problem and
// answers null. The ORDER is the contract: shape before key, the nonce's MAC
// and expiry before the signature (cheap refusals first), and the nonce SPENT
// only after the signature verifies — so a forged request cannot burn a nonce a
// client is holding, and two copies of one signed request cannot both pass.
// ---------------------------------------------------------------------------
async function authenticate(ctx, spec) {
  log.debug("Entering authenticate(). key=" + spec.key);
  const req = ctx.req;
  if (!jws.isJoseJson(req.headers['content-type'])) {
    log.debug("Leaving authenticate(). Wrong media type.");
    return acmeProblem(ctx, 415, 'malformed', 'STS-ACME-0010', 'An ACME ' +
                       'request body is application/jose+json (RFC 8555 ' +
                       'section 6.2).');
  }
  const max = Number(config.value('acme.maxRequestBytes'));
  const declared = Number(req.headers['content-length'] || 0);
  const actual = req.rawBody ? req.rawBody.length
                             : Buffer.byteLength(String(req.body || ''));
  if (declared > max || actual > max) {
    log.debug("Leaving authenticate(). Too large.");
    return acmeProblem(ctx, 413, 'malformed', 'STS-ACME-0011', 'The request ' +
                       'body is larger than acme.maxRequestBytes (' + max +
                       ' bytes).');
  }
  const parts = jws.parseBody(req.body);
  if (!parts.ok) {
    log.debug("Leaving authenticate(). Not a flattened JWS.");
    return sendRefusal(ctx, parts, 'STS-ACME-0012');
  }
  const read = jws.parseProtectedHeader(parts);
  if (!read.ok) {
    log.debug("Leaving authenticate(). Bad header.");
    return sendRefusal(ctx, read, 'STS-ACME-0014');
  }
  const header = read.header;
  const alg = jws.checkAlgorithm(header.alg);
  if (!alg.ok) {
    log.debug("Leaving authenticate(). Unsupported algorithm.");
    return sendRefusal(ctx, alg, 'STS-ACME-0015');
  }
  const hasJwk = header.jwk !== undefined;
  const hasKid = header.kid !== undefined;
  if (hasJwk === hasKid || (spec.key === 'jwk' && !hasJwk) ||
      (spec.key === 'kid' && !hasKid)) {
    log.debug("Leaving authenticate(). jwk/kid rule.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0020', 'The ' +
                       'protected header must carry exactly one of "jwk" ' +
                       'and "kid", and ' +
                       'this resource takes ' +
                       (spec.key === 'either' ? 'either'
                                              : '"' + spec.key + '"') +
                       ' (RFC 8555 section 6.2).');
  }
  const nonce = jws.checkNonce(header.nonce, realms.currentId());
  if (!nonce.ok) {
    log.debug("Leaving authenticate(). Bad nonce: " + nonce.reason);
    return acmeProblem(ctx, 400, 'badNonce',
                       nonce.reason === 'expired' ? 'STS-ACME-0017'
                                                  : 'STS-ACME-0016',
                       nonce.reason === 'expired'
                         ? 'The Replay-Nonce has expired. Retry with the one ' +
                           'on this response.'
                         : 'The Replay-Nonce is missing or is not one this ' +
                           'server issued in this realm. Retry with the one ' +
                           'on this response.');
  }
  const expectedUrl = helpers.baseUrlOf(req) + req.path;
  if (header.url !== expectedUrl) {
    log.debug("Leaving authenticate(). url mismatch.");
    return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0019', 'The ' +
                       'protected header\'s "url" is not the URL this ' +
                       'request ' +
                       'was sent to (RFC 8555 section 6.4).');
  }
  let account = null;
  let key = null;
  let accountKey = null;
  if (hasKid) {
    const accountPrefix = ctx.urls.base + '/account/';
    const id = header.kid.indexOf(accountPrefix) === 0
      ? header.kid.slice(accountPrefix.length) : '';
    account = ID_PATTERN.test(id) ? store.getAccount(id) : null;
    ctx.identity = account ? 'account:' + account.id : '';
    if (!account) {
      log.debug("Leaving authenticate(). No such account.");
      return acmeProblem(ctx, 400, 'accountDoesNotExist', 'STS-ACME-0022',
                         'The "kid" is not the URL of an account on this ' +
                         'server in this realm.');
    }
    ctx.principal = 'account:' + account.id;
    ctx.target = account.entry ? core.entryUri(account.entry) : null;
    if (account.status !== 'valid') {
      log.debug("Leaving authenticate(). Account not valid.");
      return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0023', 'The ' +
                         'account is ' + account.status + '; a deactivated ' +
                         'account authorizes nothing (RFC 8555 section ' +
                         '7.3.6).');
    }
    if (!jws.algorithmFitsKey(header.alg, account.jwk)) {
      log.debug("Leaving authenticate(). alg does not fit the account key.");
      return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0021', 'The JWS ' +
                         '"alg" cannot have been made with this account\'s ' +
                         'key.');
    }
    key = account.jwk;
  } else {
    accountKey = jws.checkAccountKey(header.jwk, header.alg);
    if (!accountKey.ok) {
      log.debug("Leaving authenticate(). Bad jwk.");
      return sendRefusal(ctx, accountKey, 'STS-ACME-0021');
    }
    ctx.identity = 'key:' + accountKey.thumbprint;
    key = accountKey.jwk;
  }
  const verified = jws.verifyFlattened(parts, key, header.alg);
  if (!verified.ok) {
    log.debug("Leaving authenticate(). Signature.");
    return sendRefusal(ctx, verified, 'STS-ACME-0024');
  }
  // SPENT ACROSS THE CLUSTER SINCE 2026-09-14 (#46): the local map first, then
  // a claim in the store, so two copies of one signed request at two nodes
  // cannot both pass. `acme_store.js`'s `spendNonceOnce()` argues it, and it is
  // why this function is asynchronous.
  /** @type {any} */
  const spent = await store.spendNonceOnce(nonce.id, nonce.expiresS);
  if (!spent.ok && spent.reason === 'store') {
    log.error(errorCodes.tag('STS-ACME-0099') + 'acme: a Replay-Nonce could ' +
              'not be proved unspent (' + spent.why + '); the request is ' +
              'refused.');
    log.debug("Leaving authenticate(). Nonce store.");
    return acmeProblem(ctx, 500, 'serverInternal', 'STS-ACME-0099', 'The ' +
                       'server could not check the Replay-Nonce. Retry.');
  }
  if (!spent.ok) {
    log.debug("Leaving authenticate(). Nonce replayed.");
    return acmeProblem(ctx, 400, 'badNonce', 'STS-ACME-0018', 'That ' +
                       'Replay-Nonce has already been used. Retry with the ' +
                       'one on this response.');
  }
  const throttled = await core.throttledShared(FAMILY, req, ctx.identity);
  if (throttled) {
    log.debug("Leaving authenticate(). Identity throttled.");
    return coreRefusal(ctx, throttled, 'STS-ACME-0003');
  }
  const payload = jws.readPayload(parts);
  if (!payload.ok) {
    log.debug("Leaving authenticate(). Payload unreadable.");
    return sendRefusal(ctx, payload, 'STS-ACME-0025');
  }
  log.debug("Leaving authenticate(). Authenticated.");
  return { header: header, parts: parts, payload: payload.value,
           account: account, accountKey: accountKey };
}

// The account a `kid` request came from must be the one the URL names.
function sameAccount(ctx, signed, accountId) {
  log.debug("Entering sameAccount().");
  if (signed.account.id !== accountId) {
    acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0027', 'The resource ' +
                'belongs to a different account from the one that signed ' +
                'this request.');
    log.debug("Leaving sameAccount(). Different account.");
    return false;
  }
  log.debug("Leaving sameAccount().");
  return true;
}

function requirePostAsGet(ctx, signed) {
  log.debug("Entering requirePostAsGet().");
  if (signed.payload !== null) {
    acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0025', 'This resource is ' +
                'read with POST-as-GET: an empty payload (RFC 8555 section ' +
                '6.3).');
    log.debug("Leaving requirePostAsGet(). A payload.");
    return false;
  }
  log.debug("Leaving requirePostAsGet().");
  return true;
}

function missingResource(ctx, what) {
  log.debug("Entering missingResource().");
  log.debug("Leaving missingResource().");
  return acmeProblem(ctx, 404, 'malformed', 'STS-ACME-0028', 'There is no ' +
                     'such ' + what + ' on this server in this realm.');
}

// ---------------------------------------------------------------------------
// THE SHAPES OF THE RESOURCES (section 7.1).
// ---------------------------------------------------------------------------
function accountJson(ctx, account) {
  log.debug("Entering accountJson().");
  log.debug("Leaving accountJson().");
  return {
    status: account.status,
    contact: account.contact || [],
    termsOfServiceAgreed: !!account.termsOfServiceAgreed,
    orders: ctx.urls.orders(account.id),
    createdAt: account.createdAt
  };
}

function isExpired(when) {
  log.debug("Entering isExpired().");
  log.debug("Leaving isExpired().");
  return !!when && new Date(when).getTime() <= Date.now();
}

function authzStatus(authz) {
  log.debug("Entering authzStatus().");
  if (!authz) {
    log.debug("Leaving authzStatus(). Gone.");
    return 'invalid';
  }
  if (authz.status !== 'valid') {
    log.debug("Leaving authzStatus().");
    return authz.status;
  }
  log.debug("Leaving authzStatus().");
  return isExpired(authz.expires) ? 'expired' : 'valid';
}

// An order's status is DERIVED on read, for the store's reason: nothing moves
// it on a timer.
function orderStatus(order) {
  log.debug("Entering orderStatus().");
  if (order.status === 'valid' || order.status === 'processing') {
    log.debug("Leaving orderStatus().");
    return order.status;
  }
  if (isExpired(order.expires)) {
    log.debug("Leaving orderStatus(). Expired.");
    return 'invalid';
  }
  const broken = (order.authorizationIds || []).some(function (id) {
    return authzStatus(store.getAuthorization(id)) !== 'valid';
  });
  log.debug("Leaving orderStatus().");
  return broken ? 'invalid' : 'ready';
}

function orderJson(ctx, order) {
  log.debug("Entering orderJson().");
  const status = orderStatus(order);
  const out = {
    status: status,
    expires: order.expires,
    identifiers: order.identifiers,
    profile: order.profile,
    authorizations: (order.authorizationIds || []).map(function (id) {
      return ctx.urls.authz(id);
    }),
    finalize: ctx.urls.finalize(order.id)
  };
  if (order.replaces) {
    out.replaces = order.replaces;
  }
  if (status === 'valid' && order.certificateId) {
    out.certificate = ctx.urls.cert(order.certificateId);
  }
  log.debug("Leaving orderJson(). status=" + status);
  return out;
}

function challengeJson(ctx, authz) {
  log.debug("Entering challengeJson().");
  const status = authzStatus(authz);
  log.debug("Leaving challengeJson().");
  return {
    type: CHALLENGE_TYPE,
    url: ctx.urls.challenge(authz.id),
    status: status === 'valid' ? 'valid' : 'invalid',
    validated: authz.validated,
    token: authz.token
  };
}

function authzJson(ctx, authz) {
  log.debug("Entering authzJson().");
  const out = {
    identifier: authz.identifier,
    status: authzStatus(authz),
    expires: authz.expires,
    challenges: [challengeJson(ctx, authz)]
  };
  if (authz.wildcard) {
    out.wildcard = true;
  }
  log.debug("Leaving authzJson().");
  return out;
}

// ---------------------------------------------------------------------------
// GET /enroll/acme/directory (section 7.1.1).
// ---------------------------------------------------------------------------
function directoryJson(ctx) {
  log.debug("Entering directoryJson().");
  const profiles = {};
  core.allowedProfiles(FAMILY).forEach(function (id) {
    profiles[id] = PROFILE_DESCRIPTIONS[id] || id;
  });
  log.debug("Leaving directoryJson().");
  return {
    newNonce: ctx.urls.newNonce,
    newAccount: ctx.urls.newAccount,
    newOrder: ctx.urls.newOrder,
    revokeCert: ctx.urls.revokeCert,
    keyChange: ctx.urls.keyChange,
    renewalInfo: ctx.urls.renewalInfo,
    meta: {
      externalAccountRequired: true,
      website: helpers.baseUrlOf(ctx.req) + '/admin/acme',
      profiles: profiles
    }
  };
}

app.get(PREFIX + '/directory', guarded('directory', function (ctx) {
  log.debug("Entering the ACME directory.");
  record(ctx, { outcome: 'answered', status: 200 });
  sendJson(ctx, 200, directoryJson(ctx));
  log.debug("Leaving the ACME directory.");
}));

// ---------------------------------------------------------------------------
// HEAD|GET /enroll/acme/new-nonce (section 7.2): 200 to a HEAD, 204 to a GET.
// ---------------------------------------------------------------------------
app.head(PREFIX + '/new-nonce', guarded('new-nonce', function (ctx) {
  log.debug("Entering the ACME new-nonce HEAD.");
  record(ctx, { outcome: 'answered', status: 200 });
  commonHeaders(ctx);
  ctx.res.status(200).end();
  log.debug("Leaving the ACME new-nonce HEAD.");
}));
app.get(PREFIX + '/new-nonce', guarded('new-nonce', function (ctx) {
  log.debug("Entering the ACME new-nonce GET.");
  record(ctx, { outcome: 'answered', status: 204 });
  commonHeaders(ctx);
  ctx.res.status(204).end();
  log.debug("Leaving the ACME new-nonce GET.");
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/new-account (sections 7.3, 7.3.1, 7.3.4).
// ---------------------------------------------------------------------------
app.post(PREFIX + '/new-account', guarded('new-account', async function (ctx) {
  log.debug("Entering the ACME new-account.");
  const signed = await authenticate(ctx, { key: 'jwk' });
  if (!signed) {
    log.debug("Leaving the ACME new-account. Refused.");
    return;
  }
  const checked = jws.checkPayload(signed.payload || {},
                                   jws.schemas.NEW_ACCOUNT, 'newAccount');
  if (!checked.ok || signed.payload === null) {
    log.debug("Leaving the ACME new-account. Bad payload.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0025',
                       checked.ok ? 'A newAccount request carries a payload.'
                                  : checked.detail);
  }
  const body = checked.value;
  const thumbprint = signed.accountKey.thumbprint;
  const existing = store.accountByThumbprint(thumbprint);
  if (existing) {
    ctx.principal = 'account:' + existing.id;
    ctx.target = existing.entry ? core.entryUri(existing.entry) : null;
    record(ctx, { outcome: 'answered', status: 200 });
    log.debug("Leaving the ACME new-account. Existing account.");
    return sendJson(ctx, 200, accountJson(ctx, existing),
                    ctx.urls.account(existing.id));
  }
  if (body.onlyReturnExisting === true) {
    log.debug("Leaving the ACME new-account. None exists.");
    return acmeProblem(ctx, 400, 'accountDoesNotExist', 'STS-ACME-0030', 'No ' +
                       'account exists for this key in this realm.');
  }
  const contacts = jws.checkContacts(body.contact);
  if (!contacts.ok) {
    log.debug("Leaving the ACME new-account. Bad contact.");
    return sendRefusal(ctx, contacts, 'STS-ACME-0037');
  }
  if (!body.externalAccountBinding) {
    log.debug("Leaving the ACME new-account. No EAB.");
    return acmeProblem(ctx, 403, 'externalAccountRequired', 'STS-ACME-0031',
                       'This server requires an External Account Binding ' +
                       '(RFC 8555 section 7.3.4). An EAB key is issued for ' +
                       'one person or application on the user portal, the ' +
                       'console or /admin-api.');
  }
  const eab = jws.parseEab(body.externalAccountBinding, ctx.urls.newAccount,
                           thumbprint);
  if (!eab.ok) {
    log.debug("Leaving the ACME new-account. EAB malformed.");
    return sendRefusal(ctx, eab, 'STS-ACME-0032');
  }
  ctx.principal = 'eab:' + eab.kid;
  ctx.identity = 'eab:' + eab.kid;
  const found = core.findEab(eab.kid);
  if (!found) {
    log.debug("Leaving the ACME new-account. Unknown EAB key.");
    return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0033', 'The ' +
                       'External Account Binding key is not known in this ' +
                       'realm.');
  }
  // THE MAC FIRST: nothing about the key's state is told to a caller who
  // cannot prove they hold it.
  if (!jws.verifyEabMac(eab, found.hmacKey)) {
    log.debug("Leaving the ACME new-account. EAB MAC.");
    return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0034', 'The ' +
                       'External Account Binding does not verify with the ' +
                       'key issued under that key id.');
  }
  if (found.expired && !found.boundAccount) {
    log.debug("Leaving the ACME new-account. EAB expired.");
    return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0035', 'The ' +
                       'External Account Binding key has expired.');
  }
  ctx.target = core.entryUri(found.entry);
  const resolved = core.resolveEntry(found.entry.kind, found.entry.id);
  if (!resolved.ok) {
    log.debug("Leaving the ACME new-account. The entry is gone.");
    return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0048', 'The ' +
                       'entry that External Account Binding key was issued ' +
                       'for no longer exists in this realm.');
  }
  // ONCE ACROSS THE CLUSTER (2026-09-14, #46): the key id is claimed before
  // the binding is written, so two accounts at two nodes cannot both bind it.
  // `common/cert_enrollment.js`'s `bindEabOnce()` argues it.
  const bound = await core.bindEabOnce(eab.kid, thumbprint);
  if (!bound.ok) {
    log.debug("Leaving the ACME new-account. Bind refused.");
    return acmeProblem(ctx, 403, 'unauthorized',
                       errorCodes.codeOf(bound) || 'STS-ACME-0036',
                       String((bound.errors || [])[0] ||
                              'The External Account Binding key could not ' +
                              'bind this account.'));
  }
  const account = store.createAccount({
    jwk: signed.accountKey.jwk,
    thumbprint: thumbprint,
    contact: contacts.contacts,
    termsOfServiceAgreed: body.termsOfServiceAgreed === true,
    eabKid: eab.kid,
    entry: found.entry
  });
  ctx.principal = 'account:' + account.id;
  audit.record({
    category: 'protocol', action: 'enrollment.acme.account.create',
    protocol: 'ACME', outcome: 'success', actor: 'eab:' + eab.kid,
    target: core.entryUri(found.entry),
    summary: 'an ACME account was created and bound for life to the ' +
             core.entryLabel(found.entry),
    detail: { account: account.id, kid: eab.kid }
  });
  record(ctx, { outcome: 'redeemed', status: 201 });
  log.debug("Leaving the ACME new-account. Created " + account.id + ".");
  return sendJson(ctx, 201, accountJson(ctx, account),
                  ctx.urls.account(account.id));
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/account/:id (sections 7.3.2 and 7.3.6).
// ---------------------------------------------------------------------------
app.post(PREFIX + '/account/:id', guarded('account', async function (ctx) {
  log.debug("Entering the ACME account.");
  const signed = await authenticate(ctx, { key: 'kid' });
  if (!signed || !sameAccount(ctx, signed, String(ctx.req.params.id))) {
    log.debug("Leaving the ACME account. Refused.");
    return;
  }
  const account = signed.account;
  if (signed.payload !== null) {
    const checked = jws.checkPayload(signed.payload,
                                     jws.schemas.ACCOUNT_UPDATE, 'account');
    if (!checked.ok) {
      log.debug("Leaving the ACME account. Bad payload.");
      return sendRefusal(ctx, checked, 'STS-ACME-0025');
    }
    const update = checked.value;
    if (update.status !== undefined && update.status !== 'deactivated') {
      log.debug("Leaving the ACME account. Bad status.");
      return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0038', 'The only ' +
                         'status a client may set on its account is ' +
                         '"deactivated" (RFC 8555 section 7.3.6).');
    }
    if (update.contact !== undefined) {
      const contacts = jws.checkContacts(update.contact);
      if (!contacts.ok) {
        log.debug("Leaving the ACME account. Bad contact.");
        return sendRefusal(ctx, contacts, 'STS-ACME-0037');
      }
      account.contact = contacts.contacts;
    }
    if (update.status === 'deactivated') {
      account.status = 'deactivated';
      account.deactivatedAt = new Date().toISOString();
      audit.record({
        category: 'protocol', action: 'enrollment.acme.account.deactivate',
        protocol: 'ACME', outcome: 'success', actor: 'account:' + account.id,
        target: ctx.target || '',
        summary: 'an ACME account deactivated itself',
        detail: { account: account.id }
      });
    }
    store.saveAccount(account);
  }
  record(ctx, { outcome: 'answered', status: 200 });
  log.debug("Leaving the ACME account.");
  return sendJson(ctx, 200, accountJson(ctx, account),
                  ctx.urls.account(account.id));
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/account/:id/orders (section 7.1.2.1), paged with `page`.
// ---------------------------------------------------------------------------
app.post(PREFIX + '/account/:id/orders', guarded('orders',
                                                          async function (ctx) {
  log.debug("Entering the ACME orders list.");
  const query = validation.check(ctx.req, 'query', ORDERS_QUERY);
  if (!query.ok) {
    log.debug("Leaving the ACME orders list. Bad query.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0082', 'The orders ' +
                       'list takes one query parameter, "page": ' +
                       query.detail);
  }
  const signed = await authenticate(ctx, { key: 'kid' });
  if (!signed || !sameAccount(ctx, signed, String(ctx.req.params.id)) ||
      !requirePostAsGet(ctx, signed)) {
    log.debug("Leaving the ACME orders list. Refused.");
    return;
  }
  const ids = (signed.account.orderIds || []).filter(function (id) {
    const order = store.getOrder(id);
    return order && orderStatus(order) !== 'invalid';
  });
  const page = Number(query.value.page || 1);
  const shown = ids.slice((page - 1) * ORDERS_PER_PAGE,
                          page * ORDERS_PER_PAGE);
  if (page * ORDERS_PER_PAGE < ids.length) {
    ctx.res.append('Link', '<' + ctx.urls.orders(signed.account.id) +
                   '?page=' + (page + 1) + '>;rel="next"');
  }
  record(ctx, { outcome: 'answered', status: 200 });
  log.debug("Leaving the ACME orders list. " + shown.length + " shown.");
  return sendJson(ctx, 200, { orders: shown.map(function (id) {
    return ctx.urls.order(id);
  }) });
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/new-order (section 7.4, draft-ietf-acme-profiles, RFC 9773
// section 5).
// ---------------------------------------------------------------------------
function ownershipProblem(resolved, identifier) {
  log.debug("Entering ownershipProblem(). type=" + identifier.type);
  const entry = resolved.entry;
  if (identifier.type === 'permanent-identifier') {
    // The value was reduced to a bare identifier when it named an entry of
    // the account's own kind; a URN naming another kind is still a URN here
    // and can equal no identifier.
    log.debug("Leaving ownershipProblem().");
    return identifier.value === entry.id ? null
      : 'The permanent-identifier "' + identifier.value.slice(0, 120) +
        '" is not the ' + core.entryLabel(entry) + ' this account is bound ' +
        'to. An account is issued certificates for its own entry only.';
  }
  const requested = { uris: [], dns: [], ips: [], emails: [], upns: [] };
  if (identifier.type === 'dns') {
    requested.dns.push(identifier.value);
  } else if (identifier.type === 'ip') {
    requested.ips.push(identifier.value);
  } else if (identifier.type === 'email') {
    requested.emails.push(identifier.value);
  }
  // A DRY RUN of the core's own naming rule, so ownership has one definition.
  const names = core.namesFor(resolved, 'digital-signature', requested);
  log.debug("Leaving ownershipProblem(). owned=" + names.ok);
  return names.ok ? null : String((names.errors || [])[0]);
}

app.post(PREFIX + '/new-order', guarded('new-order', async function (ctx) {
  log.debug("Entering the ACME new-order.");
  const signed = await authenticate(ctx, { key: 'kid' });
  if (!signed) {
    log.debug("Leaving the ACME new-order. Refused.");
    return;
  }
  const checked = signed.payload === null
    ? jws.refusal('malformed', 400, 'STS-ACME-0025', 'A newOrder request ' +
                  'carries a payload.')
    : jws.checkPayload(signed.payload, jws.schemas.NEW_ORDER, 'newOrder');
  if (!checked.ok) {
    log.debug("Leaving the ACME new-order. Bad payload.");
    return sendRefusal(ctx, checked, 'STS-ACME-0025');
  }
  const body = checked.value;
  const account = signed.account;
  if (body.notBefore !== undefined || body.notAfter !== undefined) {
    log.debug("Leaving the ACME new-order. Validity requested.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0043', 'This server ' +
                       'does not accept "notBefore" or "notAfter": a ' +
                       'certificate\'s validity is ' +
                       'acme.certificateLifetimeDays ' +
                       'from issuance, shortened to the Issuing CA\'s own.');
  }
  const profileId = body.profile || core.defaultProfile(FAMILY);
  const profile = core.checkProfile(FAMILY, profileId);
  if (!profile.ok) {
    log.debug("Leaving the ACME new-order. Profile refused.");
    return acmeProblem(ctx, 400, 'invalidProfile', 'STS-ACME-0044',
                       String((profile.errors || [])[0]));
  }
  ctx.profile = profile.profile;
  const resolved = core.resolveEntry(account.entry.kind, account.entry.id);
  if (!resolved.ok) {
    log.debug("Leaving the ACME new-order. The entry is gone.");
    return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0048', 'The ' +
                       'entry this account is bound to no longer exists in ' +
                       'this realm.');
  }
  const identifiers = [];
  const seen = {};
  const unsupported = [];
  for (let i = 0; i < body.identifiers.length; i++) {
    const one = body.identifiers[i];
    if (IDENTIFIER_TYPES.indexOf(one.type) < 0) {
      unsupported.push({ type: 'unsupportedIdentifier',
                         detail: 'This server issues for dns, ip, email and ' +
                                 'permanent-identifier identifiers.',
                         identifier: { type: String(one.type).slice(0, 64),
                                       value: String(one.value)
                                         .slice(0, 256) } });
      continue;
    }
    let value = jws.normalIdentifier(one.type, one.value);
    if (one.type === 'permanent-identifier' && value) {
      const named = core.entryFromUri(value);
      value = named && named.kind === account.entry.kind ? named.id : value;
    }
    if (!value) {
      log.debug("Leaving the ACME new-order. Malformed identifier.");
      return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0041', 'The ' +
                         one.type + ' identifier "' +
                         String(one.value).slice(0, 120) + '" is not a ' +
                         'well-formed value of that type.');
    }
    const key = one.type + ':' + (one.type === 'email' ? value.toLowerCase()
                                                       : value);
    if (seen[key]) {
      log.debug("Leaving the ACME new-order. Duplicate identifier.");
      return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0046', 'The ' +
                         'identifier ' + key.slice(0, 160) + ' appears twice.');
    }
    seen[key] = true;
    identifiers.push({ type: one.type, value: value });
  }
  if (unsupported.length) {
    log.debug("Leaving the ACME new-order. Unsupported identifiers.");
    return acmeProblem(ctx, 400, 'unsupportedIdentifier', 'STS-ACME-0040',
                       unsupported.length + ' identifier(s) are of a type ' +
                       'this server does not issue for.',
                       { subproblems: unsupported });
  }
  const rejected = [];
  identifiers.forEach(function (identifier) {
    const problem = ownershipProblem(resolved, identifier);
    if (problem) {
      rejected.push({ type: 'rejectedIdentifier', detail: problem,
                      identifier: identifier });
    }
  });
  if (rejected.length) {
    log.debug("Leaving the ACME new-order. Rejected identifiers.");
    return acmeProblem(ctx, 400, 'rejectedIdentifier', 'STS-ACME-0042',
                       rejected.length === 1 ? rejected[0].detail
                         : rejected.length + ' identifiers are not the ' +
                           core.entryLabel(resolved.entry) + '\'s to ask for.',
                       { subproblems: rejected });
  }
  const types = identifiers.map(function (one) { return one.type; });
  let needs = '';
  if ((profile.profile === 'tls-server' ||
       profile.profile === 'tls-server-client') &&
      types.indexOf('dns') < 0 && types.indexOf('ip') < 0) {
    needs = 'A ' + profile.profile + ' order names at least one dns or ip ' +
            'identifier registered on the entry.';
  } else if (profile.profile === 'email' && types.indexOf('email') < 0) {
    needs = 'An email order names the person\'s mail as an email identifier ' +
            '(RFC 8823).';
  } else if (profile.profile === 'smartcard-logon' &&
             !(resolved.upn || resolved.mail)) {
    needs = 'A smartcard-logon certificate carries a user principal name, ' +
            'and the ' + core.entryLabel(resolved.entry) + ' has neither ' +
            'userPrincipalName nor mail.';
  }
  if (needs) {
    log.debug("Leaving the ACME new-order. The profile needs more.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0045', needs);
  }
  let replaces = null;
  if (body.replaces !== undefined) {
    const certId = jws.parseCertId(body.replaces);
    const old = certId ? store.certificateByCertId(certId.certId) : null;
    if (!old || old.entry.kind !== account.entry.kind ||
        old.entry.id !== account.entry.id) {
      log.debug("Leaving the ACME new-order. Unknown replaces.");
      return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0047', 'The ' +
                         '"replaces" member does not name a certificate this ' +
                         'account\'s entry was issued over ACME in this ' +
                         'realm (RFC 9773 section 5).');
    }
    if (old.replacedBy) {
      log.debug("Leaving the ACME new-order. Already replaced.");
      return acmeProblem(ctx, 409, 'alreadyReplaced', 'STS-ACME-0049', 'That ' +
                         'certificate has already been replaced by another ' +
                         'order (RFC 9773 section 5).');
    }
    replaces = certId.certId;
  }
  const lifetimeS = Number(config.value('acme.orderLifetimeS'));
  const nowMs = Date.now();
  const expires = new Date(nowMs + lifetimeS * 1000).toISOString();
  const validated = new Date(nowMs).toISOString();
  const authzIds = identifiers.map(function (identifier) {
    const wildcard = identifier.type === 'dns' &&
                     identifier.value.indexOf('*.') === 0;
    return store.createAuthorization({
      accountId: account.id,
      identifier: { type: identifier.type,
                    value: wildcard ? identifier.value.slice(2)
                                    : identifier.value },
      wildcard: wildcard,
      expires: expires,
      validated: validated,
      token: jws.b64u(nodeCrypto.randomBytes(24))
    }).id;
  });
  const order = store.createOrder(account, {
    identifiers: identifiers,
    profile: profile.profile,
    authorizationIds: authzIds,
    expires: expires,
    replaces: replaces
  });
  record(ctx, { outcome: 'answered', status: 201,
                profile: profile.profile });
  log.debug("Leaving the ACME new-order. Created " + order.id + ".");
  return sendJson(ctx, 201, orderJson(ctx, order), ctx.urls.order(order.id));
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/order/:id — an order, POST-as-GET.
// ---------------------------------------------------------------------------
function ownedOrder(ctx, signed) {
  log.debug("Entering ownedOrder().");
  const id = String(ctx.req.params.id);
  const order = ID_PATTERN.test(id) ? store.getOrder(id) : null;
  if (!order) {
    log.debug("Leaving ownedOrder(). None.");
    missingResource(ctx, 'order');
    return null;
  }
  if (!sameAccount(ctx, signed, order.accountId)) {
    log.debug("Leaving ownedOrder(). Not this account's.");
    return null;
  }
  log.debug("Leaving ownedOrder().");
  return order;
}

app.post(PREFIX + '/order/:id', guarded('order', async function (ctx) {
  log.debug("Entering the ACME order.");
  const signed = await authenticate(ctx, { key: 'kid' });
  if (!signed || !requirePostAsGet(ctx, signed)) {
    log.debug("Leaving the ACME order. Refused.");
    return;
  }
  const order = ownedOrder(ctx, signed);
  if (!order) {
    log.debug("Leaving the ACME order. Refused.");
    return;
  }
  record(ctx, { outcome: 'answered', status: 200, profile: order.profile });
  log.debug("Leaving the ACME order.");
  return sendJson(ctx, 200, orderJson(ctx, order), ctx.urls.order(order.id));
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/order/:id/finalize (section 7.4).
//
// **THE CSR MUST NAME EXACTLY THE ORDER'S IDENTIFIERS** — section 7.4's
// sentence, read as a set: every subjectAltName and a common name each count
// as one identifier of the order, nothing may be left over on either side, and
// a name of a kind the order cannot contain is refused as badCSR rather than
// dropped. The one exception is the user principal name otherName on a
// smartcard-logon order, which is not an ACME identifier type and which the
// enrollment core holds to the entry's own userPrincipalName or mail.
// ---------------------------------------------------------------------------
function csrNamesProblem(csr, order, entry) {
  log.debug("Entering csrNamesProblem().");
  const want = {};
  const keyOf = function (type, value) {
    return type + ':' + (type === 'email' || type === 'dns'
                         ? String(value).toLowerCase() : String(value));
  };
  order.identifiers.forEach(function (one) {
    want[keyOf(one.type, one.value)] = true;
  });
  const have = {};
  const add = function (type, value) {
    const normal = jws.normalIdentifier(type, value);
    if (!normal) {
      return false;
    }
    have[keyOf(type, normal)] = true;
    return true;
  };
  const requested = csr.requested || {};
  const bad = [];
  (requested.dns || []).forEach(function (one) {
    if (!add('dns', one)) {
      bad.push('dNSName ' + one);
    }
  });
  (requested.ips || []).forEach(function (one) {
    if (!add('ip', one)) {
      bad.push('iPAddress ' + one);
    }
  });
  (requested.emails || []).forEach(function (one) {
    if (!add('email', one)) {
      bad.push('rfc822Name ' + one);
    }
  });
  (requested.uris || []).forEach(function (one) {
    const named = core.entryFromUri(one);
    if (named && named.kind === entry.kind) {
      have[keyOf('permanent-identifier', named.id)] = true;
    } else {
      bad.push('URI ' + one);
    }
  });
  if ((requested.upns || []).length && order.profile !== 'smartcard-logon') {
    bad.push('a user principal name, which only a smartcard-logon order ' +
             'carries');
  }
  if (csr.commonName) {
    const cn = String(csr.commonName);
    const match = ['dns', 'ip', 'email', 'permanent-identifier']
      .map(function (type) { return keyOf(type, cn); })
      .filter(function (key) { return want[key]; })[0];
    if (match) {
      have[match] = true;
    } else {
      bad.push('the common name "' + cn.slice(0, 120) + '"');
    }
  }
  Object.keys(have).forEach(function (key) {
    if (!want[key]) {
      bad.push(key);
    }
  });
  if (bad.length) {
    log.debug("Leaving csrNamesProblem(). A name the order does not hold.");
    return 'The CSR names ' + bad.slice(0, 5).join(', ') + ', which ' +
           (bad.length === 1 ? 'is' : 'are') + ' not an identifier of this ' +
           'order (RFC 8555 section 7.4).';
  }
  const missing = Object.keys(want).filter(function (key) {
    return !have[key];
  });
  if (missing.length) {
    log.debug("Leaving csrNamesProblem(). The order names more.");
    return 'The CSR does not name ' + missing.slice(0, 5).join(', ') + ', ' +
           'which the order does. It must indicate exactly the order\'s ' +
           'identifiers (RFC 8555 section 7.4).';
  }
  log.debug("Leaving csrNamesProblem(). Exactly the order's identifiers.");
  return null;
}

app.post(PREFIX + '/order/:id/finalize', guarded('finalize',
                                                 async function (ctx) {
  log.debug("Entering the ACME finalize.");
  const signed = await authenticate(ctx, { key: 'kid' });
  if (!signed) {
    log.debug("Leaving the ACME finalize. Refused.");
    return;
  }
  const order = ownedOrder(ctx, signed);
  if (!order) {
    log.debug("Leaving the ACME finalize. Refused.");
    return;
  }
  ctx.profile = order.profile;
  const checked = signed.payload === null
    ? jws.refusal('malformed', 400, 'STS-ACME-0025', 'A finalize request ' +
                  'carries a payload with a "csr".')
    : jws.checkPayload(signed.payload, jws.schemas.FINALIZE, 'finalize');
  if (!checked.ok) {
    log.debug("Leaving the ACME finalize. Bad payload.");
    return sendRefusal(ctx, checked, 'STS-ACME-0025');
  }
  const status = orderStatus(order);
  if (status !== 'ready') {
    log.debug("Leaving the ACME finalize. Not ready: " + status);
    return acmeProblem(ctx, 403, 'orderNotReady', 'STS-ACME-0050', 'The ' +
                       'order is "' + status + '", and only a "ready" order ' +
                       'is finalized (RFC 8555 section 7.4).');
  }
  const der = jws.decodeB64url(checked.value.csr, false);
  if (!der) {
    log.debug("Leaving the ACME finalize. CSR encoding.");
    return acmeProblem(ctx, 400, 'badCSR', 'STS-ACME-0051', 'The "csr" is ' +
                       'not the base64url encoding of a DER ' +
                       'CertificationRequest.');
  }
  let csr = null;
  try {
    csr = await core.parseCsr(der, {});
  } catch (e) {
    log.debug("Caught in the ACME finalize: " + ((e && e.message) || e));
    csr = core.refuse('STS-ACME-0052', 400, 'The CSR could not be read.');
  }
  if (!csr.ok) {
    log.debug("Leaving the ACME finalize. CSR refused.");
    return coreRefusal(ctx, csr, 'STS-ACME-0052');
  }
  const mismatch = csrNamesProblem(csr, order, signed.account.entry);
  if (mismatch) {
    log.debug("Leaving the ACME finalize. CSR names.");
    return acmeProblem(ctx, 400, 'badCSR', 'STS-ACME-0053', mismatch);
  }
  // ---------------------------------------------------------------------
  // ONE FINALIZE PER ORDER, ACROSS THE CLUSTER (2026-09-14, #46 section 2).
  //
  // The "ready" check above and the "processing" write below are an await
  // apart (the CSR is parsed in between), and on several nodes the order row
  // reaches the others a moment after it is written. So two finalize requests
  // for one order — each signed with its own fresh nonce, so the nonce does
  // not join them — at two nodes, or racing on one, both saw "ready" and both
  // ISSUED: two certificates for one order, the second recorded over the
  // first. The order is CLAIMED here, once everything that can refuse without
  // side effects has run; a finalize that finds it claimed is told the order
  // is not ready, which is what it will read once the other request's
  // "processing" arrives. A refused issuance puts the order back to "ready"
  // below and gives the claim back, so the client may finalize again.
  // ---------------------------------------------------------------------
  const lifetimeMs = new Date(order.expires).getTime() - Date.now();
  const finalizing = await claims.claim({
    scope: 'acme.finalize', value: order.id,
    ttlMs: Math.max(60 * 1000, (lifetimeMs || 0) + 60 * 1000) });
  if (!finalizing.ok && finalizing.reason === 'used') {
    log.debug("Leaving the ACME finalize. Being finalized elsewhere.");
    return acmeProblem(ctx, 403, 'orderNotReady', 'STS-ACME-0098', 'The ' +
                       'order is already being finalized (RFC 8555 section ' +
                       '7.4). Poll the order.');
  }
  if (!finalizing.ok) {
    log.error(errorCodes.tag('STS-ACME-0099') + 'acme: an order could not ' +
              'be claimed for finalize (' + finalizing.why + '); refused.');
    log.debug("Leaving the ACME finalize. The store.");
    return acmeProblem(ctx, 500, 'serverInternal', 'STS-ACME-0099', 'The ' +
                       'server could not finalize the order just now. Retry.');
  }
  const account = signed.account;
  const entry = account.entry;
  const requested = {
    uris: [core.entryUri(entry)],
    dns: order.identifiers.filter(function (one) {
      return one.type === 'dns';
    }).map(function (one) { return one.value; }),
    ips: order.identifiers.filter(function (one) {
      return one.type === 'ip';
    }).map(function (one) { return one.value; }),
    emails: order.identifiers.filter(function (one) {
      return one.type === 'email';
    }).map(function (one) { return one.value; }),
    upns: (csr.requested.upns || []).slice()
  };
  order.status = 'processing';
  store.saveOrder(order);
  let issued = null;
  try {
    issued = await core.issue({
      family: FAMILY,
      profile: order.profile,
      target: entry,
      principal: { kind: entry.kind, id: entry.id, admin: false,
                   hasEntry: true, via: 'acme', realm: realms.currentId() },
      publicKeyPem: csr.publicKeyPem,
      keyAlg: csr.keyAlg,
      requested: requested,
      keySource: 'client',
      via: 'acme'
    });
  } catch (e) {
    log.debug("Caught in the ACME finalize: " + ((e && e.message) || e));
    issued = core.refuse('STS-ACME-0054', 500, 'The certificate could not ' +
                         'be issued.');
  }
  if (!issued.ok) {
    order.status = 'ready';
    store.saveOrder(order);
    claims.release(finalizing.handle);
    log.debug("Leaving the ACME finalize. Issuance refused.");
    return coreRefusal(ctx, issued, 'STS-ACME-0054');
  }
  const facts = jws.certificateFacts(jws.pemToDer(
    issued.record.certificatePem));
  const certId = facts && facts.aki
    ? jws.certIdOf(facts.aki, issued.record.serialHex) : '';
  const cert = store.recordCertificate({
    accountId: account.id,
    orderId: order.id,
    serialHex: issued.record.serialHex,
    entry: entry,
    profile: order.profile,
    notBefore: issued.record.notBefore,
    notAfter: issued.record.notAfter,
    certId: certId,
    replaces: order.replaces || null
  });
  if (order.replaces) {
    const old = store.certificateByCertId(order.replaces);
    if (old) {
      old.replacedBy = cert.id;
      store.saveCertificate(old);
    }
  }
  order.status = 'valid';
  order.certificateId = cert.id;
  store.saveOrder(order);
  record(ctx, { outcome: 'issued', status: 200, profile: order.profile,
                serialHex: cert.serialHex });
  log.debug("Leaving the ACME finalize. Issued " + cert.serialHex + ".");
  return sendJson(ctx, 200, orderJson(ctx, order), ctx.urls.order(order.id));
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/authz/:id (sections 7.5 and 7.5.2) and
// POST /enroll/acme/challenge/:id (section 7.5.1). One challenge per
// authorization, sharing its id.
// ---------------------------------------------------------------------------
function ownedAuthz(ctx, signed) {
  log.debug("Entering ownedAuthz().");
  const id = String(ctx.req.params.id);
  const authz = ID_PATTERN.test(id) ? store.getAuthorization(id) : null;
  if (!authz) {
    log.debug("Leaving ownedAuthz(). None.");
    missingResource(ctx, 'authorization');
    return null;
  }
  if (!sameAccount(ctx, signed, authz.accountId)) {
    log.debug("Leaving ownedAuthz(). Not this account's.");
    return null;
  }
  log.debug("Leaving ownedAuthz().");
  return authz;
}

app.post(PREFIX + '/authz/:id', guarded('authz', async function (ctx) {
  log.debug("Entering the ACME authorization.");
  const signed = await authenticate(ctx, { key: 'kid' });
  const authz = signed ? ownedAuthz(ctx, signed) : null;
  if (!authz) {
    log.debug("Leaving the ACME authorization. Refused.");
    return;
  }
  if (signed.payload !== null) {
    const checked = jws.checkPayload(signed.payload,
                                     jws.schemas.AUTHZ_UPDATE,
                                     'authorization');
    if (!checked.ok) {
      log.debug("Leaving the ACME authorization. Bad payload.");
      return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0055', 'The only ' +
                         'change a client may make to an authorization is ' +
                         '{"status": "deactivated"} (RFC 8555 section ' +
                         '7.5.2).');
    }
    authz.status = 'deactivated';
    store.saveAuthorization(authz);
  }
  record(ctx, { outcome: 'answered', status: 200 });
  log.debug("Leaving the ACME authorization.");
  return sendJson(ctx, 200, authzJson(ctx, authz));
}));

app.post(PREFIX + '/challenge/:id', guarded('challenge', async function (ctx) {
  log.debug("Entering the ACME challenge.");
  const signed = await authenticate(ctx, { key: 'kid' });
  const authz = signed ? ownedAuthz(ctx, signed) : null;
  if (!authz) {
    log.debug("Leaving the ACME challenge. Refused.");
    return;
  }
  if (signed.payload !== null && Object.keys(signed.payload).length) {
    log.debug("Leaving the ACME challenge. Bad payload.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0056', 'A response ' +
                       'to an ' + CHALLENGE_TYPE + ' challenge is the empty ' +
                       'object {} (RFC 8555 section 7.5.1).');
  }
  ctx.res.append('Link', '<' + ctx.urls.authz(authz.id) + '>;rel="up"');
  record(ctx, { outcome: 'answered', status: 200 });
  log.debug("Leaving the ACME challenge.");
  return sendJson(ctx, 200, challengeJson(ctx, authz));
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/cert/:id (section 7.4.2): the certificate, the family
// Issuing CA and the realm Intermediate. The service Root is not in the chain,
// as RFC 5246 section 7.4.2 and every ACME client expect: a relying party that
// trusts it already holds it.
// ---------------------------------------------------------------------------
function isSelfSigned(pem) {
  log.debug("Entering isSelfSigned().");
  let self = false;
  try {
    const cert = new nodeCrypto.X509Certificate(pem);
    self = cert.subject === cert.issuer && cert.checkIssued(cert);
  } catch (e) {
    log.debug("Caught in isSelfSigned(): " + ((e && e.message) || e));
    self = false;
  }
  log.debug("Leaving isSelfSigned(). self=" + self);
  return self;
}

app.post(PREFIX + '/cert/:id', guarded('cert', async function (ctx) {
  log.debug("Entering the ACME certificate.");
  const signed = await authenticate(ctx, { key: 'kid' });
  if (!signed || !requirePostAsGet(ctx, signed)) {
    log.debug("Leaving the ACME certificate. Refused.");
    return;
  }
  const id = String(ctx.req.params.id);
  const cert = ID_PATTERN.test(id) ? store.getCertificate(id) : null;
  if (!cert) {
    log.debug("Leaving the ACME certificate. None.");
    return missingResource(ctx, 'certificate');
  }
  if (!sameAccount(ctx, signed, cert.accountId)) {
    log.debug("Leaving the ACME certificate. Not this account's.");
    return;
  }
  const held = core.enrolledOf(cert.entry).filter(function (one) {
    return core.normalSerial(one.serialHex) === core.normalSerial(
      cert.serialHex);
  })[0];
  if (!held || !held.certificatePem) {
    log.debug("Leaving the ACME certificate. Not on the entry.");
    return missingResource(ctx, 'certificate');
  }
  const chain = [held.certificatePem].concat((held.chainPem || [])
    .filter(function (pem) { return !isSelfSigned(pem); }));
  const body = chain.map(function (pem) {
    return String(pem).trim() + '\n';
  }).join('');
  record(ctx, { outcome: 'answered', status: 200, profile: cert.profile,
                serialHex: cert.serialHex });
  commonHeaders(ctx);
  // The media type exactly as RFC 8555 section 9.1 registers it: `type()` on a
  // text body would append a charset parameter the registration does not have.
  ctx.res.set('Content-Type', 'application/pem-certificate-chain');
  ctx.res.status(200).send(Buffer.from(body, 'utf8'));
  log.debug("Leaving the ACME certificate.");
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/revoke-cert (section 7.6). Signed by the account whose
// entry holds the certificate, or by the certificate's own key (`jwk` whose
// SubjectPublicKeyInfo is the certificate's).
// ---------------------------------------------------------------------------
app.post(PREFIX + '/revoke-cert', guarded('revoke-cert',
                                          async function (ctx) {
  log.debug("Entering the ACME revoke-cert.");
  const signed = await authenticate(ctx, { key: 'either' });
  if (!signed) {
    log.debug("Leaving the ACME revoke-cert. Refused.");
    return;
  }
  const checked = signed.payload === null
    ? jws.refusal('malformed', 400, 'STS-ACME-0025', 'A revokeCert request ' +
                  'carries a payload with a "certificate".')
    : jws.checkPayload(signed.payload, jws.schemas.REVOKE, 'revokeCert');
  if (!checked.ok) {
    log.debug("Leaving the ACME revoke-cert. Bad payload.");
    return sendRefusal(ctx, checked, 'STS-ACME-0025');
  }
  const code = checked.value.reason === undefined ? 0 : checked.value.reason;
  const reason = jws.REVOCATION_REASONS[code];
  if (!reason) {
    log.debug("Leaving the ACME revoke-cert. Reason refused.");
    return acmeProblem(ctx, 400, 'badRevocationReason', 'STS-ACME-0062',
                       'Reason code ' + code + ' is not one this server ' +
                       'accepts from a subscriber. It accepts ' +
                       Object.keys(jws.REVOCATION_REASONS).join(', ') +
                       ' (RFC 5280 section 5.3.1).');
  }
  const der = jws.decodeB64url(checked.value.certificate, false);
  const facts = der ? jws.certificateFacts(der) : null;
  if (!facts) {
    log.debug("Leaving the ACME revoke-cert. Unreadable certificate.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0060', 'The ' +
                       '"certificate" is not the base64url encoding of one ' +
                       'DER certificate.');
  }
  const found = core.findEnrolled(facts.serialHex, FAMILY);
  const recorded = found ? jws.pemToDer(found.record.certificatePem) : null;
  if (!found || !recorded || !recorded.equals(facts.der)) {
    log.debug("Leaving the ACME revoke-cert. Not ours.");
    return acmeProblem(ctx, 404, 'malformed', 'STS-ACME-0061', 'That ' +
                       'certificate was not issued over ACME in this realm.');
  }
  ctx.target = core.entryUri(found.entry);
  let authorized = false;
  if (signed.account) {
    authorized = signed.account.entry.kind === found.entry.kind &&
                 signed.account.entry.id === found.entry.id;
  } else {
    const spki = jws.spkiOfJwk(signed.accountKey.jwk);
    authorized = !!spki && spki.equals(facts.spkiDer);
    ctx.principal = 'certificate-key';
  }
  if (!authorized) {
    log.debug("Leaving the ACME revoke-cert. Not authorized.");
    return acmeProblem(ctx, 403, 'unauthorized', 'STS-ACME-0063', 'The ' +
                       'request is signed neither by an account bound to the ' +
                       'entry that holds this certificate nor by the ' +
                       'certificate\'s own key.');
  }
  if (found.record.revoked) {
    log.debug("Leaving the ACME revoke-cert. Already revoked.");
    return acmeProblem(ctx, 400, 'alreadyRevoked', 'STS-ACME-0064', 'That ' +
                       'certificate is already revoked.');
  }
  const done = await core.revokeEnrolled(found.record.serialHex, reason,
                                         ctx.principal || 'acme',
                                         { family: FAMILY });
  if (!done.ok) {
    log.debug("Leaving the ACME revoke-cert. The CA refused.");
    return coreRefusal(ctx, done, 'STS-ACME-0065');
  }
  record(ctx, { outcome: 'revoked', status: 200,
                serialHex: done.serialHex, profile: found.record.profile });
  commonHeaders(ctx);
  ctx.res.status(200).end();
  log.debug("Leaving the ACME revoke-cert. Revoked " + done.serialHex + ".");
}));

// ---------------------------------------------------------------------------
// POST /enroll/acme/key-change (section 7.3.5).
// ---------------------------------------------------------------------------
app.post(PREFIX + '/key-change', guarded('key-change', async function (ctx) {
  log.debug("Entering the ACME key-change.");
  const signed = await authenticate(ctx, { key: 'kid' });
  if (!signed) {
    log.debug("Leaving the ACME key-change. Refused.");
    return;
  }
  const account = signed.account;
  const inner = jws.parseFlattenedObject(signed.payload, 'inner JWS');
  if (!inner.ok) {
    log.debug("Leaving the ACME key-change. Inner JWS.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0070', inner.detail);
  }
  const read = jws.parseProtectedHeader(inner);
  if (!read.ok) {
    log.debug("Leaving the ACME key-change. Inner header.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0070', read.detail);
  }
  const header = read.header;
  if (header.jwk === undefined || header.kid !== undefined ||
      header.nonce !== undefined || header.url !== signed.header.url) {
    log.debug("Leaving the ACME key-change. Inner header rules.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0071', 'The inner ' +
                       'JWS carries the new key as "jwk", no "kid", no ' +
                       '"nonce", and the same "url" as the outer JWS (RFC ' +
                       '8555 section 7.3.5).');
  }
  const alg = jws.checkAlgorithm(header.alg);
  if (!alg.ok) {
    log.debug("Leaving the ACME key-change. Inner algorithm.");
    return sendRefusal(ctx, alg, 'STS-ACME-0015');
  }
  const newKey = jws.checkAccountKey(header.jwk, header.alg);
  if (!newKey.ok) {
    log.debug("Leaving the ACME key-change. New key.");
    return sendRefusal(ctx, newKey, 'STS-ACME-0021');
  }
  if (!jws.verifyFlattened(inner, newKey.jwk, header.alg).ok) {
    log.debug("Leaving the ACME key-change. Inner signature.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0070', 'The inner ' +
                       'JWS is not signed by the new key it carries.');
  }
  const innerPayload = jws.readPayload(inner);
  const checked = innerPayload.ok && innerPayload.value
    ? jws.checkPayload(innerPayload.value, jws.schemas.KEY_CHANGE_INNER,
                       'keyChange')
    : jws.refusal('malformed', 400, 'STS-ACME-0070', 'The inner JWS ' +
                  'payload is {"account", "oldKey"}.');
  if (!checked.ok) {
    log.debug("Leaving the ACME key-change. Inner payload.");
    return sendRefusal(ctx, checked, 'STS-ACME-0070');
  }
  if (checked.value.account !== signed.header.kid) {
    log.debug("Leaving the ACME key-change. account differs.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0071', 'The inner ' +
                       'payload\'s "account" is not the account that signed ' +
                       'the outer JWS.');
  }
  let oldThumbprint = '';
  try {
    oldThumbprint = stsCrypto.jwkThumbprint(checked.value.oldKey);
  } catch (e) {
    log.debug("Caught in the ACME key-change: " + ((e && e.message) || e));
    oldThumbprint = '';
  }
  if (oldThumbprint !== account.thumbprint) {
    log.debug("Leaving the ACME key-change. oldKey differs.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0072', 'The inner ' +
                       'payload\'s "oldKey" is not the account\'s current ' +
                       'key.');
  }
  if (newKey.thumbprint === account.thumbprint) {
    log.debug("Leaving the ACME key-change. Same key.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0074', 'The new key ' +
                       'is the account\'s current key.');
  }
  const holder = store.accountByThumbprint(newKey.thumbprint);
  if (holder) {
    ctx.res.set('Location', ctx.urls.account(holder.id));
    log.debug("Leaving the ACME key-change. Key already bound.");
    return acmeProblem(ctx, 409, 'malformed', 'STS-ACME-0073', 'The new key ' +
                       'is already the key of another account (RFC 8555 ' +
                       'section 7.3.5).');
  }
  store.rekeyAccount(account, newKey.jwk, newKey.thumbprint);
  audit.record({
    category: 'protocol', action: 'enrollment.acme.account.key-change',
    protocol: 'ACME', outcome: 'success', actor: 'account:' + account.id,
    target: ctx.target || '',
    summary: 'an ACME account rolled over to a new key',
    detail: { account: account.id }
  });
  record(ctx, { outcome: 'answered', status: 200 });
  log.debug("Leaving the ACME key-change. Rekeyed.");
  return sendJson(ctx, 200, accountJson(ctx, account),
                  ctx.urls.account(account.id));
}));

// ---------------------------------------------------------------------------
// GET /enroll/acme/renewal-info/:id (RFC 9773 section 4). The suggested window
// is the last third of the validity; for a revoked certificate it is an hour
// in the past, which RFC 9773 section 4.2 tells a client means renew now.
// ---------------------------------------------------------------------------
const RENEWAL_RETRY_AFTER_S = 21600;

app.get(PREFIX + '/renewal-info/:id', guarded('renewal-info', function (ctx) {
  log.debug("Entering the ACME renewal-info.");
  const certId = jws.parseCertId(ctx.req.params.id);
  if (!certId) {
    log.debug("Leaving the ACME renewal-info. Malformed certID.");
    return acmeProblem(ctx, 400, 'malformed', 'STS-ACME-0080', 'The ' +
                       'certificate identifier is base64url(AKI ' +
                       'keyIdentifier) "." base64url(serial) (RFC 9773 ' +
                       'section 4.1).');
  }
  const cert = store.certificateByCertId(certId.certId);
  if (!cert) {
    log.debug("Leaving the ACME renewal-info. Unknown certificate.");
    return acmeProblem(ctx, 404, 'malformed', 'STS-ACME-0081', 'No ' +
                       'certificate issued over ACME in this realm has that ' +
                       'identifier.');
  }
  const held = core.enrolledOf(cert.entry).filter(function (one) {
    return core.normalSerial(one.serialHex) ===
           core.normalSerial(cert.serialHex);
  })[0];
  const nb = new Date(cert.notBefore).getTime();
  const na = new Date(cert.notAfter).getTime();
  let window = { start: new Date(nb + (na - nb) * 2 / 3).toISOString(),
                 end: new Date(na).toISOString() };
  if (held && held.revoked) {
    window = { start: new Date(Date.now() - 7200000).toISOString(),
               end: new Date(Date.now() - 3600000).toISOString() };
  }
  ctx.res.set('Retry-After', String(RENEWAL_RETRY_AFTER_S));
  record(ctx, { outcome: 'answered', status: 200,
                serialHex: cert.serialHex });
  log.debug("Leaving the ACME renewal-info.");
  return sendJson(ctx, 200, { suggestedWindow: window });
}));

app.use(PREFIX, methodNotAllowed);

log.info('The ACME server is registered at ' + PREFIX + '/directory (RFC ' +
         '8555, RFC 9773 renewal information, draft-ietf-acme-profiles), ' +
         'issuing from each realm\'s ACME Issuing CA with External Account ' +
         'Binding required.');

// The console's two pages. After the routes above, and nothing depends on the
// order: they are /admin paths.
require('./acme_admin');

module.exports = {
  FAMILY: FAMILY,
  PREFIX: PREFIX,
  CHALLENGE_TYPE: CHALLENGE_TYPE,
  IDENTIFIER_TYPES: IDENTIFIER_TYPES,
  PROFILE_DESCRIPTIONS: PROFILE_DESCRIPTIONS,
  urlsFor: urlsFor,
  csrNamesProblem: csrNamesProblem,
  orderStatus: orderStatus
};
