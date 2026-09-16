// @ts-check
'use strict';
//
// File: par.js
//
// ===========================================================================
// RFC 9126 — OAUTH 2.0 PUSHED AUTHORIZATION REQUESTS (2026-09-13).
//
// A client sends the parameters of an authorization request to this server
// DIRECTLY, over the back channel and authenticated as it would be at the token
// endpoint, and gets back a reference to send the browser with instead:
//
//   POST /oauth2/par                  client auth + the authorization request
//   201 { "request_uri": "urn:ietf:params:oauth:request_uri:<ref>",
//         "expires_in": 60 }
//   GET  /oauth2/authorize?client_id=app1&request_uri=urn:ietf:...
//
// So the parameters never cross the browser — they cannot be read or changed
// there — and the authorization server has seen and authenticated the client
// before a person is ever involved.
//
// **THIS FILE IS THE STORE AND THE REFERENCE, AND DECIDES NOTHING ELSE.** The
// endpoint is `oauth2.js`'s, because what a refusal looks like is protocol
// knowledge and a response object (3f's split); the validation of the pushed
// request IS the authorization endpoint's own, run over the pushed parameters
// by that module rather than written a second time; and reading a `request`
// object is `request_object.js`'s `verifyObject()`. What is here:
//
//   * `push()` — a request_uri with 256 bits from a CSPRNG in it (section 2.2,
//     and RFC 9101 section 10.2(d) by way of section 7.1), BOUND TO THE CLIENT
//     THAT PUSHED IT and to the authorization server it was pushed at;
//   * `resolve()` — what `request_object.js` calls for a request_uri in the
//     `urn:ietf:params:oauth:request_uri:` namespace. THAT MODULE NEVER FETCHES
//     ONE: a pushed request_uri is a key into this store and nothing else;
//   * `spend()` — what `issueAuthorizationResponse()` calls when an
//     authorization response goes out on one;
//   * the listing and the delete the monitoring page and `/admin-api` draw.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS WERE ASKED OF RCBJ, AND EACH TOOK THE RECOMMENDED ANSWER
// (the fourth with a change of shape — a section of an OAuth monitoring page):
//
//   1. THE CLIENT AUTHENTICATES AT /oauth2/par EXACTLY AS AT THE TOKEN
//      ENDPOINT — section 2's own words — which in this service means RFC 9700
//      mode, OAuth 2.1 mode and product mode refuse, and development observes.
//      What the observation found is recorded on the pushed request
//      (`clientAuthenticated`), and section 2.4's relaxation counts ONLY a
//      verified credential, in every mode: section 7.2's "MUST only accept new
//      redirect URIs ... from authenticated clients" is not a mode's to waive.
//   2. A REQUEST_URI IS SPENT WHEN AN AUTHORIZATION RESPONSE IS ISSUED ON IT,
//      not when it is first read. The authorization endpoint reads one browser
//      flow's request_uri at least twice — before the sign-in screen and on
//      the way back from it, and again after consent — which is section 4's
//      "MAY allow for duplicate requests due to a user reloading"; the value is
//      one-time in the sense section 7.3 is about, because nothing is ISSUED
//      twice on it. A spent one is kept until it would have expired, so a
//      replay is told "already used" rather than "unknown".
//   3. COUNTED ON AN OAUTH 2.0 MONITORING PAGE, `/admin/oauth2/monitor`, with
//      this as its first section — see `oauth2_monitor.js`.
//   4. TESTS IN PROCESS (`tests/par.js`) and an owned over-HTTP job for the
//      page and the API.
//
// ---------------------------------------------------------------------------
// WHAT A PUSHED REQUEST CARRIES, AND WHAT IT DOES NOT.
//
// The PARAMETERS the endpoint validated, exactly as the authorization endpoint
// will read them — never a client credential (`client_secret`,
// `client_assertion`), which `oauth2.js` strips before anything is kept, and
// never `request` or `request_uri` (section 2.1 refuses the second, and a
// pushed request object is verified at push time and kept as the parameters
// it VERIFIED to, with the algorithm beside it). Beside them, the facts the
// authorization endpoint needs and cannot recompute because they belong to the
// back-channel request: whether the client authenticated and by which method,
// the DPoP key a proof at the push bound the code to (RFC 9449 section 10.1),
// and whether section 2.4 was what let its redirect_uri through.
//
// **PER TRUST REALM AND PERSISTED WITH WHAT IS MINTED** — `realms.map()` with a
// `persist:` name, `authzCodes`' arrangement exactly: a push answered by one
// process and a browser arriving at another is the ordinary case in dispatch
// mode, and the store is shared the way every store is (root `CLAUDE.md`).
//
// **A FULL STORE REFUSES; IT NEVER FORGETS A LIVE ONE** — the used-assertion
// history's rule, for its reason turned round: a request_uri forgotten while
// somebody signs in is a sign-in that fails for nothing they did.
//
// **A LIBRARY (rule 3).** It registers no route, and requires `common/`
// modules and `oauth2_monitor.js`, none of which requires it back. It is
// required LAZILY by `request_object.js` and plainly by `oauth2.js`.
// ===========================================================================

const crypto = require('crypto');
const helpers = require('../common/helpers');
const config = require('../common/config');
const realms = require('../common/realms');
const errorCodes = require('../common/error_codes');
const monitor = require('./oauth2_monitor');

const log = helpers.log;

// Section 2.2: "The authorization server MAY construct the request_uri value
// using the form urn:ietf:params:oauth:request_uri:<reference-value>".
const REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:';

// 32 bytes, base64url: 256 bits of reference, which is what makes guessing one
// (section 7.1) a question about the CSPRNG rather than about a rate limit.
const REFERENCE_BYTES = 32;

// The authorization server a request was pushed at when a caller names none.
const DEFAULT_AUTHORIZATION_SERVER = 'default';

// request_uri -> the pushed request. See the header for the shape.
const pushedRequests = realms.map({ persist: 'oauth2.pushedRequests' });

function refusal(errorCode, error, description) {
  log.debug("Entering refusal(). " + errorCode);
  log.debug("Leaving refusal().");
  return errorCodes.mark({ ok: false, error: error,
                           description: description }, errorCode);
}

// The lifetime, bounded by the row's own range (5..600) — read directly, not
// `|| 60`, for the code-style rule about a legal value the fallback would hide.
function lifetimeS() {
  log.debug("Entering lifetimeS().");
  const raw = Number(config.value('oauth2.parRequestUriLifetimeS'));
  const seconds = isFinite(raw) ? Math.min(600, Math.max(5, Math.floor(raw)))
                                : 60;
  log.debug("Leaving lifetimeS(). " + seconds + "s.");
  return seconds;
}

function capacity() {
  log.debug("Entering capacity().");
  const raw = Number(config.value('oauth2.parMaxRequests'));
  log.debug("Leaving capacity().");
  return isFinite(raw) && raw >= 1 ? Math.floor(raw) : 10000;
}

// Whether a value is a request_uri in the namespace this file issues from.
// Case-sensitive in the reference and not in the URN's own letters, which RFC
// 8141 section 3.1 makes case-insensitive in the NID.
function isPushedRequestUri(value) {
  log.debug("Entering isPushedRequestUri().");
  const text = String(value === undefined || value === null ? '' : value);
  log.debug("Leaving isPushedRequestUri().");
  return text.slice(0, REQUEST_URI_PREFIX.length).toLowerCase() ===
         REQUEST_URI_PREFIX && text.length > REQUEST_URI_PREFIX.length;
}

// The one place a stored record becomes something a page or an API shows:
// every fact, and the parameters, and never anything else.
function describe(record, now) {
  log.debug("Entering describe().");
  const at = typeof now === 'number' ? now : Date.now();
  const state = record.spentAt ? 'spent'
    : (record.expiresAt <= at ? 'expired' : 'live');
  log.debug("Leaving describe(). " + state);
  return {
    request_uri: record.requestUri,
    client_id: record.clientId,
    authorization_server: record.authorizationServer,
    state: state,
    created_at: new Date(record.createdAt).toISOString(),
    expires_at: new Date(record.expiresAt).toISOString(),
    expires_in: Math.max(0, Math.ceil((record.expiresAt - at) / 1000)),
    spent_at: record.spentAt ? new Date(record.spentAt).toISOString() : null,
    reads: record.reads || 0,
    client_authenticated: !!record.clientAuthenticated,
    authentication_method: record.method || '',
    source: record.source,
    request_object_alg: record.alg || '',
    request_object_encrypted: record.encrypted || '',
    dpop_jkt: record.dpopJkt || '',
    redirect_uri: String((record.params || {}).redirect_uri || ''),
    redirect_uri_unregistered: !!record.redirectRelaxed,
    response_type: String((record.params || {}).response_type || ''),
    scope: String((record.params || {}).scope || ''),
    parameters: Object.assign({}, record.params || {})
  };
}

// Drop every record past its expiry. A spent one is simply gone; one that
// expired UNSPENT is counted, because a request_uri a client pushed and never
// used is the thing somebody debugging a client wants to see.
function sweep(now) {
  log.debug("Entering sweep().");
  const at = typeof now === 'number' ? now : Date.now();
  const gone = [];
  pushedRequests.forEach(function (record, key) {
    if (!record || record.expiresAt <= at) {
      gone.push({ key: key, record: record });
    }
  });
  gone.forEach(function (one) {
    pushedRequests.delete(one.key);
    if (one.record && !one.record.spentAt) {
      monitor.record(one.record.clientId, 'par.expired');
    }
  });
  log.debug("Leaving sweep(). " + gone.length + " swept.");
  return gone.length;
}

// ---------------------------------------------------------------------------
// push(entry) — keep a validated pushed request, and answer its request_uri.
//
//   entry.clientId             the client it is BOUND to (section 2.2)
//   entry.authorizationServer  the authorization server it was pushed at
//   entry.params               the authorization request, validated
//   entry.clientAuthenticated  whether a credential VERIFIED at the push
//   entry.method               which authentication method did
//   entry.source               'form' or 'request' (section 3)
//   entry.alg, entry.encrypted the request object's, where source is 'request'
//   entry.dpopJkt              a DPoP proof's key at the push, or ''
//   entry.redirectRelaxed      whether section 2.4 let the redirect_uri in
//
// Answers `{ ok, requestUri, expiresIn }` or a refusal. It is the endpoint's
// job to have validated everything first; this checks only what it owns.
// ---------------------------------------------------------------------------
function push(entry) {
  log.debug("Entering push().");
  const options = entry || {};
  const clientId = String(options.clientId || '');
  if (!clientId) {
    // Unreachable from the endpoint, which refuses a push with no client_id
    // (section 2.1) long before this — and a reference bound to nobody is not
    // one this file can make.
    log.debug("Leaving push(). No client to bind it to.");
    return refusal('STS-OAUTH-0405', 'invalid_request',
      'a pushed authorization request is bound to the client that pushed it ' +
      '(RFC 9126 section 2.2), and this one names no client.');
  }
  const now = Date.now();
  if (pushedRequests.size >= capacity()) {
    sweep(now);
  }
  if (pushedRequests.size >= capacity()) {
    log.warn(errorCodes.tag('STS-OAUTH-0408') + 'par: this realm holds ' +
             pushedRequests.size + ' live pushed authorization requests ' +
             '(oauth2.parMaxRequests), and the push from "' + clientId +
             '" was refused rather than forgetting one.');
    log.debug("Leaving push(). The store is full.");
    return refusal('STS-OAUTH-0408', 'temporarily_unavailable',
      'this authorization server is holding as many pushed authorization ' +
      'requests as it is configured to (oauth2.parMaxRequests), all of them ' +
      'still live. Retry shortly; a live request_uri is never forgotten to ' +
      'make room.');
  }
  const seconds = lifetimeS();
  const requestUri = REQUEST_URI_PREFIX +
    crypto.randomBytes(REFERENCE_BYTES).toString('base64url');
  const params = Object.assign({}, options.params || {});
  delete params.request;
  delete params.request_uri;
  pushedRequests.set(requestUri, {
    requestUri: requestUri,
    clientId: clientId,
    authorizationServer: String(options.authorizationServer ||
                                DEFAULT_AUTHORIZATION_SERVER),
    params: params,
    createdAt: now,
    expiresAt: now + seconds * 1000,
    spentAt: 0,
    reads: 0,
    clientAuthenticated: !!options.clientAuthenticated,
    method: String(options.method || ''),
    source: options.source === 'request' ? 'request' : 'form',
    alg: String(options.alg || ''),
    encrypted: String(options.encrypted || ''),
    dpopJkt: String(options.dpopJkt || ''),
    redirectRelaxed: !!options.redirectRelaxed
  });
  monitor.record(clientId, 'par.pushed');
  if (options.source === 'request') {
    monitor.record(clientId, 'par.request_object');
  }
  if (options.dpopJkt) {
    monitor.record(clientId, 'par.dpop_bound');
  }
  if (options.redirectRelaxed) {
    monitor.record(clientId, 'par.redirect_relaxed');
  }
  log.info('par: client "' + clientId + '" pushed an authorization request (' +
           options.source + ', ' + (options.clientAuthenticated
             ? 'authenticated by ' + options.method : 'not authenticated') +
           '), valid ' + seconds + 's.');
  log.debug("Leaving push().");
  return { ok: true, requestUri: requestUri, expiresIn: seconds };
}

// ---------------------------------------------------------------------------
// resolve(requestUri, clientId, opts) — what `request_object.js` calls for a
// request_uri in this namespace at the authorization endpoint.
//
//   opts.authorizationServer  the authorization server the request selected
//   opts.req                  the request, for its `__asProfile` if the
//                             caller had no name for it
//
// Answers `{ ok: true, params, alg, encrypted, pushed }` or a refusal whose
// error is `invalid_request_uri` (RFC 9101 section 7, which section 4 of RFC
// 9126 builds on). Every refusal here is answered by `oauth2.js` as a 400 ON
// THIS SERVER, never redirected: the redirect_uri is inside the request this
// could not find.
//
// Counts one read. It does NOT spend — see decision 2 in the header.
// ---------------------------------------------------------------------------
function resolve(requestUri, clientId, opts) {
  log.debug("Entering resolve().");
  const options = opts || {};
  const uri = String(requestUri || '');
  const client = String(clientId || '');
  const server = String(options.authorizationServer ||
                        (options.req && options.req.__asProfile) ||
                        DEFAULT_AUTHORIZATION_SERVER);
  const refused = function (code, description) {
    log.debug("Entering refused().");
    monitor.record(client, 'par.resolve_refused',
                   { error: 'invalid_request_uri' });
    log.info('par: the request_uri from "' + (client || '(no client_id)') +
             '" was refused: ' + description);
    log.debug("Leaving refused().");
    return refusal(code, 'invalid_request_uri', description);
  };
  if (!isPushedRequestUri(uri)) {
    log.debug("Leaving resolve(). Not in this namespace.");
    return refused('STS-OAUTH-0410', 'the request_uri "' + uri + '" is not ' +
      'one this authorization server issues: a pushed request_uri begins "' +
      REQUEST_URI_PREFIX + '" (RFC 9126 section 2.2).');
  }
  const now = Date.now();
  const record = pushedRequests.get(uri);
  if (!record) {
    log.debug("Leaving resolve(). Unknown.");
    return refused('STS-OAUTH-0410', 'the request_uri is not one this ' +
      'authorization server issued, or it expired and was swept. A ' +
      'request_uri is valid for oauth2.parRequestUriLifetimeS seconds from ' +
      'the push (RFC 9126 section 2.2); push the request again.');
  }
  if (record.expiresAt <= now) {
    log.debug("Leaving resolve(). Expired.");
    return refused('STS-OAUTH-0411', 'the request_uri expired ' +
      new Date(record.expiresAt).toISOString() + ' — "an expired ' +
      'request_uri MUST be rejected as invalid" (RFC 9126 section 4). Push ' +
      'the request again.');
  }
  if (String(record.clientId) !== client) {
    // Before "spent", so a client that is not the owner learns nothing about
    // the state of somebody else's reference.
    log.debug("Leaving resolve(). Another client's.");
    return refused('STS-OAUTH-0413', 'the request_uri was pushed by a ' +
      'different client than client_id "' + client + '" — a request_uri is ' +
      'bound to the client that pushed it (RFC 9126 section 2.2).');
  }
  if (String(record.authorizationServer) !== server) {
    log.debug("Leaving resolve(). Another authorization server's.");
    return refused('STS-OAUTH-0414', 'the request_uri was pushed at the "' +
      record.authorizationServer + '" authorization server and is being ' +
      'used at "' + server + '". A credential does not cross between the ' +
      'authorization servers this process serves.');
  }
  if (record.spentAt) {
    log.debug("Leaving resolve(). Already spent.");
    return refused('STS-OAUTH-0412', 'the request_uri was already used: an ' +
      'authorization response was issued on it at ' +
      new Date(record.spentAt).toISOString() + '. A client "MUST only use a ' +
      'request_uri value once" (RFC 9126 section 4); push the request again.');
  }
  record.reads = (record.reads || 0) + 1;
  pushedRequests.set(uri, record);
  monitor.record(client, 'par.resolved');
  log.debug("Leaving resolve(). Read " + record.reads + " time(s).");
  return {
    ok: true,
    params: Object.assign({}, record.params),
    alg: record.alg || '',
    encrypted: record.encrypted || '',
    pushed: {
      requestUri: uri,
      clientAuthenticated: !!record.clientAuthenticated,
      method: record.method || '',
      source: record.source,
      dpopJkt: record.dpopJkt || '',
      redirectUriAuthenticated: !!record.redirectRelaxed,
      expiresAt: record.expiresAt
    }
  };
}

// ---------------------------------------------------------------------------
// spend(requestUri) — an authorization response was issued on it. Answers
// whether anything was spent. Kept until its expiry, marked, so a replay is
// refused as USED rather than as unknown.
// ---------------------------------------------------------------------------
function spend(requestUri) {
  log.debug("Entering spend().");
  const uri = String(requestUri || '');
  const record = pushedRequests.get(uri);
  if (!record || record.spentAt) {
    log.debug("Leaving spend(). Nothing to spend.");
    return false;
  }
  record.spentAt = Date.now();
  pushedRequests.set(uri, record);
  monitor.record(record.clientId, 'par.spent');
  log.debug("Leaving spend().");
  return true;
}

// ---------------------------------------------------------------------------
// THE LISTING, for the monitoring page and `/admin-api`, newest first and
// paginated. `opts.state` narrows to 'live', 'spent' or 'all' (the default,
// which is every record not yet swept); `opts.clientId` to one client.
// ---------------------------------------------------------------------------
function list(opts) {
  log.debug("Entering list().");
  const options = opts || {};
  const now = Date.now();
  sweep(now);
  const wanted = ['live', 'spent'].indexOf(options.state) >= 0 ?
                 options.state : 'all';
  const client = options.clientId ? String(options.clientId) : '';
  const rows = [];
  pushedRequests.forEach(function (record) {
    const shown = describe(record, now);
    if (wanted !== 'all' && shown.state !== wanted) {
      return;
    }
    if (client && shown.client_id !== client) {
      return;
    }
    rows.push(shown);
  });
  rows.sort(function (a, b) {
    return a.created_at < b.created_at ? 1 :
           (a.created_at > b.created_at ? -1 : 0);
  });
  const offset = Math.max(0, Math.floor(Number(options.offset) || 0));
  const limitRaw = Math.floor(Number(options.limit));
  const limit = isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 500)
                                                   : 50;
  log.debug("Leaving list(). " + rows.length + " row(s).");
  return {
    total: rows.length,
    offset: offset,
    limit: limit,
    capacity: capacity(),
    lifetime_s: lifetimeS(),
    items: rows.slice(offset, offset + limit)
  };
}

function get(requestUri) {
  log.debug("Entering get().");
  const record = pushedRequests.get(String(requestUri || ''));
  log.debug("Leaving get(). " + (record ? 'Found.' : 'Not found.'));
  return record ? describe(record) : null;
}

// An administrator withdrew a request_uri. Answers whether there was one.
function remove(requestUri) {
  log.debug("Entering remove().");
  const uri = String(requestUri || '');
  const record = pushedRequests.get(uri);
  if (!record) {
    log.debug("Leaving remove(). Nothing to remove.");
    return false;
  }
  pushedRequests.delete(uri);
  monitor.record(record.clientId, 'par.deleted');
  log.debug("Leaving remove().");
  return true;
}

module.exports = {
  REQUEST_URI_PREFIX: REQUEST_URI_PREFIX,
  isPushedRequestUri: isPushedRequestUri,
  lifetimeS: lifetimeS,
  push: push,
  resolve: resolve,
  spend: spend,
  sweep: sweep,
  list: list,
  get: get,
  remove: remove
};
