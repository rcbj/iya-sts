// @ts-check
'use strict';
//
// File: cors.js
//
// ===========================================================================
// WHICH BROWSER PAGES MAY READ WHAT THIS SERVICE ANSWERS (2026-09-13).
//
// Until this date `common/app.js` sent `Access-Control-Allow-Origin: *` on
// every response, carving out only `/oauth2/authorize` in RFC 9700 mode. That
// was the right default for a mock whose clients are in-browser pages, and the
// wrong one for an identity provider: a script on ANY origin could read any
// answer this service gave a request that carried no cookie. It is an
// ALLOWLIST now, on every path, and this module is the whole of the decision.
//
// ---------------------------------------------------------------------------
// THE RULE, IN THE ORDER IT IS ASKED.
//
//   1. **RFC 9700 section 2.6** — in that mode `/oauth2/authorize` gets no CORS
//      at all. `oauth-oidc/oauth2_bcp.js`'s `corsForbidden()` decides, as it
//      did before this module existed.
//   2. **THIS SERVICE'S OWN ORIGINS ARE ALWAYS ALLOWED.** The address the
//      request was made to, `global.publicBaseUrl`, the embedded debugger's
//      listener (a separate origin by design, whose pages fetch discovery and
//      JWKS from the main port) and whatever `global.corsOrigins` names. "No
//      third-party origin" was the requirement, and none of these is a third
//      party.
//   3. **A REQUEST THAT NAMES A CLIENT IS JUDGED AGAINST THAT CLIENT ALONE.**
//      Its origin must be listed in the `appCorsOrigin` of the application
//      the name resolves to. A name that resolves to NOTHING — an unknown or
//      mistyped client_id — gets no CORS headers, so a browser page sees a
//      CORS error rather than the protocol's own `invalid_client`. That was
//      asked for explicitly: the alternative is answering an unknown client's
//      origin question with somebody else's list. Several names on one
//      request (a `client_id` in the body AND a Basic credential) must each
//      resolve and each allow the origin.
//   4. **A REQUEST THAT NAMES NO CLIENT IS JUDGED AGAINST THE REALM.** An
//      origin any application in the ambient realm lists is allowed. This is
//      not a loophole in rule 3; it is the only answer for the requests that
//      CANNOT name one — discovery, a JWKS, a DID document, credential issuer
//      metadata — which a browser OpenID Connect library fetches before it
//      has sent a client_id anywhere, and for EVERY PREFLIGHT, which by the
//      Fetch standard carries no body and no Authorization header. A preflight
//      only permits the request to be SENT; the answer to the real request is
//      judged by rule 3 when it names a client.
//
// An empty `appCorsOrigin` everywhere therefore allows no third-party origin
// at all, in BOTH modes. That is not mode-gated, and deliberately: this is not
// a refusal a client under test learns from, it is which pages a browser lets
// read the answer.
//
// ---------------------------------------------------------------------------
// WHAT COUNTS AS NAMING A CLIENT — the whole list, and nothing is inferred
// beyond it:
//
//   * a `client_id` in the query or in a form or JSON body;
//   * the `sub` of an RFC 7523 `client_assertion` in a form body (section 3
//     makes it the client_id);
//   * the path segment of RFC 7592's `/oauth2/register/{client_id}`;
//   * the user name of an HTTP Basic credential (RFC 6749 section 2.3.1), when
//     it resolves to an application — or, on an `/oauth2/` path, whether or
//     not it does. Elsewhere a Basic user name that resolves to no application
//     is a PERSON (SCIM and EST both accept one), and a person is not a client;
//   * the `client_id` — or `azp` — of a JWT access token in `Authorization`
//     (Bearer, DPoP or GNAP), read WITHOUT verifying it;
//   * a GNAP grant request's `client` when it is a string: an instance
//     reference (RFC 9635 section 2.3.1).
//
// **THE ACCESS TOKEN IS NOT VERIFIED HERE, AND THAT IS SAFE RATHER THAN
// CONVENIENT.** A forged `client_id` can only select that client's list, so an
// origin gains nothing it would not get by naming the client in a `client_id`
// parameter; the endpoint verifies the token and refuses it; and no
// `Access-Control-Allow-Credentials` is ever sent, so a browser never exposes
// a CREDENTIALED answer to a page on another origin whatever is echoed.
// Verifying a signature on every cross-origin request to decide a header would
// cost more than the endpoint behind it.
//
// ---------------------------------------------------------------------------
// WHY THE DECISION IS TWO MIDDLEWARES AND NOT ONE.
//
// The preflight has to be answered BEFORE the body parsers only in the sense
// that it has no body; the REAL request has to be decided AFTER them, because a
// `client_id` is usually in the body and the text parser is what reads it. So
// `preflight()` is installed where the `cors` middleware always was and
// `response()` right below the body parsers. Both run in a request worker for a
// dispatched request, for the reason every middleware in app.js does.
//
// A NAVIGATION IS LEFT ALONE. A form post from another origin — a SAML
// HTTP-POST binding, a WS-Federation sign-in response — carries an `Origin`
// header and `Sec-Fetch-Mode: navigate`, and CORS has nothing to say about it:
// the browser shows the answer as a page. Deciding it would only put a
// "withheld" line in the log for every federated sign-in.
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3). It registers no route. It requires `helpers`,
// `config`, `mode`, `validation`, `error_codes`, `applications` and
// `oauth2_bcp` — all but the last already loaded by the time `app.js` requires
// this (the registry through `admin_stats.js`), and `oauth2_bcp` registers no
// route either — and none of which requires this file, so it closes no cycle
// and moves nothing in the route order.
// ===========================================================================

const cors = require('cors');
const helpers = require('./helpers');
const { log } = helpers;
const config = require('./config');
const mode = require('./mode');
const validation = require('./validation');
const errorCodes = require('./error_codes');
const applications = require('./applications');
// For RFC 9700 section 2.6 only; see rule 1 above.
const bcp = require('../oauth-oidc/oauth2_bcp');

// The response headers a page on an allowed origin may READ beyond the
// CORS-safelisted ones. Each is one a browser client of a protocol here has to
// see: a Bearer or DPoP challenge (RFC 6750 section 3, RFC 9470), the DPoP
// nonce (RFC 9449 section 8 — a browser client that cannot read it can never
// retry), an ACME nonce and its links (RFC 8555 sections 6.5 and 7.1), and
// where a created resource is.
const EXPOSED_HEADERS = ['WWW-Authenticate', 'DPoP-Nonce', 'Location', 'Link',
                         'Replay-Nonce', 'Retry-After'];

// Where a request may name the attributes a client's name is looked for in.
const CLIENT_ID_ATTRIBUTES = ['oauthClientId'];
const BASIC_ATTRIBUTES = ['oauthClientId', 'scimClientId'];
const TOKEN_ATTRIBUTES = ['oauthClientId', 'gnapInstanceId'];
const GNAP_INSTANCE_ATTRIBUTES = ['gnapInstanceId'];

// A `global.corsOrigins` value that is not an origin is logged ONCE per value
// rather than per request.
const reportedConfiguredOrigins = new Set();

// ---------------------------------------------------------------------------
// THIS SERVICE'S OWN ORIGINS
// ---------------------------------------------------------------------------

// The origin of an http(s) URL, or ''. `global.publicBaseUrl` is documented as
// having no path, and this reads its origin whatever it carries rather than
// refusing to recognise the service's own address over a trailing segment.
function originOfUrl(url) {
  log.debug("Entering originOfUrl().");
  const text = String(url || '').trim();
  if (!text) {
    log.debug("Leaving originOfUrl(). Empty.");
    return '';
  }
  try {
    const parsed = new URL(text);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      log.debug("Leaving originOfUrl(). Not http(s).");
      return '';
    }
    log.debug("Leaving originOfUrl().");
    return parsed.origin;
  } catch (e) {
    log.debug("Caught in originOfUrl(): " + ((e && e.message) || e));
    // Not a URL, so not this service's address. The caller simply has one
    // origin fewer to compare.
    log.debug("Leaving originOfUrl(). Does not parse.");
    return '';
  }
}

// The host of a Host header without its port: `[::1]` kept bracketed, so it
// can be put straight back into a URL.
function hostnameOf(host) {
  log.debug("Entering hostnameOf().");
  const text = String(host || '').trim().toLowerCase();
  const bracketed = /^(\[[^\]]+\])(?::\d+)?$/.exec(text);
  if (bracketed) {
    log.debug("Leaving hostnameOf(). An IPv6 literal.");
    return bracketed[1];
  }
  log.debug("Leaving hostnameOf().");
  return text.replace(/:\d+$/, '');
}

function configuredOrigins() {
  log.debug("Entering configuredOrigins().");
  const out = [];
  (config.value('global.corsOrigins') || []).forEach(function (value) {
    const origin = validation.normaliseOrigin(String(value));
    if (origin) {
      out.push(origin);
      return;
    }
    if (!reportedConfiguredOrigins.has(value)) {
      reportedConfiguredOrigins.add(value);
      log.warn(errorCodes.tag('STS-HTTP-0023') + 'cors: global.corsOrigins ' +
               'carries "' + value + '", which ' +
               validation.originProblem(String(value)) + '. It is ignored — ' +
               'an origin that does not parse is never widened into one ' +
               'that does.');
    }
  });
  log.debug("Leaving configuredOrigins(). " + out.length + " origin(s).");
  return out;
}

// Every origin this request may come from and still be this service talking to
// itself. See rule 2 in the header.
function ownOrigins(req) {
  log.debug("Entering ownOrigins().");
  const out = [];
  // A hot path: called a dozen times per cross-origin request, so no
  // Entering/Leaving pair — it would drown the log around the one line that
  // matters, and ownOrigins() already brackets it.
  const add = function (origin) {
    if (origin && out.indexOf(origin) < 0) {
      out.push(origin);
    }
  };
  add(originOfUrl(helpers.pinnedBaseUrl()));
  const from = helpers.forwardedFrom(req);
  add(originOfUrl(from.proto + '://' + from.host));
  // The socket's own view as well as the forwarded one: behind a proxy the two
  // differ, and a page served straight from the listener is still this
  // service's own.
  if (req && req.get && req.get('host')) {
    add(originOfUrl((req.protocol || 'http') + '://' + req.get('host')));
  }
  const hostnames = [hostnameOf(from.host)];
  if (req && req.get && req.get('host') &&
      hostnames.indexOf(hostnameOf(req.get('host'))) < 0) {
    hostnames.push(hostnameOf(req.get('host')));
  }
  const scheme = config.value('global.https') ? 'https' : 'http';
  hostnames.filter(function (one) {
    return !!one;
  }).forEach(function (hostname) {
    // The 8443 and 9443 origins were added here until 2026-09-16, when both
    // listeners were deleted. Nothing of this service answers on them, so an
    // origin naming one is no longer this service's own.
    if (mode.embedsProtocolDebugger()) {
      add(originOfUrl(scheme + '://' + hostname + ':' +
                      config.value('debugger.port')));
    }
  });
  if (mode.embedsProtocolDebugger()) {
    add(originOfUrl(config.value('debugger.publicBaseUrl')));
  }
  configuredOrigins().forEach(add);
  log.debug("Leaving ownOrigins(). " + out.length + " origin(s).");
  return out;
}

// ---------------------------------------------------------------------------
// THE CLIENTS A REQUEST NAMES
// ---------------------------------------------------------------------------

// A JWT's payload, unverified, or null. A JWE (five segments) has nothing
// readable in it and is not a token naming anybody here.
function unverifiedClaims(token) {
  log.debug("Entering unverifiedClaims().");
  const parts = String(token || '').split('.');
  if (parts.length !== 3) {
    log.debug("Leaving unverifiedClaims(). Not a JWS.");
    return null;
  }
  try {
    const claims = helpers.jsonFromB64u(parts[1]);
    log.debug("Leaving unverifiedClaims().");
    return (claims && typeof claims === 'object') ? claims : null;
  } catch (e) {
    log.debug("Caught in unverifiedClaims(): " + ((e && e.message) || e));
    // A payload that is not JSON names no client; the endpoint is where the
    // token is refused for it.
    log.debug("Leaving unverifiedClaims(). Not JSON.");
    return null;
  }
}

// The form or JSON body as an object of arrays, or {}. Read here rather than
// through `helpers.parseBody()`, which LOGS AN ERROR for a body that is not the
// JSON its type says — right for an endpoint, and a second error line for the
// same request when asked by a header decision.
function bodyParameters(req) {
  log.debug("Entering bodyParameters().");
  const raw = typeof req.body === 'string' ? req.body : '';
  const type = String((req.headers && req.headers['content-type']) || '');
  if (!raw) {
    log.debug("Leaving bodyParameters(). No text body.");
    return {};
  }
  if (/json/i.test(type)) {
    try {
      const parsed = JSON.parse(raw);
      log.debug("Leaving bodyParameters(). JSON.");
      return (parsed && typeof parsed === 'object' &&
              !Array.isArray(parsed)) ? parsed : {};
    } catch (e) {
      log.debug("Caught in bodyParameters(): " + ((e && e.message) || e));
      // Not JSON: it names nobody, and the endpoint says what is wrong with it.
      log.debug("Leaving bodyParameters(). Not JSON.");
      return {};
    }
  }
  if (/^application\/x-www-form-urlencoded/i.test(type)) {
    const out = {};
    new URLSearchParams(raw).forEach(function (value, key) {
      (out[key] = out[key] || []).push(value);
    });
    log.debug("Leaving bodyParameters(). A form.");
    return out;
  }
  log.debug("Leaving bodyParameters(). Neither a form nor JSON.");
  return {};
}

function stringsOf(value) {
  log.debug("Entering stringsOf().");
  const list = Array.isArray(value) ? value : [value];
  log.debug("Leaving stringsOf().");
  return list.filter(function (one) {
    return typeof one === 'string' && one.trim().length > 0;
  }).map(function (one) {
    return one.trim();
  });
}

// `[{ name, attributes, where, optional }]`. `optional` marks the one kind of
// name that counts only when it resolves: a Basic user name off an OAuth path.
function namedClients(req) {
  log.debug("Entering namedClients().");
  const path = String(req.path || '');
  const oauthPath = /(^|\/)oauth2(\/|$)/.test(path);
  const names = [];
  // A hot path, for ownOrigins()'s `add` reason: no Entering/Leaving pair.
  const add = function (name, attributes, where, optional) {
    const already = names.some(function (one) {
      return one.name === name && one.attributes === attributes;
    });
    if (!already) {
      names.push({ name: name, attributes: attributes, where: where,
                   optional: !!optional });
    }
  };
  stringsOf(req.query && req.query.client_id).forEach(function (name) {
    add(name, CLIENT_ID_ATTRIBUTES, 'the client_id query parameter');
  });
  const body = bodyParameters(req);
  stringsOf(body.client_id).forEach(function (name) {
    add(name, CLIENT_ID_ATTRIBUTES, 'the client_id in the body');
  });
  stringsOf(body.client_assertion).forEach(function (assertion) {
    const claims = unverifiedClaims(assertion);
    stringsOf(claims && claims.sub).forEach(function (name) {
      add(name, CLIENT_ID_ATTRIBUTES, 'the client assertion\'s sub');
    });
  });
  if (/(^|\/)gnap$/.test(path)) {
    stringsOf(body.client).forEach(function (name) {
      add(name, GNAP_INSTANCE_ATTRIBUTES, 'the GNAP instance reference');
    });
  }
  const registration = /(?:^|\/)oauth2\/register\/([^/]+)$/.exec(path);
  if (registration) {
    try {
      add(decodeURIComponent(registration[1]), CLIENT_ID_ATTRIBUTES,
          'the registration path');
    } catch (e) {
      log.debug("Caught in namedClients(): " + ((e && e.message) || e));
      // A malformed percent-encoding names nobody; the endpoint answers 404.
    }
  }
  const authorization = String((req.headers &&
                                req.headers.authorization) || '').trim();
  const basic = /^Basic\s+(\S+)$/i.exec(authorization);
  if (basic) {
    const decoded = Buffer.from(basic[1], 'base64').toString('utf8');
    const colon = decoded.indexOf(':');
    if (colon > 0) {
      let user = decoded.slice(0, colon);
      try {
        user = decodeURIComponent(user.replace(/\+/g, ' '));
      } catch (e) {
        log.debug("Caught in namedClients(): " + ((e && e.message) || e));
        // RFC 6749 section 2.3.1 form-encodes the name; one that does not
        // decode is compared as sent.
      }
      if (user) {
        add(user, BASIC_ATTRIBUTES, 'the Basic user name', !oauthPath);
      }
    }
  }
  const token = /^(?:Bearer|DPoP|GNAP)\s+(\S+)$/i.exec(authorization);
  if (token) {
    const claims = unverifiedClaims(token[1]);
    const name = stringsOf(claims && (claims.client_id || claims.azp))[0];
    if (name) {
      add(name, TOKEN_ATTRIBUTES, 'the access token\'s client_id');
    }
  }
  log.debug("Leaving namedClients(). " + names.length + " name(s).");
  return names;
}

// ---------------------------------------------------------------------------
// THE DECISION
// ---------------------------------------------------------------------------

// `{ allowed, origin, code, why }`. `code` is set on a withheld decision about
// a cross-origin request, and is what the log line carries.
function decide(req, options) {
  log.debug("Entering decide().");
  const opts = options || {};
  const header = String((req.headers && req.headers.origin) || '').trim();
  if (!header) {
    log.debug("Leaving decide(). No Origin header.");
    return { allowed: false, origin: '', code: '', why: 'not cross-origin' };
  }
  if (bcp.corsForbidden(req)) {
    log.debug("Leaving decide(). RFC 9700 section 2.6.");
    return { allowed: false, origin: header, code: '',
             why: 'RFC 9700 section 2.6 withholds CORS from the ' +
                  'authorization endpoint' };
  }
  const origin = validation.normaliseOrigin(header);
  if (!origin) {
    log.debug("Leaving decide(). The Origin header is not an origin.");
    return { allowed: false, origin: header,
             code: opts.preflight ? 'STS-HTTP-0019' : 'STS-HTTP-0020',
             why: 'the Origin "' + header + '" ' +
                  validation.originProblem(header) };
  }
  if (ownOrigins(req).indexOf(origin) >= 0) {
    log.debug("Leaving decide(). This service's own origin.");
    return { allowed: true, origin: origin, code: '',
             why: 'this service\'s own origin' };
  }
  const names = opts.preflight ? [] : namedClients(req);
  const resolved = names.map(function (one) {
    return Object.assign({ found: applications.corsOriginsForClient(
        one.name, one.attributes) }, one);
  }).filter(function (one) {
    return one.found.known || !one.optional;
  });
  if (!resolved.length) {
    const union = applications.corsOriginsOfRealm();
    if (union.indexOf(origin) >= 0) {
      log.debug("Leaving decide(). Listed in the realm.");
      return { allowed: true, origin: origin, code: '',
               why: 'no client named, and an application in the realm ' +
                    'lists it' };
    }
    log.debug("Leaving decide(). Listed by no application.");
    return { allowed: false, origin: origin,
             code: opts.preflight ? 'STS-HTTP-0019' : 'STS-HTTP-0020',
             why: 'no application in the realm lists ' + origin +
                  ' in appCorsOrigin' + (opts.preflight ? '' :
                                         ', and the request named no client') };
  }
  const unknown = resolved.filter(function (one) {
    return !one.found.known;
  })[0];
  if (unknown) {
    log.debug("Leaving decide(). An unknown client.");
    return { allowed: false, origin: origin, code: 'STS-HTTP-0021',
             why: unknown.where + ' names "' + unknown.name + '", which no ' +
                  'application in the realm answers to' };
  }
  const refusing = resolved.filter(function (one) {
    return one.found.origins.indexOf(origin) < 0;
  })[0];
  if (refusing) {
    log.debug("Leaving decide(). The named client does not list it.");
    return { allowed: false, origin: origin, code: 'STS-HTTP-0022',
             why: 'the application "' + refusing.found.identifier + '" (' +
                  refusing.where + ') does not list ' + origin +
                  ' in appCorsOrigin' };
  }
  log.debug("Leaving decide(). Every named client lists it.");
  return { allowed: true, origin: origin, code: '',
           why: 'listed by ' + resolved.map(function (one) {
             return one.found.identifier;
           }).join(', ') };
}

function isNavigation(req) {
  log.debug("Entering isNavigation().");
  const fetchMode = String((req.headers &&
                            req.headers['sec-fetch-mode']) || '');
  log.debug("Leaving isNavigation().");
  return fetchMode === 'navigate' || fetchMode === 'nested-navigate';
}

// ---------------------------------------------------------------------------
// THE TWO MIDDLEWARES
// ---------------------------------------------------------------------------

// **GNAP'S DISCOVERY IS AN OPTIONS REQUEST (2026-09-12).** RFC 9635 section 9
// has a client "send an HTTP OPTIONS request to the grant request endpoint" and
// the AS "MUST respond with a JSON document". A preflight answered here would
// be a 204 with no body before the GNAP route ever ran, so OPTIONS on a grant
// endpoint CONTINUES to the route whatever the decision — carrying the CORS
// headers when the origin is allowed, which makes the discovery document a
// valid preflight answer as well.
function continuesToRoute(req) {
  log.debug("Entering continuesToRoute().");
  log.debug("Leaving continuesToRoute().");
  return /(^|\/)gnap$/.test(String(req.path || ''));
}

// Every OPTIONS request. Registered as `app.use()` above the body parsers and
// again as the `app.options('*')` route `/admin/sts-metadata` lists; the second
// only ever runs for the GNAP case above, and passes a request the first has
// already decided straight on — deciding again would log a refused origin
// twice for one request.
const PREFLIGHT_DECIDED = Symbol('cors.preflightDecided');

function preflight() {
  log.debug("Entering preflight().");
  // A hot path — every OPTIONS request in the service passes through it, and
  // every other request returns from its first line — so no Entering/Leaving
  // pair, which would drown the log; decide() records what it decided.
  const handler = function (req, res, next) {
    if (req.method !== 'OPTIONS' || req[PREFLIGHT_DECIDED]) {
      next();
      return;
    }
    req[PREFLIGHT_DECIDED] = true;
    res.vary('Origin');
    const decision = decide(req, { preflight: true });
    const onward = continuesToRoute(req);
    if (decision.allowed) {
      cors({ origin: decision.origin, preflightContinue: onward,
             exposedHeaders: EXPOSED_HEADERS })(req, res, next);
      return;
    }
    if (decision.code) {
      log.info(errorCodes.tag(decision.code) + 'cors: the preflight for ' +
               req.method + ' ' + req.path + ' from ' + decision.origin +
               ' was answered without CORS headers — ' + decision.why + '.');
    }
    if (onward) {
      next();
      return;
    }
    // Answered here rather than left to fall through, so an OPTIONS with no
    // Origin is still the 204 it always was and a refused preflight is not a
    // 404 that reads as a missing endpoint.
    if (decision.code) {
      errorCodes.mark(res, decision.code);
    }
    res.statusCode = 204;
    res.setHeader('Content-Length', '0');
    res.end();
  };
  log.debug("Leaving preflight().");
  return handler;
}

// Every other request, BELOW the body parsers. It never refuses anything: an
// endpoint answers exactly as before, and the header decides whether a page on
// another origin may read the answer.
function response() {
  log.debug("Entering response().");
  // A hot path — every request in the service passes through it — so no
  // Entering/Leaving pair, which would drown the log; decide() records what
  // it decided for the cross-origin ones.
  const handler = function (req, res, next) {
    if (req.method === 'OPTIONS') {
      next();
      return;
    }
    res.vary('Origin');
    if (!req.headers.origin || isNavigation(req)) {
      next();
      return;
    }
    const decision = decide(req, { preflight: false });
    if (decision.allowed) {
      res.setHeader('Access-Control-Allow-Origin', decision.origin);
      res.setHeader('Access-Control-Expose-Headers',
                    EXPOSED_HEADERS.join(', '));
    } else if (decision.code) {
      log.info(errorCodes.tag(decision.code) + 'cors: ' + req.method + ' ' +
               req.path + ' from ' + decision.origin + ' is answered ' +
               'without Access-Control-Allow-Origin — ' + decision.why + '.');
    }
    next();
  };
  log.debug("Leaving response().");
  return handler;
}

module.exports = {
  preflight: preflight,
  response: response,
  // For `tests/cors.js`, which drives the decision without a socket.
  decide: decide,
  namedClients: namedClients,
  ownOrigins: ownOrigins,
  EXPOSED_HEADERS: EXPOSED_HEADERS
};
