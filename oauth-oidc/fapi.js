// @ts-check
'use strict';
//
// File: fapi.js
//
// ===========================================================================
// THE FAPI PROFILES, AS A MODE (#138, 2026-09-22).
//
// FAPI 1.0 Part 1: Baseline (final, 2021-03-12) came first (#138), FAPI 1.0
// Part 2: Advanced (final) second (#139); #140 adds the FAPI 2.0 Security
// Profile and #141 FAPI 2.0 Message Signing, each as another value of the ONE
// switch:
//
//   oauth2.fapi = 'off' | '1-baseline' | '1-advanced'
//
// ADVANCED IS BASELINE AND MORE. Part 2 section 5.2.2 opens "the authorization
// server shall support the provisions specified in clause 5.2.2 of Financial-
// grade API Security Profile 1.0 - Part 1: Baseline, except that Section
// 5.2.2-7 (enforcement of RFC7636) is not required" — so every Baseline check
// below asks `enabled()`, the Advanced ones ask `advanced()`, and PKCE is the
// one Baseline rule Advanced relaxes: it is required only of a PUSHED request
// (item 18).
//
// a realm-runtime setting (a trust realm may carry it while the process does
// not), and a NAMED AUTHORIZATION SERVER may carry its own value in its
// profile (the `fapi` member of `authorization_servers.ts`, which is published
// in no document). So one realm can host a FAPI server at `/{id}/oauth2/…`
// beside an ordinary one — rcbj's decision on #138.
//
// **ANY FAPI PROFILE IMPLIES RFC 9700 MODE**, as `oauth2.oauth21` does:
// `oauth2_bcp.js`'s `enabled()` answers true while this does. FAPI 1.0 predates
// RFC 9700 and most of what it asks is already a row there — exact redirect
// matching, S256 only, a replayed code refused with its tokens revoked, `iss`
// on every response, no token from the authorization endpoint's query. So this
// file holds what FAPI asks BEYOND that mode, and GET /oauth2/fapi lists both.
//
// ---------------------------------------------------------------------------
// WHY THE PROFILE IS AMBIENT, NOT PASSED.
//
// RFC 9700 mode's `enabled()` is asked from a dozen places that have no
// request in hand, because a realm is ambient and that was enough. A named
// authorization server is not a realm: it is chosen by a path segment. So the
// request's profile is made ambient the same way — `oauth2.ts`'s `forProfile()`
// runs every `/{id}/oauth2/…` handler inside `withProfile()` with that
// server's value — and `enabled()` reads the ambient value first and the
// realm's setting second. A server with no value of its own follows its
// realm; one with `off` opts out of a realm-wide profile.
//
// ---------------------------------------------------------------------------
// IT IS A LEAF (rule 3). It requires `helpers.js` and `config.js` and nothing
// else; `oauth2_bcp.js`, `common/consent.ts` and `oauth2.ts` require IT, so it
// must never require any of them back. Every record it decides about is
// passed in. A refusal is `{ ok: false, errorCode, error, requirement,
// description }`, `oauth2_bcp.js`'s shape, and the caller chooses the wire.
// ===========================================================================

const { AsyncLocalStorage } = require('async_hooks');
const { log } = require('../common/helpers');
const config = require('../common/config');

// The profiles this service implements, in the order the specifications were
// published. #139–#141 add theirs here.
const PROFILES = ['1-baseline', '1-advanced'];
const ADVANCED = '1-advanced';

// The switch's own "no profile", and what a named authorization server may
// say to be NOT a FAPI server even though its realm is.
const NONE = 'off';

const BASELINE = 'FAPI 1.0 Part 1: Baseline Security Profile (final)';
const BASELINE_URL =
  'https://openid.net/specs/openid-financial-api-part-1-1_0.html';
const ADVANCED_NAME = 'FAPI 1.0 Part 2: Advanced Security Profile (final)';
const ADVANCED_URL =
  'https://openid.net/specs/openid-financial-api-part-2-1_0.html';

// The confidential client authentication methods Baseline section 5.2.2
// item 4 allows: RFC 8705's two, and OIDC Core section 9's two JWT ones.
const BASELINE_METHODS = ['tls_client_auth', 'self_signed_tls_client_auth',
                          'private_key_jwt', 'client_secret_jwt'];

// Part 2 section 5.2.2 item 14: no client_secret_jwt, and (item 16) no public
// client.
const ADVANCED_METHODS = ['tls_client_auth', 'self_signed_tls_client_auth',
                          'private_key_jwt'];

// Part 2 section 5.2.2 item 2: `code id_token`, or `code` with JARM.
const ADVANCED_RESPONSE_TYPES = ['code id_token', 'code'];

// Part 2 section 8.6: "shall use PS256 or ES256" for every JWS, both ends; and
// 8.6.1: never RSA1_5.
const ADVANCED_SIGNING_ALGS = ['PS256', 'ES256'];
const ADVANCED_DEFAULT_SIGNING_ALG = 'PS256';
const FORBIDDEN_ENCRYPTION_ALGS = ['RSA1_5'];

// The registration members that name a JWS algorithm this server or the client
// signs with, all of which section 8.6 holds to ADVANCED_SIGNING_ALGS.
const SIGNING_ALG_MEMBERS = ['id_token_signed_response_alg',
  'userinfo_signed_response_alg', 'request_object_signing_alg',
  'token_endpoint_auth_signing_alg', 'authorization_signed_response_alg',
  'introspection_signed_response_alg'];
const ENCRYPTION_ALG_MEMBERS = ['id_token_encrypted_response_alg',
  'userinfo_encrypted_response_alg', 'request_object_encryption_alg',
  'authorization_encrypted_response_alg',
  'introspection_encrypted_response_alg'];
// The metadata lists section 8.6 narrows.
const SIGNING_ALG_LISTS = ['id_token_signing_alg_values_supported',
  'userinfo_signing_alg_values_supported',
  'request_object_signing_alg_values_supported',
  'token_endpoint_auth_signing_alg_values_supported',
  'authorization_signing_alg_values_supported',
  'introspection_signing_alg_values_supported',
  'revocation_endpoint_auth_signing_alg_values_supported',
  'introspection_endpoint_auth_signing_alg_values_supported'];
const ENCRYPTION_ALG_LISTS = ['id_token_encryption_alg_values_supported',
  'userinfo_encryption_alg_values_supported',
  'request_object_encryption_alg_values_supported',
  'authorization_encryption_alg_values_supported',
  'introspection_encryption_alg_values_supported'];

// Part 2 section 5.2.2 items 13 and 17: a request object's lifetime and age.
const MAX_REQUEST_OBJECT_LIFETIME_S = 3600;
const MAX_REQUEST_OBJECT_AGE_S = 3600;

// Section 5.2.2 items 5 and 6.
const MIN_RSA_BITS = 2048;
const MIN_EC_BITS = 160;

// Section 5.2.2 item 21: "should issue access tokens with a lifetime of under
// 10 minutes unless the tokens are sender-constrained". A SHOULD, enforced as
// a cap here — the stricter reading, per rcbj's standing rule.
const MAX_UNBOUND_ACCESS_TOKEN_S = 600;

// ---------------------------------------------------------------------------
// WHAT FAPI 1.0 BASELINE ASKS OF THE AUTHORIZATION SERVER, row by row.
// `enforced` is 'yes', 'inherited' (RFC 9700 mode enforces it, and this
// profile turns that mode on), 'already' (true of this service whatever the
// setting) or 'no' with the reason in `note`.
// ---------------------------------------------------------------------------
const REQUIREMENTS = [
  { id: 'implies-rfc9700', section: '5.2.2', level: 'SHALL',
    enforced: 'inherited',
    title: 'RFC 9700 mode is on under every FAPI profile',
    note: 'Exact redirect matching (items 8-10), S256 only (item 7), a ' +
          'reused code refused (item 13), iss on every response — GET ' +
          '/oauth2/rfc9700 lists what that mode enforces.' },
  { id: 'confidential-client-auth', section: '5.2.2 item 4', level: 'SHALL',
    enforced: 'yes',
    title: 'A confidential client authenticates with mTLS, private_key_jwt ' +
           'or client_secret_jwt',
    note: 'client_secret_basic and client_secret_post are refused at ' +
          'registration and at the token and PAR endpoints ' +
          '(STS-OAUTH-0580, STS-REG-0174).' },
  { id: 'key-sizes', section: '5.2.2 items 5-6', level: 'SHALL',
    enforced: 'yes',
    title: 'RSA keys of 2048 bits or more, EC keys of 160 or more',
    note: 'A registration whose jwks holds a smaller key is refused ' +
          '(STS-REG-0175). This service\'s own keys already meet it.' },
  { id: 'pkce-s256', section: '5.2.2 item 7', level: 'SHALL',
    enforced: 'yes',
    title: 'PKCE with S256, for every client',
    note: 'RFC 9700 mode allows only S256 when PKCE is used; this profile ' +
          'requires it of confidential clients too (STS-OAUTH-0573).' },
  { id: 'redirect-uri', section: '5.2.2 items 8-10, 20', level: 'SHALL',
    enforced: 'yes',
    title: 'redirect_uri pre-registered, sent, exactly matched, and https',
    note: 'Matching is RFC 9700 mode\'s; sending it and https are this ' +
          'profile\'s (STS-OAUTH-0574, STS-REG-0176).' },
  { id: 'explicit-consent', section: '5.2.2 item 12', level: 'SHALL',
    enforced: 'yes',
    title: 'The user approves the scope explicitly unless previously ' +
           'authorized',
    note: 'The consent screen is in force whatever oauth2.consentRequired ' +
          'says, and an administrator\'s global consent does not count as ' +
          'the user\'s approval — this service\'s own console and portal ' +
          'included (rcbj\'s decision on #138).' },
  { id: 'code-single-use', section: '5.2.2 item 13', level: 'SHALL',
    enforced: 'inherited',
    title: 'A previously used authorization code is rejected',
    note: 'RFC 9700 mode\'s code-single-use, which also revokes what the ' +
          'code issued.' },
  { id: 'granted-scope', section: '5.2.2 item 15', level: 'SHALL',
    enforced: 'already',
    title: 'The granted scope is returned with the access token',
    note: 'Every token response carries scope, in every mode.' },
  { id: 'client-id-mismatch', section: '5.2.2 item 19', level: 'SHALL',
    enforced: 'yes',
    title: 'invalid_client when the client is identified two different ways',
    note: 'A Basic header, the body\'s client_id and a client assertion\'s ' +
          'sub must all name one client (STS-OAUTH-0581). Outside the ' +
          'profile the Basic header wins and the body\'s is ignored.' },
  { id: 'access-token-lifetime', section: '5.2.2 item 21', level: 'SHOULD',
    enforced: 'yes',
    title: 'Access tokens live under 10 minutes unless sender-constrained',
    note: 'An access token with no cnf is issued for at most 600 seconds.' },
  { id: 'nonce-with-openid', section: '5.2.2.2', level: 'SHALL',
    enforced: 'yes',
    title: 'nonce is required whenever openid is requested',
    note: 'RFC 9700 mode requires it only for a response type that returns ' +
          'an ID Token from the authorization endpoint (STS-OAUTH-0575).' },
  { id: 'state-without-openid', section: '5.2.2.3', level: 'SHALL',
    enforced: 'yes',
    title: 'state is required when openid is not requested',
    note: 'STS-OAUTH-0576.' },
  { id: 'loa', section: '5.2.2 item 11', level: 'SHALL', enforced: 'already',
    title: 'User authentication at an appropriate level of assurance',
    note: 'acr_values, max_age and an essential acr claim are honoured in ' +
          'every mode (RFC 9470 step-up, #118).' },
  { id: 'entropy', section: '5.2.2 item 16', level: 'SHALL',
    enforced: 'already',
    title: 'Tokens and codes are not guessable',
    note: 'Codes are 24 random identifier characters; tokens are signed ' +
          'JWTs with random jti.' },
  { id: 'symmetric-secret', section: '5.2.2 item 3', level: 'SHALL',
    enforced: 'already',
    title: 'A client secret used as a key meets OIDC Core section 16.19',
    note: 'Secrets are generated by this service, never chosen by a client.' },
  { id: 'discovery', section: '5.2.2 item 22', level: 'SHALL',
    enforced: 'already',
    title: 'OpenID Connect Discovery is supported',
    note: 'And RFC 8414, which the item allows.' },
  { id: 'revocation', section: '5.2.2 item 18', level: 'SHOULD',
    enforced: 'already',
    title: 'The end user can revoke tokens granted to a client',
    note: '/portal/applications and the global sign-out.' }
];

// ---------------------------------------------------------------------------
// WHAT FAPI 1.0 ADVANCED ASKS BEYOND BASELINE, row by row (Part 2 section
// 5.2.2 and 8.6). Under `1-advanced` GET /oauth2/fapi lists both tables, and
// the Baseline row `pkce-s256` reads as relaxed to pushed requests.
// ---------------------------------------------------------------------------
const ADVANCED_REQUIREMENTS = [
  { id: 'signed-request-object', section: '5.2.2 item 1', level: 'SHALL',
    enforced: 'yes',
    title: 'A JWS-signed request object, by value or by reference',
    note: 'An unsigned or absent request object is refused (RFC 9101, ' +
          'STS-OAUTH-0340 / 0357); a push must carry `request` ' +
          '(STS-OAUTH-0415).' },
  { id: 'response-type', section: '5.2.2 item 2', level: 'SHALL',
    enforced: 'yes',
    title: 'code id_token, or code with response_mode=jwt (JARM)',
    note: 'STS-OAUTH-0582. JARM is implemented for every response mode ' +
          '(query.jwt, fragment.jwt, form_post.jwt, jwt), in every profile.' },
  { id: 'detached-signature', section: '5.2.2.1', level: 'SHALL',
    enforced: 'yes',
    title: 'The ID Token is a detached signature carrying s_hash',
    note: 'c_hash and, where the client sent state, s_hash — both with the ' +
          'hash of the ID Token\'s own alg. s_hash is added in every mode.' },
  { id: 'sender-constrained', section: '5.2.2 items 5-6', level: 'SHALL',
    enforced: 'yes',
    title: 'Only sender-constrained access tokens; mTLS supported',
    note: 'A token request that would mint an unconstrained access token is ' +
          'refused (STS-OAUTH-0583). DPoP counts unless ' +
          'oauth2.fapiRequireMtls is on (rcbj\'s decision on #139); ' +
          'mtls_endpoint_aliases is published where the port is TLS.' },
  { id: 'parameters-from-object', section: '5.2.2 item 10', level: 'SHALL',
    enforced: 'already',
    title: 'Only parameters inside the signed request object are used',
    note: 'RFC 9101 section 6.3: the object replaces the query.' },
  { id: 'request-object-lifetime', section: '5.2.2 items 13, 17',
    level: 'SHALL', enforced: 'yes',
    title: 'exp and nbf required; exp at most 60 minutes after nbf; nbf at ' +
           'most 60 minutes old',
    note: 'STS-OAUTH-0584.' },
  { id: 'client-auth', section: '5.2.2 item 14', level: 'SHALL',
    enforced: 'yes',
    title: 'tls_client_auth, self_signed_tls_client_auth or private_key_jwt',
    note: 'client_secret_jwt is refused too (STS-OAUTH-0580, STS-REG-0174).' },
  { id: 'request-object-aud', section: '5.2.2 item 15', level: 'SHALL',
    enforced: 'yes',
    title: 'The request object\'s aud is the issuer',
    note: 'STS-OAUTH-0585.' },
  { id: 'no-public-clients', section: '5.2.2 item 16', level: 'SHALL',
    enforced: 'yes',
    title: 'Public clients are not supported',
    note: 'token_endpoint_auth_method none is refused at registration and ' +
          'at the token and PAR endpoints.' },
  { id: 'par-pkce', section: '5.2.2 item 18', level: 'SHALL',
    enforced: 'yes',
    title: 'A pushed request uses PKCE with S256',
    note: 'STS-OAUTH-0573, for pushed requests only.' },
  { id: 'algorithms', section: '8.6, 8.6.1', level: 'SHALL', enforced: 'yes',
    title: 'PS256 or ES256 for every JWS; never RSA1_5',
    note: 'This server signs with PS256 by default under the profile (ID ' +
          'Token, access token, UserInfo, JARM, introspection); a client ' +
          'algorithm outside the two is refused (STS-OAUTH-0586, ' +
          'STS-REG-0177), and the metadata lists are narrowed to match.' }
];

// The ambient profile of the request being answered: the named
// authorization server's own value, when `oauth2.ts` set one.
const ambient = new AsyncLocalStorage();

// Whether `value` is something the switch accepts.
function known(value) {
  log.debug("Entering known().");
  const text = String(value || '');
  log.debug("Leaving known().");
  return text === '' || text === NONE || PROFILES.indexOf(text) >= 0;
}

// Runs `fn` with `value` as the request's FAPI profile — a named
// authorization server's own. An empty value leaves the realm's in force.
function withProfile(value, fn) {
  log.debug("Entering withProfile(). " + (value || '(the realm\'s)'));
  log.debug("Leaving withProfile().");
  return ambient.run({ profile: String(value || '') }, fn);
}

// The FAPI profile in force: the named authorization server's, then the
// realm's (or the process's) setting. '' when none.
function profile() {
  log.debug("Entering profile().");
  const held = ambient.getStore();
  const own = held && held.profile ? String(held.profile) : '';
  if (own === NONE) {
    log.debug("Leaving profile(). This server opts out.");
    return '';
  }
  const value = own || String(config.value('oauth2.fapi') || '');
  log.debug("Leaving profile(). " + (value || '(none)'));
  return PROFILES.indexOf(value) >= 0 ? value : '';
}

function enabled() {
  log.debug("Entering enabled().");
  const on = profile() !== '';
  log.debug("Leaving enabled(). " + on);
  return on;
}

// Whether FAPI 1.0 Advanced is in force.
function advanced() {
  log.debug("Entering advanced().");
  const on = profile() === ADVANCED;
  log.debug("Leaving advanced(). " + on);
  return on;
}

// The name of the profile in force, for a refusal's sentence.
function profileName() {
  log.debug("Entering profileName().");
  log.debug("Leaving profileName().");
  return advanced() ? ADVANCED_NAME : BASELINE;
}

function refusal(errorCode, error, requirement, description) {
  log.debug("Entering refusal(). " + requirement);
  log.debug("Leaving refusal().");
  return { ok: false, errorCode: errorCode, error: error,
           requirement: requirement,
           description: description + ' (' + profileName() + ', ' +
             'oauth2.fapi=' + profile() + ').' };
}

// Whether a redirect URI is https — Baseline item 20 names no loopback
// exception.
function httpsUri(uri) {
  log.debug("Entering httpsUri().");
  let ok = false;
  try {
    ok = new URL(String(uri)).protocol === 'https:';
  } catch (e) {
    log.debug("Caught in httpsUri(): " + ((e && e.message) || e));
    // Not a URL: not an https one.
    ok = false;
  }
  log.debug("Leaving httpsUri(). " + ok);
  return ok;
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION REQUEST (and a pushed one, which the same vetting reads).
// `query` is the request's parameters; `context.pushed` whether it arrived by
// PAR — the one thing Advanced's PKCE rule turns on.
// ---------------------------------------------------------------------------
function authorizationRefusal(query, context) {
  log.debug("Entering authorizationRefusal().");
  if (!enabled()) {
    log.debug("Leaving authorizationRefusal(). Off.");
    return null;
  }
  const q = query || {};
  const ctx = context || {};
  const scopes = String(q.scope || '').split(/\s+/);
  if (!q.redirect_uri) {
    log.debug("Leaving authorizationRefusal(). No redirect_uri.");
    return refusal('STS-OAUTH-0574', 'invalid_request', 'redirect-uri',
                   'redirect_uri is required in the authorization request ' +
                   '(section 5.2.2 item 9)');
  }
  if (!httpsUri(q.redirect_uri)) {
    log.debug("Leaving authorizationRefusal(). Not https.");
    return refusal('STS-OAUTH-0574', 'invalid_request', 'redirect-uri',
                   'redirect_uri must use the https scheme (section 5.2.2 ' +
                   'item 20)');
  }
  // Baseline item 7 for every client; Advanced relaxes it to a pushed request
  // (Part 2 section 5.2.2's exception, and item 18). A challenge that IS sent
  // is still held to S256 under both.
  const pkceAsked = !advanced() || !!ctx.pushed;
  const challenged = !!q.code_challenge;
  if ((pkceAsked && !challenged) ||
      (challenged && q.code_challenge_method !== 'S256')) {
    log.debug("Leaving authorizationRefusal(). No S256 challenge.");
    return refusal('STS-OAUTH-0573', 'invalid_request', 'pkce-s256',
                   'a code_challenge with code_challenge_method=S256 is ' +
                   'required ' + (advanced() ? 'of a pushed request ' +
                   '(Part 2 section 5.2.2 item 18)'
                                            : 'of every client (section ' +
                   '5.2.2 item 7)'));
  }
  if (advanced()) {
    const type = responseTypeOf(q.response_type);
    const jarm = JARM_MODES.indexOf(String(q.response_mode || '')) >= 0;
    if (!(type === 'code id_token' || (type === 'code' && jarm))) {
      log.debug("Leaving authorizationRefusal(). A response type Advanced " +
                "does not allow.");
      return refusal('STS-OAUTH-0582', 'unsupported_response_type',
                     'response-type',
                     'response_type "' + String(q.response_type || '') +
                     '"' + (q.response_mode ? ' with response_mode "' +
                     q.response_mode + '"' : '') + ' is not one this ' +
                     'profile allows: it is `code id_token`, or `code` ' +
                     'with response_mode=jwt (JARM) (Part 2 section 5.2.2 ' +
                     'item 2)');
    }
  }
  if (scopes.indexOf('openid') >= 0 && !q.nonce) {
    log.debug("Leaving authorizationRefusal(). No nonce.");
    return refusal('STS-OAUTH-0575', 'invalid_request', 'nonce-with-openid',
                   'nonce is required when openid is requested (section ' +
                   '5.2.2.2)');
  }
  if (scopes.indexOf('openid') < 0 && !q.state) {
    log.debug("Leaving authorizationRefusal(). No state.");
    return refusal('STS-OAUTH-0576', 'invalid_request',
                   'state-without-openid',
                   'state is required when openid is not requested ' +
                   '(section 5.2.2.3)');
  }
  log.debug("Leaving authorizationRefusal(). Allowed.");
  return null;
}

// A response_type with its values in a fixed order, so that `id_token code`
// is `code id_token`.
function responseTypeOf(value) {
  log.debug("Entering responseTypeOf().");
  const words = String(value || '').split(/\s+/).filter(Boolean).sort();
  log.debug("Leaving responseTypeOf().");
  return words.join(' ');
}

// JARM's response modes (JARM section 2.3). Kept here as well as in
// `jarm.ts` because this file is a leaf that may require nothing.
const JARM_MODES = ['jwt', 'query.jwt', 'fragment.jwt', 'form_post.jwt'];

// ---------------------------------------------------------------------------
// SECTION 5.2.2 ITEM 19: every client identifier one request carries — the
// Basic header's, the body's client_id, a client assertion's sub — must be the
// same one. `ids` is what the endpoint read, empty strings for absent ones.
// ---------------------------------------------------------------------------
function clientIdentifierRefusal(ids) {
  log.debug("Entering clientIdentifierRefusal().");
  const named = (ids || []).map(String).filter(function (one) {
    return one !== '';
  });
  const distinct = named.filter(function (one, i) {
    return named.indexOf(one) === i;
  });
  if (!enabled() || distinct.length < 2) {
    log.debug("Leaving clientIdentifierRefusal(). One client.");
    return null;
  }
  log.debug("Leaving clientIdentifierRefusal(). Several.");
  return refusal('STS-OAUTH-0581', 'invalid_client', 'client-id-mismatch',
                 'this request names ' + distinct.length + ' different ' +
                 'clients (' + distinct.map(function (one) {
                   return '"' + one + '"';
                 }).join(', ') + ') in the ways it identifies one (section ' +
                 '5.2.2 item 19)');
}

// ---------------------------------------------------------------------------
// THE CLIENT'S AUTHENTICATION at the token and PAR endpoints. `method` is
// what the client's entry declares (`bcp.observeClientAuthentication()`'s
// `method`); `none` is a public client, which section 5.2.3 allows.
// ---------------------------------------------------------------------------
function clientAuthenticationRefusal(method) {
  log.debug("Entering clientAuthenticationRefusal(). " + method);
  const used = String(method || '');
  if (!enabled() || !used) {
    log.debug("Leaving clientAuthenticationRefusal(). Nothing to judge.");
    return null;
  }
  const allowed = advanced() ? ADVANCED_METHODS
                             : BASELINE_METHODS.concat(['none']);
  if (allowed.indexOf(used) >= 0) {
    log.debug("Leaving clientAuthenticationRefusal(). Allowed.");
    return null;
  }
  log.debug("Leaving clientAuthenticationRefusal(). Refused.");
  return refusal('STS-OAUTH-0580', 'invalid_client',
                 used === 'none' ? 'no-public-clients'
                                 : 'confidential-client-auth',
                 used === 'none'
                   ? 'this client is a public client, and this profile ' +
                     'supports none (Part 2 section 5.2.2 item 16)'
                   : 'this client authenticates with ' + used + ', and a ' +
                     'confidential client must use ' +
                     allowed.filter(function (one) {
                       return one !== 'none';
                     }).join(', ') + ' (' + (advanced()
                       ? 'Part 2 section 5.2.2 item 14'
                       : 'section 5.2.2 item 4') + ')');
}

// The size of one JWK's key in bits, or 0 when it is not RSA or EC.
function keyBits(jwk) {
  log.debug("Entering keyBits().");
  const key = jwk || {};
  if (key.kty === 'RSA' && typeof key.n === 'string') {
    const bytes = Buffer.from(key.n, 'base64url');
    let bits = bytes.length * 8;
    for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
      bits -= 8;
    }
    log.debug("Leaving keyBits(). RSA.");
    return bits;
  }
  if (key.kty === 'EC') {
    const sizes = { 'P-256': 256, 'P-384': 384, 'P-521': 521,
                    'secp256k1': 256 };
    log.debug("Leaving keyBits(). EC.");
    return sizes[String(key.crv)] || 0;
  }
  log.debug("Leaving keyBits(). Neither.");
  return -1;
}

// ---------------------------------------------------------------------------
// A CLIENT REGISTRATION (RFC 7591), before anything is written.
// ---------------------------------------------------------------------------
function registrationRefusal(metadata) {
  log.debug("Entering registrationRefusal().");
  if (!enabled()) {
    log.debug("Leaving registrationRefusal(). Off.");
    return null;
  }
  const meta = metadata || {};
  const method = String(meta.token_endpoint_auth_method || '');
  const methods = advanced() ? ADVANCED_METHODS
                             : BASELINE_METHODS.concat(['none']);
  if (method && methods.indexOf(method) < 0) {
    log.debug("Leaving registrationRefusal(). A method FAPI refuses.");
    return refusal('STS-REG-0174', 'invalid_client_metadata',
                   'confidential-client-auth',
                   'token_endpoint_auth_method "' + method + '" is not one ' +
                   'a client of this profile may use; it is one of ' +
                   methods.join(', ') + ' (' + (advanced()
                     ? 'Part 2 section 5.2.2 items 14 and 16'
                     : 'section 5.2.2 item 4') + ')');
  }
  if (advanced()) {
    const problem = advancedRegistrationProblem(meta);
    if (problem) {
      log.debug("Leaving registrationRefusal(). Advanced refuses it.");
      return problem;
    }
  }
  const uris = Array.isArray(meta.redirect_uris) ? meta.redirect_uris : [];
  const plain = uris.filter(function (uri) {
    return !httpsUri(uri);
  });
  if (plain.length) {
    log.debug("Leaving registrationRefusal(). A redirect URI is not https.");
    return refusal('STS-REG-0176', 'invalid_redirect_uri', 'redirect-uri',
                   'every redirect URI must use the https scheme; ' +
                   plain.map(String).join(', ') + ' does not (section ' +
                   '5.2.2 item 20)');
  }
  const keys = meta.jwks && Array.isArray(meta.jwks.keys) ? meta.jwks.keys
                                                          : [];
  for (let i = 0; i < keys.length; i++) {
    const bits = keyBits(keys[i]);
    const small = (keys[i] && keys[i].kty === 'RSA' && bits < MIN_RSA_BITS) ||
                  (keys[i] && keys[i].kty === 'EC' && bits < MIN_EC_BITS);
    if (small) {
      log.debug("Leaving registrationRefusal(). A key is too small.");
      return refusal('STS-REG-0175', 'invalid_client_metadata', 'key-sizes',
                     'jwks key ' + (keys[i].kid ? '"' + keys[i].kid + '" '
                                                : '') +
                     'is ' + keys[i].kty + ' of ' + bits + ' bits; RSA keys ' +
                     'must be ' + MIN_RSA_BITS + ' bits or more and EC keys ' +
                     MIN_EC_BITS + ' or more (section 5.2.2 items 5-6)');
    }
  }
  log.debug("Leaving registrationRefusal(). Allowed.");
  return null;
}

// What Advanced asks of a registration beyond Baseline: the response types
// (item 2), the signing algorithms (8.6) and no RSA1_5 (8.6.1).
function advancedRegistrationProblem(meta) {
  log.debug("Entering advancedRegistrationProblem().");
  const types = Array.isArray(meta.response_types) ? meta.response_types
                                                   : [];
  const badType = types.map(responseTypeOf).filter(function (one) {
    return ADVANCED_RESPONSE_TYPES.indexOf(one) < 0;
  });
  if (badType.length) {
    log.debug("Leaving advancedRegistrationProblem(). A response type.");
    return refusal('STS-REG-0178', 'invalid_client_metadata',
                   'response-type',
                   'response_types ' + JSON.stringify(badType) + ' is not ' +
                   'one this profile allows; it allows ' +
                   ADVANCED_RESPONSE_TYPES.join(' and ') + ' (Part 2 ' +
                   'section 5.2.2 item 2)');
  }
  for (let i = 0; i < SIGNING_ALG_MEMBERS.length; i++) {
    const value = meta[SIGNING_ALG_MEMBERS[i]];
    if (value !== undefined && value !== null && value !== '' &&
        ADVANCED_SIGNING_ALGS.indexOf(String(value)) < 0) {
      log.debug("Leaving advancedRegistrationProblem(). A signing alg.");
      return refusal('STS-REG-0177', 'invalid_client_metadata',
                     'algorithms',
                     SIGNING_ALG_MEMBERS[i] + ' "' + value + '" is not ' +
                     ADVANCED_SIGNING_ALGS.join(' or ') + ' (Part 2 section ' +
                     '8.6)');
    }
  }
  for (let i = 0; i < ENCRYPTION_ALG_MEMBERS.length; i++) {
    const value = String(meta[ENCRYPTION_ALG_MEMBERS[i]] || '');
    if (FORBIDDEN_ENCRYPTION_ALGS.indexOf(value) >= 0) {
      log.debug("Leaving advancedRegistrationProblem(). RSA1_5.");
      return refusal('STS-REG-0177', 'invalid_client_metadata',
                     'algorithms',
                     ENCRYPTION_ALG_MEMBERS[i] + ' "' + value + '" may not ' +
                     'be used (Part 2 section 8.6.1)');
    }
  }
  log.debug("Leaving advancedRegistrationProblem(). None.");
  return null;
}

// ---------------------------------------------------------------------------
// SECTION 8.6 AT A SIGNATURE: this server's DEFAULT algorithm for what it
// signs when the client registered none ('' leaves the caller's own default),
// and whether an algorithm — the client's or this server's — may be used.
// ---------------------------------------------------------------------------
function defaultSigningAlg() {
  log.debug("Entering defaultSigningAlg().");
  log.debug("Leaving defaultSigningAlg().");
  return advanced() ? ADVANCED_DEFAULT_SIGNING_ALG : '';
}

function signingAlgAllowed(alg) {
  log.debug("Entering signingAlgAllowed(). " + alg);
  log.debug("Leaving signingAlgAllowed().");
  return !advanced() || ADVANCED_SIGNING_ALGS.indexOf(String(alg)) >= 0;
}

function encryptionAlgAllowed(alg) {
  log.debug("Entering encryptionAlgAllowed(). " + alg);
  log.debug("Leaving encryptionAlgAllowed().");
  return !advanced() || FORBIDDEN_ENCRYPTION_ALGS.indexOf(String(alg)) < 0;
}

// A JWS a client presented (a client assertion, a request object) signed with
// an algorithm section 8.6 does not allow. `what` names it in the sentence.
function signingAlgRefusal(alg, what) {
  log.debug("Entering signingAlgRefusal(). " + alg);
  if (signingAlgAllowed(alg)) {
    log.debug("Leaving signingAlgRefusal(). Allowed.");
    return null;
  }
  log.debug("Leaving signingAlgRefusal(). Refused.");
  return refusal('STS-OAUTH-0586', 'invalid_request', 'algorithms',
                 what + ' is signed ' + alg + ', and this profile allows ' +
                 ADVANCED_SIGNING_ALGS.join(' or ') + ' (Part 2 section 8.6)');
}

// Part 2 section 5.2.2 item 1: a signed request object is required.
function requiresSignedRequestObject() {
  log.debug("Entering requiresSignedRequestObject().");
  log.debug("Leaving requiresSignedRequestObject().");
  return advanced();
}

// ---------------------------------------------------------------------------
// PART 2 SECTION 5.2.2 ITEMS 13, 15 AND 17 — a verified request object's
// claims. `issuer` is this authorization server's; `now` seconds.
// ---------------------------------------------------------------------------
function requestObjectRefusal(claims, issuer, now) {
  log.debug("Entering requestObjectRefusal().");
  if (!advanced()) {
    log.debug("Leaving requestObjectRefusal(). Not Advanced.");
    return null;
  }
  const c = claims || {};
  const at = Number(now) || Math.floor(Date.now() / 1000);
  const exp = Number(c.exp);
  const nbf = Number(c.nbf);
  if (!isFinite(exp) || !isFinite(nbf) || c.exp === undefined ||
      c.nbf === undefined) {
    log.debug("Leaving requestObjectRefusal(). exp or nbf missing.");
    return refusal('STS-OAUTH-0584', 'invalid_request_object',
                   'request-object-lifetime',
                   'the request object carries no ' + [c.exp === undefined
                     ? 'exp' : '', c.nbf === undefined ? 'nbf' : '']
                     .filter(Boolean).join(' and no ') + ', and both are ' +
                   'required (Part 2 section 5.2.2 items 13 and 17)');
  }
  if (exp - nbf > MAX_REQUEST_OBJECT_LIFETIME_S) {
    log.debug("Leaving requestObjectRefusal(). Too long a lifetime.");
    return refusal('STS-OAUTH-0584', 'invalid_request_object',
                   'request-object-lifetime',
                   'the request object\'s exp is ' + (exp - nbf) + ' ' +
                   'seconds after its nbf, and the limit is ' +
                   MAX_REQUEST_OBJECT_LIFETIME_S + ' (Part 2 section 5.2.2 ' +
                   'item 13)');
  }
  if (at - nbf > MAX_REQUEST_OBJECT_AGE_S) {
    log.debug("Leaving requestObjectRefusal(). Too old.");
    return refusal('STS-OAUTH-0584', 'invalid_request_object',
                   'request-object-lifetime',
                   'the request object\'s nbf is ' + (at - nbf) + ' ' +
                   'seconds in the past, and the limit is ' +
                   MAX_REQUEST_OBJECT_AGE_S + ' (Part 2 section 5.2.2 item ' +
                   '17)');
  }
  const audiences = (Array.isArray(c.aud) ? c.aud : [c.aud])
    .filter(function (one) {
      return one !== undefined && one !== null;
    }).map(String);
  if (audiences.indexOf(String(issuer || '')) < 0) {
    log.debug("Leaving requestObjectRefusal(). aud is not the issuer.");
    return refusal('STS-OAUTH-0585', 'invalid_request_object',
                   'request-object-aud',
                   'the request object\'s aud is ' + JSON.stringify(c.aud) +
                   ', and it must be this server\'s issuer "' + issuer +
                   '" (Part 2 section 5.2.2 item 15)');
  }
  log.debug("Leaving requestObjectRefusal(). Allowed.");
  return null;
}

// ---------------------------------------------------------------------------
// PART 2 SECTION 5.2.2 ITEMS 5 AND 6 — whether an access token about to be
// issued is sender-constrained enough. `dpop` and `mtls` say what binds it.
// DPoP counts unless `oauth2.fapiRequireMtls` is on (rcbj's decision on
// #139): FAPI 1.0 names mutual TLS, and the flag is strict compliance.
// ---------------------------------------------------------------------------
function requiresMtls() {
  log.debug("Entering requiresMtls().");
  log.debug("Leaving requiresMtls().");
  return advanced() && !!config.value('oauth2.fapiRequireMtls');
}

function senderConstraintRefusal(binding) {
  log.debug("Entering senderConstraintRefusal().");
  if (!advanced()) {
    log.debug("Leaving senderConstraintRefusal(). Not Advanced.");
    return null;
  }
  const b = binding || {};
  if (b.mtls || (b.dpop && !requiresMtls())) {
    log.debug("Leaving senderConstraintRefusal(). Bound.");
    return null;
  }
  log.debug("Leaving senderConstraintRefusal(). Unbound.");
  return refusal('STS-OAUTH-0583', 'invalid_request', 'sender-constrained',
                 requiresMtls()
                   ? 'this request presented no TLS client certificate, and ' +
                     'every access token here is bound to one — ' +
                     'oauth2.fapiRequireMtls is on (Part 2 section 5.2.2 ' +
                     'items 5 and 6)'
                   : 'this request neither presented a TLS client ' +
                     'certificate nor carried a DPoP proof, and every access ' +
                     'token here is sender-constrained (Part 2 section 5.2.2 ' +
                     'item 5)');
}

// Section 5.2.2 item 21: the lifetime an access token may have. `bound` is
// whether it carries a cnf (DPoP or mTLS).
function accessTokenLifetime(asked, bound) {
  log.debug("Entering accessTokenLifetime().");
  const wanted = Number(asked) || 0;
  if (!enabled() || bound || wanted <= MAX_UNBOUND_ACCESS_TOKEN_S) {
    log.debug("Leaving accessTokenLifetime(). As asked.");
    return wanted;
  }
  log.debug("Leaving accessTokenLifetime(). Capped.");
  return MAX_UNBOUND_ACCESS_TOKEN_S;
}

// Section 5.2.2 item 15: whether the granted scope is always returned.
function alwaysReturnsScope() {
  log.debug("Entering alwaysReturnsScope().");
  log.debug("Leaving alwaysReturnsScope().");
  return enabled();
}

// Section 5.2.2 item 12: whether an administrator's global consent may stand
// in for the user's own approval.
function honoursGlobalConsent() {
  log.debug("Entering honoursGlobalConsent().");
  log.debug("Leaving honoursGlobalConsent().");
  return !enabled();
}

// What this profile does to the metadata an authorization server publishes.
// RFC 9700 mode's own narrowing has already run.
function applyToMetadata(metadata) {
  log.debug("Entering applyToMetadata().");
  if (!enabled()) {
    log.debug("Leaving applyToMetadata(). Off.");
    return metadata;
  }
  metadata.code_challenge_methods_supported = ['S256'];
  const allowedMethods = advanced() ? ADVANCED_METHODS
                                    : BASELINE_METHODS.concat(['none']);
  const methods = metadata.token_endpoint_auth_methods_supported;
  if (Array.isArray(methods)) {
    metadata.token_endpoint_auth_methods_supported =
      methods.filter(function (one) {
        return allowedMethods.indexOf(one) >= 0;
      });
  }
  if (advanced()) {
    if (Array.isArray(metadata.response_types_supported)) {
      metadata.response_types_supported = metadata.response_types_supported
        .filter(function (one) {
          return ADVANCED_RESPONSE_TYPES.indexOf(responseTypeOf(one)) >= 0;
        });
    }
    SIGNING_ALG_LISTS.forEach(function (name) {
      if (Array.isArray(metadata[name])) {
        metadata[name] = metadata[name].filter(function (one) {
          return ADVANCED_SIGNING_ALGS.indexOf(one) >= 0;
        });
      }
    });
    ENCRYPTION_ALG_LISTS.forEach(function (name) {
      if (Array.isArray(metadata[name])) {
        metadata[name] = metadata[name].filter(function (one) {
          return FORBIDDEN_ENCRYPTION_ALGS.indexOf(one) < 0;
        });
      }
    });
    metadata.require_signed_request_object = true;
  }
  log.debug("Leaving applyToMetadata().");
  return metadata;
}

// What GET /oauth2/fapi publishes.
function state() {
  log.debug("Entering state().");
  const on = profile();
  const view = {
    profile: on || null,
    enabled: !!on,
    profiles_supported: PROFILES.slice(),
    specification: on === ADVANCED ? ADVANCED_NAME + ', over ' + BASELINE
                                   : BASELINE,
    url: on === ADVANCED ? ADVANCED_URL : BASELINE_URL,
    require_mtls: requiresMtls(),
    implies: 'oauth2.rfc9700 — GET /oauth2/rfc9700 lists what that mode ' +
             'enforces, and every FAPI profile turns it on',
    what_it_means: on
      ? 'Every row below marked yes is refused, on top of everything RFC ' +
        '9700 mode enforces.'
      : 'Set oauth2.fapi (a trust realm may carry it), or the fapi member ' +
        'of a named authorization server on /admin/authorization-servers, ' +
        'to turn a profile on.',
    settings: {
      'oauth2.fapi': String(config.value('oauth2.fapi') || '') || null,
      'oauth2.fapiRequireMtls': !!config.value('oauth2.fapiRequireMtls'),
      'oauth2.rfc9700': !!config.value('oauth2.rfc9700')
    },
    requirements: REQUIREMENTS.map(function (row) {
      const relaxed = on === ADVANCED && row.id === 'pkce-s256';
      return { id: row.id, section: 'FAPI 1.0 Part 1 ' + row.section,
               level: row.level,
               enforced: relaxed ? 'relaxed' : row.enforced,
               title: row.title,
               note: relaxed ? 'Part 2 section 5.2.2 exempts item 7 except ' +
                 'for a pushed request (item 18): a challenge that is sent ' +
                 'is still held to S256.' : row.note };
    }).concat(on === ADVANCED ? ADVANCED_REQUIREMENTS.map(function (row) {
      return { id: row.id, section: 'FAPI 1.0 Part 2 ' + row.section,
               level: row.level, enforced: row.enforced, title: row.title,
               note: row.note };
    }) : [])
  };
  log.debug("Leaving state().");
  return view;
}

module.exports = {
  PROFILES: PROFILES,
  ADVANCED: ADVANCED,
  NONE: NONE,
  ADVANCED_METHODS: ADVANCED_METHODS,
  ADVANCED_SIGNING_ALGS: ADVANCED_SIGNING_ALGS,
  ADVANCED_REQUIREMENTS: ADVANCED_REQUIREMENTS,
  JARM_MODES: JARM_MODES,
  MAX_REQUEST_OBJECT_LIFETIME_S: MAX_REQUEST_OBJECT_LIFETIME_S,
  BASELINE_METHODS: BASELINE_METHODS,
  MIN_RSA_BITS: MIN_RSA_BITS,
  MIN_EC_BITS: MIN_EC_BITS,
  MAX_UNBOUND_ACCESS_TOKEN_S: MAX_UNBOUND_ACCESS_TOKEN_S,
  REQUIREMENTS: REQUIREMENTS,
  known: known,
  withProfile: withProfile,
  profile: profile,
  enabled: enabled,
  advanced: advanced,
  responseTypeOf: responseTypeOf,
  defaultSigningAlg: defaultSigningAlg,
  signingAlgAllowed: signingAlgAllowed,
  encryptionAlgAllowed: encryptionAlgAllowed,
  signingAlgRefusal: signingAlgRefusal,
  requiresSignedRequestObject: requiresSignedRequestObject,
  requestObjectRefusal: requestObjectRefusal,
  requiresMtls: requiresMtls,
  senderConstraintRefusal: senderConstraintRefusal,
  authorizationRefusal: authorizationRefusal,
  clientAuthenticationRefusal: clientAuthenticationRefusal,
  clientIdentifierRefusal: clientIdentifierRefusal,
  keyBits: keyBits,
  registrationRefusal: registrationRefusal,
  accessTokenLifetime: accessTokenLifetime,
  alwaysReturnsScope: alwaysReturnsScope,
  honoursGlobalConsent: honoursGlobalConsent,
  applyToMetadata: applyToMetadata,
  state: state
};
