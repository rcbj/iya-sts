// @ts-check
'use strict';
//
// File: fapi.js
//
// ===========================================================================
// THE FAPI PROFILES, AS A MODE (#138, 2026-09-22).
//
// FAPI 1.0 Part 1: Baseline (final, 2021-03-12) first; #139 adds FAPI 1.0
// Part 2 (Advanced), #140 the FAPI 2.0 Security Profile and #141 FAPI 2.0
// Message Signing, each as another value of the ONE switch:
//
//   oauth2.fapi = 'off' | '1-baseline'
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
const PROFILES = ['1-baseline'];

// The switch's own "no profile", and what a named authorization server may
// say to be NOT a FAPI server even though its realm is.
const NONE = 'off';

const BASELINE = 'FAPI 1.0 Part 1: Baseline Security Profile (final)';
const BASELINE_URL =
  'https://openid.net/specs/openid-financial-api-part-1-1_0.html';

// The confidential client authentication methods Baseline section 5.2.2
// item 4 allows: RFC 8705's two, and OIDC Core section 9's two JWT ones.
const BASELINE_METHODS = ['tls_client_auth', 'self_signed_tls_client_auth',
                          'private_key_jwt', 'client_secret_jwt'];

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

function refusal(errorCode, error, requirement, description) {
  log.debug("Entering refusal(). " + requirement);
  log.debug("Leaving refusal().");
  return { ok: false, errorCode: errorCode, error: error,
           requirement: requirement,
           description: description + ' (' + BASELINE + ', ' +
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
// `query` is the request's parameters; `confidential` whether the client's
// entry declares a credential.
// ---------------------------------------------------------------------------
function authorizationRefusal(query) {
  log.debug("Entering authorizationRefusal().");
  if (!enabled()) {
    log.debug("Leaving authorizationRefusal(). Off.");
    return null;
  }
  const q = query || {};
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
  if (!q.code_challenge || q.code_challenge_method !== 'S256') {
    log.debug("Leaving authorizationRefusal(). No S256 challenge.");
    return refusal('STS-OAUTH-0573', 'invalid_request', 'pkce-s256',
                   'a code_challenge with code_challenge_method=S256 is ' +
                   'required of every client (section 5.2.2 item 7)');
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
  if (!enabled() || !used || used === 'none' ||
      BASELINE_METHODS.indexOf(used) >= 0) {
    log.debug("Leaving clientAuthenticationRefusal(). Allowed.");
    return null;
  }
  log.debug("Leaving clientAuthenticationRefusal(). Refused.");
  return refusal('STS-OAUTH-0580', 'invalid_client',
                 'confidential-client-auth',
                 'this client authenticates with ' + used + ', and a ' +
                 'confidential client must use ' +
                 BASELINE_METHODS.join(', ') + ' (section 5.2.2 item 4)');
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
  if (method && method !== 'none' && BASELINE_METHODS.indexOf(method) < 0) {
    log.debug("Leaving registrationRefusal(). A method FAPI refuses.");
    return refusal('STS-REG-0174', 'invalid_client_metadata',
                   'confidential-client-auth',
                   'token_endpoint_auth_method "' + method + '" is not one ' +
                   'a FAPI client may use; it is one of ' +
                   BASELINE_METHODS.join(', ') + ', or none for a public ' +
                   'client (section 5.2.2 item 4)');
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
  const methods = metadata.token_endpoint_auth_methods_supported;
  if (Array.isArray(methods)) {
    metadata.token_endpoint_auth_methods_supported =
      methods.filter(function (one) {
        return one === 'none' || BASELINE_METHODS.indexOf(one) >= 0;
      });
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
    specification: BASELINE,
    url: BASELINE_URL,
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
      'oauth2.rfc9700': !!config.value('oauth2.rfc9700')
    },
    requirements: REQUIREMENTS.map(function (row) {
      return { id: row.id, section: 'FAPI 1.0 Part 1 ' + row.section,
               level: row.level, enforced: row.enforced, title: row.title,
               note: row.note };
    })
  };
  log.debug("Leaving state().");
  return view;
}

module.exports = {
  PROFILES: PROFILES,
  NONE: NONE,
  BASELINE_METHODS: BASELINE_METHODS,
  MIN_RSA_BITS: MIN_RSA_BITS,
  MIN_EC_BITS: MIN_EC_BITS,
  MAX_UNBOUND_ACCESS_TOKEN_S: MAX_UNBOUND_ACCESS_TOKEN_S,
  REQUIREMENTS: REQUIREMENTS,
  known: known,
  withProfile: withProfile,
  profile: profile,
  enabled: enabled,
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
