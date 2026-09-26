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
//   oauth2.fapi = 'off' | '1-baseline' | '1-advanced' | '2-security'
//                 | '2-message-signing'
//
// FAPI 2.0 MESSAGE SIGNING (final, 2025-09-25; #141) IS THE SECURITY PROFILE
// PLUS ALL THREE OF ITS COMPONENTS — rcbj's decision, over a switch per
// component: a JAR-signed request object required at PAR (section 5.3), JARM
// required (5.4), and RFC 9701 introspection responses signed (5.5, which
// every JWT introspection response here already is). `fapi2()` is true for
// both 2.0 values, and `messageSigning()` for the second.
//
// THE FAPI 2.0 SECURITY PROFILE (final, #140) IS NOT BUILT ON 1.0. It is a
// profile of its own — confidential clients only, PAR always, `code` only,
// PKCE S256 always, sender-constrained tokens (mTLS or DPoP), mTLS or
// private_key_jwt, the issuer as the assertion's sole `aud`, codes of at most
// 60 seconds, no refresh token rotation, PS256/ES256/EdDSA — so the FAPI 1.0
// rows ask `v1()` and the 2.0 rows `fapi2()`, and the few that both ask
// `enabled()`. rcbj's answers on #140: rotation off unless
// `oauth2.refreshTokenRotation` forces it; the ordinary consent rules (the
// person's-own-consent rule is FAPI 1.0 item 12's, not 2.0's); DPoP nonces
// left to their setting; and BCP 195's TLS suites for every listener, which
// is `tls/tls_server.js`'s and not this file's.
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
const PROFILES = ['1-baseline', '1-advanced', '2-security',
                  '2-message-signing'];
const ADVANCED = '1-advanced';
const FAPI2 = '2-security';
const MESSAGE_SIGNING = '2-message-signing';

// The switch's own "no profile", and what a named authorization server may
// say to be NOT a FAPI server even though its realm is.
const NONE = 'off';

const BASELINE = 'FAPI 1.0 Part 1: Baseline Security Profile (final)';
const BASELINE_URL =
  'https://openid.net/specs/openid-financial-api-part-1-1_0.html';
const ADVANCED_NAME = 'FAPI 1.0 Part 2: Advanced Security Profile (final)';
const FAPI2_NAME = 'FAPI 2.0 Security Profile (final)';
const FAPI2_URL =
  'https://openid.net/specs/fapi-security-profile-2_0-final.html';
const MESSAGE_SIGNING_NAME = 'FAPI 2.0 Message Signing (final)';
const MESSAGE_SIGNING_URL =
  'https://openid.net/specs/fapi-message-signing-2_0.html';
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
// FAPI 2.0 section 5.4.1 item 2: PS256, ES256 or EdDSA (Ed25519).
const FAPI2_SIGNING_ALGS = ['PS256', 'ES256', 'EdDSA'];
// FAPI 2.0 section 5.3.2.2 item 1.
const FAPI2_RESPONSE_TYPES = ['code'];
// FAPI 2.0 section 5.4.1 item 5: an elliptic curve key of 224 bits or more.
const FAPI2_MIN_EC_BITS = 224;
// FAPI 2.0 section 5.3.2.1 item 11 and 5.3.2.2 item 12.
const FAPI2_MAX_CODE_LIFETIME_S = 60;
const FAPI2_MAX_REQUEST_URI_LIFETIME_S = 599;
// FAPI 2.0 section 5.3.2.1 item 13: an iat or nbf more than 60 seconds in the
// future is rejected (and one up to 10 seconds ahead accepted, which every
// skew setting here already allows).
const FAPI2_MAX_FUTURE_S = 60;
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
  'introspection_endpoint_auth_signing_alg_values_supported',
  // FAPI-CIBA (#142): a signed authentication request is a JWS like any
  // other here, and its algorithms are the profile's.
  'backchannel_authentication_request_signing_alg_values_supported'];
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

// ---------------------------------------------------------------------------
// WHAT THE FAPI 2.0 SECURITY PROFILE ASKS OF THE AUTHORIZATION SERVER, row by
// row (sections 5.3.2.1, 5.3.2.2, 5.4). Its own table: 2.0 is not 1.0 plus
// something, and the FAPI 1.0 rows are not listed under it.
// ---------------------------------------------------------------------------
const FAPI2_REQUIREMENTS = [
  { id: 'implies-rfc9700', section: '5.3.2.1 items 2, 7', level: 'SHALL',
    enforced: 'inherited',
    title: 'No password grant, no open redirector — RFC 9700 mode is on',
    note: 'GET /oauth2/rfc9700 lists what that mode enforces.' },
  { id: 'confidential-only', section: '5.3.2.1 item 3', level: 'SHALL',
    enforced: 'yes', title: 'Confidential clients only',
    note: 'A public client is refused at registration and at the token and ' +
          'PAR endpoints (STS-OAUTH-0580, STS-REG-0174).' },
  { id: 'sender-constrained', section: '5.3.2.1 items 4-5', level: 'SHALL',
    enforced: 'yes',
    title: 'Only sender-constrained access tokens, by mTLS or DPoP',
    note: 'A token request presenting neither is refused (STS-OAUTH-0583). ' +
          'DPoP server nonces stay with oauth2.dpopNonceRequired (item 10, ' +
          'a MAY; rcbj\'s decision on #140).' },
  { id: 'client-auth', section: '5.3.2.1 item 6', level: 'SHALL',
    enforced: 'yes', title: 'mTLS or private_key_jwt',
    note: 'STS-OAUTH-0580, STS-REG-0174.' },
  { id: 'assertion-aud', section: '5.3.2.1 item 8', level: 'SHALL',
    enforced: 'yes',
    title: 'A client assertion\'s aud is the issuer, as a string, alone',
    note: 'OAuth 2.1 mode\'s rfc7523bis rule, turned on by this profile.' },
  { id: 'no-rotation', section: '5.3.2.1 item 9', level: 'SHALL',
    enforced: 'yes', title: 'No refresh token rotation',
    note: 'Unless oauth2.refreshTokenRotation is set — the "extraordinary ' +
          'circumstance" the item allows, and rcbj\'s decision on #140.' },
  { id: 'code-lifetime', section: '5.3.2.1 item 11', level: 'SHALL',
    enforced: 'yes', title: 'Authorization codes live 60 seconds at most',
    note: 'oauth2.authorizationCodeTtlS is capped at 60 under the profile.' },
  { id: 'dpop-code-binding', section: '5.3.2.1 item 12', level: 'SHALL',
    enforced: 'already', title: 'Authorization code binding to a DPoP key',
    note: 'dpop_jkt at the authorization and PAR endpoints (RFC 9449 ' +
          'section 10).' },
  { id: 'jwt-timestamps', section: '5.3.2.1 item 13', level: 'SHALL',
    enforced: 'yes',
    title: 'An iat or nbf more than 60 seconds in the future is rejected',
    note: 'Client assertions, request objects and DPoP proofs ' +
          '(STS-OAUTH-0590).' },
  { id: 'response-type', section: '5.3.2.2 item 1', level: 'SHALL',
    enforced: 'yes', title: 'response_type code only',
    note: 'STS-OAUTH-0582, STS-REG-0178.' },
  { id: 'par-required', section: '5.3.2.2 items 2-4', level: 'SHALL',
    enforced: 'yes',
    title: 'Pushed authorization requests, client-authenticated, required',
    note: 'An authorization request not pushed is refused (STS-OAUTH-0419); ' +
          'an unauthenticated push is refused (STS-OAUTH-0589).' },
  { id: 'pkce-s256', section: '5.3.2.2 item 5', level: 'SHALL',
    enforced: 'yes', title: 'PKCE with S256 for every request',
    note: 'STS-OAUTH-0573.' },
  { id: 'par-redirect-uri', section: '5.3.2.2 item 6', level: 'SHALL',
    enforced: 'yes', title: 'redirect_uri in the pushed request',
    note: 'OAuth 2.1 mode\'s default to the registered one does not apply ' +
          '(STS-OAUTH-0574).' },
  { id: 'iss-parameter', section: '5.3.2.2 item 7', level: 'SHALL',
    enforced: 'already', title: 'The RFC 9207 iss on every response',
    note: 'In every mode.' },
  { id: 'code-single-use', section: '5.3.2.2 item 9', level: 'SHALL',
    enforced: 'inherited', title: 'A used authorization code is rejected',
    note: 'RFC 9700 mode\'s code-single-use.' },
  { id: 'request-uri-lifetime', section: '5.3.2.2 item 12', level: 'SHALL',
    enforced: 'yes', title: 'A request_uri expires in under 600 seconds',
    note: 'oauth2.parRequestUriLifetimeS is capped at 599 under the profile.' },
  { id: 'algorithms', section: '5.4.1 items 2-5', level: 'SHALL',
    enforced: 'yes',
    title: 'PS256, ES256 or EdDSA; RSA keys of 2048 bits, EC of 224',
    note: 'This server signs PS256 by default under the profile; a client ' +
          'algorithm or key outside these is refused (STS-OAUTH-0586, ' +
          'STS-REG-0177, STS-REG-0175). EdDSA is Ed25519 while ' +
          'oauth2.eddsaCurve is.' },
  { id: 'tls', section: '5.2.1, 5.2.2', level: 'SHALL', enforced: 'deployment',
    title: 'TLS 1.2 or later, BCP 195\'s TLS 1.2 cipher suites',
    note: 'Every listener\'s default since #140 (tls.ciphers, ' +
          'tls.minVersion), TLS 1.3 preferred; a property of the process, ' +
          'not of a realm.' }
];

// ---------------------------------------------------------------------------
// WHAT FAPI 2.0 MESSAGE SIGNING ADDS TO THE SECURITY PROFILE (section 5), row
// by row. Under `2-message-signing` GET /oauth2/fapi lists these after the
// Security Profile's.
// ---------------------------------------------------------------------------
const MESSAGE_SIGNING_REQUIREMENTS = [
  { id: 'signed-request-at-par', section: '5.3.2 item 1', level: 'SHALL',
    enforced: 'yes',
    title: 'A JAR-signed request object at the PAR endpoint',
    note: 'A push of plain parameters is refused (STS-OAUTH-0415).' },
  { id: 'request-object-claims', section: '5.3.2 items 2-4', level: 'SHALL',
    enforced: 'yes',
    title: 'aud the issuer; nbf at most 60 minutes old; exp at most 60 ' +
           'minutes after nbf',
    note: 'STS-OAUTH-0584, STS-OAUTH-0585.' },
  { id: 'request-object-typ', section: '5.3.2 item 5', level: 'SHALL',
    enforced: 'already', title: 'typ oauth-authz-req+jwt is accepted',
    note: 'RFC 9101 section 10.8, in every mode.' },
  { id: 'jarm-required', section: '5.4.2 item 1', level: 'SHALL',
    enforced: 'yes',
    title: 'Signed authorization responses (JARM), required',
    note: 'A request without a JARM response mode is refused ' +
          '(STS-OAUTH-0591); response_modes_supported lists only JARM\'s.' },
  { id: 'jarm-iss', section: '5.4.2 item 2', level: 'SHOULD',
    enforced: 'yes', title: 'iss inside the JWT, not beside it',
    note: 'A JARM response is the single `response` parameter.' },
  { id: 'signed-introspection', section: '5.5.2 item 1', level: 'SHALL',
    enforced: 'already',
    title: 'Introspection responses in JWT format are signed (RFC 9701)',
    note: 'Every JWT introspection response is; PS256 by default under the ' +
          'profile.' },
  { id: 'non-repudiation', section: '5.2', level: 'guidance',
    enforced: 'deployment',
    title: 'Non-repudiation: keys and records kept',
    note: 'Retired signing keys stay published for their grace period and ' +
          'every issuance is audited; docs/oauth-security.md says what a ' +
          'deployment keeps and for how long.' },
  // FAPI-CIBA (#142): the profile of CIBA the FAPI profiles bring with them
  // wherever `oauth2.ciba` is on — rcbj's answer, no setting of its own.
  { id: 'ciba-confidential', section: 'FAPI-CIBA 5.2.2 item 1',
    level: 'SHALL', enforced: 'yes',
    title: 'CIBA for confidential clients only, authenticated as FAPI ' +
           'allows',
    note: 'The backchannel authentication endpoint refuses a method the ' +
          'profile does not allow, and a client assertion signed outside ' +
          'its algorithms (STS-OAUTH-0580, STS-OAUTH-0586).' },
  { id: 'ciba-binding-message', section: 'FAPI-CIBA 5.2.2 item 2',
    level: 'SHALL', enforced: 'yes',
    title: 'A binding_message in every authentication request',
    note: 'Nothing else in a request here makes its authorization context ' +
          'unique, so a request without one is refused (STS-OAUTH-0663).' },
  { id: 'ciba-no-push', section: 'FAPI-CIBA 5.2.2 items 3-5',
    level: 'SHALL', enforced: 'yes',
    title: 'Poll and ping, never push',
    note: 'backchannel_token_delivery_modes_supported drops push; a push ' +
          'client is refused at registration (STS-REG-0198) and at the ' +
          'endpoint (STS-OAUTH-0662).' },
  { id: 'ciba-signed-request', section: 'FAPI-CIBA 5.2.2 (FAPI 1.0)',
    level: 'SHALL', enforced: 'yes',
    title: 'Signed and unsigned requests; a signed one lives at most 60 ' +
           'minutes, signed with the profile\'s algorithms',
    note: 'nbf and exp at most an hour apart in every mode (CIBA 7.1.1); ' +
          'the algorithm is the profile\'s (STS-OAUTH-0586).' },
  { id: 'ciba-request-context', section: 'FAPI-CIBA 5.2.2 item 8, 5.3',
    level: 'MAY', enforced: 'yes',
    title: 'request_context accepted',
    note: 'A JSON object, kept on the request for the person\'s approval ' +
          'page to show (STS-OAUTH-0664 when it is not one).' }
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

// Whether the FAPI 2.0 Security Profile is in force.
function fapi2() {
  log.debug("Entering fapi2().");
  const on = profile() === FAPI2 || profile() === MESSAGE_SIGNING;
  log.debug("Leaving fapi2(). " + on);
  return on;
}

// Whether FAPI 2.0 Message Signing is in force (and so the Security Profile).
function messageSigning() {
  log.debug("Entering messageSigning().");
  const on = profile() === MESSAGE_SIGNING;
  log.debug("Leaving messageSigning(). " + on);
  return on;
}

// Whether a FAPI 1.0 profile (Baseline or Advanced) is in force.
function v1() {
  log.debug("Entering v1().");
  const on = enabled() && !fapi2();
  log.debug("Leaving v1(). " + on);
  return on;
}

// The JWS algorithms the profile in force allows, or null for no limit.
function profileSigningAlgs() {
  log.debug("Entering profileSigningAlgs().");
  log.debug("Leaving profileSigningAlgs().");
  return advanced() ? ADVANCED_SIGNING_ALGS
    : (fapi2() ? FAPI2_SIGNING_ALGS : null);
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
  return advanced() ? ADVANCED_NAME
    : (messageSigning() ? MESSAGE_SIGNING_NAME + ', over ' + FAPI2_NAME
                        : (fapi2() ? FAPI2_NAME : BASELINE));
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

// Whether a redirect URI is acceptable to the profile in force: https, and —
// under FAPI 2.0 only — http to a loopback address, which section 5.3.2.2
// item 8 excepts for native clients.
function redirectUriAllowed(uri) {
  log.debug("Entering redirectUriAllowed().");
  if (httpsUri(uri)) {
    log.debug("Leaving redirectUriAllowed(). https.");
    return true;
  }
  let loopback = false;
  try {
    const url = new URL(String(uri));
    loopback = url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].indexOf(url.hostname) >= 0;
  } catch (e) {
    log.debug("Caught in redirectUriAllowed(): " + ((e && e.message) || e));
    // Not a URL: not a loopback one.
    loopback = false;
  }
  log.debug("Leaving redirectUriAllowed(). loopback=" + loopback);
  return fapi2() && loopback;
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
  if (!redirectUriAllowed(q.redirect_uri)) {
    log.debug("Leaving authorizationRefusal(). Not https.");
    return refusal('STS-OAUTH-0574', 'invalid_request', 'redirect-uri',
                   'redirect_uri must use the https scheme (' + (fapi2()
                     ? 'FAPI 2.0 section 5.3.2.2 item 8; http is allowed ' +
                       'only to a loopback address'
                     : 'section 5.2.2 item 20') + ')');
  }
  // Baseline item 7 for every client; Advanced relaxes it to a pushed request
  // (Part 2 section 5.2.2's exception, and item 18). A challenge that IS sent
  // is still held to S256 under both.
  const pkceAsked = fapi2() || !advanced() || !!ctx.pushed;
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
  if (fapi2() && responseTypeOf(q.response_type) !== 'code') {
    log.debug("Leaving authorizationRefusal(). Not code.");
    return refusal('STS-OAUTH-0582', 'unsupported_response_type',
                   'response-type',
                   'response_type "' + String(q.response_type || '') +
                   '" is not code, the only one this profile allows (FAPI ' +
                   '2.0 section 5.3.2.2 item 1)');
  }
  // FAPI 2.0 Message Signing section 5.4.2 item 1 (#141): JARM, required.
  if (messageSigning() &&
      JARM_MODES.indexOf(String(q.response_mode || '')) < 0) {
    log.debug("Leaving authorizationRefusal(). Not JARM.");
    return refusal('STS-OAUTH-0591', 'invalid_request', 'jarm-required',
                   'response_mode "' + String(q.response_mode || '') + '" ' +
                   'is not a JWT-secured one; this profile requires JARM ' +
                   '(FAPI 2.0 Message Signing section 5.4.2 item 1) — ' +
                   'response_mode=jwt');
  }
  if (advanced()) {
    const type = responseTypeOf(q.response_type);
    const jarm = JARM_MODES.indexOf(String(q.response_mode || '')) >= 0;
    // `code` IS a response type this profile allows; with a response mode
    // that is not JARM, the MODE is what is wrong, so it is invalid_request
    // rather than unsupported_response_type (#187: the OpenID conformance
    // suite's ensure-response-mode-query module at PAR, which RFC 9126
    // section 2.3 answers with invalid_request).
    if (type === 'code' && !jarm) {
      log.debug("Leaving authorizationRefusal(). code without JARM.");
      return refusal('STS-OAUTH-0708', 'invalid_request', 'response-type',
                     'response_type "code" is allowed only with ' +
                     'response_mode=jwt (JARM), and this request\'s ' +
                     'response_mode is "' + String(q.response_mode || '') +
                     '" (Part 2 section 5.2.2 item 2)');
    }
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
  // A REQUEST NAMING NO SCOPE, under FAPI 1.0 Advanced (#187). Part 2
  // section 5.2.2 item 10 has the authorization server use only the
  // parameters of the signed request object, and RFC 6749 section 3.3 lets
  // it either apply a default or fail a request with no scope. This one
  // fails it: a signed request whose object names no scope is, far more
  // often than not, a client that put scope outside the object (section
  // 5.2.3 item 8), and serving it with a default would grant something the
  // signed request never asked for. The OpenID conformance suite's
  // ensure-request-object-without-scope-fails module expects the refusal.
  if (advanced() && !fapi2() && !String(q.scope || '').trim()) {
    log.debug("Leaving authorizationRefusal(). No scope.");
    return refusal('STS-OAUTH-0709', 'invalid_request', 'scope-required',
                   'the request names no scope; under this profile only ' +
                   'the parameters of the signed request object are used ' +
                   '(Part 2 section 5.2.2 item 10), so scope belongs in it, ' +
                   'and RFC 6749 section 3.3 lets this server refuse a ' +
                   'request without one rather than apply a default');
  }
  // FAPI 1.0's two parameter rules; FAPI 2.0 leans on PKCE instead.
  if (fapi2()) {
    log.debug("Leaving authorizationRefusal(). Allowed (FAPI 2.0).");
    return null;
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
  const allowed = (advanced() || fapi2()) ? ADVANCED_METHODS
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
                     'supports none (' + (fapi2() ? 'FAPI 2.0 section ' +
                     '5.3.2.1 item 3' : 'Part 2 section 5.2.2 item 16') + ')'
                   : 'this client authenticates with ' + used + ', and a ' +
                     'confidential client must use ' +
                     allowed.filter(function (one) {
                       return one !== 'none';
                     }).join(', ') + ' (' + (fapi2()
                       ? 'FAPI 2.0 section 5.3.2.1 item 6'
                       : (advanced() ? 'Part 2 section 5.2.2 item 14'
                                     : 'section 5.2.2 item 4')) + ')');
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
  const methods = (advanced() || fapi2()) ? ADVANCED_METHODS
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
  // FAPI-CIBA (#142): push is not a delivery mode this profile allows.
  if (String(meta.backchannel_token_delivery_mode || '') === 'push') {
    log.debug("Leaving registrationRefusal(). CIBA push.");
    return refusal('STS-REG-0198', 'invalid_client_metadata', 'ciba-no-push',
                   'backchannel_token_delivery_mode "push" is not allowed ' +
                   'under this profile; register poll or ping (FAPI-CIBA ' +
                   'section 5.2.2 item 3)');
  }
  if (advanced() || fapi2()) {
    const problem = advancedRegistrationProblem(meta);
    if (problem) {
      log.debug("Leaving registrationRefusal(). Advanced refuses it.");
      return problem;
    }
  }
  const uris = Array.isArray(meta.redirect_uris) ? meta.redirect_uris : [];
  const plain = uris.filter(function (uri) {
    return !redirectUriAllowed(uri);
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
    const minEc = fapi2() ? FAPI2_MIN_EC_BITS : MIN_EC_BITS;
    const small = (keys[i] && keys[i].kty === 'RSA' && bits < MIN_RSA_BITS) ||
                  (keys[i] && keys[i].kty === 'EC' && bits < minEc);
    if (small) {
      log.debug("Leaving registrationRefusal(). A key is too small.");
      return refusal('STS-REG-0175', 'invalid_client_metadata', 'key-sizes',
                     'jwks key ' + (keys[i].kid ? '"' + keys[i].kid + '" '
                                                : '') +
                     'is ' + keys[i].kty + ' of ' + bits + ' bits; RSA keys ' +
                     'must be ' + MIN_RSA_BITS + ' bits or more and EC keys ' +
                     minEc + ' or more (' + (fapi2() ? 'FAPI 2.0 section ' +
                     '5.4.1 items 4-5' : 'section 5.2.2 items 5-6') + ')');
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
  const allowedTypes = fapi2() ? FAPI2_RESPONSE_TYPES
                               : ADVANCED_RESPONSE_TYPES;
  const allowedAlgs = profileSigningAlgs() || ADVANCED_SIGNING_ALGS;
  const badType = types.map(responseTypeOf).filter(function (one) {
    return allowedTypes.indexOf(one) < 0;
  });
  if (badType.length) {
    log.debug("Leaving advancedRegistrationProblem(). A response type.");
    return refusal('STS-REG-0178', 'invalid_client_metadata',
                   'response-type',
                   'response_types ' + JSON.stringify(badType) + ' is not ' +
                   'one this profile allows; it allows ' +
                   allowedTypes.join(' and ') + ' (' + (fapi2()
                     ? 'FAPI 2.0 section 5.3.2.2 item 1'
                     : 'Part 2 section 5.2.2 item 2') + ')');
  }
  for (let i = 0; i < SIGNING_ALG_MEMBERS.length; i++) {
    const value = meta[SIGNING_ALG_MEMBERS[i]];
    if (value !== undefined && value !== null && value !== '' &&
        allowedAlgs.indexOf(String(value)) < 0) {
      log.debug("Leaving advancedRegistrationProblem(). A signing alg.");
      return refusal('STS-REG-0177', 'invalid_client_metadata',
                     'algorithms',
                     SIGNING_ALG_MEMBERS[i] + ' "' + value + '" is not ' +
                     allowedAlgs.join(' or ') + ' (' + (fapi2()
                       ? 'FAPI 2.0 section 5.4.1' : 'Part 2 section 8.6') +
                     ')');
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
// ---------------------------------------------------------------------------
// FAPI-CIBA (#142), at the backchannel authentication endpoint: what a request
// needs beyond CIBA Core under any FAPI profile. `opts.mode` is the client's
// registered delivery mode and `opts.bindingMessage` the request's. Client
// authentication and the algorithms are the ordinary checks, asked by the
// endpoint through `clientAuthenticationRefusal()` and `signingAlgRefusal()`.
// ---------------------------------------------------------------------------
function cibaRefusal(opts) {
  log.debug("Entering cibaRefusal().");
  if (!enabled()) {
    log.debug("Leaving cibaRefusal(). Off.");
    return null;
  }
  const o = opts || {};
  if (String(o.mode || '') === 'push') {
    log.debug("Leaving cibaRefusal(). Push.");
    return refusal('STS-OAUTH-0662', 'unauthorized_client', 'ciba-no-push',
                   'this client registered the push delivery mode, which ' +
                   'this profile does not allow; it must register poll or ' +
                   'ping (FAPI-CIBA section 5.2.2 item 3)');
  }
  if (!String(o.bindingMessage || '')) {
    log.debug("Leaving cibaRefusal(). No binding message.");
    return refusal('STS-OAUTH-0663', 'invalid_request',
                   'ciba-binding-message',
                   'a binding_message is required: it is what binds the ' +
                   'consumption device to the approval (FAPI-CIBA section ' +
                   '5.2.2 item 2)');
  }
  log.debug("Leaving cibaRefusal(). Nothing refused.");
  return null;
}

function defaultSigningAlg() {
  log.debug("Entering defaultSigningAlg().");
  log.debug("Leaving defaultSigningAlg().");
  return (advanced() || fapi2()) ? ADVANCED_DEFAULT_SIGNING_ALG : '';
}

function signingAlgAllowed(alg) {
  log.debug("Entering signingAlgAllowed(). " + alg);
  const list = profileSigningAlgs();
  log.debug("Leaving signingAlgAllowed().");
  return !list || list.indexOf(String(alg)) >= 0;
}

// RSA1_5 is refused under FAPI 1.0 Advanced (section 8.6.1) and under 2.0,
// whose section 5.4.1 item 1 holds every JWT to RFC 8725, and RFC 8725
// section 3.2 is the one that retires RSA1_5.
function encryptionAlgAllowed(alg) {
  log.debug("Entering encryptionAlgAllowed(). " + alg);
  log.debug("Leaving encryptionAlgAllowed().");
  return !(advanced() || fapi2()) ||
         FORBIDDEN_ENCRYPTION_ALGS.indexOf(String(alg)) < 0;
}

// FAPI 2.0 section 5.3.2.1 item 13: a JWT's `iat` or `nbf` more than 60
// seconds in the future. `what` names the JWT in the sentence.
function futureTimestampRefusal(claims, what, now) {
  log.debug("Entering futureTimestampRefusal().");
  if (!fapi2()) {
    log.debug("Leaving futureTimestampRefusal(). Not FAPI 2.0.");
    return null;
  }
  const c = claims || {};
  const at = Number(now) || Math.floor(Date.now() / 1000);
  const ahead = ['iat', 'nbf'].filter(function (name) {
    return c[name] !== undefined && Number(c[name]) - at > FAPI2_MAX_FUTURE_S;
  });
  if (!ahead.length) {
    log.debug("Leaving futureTimestampRefusal(). In time.");
    return null;
  }
  log.debug("Leaving futureTimestampRefusal(). Ahead.");
  return refusal('STS-OAUTH-0590', 'invalid_request', 'jwt-timestamps',
                 what + '\'s ' + ahead.join(' and ') + ' is more than ' +
                 FAPI2_MAX_FUTURE_S + ' seconds in the future (FAPI 2.0 ' +
                 'section 5.3.2.1 item 13)');
}

// FAPI 2.0 section 5.3.2.2 items 2-4: every authorization request is pushed,
// and a push is client-authenticated.
function requiresPar() {
  log.debug("Entering requiresPar().");
  log.debug("Leaving requiresPar().");
  return fapi2();
}

function parAuthenticationRefusal(authenticated) {
  log.debug("Entering parAuthenticationRefusal().");
  if (!fapi2() || authenticated) {
    log.debug("Leaving parAuthenticationRefusal(). Allowed.");
    return null;
  }
  log.debug("Leaving parAuthenticationRefusal(). Unauthenticated.");
  return refusal('STS-OAUTH-0589', 'invalid_client', 'par-required',
                 'a pushed authorization request must authenticate its ' +
                 'client (FAPI 2.0 section 5.3.2.2 item 4)');
}

// FAPI 2.0 section 5.3.2.1 item 8: a client assertion's `aud` is the issuer,
// as a string. OAuth 2.1 mode's rule, asked for by this profile too.
function strictAssertionAudience() {
  log.debug("Entering strictAssertionAudience().");
  log.debug("Leaving strictAssertionAudience().");
  return fapi2();
}

// FAPI 2.0 section 5.3.2.1 item 9: no refresh token rotation — true when the
// profile turns it off, which `sender_constraints.js`'s `rotationRequired()`
// asks before any mode. `oauth2.refreshTokenRotation` still forces it.
function forbidsRotation() {
  log.debug("Entering forbidsRotation().");
  log.debug("Leaving forbidsRotation().");
  return fapi2();
}

// FAPI 2.0 section 5.3.2.1 item 11 and 5.3.2.2 item 12: the lifetimes a code
// and a pushed request_uri may have, given what the settings ask for.
function codeLifetimeMs(asked) {
  log.debug("Entering codeLifetimeMs().");
  const wanted = Number(asked) || 0;
  log.debug("Leaving codeLifetimeMs().");
  return fapi2() ? Math.min(wanted, FAPI2_MAX_CODE_LIFETIME_S * 1000)
                 : wanted;
}

function requestUriLifetimeS(asked) {
  log.debug("Entering requestUriLifetimeS().");
  const wanted = Number(asked) || 0;
  log.debug("Leaving requestUriLifetimeS().");
  return fapi2() ? Math.min(wanted, FAPI2_MAX_REQUEST_URI_LIFETIME_S)
                 : wanted;
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
                 (profileSigningAlgs() || []).join(' or ') + ' (' + (fapi2()
                   ? 'FAPI 2.0 section 5.4.1' : 'Part 2 section 8.6') + ')');
}

// Part 2 section 5.2.2 item 1: a signed request object is required.
function requiresSignedRequestObject() {
  log.debug("Entering requiresSignedRequestObject().");
  log.debug("Leaving requiresSignedRequestObject().");
  return advanced() || messageSigning();
}

// ---------------------------------------------------------------------------
// PART 2 SECTION 5.2.2 ITEMS 13, 15 AND 17 — a verified request object's
// claims. `issuer` is this authorization server's; `now` seconds.
// ---------------------------------------------------------------------------
function requestObjectRefusal(claims, issuer, now) {
  log.debug("Entering requestObjectRefusal().");
  // FAPI 1.0 Advanced items 13, 15, 17, and FAPI 2.0 Message Signing section
  // 5.3.2 items 2-4, which ask the same three things (#141).
  if (!advanced() && !messageSigning()) {
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
  if (!advanced() && !fapi2()) {
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
                     'token here is sender-constrained (' + (fapi2()
                       ? 'FAPI 2.0 section 5.3.2.1 item 4'
                       : 'Part 2 section 5.2.2 item 5') + ')');
}

// Section 5.2.2 item 21: the lifetime an access token may have. `bound` is
// whether it carries a cnf (DPoP or mTLS).
function accessTokenLifetime(asked, bound) {
  log.debug("Entering accessTokenLifetime().");
  const wanted = Number(asked) || 0;
  if (!v1() || bound || wanted <= MAX_UNBOUND_ACCESS_TOKEN_S) {
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
  return !v1();
}

// Whether the profile makes the consent screen compulsory — FAPI 1.0 item
// 12. FAPI 2.0 leaves consent to the ordinary rules (rcbj, #140).
function requiresConsent() {
  log.debug("Entering requiresConsent().");
  log.debug("Leaving requiresConsent().");
  return v1();
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
  const allowedMethods = (advanced() || fapi2()) ? ADVANCED_METHODS
                                    : BASELINE_METHODS.concat(['none']);
  const methods = metadata.token_endpoint_auth_methods_supported;
  if (Array.isArray(methods)) {
    metadata.token_endpoint_auth_methods_supported =
      methods.filter(function (one) {
        return allowedMethods.indexOf(one) >= 0;
      });
  }
  if (advanced() || fapi2()) {
    const types = fapi2() ? FAPI2_RESPONSE_TYPES : ADVANCED_RESPONSE_TYPES;
    const algs = profileSigningAlgs() || [];
    if (Array.isArray(metadata.response_types_supported)) {
      metadata.response_types_supported = metadata.response_types_supported
        .filter(function (one) {
          return types.indexOf(responseTypeOf(one)) >= 0;
        });
    }
    SIGNING_ALG_LISTS.concat(fapi2() ? ['dpop_signing_alg_values_supported']
                                     : []).forEach(function (name) {
      if (Array.isArray(metadata[name])) {
        metadata[name] = metadata[name].filter(function (one) {
          return algs.indexOf(one) >= 0;
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
    if (advanced() || messageSigning()) {
      metadata.require_signed_request_object = true;
    }
    if (messageSigning() &&
        Array.isArray(metadata.response_modes_supported)) {
      metadata.response_modes_supported = metadata.response_modes_supported
        .filter(function (one) {
          return JARM_MODES.indexOf(one) >= 0;
        });
    }
    if (fapi2()) {
      metadata.require_pushed_authorization_requests = true;
    }
  }
  // FAPI-CIBA (#142), under every profile: poll and ping only.
  if (Array.isArray(metadata.backchannel_token_delivery_modes_supported)) {
    metadata.backchannel_token_delivery_modes_supported =
      metadata.backchannel_token_delivery_modes_supported
        .filter(function (one) {
          return one !== 'push';
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
    specification: on === MESSAGE_SIGNING
      ? MESSAGE_SIGNING_NAME + ', over ' + FAPI2_NAME
      : on === FAPI2 ? FAPI2_NAME
      : (on === ADVANCED ? ADVANCED_NAME + ', over ' + BASELINE : BASELINE),
    url: on === MESSAGE_SIGNING ? MESSAGE_SIGNING_URL
      : on === FAPI2 ? FAPI2_URL
      : (on === ADVANCED ? ADVANCED_URL : BASELINE_URL),
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
    requirements: (on === FAPI2 || on === MESSAGE_SIGNING)
      ? FAPI2_REQUIREMENTS.map(function (row) {
        return { id: row.id, section: 'FAPI 2.0 ' + row.section,
                 level: row.level, enforced: row.enforced, title: row.title,
                 note: row.note };
      }).concat(on === MESSAGE_SIGNING
        ? MESSAGE_SIGNING_REQUIREMENTS.map(function (row) {
          return { id: row.id,
                   section: 'FAPI 2.0 Message Signing ' + row.section,
                   level: row.level, enforced: row.enforced,
                   title: row.title, note: row.note };
        }) : [])
      : REQUIREMENTS.map(function (row) {
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
  FAPI2: FAPI2,
  MESSAGE_SIGNING: MESSAGE_SIGNING,
  MESSAGE_SIGNING_REQUIREMENTS: MESSAGE_SIGNING_REQUIREMENTS,
  FAPI2_SIGNING_ALGS: FAPI2_SIGNING_ALGS,
  FAPI2_REQUIREMENTS: FAPI2_REQUIREMENTS,
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
  fapi2: fapi2,
  messageSigning: messageSigning,
  v1: v1,
  profileSigningAlgs: profileSigningAlgs,
  redirectUriAllowed: redirectUriAllowed,
  futureTimestampRefusal: futureTimestampRefusal,
  requiresPar: requiresPar,
  parAuthenticationRefusal: parAuthenticationRefusal,
  strictAssertionAudience: strictAssertionAudience,
  forbidsRotation: forbidsRotation,
  codeLifetimeMs: codeLifetimeMs,
  requestUriLifetimeS: requestUriLifetimeS,
  requiresConsent: requiresConsent,
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
  cibaRefusal: cibaRefusal,
  clientIdentifierRefusal: clientIdentifierRefusal,
  keyBits: keyBits,
  registrationRefusal: registrationRefusal,
  accessTokenLifetime: accessTokenLifetime,
  alwaysReturnsScope: alwaysReturnsScope,
  honoursGlobalConsent: honoursGlobalConsent,
  applyToMetadata: applyToMetadata,
  state: state
};
