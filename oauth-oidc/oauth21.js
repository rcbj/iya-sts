'use strict';
//
// File: oauth21.js
//
// ===========================================================================
// THE OAUTH 2.1 AUTHORIZATION FRAMEWORK — AS A MODE (2026-09-13).
//
// draft-ietf-oauth-v2-1-16, which is still an Internet-Draft: the working group
// has it down for the IESG in December 2026. Every row below cites that
// revision by name, because a draft moves and a compliance report that said
// "OAuth 2.1" with no revision would be a claim about a document that does not
// exist yet.
//
// `oauth2.oauth21` turns it on, and ON IT IMPLIES `oauth2.rfc9700`:
// `oauth2_bcp.js`'s `enabled()` answers true for either. That is not a
// convenience. OAuth 2.1 section 10 describes itself as OAuth 2.0 "with the
// extensions and restrictions from known best current practices applied", and
// almost every one of those restrictions is already a row in RFC 9700 mode —
// no implicit grant, no password grant, exact redirect matching, S256 only, the
// PKCE downgrade, single-use codes, `iss`, no token in a query string, refresh
// rotation, 303 rather than 307. Enforcing them twice would be two answers to
// one question, and the second would be the one nobody updated.
//
// So this file holds the DIFFERENCE, and the difference has two halves:
//
//   * where 2.1 is STRICTER than RFC 9700 mode — PKCE for confidential clients,
//     a client that must be registered, a presented credential that must
//     verify, a JWT client assertion addressed to the issuer alone, no SAML
//     client authentication, a repeated parameter, a code that lives ten
//     minutes, `error_description`'s character set;
//   * where 2.1 is LOOSER, and RFC 9700 mode would refuse a client that follows
//     2.1 to the letter — `redirect_uri` removed from the token request
//     (section 10.2) and optional at the authorization endpoint when one is
//     registered (section 4.1.1). THIS IS THE HALF THAT MAKES IT A MODE OF ITS
//     OWN rather than a relabelling of the other one.
//
// ---------------------------------------------------------------------------
// IT IS A LEAF (rule 3, and `oauth-oidc/CLAUDE.md` rule 3ah).
//
// It registers no route and requires `helpers.js` and `config.js` and nothing
// else. `oauth2_bcp.js` requires IT — for its own `enabled()`, the two places
// RFC 9700 mode has to step aside, and the stricter checks that ride inside
// its own (PKCE, the registered-URI rule, registration, the metadata) —
// `sender_constraints.js` requires it (#34), and `oauth2.js` requires it for
// the rest — so it must never require any of those back, nor
// `applications.js` or `client_auth.js`, which `oauth2_bcp.js` already
// requires. Every record it decides about is PASSED IN: the client's
// configuration, the authorization code, what the request presented, what the
// observation found.
//
// THE SPLIT IS `oauth2_bcp.js`'s: this decides and says why, and never touches
// `res`. A refusal is
// `{ ok: false, errorCode, error, requirement, description }` and `oauth2.js`
// chooses what it looks like on the wire.
// ===========================================================================

const { log } = require('../common/helpers');
const config = require('../common/config');

const DRAFT = 'draft-ietf-oauth-v2-1-16';
const DRAFT_URL = 'https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/16/';
// Section 2.4 makes this one mandatory for JWT client authentication, so it is
// cited beside the framework rather than folded into it.
const AUDIENCE_DRAFT = 'draft-ietf-oauth-rfc7523bis-11';

// Section 4.1.2: "A maximum authorization code lifetime of 10 minutes is
// RECOMMENDED." A cap rather than a new setting, because the setting that
// decides a code's lifetime already exists and a mode that invented a second
// one would be two answers to "how long does a code live".
const MAX_CODE_TTL_MS = 10 * 60 * 1000;

// The grants the registered-client rule applies to. Each is a grant a CLIENT
// makes in its own name after an authorization this server gave it, or asks for
// in its own name outright. What is left out is left out on purpose and is on
// the report: OpenID4VCI's pre-authorized code is anonymous access by that
// specification's design, and the two assertion grants authenticate the
// SUBJECT with a signature and may arrive with no client at all.
const REGISTERED_CLIENT_GRANTS = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:token-exchange'
];

// Parameters the specifications that define them say may repeat. Everything
// else is refused when repeated (sections 3.1 and 3.2).
const REPEATABLE_PARAMETERS = ['resource', 'audience'];

// ---------------------------------------------------------------------------
// THE TABLE, in `oauth2_bcp.js`'s shape and read the same three ways: the
// checks cite a row by id, `GET /oauth2/oauth21` publishes it, and the coverage
// note on /admin/sts-metadata was written from it.
//
// `enforced` is that file's vocabulary with one addition:
//   'yes'       — refused when the mode is on
//   'always'    — true in every mode, and listed so nobody has to read the code
//   'inherited' — enforced by RFC 9700 mode, which this mode turns on; the row
//                 names the RFC 9700 row that does it
//   'no'        — not enforced, and `note` says why
// ---------------------------------------------------------------------------
const REQUIREMENTS = [
  { id: 'implies-rfc9700', section: '10', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'inherited',
    title: 'The best current practices OAuth 2.1 consolidates are applied',
    note: 'oauth2.oauth21 turns RFC 9700 mode on. The implicit grant and ' +
          'every response type naming token (no-implicit), the password ' +
          'grant (no-ropc), exact redirect URI matching ' +
          '(redirect-exact-match), S256 only (pkce-s256), the PKCE downgrade ' +
          '(pkce-downgrade), single-use codes with revocation on a valid ' +
          'replay (code-single-use), iss on every authorization response ' +
          '(iss-parameter), no access token in a query string ' +
          '(no-token-in-query), refresh token rotation (refresh-rotation), ' +
          '303 rather than 307 (no-307-redirect), exact metadata — all ' +
          'enforced there, and GET /oauth2/rfc9700 lists them.' },

  { id: 'token-redirect-uri-optional', section: '10.2, 4.1.3', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'Accept a token request with no redirect_uri',
    note: 'THE ROW THAT MAKES THIS A MODE OF ITS OWN. RFC 6749 section 4.1.3 ' +
          'required redirect_uri at the token endpoint, and RFC 9700 mode ' +
          'enforces that (transaction-bound, STS-OAUTH-0147). OAuth 2.1 ' +
          'removed the parameter because PKCE binds the code instead, so a ' +
          'client following 2.1 alone never sends it. Section 10.2 still ' +
          'requires a server that supports both kinds of client to accept it ' +
          'and enforce it when it IS sent, which this does in every mode. ' +
          'The one exception is a code minted under the OpenID Connect nonce ' +
          'exemption below: it has no PKCE, so redirect_uri is still the ' +
          'binding and is still required.' },

  { id: 'authorize-redirect-uri-default', section: '4.1.1, 2.3.2',
    level: 'MUST', appliesTo: 'authorization server', enforced: 'yes',
    title: 'redirect_uri is optional when exactly one is registered',
    note: 'A request with no redirect_uri from a client with ONE registered ' +
          'URI is answered at that URI; with several it is refused, because ' +
          'section 4.1.1 makes the parameter REQUIRED then. The registered ' +
          'value is checked against the same allowlist a presented one is ' +
          'before it is used, because an ldapmodify can put anything on an ' +
          'entry and a default nobody presented is still an address a ' +
          'browser is sent to.' },

  { id: 'registered-client-required', section: '2.3.1, 2.5', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A client must have registered its complete redirect URI',
    note: 'Section 2.3.1: "Authorization servers MUST require clients to ' +
          'register their complete redirect URI". A client with no ' +
          'oauthRedirectUri of its own is refused at the authorization ' +
          'endpoint as a 400 on this server, never redirected — whether it ' +
          'was never seen, was only SIGHTED, or holds only addresses product ' +
          'mode is withholding as unconfirmed. oauth2.redirectUris, the ' +
          'service-wide list RFC 9700 mode falls back to, is NOT consulted: ' +
          'a list every client may use is the opposite of a URI a client ' +
          'registered. A post_logout_redirect_uri likewise needs a client ' +
          'with its own oauthPostLogoutRedirectUri.' },

  { id: 'declared-client-at-token-endpoint', section: '2.5, 3.2.1',
    level: 'MUST', appliesTo: 'authorization server', enforced: 'yes',
    title: 'A token request naming a client must name one this service holds',
    note: 'Refused with invalid_client for authorization_code, ' +
          'refresh_token, client_credentials and token exchange when the ' +
          'client_id names an entry that DECLARES nothing — only what a ' +
          'sighting writes. Sighting is how every client used to get an ' +
          'entry here, so "has an entry" is not "is registered"; declared ' +
          'means an RFC 7591 registration, a redirect URI, an authentication ' +
          'method, a credential, an assertion issuer or a declared protocol ' +
          'family. NOT APPLIED, deliberately: the OpenID4VCI pre-authorized ' +
          'code grant (anonymous access by that specification\'s design) and ' +
          'the RFC 7523 / RFC 7522 assertion grants, whose subject is ' +
          'authenticated by a signature and which may arrive with no client ' +
          'at all.' },

  { id: 'client-authentication-when-presented', section: '3.2.2, 2.4',
    level: 'MUST', appliesTo: 'authorization server', enforced: 'yes',
    title: 'A credential that is presented must verify',
    note: 'Section 3.2.2: the authorization server MUST "authenticate the ' +
          'client if client authentication is included". RFC 9700 mode lets ' +
          'a secret or an assertion from a public client, an unknown client ' +
          'or a confidential client with nothing on file through unchecked; ' +
          'this mode refuses it, because a credential the server cannot ' +
          'check is one a client believes was checked. And section 2.4: a ' +
          'client MUST NOT use more than one method in a request — Basic and ' +
          'a body secret, or either beside a client_assertion — which is ' +
          'refused with invalid_request rather than one of them being ' +
          'preferred silently, at the token endpoint and at ' +
          '/oauth2/introspect alike.' },

  { id: 'client-credentials-confidential-only', section: '4.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'The client credentials grant is for confidential clients only',
    note: 'Section 4.2: "The client credentials grant type MUST only be used ' +
          'by confidential clients" and "The authorization server MUST ' +
          'authenticate the client." A request that did not authenticate — a ' +
          'public client, an unknown one, one with nothing on file — is ' +
          'refused with invalid_client.' },

  { id: 'pkce-required', section: '4.1.1, 4.1.2.1, 7.5.1.1', level: 'MUST',
    appliesTo: 'client (enforced by this server)', enforced: 'yes',
    title: 'PKCE for every client, confidential ones included',
    note: 'RFC 9700 makes PKCE a SHOULD for a confidential client and that ' +
          'mode only logs one that omits it. Section 7.5.1.1 makes it ' +
          'REQUIRED and the server MUST enforce it "unless both of the ' +
          'following criteria are met: the client is a confidential client; ' +
          'there is reasonable assurance by the authorization server that ' +
          'the client implements the OpenID Connect nonce mechanism ' +
          'properly". The assurance read here is: a credential ON FILE (not ' +
          'merely a confidential method — a client declaring one with ' +
          'nothing to check is no assurance of anything), an openid scope ' +
          'and a nonce. A code minted under that exemption is marked and ' +
          'redeemed only by a client that authenticated. A code with no ' +
          'challenge and no exemption is refused at the token endpoint too, ' +
          'which is section 4.1.3\'s last bullet.' },

  { id: 'pkce-method-required', section: '4.1.1', level: 'MUST',
    appliesTo: 'client (enforced by this server)', enforced: 'yes',
    title: 'code_challenge_method is REQUIRED',
    note: 'RFC 7636 defaulted an absent method to plain; section 4.1.1 makes ' +
          'it REQUIRED and section 7.5.2 forbids plain outright. A challenge ' +
          'with no method is refused as missing the method, rather than ' +
          'being read as plain and refused as plain — which is true and ' +
          'sends a client author looking for a value they never sent.' },

  { id: 'client-assertion-audience', section: '2.4 (' + AUDIENCE_DRAFT +
    ' section 4, item 3b)', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A JWT client assertion names the issuer as its sole audience',
    note: 'Section 2.4 requires the updated audience guidance: for CLIENT ' +
          'AUTHENTICATION the aud "MUST use the issuer identifier of the ' +
          'authorization server as its sole value", the token endpoint URL ' +
          'MUST NOT be used, and the server MUST reject anything else. Every ' +
          'other mode here accepts the token endpoint URL, the issuer or the ' +
          'base, and an array containing any of them. The assertion GRANTS ' +
          'are unchanged — that draft still allows the issuer or the token ' +
          'endpoint there. An explicit typ of client-authentication+jwt is ' +
          'NOT required: the same draft says servers are NOT RECOMMENDED to ' +
          'reject its absence.' },

  { id: 'no-saml-client-authentication', section: '2.4 (' + AUDIENCE_DRAFT +
    ' section 3)', level: 'MUST NOT',
    appliesTo: 'client (enforced by this server)', enforced: 'yes',
    title: 'No SAML bearer assertions for client authentication',
    note: 'That draft: "SAML Bearer Assertions MUST NOT be used for client ' +
          'authentication for any new applications." saml2_bearer client ' +
          'authentication is refused with invalid_client, dropped from ' +
          'token_endpoint_auth_methods_supported, and refused at ' +
          'registration. The RFC 7522 GRANT — a SAML assertion naming the ' +
          'person a token is for — is a different use and is untouched.' },

  { id: 'client-secret-brute-force', section: '2.4.1', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'Protect an endpoint that checks a client secret against guessing',
    note: 'Section 2.4.1: "the authorization server MUST protect any ' +
          'endpoint utilizing it against brute force attacks." Applied ' +
          'wherever this service CHECKS a client secret — RFC 9700 mode, ' +
          'this mode and product mode — and not only here, because a secret ' +
          'that is checked unthrottled is the same weakness in every mode. ' +
          'Only FAILED authentications are counted, per realm, per client_id ' +
          'and client address together (so nobody elsewhere can lock a ' +
          'client out), under security.rateLimitWindowS and ' +
          'security.rateLimitPerIdentity; the answer is a 429 with ' +
          'Retry-After.' },

  { id: 'no-repeated-parameters', section: '3.1, 3.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A request parameter must not be repeated',
    note: 'Sections 3.1 and 3.2: "Request and response parameters defined by ' +
          'this specification MUST NOT be included more than once." Refused ' +
          'at the authorization and token endpoints with invalid_request. ' +
          'resource (RFC 8707) and audience (RFC 8693) may repeat, because ' +
          'the specifications that define them say so.' },

  { id: 'loopback-any-port', section: '4.1.1, 8.4.2', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A loopback redirect URI may use any port',
    note: 'Section 8.4.2: "The authorization server MUST allow any port to ' +
          'be specified at the time of the request for loopback IP redirect ' +
          'URIs." RFC 9700 mode honours oauth2.loopbackPortWildcard, which ' +
          'may be turned off to show a native client failing against a ' +
          'server that got this wrong; this mode ignores that setting, ' +
          'because a compliance mode with a switch that makes it ' +
          'non-compliant is not one.' },

  { id: 'code-lifetime', section: '4.1.2', level: 'RECOMMENDED',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'An authorization code lives at most ten minutes',
    note: 'Section 4.1.2: a code "MUST expire shortly after it is issued" ' +
          'and "a maximum authorization code lifetime of 10 minutes is ' +
          'RECOMMENDED." A code is minted with the smaller of ' +
          'oauth2.authorizationCodeTtlS and six hundred seconds.' },

  { id: 'error-description-charset', section: '3.2.4, 4.1.2.1', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'error_description uses only the characters the grammar allows',
    note: 'Values "MUST NOT include characters outside the set %x20-21 / ' +
          '%x23-5B / %x5D-7E" — no double quote, no backslash, nothing ' +
          'outside ASCII. This service writes long, punctuated descriptions ' +
          'with em dashes in them, and every mode sends them as written; ' +
          'this mode replaces what the grammar forbids on the way out, and ' +
          'the full sentence still goes to the log.' },

  { id: 'private-use-redirect-schemes', section: '8.4.3, 2.3.1',
    level: 'SHOULD', appliesTo: 'authorization server', enforced: 'always',
    title: 'Private-use URI scheme redirects, named for a domain in reverse',
    note: 'Accepted in every mode since 2026-09-13 ' +
          '(com.example.app:/callback), and a scheme with no period is ' +
          'refused in every mode, which is section 2.3.1\'s SHOULD and also ' +
          'what stops localhost:3000/cb — typed without http:// — parsing as ' +
          'a scheme called localhost. response_mode=form_post to one is ' +
          'refused: an operating system hands a protocol handler a URL, ' +
          'never a request body.' },

  { id: 'refresh-scope-identical', section: '4.3.3', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'always',
    title: 'A rotated refresh token carries the scope of the one presented',
    note: 'Since 2026-09-13 in every mode: a refresh that narrows its scope ' +
          'or its resources narrows the ACCESS token it mints, and the new ' +
          'refresh token carries what the presented one carried. RFC 6749 ' +
          'section 6 says the same sentence.' },

  // #34 (2026-09-15). The row this issue was opened to settle: section 4.3.1
  // is the one place either specification says anything MUST be done about a
  // refresh token, and DPoP is one of two ways to do it rather than the
  // requirement itself.
  { id: 'refresh-public-rotation', section: '4.3.1', level: 'MUST',
    appliesTo: 'authorization server', enforced: 'yes',
    title: 'A public client\'s refresh token is sender-constrained OR ' +
           'rotated with replay detection',
    note: 'A CHOICE OF TWO, and this service takes the second: every refresh ' +
          'token rotates on use, a replayed one is refused, and the whole ' +
          'family descended from the original grant is revoked — ' +
          '`refresh-rotation` and `refresh-replay-family` in the RFC 9700 ' +
          'report are where it happens. **Neither this section nor RFC 9700 ' +
          'requires DPoP**; `oauth2.refreshTokenRequireDpop` and ' +
          '`oauth2.refreshTokenRequireMtls` are how an operator asks for the ' +
          'first way as well, and both are off unless set. Rotation covers ' +
          'EVERY client here rather than public ones alone, because this ' +
          'server cannot authenticate a client it did not register and ' +
          '"public" is the safe reading of an unknown one. **An UNDECLARED ' +
          'client gets no refresh token at all in this mode** — see ' +
          '`declared-client-at-token-endpoint`, which section 2.3.1 already ' +
          'required and which this row depends on: rotation detects the ' +
          'replay of a token belonging to somebody, and a client nobody ' +
          'declared is nobody.' }
];

function enabled() {
  log.debug("Entering enabled().");
  log.debug("Leaving enabled().");
  return !!config.value('oauth2.oauth21');
}

function refusal(errorCode, error, requirement, description) {
  log.debug("Entering refusal(). " + errorCode);
  log.debug("Leaving refusal().");
  return { ok: false, errorCode: errorCode, error: error,
           requirement: requirement,
           description: 'OAuth 2.1 (' + DRAFT + ') ' + description };
}

function hasScope(scope, value) {
  log.debug("Entering hasScope().");
  log.debug("Leaving hasScope().");
  return String(scope || '').split(/\s+/).indexOf(value) >= 0;
}

// ---------------------------------------------------------------------------
// THE AUTHORIZATION ENDPOINT.
// ---------------------------------------------------------------------------

// The refusal for a client with no redirect URI of its own. Null when it has
// one. `client` is `applications.clientConfigOf()`'s answer, and its
// `unconfirmed_redirect_uris` is what product mode withheld — named in the
// sentence, because "you have no redirect URI" is false of an entry that holds
// three nobody has confirmed.
function registeredClientRefusal(client, clientId) {
  log.debug("Entering registeredClientRefusal(). client=" + clientId);
  const own = client && Array.isArray(client.redirect_uris)
    ? client.redirect_uris : [];
  if (own.length) {
    log.debug("Leaving registeredClientRefusal(). It has " + own.length + ".");
    return null;
  }
  const withheld = client && Array.isArray(client.unconfirmed_redirect_uris)
    ? client.unconfirmed_redirect_uris : [];
  if (withheld.length) {
    log.debug("Leaving registeredClientRefusal(). Only unconfirmed ones.");
    return refusal('STS-OAUTH-0272', 'invalid_request',
      'registered-client-required',
      'section 2.3.1: a client must have registered its complete redirect ' +
      'URI. Client "' + clientId + '" holds ' + withheld.length + ' ' +
      'redirect URI(s) this service observed and nobody has confirmed (' +
      withheld.join(', ') + '), and product mode does not believe an ' +
      'observed address. Confirm the one it should use on ' +
      '/admin/applications, or POST /admin-api/applications/confirm-address.');
  }
  log.debug("Leaving registeredClientRefusal(). None at all.");
  return refusal('STS-OAUTH-0271', 'invalid_request',
    'registered-client-required',
    'section 2.3.1: "Authorization servers MUST require clients to register ' +
    'their complete redirect URI." Client "' + (clientId || '') + '" has ' +
    ((client && client.known) ? 'an entry here with no redirect URI on it'
                              : 'no entry here at all') + '. ' +
    'Register it at POST /oauth2/register with its redirect_uris, or give ' +
    'its application entry an oauthRedirectUri on /admin/applications. The ' +
    'service-wide oauth2.redirectUris list is not consulted in this mode.');
}

// Which URI to answer at when the request named none. Section 4.1.1: OPTIONAL
// if exactly one is registered and REQUIRED if several are. The caller checks
// the answer against the redirect allowlist before using it — this file cannot
// require the module that holds it, and a default is still an address a
// browser is sent to.
function defaultRedirectUri(client, clientId) {
  log.debug("Entering defaultRedirectUri(). client=" + clientId);
  const own = client && Array.isArray(client.redirect_uris)
    ? client.redirect_uris : [];
  if (own.length === 1) {
    log.debug("Leaving defaultRedirectUri(). The one registered.");
    return { ok: true, uri: String(own[0]) };
  }
  if (own.length > 1) {
    log.debug("Leaving defaultRedirectUri(). Several registered.");
    return refusal('STS-OAUTH-0273', 'invalid_request',
      'authorize-redirect-uri-default',
      'section 4.1.1: redirect_uri is REQUIRED when a client has registered ' +
      'more than one, and client "' + clientId + '" has ' + own.length +
      '. Send the one this request should be answered at.');
  }
  log.debug("Leaving defaultRedirectUri(). None registered.");
  return registeredClientRefusal(client, clientId);
}

// Whether this request needs PKCE, and if it does not, why. `confidential` is
// the caller's answer to "a confidential method AND a credential on file to
// check it against", because that is what makes the OpenID Connect nonce an
// assurance rather than a hope. Answers `{ ok: true, exempt: '' }`, `{ ok:
// true, exempt: 'oidc-nonce' }`, or a refusal.
function pkceDecision(opts) {
  log.debug("Entering pkceDecision().");
  const query = opts.query || {};
  const types = opts.types || [];
  if (types.indexOf('code') < 0) {
    log.debug("Leaving pkceDecision(). No code is issued.");
    return { ok: true, exempt: '' };
  }
  if (query.code_challenge) {
    // THE RAW VALUE: the code record stores `|| 'plain'`, which would read a
    // missing method as a present one.
    if (query.code_challenge_method === undefined ||
        String(query.code_challenge_method) === '') {
      log.debug("Leaving pkceDecision(). A challenge with no method.");
      return refusal('STS-OAUTH-0276', 'invalid_request',
        'pkce-method-required',
        'section 4.1.1: code_challenge_method is REQUIRED — send ' +
        'code_challenge_method=S256. RFC 7636 read an absent method as ' +
        'plain; OAuth 2.1 removed that default and forbids plain (section ' +
        '7.5.2).');
    }
    log.debug("Leaving pkceDecision(). PKCE is in use.");
    return { ok: true, exempt: '' };
  }
  if (opts.confidential && hasScope(query.scope, 'openid') && query.nonce) {
    log.debug("Leaving pkceDecision(). The OpenID Connect nonce exemption.");
    return { ok: true, exempt: 'oidc-nonce' };
  }
  const missing = [];
  if (!opts.confidential) {
    missing.push('the client is not confidential with a credential on file');
  }
  if (!hasScope(query.scope, 'openid')) {
    missing.push('the request is not OpenID Connect (no openid scope)');
  }
  if (!query.nonce) {
    missing.push('the request carries no nonce');
  }
  log.debug("Leaving pkceDecision(). PKCE is required.");
  return refusal('STS-OAUTH-0275', 'invalid_request', 'pkce-required',
    'section 7.5.1.1: code_challenge and code_verifier are REQUIRED for ' +
    'every ' +
    'client, confidential ones included, unless a confidential client is ' +
    'relying on the OpenID Connect nonce instead — and here ' +
    missing.join(', and ') + '. Send code_challenge with ' +
    'code_challenge_method=S256.');
}

// The code-record fields this mode adds, so the one place a code is minted
// does not have to know which ones they are.
function codeRecordFields(query, types) {
  log.debug("Entering codeRecordFields().");
  if (!enabled()) {
    log.debug("Leaving codeRecordFields(). The mode is off.");
    return {};
  }
  const issuesCode = (types || []).indexOf('code') >= 0;
  log.debug("Leaving codeRecordFields().");
  return {
    // A code with no challenge can only have got past pkceDecision() by the
    // nonce exemption, so that is what it is marked as. Recomputed rather than
    // carried from the first pass, because the authorization request runs
    // through the endpoint twice and the second pass is the one that mints.
    pkce_exempt: issuesCode && !(query && query.code_challenge)
      ? 'oidc-nonce' : ''
  };
}

// The lifetime to mint a code with.
function codeTtlMs(configuredMs) {
  log.debug("Entering codeTtlMs().");
  const configured = Number(configuredMs);
  if (!enabled() || !(configured > 0)) {
    log.debug("Leaving codeTtlMs(). As configured.");
    return configuredMs;
  }
  log.debug("Leaving codeTtlMs().");
  return Math.min(configured, MAX_CODE_TTL_MS);
}

// ---------------------------------------------------------------------------
// THE TOKEN ENDPOINT.
// ---------------------------------------------------------------------------

// Whether RFC 6749's token-request redirect_uri is still required of this
// code. Every mode but this one: yes. This mode: only for a code minted under
// the nonce exemption, which has no PKCE to bind it.
function tokenRedirectUriRequired(record) {
  log.debug("Entering tokenRedirectUriRequired().");
  if (!enabled()) {
    log.debug("Leaving tokenRedirectUriRequired(). The mode is off.");
    return true;
  }
  log.debug("Leaving tokenRedirectUriRequired().");
  return !!(record && record.pkce_exempt);
}

// Section 4.1.3's last bullet, and the second half of the exemption.
function tokenCodeRefusal(opts) {
  log.debug("Entering tokenCodeRefusal().");
  const record = opts.record || {};
  if (!enabled() || record.code_challenge) {
    log.debug("Leaving tokenCodeRefusal(). Nothing to refuse.");
    return null;
  }
  if (record.pkce_exempt !== 'oidc-nonce') {
    log.debug("Leaving tokenCodeRefusal(). No challenge and no exemption.");
    return refusal('STS-OAUTH-0277', 'invalid_grant', 'pkce-required',
      'section 4.1.3: "If there was no code_challenge in the authorization ' +
      'request associated with the authorization code in the token request, ' +
      'the authorization server MUST reject the token request." This code ' +
      'was issued without one — before this mode was turned on, or by ' +
      'another mode. Start a new authorization request with PKCE.');
  }
  if (!opts.authenticated) {
    log.debug("Leaving tokenCodeRefusal(). Exempt, and unauthenticated.");
    return refusal('STS-OAUTH-0277', 'invalid_grant', 'pkce-required',
      'section 7.5.1.1: this code was issued without PKCE to a confidential ' +
      'client relying on the OpenID Connect nonce, and a code like that is ' +
      'redeemed only by that client authenticating — which this request did ' +
      'not.');
  }
  log.debug("Leaving tokenCodeRefusal(). Exempt and authenticated.");
  return null;
}

// How many client authentication methods a request carried. `presented` is
// what the endpoint read: a Basic header, a body secret, a client assertion.
function multipleMethodsRefusal(presented) {
  log.debug("Entering multipleMethodsRefusal().");
  if (!enabled()) {
    log.debug("Leaving multipleMethodsRefusal(). The mode is off.");
    return null;
  }
  const p = presented || {};
  const methods = [];
  if (p.basic) {
    methods.push('an Authorization: Basic header');
  }
  if (p.bodySecret) {
    methods.push('client_secret in the body');
  }
  if (p.assertion) {
    methods.push('a client_assertion');
  }
  if (methods.length < 2) {
    log.debug("Leaving multipleMethodsRefusal(). One or none.");
    return null;
  }
  log.debug("Leaving multipleMethodsRefusal(). " + methods.length + ".");
  return refusal('STS-OAUTH-0281', 'invalid_request',
    'client-authentication-when-presented',
    'section 2.4: "The client MUST NOT use more than one authentication ' +
    'method in each request." This one carried ' + methods.join(' and ') +
    '. Send one.');
}

// What the token endpoint decides about the CLIENT'S ENTRY, before anything
// is verified. TWO FUNCTIONS AND NOT ONE because the endpoint asks them at two
// different moments: this one before the request is recorded against the
// client's entry — a refusal for being unregistered must not be what creates
// the entry — and the one below after the credential has been observed.
function tokenClientDeclarationRefusal(opts) {
  log.debug("Entering tokenClientDeclarationRefusal().");
  if (!enabled()) {
    log.debug("Leaving tokenClientDeclarationRefusal(). The mode is off.");
    return null;
  }
  const grant = String(opts.grant || '');
  const clientId = String(opts.clientId || '');
  const registered = opts.registered || {};
  const presented = opts.presented || {};

  if (String(registered.token_endpoint_auth_method || '') === 'saml2_bearer' ||
      (presented.assertion && presented.samlAssertion)) {
    log.debug("Leaving tokenClientDeclarationRefusal(). SAML client " +
              "authentication.");
    return refusal('STS-OAUTH-0282', 'invalid_client',
      'no-saml-client-authentication',
      'section 2.4 requires ' + AUDIENCE_DRAFT + ', which says SAML Bearer ' +
      'Assertions "MUST NOT be used for client authentication for any new ' +
      'applications." Authenticate with private_key_jwt, an RFC 8705 ' +
      'certificate, or a client secret. An RFC 7522 assertion as the GRANT ' +
      'is unaffected.');
  }

  // #34 (2026-09-15): A REQUEST THAT NAMES NO CLIENT AT ALL used to skip this
  // check entirely, because the condition below opens with `clientId &&`. For
  // these four grants that is the same hole the check exists to close — the
  // refresh grant reached it with no `client_id` and was rotated as if it
  // belonged to somebody — and it is the case rcbj asked to have refused
  // rather than treated as a public client.
  if (!clientId && REGISTERED_CLIENT_GRANTS.indexOf(grant) >= 0) {
    log.debug("Leaving tokenClientDeclarationRefusal(). No client at all.");
    return refusal('STS-OAUTH-0297', 'invalid_client',
      'declared-client-at-token-endpoint',
      'sections 2.3.1 and 2.5: the ' + grant + ' grant is made by a client ' +
      'in its own name, and this request named no client at all. Send ' +
      'client_id, and register the client at POST /oauth2/register or ' +
      'declare it on /admin/applications.');
  }

  if (clientId && REGISTERED_CLIENT_GRANTS.indexOf(grant) >= 0 &&
      !registered.declared) {
    log.debug("Leaving tokenClientDeclarationRefusal(). The client declares " +
              "nothing.");
    return refusal('STS-OAUTH-0278', 'invalid_client',
      'declared-client-at-token-endpoint',
      'sections 2.3.1 and 2.5: client "' + clientId + '" ' +
      (registered.known ? 'has an entry here that was only ever SIGHTED — ' +
                          'nothing on it was registered or declared'
                        : 'is not registered here') + '. ' +
      'Register it at POST /oauth2/register, or declare it on ' +
      '/admin/applications (a redirect URI, an authentication method or a ' +
      'credential).');
  }
  log.debug("Leaving tokenClientDeclarationRefusal(). Nothing refused.");
  return null;
}

// ---------------------------------------------------------------------------
// THE TWO ASSERTION GRANTS, AND THE REFRESH TOKEN THEY MAY NOT MINT (#34,
// 2026-09-15).
//
// RFC 7523 and RFC 7522 are deliberately outside `REGISTERED_CLIENT_GRANTS`
// (see the comment above it): they authenticate the SUBJECT with a signature
// and may arrive with no client at all, so refusing them for want of a
// declared client would refuse the grant for being what it is. That stands.
//
// What does NOT stand is minting a refresh token into that arrangement while
// this mode is on. Section 4.3.1's rotation is bookkeeping about a chain
// belonging to a client, and a chain belonging to nobody cannot be checked
// against the client presenting it — `checkRefreshRequest()` would refuse
// every redemption of it for want of a `client_id` anyway, an hour later and
// with a message about RFC 6749. So:
//
//   * a client NAMED on one of these grants must be declared, like any other
//     client naming itself at this endpoint;
//   * a grant with NO client gets its access token and no refresh token, which
//     is the honest version of what the redemption would have done.
// ---------------------------------------------------------------------------
const ASSERTION_GRANTS = [
  'urn:ietf:params:oauth:grant-type:jwt-bearer',
  'urn:ietf:params:oauth:grant-type:saml2-bearer'
];

function assertionClientRefusal(opts) {
  log.debug("Entering assertionClientRefusal().");
  if (!enabled()) {
    log.debug("Leaving assertionClientRefusal(). The mode is off.");
    return null;
  }
  const o = opts || {};
  const grant = String(o.grant || '');
  const clientId = String(o.clientId || '');
  const registered = o.registered || {};
  if (clientId && ASSERTION_GRANTS.indexOf(grant) >= 0 &&
      !registered.declared) {
    log.debug("Leaving assertionClientRefusal(). Undeclared client.");
    return refusal('STS-OAUTH-0299', 'invalid_client',
      'declared-client-at-token-endpoint',
      'sections 2.3.1 and 2.5: client "' + clientId + '" ' +
      (registered.known ? 'has an entry here that was only ever SIGHTED'
                        : 'is not registered here') + ', and named itself on ' +
      'an assertion grant. The assertion may speak for the subject; the ' +
      'client naming itself still has to be one this server knows. Register ' +
      'it, declare it on /admin/applications, or send no client_id.');
  }
  log.debug("Leaving assertionClientRefusal(). Nothing refused.");
  return null;
}

// Whether a refresh token is withheld from this grant. The caller sets
// `withRefresh: false` and records STS-OAUTH-0298 on the audit row; the token
// response is otherwise untouched, and RFC 6749 section 5.1 makes
// `refresh_token` optional in it.
function withholdsRefreshToken(opts) {
  log.debug("Entering withholdsRefreshToken().");
  if (!enabled()) {
    log.debug("Leaving withholdsRefreshToken(). The mode is off.");
    return false;
  }
  const o = opts || {};
  const answer = ASSERTION_GRANTS.indexOf(String(o.grant || '')) >= 0 &&
                 !String(o.clientId || '');
  log.debug("Leaving withholdsRefreshToken(). " + answer);
  return answer;
}

// What the token endpoint decides about what the client PRESENTED, once
// `bcp.observeClientAuthentication()` — made in every mode — has said whether
// it verified.
function tokenClientAuthenticationRefusal(opts) {
  log.debug("Entering tokenClientAuthenticationRefusal().");
  if (!enabled()) {
    log.debug("Leaving tokenClientAuthenticationRefusal(). The mode is off.");
    return null;
  }
  const grant = String(opts.grant || '');
  const observation = opts.observation || {};
  const presented = opts.presented || {};
  const presentedSomething = !!(presented.basic || presented.bodySecret ||
                                presented.assertion);
  if (presentedSomething && !observation.authenticated) {
    log.debug("Leaving tokenClientAuthenticationRefusal(). Presented and " +
              "not verified.");
    return refusal('STS-OAUTH-0280', 'invalid_client',
      'client-authentication-when-presented',
      'section 3.2.2: the authorization server MUST authenticate the client ' +
      'if client authentication is included, and this request included it — ' +
      'but ' + (observation.why || 'it did not verify.'));
  }

  if (grant === 'client_credentials' && !observation.authenticated) {
    log.debug("Leaving tokenClientAuthenticationRefusal(). " +
              "client_credentials, unauthenticated.");
    return refusal('STS-OAUTH-0279', 'invalid_client',
      'client-credentials-confidential-only',
      'section 4.2: the client credentials grant "MUST only be used by ' +
      'confidential clients" and the server "MUST authenticate the client". ' +
      (observation.why || 'This request did not authenticate.'));
  }

  log.debug("Leaving tokenClientAuthenticationRefusal(). Nothing refused.");
  return null;
}

// ---------------------------------------------------------------------------
// WHAT EVERY ENDPOINT SHARES.
// ---------------------------------------------------------------------------

// Whether a JWT client assertion must name the issuer as its sole audience.
function strictClientAssertionAudience() {
  log.debug("Entering strictClientAssertionAudience().");
  log.debug("Leaving strictClientAssertionAudience().");
  return enabled();
}

// Whether the loopback port wildcard applies whatever its setting says.
function loopbackAnyPort() {
  log.debug("Entering loopbackAnyPort().");
  log.debug("Leaving loopbackAnyPort().");
  return enabled();
}

// The refusal for a repeated parameter, or null. `repeated` is the list of
// names the caller found more than once.
function repeatedParameterRefusal(repeated, where) {
  log.debug("Entering repeatedParameterRefusal().");
  if (!enabled()) {
    log.debug("Leaving repeatedParameterRefusal(). The mode is off.");
    return null;
  }
  const names = (repeated || []).filter(function (name) {
    return REPEATABLE_PARAMETERS.indexOf(name) < 0;
  });
  if (!names.length) {
    log.debug("Leaving repeatedParameterRefusal(). Nothing repeated.");
    return null;
  }
  log.debug("Leaving repeatedParameterRefusal(). " + names.join(', '));
  return refusal('STS-OAUTH-0285', 'invalid_request',
    'no-repeated-parameters',
    'sections 3.1 and 3.2: request parameters "MUST NOT be included more ' +
    'than once", and this ' + (where || 'request') + ' repeats ' +
    names.join(', ') + '.');
}

// The names that occur more than once in a parsed query (express gives an
// array for a repeat) or in a form body read as text.
function repeatedNames(query, rawBody) {
  log.debug("Entering repeatedNames().");
  const seen = {};
  const repeated = [];
  if (query && typeof query === 'object') {
    Object.keys(query).forEach(function (name) {
      if (Array.isArray(query[name])) {
        repeated.push(name);
      }
    });
  }
  if (typeof rawBody === 'string' && rawBody) {
    rawBody.split('&').forEach(function (pair) {
      const name = pair.split('=')[0];
      if (!name) {
        return;
      }
      let decoded = name;
      try {
        decoded = decodeURIComponent(name.replace(/\+/g, ' '));
      } catch (e) {
        log.debug("Caught in repeatedNames(): " + ((e && e.message) || e));
        // An undecodable name is counted as the text it is; the body parser
        // has refused it already if it matters.
      }
      if (seen[decoded] && repeated.indexOf(decoded) < 0) {
        repeated.push(decoded);
      }
      seen[decoded] = true;
    });
  }
  log.debug("Leaving repeatedNames(). " + repeated.length + " repeated.");
  return repeated;
}

// Section 3.2.4 / 4.1.2.1's character set, applied to an error_description on
// the way out. The replacements for the punctuation this service actually
// writes keep a sentence readable; anything else outside the set becomes `?`.
const DESCRIPTION_REPLACEMENTS = {
  '—': '-', '–': '-', '‘': '\'', '’': '\'',
  '“': '\'', '”': '\'', '…': '...', '"': '\'', '\\': '/',
  ' ': ' '
};

function sanitizeDescription(text) {
  log.debug("Entering sanitizeDescription().");
  if (!enabled() || typeof text !== 'string') {
    log.debug("Leaving sanitizeDescription(). As written.");
    return text;
  }
  const out = text.replace(/[\r\n\t]+/g, ' ')
    .replace(/[^\x20\x21\x23-\x5B\x5D-\x7E]/g, function (ch) {
      return Object.prototype.hasOwnProperty.call(DESCRIPTION_REPLACEMENTS, ch)
        ? DESCRIPTION_REPLACEMENTS[ch] : '?';
    });
  log.debug("Leaving sanitizeDescription().");
  return out;
}

// ---------------------------------------------------------------------------
// REGISTRATION — the refusals an endpoint makes, made where a client records
// what it will do (`oauth-oidc/CLAUDE.md` 3f: a refusal at an endpoint needs
// the matching refusal at registration).
// ---------------------------------------------------------------------------
function registrationRefusal(metadata) {
  log.debug("Entering registrationRefusal().");
  if (!enabled()) {
    log.debug("Leaving registrationRefusal(). The mode is off.");
    return null;
  }
  const meta = metadata || {};
  const method = String(meta.token_endpoint_auth_method || '');
  if (method === 'saml2_bearer') {
    log.debug("Leaving registrationRefusal(). saml2_bearer.");
    return refusal('STS-OAUTH-0287', 'invalid_client_metadata',
      'no-saml-client-authentication',
      'requires ' + AUDIENCE_DRAFT + ', under which SAML bearer assertions ' +
      '"MUST NOT be used for client authentication", so this server will not ' +
      'register a client for token_endpoint_auth_method=saml2_bearer.');
  }
  const grants = Array.isArray(meta.grant_types)
    ? meta.grant_types.map(String) : [];
  if (grants.indexOf('client_credentials') >= 0 && method === 'none') {
    log.debug("Leaving registrationRefusal(). client_credentials, public.");
    return refusal('STS-OAUTH-0289', 'invalid_client_metadata',
      'client-credentials-confidential-only',
      'section 4.2: the client credentials grant is for confidential clients ' +
      'only, and this registration asks for it with ' +
      'token_endpoint_auth_method=none.');
  }
  log.debug("Leaving registrationRefusal(). Nothing refused.");
  return null;
}

// What the metadata stops advertising, for the reason `oauth2_bcp.js` gives: a
// discovery document is a promise the endpoints keep.
function applyToMetadata(metadata) {
  log.debug("Entering applyToMetadata().");
  if (!enabled() || !metadata) {
    log.debug("Leaving applyToMetadata(). Unchanged.");
    return metadata;
  }
  if (Array.isArray(metadata.token_endpoint_auth_methods_supported)) {
    metadata.token_endpoint_auth_methods_supported =
        metadata.token_endpoint_auth_methods_supported.filter(function (one) {
      return one !== 'saml2_bearer';
    });
  }
  log.debug("Leaving applyToMetadata().");
  return metadata;
}

// What GET /oauth2/oauth21 publishes.
function state() {
  log.debug("Entering state().");
  const on = enabled();
  const view = {
    specification: 'The OAuth 2.1 Authorization Framework',
    draft: DRAFT,
    url: DRAFT_URL,
    status: 'an Internet-Draft, not an RFC: every row below cites this ' +
            'revision, and a later one may say something different',
    enabled: on,
    implies: 'oauth2.rfc9700 — GET /oauth2/rfc9700 lists what that mode ' +
             'enforces, and this mode turns it on',
    what_it_means: on
      ? 'Every row below marked yes is refused, on top of everything RFC ' +
        '9700 mode enforces. Two RFC 9700 behaviours step aside: a token ' +
        'request may omit redirect_uri, and an authorization request may ' +
        'omit it when one is registered.'
      : 'Set oauth2.oauth21 (restart-only for the process; a trust realm may ' +
        'carry it) to turn the mode on.',
    settings: {
      'oauth2.oauth21': on,
      'oauth2.rfc9700': !!config.value('oauth2.rfc9700'),
      'oauth2.authorizationCodeTtlS':
          config.value('oauth2.authorizationCodeTtlS'),
      'oauth2.loopbackPortWildcard':
          !!config.value('oauth2.loopbackPortWildcard'),
      // #34 (2026-09-15): section 4.3.1's OTHER answer, which this mode does
      // not require and an operator may. Reported here because a reader of
      // this page is reading it to find out what section 4.3.1 means HERE, and
      // "rotated" and "rotated and sender-constrained" are different answers.
      'oauth2.refreshTokenRotation':
          !!config.value('oauth2.refreshTokenRotation'),
      'oauth2.refreshTokenRequireDpop':
          !!config.value('oauth2.refreshTokenRequireDpop'),
      'oauth2.refreshTokenRequireMtls':
          !!config.value('oauth2.refreshTokenRequireMtls')
    },
    exemptions: [
      'The OpenID4VCI pre-authorized code grant is not held to the ' +
      'registered-client rule: anonymous access is that specification\'s ' +
      'design.',
      'The RFC 7523 and RFC 7522 assertion grants are not held to it either ' +
      'when they carry no client.',
      'An OpenID4VCI wallet using the authorization code flow with a ' +
      'client_id nobody registered IS refused — register the wallet, or use ' +
      'a realm without this mode.'
    ],
    requirements: REQUIREMENTS.map(function (row) {
      return { id: row.id, section: DRAFT + ' ' + row.section,
               level: row.level, applies_to: row.appliesTo,
               enforced: row.enforced, title: row.title, note: row.note };
    })
  };
  log.debug("Leaving state().");
  return view;
}

module.exports = {
  DRAFT: DRAFT,
  AUDIENCE_DRAFT: AUDIENCE_DRAFT,
  MAX_CODE_TTL_MS: MAX_CODE_TTL_MS,
  REGISTERED_CLIENT_GRANTS: REGISTERED_CLIENT_GRANTS,
  REQUIREMENTS: REQUIREMENTS,
  enabled: enabled,
  registeredClientRefusal: registeredClientRefusal,
  defaultRedirectUri: defaultRedirectUri,
  pkceDecision: pkceDecision,
  codeRecordFields: codeRecordFields,
  codeTtlMs: codeTtlMs,
  tokenRedirectUriRequired: tokenRedirectUriRequired,
  tokenCodeRefusal: tokenCodeRefusal,
  multipleMethodsRefusal: multipleMethodsRefusal,
  tokenClientDeclarationRefusal: tokenClientDeclarationRefusal,
  ASSERTION_GRANTS: ASSERTION_GRANTS,
  assertionClientRefusal: assertionClientRefusal,
  withholdsRefreshToken: withholdsRefreshToken,
  tokenClientAuthenticationRefusal: tokenClientAuthenticationRefusal,
  strictClientAssertionAudience: strictClientAssertionAudience,
  loopbackAnyPort: loopbackAnyPort,
  repeatedParameterRefusal: repeatedParameterRefusal,
  repeatedNames: repeatedNames,
  sanitizeDescription: sanitizeDescription,
  registrationRefusal: registrationRefusal,
  applyToMetadata: applyToMetadata,
  state: state
};
