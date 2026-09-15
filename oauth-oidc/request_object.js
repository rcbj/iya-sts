'use strict';
//
// File: request_object.js
//
// ===========================================================================
// RFC 9101 — THE JWT-SECURED AUTHORIZATION REQUEST (JAR), AND OPENID CONNECT
// CORE SECTION 6's REQUEST OBJECT (2026-09-13).
//
// An authorization request is a list of query parameters anybody on the path
// can read and change. RFC 9101 lets a client put those parameters in a JWT it
// SIGNS — and may encrypt — and send it instead:
//
//   GET /oauth2/authorize?client_id=app1&request=eyJ...            (by value)
//   GET /oauth2/authorize?client_id=app1&request_uri=https://...   (by reference)
//
// This file turns either into the parameters the authorization endpoint then
// runs on, and refuses everything RFC 9101 says to refuse. `oauth2.js`'s
// `authorizeEndpoint()` calls `resolve()` before it reads anything else, and
// answers a refusal ON THIS SERVER as a 400 — never by redirecting — for the
// reason that endpoint's shape check gives: the redirect_uri is INSIDE the
// request object, and one not yet verified is not an address to send an error
// to.
//
// ---------------------------------------------------------------------------
// FOUR DECISIONS WERE ASKED OF RCBJ BEFORE THIS WAS BUILT, AND EACH TOOK THE
// RECOMMENDED ANSWER. They are the design:
//
//   1. A request_uri IS FETCHED ONLY WHEN THE CLIENT REGISTERED IT — exactly,
//      `#fragment` removed — in `request_uris` (`oauthRequestUri`). Section 5.2
//      says the server MUST GET it, and section 10.4 is a page on why that is a
//      server-side request forgery waiting to happen; this service's own
//      standing position was never to dial a URL a caller supplied. Both hold
//      at once because a registered request_uri was DECLARED on the client's
//      entry — by an operator, or by a registration — before any request named
//      it. No redirect is followed, the body is capped
//      (`oauth2.requestUriMaxBytes`), the wait is bounded
//      (`oauth2.requestUriTimeoutMs`), and in product mode it must be https and
//      answer `application/oauth-authz-req+jwt` or `application/jwt`
//      (`mode.acceptsLooseRequestUris()`).
//   2. AN UNSIGNED REQUEST OBJECT (`alg: none`) IS ACCEPTED IN DEVELOPMENT AND
//      REFUSED IN PRODUCT (`mode.acceptsUnsignedRequestObjects()`). RFC 9101
//      section 4 allows only signed ones; OpenID Connect Core 6.1 still allows
//      `none`, and many clients send it. Development refuses it too wherever a
//      signed one is REQUIRED — section 10.5's `require_signed_request_object`,
//      from the setting, the client's entry or the authorization server's
//      profile.
//   3. THE `typ` HEADER IS CHECKED FOR A WRONG TYPE, NOT FOR PRESENCE. Absent,
//      `JWT` and `oauth-authz-req+jwt` are accepted; any other explicit type —
//      `at+jwt`, `token-introspection+jwt`, `secevent+jwt` — is refused in
//      every mode. Section 10.8 says requiring the type "will break most
//      existing deployments"; refusing a DIFFERENT type is the cross-JWT
//      confusion defence without that cost.
//   4. ENCRYPTION IS TO A KEY THIS REALM PUBLISHES — an RSA and an EC key in
//      `/oauth2/jwks` marked `use: "enc"`, members of the realm's key set
//      (`helpers.requestObjectKeysFor()`) — or, for the symmetric families, to
//      the client's own secret.
//
// ---------------------------------------------------------------------------
// WHAT IS VERIFIED, IN ORDER, AND WHY THE ORDER.
//
//   * WHICH DOCUMENT: `request` and `request_uri` together are refused;
//     `client_id` is required as a query parameter (section 5), because it is
//     what says whose keys verify the object and whose request_uris may be
//     fetched — reading it out of an unverified object would be choosing the
//     verifier from a document that has not been verified.
//   * WHAT THE AUTHORIZATION SERVER OFFERS: a named authorization server's
//     profile may publish `request_parameter_supported: false`,
//     `request_uri_parameter_supported: false`, `require_signed_request_object`
//     and narrower algorithm lists, and each is enforced
//     (`authorization_servers.js`).
//   * DECRYPTION (section 6.1), where the object is a five-part JWE, and a
//     client that registered an encryption algorithm must use it.
//   * THE TYPE, then THE SIGNATURE (section 6.2), with the client's registered
//     keys — `assertion_grant.keysForParty()`, the same answer to "which of
//     this party's keys may sign" RFC 7523 uses — or its secret for HMAC, and
//     the registered key's certificate chain and revocation after it verifies,
//     as every other signature from a client is checked here.
//   * THE CLAIMS: `exp` and `nbf` where present; `iss`, where present, is the
//     client; `aud`, where present, names this authorization server; the
//     `client_id` claim, where present, is the query's (section 6.3 "MUST be
//     identical").
//   * ASSEMBLY (section 6.3): "The authorization server MUST only use the
//     parameters in the Request Object, even if the same parameter is provided
//     in the query parameter." So the query is REPLACED, not merged — with two
//     exceptions that are this service's own and carry nothing of the client's:
//     `client_id`, which the section requires be identical, and the round-trip
//     markers the sign-in and consent screens append on the way back
//     (`ROUND_TRIP_FIELDS`).
//
// ---------------------------------------------------------------------------
// THE OPTIONAL HALF, EVERY ITEM OF IT (rcbj: "all optional spec features should
// be implemented").
//
//   * EXPLICIT TYPING REQUIRED (section 10.8's "a good idea for new OAuth
//     deployment profiles") — `oauth2.requireRequestObjectType`, off by
//     default.
//   * `iss` AND `aud` REQUIRED (section 4's SHOULD, enforced) —
//     `oauth2.requireRequestObjectIssuerAudience`, off by default.
//   * THE `kid` (section 6.2): a `kid` in the header MUST name the key used, so
//     one naming no key of this client is refused rather than every key tried.
//   * THE CONSENT SCREEN SAYS THE REQUEST WAS VETTED (section 11.1's SHOULD):
//     `resolve()` answers `alg` and `encrypted`, which `oauth2.js` hands to the
//     sign-in and consent screens.
//   * A request_uri's CONTENT CACHED, and its FRAGMENT CHECKED (OpenID Connect
//     Core section 6.2: the server MAY cache, and a URI whose content may
//     change SHOULD carry the base64url SHA-256 of the content as its fragment)
//     — `oauth2.requestUriCacheS`, 0 (off) by default; a fragment of 43
//     base64url characters is checked against the content in every mode.
//   * `response_type` DUPLICATED IN THE QUERY MUST MATCH (OpenID Connect Core
//     section 6.1, where section 5 of RFC 9101 lets a client duplicate
//     parameters for backward compatibility) — a different value is refused.
//   * A PUSHED AUTHORIZATION REQUEST'S URN
//     (`urn:ietf:params:oauth:request_uri:`, RFC 9126 via section 5.2) is never
//     fetched: it is resolved by `oauth-oidc/par.js` where that exists, and
//     `request_uri_not_supported` where it does not.
//
// **NOT DONE, AND SAID:** a request object's `jti` is not remembered, so one
// may be replayed within its lifetime — RFC 9101 does not ask for it, and the
// authorization endpoint runs every request twice (before and after sign-in),
// which a once-only rule would refuse.
//
// **A LIBRARY (rule 3).** It registers no route and requires `common/` modules
// and `assertion_grant.js`, none of which requires it back.
// ===========================================================================

const http = require('http');
const nodeCrypto = require('crypto');
const https = require('https');
const stsCrypto = require('../common/crypto');
const pki = require('../common/pki');
const errorCodes = require('../common/error_codes');
const revocationStatus = require('../common/revocation_status');
const applications = require('../common/applications');
const config = require('../common/config');
const mode = require('../common/mode');
const version = require('../common/version');
const helpers = require('../common/helpers');
const realms = require('../common/realms');
// `keysForParty()`: which of a client's registered keys may verify something it
// signed. One answer for RFC 7523, the software statement and this.
const assertionGrant = require('./assertion_grant');

const log = helpers.log;

// Section 4 and section 9.4.1.
const TYP = 'oauth-authz-req+jwt';
const MEDIA_TYPE = 'application/oauth-authz-req+jwt';

// What a registered request_uri may answer with. `application/jwt` beside the
// registered type, because OpenID Connect Core section 6.2 predates the
// registration and a great many request objects are served that way.
const ACCEPTED_MEDIA_TYPES = [MEDIA_TYPE, 'application/jwt'];

// A `typ` that says this is a request object, or says nothing more specific.
const ACCEPTED_TYPES = ['', 'jwt', TYP];

// The JWT claims a request object carries ABOUT ITSELF, which are not
// authorization request parameters and are not handed to the endpoint.
const JWT_CLAIMS = ['iss', 'aud', 'exp', 'iat', 'nbf', 'jti'];

// RFC 9126 section 2.2's URN, which names a pushed request held HERE.
const PAR_URN_PREFIX = 'urn:ietf:params:oauth:request_uri:';

// OpenID Connect Core section 6.2: a request_uri's content, per realm, for
// `oauth2.requestUriCacheS`. Keyed by the WHOLE registered URI, fragment
// included, because the fragment is what names a version of the content. Not
// persisted: it is a copy of something re-fetchable, and a stale copy restored
// after a restart would be the one thing the cache must not hand out.
const requestUriCache = realms.map();

const MAX_CACHED_REQUEST_URIS = 256;

// This service's own round-trip fields, which the sign-in and consent screens
// put in the URL on the way back to the authorization endpoint. They are not
// the client's, so the section 6.3 replacement keeps them from the query.
// `jar_prompt_honoured` is this file's own: the first pass honoured the
// object's `prompt`, and the second must not ask again for ever.
const ROUND_TRIP_FIELDS = ['authn_error', 'authn_error_description',
                           'consent_error', 'consent_error_description',
                           'jar_prompt_honoured'];

function skewSeconds() {
  log.debug("Entering skewSeconds().");
  log.debug("Leaving skewSeconds().");
  // `assertion_grant.js`'s setting, for its reason: it answers how far out a
  // CLIENT'S clock may be, and a request object is a client's document.
  return config.value('oauth2.clientAssertionSkewS');
}

// A refusal: the RFC 9101 section 7 error, the sentence, and the code under
// the Symbol `mark()` uses.
function refusal(errorCode, error, description) {
  log.debug("Entering refusal(). " + errorCode);
  log.debug("Leaving refusal().");
  return errorCodes.mark({ ok: false, error: error,
                           description: description }, errorCode);
}

// Whether a signed request object is REQUIRED for this request: the setting,
// the client's entry, or the selected authorization server's profile.
function signedRequired(client, profile) {
  log.debug("Entering signedRequired().");
  const required = !!config.value('oauth2.requireSignedRequestObject') ||
                   !!(client && client.require_signed_request_object) ||
                   !!(profile && profile.requireSigned === true);
  log.debug("Leaving signedRequired(). " + required);
  return required;
}

// Section 10.8: a type naming ANOTHER kind of JWT is refused; none, `JWT` and
// this type are not. RFC 7515 section 4.1.9's case and prefix rules.
function typProblem(typ, required) {
  log.debug("Entering typProblem().");
  const text = typ === undefined || typ === null ? ''
    : String(typ).trim().toLowerCase().replace(/^application\//, '');
  if (required && text !== TYP) {
    log.debug("Leaving typProblem(). The type is required.");
    return 'its header is ' + (text ? 'typed "' + String(typ) + '"' :
                               'not typed') + ', and ' +
           'oauth2.requireRequestObjectType requires every request object to ' +
           'be explicitly typed "' + TYP + '" (RFC 9101 section 10.8).';
  }
  if (typ === undefined || typ === null) {
    log.debug("Leaving typProblem(). No type.");
    return '';
  }
  if (ACCEPTED_TYPES.indexOf(text) >= 0) {
    log.debug("Leaving typProblem(). Accepted.");
    return '';
  }
  log.debug("Leaving typProblem(). Another kind of JWT.");
  return 'its header is typed "' + String(typ) + '", which is another ' +
         'kind of JWT. A request object is typed "' + TYP + '" (RFC 9101 ' +
         'section 4), ' +
         'or not typed at all; a JWT typed as something else is refused, so ' +
         'that a token issued for another purpose cannot be replayed as an ' +
         'authorization request (section 10.8).';
}

function withoutFragment(uri) {
  log.debug("Entering withoutFragment().");
  const text = String(uri || '').trim();
  const hash = text.indexOf('#');
  log.debug("Leaving withoutFragment().");
  return hash >= 0 ? text.slice(0, hash) : text;
}

function jsonPart(compact, index) {
  log.debug("Entering jsonPart().");
  const part = String(compact || '').split('.')[index];
  log.debug("Leaving jsonPart().");
  return JSON.parse(Buffer.from(String(part || ''), 'base64url')
                          .toString('utf8'));
}

// ---------------------------------------------------------------------------
// THE FETCH (section 5.2). Resolves `{ ok, jwt }` or a refusal and NEVER
// rejects. Only ever called with a URI already matched against the client's
// registration — see `resolve()`.
// ---------------------------------------------------------------------------
function fetchRequestUri(uri) {
  log.debug("Entering fetchRequestUri().");
  const target = new URL(withoutFragment(uri));
  const secure = target.protocol === 'https:';
  const cap = Number(config.value('oauth2.requestUriMaxBytes')) || 65536;
  const timeout = Number(config.value('oauth2.requestUriTimeoutMs')) || 5000;
  if (!secure) {
    log.warn('request_object: fetching the registered request_uri ' +
             target.href + ' over plain http, which development mode ' +
             'allows and product mode refuses.');
  }
  log.debug("Leaving fetchRequestUri(). Dialling " + target.origin + ".");
  return new Promise(function (resolve) {
    let settled = false;
    const done = function (result) {
      log.debug("Entering done().");
      if (!settled) {
        settled = true;
        resolve(result);
      }
      log.debug("Leaving done().");
    };
    let request = null;
    try {
      request = (secure ? https : http).request({
        protocol: target.protocol, hostname: target.hostname,
        port: target.port || (secure ? 443 : 80),
        path: target.pathname + target.search, method: 'GET',
        headers: { 'Accept': MEDIA_TYPE + ', application/jwt;q=0.9',
                   'User-Agent': version.userAgent('request-uri') },
        timeout: timeout
      }, function (response) {
        const status = response.statusCode;
        if (status !== 200) {
          response.resume();
          done(refusal('STS-OAUTH-0347', 'invalid_request_uri',
            'the request_uri "' + target.href + '" answered HTTP ' + status +
            (status >= 300 && status < 400
              ? ' — a redirect, which is not followed (RFC 9101 section 10.4)'
              : '') + ', where a request object was expected.'));
          return;
        }
        const type = String(response.headers['content-type'] || '')
          .split(';')[0].trim().toLowerCase();
        if (ACCEPTED_MEDIA_TYPES.indexOf(type) < 0) {
          if (!mode.acceptsLooseRequestUris()) {
            response.resume();
            done(refusal('STS-OAUTH-0348', 'invalid_request_uri',
              'the request_uri "' + target.href + '" answered with the media ' +
              'type "' + (type || '(none)') + '", and a request object is ' +
              MEDIA_TYPE + ' (RFC 9101 section 5.2) or application/jwt. ' +
              'Product mode refuses anything else.'));
            return;
          }
          log.warn('request_object: the registered request_uri ' +
                   target.href + ' answered "' + (type || '(none)') + '" ' +
                   'rather than ' + MEDIA_TYPE + ', which development mode ' +
                   'accepts.');
        }
        const chunks = [];
        let size = 0;
        response.on('data', function (chunk) {
          size += chunk.length;
          if (size > cap) {
            response.destroy();
            done(refusal('STS-OAUTH-0347', 'invalid_request_uri',
              'the request_uri "' + target.href + '" answered with more than ' +
              cap + ' bytes (oauth2.requestUriMaxBytes).'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', function () {
          done({ ok: true,
                 jwt: Buffer.concat(chunks).toString('utf8').trim() });
        });
        response.on('error', function (e) {
          log.debug("Caught in fetchRequestUri(): " + ((e && e.message) || e));
          done(refusal('STS-OAUTH-0347', 'invalid_request_uri',
            'the request_uri "' + target.href + '" could not be read: ' +
            e.message + '.'));
        });
      });
    } catch (e) {
      log.debug("Caught in fetchRequestUri(): " + ((e && e.message) || e));
      done(refusal('STS-OAUTH-0347', 'invalid_request_uri',
        'the request_uri "' + target.href + '" could not be dialled: ' +
        e.message + '.'));
      return;
    }
    request.on('timeout', function () {
      request.destroy(new Error('no answer within ' + timeout + 'ms ' +
                                '(oauth2.requestUriTimeoutMs)'));
    });
    request.on('error', function (e) {
      log.debug("Caught in fetchRequestUri(): " + ((e && e.message) || e));
      done(refusal('STS-OAUTH-0347', 'invalid_request_uri',
        'the request_uri "' + target.href + '" could not be fetched: ' +
        e.message + '.'));
    });
    request.end();
  });
}

// ---------------------------------------------------------------------------
// SECTION 6.1: A FIVE-PART REQUEST OBJECT IS DECRYPTED FIRST. Answers
// `{ ok, jws, alg, enc }` or a refusal.
// ---------------------------------------------------------------------------
// THE KEY A CLIENT SECRET MAKES FOR A SYMMETRIC JWE — OpenID Connect Core
// section 10.2: the leftmost bits of the SHA-2 hash of the secret's octets, as
// many as the algorithm needs, using SHA-256 up to 256 bits, SHA-384 up to 384
// and SHA-512 up to 512. For `dir` the size is the content encryption key's.
// PBES2 is handed the secret itself, because stretching a password is what
// that family is for.
const SYMMETRIC_KEY_BYTES = {
  A128KW: 16, A192KW: 24, A256KW: 32,
  A128GCMKW: 16, A192GCMKW: 24, A256GCMKW: 32
};
const DIRECT_KEY_BYTES = {
  A128GCM: 16, A192GCM: 24, A256GCM: 32,
  'A128CBC-HS256': 32, 'A192CBC-HS384': 48, 'A256CBC-HS512': 64
};

function symmetricKeyFor(alg, enc, secret) {
  log.debug("Entering symmetricKeyFor(). alg=" + alg + ", enc=" + enc);
  if (/^PBES2-/.test(alg)) {
    log.debug("Leaving symmetricKeyFor(). PBES2 takes the secret.");
    return secret;
  }
  const bytes = alg === 'dir' ? DIRECT_KEY_BYTES[enc] :
    SYMMETRIC_KEY_BYTES[alg];
  if (!bytes) {
    log.debug("Leaving symmetricKeyFor(). No size known; the secret as is.");
    return secret;
  }
  const hash = bytes <= 32 ? 'sha256' : bytes <= 48 ? 'sha384' : 'sha512';
  log.debug("Leaving symmetricKeyFor().");
  return nodeCrypto.createHash(hash).update(Buffer.from(String(secret), 'utf8'))
    .digest().subarray(0, bytes);
}

function decrypt(compact, client, profile, keySet) {
  log.debug("Entering decrypt().");
  let header = null;
  try {
    header = jsonPart(compact, 0);
  } catch (e) {
    log.debug("Caught in decrypt(): " + ((e && e.message) || e));
    log.debug("Leaving decrypt(). The header is not JSON.");
    return refusal('STS-OAUTH-0353', 'invalid_request_object',
      'the request object has five parts, so it is encrypted (RFC 9101 ' +
      'section 6.1), and its protected header is not base64url JSON: ' +
      e.message);
  }
  const alg = String(header.alg || '');
  const enc = String(header.enc || '');
  const registeredAlg = String(client.request_object_encryption_alg || '');
  const registeredEnc = registeredAlg
    ? String(client.request_object_encryption_enc || '') ||
      applications.REQUEST_OBJECT_DEFAULT_ENC
    : '';
  if (registeredAlg && (alg !== registeredAlg || enc !== registeredEnc)) {
    log.debug("Leaving decrypt(). Not what the client registered.");
    return refusal('STS-OAUTH-0350', 'invalid_request_object',
      'the request object is encrypted "' + alg + '"/"' + enc + '", and this ' +
      'client registered request_object_encryption_alg "' + registeredAlg +
      '" with enc "' + registeredEnc + '".');
  }
  const offeredAlgs = (profile && profile.encryptionAlgs) ||
                      applications.REQUEST_OBJECT_ENCRYPTION_ALGS;
  const offeredEncs = (profile && profile.encryptionEncs) ||
                      applications.REQUEST_OBJECT_ENCRYPTION_ENCS;
  if (offeredAlgs.indexOf(alg) < 0 || offeredEncs.indexOf(enc) < 0) {
    log.debug("Leaving decrypt(). Not offered.");
    return refusal('STS-OAUTH-0351', 'invalid_request_object',
      'the request object is encrypted "' + alg + '"/"' + enc + '", and this ' +
      'authorization server decrypts request objects with ' +
      JSON.stringify(offeredAlgs) + ' and ' + JSON.stringify(offeredEncs) +
      ' (request_object_encryption_alg_values_supported and ' +
      'request_object_encryption_enc_values_supported).');
  }
  const options = { allowedAlg: [alg], allowedEnc: [enc] };
  if (stsCrypto.JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0) {
    if (!client.client_secret) {
      log.debug("Leaving decrypt(). No secret to decrypt with.");
      return refusal('STS-OAUTH-0352', 'invalid_request_object',
        'the request object is encrypted with the symmetric algorithm "' +
        alg + '", which is keyed by the client secret, and this client has ' +
        'none on its entry.');
    }
    options.secret = symmetricKeyFor(alg, enc, client.client_secret);
  } else {
    const keys = helpers.requestObjectKeysFor(keySet);
    const own = stsCrypto.JWE_ECDH_ALGS.indexOf(alg) >= 0 ? keys.ec : keys.rsa;
    if (header.kid && own && own.publicJwk &&
        String(header.kid) !== String(own.publicJwk.kid)) {
      log.debug("Leaving decrypt(). Encrypted to another key.");
      return refusal('STS-OAUTH-0352', 'invalid_request_object',
        'the request object is encrypted to the key "' + header.kid + '", ' +
        'and this authorization server\'s request object encryption key for ' +
        alg + ' is "' + own.publicJwk.kid + '" — the key marked use "enc" ' +
        'at /oauth2/jwks. A key from another realm, or from before the keys ' +
        'were rotated, opens nothing here.');
    }
    options.privateKey = own.privateKey;
  }
  let opened = null;
  try {
    opened = stsCrypto.decryptJweCompact(compact, options);
  } catch (e) {
    log.debug("Caught in decrypt(): " + ((e && e.message) || e));
    log.debug("Leaving decrypt(). It would not decrypt.");
    return refusal('STS-OAUTH-0353', 'invalid_request_object',
      'the encrypted request object could not be decrypted: ' + e.message);
  }
  const jws = String(opened.plaintext || '').trim();
  if (jws.split('.').length !== 3) {
    log.debug("Leaving decrypt(). Not a nested JWS.");
    return refusal('STS-OAUTH-0354', 'invalid_request_object',
      'the request object decrypted to something that is not a JWS. RFC 9101 ' +
      'section 4 says a request object is signed and THEN encrypted, so what ' +
      'is inside the JWE must be a three-part JWT.');
  }
  log.debug("Leaving decrypt(). " + alg + " " + enc + ".");
  return { ok: true, jws: jws, alg: alg, enc: enc };
}

// The claims of an UNSIGNED request object, checked by hand for what
// `verifyJwsAsync()` checks of a signed one.
function unsignedClaims(jws) {
  log.debug("Entering unsignedClaims().");
  const claims = jsonPart(jws, 1);
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new Error('its payload is not a JSON object');
  }
  const now = Math.floor(Date.now() / 1000);
  const skew = Number(skewSeconds()) || 0;
  if (claims.exp !== undefined && Number(claims.exp) + skew < now) {
    throw new Error('jwt expired');
  }
  if (claims.nbf !== undefined && Number(claims.nbf) - skew > now) {
    throw new Error('jwt not active');
  }
  log.debug("Leaving unsignedClaims().");
  return claims;
}

// ---------------------------------------------------------------------------
// SECTION 6.2: THE SIGNATURE. Answers `{ ok, claims, alg }` or a refusal.
// ---------------------------------------------------------------------------
async function verify(jws, client, clientId, profile, required) {
  log.debug("Entering verify().");
  let header = null;
  try {
    header = jsonPart(jws, 0);
  } catch (e) {
    log.debug("Caught in verify(): " + ((e && e.message) || e));
    log.debug("Leaving verify(). Not a JWT.");
    return refusal('STS-OAUTH-0355', 'invalid_request_object',
      'the request object is not a JWT: ' + e.message);
  }
  const typeRequired = !!config.value('oauth2.requireRequestObjectType');
  const typ = typProblem(header.typ, typeRequired);
  if (typ) {
    log.debug("Leaving verify(). The wrong type.");
    return refusal(typeRequired && ACCEPTED_TYPES.indexOf(
                     String(header.typ || '').trim().toLowerCase()
                       .replace(/^application\//, '')) >= 0
                     ? 'STS-OAUTH-0368' : 'STS-OAUTH-0356',
                   'invalid_request_object',
                   'the request object is refused: ' + typ);
  }
  const alg = String(header.alg || '');
  // AN UNSIGNED OBJECT THAT IS REFUSED IS REFUSED FOR BEING UNSIGNED, before
  // the registered and advertised lists are read: a required signature takes
  // `none` off the advertised list too, and "not advertised" would name the
  // consequence rather than the rule.
  if (alg === 'none' && (!mode.acceptsUnsignedRequestObjects() || required)) {
    log.debug("Leaving verify(). Unsigned and refused.");
    return refusal('STS-OAUTH-0357', 'invalid_request_object',
      'the request object is unsigned (alg "none"), and ' +
      (required
        ? 'a signed request object is required here — by ' +
          'oauth2.requireSignedRequestObject, this client\'s ' +
          'require_signed_request_object or this authorization server\'s ' +
          'metadata (RFC 9101 section 10.5)'
        : 'this realm is in product mode, where RFC 9101 section 4\'s ' +
          'signed request object is required') + '.');
  }
  const registeredAlg = String(client.request_object_signing_alg || '');
  if (registeredAlg && alg !== registeredAlg) {
    log.debug("Leaving verify(). Not the registered algorithm.");
    return refusal('STS-OAUTH-0358', 'invalid_request_object',
      'the request object is signed "' + alg + '", and this client ' +
      'registered request_object_signing_alg "' + registeredAlg + '" — every ' +
      'request object from it must use that algorithm.');
  }
  const offered = profile && profile.signingAlgs;
  if (Array.isArray(offered) && offered.indexOf(alg) < 0) {
    log.debug("Leaving verify(). Not offered.");
    return refusal('STS-OAUTH-0359', 'invalid_request_object',
      'the request object is signed "' + alg + '", and this authorization ' +
      'server advertises request_object_signing_alg_values_supported ' +
      JSON.stringify(offered) + '.');
  }
  if (alg === 'none') {
    try {
      const claims = unsignedClaims(jws);
      log.info('request_object: an UNSIGNED request object from "' + clientId +
               '" was accepted, which development mode allows (OpenID ' +
               'Connect Core section 6.1) and product mode refuses.');
      log.debug("Leaving verify(). Unsigned, accepted.");
      return { ok: true, claims: claims, alg: 'none' };
    } catch (e) {
      log.debug("Caught in verify(): " + ((e && e.message) || e));
      log.debug("Leaving verify(). The unsigned claims are refused.");
      return refusal('STS-OAUTH-0364', 'invalid_request_object',
        'the unsigned request object is refused: ' + e.message + '.');
    }
  }
  if (applications.REQUEST_OBJECT_SIGNING_ALGS.indexOf(alg) < 0) {
    log.debug("Leaving verify(). An algorithm this service has not.");
    return refusal('STS-OAUTH-0360', 'invalid_request_object',
      'the request object names the algorithm "' + alg + '", which this ' +
      'service does not verify. It verifies ' +
      applications.REQUEST_OBJECT_SIGNING_ALGS.join(', ') + '.');
  }
  let candidates = [];
  let why = '';
  if (/^HS/.test(alg)) {
    if (client.client_secret) {
      candidates.push({ kid: '', key: client.client_secret, source: 'secret' });
    } else {
      why = 'it is signed with the HMAC algorithm "' + alg + '", which is ' +
            'keyed by the client secret, and this client has none';
    }
  } else {
    const read = assertionGrant.keysForParty({
      oauthJwks: client.jwks, oauthAssertionJwks: client.assertion_jwks
    }, 'application');
    candidates = read.keys;
    if (!candidates.length) {
      why = 'this client holds no key a request object could be verified ' +
            'with' + (read.problems.length
              ? ' (' + read.problems.join('; ') + ')' : '') +
            (client.jwks_uri
              ? ' — it registered a jwks_uri, which this service does not ' +
                'fetch; register the keys by value as `jwks`'
              : '. Register its public keys as `jwks`, or issue it a key ' +
                'pair from /admin/pki');
    }
  }
  if (!candidates.length) {
    log.debug("Leaving verify(). No key.");
    return refusal('STS-OAUTH-0361', 'invalid_request_object',
                   'the request object cannot be verified: ' + why + '.');
  }
  // SECTION 6.2: "If a kid Header Parameter is present, the key identified
  // MUST be the key used and MUST be a key associated with the client." So a
  // `kid` naming none of this client's keys is refused rather than every key
  // tried. An HMAC secret has no kid, so a `kid` on an HS* object names
  // nothing and is ignored.
  let attempts = candidates;
  if (header.kid && !/^HS/.test(alg)) {
    attempts = candidates.filter(function (one) {
      return one.kid === String(header.kid);
    });
    if (!attempts.length) {
      log.debug("Leaving verify(). The kid names no key of this client.");
      return refusal('STS-OAUTH-0370', 'invalid_request_object',
        'the request object names the key "' + header.kid + '", which is ' +
        'not one of this client\'s keys (' + candidates.map(function (one) {
          return '"' + (one.kid || '(no kid)') + '"';
        }).join(', ') + '). RFC 9101 section 6.2: the key a kid identifies ' +
        'MUST be the key used and MUST be associated with the client.');
    }
  }
  let claims = null;
  let usedKey = null;
  let lastError = '';
  for (let i = 0; i < attempts.length && !claims; i++) {
    try {
      claims = await stsCrypto.verifyJwsAsync(jws, attempts[i].key, {
        algorithms: [alg], clockTolerance: skewSeconds()
      });
      usedKey = attempts[i];
    } catch (e) {
      log.debug("Caught in verify(): " + ((e && e.message) || e));
      lastError = e.message;
    }
  }
  if (!claims) {
    log.debug("Leaving verify(). It did not verify.");
    return refusal('STS-OAUTH-0362', 'invalid_request_object',
      'the request object did not verify with any key this client holds: ' +
      lastError + '.');
  }
  const usedX5c = usedKey && usedKey.jwk && Array.isArray(usedKey.jwk.x5c)
    ? usedKey.jwk.x5c : [];
  if (usedX5c.length) {
    const keyChain = await pki.verifySignerChain(undefined, {
      certificate: usedX5c[0], chain: usedX5c.slice(1), key: usedKey.jwk,
      source: 'the key "' + (usedKey.kid || '(no kid)') + '" in ' +
              usedKey.source + ' for "' + clientId + '"'
    });
    if (!keyChain.ok) {
      log.debug("Leaving verify(). The key's chain is refused.");
      return refusal(errorCodes.codeOf(keyChain) || 'STS-OAUTH-0363',
        'invalid_request_object',
        'the certificate of the key that verified this request object does ' +
        'not have a valid trust chain: ' + keyChain.why);
    }
  }
  if (usedKey && usedKey.jwk) {
    const verdict = await revocationStatus.registeredKeyVerdictFor(usedKey.jwk,
      'the key "' + (usedKey.kid || '(no kid)') + '" in ' + usedKey.source +
      ' for "' + clientId + '"');
    if (verdict && verdict.refused) {
      log.debug("Leaving verify(). The key is revoked.");
      return refusal('STS-PKI-0129', 'invalid_request_object',
        'the key that verified this request object may no longer be used: ' +
        verdict.why);
    }
  }
  log.debug("Leaving verify(). Verified with " + alg + ".");
  return { ok: true, claims: claims, alg: alg };
}

// ---------------------------------------------------------------------------
// SECTION 6.3: THE PARAMETERS. Every claim that is not a JWT claim about the
// object itself, as the endpoint reads a query: a string stays a string, a
// number or a boolean becomes its text, `resource` keeps its array (RFC 8707
// repeats it), and an object — `claims`, `authorization_details` — is the JSON
// a query would have carried. `request` and `request_uri` inside an object are
// dropped: a request object does not refer to another one.
// ---------------------------------------------------------------------------
function parametersFrom(claims, outer, clientId) {
  log.debug("Entering parametersFrom().");
  const params = {};
  Object.keys(claims || {}).forEach(function (name) {
    if (JWT_CLAIMS.indexOf(name) >= 0 || name === 'request' ||
        name === 'request_uri') {
      return;
    }
    const value = claims[name];
    if (value === undefined || value === null) {
      return;
    }
    if (Array.isArray(value) && name === 'resource') {
      params[name] = value.map(String);
    } else if (typeof value === 'object') {
      params[name] = JSON.stringify(value);
    } else {
      params[name] = String(value);
    }
  });
  params.client_id = String(clientId);
  ROUND_TRIP_FIELDS.forEach(function (name) {
    if (outer && outer[name] !== undefined) {
      params[name] = outer[name];
    }
  });
  if (params.jar_prompt_honoured !== undefined) {
    delete params.prompt;
  }
  log.debug("Leaving parametersFrom(). " + Object.keys(params).length +
            " parameter(s).");
  return params;
}

// ---------------------------------------------------------------------------
// OPENID CONNECT CORE SECTION 6.2's FRAGMENT: a request_uri whose content may
// change SHOULD carry the base64url SHA-256 of that content as its fragment.
// A fragment that has that SHAPE — 43 base64url characters — is checked
// against what was fetched, in every mode; any other fragment is the client's
// own and is not read.
// ---------------------------------------------------------------------------
function fragmentProblem(uri, content) {
  log.debug("Entering fragmentProblem().");
  const text = String(uri || '');
  const hash = text.indexOf('#');
  const fragment = hash >= 0 ? text.slice(hash + 1) : '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(fragment)) {
    log.debug("Leaving fragmentProblem(). No SHA-256 fragment.");
    return '';
  }
  const digest = require('crypto').createHash('sha256')
    .update(String(content), 'utf8').digest('base64url');
  log.debug("Leaving fragmentProblem().");
  return digest === fragment ? '' :
    'the request_uri\'s fragment is "' + fragment + '", which is the ' +
    'SHA-256 of a different request object: what it answers with now ' +
    'hashes to "' + digest + '" (OpenID Connect Core section 6.2). The ' +
    'content has changed since the URI was written, so it is not used.';
}

function cacheSeconds() {
  log.debug("Entering cacheSeconds().");
  const seconds = Number(config.value('oauth2.requestUriCacheS'));
  log.debug("Leaving cacheSeconds().");
  return isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : 0;
}

// A registered request_uri's content: from the cache where
// `oauth2.requestUriCacheS` is on and an unexpired copy is held, and fetched
// otherwise. The fragment check runs on either. Resolves `{ ok, jwt, cached }`
// or a refusal.
async function contentOf(uri) {
  log.debug("Entering contentOf().");
  const ttl = cacheSeconds();
  const now = Date.now();
  if (ttl) {
    const held = requestUriCache.get(uri);
    if (held && held.until > now) {
      log.debug("Leaving contentOf(). From the cache.");
      return { ok: true, jwt: held.jwt, cached: true };
    }
  }
  const fetched = await fetchRequestUri(uri);
  if (!fetched.ok) {
    log.debug("Leaving contentOf(). The fetch failed.");
    return fetched;
  }
  const problem = fragmentProblem(uri, fetched.jwt);
  if (problem) {
    log.debug("Leaving contentOf(). The fragment does not match.");
    return refusal('STS-OAUTH-0349', 'invalid_request_uri', problem);
  }
  if (ttl) {
    while (requestUriCache.size >= MAX_CACHED_REQUEST_URIS) {
      requestUriCache.delete(requestUriCache.keys().next().value);
    }
    requestUriCache.set(uri, { jwt: fetched.jwt, until: now + ttl * 1000 });
  }
  log.debug("Leaving contentOf(). Fetched.");
  return { ok: true, jwt: fetched.jwt, cached: false };
}

// ---------------------------------------------------------------------------
// A REQUEST OBJECT, FROM ITS COMPACT FORM TO THE PARAMETERS IT CARRIES.
//
// The half of `resolve()` that does not care how the object arrived, and the
// function `oauth-oidc/par.js` calls for a `request` pushed to it (RFC 9126
// section 3), so a pushed request object and one sent to the authorization
// endpoint are one verifier.
//
//   jwt       the compact JWS or JWE
//   client    `applications.clientConfigOf(clientId)`
//   clientId  the client that SENT it — the query's, or the authenticated one
//   issuer    this authorization server's issuer identifier
//   asBase    its base URL
//   profile   see resolve()
//   keySet    the realm's key set
//   query     optional: the query it arrived with, for the round-trip fields
//             and OpenID Connect's duplicated response_type
//
// Resolves `{ ok: true, params, alg, encrypted }` or a refusal. Never rejects.
// ---------------------------------------------------------------------------
async function verifyObject(opts) {
  log.debug("Entering verifyObject().");
  const options = opts || {};
  const client = options.client || {};
  const profile = options.profile || {};
  const clientId = String(options.clientId || '');
  const query = options.query || {};
  const required = signedRequired(client, profile);
  const compact = String(options.jwt || '').trim();

  let jws = compact;
  let encrypted = '';
  const parts = compact.split('.').length;
  if (parts === 5) {
    const opened = decrypt(compact, client, profile, options.keySet);
    if (!opened.ok) {
      log.debug("Leaving verifyObject(). Decryption refused.");
      return opened;
    }
    jws = opened.jws;
    encrypted = opened.alg + ' ' + opened.enc;
  } else if (parts !== 3) {
    log.debug("Leaving verifyObject(). Not a JWT.");
    return refusal('STS-OAUTH-0355', 'invalid_request_object',
      'the request object is not a compact JWT: it has ' + parts + ' ' +
      'part(s), where a JWS has three and a JWE five.');
  } else if (client.request_object_encryption_alg) {
    log.debug("Leaving verifyObject(). Should have been encrypted.");
    return refusal('STS-OAUTH-0350', 'invalid_request_object',
      'the request object is not encrypted, and this client registered ' +
      'request_object_encryption_alg "' + client.request_object_encryption_alg +
      '" — every request object from it must be encrypted.');
  }

  const verified = await verify(jws, client, clientId, profile, required);
  if (!verified.ok) {
    log.debug("Leaving verifyObject(). The object is refused.");
    return verified;
  }
  const claims = verified.claims;
  if (config.value('oauth2.requireRequestObjectIssuerAudience') &&
      (claims.iss === undefined || claims.aud === undefined)) {
    log.debug("Leaving verifyObject(). iss or aud missing.");
    return refusal('STS-OAUTH-0369', 'invalid_request_object',
      'the request object carries no ' +
      [claims.iss === undefined ? '`iss`' : '',
       claims.aud === undefined ? '`aud`' : ''].filter(Boolean)
        .join(' and no ') +
      ', and oauth2.requireRequestObjectIssuerAudience requires both (RFC ' +
      '9101 section 4: a signed request object SHOULD contain them).');
  }
  if (claims.iss !== undefined && String(claims.iss) !== clientId) {
    log.debug("Leaving verifyObject(). The wrong issuer.");
    return refusal('STS-OAUTH-0365', 'invalid_request_object',
      'the request object\'s `iss` is "' + claims.iss + '", and the client ' +
      'is "' + clientId + '". A request object is issued by the client that ' +
      'sends it.');
  }
  if (claims.aud !== undefined) {
    const audiences = (Array.isArray(claims.aud) ? claims.aud : [claims.aud])
      .map(String);
    const accepted = [String(options.issuer || ''),
                      String(options.asBase || '') + '/oauth2/authorize']
      .filter(Boolean);
    if (!audiences.some(function (one) {
      return accepted.indexOf(one) >= 0;
    })) {
      log.debug("Leaving verifyObject(). The wrong audience.");
      return refusal('STS-OAUTH-0366', 'invalid_request_object',
        'the request object\'s `aud` is ' + JSON.stringify(claims.aud) + ', ' +
        'and it is addressed to this authorization server by its issuer ' +
        'identifier "' + options.issuer + '" (RFC 9101 section 4) or its ' +
        'authorization endpoint.');
    }
  }
  if (claims.client_id !== undefined && String(claims.client_id) !== clientId) {
    log.debug("Leaving verifyObject(). client_id differs.");
    return refusal('STS-OAUTH-0367', 'invalid_request_object',
      'the request object\'s `client_id` is "' + claims.client_id + '" and ' +
      'the query parameter is "' + clientId + '". RFC 9101 section 6.3 says ' +
      'the two MUST be identical.');
  }
  if (query.response_type !== undefined && claims.response_type !== undefined &&
      String(query.response_type) !== String(claims.response_type)) {
    log.debug("Leaving verifyObject(). response_type differs.");
    return refusal('STS-OAUTH-0371', 'invalid_request_object',
      'the query says response_type "' + query.response_type + '" and the ' +
      'request object says "' + claims.response_type + '". A client may ' +
      'duplicate a parameter in the query for backward compatibility (RFC ' +
      '9101 section 5), and OpenID Connect Core section 6.1 says ' +
      'response_type MUST then match.');
  }
  const params = parametersFrom(claims, query, clientId);
  helpers.logArtifact('RFC 9101 request object',
                      'as verified (' + verified.alg +
                      (encrypted ? ', encrypted ' + encrypted : '') + ')',
                      params);
  // `claims` is the verified claim set itself, for `par.js`: RFC 9126 section 3
  // refuses an authenticated client's object with NO `client_id` claim, which
  // `params` cannot show because section 6.3's assembly always fills one in.
  log.debug("Leaving verifyObject(). " + verified.alg + ".");
  return { ok: true, params: params, alg: verified.alg, encrypted: encrypted,
           claims: claims };
}

// A pushed authorization request's URN, handed to `par.js` where it exists.
// Required LAZILY: that module requires this one for `verifyObject()`, and a
// require back at load would close the cycle.
async function pushedRequest(uri, clientId, context) {
  log.debug("Entering pushedRequest().");
  let par = null;
  try {
    par = require('./par');
  } catch (e) {
    log.debug("Caught in pushedRequest(): " + ((e && e.message) || e));
    par = null;
  }
  if (!par || typeof par.resolve !== 'function') {
    log.debug("Leaving pushedRequest(). No PAR here.");
    return refusal('STS-OAUTH-0372', 'request_uri_not_supported',
      'the request_uri "' + uri + '" is a pushed authorization request URN ' +
      '(RFC 9126), and this service has no pushed authorization request ' +
      'endpoint to have issued it.');
  }
  try {
    // `authorizationServer` and `req` are what let a URN pushed at one named
    // authorization server be refused at another; par.js decides that.
    const answer = await par.resolve(uri, clientId, context || {});
    log.debug("Leaving pushedRequest().");
    return answer || refusal('STS-OAUTH-0372', 'invalid_request_uri',
      'the pushed authorization request "' + uri + '" resolved to nothing.');
  } catch (e) {
    log.debug("Caught in pushedRequest(): " + ((e && e.message) || e));
    log.debug("Leaving pushedRequest(). It threw.");
    return refusal('STS-OAUTH-0372', 'invalid_request_uri',
      'the pushed authorization request "' + uri + '" could not be ' +
      'resolved: ' + e.message);
  }
}

// ---------------------------------------------------------------------------
// THE ONE ENTRY POINT FOR THE AUTHORIZATION ENDPOINT.
//
//   query    the request's own query, as express parsed it
//   client   `applications.clientConfigOf()` for the query's client_id
//   issuer   this authorization server's issuer identifier
//   asBase   its base URL, for the authorization endpoint's address
//   profile  what the selected authorization server PUBLISHES:
//            { requestSupported, requestUriSupported, requireSigned,
//              signingAlgs, encryptionAlgs, encryptionEncs } — a boolean or a
//            list, or undefined/null where the profile removed the member
//   keySet   the realm's key set (`helpers.stsKeysFor()`)
//   authorizationServer, req
//            handed to `par.js` for a pushed request's URN, and read by
//            nothing here
//
// Resolves `{ ok: true, used: false }` for a request that is not JWT-secured,
// `{ ok: true, used: true, params, source, alg, encrypted }` for one that is,
// or a refusal. NEVER rejects.
// ---------------------------------------------------------------------------
async function resolve(opts) {
  log.debug("Entering resolve().");
  const options = opts || {};
  const query = options.query || {};
  const client = options.client || {};
  const profile = options.profile || {};
  const required = signedRequired(client, profile);
  const byValue = query.request !== undefined && query.request !== '';
  const byReference = query.request_uri !== undefined &&
                      query.request_uri !== '';
  if (!byValue && !byReference) {
    if (required) {
      log.debug("Leaving resolve(). A signed request object is required.");
      return refusal('STS-OAUTH-0340', 'invalid_request',
        'this authorization request carries no request object, and a signed ' +
        'one is required here (RFC 9101 section 10.5) — by ' +
        [config.value('oauth2.requireSignedRequestObject')
           ? 'oauth2.requireSignedRequestObject' : '',
         client.require_signed_request_object
           ? 'this client\'s require_signed_request_object' : '',
         profile.requireSigned === true
           ? 'this authorization server\'s require_signed_request_object' : '']
          .filter(Boolean).join(' and ') +
        '. Send the parameters in a signed JWT, as `request` or ' +
        '`request_uri`.');
    }
    log.debug("Leaving resolve(). Not a JWT-secured request.");
    return { ok: true, used: false };
  }
  if (byValue && byReference) {
    log.debug("Leaving resolve(). Both.");
    return refusal('STS-OAUTH-0341', 'invalid_request',
      'this authorization request carries both `request` and ' +
      '`request_uri`. RFC 9101 section 5 sends a request object by value or ' +
      'by reference, not both.');
  }
  if (Array.isArray(query.request) || Array.isArray(query.request_uri)) {
    log.debug("Leaving resolve(). Repeated.");
    return refusal('STS-OAUTH-0341', 'invalid_request',
      'this authorization request repeats `' +
      (byValue ? 'request' : 'request_uri') + '`; there is one request ' +
      'object per request.');
  }
  if (byValue && profile.requestSupported === false) {
    log.debug("Leaving resolve(). request not supported here.");
    return refusal('STS-OAUTH-0342', 'request_not_supported',
      'this authorization server publishes request_parameter_supported ' +
      'false, so a request object may not be sent by value here.');
  }
  // RFC 9126 section 5: a request_uri the PAR endpoint issued is usable here
  // "regardless of other authorization server metadata", so a URN is not
  // refused by request_uri_parameter_supported false.
  const pushedUrn = byReference &&
    String(query.request_uri).indexOf(PAR_URN_PREFIX) === 0;
  if (byReference && !pushedUrn && profile.requestUriSupported === false) {
    log.debug("Leaving resolve(). request_uri not supported here.");
    return refusal('STS-OAUTH-0343', 'request_uri_not_supported',
      'this authorization server publishes request_uri_parameter_supported ' +
      'false, so a request object may not be sent by reference here.');
  }
  const clientId = String(query.client_id || '');
  if (!clientId) {
    log.debug("Leaving resolve(). No client_id.");
    return refusal('STS-OAUTH-0344', 'invalid_request',
      'this authorization request carries a request object and no ' +
      '`client_id` query parameter. RFC 9101 section 5 requires it: it is ' +
      'what says whose keys verify the object' +
      (byReference ? ' and whose registered request_uris may be fetched' : '') +
      ', and reading it out of an object nobody has verified yet would ' +
      'choose the verifier from the document being verified.');
  }

  let compact = '';
  let cached = false;
  if (byValue) {
    compact = String(query.request).trim();
  } else if (pushedUrn) {
    const pushed = await pushedRequest(String(query.request_uri), clientId, {
      authorizationServer: options.authorizationServer, req: options.req
    });
    if (!pushed.ok) {
      log.debug("Leaving resolve(). The pushed request is refused.");
      return pushed;
    }
    if (pushed.params) {
      const params = Object.assign({}, pushed.params,
                                   { client_id: clientId });
      ROUND_TRIP_FIELDS.forEach(function (name) {
        if (query[name] !== undefined) {
          params[name] = query[name];
        }
      });
      if (params.jar_prompt_honoured !== undefined) {
        delete params.prompt;
      }
      log.debug("Leaving resolve(). A pushed request's parameters.");
      return { ok: true, used: true, params: params, source: 'par',
               alg: pushed.alg || '', encrypted: pushed.encrypted || '',
               pushed: pushed.pushed || null };
    }
    compact = String(pushed.jwt || '').trim();
  } else {
    const asked = String(query.request_uri).trim();
    const wanted = withoutFragment(asked);
    const registered = (client.request_uris || []).map(String);
    const match = registered.filter(function (one) {
      return withoutFragment(one) === wanted;
    })[0];
    if (match === undefined) {
      log.warn('request_object: client "' + clientId + '" sent a request_uri ' +
               'it has not registered, which was refused and not fetched.');
      log.debug("Leaving resolve(). An unregistered request_uri.");
      return refusal('STS-OAUTH-0345', 'invalid_request_uri',
        'the request_uri "' + wanted + '" is not one client "' + clientId +
        '" has registered (request_uris). This service fetches a ' +
        'request_uri only when the client registered it beforehand, so that ' +
        'it cannot be made to dial a URL a request chose (RFC 9101 section ' +
        '10.4). Register it on the application, or send the request object ' +
        'by value.');
    }
    if (asked.length > 512) {
      log.warn('request_object: client "' + clientId + '" sent a request_uri ' +
               'of ' + asked.length + ' characters; RFC 9101 section 5.2 ' +
               'says one SHOULD NOT exceed 512.');
    }
    const problem = applications.requestUriProblem(wanted);
    if (problem) {
      log.debug("Leaving resolve(). A registered request_uri now refused.");
      return refusal('STS-OAUTH-0346', 'invalid_request_uri',
        'the registered request_uri cannot be fetched: ' + problem + '.');
    }
    // THE URI AS SENT, fragment and all: the fragment is what names a version
    // of the content for the cache and the SHA-256 check, and it is never sent
    // on the wire.
    const content = await contentOf(asked);
    if (!content.ok) {
      log.debug("Leaving resolve(). The content could not be had.");
      return content;
    }
    compact = content.jwt;
    cached = content.cached;
  }

  const object = await verifyObject({
    jwt: compact, client: client, clientId: clientId, issuer: options.issuer,
    asBase: options.asBase, profile: profile, keySet: options.keySet,
    query: query
  });
  if (!object.ok) {
    log.debug("Leaving resolve(). The object is refused.");
    return object;
  }
  log.debug("Leaving resolve(). " + (byValue ? 'By value' : 'By reference') +
            ", " + object.alg + ".");
  return { ok: true, used: true, params: object.params,
           source: byValue ? 'request' : 'request_uri', cached: cached,
           alg: object.alg, encrypted: object.encrypted };
}

module.exports = {
  TYP: TYP,
  MEDIA_TYPE: MEDIA_TYPE,
  PAR_URN_PREFIX: PAR_URN_PREFIX,
  ROUND_TRIP_FIELDS: ROUND_TRIP_FIELDS,
  typProblem: typProblem,
  signedRequired: signedRequired,
  fragmentProblem: fragmentProblem,
  parametersFrom: parametersFrom,
  verifyObject: verifyObject,
  resolve: resolve
};
