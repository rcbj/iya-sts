'use strict';
//
// File: introspection_jwt.js
//
// ===========================================================================
// RFC 9701 — JWT RESPONSE FOR OAUTH TOKEN INTROSPECTION (2026-09-13).
//
// RFC 7662 answers an introspection request with a JSON object, and a resource
// server that receives one has only the TLS connection to tell it who wrote it.
// RFC 9701 lets the resource server ask for the same answer as a SIGNED JWT —
// and, if it registered a key, an encrypted one — so the answer can be kept,
// forwarded and checked later as a statement this authorization server made
// about that token to that resource server:
//
//   Accept: application/token-introspection+jwt           (section 4)
//
//   Content-Type: application/token-introspection+jwt     (section 5)
//   header  { "typ": "token-introspection+jwt", "alg": ..., "kid": ... }
//   claims  { "iss": <this authorization server>,
//             "aud": <the resource server's client_id>,
//             "iat": <now>,
//             "token_introspection": { <the RFC 7662 response> } }
//
// **THE FOUR THINGS THIS FILE DECIDES**, so that the endpoint in `oauth2.js`,
// the registration endpoint and the application registry cannot disagree:
//
//   * WHETHER A REQUEST ASKED FOR ONE — `wantsJwt()`, which reads the Accept
//     header with its q-values rather than looking for a substring.
//   * WHAT A CLIENT REGISTERED — `protectionFor()`, which applies section 6's
//     defaults (RS256; A128CBC-HS256 once an `alg` is registered) and refuses a
//     registration this service cannot honour, or the selected authorization
//     server does not advertise, rather than downgrading it.
//   * WHETHER THE TOKEN WAS INTENDED FOR THE CALLER — `intendedFor()`, section
//     5's "not intended to be introspected by the resource server", asked of
//     the JSON answer as well as the JWT wherever the caller authenticated.
//   * WHAT IS SIGNED — `respond()`, which builds the claims itself so a
//     response cannot be signed without `iss`, `aud` and `iat`, and cannot
//     carry anything but `active: false` for a token that is not active.
//
// **THE CALLER MUST HAVE AUTHENTICATED THE RESOURCE SERVER FIRST.** Section 4
// says the authorization server MUST authenticate the caller, and section 5
// that one that does not is refused with a 400. That refusal is `oauth2.js`'s,
// because it is a response; what makes it structural rather than a convention
// is that `respond()` takes the `aud` from the AUTHENTICATED client and has no
// other place to get one. A JWT addressed to nobody is not something this file
// can produce.
//
// **THE JWT IS NOT A TOKEN, AND FOUR THINGS HERE KEEP IT FROM LOOKING LIKE
// ONE.** Section 8.1 is about exactly this confusion:
//
//   * the header `typ` is `token-introspection+jwt`, which no resource server
//     here accepts — `jwt_access_token.js` requires `at+jwt`;
//   * the claims carry no `sub` and no `exp` — section 5's SHOULD NOT, taken;
//   * the introspection members are NESTED under `token_introspection`, so a
//     `scope` or a `client_id` never sits at the top level of a signed object;
//   * it is signed through `helpers.signJwtAsAsync()` and NOT `signJwt()`, so
//     it is never recorded in the token registry: `/admin/tokens` lists what
//     this service issued as credentials, and this is a response.
//
// **ENCRYPTION IS TO THE CLIENT'S OWN REGISTERED KEY, FROM THE ASYMMETRIC
// LIST.** The same reasoning as the UserInfo response's in `oauth2.js`: the
// symmetric families in `common/crypto.js`'s table are for a document encrypted
// TO this service, and here the only key is the one the client registered. And
// the same refusal: an inline JWKS only, never a `jwks_uri` dialled while
// answering a request.
//
// **A LIBRARY (rule 3).** It registers no route and requires `helpers.js`,
// `common/crypto.js`, `common/applications.js`, `error_codes.js` and
// `jwt_access_token.js`, none of which requires it back, so it cannot join a
// cycle and its place in the require order is not a place. `oauth2.js`
// requires it.
// ===========================================================================

const helpers = require('../common/helpers');
const stsCrypto = require('../common/crypto');
// The application registry owns what a VALUE of one of its attributes may be,
// which is where the three RFC 9701 client metadata members are checked on the
// way in (consent.js's argument about the scope grammar). This file reads the
// same rule when it answers, for a value an `ldapmodify` put there.
const applications = require('../common/applications');
// The registry of error codes: a leaf. A refusal returned from here carries its
// code under the Symbol `mark()` uses, never as an enumerable member.
const errorCodes = require('../common/error_codes');
// For `isOwnResourceAudience()` alone: whether an `aud` value is this
// service's default resource indicator. A library requiring only `common/`
// modules and `authorization_servers.js`, so this is still a leaf.
const jwtAccessToken = require('./jwt_access_token');

const log = helpers.log;

// Section 4 and section 10.3.1: the media type a resource server sends in
// Accept, and that the response carries as its Content-Type.
const MEDIA_TYPE = 'application/token-introspection+jwt';

// Section 5: "the typ header parameter set to token-introspection+jwt" — the
// media type with the `application/` prefix left off, which RFC 7515 section
// 4.1.9 recommends and says a recipient must treat as the same.
const TYP = 'token-introspection+jwt';

// Section 6's two defaults. RS256 when a client registers no signing algorithm,
// and A128CBC-HS256 when it registers an encryption algorithm and no `enc`.
const DEFAULT_SIGNING_ALG = applications.INTROSPECTION_DEFAULT_SIGNING_ALG;
const DEFAULT_ENC = applications.INTROSPECTION_DEFAULT_ENC;

// What `introspection_*_values_supported` advertise (section 7). Read off the
// registry, which reads `common/crypto.js`'s own tables, so the metadata, the
// registration check and the signer are one list.
const SIGNING_ALGS = applications.INTROSPECTION_SIGNING_ALGS;
const ENCRYPTION_ALGS = applications.INTROSPECTION_ENCRYPTION_ALGS;
const ENCRYPTION_ENCS = applications.INTROSPECTION_ENCRYPTION_ENCS;

// ---------------------------------------------------------------------------
// DID THIS REQUEST ASK FOR A JWT?
//
// Section 4 is one sentence — the resource server "requests a JWT introspection
// response by including an Accept header" naming the media type — and the
// reading of it that matters is what a request that says NOTHING gets. Every
// introspection client written before RFC 9701 sends no Accept header, or
// `*/*`, or `application/json`; each of them must go on getting the RFC 7662
// JSON they always got, so a JWT is answered only where the media type is
// NAMED, explicitly, with a quality of more than zero, and at least as high as
// the quality `application/json` has in the same header.
//
// A tie goes to the JWT, and that is a choice rather than an accident: a client
// that wrote `application/token-introspection+jwt, application/json` named the
// JWT on purpose and added JSON as a fallback, and RFC 9110 section 12.5.1
// leaves equal preferences to the server.
//
// Parsed here rather than with express's `req.accepts()`, for two reasons that
// point the same way: this function is asked of a plain header string by the
// tests, and `req.accepts()` answers "which of these would you send" rather
// than "was this one named", which is the question a wildcard makes different.
// ---------------------------------------------------------------------------
function acceptRanges(header) {
  log.debug("Entering acceptRanges().");
  const ranges = String(header || '').split(',').map(function (part) {
    const pieces = part.split(';');
    const type = String(pieces[0] || '').trim().toLowerCase();
    let q = 1;
    pieces.slice(1).forEach(function (param) {
      const pair = param.split('=');
      if (String(pair[0] || '').trim().toLowerCase() === 'q') {
        const value = Number(String(pair[1] || '').trim());
        q = isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
      }
    });
    return { type: type, q: q };
  }).filter(function (range) {
    return range.type.indexOf('/') > 0;
  });
  log.debug("Leaving acceptRanges(). " + ranges.length + " range(s).");
  return ranges;
}

// The quality a media type gets from a header: the q of the MOST SPECIFIC range
// that matches it (RFC 9110 section 12.5.1), or null where nothing matches.
function qualityOf(ranges, mediaType) {
  log.debug("Entering qualityOf(). mediaType=" + mediaType);
  const major = mediaType.split('/')[0] + '/*';
  let best = null;
  let specificity = 0;
  ranges.forEach(function (range) {
    const rank = range.type === mediaType ? 3 :
                 (range.type === major ? 2 : (range.type === '*/*' ? 1 : 0));
    if (rank > specificity) {
      specificity = rank;
      best = range.q;
    }
  });
  log.debug("Leaving qualityOf(). " + best);
  return best;
}

function wantsJwt(acceptHeader) {
  log.debug("Entering wantsJwt().");
  const ranges = acceptRanges(acceptHeader);
  const named = ranges.filter(function (range) {
    return range.type === MEDIA_TYPE;
  });
  if (!named.length || named[0].q <= 0) {
    log.debug("Leaving wantsJwt(). The media type was not named.");
    return false;
  }
  const json = qualityOf(ranges, 'application/json');
  log.debug("Leaving wantsJwt().");
  return json === null || named[0].q >= json;
}

// ---------------------------------------------------------------------------
// WHAT THIS CLIENT REGISTERED, WITH SECTION 6's DEFAULTS APPLIED.
//
// `client` is `applications.clientConfigOf()`'s answer, which carries the three
// members read off the entry's attributes — so a value an operator set on the
// console, one an RFC 7591 registration wrote, and one an `ldapmodify` put
// there are the same value by the time it is read.
//
// A value this service cannot honour is REFUSED rather than replaced with the
// default. A resource server that registered ES384 and got RS256 back would
// either reject a response that is perfectly well signed or, worse, accept an
// algorithm it had deliberately excluded; either way the registration was the
// thing that was ignored. The registry refuses the same values on every write
// door, so reaching here with one means an `ldapmodify`.
// ---------------------------------------------------------------------------
// `advertised` is what the authorization server the request selected
// PUBLISHES — `{ signing, encryption, enc }`, each a list, or null where its
// profile removed the member (and then the check does not run, as for every
// enforced member in `authorization_servers.js`). A registration outside a
// list it publishes is refused with `notAdvertised: true`, which the endpoint
// answers as the CLIENT's problem (400) rather than as this service failing
// (500): the registration is fine, and this authorization server does not
// offer it — the token endpoint's rule about an authentication method, made
// again for a response.
function protectionFor(client, advertised) {
  log.debug("Entering protectionFor().");
  const registered = client || {};
  const signAlg = String(registered.introspection_signed_response_alg || '')
    .trim() || DEFAULT_SIGNING_ALG;
  const encAlg = String(registered.introspection_encrypted_response_alg || '')
    .trim();
  const encEncRaw = String(registered.introspection_encrypted_response_enc ||
                           '').trim();
  const problem = applications.introspectionResponseProblem({
    introspection_signed_response_alg: signAlg,
    introspection_encrypted_response_alg: encAlg,
    introspection_encrypted_response_enc: encEncRaw
  });
  if (problem) {
    log.debug("Leaving protectionFor(). Refused.");
    return errorCodes.mark({ ok: false, description: problem.description },
                           'STS-OAUTH-0293');
  }
  const encEnc = encAlg ? (encEncRaw || DEFAULT_ENC) : '';
  const offered = advertised || {};
  const outside = [
    ['introspection_signed_response_alg', signAlg, offered.signing,
     'introspection_signing_alg_values_supported'],
    ['introspection_encrypted_response_alg', encAlg, offered.encryption,
     'introspection_encryption_alg_values_supported'],
    ['introspection_encrypted_response_enc', encEnc, offered.enc,
     'introspection_encryption_enc_values_supported']
  ].filter(function (row) {
    return row[1] && Array.isArray(row[2]) && row[2].indexOf(row[1]) < 0;
  })[0];
  if (outside) {
    log.debug("Leaving protectionFor(). Not advertised: " + outside[0] + ".");
    return errorCodes.mark({ ok: false, notAdvertised: true,
      description: 'This client\'s ' + outside[0] + ' is "' + outside[1] +
        '"' + (outside[0] === 'introspection_signed_response_alg' &&
               !String(registered.introspection_signed_response_alg ||
                       '').trim()
          ? ' (RFC 9701 section 6\'s default, since it registered none)' : '') +
        ', and this authorization server advertises ' + outside[3] + ' ' +
        JSON.stringify(outside[2]) + '. A client may use any authorization ' +
        'server here, but only in a way that server offers.' },
      'STS-OAUTH-0296');
  }
  log.debug("Leaving protectionFor(). alg=" + signAlg +
            (encAlg ? ', encrypted ' + encAlg : ''));
  return { ok: true, signAlg: signAlg, encAlg: encAlg, encEnc: encEnc };
}

// ---------------------------------------------------------------------------
// WAS THIS TOKEN INTENDED FOR THE RESOURCE SERVER ASKING? (2026-09-13)
//
// Section 5: "If the access token is invalid, expired, revoked, or is not
// intended to be introspected by the resource server, then the authorization
// server MUST set the value of the active member in the token_introspection
// claim to false". Until this function every authenticated client learnt
// everything about every token it could name. rcbj chose the rule, and chose
// it for EVERY caller that authenticated — a JWT request in every mode, a JSON
// one in product mode — not only for the JWT: a JSON answer and a JWT answer to
// one caller about one token that disagreed would be two introspection
// endpoints under one path. An anonymous development caller is the one that
// cannot be asked, because there is nobody to compare the token with.
//
// A token is intended for the caller when ANY of these holds:
//
//   * it is the caller's OWN token — its `client_id` claim is the caller's.
//     A client introspecting the credential it holds learns nothing it was not
//     given, and this is the ONLY way a refresh token is intended for anybody:
//     its `aud` is the token endpoint, which names no resource server;
//   * an `aud` value is THIS SERVICE'S DEFAULT RESOURCE INDICATOR
//     (`<base>/resource`, or a named authorization server's) — a token that
//     named no resource server is this service's own resource server's, and
//     any authenticated caller may ask about it. That is what keeps every
//     deployment that introspects an ordinary token working;
//   * an `aud` value names the caller's ENTRY — one of its `oauthClientId`
//     values, one of its `oauthAudience` values, or its
//     `oauthPermissionBaseUri` (normalised both sides, as
//     `forPermissionBase()` does). Those are the three ways `oauth2.js` puts a
//     resource server into `aud`: a scope naming its client_id, an RFC 8707
//     `resource` it registered as its audience, and a delegated permission.
//
// Otherwise it is answered exactly as an invalid token is — `{active:false}`
// and nothing else — so a caller cannot tell "not yours" from "not a token",
// which is the point of section 5 putting them in one sentence.
// `answer` is the RFC 7662 object; `base` the REQUEST's base URL (not the
// authorization server's), which is what `isOwnResourceAudience()` compares.
// ---------------------------------------------------------------------------
function intendedFor(answer, clientId, base) {
  log.debug("Entering intendedFor(). client=" + clientId);
  const token = answer || {};
  const caller = String(clientId || '');
  if (token.active !== true) {
    log.debug("Leaving intendedFor(). Not active.");
    return false;
  }
  if (!caller) {
    log.debug("Leaving intendedFor(). No caller to compare with.");
    return false;
  }
  if (String(token.client_id || '') === caller) {
    log.debug("Leaving intendedFor(). The caller's own token.");
    return true;
  }
  if (token.token_type === 'refresh_token') {
    log.debug("Leaving intendedFor(). A refresh token is its client's alone.");
    return false;
  }
  const audiences = (Array.isArray(token.aud) ? token.aud : [token.aud])
    .filter(function (one) {
      return one !== undefined && one !== null && String(one) !== '';
    }).map(String);
  if (audiences.some(function (one) {
    return jwtAccessToken.isOwnResourceAudience(one, base);
  })) {
    log.debug("Leaving intendedFor(). This service's own resource server.");
    return true;
  }
  // The caller's name, then the entry's four spellings — one reading of "an
  // aud naming this application", shared with RFC 9470's stand-in resource
  // since 2026-09-13 (`applications.audienceNamesEntry()`).
  const entry = applications.forClientId(caller);
  const matched = audiences.indexOf(caller) >= 0 ||
                  applications.audienceNamesEntry(entry, audiences);
  log.debug("Leaving intendedFor(). " + (matched ? "Named in aud." :
            "Not intended for this caller."));
  return matched;
}

// ---------------------------------------------------------------------------
// THE KEY A RESPONSE IS ENCRYPTED TO, OUT OF WHAT THE CLIENT REGISTERED.
//
// Moved here from `oauth2.js`, where it was written for the UserInfo response,
// because this is the second response a client may ask to have encrypted to its
// own key and two copies of "which of this client's keys may be encrypted to"
// is one copy that will be wrong. `member` names the registration member being
// honoured, so the sentence a client gets back names the member it registered.
//
// Inline `jwks` only: a `jwks_uri` would have this service make an outbound
// HTTPS call to a URL the client chose, at the moment it answers a request —
// the refusal `client_auth.js` makes about verifying with one, made again.
// `jwks` arrives as an object from a registration document and as TEXT from the
// application registry (`oauthJwks`), so both are read.
// ---------------------------------------------------------------------------
function recipientKey(registered, alg, member) {
  log.debug("Entering recipientKey(). alg=" + alg);
  const client = registered || {};
  let jwks = client.jwks;
  if (typeof jwks === 'string') {
    try {
      jwks = jwks.trim() ? JSON.parse(jwks) : null;
    } catch (e) {
      log.debug("Caught in recipientKey(): " + ((e && e.message) || e));
      log.debug("Leaving recipientKey(). The jwks is not JSON.");
      throw new Error('This client registered ' + member + '="' + alg +
        '", and the "jwks" on its entry is not a JSON Web Key Set (' +
        e.message + '), so there is no key to encrypt to.');
    }
  }
  if (!jwks || !Array.isArray(jwks.keys) || !jwks.keys.length) {
    log.debug("Leaving recipientKey(). No inline jwks.");
    throw new Error(client.jwks_uri
      ? 'This client registered a jwks_uri, and this service reads an INLINE ' +
        '"jwks" member only — it will not fetch a URL a client chose while ' +
        'answering that client\'s request. Re-register with the key material ' +
        'in a "jwks" member.'
      : 'This client registered ' + member + '="' + alg +
        '" and no "jwks" member, so there is no key to encrypt to.');
  }
  // A key marked for encryption if there is one, otherwise the first key of the
  // right type — `use` is optional, and a client that published one key for
  // both purposes has still told us which key it holds.
  const wantEc = alg.indexOf('ECDH') === 0;
  const candidates = jwks.keys.filter(function (key) {
    if (!key || (key.use && key.use !== 'enc')) {
      return false;
    }
    return wantEc ? key.kty === 'EC' : key.kty === 'RSA';
  });
  if (!candidates.length) {
    log.debug("Leaving recipientKey(). No usable key.");
    throw new Error('This client registered ' + member + '="' + alg +
      '", which needs ' + (wantEc ? 'an EC' : 'an RSA') + ' key, and ' +
      'its jwks has none that can be used for encryption.');
  }
  log.debug("Leaving recipientKey(). kid=" + (candidates[0].kid || '(none)'));
  return candidates[0];
}

// ---------------------------------------------------------------------------
// THE CLAIMS, AND THE ONE RULE ABOUT A TOKEN THAT IS NOT ACTIVE.
//
// Section 5: "If the access token is invalid, expired, revoked, or is not
// intended to be introspected by the resource server, then the authorization
// server MUST set the value of the active member in the token_introspection
// claim to false and MUST NOT include other members." The caller's JSON for an
// inactive token already is exactly `{ active: false }`; it is rebuilt here
// anyway, because a response signed by this service is the one place a member
// that leaked into that object would become a statement nobody can take back.
// ---------------------------------------------------------------------------
function claimsFor(introspection, issuer, audience, now) {
  log.debug("Entering claimsFor().");
  const answer = introspection && introspection.active === true
    ? introspection : { active: false };
  log.debug("Leaving claimsFor(). active=" + (answer.active === true));
  return {
    iss: String(issuer),
    aud: String(audience),
    iat: now,
    token_introspection: answer
  };
}

// ---------------------------------------------------------------------------
// THE RESPONSE. Resolves `{ contentType, body, alg, enc }`, or rejects with a
// sentence fit to hand back as an `error_description` — every such sentence is
// about what the CLIENT registered.
//
// ASYNCHRONOUS because a client may register one of the post-quantum
// algorithms `introspection_signing_alg_values_supported` advertises, and an
// SLH-DSA signature is seconds of computation that `signJwtAsAsync()` moves to
// the worker pool. `session` is the pool's routing hint: the resource server's
// own client_id, so one resource server's signatures queue behind each other.
//
// SIGN, THEN ENCRYPT — section 5's "it MUST be a Nested JWT" — with the outer
// header carrying `cty: "JWT"` (RFC 7519 section 5.2) and the same `typ`, so a
// resource server that checks the header before it decrypts sees the type it is
// required to check.
// ---------------------------------------------------------------------------
function respond(opts) {
  log.debug("Entering respond().");
  const options = opts || {};
  const client = options.client || {};
  const audience = String(client.client_id || '');
  if (!audience) {
    // Structurally unreachable from the endpoint, which authenticates first.
    log.debug("Leaving respond(). No authenticated client to address it to.");
    return Promise.reject(new Error('An RFC 9701 introspection response is ' +
      'addressed to the resource server that asked, and this request named ' +
      'no client.'));
  }
  const protection = protectionFor(client, options.advertised);
  if (!protection.ok) {
    log.debug("Leaving respond(). The registration cannot be honoured.");
    return Promise.reject(new Error(protection.description));
  }
  const now = typeof options.now === 'number' ? options.now :
              Math.floor(Date.now() / 1000);
  const claims = claimsFor(options.introspection, options.issuer, audience,
                           now);
  helpers.logArtifact('RFC 9701 introspection response', 'before signing',
                      { header: { typ: TYP, alg: protection.signAlg },
                        payload: claims });
  log.debug("Leaving respond(). Signing with " + protection.signAlg + ".");
  return helpers.signJwtAsAsync(claims, protection.signAlg,
                                client.client_secret,
                                { header: { typ: TYP },
                                  certificateHeader: 'introspection',
                                  session: audience })
    .then(function (signed) {
      if (!protection.encAlg) {
        return { contentType: MEDIA_TYPE, body: signed,
                 alg: protection.signAlg, enc: '' };
      }
      const jwe = stsCrypto.encryptJweCompact(signed, {
        alg: protection.encAlg,
        enc: protection.encEnc,
        jwk: recipientKey(client, protection.encAlg,
                          'introspection_encrypted_response_alg'),
        cty: 'JWT',
        typ: TYP
      });
      return { contentType: MEDIA_TYPE, body: jwe, alg: protection.signAlg,
               enc: protection.encAlg + ' ' + protection.encEnc };
    });
}

module.exports = {
  MEDIA_TYPE: MEDIA_TYPE,
  TYP: TYP,
  DEFAULT_SIGNING_ALG: DEFAULT_SIGNING_ALG,
  DEFAULT_ENC: DEFAULT_ENC,
  SIGNING_ALGS: SIGNING_ALGS,
  ENCRYPTION_ALGS: ENCRYPTION_ALGS,
  ENCRYPTION_ENCS: ENCRYPTION_ENCS,
  wantsJwt: wantsJwt,
  protectionFor: protectionFor,
  intendedFor: intendedFor,
  recipientKey: recipientKey,
  claimsFor: claimsFor,
  respond: respond
};
