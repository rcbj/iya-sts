// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fapi_client.ts
//
// ===========================================================================
// THIS SERVICE AS A FAPI CLIENT OF A PARTNER AUTHORIZATION SERVER (#931).
//
// An inbound OpenID Connect relationship (`fedRole` service-provider) can be
// held to a FAPI profile the partner enforces. The usual partner is a bank
// or another financial OpenID Provider that refuses an ordinary code-flow
// client and a client secret. After the partner answers, this service's own
// applications see only this service: the partner's tokens are not handed on.
//
// `fedFapi` names the profile. Empty is today's relying party (#930).
//
//   * `1-advanced` — FAPI 1.0 Advanced. `code id_token`, PKCE S256, a PS256
//     request object by value (RFC 9101), and `private_key_jwt` — or, where
//     `fedTokenAuth` says `tls_client_auth`, RFC 8705 section 2.1's mutual-TLS
//     client authentication. Its access tokens are sender-constrained the
//     way that profile requires, by mutual TLS (RFC 8705 section 3; rcbj's
//     decision of 2026-11-13): the token request, the refresh and UserInfo
//     present the relationship's TLS client certificate
//     (`federation_client_certificate.ts`), and the partner binds the token
//     to it (`cnf.x5t#S256`). Where the partner's discovery document names
//     `mtls_endpoint_aliases` (section 5), those addresses are dialled. No
//     DPoP and no pushed authorization request: a DPoP proof sent to an
//     authorization server that does not advertise DPoP fails the plan.
//   * `2-security` — FAPI 2.0 Security Profile. Discovery is required.
//     The authorization request is pushed (RFC 9126) to the
//     `pushed_authorization_request_endpoint` the discovery document names,
//     and the browser is sent only `client_id` and `request_uri`. `code`,
//     PKCE S256, `private_key_jwt`, and a DPoP-bound access token (RFC 9449).
//   * `2-message-signing` — the same, plus a PS256 request object inside
//     the push and `response_mode=jwt` (JARM), verified before the code is
//     redeemed.
//
// `private_key_jwt` is signed with this realm's RSA key as PS256. `iss` and
// `sub` are `fedClientId`. `aud` is the partner's issuer (`fedPeer`), not
// the token endpoint, and the assertion lives 60 seconds. That is a general
// realm-key assertion. `oidfed_rp.ts`'s `clientAssertion()` stays the Trust
// Chain OP's, whose audience is the OP's Entity Identifier.
//
// DPoP uses a key made for the sign-in (ES256), the same shape as
// `atproto_client.ts` plus the method, an optional access-token hash, and
// one retry when the partner answers `use_dpop_nonce`. The key rides on the
// flow context for the sign-in. When the relationship keeps the partner's
// refresh token, the key is sealed with that token and opened again for the
// refresh. Outbound mutual TLS is `1-advanced`'s alone (`usesMtls()`).
//
// WHAT THE ANSWER IS HELD TO, beside a plain relationship's checks (#931's
// review). 1-advanced requires `s_hash` over the `state` on the front
// ID Token (STS-FED-0248). A 2.x answer must name its issuer, RFC 9207
// (STS-FED-0249), and its token response must say `token_type` DPoP, at
// sign-in and at every refresh (STS-FED-0251). A JARM response JWT must
// carry `exp` (STS-FED-0250). A relationship with no profile is asked
// none of these.
//
// There is no CIBA client. `POST /oauth2/bc-authorize` is this service as
// the authorization server. A profile is ignored on a relationship that is
// not OpenID Connect, and on one that is an OpenID Federation OP
// (`fedTrustAnchor`): that path signs its own request.
//
// ALL CRYPTOGRAPHY IS `common/crypto.js`'s (rule 3r). A static utility
// class. It registers nothing. `federation_sp.ts` dials.
// ===========================================================================

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');

const log = helpers.log;

const CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

// FAPI 2.0 limits a `private_key_jwt` to 60 seconds. A request object this
// profile signs uses the same bound: a shorter lifetime is still acceptable
// to a server that allows up to an hour.
const ASSERTION_LIFETIME_S = 60;

type Json = any;

/**
 * The FAPI client profiles an inbound OpenID Connect relationship can use.
 * A static utility class.
 */
class FapiClient {
  static readonly CLIENT_ASSERTION_TYPE = CLIENT_ASSERTION_TYPE;

  /**
   * The profile `fedFapi` names, or '' when this relationship is not a
   * FAPI client. An unknown value, a protocol other than OpenID Connect,
   * and an OpenID Federation OP are ''.
   *
   * @param record - the relationship
   * @returns `1-advanced`, `2-security`, `2-message-signing`, or ''
   */
  static profileOf(record: Json): string {
    log.debug("Entering FapiClient.profileOf().");
    const raw = String((record && record.fedFapi) || '').trim();
    const known = raw === '1-advanced' || raw === '2-security' ||
      raw === '2-message-signing';
    const usable = !!record && record.fedProtocol === 'oidc' &&
      !String(record.fedTrustAnchor || '').trim() && known;
    log.debug("Leaving FapiClient.profileOf(). " + (usable ? raw : 'none'));
    return usable ? raw : '';
  }

  /**
   * Whether the profile pushes the authorization request.
   *
   * @param profile - `profileOf()`
   * @returns whether it does
   */
  static usesPar(profile: string): boolean {
    log.debug("Entering FapiClient.usesPar().");
    log.debug("Leaving FapiClient.usesPar().");
    return profile === '2-security' || profile === '2-message-signing';
  }

  /**
   * Whether the profile sender-constrains the access token with DPoP.
   *
   * @param profile - `profileOf()`
   * @returns whether it does
   */
  static usesDpop(profile: string): boolean {
    log.debug("Entering FapiClient.usesDpop().");
    log.debug("Leaving FapiClient.usesDpop().");
    return profile === '2-security' || profile === '2-message-signing';
  }

  /**
   * Whether the profile sender-constrains the access token with mutual TLS
   * (RFC 8705 section 3): FAPI 1.0 Advanced (#931, rcbj's decision of
   * 2026-11-13). The token request, the refresh and UserInfo present the
   * relationship's TLS client certificate.
   *
   * @param profile - `profileOf()`
   * @returns whether it does
   */
  static usesMtls(profile: string): boolean {
    log.debug("Entering FapiClient.usesMtls().");
    log.debug("Leaving FapiClient.usesMtls().");
    return profile === '1-advanced';
  }

  /**
   * Whether the profile authenticates at the token endpoint with its TLS
   * client certificate rather than `private_key_jwt`: `1-advanced` with
   * `fedTokenAuth` `tls_client_auth` (RFC 8705 section 2.1). The 2.x
   * profiles always use `private_key_jwt`.
   *
   * @param record - the relationship
   * @returns whether it does
   */
  static usesTlsClientAuth(record: Json): boolean {
    log.debug("Entering FapiClient.usesTlsClientAuth().");
    const out = FapiClient.usesMtls(FapiClient.profileOf(record)) &&
      String((record && record.fedTokenAuth) || '') === 'tls_client_auth';
    log.debug("Leaving FapiClient.usesTlsClientAuth(). " + out);
    return out;
  }

  /**
   * Whether the profile requires a signed authorization response.
   *
   * @param profile - `profileOf()`
   * @returns whether it does
   */
  static usesJarm(profile: string): boolean {
    log.debug("Entering FapiClient.usesJarm().");
    log.debug("Leaving FapiClient.usesJarm().");
    return profile === '2-message-signing';
  }

  /**
   * Whether the profile puts a request object on the browser's
   * authorization URL. Message signing puts one in the push instead.
   *
   * @param profile - `profileOf()`
   * @returns whether it does
   */
  static sendsRequestByValue(profile: string): boolean {
    log.debug("Entering FapiClient.sendsRequestByValue().");
    log.debug("Leaving FapiClient.sendsRequestByValue().");
    return profile === '1-advanced';
  }

  /**
   * Whether the profile cannot start without the partner's discovery
   * document. The pushed-authorization endpoint is read from it.
   *
   * @param profile - `profileOf()`
   * @returns whether it does
   */
  static needsDiscovery(profile: string): boolean {
    log.debug("Entering FapiClient.needsDiscovery().");
    log.debug("Leaving FapiClient.needsDiscovery().");
    return FapiClient.usesPar(profile);
  }

  /**
   * A copy of the relationship with the profile's response type, response
   * mode and scope applied. No profile returns the same record.
   *
   * @param record - the relationship
   * @returns the record the authorization request is built from
   */
  static shapedRecord(record: Json): Json {
    log.debug("Entering FapiClient.shapedRecord().");
    const profile = FapiClient.profileOf(record);
    if (!profile) {
      log.debug("Leaving FapiClient.shapedRecord(). None.");
      return record;
    }
    const out = Object.assign({}, record);
    const words = String(out.fedScope || '').trim().split(/\s+/)
      .filter(function (one) {
        return !!one;
      });
    if (words.indexOf('openid') < 0) {
      words.unshift('openid');
    }
    out.fedScope = words.join(' ');
    if (profile === '1-advanced') {
      out.fedResponseType = 'code id_token';
      // `query` cannot carry the front-channel ID Token. Empty becomes
      // form_post, which is what a hybrid response uses here. `fragment`
      // is left as the operator set it.
      if (String(out.fedResponseMode || '') === 'query') {
        out.fedResponseMode = '';
      }
    } else {
      out.fedResponseType = 'code';
      if (profile === '2-message-signing') {
        out.fedResponseMode = 'jwt';
      } else if (String(out.fedResponseMode || '') === 'form_post') {
        out.fedResponseMode = '';
      }
    }
    log.debug("Leaving FapiClient.shapedRecord(). " + profile);
    return out;
  }

  /**
   * Makes the key one sign-in's DPoP proofs are signed with.
   *
   * @returns `{ pem, jwk }`, `jwk` the public half alone
   */
  static newKey(): Json {
    log.debug("Entering FapiClient.newKey().");
    const pair = stsCrypto.generateSigningJwkPair('ES256');
    const open = pair.publicJwk;
    log.debug("Leaving FapiClient.newKey().");
    return { pem: pair.privateKeyPem,
             jwk: { kty: open.kty, crv: open.crv, x: open.x, y: open.y } };
  }

  /**
   * Signs a DPoP proof (RFC 9449 section 4.2) for one request.
   *
   * @param key - what `newKey()` made
   * @param method - the HTTP method
   * @param url - the address the proof is for
   * @param nonce - the server's nonce, when it has given one
   * @param accessToken - the access token a resource request presents;
   *   its hash is `ath`
   * @returns the proof
   */
  static proof(key: Json, method: string, url: string, nonce: string,
               accessToken?: string): string {
    log.debug("Entering FapiClient.proof().");
    const target = new URL(String(url || ''));
    const claims: Json = {
      jti: stsCrypto.randomToken(128),
      htm: String(method || 'POST').toUpperCase(),
      htu: target.origin + target.pathname,
      iat: Math.floor(Date.now() / 1000)
    };
    if (nonce) {
      claims.nonce = String(nonce);
    }
    if (accessToken) {
      // The token is ASCII. `digest` hashes a string as UTF-8, which is
      // the same bytes.
      claims.ath = stsCrypto.digest('sha256', String(accessToken),
                                    'base64url');
    }
    log.debug("Leaving FapiClient.proof().");
    // certificate-header: none — a DPoP proof is verified against the
    // `jwk` in its own header (RFC 9449 section 4.2), a key made for one
    // sign-in that no certificate was ever issued for.
    return stsCrypto.signJws(claims, key.pem, {
      algorithm: 'ES256', header: { typ: 'dpop+jwt', jwk: key.jwk } });
  }

  /**
   * Signs the `private_key_jwt` for a token, refresh or pushed-authorization
   * request. `aud` is the partner's issuer. Lives 60 seconds.
   *
   * @param record - the relationship, its `fedPeer` the issuer
   * @returns the assertion
   */
  static clientAssertion(record: Json): string {
    log.debug("Entering FapiClient.clientAssertion().");
    const iat = Math.floor(Date.now() / 1000);
    const claims = {
      iss: String(record.fedClientId || ''),
      sub: String(record.fedClientId || ''),
      aud: String(record.fedPeer || '').trim(),
      jti: stsCrypto.randomUuid(),
      iat: iat,
      exp: iat + ASSERTION_LIFETIME_S
    };
    log.debug("Leaving FapiClient.clientAssertion().");
    // certificate-header: none — the partner verifies this against the
    // public key the relationship registered, not a certificate path.
    return helpers.signJwtAs(claims, 'PS256', null, {});
  }

  /**
   * Signs the authorization request as a request object (RFC 9101), PS256,
   * living 60 seconds. The parameters already on `params` are the claims.
   *
   * @param record - the relationship
   * @param params - the authorization parameters
   * @returns the request object
   */
  static requestObject(record: Json, params: URLSearchParams): string {
    log.debug("Entering FapiClient.requestObject().");
    const claims: Json = {};
    params.forEach(function (value, name) {
      claims[name] = value;
    });
    const now = Math.floor(Date.now() / 1000);
    claims.iss = String(record.fedClientId || '');
    claims.aud = String(record.fedPeer || '').trim();
    claims.iat = now;
    claims.nbf = now;
    claims.exp = now + ASSERTION_LIFETIME_S;
    claims.jti = stsCrypto.randomUuid();
    log.debug("Leaving FapiClient.requestObject().");
    // certificate-header: none — a request object is verified against the
    // key the relationship registered at the partner (RFC 9101).
    return helpers.signJwtAs(claims, 'PS256', null,
                             { header: { typ: 'oauth-authz-req+jwt' } });
  }

  /**
   * Says why a verified JARM payload cannot be used, or '' when it can.
   * `state` is how the flow is found. An `error` is the partner's refusal
   * and is returned to the caller; a success carries a `code`.
   *
   * @param payload - the verified response JWT's claims
   * @returns the problem, or ''
   */
  static jarmProblem(payload: Json): string {
    log.debug("Entering FapiClient.jarmProblem().");
    const claims = payload || {};
    let why = '';
    if (!String(claims.state || '')) {
      why = 'it carries no state';
    } else if (!String(claims.code || '') && !String(claims.error || '')) {
      why = 'it carries neither a code nor an error';
    }
    log.debug("Leaving FapiClient.jarmProblem(). " + (why || 'usable'));
    return why;
  }

  /**
   * Says why a verified JARM payload has no usable lifetime, or '' when it
   * has one. JARM section 4.4 has the client check `exp`, and `jwt.verify`
   * checks it only when it is there: a response JWT with no `exp` would
   * otherwise be good for ever, so a captured one could be replayed at any
   * later sign-in that reused its state (#931's review).
   *
   * @param payload - the verified response JWT's claims
   * @returns the problem, or ''
   */
  static jarmExpiryProblem(payload: Json): string {
    log.debug("Entering FapiClient.jarmExpiryProblem().");
    const exp = (payload || {}).exp;
    const why = typeof exp === 'number' && isFinite(exp)
      ? '' : 'it carries no exp (as a number)';
    log.debug("Leaving FapiClient.jarmExpiryProblem(). " +
              (why || 'usable'));
    return why;
  }

  /**
   * Whether the authorization response must name its issuer (RFC 9207).
   * FAPI 2.0 Security Profile section 5.3.2.2 has the client verify `iss`,
   * so a 2.x response without one is refused rather than accepted as a
   * plain relationship accepts it. Under JARM the `iss` is the response
   * JWT's own, verified against `fedPeer` before it is read. 1-advanced is
   * left as it was: its front-channel ID Token is the detached signature
   * that names the issuer.
   *
   * @param profile - `profileOf()`
   * @returns whether it must
   */
  static requiresIssuerParameter(profile: string): boolean {
    log.debug("Entering FapiClient.requiresIssuerParameter().");
    log.debug("Leaving FapiClient.requiresIssuerParameter().");
    return FapiClient.usesPar(profile);
  }

  /**
   * Whether a front-channel ID Token must carry `s_hash` over the `state`.
   * FAPI 1.0 Advanced (Part 2, section 5.1.1 and 5.2.2.1) uses the ID Token
   * from the authorization endpoint as a detached signature over the
   * response, and `state` is one of the values it signs: without `s_hash`
   * a state swapped on the way back is accepted.
   *
   * @param profile - `profileOf()`
   * @returns whether it must
   */
  static requiresStateHash(profile: string): boolean {
    log.debug("Entering FapiClient.requiresStateHash().");
    log.debug("Leaving FapiClient.requiresStateHash().");
    return profile === '1-advanced';
  }

  /**
   * Says why a token response cannot be used by a profile that binds its
   * access token with DPoP, or '' when it can. RFC 9449 section 5: an
   * access token bound to the proof key comes back as `token_type` `DPoP`
   * (compared without case). A `Bearer` answer is a token the partner did
   * not bind, and FAPI 2.0 requires a sender-constrained one, so it is not
   * presented anywhere.
   *
   * @param profile - `profileOf()`
   * @param tokens - the token endpoint's JSON
   * @returns the problem, or ''
   */
  static tokenTypeProblem(profile: string, tokens: Json): string {
    log.debug("Entering FapiClient.tokenTypeProblem().");
    let why = '';
    if (FapiClient.usesDpop(profile)) {
      const type = String((tokens || {}).token_type || '');
      if (type.toLowerCase() !== 'dpop') {
        why = 'its token_type is "' + type.slice(0, 40) + '", not DPoP';
      }
    }
    log.debug("Leaving FapiClient.tokenTypeProblem(). " + (why || 'usable'));
    return why;
  }

  /**
   * Sends once, and again when the partner answers `use_dpop_nonce` with a
   * nonce other than the one just sent. A repeat of the same nonce is not
   * retried: that would loop.
   *
   * @param send - posts with the nonce it is given and answers
   *   `{ ok, json, headers }`
   * @param firstNonce - the nonce already held, or ''
   * @returns the answer kept
   */
  static async withNonce(send: (nonce: string) => Promise<Json>,
                         firstNonce: string): Promise<Json> {
    log.debug("Entering FapiClient.withNonce().");
    const nonce = String(firstNonce || '');
    let answer = await send(nonce);
    const headers = (answer && answer.headers) || {};
    const next = String(headers['dpop-nonce'] || '');
    const err = answer && answer.json && answer.json.error;
    if (answer && !answer.ok && next && err === 'use_dpop_nonce' &&
        next !== nonce) {
      answer = await send(next);
    }
    log.debug("Leaving FapiClient.withNonce(). " +
              ((answer && answer.status) || 0));
    return answer;
  }
}

export = FapiClient;
