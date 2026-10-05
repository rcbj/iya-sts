// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: http_signatures.ts
//
// ---------------------------------------------------------------------------
// FAPI 2.0 HTTP SIGNATURES AT THE OAUTH RESOURCE SERVERS (#178, 2026-10-05).
//
// The specification of record is the OpenID Foundation's *FAPI 2.0 Http
// Signatures*, draft of 26 June 2026 (Tonge, Fett, Heenan), cited by that
// date as `oauth21.js` cites its draft. It split out of FAPI 2.0 Message
// Signing, whose final text (2025-09-25) has no HTTP-signature sections. It
// profiles RFC 9421 and RFC 9530 for two messages: NR5, a resource request
// (section 5.3.1), and NR6, a resource response (section 5.3.2).
//
// This module is the POLICY: which components, which tag, which key, and what
// is refused. The mechanism, every byte of a signature base and every
// signature, is `common/crypto.js` section 14 (rcbj's rule: every
// cryptographic operation in the common module). Nothing here touches a key.
//
// ---------------------------------------------------------------------------
// THE REQUEST (section 5.3.1.2). A signature tagged `fapi-2-request` is
// verified with a key from the CLIENT's registration (its `jwks`, its
// assertion `jwks`, or its fetched `jwks_uri`; `assertion_grant.keysForParty()`
// is the one reader). The client is the access token's `client_id`, so the
// signer is held to the client the token was issued to, which is the
// draft's NOTE ("from a JWT access token"). The key is the one the
// Signature-Input's `keyid` names, and a signature with no keyid names none.
// It must cover `@method`, `@target-uri` and `authorization`, `dpop` when
// that header is present and `content-digest` when there is a body, and carry
// `created` within `oauth2.httpSignatureMaxAgeS` (60 s, the draft's
// recommendation) in either direction. The Content-Digest is checked
// against the bytes received (RFC 9530). Every failure is a 401, as the
// draft says.
//
// **A SIGNATURE THAT IS PRESENT IS VERIFIED IN EVERY SETTING** (rcbj's
// decision). A client that signed a request believes the signature protects
// it, and a server that ignored it would be checking nothing in a way nobody
// can see. `oauth2.httpSignatures` decides only whether an UNSIGNED request is
// refused (`require-requests`) and whether responses are signed. A client
// can require signed requests of itself with `oauthHttpSignedRequests` on its
// entry.
//
// ---------------------------------------------------------------------------
// THE RESPONSE (section 5.3.2.1). Signed with the realm key
// `oauth2.httpSignatureResponseAlg` names (ES256 by default), the key the
// realm's JWKS publishes with that `alg`, named by its published kid. Under
// RFC 9421 section 3.3.7 a JWS name never travels as the `alg` parameter, so
// the JWK's own `alg` is how a client learns the algorithm. That is why the
// RSA key, published as RS256, is not offered. It covers `@status`,
// `content-type` and `content-digest` when there is a body (the
// Content-Digest is added, sha-256, a content-encoding agnostic method).
// Through `;req` (RFC 9421 section 2.4) it also covers the request's
// `@method`, `@target-uri` and `content-digest`. When the request was signed
// it covers that signature's `signature` and `signature-input` members by
// `;key`, and every component the request signature covered.
//
// TWO PLACES WHERE THE DRAFT AND RFC 9421 PULL APART, recorded rather than
// resolved silently:
//
//   * RFC 9421 section 2.4 calls covering a request's Signature and
//     Signature-Input fields in a response "NOT RECOMMENDED", because a
//     signature over a signature does not cover what that signature covered
//     (section 7.3.7). The draft's section 5.3.2.1 says the response "shall"
//     include them. Both are done: the members, as the draft requires, AND
//     every component the request signature covered, with `;req`, which is
//     what section 2.4 says a response to a signed request SHOULD sign
//     instead. The second answers the first's objection.
//   * The draft names RFC 9530 in one place and its draft
//     (I-D.ietf-httpbis-digest-headers) in another. They define the same
//     field, so this module treats the citation as RFC 9530.
//
// WHEN A RESPONSE IS SIGNED: when `oauth2.httpSignatures` is not `off`, when
// the client set `oauthHttpSignedRequests`, or when the request carried a
// verified `fapi-2-request` signature. A client that signs its requests can
// verify a signed response, and a signature costs a reader who cannot
// nothing. Only a response to a request whose access token was ACCEPTED is
// signed, which is the resource response NR6 names. A 401 refusing the token
// is not one.
//
// A response the signer cannot sign, because no realm key for the
// algorithm exists or a write already began, goes out unsigned and is logged
// (STS-OAUTH-0942). A client requiring a signature refuses it, which is the
// draft's own answer to an unsigned response.
//
// ---------------------------------------------------------------------------
// WHERE IT IS ASKED. `dpop.presentedAccessToken()` is the one door every
// resource server here goes through: UserInfo, the step-up resource, the
// OpenID4VCI endpoints, SCIM, Shared Signals, Grant Management and VC-API. It
// asks `atResource()` last, after the token, its binding and the step-up
// requirement have passed, so a signature is never checked on a request the
// token already refused. SCIM and Shared Signals call that door with a
// recording stand-in for the response. A refusal is written there and
// translated as theirs are, while the response SIGNER is armed on
// `req.res`, the real one, so their responses are signed too.
//
// THE KEYS ARE FETCHED ON ARRIVAL. A client that registered only a
// `jwks_uri` has keys this synchronous check can read only from
// `client_jwks.js`'s cache, so `keyPrefetch()`, a middleware `oauth2.ts`
// registers beside `dpop.proofClaims()`, fills the cache for a request
// carrying a `fapi-2-request` signature before any handler runs. It decides
// nothing: it reads the token's `client_id` UNVERIFIED, only to choose which
// cache entry to fill, which is `proofClaims()`'s argument for reading a jti.
//
// IT IS A LIBRARY (rule 3): it registers no route. `dpop.ts` reaches it
// lazily, so `dpop.ts` stays the leaf rule 3 asks it to be.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import sf = require('../common/structured_fields');
import applications = require('../common/applications');
import realms = require('../common/realms');
import assertionGrant = require('./assertion_grant');

// A request, a response, claims, a JWK: JSON-shaped values.
type Json = any;

interface HttpSignaturesDeps {
  log: typeof helpers.log;
  config: typeof config;
  errorCodes: typeof errorCodes;
  stsCrypto: typeof stsCrypto;
  sf: typeof sf;
  baseUrlOf: (req: Json) => string;
  currentPrefix: () => string;
  nowSec: () => number;
  jsonFromB64u: (text: string) => Json;
  vciError: (res: Json, status: number, error: string,
             description: string) => void;
  signingKeyFor: (alg: string) => Json;
  publishedKidFor: (kid: string) => string;
  httpSignaturesOf: (clientId: string) => Json;
  keysForParty: (fields: Json, kind: string) => Json;
  ensurePartyKeys: (fields: Json, kind: string, kid: string) => Promise<Json>;
}

// The draft's two tags (sections 5.3.1.1 and 5.3.2.1).
const REQUEST_TAG = 'fapi-2-request';
const RESPONSE_TAG = 'fapi-2-response';

// The three values of `oauth2.httpSignatures`, weakest first.
const MODES = ['off', 'sign-responses', 'require-requests'];

// The label a response signature is given. Any key is legal (RFC 9421
// section 4); this one names what it is.
const RESPONSE_LABEL = 'fapi';

// Where a request's verdict and the response signer's state are kept.
const STATE = Symbol('fapi-http-signatures');

/**
 * The FAPI 2.0 HTTP Signatures profile (draft of 26 June 2026) at the OAuth
 * resource servers: signed requests verified, responses signed. The policy;
 * `common/crypto.js` section 14 is the mechanism.
 */
class HttpSignatures {
  static readonly REQUEST_TAG = REQUEST_TAG;
  static readonly RESPONSE_TAG = RESPONSE_TAG;
  static readonly MODES = MODES;

  /**
   * Builds the profile from the modules it reads.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: HttpSignaturesDeps) {
    deps.log.debug("Entering HttpSignatures.constructor().");
    deps.log.debug("Leaving HttpSignatures.constructor().");
  }

  /**
   * The setting in force in the ambient realm.
   *
   * @returns `off`, `sign-responses` or `require-requests`
   */
  mode(): string {
    const { log, config } = this.deps;
    log.debug("Entering HttpSignatures.mode().");
    const value = String(config.value('oauth2.httpSignatures') || 'off');
    log.debug("Leaving HttpSignatures.mode(). " + value);
    return MODES.indexOf(value) >= 0 ? value : 'off';
  }

  // The client an access token was issued to: `client_id` (RFC 9068 section
  // 2.2), else `azp`.
  private clientOf(claims: Json): string {
    const { log } = this.deps;
    log.debug("Entering HttpSignatures.clientOf().");
    const c = claims || {};
    log.debug("Leaving HttpSignatures.clientOf().");
    return String(c.client_id || c.azp || '');
  }

  // The request as RFC 9421 reads it. The target URI is the address the
  // request arrived on: the origin `baseUrlOf()` answers (which believes a
  // forwarded header exactly when the rest of the service does), and
  // `req.originalUrl`. Not `req.url`: the realm middleware strips the realm
  // prefix from that, and a router mounted on a path (SCIM's) strips its
  // mount point too, while the client signed the whole URI.
  private requestMessage(req: Json): Json {
    const { log, baseUrlOf, currentPrefix } = this.deps;
    log.debug("Entering HttpSignatures.requestMessage().");
    const withPrefix = baseUrlOf(req);
    const prefix = currentPrefix();
    const origin = prefix && withPrefix.slice(-prefix.length) === prefix
      ? withPrefix.slice(0, -prefix.length) : withPrefix;
    log.debug("Leaving HttpSignatures.requestMessage().");
    return { method: req.method,
             targetUri: origin + (req.originalUrl || req.url || ''),
             headers: req.headers || {} };
  }

  // The request content as received, for RFC 9530. `app.js` keeps the bytes
  // beside the decoded string for exactly this (`req.rawBody`).
  private bodyOf(req: Json): Buffer {
    const { log } = this.deps;
    log.debug("Entering HttpSignatures.bodyOf().");
    const raw = req && req.rawBody;
    log.debug("Leaving HttpSignatures.bodyOf().");
    return Buffer.isBuffer(raw) ? raw : Buffer.alloc(0);
  }

  // Is there any signature tagged fapi-2-request? A Signature-Input that does
  // not parse is answered as "present", so it is verified and refused rather
  // than ignored.
  private requestSigned(message: Json): boolean {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering HttpSignatures.requestSigned().");
    const headers = message.headers || {};
    if (headers['signature-input'] === undefined &&
        headers['signature'] === undefined) {
      log.debug("Leaving HttpSignatures.requestSigned(). No signature.");
      return false;
    }
    const parsed = stsCrypto.parseHttpSignatures(message);
    const tagged = !parsed.ok || parsed.signatures.some(function (one: Json) {
      return one.params.tag === REQUEST_TAG;
    });
    log.debug("Leaving HttpSignatures.requestSigned(). " + tagged);
    return tagged;
  }

  // The client's keys, as JWKs, each without the `source` member
  // `keysForParty()` adds.
  private keysOf(fields: Json): Json[] {
    const { log, keysForParty } = this.deps;
    log.debug("Entering HttpSignatures.keysOf().");
    const read = keysForParty(fields, 'application');
    const keys = (read.keys || []).map(function (one: Json) {
      const jwk = Object.assign({}, one);
      delete jwk.source;
      return jwk;
    });
    log.debug("Leaving HttpSignatures.keysOf(). " + keys.length + " key(s).");
    return keys;
  }

  // Sends a 401 on `res` (which may be a recording stand-in) under the
  // scheme the token was presented with. `invalid_request` is RFC 6750
  // section 3.1's code for a malformed request, and the draft makes every
  // signature failure a 401.
  private refuseRequest(res: Json, scheme: string, code: string,
                 description: string): false {
    const { log, errorCodes, vciError } = this.deps;
    log.debug("Entering HttpSignatures.refuseRequest(). " + code);
    res.set('WWW-Authenticate', (scheme === 'dpop' ? 'DPoP' : 'Bearer') +
            ' error="invalid_request"');
    log.warn(errorCodes.tag(code) + 'FAPI 2.0 HTTP Signatures: ' +
             description);
    errorCodes.mark(res, code);
    // error-code: none — marked on the line above with the caller's code.
    vciError(res, 401, 'invalid_request', description);
    log.debug("Leaving HttpSignatures.refuseRequest().");
    return false;
  }

  /**
   * Holds a request to the profile at a resource server, after its access
   * token was accepted: verifies a `fapi-2-request` signature when one is
   * present, refuses an unsigned request where one is required, and arms the
   * response signer. Sends the refusal itself.
   *
   * @param req - the request
   * @param res - the response, or a recording stand-in for it
   * @param presented - what `dpop.presentedAccessToken()` accepted:
   *   `claims`, `scheme`
   * @param where - the endpoint, for the log
   * @returns true to go on, false once a refusal has been sent
   */
  atResource(req: Json, res: Json, presented: Json, where?: string): boolean {
    const { log, config, errorCodes, stsCrypto, nowSec,
            httpSignaturesOf } = this.deps;
    log.debug("Entering HttpSignatures.atResource(). " + (where || ''));
    const mode = this.mode();
    const clientId = this.clientOf(presented && presented.claims);
    const client = clientId ? httpSignaturesOf(clientId)
                            : { known: false, required: false, fields: {} };
    const scheme = String((presented && presented.scheme) || 'bearer');
    const message = this.requestMessage(req);
    const signed = this.requestSigned(message);
    const required = mode === 'require-requests' || client.required;
    let verified: Json = null;
    if (!signed && required) {
      log.debug("Leaving HttpSignatures.atResource(). Unsigned, required.");
      return this.refuseRequest(res, scheme, 'STS-OAUTH-0939',
        'this resource requires a signed request (' +
        (client.required ? 'the client\'s oauthHttpSignedRequests'
                         : 'oauth2.httpSignatures is require-requests') +
        '), and this one carries no HTTP message signature tagged "' +
        REQUEST_TAG + '" (FAPI 2.0 HTTP Signatures section 5.3.1.2).');
    }
    if (signed) {
      if (!client.known) {
        log.debug("Leaving HttpSignatures.atResource(). Unknown client.");
        return this.refuseRequest(res, scheme, 'STS-OAUTH-0941',
          'the request is signed, and its access token names ' +
          (clientId ? 'the client "' + clientId + '", which no ' +
                      'application here registers'
                    : 'no client') +
          ', so there is no registered key to verify the signature with ' +
          '(FAPI 2.0 HTTP Signatures section 5.3.1.2).');
      }
      const body = this.bodyOf(req);
      const hasBody = body.length > 0;
      if (hasBody) {
        const digest = stsCrypto.verifyContentDigest(
          req.headers['content-digest'], body,
          { accepted: stsCrypto.CONTENT_DIGEST_ALGORITHMS });
        if (!digest.ok) {
          log.debug("Leaving HttpSignatures.atResource(). Content-Digest.");
          return this.refuseRequest(res, scheme,
                             errorCodes.codeOf(digest) || 'STS-OAUTH-0940',
                             'the request\'s Content-Digest does not hold: ' +
                             digest.why);
        }
      }
      const components = ['@method', '@target-uri', 'authorization'];
      if (req.headers['dpop'] !== undefined) {
        components.push('dpop');
      }
      if (hasBody) {
        components.push('content-digest');
      }
      const keys = this.keysOf(client.fields);
      const maxAgeS = Number(config.value('oauth2.httpSignatureMaxAgeS'));
      const result = stsCrypto.verifyHttpMessage(message, {
        keyFor: function (parsed: Json) {
          const kid = parsed.params.keyid;
          const jwk = kid === undefined ? null : keys.filter(function (one) {
            return one.kid === kid;
          })[0];
          return jwk ? { key: jwk, algorithm: jwk.alg } : null;
        },
        now: nowSec(),
        maxAgeS: maxAgeS,
        skewS: maxAgeS,
        requireCreated: true,
        requireTag: REQUEST_TAG,
        requireComponents: components
      });
      if (!result.ok) {
        log.debug("Leaving HttpSignatures.atResource(). Refused: " +
                  result.why);
        return this.refuseRequest(res, scheme,
                           errorCodes.codeOf(result) || 'STS-OAUTH-0940',
                           'the request\'s HTTP message signature is ' +
                           'refused: ' + result.why);
      }
      verified = result.verified[0];
    }
    if (mode !== 'off' || client.required || verified) {
      this.armResponse(req, message, verified);
    }
    log.debug("Leaving HttpSignatures.atResource(). signed=" + signed +
              ", required=" + required);
    return true;
  }

  // The request components a response covers, with `;req`: the draft's
  // three, then everything the request signature covered (RFC 9421 section
  // 2.4's SHOULD), then the request signature's own two members (the
  // draft's "shall"). Deduplicated by RFC 9421's identity rule, parameter
  // order aside, because a component may be covered once.
  private requestComponents(message: Json, verified: Json): string[] {
    const { log, sf } = this.deps;
    log.debug("Entering HttpSignatures.requestComponents().");
    const out: string[] = [];
    const seen: Record<string, boolean> = {};
    const add = function (serialized: string): void {
      const item = sf.parseItem(serialized);
      if (sf.param(item.params, 'req') === undefined) {
        item.params = item.params.concat([['req',
                                           { type: 'boolean', value: true }]]);
      }
      const identity = JSON.stringify([item.value,
        item.params.map(function (pair: Json) {
          return sf.serializeParams([pair]);
        }).sort()]);
      if (!seen[identity]) {
        seen[identity] = true;
        out.push(sf.serializeItem(item));
      }
    };
    add('"@method"');
    add('"@target-uri"');
    if (message.headers['content-digest'] !== undefined) {
      add('"content-digest"');
    }
    if (verified) {
      (verified.components || []).forEach(add);
      add('"signature";key=' + sf.serializeBareItem(
        { type: 'string', value: verified.label }));
      add('"signature-input";key=' + sf.serializeBareItem(
        { type: 'string', value: verified.label }));
    }
    log.debug("Leaving HttpSignatures.requestComponents(). " + out.length);
    return out;
  }

  // Wraps the REAL response's `end()` (`req.res`, which a recording
  // stand-in is not) so the signature is computed over the status, the
  // headers and the body as they are sent. A response that has already
  // started writing cannot carry a header computed from its whole body, so
  // it goes out unsigned and is logged.
  private armResponse(req: Json, message: Json, verified: Json): void {
    const { log } = this.deps;
    log.debug("Entering HttpSignatures.armResponse().");
    const res = req && req.res;
    if (!res || typeof res.end !== 'function' || res[STATE]) {
      log.debug("Leaving HttpSignatures.armResponse(). Nothing to arm.");
      return;
    }
    const self = this;
    const state = { wrote: false, done: false };
    res[STATE] = state;
    const originalWrite = res.write;
    const originalEnd = res.end;
    res.write = function (...args: any[]) {
      state.wrote = true;
      return originalWrite.apply(res, args);
    };
    res.end = function (...args: any[]) {
      if (!state.done) {
        state.done = true;
        self.signResponse(res, args, message, verified, state.wrote);
      }
      return originalEnd.apply(res, args);
    };
    log.debug("Leaving HttpSignatures.armResponse().");
  }

  // Section 5.3.2.1. Never throws: a response is always sent.
  private signResponse(res: Json, args: any[], request: Json, verified: Json,
                       wrote: boolean): void {
    const { log, config, errorCodes, stsCrypto, nowSec, signingKeyFor,
            publishedKidFor } = this.deps;
    log.debug("Entering HttpSignatures.signResponse().");
    if (wrote || res.headersSent) {
      log.warn(errorCodes.tag('STS-OAUTH-0942') + 'FAPI 2.0 HTTP ' +
               'Signatures: a resource response was written before it ' +
               'ended, so it is sent unsigned.');
      log.debug("Leaving HttpSignatures.signResponse(). Already writing.");
      return;
    }
    try {
      const chunk = args[0];
      const body = chunk === undefined || chunk === null ||
                   typeof chunk === 'function'
        ? Buffer.alloc(0)
        : (Buffer.isBuffer(chunk) ? chunk
            : Buffer.from(String(chunk), typeof args[1] === 'string'
                ? args[1] as BufferEncoding : 'utf8'));
      const components = ['@status'];
      if (res.getHeader('content-type') !== undefined) {
        components.push('content-type');
      }
      if (body.length > 0) {
        res.setHeader('Content-Digest',
                      stsCrypto.contentDigest(body, 'sha-256'));
        components.push('content-digest');
      }
      const alg = String(config.value('oauth2.httpSignatureResponseAlg') ||
                         'ES256');
      const signer = signingKeyFor(alg);
      const headers: Record<string, string> = {};
      const held = res.getHeaders();
      Object.keys(held).forEach(function (name) {
        const value = held[name];
        headers[name.toLowerCase()] = Array.isArray(value)
          ? value.join(', ') : String(value);
      });
      const message = { status: res.statusCode, headers: headers,
                        request: request };
      const signed = stsCrypto.signHttpMessage(message, {
        label: RESPONSE_LABEL,
        components: components.concat(this.requestComponents(request,
                                                              verified)),
        params: [['created', nowSec()],
                 ['keyid', publishedKidFor(signer.kid)],
                 ['tag', RESPONSE_TAG]],
        key: signer.key,
        algorithm: alg
      });
      if (!signed.ok) {
        log.warn(errorCodes.tag('STS-OAUTH-0942') + 'FAPI 2.0 HTTP ' +
                 'Signatures: a resource response could not be signed, and ' +
                 'is sent unsigned: ' + signed.why);
        log.debug("Leaving HttpSignatures.signResponse(). Refused.");
        return;
      }
      res.setHeader('Signature-Input', signed.signatureInput);
      res.setHeader('Signature', signed.signature);
      log.debug("Leaving HttpSignatures.signResponse(). Signed with " + alg +
                ".");
    } catch (e) {
      log.debug("Caught in HttpSignatures.signResponse(): " +
                ((e && e.message) || e));
      // The realm holds no key for the algorithm, or a header was refused.
      // The response still goes out; a client requiring a signature refuses
      // an unsigned one.
      log.warn(errorCodes.tag('STS-OAUTH-0942') + 'FAPI 2.0 HTTP ' +
               'Signatures: a resource response could not be signed, and is ' +
               'sent unsigned: ' + ((e && e.message) || e));
      log.debug("Leaving HttpSignatures.signResponse(). Threw.");
    }
  }

  /**
   * Returns the middleware that fetches a signing client's `jwks_uri` on
   * arrival, so the synchronous check finds its keys. It decides nothing.
   *
   * @returns the express middleware
   */
  keyPrefetch(): (req: Json, res: Json, next: () => void) => void {
    const { log, stsCrypto, jsonFromB64u, httpSignaturesOf,
            ensurePartyKeys } = this.deps;
    log.debug("Entering HttpSignatures.keyPrefetch().");
    log.debug("Leaving HttpSignatures.keyPrefetch().");
    return function httpSignatureKeyPrefetch(req, res, next) {
      log.debug("Entering httpSignatureKeyPrefetch().");
      const input = String((req.headers &&
                            req.headers['signature-input']) || '');
      const auth = String((req.headers && req.headers.authorization) || '');
      const token = /^(?:Bearer|DPoP)\s+(\S+)\s*$/i.exec(auth);
      if (input.indexOf(REQUEST_TAG) < 0 || !token) {
        log.debug("Leaving httpSignatureKeyPrefetch(). Nothing to fetch.");
        next();
        return;
      }
      let clientId = '';
      try {
        const claims = jsonFromB64u(String(token[1]).split('.')[1]) || {};
        clientId = String(claims.client_id || claims.azp || '');
      } catch (e) {
        log.debug("Caught in httpSignatureKeyPrefetch(): " +
                  ((e && e.message) || e));
        // Not a JWT. An opaque token names no client to fetch keys for;
        // the check refuses the signature for that.
        clientId = '';
      }
      const parsed = stsCrypto.parseHttpSignatures({ headers: req.headers });
      const tagged = parsed.ok ? parsed.signatures.filter(function (one: Json) {
        return one.params.tag === REQUEST_TAG;
      })[0] : null;
      const client = clientId ? httpSignaturesOf(clientId) : null;
      if (!client || !client.known || !tagged) {
        log.debug("Leaving httpSignatureKeyPrefetch(). No client or keyid.");
        next();
        return;
      }
      ensurePartyKeys(client.fields, 'application',
                      String(tagged.params.keyid || ''))
        .then(function () {
          log.debug("Leaving httpSignatureKeyPrefetch(). Fetched.");
          next();
        }, function (e: Json) {
          log.debug("Caught in httpSignatureKeyPrefetch(): " +
                    ((e && e.message) || e));
          // ensurePartyKeys() never rejects; a refused fetch leaves the
          // check without the key, and it refuses the signature for that.
          next();
        });
    };
  }

  // What the composition root passes (#50, R2).
  /**
   * Returns the real modules the instance is built from.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): HttpSignaturesDeps {
    helpers.log.debug("Entering HttpSignatures.defaultDeps().");
    helpers.log.debug("Leaving HttpSignatures.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      stsCrypto: stsCrypto,
      sf: sf,
      baseUrlOf: helpers.baseUrlOf,
      currentPrefix: realms.currentPrefix,
      nowSec: helpers.nowSec,
      jsonFromB64u: helpers.jsonFromB64u,
      vciError: helpers.vciError,
      signingKeyFor: helpers.signingKeyFor,
      publishedKidFor: helpers.publishedKidFor,
      httpSignaturesOf: applications.httpSignaturesOf,
      keysForParty: assertionGrant.keysForParty,
      ensurePartyKeys: assertionGrant.ensurePartyKeys
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). The exports are
// FACADES forwarding to it; a process that never runs the root gets a default
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<HttpSignatures>(
  'oauth-oidc/http_signatures',
  () => new HttpSignatures(HttpSignatures.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module on this pattern does.
slot.buildNowUnlessDeferred();

/**
 * FAPI 2.0 HTTP Signatures (draft of 26 June 2026) at the OAuth resource
 * servers. A library that registers no route.
 *
 * @namespace
 */
export = {
  HttpSignatures: HttpSignatures,
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: HttpSignatures): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or
   * `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  REQUEST_TAG: HttpSignatures.REQUEST_TAG,
  RESPONSE_TAG: HttpSignatures.RESPONSE_TAG,
  MODES: HttpSignatures.MODES,
  mode: slot.forward('mode'),
  atResource: slot.forward('atResource'),
  keyPrefetch: slot.forward('keyPrefetch')
};
