'use strict';
//
// File: gnap_proof.ts
//
// ---------------------------------------------------------------------------
// DID THIS REQUEST PROVE POSSESSION OF THIS KEY — THE ONE QUESTION EVERY GNAP
// ENDPOINT ASKS, ANSWERED FOR ALL FOUR PROOFING METHODS IN ONE PLACE.
//
// RFC 9635 section 7.3 defines four methods and section 10.16 registers them:
// HTTP Message Signatures (`httpsig`), mutual TLS (`mtls`), a detached JWS in a
// header (`jwsd`) and an attached JWS as the body (`jws`). The same four are
// used by a client at the grant endpoint (a non-authorized signed request), at
// the continuation and management URIs (a bound token request), by a resource
// server calling introspection or registration (RFC 9767 section 3.2), and by a
// client at the demonstration RS. So one verifier, handed a key DESCRIPTOR from
// `gnap_keys.ts`, and every one of those callers gets the same answer.
//
// **THIS IS NOT PERMISSIVE IN ANY MODE, AND THAT IS THE SAME ARGUMENT THIS
// SERVICE ALREADY MAKES THREE TIMES.** `/authn/spnego` verifies a real
// Kerberos key, `/authn/totp` a real TOTP code, `/authn/backup-code` a real
// recovery code — each because there is nothing left of the specification once
// the comparison goes (root CLAUDE.md, *Things this service deliberately does
// not do*). A GNAP key proof is the fourth. A grant endpoint that accepted an
// unsigned request would issue a token BOUND to a key nobody proved they held,
// and every later step — continuation, rotation, the RS — would be checking a
// binding to nothing. What stays permissive is what the AS decides ABOUT a
// proved key it has never seen, and that is `gnap_grants.ts`'s, mode-gated.
//
// ---------------------------------------------------------------------------
// WHAT EACH METHOD MUST COVER (section 7.3: "all relevant portions of the
// request ... the URI being called, the HTTP method being used, any relevant
// HTTP headers and values, and the HTTP message content itself").
//
//   httpsig  `@method`, `@target-uri`; `content-digest` when there is content
//            (and the digest is RECOMPUTED over the bytes, section 7.3.1);
//            `authorization` when a token is bound; tag `gnap`; `created`
//            within `gnap.signatureMaxAgeS`; a `nonce`, when present, unique;
//            no `alg` parameter; keyid = the JWK's kid.
//   mtls     the TLS client certificate IS the key; the connection covers the
//            message (section 7.3.2). No chain validation — section 7.3.2
//            says a verifier often does none, and the key was presented in the
//            request, which is the trust.
//   jwsd     typ `gnap-binding-jwsd`, alg = the key's, kid = the JWK's, `htm`,
//            `uri`, `created`; `ath` when bound; payload = SHA-256 of content.
//   jws      the same header with typ `gnap-binding-jws`; the payload IS the
//            request content, which is why the body is read through here.
//
// ---------------------------------------------------------------------------
// ONE READING OF SECTION 7.3.3 THAT HAD TO BE CHOSEN.
//
// The text says the JWS payload "is the base64url encoding (without padding) of
// the SHA-256 digest of the bytes of the content", and its example shows the
// compact serialisation's MIDDLE segment equal to that base64url value — which
// is what you get if the payload BYTES are the raw digest, not the base64url
// string (that would be encoded a second time). Implementations exist that do
// each. A verifier that accepted only one would refuse the other half of the
// ecosystem over an ambiguity that has nothing to do with security — both bind
// exactly the same digest. So both are accepted, and a middle segment left
// EMPTY (a true RFC 7515 Appendix F detached payload) is reconstructed each
// way.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapProof` takes node's crypto, the settings reader, the logger,
// the base-URL and clock readers, the service's crypto module, the error-code
// table, `mtls.js`, `gnap_httpsig` and `gnap_store` through its constructor,
// and every helper is one of its private methods. The module still exports
// the old names from a TRANSITIONAL instance for `gnap_grants`, `gnap_rs`,
// `ssf/ssf_cluster.js` and the tests, which require it by those names.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import config = require('../common/config');
import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');
import mtls = require('../oauth-oidc/mtls');
import httpsig = require('./gnap_httpsig');
import store = require('./gnap_store');

// A result in the one shape every GNAP library returns: `ok`, and either the
// refusal's members or the answer's.
interface Result {
  ok: boolean;
  [member: string]: any;
}

interface GnapProofDeps {
  nodeCrypto: typeof nodeCrypto;
  config: { value(key: string): any };
  log: {
    debug(message: string): void;
    warn(message: string): void;
  };
  baseUrlOf(req: any): string;
  nowSec(): number;
  stsCrypto: typeof stsCrypto;
  errorCodes: {
    mark<T>(res: T, code: string): T;
    codeOf(res: unknown): string;
  };
  mtls: typeof mtls;
  httpsig: typeof httpsig;
  store: typeof store;
}

class GnapProof {
  constructor(private readonly deps: GnapProofDeps) {
    deps.log.debug("Entering GnapProof.constructor().");
    deps.log.debug("Leaving GnapProof.constructor().");
  }

  private refusal(code: string, why: string,
                  gnapError?: string): Result {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapProof.refusal().");
    const out = { ok: false, errorCode: code, why: why,
                  gnapError: gnapError || 'invalid_client' };
    log.debug("Leaving GnapProof.refusal().");
    return errorCodes.mark(out, code);
  }

  private maxAgeS() {
    const { config, log } = this.deps;
    log.debug("Entering GnapProof.maxAgeS().");
    const value = Number(config.value('gnap.signatureMaxAgeS'));
    log.debug("Leaving GnapProof.maxAgeS().");
    return Number.isFinite(value) && value > 0 ? value : 300;
  }

  private b64u(buffer) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.b64u().");
    log.debug("Leaving GnapProof.b64u().");
    return Buffer.from(buffer).toString('base64url');
  }

  private sha256(bytes) {
    const { nodeCrypto, log } = this.deps;
    log.debug("Entering GnapProof.sha256().");
    log.debug("Leaving GnapProof.sha256().");
    return nodeCrypto.createHash('sha256').update(bytes).digest();
  }

  // The access token hash of sections 7.3.3/7.3.4: base64url SHA-256 of the
  // ASCII token value — the same computation as DPoP's `ath` (RFC 9449).
  athOf(token) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.athOf().");
    log.debug("Leaving GnapProof.athOf().");
    return this.b64u(this.sha256(Buffer.from(String(token), 'ascii')));
  }

  // The absolute URI the client addressed. `baseUrlOf()` carries scheme, host
  // and the realm prefix the front middleware stripped; `req.url` is the rest.
  // A signature over any other spelling of the URI fails, which is correct: the
  // client signed the URI the AS gave it, and section 3.1 says to use it
  // exactly.
  targetUriOf(req) {
    const { log, baseUrlOf } = this.deps;
    log.debug("Entering GnapProof.targetUriOf().");
    log.debug("Leaving GnapProof.targetUriOf().");
    return baseUrlOf(req) + (req.url || '');
  }

  // The GNAP token in `Authorization`, when the request carries one.
  presentedToken(req) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.presentedToken().");
    const header = String((req.headers && req.headers.authorization) || '');
    const match = header.match(/^GNAP\s+([A-Za-z0-9\-._~+/]+=*)\s*$/);
    log.debug("Leaving GnapProof.presentedToken().");
    return match ? match[1] : null;
  }

  // ---------------------------------------------------------------------------
  // THE REQUEST CONTENT, READ ONCE, BEFORE ANYTHING IS VERIFIED.
  //
  // A grant request carries the very key it must be verified with, so the body
  // has to be READ before the proof can be CHECKED — for `jws` that means
  // decoding a payload whose signature has not been checked yet. That is safe
  // for one reason, and `verifyRequest()` keeps it true: nothing read here is
  // acted on until the proof over it has verified against the key it names.
  // ---------------------------------------------------------------------------
  readBody(req) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.readBody().");
    const raw = Buffer.isBuffer(req.rawBody) ? req.rawBody
      : Buffer.from(typeof req.body === 'string' ? req.body : '', 'utf8');
    const hadContent = raw.length > 0;
    if (!hadContent) {
      log.debug("Leaving GnapProof.readBody(). No content.");
      return { ok: true, hadContent: false, raw: raw, json: null, jose: null };
    }
    const type = String(req.headers['content-type'] || '').toLowerCase();
    const text = raw.toString('utf8');
    if (type.indexOf('application/jose') === 0 ||
        /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text.trim())) {
      const parts = text.trim().split('.');
      let json;
      try {
        const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
        json = JSON.parse(payload);
        // A ROTATION wraps the old-key JWS as the payload of the new-key one
        // (section 7.3.4.1), so the payload may itself be a compact JWS. Its
        // content is the innermost payload.
        if (typeof json === 'string' && json.split('.').length === 3) {
          json = JSON.parse(Buffer.from(json.split('.')[1], 'base64url')
                                  .toString('utf8'));
        }
      } catch (e) {
        log.debug("Caught in GnapProof.readBody(): " + ((e && e.message) || e));
        const inner = Buffer.from(parts[1] || '', 'base64url').toString('utf8');
        if (inner.split('.').length === 3) {
          try {
            json = JSON.parse(Buffer.from(inner.split('.')[1], 'base64url')
                                    .toString('utf8'));
          } catch (e2) {
            log.debug("Caught in GnapProof.readBody(): " +
                      ((e2 && e2.message) || e2));
            // Neither layer is JSON; refused below with one sentence.
            json = undefined;
          }
        }
        if (json === undefined) {
          log.debug("Leaving GnapProof.readBody(). An attached JWS whose " +
                    "payload is not JSON.");
          return this.refusal('STS-GNAP-0260',
                              'the request content is a JWS whose payload is ' +
                              'not a JSON object (RFC 9635 ' +
                              'section 7.3.4).', 'invalid_request');
        }
      }
      log.debug("Leaving GnapProof.readBody(). Attached JWS.");
      return { ok: true, hadContent: true, raw: raw, json: json,
               jose: text.trim() };
    }
    try {
      const json = JSON.parse(text);
      log.debug("Leaving GnapProof.readBody(). JSON.");
      return { ok: true, hadContent: true, raw: raw, json: json, jose: null };
    } catch (e) {
      log.debug("Caught in GnapProof.readBody(): " + ((e && e.message) || e));
      log.debug("Leaving GnapProof.readBody(). Not JSON: " + e.message);
      return this.refusal('STS-GNAP-0261',
                          'the request content is not JSON (RFC 9635 section ' +
                          '2 requires a JSON object with Content-Type ' +
                          'application/json).',
                          'invalid_request');
    }
  }

  // ---------------------------------------------------------------------------
  // A JWS SIGNATURE OVER AN ARBITRARY SIGNING INPUT.
  //
  // `common/crypto.js`'s `verifyCompactJws()` insists on a JSON payload, which
  // is right for every token this service reads and wrong for a detached JWS,
  // whose payload is a digest. So the byte check is here — for the classical
  // families only, which is every algorithm a GNAP key can carry
  // (`gnap_keys.ts` refuses the rest), and with node's own primitives.
  // ---------------------------------------------------------------------------
  verifyJwsBytes(alg, descriptor, signingInput, signature) {
    const { nodeCrypto, log, stsCrypto } = this.deps;
    log.debug("Entering GnapProof.verifyJwsBytes(). alg=" + alg);
    const spec = stsCrypto.JWS_ALGS[alg];
    if (!spec || alg === 'none') {
      log.debug("Leaving GnapProof.verifyJwsBytes(). Unknown algorithm.");
      return false;
    }
    const data = Buffer.from(signingInput, 'ascii');
    try {
      if (spec.family === 'hmac') {
        if (!descriptor.secret) {
          log.debug("Leaving GnapProof.verifyJwsBytes(). HMAC with no shared " +
                    "secret.");
          return false;
        }
        const mac = nodeCrypto.createHmac(spec.hash, descriptor.secret)
                              .update(data)
                              .digest();
        const ok = mac.length === signature.length &&
                   nodeCrypto.timingSafeEqual(mac, signature);
        log.debug("Leaving GnapProof.verifyJwsBytes(). HMAC " + ok);
        return ok;
      }
      if (!descriptor.publicKey) {
        log.debug("Leaving GnapProof.verifyJwsBytes(). No public key.");
        return false;
      }
      if (spec.family === 'okp') {
        const ok = nodeCrypto.verify(null, data, descriptor.publicKey,
                                     signature);
        log.debug("Leaving GnapProof.verifyJwsBytes(). EdDSA " + ok);
        return ok;
      }
      const options: nodeCrypto.VerifyKeyObjectInput = {
        key: descriptor.publicKey
      };
      if (spec.family === 'ec') {
        options.dsaEncoding = 'ieee-p1363';
      }
      if (/^PS/.test(alg)) {
        options.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
        options.saltLength = nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST;
      }
      const ok = nodeCrypto.verify(spec.hash, data, options, signature);
      log.debug("Leaving GnapProof.verifyJwsBytes(). " + alg + " " + ok);
      return ok;
    } catch (e) {
      log.debug("Caught in GnapProof.verifyJwsBytes(): " +
                ((e && e.message) || e));
      // A key that does not fit the algorithm throws inside node. That is a
      // verification failure like any other; the message is the useful detail.
      log.debug("Leaving GnapProof.verifyJwsBytes(). Threw: " + e.message);
      return false;
    }
  }

  // The algorithm a descriptor's JWS proofs must use: the JWK's alg (section
  // 7.3.3: "If the key is presented as a JWK, this MUST be equal to the alg
  // parameter of the key"), the registered one for a shared secret, and the
  // type-derived one for a certificate.
  private expectedJwsAlg(descriptor) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.expectedJwsAlg().");
    log.debug("Leaving GnapProof.expectedJwsAlg().");
    return descriptor.alg || null;
  }

  // ---------------------------------------------------------------------------
  // ONE JWS LAYER, CHECKED AGAINST THE REQUEST. Shared by jwsd and jws, and by
  // both layers of a rotation.
  // ---------------------------------------------------------------------------
  private checkJwsLayer(compact, descriptor, ctx, allowedTypes, payloadCheck) {
    const { log, nowSec, store } = this.deps;
    log.debug("Entering GnapProof.checkJwsLayer(). types=" +
              allowedTypes.join(','));
    const parts = String(compact || '').split('.');
    if (parts.length !== 3) {
      log.debug("Leaving GnapProof.checkJwsLayer(). Not a compact JWS.");
      return this.refusal('STS-GNAP-0262',
                          'the key proof is not a compact JWS (RFC 7515).');
    }
    let header;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in GnapProof.checkJwsLayer(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapProof.checkJwsLayer(). Header is not JSON: " +
                e.message);
      return this.refusal('STS-GNAP-0262',
                          'the key proof\'s JOSE header is not JSON.');
    }
    if (allowedTypes.indexOf(header.typ) < 0) {
      log.debug("Leaving GnapProof.checkJwsLayer(). typ " + header.typ);
      return this.refusal('STS-GNAP-0263',
                          'the key proof\'s typ is "' + header.typ + '"; ' +
                          'this request needs ' +
                          allowedTypes.join(' or ') + ' (RFC 9635 section ' +
                          '7.3).');
    }
    const expected = this.expectedJwsAlg(descriptor);
    if (!header.alg || header.alg === 'none' || header.alg !== expected) {
      log.debug("Leaving GnapProof.checkJwsLayer(). alg " + header.alg +
                " expected " + expected);
      return this.refusal('STS-GNAP-0264',
                          'the key proof\'s alg must be the key\'s own ("' +
                          expected + '") and never "none" (RFC 9635 section ' +
                          '7.3.3).');
    }
    if (descriptor.format === 'jwk' && header.kid !== descriptor.jwk.kid) {
      log.debug("Leaving GnapProof.checkJwsLayer(). kid mismatch.");
      return this.refusal('STS-GNAP-0265',
                          'the key proof\'s kid does not name the presented ' +
                          'JWK (RFC 9635 section 7.3.3).');
    }
    if (header.htm !== ctx.method) {
      log.debug("Leaving GnapProof.checkJwsLayer(). htm mismatch.");
      return this.refusal('STS-GNAP-0266',
                          'the key proof\'s htm is "' + header.htm + '" and ' +
                          'the request method is ' + ctx.method + '.');
    }
    if (header.uri !== ctx.targetUri) {
      log.debug("Leaving GnapProof.checkJwsLayer(). uri mismatch: " +
                header.uri + " vs " + ctx.targetUri);
      return this.refusal('STS-GNAP-0267',
                          'the key proof\'s uri is not the URI this request ' +
                          'was sent to (' + ctx.targetUri + ').');
    }
    const now = nowSec();
    if (!Number.isInteger(header.created) ||
        Math.abs(now - header.created) > this.maxAgeS()) {
      log.debug("Leaving GnapProof.checkJwsLayer(). created out of window.");
      return this.refusal('STS-GNAP-0268', 'the key proof\'s created time is ' +
                          'missing or more than ' +
                          this.maxAgeS() + ' seconds from now.');
    }
    if (ctx.accessToken) {
      if (header.ath !== this.athOf(ctx.accessToken)) {
        log.debug("Leaving GnapProof.checkJwsLayer(). ath mismatch.");
        return this.refusal('STS-GNAP-0269',
                            'the key proof does not carry the hash of the ' +
                            'presented access token in "ath" (RFC 9635 ' +
                            'section 7.3.3).');
      }
    }
    const signature = Buffer.from(parts[2], 'base64url');
    const payloads = payloadCheck(parts[1]);
    if (!payloads.ok) {
      log.debug("Leaving GnapProof.checkJwsLayer(). Payload does not match " +
                "the request.");
      return payloads;
    }
    const verified = payloads.candidates.some((middle) => {
      return this.verifyJwsBytes(header.alg, descriptor, parts[0] + '.' +
                                 middle,
                                 signature);
    });
    if (!verified) {
      log.debug("Leaving GnapProof.checkJwsLayer(). Signature does not " +
                "verify.");
      return this.refusal('STS-GNAP-0270',
                          'the key proof\'s signature does not verify ' +
                          'against the presented key.');
    }
    if (!store.remember('jws|' + parts[2], this.maxAgeS() * 2)) {
      log.debug("Leaving GnapProof.checkJwsLayer(). Replay.");
      return this.refusal('STS-GNAP-0271',
                          'this key proof has already been used.');
    }
    this.noteReplayKey(ctx, 'jws|' + parts[2]);
    log.debug("Leaving GnapProof.checkJwsLayer().");
    return { ok: true, header: header, payload: parts[1] };
  }

  // What the middle segment of a detached JWS may be, given the content.
  private detachedPayloadCheck(raw, hadContent) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.detachedPayloadCheck().");
    log.debug("Leaving GnapProof.detachedPayloadCheck().");
    return (middle) => {
      if (!hadContent) {
        if (middle !== '') {
          return this.refusal('STS-GNAP-0272',
                              'a request with no content is signed over an ' +
                              'empty payload (RFC 9635 section 7.3.3).');
        }
        return { ok: true, candidates: [''] };
      }
      const digest = this.sha256(raw);
      const once = this.b64u(digest);
      const twice = this.b64u(Buffer.from(once, 'ascii'));
      if (middle === '') {
        return { ok: true, candidates: [once, twice] };
      }
      if (middle !== once && middle !== twice) {
        return this.refusal('STS-GNAP-0273',
                            'the detached JWS does not carry the SHA-256 ' +
                            'digest of this request\'s content (RFC 9635 ' +
                            'section 7.3.3).');
      }
      return { ok: true, candidates: [middle] };
    };
  }

  // ---------------------------------------------------------------------------
  // HTTP MESSAGE SIGNATURES (section 7.3.1).
  // ---------------------------------------------------------------------------
  private httpsigAlgorithm(descriptor) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.httpsigAlgorithm().");
    if (descriptor.proof && descriptor.proof.params &&
        descriptor.proof.params.alg) {
      log.debug("Leaving GnapProof.httpsigAlgorithm().");
      return descriptor.proof.params.alg;
    }
    if (descriptor.secret) {
      log.debug("Leaving GnapProof.httpsigAlgorithm().");
      return descriptor.alg === 'HS256' || !descriptor.alg ? 'hmac-sha256' :
             descriptor.alg;
    }
    log.debug("Leaving GnapProof.httpsigAlgorithm().");
    return descriptor.alg;
  }

  // Whether a verified signature covered a component. `gnap_httpsig.ts` reports
  // covered components as their SERIALISED identifiers (RFC 9421 section 2:
  // `"signature";key="old-key"`), so the comparison is on that spelling —
  // parsed back through the structured-field parser rather than matched as
  // text, because parameter order and quoting are the serialiser's to choose.
  private componentNamed(components, name, key) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.componentNamed().");
    const sf = require('./gnap_sf');
    log.debug("Leaving GnapProof.componentNamed().");
    return (components || []).some((serialised) => {
      let item;
      try {
        item = typeof serialised === 'string' ? sf.parseItem(serialised) :
               serialised;
      } catch (e) {
        log.debug("Caught in a callback in componentNamed(): " +
                  ((e && e.message) || e));
        // Not a component identifier this parser reads; it covers nothing asked
        // about.
        return false;
      }
      if (!item || item.value !== name) {
        return false;
      }
      if (key === undefined) {
        return true;
      }
      return sf.paramValue(item.params, 'key') === key;
    });
  }

  private verifyHttpsig(req, descriptor, ctx) {
    const { log, nowSec, errorCodes, httpsig, store } = this.deps;
    log.debug("Entering GnapProof.verifyHttpsig().");
    const message = { method: ctx.method, targetUri: ctx.targetUri,
                      headers: req.headers };
    if (ctx.hadContent) {
      const accepted = [(descriptor.proof.params &&
                         descriptor.proof.params.contentDigestAlg) ||
                         'sha-256'];
      const digest = httpsig.verifyContentDigest(req.headers['content-digest'],
                                                 ctx.raw,
                                                 { accepted: accepted });
      if (!digest.ok) {
        log.debug("Leaving GnapProof.verifyHttpsig(). Content-Digest refused.");
        return this.refusal(errorCodes.codeOf(digest) || 'STS-GNAP-0274',
                            'the Content-Digest does not match the request ' +
                            'content: ' + digest.why);
      }
    }
    const required = ['@method', '@target-uri'];
    if (ctx.hadContent) {
      required.push('content-digest');
    }
    if (ctx.accessToken) {
      required.push('authorization');
    }
    const result = httpsig.verify(message, {
      keyFor: (parsed) => {
        log.debug("Entering keyFor().");
        if (parsed.params.tag !== (ctx.tag || 'gnap')) {
          log.debug("Leaving keyFor().");
          return null;
        }
        if (descriptor.format === 'jwk' &&
            parsed.params.keyid !== descriptor.jwk.kid) {
          log.debug("Leaving keyFor().");
          return null;
        }
        log.debug("Leaving keyFor().");
        return { key: descriptor.secret || descriptor.publicKey,
                 algorithm: this.httpsigAlgorithm(descriptor) };
      },
      now: nowSec(),
      maxAgeS: this.maxAgeS(),
      requireComponents: required,
      requireTag: ctx.tag || 'gnap',
      requireCreated: true,
      // RFC 9635 section 7.3.1: "The verifier MUST examine all included
      // signatures until it finds (at least) one that is acceptable" — and a
      // key rotation carries two, only one of which is for this key.
      require: 'any',
      forbidAlgParam: true
    });
    if (!result.ok) {
      log.debug("Leaving GnapProof.verifyHttpsig(). " + result.why);
      return this.refusal(errorCodes.codeOf(result) || 'STS-GNAP-0275',
                          'the HTTP message signature does not verify: ' +
                          result.why);
    }
    const chosen = result.verified[0];
    if (chosen.params.nonce &&
        !store.remember('httpsig|' + descriptor.identity + '|' +
                        chosen.params.nonce, this.maxAgeS() * 2)) {
      log.debug("Leaving GnapProof.verifyHttpsig(). Nonce replay.");
      return this.refusal('STS-GNAP-0276',
                          'the signature nonce has already been used (RFC ' +
                          '9635 section 7.3.1).');
    }
    if (chosen.params.nonce) {
      this.noteReplayKey(ctx, 'httpsig|' + descriptor.identity + '|' +
                         chosen.params.nonce);
    }
    log.debug("Leaving GnapProof.verifyHttpsig(). label=" + chosen.label);
    return { ok: true, verified: result.verified };
  }

  // ---------------------------------------------------------------------------
  // MUTUAL TLS (section 7.3.2).
  // ---------------------------------------------------------------------------
  private verifyMtls(req, descriptor) {
    const { nodeCrypto, log, stsCrypto, mtls } = this.deps;
    log.debug("Entering GnapProof.verifyMtls().");
    const certificate = mtls.peerCertificate(req);
    if (!certificate) {
      log.debug("Leaving GnapProof.verifyMtls(). No client certificate.");
      return this.refusal('STS-GNAP-0277',
                          'the key is proved by mutual TLS and this ' +
                          'connection presented no client certificate (RFC ' +
                          '9635 section 7.3.2).');
    }
    const thumbprint = stsCrypto.certificateThumbprint(certificate.raw);
    if (descriptor.format === 'cert' || descriptor.format === 'cert#S256') {
      if (thumbprint !== descriptor.thumbprint) {
        log.debug("Leaving GnapProof.verifyMtls(). Thumbprint mismatch.");
        return this.refusal('STS-GNAP-0278',
                            'the TLS client certificate is not the ' +
                            'certificate the key names.');
      }
      log.debug("Leaving GnapProof.verifyMtls(). Certificate matches.");
      return { ok: true, thumbprint: thumbprint };
    }
    if (descriptor.publicKey) {
      // A JWK proved over MTLS: the same PUBLIC KEY, compared as
      // SubjectPublicKeyInfo.
      const presented =
        new nodeCrypto.X509Certificate(certificate.raw).publicKey
          .export({ type: 'spki', format: 'der' });
      const expected = descriptor.publicKey.export(
          { type: 'spki', format: 'der' });
      if (Buffer.compare(presented, expected) === 0) {
        log.debug("Leaving GnapProof.verifyMtls(). JWK matches the " +
                  "certificate's key.");
        return { ok: true, thumbprint: thumbprint };
      }
    }
    log.debug("Leaving GnapProof.verifyMtls(). Key does not match.");
    return this.refusal('STS-GNAP-0278',
                        'the TLS client certificate does not carry the ' +
                        'presented key.');
  }

  // ---------------------------------------------------------------------------
  // THE ENTRY POINT.
  //
  // `options.accessToken` — the token this request is bound to, if any.
  // `options.rotation` — the new key's descriptor for a key rotation (section
  // 6.1.1); both keys are proved, in the order and with the coverage section
  // 7.3 requires.
  // ---------------------------------------------------------------------------
  verifyRequest(req, body, descriptor, options) {
    const { log, mtls, httpsig } = this.deps;
    log.debug("Entering GnapProof.verifyRequest(). method=" +
              (descriptor && descriptor.proof &&
              descriptor.proof.method));
    const opts = options || {};
    if (!descriptor || !descriptor.ok) {
      log.debug("Leaving GnapProof.verifyRequest(). No key.");
      return this.refusal('STS-GNAP-0279',
                          'no key to verify this request with.');
    }
    const ctx = { method: req.method, targetUri: this.targetUriOf(req),
                  accessToken: opts.accessToken || null,
                  hadContent: body.hadContent, raw: body.raw,
                  // What the replay cache remembered for this request, so that
                  // verifyRequestOnce() can spend the same keys across the
                  // cluster. Shared by reference with a rotation's second ctx.
                  replayKeys: [] };
    const method = descriptor.proof.method;
    if (descriptor.format === 'cert#S256' && method !== 'mtls') {
      log.debug("Leaving GnapProof.verifyRequest(). Thumbprint-only key with " +
                "a signature method.");
      return this.refusal('STS-GNAP-0280',
                          'a "cert#S256" key carries no public key and can ' +
                          'only be proved by mutual TLS (RFC 9635 section ' +
                          '7.1).');
    }
    const rotation = opts.rotation || null;
    if (rotation &&
        !require('./gnap_keys').sameProof(rotation.proof, descriptor.proof)) {
      log.debug("Leaving GnapProof.verifyRequest(). Rotation changes the " +
                "proofing method.");
      return this.refusal('STS-GNAP-0281',
                          'a key rotation must keep the proofing method and ' +
                          'its parameters (RFC 9635 section ' +
                          '6.1.1).', 'invalid_rotation');
    }
    let outcome;
    if (method === 'mtls') {
      if (rotation) {
        log.debug("Leaving GnapProof.verifyRequest(). MTLS cannot rotate.");
        return this.refusal('STS-GNAP-0282',
                            'key rotation is not defined for mutual TLS (RFC ' +
                            '9635 section ' +
                            '7.3.2.1).', 'key_rotation_not_supported');
      }
      outcome = this.verifyMtls(req, descriptor);
    } else if (method === 'httpsig') {
      outcome = rotation
        ? this.verifyHttpsigRotation(req, descriptor, rotation, ctx)
        : this.verifyHttpsig(req, descriptor, ctx);
    } else if (method === 'jwsd') {
      outcome = rotation
        ? this.verifyJwsdRotation(req, descriptor, rotation, ctx)
        : this.verifyJwsd(req, descriptor, ctx);
    } else if (method === 'jws') {
      outcome = rotation
        ? this.verifyJwsRotation(req, body, descriptor, rotation, ctx)
        : this.verifyJws(req, body, descriptor, ctx);
    } else {
      outcome = this.refusal('STS-GNAP-0283', 'the proofing method "' + method +
                             '" is not implemented.');
    }
    if (!outcome.ok && rotation) {
      outcome.gnapError = outcome.gnapError === 'key_rotation_not_supported'
        ? outcome.gnapError : 'invalid_rotation';
    }
    log.debug("Leaving GnapProof.verifyRequest(). ok=" + outcome.ok);
    return Object.assign(outcome, { method: method,
                                    replayKeys: ctx.replayKeys });
  }

  // ---------------------------------------------------------------------------
  // THE REPLAY CACHE ACROSS THE CLUSTER (2026-09-14, #46).
  //
  // `store.remember()` is synchronous and is where a replay is refused first —
  // inside `checkJwsLayer()` and `verifyHttpsig()`, several calls deep in a
  // verification that is synchronous from its five callers down. Its map is
  // replicated, not shared, so a proof accepted on one node was accepted again
  // on another inside the replication window: exactly the replay section
  // 7.3.1's "MUST determine that the nonce value is unique" is there to stop.
  //
  // A database answer cannot be had inside a synchronous function, and making
  // the whole verification asynchronous would put an await between every layer
  // of a rotation's two signatures for no reason. So the keys the cache
  // remembered are COLLECTED on the verification's context (`noteReplayKey()`),
  // returned on its outcome, and SPENT AT THE ASYNC BOUNDARY:
  // `verifyRequestOnce()` is `verifyRequest()` followed by one cluster claim
  // per key, and every caller that acts on a verified request calls it instead,
  // before it acts. The in-memory check therefore stays first and unchanged,
  // and a proof this process had never seen is refused as a replay when another
  // node has already accepted it. A claim lives for the window the cache
  // remembers a key (twice `gnap.signatureMaxAgeS`), plus the store's skew.
  //
  // `presentation()` in gnap_rs.ts keeps the synchronous call, because
  // ssf/ssf_auth.js calls it synchronously; its asynchronous caller spends the
  // keys it returns (see there).
  // ---------------------------------------------------------------------------
  private noteReplayKey(ctx, key) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.noteReplayKey().");
    if (ctx && Array.isArray(ctx.replayKeys)) {
      ctx.replayKeys.push(key);
    }
    log.debug("Leaving GnapProof.noteReplayKey().");
  }

  async spendProof(verified) {
    const { log, store } = this.deps;
    log.debug("Entering GnapProof.spendProof().");
    const replayKeys = (verified && verified.replayKeys) || [];
    for (const key of replayKeys) {
      const spent = await store.spend('proof', key, this.maxAgeS() * 2,
                                      'STS-GNAP-0715');
      if (!spent.ok && spent.reason === 'used') {
        log.debug("Leaving GnapProof.spendProof(). Replayed on another node.");
        return this.refusal('STS-GNAP-0715',
                            'this key proof has already been used (RFC 9635 ' +
                            'section 7.3.1).');
      }
      if (!spent.ok) {
        log.debug("Leaving GnapProof.spendProof(). The claim store could not " +
                  "be asked.");
        return this.refusal('STS-GNAP-0716',
                            'this authorization server could not confirm the ' +
                            'key proof is unused; retry with a fresh ' +
                            'signature.');
      }
    }
    log.debug("Leaving GnapProof.spendProof(). " + replayKeys.length +
              " key(s) spent.");
    return { ok: true };
  }

  async verifyRequestOnce(req, body, descriptor, options) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.verifyRequestOnce().");
    const verified = this.verifyRequest(req, body, descriptor, options);
    if (!verified.ok) {
      log.debug("Leaving GnapProof.verifyRequestOnce(). Refused locally.");
      return verified;
    }
    const spent = await this.spendProof(verified);
    if (!spent.ok) {
      log.debug("Leaving GnapProof.verifyRequestOnce(). Refused at the spend.");
      return Object.assign(spent, { method: verified.method });
    }
    log.debug("Leaving GnapProof.verifyRequestOnce().");
    return verified;
  }

  private verifyJwsd(req, descriptor, ctx) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.verifyJwsd().");
    const header = req.headers['detached-jws'];
    if (!header) {
      log.debug("Leaving GnapProof.verifyJwsd().");
      return this.refusal('STS-GNAP-0284',
                          'the key is proved by a detached JWS and the ' +
                          'request has no Detached-JWS header (RFC 9635 ' +
                          'section 7.3.3).');
    }
    log.debug("Leaving GnapProof.verifyJwsd().");
    return this.checkJwsLayer(header, descriptor, ctx, ['gnap-binding-jwsd'],
                              this.detachedPayloadCheck(ctx.raw,
                              ctx.hadContent));
  }

  private verifyJws(req, body, descriptor, ctx) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.verifyJws().");
    if (!ctx.hadContent) {
      // Section 7.3.4: with no content the attached method signs an empty
      // payload and sends it in Detached-JWS — the section names no typ for
      // that case, so either binding type is accepted.
      const header = req.headers['detached-jws'];
      if (!header) {
        log.debug("Leaving GnapProof.verifyJws().");
        return this.refusal('STS-GNAP-0284',
                            'a request with no content proved by "jws" ' +
                            'carries its signature in the Detached-JWS ' +
                            'header (RFC 9635 section 7.3.4).');
      }
      log.debug("Leaving GnapProof.verifyJws().");
      return this.checkJwsLayer(header, descriptor, ctx,
                                ['gnap-binding-jws', 'gnap-binding-jwsd'],
                                this.detachedPayloadCheck(ctx.raw, false));
    }
    if (!body.jose) {
      log.debug("Leaving GnapProof.verifyJws().");
      return this.refusal('STS-GNAP-0285',
                          'the key is proved by an attached JWS and the ' +
                          'request content is not one (RFC 9635 section ' +
                          '7.3.4).');
    }
    log.debug("Leaving GnapProof.verifyJws().");
    return this.checkJwsLayer(body.jose, descriptor, ctx, ['gnap-binding-jws'],
                              (middle) => {
      return { ok: true, candidates: [middle] };
    });
  }

  // Section 7.3.1.1: the old key signs normally (tag gnap), the new key signs a
  // second time (tag gnap-rotate) covering the first signature and its input.
  private verifyHttpsigRotation(req, oldKey, newKey, ctx) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.verifyHttpsigRotation().");
    const first = this.verifyHttpsig(req, oldKey, ctx);
    if (!first.ok) {
      log.debug("Leaving GnapProof.verifyHttpsigRotation(). Old key refused.");
      return first;
    }
    const oldLabels = first.verified.map((one) => {
      return one.label;
    });
    const second = this.verifyHttpsig(req, newKey,
                                      Object.assign({}, ctx,
                                      { tag: 'gnap-rotate' }));
    if (!second.ok) {
      log.debug("Leaving GnapProof.verifyHttpsigRotation(). New key refused.");
      return second;
    }
    const covers = second.verified.some((one) => {
      return oldLabels.some((label) => {
        return this.componentNamed(one.components, 'signature', label) &&
          this.componentNamed(one.components, 'signature-input', label);
      });
    });
    if (!covers) {
      log.debug("Leaving GnapProof.verifyHttpsigRotation(). New signature " +
                "does not cover the old one.");
      return this.refusal('STS-GNAP-0286',
                          'the new key\'s signature must cover the old ' +
                          'key\'s "signature" and "signature-input" (RFC ' +
                          '9635 section 7.3.1.1).');
    }
    log.debug("Leaving GnapProof.verifyHttpsigRotation().");
    return { ok: true };
  }

  // Section 7.3.3.1: the new key signs a JWS whose payload is the old key's JWS
  // (typ gnap-binding-rotation-jwsd), which signs the content digest.
  private verifyJwsdRotation(req, oldKey, newKey, ctx) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.verifyJwsdRotation().");
    const outer = req.headers['detached-jws'];
    if (!outer) {
      log.debug("Leaving GnapProof.verifyJwsdRotation(). No header.");
      return this.refusal('STS-GNAP-0284',
                          'a detached-JWS key rotation carries its proof in ' +
                          'the Detached-JWS header (RFC 9635 section ' +
                          '7.3.3.1).');
    }
    let inner = null;
    const checkedOuter = this.checkJwsLayer(outer, newKey, ctx,
                                            ['gnap-binding-jwsd'],
                                            (middle) => {
      inner = Buffer.from(middle, 'base64url').toString('ascii');
      return { ok: true, candidates: [middle] };
    });
    if (!checkedOuter.ok) {
      log.debug("Leaving GnapProof.verifyJwsdRotation(). Outer layer refused.");
      return checkedOuter;
    }
    const checkedInner = this.checkJwsLayer(inner, oldKey, ctx,
                                            ['gnap-binding-rotation-jwsd'],
                                            this.detachedPayloadCheck(ctx.raw,
                                                            ctx.hadContent));
    log.debug("Leaving GnapProof.verifyJwsdRotation(). inner ok=" +
              checkedInner.ok);
    return checkedInner.ok ? { ok: true } : checkedInner;
  }

  // Section 7.3.4.1: the same nesting, attached.
  private verifyJwsRotation(req, body, oldKey, newKey, ctx) {
    const { log } = this.deps;
    log.debug("Entering GnapProof.verifyJwsRotation().");
    if (!body.jose) {
      log.debug("Leaving GnapProof.verifyJwsRotation(). Content is not a JWS.");
      return this.refusal('STS-GNAP-0285',
                          'an attached-JWS key rotation sends a JWS as the ' +
                          'content (RFC 9635 section 7.3.4.1).');
    }
    let inner = null;
    const checkedOuter = this.checkJwsLayer(body.jose, newKey, ctx,
                                            ['gnap-binding-jws'], (middle) => {
      inner = Buffer.from(middle, 'base64url').toString('utf8');
      return { ok: true, candidates: [middle] };
    });
    if (!checkedOuter.ok) {
      log.debug("Leaving GnapProof.verifyJwsRotation(). Outer layer refused.");
      return checkedOuter;
    }
    if (inner && inner.charAt(0) === '"') {
      // A payload that is the JSON STRING of the inner JWS rather than its bare
      // characters — both spellings of "the value of the JWS object is taken as
      // the payload" exist, and they carry the same signature.
      try {
        inner = JSON.parse(inner);
      } catch (e) {
        log.debug("Caught in GnapProof.verifyJwsRotation(): " +
                  ((e && e.message) || e));
        // Left as it was; the inner check below refuses it with a sentence.
        log.debug("verifyJwsRotation(): inner payload is not a JSON string: " +
                  e.message);
      }
    }
    const checkedInner = this.checkJwsLayer(inner, oldKey, ctx,
                                            ['gnap-binding-rotation-jws'],
                                            (middle) => {
      return { ok: true, candidates: [middle] };
    });
    log.debug("Leaving GnapProof.verifyJwsRotation(). inner ok=" +
              checkedInner.ok);
    return checkedInner.ok ? { ok: true } : checkedInner;
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one; `helpers` supplies the
// logger and the base-URL and clock readers, as it did for this module
// before.
const proof = new GnapProof({
  nodeCrypto: nodeCrypto,
  config: config,
  log: helpers.log,
  baseUrlOf: helpers.baseUrlOf,
  nowSec: helpers.nowSec,
  stsCrypto: stsCrypto,
  errorCodes: errorCodes,
  mtls: mtls,
  httpsig: httpsig,
  store: store
});

export = {
  GnapProof: GnapProof,
  readBody: proof.readBody.bind(proof) as GnapProof['readBody'],
  verifyRequest: proof.verifyRequest.bind(proof) as GnapProof['verifyRequest'],
  verifyRequestOnce:
    proof.verifyRequestOnce.bind(proof) as GnapProof['verifyRequestOnce'],
  spendProof: proof.spendProof.bind(proof) as GnapProof['spendProof'],
  presentedToken:
    proof.presentedToken.bind(proof) as GnapProof['presentedToken'],
  targetUriOf: proof.targetUriOf.bind(proof) as GnapProof['targetUriOf'],
  athOf: proof.athOf.bind(proof) as GnapProof['athOf'],
  verifyJwsBytes:
    proof.verifyJwsBytes.bind(proof) as GnapProof['verifyJwsBytes']
};
