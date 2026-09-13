'use strict';
//
// File: gnap_proof.js
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
// `gnap_keys.js`, and every one of those callers gets the same answer.
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
// proved key it has never seen, and that is `gnap.js`'s, mode-gated.
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
// EMPTY (a true RFC 7515 Appendix F detached payload) is reconstructed each way.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const config = require('../common/config');
const { log, baseUrlOf, nowSec } = require('../common/helpers');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');
const mtls = require('../oauth-oidc/mtls');
const httpsig = require('./gnap_httpsig');
const store = require('./gnap_store');

function refusal(code, why, gnapError) {
  const out = { ok: false, errorCode: code, why: why, gnapError: gnapError || 'invalid_client' };
  return errorCodes.mark(out, code);
}

function maxAgeS() {
  const value = Number(config.value('gnap.signatureMaxAgeS'));
  return Number.isFinite(value) && value > 0 ? value : 300;
}

function b64u(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function sha256(bytes) {
  return nodeCrypto.createHash('sha256').update(bytes).digest();
}

// The access token hash of sections 7.3.3/7.3.4: base64url SHA-256 of the
// ASCII token value — the same computation as DPoP's `ath` (RFC 9449).
function athOf(token) {
  return b64u(sha256(Buffer.from(String(token), 'ascii')));
}

// The absolute URI the client addressed. `baseUrlOf()` carries scheme, host
// and the realm prefix the front middleware stripped; `req.url` is the rest.
// A signature over any other spelling of the URI fails, which is correct: the
// client signed the URI the AS gave it, and section 3.1 says to use it exactly.
function targetUriOf(req) {
  return baseUrlOf(req) + (req.url || '');
}

// The GNAP token in `Authorization`, when the request carries one.
function presentedToken(req) {
  const header = String((req.headers && req.headers.authorization) || '');
  const match = header.match(/^GNAP\s+([A-Za-z0-9\-._~+/]+=*)\s*$/);
  return match ? match[1] : null;
}

// ---------------------------------------------------------------------------
// THE REQUEST CONTENT, READ ONCE, BEFORE ANYTHING IS VERIFIED.
//
// A grant request carries the very key it must be verified with, so the body
// has to be READ before the proof can be CHECKED — for `jws` that means
// decoding a payload whose signature has not been checked yet. That is safe for
// one reason, and `verifyRequest()` keeps it true: nothing read here is acted
// on until the proof over it has verified against the key it names.
// ---------------------------------------------------------------------------
function readBody(req) {
  log.debug("Entering readBody().");
  const raw = Buffer.isBuffer(req.rawBody) ? req.rawBody
    : Buffer.from(typeof req.body === 'string' ? req.body : '', 'utf8');
  const hadContent = raw.length > 0;
  if (!hadContent) {
    log.debug("Leaving readBody(). No content.");
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
        json = JSON.parse(Buffer.from(json.split('.')[1], 'base64url').toString('utf8'));
      }
    } catch (e) {
      const inner = Buffer.from(parts[1] || '', 'base64url').toString('utf8');
      if (inner.split('.').length === 3) {
        try {
          json = JSON.parse(Buffer.from(inner.split('.')[1], 'base64url').toString('utf8'));
        } catch (e2) {
          // Neither layer is JSON; refused below with one sentence.
          json = undefined;
        }
      }
      if (json === undefined) {
        log.debug("Leaving readBody(). An attached JWS whose payload is not JSON.");
        return refusal('STS-GNAP-0260', 'the request content is a JWS whose payload is not a ' +
                       'JSON object (RFC 9635 section 7.3.4).', 'invalid_request');
      }
    }
    log.debug("Leaving readBody(). Attached JWS.");
    return { ok: true, hadContent: true, raw: raw, json: json, jose: text.trim() };
  }
  try {
    const json = JSON.parse(text);
    log.debug("Leaving readBody(). JSON.");
    return { ok: true, hadContent: true, raw: raw, json: json, jose: null };
  } catch (e) {
    log.debug("Leaving readBody(). Not JSON: " + e.message);
    return refusal('STS-GNAP-0261', 'the request content is not JSON (RFC 9635 section 2 ' +
                   'requires a JSON object with Content-Type application/json).',
                   'invalid_request');
  }
}

// ---------------------------------------------------------------------------
// A JWS SIGNATURE OVER AN ARBITRARY SIGNING INPUT.
//
// `common/crypto.js`'s `verifyCompactJws()` insists on a JSON payload, which is
// right for every token this service reads and wrong for a detached JWS, whose
// payload is a digest. So the byte check is here — for the classical families
// only, which is every algorithm a GNAP key can carry (`gnap_keys.js` refuses
// the rest), and with node's own primitives.
// ---------------------------------------------------------------------------
function verifyJwsBytes(alg, descriptor, signingInput, signature) {
  log.debug("Entering verifyJwsBytes(). alg=" + alg);
  const spec = stsCrypto.JWS_ALGS[alg];
  if (!spec || alg === 'none') {
    log.debug("Leaving verifyJwsBytes(). Unknown algorithm.");
    return false;
  }
  const data = Buffer.from(signingInput, 'ascii');
  try {
    if (spec.family === 'hmac') {
      if (!descriptor.secret) {
        log.debug("Leaving verifyJwsBytes(). HMAC with no shared secret.");
        return false;
      }
      const mac = nodeCrypto.createHmac(spec.hash, descriptor.secret).update(data).digest();
      const ok = mac.length === signature.length && nodeCrypto.timingSafeEqual(mac, signature);
      log.debug("Leaving verifyJwsBytes(). HMAC " + ok);
      return ok;
    }
    if (!descriptor.publicKey) {
      log.debug("Leaving verifyJwsBytes(). No public key.");
      return false;
    }
    if (spec.family === 'okp') {
      const ok = nodeCrypto.verify(null, data, descriptor.publicKey, signature);
      log.debug("Leaving verifyJwsBytes(). EdDSA " + ok);
      return ok;
    }
    const options = { key: descriptor.publicKey };
    if (spec.family === 'ec') {
      options.dsaEncoding = 'ieee-p1363';
    }
    if (/^PS/.test(alg)) {
      options.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
      options.saltLength = nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST;
    }
    const ok = nodeCrypto.verify(spec.hash, data, options, signature);
    log.debug("Leaving verifyJwsBytes(). " + alg + " " + ok);
    return ok;
  } catch (e) {
    // A key that does not fit the algorithm throws inside node. That is a
    // verification failure like any other; the message is the useful detail.
    log.debug("Leaving verifyJwsBytes(). Threw: " + e.message);
    return false;
  }
}

// The algorithm a descriptor's JWS proofs must use: the JWK's alg (section
// 7.3.3: "If the key is presented as a JWK, this MUST be equal to the alg
// parameter of the key"), the registered one for a shared secret, and the
// type-derived one for a certificate.
function expectedJwsAlg(descriptor) {
  return descriptor.alg || null;
}

// ---------------------------------------------------------------------------
// ONE JWS LAYER, CHECKED AGAINST THE REQUEST. Shared by jwsd and jws, and by
// both layers of a rotation.
// ---------------------------------------------------------------------------
function checkJwsLayer(compact, descriptor, ctx, allowedTypes, payloadCheck) {
  log.debug("Entering checkJwsLayer(). types=" + allowedTypes.join(','));
  const parts = String(compact || '').split('.');
  if (parts.length !== 3) {
    log.debug("Leaving checkJwsLayer(). Not a compact JWS.");
    return refusal('STS-GNAP-0262', 'the key proof is not a compact JWS (RFC 7515).');
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch (e) {
    log.debug("Leaving checkJwsLayer(). Header is not JSON: " + e.message);
    return refusal('STS-GNAP-0262', 'the key proof\'s JOSE header is not JSON.');
  }
  if (allowedTypes.indexOf(header.typ) < 0) {
    log.debug("Leaving checkJwsLayer(). typ " + header.typ);
    return refusal('STS-GNAP-0263', 'the key proof\'s typ is "' + header.typ + '"; this ' +
                   'request needs ' + allowedTypes.join(' or ') + ' (RFC 9635 section 7.3).');
  }
  const expected = expectedJwsAlg(descriptor);
  if (!header.alg || header.alg === 'none' || header.alg !== expected) {
    log.debug("Leaving checkJwsLayer(). alg " + header.alg + " expected " + expected);
    return refusal('STS-GNAP-0264', 'the key proof\'s alg must be the key\'s own ("' +
                   expected + '") and never "none" (RFC 9635 section 7.3.3).');
  }
  if (descriptor.format === 'jwk' && header.kid !== descriptor.jwk.kid) {
    log.debug("Leaving checkJwsLayer(). kid mismatch.");
    return refusal('STS-GNAP-0265', 'the key proof\'s kid does not name the presented JWK ' +
                   '(RFC 9635 section 7.3.3).');
  }
  if (header.htm !== ctx.method) {
    log.debug("Leaving checkJwsLayer(). htm mismatch.");
    return refusal('STS-GNAP-0266', 'the key proof\'s htm is "' + header.htm + '" and the ' +
                   'request method is ' + ctx.method + '.');
  }
  if (header.uri !== ctx.targetUri) {
    log.debug("Leaving checkJwsLayer(). uri mismatch: " + header.uri + " vs " + ctx.targetUri);
    return refusal('STS-GNAP-0267', 'the key proof\'s uri is not the URI this request was ' +
                   'sent to (' + ctx.targetUri + ').');
  }
  const now = nowSec();
  if (!Number.isInteger(header.created) || Math.abs(now - header.created) > maxAgeS()) {
    log.debug("Leaving checkJwsLayer(). created out of window.");
    return refusal('STS-GNAP-0268', 'the key proof\'s created time is missing or more than ' +
                   maxAgeS() + ' seconds from now.');
  }
  if (ctx.accessToken) {
    if (header.ath !== athOf(ctx.accessToken)) {
      log.debug("Leaving checkJwsLayer(). ath mismatch.");
      return refusal('STS-GNAP-0269', 'the key proof does not carry the hash of the presented ' +
                     'access token in "ath" (RFC 9635 section 7.3.3).');
    }
  }
  const signature = Buffer.from(parts[2], 'base64url');
  const payloads = payloadCheck(parts[1]);
  if (!payloads.ok) {
    log.debug("Leaving checkJwsLayer(). Payload does not match the request.");
    return payloads;
  }
  const verified = payloads.candidates.some(function (middle) {
    return verifyJwsBytes(header.alg, descriptor, parts[0] + '.' + middle, signature);
  });
  if (!verified) {
    log.debug("Leaving checkJwsLayer(). Signature does not verify.");
    return refusal('STS-GNAP-0270', 'the key proof\'s signature does not verify against the ' +
                   'presented key.');
  }
  if (!store.remember('jws|' + parts[2], maxAgeS() * 2)) {
    log.debug("Leaving checkJwsLayer(). Replay.");
    return refusal('STS-GNAP-0271', 'this key proof has already been used.');
  }
  log.debug("Leaving checkJwsLayer().");
  return { ok: true, header: header, payload: parts[1] };
}

// What the middle segment of a detached JWS may be, given the content.
function detachedPayloadCheck(raw, hadContent) {
  return function (middle) {
    if (!hadContent) {
      if (middle !== '') {
        return refusal('STS-GNAP-0272', 'a request with no content is signed over an empty ' +
                       'payload (RFC 9635 section 7.3.3).');
      }
      return { ok: true, candidates: [''] };
    }
    const digest = sha256(raw);
    const once = b64u(digest);
    const twice = b64u(Buffer.from(once, 'ascii'));
    if (middle === '') {
      return { ok: true, candidates: [once, twice] };
    }
    if (middle !== once && middle !== twice) {
      return refusal('STS-GNAP-0273', 'the detached JWS does not carry the SHA-256 digest of ' +
                     'this request\'s content (RFC 9635 section 7.3.3).');
    }
    return { ok: true, candidates: [middle] };
  };
}

// ---------------------------------------------------------------------------
// HTTP MESSAGE SIGNATURES (section 7.3.1).
// ---------------------------------------------------------------------------
function httpsigAlgorithm(descriptor) {
  if (descriptor.proof && descriptor.proof.params && descriptor.proof.params.alg) {
    return descriptor.proof.params.alg;
  }
  if (descriptor.secret) {
    return descriptor.alg === 'HS256' || !descriptor.alg ? 'hmac-sha256' : descriptor.alg;
  }
  return descriptor.alg;
}

// Whether a verified signature covered a component. `gnap_httpsig.js` reports
// covered components as their SERIALISED identifiers (RFC 9421 section 2:
// `"signature";key="old-key"`), so the comparison is on that spelling — parsed
// back through the structured-field parser rather than matched as text, because
// parameter order and quoting are the serialiser's to choose.
function componentNamed(components, name, key) {
  const sf = require('./gnap_sf');
  return (components || []).some(function (serialised) {
    let item;
    try {
      item = typeof serialised === 'string' ? sf.parseItem(serialised) : serialised;
    } catch (e) {
      // Not a component identifier this parser reads; it covers nothing asked about.
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

function verifyHttpsig(req, descriptor, ctx) {
  log.debug("Entering verifyHttpsig().");
  const message = { method: ctx.method, targetUri: ctx.targetUri, headers: req.headers };
  if (ctx.hadContent) {
    const accepted = [(descriptor.proof.params && descriptor.proof.params.contentDigestAlg) || 'sha-256'];
    const digest = httpsig.verifyContentDigest(req.headers['content-digest'], ctx.raw,
                                               { accepted: accepted });
    if (!digest.ok) {
      log.debug("Leaving verifyHttpsig(). Content-Digest refused.");
      return refusal(errorCodes.codeOf(digest) || 'STS-GNAP-0274',
                     'the Content-Digest does not match the request content: ' + digest.why);
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
    keyFor: function (parsed) {
      if (parsed.params.tag !== (ctx.tag || 'gnap')) {
        return null;
      }
      if (descriptor.format === 'jwk' && parsed.params.keyid !== descriptor.jwk.kid) {
        return null;
      }
      return { key: descriptor.secret || descriptor.publicKey, algorithm: httpsigAlgorithm(descriptor) };
    },
    now: nowSec(),
    maxAgeS: maxAgeS(),
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
    log.debug("Leaving verifyHttpsig(). " + result.why);
    return refusal(errorCodes.codeOf(result) || 'STS-GNAP-0275',
                   'the HTTP message signature does not verify: ' + result.why);
  }
  const chosen = result.verified[0];
  if (chosen.params.nonce &&
      !store.remember('httpsig|' + descriptor.identity + '|' + chosen.params.nonce, maxAgeS() * 2)) {
    log.debug("Leaving verifyHttpsig(). Nonce replay.");
    return refusal('STS-GNAP-0276', 'the signature nonce has already been used (RFC 9635 ' +
                   'section 7.3.1).');
  }
  log.debug("Leaving verifyHttpsig(). label=" + chosen.label);
  return { ok: true, verified: result.verified };
}

// ---------------------------------------------------------------------------
// MUTUAL TLS (section 7.3.2).
// ---------------------------------------------------------------------------
function verifyMtls(req, descriptor) {
  log.debug("Entering verifyMtls().");
  const certificate = mtls.peerCertificate(req);
  if (!certificate) {
    log.debug("Leaving verifyMtls(). No client certificate.");
    return refusal('STS-GNAP-0277', 'the key is proved by mutual TLS and this connection ' +
                   'presented no client certificate (RFC 9635 section 7.3.2).');
  }
  const thumbprint = stsCrypto.certificateThumbprint(certificate.raw);
  if (descriptor.format === 'cert' || descriptor.format === 'cert#S256') {
    if (thumbprint !== descriptor.thumbprint) {
      log.debug("Leaving verifyMtls(). Thumbprint mismatch.");
      return refusal('STS-GNAP-0278', 'the TLS client certificate is not the certificate the ' +
                     'key names.');
    }
    log.debug("Leaving verifyMtls(). Certificate matches.");
    return { ok: true, thumbprint: thumbprint };
  }
  if (descriptor.publicKey) {
    // A JWK proved over MTLS: the same PUBLIC KEY, compared as SubjectPublicKeyInfo.
    const presented = new nodeCrypto.X509Certificate(certificate.raw).publicKey
      .export({ type: 'spki', format: 'der' });
    const expected = descriptor.publicKey.export({ type: 'spki', format: 'der' });
    if (Buffer.compare(presented, expected) === 0) {
      log.debug("Leaving verifyMtls(). JWK matches the certificate's key.");
      return { ok: true, thumbprint: thumbprint };
    }
  }
  log.debug("Leaving verifyMtls(). Key does not match.");
  return refusal('STS-GNAP-0278', 'the TLS client certificate does not carry the presented key.');
}

// ---------------------------------------------------------------------------
// THE ENTRY POINT.
//
// `options.accessToken` — the token this request is bound to, if any.
// `options.rotation` — the new key's descriptor for a key rotation (section
// 6.1.1); both keys are proved, in the order and with the coverage section
// 7.3 requires.
// ---------------------------------------------------------------------------
function verifyRequest(req, body, descriptor, options) {
  log.debug("Entering verifyRequest(). method=" + (descriptor && descriptor.proof &&
            descriptor.proof.method));
  const opts = options || {};
  if (!descriptor || !descriptor.ok) {
    log.debug("Leaving verifyRequest(). No key.");
    return refusal('STS-GNAP-0279', 'no key to verify this request with.');
  }
  const ctx = { method: req.method, targetUri: targetUriOf(req), accessToken: opts.accessToken || null,
                hadContent: body.hadContent, raw: body.raw };
  const method = descriptor.proof.method;
  if (descriptor.format === 'cert#S256' && method !== 'mtls') {
    log.debug("Leaving verifyRequest(). Thumbprint-only key with a signature method.");
    return refusal('STS-GNAP-0280', 'a "cert#S256" key carries no public key and can only be ' +
                   'proved by mutual TLS (RFC 9635 section 7.1).');
  }
  const rotation = opts.rotation || null;
  if (rotation && !require('./gnap_keys').sameProof(rotation.proof, descriptor.proof)) {
    log.debug("Leaving verifyRequest(). Rotation changes the proofing method.");
    return refusal('STS-GNAP-0281', 'a key rotation must keep the proofing method and its ' +
                   'parameters (RFC 9635 section 6.1.1).', 'invalid_rotation');
  }
  let outcome;
  if (method === 'mtls') {
    if (rotation) {
      log.debug("Leaving verifyRequest(). MTLS cannot rotate.");
      return refusal('STS-GNAP-0282', 'key rotation is not defined for mutual TLS (RFC 9635 ' +
                     'section 7.3.2.1).', 'key_rotation_not_supported');
    }
    outcome = verifyMtls(req, descriptor);
  } else if (method === 'httpsig') {
    outcome = rotation ? verifyHttpsigRotation(req, descriptor, rotation, ctx)
                       : verifyHttpsig(req, descriptor, ctx);
  } else if (method === 'jwsd') {
    outcome = rotation ? verifyJwsdRotation(req, descriptor, rotation, ctx)
                       : verifyJwsd(req, descriptor, ctx);
  } else if (method === 'jws') {
    outcome = rotation ? verifyJwsRotation(req, body, descriptor, rotation, ctx)
                       : verifyJws(req, body, descriptor, ctx);
  } else {
    outcome = refusal('STS-GNAP-0283', 'the proofing method "' + method + '" is not implemented.');
  }
  if (!outcome.ok && rotation) {
    outcome.gnapError = outcome.gnapError === 'key_rotation_not_supported'
      ? outcome.gnapError : 'invalid_rotation';
  }
  log.debug("Leaving verifyRequest(). ok=" + outcome.ok);
  return Object.assign(outcome, { method: method });
}

function verifyJwsd(req, descriptor, ctx) {
  const header = req.headers['detached-jws'];
  if (!header) {
    return refusal('STS-GNAP-0284', 'the key is proved by a detached JWS and the request has no ' +
                   'Detached-JWS header (RFC 9635 section 7.3.3).');
  }
  return checkJwsLayer(header, descriptor, ctx, ['gnap-binding-jwsd'],
                       detachedPayloadCheck(ctx.raw, ctx.hadContent));
}

function verifyJws(req, body, descriptor, ctx) {
  if (!ctx.hadContent) {
    // Section 7.3.4: with no content the attached method signs an empty
    // payload and sends it in Detached-JWS — the section names no typ for that
    // case, so either binding type is accepted.
    const header = req.headers['detached-jws'];
    if (!header) {
      return refusal('STS-GNAP-0284', 'a request with no content proved by "jws" carries its ' +
                     'signature in the Detached-JWS header (RFC 9635 section 7.3.4).');
    }
    return checkJwsLayer(header, descriptor, ctx, ['gnap-binding-jws', 'gnap-binding-jwsd'],
                         detachedPayloadCheck(ctx.raw, false));
  }
  if (!body.jose) {
    return refusal('STS-GNAP-0285', 'the key is proved by an attached JWS and the request ' +
                   'content is not one (RFC 9635 section 7.3.4).');
  }
  return checkJwsLayer(body.jose, descriptor, ctx, ['gnap-binding-jws'], function (middle) {
    return { ok: true, candidates: [middle] };
  });
}

// Section 7.3.1.1: the old key signs normally (tag gnap), the new key signs a
// second time (tag gnap-rotate) covering the first signature and its input.
function verifyHttpsigRotation(req, oldKey, newKey, ctx) {
  log.debug("Entering verifyHttpsigRotation().");
  const first = verifyHttpsig(req, oldKey, ctx);
  if (!first.ok) {
    log.debug("Leaving verifyHttpsigRotation(). Old key refused.");
    return first;
  }
  const oldLabels = first.verified.map(function (one) {
    return one.label;
  });
  const second = verifyHttpsig(req, newKey, Object.assign({}, ctx, { tag: 'gnap-rotate' }));
  if (!second.ok) {
    log.debug("Leaving verifyHttpsigRotation(). New key refused.");
    return second;
  }
  const covers = second.verified.some(function (one) {
    return oldLabels.some(function (label) {
      return componentNamed(one.components, 'signature', label) &&
        componentNamed(one.components, 'signature-input', label);
    });
  });
  if (!covers) {
    log.debug("Leaving verifyHttpsigRotation(). New signature does not cover the old one.");
    return refusal('STS-GNAP-0286', 'the new key\'s signature must cover the old key\'s ' +
                   '"signature" and "signature-input" (RFC 9635 section 7.3.1.1).');
  }
  log.debug("Leaving verifyHttpsigRotation().");
  return { ok: true };
}

// Section 7.3.3.1: the new key signs a JWS whose payload is the old key's JWS
// (typ gnap-binding-rotation-jwsd), which signs the content digest.
function verifyJwsdRotation(req, oldKey, newKey, ctx) {
  log.debug("Entering verifyJwsdRotation().");
  const outer = req.headers['detached-jws'];
  if (!outer) {
    log.debug("Leaving verifyJwsdRotation(). No header.");
    return refusal('STS-GNAP-0284', 'a detached-JWS key rotation carries its proof in the ' +
                   'Detached-JWS header (RFC 9635 section 7.3.3.1).');
  }
  let inner = null;
  const checkedOuter = checkJwsLayer(outer, newKey, ctx, ['gnap-binding-jwsd'], function (middle) {
    inner = Buffer.from(middle, 'base64url').toString('ascii');
    return { ok: true, candidates: [middle] };
  });
  if (!checkedOuter.ok) {
    log.debug("Leaving verifyJwsdRotation(). Outer layer refused.");
    return checkedOuter;
  }
  const checkedInner = checkJwsLayer(inner, oldKey, ctx, ['gnap-binding-rotation-jwsd'],
                                     detachedPayloadCheck(ctx.raw, ctx.hadContent));
  log.debug("Leaving verifyJwsdRotation(). inner ok=" + checkedInner.ok);
  return checkedInner.ok ? { ok: true } : checkedInner;
}

// Section 7.3.4.1: the same nesting, attached.
function verifyJwsRotation(req, body, oldKey, newKey, ctx) {
  log.debug("Entering verifyJwsRotation().");
  if (!body.jose) {
    log.debug("Leaving verifyJwsRotation(). Content is not a JWS.");
    return refusal('STS-GNAP-0285', 'an attached-JWS key rotation sends a JWS as the content ' +
                   '(RFC 9635 section 7.3.4.1).');
  }
  let inner = null;
  const checkedOuter = checkJwsLayer(body.jose, newKey, ctx, ['gnap-binding-jws'], function (middle) {
    inner = Buffer.from(middle, 'base64url').toString('utf8');
    return { ok: true, candidates: [middle] };
  });
  if (!checkedOuter.ok) {
    log.debug("Leaving verifyJwsRotation(). Outer layer refused.");
    return checkedOuter;
  }
  if (inner && inner.charAt(0) === '"') {
    // A payload that is the JSON STRING of the inner JWS rather than its bare
    // characters — both spellings of "the value of the JWS object is taken as
    // the payload" exist, and they carry the same signature.
    try {
      inner = JSON.parse(inner);
    } catch (e) {
      // Left as it was; the inner check below refuses it with a sentence.
      log.debug("verifyJwsRotation(): inner payload is not a JSON string: " + e.message);
    }
  }
  const checkedInner = checkJwsLayer(inner, oldKey, ctx, ['gnap-binding-rotation-jws'], function (middle) {
    return { ok: true, candidates: [middle] };
  });
  log.debug("Leaving verifyJwsRotation(). inner ok=" + checkedInner.ok);
  return checkedInner.ok ? { ok: true } : checkedInner;
}

module.exports = {
  readBody: readBody,
  verifyRequest: verifyRequest,
  presentedToken: presentedToken,
  targetUriOf: targetUriOf,
  athOf: athOf,
  verifyJwsBytes: verifyJwsBytes
};
