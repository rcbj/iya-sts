'use strict';
//
// File: gnap_keys.js
//
// ---------------------------------------------------------------------------
// WHAT A GNAP KEY IS, IN EVERY SHAPE THE PROTOCOL LETS ONE ARRIVE IN.
//
// RFC 9635 section 7.1 has a key arrive BY VALUE — an object naming a proofing
// method and carrying the public key in exactly one of three formats (`jwk`,
// `cert`, `cert#S256`) — or BY REFERENCE, as an opaque string the AS resolves
// (section 7.1.1). The same shape appears in four places: the client's key in a
// grant request, the key an access token is bound to, the new key of a key
// rotation (section 6.1.1) and a resource server's key (RFC 9767 section 3.2).
// So the reading of it is ONE module, route-free, and everything that holds a
// key holds the DESCRIPTOR this module builds rather than the JSON it came
// from.
//
// A descriptor is `{ proof, format, identity, jwk, certificate, thumbprint,
// publicKey, alg, reference, secret }`, and two of those members carry the
// argument of this file:
//
//   * **`identity` is how "the same key" is decided, and it is a THUMBPRINT
//     rather than the JSON.** Section 2.3 says the AS MUST treat two requests
//     carrying the same public key by value as the same client instance. A JWK
//     with its members in a different order, with or without `use`, or with an
//     `x5c` beside it is the same key, and comparing JSON would make it a
//     different client. RFC 7638 for a JWK, RFC 8705's `x5t#S256` for a
//     certificate — the SAME digest `oauth-oidc/mtls.js` binds tokens with —
//     and the reference string itself for a reference.
//   * **`publicKey` is never persisted.** A node KeyObject is not JSON, and the
//     stores this subsystem writes are JSON rows (persistence/CLAUDE.md). What
//     is stored is the key object the client sent, and `describe()` rebuilds
//     the descriptor from it on every read — which also means a descriptor can
//     never be stale against the row it was built from.
//
// ---------------------------------------------------------------------------
// THE REFUSALS HERE ARE THE SPECIFICATION'S, NOT A MODE'S.
//
// A JWK with no `alg` or `kid`, an `alg` of `none`, a private member, a
// symmetric key sent by value, or a key in two formats at once is not a
// permissive-versus-strict question: section 7.1 says MUST for each, and a key
// that fails one of them cannot be proved in any mode, because the proofing
// methods READ `alg` and `kid` (section 7.3.1: the signature's keyid MUST be
// the JWK's kid, and the algorithm MUST be the JWK's alg). So these are
// refusals in development too — the same argument `common/validation.js` makes
// for shape. What IS mode-gated is what happens to a WELL-FORMED key the AS has
// never seen, and that decision is `gnap.js`'s, not this file's.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const { log } = require('../common/helpers');
const stsCrypto = require('../common/crypto');
const errorCodes = require('../common/error_codes');

// RFC 9635 section 7.3 / 10.16. The ORDER is the order discovery publishes.
const PROOF_METHODS = ['httpsig', 'mtls', 'jwsd', 'jws'];

// Section 7.1 / 10.17. Exactly one of these may be present on a key by value.
const KEY_FORMATS = ['jwk', 'cert', 'cert#S256'];

// Members that make a JWK a PRIVATE or SYMMETRIC key. Section 7.1: "A key
// presented by value MUST be a public key", and 7.1.2: symmetric keys MUST NOT
// be passed by value. `k` is the oct key's only member, so an oct JWK is
// refused by this list as well as by its kty.
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'];

// ---------------------------------------------------------------------------
// THE HTTP-SIGNATURE ALGORITHM A KEY MEANS, WHEN THE PROOF IS THE STRING FORM.
//
// Section 7.3.1: in string form "the signing algorithm MUST be derived from the
// key material (such as using the JWS algorithm in a JWK formatted key)". For a
// JWK that is its `alg`, read by `gnap_httpsig.js` through RFC 9421 section
// 3.3.7's JWS mapping. A CERTIFICATE carries no `alg`, so the choice below is
// this service's, and it is the least surprising one for each key type: the
// PKCS #1 v1.5 / ECDSA / EdDSA algorithm a JOSE library would pick for that
// key. A client that wants anything else uses the object form, which names
// `alg` explicitly and wins.
// ---------------------------------------------------------------------------
function jwsAlgForKeyObject(keyObject) {
  log.debug("Entering jwsAlgForKeyObject().");
  const type = keyObject.asymmetricKeyType;
  if (type === 'rsa' || type === 'rsa-pss') {
    log.debug("Leaving jwsAlgForKeyObject().");
    return 'RS256';
  }
  if (type === 'ec') {
    const curve = (keyObject.asymmetricKeyDetails || {}).namedCurve;
    if (curve === 'secp384r1') {
      log.debug("Leaving jwsAlgForKeyObject().");
      return 'ES384';
    }
    if (curve === 'secp521r1') {
      log.debug("Leaving jwsAlgForKeyObject().");
      return 'ES512';
    }
    log.debug("Leaving jwsAlgForKeyObject().");
    return 'ES256';
  }
  if (type === 'ed25519') {
    log.debug("Leaving jwsAlgForKeyObject().");
    return 'EdDSA';
  }
  log.debug("Leaving jwsAlgForKeyObject().");
  return null;
}

// A refusal in the one shape every GNAP library returns. The code is a Symbol
// mark as well as a member so that `/admin-api` JSON of a result never leaks
// it (common/CLAUDE.md), while callers that forward a refusal read it back.
function refusal(code, why, gnapError) {
  log.debug("Entering refusal().");
  const out = { ok: false, errorCode: code, why: why,
                gnapError: gnapError || 'invalid_request' };
  log.debug("Leaving refusal().");
  return errorCodes.mark(out, code);
}

// ---------------------------------------------------------------------------
// THE PROOFING METHOD, in either of its two shapes (section 7.3).
//
// A string is the method name. An object MUST carry `method`, and only
// `httpsig` defines object parameters (`alg`, `content-digest-alg`, both
// REQUIRED in object form); an object for any other method is a key this
// service cannot interpret, and section 7.3 gives it no meaning to guess.
// ---------------------------------------------------------------------------
function normaliseProof(proof) {
  log.debug("Entering normaliseProof().");
  if (typeof proof === 'string') {
    if (PROOF_METHODS.indexOf(proof) < 0) {
      log.debug("Leaving normaliseProof(). Unknown method.");
      return refusal('STS-GNAP-0001',
                     'the key names the proofing method "' + proof +
                     '", and this authorization server implements ' +
                     PROOF_METHODS.join(', ') + '.', 'invalid_client');
    }
    log.debug("Leaving normaliseProof(). String form.");
    return { ok: true, method: proof, params: {} };
  }
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
    log.debug("Leaving normaliseProof(). Not a string or an object.");
    return refusal('STS-GNAP-0002', 'a key\'s "proof" must be a method name ' +
                   'or an object with a "method" member (RFC 9635 section ' +
                   '7.3).');
  }
  if (typeof proof.method !== 'string' ||
      PROOF_METHODS.indexOf(proof.method) < 0) {
    log.debug("Leaving normaliseProof(). Object with no known method.");
    return refusal('STS-GNAP-0001', 'the key\'s proof object names no method ' +
                   'this authorization server implements ' +
                   '(' + PROOF_METHODS.join(', ') + ').',
                   'invalid_client');
  }
  if (proof.method !== 'httpsig') {
    log.debug("Leaving normaliseProof(). Object form for a string-only " +
              "method.");
    return refusal('STS-GNAP-0003', 'the "' + proof.method + '" proofing ' +
                   'method is defined in string form only (RFC 9635 section ' +
                   '10.16).');
  }
  if (typeof proof.alg !== 'string' || !proof.alg ||
      typeof proof['content-digest-alg'] !== 'string' ||
      !proof['content-digest-alg']) {
    log.debug("Leaving normaliseProof(). httpsig object missing alg or " +
              "content-digest-alg.");
    return refusal('STS-GNAP-0004', 'an httpsig proof in object form must ' +
                   'carry both "alg" and "content-digest-alg" (RFC 9635 ' +
                   'section 7.3.1).');
  }
  log.debug("Leaving normaliseProof(). httpsig object form.");
  return { ok: true, method: 'httpsig',
           params: { alg: proof.alg,
                     contentDigestAlg: proof['content-digest-alg'] } };
}

// A certificate from a `cert` member: PEM, with or without its header and
// footer, internal whitespace allowed (section 7.1 citing RFC 7468).
function certificateFrom(value) {
  log.debug("Entering certificateFrom().");
  const text = String(value || '').replace(/-----(BEGIN|END) CERTIFICATE-----/g,
                                           '')
    .replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/=]+$/.test(text)) {
    log.debug("Leaving certificateFrom(). Not base64.");
    return null;
  }
  try {
    const certificate = new nodeCrypto.X509Certificate(
        Buffer.from(text, 'base64'));
    log.debug("Leaving certificateFrom().");
    return certificate;
  } catch (e) {
    // Not a certificate. The caller refuses with a sentence naming the member;
    // the parser's own message is logged here because it is the useful detail.
    log.debug("Leaving certificateFrom(). Not a certificate: " + e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// A KEY BY VALUE OR BY REFERENCE, INTO A DESCRIPTOR.
//
// `options.resolveReference(reference)` is how a reference becomes key
// material; this file does not know where references live (application
// entries, dynamic instance records) and must not, because that would make a
// route-free library require the directory. It answers `null` for "unknown",
// which the caller turns into `invalid_client` — section 2.3.1 and 7.1.1.
// ---------------------------------------------------------------------------
function describe(key, options) {
  log.debug("Entering describe().");
  const opts = options || {};
  if (typeof key === 'string') {
    if (!key) {
      log.debug("Leaving describe(). Empty reference.");
      return refusal('STS-GNAP-0005', 'a key reference must be a non-empty ' +
                                      'string.');
    }
    const resolved = typeof opts.resolveReference === 'function' ?
                     opts.resolveReference(key) : null;
    if (!resolved) {
      log.debug("Leaving describe(). Unknown key reference.");
      return refusal('STS-GNAP-0006', 'the key reference is not one this ' +
                     'authorization server knows (RFC 9635 section ' +
                     '7.1.1).', 'invalid_client');
    }
    // A resolved reference is either a registered public key by value (which is
    // described like any other) or a SHARED SECRET — the one case section 7.1.1
    // allows a symmetric key, precisely because it never crosses the wire.
    if (resolved.secret) {
      const proof = normaliseProof(resolved.proof || 'httpsig');
      if (!proof.ok) {
        log.debug("Leaving describe(). The registered reference names a bad " +
                  "proof.");
        return proof;
      }
      log.debug("Leaving describe(). Symmetric key reference.");
      return { ok: true, proof: proof, format: 'reference', reference: key,
               identity: 'ref:' + key, secret: Buffer.from(resolved.secret),
               alg: resolved.alg || 'HS256', publicKey: null, jwk: null,
               certificate: null, thumbprint: null, value: key };
    }
    const inner = describe(resolved.key, {});
    if (!inner.ok) {
      log.debug("Leaving describe(). The registered reference holds a bad " +
                "key.");
      return inner;
    }
    inner.reference = key;
    inner.value = key;
    log.debug("Leaving describe(). Public key by reference.");
    return inner;
  }
  if (!key || typeof key !== 'object' || Array.isArray(key)) {
    log.debug("Leaving describe(). Neither a string nor an object.");
    return refusal('STS-GNAP-0005', 'a key must be an object (RFC 9635 ' +
                   'section 7.1) or a reference string (section 7.1.1).');
  }
  const proof = normaliseProof(key.proof);
  if (!proof.ok) {
    log.debug("Leaving describe(). Bad proof.");
    return proof;
  }
  const present = KEY_FORMATS.filter(function (format) {
    return key[format] !== undefined;
  });
  if (present.length !== 1) {
    // Section 11.35: presenting one key in several formats lets a verifier and
    // a signer disagree about which one is the key. Exactly one, therefore —
    // and zero is simply no key.
    log.debug("Leaving describe(). " + present.length + " key formats.");
    return refusal('STS-GNAP-0007', 'a key by value must be presented in ' +
                   'exactly one format (jwk, cert or cert#S256); this one ' +
                   'has ' + present.length +
                   ' (RFC 9635 sections 7.1 and 11.35).', 'invalid_client');
  }
  const format = present[0];
  if (format === 'jwk') {
    log.debug("Leaving describe().");
    return describeJwk(key, proof);
  }
  if (format === 'cert') {
    const certificate = certificateFrom(key.cert);
    if (!certificate) {
      log.debug("Leaving describe(). cert does not parse.");
      return refusal('STS-GNAP-0008', 'the key\'s "cert" member is not a PEM ' +
                     'X.509 certificate.', 'invalid_client');
    }
    const publicKey = certificate.publicKey;
    log.debug("Leaving describe(). Certificate.");
    return { ok: true, proof: proof, format: 'cert', jwk: null,
             certificate: certificate,
             thumbprint: stsCrypto.certificateThumbprint(certificate),
             identity: 'x5t:' + stsCrypto.certificateThumbprint(certificate),
             publicKey: publicKey, alg: jwsAlgForKeyObject(publicKey),
             reference: null, secret: null, value: key };
  }
  // `cert#S256`: a thumbprint and nothing else. Section 7.1 says so plainly —
  // "this format does not include the full public key" — which means it can
  // only ever be proved by MTLS, where the certificate arrives in the TLS
  // handshake. A signature method with no public key has nothing to verify
  // against, and that refusal is the proof module's, with the method in hand.
  const thumbprint = String(key['cert#S256'] || '');
  if (!/^[A-Za-z0-9_-]{43}$/.test(thumbprint)) {
    log.debug("Leaving describe(). cert#S256 is not a SHA-256 base64url " +
              "value.");
    return refusal('STS-GNAP-0009', 'the key\'s "cert#S256" member is not a ' +
                   'base64url SHA-256 thumbprint (RFC ' +
                   '8705).', 'invalid_client');
  }
  log.debug("Leaving describe(). Certificate thumbprint.");
  return { ok: true, proof: proof, format: 'cert#S256', jwk: null,
           certificate: null,
           thumbprint: thumbprint, identity: 'x5t:' +
                                             thumbprint, publicKey: null,
           alg: null, reference: null, secret: null, value: key };
}

function describeJwk(key, proof) {
  log.debug("Entering describeJwk().");
  const jwk = key.jwk;
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
    log.debug("Leaving describeJwk(). Not an object.");
    return refusal('STS-GNAP-0010', 'the key\'s "jwk" member must be a JSON ' +
                   'Web Key object.', 'invalid_client');
  }
  if (jwk.kty === 'oct' ||
      PRIVATE_MEMBERS.some(function (m) { return jwk[m] !== undefined; })) {
    log.debug("Leaving describeJwk(). Private or symmetric member present.");
    return refusal('STS-GNAP-0011', 'a key by value must be a PUBLIC key; ' +
                   'this JWK carries private or symmetric key material (RFC ' +
                   '9635 sections 7.1 and 7.1.2).',
                   'invalid_client');
  }
  if (typeof jwk.alg !== 'string' || !jwk.alg || jwk.alg === 'none' ||
      typeof jwk.kid !== 'string' || !jwk.kid) {
    log.debug("Leaving describeJwk(). alg or kid missing, or alg none.");
    return refusal('STS-GNAP-0012', 'a JWK presented in GNAP must carry ' +
                   '"alg" (not "none") and "kid" (RFC 9635 section ' +
                   '7.1).', 'invalid_client');
  }
  const spec = stsCrypto.JWS_ALGS[jwk.alg];
  if (!spec || spec.family === 'hmac' || (spec.kty && spec.kty !== jwk.kty)) {
    log.debug("Leaving describeJwk(). alg does not fit the key type.");
    return refusal('STS-GNAP-0013', 'the JWK\'s alg "' + jwk.alg + '" is not ' +
                   'an asymmetric JWS algorithm for ' +
                   'a ' + jwk.kty + ' key.', 'invalid_client');
  }
  let publicKey;
  let thumbprint;
  try {
    publicKey = nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' });
    thumbprint = stsCrypto.jwkThumbprint(jwk);
  } catch (e) {
    log.debug("Leaving describeJwk(). The key does not import: " + e.message);
    return refusal('STS-GNAP-0014',
                   'the JWK does not import as a public key: ' +
                   e.message, 'invalid_client');
  }
  log.debug("Leaving describeJwk().");
  return { ok: true, proof: proof, format: 'jwk', jwk: jwk, certificate: null,
           thumbprint: thumbprint, identity: 'jkt:' + thumbprint,
           publicKey: publicKey,
           alg: jwk.alg, reference: null, secret: null, value: key };
}

// The confirmation an access token carries for a descriptor (RFC 9767 section
// 2.1.4): `jkt` for a JWK, `x5t#S256` for a certificate, `kid` for a reference.
function confirmationOf(descriptor) {
  log.debug("Entering confirmationOf().");
  if (!descriptor) {
    log.debug("Leaving confirmationOf().");
    return null;
  }
  if (descriptor.format === 'jwk') {
    log.debug("Leaving confirmationOf().");
    return { jkt: descriptor.thumbprint };
  }
  if (descriptor.format === 'cert' || descriptor.format === 'cert#S256') {
    log.debug("Leaving confirmationOf().");
    return { 'x5t#S256': descriptor.thumbprint };
  }
  log.debug("Leaving confirmationOf().");
  return { kid: descriptor.reference };
}

// Whether a presented descriptor is the key a confirmation names. Used by the
// demonstration RS and by every format's verify(), which is handed this
// shape as `presentedKey`.
function presentedFor(descriptor) {
  log.debug("Entering presentedFor().");
  log.debug("Leaving presentedFor().");
  return confirmationOf(descriptor);
}

// Section 6.1.1: "The proofing method and parameters for the new key MUST be
// the same as those established for the previous key."
function sameProof(a, b) {
  log.debug("Entering sameProof().");
  if (!a || !b || a.method !== b.method) {
    log.debug("Leaving sameProof().");
    return false;
  }
  log.debug("Leaving sameProof().");
  return JSON.stringify(a.params || {}) === JSON.stringify(b.params || {});
}

module.exports = {
  PROOF_METHODS: PROOF_METHODS,
  KEY_FORMATS: KEY_FORMATS,
  normaliseProof: normaliseProof,
  describe: describe,
  confirmationOf: confirmationOf,
  presentedFor: presentedFor,
  sameProof: sameProof,
  jwsAlgForKeyObject: jwsAlgForKeyObject,
  certificateFrom: certificateFrom
};
