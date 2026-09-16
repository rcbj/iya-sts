'use strict';
//
// File: gnap_keys.ts
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
// never seen, and that decision is `gnap_grants.ts`'s, not this file's.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `GnapKeys` takes node's crypto, the service's crypto module, the
// error-code table and the logger through its constructor. The module still
// exports every old name from a TRANSITIONAL instance for the unconverted GNAP
// modules that require it; the two tables are static members.
// ---------------------------------------------------------------------------

import nodeCrypto = require('crypto');
import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import errorCodes = require('../common/error_codes');

// A result in the one shape every GNAP library returns: `ok`, and either the
// refusal's members or the descriptor's (see the header).
interface KeyResult {
  ok: boolean;
  [member: string]: any;
}

// How a caller resolves a key reference; `null` for "unknown".
interface DescribeOptions {
  resolveReference?(reference: string): any;
}

interface GnapKeysDeps {
  nodeCrypto: typeof nodeCrypto;
  stsCrypto: {
    JWS_ALGS: Record<string, any>;
    certificateThumbprint(certificate: any): string;
    jwkThumbprint(jwk: any): string;
  };
  errorCodes: { mark<T>(res: T, code: string): T };
  log: { debug(message: string): void };
}

// RFC 9635 section 7.3 / 10.16. The ORDER is the order discovery publishes.
const PROOF_METHODS = ['httpsig', 'mtls', 'jwsd', 'jws'];

// Section 7.1 / 10.17. Exactly one of these may be present on a key by value.
const KEY_FORMATS = ['jwk', 'cert', 'cert#S256'];

// Members that make a JWK a PRIVATE or SYMMETRIC key. Section 7.1: "A key
// presented by value MUST be a public key", and 7.1.2: symmetric keys MUST NOT
// be passed by value. `k` is the oct key's only member, so an oct JWK is
// refused by this list as well as by its kty.
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'];

class GnapKeys {
  static readonly PROOF_METHODS = PROOF_METHODS;
  static readonly KEY_FORMATS = KEY_FORMATS;

  constructor(private readonly deps: GnapKeysDeps) {
    deps.log.debug("Entering GnapKeys.constructor().");
    deps.log.debug("Leaving GnapKeys.constructor().");
  }

  // -------------------------------------------------------------------------
  // THE HTTP-SIGNATURE ALGORITHM A KEY MEANS, WHEN THE PROOF IS THE STRING
  // FORM.
  //
  // Section 7.3.1: in string form "the signing algorithm MUST be derived from
  // the key material (such as using the JWS algorithm in a JWK formatted
  // key)". For a JWK that is its `alg`, read by `gnap_httpsig.ts` through RFC
  // 9421 section 3.3.7's JWS mapping. A CERTIFICATE carries no `alg`, so the
  // choice below is this service's, and it is the least surprising one for
  // each key type: the PKCS #1 v1.5 / ECDSA / EdDSA algorithm a JOSE library
  // would pick for that key. A client that wants anything else uses the
  // object form, which names `alg` explicitly and wins.
  // -------------------------------------------------------------------------
  jwsAlgForKeyObject(keyObject: any): string | null {
    const { log } = this.deps;
    log.debug("Entering GnapKeys.jwsAlgForKeyObject().");
    const type = keyObject.asymmetricKeyType;
    if (type === 'rsa' || type === 'rsa-pss') {
      log.debug("Leaving GnapKeys.jwsAlgForKeyObject().");
      return 'RS256';
    }
    if (type === 'ec') {
      const curve = (keyObject.asymmetricKeyDetails || {}).namedCurve;
      if (curve === 'secp384r1') {
        log.debug("Leaving GnapKeys.jwsAlgForKeyObject().");
        return 'ES384';
      }
      if (curve === 'secp521r1') {
        log.debug("Leaving GnapKeys.jwsAlgForKeyObject().");
        return 'ES512';
      }
      log.debug("Leaving GnapKeys.jwsAlgForKeyObject().");
      return 'ES256';
    }
    if (type === 'ed25519') {
      log.debug("Leaving GnapKeys.jwsAlgForKeyObject().");
      return 'EdDSA';
    }
    log.debug("Leaving GnapKeys.jwsAlgForKeyObject().");
    return null;
  }

  // A refusal in the one shape every GNAP library returns. The code is a
  // Symbol mark as well as a member so that `/admin-api` JSON of a result
  // never leaks it (common/CLAUDE.md), while callers that forward a refusal
  // read it back.
  private refusal(code: string, why: string, gnapError?: string): KeyResult {
    const { log, errorCodes } = this.deps;
    log.debug("Entering GnapKeys.refusal().");
    const out = { ok: false, errorCode: code, why: why,
                  gnapError: gnapError || 'invalid_request' };
    log.debug("Leaving GnapKeys.refusal().");
    return errorCodes.mark(out, code);
  }

  // -------------------------------------------------------------------------
  // THE PROOFING METHOD, in either of its two shapes (section 7.3).
  //
  // A string is the method name. An object MUST carry `method`, and only
  // `httpsig` defines object parameters (`alg`, `content-digest-alg`, both
  // REQUIRED in object form); an object for any other method is a key this
  // service cannot interpret, and section 7.3 gives it no meaning to guess.
  // -------------------------------------------------------------------------
  normaliseProof(proof: any): KeyResult {
    const { log } = this.deps;
    log.debug("Entering GnapKeys.normaliseProof().");
    if (typeof proof === 'string') {
      if (PROOF_METHODS.indexOf(proof) < 0) {
        log.debug("Leaving GnapKeys.normaliseProof(). Unknown method.");
        return this.refusal('STS-GNAP-0001',
                            'the key names the proofing method "' + proof +
                            '", and this authorization server implements ' +
                            PROOF_METHODS.join(', ') + '.', 'invalid_client');
      }
      log.debug("Leaving GnapKeys.normaliseProof(). String form.");
      return { ok: true, method: proof, params: {} };
    }
    if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
      log.debug("Leaving GnapKeys.normaliseProof(). Not a string or an " +
                "object.");
      return this.refusal('STS-GNAP-0002', 'a key\'s "proof" must be a ' +
                          'method name or an object with a "method" member ' +
                          '(RFC 9635 section 7.3).');
    }
    if (typeof proof.method !== 'string' ||
        PROOF_METHODS.indexOf(proof.method) < 0) {
      log.debug("Leaving GnapKeys.normaliseProof(). Object with no known " +
                "method.");
      return this.refusal('STS-GNAP-0001', 'the key\'s proof object names ' +
                          'no method this authorization server implements ' +
                          '(' + PROOF_METHODS.join(', ') + ').',
                          'invalid_client');
    }
    if (proof.method !== 'httpsig') {
      log.debug("Leaving GnapKeys.normaliseProof(). Object form for a " +
                "string-only method.");
      return this.refusal('STS-GNAP-0003', 'the "' + proof.method + '" ' +
                          'proofing method is defined in string form only ' +
                          '(RFC 9635 section 10.16).');
    }
    if (typeof proof.alg !== 'string' || !proof.alg ||
        typeof proof['content-digest-alg'] !== 'string' ||
        !proof['content-digest-alg']) {
      log.debug("Leaving GnapKeys.normaliseProof(). httpsig object missing " +
                "alg or content-digest-alg.");
      return this.refusal('STS-GNAP-0004', 'an httpsig proof in object form ' +
                          'must carry both "alg" and "content-digest-alg" ' +
                          '(RFC 9635 section 7.3.1).');
    }
    log.debug("Leaving GnapKeys.normaliseProof(). httpsig object form.");
    return { ok: true, method: 'httpsig',
             params: { alg: proof.alg,
                       contentDigestAlg: proof['content-digest-alg'] } };
  }

  // A certificate from a `cert` member: PEM, with or without its header and
  // footer, internal whitespace allowed (section 7.1 citing RFC 7468).
  certificateFrom(value: unknown): nodeCrypto.X509Certificate | null {
    const { log, nodeCrypto } = this.deps;
    log.debug("Entering GnapKeys.certificateFrom().");
    const text = String(value || '')
      .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    if (!/^[A-Za-z0-9+/=]+$/.test(text)) {
      log.debug("Leaving GnapKeys.certificateFrom(). Not base64.");
      return null;
    }
    try {
      const certificate = new nodeCrypto.X509Certificate(
          Buffer.from(text, 'base64'));
      log.debug("Leaving GnapKeys.certificateFrom().");
      return certificate;
    } catch (e) {
      // Not a certificate. The caller refuses with a sentence naming the
      // member; the parser's own message is logged here because it is the
      // useful detail.
      log.debug("Caught in GnapKeys.certificateFrom(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapKeys.certificateFrom(). Not a certificate: " +
                e.message);
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // A KEY BY VALUE OR BY REFERENCE, INTO A DESCRIPTOR.
  //
  // `options.resolveReference(reference)` is how a reference becomes key
  // material; this file does not know where references live (application
  // entries, dynamic instance records) and must not, because that would make
  // a route-free library require the directory. It answers `null` for
  // "unknown", which the caller turns into `invalid_client` — section 2.3.1
  // and 7.1.1.
  // -------------------------------------------------------------------------
  describe(key: any, options?: DescribeOptions): KeyResult {
    const { log, stsCrypto } = this.deps;
    log.debug("Entering GnapKeys.describe().");
    const opts = options || {};
    if (typeof key === 'string') {
      if (!key) {
        log.debug("Leaving GnapKeys.describe(). Empty reference.");
        return this.refusal('STS-GNAP-0005', 'a key reference must be a ' +
                            'non-empty string.');
      }
      const resolved = typeof opts.resolveReference === 'function' ?
                       opts.resolveReference(key) : null;
      if (!resolved) {
        log.debug("Leaving GnapKeys.describe(). Unknown key reference.");
        return this.refusal('STS-GNAP-0006', 'the key reference is not one ' +
                            'this authorization server knows (RFC 9635 ' +
                            'section 7.1.1).', 'invalid_client');
      }
      // A resolved reference is either a registered public key by value
      // (which is described like any other) or a SHARED SECRET — the one case
      // section 7.1.1 allows a symmetric key, precisely because it never
      // crosses the wire.
      if (resolved.secret) {
        const proof = this.normaliseProof(resolved.proof || 'httpsig');
        if (!proof.ok) {
          log.debug("Leaving GnapKeys.describe(). The registered reference " +
                    "names a bad proof.");
          return proof;
        }
        log.debug("Leaving GnapKeys.describe(). Symmetric key reference.");
        return { ok: true, proof: proof, format: 'reference',
                 reference: key, identity: 'ref:' + key,
                 secret: Buffer.from(resolved.secret),
                 alg: resolved.alg || 'HS256', publicKey: null, jwk: null,
                 certificate: null, thumbprint: null, value: key };
      }
      const inner = this.describe(resolved.key, {});
      if (!inner.ok) {
        log.debug("Leaving GnapKeys.describe(). The registered reference " +
                  "holds a bad key.");
        return inner;
      }
      inner.reference = key;
      inner.value = key;
      log.debug("Leaving GnapKeys.describe(). Public key by reference.");
      return inner;
    }
    if (!key || typeof key !== 'object' || Array.isArray(key)) {
      log.debug("Leaving GnapKeys.describe(). Neither a string nor an " +
                "object.");
      return this.refusal('STS-GNAP-0005', 'a key must be an object (RFC ' +
                          '9635 section 7.1) or a reference string (section ' +
                          '7.1.1).');
    }
    const proof = this.normaliseProof(key.proof);
    if (!proof.ok) {
      log.debug("Leaving GnapKeys.describe(). Bad proof.");
      return proof;
    }
    const present = KEY_FORMATS.filter(function (format) {
      return key[format] !== undefined;
    });
    if (present.length !== 1) {
      // Section 11.35: presenting one key in several formats lets a verifier
      // and a signer disagree about which one is the key. Exactly one,
      // therefore — and zero is simply no key.
      log.debug("Leaving GnapKeys.describe(). " + present.length +
                " key formats.");
      return this.refusal('STS-GNAP-0007', 'a key by value must be ' +
                          'presented in exactly one format (jwk, cert or ' +
                          'cert#S256); this one has ' + present.length +
                          ' (RFC 9635 sections 7.1 and 11.35).',
                          'invalid_client');
    }
    const format = present[0];
    if (format === 'jwk') {
      log.debug("Leaving GnapKeys.describe().");
      return this.describeJwk(key, proof);
    }
    if (format === 'cert') {
      const certificate = this.certificateFrom(key.cert);
      if (!certificate) {
        log.debug("Leaving GnapKeys.describe(). cert does not parse.");
        return this.refusal('STS-GNAP-0008', 'the key\'s "cert" member is ' +
                            'not a PEM X.509 certificate.', 'invalid_client');
      }
      const publicKey = certificate.publicKey;
      log.debug("Leaving GnapKeys.describe(). Certificate.");
      return { ok: true, proof: proof, format: 'cert', jwk: null,
               certificate: certificate,
               thumbprint: stsCrypto.certificateThumbprint(certificate),
               identity: 'x5t:' +
                 stsCrypto.certificateThumbprint(certificate),
               publicKey: publicKey,
               alg: this.jwsAlgForKeyObject(publicKey),
               reference: null, secret: null, value: key };
    }
    // `cert#S256`: a thumbprint and nothing else. Section 7.1 says so plainly
    // — "this format does not include the full public key" — which means it
    // can only ever be proved by MTLS, where the certificate arrives in the
    // TLS handshake. A signature method with no public key has nothing to
    // verify against, and that refusal is the proof module's, with the method
    // in hand.
    const thumbprint = String(key['cert#S256'] || '');
    if (!/^[A-Za-z0-9_-]{43}$/.test(thumbprint)) {
      log.debug("Leaving GnapKeys.describe(). cert#S256 is not a SHA-256 " +
                "base64url value.");
      return this.refusal('STS-GNAP-0009', 'the key\'s "cert#S256" member ' +
                          'is not a base64url SHA-256 thumbprint (RFC ' +
                          '8705).', 'invalid_client');
    }
    log.debug("Leaving GnapKeys.describe(). Certificate thumbprint.");
    return { ok: true, proof: proof, format: 'cert#S256', jwk: null,
             certificate: null,
             thumbprint: thumbprint, identity: 'x5t:' + thumbprint,
             publicKey: null,
             alg: null, reference: null, secret: null, value: key };
  }

  private describeJwk(key: any, proof: KeyResult): KeyResult {
    const { log, nodeCrypto, stsCrypto } = this.deps;
    log.debug("Entering GnapKeys.describeJwk().");
    const jwk = key.jwk;
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
      log.debug("Leaving GnapKeys.describeJwk(). Not an object.");
      return this.refusal('STS-GNAP-0010', 'the key\'s "jwk" member must be ' +
                          'a JSON Web Key object.', 'invalid_client');
    }
    if (jwk.kty === 'oct' ||
        PRIVATE_MEMBERS.some(function (m) {
          return jwk[m] !== undefined;
        })) {
      log.debug("Leaving GnapKeys.describeJwk(). Private or symmetric " +
                "member present.");
      return this.refusal('STS-GNAP-0011', 'a key by value must be a PUBLIC ' +
                          'key; this JWK carries private or symmetric key ' +
                          'material (RFC 9635 sections 7.1 and 7.1.2).',
                          'invalid_client');
    }
    if (typeof jwk.alg !== 'string' || !jwk.alg || jwk.alg === 'none' ||
        typeof jwk.kid !== 'string' || !jwk.kid) {
      log.debug("Leaving GnapKeys.describeJwk(). alg or kid missing, or alg " +
                "none.");
      return this.refusal('STS-GNAP-0012', 'a JWK presented in GNAP must ' +
                          'carry "alg" (not "none") and "kid" (RFC 9635 ' +
                          'section 7.1).', 'invalid_client');
    }
    const spec = stsCrypto.JWS_ALGS[jwk.alg];
    if (!spec || spec.family === 'hmac' ||
        (spec.kty && spec.kty !== jwk.kty)) {
      log.debug("Leaving GnapKeys.describeJwk(). alg does not fit the key " +
                "type.");
      return this.refusal('STS-GNAP-0013', 'the JWK\'s alg "' + jwk.alg +
                          '" is not an asymmetric JWS algorithm for ' +
                          'a ' + jwk.kty + ' key.', 'invalid_client');
    }
    let publicKey: nodeCrypto.KeyObject;
    let thumbprint: string;
    try {
      publicKey = nodeCrypto.createPublicKey({ key: jwk, format: 'jwk' });
      thumbprint = stsCrypto.jwkThumbprint(jwk);
    } catch (e) {
      log.debug("Caught in GnapKeys.describeJwk(): " +
                ((e && e.message) || e));
      log.debug("Leaving GnapKeys.describeJwk(). The key does not import: " +
                e.message);
      return this.refusal('STS-GNAP-0014',
                          'the JWK does not import as a public key: ' +
                          e.message, 'invalid_client');
    }
    log.debug("Leaving GnapKeys.describeJwk().");
    return { ok: true, proof: proof, format: 'jwk', jwk: jwk,
             certificate: null,
             thumbprint: thumbprint, identity: 'jkt:' + thumbprint,
             publicKey: publicKey,
             alg: jwk.alg, reference: null, secret: null, value: key };
  }

  // The confirmation an access token carries for a descriptor (RFC 9767
  // section 2.1.4): `jkt` for a JWK, `x5t#S256` for a certificate, `kid` for
  // a reference.
  confirmationOf(descriptor: any): Record<string, any> | null {
    const { log } = this.deps;
    log.debug("Entering GnapKeys.confirmationOf().");
    if (!descriptor) {
      log.debug("Leaving GnapKeys.confirmationOf().");
      return null;
    }
    if (descriptor.format === 'jwk') {
      log.debug("Leaving GnapKeys.confirmationOf().");
      return { jkt: descriptor.thumbprint };
    }
    if (descriptor.format === 'cert' || descriptor.format === 'cert#S256') {
      log.debug("Leaving GnapKeys.confirmationOf().");
      return { 'x5t#S256': descriptor.thumbprint };
    }
    log.debug("Leaving GnapKeys.confirmationOf().");
    return { kid: descriptor.reference };
  }

  // Whether a presented descriptor is the key a confirmation names. Used by
  // the demonstration RS and by every format's verify(), which is handed this
  // shape as `presentedKey`.
  presentedFor(descriptor: any): Record<string, any> | null {
    const { log } = this.deps;
    log.debug("Entering GnapKeys.presentedFor().");
    log.debug("Leaving GnapKeys.presentedFor().");
    return this.confirmationOf(descriptor);
  }

  // Section 6.1.1: "The proofing method and parameters for the new key MUST
  // be the same as those established for the previous key."
  sameProof(a: any, b: any): boolean {
    const { log } = this.deps;
    log.debug("Entering GnapKeys.sameProof().");
    if (!a || !b || a.method !== b.method) {
      log.debug("Leaving GnapKeys.sameProof().");
      return false;
    }
    log.debug("Leaving GnapKeys.sameProof().");
    return JSON.stringify(a.params || {}) === JSON.stringify(b.params || {});
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, as the composition root will build one.
const keys = new GnapKeys({
  nodeCrypto: nodeCrypto,
  stsCrypto: stsCrypto,
  errorCodes: errorCodes,
  log: helpers.log
});

export = {
  GnapKeys: GnapKeys,
  PROOF_METHODS: GnapKeys.PROOF_METHODS,
  KEY_FORMATS: GnapKeys.KEY_FORMATS,
  normaliseProof: keys.normaliseProof.bind(keys) as GnapKeys['normaliseProof'],
  describe: keys.describe.bind(keys) as GnapKeys['describe'],
  confirmationOf: keys.confirmationOf.bind(keys) as GnapKeys['confirmationOf'],
  presentedFor: keys.presentedFor.bind(keys) as GnapKeys['presentedFor'],
  sameProof: keys.sameProof.bind(keys) as GnapKeys['sameProof'],
  jwsAlgForKeyObject:
    keys.jwsAlgForKeyObject.bind(keys) as GnapKeys['jwsAlgForKeyObject'],
  certificateFrom:
    keys.certificateFrom.bind(keys) as GnapKeys['certificateFrom']
};
