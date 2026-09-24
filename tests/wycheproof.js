'use strict';
//
// File: wycheproof.js
//
// ===========================================================================
// C2SP WYCHEPROOF AGAINST common/crypto.js (#202, 2026-09-24).
//
// Wycheproof is the standard corpus of known-attack test vectors: malleable
// and BER-encoded signatures, points off the curve, truncated tags, bad
// padding, edge-case integers. Every vector file at the pinned commit is
// CLASSIFIED here — applied through one or more of crypto.js's own doors, or
// not applicable with the reason — and a file nobody classified fails the
// run, so a corpus bump cannot silently add algorithms this file never looked
// at.
//
// **THROUGH crypto.js AND NEVER AROUND IT.** A door is a function the service
// calls: `jwsSignatureValid()` (what `verifyCompactJws()` checks, #202),
// `verifyXmlSignatureValue()`, `verifyRawSignature()`,
// `verifyCoseSignature()`, `verifyWithPublicKey()`, `openJweContent()` /
// `sealJweContent()`, `aesKeyWrap()` / `aesKeyUnwrap()`,
// `decryptJweCompact()`, `verifyCompactJws()` and `decryptElement()`. Where a
// door frames its input — an XML EncryptedData, a compact JWE — the vector is
// put INTO that frame, and the answer read back out of the door's own
// refusal codes. Node's crypto is used here only to BUILD inputs (a content
// ciphertext under a vector's key) and as an independent second opinion.
//
// **EXPECTATIONS.** `valid` must be accepted and `invalid` refused.
// `acceptable` is decided per flag in ACCEPTABLE below, with the reason, and
// an acceptable vector with no decision fails. Where a door implements a
// NARROWER profile than the primitive (JWE's 96-bit IV and 128-bit tag, the
// JWS MAC being the whole HMAC, RSA1_5 never decrypted) the expectation is
// the profile's, named in PROFILE and counted apart.
//
// The corpus is fetched when the tests image is built
// (tests/tools/fetch-vectors.sh) into tests/vectors/wycheproof/;
// STS_WYCHEPROOF_DIR overrides that. tests/CLAUDE.md, *The external test
// vectors*, is the provenance and the licence.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'wycheproof',
  level: process.env.LOG_LEVEL || 'info' });

const VECTORS = process.env.STS_WYCHEPROOF_DIR ||
  path.join(__dirname, 'vectors', 'wycheproof');
const DIR = path.join(VECTORS, 'testvectors_v1');

// ---------------------------------------------------------------------------
// THE ACCEPTABLE DECISIONS. Every `acceptable` result a door meets must be
// decided here, by one of its flags: 'reject', 'accept' or 'either'.
// ---------------------------------------------------------------------------
const ACCEPTABLE = {
  // RSASSA-PKCS1-v1_5 DigestInfo without the NULL parameters (RFC 8017
  // section 9.2 note 1 allows a verifier to accept it). OpenSSL ACCEPTS the
  // form for the SHA-2 family, which is a long-standing interoperability
  // choice and not a forgery: the encoding is still unique per hash and the
  // signature still covers it. Decided 'either' rather than forcing a
  // hand-written verifier over node's.
  MissingNull: { decision: 'either', why: 'RFC 8017 9.2 note 1: a verifier ' +
    'may accept the DigestInfo without NULL; OpenSSL does, and it is not ' +
    'malleability (one encoding per hash)' },
  // A DER INTEGER missing its leading zero is BER, and a verifier that takes
  // BER is malleable.
  MissingZero: { decision: 'reject', why: 'BER is not DER; accepting it is ' +
    'signature malleability' },
  // A compressed point: XML Signature 1.1 section 4.5.2.3.1 writes the
  // ECKeyValue PublicKey uncompressed, and `agreedKey()` refuses any other.
  CompressedPublic: { decision: 'reject', why: 'XMLDSig 1.1 ECKeyValue is ' +
    'the uncompressed point' },
  CompressedPoint: { decision: 'reject', why: 'as CompressedPublic' },
  // AES key wrap of 8 octets — RFC 3394 needs two semiblocks, and no key
  // this service wraps (a CEK) is shorter than sixteen.
  ShortKey: { decision: 'reject', why: 'RFC 3394 wraps n >= 2 semiblocks' },
  // An OAEP ciphertext that is a small integer: whether it decrypts depends
  // only on the padding check, which is what the other vectors hold.
  SmallIntegerCiphertext: { decision: 'either', why: 'the padding decides; ' +
    'no security property turns on it' }
};

// ---------------------------------------------------------------------------
// ERRATA IN THE CORPUS AT THE PINNED COMMIT: vectors whose own bytes
// contradict their result. Each is decided here, with what was checked.
// ---------------------------------------------------------------------------
const ERRATA = {
  'json_web_signature_test.json#367': { expect: 'accept', why: 'the token ' +
    'is byte-identical to tc357 (valid): its "invalid padding" was lost ' +
    'when the vector was serialized, so it cannot be refused without ' +
    'refusing tc357' },
  'json_web_signature_test.json#370': { expect: 'accept', why: 'as tc367 — ' +
    'byte-identical to tc357' }
};

// ---------------------------------------------------------------------------
// THE FILES NO DOOR APPLIES TO, and why. Matched in order.
// ---------------------------------------------------------------------------
const NOT_APPLICABLE = [
  [/^(aegis|ascon|morus|xchacha20|chacha20|aead_aes_siv|aes_siv|aes_gcm_siv|aes_eax|aes_ccm|aes_gmac|aes_xts|aes_cmac|aes_kwp|c2sp_chunked)/,
   'crypto.js offers no such cipher or mode: its AEADs are AES-GCM and ' +
   'RFC 7518 AES-CBC-HMAC, its key wraps RFC 3394 AES-KW'],
  [/^(aria|camellia|seed|sm4)_/, 'crypto.js offers no ARIA, Camellia, SEED ' +
   'or SM4'],
  [/^aes_ff1_/, 'crypto.js does no format-preserving encryption'],
  [/^(siphash|siphashx|vmac|kmac|hmac_sm3)/, 'crypto.js offers no such MAC'],
  [/^hmac_(sha1|sha224|sha3_|sha512_2)/, 'no JWS algorithm uses this HMAC ' +
   '(HS256/384/512 only); hotpCode() truncates to digits and is held to RFC ' +
   '4226/6238 by tests/totp*.js'],
  [/^bls_/, 'crypto.js does no BLS signatures (BBS is vendored and is not ' +
   'a BLS signature verifier over G2)'],
  [/^(primality|ec_prime_order_curves)_/, 'crypto.js generates no primes or ' +
   'curves; key generation is node\'s'],
  [/^(x25519|x448)/, 'crypto.js agrees keys only by ECDH over P-256/384/521 ' +
   '(JWE ECDH-ES, XML Encryption 1.1 ECDH-ES)'],
  [/^ecdh_(brainpool|sect|secp224r1|secp256k1)/, 'both ECDH doors agree over ' +
   'P-256, P-384 and P-521 only, and refuse other curves by name'],
  [/^ecdh_secp(256r1|384r1|521r1)_(test|pem_test)/, 'no door takes the peer ' +
   'key as an SPKI or PEM: JWE carries it as a JWK (the _webcrypto files) ' +
   'and XML as an uncompressed point (the _ecpoint files)'],
  [/^ecdsa_.*_bitcoin_/, 'the low-S rule is Bitcoin\'s; neither JOSE (RFC ' +
   '8812) nor XMLDSig requires it'],
  [/^ecdsa_.*shake/, 'no door verifies ECDSA with SHAKE'],
  [/^ecdsa_secp(160|192)/, 'node\'s OpenSSL does not read these curves as ' +
   'verification keys (tried at run time; see the curve check below)'],
  [/^dsa_2048_224_sha224/, 'XMLDSig names dsa-sha1 and dsa-sha256 only'],
  [/^rsa_signature_.*_(sha3_|sha512_2)/, 'no door verifies RSASSA-PKCS1 ' +
   'with SHA-3 or SHA-512/t'],
  [/^rsa_pss_.*shake/, 'no door verifies RSASSA-PSS with SHAKE'],
  [/^rsa_pss_2048_sha512_224/, 'no door verifies with SHA-512/224'],
  [/^rsa_pkcs1_\d+_sig_gen_/, 'no crypto.js door signs caller-chosen ' +
   'octets with RSASSA-PKCS1 (jsonwebtoken signs JWS; every signer frames ' +
   'what it signs); the verify vectors hold the same primitive'],
  [/^rsa_oaep_.*sha(224|512_224|512_256)_mgf1/, 'no door names a SHA-224 ' +
   'or SHA-512/t OAEP digest'],
  [/^rsa_three_primes_oaep_.*sha224/, 'no door names a SHA-224 OAEP digest'],
  [/^(hkdf|pbkdf2|pbes2)_/, 'no door takes a caller\'s salt, info or ' +
   'iterations: encryptWithKek() derives with HKDF over fixed labels, ' +
   'pbes2Key() prefixes the salt with the JWE alg (RFC 7518 4.8.1.1), and ' +
   'Wycheproof\'s PBES2 is PKCS#5 with AES-CBC, not JWE\'s PBES2+AESKW'],
  [/^mldsa_\d+_sign_noseed_/, 'crypto.js holds an ML-DSA private key only ' +
   'as its 32-byte seed (RFC 9964 section 3.2); an expanded key reaches no ' +
   'door'],
  [/^mlkem_/, 'crypto.js encapsulates and decapsulates nothing — no ' +
   'protocol here has an ML-KEM method (XML Encryption and JOSE register ' +
   'none); the service\'s ML-KEM KEY GENERATION is held to NIST\'s keyGen ' +
   'vectors by tests/acvp_pqc.js']
];

// Wycheproof's hash names -> node's.
// nodeHash() is a hot path: called for every group; no Entering/Leaving pair.
function nodeHash(name) {
  const map = { 'SHA-1': 'sha1', 'SHA-224': 'sha224', 'SHA-256': 'sha256',
                'SHA-384': 'sha384', 'SHA-512': 'sha512',
                'SHA3-224': 'sha3-224', 'SHA3-256': 'sha3-256',
                'SHA3-384': 'sha3-384', 'SHA3-512': 'sha3-512',
                'SHA-512/224': 'sha512-224', 'SHA-512/256': 'sha512-256' };
  return map[String(name)] || null;
}

// hex() is a hot path: every vector field; no Entering/Leaving pair.
function hex(s) {
  return Buffer.from(String(s || ''), 'hex');
}

// ---------------------------------------------------------------------------
// THE DOORS, one runner per way in. Each takes (context, test) and resolves
// true for ACCEPTED and false for REFUSED; a throw is a refusal. Hot paths:
// they run once per vector and carry no Entering/Leaving pair.
// ---------------------------------------------------------------------------
let crypto = null;
let errorCodes = null;

// refusesOnThrow() is a hot path: wraps every vector.
async function refusesOnThrow(fn) {
  try {
    return !!(await fn());
  } catch (e) {
    log.debug('Caught in refusesOnThrow(): ' + ((e && e.message) || e));
    return false;
  }
}

// pemPublic() is a hot path: once per group.
function pemPublic(g) {
  return nodeCrypto.createPublicKey(g.publicKeyPem);
}

// The XML SignatureMethod URI for a family and hash, from crypto.js's own
// table, so this file carries no URI of its own.
// xmlMethod() is a hot path: once per group.
function xmlMethod(family, hash, keyType) {
  const rows = crypto.xmlSignatureAlgorithms().verified;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (r.family === family && (r.hash || null) === (hash || null) &&
        (!keyType || r.keyTypes.indexOf(keyType) >= 0) &&
        !/#rsa-pss$/.test(r.uri)) {
      return r.uri;
    }
  }
  return null;
}

const XMLDSIG_RSA_PSS = 'http://www.w3.org/2007/05/xmldsig-more#rsa-pss';

// ---------------------------------------------------------------------------
// THE APPLICATIONS: which door each file goes through, and with what.
// `group(g, file)` answers a context, or a string naming why the group is not
// applicable. `expect(ctx, t)` may override the corpus's answer with the
// door's profile: { expect: 'reject' | 'skip', why }.
// ---------------------------------------------------------------------------
const JWS_EC = { secp256r1: ['ES256', 'sha256'], secp384r1: ['ES384', 'sha384'],
                 secp521r1: ['ES512', 'sha512'],
                 secp256k1: ['ES256K', 'sha256'] };
const COSE_EC = { secp256r1: [-7, 'sha256'], secp384r1: [-35, 'sha384'],
                  secp521r1: [-36, 'sha512'] };
const JWS_RS = { sha256: 'RS256', sha384: 'RS384', sha512: 'RS512' };
const COSE_RS = { sha256: -257, sha384: -258, sha512: -259 };
const JWS_PS = { sha256: ['PS256', 32], sha384: ['PS384', 48],
                 sha512: ['PS512', 64] };
const COSE_PS = { sha256: -37, sha384: -38, sha512: -39 };
const XML_HASHES = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512',
                    'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512'];
const RAW_HASHES = ['sha1', 'sha256', 'sha384', 'sha512'];
const ML_DSA = { mldsa_44: ['ML-DSA-44', -48], mldsa_65: ['ML-DSA-65', -49],
                 mldsa_87: ['ML-DSA-87', -50] };

// ecGroup() is a hot path: once per group.
function ecGroup(g, file) {
  const curve = g.publicKey && g.publicKey.curve;
  const hash = nodeHash(g.sha);
  let key = null;
  try {
    key = pemPublic(g);
  } catch (e) {
    log.debug('Caught in ecGroup(): ' + ((e && e.message) || e));
    return 'node cannot read a ' + curve + ' key';
  }
  return { curve: curve, hash: hash, key: key, p1363: /_p1363_/.test(file),
           g: g };
}

// Every `group`, `expect` and `run` method below is a HOT PATH — called once
// per test group or once per vector, some hundred thousand times a run — so
// none carries an Entering/Leaving pair, which would drown the log.
const APPLICATIONS = [
  // ----- ECDSA -----------------------------------------------------------
  { door: 'JWS ES*', files: /^ecdsa_secp(256r1|384r1|521r1|256k1)_sha\d+_p1363_test/,
    group: function (g, file) {
      const c = ecGroup(g, file);
      if (typeof c === 'string') {
        return c;
      }
      const row = JWS_EC[c.curve];
      if (!row || row[1] !== c.hash) {
        return 'no JWS algorithm pairs ' + c.curve + ' with ' + c.hash;
      }
      c.alg = row[0];
      c.jwk = g.publicKeyJwk;
      return c;
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.jwsSignatureValid(c.alg, c.jwk || c.key, hex(t.msg),
                                        hex(t.sig));
      });
    } },
  { door: 'XML ecdsa-*', files: /^ecdsa_(?!.*(bitcoin|shake)).*_test/,
    group: function (g, file) {
      const c = ecGroup(g, file);
      if (typeof c === 'string') {
        return c;
      }
      c.uri = XML_HASHES.indexOf(c.hash) >= 0 ? xmlMethod('ecdsa', c.hash)
                                               : null;
      return c.uri ? c : 'no XML ECDSA method with ' + g.sha;
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.verifyXmlSignatureValue(c.uri, c.key, hex(t.msg),
                                              hex(t.sig));
      });
    } },
  { door: 'raw ecdsa', files: /^ecdsa_(?!.*(bitcoin|shake)).*_test/,
    group: function (g, file) {
      const c = ecGroup(g, file);
      if (typeof c === 'string') {
        return c;
      }
      return RAW_HASHES.indexOf(c.hash) >= 0 ? c
        : 'verifyRawSignature() names SHA-1 and SHA-2 only';
    },
    run: function (c, t) {
      return crypto.verifyRawSignature({ family: 'ecdsa', hash: c.hash,
        encoding: c.p1363 ? 'p1363' : 'der' }, c.key, hex(t.msg), hex(t.sig));
    } },
  { door: 'COSE ES*', files: /^ecdsa_secp(256r1|384r1|521r1)_sha\d+_test/,
    group: function (g, file) {
      const c = ecGroup(g, file);
      if (typeof c === 'string') {
        return c;
      }
      const row = COSE_EC[c.curve];
      if (!row || row[1] !== c.hash) {
        return 'no COSE algorithm pairs ' + c.curve + ' with ' + c.hash;
      }
      c.alg = row[0];
      return c;
    },
    run: function (c, t) {
      return crypto.verifyCoseSignature(c.alg, c.key, hex(t.msg), hex(t.sig));
    } },
  { door: 'verifyWithPublicKey ecdsa', files: /^ecdsa_.*_sha256_(p1363_)?test/,
    group: function (g, file) {
      const c = ecGroup(g, file);
      return typeof c === 'string' ? c : Object.assign(c,
        { der: hex(g.publicKeyDer) });
    },
    run: function (c, t) {
      return crypto.verifyWithPublicKey(c.der, hex(t.msg), hex(t.sig),
                                        c.p1363 ? 'p1363' : 'der');
    } },
  // ----- RSASSA-PKCS1-v1_5 -----------------------------------------------
  { door: 'JWS RS*', files: /^rsa_signature_\d+_sha(256|384|512)_test/,
    group: function (g) {
      return { alg: JWS_RS[nodeHash(g.sha)], key: g.keyJwk || g.publicKeyPem };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.jwsSignatureValid(c.alg, c.key, hex(t.msg), hex(t.sig));
      });
    } },
  { door: 'XML rsa-sha*', files: /^rsa_signature_\d+_sha(224|256|384|512)_test/,
    group: function (g) {
      return { uri: xmlMethod('rsa', nodeHash(g.sha)), key: pemPublic(g) };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.verifyXmlSignatureValue(c.uri, c.key, hex(t.msg),
                                              hex(t.sig));
      });
    } },
  { door: 'raw rsa-pkcs1', files: /^rsa_signature_\d+_sha(256|384|512)_test/,
    group: function (g) {
      return { hash: nodeHash(g.sha), key: pemPublic(g) };
    },
    run: function (c, t) {
      return crypto.verifyRawSignature({ family: 'rsa-pkcs1', hash: c.hash },
                                       c.key, hex(t.msg), hex(t.sig));
    } },
  { door: 'COSE RS*', files: /^rsa_signature_\d+_sha(256|384|512)_test/,
    group: function (g) {
      return { alg: COSE_RS[nodeHash(g.sha)], key: pemPublic(g) };
    },
    run: function (c, t) {
      return crypto.verifyCoseSignature(c.alg, c.key, hex(t.msg), hex(t.sig));
    } },
  { door: 'verifyWithPublicKey rsa', files: /^rsa_signature_\d+_sha256_test/,
    group: function (g) {
      return { der: hex(g.publicKeyDer) };
    },
    run: function (c, t) {
      return crypto.verifyWithPublicKey(c.der, hex(t.msg), hex(t.sig));
    } },
  // ----- RSASSA-PSS ------------------------------------------------------
  { door: 'JWS PS*', files: /^rsa_pss_(\d+_sha\d+_mgf1_\d+|misc)_test/,
    group: function (g) {
      const hash = nodeHash(g.sha);
      const row = JWS_PS[hash];
      if (!row || nodeHash(g.mgfSha) !== hash || Number(g.sLen) !== row[1]) {
        return 'not a JWS PS* parameter set (' + g.sha + ', MGF1 ' +
          g.mgfSha + ', sLen ' + g.sLen + ')';
      }
      return { alg: row[0], key: g.publicKeyJwk || g.publicKeyPem };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.jwsSignatureValid(c.alg, c.key, hex(t.msg), hex(t.sig));
      });
    } },
  { door: 'XML rsa-pss (RSAPSSParams)', files: /^rsa_pss_/,
    group: function (g) {
      const hash = nodeHash(g.sha);
      if (XML_HASHES.indexOf(hash) < 0 || nodeHash(g.mgfSha) !== hash) {
        return 'RSAPSSParams with MGF1 over a different digest is refused ' +
          'by name (node cannot express it)';
      }
      return { key: pemPublic(g),
               pss: { hash: hash, saltLength: Number(g.sLen) } };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.verifyXmlSignatureValue(XMLDSIG_RSA_PSS, c.key,
          hex(t.msg), hex(t.sig), c.pss);
      });
    } },
  { door: 'XML <hash>-rsa-MGF1', files: /^rsa_pss_/,
    group: function (g) {
      const hash = nodeHash(g.sha);
      if (XML_HASHES.indexOf(hash) < 0 || nodeHash(g.mgfSha) !== hash ||
          Number(g.sLen) !== nodeCrypto.createHash(hash).digest().length) {
        return 'the MGF1 URIs fix the salt at the digest length';
      }
      return { key: pemPublic(g), uri: xmlMethod('rsa-pss', hash) };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.verifyXmlSignatureValue(c.uri, c.key, hex(t.msg),
                                              hex(t.sig));
      });
    } },
  { door: 'raw rsa-pss', files: /^rsa_pss_/,
    group: function (g) {
      const hash = nodeHash(g.sha);
      if (RAW_HASHES.indexOf(hash) < 0 || nodeHash(g.mgfSha) !== hash) {
        return 'verifyRawSignature() uses MGF1 over the message digest';
      }
      return { key: pemPublic(g), hash: hash, sLen: Number(g.sLen) };
    },
    run: function (c, t) {
      return crypto.verifyRawSignature({ family: 'rsa-pss', hash: c.hash,
        saltLength: c.sLen }, c.key, hex(t.msg), hex(t.sig));
    } },
  { door: 'COSE PS*', files: /^rsa_pss_/,
    group: function (g) {
      const hash = nodeHash(g.sha);
      const row = JWS_PS[hash];
      if (!row || nodeHash(g.mgfSha) !== hash || Number(g.sLen) !== row[1]) {
        return 'not a COSE PS* parameter set';
      }
      return { alg: COSE_PS[hash], key: pemPublic(g) };
    },
    run: function (c, t) {
      return crypto.verifyCoseSignature(c.alg, c.key, hex(t.msg), hex(t.sig));
    } },
  // ----- EdDSA -----------------------------------------------------------
  { door: 'JWS EdDSA', files: /^ed25519_test/,
    group: function (g) {
      return { key: g.publicKeyJwk };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.jwsSignatureValid('EdDSA', c.key, hex(t.msg),
                                        hex(t.sig));
      });
    } },
  { door: 'XML eddsa-*', files: /^ed(25519|448)_test/,
    group: function (g, file) {
      return { key: pemPublic(g),
               uri: xmlMethod('eddsa', null, /448/.test(file) ? 'ed448'
                                                                : 'ed25519') };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.verifyXmlSignatureValue(c.uri, c.key, hex(t.msg),
                                              hex(t.sig));
      });
    } },
  { door: 'raw eddsa', files: /^ed(25519|448)_test/,
    group: function (g) {
      return { key: pemPublic(g) };
    },
    run: function (c, t) {
      return crypto.verifyRawSignature({ family: 'eddsa' }, c.key, hex(t.msg),
                                       hex(t.sig));
    } },
  { door: 'COSE EdDSA', files: /^ed(25519|448)_test/,
    group: function (g) {
      return { key: pemPublic(g) };
    },
    run: function (c, t) {
      return crypto.verifyCoseSignature(-8, c.key, hex(t.msg), hex(t.sig));
    } },
  { door: 'verifyWithPublicKey eddsa', files: /^ed(25519|448)_test/,
    group: function (g) {
      return { der: hex(g.publicKeyDer) };
    },
    run: function (c, t) {
      return crypto.verifyWithPublicKey(c.der, hex(t.msg), hex(t.sig));
    } },
  // ----- DSA (XMLDSig only) ----------------------------------------------
  { door: 'XML dsa-sha256', files: /^dsa_.*_sha256_(p1363_)?test/,
    group: function (g) {
      return { key: pemPublic(g), uri: xmlMethod('dsa', 'sha256') };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.verifyXmlSignatureValue(c.uri, c.key, hex(t.msg),
                                              hex(t.sig));
      });
    } },
  // ----- HMAC (JWS HS*) --------------------------------------------------
  { door: 'JWS HS*', files: /^hmac_sha(256|384|512)_test/,
    group: function (g, file) {
      const bits = Number(/hmac_sha(\d+)/.exec(file)[1]);
      return { alg: 'HS' + bits, full: Number(g.tagSize) === bits };
    },
    expect: function (c) {
      return c.full ? null : { expect: 'reject', why: 'a JWS HS* MAC is the ' +
        'whole HMAC output (RFC 7518 3.2); a truncated tag is refused' };
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.jwsSignatureValid(c.alg, hex(t.key), hex(t.msg),
                                        hex(t.tag));
      });
    } },
  // ----- ML-DSA ----------------------------------------------------------
  { door: 'JWS ML-DSA', files: /^mldsa_\d+_verify_test/,
    group: function (g, file) {
      return { alg: ML_DSA[file.slice(0, 8)][0], pub: hex(g.publicKey) };
    },
    expect: mlDsaContext,
    run: function (c, t) {
      return refusesOnThrow(function () {
        return crypto.jwsSignatureValid(c.alg, c.pub, hex(t.msg), hex(t.sig));
      });
    } },
  { door: 'COSE ML-DSA', files: /^mldsa_\d+_verify_test/,
    group: function (g, file) {
      return { alg: ML_DSA[file.slice(0, 8)][1], pub: hex(g.publicKey) };
    },
    expect: mlDsaContext,
    run: function (c, t) {
      return crypto.verifyCoseSignature(c.alg, c.pub, hex(t.msg), hex(t.sig));
    } },
  { door: 'raw pq (vendored engine)', files: /^mldsa_\d+_verify_test/,
    group: function (g) {
      return { der: hex(g.publicKeyDer) };
    },
    expect: mlDsaContext,
    run: function (c, t) {
      return crypto.verifyRawSignature({ family: 'pq' }, c.der, hex(t.msg),
                                       hex(t.sig));
    } },
  { door: 'XML ml-dsa (node)', files: /^mldsa_\d+_verify_test/,
    group: function (g, file) {
      const alg = ML_DSA[file.slice(0, 8)][0].toLowerCase();
      const uri = xmlMethod('pq', null, alg);
      let key = null;
      try {
        key = nodeCrypto.createPublicKey({ key: hex(g.publicKeyDer),
                                           format: 'der', type: 'spki' });
      } catch (e) {
        log.debug('Caught in XML ml-dsa group(): ' + ((e && e.message) || e));
        key = null;
      }
      return { uri: uri, key: key };
    },
    expect: mlDsaContext,
    run: function (c, t) {
      return refusesOnThrow(function () {
        return c.key && crypto.verifyXmlSignatureValue(c.uri, c.key,
          hex(t.msg), hex(t.sig));
      });
    } },
  { door: 'JWS ML-DSA signer (seed)', files: /^mldsa_\d+_sign_seed_test/,
    group: function (g, file) {
      return { alg: ML_DSA[file.slice(0, 8)][0], seed: hex(g.privateSeed),
               pub: hex(g.publicKey) };
    },
    expect: function (c, t) {
      if (t.ctx !== undefined && t.ctx !== '') {
        return { expect: 'skip', why: 'a context string: crypto.js signs ' +
          'pure ML-DSA with the empty context only' };
      }
      if ((t.flags || []).indexOf('Internal') >= 0) {
        return { expect: 'skip', why: 'the internal interface (mu): no door' };
      }
      return null;
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        const sig = crypto.jwsSignatureOver(c.alg, c.seed, hex(t.msg));
        if ((t.flags || []).indexOf('Randomized') >= 0) {
          // A hedged vector: its bytes cannot be reproduced, so ours is held
          // to the vector's public key by the vendored engine instead.
          const spki = require('../common/vendored/pqc_x509')
            .encodeSpki(c.alg, c.pub);
          return nodeCrypto.verify(null, hex(t.msg),
            nodeCrypto.createPublicKey({ key: Buffer.from(spki),
                                         format: 'der', type: 'spki' }), sig);
        }
        return sig.equals(hex(t.sig));
      });
    } },
  // ----- AEAD ------------------------------------------------------------
  { door: 'JWE A*GCM content', files: /^aes_gcm_test/,
    group: function (g) {
      const enc = { 128: 'A128GCM', 192: 'A192GCM', 256: 'A256GCM' }[
        Number(g.keySize)];
      return enc ? { enc: enc, profile: Number(g.ivSize) === 96 &&
                     Number(g.tagSize) === 128, g: g }
                 : 'no AES-' + g.keySize + '-GCM enc';
    },
    expect: function (c) {
      return c.profile ? null : { expect: 'reject', why: 'RFC 7518 5.3: a ' +
        '96-bit IV and a 128-bit tag, and nothing else' };
    },
    run: jweContentRun },
  { door: 'JWE A*CBC-HS* content', files: /^a\d+cbc_hs\d+_test/,
    group: function (g, file) {
      const m = /^a(\d+)cbc_hs(\d+)/.exec(file);
      return { enc: 'A' + m[1] + 'CBC-HS' + m[2], profile: true };
    },
    run: jweContentRun },
  { door: 'XML aes*-gcm (decryptElement)', files: /^aes_gcm_test/,
    group: function (g) {
      const cipher = { 128: 'aes128-gcm', 256: 'aes256-gcm' }[
        Number(g.keySize)];
      if (!cipher) {
        return 'XML Encryption here has no aes192-gcm';
      }
      if (Number(g.ivSize) !== 96 || Number(g.tagSize) !== 128) {
        return 'an XML EncryptedData carries a 96-bit IV and a 128-bit tag ' +
          'by construction (the CipherValue layout)';
      }
      return { cipher: cipher, gcm: true };
    },
    expect: function (c, t) {
      return t.aad ? { expect: 'skip', why: 'XML Encryption has no AAD' }
                   : null;
    },
    run: xmlContentRun },
  { door: 'XML aes*-cbc (decryptElement)', files: /^aes_cbc_pkcs5_test/,
    group: function (g) {
      const cipher = { 128: 'aes128-cbc', 256: 'aes256-cbc' }[
        Number(g.keySize)];
      return cipher ? { cipher: cipher, gcm: false }
                    : 'XML Encryption here has no aes192-cbc';
    },
    expect: xmlCbcPadding,
    run: xmlContentRun },
  // ----- AES key wrap ----------------------------------------------------
  { door: 'AES-KW (JWE A*KW, ECDH-ES+A*KW, XML kw-aes*)',
    files: /^aes_wrap_test/,
    group: function () {
      return {};
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        const out = crypto.aesKeyUnwrap(hex(t.key), hex(t.ct));
        if (!out.equals(hex(t.msg))) {
          return false;
        }
        return crypto.aesKeyWrap(hex(t.key), hex(t.msg)).equals(hex(t.ct));
      });
    } },
  // ----- ECDH ------------------------------------------------------------
  { door: 'JWE ECDH-ES (decryptJweCompact)',
    files: /^ecdh_secp(256r1|384r1|521r1)_webcrypto_test/,
    group: function () {
      return {};
    },
    run: jweEcdhRun },
  { door: 'XML ECDH-ES (decryptElement)',
    files: /^ecdh_secp(256r1|384r1|521r1)_ecpoint_test/,
    group: function (g) {
      return { curve: g.curve };
    },
    run: xmlEcdhRun },
  // ----- RSA decryption --------------------------------------------------
  { door: 'JWE RSA-OAEP / RSA-OAEP-256 (decryptJweCompact)',
    files: /^rsa_(three_primes_)?oaep_/,
    group: function (g) {
      const pair = nodeHash(g.sha) + '/' + nodeHash(g.mgfSha);
      const alg = { 'sha1/sha1': 'RSA-OAEP', 'sha256/sha256': 'RSA-OAEP-256' }[
        pair];
      if (!alg) {
        return 'no JWE alg is OAEP with ' + pair;
      }
      if (Number(g.keySize) < 2048) {
        return 'a ' + g.keySize + '-bit key: RFC 7518 4.2 and 4.3 require ' +
          '2048 bits or more, and this service never holds a smaller one';
      }
      return { alg: alg, key: nodeCrypto.createPrivateKey(g.privateKeyPem) };
    },
    expect: function (c, t) {
      return t.label ? { expect: 'skip', why: 'JWE RSA-OAEP has no label' }
                     : null;
    },
    run: jweRsaRun },
  { door: 'XML rsa-oaep / rsa-oaep-mgf1p (decryptElement)',
    files: /^rsa_(three_primes_)?oaep_/,
    group: function (g) {
      const hash = nodeHash(g.sha);
      const mgf = nodeHash(g.mgfSha);
      if (['sha1', 'sha256', 'sha384', 'sha512'].indexOf(hash) < 0 ||
          ['sha1', 'sha256', 'sha384', 'sha512'].indexOf(mgf) < 0) {
        return 'XML Encryption names no ' + g.sha + ' or ' + g.mgfSha;
      }
      if (Number(g.keySize) < 2048) {
        return 'a ' + g.keySize + '-bit key this service never holds';
      }
      return { hash: hash, mgf: mgf,
               key: nodeCrypto.createPrivateKey(g.privateKeyPem) };
    },
    expect: function (c) {
      return c.hash === c.mgf ? null : { expect: 'reject', why: 'an ' +
        'rsa-oaep naming two different digests is refused by name ' +
        '(STS-KEYS-0072): node derives MGF1 from the OAEP digest' };
    },
    run: xmlRsaOaepRun },
  { door: 'XML rsa-1_5 (decryptElement, development)',
    files: /^rsa_pkcs1_\d+_test/,
    group: function (g) {
      return { key: nodeCrypto.createPrivateKey(g.privateKeyPem) };
    },
    expect: function (c, t) {
      if (!require('../common/mode').usesBrokenAlgorithms()) {
        return { expect: 'reject', why: 'product never unwraps rsa-1_5 ' +
          '(STS-KEYS-0070, XML Encryption 1.1 section 6.1.2)' };
      }
      return t.result === 'valid' ? null : { expect: 'no-document', why:
        'OpenSSL\'s implicit rejection: a bad padding unwraps to a ' +
        'deterministic random key rather than failing, so the refusal is ' +
        'the key-length or cipher check after it, never a decrypted ' +
        'document — and product mode never unwraps rsa-1_5 (STS-KEYS-0070)' };
    },
    run: xmlRsa15Run },
  // ----- The JOSE files --------------------------------------------------
  { door: 'verifyCompactJws', files: /^json_web_(signature|crypto|key)_test/,
    group: function (g) {
      return /^jwe/.test(String(g.comment)) ? 'a JWE group (below)'
                                            : joseSigGroup(g);
    },
    expect: joseSigProfile,
    run: function (c, t) {
      return refusesOnThrow(function () {
        try {
          return crypto.verifyCompactJws(t.jws, c.key,
                                         { algorithms: [c.alg] });
        } catch (e) {
          // The door's profile: a JWS here carries JSON claims, and the
          // payload is read only AFTER the signature verified — so this
          // refusal is a signature the door accepted.
          if (/payload is not readable/.test(String(e.message))) {
            return true;
          }
          throw e;
        }
      });
    } },
  { door: 'decryptJweCompact', files: /^json_web_(encryption|crypto)_test/,
    group: function (g) {
      return /^jwe|^rfc_7520|^Pkcs5/.test(String(g.comment)) ||
        g.type === 'JsonWebEncryption' ? joseEncGroup(g) : 'a JWS group';
    },
    expect: function (c, t) {
      const skip = joseSkip(c, t);
      if (skip) {
        return skip;
      }
      if (c.alg === 'RSA1_5') {
        return { expect: 'reject', why: 'RSA1_5 is refused by name in every ' +
          'mode (common/crypto.js, section 4)' };
      }
      if (/"zip"/.test(Buffer.from(String(t.jwe).split('.')[0], 'base64url')
        .toString('utf8'))) {
        return { expect: 'reject', why: 'this service advertises no ' +
          'zip_values_supported and refuses a compressed JWE by name' };
      }
      return null;
    },
    run: function (c, t) {
      return refusesOnThrow(function () {
        const opts = Object.assign({ allowedAlg: [c.alg] }, c.opts);
        const out = crypto.decryptJweCompact(t.jwe, opts);
        return t.pt === undefined || Buffer.from(out.plaintext, 'utf8')
          .equals(hex(t.pt));
      });
    } }
];

// mlDsaContext() is a hot path: once per ML-DSA vector.
function mlDsaContext(c, t) {
  if (t.ctx !== undefined && t.ctx !== '') {
    return { expect: 'skip', why: 'a context string: every door verifies ' +
      'pure ML-DSA with the empty context' };
  }
  return null;
}

// XML Encryption 1.1 section 5.2's padding is not PKCS#7: the last octet
// counts the padding (1 to 16) and the others are arbitrary. A vector
// Wycheproof calls invalid for its OTHER padding octets is a valid XML
// Encryption ciphertext, and the door must open it; decided here with node,
// independently of the door.
// xmlCbcPadding() is a hot path: once per vector.
function xmlCbcPadding(c, t) {
  const ct = hex(t.ct);
  if (t.result === 'valid' || !ct.length || ct.length % 16) {
    return null;
  }
  const d = nodeCrypto.createDecipheriv('aes-' + (hex(t.key).length * 8) +
                                        '-cbc', hex(t.key), hex(t.iv));
  d.setAutoPadding(false);
  const padded = Buffer.concat([d.update(ct), d.final()]);
  const count = padded[padded.length - 1];
  return count >= 1 && count <= 16
    ? { expect: 'accept', why: 'XML Encryption 1.1 5.2 padding: only the ' +
        'last octet (' + count + ') is defined' }
    : null;
}

// jweContentRun() is a hot path: once per AEAD vector.
async function jweContentRun(c, t) {
  return refusesOnThrow(function () {
    const pt = crypto.openJweContent(c.enc, hex(t.key), hex(t.iv), hex(t.aad),
                                     hex(t.ct), hex(t.tag));
    if (!pt.equals(hex(t.msg))) {
      return false;
    }
    const sealed = crypto.sealJweContent(c.enc, hex(t.key), hex(t.iv),
                                         hex(t.aad), hex(t.msg));
    return sealed.ciphertext.equals(hex(t.ct)) && sealed.tag.equals(hex(t.tag));
  });
}

// ---------------------------------------------------------------------------
// XML ENCRYPTION FRAMES. The key a vector names is carried to
// `decryptElement()` the way a real sender carries a content key: wrapped
// with rsa-oaep-mgf1p to an RSA key made here, at run time.
// ---------------------------------------------------------------------------
const XENC = 'http://www.w3.org/2001/04/xmlenc#';
const XENC11 = 'http://www.w3.org/2009/xmlenc11#';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const DSIG11 = 'http://www.w3.org/2009/xmldsig11#';
let transportKey = null;

// encryptedData() is a hot path: once per XML vector.
function encryptedData(cipherUri, keyInfoInner, cipherValue) {
  return '<xenc:EncryptedData xmlns:xenc="' + XENC + '" xmlns:xenc11="' +
    XENC11 + '" xmlns:ds="' + DS + '" xmlns:dsig11="' + DSIG11 + '">' +
    '<xenc:EncryptionMethod Algorithm="' + cipherUri + '"/>' +
    '<ds:KeyInfo>' + keyInfoInner + '</ds:KeyInfo>' +
    '<xenc:CipherData><xenc:CipherValue>' + cipherValue.toString('base64') +
    '</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>';
}

// encryptedKey() is a hot path: once per XML vector.
function encryptedKey(methodInner, methodUri, wrapped) {
  return '<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="' + methodUri +
    '">' + methodInner + '</xenc:EncryptionMethod><xenc:CipherData>' +
    '<xenc:CipherValue>' + wrapped.toString('base64') + '</xenc:CipherValue>' +
    '</xenc:CipherData></xenc:EncryptedKey>';
}

// The code decryptElement() marked, or 'ok'.
// outcome() is a hot path: once per XML vector.
function outcome(res) {
  return res && res.ok ? 'ok' : String(errorCodes.codeOf(res) || '?');
}

// A small document encrypted by NODE under a key, as the data a wrapped or
// agreed key has to open.
// sealedDocument() is a hot path: once per XML vector.
function sealedDocument(key, gcm) {
  const bits = key.length * 8;
  const iv = nodeCrypto.randomBytes(gcm ? 12 : 16);
  const c = nodeCrypto.createCipheriv('aes-' + bits + (gcm ? '-gcm' : '-cbc'),
                                      key, iv);
  const body = Buffer.concat([c.update('<a/>'), c.final()]);
  return Buffer.concat(gcm ? [iv, body, /** @type {any} */ (c).getAuthTag()]
                           : [iv, body]);
}

// xmlContentRun() is a hot path: once per vector. Accepted when the CIPHER
// accepted: the decryption is refused afterwards only because Wycheproof's
// plaintext is not XML (STS-KEYS-0023) or not UTF-8 (STS-KEYS-0025).
// STS-KEYS-0022 is the cipher's own refusal (the tag, or the padding).
async function xmlContentRun(c, t) {
  const wrapped = nodeCrypto.publicEncrypt({ key: transportKey.publicKey,
    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' },
    hex(t.key));
  const body = Buffer.concat(c.gcm ? [hex(t.iv), hex(t.ct), hex(t.tag)]
                                   : [hex(t.iv), hex(t.ct)]);
  const uri = (c.gcm ? XENC11 : XENC) + c.cipher;
  const xml = encryptedData(uri, encryptedKey('', XENC + 'rsa-oaep-mgf1p',
                                              wrapped), body);
  const res = crypto.decryptElement(xml, transportKey.privateKey, {});
  const code = outcome(res);
  return code === 'ok' || code === 'STS-KEYS-0023' || code === 'STS-KEYS-0025';
}

const OAEP_DIGEST_URI = { sha1: DS + 'sha1', sha256: XENC + 'sha256',
  sha384: 'http://www.w3.org/2001/04/xmldsig-more#sha384',
  sha512: XENC + 'sha512' };

// The unwrap accepted when the document opened (a 16- or 32-octet message,
// sealed here under it) or the length check refused it (STS-KEYS-0021, any
// other length) — both come after the key transport succeeded. STS-KEYS-0024
// is the transport's own refusal.
// xmlRsaOaepRun() is a hot path: once per vector.
async function xmlRsaOaepRun(c, t) {
  const msg = hex(t.msg);
  const fits = msg.length === 16 || msg.length === 32;
  const cipher = 'aes' + (msg.length === 32 ? 256 : 128) + '-cbc';
  const data = fits ? sealedDocument(msg, false)
                    : sealedDocument(Buffer.alloc(16), false);
  const label = t.label ? '<xenc:OAEPparams>' +
    hex(t.label).toString('base64') + '</xenc:OAEPparams>' : '';
  const doors = [];
  if (c.hash === 'sha1' && c.mgf === 'sha1') {
    doors.push(encryptedKey(label, XENC + 'rsa-oaep-mgf1p', hex(t.ct)));
  }
  doors.push(encryptedKey('<ds:DigestMethod Algorithm="' +
    OAEP_DIGEST_URI[c.hash] + '"/><xenc11:MGF Algorithm="' + XENC11 + 'mgf1' +
    c.mgf + '"/>' + label, XENC11 + 'rsa-oaep', hex(t.ct)));
  let all = true;
  for (let i = 0; i < doors.length; i++) {
    const res = crypto.decryptElement(encryptedData(XENC + cipher, doors[i],
                                                    data), c.key, {});
    const code = outcome(res);
    all = all && (fits ? code === 'ok' : code === 'STS-KEYS-0021');
  }
  return all;
}

// xmlRsa15Run() is a hot path: once per vector. See the expectation: an invalid
// padding can only ever be refused AFTER the unwrap.
async function xmlRsa15Run(c, t) {
  const msg = hex(t.msg);
  const fits = msg.length === 16 || msg.length === 32;
  const cipher = 'aes' + (msg.length === 32 ? 256 : 128) + '-cbc';
  const data = sealedDocument(fits ? msg : Buffer.alloc(16), false);
  const res = crypto.decryptElement(encryptedData(XENC + cipher,
    encryptedKey('', XENC + 'rsa-1_5', hex(t.ct)), data), c.key, {});
  const code = outcome(res);
  if (!require('../common/mode').usesBrokenAlgorithms()) {
    return code !== 'STS-KEYS-0070';
  }
  if (t.result !== 'valid') {
    return code === 'ok';
  }
  return fits ? code === 'ok' : code === 'STS-KEYS-0021';
}

// ---------------------------------------------------------------------------
// ECDH. The harness derives the content key from the vector's EXPECTED shared
// secret with its own Concat KDF (RFC 7518 4.6.2 / XML Encryption 1.1 5.4.1),
// seals a document under it with node, and asks the door to open it with the
// vector's private key and public point.
// ---------------------------------------------------------------------------
// concatKdf() is a hot path: once per ECDH vector.
function concatKdf(z, bytes, otherInfo) {
  const blocks = [];
  for (let i = 1; blocks.length * 32 < bytes; i++) {
    const n = Buffer.alloc(4);
    n.writeUInt32BE(i);
    blocks.push(nodeCrypto.createHash('sha256')
      .update(Buffer.concat([n, z, otherInfo])).digest());
  }
  return Buffer.concat(blocks).subarray(0, bytes);
}

// u32() is a hot path.
function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}

// jweEcdhRun() is a hot path: once per vector.
async function jweEcdhRun(c, t) {
  return refusesOnThrow(function () {
    const privateKey = nodeCrypto.createPrivateKey({ key: t.private,
                                                    format: 'jwk' });
    const header = { alg: 'ECDH-ES', enc: 'A128GCM', epk: t.public };
    const h = Buffer.from(JSON.stringify(header)).toString('base64url');
    const alg = Buffer.from('A128GCM');
    const cek = concatKdf(hex(t.shared), 16, Buffer.concat([u32(alg.length),
      alg, u32(0), u32(0), u32(128)]));
    const iv = nodeCrypto.randomBytes(12);
    const g = /** @type {any} */ (nodeCrypto.createCipheriv('aes-128-gcm',
                                                             cek, iv));
    g.setAAD(Buffer.from(h, 'ascii'));
    const ct = Buffer.concat([g.update('wycheproof'), g.final()]);
    const out = crypto.decryptJweCompact([h, '', iv.toString('base64url'),
      ct.toString('base64url'), g.getAuthTag().toString('base64url')]
      .join('.'), { privateKey: privateKey });
    return out.plaintext === 'wycheproof';
  });
}

const EC_OIDS = {
  secp256r1: { urn: 'urn:oid:1.2.840.10045.3.1.7', bytes: 32,
               der: '06082a8648ce3d030107' },
  secp384r1: { urn: 'urn:oid:1.3.132.0.34', bytes: 48, der: '06052b81040022' },
  secp521r1: { urn: 'urn:oid:1.3.132.0.35', bytes: 66, der: '06052b81040023' }
};

// derLength() is a hot path.
function derLength(n) {
  return n < 128 ? Buffer.from([n]) : Buffer.from([0x81, n]);
}

// An RFC 5915 ECPrivateKey with the public key omitted — node derives it.
// ecPrivateKey() is a hot path: once per vector.
function ecPrivateKey(curve, scalarHex) {
  const info = EC_OIDS[curve];
  let d = hex(scalarHex);
  while (d.length > info.bytes && d[0] === 0) {
    d = d.subarray(1);
  }
  d = Buffer.concat([Buffer.alloc(info.bytes - d.length), d]);
  const oid = hex(info.der);
  const body = Buffer.concat([Buffer.from([2, 1, 1, 4]), derLength(d.length),
    d, Buffer.from([0xa0]), derLength(oid.length), oid]);
  return nodeCrypto.createPrivateKey({ key: Buffer.concat([Buffer.from([0x30]),
    derLength(body.length), body]), format: 'der', type: 'sec1' });
}

// xmlEcdhRun() is a hot path: once per vector.
async function xmlEcdhRun(c, t) {
  const info = EC_OIDS[c.curve];
  const key = concatKdf(hex(t.shared), 16, Buffer.alloc(0));
  const agreement = '<xenc:AgreementMethod Algorithm="' + XENC11 +
    'ECDH-ES"><xenc11:KeyDerivationMethod Algorithm="' + XENC11 +
    'ConcatKDF"><xenc11:ConcatKDFParams><ds:DigestMethod Algorithm="' +
    XENC + 'sha256"/></xenc11:ConcatKDFParams></xenc11:KeyDerivationMethod>' +
    '<xenc:OriginatorKeyInfo><dsig11:ECKeyValue><dsig11:NamedCurve URI="' +
    info.urn + '"/><dsig11:PublicKey>' + hex(t.public).toString('base64') +
    '</dsig11:PublicKey></dsig11:ECKeyValue></xenc:OriginatorKeyInfo>' +
    '</xenc:AgreementMethod>';
  const res = crypto.decryptElement(encryptedData(XENC11 + 'aes128-gcm',
    agreement, sealedDocument(key, true)), ecPrivateKey(c.curve, t.private),
    {});
  return outcome(res) === 'ok';
}

// ---------------------------------------------------------------------------
// JWE RSA-OAEP: the vector's ciphertext is the encrypted_key; the content is
// sealed here under the vector's message when that is a CEK length, and the
// door's own "the unwrapped content encryption key is N bytes" is the
// acceptance of the unwrap otherwise.
// ---------------------------------------------------------------------------
const CEK_ENC = { 16: 'A128GCM', 24: 'A192GCM', 32: 'A256GCM',
                  48: 'A192CBC-HS384', 64: 'A256CBC-HS512' };

// jweRsaRun() is a hot path: once per vector.
async function jweRsaRun(c, t) {
  const msg = hex(t.msg);
  const enc = CEK_ENC[msg.length] || 'A128GCM';
  const h = Buffer.from(JSON.stringify({ alg: c.alg, enc: enc }))
    .toString('base64url');
  let iv = nodeCrypto.randomBytes(enc.indexOf('CBC') > 0 ? 16 : 12);
  let sealed = { ciphertext: Buffer.alloc(1), tag: Buffer.alloc(16) };
  if (CEK_ENC[msg.length]) {
    sealed = crypto.sealJweContent(enc, msg, iv, Buffer.from(h, 'ascii'),
                                   Buffer.from('wycheproof'));
  }
  try {
    const out = crypto.decryptJweCompact([h, hex(t.ct).toString('base64url'),
      iv.toString('base64url'), sealed.ciphertext.toString('base64url'),
      sealed.tag.toString('base64url')].join('.'), { privateKey: c.key });
    return !!CEK_ENC[msg.length] && out.plaintext === 'wycheproof';
  } catch (e) {
    log.debug('Caught in jweRsaRun(): ' + ((e && e.message) || e));
    return !CEK_ENC[msg.length] &&
      /unwrapped content encryption key is/.test(String(e.message));
  }
}

// ---------------------------------------------------------------------------
// THE JOSE FILES.
// ---------------------------------------------------------------------------
// publicPart() is a hot path.
function publicPart(jwk) {
  const out = Object.assign({}, jwk);
  ['d', 'p', 'q', 'dp', 'dq', 'qi'].forEach(function (m) {
    delete out[m];
  });
  return out;
}

// joseSigGroup() is a hot path: once per group.
function joseSigGroup(g) {
  let key = g.public || g.private;
  if (key && key.keys) {
    if (key.keys.length !== 1) {
      return 'a key SET: crypto.js verifies against the one key a caller ' +
        'chose; choosing among several (by kid, by kty) is the caller\'s ' +
        'and is held where it is done (oauth-oidc/client_jwks)';
    }
    key = key.keys[0];
  }
  if (!key || !key.alg) {
    return 'no algorithm is named by the key';
  }
  return { alg: key.alg, key: key.kty === 'oct'
    ? Buffer.from(String(key.k || ''), 'base64url') : publicPart(key) };
}

// joseEncGroup() is a hot path: once per group.
function joseEncGroup(g) {
  const key = g.private;
  if (!key || !key.alg) {
    return 'no algorithm is named by the key';
  }
  if (key.kty === 'oct') {
    // RFC 7520's `dir` key names the CONTENT algorithm as its `alg`.
    return { alg: /^A\d+(GCM|CBC-HS\d+)$/.test(key.alg) ? 'dir' : key.alg,
             opts: { secret: Buffer.from(String(key.k), 'base64url') } };
  }
  return { alg: key.alg, opts: { privateKey: nodeCrypto.createPrivateKey(
    { key: key, format: 'jwk' }) } };
}

// Where the JWS door's answer is its profile's rather than the corpus's.
// joseSigProfile() is a hot path: once per JOSE vector.
function joseSigProfile(c, t) {
  const skip = joseSkip(c, t);
  if (skip) {
    return skip;
  }
  const comment = String(t.comment || '');
  if (/^InvalidCharacterInserted/.test(comment)) {
    return { expect: 'reject', why: 'Wycheproof calls this valid on the ' +
      'reading that a decoder drops the character before the MAC is ' +
      'checked; RFC 7515 section 2 has no such character, and a verifier ' +
      'that drops it gives one token many spellings — the strict reading ' +
      'is kept, as tc361 and tc366 (invalid) require of the same bytes' };
  }
  if (comment === 'key_too_short') {
    return { expect: 'accept', why: 'RECORDED EXCEPTION on #202: an HMAC ' +
      'key shorter than its hash output is accepted in both modes, because ' +
      'the parent project\'s vendored sts_jws_verification.js registers ' +
      '~30-octet client secrets and runs in product (common/crypto.js, ' +
      'hmacKeyProblem())' };
  }
  if (comment === 'rejects1024bitRsaKey' &&
      require('../common/mode').usesBrokenAlgorithms()) {
    return { expect: 'accept', why: 'development accepts a key under RFC ' +
      '7518\'s sizes so a client holding one can be exercised; the product ' +
      'child below holds the refusal' };
  }
  let header = {};
  if (/^Figure/.test(comment)) {
    header = JSON.parse(Buffer.from(String(t.jws).split('.')[0], 'base64url')
      .toString('utf8'));
  }
  if (/^Figure/.test(comment) && header.alg !== c.alg) {
    return { expect: 'either', why: 'RFC 7520\'s key names ' + c.alg +
      ' and the example signs with ' + header.alg + ': whether that is ' +
      'accepted is the CALLER\'s list of algorithms (RFC 8725 3.1), which ' +
      'this door takes rather than reads from the key' };
  }
  return null;
}

// joseSkip() is a hot path.
function joseSkip(c, t) {
  const token = t.jws !== undefined ? t.jws : t.jwe;
  if (typeof token !== 'string' || /^\s*\{/.test(token)) {
    return { expect: 'skip', why: 'the JSON serialization: crypto.js reads ' +
      'the compact serialization only' };
  }
  return null;
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
function notApplicable(file) {
  log.debug('Entering notApplicable(). ' + file);
  for (let i = 0; i < NOT_APPLICABLE.length; i++) {
    if (NOT_APPLICABLE[i][1] && NOT_APPLICABLE[i][0].test(file)) {
      log.debug('Leaving notApplicable(). ' + NOT_APPLICABLE[i][1]);
      return NOT_APPLICABLE[i][1];
    }
  }
  log.debug('Leaving notApplicable(). Applicable, or unclassified.');
  return null;
}

// The expectation for one vector: 'accept', 'reject', 'either', 'skip' or
// 'no-document', and why.
// expectationOf() is a hot path: once per vector.
function expectationOf(app, c, t, file) {
  if (ERRATA[file + '#' + t.tcId]) {
    return ERRATA[file + '#' + t.tcId];
  }
  const profile = app.expect ? app.expect(c, t) : null;
  if (profile) {
    return profile;
  }
  if (t.result === 'valid') {
    return { expect: 'accept' };
  }
  if (t.result === 'invalid') {
    return { expect: 'reject' };
  }
  const flags = t.flags || [];
  for (let i = 0; i < flags.length; i++) {
    if (ACCEPTABLE[flags[i]]) {
      return { expect: ACCEPTABLE[flags[i]].decision,
               why: ACCEPTABLE[flags[i]].why };
    }
  }
  return { expect: 'undecided', why: 'an acceptable vector with flags ' +
    JSON.stringify(flags) + ' and no decision in ACCEPTABLE' };
}

async function runFile(t, file, apps, totals) {
  log.debug('Entering runFile(). ' + file);
  const json = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8'));
  for (let a = 0; a < apps.length; a++) {
    const app = apps[a];
    const count = { pass: 0, fail: 0, skip: 0, profile: 0, acceptable: 0,
                    groupsNa: 0 };
    const failures = [];
    let lastWhy = '';
    for (let gi = 0; gi < json.testGroups.length; gi++) {
      const g = json.testGroups[gi];
      let c;
      try {
        c = app.group(g, file);
      } catch (e) {
        log.debug('Caught in runFile(): ' + ((e && e.message) || e));
        c = 'the group could not be prepared: ' + e.message;
      }
      if (typeof c === 'string') {
        lastWhy = c;
        count.groupsNa++;
        count.skip += g.tests.length;
        continue;
      }
      for (let ti = 0; ti < g.tests.length; ti++) {
        const v = g.tests[ti];
        const want = expectationOf(app, c, v, file);
        if (want.expect === 'skip') {
          count.skip++;
          continue;
        }
        let accepted;
        try {
          accepted = await app.run(c, v);
        } catch (e) {
          log.debug('Caught in runFile(): ' + ((e && e.message) || e));
          accepted = false;
        }
        let good;
        if (want.expect === 'accept') {
          good = accepted;
        } else if (want.expect === 'reject') {
          good = !accepted;
        } else if (want.expect === 'no-document') {
          good = !accepted;
        } else if (want.expect === 'either') {
          good = true;
        } else {
          good = false;
        }
        if (want.why && want.expect !== 'either') {
          count.profile++;
        }
        if (v.result === 'acceptable') {
          count.acceptable++;
        }
        if (good) {
          count.pass++;
        } else {
          count.fail++;
          failures.push('tc' + v.tcId + ' (' + v.result + ', ' +
            JSON.stringify(v.flags || []) + ', ' + (v.comment || '') +
            ') wanted ' + want.expect + ', got ' +
            (accepted ? 'accepted' : 'refused') +
            (want.why ? ' [' + want.why + ']' : ''));
        }
      }
    }
    totals.pass += count.pass;
    totals.fail += count.fail;
    totals.skip += count.skip;
    totals.doors[app.door] = (totals.doors[app.door] || 0) + count.pass +
                             count.fail;
    if (count.pass + count.fail === 0) {
      t.log.info('  - ' + app.door + ' — ' + file + ': not applicable (' +
                 (lastWhy || 'every vector is outside the door') + ')');
      continue;
    }
    t.check(count.fail === 0,
      app.door + ' — ' + file + ': ' + count.pass + ' passed, ' +
      count.fail + ' failed, ' + count.skip + ' not applicable' +
      (count.profile ? ', ' + count.profile + ' held to the door\'s profile'
                     : '') +
      (count.acceptable ? ', ' + count.acceptable + ' acceptable decided'
                        : ''),
      failures.slice(0, 40).join('; ') +
        (failures.length > 8 ? '; … ' + (failures.length - 8) + ' more' : '') ||
        'no vector reached this door');
  }
  log.debug('Leaving runFile().');
}

// ---------------------------------------------------------------------------
// THE PRODUCT-MODE CHILD. Two refusals differ by mode — an RSA JWS key
// under 2048 bits, and rsa-1_5 key transport — and the mode is read when a
// setting is, so the files that reach them run again in a process started
// in product mode.
// ---------------------------------------------------------------------------
const CHILD_FLAG = 'STS_WYCHEPROOF_PRODUCT_CHILD';
const PRODUCT_FILES = '^json_web_(key|signature|crypto)_test|' +
                      '^rsa_pkcs1_\\d+_test';

function inAProductChild(t) {
  log.debug('Entering inAProductChild().');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const run = require('child_process').spawnSync(process.execPath,
    [__filename], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', STS_MODE: 'product',
                                  STS_WYCHEPROOF_DIR: VECTORS,
                                  STS_WYCHEPROOF_ONLY: PRODUCT_FILES }, {
        [CHILD_FLAG]: '1' }),
      encoding: 'utf8', timeout: 240000, maxBuffer: 64 * 1024 * 1024 });
  let report = null;
  try {
    report = JSON.parse(String(run.stdout).trim().split('\n').pop());
  } catch (e) {
    log.debug('Caught in inAProductChild(): ' + ((e && e.message) || e));
    report = null;
  }
  t.check(!!report && report.product === true && report.passed > 0 &&
          report.failures.length === 0,
    'product mode: a JWS RSA key under 2048 bits and rsa-1_5 are ' +
    'refused (' +
    (report ? report.passed : 0) + ' file checks)',
    report ? report.failures.slice(0, 10).join('; ')
           : 'exit ' + run.status + ' ' + String(run.stderr).slice(0, 800));
  log.debug('Leaving inAProductChild().');
}

module.exports = {
  name: 'wycheproof',
  describe: 'C2SP Wycheproof, every vector file, through common/crypto.js\'s ' +
            'own doors (#202)',
  run: async function (t) {
    log.debug('Entering run().');
    if (!fs.existsSync(DIR)) {
      t.bad('the Wycheproof corpus is not at ' + DIR,
        'it is fetched when the tests image is built ' +
        '(tests/tools/fetch-vectors.sh); run this file in that image');
      log.debug('Leaving run(). No corpus.');
      return;
    }
    crypto = require('../common/crypto');
    errorCodes = require('../common/error_codes');
    transportKey = nodeCrypto.generateKeyPairSync('rsa',
                                                  { modulusLength: 2048 });
    const commit = fs.existsSync(path.join(VECTORS, 'COMMIT'))
      ? fs.readFileSync(path.join(VECTORS, 'COMMIT'), 'utf8').trim()
      : '(unstamped)';
    t.log.info('=== Wycheproof ' + commit + ' ===');
    const files = fs.readdirSync(DIR).filter(function (f) {
      return /\.json$/.test(f);
    }).sort();
    const only = process.env.STS_WYCHEPROOF_ONLY
      ? new RegExp(process.env.STS_WYCHEPROOF_ONLY) : null;
    const totals = { pass: 0, fail: 0, skip: 0, doors: {} };
    const na = [];
    const unclassified = [];
    const started = Date.now();
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      if (only && !only.test(file)) {
        continue;
      }
      const apps = APPLICATIONS.filter(function (app) {
        return app.files.test(file);
      });
      if (!apps.length) {
        const why = notApplicable(file);
        if (why) {
          na.push(file + ': ' + why);
        } else {
          unclassified.push(file);
        }
        continue;
      }
      await runFile(t, file, apps, totals);
    }
    t.check(unclassified.length === 0,
      'every vector file is applied or listed as not applicable',
      unclassified.join(', '));
    t.log.info('not applicable (' + na.length + ' files):\n  ' +
               na.join('\n  '));
    t.log.info('Wycheproof: ' + totals.pass + ' vectors passed, ' +
      totals.fail + ' failed, ' + totals.skip + ' not applicable, in ' +
      Math.round((Date.now() - started) / 1000) + ' s; by door: ' +
      JSON.stringify(totals.doors));
    if (!process.env[CHILD_FLAG]) {
      inAProductChild(t);
    }
    log.debug('Leaving run().');
  }
};

if (require.main === module && process.env[CHILD_FLAG]) {
  const childHarness = require('./harness').createHarness('wycheproof-product');
  module.exports.run(childHarness).then(function () {
    process.stdout.write('\n' + JSON.stringify({
      product: !require('../common/mode').usesBrokenAlgorithms(),
      passed: childHarness.passed(), failures: childHarness.failures() }) +
      '\n');
    process.exit(0);
  });
}
