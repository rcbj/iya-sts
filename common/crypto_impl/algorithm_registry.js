// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: algorithm_registry.js
//
// ===========================================================================
// EVERY SIGNATURE ALGORITHM THIS SERVICE KNOWS, ONCE (#1368, phase 1, #1374).
//
// Each protocol names an algorithm its own way: `PS256` in JOSE, `-37` in
// COSE, a URI in XML, an OID and a PKI id in X.509. Until this file each of
// those spellings lived in a table of its own, so nothing could say "which
// algorithms, in which order, for which surface", and four COSE tables had
// grown apart. Now every such table is a VIEW of the rows below: it keeps its
// name, its shape, its members and its order, and reads them from here.
//
// A LEAF. It requires nothing of this service, because `config.js` reads it
// to build its `enumValues`, and `config.js` requires almost nothing in this
// repository so that everything else may require it.
//
// ---------------------------------------------------------------------------
// A ROW:
//
//   id        the canonical name: the JOSE `alg` where one exists
//   family    what the JWS table calls it: pq, ec, okp, rsa, hmac, dsa, bbs
//   kind      the operation: ml-dsa, slh-dsa, composite, ecdsa, eddsa,
//             rsa-pss, rsa-pkcs1, hmac, dsa, bbs
//   hash      the node digest name, or null where the algorithm chooses it
//   keyKind   the key it needs: akp, ec, okp, rsa, secret, dsa, bls12-381
//   pqc       `pqc_support.ts`'s kind for a signature: pq, composite or null
//   weak      broken or short (SHA-1, RIPEMD-160); nothing admits it unasked
//   sha1      SHA-1 in particular, which has settings of its own
//   jose cose xml x509 oid cms di httpsig tls dkim
//             its spelling on a surface, or null where it has none
//   aliases   other spellings a surface accepts for the same algorithm: XML's
//             second `rsa-sha224` URI, TLS's `rsa_pss_pss_*`, and on `httpsig`
//             the JWS name RFC 9421 section 3.3.7 allows
//   engine    per surface, what that surface's own code reads: the row of the
//             table it replaced, verbatim
//
// **THE SAME BYTES MAKE THE SAME ROW, AND NOT THE SAME NAME.** COSE `-8`
// (polymorphic EdDSA) and `-19` (fully specified Ed25519, RFC 9864) are two
// rows, as are `-7` and `-9`, because a setting can name one without the
// other. JOSE's `ML-DSA-44-ES256` and X.509's `mldsa44-ecdsa-p256-sha256` are
// one row: `pqc.js` and `pqc_x509.js` sign under the same label.
//
// ---------------------------------------------------------------------------
// TWO ORDERS, WHICH MUST NOT BE CONFUSED (#1368's review).
//
// `ROWS` is written in PREFERENCE ORDER: post-quantum strongest first, then
// classical strongest and most specific first, the weak ones last. It is what
// a console draws. It is NOT what an unconfigured service does: post-quantum
// signing is on by default, so treating it as the default would move every
// signature to ML-DSA and reorder discovery.
//
// `RECORDED` is what each surface and consumer does TODAY, member by member.
// An empty setting means that order. COSE has three such lists on purpose:
// mdoc (ISO/IEC 18013-5) takes no RSA, the status-list engine takes neither
// the fully specified forms nor RS1, and the verifier takes all twenty. A row
// on a surface is therefore not a promise that every consumer takes it.
//
// ---------------------------------------------------------------------------
// WHAT IS NOT HERE: the settings' narrower lists that are a decision about one
// use case (`oid4vp.x509SigningAlgorithm`, `webauthn.algorithms`' order) stay
// on their rows, and `tests/algorithm_registry.js` holds every name in them to
// a row. Key encryption is #1368's later twin. `x509.js`'s `SIG_ALGS` and
// `pq_jose.js`'s `PQ_ALGS` remain the engines' own tables, because they carry
// what the engines run on; the same test holds them equal to these rows.
//
// ---------------------------------------------------------------------------
// WHAT THE TABLES' OWN COMMENTS SAID, KEPT WITH THE ROWS THEY WERE ABOUT.
//
// **SHA-1 and RIPEMD-160 are weak**, and SHA-1 is the one a setting governs:
// RIPEMD-160's 160-bit output is SHA-1's, it is recorded as weak and accepted.
//
// **The XML HMAC methods (#658)** are a WS-Security signature keyed by a
// Kerberos token's session key (Kerberos Token Profile 1.1 section 3.2). Their
// key type is `secret`, which no certificate's public key is, so every path
// that verifies with a certificate refuses one; only `verifyWsSecurityHmac()`
// checks them, with the key the acceptor established. HMAC-SHA1 is SHA-1 to
// the algorithm policy, as every SHA-1 method is.
//
// **The XML post-quantum rows are the stateless families only**: HSS/LMS has a
// row in `xmldsig.js` and no verifier in node. The URIs must equal `xmldsig.js`'s
// and the test holds them to it, so the two cannot disagree about an identifier.
//
// **`ownSigner`** marks a JOSE row `jsonwebtoken` cannot sign: ES256K (RFC 8812),
// EdDSA (RFC 8037; Ed25519 hashes internally, so there is no digest to name) and
// everything post-quantum, which `pq_jose.js` performs. That is what makes those
// ordinary: `signJws()` and `verifyCompactJws()` route to it, and every metadata
// list reading the JOSE names gained them without being touched.
//
// **`kty: 'AKP'`** is RFC 9964's key type. RFC 9964 defined the AKP thumbprint
// members on 2026-09-13; since #150 DPoP takes the three JOSE-registered ML-DSA
// algorithms and refuses the rest by name (`oauth-oidc/dpop.ts`).
//
// **`engine.jose`'s `padding` IS NODE'S CONSTANT'S NAME**, resolved by
// `joseTable()`, so that this leaf needs no `crypto`: `tests/
// crypto_centralised.js` holds node's module to the crypto modules.
// ===========================================================================

const bunyan = require('bunyan');

// A process may load this before any configuration exists, so the level comes
// from the environment; `config.js` reads this file before it has settings.
const log = bunyan.createLogger({
  name: 'algorithm_registry',
  level: process.env.STS_LOG_LEVEL || 'info'
});

// Every surface a row may have a spelling on.
const SURFACES = ['jose', 'cose', 'xml', 'x509', 'cms', 'di', 'httpsig',
                  'tls', 'dkim'];

// The families `crypto.js`'s `verifyRawSignature()` understands. A property of
// that function and not of any one row, written here so that its one list of
// names is with the others.
const RAW_SIGNATURE_FAMILIES = ['rsa-pkcs1', 'rsa-pss', 'ecdsa', 'eddsa',
                                'pq'];

// The rows, in preference order. Generated once from the tables they replaced
// and edited here since.
const ROWS = [
  { id: 'ML-DSA-87', family: 'pq', kind: 'ml-dsa', hash: null, keyKind: 'akp',
    pqc: 'pq',
    jose: 'ML-DSA-87',
    cose: -50,
    xml: 'http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87',
    pki: 'ml-dsa-87',
    oid: '2.16.840.1.101.3.4.3.19',
    tls: 'mldsa87',
    spec: 'RFC 9964; FIPS 204',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-87',
        ownSigner: true
      },
      cose: { name: 'ML-DSA-87', family: 'pq', hash: null, kty: 'AKP' },
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['ml-dsa-87'],
        label: 'ML-DSA-87 (FIPS 204, category 5 — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ML-DSA-65', family: 'pq', kind: 'ml-dsa', hash: null, keyKind: 'akp',
    pqc: 'pq',
    jose: 'ML-DSA-65',
    cose: -49,
    xml: 'http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65',
    pki: 'ml-dsa-65',
    oid: '2.16.840.1.101.3.4.3.18',
    tls: 'mldsa65',
    spec: 'RFC 9964; FIPS 204',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-65',
        ownSigner: true
      },
      cose: { name: 'ML-DSA-65', family: 'pq', hash: null, kty: 'AKP' },
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['ml-dsa-65'],
        label: 'ML-DSA-65 (FIPS 204, category 3 — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ML-DSA-44', family: 'pq', kind: 'ml-dsa', hash: null, keyKind: 'akp',
    pqc: 'pq',
    jose: 'ML-DSA-44',
    cose: -48,
    xml: 'http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44',
    pki: 'ml-dsa-44',
    oid: '2.16.840.1.101.3.4.3.17',
    tls: 'mldsa44',
    spec: 'RFC 9964; FIPS 204',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-44',
        ownSigner: true
      },
      cose: { name: 'ML-DSA-44', family: 'pq', hash: null, kty: 'AKP' },
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['ml-dsa-44'],
        label: 'ML-DSA-44 (FIPS 204, category 2 — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHAKE-256f', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-256f',
    pki: 'slh-dsa-shake-256f',
    oid: '2.16.840.1.101.3.4.3.31',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-shake-256f'],
        label: 'SLH-DSA-SHAKE-256f (FIPS 205, fast — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHAKE-256s', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-256s',
    pki: 'slh-dsa-shake-256s',
    oid: '2.16.840.1.101.3.4.3.30',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-shake-256s'],
        label: 'SLH-DSA-SHAKE-256s (FIPS 205, small — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHAKE-192f', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-192f',
    pki: 'slh-dsa-shake-192f',
    oid: '2.16.840.1.101.3.4.3.29',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-shake-192f'],
        label: 'SLH-DSA-SHAKE-192f (FIPS 205, fast — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHAKE-192s', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-192s',
    pki: 'slh-dsa-shake-192s',
    oid: '2.16.840.1.101.3.4.3.28',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-shake-192s'],
        label: 'SLH-DSA-SHAKE-192s (FIPS 205, small — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHAKE-128f', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-128f',
    pki: 'slh-dsa-shake-128f',
    oid: '2.16.840.1.101.3.4.3.27',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-shake-128f'],
        label: 'SLH-DSA-SHAKE-128f (FIPS 205, fast — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHAKE-128s', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    jose: 'SLH-DSA-SHAKE-128s',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-128s',
    pki: 'slh-dsa-shake-128s',
    oid: '2.16.840.1.101.3.4.3.26',
    spec: 'FIPS 205',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'SLH-DSA-SHAKE-128s',
        ownSigner: true
      },
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-shake-128s'],
        label: 'SLH-DSA-SHAKE-128s (FIPS 205, small — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHA2-256f', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-256f',
    pki: 'slh-dsa-sha2-256f',
    oid: '2.16.840.1.101.3.4.3.25',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-sha2-256f'],
        label: 'SLH-DSA-SHA2-256f (FIPS 205, fast — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHA2-256s', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-256s',
    pki: 'slh-dsa-sha2-256s',
    oid: '2.16.840.1.101.3.4.3.24',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-sha2-256s'],
        label: 'SLH-DSA-SHA2-256s (FIPS 205, small — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHA2-192f', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-192f',
    pki: 'slh-dsa-sha2-192f',
    oid: '2.16.840.1.101.3.4.3.23',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-sha2-192f'],
        label: 'SLH-DSA-SHA2-192f (FIPS 205, fast — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHA2-192s', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-192s',
    pki: 'slh-dsa-sha2-192s',
    oid: '2.16.840.1.101.3.4.3.22',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-sha2-192s'],
        label: 'SLH-DSA-SHA2-192s (FIPS 205, small — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHA2-128f', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-128f',
    pki: 'slh-dsa-sha2-128f',
    oid: '2.16.840.1.101.3.4.3.21',
    spec: 'FIPS 205',
    engine: {
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-sha2-128f'],
        label: 'SLH-DSA-SHA2-128f (FIPS 205, fast — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'SLH-DSA-SHA2-128s', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    jose: 'SLH-DSA-SHA2-128s',
    xml: 'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-128s',
    pki: 'slh-dsa-sha2-128s',
    oid: '2.16.840.1.101.3.4.3.20',
    spec: 'FIPS 205',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'SLH-DSA-SHA2-128s',
        ownSigner: true
      },
      xml: {
        family: 'pq',
        hash: null,
        keyTypes: ['slh-dsa-sha2-128s'],
        label: 'SLH-DSA-SHA2-128s (FIPS 205, small — draft)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ML-DSA-87-Ed448', family: 'pq', kind: 'composite', hash: null,
    keyKind: 'akp', pqc: 'composite',
    jose: 'ML-DSA-87-Ed448',
    pki: 'mldsa87-ed448-shake256',
    oid: '1.3.6.1.5.5.7.6.51',
    spec:
      'draft-ietf-jose-pq-composite-sigs; ' +
      'draft-ietf-lamps-pq-composite-sigs',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-87-Ed448',
        ownSigner: true
      }
    } },
  { id: 'ML-DSA-87-ES384', family: 'pq', kind: 'composite', hash: null,
    keyKind: 'akp', pqc: 'composite',
    jose: 'ML-DSA-87-ES384',
    pki: 'mldsa87-ecdsa-p384-sha512',
    oid: '1.3.6.1.5.5.7.6.49',
    spec:
      'draft-ietf-jose-pq-composite-sigs; ' +
      'draft-ietf-lamps-pq-composite-sigs',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-87-ES384',
        ownSigner: true
      }
    } },
  { id: 'ML-DSA-65-Ed25519', family: 'pq', kind: 'composite', hash: null,
    keyKind: 'akp', pqc: 'composite',
    jose: 'ML-DSA-65-Ed25519',
    pki: 'mldsa65-ed25519-sha512',
    oid: '1.3.6.1.5.5.7.6.48',
    spec:
      'draft-ietf-jose-pq-composite-sigs; ' +
      'draft-ietf-lamps-pq-composite-sigs',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-65-Ed25519',
        ownSigner: true
      }
    } },
  { id: 'ML-DSA-65-ES256', family: 'pq', kind: 'composite', hash: null,
    keyKind: 'akp', pqc: 'composite',
    jose: 'ML-DSA-65-ES256',
    pki: 'mldsa65-ecdsa-p256-sha512',
    oid: '1.3.6.1.5.5.7.6.45',
    spec:
      'draft-ietf-jose-pq-composite-sigs; ' +
      'draft-ietf-lamps-pq-composite-sigs',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-65-ES256',
        ownSigner: true
      }
    } },
  { id: 'ML-DSA-44-Ed25519', family: 'pq', kind: 'composite', hash: null,
    keyKind: 'akp', pqc: 'composite',
    jose: 'ML-DSA-44-Ed25519',
    pki: 'mldsa44-ed25519-sha512',
    oid: '1.3.6.1.5.5.7.6.39',
    spec:
      'draft-ietf-jose-pq-composite-sigs; ' +
      'draft-ietf-lamps-pq-composite-sigs',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-44-Ed25519',
        ownSigner: true
      }
    } },
  { id: 'ML-DSA-44-ES256', family: 'pq', kind: 'composite', hash: null,
    keyKind: 'akp', pqc: 'composite',
    jose: 'ML-DSA-44-ES256',
    pki: 'mldsa44-ecdsa-p256-sha256',
    oid: '1.3.6.1.5.5.7.6.40',
    spec:
      'draft-ietf-jose-pq-composite-sigs; ' +
      'draft-ietf-lamps-pq-composite-sigs',
    engine: {
      jose: {
        family: 'pq',
        hash: null,
        kty: 'AKP',
        alg: 'ML-DSA-44-ES256',
        ownSigner: true
      }
    } },
  { id: 'ML-DSA-44-RSA2048-PSS-SHA256', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa44-rsa2048-pss-sha256',
    oid: '1.3.6.1.5.5.7.6.37',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-44-RSA2048-PKCS15-SHA256', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa44-rsa2048-pkcs15-sha256',
    oid: '1.3.6.1.5.5.7.6.38',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-65-RSA3072-PSS-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa65-rsa3072-pss-sha512',
    oid: '1.3.6.1.5.5.7.6.41',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-65-RSA3072-PKCS15-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa65-rsa3072-pkcs15-sha512',
    oid: '1.3.6.1.5.5.7.6.42',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-65-RSA4096-PSS-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa65-rsa4096-pss-sha512',
    oid: '1.3.6.1.5.5.7.6.43',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-65-RSA4096-PKCS15-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa65-rsa4096-pkcs15-sha512',
    oid: '1.3.6.1.5.5.7.6.44',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-65-ECDSA-P384-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa65-ecdsa-p384-sha512',
    oid: '1.3.6.1.5.5.7.6.46',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-87-RSA3072-PSS-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa87-rsa3072-pss-sha512',
    oid: '1.3.6.1.5.5.7.6.52',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-87-RSA4096-PSS-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa87-rsa4096-pss-sha512',
    oid: '1.3.6.1.5.5.7.6.53',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ML-DSA-87-ECDSA-P521-SHA512', family: 'pq', kind: 'composite',
    hash: null, keyKind: 'akp', pqc: 'composite',
    pki: 'mldsa87-ecdsa-p521-sha512',
    oid: '1.3.6.1.5.5.7.6.54',
    spec: 'draft-ietf-lamps-pq-composite-sigs' },
  { id: 'ES512', family: 'ec', kind: 'ecdsa', hash: 'sha512', keyKind: 'ec',
    jose: 'ES512',
    cose: -36,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
    pki: 'sha512-ecdsa',
    oid: '1.2.840.10045.4.3.4',
    cms: '1.2.840.10045.4.3.4',
    tls: 'ecdsa_secp521r1_sha512',
    spec: 'RFC 7518 section 3.4; RFC 9053',
    engine: {
      jose: {
        family: 'ec',
        hash: 'sha512',
        kty: 'EC',
        crv: 'P-521',
        namedCurve: 'secp521r1',
        sigBytes: 132
      },
      cose: { name: 'ES512', family: 'ecdsa', hash: 'sha512', kty: 'EC' },
      xml: {
        family: 'ecdsa',
        hash: 'sha512',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA512',
        weak: false,
        sha1: false
      },
      cms: { key: 'ec', digest: 'sha512', label: 'ecdsa-with-SHA512' }
    } },
  { id: 'ES384', family: 'ec', kind: 'ecdsa', hash: 'sha384', keyKind: 'ec',
    jose: 'ES384',
    cose: -35,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
    pki: 'sha384-ecdsa',
    oid: '1.2.840.10045.4.3.3',
    cms: '1.2.840.10045.4.3.3',
    httpsig: 'ecdsa-p384-sha384',
    tls: 'ecdsa_secp384r1_sha384',
    spec: 'RFC 7518 section 3.4; RFC 9053',
    engine: {
      jose: {
        family: 'ec',
        hash: 'sha384',
        kty: 'EC',
        crv: 'P-384',
        namedCurve: 'secp384r1',
        sigBytes: 96
      },
      cose: { name: 'ES384', family: 'ecdsa', hash: 'sha384', kty: 'EC' },
      xml: {
        family: 'ecdsa',
        hash: 'sha384',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA384',
        weak: false,
        sha1: false
      },
      httpsig: {
        registry: 'http',
        kind: 'ecdsa',
        hash: 'sha384',
        curve: 'secp384r1',
        coordinateBytes: 48,
        spec: 'RFC 9421 section 3.3.5'
      },
      cms: { key: 'ec', digest: 'sha384', label: 'ecdsa-with-SHA384' }
    } },
  { id: 'ES256', family: 'ec', kind: 'ecdsa', hash: 'sha256', keyKind: 'ec',
    jose: 'ES256',
    cose: -7,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
    pki: 'sha256-ecdsa',
    oid: '1.2.840.10045.4.3.2',
    cms: '1.2.840.10045.4.3.2',
    httpsig: 'ecdsa-p256-sha256',
    tls: 'ecdsa_secp256r1_sha256',
    spec: 'RFC 7518 section 3.4; RFC 9053',
    engine: {
      jose: {
        family: 'ec',
        hash: 'sha256',
        kty: 'EC',
        crv: 'P-256',
        namedCurve: 'prime256v1',
        sigBytes: 64
      },
      cose: { name: 'ES256', family: 'ecdsa', hash: 'sha256', kty: 'EC' },
      xml: {
        family: 'ecdsa',
        hash: 'sha256',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA256',
        weak: false,
        sha1: false
      },
      httpsig: {
        registry: 'http',
        kind: 'ecdsa',
        hash: 'sha256',
        curve: 'prime256v1',
        coordinateBytes: 32,
        spec: 'RFC 9421 section 3.3.4'
      },
      cms: { key: 'ec', digest: 'sha256', label: 'ecdsa-with-SHA256' }
    } },
  { id: 'ES256K', family: 'ec', kind: 'ecdsa', hash: 'sha256', keyKind: 'ec',
    jose: 'ES256K',
    cose: -47,
    spec: 'RFC 8812',
    engine: {
      jose: {
        family: 'ec',
        hash: 'sha256',
        kty: 'EC',
        crv: 'secp256k1',
        namedCurve: 'secp256k1',
        sigBytes: 64,
        ownSigner: true
      },
      cose: {
        name: 'ES256K',
        family: 'ecdsa',
        hash: 'sha256',
        kty: 'EC',
        curve: 'secp256k1'
      }
    } },
  { id: 'ESP512', family: 'ec', kind: 'ecdsa', hash: 'sha512', keyKind: 'ec',
    cose: -52,
    spec: 'RFC 9864',
    engine: {
      cose: {
        name: 'ESP512',
        family: 'ecdsa',
        hash: 'sha512',
        kty: 'EC',
        curve: 'secp521r1'
      }
    } },
  { id: 'ESP384', family: 'ec', kind: 'ecdsa', hash: 'sha384', keyKind: 'ec',
    cose: -51,
    spec: 'RFC 9864',
    engine: {
      cose: {
        name: 'ESP384',
        family: 'ecdsa',
        hash: 'sha384',
        kty: 'EC',
        curve: 'secp384r1'
      }
    } },
  { id: 'ESP256', family: 'ec', kind: 'ecdsa', hash: 'sha256', keyKind: 'ec',
    cose: -9,
    spec: 'RFC 9864',
    engine: {
      cose: {
        name: 'ESP256',
        family: 'ecdsa',
        hash: 'sha256',
        kty: 'EC',
        curve: 'prime256v1'
      }
    } },
  { id: 'EdDSA', family: 'okp', kind: 'eddsa', hash: null, keyKind: 'okp',
    jose: 'EdDSA',
    cose: -8,
    spec: 'RFC 8037; RFC 9053',
    engine: {
      jose: {
        family: 'okp',
        hash: null,
        kty: 'OKP',
        crv: 'Ed25519',
        sigBytes: 64,
        ownSigner: true
      },
      cose: { name: 'EdDSA', family: 'eddsa', hash: null, kty: 'OKP' }
    } },
  { id: 'Ed448', family: 'okp', kind: 'eddsa', hash: null, keyKind: 'okp',
    cose: -53,
    xml: 'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448',
    tls: 'ed448',
    spec: 'RFC 8032; RFC 9864; RFC 9231',
    engine: {
      cose: {
        name: 'Ed448',
        family: 'eddsa',
        hash: null,
        kty: 'OKP',
        okp: 'ed448'
      },
      xml: {
        family: 'eddsa',
        hash: null,
        keyTypes: ['ed448'],
        label: 'EdDSA Ed448 (RFC 9231)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'Ed25519', family: 'okp', kind: 'eddsa', hash: null, keyKind: 'okp',
    cose: -19,
    xml: 'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519',
    pki: 'ed25519',
    oid: '1.3.101.112',
    httpsig: 'ed25519',
    tls: 'ed25519',
    dkim: 'ed25519-sha256',
    spec: 'RFC 8032; RFC 9864; RFC 9231; RFC 9421 section 3.3.6; RFC 8463',
    engine: {
      cose: {
        name: 'Ed25519',
        family: 'eddsa',
        hash: null,
        kty: 'OKP',
        okp: 'ed25519'
      },
      xml: {
        family: 'eddsa',
        hash: null,
        keyTypes: ['ed25519'],
        label: 'EdDSA Ed25519 (RFC 9231)',
        weak: false,
        sha1: false
      },
      httpsig: {
        registry: 'http',
        kind: 'eddsa',
        curves: ['ed25519'],
        spec: 'RFC 9421 section 3.3.6'
      }
    } },
  { id: 'PS512', family: 'rsa', kind: 'rsa-pss', hash: 'sha512', keyKind: 'rsa',
    jose: 'PS512',
    cose: -39,
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1',
    pki: 'sha512-rsapss',
    oid: '1.2.840.113549.1.1.10',
    httpsig: 'rsa-pss-sha512',
    tls: 'rsa_pss_rsae_sha512',
    aliases: { tls: ['rsa_pss_pss_sha512'] },
    spec: 'RFC 7518 section 3.5; RFC 8230; RFC 9231',
    engine: {
      jose: {
        family: 'rsa',
        hash: 'sha512',
        kty: 'RSA',
        padding: 'RSA_PKCS1_PSS_PADDING',
        saltLength: 64
      },
      cose: {
        name: 'PS512',
        family: 'rsa-pss',
        hash: 'sha512',
        kty: 'RSA',
        saltLength: 64
      },
      xml: {
        family: 'rsa-pss',
        hash: 'sha512',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA512 with MGF1',
        weak: false,
        sha1: false
      },
      httpsig: {
        registry: 'http',
        kind: 'rsa-pss',
        hash: 'sha512',
        saltLength: 64,
        spec: 'RFC 9421 section 3.3.1'
      }
    } },
  { id: 'PS384', family: 'rsa', kind: 'rsa-pss', hash: 'sha384', keyKind: 'rsa',
    jose: 'PS384',
    cose: -38,
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1',
    pki: 'sha384-rsapss',
    oid: '1.2.840.113549.1.1.10',
    tls: 'rsa_pss_rsae_sha384',
    aliases: { tls: ['rsa_pss_pss_sha384'] },
    spec: 'RFC 7518 section 3.5; RFC 8230; RFC 9231',
    engine: {
      jose: {
        family: 'rsa',
        hash: 'sha384',
        kty: 'RSA',
        padding: 'RSA_PKCS1_PSS_PADDING',
        saltLength: 48
      },
      cose: {
        name: 'PS384',
        family: 'rsa-pss',
        hash: 'sha384',
        kty: 'RSA',
        saltLength: 48
      },
      xml: {
        family: 'rsa-pss',
        hash: 'sha384',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA384 with MGF1',
        weak: false,
        sha1: false
      }
    } },
  { id: 'PS256', family: 'rsa', kind: 'rsa-pss', hash: 'sha256', keyKind: 'rsa',
    jose: 'PS256',
    cose: -37,
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1',
    pki: 'sha256-rsapss',
    oid: '1.2.840.113549.1.1.10',
    tls: 'rsa_pss_rsae_sha256',
    aliases: { tls: ['rsa_pss_pss_sha256'] },
    spec: 'RFC 7518 section 3.5; RFC 8230; RFC 9231',
    engine: {
      jose: {
        family: 'rsa',
        hash: 'sha256',
        kty: 'RSA',
        padding: 'RSA_PKCS1_PSS_PADDING',
        saltLength: 32
      },
      cose: {
        name: 'PS256',
        family: 'rsa-pss',
        hash: 'sha256',
        kty: 'RSA',
        saltLength: 32
      },
      xml: {
        family: 'rsa-pss',
        hash: 'sha256',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA256 with MGF1',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RS512', family: 'rsa', kind: 'rsa-pkcs1', hash: 'sha512',
    keyKind: 'rsa',
    jose: 'RS512',
    cose: -259,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
    pki: 'sha512-rsa',
    oid: '1.2.840.113549.1.1.13',
    cms: '1.2.840.113549.1.1.13',
    tls: 'rsa_pkcs1_sha512',
    spec: 'RFC 7518 section 3.3; RFC 8230; RFC 9231',
    engine: {
      jose: { family: 'rsa', hash: 'sha512', kty: 'RSA' },
      cose: { name: 'RS512', family: 'rsa-pkcs1', hash: 'sha512', kty: 'RSA' },
      xml: {
        family: 'rsa',
        hash: 'sha512',
        keyTypes: ['rsa'],
        label: 'RSA-SHA512',
        weak: false,
        sha1: false
      },
      cms: { key: 'rsa', digest: 'sha512', label: 'sha512WithRSAEncryption' }
    } },
  { id: 'RS384', family: 'rsa', kind: 'rsa-pkcs1', hash: 'sha384',
    keyKind: 'rsa',
    jose: 'RS384',
    cose: -258,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    pki: 'sha384-rsa',
    oid: '1.2.840.113549.1.1.12',
    cms: '1.2.840.113549.1.1.12',
    tls: 'rsa_pkcs1_sha384',
    spec: 'RFC 7518 section 3.3; RFC 8230; RFC 9231',
    engine: {
      jose: { family: 'rsa', hash: 'sha384', kty: 'RSA' },
      cose: { name: 'RS384', family: 'rsa-pkcs1', hash: 'sha384', kty: 'RSA' },
      xml: {
        family: 'rsa',
        hash: 'sha384',
        keyTypes: ['rsa'],
        label: 'RSA-SHA384',
        weak: false,
        sha1: false
      },
      cms: { key: 'rsa', digest: 'sha384', label: 'sha384WithRSAEncryption' }
    } },
  { id: 'RS256', family: 'rsa', kind: 'rsa-pkcs1', hash: 'sha256',
    keyKind: 'rsa',
    jose: 'RS256',
    cose: -257,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    pki: 'sha256-rsa',
    oid: '1.2.840.113549.1.1.11',
    cms: '1.2.840.113549.1.1.11',
    httpsig: 'rsa-v1_5-sha256',
    tls: 'rsa_pkcs1_sha256',
    dkim: 'rsa-sha256',
    spec: 'RFC 7518 section 3.3; RFC 8230; RFC 9231',
    engine: {
      jose: { family: 'rsa', hash: 'sha256', kty: 'RSA' },
      cose: { name: 'RS256', family: 'rsa-pkcs1', hash: 'sha256', kty: 'RSA' },
      xml: {
        family: 'rsa',
        hash: 'sha256',
        keyTypes: ['rsa'],
        label: 'RSA-SHA256',
        weak: false,
        sha1: false
      },
      httpsig: {
        registry: 'http',
        kind: 'rsa-v1_5',
        hash: 'sha256',
        spec: 'RFC 9421 section 3.3.2'
      },
      cms: { key: 'rsa', digest: 'sha256', label: 'sha256WithRSAEncryption' }
    } },
  { id: 'HS512', family: 'hmac', kind: 'hmac', hash: 'sha512',
    keyKind: 'secret',
    jose: 'HS512',
    xml: 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512',
    spec: 'RFC 7518 section 3.2; RFC 9231',
    engine: {
      jose: { family: 'hmac', hash: 'sha512' },
      xml: {
        family: 'hmac',
        hash: 'sha512',
        keyTypes: ['secret'],
        label: 'HMAC-SHA512 (a Kerberos token\'s session key)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'HS384', family: 'hmac', kind: 'hmac', hash: 'sha384',
    keyKind: 'secret',
    jose: 'HS384',
    xml: 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384',
    spec: 'RFC 7518 section 3.2; RFC 9231',
    engine: {
      jose: { family: 'hmac', hash: 'sha384' },
      xml: {
        family: 'hmac',
        hash: 'sha384',
        keyTypes: ['secret'],
        label: 'HMAC-SHA384 (a Kerberos token\'s session key)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'HS256', family: 'hmac', kind: 'hmac', hash: 'sha256',
    keyKind: 'secret',
    jose: 'HS256',
    xml: 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
    httpsig: 'hmac-sha256',
    spec: 'RFC 7518 section 3.2; RFC 9231',
    engine: {
      jose: { family: 'hmac', hash: 'sha256' },
      xml: {
        family: 'hmac',
        hash: 'sha256',
        keyTypes: ['secret'],
        label: 'HMAC-SHA256 (a Kerberos token\'s session key)',
        weak: false,
        sha1: false
      },
      httpsig: {
        registry: 'http',
        kind: 'hmac',
        hash: 'sha256',
        minKeyBytes: 32,
        spec: 'RFC 9421 section 3.3.3'
      }
    } },
  { id: 'RSA-SHA224', family: 'rsa', kind: 'rsa-pkcs1', hash: 'sha224',
    keyKind: 'rsa',
    xml: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224',
    aliases: { xml: ['http://www.w3.org/2007/05/xmldsig-more#rsa-sha224'] },
    spec: 'RFC 9231 section 2.3.4',
    engine: {
      xml: {
        family: 'rsa',
        hash: 'sha224',
        keyTypes: ['rsa'],
        label: 'RSA-SHA224',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RSA-PSS-SHA3-512', family: 'rsa', kind: 'rsa-pss', hash: 'sha3-512',
    keyKind: 'rsa',
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1',
    spec: 'RFC 9231 section 2.3.10',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'sha3-512',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA3-512 with MGF1',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RSA-PSS-SHA3-384', family: 'rsa', kind: 'rsa-pss', hash: 'sha3-384',
    keyKind: 'rsa',
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1',
    spec: 'RFC 9231 section 2.3.10',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'sha3-384',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA3-384 with MGF1',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RSA-PSS-SHA3-256', family: 'rsa', kind: 'rsa-pss', hash: 'sha3-256',
    keyKind: 'rsa',
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1',
    spec: 'RFC 9231 section 2.3.10',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'sha3-256',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA3-256 with MGF1',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RSA-PSS-SHA3-224', family: 'rsa', kind: 'rsa-pss', hash: 'sha3-224',
    keyKind: 'rsa',
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1',
    spec: 'RFC 9231 section 2.3.10',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'sha3-224',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA3-224 with MGF1',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RSA-PSS-SHA224', family: 'rsa', kind: 'rsa-pss', hash: 'sha224',
    keyKind: 'rsa',
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1',
    spec: 'RFC 9231 section 2.3.10',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'sha224',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA224 with MGF1',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RSA-PSS-PARAMS', family: 'rsa', kind: 'rsa-pss', hash: 'sha256',
    keyKind: 'rsa',
    xml: 'http://www.w3.org/2007/05/xmldsig-more#rsa-pss',
    spec: 'RFC 9231 section 2.3.9',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'sha256',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS with parameters (RFC 9231 section 2.3.9)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ECDSA-SHA3-512', family: 'ec', kind: 'ecdsa', hash: 'sha3-512',
    keyKind: 'ec',
    xml: 'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512',
    spec: 'RFC 9231 section 2.3.6',
    engine: {
      xml: {
        family: 'ecdsa',
        hash: 'sha3-512',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA3-512',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ECDSA-SHA3-384', family: 'ec', kind: 'ecdsa', hash: 'sha3-384',
    keyKind: 'ec',
    xml: 'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384',
    spec: 'RFC 9231 section 2.3.6',
    engine: {
      xml: {
        family: 'ecdsa',
        hash: 'sha3-384',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA3-384',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ECDSA-SHA3-256', family: 'ec', kind: 'ecdsa', hash: 'sha3-256',
    keyKind: 'ec',
    xml: 'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256',
    spec: 'RFC 9231 section 2.3.6',
    engine: {
      xml: {
        family: 'ecdsa',
        hash: 'sha3-256',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA3-256',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ECDSA-SHA3-224', family: 'ec', kind: 'ecdsa', hash: 'sha3-224',
    keyKind: 'ec',
    xml: 'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224',
    spec: 'RFC 9231 section 2.3.6',
    engine: {
      xml: {
        family: 'ecdsa',
        hash: 'sha3-224',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA3-224',
        weak: false,
        sha1: false
      }
    } },
  { id: 'ECDSA-SHA224', family: 'ec', kind: 'ecdsa', hash: 'sha224',
    keyKind: 'ec',
    xml: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224',
    spec: 'RFC 9231 section 2.3.6',
    engine: {
      xml: {
        family: 'ecdsa',
        hash: 'sha224',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA224',
        weak: false,
        sha1: false
      }
    } },
  { id: 'DSA-SHA256', family: 'dsa', kind: 'dsa', hash: 'sha256',
    keyKind: 'dsa',
    xml: 'http://www.w3.org/2009/xmldsig11#dsa-sha256',
    spec: 'XML Signature Syntax and Processing 1.1',
    engine: {
      xml: {
        family: 'dsa',
        hash: 'sha256',
        keyTypes: ['dsa'],
        label: 'DSA-SHA256 (XMLDSig 1.1)',
        weak: false,
        sha1: false
      }
    } },
  { id: 'RSA-RIPEMD160', family: 'rsa', kind: 'rsa-pkcs1', hash: 'ripemd160',
    keyKind: 'rsa', weak: true,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160',
    spec: 'RFC 9231 section 2.3.5',
    engine: {
      xml: {
        family: 'rsa',
        hash: 'ripemd160',
        keyTypes: ['rsa'],
        label: 'RSA-RIPEMD160',
        weak: true,
        sha1: false
      }
    } },
  { id: 'RSA-PSS-RIPEMD160', family: 'rsa', kind: 'rsa-pss', hash: 'ripemd160',
    keyKind: 'rsa', weak: true,
    xml: 'http://www.w3.org/2007/05/xmldsig-more#ripemd160-rsa-MGF1',
    spec: 'RFC 9231 section 2.3.10',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'ripemd160',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS RIPEMD160 with MGF1',
        weak: true,
        sha1: false
      }
    } },
  { id: 'ECDSA-RIPEMD160', family: 'ec', kind: 'ecdsa', hash: 'ripemd160',
    keyKind: 'ec', weak: true,
    xml: 'http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160',
    spec: 'RFC 9231 section 2.3.6',
    engine: {
      xml: {
        family: 'ecdsa',
        hash: 'ripemd160',
        keyTypes: ['ec'],
        label: 'ECDSA-RIPEMD160',
        weak: true,
        sha1: false
      }
    } },
  { id: 'RS1', family: 'rsa', kind: 'rsa-pkcs1', hash: 'sha1', keyKind: 'rsa',
    weak: true, sha1: true,
    cose: -65535,
    xml: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    pki: 'sha1-rsa',
    oid: '1.2.840.113549.1.1.5',
    spec:
      'RFC 8812 section 2 (MUST NOT); XML Signature Syntax and Processing ' +
      '1.1; RFC 5280',
    engine: {
      cose: {
        name: 'RS1',
        family: 'rsa-pkcs1',
        hash: 'sha1',
        kty: 'RSA',
        insecure: true
      },
      xml: {
        family: 'rsa',
        hash: 'sha1',
        keyTypes: ['rsa'],
        label: 'RSA-SHA1',
        weak: true,
        sha1: true
      }
    } },
  { id: 'RSA-PSS-SHA1', family: 'rsa', kind: 'rsa-pss', hash: 'sha1',
    keyKind: 'rsa', weak: true, sha1: true,
    xml: 'http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1',
    spec: 'RFC 9231 section 2.3.10',
    engine: {
      xml: {
        family: 'rsa-pss',
        hash: 'sha1',
        keyTypes: ['rsa', 'rsa-pss'],
        label: 'RSASSA-PSS SHA1 with MGF1',
        weak: true,
        sha1: true
      }
    } },
  { id: 'ECDSA-SHA1', family: 'ec', kind: 'ecdsa', hash: 'sha1', keyKind: 'ec',
    weak: true, sha1: true,
    xml: 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1',
    pki: 'sha1-ecdsa',
    oid: '1.2.840.10045.4.1',
    spec: 'RFC 9231 section 2.3.6; RFC 5758',
    engine: {
      xml: {
        family: 'ecdsa',
        hash: 'sha1',
        keyTypes: ['ec'],
        label: 'ECDSA-SHA1',
        weak: true,
        sha1: true
      }
    } },
  { id: 'DSA-SHA1', family: 'dsa', kind: 'dsa', hash: 'sha1', keyKind: 'dsa',
    weak: true, sha1: true,
    xml: 'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
    spec: 'XML Signature Syntax and Processing 1.1',
    engine: {
      xml: {
        family: 'dsa',
        hash: 'sha1',
        keyTypes: ['dsa'],
        label: 'DSA-SHA1',
        weak: true,
        sha1: true
      }
    } },
  { id: 'HMAC-SHA1', family: 'hmac', kind: 'hmac', hash: 'sha1',
    keyKind: 'secret', weak: true, sha1: true,
    xml: 'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
    spec: 'XML Signature Syntax and Processing 1.1',
    engine: {
      xml: {
        family: 'hmac',
        hash: 'sha1',
        keyTypes: ['secret'],
        label: 'HMAC-SHA1 (a Kerberos token\'s session key)',
        weak: true,
        sha1: true
      }
    } },
  { id: 'rsaEncryption', family: 'rsa', kind: 'rsa-pkcs1', hash: null,
    keyKind: 'rsa',
    cms: '1.2.840.113549.1.1.1',
    spec: 'RFC 8017; RFC 5652',
    engine: { cms: { key: 'rsa', digest: null, label: 'RSA PKCS #1 v1.5' } } },
  { id: 'mldsa44-jcs-2024', family: 'pq', kind: 'ml-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    di: 'mldsa44-jcs-2024',
    spec: 'W3C Quantum-Resistant Cryptosuites v1.0' },
  { id: 'slhdsa128-jcs-2024', family: 'pq', kind: 'slh-dsa', hash: null,
    keyKind: 'akp', pqc: 'pq',
    di: 'slhdsa128-jcs-2024',
    spec: 'W3C Quantum-Resistant Cryptosuites v1.0' },
  { id: 'ecdsa-rdfc-2019', family: 'ec', kind: 'ecdsa', hash: null,
    keyKind: 'ec',
    di: 'ecdsa-rdfc-2019',
    spec: 'W3C Data Integrity ECDSA Cryptosuites v1.0' },
  { id: 'ecdsa-jcs-2019', family: 'ec', kind: 'ecdsa', hash: null,
    keyKind: 'ec',
    di: 'ecdsa-jcs-2019',
    spec: 'W3C Data Integrity ECDSA Cryptosuites v1.0' },
  { id: 'ecdsa-sd-2023', family: 'ec', kind: 'ecdsa', hash: null, keyKind: 'ec',
    di: 'ecdsa-sd-2023',
    spec: 'W3C Data Integrity ECDSA Cryptosuites v1.0' },
  { id: 'eddsa-rdfc-2022', family: 'okp', kind: 'eddsa', hash: null,
    keyKind: 'okp',
    di: 'eddsa-rdfc-2022',
    spec: 'W3C Data Integrity EdDSA Cryptosuites v1.0' },
  { id: 'eddsa-jcs-2022', family: 'okp', kind: 'eddsa', hash: null,
    keyKind: 'okp',
    di: 'eddsa-jcs-2022',
    spec: 'W3C Data Integrity EdDSA Cryptosuites v1.0' },
  { id: 'Ed25519Signature2020', family: 'okp', kind: 'eddsa', hash: null,
    keyKind: 'okp',
    di: 'Ed25519Signature2020',
    spec: 'W3C Ed25519Signature2020 (legacy, zcap)' },
  { id: 'bbs-2023', family: 'bbs', kind: 'bbs', hash: null,
    keyKind: 'bls12-381',
    di: 'bbs-2023',
    spec: 'W3C Data Integrity BBS Cryptosuites v1.0' }
];

// Today's order, per surface and per consumer.
const RECORDED = {
  jose: ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384',
         'PS512', 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA', 'ML-DSA-44',
         'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128s', 'SLH-DSA-SHAKE-128s',
         'ML-DSA-44-ES256', 'ML-DSA-65-ES256', 'ML-DSA-87-ES384',
         'ML-DSA-44-Ed25519', 'ML-DSA-65-Ed25519', 'ML-DSA-87-Ed448'],
  cose: [-7, -35, -36, -8, -257, -258, -259, -37, -38, -39, -48, -49, -50, -9,
         -51, -52, -47, -19, -53, -65535],
  'cose.status': [-7, -35, -36, -8, -47, -37, -38, -39, -257, -258, -259, -48,
                  -49, -50],
  'cose.mdoc': [-7, -9, -35, -51, -36, -52, -8, -19, -53, -48, -49, -50],
  xml: ['http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224',
        'http://www.w3.org/2007/05/xmldsig-more#rsa-sha224',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
        'http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160',
        'http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#ripemd160-rsa-MGF1',
        'http://www.w3.org/2007/05/xmldsig-more#rsa-pss',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
        'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
        'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-224',
        'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256',
        'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-384',
        'http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-512',
        'http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160',
        'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519',
        'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448',
        'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
        'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
        'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256',
        'http://www.w3.org/2001/04/xmldsig-more#hmac-sha384',
        'http://www.w3.org/2001/04/xmldsig-more#hmac-sha512',
        'http://www.w3.org/2009/xmldsig11#dsa-sha256',
        'http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44',
        'http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65',
        'http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-128s',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-128f',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-192s',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-192f',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-256s',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-sha2-256f',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-128s',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-128f',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-192s',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-192f',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-256s',
        'http://www.w3.org/2026/08/xmldsig-more#slh-dsa-shake-256f'],
  x509: ['sha256-rsa', 'sha384-rsa', 'sha512-rsa', 'sha256-rsapss',
         'sha384-rsapss', 'sha512-rsapss', 'sha1-rsa', 'sha256-ecdsa',
         'sha384-ecdsa', 'sha512-ecdsa', 'sha1-ecdsa', 'ed25519', 'ml-dsa-44',
         'ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128s', 'slh-dsa-sha2-128f',
         'slh-dsa-sha2-192s', 'slh-dsa-sha2-192f', 'slh-dsa-sha2-256s',
         'slh-dsa-sha2-256f', 'slh-dsa-shake-128s', 'slh-dsa-shake-128f',
         'slh-dsa-shake-192s', 'slh-dsa-shake-192f', 'slh-dsa-shake-256s',
         'slh-dsa-shake-256f', 'mldsa44-rsa2048-pss-sha256',
         'mldsa44-rsa2048-pkcs15-sha256', 'mldsa44-ed25519-sha512',
         'mldsa44-ecdsa-p256-sha256', 'mldsa65-rsa3072-pss-sha512',
         'mldsa65-rsa3072-pkcs15-sha512', 'mldsa65-rsa4096-pss-sha512',
         'mldsa65-rsa4096-pkcs15-sha512', 'mldsa65-ecdsa-p256-sha512',
         'mldsa65-ecdsa-p384-sha512', 'mldsa65-ed25519-sha512',
         'mldsa87-ecdsa-p384-sha512', 'mldsa87-ed448-shake256',
         'mldsa87-rsa3072-pss-sha512', 'mldsa87-rsa4096-pss-sha512',
         'mldsa87-ecdsa-p521-sha512'],
  httpsig: ['rsa-pss-sha512', 'rsa-v1_5-sha256', 'hmac-sha256',
            'ecdsa-p256-sha256', 'ecdsa-p384-sha384', 'ed25519'],
  cms: ['1.2.840.113549.1.1.1', '1.2.840.113549.1.1.11',
        '1.2.840.113549.1.1.12', '1.2.840.113549.1.1.13', '1.2.840.10045.4.3.2',
        '1.2.840.10045.4.3.3', '1.2.840.10045.4.3.4'],
  dkim: ['rsa-sha256', 'ed25519-sha256'],
  tls: ['mldsa65', 'mldsa87', 'mldsa44', 'ecdsa_secp256r1_sha256',
        'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'ed25519', 'ed448',
        'rsa_pss_pss_sha256', 'rsa_pss_pss_sha384', 'rsa_pss_pss_sha512',
        'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512',
        'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512'],
  di: ['ecdsa-rdfc-2019', 'ecdsa-jcs-2019', 'ecdsa-sd-2023', 'eddsa-rdfc-2022',
       'eddsa-jcs-2022', 'mldsa44-jcs-2024', 'slhdsa128-jcs-2024', 'bbs-2023',
       'Ed25519Signature2020']
};

// XML methods known and refused, and the digests, which are a separate list.
const XML_REFUSED = {
  'http://www.w3.org/2001/04/xmldsig-more#rsa-md5':
    'MD5 is broken and RFC 9231 says it MUST NOT be used',
  'http://www.w3.org/2001/04/xmldsig-more#hmac-md5':
    'MD5 is broken and RFC 9231 says it MUST NOT be used',
  'http://www.w3.org/2007/05/xmldsig-more#md2-rsa-MGF1':
    'MD2 and MD5 are broken',
  'http://www.w3.org/2007/05/xmldsig-more#md5-rsa-MGF1':
    'MD2 and MD5 are broken',
  'http://www.w3.org/2007/05/xmldsig-more#rsa-whirlpool':
    'Whirlpool and RIPEMD-128 are not in node\'s OpenSSL default provider',
  'http://www.w3.org/2007/05/xmldsig-more#ecdsa-whirlpool':
    'Whirlpool and RIPEMD-128 are not in node\'s OpenSSL default provider',
  'http://www.w3.org/2007/05/xmldsig-more#whirlpool-rsa-MGF1':
    'Whirlpool and RIPEMD-128 are not in node\'s OpenSSL default provider',
  'http://www.w3.org/2007/05/xmldsig-more#ripemd128-rsa-MGF1':
    'Whirlpool and RIPEMD-128 are not in node\'s OpenSSL default provider',
  'http://www.w3.org/2001/04/xmldsig-more#esign-sha1':
    'ESIGN has no implementation in OpenSSL',
  'http://www.w3.org/2001/04/xmldsig-more#esign-sha224':
    'ESIGN has no implementation in OpenSSL',
  'http://www.w3.org/2001/04/xmldsig-more#esign-sha256':
    'ESIGN has no implementation in OpenSSL',
  'http://www.w3.org/2001/04/xmldsig-more#esign-sha384':
    'ESIGN has no implementation in OpenSSL',
  'http://www.w3.org/2001/04/xmldsig-more#esign-sha512':
    'ESIGN has no implementation in OpenSSL',
  'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519ph':
    'node verifies pure EdDSA only, not the pre-hashed or context variants',
  'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519ctx':
    'node verifies pure EdDSA only, not the pre-hashed or context variants',
  'http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448ph':
    'node verifies pure EdDSA only, not the pre-hashed or context variants',
  'http://www.w3.org/2026/08/xmldsig-more#hss-lms':
    'HSS/LMS is a stateful hash-based scheme and OpenSSL 3.5 (node 24) has ' +
    'no verifier for it'
};
const XML_DIGESTS = {
  'http://www.w3.org/2000/09/xmldsig#sha1': {
    hash: 'sha1',
    label: 'SHA-1',
    weak: true,
    sha1: true
  },
  'http://www.w3.org/2001/04/xmldsig-more#sha224': {
    hash: 'sha224',
    label: 'SHA-224',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2001/04/xmlenc#sha256': {
    hash: 'sha256',
    label: 'SHA-256',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2001/04/xmldsig-more#sha384': {
    hash: 'sha384',
    label: 'SHA-384',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2001/04/xmlenc#sha512': {
    hash: 'sha512',
    label: 'SHA-512',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2007/05/xmldsig-more#sha3-224': {
    hash: 'sha3-224',
    label: 'SHA3-224',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2007/05/xmldsig-more#sha3-256': {
    hash: 'sha3-256',
    label: 'SHA3-256',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2007/05/xmldsig-more#sha3-384': {
    hash: 'sha3-384',
    label: 'SHA3-384',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2007/05/xmldsig-more#sha3-512': {
    hash: 'sha3-512',
    label: 'SHA3-512',
    weak: false,
    sha1: false
  },
  'http://www.w3.org/2001/04/xmlenc#ripemd160': {
    hash: 'ripemd160',
    label: 'RIPEMD-160',
    weak: true,
    sha1: false
  }
};
const XML_DIGESTS_REFUSED = {
  'http://www.w3.org/2001/04/xmldsig-more#md5': 'MD5 is broken',
  'http://www.w3.org/2007/05/xmldsig-more#whirlpool':
    'Whirlpool is not in node\'s OpenSSL default provider'
};

const CLASSICAL_KEY_ALGORITHMS = ['rsa-2048', 'rsa-3072', 'rsa-4096', 'ec-p256',
                                  'ec-p384', 'ec-p521', 'ed25519'];
const KEM_KEY_ALGORITHMS = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024'];

// ---------------------------------------------------------------------------
// THE ROWS MADE UNIFORM, AND THE INDEX. Run once, at load.
// ---------------------------------------------------------------------------
const BY_ID = new Map();
const BY_SPELLING = {};
const BY_OID = new Map();

function indexRows() {
  log.debug("Entering indexRows().");
  SURFACES.forEach(function (surface) {
    BY_SPELLING[surface] = new Map();
  });
  ROWS.forEach(function (row) {
    row.pqc = row.pqc || null;
    row.weak = row.weak === true;
    row.sha1 = row.sha1 === true;
    row.aliases = row.aliases || {};
    row.engine = row.engine || {};
    row.x509 = row.pki || null;
    delete row.pki;
    row.oid = row.oid || null;
    // RFC 9421 section 3.3.7: every JWS algorithm is an HTTP signature
    // algorithm under its JWS name, beside any name of its own in section 3.3.
    if (row.jose && row.httpsig) {
      row.aliases.httpsig = [row.jose];
    } else if (row.jose) {
      row.httpsig = row.jose;
    }
    SURFACES.forEach(function (surface) {
      if (row[surface] === undefined) {
        row[surface] = null;
      }
      if (row[surface] !== null) {
        BY_SPELLING[surface].set(String(row[surface]), row);
      }
      (row.aliases[surface] || []).forEach(function (alias) {
        BY_SPELLING[surface].set(String(alias), row);
      });
    });
    BY_ID.set(row.id, row);
    if (row.oid) {
      BY_OID.set(row.oid, (BY_OID.get(row.oid) || []).concat([row]));
    }
  });
  log.debug("Leaving indexRows(). " + ROWS.length + " rows.");
}
indexRows();

// A copy, so that no caller can change what another reads. These tables are
// plain data, so JSON keeps everything they hold.
function copyOf(value) {
  log.debug("Entering copyOf().");
  log.debug("Leaving copyOf().");
  return JSON.parse(JSON.stringify(value));
}

// ---------------------------------------------------------------------------
// THE LOOKUPS. byId(), bySpelling(), spelling() and their neighbours are a HOT
// PATH, asked per signature once #1368's policy reads them, so they carry no
// Entering/Leaving pair, which would drown the log.
// ---------------------------------------------------------------------------
/**
 * Returns a row by its canonical name.
 *
 * @param id - the row's `id`
 * @returns the row, or null
 */
function byId(id) {
  return BY_ID.get(String(id)) || null;
}

/**
 * Returns the row a surface's spelling names, an alias included.
 *
 * @param surface - one of `SURFACES`
 * @param value - the spelling; a COSE identifier may be a number or a string
 * @returns the row, or null
 */
function bySpelling(surface, value) {
  const index = BY_SPELLING[surface];
  return (index && index.get(String(value))) || null;
}

/**
 * Returns a row's primary spelling on a surface.
 *
 * @param id - the row's `id`
 * @param surface - one of `SURFACES`
 * @returns the spelling, or null where the row has none there
 */
function spelling(id, surface) {
  const row = byId(id);
  return row ? row[surface] : null;
}

/**
 * Returns the rows an X.509 signature algorithm OID may name. Several, for
 * RSASSA-PSS, whose hash is in the parameters and not the OID.
 *
 * @param oid - a dotted object identifier
 * @returns the rows, possibly none
 */
function byOid(oid) {
  return BY_OID.get(String(oid)) || [];
}

/**
 * Lists the rows that have a spelling on a surface, in PREFERENCE order.
 *
 * @param surface - one of `SURFACES`
 * @returns the rows
 */
function on(surface) {
  log.debug("Entering on(). " + surface);
  const rows = ROWS.filter(function (row) {
    return row[surface] !== null && row[surface] !== undefined;
  });
  log.debug("Leaving on(). " + rows.length);
  return rows;
}

/**
 * Lists a surface's or consumer's spellings in the order it uses TODAY, which
 * is what an empty setting means.
 *
 * @param name - a key of `RECORDED`, such as `jose` or `cose.mdoc`
 * @returns a new array of spellings
 */
function recorded(name) {
  log.debug("Entering recorded(). " + name);
  log.debug("Leaving recorded().");
  return (RECORDED[name] || []).slice();
}

// ---------------------------------------------------------------------------
// THE VIEWS. One per table this file replaced, in that table's shape. Each is
// read once, when its module loads.
// ---------------------------------------------------------------------------
/**
 * The JWS table, in `crypto.js`'s `JWS_ALGS` shape.
 *
 * @param constants - node's `crypto.constants`, which `padding` names a member
 *   of
 * @returns JOSE `alg` to its engine row
 */
function joseTable(constants) {
  log.debug("Entering joseTable().");
  const table = {};
  RECORDED.jose.forEach(function (alg) {
    const entry = copyOf(bySpelling('jose', alg).engine.jose);
    if (entry.padding) {
      entry.padding = constants[entry.padding];
    }
    table[alg] = entry;
  });
  log.debug("Leaving joseTable().");
  return table;
}

/**
 * Lists JOSE names in today's order, narrowed by a test of the row.
 *
 * @param keep - given a row, whether to list it; every row where absent
 * @returns the names
 */
function joseNames(keep) {
  log.debug("Entering joseNames().");
  const names = RECORDED.jose.filter(function (alg) {
    return !keep || keep(bySpelling('jose', alg));
  });
  log.debug("Leaving joseNames(). " + names.length);
  return names;
}

/** @returns the asymmetric JOSE names: never a MAC, in today's order */
function asymmetricJoseNames() {
  log.debug("Entering asymmetricJoseNames().");
  log.debug("Leaving asymmetricJoseNames().");
  return joseNames(function (row) {
    return row.family !== 'hmac';
  });
}

/** @returns the post-quantum and composite JOSE names, in today's order */
function postQuantumJoseNames() {
  log.debug("Entering postQuantumJoseNames().");
  log.debug("Leaving postQuantumJoseNames().");
  return joseNames(function (row) {
    return row.pqc !== null;
  });
}

/** @returns the asymmetric classical JOSE names, in today's order */
function classicalAsymmetricJoseNames() {
  log.debug("Entering classicalAsymmetricJoseNames().");
  log.debug("Leaving classicalAsymmetricJoseNames().");
  return joseNames(function (row) {
    return row.family !== 'hmac' && row.pqc === null;
  });
}

/** @returns the COSE table, in `crypto.js`'s `COSE_SIGNATURE_ALGS` shape */
function coseTable() {
  log.debug("Entering coseTable().");
  const table = {};
  RECORDED.cose.forEach(function (id) {
    table[String(id)] = copyOf(bySpelling('cose', id).engine.cose);
  });
  log.debug("Leaving coseTable().");
  return table;
}

/** @returns COSE identifier to name, in `webauthn.js`'s `COSE_ALGS` shape */
function coseNames() {
  log.debug("Entering coseNames().");
  const table = {};
  RECORDED.cose.forEach(function (id) {
    table[String(id)] = bySpelling('cose', id).id;
  });
  log.debug("Leaving coseNames().");
  return table;
}

/** @returns the COSE identifiers of the broken algorithms */
function insecureCoseIds() {
  log.debug("Entering insecureCoseIds().");
  const ids = RECORDED.cose.filter(function (id) {
    return bySpelling('cose', id).engine.cose.insecure === true;
  });
  log.debug("Leaving insecureCoseIds().");
  return ids;
}

/**
 * One consumer's COSE identifiers, in the order it uses them.
 *
 * @param consumer - `cose.mdoc` or `cose.status`
 * @returns the identifiers
 */
function coseIds(consumer) {
  log.debug("Entering coseIds(). " + consumer);
  log.debug("Leaving coseIds().");
  return recorded(consumer);
}

/**
 * One consumer's COSE identifiers keyed by name, in the order it uses them.
 *
 * @param consumer - `cose.mdoc` or `cose.status`
 * @returns name to identifier
 */
function coseIdsByName(consumer) {
  log.debug("Entering coseIdsByName(). " + consumer);
  const table = {};
  recorded(consumer).forEach(function (id) {
    table[bySpelling('cose', id).id] = id;
  });
  log.debug("Leaving coseIdsByName().");
  return table;
}

/** @returns `crypto.js`'s `XML_SIGNATURE_METHODS`: URI to its engine row */
function xmlSignatureMethods() {
  log.debug("Entering xmlSignatureMethods().");
  const table = {};
  RECORDED.xml.forEach(function (uri) {
    table[uri] = copyOf(bySpelling('xml', uri).engine.xml);
  });
  log.debug("Leaving xmlSignatureMethods().");
  return table;
}

/** @returns the XML SignatureMethods known and refused: URI to the reason */
function xmlSignaturesRefused() {
  log.debug("Entering xmlSignaturesRefused().");
  log.debug("Leaving xmlSignaturesRefused().");
  return copyOf(XML_REFUSED);
}

/** @returns the XML DigestMethods verified: URI to `{ hash, label, weak, sha1 }` */
function xmlDigestMethods() {
  log.debug("Entering xmlDigestMethods().");
  log.debug("Leaving xmlDigestMethods().");
  return copyOf(XML_DIGESTS);
}

/** @returns the XML DigestMethods known and refused: URI to the reason */
function xmlDigestsRefused() {
  log.debug("Entering xmlDigestsRefused().");
  log.debug("Leaving xmlDigestsRefused().");
  return copyOf(XML_DIGESTS_REFUSED);
}

/**
 * RFC 9421 section 3.3's own names, in `HTTP_SIGNATURE_ALGORITHMS`' shape. The
 * JWS names of section 3.3.7 are added by `crypto.js`, which derives their
 * shape from `JWS_ALGS`.
 *
 * @returns name to its engine row
 */
function httpSignatureAlgorithms() {
  log.debug("Entering httpSignatureAlgorithms().");
  const table = {};
  RECORDED.httpsig.forEach(function (name) {
    table[name] = copyOf(bySpelling('httpsig', name).engine.httpsig);
  });
  log.debug("Leaving httpSignatureAlgorithms().");
  return table;
}

/** @returns the CMS signature OIDs PKINIT verifies, to their engine rows */
function cmsSignatures() {
  log.debug("Entering cmsSignatures().");
  const table = {};
  RECORDED.cms.forEach(function (oid) {
    table[oid] = copyOf(bySpelling('cms', oid).engine.cms);
  });
  log.debug("Leaving cmsSignatures().");
  return table;
}

/** @returns the DKIM algorithms this service signs with */
function dkimAlgorithms() {
  log.debug("Entering dkimAlgorithms().");
  log.debug("Leaving dkimAlgorithms().");
  return recorded('dkim');
}

/** @returns the ML-DSA parameter sets' PKI ids to their OIDs */
function mlDsaOids() {
  log.debug("Entering mlDsaOids().");
  const table = {};
  RECORDED.x509.forEach(function (pkiId) {
    const row = bySpelling('x509', pkiId);
    if (row.kind === 'ml-dsa') {
      table[pkiId] = row.oid;
    }
  });
  log.debug("Leaving mlDsaOids().");
  return table;
}

/** @returns the PKI signature ids, in `x509.js`'s `SIG_ALG_ORDER` */
function pkiSignatureAlgorithms() {
  log.debug("Entering pkiSignatureAlgorithms().");
  log.debug("Leaving pkiSignatureAlgorithms().");
  return recorded('x509');
}

/**
 * The PKI key ids: the classical keys, every post-quantum signature key, then
 * the KEMs, which sign nothing and so have no row.
 *
 * @returns the ids
 */
function pkiKeyAlgorithms() {
  log.debug("Entering pkiKeyAlgorithms().");
  const postQuantum = RECORDED.x509.filter(function (pkiId) {
    return bySpelling('x509', pkiId).pqc !== null;
  });
  log.debug("Leaving pkiKeyAlgorithms().");
  return CLASSICAL_KEY_ALGORITHMS.concat(postQuantum, KEM_KEY_ALGORITHMS);
}

module.exports = {
  SURFACES: SURFACES,
  ROWS: ROWS,
  RAW_SIGNATURE_FAMILIES: RAW_SIGNATURE_FAMILIES,
  byId: byId,
  bySpelling: bySpelling,
  spelling: spelling,
  byOid: byOid,
  on: on,
  recorded: recorded,
  joseTable: joseTable,
  joseNames: joseNames,
  asymmetricJoseNames: asymmetricJoseNames,
  postQuantumJoseNames: postQuantumJoseNames,
  classicalAsymmetricJoseNames: classicalAsymmetricJoseNames,
  coseTable: coseTable,
  coseNames: coseNames,
  insecureCoseIds: insecureCoseIds,
  coseIds: coseIds,
  coseIdsByName: coseIdsByName,
  xmlSignatureMethods: xmlSignatureMethods,
  xmlSignaturesRefused: xmlSignaturesRefused,
  xmlDigestMethods: xmlDigestMethods,
  xmlDigestsRefused: xmlDigestsRefused,
  httpSignatureAlgorithms: httpSignatureAlgorithms,
  cmsSignatures: cmsSignatures,
  dkimAlgorithms: dkimAlgorithms,
  mlDsaOids: mlDsaOids,
  pkiSignatureAlgorithms: pkiSignatureAlgorithms,
  pkiKeyAlgorithms: pkiKeyAlgorithms
};
