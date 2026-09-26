'use strict';
//
// File: vc_data_integrity.ts
//
// ---------------------------------------------------------------------------
// W3C VERIFIABLE CREDENTIAL DATA INTEGRITY 1.0 PROOFS OVER JSON (JCS), FOR THE
// HOLDER'S PROOF ON A VERIFIABLE PRESENTATION (#38 follow-ups, 2026-09-17).
//
// An `ldp_vc` credential this issuer mints carries a bbs-2023 proof, and a
// derived bbs-2023 proof has NO HOLDER KEY: anybody who holds the base
// credential can derive one. That is fine at the bar door and it is not a
// sign-in. OpenID4VP 1.0 Appendix B.1.3.2.5 says what a presentation of an
// `ldp_vc` proves freshness and audience with: a Data Integrity proof ON THE
// PRESENTATION, whose `challenge` MUST be the request's `nonce` and whose
// `domain` MUST be the Client Identifier — or, over the Digital Credentials
// API, the Origin prefixed with `origin:` (Appendix A.4). This file verifies
// that proof, and signs one for a test to present.
//
// FOUR CRYPTOSUITES, ALL OF THEM THE JCS KIND, AND WHY JCS:
//
//   ecdsa-jcs-2019    W3C Data Integrity ECDSA Cryptosuites v1.0, section
//                     3.3 — P-256 with SHA-256, P-384 with SHA-384
//   eddsa-jcs-2022    W3C Data Integrity EdDSA Cryptosuites v1.0, section
//                     3.3 — Ed25519
//   mldsa44-jcs-2024  W3C Quantum-Resistant Cryptosuites v1.0 (First Public
//                     Working Draft, 16 June 2026), section 3.3 — ML-DSA-44
//                     with SHA-256. That draft defines no ML-DSA-65 or
//                     ML-DSA-87 suite ("a maximum security category of 2"),
//                     so neither is accepted here: a suite name nobody
//                     registered would be this service inventing one.
//   slhdsa128-jcs-2024
//                     the same draft, section 3.4 — SLH-DSA-SHA2-128s with
//                     SHA-256 ("a maximum security category of 1"; its Table
//                     7). Added 2026-09-22 for the GNAP zcap token (#43); the
//                     draft's FALCON-512 and SQIsign-I suites are not here,
//                     because their multicodec codes are, in the draft's own
//                     words, "preliminary and not currently registered" and
//                     this service holds no key for either.
//
// The RDFC variants canonicalize the presentation as an RDF dataset, which
// means a JSON-LD processor and a document loader for whatever `@context` a
// wallet names — a fetch this service does not make for a request somebody
// else wrote (the root `CLAUDE.md`'s *Dial a URL a CALLER supplied*). JCS
// canonicalizes the JSON as it is, needs no context resolved, and is what
// every one of the three specifications offers beside RDFC for exactly this
// reason. A presentation's holder proof is signed by the wallet over a
// document the wallet built; nothing is gained by reading it as a graph.
//
// THE ALGORITHM, identical in shape in all three (the suite decides the hash,
// the signature and the multibase):
//
//   proofConfig    the proof without `proofValue`. When the proof carries an
//                  `@context`, the secured document's `@context` MUST start
//                  with it and the unsecured document takes it (the specs'
//                  verify step 5); when it carries none, the document's own
//                  `@context` is put on the configuration, which is what the
//                  create step 2 of the two EC suites strongly advises and
//                  what the quantum-resistant draft requires (its 3.1.2).
//   hashData       H(JCS(proofConfig)) || H(JCS(unsecured document)), H being
//                  SHA-384 for P-384 and SHA-256 everywhere else.
//   proofValue     multibase: base58-btc (`z`) for the ECDSA and EdDSA
//                  suites, base64url (`u`) for the ML-DSA one — the draft
//                  says base64url, and its test vector is `u…`.
//
// **A PROOF WITH NO `@context` IS TRIED TWICE, and only for the two EC
// suites.** Their create step 2 is advised rather than required and the
// EdDSA specification records that some implementers skip it, so a proof
// signed without the context on its configuration is tried that way too.
// Both readings are the same key's signature over the same document; the
// second accepts nothing the first would have refused on any ground but
// interoperability.
//
// ---------------------------------------------------------------------------
// WHAT `verifyProof()` REFUSES, each as a check of its own so the page that
// prints the result can say which rule was broken — the Verifier's habit
// (`vc_verifier.ts`, `vpCheck()`):
//
//   type, cryptosuite (supported, and in the caller's list), proofPurpose,
//   challenge, domain (a string, or an ordered set containing the expected
//   value — Data Integrity 1.0 allows both), created (present, a valid
//   dateTime, not in the future beyond the clock allowance, not older than
//   `maxAgeS` when one is given), expires (not passed, when present), the
//   verification method (resolvable, a key of the kind the suite signs
//   with), the holder (the method's controller IS the presentation's
//   `holder` when one is named), the proof value (the right multibase and
//   the right length), the context prefix, and the signature.
//
// **`expectedChallenge` AND `expectedDomain` ARE REQUIRED ARGUMENTS.** Left
// undefined, the check FAILS rather than passing by default: the one caller
// this file was written for is a sign-in, and a verifier that quietly
// skipped freshness because an argument was forgotten would be the defect
// this file exists to close. `null` says, on purpose, that the value is not
// asked for (an issuer's `assertionMethod` proof has no challenge).
//
// **A PROOF SET** (`proof` as an array, Data Integrity 1.0 section 4.2) is
// verified by choosing ONE member: the first whose purpose and challenge are
// the expected ones, else the first whose purpose is, else the first. The
// other members are not verified — a presentation needs one holder proof
// that answers THIS request, and a set member made for another request is
// not a reason to refuse the one that was. Every member is removed from the
// unsecured document, as the specification's proof-set verification does. A
// member naming `previousProof` (a proof CHAIN) is refused: nothing here
// would verify the chain it depends on.
//
// **THE VERIFICATION METHODS ARE `did:jwk` AND `did:key` ONLY**, both
// resolved from the identifier itself with no network. `did:jwk` is what
// `vc_issuer.ts` binds an `ldp_vc` credential to; `did:key` with a Multikey
// is what the three specifications' own examples use (P-256 `0x1200`, P-384
// `0x1201`, Ed25519 `0xed`, ML-DSA-44 `0x1210`, SLH-DSA-SHA2-128s
// `0x1220`). A method a resolver would
// have to FETCH is refused, for the reason JCS was chosen above.
//
// **NO NPM PACKAGE FOR JCS OR BASE58, THOUGH BOTH ARE IN `node_modules`.**
// `canonicalize` and `base58-universal` arrive there only as dependencies of
// the JSON-LD libraries, `package.json` names neither, and
// `base58-universal` is an ES module this CommonJS file could load only
// through node's newer `require(esm)`. RFC 8785 is twenty lines over
// `JSON.stringify` (whose string and number serialisation the RFC adopts
// verbatim) and base58 is thirty; a dependency that could vanish in the next
// lockfile refresh is worse than either.
//
// A LIBRARY (rule 3): it registers no route and requires only `common/`
// leaves (`helpers` for the logger, `crypto` for the clock allowance,
// `pq_jose` for ML-DSA), so any module in this directory can require it
// without a cycle. ML-DSA goes through `pq_jose`'s asynchronous pair, so a
// verification happens in the worker pool where one is running.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import pqJose = require('../common/pq_jose');
import InstanceSlot = require('../common/instance_slot');
// The closed JSON-LD loader and RDFC-1.0 (#195, #196). A library that
// requires only `jsonld` and `common/` leaves.
import vcJsonLd = require('./vc_jsonld');
// ecdsa-sd-2023's base and derived proofs (#196). A library that requires
// `vc_jsonld.ts`, `vc_status_codec.ts` and `common/` leaves — never this one.
import vcEcdsaSd = require('./vc_ecdsa_sd');

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

interface Suite {
  id: string;
  kind: 'ec' | 'ed25519' | 'pq';
  multibase: 'z' | 'u';
  spec: string;
  pqAlg?: string;
  // How the document is made into bytes: RFC 8785 JSON, or RDFC-1.0 N-Quads
  // (#195, #196).
  canon: 'jcs' | 'rdfc';
  // ecdsa-sd-2023 (#196): a base proof to sign, a derived proof to verify,
  // both `vc_ecdsa_sd.ts`'s.
  sd?: boolean;
}

interface VcDataIntegrityDeps {
  log: typeof helpers.log;
  pqSignAsync: typeof pqJose.signAsync;
  pqVerifyAsync: typeof pqJose.verifyAsync;
  clockSkewS: () => number;
  // RDFC-1.0 over the closed loader (`vc_jsonld.ts`, #195/#196).
  canonize: (document: any) => Promise<string>;
  stsCrypto: typeof stsCrypto;
  // The ambient realm's key set, for `realmKeyFor()` (#194).
  stsKeysFor: () => any;
  sd: typeof vcEcdsaSd;
}

const SUITES: Record<string, Suite> = {
  'ecdsa-jcs-2019': {
    id: 'ecdsa-jcs-2019', kind: 'ec', multibase: 'z', canon: 'jcs',
    spec: 'W3C Data Integrity ECDSA Cryptosuites v1.0, section 3.3' },
  'eddsa-jcs-2022': {
    id: 'eddsa-jcs-2022', kind: 'ed25519', multibase: 'z', canon: 'jcs',
    spec: 'W3C Data Integrity EdDSA Cryptosuites v1.0, section 3.3' },
  'mldsa44-jcs-2024': {
    id: 'mldsa44-jcs-2024', kind: 'pq', multibase: 'u', canon: 'jcs',
    pqAlg: 'ML-DSA-44',
    spec: 'W3C Quantum-Resistant Cryptosuites v1.0 (FPWD), section 3.3' },
  'slhdsa128-jcs-2024': {
    id: 'slhdsa128-jcs-2024', kind: 'pq', multibase: 'u', canon: 'jcs',
    pqAlg: 'SLH-DSA-SHA2-128s',
    spec: 'W3C Quantum-Resistant Cryptosuites v1.0 (FPWD), section 3.4' },
  // #195, #196: the RDFC suites, over `vc_jsonld.ts`'s closed loader.
  'ecdsa-rdfc-2019': {
    id: 'ecdsa-rdfc-2019', kind: 'ec', multibase: 'z', canon: 'rdfc',
    spec: 'W3C Data Integrity ECDSA Cryptosuites v1.0, section 3.2' },
  'eddsa-rdfc-2022': {
    id: 'eddsa-rdfc-2022', kind: 'ed25519', multibase: 'z', canon: 'rdfc',
    spec: 'W3C Data Integrity EdDSA Cryptosuites v1.0, section 3.2' },
  'ecdsa-sd-2023': {
    id: 'ecdsa-sd-2023', kind: 'ec', multibase: 'u', canon: 'rdfc', sd: true,
    spec: 'W3C Data Integrity ECDSA Cryptosuites v1.0, section 3.6' }
};

const SUPPORTED_CRYPTOSUITES = Object.keys(SUITES);

// The EC curves ecdsa-jcs-2019 defines, with the hash each is signed under
// and the length of a raw r||s signature.
const EC_CURVES: Record<string, { hash: string; sigBytes: number;
                                  oid: string; pointBytes: number }> = {
  'P-256': { hash: 'sha256', sigBytes: 64, oid: '06082a8648ce3d030107',
             pointBytes: 32 },
  'P-384': { hash: 'sha384', sigBytes: 96, oid: '06052b81040022',
             pointBytes: 48 }
};

// The post-quantum keys' sizes — FIPS 204 table 2 for ML-DSA-44, FIPS 205
// table 2 for SLH-DSA-SHA2-128s, both restated in the draft's Tables 4 and 6
// — and their Multikey prefixes (its Table 1). A public key or a signature of
// any other length is not one, whatever it decodes to.
const PQ_KEYS: Record<string, { pub: number; sig: number;
                                prefix: number[]; suite: string }> = {
  'ML-DSA-44': { pub: 1312, sig: 2420, prefix: [0x90, 0x24],
                 suite: 'mldsa44-jcs-2024' },
  'SLH-DSA-SHA2-128s': { pub: 32, sig: 7856, prefix: [0xa0, 0x24],
                         suite: 'slhdsa128-jcs-2024' }
};

// The Multikey prefixes (the varint of each multicodec code) this file
// resolves a `did:key` by.
const MULTIKEY_PREFIXES: { prefix: number[]; kind: string }[] = [
  { prefix: [0x80, 0x24], kind: 'P-256' },
  { prefix: [0x81, 0x24], kind: 'P-384' },
  { prefix: [0xed, 0x01], kind: 'Ed25519' },
  { prefix: [0x90, 0x24], kind: 'ML-DSA-44' },
  { prefix: [0xa0, 0x24], kind: 'SLH-DSA-SHA2-128s' }
];

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// XML Schema 1.1 dateTime, which is what `created` and `expires` are.
const DATE_TIME = new RegExp('^-?\\d{4,}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:' +
  '\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})?$');

// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), before the
// 32 raw bytes.
const ED25519_SPKI_PREFIX = '302a300506032b6570032100';

class VcDataIntegrity {
  static readonly SUPPORTED_CRYPTOSUITES = SUPPORTED_CRYPTOSUITES;
  static readonly SUITES = SUITES;

  constructor(private readonly deps: VcDataIntegrityDeps) {
    deps.log.debug("Entering VcDataIntegrity.constructor().");
    deps.log.debug("Leaving VcDataIntegrity.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): VcDataIntegrityDeps {
    helpers.log.debug("Entering VcDataIntegrity.defaultDeps().");
    helpers.log.debug("Leaving VcDataIntegrity.defaultDeps().");
    return {
      log: helpers.log,
      pqSignAsync: pqJose.signAsync,
      pqVerifyAsync: pqJose.verifyAsync,
      clockSkewS: function clockSkewS(): number {
        helpers.log.debug("Entering clockSkewS().");
        helpers.log.debug("Leaving clockSkewS().");
        return Number(stsCrypto.tokenClockSkew()) || 0;
      },
      canonize: function canonize(document: any): Promise<string> {
        helpers.log.debug("Entering canonize().");
        helpers.log.debug("Leaving canonize().");
        return vcJsonLd.canonize(document);
      },
      stsCrypto: stsCrypto,
      stsKeysFor: function stsKeysFor(): any {
        helpers.log.debug("Entering stsKeysFor().");
        helpers.log.debug("Leaving stsKeysFor().");
        return helpers.stsKeysFor();
      },
      sd: vcEcdsaSd
    };
  }

  // -------------------------------------------------------------------------
  // RFC 8785, THE JSON CANONICALIZATION SCHEME. Object members sorted by
  // their UTF-16 code units — which is what `Array.prototype.sort()` compares
  // — and every primitive serialised by `JSON.stringify()`, whose string
  // escaping and number formatting the RFC adopts (its sections 3.2.2.2 and
  // 3.2.2.3). A value JSON cannot carry is an error rather than a silent
  // omission: a signature over a document this function had quietly changed
  // would verify something nobody signed.
  // -------------------------------------------------------------------------
  jcs(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.jcs().");
    if (value === null || typeof value === 'boolean' ||
        typeof value === 'string') {
      log.debug("Leaving VcDataIntegrity.jcs(). A primitive.");
      return JSON.stringify(value);
    }
    if (typeof value === 'number') {
      if (!isFinite(value)) {
        log.debug("Leaving VcDataIntegrity.jcs(). Not a JSON number.");
        throw new Error('JCS: ' + value + ' is not a JSON number.');
      }
      log.debug("Leaving VcDataIntegrity.jcs(). A number.");
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      const items = value.map((item) => {
        return item === undefined ? 'null' : this.jcs(item);
      });
      log.debug("Leaving VcDataIntegrity.jcs(). An array.");
      return '[' + items.join(',') + ']';
    }
    if (typeof value === 'object') {
      const record = value as Record<string, unknown>;
      const members = Object.keys(record).filter((key) => {
        return record[key] !== undefined;
      }).sort().map((key) => {
        return JSON.stringify(key) + ':' + this.jcs(record[key]);
      });
      log.debug("Leaving VcDataIntegrity.jcs(). An object.");
      return '{' + members.join(',') + '}';
    }
    log.debug("Leaving VcDataIntegrity.jcs(). Not JSON.");
    throw new Error('JCS: a ' + typeof value + ' is not a JSON value.');
  }

  // -------------------------------------------------------------------------
  // BASE58-BTC, the alphabet Bitcoin defined and multibase names `z`.
  // Leading zero bytes are leading '1's; the rest is a big-endian integer.
  // -------------------------------------------------------------------------
  base58Encode(bytes: Uint8Array): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.base58Encode().");
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) {
      zeros += 1;
    }
    let n = BigInt('0x' + (Buffer.from(bytes).toString('hex') || '0'));
    let out = '';
    while (n > BigInt(0)) {
      const rem = Number(n % BigInt(58));
      n = n / BigInt(58);
      out = BASE58_ALPHABET.charAt(rem) + out;
    }
    log.debug("Leaving VcDataIntegrity.base58Encode().");
    return '1'.repeat(zeros) + out;
  }

  base58Decode(text: string): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.base58Decode().");
    let zeros = 0;
    while (zeros < text.length && text.charAt(zeros) === '1') {
      zeros += 1;
    }
    let n = BigInt(0);
    for (let i = zeros; i < text.length; i++) {
      const digit = BASE58_ALPHABET.indexOf(text.charAt(i));
      if (digit < 0) {
        log.debug("Leaving VcDataIntegrity.base58Decode(). Not base58.");
        throw new Error('"' + text.charAt(i) + '" is not a base58-btc ' +
                        'character.');
      }
      n = n * BigInt(58) + BigInt(digit);
    }
    let hex = n > BigInt(0) ? n.toString(16) : '';
    if (hex.length % 2) {
      hex = '0' + hex;
    }
    log.debug("Leaving VcDataIntegrity.base58Decode().");
    return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, 'hex')]);
  }

  // A multibase value in one of the two bases this file reads, refused
  // unless it is the one the caller expects.
  multibaseDecode(value: unknown, expected: 'z' | 'u'): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.multibaseDecode(). expected=" +
              expected);
    const text = typeof value === 'string' ? value : '';
    if (!text || text.charAt(0) !== expected) {
      log.debug("Leaving VcDataIntegrity.multibaseDecode(). Wrong base.");
      throw new Error('expected a multibase ' +
        (expected === 'z' ? 'base58-btc ("z")' : 'base64url ("u")') +
        ' value; this one starts "' + text.charAt(0) + '".');
    }
    const body = text.slice(1);
    if (expected === 'u') {
      if (!/^[A-Za-z0-9_-]*$/.test(body)) {
        log.debug("Leaving VcDataIntegrity.multibaseDecode(). Not " +
                  "base64url.");
        throw new Error('the multibase value is not base64url.');
      }
      log.debug("Leaving VcDataIntegrity.multibaseDecode(). base64url.");
      return Buffer.from(body, 'base64url');
    }
    log.debug("Leaving VcDataIntegrity.multibaseDecode(). base58-btc.");
    return this.base58Decode(body);
  }

  // -------------------------------------------------------------------------
  // KEYS AND IDENTIFIERS.
  // -------------------------------------------------------------------------

  // The public members of a JWK, in a fixed order with `kty` first — what a
  // did:jwk is made of (the did:jwk method encodes the JWK as JSON; a
  // private member in one would publish the key).
  publicJwkOf(jwk: any): any {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.publicJwkOf(). kty=" +
              (jwk && jwk.kty));
    const members: Record<string, string[]> = {
      EC: ['crv', 'x', 'y'], OKP: ['crv', 'x'], RSA: ['n', 'e'],
      AKP: ['alg', 'pub']
    };
    const wanted = jwk && members[jwk.kty];
    if (!wanted) {
      log.debug("Leaving VcDataIntegrity.publicJwkOf(). Unknown kty.");
      throw new Error('a JWK of kty "' + (jwk && jwk.kty) + '" has no ' +
                      'public form this file knows.');
    }
    const out: Record<string, string> = { kty: jwk.kty };
    wanted.forEach(function (name) {
      if (typeof jwk[name] !== 'string' || !jwk[name]) {
        throw new Error('a ' + jwk.kty + ' JWK needs "' + name + '".');
      }
      out[name] = jwk[name];
    });
    log.debug("Leaving VcDataIntegrity.publicJwkOf().");
    return out;
  }

  didJwkOf(jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.didJwkOf().");
    const did = 'did:jwk:' + Buffer.from(
      JSON.stringify(this.publicJwkOf(jwk)), 'utf8').toString('base64url');
    log.debug("Leaving VcDataIntegrity.didJwkOf().");
    return did;
  }

  jwkOfDidJwk(did: unknown): any {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.jwkOfDidJwk().");
    const text = String(did || '').split('#')[0];
    const match = /^did:jwk:([A-Za-z0-9_-]+)$/.exec(text);
    if (!match) {
      log.debug("Leaving VcDataIntegrity.jwkOfDidJwk(). Not a did:jwk.");
      throw new Error('"' + text + '" is not a did:jwk.');
    }
    let jwk: any = null;
    try {
      jwk = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'));
    } catch (e) {
      log.debug("Caught in VcDataIntegrity.jwkOfDidJwk(): " +
                ((e && e.message) || e));
      log.debug("Leaving VcDataIntegrity.jwkOfDidJwk(). Not JSON.");
      throw new Error('the did:jwk does not decode to a JSON JWK: ' +
                      ((e && e.message) || e));
    }
    if (!jwk || typeof jwk !== 'object' || 'd' in jwk || 'priv' in jwk) {
      log.debug("Leaving VcDataIntegrity.jwkOfDidJwk(). Unusable JWK.");
      throw new Error('the did:jwk is not a public JWK (it is not an ' +
                      'object, or it carries a private member).');
    }
    log.debug("Leaving VcDataIntegrity.jwkOfDidJwk().");
    return this.publicJwkOf(jwk);
  }

  // A DER SubjectPublicKeyInfo for an EC point in either form, which OpenSSL
  // decompresses on import — so a compressed Multikey needs no curve
  // arithmetic here.
  private ecSpki(curve: string, point: Buffer): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.ecSpki(). curve=" + curve);
    const der = function der(tag: number, body: Buffer): Buffer {
      log.debug("Entering der().");
      const len = body.length < 0x80 ? Buffer.from([body.length])
        : Buffer.from([0x81, body.length]);
      log.debug("Leaving der().");
      return Buffer.concat([Buffer.from([tag]), len, body]);
    };
    const algorithm = der(0x30, Buffer.concat([
      Buffer.from('06072a8648ce3d0201', 'hex'),
      Buffer.from(EC_CURVES[curve].oid, 'hex')]));
    const bits = der(0x03, Buffer.concat([Buffer.from([0]), point]));
    log.debug("Leaving VcDataIntegrity.ecSpki().");
    return der(0x30, Buffer.concat([algorithm, bits]));
  }

  // The did:key of a public JWK, with the Multikey each suite's examples use.
  didKeyOf(jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.didKeyOf().");
    log.debug("Leaving VcDataIntegrity.didKeyOf().");
    return 'did:key:' + this.multikeyOf(jwk);
  }

  // -------------------------------------------------------------------------
  // THE MULTIKEY `publicKeyMultibase` OF A PUBLIC JWK (Controlled Identifiers
  // v1.0's Multikey): the multicodec prefix and the raw key, base58-btc for
  // the EC and EdDSA suites (EdDSA Cryptosuites v1.0 section 2.1.1: "MUST
  // start with the base-58-btc prefix") and base64url for the post-quantum
  // ones (the Quantum-Resistant draft's section 2.1.1: "MUST then be encoded
  // using the base-64-url alphabet"). What a `did:key` is made of, and what a
  // controller document publishes a Multikey verification method with.
  // -------------------------------------------------------------------------
  multikeyOf(jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.multikeyOf().");
    const pub = this.publicJwkOf(jwk);
    let prefix: number[] = null;
    let raw: Buffer = null;
    let base: 'z' | 'u' = 'z';
    if (pub.kty === 'EC' && EC_CURVES[pub.crv]) {
      const x = Buffer.from(pub.x, 'base64url');
      const y = Buffer.from(pub.y, 'base64url');
      raw = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 3 : 2]), x]);
      prefix = pub.crv === 'P-256' ? [0x80, 0x24] : [0x81, 0x24];
    } else if (pub.kty === 'OKP' && pub.crv === 'Ed25519') {
      raw = Buffer.from(pub.x, 'base64url');
      prefix = [0xed, 0x01];
    } else if (pub.kty === 'AKP' && PQ_KEYS[pub.alg]) {
      raw = Buffer.from(pub.pub, 'base64url');
      prefix = PQ_KEYS[pub.alg].prefix;
      base = 'u';
    } else {
      log.debug("Leaving VcDataIntegrity.multikeyOf(). No Multikey.");
      throw new Error('no Multikey this file knows for this key.');
    }
    const bytes = Buffer.concat([Buffer.from(prefix), raw]);
    const encoded = base === 'z' ? 'z' + this.base58Encode(bytes)
                                 : 'u' + bytes.toString('base64url');
    log.debug("Leaving VcDataIntegrity.multikeyOf().");
    return encoded;
  }

  jwkOfMultikey(multikey: string): any {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.jwkOfMultikey().");
    const base = multikey.charAt(0);
    if (base !== 'z' && base !== 'u') {
      log.debug("Leaving VcDataIntegrity.jwkOfMultikey(). Unknown base.");
      throw new Error('a did:key Multikey must be base58-btc ("z") or ' +
                      'base64url ("u").');
    }
    const bytes = this.multibaseDecode(multikey, base);
    const found = MULTIKEY_PREFIXES.filter(function (one) {
      return bytes.length > one.prefix.length &&
        one.prefix.every(function (b, i) { return bytes[i] === b; });
    })[0];
    if (!found) {
      log.debug("Leaving VcDataIntegrity.jwkOfMultikey(). Unknown codec.");
      throw new Error('the did:key names a key type this file does not ' +
                      'resolve (P-256, P-384, Ed25519, ML-DSA-44 and ' +
                      'SLH-DSA-SHA2-128s only).');
    }
    const raw = bytes.subarray(found.prefix.length);
    let jwk: any;
    if (found.kind === 'Ed25519') {
      if (raw.length !== 32) {
        throw new Error('an Ed25519 Multikey is 32 bytes.');
      }
      jwk = { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') };
    } else if (PQ_KEYS[found.kind]) {
      if (raw.length !== PQ_KEYS[found.kind].pub) {
        throw new Error('an ' + found.kind + ' Multikey is ' +
                        PQ_KEYS[found.kind].pub + ' bytes.');
      }
      jwk = { kty: 'AKP', alg: found.kind, pub: raw.toString('base64url') };
    } else {
      const size = EC_CURVES[found.kind].pointBytes;
      if (raw.length !== size + 1 && raw.length !== 2 * size + 1) {
        throw new Error('a ' + found.kind + ' Multikey is a ' +
                        (size + 1) + '-byte compressed point.');
      }
      const key = crypto.createPublicKey({
        key: this.ecSpki(found.kind, raw), format: 'der', type: 'spki' });
      const exported: any = key.export({ format: 'jwk' });
      jwk = { kty: 'EC', crv: found.kind, x: exported.x, y: exported.y };
    }
    log.debug("Leaving VcDataIntegrity.jwkOfMultikey(). " + found.kind);
    return jwk;
  }

  // -------------------------------------------------------------------------
  // A VERIFICATION METHOD, RESOLVED FROM ITS OWN IDENTIFIER. Throws, with the
  // reason, for anything this file will not resolve; `verifyProof()` turns
  // that into a failed check.
  // -------------------------------------------------------------------------
  resolveVerificationMethod(vm: unknown): { jwk: any; controller: string } {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.resolveVerificationMethod().");
    const text = typeof vm === 'string' ? vm :
      (vm && typeof vm === 'object' && typeof (vm as any).id === 'string'
        ? (vm as any).id : '');
    const hash = text.indexOf('#');
    const did = hash >= 0 ? text.slice(0, hash) : text;
    const fragment = hash >= 0 ? text.slice(hash + 1) : '';
    if (/^did:jwk:/.test(did)) {
      if (hash >= 0 && fragment !== '0') {
        log.debug("Leaving VcDataIntegrity.resolveVerificationMethod(). " +
                  "Bad did:jwk fragment.");
        throw new Error('a did:jwk has one verification method, "#0"; ' +
                        'this names "#' + fragment + '".');
      }
      const jwk = this.jwkOfDidJwk(did);
      log.debug("Leaving VcDataIntegrity.resolveVerificationMethod(). " +
                "did:jwk.");
      return { jwk: jwk, controller: did };
    }
    const keyMatch = /^did:key:([zu][A-Za-z0-9_-]+)$/.exec(did);
    if (keyMatch) {
      if (hash >= 0 && fragment !== keyMatch[1]) {
        log.debug("Leaving VcDataIntegrity.resolveVerificationMethod(). " +
                  "Bad did:key fragment.");
        throw new Error('a did:key\'s one verification method is ' +
                        'fragment "#' + keyMatch[1] + '".');
      }
      const jwk = this.jwkOfMultikey(keyMatch[1]);
      log.debug("Leaving VcDataIntegrity.resolveVerificationMethod(). " +
                "did:key.");
      return { jwk: jwk, controller: did };
    }
    log.debug("Leaving VcDataIntegrity.resolveVerificationMethod(). " +
              "Unresolvable.");
    throw new Error('the verification method "' + text + '" is neither a ' +
      'did:jwk nor a did:key; this Verifier resolves no identifier it would ' +
      'have to fetch.');
  }

  // ---------------------------------------------------------------------------
  // THE REALM'S OWN KEY OF A CURVE, AS A did:key (#194-#197): the Ed25519,
  // P-256 or P-384 member of the ambient realm's key set — made at run time,
  // sealed in product, agreed across every process of the realm — named by
  // the did:key of its public half. What this service signs a Data Integrity
  // proof with when it is the ISSUER (the VC-API adapter, `vc_api.ts`) and
  // what the JSON-LD form of its Bitstring Status List credentials is signed
  // with. A did:key rather than the realm's did:web because it resolves from
  // the identifier itself: nobody has to fetch anything to check it, which
  // is the property this file's own verifier holds every holder to.
  // Answers `{ privateKey, publicJwk, did, verificationMethod }`; throws
  // when the realm holds no such key, which is a defect in the key set.
  // ---------------------------------------------------------------------------
  realmKeyFor(curve: string): any {
    const { log, stsKeysFor } = this.deps;
    log.debug("Entering VcDataIntegrity.realmKeyFor(). " + curve);
    const alg = curve === 'Ed25519' ? 'EdDSA'
      : (curve === 'P-256' ? 'ES256' : (curve === 'P-384' ? 'ES384' : ''));
    const held = stsKeysFor() || {};
    const found = (held.extraKeys || []).filter(function (one: any) {
      return one && one.alg === alg && one.publicJwk &&
        (alg !== 'EdDSA' || one.publicJwk.crv === 'Ed25519');
    })[0];
    if (!alg || !found || !found.privateKey) {
      log.debug("Leaving VcDataIntegrity.realmKeyFor(). None.");
      throw new Error('this realm holds no ' + curve + ' signing key.');
    }
    const publicJwk = this.publicJwkOf(found.publicJwk);
    const multikey = this.multikeyOf(publicJwk);
    const did = 'did:key:' + multikey;
    log.debug("Leaving VcDataIntegrity.realmKeyFor().");
    return { privateKey: found.privateKey, publicJwk: publicJwk, did: did,
             verificationMethod: did + '#' + multikey,
             kid: found.publicJwk.kid };
  }

  // Which of the three suites a holder key signs with, or '' — and, for '',
  // the sentence that says why.
  cryptosuiteForJwk(jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.cryptosuiteForJwk().");
    const k = jwk || {};
    let suite = '';
    if (k.kty === 'EC' && EC_CURVES[k.crv]) {
      suite = 'ecdsa-jcs-2019';
    } else if (k.kty === 'OKP' && k.crv === 'Ed25519') {
      suite = 'eddsa-jcs-2022';
    } else if (k.kty === 'AKP' && PQ_KEYS[k.alg]) {
      suite = PQ_KEYS[k.alg].suite;
    }
    log.debug("Leaving VcDataIntegrity.cryptosuiteForJwk(). " +
              (suite || 'none'));
    return suite;
  }

  unsupportedReason(jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.unsupportedReason().");
    const k = jwk || {};
    let why = '';
    if (this.cryptosuiteForJwk(k)) {
      why = '';
    } else if (k.kty === 'RSA') {
      why = 'no Data Integrity cryptosuite signs with RSA; an RSA holder ' +
            'key cannot make a holder proof on a presentation.';
    } else if (k.kty === 'EC') {
      why = 'ecdsa-jcs-2019 defines P-256 and P-384 only; ' +
            (k.crv || 'this curve') + ' has no Data Integrity cryptosuite.';
    } else if (k.kty === 'OKP') {
      why = 'eddsa-jcs-2022 defines Ed25519 only; ' + (k.crv || 'this ' +
            'curve') + ' has no Data Integrity cryptosuite.';
    } else if (k.kty === 'AKP') {
      why = 'the W3C Quantum-Resistant Cryptosuites draft defines ' +
            'ML-DSA-44 (mldsa44-jcs-2024) and SLH-DSA-SHA2-128s ' +
            '(slhdsa128-jcs-2024) of the algorithms this service holds, so ' +
            (k.alg || 'this algorithm') + ' has none there; ML-DSA-65, ' +
            'ML-DSA-87, SLH-DSA-SHAKE-128s and the composites have none.';
    } else {
      why = 'a key of kty "' + (k.kty || '') + '" has no Data Integrity ' +
            'cryptosuite.';
    }
    log.debug("Leaving VcDataIntegrity.unsupportedReason().");
    return why;
  }

  // Is this key one the suite signs with? '' when it is, the reason when not.
  private keyMismatch(suite: Suite, jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.keyMismatch(). suite=" + suite.id);
    const actual = this.cryptosuiteForJwk(jwk);
    log.debug("Leaving VcDataIntegrity.keyMismatch().");
    // The JCS suite a key signs with names its KIND; the RDFC suite of the
    // same kind signs with the same keys (#195, #196).
    const actualSuite = SUITES[actual];
    if (suite.sd && !(jwk && jwk.kty === 'EC' && jwk.crv === 'P-256')) {
      return 'ecdsa-sd-2023 signs with a P-256 key (its derived proof ' +
        'encodes a 64-byte signature, section 3.5.8); this is ' +
        ((jwk && (jwk.crv || jwk.kty)) || 'another kind of key') + '.';
    }
    if (actualSuite && actualSuite.kind === suite.kind &&
        (actualSuite.pqAlg || '') === (suite.pqAlg || '')) {
      return '';
    }
    return 'the verification method is ' + ((jwk && jwk.kty) || '?') + ' ' +
      ((jwk && (jwk.crv || jwk.alg)) || '') + ', which ' + suite.id +
      ' does not sign with' + (actual ? ' (it is a ' + actual + ' key)' :
      '') + '.';
  }

  // The hash a suite applies, for a given key.
  private hashName(suite: Suite, jwk: any): string {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.hashName().");
    log.debug("Leaving VcDataIntegrity.hashName().");
    return suite.kind === 'ec' && jwk && jwk.crv === 'P-384' ? 'sha384'
                                                             : 'sha256';
  }

  // THE SAME FOR EITHER KIND OF SUITE (#195, #196): for an RDFC suite,
  // H(RDFC(proofConfig)) || H(RDFC(unsecuredDocument)), the proof
  // configuration carrying the document's `@context` (EdDSA and ECDSA
  // Cryptosuites v1.0, sections 3.2.4 and 3.2.5). Asynchronous, because the
  // JSON-LD processor is.
  async hashDataAsync(suite: Suite, jwk: any, proofConfig: any,
                      unsecured: any): Promise<Buffer> {
    const { log, canonize } = this.deps;
    log.debug("Entering VcDataIntegrity.hashDataAsync(). suite=" + suite.id);
    if (suite.canon !== 'rdfc') {
      log.debug("Leaving VcDataIntegrity.hashDataAsync(). JCS.");
      return this.hashData(suite, jwk, proofConfig, unsecured);
    }
    const hash = this.hashName(suite, jwk);
    const config = Object.assign({}, proofConfig);
    delete config.proofValue;
    if (unsecured && unsecured['@context'] !== undefined) {
      config['@context'] = unsecured['@context'];
    } else {
      delete config['@context'];
    }
    const canonicalConfig = await canonize(config);
    const canonicalDocument = await canonize(unsecured);
    const configHash = crypto.createHash(hash)
      .update(canonicalConfig, 'utf8').digest();
    const documentHash = crypto.createHash(hash)
      .update(canonicalDocument, 'utf8').digest();
    log.debug("Leaving VcDataIntegrity.hashDataAsync(). RDFC.");
    return Buffer.concat([configHash, documentHash]);
  }

  // hashData = H(JCS(proofConfig)) || H(JCS(unsecuredDocument)).
  hashData(suite: Suite, jwk: any, proofConfig: any,
           unsecured: any): Buffer {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.hashData(). suite=" + suite.id);
    const hash = this.hashName(suite, jwk);
    const configHash = crypto.createHash(hash)
      .update(this.jcs(proofConfig), 'utf8').digest();
    const documentHash = crypto.createHash(hash)
      .update(this.jcs(unsecured), 'utf8').digest();
    log.debug("Leaving VcDataIntegrity.hashData().");
    return Buffer.concat([configHash, documentHash]);
  }

  private signatureBytes(suite: Suite, jwk: any): number {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.signatureBytes().");
    log.debug("Leaving VcDataIntegrity.signatureBytes().");
    if (suite.kind === 'ec') {
      return EC_CURVES[jwk.crv] ? EC_CURVES[jwk.crv].sigBytes : 0;
    }
    return suite.kind === 'ed25519' ? 64 : PQ_KEYS[suite.pqAlg].sig;
  }

  private async signBytes(suite: Suite, privateKey: any, jwk: any,
                          data: Buffer): Promise<Buffer> {
    const { log, pqSignAsync } = this.deps;
    log.debug("Entering VcDataIntegrity.signBytes(). suite=" + suite.id);
    if (suite.kind === 'pq') {
      const priv = privateKey && typeof privateKey === 'object' &&
        typeof privateKey.priv === 'string'
        ? Buffer.from(privateKey.priv, 'base64url')
        : Buffer.from(privateKey);
      const sig = await pqSignAsync(suite.pqAlg, priv, data);
      log.debug("Leaving VcDataIntegrity.signBytes(). " + suite.pqAlg);
      return Buffer.from(sig);
    }
    const { stsCrypto } = this.deps;
    if (suite.kind === 'ed25519') {
      log.debug("Leaving VcDataIntegrity.signBytes(). Ed25519.");
      return stsCrypto.signRawSignature({ family: 'eddsa' }, privateKey,
                                        data);
    }
    log.debug("Leaving VcDataIntegrity.signBytes(). ECDSA.");
    return stsCrypto.signRawSignature({ family: 'ecdsa',
      hash: this.hashName(suite, jwk), encoding: 'p1363' }, privateKey, data);
  }

  private async verifyBytes(suite: Suite, jwk: any, data: Buffer,
                            signature: Buffer): Promise<boolean> {
    const { log, pqVerifyAsync } = this.deps;
    log.debug("Entering VcDataIntegrity.verifyBytes(). suite=" + suite.id);
    if (suite.kind === 'pq') {
      const ok = await pqVerifyAsync(suite.pqAlg,
        Buffer.from(jwk.pub, 'base64url'), data, signature);
      log.debug("Leaving VcDataIntegrity.verifyBytes(). " + suite.pqAlg +
                " " + ok);
      return !!ok;
    }
    const { stsCrypto } = this.deps;
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    if (suite.kind === 'ed25519') {
      const ok = await stsCrypto.verifyRawSignature({ family: 'eddsa' }, key,
                                                    data, signature);
      log.debug("Leaving VcDataIntegrity.verifyBytes(). Ed25519 " + ok);
      return ok;
    }
    const ok = await stsCrypto.verifyRawSignature({ family: 'ecdsa',
      hash: this.hashName(suite, jwk), encoding: 'p1363' }, key, data,
      signature);
    log.debug("Leaving VcDataIntegrity.verifyBytes(). ECDSA " + ok);
    return ok;
  }

  // -------------------------------------------------------------------------
  // SIGNING A PRESENTATION — for the tests, and for anything here that ever
  // has to present one. `options.publicJwk` is the holder's key;
  // `privateKey` is a node KeyObject or a private JWK (an AKP one carrying
  // RFC 9964's `priv` seed).
  // -------------------------------------------------------------------------
  async signPresentation(unsecuredVp: any, options: any): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.signPresentation().");
    log.debug("Leaving VcDataIntegrity.signPresentation().");
    return this.signDocument(unsecuredVp, options);
  }

  // -------------------------------------------------------------------------
  // SIGNING ANY DOCUMENT — the create-proof algorithm of the suite named or
  // implied by the key (EdDSA 3.3.1, ECDSA 3.3.1, Quantum-Resistant 3.3.1 and
  // 3.4.1). `signPresentation()` is this with a presentation's defaults.
  //
  // `options.proofMembers` are members the caller's PROOF PURPOSE puts on the
  // proof before it is signed — ZCAP-LD's `capabilityChain` (#43,
  // `gnap/token_zcap.ts`) — and they are covered by the signature like every
  // other proof option, because the proof configuration is the proof less
  // its `proofValue`. They may not override the members this function sets
  // (`type`, `cryptosuite`, `proofValue`, `@context`): a caller that could
  // would be signing a proof of some other suite under this suite's name.
  // -------------------------------------------------------------------------
  async signDocument(unsecured: any, options: any): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.signDocument().");
    const o = options || {};
    const publicJwk = this.publicJwkOf(o.publicJwk);
    const suiteId = o.cryptosuite || this.cryptosuiteForJwk(publicJwk);
    const suite = SUITES[suiteId];
    if (!suite) {
      log.debug("Leaving VcDataIntegrity.signDocument(). No suite.");
      throw new Error('no cryptosuite for this key: ' +
                      (this.unsupportedReason(publicJwk) || suiteId));
    }
    const mismatch = this.keyMismatch(suite, publicJwk);
    if (mismatch) {
      log.debug("Leaving VcDataIntegrity.signDocument(). Wrong key.");
      throw new Error(mismatch);
    }
    if (suite.sd) {
      const { sd } = this.deps;
      const existing = [].concat(unsecured && unsecured.proof !== undefined ?
                                 unsecured.proof : []);
      const based = await sd.createBaseProof(unsecured, {
        publicJwk: publicJwk, privateKey: o.privateKey,
        verificationMethod: o.verificationMethod ||
          (this.didJwkOf(publicJwk) + '#0'),
        mandatoryPointers: o.mandatoryPointers, created: o.created,
        proofPurpose: o.proofPurpose || 'assertionMethod' });
      if (existing.length) {
        based.proof = existing.concat([based.proof]);
      }
      log.debug("Leaving VcDataIntegrity.signDocument(). ecdsa-sd-2023.");
      return based;
    }
    const extra = o.proofMembers && typeof o.proofMembers === 'object'
      ? o.proofMembers : {};
    const reserved = ['type', 'cryptosuite', 'proofValue', '@context']
      .filter(function (name) {
        return Object.prototype.hasOwnProperty.call(extra, name);
      });
    if (reserved.length) {
      log.debug("Leaving VcDataIntegrity.signDocument(). Reserved member.");
      throw new Error('proofMembers may not set ' + reserved.join(', ') +
                      '; this function sets them.');
    }
    const document = Object.assign({}, unsecured || {});
    delete document.proof;
    const proof: any = {
      type: 'DataIntegrityProof',
      cryptosuite: suite.id,
      created: o.created || new Date().toISOString()
        .replace(/\.\d{3}Z$/, 'Z'),
      verificationMethod: o.verificationMethod ||
        (this.didJwkOf(publicJwk) + '#0'),
      proofPurpose: o.proofPurpose || 'authentication'
    };
    if (o.challenge !== undefined && o.challenge !== null) {
      proof.challenge = o.challenge;
    }
    if (o.domain !== undefined && o.domain !== null) {
      proof.domain = o.domain;
    }
    if (o.expires) {
      proof.expires = o.expires;
    }
    Object.keys(extra).forEach(function (name) {
      proof[name] = extra[name];
    });
    // Create step 2 of every JCS suite: the document's @context goes on the
    // proof, so a verifier can check the document still starts with it. An
    // RDFC suite puts it on the proof CONFIGURATION only (section 3.2.5),
    // which `hashDataAsync()` does; the proof it returns carries none.
    if (document['@context'] !== undefined && suite.canon === 'jcs') {
      proof['@context'] = document['@context'];
    }
    if (o.id !== undefined) {
      proof.id = o.id;
    }
    if (o.previousProof !== undefined) {
      proof.previousProof = o.previousProof;
    }
    // A proof SET or CHAIN (Data Integrity 1.0 section 4.2): the document
    // already secured is signed as it stands, with the earlier proofs a
    // chain names as its `proof` (section 4.3, "Add Proof Set/Chain").
    const existing = [].concat(unsecured && unsecured.proof !== undefined ?
                               unsecured.proof : []);
    const signedOver: any = Object.assign({}, document);
    if (o.previousProof !== undefined) {
      const wanted = [].concat(o.previousProof);
      const matching = existing.filter(function (p: any) {
        return p && wanted.indexOf(p.id) >= 0;
      });
      if (matching.length !== wanted.length) {
        log.debug("Leaving VcDataIntegrity.signDocument(). A previous " +
                  "proof is missing.");
        throw new Error('previousProof names a proof the document does ' +
                        'not carry.');
      }
      signedOver.proof = matching.length === 1 ? matching[0] : matching;
    }
    const data = await this.hashDataAsync(suite, publicJwk, proof,
                                          signedOver);
    const signature = await this.signBytes(suite, o.privateKey, publicJwk,
                                           data);
    proof.proofValue = suite.multibase === 'z'
      ? 'z' + this.base58Encode(signature)
      : 'u' + signature.toString('base64url');
    log.debug("Leaving VcDataIntegrity.signDocument(). " + suite.id);
    return Object.assign(document, { proof: existing.length
      ? existing.concat([proof]) : proof });
  }

  // The one member of a proof set this verification is about. See the
  // header for the order.
  private chooseProof(proof: any, options: any): any {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.chooseProof().");
    if (!Array.isArray(proof)) {
      log.debug("Leaving VcDataIntegrity.chooseProof(). Not a set.");
      return proof;
    }
    const purpose = options.expectedPurpose || 'authentication';
    const members = proof.filter(function (p) {
      return p && typeof p === 'object';
    });
    const exact = members.filter(function (p) {
      return p.proofPurpose === purpose &&
        p.challenge === options.expectedChallenge;
    })[0];
    const byPurpose = members.filter(function (p) {
      return p.proofPurpose === purpose;
    })[0];
    log.debug("Leaving VcDataIntegrity.chooseProof(). " + members.length +
              " member(s).");
    return exact || byPurpose || members[0] || null;
  }

  private dateCheck(value: unknown): number {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.dateCheck().");
    if (typeof value !== 'string' || !DATE_TIME.test(value)) {
      log.debug("Leaving VcDataIntegrity.dateCheck(). Not a dateTime.");
      return NaN;
    }
    log.debug("Leaving VcDataIntegrity.dateCheck().");
    return Date.parse(value);
  }

  // -------------------------------------------------------------------------
  // VERIFYING ONE. Never throws for a proof that is wrong — the answer is
  // `ok: false` and the check that failed. See the header for the list.
  // -------------------------------------------------------------------------
  async verifyProof(securedDocument: any, options: any): Promise<any> {
    const { log, clockSkewS } = this.deps;
    log.debug("Entering VcDataIntegrity.verifyProof().");
    const o = options || {};
    const checks: Check[] = [];
    const result: any = { ok: false, checks: checks, jwk: null,
                          verificationMethod: '', controller: '',
                          cryptosuite: '' };
    const check = function check(name: string, ok: unknown,
                                 detail: string): boolean {
      log.debug("Entering check(). " + name);
      checks.push({ name: name, ok: !!ok, detail: detail });
      log.debug("Leaving check(). " + (ok ? "OK" : "FAILED"));
      return !!ok;
    };
    const doc = securedDocument;
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      check('Document', false, 'a secured document is a JSON object.');
      log.debug("Leaving VcDataIntegrity.verifyProof(). Not an object.");
      return result;
    }
    // `onlyProof` names the member to verify (`verifyAllProofs()`, which
    // also sets `chain`: a member naming `previousProof` is then verified
    // over the document carrying the proofs it names, Data Integrity 1.0
    // section 4.4).
    const proof = o.onlyProof !== undefined ? o.onlyProof
                                            : this.chooseProof(doc.proof, o);
    if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
      check('Proof', false, 'the document carries no proof, or its proof ' +
            'is not a map.');
      log.debug("Leaving VcDataIntegrity.verifyProof(). No proof.");
      return result;
    }
    let chained: any[] = null;
    if (proof.previousProof !== undefined && o.chain) {
      const wanted = [].concat(proof.previousProof);
      const members = [].concat(doc.proof);
      chained = members.filter(function (p: any) {
        return p && typeof p === 'object' && p.id !== undefined &&
          wanted.indexOf(p.id) >= 0;
      });
      check('Proof', chained.length === wanted.length &&
            wanted.every(function (w: any) { return typeof w === 'string'; }),
            chained.length === wanted.length
              ? 'a proof chained to ' + wanted.join(', ') + '.'
              : 'previousProof names ' + JSON.stringify(proof.previousProof) +
                ', and the document carries no proof with that id.');
    } else {
      check('Proof', proof.previousProof === undefined, proof.previousProof
        ? 'the proof names previousProof — a proof chain, which this ' +
          'Verifier does not follow.'
        : (Array.isArray(doc.proof)
            ? 'one member of a proof set of ' + doc.proof.length + ' chosen.'
            : 'one proof.'));
    }

    // --- what the proof says about itself ---------------------------------
    check('Proof type', proof.type === 'DataIntegrityProof',
          'type is "' + proof.type + '"; a Data Integrity proof is ' +
          '"DataIntegrityProof".');
    const suite = SUITES[proof.cryptosuite];
    const allowed = Array.isArray(o.allowedCryptosuites)
      ? o.allowedCryptosuites : SUPPORTED_CRYPTOSUITES;
    result.cryptosuite = String(proof.cryptosuite || '');
    check('Cryptosuite', !!suite && allowed.indexOf(proof.cryptosuite) >= 0,
          'cryptosuite is "' + proof.cryptosuite + '"; this Verifier ' +
          'accepts ' + allowed.filter(function (s) {
            return !!SUITES[s];
          }).join(', ') + '.');
    const purpose = o.expectedPurpose || 'authentication';
    check('Proof purpose', proof.proofPurpose === purpose,
          'proofPurpose is "' + proof.proofPurpose + '"; this request ' +
          'needs "' + purpose + '".');
    if (o.expectedChallenge === undefined) {
      check('Challenge', false, 'the caller named no expected challenge, ' +
            'so freshness cannot be checked (null says it is not asked ' +
            'for).');
    } else if (o.expectedChallenge === null) {
      check('Challenge', true, 'not asked for.');
    } else {
      check('Challenge', proof.challenge === o.expectedChallenge,
            'challenge is "' + (proof.challenge === undefined ? '—' :
            proof.challenge) + '"; this request\'s nonce is "' +
            o.expectedChallenge + '".');
    }
    if (o.expectedDomain === undefined) {
      check('Domain', false, 'the caller named no expected domain, so the ' +
            'audience cannot be checked (null says it is not asked for).');
    } else if (o.expectedDomain === null) {
      check('Domain', true, 'not asked for.');
    } else {
      const domains = Array.isArray(proof.domain) ? proof.domain
        : (proof.domain === undefined ? [] : [proof.domain]);
      check('Domain', domains.indexOf(o.expectedDomain) >= 0,
            'domain is ' + JSON.stringify(proof.domain === undefined ?
            null : proof.domain) + '; this Verifier is "' +
            o.expectedDomain + '".');
    }
    const nowMs = typeof o.now === 'number' ? o.now : Date.now();
    const skewMs = Math.max(0, Number(o.clockSkewS !== undefined ?
      o.clockSkewS : clockSkewS()) || 0) * 1000;
    const created = this.dateCheck(proof.created);
    if (proof.created === undefined && o.createdRequired === false) {
      check('Created', true, 'no created, which a proof may omit.');
    } else if (isNaN(created)) {
      check('Created', false, 'created is ' + JSON.stringify(
        proof.created === undefined ? null : proof.created) + '; a holder ' +
        'proof must say when it was made, as an XML Schema dateTime.');
    } else if (created > nowMs + skewMs) {
      check('Created', false, 'created (' + proof.created + ') is in the ' +
            'future.');
    } else if (typeof o.maxAgeS === 'number' &&
               nowMs - created > o.maxAgeS * 1000 + skewMs) {
      check('Created', false, 'created (' + proof.created + ') is ' +
            Math.round((nowMs - created) / 1000) + 's ago; at most ' +
            o.maxAgeS + 's is accepted.');
    } else {
      check('Created', true, 'created ' + proof.created + '.');
    }
    if (proof.expires !== undefined) {
      const expires = this.dateCheck(proof.expires);
      check('Expires', !isNaN(expires) && expires + skewMs > nowMs,
            'expires is ' + JSON.stringify(proof.expires) + '.');
    }

    // --- the key ------------------------------------------------------------
    // A caller that publishes its OWN keys under an https identifier (the
    // GNAP zcap controller document, #43) passes `resolveVerificationMethod`,
    // which answers { jwk, controller } from what it holds or throws; nothing
    // is fetched either way. Without one, only did:jwk and did:key resolve.
    let resolved: { jwk: any; controller: string } = null;
    try {
      resolved = typeof o.resolveVerificationMethod === 'function'
        ? o.resolveVerificationMethod(proof.verificationMethod)
        : this.resolveVerificationMethod(proof.verificationMethod);
    } catch (e) {
      log.debug("Caught in VcDataIntegrity.verifyProof(): " +
                ((e && e.message) || e));
      check('Verification method', false, String((e && e.message) || e));
    }
    if (resolved) {
      result.jwk = resolved.jwk;
      result.controller = resolved.controller;
      result.verificationMethod = String(proof.verificationMethod);
      const mismatch = suite ? this.keyMismatch(suite, resolved.jwk) : '';
      check('Verification method', !mismatch, mismatch ||
            'resolves to a ' + resolved.jwk.kty + ' key (' +
            (resolved.jwk.crv || resolved.jwk.alg) + ').');
      const holder = typeof doc.holder === 'string' ? doc.holder
        : (doc.holder && typeof doc.holder.id === 'string' ?
           doc.holder.id : '');
      if (holder) {
        check('Holder', holder === resolved.controller,
              'the presentation\'s holder is "' + holder + '"; the proof ' +
              'was made by a key of "' + resolved.controller + '".');
      }
    }

    // --- the value and the context ------------------------------------------
    let signature: Buffer = null;
    if (suite) {
      try {
        signature = this.multibaseDecode(proof.proofValue, suite.multibase);
        const want = resolved && !suite.sd
          ? this.signatureBytes(suite, resolved.jwk) : 0;
        if (want && signature.length !== want) {
          check('Proof value', false, 'the signature is ' +
                signature.length + ' bytes; ' + suite.id + ' with this key ' +
                'makes ' + want + '.');
          signature = null;
        } else {
          check('Proof value', true, 'a ' + signature.length + '-byte ' +
                'signature.');
        }
      } catch (e) {
        log.debug("Caught in VcDataIntegrity.verifyProof(): " +
                  ((e && e.message) || e));
        check('Proof value', false, 'proofValue: ' +
              String((e && e.message) || e));
        signature = null;
      }
    }
    const unsecured = Object.assign({}, doc);
    delete unsecured.proof;
    if (chained && chained.length) {
      unsecured.proof = chained.length === 1 ? chained[0] : chained;
    }
    const config = Object.assign({}, proof);
    delete config.proofValue;
    const configs: any[] = [];
    if (suite && suite.canon === 'rdfc') {
      // RDFC: the configuration takes the document's @context whatever the
      // proof carried (`hashDataAsync()`); a proof that does carry one must
      // still be a prefix of the document's.
      if (config['@context'] !== undefined) {
        const proofContext = [].concat(config['@context']);
        const docContext = [].concat(doc['@context'] === undefined ? [] :
                                     doc['@context']);
        const prefixOk = proofContext.every(function (one, i) {
          return JSON.stringify(one) === JSON.stringify(docContext[i]);
        });
        check('Context', prefixOk, prefixOk
          ? 'the document\'s @context starts with the proof\'s.'
          : 'the document\'s @context does not start with the proof\'s ' +
            '@context, in order.');
      }
      configs.push(config);
    } else if (config['@context'] !== undefined) {
      const proofContext = [].concat(config['@context']);
      const docContext = [].concat(doc['@context'] === undefined ? [] :
                                   doc['@context']);
      const prefixOk = proofContext.every(function (one, i) {
        return JSON.stringify(one) === JSON.stringify(docContext[i]);
      });
      check('Context', prefixOk, prefixOk
        ? 'the document\'s @context starts with the proof\'s.'
        : 'the document\'s @context does not start with the proof\'s ' +
          '@context, in order.');
      unsecured['@context'] = config['@context'];
      configs.push(config);
    } else if (doc['@context'] !== undefined) {
      configs.push(Object.assign({}, config,
                                 { '@context': doc['@context'] }));
      if (suite && suite.kind !== 'pq') {
        configs.push(config);
      }
    } else {
      configs.push(config);
    }

    // --- the signature ------------------------------------------------------
    const ready = checks.every(function (c) { return c.ok; });
    if (!ready || !suite || !resolved || !signature) {
      check('Signature', false, 'not checked: an earlier check failed.');
      log.debug("Leaving VcDataIntegrity.verifyProof(). Refused before " +
                "the signature.");
      return result;
    }
    let verified = false;
    if (suite.sd) {
      // The derived proof over the document carrying only this proof.
      const { sd } = this.deps;
      const one = Object.assign({}, unsecured, { proof: proof });
      const answer = await sd.verifyDerivedProof(one, resolved.jwk);
      check('Signature', answer.ok, answer.detail);
      result.ok = checks.every(function (c) { return c.ok; });
      log.debug("Leaving VcDataIntegrity.verifyProof(). ecdsa-sd-2023 ok=" +
                result.ok);
      return result;
    }
    for (let i = 0; i < configs.length && !verified; i++) {
      try {
        verified = await this.verifyBytes(suite, resolved.jwk,
          await this.hashDataAsync(suite, resolved.jwk, configs[i],
                                   unsecured),
          signature);
      } catch (e) {
        log.debug("Caught in VcDataIntegrity.verifyProof(): " +
                  ((e && e.message) || e));
        check('Canonicalization', false, String((e && e.message) || e));
        verified = false;
      }
    }
    check('Signature', verified, verified
      ? 'verifies against the verification method\'s key (' + suite.id +
        ').'
      : 'does not verify against the verification method\'s key: the ' +
        'document or the proof configuration was not what was signed, or ' +
        'another key signed it.');
    result.ok = checks.every(function (c) { return c.ok; });
    log.debug("Leaving VcDataIntegrity.verifyProof(). ok=" + result.ok);
    return result;
  }

  // An ecdsa-sd-2023 derived proof from the base proof a document carries
  // (#196; `vc_ecdsa_sd.ts`, section 3.6.6).
  async deriveProof(securedDocument: any,
                    selectivePointers: string[]): Promise<any> {
    const { log, sd } = this.deps;
    log.debug("Entering VcDataIntegrity.deriveProof().");
    const out = await sd.deriveProof(securedDocument, selectivePointers);
    log.debug("Leaving VcDataIntegrity.deriveProof().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // EVERY PROOF ON A DOCUMENT (#194-#196): a proof set and its chains, each
  // member verified (Data Integrity 1.0 section 4.4, "Verify Proof Sets and
  // Chains"), where `verifyProof()` chooses ONE for a sign-in. Answers
  // `{ ok, results }`, one result per member in order; `ok` only when there
  // is at least one member and every one verified.
  // ---------------------------------------------------------------------------
  async verifyAllProofs(securedDocument: any, options: any): Promise<any> {
    const { log } = this.deps;
    log.debug("Entering VcDataIntegrity.verifyAllProofs().");
    const doc = securedDocument;
    if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
      log.debug("Leaving VcDataIntegrity.verifyAllProofs(). Not a map.");
      return { ok: false, results: [], reason: 'a secured document is a ' +
               'JSON object.' };
    }
    const members = doc.proof === undefined ? [] : [].concat(doc.proof);
    if (!members.length || doc.proof === null) {
      log.debug("Leaving VcDataIntegrity.verifyAllProofs(). No proof.");
      return { ok: false, results: [], reason: 'the document carries no ' +
               'proof.' };
    }
    const results: any[] = [];
    for (let i = 0; i < members.length; i++) {
      results.push(await this.verifyProof(doc, Object.assign({}, options,
        { onlyProof: members[i], chain: true })));
    }
    const ok = results.every(function (r) { return r.ok; });
    log.debug("Leaving VcDataIntegrity.verifyAllProofs(). " + ok + " (" +
              results.length + " member(s)).");
    return { ok: ok, results: results, reason: '' };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2) — `vc_issued.ts`'s
// arrangement: the exports are FACADES forwarding to the instance the root
// installs, and a process without the root builds a default at load.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcDataIntegrity>(
  'oid4vc/vc_data_integrity',
  () => new VcDataIntegrity(VcDataIntegrity.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading any module on the pattern
// does.
slot.buildNowUnlessDeferred();

export = {
  VcDataIntegrity: VcDataIntegrity,
  installInstance: (instance: VcDataIntegrity): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SUPPORTED_CRYPTOSUITES: VcDataIntegrity.SUPPORTED_CRYPTOSUITES,
  SUITES: VcDataIntegrity.SUITES,
  jcs: slot.forward('jcs'),
  base58Encode: slot.forward('base58Encode'),
  base58Decode: slot.forward('base58Decode'),
  multibaseDecode: slot.forward('multibaseDecode'),
  publicJwkOf: slot.forward('publicJwkOf'),
  didJwkOf: slot.forward('didJwkOf'),
  jwkOfDidJwk: slot.forward('jwkOfDidJwk'),
  didKeyOf: slot.forward('didKeyOf'),
  resolveVerificationMethod: slot.forward('resolveVerificationMethod'),
  cryptosuiteForJwk: slot.forward('cryptosuiteForJwk'),
  unsupportedReason: slot.forward('unsupportedReason'),
  hashData: slot.forward('hashData'),
  hashDataAsync: slot.forward('hashDataAsync'),
  jwkOfMultikey: slot.forward('jwkOfMultikey'),
  verifyAllProofs: slot.forward('verifyAllProofs'),
  realmKeyFor: slot.forward('realmKeyFor'),
  deriveProof: slot.forward('deriveProof'),
  signPresentation: slot.forward('signPresentation'),
  signDocument: slot.forward('signDocument'),
  multikeyOf: slot.forward('multikeyOf'),
  verifyProof: slot.forward('verifyProof')
};
