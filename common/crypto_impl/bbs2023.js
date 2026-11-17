// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// File: bbs2023.js
'use strict';
//
// ---------------------------------------------------------------------------
// THE BBS PRIMITIVES BEHIND THE `bbs-2023` CRYPTOSUITE, and the key's
// Multikey encoding (#1878, 2026-11-17).
//
// Until #1878 this file WAS the cryptosuite, and it was not W3C's: every
// canonical statement was a BBS message, the header was the proof options'
// N-Quads, and a presentation was an envelope of disclosed statements. Since
// then the cryptosuite is `oid4vc/vc_bbs.ts`, W3C Data Integrity BBS
// Cryptosuites v1.0 step for step, and this file holds what it rests on:
// Sign, Verify, ProofGen and ProofVerify (draft-irtf-cfrg-bbs-signatures,
// BLS12-381-SHA-256), the BLS12-381 G2 Multikey, the closed JSON-LD loader
// the issuer reads its identity context through, and — READ ONLY — the
// pre-1.1 private format, for the verifier's legacy envelope.
//
// THIS SERVICE'S OWN SINCE #663 (2026-11-02), not a copy of the parent
// project's file any more, on the same terms as `pqc.js` under #363: the
// identity context it signs against is this issuer's vocabulary, named on
// this issuer's own URL (`https://iyasec.io/contexts/identity/v1`), and a
// minted credential carries no other project's name. It is edited here and
// is not re-synced from the parent.
//
// The BBS protocol code is @digitalbazaar/bbs-signatures. BBS has several
// places where a signer and verifier can share a mistake, agree perfectly,
// and agree with nobody else, which is why `tests/vc_bbs2023.js` holds the
// cryptosuite to the W3C specification's own test vectors and to a second
// implementation of it (Digital Bazaar's bbs-2023-cryptosuite, test tooling
// only), not only to itself. Nothing here is vendored to or from the
// parent any more (rcbj, #663).
//
// The library is ESM-only and this service is CommonJS, so it is loaded with
// a dynamic import() the first time it is needed and then kept.
// ---------------------------------------------------------------------------

const bunyan = require('bunyan');
const jsonld = require('jsonld');
const path = require('path');
const fs = require('fs');

// A node consumer (the tests load this module directly) may have no
// CONFIG_FILE, so fall back to info rather than failing to load —
// `pqc.js`'s arrangement.
let logLevelProblem = null;
const log = bunyan.createLogger({
  name: 'bbs2023',
  level: (function () {
    try {
      return require(process.env.CONFIG_FILE).logLevel || 'info';
    } catch (e) {
      // No logger exists yet; reported on the line after it does.
      logLevelProblem = (e && e.message) || String(e);
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('Caught in bbs2023 log level: ' + logLevelProblem);
}

const CRYPTOSUITE = 'bbs-2023';
// The label the verifier reads the pre-1.1 envelope under (see the LEGACY
// section below): never `bbs-2023`, which is the W3C cryptosuite's.
const LEGACY_CRYPTOSUITE = 'iya-bbs-2023-legacy';
const PROOF_TYPE = 'DataIntegrityProof';
const IDENTITY_CONTEXT_URL = 'https://iyasec.io/contexts/identity/v1';

// The contexts ship beside this file and are read once, at require time. A
// missing one throws here, at start, rather than as every signature failing
// later looking like a crypto bug.
const CONTEXT_DIR = path.join(__dirname, 'contexts');

function loadContext(file) {
  log.debug('Entering loadContext().');
  const candidate = path.join(CONTEXT_DIR, file);
  if (!fs.existsSync(candidate)) {
    log.debug('Leaving loadContext(). Missing.');
    throw new Error('bbs-2023 needs the JSON-LD context ' + file +
      '; looked in ' + CONTEXT_DIR);
  }
  const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8'));
  log.debug('Leaving loadContext().');
  return parsed;
}

const CONTEXTS = {
  'https://www.w3.org/ns/credentials/v2': loadContext('credentials_v2.json'),
  'https://www.w3.org/2018/credentials/v1':
    loadContext('credentials_v1.json'),
  [IDENTITY_CONTEXT_URL]: loadContext('iya_identity_v1.json')
};

// A CLOSED loader: it fetches nothing, and a document naming a context this
// issuer does not ship is refused with the URL named.
function documentLoader(url) {
  log.debug('Entering documentLoader().');
  if (CONTEXTS[url]) {
    log.debug('Leaving documentLoader().');
    return Promise.resolve({ contextUrl: null, documentUrl: url,
                             document: CONTEXTS[url] });
  }
  log.debug('Leaving documentLoader(). Refused ' + url + '.');
  return Promise.reject(new Error(
    'this issuer will only handle documents using a context it ships: ' +
    Object.keys(CONTEXTS).join(', ') + '. Asked for: ' + url));
}

let bbsLib = null;

async function bbs() {
  log.debug('Entering bbs().');
  if (!bbsLib) {
    bbsLib = await import('@digitalbazaar/bbs-signatures');
  }
  log.debug('Leaving bbs().');
  return bbsLib;
}

async function ciphersuite() {
  log.debug('Entering ciphersuite().');
  const suite = (await bbs()).CIPHERSUITES.BLS12381_SHA256;
  log.debug('Leaving ciphersuite().');
  return suite;
}

// A hot path: called once per canonical statement of every credential, so
// no Entering/Leaving pair here — it would drown the log.
const te = (s) => new TextEncoder().encode(s);

function bytesToB64u(bytes) {
  log.debug('Entering bytesToB64u().');
  log.debug('Leaving bytesToB64u().');
  return Buffer.from(bytes).toString('base64url');
}

function b64uToBytes(s) {
  log.debug('Entering b64uToBytes().');
  log.debug('Leaving b64uToBytes().');
  return new Uint8Array(Buffer.from(String(s), 'base64url'));
}

// Multibase base64url ("u" prefix, per the Data Integrity multikey encoding).
//
// SEPARATE from b64uToBytes ON PURPOSE. b64uToBytes used to strip a leading
// "u" itself, and every caller ALSO stripped the multibase prefix before
// calling it — so whenever the base64url payload happened to begin with "u",
// a second character was eaten and the key came back one byte short. A
// BLS12-381 G2 key is 96 bytes; the failure produced 95, and every signature
// then failed to verify while looking like a crypto bug. It only bites for
// roughly one key in sixty-four, so it passed locally and failed in CI on the
// same code.
function multibaseToBytes(s) {
  log.debug('Entering multibaseToBytes().');
  const text = String(s || '');
  if (text.charAt(0) !== 'u') {
    log.debug('Leaving multibaseToBytes(). Not multibase base64url.');
    throw new Error('expected multibase base64url (a leading "u"), got: ' +
      text.slice(0, 12));
  }
  log.debug('Leaving multibaseToBytes().');
  return b64uToBytes(text.slice(1));
}

async function generateKeyPair() {
  log.debug('Entering generateKeyPair().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const { secretKey, publicKey } =
    await lib.generateKeyPair({ ciphersuite: suite });
  log.debug('Leaving generateKeyPair().');
  return { secretKey, publicKey };
}

// ---------------------------------------------------------------------------
// THE BBS PRIMITIVES (#1878): Sign, Verify, ProofGen and ProofVerify of
// draft-irtf-cfrg-bbs-signatures over BLS12-381-SHA-256, and nothing about a
// document. `oid4vc/vc_bbs.ts` is the cryptosuite — W3C Data Integrity BBS
// Cryptosuites v1.0, its base proof, its derived proof and their checks —
// and asks these through `common/crypto.js` (rule 3r). Each verifier answers
// false for a signature or proof the library rejects by throwing: one that
// does not verify, as far as a caller is concerned.
// ---------------------------------------------------------------------------
async function sign(input) {
  log.debug('Entering sign().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const signature = await lib.sign({
    secretKey: input.secretKey, publicKey: input.publicKey,
    header: input.header, messages: input.messages, ciphersuite: suite
  });
  log.debug('Leaving sign().');
  return signature;
}

async function verifySignature(input) {
  log.debug('Entering verifySignature().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const ok = await lib.verifySignature({
    publicKey: input.publicKey, signature: input.signature,
    header: input.header, messages: input.messages, ciphersuite: suite
  }).catch((e) => {
    log.debug('Caught in verifySignature(): ' + ((e && e.message) || e));
    return false;
  });
  log.debug('Leaving verifySignature(). ' + !!ok);
  return !!ok;
}

async function deriveProof(input) {
  log.debug('Entering deriveProof().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const proof = await lib.deriveProof({
    publicKey: input.publicKey, signature: input.signature,
    header: input.header, messages: input.messages,
    presentationHeader: input.presentationHeader,
    disclosedMessageIndexes: input.disclosedMessageIndexes,
    ciphersuite: suite
  });
  log.debug('Leaving deriveProof().');
  return proof;
}

async function verifyProof(input) {
  log.debug('Entering verifyProof().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const ok = await lib.verifyProof({
    publicKey: input.publicKey, proof: input.proof, header: input.header,
    presentationHeader: input.presentationHeader,
    disclosedMessages: input.disclosedMessages,
    disclosedMessageIndexes: input.disclosedMessageIndexes,
    ciphersuite: suite
  }).catch((e) => {
    log.debug('Caught in verifyProof(): ' + ((e && e.message) || e));
    return false;
  });
  log.debug('Leaving verifyProof(). ' + !!ok);
  return !!ok;
}

// ---------------------------------------------------------------------------
// THE PUBLIC KEY AS A MULTIKEY (vc-di-bbs section 2.1.1, #1878): `z` and the
// base58btc of the bls12_381-g2-pub multicodec (0xeb 0x01) followed by the
// 96-byte compressed G2 point. "Any other encoding MUST NOT be allowed."
// Until #1878 this service published `u` and the raw 96 bytes, which no
// other implementation reads.
// ---------------------------------------------------------------------------
const G2_MULTICODEC = [0xeb, 0x01];
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  log.debug('Entering base58Encode().');
  const input = Buffer.from(bytes);
  let n = BigInt('0x' + (input.length ? input.toString('hex') : '0'));
  let out = '';
  while (n > BigInt(0)) {
    out = B58[Number(n % BigInt(58))] + out;
    n = n / BigInt(58);
  }
  for (let i = 0; i < input.length && input[i] === 0; i++) {
    out = '1' + out;
  }
  log.debug('Leaving base58Encode().');
  return out;
}

function base58Decode(text) {
  log.debug('Entering base58Decode().');
  const s = String(text || '');
  let n = BigInt(0);
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) {
      log.debug('Leaving base58Decode(). Not base58.');
      throw new Error('not base58btc: "' + ch + '".');
    }
    n = n * BigInt(58) + BigInt(v);
  }
  let hex = n === BigInt(0) ? '' : n.toString(16);
  if (hex.length % 2) {
    hex = '0' + hex;
  }
  let zeros = 0;
  while (zeros < s.length && s.charAt(zeros) === '1') {
    zeros += 1;
  }
  log.debug('Leaving base58Decode().');
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, 'hex')]);
}

function publicKeyMultibase(publicKey) {
  log.debug('Entering publicKeyMultibase().');
  const key = Buffer.from(publicKey || []);
  if (key.length !== 96) {
    log.debug('Leaving publicKeyMultibase(). Not a G2 key.');
    throw new Error('a BLS12-381 G2 public key is 96 bytes; got ' +
                    key.length + '.');
  }
  log.debug('Leaving publicKeyMultibase().');
  return 'z' + base58Encode(Buffer.concat([Buffer.from(G2_MULTICODEC), key]));
}

function publicKeyFromMultibase(value) {
  log.debug('Entering publicKeyFromMultibase().');
  const text = String(value || '');
  if (text.charAt(0) !== 'z') {
    log.debug('Leaving publicKeyFromMultibase(). Not base58btc.');
    throw new Error('a bbs-2023 publicKeyMultibase starts with "z" ' +
                    '(base58btc); got "' + text.slice(0, 12) + '".');
  }
  const bytes = base58Decode(text.slice(1));
  if (bytes.length !== 98 || bytes[0] !== G2_MULTICODEC[0] ||
      bytes[1] !== G2_MULTICODEC[1]) {
    log.debug('Leaving publicKeyFromMultibase(). Not bls12_381-g2-pub.');
    throw new Error('not a bls12_381-g2-pub Multikey (0xeb01 and 96 bytes).');
  }
  log.debug('Leaving publicKeyFromMultibase().');
  return new Uint8Array(bytes.subarray(2));
}

// ---------------------------------------------------------------------------
// THE PRE-1.1 PRIVATE FORMAT, READ AND NEVER MADE (#1878). Until 1.1.0 this
// service's `bbs-2023` was its own: every canonical statement a BBS message,
// the header the canonical N-Quads of the proof options, the proofValue the
// raw signature, and a presentation an envelope of disclosed statements
// beside a raw BBS proof. No W3C implementation reads it, and nothing here
// makes it any more. The OpenID4VP verifier still READS such an envelope,
// only under the non-standard label `iya-bbs-2023-legacy` and only while
// `oid4vp.legacyBbsEnvelope` is on — `oid4vc/vc_verifier.ts` argues it.
// ---------------------------------------------------------------------------
async function legacyCanonicalizedStatements(doc) {
  log.debug('Entering legacyCanonicalizedStatements().');
  const nquads = await jsonld.canonize(doc, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader,
    safe: true
  });
  const statements = String(nquads).split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => l + '\n');
  log.debug('Leaving legacyCanonicalizedStatements().');
  return statements;
}

function proofConfig(proof) {
  log.debug('Entering proofConfig().');
  const config = {};
  Object.keys(proof).forEach((k) => {
    if (k !== 'proofValue') {
      config[k] = proof[k];
    }
  });
  log.debug('Leaving proofConfig().');
  return config;
}

async function legacyHeaderFor(proof) {
  log.debug('Entering legacyHeaderFor().');
  const statements =
    await legacyCanonicalizedStatements(proofConfig(proof));
  log.debug('Leaving legacyHeaderFor().');
  return te(statements.join(''));
}

async function legacyVerifyDerived(publicKey, derivedProof, header,
                                   presentationHeader, disclosedStatements,
                                   disclosedIndexes) {
  log.debug('Entering legacyVerifyDerived().');
  const ok = await verifyProof({
    publicKey,
    proof: derivedProof,
    header,
    presentationHeader,
    disclosedMessages: disclosedStatements.map(te),
    disclosedMessageIndexes:
      disclosedIndexes.slice().sort((a, b) => a - b)
  });
  log.debug('Leaving legacyVerifyDerived().');
  return ok;
}

module.exports = {
  CRYPTOSUITE,
  LEGACY_CRYPTOSUITE,
  PROOF_TYPE,
  IDENTITY_CONTEXT_URL,
  generateKeyPair,
  sign,
  verifySignature,
  deriveProof,
  verifyProof,
  publicKeyMultibase,
  publicKeyFromMultibase,
  legacyCanonicalizedStatements,
  legacyHeaderFor,
  legacyVerifyDerived,
  bytesToB64u,
  b64uToBytes,
  multibaseToBytes,
  documentLoader
};
