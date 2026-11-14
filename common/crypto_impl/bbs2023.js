// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
// File: bbs2023.js
'use strict';
//
// ---------------------------------------------------------------------------
// The issuer and verifier half of the `bbs-2023` cryptosuite.
//
// THIS SERVICE'S OWN SINCE #663 (2026-11-02), not a copy of the parent
// project's file any more, on the same terms as `pqc.js` under #363: the
// identity context it signs against is this issuer's vocabulary, named on
// this issuer's own URL (`https://iyasec.io/contexts/identity/v1`), and a
// minted credential carries no other project's name. It is edited here and
// is not re-synced from the parent.
//
// This deliberately does NOT reuse the debugger's client/src/bbs2023.js. The
// BBS protocol code here is @digitalbazaar/bbs-signatures — a different
// implementation from the one the browser runs — so a credential this
// service issues is signed by one codebase and its derived proof is
// produced by another, and each side verifies the other's work. That
// cross-check is the point: BBS has several places where a signer and
// verifier can share a mistake, agree perfectly, and agree with nobody else.
//
// What IS shared, and must be, is the canonical form. bbs-2023 signs
// canonical N-Quad statements, so both sides run the same `jsonld`
// canonicalization over the same contexts. A one-byte difference there fails
// every signature while looking exactly like a crypto bug — so a wallet
// needs this issuer's identity context before it can derive a proof from a
// credential issued here. Nothing here is vendored to or from the parent
// any more (rcbj, #663).
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

async function canonicalizedStatements(doc) {
  log.debug('Entering canonicalizedStatements().');
  const nquads = await jsonld.canonize(doc, {
    algorithm: 'URDNA2015',
    format: 'application/n-quads',
    documentLoader,
    safe: true
  });
  const statements = String(nquads).split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => l + '\n');
  log.debug('Leaving canonicalizedStatements().');
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

async function headerFor(proof) {
  log.debug('Entering headerFor().');
  const statements = await canonicalizedStatements(proofConfig(proof));
  log.debug('Leaving headerFor().');
  return te(statements.join(''));
}

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

// --- issue ------------------------------------------------------------------
async function issue(unsecured, proofOptions, secretKey, publicKey) {
  log.debug('Entering issue().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const proof = Object.assign({
    '@context': unsecured['@context'],
    type: PROOF_TYPE,
    cryptosuite: CRYPTOSUITE,
    proofPurpose: 'assertionMethod'
  }, proofOptions);

  const document = Object.assign({}, unsecured);
  delete document.proof;
  const statements = await canonicalizedStatements(document);
  const header = await headerFor(proof);
  const signature = await lib.sign({
    secretKey, publicKey, header, messages: statements.map(te),
    ciphersuite: suite
  });

  const attached = Object.assign({}, proof);
  delete attached['@context'];
  attached.proofValue = 'u' + bytesToB64u(signature);
  const secured = Object.assign({}, document, { proof: attached });
  log.debug('Leaving issue().');
  return { credential: secured, statements, header, signature };
}

// --- verify -----------------------------------------------------------------
// Every crypto operation this service is handed goes through one of these
// two. A signature the library rejects by throwing is a signature that did
// not verify, so each answers false for it rather than throwing on.
async function verifyBase(secured, publicKey) {
  log.debug('Entering verifyBase().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const proof = secured.proof || {};
  const document = Object.assign({}, secured);
  delete document.proof;
  const reproof = Object.assign({ '@context': secured['@context'] }, proof);
  delete reproof.proofValue;
  const statements = await canonicalizedStatements(document);
  const header = await headerFor(reproof);
  const signature = multibaseToBytes(proof.proofValue);
  const ok = await lib.verifySignature({
    publicKey, signature, header, messages: statements.map(te),
    ciphersuite: suite
  }).catch((e) => {
    log.debug('Caught in verifyBase(): ' + ((e && e.message) || e));
    return false;
  });
  log.debug('Leaving verifyBase().');
  return { ok, statements, header };
}

async function verifyDerived(publicKey, derivedProof, header,
                             presentationHeader, disclosedStatements,
                             disclosedIndexes) {
  log.debug('Entering verifyDerived().');
  const lib = await bbs();
  const suite = await ciphersuite();
  const ok = await lib.verifyProof({
    publicKey,
    proof: derivedProof,
    header,
    presentationHeader,
    disclosedMessages: disclosedStatements.map(te),
    disclosedMessageIndexes:
      disclosedIndexes.slice().sort((a, b) => a - b),
    ciphersuite: suite
  }).catch((e) => {
    log.debug('Caught in verifyDerived(): ' + ((e && e.message) || e));
    return false;
  });
  log.debug('Leaving verifyDerived().');
  return ok;
}

module.exports = {
  CRYPTOSUITE,
  PROOF_TYPE,
  IDENTITY_CONTEXT_URL,
  canonicalizedStatements,
  headerFor,
  generateKeyPair,
  issue,
  verifyBase,
  verifyDerived,
  bytesToB64u,
  b64uToBytes,
  multibaseToBytes,
  documentLoader
};
