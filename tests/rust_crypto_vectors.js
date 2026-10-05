// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: rust_crypto_vectors.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE OTHER DIRECTION OF THE PARITY PROOF (#444,
// rust/DESIGN.md sections 6 and 10.2): what the Rust crate `sts-crypto`
// signed, with keys it generated, verified by the Node service's own
// verifier.
//
// The vectors are written by that crate's test (`STS_WRITE_VECTORS=1`) into
// a directory that is NEVER COMMITTED — they carry private keys, and this
// repository commits no key material (`tests/tools/crypto-vectors.js` says
// how to make them). With none there this test says so and checks nothing:
// the Rust toolchain is not in the tests image yet. The first direction —
// every Node vector verified in Rust — is the crate's
// `tests/node_vectors.rs`.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const bunyan = require('bunyan');
const crypto = require('../common/crypto');

const log = bunyan.createLogger({ name: 'rust_crypto_vectors',
  level: process.env.STS_LOG_LEVEL || 'info' });

const VECTORS = process.env.STS_CRYPTO_VECTORS ||
  path.join(__dirname, 'vectors', 'sts-crypto');

/**
 * @param {string} name - the vector file
 * @returns {Array<any>} its rows
 */
function read(name) {
  log.debug("Entering read().");
  const rows = JSON.parse(fs.readFileSync(path.join(VECTORS, name), 'utf8'));
  log.debug("Leaving read().");
  return rows;
}

/**
 * @param {any} t - the runner's check collector
 */
function run(t) {
  log.debug("Entering run().");
  if (!fs.existsSync(path.join(VECTORS, 'jws-rust.json'))) {
    log.info('rust_crypto_vectors: no Rust vectors in ' + VECTORS + ', so ' +
             'nothing is checked (tests/tools/crypto-vectors.js says how ' +
             'to make them).');
    log.debug("Leaving run(). No vectors.");
    return;
  }
  const rows = read('jws-rust.json');
  t.check(rows.length === crypto.JWS_SIGNING_ALGS.length,
          'there is one Rust JWS vector per algorithm Node speaks',
          rows.length + ' / ' + crypto.JWS_SIGNING_ALGS.length);
  rows.forEach(function (row) {
    // An HMAC key is its octets; every other key is handed over as the JWK
    // a verifier is given in practice.
    const key = row.jwk.kty === 'oct' ? Buffer.from(row.jwk.k, 'base64url')
      : row.jwk;
    let verified = null;
    let why = '';
    try {
      verified = crypto.verifyCompactJws(row.token, key,
                                         { algorithms: [row.alg] });
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      why = (e && e.message) || String(e);
    }
    t.check(!!verified && verified.claims.sub === 'alice' &&
            verified.header.kid === 'rust-1',
            row.alg + ': a token Rust signed with a key Rust generated ' +
            'verifies in Node', why);
  });
  const jwes = read('jwe-rust.json');
  t.check(jwes.length >= crypto.JWE_ALGS.length,
          'there is a Rust JWE vector for every alg Node speaks',
          jwes.length + ' / ' + crypto.JWE_ALGS.length);
  jwes.forEach(function (row) {
    const options = {};
    if (row.secret) {
      options.secret = Buffer.from(row.secret, 'base64url');
    }
    if (row.privatePem) {
      options.privateKey = nodeCrypto.createPrivateKey(row.privatePem);
    }
    if (row.privateJwk) {
      options.privateJwk = row.privateJwk;
    }
    let opened = null;
    let why = '';
    try {
      opened = crypto.decryptJweCompact(row.compact, options);
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      why = (e && e.message) || String(e);
    }
    t.check(!!opened && opened.plaintext === '{"sub":"alice"}',
            row.alg + ' ' + row.enc + ': a JWE Rust encrypted decrypts in ' +
            'Node', why);
  });
  if (fs.existsSync(path.join(VECTORS, 'xmldsig-rust.json'))) {
    xmlSignatures(t, read('xmldsig-rust.json'));
  }
  if (fs.existsSync(path.join(VECTORS, 'secrets-rust.json'))) {
    secretsFromRust(t, read('secrets-rust.json'));
  }
  if (fs.existsSync(path.join(VECTORS, 'xmlenc-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'xmlenc-node.json'))) {
    xmlEncryption(t, read('xmlenc-rust.json'), read('xmlenc-node.json'));
  }
  log.debug("Leaving run().");
}

// SECRETS: every scrypt hash Rust made verifies here (and a wrong secret
// does not), every envelope Rust sealed opens under its data key, and every
// data key Rust wrapped unwraps under the key-encryption key and AAD.
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - secrets-rust.json
 */
function secretsFromRust(t, vectors) {
  log.debug("Entering secretsFromRust().");
  vectors.hashes.forEach(function (row) {
    t.check(crypto.verifySecret(row.plain, row.stored) &&
            !crypto.verifySecret(row.plain + 'x', row.stored),
            'a scrypt hash Rust made verifies in Node, and only for its ' +
            'secret');
  });
  vectors.envelopes.forEach(function (row) {
    let opened = null;
    try {
      opened = crypto.decryptWithDek(Buffer.from(row.key, 'base64'),
                                     row.sealed, 'vectors');
    } catch (e) {
      log.debug("Caught in secretsFromRust(): " + ((e && e.message) || e));
    }
    t.check(opened === row.plain, row.alg + ': an envelope Rust sealed ' +
            'opens in Node');
  });
  vectors.wraps.forEach(function (row) {
    let dek = null;
    try {
      dek = crypto.unwrapDek(row.kek, row.wrapped, row.aad);
    } catch (e) {
      log.debug("Caught in secretsFromRust(): " + ((e && e.message) || e));
    }
    t.check(!!dek && dek.toString('base64') === row.dek,
            'a data key Rust wrapped unwraps in Node');
  });
  log.debug("Leaving secretsFromRust().");
}

// XML ENCRYPTION: every element Rust encrypted — an RSA recipient in each
// cipher and key transport, an EC one in each curve, key wrap and cipher —
// decrypts with crypto.decryptElement() to the plaintext it was given, with
// the recipient key Node generated (xmlenc-node.json).
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - xmlenc-rust.json
 * @param {any} node - xmlenc-node.json, for the recipients' keys
 */
function xmlEncryption(t, vectors, node) {
  log.debug("Entering xmlEncryption().");
  vectors.cases.forEach(function (row) {
    const opened = crypto.decryptElement(row.xml,
      node.recipients[row.recipient].privateKeyPem, {});
    t.check(!!opened.ok && opened.xml === row.plain,
            row.name + ': an element Rust encrypted decrypts in Node',
            opened.why || '');
  });
  log.debug("Leaving xmlEncryption().");
}

// XML SIGNATURE: every document Rust signed, in each of the ten methods
// saml.signatureAlgorithm offers, gets the verdict from
// crypto.verifyXmlSignature() here that Node's own signature of the same
// document got (`ok`, carried in the vector) — a WithComments signature over
// a document with a comment fails in both, because signEnveloped() digests
// without comments; and every Redirect binding signature verifies against
// the signer's public key.
/**
 * @param {any} t - the runner's check collector
 * @param {any} vectors - xmldsig-rust.json
 */
function xmlSignatures(t, vectors) {
  log.debug("Entering xmlSignatures().");
  vectors.signed.forEach(function (row) {
    const verdict = crypto.verifyXmlSignature(row.signed, {
      element: row.element, publicKeyPem: row.publicKeyPem });
    t.check(!!verdict.ok === !!row.ok,
            row.name + ': the XML Rust signed gets Node\'s verdict on its ' +
            'own (' + (row.ok ? 'verifies' : 'refused') + ')', verdict.why);
  });
  vectors.queries.forEach(function (row) {
    const method = crypto.xmlSignatureAlgorithms().verified
      .filter(function (m) { return m.uri === row.sigAlg; })[0];
    let ok = false;
    try {
      ok = !!method && crypto.verifyXmlSignatureValue(row.sigAlg,
        nodeCrypto.createPublicKey(row.publicKeyPem),
        Buffer.from(row.query, 'utf8'),
        Buffer.from(row.signature, 'base64'), null);
    } catch (e) {
      log.debug("Caught in xmlSignatures(): " + ((e && e.message) || e));
    }
    t.check(ok, row.name + ': a Redirect binding signature Rust made ' +
            'verifies in Node');
  });
  log.debug("Leaving xmlSignatures().");
}

module.exports = {
  name: 'rust_crypto_vectors',
  describe: 'what the Rust sts-crypto crate signed verifies, and what it ' +
            'encrypted decrypts, in the Node service — every JWS and JWE ' +
            'algorithm, every XML signature method this service signs ' +
            'with, and every XML Encryption cipher, transport and agreement',
  run: run
};
