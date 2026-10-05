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
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rust_crypto_vectors',
  describe: 'what the Rust sts-crypto crate signed verifies, and what it ' +
            'encrypted decrypts, in the Node service — every JWS and JWE ' +
            'algorithm',
  run: run
};
