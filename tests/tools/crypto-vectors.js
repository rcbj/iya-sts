#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: crypto-vectors.js
//
// ---------------------------------------------------------------------------
// THE NODE HALF OF THE CRYPTOGRAPHIC PARITY PROOF (#444, rust/DESIGN.md
// sections 6 and 10.2).
//
// For every algorithm in a row of the design's table, this writes what the
// Node service produces — keys, signatures, tokens — into
// `rust/crates/sts-crypto/vectors/*-node.json`, and `sts-crypto`'s tests
// must verify every one of them, and match byte for byte where the scheme is
// deterministic. The other direction is `tests/rust_crypto_vectors.js`,
// which verifies what the Rust crate wrote into `*-rust.json`. Both files
// are committed, so neither proof needs the other runtime to be installed.
//
//   node tests/tools/crypto-vectors.js        rewrite the Node vectors
//
// Loading common/crypto.js needs its npm dependencies, so this runs where
// they are installed (the tests image, or a checkout after `npm install`).
// Regenerating changes every randomised value, which is expected; the
// vectors are evidence, not fixtures.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const OUT = path.join(ROOT, 'rust', 'crates', 'sts-crypto', 'vectors');

const crypto = require(path.join(ROOT, 'common', 'crypto.js'));
const pqJose = require(path.join(ROOT, 'common', 'pq_jose.js'));

const DETERMINISTIC = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
                       'EdDSA'];

const CURVES = { ES256: 'prime256v1', ES384: 'secp384r1',
                 ES512: 'secp521r1', ES256K: 'secp256k1' };

// A key for `alg`: the JWK a Rust verifier is handed, and what signJws()
// signs with here.
function keyFor(alg) {
  if (/^HS/.test(alg)) {
    const secret = nodeCrypto.randomBytes(Number(alg.slice(2)) / 8);
    return { jwk: { kty: 'oct', k: secret.toString('base64url') },
             signing: secret };
  }
  if (pqJose.isPqAlg(alg)) {
    const pair = pqJose.generate(alg);
    return { jwk: { kty: 'AKP', alg: alg, pub: pair.pub.toString('base64url'),
                    priv: pair.priv.toString('base64url') },
             signing: pair.priv };
  }
  const pair = /^(RS|PS)/.test(alg)
    ? nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    : alg === 'EdDSA' ? nodeCrypto.generateKeyPairSync('ed25519')
      : nodeCrypto.generateKeyPairSync('ec', { namedCurve: CURVES[alg] });
  return { jwk: pair.privateKey.export({ format: 'jwk' }),
           signing: pair.privateKey };
}

function jws() {
  return crypto.JWS_SIGNING_ALGS.map(function (alg) {
    const key = keyFor(alg);
    const input = Buffer.from('eyJhbGciOiJ4In0.eyJzdWIiOiJhbGljZSJ9',
                              'ascii');
    const signature = /^(HS|RS|PS|ES(256|384|512)$)/.test(alg)
      ? nodeSignature(alg, key.signing, input)
      : crypto.jwsSignatureOver(alg, key.signing, input);
    const token = crypto.signJws({ sub: 'alice', iat: 1000 }, key.signing,
                                 { algorithm: alg, keyid: 'node-1' });
    return { alg: alg, deterministic: DETERMINISTIC.indexOf(alg) >= 0,
             jwk: key.jwk, input: input.toString('ascii'),
             signature: signature.toString('base64url'), token: token,
             idTokenHalfHash: crypto.idTokenHalfHash('the-access-token',
                                                     alg) };
  });
}

// The signature node's crypto makes for the rows jsonwebtoken signs, with
// the same parameters crypto.js verifies them with.
function nodeSignature(alg, key, input) {
  const hash = 'sha' + alg.slice(2);
  if (/^HS/.test(alg)) {
    return nodeCrypto.createHmac(hash, key).update(input).digest();
  }
  const params = { key: key };
  if (/^PS/.test(alg)) {
    params.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
    params.saltLength = Number(alg.slice(2)) / 8;
  }
  if (/^ES/.test(alg)) {
    params.dsaEncoding = 'ieee-p1363';
  }
  return nodeCrypto.sign(hash, input, params);
}

const VECTORS = [{ file: 'jws-node.json', build: jws }];

if (require.main === module) {
  fs.mkdirSync(OUT, { recursive: true });
  VECTORS.forEach(function (one) {
    fs.writeFileSync(path.join(OUT, one.file),
                     JSON.stringify(one.build(), null, 1) + '\n');
    console.log('wrote ' + path.relative(ROOT, path.join(OUT, one.file)));
  });
}
