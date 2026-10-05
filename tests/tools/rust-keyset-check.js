#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// NODE READS WHAT THE RUST RUNTIME MADE (#444). The Rust test
// `a_made_key_set_is_whole` (rust/crates/sts-store/tests/keystore_vectors.rs),
// run with STS_KEYSET_OUT=<dir>, makes a realm key set, saves it sealed into
// an ldif store's keys.json in <dir>, and writes expected.json: the kids it
// derived, the JWKS it serves and a token it signed in every algorithm. This
// reads that store through keystore.js's own start, in product key mode,
// under the vectors' key-encryption key, and checks that Node
//
//   * reports the same signing kid, curve kids and request-encryption kid;
//   * builds sendJwks()'s entries over the set byte for byte as Rust does;
//   * verifies every token with its own verifyJws();
//   * signs with the RSA key and verifies against the certificate.
//
// Usage, from the root of a tree whose TypeScript is compiled (the tests
// image, or a scratch copy built for it):
//
//   STS_KEYSET_OUT=/tmp/ks STS_CRYPTO_VECTORS=/tmp/vec cargo test --release \
//     -p sts-store --test keystore_vectors a_made_key_set_is_whole
//   node tests/tools/rust-keyset-check.js /tmp/ks /tmp/vec/keystore-kek.txt
//
// Exits 1 on the first disagreement, naming it. The KEK is the one the
// vectors generated: never a real one, and never committed.

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const OUT = process.argv[2] || process.env.STS_KEYSET_OUT || '';
const KEK = process.argv[3] ||
  path.join(process.env.STS_CRYPTO_VECTORS || '', 'keystore-kek.txt');

if (!OUT || !fs.existsSync(path.join(OUT, 'keys.json'))) {
  console.error('usage: rust-keyset-check.js <dir with keys.json> <kek file>');
  process.exit(2);
}

// The key settings are read from the environment once, at the first require
// of config.js: set before anything of the service is loaded.
process.env.STS_KEYS_SOURCE = 'persisted';
process.env.STS_KEYS_KEK_PROVIDER = 'file';
process.env.STS_KEYS_KEK_FILE = KEK;
process.env.STS_LOG_LEVEL = process.env.STS_LOG_LEVEL || 'error';

const keystore = require(path.join(ROOT, 'common', 'keystore.js'));
const rows = JSON.parse(fs.readFileSync(path.join(OUT, 'keys.json'),
                                        'utf8')).keys;
keystore.setStore({
  loadKeys: function () {
    return Promise.resolve(rows);
  },
  saveKeys: function () {
    return Promise.resolve();
  }
});

const problems = [];

function expect(what, ok) {
  console.log((ok ? 'ok   ' : 'FAIL ') + what);
  if (!ok) {
    problems.push(what);
  }
}

function stripPem(pem) {
  return String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

(async function () {
  await keystore.start();
  const helpers = require(path.join(ROOT, 'common', 'helpers.js'));
  const stsCrypto = require(path.join(ROOT, 'common', 'crypto.js'));
  const forge = require('node-forge');
  const set = helpers.stsKeysFor();
  const want = JSON.parse(fs.readFileSync(path.join(OUT, 'expected.json'),
                                          'utf8'));

  expect('the signing kid is Rust\'s', set.kid === want.kid);
  expect('the curve kids are Rust\'s', JSON.stringify(
    (set.extraKeys || []).map(function (k) {
      return k.publicJwk.kid;
    })) === JSON.stringify(want.curveKids));
  expect('the request-encryption kid is Rust\'s',
         !!set.vciRequestEncKey &&
         set.vciRequestEncKey.publicJwk.kid === want.vciKid);

  // sendJwks()'s entries, built Node's way: the RSA modulus through forge,
  // the curve keys, the request object keys.
  const pub = forge.pki.certificateFromPem(set.certPem).publicKey;
  const b64u = function (hex) {
    return Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex')
      .toString('base64url');
  };
  const ro = helpers.requestObjectKeysFor();
  const jwks = { keys: [{
    kty: 'RSA', use: 'sig', kid: set.kid,
    n: b64u(pub.n.toString(16)), e: b64u(pub.e.toString(16)),
    x5c: [set.certB64].concat((set.certChainPem || []).map(stripPem))
  }].concat((set.extraKeys || []).map(function (k) {
    return k.publicJwk;
  })).concat([ro.rsa.publicJwk, ro.ec.publicJwk]) };
  expect('the JWKS is Rust\'s, byte for byte',
         JSON.stringify(jwks, null, 2) === JSON.stringify(want.jwks, null, 2));

  // Every token Rust signed, verified by verifyJws() against the key Node
  // holds under the header's kid.
  Object.keys(want.tokens || {}).forEach(function (name) {
    const token = want.tokens[name];
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url')
      .toString('utf8'));
    let key = null;
    if (header.kid === set.kid) {
      key = new nodeCrypto.X509Certificate(
        Buffer.from(set.certB64, 'base64')).publicKey;
    } else {
      const found = (set.extraKeys || []).filter(function (k) {
        return k.publicJwk.kid === header.kid;
      })[0];
      key = found
        ? nodeCrypto.createPublicKey({ key: found.publicJwk, format: 'jwk' })
        : null;
    }
    let claims = null;
    try {
      claims = stsCrypto.verifyJws(token, key, { algorithms: [header.alg],
                                                 ignoreExpiration: true });
    } catch (e) {
      claims = { refused: e.message };
    }
    expect('Node verifies Rust\'s ' + name + ' token',
           !!claims && claims.sub === 'alice');
  });

  // The set's RSA key as helpers.js hands it out: decrypted on demand.
  const signature = nodeCrypto.sign('sha256', Buffer.from('x'),
    set.privateKey || nodeCrypto.createPrivateKey(set.privateKeyPem));
  const certificate = new nodeCrypto.X509Certificate(
    Buffer.from(set.certB64, 'base64'));
  expect('Node signs with the RSA key and the certificate verifies it',
         nodeCrypto.verify('sha256', Buffer.from('x'), certificate.publicKey,
                           signature));

  if (problems.length) {
    console.error(problems.length + ' disagreement(s).');
    process.exitCode = 1;
  }
})().catch(function (e) {
  console.error(e);
  process.exitCode = 1;
});
