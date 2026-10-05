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
// Node service produces — keys, signatures, tokens, JWEs — as
// `jws-node.json` and `jwe-node.json` in a vectors directory, and
// `sts-crypto`'s tests must verify or decrypt every one of them, and match
// byte for byte where the scheme is deterministic. Those tests write what the
// Rust crate produces into the same directory (`jws-rust.json`,
// `jwe-rust.json`), and `tests/rust_crypto_vectors.js` verifies and decrypts
// every one of THEM in Node.
//
// **THE DIRECTORY IS NEVER COMMITTED**: the vectors carry private keys and
// shared secrets, and this repository commits no key material, generated or
// borrowed (`tests/tools/fetch-vectors.sh`). It is
// `tests/vectors/sts-crypto/` by default — gitignored and dockerignored
// with the other external vectors — or `STS_CRYPTO_VECTORS`.
//
//   node tests/tools/crypto-vectors.js [directory]
//   STS_CRYPTO_VECTORS=<dir> STS_WRITE_VECTORS=1 cargo test -p sts-crypto
//   node tests/run.js --only=rust_crypto_vectors
//
// Loading common/crypto.js needs its npm dependencies and node 24 (the
// post-quantum keys use its `raw-public` export format), as in the service
// image.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const OUT = process.argv[2] || process.env.STS_CRYPTO_VECTORS ||
  path.join(ROOT, 'tests', 'vectors', 'sts-crypto');

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

// A JWE per alg (with A256GCM, or none for an Integrated HPKE alg), and
// RSA-OAEP-256 with every enc: the recipient's private key and the compact
// JWE Node encrypted to it.
function jweSecretFor(alg, enc) {
  const sizes = { A128KW: 16, A192KW: 24, A256KW: 32, A128GCMKW: 16,
                  A192GCMKW: 24, A256GCMKW: 32 };
  if (sizes[alg]) {
    return nodeCrypto.randomBytes(sizes[alg]);
  }
  if (alg === 'dir') {
    return nodeCrypto.randomBytes(crypto.JWE_ENCS[enc].cekBytes);
  }
  return Buffer.from('a password for PBES2', 'utf8');
}

function jweRecipient(alg) {
  if (crypto.JWE_SYMMETRIC_ALGS.indexOf(alg) >= 0) {
    return null;
  }
  if (crypto.JWE_RSA_ALGS.indexOf(alg) >= 0 ||
      crypto.JWE_ECDH_ALGS.indexOf(alg) >= 0) {
    const pair = crypto.JWE_RSA_ALGS.indexOf(alg) >= 0
      ? nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
      : nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    return { publicJwk: pair.publicKey.export({ format: 'jwk' }),
             privateJwk: pair.privateKey.export({ format: 'jwk' }) };
  }
  return crypto.generateJweKemKeyPair(alg, 'node-1');
}

function jwe() {
  const cases = crypto.JWE_ALGS.map(function (alg) {
    return { alg: alg, enc: 'A256GCM' };
  }).concat(Object.keys(crypto.JWE_ENCS).map(function (enc) {
    return { alg: 'RSA-OAEP-256', enc: enc };
  }), Object.keys(crypto.JWE_ENCS).map(function (enc) {
    return { alg: 'dir', enc: enc };
  }));
  return cases.map(function (one) {
    const recipient = jweRecipient(one.alg);
    const secret = recipient ? null : jweSecretFor(one.alg, one.enc);
    const compact = crypto.encryptJweCompact('{"sub":"alice"}', {
      alg: one.alg, enc: one.enc,
      jwk: recipient ? recipient.publicJwk : undefined,
      secret: secret || undefined });
    return { alg: one.alg, enc: one.enc,
             privateJwk: recipient ? recipient.privateJwk : null,
             secret: secret ? secret.toString('base64url') : null,
             compact: compact };
  });
}

// CANONICAL XML: every element of every document, in all four forms, as
// common/vendored/xmldsig.js computes it in place — the bytes every XML
// signature here is made and checked over, which sts-xml must reproduce
// exactly. The documents are the hand-written edge cases below and, when
// STS_C14N_CORPUS names a directory, every .xml file under it (the W3C
// interop cases tests/tools/fetch-w3c-xmlsec.sh fetches). A document Node
// refuses to parse is recorded as refused, and Rust must refuse it too.
const C14N_CASES = [
  '<a:r xmlns:a="urn:a" xmlns:b="urn:b" z="1" a:y="&lt;2&gt;"><c>x&amp;y</c></a:r>',
  '<r xmlns="urn:d"><c xmlns=""><d xmlns="urn:e"/></c><!-- c --><?pi data?></r>',
  '<r xmlns:p="urn:p"><p:c p:a="1" b="2" xml:lang="en"><e xmlns:p="urn:p"/></p:c></r>',
  '<r>\r\n<a b="t\tn\nr\r">&#xD;&#x9;\t</a><![CDATA[<x> & ]]></r>',
  '<r xmlns:a="urn:z" xmlns:b="urn:a"><e b:y="1" a:x="2" c="3" b:a="4"/></r>',
  '<s:Envelope xmlns:s="urn:s" xmlns:xsi="urn:xsi"><s:Body><t xsi:type="s:T" ' +
    'xmlns="urn:t">\u00e9\u4e2d\ud83d\ude00</t></s:Body></s:Envelope>',
  '<r xmlns="urn:a"><a xmlns="urn:a"/><b xmlns=""/><c xmlns="urn:c"><d xmlns=""/></c></r>',
  '<r><!--x--><a><!--y--></a></r>',
  '<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>',
  '<r><a></b></r>'
];

function c14nCorpus() {
  const out = C14N_CASES.map(function (xml, i) {
    return { name: 'case-' + i, xml: xml };
  });
  const dir = process.env.STS_C14N_CORPUS;
  if (dir) {
    const walk = function (d) {
      fs.readdirSync(d, { withFileTypes: true }).forEach(function (e) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) {
          walk(full);
        } else if (/\.xml$/.test(e.name)) {
          out.push({ name: path.relative(dir, full),
                     xml: fs.readFileSync(full, 'utf8') });
        }
      });
    };
    walk(dir);
  }
  return out;
}

function c14n() {
  const xmldsig = require(path.join(ROOT, 'common', 'vendored',
                                    'xmldsig.js'));
  return c14nCorpus().map(function (one) {
    let doc;
    try {
      doc = xmldsig.parseXmlStrict(one.xml, 'a corpus document');
    } catch (e) {
      return { name: one.name, xml: one.xml, refused: e.message };
    }
    const forms = [];
    const all = doc.getElementsByTagName('*');
    for (let i = 0; i < all.length; i++) {
      forms.push([
        xmldsig.canonicalize(all[i], {}),
        xmldsig.canonicalize(all[i], { comments: true }),
        xmldsig.canonicalizeInclusive(all[i], {}),
        xmldsig.canonicalizeInclusive(all[i], { comments: true })
      ]);
    }
    return { name: one.name, xml: one.xml, forms: forms };
  });
}

const VECTORS = [{ file: 'jws-node.json', build: jws },
                 { file: 'jwe-node.json', build: jwe },
                 { file: 'c14n-node.json', build: c14n }];

if (require.main === module) {
  fs.mkdirSync(OUT, { recursive: true });
  VECTORS.forEach(function (one) {
    fs.writeFileSync(path.join(OUT, one.file),
                     JSON.stringify(one.build(), null, 1) + '\n');
    console.log('wrote ' + path.relative(ROOT, path.join(OUT, one.file)));
  });
}
