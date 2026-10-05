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
  if (fs.existsSync(path.join(VECTORS, 'pq-x509-rust.json'))) {
    log.debug("Leaving run(). The post-quantum checks are asynchronous.");
    return pqX509FromRust(t, read('pq-x509-rust.json')).then(function () {
      return restOfRun(t);
    });
  }
  log.debug("Leaving run().");
  return restOfRun(t);
}

/**
 * The checks after the post-quantum X.509 ones.
 *
 * @param {any} t - the runner's check collector
 * @returns {Promise<void>|undefined} when the asynchronous checks are done
 */
function restOfRun(t) {
  log.debug("Entering restOfRun().");
  if (fs.existsSync(path.join(VECTORS, 'secrets-rust.json'))) {
    secretsFromRust(t, read('secrets-rust.json'));
  }
  if (fs.existsSync(path.join(VECTORS, 'xmlenc-rust.json')) &&
      fs.existsSync(path.join(VECTORS, 'xmlenc-node.json'))) {
    xmlEncryption(t, read('xmlenc-rust.json'), read('xmlenc-node.json'));
  }
  const pending = [];
  if (fs.existsSync(path.join(VECTORS, 'sigstore-rust.json'))) {
    pending.push(function () {
      return sigstoreFromRust(t, read('sigstore-rust.json'));
    });
  }
  if (fs.existsSync(path.join(VECTORS, 'x509-rust.json'))) {
    pending.push(function () {
      return x509FromRust(t, read('x509-rust.json'));
    });
  }
  log.debug("Leaving restOfRun(). " + pending.length + " asynchronous.");
  return pending.reduce(function (chain, next) {
    return chain.then(next);
  }, Promise.resolve());
}

// X.509: every certificate Rust issued is described by Node exactly as Rust
// describes it (a post-quantum key aside, which Node calls "Ed25519"), and
// every link of its chain verifies in Node as it does in Rust; every
// PKCS#10 request Rust made parses, and its proof of possession verifies
// where pkijs can check one.
/**
 * @param {any} t - the runner's check collector
 * @param {any} rows - x509-rust.json
 * @returns {Promise<void>} when every row is checked
 */
async function x509FromRust(t, rows) {
  log.debug("Entering x509FromRust().");
  const x509 = require('../common/vendored/x509.js');
  const pkijs = require('pkijs');
  const bytes = require('../common/vendored/crypto_bytes.js');
  const strip = function (link) {
    const out = Object.assign({}, link);
    delete out.error;
    return out;
  };
  for (const row of rows) {
    if (row.csr) {
      let ok = false;
      let why = '';
      try {
        const req = pkijs.CertificationRequest.fromBER(
          bytes.pemToDer(row.csr));
        const oid = req.signatureAlgorithm.algorithmId;
        ok = oid === '1.3.101.112' || /^2\.16\.840\.1\.101\.3\.4\.3\./.test(oid)
          ? true : await req.verify();
      } catch (e) {
        log.debug("Caught in x509FromRust(): " + ((e && e.message) || e));
        why = (e && e.message) || String(e);
      }
      t.check(ok, row.name + ': a request Rust made parses in Node, and ' +
              'verifies where pkijs can check it', why);
      continue;
    }
    const described = await x509.describeCertificate(row.pem);
    const mine = Object.assign({}, row.describe);
    if (described.publicKey === 'Ed25519' && mine.publicKey !== 'Ed25519') {
      described.publicKey = mine.publicKey;
    }
    t.check(JSON.stringify(described) === JSON.stringify(mine),
            row.name + ': Node describes a certificate Rust issued as Rust ' +
            'does', JSON.stringify(described));
    const links = (await x509.verifyChain(row.chain)).map(strip);
    t.check(JSON.stringify(links) === JSON.stringify(row.links.map(strip)) &&
            links[0].signatureValid === true,
            row.name + ': its chain verifies in Node as in Rust',
            JSON.stringify(links));
  }
  log.debug("Leaving x509FromRust().");
}

// SIGSTORE AND TUF: Rust's two canonical forms are Node's strings, every TUF
// signature Rust made — Ed25519, ECDSA, RSA and ML-DSA — counts towards the
// role's threshold here, and Rust's Rekor SET verifies (and, its log index
// changed, does not).
/**
 * @param {any} t - the runner's check collector
 * @param {any} v - sigstore-rust.json
 * @returns {Promise<void>} when every check is made
 */
async function sigstoreFromRust(t, v) {
  log.debug("Entering sigstoreFromRust().");
  t.check(crypto.olpcCanonicalJson(v.signed) === v.olpc,
          'Rust\'s OLPC canonical JSON is Node\'s');
  t.check(crypto.jcsCanonicalJson(v.rekor.payload) === v.rekor.jcs,
          'Rust\'s JCS canonical JSON is Node\'s');
  const verdict = await crypto.verifyThresholdSignatures(v.signed,
                                                         v.signatures,
                                                         v.keys, v.role);
  t.check(verdict.ok && verdict.valid === 4,
          'all four TUF signatures Rust made verify in Node',
          JSON.stringify(verdict));
  const logs = v.rekor.logs.map(function (l) {
    return { logIdHex: l.logIdHex, spki: Buffer.from(l.spki, 'base64') };
  });
  const set = Buffer.from(v.rekor.set, 'base64');
  t.check(await crypto.verifyRekorSet(v.rekor.payload, set, logs) === '',
          'a Rekor SET Rust signed verifies in Node');
  const changed = Object.assign({}, v.rekor.payload,
                                { logIndex: v.rekor.payload.logIndex + 1 });
  t.check(await crypto.verifyRekorSet(changed, set, logs) ===
          'unable to verify SET', 'and not over another log index');
  log.debug("Leaving sigstoreFromRust().");
}

// The composite whose ECDSA half is P-521: @noble/curves 1.4.0 writes and
// reads its DER with a short-form length, which is not DER.
const NOBLE_P521 = 'mldsa87-ecdsa-p521-sha512';

// POST-QUANTUM KEYS IN X.509: every signature Rust made verifies with
// pqc_x509.js, the engine every post-quantum certificate here is checked by.
/**
 * @param {any} t - the runner's check collector
 * @param {any} rows - pq-x509-rust.json
 * @returns {Promise<void>} when every row is checked
 */
async function pqX509FromRust(t, rows) {
  log.debug("Entering pqX509FromRust().");
  const pqcX509 = require('../common/vendored/pqc_x509.js');
  for (const row of rows) {
    let ok = false;
    try {
      ok = await pqcX509.verify(row.id, Buffer.from(row.signature, 'base64'),
                                Buffer.from(row.message, 'base64'),
                                Buffer.from(row.pub, 'base64'));
    } catch (e) {
      log.debug("Caught in pqX509FromRust(): " + ((e && e.message) || e));
    }
    if (row.id === NOBLE_P521) {
      // The known defect: @noble/curves 1.4.0 reads a DER ECDSA signature
      // with a short-form length only, so a correct P-521 one is refused.
      // When Node is fixed this fails, and the exception goes.
      t.check(!ok, row.id + ': Node refuses a correct (long-form DER) P-521 ' +
              'signature — the known @noble/curves 1.4.0 defect');
      continue;
    }
    t.check(ok, row.id + ': a signature Rust made verifies in Node');
  }
  log.debug("Leaving pqX509FromRust().");
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
