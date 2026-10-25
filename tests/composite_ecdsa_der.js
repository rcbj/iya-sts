// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: composite_ecdsa_der.js
//
// ===========================================================================
// THE ECDSA HALF OF A COMPOSITE ML-DSA SIGNATURE, IN DER (#445).
//
// `common/crypto_impl/pqc_x509.js` signs that half with @noble/curves 1.4.0
// and used to ask the same library to write the Ecdsa-Sig-Value. That
// release writes the SEQUENCE length as one byte. A P-521 signature is
// always longer than 127 bytes, so the byte is not a length: OpenSSL
// refuses every signature this service produced for
// id-MLDSA87-ECDSA-P521-SHA512, and this service refused a correct
// long-form signature from anyone else. P-256 and P-384 stay under the
// limit.
//
// WHY IN PROCESS, which is the question tests/CLAUDE.md asks first. The
// assertion is byte-level, against node's OpenSSL, with no port: the
// traditional half of a signature this module produced, and a half OpenSSL
// produced, over the composite message representative. Nothing about it is
// visible on an HTTP endpoint that the protocol suite could drive without
// reimplementing the split.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const nobleDsa = require('@noble/post-quantum/ml-dsa.js');
const pqc = require('../common/crypto_impl/pqc');
const pqx = require('../common/crypto_impl/pqc_x509');

const log = require('bunyan').createLogger({
  name: 'composite_ecdsa_der',
  level: process.env.LOG_LEVEL || 'info'
});

// The assertion is the ECDSA half, signed and verified by pqc_x509.js.
// ML-DSA stays on the registry's primitive. Node 24.22.1's OpenSSL exports
// that private key as a seed only, which pq_native.js currently refuses
// (no expanded key to read). @noble/post-quantum speaks the same prim
// shape, so the DER check still runs; a build whose keygen works is left
// on OpenSSL.
const NOBLE_ML_DSA = {
  'ML-DSA-44': nobleDsa.ml_dsa44,
  'ML-DSA-65': nobleDsa.ml_dsa65,
  'ML-DSA-87': nobleDsa.ml_dsa87
};

function useNobleMlDsa(name) {
  log.debug("Entering useNobleMlDsa().");
  const entry = pqc.signatureAlg(name);
  entry.prim = NOBLE_ML_DSA[name];
  log.debug("Leaving useNobleMlDsa().");
}

// trad.sigHash is not the composite pre-hash. P-256 signs SHA-256, P-384
// SHA-384 and P-521 SHA-512, whatever the algorithm's own name ends in.
const CASES = [
  { alg: 'mldsa65-ecdsa-p256-sha512', hash: 'sha256', longForm: false },
  { alg: 'mldsa87-ecdsa-p384-sha512', hash: 'sha384', longForm: false },
  { alg: 'mldsa87-ecdsa-p521-sha512', hash: 'sha512', longForm: true }
];

function nodeHashName(sigHash) {
  log.debug("Entering nodeHashName().");
  log.debug("Leaving nodeHashName().");
  return sigHash.replace(/-/g, '').toLowerCase();
}

function traditionalKey(cfg, priv) {
  log.debug("Entering traditionalKey().");
  const halves = pqx.splitCompositePrivate(cfg, priv);
  const key = nodeCrypto.createPrivateKey({
    key: Buffer.from(halves.trad),
    format: 'der',
    type: 'sec1'
  });
  log.debug("Leaving traditionalKey().");
  return key;
}

// The one-byte length noble 1.4.0 writes: drop the 0x81 of a legal
// long-form SEQUENCE, leaving 30 LL …, which DER reads as a length of
// LL octets of length.
function shortFormOf(der) {
  log.debug("Entering shortFormOf().");
  if (der[0] !== 0x30 || der[1] !== 0x81) {
    log.debug("Leaving shortFormOf(). Not a long-form SEQUENCE.");
    throw new Error('expected a long-form SEQUENCE, got ' +
        Buffer.from(der.subarray(0, 3)).toString('hex'));
  }
  const out = Buffer.concat([
    Buffer.from([0x30, der[2]]), der.subarray(3)
  ]);
  log.debug("Leaving shortFormOf().");
  return out;
}

async function oneAlgorithm(t, spec) {
  log.debug("Entering oneAlgorithm(). alg=" + spec.alg);
  const cfg = pqx.COMPOSITE_ALGS[spec.alg];
  const message = Buffer.from('composite ECDSA DER, ' + spec.alg);
  let pair;
  try {
    pair = await pqx.generateKeyPair(spec.alg);
  } catch (e) {
    // A seed-only export is pq_native's refusal, not a bad ECDSA
    // signature. Retrying on noble keeps this file about the DER.
    log.debug("Caught in oneAlgorithm(): " + ((e && e.message) || e));
    if (!e || !/seed only/.test(e.message)) {
      log.debug("Leaving oneAlgorithm(). Unexpected keygen failure.");
      throw e;
    }
    useNobleMlDsa(cfg.mldsa);
    pair = await pqx.generateKeyPair(spec.alg);
  }
  const signature = Buffer.from(await pqx.sign(spec.alg, message, pair.priv));
  const parts = pqx.splitCompositeSignature(cfg, signature);
  const trad = Buffer.from(parts.trad);
  const mPrime = Buffer.from(pqx.compositeMessage(cfg, message));
  const key = traditionalKey(cfg, pair.priv);
  const long = trad.length >= 2 && trad[0] === 0x30 && trad[1] === 0x81;
  t.equal(long, spec.longForm,
          spec.alg + ': the ECDSA half ' +
          (spec.longForm ? 'uses' : 'does not need') +
          ' DER long-form length');
  t.check(nodeCrypto.verify(spec.hash, mPrime,
              { key: key, dsaEncoding: 'der' }, trad),
          spec.alg + ': OpenSSL verifies the ECDSA half this service wrote',
          trad.subarray(0, 4).toString('hex') + ' (' + trad.length + ')');
  t.check(await pqx.verify(spec.alg, signature, message, pair.pub),
          spec.alg + ': this service verifies its own composite');
  t.check(!(await pqx.verify(spec.alg, signature,
              Buffer.from('other'), pair.pub)),
          spec.alg + ': a different message does not verify');

  const opensslHalf = nodeCrypto.sign(spec.hash, mPrime, {
    key: key, dsaEncoding: 'der'
  });
  const spliced = Buffer.concat([Buffer.from(parts.mldsa), opensslHalf]);
  t.check(await pqx.verify(spec.alg, spliced, message, pair.pub),
          spec.alg + ': an ECDSA half OpenSSL wrote verifies here');
  if (spec.longForm) {
    const broken = Buffer.concat([
      Buffer.from(parts.mldsa), shortFormOf(trad)
    ]);
    t.check(!nodeCrypto.verify(spec.hash, mPrime,
                { key: key, dsaEncoding: 'der' }, shortFormOf(trad)),
            spec.alg + ': OpenSSL refuses the short-form length noble ' +
            '1.4.0 used to write');
    t.check(!(await pqx.verify(spec.alg, broken, message, pair.pub)),
            spec.alg + ': this service refuses that short form too');
  }
  // nodeHashName is here so a future row cannot pass the JOSE name
  // ('SHA-256') to crypto.verify, which does not accept the hyphen.
  t.equal(nodeHashName(cfg.trad.sigHash), spec.hash,
          spec.alg + ': the traditional hash is ' + spec.hash);
  log.debug("Leaving oneAlgorithm().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== composite ECDSA signatures, DER against OpenSSL ===');
  let i;
  for (i = 0; i < CASES.length; i++) {
    await oneAlgorithm(t, CASES[i]);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'composite_ecdsa_der',
  describe: 'pqc_x509.js: a composite ECDSA half is DER that OpenSSL ' +
            'accepts, including the long form a P-521 signature needs ' +
            '(#445)',
  run: run
};
