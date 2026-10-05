// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pq_native.js
//
// ===========================================================================
// ML-DSA, SLH-DSA AND ML-KEM ON NODE'S OPENSSL (#363, 2026-09-30).
//
// `common/pq_native.js` replaced `@noble/post-quantum` inside the service,
// and the post-quantum worker pool with it. This holds it to the library it
// replaced — which the tests keep (`tests/package.json`) exactly so that the
// two can be compared — and to what the pool used to promise:
//
//   A. THE SAME KEYS. From one seed, the same ML-DSA and ML-KEM public and
//      expanded secret keys as noble; so a key product mode stored before
//      #363 is the same key after it.
//   B. INTEROPERATION BOTH WAYS. noble verifies our signatures and we verify
//      noble's, with and without a context string, for all three ML-DSA
//      sets and every SLH-DSA set; each decapsulates the other's ML-KEM
//      ciphertexts, from the expanded key and from the seed.
//   C. THE SIZES the standards give (the table in pq_native.js), against
//      what OpenSSL actually produces.
//   D. THE REFUSALS: a context mismatch fails, a wrong-size signature is a
//      false and not a throw, and the three things node does not offer —
//      derandomized encapsulation, seeded SLH-DSA key generation and the
//      pre-hash variants — throw rather than being approximated.
//   E. OFF THE EVENT LOOP: an SLH-DSA-SHAKE-128s signature through
//      `signAsync()` lets timers fire while it computes, which is the whole
//      reason the pool existed; a synchronous one does not.
//   F. THE CALLERS: `pq_jose.js` signs and verifies every one of its eleven
//      algorithms through both doors and the two agree; `crypto.js`'s
//      async scrypt doors agree with the sync ones.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const pq = require('../common/pq_native');
const nobleDsa = require('@noble/post-quantum/ml-dsa.js');
const nobleSlh = require('@noble/post-quantum/slh-dsa.js');
const nobleKem = require('@noble/post-quantum/ml-kem.js');

const log = require('bunyan').createLogger({ name: 'pq_native',
  level: process.env.LOG_LEVEL || 'info' });

const DSA = ['ml_dsa44', 'ml_dsa65', 'ml_dsa87'];
const KEM = ['ml_kem512', 'ml_kem768', 'ml_kem1024'];
// The fast SLH-DSA sets are exercised in full; the `s` sets cost hundreds of
// milliseconds each and one of them is E's subject.
const SLH_FAST = ['slh_dsa_sha2_128f', 'slh_dsa_sha2_192f',
                  'slh_dsa_sha2_256f', 'slh_dsa_shake_128f',
                  'slh_dsa_shake_192f', 'slh_dsa_shake_256f'];

function same(a, b) {
  log.debug('Entering same().');
  log.debug('Leaving same().');
  return Buffer.from(a).equals(Buffer.from(b));
}

// noble 0.4.1 verifies as (publicKey, msg, sig, ctx).
function nobleVerifies(prim, pub, msg, sig, ctx) {
  log.debug('Entering nobleVerifies().');
  const ok = ctx ? prim.verify(new Uint8Array(pub), new Uint8Array(msg),
                               new Uint8Array(sig), new Uint8Array(ctx))
    : prim.verify(new Uint8Array(pub), new Uint8Array(msg),
                  new Uint8Array(sig));
  log.debug('Leaving nobleVerifies().');
  return ok;
}

function throwsWith(f, pattern) {
  log.debug('Entering throwsWith().');
  try {
    f();
  } catch (e) {
    log.debug('Caught in throwsWith(): ' + ((e && e.message) || e));
    log.debug('Leaving throwsWith(). Threw.');
    return pattern.test(String(e && e.message));
  }
  log.debug('Leaving throwsWith(). Did not throw.');
  return false;
}

function keysAndInterop(t) {
  log.debug('Entering keysAndInterop().');
  t.log.info('=== A-C. ML-DSA: the same keys, both ways, the sizes ===');
  const msg = Buffer.from('pq_native interop');
  const ctx = Buffer.from('COMPSIG-TEST-LABEL');
  DSA.forEach(function (name) {
    const seed = nodeCrypto.randomBytes(32);
    const ours = pq[name].keygen(seed);
    const theirs = nobleDsa[name].keygen(new Uint8Array(seed));
    t.check(same(ours.publicKey, theirs.publicKey) &&
            same(ours.secretKey, theirs.secretKey),
            'A. ' + name + ': the same public and expanded key from one seed');
    const plain = pq[name].sign(ours.secretKey, msg);
    const fromSeed = pq[name].sign(seed, msg, ctx);
    const nobleSig = nobleDsa[name].sign(theirs.secretKey,
                                         new Uint8Array(msg),
                                         new Uint8Array(ctx));
    t.check(nobleVerifies(nobleDsa[name], ours.publicKey, msg, plain) &&
            nobleVerifies(nobleDsa[name], ours.publicKey, msg, fromSeed,
                          ctx) &&
            pq[name].verify(ours.publicKey, msg, nobleSig, ctx),
            'B. ' + name + ': noble verifies ours (expanded key and seed, ' +
            'with a context) and we verify noble\'s');
    t.check(!pq[name].verify(ours.publicKey, msg, fromSeed) &&
            !pq[name].verify(ours.publicKey, msg, plain, ctx),
            'D. ' + name + ': a context that does not match does not verify');
    const L = pq[name].lengths;
    t.check(ours.publicKey.length === L.publicKey &&
            ours.secretKey.length === L.secretKey &&
            plain.length === L.signature,
            'C. ' + name + ': public ' + L.publicKey + ', secret ' +
            L.secretKey + ', signature ' + L.signature + ' octets');
    t.check(pq[name].verify(ours.publicKey, msg, plain.subarray(1)) === false,
            'D. ' + name + ': a short signature is false, not a throw');
  });
  t.log.info('=== A-C. SLH-DSA ===');
  SLH_FAST.forEach(function (name) {
    const kp = pq[name].keygen();
    const sig = pq[name].sign(kp.secretKey, msg);
    t.check(nobleVerifies(nobleSlh[name], kp.publicKey, msg, sig) &&
            kp.publicKey.length === pq[name].lengths.publicKey &&
            kp.secretKey.length === pq[name].lengths.secretKey &&
            sig.length === pq[name].lengths.signature,
            'B/C. ' + name + ': noble verifies ours, and the sizes hold');
    const theirs = nobleSlh[name].keygen();
    const nobleSig = nobleSlh[name].sign(theirs.secretKey,
                                         new Uint8Array(msg));
    t.check(pq[name].verify(theirs.publicKey, msg, nobleSig) &&
            pq[name].verify(kp.publicKey, msg, pq[name].sign(
              theirs.secretKey, msg)) === false,
            'B. ' + name + ': we verify noble\'s, and a key signs only for ' +
            'its own public key');
  });
  t.log.info('=== A-C. ML-KEM ===');
  KEM.forEach(function (name) {
    const seed = nodeCrypto.randomBytes(64);
    const ours = pq[name].keygen(seed);
    const theirs = nobleKem[name].keygen(new Uint8Array(seed));
    t.check(same(ours.publicKey, theirs.publicKey) &&
            same(ours.secretKey, theirs.secretKey),
            'A. ' + name + ': the same ek and expanded dk from d || z');
    const toUs = nobleKem[name].encapsulate(theirs.publicKey);
    const toThem = pq[name].encapsulate(ours.publicKey);
    t.check(same(pq[name].decapsulate(toUs.cipherText, ours.secretKey),
                 toUs.sharedSecret) &&
            same(pq[name].decapsulate(toUs.cipherText, seed),
                 toUs.sharedSecret) &&
            same(nobleKem[name].decapsulate(toThem.cipherText,
                                            theirs.secretKey),
                 toThem.sharedSecret),
            'B. ' + name + ': each decapsulates the other\'s ciphertext, ' +
            'from the expanded key and from the seed');
    const L = pq[name].lengths;
    t.check(ours.publicKey.length === L.publicKey &&
            ours.secretKey.length === L.secretKey &&
            toThem.cipherText.length === L.cipherText &&
            toThem.sharedSecret.length === 32,
            'C. ' + name + ': ek ' + L.publicKey + ', dk ' + L.secretKey +
            ', ciphertext ' + L.cipherText + ' octets');
  });
  log.debug('Leaving keysAndInterop().');
}

function refusals(t) {
  log.debug('Entering refusals().');
  t.log.info('=== D. what node does not offer is refused ===');
  const kem = pq.ml_kem768.keygen();
  t.check(throwsWith(function () {
    pq.ml_kem768.encapsulate(kem.publicKey, nodeCrypto.randomBytes(32));
  }, /Encaps_internal/),
          'D1. encapsulation with given randomness throws');
  t.check(throwsWith(function () {
    pq.slh_dsa_sha2_128f.keygen(nodeCrypto.randomBytes(48));
  }, /KeyGen_internal/),
          'D2. SLH-DSA key generation from given seeds throws');
  t.check(throwsWith(function () {
    pq.ml_dsa44.prehash('SHA2-256');
  }, /pure variant/) && throwsWith(function () {
    pq.slh_dsa_sha2_128f.prehash('SHA2-256');
  }, /pure variant/),
          'D3. the pre-hash variants throw');
  t.check(throwsWith(function () {
    pq.ml_dsa44.sign(nodeCrypto.randomBytes(31), Buffer.from('m'));
  }, /32-octet seed/) && throwsWith(function () {
    pq.ml_kem512.decapsulate(Buffer.alloc(10), kem.secretKey);
  }, /ciphertext is 768/),
          'D4. a key or ciphertext of the wrong size is named');
  log.debug('Leaving refusals().');
}

async function offTheLoop(t) {
  log.debug('Entering offTheLoop().');
  t.log.info('=== E. an SLH-DSA-SHAKE-128s signature does not hold the ' +
             'event loop ===');
  const kp = pq.slh_dsa_shake_128s.keygen();
  const msg = Buffer.from('off the loop');
  let ticks = 0;
  const timer = setInterval(function () {
    ticks++;
  }, 5);
  const started = Date.now();
  const sig = await pq.slh_dsa_shake_128s.signAsync(kp.secretKey, msg);
  const asyncMs = Date.now() - started;
  const asyncTicks = ticks;
  ticks = 0;
  pq.slh_dsa_shake_128s.sign(kp.secretKey, msg);
  const syncTicks = ticks;
  clearInterval(timer);
  t.check(asyncTicks >= 3 && syncTicks === 0,
          'E1. the loop ticked ' + asyncTicks + ' times during a ' +
          asyncMs + ' ms signAsync() and ' + syncTicks + ' during the ' +
          'synchronous sign()');
  t.check(await pq.slh_dsa_shake_128s.verifyAsync(kp.publicKey, msg, sig) &&
          !(await pq.slh_dsa_shake_128s.verifyAsync(kp.publicKey,
                                                    Buffer.from('other'),
                                                    sig)),
          'E2. verifyAsync() answers true and false');
  const made = await pq.slh_dsa_sha2_128s.keygenAsync();
  t.check(made.publicKey.length === 32 && made.secretKey.length === 64,
          'E3. keygenAsync() makes a key pair off the loop');
  log.debug('Leaving offTheLoop().');
}

async function callers(t) {
  log.debug('Entering callers().');
  t.log.info('=== F. pq_jose.js and crypto.js over it ===');
  const pqJose = require('../common/pq_jose');
  const msg = Buffer.from('pq_jose through pq_native');
  for (const alg of pqJose.PQ_ALGS) {
    const pair = /^SLH/.test(alg) ? await pqJose.generateAsync(alg)
      : pqJose.generate(alg);
    const syncSig = pqJose.sign(alg, pair.priv, msg);
    const asyncSig = await pqJose.signAsync(alg, pair.priv, msg);
    t.check(pqJose.verify(alg, pair.pub, msg, asyncSig) &&
            await pqJose.verifyAsync(alg, pair.pub, msg, syncSig) &&
            !pqJose.verify(alg, pair.pub, Buffer.from('other'), syncSig),
            'F1. ' + alg + ': both doors sign, both verify, and a changed ' +
            'message does not');
  }
  const crypto = require('../common/crypto');
  const stored = await crypto.hashSecretAsync('pq-native-secret');
  const syncStored = crypto.hashSecret('pq-native-secret');
  t.check(crypto.verifySecret('pq-native-secret', stored) &&
          await crypto.verifySecretAsync('pq-native-secret', syncStored) &&
          !(await crypto.verifySecretAsync('wrong', stored)),
          'F2. async scrypt on libuv agrees with the sync door both ways');
  log.debug('Leaving callers().');
}

async function run(t) {
  log.debug('Entering run().');
  keysAndInterop(t);
  refusals(t);
  await offTheLoop(t);
  await callers(t);
  log.debug('Leaving run().');
}

module.exports = {
  name: 'pq_native',
  describe: 'ML-DSA, SLH-DSA and ML-KEM on node\'s OpenSSL (#363): the ' +
            'same keys as @noble/post-quantum, interoperation both ways, ' +
            'the sizes, the refusals, off the event loop, and the callers',
  run: run
};
