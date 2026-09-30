// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: pq_native.js
//
// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204), SLH-DSA (FIPS 205) AND ML-KEM (FIPS 203) ON NODE'S
// OPENSSL (#363, 2026-09-30).
//
// Until #363 every post-quantum primitive here was `@noble/post-quantum`,
// JavaScript on the V8 heap, and slow enough that an SLH-DSA signature held
// the event loop for SECONDS — which is what `common/worker_pool.js` existed
// for: a pool of forked processes, each a whole node runtime of ~90 MB, to
// compute off the main thread. Node 24 is built on OpenSSL 3.5, which
// implements all three standards in C. Measured in the service image (node
// 24.16, OpenSSL 3.5.6): ML-DSA keygen 1-2 ms and a signature ~1 ms,
// ML-KEM keygen 0.1-0.3 ms, SLH-DSA-SHA2-128s sign 234 ms and SHAKE-128s
// 637 ms — the `s` sets are slow by design, in C too. So:
//
//   * the synchronous functions below are what every caller used before,
//     now native — fast enough inline for everything but SLH-DSA signing
//     and key generation;
//   * the `*Async` functions run on LIBUV'S THREAD POOL (node's own
//     `crypto.sign(..., callback)`, `generateKeyPair()`, `encapsulate()`),
//     which is native threads and no second V8 heap, so an SLH-DSA
//     signature holds nobody up and needs no worker process.
//
// **THE SHAPE IS @noble/post-quantum 0.4.1's**, argument order included —
// `sign(secretKey, msg, ctx)`, `verify(publicKey, msg, sig, ctx)`,
// `keygen(seed)`, `encapsulate(publicKey)`, `decapsulate(cipherText,
// secretKey)` — because four modules (`pq_jose.js`, `crypto.js`, and the two
// formerly vendored `pqc.js` and `pqc_x509.js`) were written against it, and
// keeping the shape is what kept each of those changes to a require line.
//
// **THE KEY FORMS ARE THE STANDARDS', AND UNCHANGED**, which is what makes
// this a drop-in for keys already stored in product mode. It was checked
// against @noble/post-quantum before that library was removed: from the same
// 32-byte ML-DSA seed, 64-byte ML-KEM seed (d || z) or SLH-DSA secret key,
// OpenSSL derives the same public key, and each verifies the other's
// signatures. `secretKey` is the EXPANDED key for ML-DSA (FIPS 204's sk) and
// ML-KEM (FIPS 203's dk), exactly as noble returned it, and SLH-DSA's own
// secret key; the seeds stay the stored form (RFC 9964 section 3.2,
// pqc-kem section 8), expanded on each use.
//
// THREE THINGS NOBLE HAD AND THIS DOES NOT, each refused loudly rather than
// approximated:
//
//   1. **Deterministic signing.** OpenSSL signs HEDGED (FIPS 204 section
//      3.4, FIPS 205 section 9.2 — the variant both standards recommend) and
//      node exposes no switch. The only callers that asked for determinism
//      were tests reproducing NIST's deterministic vectors; they now verify
//      the vector's signature instead (`tests/acvp_pqc.js`).
//   2. **Derandomized encapsulation** (FIPS 203 Encaps_internal with a given
//      m). Only test vectors (HPKE, X-Wing) passed m; they now check the
//      receiving side, decapsulating the vector's ciphertext.
//   3. **HashML-DSA / HashSLH-DSA** (the pre-hash variants). Node's API
//      signs the pure variants only. Nothing in the service asks for them.
//
// A LEAF: it requires node's crypto, bunyan and config and nothing of this
// service, because `crypto.js` and the PKI modules all reach it.
// ---------------------------------------------------------------------------

// `any`: node 24's crypto takes the `raw-public`, `raw-private` and `raw-seed`
// key formats and the ML-DSA / SLH-DSA / ML-KEM key types, and the
// @types/node this repository checks against does not declare them yet. The
// calls are the documented API (node 24.16); only the declarations lag.
const nodeCrypto = /** @type {any} */ (require('crypto'));
const bunyan = require('bunyan');
const config = require('./config');

let logLevelProblem = null;
const log = bunyan.createLogger({
  name: 'pq_native',
  level: (function () {
    try {
      return config.value('global.logLevel') || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('No log level could be read, so info: ' +
            logLevelProblem.message);
}

// ---------------------------------------------------------------------------
// DER, just enough of it. A PKCS#8 PrivateKeyInfo is built around the key
// bytes, because OpenSSL reads an EXPANDED ML-DSA or ML-KEM private key only
// through PKCS#8 (node's `raw-private` form refuses them), and one is parsed
// back to find the expanded key inside a PKCS#8 that OpenSSL exported.
// ---------------------------------------------------------------------------
function derLength(n) {
  log.debug('Entering derLength().');
  if (n < 0x80) {
    log.debug('Leaving derLength(). Short form.');
    return Buffer.from([n]);
  }
  if (n < 0x100) {
    log.debug('Leaving derLength(). One octet.');
    return Buffer.from([0x81, n]);
  }
  if (n < 0x10000) {
    log.debug('Leaving derLength(). Two octets.');
    return Buffer.from([0x82, n >> 8, n & 0xff]);
  }
  log.debug('Leaving derLength(). Too long.');
  throw new Error('pq_native: a DER element of ' + n + ' octets is longer ' +
                  'than any key this module builds');
}

function der(tag, contents) {
  log.debug('Entering der().');
  const body = Buffer.from(contents);
  log.debug('Leaving der().');
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

// Reads one TLV at `at` and returns its tag, where its contents start and
// where it ends.
function derRead(buf, at) {
  log.debug('Entering derRead().');
  const tag = buf[at];
  let len = buf[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const octets = len & 0x7f;
    len = 0;
    for (let i = 0; i < octets; i++) {
      len = (len * 256) + buf[start + i];
    }
    start += octets;
  }
  if (start + len > buf.length) {
    log.debug('Leaving derRead(). Truncated.');
    throw new Error('pq_native: a DER element runs past its buffer');
  }
  log.debug('Leaving derRead().');
  return { tag: tag, start: start, end: start + len };
}

// ---------------------------------------------------------------------------
// The parameter sets. `oid` is the DER of the NIST algorithm identifier
// (2.16.840.1.101.3.4.3.x for the signatures, .4.x for ML-KEM), which is all
// a PKCS#8 AlgorithmIdentifier holds for these — no parameters. `node` is
// the name node's crypto knows the set by. The sizes are the standards'
// (FIPS 204 Table 2, FIPS 205 Table 2, FIPS 203 Table 3), and they are
// checked against the keys OpenSSL actually produces by
// `tests/pq_native.js`, not trusted.
// ---------------------------------------------------------------------------
const NIST_SIG = '0609608648016503040';
const NIST_KEM = '0609608648016503040';

/**
 * The ML-DSA parameter sets: node's name, the algorithm identifier's DER and
 * the FIPS 204 sizes.
 */
const ML_DSA = {
  'ML-DSA-44': { node: 'ml-dsa-44', oid: NIST_SIG + '311',
                 publicKey: 1312, secretKey: 2560, signature: 2420 },
  'ML-DSA-65': { node: 'ml-dsa-65', oid: NIST_SIG + '312',
                 publicKey: 1952, secretKey: 4032, signature: 3309 },
  'ML-DSA-87': { node: 'ml-dsa-87', oid: NIST_SIG + '313',
                 publicKey: 2592, secretKey: 4896, signature: 4627 }
};

/**
 * The twelve SLH-DSA parameter sets of FIPS 205: node's name and sizes.
 */
const SLH_DSA = {
  'SLH-DSA-SHA2-128s': { node: 'slh-dsa-sha2-128s', n: 16, sig: 7856 },
  'SLH-DSA-SHA2-128f': { node: 'slh-dsa-sha2-128f', n: 16, sig: 17088 },
  'SLH-DSA-SHA2-192s': { node: 'slh-dsa-sha2-192s', n: 24, sig: 16224 },
  'SLH-DSA-SHA2-192f': { node: 'slh-dsa-sha2-192f', n: 24, sig: 35664 },
  'SLH-DSA-SHA2-256s': { node: 'slh-dsa-sha2-256s', n: 32, sig: 29792 },
  'SLH-DSA-SHA2-256f': { node: 'slh-dsa-sha2-256f', n: 32, sig: 49856 },
  'SLH-DSA-SHAKE-128s': { node: 'slh-dsa-shake-128s', n: 16, sig: 7856 },
  'SLH-DSA-SHAKE-128f': { node: 'slh-dsa-shake-128f', n: 16, sig: 17088 },
  'SLH-DSA-SHAKE-192s': { node: 'slh-dsa-shake-192s', n: 24, sig: 16224 },
  'SLH-DSA-SHAKE-192f': { node: 'slh-dsa-shake-192f', n: 24, sig: 35664 },
  'SLH-DSA-SHAKE-256s': { node: 'slh-dsa-shake-256s', n: 32, sig: 29792 },
  'SLH-DSA-SHAKE-256f': { node: 'slh-dsa-shake-256f', n: 32, sig: 49856 }
};

/**
 * The ML-KEM parameter sets: node's name, the algorithm identifier's DER and
 * the FIPS 203 sizes.
 */
const ML_KEM = {
  'ML-KEM-512': { node: 'ml-kem-512', oid: NIST_KEM + '401',
                  publicKey: 800, secretKey: 1632, cipherText: 768 },
  'ML-KEM-768': { node: 'ml-kem-768', oid: NIST_KEM + '402',
                  publicKey: 1184, secretKey: 2400, cipherText: 1088 },
  'ML-KEM-1024': { node: 'ml-kem-1024', oid: NIST_KEM + '403',
                   publicKey: 1568, secretKey: 3168, cipherText: 1568 }
};

function bytes(value) {
  log.debug('Entering bytes().');
  if (value == null) {
    log.debug('Leaving bytes(). Nothing given.');
    throw new Error('pq_native: a key, message or signature is missing');
  }
  log.debug('Leaving bytes().');
  return Buffer.from(value.buffer ? new Uint8Array(value.buffer,
    value.byteOffset, value.byteLength) : value);
}

function out(buffer) {
  log.debug('Entering out().');
  log.debug('Leaving out().');
  return new Uint8Array(buffer);
}

// A PKCS#8 PrivateKeyInfo around a private key as the IETF LAMPS drafts
// define it for these algorithms: `[0] IMPLICIT OCTET STRING` for a seed and
// a plain OCTET STRING for an expanded key.
function pkcs8(oidHex, inner) {
  log.debug('Entering pkcs8().');
  const info = der(0x30, Buffer.concat([
    Buffer.from([0x02, 0x01, 0x00]),
    der(0x30, Buffer.from(oidHex, 'hex')),
    der(0x04, inner)
  ]));
  log.debug('Leaving pkcs8().');
  return nodeCrypto.createPrivateKey({ key: info, format: 'der',
                                       type: 'pkcs8' });
}

// The expanded key out of an OpenSSL-exported PKCS#8. OpenSSL 3.5 writes
// these keys in the "both" form — SEQUENCE { seed OCTET STRING, expandedKey
// OCTET STRING } — or the expanded form alone; either way the expanded key
// is the last OCTET STRING inside the PrivateKeyInfo's privateKey.
function expandedFrom(keyObject) {
  log.debug('Entering expandedFrom().');
  const info = keyObject.export({ format: 'der', type: 'pkcs8' });
  const top = derRead(info, 0);
  const version = derRead(info, top.start);
  const algId = derRead(info, version.end);
  const privateKey = derRead(info, algId.end);
  const choice = derRead(info, privateKey.start);
  if (choice.tag === 0x04) {
    log.debug('Leaving expandedFrom(). Expanded form.');
    return info.subarray(choice.start, choice.end);
  }
  if (choice.tag === 0x30) {
    const seed = derRead(info, choice.start);
    const expanded = derRead(info, seed.end);
    log.debug('Leaving expandedFrom(). Both form.');
    return info.subarray(expanded.start, expanded.end);
  }
  log.debug('Leaving expandedFrom(). Seed only.');
  throw new Error('pq_native: OpenSSL exported this key as a seed only, ' +
                  'with no expanded key to read');
}

function signOptions(key, ctx) {
  log.debug('Entering signOptions().');
  const context = ctx && ctx.length ? bytes(ctx) : null;
  log.debug('Leaving signOptions().');
  return context ? { key: key, context: context } : key;
}

function promised(start) {
  log.debug('Entering promised().');
  log.debug('Leaving promised().');
  return new Promise(function (resolve, reject) {
    start(function (err, value) {
      if (err) {
        reject(err);
        return;
      }
      resolve(value);
    });
  });
}

// ---------------------------------------------------------------------------
// ML-DSA
// ---------------------------------------------------------------------------
function mlDsa(name) {
  const set = ML_DSA[name];
  const fromSeed = function (seed) {
    log.debug('Entering ' + name + ' fromSeed().');
    const s = bytes(seed);
    if (s.length !== 32) {
      log.debug('Leaving ' + name + ' fromSeed(). Wrong seed size.');
      throw new Error('an ' + name + ' seed is 32 octets (FIPS 204 ' +
                      'KeyGen_internal); this one is ' + s.length);
    }
    log.debug('Leaving ' + name + ' fromSeed().');
    return pkcs8(set.oid, der(0x80, s));
  };
  const fromSecret = function (secretKey) {
    log.debug('Entering ' + name + ' fromSecret().');
    const sk = bytes(secretKey);
    if (sk.length === 32) {
      log.debug('Leaving ' + name + ' fromSecret(). A seed.');
      return fromSeed(sk);
    }
    if (sk.length !== set.secretKey) {
      log.debug('Leaving ' + name + ' fromSecret(). Wrong size.');
      throw new Error('an ' + name + ' secret key is ' + set.secretKey +
                      ' octets (or its 32-octet seed); this one is ' +
                      sk.length);
    }
    log.debug('Leaving ' + name + ' fromSecret(). Expanded.');
    return pkcs8(set.oid, der(0x04, sk));
  };
  const publicKeyOf = function (publicKey) {
    log.debug('Entering ' + name + ' publicKeyOf().');
    log.debug('Leaving ' + name + ' publicKeyOf().');
    return nodeCrypto.createPublicKey({ key: bytes(publicKey),
      format: 'raw-public', asymmetricKeyType: set.node });
  };
  const pairOf = function (privateKey) {
    log.debug('Entering ' + name + ' pairOf().');
    const pub = nodeCrypto.createPublicKey(privateKey)
      .export({ format: 'raw-public' });
    log.debug('Leaving ' + name + ' pairOf().');
    return { publicKey: out(pub), secretKey: out(expandedFrom(privateKey)) };
  };
  return {
    name: name,
    lengths: { publicKey: set.publicKey, secretKey: set.secretKey,
               signature: set.signature, seed: 32 },
    // With a seed, FIPS 204 KeyGen_internal from it; without, a fresh seed.
    keygen: function (seed) {
      log.debug('Entering ' + name + ' keygen().');
      const s = seed ? bytes(seed) : nodeCrypto.randomBytes(32);
      const pair = pairOf(fromSeed(s));
      log.debug('Leaving ' + name + ' keygen().');
      return { publicKey: pair.publicKey, secretKey: pair.secretKey,
               seed: out(s) };
    },
    publicFromSeed: function (seed) {
      log.debug('Entering ' + name + ' publicFromSeed().');
      const pub = nodeCrypto.createPublicKey(fromSeed(seed))
        .export({ format: 'raw-public' });
      log.debug('Leaving ' + name + ' publicFromSeed().');
      return out(pub);
    },
    // `secretKey` is the expanded key or the 32-octet seed. Always hedged.
    sign: function (secretKey, msg, ctx) {
      log.debug('Entering ' + name + ' sign().');
      const sig = nodeCrypto.sign(null, bytes(msg),
                                  signOptions(fromSecret(secretKey), ctx));
      log.debug('Leaving ' + name + ' sign().');
      return out(sig);
    },
    verify: function (publicKey, msg, sig, ctx) {
      log.debug('Entering ' + name + ' verify().');
      const s = bytes(sig);
      if (s.length !== set.signature) {
        log.debug('Leaving ' + name + ' verify(). Wrong signature size.');
        return false;
      }
      const ok = nodeCrypto.verify(null, bytes(msg),
                                   signOptions(publicKeyOf(publicKey), ctx),
                                   s);
      log.debug('Leaving ' + name + ' verify(). ok=' + ok);
      return ok;
    },
    signAsync: function (secretKey, msg, ctx) {
      log.debug('Entering ' + name + ' signAsync().');
      const key = signOptions(fromSecret(secretKey), ctx);
      const m = bytes(msg);
      log.debug('Leaving ' + name + ' signAsync(). On libuv.');
      return promised(function (done) {
        nodeCrypto.sign(null, m, key, done);
      }).then(out);
    },
    verifyAsync: function (publicKey, msg, sig, ctx) {
      log.debug('Entering ' + name + ' verifyAsync().');
      const s = bytes(sig);
      if (s.length !== set.signature) {
        log.debug('Leaving ' + name + ' verifyAsync(). Wrong size.');
        return Promise.resolve(false);
      }
      const key = signOptions(publicKeyOf(publicKey), ctx);
      const m = bytes(msg);
      log.debug('Leaving ' + name + ' verifyAsync(). On libuv.');
      return promised(function (done) {
        nodeCrypto.verify(null, m, key, s, done);
      });
    },
    prehash: function (hashName) {
      log.debug('Entering ' + name + ' prehash(). ' + hashName);
      log.debug('Leaving ' + name + ' prehash(). Not available.');
      throw new Error('Hash' + name + ' (pre-hash ' + hashName + ') is not ' +
                      'available: node signs the pure variant of FIPS 204 ' +
                      'only');
    }
  };
}

// ---------------------------------------------------------------------------
// SLH-DSA. Its secret key is SK.seed || SK.prf || PK.seed || PK.root (4n
// octets), which node reads and writes as `raw-private` directly.
// ---------------------------------------------------------------------------
function slhDsa(name) {
  const set = SLH_DSA[name];
  const privateKeyOf = function (secretKey) {
    log.debug('Entering ' + name + ' privateKeyOf().');
    const sk = bytes(secretKey);
    if (sk.length !== 4 * set.n) {
      log.debug('Leaving ' + name + ' privateKeyOf(). Wrong size.');
      throw new Error('an ' + name + ' secret key is ' + (4 * set.n) +
                      ' octets; this one is ' + sk.length);
    }
    log.debug('Leaving ' + name + ' privateKeyOf().');
    return nodeCrypto.createPrivateKey({ key: sk, format: 'raw-private',
                                         asymmetricKeyType: set.node });
  };
  const publicKeyOf = function (publicKey) {
    log.debug('Entering ' + name + ' publicKeyOf().');
    log.debug('Leaving ' + name + ' publicKeyOf().');
    return nodeCrypto.createPublicKey({ key: bytes(publicKey),
      format: 'raw-public', asymmetricKeyType: set.node });
  };
  const pairOf = function (pair) {
    log.debug('Entering ' + name + ' pairOf().');
    log.debug('Leaving ' + name + ' pairOf().');
    return {
      publicKey: out(pair.publicKey.export({ format: 'raw-public' })),
      secretKey: out(pair.privateKey.export({ format: 'raw-private' }))
    };
  };
  return {
    name: name,
    lengths: { publicKey: 2 * set.n, secretKey: 4 * set.n,
               signature: set.sig },
    // FIPS 205 KeyGen_internal from given seeds is not offered by node's
    // API, so a seed is REFUSED rather than ignored: a caller that passed
    // one expects the key those seeds define.
    keygen: function (seed) {
      log.debug('Entering ' + name + ' keygen().');
      if (seed != null) {
        log.debug('Leaving ' + name + ' keygen(). Seeded.');
        throw new Error(name + ' key generation from given seeds ' +
                        '(KeyGen_internal) is not available on node\'s ' +
                        'OpenSSL');
      }
      const pair = pairOf(nodeCrypto.generateKeyPairSync(
        set.node));
      log.debug('Leaving ' + name + ' keygen().');
      return pair;
    },
    keygenAsync: function () {
      log.debug('Entering ' + name + ' keygenAsync().');
      log.debug('Leaving ' + name + ' keygenAsync(). On libuv.');
      return promised(function (done) {
        nodeCrypto.generateKeyPair(set.node, {},
          function (err, publicKey, privateKey) {
            done(err, err ? null : pairOf({ publicKey: publicKey,
                                            privateKey: privateKey }));
          });
      });
    },
    sign: function (secretKey, msg, ctx) {
      log.debug('Entering ' + name + ' sign().');
      const sig = nodeCrypto.sign(null, bytes(msg),
                                  signOptions(privateKeyOf(secretKey), ctx));
      log.debug('Leaving ' + name + ' sign().');
      return out(sig);
    },
    verify: function (publicKey, msg, sig, ctx) {
      log.debug('Entering ' + name + ' verify().');
      const s = bytes(sig);
      if (s.length !== set.sig) {
        log.debug('Leaving ' + name + ' verify(). Wrong signature size.');
        return false;
      }
      const ok = nodeCrypto.verify(null, bytes(msg),
                                   signOptions(publicKeyOf(publicKey), ctx),
                                   s);
      log.debug('Leaving ' + name + ' verify(). ok=' + ok);
      return ok;
    },
    signAsync: function (secretKey, msg, ctx) {
      log.debug('Entering ' + name + ' signAsync().');
      const key = signOptions(privateKeyOf(secretKey), ctx);
      const m = bytes(msg);
      log.debug('Leaving ' + name + ' signAsync(). On libuv.');
      return promised(function (done) {
        nodeCrypto.sign(null, m, key, done);
      }).then(out);
    },
    verifyAsync: function (publicKey, msg, sig, ctx) {
      log.debug('Entering ' + name + ' verifyAsync().');
      const s = bytes(sig);
      if (s.length !== set.sig) {
        log.debug('Leaving ' + name + ' verifyAsync(). Wrong size.');
        return Promise.resolve(false);
      }
      const key = signOptions(publicKeyOf(publicKey), ctx);
      const m = bytes(msg);
      log.debug('Leaving ' + name + ' verifyAsync(). On libuv.');
      return promised(function (done) {
        nodeCrypto.verify(null, m, key, s, done);
      });
    },
    prehash: function (hashName) {
      log.debug('Entering ' + name + ' prehash(). ' + hashName);
      log.debug('Leaving ' + name + ' prehash(). Not available.');
      throw new Error('Hash' + name + ' (pre-hash ' + hashName + ') is not ' +
                      'available: node signs the pure variant of FIPS 205 ' +
                      'only');
    }
  };
}

// ---------------------------------------------------------------------------
// ML-KEM. The 64-octet seed is d || z (FIPS 203 KeyGen_internal), which node
// reads as `raw-seed`; the expanded dk goes in through PKCS#8.
// ---------------------------------------------------------------------------
function mlKem(name) {
  const set = ML_KEM[name];
  const fromSeed = function (seed) {
    log.debug('Entering ' + name + ' fromSeed().');
    const s = bytes(seed);
    if (s.length !== 64) {
      log.debug('Leaving ' + name + ' fromSeed(). Wrong seed size.');
      throw new Error('an ' + name + ' seed is the 64 octets d || z (FIPS ' +
                      '203 KeyGen_internal); this one is ' + s.length);
    }
    log.debug('Leaving ' + name + ' fromSeed().');
    return nodeCrypto.createPrivateKey({ key: s, format: 'raw-seed',
                                         asymmetricKeyType: set.node });
  };
  const fromSecret = function (secretKey) {
    log.debug('Entering ' + name + ' fromSecret().');
    const sk = bytes(secretKey);
    if (sk.length === 64) {
      log.debug('Leaving ' + name + ' fromSecret(). A seed.');
      return fromSeed(sk);
    }
    if (sk.length !== set.secretKey) {
      log.debug('Leaving ' + name + ' fromSecret(). Wrong size.');
      throw new Error('an ' + name + ' decapsulation key is ' +
                      set.secretKey + ' octets (or its 64-octet seed); ' +
                      'this one is ' + sk.length);
    }
    log.debug('Leaving ' + name + ' fromSecret(). Expanded.');
    return pkcs8(set.oid, der(0x04, sk));
  };
  const publicKeyOf = function (publicKey) {
    log.debug('Entering ' + name + ' publicKeyOf().');
    const pk = bytes(publicKey);
    if (pk.length !== set.publicKey) {
      log.debug('Leaving ' + name + ' publicKeyOf(). Wrong size.');
      throw new Error('an ' + name + ' encapsulation key is ' +
                      set.publicKey + ' octets; this one is ' + pk.length);
    }
    log.debug('Leaving ' + name + ' publicKeyOf().');
    return nodeCrypto.createPublicKey({ key: pk, format: 'raw-public',
                                        asymmetricKeyType: set.node });
  };
  return {
    name: name,
    lengths: { publicKey: set.publicKey, secretKey: set.secretKey,
               cipherText: set.cipherText, sharedSecret: 32, seed: 64 },
    keygen: function (seed) {
      log.debug('Entering ' + name + ' keygen().');
      const s = seed ? bytes(seed) : nodeCrypto.randomBytes(64);
      const key = fromSeed(s);
      const pub = nodeCrypto.createPublicKey(key)
        .export({ format: 'raw-public' });
      log.debug('Leaving ' + name + ' keygen().');
      return { publicKey: out(pub), secretKey: out(expandedFrom(key)),
               seed: out(s) };
    },
    publicFromSeed: function (seed) {
      log.debug('Entering ' + name + ' publicFromSeed().');
      const pub = nodeCrypto.createPublicKey(fromSeed(seed))
        .export({ format: 'raw-public' });
      log.debug('Leaving ' + name + ' publicFromSeed().');
      return out(pub);
    },
    // FIPS 203 Encaps. A second argument would be Encaps_internal's m, which
    // node does not take; refusing it is better than ignoring it, because a
    // caller that passed one expects a reproducible ciphertext.
    encapsulate: function (publicKey, m) {
      log.debug('Entering ' + name + ' encapsulate().');
      if (m != null) {
        log.debug('Leaving ' + name + ' encapsulate(). Derandomized.');
        throw new Error(name + ' encapsulation with given randomness ' +
                        '(Encaps_internal) is not available on node\'s ' +
                        'OpenSSL');
      }
      const r = nodeCrypto.encapsulate(publicKeyOf(publicKey));
      log.debug('Leaving ' + name + ' encapsulate().');
      return { cipherText: out(r.ciphertext),
               sharedSecret: out(r.sharedKey) };
    },
    // `secretKey` is the expanded dk or the 64-octet seed.
    decapsulate: function (cipherText, secretKey) {
      log.debug('Entering ' + name + ' decapsulate().');
      const ct = bytes(cipherText);
      if (ct.length !== set.cipherText) {
        log.debug('Leaving ' + name + ' decapsulate(). Wrong size.');
        throw new Error('an ' + name + ' ciphertext is ' + set.cipherText +
                        ' octets; this one is ' + ct.length);
      }
      const ss = nodeCrypto.decapsulate(fromSecret(secretKey), ct);
      log.debug('Leaving ' + name + ' decapsulate().');
      return out(ss);
    }
  };
}

// Written out rather than built from SLH_DSA's keys, so the names are
// visible to a reader and to the type checker alike.
const exported = {
  ML_DSA: ML_DSA,
  SLH_DSA: SLH_DSA,
  ML_KEM: ML_KEM,
  ml_dsa44: mlDsa('ML-DSA-44'),
  ml_dsa65: mlDsa('ML-DSA-65'),
  ml_dsa87: mlDsa('ML-DSA-87'),
  slh_dsa_sha2_128s: slhDsa('SLH-DSA-SHA2-128s'),
  slh_dsa_sha2_128f: slhDsa('SLH-DSA-SHA2-128f'),
  slh_dsa_sha2_192s: slhDsa('SLH-DSA-SHA2-192s'),
  slh_dsa_sha2_192f: slhDsa('SLH-DSA-SHA2-192f'),
  slh_dsa_sha2_256s: slhDsa('SLH-DSA-SHA2-256s'),
  slh_dsa_sha2_256f: slhDsa('SLH-DSA-SHA2-256f'),
  slh_dsa_shake_128s: slhDsa('SLH-DSA-SHAKE-128s'),
  slh_dsa_shake_128f: slhDsa('SLH-DSA-SHAKE-128f'),
  slh_dsa_shake_192s: slhDsa('SLH-DSA-SHAKE-192s'),
  slh_dsa_shake_192f: slhDsa('SLH-DSA-SHAKE-192f'),
  slh_dsa_shake_256s: slhDsa('SLH-DSA-SHAKE-256s'),
  slh_dsa_shake_256f: slhDsa('SLH-DSA-SHAKE-256f'),
  ml_kem512: mlKem('ML-KEM-512'),
  ml_kem768: mlKem('ML-KEM-768'),
  ml_kem1024: mlKem('ML-KEM-1024')
};

/**
 * ML-DSA, SLH-DSA and ML-KEM on node's OpenSSL, in @noble/post-quantum
 * 0.4.1's shape: `ml_dsa44`/`65`/`87`, the twelve `slh_dsa_*` sets and
 * `ml_kem512`/`768`/`1024`, each with synchronous operations and, for the
 * signatures, `*Async` forms that run on libuv's thread pool.
 * @namespace
 */
module.exports = exported;
