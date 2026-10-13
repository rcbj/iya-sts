// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: acvp_pqc.js
//
// ===========================================================================
// NIST ACVP VECTORS FOR FIPS 203 ML-KEM, FIPS 204 ML-DSA AND FIPS 205
// SLH-DSA (#203, 2026-09-24).
//
// The official vectors from usnistgov/ACVP-Server's gen-val/json-files —
// keyGen, sigGen, sigVer and encapDecap, both revisions where there are two
// — held to what this service does with each algorithm, through
// common/crypto.js wherever crypto.js has a door, and through the vendored
// engine crypto.js and `pki.js` share (`common/vendored/pqc_x509.js`) where
// crypto.js has none. Every vector set is read and every test group is
// either APPLIED or counted as not applicable with its reason; nothing is
// skipped silently.
//
// WHAT THIS SERVICE HAS, which decides what applies:
//
//   ML-DSA-44/65/87   signs JWS (pure, EMPTY context, HEDGED — node's
//                     OpenSSL since #363, which has no deterministic switch),
//                     holding the private key as the 32-byte seed; so a
//                     sigGen case is held as: the service's own signature
//                     from NIST's seed verifies under NIST's public key and
//                     differs from NIST's deterministic one, and NIST's
//                     signature verifies at every door. It verifies JWS,
//                     COSE (WebAuthn), XML
//                     (node's OpenSSL) and raw proofs (the vendored engine).
//                     Composites use the ML-DSA label as a context internally
//                     and are not an ACVP algorithm.
//   SLH-DSA           JWS signs and verifies SHA2-128s and SHAKE-128s,
//                     hedged, pure, empty context, the private key being sk
//                     itself; XML and raw proofs verify all twelve parameter
//                     sets. No door derives a key from given seeds (node's
//                     OpenSSL generates from its own), so keyGen is held as
//                     sk -> pk and a signature by sk verifying under pk.
//   ML-KEM-512/768/1024  key generation (EST /serverkeygen, through the
//                     vendored engine from a 64-octet d || z seed) and, since
//                     #82, DECAPSULATION (and encapsulation, which node's
//                     OpenSSL does only with its own randomness, so the
//                     encapsulation vectors, made with a given m, do not
//                     apply since #363) through
//                     common/crypto.js's JWE key establishment (section 4a):
//                     the ML-KEM JWE algs and HPKE's ML-KEM and hybrid KEMs.
//                     Its keys are the d || z seed only, so an EXPANDED
//                     decapsulation key has no door; the encapsulation key
//                     check (FIPS 203 section 7.2) is crypto.js's own.
//
// SO: no door takes a context string, the pre-hash (HashML-DSA,
// HashSLH-DSA) variants, the internal interface or an external mu; ML-DSA
// signing is from a seed only, so an EXPANDED-key sigGen case cannot be
// signed here — its expected signature is held to every verify door instead.
// Those groups are counted and named in the log.
//
// The corpus is fetched when the tests image is built
// (tests/tools/fetch-vectors.sh) into tests/vectors/acvp/; STS_ACVP_DIR
// overrides that. tests/CLAUDE.md, *The external test vectors*, carries the
// provenance (NIST, public domain).
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'acvp_pqc',
  level: process.env.LOG_LEVEL || 'info' });

const DIR = process.env.STS_ACVP_DIR ||
  path.join(__dirname, 'vectors', 'acvp');

const COSE = { 'ML-DSA-44': -48, 'ML-DSA-65': -49, 'ML-DSA-87': -50 };

let crypto = null;
let pqcX509 = null;
let pqc = null;

// hex() is a hot path: every vector field; no Entering/Leaving pair.
function hex(s) {
  return Buffer.from(String(s || ''), 'hex');
}

function load(set) {
  log.debug('Entering load(). ' + set);
  const file = path.join(DIR, set, 'internalProjection.json');
  const json = JSON.parse(fs.readFileSync(file, 'utf8'));
  log.debug('Leaving load().');
  return json;
}

// A tally per vector set: what passed, what failed, and what was not
// applicable, by reason.
// tally() is a hot path.
function tally() {
  return { pass: 0, fail: 0, na: {}, failures: [] };
}

// notApplicable() is a hot path.
function notApplicable(tl, why, n) {
  tl.na[why] = (tl.na[why] || 0) + n;
}

// record() is a hot path: once per vector and door.
function record(tl, ok, what) {
  if (ok) {
    tl.pass++;
  } else {
    tl.fail++;
    tl.failures.push(what);
  }
}

function report(t, set, tl) {
  log.debug('Entering report(). ' + set);
  const na = Object.keys(tl.na).map(function (why) {
    return tl.na[why] + ' ' + why;
  });
  t.check(tl.fail === 0 && tl.pass > 0, set + ': ' + tl.pass + ' passed, ' +
    tl.fail + ' failed' + (na.length ? '; not applicable: ' +
    na.join('; ') : ''), tl.failures.slice(0, 10).join('; '));
  log.debug('Leaving report().');
}

// A signature an independent verifier — node's OpenSSL, from the vector's
// public key — accepts.
// nodeVerifies() is a hot path.
function nodeVerifies(alg, pk, msg, sig) {
  const spki = Buffer.from(pqcX509.encodeSpki(alg, pk));
  return nodeCrypto.verify(null, msg, nodeCrypto.createPublicKey(
    { key: spki, format: 'der', type: 'spki' }), sig);
}

// hedgedDiffersAndVerifies() is a hot path: once per deterministic case.
// What the service ACTUALLY signs with (#203, #363): FIPS 204/205's hedged
// variant, so it is not NIST's deterministic signature, and it verifies
// under NIST's public key — which also shows the key the service derives
// from NIST's seed is NIST's.
function hedgedDiffersAndVerifies(tl, alg, priv, pk, msg, deterministic,
                                  what) {
  const hedged = crypto.jwsSignatureOver(alg, priv, msg);
  record(tl, !hedged.equals(deterministic) && nodeVerifies(alg, pk, msg,
                                                           hedged),
         what + ' the default signature is hedged and verifies');
}

// Every verify door this service has for `alg`, over one signature: which
// accepted. JWS for the JOSE algorithms, COSE for ML-DSA, XML (node) and the
// raw proof (vendored engine) for every ML-DSA and SLH-DSA set.
// verifyDoors() is a hot path: once per signature.
async function verifyDoors(alg, pk, msg, sig) {
  const answers = {};
  const guard = function (fn) {
    try {
      return !!fn();
    } catch (e) {
      log.debug('Caught in verifyDoors(): ' + ((e && e.message) || e));
      return false;
    }
  };
  if (crypto.JWS_SIGNING_ALGS.indexOf(alg) >= 0) {
    answers.jws = guard(function () {
      return crypto.jwsSignatureValid(alg, pk, msg, sig);
    });
  }
  if (COSE[alg]) {
    answers.cose = crypto.verifyCoseSignature(COSE[alg], pk, msg, sig);
  }
  const spki = Buffer.from(pqcX509.encodeSpki(alg, pk));
  answers.raw = await crypto.verifyRawSignature({ family: 'pq' }, spki, msg,
                                                sig);
  const uri = crypto.xmlSignatureAlgorithms().verified.filter(function (r) {
    return r.family === 'pq' && r.keyTypes.indexOf(alg.toLowerCase()) >= 0;
  })[0];
  if (uri) {
    answers.xml = guard(function () {
      return crypto.verifyXmlSignatureValue(uri.uri, nodeCrypto.createPublicKey(
        { key: spki, format: 'der', type: 'spki' }), msg, sig);
    });
  }
  return answers;
}

// verifyEverywhere() is a hot path.
async function verifyEverywhere(tl, alg, t, expected, what) {
  const answers = await verifyDoors(alg, hex(t.pk), hex(t.message),
                                    hex(t.signature));
  Object.keys(answers).forEach(function (door) {
    record(tl, answers[door] === expected, what + ' ' + door + ' ' +
           (answers[door] ? 'accepted' : 'refused'));
  });
}

// Why a signature group or case reaches no door, or '' when it does.
// signatureScope() is a hot path.
function signatureScope(g, t) {
  if (g.signatureInterface === 'internal') {
    return g.externalMu ? 'external-mu cases (no door takes mu)'
                        : 'internal-interface cases (no door signs M\')';
  }
  if (g.preHash === 'preHash') {
    return 'pre-hash (HashML-DSA / HashSLH-DSA) cases (no door offers it)';
  }
  if (t && t.context) {
    return 'cases with a context string (every door uses the empty one)';
  }
  return '';
}

// ---------------------------------------------------------------------------
// ML-DSA (FIPS 204).
// ---------------------------------------------------------------------------
async function mlDsaKeyGen(t) {
  log.debug('Entering mlDsaKeyGen().');
  const set = 'ML-DSA-keyGen-FIPS204';
  const tl = tally();
  const json = load(set);
  for (const g of json.testGroups) {
    const alg = g.parameterSet;
    for (const v of g.tests) {
      const seed = hex(v.seed);
      // crypto.js's JWS signer holds the key AS the seed, so a signature it
      // makes from NIST's seed verifying under NIST's pk is the keyGen.
      const sig = crypto.jwsSignatureOver(alg, seed, Buffer.from('acvp'));
      record(tl, nodeVerifies(alg, hex(v.pk), Buffer.from('acvp'), sig),
             alg + ' tc' + v.tcId + ' JWS signer from the seed');
      // The vendored engine pki.js keeps a certificate's key with.
      record(tl, Buffer.from(pqcX509.publicFromPrivate(alg, seed))
        .equals(hex(v.pk)), alg + ' tc' + v.tcId + ' publicFromPrivate');
      record(tl, Buffer.from(pqcX509.expandPrivate(pqcX509.alg(alg), seed))
        .equals(hex(v.sk)), alg + ' tc' + v.tcId + ' expandPrivate');
    }
  }
  report(t, set, tl);
  log.debug('Leaving mlDsaKeyGen().');
}

async function mlDsaSigGen(t, set) {
  log.debug('Entering mlDsaSigGen(). ' + set);
  const tl = tally();
  const json = load(set);
  for (const g of json.testGroups) {
    const alg = g.parameterSet;
    for (const v of g.tests) {
      const why = signatureScope(g, v);
      if (why) {
        notApplicable(tl, why, 1);
        continue;
      }
      const what = alg + ' tg' + g.tgId + ' tc' + v.tcId;
      if (g.deterministic && v.seed && g.keyFormat === 'seed') {
        // The service signs hedged from the seed (#363: node's OpenSSL has
        // no deterministic switch), so NIST's bytes cannot be reproduced;
        // the signature must verify under NIST's key and differ from
        // NIST's deterministic one.
        hedgedDiffersAndVerifies(tl, alg, hex(v.seed), hex(v.pk),
                                 hex(v.message), hex(v.signature), what);
      } else {
        notApplicable(tl, (g.deterministic ? 'expanded-key' : 'hedged') +
          ' signing (checked below as verification instead)', 1);
      }
      await verifyEverywhere(tl, alg, v, true, what);
    }
  }
  report(t, set, tl);
  log.debug('Leaving mlDsaSigGen().');
}

async function sigVer(t, set) {
  log.debug('Entering sigVer(). ' + set);
  const tl = tally();
  const json = load(set);
  for (const g of json.testGroups) {
    for (const v of g.tests) {
      const why = signatureScope(g, v);
      if (why) {
        notApplicable(tl, why, 1);
        continue;
      }
      await verifyEverywhere(tl, g.parameterSet, v, v.testPassed === true ||
        v.testPassed === 'True', g.parameterSet + ' tg' + g.tgId + ' tc' +
        v.tcId + ' (' + (v.reason || 'valid') + ')');
    }
  }
  report(t, set, tl);
  log.debug('Leaving sigVer().');
}

// ---------------------------------------------------------------------------
// SLH-DSA (FIPS 205).
// ---------------------------------------------------------------------------
async function slhDsaKeyGen(t) {
  log.debug('Entering slhDsaKeyGen().');
  const set = 'SLH-DSA-keyGen-FIPS205';
  const tl = tally();
  const json = load(set);
  for (const g of json.testGroups) {
    const alg = g.parameterSet;
    for (const v of g.tests) {
      // No door derives an SLH-DSA key from caller-chosen seeds: every
      // path (pq_jose.generate(), the engine's generateAkpKeyPair()) is
      // node's OpenSSL generating from its own randomness since #363. What
      // is held: the public key the engine pairs with NIST's private key
      // (FIPS 205 section 9.1) is NIST's, and a signature by that private
      // key, through the engine, verifies under NIST's public key.
      record(tl, Buffer.from(pqcX509.publicFromPrivate(alg, hex(v.sk)))
        .equals(hex(v.pk)), alg + ' tc' + v.tcId + ' publicFromPrivate');
      const probe = Buffer.from('acvp ' + alg + ' tc' + v.tcId);
      record(tl, nodeVerifies(alg, hex(v.pk), probe, Buffer.from(
        pqc.signWithPriv(alg, probe, hex(v.sk)))),
        alg + ' tc' + v.tcId + ' sk signs for pk');
      notApplicable(tl, 'key generation from given seeds (no door takes ' +
        'them; node\'s OpenSSL generates from its own)', 1);
    }
  }
  report(t, set, tl);
  log.debug('Leaving slhDsaKeyGen().');
}

async function slhDsaSigGen(t) {
  log.debug('Entering slhDsaSigGen().');
  const set = 'SLH-DSA-sigGen-FIPS205';
  const tl = tally();
  const json = load(set);
  for (const g of json.testGroups) {
    const alg = g.parameterSet;
    for (const v of g.tests) {
      const why = signatureScope(g, v);
      if (why) {
        notApplicable(tl, why, 1);
        continue;
      }
      const what = alg + ' tg' + g.tgId + ' tc' + v.tcId;
      if (g.deterministic && crypto.JWS_SIGNING_ALGS.indexOf(alg) >= 0) {
        // Hedged since #363, as ML-DSA's sigGen above says.
        hedgedDiffersAndVerifies(tl, alg, hex(v.sk), hex(v.pk),
                                 hex(v.message), hex(v.signature), what);
      } else {
        notApplicable(tl, g.deterministic ? 'signing with a set no JWS ' +
          'algorithm names (checked below as verification)' : 'hedged ' +
          'signing with NIST\'s randomness (checked below as ' +
          'verification)', 1);
      }
      await verifyEverywhere(tl, alg, v, true, what);
    }
  }
  report(t, set, tl);
  log.debug('Leaving slhDsaSigGen().');
}

// ---------------------------------------------------------------------------
// ML-KEM (FIPS 203).
// ---------------------------------------------------------------------------
async function mlKemKeyGen(t) {
  log.debug('Entering mlKemKeyGen().');
  const set = 'ML-KEM-keyGen-FIPS203';
  const tl = tally();
  const json = load(set);
  for (const g of json.testGroups) {
    const alg = g.parameterSet;
    for (const v of g.tests) {
      // The seed the vendored engine keeps an ML-KEM key as (RFC 9935's
      // seed arm) is d || z, FIPS 203 algorithm 16's two inputs.
      const seed = Buffer.concat([hex(v.d), hex(v.z)]);
      record(tl, Buffer.from(pqcX509.publicFromPrivate(alg, seed))
        .equals(hex(v.ek)), alg + ' tc' + v.tcId + ' ek');
      record(tl, Buffer.from(pqcX509.expandPrivate(pqcX509.alg(alg), seed))
        .equals(hex(v.dk)), alg + ' tc' + v.tcId + ' dk');
    }
  }
  report(t, set, tl);
  log.debug('Leaving mlKemKeyGen().');
}

// THE HPKE ML-KEM KEM IDS (draft-ietf-hpke-pq-05 Table 2), the door
// common/crypto.js encapsulates and decapsulates through.
const MLKEM_KEM_ID = { 'ML-KEM-512': 0x0040, 'ML-KEM-768': 0x0041,
                       'ML-KEM-1024': 0x0042 };

// Decapsulation from the seed and the encapsulation key check — through
// crypto.js since #82. Encapsulation vectors are made with FIPS 203
// Encaps_internal and a given m, which node's OpenSSL does not take (#363), so
// they are counted and named; the decapsulation groups hold the same arithmetic
// from the receiving side. Decapsulation from an EXPANDED key, and the
// decapsulation key check (which is of an expanded key), have no door: this
// service holds an ML-KEM key as its 64-octet seed only
// (draft-ietf-jose-pqc-kem-06 section 8, draft-ietf-hpke-pq section 3), so
// those groups are counted and named.
function mlKemEncapDecap(t, set) {
  log.debug('Entering mlKemEncapDecap(). ' + set);
  const tl = tally();
  const json = load(set);
  json.testGroups.forEach(function (g) {
    const alg = g.parameterSet;
    const kemId = MLKEM_KEM_ID[alg];
    if (g.function === 'encapsulation') {
      notApplicable(tl, 'encapsulation with a given m (Encaps_internal) — ' +
        'node\'s OpenSSL takes no randomness', g.tests.length);
    } else if (g.function === 'encapsulationKeyCheck') {
      g.tests.forEach(function (v) {
        let passed = true;
        try {
          crypto.hpke.mlkemCheckEncapsulationKey(alg, hex(v.ek));
        } catch (e) {
          log.debug('Caught in mlKemEncapDecap(): ' + ((e && e.message) || e));
          passed = false;
        }
        record(tl, passed === v.testPassed,
               alg + ' tc' + v.tcId + ' encapsulationKeyCheck');
      });
    } else if (g.function === 'decapsulation' && g.keyFormat === 'seed') {
      g.tests.forEach(function (v) {
        const seed = Buffer.concat([hex(v.d), hex(v.z)]);
        record(tl, crypto.hpke.decap(kemId, hex(v.c), seed).equals(hex(v.k)),
               alg + ' tc' + v.tcId + ' decapsulation (seed)');
      });
    } else {
      notApplicable(tl, g.function + (g.keyFormat ? ' (' + g.keyFormat +
        ' key)' : ' (expanded key)') + ' — keys here are the d || z seed ' +
        'only', g.tests.length);
    }
  });
  report(t, set, tl);
  log.debug('Leaving mlKemEncapDecap().');
}

module.exports = {
  name: 'acvp_pqc',
  describe: 'NIST ACVP ML-KEM, ML-DSA and SLH-DSA vectors through the ' +
            'service\'s own post-quantum code (#203)',
  run: async function (t) {
    log.debug('Entering run().');
    if (!fs.existsSync(DIR)) {
      t.bad('the ACVP vectors are not at ' + DIR,
        'they are fetched when the tests image is built ' +
        '(tests/tools/fetch-vectors.sh); run this file in that image');
      log.debug('Leaving run(). No corpus.');
      return;
    }
    crypto = require('../common/crypto');
    pqcX509 = require('../common/vendored/pqc_x509');
    pqc = require('../common/vendored/pqc');
    const commit = fs.existsSync(path.join(DIR, 'COMMIT'))
      ? fs.readFileSync(path.join(DIR, 'COMMIT'), 'utf8').trim()
      : '(unstamped)';
    t.log.info('=== ACVP-Server ' + commit + ' ===');
    const started = Date.now();
    await mlDsaKeyGen(t);
    await mlDsaSigGen(t, 'ML-DSA-sigGen-FIPS204');
    await mlDsaSigGen(t, 'ML-DSA-sigGen-FIPS204-tr1');
    await sigVer(t, 'ML-DSA-sigVer-FIPS204');
    await slhDsaKeyGen(t);
    await slhDsaSigGen(t);
    await sigVer(t, 'SLH-DSA-sigVer-FIPS205');
    await mlKemKeyGen(t);
    mlKemEncapDecap(t, 'ML-KEM-encapDecap-FIPS203');
    mlKemEncapDecap(t, 'ML-KEM-encapDecap-FIPS203-tr1');
    t.log.info('ACVP: ' + Math.round((Date.now() - started) / 1000) + ' s');
    log.debug('Leaving run().');
  }
};
