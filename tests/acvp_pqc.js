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
//   ML-DSA-44/65/87   signs JWS (pure, EMPTY context, DETERMINISTIC — noble's
//                     default with no randomness), holding the private key as
//                     the 32-byte seed; verifies JWS, COSE (WebAuthn), XML
//                     (node's OpenSSL) and raw proofs (the vendored engine).
//                     Composites use the ML-DSA label as a context internally
//                     and are not an ACVP algorithm.
//   SLH-DSA           JWS signs and verifies SHA2-128s and SHAKE-128s,
//                     deterministic, pure, empty context, the private key
//                     being sk itself; XML and raw proofs verify all twelve
//                     parameter sets.
//   ML-KEM-512/768/1024  KEY GENERATION only (EST /serverkeygen, through the
//                     vendored engine from a 64-octet d || z seed). Nothing
//                     here encapsulates or decapsulates: no protocol this
//                     service speaks has an ML-KEM method.
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
        // crypto.js signs deterministically from the seed: the bytes must be
        // NIST's.
        const sig = crypto.jwsSignatureOver(alg, hex(v.seed), hex(v.message));
        record(tl, sig.equals(hex(v.signature)), what + ' JWS signer bytes');
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
      // No crypto.js door derives an SLH-DSA key from caller-chosen seeds;
      // the one keygen every path reaches (pq_jose.generate(), the vendored
      // engine's generateAkpKeyPair()) is noble's, which is called here WITH
      // NIST's three seeds. And the public key the engine pairs with a
      // private one (FIPS 205 section 9.1) must be NIST's.
      const kp = pqc.signatureAlg(alg).prim.keygen(Buffer.concat(
        [hex(v.skSeed), hex(v.skPrf), hex(v.pkSeed)]));
      record(tl, Buffer.from(kp.secretKey).equals(hex(v.sk)) &&
        Buffer.from(kp.publicKey).equals(hex(v.pk)),
        alg + ' tc' + v.tcId + ' keygen');
      record(tl, Buffer.from(pqcX509.publicFromPrivate(alg, hex(v.sk)))
        .equals(hex(v.pk)), alg + ' tc' + v.tcId + ' publicFromPrivate');
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
        const sig = crypto.jwsSignatureOver(alg, hex(v.sk), hex(v.message));
        record(tl, sig.equals(hex(v.signature)), what + ' JWS signer bytes');
      } else {
        notApplicable(tl, g.deterministic ? 'signing with a set no JWS ' +
          'algorithm names (checked below as verification)' : 'hedged ' +
          'signing — crypto.js signs deterministically (checked below as ' +
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

function mlKemEncapDecap(t, set) {
  log.debug('Entering mlKemEncapDecap(). ' + set);
  const json = load(set);
  let cases = 0;
  const functions = {};
  json.testGroups.forEach(function (g) {
    cases += g.tests.length;
    functions[g.function] = true;
  });
  // Read, counted and named: this is the honest answer rather than a
  // silent omission.
  t.check(cases > 0, set + ': ' + cases + ' cases (' +
    Object.keys(functions).join(', ') + ') not applicable — nothing in this ' +
    'service encapsulates or decapsulates, and no key it accepts from ' +
    'outside is an ML-KEM encapsulation key (a CSR carrying one is refused, ' +
    'STS-ENROLL-0032)', cases ? '' : 'the vector set is empty');
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
