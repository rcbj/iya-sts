// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

'use strict';
//
// File: jwe_pq_kem.js
//
// ===========================================================================
// POST-QUANTUM AND HPKE KEY ESTABLISHMENT IN JWE (#82, 2026-09-27).
//
// `common/crypto.js` section 4a, held to answers that are not its own:
//
//   A. draft-ietf-hpke-pq-05's published vectors — every suite in the file:
//      ML-KEM-512/768/1024, the three PQ/T hybrids (X-Wing among them) and
//      the classical DHKEMs, over HKDF, SHAKE and TurboSHAKE, with AES-GCM
//      and ChaCha20-Poly1305: DeriveKeyPair, Decap of the vector's `enc`,
//      the key schedule, every decryption and every export — from the
//      RECEIVING side since #363, because the vectors' Encap used a given
//      ikmE and ML-KEM on node's OpenSSL takes no randomness — and a round
//      trip through an Encap with our own.
//   B. draft-irtf-cfrg-concrete-hybrid-kems' vectors: key expansion from the
//      seed, decapsulation of the vector's ciphertext, and a round trip
//      (the same reason as A).
//   C. The JOSE working group's HPKE JWEs (draft-ietf-jose-hpke-encrypt-22's
//      repository): each compact JWE decrypted through `decryptJweCompact()`
//      with the vector's key — HPKE-0 to HPKE-7, Integrated and Key
//      Encryption. HPKE-4-KE and HPKE-6-KE are counted as not applicable:
//      -22 removed them. The flattened JSON serialisations are not
//      applicable: this service speaks the compact serialisation only.
//   D. node's own OpenSSL ML-KEM (node 24): a ciphertext node encapsulated
//      decapsulates here to node's key, and one encapsulated here decapsulates
//      in node. Since #363 the primitive here IS node's OpenSSL, so this
//      holds the key and ciphertext plumbing around it (the seed, the
//      encapsulation key check) rather than a second implementation.
//   E. Every post-quantum and HPKE alg against every `enc`, through the two
//      public functions, and the refusals a wrong key or a malformed JWE gets.
//   F. pqc-kem-05's KMAC256 derivation rebuilt here from the draft's own
//      description (no draft carries a vector for it), the realm-key setting's
//      value list against crypto.js's table, a derived key pair's
//      determinism, and the cost that decided the worker pool question.
//
// The A-C corpora are fetched when the tests image is built
// (tests/tools/fetch-vectors.sh, into tests/vectors/hpke/); STS_HPKE_DIR
// overrides that. Nothing here is committed key material.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'jwe_pq_kem',
  level: process.env.LOG_LEVEL || 'info' });

const DIR = process.env.STS_HPKE_DIR ||
  path.join(__dirname, 'vectors', 'hpke');

let crypto = null;

// hex() is a hot path: every vector field; no Entering/Leaving pair.
function hex(s) {
  return Buffer.from(String(s || ''), 'hex');
}

function load(name) {
  log.debug('Entering load(). ' + name);
  const out = JSON.parse(fs.readFileSync(path.join(DIR, name), 'utf8'));
  log.debug('Leaving load().');
  return out;
}

// A refusal: `fn` must throw, and its message must match `pattern`.
function refuses(t, fn, pattern, what) {
  log.debug('Entering refuses(). ' + what);
  let message = '';
  try {
    fn();
  } catch (e) {
    log.debug('Caught in refuses(): ' + ((e && e.message) || e));
    message = String((e && e.message) || e);
  }
  t.check(!!message && pattern.test(message), 'refused: ' + what,
          message || 'it was not refused');
  log.debug('Leaving refuses().');
}

// ---------------------------------------------------------------------------
// A. draft-ietf-hpke-pq-05.
// ---------------------------------------------------------------------------
function hpkePq(t) {
  log.debug('Entering hpkePq().');
  const h = crypto.hpke;
  let pass = 0;
  const failures = [];
  load('hpke-pq.json').forEach(function (v) {
    const tag = 'kem 0x' + v.kem_id.toString(16) + ' kdf 0x' +
                v.kdf_id.toString(16) + ' aead 0x' + v.aead_id.toString(16);
    try {
      const kp = h.deriveKeyPair(v.kem_id, hex(v.ikmR));
      const suite = { kem: v.kem_id, kdf: v.kdf_id, aead: v.aead_id };
      const psk = v.psk ? { psk: hex(v.psk), pskId: hex(v.psk_id) } : {};
      // FROM THE RECEIVING SIDE since #363: the vectors' `enc` is made with
      // a given ikmE, and ML-KEM on node's OpenSSL takes no randomness, so
      // the receiver is set up on the vector's `enc` and must reach the
      // vector's secret, key schedule, plaintexts and exports; a sender with
      // its own randomness must then round-trip with that receiver's key.
      const r = h.setupReceiver(suite, hex(v.enc), kp.sk,
                                Object.assign({ info: hex(v.info) }, psk));
      const s = h.setupSender(suite, kp.pk, Object.assign({
        info: hex(v.info) }, psk));
      const back = h.setupReceiver(suite, s.enc, kp.sk,
                                   Object.assign({ info: hex(v.info) }, psk));
      const checks = [
        ['skRm', kp.sk.equals(hex(v.skRm))],
        ['pkRm', kp.pk.equals(hex(v.pkRm))],
        ['shared_secret', r.sharedSecret.equals(hex(v.shared_secret))],
        ['key', r.context.key.equals(hex(v.key))],
        ['base_nonce', r.context.baseNonce.equals(hex(v.base_nonce))],
        ['exporter_secret', r.context.exporterSecret
          .equals(hex(v.exporter_secret))],
        ['round trip', s.sharedSecret.equals(back.sharedSecret)]
      ];
      (v.encryptions || []).forEach(function (e, i) {
        r.context.seq = typeof e.seq === 'number' ? e.seq : i;
        checks.push(['ct ' + i,
                     r.context.open(hex(e.aad), hex(e.ct)).equals(hex(e.pt))]);
      });
      (v.exports || []).forEach(function (x, i) {
        checks.push(['export ' + i, r.context.exportSecret(
          hex(x.exporter_context), x.L).equals(hex(x.exported_value))]);
      });
      const bad = checks.filter(function (c) {
        return !c[1];
      });
      if (bad.length) {
        failures.push(tag + ': ' + bad.map(function (c) {
          return c[0];
        }).join(', '));
      } else {
        pass++;
      }
    } catch (e) {
      log.debug('Caught in hpkePq(): ' + ((e && e.message) || e));
      failures.push(tag + ': threw ' + e.message);
    }
  });
  t.check(pass > 0 && !failures.length, 'draft-ietf-hpke-pq-05: ' + pass +
          ' suite(s) reproduced from the receiving side, key pair to ' +
          'export', failures.join('; '));
  log.debug('Leaving hpkePq().');
}

// ---------------------------------------------------------------------------
// B. The concrete hybrid KEMs.
// ---------------------------------------------------------------------------
const HYBRID_NAMES = { mlkem768_p256: 'MLKEM768-P256',
                       mlkem768_x25519: 'MLKEM768-X25519',
                       mlkem1024_p384: 'MLKEM1024-P384' };

function concreteHybrids(t) {
  log.debug('Entering concreteHybrids().');
  const h = crypto.hpke;
  const json = load('concrete-hybrid-kems.json');
  Object.keys(json).forEach(function (key) {
    const name = HYBRID_NAMES[key];
    let pass = 0;
    const failures = [];
    if (!name) {
      t.check(false, 'a hybrid KEM this test does not name: ' + key, '');
      return;
    }
    json[key].forEach(function (v, i) {
      try {
        const seed = hex(v.seed);
        const x = h.hybridExpand(name, seed);
        // The vector's ciphertext is decapsulated (#363: its encapsulation
        // used given randomness, which node's ML-KEM does not take), and an
        // encapsulation with our own randomness must round-trip.
        const e = h.hybridEncaps(name, x.ek);
        const ok = x.ek.equals(hex(v.encapsulation_key)) &&
                   h.hybridDecaps(name, seed, hex(v.ciphertext))
                     .equals(hex(v.shared_secret)) &&
                   h.hybridDecaps(name, seed, e.ct).equals(e.ss);
        if (ok) {
          pass++;
        } else {
          failures.push(name + ' #' + i);
        }
      } catch (err) {
        log.debug('Caught in concreteHybrids(): ' +
                  ((err && err.message) || err));
        failures.push(name + ' #' + i + ' threw ' + err.message);
      }
    });
    t.check(pass > 0 && !failures.length, 'concrete hybrid KEM ' + name + ': ' +
            pass + ' vector(s), keys, decapsulation and a round trip',
            failures.join('; '));
  });
  log.debug('Leaving concreteHybrids().');
}

// ---------------------------------------------------------------------------
// C. The JOSE working group's HPKE JWEs.
// ---------------------------------------------------------------------------
function joseHpke(t) {
  log.debug('Entering joseHpke().');
  let pass = 0;
  const na = [];
  const failures = [];
  load('jose-hpke.json').forEach(function (v) {
    if (crypto.JWE_HPKE_ALGS.indexOf(v.alg) < 0) {
      na.push(v.alg);
      return;
    }
    try {
      const opened = crypto.decryptJweCompact(v.compact,
                                              { privateJwk: v.jwk });
      const pub = crypto.publicJweKemJwk(v.jwk);
      const mine = crypto.encryptJweCompact(opened.plaintext,
        { alg: v.alg, enc: 'A256GCM', jwk: pub });
      const back = crypto.decryptJweCompact(mine, { privateJwk: v.jwk });
      if (opened.plaintext.length && back.plaintext === opened.plaintext &&
          (crypto.isIntegratedJweAlg(v.alg) === (opened.header.enc ===
                                                undefined))) {
        pass++;
      } else {
        failures.push(v.alg);
      }
    } catch (e) {
      log.debug('Caught in joseHpke(): ' + ((e && e.message) || e));
      failures.push(v.alg + ' threw ' + e.message);
    }
  });
  t.check(pass > 0 && !failures.length, 'draft-ietf-jose-hpke-encrypt ' +
          'vectors: ' + pass + ' compact JWE(s) decrypted and re-encrypted ' +
          'to the vector\'s key; not applicable: ' + (na.join(', ') ||
          'none') + ' (removed by -22), and every flattened JSON ' +
          'serialisation (this service speaks the compact one)',
          failures.join('; '));
  t.check(na.join(',') === 'HPKE-4-KE,HPKE-6-KE', 'the not-applicable ' +
          'vectors are exactly the two -22 removed', na.join(','));
  log.debug('Leaving joseHpke().');
}

// ---------------------------------------------------------------------------
// D. node's OpenSSL ML-KEM, both directions.
// ---------------------------------------------------------------------------
const KEM_ID = { 'ml-kem-512': 0x0040, 'ml-kem-768': 0x0041,
                 'ml-kem-1024': 0x0042 };

function againstOpenSsl(t) {
  log.debug('Entering againstOpenSsl().');
  if (typeof nodeCrypto.encapsulate !== 'function') {
    t.check(true, 'node ' + process.version + ' has no ML-KEM, so the ' +
            'OpenSSL cross-check is not applicable here (node 24 in the ' +
            'tests image has it)', '');
    log.debug('Leaving againstOpenSsl(). No native ML-KEM.');
    return;
  }
  Object.keys(KEM_ID).forEach(function (type) {
    const kemId = KEM_ID[type];
    const pair = nodeCrypto.generateKeyPairSync(
      /** @type {any} */ (type));
    const seed = pair.privateKey.export(
      /** @type {any} */ ({ format: 'raw-seed' }));
    const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
    const ek = spki.subarray(spki.length - crypto.hpke.KEMS[kemId].Npk);
    const theirs = /** @type {any} */ (nodeCrypto).encapsulate(
      pair.publicKey);
    const ours = crypto.hpke.encap(kemId, ek);
    t.check(crypto.hpke.decap(kemId, theirs.ciphertext, seed)
              .equals(theirs.sharedKey) &&
            /** @type {any} */ (nodeCrypto).decapsulate(pair.privateKey,
              ours.enc).equals(ours.ss),
            type + ': OpenSSL encapsulates and crypto.js decapsulates from ' +
            'the seed, and the reverse', '');
  });
  log.debug('Leaving againstOpenSsl().');
}

// ---------------------------------------------------------------------------
// E. Every alg, every enc, and the refusals.
// ---------------------------------------------------------------------------
function roundTrips(t) {
  log.debug('Entering roundTrips().');
  const algs = crypto.JWE_MLKEM_ALGS.concat(crypto.JWE_HPKE_ALGS);
  const encs = Object.keys(crypto.JWE_ENCS);
  const failures = [];
  let n = 0;
  algs.forEach(function (alg) {
    const kp = crypto.generateJweKemKeyPair(alg, 'k-' + alg);
    encs.forEach(function (enc) {
      try {
        const jwe = crypto.encryptJweCompact('{"n":' + n + '}',
          { alg: alg, enc: enc, jwk: kp.publicJwk });
        const header = JSON.parse(Buffer.from(jwe.split('.')[0], 'base64url')
                                        .toString('utf8'));
        const out = crypto.decryptJweCompact(jwe,
          { privateJwk: kp.privateJwk, allowedAlg: [alg],
            allowedEnc: [enc], expectedKid: 'k-' + alg });
        const integrated = crypto.isIntegratedJweAlg(alg);
        const shapeOk = integrated
          ? header.enc === undefined && header.ek === undefined &&
            jwe.split('.')[2] === '' && jwe.split('.')[4] === ''
          : header.enc === enc && typeof header.ek === 'string';
        if (out.plaintext !== '{"n":' + n + '}' || !shapeOk ||
            header.kid !== 'k-' + alg) {
          failures.push(alg + '/' + enc);
        }
      } catch (e) {
        log.debug('Caught in roundTrips(): ' + ((e && e.message) || e));
        failures.push(alg + '/' + enc + ' threw ' + e.message);
      }
      n++;
    });
  });
  t.check(!failures.length, n + ' round trips: every ML-KEM and HPKE alg ' +
          'with every enc (an Integrated alg carries no enc, no ek, and an ' +
          'empty IV and tag)', failures.slice(0, 10).join('; '));
  t.check(JSON.stringify(crypto.JWE_POST_QUANTUM_ALGS) ===
          JSON.stringify(crypto.JWE_MLKEM_ALGS.concat(algs.filter(
            function (a) {
              return /^HPKE-(8|9|1[0-6])(-KE)?$/.test(a);
            }))) &&
          JSON.stringify(crypto.JWE_HYBRID_ALGS) ===
          JSON.stringify(algs.filter(function (a) {
            return /^HPKE-(8|9|10|11|12|13)(-KE)?$/.test(a);
          })),
          'the post-quantum list is ML-KEM and HPKE-8 to 16; the hybrid ' +
          'list HPKE-8 to 13', JSON.stringify(crypto.JWE_POST_QUANTUM_ALGS));

  const a768 = crypto.generateJweKemKeyPair('ML-KEM-768');
  const a1024 = crypto.generateJweKemKeyPair('ML-KEM-1024');
  const xwing = crypto.generateJweKemKeyPair('HPKE-10-KE');
  const p256 = crypto.generateJweKemKeyPair('HPKE-0');
  refuses(t, function () {
    crypto.encryptJweCompact('x', { alg: 'ML-KEM-768+A192KW', enc: 'A256GCM',
                                    jwk: a768.publicJwk });
  }, /names exactly one algorithm/, 'an AKP key for another alg');
  refuses(t, function () {
    crypto.encryptJweCompact('x', { alg: 'HPKE-10-KE', enc: 'A256GCM',
      jwk: Object.assign({}, a768.publicJwk, { alg: 'HPKE-10-KE' }) });
  }, /pub.*octets/, 'an AKP key of the wrong size for its alg');
  refuses(t, function () {
    crypto.encryptJweCompact('x', { alg: 'HPKE-3', jwk: p256.publicJwk });
  }, /OKP/, 'a P-256 key for an X25519 suite');
  refuses(t, function () {
    crypto.encryptJweCompact('x', { alg: 'ML-KEM-768', enc: 'A256GCM',
      jwk: { kty: 'RSA', n: 'AQAB', e: 'AQAB' } });
  }, /type "AKP"/, 'an RSA key for ML-KEM');
  refuses(t, function () {
    crypto.decryptJweCompact(crypto.encryptJweCompact('x',
      { alg: 'ML-KEM-768', enc: 'A256GCM', jwk: a768.publicJwk }),
      { privateJwk: a1024.privateJwk });
  }, /AKP key for that algorithm/, 'the private key of another alg');
  refuses(t, function () {
    crypto.decryptJweCompact(crypto.encryptJweCompact('x',
      { alg: 'HPKE-10-KE', enc: 'A256GCM', jwk: xwing.publicJwk }),
      { privateJwk: crypto.generateJweKemKeyPair('HPKE-10-KE').privateJwk });
  }, /did not decrypt|could not be unwrapped/,
     'another key of the same alg (the HPKE tag does not verify)');
  // A JWE whose header is changed after it was made.
  const integrated = crypto.encryptJweCompact('x', { alg: 'HPKE-10',
    jwk: crypto.publicJweKemJwk(crypto.generateJweKemKeyPair('HPKE-10')
      .publicJwk) });
  const parts = integrated.split('.');
  const withEnc = Buffer.from(JSON.stringify(Object.assign(JSON.parse(
    Buffer.from(parts[0], 'base64url').toString('utf8')), { enc: 'A256GCM' })))
    .toString('base64url');
  refuses(t, function () {
    crypto.decryptJweCompact([withEnc].concat(parts.slice(1)).join('.'),
      { privateJwk: xwing.privateJwk });
  }, /MUST NOT carry `enc`/, 'an Integrated JWE carrying enc');
  refuses(t, function () {
    crypto.decryptJweCompact([parts[0], parts[1], 'AAAAAAAAAAAAAAAA',
                              parts[3], ''].join('.'),
      { privateJwk: xwing.privateJwk });
  }, /IV and\s+Authentication Tag empty|carries an IV/,
     'an Integrated JWE with an IV');
  const ke = crypto.encryptJweCompact('x', { alg: 'ML-KEM-768+A192KW',
    enc: 'A256GCM', jwk: crypto.generateJweKemKeyPair('ML-KEM-768+A192KW')
      .publicJwk });
  const keParts = ke.split('.');
  const noEk = JSON.parse(Buffer.from(keParts[0], 'base64url')
    .toString('utf8'));
  delete noEk.ek;
  refuses(t, function () {
    crypto.decryptJweCompact([Buffer.from(JSON.stringify(noEk))
      .toString('base64url')].concat(keParts.slice(1)).join('.'),
      { privateJwk: a768.privateJwk });
  }, /`ek`/, 'an ML-KEM JWE with no ek');
  const psk = crypto.encryptJweCompact('x', { alg: 'HPKE-10-KE',
    enc: 'A256GCM', jwk: xwing.publicJwk, psk: nodeCrypto.randomBytes(32),
    pskId: Buffer.from('psk-1') });
  refuses(t, function () {
    crypto.decryptJweCompact(psk, { privateJwk: xwing.privateJwk });
  }, /pre-shared key/, 'an HPKE mode_psk JWE with no PSK held');
  const unreduced = Buffer.from(a768.publicJwk.pub, 'base64url');
  unreduced[0] = 0xff;
  unreduced[1] = 0xff;
  refuses(t, function () {
    crypto.encryptJweCompact('x', { alg: 'ML-KEM-768', enc: 'A256GCM',
      jwk: Object.assign({}, a768.publicJwk,
                         { pub: unreduced.toString('base64url') }) });
  }, /modulus check/, 'an unreduced ML-KEM encapsulation key (FIPS 203 7.2)');
  // And mode_psk round-trips with the key and id both held.
  const pskKey = nodeCrypto.randomBytes(32);
  const withPsk = crypto.encryptJweCompact('psk', { alg: 'HPKE-10-KE',
    enc: 'A256GCM', jwk: crypto.publicJweKemJwk(xwing.publicJwk),
    psk: pskKey, pskId: Buffer.from('id') });
  const pskHeader = JSON.parse(Buffer.from(withPsk.split('.')[0],
                                           'base64url').toString('utf8'));
  t.check(pskHeader.psk_id === Buffer.from('id').toString('base64url') &&
          crypto.decryptJweCompact(withPsk, { privateJwk: xwing.privateJwk,
                                              psk: pskKey })
            .plaintext === 'psk',
          'HPKE mode_psk: psk_id in the header, base64url, and opened with ' +
          'the PSK', JSON.stringify(pskHeader));
  log.debug('Leaving roundTrips().');
}

// ---------------------------------------------------------------------------
// F. The KDF, the setting's values, derivation and cost.
// ---------------------------------------------------------------------------
function kdfAndSettings(t) {
  log.debug('Entering kdfAndSettings().');
  // pqc-kem-05 section 5.1: KMAC256(K, X, L, S = "") with X = AlgorithmID ||
  // SuppPubInfo (RFC 7518 section 4.6.2's fields: a 32-bit length and the
  // name; the key length in bits as a 32-bit integer).
  const kmac = require('@noble/hashes/sha3-addons').kmac256;
  const u32 = function (n) {
    log.debug('Entering u32().');
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n);
    log.debug('Leaving u32().');
    return b;
  };
  const ss = nodeCrypto.randomBytes(32);
  const expected = Buffer.from(kmac(ss, Buffer.concat([
    u32(7), Buffer.from('A256GCM'), u32(256)]), { dkLen: 32 }));
  t.check(crypto.hpke.mlkemJoseKdf(ss, 'A256GCM', 32).equals(expected),
          'pqc-kem-05 KMAC256 over AlgorithmID || SuppPubInfo, PartyU/V ' +
          'left out, S empty', '');

  const config = require('../common/config');
  const row = (config.SETTINGS || []).filter(function (r) {
    return r.key === 'keys.encryptionKemAlgs';
  })[0] || {};
  t.check(JSON.stringify(row.csvValues) ===
          JSON.stringify(crypto.JWE_MLKEM_ALGS.concat(crypto.JWE_HPKE_ALGS)) &&
          row.dflt === '',
          'keys.encryptionKemAlgs offers exactly crypto.js\'s ML-KEM and ' +
          'HPKE algs, and is empty by default', JSON.stringify(row.csvValues));
  const vp = (config.SETTINGS || []).filter(function (r) {
    return r.key === 'oid4vp.responseEncryptionKeyAlgs';
  })[0] || {};
  t.check(vp.dflt === 'HPKE-10-KE,ECDH-ES' &&
          (vp.csvValues || []).indexOf('HPKE-10') === -1,
          'OID4VP offers the X-Wing key first and ECDH-ES second by ' +
          'default, and never an Integrated alg', String(vp.dflt));

  const ikm = nodeCrypto.randomBytes(64);
  const failures = crypto.JWE_MLKEM_ALGS.concat(crypto.JWE_HPKE_ALGS)
    .filter(function (alg) {
      const a = crypto.deriveJweKemKeyPair(alg, ikm, 'd');
      const b = crypto.deriveJweKemKeyPair(alg, ikm, 'd');
      const jwe = crypto.encryptJweCompact('d', { alg: alg, enc: 'A128GCM',
                                                  jwk: a.publicJwk });
      return JSON.stringify(a) !== JSON.stringify(b) ||
             crypto.decryptJweCompact(jwe, { privateJwk: b.privateJwk })
               .plaintext !== 'd';
    });
  t.check(!failures.length, 'a key pair derived for a refresh token is the ' +
          'same every time and opens what it sealed', failures.join(', '));

  // THE COST, measured for the worker pool question (#82's note). Logged,
  // not asserted: a loaded CI runner is slower, and the decision is recorded
  // in common/CLAUDE.md with the figures this prints.
  [['RSA-OAEP-256', null], ['ML-KEM-768', null], ['HPKE-10-KE', null],
   ['HPKE-12-KE', null]].forEach(function (row) {
    const alg = row[0];
    let pub;
    let priv;
    if (alg === 'RSA-OAEP-256') {
      const pair = nodeCrypto.generateKeyPairSync('rsa',
                                                  { modulusLength: 2048 });
      pub = pair.publicKey.export({ format: 'jwk' });
      priv = { privateKey: pair.privateKey };
    } else {
      const pair = crypto.generateJweKemKeyPair(alg);
      pub = pair.publicJwk;
      priv = { privateJwk: pair.privateJwk };
    }
    const started = process.hrtime.bigint();
    for (let i = 0; i < 50; i++) {
      crypto.decryptJweCompact(crypto.encryptJweCompact('t',
        { alg: alg, enc: 'A256GCM', jwk: pub }), priv);
    }
    t.log.info('cost: ' + alg + ' encrypt + decrypt, ' +
               (Number(process.hrtime.bigint() - started) / 50e6).toFixed(2) +
               ' ms');
  });
  log.debug('Leaving kdfAndSettings().');
}

module.exports = {
  name: 'jwe_pq_kem',
  describe: 'ML-KEM and HPKE (PQ, hybrid, classical) as JWE key ' +
            'management, against the drafts\' vectors and OpenSSL (#82)',
  run: async function (t) {
    log.debug('Entering run().');
    crypto = require('../common/crypto');
    if (!fs.existsSync(DIR)) {
      t.bad('the HPKE vectors are not at ' + DIR,
        'they are fetched when the tests image is built ' +
        '(tests/tools/fetch-vectors.sh); run this file in that image');
    } else {
      const commit = fs.existsSync(path.join(DIR, 'COMMIT'))
        ? fs.readFileSync(path.join(DIR, 'COMMIT'), 'utf8').trim()
          .replace(/\n/g, ', ')
        : '(unstamped)';
      t.log.info('=== HPKE vectors: ' + commit + ' ===');
      hpkePq(t);
      concreteHybrids(t);
      joseHpke(t);
    }
    againstOpenSsl(t);
    roundTrips(t);
    kdfAndSettings(t);
    log.debug('Leaving run().');
  }
};
