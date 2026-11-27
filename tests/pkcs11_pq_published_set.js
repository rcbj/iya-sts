// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pkcs11_pq_published_set.js
//
// ---------------------------------------------------------------------------
// SLH-DSA IN A PKCS#11 TOKEN, AND THE REALM'S PUBLISHED POST-QUANTUM SET
// MADE THERE WHEN THE TOKEN OFFERS IT (#2220).
//
// SoftHSM2 2.6 (the tests image's) offers neither CKM_ML_DSA nor
// CKM_SLH_DSA, so the token here is a STUB: the engine's own
// `Pkcs11Token` over a fake module for the mechanism selection (A), and a
// token object that signs with a real node ML-DSA or SLH-DSA key behind
// `crypto.js`'s HSM key door for the rest (B, C), so a signature made
// "in the token" is checked against its public half.
//
//   A. the engine: CKM_SLH_DSA (0x2e) and its generation mechanism (0x2d),
//      the parameter set on the key, a refusal before C_Sign without the
//      mechanism, generation only where BOTH mechanisms are listed, and
//      the offer report;
//   B. `crypto.js`: a JWS and a raw signature with an ML-DSA and an SLH-DSA
//      key in the token verify — the framing and the key-kind check that
//      node 24's `ml-dsa-65` spelling failed;
//   C. `helpers.js`'s `pqPairFor()`: a key the token offers is made there,
//      one it does not (and every composite) in software; and the keystore
//      carries an HSM reference through as is.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const log = require('bunyan').createLogger({ name: 'pkcs11_pq_published_set',
  level: process.env.LOG_LEVEL || 'info' });

function tokenWith(lib, mechanisms) {
  log.debug("Entering tokenWith().");
  const pkcs11 = require('../common/crypto_impl/pkcs11');
  const token = new pkcs11.Pkcs11Token({}, { modulePath: 'fake' });
  token.entry = pkcs11.newEntry({}, lib, 'fake');
  token.mechanisms = mechanisms;
  token.idle = [{ h: 1, epoch: 0 }];
  token.open = 1;
  token.generation = 0;
  token.slot = 0;
  log.debug("Leaving tokenWith().");
  return token;
}

// Node's name for a JOSE post-quantum algorithm.
function nodeName(alg) {
  log.debug("Entering nodeName().");
  log.debug("Leaving nodeName().");
  return alg.toLowerCase();
}

// A token that holds real node keys: `generateKeyPair()` makes one, and
// `signSync()` / `sign()` sign with it. `offered` is the algorithms it
// "lists the mechanisms" for.
function stubToken(offered) {
  log.debug("Entering stubToken().");
  const keys = new Map();
  const signed = [];
  const token = {
    signed: signed,
    describe: function () {
      return 'the stub token';
    },
    canGenerate: function (spec) {
      return spec.kty === 'AKP' && offered.indexOf(spec.alg) >= 0;
    },
    generateKeyPair: function (spec, label, id) {
      const pair = nodeCrypto.generateKeyPairSync(nodeName(spec.alg));
      const raw = pair.publicKey.export({ format: 'raw-public' });
      keys.set(id.toString('hex'), pair.privateKey);
      return {
        key: { id: id.toString('hex') },
        publicKey: { raw: raw, type: 'public',
                     asymmetricKeyType: pair.publicKey.asymmetricKeyType,
                     asymmetricKeyDetails: { parameterSet: spec.alg },
                     node: pair.publicKey,
                     export: function (o) {
                       return pair.publicKey.export(o);
                     } }
      };
    },
    generateKeyPairAsync: function (spec, label, id) {
      return Promise.resolve(token.generateKeyPair(spec, label, id));
    },
    signSync: function (engineKey, alg, data) {
      signed.push(alg);
      return nodeCrypto.sign(null, Buffer.from(data),
                             keys.get(engineKey.id));
    },
    sign: function (engineKey, alg, data) {
      signed.push(alg);
      return Promise.resolve(nodeCrypto.sign(null, Buffer.from(data),
                                             keys.get(engineKey.id)));
    }
  };
  log.debug("Leaving stubToken().");
  return token;
}

async function checkEngine(t) {
  log.debug("Entering checkEngine().");
  const pkcs11 = require('../common/crypto_impl/pkcs11');
  const codes = require('../common/error_codes');
  const CK = pkcs11.CK;
  t.equal(CK.CKM_SLH_DSA, 0x2e, 'A1. CKM_SLH_DSA is PKCS#11 3.2\'s 0x2e');
  t.equal(CK.CKM_SLH_DSA_KEY_PAIR_GEN, 0x2d,
          'A2. its key-pair generation is 0x2d');
  t.equal(CK.CKK_SLH_DSA, 0x4b, 'A3. CKK_SLH_DSA is 0x4b');
  t.equal(pkcs11.SIGNING['SLH-DSA-SHA2-128s'].parameterSet,
          CK.CKP_SLH_DSA_SHA2_128S,
          'A4. SLH-DSA-SHA2-128s signs under its own parameter set');
  const key = { handle: 9, generation: 0, template: [], what: 'the key' };
  const silent = [];
  const absent = tokenWith({
    C_SignInit: function () {
      silent.push('init');
    },
    C_SignAsync: function () {
      silent.push('sign');
      return Promise.resolve(Buffer.alloc(4));
    }
  }, new Map([[CK.CKM_ML_DSA, CK.CKF_SIGN]]));
  let refused = null;
  try {
    await absent.sign(key, 'SLH-DSA-SHAKE-128s', Buffer.from('abc'));
  } catch (e) {
    refused = e;
  }
  t.equal(codes.codeOf(refused), 'STS-KEYS-0206',
          'A5. a token without CKM_SLH_DSA refuses an SLH-DSA signature');
  t.check(/CKM_SLH_DSA/.test(String(refused && refused.message)),
          'A6. the refusal names CKM_SLH_DSA',
          String(refused && refused.message));
  t.equal(silent.length, 0, 'A7. C_Sign was not called');
  const calls = [];
  const offered = tokenWith({
    C_SignInit: function (session, mechanism) {
      calls.push(mechanism);
    },
    C_SignAsync: function (session, input, buf) {
      calls.push(buf.length);
      return Promise.resolve(Buffer.alloc(8, 1));
    }
  }, new Map([[CK.CKM_SLH_DSA, CK.CKF_SIGN],
              [CK.CKM_SLH_DSA_KEY_PAIR_GEN, 0]]));
  const sig = await offered.sign(key, 'SLH-DSA-SHA2-128s',
                                 Buffer.from('abc'));
  t.equal(sig.length, 8, 'A8. the token\'s SLH-DSA signature is returned');
  t.equal(calls[0].mechanism, 0x2e, 'A9. C_SignInit asked for CKM_SLH_DSA');
  t.check(calls[1] >= 7856,
          'A10. the buffer holds an SLH-DSA-128s signature (7856 octets)',
          String(calls[1]));
  const plan = offered.keyPairPlan({ kty: 'AKP', alg: 'SLH-DSA-SHA2-128s' },
                                   'lbl', Buffer.from('id'));
  t.equal(plan.mech, 0x2d,
          'A11. SLH-DSA generation uses CKM_SLH_DSA_KEY_PAIR_GEN');
  const set = plan.priv.filter(function (a) {
    return a.type === CK.CKA_PARAMETER_SET;
  })[0];
  t.equal(set && set.value, CK.CKP_SLH_DSA_SHA2_128S,
          'A12. the parameter set is on the private key');
  const genOnly = tokenWith({}, new Map([[CK.CKM_SLH_DSA_KEY_PAIR_GEN, 0]]));
  t.equal(genOnly.canGenerate({ kty: 'AKP', alg: 'SLH-DSA-SHA2-128s' }),
          false, 'A13. generation alone is not enough: the token must ' +
          'also sign');
  t.equal(offered.canGenerate({ kty: 'AKP', alg: 'SLH-DSA-SHA2-128s' }),
          true, 'A14. both mechanisms listed, the key is made in the token');
  t.equal(offered.canGenerate({ kty: 'AKP', alg: 'ML-DSA-65' }), false,
          'A15. ML-DSA is still asked of its own mechanisms');
  const offer = offered.postQuantumOffer();
  t.check(offer['SLH-DSA-SHA2-128s'].offered === true &&
          offer['SLH-DSA-SHAKE-128s'].offered === true &&
          offer['ML-DSA-44'].offered === false,
          'A16. the offer report says which published algorithms the ' +
          'token makes', JSON.stringify(offer));
  const raw = nodeCrypto.generateKeyPairSync('slh-dsa-sha2-128s').publicKey
    .export({ format: 'raw-public' });
  const reader = tokenWith({
    C_GetAttributeValue: function (session, handle, template) {
      return [{ type: template[0].type, value: raw }];
    }
  }, new Map());
  const pub = reader.publicKeyOf(3, { kty: 'AKP', alg: 'SLH-DSA-SHA2-128s' });
  t.check(/^slh-dsa/.test(String(pub.asymmetricKeyType)),
          'A17. an SLH-DSA public half is an slh-dsa key',
          String(pub.asymmetricKeyType));
  t.check(Buffer.from(pub.raw).equals(raw),
          'A18. the raw public key travels on the half');
  log.debug("Leaving checkEngine().");
}

async function checkDoors(t) {
  log.debug("Entering checkDoors().");
  const stsCrypto = require('../common/crypto');
  for (const alg of ['ML-DSA-65', 'SLH-DSA-SHA2-128s']) {
    const token = stubToken([alg]);
    const made = stsCrypto.generatePkcs11KeyPair(token, 'pkcs11:token=stub',
      { kty: 'AKP', alg: alg }, 'lbl');
    t.check(stsCrypto.isHsmKey(made.privateKey.ref),
            'B1. ' + alg + ': the key made in the token is an HSM key');
    const jws = stsCrypto.signJws({ sub: 'alice' }, made.privateKey.ref,
                                  { algorithm: alg });
    const parts = String(jws).split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url')
      .toString('utf8'));
    t.equal(header.alg, alg, 'B2. ' + alg + ': the JWS header names it');
    t.check(nodeCrypto.verify(null, Buffer.from(parts[0] + '.' + parts[1]),
                              made.publicKey.node,
                              Buffer.from(parts[2], 'base64url')),
            'B3. ' + alg + ': the JWS signed in the token verifies');
    const later = await stsCrypto.signJwsAsync({ sub: 'bob' },
      made.privateKey.ref, { algorithm: alg });
    const p2 = String(later).split('.');
    t.check(nodeCrypto.verify(null, Buffer.from(p2[0] + '.' + p2[1]),
                              made.publicKey.node,
                              Buffer.from(p2[2], 'base64url')),
            'B4. ' + alg + ': signed off the event loop, it verifies too');
    const data = Buffer.from('raw bytes');
    const rawSig = stsCrypto.signRawSignature({ family: 'pq', alg: alg },
                                              made.privateKey.ref, data);
    t.check(nodeCrypto.verify(null, data, made.publicKey.node, rawSig),
            'B5. ' + alg + ': a raw signature (Data Integrity, COSE) is ' +
            'the token\'s, and verifies');
    t.check(token.signed.length === 3 && token.signed.every(function (a) {
      return a === alg;
    }), 'B6. ' + alg + ': every signature was asked of the token',
    JSON.stringify(token.signed));
  }
  log.debug("Leaving checkDoors().");
}

async function checkPublishedSet(t) {
  log.debug("Entering checkPublishedSet().");
  const helpers = require('../common/helpers');
  const keystore = require('../common/keystore');
  const stsCrypto = require('../common/crypto');
  const hsm = { token: stubToken(['ML-DSA-44', 'SLH-DSA-SHAKE-128s']),
                uri: 'pkcs11:token=stub' };
  const inToken = helpers.pqPairFor('ML-DSA-44', hsm, '');
  t.check(typeof inToken.priv === 'string' &&
          stsCrypto.isHsmKey(inToken.priv),
          'C1. ML-DSA-44, offered: made in the token, its private half a ' +
          'reference');
  t.equal(Buffer.from(inToken.pub).length, 1312,
          'C2. its raw ML-DSA-44 public key is the token\'s');
  const slh = await helpers.pqPairForAsync('SLH-DSA-SHAKE-128s', hsm, '');
  t.check(stsCrypto.isHsmKey(slh.priv),
          'C3. SLH-DSA-SHAKE-128s, offered: made in the token, off the loop');
  const soft = helpers.pqPairFor('ML-DSA-87', hsm, '');
  t.check(Buffer.isBuffer(Buffer.from(soft.priv)) &&
          !stsCrypto.isHsmKey(soft.priv),
          'C4. ML-DSA-87, not offered: made in software');
  const composite = helpers.pqPairFor('ML-DSA-65-ES256', hsm, '');
  t.check(!stsCrypto.isHsmKey(composite.priv),
          'C5. a composite is always made in software');
  const none = helpers.pqPairFor('ML-DSA-44', null, '');
  t.check(!stsCrypto.isHsmKey(none.priv),
          'C6. with no token, software, as before');
  const stored = keystore.pqPrivateOut(inToken.priv);
  t.equal(stored, inToken.priv,
          'C7. the keystore stores an HSM reference as is');
  t.equal(keystore.pqPrivateIn(stored), inToken.priv,
          'C8. and reads it back as the reference');
  const bytes = Buffer.from(none.priv);
  t.check(Buffer.from(keystore.pqPrivateIn(keystore.pqPrivateOut(bytes)))
    .equals(bytes), 'C9. raw bytes still travel as base64, unchanged');
  log.debug("Leaving checkPublishedSet().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkEngine(t);
  await checkDoors(t);
  await checkPublishedSet(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pkcs11_pq_published_set',
  describe: 'SLH-DSA in a PKCS#11 token, and the published post-quantum ' +
            'set made in the token when it offers it (#2220)',
  run: run
};
