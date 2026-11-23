// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pkcs11_mldsa.js
//
// ---------------------------------------------------------------------------
// ML-DSA IN A PKCS#11 TOKEN, ONLY WHEN THE MODULE OFFERS IT.
//
// CKM_ML_DSA is 0x1d (PKCS#11 3.2). A token that does not offer it with
// CKF_SIGN refuses before C_Sign (STS-KEYS-0206). One that does is asked
// for a buffer large enough for ML-DSA-87 (4627 octets). SLH-DSA is not a
// mechanism here. The realm's published post-quantum set stays in software.
// ---------------------------------------------------------------------------

const log = require('bunyan').createLogger({ name: 'pkcs11_mldsa',
  level: process.env.LOG_LEVEL || 'info' });

function tokenWith(lib, mechanisms) {
  log.debug("Entering tokenWith().");
  const pkcs11 = require('../common/crypto_impl/pkcs11');
  const token = new pkcs11.Pkcs11Token({}, { modulePath: 'fake' });
  token.entry = { lib: lib };
  token.mechanisms = mechanisms;
  token.idle = [1];
  token.generation = 0;
  token.slot = 0;
  log.debug("Leaving tokenWith().");
  return token;
}

function run(t) {
  log.debug("Entering run().");
  const pkcs11 = require('../common/crypto_impl/pkcs11');
  const codes = require('../common/error_codes');
  const CK = pkcs11.CK;
  const key = { handle: 9, generation: 0, template: [], what: 'the key' };
  t.equal(pkcs11.SIGNING['SLH-DSA-SHAKE-128s'], undefined,
          '1. SLH-DSA is not a PKCS#11 signing algorithm here');
  t.equal(CK.CKM_ML_DSA, 0x1d, '2. CKM_ML_DSA is PKCS#11 3.2\'s 0x1d');
  t.equal(CK.CKM_ML_DSA_KEY_PAIR_GEN, 0x1c,
          '3. key-pair generation is 0x1c, not a pre-hash mechanism');
  const silent = [];
  const absent = tokenWith({
    C_SignInit: function () {
      silent.push('init');
    },
    C_SignAsync: function () {
      silent.push('sign');
      return Promise.resolve(Buffer.alloc(4));
    }
  }, new Map());
  // The offer check throws before C_Sign, so it is not a rejection.
  let pending;
  try {
    pending = absent.sign(key, 'ML-DSA-87', Buffer.from('abc'));
  } catch (e) {
    pending = Promise.reject(e);
  }
  return pending.then(function () {
    t.check(false, '4. a token without CKM_ML_DSA signed');
  }, function (e) {
    t.equal(codes.codeOf(e), 'STS-KEYS-0206',
            '4. no CKM_ML_DSA is STS-KEYS-0206');
    t.equal(silent.length, 0, '5. C_Sign was not called');
    const calls = [];
    const offered = tokenWith({
      C_SignInit: function (session, mechanism) {
        calls.push(mechanism);
      },
      C_SignAsync: function (session, input, buf) {
        calls.push(buf.length);
        return Promise.resolve(Buffer.alloc(8, 1));
      }
    }, new Map([[CK.CKM_ML_DSA, CK.CKF_SIGN]]));
    return offered.sign(key, 'ML-DSA-87', Buffer.from('abc'))
      .then(function (sig) {
        t.equal(sig.length, 8, '6. the token\'s signature is returned');
        t.equal(calls[0].mechanism, 0x1d,
                '7. C_SignInit asked for CKM_ML_DSA');
        t.check(calls[1] >= 4627,
                '8. the signature buffer holds an ML-DSA-87 signature',
                String(calls[1]));
        const bare = tokenWith({}, new Map());
        let refused = null;
        try {
          bare.keyPairPlan({ kty: 'AKP', alg: 'ML-DSA-65' }, 'lbl',
                           Buffer.from('id'));
        } catch (err) {
          refused = err;
        }
        t.equal(codes.codeOf(refused), 'STS-KEYS-0207',
                '9. generation without the mechanism is STS-KEYS-0207');
        t.equal(bare.canGenerate({ kty: 'AKP', alg: 'ML-DSA-65' }), false,
                '10. canGenerate is false until the mechanism is listed');
        const ready = tokenWith({}, new Map([
          [CK.CKM_ML_DSA_KEY_PAIR_GEN, 0]]));
        const plan = ready.keyPairPlan({ kty: 'AKP', alg: 'ML-DSA-65' },
                                       'lbl', Buffer.from('id'));
        t.equal(plan.mech, 0x1c,
                '11. generation uses CKM_ML_DSA_KEY_PAIR_GEN');
        const set = plan.pub.filter(function (a) {
          return a.type === CK.CKA_PARAMETER_SET;
        })[0];
        t.equal(set && set.value, CK.CKP_ML_DSA_65,
                '12. the parameter set is ML-DSA-65');
        t.equal(ready.canGenerate({ kty: 'AKP', alg: 'ML-DSA-65' }), true,
                '13. canGenerate is true once the mechanism is listed');
        const raw = Buffer.alloc(1952, 7);
        const reader = tokenWith({
          C_GetAttributeValue: function (session, handle, template) {
            return [{ type: template[0].type, value: raw }];
          }
        }, new Map());
        const pub = reader.publicKeyOf(3, { kty: 'AKP', alg: 'ML-DSA-65' });
        t.equal(pub.asymmetricKeyType, 'ml-dsa',
                '14. the public half says ml-dsa on a runtime that cannot ' +
                'import it');
        t.equal(pub.asymmetricKeyDetails.parameterSet, 'ML-DSA-65',
                '15. the parameter set is recorded on the public half');
        t.equal(pub.export()[0], 0x30,
                '16. the public half exports a SubjectPublicKeyInfo');
        log.debug("Leaving run().");
      });
  });
}

module.exports = {
  name: 'pkcs11_mldsa',
  describe: 'PKCS#11 ML-DSA only when the module offers CKM_ML_DSA',
  run: run
};

if (require.main === module) {
  const harness = require('./harness').createHarness('pkcs11_mldsa');
  run(harness).then(function () {
    const failures = harness.failures();
    if (failures.length) {
      failures.forEach(function (line) {
        harness.log.error(line);
      });
      process.exit(1);
    }
    harness.log.info(harness.passed() + ' passed');
  }).catch(function (e) {
    harness.log.error(String((e && e.stack) || e));
    process.exit(1);
  });
}
