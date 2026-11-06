// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: signature_policy.js
//
// ---------------------------------------------------------------------------
// ONE ANSWER TO "MAY THIS REALM USE THIS ALGORITHM" (#1368, phase 3).
//
// What is held here is the audit's second finding: the gate existed at some
// doors and not others. So each door is driven with the switch on and off, the
// ones that had no gate above all: a GNAP `jws` proof, an HTTP message
// signature, and `signJwt()`. And the defaults are held to today: nothing
// default is refused, and an empty list means today's order and not the
// registry's preference order.
// ---------------------------------------------------------------------------

module.exports = {
  name: 'signature_policy',
  run: async function run(t) {
    const config = require('../common/config');
    const errorCodes = require('../common/error_codes');
    const stsCrypto = require('../common/crypto');
    const helpers = require('../common/helpers');
    const pqJose = require('../common/pq_jose');
    const registry = require('../common/crypto_impl/algorithm_registry');
    const policy = require('../common/signature_policy');
    const PQ = 'keys.postQuantumSigning';
    const EDDSA = 'keys.eddsaSigning';
    const LIST = 'keys.signingAlgorithms';

    const clear = function () {
      [PQ, EDDSA, LIST].forEach(function (key) {
        config.clearOverride(key);
      });
    };
    const codeThrownBy = function (f) {
      try {
        f();
      } catch (e) {
        return errorCodes.codeOf(e) || ('threw: ' + e.message);
      }
      return null;
    };

    const pair = pqJose.generate('ML-DSA-44');
    const input = Buffer.from('signing input');
    const signature = pqJose.sign('ML-DSA-44', pair.priv, input);
    const pub = pair.pub;
    const jwk = pqJose.akpPublicJwk('ML-DSA-44', pair.pub, 'pq');
    const httpRequest = function () {
      return { method: 'POST', targetUri: 'https://example.com/token',
               headers: { host: 'example.com' } };
    };
    const httpOptions = { label: 'sig', components: ['@method'],
                          params: { created: 1700000000, keyid: 'k' },
                          key: Buffer.from(pair.priv),
                          algorithm: 'ML-DSA-44' };
    const verifyOptions = {
      keyFor: function () {
        return { key: jwk, algorithm: 'ML-DSA-44' };
      },
      now: 1700000000
    };

    try {
      clear();

      // ---- The defaults are today. ---------------------------------------
      t.check(policy.joseSignList() === null, 'an empty list is no list');
      t.check(policy.signCause('jose', 'RS256') === null,
        'RS256 is signable by default');
      t.check(policy.signCause('jose', 'ML-DSA-65') === null,
        'post-quantum is signable by default');
      t.check(policy.signCause('jose', 'EdDSA') !== null,
        'EdDSA is not signable by default (#1292)');
      t.check(policy.acceptCause('jose', 'EdDSA') === null,
        'and is still accepted: the switch never governed acceptance');
      t.check(policy.acceptCause('jose', 'ML-DSA-65') === null,
        'post-quantum is accepted by default');
      const signable = policy.effective('jose', 'sign');
      t.check(signable[0] === 'HS256' && signable.indexOf('RS256') === 3,
        'an empty list means today\'s order, not preference order',
        signable.slice(0, 4).join());
      t.check(signable.indexOf('EdDSA') < 0,
        'the effective list leaves out what the switch removes');
      t.check(JSON.stringify(policy.effective('jose', 'accept')) ===
        JSON.stringify(stsCrypto.JWS_SIGNING_ALGS),
      'everything is accepted by default, in today\'s order');
      t.check(JSON.stringify(policy.effective('httpsig', 'accept')) ===
        JSON.stringify(Object.keys(stsCrypto.HTTP_SIGNATURE_ALGORITHMS)),
      'the HTTP signature list is the table the verifier reads, in its order');
      t.check(pqJose.verify('ML-DSA-44', pub, input, signature) === true &&
        stsCrypto.jwsSignatureValid('ML-DSA-44', pub, input, signature),
      'a post-quantum signature verifies by default');

      const signedHttp = stsCrypto.signHttpMessage(httpRequest(), httpOptions);
      t.check(signedHttp.ok, 'an HTTP message signature in ML-DSA is made',
        JSON.stringify(signedHttp));
      const httpMessage = Object.assign(httpRequest(), { headers: {
        host: 'example.com', 'signature-input': signedHttp.signatureInput,
        signature: signedHttp.signature } });
      t.check(stsCrypto.verifyHttpMessage(httpMessage, verifyOptions).ok,
        'and verifies by default');

      // ---- Post-quantum off: the doors that had no gate. -----------------
      config.setOverride(PQ, false);
      t.check(codeThrownBy(function () {
        return stsCrypto.jwsSignatureValid('ML-DSA-44', pub, input, signature);
      }) === 'STS-KEYS-0157',
      'jwsSignatureValid(), which GNAP jws and jwsd use, refuses it');
      t.check(codeThrownBy(function () {
        return helpers.signJwt({ sub: 'p' }, {}, { algorithm: 'ML-DSA-44' });
      }) === 'STS-KEYS-0158', 'signJwt() refuses post-quantum');
      t.check(policy.effective('jose', 'accept').every(function (alg) {
        return registry.bySpelling('jose', alg).pqc === null;
      }), 'nothing post-quantum is accepted');
      const unsigned = stsCrypto.signHttpMessage(httpRequest(), httpOptions);
      t.check(unsigned.ok === false && unsigned.errorCode === 'STS-KEYS-0177',
        'signHttpMessage() refuses post-quantum', JSON.stringify(unsigned));
      const unverified = stsCrypto.verifyHttpMessage(httpMessage,
                                                     verifyOptions);
      t.check(unverified.ok === false &&
        unverified.errorCode === 'STS-KEYS-0176',
      'verifyHttpMessage() refuses it before the signature',
      JSON.stringify(unverified));
      t.check(policy.acceptCause('httpsig', 'rsa-pss-sha512') === null,
        'a classical one is not');
      config.clearOverride(PQ);

      // ---- What the switch does NOT reach: COSE, for one, which passkeys use.
      config.setOverride(PQ, false);
      t.check(codeThrownBy(function () {
        return stsCrypto.verifyCoseSignature(-48, pub, input, signature);
      }) === null, 'COSE ML-DSA is not refused with the switch off');
      t.check(policy.acceptCause('jose', 'RS256') === null,
        'and neither is a classical JWS');
      config.clearOverride(PQ);

      // ---- EdDSA off, the default: signJwt() answers as signJwtAs(). ------
      t.check(codeThrownBy(function () {
        return helpers.signJwt({ sub: 'e' }, {}, { algorithm: 'EdDSA' });
      }) === 'STS-KEYS-0165', 'signJwt(EdDSA) is refused');
      t.check(codeThrownBy(function () {
        return helpers.signJwt({ sub: 'e' }, {},
          { algorithm: 'EdDSA', keyNamedElsewhere: true });
      }) === null, 'except where the key travels with the signature');
      t.check(helpers.usableSigningAlg('EdDSA') === 'RS256',
        'a setting naming EdDSA signs with RS256 instead');
      t.check(helpers.usableSigningAlg('ES256') === 'ES256',
        'a setting naming a usable algorithm keeps it');

      // ---- The list governs signJwt() too. --------------------------------
      config.setOverride(LIST, 'PS256,RS256');
      t.check(codeThrownBy(function () {
        return helpers.signJwt({ sub: 'l' }, {}, { algorithm: 'ES256' });
      }) === 'STS-KEYS-0166', 'signJwt() refuses an unlisted algorithm');
      t.check(codeThrownBy(function () {
        return helpers.signJwt({ sub: 'l' }, {},
          { algorithm: 'ES256', keyNamedElsewhere: true });
      }) === 'STS-KEYS-0166', 'the list applies wherever the key travels');
      t.check(typeof helpers.signJwt({ sub: 'l' }, {}) === 'string',
        'a default signature is made: the list always holds RS256');
      t.check(JSON.stringify(policy.effective('jose', 'sign')) ===
        JSON.stringify(['PS256', 'RS256']),
      'a configured list is in its own order');
      config.setOverride(LIST, 'ES256');
      t.check(policy.joseSignList().indexOf('RS256') >= 0,
        'RS256 is held in whatever an override says');
      config.clearOverride(LIST);

      // ---- A post-quantum token this realm signed verifies. ----------------
      const token = await helpers.signJwtAsAsync({ sub: 'own', iat: 1 },
                                                 'ML-DSA-44', null, {});
      t.check(helpers.verifyOwnJws(token, {}).sub === 'own',
        'verifyOwnJws() verifies this realm\'s own ML-DSA token');
    } finally {
      clear();
    }
  }
};
