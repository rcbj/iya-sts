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
      [PQ, EDDSA, LIST, 'keys.pqcOnly', 'keys.acceptedSigningAlgorithms',
       'cose.algorithms', 'cose.acceptedAlgorithms', 'saml.signatureAlgorithms',
       'saml.acceptedSignatureAlgorithms', 'saml.acceptedDigestAlgorithms',
       'pki.acceptedSignatureAlgorithms',
       'oauth2.httpSignatureAcceptedAlgorithms'].forEach(function (key) {
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

      // ---- The lists (phase 4). Empty by default, and empty is today. -------
      const lists = ['keys.acceptedSigningAlgorithms', 'keys.pqcOnly',
        'cose.algorithms', 'cose.acceptedAlgorithms',
        'saml.signatureAlgorithms', 'saml.acceptedSignatureAlgorithms',
        'saml.acceptedDigestAlgorithms', 'vc.cryptosuites',
        'vc.acceptedCryptosuites', 'pki.acceptedSignatureAlgorithms',
        'oauth2.httpSignatureAcceptedAlgorithms'];
      lists.forEach(function (key) {
        const row = config.SETTINGS.filter(function (one) {
          return one.key === key;
        })[0];
        t.check(!!row && row.group === 'Signing algorithms' &&
          row.runtime === true && !row.dflt,
        key + ' exists, runtime, empty or off by default');
      });
      const clearLists = function () {
        lists.forEach(function (key) {
          config.clearOverride(key);
        });
      };
      const write = function (key, value) {
        const problem = config.checkOverride(key, value);
        const code = problem ? config.checkOverrideCode(key, value) : '';
        return { problem: problem, code: code };
      };

      // JOSE: refused before the signature, at both doors.
      config.setOverride('keys.acceptedSigningAlgorithms', 'RS256');
      t.check(codeThrownBy(function () {
        return stsCrypto.jwsSignatureValid('ML-DSA-44', pub, input, signature);
      }) === 'STS-KEYS-0179', 'an unlisted JWS is refused first');
      t.check(policy.acceptCause('jose', 'RS256') === null,
        'a listed one is not');
      t.check(typeof helpers.verifyOwnJws(helpers.signJwt({ sub: 'self' }, {}),
                                          {}).sub === 'string',
      'the realm still reads its own tokens');
      config.clearOverride('keys.acceptedSigningAlgorithms');

      // HTTP signatures: one list for OAuth and GNAP.
      config.setOverride('oauth2.httpSignatureAcceptedAlgorithms', 'ES256');
      const httpRefused = stsCrypto.verifyHttpMessage(httpMessage,
                                                      verifyOptions);
      t.check(httpRefused.ok === false &&
        httpRefused.errorCode === 'STS-KEYS-0180',
      'an unlisted HTTP signature is refused', JSON.stringify(httpRefused));
      t.check(policy.acceptCause('httpsig', 'ecdsa-p256-sha256') === null,
        'RFC 9421\'s own name for a listed row is accepted');
      config.clearOverride('oauth2.httpSignatureAcceptedAlgorithms');

      // COSE: the door, and passkeys untouched.
      const prot = Buffer.from([0xa1, 0x01, 0x26]);
      const ec = require('crypto').generateKeyPairSync('ec',
        { namedCurve: 'prime256v1' });
      const coseSig = stsCrypto.coseSign1Sign(-7, ec.privateKey, prot, input);
      config.setOverride('cose.acceptedAlgorithms', 'ML-DSA-65');
      t.check(codeThrownBy(function () {
        return stsCrypto.coseSign1Verify(-7, ec.publicKey, prot, input,
                                         coseSig);
      }) === 'STS-KEYS-0181', 'an unlisted COSE_Sign1 is refused at the door');
      t.check(stsCrypto.verifyCoseSignature(-7, ec.publicKey,
        Buffer.from('x'), Buffer.alloc(64)) === false,
      'verifyCoseSignature(), which passkeys use, is not asked');
      config.clearOverride('cose.acceptedAlgorithms');
      config.setOverride('cose.algorithms', 'ML-DSA-65');
      t.check(codeThrownBy(function () {
        return stsCrypto.coseSign1Sign(-7, ec.privateKey, prot, input);
      }) === 'STS-KEYS-0186', 'an unlisted COSE signature is not made');
      config.clearOverride('cose.algorithms');

      // JOSE THROUGH THE LIBRARY PATH (2026-11-14, #444's D12): an ES256 JWS
      // — which jsonwebtoken verifies, not the shared verifier — is refused
      // under keys.acceptedSigningAlgorithms=RS256 with STS-KEYS-0179, as the
      // shared verifier's algorithms are. A client's private_key_jwt goes
      // this way.
      const jwtLib = require('jsonwebtoken');
      const es256 = jwtLib.sign({ iss: 'c', sub: 'c', aud: 'a' },
        ec.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        { algorithm: 'ES256', expiresIn: 60 });
      const ecPub = ec.publicKey.export({ type: 'spki', format: 'pem' });
      t.check(!!stsCrypto.verifyJws(es256, ecPub, { algorithms: ['ES256'] }),
        'an ES256 JWS verifies by default');
      config.setOverride('keys.acceptedSigningAlgorithms', 'RS256');
      t.check(codeThrownBy(function () {
        return stsCrypto.verifyJws(es256, ecPub, { algorithms: ['ES256'] });
      }) === 'STS-KEYS-0179', 'and is refused, STS-KEYS-0179, when the ' +
        'accepted list leaves ES256 out');
      config.clearOverride('keys.acceptedSigningAlgorithms');

      // XML: the verdict, and digests as a second list.
      const RSA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
      const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
      t.check(stsCrypto.xmlAlgorithmVerdict(RSA256, [SHA256]).problem === '',
        'an XML method is accepted by default');
      config.setOverride('saml.acceptedSignatureAlgorithms', 'RS256');
      t.check(stsCrypto.xmlAlgorithmVerdict(RSA256, [SHA256]).problem === '',
        'a listed XML method is accepted');
      t.check(stsCrypto.xmlAlgorithmVerdict(
        'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', [SHA256]).code ===
        'STS-KEYS-0182', 'an unlisted XML method is refused');
      config.clearOverride('saml.acceptedSignatureAlgorithms');
      config.setOverride('saml.acceptedDigestAlgorithms', 'SHA-512');
      t.check(stsCrypto.xmlAlgorithmVerdict(RSA256, [SHA256]).code ===
        'STS-KEYS-0183', 'an unlisted XML digest is refused');
      config.clearOverride('saml.acceptedDigestAlgorithms');

      // X.509: the row, by OID, with PSS's hash from its parameters.
      config.setOverride('pki.acceptedSignatureAlgorithms', 'RS256,PS384');
      t.check(policy.acceptX509Cause('1.2.840.113549.1.1.11') === null,
        'a listed certificate signature is accepted');
      t.check(policy.acceptX509Cause('1.2.840.10045.4.3.2').code ===
        'STS-KEYS-0185', 'an unlisted one is refused');
      const PSS = '1.2.840.113549.1.1.10';
      t.check(policy.acceptX509Cause(PSS, 'sha384') === null &&
        policy.acceptX509Cause(PSS, 'sha256') !== null,
      'RSASSA-PSS is told apart by its hash');
      config.clearOverride('pki.acceptedSignatureAlgorithms');

      // The path rule's check reaches an operator under its own code.
      t.check(require('../common/pki').authorityCode(
        { check: 'unaccepted-signature' }, 'STS-PKI-0000') === 'STS-KEYS-0185',
      'a path refused by the list reports the list\'s code');

      // keys.pqcOnly, and RS256's one place under it.
      config.setOverride('keys.pqcOnly', true);
      t.check(policy.signCause('jose', 'RS256').code === 'STS-KEYS-0191',
        'pqcOnly refuses a classical signature');
      t.check(policy.signCause('jose', 'RS256', { idToken: true }) === null,
        'RS256 stays for an ID Token (OpenID Connect Discovery)');
      t.check(policy.signCause('jose', 'ES256', { idToken: true }) !== null,
        'and only RS256');
      t.check(policy.signCause('jose', 'ML-DSA-65') === null,
        'post-quantum signs');
      t.check(policy.acceptCause('jose', 'RS256') === null,
        'and what is accepted does not change');
      t.check(policy.defaultJoseAlg() === 'ML-DSA-44',
        'the default is post-quantum under it', policy.defaultJoseAlg());
      t.check(policy.effective('jose', 'sign').every(function (alg) {
        return registry.bySpelling('jose', alg).pqc !== null;
      }), 'the effective list is post-quantum only');
      config.setOverride(LIST, 'ML-DSA-87,ML-DSA-65,RS256');
      t.check(policy.defaultJoseAlg() === 'ML-DSA-87',
        'a list\'s first usable element is the default');
      t.check(policy.signCause('jose', 'ML-DSA-44') !== null,
        'and a post-quantum algorithm it leaves out is refused');
      config.clearOverride(LIST);
      config.clearOverride('keys.pqcOnly');

      // keys.pqcOnly replaces a classical credential or status-list algorithm,
      // and leaves the documented EdDSA refusal to the operator.
      t.check(policy.underPqcOnly('RS256') === 'RS256' &&
        policy.underPqcOnly('EdDSA') === 'EdDSA',
      'underPqcOnly() changes nothing with the flag off');
      config.setOverride('keys.pqcOnly', true);
      t.check(policy.underPqcOnly('RS256') === 'ML-DSA-44',
        'and moves a classical choice to post-quantum with it on',
        policy.underPqcOnly('RS256'));
      t.check(policy.underPqcOnly('ML-DSA-65') === 'ML-DSA-65',
        'and leaves a post-quantum choice');
      config.clearOverride('keys.pqcOnly');
      config.setOverride('vc.acceptedCryptosuites', 'eddsa-jcs-2022');
      t.check(policy.acceptCause('di', 'bbs-2023').code === 'STS-KEYS-0184' &&
        policy.acceptCause('di', 'eddsa-jcs-2022') === null,
      'bbs-2023 is governed as a Data Integrity suite');
      config.clearOverride('vc.acceptedCryptosuites');

      // A configured list's first usable element is the default; empty is not.
      t.check(policy.defaultJoseAlg() === 'RS256', 'by default, RS256');
      config.setOverride(LIST, 'PS256,RS256');
      t.check(policy.defaultJoseAlg() === 'PS256' &&
        helpers.usableSigningAlg('ES256') === 'PS256',
      'a list\'s order is a preference, and what a setting falls back to');
      config.clearOverride(LIST);

      // The write rules.
      t.check(write('cose.algorithms', 'ES256,ES256').code === 'STS-KEYS-0189',
        'a list may not name an algorithm twice');
      t.check(write('keys.acceptedSigningAlgorithms', 'ES256').code ===
        'STS-KEYS-0190', 'an accept list must hold what the realm signs with');
      t.check(!write('keys.acceptedSigningAlgorithms', 'RS256,ES256').problem,
        'one that does is accepted');
      config.setOverride(LIST, 'PS256,RS256');
      t.check(write('keys.acceptedSigningAlgorithms', 'RS256').code ===
        'STS-KEYS-0190', 'and that is the configured sign list, where set');
      t.check(write('oauth2.signedMetadataAlgorithm', 'ES256').code ===
        'STS-KEYS-0192', 'a chosen algorithm must be within its list');
      t.check(!write('oauth2.signedMetadataAlgorithm', 'PS256').problem,
        'one that is, is accepted');
      config.clearOverride(LIST);
      t.check(write('saml.signatureAlgorithms', 'RS384').code ===
        'STS-KEYS-0192', 'a list may not leave out the chosen XML algorithm');
      config.setOverride('saml.signatureAlgorithms', 'RS256,RS512');
      t.check(write('saml.signatureAlgorithm', 'rsa-sha384').code ===
        'STS-KEYS-0192', 'saml.signatureAlgorithm stays within its list');
      t.check(!write('saml.signatureAlgorithm', 'rsa-sha512').problem,
        'and may name what is in it');
      config.clearOverride('saml.signatureAlgorithms');
      // A REALM'S OVERRIDES ARE ONE WRITE (2026-11-14, #444's D12): the
      // chosen algorithm is judged against the list beside it in the same
      // object, at a create and an update, as config/set judges it.
      const realms = require('../common/realms');
      const RID = 'sigpol' + process.pid;
      const madeBad = realms.create({ id: RID, name: 'Signature policy',
        overrides: { 'keys.signingAlgorithms': 'RS256',
                     'oauth2.accessTokenSigningAlg': 'ES256' } });
      t.check(madeBad && madeBad.ok === false &&
              errorCodes.codeOf(madeBad) === 'STS-KEYS-0192',
              'a realm created with a chosen algorithm outside the list in ' +
              'the same overrides is refused, STS-KEYS-0192',
              JSON.stringify(madeBad && (madeBad.errors || madeBad.ok)));
      const madeOk = realms.create({ id: RID, name: 'Signature policy',
        overrides: { 'keys.signingAlgorithms': 'RS256,ES256',
                     'oauth2.accessTokenSigningAlg': 'ES256' } });
      t.check(madeOk && madeOk.ok === true,
              'and taken when the list beside it holds it',
              JSON.stringify(madeOk && (madeOk.errors || madeOk.ok)));
      const updated = realms.update(RID, { overrides: {
        'keys.signingAlgorithms': 'RS256',
        'oauth2.signedMetadataAlgorithm': 'ES256' } });
      t.check(updated && updated.ok === false &&
              errorCodes.codeOf(updated) === 'STS-KEYS-0192',
              'an update is judged the same way',
              JSON.stringify(updated && (updated.errors || updated.ok)));
      // And one setting at a time (`/admin-api/realms/set`): the realm's own
      // list is the companion, not the caller's realm's.
      const RID2 = RID + 'b';
      realms.create({ id: RID2, name: 'Signature policy, one setting',
        overrides: { 'keys.signingAlgorithms': 'RS256' } });
      const setBad = realms.setOverride(RID2, 'oauth2.accessTokenSigningAlg',
                                        'ES256');
      t.check(setBad && setBad.ok === false &&
              errorCodes.codeOf(setBad) === 'STS-KEYS-0192',
              'realms/set of a chosen algorithm outside the realm\'s own ' +
              'list is refused, STS-KEYS-0192',
              JSON.stringify(setBad && (setBad.errors || setBad.ok)));
      const setOk = realms.setOverride(RID2, 'oauth2.accessTokenSigningAlg',
                                       'RS256');
      t.check(setOk && setOk.ok === true, 'and one within it is taken',
              JSON.stringify(setOk && (setOk.errors || setOk.ok)));
      realms.remove(RID2);
      realms.remove(RID);
      config.setOverride(PQ, false);
      t.check(write('keys.pqcOnly', true).code === 'STS-KEYS-0193',
        'pqcOnly cannot go on with post-quantum signing off');
      config.clearOverride(PQ);
      config.setOverride('keys.pqcOnly', true);
      t.check(write(PQ, false).code === 'STS-KEYS-0193',
        'nor can post-quantum signing go off under it');
      config.clearOverride('keys.pqcOnly');
      t.check(policy.writeRule('tls.signatureAlgorithms', 'nonsense').code ===
        'STS-KEYS-0194', 'a TLS sigalg must have a row');
      t.check(policy.writeRule('tls.signatureAlgorithms',
                               'ed25519:mldsa65') === null,
      'and one that has is accepted');
      clearLists();
    } finally {
      clear();
    }
  }
};
