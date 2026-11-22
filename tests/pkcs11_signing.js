// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pkcs11_signing.js
//
// ===========================================================================
// A REALM'S CLASSICAL SIGNING KEYS IN A HARDWARE SECURITY MODULE (#1955 P8,
// rcbj's D6: "both"): `keys.signingKeyStore=pkcs11` with the token
// `keys.signingKeyToken` names.
//
// In a CHILD PROCESS per module (the keystore and the key sets are the
// process's), with the protocol stack loaded and the keystore persisting
// into a store held in memory:
//
//   * a FAKE binding (`tests/tools/fake-pkcs11.js`), always;
//   * SOFTHSM2 where the image has it (see `tests/pkcs11_kek.js`), which also
//     MEASURES the signatures — the latency per signature is reported in the
//     finding's detail. Where it is missing that half is SKIPPED, not passed.
//
// Asserted:
//   A. the key set: the RS256 key, the XML key and every curve key the module
//      makes are HSM keys; post-quantum keys and a curve it does not make are
//      software, and `hsmKeyReport()` says which; the token holds them
//      sensitive and NOT extractable.
//   B. what is published is the HSM's public key: the JWKS, the self-signed
//      certificate.
//   C. what is signed verifies: an RS256 JWT through jsonwebtoken's framing
//      (claim conveniences), an ES256 JWT off the event loop, an EdDSA one,
//      and a SAML assertion against the XML key's certificate.
//   D. what is written down holds references and no private key.
//   E. a restart restores the same keys from the references, and they sign.
//   F. a rotation makes the next key in the HSM too.
//   G. the refusals: the HSM away is STS-KEYS-0201 and no crash, and comes
//      back; a realm asking for the HSM where the keystore does not persist is
//      STS-KEYS-0206; a post-quantum algorithm with an HSM key is 0206.
//   J. synchronous signing is off unless keys.pkcs11SynchronousSign is on
//      (STS-KEYS-0209). The child opts in so C–H can sign, then turns it
//      off. A module with no C_SignAsync refuses sign() the same way, and
//      signs once the setting is on.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'pkcs11_signing',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.PS_ROOT;
  const OUT = process.env.PS_OUT;
  const DIR = process.env.PS_DIR;
  const WHICH = process.env.PS_WHICH;
  const fs = require('fs');
  const nodeCrypto = require('crypto');
  const childProcess = require('child_process');
  const findings = [];
  const tag = WHICH === 'softhsm' ? 'SoftHSM2: ' : '';
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: tag + what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  async function refusedWith(fn) {
    try {
      await fn();
    } catch (e) {
      const all = String((e && e.message) || e)
        .match(/STS-[A-Z0-9]+-\d{4}/g) || [];
      const marked = require(ROOT + '/common/error_codes').codeOf(e);
      return (marked ? marked + ' ' : '') + all.join(' ') + ' :: ' +
        String((e && e.message) || e).slice(0, 300);
    }
    return 'not refused';
  }

  const rows = new Map();
  const store = {
    rows: rows,
    loadKeys: function () {
      return Promise.resolve(Array.from(rows.entries()).map(function (p) {
        return { realm: p[0], material: p[1] };
      }));
    },
    loadKey: function (key) {
      return Promise.resolve(rows.has(key) ? rows.get(key) : null);
    },
    saveKeys: function (key, text) {
      rows.set(key, text);
      return Promise.resolve();
    },
    deleteKeys: function (key) {
      rows.delete(key);
      return Promise.resolve();
    },
    mergeKeys: function (key, text, merge) {
      return Promise.resolve().then(function () {
        const current = rows.has(key) ? rows.get(key) : null;
        const next = current === null ? text : merge(current);
        if (next !== null && next !== undefined) {
          rows.set(key, next);
        }
        return { material: rows.get(key) };
      });
    }
  };

  const pinFile = DIR + '/pin';
  const kekFile = DIR + '/kek';
  fs.writeFileSync(kekFile, nodeCrypto.randomBytes(32).toString('base64'),
                   { mode: 0o600 });
  process.env.STS_KEYS_SOURCE = 'persisted';
  process.env.STS_KEYS_KEK_PROVIDER = 'file';
  process.env.STS_KEYS_KEK_FILE = kekFile;
  process.env.STS_SECRETS_ALLOW_LOCAL_SECRETS = 'true';
  process.env.STS_KEYS_SIGNING_KEY_STORE = 'pkcs11';
  // The synchronous doors below are the opt-in. The default is off.
  process.env.STS_KEYS_PKCS11_SYNCHRONOUS_SIGN = 'true';
  process.env.STS_KEYS_PKCS11_PIN_PROVIDER = 'file';
  process.env.STS_KEYS_PKCS11_PIN_REF = pinFile;

  let binding;
  if (WHICH === 'softhsm') {
    const conf = DIR + '/softhsm2.conf';
    fs.mkdirSync(DIR + '/tokens');
    fs.writeFileSync(conf, 'directories.tokendir = ' + DIR + '/tokens\n' +
                     'objectstore.backend = file\n');
    process.env.SOFTHSM2_CONF = conf;
    childProcess.execFileSync('softhsm2-util', ['--init-token', '--free',
      '--label', 'signing', '--so-pin', '5678', '--pin', '4321'],
      { stdio: 'ignore', env: process.env });
    fs.writeFileSync(pinFile, '4321');
    binding = require(process.env.PS_PKCS11JS);
    process.env.STS_KEYS_PKCS11_MODULE = process.env.PS_SOFTHSM_MODULE;
  } else {
    binding = require(ROOT + '/tests/tools/fake-pkcs11.js').fakeBinding({
      tokens: [{ label: 'signing', pin: '4321' }] });
    fs.writeFileSync(pinFile, '4321');
    process.env.STS_KEYS_PKCS11_MODULE = '/fake/libfake-pkcs11.so';
  }
  process.env.STS_KEYS_SIGNING_KEY_TOKEN = 'pkcs11:token=signing';

  (async function () {
    const secrets = require(ROOT + '/common/secrets');
    secrets.setSdkLoader(function (name) {
      if (name === 'pkcs11js') {
        return binding;
      }
      throw new Error('Cannot find module \'' + name + '\'');
    });
    require(ROOT + '/common/protocol_stack');
    const keystore = require(ROOT + '/common/keystore');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const stsCrypto = require(ROOT + '/common/crypto');
    const saml2 = require(ROOT + '/saml/saml2');
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    const REALM = realms.DEFAULT_ID;
    const keysNow = function () {
      return helpers.stsKeysFor.of(REALM);
    };

    // ------------------------------------------------------------ A
    const keys = keysNow();
    const report = realms.run(realms.get(REALM) || realms.DEFAULT_REALM,
                              helpers.hsmKeyReport);
    note(stsCrypto.isHsmKey(keys.privateKey) &&
         stsCrypto.isHsmKey(keys.privateKeyPem) &&
         stsCrypto.isHsmKey(keys.xmlKey.privateKeyPem),
         'A1. the RS256 key and the XML key are in the HSM',
         JSON.stringify(report));
    const curveIn = report.inHsm.filter(function (n) {
      return /^ES|EdDSA/.test(n);
    });
    note(curveIn.indexOf('ES256') >= 0 && curveIn.indexOf('ES384') >= 0 &&
         curveIn.some(function (n) { return /Ed25519/.test(n); }),
         'A2. and so are the curve keys the module makes',
         JSON.stringify(report.inHsm));
    note(report.inSoftware.every(function (n) {
      return /Ed448|ML-DSA|SLH-DSA|ES512|ES256K/.test(n);
    }) && report.inHsm.every(function (n) {
      return !/ML-DSA|SLH-DSA/.test(n);
    }), 'A3. what is in software is a curve the module does not make, or ' +
        'post-quantum — never an RSA or P-256 key',
         JSON.stringify(report.inSoftware));
    const token = secrets.heldSigningToken().token;
    const privs = token.find([{ type: 0x0, value: 3 }]);
    const attrs = privs.map(function (h) {
      const a = token.attributes(h, [0x162, 0x103]);
      return [a.get(0x162) && a.get(0x162)[0], a.get(0x103) &&
              a.get(0x103)[0]];
    });
    note(privs.length >= 3 && attrs.every(function (p) {
      return p[0] === 0 && p[1] === 1;
    }), 'A4. every private key in the token is sensitive and not ' +
        'extractable', privs.length + ' ' + JSON.stringify(attrs));

    // ------------------------------------------------------------ B
    const hsmPub = keys.privateKey.publicKey.export({ format: 'jwk' });
    const certPub = stsCrypto.publicKeyOf(keys.selfSignedCertPem ||
                                          keys.certPem)
      .export({ format: 'jwk' });
    note(hsmPub.n === certPub.n, 'B1. the RS256 key\'s certificate holds the ' +
         'HSM key\'s public key');
    const es = (keys.extraKeys || []).filter(function (one) {
      return one.alg === 'ES256';
    })[0];
    const esPub = es.privateKey.publicKey.export({ format: 'jwk' });
    note(es.publicJwk.x === esPub.x && es.publicJwk.y === esPub.y,
         'B2. the published ES256 JWK is the HSM key\'s');

    // ------------------------------------------------------------ C
    const rs = stsCrypto.signJws({ sub: 'p8', aud: 'p8' }, keys.privateKey,
      { algorithm: 'RS256', issuer: 'https://p8.test', expiresIn: 3600,
        keyid: keys.kid });
    let rsOk = false;
    try {
      rsOk = !!helpers.verifyOwnJws(rs);
    } catch (e) {
      rsOk = String((e && e.message) || e);
    }
    const rsBody = JSON.parse(Buffer.from(rs.split('.')[1], 'base64url'));
    note(rsOk === true && rsBody.iss === 'https://p8.test' &&
         rsBody.exp - rsBody.iat === 3600,
         'C1. an RS256 JWT with claim conveniences, signed in the HSM, ' +
         'verifies', String(rsOk));
    const t0 = process.hrtime.bigint();
    const esTok = await stsCrypto.signJwsAsync({ sub: 'p8' }, es.privateKey,
      { algorithm: 'ES256', keyid: es.publicJwk.kid });
    const t1 = process.hrtime.bigint();
    const esParts = esTok.split('.');
    note(nodeCrypto.verify('sha256', Buffer.from(esParts[0] + '.' +
           esParts[1]), { key: es.privateKey.publicKey,
                          dsaEncoding: 'ieee-p1363' },
         Buffer.from(esParts[2], 'base64url')),
         'C2. an ES256 JWT signed off the event loop verifies',
         Number(t1 - t0) / 1e6 + ' ms');
    const ed = (keys.extraKeys || []).filter(function (one) {
      return one.alg === 'EdDSA' && one.publicJwk.crv === 'Ed25519';
    })[0];
    const edTok = stsCrypto.signJws({ sub: 'p8' }, ed.privateKey,
      { algorithm: 'EdDSA', keyid: ed.publicJwk.kid });
    const edParts = edTok.split('.');
    note(stsCrypto.isHsmKey(ed.privateKey) &&
         nodeCrypto.verify(null, Buffer.from(edParts[0] + '.' + edParts[1]),
           ed.privateKey.publicKey, Buffer.from(edParts[2], 'base64url')),
         'C3. an EdDSA (Ed25519) JWT signed in the HSM verifies');
    let samlOk = 'not built';
    try {
      const assertion = saml2.buildSamlAssertion('p8-alice',
                                                 'https://sp.p8.test', 5);
      samlOk = stsCrypto.verifyXmlSignature(assertion, {
        element: 'Assertion', certPem: helpers.STS.xml.certPem }).ok;
    } catch (e) {
      samlOk = String((e && e.message) || e);
    }
    note(samlOk === true, 'C4. a SAML assertion signed by the XML key in the ' +
         'HSM verifies against its certificate', String(samlOk));

    // ------------------------------------------------------------ J
    // The child opted in. Off, a synchronous JWS refuses; the asynchronous
    // door still signs. On again before the rest of the cases.
    const config = require(ROOT + '/common/config');
    config.setOverride('keys.pkcs11SynchronousSign', false);
    const syncOff = await refusedWith(function () {
      return stsCrypto.signJws({ sub: 'off' }, keys.privateKey,
                               { algorithm: 'RS256' });
    });
    note(/STS-KEYS-0209/.test(syncOff),
         'J1. a synchronous JWS with an HSM key is refused while ' +
         'keys.pkcs11SynchronousSign is off', syncOff);
    const asyncStill = await stsCrypto.signJwsAsync({ sub: 'off' },
      es.privateKey, { algorithm: 'ES256', keyid: es.publicJwk.kid });
    note(asyncStill.split('.').length === 3,
         'J2. an asynchronous signature still signs while that setting ' +
         'is off');
    config.setOverride('keys.pkcs11SynchronousSign', true);
    let syncOn = 'not signed';
    try {
      syncOn = stsCrypto.signJws({ sub: 'on' }, keys.privateKey,
                                 { algorithm: 'RS256' }) ? 'signed' : '';
    } catch (e) {
      syncOn = String((e && e.message) || e);
    }
    note(syncOn === 'signed',
         'J3. the same door signs once the setting is on', syncOn);

    // ------------------------------------------------------------ I
    // DECRYPTION WITH THE REALM'S KEYS IN THE HSM (#1955 P8 follow-up):
    // what a partner encrypted to the realm's certificate or JWKS key.
    const plainXml = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:' +
      'SAML:2.0:assertion" ID="_p8">hsm</saml:Assertion>';
    // SoftHSM2 2.6 decrypts RSA-OAEP over SHA-1 only (measured), so there
    // SHA-256 is asserted to be REFUSED with the module's limit, and SHA-1
    // to open; the fake module (and a YubiHSM 2) does both.
    const codeOf = require(ROOT + '/common/error_codes').codeOf;
    const sealedXml = stsCrypto.encryptElement(plainXml,
      helpers.STS.xml.certPem, { keyTransport: 'rsa-oaep-mgf1p' });
    const openedXml = helpers.decryptOwnElement(sealedXml);
    note(openedXml && openedXml.ok && openedXml.xml === plainXml,
         'I1. an assertion encrypted to the XML key\'s certificate ' +
         '(rsa-oaep-mgf1p) opens through decryptOwnElement(), RSA-OAEP in ' +
         'the HSM', openedXml && openedXml.why);
    const sealed256 = stsCrypto.encryptElement(plainXml,
      helpers.STS.xml.certPem, { keyTransport: 'rsa-oaep' });
    const opened256 = stsCrypto.decryptElement(sealed256,
      keys.xmlKey.privateKeyPem);
    note(WHICH === 'softhsm'
      ? !opened256.ok && codeOf(opened256) === 'STS-KEYS-0207'
      : opened256.ok && opened256.xml === plainXml,
         WHICH === 'softhsm'
           ? 'I1a. rsa-oaep over SHA-256, which SoftHSM2 cannot decrypt, is ' +
             'refused with the module\'s limit (STS-KEYS-0207), not a crash'
           : 'I1a. and rsa-oaep over SHA-256 opens too',
         codeOf(opened256) + ' ' + (opened256.why || ''));
    const rsaJwk = keys.privateKey.publicKey.export({ format: 'jwk' });
    const rsaJwe = stsCrypto.encryptJweCompact('jwe-rsa',
      { alg: 'RSA-OAEP', enc: 'A256GCM', jwk: rsaJwk });
    const rsaBack = await stsCrypto.decryptJweCompactAsync(rsaJwe,
      { privateKey: keys.privateKey, allowedEnc: ['A256GCM'] });
    const rsaBackSync = stsCrypto.decryptJweCompact(rsaJwe,
      { privateKey: keys.privateKey, allowedEnc: ['A256GCM'] });
    note(rsaBack.plaintext === 'jwe-rsa' && rsaBackSync.plaintext ===
         'jwe-rsa', 'I2. a JWE RSA-OAEP to the RS256 key opens, off the ' +
         'loop and in place');
    const rsa256 = stsCrypto.encryptJweCompact('jwe-rsa-256',
      { alg: 'RSA-OAEP-256', enc: 'A256GCM', jwk: rsaJwk });
    const rsa256Back = await refusedWith(async function () {
      const got = await stsCrypto.decryptJweCompactAsync(rsa256,
        { privateKey: keys.privateKey, allowedEnc: ['A256GCM'] });
      if (got.plaintext !== 'jwe-rsa-256') {
        throw new Error('wrong plaintext');
      }
    });
    note(WHICH === 'softhsm' ? /STS-KEYS-0207/.test(rsa256Back)
                             : rsa256Back === 'not refused',
         WHICH === 'softhsm'
           ? 'I2a. RSA-OAEP-256 on SoftHSM2 is refused with STS-KEYS-0207'
           : 'I2a. and RSA-OAEP-256 opens too', rsa256Back);
    const ecJwe = stsCrypto.encryptJweCompact('jwe-ec',
      { alg: 'ECDH-ES+A128KW', enc: 'A128GCM', jwk: es.publicJwk });
    const ecBack = await stsCrypto.decryptJweCompactAsync(ecJwe,
      { privateKey: es.privateKey, allowedEnc: ['A128GCM'] });
    const ecDirect = stsCrypto.encryptJweCompact('jwe-ec-dir',
      { alg: 'ECDH-ES', enc: 'A256GCM', jwk: es.publicJwk });
    const ecDirectBack = stsCrypto.decryptJweCompact(ecDirect,
      { privateKey: es.privateKey, allowedEnc: ['A256GCM'] });
    note(ecBack.plaintext === 'jwe-ec' &&
         ecDirectBack.plaintext === 'jwe-ec-dir',
         'I3. a JWE ECDH-ES (direct and +A128KW) to the ES256 key opens, ' +
         'the agreement made in the HSM');
    const legacyXml = stsCrypto.encryptElement(plainXml,
      helpers.STS.xml.certPem, { keyTransport: 'rsa-1_5' });
    const legacyOpened = stsCrypto.decryptElement(legacyXml,
      keys.xmlKey.privateKeyPem);
    note(legacyOpened && !legacyOpened.ok,
         'I4. RSA PKCS#1 v1.5 is never asked of an HSM key',
         legacyOpened && (legacyOpened.why || ''));
    if (WHICH !== 'softhsm') {
      // A KEY MADE BEFORE THE KEYS COULD DECRYPT: its CKA_DECRYPT and
      // CKA_DERIVE taken away, as the first cut of P8 made them.
      const xmlRef = stsCrypto.hsmRefOf(keys.xmlKey.privateKeyPem);
      const xmlHandles = token.find([{ type: 0x0, value: 3 },
        { type: 0x102, value: Buffer.from(xmlRef.id, 'hex') }]);
      xmlHandles.forEach(function (h) {
        binding.withoutDecrypt(h);
      });
      const oldOpened = stsCrypto.decryptElement(sealedXml,
        keys.xmlKey.privateKeyPem);
      const oldCode = require(ROOT + '/common/error_codes').codeOf(oldOpened);
      note(!oldOpened.ok && oldCode === 'STS-KEYS-0208' &&
           /rotate/.test(oldOpened.why),
           'I5. an HSM key made without decryption is refused with ' +
           'STS-KEYS-0208 and the rotation that replaces it',
           oldCode + ' ' + oldOpened.why);
    }

    // ------------------------------------------------------------ D
    await keystore.settleAll();
    // What the keystore wrote, sealed, opened again: the members a PEM was
    // in hold references.
    const opened = keystore.privateMaterialFor(REALM) || {};
    const xmlPem = String((opened.xmlKey && opened.xmlKey.privateKeyPem) ||
                          '');
    const anyPem = Array.from(rows.values()).some(function (text) {
      return /BEGIN (RSA |EC )?PRIVATE KEY/.test(String(text));
    });
    note(String(opened.privateKeyPem || '').indexOf('pkcs11-key:v1:') === 0 &&
         (!xmlPem || xmlPem.indexOf('pkcs11-key:v1:') === 0) && !anyPem,
         'D1. the stored key set holds references where the private keys ' +
         'were, and no row holds a private key in the clear',
         String(opened.privateKeyPem || '').slice(0, 40) + ' / ' +
         xmlPem.slice(0, 40));

    // ------------------------------------------------------------ E
    const kid0 = keys.kid;
    keystore.reset();
    keystore.setStore(store);
    await keystore.start();
    helpers.resetStsKeys();
    const back = keysNow();
    const rs2 = stsCrypto.signJws({ sub: 'p8-again' }, back.privateKey,
      { algorithm: 'RS256', keyid: back.kid });
    let rs2Ok = false;
    try {
      rs2Ok = !!helpers.verifyOwnJws(rs2);
    } catch (e) {
      rs2Ok = String((e && e.message) || e);
    }
    note(back.kid === kid0 && stsCrypto.isHsmKey(back.privateKey) &&
         rs2Ok === true,
         'E1. a restart restores the same HSM keys from their references, ' +
         'and they sign', back.kid + ' / ' + kid0 + ' ' + rs2Ok);

    // ------------------------------------------------------------ F
    const minted = await helpers.ensureNextGenerations(REALM,
      { units: ['jose:RS256'] });
    const next = helpers.standbyOf(keysNow(), 'jose:RS256')
      .filter(function (one) { return one.role === 'next'; })[0];
    note(minted.ok && next && stsCrypto.isHsmKey(next.privateKey),
         'F1. a rotation\'s next key is made in the HSM',
         JSON.stringify(minted));

    // ------------------------------------------------------------ G
    const pq = await refusedWith(function () {
      return stsCrypto.signJws({ sub: 'x' }, keysNow().privateKey,
                               { algorithm: 'ML-DSA-44' });
    });
    note(/STS-KEYS-0206/.test(pq), 'G1. a post-quantum signature is never ' +
         'asked of an HSM key', pq);
    if (WHICH !== 'softhsm') {
      binding.breakAlways(true);
      const away = await refusedWith(function () {
        return stsCrypto.signJws({ sub: 'x' }, keysNow().privateKey,
                                 { algorithm: 'RS256' });
      });
      binding.breakAlways(false);
      note(/STS-KEYS-0201/.test(away), 'G2. the HSM away is a refusal with ' +
           'its code, not a crash', away);
      let back2 = 'not signed';
      try {
        back2 = stsCrypto.signJws({ sub: 'x' }, keysNow().privateKey,
                                  { algorithm: 'RS256' }) ? 'signed' : '';
      } catch (e) {
        back2 = String((e && e.message) || e);
      }
      note(back2 === 'signed', 'G3. and the next signature after it comes ' +
           'back reconnects', back2);
    }
    process.env.STS_KEYS_SOURCE = 'generated';
    keystore.reset();
    helpers.resetStsKeys();
    const notPersisting = await refusedWith(function () {
      return helpers.stsKeysFor.of(REALM).kid;
    });
    note(/STS-KEYS-0206/.test(notPersisting), 'G4. a realm asking for the ' +
         'HSM where the keystore does not persist is refused', notPersisting);
    process.env.STS_KEYS_SOURCE = 'persisted';
    helpers.resetStsKeys();

    // ------------------------------------------------------------ H
    if (WHICH === 'softhsm') {
      const k = keysNow();
      const N = 200;
      let a = process.hrtime.bigint();
      for (let i = 0; i < N; i++) {
        stsCrypto.signJws({ sub: 'm' + i }, k.privateKey,
                          { algorithm: 'RS256' });
      }
      const rsSync = Number(process.hrtime.bigint() - a) / 1e6 / N;
      const e256 = (k.extraKeys || []).filter(function (one) {
        return one.alg === 'ES256';
      })[0];
      a = process.hrtime.bigint();
      for (let i = 0; i < N; i++) {
        stsCrypto.signJws({ sub: 'm' + i }, e256.privateKey,
                          { algorithm: 'ES256' });
      }
      const esSync = Number(process.hrtime.bigint() - a) / 1e6 / N;
      a = process.hrtime.bigint();
      await Promise.all(Array.from({ length: N }, function (x, i) {
        return stsCrypto.signJwsAsync({ sub: 'm' + i }, e256.privateKey,
                                      { algorithm: 'ES256' });
      }));
      const esAsync = Number(process.hrtime.bigint() - a) / 1e6 / N;
      const soft = nodeCrypto.generateKeyPairSync('rsa',
        { modulusLength: 2048 }).privateKey;
      a = process.hrtime.bigint();
      for (let i = 0; i < N; i++) {
        stsCrypto.signJws({ sub: 'm' + i }, soft, { algorithm: 'RS256' });
      }
      const softSync = Number(process.hrtime.bigint() - a) / 1e6 / N;
      const xmlDoc = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:' +
        '2.0:assertion" ID="_m" IssueInstant="2026-11-20T00:00:00Z" ' +
        'Version="2.0"><saml:Issuer>p8</saml:Issuer></saml:Assertion>';
      a = process.hrtime.bigint();
      for (let i = 0; i < 50; i++) {
        stsCrypto.signXml(xmlDoc, { privateKeyPem: k.xmlKey.privateKeyPem,
                                    certPem: helpers.STS.xml.certPem });
      }
      const xmlSync = Number(process.hrtime.bigint() - a) / 1e6 / 50;
      const sealedM = stsCrypto.encryptElement(plainXml,
        helpers.STS.xml.certPem, { keyTransport: 'rsa-oaep' });
      a = process.hrtime.bigint();
      for (let i = 0; i < 50; i++) {
        stsCrypto.decryptElement(sealedM, k.xmlKey.privateKeyPem);
      }
      const decSync = Number(process.hrtime.bigint() - a) / 1e6 / 50;
      note(true, 'H2. what holds the event loop, measured: a software ' +
           'RS256 (RSA-2048) signature ' + softSync.toFixed(3) + ' ms in ' +
           'place against ' + rsSync.toFixed(3) + ' ms in the HSM; a SAML ' +
           'signature in the HSM ' + xmlSync.toFixed(3) + ' ms; an XML ' +
           'RSA-OAEP decryption in the HSM ' + decSync.toFixed(3) + ' ms');
      note(true, 'H1. latency per signature, measured (' + N + ' each): ' +
           'RS256 ' + rsSync.toFixed(3) + ' ms in place; ES256 ' +
           esSync.toFixed(3) + ' ms in place, ' + esAsync.toFixed(3) +
           ' ms each with ' + N + ' at once off the loop');
    }

    // A module with no C_SignAsync. The fake used above has one, so this
    // is a second token. Key generation stays synchronous.
    if (WHICH !== 'softhsm') {
      const pkcs11 = require(ROOT + '/common/crypto_impl/pkcs11');
      const nosyncPath = '/fake/libfake-pkcs11-nosync.so';
      const b2 = require(ROOT + '/tests/tools/fake-pkcs11.js')
        .fakeBinding({ modulePath: nosyncPath,
                       tokens: [{ label: 'nosync', pin: '4321' }] });
      delete b2.PKCS11.prototype.C_SignAsync;
      const token = pkcs11.openToken(b2, {
        modulePath: nosyncPath, tokenLabel: 'nosync', pin: '4321' });
      const pair = token.generateKeyPair({ kty: 'EC', crv: 'P-256' },
                                          'ns', Buffer.from('ns'));
      config.setOverride('keys.pkcs11SynchronousSign', false);
      let noAsync = 'not refused';
      try {
        await token.sign(pair.key, 'ES256', Buffer.from('abc'));
        noAsync = 'signed';
      } catch (e) {
        noAsync = (codeOf(e) || '') + ' ' + ((e && e.message) || e);
      }
      let noSync = 'not refused';
      try {
        token.signSync(pair.key, 'ES256', Buffer.from('abc'));
        noSync = 'signed';
      } catch (e) {
        noSync = (codeOf(e) || '') + ' ' + ((e && e.message) || e);
      }
      note(/STS-KEYS-0209/.test(noAsync) && /STS-KEYS-0209/.test(noSync),
           'J4. with no C_SignAsync, sign() and signSync refuse while ' +
           'synchronous signing is off', noAsync + ' | ' + noSync);
      config.setOverride('keys.pkcs11SynchronousSign', true);
      let blocked = null;
      try {
        blocked = token.signSync(pair.key, 'ES256', Buffer.from('abc'));
      } catch (e) {
        blocked = String((e && e.message) || e);
      }
      note(Buffer.isBuffer(blocked) && blocked.length > 0,
           'J5. and signSync uses C_Sign once the setting is on',
           Buffer.isBuffer(blocked) ? blocked.length : blocked);
      const fallen = await token.sign(pair.key, 'ES256',
                                      Buffer.from('def'));
      note(Buffer.isBuffer(fallen) && fallen.length > 0,
           'J6. sign() falls back to C_Sign only while the setting is on');
    }
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function runChild(which) {
  log.debug("Entering runChild(). " + which);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-pkcs11s-'));
  const out = path.join(dir, 'findings.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_(?!TEST_)|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, {
        LOG_LEVEL: 'fatal', PS_ROOT: ROOT, PS_OUT: out, PS_DIR: dir,
        PS_WHICH: which,
        PS_PKCS11JS: process.env.STS_TEST_PKCS11JS ||
                     '/opt/pkcs11js/node_modules/pkcs11js',
        PS_SOFTHSM_MODULE: process.env.STS_TEST_SOFTHSM_MODULE ||
                           '/usr/lib/softhsm/libsofthsm2.so' }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    log.debug("Caught in runChild(): " + ((e && e.message) || e));
  }
  log.debug("Leaving runChild().");
  return { findings: findings, result: result };
}

// Whether this image has SoftHSM2 and the binding.
function softHsmHere() {
  log.debug("Entering softHsmHere().");
  const module = process.env.STS_TEST_SOFTHSM_MODULE ||
                 '/usr/lib/softhsm/libsofthsm2.so';
  const binding = process.env.STS_TEST_PKCS11JS ||
                  '/opt/pkcs11js/node_modules/pkcs11js';
  let util = false;
  try {
    childProcess.execFileSync('softhsm2-util', ['--version'],
                              { stdio: 'ignore' });
    util = true;
  } catch (e) {
    log.debug("Caught in softHsmHere(): " + ((e && e.message) || e));
    util = false;
  }
  log.debug("Leaving softHsmHere().");
  return util && fs.existsSync(module) && fs.existsSync(binding);
}

function run(t) {
  log.debug("Entering run().");
  const halves = ['fake'].concat(softHsmHere() ? ['softhsm'] : []);
  halves.forEach(function (which) {
    const got = runChild(which);
    if (t.check(Array.isArray(got.findings), which + ': the child process ' +
                'reported its findings',
                'exit ' + got.result.status + ' ' +
                String(got.result.stderr || '').slice(-1500))) {
      got.findings.forEach(function (one) {
        t.check(one.ok, one.what, one.detail);
      });
    }
  });
  if (halves.length === 1) {
    t.check(true, 'SKIPPED, NOT PASSED: no SoftHSM2 here, so the signing ' +
                  'keys were held only to the fake module');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pkcs11_signing',
  describe: 'a realm\'s classical signing keys in a PKCS#11 HSM: made there, ' +
            'published, signing JWTs and SAML, restored, rotated, refused ' +
            'where they cannot be held, and refusing a synchronous signature ' +
            'while keys.pkcs11SynchronousSign is off — against a fake module ' +
            'and SoftHSM2',
  run: run
};
