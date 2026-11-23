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
//      signs once the setting is on; one with no C_DecryptAsync or
//      C_DeriveKeyAsync refuses a decryption or an agreement the same way.
//   K. (#1955 P8 follow-up, 2026-11-23) with the setting OFF, every door
//      signs or decrypts off the event loop: an access token, a JWS of each
//      kind, a SAML 2.0 and a SAML 1.1 assertion, a Redirect-binding
//      signature, any XML document, an EncryptedAssertion, answers fetched
//      ahead for WS-Trust, a JWE, a WS-Trust token, a key set and a
//      rotation — and holds nothing. Against the fake module the
//      asynchronous calls settle 25 ms later and the blocking calls throw,
//      so a timer scheduled before each operation fires before it resolves;
//      against SoftHSM2 the binding's blocking calls are made to throw.
//   H. (SoftHSM2) the latency, in place and off the loop.
//   K20. (SoftHSM2) no blocking PKCS#11 call of ANY kind is made on the
//      thread that serves — sessions, logins, searches, attribute reads and
//      each operation's Init are the control thread's.
//   L. a software key's output is byte-identical through the off-the-loop
//      twins: a JWS, an XML signature, a Redirect-binding signature, an XML
//      decryption; and the shared builders' twins answer alike (a published
//      JWT byte for byte, the PEP proxy's Response but for its fresh ids).
//   M. two tokens on one module meeting an outage at once recover with one
//      re-initialisation, after their operations drain, and both sign.
//   N. (SoftHSM2) another thread hears a re-initialisation on the outage
//      channel and does not finalize again for an outage met on an older
//      session, so this thread's new sessions survive.
//   E2, K20 also hold a thread's FIRST use of a key: found off the event
//      loop at the keystore's start and by `helpers.prepareKeySet()`.
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
    // M's second token on the same module, made before the module is
    // initialised so its slot list holds it.
    childProcess.execFileSync('softhsm2-util', ['--init-token', '--free',
      '--label', 'second', '--so-pin', '5678', '--pin', '4321'],
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
    // ------------------------------------------------------------ K
    // EVERY DOOR OFF THE EVENT LOOP, WITH THE SETTING OFF (#1955 P8
    // follow-up, 2026-11-23; rcbj: "I do not want this activity to block
    // the main event loop"). Each door signs or decrypts with
    // keys.pkcs11SynchronousSign off, and holds nothing:
    //   * the FAKE module's asynchronous calls settle 25 ms later on a timer
    //     and its blocking C_Sign / C_Decrypt / C_DeriveKey throw, so a
    //     timer scheduled before the operation fires before it resolves;
    //   * on SOFTHSM2 the binding's blocking C_Sign, C_Decrypt and
    //     C_DeriveKey are replaced by ones that throw, so a door that called
    //     one would fail — and the timer is reported (a real module may
    //     answer inside a millisecond, so it is not asserted there).
    config.setOverride('keys.pkcs11SynchronousSign', false);
    const heldToken = secrets.heldSigningToken().token;
    const realLib = heldToken.entry.lib;
    const blockingMade = [];
    const unpatched = {};
    if (WHICH === 'softhsm') {
      ['C_Sign', 'C_Decrypt', 'C_DeriveKey'].forEach(function (name) {
        unpatched[name] = realLib[name];
        realLib[name] = function () {
          blockingMade.push(name);
          throw new Error('the blocking ' + name + ' was called');
        };
      });
    } else {
      binding.slowAsyncOnly(25);
    }
    // NO BLOCKING CALL OF ANY KIND ON THIS THREAD (#1955 P8 follow-up): on
    // SoftHSM2 every other call of the binding this thread loaded is
    // recorded while K runs — C_OpenSession, C_Login, C_FindObjects*,
    // C_GetAttributeValue, every C_*Init, the key wrap's objects, C_Finalize
    // — after the token is made to open its sessions and find its keys again
    // (its idle sessions dropped, its generation moved). They are the control
    // thread's (`pkcs11_thread.js`), on its own copy of the binding, so this
    // thread may make the asynchronous calls and nothing else.
    const syncMade = [];
    const recorded = {};
    if (WHICH === 'softhsm') {
      const proto = Object.getPrototypeOf(realLib);
      Object.getOwnPropertyNames(proto).concat(Object.keys(realLib))
        .forEach(function (name) {
          if (!/^C_/.test(name) || /Async$/.test(name) ||
              Object.prototype.hasOwnProperty.call(recorded, name) ||
              Object.prototype.hasOwnProperty.call(unpatched, name) ||
              typeof realLib[name] !== 'function') {
            return;
          }
          recorded[name] = Object.prototype.hasOwnProperty.call(realLib, name)
            ? realLib[name] : null;
          const through = realLib[name];
          realLib[name] = function () {
            syncMade.push(name);
            return through.apply(realLib, arguments);
          };
        });
      heldToken.dropIdle();
      heldToken.generation++;
    }
    // AND A THREAD'S FIRST USE OF A KEY: the keys this thread resolved are
    // forgotten and its key sets dropped, as a new request worker starts
    // with neither, and the request middleware's road
    // (`helpers.prepareKeySet()`) finds them again before anything reads a
    // set — so K20 also holds that no first resolution searched the token on
    // this thread.
    stsCrypto.forgetHsmKeys();
    helpers.resetStsKeys();
    await helpers.prepareKeySet(REALM);
    async function offTheLoop(fn) {
      let fired = false;
      const timer = setTimeout(function () {
        fired = true;
      }, 0);
      const t0 = process.hrtime.bigint();
      let out;
      let error = null;
      try {
        out = await fn();
      } catch (e) {
        error = e;
      }
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      clearTimeout(timer);
      return { out: out, error: error, fired: fired, ms: ms };
    }
    function heldNothing(r) {
      return WHICH === 'softhsm' ? !r.error : (!r.error && r.fired);
    }
    function how(r) {
      return (r.error ? 'error: ' + ((r.error && r.error.message) ||
                                     r.error) + ' ' : '') +
             'timer first: ' + r.fired + ', ' + r.ms.toFixed(2) + ' ms';
    }
    const verifyJose = function (jws, publicKey, alg) {
      const parts = String(jws || '').split('.');
      const input = Buffer.from(parts[0] + '.' + parts[1]);
      const sig = Buffer.from(parts[2] || '', 'base64url');
      if (alg === 'EdDSA') {
        return nodeCrypto.verify(null, input, publicKey, sig);
      }
      return nodeCrypto.verify(alg === 'RS256' ? 'sha256' : 'sha256',
        input, alg === 'RS256' ? publicKey
                               : { key: publicKey,
                                   dsaEncoding: 'ieee-p1363' }, sig);
    };

    const k1 = await offTheLoop(function () {
      return helpers.signJwtOffLoop({ sub: 'k1', typ: 'Bearer' },
                                    { kind: 'access_token' });
    });
    let k1Ok = false;
    try {
      k1Ok = !!helpers.verifyOwnJws(k1.out);
    } catch (e) {
      k1Ok = String((e && e.message) || e);
    }
    note(heldNothing(k1) && k1Ok === true,
         'K1. an access token (helpers.signJwtOffLoop, RS256) signs in the ' +
         'HSM with the setting off, holding nothing', how(k1) + ' ' + k1Ok);
    const k2 = await offTheLoop(function () {
      return helpers.signJwtAsOffLoop({ sub: 'k2' }, 'ES256', null, {});
    });
    note(heldNothing(k2) && verifyJose(k2.out, es.privateKey.publicKey,
                                       'ES256'),
         'K2. an ES256 JWS (helpers.signJwtAsOffLoop: WS-Trust JWTs, SETs, ' +
         'software statements, FAPI client assertions) signs off the loop',
         how(k2));
    const k3 = await offTheLoop(function () {
      return stsCrypto.signJwsOffLoop({ sub: 'k3' }, ed.privateKey,
                                      { algorithm: 'EdDSA' });
    });
    note(heldNothing(k3) && verifyJose(k3.out, ed.privateKey.publicKey,
                                       'EdDSA'),
         'K3. an EdDSA JWS (stsCrypto.signJwsOffLoop) signs off the loop',
         how(k3));
    const k4 = await offTheLoop(function () {
      return saml2.buildSamlAssertionAsync('k4-alice', 'https://sp.k4.test',
                                           5);
    });
    let k4Ok = 'not built';
    try {
      k4Ok = stsCrypto.verifyXmlSignature(k4.out, {
        element: 'Assertion', certPem: helpers.STS.xml.certPem }).ok;
    } catch (e) {
      k4Ok = String((e && e.message) || e);
    }
    note(heldNothing(k4) && k4Ok === true && /<ds:SignatureValue>/.test(
           String(k4.out)),
         'K4. a SAML 2.0 assertion (saml2.buildSamlAssertionAsync: SSO, ' +
         'WS-Federation, WS-Trust) is signed off the loop and verifies',
         how(k4) + ' ' + k4Ok);
    const saml11 = require(ROOT + '/saml/saml11');
    const k5 = await offTheLoop(function () {
      return saml11.buildSaml11AssertionAsync({ subject: 'k5-alice',
        audience: 'https://rp.k5.test', lifetimeMin: 5 });
    });
    let k5Ok = 'not built';
    try {
      k5Ok = stsCrypto.verifyXmlSignature(k5.out, {
        element: 'Assertion', certPem: helpers.STS.xml.certPem }).ok;
    } catch (e) {
      k5Ok = String((e && e.message) || e);
    }
    note(heldNothing(k5) && k5Ok === true,
         'K5. a SAML 1.1 assertion (saml11.buildSaml11AssertionAsync) is ' +
         'signed off the loop and verifies', how(k5) + ' ' + k5Ok);
    const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const qs = 'SAMLResponse=abc&RelayState=k6&SigAlg=' +
               encodeURIComponent(RSA_SHA256);
    const k6 = await offTheLoop(function () {
      return stsCrypto.signQueryStringOffLoop(qs,
        helpers.STS.xmlSigner.privateKeyPem, RSA_SHA256,
        helpers.STS.xmlSigner.privateKey);
    });
    note(heldNothing(k6) && nodeCrypto.verify('sha256', Buffer.from(qs),
           stsCrypto.publicKeyOf(helpers.STS.xml.certPem),
           Buffer.from(String(k6.out || ''), 'base64')),
         'K6. an HTTP-Redirect binding signature ' +
         '(stsCrypto.signQueryStringOffLoop) is made off the loop',
         how(k6));
    const k7doc = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:' +
      '2.0:metadata" ID="_k7" entityID="https://k7.test"/>';
    const k7 = await offTheLoop(function () {
      return stsCrypto.signXmlOffLoop(k7doc, {
        privateKeyPem: helpers.STS.xmlSigner.privateKeyPem,
        privateKey: helpers.STS.xmlSigner.privateKey,
        certPem: helpers.STS.xmlSigner.certPem,
        placement: stsCrypto.PLACEMENT.FIRST, refUri: '#_k7' });
    });
    let k7Ok = 'not signed';
    try {
      k7Ok = stsCrypto.verifyXmlSignature(k7.out, {
        element: 'EntityDescriptor',
        certPem: helpers.STS.xml.certPem }).ok;
    } catch (e) {
      k7Ok = String((e && e.message) || e);
    }
    note(heldNothing(k7) && k7Ok === true,
         'K7. any XML document (stsCrypto.signXmlOffLoop: metadata, ' +
         'protocol messages) is signed off the loop and verifies',
         how(k7) + ' ' + k7Ok);
    const sealedK = stsCrypto.encryptElement(plainXml,
      helpers.STS.xml.certPem, { keyTransport: 'rsa-oaep-mgf1p' });
    const k8 = await offTheLoop(function () {
      return helpers.decryptOwnElementOffLoop(sealedK);
    });
    note(heldNothing(k8) && k8.out && k8.out.ok && k8.out.xml === plainXml,
         'K8. an EncryptedAssertion (helpers.decryptOwnElementOffLoop: ' +
         'SAML Single Logout\'s EncryptedID, an RFC 7522 grant) opens ' +
         'off the loop', how(k8) + ' ' + (k8.out && k8.out.why));
    const answers = await stsCrypto.hsmAnswersFor(function () {
      return helpers.decryptOwnElement(sealedK);
    });
    const k9 = stsCrypto.withHsmAnswers(answers, function () {
      return helpers.decryptOwnElement(sealedK);
    });
    const k9Bare = helpers.decryptOwnElement(sealedK);
    note(answers.size >= 1 && k9 && k9.ok && k9.xml === plainXml &&
         k9Bare && !k9Bare.ok,
         'K9. answers fetched ahead (stsCrypto.hsmAnswersFor: a WS-Trust ' +
         'encrypted request) open the synchronous door, which without them ' +
         'refuses', answers.size + ' answer(s); bare: ' +
         (k9Bare && k9Bare.why));
    const k10 = await offTheLoop(function () {
      return stsCrypto.decryptJweCompactAsync(rsaJwe,
        { privateKey: keys.privateKey, allowedEnc: ['A256GCM'] });
    });
    const k11 = await offTheLoop(function () {
      return stsCrypto.decryptJweCompactAsync(ecJwe,
        { privateKey: es.privateKey, allowedEnc: ['A128GCM'] });
    });
    note(heldNothing(k10) && heldNothing(k11) &&
         k10.out.plaintext === 'jwe-rsa' && k11.out.plaintext === 'jwe-ec',
         'K10. a JWE to the RS256 key (RSA-OAEP) and to the ES256 key ' +
         '(ECDH-ES+A128KW) opens off the loop', how(k10) + ' / ' + how(k11));
    const WsModel = require(ROOT + '/ws-trust/ws_model');
    const wstrust = require(ROOT + '/ws-trust/wstrust');
    const k12 = await offTheLoop(function () {
      return wstrust.buildTokenAsync(WsModel.term('wst.tokenType', 'saml2'),
        'k12-alice', 'https://rp.k12.test', 5);
    });
    const k12j = await offTheLoop(function () {
      return wstrust.buildTokenAsync(WsModel.term('wst.tokenType', 'jwt'),
        'k12-alice', 'https://rp.k12.test', 5);
    });
    let k12Ok = 'not built';
    try {
      k12Ok = stsCrypto.verifyXmlSignature(k12.out.xml, {
        element: 'Assertion', certPem: helpers.STS.xml.certPem }).ok;
    } catch (e) {
      k12Ok = String((e && e.message) || e);
    }
    const k12Jwt = /<wsse:BinarySecurityToken[^>]*>([^<]+)</.exec(
      String((k12j.out || {}).xml || ''));
    let k12jOk = false;
    try {
      k12jOk = !!helpers.verifyOwnJws(k12Jwt ? k12Jwt[1] : '');
    } catch (e) {
      k12jOk = String((e && e.message) || e);
    }
    note(heldNothing(k12) && heldNothing(k12j) && k12Ok === true &&
         k12jOk === true,
         'K11. a WS-Trust token (wstrust.buildTokenAsync), SAML 2.0 and JWT, ' +
         'is signed off the loop and verifies',
         how(k12) + ' ' + k12Ok + ' / ' + how(k12j) + ' ' + k12jOk);
    const syncXml = await refusedWith(function () {
      return stsCrypto.signXml(k7doc, {
        privateKeyPem: helpers.STS.xmlSigner.privateKeyPem,
        certPem: helpers.STS.xmlSigner.certPem });
    });
    const syncDec = stsCrypto.decryptElement(sealedK,
                                             keys.xmlKey.privateKeyPem);
    note(/STS-KEYS-0209/.test(syncXml) && syncDec && !syncDec.ok,
         'K12. the synchronous doors themselves still refuse an HSM key ' +
         'while the setting is off (STS-KEYS-0209), signing and decrypting',
         syncXml.slice(0, 120) + ' | ' + (syncDec && syncDec.why));
    // A key set made and rotated with the setting off: the certificate
    // over each RSA key is signed with C_SignAsync (prepareKeySet()).
    const realmsK = require(ROOT + '/common/realms');
    let k13 = 'not made';
    try {
      realmsK.create({ id: 'p8k' });
      const madeK = await offTheLoop(function () {
        return helpers.prepareKeySet('p8k');
      });
      const setK = helpers.stsKeysFor.of('p8k');
      const certK = new nodeCrypto.X509Certificate(setK.certPem);
      const xmlCertK = new nodeCrypto.X509Certificate(
        setK.xmlKey.selfSignedCertPem || setK.xmlKey.certPem);
      k13 = (stsCrypto.isHsmKey(setK.privateKeyPem) &&
             stsCrypto.isHsmKey(setK.xmlKey.privateKeyPem) &&
             certK.verify(setK.privateKey.publicKey) &&
             certK.publicKey.export({ format: 'jwk' }).n ===
               setK.privateKey.publicKey.export({ format: 'jwk' }).n &&
             !!xmlCertK && (WHICH === 'softhsm' || madeK.fired))
        ? 'made' : 'wrong: ' + how(madeK);
    } catch (e) {
      k13 = String((e && e.stack) || e).slice(0, 400);
    }
    note(k13 === 'made',
         'K13. a realm\'s key set is made in the HSM with the setting off, ' +
         'its self-signed certificates signed off the loop', k13);
    let k14 = 'not minted';
    try {
      const mintedK = await realmsK.run(realmsK.get('p8k'), function () {
        return helpers.ensureNextGenerations('p8k',
                                             { units: ['jose:RS256'] });
      });
      const nextK = helpers.standbyOf(helpers.stsKeysFor.of('p8k'),
                                      'jose:RS256')
        .filter(function (one) { return one.role === 'next'; })[0];
      k14 = mintedK.ok && nextK && stsCrypto.isHsmKey(nextK.privateKey) &&
            new nodeCrypto.X509Certificate(nextK.certPem)
              .verify(nextK.privateKey.publicKey)
        ? 'minted' : 'wrong: ' + JSON.stringify(mintedK);
    } catch (e) {
      k14 = String((e && e.stack) || e).slice(0, 400);
    }
    note(k14 === 'minted',
         'K14. a rotation\'s next RSA key is made with the setting off, its ' +
         'certificate signed off the loop', k14);
    // The protocol modules' own async twins (#1955 P8 follow-up): signed
    // metadata, SAML and WS-Federation, and a published JWT.
    const docs = [
      ['K16. SAML 2.0 IdP metadata (saml2_sso.metadataForAsync)',
       function () {
         return require(ROOT + '/saml/saml2_sso')
           .metadataForAsync('https://p8.test', '');
       }, 'EntityDescriptor'],
      ['K17. SAML 1.1 metadata (saml11_sso.metadataForAsync)',
       function () {
         return require(ROOT + '/saml/saml11_sso')
           .metadataForAsync('https://p8.test', '');
       }, 'EntityDescriptor'],
      ['K18. WS-Federation metadata (wsfed.federationMetadataAsync)',
       function () {
         return require(ROOT + '/ws-federation/wsfed')
           .federationMetadataAsync('https://p8.test');
       }, 'EntityDescriptor']
    ];
    for (let d = 0; d < docs.length; d++) {
      const r = await offTheLoop(docs[d][1]);
      const xml = r.out && typeof r.out === 'object' && r.out.xml
        ? r.out.xml : r.out;
      let ok = 'not signed';
      try {
        ok = /<ds:Signature/.test(String(xml)) &&
             stsCrypto.verifyXmlSignature(String(xml), {
               element: docs[d][2],
               certPem: helpers.STS.xml.certPem }).ok;
      } catch (e) {
        ok = String((e && e.message) || e);
      }
      note(heldNothing(r) && ok === true,
           docs[d][0] + ' is signed off the loop and verifies',
           how(r) + ' ' + ok);
    }
    const k19 = await offTheLoop(function () {
      return require(ROOT + '/oauth-oidc/oauth2').signPublishedDocumentAsync(
        { sub: 'k19' }, 'https://p8.test', 300, 'oauth-signed-metadata');
    });
    let k19Ok = false;
    try {
      k19Ok = !!helpers.verifyOwnJws(k19.out);
    } catch (e) {
      k19Ok = String((e && e.message) || e);
    }
    note(heldNothing(k19) && k19Ok === true,
         'K19. a published JWT — RFC 8414 signed_metadata, AuthZEN and ' +
         'OpenID4VCI metadata (oauth2.signPublishedDocumentAsync) — is ' +
         'signed off the loop and verifies', how(k19) + ' ' + k19Ok);
    if (WHICH === 'softhsm') {
      Object.keys(unpatched).forEach(function (name) {
        realLib[name] = unpatched[name];
      });
      Object.keys(recorded).forEach(function (name) {
        if (recorded[name]) {
          realLib[name] = recorded[name];
        } else {
          delete realLib[name];
        }
      });
      note(blockingMade.length === 0,
           'K15. no door called a blocking C_Sign, C_Decrypt or C_DeriveKey ' +
           'with the setting off', JSON.stringify(blockingMade));
      note(syncMade.length === 0 && heldToken.entry.control.started >= 1,
           'K20. nor any other blocking PKCS#11 call on this thread — the ' +
           'sessions were opened and logged in, the keys found again, each ' +
           'operation begun and the key-set certificates\' public keys read ' +
           'by the control thread', JSON.stringify(syncMade.slice(0, 40)) +
           ' (' + syncMade.length + ' call(s)); control threads started: ' +
           heldToken.entry.control.started);
    } else {
      const made = binding.slowAsyncOnly(0);
      note(made.length === 0,
           'K15. no door called a blocking C_Sign, C_Decrypt or C_DeriveKey ' +
           'with the setting off', JSON.stringify(made));
    }
    config.setOverride('keys.pkcs11SynchronousSign', true);

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
    // A START WITH NOTHING RESOLVED (#1955 P8 follow-up): the keystore finds
    // every stored HSM key through the control thread before it finishes,
    // so reading the set after it makes no blocking PKCS#11 call here.
    stsCrypto.forgetHsmKeys();
    await keystore.start();
    helpers.resetStsKeys();
    const startLib = secrets.heldSigningToken().token.entry.lib;
    const startCalls = [];
    const startSaved = {};
    if (WHICH === 'softhsm') {
      Object.getOwnPropertyNames(Object.getPrototypeOf(startLib))
        .forEach(function (name) {
          if (!/^C_/.test(name) || /Async$/.test(name)) {
            return;
          }
          startSaved[name] = true;
          const through = startLib[name];
          startLib[name] = function () {
            startCalls.push(name);
            return through.apply(startLib, arguments);
          };
        });
    }
    const back = keysNow();
    void back.kid;
    void (back.extraKeys || []).length;
    if (WHICH === 'softhsm') {
      Object.keys(startSaved).forEach(function (name) {
        delete startLib[name];
      });
      note(startCalls.length === 0,
           'E2. the keystore\'s start found the stored HSM keys off the ' +
           'event loop: reading the restored set made no blocking PKCS#11 ' +
           'call', JSON.stringify(startCalls.slice(0, 20)));
    }
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
      // OFF THE LOOP (#1955 P8 follow-up): the same operations through the
      // asynchronous doors, N at once — wall time per operation, and the
      // longest the event loop went without turning while they ran.
      const lag = { worst: 0, last: Date.now(), on: true };
      const beat = function () {
        const now = Date.now();
        lag.worst = Math.max(lag.worst, now - lag.last);
        lag.last = now;
        if (lag.on) {
          setTimeout(beat, 1);
        }
      };
      setTimeout(beat, 1);
      a = process.hrtime.bigint();
      await Promise.all(Array.from({ length: N }, function (x, i) {
        return stsCrypto.signJwsOffLoop({ sub: 'm' + i }, k.privateKey,
                                        { algorithm: 'RS256' });
      }));
      const rsAsync = Number(process.hrtime.bigint() - a) / 1e6 / N;
      a = process.hrtime.bigint();
      await Promise.all(Array.from({ length: 50 }, function () {
        return stsCrypto.signXmlOffLoop(xmlDoc,
          { privateKeyPem: k.xmlKey.privateKeyPem,
            certPem: helpers.STS.xml.certPem });
      }));
      const xmlAsync = Number(process.hrtime.bigint() - a) / 1e6 / 50;
      a = process.hrtime.bigint();
      await Promise.all(Array.from({ length: 50 }, function () {
        return stsCrypto.decryptElementOffLoop(sealedM,
                                               k.xmlKey.privateKeyPem);
      }));
      const decAsync = Number(process.hrtime.bigint() - a) / 1e6 / 50;
      lag.on = false;
      note(true, 'H3. off the loop, measured: RS256 ' + rsAsync.toFixed(3) +
           ' ms each with ' + N + ' at once; a SAML signature ' +
           xmlAsync.toFixed(3) + ' ms each with 50 at once; an XML ' +
           'RSA-OAEP decryption ' + decAsync.toFixed(3) + ' ms each with ' +
           '50 at once; the event loop\'s longest gap meanwhile ' +
           lag.worst + ' ms');
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
      delete b2.PKCS11.prototype.C_DeriveKeyAsync;
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
      const peerJwk = nodeCrypto.generateKeyPairSync('ec',
        { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
      const peerPoint = Buffer.concat([Buffer.from([4]),
        Buffer.from(peerJwk.x, 'base64url'),
        Buffer.from(peerJwk.y, 'base64url')]);
      let noDerive = 'not refused';
      try {
        await token.deriveEcdh(pair.key, peerPoint, 32, true);
        noDerive = 'derived';
      } catch (e) {
        noDerive = (codeOf(e) || '') + ' ' + ((e && e.message) || e);
      }
      note(/STS-KEYS-0209/.test(noDerive),
           'J4a. with no C_DeriveKeyAsync, an ECDH agreement asked off the ' +
           'loop refuses while the setting is off, before C_DeriveKey',
           noDerive);
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
      let derivedOn = null;
      try {
        derivedOn = await token.deriveEcdh(pair.key, peerPoint, 32, true);
      } catch (e) {
        derivedOn = String((e && e.message) || e);
      }
      note(Buffer.isBuffer(derivedOn) && derivedOn.length === 32,
           'J6a. and the agreement falls back to C_DeriveKey only while the ' +
           'setting is on', Buffer.isBuffer(derivedOn) ? derivedOn.length
                                                     : derivedOn);
    }

    // ------------------------------------------------------------ L
    // A SOFTWARE KEY'S OUTPUT IS BYTE-IDENTICAL through the off-the-loop
    // twins (#1955 P8 follow-up): the twin IS the synchronous door, called
    // and resolved. RS256 and RSA-SHA256 (PKCS#1 v1.5) are deterministic, so
    // the same input signs to the same bytes.
    config.setOverride('keys.pkcs11SynchronousSign', false);
    const softPair = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 2048 });
    const softPem = softPair.privateKey.export({ type: 'pkcs8',
                                                 format: 'pem' });
    const jwsOpts = { algorithm: 'RS256', keyid: 'soft', noTimestamp: true };
    const softSync = stsCrypto.signJws({ sub: 'l1', n: 1 }, softPem,
                                       jwsOpts);
    const softTwin = await stsCrypto.signJwsOffLoop({ sub: 'l1', n: 1 },
                                                    softPem, jwsOpts);
    note(typeof softSync === 'string' && softSync === softTwin,
         'L1. a software RS256 JWS is the same bytes through ' +
         'signJwsOffLoop() as through signJws()',
         String(softSync).slice(-24) + ' / ' + String(softTwin).slice(-24));
    const softCert = stsCrypto.selfSignedRsaCertificate({
      bits: 2048, rsaPrivateKeyPem: softPem, commonName: 'l2',
      serialPrefix: 'l2', years: 1 });
    const lDoc = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:' +
      '2.0:metadata" ID="_l2" entityID="https://l2.test"/>';
    const xmlOpts = { privateKeyPem: softPem, certPem: softCert.certPem,
                      placement: stsCrypto.PLACEMENT.FIRST, refUri: '#_l2' };
    const xmlSyncL = stsCrypto.signXml(lDoc, xmlOpts);
    const xmlTwinL = await stsCrypto.signXmlOffLoop(lDoc, xmlOpts);
    note(typeof xmlSyncL === 'string' && xmlSyncL === xmlTwinL,
         'L2. a software key\'s XML signature is the same bytes through ' +
         'signXmlOffLoop() as through signXml()',
         String(xmlSyncL).length + ' / ' + String(xmlTwinL).length);
    const lQs = 'SAMLRequest=l3&SigAlg=' + encodeURIComponent(
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    const qsSync = stsCrypto.signQueryString(lQs, softPem,
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    const qsTwin = await stsCrypto.signQueryStringOffLoop(lQs, softPem,
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    note(qsSync === qsTwin && !!qsSync,
         'L3. a software key\'s Redirect-binding signature is the same ' +
         'bytes off the loop');
    const lSealed = stsCrypto.encryptElement(plainXml, softCert.certPem,
                                             { keyTransport: 'rsa-oaep' });
    const decSyncL = stsCrypto.decryptElement(lSealed, softPem);
    const decTwinL = await stsCrypto.decryptElementOffLoop(lSealed, softPem);
    note(decSyncL && decSyncL.ok && decTwinL && decTwinL.ok &&
         decSyncL.xml === decTwinL.xml && decSyncL.xml === plainXml,
         'L4. a software key\'s XML decryption answers the same through ' +
         'decryptElementOffLoop()', (decTwinL && decTwinL.why) || '');
    config.setOverride('keys.pkcs11SynchronousSign', true);
    // THE SHARED BUILDERS (#1955 P8 follow-up): the twins of a published
    // JWT and of the PEP proxy's Response share every step but the
    // signature. RS256 is deterministic, so a published JWT is the same
    // bytes both ways within one second (asked again across a boundary).
    const oauth2L = require(ROOT + '/oauth-oidc/oauth2');
    let l5 = 'not signed';
    for (let i = 0; i < 3; i++) {
      const second0 = Math.floor(Date.now() / 1000);
      const a5 = oauth2L.signPublishedDocument({ sub: 'l5' },
        'https://l5.test', 300, 'oauth-signed-metadata');
      const b5 = await oauth2L.signPublishedDocumentAsync({ sub: 'l5' },
        'https://l5.test', 300, 'oauth-signed-metadata');
      if (Math.floor(Date.now() / 1000) !== second0) {
        continue;
      }
      l5 = a5 === b5 ? 'same' : 'different: ' + String(a5).slice(-20) +
                                 ' / ' + String(b5).slice(-20);
      break;
    }
    note(l5 === 'same',
         'L5. a published JWT is the same bytes through ' +
         'signPublishedDocumentAsync() as through signPublishedDocument()',
         l5);
    // The Response carries fresh IDs and instants, so it is compared with
    // those (and the digests and signatures over them) blanked.
    const sso2L = require(ROOT + '/saml/saml2_sso');
    const blank = function (xml) {
      return String(xml || '')
        .replace(new RegExp('\\b(ID|IssueInstant|NotBefore|NotOnOrAfter|' +
          'AuthnInstant|SessionIndex|SessionNotOnOrAfter|URI)="[^"]*"', 'g'),
                 '$1=""')
        .replace(/<(ds:DigestValue|ds:SignatureValue)>[^<]*</g, '<$1><')
        .replace(/>_[0-9a-f]{20,}</g, '><');
    };
    let l6 = 'not built';
    try {
      const sessionL = { id: 'l6-session', user: { username: 'l6-alice' },
                         authTime: Math.floor(Date.now() / 1000),
                         amr: ['pwd'] };
      const optsL = { session: sessionL, spEntityId: 'https://sp.l6.test',
                      acsUrl: 'https://sp.l6.test/acs' };
      const a6 = sso2L.pepProxyResponse(optsL);
      const b6 = await sso2L.pepProxyResponseAsync(optsL);
      l6 = a6.ok && b6.ok && blank(a6.xml) === blank(b6.xml) &&
           /<ds:SignatureValue>/.test(a6.xml)
        ? 'same' : 'different: ' + JSON.stringify([a6.ok, b6.ok,
                                                  a6.why, b6.why]);
    } catch (e) {
      l6 = String((e && e.stack) || e).slice(0, 400);
    }
    note(l6 === 'same',
         'L6. the PEP proxy\'s Response is the same document both ways, ' +
         'but for its fresh identifiers, instants and the signatures over ' +
         'them', l6);

    // ------------------------------------------------------------ M
    // TWO TOKENS ON ONE MODULE RECOVER TOGETHER (#1955 P8 follow-up): an
    // outage met on both at once initialises the shared module again ONCE,
    // after the operations holding its sessions drain; every session from
    // before is forgotten, none is lent again, and both tokens sign after
    // it. The fake loses its device; SoftHSM2 is told it did (the recovery
    // itself, C_Finalize and C_Initialize, is real).
    {
      const pkcs11M = require(ROOT + '/common/crypto_impl/pkcs11');
      let bindingM = binding;
      let modulePathM = String(process.env.STS_KEYS_PKCS11_MODULE);
      let first;
      if (WHICH === 'softhsm') {
        first = heldToken;
      } else {
        modulePathM = '/fake/libfake-pkcs11-pair.so';
        bindingM = require(ROOT + '/tests/tools/fake-pkcs11.js')
          .fakeBinding({ modulePath: modulePathM,
                         tokens: [{ label: 'one', pin: '4321' },
                                  { label: 'second', pin: '4321' }] });
        first = pkcs11M.openToken(bindingM, { modulePath: modulePathM,
          tokenLabel: 'one', pin: '4321', maxSessions: 3 });
      }
      const second = pkcs11M.openToken(bindingM, { modulePath: modulePathM,
        tokenLabel: 'second', pin: '4321', maxSessions: 3 });
      let m = 'not run';
      try {
        const keyA = await first.generateKeyPairAsync(
          { kty: 'EC', crv: 'P-256' }, 'm-a', nodeCrypto.randomBytes(8));
        const keyB = await second.generateKeyPairAsync(
          { kty: 'EC', crv: 'P-256' }, 'm-b', nodeCrypto.randomBytes(8));
        const epoch0 = first.entry.epoch;
        const sameEntry = first.entry === second.entry;
        const signs = function (n) {
          const out = [];
          for (let i = 0; i < n; i++) {
            out.push(first.sign(keyA.key, 'ES256', Buffer.from('a' + i)));
            out.push(second.sign(keyB.key, 'ES256', Buffer.from('b' + i)));
          }
          return out;
        };
        const before = signs(3);
        let recovered;
        if (WHICH === 'softhsm') {
          // Both tokens meet a lost device while their signatures are in
          // flight.
          recovered = Promise.all([first.recover({ code: 0x30,
                                                   message: 'test' }),
                                   second.recover({ code: 0x30,
                                                    message: 'test' })]);
        } else {
          bindingM.loseDevice();
          recovered = Promise.resolve();
        }
        const settled = await Promise.allSettled(before.concat([recovered]));
        const after = await Promise.allSettled(signs(2));
        const failed = settled.concat(after).filter(function (r) {
          return r.status !== 'fulfilled';
        }).map(function (r) {
          return String((r.reason && r.reason.message) || r.reason);
        });
        const verifies = await first.sign(keyA.key, 'ES256',
                                          Buffer.from('m-check'));
        const ok = nodeCrypto.verify('sha256', Buffer.from('m-check'),
          { key: keyA.publicKey, dsaEncoding: 'ieee-p1363' }, verifies);
        m = JSON.stringify({ sameEntry: sameEntry,
          epochMoved: first.entry.epoch - epoch0,
          failed: failed, verifies: ok,
          lent: [first.lent, second.lent],
          inflight: first.entry.inflight,
          open: [first.open, second.open],
          recovering: !!first.entry.recovering });
        const parsed = JSON.parse(m);
        m = sameEntry && parsed.epochMoved === 1 && !failed.length && ok &&
            parsed.inflight === 0 && !parsed.recovering &&
            first.lent === 0 && second.lent === 0 &&
            first.open >= 1 && first.open <= first.maxSessions + 1 &&
            second.open >= 1 && second.open <= second.maxSessions + 1
          ? 'recovered ' + m : 'wrong ' + m;
      } catch (e) {
        m = String((e && e.stack) || e).slice(0, 600);
      }
      note(/^recovered/.test(m),
           'M1. two tokens on one module meeting an outage at once recover ' +
           'with ONE re-initialisation, after their operations drain, and ' +
           'both sign after it', m);
      second.close();
    }

    // ------------------------------------------------------------ N
    // ANOTHER THREAD'S OUTAGE (#1955 P8 follow-up, SoftHSM2): C_Finalize is
    // process-wide. This thread initialises the module again and says so on
    // the outage channel; a worker thread on the same module hears it, and
    // when it then meets a device error on a session opened before, it does
    // NOT finalize again — so this thread's fresh sessions survive and its
    // next signature needs no reconnect.
    if (WHICH === 'softhsm') {
      const workerThreads = require('worker_threads');
      const wcode = [
        "const { parentPort, workerData } = require('worker_threads');",
        "const binding = require(workerData.bindingPath);",
        "const pk = require(workerData.root +",
        "  '/common/crypto_impl/pkcs11');",
        "(async function () {",
        "  const t = pk.openToken(binding, {",
        "    modulePath: workerData.modulePath,",
        "    tokenLabel: 'second', pin: '4321', maxSessions: 2 });",
        "  const k = await t.generateKeyPairAsync({ kty: 'EC', crv: 'P-256' },",
        "    'n', require('crypto').randomBytes(8));",
        "  await t.sign(k.key, 'ES256', Buffer.from('x'));",
        "  const epoch0 = t.entry.epoch;",
        "  parentPort.on('message', async function (m) {",
        "    try {",
        "      if (m.ask === 'epoch') {",
        "        parentPort.postMessage({ epoch: t.entry.epoch });",
        "      } else if (m.ask === 'outage') {",
        "        await t.recover({ code: 0x30, message: 'test' }, epoch0);",
        "        const sig = await t.sign(k.key, 'ES256', Buffer.from('y'));",
        "        parentPort.postMessage({ recovered: true, sig: sig.length });",
        "      }",
        "    } catch (e) {",
        "      parentPort.postMessage({ error: String((e && e.stack) || e) });",
        "    }",
        "  });",
        "  parentPort.postMessage({ ready: true, epoch: epoch0 });",
        "})().catch(function (e) {",
        "  parentPort.postMessage({ error: String((e && e.stack) || e) });",
        "});"].join('\n');
      let n = 'not run';
      const w = new workerThreads.Worker(wcode, { eval: true,
        workerData: { root: ROOT, bindingPath: process.env.PS_PKCS11JS,
                      modulePath: String(process.env.STS_KEYS_PKCS11_MODULE) }
      });
      const nextOf = function (pred) {
        return new Promise(function (resolve) {
          const f = function (msg) {
            if (msg.error || pred(msg)) {
              w.off('message', f);
              resolve(msg);
            }
          };
          w.on('message', f);
        });
      };
      try {
        const ready = await nextOf(function (msg) {
          return msg.ready;
        });
        if (ready.error) {
          throw new Error(ready.error);
        }
        const mainKey = await heldToken.generateKeyPairAsync(
          { kty: 'EC', crv: 'P-256' }, 'n-main', nodeCrypto.randomBytes(8));
        await heldToken.recover({ code: 0x30, message: 'test' });
        let moved = { epoch: ready.epoch };
        for (let i = 0; i < 50 && moved.epoch === ready.epoch; i++) {
          await new Promise(function (resolve) {
            setTimeout(resolve, 20);
          });
          w.postMessage({ ask: 'epoch' });
          moved = await nextOf(function (msg) {
            return msg.epoch !== undefined;
          });
        }
        await heldToken.sign(mainKey.key, 'ES256', Buffer.from('n1'));
        const before = heldToken.reconnects;
        w.postMessage({ ask: 'outage' });
        const got = await nextOf(function (msg) {
          return msg.recovered;
        });
        const after = await heldToken.sign(mainKey.key, 'ES256',
                                           Buffer.from('n2'));
        n = JSON.stringify({ heard: moved.epoch !== ready.epoch,
                             worker: got.recovered ? 'signed' : got.error,
                             reconnects: heldToken.reconnects - before,
                             signed: nodeCrypto.verify('sha256',
                               Buffer.from('n2'),
                               { key: mainKey.publicKey,
                                 dsaEncoding: 'ieee-p1363' }, after) });
        const parsed = JSON.parse(n);
        n = (parsed.heard && parsed.worker === 'signed' &&
             parsed.reconnects === 0 && parsed.signed ? 'held ' : 'wrong ') +
            n;
      } catch (e) {
        n = String((e && e.stack) || e).slice(0, 600);
      }
      await w.terminate();
      note(/^held/.test(n),
           'N1. a worker thread hears this thread initialise the module ' +
           'again, and an outage it then meets on an older session does not ' +
           'finalize it again: this thread signs after it with no reconnect',
           n);
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
            'where they cannot be held, and signing and decrypting off the ' +
            'event loop on every door while keys.pkcs11SynchronousSign is ' +
            'off — against a fake module and SoftHSM2',
  run: run
};
