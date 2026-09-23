'use strict';
//
// File: federation_encryption.js
//
// ===========================================================================
// A PARTNER'S ENCRYPTED ASSERTION OR ID TOKEN (#168), IN PROCESS, IN BOTH
// MODES.
//
// `federation/federation_encryption.ts` owns each service-provider-side
// relationship's encryption key — issued under the realm's Intermediate,
// rotated with a grace period, published, and decrypted with under exactly
// the algorithms the relationship accepts — and `common/crypto.js` performs
// the XML Encryption and JWE underneath. `tests/vendored/
// sts_federation_encryption.js` drives the sign-ins over HTTP with an
// independent encryptor; this file pins what is cheaper at the function:
//
//   0. the mode predicate, and when plaintext is refused;
//   1. XML Encryption in common/crypto.js: XML Encryption 1.1's rsa-oaep
//      (SHA-256, MGF1-SHA-256) and ECDH-ES key agreement round-trip, and a
//      caller's allow-list refuses before any key operation;
//   2. a relationship's key: issued at create through the console's action,
//      under the realm's Intermediate, keyEncipherment for RSA and
//      keyAgreement for EC, sealed in product and never in a view;
//   3. the four fields: the defaults, the refusals — AES-CBC, rsa-1_5 and
//      RSA1_5 in every mode, an algorithm the key cannot do, a field on SAML
//      1.1 — and a new key type issuing a key of that type;
//   4. decryptXml(): the configured algorithms decrypt; every other one is
//      STS-FED-0139; every decryption failure is STS-FED-0138 with ONE
//      sentence;
//   5. decryptJwe(): the same for an ID Token, and a kid naming no key held;
//   6. rotation: the replaced key decrypts through its grace and not after
//      it, a zero grace drops it at once, and the retirement job's body
//      removes it;
//   7. publication: the KeyDescriptor and the JWK carry the public half only.
//
// WHY A CHILD PROCESS PER MODE: it loads the whole protocol stack and puts a
// realm of its own in product mode for the second run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({
  name: 'federation_encryption', level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.FEN_ROOT;
  const OUT = process.env.FEN_OUT;
  const MODE = process.env.FEN_MODE;
  const fs = require('fs');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: '[' + MODE + '] ' + what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const mode = require(ROOT + '/common/mode');
    const errorCodes = require(ROOT + '/common/error_codes');
    const stsCrypto = require(ROOT + '/common/crypto');
    const keystore = require(ROOT + '/common/keystore');
    const x509 = require(ROOT + '/common/vendored/x509');
    const audit = require(ROOT + '/common/audit');
    require(ROOT + '/ldap/ldap_server');
    const actions = require(ROOT + '/admin-core/admin_actions');
    const federation = require(ROOT + '/federation/federation');
    const fedEncryption = require(ROOT + '/federation/federation_encryption');

    const SP = 'fen' + (MODE === 'product' ? 'p' : 'd');
    // A PRODUCT REALM SEALS WHAT IT STORES, and an in-process stack has no
    // key-encryption key: an ephemeral one is offered while the process is
    // still in development, which is the only time the keystore takes one.
    if (MODE === 'product') {
      keystore.useEphemeralKek(nodeCrypto.randomBytes(32).toString('hex'));
    }
    realms.create({ id: SP });
    function inSp(fn) {
      return realms.run(realms.get(SP), fn);
    }
    inSp(function () {
      if (MODE === 'product') {
        config.setOverride('global.mode', 'product');
      }
    });
    const act = function (body) {
      return inSp(function () {
        return actions.federationAction(body);
      });
    };
    const get = function (id) {
      return inSp(function () {
        return federation.get(id);
      });
    };
    const codeOf = function (result) {
      return errorCodes.codeOf(result) || '';
    };

    // =====================================================================
    // 0. THE MODE PREDICATE, AND WHEN PLAINTEXT IS REFUSED
    // =====================================================================
    note(inSp(function () {
      return mode.acceptsUnencryptedFederatedAssertions();
    }) === (MODE !== 'product'),
         '0a. mode.acceptsUnencryptedFederatedAssertions() is ' +
         (MODE !== 'product') + ' in ' + MODE + ' mode');

    // =====================================================================
    // 2. A RELATIONSHIP'S KEY, issued at create
    // =====================================================================
    const made = {};
    for (const [id, protocol] of [['fen-saml', 'saml2'], ['fen-oidc', 'oidc'],
                                  ['fen-wsfed', 'wsfed'],
                                  ['fen-saml11', 'saml11']]) {
      made[id] = await act({ action: 'create', id: id,
                             role: 'service-provider', protocol: protocol,
                             peer: 'urn:test:fen:' + id });
    }
    const saml = get('fen-saml');
    const oidc = get('fen-oidc');
    const samlKey = federation.currentEncryptionKeyOf(saml);
    const oidcKey = federation.currentEncryptionKeyOf(oidc);
    note(made['fen-saml'].ok && samlKey && samlKey.keyType === 'rsa-3072' &&
         oidcKey && oidcKey.keyType === 'ec-p256' &&
         federation.currentEncryptionKeyOf(get('fen-wsfed')) &&
         !federation.currentEncryptionKeyOf(get('fen-saml11')),
         '2a. SAML 2.0 and WS-Federation get an RSA 3072 key at create, ' +
         'OpenID Connect a P-256 one, SAML 1.1 none',
         JSON.stringify([made['fen-saml'].errors, samlKey && samlKey.keyType,
                         oidcKey && oidcKey.keyType]));
    note(saml.fedKeyManagementAlgorithm === 'rsa-oaep' &&
         saml.fedContentEncryptionAlgorithm === 'aes256-gcm' &&
         oidc.fedKeyManagementAlgorithm === 'ECDH-ES' &&
         oidc.fedContentEncryptionAlgorithm === 'A256GCM' &&
         saml.fedAllowUnencrypted === 'FALSE',
         '2b. the defaults are written onto the entry: rsa-oaep / ' +
         'aes256-gcm, ECDH-ES / A256GCM, fedAllowUnencrypted FALSE',
         JSON.stringify([saml.fedKeyManagementAlgorithm,
                         oidc.fedKeyManagementAlgorithm]));
    const pemOf = function (b64) {
      return '-----BEGIN CERTIFICATE-----\n' +
        String(b64).match(/.{1,64}/g).join('\n') +
        '\n-----END CERTIFICATE-----\n';
    };
    const samlUsage = JSON.stringify(
      (await x509.describeCertificate(pemOf(samlKey.certificate)))
        .extensions || []);
    const oidcUsage = JSON.stringify(
      (await x509.describeCertificate(pemOf(oidcKey.certificate)))
        .extensions || []);
    note(/keyEncipherment/.test(samlUsage) &&
         !/digitalSignature/.test(samlUsage) &&
         /keyAgreement/.test(oidcUsage) && !/digitalSignature/.test(oidcUsage)
         && samlKey.chain.length >= 2,
         '2c. the certificate is under the realm\'s Intermediate, ' +
         'keyEncipherment for RSA and keyAgreement for EC, never ' +
         'digitalSignature', samlUsage.slice(0, 300));
    note(samlKey.sealed === (MODE === 'product') &&
         (MODE === 'product'
           ? /^\$aesgcm\$/.test(samlKey.privateKey)
           : /BEGIN PRIVATE KEY/.test(samlKey.privateKey)),
         '2d. the private key is ' + (MODE === 'product'
           ? 'SEALED under the key-encryption key'
           : 'held as a PEM (keys do not persist in development)'));
    const view = inSp(function () {
      return fedEncryption.viewOf(saml);
    });
    note(JSON.stringify(view).indexOf('PRIVATE KEY') < 0 &&
         JSON.stringify(federation.encryptionKeyView(saml))
           .indexOf('privateKey') < 0 &&
         view.current === samlKey.kid &&
         /BEGIN CERTIFICATE/.test(view.certificatePem),
         '2e. the view carries the certificate and the kid and never a ' +
         'private key');

    // =====================================================================
    // 0 again: required, and readiness
    // =====================================================================
    const required = function (record) {
      return inSp(function () {
        return federation.encryptionRequired(record);
      });
    };
    note(required(saml) === (MODE === 'product') &&
         required(get('fen-wsfed')) === (MODE === 'product') &&
         required(oidc) === false && required(get('fen-saml11')) === false,
         '0b. plaintext is refused for SAML 2.0 and WS-Federation in ' +
         'product only, and never for an OpenID Connect code flow or SAML ' +
         '1.1');
    await act({ action: 'set', id: 'fen-oidc', field: 'fedResponseType',
                value: 'id_token' });
    note(required(get('fen-oidc')) === (MODE === 'product'),
         '0c. an id_token by form_post crosses the browser and is refused ' +
         'in clear in product');
    await act({ action: 'set', id: 'fen-saml', field: 'fedAllowUnencrypted',
                value: 'on' });
    note(get('fen-saml').fedAllowUnencrypted === 'TRUE' &&
         required(get('fen-saml')) === false,
         '0d. fedAllowUnencrypted accepts plaintext, and is stored TRUE');
    await act({ action: 'set', id: 'fen-saml', field: 'fedAllowUnencrypted',
                value: 'FALSE' });
    const bare = inSp(function () {
      federation.create({ fedId: 'fen-bare', fedRole: 'service-provider',
                          fedProtocol: 'saml2' });
      return federation.readinessOf(federation.get('fen-bare'));
    });
    const needsKey = bare.missing.some(function (one) {
      return /fedEncryptionKey/.test(one);
    });
    note(needsKey === (MODE === 'product'),
         '0e. a relationship with no key is ' + (MODE === 'product'
           ? 'NOT READY in product, and says which field'
           : 'ready in development, which accepts plaintext'),
         JSON.stringify(bare.missing));

    // =====================================================================
    // 3. THE FOUR FIELDS
    // =====================================================================
    const refusals = [
      ['fen-saml', 'fedContentEncryptionAlgorithm', 'aes256-cbc',
       'STS-FED-0139'],
      ['fen-saml', 'fedKeyManagementAlgorithm', 'rsa-1_5', 'STS-FED-0139'],
      ['fen-oidc', 'fedKeyManagementAlgorithm', 'RSA1_5', 'STS-FED-0139'],
      ['fen-oidc', 'fedContentEncryptionAlgorithm', 'A128CBC-HS256',
       'STS-FED-0139'],
      ['fen-saml', 'fedKeyManagementAlgorithm', 'ecdh-es', 'STS-FED-0143'],
      ['fen-saml', 'fedKeyManagementAlgorithm', 'RSA-OAEP-256',
       'STS-FED-0143'],
      ['fen-saml11', 'fedEncryptionKeyType', 'rsa-3072', 'STS-FED-0143'],
      ['fen-saml', 'fedEncryptionKey', '{}', 'STS-FED-0067']
    ];
    // A REFUSED CHANGE TO THE REGISTER carries its code on the audit row and
    // not on the result, which /admin-api serialises whole.
    const coded = function (code) {
      return inSp(function () {
        return audit.list();
      }).filter(function (row) {
        return row.errorCode === code;
      }).length;
    };
    for (const one of refusals) {
      const before = coded(one[3]);
      const r = await act({ action: 'set', id: one[0], field: one[1],
                            value: one[2] });
      note(!r.ok && coded(one[3]) === before + 1,
           '3a. ' + one[1] + '=' + one[2] + ' on ' + one[0] + ' is refused ' +
           '(' + one[3] + ')', codeOf(r) + ' ' + JSON.stringify(r.errors));
    }
    const typed = await act({ action: 'set', id: 'fen-wsfed',
                              field: 'fedEncryptionKeyType',
                              value: 'ec-p256' });
    const wsfed = get('fen-wsfed');
    const wsfedKey = federation.currentEncryptionKeyOf(wsfed);
    note(typed.ok && wsfedKey && wsfedKey.keyType === 'ec-p256' &&
         wsfed.fedKeyManagementAlgorithm === 'ecdh-es' &&
         federation.encryptionKeysOf(wsfed).length === 2,
         '3b. a new key type issues a key of that type at once, takes its ' +
         'default key management, and keeps the old key in its grace',
         JSON.stringify([typed.errors, wsfedKey && wsfedKey.keyType,
                         wsfed.fedKeyManagementAlgorithm]));

    // =====================================================================
    // 1 and 4. XML ENCRYPTION, and decryptXml()'s policy
    // =====================================================================
    const plain = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
      'assertion" ID="_fen" Version="2.0"><saml:Issuer>urn:test</saml:Issuer>' +
      '</saml:Assertion>';
    const decryptXml = function (id, xml) {
      return inSp(function () {
        return fedEncryption.decryptXml(federation.get(id), xml);
      });
    };
    const samlCert = pemOf(samlKey.certificate);
    const good = decryptXml('fen-saml', stsCrypto.encryptElement(plain,
      samlCert, { algorithm: 'aes256-gcm', keyTransport: 'rsa-oaep' }));
    note(good.ok && good.xml === plain && /rsa-oaep/.test(good.algorithm),
         '1a/4a. XML Encryption 1.1 rsa-oaep (SHA-256, MGF1-SHA-256) with ' +
         'aes256-gcm round-trips and is what the relationship accepts',
         good.why);
    const ecGood = decryptXml('fen-wsfed', stsCrypto.encryptElement(plain,
      pemOf(wsfedKey.certificate), { algorithm: 'aes256-gcm' }));
    note(ecGood.ok && ecGood.xml === plain && /ecdh-es/.test(ecGood.algorithm),
         '1b/4b. to an EC key it is ECDH-ES (ConcatKDF, kw-aes256), and it ' +
         'round-trips', ecGood.why);
    const allow = stsCrypto.decryptElement(stsCrypto.encryptElement(plain,
      samlCert, { keyTransport: 'rsa-oaep' }), '', {
      allowedKeyManagement: ['ecdh-es'] });
    note(!allow.ok && allow.refused &&
         errorCodes.codeOf(allow) === 'STS-KEYS-0071',
         '1c. a caller\'s allow-list refuses before any key operation ' +
         '(no key was given at all; STS-KEYS-0071)', allow.why);
    const wrongAlg = [
      ['aes128-gcm', 'rsa-oaep'], ['aes256-cbc', 'rsa-oaep'],
      ['aes256-gcm', 'rsa-oaep-mgf1p'], ['aes256-gcm', 'rsa-1_5']];
    for (const one of wrongAlg) {
      const r = decryptXml('fen-saml', stsCrypto.encryptElement(plain,
        samlCert, { algorithm: one[0], keyTransport: one[1] }));
      note(!r.ok && r.code === 'STS-FED-0139',
           '4c. ' + one[0] + ' under ' + one[1] + ' is refused (0139)',
           r.code + ' ' + r.why);
    }
    const other = await inSp(async function () {
      return require(ROOT + '/common/pki').issueEncryptionKeyPair(undefined,
        { identifier: 'fen-other', keyAlg: 'rsa-3072' });
    });
    const wrongKey = decryptXml('fen-saml', stsCrypto.encryptElement(plain,
      other.issued.certificatePem, { keyTransport: 'rsa-oaep' }));
    const sealedXml = stsCrypto.encryptElement(plain, samlCert,
                                               { keyTransport: 'rsa-oaep' });
    const tampered = decryptXml('fen-saml', sealedXml.replace(
      /(<xenc:CipherData><xenc:CipherValue>)([A-Za-z0-9+/])([^<]*<\/xenc:CipherValue><\/xenc:CipherData><\/xenc:EncryptedData>)/,
      function (all, a, b, c) {
        return a + (b === 'A' ? 'B' : 'A') + c;
      }));
    note(!wrongKey.ok && wrongKey.code === 'STS-FED-0138' &&
         !tampered.ok && tampered.code === 'STS-FED-0138' &&
         wrongKey.why === tampered.why,
         '4d. a wrong key and an altered ciphertext are the SAME code and ' +
         'the same sentence (0138): no oracle',
         JSON.stringify([wrongKey.code, tampered.code, wrongKey.detail,
                         tampered.detail]));

    // =====================================================================
    // 5. decryptJwe()
    // =====================================================================
    const oidcNow = get('fen-oidc');
    const jwk = inSp(function () {
      return fedEncryption.publicJwkOf(oidcNow);
    });
    const jws = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln';
    const decryptJwe = function (compact) {
      return inSp(function () {
        return fedEncryption.decryptJwe(federation.get('fen-oidc'), compact);
      });
    };
    const jweGood = decryptJwe(stsCrypto.encryptJweCompact(jws,
      { jwk: jwk, alg: 'ECDH-ES', enc: 'A256GCM', cty: 'JWT' }));
    note(jweGood.ok && jweGood.plaintext === jws,
         '5a. an ECDH-ES / A256GCM ID Token decrypts to the signed token ' +
         'inside', jweGood.why);
    const jweCases = [
      ['A128CBC-HS256', 'ECDH-ES', 'STS-FED-0139'],
      ['A128GCM', 'ECDH-ES', 'STS-FED-0139'],
      ['A256GCM', 'ECDH-ES+A256KW', 'STS-FED-0139']];
    for (const one of jweCases) {
      const r = decryptJwe(stsCrypto.encryptJweCompact(jws,
        { jwk: jwk, alg: one[1], enc: one[0] }));
      note(!r.ok && r.code === one[2], '5b. alg ' + one[1] + ' enc ' +
           one[0] + ' is refused (' + one[2] + ')', r.code + ' ' + r.why);
    }
    const stranger = nodeCrypto.generateKeyPairSync('ec',
      { namedCurve: 'prime256v1' });
    const strangerJwk = Object.assign(stranger.publicKey.export(
      { format: 'jwk' }), { kid: jwk.kid });
    const jweWrong = decryptJwe(stsCrypto.encryptJweCompact(jws,
      { jwk: strangerJwk, alg: 'ECDH-ES', enc: 'A256GCM' }));
    const jweUnknown = decryptJwe(stsCrypto.encryptJweCompact(jws,
      { jwk: Object.assign({}, jwk, { kid: 'nobody' }), alg: 'ECDH-ES',
        enc: 'A256GCM' }));
    note(!jweWrong.ok && jweWrong.code === 'STS-FED-0138' &&
         jweWrong.why === wrongKey.why &&
         !jweUnknown.ok && jweUnknown.code === 'STS-FED-0137',
         '5c. a JWE to another key under our kid is 0138, with the one ' +
         'sentence; a kid naming no key held is 0137',
         JSON.stringify([jweWrong.code, jweUnknown.code]));

    // =====================================================================
    // 6. ROTATION AND THE GRACE PERIOD
    // =====================================================================
    const oldCert = samlCert;
    const rotated = await act({ action: 'rotate-key', id: 'fen-saml' });
    const afterRotate = get('fen-saml');
    const rows = federation.encryptionKeysOf(afterRotate);
    const previous = rows.filter(function (row) {
      return row.state === 'previous';
    })[0];
    const toOld = stsCrypto.encryptElement(plain, oldCert,
                                           { keyTransport: 'rsa-oaep' });
    const inGrace = decryptXml('fen-saml', toOld);
    note(rotated.ok && rotated.kid !== samlKey.kid && previous &&
         previous.kid === samlKey.kid && inGrace.ok &&
         inGrace.kid === samlKey.kid,
         '6a. a rotation makes a new key current and the old one still ' +
         'decrypts in its grace', JSON.stringify([rotated.errors,
                                                  inGrace.why]));
    const later = previous ? Number(previous.retiresAt) + 1000 : 0;
    const pastGrace = inSp(function () {
      return fedEncryption.decryptXml(federation.get('fen-saml'), toOld,
                                      later);
    });
    note(!pastGrace.ok && pastGrace.code === 'STS-FED-0138',
         '6b. past its retiresAt the old key decrypts nothing, before any ' +
         'job has run (checked at the read)', pastGrace.code);
    const retired = inSp(function () {
      return fedEncryption.retireDue(later);
    });
    note(retired.retired >= 1 &&
         federation.encryptionKeysOf(get('fen-saml')).length === 1,
         '6c. the retirement job\'s body removes it from the entry',
         JSON.stringify(retired));
    inSp(function () {
      config.setOverride('federation.encryptionKeyGraceS', '0');
    });
    await act({ action: 'rotate-key', id: 'fen-saml' });
    note(federation.encryptionKeysOf(get('fen-saml')).length === 1,
         '6d. a zero grace drops the replaced key at the rotation');
    inSp(function () {
      config.clearOverride('federation.encryptionKeyGraceS');
    });
    const refusedRotate = await act({ action: 'rotate-key',
                                      id: 'fen-saml11' });
    note(!refusedRotate.ok && codeOf(refusedRotate) === 'STS-FED-0144',
         '6e. SAML 1.1 has no key to rotate (0144)', codeOf(refusedRotate));

    // =====================================================================
    // 7. PUBLICATION
    // =====================================================================
    const descriptor = inSp(function () {
      return fedEncryption.keyDescriptorOf(get('fen-saml'));
    });
    note(/<md:KeyDescriptor use="encryption">/.test(descriptor) &&
         /xmlenc11#rsa-oaep/.test(descriptor) &&
         /mgf1sha256/.test(descriptor) && /aes256-gcm/.test(descriptor) &&
         descriptor.indexOf(federation.currentEncryptionKeyOf(
           get('fen-saml')).certificate) > 0,
         '7a. the KeyDescriptor names the current certificate and exactly ' +
         'the algorithms accepted');
    note(jwk && jwk.use === 'enc' && jwk.alg === 'ECDH-ES' && !jwk.d &&
         jwk.kty === 'EC' && Array.isArray(jwk.x5c),
         '7b. the JWK is use enc, alg ECDH-ES, public only, with its x5c',
         JSON.stringify(jwk));

    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: '[' + MODE + '] the child ran to the ' +
                                     'end', detail: e && e.stack });
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function runMode(t, modeName) {
  log.debug("Entering runMode(). " + modeName);
  const out = path.join(os.tmpdir(), 'federation-encryption-' + process.pid +
                        '-' + modeName + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', FEN_ROOT: ROOT,
                                  FEN_OUT: out, FEN_MODE: modeName }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in runMode(): " + ((e && e.message) || e));
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in runMode(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings), '[' + modeName + '] the child ' +
              'process reported',
              'exit ' + result.status + ' ' +
              String(result.stderr || '').slice(-800))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving runMode().");
}

function run(t) {
  log.debug("Entering run().");
  runMode(t, 'development');
  runMode(t, 'product');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'federation_encryption',
  describe: 'a partner\'s encrypted assertion or ID Token (#168), in ' +
            'development and product: the mode predicate; XML Encryption ' +
            '1.1 rsa-oaep and ECDH-ES in common/crypto.js; a relationship\'s ' +
            'key issued under the Intermediate and sealed; the four fields ' +
            'and their refusals; decryptXml() and decryptJwe() under the ' +
            'relationship\'s policy with one code for every failure; ' +
            'rotation with its grace period and the retirement job; and ' +
            'the KeyDescriptor and JWK',
  run: run
};
