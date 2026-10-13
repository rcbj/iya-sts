// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: pinned_signers.js
//
// ===========================================================================
// A PINNED KEY PAIR AS A REAL SIGNER (2026-09-27, #263).
//
// rcbj's decision: a key an operator pins into a `jose` or `xml` slot on
// /admin/pki signs for the realm, OFF by default (`pki.pinnedSigners`). What
// this file holds the service to:
//
//   A. OFF. A realm that has not turned the setting on signs exactly as
//      before, and a pin into a slot it signs from is still refused with
//      STS-PKI-0206 (#245) — which no test held until now.
//   B. VALIDATION. The key must be the slot's (STS-PKI-0207): an EC key on
//      another curve, an RSA key under 2048 bits and an ML-DSA key of another
//      parameter set are refused; a composite slot is not pinnable
//      (STS-PKI-0208); an operator's chain must link (STS-PKI-0209) and their
//      certificate be valid now (STS-PKI-0210).
//   C. PUBLISHED AHEAD OF USE. A pin in its lead is in the JWKS and signs
//      nothing; unpinned before it signed, it is gone at once.
//   D. JOSE. Pinned RS256 (through the console action): tokens carry its
//      kid, verify against its JWKS entry (whose x5c holds the key), verify
//      through verifyOwnJws(), and `keys.kidFormat` applies to it; the pin is
//      audited and announced with signing-key-rotated.
//   E. POST-QUANTUM. Pinned ML-DSA-65 signs ML-DSA-65 tokens that verify
//      against its AKP JWK.
//   F. XML. Pinned RS256 with the operator's certificate and chain: a SAML
//      assertion is signed by it, the metadata publishes its certificate, and
//      the operator's chain is not re-certified by a renewal.
//   G. ROTATION. `signing.rotate` gives the pinned unit no next key; other
//      units get one.
//   H. UNPIN. The generated key signs again, the pinned key goes on verifying
//      through its grace, the unpin is announced, and `signing.retire` drops
//      it once the grace has passed; an unpin of nothing is STS-PKI-0211.
//   I. EXPIRY. `signing.retire` warns (STS-PKI-0212) as a pinned certificate
//      nears its end, and the console model marks it.
//   X. DECRYPTION. The xml pin is also the key partners encrypt to: an
//      operator certificate without keyEncipherment is STS-PKI-0217; the SAML
//      metadata's use="encryption" KeyDescriptor carries it; what is
//      encrypted to it decrypts; what was encrypted to the generated key
//      decrypts through the grace and not after; unpinned, the metadata goes
//      back and the pinned key decrypts through its own grace, then not.
//   J. CUSTODY. The private key is in the realm's PKI row (the one sealed
//      under the key-encryption key) and in no public view.
//
// In a child process on an ephemeral loopback port, with the whole stack.
// Every key is generated here, at test time.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'pinned_signers',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function childMain() {
  const ROOT = process.env.PS_ROOT;
  const OUT = process.env.PS_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const get = function (port, urlPath) {
    return new Promise(function (resolve) {
      // A fresh connection each time (`agent: false`): node 24's default
      // agent keeps sockets alive, and one the server closed after its
      // keep-alive timeout answers the next request with ECONNRESET.
      http.get({ host: '127.0.0.1', port: port, path: urlPath,
                 agent: false },
               function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = null;
          try {
            json = JSON.parse(text);
          } catch (e) {
            json = null;
          }
          resolve({ status: res.statusCode, text: text, json: json });
        });
      }).on('error', function (e) {
        resolve({ status: 0, text: String(e && e.message), json: null });
      });
    });
  };
  const sleep = function (ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  };
  const pem = function (key) {
    return key.export({ type: 'pkcs8', format: 'pem' });
  };
  const headerOf = function (token) {
    return JSON.parse(Buffer.from(String(token).split('.')[0], 'base64url')
      .toString('utf8'));
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const helpers = require(ROOT + '/common/helpers');
    const realms = require(ROOT + '/common/realms');
    const pki = require(ROOT + '/common/pki');
    const keystore = require(ROOT + '/common/keystore');
    const stsCrypto = require(ROOT + '/common/crypto');
    const pqJose = require(ROOT + '/common/pq_jose');
    const pqcX509 = require(ROOT + '/common/vendored/pqc_x509');
    const x509 = require(ROOT + '/common/vendored/x509');
    const rotation = require(ROOT + '/common/signing_rotation');
    const pkiAdmin = require(ROOT + '/admin-ui/pki_admin');
    const audit = require(ROOT + '/common/audit');
    const ssf = require(ROOT + '/ssf/ssf');
    const saml2 = require(ROOT + '/saml/saml2');

    // THE ANNOUNCEMENTS, captured where signing_rotation.ts sends them.
    const announced = [];
    ssf.signingKeyRotated = function (notice) {
      announced.push(notice);
      return Promise.resolve({ sent: 0, streams: 0 });
    };

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    await pki.start();

    const ON = 'pinned-on';
    const OFF = 'pinned-off';
    realms.create({ id: ON, name: 'Pinned signers on',
                    overrides: { 'pki.pinnedSigners': true,
                                 'pki.pinnedSignerLeadMinutes': 0 } });
    realms.create({ id: OFF, name: 'Pinned signers off' });
    const inRealm = function (id, fn) {
      return realms.run(realms.get(id), fn);
    };
    for (const id of [ON, OFF]) {
      const built = await pki.buildScope(id, {});
      note(built.ok, 'the ' + id + ' branch is built',
           (built.errors || []).join(' '));
      // Make the key set, and wait for its certification (certifyLater).
      inRealm(id, function () {
        return helpers.STS.kid;
      });
      for (let i = 0; i < 100; i++) {
        const plain = pki.certificateFor(id, 'jose', 'RS256');
        const curve = pki.certificateFor(id, 'jose', 'ES256:P-256');
        if (plain && plain.kid && curve && curve.kid) {
          break;
        }
        await sleep(100);
      }
    }
    const jwksOf = async function (id) {
      const r = await get(port, '/realm/' + id + '/oauth2/jwks');
      return (r.json && r.json.keys) || [];
    };
    const kidsOf = function (keys) {
      return keys.map(function (k) { return k.kid; });
    };

    // --- A. off ---------------------------------------------------------------
    const offKid = inRealm(OFF, function () { return helpers.STS.kid; });
    const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const offPin = await pki.pinKeyPair(OFF, 'jose', 'RS256',
                                        { privateKeyPem: pem(rsa.privateKey) });
    note(!offPin.ok && offPin.errors &&
         require(ROOT + '/common/error_codes').codeOf(offPin) ===
           'STS-PKI-0206',
         'A1. setting off: a pin into the slot the realm signs from is ' +
         'refused with STS-PKI-0206', JSON.stringify(offPin));
    const offToken = inRealm(OFF, function () {
      return helpers.signJwt({ sub: 'off', iss: 'https://off.test' });
    });
    note(headerOf(offToken).kid === offKid &&
         pki.pinnedSignersFor(OFF).length === 0,
         'A2. and the realm signs with its generated key, pinning nothing',
         headerOf(offToken).kid + ' / ' + offKid);

    // --- B. validation ----------------------------------------------------------
    const codeOf = require(ROOT + '/common/error_codes').codeOf;
    const p384 = nodeCrypto.generateKeyPairSync('ec',
      { namedCurve: 'secp384r1' });
    const wrongCurve = await pki.pinKeyPair(ON, 'jose', 'ES256:P-256',
      { privateKeyPem: pem(p384.privateKey) });
    note(!wrongCurve.ok && codeOf(wrongCurve) === 'STS-PKI-0207',
         'B1. a P-384 key in the ES256:P-256 slot is STS-PKI-0207',
         JSON.stringify(wrongCurve));
    const small = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 1024 });
    const tooSmall = await pki.pinKeyPair(ON, 'jose', 'RS256',
      { privateKeyPem: pem(small.privateKey) });
    note(!tooSmall.ok && codeOf(tooSmall) === 'STS-PKI-0207',
         'B2. a 1024-bit RSA key in RS256 is STS-PKI-0207',
         JSON.stringify(tooSmall));
    const ec256 = nodeCrypto.generateKeyPairSync('ec',
      { namedCurve: 'prime256v1' });
    const ecInRsa = await pki.pinKeyPair(ON, 'xml', 'RS256',
      { privateKeyPem: pem(ec256.privateKey) });
    note(!ecInRsa.ok && codeOf(ecInRsa) === 'STS-PKI-0207',
         'B3. an EC key in the xml RS256 slot is STS-PKI-0207',
         JSON.stringify(ecInRsa));
    const ml44 = await pqcX509.generateKeyPair('ML-DSA-44');
    const wrongSet = await pki.pinKeyPair(ON, 'jose', 'ML-DSA-65',
      { privateKeyPem: pqcX509.privatePem('ML-DSA-44', ml44.priv) });
    note(!wrongSet.ok && codeOf(wrongSet) === 'STS-PKI-0207',
         'B4. an ML-DSA-44 key in the ML-DSA-65 slot is STS-PKI-0207',
         JSON.stringify(wrongSet));
    const composite = await pki.pinKeyPair(ON, 'jose', 'ML-DSA-65-ES256',
      { privateKeyPem: pem(ec256.privateKey) });
    note(!composite.ok && codeOf(composite) === 'STS-PKI-0208',
         'B5. a composite slot is not pinnable: STS-PKI-0208',
         JSON.stringify(composite));

    // An operator's own CA, and certificates from it.
    const caKey = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 2048 });
    const spkiPem = function (key) {
      return nodeCrypto.createPublicKey(key)
        .export({ type: 'spki', format: 'pem' });
    };
    const operatorCaPem = await x509.issueCertificate({
      subject: [{ name: 'CN', value: 'Operator Test CA' }],
      subjectPublicKey: spkiPem(caKey.privateKey),
      issuerPrivateKey: pem(caKey.privateKey),
      signatureAlg: 'sha256-rsa',
      notBefore: new Date(Date.now() - 3600000).toISOString(),
      notAfter: new Date(Date.now() + 5 * 365 * 86400000).toISOString(),
      extensions: {
        basicConstraints: { present: true, critical: true, ca: true },
        keyUsage: { present: true, critical: true,
                    usages: ['keyCertSign', 'cRLSign'] },
        subjectKeyIdentifier: { present: true }
      }
    }).then(function (made) { return made.pem; });
    const leafFrom = async function (subjectKey, notBefore, notAfter,
                                     usages) {
      const made = await x509.issueCertificate({
        subject: [{ name: 'CN', value: 'Operator XML signer' }],
        subjectPublicKey: spkiPem(subjectKey),
        issuer: { certificatePem: operatorCaPem,
                  privateKeyPem: pem(caKey.privateKey), keyAlg: 'rsa-2048' },
        signatureAlg: 'sha256-rsa',
        notBefore: notBefore.toISOString(),
        notAfter: notAfter.toISOString(),
        extensions: {
          basicConstraints: { present: true, critical: true, ca: false },
          keyUsage: { present: true, critical: true,
                      usages: usages || ['digitalSignature',
                                         'keyEncipherment'] },
          subjectKeyIdentifier: { present: true },
          authorityKeyIdentifier: { present: true }
        }
      });
      return made.pem;
    };
    const xmlKey = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 2048 });
    const xmlLeaf = await leafFrom(xmlKey.privateKey,
                                   new Date(Date.now() - 3600000),
                                   new Date(Date.now() + 365 * 86400000));
    const stranger = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 2048 });
    const strangerCa = await x509.issueCertificate({
      subject: [{ name: 'CN', value: 'Somebody else' }],
      subjectPublicKey: spkiPem(stranger.privateKey),
      issuerPrivateKey: pem(stranger.privateKey),
      signatureAlg: 'sha256-rsa',
      extensions: {
        basicConstraints: { present: true, critical: true, ca: true },
        keyUsage: { present: true, critical: true,
                    usages: ['keyCertSign'] }
      }
    }).then(function (made) { return made.pem; });
    const badChain = await pki.pinKeyPair(ON, 'xml', 'RS256',
      { privateKeyPem: pem(xmlKey.privateKey), certificatePem: xmlLeaf,
        chainPem: strangerCa });
    note(!badChain.ok && codeOf(badChain) === 'STS-PKI-0209',
         'B6. a chain whose first certificate did not issue the leaf is ' +
         'STS-PKI-0209', JSON.stringify(badChain));
    const expiredLeaf = await leafFrom(xmlKey.privateKey,
                                       new Date(Date.now() - 10 * 86400000),
                                       new Date(Date.now() - 86400000));
    const expired = await pki.pinKeyPair(ON, 'xml', 'RS256',
      { privateKeyPem: pem(xmlKey.privateKey), certificatePem: expiredLeaf,
        chainPem: operatorCaPem });
    note(!expired.ok && codeOf(expired) === 'STS-PKI-0210',
         'B7. an expired certificate is STS-PKI-0210',
         JSON.stringify(expired));
    const signOnlyLeaf = await leafFrom(xmlKey.privateKey,
                                        new Date(Date.now() - 3600000),
                                        new Date(Date.now() + 86400000),
                                        ['digitalSignature']);
    const signOnly = await pki.pinKeyPair(ON, 'xml', 'RS256',
      { privateKeyPem: pem(xmlKey.privateKey), certificatePem: signOnlyLeaf,
        chainPem: operatorCaPem });
    note(!signOnly.ok && codeOf(signOnly) === 'STS-PKI-0217',
         'B8. an xml certificate whose keyUsage lacks keyEncipherment is ' +
         'STS-PKI-0217: an xml pin is also the key partners encrypt to',
         JSON.stringify(signOnly));

    // --- C. published ahead of use -------------------------------------------
    const es384 = nodeCrypto.generateKeyPairSync('ec',
      { namedCurve: 'secp384r1' });
    const generated384 = inRealm(ON, function () {
      return helpers.signingKeyFor('ES384').kid;
    });
    const pending = await pki.pinKeyPair(ON, 'jose', 'ES384:P-384',
      { privateKeyPem: pem(es384.privateKey) }, { leadMs: 3600000 });
    note(pending.ok && pending.signer &&
         /^sts-pinned-/.test(pending.signer.kid),
         'C1. a pin with a lead is accepted, with a kid derived from its key',
         JSON.stringify(pending.signer || pending.errors));
    const pendingKid = pending.signer && pending.signer.kid;
    note(kidsOf(await jwksOf(ON)).indexOf(pendingKid) >= 0,
         'C2. it is in the JWKS at once, ahead of its use');
    note(inRealm(ON, function () {
           return helpers.signingKeyFor('ES384').kid;
         }) === generated384,
         'C3. and signs nothing during its lead: ES384 is still the ' +
         'generated key');
    const dropPending = pki.unpinKeyPair(ON, 'jose', 'ES384:P-384',
                                         { graceMs: 86400000 });
    note(dropPending.ok && !dropPending.signed &&
         kidsOf(await jwksOf(ON)).indexOf(pendingKid) < 0,
         'C4. unpinned before it signed, it is gone at once',
         JSON.stringify(dropPending));

    // --- D. jose RS256, through the console action ----------------------------
    const generatedKid = inRealm(ON, function () {
      return helpers.STS.kid;
    });
    const joseKey = nodeCrypto.generateKeyPairSync('rsa',
      { modulusLength: 2048 });
    const before = announced.length;
    const pinned = await inRealm(ON, function () {
      return pkiAdmin.pkiAction({ action: 'pin-key', scope: ON,
                                  useCase: 'jose', slot: 'RS256',
                                  privateKeyPem: pem(joseKey.privateKey) });
    });
    const joseKid = pinned.kid;
    note(pinned.ok && /^sts-pinned-/.test(String(joseKid)),
         'D1. the console pins an RS256 key as the realm\'s signer',
         JSON.stringify(pinned));
    const idToken = inRealm(ON, function () {
      return helpers.signJwt({ sub: 'alice', iss: 'https://on.test',
                               aud: 'rp', exp: Math.floor(Date.now() / 1000) +
                               600 }, null, { certificateHeader: 'id-token' });
    });
    note(headerOf(idToken).kid === joseKid,
         'D2. a token signed now carries the pinned key\'s kid',
         headerOf(idToken).kid);
    const jwks = await jwksOf(ON);
    const entry = jwks.filter(function (k) { return k.kid === joseKid; })[0];
    let verified = false;
    try {
      verified = !!stsCrypto.verifyJws(idToken,
        nodeCrypto.createPublicKey({ key: { kty: entry.kty, n: entry.n,
                                            e: entry.e }, format: 'jwk' }),
        { algorithms: ['RS256'] });
    } catch (e) {
      verified = false;
    }
    note(entry && verified,
         'D3. and verifies against the JWKS entry of the pinned key');
    let x5cHolds = false;
    try {
      const first = new nodeCrypto.X509Certificate(
        Buffer.from(entry.x5c[0], 'base64'));
      x5cHolds = first.publicKey.export({ type: 'spki', format: 'der' })
        .equals(nodeCrypto.createPublicKey(joseKey.privateKey)
          .export({ type: 'spki', format: 'der' })) && entry.x5c.length >= 2;
    } catch (e) {
      x5cHolds = false;
    }
    note(x5cHolds, 'D4. its x5c holds the pinned key, with its chain');
    note(kidsOf(jwks).indexOf(generatedKid) >= 0,
         'D5. and the generated key stays published beside it');
    let ownOk = false;
    try {
      ownOk = !!inRealm(ON, function () {
        return helpers.verifyOwnJws(idToken);
      });
    } catch (e) {
      ownOk = false;
    }
    note(ownOk, 'D6. verifyOwnJws() accepts what the pinned key signed');
    const rotatedNotice = announced.slice(before).filter(function (n) {
      return n.realm === ON && (n.rotated || []).some(function (r) {
        return r.unit === 'jose:RS256' && r.to === joseKid &&
               r.from === generatedKid;
      });
    })[0];
    note(rotatedNotice && rotatedNotice.reason === 'requested',
         'D7. the pin is announced with signing-key-rotated (' +
         'generated -> pinned, requested)', JSON.stringify(announced));
    note(inRealm(ON, function () {
           return audit.list();
         }).some(function (row) {
           return row.action === 'keys.pin';
         }), 'D8. and audited as keys.pin');
    {
      const config = require(ROOT + '/common/config');
      inRealm(ON, function () {
        config.setOverride('keys.kidFormat', 'jwk-thumbprint-uri');
      });
      const uriToken = inRealm(ON, function () {
        return helpers.signJwt({ sub: 'bob', iss: 'https://on.test' });
      });
      const uriKid = headerOf(uriToken).kid;
      const uriJwks = await jwksOf(ON);
      note(/^urn:ietf:params:oauth:jwk-thumbprint:sha-256:/.test(uriKid) &&
           kidsOf(uriJwks).indexOf(uriKid) >= 0,
           'D9. keys.kidFormat applies: the pinned key is named by its RFC ' +
           '9278 thumbprint URI, and the JWKS carries that name', uriKid);
      inRealm(ON, function () {
        config.clearOverride('keys.kidFormat');
      });
    }

    // --- E. post-quantum -------------------------------------------------------
    const ml65 = await pqcX509.generateKeyPair('ML-DSA-65');
    const pqPin = await pki.pinKeyPair(ON, 'jose', 'ML-DSA-65',
      { privateKeyPem: pqcX509.privatePem('ML-DSA-65', ml65.priv) },
      { leadMs: 0 });
    note(pqPin.ok, 'E1. an ML-DSA-65 key is pinned into the ML-DSA-65 slot',
         JSON.stringify(pqPin.errors || pqPin.signer));
    const pqToken = await inRealm(ON, function () {
      return helpers.signJwtAsAsync({ sub: 'pq' }, 'ML-DSA-65', null, {});
    });
    const pqEntry = (await jwksOf(ON)).filter(function (k) {
      return k.kid === (pqPin.signer && pqPin.signer.kid);
    })[0];
    const parts = String(pqToken).split('.');
    note(headerOf(pqToken).kid === (pqPin.signer && pqPin.signer.kid) &&
         pqEntry && pqEntry.kty === 'AKP' &&
         pqJose.verify('ML-DSA-65', Buffer.from(pqEntry.pub, 'base64url'),
                       Buffer.from(parts[0] + '.' + parts[1], 'ascii'),
                       Buffer.from(parts[2], 'base64url')),
         'E2. an ML-DSA-65 token is signed by it and verifies against its ' +
         'AKP JWK');

    // --- F. xml, with the operator's certificate and chain --------------------
    const xmlPin = await rotation.pinSigningKey(ON, 'xml', 'RS256',
      { privateKeyPem: pem(xmlKey.privateKey), certificatePem: xmlLeaf,
        chainPem: operatorCaPem });
    note(xmlPin.ok && xmlPin.signer,
         'F1. an xml RS256 key with the operator\'s certificate and chain ' +
         'is pinned', JSON.stringify(xmlPin.errors || xmlPin.signer));
    const assertion = inRealm(ON, function () {
      return saml2.buildSamlAssertion('alice', 'https://sp.test', 5);
    });
    const generatedXmlCert = inRealm(ON, function () {
      return helpers.STS.xml.certPem;
    });
    note(stsCrypto.verifyXmlSignature(assertion, { element: 'Assertion',
           certPem: xmlLeaf }).ok &&
         !stsCrypto.verifyXmlSignature(assertion, { element: 'Assertion',
           certPem: generatedXmlCert }).ok,
         'F2. a SAML assertion is signed by the pinned key and not the ' +
         'generated one');
    const md = await get(port, '/realm/' + ON + '/saml2/metadata');
    note(md.text.indexOf(stsCrypto.stripPem(xmlLeaf)) >= 0,
         'F3. the SAML metadata publishes the operator\'s certificate');
    const renewed = await pki.recertifyUseCase(ON, 'xml');
    const afterRenew = pki.pinnedSignersFor(ON).filter(function (one) {
      return one.useCase === 'xml';
    })[0];
    note(renewed.ok && afterRenew &&
         afterRenew.certificatePem === xmlLeaf &&
         afterRenew.chainPem[0] === operatorCaPem,
         'F4. a renewal of the xml Issuing CA leaves the operator\'s ' +
         'certificate and chain alone');

    // --- X. the xml pin is also the decryption key ----------------------------
    const encryptionCerts = function (text) {
      const out = [];
      const re = /<md:KeyDescriptor use="encryption">[\s\S]*?<ds:X509Certificate>([^<]+)</g;
      let m = re.exec(text);
      while (m) {
        out.push(m[1]);
        m = re.exec(text);
      }
      return out;
    };
    const secret = '<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
      'assertion">x-' + nodeCrypto.randomBytes(4).toString('hex') +
      '</saml:NameID>';
    const opens = function (certPem) {
      const sealed = stsCrypto.encryptElement(secret, certPem,
        { keyTransport: 'rsa-oaep', wrapper: 'saml:EncryptedID' });
      const opened = inRealm(ON, function () {
        return helpers.decryptOwnElement(sealed);
      });
      return !!(opened && opened.ok && opened.xml === secret);
    };
    note(JSON.stringify(encryptionCerts(md.text)) ===
           JSON.stringify([stsCrypto.stripPem(xmlLeaf)]),
         'X1. the SAML 2.0 metadata\'s use="encryption" KeyDescriptor is ' +
         'the pinned certificate, alone, once it signs',
         JSON.stringify(encryptionCerts(md.text)).slice(0, 80));
    note(opens(xmlLeaf),
         'X2. something encrypted to the pinned certificate decrypts');
    note(opens(generatedXmlCert),
         'X3. and something encrypted to the generated XML certificate ' +
         'still decrypts, within the grace');
    const xmlRecord = function () {
      const row = keystore.pkiFor(ON);
      return Object.keys(row.certs).map(function (k) {
        return row.certs[k];
      }).filter(function (r) {
        return r.useCase === 'xml' && r.kid === xmlPin.signer.kid;
      })[0];
    };
    const savedUntil = xmlRecord().pinnedSigner.supersedesUntil;
    xmlRecord().pinnedSigner.supersedesUntil = Date.now() - 1000;
    note(!opens(generatedXmlCert) && opens(xmlLeaf),
         'X4. once the grace has passed, the generated key no longer ' +
         'decrypts; the pinned one does');
    xmlRecord().pinnedSigner.supersedesUntil = savedUntil;
    const offMd = await get(port, '/realm/' + OFF + '/saml2/metadata');
    const offXmlCert = inRealm(OFF, function () {
      return helpers.STS.xml.certPem;
    });
    note(JSON.stringify(encryptionCerts(offMd.text)) ===
           JSON.stringify([stsCrypto.stripPem(offXmlCert)]),
         'X5. with the setting off, the encryption KeyDescriptor is the ' +
         'generated key\'s, as before');

    // --- G. rotation skips it --------------------------------------------------
    const keysNow = function () {
      return helpers.stsKeysFor.of(ON);
    };
    await rotation.rotateDue(ON);
    const nextOf = function (unit) {
      return helpers.standbyOf(keysNow(), unit).filter(function (one) {
        return one.role === 'next';
      })[0];
    };
    note(!nextOf('jose:RS256') && !nextOf('xml:RS256') &&
         !!nextOf('jose:ES256:P-256'),
         'G1. signing.rotate gives the pinned units no next key, and the ' +
         'others one');
    note(pki.pinnedSignersFor(ON).filter(function (one) {
           return one.kid === joseKid && one.role === 'active';
         }).length === 1,
         'G2. and the pinned key is untouched');

    // --- I. expiry --------------------------------------------------------------
    const joseView = pki.pinnedSignersFor(ON).filter(function (one) {
      return one.kid === joseKid;
    })[0];
    const nearEnd = new Date(joseView.notAfter).getTime() - 5 * 86400000;
    const warned = rotation.retireDue(ON, { nowMs: function () {
      return nearEnd;
    } });
    note(warned.pinnedWarned >= 1,
         'I1. signing.retire warns as a pinned certificate nears its end',
         JSON.stringify(warned));
    const model = inRealm(ON, function () {
      return pkiAdmin.pkiView({ query: {} }).pinnedSigners;
    });
    note(model && model.on === true && model.keys.length >= 3,
         'I2. the console model lists the pinned keys and says the realm ' +
         'signs with them', JSON.stringify(model && model.keys.map(
           function (k) { return k.kid + ':' + k.role; })));

    // --- J. custody -------------------------------------------------------------
    const row = keystore.pkiFor(ON);
    const held = Object.keys(row.certs).map(function (k) {
      return row.certs[k];
    }).filter(function (r) { return r.kid === joseKid; })[0];
    note(held && held.privateKeyPem === pem(joseKey.privateKey),
         'J1. the pinned private key is kept in the realm\'s PKI row, which ' +
         'the keystore seals under the key-encryption key');
    note(JSON.stringify(model).indexOf('PRIVATE KEY') < 0 &&
         JSON.stringify(pki.describeScope(ON)).indexOf('PRIVATE KEY') < 0 &&
         JSON.stringify(pki.pinnedSignersFor(ON)).indexOf('PRIVATE KEY') < 0,
         'J2. and no public view carries a private key');

    // --- K. the setting cannot be turned off under a live pin -----------------
    const config = require(ROOT + '/common/config');
    const kWrite = inRealm(ON, function () {
      return config.setOverride('pki.pinnedSigners', 'false');
    });
    note(!kWrite.ok && codeOf(kWrite) === 'STS-PKI-0215' &&
         /Unpin first/.test((kWrite.errors || []).join(' ')),
         'K1. the config-set door refuses pki.pinnedSigners=false while a ' +
         'pin is live, STS-PKI-0215, and says to unpin first',
         JSON.stringify(kWrite));
    note(inRealm(ON, function () {
           return config.checkWriteCode('pki.pinnedSigners', false) ===
                    'STS-PKI-0215' &&
                  !!config.checkWrite('pki.pinnedSigners', false) &&
                  config.checkWrite('pki.pinnedSigners', true) === null;
         }),
         'K2. checkWrite() — what a console section asks before any write — ' +
         'refuses off and allows on');
    const kRealmSet = realms.setOverride(ON, 'pki.pinnedSigners', false);
    note(!kRealmSet.ok && codeOf(kRealmSet) === 'STS-PKI-0215',
         'K3. the realm-override door refuses it too',
         JSON.stringify(kRealmSet));
    const kClear = realms.clearOverride(ON, 'pki.pinnedSigners');
    note(!kClear.ok && codeOf(kClear) === 'STS-PKI-0215',
         'K4. and a clear of the realm\'s override, which would fall back to ' +
         'the default off', JSON.stringify(kClear));
    const without = Object.assign({}, realms.get(ON).overrides);
    delete without['pki.pinnedSigners'];
    const kUpdate = realms.update(ON, { overrides: without });
    note(!kUpdate.ok && codeOf(kUpdate) === 'STS-PKI-0215',
         'K5. and an update whose overrides leave it out',
         JSON.stringify(kUpdate));
    const kConsoleReset = inRealm(ON, function () {
      return config.clearOverride('pki.pinnedSigners');
    });
    const kResetAll = inRealm(ON, function () {
      return config.clearAllOverrides();
    });
    note(!kConsoleReset.ok && codeOf(kConsoleReset) === 'STS-PKI-0215' &&
         !kResetAll.ok && codeOf(kResetAll) === 'STS-PKI-0215',
         'K6. and the console\'s reset and reset-all');
    const adminActions = require(ROOT + '/admin-core/admin_actions');
    const kSetMany = await inRealm(ON, function () {
      return adminActions.configAction({ action: 'set-many',
                                         'pki.pinnedSigners': 'false' });
    });
    note(kSetMany && kSetMany.ok === false &&
         codeOf(kSetMany) === 'STS-PKI-0215',
         'K7. and a console section\'s Save (set-many), with the same code',
         JSON.stringify(kSetMany));
    note(inRealm(ON, function () {
           return config.value('pki.pinnedSigners') === true &&
                  helpers.signJwt({ sub: 'k' }).length > 0 &&
                  headerOf(helpers.signJwt({ sub: 'k' })).kid === joseKid;
         }),
         'K8. nothing changed: the setting is on and the pinned key signs');
    const FLIP = 'pinned-flip';
    realms.create({ id: FLIP, name: 'Pinned then off at start',
                    overrides: { 'pki.pinnedSigners': true,
                                 'pki.pinnedSignerLeadMinutes': 0 } });
    await pki.buildScope(FLIP, {});
    const flipKey = nodeCrypto.generateKeyPairSync('ec',
      { namedCurve: 'prime256v1' });
    const flipPin = await pki.pinKeyPair(FLIP, 'jose', 'ES256:P-256',
      { privateKeyPem: pem(flipKey.privateKey) });
    // What a start does: the value arrives from outside every door.
    realms.get(FLIP).overrides['pki.pinnedSigners'] = false;
    const reported = pki.reportPinsWithSignersOff([FLIP]);
    note(flipPin.ok && reported === 1 && inRealm(FLIP, function () {
           return helpers.signingKeyFor('ES256').kid !==
                  (flipPin.signer && flipPin.signer.kid);
         }),
         'K9. a start that finds pins with the setting off says so ' +
         '(STS-PKI-0216) and signs with the generated key',
         JSON.stringify({ reported: reported, pin: flipPin.signer }));

    // --- H. unpin ---------------------------------------------------------------
    const beforeUnpin = announced.length;
    const unpinned = await inRealm(ON, function () {
      return pkiAdmin.pkiAction({ action: 'unpin-key', scope: ON,
                                  useCase: 'jose', slot: 'RS256' });
    });
    note(unpinned.ok && (unpinned.unpinned || [])[0] === joseKid,
         'H1. the console unpins it', JSON.stringify(unpinned));
    const afterToken = inRealm(ON, function () {
      return helpers.signJwt({ sub: 'carol', iss: 'https://on.test' });
    });
    note(headerOf(afterToken).kid === generatedKid,
         'H2. the generated key signs again', headerOf(afterToken).kid);
    let stillOk = false;
    try {
      stillOk = !!inRealm(ON, function () {
        return helpers.verifyOwnJws(idToken);
      });
    } catch (e) {
      stillOk = false;
    }
    note(stillOk && kidsOf(await jwksOf(ON)).indexOf(joseKid) >= 0,
         'H3. what the pinned key signed goes on verifying through its ' +
         'grace, and it stays published');
    note(announced.slice(beforeUnpin).some(function (n) {
           return (n.rotated || []).some(function (r) {
             return r.unit === 'jose:RS256' && r.from === joseKid &&
                    r.to === generatedKid;
           });
         }),
         'H4. the unpin is announced (pinned -> generated)');
    const nothing = pki.unpinKeyPair(ON, 'jose', 'RS256');
    note(!nothing.ok && codeOf(nothing) === 'STS-PKI-0211',
         'H5. unpinning a slot with nothing pinned is STS-PKI-0211');
    const graceEnd = new Date(pki.pinnedSignersFor(ON).filter(function (one) {
      return one.kid === joseKid;
    })[0].retiredUntil).getTime();
    const dropped = rotation.retireDue(ON, { nowMs: function () {
      return graceEnd + 1000;
    } });
    note(dropped.pinnedDropped >= 1 &&
         kidsOf(await jwksOf(ON)).indexOf(joseKid) < 0,
         'H6. past its grace signing.retire drops it, and it leaves the JWKS',
         JSON.stringify(dropped));
    const xmlUnpin = rotation.unpinSigningKey(ON, 'xml', 'RS256');
    const mdAfter = await get(port, '/realm/' + ON + '/saml2/metadata');
    // By KEY: F4's renewal gave the generated key a new certificate.
    const keyOf = function (b64OrPem) {
      const der = /BEGIN/.test(b64OrPem) ? b64OrPem
        : Buffer.from(b64OrPem, 'base64');
      return new nodeCrypto.X509Certificate(der).publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64');
    };
    const offered = encryptionCerts(mdAfter.text);
    note(xmlUnpin.ok && offered.length === 1 &&
         keyOf(offered[0]) === keyOf(generatedXmlCert),
         'X6. unpinned, the metadata offers the generated key for ' +
         'encryption again', JSON.stringify(encryptionCerts(mdAfter.text))
           .slice(0, 120) + ' / ' + stsCrypto.stripPem(generatedXmlCert)
           .slice(0, 40));
    note(opens(generatedXmlCert) && opens(xmlLeaf),
         'X6a. and both the generated key and the unpinned one decrypt, the ' +
         'latter through its grace',
         opens(generatedXmlCert) + ' ' + opens(xmlLeaf));
    note(announced.some(function (n) {
           return (n.rotated || []).some(function (r) {
             return r.unit === 'xml:RS256' && r.from === xmlPin.signer.kid;
           });
         }), 'X7. the xml unpin — signing and decryption both — is ' +
             'announced');
    xmlRecord().pinnedSigner.retiredUntil = Date.now() - 1000;
    note(!opens(xmlLeaf) && opens(generatedXmlCert),
         'X8. past its grace the unpinned key no longer decrypts');
    pki.unpinKeyPair(ON, 'jose', 'ML-DSA-65');
    const offNow = realms.setOverride(ON, 'pki.pinnedSigners', false);
    note(offNow.ok,
         'H7. with nothing live or pending pinned, it can be turned off',
         JSON.stringify(offNow));

    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'pinned-signers-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', PS_ROOT: ROOT, PS_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pinned_signers',
  describe: 'a pinned key pair as a real signer (#263): off by default and ' +
            'refused into a live slot; key type checked per slot; published ' +
            'ahead of use; signs JWS (RS256 and ML-DSA-65) and XML with the ' +
            'operator\'s chain; rotation skips it; unpin restores the ' +
            'generated key, announced, verifying through its grace; expiry ' +
            'warned; the private key in no public view',
  run: run
};
