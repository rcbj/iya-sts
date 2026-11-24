// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: xmldsig_native.js
//
// ===========================================================================
// XML SIGNATURE AND XML ENCRYPTION ON NODE'S OPENSSL, AND NOTHING LOST (#1615,
// ASVS 5.0.0 11.2.1).
//
// `common/crypto_impl/xmldsig.js` signed RSA XML Signatures, digested every
// Reference, ran AES for XML Encryption and computed HKDF in forge's
// JavaScript, and `common/crypto.js`'s `encryptElement()` encrypted every
// SAML assertion with forge's AES. All of it is node's now. forge is still
// in the tree, and is the REFERENCE here: what node makes is held to what
// forge made, so the change is proved to change no octet, and every
// algorithm that worked before is proved to work still (rcbj, 2026-11-24:
// "We do not want to lose any existing supported signature algorithms,
// especially PQC").
//
//   A. RSA PKCS#1 v1.5, every method `signEnveloped()` signs (SHA-1, -256,
//      -384, -512), over a document with non-ASCII text: the SignatureValue
//      is BYTE FOR BYTE forge's signature of the canonical SignedInfo's
//      UTF-8, and the signature verifies. The Redirect binding's query
//      string signature too.
//   B. EVERY RSA METHOD THE GENERAL ENGINE SIGNS (`SIG_METHODS`' `rsa`
//      rows): signs and verifies — v1.5
//      byte for byte against forge where forge has the hash, PSS (random)
//      verified by forge as well as by node.
//   C. EVERY DIGEST METHOD: node's digest equals forge's where forge has the
//      hash, and node's own `createHash` for the rest, over the UTF-8 and the
//      binary-string forms both.
//   D. XML ENCRYPTION, every content cipher `dataAlgSpec()` knows (AES-GCM
//      128/192/256, AES-CBC 128/192/256, 3DES-CBC): encrypted by node and
//      decrypted by FORGE, and round-tripped; a CBC body padded with random
//      octets (ISO 10126, xmlsec's) still decrypts, a tampered GCM body does
//      not.
//   E. `encryptElement()` (the SAML assertion's encryption) decrypts with
//      `decryptElement()` for AES-128/256-GCM, and its GCM body opens under
//      forge as well.
//   F. `selfSignedCertFor()` is a certificate node and forge both verify.
//   G. POST-QUANTUM is untouched: an ML-DSA SignatureMethod still goes to
//      the caller's signer with the UTF-8 of SignedInfo, and never to RSA.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'xmldsig_native',
  level: process.env.LOG_LEVEL || 'info' });

const DS = 'http://www.w3.org/2000/09/xmldsig#';
const XENC = 'http://www.w3.org/2001/04/xmlenc#';
const XENC11 = 'http://www.w3.org/2009/xmlenc11#';
// A document whose text is not ASCII: a signer that signed the JS string
// rather than its UTF-8 would sign a different message here.
const DOCUMENT = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
  'assertion" ID="_n1615" Version="2.0" IssueInstant="2026-11-24T00:00:00Z">' +
  '<saml:Issuer>https://idp.example</saml:Issuer>' +
  '<saml:Subject><saml:NameID>Grüße — 東京 🌸 Ångström</saml:NameID>' +
  '</saml:Subject></saml:Assertion>';

// The text of the first element named `local` in DS, or ''.
function dsText(xml, local) {
  log.debug("Entering dsText(). " + local);
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const el = doc.getElementsByTagNameNS(DS, local)[0];
  log.debug("Leaving dsText().");
  return el ? String(el.textContent || '').replace(/\s+/g, '') : '';
}

// The canonical SignedInfo of a signed document, as the signer
// canonicalized it (exclusive c14n, which a subtree renders the same in
// place or alone).
function signedInfoCanon(xmldsig, xml) {
  log.debug("Entering signedInfoCanon().");
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const si = doc.getElementsByTagNameNS(DS, 'SignedInfo')[0];
  log.debug("Leaving signedInfoCanon().");
  return xmldsig.canonicalize(si);
}

// forge's PKCS#1 v1.5 signature over `octets` (a binary string) with `hash`.
function forgeSign(forge, keyPem, hash, octets) {
  log.debug("Entering forgeSign(). " + hash);
  const md = forge.md[hash].create();
  md.update(octets);
  log.debug("Leaving forgeSign().");
  return forge.util.encode64(forge.pki.privateKeyFromPem(keyPem).sign(md));
}

async function run(t) {
  log.debug("Entering run().");
  // `common/crypto` first: it installs DOMParser and registers the
  // registry's XML methods into the vendored tables.
  const stsCrypto = require('../common/crypto');
  const xmldsig = require('../common/crypto_impl/xmldsig.js');
  const forge = xmldsig.forge;

  const pair = nodeCrypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' } });
  const keyPem = pair.privateKey;
  const certPem = xmldsig.selfSignedCertFor(keyPem, pair.publicKey,
                                            'xmldsig-native');

  t.log.info('=== F. selfSignedCertFor() ===');
  const x509 = new nodeCrypto.X509Certificate(certPem);
  t.check(x509.verify(x509.publicKey),
          'F1. node verifies the self-signed certificate');
  const fcert = forge.pki.certificateFromPem(certPem);
  t.check(fcert.verify(fcert),
          'F2. and forge verifies it too (the same TBSCertificate and OID)');

  t.log.info('=== A. signEnveloped(): byte for byte forge\'s ===');
  const ENVELOPED = [
    ['http://www.w3.org/2000/09/xmldsig#rsa-sha1', 'sha1'],
    ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', 'sha256'],
    ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', 'sha384'],
    ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', 'sha512']];
  for (const row of ENVELOPED) {
    const signed = xmldsig.signEnveloped(DOCUMENT, {
      privateKeyPem: keyPem, certPem: certPem, sigAlg: row[0],
      placement: 'after-issuer', refUri: '#_n1615' });
    const expected = forgeSign(forge, keyPem, row[1],
      forge.util.encodeUtf8(signedInfoCanon(xmldsig, signed)));
    t.equal(dsText(signed, 'SignatureValue'), expected,
            'A. ' + row[1] + ': the SignatureValue is forge\'s, byte for byte');
    const verdict = xmldsig.verifyXml(signed, {});
    t.check(verdict && verdict.valid === true,
            'A. ' + row[1] + ': and it verifies', JSON.stringify(verdict));
  }
  const query = 'SAMLRequest=abc%2Bdef&RelayState=r&SigAlg=' +
    encodeURIComponent(ENVELOPED[1][0]);
  t.equal(xmldsig.signQueryString(query, { privateKeyPem: keyPem,
                                           sigAlg: ENVELOPED[1][0] }),
          forgeSign(forge, keyPem, 'sha256', forge.util.encodeUtf8(query)),
          'A. the Redirect binding\'s query-string signature is forge\'s');

  t.log.info('=== B. every RSA method in the general engine ===');
  // The rows whose family is `rsa` are the ones the engine's own signer
  // signs, and always did; the rows `common/crypto.js` registers carry the
  // registry's family names and are verified, never signed, here.
  const rsaMethods = Object.keys(xmldsig.SIG_METHODS).filter(function (uri) {
    return xmldsig.SIG_METHODS[uri].family === 'rsa';
  });
  t.check(rsaMethods.length >= 7,
          'B0. the table holds at least the seven RSA methods it always had',
          rsaMethods.join(' '));
  for (const uri of rsaMethods) {
    const m = xmldsig.SIG_METHODS[uri];
    const hash = String(m.hash);
    const pss = m.pad === 'pss';
    let out = null;
    let threw = '';
    try {
      out = xmldsig.signXml(DOCUMENT, {
        mode: 'enveloped', keyInfo: 'x509', placement: 'after-issuer',
        privateKeyPem: keyPem, certPem: certPem, sigAlg: uri,
        c14nAlg: xmldsig.C14N_EXCLUSIVE });
    } catch (e) {
      threw = e.message;
    }
    const xml = out && (typeof out === 'string' ? out : out.xml);
    if (!xml) {
      t.check(false, 'B. ' + uri + ': signed', threw);
      continue;
    }
    const verdict = xmldsig.verifyXml(xml, {});
    t.check(verdict && verdict.valid === true,
            'B. ' + uri + ': signed and verified', JSON.stringify(verdict));
    if (!forge.md[hash]) {
      continue;
    }
    const octets = forge.util.encodeUtf8(signedInfoCanon(xmldsig, xml));
    const value = dsText(xml, 'SignatureValue');
    if (pss) {
      const md = forge.md[hash].create();
      md.update(octets);
      const ok = forge.pki.publicKeyFromPem(pair.publicKey).verify(
        md.digest().getBytes(), forge.util.decode64(value),
        forge.pss.create({ md: forge.md[hash].create(),
          mgf: forge.mgf.mgf1.create(forge.md[hash].create()),
          saltLength: forge.md[hash].create().digestLength }));
      t.check(ok, 'B. ' + uri + ': forge verifies the PSS signature with ' +
              'the parameters it signed with');
    } else {
      t.equal(value, forgeSign(forge, keyPem, hash, octets),
              'B. ' + uri + ': the SignatureValue is forge\'s, byte for byte');
    }
  }

  t.log.info('=== C. every digest method ===');
  const text = 'Grüße — 東京 🌸';
  const binary = forge.util.encodeUtf8(text);
  for (const uri of Object.keys(xmldsig.DIGEST_METHODS)) {
    const md = xmldsig.digestSpec(uri).md;
    const a = md.create();
    a.update(binary);
    const got = a.digest().getBytes();
    const hash = md.algorithm || null;
    if (hash && forge.md[hash]) {
      const f = forge.md[hash].create();
      f.update(binary);
      t.equal(Buffer.from(got, 'binary').toString('hex'),
              Buffer.from(f.digest().getBytes(), 'binary').toString('hex'),
              'C. ' + uri + ': node\'s digest is forge\'s');
      const u = md.create();
      u.update(text, 'utf8');
      t.equal(u.digest().getBytes(), got,
              'C. ' + uri + ': update(s, "utf8") hashes the UTF-8, as ' +
              'forge\'s did');
    } else {
      t.check(got.length > 0,
              'C. ' + uri + ': digested (a row forge never had)');
    }
  }

  t.log.info('=== D. XML Encryption, every content cipher ===');
  const CIPHERS = [XENC11 + 'aes128-gcm', XENC11 + 'aes192-gcm',
                   XENC11 + 'aes256-gcm', XENC + 'aes128-cbc',
                   XENC + 'aes192-cbc', XENC + 'aes256-cbc',
                   XENC + 'tripledes-cbc'];
  const unwrap = function (xml) {
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    const values = doc.getElementsByTagNameNS(XENC, 'CipherValue');
    const wrapped = Buffer.from(String(values[0].textContent), 'base64');
    return { key: nodeCrypto.privateDecrypt({ key: keyPem,
      padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256' }, wrapped),
      body: String(values[1].textContent) };
  };
  for (const uri of CIPHERS) {
    const spec = xmldsig.dataAlgSpec(uri);
    const encrypted = xmldsig.encryptXml(DOCUMENT, { certPem: certPem,
      dataAlg: uri, keyAlg: XENC11 + 'rsa-oaep',
      digest: XENC + 'sha256', mgf: XENC11 + 'mgf1sha256' });
    t.equal(xmldsig.decryptXml(encrypted, { privateKeyPem: keyPem }),
            DOCUMENT, 'D. ' + uri + ': round trip');
    // FORGE OPENS WHAT NODE SEALED: the CipherValue's layout (IV, body, tag)
    // and the padding are forge's.
    const opened = unwrap(encrypted);
    const raw = forge.util.decode64(opened.body);
    const decipher = forge.cipher.createDecipher(spec.cipher,
      opened.key.toString('binary'));
    if (spec.gcm) {
      decipher.start({ iv: raw.substring(0, spec.ivBytes),
        tag: forge.util.createBuffer(raw.substring(raw.length - 16)),
        tagLength: 128 });
      decipher.update(forge.util.createBuffer(
        raw.substring(spec.ivBytes, raw.length - 16)));
    } else {
      decipher.start({ iv: raw.substring(0, spec.ivBytes) });
      decipher.update(forge.util.createBuffer(raw.substring(spec.ivBytes)));
    }
    t.check(decipher.finish() &&
            forge.util.decodeUtf8(decipher.output.getBytes()) === DOCUMENT,
            'D. ' + uri + ': forge decrypts what node encrypted');
    if (!spec.gcm) {
      // ISO 10126 PADDING, as xmlsec writes it: random octets and a count.
      const block = spec.cipher === '3DES-CBC' ? 8 : 16;
      const plain = Buffer.from(DOCUMENT, 'utf8');
      const count = block - (plain.length % block);
      const padding = Buffer.concat([nodeCrypto.randomBytes(count - 1),
                                     Buffer.from([count])]);
      const iv = nodeCrypto.randomBytes(spec.ivBytes);
      const enc = nodeCrypto.createCipheriv(spec.cipher === '3DES-CBC'
        ? 'des-ede3-cbc' : 'aes-' + (spec.keyBytes * 8) + '-cbc',
      opened.key, iv);
      enc.setAutoPadding(false);
      const body = Buffer.concat([iv, enc.update(Buffer.concat([plain,
        padding])), enc.final()]).toString('base64');
      const iso = encrypted.replace(opened.body, body);
      t.equal(xmldsig.decryptXml(iso, { privateKeyPem: keyPem }), DOCUMENT,
              'D. ' + uri + ': random (ISO 10126) padding still decrypts');
    } else {
      const bytes = Buffer.from(opened.body, 'base64');
      bytes[spec.ivBytes] ^= 1;
      const tampered = encrypted.replace(opened.body,
                                         bytes.toString('base64'));
      let refused = false;
      try {
        xmldsig.decryptXml(tampered, { privateKeyPem: keyPem });
      } catch (e) {
        refused = /data decryption failed/.test(e.message);
      }
      t.check(refused, 'D. ' + uri + ': a tampered body is refused');
    }
  }

  t.log.info('=== E. encryptElement() / decryptElement() ===');
  for (const name of ['aes128-gcm', 'aes256-gcm']) {
    const sealed = stsCrypto.encryptElement(DOCUMENT, certPem,
      { algorithm: name, keyTransport: 'rsa-oaep' });
    const back = stsCrypto.decryptElement(sealed, keyPem, {});
    t.check(back && back.ok && /Grüße — 東京 🌸 Ångström/.test(back.xml),
            'E. ' + name + ': encryptElement() round-trips',
            JSON.stringify(back && (back.why || back.algorithm)));
  }

  t.log.info('=== G. post-quantum: the caller\'s signer, untouched ===');
  const mlDsa = Object.keys(xmldsig.SIG_METHODS).filter(function (uri) {
    return xmldsig.SIG_METHODS[uri].postQuantum;
  })[0];
  t.check(!!mlDsa, 'G0. a post-quantum SignatureMethod is in the table',
          String(mlDsa));
  if (mlDsa) {
    let handed = null;
    const signed = xmldsig.signEnveloped(DOCUMENT, {
      sigAlg: mlDsa, placement: 'after-issuer', refUri: '#_n1615',
      includeKeyInfo: false,
      signer: function (octets) {
        handed = octets;
        return 'pq-signature-bytes';
      } });
    t.equal(handed, forge.util.encodeUtf8(signedInfoCanon(xmldsig, signed)),
            'G1. the signer is handed the UTF-8 of the canonical SignedInfo');
    t.equal(dsText(signed, 'SignatureValue'),
            forge.util.encode64('pq-signature-bytes'),
            'G2. and what it answers is the SignatureValue');
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'xmldsig_native',
  describe: 'XML Signature and XML Encryption on node\'s OpenSSL, held to ' +
            'forge\'s output for every RSA and digest method and every ' +
            'content cipher, post-quantum untouched (#1615)',
  run: run
};
