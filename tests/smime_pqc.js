// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: smime_pqc.js
//
// ---------------------------------------------------------------------------
// S/MIME TO AN ML-KEM CERTIFICATE (RFC 9629, RFC 9935).
//
// The recipient is KEMRecipientInfo inside an implicit [4]
// OtherRecipientInfo. Checks 6-11 build the CBC EnvelopedData that
// `mail.smimeContentEncryption` `aes256-cbc` asks for; the default,
// AES-256-GCM in an AuthEnvelopedData (#2124), is
// `tests/smime_auth_enveloped.js`'s. A runtime that cannot
// encapsulate refuses rather than writing a classical envelope. The wrap
// and the DER are checked here with a fixed shared secret, so this file
// never calls encapsulate.
// ---------------------------------------------------------------------------

const nodeCrypto = require('crypto');
const asn1js = require('asn1js');
const pkijs = require('pkijs');
const log = require('bunyan').createLogger({ name: 'smime_pqc',
  level: process.env.LOG_LEVEL || 'info' });

const KEM_OID = '2.16.840.1.101.3.4.4.2';
const ORI_OID = Buffer.from('060b2a864886f70d0109100d03', 'hex');

function view(buf) {
  const b = Buffer.from(buf);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function certificate(publicBytes) {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 7 });
  const name = new pkijs.RelativeDistinguishedNames({
    typesAndValues: [new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: 'Ada' })
    })]
  });
  cert.issuer = name;
  cert.subject = name;
  const now = new Date();
  cert.notBefore.value = new Date(now.getTime() - 60000);
  cert.notAfter.value = new Date(now.getTime() + 86400000);
  cert.subjectPublicKeyInfo = new pkijs.PublicKeyInfo();
  cert.subjectPublicKeyInfo.algorithm = new pkijs.AlgorithmIdentifier({
    algorithmId: KEM_OID
  });
  cert.subjectPublicKeyInfo.subjectPublicKey = new asn1js.BitString({
    valueHex: view(Buffer.alloc(publicBytes, 3))
  });
  cert.signature = new pkijs.AlgorithmIdentifier({
    algorithmId: '2.16.840.1.101.3.4.3.18'
  });
  cert.signatureAlgorithm = cert.signature;
  cert.signatureValue = new asn1js.BitString({
    valueHex: view(Buffer.from([0]))
  });
  return cert;
}

function run(t) {
  log.debug("Entering run().");
  const crypto = require('../common/crypto');
  const row = {
    name: 'ML-KEM-768', publicBytes: 1184, cipherBytes: 1088,
    kekBytes: 32, wrap: 'id-aes256-wrap',
    wrapOid: '2.16.840.1.101.3.4.1.45', kem: 'ml_kem768'
  };
  const shared = Buffer.alloc(32, 4);
  const cek = Buffer.alloc(32, 9);
  const wrapped = crypto.smimeKemWrap(shared, row.wrapOid, row.kekBytes, cek);
  t.equal(wrapped.kek.length, 32, '1. HKDF output is the AES-256 KEK');
  t.equal(wrapped.wrapped.length, 40, '2. AES-KW adds the 8-octet IV');
  const open = nodeCrypto.createDecipheriv('id-aes256-wrap', wrapped.kek,
    Buffer.alloc(8, 0xa6));
  const back = Buffer.concat([open.update(wrapped.wrapped), open.final()]);
  t.check(back.equals(cek), '3. the wrapped content key unwraps');
  const cert = certificate(1184);
  const der = Buffer.from(cert.toSchema(true).toBER(false));
  const chosen = crypto.smimeRecipientCertificate([der], new Date());
  t.equal(chosen.ok, true, '4. an ML-KEM-768 certificate can receive',
          chosen.error);
  const short = crypto.smimeRecipientCertificate(
    [Buffer.from(certificate(10).toSchema(true).toBER(false))], new Date());
  t.check(short.ok === false && /1184/.test(String(short.error)),
          '5. a short ML-KEM public key is refused', short.error);
  const mime = Buffer.from('hello smime');
  const iv = Buffer.alloc(16, 0x11);
  const envelope = crypto.smimeKemAssemble(mime, cert, row, KEM_OID, {
    cipherText: Buffer.alloc(1088, 0x5a), sharedSecret: shared,
    cek: cek, iv: iv
  }, 'aes256-cbc');
  t.equal(envelope[0], 0x30, '6. the envelope is a ContentInfo');
  t.check(envelope.indexOf(Buffer.from([0x02, 0x01, 0x03])) >= 0,
          '7. EnvelopedData version is 3');
  t.check(envelope.indexOf(Buffer.from([0xa4])) >= 0 &&
          envelope.indexOf(ORI_OID) >= 0,
          '8. the recipient is an implicit [4] OtherRecipientInfo');
  t.check(envelope.indexOf(wrapped.wrapped) >= 0,
          '9. the wrapped key is in the recipient info');
  const marker = Buffer.concat([Buffer.from([0x04, 0x10]), iv]);
  const at = envelope.indexOf(marker);
  t.check(at >= 0 && envelope[at + marker.length] === 0x80,
          '10. the content is an implicit OCTET STRING after the IV');
  const n = envelope[at + marker.length + 1];
  const ct = envelope.slice(at + marker.length + 2,
                            at + marker.length + 2 + n);
  const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', cek, iv);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  t.check(plain.equals(mime), '11. AES-256-CBC opens to the MIME entity',
          plain.toString());
  return crypto.smimeEnvelope(mime, der).then(function (out) {
    t.check(out[0] === 0x30 && out.indexOf(ORI_OID) >= 0,
            '12. encapsulation produced a KEM envelope');
    log.debug("Leaving run(). Encapsulated.");
  }, function (e) {
    const message = String((e && e.message) || e);
    t.check(message.indexOf('ML-KEM encapsulation is not available') >= 0,
            '12. a runtime without ML-KEM refuses the envelope', message);
    t.check(message.indexOf('STS-') < 0,
            '13. the refusal sentence carries no error code');
    log.debug("Leaving run().");
  });
}

module.exports = {
  name: 'smime_pqc',
  describe: 'S/MIME: ML-KEM recipients use KEMRecipientInfo, and a ' +
            'runtime that cannot encapsulate does not fall back',
  run: run
};

if (require.main === module) {
  const harness = require('./harness').createHarness('smime_pqc');
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
    harness.log.error(e && e.stack || e);
    process.exit(1);
  });
}
