// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: x509_serial_encoding.js
//
// ===========================================================================
// A CALLER'S SERIAL NUMBER IS WRITTEN IN DER'S SHORTEST FORM (2026-11-05).
//
// `common/crypto_impl/x509.js`'s `issueCertificate()` takes a serial as hex.
// It wrote the hex's bytes as they came, so a serial beginning with a zero
// byte and then one below 0x80 (00 3f …) became an INTEGER with a needless
// leading zero, which DER forbids (X.690 8.3.2) and OpenSSL refuses as
// "illegal padding" when the certificate is loaded. tests/federation_oidc_rp.js
// draws a random eight-byte serial for its partner's TLS certificate and failed
// that way in a full run's cluster mode, about once in five hundred.
//
// Here, with the serials chosen rather than drawn: each certificate is
// issued, read by node's X509Certificate (OpenSSL), handed to
// tls.createSecureContext() (the call that failed), and its serial is the
// caller's number with only the redundant zeros gone. A serial whose first
// byte is 0x80 or more still gets the one zero that keeps it positive.
// ===========================================================================

const log = require('bunyan').createLogger({
  name: 'x509_serial_encoding',
  level: process.env.STS_LOG_LEVEL || 'info'
});

// [the hex the caller gives, the INTEGER's content octets DER must hold,
//  the serial node's X509Certificate prints (without the sign octet)]
const CASES = [
  ['003f0102030405ff', '3f0102030405ff', '3F0102030405FF'],
  ['00003f01', '3f01', '3F01'],
  ['0080aabb', '0080aabb', '80AABB'],
  ['80aabb', '0080aabb', '80AABB'],
  ['7f', '7f', '7F'],
  ['00', '00', '0'],
  ['0000', '00', '0']
];

// The serial's content octets, read off the DER: Certificate SEQUENCE,
// tbsCertificate SEQUENCE, the [0] version, then the INTEGER.
function serialOctets(der) {
  log.debug("Entering serialOctets().");
  let at = 0;
  const header = function () {
    log.debug("Entering header().");
    const tag = der[at];
    let len = der[at + 1];
    let skip = 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) {
        len = len * 256 + der[at + 2 + i];
      }
      skip += n;
    }
    const out = { tag: tag, len: len, body: at + skip };
    log.debug("Leaving header().");
    return out;
  };
  at = header().body;
  at = header().body;
  const version = header();
  if (version.tag === 0xa0) {
    at = version.body + version.len;
  }
  const serial = header();
  log.debug("Leaving serialOctets().");
  return Buffer.from(der.subarray(serial.body, serial.body + serial.len))
    .toString('hex');
}

async function run(t) {
  log.debug("Entering run().");
  const nodeCrypto = require('crypto');
  const tls = require('tls');
  const x509 = require('../common/crypto_impl/x509');
  const keyMaterial = require('../common/crypto_impl/key_material');
  const pair = await keyMaterial.generateKeyPair('ec-p256');
  for (const one of CASES) {
    const given = one[0];
    const octets = one[1];
    const expected = one[2];
    const cert = await x509.issueCertificate({
      subject: [{ name: 'CN', value: 'serial-' + given }],
      subjectPublicKey: pair.publicPem,
      issuerPrivateKey: pair.privatePem, signatureAlg: 'sha256-ecdsa',
      serial: given,
      notBefore: new Date(Date.now() - 60000).toISOString(),
      notAfter: new Date(Date.now() + 3600000).toISOString(),
      extensions: { basicConstraints: { present: true, critical: true,
                                        ca: false } } });
    let read = null;
    let loaded = null;
    let der = '';
    try {
      const parsed = new nodeCrypto.X509Certificate(cert.pem);
      read = parsed.serialNumber;
      der = serialOctets(parsed.raw);
      tls.createSecureContext({ key: pair.privatePem, cert: cert.pem });
      loaded = 'loaded';
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      loaded = String((e && e.message) || e);
    }
    t.equal(loaded, 'loaded', 'serial ' + given + ': OpenSSL loads the ' +
            'certificate into a TLS context');
    t.equal(der, octets, 'serial ' + given + ': the DER INTEGER holds ' +
            octets + ' and no redundant zero');
    t.equal(read, expected, 'serial ' + given + ': OpenSSL reads ' +
            expected);
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'x509_serial_encoding',
  describe: 'A caller\'s certificate serial is written in DER\'s shortest ' +
            'form: a leading zero byte OpenSSL refuses as "illegal padding" ' +
            'is dropped, and the one a high first byte needs is kept',
  run: run
};
