// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: portal_pem_file.js
//
// ===========================================================================
// THE PORTAL'S PEM FILE CHOOSERS (#2294), IN PROCESS.
//
// `portal/web_pem_file.ts` runs in the browser: the PIV enrolment's three
// boxes take a chosen file only when it is the PEM the box takes. Here its
// check is held to real material made by this service's own encoder and by
// node, and to every way a file is wrong:
//
//   A. ACCEPTED: a certificate and a certificate request, each as the box
//      for it takes it; text around the block is not put in the box.
//   B. REFUSED BY ARMOUR: no block, a private key, a request in a
//      certificate box (and the reverse), two blocks, mismatched armour.
//   C. REFUSED BY CONTENT: base64 that is not base64, DER cut short, a
//      SEQUENCE that is not a certificate, a file over 64 KiB.
//   D. THE CHOOSER: a chosen file fills its box and says so; a wrong one
//      leaves the box as it was and says why; the form's markup draws all
//      three choosers with no name, so a file is never sent.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'portal_pem_file',
  level: process.env.LOG_LEVEL || 'info' });

// A fake element: an attribute table, a value and a text.
function element(attributes) {
  log.debug("Entering element().");
  const listeners = {};
  log.debug("Leaving element().");
  return {
    value: '', textContent: '', className: '',
    getAttribute: function (name) {
      return Object.prototype.hasOwnProperty.call(attributes, name)
        ? attributes[name] : null;
    },
    addEventListener: function (type, fn) {
      listeners[type] = fn;
    },
    fire: function (type) {
      return listeners[type] && listeners[type]();
    }
  };
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== the portal\'s PEM file choosers (#2294) ===');
  const PemFile = require('../portal/web_pem_file');
  const keyMaterial = require('../common/crypto_impl/key_material');
  const x509 = require('../common/crypto_impl/x509');
  const testCa = require('./protocol/outbound_test_ca');

  const ca = await testCa.makeCa();
  const certPem = ca.certPem;
  const pair = await keyMaterial.generateKeyPair('ec-p256');
  const csr = await x509.certificationRequest({ subject: 'CN=alice',
    publicKeyPem: pair.publicPem, privateKeyPem: pair.privatePem,
    subjectAltName: [] });
  const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\n' +
    Buffer.from(csr.der).toString('base64').replace(/(.{64})/g, '$1\n')
      .replace(/\n$/, '') + '\n-----END CERTIFICATE REQUEST-----\n';
  const keyPem = nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8',
                                                 format: 'pem' });
  const why = function (text, kind) {
    log.debug("Entering why().");
    const out = PemFile.check(text, kind);
    log.debug("Leaving why().");
    return out.ok ? '' : out.why;
  };

  // A. Accepted.
  const cert = PemFile.check(certPem, 'certificate');
  t.check(cert.ok && cert.pem.indexOf('-----BEGIN CERTIFICATE-----') === 0,
          'A: a certificate is accepted in a certificate box', cert.why);
  const req = PemFile.check(csrPem, 'request');
  t.check(req.ok, 'A: a certificate request is accepted in a request box',
          req.why);
  const wrapped = PemFile.check('Certificate:\n    Data: ...\n' + certPem +
                                'trailing words\n', 'certificate');
  t.check(wrapped.ok && !/Data:|trailing/.test(wrapped.pem),
          'A: text around the block is not put in the box', wrapped.pem);
  t.check(Buffer.from(cert.pem.replace(/-----[^-]+-----|\s/g, ''),
                      'base64').equals(Buffer.from(certPem
                        .replace(/-----[^-]+-----|\s/g, ''), 'base64')),
          'A: the block put in the box is the file\'s bytes');

  // B. Refused by armour.
  t.check(/no PEM block/.test(why('hello', 'certificate')),
          'B: a file with no PEM block is refused');
  t.check(/PRIVATE KEY/.test(why(keyPem, 'certificate')),
          'B: a private key is refused, named by its label');
  t.check(why(csrPem, 'certificate') !== '',
          'B: a certificate request is refused in a certificate box');
  t.check(why(certPem, 'request') !== '',
          'B: a certificate is refused in a request box');
  t.check(/2 PEM blocks/.test(why(certPem + certPem, 'certificate')),
          'B: a file holding two certificates is refused');
  t.check(/ends with/.test(why(certPem.replace('END CERTIFICATE',
                                               'END X509 CRL'),
                               'certificate')),
          'B: a block whose END line names another label is refused');

  // C. Refused by content.
  t.check(/base64/.test(why('-----BEGIN CERTIFICATE-----\nnot*base64!\n' +
                            '-----END CERTIFICATE-----\n', 'certificate')),
          'C: base64 that is not base64 is refused');
  const der = Buffer.from(certPem.replace(/-----[^-]+-----|\s/g, ''),
                          'base64');
  const cut = PemFile.pem('CERTIFICATE',
                          der.subarray(0, der.length - 8).toString('base64'));
  t.check(why(cut, 'certificate') !== '', 'C: DER cut short is refused');
  const notCert = PemFile.pem('CERTIFICATE',
    Buffer.from([0x30, 0x03, 0x02, 0x01, 0x05]).toString('base64'));
  t.check(why(notCert, 'certificate') !== '',
          'C: a SEQUENCE that is not a certificate is refused');
  t.check(/64 KiB/.test(why(certPem + ' '.repeat(70000), 'certificate')),
          'C: a file over 64 KiB is refused');
  t.check(why(PemFile.pem('CERTIFICATE REQUEST', der.toString('base64')),
              'request') !== '',
          'C: a certificate\'s DER labelled as a request is refused');

  // D. The chooser.
  const t9 = { text: function (key, values) {
    return key + ' ' + JSON.stringify(values || {});
  } };
  const box = element({});
  box.value = 'what was there';
  const note = element({});
  const make = function (text, name) {
    log.debug("Entering make().");
    const input = element({ 'data-pem-file': 'box', 'data-pem-note': 'note',
                            'data-pem-kind': 'certificate' });
    input.files = [{ name: name, size: text.length,
                     text: function () {
                       return Promise.resolve(text);
                     } }];
    log.debug("Leaving make().");
    return input;
  };
  const doc = {
    getElementById: function (id) {
      return id === 'box' ? box : (id === 'note' ? note : null);
    },
    querySelectorAll: function () {
      return [];
    }
  };
  await PemFile.read(doc, make(keyPem, 'key.pem'), t9);
  t.check(box.value === 'what was there' &&
          /fileRefused/.test(note.textContent) &&
          /key\.pem/.test(note.textContent),
          'D: a wrong file leaves the box as it was and says why',
          note.textContent);
  await PemFile.read(doc, make(certPem, 'f9.pem'), t9);
  t.check(box.value === cert.pem && /fileRead/.test(note.textContent),
          'D: a certificate file fills its box and says so',
          note.textContent);

  const pages = require('../portal/web_tokens');
  const html = pages.enrolCard({ piv: { profiles: ['piv-auth'] } },
    { html: function (key) {
      return key;
    }, text: function (key) {
      return key;
    } });
  const choosers = html.match(/<input type="file"[^>]*>/g) || [];
  t.check(choosers.length === 3, 'D: the PIV form draws three file choosers',
          String(choosers.length));
  t.check(choosers.every(function (one) {
    return !/\sname="/.test(one);
  }), 'D: no chooser has a name, so the form never sends a file');
  t.check(/data-pem-file="piv-csr" data-pem-kind="request"/.test(html) &&
          /data-pem-file="piv-attest" data-pem-kind="certificate"/
            .test(html) &&
          /data-pem-file="piv-f9" data-pem-kind="certificate"/.test(html),
          'D: each chooser names its box and the kind it checks');

  // E. The issued certificate's download (#2296).
  const issuedHtml = pages.enrolCard({ piv: { profiles: ['piv-auth'] },
    issued: { profile: 'piv-auth', certificatePem: certPem } },
  { html: function (key) {
    return key;
  }, text: function (key) {
    return key;
  } });
  const link = /<a class="btn" id="piv-issued-download" download="cert\.pem" href="data:application\/x-pem-file;charset=utf-8,([^"]*)">portalTokens\.piv\.save<\/a>/
    .exec(issuedHtml);
  t.check(!!link, 'E: the new certificate has a download link named ' +
          'cert.pem beside its box', issuedHtml.slice(0, 400));
  t.check(!!link && decodeURIComponent(link[1].replace(/&amp;/g, '&')) ===
          certPem, 'E: the download is exactly the certificate in the box');

  // F. The PIV tab's layout and certificates (#2299).
  const tr = { html: function (key) {
    return key;
  }, text: function (key) {
    return key;
  }, date: function (value) {
    return 'D(' + value + ')';
  } };
  const form = pages.enrolCard({ piv: { profiles: ['piv-auth'] } }, tr);
  t.check(['piv-csr', 'piv-attest', 'piv-f9'].every(function (box) {
    return new RegExp('<div class="pem-row"><textarea id="' + box +
                      '"[^>]*></textarea><span class="pem-file">')
      .test(form);
  }), 'F: each PEM box and its file chooser are on one row');
  const certs = pages.certificatesCard({
    issued: { serialHex: 'bb' },
    pivCertificates: [
      { serialHex: 'bb', profile: 'piv-auth', subject: 'CN=alice',
        keyAlg: 'ec-p256', notAfter: '2027-01-01T00:00:00Z',
        issuedAt: '2026-11-27T00:00:00Z', status: 'valid' },
      { serialHex: 'aa', profile: 'piv-sign', subject: 'CN=<b>x</b>',
        keyAlg: '', notAfter: '2027-01-01T00:00:00Z',
        issuedAt: '2026-11-26T00:00:00Z', status: 'revoked' }] }, tr);
  t.check(/<tr class="fresh-row"><td>9a<\/td><td>piv-auth \(ec-p256\)/
            .test(certs), 'F: the certificate just issued is the ' +
          'highlighted row, with its slot and key', certs.slice(0, 400));
  t.check(/<td>9c<\/td>/.test(certs) &&
          /class="state-revoked">portalTokens\.piv\.certs\.revoked/
            .test(certs), 'F: each row shows its slot and its state, ' +
          'coloured as the Certificates page colours it');
  t.check(certs.indexOf('<b>x</b>') < 0 &&
          certs.indexOf('&lt;b&gt;x&lt;/b&gt;') >= 0,
          'F: a subject is escaped');
  t.check(/id="piv-certificates-none"/.test(pages.certificatesCard(
    { pivCertificates: [] }, tr)), 'F: no certificate says so');
  const tk = require('../portal/web_tokens_and_keys');
  const tabbed = tk.render({ piv: { profiles: ['piv-auth'] },
    pivCertificates: [] }, { t: tr, me: {} });
  t.check(/id="tk-piv">[\s\S]*id="piv-enrol"[\s\S]*id="piv-certificates"/
            .test(tabbed), 'F: the PIV tab draws the certificates after ' +
          'the enrolment form');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'portal_pem_file',
  describe: 'The portal\'s PIV PEM file choosers take a file only when it is ' +
            'the certificate or request its box takes, checked in the ' +
            'browser by armour, base64 and DER shape',
  run: run
};
