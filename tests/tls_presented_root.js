// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tls_presented_root.js
//
// ===========================================================================
// THE SERVICE ROOT GOES WITH EVERY CHAIN THIS SERVICE REPORTS (#1064).
//
// A Windows user reported that across fresh installs the Issuing CA and the
// Intermediate differed and "the Root was the same". It never was: every
// install builds its own Root, and every Root is called `CN=sts Root CA,
// O=sts`. The TLS listeners sent the leaf, the Issuing CA and the Intermediate
// and left the Root out (RFC 8446 section 4.4.2 allows that), so a client
// never handed the current Root saw only a NAME and matched it to an older
// Root of that name. Since #1064 every reported chain ends with the Root,
// completed in one place, `common/pki.js` `chainThroughRoot()`.
//
// What this holds, each half the way a reader of it meets it:
//
//   A. A REAL TLS HANDSHAKE on the bundle `tls/tls_server.js`'s
//      `presentedBundlePem()` builds — the bundle every listener presents —
//      carries four certificates, the last of them THIS process's Root, and
//      a client trusting that Root alone verifies it. What the certificate is
//      STORED with (`chainPem`) keeps the Root out.
//   B. `chainThroughRoot()` itself: the Root is the one that SIGNS the chain,
//      never one chosen by name; a chain under somebody else's Root is
//      answered as it came; a leaf alone is answered alone; HAIP's
//      `withoutRoot` leaves it off; bare base64 is taken as well as PEM.
//   C. JOSE and XML: a published `x5c` and an XML `ds:X509Data` end with the
//      Root, the leaf first; an XML signature carrying the chain in KeyInfo
//      still verifies under this service's verifier and under xml-crypto
//      reading the signer's certificate from KeyInfo, which takes the FIRST.
//   D. The listeners that build a context of their own take their bundle
//      from `presentedBundlePem()` rather than joining a chain themselves.
//
// In process, for `tests/tls_trust_anchor.js`'s reason: the claim is about
// what a process presents once `pki.start()` has certified its listener, and
// the assertion that matters is a handshake OpenSSL answers.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives: this
// file must not inherit a CONFIG_FILE from whatever launched the run.
delete process.env.CONFIG_FILE;

const fs = require('fs');
const nodeCrypto = require('crypto');
const path = require('path');
const tls = require('tls');
const { DOMParser } = require('@xmldom/xmldom');
const { SignedXml } = require('xml-crypto');

const keystore = require('../common/keystore');
const pki = require('../common/pki');
const helpers = require('../common/helpers');
const stsCrypto = require('../common/crypto');
const tlsServer = require('../tls/tls_server');

// This file's own logger, for the Entering/Leaving lines and the handled
// exceptions the code style asks for.
const log = require('bunyan').createLogger({ name: 'tls_presented_root',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

function fingerprintOf(pem) {
  log.debug("Entering fingerprintOf().");
  log.debug("Leaving fingerprintOf().");
  return new nodeCrypto.X509Certificate(pem).fingerprint256;
}

function pemCount(bundle) {
  log.debug("Entering pemCount().");
  log.debug("Leaving pemCount().");
  return (String(bundle).match(/-----BEGIN CERTIFICATE-----/g) || []).length;
}

// ---------------------------------------------------------------------------
// ONE HANDSHAKE, AND WHAT THE SERVER SENT.
//
// With no `ca` the client's store holds nothing of this service's, so the
// chain `getPeerCertificate(true)` walks is exactly what came over the wire:
// a Root that was SENT is its own issuer, and an Intermediate sent without
// one has no issuer to point at. Walked by fingerprint until it repeats. With
// `anchorPem` the same bundle is verified against that one Root.
// ---------------------------------------------------------------------------
function handshake(bundlePem, keyPem, anchorPem) {
  log.debug("Entering handshake().");
  log.debug("Leaving handshake().");
  return new Promise(function (resolve) {
    const server = tls.createServer({ cert: bundlePem, key: keyPem },
      function (socket) {
        socket.end();
      });
    server.listen(0, '127.0.0.1', function () {
      const socket = tls.connect({
        host: '127.0.0.1',
        port: server.address().port,
        ca: anchorPem ? [anchorPem] : undefined,
        rejectUnauthorized: !!anchorPem,
        checkServerIdentity: function () {
          log.debug("Entering checkServerIdentity().");
          log.debug("Leaving checkServerIdentity().");
          return undefined;
        }
      }, function () {
        const seen = [];
        let cert = socket.getPeerCertificate(true);
        while (cert && cert.fingerprint256 &&
               seen.indexOf(cert.fingerprint256) < 0) {
          seen.push(cert.fingerprint256);
          cert = cert.issuerCertificate;
        }
        socket.destroy();
        server.close(function () {
          resolve({ error: '', chain: seen });
        });
      });
      socket.on('error', function (e) {
        socket.destroy();
        server.close(function () {
          resolve({ error: e.code || e.message, chain: [] });
        });
      });
    });
  });
}

async function sectionA(t) {
  log.debug("Entering sectionA().");
  t.log.info('=== A. the bundle every TLS listener presents ===');
  const listener = tlsServer.serverCertificate();
  const root = pki.serviceRoot();
  t.check(root && root.certificatePem, 'pki.start() built a service Root');
  t.equal(listener.chainPem.length, 2,
          'the listener certificate is STORED with its Issuing CA and ' +
          'Intermediate, and without the Root — chainPem keeps its meaning');
  t.check(listener.chainPem.indexOf(root.certificatePem) < 0,
          'the stored chain does not carry the Root');
  const bundle = tlsServer.presentedBundlePem(listener);
  t.equal(pemCount(bundle), 4,
          'the presented bundle is four certificates: leaf, Issuing CA, ' +
          'Intermediate, Root');
  const sent = await handshake(bundle, listener.privateKeyPem, '');
  t.equal(sent.error, '', 'a handshake on it completes');
  t.equal(sent.chain.length, 4,
          'and FOUR certificates arrive — the Root among them',
          sent.chain.length + ' certificate(s)');
  t.equal(sent.chain[sent.chain.length - 1],
          fingerprintOf(root.certificatePem),
          'the last of them is THIS process\'s Root, by fingerprint — not a ' +
          'Root of the same name');
  const verified = await handshake(bundle, listener.privateKeyPem,
                                   root.certificatePem);
  t.equal(verified.error, '',
          'a client trusting that Root alone verifies the chain');
  const withoutRoot = [listener.certPem].concat(listener.chainPem).join('');
  const before = await handshake(withoutRoot, listener.privateKeyPem, '');
  t.equal(before.chain.length, 3,
          'and before #1064 the same listener sent three — the Root was ' +
          'never on the wire', before.chain.length + ' certificate(s)');
  t.equal(tlsServer.clientTruststoreOptions().cert[0], bundle,
          'secureContextOptions() — the main port\'s and the debugger\'s ' +
          'context — presents exactly that bundle');
  log.debug("Leaving sectionA().");
}

function sectionB(t) {
  log.debug("Entering sectionB().");
  t.log.info('=== B. chainThroughRoot(), the one place a chain is completed ' +
             '===');
  const listener = tlsServer.serverCertificate();
  const root = pki.serviceRoot();
  const full = pki.chainThroughRoot(listener.certPem, listener.chainPem);
  t.equal(full.length, 4, 'leaf, chain and Root');
  t.equal(full[0], listener.certPem, 'the leaf first');
  t.equal(full[3], root.certificatePem, 'the Root last');
  t.equal(pki.chainThroughRoot(listener.certPem, listener.chainPem,
                               { withoutRoot: true }).length, 3,
          'withoutRoot — HAIP 1.0\'s exception, and the only one — leaves ' +
          'it off');
  t.equal(pki.chainThroughRoot(listener.certPem, []).length, 1,
          'a certificate with no chain is answered alone');
  const foreignLeaf = stsCrypto.selfSignedRsaCertificate(
    { commonName: 'foreign-leaf' });
  const foreignTop = stsCrypto.selfSignedRsaCertificate(
    { commonName: 'sts Root CA' });
  t.equal(pki.chainThroughRoot(foreignLeaf.certPem,
                               [foreignTop.certPem]).length, 2,
          'a chain under somebody else\'s Root — even one CALLED "sts Root ' +
          'CA" — is answered as it came: the Root is matched by signature');
  const b64 = listener.chainPem.map(stsCrypto.stripPem);
  const fromB64 = pki.chainThroughRoot(stsCrypto.stripPem(listener.certPem),
                                       b64);
  t.equal(fromB64.length, 4,
          'bare base64, the way a federation row and a cluster\'s listener ' +
          'leaves hold certificates, is completed too');
  t.equal(fingerprintOf(fromB64[3]), fingerprintOf(root.certificatePem),
          '  and through the same Root');
  log.debug("Leaving sectionB().");
}

function sectionC(t) {
  log.debug("Entering sectionC().");
  t.log.info('=== C. JOSE x5c and XML X509Data ===');
  const root = pki.serviceRoot();
  const rootB64 = stsCrypto.stripPem(root.certificatePem);
  const signer = helpers.STS.xmlSigner;
  t.check(signer && signer.certPem && (signer.certChainPem || []).length,
          'the XML signer holds a certified key with a chain');
  const x5c = helpers.x5cOf(signer.certPem, signer.certChainPem);
  t.equal(x5c[0], stsCrypto.stripPem(signer.certPem),
          'x5c: the certificate holding the key first (RFC 7517 section 4.7)');
  t.equal(x5c[x5c.length - 1], rootB64, 'x5c: the Root last');
  const data = helpers.xmlSignerKeyInfo(signer);
  const certs = data.match(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)
    || [];
  t.equal(certs.length, x5c.length,
          'X509Data: one X509Certificate per member of the chain');
  t.check(data.indexOf('<ds:X509Certificate>' +
                       stsCrypto.stripPem(signer.certPem)) ===
          '<ds:X509Data>'.length,
          'X509Data: the signer\'s own certificate FIRST');
  t.check(certs[certs.length - 1].indexOf(rootB64) > 0,
          'X509Data: the Root last');

  const xml = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:' +
    'assertion" ID="_root1064" Version="2.0" IssueInstant="' +
    new Date().toISOString() + '"><saml:Issuer>https://sts.example.com' +
    '</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID>' +
    '</saml:Subject></saml:Assertion>';
  const signed = stsCrypto.signXml(xml, {
    privateKeyPem: signer.privateKeyPem,
    privateKey: signer.privateKey,
    certPem: signer.certPem,
    keyInfoXml: data,
    what: 'a #1064 assertion'
  });
  const keyInfoCerts = (signed.split('<ds:KeyInfo')[1] || '')
    .match(/<ds:X509Certificate>/g) || [];
  t.equal(keyInfoCerts.length, x5c.length,
          'a signed assertion\'s KeyInfo carries the whole chain');
  const ours = stsCrypto.verifyXmlSignature(signed, {
    element: 'Assertion', certPem: signer.certPem });
  t.check(ours && ours.ok, 'and it verifies under this service\'s verifier',
          JSON.stringify(ours && ours.why));
  const parsed = new DOMParser().parseFromString(signed, 'text/xml');
  const sigEl = parsed.getElementsByTagNameNS(stsCrypto.DS_NS,
                                              'Signature')[0];
  let independent = false;
  try {
    const check = new SignedXml({
      getCertFromKeyInfo: SignedXml.getCertFromKeyInfo });
    check.loadSignature(sigEl);
    independent = !!check.checkSignature(signed);
  } catch (e) {
    log.debug("Caught in sectionC(): " + ((e && e.message) || e));
    independent = false;
  }
  t.check(independent,
          'and under xml-crypto taking the signer\'s certificate from ' +
          'KeyInfo — which reads the FIRST X509Certificate, the leaf');
  const bare = stsCrypto.signXml(xml, {
    privateKeyPem: signer.privateKeyPem,
    privateKey: signer.privateKey,
    certPem: signer.certPem,
    keyInfoXml: data,
    includeKeyInfo: false,
    what: 'a #1064 assertion without KeyInfo'
  });
  t.check(bare.indexOf('X509Certificate') < 0,
          'includeKeyInfo: false still means no KeyInfo at all');
  log.debug("Leaving sectionC().");
}

function sectionD(t) {
  log.debug("Entering sectionD().");
  t.log.info('=== D. every listener takes its bundle from one function ===');
  [['server.js', 'tlsServer.presentedBundlePem(serverCert)',
    'the main port at creation'],
   ['tls/listeners.js', 'tlsServer.presentedBundlePem(',
    'the custom and realm listeners'],
   ['ldap/ldap_server.js', 'tlsServer.presentedBundlePem(serverCertificate)',
    'LDAPS, as ldapjs is handed it'],
   ['common/cell_channel.ts', 'tlsServer.presentedBundlePem(',
    'the channel between cells'],
   ['spiffe/spiffe_grpc.ts', 'SpiffeGrpc.presentedChainPem(svid)',
    'SPIFFE\'s gRPC listeners']
  ].forEach(function (row) {
    const src = fs.readFileSync(path.join(ROOT, row[0]), 'utf8');
    t.check(src.indexOf(row[1]) >= 0,
            row[0] + ': ' + row[2] + ' presents presentedBundlePem()\'s ' +
            'bundle');
  });
  const ldap = fs.readFileSync(path.join(ROOT, 'ldap', 'ldap_server.js'),
                               'utf8').replace(/\s+/g, ' ');
  t.check(!/concat\(\s*(current|serverCertificate)\.chainPem\s*\)/.test(ldap),
          'ldap/ldap_server.js joins no chain of its own any more');
  log.debug("Leaving sectionD().");
}

async function run(t) {
  log.debug("Entering run().");
  await keystore.start();
  const started = await pki.start({ realmIds: [] });
  t.check(started.ok, 'pki.start() builds the hierarchy',
          JSON.stringify(started));
  await sectionA(t);
  sectionB(t);
  sectionC(t);
  sectionD(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'tls presented root',
  describe: 'every chain this service reports ends with the service Root — ' +
            'the TLS listeners\' handshake, x5c and XML X509Data — completed ' +
            'in one place (#1064)',
  run: run
};
