// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: tests/peer/peer_pki.js
//
// ===========================================================================
// THE TEST PEER'S CERTIFICATES, MADE WHEN IT STARTS (#586). NOTHING HERE IS
// COMMITTED, AND NOTHING IS READ FROM DISK.
//
//   * a CA, whose certificate — and only its certificate — is written to the
//     directory the stack shares with the service (`sts-test-shared`), so a
//     product-mode realm can be told to trust it through a `…CaFile` setting
//     (`ssf.pushCaFile`): product mode verifies every outbound certificate
//     (#171), and a skip of verification is development only;
//   * the TLS listener's certificate under that CA, for the names the peer
//     is reached by;
//   * per tenant, a self-signed SIGNING certificate — what a SAML service
//     provider or relying party registers as `samlSigningCertificate`, and
//     signs its AuthnRequests, ArtifactResolves and SAML 1.1 Requests with.
//
// The keys are node's (`generateKeyPairSync`); the certificates are
// node-forge's, the encoder `sts_saml11.js` and `sts_xml_schema_validation.js`
// already build their relying parties' certificates with. The vendored PKI
// encoder (`common/vendored/x509.js`) is not reachable from this image's
// build context, and the peer needs nothing it has that forge lacks: no CRL
// is named, because the service asks a CRL of a chain somebody PRESENTS
// (#174) and this one is only ever presented by a listener it dials, as
// `outbound_test_ca.js`'s listener certificates are.
// ===========================================================================

const nodeCrypto = require("crypto");
const net = require("net");
const forge = require("node-forge");
const util = require("./peer_util.js");

const log = util.logger("peer_pki");

// A fresh RSA pair as PEM, made by node (forge's own generator is slow and
// draws on its own PRNG).
function rsaPair() {
  log.debug("Entering rsaPair().");
  const pair = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  log.debug("Leaving rsaPair().");
  return {
    privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" })
  };
}

// A serial number: positive, 16 bytes, from node's CSPRNG.
function serial() {
  log.debug("Entering serial().");
  const bytes = nodeCrypto.randomBytes(16);
  // Positive and minimal: a zero first byte would make a DER INTEGER with a
  // superfluous leading 0x00, which OpenSSL refuses ("illegal padding").
  bytes[0] = (bytes[0] & 0x7f) || 0x01;
  log.debug("Leaving serial().");
  return bytes.toString("hex");
}

// The parts every certificate here shares. Valid from a minute ago (clock
// skew between containers) for a day — longer than any run.
function certificateFor(subjectCn, publicKeyPem) {
  log.debug("Entering certificateFor(). " + subjectCn);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  cert.serialNumber = serial();
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 3600 * 1000);
  cert.setSubject([{ name: "commonName", value: subjectCn }]);
  log.debug("Leaving certificateFor().");
  return cert;
}

function finish(cert, signerPem) {
  log.debug("Entering finish().");
  cert.sign(forge.pki.privateKeyFromPem(signerPem), forge.md.sha256.create());
  const pem = forge.pki.certificateToPem(cert);
  const der = Buffer.from(forge.asn1.toDer(
    forge.pki.certificateToAsn1(cert)).getBytes(), "binary");
  log.debug("Leaving finish().");
  return { certPem: pem, certB64: der.toString("base64"), certDer: der };
}

// The CA: `{ certPem, certB64, privateKeyPem }`.
function makeCa(label) {
  log.debug("Entering makeCa().");
  const pair = rsaPair();
  const cert = certificateFor(label || ("sts-test-peer CA " + Date.now()),
                              pair.publicKeyPem);
  cert.setIssuer(cert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" }
  ]);
  const out = finish(cert, pair.privateKeyPem);
  out.privateKeyPem = pair.privateKeyPem;
  out.forgeCert = cert;
  log.debug("Leaving makeCa().");
  return out;
}

// A TLS server certificate under `ca` for every name in `names` (a DNS name
// or an address). `{ key, cert }`, for tls.createServer().
function listenerCertificate(ca, names) {
  log.debug("Entering listenerCertificate(). " + names.join(","));
  const pair = rsaPair();
  const cert = certificateFor(names[0], pair.publicKeyPem);
  cert.setIssuer(ca.forgeCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false, critical: true },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true,
      critical: true },
    { name: "extKeyUsage", serverAuth: true },
    { name: "subjectAltName", altNames: names.map(function (one) {
      return net.isIP(one) ? { type: 7, ip: one } : { type: 2, value: one };
    }) },
    { name: "authorityKeyIdentifier",
      keyIdentifier: ca.forgeCert.generateSubjectKeyIdentifier().getBytes() },
    { name: "subjectKeyIdentifier" }
  ]);
  const out = finish(cert, ca.privateKeyPem);
  log.debug("Leaving listenerCertificate().");
  return { key: pair.privateKeyPem, cert: out.certPem + ca.certPem };
}

// A self-signed signing certificate: `{ privateKeyPem, certPem, certB64 }`.
function signingCertificate(cn) {
  log.debug("Entering signingCertificate(). " + cn);
  const pair = rsaPair();
  const cert = certificateFor(cn, pair.publicKeyPem);
  cert.setIssuer(cert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, nonRepudiation: true }
  ]);
  const out = finish(cert, pair.privateKeyPem);
  out.privateKeyPem = pair.privateKeyPem;
  log.debug("Leaving signingCertificate().");
  return { privateKeyPem: out.privateKeyPem, certPem: out.certPem,
           certB64: out.certB64 };
}

module.exports = {
  makeCa: makeCa,
  listenerCertificate: listenerCertificate,
  signingCertificate: signingCertificate
};
