"use strict";
//
// File: outbound_test_ca.js
//
// ===========================================================================
// A CERTIFICATE AUTHORITY MADE AT RUN TIME, WHICH THE SERVICE UNDER TEST CAN
// BE TOLD TO TRUST, FOR A LISTENER THIS SUITE RUNS (#171, 2026-09-23).
//
// Since #171 no outbound request this service makes in product mode goes over
// TLS without verifying the certificate of whoever answers — the four
// `…SkipTlsVerification` settings are development only — so a job that
// stands up a push or notify listener of its own and wants the service to
// reach it in product mode has to present a certificate the service TRUSTS.
// What product uses to trust a private CA is a `…CaFile` setting, which names
// a FILE on the service's own filesystem.
//
// **NO KEY MATERIAL IS COMMITTED (rcbj, 2026-09-23).** Every job makes a
// fresh CA key pair and certificate here, in memory, and the listener
// certificates it needs under it. The CA CERTIFICATE reaches the service
// through a directory both sides can see, named twice because the two sides
// see it at different paths:
//
//   OUTBOUND_TEST_CA_DIR    where THIS process writes the certificate;
//   OUTBOUND_TEST_CA_FILE   the path the SERVICE reads it at — its file name
//                           is the one written into the directory above.
//
//   * the compose stacks mount one named volume into the runner and into
//     `sts` (and `sts2`, through `extends`) at /run/sts-test and set both;
//   * `./run-coverage.sh`, whose service is a child of the runner, names one
//     temp directory for both;
//   * a private container started by hand needs a `-v` of a host directory
//     at the service-side path, and both variables.
//
// **WHERE NEITHER IS SET THERE IS NO SHARED DIRECTORY** — an AWS target, or a
// hand run without the mount — and `caLocation()` answers null: the sections
// that need one SKIP, saying so, rather than fail. A mount that is set but not
// seen by the service is a misconfiguration and does fail, on STS-CORE-0104.
//
// The certificates are built by `common/vendored/x509.js` and the keys by
// `common/vendored/key_material.js` — the PKI encoder this repository vendors
// from the debugger, which `sts_application_credentials.js` builds its
// external hierarchy with too — so there is one certificate encoder and no
// test-local one. Nothing from the service itself.
// ===========================================================================

const fs = require("fs");
const net = require("net");
const path = require("path");

const log = require("bunyan").createLogger({ name: "outbound_test_ca",
  level: process.env.LOG_LEVEL || "info" });

const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "vendored", "x509.js"));
const keys = require(path.join(REPO, "common", "vendored",
                               "key_material.js"));

// The shared directory, or null when there is none — see the header.
function caLocation() {
  log.debug("Entering caLocation().");
  const dir = String(process.env.OUTBOUND_TEST_CA_DIR || "");
  const file = String(process.env.OUTBOUND_TEST_CA_FILE || "");
  if (!dir || !file) {
    log.debug("Leaving caLocation(). None.");
    return null;
  }
  log.debug("Leaving caLocation().");
  return { dir: dir, serviceFile: file,
           localFile: path.join(dir, path.basename(file)) };
}

// The sentence a skipping section logs.
function skipReason() {
  log.debug("Entering skipReason().");
  log.debug("Leaving skipReason().");
  return "SKIPPED: there is no directory shared with the service " +
         "(OUTBOUND_TEST_CA_DIR and OUTBOUND_TEST_CA_FILE are not both " +
         "set), so the service cannot be told to trust a CA this job made. " +
         "Product mode verifies every outbound certificate (#171).";
}

function subjectAltNameOf(hostname) {
  log.debug("Entering subjectAltNameOf().");
  const names = [{ kind: net.isIP(String(hostname)) ? "ip" : "dns",
                   value: String(hostname) }];
  if (hostname !== "localhost") {
    names.push({ kind: "dns", value: "localhost" });
  }
  log.debug("Leaving subjectAltNameOf().");
  return { present: true, critical: false, names: names };
}

// A fresh CA: `{ certPem, privatePem }`.
async function makeCa() {
  log.debug("Entering makeCa().");
  const pair = await keys.generateKeyPair("rsa-2048");
  const root = await x509.issueCertificate({
    subject: [{ name: "CN", value: "outbound test CA " + Date.now() }],
    subjectPublicKey: pair.publicPem, signatureAlg: "sha256-rsa",
    profile: "root-ca",
    issuer: { privateKeyPem: pair.privatePem, keyAlg: "rsa-2048" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: true,
                          pathLen: null },
      keyUsage: { present: true, critical: true,
                  usages: ["keyCertSign", "cRLSign"] }
    }
  });
  log.debug("Leaving makeCa().");
  return { certPem: root.pem, privatePem: pair.privatePem };
}

// A TLS server key and certificate for `hostname`, issued by `ca` (or
// self-signed when `ca` is null). `{ key, cert }`, for https.createServer().
async function listenerCertificate(ca, hostname) {
  log.debug("Entering listenerCertificate(). " + hostname);
  const pair = await keys.generateKeyPair("rsa-2048");
  const issuer = ca
    ? { certificatePem: ca.certPem, privateKeyPem: ca.privatePem,
        keyAlg: "rsa-2048" }
    : { privateKeyPem: pair.privatePem, keyAlg: "rsa-2048" };
  const leaf = await x509.issueCertificate({
    subject: [{ name: "CN", value: String(hostname) }],
    subjectPublicKey: pair.publicPem, signatureAlg: "sha256-rsa",
    profile: "tls-server", issuer: issuer,
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ["digitalSignature", "keyEncipherment"] },
      extKeyUsage: { present: true, critical: false, usages: ["serverAuth"] },
      subjectAltName: subjectAltNameOf(hostname)
    }
  });
  log.debug("Leaving listenerCertificate().");
  return { key: pair.privatePem, cert: leaf.pem };
}

// A self-signed certificate for `hostname`, which no CA file trusts.
async function selfSignedCertificate(hostname) {
  log.debug("Entering selfSignedCertificate(). " + hostname);
  log.debug("Leaving selfSignedCertificate().");
  return listenerCertificate(null, hostname);
}

// Write `ca`'s certificate into the shared directory and answer the path the
// SERVICE reads it at, or null when there is no shared directory.
function publishCa(ca) {
  log.debug("Entering publishCa().");
  const where = caLocation();
  if (!where) {
    log.debug("Leaving publishCa(). No shared directory.");
    return null;
  }
  fs.mkdirSync(where.dir, { recursive: true });
  fs.writeFileSync(where.localFile, ca.certPem, { mode: 0o644 });
  log.debug("Leaving publishCa(). " + where.localFile);
  return where.serviceFile;
}

module.exports = {
  caLocation: caLocation,
  skipReason: skipReason,
  makeCa: makeCa,
  listenerCertificate: listenerCertificate,
  selfSignedCertificate: selfSignedCertificate,
  publishCa: publishCa
};
