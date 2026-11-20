// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/trust_bootstrap.js
//
// ===========================================================================
// HOW A RUN LEARNS THE SERVICE'S CHAIN WITHOUT DIALLING IT UNVERIFIED
// (2026-11-20), `tools/trust.js`, over REAL HANDSHAKES on loopback listeners
// this file builds: a CA of its own stands in for the service Root, a leaf
// under it for 127.0.0.1 for the main port, which answers
// `/tls/server-certificate` with the chain, and a plain-HTTP listener for
// the revocation listener, which answers `/pki/ca/service/root.cer` (DER).
//
//   A. fetchCertificate() with no anchor held reads the Root from the
//      revocation listener and fetches the chain VERIFIED against it.
//   B. A revocation listener publishing another Root is no anchor: the fetch
//      fails, saying the chain does not verify against it.
//   C. No revocation listener: the fetch fails naming it and the two
//      variables that would supply an anchor, rather than not verifying.
//   D. With the bundle held (useBundle()), the chain verifies against it
//      and the revocation listener is never asked.
//   E. anchorsFor() answers the known anchors plus the Root when those do
//      not verify the listener, and the known anchors alone when they do.
// ===========================================================================

const fs = require('fs');
const http = require('http');
const https = require('https');
const nodeCrypto = require('crypto');
const os = require('os');
const path = require('path');
const tls = require('tls');

const testCa = require('./protocol/outbound_test_ca');
const serviceTrust = require('./tools/service_trust');
const trust = require('./tools/trust');

const log = require('bunyan').createLogger({ name: 'trust_bootstrap',
  level: process.env.LOG_LEVEL || 'info' });

// The variables this file changes, put back whatever happens.
const SAVED = ['NODE_EXTRA_CA_CERTS', 'STS_TRUST_BUNDLE', 'PKI_HTTP_PORT'];

// A server on 127.0.0.1, resolved once listening.
function listening(server) {
  log.debug("Entering listening().");
  log.debug("Leaving listening().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

// The main port: the chain at /tls/server-certificate, 'ok' elsewhere.
function mainPort(leaf, chainPem) {
  log.debug("Entering mainPort().");
  log.debug("Leaving mainPort().");
  return listening(https.createServer({ key: leaf.key, cert: leaf.cert },
    function (req, res) {
      res.end(req.url === trust.CERTIFICATE_PATH ? chainPem : 'ok');
    }));
}

// The revocation listener: `rootPem` as DER at /pki/ca/service/root.cer.
function revocationPort(rootPem) {
  log.debug("Entering revocationPort().");
  const der = new nodeCrypto.X509Certificate(rootPem).raw;
  log.debug("Leaving revocationPort().");
  return listening(http.createServer(function (req, res) {
    if (req.url !== '/pki/ca/service/root.cer') {
      res.statusCode = 404;
      res.end();
      return;
    }
    res.setHeader('content-type', 'application/pkix-cert');
    res.end(der);
  }));
}

// A port nothing listens on: one bound and closed again.
function closedPort() {
  log.debug("Entering closedPort().");
  log.debug("Leaving closedPort().");
  return new Promise(function (resolve) {
    const probe = http.createServer();
    probe.listen(0, '127.0.0.1', function () {
      const port = probe.address().port;
      probe.close(function () {
        resolve(port);
      });
    });
  });
}

// What a promise settled with: { value } or { error }.
async function settled(promise) {
  log.debug("Entering settled().");
  try {
    const value = await promise;
    log.debug("Leaving settled(). Resolved.");
    return { value: value };
  } catch (e) {
    log.debug("Caught in settled(): " + ((e && e.message) || e));
    log.debug("Leaving settled(). Rejected.");
    return { error: e };
  }
}

// One GET verified against `ca`; { status } or { error }.
function get(url, ca) {
  log.debug("Entering get(). " + url);
  log.debug("Leaving get().");
  return new Promise(function (resolve) {
    const req = https.get(url, { agent: false, ca: ca }, function (res) {
      res.resume();
      resolve({ status: res.statusCode });
    });
    req.on('error', function (e) {
      log.debug("Caught in get(): " + ((e && e.message) || e));
      resolve({ error: e });
    });
  });
}

async function run(t) {
  log.debug("Entering run().");
  const saved = {};
  SAVED.forEach(function (name) {
    saved[name] = process.env[name];
    delete process.env[name];
  });
  serviceTrust.useBundle('');
  serviceTrust.forgetRefresh();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trust-bootstrap-'));
  const servers = [];
  try {
    const root = await testCa.makeCa();
    const leaf = await testCa.listenerCertificate(root, '127.0.0.1');
    const stranger = await testCa.makeCa();
    const chainPem = leaf.cert + root.certPem;
    const main = await mainPort(leaf, chainPem);
    const pki = await revocationPort(root.certPem);
    const wrongPki = await revocationPort(stranger.certPem);
    servers.push(main, pki, wrongPki);
    const url = 'https://127.0.0.1:' + main.address().port;

    // ---- A ------------------------------------------------------------
    const fetched = await settled(trust.fetchCertificate(url, 5000,
      { pkiPort: pki.address().port }));
    t.check(fetched.value === chainPem,
            'A. with no anchor held, the chain is fetched verified against ' +
            'the Root the revocation listener publishes',
            String(fetched.error && fetched.error.message));

    // ---- B ------------------------------------------------------------
    const misled = await settled(trust.fetchCertificate(url, 5000,
      { pkiPort: wrongPki.address().port }));
    t.check(!!misled.error &&
            /does not verify against the service Root/.test(
              misled.error.message),
            'B. a revocation listener publishing another Root is no ' +
            'anchor: the fetch fails, saying so',
            String(misled.error ? misled.error.message : misled.value));

    // ---- C ------------------------------------------------------------
    const nowhere = await closedPort();
    const lost = await settled(trust.fetchCertificate(url, 5000,
      { pkiPort: nowhere }));
    t.check(!!lost.error && /revocation listener/.test(lost.error.message) &&
            /PKI_HTTP_PORT/.test(lost.error.message) &&
            /STS_TRUST_BUNDLE/.test(lost.error.message),
            'C. no revocation listener: the fetch fails naming it and the ' +
            'variables that would give an anchor, and never goes unverified',
            String(lost.error ? lost.error.message : lost.value));

    // ---- D ------------------------------------------------------------
    const bundle = path.join(dir, 'bundle.pem');
    fs.writeFileSync(bundle, chainPem);
    serviceTrust.useBundle(bundle);
    const held = await settled(trust.fetchCertificate(url, 5000,
      { pkiPort: nowhere }));
    t.check(held.value === chainPem,
            'D. with the bundle held, the chain verifies against it and ' +
            'the revocation listener is never asked',
            String(held.error && held.error.message));

    // ---- E ------------------------------------------------------------
    // The held bundle is the leaf and the Root, so the known anchors are
    // the system's roots and those two, and nothing is appended to them.
    const knownOnly = await trust.anchorsFor(url, { pkiPort: nowhere });
    t.check(knownOnly.length === tls.rootCertificates.length + 2 &&
            (await get(url + '/', knownOnly)).status === 200,
            'E1. anchorsFor() answers the known anchors alone when they ' +
            'verify the listener');
    serviceTrust.useBundle('');
    const withRoot = await trust.anchorsFor(url,
      { pkiPort: pki.address().port });
    t.check(withRoot.indexOf(root.certPem) >= 0 &&
            (await get(url + '/', withRoot)).status === 200,
            'E2. and adds the service Root when they do not, which then ' +
            'verifies the listener');
    const stillRefused = await get(url + '/',
      await trust.anchorsFor(url, { pkiPort: nowhere }));
    t.check(!!stillRefused.error &&
            serviceTrust.isUntrusted(stillRefused.error),
            'E3. without a Root to add, the known anchors still refuse the ' +
            'listener: never an answer that reads as "do not verify"',
            String(stillRefused.error && stillRefused.error.code));
  } finally {
    servers.forEach(function (server) {
      server.close();
    });
    serviceTrust.useBundle('');
    SAVED.forEach(function (name) {
      if (saved[name] === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = saved[name];
      }
    });
    fs.rmSync(dir, { recursive: true, force: true });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'trust_bootstrap',
  describe: 'A run learns the service\'s chain verified against the Root its ' +
            'revocation listener publishes, never by dialling it ' +
            'unverified (2026-11-20)',
  run: run
};
