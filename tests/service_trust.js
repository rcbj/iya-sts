// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/service_trust.js
//
// ===========================================================================
// THE TRUSTSTORE A JOB VERIFIES THE SERVICE AGAINST (2026-11-20),
// `tools/service_trust.js`, over REAL HANDSHAKES on loopback listeners this
// file builds: a CA of its own stands in for the service Root, a leaf under
// it for 127.0.0.1 for the listener, and the bundle file for the one the
// runner writes.
//
//   A. tlsOptions() verifies: a listener under the bundle's Root is
//      answered; one under a stranger's CA is refused, and isUntrusted()
//      says so; the right chain under the WRONG NAME is refused too (the
//      host name is checked, not only the chain).
//   B. Where the bundle comes from: no variable is an error naming the
//      variables, never an empty truststore; useBundle() wins over
//      NODE_EXTRA_CA_CERTS, which wins over STS_TRUST_BUNDLE; the file is
//      read at every call, so a rewrite is seen without another call.
//   C. roots() is the self-signed certificates of the bundle and nothing
//      else; trustedCa() is the default roots plus the bundle.
//   D. refresh() re-reads the chain from /tls/server-certificate over a
//      connection verified against the chain held, and verifies the NEW
//      listener from then on; forgetRefresh() goes back to the file.
//   E. serviceRoot() reads /pki/ca/service/root.cer (DER) as PEM.
//   F. isUntrusted() tells this client's refusal from the server's alert.
// ===========================================================================

const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const tls = require('tls');

const testCa = require('./protocol/outbound_test_ca');
const serviceTrust = require('./tools/service_trust');

const log = require('bunyan').createLogger({ name: 'service_trust',
  level: process.env.LOG_LEVEL || 'info' });

// The variables this file changes, put back whatever happens.
const SAVED = ['NODE_EXTRA_CA_CERTS', 'STS_TRUST_BUNDLE'];

// An https listener answering `body` at every path, on 127.0.0.1.
function listener(cred, body) {
  log.debug("Entering listener().");
  const server = https.createServer({ key: cred.key, cert: cred.cert },
    function (req, res) {
      res.end(typeof body === 'function' ? body(req) : body);
    });
  log.debug("Leaving listener().");
  return new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', function () {
      resolve(server);
    });
  });
}

// One GET with `options`; resolves { status, body } or { error }.
function get(url, options) {
  log.debug("Entering get(). " + url);
  log.debug("Leaving get().");
  return new Promise(function (resolve) {
    let req;
    try {
      req = https.get(url, Object.assign({ agent: false }, options),
        function (res) {
          let body = '';
          res.on('data', function (c) {
            body += c;
          });
          res.on('end', function () {
            resolve({ status: res.statusCode, body: body });
          });
        });
    } catch (e) {
      log.debug("Caught in get(): " + ((e && e.message) || e));
      resolve({ error: e });
      return;
    }
    req.on('error', function (e) {
      resolve({ error: e });
    });
  });
}

function write(dir, name, text) {
  log.debug("Entering write(). " + name);
  const file = path.join(dir, name);
  fs.writeFileSync(file, text);
  log.debug("Leaving write().");
  return file;
}

function clearVariables() {
  log.debug("Entering clearVariables().");
  SAVED.forEach(function (name) {
    delete process.env[name];
  });
  serviceTrust.useBundle('');
  serviceTrust.forgetRefresh();
  log.debug("Leaving clearVariables().");
}

async function run(t) {
  log.debug("Entering run().");
  const saved = {};
  SAVED.forEach(function (name) {
    saved[name] = process.env[name];
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'service-trust-'));
  const servers = [];
  try {
    const root = await testCa.makeCa();
    const leaf = await testCa.listenerCertificate(root, '127.0.0.1');
    const stranger = await testCa.makeCa();
    const strangerLeaf = await testCa.listenerCertificate(stranger,
                                                          '127.0.0.1');
    const misnamed = await testCa.listenerCertificate(root, 'elsewhere.test');
    const bundle = write(dir, 'bundle.pem', leaf.cert + root.certPem);

    const good = await listener(leaf, 'good');
    const bad = await listener(strangerLeaf, 'stranger');
    const wrong = await listener(misnamed, 'misnamed');
    servers.push(good, bad, wrong);
    const at = function (server) {
      return 'https://127.0.0.1:' + server.address().port + '/';
    };

    // ---- A ------------------------------------------------------------
    clearVariables();
    process.env.NODE_EXTRA_CA_CERTS = bundle;
    const ok = await get(at(good), serviceTrust.tlsOptions({}));
    t.check(ok.status === 200 && ok.body === 'good',
            'A1. a listener under the bundle\'s Root is answered, verified',
            JSON.stringify(ok.error && ok.error.code));
    const refused = await get(at(bad), serviceTrust.tlsOptions({}));
    t.check(!!refused.error && serviceTrust.isUntrusted(refused.error),
            'A2. a listener under a stranger\'s CA is refused, and ' +
            'isUntrusted() says it was this client that refused it',
            String(refused.error && refused.error.code));
    const named = await get(at(wrong), serviceTrust.tlsOptions({}));
    t.check(!!named.error && serviceTrust.isUntrusted(named.error),
            'A3. the right chain under the wrong name is refused: the host ' +
            'name is checked, not only the chain',
            String(named.error && named.error.code));
    const raw = await get(at(good), { ca: serviceTrust.trustedCa() });
    t.check(raw.status === 200,
            'A4. `ca: trustedCa()` on a raw request verifies the same way');
    const kept = serviceTrust.tlsOptions({ servername: 'x', ca: 'EXTRA' });
    t.check(kept.servername === 'x' &&
            kept.ca[kept.ca.length - 1] === 'EXTRA',
            'A5. tlsOptions() keeps the caller\'s options and adds to a ' +
            '`ca` it was given rather than dropping it');

    // ---- B ------------------------------------------------------------
    clearVariables();
    let threw = null;
    try {
      serviceTrust.ca();
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      threw = e;
    }
    t.check(threw && /NODE_EXTRA_CA_CERTS/.test(threw.message) &&
            /STS_TRUST_BUNDLE/.test(threw.message),
            'B1. no bundle is an error naming both variables, never an ' +
            'empty truststore', threw ? threw.message : 'no error');
    const empty = write(dir, 'empty.pem', 'no certificate here\n');
    process.env.STS_TRUST_BUNDLE = empty;
    let threwEmpty = null;
    try {
      serviceTrust.ca();
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      threwEmpty = e;
    }
    t.check(threwEmpty && threwEmpty.message.indexOf(empty) >= 0,
            'B2. a bundle holding no certificate is an error naming it');
    const other = write(dir, 'other.pem', stranger.certPem);
    process.env.STS_TRUST_BUNDLE = other;
    process.env.NODE_EXTRA_CA_CERTS = bundle;
    t.equal(serviceTrust.bundlePath(), bundle,
            'B3. a job\'s NODE_EXTRA_CA_CERTS wins over STS_TRUST_BUNDLE');
    serviceTrust.useBundle(other);
    t.equal(serviceTrust.bundlePath(), other,
            'B4. the runner\'s useBundle() wins over both');
    serviceTrust.useBundle('');
    delete process.env.NODE_EXTRA_CA_CERTS;
    t.equal(serviceTrust.bundlePath(), other,
            'B5. STS_TRUST_BUNDLE alone is used (a hand run)');
    const moving = write(dir, 'moving.pem', stranger.certPem);
    serviceTrust.useBundle(moving);
    const before = await get(at(good), serviceTrust.tlsOptions({}));
    fs.writeFileSync(moving, leaf.cert + root.certPem);
    const after = await get(at(good), serviceTrust.tlsOptions({}));
    t.check(before.error && after.status === 200,
            'B6. the file is read at every call: refused under the old ' +
            'bundle, answered once the runner rewrote it',
            String(before.error && before.error.code) + ' ' + after.status);

    // ---- C ------------------------------------------------------------
    clearVariables();
    process.env.NODE_EXTRA_CA_CERTS = bundle;
    const roots = serviceTrust.roots();
    t.check(roots.length === 1 &&
            roots[0].trim() === root.certPem.trim(),
            'C1. roots() is the bundle\'s self-signed certificate only',
            String(roots.length));
    t.equal(serviceTrust.trustedCa().length,
            tls.rootCertificates.length + 2,
            'C2. trustedCa() is the default roots plus the bundle');

    // ---- D ------------------------------------------------------------
    // The service rotates: a new Root and a new leaf, served at
    // /tls/server-certificate by a listener still presenting the OLD one
    // (as the service does until its rebuild completes).
    const newRoot = await testCa.makeCa();
    const newLeaf = await testCa.listenerCertificate(newRoot, '127.0.0.1');
    const rotated = await listener(newLeaf, 'rotated');
    const publisher = await listener(leaf, function (req) {
      return req.url === '/tls/server-certificate'
        ? newLeaf.cert + newRoot.certPem : 'not here';
    });
    servers.push(rotated, publisher);
    const stale = await get(at(rotated), serviceTrust.tlsOptions({}));
    const fetched = await serviceTrust.refresh(at(publisher));
    const fresh = await get(at(rotated), serviceTrust.tlsOptions({}));
    t.check(stale.error && fetched.length === 2 && fresh.status === 200,
            'D1. refresh() reads the new chain over a verified connection ' +
            'and the rotated listener verifies from then on',
            String(stale.error && stale.error.code) + ' ' + fetched.length +
            ' ' + fresh.status);
    let refreshRefused = null;
    try {
      await serviceTrust.refresh(at(bad));
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      refreshRefused = e;
    }
    t.check(refreshRefused && serviceTrust.isUntrusted(refreshRefused),
            'D2. refresh() from a server the held chain does not cover is ' +
            'refused, not adopted');
    serviceTrust.forgetRefresh();
    const back = await get(at(rotated), serviceTrust.tlsOptions({}));
    t.check(!!back.error, 'D3. forgetRefresh() goes back to the file');

    // ---- E ------------------------------------------------------------
    const der = Buffer.from(root.certPem.replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, ''), 'base64');
    const plain = http.createServer(function (req, res) {
      if (req.url === '/pki/ca/service/root.cer') {
        res.setHeader('content-type', 'application/pkix-cert');
        res.end(der);
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise(function (resolve) {
      plain.listen(0, '127.0.0.1', resolve);
    });
    servers.push(plain);
    const base = 'http://127.0.0.1:' + plain.address().port;
    const pem = await serviceTrust.serviceRoot(base);
    t.check(pem.trim() === root.certPem.trim(),
            'E1. serviceRoot() reads the DER Root as PEM');
    let missing = null;
    try {
      await serviceTrust.serviceRoot(base + '/nothing/');
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      missing = e;
    }
    t.check(missing === null,
            'E2. the Root\'s address is absolute: a base with a path still ' +
            'reads /pki/ca/service/root.cer');

    // ---- F ------------------------------------------------------------
    t.check(['UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
             'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN',
             'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED']
      .every(function (code) {
        return serviceTrust.isUntrusted({ code: code });
      }), 'F1. each way this client refuses a certificate is untrusted');
    t.check(!['ERR_SSL_TLSV1_ALERT_CERTIFICATE_REQUIRED',
              'ERR_SSL_SSLV3_ALERT_BAD_CERTIFICATE', 'ECONNRESET',
              'ERR_SSL_NO_SHARED_CIPHER', '']
      .some(function (code) {
        return serviceTrust.isUntrusted({ code: code });
      }), 'F2. the SERVER\'s alert about a certificate, a reset and a ' +
          'refused cipher are not');
  } finally {
    servers.forEach(function (s) {
      s.close();
    });
    clearVariables();
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
  name: 'service_trust',
  describe: 'A job verifies the running service against the chain the ' +
            'runner fetched: chain and name checked, a stranger refused, ' +
            'the bundle re-read, a rotation followed (2026-11-20)',
  run: run
};
