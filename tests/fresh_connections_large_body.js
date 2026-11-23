// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// @ts-check
'use strict';
//
// File: tests/fresh_connections_large_body.js
//
// ===========================================================================
// A BODY PAST 64 KiB ON A CONNECTION THE SERVER CLOSES DOES NOT KILL THE JOB
// (2026-10-28): the cluster preload's handler wrap, reproduced and held.
//
// `tests/tools/fresh-connections.js` dispatches every `fetch()` of a cluster
// job with undici's `reset: true`, so the server closes the connection after
// each response. That reaches a race in undici's HTTP/1 client (node 24.22's
// 7.30.1, and 6.28 in node 22): the parser pauses when `fetch()`'s body
// stream is over its high-water mark, and if the socket's `end` arrives
// while it is paused — the last chunk and the close together, the job not
// yet draining — `Parser.finish()` opens with `assert(!this.paused)` and the
// process dies with an AssertionError no `try` can catch. It killed
// `oauth2_sts_endpoints` (ca826bac) and `sts_metadata` (run #10 of
// 2026-10-28), each on the default realm's 67 KB JWKS, each in the cluster
// mode only. The preload's `neverPausing()` answers true from the handler's
// `onData()`, so the parser never pauses.
//
// WHAT IS ASSERTED IS THE CRASH NOT HAPPENING, in a CHILD PROCESS with the
// preload required exactly as `run-report.js` requires it: a local HTTPS
// server answers a 67,480-byte body (the JWKS's size), and the child fetches
// it 1,500 times over eight concurrent loops, draining each body one
// `setImmediate` after the response arrives — which is what a job does when
// it logs or asserts between `await fetch()` and `await r.text()`, and what
// makes the race certain rather than rare: without the wrap the child died
// three runs out of three on 2026-10-28, with it 1,500 of 1,500 answered,
// three runs out of three. The mutant is `neverPausing()` returning its
// argument.
//
// In process because what is held is a property of the PRELOAD, which no
// request to a running service can ask; a child, because the failure is the
// process dying.
// ===========================================================================

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const PRELOAD = path.join(__dirname, 'tools', 'fresh-connections.js');

// The child's program, as a string: it runs in a `node -e` child, so its
// functions carry no Entering/Leaving pair (the code-style exemption).
//
// VERIFIED (#1954's follow-up): the server's certificate is made HERE, before
// the child starts, and handed to it as NODE_EXTRA_CA_CERTS, which node reads
// only at start. Until then the child set NODE_TLS_REJECT_UNAUTHORIZED=0 for
// its whole process, and a fetch with its own dispatcher would bypass the
// preload this file exists to hold.
const CHILD = `
const fs = require('fs');
const https = require('https');
const body = Buffer.alloc(Number(process.env.BODY), 0x41);
const srv = https.createServer({
  key: fs.readFileSync(process.env.KEY_FILE),
  cert: fs.readFileSync(process.env.CERT_FILE)
}, function (req, res) {
  res.setHeader('content-type', 'application/json');
  res.setHeader('content-length', String(body.length));
  res.end(body);
});
srv.listen(0, async function () {
  const url = 'https://localhost:' + srv.address().port + '/';
  const n = Number(process.env.N);
  let ok = 0;
  let started = 0;
  await Promise.all(Array.from({ length: 8 }, async function () {
    while (started < n) {
      started++;
      const r = await fetch(url);
      const text = await new Promise(function (resolve) {
        setImmediate(function () { resolve(r.text()); });
      });
      if (text.length === body.length) { ok++; }
    }
  }));
  console.log(JSON.stringify({ ok: ok, n: n }));
  srv.close();
});
`;

function runChild(env) {
  log.debug("Entering runChild().");
  const promise = new Promise(function (resolve) {
    const child = spawn(process.execPath,
      ['--no-warnings', '-r', PRELOAD, '-e', CHILD], {
        env: Object.assign({}, process.env, env),
        cwd: __dirname,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    let out = '';
    let err = '';
    child.stdout.on('data', function (d) {
      out += d;
    });
    child.stderr.on('data', function (d) {
      err += d;
    });
    child.on('close', function (code, signal) {
      resolve({ code: code, signal: signal, out: out, err: err });
    });
  });
  log.debug("Leaving runChild().");
  return promise;
}

/**
 * A self-signed certificate for localhost, written to a directory of its own.
 *
 * @param {string} dir - where to write `key.pem` and `cert.pem`
 * @returns {{ key: string, cert: string }} the two paths
 */
function localhostCertificate(dir) {
  log.debug("Entering localhostCertificate().");
  const forge = require('node-forge');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 86400000);
  cert.setSubject([{ name: 'commonName', value: 'localhost' }]);
  cert.setIssuer([{ name: 'commonName', value: 'localhost' }]);
  // The name is checked: a SAN, since a client ignores the CN beside one.
  cert.setExtensions([{ name: 'subjectAltName',
                        altNames: [{ type: 2, value: 'localhost' }] }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const out = { key: path.join(dir, 'key.pem'),
                cert: path.join(dir, 'cert.pem') };
  fs.writeFileSync(out.key, forge.pki.privateKeyToPem(keys.privateKey),
                   { mode: 0o600 });
  fs.writeFileSync(out.cert, forge.pki.certificateToPem(cert));
  log.debug("Leaving localhostCertificate().");
  return out;
}

let log = null;

module.exports = {
  name: 'fresh_connections_large_body',
  describe: 'the cluster preload: a 67 KB body on a server-closed ' +
            'connection, fetched 1,500 times, kills nothing',
  run: async function (t) {
    log = t.log;
    log.debug("Entering run().");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-fresh-'));
    let result;
    try {
      const pems = localhostCertificate(dir);
      result = await runChild({
        STS_TEST_FRESH_CONNECTIONS: '1',
        BODY: '67480',
        N: '1500',
        KEY_FILE: pems.key,
        CERT_FILE: pems.cert,
        NODE_EXTRA_CA_CERTS: pems.cert,
        NODE_PATH: path.join(__dirname, 'node_modules') + path.delimiter +
                   path.join(__dirname, '..', 'node_modules')
      });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
    const paused = /assert\(!this\.paused\)/.test(result.err);
    t.check(!paused, 'the child did not die on undici\'s ' +
            '`assert(!this.paused)`', result.err.slice(-600));
    t.equal(result.code, 0, 'the child exited 0', result.err.slice(-600));
    let report = null;
    try {
      report = JSON.parse(result.out.trim().split('\n').pop() || 'null');
    } catch (e) {
      log.debug("Caught in run(): " + ((e && e.message) || e));
      // Not the child's report: the child died before printing one, which
      // the checks above have already said.
      report = null;
    }
    t.check(report !== null && report.ok === report.n && report.n === 1500,
            'every one of the 1,500 bodies was read whole',
            result.out.slice(-300));
    log.debug("Leaving run().");
  }
};
