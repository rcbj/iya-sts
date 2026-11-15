// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/rust-saml-proxy.js
//
// ---------------------------------------------------------------------------
// ONE ADDRESS, TWO RUNTIMES ON ONE STORE (#444, phase 7, the `saml` slice),
// rust-oauth-proxy.js's shape: run on the host by
// tests/tools/rust-saml-jobs.sh, it sends what the Rust runtime has ported
// of SAML 2.0 (`RUST_PATHS`) to the Rust service and everything else —
// `/admin-api`, the sign-in, single sign-on, logout, artifacts — to the
// Node one, both on the SAME store.
//
//   node rust-saml-proxy.js <listen port> <rust base> <node base>
//
// TLS on both sides; the upstream certificates are not verified (each
// runtime's own, made at its start). The proxy's own certificate is a
// throwaway one generated at start.
// ---------------------------------------------------------------------------

const https = require('https');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const [listen, rustBase, nodeBase] = process.argv.slice(2);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'saml-proxy-'));
childProcess.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048',
  '-nodes', '-keyout', path.join(dir, 'key.pem'), '-out',
  path.join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost'],
  { stdio: 'ignore' });
const key = fs.readFileSync(path.join(dir, 'key.pem'));
const cert = fs.readFileSync(path.join(dir, 'cert.pem'));
fs.rmSync(dir, { recursive: true, force: true });

// What the Rust runtime does not answer yet (#444 phase 5; the consent
// screen and `/authn-api/consent` left with the `oauth4` slice, UserInfo and
// the two mode reports with `oauth5`, RP-Initiated Logout's
// `/oauth2/logout` with `oauth6`): beside the slice-two set, the FAPI
// report, the attestation challenge and the device and CIBA endpoints — each
// under a named authorization server too.
// What the Rust runtime answers of SAML 2.0 (bins/sts-runtime/src/saml.rs):
// the POST binding's script and the UNSCOPED metadata document, in any
// realm. Everything else is Node's.
const RUST_PATHS = new RegExp('^(/realm/[^/]+)?/saml2/(autopost\\.js|' +
  'metadata)(\\?|$)');
const counts = { rust: 0, node: 0 };
function forward(req, res, toNode) {
  const target = new URL(toNode ? nodeBase : rustBase);
  counts[toNode ? 'node' : 'rust'] += 1;
  const upstream = https.request({ host: target.hostname, port: target.port,
    path: req.url, method: req.method, headers: req.headers,
    rejectUnauthorized: false }, function (up) {
    res.writeHead(up.statusCode, up.headers);
    up.pipe(res);
  });
  upstream.on('error', function (e) {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('proxy: ' + e.message);
  });
  req.pipe(upstream);
}
https.createServer({ key: key, cert: cert }, function (req, res) {
  forward(req, res, !RUST_PATHS.test(req.url));
}).listen(Number(listen), '127.0.0.1', function () {
  console.log('proxy: listening on ' + listen);
});
process.on('SIGTERM', function () {
  console.log('proxy: ' + JSON.stringify(counts));
  process.exit(0);
});
