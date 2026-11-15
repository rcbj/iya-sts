// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/rust-oauth-proxy.js
//
// ---------------------------------------------------------------------------
// ONE ADDRESS, TWO RUNTIMES ON ONE STORE (#444, phase 5, the `oauth2`
// slice): the protocol jobs that exercise the authorization server set
// themselves up through `/admin-api`, which the Rust runtime does not serve
// yet. This proxy, run on the host by tests/tools/rust-oauth-jobs.sh, sends
// `/admin-api/*` to a Node service and everything else to the Rust one —
// both on the SAME store, coordinating through its change log — so a job
// sees one service whose authorization server is Rust's.
//
//   node rust-oauth-proxy.js <listen port> <rust base> <node base>
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
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oauth-proxy-'));
childProcess.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048',
  '-nodes', '-keyout', path.join(dir, 'key.pem'), '-out',
  path.join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost'],
  { stdio: 'ignore' });
const key = fs.readFileSync(path.join(dir, 'key.pem'));
const cert = fs.readFileSync(path.join(dir, 'cert.pem'));
fs.rmSync(dir, { recursive: true, force: true });

const counts = { rust: 0, node: 0 };
https.createServer({ key: key, cert: cert }, function (req, res) {
  const toNode = /^(\/realm\/[^/]+)?\/admin-api(\/|$)/.test(req.url);
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
}).listen(Number(listen), '127.0.0.1', function () {
  console.log('proxy: listening on ' + listen);
});
process.on('SIGTERM', function () {
  console.log('proxy: ' + JSON.stringify(counts));
  process.exit(0);
});
