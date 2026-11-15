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
// `/admin-api/*` — and the OAuth endpoints the runtime does not port yet
// (`NODE_PATHS`) — to a Node service and everything else,
// the authorization and token endpoints, discovery, the JWKS and the
// sign-in screens, to the Rust one —
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

// What the Rust runtime does not answer yet (#444 phase 5; the consent
// screen and `/authn-api/consent` left with the `oauth4` slice, UserInfo and
// the two mode reports with `oauth5`, RP-Initiated Logout's
// `/oauth2/logout` with `oauth6`): beside the slice-two set, the FAPI
// report, the attestation challenge and the device and CIBA endpoints — each
// under a named authorization server too.
const NODE_PATHS = new RegExp('^(/realm/[^/]+)?(/[^/]+)?(/admin-api|' +
  '/oauth2/(register|introspect|revoke|' +
  'fapi|challenge|device_authorization|' +
  'bc-authorize)|' +
  '/\\.well-known/webfinger)(/|\\?|$)');
// THE GRANTS THE RUST TOKEN ENDPOINT DOES NOT ISSUE YET (#444 phase 5,
// the `oauth6` slice): a token request is routed by its `grant_type` as
// well as its path — RFC 8693's token exchange, and the device and CIBA
// grants whose endpoints are Node's above — so a job reaches the grants
// after them. Both runtimes verify the other's tokens: one store, one key.
const TOKEN_PATH = new RegExp('^(/realm/[^/]+)?(/[^/]+)?/oauth2/token' +
  '(\\?|$)');
const NODE_GRANTS = ['urn:ietf:params:oauth:grant-type:token-exchange',
  'urn:ietf:params:oauth:grant-type:device_code',
  'urn:openid:params:grant-type:ciba'];
const counts = { rust: 0, node: 0 };
function forward(req, res, toNode, body) {
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
  if (body === null) {
    req.pipe(upstream);
  } else {
    upstream.end(body);
  }
}
https.createServer({ key: key, cert: cert }, function (req, res) {
  if (req.method === 'POST' && TOKEN_PATH.test(req.url)) {
    const chunks = [];
    req.on('data', function (c) {
      chunks.push(c);
    });
    req.on('end', function () {
      const body = Buffer.concat(chunks);
      const grant = new URLSearchParams(body.toString('utf8'))
        .get('grant_type') || '';
      forward(req, res, NODE_GRANTS.indexOf(grant) >= 0, body);
    });
    return;
  }
  forward(req, res, NODE_PATHS.test(req.url), null);
}).listen(Number(listen), '127.0.0.1', function () {
  console.log('proxy: listening on ' + listen);
});
process.on('SIGTERM', function () {
  console.log('proxy: ' + JSON.stringify(counts));
  process.exit(0);
});
