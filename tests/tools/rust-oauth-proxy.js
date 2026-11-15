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
// `/oauth2/logout` with `oauth6`, introspection and revocation with
// `oauth7`): beside the slice-two set, the FAPI report, the attestation
// challenge and the device and CIBA endpoints — each under a named
// authorization server too.
// The device authorization endpoint and grant left with `oauth8`; the
// person's answer on /portal/device is still Node's /account-api operation.
const NODE_PATHS = new RegExp('^(/realm/[^/]+)?(/[^/]+)?(/admin-api|' +
  '/account-api/device|' +
  '/oauth2/(register|' +
  'fapi|challenge|' +
  'bc-authorize)|' +
  '/\\.well-known/webfinger)(/|\\?|$)');
// THE GRANTS THE RUST TOKEN ENDPOINT DOES NOT ISSUE YET (#444 phase 5,
// the `oauth6` slice): a token request is routed by its `grant_type` as
// well as its path — the device and CIBA grants whose endpoints are Node's
// above — so a job reaches the grants after them. Both runtimes verify the other's tokens: one store, one key.
const TOKEN_PATH = new RegExp('^(/realm/[^/]+)?(/[^/]+)?/oauth2/token' +
  '(\\?|$)');
const NODE_GRANTS = ['urn:openid:params:grant-type:ciba'];
// RFC 8693's TOKEN EXCHANGE IS RUST'S since the `oauth8` slice, except an
// exchange presenting or asking for a type whose verifier is not ported:
// an RFC 7522 SAML assertion, a Kerberos ticket (#658) and Native SSO's
// device secret (#130). Rust refuses those as types it does not take; the
// jobs that exercise them reach Node.
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const NODE_EXCHANGE_TYPES = new RegExp('^(urn:ietf:params:oauth:' +
  'token-type:saml[12]|urn:openid:params:token-type:device-secret|' +
  'http://docs\\.oasis-open\\.org/wss/oasis-wss-kerberos-token-' +
  'profile-1\\.1#.*)$');
function exchangeToNode(params) {
  return ['subject_token_type', 'actor_token_type', 'requested_token_type']
    .some(function (name) {
      return NODE_EXCHANGE_TYPES.test(String(params.get(name) || '').trim());
    });
}
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
      const params = new URLSearchParams(body.toString('utf8'));
      const grant = params.get('grant_type') || '';
      forward(req, res, NODE_GRANTS.indexOf(grant) >= 0 ||
              (grant === EXCHANGE && exchangeToNode(params)), body);
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
