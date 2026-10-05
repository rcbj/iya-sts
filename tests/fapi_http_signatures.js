// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fapi_http_signatures.js
//
// ===========================================================================
// FAPI 2.0 HTTP SIGNATURES AT THE RESOURCE SERVERS (#178): THE POLICY, HELD
// TO THE DRAFT OF 26 JUNE 2026, SECTION BY SECTION.
//
// `oauth-oidc/http_signatures.ts` decides which components a signed request
// must cover, how old it may be, which key verifies it, when an unsigned one
// is refused and what a signed response covers. `common/crypto.js` section
// 14 does the signing, and `tests/http_signatures.js` holds that to the
// RFC's vectors. This file builds the policy's class with its registry, key
// and clock dependencies replaced by fixtures, and the REAL crypto module,
// and drives `atResource()` the way `dpop.presentedAccessToken()` does.
//
// WHY IN PROCESS: every case here is a chosen instant (`created` a minute
// and a second ago), a chosen registration (a client that requires
// signatures, one no entry claims) or a response whose bytes the test must
// hold beside the request to verify `;req`. Over HTTP the service's clock
// and its directory decide those. The HTTP half, which a client sees, is
// `tests/vendored/sts_fapi_http_signatures.js`.
// ===========================================================================

// Deleted rather than set, for the reason config_realm_layer.js gives.
delete process.env.CONFIG_FILE;

// The test's own key pairs are generated here, in the test, never committed
// (rcbj's rule): node's crypto is the independent oracle a test of the
// common module is allowed.
const nodeCrypto = require('crypto');
const errorCodes = require('../common/error_codes');
const stsCrypto = require('../common/crypto');
const sf = require('../common/structured_fields');
const httpSignatures = require('../oauth-oidc/http_signatures');

const log = require('bunyan').createLogger({ name: 'fapi_http_signatures',
  level: process.env.LOG_LEVEL || 'info' });

const NOW = 1790000000;
const CLIENT = 'fapi-client';
const BASE = 'https://rs.example';

function clientKeys() {
  log.debug("Entering clientKeys().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                            { kid: 'client-1', alg: 'ES256', use: 'sig' });
  log.debug("Leaving clientKeys().");
  return { privateKey: pair.privateKey, jwk: jwk };
}

function serverKeys() {
  log.debug("Entering serverKeys().");
  const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  log.debug("Leaving serverKeys().");
  return pair;
}

// The policy, with fixtures for everything it reads but the crypto module.
function profile(fixture) {
  log.debug("Entering profile().");
  const settings = Object.assign({
    'oauth2.httpSignatures': 'off',
    'oauth2.httpSignatureMaxAgeS': 60,
    'oauth2.httpSignatureResponseAlg': 'ES256'
  }, fixture.settings || {});
  const out = new httpSignatures.HttpSignatures({
    log: log,
    config: { value: function (key) { return settings[key]; } },
    errorCodes: errorCodes,
    stsCrypto: stsCrypto,
    sf: sf,
    baseUrlOf: function () { return BASE; },
    currentPrefix: function () { return ''; },
    nowSec: function () { return NOW; },
    jsonFromB64u: function (text) {
      return JSON.parse(Buffer.from(text, 'base64url').toString('utf8'));
    },
    vciError: function (res, status, error, description) {
      res.statusCode = status;
      res.sentBody = { error: error, error_description: description };
    },
    signingKeyFor: function (alg) {
      if (fixture.noServerKey) {
        throw new Error('this realm holds no key for "' + alg + '".');
      }
      return { key: fixture.server.privateKey, kid: 'server-1' };
    },
    publishedKidFor: function (kid) { return kid; },
    httpSignaturesOf: function (clientId) {
      return clientId === CLIENT
        ? { known: true, required: !!fixture.clientRequires, fields: {} }
        : { known: false, required: false, fields: {} };
    },
    keysForParty: function () {
      return { keys: [Object.assign({ source: 'oauthJwks' },
                                    fixture.client.jwk)] };
    },
    ensurePartyKeys: function () { return Promise.resolve(null); }
  });
  log.debug("Leaving profile().");
  return out;
}

// A response object enough like express's for the signer: headers, a
// status, write() and end().
function fakeResponse() {
  log.debug("Entering fakeResponse().");
  const headers = {};
  const res = {
    statusCode: 200, headersSent: false, ended: null, sentBody: null,
    set: function (name, value) { headers[name.toLowerCase()] = value; },
    setHeader: function (name, value) { headers[name.toLowerCase()] = value; },
    getHeader: function (name) { return headers[name.toLowerCase()]; },
    getHeaders: function () { return Object.assign({}, headers); },
    write: function () { res.headersSent = true; return true; },
    end: function (chunk) { res.ended = chunk === undefined ? '' : chunk; }
  };
  log.debug("Leaving fakeResponse().");
  return res;
}

// A request from CLIENT, signed (or not) by `options.sign`.
function request(fixture, options) {
  log.debug("Entering request().");
  const o = options || {};
  const payload = Buffer.from(JSON.stringify({ client_id: CLIENT }))
    .toString('base64url');
  const token = 'eyJhbGciOiJub25lIn0.' + payload + '.';
  const body = o.body ? Buffer.from(o.body, 'utf8') : Buffer.alloc(0);
  const headers = { host: 'rs.example',
                    authorization: (o.dpop ? 'DPoP ' : 'Bearer ') + token };
  if (o.dpop) {
    headers.dpop = 'eyJ0eXAiOiJkcG9wK2p3dCJ9.e30.sig';
  }
  if (body.length) {
    headers['content-type'] = 'application/json';
    headers['content-digest'] = o.badDigest
      ? stsCrypto.contentDigest(Buffer.from('something else'), 'sha-256')
      : stsCrypto.contentDigest(body, 'sha-256');
  }
  const req = { method: o.method || 'GET', url: '/oauth2/userinfo',
                originalUrl: '/oauth2/userinfo', headers: headers,
                rawBody: body.length ? body : undefined,
                res: fakeResponse() };
  if (o.sign) {
    const components = o.components ||
      ['@method', '@target-uri', 'authorization']
        .concat(o.dpop ? ['dpop'] : [])
        .concat(body.length ? ['content-digest'] : []);
    const signed = stsCrypto.signHttpMessage({
      method: req.method, targetUri: BASE + req.originalUrl, headers: headers
    }, {
      label: 'sig1', components: components,
      params: [['created', o.created === undefined ? NOW : o.created],
               ['keyid', o.keyid === undefined ? 'client-1' : o.keyid],
               ['tag', o.tag || 'fapi-2-request']],
      key: fixture.client.privateKey, algorithm: 'ES256' });
    headers['signature-input'] = signed.signatureInput;
    headers.signature = signed.signature;
  }
  log.debug("Leaving request().");
  return { req: req, presented: { claims: { client_id: CLIENT },
                                  scheme: o.dpop ? 'dpop' : 'bearer' } };
}

function refusedWith(t, sent, code, what) {
  log.debug("Entering refusedWith().");
  const res = sent.res;
  t.check(sent.ok === false && res.statusCode === 401 &&
          errorCodes.codeOf(res) === code &&
          /error="invalid_request"/.test(res.getHeader('www-authenticate')),
          what + ' — 401 ' + code,
          JSON.stringify({ ok: sent.ok, status: res.statusCode,
                           code: errorCodes.codeOf(res),
                           body: res.sentBody }));
  log.debug("Leaving refusedWith().");
}

function ask(p, built) {
  log.debug("Entering ask().");
  const res = fakeResponse();
  const ok = p.atResource(built.req, res, built.presented, 'a test');
  log.debug("Leaving ask().");
  return { ok: ok, res: res };
}

// SECTION 5.3.1.2: the resource server as verifier.
function requests(t) {
  log.debug("Entering requests().");
  t.log.info('=== section 5.3.1.2: signed requests ===');
  const fixture = { client: clientKeys(), server: serverKeys() };
  const off = profile(fixture);
  const required = profile(Object.assign({}, fixture,
    { settings: { 'oauth2.httpSignatures': 'require-requests' } }));

  t.check(ask(off, request(fixture)).ok,
          'off: an unsigned request goes on');
  t.check(ask(off, request(fixture, { sign: true })).ok,
          'a valid signed request goes on');
  t.check(ask(off, request(fixture, { sign: true, body: '{"a":1}',
                                      method: 'POST' })).ok,
          'a valid signed request with a body and its Content-Digest goes on');
  t.check(ask(off, request(fixture, { sign: true, dpop: true })).ok,
          'a valid signed DPoP request covering dpop goes on');

  refusedWith(t, ask(required, request(fixture)), 'STS-OAUTH-0939',
              'require-requests: an unsigned request');
  refusedWith(t, ask(profile(Object.assign({}, fixture,
                                           { clientRequires: true })),
                     request(fixture)), 'STS-OAUTH-0939',
              'oauthHttpSignedRequests: an unsigned request from that client');
  refusedWith(t, ask(required, request(fixture, { sign: true, tag: 'gnap' })),
              'STS-OAUTH-0939',
              'require-requests: a signature with another tag is no FAPI ' +
              'signature');

  // A signature that is present is verified whatever the setting says.
  refusedWith(t, ask(off, request(fixture, { sign: true,
    components: ['@method', '@target-uri'] })), 'STS-KEYS-0150',
              'off: a signature that does not cover authorization');
  refusedWith(t, ask(off, request(fixture, { sign: true,
    components: ['@method', 'authorization'] })), 'STS-KEYS-0150',
              'a signature that does not cover @target-uri');
  refusedWith(t, ask(off, request(fixture, { sign: true,
    components: ['@target-uri', 'authorization'] })), 'STS-KEYS-0150',
              'a signature that does not cover @method');
  refusedWith(t, ask(off, request(fixture, { sign: true, dpop: true,
    components: ['@method', '@target-uri', 'authorization'] })),
              'STS-KEYS-0150',
              'a DPoP request whose signature does not cover dpop');
  refusedWith(t, ask(off, request(fixture, { sign: true, body: '{"a":1}',
    method: 'POST', components: ['@method', '@target-uri',
                                 'authorization'] })), 'STS-KEYS-0150',
              'a request with a body whose signature does not cover ' +
              'content-digest');
  refusedWith(t, ask(off, request(fixture, { sign: true, body: '{"a":1}',
    method: 'POST', badDigest: true })), 'STS-KEYS-0111',
              'a Content-Digest that does not match the body');
  refusedWith(t, ask(off, request(fixture, { sign: true,
                                             created: NOW - 61 })),
              'STS-KEYS-0147', 'a signature created 61 s ago (the draft\'s ' +
              '1 minute)');
  refusedWith(t, ask(off, request(fixture, { sign: true,
                                             created: NOW + 61 })),
              'STS-KEYS-0148', 'a signature created 61 s in the future');
  t.check(ask(off, request(fixture, { sign: true, created: NOW - 60 })).ok,
          'a signature created 60 s ago is inside the window');
  refusedWith(t, ask(off, request(fixture, { sign: true,
                                             keyid: 'nobody' })),
              'STS-KEYS-0151', 'a keyid the client registered no key under');
  const stranger = request(fixture, { sign: true });
  stranger.presented.claims = { client_id: 'unregistered' };
  refusedWith(t, ask(off, stranger), 'STS-OAUTH-0941',
              'a signed request whose token names a client nobody ' +
              'registered');
  const other = { client: clientKeys(), server: fixture.server };
  refusedWith(t, ask(off, request(other, { sign: true })), 'STS-KEYS-0153',
              'a signature by a key the client did not register');
  const changed = request(fixture, { sign: true });
  changed.req.originalUrl = '/oauth2/userinfo?x=1';
  refusedWith(t, ask(off, changed), 'STS-KEYS-0153',
              'a request whose target URI is not the one signed');
  log.debug("Leaving requests().");
}

// What the signer put on a response, verified as a client would: with the
// request beside it and the realm key.
function verifyResponse(fixture, built, components) {
  log.debug("Entering verifyResponse().");
  const res = built.req.res;
  const headers = {};
  Object.keys(res.getHeaders()).forEach(function (name) {
    headers[name] = String(res.getHeaders()[name]);
  });
  const result = stsCrypto.verifyHttpMessage({
    status: res.statusCode, headers: headers,
    request: { method: built.req.method,
               targetUri: BASE + built.req.originalUrl,
               headers: built.req.headers }
  }, {
    keyFor: function () {
      return { key: fixture.server.publicKey, algorithm: 'ES256' };
    },
    requireTag: 'fapi-2-response', requireCreated: true,
    requireComponents: components
  });
  log.debug("Leaving verifyResponse().");
  return result;
}

// SECTION 5.3.2.1: the resource server as signer.
function responses(t) {
  log.debug("Entering responses().");
  t.log.info('=== section 5.3.2.1: signed responses ===');
  const fixture = { client: clientKeys(), server: serverKeys() };
  const signing = profile(Object.assign({}, fixture,
    { settings: { 'oauth2.httpSignatures': 'sign-responses' } }));
  const off = profile(fixture);

  const plain = request(fixture);
  t.check(ask(off, plain).ok, 'off: an unsigned request goes on');
  plain.req.res.end('{}');
  t.check(plain.req.res.getHeader('signature') === undefined,
          'off, unsigned request: the response is not signed');

  const unsigned = request(fixture);
  t.check(ask(signing, unsigned).ok, 'sign-responses: an unsigned request ' +
          'goes on');
  unsigned.req.res.setHeader('Content-Type', 'application/json');
  unsigned.req.res.end('{"sub":"x"}');
  const res1 = unsigned.req.res;
  t.check(res1.getHeader('content-digest') ===
            stsCrypto.contentDigest(Buffer.from('{"sub":"x"}'), 'sha-256'),
          'the response carries a sha-256 Content-Digest of its body',
          res1.getHeader('content-digest'));
  t.check(/tag="fapi-2-response"/.test(res1.getHeader('signature-input')) &&
          /;created=\d+/.test(res1.getHeader('signature-input')) &&
          /keyid="server-1"/.test(res1.getHeader('signature-input')),
          'the response signature carries created, keyid and ' +
          'tag="fapi-2-response"', res1.getHeader('signature-input'));
  const v1 = verifyResponse(fixture, unsigned,
    ['@status', 'content-digest', 'content-type', '"@method";req',
     '"@target-uri";req']);
  t.check(v1.ok, 'the response verifies with the realm key, covering ' +
          '@status, content-digest and the request\'s @method and ' +
          '@target-uri by ;req', JSON.stringify(v1));

  // A response to a SIGNED request, under `off`: it is signed because the
  // request was, and it covers the request's signature by ;key.
  const signedReq = request(fixture, { sign: true, body: '{"a":1}',
                                       method: 'POST' });
  t.check(ask(off, signedReq).ok, 'off: a signed request goes on');
  signedReq.req.res.setHeader('Content-Type', 'application/json');
  signedReq.req.res.end(Buffer.from('{"ok":true}'));
  const covers = ['@status', 'content-digest', '"@method";req',
                  '"@target-uri";req', '"content-digest";req',
                  '"authorization";req',
                  '"signature";req;key="sig1"',
                  '"signature-input";req;key="sig1"'];
  const v2 = verifyResponse(fixture, signedReq, covers);
  t.check(v2.ok, 'a response to a signed request is signed even under ' +
          'off, and covers the request\'s Content-Digest, every component ' +
          'its signature covered, and its Signature and Signature-Input ' +
          'members', JSON.stringify(v2));
  const tampered = Object.assign({}, signedReq);
  tampered.req = Object.assign({}, signedReq.req,
    { headers: Object.assign({}, signedReq.req.headers,
                             { authorization: 'Bearer another' }) });
  t.check(!verifyResponse(fixture, tampered, covers).ok,
          'the same response does not verify against a different request');

  // A response with no body carries no Content-Digest and still signs.
  const empty = request(fixture);
  ask(signing, empty);
  empty.req.res.statusCode = 204;
  empty.req.res.end();
  t.check(empty.req.res.getHeader('content-digest') === undefined &&
          verifyResponse(fixture, empty, ['@status']).ok,
          'a 204 with no body is signed without a Content-Digest');

  // A response that began writing goes out unsigned, and so does one the
  // realm holds no key for. Both still end.
  const streamed = request(fixture);
  ask(signing, streamed);
  streamed.req.res.write('part');
  streamed.req.res.end('rest');
  t.check(streamed.req.res.ended === 'rest' &&
          streamed.req.res.getHeader('signature') === undefined,
          'a streamed response is sent, unsigned');
  const keyless = profile(Object.assign({}, fixture,
    { noServerKey: true,
      settings: { 'oauth2.httpSignatures': 'sign-responses' } }));
  const nokey = request(fixture);
  ask(keyless, nokey);
  nokey.req.res.end('{}');
  t.check(nokey.req.res.ended === '{}' &&
          nokey.req.res.getHeader('signature') === undefined,
          'a realm with no key for the algorithm sends the response unsigned');

  // The signer is armed on req.res, the REAL response, even when the check
  // was handed a stand-in (SCIM and Shared Signals do that).
  const viaShim = request(fixture);
  const shim = fakeResponse();
  signing.atResource(viaShim.req, shim, viaShim.presented, 'SCIM');
  viaShim.req.res.end('{}');
  t.check(viaShim.req.res.getHeader('signature') !== undefined &&
          shim.getHeader('signature') === undefined,
          'a check handed a stand-in arms the real response');
  log.debug("Leaving responses().");
}

function run(t) {
  log.debug("Entering run().");
  requests(t);
  responses(t);
  t.check(t.passed() >= 30, 'the file made at least 30 passing checks',
          'made ' + t.passed());
  log.debug("Leaving run().");
}

module.exports = {
  name: 'fapi_http_signatures',
  describe: 'FAPI 2.0 HTTP Signatures (draft of 26 June 2026) at the ' +
            'resource servers: signed requests verified, responses signed',
  run: run
};
