// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/tools/oauth-vectors.js
//
// ---------------------------------------------------------------------------
// THE AUTHORIZATION SERVER'S CORE, AS NODE ANSWERS IT (#444, phase 5, the
// `oauth` slice): the vectors `rust/crates/sts-oauth/tests/oauth_vectors.rs`
// reads. Run by `crypto-vectors.js` (`oauth-node.json`), in a child of its
// own, so the protocol stack it loads is fresh.
//
// What is recorded, each set with what it was built from:
//
//   sanitize    oauth21.sanitizeDescription() over awkward sentences.
//   jwks        GET /oauth2/jwks in several realms of differing policy and
//               mode, each with the stored key set (`keystore.serialise()`),
//               the certificates the hierarchy published over its keys, the
//               service Root and the answer.
//   clientAuth  oauth2_bcp's observeClientAuthentication() and
//               checkClientAuthentication() — and so client_auth.js's
//               methodFor() and verify() — over clients of every method this
//               slice ports, with what they presented and the clock.
//
// No key material is kept beyond the vectors directory, which is never
// committed. The functions here are plain Node and follow the root
// CLAUDE.md's style; a builder is a tool, not service code, and logs nothing.
// ---------------------------------------------------------------------------

const http = require('http');
const nodeCrypto = require('crypto');
const path = require('path');

function clone(value) {
  return value === undefined ? null : JSON.parse(JSON.stringify(value));
}

function b64u(value) {
  return Buffer.from(typeof value === 'string' ? value
    : JSON.stringify(value)).toString('base64url');
}

// A compact JWS signed here, as a client signs one.
function signJws(header, claims, key, alg) {
  const input = b64u(header) + '.' + b64u(claims);
  let signature;
  if (/^HS/.test(alg)) {
    signature = nodeCrypto.createHmac('sha' + alg.slice(2), key)
      .update(input).digest();
  } else if (/^ES/.test(alg)) {
    signature = nodeCrypto.sign('sha' + alg.slice(2), Buffer.from(input),
      { key: key, dsaEncoding: 'ieee-p1363' });
  } else if (/^PS/.test(alg)) {
    signature = nodeCrypto.sign('sha' + alg.slice(2), Buffer.from(input),
      { key: key, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: Number(alg.slice(2)) / 8 });
  } else {
    signature = nodeCrypto.sign('sha' + alg.slice(2), Buffer.from(input), key);
  }
  return input + '.' + signature.toString('base64url');
}

function get(port, urlPath) {
  return new Promise(function (resolve) {
    http.get({ host: '127.0.0.1', port: port, path: urlPath },
      function (res) {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text });
        });
      }).on('error', function (e) {
      resolve({ status: 0, headers: {}, text: String(e && e.message) });
    });
  });
}

function sanitizeVectors(oauth21) {
  return ['plain words.', 'an em dash — and an en dash –',
          'quotes “like” ‘these’ and "these"', 'a back\\slash',
          'tabs\tand\r\nnewlines\n\n', 'an ellipsis…', 'a no-break space',
          'é and 𝄞 and ☃', '{json: "x"}', ''].map(function (one) {
    return { text: one, sanitized: oauth21.sanitizeDescription(one) };
  });
}

// What the JWKS reads about a key set: every certificate the hierarchy
// published over a jose key, by `<slot>@<kid>`, and the pinned signers.
function sourcesOf(pki, helpers, realmId, keys) {
  const published = {};
  const kids = [{ slot: 'RS256', kid: keys.kid }];
  helpers.standbyOf(keys).forEach(function (one) {
    if (one.useCase === 'jose') {
      kids.push({ slot: String(one.unit || '').split(':').slice(1).join(':'),
                  kid: one.kid });
    }
  });
  (keys.signerGroups || []).forEach(function (one) {
    if (one.publicJwk) {
      kids.push({ slot: one.slot, kid: one.publicJwk.kid });
    }
  });
  kids.forEach(function (one) {
    const held = pki.publishedCertificateFor(realmId, 'jose', one.slot,
                                             one.kid);
    if (held) {
      published[one.slot + '@' + one.kid] = {
        certificatePem: held.certificatePem,
        chainPem: (held.chainPem || []).slice() };
    }
  });
  const root = pki.serviceRoot ? pki.serviceRoot() : null;
  const pinned = (pki.pinnedSignersFor ? pki.pinnedSignersFor(realmId) : [])
    .filter(function (one) {
      return one.useCase === 'jose';
    }).map(function (one) {
      return { kid: one.kid, kind: one.kind,
               certificatePem: one.certificatePem,
               chainPem: one.chainPem, publicJwk: one.publicJwk || null };
    });
  return { published: published,
           rootPem: (root && root.certificatePem) || null,
           pinned: pinned };
}

async function jwksVectors(ROOT, port, mods) {
  const { config, realms, helpers, keystore, pki } = mods;
  const SCENARIOS = [
    { name: 'development, defaults', overrides: {} },
    { name: 'product, defaults', overrides: { 'global.mode': 'product' } },
    { name: 'eddsa on', overrides: { 'keys.eddsaSigning': true } },
    { name: 'post-quantum off', overrides: { 'keys.postQuantumSigning': false } },
    { name: 'pqc only', overrides: { 'keys.pqcOnly': true } },
    { name: 'a sign list', overrides: { 'keys.signingAlgorithms': 'ES256,RS256,PS256' } },
    { name: 'thumbprint kids', overrides: { 'keys.kidFormat': 'jwk-thumbprint-uri' } },
    { name: 'next generations', overrides: {}, next: true },
    { name: 'next generations, product',
      overrides: { 'global.mode': 'product' }, next: true }
  ];
  const out = [];
  for (let i = 0; i < SCENARIOS.length; i++) {
    const scenario = SCENARIOS[i];
    const id = 'jwks' + i;
    const made = realms.create({ id: id, name: id,
                                 description: 'oauth-vectors.js',
                                 overrides: scenario.overrides });
    if (!made.ok) {
      out.push({ name: scenario.name, problem: JSON.stringify(made) });
      continue;
    }
    const realm = realms.get(id);
    await realms.run(realm, async function () {
      const keys = helpers.stsKeysFor();
      try {
        await pki.ensureRoot();
        await pki.ensureScope(id);
        await pki.certifyKeySet(id, keys);
      } catch (e) {
        out.push({ name: scenario.name, problem: 'pki: ' + e.message });
      }
      if (scenario.next) {
        await helpers.ensureNextGenerations(id, { units: ['jose:RS256',
          'jose:ES256'] });
      }
    });
    const answer = await get(port, '/realm/' + id + '/oauth2/jwks');
    await realms.run(realm, async function () {
      const keys = helpers.stsKeysFor();
      const settings = {};
      ['keys.postQuantumSigning', 'keys.eddsaSigning', 'keys.pqcOnly',
       'keys.signingAlgorithms', 'keys.kidFormat', 'keys.encryptionKemAlgs',
       'keys.jwksCertificateUrl', 'global.mode'].forEach(function (k) {
        settings[k] = clone(config.value(k));
      });
      out.push({ name: scenario.name, realm: id, settings: settings,
                 mode: require(ROOT + '/common/mode').current(),
                 nowMs: Date.now(),
                 blob: clone(keystore.serialise(keys)),
                 sources: sourcesOf(pki, helpers, id, keys),
                 status: answer.status,
                 cacheControl: answer.headers['cache-control'] || '',
                 body: answer.text });
    });
  }
  return out;
}

// A fake request: headers only, and no TLS socket.
function requestWith(headers) {
  return { headers: headers || {}, socket: {}, connection: {} };
}

async function clientAuthVectors(mods) {
  const { bcp, config } = mods;
  const SECRET = 'oauth-vector-secret-0123456789abcdef0123456789abcdef';
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const other = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rsaJwk = Object.assign(rsa.publicKey.export({ format: 'jwk' }),
                               { kid: 'rsa-1', use: 'sig' });
  const ecJwk = Object.assign(ec.publicKey.export({ format: 'jwk' }),
                              { kid: 'ec-1' });
  const jwks = JSON.stringify({ keys: [rsaJwk, ecJwk] });
  const BASE = 'https://as.vectors.example';
  const audiences = [BASE + '/oauth2/token', BASE, BASE];
  const now = function () {
    return Math.floor(Date.now() / 1000);
  };
  const assertion = function (o) {
    const claims = Object.assign({ iss: o.iss || 'c-pkjwt',
      sub: o.sub === undefined ? (o.iss || 'c-pkjwt') : o.sub,
      aud: o.aud || BASE + '/oauth2/token',
      jti: o.jti === undefined ? nodeCrypto.randomUUID() : o.jti,
      iat: now(), exp: now() + (o.life || 60) }, o.extra || {});
    if (o.noExp) {
      delete claims.exp;
    }
    if (o.noJti) {
      delete claims.jti;
    }
    return signJws(Object.assign({ alg: o.alg, typ: 'JWT' },
                                 o.kid ? { kid: o.kid } : {}),
                   claims, o.key, o.alg);
  };
  const client = function (id, method, extra) {
    return Object.assign({ known: true, client_id: id, identifier: id,
                           token_endpoint_auth_method: method }, extra || {});
  };
  const basic = function (id, secret) {
    return 'Basic ' + Buffer.from(encodeURIComponent(id) + ':' +
                                  encodeURIComponent(secret))
      .toString('base64');
  };
  const replayed = assertion({ alg: 'ES256', key: ec.privateKey,
                               kid: 'ec-1' });
  const CASES = [
    { name: 'secret_basic, good', registered: client('c-basic',
        'client_secret_basic', { client_secret: SECRET }),
      clientSecret: SECRET, headers: { authorization: basic('c-basic',
                                                              SECRET) } },
    { name: 'secret_basic, wrong', registered: client('c-basic',
        'client_secret_basic', { client_secret: SECRET }),
      clientSecret: 'nope', headers: { authorization: basic('c-basic',
                                                              'nope') } },
    { name: 'secret_basic, none presented', registered: client('c-basic',
        'client_secret_basic', { client_secret: SECRET }) },
    { name: 'secret_post, good', registered: client('c-post',
        'client_secret_post', { client_secret: SECRET }),
      clientSecret: SECRET },
    { name: 'two methods, basic chosen', registered: client('c-two',
        'client_secret_basic', { client_secret: SECRET,
          token_endpoint_auth_methods: ['client_secret_post',
                                        'client_secret_basic'] }),
      clientSecret: 'nope', headers: { authorization: basic('c-two',
                                                              'nope') } },
    { name: 'two methods, none presented', registered: client('c-two',
        'client_secret_basic', { client_secret: SECRET,
          token_endpoint_auth_methods: ['client_secret_post',
                                        'client_secret_basic'] }) },
    { name: 'public', registered: client('c-pub', 'none') },
    { name: 'no method declared', registered: client('c-undeclared', '') },
    { name: 'unknown client', registered: { known: false } },
    { name: 'confidential, nothing on file',
      registered: client('c-empty', 'private_key_jwt') },
    { name: 'secret_jwt, good', registered: client('c-sjwt',
        'client_secret_jwt', { client_secret: SECRET }),
      assertion: assertion({ iss: 'c-sjwt', alg: 'HS256', key: SECRET }) },
    { name: 'secret_jwt, RS256', registered: client('c-sjwt',
        'client_secret_jwt', { client_secret: SECRET }),
      assertion: assertion({ iss: 'c-sjwt', alg: 'RS256',
                             key: rsa.privateKey }) },
    { name: 'secret_jwt, wrong secret', registered: client('c-sjwt',
        'client_secret_jwt', { client_secret: SECRET }),
      assertion: assertion({ iss: 'c-sjwt', alg: 'HS256',
                             key: SECRET + 'x' }) },
    { name: 'pkjwt, RS256', registered: client('c-pkjwt', 'private_key_jwt',
        { jwks: jwks }),
      assertion: assertion({ alg: 'RS256', key: rsa.privateKey,
                             kid: 'rsa-1' }) },
    { name: 'pkjwt, PS256', registered: client('c-pkjwt', 'private_key_jwt',
        { jwks: jwks }),
      assertion: assertion({ alg: 'PS256', key: rsa.privateKey }) },
    { name: 'pkjwt, ES256', registered: client('c-pkjwt', 'private_key_jwt',
        { jwks: jwks }), assertion: replayed },
    { name: 'pkjwt, ES256 replayed', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }), assertion: replayed },
    { name: 'pkjwt, HS256 refused', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }),
      assertion: assertion({ alg: 'HS256', key: 'x'.repeat(40) }) },
    { name: 'pkjwt, another key', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }),
      assertion: assertion({ alg: 'ES256', key: other.privateKey }) },
    { name: 'pkjwt, wrong audience', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }),
      assertion: assertion({ alg: 'ES256', key: ec.privateKey,
                             aud: 'https://elsewhere.example' }) },
    { name: 'pkjwt, expired', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }),
      assertion: assertion({ alg: 'ES256', key: ec.privateKey,
                             life: -600 }) },
    { name: 'pkjwt, sub differs', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }),
      assertion: assertion({ alg: 'ES256', key: ec.privateKey,
                             sub: 'somebody' }) },
    { name: 'pkjwt, no jti', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }),
      assertion: assertion({ alg: 'ES256', key: ec.privateKey,
                             noJti: true }) },
    { name: 'pkjwt, no exp', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }),
      assertion: assertion({ alg: 'ES256', key: ec.privateKey,
                             noExp: true }) },
    { name: 'pkjwt, wrong type', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }), assertionType: 'urn:x',
      assertion: assertion({ alg: 'ES256', key: ec.privateKey }) },
    { name: 'pkjwt, none presented', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }) },
    { name: 'pkjwt, a JWKS that is not JSON', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: '{not json' }),
      assertion: assertion({ alg: 'ES256', key: ec.privateKey }) },
    { name: 'pkjwt, strict audience', registered: client('c-pkjwt',
        'private_key_jwt', { jwks: jwks }), strictAudience: BASE,
      assertion: assertion({ alg: 'ES256', key: ec.privateKey }) },
    { name: 'tls_client_auth, no certificate', registered: client('c-tls',
        'tls_client_auth', { tls_client_auth_subject_dn: 'CN=x' }) },
    { name: 'self-signed tls, no certificate', registered: client('c-sstls',
        'self_signed_tls_client_auth', { certificate_thumbprint: 'abc' }) }
  ];
  const out = [];
  for (const mode of ['development', 'product']) {
    config.setOverride('global.mode', mode);
    for (const c of CASES) {
      const fields = { clientId: String(c.registered.client_id || ''),
        clientSecret: c.clientSecret, assertion: c.assertion,
        assertionType: c.assertion
          ? (c.assertionType || ('urn:ietf:params:oauth:client-assertion-' +
                                 'type:jwt-bearer')) : undefined,
        audiences: audiences, strictAudience: c.strictAudience || '',
        issuer: BASE, registered: c.registered };
      const nowMs = Date.now();
      const observed = await bcp.observeClientAuthentication(Object.assign(
        { request: requestWith(c.headers) }, fields));
      const checked = await bcp.checkClientAuthentication(Object.assign(
        { request: requestWith(c.headers) }, fields));
      out.push({ name: c.name, mode: mode, nowMs: nowMs,
                 bcpEnabled: bcp.enabled(),
                 input: clone(Object.assign({ headers: c.headers || {} },
                                            fields)),
                 observed: clone(observed), checked: clone(checked) });
    }
    config.setOverride('oauth2.rfc9700', true);
    for (const c of CASES.slice(0, 3)) {
      const fields = { clientId: String(c.registered.client_id || ''),
        clientSecret: c.clientSecret, audiences: audiences,
        strictAudience: '', issuer: BASE, registered: c.registered };
      const checked = await bcp.checkClientAuthentication(Object.assign(
        { request: requestWith(c.headers) }, fields));
      out.push({ name: c.name + ' (RFC 9700 mode)', mode: mode,
                 nowMs: Date.now(), bcpEnabled: bcp.enabled(),
                 input: clone(Object.assign({ headers: c.headers || {} },
                                            fields)),
                 observed: null, checked: clone(checked) });
    }
    config.clearOverride('oauth2.rfc9700');
  }
  config.clearOverride('global.mode');
  return out;
}

// The model's request validators, over inputs as Express parses them
// (`qs`: a repeated name is an array, `a[b]=c` an object).
function validationVectors(ROOT) {
  const validation = require(path.join(ROOT, 'common', 'validation'));
  const OAuthModel = require(path.join(ROOT, 'oauth-oidc', 'oauth_model'));
  const V = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const authorize = [
    {}, { client_id: 'a', response_type: 'code', extra: 'kept' },
    { client_id: 'a b' }, { client_id: '' }, { client_id: 'x'.repeat(257) },
    { client_id: ['a', 'b'] }, { scope: { a: 'b' } }, { state: 'a\nb' },
    { scope: 'openid "x"' }, { scope: 'openid  profile' }, { scope: '' },
    { code_challenge: 'abc' }, { code_challenge: V }, { code_challenge: '' },
    { max_age: 'soon' }, { max_age: '-1' }, { max_age: '1.5' },
    { max_age: '30' }, { max_age: '' }, { max_age: '400000000' },
    { domain_hint: 'a b' }, { response_mode: 'x'.repeat(65) },
    { redirect_uri: 'https://rp.example/cb' },
    { redirect_uri: 'https://rp.example/cb#frag' },
    { redirect_uri: 'rp.example/cb' }, { redirect_uri: 'myapp:/cb' },
    { redirect_uri: 'com.example.app:/cb' }, { redirect_uri: 'http:///x' },
    { resource: 'javascript:alert(1)' },
    { resource: ['https://a.example', 'https://b.example'] },
    { resource: ['https://a.example', 'data:x'] },
    { dpop_jkt: 'a=b' }, { login_hint: 'Ann Lee' },
    { __proto__: null, constructor: 'x' },
    { claim: ['a', 'b'] }, { claim: 'one' }
  ];
  const token = [
    { grant_type: 'authorization_code', code: 'c', code_verifier: V },
    { code_verifier: 'short' }, { client_id: 'x'.repeat(257) },
    { scope: 'openid "x"' }, { refresh_token: '' }, { code: '' },
    { client_assertion_type: 'nope' }, { state: 'a\nb' },
    { password: 'line\nbreak' }, { grant_type: 'x', unknown: 'kept' },
    { grant_type: ['a', 'b'] }, { resource: 'https://a.example' }
  ];
  const run = function (id, where, inputs) {
    return inputs.map(function (input) {
      const answer = validation.checkParsed(input, where,
                                            OAuthModel.request(id));
      return { id: id, where: where, input: clone(input),
               keys: Object.keys(input),
               answer: clone(answer) };
    });
  };
  return run('authorize', 'query', authorize)
    .concat(run('token', 'body', token));
}

// A form POST, as a client sends one.
function post(port, urlPath, form, headers) {
  return new Promise(function (resolve) {
    const body = new URLSearchParams(form).toString();
    const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
      method: 'POST', headers: Object.assign({
        'content-type': 'application/x-www-form-urlencoded',
        'content-length': Buffer.byteLength(body) }, headers || {}) },
    function (res) {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', function (c) {
        text += c;
      });
      res.on('end', function () {
        resolve({ status: res.statusCode, headers: res.headers, text: text });
      });
    });
    req.on('error', function (e) {
      resolve({ status: 0, headers: {}, text: String(e && e.message) });
    });
    req.end(body);
  });
}

function decoded(jwt) {
  const parts = String(jwt || '').split('.');
  if (parts.length !== 3) {
    return null;
  }
  return { header: JSON.parse(Buffer.from(parts[0], 'base64url')),
           claims: JSON.parse(Buffer.from(parts[1], 'base64url')) };
}

// THE TOKEN ENDPOINT over HTTP: the client credentials grant with each
// client authentication method, and the refusals before any grant, in a
// development realm and a product one.
async function tokenVectors(ROOT, port, mods) {
  const { realms, helpers } = mods;
  const applications = require(path.join(ROOT, 'common', 'applications'));
  const SECRET = 'oauth-vector-token-secret-0123456789abcdef0123456789ab';
  const ec = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ecJwk = Object.assign(ec.publicKey.export({ format: 'jwk' }),
                              { kid: 'tk-ec' });
  const out = [];
  for (const realmMode of ['development', 'product']) {
    const id = 'tok' + realmMode.slice(0, 3);
    const made = realms.create({ id: id, name: id,
      description: 'oauth-vectors.js',
      overrides: realmMode === 'product' ? { 'global.mode': 'product' }
        : {} });
    if (!made.ok) {
      out.push({ name: '(realm refused)', problem: JSON.stringify(made) });
    }
    const realm = realms.get(id);
    const clients = {};
    realms.run(realm, function () {
      const make = function (cid, fields) {
        applications.createApplication({ identifier: cid,
          protocols: ['oauth2'],
          fields: Object.assign({ oauthClientId: cid,
            oauthRedirectUri: ['https://rp.vectors.example/cb'],
            oauthGrantType: ['client_credentials', 'authorization_code',
                             'refresh_token'] }, fields) });
      };
      make('tk-basic', { oauthClientSecret: SECRET,
                         oauthTokenEndpointAuthMethod: 'client_secret_basic' });
      make('tk-post', { oauthClientSecret: SECRET,
                        oauthTokenEndpointAuthMethod: 'client_secret_post' });
      make('tk-pkjwt', { oauthJwks: JSON.stringify({ keys: [ecJwk] }),
                         oauthTokenEndpointAuthMethod: 'private_key_jwt' });
      make('tk-public', { oauthTokenEndpointAuthMethod: 'none' });
      ['tk-basic', 'tk-post', 'tk-pkjwt', 'tk-public', 'tk-nobody']
        .forEach(function (cid) {
          clients[cid] = clone(applications.clientConfigOf(cid));
          clients[cid + ':flows'] = clone(applications.declaredFlowsOf(cid));
        });
    });
    const P = '/realm/' + id;
    const BASE = 'http://127.0.0.1:' + port + P;
    const basic = function (cid, secret) {
      return 'Basic ' + Buffer.from(cid + ':' + secret).toString('base64');
    };
    const assertion = function () {
      const now = Math.floor(Date.now() / 1000);
      return signJws({ alg: 'ES256', typ: 'JWT', kid: 'tk-ec' },
        { iss: 'tk-pkjwt', sub: 'tk-pkjwt', aud: BASE + '/oauth2/token',
          jti: nodeCrypto.randomUUID(), iat: now, exp: now + 60 },
        ec.privateKey, 'ES256');
    };
    const CASES = [
      { name: 'cc, basic', form: { grant_type: 'client_credentials' },
        headers: { authorization: basic('tk-basic', SECRET) } },
      { name: 'cc, basic, a scope',
        form: { grant_type: 'client_credentials', scope: 'read write' },
        headers: { authorization: basic('tk-basic', SECRET) } },
      { name: 'cc, post', form: { grant_type: 'client_credentials',
          client_id: 'tk-post', client_secret: SECRET } },
      { name: 'cc, private_key_jwt', form: function () {
        return { grant_type: 'client_credentials',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-' +
            'type:jwt-bearer', client_assertion: assertion() };
      } },
      { name: 'cc, wrong secret', form: { grant_type: 'client_credentials' },
        headers: { authorization: basic('tk-basic', 'nope') } },
      { name: 'cc, public client', form: { grant_type: 'client_credentials',
          client_id: 'tk-public' } },
      { name: 'cc, unknown client', form: { grant_type: 'client_credentials',
          client_id: 'tk-nobody', client_secret: 'x' } },
      { name: 'no grant_type', form: { client_id: 'tk-post',
          client_secret: SECRET } },
      { name: 'an unknown grant_type', form: { grant_type: 'urn:nope',
          client_id: 'tk-post', client_secret: SECRET } },
      { name: 'a malformed scope', form: { grant_type: 'client_credentials',
          client_id: 'tk-post', client_secret: SECRET, scope: 'a "b"' } },
      { name: 'the password grant', form: { grant_type: 'password',
          client_id: 'tk-post', client_secret: SECRET, username: 'u',
          password: 'p' } }
    ];
    for (const c of CASES) {
      const form = typeof c.form === 'function' ? c.form() : c.form;
      const nowMs = Date.now();
      const r = await post(port, P + '/oauth2/token', form, c.headers);
      let body = r.text;
      try {
        body = JSON.parse(r.text);
      } catch (e) {
        body = r.text;
      }
      const kept = {};
      ['content-type', 'cache-control', 'www-authenticate', 'pragma']
        .forEach(function (h) {
          if (r.headers[h] !== undefined) {
            kept[h] = r.headers[h];
          }
        });
      out.push({ name: c.name, realm: id, mode: realmMode, nowMs: nowMs,
                 base: BASE, form: form, headers: c.headers || {},
                 status: r.status, responseHeaders: kept, body: body,
                 accessToken: body && body.access_token
                   ? decoded(body.access_token) : null });
    }
    await realms.run(realm, async function () {
      // A refresh token Node seals, for Rust to open.
      const crypto = require(path.join(ROOT, 'oauth-oidc',
                                       'refresh_token_crypto'));
      const jws = signJws({ alg: 'ES256', typ: 'JWT' },
                          { typ: 'Refresh', jti: 'rt-' + id },
                          ec.privateKey, 'ES256');
      out.push({ name: '(the realm)', realm: id, mode: realmMode,
                 clients: clients,
                 blob: clone(mods.keystore.serialise(helpers.stsKeysFor())),
                 refresh: { jws: jws, sealed: crypto.seal(jws) } });
    });
  }
  return out;
}

// A GET, as a browser sends one.
function getWith(port, urlPath, headers) {
  return new Promise(function (resolve) {
    http.get({ host: '127.0.0.1', port: port, path: urlPath,
               headers: headers || {} },
      function (res) {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          resolve({ status: res.statusCode, headers: res.headers,
                    text: text });
        });
      }).on('error', function (e) {
      resolve({ status: 0, headers: {}, text: String(e && e.message) });
    });
  });
}

// A DPoP proof (RFC 9449 section 4.2) by the key `pair`.
function dpopProof(pair, htu, nonce) {
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const claims = { jti: nodeCrypto.randomUUID(), htm: 'POST', htu: htu,
                   iat: Math.floor(Date.now() / 1000) };
  if (nonce) {
    claims.nonce = nonce;
  }
  return signJws({ typ: 'dpop+jwt', alg: 'ES256',
                   jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } },
                 claims, pair.privateKey, 'ES256');
}

// THE CODE FLOW (#444 phase 5, the `oauth2` slice): the authorization
// endpoint answered with and without a session, each code's stored record
// and each pending sign-in, then the code and refresh grants with DPoP —
// in a development realm and a product one, with the session row, the
// clients and the person as Node held them.
async function codeVectors(ROOT, port, mods) {
  const { realms, helpers } = mods;
  const applications = require(path.join(ROOT, 'common', 'applications'));
  const ldap = require(path.join(ROOT, 'ldap', 'ldap_server'));
  const authnModule = require(path.join(ROOT, 'authn', 'authn'));
  const stsCrypto = require(path.join(ROOT, 'common', 'crypto'));
  const SECRET = 'oauth-vector-code-secret-0123456789abcdef0123456789ab';
  const REDIRECT = 'https://rp.vectors.example/cb';
  const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const CHALLENGE = nodeCrypto.createHash('sha256').update(VERIFIER)
    .digest('base64url');
  // A browser's user agent: product mode's risk engine ends the sessions
  // of an automated client (STS-RISK-0016).
  const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36';
  const out = [];
  for (const realmMode of ['development', 'product']) {
    const id = 'code' + realmMode.slice(0, 3);
    // A public client is asked consent every time in product
    // (`oauth2.consentAlwaysForPublicClients`), which is the consent
    // screen's; the product realm turns that off so the code is issued.
    realms.create({ id: id, name: id, description: 'oauth-vectors.js',
      overrides: realmMode === 'product'
        ? { 'global.mode': 'product',
            'oauth2.consentAlwaysForPublicClients': false } : {} });
    const realm = realms.get(id);
    const P = '/realm/' + id;
    const BASE = 'http://127.0.0.1:' + port + P;
    const facts = {};
    let cookie = '';
    let session = null;
    let user = null;
    realms.run(realm, function () {
      ldap.createUser('vec-ann', { attributes: { cn: 'Ann Vector',
        sn: 'Vector', givenName: 'Ann', mail: 'ann@vectors.example' } });
      const make = function (cid, fields) {
        applications.createApplication({ identifier: cid,
          protocols: ['oauth2', 'oidc'], registeredBy: 'oauth-vectors.js',
          fields: Object.assign({ oauthClientId: cid,
            oauthRedirectUri: [REDIRECT],
            oauthGrantType: ['authorization_code', 'refresh_token'],
            oauthGlobalConsent: ['openid', 'offline_access', 'read'],
            oauthAllowedScope: ['openid', 'offline_access', 'read'] },
            fields) });
      };
      make('cf-pub', { oauthTokenEndpointAuthMethod: 'none' });
      make('cf-conf', { oauthClientSecret: SECRET,
                        oauthTokenEndpointAuthMethod: 'client_secret_basic' });
      make('cf-ask', { oauthTokenEndpointAuthMethod: 'none',
                       oauthGlobalConsent: [] });
      make('cf-norefresh', { oauthTokenEndpointAuthMethod: 'none',
                             oauthGrantType: ['authorization_code'] });
      ['cf-pub', 'cf-conf', 'cf-ask', 'cf-norefresh', 'cf-nobody']
        .forEach(function (cid) {
          facts[cid] = {
            config: clone(applications.clientConfigOf(cid)),
            flows: clone(applications.declaredFlowsOf(cid)),
            allowedScopes: clone(applications.allowedScopesOf(cid)),
            globalConsents: clone(require(path.join(ROOT, 'common',
              'consent')).globalConsentsOf(cid)),
            entry: clone(applications.get(cid))
          };
        });
      const req0 = { headers: { 'user-agent': UA }, body: {},
                     method: 'GET', url: '/' };
      const res0 = { cookies: [], locals: {}, req: req0,
        set: function (k, v) {
          if (String(k).toLowerCase() === 'set-cookie') {
            this.cookies = [].concat(v);
          }
        },
        append: function (k, v) {
          if (String(k).toLowerCase() === 'set-cookie') {
            this.cookies = this.cookies.concat(v);
          }
        },
        getHeader: function () {
          return this.cookies;
        } };
      session = authnModule.startSession(res0, 'vec-ann', ['pwd'], null,
                                         'OAuth 2.0 / OIDC',
                                         { request: req0 });
      const line = res0.cookies.filter(function (l) {
        return /^sts_session=/.test(l);
      }).pop() || '';
      cookie = line.split(';')[0];
      user = clone(helpers.userFor('vec-ann'));
    });
    const handle = function (name) {
      return realms.handleFor(name).partition(id);
    };
    const sessionRow = clone(handle('authn.sessions').get(session.id));
    out.push({ name: '(the realm)', realm: id, mode: realmMode, base: BASE,
               facts: facts, cookie: cookie, session: sessionRow,
               sessionId: session.id, user: user,
               blob: clone(mods.keystore.serialise(
                 realms.run(realm, function () {
                   return helpers.stsKeysFor();
                 }))) });
    const authorize = function (params) {
      return P + '/oauth2/authorize?' + new URLSearchParams(params)
        .toString();
    };
    const pkce = { response_type: 'code', redirect_uri: REDIRECT,
                   scope: 'openid read', state: 'st-1', nonce: 'n-1',
                   code_challenge: CHALLENGE, code_challenge_method: 'S256' };
    const CASES = [
      { name: 'code, a session', query: Object.assign({ client_id: 'cf-pub' },
                                                      pkce) },
      { name: 'code, fragment', query: Object.assign({ client_id: 'cf-pub',
          response_mode: 'fragment' }, pkce) },
      { name: 'code, form_post', query: Object.assign({ client_id: 'cf-pub',
          response_mode: 'form_post' }, pkce) },
      { name: 'code, a resource', query: Object.assign({ client_id: 'cf-pub',
          resource: BASE + '/resource' }, pkce) },
      { name: 'code, offline_access', query: Object.assign({
          client_id: 'cf-pub' }, pkce, { scope: 'openid offline_access' }) },
      { name: 'code, confidential, no PKCE', query: { client_id: 'cf-conf',
          response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
          state: 'st-2' } },
      { name: 'code, public, no PKCE', query: { client_id: 'cf-pub',
          response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
          state: 'st-3' } },
      { name: 'code, plain PKCE', query: Object.assign({ client_id: 'cf-pub' },
          pkce, { code_challenge_method: 'plain', code_challenge: VERIFIER }) },
      { name: 'no session', cookie: '', query: Object.assign({
          client_id: 'cf-pub' }, pkce) },
      { name: 'no session, prompt=none', cookie: '', query: Object.assign({
          client_id: 'cf-pub', prompt: 'none' }, pkce) },
      { name: 'prompt=login', query: Object.assign({ client_id: 'cf-pub',
          prompt: 'login' }, pkce) },
      { name: 'an unregistered redirect_uri', query: Object.assign({
          client_id: 'cf-pub' }, pkce,
          { redirect_uri: 'https://elsewhere.example/cb' }) },
      { name: 'an unknown client', query: Object.assign({
          client_id: 'cf-nobody' }, pkce) },
      { name: 'no client_id', query: Object.assign({}, pkce) },
      { name: 'response_type token', query: Object.assign({
          client_id: 'cf-pub' }, pkce, { response_type: 'token' }) },
      { name: 'no response_type', query: Object.assign({
          client_id: 'cf-pub' }, pkce, { response_type: '' }) },
      { name: 'a protected scope', query: Object.assign({
          client_id: 'cf-pub' }, pkce, { scope: 'openid admin:read' }) },
      { name: 'consent needed', query: Object.assign({ client_id: 'cf-ask' },
          pkce) },
      { name: 'consent needed, prompt=none', query: Object.assign({
          client_id: 'cf-ask', prompt: 'none' }, pkce) },
      { name: 'an unregistered resource', query: Object.assign({
          client_id: 'cf-pub', resource: 'https://nobody.example/api' },
          pkce) },
      { name: 'a malformed query', query: Object.assign({
          client_id: 'cf-pub' }, pkce, { state: 'a\nb' }) },
      { name: 'code, no refresh grant', query: Object.assign({
          client_id: 'cf-norefresh' }, pkce) }
    ];
    const codes = {};
    for (const c of CASES) {
      const nowMs = Date.now();
      const sent = c.cookie === undefined ? cookie : c.cookie;
      const r = await getWith(port, authorize(c.query),
        Object.assign({ accept: 'application/json',
                        'user-agent': UA },
                      sent ? { cookie: sent } : {}));
      const location = String(r.headers.location || '');
      let code = '';
      let record = null;
      let pending = null;
      const found = /[?&#]code=([^&]+)/.exec(location) ||
        /name="code" value="([^"]+)"/.exec(r.text);
      if (found) {
        code = decodeURIComponent(found[1]);
        record = clone(handle('oauth2.authzCodes')
          .get(stsCrypto.credentialDigest(code)));
        codes[c.name] = { code: code, record: record };
      }
      const authnId = /[?&]authn=([^&]+)/.exec(location);
      if (authnId) {
        pending = clone(handle('authn.pending')
          .get(decodeURIComponent(authnId[1])));
      }
      out.push({ kind: 'authorize', name: c.name, realm: id, mode: realmMode,
                 nowMs: nowMs, base: BASE, query: c.query,
                 cookie: sent || '', status: r.status,
                 location: location,
                 contentType: r.headers['content-type'] || '',
                 csp: r.headers['content-security-policy'] || '',
                 body: /json/.test(String(r.headers['content-type'] || ''))
                   ? JSON.parse(r.text) : r.text,
                 code: code, record: record, pending: pending });
    }
    // THE TOKEN ENDPOINT: each code redeemed with a DPoP proof, then the
    // refresh, then the replays.
    const pair = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const htu = BASE + '/oauth2/token';
    const token = async function (name, form, headers, more) {
      const nowMs = Date.now();
      const r = await post(port, P + '/oauth2/token', form, headers);
      let body = r.text;
      try {
        body = JSON.parse(r.text);
      } catch (e) {
        body = r.text;
      }
      const row = Object.assign({ kind: 'token', name: name, realm: id,
        mode: realmMode, nowMs: nowMs, base: BASE, form: form,
        headers: headers || {}, status: r.status,
        responseHeaders: { 'content-type': r.headers['content-type'],
                           'cache-control': r.headers['cache-control'],
                           'dpop-nonce': r.headers['dpop-nonce'] },
        body: body,
        accessToken: body && body.access_token ? decoded(body.access_token)
          : null,
        idToken: body && body.id_token ? decoded(body.id_token) : null },
        more || {});
      if (body && body.refresh_token) {
        row.refreshClaims = realms.run(realm, function () {
          const opened = require(path.join(ROOT, 'oauth-oidc',
            'refresh_token_crypto')).open(body.refresh_token);
          return JSON.parse(Buffer.from(opened.split('.')[1], 'base64url'));
        });
      }
      out.push(row);
      return body;
    };
    const redeem = function (caseName, client, extra, headers) {
      const held = codes[caseName];
      const form = Object.assign({ grant_type: 'authorization_code',
        code: held ? held.code : 'nope', redirect_uri: REDIRECT,
        client_id: client, code_verifier: VERIFIER }, extra || {});
      Object.keys(form).forEach(function (k) {
        if (form[k] === undefined) {
          delete form[k];
        }
      });
      return form;
    };
    const first = await token('redeem, DPoP',
      redeem('code, a session', 'cf-pub'), { dpop: dpopProof(pair, htu) },
      { codeRecord: (codes['code, a session'] || {}).record });
    await token('redeem, no DPoP (public console rule absent)',
      redeem('code, fragment', 'cf-pub'), {},
      { codeRecord: (codes['code, fragment'] || {}).record });
    await token('redeem, wrong verifier',
      redeem('code, form_post', 'cf-pub', { code_verifier: 'x'.repeat(43) }),
      { dpop: dpopProof(pair, htu) },
      { codeRecord: (codes['code, form_post'] || {}).record });
    await token('redeem, a resource',
      redeem('code, a resource', 'cf-pub', { resource: BASE + '/resource' }),
      { dpop: dpopProof(pair, htu) },
      { codeRecord: (codes['code, a resource'] || {}).record });
    await token('redeem, offline_access',
      redeem('code, offline_access', 'cf-pub'),
      { dpop: dpopProof(pair, htu) },
      { codeRecord: (codes['code, offline_access'] || {}).record });
    await token('redeem, confidential',
      redeem('code, confidential, no PKCE', 'cf-conf',
             { code_verifier: undefined }),
      { authorization: 'Basic ' + Buffer.from('cf-conf:' + SECRET)
          .toString('base64') },
      { codeRecord: (codes['code, confidential, no PKCE'] || {}).record });
    await token('redeem, no refresh grant',
      redeem('code, no refresh grant', 'cf-norefresh'),
      { dpop: dpopProof(pair, htu) },
      { codeRecord: (codes['code, no refresh grant'] || {}).record });
    await token('redeem, an unknown code',
      redeem('(none)', 'cf-pub'), { dpop: dpopProof(pair, htu) });
    await token('a malformed DPoP proof', redeem('(none)', 'cf-pub'),
      { dpop: 'not.a.proof' });
    if (first && first.refresh_token) {
      const rt = first.refresh_token;
      const refreshed = await token('refresh, DPoP',
        { grant_type: 'refresh_token', refresh_token: rt,
          client_id: 'cf-pub' }, { dpop: dpopProof(pair, htu) },
        { presented: rt });
      await token('refresh, no proof',
        { grant_type: 'refresh_token',
          refresh_token: (refreshed && refreshed.refresh_token) || rt,
          client_id: 'cf-pub' }, {},
        { presented: (refreshed && refreshed.refresh_token) || rt });
      await token('refresh, another key',
        { grant_type: 'refresh_token',
          refresh_token: (refreshed && refreshed.refresh_token) || rt,
          client_id: 'cf-pub' },
        { dpop: dpopProof(nodeCrypto.generateKeyPairSync('ec',
          { namedCurve: 'P-256' }), htu) },
        { presented: (refreshed && refreshed.refresh_token) || rt });
      await token('refresh, a wider scope',
        { grant_type: 'refresh_token',
          refresh_token: (refreshed && refreshed.refresh_token) || rt,
          client_id: 'cf-pub', scope: 'openid read write' },
        { dpop: dpopProof(pair, htu) },
        { presented: (refreshed && refreshed.refresh_token) || rt });
      await token('refresh, the rotated one (a replay)',
        { grant_type: 'refresh_token', refresh_token: rt,
          client_id: 'cf-pub' }, { dpop: dpopProof(pair, htu) },
        { presented: rt });
      await token('redeem again (a replay)',
        redeem('code, a session', 'cf-pub'), { dpop: dpopProof(pair, htu) });
      await token('refresh after the code replay',
        { grant_type: 'refresh_token',
          refresh_token: (refreshed && refreshed.refresh_token) || rt,
          client_id: 'cf-pub' }, { dpop: dpopProof(pair, htu) },
        { presented: (refreshed && refreshed.refresh_token) || rt });
      await token('refresh, garbage',
        { grant_type: 'refresh_token', refresh_token: 'garbage',
          client_id: 'cf-pub' }, { dpop: dpopProof(pair, htu) });
    }
    // THE DISCOVERY DOCUMENTS.
    for (const doc of ['/.well-known/oauth-authorization-server',
                       '/.well-known/openid-configuration']) {
      const r = await getWith(port, P + doc, {});
      let body = r.text;
      try {
        body = JSON.parse(r.text);
      } catch (e) {
        body = r.text;
      }
      out.push({ kind: 'metadata', name: doc, realm: id, mode: realmMode,
                 base: BASE, status: r.status,
                 cacheControl: r.headers['cache-control'] || '',
                 contentType: r.headers['content-type'] || '', body: body });
    }
  }
  return out;
}

async function build(ROOT) {
  require(path.join(ROOT, 'common', 'protocol_stack'));
  const app = require(path.join(ROOT, 'common', 'app'));
  const mods = {
    config: require(path.join(ROOT, 'common', 'config')),
    realms: require(path.join(ROOT, 'common', 'realms')),
    helpers: require(path.join(ROOT, 'common', 'helpers')),
    keystore: require(path.join(ROOT, 'common', 'keystore')),
    pki: require(path.join(ROOT, 'common', 'pki')),
    oauth21: require(path.join(ROOT, 'oauth-oidc', 'oauth21')),
    bcp: require(path.join(ROOT, 'oauth-oidc', 'oauth2_bcp'))
  };
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const out = { problems: [] };
  mods.config.setOverride('realms.maxCount', 64);
  try {
    out.sanitize = sanitizeVectors(mods.oauth21);
    out.validation = validationVectors(ROOT);
    out.clientAuth = await clientAuthVectors(mods);
    out.jwks = await jwksVectors(ROOT, port, mods);
    out.token = await tokenVectors(ROOT, port, mods);
    out.code = await codeVectors(ROOT, port, mods);
  } catch (e) {
    out.problems.push(String((e && e.stack) || e));
  }
  server.close();
  return out;
}

// THE OTHER DIRECTION: what Rust wrote (`oauth-rust.json`), read by Node —
// a refresh token Rust sealed opens under Node's refresh_token_crypto.ts
// with the same stored key set, and an access token Rust signed verifies
// under the set's certificate with Node's verifier.
function checkRust(ROOT, rows, check) {
  const keystore = require(path.join(ROOT, 'common', 'keystore'));
  const stsCrypto = require(path.join(ROOT, 'common', 'crypto'));
  const crypto = require(path.join(ROOT, 'oauth-oidc', 'refresh_token_crypto'));
  (rows.realms || []).forEach(function (row) {
    const keys = keystore.deserialise(row.blob);
    let opened = '';
    try {
      opened = crypto.open(row.sealed, keys);
    } catch (e) {
      opened = 'refused: ' + e.message;
    }
    check(opened === row.jws, 'oauth: Node opens the refresh token Rust ' +
          'sealed in ' + row.realm, opened);
    let claims = null;
    try {
      claims = stsCrypto.verifyJws(row.accessToken, row.blob.certPem,
                                   { algorithms: ['RS256'] });
    } catch (e) {
      claims = { refused: e.message };
    }
    check(!!claims && claims.jti === row.claims.jti &&
          claims.typ === 'Bearer', 'oauth: Node verifies the access token ' +
          'Rust signed in ' + row.realm, JSON.stringify(claims));
  });
}

module.exports = { build: build, checkRust: checkRust };
