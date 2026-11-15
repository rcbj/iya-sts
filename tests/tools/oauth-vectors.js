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
  try {
    out.sanitize = sanitizeVectors(mods.oauth21);
    out.clientAuth = await clientAuthVectors(mods);
    out.jwks = await jwksVectors(ROOT, port, mods);
  } catch (e) {
    out.problems.push(String((e && e.stack) || e));
  }
  server.close();
  return out;
}

module.exports = { build: build };
