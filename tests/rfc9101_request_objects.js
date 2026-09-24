'use strict';
//
// File: rfc9101_request_objects.js
//
// ===========================================================================
// RFC 9101 — THE JWT-SECURED AUTHORIZATION REQUEST, AND OPENID CONNECT CORE
// SECTION 6's REQUEST OBJECT, EVERY FEATURE, POSITIVE AND NEGATIVE
// (2026-09-13).
//
// `oauth-oidc/request_object.ts` argues the design. What is held here:
//
//   1. THE LIBRARY: the `typ` rules (section 10.8, and the required-type
//      setting), the OpenID Connect section 6.2 fragment digest, the section
//      6.3 parameter assembly, and the round-trip marker that keeps `prompt`
//      from asking for ever.
//   2. THE REGISTRY'S CHECK of the five client metadata members, and the
//      realm's request object encryption keys through the keystore.
//   3. THE ENDPOINT, in a child process on an ephemeral loopback port, with a
//      SECOND listener serving request objects by reference:
//        a. a signed request object by value, all the way to a code, with the
//           query's own parameters ignored and the object's used;
//        b. every signing algorithm family (ES256, RS256, PS256, HS256), the
//           kid rule, and the signature, iss, aud, client_id, exp refusals;
//        c. unsigned objects in development, and every way they are refused;
//        d. the typ rules and both "require" settings;
//        e. require_signed_request_object from the setting, the client and a
//           named authorization server's profile;
//        f. request_uri: registered and fetched, unregistered and never
//           dialled, plain http and wrong media types by mode, errors,
//           redirects, oversize, timeout, the fragment digest and the cache;
//        g. encryption: RSA-OAEP-256 by THIS FILE's own JWE code, ECDH-ES and a
//           symmetric key, and every decryption refusal, another realm's key
//           included;
//        h. what a profile narrows, and PAR's URN;
//        i. the round trip: `prompt=login` in the object does not loop, and the
//           sign-in and consent screens say the request was vetted;
//        j. the metadata, the JWKS, registration, and the console's writes.
//
// **THE CHILD** is `tests/rfc9068_access_tokens.js`'s reason: the protocol
// stack registers every route on the shared app and builds a CA.
// **THE SIGNER AND THE RSA JWE ARE WRITTEN HERE**, for `sts_dpop.js`'s: a
// request object made by the implementation that verifies it proves only that
// the implementation agrees with itself.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'rfc9101_request_objects',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const ro = require('../oauth-oidc/request_object');
const applications = require('../common/applications');
const config = require('../common/config');

// ---------------------------------------------------------------------------
// 1. THE LIBRARY.
// ---------------------------------------------------------------------------
function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. typ, the fragment digest and the assembly ===');
  t.equal(ro.typProblem(undefined), '', '1a. no typ is accepted');
  t.equal(ro.typProblem('JWT'), '', '1b. typ JWT is accepted');
  t.equal(ro.typProblem('oauth-authz-req+jwt'), '',
          '1c. typ oauth-authz-req+jwt is accepted');
  t.equal(ro.typProblem('application/OAUTH-AUTHZ-REQ+JWT'), '',
          '1d. in any case and with the application/ prefix');
  t.check(/another kind of JWT/.test(ro.typProblem('at+jwt')) &&
          /another kind/.test(ro.typProblem('token-introspection+jwt')),
          '1e. section 10.8: a JWT typed as something else is refused');
  t.check(/requireRequestObjectType/.test(ro.typProblem('JWT', true)) &&
          /requireRequestObjectType/.test(ro.typProblem(undefined, true)) &&
          ro.typProblem('oauth-authz-req+jwt', true) === '',
          '1f. with the type required, only oauth-authz-req+jwt is accepted');

  const content = 'eyJhbGciOiJub25lIn0.eyJhIjoxfQ.';
  const digest = nodeCrypto.createHash('sha256').update(content)
    .digest('base64url');
  t.equal(ro.fragmentProblem('https://c.example/ro#' + digest, content), '',
          '1g. OIDC 6.2: a fragment that is the SHA-256 of the content passes');
  t.check(/SHA-256 of a different/.test(ro.fragmentProblem(
            'https://c.example/ro#' + digest, content + 'x')),
          '1h. and a fragment of another content is refused');
  t.equal(ro.fragmentProblem('https://c.example/ro#v2', content), '',
          '1i. a fragment that is not a digest is the client\'s own');

  const params = ro.parametersFrom({
    iss: 'app1', aud: 'https://as', exp: 1, iat: 1, nbf: 1, jti: 'j',
    request: 'x', request_uri: 'y', response_type: 'code', max_age: 300,
    claims: { userinfo: { email: null } }, resource: ['https://a', 'https://b'],
    prompt: 'login', scope: 'openid', client_id: 'app1'
  }, { authn_error: 'access_denied', scope: 'ignored', jar_prompt_honoured: '1' },
  'app1');
  t.check(!('iss' in params) && !('aud' in params) && !('exp' in params) &&
          !('jti' in params) && !('request' in params) &&
          !('request_uri' in params),
          '1j. section 6.3: JWT claims and nested request/request_uri are not ' +
          'parameters', JSON.stringify(params));
  t.check(params.max_age === '300' && params.claims ===
          '{"userinfo":{"email":null}}' && Array.isArray(params.resource) &&
          params.resource.length === 2 && params.scope === 'openid',
          '1k. a number is its text, an object its JSON, resource stays a ' +
          'list, and the query\'s scope is ignored', JSON.stringify(params));
  t.check(params.authn_error === 'access_denied' && !('prompt' in params),
          '1l. the round-trip fields come from the query, and ' +
          'jar_prompt_honoured drops the object\'s prompt');
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE REGISTRY'S CHECK AND THE KEYS.
// ---------------------------------------------------------------------------
function registry(t) {
  log.debug("Entering registry().");
  t.log.info('=== 2. client metadata and the encryption keys ===');
  const problem = applications.requestObjectMetadataProblem;
  t.equal(problem({ request_uris: ['https://c.example/ro.jwt'],
                    request_object_signing_alg: 'ES256',
                    request_object_encryption_alg: 'RSA-OAEP-256',
                    request_object_encryption_enc: 'A256GCM',
                    require_signed_request_object: true }), null,
          '2a. a complete, usable registration passes');
  t.check(/https/.test((problem({ request_uris: ['ftp://c.example/x'] }) ||
                        {}).description),
          '2b. a request_uri that is not http(s) is refused');
  t.check(/user name or password/.test((problem({ request_uris:
            ['https://u:p@c.example/x'] }) || {}).description),
          '2c. a request_uri with credentials in it is refused');
  t.check(/must be an array/.test((problem({ request_uris: 'https://x' }) ||
                                   {}).description),
          '2d. request_uris must be an array');
  t.check(/not an algorithm this service verifies/.test((problem({
            request_object_signing_alg: 'XS999' }) || {}).description),
          '2e. an unknown signing algorithm is refused');
  t.equal(problem({ request_object_signing_alg: 'none' }), null,
          '2f. development: none may be registered');
  t.check(/require_signed_request_object/.test((problem({
            request_object_signing_alg: 'none',
            require_signed_request_object: true }) || {}).description),
          '2g. but not beside require_signed_request_object');
  t.check(/without request_object_encryption_alg/.test((problem({
            request_object_encryption_enc: 'A128GCM' }) || {}).description),
          '2h. an enc without an alg is refused');
  t.check(/not an algorithm this service decrypts/.test((problem({
            request_object_encryption_alg: 'RSA1_5' }) || {}).description),
          '2i. an encryption algorithm this service does not decrypt is refused');
  t.check(/true or false/.test((problem({
            require_signed_request_object: 'yes' }) || {}).description),
          '2j. require_signed_request_object must be a boolean');
  try {
    config.setOverride('global.mode', 'product');
    t.check(/development mode only/.test((problem({
              request_uris: ['http://c.example/ro'] }) || {}).description) &&
            /product mode/.test((problem({
              request_object_signing_alg: 'none' }) || {}).description),
            '2k. product: an http request_uri and a registered none are refused');
  } finally {
    config.clearOverride('global.mode');
  }

  log.debug("Leaving registry().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINT, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.R91_ROOT;
  const OUT = process.env.R91_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }
  const b64 = function (value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  };

  // --- this file's own signer ------------------------------------------------
  function sign(alg, payload, key, header) {
    const head = Object.assign({ alg: alg }, header || {});
    const input = b64(head) + '.' + b64(payload);
    if (alg === 'none') {
      return input + '.';
    }
    const digest = 'sha' + alg.slice(2);
    let signature = null;
    if (/^HS/.test(alg)) {
      signature = crypto.createHmac(digest, key).update(input).digest();
    } else if (/^ES/.test(alg)) {
      signature = crypto.sign(digest, Buffer.from(input),
                              { key: key, dsaEncoding: 'ieee-p1363' });
    } else if (/^PS/.test(alg)) {
      signature = crypto.sign(digest, Buffer.from(input), {
        key: key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST });
    } else {
      signature = crypto.sign(digest, Buffer.from(input), key);
    }
    return input + '.' + signature.toString('base64url');
  }

  // --- this file's own JWE: RSA-OAEP-256 and A128CBC-HS256 -----------------
  function encryptRsa(plaintext, jwk, header) {
    const head = Object.assign({ alg: 'RSA-OAEP-256', enc: 'A128CBC-HS256',
                                 cty: 'JWT', kid: jwk.kid }, header || {});
    const encoded = b64(head);
    const cek = crypto.randomBytes(32);
    const publicKey = crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n,
                                                      e: jwk.e },
                                               format: 'jwk' });
    const wrapped = crypto.publicEncrypt({ key: publicKey, oaepHash: 'sha256',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, cek);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', cek.subarray(16), iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'),
                                      cipher.final()]);
    const aad = Buffer.from(encoded, 'ascii');
    const al = Buffer.alloc(8);
    al.writeBigUInt64BE(BigInt(aad.length * 8));
    const tag = crypto.createHmac('sha256', cek.subarray(0, 16))
      .update(Buffer.concat([aad, iv, ciphertext, al])).digest()
      .subarray(0, 16);
    return [encoded, wrapped.toString('base64url'), iv.toString('base64url'),
            ciphertext.toString('base64url'), tag.toString('base64url')]
      .join('.');
  }

  let jar = {};
  function cookieHeader() {
    return Object.keys(jar).map(function (k) {
      return k + '=' + jar[k];
    }).join('; ');
  }
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json)
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      if (o.cookies && Object.keys(jar).length) {
        headers.cookie = cookieHeader();
      }
      if (method !== 'GET') {
        headers['content-type'] = o.json !== undefined ? 'application/json'
          : 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        (res.headers['set-cookie'] || []).forEach(function (line) {
          const pair = line.split(';')[0];
          const eq = pair.indexOf('=');
          jar[pair.slice(0, eq)] = pair.slice(eq + 1);
        });
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const stsCrypto = require(ROOT + '/common/crypto');
    const realms = require(ROOT + '/common/realms');
    const servers = require(ROOT + '/oauth-oidc/authorization_servers');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;

    // THE REQUEST OBJECT SERVER: a second listener that plays the client's
    // own host for request_uri, counting what is fetched.
    const served = { '/ro/good': '', '/ro/plain': '', '/ro/digest': '' };
    const hits = {};
    const roServer = http.createServer(function (req, res) {
      const p = req.url;
      hits[p] = (hits[p] || 0) + 1;
      if (p === '/ro/good' || p === '/ro/digest') {
        res.writeHead(200, { 'content-type': 'application/oauth-authz-req+jwt' });
        return res.end(served[p]);
      }
      if (p === '/ro/jwt') {
        res.writeHead(200, { 'content-type': 'application/jwt' });
        return res.end(served['/ro/good']);
      }
      if (p === '/ro/plain') {
        res.writeHead(200, { 'content-type': 'text/plain' });
        return res.end(served['/ro/good']);
      }
      if (p === '/ro/missing') {
        res.writeHead(404);
        return res.end('nope');
      }
      if (p === '/ro/redirect') {
        res.writeHead(302, { location: '/ro/good' });
        return res.end();
      }
      if (p === '/ro/big') {
        res.writeHead(200, { 'content-type': 'application/oauth-authz-req+jwt' });
        return res.end(Buffer.alloc(8192, 'a'));
      }
      if (p === '/ro/slow') {
        return;
      }
      if (p === '/ro/unregistered') {
        res.writeHead(200, { 'content-type': 'application/oauth-authz-req+jwt' });
        return res.end(served['/ro/good']);
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise(function (r) { roServer.listen(0, '127.0.0.1', r); });
    const RO = 'http://127.0.0.1:' + roServer.address().port;

    // --- 2l-2n. the realm's request object encryption keys, here in the
    // child: making a key set certifies it under the realm's CA, which
    // `run.js`'s shared process must not be left holding.
    const helpers = require(ROOT + '/common/helpers');
    const keystore = require(ROOT + '/common/keystore');
    const set = helpers.stsKeysFor();
    const keys = set.requestObjectEncKeys;
    note(keys && keys.rsa.publicJwk.kty === 'RSA' &&
            keys.ec.publicJwk.kty === 'EC' && keys.rsa.publicJwk.use === 'enc' &&
            /^sts-ro-rsa-/.test(keys.rsa.publicJwk.kid) &&
            !keys.rsa.publicJwk.d && !keys.ec.publicJwk.d,
            '2l. the realm\'s key set carries an RSA and an EC request object ' +
            'encryption key, use enc, with no private member in the JWK');
    const blob = keystore.serialise(set);
    const back = keystore.deserialise(blob, crypto);
    note(blob.requestObjectEncKeys && /PRIVATE KEY/.test(
              blob.requestObjectEncKeys.rsa.privateKeyPem) &&
            back.requestObjectEncKeys.ec.publicJwk.kid === keys.ec.publicJwk.kid,
            '2m. they are written down with the set and come back from it');
    const without = Object.assign({}, blob, { requestObjectEncKeys: null });
    note(keystore.enriches(blob, without) &&
            !keystore.enriches(without, blob),
            '2n. a set gaining them enriches one without; losing them does not');

    config.setOverride('oauth2.consentRequired', false);

    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const ecJwk = Object.assign(ec.publicKey.export({ format: 'jwk' }),
                                { kid: 'r91-ec', use: 'sig' });
    const rsaJwk = Object.assign(rsa.publicKey.export({ format: 'jwk' }),
                                 { kid: 'r91-rsa', use: 'sig' });
    const SECRET = 'r91-client-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.r91.example/cb';
    const digestUri = function (content) {
      return RO + '/ro/digest#' + crypto.createHash('sha256').update(content)
        .digest('base64url');
    };
    const withoutNulls = function (all) {
      Object.keys(all).forEach(function (k) {
        if (all[k] === null) {
          delete all[k];
        }
      });
      return all;
    };
    const make = function (id, fields) {
      applications.createApplication({ identifier: id, protocols: ['oauth2'],
        fields: withoutNulls(Object.assign({ oauthClientId: id,
          oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
          oauthTokenEndpointAuthMethod: 'client_secret_basic',
          oauthJwks: JSON.stringify({ keys: [ecJwk, rsaJwk] }) }, fields)) });
    };
    make('r91', { oauthRequestUri: [RO + '/ro/good', RO + '/ro/jwt',
                                     RO + '/ro/plain', RO + '/ro/missing',
                                     RO + '/ro/redirect', RO + '/ro/big',
                                     RO + '/ro/slow', RO + '/ro/digest'] });
    make('r91-nokeys', { oauthJwks: null });
    make('r91-es256', { oauthRequestObjectSigningAlg: 'ES256' });
    make('r91-enc', { oauthRequestObjectEncryptionAlg: 'RSA-OAEP-256' });
    make('r91-strict', { oauthRequireSignedRequestObject: 'TRUE' });

    const claimsFor = function (clientId, extra) {
      return Object.assign({
        iss: clientId, aud: BASE, client_id: clientId,
        response_type: 'code', redirect_uri: REDIRECT, scope: 'openid',
        state: 'st-' + crypto.randomBytes(6).toString('hex'),
        nonce: 'n-' + crypto.randomBytes(6).toString('hex'),
        exp: Math.floor(Date.now() / 1000) + 300
      }, extra || {});
    };
    const good = function (clientId, extra, header) {
      return sign('ES256', claimsFor(clientId || 'r91', extra), ec.privateKey,
                  Object.assign({ typ: 'oauth-authz-req+jwt', kid: 'r91-ec' },
                                header || {}));
    };
    const authorize = function (query, prefix) {
      jar = {};
      return request(port, 'GET', (prefix || '') + '/oauth2/authorize?' +
                     new URLSearchParams(query).toString());
    };
    const refusedWith = function (r, error, pattern) {
      return r.status === 400 && r.json && r.json.error === error &&
             (!pattern || pattern.test(r.json.error_description || ''));
    };
    const toSignIn = function (r) {
      return r.status === 302 &&
             /\/authn\/login/.test(String(r.headers.location || ''));
    };
    // Sign in through the real screen and come back; answers the final
    // response (the authorization response) and the pages on the way.
    const signIn = async function (first, username) {
      if (!toSignIn(first)) {
        return { final: first, page: null };
      }
      const page = await request(port, 'GET', first.headers.location,
                                 { cookies: true });
      const form = {};
      (page.text.match(/<input type="hidden"[^>]*>/g) || []).forEach(
        function (tag) {
          const name = /name="([^"]+)"/.exec(tag);
          const value = /value="([^"]*)"/.exec(tag);
          if (name) {
            form[name[1]] = value ? value[1].replace(/&amp;/g, '&') : '';
          }
        });
      form.username = username || 'r91-alice';
      form.password = 'anything';
      form.action = 'login';
      const posted = await request(port, 'POST', '/authn/login',
                                   { form: form, cookies: true });
      const back = String(posted.headers.location || '');
      const final = back
        ? await request(port, 'GET', back.replace(/^https?:\/\/[^/]+/, ''),
                        { cookies: true })
        : posted;
      return { final: final, page: page, posted: posted, back: back };
    };
    const codeAt = function (r, state) {
      const loc = String((r && r.headers && r.headers.location) || '');
      return r && r.status === 302 && loc.indexOf(REDIRECT) === 0 &&
             /[?&]code=/.test(loc) &&
             (!state || loc.indexOf('state=' + state) >= 0);
    };

    // --- a. by value, all the way -------------------------------------------
    let claims = claimsFor('r91');
    let object = sign('ES256', claims, ec.privateKey,
                      { typ: 'oauth-authz-req+jwt', kid: 'r91-ec' });
    let r = await authorize({ client_id: 'r91', request: object,
                              redirect_uri: 'https://evil.example/cb',
                              scope: 'profile', state: 'query-state' });
    note(toSignIn(r), '3a. a signed request object by value reaches the ' +
         'sign-in screen', r.status + ' ' + r.text.slice(0, 200));
    let flow = await signIn(r);
    note(/request=/.test(flow.back) && !/evil\.example/.test(flow.back) &&
         !/scope=/.test(flow.back),
         '3b. the return URL carries the request object again, not the ' +
         'resolved or the query\'s parameters', flow.back.slice(0, 160));
    note(codeAt(flow.final, claims.state),
         '3c. the authorization response goes to the OBJECT\'s redirect_uri ' +
         'with the OBJECT\'s state: the query\'s are ignored (section 6.3)',
         flow.final.status + ' ' + flow.final.headers.location);
    note(flow.page && /signed request object \(ES256\)/.test(flow.page.text),
         '3d. section 11.1: the sign-in screen says the request was a ' +
         'verified signed request object', flow.page &&
         flow.page.text.slice(0, 80));

    r = await authorize({ client_id: 'r91', request: object,
                          response_type: 'token' });
    note(refusedWith(r, 'invalid_request_object', /response_type/),
         '3e. OIDC 6.1: a response_type duplicated in the query must match',
         r.status + ' ' + r.text.slice(0, 160));
    r = await authorize({ client_id: 'r91', request: object,
                          response_type: 'code' });
    note(toSignIn(r), '3f. and a matching duplicate is accepted', r.status);

    // --- b. algorithms and claims -------------------------------------------
    const sent = async function (compact, clientId) {
      return authorize({ client_id: clientId || 'r91', request: compact });
    };
    r = await sent(sign('RS256', claimsFor('r91'), rsa.privateKey,
                        { kid: 'r91-rsa' }));
    note(toSignIn(r), '3g. RS256 with the registered RSA key', r.status + ' ' +
         r.text.slice(0, 160));
    r = await sent(sign('PS256', claimsFor('r91'), rsa.privateKey,
                        { kid: 'r91-rsa' }));
    note(toSignIn(r), '3h. PS256', r.status + ' ' + r.text.slice(0, 160));
    r = await sent(sign('HS256', claimsFor('r91'), SECRET));
    note(toSignIn(r), '3i. HS256 keyed by the client secret', r.status + ' ' +
         r.text.slice(0, 160));
    r = await sent(sign('ES256', claimsFor('r91'), ec.privateKey));
    note(toSignIn(r), '3j. no kid: every registered key of the family is ' +
         'tried', r.status);
    r = await sent(sign('ES256', claimsFor('r91'), ec.privateKey,
                        { kid: 'nobody' }));
    note(refusedWith(r, 'invalid_request_object', /section 6\.2/),
         '3k. section 6.2: a kid naming no key of this client is refused',
         r.text.slice(0, 200));
    r = await sent(sign('ES256', claimsFor('r91'), other.privateKey,
                        { kid: 'r91-ec' }));
    note(refusedWith(r, 'invalid_request_object', /did not verify/),
         '3l. a signature by another key is refused', r.text.slice(0, 160));
    r = await sent(sign('HS256', claimsFor('r91'), 'wrong-secret'));
    note(refusedWith(r, 'invalid_request_object', /did not verify/),
         '3m. HS256 with the wrong secret is refused', r.text.slice(0, 160));
    r = await sent(good('r91', { iss: 'someone-else' }));
    note(refusedWith(r, 'invalid_request_object', /`iss`/),
         '3n. an iss that is not the client is refused', r.text.slice(0, 160));
    r = await sent(good('r91', { aud: 'https://other-as.example' }));
    note(refusedWith(r, 'invalid_request_object', /`aud`/),
         '3o. an aud that is not this authorization server is refused',
         r.text.slice(0, 160));
    r = await sent(good('r91', { aud: BASE + '/oauth2/authorize' }));
    note(toSignIn(r), '3p. an aud naming the authorization endpoint is ' +
         'accepted', r.status);
    r = await sent(good('r91', { client_id: 'r91-es256' }));
    note(refusedWith(r, 'invalid_request_object', /MUST be identical/),
         '3q. section 6.3: a client_id claim differing from the query is ' +
         'refused', r.text.slice(0, 160));
    r = await sent(good('r91', { request_uri:
      'urn:ietf:params:oauth:request_uri:nested' }));
    note(refusedWith(r, 'invalid_request_object', /MUST NOT be included/),
         '3q-ii. section 4: a request_uri claim is refused, not dropped ' +
         '(#176)', r.text.slice(0, 160));
    r = await sent(good('r91', { request: 'eyJ.nested.' }));
    note(refusedWith(r, 'invalid_request_object', /MUST NOT be included/),
         '3q-iii. and so is a request claim', r.text.slice(0, 160));
    r = await sent(good('r91', { exp: Math.floor(Date.now() / 1000) - 3600 }));
    note(refusedWith(r, 'invalid_request_object', /expired/),
         '3r. an expired request object is refused', r.text.slice(0, 160));
    r = await sent(sign('RS256', claimsFor('r91-es256'), rsa.privateKey,
                        { kid: 'r91-rsa' }), 'r91-es256');
    note(refusedWith(r, 'invalid_request_object', /registered request_object/),
         '3s. a client registered for ES256 is refused an RS256 object',
         r.text.slice(0, 160));
    r = await sent(good('r91-es256'), 'r91-es256');
    note(toSignIn(r), '3t. and accepted in ES256', r.status);
    r = await sent(sign('ES256', claimsFor('r91-nokeys'), ec.privateKey),
                   'r91-nokeys');
    note(refusedWith(r, 'invalid_request_object', /holds no key/),
         '3u. a client with no registered key cannot send a signed object',
         r.text.slice(0, 160));
    r = await sent(b64({ alg: 'XS256' }) + '.' + b64(claimsFor('r91')) +
                   '.c2ln');
    note(refusedWith(r, 'invalid_request_object', /XS256/),
         '3v1. a signing algorithm this service does not know is refused',
         r.text.slice(0, 160));
    r = await sent(Buffer.from('{not json').toString('base64url') + '.' +
                   b64(claimsFor('r91')) + '.c2ln');
    note(r.status === 400 && /invalid_request_object/.test(r.text),
         '3v2. a header that is not JSON is refused', r.text.slice(0, 160));
    r = await sent(b64({ alg: 'none' }) + '.' +
                   Buffer.from('[not an object').toString('base64url') + '.');
    note(r.status === 400 && /invalid_request_object/.test(r.text),
         '3v3. an unsigned object whose claims are not a JSON object is ' +
         'refused', r.text.slice(0, 160));
    r = await sent('not.a.jwt.at.all.really');
    note(r.status === 400 && /invalid_request_object/.test(r.text),
         '3v. something that is not a JWT is refused', r.text.slice(0, 120));

    // --- c. unsigned --------------------------------------------------------
    const unsigned = sign('none', claimsFor('r91'), null);
    r = await sent(unsigned);
    note(toSignIn(r), '3w. development: an unsigned request object (OIDC ' +
         '6.1) is accepted', r.status + ' ' + r.text.slice(0, 160));
    r = await sent(sign('none', claimsFor('r91', {
      exp: Math.floor(Date.now() / 1000) - 3600 }), null));
    note(refusedWith(r, 'invalid_request_object', /expired/),
         '3x. and refused when it is expired', r.text.slice(0, 160));
    config.setOverride('oauth2.requireSignedRequestObject', true);
    try {
      r = await sent(unsigned);
      note(refusedWith(r, 'invalid_request_object', /unsigned/),
           '3y. section 10.5: refused where a signed object is required',
           r.text.slice(0, 160));
      r = await authorize({ client_id: 'r91', response_type: 'code',
                            redirect_uri: REDIRECT, scope: 'openid' });
      note(refusedWith(r, 'invalid_request', /requireSignedRequestObject/),
           '3z. and a plain request is refused by the setting',
           r.text.slice(0, 200));
      r = await sent(good('r91'));
      note(toSignIn(r), '3aa. while a signed object is accepted', r.status);
    } finally {
      config.clearOverride('oauth2.requireSignedRequestObject');
    }
    config.setOverride('global.mode', 'product');
    try {
      r = await sent(unsigned);
      note(refusedWith(r, 'invalid_request_object', /product mode/),
           '3ab. product: an unsigned request object is refused',
           r.text.slice(0, 160));
    } finally {
      config.clearOverride('global.mode');
    }

    // --- d. typ and the two require settings ----------------------------------
    r = await sent(good('r91', {}, { typ: 'at+jwt' }));
    note(refusedWith(r, 'invalid_request_object', /another kind of JWT/),
         '3ac. section 10.8: typ at+jwt is refused', r.text.slice(0, 160));
    r = await sent(sign('ES256', claimsFor('r91'), ec.privateKey,
                        { kid: 'r91-ec' }));
    note(toSignIn(r), '3ad. no typ is accepted by default', r.status);
    config.setOverride('oauth2.requireRequestObjectType', true);
    try {
      r = await sent(sign('ES256', claimsFor('r91'), ec.privateKey,
                          { kid: 'r91-ec', typ: 'JWT' }));
      note(refusedWith(r, 'invalid_request_object', /requireRequestObjectType/),
           '3ae. with the type required, typ JWT is refused',
           r.text.slice(0, 160));
      r = await sent(sign('ES256', claimsFor('r91'), ec.privateKey,
                          { kid: 'r91-ec' }));
      note(refusedWith(r, 'invalid_request_object', /requireRequestObjectType/),
           '3ae2. and no typ at all is refused', r.text.slice(0, 160));
      r = await sent(good('r91'));
      note(toSignIn(r), '3af. and oauth-authz-req+jwt accepted', r.status);
    } finally {
      config.clearOverride('oauth2.requireRequestObjectType');
    }
    const noIss = claimsFor('r91');
    delete noIss.iss;
    delete noIss.aud;
    r = await sent(sign('ES256', noIss, ec.privateKey, { kid: 'r91-ec' }));
    note(toSignIn(r), '3ag. without iss and aud, accepted by default',
         r.status);
    config.setOverride('oauth2.requireRequestObjectIssuerAudience', true);
    try {
      r = await sent(sign('ES256', noIss, ec.privateKey, { kid: 'r91-ec' }));
      note(refusedWith(r, 'invalid_request_object', /requireRequestObjectIssuer/),
           '3ah. with them required, refused', r.text.slice(0, 160));
      r = await sent(good('r91'));
      note(toSignIn(r), '3ai. and an object carrying both accepted', r.status);
    } finally {
      config.clearOverride('oauth2.requireRequestObjectIssuerAudience');
    }

    // --- e. require_signed_request_object, client and profile --------------------
    r = await authorize({ client_id: 'r91-strict', response_type: 'code',
                          redirect_uri: REDIRECT, scope: 'openid' });
    note(refusedWith(r, 'invalid_request', /this client/),
         '3aj. a client registered require_signed_request_object refuses a ' +
         'plain request', r.text.slice(0, 200));
    r = await sent(sign('none', claimsFor('r91-strict'), null), 'r91-strict');
    note(refusedWith(r, 'invalid_request_object', /unsigned/),
         '3ak. and an unsigned object from it', r.text.slice(0, 160));
    r = await sent(good('r91-strict'), 'r91-strict');
    note(toSignIn(r), '3al. and accepts a signed one', r.status);
    r = await authorize({ client_id: 'r91', response_type: 'code',
                          redirect_uri: REDIRECT, scope: 'openid' });
    note(toSignIn(r), '3am. another client\'s plain request is unaffected',
         r.status);
    await request(port, 'GET', '/.well-known/oauth-authorization-server/r91as');
    servers.setMember('r91as', 'require_signed_request_object', 'true');
    r = await authorize({ client_id: 'r91', response_type: 'code',
                          redirect_uri: REDIRECT, scope: 'openid' }, '/r91as');
    note(refusedWith(r, 'invalid_request', /authorization server/),
         '3an. a named authorization server publishing ' +
         'require_signed_request_object refuses a plain request',
         r.text.slice(0, 200));
    servers.removeMember('r91as', 'require_signed_request_object');

    // --- f. request_uri ------------------------------------------------------------
    served['/ro/good'] = good('r91');
    const byRef = function (uri, clientId) {
      return authorize({ client_id: clientId || 'r91', request_uri: uri });
    };
    hits['/ro/good'] = 0;
    r = await byRef(RO + '/ro/good');
    note(toSignIn(r) && hits['/ro/good'] === 1,
         '3ao. a registered request_uri is fetched once and accepted',
         r.status + ' hits=' + hits['/ro/good'] + ' ' + r.text.slice(0, 160));
    flow = await signIn(r);
    note(/request_uri=/.test(flow.back) && codeAt(flow.final),
         '3ap. and the round trip carries the request_uri to a code',
         flow.final.status + ' ' + flow.final.headers.location);
    hits['/ro/unregistered'] = 0;
    r = await byRef(RO + '/ro/unregistered');
    note(refusedWith(r, 'invalid_request_uri', /not one client/) &&
         !hits['/ro/unregistered'],
         '3aq. an unregistered request_uri is refused and NEVER dialled',
         r.text.slice(0, 160) + ' hits=' + hits['/ro/unregistered']);
    r = await byRef(RO + '/ro/jwt');
    note(toSignIn(r), '3ar. application/jwt is accepted', r.status);
    r = await byRef(RO + '/ro/plain');
    note(toSignIn(r), '3as. development: another media type is accepted, ' +
         'logged', r.status);
    r = await byRef(RO + '/ro/missing');
    note(refusedWith(r, 'invalid_request_uri', /HTTP 404/),
         '3at. a request_uri answering 404 is refused', r.text.slice(0, 160));
    hits['/ro/good'] = 0;
    r = await byRef(RO + '/ro/redirect');
    note(refusedWith(r, 'invalid_request_uri', /not followed/) &&
         !hits['/ro/good'],
         '3au. section 10.4: a redirect is not followed', r.text.slice(0, 160));
    config.setOverride('oauth2.requestUriMaxBytes', 1024);
    try {
      r = await byRef(RO + '/ro/big');
      note(refusedWith(r, 'invalid_request_uri', /requestUriMaxBytes/),
           '3av. a response over oauth2.requestUriMaxBytes is refused',
           r.text.slice(0, 160));
    } finally {
      config.clearOverride('oauth2.requestUriMaxBytes');
    }
    config.setOverride('oauth2.requestUriTimeoutMs', 300);
    try {
      r = await byRef(RO + '/ro/slow');
      note(refusedWith(r, 'invalid_request_uri', /requestUriTimeoutMs/),
           '3aw. a request_uri that does not answer is given up on',
           r.text.slice(0, 160));
    } finally {
      config.clearOverride('oauth2.requestUriTimeoutMs');
    }
    served['/ro/digest'] = good('r91');
    applications.updateApplication('r91', { attribute: 'oauthRequestUri',
      mode: 'add', value: digestUri(served['/ro/digest']) });
    r = await byRef(digestUri(served['/ro/digest']));
    note(toSignIn(r), '3ax. OIDC 6.2: a request_uri whose fragment is the ' +
         'SHA-256 of its content is accepted', r.status + ' ' +
         r.text.slice(0, 160));
    const stale = digestUri(served['/ro/digest']);
    served['/ro/digest'] = good('r91');
    r = await byRef(stale);
    note(refusedWith(r, 'invalid_request_uri', /SHA-256 of a different/),
         '3ay. and refused once the content changes under the fragment',
         r.text.slice(0, 160));
    hits['/ro/good'] = 0;
    await byRef(RO + '/ro/good');
    await byRef(RO + '/ro/good');
    note(hits['/ro/good'] === 2, '3az. with no cache, each request fetches',
         'hits=' + hits['/ro/good']);
    config.setOverride('oauth2.requestUriCacheS', 60);
    try {
      hits['/ro/good'] = 0;
      const one = await byRef(RO + '/ro/good');
      const two = await byRef(RO + '/ro/good');
      note(toSignIn(one) && toSignIn(two) && hits['/ro/good'] === 1,
           '3ba. OIDC 6.2: with oauth2.requestUriCacheS on, the content is ' +
           'fetched once and reused', 'hits=' + hits['/ro/good']);
    } finally {
      config.clearOverride('oauth2.requestUriCacheS');
    }
    config.setOverride('global.mode', 'product');
    try {
      hits['/ro/good'] = 0;
      r = await byRef(RO + '/ro/good');
      note(refusedWith(r, 'invalid_request_uri', /https/) &&
           !hits['/ro/good'],
           '3bb. product: a plain http request_uri is refused before it is ' +
           'dialled', r.text.slice(0, 160));
    } finally {
      config.clearOverride('global.mode');
    }
    r = await authorize({ client_id: 'r91', request: good('r91'),
                          request_uri: RO + '/ro/good' });
    note(refusedWith(r, 'invalid_request', /both/),
         '3bc. request and request_uri together are refused',
         r.text.slice(0, 160));
    r = await authorize({ request: good('r91') });
    note(refusedWith(r, 'invalid_request', /client_id/),
         '3bd. section 5: a request object with no client_id query parameter ' +
         'is refused', r.text.slice(0, 160));
    r = await request(port, 'GET', '/oauth2/authorize?client_id=r91&request=' +
      encodeURIComponent(good('r91')) + '&request=' +
      encodeURIComponent(good('r91')));
    note(refusedWith(r, 'invalid_request', /repeats/),
         '3be. a repeated request parameter is refused', r.text.slice(0, 160));

    // --- g. encryption -------------------------------------------------------------
    const jwks = (await request(port, 'GET', '/oauth2/jwks')).json;
    const encRsa = jwks.keys.filter(function (k) {
      return k.use === 'enc' && k.kty === 'RSA';
    })[0];
    const encEc = jwks.keys.filter(function (k) {
      return k.use === 'enc' && k.kty === 'EC';
    })[0];
    note(encRsa && encEc && /^sts-ro-/.test(encRsa.kid) &&
         jwks.keys[0].use === 'sig',
         '3bf. /oauth2/jwks publishes an RSA and an EC use-enc key, after the ' +
         'signing keys', JSON.stringify((jwks.keys || []).map(function (k) {
           return k.kid + ':' + k.use;
         })));
    r = await sent(encryptRsa(good('r91'), encRsa));
    note(toSignIn(r), '3bg. section 6.1: signed then encrypted with ' +
         'RSA-OAEP-256 by this file\'s own JWE code', r.status + ' ' +
         r.text.slice(0, 200));
    r = await sent(stsCrypto.encryptJweCompact(good('r91'), {
      alg: 'ECDH-ES', enc: 'A256GCM', jwk: encEc, cty: 'JWT' }));
    note(toSignIn(r), '3bh. ECDH-ES to the published EC key', r.status + ' ' +
         r.text.slice(0, 200));
    // OpenID Connect Core section 10.2, computed HERE: the leftmost octets of
    // the SHA-2 of the client secret.
    const secretKey = function (bytes) {
      const hash = bytes <= 32 ? 'sha256' : bytes <= 48 ? 'sha384' : 'sha512';
      return crypto.createHash(hash).update(SECRET).digest().subarray(0, bytes);
    };
    r = await sent(stsCrypto.encryptJweCompact(good('r91'), {
      alg: 'A256KW', enc: 'A128CBC-HS256', secret: secretKey(32),
      cty: 'JWT' }));
    note(toSignIn(r), '3bi. A256KW keyed by the SHA-256 of the client secret ' +
         '(OIDC Core 10.2)', r.status + ' ' + r.text.slice(0, 200));
    r = await sent(stsCrypto.encryptJweCompact(good('r91'), {
      alg: 'A128GCMKW', enc: 'A256GCM', secret: secretKey(16), cty: 'JWT' }));
    note(toSignIn(r), '3bi2. A128GCMKW keyed by its leftmost 128 bits',
         r.status + ' ' + r.text.slice(0, 200));
    r = await sent(stsCrypto.encryptJweCompact(good('r91'), {
      alg: 'dir', enc: 'A256CBC-HS512', secret: secretKey(64), cty: 'JWT' }));
    note(toSignIn(r), '3bi3. dir with A256CBC-HS512 keyed by the SHA-512 of ' +
         'the client secret', r.status + ' ' + r.text.slice(0, 200));
    r = await sent(stsCrypto.encryptJweCompact(good('r91'), {
      alg: 'A256KW', enc: 'A128CBC-HS256',
      secret: Buffer.from(SECRET).subarray(0, 32), cty: 'JWT' }));
    note(refusedWith(r, 'invalid_request_object', /could not be decrypted/),
         '3bi4. the raw secret\'s own octets are not the key',
         r.text.slice(0, 160));
    r = await sent(encryptRsa(good('r91'), Object.assign({}, encRsa,
                                                         { kid: 'elsewhere' })));
    note(refusedWith(r, 'invalid_request_object', /encrypted to the key/),
         '3bj. a JWE naming a kid that is not this realm\'s key is refused',
         r.text.slice(0, 160));
    r = await sent(stsCrypto.encryptJweCompact(good('r91-nokeys'), {
      alg: 'A256KW', enc: 'A128CBC-HS256', secret: crypto.randomBytes(32),
      cty: 'JWT' }), 'r91-nokeys');
    note(r.status === 400 && /invalid_request_object/.test(r.text),
         '3bk. a JWE under a secret that is not the client\'s does not open',
         r.text.slice(0, 160));
    r = await sent(encryptRsa('not a jws', encRsa));
    note(refusedWith(r, 'invalid_request_object', /not a JWS/),
         '3bl. section 4: what is inside must be a signed JWT',
         r.text.slice(0, 160));
    const broken = encryptRsa(good('r91'), encRsa).split('.');
    broken[3] = Buffer.from('tampered').toString('base64url');
    r = await sent(broken.join('.'));
    note(refusedWith(r, 'invalid_request_object', /could not be decrypted/),
         '3bm. a tampered JWE is refused', r.text.slice(0, 160));
    r = await sent(good('r91-enc'), 'r91-enc');
    note(refusedWith(r, 'invalid_request_object', /must be encrypted/),
         '3bn. a client registered for encryption is refused a plain object',
         r.text.slice(0, 160));
    r = await sent(encryptRsa(good('r91-enc'), encRsa), 'r91-enc');
    note(toSignIn(r), '3bo. and accepted encrypted as registered', r.status);
    r = await sent(stsCrypto.encryptJweCompact(good('r91-enc'), {
      alg: 'ECDH-ES', enc: 'A128CBC-HS256', jwk: encEc, cty: 'JWT' }),
                   'r91-enc');
    note(refusedWith(r, 'invalid_request_object', /registered/),
         '3bp. and refused under another algorithm than registered',
         r.text.slice(0, 160));
    realms.create({ id: 'r91other' });
    const otherJwks = (await request(port, 'GET',
                                     '/realm/r91other/oauth2/jwks')).json;
    const otherRsa = otherJwks.keys.filter(function (k) {
      return k.use === 'enc' && k.kty === 'RSA';
    })[0];
    r = await sent(encryptRsa(good('r91'), otherRsa));
    note(otherRsa && otherRsa.kid !== encRsa.kid &&
         refusedWith(r, 'invalid_request_object', /encrypted to the key/),
         '3bq. another realm\'s published key opens nothing here',
         r.text.slice(0, 160));

    // --- h. profile narrowing and PAR -------------------------------------------
    await request(port, 'GET', '/.well-known/oauth-authorization-server/r91np');
    servers.setMember('r91np', 'request_parameter_supported', 'false');
    r = await authorize({ client_id: 'r91', request: good('r91', {
      aud: BASE + '/r91np' }) }, '/r91np');
    note(refusedWith(r, 'request_not_supported'),
         '3br. request_parameter_supported false: request_not_supported',
         r.text.slice(0, 160));
    servers.setMember('r91np', 'request_uri_parameter_supported', 'false');
    r = await authorize({ client_id: 'r91', request_uri: RO + '/ro/good' },
                        '/r91np');
    note(refusedWith(r, 'request_uri_not_supported'),
         '3bs. request_uri_parameter_supported false: request_uri_not_supported',
         r.text.slice(0, 160));
    r = await authorize({ client_id: 'r91',
      request_uri: 'urn:ietf:params:oauth:request_uri:not-a-real-one' },
                        '/r91np');
    note(r.status === 400 && !/request_uri_parameter_supported/.test(r.text),
         '3bs2. RFC 9126 section 5: a pushed request\'s URN is not refused by ' +
         'request_uri_parameter_supported false', r.text.slice(0, 160));
    servers.removeMember('r91np', 'request_parameter_supported');
    servers.setMember('r91np', 'request_object_signing_alg_values_supported',
                      '["RS256"]');
    r = await authorize({ client_id: 'r91', request: good('r91', {
      aud: BASE + '/r91np' }) }, '/r91np');
    note(refusedWith(r, 'invalid_request_object', /RS256/),
         '3bt. a profile listing only RS256 refuses ES256', r.text.slice(0, 160));
    r = await authorize({ client_id: 'r91', request: sign('RS256',
      claimsFor('r91', { aud: BASE + '/r91np' }), rsa.privateKey,
      { kid: 'r91-rsa' }) }, '/r91np');
    note(toSignIn(r), '3bu. and accepts RS256', r.status + ' ' +
         r.text.slice(0, 160));
    servers.setMember('r91np', 'request_object_encryption_alg_values_supported',
                      '["ECDH-ES"]');
    r = await authorize({ client_id: 'r91', request: encryptRsa(sign('RS256',
      claimsFor('r91', { aud: BASE + '/r91np' }), rsa.privateKey,
      { kid: 'r91-rsa' }), encRsa) }, '/r91np');
    note(refusedWith(r, 'invalid_request_object', /decrypts request objects/),
         '3bv. a profile listing only ECDH-ES refuses RSA-OAEP-256',
         r.text.slice(0, 160));
    const parPresent = fs.existsSync(ROOT + '/oauth-oidc/par.ts');
    r = await authorize({ client_id: 'r91',
      request_uri: 'urn:ietf:params:oauth:request_uri:not-a-real-one' });
    note(r.status === 400 && !/not one client/.test(r.text) &&
         (parPresent || refusedWith(r, 'request_uri_not_supported', /RFC 9126/)),
         '3bw. a PAR URN is never matched against request_uris or fetched' +
         (parPresent ? '' : ', and without PAR it is request_uri_not_supported'),
         r.text.slice(0, 160));

    // --- i. the round trip -------------------------------------------------------------
    const loginClaims = claimsFor('r91', { prompt: 'login' });
    r = await sent(sign('ES256', loginClaims, ec.privateKey,
                        { kid: 'r91-ec', typ: 'oauth-authz-req+jwt' }));
    flow = await signIn(r);
    note(/jar_prompt_honoured=1/.test(flow.back) &&
         codeAt(flow.final, loginClaims.state),
         '3bx. prompt=login inside the object is honoured once and does not ' +
         'loop back to the sign-in screen', flow.back.slice(0, 120) + ' -> ' +
         flow.final.status + ' ' + flow.final.headers.location);
    config.clearOverride('oauth2.consentRequired');
    try {
      make('r91-consent', {});
      const consentClaims = claimsFor('r91-consent', { scope: 'openid email' });
      r = await sent(sign('ES256', consentClaims, ec.privateKey,
                          { kid: 'r91-ec' }), 'r91-consent');
      flow = await signIn(r, 'r91-consenter');
      const consentPage = String(flow.final.headers.location || '');
      const drawn = consentPage
        ? await request(port, 'GET', consentPage.replace(/^https?:\/\/[^/]+/,
                                                         ''), { cookies: true })
        : { text: '' };
      note(/\/oauth2\/consent/.test(consentPage) &&
           /signed request object \(ES256\)/.test(drawn.text),
           '3by. section 11.1: the consent screen says the request was a ' +
           'verified signed request object', consentPage + ' ' +
           drawn.text.slice(0, 80));
    } finally {
      config.setOverride('oauth2.consentRequired', false);
    }

    // --- j. metadata, registration and the console's writes ---------------------------
    let meta = (await request(port, 'GET',
                              '/.well-known/openid-configuration')).json;
    note(meta.request_parameter_supported === true &&
         meta.request_uri_parameter_supported === true &&
         meta.require_request_uri_registration === true &&
         meta.require_signed_request_object === false &&
         meta.request_object_signing_alg_values_supported.indexOf('ES256') >=
           0 &&
         meta.request_object_signing_alg_values_supported.indexOf('none') >= 0 &&
         meta.request_object_encryption_alg_values_supported
           .indexOf('RSA-OAEP-256') >= 0 &&
         meta.request_object_encryption_enc_values_supported
           .indexOf('A128CBC-HS256') >= 0,
         '3bz. the OpenID Provider Configuration publishes every request ' +
         'object member, none included in development', JSON.stringify({
           a: meta.request_parameter_supported,
           b: meta.request_uri_parameter_supported,
           c: meta.require_request_uri_registration }));
    config.setOverride('oauth2.requireSignedRequestObject', true);
    try {
      meta = (await request(port, 'GET',
                            '/.well-known/oauth-authorization-server')).json;
      note(meta.require_signed_request_object === true &&
           meta.request_object_signing_alg_values_supported.indexOf('none') <
             0,
           '3ca. with signing required, RFC 8414 says so and stops ' +
           'advertising none');
    } finally {
      config.clearOverride('oauth2.requireSignedRequestObject');
    }
    const narrowedMeta = (await request(port, 'GET',
      '/.well-known/oauth-authorization-server/r91np')).json;
    note(narrowedMeta.request_uri_parameter_supported === false &&
         JSON.stringify(narrowedMeta
           .request_object_signing_alg_values_supported) === '["RS256"]',
         '3cb. a named authorization server\'s document says what its ' +
         'endpoint did');

    r = await request(port, 'POST', '/oauth2/register', { json: {
      client_name: 'r91 registered', redirect_uris: [REDIRECT],
      request_uris: ['https://rp.r91.example/ro.jwt'],
      request_object_signing_alg: 'PS256',
      request_object_encryption_alg: 'ECDH-ES',
      request_object_encryption_enc: 'A256GCM',
      require_signed_request_object: true } });
    const registered = r.json || {};
    const config2 = registered.client_id
      ? applications.clientConfigOf(registered.client_id) : {};
    note((r.status === 201 || r.status === 200) &&
         config2.request_object_signing_alg === 'PS256' &&
         config2.request_object_encryption_enc === 'A256GCM' &&
         config2.require_signed_request_object === true &&
         JSON.stringify(config2.request_uris) ===
           '["https://rp.r91.example/ro.jwt"]',
         '3cc. RFC 7591: the five members land on the entry',
         r.status + ' ' + r.text.slice(0, 160));
    if (registered.client_id) {
      const read = await request(port, 'GET', '/oauth2/register/' +
        registered.client_id, { headers: { authorization: 'Bearer ' +
                                           registered.registration_access_token
                                         } });
      note(read.status === 200 && read.json.request_object_signing_alg ===
           'PS256' && read.json.require_signed_request_object === true,
           '3cd. RFC 7592: and read back', read.status + ' ' +
           read.text.slice(0, 160));
    }
    r = await request(port, 'POST', '/oauth2/register', { json: {
      client_name: 'r91 bad', redirect_uris: [REDIRECT],
      request_uris: ['ftp://rp.r91.example/ro.jwt'] } });
    note(r.status === 400 && r.json.error === 'invalid_client_metadata',
         '3ce. a registration with an unusable request_uri is refused',
         r.text.slice(0, 160));
    r = await request(port, 'POST', '/oauth2/register', { json: {
      client_name: 'r91 bad2', redirect_uris: [REDIRECT],
      request_object_encryption_enc: 'A256GCM' } });
    note(r.status === 400 && r.json.error === 'invalid_client_metadata',
         '3cf. a registration with an enc and no alg is refused',
         r.text.slice(0, 160));

    let u = applications.updateApplication('r91', {
      attribute: 'oauthRequestUri', mode: 'add', value: 'ftp://x.example/ro' });
    note(!u.ok && /oauthRequestUri/.test(JSON.stringify(u.errors)),
         '3cg. the console refuses an unusable request URI',
         JSON.stringify(u.errors));
    u = applications.updateApplication('r91', {
      attribute: 'oauthRequireSignedRequestObject', mode: 'set',
      value: 'yes' });
    note(!u.ok, '3ch. and a require flag that is not TRUE or FALSE',
         JSON.stringify(u.errors));
    u = applications.updateApplication('r91', {
      attribute: 'oauthRequestObjectEncryptionEnc', mode: 'set',
      value: 'A128GCM' });
    note(!u.ok, '3ci. and an enc on an entry with no encryption alg',
         JSON.stringify(u.errors));
    u = applications.updateApplication('r91', {
      attribute: 'oauthRequestObjectSigningAlg', mode: 'set', value: 'ES384' });
    note(u.ok && applications.clientConfigOf('r91').request_object_signing_alg ===
         'ES384', '3cj. and accepts a usable signing algorithm',
         JSON.stringify(u));

    const cryptoMetadata = require(ROOT + '/admin-ui/crypto_metadata');
    const family = cryptoMetadata.FAMILIES.filter(function (row) {
      return row.name === 'OAuth2 / OIDC';
    })[0];
    const listed = function (what) {
      const row = (family ? family.algorithms() : []).filter(function (one) {
        return one[0] === what;
      })[0];
      return row ? JSON.stringify(row[1]) : '(missing)';
    };
    meta = (await request(port, 'GET',
                          '/.well-known/oauth-authorization-server')).json;
    note(listed('Request object signature (RFC 9101)') === JSON.stringify(
           meta.request_object_signing_alg_values_supported.filter(
             function (alg) { return alg !== 'none'; })) &&
         listed('Request object decryption (RFC 9101)') === JSON.stringify(
           meta.request_object_encryption_alg_values_supported),
         '3ck. /admin/crypto-metadata lists what the metadata advertises');

    server.close();
    roServer.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 3. the endpoint, in a child process ===');
  const out = path.join(os.tmpdir(), 'rfc9101-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', R91_ROOT: ROOT, R91_OUT: out }),
      encoding: 'utf8', timeout: 240000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  library(t);
  registry(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'rfc9101 request objects',
  describe: 'JWT-secured authorization requests: by value and by reference, ' +
            'signing, encryption, the require settings, profiles and metadata',
  run: run
};
