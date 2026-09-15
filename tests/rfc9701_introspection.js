'use strict';
//
// File: rfc9701_introspection.js
//
// ===========================================================================
// RFC 9701 — THE JWT RESPONSE FOR OAUTH TOKEN INTROSPECTION (2026-09-13).
//
// `oauth-oidc/introspection_jwt.js` argues the design. What is held here:
//
//   1. THE LIBRARY: the Accept reading (a JWT only where the media type is
//      NAMED, with q-values and wildcards read the way RFC 9110 says), section
//      6's defaults and refusals, section 5's rule that an inactive token's
//      claim is `{ active: false }` and nothing else, and the recipient key
//      read from a registration document and from an attribute alike;
//   2. THE REGISTRY'S CHECK: what `introspectionResponseProblem()` refuses,
//      because it is what the registration endpoint, the console and
//      `/admin-api` all ask;
//   3. THE ENDPOINT, in a child process on an ephemeral loopback port — JSON
//      unchanged for an anonymous caller in development, a JWT refused 400 to
//      an unauthenticated one, the JWT's header, media type and claims, its
//      signature verified by THIS FILE's own code against the published JWKS
//      in RS256, ES256 and HS256, an encrypted response decrypted by this
//      file's own RSA-OAEP-256 / A128CBC-HS256, the three members through RFC
//      7591 and the application registry, the discovery members, a named
//      authorization server's issuer, a registration nothing can honour
//      answered 500, and product mode's 401 for anonymous JSON;
//   4. SECTION 5's "INTENDED FOR THE RESOURCE SERVER" at the endpoint, by
//      client_id, oauthAudience and permission base, a refresh token its own
//      client's alone, and who is not restricted;
//   5. A NAMED AUTHORIZATION SERVER'S PROFILE narrowing the auth methods and
//      the signing list, and a removed member not checking;
//   6. OAUTH 2.1 SECTION 2.4 at introspection, in a realm in that mode;
//   7. /admin/crypto-metadata's introspection rows against discovery.
//
// **THE CHILD IS NOT FASTIDIOUSNESS**, for `tests/rfc9068_access_tokens.js`'s
// reason: loading the protocol stack into `run.js`'s one process builds a
// certificate authority and registers every route on the shared app.
//
// **THE VERIFIER AND THE DECRYPTOR ARE WRITTEN HERE**, for `sts_dpop.js`'s:
// a JWT checked with the implementation that made it proves only that the
// implementation agrees with itself.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'rfc9701_introspection',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

const ij = require('../oauth-oidc/introspection_jwt');
const applications = require('../common/applications');
const errorCodes = require('../common/error_codes');

// ---------------------------------------------------------------------------
// 1. THE LIBRARY.
// ---------------------------------------------------------------------------
function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. the Accept reading, the defaults and the claims ===');
  const MT = 'application/token-introspection+jwt';
  const table = [
    [undefined, false, 'no Accept header'],
    ['', false, 'an empty Accept header'],
    ['*/*', false, 'a wildcard alone'],
    ['application/json', false, 'application/json'],
    ['application/*', false, 'application/* does not NAME the JWT'],
    [MT, true, 'the media type alone'],
    ['APPLICATION/Token-Introspection+JWT', true, 'in any case'],
    [MT + ', application/json', true, 'named first, JSON as a fallback'],
    ['application/json, ' + MT, true, 'an equal quality goes to the JWT'],
    ['application/json, ' + MT + ';q=0.5', false, 'JSON preferred by q'],
    [MT + ';q=0.9, */*;q=0.1', true, 'the JWT preferred over a wildcard'],
    [MT + ';q=0', false, 'q=0 means not acceptable'],
    [MT + ';q=0.4, application/*;q=0.8', false,
     'application/* raises JSON above the JWT']
  ];
  table.forEach(function (row, i) {
    t.equal(ij.wantsJwt(row[0]), row[1], '1a.' + (i + 1) + ' ' + row[2]);
  });

  let p = ij.protectionFor({});
  t.check(p.ok && p.signAlg === 'RS256' && p.encAlg === '' && p.encEnc === '',
          '1b. nothing registered: RS256, not encrypted', JSON.stringify(p));
  p = ij.protectionFor({ introspection_encrypted_response_alg: 'RSA-OAEP' });
  t.check(p.ok && p.encEnc === 'A128CBC-HS256',
          '1c. an alg with no enc: section 6\'s A128CBC-HS256', p.encEnc);
  p = ij.protectionFor({ introspection_signed_response_alg: 'none' });
  t.check(!p.ok && errorCodes.codeOf(p) === 'STS-OAUTH-0293',
          '1d. `none` is refused, not downgraded, with STS-OAUTH-0293',
          JSON.stringify(p));
  p = ij.protectionFor({ introspection_encrypted_response_enc: 'A256GCM' });
  t.check(!p.ok && /MUST NOT/.test(p.description),
          '1e. an enc with no alg is refused where it is read', p.description);
  p = ij.protectionFor({ introspection_encrypted_response_alg: 'dir' });
  t.check(!p.ok, '1f. a symmetric key management algorithm is refused');

  const narrowed = { signing: ['PS256'], encryption: null, enc: null };
  p = ij.protectionFor({}, narrowed);
  t.check(!p.ok && p.notAdvertised &&
          errorCodes.codeOf(p) === 'STS-OAUTH-0296' &&
          /default/.test(p.description),
          '1p. an authorization server advertising only PS256 refuses the ' +
          'RS256 default, NAMING it as the default, with STS-OAUTH-0296',
          JSON.stringify(p));
  p = ij.protectionFor({ introspection_signed_response_alg: 'PS256' },
                       narrowed);
  t.check(p.ok, '1q. and answers a client that registered PS256');
  p = ij.protectionFor({ introspection_encrypted_response_alg: 'RSA-OAEP' },
                       { signing: null, encryption: ['ECDH-ES'],
                         enc: ['A128CBC-HS256'] });
  t.check(!p.ok && p.notAdvertised && /encrypted_response_alg/.test(
    p.description), '1r. an encryption algorithm outside the list is refused');
  p = ij.protectionFor({}, { signing: null, encryption: ['ECDH-ES'],
                             enc: ['A256GCM'] });
  t.check(p.ok, '1s. a list about encryption asks nothing of a client that ' +
          'registered none, and a removed member (null) asks nothing at all');

  const BASE_URL = 'https://idp.example';
  const own = { active: true, client_id: 'app1', aud: 'api-x',
                token_type: 'Bearer' };
  t.check(ij.intendedFor(own, 'app1', BASE_URL),
          '1t. section 5: a client may introspect its own token');
  t.check(!ij.intendedFor(own, 'someone-else', BASE_URL),
          '1u. a token addressed to another resource server is not intended ' +
          'for this caller');
  t.check(ij.intendedFor({ active: true, client_id: 'app1',
                           aud: BASE_URL + '/resource' }, 'rs', BASE_URL) &&
          ij.intendedFor({ active: true, client_id: 'app1',
                           aud: ['api-x', BASE_URL + '/t1/resource'] }, 'rs',
                         BASE_URL),
          '1v. a token naming this service\'s default resource indicator ' +
          '(or a named authorization server\'s) is any caller\'s');
  t.check(!ij.intendedFor({ active: true, client_id: 'app1',
                            aud: 'https://other.example/resource' }, 'rs',
                          BASE_URL),
          '1w. somebody else\'s /resource is not this service\'s');
  const refresh = { active: true, client_id: 'app1', token_type:
                    'refresh_token', aud: BASE_URL + '/resource' };
  t.check(ij.intendedFor(refresh, 'app1', BASE_URL) &&
          !ij.intendedFor(refresh, 'rs', BASE_URL),
          '1x. a refresh token is its own client\'s ALONE, whatever its aud');
  t.check(!ij.intendedFor({ active: false }, 'app1', BASE_URL) &&
          !ij.intendedFor(own, '', BASE_URL),
          '1y. nothing is intended for an inactive token or a caller with ' +
          'no identity');

  const active = { active: true, scope: 'read', client_id: 'c', sub: 's' };
  let c = ij.claimsFor(active, 'https://idp.example', 'rs1', 1000);
  t.check(c.iss === 'https://idp.example' && c.aud === 'rs1' &&
          c.iat === 1000 && c.token_introspection === active,
          '1g. iss, aud and iat at the top, the answer nested',
          JSON.stringify(c));
  t.check(!('sub' in c) && !('exp' in c) && !('scope' in c),
          '1h. no sub, no exp and no introspection member at the top level');
  c = ij.claimsFor({ active: false, scope: 'leaked', sub: 'x' }, 'i', 'a', 1);
  t.equal(JSON.stringify(c.token_introspection), '{"active":false}',
          '1i. section 5: an inactive answer carries NOTHING but active');
  c = ij.claimsFor({ active: 'true', scope: 'x' }, 'i', 'a', 1);
  t.equal(JSON.stringify(c.token_introspection), '{"active":false}',
          '1j. an active member that is not the boolean true is not active');

  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                            { kid: 'enc-1', use: 'enc' });
  const sig = Object.assign({}, jwk, { kid: 'sig-1', use: 'sig' });
  const member = 'introspection_encrypted_response_alg';
  t.equal(ij.recipientKey({ jwks: { keys: [sig, jwk] } }, 'RSA-OAEP-256',
                          member).kid, 'enc-1',
          '1k. the key marked for encryption is chosen over a signing key');
  t.equal(ij.recipientKey({ jwks: JSON.stringify({ keys: [jwk] }) },
                          'RSA-OAEP-256', member).kid, 'enc-1',
          '1l. a jwks held as TEXT (the attribute) is read like an object');
  const refused = function (registered, alg) {
    try {
      ij.recipientKey(registered, alg, member);
      return '';
    } catch (e) {
      log.debug("Caught in refused(): " + ((e && e.message) || e));
      return e.message;
    }
  };
  t.check(/jwks_uri/.test(refused({ jwks_uri: 'https://x' }, 'RSA-OAEP')),
          '1m. a jwks_uri is named and never fetched');
  t.check(/EC/.test(refused({ jwks: { keys: [jwk] } }, 'ECDH-ES')),
          '1n. ECDH-ES with only an RSA key is refused naming the key type');
  t.check(/not a JSON Web Key Set/.test(refused({ jwks: '{nope' },
                                                'RSA-OAEP')),
          '1o. a jwks that is not JSON is refused by name');
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE REGISTRY'S CHECK.
// ---------------------------------------------------------------------------
function registry(t) {
  log.debug("Entering registry().");
  t.log.info('=== 2. introspectionResponseProblem() ===');
  const problem = applications.introspectionResponseProblem;
  t.equal(problem({}), null, '2a. nothing registered is nothing to refuse');
  t.equal(problem({ introspection_signed_response_alg: 'ML-DSA-65',
                    introspection_encrypted_response_alg: 'ECDH-ES+A256KW',
                    introspection_encrypted_response_enc: 'A256GCM' }), null,
          '2b. a post-quantum signature, an ECDH key wrap and A256GCM pass');
  let p = problem({ introspection_signed_response_alg: 'none' });
  t.check(p && p.error === 'invalid_client_metadata' &&
          p.errorCode === 'STS-REG-0072' && /section 5/.test(p.description),
          '2c. `none` is invalid_client_metadata citing section 5',
          JSON.stringify(p));
  p = problem({ introspection_signed_response_alg: 'RS1' });
  t.check(p && p.member === 'introspection_signed_response_alg',
          '2d. an unknown signing algorithm names its member');
  p = problem({ introspection_encrypted_response_alg: 'A128KW' });
  t.check(p && /symmetric/.test(p.description),
          '2e. a symmetric key wrap is refused, saying why');
  p = problem({ introspection_encrypted_response_enc: 'A128GCM' });
  t.check(p && p.member === 'introspection_encrypted_response_enc' &&
          /MUST NOT/.test(p.description),
          '2f. section 6: an enc without an alg is refused');
  p = problem({ introspection_encrypted_response_alg: 'RSA-OAEP',
                introspection_encrypted_response_enc: 'A999' });
  t.check(p && p.member === 'introspection_encrypted_response_enc',
          '2g. an unknown enc is refused');
  p = problem({ introspection_signed_response_alg: ['RS256'] });
  t.check(p && /string/.test(p.description),
          '2h. a member that is not a string is refused');
  t.check(ij.SIGNING_ALGS.indexOf('none') < 0 &&
          ij.SIGNING_ALGS.indexOf('RS256') >= 0 &&
          ij.SIGNING_ALGS.indexOf('HS256') >= 0 &&
          ij.ENCRYPTION_ALGS.indexOf('RSA-OAEP-256') >= 0 &&
          ij.ENCRYPTION_ALGS.indexOf('dir') < 0,
          '2i. the advertised lists: no none, HMAC signing, no symmetric JWE');
  log.debug("Leaving registry().");
}

// ---------------------------------------------------------------------------
// 3. THE ENDPOINT, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.R97_ROOT;
  const OUT = process.env.R97_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json)
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET') {
        headers['content-type'] = o.json !== undefined ? 'application/json'
          : 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.on('data', function (chunk) { text += chunk; });
        res.on('end', function () {
          let parsed = null;
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            // A JWT is not JSON: the raw body is what is kept. No logger in a
            // `node -e` child, so the reason travels on the result.
            parsed = { parseError: e.message };
          }
          resolve({ status: res.statusCode, headers: res.headers, text: text,
                    json: parsed });
        });
      });
      req.end(body);
    });
  }

  function part(token, i) {
    return JSON.parse(Buffer.from(String(token).split('.')[i], 'base64url')
                            .toString('utf8'));
  }

  // THIS FILE'S OWN JWS CHECK — node's crypto and nothing from the service.
  function verifies(token, jwks, secret) {
    const pieces = String(token).split('.');
    const head = part(token, 0);
    const data = Buffer.from(pieces[0] + '.' + pieces[1]);
    const signature = Buffer.from(pieces[2], 'base64url');
    const digest = 'sha' + head.alg.slice(2);
    if (/^HS/.test(head.alg)) {
      const mac = crypto.createHmac(digest, secret).update(data).digest();
      return mac.length === signature.length &&
             crypto.timingSafeEqual(mac, signature);
    }
    const key = (jwks.keys || []).filter(function (one) {
      return one.kid === head.kid;
    })[0];
    if (!key) {
      return false;
    }
    const publicKey = crypto.createPublicKey({ key: key, format: 'jwk' });
    return crypto.verify(digest, data,
      /^ES/.test(head.alg) ? { key: publicKey, dsaEncoding: 'ieee-p1363' }
                           : publicKey, signature);
  }

  // THIS FILE'S OWN JWE — RSA-OAEP-256 and A128CBC-HS256 (RFC 7518 5.2.2.1).
  function decrypts(compact, privateKey) {
    const pieces = String(compact).split('.');
    const cek = crypto.privateDecrypt({ key: privateKey, oaepHash: 'sha256',
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(pieces[1], 'base64url'));
    const macKey = cek.subarray(0, 16);
    const encKey = cek.subarray(16);
    const iv = Buffer.from(pieces[2], 'base64url');
    const ciphertext = Buffer.from(pieces[3], 'base64url');
    const aad = Buffer.from(pieces[0], 'ascii');
    const al = Buffer.alloc(8);
    al.writeBigUInt64BE(BigInt(aad.length * 8));
    const tag = crypto.createHmac('sha256', macKey)
      .update(Buffer.concat([aad, iv, ciphertext, al])).digest()
      .subarray(0, 16);
    if (!crypto.timingSafeEqual(tag, Buffer.from(pieces[4], 'base64url'))) {
      throw new Error('the authentication tag did not verify');
    }
    const decipher = crypto.createDecipheriv('aes-128-cbc', encKey, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
      .toString('utf8');
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;
    const JWT = 'application/token-introspection+jwt';

    const CLIENT_SECRET = 'r97-client-secret-0123456789abcdef';
    applications.createApplication({ identifier: 'r97-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'r97-client', oauthClientSecret: CLIENT_SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['client_credentials', 'password',
                                 'refresh_token'] } });
    const RS_SECRET = 'r97-resource-server-secret-abcdef0123';
    applications.createApplication({ identifier: 'r97-rs',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'r97-rs', oauthClientSecret: RS_SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_basic' } });
    const basic = 'Basic ' + Buffer.from('r97-rs:' + RS_SECRET)
      .toString('base64');

    let r = await request(port, 'POST', '/oauth2/token', { form: {
      grant_type: 'client_credentials', client_id: 'r97-client',
      client_secret: CLIENT_SECRET } });
    const token = r.json && r.json.access_token;
    note(r.status === 200 && token, '3a. a token to introspect was issued',
         r.status + ' ' + r.text.slice(0, 160));
    const jwks = (await request(port, 'GET', '/oauth2/jwks')).json;

    const introspect = function (headers, form, urlPath) {
      return request(port, 'POST', urlPath || '/oauth2/introspect',
                     { form: Object.assign({ token: token }, form || {}),
                       headers: headers || {} });
    };

    // --- RFC 7662, unchanged in development ---------------------------------
    r = await introspect({});
    note(r.status === 200 && r.json.active === true &&
         r.json.client_id === 'r97-client' &&
         /^application\/json/.test(r.headers['content-type']),
         '3b. development: anonymous JSON introspection is unchanged',
         r.status + ' ' + r.text.slice(0, 160));
    note(/Accept/.test(r.headers['vary'] || ''),
         '3c. the response varies on Accept', r.headers['vary']);

    // --- the JWT request must authenticate -----------------------------------
    r = await introspect({ accept: JWT });
    note(r.status === 400 && r.json.error === 'invalid_client' &&
         /RFC 9701 section 5/.test(r.json.error_description || ''),
         '3d. section 5: an anonymous JWT request is refused 400 ' +
         'invalid_client', r.status + ' ' + r.text.slice(0, 200));
    r = await introspect({ accept: JWT, authorization: 'Basic ' +
      Buffer.from('r97-rs:wrong').toString('base64') });
    note(r.status === 400 && r.json.error === 'invalid_client',
         '3e. a wrong secret is refused the same way',
         r.status + ' ' + r.text.slice(0, 160));
    r = await introspect({ accept: JWT }, { client_id: 'r97-client' });
    note(r.status === 400, '3f. a client_id with no credential is refused',
         r.status);

    // --- the JWT -------------------------------------------------------------
    r = await introspect({ accept: JWT, authorization: basic });
    note(r.status === 200 && r.headers['content-type'] === JWT,
         '3g. section 5: 200 with Content-Type exactly ' + JWT,
         r.status + ' ' + r.headers['content-type'] + ' ' +
         r.text.slice(0, 120));
    if (r.status === 200) {
      const head = part(r.text, 0);
      const claims = part(r.text, 1);
      note(head.typ === 'token-introspection+jwt' && head.alg === 'RS256',
           '3h. header typ token-introspection+jwt, alg RS256 by default',
           JSON.stringify(head));
      note(verifies(r.text, jwks), '3i. the signature verifies against ' +
           '/oauth2/jwks with this file\'s own verifier');
      note(claims.iss === BASE && claims.aud === 'r97-rs' &&
           typeof claims.iat === 'number' &&
           Math.abs(claims.iat - Date.now() / 1000) < 60,
           '3j. iss is this authorization server, aud the resource server, ' +
           'iat now', JSON.stringify(claims).slice(0, 200));
      note(!('sub' in claims) && !('exp' in claims),
           '3k. no sub and no exp at the top level');
      const inner = claims.token_introspection || {};
      note(inner.active === true && inner.client_id === 'r97-client' &&
           inner.jti && inner.token_type === 'Bearer',
           '3l. token_introspection is the RFC 7662 answer',
           JSON.stringify(inner).slice(0, 200));
    }
    r = await request(port, 'POST', '/oauth2/introspect', {
      form: { token: 'not-a-token' },
      headers: { accept: JWT, authorization: basic } });
    note(r.status === 200 &&
         JSON.stringify(part(r.text, 1).token_introspection) ===
           '{"active":false}',
         '3m. an inactive token: token_introspection is {"active":false} ' +
         'alone', r.text.slice(0, 120));
    r = await introspect({ accept: 'application/json, ' + JWT + ';q=0.2',
                           authorization: basic });
    note(r.status === 200 && r.json && r.json.active === true,
         '3n. JSON preferred in Accept is answered as JSON', r.text.slice(0,
                                                                          80));
    r = await introspect({ accept: JWT }, { client_id: 'r97-rs',
                                             client_secret: RS_SECRET });
    note(r.status === 200 && part(r.text, 1).aud === 'r97-rs',
         '3o. client_secret_post authenticates too — the token endpoint\'s ' +
         'methods, not only Basic', r.status);

    // --- what the resource server registers ----------------------------------
    let u = applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionSignedResponseAlg', mode: 'set',
      value: 'ES256' });
    note(u.ok, '3p. ES256 set through the registry', JSON.stringify(u));
    r = await introspect({ accept: JWT, authorization: basic });
    note(r.status === 200 && part(r.text, 0).alg === 'ES256' &&
         verifies(r.text, jwks),
         '3q. the response is ES256 and verifies with the published EC key',
         r.status + ' ' + r.text.slice(0, 120));
    applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionSignedResponseAlg', mode: 'set',
      value: 'HS256' });
    r = await introspect({ accept: JWT, authorization: basic });
    note(r.status === 200 && part(r.text, 0).alg === 'HS256' &&
         verifies(r.text, null, RS_SECRET) && !part(r.text, 0).kid,
         '3r. HS256 is keyed by the client secret and names no kid',
         r.status + ' ' + JSON.stringify(part(r.text, 0)));
    u = applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionSignedResponseAlg', mode: 'set',
      value: 'none' });
    note(!u.ok && require(ROOT + '/common/error_codes').codeOf(u) ===
         'STS-REG-0073', '3s. `none` is refused at the registry',
         JSON.stringify(u));
    u = applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionEncryptedResponseEnc', mode: 'set',
      value: 'A128CBC-HS256' });
    note(!u.ok, '3t. an enc onto an entry with no alg is refused',
         JSON.stringify(u));

    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const encJwk = Object.assign(pair.publicKey.export({ format: 'jwk' }),
                                 { kid: 'r97-enc', use: 'enc' });
    applications.updateApplication('r97-rs', { attribute: 'oauthJwks',
      mode: 'set', value: JSON.stringify({ keys: [encJwk] }) });
    applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionSignedResponseAlg', mode: 'set',
      value: '' });
    u = applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionEncryptedResponseAlg', mode: 'set',
      value: 'RSA-OAEP-256' });
    note(u.ok, '3u. RSA-OAEP-256 set', JSON.stringify(u));
    r = await introspect({ accept: JWT, authorization: basic });
    if (r.status === 200 && r.text.split('.').length === 5) {
      const outer = part(r.text, 0);
      note(outer.alg === 'RSA-OAEP-256' && outer.enc === 'A128CBC-HS256' &&
           outer.cty === 'JWT' && outer.typ === 'token-introspection+jwt' &&
           outer.kid === 'r97-enc',
           '3v. a Nested JWT: RSA-OAEP-256, the default enc, cty JWT, the ' +
           'typ, and the registered key\'s kid', JSON.stringify(outer));
      let inner = '';
      try {
        inner = decrypts(r.text, pair.privateKey);
      } catch (e) {
        inner = 'error: ' + e.message;
      }
      note(inner.split('.').length === 3 &&
           part(inner, 0).typ === 'token-introspection+jwt' &&
           verifies(inner, jwks) && part(inner, 1).aud === 'r97-rs',
           '3w. this file decrypts it to a signed JWT that verifies',
           inner.slice(0, 80));
    } else {
      note(false, '3v. an encrypted response was issued',
           r.status + ' ' + r.text.slice(0, 200));
    }

    // --- a registration nothing can honour (an ldapmodify's leftovers) -------
    applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionEncryptedResponseEnc', mode: 'set',
      value: 'A256GCM' });
    applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionEncryptedResponseAlg', mode: 'set',
      value: '' });
    r = await introspect({ accept: JWT, authorization: basic });
    note(r.status === 500 && r.json.error === 'server_error' &&
         /MUST NOT/.test(r.json.error_description || ''),
         '3x. an enc left without an alg: 500 with the reason, never an ' +
         'unencrypted response', r.status + ' ' + r.text.slice(0, 200));
    applications.updateApplication('r97-rs', {
      attribute: 'oauthIntrospectionEncryptedResponseEnc', mode: 'set',
      value: '' });

    // --- RFC 7591 ------------------------------------------------------------
    r = await request(port, 'POST', '/oauth2/register', { json: {
      client_name: 'r97 bad', grant_types: ['client_credentials'],
      introspection_signed_response_alg: 'none' } });
    note(r.status === 400 && r.json.error === 'invalid_client_metadata',
         '3y. registration naming `none` is invalid_client_metadata',
         r.status + ' ' + r.text.slice(0, 200));
    r = await request(port, 'POST', '/oauth2/register', { json: {
      client_name: 'r97 registered', grant_types: ['client_credentials'],
      token_endpoint_auth_method: 'client_secret_post',
      introspection_signed_response_alg: 'PS384' } });
    const registered = r.json || {};
    note((r.status === 201 || r.status === 200) && registered.client_id,
         '3z. a registration naming PS384 is accepted',
         r.status + ' ' + r.text.slice(0, 200));
    if (registered.client_id) {
      note(applications.clientConfigOf(registered.client_id)
             .introspection_signed_response_alg === 'PS384',
           '3aa. and lands on the entry\'s attribute');
      r = await request(port, 'POST', '/oauth2/introspect', {
        form: { token: token, client_id: registered.client_id,
                client_secret: registered.client_secret },
        headers: { accept: JWT } });
      note(r.status === 200 && part(r.text, 0).alg === 'PS384' &&
           part(r.text, 1).aud === registered.client_id,
           '3ab. and the registered client\'s response is PS384',
           r.status + ' ' + r.text.slice(0, 120));
    }

    // --- metadata and a named authorization server ---------------------------
    const meta = (await request(port, 'GET',
      '/.well-known/oauth-authorization-server')).json;
    note(Array.isArray(meta.introspection_signing_alg_values_supported) &&
         meta.introspection_signing_alg_values_supported.indexOf('RS256') >=
           0 &&
         meta.introspection_signing_alg_values_supported.indexOf('none') < 0 &&
         Array.isArray(meta.introspection_encryption_alg_values_supported) &&
         Array.isArray(meta.introspection_encryption_enc_values_supported) &&
         meta.introspection_encryption_enc_values_supported
           .indexOf('A128CBC-HS256') >= 0,
         '3ac. section 7: the three members are published',
         JSON.stringify(meta.introspection_encryption_alg_values_supported));
    note(meta.introspection_endpoint_auth_methods_supported &&
         meta.introspection_endpoint_auth_methods_supported
           .indexOf('client_secret_jwt') >= 0,
         '3ad. the introspection auth methods are the verifiable ones',
         JSON.stringify(meta.introspection_endpoint_auth_methods_supported));
    r = await introspect({ accept: JWT, authorization: basic }, {},
                         '/tenant9701/oauth2/introspect');
    note(r.status === 200 && part(r.text, 1).iss === BASE + '/tenant9701',
         '3ae. a named authorization server signs as its own issuer',
         r.status + ' ' + r.text.slice(0, 160));

    // --- 4. section 5's "intended for the resource server" -------------------
    const make = function (id, secret, fields) {
      applications.createApplication({ identifier: id, protocols: ['oauth2'],
        fields: Object.assign({ oauthClientId: id, oauthClientSecret: secret,
          oauthTokenEndpointAuthMethod: 'client_secret_post' }, fields) });
    };
    const asJwt = function (tokenValue, id, secret, urlPath) {
      return request(port, 'POST', urlPath || '/oauth2/introspect', {
        form: { token: tokenValue, client_id: id, client_secret: secret },
        headers: { accept: JWT } });
    };
    const activeIn = function (response) {
      return response.status === 200 &&
             part(response.text, 1).token_introspection.active === true;
    };
    make('r97-api', 'r97-api-secret-0123456789abcdef', {});
    make('r97-aud', 'r97-aud-secret-0123456789abcdef',
         { oauthAudience: ['https://api.r97.example/'] });
    make('r97-perm', 'r97-perm-secret-0123456789abcdef',
         { oauthPermissionBaseUri: 'https://perm.r97.example',
           oauthPermission: ['read|reads things'] });
    const tokenFor = async function (form) {
      const got = await request(port, 'POST', '/oauth2/token', { form:
        Object.assign({ client_id: 'r97-client',
                        client_secret: CLIENT_SECRET }, form) });
      return got.json || {};
    };
    const apiToken = (await tokenFor({ grant_type: 'client_credentials',
                                       scope: 'r97-api' })).access_token;
    note(apiToken && part(apiToken, 1).aud === 'r97-api',
         '4a. a token addressed to r97-api by its scope', apiToken &&
         JSON.stringify(part(apiToken, 1).aud));
    r = await asJwt(apiToken, 'r97-rs', RS_SECRET);
    note(r.status === 200 && JSON.stringify(part(r.text, 1)
           .token_introspection) === '{"active":false}',
         '4b. section 5: r97-rs asking about r97-api\'s token is told ' +
         '{"active":false} and nothing else', r.text.slice(0, 160));
    r = await asJwt(apiToken, 'r97-api', 'r97-api-secret-0123456789abcdef');
    note(activeIn(r), '4c. r97-api, named in aud by its client_id, is told ' +
         'it is active', r.status + ' ' + r.text.slice(0, 120));
    r = await asJwt(apiToken, 'r97-client', CLIENT_SECRET);
    note(activeIn(r), '4d. and the client holding the token may ask about ' +
         'its own token', r.status);
    r = await request(port, 'POST', '/oauth2/introspect',
                      { form: { token: apiToken } });
    note(r.status === 200 && r.json.active === true,
         '4e. an anonymous development JSON caller is NOT restricted — there ' +
         'is nobody to compare the token with', r.text.slice(0, 80));
    r = await request(port, 'POST', '/oauth2/introspect',
                      { form: { token: apiToken, client_id: 'r97-rs',
                                client_secret: RS_SECRET } });
    note(r.status === 200 && r.json.active === true,
         '4f. nor is a development JSON caller whose credential nothing ' +
         'checked', r.text.slice(0, 80));

    const audToken = (await tokenFor({ grant_type: 'client_credentials',
      resource: 'https://api.r97.example/' })).access_token;
    r = await asJwt(audToken, 'r97-aud', 'r97-aud-secret-0123456789abcdef');
    note(activeIn(r), '4g. an RFC 8707 resource matching the caller\'s ' +
         'oauthAudience is intended for it', r.status + ' ' +
         (audToken && JSON.stringify(part(audToken, 1).aud)));
    r = await asJwt(audToken, 'r97-api', 'r97-api-secret-0123456789abcdef');
    note(r.status === 200 && !activeIn(r),
         '4h. and not for another resource server', r.status);

    const permToken = (await tokenFor({ grant_type: 'client_credentials',
      scope: 'https://perm.r97.example/read' })).access_token;
    r = await asJwt(permToken, 'r97-perm', 'r97-perm-secret-0123456789abcdef');
    note(activeIn(r), '4i. a delegated permission\'s base URI names the ' +
         'resource that defines it, normalised', r.status + ' ' +
         (permToken && JSON.stringify(part(permToken, 1).aud)));

    // A resource written WITHOUT the separator is the same API base, and the
    // aud then carries it as written — the case where only normalising BOTH
    // sides finds the resource.
    const bareToken = (await tokenFor({ grant_type: 'client_credentials',
      resource: 'https://perm.r97.example' })).access_token;
    r = await asJwt(bareToken, 'r97-perm', 'r97-perm-secret-0123456789abcdef');
    note(activeIn(r) && part(bareToken, 1).aud === 'https://perm.r97.example',
         '4i2. and a resource naming that base without its trailing slash ' +
         'still names it', r.status + ' ' +
         (bareToken && JSON.stringify(part(bareToken, 1).aud)));

    const passwordGrant = await tokenFor({ grant_type: 'password',
      username: 'r97-alice', password: 'anything',
      scope: 'openid offline_access' });
    const refreshToken = passwordGrant.refresh_token;
    note(!!refreshToken, '4j. a refresh token to introspect was issued',
         JSON.stringify(Object.keys(passwordGrant)));
    if (refreshToken) {
      r = await asJwt(refreshToken, 'r97-rs', RS_SECRET);
      note(r.status === 200 && !activeIn(r),
           '4k. a refresh token is not a resource server\'s to ask about',
           r.text.slice(0, 120));
      r = await asJwt(refreshToken, 'r97-client', CLIENT_SECRET);
      note(activeIn(r) && part(r.text, 1).token_introspection.token_type ===
           'refresh_token', '4l. but its own client may', r.status);
    }

    // --- 5. a named authorization server narrows what it advertises ----------
    const servers = require(ROOT + '/oauth-oidc/authorization_servers');
    await request(port, 'GET',
                  '/.well-known/oauth-authorization-server/r97narrow');
    servers.setMember('r97narrow', 'introspection_signing_alg_values_supported',
                      '["PS256"]');
    r = await introspect({ accept: JWT, authorization: basic }, {},
                         '/r97narrow/oauth2/introspect');
    note(r.status === 400 && r.json.error === 'invalid_client' &&
         /PS256/.test(r.json.error_description || '') &&
         /default/.test(r.json.error_description || ''),
         '5a. a profile advertising only PS256 refuses a resource server on ' +
         'the RS256 default, 400, naming the list',
         r.status + ' ' + r.text.slice(0, 200));
    r = await introspect({ accept: JWT, authorization: basic });
    note(r.status === 200 && part(r.text, 0).alg === 'RS256',
         '5b. the default authorization server is unaffected', r.status);
    servers.setMember('r97narrow', 'introspection_signing_alg_values_supported',
                      '["RS256","PS256"]');
    servers.setMember('r97narrow',
                      'introspection_endpoint_auth_methods_supported',
                      '["private_key_jwt"]');
    r = await introspect({ accept: JWT, authorization: basic }, {},
                         '/r97narrow/oauth2/introspect');
    note(r.status === 400 && /private_key_jwt/.test(
           r.json.error_description || ''),
         '5c. a profile not advertising client_secret_basic refuses that ' +
         'client before its secret is read', r.status + ' ' +
         r.text.slice(0, 200));
    servers.removeMember('r97narrow',
                         'introspection_endpoint_auth_methods_supported');
    r = await introspect({ accept: JWT, authorization: basic }, {},
                         '/r97narrow/oauth2/introspect');
    note(r.status === 200 && part(r.text, 1).iss === BASE + '/r97narrow',
         '5d. a REMOVED member means the check does not run', r.status + ' ' +
         r.text.slice(0, 120));
    const narrowedMeta = (await request(port, 'GET',
      '/.well-known/oauth-authorization-server/r97narrow')).json;
    note(JSON.stringify(narrowedMeta
           .introspection_signing_alg_values_supported) ===
           '["RS256","PS256"]' &&
         !('introspection_endpoint_auth_methods_supported' in narrowedMeta),
         '5e. and the document says exactly what the endpoint did',
         JSON.stringify(narrowedMeta
           .introspection_signing_alg_values_supported));

    // --- 6. OAuth 2.1 section 2.4 at introspection ---------------------------
    const realms = require(ROOT + '/common/realms');
    const made = realms.create({ id: 'r97o21',
                                 overrides: { 'oauth2.oauth21': true } });
    note(made && made.ok !== false, '6a. a realm in OAuth 2.1 mode',
         JSON.stringify(made).slice(0, 200));
    r = await request(port, 'POST', '/realm/r97o21/oauth2/introspect', {
      form: { token: token, client_secret: RS_SECRET },
      headers: { authorization: basic } });
    note(r.status === 400 && r.json.error === 'invalid_request' &&
         /2\.4/.test(r.json.error_description || ''),
         '6b. OAuth 2.1: Basic AND a body secret on one introspection ' +
         'request is refused, even for a JSON request', r.status + ' ' +
         r.text.slice(0, 200));
    r = await request(port, 'POST', '/oauth2/introspect', {
      form: { token: token, client_secret: RS_SECRET },
      headers: { authorization: basic } });
    note(r.status === 200, '6c. and outside the mode the same request is ' +
         'answered', r.status);

    // --- 7. the crypto-metadata page reads the same lists --------------------
    const crypto_metadata = require(ROOT + '/admin-ui/crypto_metadata');
    const family = crypto_metadata.FAMILIES.filter(function (row) {
      return row.name === 'OAuth2 / OIDC';
    })[0];
    const groups = family ? family.algorithms() : [];
    const listed = function (what) {
      const row = groups.filter(function (one) { return one[0] === what; })[0];
      return row ? JSON.stringify(row[1]) : '(missing)';
    };
    note(listed('JWT introspection response (RFC 9701)') ===
           JSON.stringify(meta.introspection_signing_alg_values_supported) &&
         listed('JWT introspection response encryption (RFC 9701)') ===
           JSON.stringify(meta.introspection_encryption_alg_values_supported),
         '7a. /admin/crypto-metadata lists the introspection algorithms the ' +
         'discovery document advertises', listed(
           'JWT introspection response (RFC 9701)').slice(0, 80));

    // --- product mode --------------------------------------------------------
    config.setOverride('global.mode', 'product');
    try {
      r = await introspect({});
      note(r.status === 401 && r.json.error === 'invalid_client',
           '3af. product: anonymous JSON introspection is refused 401',
           r.status + ' ' + r.text.slice(0, 200));
      r = await introspect({ authorization: basic });
      note(r.status === 200 && r.json.active === true,
           '3ag. product: an authenticated JSON request is answered',
           r.status + ' ' + r.text.slice(0, 120));
      r = await request(port, 'POST', '/oauth2/introspect', {
        form: { token: apiToken }, headers: { authorization: basic } });
      note(r.status === 200 && JSON.stringify(r.json) === '{"active":false}',
           '3ah. product: the JSON answer is restricted like the JWT — ' +
           'r97-api\'s token is {"active":false} to r97-rs',
           r.status + ' ' + r.text.slice(0, 120));
    } finally {
      config.clearOverride('global.mode');
    }

    server.close();
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
  const out = path.join(os.tmpdir(), 'rfc9701-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', R97_ROOT: ROOT, R97_OUT: out }),
      encoding: 'utf8', timeout: 180000, cwd: ROOT
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
  name: 'rfc9701 introspection',
  describe: 'the JWT introspection response: Accept, authentication, typ, ' +
            'claims, signing and encryption as registered, and the metadata',
  run: run
};
