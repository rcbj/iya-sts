'use strict';
//
// File: oidc_registration.js
//
// ===========================================================================
// OPENID CONNECT DYNAMIC CLIENT REGISTRATION, RFC 7591 / 7592's GAPS, AND A
// FETCHED `jwks_uri` (#120, 2026-09-22).
//
// `oauth-oidc/CLAUDE.md`, *OpenID Connect Registration*, argues the design.
// What is held here:
//
//   1. THE LIBRARY: `applications.oidcRegistrationProblem()` for every rule
//      (REG-0181..0188), `registeredFlowsOf()` reading the registration and
//      not the sightings, `initiateLoginUriOf()`, and `step_up.ts`'s
//      registered defaults each overridden by the request's own.
//   2. THE ENDPOINTS, in a child process on an ephemeral loopback port, with
//      a SECOND listener playing the clients' key host:
//        a. registration returns section 2's defaults, and refuses by name;
//        b. RFC 7592: the client_id and client_secret an update names, and
//           401 invalid_token for a client that no longer exists, whose
//           token is then revoked; the per-server routes exist;
//        c. a registered response_types and grant_types ENFORCED;
//        d. a client assertion verified against a fetched jwks_uri, the set
//           cached, fetched again for a new kid, and refused when the address
//           answers nothing usable or redirects;
//        e. a registration asking for an encrypted ID Token whose jwks_uri
//           gives no key is refused, naming the fetch; the encryption key
//           reader finds a fetched set.
//
// **THE CHILD** is `tests/rfc9068_access_tokens.js`'s reason: the protocol
// stack registers every route on the shared app and builds a CA.
// **THE SIGNER IS WRITTEN HERE**, for `sts_dpop.js`'s reason.
//
// Not over HTTP against a container (tests/CLAUDE.md's rule 3): the fetch
// needs a key host the service can reach, and product mode refuses every
// address a test could offer it.
// ===========================================================================

delete process.env.CONFIG_FILE;

const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'oidc_registration',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// 1. THE LIBRARY.
// ---------------------------------------------------------------------------
function library(t) {
  log.debug("Entering library().");
  t.log.info('=== 1. the library ===');
  const applications = require('../common/applications');
  const stepUp = require('../oauth-oidc/step_up');
  const problem = function (metadata) {
    const found = applications.oidcRegistrationProblem(metadata);
    return found ? found.errorCode : '';
  };
  const WEB = { redirect_uris: ['https://rp.example/cb'] };
  const cases = [
    [{}, '', 'client_credentials alone, response_types omitted, needs no ' +
     'redirect URI and defaults to no response type',
     { grant_types: ['client_credentials'] }],
    [{ grant_types: ['authorization_code', 'refresh_token'],
       response_types: ['code', 'code id_token'],
       redirect_uris: ['https://rp.example/cb'] }, '',
     'code id_token without the implicit grant (FAPI 1.0 Advanced\'s hybrid)'],
    [{ grant_types: ['authorization_code'],
       response_types: ['code token'],
       redirect_uris: ['https://rp.example/cb'] }, 'STS-REG-0183',
     'a response type returning an access token without the implicit grant'],
    [WEB, '', 'a plain web client'],
    [{ application_type: 'desktop' }, 'STS-REG-0181', 'an unknown ' +
     'application_type'],
    [{ application_type: 'native',
       redirect_uris: ['https://rp.example/cb'] }, 'STS-REG-0182',
     'a native client with an https redirect URI'],
    [{ application_type: 'native',
       redirect_uris: ['http://rp.example/cb'] }, 'STS-REG-0182',
     'a native client with a non-loopback http redirect URI'],
    [{ application_type: 'native',
       redirect_uris: ['http://127.0.0.1:8080/cb',
                       'com.example.app:/cb'] }, '',
     'a native client on the loopback and a private-use scheme'],
    [{ grant_types: ['implicit'], response_types: ['id_token'],
       redirect_uris: ['http://localhost/cb'] }, 'STS-REG-0182',
     'an implicit web client on localhost'],
    [{ grant_types: ['client_credentials'], response_types: ['code'],
       redirect_uris: ['https://rp.example/cb'] }, 'STS-REG-0183',
     'response_types code without the authorization_code grant'],
    [{ grant_types: ['authorization_code'] }, 'STS-REG-0184',
     'the authorization_code grant with no redirect_uris'],
    [Object.assign({ id_token_signed_response_alg: 'XX512' }, WEB),
     'STS-REG-0185', 'an ID Token algorithm this service does not sign with'],
    [Object.assign({ userinfo_signed_response_alg: 'none' }, WEB), '',
     'UserInfo unsigned, which section 2 allows'],
    [Object.assign({ jwks: { keys: [] },
                     jwks_uri: 'https://rp.example/jwks' }, WEB),
     'STS-REG-0186', 'jwks together with jwks_uri'],
    [Object.assign({ jwks_uri: 'http://rp.example/jwks' }, WEB),
     'STS-REG-0186', 'a jwks_uri that is not https'],
    [Object.assign({ default_max_age: -5 }, WEB), 'STS-REG-0187',
     'a negative default_max_age'],
    [Object.assign({ require_auth_time: 'yes' }, WEB), 'STS-REG-0187',
     'require_auth_time that is not a boolean'],
    [Object.assign({ default_acr_values: 'mfa' }, WEB), 'STS-REG-0187',
     'default_acr_values that is not an array'],
    [Object.assign({ initiate_login_uri: 'http://rp.example/login' }, WEB),
     'STS-REG-0188', 'an http initiate_login_uri'],
    [Object.assign({ initiate_login_uri: 'https://rp.example/login',
                     default_max_age: 300, require_auth_time: true,
                     default_acr_values: ['mfa', '1'] }, WEB), '',
     'every member well formed']
  ];
  cases.forEach(function (one) {
    const metadata = Object.assign({}, one[3] || {}, one[0]);
    t.check(problem(metadata) === one[1], '1a. ' + one[2] + ' → ' +
            (one[1] || 'accepted'), 'got ' + (problem(metadata) || 'accepted'));
  });

  const lists = applications.grantsAndResponseTypesOf({
    grant_types: ['client_credentials'] });
  t.check(lists.response_types.length === 0 &&
            applications.grantsAndResponseTypesOf({}).response_types[0] ===
              'code',
          '1a. response_types defaults to code only beside a redirect grant',
          JSON.stringify(lists));

  const withLogin = { fields: { appRegistrationJson: JSON.stringify({
    initiate_login_uri: 'https://rp.example/login?x=1' }) } };
  const httpLogin = { fields: { appRegistrationJson: JSON.stringify({
    initiate_login_uri: 'http://rp.example/login' }) } };
  t.check(applications.initiateLoginUriOf(withLogin) ===
            'https://rp.example/login?x=1' &&
          applications.initiateLoginUriOf(httpLogin) === '' &&
          applications.initiateLoginUriOf({ fields: {} }) === '' &&
          applications.initiateLoginUriOf({ fields: {
            appRegistrationJson: '{not json' } }) === '',
          '1b. initiateLoginUriOf() answers an https value and nothing else, ' +
          'whatever an ldapmodify left');

  const registered = { default_acr_values: ['mfa'], default_max_age: 60 };
  const bare = stepUp.requirementOf({}, registered);
  t.check(bare.acrValues.join(' ') === 'mfa' && bare.maxAge === 60 &&
            bare.present,
          '1c. a request naming neither gets the registered defaults',
          JSON.stringify(bare));
  const own = stepUp.requirementOf({ acr_values: '1', max_age: '5' },
                                   registered);
  t.check(own.acrValues.join(' ') === '1' && own.maxAge === 5,
          '1d. the request\'s own acr_values and max_age override them',
          JSON.stringify(own));
  const half = stepUp.requirementOf({ max_age: '5' }, registered);
  t.check(half.acrValues.join(' ') === 'mfa' && half.maxAge === 5,
          '1e. each default is overridden only by its own parameter',
          JSON.stringify(half));
  const none = stepUp.requirementOf({}, null);
  t.check(!none.present, '1f. no registration, no requirement');
  log.debug("Leaving library().");
}

// ---------------------------------------------------------------------------
// 2. THE ENDPOINTS, IN A CHILD.
// ---------------------------------------------------------------------------
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.OR_ROOT;
  const OUT = process.env.OR_OUT;
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
  function signEs256(payload, key, kid) {
    const input = b64({ alg: 'ES256', typ: 'JWT', kid: kid }) + '.' +
                  b64(payload);
    const signature = crypto.sign('sha256', Buffer.from(input),
                                  { key: key, dsaEncoding: 'ieee-p1363' });
    return input + '.' + signature.toString('base64url');
  }
  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      const body = o.json !== undefined ? JSON.stringify(o.json)
        : (o.form ? new URLSearchParams(o.form).toString() : '');
      const headers = Object.assign({}, o.headers || {});
      if (method !== 'GET' && method !== 'DELETE') {
        headers['content-type'] = o.json !== undefined ? 'application/json'
          : 'application/x-www-form-urlencoded';
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
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
      req.end(method === 'GET' || method === 'DELETE' ? undefined : body);
    });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const applications = require(ROOT + '/common/applications');
    const config = require(ROOT + '/common/config');
    const clientJwks = require(ROOT + '/oauth-oidc/client_jwks');
    const introspectionJwt = require(ROOT + '/oauth-oidc/introspection_jwt');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const BASE = 'http://127.0.0.1:' + port;

    // THE KEY HOST: the clients' own server for jwks_uri, counting fetches.
    const k1 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const k2 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const enc = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwkOf = function (pair, kid, use) {
      return Object.assign(pair.publicKey.export({ format: 'jwk' }),
                           { kid: kid, use: use || 'sig' });
    };
    let served = { keys: [jwkOf(k1, 'k1')] };
    const hits = {};
    const keyHost = http.createServer(function (req, res) {
      hits[req.url] = (hits[req.url] || 0) + 1;
      if (req.url === '/jwks') {
        res.writeHead(200, { 'content-type': 'application/jwk-set+json' });
        return res.end(JSON.stringify(served));
      }
      if (req.url === '/enc-jwks') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ keys: [jwkOf(enc, 'e1', 'enc')] }));
      }
      if (req.url === '/not-a-set') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('{"hello":"world"}');
      }
      if (req.url === '/redirect') {
        res.writeHead(302, { location: '/jwks' });
        return res.end();
      }
      res.writeHead(404);
      return res.end();
    });
    await new Promise(function (r) { keyHost.listen(0, '127.0.0.1', r); });
    const KEYS = 'http://127.0.0.1:' + keyHost.address().port;

    config.setOverride('oauth2.consentRequired', false);
    // The key host is plain http on the loopback; development mode dials an
    // internal address, and this lets it dial http.
    config.setOverride('federation.outboundAllowInsecure', true);

    // --- a. registration ---------------------------------------------------
    let r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://rp.or.example/cb'],
                client_name: 'OR minimal' } });
    const minimal = r.json || {};
    note(r.status === 201 &&
           minimal.token_endpoint_auth_method === 'client_secret_basic' &&
           JSON.stringify(minimal.grant_types) === '["authorization_code"]' &&
           JSON.stringify(minimal.response_types) === '["code"]' &&
           minimal.application_type === 'web',
         '2a. a registration is answered with section 2\'s defaults applied',
         r.status + ' ' + r.text.slice(0, 300));
    const refusals = [
      [{ application_type: 'desktop',
         redirect_uris: ['https://rp.or.example/cb'] },
       'invalid_client_metadata', 'an unknown application_type'],
      [{ application_type: 'native',
         redirect_uris: ['https://rp.or.example/cb'] },
       'invalid_redirect_uri', 'a native client\'s https redirect URI'],
      [{ grant_types: ['client_credentials'], response_types: ['code'],
         redirect_uris: ['https://rp.or.example/cb'] },
       'invalid_client_metadata', 'grant and response types that disagree'],
      [{ redirect_uris: ['https://rp.or.example/cb'],
         jwks_uri: 'http://rp.or.example/jwks' },
       'invalid_client_metadata', 'an http jwks_uri'],
      [{ redirect_uris: ['https://rp.or.example/cb'],
         initiate_login_uri: 'http://rp.or.example/login' },
       'invalid_client_metadata', 'an http initiate_login_uri']
    ];
    for (const one of refusals) {
      r = await request(port, 'POST', '/oauth2/register', { json: one[0] });
      note(r.status === 400 && r.json && r.json.error === one[1],
           '2a. refused ' + one[1] + ': ' + one[2],
           r.status + ' ' + r.text.slice(0, 200));
    }
    r = await request(port, 'POST', '/oauth2/register',
      { json: { application_type: 'native',
                redirect_uris: ['http://127.0.0.1:9/cb'] } });
    note(r.status === 201 && r.json.application_type === 'native',
         '2a. a native client on the loopback is registered',
         r.status + ' ' + r.text.slice(0, 200));

    // --- b. RFC 7592 -------------------------------------------------------
    const manage = function (method, client, opts) {
      return request(port, method, '/oauth2/register/' +
                     encodeURIComponent(client.client_id),
                     Object.assign({ headers: { authorization: 'Bearer ' +
                       client.registration_access_token } }, opts || {}));
    };
    r = await manage('GET', minimal);
    note(r.status === 200 && r.json.client_id === minimal.client_id &&
           r.json.grant_types && r.json.response_types,
         '2b. the read returns the registration, defaults included',
         r.status + ' ' + r.text.slice(0, 200));
    r = await manage('PUT', minimal, { json: {
      client_id: 'somebody-else',
      redirect_uris: ['https://rp.or.example/cb'] } });
    note(r.status === 400 && r.json.error === 'invalid_request',
         '2b. an update naming another client_id is refused (section 2.2)',
         r.status + ' ' + r.text.slice(0, 200));
    r = await manage('PUT', minimal, { json: {
      client_id: minimal.client_id, client_secret: 'not-the-one',
      redirect_uris: ['https://rp.or.example/cb'] } });
    note(r.status === 400 && r.json.error === 'invalid_request',
         '2b. an update naming a client_secret it was not issued is refused',
         r.status + ' ' + r.text.slice(0, 200));
    r = await manage('PUT', minimal, { json: {
      client_id: minimal.client_id,
      redirect_uris: ['https://rp.or.example/cb2'] } });
    note(r.status === 200 && r.json.token_endpoint_auth_method ===
           'client_secret_basic' &&
           JSON.stringify(r.json.redirect_uris) ===
             '["https://rp.or.example/cb2"]',
         '2b. a well-formed update is answered with the defaults applied',
         r.status + ' ' + r.text.slice(0, 200));
    r = await request(port, 'GET', '/or1/oauth2/register/' +
                      encodeURIComponent(minimal.client_id),
                      { headers: { authorization: 'Bearer nope' } });
    note(r.status !== 404,
         '2b. the management routes exist under a named authorization server',
         r.status + ' ' + r.text.slice(0, 120));
    // A client removed by hand: its token is revoked and the answer is 401.
    r = await request(port, 'POST', '/oauth2/register',
      { json: { redirect_uris: ['https://rp.or.example/cb'] } });
    const doomed = r.json || {};
    applications.deleteApplication(doomed.client_id);
    r = await manage('GET', doomed);
    note(r.status === 401 && r.json.error === 'invalid_token' &&
           /invalid_token/.test(String(r.headers['www-authenticate'] || '')),
         '2b. a registration access token for a client that no longer exists ' +
         'is 401 invalid_token (section 3)',
         r.status + ' ' + r.text.slice(0, 200) + ' ' +
         r.headers['www-authenticate']);

    // --- c. enforcement ----------------------------------------------------
    r = await request(port, 'GET', '/oauth2/authorize?' + new URLSearchParams({
      client_id: minimal.client_id, response_type: 'code id_token',
      redirect_uri: 'https://rp.or.example/cb2', scope: 'openid',
      nonce: 'n-1', state: 's-1', code_challenge_method: 'S256',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    }).toString());
    const location = String(r.headers.location || '');
    note(r.status === 302 && /error=unauthorized_client/.test(location),
         '2c. a response_type the client did not register is ' +
         'unauthorized_client, redirected',
         r.status + ' ' + location.slice(0, 200) + ' ' + r.text.slice(0, 200));
    r = await request(port, 'POST', '/oauth2/token', {
      form: { grant_type: 'client_credentials' },
      headers: { authorization: 'Basic ' + Buffer.from(
        encodeURIComponent(minimal.client_id) + ':' +
        encodeURIComponent(minimal.client_secret)).toString('base64') } });
    note(r.status === 400 && r.json.error === 'unauthorized_client',
         '2c. a grant the client did not register is unauthorized_client',
         r.status + ' ' + r.text.slice(0, 200));

    // --- d. a fetched jwks_uri ---------------------------------------------
    // THE RFC 7523 GRANT, not client authentication: development mode
    // observes a client assertion that fails rather than refusing it, and the
    // grant's signature is verified in every mode. The issuer is declared.
    const makeKeyed = function (id, uri) {
      applications.createApplication({ identifier: id, protocols: ['oauth2'],
        fields: { oauthClientId: id, oauthJwksUri: uri,
                  oauthAssertionIssuer: id } });
    };
    makeKeyed('or-keyed', KEYS + '/jwks');
    makeKeyed('or-empty', KEYS + '/not-a-set');
    makeKeyed('or-moved', KEYS + '/redirect');
    const assertionFor = function (id, pair, kid) {
      const now = Math.floor(Date.now() / 1000);
      return signEs256({ iss: id, sub: 'or-person',
                         aud: BASE + '/oauth2/token',
                         jti: crypto.randomBytes(12).toString('hex'),
                         iat: now, exp: now + 120 }, pair.privateKey, kid);
    };
    const tokenWith = function (id, pair, kid) {
      return request(port, 'POST', '/oauth2/token', { form: {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: assertionFor(id, pair, kid) } });
    };
    r = await tokenWith('or-keyed', k1, 'k1');
    note(r.status === 200 && r.json.access_token && hits['/jwks'] === 1,
         '2d. an RFC 7523 assertion verifies against the fetched jwks_uri',
         r.status + ' hits=' + hits['/jwks'] + ' ' + r.text.slice(0, 200));
    r = await tokenWith('or-keyed', k1, 'k1');
    note(r.status === 200 && hits['/jwks'] === 1,
         '2d. and the set is cached: a second request fetches nothing',
         r.status + ' hits=' + hits['/jwks']);
    served = { keys: [jwkOf(k1, 'k1'), jwkOf(k2, 'k2')] };
    r = await tokenWith('or-keyed', k2, 'k2');
    note(r.status === 400 && hits['/jwks'] === 1,
         '2d. a new kid within oauth2.clientJwksRefetchS is not fetched for',
         r.status + ' hits=' + hits['/jwks']);
    config.setOverride('oauth2.clientJwksRefetchS', 0);
    r = await tokenWith('or-keyed', k2, 'k2');
    note(r.status === 200 && hits['/jwks'] === 2,
         '2d. past it, a kid the cached set lacks fetches the set again',
         r.status + ' hits=' + hits['/jwks'] + ' ' + r.text.slice(0, 200));
    r = await tokenWith('or-empty', k1, 'k1');
    note(r.status === 400 && r.json.error === 'invalid_grant',
         '2d. a jwks_uri answering no key set is invalid_grant',
         r.status + ' ' + r.text.slice(0, 200));
    r = await tokenWith('or-moved', k1, 'k1');
    note(r.status === 400 && hits['/redirect'] === 1 &&
           (hits['/jwks'] || 0) === 2,
         '2d. a redirect is not followed (the outbound policy)',
         r.status + ' ' + JSON.stringify(hits));
    config.setOverride('federation.outboundAllowInsecure', false);
    const before = hits['/jwks'];
    const refused = await clientJwks.ensure(KEYS + '/jwks?fresh', '');
    note(!refused.ok && hits['/jwks'] === before,
         '2d. with federation.outboundAllowInsecure off an http jwks_uri is ' +
         'never dialled', JSON.stringify(refused));
    config.setOverride('federation.outboundAllowInsecure', true);

    // --- e. an encrypted response's key ------------------------------------
    r = await request(port, 'POST', '/oauth2/register', { json: {
      redirect_uris: ['https://rp.or.example/cb'],
      jwks_uri: 'https://127.0.0.1:1/jwks',
      id_token_encrypted_response_alg: 'RSA-OAEP-256' } });
    note(r.status === 400 && r.json.error === 'invalid_client_metadata' &&
           /could not be fetched/.test(String(r.json.error_description)),
         '2e. an encrypted ID Token whose jwks_uri gives no key is refused, ' +
         'naming the fetch', r.status + ' ' + r.text.slice(0, 300));
    const fetched = await clientJwks.ensure(KEYS + '/enc-jwks', '');
    let key = null;
    try {
      key = introspectionJwt.recipientKey({ jwks_uri: KEYS + '/enc-jwks' },
        'RSA-OAEP-256', 'id_token_encrypted_response_alg');
    } catch (e) {
      key = { error: e.message };
    }
    note(fetched.ok && key && key.kid === 'e1',
         '2e. the encryption key reader finds a fetched set',
         JSON.stringify(key).slice(0, 200));

    server.close();
    keyHost.close();
    fs.writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    note(false, 'the child threw', e && e.stack ? e.stack : e);
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  t.log.info('=== 2. the endpoints, in a child process ===');
  const out = path.join(os.tmpdir(), 'oidc-registration-' + process.pid + '-' +
                        Math.random().toString(36).slice(2) + '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', 'const fs = require("fs");\n(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', OR_ROOT: ROOT, OR_OUT: out }),
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
  t.check(findings.length >= 20, 'the child ran every section',
          findings.length + ' finding(s)');
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  library(t);
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oidc registration',
  describe: 'OpenID Connect Registration and RFC 7591/7592 (#120): the ' +
            'metadata rules, enforced grant and response types, RFC 7592\'s ' +
            'binding, and a fetched jwks_uri',
  run: run
};
