// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/oauth_model_wire.js
//
// ---------------------------------------------------------------------------
// WHAT THE OAUTH 2.0 AND OPENID CONNECT ENDPOINTS ANSWER, HELD BYTE FOR BYTE
// (#1579 item 6).
//
// The request parameters of every endpoint, the members of the discovery
// documents and of every answer, the error codes and the claim sets of what
// this service issues come from `models/oauth/oauth.tsp` since #1579. Before
// the switch the request validators were written by hand in
// `oauth-oidc/oauth2.ts`, and the switch was to change NOTHING a client sees:
// the model describes and validates the wire, it does not reshape it. So this
// records what the hand-written version answered, in
// `tests/oauth_model_wire.snapshot.json`, and holds every later build to it:
// a scripted conversation with every endpoint — its success where one can be
// had without a browser, and its refusals — in the four modes that change a
// refusal: development (the default realm), RFC 9700 mode, OAuth 2.1 mode and
// the FAPI 2.0 Security Profile, each a realm of its own.
//
// What is recorded of each answer: the status, every header but the ones that
// are about the connection (`date`, `connection`, `keep-alive`,
// `content-length`, `etag`), and the body — parsed when it is JSON, as text
// otherwise. A JWT is DECODED, header and claims, and its signature dropped,
// so the claim set an issuer produced is held too, member by member.
//
// Values that differ from run to run are replaced by a placeholder: an
// instant, a port, a UUID (numbered in order of appearance), a key's material
// and id, every random credential this service hands out (by member name),
// and any run of 32 or more base64url characters left after that. The
// comparison is of everything else, exactly.
//
// `OAUTH_WIRE_PRINT=1 node tests/oauth_model_wire.js` prints the snapshot
// instead of comparing it; that is how the file was written, from the image
// of the tree before the switch, and how it is rewritten when the wire is
// MEANT to change.
//
// A CHILD PROCESS, as tests/scim_model_wire.js runs one: the protocol stack
// and a listener are loaded once, fresh, and nothing leaks into the runner.
// ---------------------------------------------------------------------------

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'oauth_model_wire',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');
const SNAPSHOT = path.join(__dirname, 'oauth_model_wire.snapshot.json');

// The child's whole program, serialised with toString() and run by `node -e`
// — so it may use nothing from this file's scope, and (root CLAUDE.md, Code
// style) it is exempt from the Entering/Leaving rule and carries its errors
// on the result it writes.
function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.OW_ROOT;
  const OUT = process.env.OW_OUT;
  const http = require('http');
  const record = { wire: [], problems: [] };

  const SKIPPED_HEADERS = ['date', 'connection', 'keep-alive',
                           'content-length', 'etag', 'transfer-encoding'];

  function request(port, method, urlPath, opts) {
    const o = opts || {};
    return new Promise(function (resolve) {
      let body = '';
      const headers = Object.assign({}, o.headers || {});
      if (o.form !== undefined) {
        body = typeof o.form === 'string' ? o.form
          : new URLSearchParams(o.form).toString();
        headers['content-type'] = 'application/x-www-form-urlencoded';
      } else if (o.json !== undefined) {
        body = typeof o.json === 'string' ? o.json : JSON.stringify(o.json);
        headers['content-type'] = 'application/json';
      }
      if (body) {
        headers['content-length'] = Buffer.byteLength(body);
      }
      const req = http.request({ host: '127.0.0.1', port: port, path: urlPath,
                                 method: method, headers: headers },
                               function (res) {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', function (c) {
          text += c;
        });
        res.on('end', function () {
          let parsed;
          const type = String(res.headers['content-type'] || '');
          if (/json/.test(type) && text) {
            try {
              parsed = JSON.parse(text);
            } catch (e) {
              parsed = { unparsed: text };
            }
          } else {
            parsed = text;
          }
          const kept = {};
          Object.keys(res.headers).sort().forEach(function (name) {
            if (SKIPPED_HEADERS.indexOf(name) < 0) {
              kept[name] = res.headers[name];
            }
          });
          resolve({ status: res.statusCode, headers: kept, body: parsed });
        });
      });
      req.on('error', function (e) {
        resolve({ status: 0, headers: {}, body: String(e && e.message) });
      });
      req.end(body);
    });
  }

  function basic(id, secret) {
    return 'Basic ' + Buffer.from(encodeURIComponent(id) + ':' +
                                  encodeURIComponent(secret))
      .toString('base64');
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const realms = require(ROOT + '/common/realms');
    const applications = require(ROOT + '/common/applications');
    const ldap = require(ROOT + '/ldap/ldap_server');

    const server = http.createServer(app);
    await new Promise(function (r) {
      server.listen(0, '127.0.0.1', r);
    });
    const port = server.address().port;

    config.setOverride('oauth2.consentRequired', 'false');
    config.setOverride('oauth2.deviceAuthorization', 'true');
    config.setOverride('oauth2.ciba', 'true');

    const SECRET = 'wire-client-secret-0123456789abcdef0123456789';
    const REDIRECT = 'https://rp.wire.example/cb';
    const LOGGED_OUT = 'https://rp.wire.example/bye';
    const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    const MODES = [
      { name: 'development', id: null, overrides: null },
      { name: 'rfc9700', id: 'wire9700',
        overrides: { 'oauth2.rfc9700': true } },
      { name: 'oauth21', id: 'wire21',
        overrides: { 'oauth2.oauth21': true } },
      { name: 'fapi2', id: 'wirefapi',
        overrides: { 'oauth2.fapi': '2-security' } }
    ];

    for (let m = 0; m < MODES.length; m++) {
      const mode = MODES[m];
      let realm = realms.DEFAULT_REALM;
      if (mode.id) {
        const made = realms.create({ id: mode.id, name: mode.id,
                                     description: 'oauth_model_wire.js',
                                     overrides: mode.overrides });
        if (!made.ok) {
          record.problems.push(mode.name + ': ' +
                               JSON.stringify(made.errors || made));
          continue;
        }
        realm = realms.get(mode.id);
      }
      const P = mode.id ? '/realm/' + mode.id : '';
      realms.run(realm, function () {
        ldap.createUser('wire-user', { invent: false });
        const make = function (id, fields) {
          return applications.createApplication({ identifier: id,
            protocols: ['oauth2'],
            fields: Object.assign({ oauthClientId: id,
              oauthClientSecret: SECRET,
              oauthRedirectUri: [REDIRECT],
              oauthPostLogoutRedirectUri: [LOGGED_OUT],
              oauthTokenEndpointAuthMethod: 'client_secret_basic' },
                                  fields || {}) });
        };
        make('wire-conf');
        make('wire-pub', { oauthTokenEndpointAuthMethod: 'none',
                           oauthClientSecret: '' });
        applications.updateApplication('wire-pub', {
          attribute: 'oauthClientSecret', mode: 'set', value: '' });
      });

      const AUTH = { authorization: basic('wire-conf', SECRET) };
      const step = async function (name, method, p, opts) {
        const r = await request(port, method, P + p, opts);
        record.wire.push({ mode: mode.name, step: name, method: method,
                           path: p, status: r.status, headers: r.headers,
                           body: r.body });
        return r;
      };
      const q = function (params) {
        return '?' + new URLSearchParams(params).toString();
      };
      const goodAuthorize = { response_type: 'code', client_id: 'wire-conf',
        redirect_uri: REDIRECT, scope: 'openid profile', state: 'st-fixed',
        nonce: 'n-fixed', code_challenge: CHALLENGE,
        code_challenge_method: 'S256' };
      const authorize = function (extra) {
        return Object.assign({}, goodAuthorize, extra || {});
      };

      // DISCOVERY.
      await step('openid-configuration', 'GET',
                 '/.well-known/openid-configuration');
      await step('oauth-authorization-server', 'GET',
                 '/.well-known/oauth-authorization-server');
      await step('jwks', 'GET', '/oauth2/jwks');
      await step('rfc9700 report', 'GET', '/oauth2/rfc9700');
      await step('oauth21 report', 'GET', '/oauth2/oauth21');
      await step('fapi report', 'GET', '/oauth2/fapi');

      // THE AUTHORIZATION ENDPOINT.
      await step('authorize, nothing', 'GET', '/oauth2/authorize');
      await step('authorize, an unknown client', 'GET', '/oauth2/authorize' +
                 q(authorize({ client_id: 'wire-nobody' })));
      await step('authorize, to sign-in', 'GET', '/oauth2/authorize' +
                 q(authorize()));
      await step('authorize, POST to sign-in', 'POST', '/oauth2/authorize',
                 { form: authorize() });
      await step('authorize, an unregistered redirect_uri', 'GET',
                 '/oauth2/authorize' +
                 q(authorize({ redirect_uri: 'https://evil.example/cb' })));
      await step('authorize, redirect_uri twice', 'GET', '/oauth2/authorize' +
                 q(authorize()) + '&redirect_uri=' +
                 encodeURIComponent(REDIRECT));
      await step('authorize, a structured scope', 'GET', '/oauth2/authorize' +
                 q(authorize({ scope: undefined })).replace('scope=undefined',
                                                            'scope[a]=b'));
      await step('authorize, a malformed scope', 'GET', '/oauth2/authorize' +
                 q(authorize({ scope: 'openid "x"' })));
      await step('authorize, a short code_challenge', 'GET',
                 '/oauth2/authorize' + q(authorize({ code_challenge: 'abc' })));
      await step('authorize, max_age not a number', 'GET',
                 '/oauth2/authorize' + q(authorize({ max_age: 'soon' })));
      await step('authorize, max_age negative', 'GET',
                 '/oauth2/authorize' + q(authorize({ max_age: '-1' })));
      await step('authorize, a bad domain_hint', 'GET', '/oauth2/authorize' +
                 q(authorize({ domain_hint: 'a b' })));
      await step('authorize, a control character in state', 'GET',
                 '/oauth2/authorize' + q(authorize({ state: 'a\nb' })));
      await step('authorize, an overlong response_mode', 'GET',
                 '/oauth2/authorize' +
                 q(authorize({ response_mode: 'x'.repeat(65) })));
      await step('authorize, response_type token', 'GET',
                 '/oauth2/authorize' + q(authorize({ response_type: 'token',
                                                     code_challenge: '',
                                                     code_challenge_method:
                                                       '' })));
      await step('authorize, no PKCE', 'GET', '/oauth2/authorize' +
                 q(authorize({ code_challenge: '',
                               code_challenge_method: '' })));
      await step('authorize, PKCE plain', 'GET', '/oauth2/authorize' +
                 q(authorize({ code_challenge: VERIFIER,
                               code_challenge_method: 'plain' })));
      await step('authorize, a bad dpop_jkt', 'GET', '/oauth2/authorize' +
                 q(authorize({ dpop_jkt: 'not base64url!' })));
      await step('authorize, resource twice', 'GET', '/oauth2/authorize' +
                 q(authorize()) + '&resource=https%3A%2F%2Fa.example%2F' +
                 '&resource=https%3A%2F%2Fb.example%2F');
      await step('authorize, a javascript resource', 'GET',
                 '/oauth2/authorize' +
                 q(authorize({ resource: 'javascript:alert(1)' })));
      await step('authorize, a polluting key', 'GET', '/oauth2/authorize' +
                 q(authorize()) + '&__proto__=x');
      await step('authorize, a bad request_uri', 'GET', '/oauth2/authorize' +
                 q({ client_id: 'wire-conf',
                     request_uri: 'urn:ietf:params:oauth:request_uri:nope' }));

      // PUSHED AUTHORIZATION REQUESTS.
      const pushed = await step('par', 'POST', '/oauth2/par', {
        headers: AUTH, form: authorize() });
      await step('par, request_uri given', 'POST', '/oauth2/par', {
        headers: AUTH, form: authorize({
          request_uri: 'urn:ietf:params:oauth:request_uri:x' }) });
      await step('par, no client', 'POST', '/oauth2/par', {
        form: authorize({ client_id: '' }) });
      await step('par, a short code_challenge', 'POST', '/oauth2/par', {
        headers: AUTH, form: authorize({ code_challenge: 'abc' }) });
      await step('par, a wrong secret', 'POST', '/oauth2/par', {
        headers: { authorization: basic('wire-conf', 'wrong') },
        form: authorize() });
      await step('par, not a form', 'POST', '/oauth2/par', {
        headers: AUTH, json: { client_id: 'wire-conf' } });
      if (pushed.body && pushed.body.request_uri) {
        await step('authorize, by the pushed request_uri', 'GET',
                   '/oauth2/authorize' +
                   q({ client_id: 'wire-conf',
                       request_uri: pushed.body.request_uri }));
      }

      // THE TOKEN ENDPOINT.
      await step('token, nothing', 'POST', '/oauth2/token', { form: {} });
      await step('token, no grant_type', 'POST', '/oauth2/token', {
        headers: AUTH, form: { scope: 'openid' } });
      await step('token, an unsupported grant_type', 'POST', '/oauth2/token', {
        headers: AUTH, form: { grant_type: 'urn:example:nope' } });
      const cc = await step('token, client_credentials', 'POST',
                            '/oauth2/token', { headers: AUTH, form: {
                              grant_type: 'client_credentials' } });
      await step('token, client_credentials in the body', 'POST',
                 '/oauth2/token', { form: { grant_type: 'client_credentials',
                                            client_id: 'wire-conf',
                                            client_secret: SECRET } });
      await step('token, a wrong secret', 'POST', '/oauth2/token', {
        headers: { authorization: basic('wire-conf', 'wrong') },
        form: { grant_type: 'client_credentials' } });
      await step('token, an unknown client', 'POST', '/oauth2/token', {
        headers: { authorization: basic('wire-nobody', SECRET) },
        form: { grant_type: 'client_credentials' } });
      await step('token, a malformed scope', 'POST', '/oauth2/token', {
        headers: AUTH, form: { grant_type: 'client_credentials',
                               scope: 'a "b"' } });
      await step('token, an overlong client_id', 'POST', '/oauth2/token', {
        form: { grant_type: 'client_credentials',
                client_id: 'x'.repeat(300) } });
      await step('token, an invalid code', 'POST', '/oauth2/token', {
        headers: AUTH, form: { grant_type: 'authorization_code',
                               code: 'nope', redirect_uri: REDIRECT,
                               code_verifier: VERIFIER } });
      await step('token, a short code_verifier', 'POST', '/oauth2/token', {
        headers: AUTH, form: { grant_type: 'authorization_code',
                               code: 'nope', redirect_uri: REDIRECT,
                               code_verifier: 'short' } });
      await step('token, a public client\'s code', 'POST', '/oauth2/token', {
        form: { grant_type: 'authorization_code', client_id: 'wire-pub',
                code: 'nope', redirect_uri: REDIRECT,
                code_verifier: VERIFIER } });
      const pw = await step('token, password', 'POST', '/oauth2/token', {
        headers: AUTH, form: { grant_type: 'password', username: 'wire-user',
                               password: 'whatever',
                               scope: 'openid profile email' } });
      const refresh = pw.body && pw.body.refresh_token;
      if (refresh) {
        await step('token, refresh', 'POST', '/oauth2/token', {
          headers: AUTH, form: { grant_type: 'refresh_token',
                                 refresh_token: refresh } });
      }
      await step('token, an invalid refresh_token', 'POST', '/oauth2/token', {
        headers: AUTH, form: { grant_type: 'refresh_token',
                               refresh_token: 'nope' } });
      const ccToken = cc.body && cc.body.access_token;
      await step('token, exchange', 'POST', '/oauth2/token', {
        headers: AUTH, form: {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token: ccToken || 'none',
          subject_token_type:
            'urn:ietf:params:oauth:token-type:access_token' } });
      await step('token, exchange with no subject_token_type', 'POST',
                 '/oauth2/token', { headers: AUTH, form: {
                   grant_type:
                     'urn:ietf:params:oauth:grant-type:token-exchange',
                   subject_token: ccToken || 'none' } });
      await step('token, exchange with a bad subject_token_type', 'POST',
                 '/oauth2/token', { headers: AUTH, form: {
                   grant_type:
                     'urn:ietf:params:oauth:grant-type:token-exchange',
                   subject_token: 'x', subject_token_type: 'not a uri' } });
      await step('token, a JWT bearer grant', 'POST', '/oauth2/token', {
        headers: AUTH, form: {
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: 'a.b.c' } });
      await step('token, a SAML bearer grant', 'POST', '/oauth2/token', {
        headers: AUTH, form: {
          grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
          assertion: 'bm90IHNhbWw' } });
      await step('token, a client assertion', 'POST', '/oauth2/token', {
        form: { grant_type: 'client_credentials', client_id: 'wire-conf',
                client_assertion_type:
                  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: 'a.b.c' } });
      await step('token, an invalid device_code', 'POST', '/oauth2/token', {
        headers: AUTH, form: {
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: 'nope' } });
      await step('token, an invalid auth_req_id', 'POST', '/oauth2/token', {
        headers: AUTH, form: { grant_type: 'urn:openid:params:grant-type:ciba',
                               auth_req_id: 'nope' } });
      await step('token, a bad DPoP proof', 'POST', '/oauth2/token', {
        headers: Object.assign({ dpop: 'not-a-proof' }, AUTH),
        form: { grant_type: 'client_credentials' } });
      await step('token, a JSON body', 'POST', '/oauth2/token', {
        headers: AUTH, json: { grant_type: 'client_credentials' } });
      await step('token, GET', 'GET', '/oauth2/token');

      // INTROSPECTION AND REVOCATION.
      await step('introspect', 'POST', '/oauth2/introspect', {
        headers: AUTH, form: { token: ccToken || 'none' } });
      await step('introspect, as a JWT', 'POST', '/oauth2/introspect', {
        headers: Object.assign({
          accept: 'application/token-introspection+jwt' }, AUTH),
        form: { token: ccToken || 'none' } });
      await step('introspect, an odd hint', 'POST', '/oauth2/introspect', {
        headers: AUTH, form: { token: ccToken || 'none',
                               token_type_hint: 'requesting_party_token' } });
      await step('introspect, no client', 'POST', '/oauth2/introspect', {
        form: { token: ccToken || 'none' } });
      await step('introspect, no token', 'POST', '/oauth2/introspect', {
        headers: AUTH, form: {} });
      await step('introspect, an unknown token', 'POST', '/oauth2/introspect', {
        headers: AUTH, form: { token: 'nope' } });
      await step('revoke, no token', 'POST', '/oauth2/revoke', {
        headers: AUTH, form: {} });
      await step('revoke, an unknown token', 'POST', '/oauth2/revoke', {
        headers: AUTH, form: { token: 'nope', token_type_hint: 'whatever' } });
      await step('revoke, no client', 'POST', '/oauth2/revoke', {
        form: { token: 'nope' } });

      // USERINFO.
      const pwToken = pw.body && pw.body.access_token;
      await step('userinfo', 'GET', '/oauth2/userinfo', {
        headers: { authorization: 'Bearer ' + (pwToken || 'none') } });
      await step('userinfo, POST', 'POST', '/oauth2/userinfo', {
        headers: { authorization: 'Bearer ' + (pwToken || 'none') } });
      await step('userinfo, a claim asked', 'GET', '/oauth2/userinfo?claim=' +
                 'email&claim=address', {
                   headers: { authorization: 'Bearer ' +
                                             (pwToken || 'none') } });
      await step('userinfo, a malformed claims', 'GET',
                 '/oauth2/userinfo?claims=%7Bnope', {
                   headers: { authorization: 'Bearer ' +
                                             (pwToken || 'none') } });
      await step('userinfo, no token', 'GET', '/oauth2/userinfo');
      await step('userinfo, a client_credentials token', 'GET',
                 '/oauth2/userinfo', {
                   headers: { authorization: 'Bearer ' +
                                             (ccToken || 'none') } });
      await step('userinfo, a bad token', 'GET', '/oauth2/userinfo', {
        headers: { authorization: 'Bearer nope' } });
      await step('userinfo, the token in the query', 'GET',
                 '/oauth2/userinfo?access_token=nope');

      // DYNAMIC REGISTRATION AND MANAGEMENT.
      const registered = await step('register', 'POST', '/oauth2/register', {
        json: { redirect_uris: [REDIRECT], client_name: 'Wire',
                grant_types: ['authorization_code', 'refresh_token'],
                response_types: ['code'],
                token_endpoint_auth_method: 'client_secret_basic' } });
      const rid = registered.body && registered.body.client_id;
      const rat = registered.body && registered.body.registration_access_token;
      if (rid) {
        const ratHeader = { authorization: 'Bearer ' + (rat || 'none') };
        await step('register, read', 'GET', '/oauth2/register/' +
                   encodeURIComponent(rid), { headers: ratHeader });
        await step('register, read without the token', 'GET',
                   '/oauth2/register/' + encodeURIComponent(rid));
        await step('register, update', 'PUT', '/oauth2/register/' +
                   encodeURIComponent(rid), { headers: ratHeader, json: {
                     client_id: rid, redirect_uris: [REDIRECT],
                     client_name: 'Wire 2',
                     grant_types: ['authorization_code'],
                     response_types: ['code'],
                     token_endpoint_auth_method: 'client_secret_basic' } });
        await step('register, delete', 'DELETE', '/oauth2/register/' +
                   encodeURIComponent(rid), { headers: ratHeader });
      }
      await step('register, a bad application_type', 'POST',
                 '/oauth2/register', { json: {
                   redirect_uris: [REDIRECT], application_type: 'desktop' } });
      await step('register, not JSON', 'POST', '/oauth2/register',
                 { form: { redirect_uris: REDIRECT } });
      await step('register, a malformed body', 'POST', '/oauth2/register',
                 { json: '{"redirect_uris":' });
      await step('register, an unknown client read', 'GET',
                 '/oauth2/register/wire-nobody',
                 { headers: { authorization: 'Bearer nope' } });

      // DEVICE AUTHORIZATION AND CIBA.
      const device = await step('device_authorization', 'POST',
                                '/oauth2/device_authorization', {
                                  headers: AUTH, form: { scope: 'openid' } });
      if (device.body && device.body.device_code) {
        await step('token, a pending device_code', 'POST', '/oauth2/token', {
          headers: AUTH, form: {
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: device.body.device_code } });
      }
      await step('device_authorization, a malformed scope', 'POST',
                 '/oauth2/device_authorization', {
                   headers: AUTH, form: { scope: 'a "b"' } });
      await step('device_authorization, no client', 'POST',
                 '/oauth2/device_authorization', { form: {} });
      const ciba = await step('bc-authorize', 'POST', '/oauth2/bc-authorize', {
        headers: AUTH, form: { scope: 'openid', login_hint: 'wire-user',
                               binding_message: 'wire' } });
      if (ciba.body && ciba.body.auth_req_id) {
        await step('token, a pending auth_req_id', 'POST', '/oauth2/token', {
          headers: AUTH, form: {
            grant_type: 'urn:openid:params:grant-type:ciba',
            auth_req_id: ciba.body.auth_req_id } });
      }
      await step('bc-authorize, no hint', 'POST', '/oauth2/bc-authorize', {
        headers: AUTH, form: { scope: 'openid' } });
      await step('bc-authorize, an overlong requested_expiry', 'POST',
                 '/oauth2/bc-authorize', { headers: AUTH, form: {
                   scope: 'openid', login_hint: 'wire-user',
                   requested_expiry: '1'.repeat(17) } });

      // RP-INITIATED LOGOUT.
      await step('logout, nothing', 'GET', '/oauth2/logout');
      await step('logout, a javascript post_logout_redirect_uri', 'GET',
                 '/oauth2/logout' +
                 q({ client_id: 'wire-conf',
                     post_logout_redirect_uri: 'javascript:alert(1)' }));
      await step('logout, an unregistered post_logout_redirect_uri', 'GET',
                 '/oauth2/logout' +
                 q({ client_id: 'wire-conf',
                     post_logout_redirect_uri: 'https://evil.example/' }));
      await step('logout, a registered post_logout_redirect_uri', 'GET',
                 '/oauth2/logout' +
                 q({ client_id: 'wire-conf', state: 's1',
                     post_logout_redirect_uri: LOGGED_OUT }));
      if (pw.body && pw.body.id_token) {
        await step('logout, an id_token_hint', 'GET', '/oauth2/logout' +
                   q({ id_token_hint: pw.body.id_token, state: 's2',
                       post_logout_redirect_uri: LOGGED_OUT }));
      }
      await step('logout, state twice', 'GET', '/oauth2/logout?state=a&' +
                 'state=b');
      await step('logout, POST', 'POST', '/oauth2/logout', {
        form: { client_id: 'wire-conf' } });

      // GRANT MANAGEMENT AND SESSION MANAGEMENT.
      await step('grants, an unknown grant', 'GET', '/oauth2/grants/nope', {
        headers: { authorization: 'Bearer ' + (ccToken || 'none') } });
      await step('grants, no token', 'GET', '/oauth2/grants/nope');
      await step('check_session', 'GET', '/oauth2/check_session');

      // AND THE TOKENS LAST, SO THEIR REVOCATION CHANGES NOTHING ABOVE.
      if (refresh) {
        await step('revoke, the refresh token', 'POST', '/oauth2/revoke', {
          headers: AUTH, form: { token: refresh,
                                 token_type_hint: 'refresh_token' } });
        await step('introspect, the revoked refresh token', 'POST',
                   '/oauth2/introspect', { headers: AUTH,
                                           form: { token: refresh } });
      }
      if (ccToken) {
        await step('revoke, the access token', 'POST', '/oauth2/revoke', {
          headers: AUTH, form: { token: ccToken } });
        await step('introspect, the revoked access token', 'POST',
                   '/oauth2/introspect', { headers: AUTH,
                                           form: { token: ccToken } });
      }
    }
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  })().catch(function (e) {
    record.problems.push(String(e && e.stack));
    require('fs').writeFileSync(OUT, JSON.stringify(record));
    process.exit(0);
  });
}

// The member names whose values this service draws at random, each replaced
// by its name. A JWT among them is decoded rather than replaced.
const VOLATILE_MEMBERS = ['access_token', 'refresh_token', 'device_code',
  'user_code', 'client_secret', 'registration_access_token', 'auth_req_id',
  'request_uri', 'verification_uri_complete', 'code', 'session_state',
  'jti', 'sid', 'at_hash', 'c_hash', 'rt_hash', 'kid', 'n', 'e', 'x', 'y',
  'x5c', 'x5t', 'x5t#S256', 'iat', 'exp', 'nbf', 'auth_time',
  'client_id_issued_at', 'client_secret_expires_at', 'dpop-nonce',
  'signed_metadata', 'grant_id', 'device_secret', 'authn', 'idx'];

const JWT = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$/;

// A compact JWS, decoded: its header and claims, its signature dropped. A JWE
// (five parts) is left for the generic patterns.
function decodeJwt(text) {
  log.debug("Entering decodeJwt().");
  const parts = text.split('.');
  try {
    const out = { jwt: {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')),
      claims: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')),
      signed: parts[2].length > 0 } };
    log.debug("Leaving decodeJwt().");
    return out;
  } catch (e) {
    log.debug("Caught in decodeJwt(): " + ((e && e.message) || e));
    log.debug("Leaving decodeJwt(). Not a JWT.");
    return text;
  }
}

// Walks a value: a JWT anywhere is decoded, and a volatile member's value is
// replaced by its name. A URL's query is walked as members too, so a
// Location header holding a code or a request_uri is held to the rest.
function scrub(value, name) {
  log.debug("Entering scrub().");
  if (Array.isArray(value)) {
    const list = value.map(function (one) {
      return scrub(one, name);
    });
    log.debug("Leaving scrub().");
    return list;
  }
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach(function (key) {
      out[key] = scrub(value[key], key);
    });
    log.debug("Leaving scrub().");
    return out;
  }
  // A cookie's value is a handle drawn at random; its name and its
  // attributes are what is held.
  if (name === 'set-cookie' && typeof value === 'string') {
    log.debug("Leaving scrub(). A cookie.");
    return value.replace(/=[^;]*/, '=<cookie>');
  }
  if (typeof value === 'string' && JWT.test(value)) {
    const decoded = decodeJwt(value);
    if (decoded !== value) {
      log.debug("Leaving scrub(). A JWT.");
      return scrub(decoded, name);
    }
  }
  // An instant in seconds, which a JSON number cannot hold a placeholder
  // for in the text.
  if (typeof value === 'number' && value >= 1.7e9 && value < 2.2e9) {
    log.debug("Leaving scrub(). An instant.");
    return '<epoch>';
  }
  if (name && VOLATILE_MEMBERS.indexOf(name) >= 0 && value !== undefined &&
      value !== null && value !== '') {
    log.debug("Leaving scrub(). A volatile member.");
    return '<' + name + '>';
  }
  if (typeof value === 'string' && /^(https?:\/\/|\/)[^ ]*\?/.test(value)) {
    const mark = value.indexOf('?');
    const query = new URLSearchParams(value.slice(mark + 1));
    const kept = [];
    query.forEach(function (v, k) {
      const one = scrub(v, k);
      kept.push(k + '=' + (typeof one === 'string' ? one
        : JSON.stringify(one)));
    });
    log.debug("Leaving scrub(). A URL.");
    return { url: value.slice(0, mark), query: kept };
  }
  log.debug("Leaving scrub().");
  return value;
}

// The run-to-run values, each replaced by a placeholder, a UUID's numbered in
// order of first appearance, so that two runs of one tree record the same
// text.
function normalise(record) {
  log.debug("Entering normalise().");
  const seen = new Map();
  const PATTERNS = [
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['httpdate', /[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    // How long the process has been up, which a refusal of a code says.
    ['uptime', /up \d+ second\(s\)/g],
    // A dynamically registered client's id.
    ['client', /sts-client-[A-Za-z0-9_-]+/g],
    // A sign-in transaction's handle, in a redirect's text body.
    ['authn', /authn=[A-Za-z0-9_-]+/g],
    // A random value has an upper-case letter and a digit in it, which a
    // member name (`token_endpoint_auth_signing_alg_values_supported`) has
    // not: a member name is never a placeholder.
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{32,}/g]
  ];
  const text = JSON.stringify(scrub(record), null, 1);
  let out = text;
  PATTERNS.forEach(function (pair) {
    out = out.replace(pair[1], function (value) {
      if (pair[0] !== 'uuid') {
        return '<' + pair[0] + '>';
      }
      const key = pair[0] + ':' + value.toLowerCase();
      if (!seen.has(key)) {
        seen.set(key, '<' + pair[0] + '#' + (seen.size + 1) + '>');
      }
      return seen.get(key);
    });
  });
  log.debug("Leaving normalise().");
  return JSON.parse(out);
}

// Runs the child and answers its record, normalised, or null.
function capture() {
  log.debug("Entering capture().");
  const out = path.join(os.tmpdir(), 'oauth-model-wire-' + process.pid +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|SCIM_|OAUTH2_|LDAP_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', OW_ROOT: ROOT, OW_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let record = null;
  try {
    record = JSON.parse(fs.readFileSync(out, 'utf8'));
    fs.unlinkSync(out);
  } catch (e) {
    log.debug("Caught in capture(): " + ((e && e.message) || e));
    log.debug("Leaving capture(). No record: exit " + result.status + " " +
              String(result.stderr || '').slice(-800));
    return null;
  }
  log.debug("Leaving capture().");
  return normalise(record);
}

// The first place two values differ, as a dotted path, or null.
function firstDifference(a, b, where) {
  log.debug("Entering firstDifference().");
  if (JSON.stringify(a) === JSON.stringify(b)) {
    log.debug("Leaving firstDifference(). Equal.");
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = Array.from(new Set(Object.keys(a).concat(Object.keys(b))));
    for (let i = 0; i < keys.length; i++) {
      const inner = firstDifference(a[keys[i]], b[keys[i]],
                                    where + '.' + keys[i]);
      if (inner) {
        log.debug("Leaving firstDifference().");
        return inner;
      }
    }
  }
  log.debug("Leaving firstDifference().");
  return where + ': ' + JSON.stringify(b).slice(0, 300) + ' where ' +
    JSON.stringify(a).slice(0, 300) + ' was recorded';
}

function run(t) {
  log.debug("Entering run().");
  const now = capture();
  if (!t.check(!!now, 'the child process reported')) {
    log.debug("Leaving run().");
    return;
  }
  t.check(now.problems.length === 0, 'the child ran to the end',
          now.problems.join('\n'));
  let recorded = null;
  try {
    recorded = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    recorded = null;
  }
  if (!t.check(!!recorded, 'the recorded wire is in the tree', SNAPSHOT)) {
    log.debug("Leaving run().");
    return;
  }
  t.check(recorded.wire.length === now.wire.length,
          'the conversation has as many steps as recorded',
          now.wire.length + ' vs ' + recorded.wire.length);
  recorded.wire.forEach(function (one, i) {
    t.check(firstDifference(one, now.wire[i], 'wire') === null,
            one.mode + ', ' + one.step + ': ' + one.method +
            ' answers as recorded (' + one.status + ')',
            firstDifference(one, now.wire[i], 'wire'));
  });
  log.debug("Leaving run().");
}

if (require.main === module && process.env.OAUTH_WIRE_PRINT) {
  process.stdout.write(JSON.stringify(capture(), null, 1) + '\n');
}

module.exports = {
  name: 'oauth_model_wire',
  describe: 'what the OAuth 2.0 and OpenID Connect endpoints answer, byte ' +
            'for byte, against the record made before their parameters, ' +
            'members, error codes and claim sets came from the model ' +
            '(#1579): discovery, every endpoint\'s success and refusals, ' +
            'in development, RFC 9700, OAuth 2.1 and FAPI 2.0 modes',
  run: run
};
