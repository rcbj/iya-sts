// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oauth_model_wire.js
//
// ===========================================================================
// WHAT THE OAUTH 2.0 AND OPENID CONNECT ENDPOINTS ANSWER, HELD TO THE
// RECORDED WIRE, OVER THE WIRE (#1579 item 6; D12, #444).
//
// `tests/oauth_model_wire.js` holds every endpoint's answers, byte for byte,
// to `tests/protocol/oauth_model_wire.snapshot.json`, from a child process
// on a plain-HTTP loopback port. This job has the same scripted conversation with
// a RUNNING service — its four modes, each in a throwaway realm of this
// run's own (development, RFC 9700, OAuth 2.1, FAPI 2.0 Security Profile) —
// and holds every answer to the same snapshot after putting back what only
// the place of the conversation changes:
//
//   * the realm: the development mode's realm is the in-process file's
//     DEFAULT realm, so its prefix is taken out; each other realm's id loses
//     this run's stamp;
//   * the origin: `https://localhost:<port>` is the recorded
//     `http://127.0.0.1:<port>`, in every spelling (plain, URL-encoded);
//   * HSTS, which only a TLS listener sends;
//
// and then the in-process file's own normalisation (its placeholders for
// instants, ports, UUIDs, key material and random credentials). Each step is
// a check: it answers as recorded, or the first difference is named.
//
// THE SNAPSHOT LIVES BESIDE THIS JOB, so it survives the in-process file
// (`OAUTH_WIRE_SNAPSHOT` names another).
//
// NOT CARRIED: the in-process file's `flows` mode — the paths that need a
// signed-in browser, a key pair, a client certificate on a second listener
// the job starts with the app, a SAML assertion signed by a fixture and a
// back-channel Logout Token received by a relying party on the loopback.
// OWED to the families that drive those flows over the wire
// (sts_oidc_core, sts_dpop, sts_rfc8705_mtls, sts_saml2_bearer_grant,
// sts_backchannel_logout), whose answers are held there by assertion rather
// than by snapshot.
//
// OWNED HERE (local: true): this repository's own authorization server.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const K = require("./oauth_wire_kit.js").kit("sts_oauth_model_wire");
const log = K.log;

const SNAPSHOT = process.env.OAUTH_WIRE_SNAPSHOT ||
  path.join(__dirname, "oauth_model_wire.snapshot.json");
const SKIPPED_HEADERS = ["date", "connection", "keep-alive",
                         "content-length", "etag", "transfer-encoding",
                         "strict-transport-security"];
const SECRET = "wire-client-secret-0123456789abcdef0123456789";
const REDIRECT = "https://rp.wire.example/cb";
const LOGGED_OUT = "https://rp.wire.example/bye";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const MODES = [
  { name: "development", prefix: "wiredev", overrides: {} },
  { name: "rfc9700", prefix: "wire9700",
    overrides: { "oauth2.rfc9700": "true" } },
  { name: "oauth21", prefix: "wire21",
    overrides: { "oauth2.oauth21": "true" } },
  { name: "fapi2", prefix: "wirefapi",
    overrides: { "oauth2.fapi": "2-security" } }
];

// One request, as the in-process file's `request()` made it: no
// User-Agent or Accept of its own, the body by content type, every header
// but the connection's kept.
function request(method, url, opts) {
  log.debug("Entering request(). " + method + " " + url);
  const o = opts || {};
  let body = "";
  const headers = Object.assign({}, o.headers || {});
  if (o.form !== undefined) {
    body = typeof o.form === "string" ? o.form
      : new URLSearchParams(o.form).toString();
    headers["content-type"] = "application/x-www-form-urlencoded";
  } else if (o.json !== undefined) {
    body = typeof o.json === "string" ? o.json : JSON.stringify(o.json);
    headers["content-type"] = "application/json";
  }
  if (body) {
    headers["content-length"] = Buffer.byteLength(body);
  }
  const u = new URL(url);
  const lib = u.protocol === "https:" ? https : http;
  log.debug("Leaving request().");
  return new Promise(function (resolve) {
    const req = lib.request({ hostname: u.hostname, port: u.port,
                              path: u.pathname + u.search, method: method,
                              headers: headers }, function (res) {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", function (c) {
        text += c;
      });
      res.on("end", function () {
        let parsed;
        const type = String(res.headers["content-type"] || "");
        if (/json/.test(type) && text) {
          try {
            parsed = JSON.parse(text);
          } catch (e) {
            log.debug("Caught in request(): " + ((e && e.message) || e));
            // Recorded as the in-process file records it.
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
    req.on("error", function (e) {
      log.debug("Caught in request(): " + ((e && e.message) || e));
      // A refused connection is recorded as the in-process file did.
      resolve({ status: 0, headers: {}, body: String(e && e.message) });
    });
    req.end(body);
  });
}

function basic(id, secret) {
  log.debug("Entering basic().");
  log.debug("Leaving basic().");
  return "Basic " + Buffer.from(encodeURIComponent(id) + ":" +
                                encodeURIComponent(secret))
    .toString("base64");
}

async function setUpRealm(mode) {
  log.debug("Entering setUpRealm(). " + mode.name);
  const id = await K.realm(mode.prefix, "development", mode.overrides);
  await K.set(id, "oauth2.deviceAuthorization", true);
  await K.set(id, "oauth2.ciba", true);
  await K.ok(K.rb(id) + "/admin-api/users/create",
             { username: "wire-user", invent: false },
             "created wire-user");
  const make = function (client, fields) {
    log.debug("Entering make(). " + client);
    log.debug("Leaving make().");
    return K.app(id, client, Object.assign({ oauthClientId: [client],
      oauthClientSecret: SECRET, oauthRedirectUri: [REDIRECT],
      oauthPostLogoutRedirectUri: [LOGGED_OUT],
      oauthTokenEndpointAuthMethod: "client_secret_basic" }, fields || {}),
      { protocols: ["oauth2"] });
  };
  await make("wire-conf");
  const pub = { oauthClientId: ["wire-pub"], oauthRedirectUri: [REDIRECT],
                oauthPostLogoutRedirectUri: [LOGGED_OUT],
                oauthTokenEndpointAuthMethod: "none" };
  await K.app(id, "wire-pub", pub, { protocols: ["oauth2"] });
  log.debug("Leaving setUpRealm().");
  return id;
}

// One mode's conversation, as the in-process file has it, against realm
// `id`; every answer is pushed onto `record.wire`.
async function runMode(mode, id, record) {
  log.debug("Entering runMode(). " + mode.name);
  const P = "/realm/" + id;
  // THE CONVERSATION BELOW IS `tests/oauth_model_wire.js`'s, copied as it
  // stands (its indentation kept, so a diff against it stays readable),
  // with `request()` aimed at the running service.
  for (let once = 0; once < 1; once++) {
      const AUTH = { authorization: basic('wire-conf', SECRET) };
      const step = async function (name, method, p, opts) {
        log.debug("Entering step(). " + name);
        const r = await request(method, K.base + P + p, opts);
        record.wire.push({ mode: mode.name, step: name, method: method,
                           path: p, status: r.status, headers: r.headers,
                           body: r.body });
        log.debug("Leaving step().");
        return r;
      };
      const q = function (params) {
        log.debug("Entering q().");
        log.debug("Leaving q().");
        return '?' + new URLSearchParams(params).toString();
      };
      const goodAuthorize = { response_type: 'code', client_id: 'wire-conf',
        redirect_uri: REDIRECT, scope: 'openid profile', state: 'st-fixed',
        nonce: 'n-fixed', code_challenge: CHALLENGE,
        code_challenge_method: 'S256' };
      const authorize = function (extra) {
        log.debug("Entering authorize().");
        log.debug("Leaving authorize().");
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
      // RFC 7591 section 2's members, each sent as a JSON type its
      // definition does not allow: the refusal each one gets.
      if (mode.name === 'development') {
        const WRONG = [
          ['redirect_uris', 'x'], ['request_uris', 'x'], ['request_uris', [5]],
          ['jwks_uri', 5], ['jwks', 'x'], ['backchannel_logout_uri', 5],
          ['frontchannel_logout_uri', 5], ['initiate_login_uri', 5],
          ['post_logout_redirect_uris', 'x'], ['sector_identifier_uri', 5],
          ['introspection_signed_response_alg', 5],
          ['introspection_encrypted_response_alg', 5],
          ['id_token_signed_response_alg', 5],
          ['id_token_encrypted_response_alg', 5],
          ['userinfo_signed_response_alg', 5],
          ['userinfo_encrypted_response_alg', 5],
          ['authorization_signed_response_alg', 5],
          ['authorization_encrypted_response_alg', 5],
          ['request_object_signing_alg', 5],
          ['request_object_encryption_alg', 5],
          ['token_endpoint_auth_signing_alg', 5],
          ['require_pushed_authorization_requests', 'yes'],
          ['require_signed_request_object', 'yes'],
          ['backchannel_user_code_parameter', 'yes'],
          ['backchannel_token_delivery_mode', 5],
          ['backchannel_client_notification_endpoint', 5],
          ['backchannel_authentication_request_signing_alg', 5],
          ['backchannel_logout_session_required', 'yes'],
          ['frontchannel_logout_session_required', 'yes'],
          ['tls_client_certificate_bound_access_tokens', 'yes'],
          ['tls_client_auth_subject_dn', 5],
          ['authorization_details_types', 'x'], ['default_max_age', -5],
          ['default_max_age', 'x'], ['require_auth_time', 'yes'],
          ['default_acr_values', 'mfa'], ['subject_type', 5],
          ['application_type', 5], ['token_endpoint_auth_method', 5],
          ['grant_types', 'x'], ['response_types', 'x'], ['client_name', 5],
          ['contacts', 'x'], ['logo_uri', 42], ['client_uri', 42],
          ['policy_uri', 42], ['tos_uri', 42], ['scope', 5],
          ['software_id', 5], ['software_version', 5],
          ['software_statement', 5], ['command_endpoint', 5]];
        for (let w = 0; w < WRONG.length; w++) {
          const doc = { redirect_uris: [REDIRECT] };
          doc[WRONG[w][0]] = WRONG[w][1];
          await step('register, ' + WRONG[w][0] + ' ' +
                     JSON.stringify(WRONG[w][1]), 'POST', '/oauth2/register',
                     { json: doc });
        }
      }

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
  log.debug("Leaving runMode().");
}

// The member names whose values this service draws at random, each replaced
// by its name. A JWT among them is decoded rather than replaced.
const VOLATILE_MEMBERS = ['access_token', 'refresh_token', 'device_code',
  'user_code', 'client_secret', 'registration_access_token', 'auth_req_id',
  'request_uri', 'verification_uri_complete', 'code', 'session_state',
  'jti', 'sid', 'at_hash', 'c_hash', 'rt_hash', 'kid', 'n', 'e', 'x', 'y',
  'x5c', 'x5t', 'x5t#S256', 'iat', 'exp', 'nbf', 'auth_time',
  'client_id_issued_at', 'client_secret_expires_at', 'dpop-nonce',
  'signed_metadata', 'grant_id', 'device_secret', 'authn', 'idx', 'jkt',
  'response', 's_hash'];

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
  // Express's redirect body names the address the Location header does,
  // and is read the same way.
  if (typeof value === 'string' && /^Found\. Redirecting to /.test(value)) {
    log.debug("Leaving scrub(). A redirect's body.");
    return { redirecting: scrub(value.slice('Found. Redirecting to '.length),
                                name) };
  }
  // A form a page posts (form_post, JARM's form_post.jwt): each credential
  // it carries is a placeholder by its name.
  if (typeof value === 'string' && value.indexOf('<form') >= 0) {
    value = value.replace(new RegExp('(name="(' +
      VOLATILE_MEMBERS.join('|').replace(/#/g, '\\#') +
      ')" value=")[^"]*"', 'g'), '$1<$2>"');
  }
  if (typeof value === 'string' && /^(https?:\/\/|\/)[^ ]*[?#]/.test(value)) {
    const mark = value.search(/[?#]/);
    const query = new URLSearchParams(value.slice(mark + 1)
      .replace(/#/g, '&'));
    const kept = [];
    query.forEach(function (v, k) {
      const one = scrub(v, k);
      kept.push(k + '=' + (typeof one === 'string' ? one
        : JSON.stringify(one)));
    });
    log.debug("Leaving scrub(). A URL.");
    return { url: value.slice(0, mark), query: kept,
             in: value.charAt(mark) === '#' ? 'fragment' : 'query' };
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
    // THE PAGE FOOTER (2026-11-14), on every shell and error page: its
    // version and build line differ per build, and what it holds is
    // `tests/page_footer.js`'s to check, so here it is one placeholder.
    ['footer', /<footer class=\\"sts-footer\\".*?<\/footer>/g],
    ['footercss', /body:has\(>\.sts-footer\).*?\.sts-footer-social\{gap:18px\}\}/g],
    ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi],
    ['time', /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g],
    ['httpdate', /[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d GMT/g],
    ['port', /127\.0\.0\.1(:|%3A)\d+/g],
    ['epoch', /\b1[789]\d{8}\b/g],
    // How long the process has been up, which a refusal of a code says.
    ['uptime', /up \d+ second\(s\)/g],
    // An error page's incident ID, a process-wide count of the incidents
    // before it: any earlier refusal anywhere in the run moves it.
    ['incident', /(?<=Incident ID<\/dt><dd><code>)\d+/g],
    // A dynamically registered client's id.
    ['client', /sts-client-[A-Za-z0-9_-]+/g],
    // A sign-in transaction's handle, in a redirect's text body.
    ['authn', /authn=[A-Za-z0-9_-]+/g],
    // A random value has an upper-case letter and a digit in it, which a
    // member name (`token_endpoint_auth_signing_alg_values_supported`) has
    // not: a member name is never a placeholder.
    ['random', /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{32,}/g]
  ];
  const text = JSON.stringify(placed(scrub(record)), null, 1);
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
  // String(): a member missing on one side stringifies to undefined.
  return where + ': ' + String(JSON.stringify(b)).slice(0, 300) +
    ' where ' + String(JSON.stringify(a)).slice(0, 300) + ' was recorded';
}

// What only the place of the conversation changes, put back, after the
// JWTs are decoded and before the placeholders: this run's realm ids and the
// service's origin in every spelling, and the four things only a TLS
// listener or a realm of its own answers differently —
//   * a cookie's `Secure` attribute;
//   * `tls_client_auth` and `self_signed_tls_client_auth` in an
//     `*_auth_methods_supported` list and in the sentence naming that list,
//     `tls_client_certificate_bound_access_tokens` and
//     `mtls_endpoint_aliases` (RFC 8705 is advertised only where a client
//     certificate can arrive);
//   * a JWS header's `x5u`, the realm's issuing chain, which the in-process
//     file's realms had none of;
//   * the RFC 9700 report's sentence, its scheme and its row about
//     `global.https`.
let REALMS_OF = {};
let recordedRows = {};
let DOMAINS_OF = {};

function placed(record) {
  log.debug("Entering placed().");
  const walk = function (value, name) {
    // Recursive over every value of the record: no Entering/Leaving pair,
    // which would be a line per member of every answer.
    if (Array.isArray(value)) {
      let list = value.map(function (one) {
        return walk(one, name);
      });
      if (/_auth_methods_supported$/.test(String(name || ""))) {
        list = list.filter(function (one) {
          return one !== "tls_client_auth" &&
                 one !== "self_signed_tls_client_auth";
        });
      }
      return list;
    }
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value).forEach(function (key) {
        if (key === "x5u" && name === "header") {
          return;
        }
        if (key === "mtls_endpoint_aliases") {
          return;
        }
        if (key === "tls_client_certificate_bound_access_tokens" &&
            value[key] === true) {
          out[key] = false;
          return;
        }
        out[key] = walk(value[key], key);
      });
      return out;
    }
    if (typeof value === "string" && name === "set-cookie") {
      return value.replace(/; Secure(?=;|$)/g, "");
    }
    return value;
  };
  const walked = walk(record, "");
  (walked.wire || []).forEach(function (one) {
    const body = one.body;
    if (body && typeof body === "object" && body.settings &&
        body.settings["global.https"] === true) {
      body.settings["global.https"] = false;
    }
    if (body && body.authorization_endpoint_scheme === "https") {
      body.authorization_endpoint_scheme = "http";
    }
    // THE RFC 9700 REPORT'S ROWS THAT TLS DECIDES — the ones whose
    // recorded note says the plain listener (`global.https` off) is why:
    // over TLS each says otherwise, so the recorded row stands, by mode and
    // id.
    (body && Array.isArray(body.requirements) ? body.requirements : [])
      .forEach(function (row, i) {
        const was = recordedRows[one.mode + " " + (row && row.id)];
        if (row && was && row.enforced !== was.enforced &&
            /global\.https/.test(String(was.note || ""))) {
          body.requirements[i] = was;
        }
      });
    if (body && typeof body.what_it_means === "string") {
      body.what_it_means = body.what_it_means.replace(
        "which is https.",
        "which is http, because global.https has been turned off.");
    }
  });
  let text = JSON.stringify(walked);
  const origin = new URL(K.base);
  const swaps = [];
  Object.keys(REALMS_OF).forEach(function (id) {
    const to = REALMS_OF[id];
    swaps.push([K.base + "/realm/" + id, to ? K.base + "/realm/" + to
                                            : K.base]);
    swaps.push([encodeURIComponent(K.base + "/realm/" + id),
                encodeURIComponent(to ? K.base + "/realm/" + to : K.base)]);
    swaps.push(["/realm/" + id, to ? "/realm/" + to : ""]);
    swaps.push([encodeURIComponent("/realm/" + id),
                to ? encodeURIComponent("/realm/" + to) : ""]);
    swaps.push([DOMAINS_OF[id], to ? to + ".example.com" : "example.com"]);
    swaps.push([id, to || "default"]);
  });
  swaps.push([K.base, "http://127.0.0.1:1"]);
  swaps.push([encodeURIComponent(K.base),
              encodeURIComponent("http://127.0.0.1:1")]);
  swaps.push([origin.host, "127.0.0.1:1"]);
  swaps.push([encodeURIComponent(origin.host), "127.0.0.1%3A1"]);
  swaps.forEach(function (pair) {
    text = text.split(JSON.stringify(pair[0]).slice(1, -1))
      .join(JSON.stringify(pair[1]).slice(1, -1));
  });
  text = text.split("['private_key_jwt','tls_client_auth'," +
                    "'self_signed_tls_client_auth']")
    .join("['private_key_jwt']");
  // The in-process placeholder knows seconds; a running service has been up
  // longer.
  text = text.replace(/up \d+ (second|minute|hour|day)\(s\)/g,
                      "up 1 second(s)");
  log.debug("Leaving placed().");
  return JSON.parse(text);
}

async function test() {
  log.debug("Entering test().");
  const recorded = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8"));
  recorded.wire.forEach(function (one) {
    if (one.step === "rfc9700 report" && one.body &&
        Array.isArray(one.body.requirements)) {
      one.body.requirements.forEach(function (row) {
        recordedRows[one.mode + " " + row.id] = row;
      });
    }
  });
  const record = { wire: [], problems: [] };
  for (const mode of MODES) {
    const id = await setUpRealm(mode);
    REALMS_OF[id] = mode.name === "development" ? "" : mode.prefix;
    DOMAINS_OF[id] = id + ".example.net";
    await runMode(mode, id, record);
  }
  const now = normalise(record);
  const expected = recorded.wire.filter(function (one) {
    return one.mode !== "flows";
  });
  K.check("the conversation has as many steps as recorded, the flows " +
          "aside", function () {
    assert.strictEqual(now.wire.length, expected.length);
  });
  const differing = [];
  expected.forEach(function (one, i) {
    const why = firstDifference(one, now.wire[i], "wire");
    if (why) {
      differing.push(one.mode + ", " + one.step + ": " + why);
    } else {
      K.check(one.mode + ", " + one.step + ": " + one.method +
              " answers as recorded (" + one.status + ")", function () {
        assert.ok(true);
      });
    }
  });
  differing.forEach(function (one) {
    log.error("DIFFERS: " + one.slice(0, 900));
  });
  K.check("every step answers as recorded", function () {
    assert.strictEqual(differing.length, 0, differing.length +
                       " step(s) differ; the first: " +
                       String(differing[0]).slice(0, 600));
  });
  log.debug("Leaving test().");
}

K.main(test, 466);
