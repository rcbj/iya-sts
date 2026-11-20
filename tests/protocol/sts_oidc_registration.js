// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_oidc_registration.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT DYNAMIC CLIENT REGISTRATION, RFC 7591 / 7592's GAPS AND A
// FETCHED `jwks_uri` (#120), OVER THE WIRE.
//
// D12 (#444): carries over `tests/oidc_registration.js` — its rule table
// (1a, `oidcRegistrationProblem()`) asked of `POST /oauth2/register` with
// each code read off `/admin-api/audit`, and its child process (2a–2f) —
// against a running service, in a development realm of its own (switched to
// product for one document and back), with a listener in this job playing
// the clients' key host, which the SERVICE dials (OUTBOUND_TEST_HOST):
//
//   1. every registration rule: an unknown application_type
//      (STS-REG-0181), a native client's redirect URIs and an implicit web
//      client on localhost (STS-REG-0182), response and grant types that
//      disagree (STS-REG-0183), a code grant with no redirect URI
//      (STS-REG-0184), an ID Token algorithm this service does not sign
//      with or `none` (STS-REG-0185), jwks with jwks_uri or an http one
//      (STS-REG-0186), the step-up defaults' types (STS-REG-0187), an http
//      initiate_login_uri (STS-REG-0188), the display URIs (STS-REG-0365);
//      and every well-formed one registered;
//   2a. section 2's defaults applied; the refusals by error (and a wrong
//      JSON type); `none` never in id_token_signing_alg_values_supported in
//      either mode; a native loopback client;
//   2b. RFC 7592: the read, an update naming another client_id or a secret
//      it was not issued, a well-formed update, the routes under a named
//      server, and 401 invalid_token for a client removed by hand;
//   2c. a registered response_types and grant_types ENFORCED;
//   2d. an RFC 7523 assertion verified against a fetched jwks_uri, the set
//      cached, a new kid not fetched for inside
//      `oauth2.clientJwksRefetchS` and fetched past it, a non-set and a
//      redirect refused, and an http jwks_uri never dialled with
//      `federation.outboundAllowHttp` off;
//   2e. an encrypted ID Token whose jwks_uri gives no key refused, naming
//      the fetch;
//   2f. logo_uri, policy_uri and tos_uri returned and kept on the entry,
//      their refusals, and an RFC 7592 update dropping two.
//
// NOT CARRIED, and why: `initiateLoginUriOf()` and `step_up.ts`'s
// registered defaults as functions (1b–1f), `clientDisplayOf()` and the
// encryption key reader called directly (2e's second half, 2f's second)
// are library — (d); the display reaches the sign-in screen's view, which
// `sts_authn_*` jobs read. Owed, as the in-process file says: a refresh
// token withheld from a client that registered no refresh_token grant
// (STS-OAUTH-0600), and the portal's initiate_login_uri link.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_oidc_registration");
const log = K.log;

const FLOOR = 62;
const K1 = K.keyPair("ES256", "k1");
const K2 = K.keyPair("ES256", "k2");

let D;
let ISS;
let L;
let served;
const hits = {};

function check(what, fn) {
  K.check(what, fn);
}

function register(body, prefix) {
  log.debug("Entering register().");
  log.debug("Leaving register().");
  return K.send(K.rb(D) + (prefix || "") + "/oauth2/register",
                { json: body });
}

function manage(method, client, body) {
  log.debug("Entering manage(). " + method);
  log.debug("Leaving manage().");
  return K.send(K.rb(D) + "/oauth2/register/" +
    encodeURIComponent(client.client_id), { method: method,
    headers: { Authorization: "Bearer " + client.registration_access_token },
    json: body });
}

// ------------------------------------------------------------------ 1
async function rules() {
  log.debug("Entering rules().");
  log.info("=== 1. every registration rule, by its code ===");
  const WEB = { redirect_uris: ["https://rp.example/cb"] };
  const cases = [
    [{ grant_types: ["client_credentials"] }, "",
     "client_credentials alone needs no redirect URI"],
    [{ grant_types: ["authorization_code", "refresh_token"],
       response_types: ["code", "code id_token"],
       redirect_uris: ["https://rp.example/cb"] }, "",
     "code id_token without the implicit grant (FAPI 1.0 Advanced's hybrid)"],
    [{ grant_types: ["authorization_code"], response_types: ["code token"],
       redirect_uris: ["https://rp.example/cb"] }, "STS-REG-0183",
     "a response type returning an access token without the implicit grant"],
    [WEB, "", "a plain web client"],
    [{ response_types: ["none"], redirect_uris: ["https://rp.example/cb"] },
     "", "response_types none alone, with the default grant"],
    [{ application_type: "desktop" }, "STS-REG-0181",
     "an unknown application_type"],
    [{ application_type: "native", redirect_uris: ["https://rp.example/cb"] },
     "STS-REG-0182", "a native client with an https redirect URI"],
    [{ application_type: "native", redirect_uris: ["http://rp.example/cb"] },
     "STS-REG-0182", "a native client with a non-loopback http redirect URI"],
    [{ application_type: "native",
       redirect_uris: ["http://127.0.0.1:8080/cb", "com.example.app:/cb"] },
     "", "a native client on the loopback and a private-use scheme"],
    [{ grant_types: ["implicit"], response_types: ["id_token"],
       redirect_uris: ["http://localhost/cb"] }, "STS-REG-0182",
     "an implicit web client on localhost"],
    [{ grant_types: ["client_credentials"], response_types: ["code"],
       redirect_uris: ["https://rp.example/cb"] }, "STS-REG-0183",
     "response_types code without the authorization_code grant"],
    [{ grant_types: ["authorization_code"] }, "STS-REG-0184",
     "the authorization_code grant with no redirect_uris"],
    [Object.assign({ id_token_signed_response_alg: "XX512" }, WEB),
     "STS-REG-0185", "an ID Token algorithm this service does not sign with"],
    [Object.assign({ id_token_signed_response_alg: "none" }, WEB),
     "STS-REG-0185", "an unsigned ID Token (OIDF oidcc-idtoken-unsigned)"],
    [Object.assign({ userinfo_signed_response_alg: "none" }, WEB), "",
     "UserInfo unsigned, which section 2 allows"],
    [Object.assign({ jwks: { keys: [] },
                     jwks_uri: "https://rp.example/jwks" }, WEB),
     "STS-REG-0186", "jwks together with jwks_uri"],
    [Object.assign({ jwks_uri: "http://rp.example/jwks" }, WEB),
     "STS-REG-0186", "a jwks_uri that is not https"],
    [Object.assign({ default_max_age: -5 }, WEB), "STS-REG-0187",
     "a negative default_max_age"],
    [Object.assign({ require_auth_time: "yes" }, WEB), "STS-REG-0187",
     "require_auth_time that is not a boolean"],
    [Object.assign({ default_acr_values: "mfa" }, WEB), "STS-REG-0187",
     "default_acr_values that is not an array"],
    [Object.assign({ initiate_login_uri: "http://rp.example/login" }, WEB),
     "STS-REG-0188", "an http initiate_login_uri"],
    [Object.assign({ logo_uri: "https://cdn.rp.example/logo.png",
                     policy_uri: "https://rp.example/privacy",
                     tos_uri: "https://rp.example/terms" }, WEB), "",
     "https logo_uri, policy_uri and tos_uri"],
    [Object.assign({ logo_uri: "http://cdn.rp.example/logo.png" }, WEB),
     "STS-REG-0365", "an http logo_uri"],
    [Object.assign({ policy_uri: "not a url" }, WEB), "STS-REG-0365",
     "a policy_uri that is not a URL"],
    [Object.assign({ tos_uri: "https://u:p@rp.example/terms" }, WEB),
     "STS-REG-0365", "a tos_uri carrying credentials"],
    [Object.assign({ tos_uri: 42 }, WEB), "STS-REG-0365",
     "a tos_uri that is not a string"],
    [Object.assign({ logo_uri: "data:image/png;base64,AAAA" }, WEB),
     "STS-REG-0365", "a data: logo_uri"],
    [Object.assign({ initiate_login_uri: "https://rp.example/login",
                     default_max_age: 300, require_auth_time: true,
                     default_acr_values: ["mfa", "1"] }, WEB), "",
     "every member well formed"]
  ];
  for (const one of cases) {
    if (!one[1]) {
      const r = await register(one[0]);
      check("1. registered: " + one[2], function () {
        assert.strictEqual(r.status, 201, K.shown(r));
      });
      continue;
    }
    const c = await K.coded(D, one[1], function () {
      return register(one[0]);
    });
    check("1. refused " + one[1] + ": " + one[2], function () {
      assert.strictEqual(c.answer.status, 400, K.shown(c.answer));
      assert.ok(/^invalid_/.test(c.answer.json.error), K.shown(c.answer));
      assert.ok(c.rose >= 1, one[1] + " was not recorded");
    });
  }
  log.debug("Leaving rules().");
}

// ------------------------------------------------------------------ 2a-c
async function registration() {
  log.debug("Entering registration().");
  log.info("=== 2a. registration ===");
  let r = await register({ redirect_uris: ["https://rp.or.example/cb"],
                           client_name: "OR minimal" });
  const minimal = r.json || {};
  check("2a. a registration is answered with section 2's defaults applied",
        function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(minimal.token_endpoint_auth_method,
                       "client_secret_basic");
    assert.deepStrictEqual(minimal.grant_types, ["authorization_code"]);
    assert.deepStrictEqual(minimal.response_types, ["code"]);
    assert.strictEqual(minimal.application_type, "web");
  });
  const refusals = [
    [{ application_type: "desktop",
       redirect_uris: ["https://rp.or.example/cb"] },
     "invalid_client_metadata", "an unknown application_type"],
    [{ application_type: "native",
       redirect_uris: ["https://rp.or.example/cb"] },
     "invalid_redirect_uri", "a native client's https redirect URI"],
    [{ grant_types: ["client_credentials"], response_types: ["code"],
       redirect_uris: ["https://rp.or.example/cb"] },
     "invalid_client_metadata", "grant and response types that disagree"],
    [{ redirect_uris: ["https://rp.or.example/cb"],
       jwks_uri: "http://rp.or.example/jwks" },
     "invalid_client_metadata", "an http jwks_uri"],
    [{ redirect_uris: ["https://rp.or.example/cb"],
       initiate_login_uri: "http://rp.or.example/login" },
     "invalid_client_metadata", "an http initiate_login_uri"],
    [{ redirect_uris: ["https://rp.or.example/cb"],
       grant_types: "authorization_code" },
     "invalid_client_metadata", "grant_types as a string"],
    [{ redirect_uris: ["https://rp.or.example/cb"], client_name: 5 },
     "invalid_client_metadata", "client_name as a number"],
    [{ redirect_uris: ["https://rp.or.example/cb"], contacts: [5] },
     "invalid_client_metadata", "contacts holding a number"],
    [{ redirect_uris: ["https://rp.or.example/cb"],
       id_token_signed_response_alg: "none" },
     "invalid_client_metadata", "id_token_signed_response_alg none, " +
     "naming the member"]
  ];
  for (const one of refusals) {
    r = await register(one[0]);
    check("2a. refused " + one[1] + ": " + one[2], function () {
      assert.strictEqual(r.status, 400, K.shown(r));
      assert.strictEqual(r.json.error, one[1]);
      if (one[0].id_token_signed_response_alg) {
        assert.ok(/id_token_signed_response_alg/.test(
          r.json.error_description));
      }
    });
  }
  const algs = async function () {
    log.debug("Entering algs().");
    const d = await K.send(K.rb(D) + "/.well-known/openid-configuration");
    log.debug("Leaving algs().");
    return (d.json || {}).id_token_signing_alg_values_supported;
  };
  const devAlgs = await algs();
  await K.set(D, "global.mode", "product");
  let productAlgs;
  try {
    productAlgs = await algs();
  } finally {
    await K.set(D, "global.mode", "development");
  }
  check("2a. id_token_signing_alg_values_supported never lists none, in " +
        "development or product", function () {
    [devAlgs, productAlgs].forEach(function (list) {
      assert.ok(Array.isArray(list) && list.length > 0 &&
                list.indexOf("none") < 0, JSON.stringify(list));
    });
  });
  r = await register({ application_type: "native",
                       redirect_uris: ["http://127.0.0.1:9/cb"] });
  check("2a. a native client on the loopback is registered", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(r.json.application_type, "native");
  });

  log.info("=== 2b. RFC 7592 ===");
  r = await manage("GET", minimal);
  check("2b. the read returns the registration, defaults included",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.client_id, minimal.client_id);
    assert.ok(r.json.grant_types && r.json.response_types);
  });
  r = await manage("PUT", minimal, { client_id: "somebody-else",
    redirect_uris: ["https://rp.or.example/cb"] });
  check("2b. an update naming another client_id is refused (section 2.2)",
        function () {
    assert.ok(r.status === 400 && r.json.error === "invalid_request",
              K.shown(r));
  });
  r = await manage("PUT", minimal, { client_id: minimal.client_id,
    client_secret: "not-the-one",
    redirect_uris: ["https://rp.or.example/cb"] });
  check("2b. an update naming a client_secret it was not issued is refused",
        function () {
    assert.ok(r.status === 400 && r.json.error === "invalid_request",
              K.shown(r));
  });
  r = await manage("PUT", minimal, { client_id: minimal.client_id,
    redirect_uris: ["https://rp.or.example/cb2"] });
  check("2b. a well-formed update is answered with the defaults applied",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.token_endpoint_auth_method,
                       "client_secret_basic");
    assert.deepStrictEqual(r.json.redirect_uris,
                           ["https://rp.or.example/cb2"]);
  });
  r = await K.send(K.rb(D) + "/or1/oauth2/register/" +
    encodeURIComponent(minimal.client_id),
    { headers: { Authorization: "Bearer nope" } });
  check("2b. the management routes exist under a named authorization " +
        "server", function () {
    assert.notStrictEqual(r.status, 404, K.shown(r));
  });
  const doomed = (await register({ redirect_uris:
                                   ["https://rp.or.example/cb"] })).json;
  await K.ok(K.rb(D) + "/admin-api/applications/forget",
             { application: doomed.client_id }, "removed a client by hand");
  r = await manage("GET", doomed);
  check("2b. a registration access token for a client that no longer " +
        "exists is 401 invalid_token (section 3)", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_token");
    assert.ok(/invalid_token/.test(r.headers.get("www-authenticate") || ""));
  });

  log.info("=== 2c. enforcement ===");
  const p = K.pkce();
  r = await K.send(K.rb(D) + "/oauth2/authorize?" + new URLSearchParams({
    client_id: minimal.client_id, response_type: "code id_token",
    redirect_uri: "https://rp.or.example/cb2", scope: "openid",
    nonce: "n-1", state: "s-1", code_challenge_method: "S256",
    code_challenge: p.challenge }));
  check("2c. a response_type the client did not register is " +
        "unauthorized_client, redirected", function () {
    assert.strictEqual(r.status, 302, K.shown(r));
    assert.ok(/error=unauthorized_client/.test(r.location), r.location);
  });
  r = await K.send(K.rb(D) + "/oauth2/token", {
    form: { grant_type: "client_credentials" },
    headers: { Authorization: K.basic(minimal.client_id,
                                      minimal.client_secret) } });
  check("2c. a grant the client did not register is unauthorized_client",
        function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "unauthorized_client");
  });
  log.debug("Leaving registration().");
}

// ------------------------------------------------------------------ 2d
async function fetchedKeys() {
  log.debug("Entering fetchedKeys().");
  log.info("=== 2d. a fetched jwks_uri ===");
  for (const one of [["or-keyed", "/jwks"], ["or-empty", "/not-a-set"],
                     ["or-moved", "/redirect"]]) {
    await K.app(D, one[0], { oauthClientId: one[0],
      oauthJwksUri: L.origin + one[1], oauthAssertionIssuer: one[0] });
  }
  const tokenWith = function (id, key) {
    log.debug("Entering tokenWith().");
    const now = Math.floor(Date.now() / 1000);
    log.debug("Leaving tokenWith().");
    return K.send(K.rb(D) + "/oauth2/token", { form: {
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: K.jws("ES256", { kid: key.kid }, { iss: id,
        sub: "or-person", aud: ISS + "/oauth2/token", jti: K.rand(12),
        iat: now, exp: now + 120 }, key) } });
  };
  let r = await tokenWith("or-keyed", K1);
  check("2d. an RFC 7523 assertion verifies against the fetched jwks_uri",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(hits["/jwks"], 1);
  });
  r = await tokenWith("or-keyed", K1);
  check("2d. and the set is cached: a second request fetches nothing",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(hits["/jwks"], 1);
  });
  served = { keys: [K1.jwk, K2.jwk] };
  r = await tokenWith("or-keyed", K2);
  check("2d. a new kid within oauth2.clientJwksRefetchS is not fetched for",
        function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(hits["/jwks"], 1);
  });
  await K.set(D, "oauth2.clientJwksRefetchS", 0);
  r = await tokenWith("or-keyed", K2);
  check("2d. past it, a kid the cached set lacks fetches the set again",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(hits["/jwks"], 2);
  });
  r = await tokenWith("or-empty", K1);
  check("2d. a jwks_uri answering no key set is invalid_grant", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_grant");
  });
  r = await tokenWith("or-moved", K1);
  check("2d. a redirect is not followed (the outbound policy)", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(hits["/redirect"], 1);
    assert.strictEqual(hits["/jwks"], 2);
  });
  await K.app(D, "or-plain", { oauthClientId: "or-plain",
    oauthJwksUri: L.origin + "/jwks-plain", oauthAssertionIssuer:
    "or-plain" });
  await K.set(D, "federation.outboundAllowHttp", false);
  try {
    r = await tokenWith("or-plain", K1);
  } finally {
    await K.set(D, "federation.outboundAllowHttp", true);
  }
  check("2d. with federation.outboundAllowHttp off an http jwks_uri is " +
        "never dialled", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(!hits["/jwks-plain"]);
  });
  log.debug("Leaving fetchedKeys().");
}

// ------------------------------------------------------------------ 2e, 2f
async function encryptionAndDisplay() {
  log.debug("Entering encryptionAndDisplay().");
  log.info("=== 2e. an encrypted response's key ===");
  let r = await register({ redirect_uris: ["https://rp.or.example/cb"],
    jwks_uri: "https://127.0.0.1:1/jwks",
    id_token_encrypted_response_alg: "RSA-OAEP-256" });
  check("2e. an encrypted ID Token whose jwks_uri gives no key is refused, " +
        "naming the fetch", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client_metadata");
    assert.ok(/could not be fetched/.test(r.json.error_description));
  });

  log.info("=== 2f. what the screens show ===");
  const LOGO = "https://cdn.or.example:8443/logo.png";
  r = await register({ redirect_uris: ["https://rp.or.example/cb"],
    client_name: "OR shown", logo_uri: LOGO,
    policy_uri: "https://rp.or.example/privacy",
    tos_uri: "https://rp.or.example/terms" });
  const shown = r.json || {};
  const entryOf = async function (id) {
    log.debug("Entering entryOf().");
    const v = await K.send(K.rb(D) + "/admin-api/applications?application=" +
                           encodeURIComponent(id));
    log.debug("Leaving entryOf().");
    return JSON.stringify(v.json || {});
  };
  let entry = await entryOf(shown.client_id);
  check("2f. logo_uri, policy_uri and tos_uri are returned and kept as " +
        "oauthLogoUri, oauthPolicyUri and oauthTosUri", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(shown.logo_uri, LOGO);
    assert.strictEqual(shown.policy_uri, "https://rp.or.example/privacy");
    assert.strictEqual(shown.tos_uri, "https://rp.or.example/terms");
    ["oauthLogoUri", "oauthPolicyUri", "oauthTosUri"].forEach(function (k) {
      assert.ok(entry.indexOf(k) >= 0, k + " " + entry.slice(0, 300));
    });
    assert.ok(entry.indexOf(LOGO) >= 0);
  });
  for (const bad of [{ logo_uri: "http://cdn.or.example/logo.png" },
                     { policy_uri: "/privacy" },
                     { tos_uri: "https://rp.or.example/a b" }]) {
    r = await register(Object.assign({
      redirect_uris: ["https://rp.or.example/cb"] }, bad));
    check("2f. refused invalid_client_metadata: " + JSON.stringify(bad),
          function () {
      assert.strictEqual(r.status, 400, K.shown(r));
      assert.strictEqual(r.json.error, "invalid_client_metadata");
      assert.ok(new RegExp(Object.keys(bad)[0]).test(
        r.json.error_description));
    });
  }
  r = await manage("PUT", shown, { client_id: shown.client_id,
    redirect_uris: ["https://rp.or.example/cb"], client_name: "OR shown",
    logo_uri: LOGO });
  entry = await entryOf(shown.client_id);
  check("2f. an RFC 7592 update that drops policy_uri and tos_uri removes " +
        "them from the entry", function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.strictEqual(r.json.logo_uri, LOGO);
    assert.strictEqual(r.json.tos_uri, undefined);
    assert.ok(entry.indexOf("https://rp.or.example/terms") < 0 &&
              entry.indexOf("https://rp.or.example/privacy") < 0,
              entry.slice(0, 400));
  });
  r = await manage("PUT", shown, { client_id: shown.client_id,
    redirect_uris: ["https://rp.or.example/cb"],
    logo_uri: "ftp://cdn.or.example/logo.png" });
  check("2f. an RFC 7592 update with a non-https logo_uri is refused",
        function () {
    assert.ok(r.status === 400 && r.json.error === "invalid_client_metadata",
              K.shown(r));
  });
  log.debug("Leaving encryptionAndDisplay().");
}

async function test() {
  log.debug("Entering test().");
  D = await K.realm("oreg", "development",
                    { "federation.outboundAllowHttp": true });
  ISS = (await K.send(K.rb(D) + "/.well-known/oauth-authorization-server"))
    .json.issuer;
  served = { keys: [K1.jwk] };
  const count = function (path, fn) {
    log.debug("Entering count().");
    log.debug("Leaving count().");
    return function (req, res) {
      hits[path] = (hits[path] || 0) + 1;
      fn(req, res);
    };
  };
  L = await K.listener({
    "/jwks": count("/jwks", function (req, res) {
      res.writeHead(200, { "Content-Type": "application/jwk-set+json" });
      res.end(JSON.stringify(served));
    }),
    "/jwks-plain": count("/jwks-plain", function (req, res) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(served));
    }),
    "/not-a-set": count("/not-a-set", function (req, res) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{\"hello\":\"world\"}");
    }),
    "/redirect": count("/redirect", function (req, res) {
      res.writeHead(302, { Location: "/jwks" });
      res.end();
    })
  });
  try {
    await rules();
    await registration();
    await fetchedKeys();
    await encryptionAndDisplay();
  } finally {
    L.close();
  }
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
