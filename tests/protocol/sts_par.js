// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_par.js
//
// ---------------------------------------------------------------------------
// RFC 9126, PUSHED AUTHORIZATION REQUESTS, OVER THE WIRE.
//
// D12 (#444): carries over `tests/par.js` — its child process's sections 3a
// to 3o, and the half of its library sections a client or an administrator
// can see — against a running service, in throwaway realms of its own (a
// development realm, an RFC 9700 one, an OAuth 2.1 one, a product one and a
// small-store one). What `par.get()` showed in process is read here off
// `GET /admin-api/oauth2/monitor`'s `pushedRequests` rows, and the codes off
// `/admin-api/audit`:
//
//   A. discovery: both documents and a named server's own URL;
//   B. a push (201, JSON, no-store, a 256-bit reference, 60 s), kept with
//      its client authenticated and no credential; two pushes two
//      references; reads that do not spend; the round trip carrying only
//      the request_uri; the PUSHED state, redirect_uri and PKCE used; the
//      spend, and a replay refused (STS-OAUTH-0412);
//   C. section 2.3: 405 with Allow (0401), 413 (0402), a JSON body, a
//      malformed and a repeated parameter (0403), `resource` repeated kept,
//      request_uri in a push (0404), no client (0405), two clients (0406),
//      429 with Retry-After (0407) and another client unaffected;
//   D. the push validated as an authorization request;
//   E. client authentication: observed in development, a public client, a
//      client assertion to the PAR endpoint, the issuer, the token endpoint
//      and another audience; RFC 9700's 401 with the Basic challenge;
//      OAuth 2.1's two methods and its default redirect_uri; product's
//      public client allowed and its confidential client refused;
//   F. at the authorization endpoint: unknown (0410), another client's
//      (0413), no client_id, another authorization server's (0414), a named
//      server's own, expired (0411);
//   G. section 2.4 on, off, for a failed credential, for a public client,
//      and turned off after the push (section 7.4);
//   H. the require policy (STS-OAUTH-0419): the realm, a client, RFC 7591
//      registration (and STS-REG-0120 for a string), a named server, a
//      removed member not checking, "maybe" refused at the registry;
//   I. section 3: a pushed request object, parameters beside it (0409),
//      another client_id, no client_id claim, a bad signature, a plain push
//      where a signed object is required (0415) and the requirement
//      arriving after the push;
//   J. RFC 9449 section 10.1: the code bound (refused without the key,
//      redeemed with it), another dpop_jkt (0417), a proof for another URL
//      (recorded as the checker's STS-OAUTH-0106, not 0416);
//   K. the sign-in and consent markers stripped from a push;
//   L. switched off (0400): 404, the member gone, an earlier request_uri
//      still usable (section 5);
//   M. a realm's full store 503 (0408), another realm unaffected;
//   N. the administrator's view: the rows' paging and filters, a delete,
//      and the per-client counters.
//
// NOT CARRIED, and why: the request_uri namespace predicate and `resolve()`
// / `spend()` called directly (1a, 1b, 1f–1j) are library — what they
// answer is what B and F observe; "a push bound to nobody" (1c) cannot be
// sent, since the endpoint refuses a push naming no client first (C);
// the expiry SWEEP with a moved clock (1k–1n) is class (d) — the wire sees
// the expiry (F) and not the sweep; the registry's attribute parser (2) is
// observed only through H's refusal.
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_par");
const log = K.log;

const SECRET = "par-client-secret-" + K.rand(16);
const REDIRECT = "https://rp.par.example/cb";
const OTHER_REDIRECT = "https://rp.par.example/elsewhere";
const UNREGISTERED = "https://rp.par.example/per-request";
const PERSON = "par-alice-" + K.STAMP;
const PASSWORD = "Par-" + K.rand(9) + "-pw!";
const EC = K.keyPair("ES256", "par-ec");
const FLOOR = 96;

let D;
let R9700;
let R21;
let PROD;
let FULL;
let ISS;
let PKCE;

function check(what, fn) {
  K.check(what, fn);
}

function fields(id, extra) {
  log.debug("Entering fields(). " + id);
  log.debug("Leaving fields().");
  return Object.assign({ oauthClientId: id, oauthClientSecret: SECRET,
    oauthRedirectUri: [REDIRECT],
    oauthTokenEndpointAuthMethod: "client_secret_basic",
    oauthGrantType: ["authorization_code", "refresh_token"],
    oauthJwks: JSON.stringify({ keys: [EC.jwk] }) }, extra || {});
}

async function client(realm, id, extra) {
  log.debug("Entering client(). " + id);
  await K.app(realm, id, fields(id, extra));
  log.debug("Leaving client().");
}

async function publicClient(realm, id) {
  log.debug("Entering publicClient(). " + id);
  await K.app(realm, id, { oauthClientId: id, oauthRedirectUri: [REDIRECT],
    oauthTokenEndpointAuthMethod: "none",
    oauthGrantType: ["authorization_code"] });
  log.debug("Leaving publicClient().");
}

function pushForm(extra) {
  log.debug("Entering pushForm().");
  log.debug("Leaving pushForm().");
  return Object.assign({ response_type: "code", redirect_uri: REDIRECT,
    scope: "openid", state: "st-" + K.rand(4), nonce: "n-" + K.rand(4),
    code_challenge: PKCE.challenge, code_challenge_method: "S256" },
    extra || {});
}

// A PUSH: Basic by default; `o.basic === false` names the client in the
// body; `o.form` replaces the whole form (a string is sent as written).
function push(realm, id, extra, o) {
  log.debug("Entering push(). " + id);
  const opts = o || {};
  const headers = Object.assign({}, opts.headers || {});
  if (opts.basic !== false) {
    headers.Authorization = K.basic(id, opts.secret || SECRET);
  }
  log.debug("Leaving push().");
  return K.send(K.rb(realm) + (opts.prefix || "") + "/oauth2/par", {
    headers: headers,
    form: opts.form || pushForm(Object.assign(
      opts.basic === false ? { client_id: id } : {}, extra || {})) });
}

function authorize(realm, query, prefix, b) {
  log.debug("Entering authorize().");
  log.debug("Leaving authorize().");
  return (b || K.browser()).go(K.rb(realm) + (prefix || "") +
    "/oauth2/authorize?" + new URLSearchParams(query).toString());
}

function refused(r, status, error, pattern) {
  log.debug("Entering refused().");
  log.debug("Leaving refused().");
  return r.status === status && !!r.json && r.json.error === error &&
    (!pattern || pattern.test(r.json.error_description || ""));
}

function digestsOf(uri) {
  log.debug("Entering digestsOf().");
  const h = nodeCrypto.createHash("sha256").update(String(uri));
  const raw = h.digest();
  log.debug("Leaving digestsOf().");
  return [raw.toString("base64url"), raw.toString("hex"),
          "sha256:" + raw.toString("hex").slice(0, 12)];
}

// THE ADMINISTRATOR'S ROW FOR ONE PUSHED REQUEST, or null.
async function listed(realm, uri, query) {
  log.debug("Entering listed().");
  const r = await K.send(K.rb(realm) + "/admin-api/oauth2/monitor?" +
    new URLSearchParams(Object.assign({ per: "200" }, query || {})));
  const ids = digestsOf(uri);
  const items = (parSection(r.json).pushedRequests || {}).items || [];
  const row = items.find(function (one) {
    return ids.indexOf(one.request_uri_digest) >= 0 ||
           (one.request_uri_shown &&
            ids[2].indexOf(one.request_uri_shown.replace(/…$/, "")) === 0);
  }) || null;
  log.debug("Leaving listed(). " + !!row);
  return row;
}

// The monitor's PAR section: its counters, its clients and its rows.
function parSection(json) {
  log.debug("Entering parSection().");
  const found = ((json && json.sections) || []).find(function (one) {
    return one.id === "par";
  });
  log.debug("Leaving parSection().");
  return found || {};
}

async function monitor(realm, query) {
  log.debug("Entering monitor().");
  const r = await K.send(K.rb(realm) + "/admin-api/oauth2/monitor?" +
    new URLSearchParams(query || {}));
  log.debug("Leaving monitor().");
  return parSection(r.json);
}

async function flow(realm, id, uri, prefix, extraQuery) {
  log.debug("Entering flow().");
  const b = K.browser();
  const first = await authorize(realm, Object.assign(
    { client_id: id, request_uri: uri }, extraQuery || {}), prefix, b);
  const final = await K.signIn(realm, b, first, PERSON, PASSWORD);
  log.debug("Leaving flow().");
  return { first: first, final: final };
}

function redeem(realm, id, code, extraHeaders) {
  log.debug("Entering redeem().");
  log.debug("Leaving redeem().");
  return K.send(K.rb(realm) + "/oauth2/token", {
    headers: Object.assign({ Authorization: K.basic(id, SECRET) },
                           extraHeaders || {}),
    form: { grant_type: "authorization_code", code: code,
            redirect_uri: REDIRECT, code_verifier: PKCE.verifier } });
}

// ------------------------------------------------------------------- A, B
async function discoveryAndFlow() {
  log.debug("Entering discoveryAndFlow().");
  log.info("=== A. discovery ===");
  const rb = K.rb(D);
  let meta = (await K.send(rb +
    "/.well-known/oauth-authorization-server")).json;
  check("A1. RFC 8414 metadata publishes the PAR endpoint and " +
        "require_pushed_authorization_requests false", function () {
    assert.strictEqual(meta.pushed_authorization_request_endpoint,
                       ISS + "/oauth2/par");
    assert.strictEqual(meta.require_pushed_authorization_requests, false);
  });
  const oidc = (await K.send(rb + "/.well-known/openid-configuration")).json;
  check("A2. and so does the OpenID Provider Configuration", function () {
    assert.strictEqual(oidc.pushed_authorization_request_endpoint,
                       ISS + "/oauth2/par");
  });
  const named = (await K.send(rb +
    "/.well-known/oauth-authorization-server/parAS")).json;
  check("A3. a named authorization server publishes its own", function () {
    assert.strictEqual(named.pushed_authorization_request_endpoint,
                       ISS + "/parAS/oauth2/par");
  });

  log.info("=== B. a push, and the whole flow ===");
  const form = pushForm();
  let r = await K.send(rb + "/oauth2/par", {
    headers: { Authorization: K.basic("par-a", SECRET) }, form: form });
  check("B1. a push is 201 { request_uri, expires_in }, JSON, no-store, a " +
        "256-bit base64url reference and the default 60 s", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.ok(/application\/json/.test(r.headers.get("content-type")));
    assert.ok(/no-store/.test(r.headers.get("cache-control") || ""));
    assert.ok(/^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$/.test(
      r.json.request_uri), r.json.request_uri);
    assert.strictEqual(r.json.expires_in, 60);
  });
  const uri = r.json.request_uri;
  const second = await push(D, "par-a");
  check("B2. two pushes are two references", function () {
    assert.strictEqual(second.status, 201);
    assert.notStrictEqual(second.json.request_uri, uri);
  });
  let row = await listed(D, uri);
  check("B3. the push is kept with the client authenticated, its method, " +
        "and no credential among its parameters", function () {
    assert.ok(row, "no row for the push");
    assert.strictEqual(row.client_authenticated, true);
    assert.strictEqual(row.authentication_method, "client_secret_basic");
    assert.strictEqual(row.parameters.client_id, "par-a");
    assert.strictEqual(row.parameters.client_secret, undefined);
    assert.strictEqual(row.state, "live");
    assert.strictEqual(row.source, "form");
  });
  // Two reads before the sign-in: neither spends.
  const peek = await authorize(D, { client_id: "par-a", request_uri: uri });
  const run = await flow(D, "par-a", uri, "",
    { state: "evil", redirect_uri: OTHER_REDIRECT,
      scope: "openid profile" });
  check("B4. the request_uri sends the browser to sign in, and a first " +
        "read does not spend it", function () {
    assert.ok(K.toSignIn(peek), K.shown(peek));
    assert.ok(K.toSignIn(run.first), K.shown(run.first));
  });
  check("B5. the round trip carries the request_uri and not the pushed " +
        "parameters", function () {
    const loc = decodeURIComponent(run.first.location);
    assert.ok(!/code_challenge|state=st-/.test(loc), loc);
  });
  const params = K.answerAt(run.final, REDIRECT);
  check("B6. the response goes to the PUSHED redirect_uri with the PUSHED " +
        "state — the query's own ignored", function () {
    assert.ok(params && params.get("code"), K.shown(run.final));
    assert.strictEqual(params.get("state"), form.state);
  });
  r = await redeem(D, "par-a", params.get("code"));
  check("B7. the code redeems with the pushed PKCE challenge's verifier",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(r.json.access_token && r.json.id_token);
  });
  row = await listed(D, uri, { state: "spent" });
  check("B8. the request_uri is spent by the response, and both reads " +
        "before it were counted", function () {
    assert.ok(row, "no spent row");
    assert.strictEqual(row.state, "spent");
    assert.ok(row.reads >= 2, String(row.reads));
    assert.ok(row.spent_at);
  });
  const replay = await K.coded(D, "STS-OAUTH-0412", function () {
    return authorize(D, { client_id: "par-a", request_uri: uri });
  });
  check("B9. a replay of a spent request_uri is refused 400 on this " +
        "server, recorded STS-OAUTH-0412", function () {
    assert.ok(refused(replay.answer, 400, "invalid_request_uri",
                      /already used/), K.shown(replay.answer));
    assert.ok(replay.rose >= 1);
  });
  log.debug("Leaving discoveryAndFlow().");
}

// ------------------------------------------------------------------- C, D
async function section23() {
  log.debug("Entering section23().");
  log.info("=== C. what section 2.3 refuses ===");
  const rb = K.rb(D);
  let c = await K.coded(D, "STS-OAUTH-0401", function () {
    return K.send(rb + "/oauth2/par");
  });
  check("C1. GET is 405 with Allow: POST (STS-OAUTH-0401)", function () {
    assert.strictEqual(c.answer.status, 405);
    assert.strictEqual(c.answer.headers.get("allow"), "POST");
    assert.ok(c.rose >= 1);
  });
  let r = await K.send(rb + "/oauth2/par", { method: "PUT",
                                            form: pushForm() });
  check("C2. and so is PUT", function () {
    assert.strictEqual(r.status, 405);
  });
  await K.set(D, "oauth2.parMaxBodyBytes", 1024);
  try {
    c = await K.coded(D, "STS-OAUTH-0402", function () {
      return push(D, "par-a", { state: "x".repeat(2000) });
    });
    r = await push(D, "par-a");
  } finally {
    await K.unset(D, "oauth2.parMaxBodyBytes");
  }
  check("C3. a push past oauth2.parMaxBodyBytes is 413 (STS-OAUTH-0402), " +
        "and one under it is not", function () {
    assert.strictEqual(c.answer.status, 413, K.shown(c.answer));
    assert.ok(c.rose >= 1);
    assert.strictEqual(r.status, 201);
  });
  c = await K.coded(D, "STS-OAUTH-0403", function () {
    return K.send(rb + "/oauth2/par", { headers: {
      Authorization: K.basic("par-a", SECRET),
      "Content-Type": "application/json" },
      raw: JSON.stringify(pushForm()) });
  });
  check("C4. a JSON body is refused (STS-OAUTH-0403)", function () {
    assert.ok(refused(c.answer, 400, "invalid_request",
                      /x-www-form-urlencoded/), K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  r = await push(D, "par-a", { max_age: "not-a-number" });
  check("C5. a malformed parameter is refused", function () {
    assert.ok(refused(r, 400, "invalid_request"), K.shown(r));
  });
  r = await K.send(rb + "/oauth2/par", {
    headers: { Authorization: K.basic("par-a", SECRET) },
    form: new URLSearchParams(pushForm()).toString() + "&state=again" });
  check("C6. a repeated state is refused", function () {
    assert.ok(refused(r, 400, "invalid_request", /repeats state/),
              K.shown(r));
  });
  r = await K.send(rb + "/oauth2/par", {
    headers: { Authorization: K.basic("par-a", SECRET) },
    form: new URLSearchParams(pushForm()).toString() +
      "&resource=" + encodeURIComponent("https://api1.par.example/") +
      "&resource=" + encodeURIComponent("https://api2.par.example/") });
  const two = r.status === 201 ? await listed(D, r.json.request_uri) : null;
  check("C7. resource may repeat (RFC 8707), and both are kept",
        function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.ok(two && Array.isArray(two.parameters.resource) &&
              two.parameters.resource.length === 2,
              JSON.stringify(two && two.parameters));
  });
  c = await K.coded(D, "STS-OAUTH-0404", function () {
    return push(D, "par-a",
                { request_uri: "urn:ietf:params:oauth:request_uri:x" });
  });
  check("C8. request_uri in a push is refused (section 2.1, " +
        "STS-OAUTH-0404)", function () {
    assert.ok(refused(c.answer, 400, "invalid_request",
                      /MUST NOT be provided/), K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  c = await K.coded(D, "STS-OAUTH-0405", function () {
    return K.send(rb + "/oauth2/par", { form: pushForm() });
  });
  check("C9. a push naming no client is refused (STS-OAUTH-0405)",
        function () {
    assert.ok(refused(c.answer, 400, "invalid_request", /requires client_id/),
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  c = await K.coded(D, "STS-OAUTH-0406", function () {
    return push(D, "par-a", { client_id: "par-b" });
  });
  check("C10. a body client_id that is not the authenticated client is " +
        "refused (STS-OAUTH-0406)", function () {
    assert.ok(refused(c.answer, 400, "invalid_request",
                      /must\s+be the same client/), K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  await K.set(D, "oauth2.parRequestsPerMinute", 3);
  const statuses = [];
  let other;
  let rate;
  try {
    for (let i = 0; i < 3; i++) {
      statuses.push(await push(D, "par-limit"));
    }
    rate = await K.coded(D, "STS-OAUTH-0407", function () {
      return push(D, "par-limit");
    });
    other = await push(D, "par-b");
  } finally {
    await K.unset(D, "oauth2.parRequestsPerMinute");
  }
  check("C11. the fourth push in the window is 429 with Retry-After " +
        "(STS-OAUTH-0407)", function () {
    assert.deepStrictEqual(statuses.map(function (one) {
      return one.status;
    }), [201, 201, 201]);
    assert.strictEqual(rate.answer.status, 429, K.shown(rate.answer));
    assert.ok(Number(rate.answer.headers.get("retry-after")) > 0);
    assert.ok(rate.rose >= 1);
  });
  check("C12. and another client is not affected", function () {
    assert.strictEqual(other.status, 201, K.shown(other));
  });

  log.info("=== D. validated as an authorization request ===");
  const cases = [
    ["D1. an unsupported response_type is refused at the push",
     { response_type: "bogus" }, "unsupported_response_type"],
    ["D2. no redirect_uri is refused", { redirect_uri: "" },
     "invalid_request", /redirect_uri/],
    ["D3. an unusable redirect_uri is refused for its shape",
     { redirect_uri: "javascript:alert(1)" }, "invalid_request"],
    ["D4. a malformed claims request is refused", { claims: "{not json" },
     "invalid_request"],
    ["D5. a resource with a fragment is invalid_target",
     { resource: "https://api.par.example/#frag" }, "invalid_target"],
    ["D6. malformed authorization_details are refused",
     { authorization_details: "{\"type\": 1}" },
     "invalid_authorization_details"],
    ["D7. a response_mode this server does not advertise is refused",
     { response_mode: "web_message" }, "invalid_request"],
    ["D8. an unadvertised code_challenge_method is refused",
     { code_challenge_method: "S512" }, null]
  ];
  for (const one of cases) {
    r = await push(D, "par-a", one[1]);
    check(one[0], function () {
      if (one[2]) {
        assert.ok(refused(r, 400, one[2], one[3]), K.shown(r));
      } else {
        assert.strictEqual(r.status, 400, K.shown(r));
      }
    });
  }
  log.debug("Leaving section23().");
}

// ---------------------------------------------------------------------- E
function assertion(aud) {
  log.debug("Entering assertion().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving assertion().");
  return K.jws("ES256", { kid: "par-ec" }, { iss: "par-jwt", sub: "par-jwt",
    aud: aud, jti: K.rand(8), iat: now, exp: now + 120 }, EC);
}

function assertionForm(aud) {
  log.debug("Entering assertionForm().");
  log.debug("Leaving assertionForm().");
  return pushForm({ client_id: "par-jwt",
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion(aud) });
}

async function clientAuthentication() {
  log.debug("Entering clientAuthentication().");
  log.info("=== E. client authentication as at the token endpoint ===");
  let r = await push(D, "par-a", {}, { secret: "wrong-secret" });
  let row = r.status === 201 ? await listed(D, r.json.request_uri) : null;
  check("E1. development: a wrong secret is observed, not refused, and " +
        "the push is not authenticated", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(row && row.client_authenticated, false);
  });
  r = await push(D, "par-public", {}, { basic: false });
  row = r.status === 201 ? await listed(D, r.json.request_uri) : null;
  check("E2. a public client pushes with client_id alone", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(row && row.client_authenticated, false);
  });
  const audiences = [
    ["E3. private_key_jwt with the PAR endpoint URL as its audience " +
     "authenticates (section 2)", ISS + "/oauth2/par", true],
    ["E4. and with the issuer", ISS, true],
    ["E5. and with the token endpoint URL", ISS + "/oauth2/token", true],
    ["E6. another audience does not authenticate (development observes)",
     "https://somebody-else.example/token", false]
  ];
  for (const one of audiences) {
    r = await push(D, "par-jwt", {}, { basic: false,
                                       form: assertionForm(one[1]) });
    row = r.status === 201 ? await listed(D, r.json.request_uri) : null;
    check(one[0], function () {
      assert.strictEqual(r.status, 201, K.shown(r));
      assert.strictEqual(row && row.client_authenticated, one[2]);
      if (one[2]) {
        assert.strictEqual(row.authentication_method, "private_key_jwt");
      }
    });
  }
  r = await push(R9700, "par-a", {}, { secret: "wrong-secret" });
  check("E7. RFC 9700 mode: a wrong secret at PAR is 401 invalid_client " +
        "with the Basic challenge", function () {
    assert.strictEqual(r.status, 401, K.shown(r));
    assert.strictEqual(r.json.error, "invalid_client");
    assert.ok(/^Basic /.test(r.headers.get("www-authenticate") || ""));
  });
  r = await push(R9700, "par-a");
  check("E8. and the right one is accepted", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
  });
  r = await K.send(K.rb(R9700) + "/oauth2/par", {
    form: assertionForm("https://somebody-else.example/token") });
  check("E9. RFC 9700 mode: a client assertion for another audience is " +
        "refused", function () {
    assert.ok(refused(r, 401, "invalid_client"), K.shown(r));
  });
  r = await push(R21, "par-a", { client_secret: SECRET });
  check("E10. OAuth 2.1 mode: Basic and a body secret together are refused",
        function () {
    assert.ok(refused(r, 400, "invalid_request", /2\.4/), K.shown(r));
  });
  r = await push(R21, "par-a", { redirect_uri: undefined });
  row = r.status === 201 ? await listed(R21, r.json.request_uri) : null;
  check("E11. OAuth 2.1 mode: a push with no redirect_uri takes the one " +
        "registered (section 4.1.1)", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(row && row.redirect_uri, REDIRECT);
  });
  r = await push(PROD, "par-public", {}, { basic: false });
  check("E12. product mode: a PUBLIC client may push without a credential",
        function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.ok(r.json.request_uri);
  });
  r = await push(PROD, "par-a", {}, { basic: false });
  check("E13. product mode: a CONFIDENTIAL client that presents no " +
        "credential is still refused 401", function () {
    assert.ok(refused(r, 401, "invalid_client"), K.shown(r));
  });
  log.debug("Leaving clientAuthentication().");
}

// ------------------------------------------------------------------- F, G
async function atTheAuthorizationEndpoint() {
  log.debug("Entering atTheAuthorizationEndpoint().");
  log.info("=== F. the request_uri at the authorization endpoint ===");
  let c = await K.coded(D, "STS-OAUTH-0410", function () {
    return authorize(D, { client_id: "par-a",
      request_uri: "urn:ietf:params:oauth:request_uri:unknown" });
  });
  check("F1. an unknown request_uri is refused 400, not redirected " +
        "(STS-OAUTH-0410)", function () {
    assert.ok(refused(c.answer, 400, "invalid_request_uri", /not one this/),
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  let r = await push(D, "par-a");
  const uri = r.json.request_uri;
  c = await K.coded(D, "STS-OAUTH-0413", function () {
    return authorize(D, { client_id: "par-b", request_uri: uri });
  });
  check("F2. another client's request_uri is refused (STS-OAUTH-0413)",
        function () {
    assert.ok(refused(c.answer, 400, "invalid_request_uri",
                      /different client/), K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  r = await authorize(D, { request_uri: uri });
  check("F3. a request_uri with no client_id is refused", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
  });
  c = await K.coded(D, "STS-OAUTH-0414", function () {
    return authorize(D, { client_id: "par-a", request_uri: uri }, "/parAS");
  });
  check("F4. a request_uri pushed at the default authorization server is " +
        "refused at a named one (STS-OAUTH-0414)", function () {
    assert.ok(refused(c.answer, 400, "invalid_request_uri",
                      /authorization server/), K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  r = await push(D, "par-a", {}, { prefix: "/parAS" });
  const namedUri = r.json && r.json.request_uri;
  const there = await authorize(D, { client_id: "par-a",
                                     request_uri: namedUri }, "/parAS");
  const here = await authorize(D, { client_id: "par-a",
                                    request_uri: namedUri });
  check("F5. one pushed at the named server works there, and not at the " +
        "default one", function () {
    assert.ok(K.toSignIn(there), K.shown(there));
    assert.ok(refused(here, 400, "invalid_request_uri"), K.shown(here));
  });
  await K.set(D, "oauth2.parRequestUriLifetimeS", 5);
  let shortUri;
  try {
    r = await push(D, "par-a");
    shortUri = r.json && r.json.request_uri;
  } finally {
    await K.unset(D, "oauth2.parRequestUriLifetimeS");
  }
  check("F6. expires_in follows oauth2.parRequestUriLifetimeS", function () {
    assert.strictEqual(r.json && r.json.expires_in, 5, K.shown(r));
  });
  await K.sleep(5600);
  c = await K.coded(D, "STS-OAUTH-0411", function () {
    return authorize(D, { client_id: "par-a", request_uri: shortUri });
  });
  check("F7. an expired request_uri is refused (STS-OAUTH-0411)",
        function () {
    assert.ok(refused(c.answer, 400, "invalid_request_uri", /expired/),
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });

  log.info("=== G. section 2.4 ===");
  r = await push(R9700, "par-a", { redirect_uri: UNREGISTERED });
  check("G1. RFC 9700 mode, setting off: an unregistered redirect_uri is " +
        "refused at the push", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(/redirect/i.test(r.json.error_description || ""));
  });
  await K.set(R9700, "oauth2.parAllowUnregisteredRedirectUris", true);
  r = await push(R9700, "par-a", { redirect_uri: UNREGISTERED });
  const relaxed = r.status === 201 ? r.json.request_uri : "";
  const row = relaxed ? await listed(R9700, relaxed) : null;
  check("G2. setting on: an AUTHENTICATED client may push one, and the " +
        "row says so", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(row && row.redirect_uri_unregistered, true);
  });
  const run = await flow(R9700, "par-a", relaxed);
  check("G3. and the authorization response goes to it", function () {
    const p = K.answerAt(run.final, UNREGISTERED);
    assert.ok(p && p.get("code"), K.shown(run.final));
  });
  r = await push(R9700, "par-a", { redirect_uri: UNREGISTERED },
                 { secret: "wrong" });
  check("G4. a client whose credential fails gets no such thing",
        function () {
    assert.strictEqual(r.status, 401, K.shown(r));
  });
  r = await push(R9700, "par-public", { redirect_uri: UNREGISTERED },
                 { basic: false });
  check("G5. a PUBLIC client may not push an unregistered redirect_uri " +
        "even with the setting on (section 7.2)", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
  });
  r = await push(R9700, "par-a", { redirect_uri: UNREGISTERED });
  const later = r.json && r.json.request_uri;
  await K.unset(R9700, "oauth2.parAllowUnregisteredRedirectUris");
  r = await authorize(R9700, { client_id: "par-a", request_uri: later });
  check("G6. turned off after the push, the authorization endpoint " +
        "refuses the same request_uri (section 7.4)", function () {
    assert.strictEqual(r.status, 400, K.shown(r));
    assert.ok(!K.toSignIn(r));
  });
  log.debug("Leaving atTheAuthorizationEndpoint().");
}

// ---------------------------------------------------------------------- H
async function requirePolicy() {
  log.debug("Entering requirePolicy().");
  log.info("=== H. the require policy ===");
  const rb = K.rb(D);
  await K.set(D, "oauth2.requirePushedAuthorizationRequests", true);
  let meta;
  let plain;
  let pushed;
  try {
    meta = (await K.send(rb + "/.well-known/oauth-authorization-server"))
      .json;
    plain = await K.coded(D, "STS-OAUTH-0419", function () {
      return authorize(D, Object.assign({ client_id: "par-a" }, pushForm()));
    });
    const p = await push(D, "par-a");
    pushed = await authorize(D, { client_id: "par-a",
                                  request_uri: p.json.request_uri });
  } finally {
    await K.unset(D, "oauth2.requirePushedAuthorizationRequests");
  }
  check("H1. required in the realm: the metadata says so", function () {
    assert.strictEqual(meta.require_pushed_authorization_requests, true);
  });
  check("H2. a plain authorization request is refused 400 on this server " +
        "(STS-OAUTH-0419)", function () {
    assert.ok(refused(plain.answer, 400, "invalid_request", /not pushed/),
              K.shown(plain.answer));
    assert.ok(plain.rose >= 1);
  });
  check("H3. and a pushed one goes through", function () {
    assert.ok(K.toSignIn(pushed), K.shown(pushed));
  });
  let w = await K.appSet(D, "par-b",
                         "oauthRequirePushedAuthorizationRequests", "TRUE");
  assert.strictEqual(w.status, 200, K.shown(w));
  let r = await authorize(D, Object.assign({ client_id: "par-b" },
                                           pushForm()));
  const notB = await authorize(D, Object.assign({ client_id: "par-a" },
                                                pushForm()));
  const pb = await push(D, "par-b");
  const viaB = await authorize(D, { client_id: "par-b",
                                    request_uri: pb.json.request_uri });
  check("H4. a client carrying require_pushed_authorization_requests is " +
        "refused a plain request, by name", function () {
    assert.ok(refused(r, 400, "invalid_request", /par-b/), K.shown(r));
  });
  check("H5. and another client is not; the requiring client's pushed " +
        "request works", function () {
    assert.ok(K.toSignIn(notB), K.shown(notB));
    assert.ok(K.toSignIn(viaB), K.shown(viaB));
  });
  w = await K.appSet(D, "par-b", "oauthRequirePushedAuthorizationRequests",
                     "maybe");
  check("H6. a write of \"maybe\" is refused at the registry", function () {
    assert.ok(w.status >= 400 || (w.json && w.json.ok === false),
              K.shown(w));
  });
  await K.appSet(D, "par-b", "oauthRequirePushedAuthorizationRequests",
                 "FALSE");
  r = await K.send(rb + "/oauth2/register", { json: {
    redirect_uris: [REDIRECT], client_name: "par reg " + K.STAMP,
    require_pushed_authorization_requests: true } });
  const registered = r.json || {};
  check("H7. RFC 7591 registration records require_pushed_authorization_" +
        "requests, and echoes it", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(registered.require_pushed_authorization_requests,
                       true);
  });
  r = await authorize(D, { client_id: registered.client_id,
    response_type: "code", redirect_uri: REDIRECT,
    code_challenge: PKCE.challenge, code_challenge_method: "S256" });
  check("H8. and the registered client is then held to it", function () {
    assert.ok(refused(r, 400, "invalid_request", /not pushed/), K.shown(r));
  });
  const reg = await K.coded(D, "STS-REG-0120", function () {
    return K.send(rb + "/oauth2/register", { json: {
      redirect_uris: [REDIRECT],
      require_pushed_authorization_requests: "yes" } });
  });
  check("H9. a registration giving it as a string is refused " +
        "invalid_client_metadata (STS-REG-0120)", function () {
    assert.ok(refused(reg.answer, 400, "invalid_client_metadata"),
              K.shown(reg.answer));
    assert.ok(reg.rose >= 1);
  });
  const api = rb + "/admin-api/authorization-servers";
  await K.ok(api + "/create", { id: "parReq" },
             "created the named authorization server parReq");
  await K.ok(api + "/set", { profile: "parReq",
    member: "require_pushed_authorization_requests", value: "true" },
    "required PAR at parReq");
  r = await authorize(D, Object.assign({ client_id: "par-a" }, pushForm()),
                      "/parReq");
  const atDefault = await authorize(D, Object.assign({ client_id: "par-a" },
                                                     pushForm()));
  check("H10. a named authorization server publishing the requirement " +
        "refuses a plain request, and the default server does not",
        function () {
    assert.ok(refused(r, 400, "invalid_request", /parReq/), K.shown(r));
    assert.ok(K.toSignIn(atDefault), K.shown(atDefault));
  });
  await K.ok(api + "/remove", { profile: "parReq",
    member: "require_pushed_authorization_requests" },
    "removed the member at parReq");
  r = await authorize(D, Object.assign({ client_id: "par-a" }, pushForm()),
                      "/parReq");
  check("H11. a removed member means the check does not run", function () {
    assert.ok(K.toSignIn(r), K.shown(r));
  });
  log.debug("Leaving requirePolicy().");
}

// ---------------------------------------------------------------------- I
function object(claims, header) {
  log.debug("Entering object().");
  const body = Object.assign({ iss: "par-a", aud: ISS, client_id: "par-a",
    exp: Math.floor(Date.now() / 1000) + 300 }, pushForm(), claims || {});
  Object.keys(body).forEach(function (k) {
    if (body[k] === undefined) {
      delete body[k];
    }
  });
  log.debug("Leaving object().");
  return K.jws("ES256", Object.assign({ typ: "oauth-authz-req+jwt",
    kid: "par-ec" }, header || {}), body, EC);
}

async function requestObjects() {
  log.debug("Entering requestObjects().");
  log.info("=== I. section 3: a pushed request object ===");
  const rb = K.rb(D);
  const auth = { Authorization: K.basic("par-a", SECRET) };
  let r = await K.send(rb + "/oauth2/par", { headers: auth,
    form: { request: object({ state: "from-object" }) } });
  const row = r.status === 201 ? await listed(D, r.json.request_uri) : null;
  check("I1. a signed request object pushed alone is verified and kept as " +
        "its parameters", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(row && row.source, "request");
    assert.strictEqual(row.request_object_alg, "ES256");
    assert.strictEqual(row.parameters.state, "from-object");
  });
  const run = await flow(D, "par-a", r.json.request_uri);
  check("I2. and the flow runs on the object's parameters", function () {
    const p = K.answerAt(run.final, REDIRECT);
    assert.ok(p && p.get("state") === "from-object", K.shown(run.final));
  });
  const c = await K.coded(D, "STS-OAUTH-0409", function () {
    return K.send(rb + "/oauth2/par", { headers: auth,
      form: { request: object(), scope: "openid email" } });
  });
  check("I3. authorization parameters beside the object are refused " +
        "(STS-OAUTH-0409)", function () {
    assert.ok(refused(c.answer, 400, "invalid_request", /section 3/),
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  r = await K.send(rb + "/oauth2/par", { headers: auth,
    form: { request: object({ client_id: "par-b" }) } });
  check("I4. an object naming another client_id is refused", function () {
    assert.ok(refused(r, 400, "invalid_request_object"), K.shown(r));
  });
  r = await K.send(rb + "/oauth2/par", { headers: auth,
    form: { request: object({ client_id: undefined }) } });
  check("I5. an authenticated client's object with no client_id claim is " +
        "refused", function () {
    assert.ok(refused(r, 400, "invalid_request_object", /no client_id claim/),
              K.shown(r));
  });
  r = await K.send(rb + "/oauth2/par", { headers: auth, form: {
    request: object({}, { kid: "nobody" }).slice(0, -8) + "AAAAAAAA" } });
  check("I6. an object whose signature does not verify is refused",
        function () {
    assert.ok(refused(r, 400, "invalid_request_object"), K.shown(r));
  });
  await K.appSet(D, "par-ro", "oauthRequireSignedRequestObject", "TRUE");
  const plain = await K.coded(D, "STS-OAUTH-0415", function () {
    return push(D, "par-ro");
  });
  check("I7. a plain push from a client requiring signed objects is " +
        "refused (section 2.3, STS-OAUTH-0415)", function () {
    assert.ok(refused(plain.answer, 400, "invalid_request",
                      /signed request object is/), K.shown(plain.answer));
    assert.ok(plain.rose >= 1);
  });
  await K.appSet(D, "par-ro", "oauthRequireSignedRequestObject", "FALSE");
  r = await push(D, "par-ro");
  const plainUri = r.json && r.json.request_uri;
  await K.appSet(D, "par-ro", "oauthRequireSignedRequestObject", "TRUE");
  r = await authorize(D, { client_id: "par-ro", request_uri: plainUri });
  check("I8. pushed plain before the requirement, refused at the " +
        "authorization endpoint after it (section 7.4)", function () {
    assert.ok(refused(r, 400, "invalid_request", /pushed as plain/),
              K.shown(r));
  });
  await K.appSet(D, "par-ro", "oauthRequireSignedRequestObject", "FALSE");
  log.debug("Leaving requestObjects().");
}

// ------------------------------------------------------------------- J, K
async function dpopAndMarkers() {
  log.debug("Entering dpopAndMarkers().");
  log.info("=== J. RFC 9449 section 10.1 ===");
  const key = K.keyPair("ES256", "par-dpop");
  const parUrl = ISS + "/oauth2/par";
  let r = await push(D, "par-a", {},
                     { headers: { DPoP: K.dpop(key, "POST", parUrl) } });
  let row = r.status === 201 ? await listed(D, r.json.request_uri) : null;
  check("J1. a DPoP proof at the push binds the request to its key",
        function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(row && row.dpop_jkt, K.thumbprint(key.jwk));
    assert.strictEqual(row.parameters.dpop_jkt, K.thumbprint(key.jwk));
  });
  let run = await flow(D, "par-a", r.json.request_uri);
  let p = K.answerAt(run.final, REDIRECT);
  r = await redeem(D, "par-a", p && p.get("code"));
  check("J2. the code it bought is refused without a proof from that key",
        function () {
    assert.ok(p && p.get("code"), K.shown(run.final));
    assert.strictEqual(r.status, 400, K.shown(r));
  });
  // A CODE IS PRESENTED ONCE, WHATEVER THE OUTCOME (#424): a second code
  // bought the same way is the one redeemed with the proof.
  r = await push(D, "par-a", {},
                 { headers: { DPoP: K.dpop(key, "POST", parUrl) } });
  run = await flow(D, "par-a", r.json.request_uri);
  p = K.answerAt(run.final, REDIRECT);
  r = await redeem(D, "par-a", p && p.get("code"),
                   { DPoP: K.dpop(key, "POST", ISS + "/oauth2/token") });
  check("J3. and a code bought the same way is redeemed with one",
        function () {
    assert.strictEqual(r.status, 200, K.shown(r));
    assert.ok(/dpop/i.test(r.json.token_type || ""));
  });
  let c = await K.coded(D, "STS-OAUTH-0417", function () {
    return push(D, "par-a",
                { dpop_jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
                { headers: { DPoP: K.dpop(key, "POST", parUrl) } });
  });
  check("J4. a dpop_jkt naming another key than the proof is refused " +
        "(STS-OAUTH-0417)", function () {
    assert.ok(refused(c.answer, 400, "invalid_dpop_proof", /same key/),
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });
  // The push records the proof checker's own code where it has one — the
  // htu mismatch's STS-OAUTH-0106 — and STS-OAUTH-0416 only where it has
  // none.
  c = await K.coded(D, "STS-OAUTH-0106", function () {
    return push(D, "par-a", {}, { headers: {
      DPoP: K.dpop(key, "POST", ISS + "/oauth2/token") } });
  });
  check("J5. a proof made for another URL is refused, recorded with the " +
        "checker's htu code STS-OAUTH-0106",
        function () {
    assert.ok(refused(c.answer, 400, "invalid_dpop_proof"),
              K.shown(c.answer));
    assert.ok(c.rose >= 1);
  });

  log.info("=== K. this service's own markers are not the client's ===");
  r = await push(D, "par-a", { authn_error: "access_denied",
                               consent_error: "access_denied" });
  row = r.status === 201 ? await listed(D, r.json.request_uri) : null;
  check("K1. a push cannot pre-load the sign-in or consent screens' own " +
        "round-trip fields", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
    assert.strictEqual(row.parameters.authn_error, undefined);
    assert.strictEqual(row.parameters.consent_error, undefined);
  });
  run = await flow(D, "par-a", r.json.request_uri);
  check("K2. and the flow is not turned into a refusal by them",
        function () {
    const q = K.answerAt(run.final, REDIRECT);
    assert.ok(q && q.get("code"), K.shown(run.final));
  });
  log.debug("Leaving dpopAndMarkers().");
}

// ------------------------------------------------------------------- L, M
async function offAndFull() {
  log.debug("Entering offAndFull().");
  log.info("=== L. switched off ===");
  let r = await push(D, "par-a");
  const beforeOff = r.json.request_uri;
  await K.set(D, "oauth2.pushedAuthorizationRequests", false);
  let off;
  let meta;
  let still;
  try {
    off = await K.coded(D, "STS-OAUTH-0400", function () {
      return push(D, "par-a");
    });
    meta = (await K.send(K.rb(D) +
      "/.well-known/oauth-authorization-server")).json;
    still = await authorize(D, { client_id: "par-a",
                                 request_uri: beforeOff });
  } finally {
    await K.unset(D, "oauth2.pushedAuthorizationRequests");
  }
  check("L1. switched off, a push is 404 invalid_request (STS-OAUTH-0400)",
        function () {
    assert.ok(refused(off.answer, 404, "invalid_request"),
              K.shown(off.answer));
    assert.ok(off.rose >= 1);
  });
  check("L2. and the metadata member is gone", function () {
    assert.ok(!("pushed_authorization_request_endpoint" in meta));
  });
  check("L3. a request_uri issued before still works (section 5)",
        function () {
    assert.ok(K.toSignIn(still), K.shown(still));
  });

  log.info("=== M. a full store ===");
  const fills = [];
  for (let i = 0; i < 10; i++) {
    fills.push(await push(FULL, "par-a"));
  }
  const full = await K.coded(FULL, "STS-OAUTH-0408", function () {
    return push(FULL, "par-a");
  });
  r = await push(D, "par-a");
  check("M1. the eleventh push to a realm holding ten is 503 " +
        "temporarily_unavailable (STS-OAUTH-0408)", function () {
    assert.ok(fills.every(function (one) {
      return one.status === 201;
    }), fills.map(function (one) {
      return one.status;
    }).join(","));
    assert.ok(refused(full.answer, 503, "temporarily_unavailable"),
              K.shown(full.answer));
    assert.ok(full.rose >= 1);
  });
  check("M2. and another realm is unaffected", function () {
    assert.strictEqual(r.status, 201, K.shown(r));
  });
  log.debug("Leaving offAndFull().");
}

// ---------------------------------------------------------------------- N
async function administrator() {
  log.debug("Entering administrator().");
  log.info("=== N. the administrator's view ===");
  for (let i = 0; i < 3; i++) {
    await push(D, "list-a");
  }
  const kept = await push(D, "list-b");
  await push(D, "list-b");
  let m = await monitor(D, { client_id: "list-a", per: "2" });
  check("N1. the rows page, and filter by client", function () {
    const pr = m.pushedRequests;
    assert.strictEqual(pr.total, 3, JSON.stringify(pr.paging));
    assert.strictEqual(pr.items.length, 2);
    assert.ok(pr.items.every(function (one) {
      return one.client_id === "list-a";
    }));
  });
  m = await monitor(D, { client_id: "list-a", per: "2", page: "2" });
  check("N2. and the last page holds the rest", function () {
    assert.strictEqual(m.pushedRequests.items.length, 1);
  });
  m = await monitor(D, { state: "spent", per: "200" });
  check("N3. the state filter answers spent rows only", function () {
    assert.ok(m.pushedRequests.items.length >= 1);
    assert.ok(m.pushedRequests.items.every(function (one) {
      return one.state === "spent";
    }));
  });
  check("N4. no row carries the request_uri itself — only its digest",
        function () {
    assert.ok(JSON.stringify(m).indexOf("urn:ietf:params:oauth:" +
                                        "request_uri:") < 0);
  });
  const row = await listed(D, kept.json.request_uri);
  const del = await K.send(K.rb(D) +
    "/admin-api/oauth2/monitor/delete-pushed-request",
    { json: { request_uri_digest: row.request_uri_digest } });
  const again = await K.send(K.rb(D) +
    "/admin-api/oauth2/monitor/delete-pushed-request",
    { json: { request_uri_digest: row.request_uri_digest } });
  const gone = await authorize(D, { client_id: "list-b",
                                    request_uri: kept.json.request_uri });
  check("N5. an administrator deletes a pushed request once; the " +
        "request_uri is then unknown", function () {
    assert.strictEqual(del.status, 200, K.shown(del));
    assert.ok(again.status >= 400 || (again.json && again.json.ok === false),
              K.shown(again));
    assert.ok(refused(gone, 400, "invalid_request_uri"), K.shown(gone));
  });
  m = await monitor(D, { per: "200" });
  const a = (m.clients || []).find(function (one) {
    return one.client_id === "par-a";
  }) || { counters: {} };
  const b = (m.clients || []).find(function (one) {
    return one.client_id === "par-b";
  }) || { counters: {} };
  const lb = (m.clients || []).find(function (one) {
    return one.client_id === "list-b";
  }) || { counters: {} };
  check("N6. the counters count pushes, reads, spends, refusals, DPoP " +
        "bindings and pushed objects per client", function () {
    const n = a.counters;
    assert.ok(n.pushed >= 10 && n.resolved >= 5 && n.spent >= 4 &&
              n.pushRefused >= 10 && n.resolveRefused >= 3 &&
              n.dpopBound >= 1 && n.pushedObjects >= 1, JSON.stringify(n));
  });
  check("N7. and a plain request refused because PAR was required, and " +
        "the administrator's delete", function () {
    assert.ok(b.counters.requiredRefused >= 1, JSON.stringify(b.counters));
    assert.ok(lb.counters.deleted >= 1, JSON.stringify(lb.counters));
  });
  log.debug("Leaving administrator().");
}

async function test() {
  log.debug("Entering test().");
  PKCE = K.pkce();
  D = await K.realm("par", "development");
  R9700 = await K.realm("par9700", "development",
                        { "oauth2.rfc9700": true });
  R21 = await K.realm("par21", "development", { "oauth2.oauth21": true });
  PROD = await K.realm("parprod", "product");
  FULL = await K.realm("parfull", "development",
                       { "oauth2.parMaxRequests": 10 });
  ISS = (await K.send(K.rb(D) + "/.well-known/oauth-authorization-server"))
    .json.issuer;
  await K.person(D, PERSON, PASSWORD);
  await K.person(R9700, PERSON, PASSWORD);
  for (const id of ["par-a", "par-b", "par-limit", "par-ro", "list-a",
                    "list-b"]) {
    await client(D, id);
  }
  await client(D, "par-jwt", { oauthTokenEndpointAuthMethod:
                               "private_key_jwt" });
  for (let i = 1; i <= 2; i++) {
    await K.ok(K.rb(D) + "/admin-api/applications/create", {
      identifier: "par-api" + i, name: "par-api" + i,
      kind: "oauth2-resource-server", protocols: ["oauth2"],
      fields: { oauthAudience: ["https://api" + i + ".par.example/"] } },
      "registered the resource par-api" + i);
  }
  await publicClient(D, "par-public");
  await client(R9700, "par-a");
  await client(R9700, "par-jwt", { oauthTokenEndpointAuthMethod:
                                   "private_key_jwt" });
  await publicClient(R9700, "par-public");
  await client(R21, "par-a");
  await client(PROD, "par-a");
  await publicClient(PROD, "par-public");
  await client(FULL, "par-a");
  await discoveryAndFlow();
  await section23();
  await clientAuthentication();
  await atTheAuthorizationEndpoint();
  await requirePolicy();
  await requestObjects();
  await dpopAndMarkers();
  await offAndFull();
  await administrator();
  log.debug("Leaving test().");
}

K.main(test, FLOOR);
