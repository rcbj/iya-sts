// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_federation_fapi_client.js
//
// ===========================================================================
// THIS SERVICE AS A FAPI CLIENT, OVER THE WIRE (#931; #444 D12, phase 7).
//
// `tests/federation_fapi_client.js` calls `federation/fapi_client.ts`'s
// decisions as functions, and section 10 of `tests/federation_oidc_rp.js`
// pins the dialling against a partner in its child process. Both are
// carried here against `oidc_partner_kit.js`'s partner on the runner, in a
// development realm with `federation.outboundAllowHttp` and
// `federation.outboundSkipTlsVerification` on. A function's verdict is
// read where the partner sees it — the authorization request, the push,
// the DPoP proof, the client assertion, the request object, the
// registration — and each refusal's code off the realm's audit log:
//
//   P. what each profile forces (fapi_client's shapedRecord, usesPar,
//      usesDpop, usesJarm, sendsRequestByValue, needsDiscovery): 2-security
//      pushes and sends the browser only client_id and request_uri, a
//      PS256 private_key_jwt (aud the issuer, sixty seconds) and a DPoP
//      proof (ES256, a public P-256 jwk, htm, htu without its query, no
//      nonce); its code redeemed with DPoP and UserInfo asked as DPoP with
//      ath; discovery off (STS-FED-0243) or a document with no PAR endpoint
//      (0243); an answer with no iss (0249) or another (0238); a token
//      response answered Bearer (0251), `dpop` accepted;
//   A. 1-advanced: `code id_token` by form_post with a PS256 request
//      object on the URL (typ oauth-authz-req+jwt, nbf = iat, sixty
//      seconds), no push; redeemed with private_key_jwt and no DPoP; no
//      s_hash or another state's (0248);
//   M. 2-message-signing: the object in the push; a JARM response opened
//      and redeemed with DPoP; another key or no state (0246), the
//      partner's error (0025), no exp (0250), then a good one;
//   N. a push refused (0244, no redirect); use_dpop_nonce retried once
//      with the partner's nonce, and not a third time; every request
//      signed afresh (no jti seen twice) and UserInfo's own challenge
//      answered with its own nonce;
//   R. what each profile registers;
//   F. refresh: a 2.x refresh proves DPoP with the sign-in's key, a
//      1-advanced one sends the assertion alone, a 2.x refresh answered
//      Bearer ends the session (0251);
//   T. 1-advanced over mutual TLS: the relationship's clientAuth
//      certificate at the token endpoint and UserInfo, the bound token
//      answered; the published leaf; tls_client_auth; not ready without
//      1-advanced; the renewal job keeping the subject; the registration's
//      tls_client_auth subject DN and mtls_endpoint_aliases; fedUserinfo
//      off; 1-advanced's fragment answer.
//
// NOT HERE: 10ai (a certificate whose key will not open — no door writes
// a broken sealed key), 10n/10o (`beginConnect`, the portal's connect
// door, is `sts_federation_consumer_providers.js`'s), and the in-process
// file's `profileOf()` for a non-OIDC record or an OpenID Federation OP
// (no relationship of either kind reaches the FAPI path).
//
// OWNED HERE (local: true). Its realms are removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const nodeCrypto = require("crypto");
const K = require("./oauth_wire_kit.js").kit("sts_federation_fapi_client");
const P = require("./oidc_partner_kit.js");

const log = K.log;
let SP = null;
let OP = null;
let op = null;

function api(path, body) {
  log.debug("Entering api(). " + path);
  log.debug("Leaving api().");
  return K.send(K.rb(SP) + "/admin-api" + path,
                body === undefined ? {} : { json: body });
}

async function setField(id, field, value) {
  log.debug("Entering setField(). " + id + " " + field);
  const r = await api("/federation/set", { id: id, field: field,
                                           value: String(value) });
  assert.strictEqual(r.status, 200, "setting " + field + " on " + id + ": " +
                     r.text.slice(0, 300));
  log.debug("Leaving setField().");
}

const DISCOVERING = { fedDiscovery: "TRUE", fedSsoUrl: null,
                      fedTokenUrl: null, fedJwksUri: null,
                      fedUserinfoUrl: null };

async function make(id, fields) {
  log.debug("Entering make(). " + id);
  const base = OP.base;
  const made = await api("/federation/create", { id: id,
    role: "service-provider", protocol: "oidc", peer: base });
  assert.strictEqual(made.status, 200, made.text.slice(0, 300));
  const all = Object.assign({ fedClientId: "frp-client",
    fedClientSecret: "frp-secret-" + K.STAMP, fedAutocreateUsers: "TRUE",
    fedSsoUrl: base + "authorize", fedTokenUrl: base + "token",
    fedJwksUri: base + "jwks", fedUserinfoUrl: base + "userinfo",
    fedScope: "openid profile email" }, fields || {});
  for (const field of Object.keys(all)) {
    if (all[field] !== null) {
      await setField(id, field, all[field]);
    }
  }
  const on = await api("/federation/enable", { id: id });
  assert.strictEqual(on.status, 200, on.text.slice(0, 300));
  log.debug("Leaving make().");
  return id;
}

async function viewOf(id) {
  log.debug("Entering viewOf(). " + id);
  const r = await api("/federation?relationship=" + encodeURIComponent(id));
  log.debug("Leaving viewOf().");
  return r.json || {};
}

async function begin(id, b) {
  log.debug("Entering begin(). " + id);
  const r = await b.go(K.rb(SP) + "/federation/login/" + id);
  const at = new URL(r.location || "http://x/");
  log.debug("Leaving begin(). " + r.status);
  return { status: r.status, location: r.location, params: at.searchParams,
           text: r.text };
}

function claims(started, extra) {
  log.debug("Entering claims().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving claims().");
  return Object.assign({ iss: OP.base, sub: "frp-person",
    aud: "frp-client", iat: now, exp: now + 300,
    nonce: started.params.get("nonce") }, extra || {});
}

// The ID Token claims of a pushed request: its nonce is in the push.
function parClaims() {
  log.debug("Entering parClaims().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving parClaims().");
  return { iss: OP.base, sub: "frp-person", aud: "frp-client", iat: now,
           exp: now + 300, nonce: op.par ? op.par.get("nonce") : "" };
}

function fresh() {
  log.debug("Entering fresh().");
  const now = Math.floor(Date.now() / 1000);
  log.debug("Leaving fresh().");
  return { iss: OP.base, sub: "frp-person", aud: "frp-client", iat: now,
           exp: now + 300 };
}

function callsTo(re) {
  log.debug("Entering callsTo().");
  log.debug("Leaving callsTo().");
  return op.calls.filter(function (c) {
    return re.test(c.path);
  });
}

function dialled(re) {
  log.debug("Entering dialled().");
  log.debug("Leaving dialled().");
  return callsTo(re).length > 0;
}

function pushScenario(extra) {
  log.debug("Entering pushScenario().");
  log.debug("Leaving pushScenario().");
  return Object.assign({ issuer: OP.base, base: OP.base, discovery: {
    pushed_authorization_request_endpoint: OP.base + "par" },
    backClaims: parClaims }, extra || {});
}

function acs(id) {
  log.debug("Entering acs(). " + id);
  log.debug("Leaving acs().");
  return K.rb(SP) + "/federation/acs/" + id;
}

function nonceOf(c) {
  log.debug("Entering nonceOf().");
  const parsed = P.jwtParts(c && c.dpop);
  log.debug("Leaving nonceOf().");
  return parsed ? String(parsed.claims.nonce || "") : "no proof";
}

function distinct(list) {
  log.debug("Entering distinct().");
  log.debug("Leaving distinct().");
  return list.every(function (one, i) {
    return one && list.indexOf(one) === i;
  });
}

async function runJob(job) {
  log.debug("Entering runJob(). " + job);
  const r = await K.send(K.rb(SP) + "/admin-api/scheduler/run",
                         { json: { job: job, realm: SP } });
  assert.ok((r.status === 200 || r.status === 202) && r.json && r.json.ok,
            job + " did not run: " + K.shown(r));
  let detail = null;
  for (let i = 0; i < 100; i += 1) {
    const d = await K.send(K.rb(SP) + "/admin-api/scheduler?run=" +
                           encodeURIComponent(r.json.runId));
    detail = (d.json && d.json.detail) || null;
    if (detail && (detail.state === "succeeded" ||
                   detail.state === "failed")) {
      break;
    }
    await K.sleep(200);
  }
  assert.ok(detail && detail.state === "succeeded", job +
            " did not succeed: " + JSON.stringify(detail).slice(0, 400));
  log.debug("Leaving runJob().");
  return detail;
}

// ------------------------------------------------------------------- P
async function security() {
  log.debug("Entering security().");
  log.info("=== P. 2-security ===");
  const SEC = await make("ffc-sec", Object.assign({ fedFapi: "2-security" },
                                                  DISCOVERING));
  const ready = await viewOf(SEC);
  K.check("P1. a 2-security relationship is ready with no endpoint written",
          function () {
            assert.ok(ready.ready, JSON.stringify(ready.missing));
          });
  op.calls = [];
  op.par = null;
  op.scenario = pushScenario();
  const b = K.browser();
  const started = await begin(SEC, b);
  const par = op.par || new URLSearchParams();
  const assertion = P.jwtParts(par.get("client_assertion"));
  const proof = P.jwtParts((callsTo(/\/par$/)[0] || {}).dpop);
  const now = Math.floor(Date.now() / 1000);
  K.check("P2. 2-security pushes the request and sends the browser only " +
          "client_id and request_uri; the push asks code, S256, no request " +
          "object, response_mode none", function () {
    assert.strictEqual(started.status, 302, started.text.slice(0, 300));
    assert.strictEqual(Array.from(started.params.keys()).sort().join(","),
                       "client_id,request_uri", started.location);
    assert.strictEqual(started.params.get("client_id"), "frp-client");
    assert.strictEqual(started.params.get("request_uri"), OP.base +
                       "pushed");
    assert.strictEqual(par.get("response_type"), "code");
    assert.strictEqual(par.get("code_challenge_method"), "S256");
    assert.ok(!par.get("request"));
    assert.ok(!par.get("response_mode"), par.toString());
  });
  K.check("P3. its private_key_jwt is PS256, iss and sub the client, aud the " +
          "issuer, and lives sixty seconds", function () {
    assert.ok(assertion, par.toString().slice(0, 300));
    assert.strictEqual(assertion.header.alg, "PS256");
    assert.strictEqual(assertion.claims.iss, "frp-client");
    assert.strictEqual(assertion.claims.sub, "frp-client");
    assert.strictEqual(assertion.claims.aud, OP.base);
    assert.strictEqual(assertion.claims.exp - assertion.claims.iat, 60);
    assert.ok(Math.abs(assertion.claims.iat - now) < 10);
    assert.ok(assertion.claims.jti);
    assert.ok(!par.get("client_secret"));
  });
  K.check("P4. its DPoP proof is ES256 dpop+jwt, a public P-256 jwk, htm " +
          "POST, htu the push without a query, and no nonce or ath",
          function () {
            assert.ok(proof);
            assert.strictEqual(proof.header.typ, "dpop+jwt");
            assert.strictEqual(proof.header.alg, "ES256");
            const jwk = proof.header.jwk || {};
            assert.ok(jwk.kty === "EC" && jwk.crv === "P-256" && jwk.x &&
                      jwk.y && !jwk.d && !jwk.alg, JSON.stringify(jwk));
            assert.strictEqual(proof.claims.htm, "POST");
            assert.strictEqual(proof.claims.htu, OP.base + "par");
            assert.ok(!("nonce" in proof.claims) && !("ath" in proof.claims));
            assert.ok(proof.claims.jti);
          });
  op.calls = [];
  let r = await b.go(acs(SEC) + "?state=" +
    encodeURIComponent(par.get("state")) + "&code=c-fapi2&iss=" +
    encodeURIComponent(OP.base));
  const token = callsTo(/\/token$/)[0] || { body: "", dpop: "" };
  const form = new URLSearchParams(token.body);
  const user = callsTo(/\/userinfo$/)[0] || { auth: "", dpop: "" };
  const userProof = P.jwtParts(user.dpop) || { claims: {}, header: {} };
  const ath = nodeCrypto.createHash("sha256").update("at-back")
    .digest("base64url");
  K.check("P5. the code is redeemed with private_key_jwt and DPoP, and " +
          "UserInfo asked as DPoP with the token's ath, htm GET and the " +
          "same key", function () {
    assert.ok(r.status < 400, K.shown(r));
    assert.ok(form.get("client_assertion") && !form.get("client_secret"));
    assert.ok(token.dpop);
    assert.strictEqual(user.auth.indexOf("DPoP "), 0, user.auth);
    assert.strictEqual(userProof.claims.ath, ath);
    assert.strictEqual(userProof.claims.htm, "GET");
    assert.strictEqual((userProof.header.jwk || {}).x,
                       (proof.header.jwk || {}).x);
  });
  const NODISCO = await make("ffc-sec-off", { fedFapi: "2-security" });
  op.calls = [];
  let got = await K.coded(SP, "STS-FED-0243", function () {
    return begin(NODISCO, K.browser());
  });
  K.check("P6. 2-security with fedDiscovery off is refused (STS-FED-0243) " +
          "and nothing is dialled", function () {
    assert.strictEqual(got.answer.status, 502, got.answer.text.slice(0,
                                                                     200));
    assert.ok(got.rose >= 1);
    assert.ok(!dialled(/openid-configuration|\/par$/),
              JSON.stringify(op.calls.map(function (c) {
                return c.path;
              })));
  });
  const NOPAR = await make("ffc-sec-nopar",
    Object.assign({ fedFapi: "2-security" }, DISCOVERING));
  op.scenario = { issuer: OP.base, base: OP.base };
  got = await K.coded(SP, "STS-FED-0243", function () {
    return begin(NOPAR, K.browser());
  });
  K.check("P7. a discovery document with no PAR endpoint is refused " +
          "(STS-FED-0243)", function () {
    assert.strictEqual(got.answer.status, 502);
    assert.ok(got.rose >= 1);
  });
  const secAnswer = async function (extra, query, code) {
    log.debug("Entering secAnswer().");
    const bb = K.browser();
    op.calls = [];
    op.par = null;
    op.scenario = pushScenario(extra);
    await begin(SEC, bb);
    const state = (op.par || new URLSearchParams()).get("state");
    const act = function () {
      op.calls = [];
      return bb.go(acs(SEC) + "?state=" + encodeURIComponent(state) +
                   "&code=c-sec" + query);
    };
    const out = code ? await K.coded(SP, code, act)
                     : { answer: await act(), rose: 0 };
    log.debug("Leaving secAnswer().");
    return out;
  };
  got = await secAnswer({}, "", "STS-FED-0249");
  K.check("P8. a 2-security answer naming no issuer is refused " +
          "(STS-FED-0249) and the code is not redeemed", function () {
    assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
    assert.ok(got.rose >= 1);
    assert.ok(!dialled(/\/token$/));
  });
  got = await secAnswer({}, "&iss=" +
    encodeURIComponent(OP.base + "someone-else/"), "STS-FED-0238");
  K.check("P9. a 2-security answer naming another issuer is still refused " +
          "(STS-FED-0238)", function () {
    assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
    assert.ok(got.rose >= 1);
    assert.ok(!dialled(/\/token$/));
  });
  got = await secAnswer({ tokenType: "Bearer" }, "&iss=" +
    encodeURIComponent(OP.base), "STS-FED-0251");
  K.check("P10. a 2-security token response answered Bearer is refused " +
          "(STS-FED-0251) and UserInfo never asked with it", function () {
    assert.strictEqual(got.answer.status, 502, K.shown(got.answer));
    assert.ok(got.rose >= 1);
    assert.ok(dialled(/\/token$/) && !dialled(/\/userinfo$/));
  });
  got = await secAnswer({ tokenType: "dpop" }, "&iss=" +
    encodeURIComponent(OP.base));
  K.check("P11. token_type is compared without case: dpop signs in and " +
          "UserInfo is asked as DPoP", function () {
    assert.ok(got.answer.status < 400, K.shown(got.answer));
    assert.strictEqual((callsTo(/\/userinfo$/)[0] || { auth: "" }).auth
      .indexOf("DPoP "), 0);
  });
  log.debug("Leaving security().");
}

// ------------------------------------------------------------------- A
async function advanced() {
  log.debug("Entering advanced().");
  log.info("=== A. 1-advanced ===");
  const ADV = await make("ffc-adv", { fedFapi: "1-advanced",
    fedResponseType: "code", fedResponseMode: "query", fedScope: "profile" });
  op.calls = [];
  op.par = null;
  const b = K.browser();
  const started = await begin(ADV, b);
  const req = P.jwtParts(started.params.get("request"));
  K.check("A1. 1-advanced forces code id_token by form_post (a query mode " +
          "cleared), keeps openid in the scope, and does not push",
          function () {
            assert.strictEqual(started.status, 302, started.text.slice(0,
                                                                     200));
            assert.strictEqual(started.params.get("response_type"),
                               "code id_token");
            assert.strictEqual(started.params.get("response_mode"),
                               "form_post");
            assert.strictEqual(started.params.get("code_challenge_method"),
                               "S256");
            assert.ok(/(^| )openid( |$)/.test(
              String(started.params.get("scope"))),
                      started.params.get("scope"));
            assert.ok(!dialled(/\/par$/));
          });
  K.check("A2. its request object is on the browser URL: PS256, typ " +
          "oauth-authz-req+jwt, iss the client, aud the issuer, nbf = iat " +
          "and sixty seconds", function () {
    assert.ok(req, started.location.slice(0, 300));
    assert.strictEqual(req.header.alg, "PS256");
    assert.strictEqual(req.header.typ, "oauth-authz-req+jwt");
    assert.strictEqual(req.claims.response_type, "code id_token");
    assert.strictEqual(req.claims.client_id, "frp-client");
    assert.strictEqual(req.claims.iss, "frp-client");
    assert.strictEqual(req.claims.aud, OP.base);
    assert.strictEqual(req.claims.nbf, req.claims.iat);
    assert.strictEqual(req.claims.exp - req.claims.iat, 60);
  });
  op.calls = [];
  op.scenario = { backClaims: function () {
    return claims(started);
  } };
  const r = await b.go(acs(ADV), { form: {
    state: started.params.get("state"), code: "c-adv",
    id_token: OP.sign(claims(started, { c_hash: P.halfHash("c-adv"),
      s_hash: P.halfHash(started.params.get("state")) })) } });
  const token = callsTo(/\/token$/)[0] || { body: "", dpop: "none" };
  const user = callsTo(/\/userinfo$/)[0] || { auth: "" };
  K.check("A3. 1-advanced with the right s_hash redeems with " +
          "private_key_jwt and no DPoP, and UserInfo stays bearer",
          function () {
            assert.ok(r.status < 400, K.shown(r));
            assert.ok(new URLSearchParams(token.body)
              .get("client_assertion"));
            assert.ok(!token.dpop, token.dpop);
            assert.strictEqual(user.auth.indexOf("Bearer "), 0, user.auth);
          });
  const advHash = async function (extra) {
    log.debug("Entering advHash().");
    const bb = K.browser();
    const begun = await begin(ADV, bb);
    op.calls = [];
    op.scenario = { backClaims: function () {
      return claims(begun);
    } };
    const out = await K.coded(SP, "STS-FED-0248", function () {
      return bb.go(acs(ADV), { form: { state: begun.params.get("state"),
        code: "c-adv-h", id_token: OP.sign(claims(begun, Object.assign(
          { c_hash: P.halfHash("c-adv-h") }, extra))) } });
    });
    log.debug("Leaving advHash().");
    return out;
  };
  let got = await advHash({});
  K.check("A4. 1-advanced: a front ID Token with no s_hash is refused " +
          "(STS-FED-0248) and the code not redeemed", function () {
    assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
    assert.ok(got.rose >= 1);
    assert.ok(!dialled(/\/token$/));
  });
  got = await advHash({ s_hash: P.halfHash("another state") });
  K.check("A5. an s_hash of another state is refused (STS-FED-0248)",
          function () {
            assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
            assert.ok(got.rose >= 1);
          });
  log.debug("Leaving advanced().");
  return ADV;
}

// ------------------------------------------------------------------- M
async function messageSigning() {
  log.debug("Entering messageSigning().");
  log.info("=== M. 2-message-signing and JARM ===");
  const MS = await make("ffc-ms", Object.assign({
    fedFapi: "2-message-signing", fedResponseMode: "query" }, DISCOVERING));
  op.calls = [];
  op.par = null;
  op.scenario = pushScenario();
  const b = K.browser();
  const started = await begin(MS, b);
  const par = op.par || new URLSearchParams();
  const req = P.jwtParts(par.get("request"));
  K.check("M1. message signing puts the request object in the push (code, " +
          "response_mode jwt), not on the browser URL", function () {
    assert.strictEqual(started.status, 302, started.text.slice(0, 200));
    assert.ok(started.location.indexOf("request=") < 0);
    assert.ok(req, par.toString().slice(0, 200));
    assert.strictEqual(req.header.alg, "PS256");
    assert.strictEqual(req.header.typ, "oauth-authz-req+jwt");
    assert.strictEqual(req.claims.response_mode, "jwt");
    assert.strictEqual(req.claims.response_type, "code");
  });
  const exp = function () {
    log.debug("Entering exp().");
    log.debug("Leaving exp().");
    return Math.floor(Date.now() / 1000) + 300;
  };
  op.calls = [];
  let r = await b.go(acs(MS) + "?response=" + encodeURIComponent(OP.sign({
    iss: OP.base, aud: "frp-client", state: par.get("state"),
    code: "c-jarm", exp: exp() })));
  const token = callsTo(/\/token$/)[0] || { body: "", dpop: "" };
  K.check("M2. a JARM response is opened and the code inside redeemed with " +
          "DPoP, UserInfo as DPoP", function () {
    assert.ok(r.status < 400, K.shown(r));
    assert.ok(/code=c-jarm/.test(token.body), token.body.slice(0, 200));
    assert.ok(token.dpop);
    assert.strictEqual((callsTo(/\/userinfo$/)[0] || { auth: "" }).auth
      .indexOf("DPoP "), 0);
  });
  // The refusals, on a relationship with the partner's key pasted (a
  // response with no state has no context to take a discovered URI from).
  const JARM = await make("ffc-jarm", Object.assign({
    fedFapi: "2-message-signing" }, DISCOVERING));
  await setField(JARM, "fedJwks", JSON.stringify({ keys: [OP.jwk] }));
  const other = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const signOther = function (c) {
    log.debug("Entering signOther().");
    const input = P.b64u({ alg: "RS256", kid: "opk-1", typ: "JWT" }) + "." +
                  P.b64u(c);
    log.debug("Leaving signOther().");
    return input + "." + nodeCrypto.sign("sha256", Buffer.from(input),
                                         other.privateKey)
      .toString("base64url");
  };
  op.calls = [];
  op.par = null;
  op.scenario = pushScenario();
  const jb = K.browser();
  await begin(JARM, jb);
  const state = (op.par || new URLSearchParams()).get("state");
  const jarmGet = function (tokenText) {
    log.debug("Entering jarmGet().");
    op.calls = [];
    log.debug("Leaving jarmGet().");
    return jb.go(acs(JARM) + "?response=" + encodeURIComponent(tokenText));
  };
  let got = await K.coded(SP, "STS-FED-0246", function () {
    return jarmGet(signOther({ iss: OP.base, aud: "frp-client",
      state: state, code: "c-stolen", exp: exp() }));
  });
  K.check("M3. a JARM response signed by another key is refused " +
          "(STS-FED-0246) and the code not redeemed", function () {
    assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
    assert.ok(got.rose >= 1);
    assert.ok(!dialled(/\/token$/));
    assert.ok(got.answer.text.indexOf("did not verify") >= 0);
  });
  got = await K.coded(SP, "STS-FED-0246", function () {
    return jarmGet(OP.sign({ iss: OP.base, aud: "frp-client",
      code: "c-nostate", exp: exp() }));
  });
  K.check("M4. a JARM response with no state is refused (STS-FED-0246)",
          function () {
            assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
            assert.ok(got.rose >= 1);
            assert.ok(!dialled(/\/token$/));
            assert.ok(got.answer.text.indexOf("no state") >= 0);
          });
  got = await K.coded(SP, "STS-FED-0025", function () {
    return jarmGet(OP.sign({ iss: OP.base, aud: "frp-client", state: state,
      error: "access_denied", exp: exp() }));
  });
  K.check("M5. a JARM response carrying the partner's error is that error " +
          "(STS-FED-0025) and redeems no code", function () {
    assert.strictEqual(got.answer.status, 400, K.shown(got.answer));
    assert.ok(got.rose >= 1);
    assert.ok(!dialled(/\/token$/));
    assert.ok(got.answer.text.indexOf("access_denied") >= 0);
  });
  got = await K.coded(SP, "STS-FED-0250", function () {
    return jarmGet(OP.sign({ iss: OP.base, aud: "frp-client", state: state,
      code: "c-noexp" }));
  });
  K.check("M6. a JARM response with no exp is refused (STS-FED-0250)",
          function () {
            assert.strictEqual(got.answer.status, 401, K.shown(got.answer));
            assert.ok(got.rose >= 1);
            assert.ok(!dialled(/\/token$/));
            assert.ok(got.answer.text.indexOf("no exp") >= 0);
          });
  r = await jarmGet(OP.sign({ iss: OP.base, aud: "frp-client", state: state,
    code: "c-jarm-kept", exp: exp() }));
  K.check("M7. the same sign-in still redeems a good JARM response",
          function () {
            assert.ok(r.status < 400, K.shown(r));
            assert.ok(/code=c-jarm-kept/.test(
              (callsTo(/\/token$/)[0] || { body: "" }).body));
          });
  log.debug("Leaving messageSigning().");
}

// ------------------------------------------------------------------- N
async function nonces() {
  log.debug("Entering nonces().");
  log.info("=== N. pushes refused, DPoP nonces, every request afresh ===");
  const PARNO = await make("ffc-parno", Object.assign({
    fedFapi: "2-security" }, DISCOVERING));
  op.calls = [];
  op.scenario = pushScenario({ parRefuse: true });
  let got = await K.coded(SP, "STS-FED-0244", function () {
    return begin(PARNO, K.browser());
  });
  K.check("N1. a push the partner refuses stays 502 (STS-FED-0244), is not " +
          "sent again, and the browser is not redirected", function () {
    assert.strictEqual(got.answer.status, 502, got.answer.text.slice(0, 200));
    assert.ok(got.rose >= 1);
    assert.ok(String(got.answer.location).indexOf("request_uri") < 0);
    assert.strictEqual(callsTo(/\/par$/).length, 1);
  });
  op.calls = [];
  op.scenario = pushScenario({ parNonce: "nonce-from-the-partner" });
  let started = await begin(PARNO, K.browser());
  let pushes = callsTo(/\/par$/);
  K.check("N2. the first push answered use_dpop_nonce is sent again with " +
          "that nonce, and that one redirects", function () {
    assert.strictEqual(pushes.length, 2);
    assert.strictEqual(started.status, 302);
    assert.ok(started.location.indexOf("request_uri=") >= 0);
    assert.strictEqual(nonceOf(pushes[0]), "");
    assert.strictEqual(nonceOf(pushes[1]), "nonce-from-the-partner");
  });
  op.calls = [];
  op.scenario = pushScenario({ parNonceAlways: true });
  started = await begin(PARNO, K.browser());
  pushes = callsTo(/\/par$/);
  K.check("N3. a partner that answers use_dpop_nonce again is not asked a " +
          "third time", function () {
    assert.strictEqual(pushes.length, 2, String(pushes.length));
    assert.strictEqual(started.status, 502);
  });
  // Every request signed afresh, and UserInfo's own challenge.
  const NJTI = await make("ffc-jti", Object.assign({ fedFapi: "2-security",
    fedRefreshTokens: "TRUE", fedRefreshEverySeconds: "1" }, DISCOVERING));
  const b = K.browser();
  op.calls = [];
  op.jtis = [];
  op.par = null;
  op.scenario = pushScenario({ rt: "rt-nonce",
    demand: { as: "as-nonce-1", rs: "rs-nonce-1", rt: "rt-nonce" } });
  await begin(NJTI, b);
  op.scenario.demand.as = "as-nonce-1b";
  const r = await b.go(acs(NJTI) + "?state=" +
    encodeURIComponent((op.par || new URLSearchParams()).get("state")) +
    "&code=c-njti&iss=" + encodeURIComponent(OP.base));
  const par = callsTo(/\/par$/);
  const token = callsTo(/\/token$/);
  const user = callsTo(/\/userinfo$/);
  op.byToken["rt-nonce"] = { claims: fresh };
  op.scenario.demand = { as: "as-nonce-2", rs: "rs-nonce-2",
                         rt: "rt-nonce" };
  const signInCalls = op.calls.length;
  await K.sleep(1600);
  await runJob("federation.partner-refresh");
  const later = op.calls.slice(signInCalls);
  const refresh = later.filter(function (c) {
    return /\/token$/.test(c.path) && /refresh_token=rt-nonce/.test(c.body);
  });
  const refreshUser = later.filter(function (c) {
    return /\/userinfo$/.test(c.path) && c.auth === "DPoP at-rt-nonce";
  });
  const mine = par.concat(token, refresh).map(function (c) {
    const sent = P.jwtParts(new URLSearchParams(c.body)
      .get("client_assertion"));
    return sent ? String(sent.claims.jti || "") : "";
  });
  const all = op.jtis.filter(function (one) {
    return one.kind === "client_assertion";
  }).map(function (one) {
    return one.jti;
  });
  K.check("N4. the push, the token request and the refresh are each " +
          "answered use_dpop_nonce and sent again, and no client assertion " +
          "jti is seen twice", function () {
    assert.ok(r.status < 400, K.shown(r));
    assert.strictEqual(par.length, 2);
    assert.strictEqual(token.length, 2);
    assert.strictEqual(refresh.length, 2, String(refresh.length));
    assert.strictEqual(mine.length, 6);
    assert.ok(distinct(mine) && distinct(all), JSON.stringify(all));
  });
  K.check("N5. UserInfo's challenge in WWW-Authenticate (scheme dPoP) is " +
          "answered with its own nonce at the sign-in and the refresh, and " +
          "neither server is sent the other's", function () {
    assert.deepStrictEqual(user.map(nonceOf), ["", "rs-nonce-1"]);
    assert.deepStrictEqual(par.map(nonceOf), ["", "as-nonce-1"]);
    assert.deepStrictEqual(token.map(nonceOf), ["as-nonce-1",
                                                "as-nonce-1b"]);
    assert.deepStrictEqual(refresh.map(nonceOf), ["as-nonce-1b",
                                                  "as-nonce-2"]);
    assert.deepStrictEqual(refreshUser.map(nonceOf), ["rs-nonce-1",
                                                      "rs-nonce-2"]);
  });
  const NRO = await make("ffc-jtims", Object.assign({
    fedFapi: "2-message-signing" }, DISCOVERING));
  op.calls = [];
  op.jtis = [];
  op.scenario = pushScenario({ demand: { as: "as-nonce-ms",
                                         rs: "rs-nonce-ms", rt: "" } });
  started = await begin(NRO, K.browser());
  const kinds = function (kind) {
    log.debug("Entering kinds(). " + kind);
    log.debug("Leaving kinds().");
    return op.jtis.filter(function (one) {
      return one.kind === kind;
    }).map(function (one) {
      return one.jti;
    });
  };
  K.check("N6. message signing's retried push carries a new request " +
          "object and a new client assertion, each with a jti of its own",
          function () {
            assert.strictEqual(started.status, 302);
            assert.strictEqual(callsTo(/\/par$/).length, 2);
            assert.strictEqual(kinds("request").length, 2);
            assert.ok(distinct(kinds("request")));
            assert.strictEqual(kinds("client_assertion").length, 2);
            assert.ok(distinct(kinds("client_assertion")));
          });
  log.debug("Leaving nonces().");
}

// ------------------------------------------------------------------- R
async function registrations() {
  log.debug("Entering registrations().");
  log.info("=== R. what a FAPI profile registers ===");
  const regFields = { fedRegister: "TRUE", fedClientId: null,
                      fedClientSecret: null };
  const REGMS = await make("ffc-regms", Object.assign({
    fedFapi: "2-message-signing" }, DISCOVERING, regFields));
  const before = op.registrations;
  op.scenario = pushScenario();
  let started = await begin(REGMS, K.browser());
  let reg = op.registered || {};
  let key = ((reg.jwks || {}).keys || [])[0] || {};
  K.check("R1. message signing registers private_key_jwt, PS256, DPoP and " +
          "a signed authorization response, a pushed request and code",
          function () {
            assert.strictEqual(started.status, 302);
            assert.strictEqual(op.registrations, before + 1);
            assert.strictEqual(reg.token_endpoint_auth_method,
                               "private_key_jwt");
            assert.strictEqual(reg.token_endpoint_auth_signing_alg, "PS256");
            assert.strictEqual(reg.dpop_bound_access_tokens, true);
            assert.strictEqual(reg.authorization_signed_response_alg,
                               "PS256");
            assert.strictEqual(reg.request_object_signing_alg, "PS256");
            assert.strictEqual(reg.require_pushed_authorization_requests,
                               true);
            assert.strictEqual(JSON.stringify(reg.response_types),
                               "[\"code\"]");
            assert.ok((reg.grant_types || []).indexOf("implicit") < 0);
            assert.ok(key.kty === "RSA" && !key.d);
          });
  const REGADV = await make("ffc-regadv", Object.assign({
    fedFapi: "1-advanced" }, DISCOVERING, regFields));
  op.scenario = { issuer: OP.base, base: OP.base };
  started = await begin(REGADV, K.browser());
  reg = op.registered || {};
  key = ((reg.jwks || {}).keys || [])[0] || {};
  K.check("R2. 1-advanced registers the request object and the hybrid " +
          "response, and not DPoP, JARM or a pushed request", function () {
    assert.strictEqual(started.status, 302);
    assert.strictEqual(reg.token_endpoint_auth_method, "private_key_jwt");
    assert.strictEqual(reg.request_object_signing_alg, "PS256");
    assert.strictEqual(JSON.stringify(reg.response_types),
                       "[\"code id_token\"]");
    assert.ok((reg.grant_types || []).indexOf("authorization_code") >= 0 &&
              (reg.grant_types || []).indexOf("implicit") >= 0);
    assert.ok(reg.dpop_bound_access_tokens !== true);
    assert.ok(!reg.authorization_signed_response_alg);
    assert.ok(!reg.require_pushed_authorization_requests);
    assert.ok(key.kty === "RSA" && !key.d);
  });
  log.debug("Leaving registrations().");
}

// ------------------------------------------------------------------- F
async function refreshes() {
  log.debug("Entering refreshes().");
  log.info("=== F. refresh under each profile ===");
  const proofX = function (header) {
    log.debug("Entering proofX().");
    const parsed = P.jwtParts(header);
    log.debug("Leaving proofX().");
    return parsed && parsed.header.jwk && parsed.header.jwk.x;
  };
  const FREF = await make("ffc-fref", Object.assign({ fedFapi: "2-security",
    fedRefreshTokens: "TRUE", fedRefreshEverySeconds: "1" }, DISCOVERING));
  const b = K.browser();
  op.calls = [];
  op.par = null;
  op.scenario = pushScenario({ rt: "rt-fapi2" });
  await begin(FREF, b);
  await b.go(acs(FREF) + "?state=" +
    encodeURIComponent((op.par || new URLSearchParams()).get("state")) +
    "&code=c-fref&iss=" + encodeURIComponent(OP.base));
  const signInX = proofX((callsTo(/\/token$/)[0] || {}).dpop);
  op.byToken["rt-fapi2"] = { claims: fresh };
  const AREF = await make("ffc-aref", { fedFapi: "1-advanced",
    fedRefreshTokens: "TRUE", fedRefreshEverySeconds: "1" });
  const ab = K.browser();
  op.scenario = { rt: "rt-fapi1" };
  const started = await begin(AREF, ab);
  op.scenario.backClaims = function () {
    return claims(started);
  };
  await ab.go(acs(AREF), { form: { state: started.params.get("state"),
    code: "c-aref", id_token: OP.sign(claims(started, {
      c_hash: P.halfHash("c-aref"),
      s_hash: P.halfHash(started.params.get("state")) })) } });
  op.byToken["rt-fapi1"] = { claims: fresh };
  await K.sleep(1600);
  op.calls = [];
  await runJob("federation.partner-refresh");
  const fref = op.calls.filter(function (c) {
    return /\/token$/.test(c.path) && /refresh_token=rt-fapi2/.test(c.body);
  })[0] || { body: "", dpop: "" };
  const fform = new URLSearchParams(fref.body);
  K.check("F1. a 2.x refresh sends private_key_jwt and a DPoP proof from " +
          "the sign-in's key, and UserInfo is asked as DPoP", function () {
    assert.ok(signInX);
    assert.strictEqual(proofX(fref.dpop), signInX);
    assert.ok(fform.get("client_assertion") && !fform.get("client_secret"));
    assert.ok(op.calls.some(function (c) {
      return /\/userinfo$/.test(c.path) && c.auth === "DPoP at-rt-fapi2";
    }));
  });
  const aref = op.calls.filter(function (c) {
    return /\/token$/.test(c.path) && /refresh_token=rt-fapi1/.test(c.body);
  })[0] || { body: "", dpop: "none" };
  K.check("F2. a 1-advanced refresh sends the assertion and no DPoP proof, " +
          "and UserInfo stays bearer", function () {
    assert.ok(new URLSearchParams(aref.body).get("client_assertion"),
              aref.body.slice(0, 200));
    assert.ok(!aref.dpop, aref.dpop);
    assert.ok(op.calls.some(function (c) {
      return /\/userinfo$/.test(c.path) && c.auth === "Bearer at-rt-fapi1";
    }));
  });
  op.byToken["rt-fapi2"].tokenType = "Bearer";
  await K.sleep(1600);
  const got = await K.coded(SP, "STS-FED-0251", async function () {
    op.calls = [];
    return runJob("federation.partner-refresh");
  });
  K.check("F3. a 2-security refresh answered Bearer ends the session " +
          "(STS-FED-0251) and UserInfo is not asked", function () {
    assert.ok(op.calls.some(function (c) {
      return /\/token$/.test(c.path) && /refresh_token=rt-fapi2/.test(c.body);
    }));
    assert.ok(got.rose >= 1);
    assert.ok(!op.calls.some(function (c) {
      return /\/userinfo$/.test(c.path) && /at-rt-fapi2/.test(c.auth);
    }));
  });
  log.debug("Leaving refreshes().");
}

// ------------------------------------------------------------------- T
async function mutualTls(ADV) {
  log.debug("Entering mutualTls().");
  log.info("=== T. 1-advanced over mutual TLS ===");
  const signIn = async function (id, extra) {
    log.debug("Entering signIn(). " + id);
    const b = K.browser();
    const begun = await begin(id, b);
    op.calls = [];
    op.scenario = Object.assign({ bindMtls: true, backClaims: function () {
      return claims(begun, extra && extra.aud ? { aud: extra.aud } : {});
    } }, (extra && extra.scenario) || {});
    const r = await b.go(acs(id), { form: {
      state: begun.params.get("state"), code: "c-mtls",
      id_token: OP.sign(claims(begun, Object.assign({
        c_hash: P.halfHash("c-mtls"),
        s_hash: P.halfHash(begun.params.get("state")) },
      extra && extra.aud ? { aud: extra.aud } : {}))) } });
    log.debug("Leaving signIn().");
    return { r: r, token: callsTo(/\/token$/)[0] ||
                          { body: "", cert: "", dpop: "", auth: "" },
             userinfo: callsTo(/\/userinfo$/)[0] || { cert: "", auth: "" } };
  };
  const MTLS = await make("ffc-mtls", { fedFapi: "1-advanced",
    fedTokenUrl: OP.mtlsBase + "token",
    fedUserinfoUrl: OP.mtlsBase + "userinfo" });
  op.boundAnswered = 0;
  op.boundRefused = 0;
  let got = await signIn(MTLS);
  let view = (await viewOf(MTLS)).clientCertificate || {};
  K.check("T1. 1-advanced presents the relationship's client certificate " +
          "at the token endpoint, beside private_key_jwt and no DPoP",
          function () {
            assert.ok(got.r.status < 400, K.shown(got.r));
            assert.ok(view.held, JSON.stringify(view).slice(0, 300));
            assert.ok(got.token.cert);
            assert.strictEqual(got.token.cert, view.x5tS256);
            assert.ok(new URLSearchParams(got.token.body)
              .get("client_assertion"));
            assert.ok(!got.token.dpop);
          });
  K.check("T2. UserInfo is asked over the same certificate, so the " +
          "certificate-bound token is answered", function () {
    assert.strictEqual(got.userinfo.cert, view.x5tS256);
    assert.strictEqual(op.boundAnswered, 1);
    assert.ok(!op.boundRefused);
  });
  let parsed = null;
  try {
    parsed = new nodeCrypto.X509Certificate(view.certificatePem || "");
  } catch (e) {
    log.debug("Caught in mutualTls(): " + ((e && e.message) || e));
    // No certificate published is what T3 reports.
    parsed = null;
  }
  K.check("T3. the certificate is a clientAuth leaf under the realm's " +
          "chain, its x5t#S256 and subject published and no private key",
          function () {
            assert.ok(parsed, "the published certificate does not parse");
            assert.ok(/(^|,)CN=federation ffc-mtls/.test(view.subject),
                      view.subject);
            assert.strictEqual(parsed.fingerprint256.replace(/:/g, "")
              .toLowerCase(), Buffer.from(view.x5tS256, "base64url")
              .toString("hex"));
            assert.ok((view.chainPem || []).length >= 2);
            assert.ok((parsed.keyUsage || []).indexOf("1.3.6.1.5.5.7.3.2") >=
                      0, JSON.stringify(parsed.keyUsage));
            assert.ok(JSON.stringify(view).indexOf("PRIVATE KEY") < 0);
          });
  await setField(MTLS, "fedTokenAuth", "tls_client_auth");
  got = await signIn(MTLS);
  const ready = await viewOf(MTLS);
  const form = new URLSearchParams(got.token.body);
  K.check("T4. tls_client_auth sends the client_id over the certificate " +
          "and no assertion, secret or Basic header", function () {
    assert.ok(ready.ready, JSON.stringify(ready.missing));
    assert.ok(got.r.status < 400, K.shown(got.r));
    assert.strictEqual(got.token.cert, view.x5tS256);
    assert.strictEqual(form.get("client_id"), "frp-client");
    assert.ok(!form.get("client_assertion") && !form.get("client_secret"));
    assert.ok(!/^Basic /.test(got.token.auth || ""));
  });
  const TCA = await make("ffc-tca-plain", { fedTokenAuth: "tls_client_auth" });
  const tca = await viewOf(TCA);
  K.check("T5. tls_client_auth without 1-advanced is not ready", function () {
    assert.ok(!tca.ready);
    assert.ok((tca.missing || []).some(function (m) {
      return /^fedFapi=1-advanced/.test(String(m));
    }), JSON.stringify(tca.missing));
  });
  // The renewal job, inside federation.clientCertificateRenewDays: every
  // held certificate is due once the window is wider than its life.
  await K.set(SP, "federation.clientCertificateRenewDays", 3650);
  await runJob("federation.client-certificate-renew");
  const renewed = (await viewOf(MTLS)).clientCertificate || {};
  await K.unset(SP, "federation.clientCertificateRenewDays");
  K.check("T6. the renewal job issues a new certificate with the same " +
          "subject inside federation.clientCertificateRenewDays",
          function () {
            assert.ok(renewed.serialHex && view.serialHex);
            assert.notStrictEqual(renewed.serialHex, view.serialHex);
            assert.strictEqual(renewed.subject, view.subject);
          });
  view = renewed;
  const ALIAS = await make("ffc-alias", Object.assign({
    fedFapi: "1-advanced", fedRegister: "TRUE", fedClientId: null,
    fedClientSecret: null, fedTokenAuth: "tls_client_auth" }, DISCOVERING));
  op.registered = null;
  const aliases = { mtls_endpoint_aliases: {
    token_endpoint: OP.mtlsBase + "token",
    userinfo_endpoint: OP.mtlsBase + "userinfo" } };
  op.scenario = { issuer: OP.base, base: OP.base, discovery: aliases };
  const ab = K.browser();
  const started = await begin(ALIAS, ab);
  const reg = op.registered || {};
  const issuedId = "dyn-" + op.registrations;
  const aliasView = (await viewOf(ALIAS)).clientCertificate || {};
  op.calls = [];
  op.scenario.bindMtls = true;
  op.scenario.backClaims = function () {
    return claims(started, { aud: issuedId });
  };
  const r = await ab.go(acs(ALIAS), { form: {
    state: started.params.get("state"), code: "c-alias",
    id_token: OP.sign(claims(started, { c_hash: P.halfHash("c-alias"),
      s_hash: P.halfHash(started.params.get("state")),
      aud: issuedId })) } });
  const aliasToken = callsTo(/\/token$/)[0] || { cert: "" };
  const aliasAskedUserinfo = dialled(/\/userinfo$/);
  K.check("T7. 1-advanced registers tls_client_auth with the certificate's " +
          "subject DN and certificate-bound access tokens", function () {
    assert.strictEqual(reg.token_endpoint_auth_method, "tls_client_auth");
    assert.strictEqual(reg.tls_client_auth_subject_dn, aliasView.subject);
    assert.strictEqual(reg.tls_client_certificate_bound_access_tokens, true);
    assert.ok(!reg.token_endpoint_auth_signing_alg);
  });
  K.check("T8. the token request goes to the discovery document's " +
          "mtls_endpoint_aliases with the client certificate, and (the " +
          "control for T9) the UserInfo alias is asked", function () {
    assert.ok(r.status < 400, K.shown(r));
    assert.ok(aliasToken.cert);
    assert.strictEqual(aliasToken.cert, aliasView.x5tS256);
    assert.ok(aliasAskedUserinfo);
  });
  const NOUI = await make("ffc-noui", Object.assign({
    fedFapi: "1-advanced", fedTokenAuth: "tls_client_auth",
    fedUserinfo: "FALSE" }, DISCOVERING));
  op.scenario = { issuer: OP.base, base: OP.base, discovery: aliases };
  const nb = K.browser();
  const nstart = await begin(NOUI, nb);
  op.calls = [];
  op.scenario.bindMtls = true;
  op.scenario.backClaims = function () {
    return claims(nstart);
  };
  const nr = await nb.go(acs(NOUI), { form: {
    state: nstart.params.get("state"), code: "c-noui",
    id_token: OP.sign(claims(nstart, { c_hash: P.halfHash("c-noui"),
      s_hash: P.halfHash(nstart.params.get("state")) })) } });
  const nview = (await viewOf(NOUI)).clientCertificate || {};
  const ntoken = callsTo(/\/token$/)[0] || { cert: "" };
  K.check("T9. with fedUserinfo off 1-advanced signs the person in on the " +
          "ID Tokens, dials the token alias with its certificate and asks " +
          "no UserInfo", function () {
    assert.ok(nr.status < 400, K.shown(nr));
    assert.ok(ntoken.cert && ntoken.cert === nview.x5tS256);
    assert.ok(!dialled(/userinfo/));
  });
  const FRAG = await make("ffc-frag", { fedFapi: "1-advanced",
                                        fedResponseMode: "fragment" });
  let page = await K.send(acs(FRAG));
  K.check("T10. 1-advanced with the fragment mode and a stored response " +
          "type of code answers the bare GET with the fragment page",
          function () {
            assert.strictEqual(page.status, 200, K.shown(page));
            assert.ok(/fragment\.js"><\/script>/.test(page.text));
            assert.ok(page.text.indexOf("id=\"fed-fragment\"") > 0);
          });
  page = await K.send(acs(ADV));
  K.check("T11. 1-advanced without the fragment mode never answers with " +
          "the page", function () {
    assert.ok(page.status !== 200 || page.text.indexOf("fragment.js") < 0);
  });
  log.debug("Leaving mutualTls().");
}

async function test() {
  log.debug("Entering test().");
  OP = await P.partner(K, { sub: "frp-person" });
  op = OP.op;
  try {
    SP = await K.realm("ffc", "development", {
      "federation.outboundAllowHttp": "true",
      "federation.outboundSkipTlsVerification": "true" });
    await security();
    const ADV = await advanced();
    await messageSigning();
    await nonces();
    await registrations();
    await refreshes();
    await mutualTls(ADV);
  } finally {
    OP.close();
  }
  log.debug("Leaving test().");
}

K.main(test, 45);
