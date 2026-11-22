// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_identity_assurance.js
//
// ---------------------------------------------------------------------------
// OPENID CONNECT FOR IDENTITY ASSURANCE 1.0 (#127), WHAT A RELYING PARTY
// SEES, OVER THE WIRE.
//
// D12 (#444): carries over tests/identity_assurance.js beyond what
// `sts_oidc_core.js` section p already holds (discovery's frameworks,
// recording one passport check, one answer, section 6's refusal of a
// request with no verification). Every verification here is recorded
// through `POST /admin-api/users/record-verification` and every answer is
// read off UserInfo for a token whose claims request asked for it:
//
//   1. section 6's request rules at the authorization endpoint
//      (invalid_request): no trust_framework, empty claims, a purpose under
//      3 or over 300 characters, a negative max_age, and a malformed
//      element refusing the whole claims request;
//   2. recording: values taken from the entry and `time` defaulted; the
//      refusals (an unconfigured framework, urn:sts:demo, a document type
//      outside the vocabulary, an electronic_signature with no serial, a
//      vouch with no attestation, an unknown check method, a claim nobody
//      verifies, a claim the entry holds nothing for); a second record
//      listed newest first; a record removed by id, an unknown id refused;
//   3. the answer: the newest satisfying record with only the members asked
//      for; `value` on the framework and evidence type choosing the
//      passport, only document_details.type returned; omitted for a
//      framework or evidence type no record carries; max_age passing over
//      an old vouch; two elements answered as an array of two; `value` and
//      `values` on a claim inside verified_claims enforced (5.7.4);
//   4. a verified value the entry no longer holds is not released;
//   5. development invents a verification under urn:sts:demo for a person
//      with none, which a request naming a real framework never matches;
//      a PRODUCT realm answers nothing and does not publish urn:sts:demo;
//   7. discovery's section 7 members, and verified_claims answered beside
//      an ordinary claim.
//
// NOT CARRIED: section 6, the automatic sources (a certificate's subject
// and a wallet's disclosures) — owed with the TLS sign-in and OpenID4VP
// families, phase 9; 1h (the parsed form parses again) and 2l (the
// console's flat form) and 8 (the console's drawing) — library and markup,
// class (d).
//
// OWNED HERE (local: true): this repository's own authorization server.
// ---------------------------------------------------------------------------

// An address compared by parsing it, not searched for as text
// (`url_match.js`).
const urls = require("./url_match.js");
const authnSignin = require("./authn_signin");
const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_identity_assurance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "ida-" + STAMP;
const PROD = "idap-" + STAMP;
const R = "/realm/" + REALM;
const RB = base + R;
const API = RB + "/admin-api";
const SECRET = "ida-" + STAMP + "-" + String(Date.now()).slice(-8) +
               "-0123456789abcdef0123456789abcdef";
const PASSWORD = "Ida-Passw0rd!-" + String(Date.now()).slice(-6);
const ALICE = "alice-" + STAMP;
const NOBODY = "nobody-" + STAMP;
const REDIRECT = "https://rp.ida.example.test/cb";
const CLIENT = "ida-rp";
const AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 " +
  "sts_identity_assurance/1.0 (" + STAMP + ")";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

function form(o) {
  log.debug("Entering form().");
  log.debug("Leaving form().");
  return new URLSearchParams(o).toString();
}

function absolute(location) {
  log.debug("Entering absolute().");
  log.debug("Leaving absolute().");
  return /^https?:\/\//i.test(String(location || ""))
    ? String(location) : base + String(location || "");
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — a page or a JWT; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers,
           location: r.headers.get("location") || "" };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

// A refusal: a 400 whose answer names no code.
async function refused(url, payload, what) {
  log.debug("Entering refused().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 400 && r.body && r.body.ok === false,
    "POST " + url + " should have refused " + what + "; it answered " +
    r.status + " " + String(r.raw).slice(0, 400));
  assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "no code is sent: " + r.raw);
  log.debug("Leaving refused().");
  return r.body;
}

async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(api, code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(api, code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(api, code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// One browser, with a cookie jar, signed in once and kept.
function browser(realmPath) {
  log.debug("Entering browser().");
  const jar = {};
  const self = {
    jar: jar,
    realm: realmPath,
    header() {
      log.debug("Entering header().");
      log.debug("Leaving header().");
      return Object.keys(jar).map(function (k) {
        return k + "=" + jar[k];
      }).join("; ");
    },
    keep(headers) {
      log.debug("Entering keep().");
      const set = headers.getSetCookie ? headers.getSetCookie() : [];
      set.forEach(function (one) {
        const pair = String(one).split(";")[0];
        const at = pair.indexOf("=");
        if (at <= 0) {
          return;
        }
        const value = pair.slice(at + 1);
        if (value === "" || /Expires=Thu, 01 Jan 1970/i.test(String(one))) {
          delete jar[pair.slice(0, at)];
        } else {
          jar[pair.slice(0, at)] = value;
        }
      });
      log.debug("Leaving keep().");
    },
    async go(method, path) {
      log.debug("Entering go(). " + method + " " + path);
      const headers = { "User-Agent": AGENT };
      const cookie = self.header();
      if (cookie) {
        headers.cookie = cookie;
      }
      const r = await fetch(absolute(path), { method: method,
        redirect: "manual", headers: headers });
      self.keep(r.headers);
      const text = await r.text();
      log.debug("Leaving go(). status=" + r.status);
      return { status: r.status, location: r.headers.get("location") || "",
               text: text, headers: r.headers };
    }
  };
  log.debug("Leaving browser().");
  return self;
}

async function signIn(b, location, who) {
  log.debug("Entering signIn(). who=" + who);
  const answer = await authnSignin.submit(base + b.realm, location,
    { action: "login", username: who, password: PASSWORD },
    { cookie: b.header(), headers: { "User-Agent": AGENT } });
  assert.ok(answer.view, "the sign-in screen: " + answer.status + " " +
            JSON.stringify(answer.errors));
  b.keep(answer.headers);
  const posted = await authnSignin.asFormAnswer(answer, function (m, u) {
    return b.go(m, u);
  });
  log.debug("Leaving signIn().");
  return posted;
}

const browsers = {};

// A code flow for `who` at `client`, answering the token response.
async function tokensFor(client, scope, who, extra) {
  log.debug("Entering tokensFor(). " + client + " " + scope);
  const rp = (extra && extra.realmPath) || R;
  const key = rp + " " + who;
  const b = browsers[key] || (browsers[key] = browser(rp));
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const params = Object.assign({ response_type: "code", client_id: client,
    redirect_uri: REDIRECT, scope: scope, state: "st",
    nonce: "n-" + STAMP,
    code_challenge: nodeCrypto.createHash("sha256").update(verifier)
      .digest("base64url"), code_challenge_method: "S256" }, extra || {});
  delete params.realmPath;
  let r = await b.go("GET", rp + "/oauth2/authorize?" + form(params));
  if ((r.status === 302 || r.status === 303) &&
      /\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(r.location)) {
    const signed = await signIn(b, r.location, who);
    r = await b.go("GET", signed.location);
  }
  const code = r.location && urls.isAt(r.location, REDIRECT)
    ? new URL(r.location).searchParams.get("code") : "";
  assert.ok(code, "a code for " + client + " (" + scope + "): " + r.status +
            " " + r.location + " " + String(r.text).slice(0, 300));
  const body = { grant_type: "authorization_code", code: code,
    redirect_uri: REDIRECT, client_id: client, client_secret: SECRET,
    code_verifier: verifier };
  if (extra && extra.resource) {
    body.resource = extra.resource;
  }
  const t = await send(base + rp + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form(body) });
  assert.strictEqual(t.status, 200, "the code redeemed: " +
                     t.raw.slice(0, 400));
  log.debug("Leaving tokensFor().");
  return t.body;
}

async function accessFor(client, scope, who, extra) {
  log.debug("Entering accessFor().");
  const t = await tokensFor(client, scope, who || ALICE, extra);
  log.debug("Leaving accessFor().");
  return decode(t.access_token);
}

async function idFor(client, scope, who) {
  log.debug("Entering idFor().");
  const t = await tokensFor(client, scope, who || ALICE);
  log.debug("Leaving idFor().");
  return decode(t.id_token);
}


const PASSPORT = {
  trust_framework: "urn:sts:local",
  assurance_level: "substantial",
  evidence: [{ type: "document",
    check_details: [{ check_method: "vpip" }],
    document_details: { type: "passport", document_number: "X1234567",
      issuer: { name: "Passport Office", country_code: "GBR" },
      date_of_issuance: "2020-01-02", date_of_expiry: "2030-01-01" } }]
};

async function setupRealm(id, mode) {
  log.debug("Entering setupRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Identity assurance " + id },
    "created the realm " + id);
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
      value: mode }, "put " + id + " in " + mode + " mode");
    await ok(base + "/admin-api/realms/set", { id: id,
      key: "authn.allowOptionalSecondFactor", value: "true" },
      "let the policy decide the second factor in " + id);
  }
  const api = base + "/realm/" + id + "/admin-api";
  await ok(api + "/config/set", { key: "oauth2.idaTrustFrameworks",
    value: "urn:sts:local,eidas" }, "configured two trust frameworks");
  for (const who of [ALICE, NOBODY]) {
    await ok(api + "/users/create", { username: who, invent: false,
      credential: "password", password: PASSWORD,
      attributes: { cn: who, givenName: who === ALICE ? "Alice" : "Nobody",
                    sn: "Liddell", mail: who + "@ida.example.test" } },
      "created " + who + " in " + id);
  }
  await ok(api + "/applications/create", { identifier: CLIENT, name: CLIENT,
    kind: "oauth2-client", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthRedirectUri: [REDIRECT],
      oauthAllowedScope: ["openid", "profile", "email"],
      oauthGrantType: ["authorization_code"],
      oauthResponseType: ["code"] } }, "registered the relying party");
  for (const one of ["openid", "profile", "email"]) {
    await ok(api + "/consent/grant-global-consent",
             { client: CLIENT, scope: one }, "consented " + one);
  }
  log.debug("Leaving setupRealm().");
  return api;
}

// UserInfo's verified_claims for one claims request's userinfo member.
async function answer(userinfo, who, realmPath) {
  log.debug("Entering answer().");
  const t = await tokensFor(CLIENT, "openid", who || ALICE, {
    claims: JSON.stringify({ userinfo: userinfo }),
    realmPath: realmPath || R });
  const r = await send(base + (realmPath || R) + "/oauth2/userinfo", {
    headers: { Authorization: "Bearer " + t.access_token } });
  assert.strictEqual(r.status, 200, "UserInfo: " + r.raw.slice(0, 300));
  log.debug("Leaving answer().");
  return r.body;
}

function element(verification, claims) {
  log.debug("Entering element().");
  log.debug("Leaving element().");
  return { verified_claims: { verification: verification, claims: claims } };
}

// The error at the client for a claims request, or "" for a code.
async function errorFor(claims) {
  log.debug("Entering errorFor().");
  const b = browsers[R + " " + ALICE];
  const r = await b.go("GET", R + "/oauth2/authorize?" + form({
    response_type: "code", client_id: CLIENT, redirect_uri: REDIRECT,
    scope: "openid", state: "st", nonce: "n",
    claims: JSON.stringify(claims) }));
  const at = urls.isAt(r.location, REDIRECT)
    ? new URL(r.location).searchParams : new URLSearchParams();
  log.debug("Leaving errorFor().");
  return at.get("error") || (at.get("code") ? "" : "none: " + r.status +
                             " " + r.location);
}

async function requestRules() {
  log.debug("Entering requestRules().");
  log.info("=== 1. section 6's request rules ===");
  await answer({ given_name: null });
  const cases = [
    [{ userinfo: { verified_claims: { verification: {},
       claims: { given_name: null } } } }, "no trust_framework member"],
    [{ id_token: { verified_claims: { verification: {
       trust_framework: null }, claims: {} } } }, "empty claims"],
    [{ userinfo: { verified_claims: { verification: {
       trust_framework: null }, claims: { given_name: {
       purpose: "ab" } } } } }, "a purpose under 3 characters"],
    [{ userinfo: { verified_claims: { verification: { trust_framework: {
       purpose: "x".repeat(301) } }, claims: { given_name: null } } } },
     "a purpose over 300 characters"],
    [{ userinfo: { verified_claims: { verification: {
       trust_framework: null, time: { max_age: -1 } },
       claims: { given_name: null } } } }, "a negative max_age"],
    [{ userinfo: { email: null }, id_token: { verified_claims: {
       claims: { name: null } } } },
     "a malformed element beside an ordinary claim"]
  ];
  for (const c of cases) {
    const error = await errorFor(c[0]);
    check("1. " + c[1] + " refuses the claims request invalid_request",
          function () {
      assert.strictEqual(error, "invalid_request", error);
    });
  }
  log.debug("Leaving requestRules().");
}

async function recording() {
  log.debug("Entering recording().");
  log.info("=== 2. recording ===");
  const kept = await ok(API + "/users/record-verification", { user: ALICE,
    verification: PASSPORT, claims: ["given_name", "family_name"] },
    "recorded the passport check");
  check("2a. recorded with the values the entry holds, and time defaulted",
        function () {
    assert.strictEqual(kept.verification.claims.given_name, "Alice");
    assert.strictEqual(kept.verification.claims.family_name, "Liddell");
    assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(
      kept.verification.verification.time), JSON.stringify(kept));
  });
  const refusals = [
    [{ trust_framework: "de_aml" }, ["given_name"],
     "an unconfigured framework"],
    [{ trust_framework: "urn:sts:demo" }, ["given_name"], "urn:sts:demo"],
    [{ trust_framework: "eidas", evidence: [{ type: "document",
       document_details: { type: "library" } }] }, ["given_name"],
     "a document type outside the vocabulary"],
    [{ trust_framework: "eidas", evidence: [{ type: "electronic_signature",
       signature_type: "qes", issuer: "CN=CA" }] }, ["given_name"],
     "an electronic_signature without its serial"],
    [{ trust_framework: "eidas", evidence: [{ type: "vouch" }] },
     ["given_name"], "a vouch without its attestation"],
    [{ trust_framework: "eidas", evidence: [{ type: "electronic_record",
       record: { type: "tax" }, check_details: [{ check_method: "guess" }] }]
     }, ["given_name"], "an unknown check method"],
    [{ trust_framework: "eidas" }, ["picture"], "a claim nobody verifies"],
    [{ trust_framework: "eidas" }, ["birth_family_name"],
     "a claim the entry holds nothing for"]
  ];
  for (const c of refusals) {
    const r = await postJson(API + "/users/record-verification", {
      user: ALICE, verification: c[0], claims: c[1] });
    check("2b. " + c[2] + " is refused 400", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw);
    });
  }
  const vouched = await ok(API + "/users/record-verification", {
    user: ALICE, verification: { trust_framework: "eidas",
      time: "2020-01-01T00:00:00Z", evidence: [{ type: "vouch",
        attestation: { type: "written_attestation",
                       voucher: { name: "Bob" } } }] },
    claims: ["given_name"] }, "recorded an old vouch");
  const listed = (await send(API + "/users/verifications?user=" +
                             encodeURIComponent(ALICE))).body || {};
  check("2c. a second record, listed newest first", function () {
    const ids = (listed.verifications || []).map(function (one) {
      return one.id;
    });
    assert.strictEqual(ids.length, 2, JSON.stringify(ids));
    assert.strictEqual(ids[0], vouched.verification.id);
  });
  log.debug("Leaving recording().");
  return { passport: kept.verification.id, vouch: vouched.verification.id };
}

async function answers() {
  log.debug("Entering answers().");
  log.info("=== 3. the answer ===");
  let r = await answer(element({ trust_framework: null },
                               { given_name: null, email: null }));
  check("3a. the newest satisfying record, only the members asked for, and " +
        "no claim it did not cover", function () {
    const vc = r.verified_claims;
    assert.ok(vc, JSON.stringify(r));
    assert.strictEqual(vc.verification.trust_framework, "eidas");
    assert.strictEqual(vc.claims.given_name, "Alice");
    assert.ok(!("email" in vc.claims));
    assert.deepStrictEqual(Object.keys(vc.verification),
                           ["trust_framework"]);
  });
  r = await answer(element({ trust_framework: { value: "urn:sts:local" },
    evidence: [{ type: { value: "document" },
                 document_details: { type: null } }] },
    { given_name: null, family_name: null }));
  check("3b. value on trust_framework and evidence type choose the passport; " +
        "only document_details.type is returned", function () {
    const v = (r.verified_claims || {}).verification || {};
    assert.strictEqual(v.trust_framework, "urn:sts:local",
                       JSON.stringify(r));
    assert.strictEqual(v.evidence.length, 1);
    assert.strictEqual(v.evidence[0].type, "document");
    assert.strictEqual(v.evidence[0].document_details.type, "passport");
    assert.strictEqual(v.evidence[0].document_details.document_number,
                       undefined);
    assert.strictEqual(r.verified_claims.claims.family_name, "Liddell");
  });
  r = await answer(element({ trust_framework: { value: "de_aml" } },
                           { given_name: null }));
  check("3c. a framework no record is under: verified_claims is omitted",
        function () {
    assert.strictEqual(r.verified_claims, undefined, JSON.stringify(r));
  });
  r = await answer(element({ trust_framework: null, evidence: [
    { type: { value: "electronic_record" } }] }, { given_name: null }));
  check("3d. an evidence type no record carries: omitted", function () {
    assert.strictEqual(r.verified_claims, undefined, JSON.stringify(r));
  });
  r = await answer(element({ trust_framework: null,
                             time: { max_age: 3600 } },
                           { given_name: null }));
  check("3e. max_age passes over the 2020 vouch to the recent passport",
        function () {
    assert.strictEqual(((r.verified_claims || {}).verification || {})
      .trust_framework, "urn:sts:local", JSON.stringify(r));
  });
  r = await answer({ verified_claims: [
    { verification: { trust_framework: { value: "eidas" } },
      claims: { given_name: null } },
    { verification: { trust_framework: { value: "urn:sts:local" } },
      claims: { family_name: null } }] });
  check("3f. two elements asked, an array of two answered", function () {
    assert.ok(Array.isArray(r.verified_claims) &&
              r.verified_claims.length === 2, JSON.stringify(r));
  });
  r = await answer(element({ trust_framework: null },
    { given_name: { value: "Somebody Else" }, family_name: null }));
  check("3g. a claim whose value does not match is omitted (5.7.4); the " +
        "rest of the element stands", function () {
    const c = (r.verified_claims || {}).claims || {};
    assert.ok(!("given_name" in c) && c.family_name === "Liddell",
              JSON.stringify(r));
  });
  r = await answer(element({ trust_framework: null },
    { given_name: { values: ["Bob", "Carol"] } }));
  check("3h. and an element left with no claim is omitted whole",
        function () {
    assert.strictEqual(r.verified_claims, undefined, JSON.stringify(r));
  });
  r = await answer(element({ trust_framework: null },
                           { given_name: { value: "Alice" } }));
  check("3i. a matching value is released", function () {
    assert.strictEqual(((r.verified_claims || {}).claims || {}).given_name,
                       "Alice", JSON.stringify(r));
  });
  r = await answer(Object.assign({ family_name: null },
    element({ trust_framework: null }, { family_name: null })));
  check("7a. verified_claims is answered beside the ordinary claim",
        function () {
    assert.strictEqual(r.family_name, "Liddell", JSON.stringify(r));
    assert.strictEqual(r.verified_claims.claims.family_name, "Liddell");
  });
  log.debug("Leaving answers().");
}

async function stale() {
  log.debug("Entering stale().");
  log.info("=== 4. a value the entry no longer holds ===");
  await ok(API + "/users/set-attribute", { user: ALICE,
    attribute: "givenName", value: "Alicia" }, "changed the given name");
  const r = await answer(element({ trust_framework: null },
                                 { given_name: null, family_name: null }));
  check("4a. the changed given name is not released as verified; the " +
        "unchanged surname is", function () {
    const c = (r.verified_claims || {}).claims || {};
    assert.ok(!("given_name" in c) && c.family_name === "Liddell",
              JSON.stringify(r));
  });
  await ok(API + "/users/set-attribute", { user: ALICE,
    attribute: "givenName", value: "Alice" }, "put the given name back");
  log.debug("Leaving stale().");
}

async function removal(ids) {
  log.debug("Entering removal().");
  const gone = await postJson(API + "/users/remove-verification", {
    user: ALICE, id: ids.vouch });
  const unknown = await postJson(API + "/users/remove-verification", {
    user: ALICE, id: "no-such-id" });
  const listed = (await send(API + "/users/verifications?user=" +
                             encodeURIComponent(ALICE))).body || {};
  check("2d. a record is removed by id, and an unknown id is refused",
        function () {
    assert.strictEqual(gone.status, 200, gone.raw.slice(0, 300));
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
    assert.deepStrictEqual((listed.verifications || []).map(function (o) {
      return o.id;
    }), [ids.passport]);
  });
  log.debug("Leaving removal().");
}

async function modes() {
  log.debug("Entering modes().");
  log.info("=== 5. development invents, product does not ===");
  let r = await answer(element({ trust_framework: null },
                               { given_name: null }), NOBODY);
  check("5a. development: an invented verification under urn:sts:demo",
        function () {
    const vc = r.verified_claims || {};
    assert.strictEqual((vc.verification || {}).trust_framework,
                       "urn:sts:demo", JSON.stringify(r));
    assert.strictEqual(vc.claims.given_name, "Nobody");
  });
  r = await answer(element({ trust_framework: { value: "eidas" } },
                           { given_name: null }), NOBODY);
  check("5b. which a request naming a real framework never matches",
        function () {
    assert.strictEqual(r.verified_claims, undefined, JSON.stringify(r));
  });
  const meta = (await send(RB + "/.well-known/openid-configuration")).body;
  check("7b. discovery: the frameworks (demo in development), four " +
        "evidence types, the vocabularies", function () {
    assert.strictEqual(meta.verified_claims_supported, true);
    assert.deepStrictEqual(meta.trust_frameworks_supported,
                           ["urn:sts:local", "eidas", "urn:sts:demo"]);
    assert.strictEqual(meta.evidence_supported.length, 4);
    assert.ok(meta.documents_supported.indexOf("passport") >= 0);
    assert.ok(meta.claims_in_verified_claims_supported
      .indexOf("nationalities") >= 0);
  });
  await setupRealm(PROD, "product");
  const P = "/realm/" + PROD;
  r = await answer(element({ trust_framework: null },
                           { given_name: null }), NOBODY, P);
  const prodMeta = (await send(base + P +
                               "/.well-known/openid-configuration")).body;
  check("5c. product: nothing, and urn:sts:demo is not published",
        function () {
    assert.strictEqual(r.verified_claims, undefined, JSON.stringify(r));
    assert.ok(prodMeta.trust_frameworks_supported
      .indexOf("urn:sts:demo") < 0,
              JSON.stringify(prodMeta.trust_frameworks_supported));
  });
  log.debug("Leaving modes().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving identity assurance at " + RB);
  await setupRealm(REALM, "");
  await requestRules();
  const ids = await recording();
  await answers();
  await stale();
  await removal(ids);
  await modes();
  assert.ok(checks >= 32, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [REALM, PROD]) {
    const r = await postJson(base + "/admin-api/realms/remove", { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main() removing realms: " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.debug("Leaving main().");
}

main();
