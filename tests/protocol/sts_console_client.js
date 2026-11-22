// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_console_client.js
//
// ---------------------------------------------------------------------------
// THE CONSOLE AS A CLIENT OF ITS OWN SERVICE, OVER THE WIRE: THE FILES IT IS
// SENT, THE TOKENS IT IS ISSUED, AND WHO IT MAY BE GRANTED TO.
//
// D12 (#444): carries over, against the running service, in a throwaway
// development realm this job creates and leaves behind:
//
//   A. tests/console_compression.js: `/admin/console.js`,
//      `/admin/console.css` and the document every `/admin` path answers are
//      sent brotli or gzip by Accept-Encoding (brotli first, `q=0` refusing
//      one, `*` offering both, nothing asked being nothing sent), each
//      decompressing to the plain bytes, each with `Vary: Accept-Encoding`;
//      a realm's document, compressed, still loads the realm's own script;
//      an `/admin-api` answer is never compressed (BREACH); and the
//      console's catalogs are one compressed static file.
//   B. tests/console_public_client.js (#446, rule 3cb): the seeded surfaces
//      are declared for their families; the console is seeded PUBLIC; a
//      token request from it with no DPoP proof is refused whole,
//      `invalid_dpop_proof`, recorded as STS-OAUTH-0943 and never sent; with
//      a proof it is a DPoP token set whose access token carries the key's
//      thumbprint; its refresh token is bound (refused without the proof,
//      redeemed with it for the same key); at `/admin-api` the bound token
//      sent as Bearer is refused and with its proof is accepted as the
//      person it names; another public client is issued a bearer token with
//      no proof. The password grant is added to the realm's console entry
//      here, as the in-process file adds it, so the token endpoint can be
//      asked without a browser: the rule every grant mints through is what
//      is under test, not the grant.
//   C. tests/console_role_needs_person.js: `POST /admin-api/rbac/grant` for
//      a name with no entry answers 400, reason `noSuchPerson`, a sentence
//      naming the person and saying to create them first, STS-ADMIN-0920 on
//      the audit and not in the answer, and nothing written — in the realm
//      and in the default realm; for a person who exists it grants, and the
//      membership resolves to their entry.
//
// What stays in process is said in each file's D12 note: an UNBOUND token
// issued to the console (STS-OAUTH-0944) can only be minted in process,
// because the token endpoint refuses to issue one.
//
// Its realms are removed at the end only when STS_TEST_REMOVE_REALMS is
// "1" (a shared private probe would fill otherwise); the suite leaves them.
//
// OWNED HERE (local: true): this repository's own console and management
// API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const https = require("https");
const zlib = require("zlib");
const names = require("./random_username.js");
const serviceTrust = require("../tools/service_trust.js");

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
var log = bunyan.createLogger({ name: "sts_console_client",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("ccl-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const CONSOLE = "sts-admin-console";
const WRITER = "ccl-writer";
const OTHER = "ccl-other-public";
const GHOST = "ccl-ghost-" + STAMP.toLowerCase().slice(-8);

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
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw, headers: r.headers };
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

async function getJson(url) {
  log.debug("Entering getJson().");
  const r = await send(url);
  assert.strictEqual(r.status, 200, "GET " + url + " answered " + r.status +
                     " " + String(r.raw).slice(0, 300));
  log.debug("Leaving getJson().");
  return r.body;
}

// The audit rows of one code in the realm whose API this is: the code is
// recorded, never sent.
async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const body = await getJson(api + "/audit?per=1&code=" +
                             encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number(body.matched || 0);
}

async function codeGrew(api, code, before) {
  log.debug("Entering codeGrew(). " + code);
  let now = before;
  for (let i = 0; i < 20 && now <= before; i += 1) {
    now = await codeCount(api, code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving codeGrew(). " + before + " -> " + now);
  return now - before;
}

// A GET whose body is NOT decoded, so the content coding the service chose
// is what is read. `fetch()` decodes and hides it.
function rawGet(url, acceptEncoding, headers) {
  log.debug("Entering rawGet(). " + url);
  log.debug("Leaving rawGet().");
  return new Promise(function (resolve, reject) {
    const all = Object.assign({}, headers || {});
    if (acceptEncoding !== null) {
      all["accept-encoding"] = acceptEncoding;
    }
    const req = https.get(url, { headers: all, ca: serviceTrust.trustedCa() },
                          function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("error", reject);
      res.on("end", function () {
        const bytes = Buffer.concat(chunks);
        const coding = String(res.headers["content-encoding"] || "");
        let plain = bytes;
        if (coding === "br") {
          plain = zlib.brotliDecompressSync(bytes);
        } else if (coding === "gzip") {
          plain = zlib.gunzipSync(bytes);
        }
        resolve({ status: res.statusCode, coding: coding,
                  vary: String(res.headers.vary || ""),
                  size: bytes.length, plain: plain.toString("utf8") });
      });
    });
    req.on("error", reject);
  });
}

function b64u(buffer) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(buffer).toString("base64url");
}

// An ES256 key and RFC 9449 proofs from it.
function dpopKey() {
  log.debug("Entering dpopKey().");
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const pub = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  log.debug("Leaving dpopKey().");
  return {
    proof: function (method, url, accessToken) {
      const claims = { jti: crypto.randomUUID(), htm: method,
                       htu: String(url).replace(/[?#].*$/, ""),
                       iat: Math.floor(Date.now() / 1000) };
      if (accessToken) {
        claims.ath = b64u(crypto.createHash("sha256").update(accessToken)
          .digest());
      }
      const input = b64u(JSON.stringify({ typ: "dpop+jwt", alg: "ES256",
                                          jwk: pub })) + "." +
                    b64u(JSON.stringify(claims));
      return input + "." + b64u(crypto.sign("sha256", Buffer.from(input),
        { key: pair.privateKey, dsaEncoding: "ieee-p1363" }));
    }
  };
}

function claimsOf(jwt) {
  log.debug("Entering claimsOf().");
  let claims = {};
  try {
    claims = JSON.parse(Buffer.from(String(jwt).split(".")[1], "base64url")
      .toString("utf8"));
  } catch (e) {
    log.debug("Caught in claimsOf(): " + ((e && e.message) || e));
    // Not a JWT; the check that reads it fails on the empty object.
    claims = {};
  }
  log.debug("Leaving claimsOf().");
  return claims;
}

function tokenRequest(form, headers) {
  log.debug("Entering tokenRequest().");
  log.debug("Leaving tokenRequest().");
  return send(RB + "/oauth2/token", { method: "POST",
    headers: Object.assign({
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json" }, headers || {}),
    body: new URLSearchParams(form).toString() });
}

function passwordGrant(clientId, headers) {
  log.debug("Entering passwordGrant().");
  log.debug("Leaving passwordGrant().");
  return tokenRequest({ grant_type: "password", username: WRITER,
    password: "anything", client_id: clientId,
    scope: "openid offline_access admin:read admin:write",
    resource: API }, headers);
}

async function compression() {
  log.debug("Entering compression().");
  log.info("=== A. the console's files, compressed where asked ===");
  const css = base + "/admin/console.css";
  const asked = [["gzip, deflate, br", "br"], ["gzip", "gzip"],
                 ["br;q=0, gzip", "gzip"], ["gzip;q=0", ""],
                 ["*", "br"], ["*, br;q=0", "gzip"], ["", ""],
                 ["identity", ""]];
  for (const pair of asked) {
    const r = await rawGet(css, pair[0]);
    check("Accept-Encoding " + JSON.stringify(pair[0]) + " is sent " +
          (pair[1] || "plain"), function () {
      assert.strictEqual(r.status, 200);
      assert.strictEqual(r.coding, pair[1]);
    });
  }
  for (const file of ["/admin/console.js", "/admin/console.css",
                      "/admin/users"]) {
    const plain = await rawGet(base + file, null);
    const br = await rawGet(base + file, "gzip, deflate, br");
    const gz = await rawGet(base + file, "gzip");
    check(file + " is brotli or gzip where asked and plain otherwise, the " +
          "same bytes each way, with Vary: Accept-Encoding", function () {
      assert.strictEqual(plain.status, 200);
      assert.strictEqual(plain.coding, "");
      assert.strictEqual(br.coding, "br");
      assert.strictEqual(gz.coding, "gzip");
      assert.ok(br.plain === plain.plain && gz.plain === plain.plain,
                "the decoded bytes differ");
      assert.ok(br.size < plain.size && gz.size < plain.size,
                plain.size + " plain, " + br.size + " br, " + gz.size +
                " gzip");
      [plain, br, gz].forEach(function (one) {
        assert.ok(/accept-encoding/i.test(one.vary), one.vary);
      });
    });
  }
  const realmPlain = await rawGet(RB + "/admin/users", null);
  const realmBr = await rawGet(RB + "/admin/users", "br");
  const wanted = 'src="/realm/' + REALM + '/admin/console.js"';
  check("a realm's document, compressed, loads the realm's own script",
        function () {
    assert.strictEqual(realmBr.coding, "br");
    assert.ok(realmBr.plain.indexOf(wanted) >= 0, wanted);
    assert.strictEqual(realmBr.plain, realmPlain.plain);
  });
  const answer = await rawGet(base + "/admin-api/me", "gzip, br",
    { authorization: "Bearer " + process.env.STS_ADMIN_API_TOKEN });
  check("an /admin-api answer is never compressed (BREACH)", function () {
    assert.strictEqual(answer.status, 200, answer.plain.slice(0, 200));
    assert.strictEqual(answer.coding, "");
  });
  const all = await rawGet(base + "/web/locales/console-all/en.json",
                           "gzip, br");
  check("every console namespace is one compressed static catalog",
        function () {
    assert.strictEqual(all.status, 200);
    assert.strictEqual(all.coding, "br");
    assert.ok(Object.keys(JSON.parse(all.plain)).length > 1000);
  });
  log.debug("Leaving compression().");
}

async function publicClient() {
  log.debug("Entering publicClient().");
  log.info("=== B. the console is a public client, DPoP-bound always ===");
  const declared = [[CONSOLE, ["oauth2", "oidc"]],
                    ["sts-user-portal", ["oauth2", "oidc"]],
                    ["sts-api-client", ["oauth2"]]];
  for (const pair of declared) {
    const app = await getJson(API + "/applications?application=" +
                              encodeURIComponent(pair[0]));
    check(pair[0] + " is seeded declared for " + pair[1].join(" and "),
          function () {
      assert.deepStrictEqual((app.allowedProtocols || []).slice().sort(),
                             pair[1]);
    });
  }
  const seeded = await getJson(API + "/applications?application=" + CONSOLE);
  check("as seeded the console is a public client", function () {
    assert.deepStrictEqual(seeded.attributes.oauthTokenEndpointAuthMethod,
                           ["none"]);
    assert.deepStrictEqual(seeded.attributes.oauthConfidential, ["FALSE"]);
  });
  await ok(API + "/applications/add", { application: CONSOLE,
    attribute: "oauthGrantType", value: "password" },
    "added the password grant to the realm's console");
  await ok(API + "/users/create", { username: WRITER, invent: false,
    attributes: { cn: "Console Writer", sn: "Writer", givenName: "Console" } },
    "created the writer");
  await ok(API + "/rbac/grant", { username: WRITER, role: "write" },
           "granted the writer the console's write role");
  await ok(API + "/applications/create", { identifier: OTHER,
    kind: "oauth2-client", name: OTHER, protocols: ["oauth2"],
    fields: { oauthClientId: [OTHER], oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["password", "refresh_token"],
              oauthRedirectUri: ["https://ccl.example.net/cb"] } },
    "created another public client");

  const key = dpopKey();
  const tokenUrl = RB + "/oauth2/token";
  const before = await codeCount(API, "STS-OAUTH-0943");
  const bare = await passwordGrant(CONSOLE, {});
  const grew = await codeGrew(API, "STS-OAUTH-0943", before);
  check("a token request from the console with no DPoP proof is refused " +
        "whole, invalid_dpop_proof, recorded as STS-OAUTH-0943", function () {
    assert.strictEqual(bare.status, 400, bare.raw.slice(0, 300));
    assert.strictEqual(bare.body.error, "invalid_dpop_proof");
    assert.ok(!bare.body.access_token);
    assert.strictEqual(grew, 1, "STS-OAUTH-0943 rows grew by " + grew);
  });
  check("and the refusal carries no error code on the wire", function () {
    assert.ok(bare.raw.indexOf("STS-") < 0, bare.raw.slice(0, 300));
  });
  const bound = await passwordGrant(CONSOLE,
                                    { DPoP: key.proof("POST", tokenUrl) });
  const jkt = ((claimsOf(bound.body && bound.body.access_token).cnf) || {})
    .jkt || "";
  check("with a proof it is a DPoP token set whose access token carries " +
        "the key's thumbprint", function () {
    assert.strictEqual(bound.status, 200, bound.raw.slice(0, 300));
    assert.strictEqual(String(bound.body.token_type).toLowerCase(), "dpop");
    assert.ok(jkt, "no cnf.jkt");
    assert.ok(bound.body.refresh_token, "no refresh token");
  });
  const unproved = await tokenRequest({ grant_type: "refresh_token",
    refresh_token: bound.body.refresh_token, client_id: CONSOLE });
  check("its refresh token redeemed with no proof is refused", function () {
    assert.strictEqual(unproved.status, 400, unproved.raw.slice(0, 300));
    assert.ok(!unproved.body.access_token);
  });
  const renewed = await tokenRequest({ grant_type: "refresh_token",
    refresh_token: bound.body.refresh_token, client_id: CONSOLE },
    { DPoP: key.proof("POST", tokenUrl) });
  check("and with its proof it is redeemed, for a token bound to the same " +
        "key", function () {
    assert.strictEqual(renewed.status, 200, renewed.raw.slice(0, 300));
    assert.strictEqual(
      (claimsOf(renewed.body.access_token).cnf || {}).jkt, jkt);
  });
  const at = bound.body.access_token;
  const asBearer = await send(API + "/me",
                              { headers: { Authorization: "Bearer " + at } });
  check("at /admin-api the bound token sent as a Bearer token is refused",
        function () {
    assert.strictEqual(asBearer.status, 401, asBearer.raw.slice(0, 300));
  });
  const proved = await send(API + "/me", { headers: {
    Authorization: "DPoP " + at, DPoP: key.proof("GET", API + "/me", at) } });
  check("and with its proof it is accepted, as the person it names",
        function () {
    assert.strictEqual(proved.status, 200, proved.raw.slice(0, 300));
    assert.strictEqual(proved.body.caller.name, WRITER);
    assert.strictEqual(proved.body.caller.clientId, CONSOLE);
    assert.ok((proved.body.scopes || []).indexOf("admin:write") >= 0,
              JSON.stringify(proved.body.scopes));
  });
  const other = await tokenRequest({ grant_type: "password",
    username: WRITER, password: "anything", client_id: OTHER,
    scope: "openid" });
  check("another public client is not touched: a bearer token with no " +
        "proof", function () {
    assert.strictEqual(other.status, 200, other.raw.slice(0, 300));
    assert.strictEqual(String(other.body.token_type).toLowerCase(),
                       "bearer");
  });
  log.debug("Leaving publicClient().");
}

async function grantTo(api, username) {
  log.debug("Entering grantTo(). " + username);
  const before = await codeCount(api, "STS-ADMIN-0920");
  const rosterBefore = await getJson(api + "/rbac");
  const r = await postJson(api + "/rbac/grant", { username: username,
                                                  role: "write" });
  const grew = await codeGrew(api, "STS-ADMIN-0920", before);
  const rosterAfter = await getJson(api + "/rbac");
  log.debug("Leaving grantTo().");
  return { r: r, grew: grew, before: rosterBefore, after: rosterAfter };
}

// The roster's grants, as names: what a grant would have written.
function rosterNames(roster) {
  log.debug("Entering rosterNames().");
  log.debug("Leaving rosterNames().");
  return JSON.stringify(roster.grants || []);
}

async function roleNeedsPerson() {
  log.debug("Entering roleNeedsPerson().");
  log.info("=== C. a console role is granted only to a person who exists ===");
  for (const where of [["the realm", API],
                       ["the default realm", base + "/admin-api"]]) {
    const got = await grantTo(where[1], GHOST);
    check(where[0] + ": a grant to a name with no entry answers 400, " +
          "noSuchPerson, naming them, recorded as STS-ADMIN-0920",
          function () {
      assert.strictEqual(got.r.status, 400, got.r.raw.slice(0, 300));
      assert.strictEqual(got.r.body.ok, false);
      assert.strictEqual(got.r.body.reason, "noSuchPerson");
      const said = (got.r.body.errors || []).join(" ") +
                   String(got.r.body.message || "");
      assert.ok(said.indexOf('"' + GHOST + '"') >= 0, said);
      assert.ok(/create the person first/i.test(said), said);
      assert.ok(said.indexOf("danglingMember") < 0, said);
      assert.strictEqual(got.grew, 1, "STS-ADMIN-0920 rows grew by " +
                         got.grew);
    });
    check(where[0] + ": the code is recorded, never sent, and nothing is " +
          "written", function () {
      assert.ok(got.r.raw.indexOf("STS-ADMIN-0920") < 0,
                got.r.raw.slice(0, 300));
      assert.ok(rosterNames(got.after).indexOf(GHOST) < 0,
                rosterNames(got.after).slice(0, 300));
      assert.strictEqual(got.after.grantCount, got.before.grantCount);
    });
  }
  const person = "ccl-person";
  const made = await ok(API + "/users/create", { username: person,
    invent: false, attributes: { cn: "Role Person", sn: "Person",
                                 givenName: "Role" } }, "created a person");
  const granted = await postJson(API + "/rbac/grant",
                                 { username: person, role: "write" });
  check("a grant to a person who exists works, and the membership " +
        "resolves to their entry", function () {
    assert.strictEqual(granted.status, 200, granted.raw.slice(0, 300));
    assert.strictEqual(granted.body.changed, true);
    assert.strictEqual(granted.body.resolves, true);
    assert.strictEqual(String(granted.body.member), String(made.dn));
  });
  log.debug("Leaving roleNeedsPerson().");
}

async function testBody() {
  log.debug("Entering testBody().");
  log.info("=== 0. a throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Console client " + STAMP },
    "created the realm");
  await compression();
  await publicClient();
  await roleNeedsPerson();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving testBody().");
}

// THE REALMS ARE REMOVED ONLY WHEN STS_TEST_REMOVE_REALMS IS "1": a private
// probe many jobs share fills its directory otherwise, while the suite's own
// rule (tests/CLAUDE.md, *No job removes a realm*) leaves them standing.
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS === "1") {
    for (const id of [REALM]) {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("Removed the realm " + id + ": " + r.status);
    }
  }
  log.debug("Leaving removeRealms().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await testBody();
  } finally {
    await removeRealms();
  }
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_console_client FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
