// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_refresh_token_encryption.js
//
// ---------------------------------------------------------------------------
// EVERY REFRESH TOKEN IS A SIGNED JWT ENCRYPTED TO ITS OWN REALM, OVER THE
// WIRE.
//
// D12 (#444): carries over section 6 of `tests/refresh_token_encryption.js`
// and the part of sections 3 and 4 a client can see, in two throwaway
// realms, through the token, introspection and revocation endpoints. Codes
// are read off `/admin-api/audit`:
//
//   1. the token endpoint hands out a refresh token that is a five-part JWE
//      under A256KW / A256GCM by default, beside a plain JWS access token;
//   2. introspection opens it: active, a refresh_token, the right person;
//   3. the refresh grant redeems it and hands back another JWE;
//   4. a signed JWT presented as a refresh token (the access token) is
//      invalid_grant and inactive at introspection (STS-OAUTH-0237, an
//      unencrypted refresh token), a tampered JWE and five parts that are no
//      JWE are invalid_grant (STS-OAUTH-0238);
//   5. a refresh token minted in one realm does not open in another, and
//      redeems in its own;
//   6. a change of algorithm strands no token: sealed under RSA-OAEP-256,
//      the setting put back, it still redeems;
//   7. revocation reads an encrypted refresh token: once revoked it no
//      longer redeems;
//   8. PBES2 at the setting is refused at the write, so STS-OAUTH-0240 (a
//      seal under PBES2) is unreachable over the wire.
//
// NOT carried, and why (class (d)): section 1 (the settings table against
// crypto.js's JWE tables, two source tables), section 2 (all sixteen by six
// pairs sealing and opening: a library loop; 6 drives the default and one
// other through the endpoints), the derived keys' independence, section 5
// (the keys serialised with the key set and backfilled — the keystore), and
// STS-OAUTH-0239 (a JWE whose content is not a signed JWT needs the realm's
// own key to make).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

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
var log = bunyan.createLogger({ name: "sts_refresh_token_encryption",
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
    // Not JSON — a PEM chain or an empty answer; the caller reads `raw`.
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

function setting(realm, key, value) {
  log.debug("Entering setting(). " + realm + " " + key + "=" + value);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: realm, key: key,
    value: String(value) }, "set " + key + " on " + realm);
}

function headerOf(token) {
  log.debug("Entering headerOf().");
  const h = JSON.parse(Buffer.from(String(token).split(".")[0], "base64url")
    .toString("utf8"));
  log.debug("Leaving headerOf().");
  return h;
}

function pemsIn(text) {
  log.debug("Entering pemsIn().");
  const found = String(text).match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  log.debug("Leaving pemsIn().");
  return found;
}

function b64Of(pem) {
  log.debug("Entering b64Of().");
  log.debug("Leaving b64Of().");
  return String(pem).replace(/-----[^-]+-----|\s/g, "");
}

function pemOfB64(b64) {
  log.debug("Entering pemOfB64().");
  log.debug("Leaving pemOfB64().");
  return "-----BEGIN CERTIFICATE-----\n" +
         String(b64).match(/.{1,64}/g).join("\n") +
         "\n-----END CERTIFICATE-----\n";
}

const REALM = "rte-" + STAMP;
const OTHER = "rteo-" + STAMP;
const CREATED = [];
const SECRET = "rte-" + STAMP + "-0123456789abcdef-secret";
const PERSON = "rte-" + STAMP;

async function realm(id) {
  log.debug("Entering realm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Refresh JWE " + STAMP },
    "created the realm " + id);
  CREATED.push(id);
  // Development is what this job asserts; a product stack's realms would
  // otherwise inherit the process's mode (and refuse the password grant).
  await setting(id, "global.mode", "development");
  const rb = base + "/realm/" + id;
  await ok(rb + "/admin-api/users/create", { username: PERSON,
    invent: false, credential: "password", password: SECRET,
    attributes: { cn: "RTE " + PERSON, givenName: "RTE", sn: PERSON,
                  mail: PERSON + "@rte.test" } }, "created " + PERSON);
  await ok(rb + "/admin-api/applications/create", { identifier: "rte-c",
    name: "rte-c", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: ["rte-c"], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["password", "refresh_token"] } },
    "registered rte-c");
  log.debug("Leaving realm().");
}

function form(realmId, path, fields) {
  log.debug("Entering form(). " + path);
  log.debug("Leaving form().");
  return send(base + "/realm/" + realmId + path, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(Object.assign({ client_id: "rte-c",
      client_secret: SECRET }, fields)).toString() });
}

function issue(realmId) {
  log.debug("Entering issue().");
  log.debug("Leaving issue().");
  return form(realmId, "/oauth2/token", { grant_type: "password",
    username: PERSON, password: SECRET, scope: "openid offline_access" });
}

function redeem(realmId, token) {
  log.debug("Entering redeem().");
  log.debug("Leaving redeem().");
  return form(realmId, "/oauth2/token", { grant_type: "refresh_token",
    refresh_token: token });
}

async function codeCount(realmId, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(base + "/realm/" + realmId +
                       "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function rose(realmId, code, before) {
  log.debug("Entering rose(). " + code);
  let n = await codeCount(realmId, code);
  for (let i = 0; i < 20 && n <= before; i += 1) {
    await sleep(150);
    n = await codeCount(realmId, code);
  }
  log.debug("Leaving rose(). " + n);
  return n > before;
}

async function test() {
  log.debug("Entering test().");
  await realm(REALM);
  await realm(OTHER);

  log.info("=== 1. a JWE ===");
  const r = await issue(REALM);
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const refresh = r.body.refresh_token;
  check("1a. the token endpoint hands out a refresh token that is a " +
        "five-part JWE", function () {
    assert.strictEqual(String(refresh).split(".").length, 5);
  });
  check("1b. under A256KW and A256GCM by default, typed as a nested JWT",
        function () {
    const h = headerOf(refresh);
    assert.strictEqual(h.alg, "A256KW", JSON.stringify(h));
    assert.strictEqual(h.enc, "A256GCM", JSON.stringify(h));
    assert.ok(h.kid, JSON.stringify(h));
  });
  check("1c. and the access token beside it is a plain JWS", function () {
    assert.strictEqual(String(r.body.access_token).split(".").length, 3);
  });

  log.info("=== 2. introspection ===");
  const ins = await form(REALM, "/oauth2/introspect", { token: refresh });
  check("2. introspection opens it: active, a refresh_token, the right " +
        "person", function () {
    assert.strictEqual(ins.status, 200, ins.raw.slice(0, 300));
    assert.strictEqual(ins.body.active, true, ins.raw.slice(0, 300));
    assert.strictEqual(ins.body.token_type, "refresh_token");
    assert.strictEqual(ins.body.username, PERSON);
  });

  log.info("=== 3. the refresh grant ===");
  const redeemed = await redeem(REALM, refresh);
  const next = redeemed.body && redeemed.body.refresh_token;
  check("3a. the refresh grant decrypts it and issues", function () {
    assert.strictEqual(redeemed.status, 200, redeemed.raw.slice(0, 300));
    assert.ok(redeemed.body.access_token);
  });
  check("3b. and the refresh token it hands back is encrypted too",
        function () {
    assert.strictEqual(String(next).split(".").length, 5);
    assert.notStrictEqual(next, refresh);
  });

  log.info("=== 4. the refusals ===");
  const c237 = await codeCount(REALM, "STS-OAUTH-0237");
  const signed = await redeem(REALM, r.body.access_token);
  check("4a. a signed JWT presented as a refresh token is invalid_grant, " +
        "and no code is sent", function () {
    assert.strictEqual(signed.status, 400, signed.raw.slice(0, 300));
    assert.strictEqual(signed.body.error, "invalid_grant");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(signed.raw));
  });
  const recorded237 = await rose(REALM, "STS-OAUTH-0237", c237);
  check("4b. recorded as an unencrypted refresh token (STS-OAUTH-0237)",
        function () {
    assert.ok(recorded237);
  });
  const signedIns = await form(REALM, "/oauth2/introspect", {
    token: r.body.access_token, token_type_hint: "refresh_token" });
  check("4c. introspection hinted refresh_token does not call it an active " +
        "refresh token", function () {
    assert.strictEqual(signedIns.status, 200);
    assert.ok(signedIns.body.active === false ||
              signedIns.body.token_type !== "refresh_token",
              signedIns.raw.slice(0, 300));
  });
  const c238 = await codeCount(REALM, "STS-OAUTH-0238");
  const parts = String(next).split(".");
  parts[3] = Buffer.from("not the ciphertext at all").toString("base64url");
  const tampered = await redeem(REALM, parts.join("."));
  const garbage = await redeem(REALM, "not.a.token.at.all");
  check("4d. a tampered JWE and five parts that are no JWE are " +
        "invalid_grant", function () {
    assert.strictEqual(tampered.status, 400, tampered.raw.slice(0, 300));
    assert.strictEqual(tampered.body.error, "invalid_grant");
    assert.strictEqual(garbage.status, 400, garbage.raw.slice(0, 300));
    assert.strictEqual(garbage.body.error, "invalid_grant");
  });
  const recorded238 = await rose(REALM, "STS-OAUTH-0238", c238 + 1);
  check("4e. both recorded STS-OAUTH-0238", function () {
    assert.ok(recorded238);
  });

  log.info("=== 5. per realm ===");
  const other = await issue(OTHER);
  const otherRefresh = other.body.refresh_token;
  const across = await redeem(REALM, otherRefresh);
  check("5a. a refresh token minted in another realm does not open in this " +
        "one", function () {
    assert.strictEqual(across.status, 400, across.raw.slice(0, 300));
    assert.strictEqual(across.body.error, "invalid_grant");
  });
  const home = await redeem(OTHER, otherRefresh);
  check("5b. while it redeems in the realm that minted it", function () {
    assert.strictEqual(home.status, 200, home.raw.slice(0, 300));
  });

  log.info("=== 6. a change of algorithm strands nothing ===");
  await setting(REALM, "oauth2.refreshTokenEncryptionAlg", "RSA-OAEP-256");
  const underRsa = (await issue(REALM)).body.refresh_token;
  check("6a. a token sealed after the change names RSA-OAEP-256",
        function () {
    assert.strictEqual(headerOf(underRsa).alg, "RSA-OAEP-256");
  });
  await ok(base + "/realm/" + REALM + "/admin-api/config/reset",
           { key: "oauth2.refreshTokenEncryptionAlg" }, "reset the alg");
  const afterReset = (await issue(REALM)).body.refresh_token;
  const stillRedeems = await redeem(REALM, underRsa);
  check("6b. the setting put back, new tokens are A256KW again and the " +
        "RSA-OAEP-256 one still redeems", function () {
    assert.strictEqual(headerOf(afterReset).alg, "A256KW");
    assert.strictEqual(stillRedeems.status, 200,
                       stillRedeems.raw.slice(0, 300));
  });

  log.info("=== 7. revocation ===");
  const fresh = (await issue(REALM)).body.refresh_token;
  const rev = await form(REALM, "/oauth2/revoke", { token: fresh });
  const revoked = await redeem(REALM, fresh);
  check("7. revocation reads an encrypted refresh token: once revoked it no " +
        "longer redeems", function () {
    assert.strictEqual(rev.status, 200, rev.raw.slice(0, 300));
    assert.strictEqual(revoked.status, 400, revoked.raw.slice(0, 300));
  });

  log.info("=== 8. PBES2 ===");
  const pbes2 = await postJson(base + "/admin-api/realms/set", { id: REALM,
    key: "oauth2.refreshTokenEncryptionAlg", value: "PBES2-HS256+A128KW" });
  check("8. PBES2 is not a refresh-token algorithm: refused at the write",
        function () {
    assert.strictEqual(pbes2.status, 400, pbes2.raw.slice(0, 300));
  });

  assert.ok(checks >= 17, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
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
  for (const id of CREATED) {
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
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.warn("could not remove the realms: " + e.message);
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). failed");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
