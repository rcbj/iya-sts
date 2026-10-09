// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_application_ldif.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION EXPORTED TO LDIF AND IMPORTED INTO ANOTHER REALM, OVER THE
// WIRE (#546).
//
// In two throwaway realms it leaves behind:
//
//   a. an application made in the first, with a client secret, exported
//      through `POST /admin-api/applications/export-ldif`: one LDIF record,
//      the file to save beside it, and NO credential unless asked;
//   b. exported again with `credentials: true`, the secret in the clear;
//   c. that file imported into the second realm through
//      `POST /admin-api/applications/import-ldif`, where the application's
//      client secret gets a token at that realm's `/oauth2/token`;
//   d. the same file again refused (400) — an import never overwrites —
//      and so is a file carrying an attribute this registry derives.
//
// OWNED HERE (local: true): this repository's own console operations and
// management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_application_ldif",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                       .slice(0, 31);
}
const FROM = realmId("ldifa-");
const TO = realmId("ldifb-");
const APP = "ldif-app-" + STAMP.toLowerCase();
const SECRET = "ldif-546-" + String(Date.now()).slice(-8) + "-secret-value";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
  return { status: r.status, body: body, raw: raw };
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

// RFC 2849 folds a line at 76 columns, so a value is searched for in the
// unfolded text.
function unfold(ldif) {
  log.debug("Entering unfold().");
  log.debug("Leaving unfold().");
  return String(ldif || "").replace(/\r?\n /g, "");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. two throwaway realms " + FROM + " and " + TO + " ===");
  for (const id of [FROM, TO]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Application LDIF " + STAMP },
      "created the realm " + id);
  }
  const fromApi = base + "/realm/" + FROM + "/admin-api";
  const toApi = base + "/realm/" + TO + "/admin-api";
  await ok(fromApi + "/applications/create", { identifier: APP,
    kind: "oauth2-client", name: APP, protocols: ["oauth2"],
    fields: { oauthClientId: [APP], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"],
              oauthRedirectUri: ["https://ldif.example.net/cb"] } },
    "created the application");

  log.info("=== a. exported without credentials ===");
  const plain = await ok(fromApi + "/applications/export-ldif",
                         { application: APP }, "exported the application");
  check("one LDIF record naming the application, and the file to save",
        function () {
    assert.ok(/^dn: cn=/m.test(plain.ldif), plain.ldif.slice(0, 400));
    assert.strictEqual(plain.ldif.match(/^dn: /mg).length, 1);
    assert.ok(/^appIdentifier: /m.test(plain.ldif) &&
              unfold(plain.ldif).indexOf(APP) >= 0, plain.ldif.slice(0, 400));
    assert.ok(/^oauthRedirectUri: https:\/\/ldif\.example\.net\/cb$/m
      .test(plain.ldif), plain.ldif);
    const file = (plain.files || [])[0];
    assert.ok(file && /\.ldif$/.test(file.name), JSON.stringify(plain.files));
    assert.strictEqual(Buffer.from(file.base64, "base64").toString("utf8"),
                       plain.ldif);
  });
  check("by default no credential is in it, and none of what the " +
        "registry derived", function () {
    assert.strictEqual(plain.credentials, false);
    assert.ok(unfold(plain.ldif).indexOf(SECRET) < 0, "the secret leaked");
    assert.ok(!/^oauthClientSecret:/mi.test(plain.ldif), plain.ldif);
    assert.ok((plain.leftOut || []).indexOf("oauthClientSecret") >= 0,
              JSON.stringify(plain.leftOut));
    assert.ok(!/^appFirstSeen:/mi.test(plain.ldif), plain.ldif);
  });

  log.info("=== b. exported with credentials ===");
  const full = await ok(fromApi + "/applications/export-ldif",
                        { application: APP, credentials: true },
                        "exported the application with its credentials");
  check("the client secret is in it, in the clear", function () {
    assert.strictEqual(full.credentials, true);
    assert.ok(unfold(full.ldif).indexOf(SECRET) >= 0, full.ldif.slice(0, 600));
  });

  log.info("=== c. imported into the other realm ===");
  await ok(toApi + "/applications/import-ldif", { ldif: full.ldif },
           "imported the application");
  const token = await send(base + "/realm/" + TO + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
                                client_id: APP,
                                client_secret: SECRET }).toString() });
  check("its client secret gets a token in the realm it was imported into",
        function () {
    assert.strictEqual(token.status, 200, token.raw.slice(0, 400));
    assert.ok(token.body && token.body.access_token, token.raw.slice(0, 400));
  });

  log.info("=== d. the refusals ===");
  const again = await postJson(toApi + "/applications/import-ldif",
                               { ldif: full.ldif });
  check("the same identifier again is refused, never overwritten",
        function () {
    assert.strictEqual(again.status, 400, again.raw.slice(0, 400));
    assert.ok(again.body && again.body.ok === false, again.raw.slice(0, 400));
  });
  const other = full.ldif.split(APP).join(APP + "-b")
    .replace(/\n*$/, "\nappFirstSeen: 20260101000000Z\n");
  const derived = await postJson(toApi + "/applications/import-ldif",
                                 { ldif: other });
  check("a file carrying a derived attribute is refused", function () {
    assert.strictEqual(derived.status, 400, derived.raw.slice(0, 400));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_application_ldif FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
