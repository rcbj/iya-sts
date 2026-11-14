// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_signature_policy.js
//
// ---------------------------------------------------------------------------
// WHAT A REALM IS CONFIGURED TO SIGN AND ACCEPT IS WHAT IT PUBLISHES, OVER HTTP
// (#1368). It works in a throwaway trust realm, which it leaves standing, so an
// AWS target and the product mode can run it: a list is written through
// /admin-api, then discovery, the JWK Set, IdP metadata, /crypto/metadata and
// /admin-api/crypto are read back. tests/signature_policy_metadata.js holds the
// defaults; this holds the configured half, from outside the process.
// ---------------------------------------------------------------------------
const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_signature_policy",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("sigpol").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const api = base + "/admin-api";
const realmApi = realmBase + "/admin-api";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function send(url, options) {
  log.debug("Entering send().");
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON: IdP metadata is XML; the caller reads `text`.
    json = null;
  }
  log.debug("Leaving send().");
  return { status: r.status, text: text, json: json };
}

function post(url, body) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return send(url, { method: "POST",
                     headers: { "Content-Type": "application/json" },
                     body: JSON.stringify(body) });
}

async function setting(key, value) {
  log.debug("Entering setting(). " + key);
  const r = await post(realmApi + "/config/set", { key: key, value: value });
  assert.strictEqual(r.status, 200, "set " + key + ": " + r.text.slice(0, 300));
  log.debug("Leaving setting().");
}

async function reset(key) {
  log.debug("Entering reset(). " + key);
  const r = await post(realmApi + "/config/reset", { key: key });
  assert.strictEqual(r.status, 200, "reset " + key + ": " +
                     r.text.slice(0, 300));
  log.debug("Leaving reset().");
}

async function discovery() {
  log.debug("Entering discovery().");
  const r = await send(realmBase + "/.well-known/openid-configuration");
  assert.strictEqual(r.status, 200);
  log.debug("Leaving discovery().");
  return r.json;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the signature policy at " + realmBase);
  const created = await post(api + "/realms/create",
                             { id: REALM, domain: REALM + ".example.net",
                               name: "Signature policy" });
  assert.strictEqual(created.status, 200, created.text.slice(0, 300));

  await setting("keys.signingAlgorithms", "PS256,RS256");
  let doc = await discovery();
  check("a signing list is published in the order configured", function () {
    assert.deepStrictEqual(doc.id_token_signing_alg_values_supported,
                           ["PS256", "RS256"]);
  });
  let jwks = (await send(realmBase + "/oauth2/jwks")).json;
  check("the JWK Set carries the keys of that list and no others", function () {
    jwks.keys.forEach(function (k) {
      assert.ok(k.use === "enc" || k.kty === "RSA",
                "an unlisted key is published: " + (k.alg || k.kty));
    });
  });
  const refused = await post(realmApi + "/config/set",
    { key: "keys.acceptedSigningAlgorithms", value: "RS256" });
  check("an accept list may not refuse what the realm signs", function () {
    assert.notStrictEqual(refused.status, 200);
  });
  await reset("keys.signingAlgorithms");

  await setting("keys.acceptedSigningAlgorithms", "RS256,ES256");
  doc = await discovery();
  check("what the realm accepts is published as what it accepts", function () {
    assert.deepStrictEqual(
      doc.request_object_signing_alg_values_supported.filter(function (alg) {
        return alg !== "none";
      }), ["RS256", "ES256"]);
  });
  await reset("keys.acceptedSigningAlgorithms");

  await setting("keys.pqcOnly", true);
  doc = await discovery();
  check("under keys.pqcOnly RS256 stays for ID Tokens, as Discovery requires",
    function () {
      const list = doc.id_token_signing_alg_values_supported;
      assert.ok(list.indexOf("RS256") >= 0 && list.indexOf("ES256") < 0 &&
                list.indexOf("ML-DSA-65") >= 0, list.join());
    });
  check("and no other list holds a classical algorithm", function () {
    assert.ok(doc.userinfo_signing_alg_values_supported.indexOf("RS256") < 0);
  });
  jwks = (await send(realmBase + "/oauth2/jwks")).json;
  check("and the JWK Set holds no classical curve signing key", function () {
    jwks.keys.forEach(function (k) {
      assert.ok(!(k.kty === "EC" && k.use !== "enc"), k.alg);
    });
  });
  await reset("keys.pqcOnly");

  const metadata = await send(realmBase + "/saml2/metadata");
  check("IdP metadata publishes algorithm support", function () {
    assert.ok(/<alg:SigningMethod /.test(metadata.text) &&
              /<alg:DigestMethod /.test(metadata.text));
  });
  await setting("saml2.publishAlgorithmSupport", false);
  const without = await send(realmBase + "/saml2/metadata");
  check("and a setting turns that off", function () {
    assert.ok(!/alg:SigningMethod/.test(without.text));
  });
  await reset("saml2.publishAlgorithmSupport");

  await setting("cose.acceptedAlgorithms", "ES256");
  const crypto = await send(realmBase + "/crypto/metadata");
  check("/crypto/metadata publishes the COSE list as configured", function () {
    assert.strictEqual(crypto.status, 200);
    assert.deepStrictEqual(crypto.json.algorithms.cose.accepted, ["-7"]);
  });
  const report = await send(realmApi + "/crypto");
  check("the console's report says what is refused, and why", function () {
    assert.strictEqual(report.status, 200, report.text.slice(0, 200));
    const rows = report.json.signaturePolicy.surfaces.cose.rows;
    assert.ok(rows.some(function (row) {
      return !row.accepts && /cose\.acceptedAlgorithms/.test(row.acceptRefusal);
    }));
  });
  await reset("cose.acceptedAlgorithms");

  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_signature_policy")
  .description("What a realm is configured to sign and accept is what it " +
    "publishes, over HTTP.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
