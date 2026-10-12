// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_vc_api_product.js
//
// ---------------------------------------------------------------------------
// THE W3C VC API AS A PRODUCT SURFACE (#598, 2026-10-12), IN A PRODUCT REALM.
//
// Until #598 `/vc-api` was a development-only test control, and the six W3C
// suite jobs reach it in throwaway DEVELOPMENT realms (`vc_suites_kit.js`,
// whose client is made by open registration, a development door). This job
// is the other half: a throwaway PRODUCT realm, a client an administrator
// made through `/admin-api` and declared the two protected scopes on, and
// the surface held to what #598 promised:
//
//   0. OFF BY DEFAULT: every route answers 501 with the VC API's error shape
//      (not Express's 404) until `vcApi.enabled` is set on the realm.
//   1. ON, a call without a token is 401; a token carrying only
//      `vc-api:verify` is 403 at the issuer.
//   2. A token carrying both issues (eddsa-jcs-2022, with a status entry)
//      and verifies; the internal `securedByEnvelope` is refused as an
//      option it does not understand (400) — it once skipped the proof
//      check — and so is an unknown one.
//   3. ITS OWN KEYS: a VC-JOSE-COSE credential it issues is a compact JWS
//      that verifies against NO key of the realm's `/oauth2/jwks` — so a
//      document a caller wrote cannot be passed off as one of this realm's
//      tokens.
//   4. The VC API's status change revokes it, and the verifier then refuses
//      it; the status-list publish is `POST /admin-api/vc-status/publish`
//      (Admin Write), and a purpose it does not publish is 400.
//   5. Turned off again, it is 501 again.
//
// OWNED HERE (local: true): this repository's oid4vc/vc_api.ts.
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
var log = bunyan.createLogger({ name: "sts_vc_api_product",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("vcapi-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                              .slice(0, 31);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const SECRET = "vc-api-" + nodeCrypto.randomBytes(12).toString("hex");
const CLIENT = "vcapi-" + STAMP.toLowerCase();
const V2 = "https://www.w3.org/ns/credentials/v2";

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
    // Not JSON — a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

function postJson(url, payload, token) {
  log.debug("Entering postJson().");
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = "Bearer " + token;
  }
  log.debug("Leaving postJson().");
  return send(url, { method: "POST", headers: headers,
                     body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.info("  " + what);
  log.debug("Leaving ok().");
  return r.body;
}

async function tokenFor(scope) {
  log.debug("Entering tokenFor().");
  const r = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_id: CLIENT, client_secret: SECRET, scope: scope }).toString() });
  assert.ok(r.body && r.body.access_token,
            "a token for " + scope + ": " + r.raw.slice(0, 300));
  log.debug("Leaving tokenFor().");
  return r.body.access_token;
}

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return r.body && Array.isArray(r.body.errors) ? r.body.errors : [];
}

// Does a compact JWS verify against an EC P-256 JWK?
function verifiesWith(jws, jwk) {
  log.debug("Entering verifiesWith().");
  const parts = String(jws).split(".");
  let good = false;
  try {
    const key = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    good = nodeCrypto.verify("sha256",
      Buffer.from(parts[0] + "." + parts[1]),
      { key: key, dsaEncoding: "ieee-p1363" },
      Buffer.from(parts[2], "base64url"));
  } catch (e) {
    log.debug("Caught in verifiesWith(): " + ((e && e.message) || e));
    // A key that is not a P-256 public key verifies nothing.
    good = false;
  }
  log.debug("Leaving verifiesWith(). " + good);
  return good;
}

async function setEnabled(value) {
  log.debug("Entering setEnabled(). " + value);
  await ok(realmApi + "/config/set", { key: "vcApi.enabled", value: value },
           "set vcApi.enabled to " + value + " in " + REALM);
  log.debug("Leaving setEnabled().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway product realm " + REALM +
           ", the VC API off ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "VC API " + STAMP,
    overrides: { "global.mode": "product" } }, "created the realm");
  const offIssuers = await send(realmBase + "/vc-api/issuers");
  const offVerify = await postJson(realmBase + "/vc-api/credentials/verify",
                                   { verifiableCredential: {} });
  check("off by default: every route answers 501 with the VC API's error " +
        "shape, not Express's 404", function () {
    assert.strictEqual(offIssuers.status, 501, offIssuers.raw.slice(0, 300));
    assert.strictEqual(offVerify.status, 501, offVerify.raw.slice(0, 300));
    assert.ok(/vcApi\.enabled/.test(JSON.stringify(errorsOf(offVerify))),
              offVerify.raw.slice(0, 300));
  });

  log.info("=== 1. on: the token, in product mode ===");
  await setEnabled(true);
  await ok(realmApi + "/applications/create", { identifier: CLIENT,
    kind: "oauth2-client", name: CLIENT, protocols: ["oauth2"],
    // The VC API's two scopes are protected: issued only to a client an
    // administrator declared them on (#110).
    fields: { oauthClientId: [CLIENT], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthAllowedScope: ["vc-api:issue", "vc-api:verify"],
              oauthGrantType: ["client_credentials"] } },
    "created the coordinator's application");
  const anonymous = await postJson(realmBase + "/vc-api/credentials/verify",
                                   { verifiableCredential: {} });
  check("without a token it is 401", function () {
    assert.strictEqual(anonymous.status, 401, anonymous.raw.slice(0, 300));
  });
  const verifyOnly = await tokenFor("vc-api:verify");
  const narrow = await send(realmBase + "/vc-api/issuers",
    { headers: { Authorization: "Bearer " + verifyOnly } });
  check("a token carrying only vc-api:verify is 403 at the issuer",
        function () {
    assert.strictEqual(narrow.status, 403, narrow.raw.slice(0, 300));
  });

  log.info("=== 2. issue and verify ===");
  const token = await tokenFor("vc-api:issue vc-api:verify");
  const listed = await send(realmBase + "/vc-api/issuers",
    { headers: { Authorization: "Bearer " + token } });
  assert.strictEqual(listed.status, 200, listed.raw.slice(0, 300));
  const byName = {};
  listed.body.issuers.forEach(function (one) {
    byName[one.name] = one;
  });
  const jcs = byName["eddsa-jcs-2022"];
  const issued = await postJson(jcs.endpoint, { credential: {
    "@context": [V2], id: "urn:uuid:" + nodeCrypto.randomUUID(),
    type: ["VerifiableCredential"], issuer: jcs.id,
    credentialSubject: { id: "did:example:subject" } },
    options: { credentialStatus: { type: "BitstringStatusListEntry",
                                   statusPurpose: "revocation" } } }, token);
  check("a token carrying vc-api:issue issues an eddsa-jcs-2022 credential " +
        "with a revocation entry", function () {
    assert.strictEqual(issued.status, 201, issued.raw.slice(0, 400));
    assert.ok(issued.body.verifiableCredential.proof,
              issued.raw.slice(0, 400));
  });
  const vc = issued.body.verifiableCredential;
  const verified = await postJson(realmBase + "/vc-api/credentials/verify",
    { verifiableCredential: vc,
      options: { checks: ["proof", "credentialStatus"] } }, token);
  check("and it verifies, status included", function () {
    assert.strictEqual(verified.status, 200, verified.raw.slice(0, 400));
    assert.strictEqual(verified.body.verified, true);
  });
  const unsigned = Object.assign({}, vc);
  delete unsigned.proof;
  const bypass = await postJson(realmBase + "/vc-api/credentials/verify",
    { verifiableCredential: unsigned,
      options: { securedByEnvelope: true } }, token);
  check("securedByEnvelope is not an option: 400, and the proof check " +
        "cannot be skipped", function () {
    assert.strictEqual(bypass.status, 400, bypass.raw.slice(0, 300));
    assert.ok(/securedByEnvelope/.test(bypass.raw), bypass.raw.slice(0, 300));
  });
  const bare = await postJson(realmBase + "/vc-api/credentials/verify",
    { verifiableCredential: unsigned }, token);
  check("an unsigned credential does not verify", function () {
    assert.strictEqual(bare.status, 400, bare.raw.slice(0, 300));
    assert.strictEqual(bare.body.verified, false);
  });
  const unknown = await postJson(jcs.endpoint, { credential: unsigned,
    options: { frobnicate: true } }, token);
  check("an option the issuer does not understand is 400", function () {
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
  });

  log.info("=== 3. its own keys ===");
  const jose = byName["jose-p256"];
  const enveloped = await postJson(jose.endpoint, { credential: {
    "@context": [V2], type: ["VerifiableCredential"], issuer: jose.id,
    credentialSubject: { id: "did:example:subject" } } }, token);
  assert.strictEqual(enveloped.status, 201, enveloped.raw.slice(0, 400));
  const envelopeId = String(enveloped.body.verifiableCredential.id || "");
  const jws = envelopeId.slice(envelopeId.indexOf(",") + 1);
  const jwks = await send(realmBase + "/oauth2/jwks");
  assert.strictEqual(jwks.status, 200, jwks.raw.slice(0, 300));
  const p256 = (jwks.body.keys || []).filter(function (k) {
    return k.kty === "EC" && k.crv === "P-256";
  });
  check("a VC-JOSE-COSE credential verifies against no key of the realm's " +
        "JWKS: the VC API signs with keys of its own", function () {
    assert.ok(jws.split(".").length === 3, envelopeId.slice(0, 200));
    assert.ok(p256.length > 0, "the JWKS publishes a P-256 key");
    p256.forEach(function (k) {
      assert.ok(!verifiesWith(jws, k), "the JWKS key " + k.kid +
                " verifies a document the VC API signed");
    });
  });

  log.info("=== 4. status, and the publish on /admin-api ===");
  const revoked = await postJson(realmBase + "/vc-api/credentials/status",
    { credentialId: vc.id, credentialStatus: {
      type: "BitstringStatusListEntry", statusPurpose: "revocation" } },
    token);
  check("the VC API's status change revokes it", function () {
    assert.strictEqual(revoked.status, 200, revoked.raw.slice(0, 300));
  });
  const published = await postJson(realmApi + "/vc-status/publish",
                                   { purpose: "revocation" });
  check("the status-list publish is an /admin-api act", function () {
    assert.strictEqual(published.status, 200, published.raw.slice(0, 300));
    assert.strictEqual(published.body.purpose, "revocation");
  });
  const wrongPurpose = await postJson(realmApi + "/vc-status/publish",
                                      { purpose: "message" });
  check("and a purpose this realm does not publish is 400", function () {
    assert.strictEqual(wrongPurpose.status, 400,
                       wrongPurpose.raw.slice(0, 300));
  });
  const after = await postJson(realmBase + "/vc-api/credentials/verify",
    { verifiableCredential: vc,
      options: { checks: ["proof", "credentialStatus"] } }, token);
  check("the verifier refuses the revoked credential", function () {
    assert.strictEqual(after.status, 400, after.raw.slice(0, 300));
    assert.strictEqual(after.body.verified, false);
  });
  const oldHook = await postJson(realmBase +
    "/oid4vci/status-lists/bitstring/revocation/publish", {}, token);
  check("the old publish hook beside the list is gone", function () {
    assert.ok(oldHook.status === 404 || oldHook.status === 405,
              oldHook.status + " " + oldHook.raw.slice(0, 200));
  });

  log.info("=== 5. off again ===");
  await setEnabled(false);
  const offAgain = await send(realmBase + "/vc-api/issuers",
    { headers: { Authorization: "Bearer " + token } });
  check("turned off, it is 501 again whatever the token", function () {
    assert.strictEqual(offAgain.status, 501, offAgain.raw.slice(0, 300));
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_vc_api_product FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
