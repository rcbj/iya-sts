// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_signature_policy_metadata.js
//
// ---------------------------------------------------------------------------
// WHAT IS PUBLISHED IS WHAT IS CONFIGURED, OVER THE WIRE (#1368, phase 5).
//
// D12 (#444): carries over `tests/signature_policy_metadata.js` into
// throwaway realms. **THE PINS ARE THAT FILE'S, COPIED BYTE FOR BYTE**: they
// were taken before phase 5 existed, from the documents an image of the
// tree answered over HTTP, and cover every `*alg_values*` list at any depth
// and every key's shape in the JWK Set, not whole documents. 1.0.0 is
// certified: a default moving is a certification question, so change a pin
// only on purpose, and in both files.
//
//   1. at the defaults, a fresh realm's RFC 8414 document, discovery and
//      OpenID4VCI issuer metadata hold every algorithm list they held before
//      phase 5, and the JWK Set the keys it held;
//   2. SAML: IdP metadata publishes algorithm support inside md:Extensions,
//      strongest first, SAML 1.1 and the WS-Federation view carry it, an
//      accept list is what it then publishes, and no weak method or HMAC is
//      advertised;
//   3. a post-quantum-first list is published first; under keys.pqcOnly the
//      JWK Set keeps the RSA key RS256 ID Tokens verify with;
//   4. no post-quantum attestation is advertised with no such attester, and
//      ML-DSA-65 is once an attester's certificate holds that key (a realm
//      whose chain is built on ML-DSA-65 lends its Intermediate);
//   5. `/crypto/metadata` has its COSE, Data Integrity, X.509, HTTP signature,
//      TLS and WebAuthn sections.
//
// NOT carried, and why: an attestation the post-quantum attester SIGNED
// getting past the signature needs that CA's private key (class (d); the
// OpenID4VCI jobs of phase 9 own a real wallet attestation), and the
// describer's rows are `sts_signature_policy.js`'s console report check.
// The classical-list, pqcOnly and accept-list documents beside these are in
// `sts_signature_policy.js` already.
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
var log = bunyan.createLogger({ name: "sts_signature_policy_metadata",
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

const REALM = "spm-" + STAMP;
const PQREALM = "spmq-" + STAMP;
const CREATED = [];

const PINS = {
  "discovery": {
    "path": "/.well-known/openid-configuration",
    "lists": 16,
    "pin": "b10c8804b9157b28e888c7c97be8163d"
  },
  "authorizationServer": {
    "path": "/.well-known/oauth-authorization-server",
    "lists": 12,
    "pin": "b48c5bfdc4f95de7a137a15c3eab659d"
  },
  "credentialIssuer": {
    "path": "/.well-known/openid-credential-issuer",
    "lists": 16,
    "pin": "254bca2e4730829edb5445152b747a22"
  }
};

const JWKS_SHAPE = [
  ["RSA", "", "sig", ""],
  ["EC", "ES256", "sig", "P-256"],
  ["EC", "ES384", "sig", "P-384"],
  ["EC", "ES512", "sig", "P-521"],
  ["EC", "ES256K", "sig", "secp256k1"],
  ["AKP", "ML-DSA-44", "sig", ""],
  ["AKP", "ML-DSA-65", "sig", ""],
  ["AKP", "ML-DSA-87", "sig", ""],
  ["AKP", "SLH-DSA-SHA2-128s", "sig", ""],
  ["AKP", "SLH-DSA-SHAKE-128s", "sig", ""],
  ["AKP", "ML-DSA-44-ES256", "sig", ""],
  ["AKP", "ML-DSA-65-ES256", "sig", ""],
  ["AKP", "ML-DSA-87-ES384", "sig", ""],
  ["AKP", "ML-DSA-44-Ed25519", "sig", ""],
  ["AKP", "ML-DSA-65-Ed25519", "sig", ""],
  ["AKP", "ML-DSA-87-Ed448", "sig", ""],
  ["RSA", "", "enc", ""],
  ["EC", "", "enc", "P-256"]
];

function lists(node, out, at) {
  log.debug("Entering lists().");
  if (Array.isArray(node)) {
    node.forEach(function (one, i) {
      lists(one, out, at + "/" + i);
    });
  } else if (node && typeof node === "object") {
    Object.keys(node).sort().forEach(function (k) {
      const v = node[k];
      if (Array.isArray(v) && /alg_values/.test(k)) {
        out.push(at + "/" + k + "=" + v.join(","));
      } else if (v && typeof v === "object") {
        lists(v, out, at + "/" + k);
      }
    });
  }
  log.debug("Leaving lists().");
  return out;
}

function shapeOf(set) {
  log.debug("Entering shapeOf().");
  log.debug("Leaving shapeOf().");
  return set.keys.map(function (k) {
    return [k.kty, k.alg || "", k.use || "", k.crv || ""];
  });
}

async function get(realm, path) {
  log.debug("Entering get(). " + path);
  const r = await send(base + "/realm/" + realm + path);
  assert.strictEqual(r.status, 200, path + " " + r.raw.slice(0, 300));
  log.debug("Leaving get().");
  return r;
}

async function makeRealm(id) {
  log.debug("Entering makeRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Signature metadata " + STAMP },
    "created the realm " + id);
  CREATED.push(id);
  // Development is what this job asserts; a product stack's realms would
  // otherwise inherit the process's mode.
  await setting(id, "global.mode", "development");
  log.debug("Leaving makeRealm().");
}

function pqAttestationAlgs(meta) {
  log.debug("Entering pqAttestationAlgs().");
  const out = [];
  Object.keys(meta.credential_configurations_supported || {})
    .forEach(function (id) {
      const types = meta.credential_configurations_supported[id]
        .proof_types_supported || {};
      ((types.attestation || {}).proof_signing_alg_values_supported || [])
        .forEach(function (alg) {
          if (/^ML-DSA/.test(alg)) {
            out.push(alg);
          }
        });
    });
  log.debug("Leaving pqAttestationAlgs().");
  return out;
}

async function test() {
  log.debug("Entering test().");
  await makeRealm(REALM);

  log.info("=== 1. at the defaults, the pins ===");
  for (const name of Object.keys(PINS)) {
    const found = lists((await get(REALM, PINS[name].path)).body, [], "");
    const pin = nodeCrypto.createHash("sha256").update(found.join("\n"))
      .digest("hex").slice(0, 32);
    check("1. " + name + ": every algorithm list is what it was before " +
          "phase 5", function () {
      assert.strictEqual(found.length, PINS[name].lists, found.join("\n"));
      assert.strictEqual(pin, PINS[name].pin, found.join("\n"));
    });
  }
  const set = (await get(REALM, "/oauth2/jwks")).body;
  check("1. the JWK Set holds the keys it held before phase 5", function () {
    assert.deepStrictEqual(shapeOf(set), JWKS_SHAPE);
  });

  log.info("=== 2. SAML ===");
  const saml = (await get(REALM, "/saml2/metadata")).raw;
  check("2a. IdP metadata publishes algorithm support by default",
        function () {
    assert.ok((saml.match(/<alg:SigningMethod /g) || []).length > 3);
    assert.ok(/<alg:DigestMethod /.test(saml));
  });
  check("2b. inside md:Extensions, where a consumer may ignore them",
        function () {
    const at = saml.indexOf("<alg:SigningMethod");
    assert.ok(at > saml.indexOf("<md:Extensions>") &&
              at < saml.indexOf("</md:Extensions>"));
  });
  check("2c. in order of preference, strongest first", function () {
    const first = saml.slice(saml.indexOf("<alg:SigningMethod"))
      .split("/>")[0];
    assert.ok(/Algorithm="[^"]*ml-dsa-87"/.test(first), first);
  });
  const saml11 = (await get(REALM, "/saml11/metadata")).raw;
  const wsfed = (await get(REALM,
    "/FederationMetadata/2007-06/FederationMetadata.xml")).raw;
  check("2d. SAML 1.1 metadata and the WS-Federation view carry them",
        function () {
    assert.ok(/<alg:SigningMethod /.test(saml11));
    assert.ok(/<alg:SigningMethod /.test(wsfed));
  });
  check("2e. no weak method and no HMAC is advertised", function () {
    assert.ok(!/rsa-sha1"|hmac-|md5/.test(saml.slice(
      saml.indexOf("<md:Extensions>"), saml.indexOf("</md:Extensions>"))));
  });
  await setting(REALM, "saml.acceptedSignatureAlgorithms", "RS256");
  const narrowed = (await get(REALM, "/saml2/metadata")).raw;
  check("2f. an accept list is what it then publishes", function () {
    assert.strictEqual((narrowed.match(/<alg:SigningMethod /g) || []).length,
                       1);
    assert.ok(/Algorithm="[^"]*rsa-sha256"\/>/.test(narrowed));
  });
  await ok(base + "/realm/" + REALM + "/admin-api/config/reset",
           { key: "saml.acceptedSignatureAlgorithms" }, "reset the list");

  log.info("=== 3. lists ===");
  await setting(REALM, "keys.signingAlgorithms", "ML-DSA-65,RS256");
  let disc = (await get(REALM, "/.well-known/openid-configuration")).body;
  check("3a. a post-quantum-first list is published first", function () {
    assert.strictEqual(disc.id_token_signing_alg_values_supported[0],
                       "ML-DSA-65", JSON.stringify(
                         disc.id_token_signing_alg_values_supported));
  });
  await ok(base + "/realm/" + REALM + "/admin-api/config/reset",
           { key: "keys.signingAlgorithms" }, "reset the list");
  await setting(REALM, "keys.pqcOnly", true);
  const pqcSet = shapeOf((await get(REALM, "/oauth2/jwks")).body);
  check("3b. under keys.pqcOnly the JWK Set keeps the RSA key RS256 ID " +
        "Tokens verify with, beside its AKP keys", function () {
    assert.ok(pqcSet.some(function (k) {
      return k[0] === "RSA" && k[2] === "sig";
    }));
    assert.ok(pqcSet.some(function (k) {
      return k[0] === "AKP";
    }));
  });
  await ok(base + "/realm/" + REALM + "/admin-api/config/reset",
           { key: "keys.pqcOnly" }, "reset pqcOnly");

  log.info("=== 4. a post-quantum attester ===");
  const meta = (await get(REALM, "/.well-known/openid-credential-issuer"))
    .body;
  check("4a. no post-quantum attestation is advertised with no such " +
        "attester", function () {
    assert.deepStrictEqual(pqAttestationAlgs(meta), []);
  });
  await makeRealm(PQREALM);
  await ok(base + "/realm/" + PQREALM + "/admin-api/pki/build",
           { keyAlg: "ml-dsa-65" }, "built a chain on ML-DSA-65");
  const der = Buffer.from(await (await fetch(base + "/pki/ca/" + PQREALM +
                                             "/intermediate.cer"))
    .arrayBuffer());
  const pem = /BEGIN CERTIFICATE/.test(der.toString("latin1"))
    ? der.toString("latin1")
    : pemOfB64(der.toString("base64"));
  await setting(REALM, "oid4vci.keyAttestationTrustedCertificates", pem);
  const withAttester = (await get(REALM,
    "/.well-known/openid-credential-issuer")).body;
  check("4b. and ML-DSA-65 is, once an attester's certificate holds that " +
        "key", function () {
    assert.ok(pqAttestationAlgs(withAttester).indexOf("ML-DSA-65") >= 0,
              JSON.stringify(pqAttestationAlgs(withAttester)));
  });
  await ok(base + "/realm/" + REALM + "/admin-api/config/reset",
           { key: "oid4vci.keyAttestationTrustedCertificates" },
           "reset the attester");

  log.info("=== 5. /crypto/metadata ===");
  const cm = (await get(REALM, "/crypto/metadata")).body;
  ["cose", "dataIntegrity", "x509", "httpsig"].forEach(function (name) {
    check("5. /crypto/metadata has a " + name + " section", function () {
      assert.ok(Array.isArray(cm.algorithms[name].accepted) &&
                cm.algorithms[name].accepted.length > 0);
    });
  });
  check("5. and the TLS and WebAuthn lists", function () {
    assert.ok(cm.algorithms.tls.signatureAlgorithms.length > 0);
    assert.ok(cm.algorithms.webauthn.offered.length > 0);
  });

  assert.ok(checks >= 19, "only " + checks + " checks ran; a section has " +
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
