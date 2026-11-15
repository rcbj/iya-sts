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
//
// D12 (#444) EXTENDS IT with what a client sees of `tests/signature_policy.js`
// (sections G-I): the list write rules by code off `/admin-api/audit`
// (STS-KEYS-0189, 0190, 0192, 0193); what an access token is signed with by
// default, under a list, under keys.pqcOnly and for a setting naming EdDSA; a
// post-quantum ID Token algorithm registrable by default; and, at a PRODUCT
// realm's token endpoint (development checks no client credential), an
// ML-DSA-44 private_key_jwt assertion accepted with keys.postQuantumSigning
// on and refused with it off. Two things are PINNED rather than asserted as
// the in-process file states them, and both are Node findings: the refusal
// is recorded STS-OAUTH-0007 (the client-authentication code) and never
// STS-KEYS-0157, and an ES256 assertion is still ACCEPTED under
// keys.acceptedSigningAlgorithms=RS256 although discovery then publishes
// RS256 alone for token_endpoint_auth (STS-KEYS-0179 is never recorded).
// NOT carried, and why: the COSE, XML, X.509 and Data Integrity doors and
// the HTTP message-signature door are owed by the families that sign and
// verify those (FAPI HTTP signatures in this phase; phases 6, 7 and 9);
// signJwt()'s own refusals, the effective lists' order and the registry are
// library answers (d); STS-KEYS-0194 cannot be reached, because
// tls.signatureAlgorithms is restart-only and a live write is refused before
// its rule.
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
const PRODUCT = "sigpp-" + REALM.slice(-20);
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

// ---- D12 (#444): tests/signature_policy.js over the wire -----------------
const nodeCrypto = require("crypto");
const mldsa = require("@noble/post-quantum/ml-dsa.js");
const SECRET = "sigpol-" + REALM.slice(-12) + "-0123456789abcdef-secret";

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(value).toString("base64url");
}

function algOf(token) {
  log.debug("Entering algOf().");
  const alg = JSON.parse(Buffer.from(String(token).split(".")[0],
                                     "base64url").toString("utf8")).alg;
  log.debug("Leaving algOf(). " + alg);
  return alg;
}

async function codeCount(realmBaseUrl, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(realmBaseUrl + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.json && r.json.matched) || 0);
}

// A write refused, and the code it is recorded under: the audit count of the
// code rises by one, and the answer names no code.
async function refusedWrite(key, value, code, what) {
  log.debug("Entering refusedWrite(). " + key);
  const before = await codeCount(realmBase, code);
  const r = await post(realmApi + "/config/set", { key: key,
                                                   value: String(value) });
  let after = await codeCount(realmBase, code);
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
    after = await codeCount(realmBase, code);
  }
  check(what + " (" + code + ")", function () {
    assert.strictEqual(r.status, 400, r.text.slice(0, 300));
    assert.strictEqual(r.json.ok, false);
    assert.ok(after > before, code + " rows " + before + " -> " + after);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.text), r.text.slice(0, 300));
  });
  log.debug("Leaving refusedWrite().");
}

async function client(realmApiUrl, id, extra) {
  log.debug("Entering client(). " + id);
  const r = await post(realmApiUrl + "/applications/create", {
    identifier: id, name: id, protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: [id], oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthGrantType: ["client_credentials"] }, extra || {}) });
  assert.strictEqual(r.status, 200, "registered " + id + ": " +
                     r.text.slice(0, 300));
  log.debug("Leaving client().");
}

async function accessTokenAlg(id) {
  log.debug("Entering accessTokenAlg(). " + id);
  const r = await send(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_id: id || "sp-cc", client_secret: SECRET }).toString() });
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving accessTokenAlg().");
  return algOf(r.json.access_token);
}

async function d12Sections() {
  log.debug("Entering d12Sections().");
  await client(realmApi, "sp-cc");

  log.info("=== G. the write rules, by code ===");
  await refusedWrite("cose.algorithms", "ES256,ES256", "STS-KEYS-0189",
                     "G1. a list may not name an algorithm twice");
  await refusedWrite("keys.acceptedSigningAlgorithms", "ES256",
                     "STS-KEYS-0190", "G2. an accept list must hold what " +
                     "the realm signs with");
  const g3 = await post(realmApi + "/config/set", {
    key: "keys.acceptedSigningAlgorithms", value: "RS256,ES256" });
  check("G3. one that does is taken", function () {
    assert.strictEqual(g3.status, 200, g3.text.slice(0, 300));
  });
  await reset("keys.acceptedSigningAlgorithms");
  await setting("keys.signingAlgorithms", "PS256,RS256");
  await refusedWrite("keys.acceptedSigningAlgorithms", "RS256",
                     "STS-KEYS-0190", "G4. and what it signs with is the " +
                     "configured sign list, where one is set");
  await refusedWrite("oauth2.signedMetadataAlgorithm", "ES256",
                     "STS-KEYS-0192", "G5. a chosen algorithm must be " +
                     "within its list");
  const g6 = await post(realmApi + "/config/set", {
    key: "oauth2.signedMetadataAlgorithm", value: "PS256" });
  check("G6. one that is, is taken", function () {
    assert.strictEqual(g6.status, 200, g6.text.slice(0, 300));
  });
  await reset("oauth2.signedMetadataAlgorithm");
  await reset("keys.signingAlgorithms");
  await refusedWrite("saml.signatureAlgorithms", "RS384", "STS-KEYS-0192",
                     "G7. an XML list may not leave out the chosen XML " +
                     "algorithm");
  await setting("saml.signatureAlgorithms", "RS256,RS512");
  await refusedWrite("saml.signatureAlgorithm", "rsa-sha384",
                     "STS-KEYS-0192", "G8. saml.signatureAlgorithm stays " +
                     "within its list");
  const g9 = await post(realmApi + "/config/set", {
    key: "saml.signatureAlgorithm", value: "rsa-sha512" });
  check("G9. and may name what is in it", function () {
    assert.strictEqual(g9.status, 200, g9.text.slice(0, 300));
  });
  await reset("saml.signatureAlgorithm");
  await reset("saml.signatureAlgorithms");
  await setting("keys.postQuantumSigning", false);
  await refusedWrite("keys.pqcOnly", true, "STS-KEYS-0193",
                     "G10. pqcOnly cannot go on with post-quantum signing off");
  await reset("keys.postQuantumSigning");
  await setting("keys.pqcOnly", true);
  await refusedWrite("keys.postQuantumSigning", false, "STS-KEYS-0193",
                     "G11. nor can post-quantum signing go off under it");
  await reset("keys.pqcOnly");

  log.info("=== H. what an access token is signed with ===");
  const plain = await accessTokenAlg();
  check("H1. RS256 by default", function () {
    assert.strictEqual(plain, "RS256");
  });
  await setting("keys.signingAlgorithms", "PS256,RS256");
  const listed = await accessTokenAlg();
  check("H2. a list's first usable element is the default: PS256",
        function () {
    assert.strictEqual(listed, "PS256");
  });
  await reset("keys.signingAlgorithms");
  await setting("oauth2.accessTokenSigningAlg", "ES256");
  await setting("keys.signingAlgorithms", "PS256,RS256");
  const fellBack = await accessTokenAlg();
  check("H3. a setting naming an algorithm the list leaves out signs with " +
        "the list's first instead", function () {
    assert.strictEqual(fellBack, "PS256");
  });
  await reset("keys.signingAlgorithms");
  await reset("oauth2.accessTokenSigningAlg");
  await setting("oauth2.accessTokenSigningAlg", "EdDSA");
  const eddsa = await accessTokenAlg();
  check("H4. EdDSA is not signable by default (#1292): a setting naming it " +
        "signs RS256", function () {
    assert.strictEqual(eddsa, "RS256");
  });
  await reset("oauth2.accessTokenSigningAlg");
  await setting("keys.pqcOnly", true);
  const pqcOnly = await accessTokenAlg();
  check("H5. under keys.pqcOnly the default is post-quantum, ML-DSA-44",
        function () {
    assert.strictEqual(pqcOnly, "ML-DSA-44");
  });
  await setting("keys.signingAlgorithms", "ML-DSA-87,ML-DSA-65,RS256");
  const pqList = await accessTokenAlg();
  check("H6. and a list's first usable element is the default under it",
        function () {
    assert.strictEqual(pqList, "ML-DSA-87");
  });
  await reset("keys.signingAlgorithms");
  await reset("keys.pqcOnly");
  const h7 = await post(realmApi + "/applications/create", {
    identifier: "sp-pq", name: "sp-pq", protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: ["sp-pq"], oauthClientSecret: SECRET,
              oauthGrantType: ["client_credentials"],
              oauthIdTokenSignedResponseAlg: "ML-DSA-65" } });
  check("H7. a post-quantum ID Token algorithm is registrable by default",
        function () {
    assert.strictEqual(h7.status, 200, h7.text.slice(0, 300));
  });

  log.info("=== I. the token endpoint of a product realm ===");
  const made = await post(api + "/realms/create", { id: PRODUCT,
    domain: PRODUCT + ".example.net", name: "Signature policy product" });
  assert.strictEqual(made.status, 200, made.text.slice(0, 300));
  const pApi = base + "/realm/" + PRODUCT + "/admin-api";
  const pBase = base + "/realm/" + PRODUCT;
  const mode = await post(api + "/realms/set", { id: PRODUCT,
    key: "global.mode", value: "product" });
  assert.strictEqual(mode.status, 200, mode.text.slice(0, 300));
  const pq = mldsa.ml_dsa44.keygen(nodeCrypto.randomBytes(32));
  const ec = nodeCrypto.generateKeyPairSync("ec",
                                            { namedCurve: "prime256v1" });
  const pqJwk = { kty: "AKP", alg: "ML-DSA-44", use: "sig", kid: "pq1",
                  pub: b64u(pq.publicKey) };
  const ecJwk = Object.assign(ec.publicKey.export({ format: "jwk" }),
                              { kid: "ec1", use: "sig", alg: "ES256" });
  for (const one of [["pkj-pq", pqJwk], ["pkj-ec", ecJwk]]) {
    const r = await post(pApi + "/applications/create", {
      identifier: one[0], name: one[0], protocols: ["oauth2"],
      fields: { oauthClientId: [one[0]],
                oauthTokenEndpointAuthMethod: "private_key_jwt",
                oauthGrantType: ["client_credentials"],
                oauthJwks: JSON.stringify({ keys: [one[1]] }) } });
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  }
  const tokenUrl = pBase + "/oauth2/token";
  const assertion = function (id, alg, kid, signer) {
    const now = Math.floor(Date.now() / 1000);
    const h = b64u(JSON.stringify({ alg: alg, kid: kid, typ: "JWT" }));
    const p = b64u(JSON.stringify({ iss: id, sub: id, aud: tokenUrl,
      iat: now, exp: now + 300,
      jti: id + "-" + nodeCrypto.randomBytes(8).toString("hex") }));
    return h + "." + p + "." + b64u(signer(Buffer.from(h + "." + p)));
  };
  const pqAssertion = function () {
    return assertion("pkj-pq", "ML-DSA-44", "pq1", function (m) {
      return mldsa.ml_dsa44.sign(pq.secretKey, m);
    });
  };
  const ecAssertion = function () {
    return assertion("pkj-ec", "ES256", "ec1", function (m) {
      return nodeCrypto.sign("sha256", m, { key: ec.privateKey,
                                            dsaEncoding: "ieee-p1363" });
    });
  };
  const present = function (id, jws) {
    return send(tokenUrl, { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials",
        client_id: id, client_assertion: jws, client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" })
        .toString() });
  };
  const pqOn = await present("pkj-pq", pqAssertion());
  check("I1. an ML-DSA-44 private_key_jwt assertion is accepted by default",
        function () {
    assert.strictEqual(pqOn.status, 200, pqOn.text.slice(0, 300));
  });
  const garbled = await present("pkj-pq", pqAssertion().slice(0, -8) +
                                "AAAAAAAA");
  check("I2. and a broken one is refused (the product realm checks)",
        function () {
    assert.strictEqual(garbled.status, 401, garbled.text.slice(0, 300));
  });
  const authBefore = await codeCount(pBase, "STS-OAUTH-0007");
  const keysBefore = await codeCount(pBase, "STS-KEYS-0157");
  const off = await post(api + "/realms/set", { id: PRODUCT,
    key: "keys.postQuantumSigning", value: "false" });
  assert.strictEqual(off.status, 200, off.text.slice(0, 300));
  const pqOff = await present("pkj-pq", pqAssertion());
  let authAfter = await codeCount(pBase, "STS-OAUTH-0007");
  for (let i = 0; i < 20 && authAfter <= authBefore; i += 1) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
    authAfter = await codeCount(pBase, "STS-OAUTH-0007");
  }
  check("I3. with keys.postQuantumSigning off the same assertion is refused " +
        "invalid_client, and no code is sent", function () {
    assert.strictEqual(pqOff.status, 401, pqOff.text.slice(0, 300));
    assert.strictEqual(pqOff.json.error, "invalid_client");
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(pqOff.text));
  });
  const keysAfter = await codeCount(pBase, "STS-KEYS-0157");
  check("I4. PINNED: it is recorded STS-OAUTH-0007, the client-" +
        "authentication refusal, and never STS-KEYS-0157", function () {
    assert.ok(authAfter > authBefore, authBefore + " -> " + authAfter);
    assert.strictEqual(keysAfter, keysBefore);
  });
  const ecOk = await present("pkj-ec", ecAssertion());
  check("I5. an ES256 assertion is accepted", function () {
    assert.strictEqual(ecOk.status, 200, ecOk.text.slice(0, 300));
  });
  const narrow = await post(api + "/realms/set", { id: PRODUCT,
    key: "keys.acceptedSigningAlgorithms", value: "RS256" });
  assert.strictEqual(narrow.status, 200, narrow.text.slice(0, 300));
  const pdoc = (await send(pBase + "/.well-known/openid-configuration")).json;
  check("I6. with keys.acceptedSigningAlgorithms=RS256 discovery publishes " +
        "RS256 alone for client assertions", function () {
    assert.deepStrictEqual(
      pdoc.token_endpoint_auth_signing_alg_values_supported, ["RS256"]);
  });
  const unlisted = await present("pkj-ec", ecAssertion());
  const k179 = await codeCount(pBase, "STS-KEYS-0179");
  check("I7. PINNED (a Node defect): an ES256 assertion is still accepted " +
        "there, and STS-KEYS-0179 is not recorded", function () {
    assert.strictEqual(unlisted.status, 200, unlisted.text.slice(0, 300));
    assert.strictEqual(k179, 0);
  });
  log.debug("Leaving d12Sections().");
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

  await d12Sections();

  assert.ok(checks >= 35, "only " + checks + " checks ran; a section has " +
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

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) both realms are removed at the end,
// pass or fail. A suite run leaves them standing (tests/CLAUDE.md, *No job
// removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [REALM, PRODUCT]) {
    const r = await post(api + "/realms/remove", { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

test().then(function () {
  return removeRealms();
}, function (e) {
  log.error(e.stack || e.message);
  return removeRealms().then(function () {
    process.exit(1);
  });
});
