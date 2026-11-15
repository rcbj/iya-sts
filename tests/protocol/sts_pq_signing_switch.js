// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_pq_signing_switch.js
//
// ---------------------------------------------------------------------------
// POST-QUANTUM JOSE SIGNING AS A PER-REALM SWITCH, OVER THE WIRE.
//
// D12 (#444): carries over `tests/pq_signing_switch.js` part B and the part
// of A a client can see, in two throwaway realms — one left at the default,
// one with `keys.postQuantumSigning` off, written through
// `/admin-api/realms/set`:
//
//   1. the row reads back on by default, and takes `false` in a realm;
//   2. the JWK Set carries AKP signing keys in the one and none in the other,
//      which keeps its classical keys with RSA first and its encryption keys
//      as they were;
//   3. RFC 8414, OpenID Connect Discovery and the OpenID4VCI issuer metadata
//      list post-quantum algorithms in the one and none in any algorithm list
//      of the other, which keeps its classical ones;
//   4. an application naming ML-DSA-44 for its ID Tokens is registered in the
//      one and refused in the other, through `/admin-api/applications/create`;
//   5. an access token from the realm that is off is classical.
//
// NOT carried, and why (class (d)): the helpers (`offeredJwsAlgs()`,
// `withoutPqSigningAlgs()`, `withoutPqSigningKeys()`) on hand-made inputs, the
// nested-object non-mutation and `signingKeyFor()` (STS-KEYS-0158) are library
// calls. The refusal of an ML-DSA signature at a door with the switch off, and
// the code it is recorded under, is `sts_signature_policy.js` section I.
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
var log = bunyan.createLogger({ name: "sts_pq_signing_switch",
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

// The JWS signature verified with node's crypto against a public key, for
// RS256 and ES256 (the two this job asks for).
function jwsVerifies(token, publicKey) {
  log.debug("Entering jwsVerifies().");
  const parts = String(token).split(".");
  const alg = headerOf(token).alg;
  const input = Buffer.from(parts[0] + "." + parts[1]);
  const sig = Buffer.from(parts[2], "base64url");
  let good = false;
  if (alg === "RS256") {
    good = nodeCrypto.verify("sha256", input, publicKey, sig);
  } else if (alg === "ES256") {
    good = nodeCrypto.verify("sha256", input,
                             { key: publicKey, dsaEncoding: "ieee-p1363" },
                             sig);
  }
  log.debug("Leaving jwsVerifies(). " + good);
  return good;
}

async function configRow(realm, key) {
  log.debug("Entering configRow(). " + key);
  const r = await send(base + "/realm/" + realm + "/admin-api/config");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  let found = null;
  const walk = function (node) {
    if (found || !node || typeof node !== "object") {
      return;
    }
    if (node.key === key && Object.prototype.hasOwnProperty.call(node,
                                                                 "value")) {
      found = node;
      return;
    }
    Object.keys(node).forEach(function (k) {
      walk(node[k]);
    });
  };
  walk(r.body);
  log.debug("Leaving configRow().");
  return found;
}

const ON = "pqon-" + STAMP;
const OFF = "pqoff-" + STAMP;
const CREATED = [];
const SECRET = "pq-switch-" + STAMP + "-0123456789abcdef-secret";
const PQ = /^(ML-DSA|SLH-DSA)/;

function pqListed(doc) {
  log.debug("Entering pqListed().");
  const out = [];
  const walk = function (node, at) {
    if (Array.isArray(node)) {
      node.forEach(function (one, i) {
        walk(one, at + "/" + i);
      });
    } else if (node && typeof node === "object") {
      Object.keys(node).forEach(function (k) {
        const v = node[k];
        if (Array.isArray(v) && /alg_values|_algs?$/.test(k)) {
          v.forEach(function (alg) {
            if (PQ.test(String(alg))) {
              out.push(at + "/" + k + "=" + alg);
            }
          });
        } else if (v && typeof v === "object") {
          walk(v, at + "/" + k);
        }
      });
    }
  };
  walk(doc, "");
  log.debug("Leaving pqListed(). " + out.length);
  return out;
}

async function realm(id) {
  log.debug("Entering realm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "PQ switch " + STAMP },
    "created the realm " + id);
  CREATED.push(id);
  // Development is what this job asserts; a product stack's realms would
  // otherwise inherit the process's mode.
  await setting(id, "global.mode", "development");
  await ok(base + "/realm/" + id + "/admin-api/applications/create", {
    identifier: "pq-cc", name: "pq-cc", protocols: ["oauth2"],
    fields: { oauthClientId: ["pq-cc"], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"] } },
    "registered pq-cc in " + id);
  log.debug("Leaving realm().");
}

async function get(id, path) {
  log.debug("Entering get(). " + id + path);
  const r = await send(base + "/realm/" + id + path);
  assert.strictEqual(r.status, 200, path + ": " + r.raw.slice(0, 300));
  log.debug("Leaving get().");
  return r.body;
}

function akpSigning(keys) {
  log.debug("Entering akpSigning().");
  log.debug("Leaving akpSigning().");
  return keys.filter(function (k) {
    return k.kty === "AKP" && k.use !== "enc";
  });
}

function encryption(keys) {
  log.debug("Entering encryption().");
  log.debug("Leaving encryption().");
  return keys.filter(function (k) {
    return k.use === "enc";
  }).map(function (k) {
    return k.kty + "/" + (k.alg || "") + "/" + (k.crv || "");
  }).sort().join(",");
}

async function test() {
  log.debug("Entering test().");
  await realm(ON);
  await realm(OFF);

  log.info("=== 1. the row ===");
  const row = await configRow(ON, "keys.postQuantumSigning");
  check("1. keys.postQuantumSigning is on by default", function () {
    assert.ok(row, "no row");
    assert.strictEqual(String(row.value), "true", JSON.stringify(row));
  });
  await setting(OFF, "keys.postQuantumSigning", false);
  const offRow = await configRow(OFF, "keys.postQuantumSigning");
  check("1. and a realm carries false", function () {
    assert.strictEqual(String(offRow.value), "false", JSON.stringify(offRow));
  });

  log.info("=== 2. the JWK Set ===");
  const onKeys = (await get(ON, "/oauth2/jwks")).keys;
  const offKeys = (await get(OFF, "/oauth2/jwks")).keys;
  check("2a. the realm left on publishes post-quantum signing keys (AKP)",
        function () {
    assert.ok(akpSigning(onKeys).length > 0);
  });
  check("2b. the realm turned off publishes none, and still its classical " +
        "keys", function () {
    assert.strictEqual(akpSigning(offKeys).length, 0, JSON.stringify(
      akpSigning(offKeys).map(function (k) {
        return k.alg;
      })));
    assert.ok(offKeys.some(function (k) {
      return k.kty === "EC" && k.use !== "enc";
    }));
  });
  check("2c. with its RSA key still first", function () {
    assert.strictEqual(offKeys[0].kty, "RSA");
  });
  check("2d. and its encryption keys as they were", function () {
    assert.strictEqual(encryption(offKeys), encryption(onKeys));
  });

  log.info("=== 3. the metadata documents ===");
  const documents = [
    ["RFC 8414", "/.well-known/oauth-authorization-server"],
    ["OpenID Connect Discovery", "/.well-known/openid-configuration"],
    ["OpenID4VCI issuer metadata", "/.well-known/openid-credential-issuer"]
  ];
  for (const one of documents) {
    const onDoc = await get(ON, one[1]);
    const offDoc = await get(OFF, one[1]);
    check("3. " + one[0] + " lists post-quantum algorithms where it is on",
          function () {
      assert.ok(pqListed(onDoc).length > 0);
    });
    check("3. and none in any algorithm list where it is off", function () {
      assert.deepStrictEqual(pqListed(offDoc).slice(0, 5), []);
    });
  }
  const offDisc = await get(OFF, "/.well-known/openid-configuration");
  check("3. and its lists keep the classical algorithms", function () {
    assert.ok(offDisc.id_token_signing_alg_values_supported.indexOf("RS256") >=
              0, JSON.stringify(offDisc.id_token_signing_alg_values_supported));
    assert.ok(offDisc.id_token_signing_alg_values_supported.indexOf("ES256") >=
              0);
  });

  log.info("=== 4. a registration naming one ===");
  const asked = function (id) {
    return postJson(base + "/realm/" + id +
                    "/admin-api/applications/create", {
      identifier: "pq-id", name: "pq-id", protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: ["pq-id"], oauthClientSecret: SECRET,
                oauthGrantType: ["client_credentials"],
                oauthIdTokenSignedResponseAlg: "ML-DSA-44" } });
  };
  const here = await asked(ON);
  const there = await asked(OFF);
  check("4a. the realm left on registers an application naming ML-DSA-44 " +
        "for its ID Tokens", function () {
    assert.strictEqual(here.status, 200, here.raw.slice(0, 300));
  });
  check("4b. the realm turned off refuses it as an algorithm it does not " +
        "sign with", function () {
    assert.strictEqual(there.status, 400, there.raw.slice(0, 300));
    assert.ok(/ML-DSA-44/.test(there.raw), there.raw.slice(0, 300));
  });

  log.info("=== 5. a token from the realm that is off ===");
  const r = await send(base + "/realm/" + OFF + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_id: "pq-cc", client_secret: SECRET }).toString() });
  check("5. an access token from the realm that is off is classical",
        function () {
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    assert.ok(!PQ.test(headerOf(r.body.access_token).alg),
              headerOf(r.body.access_token).alg);
  });

  assert.ok(checks >= 15, "only " + checks + " checks ran; a section has " +
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
