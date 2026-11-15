// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_signing_algorithm_allowlist.js
//
// ---------------------------------------------------------------------------
// ONE REALM'S SIGNING ALGORITHMS, NAMED ONE BY ONE, OVER THE WIRE.
//
// D12 (#444): carries over the part of `tests/signing_algorithm_allowlist.js`
// a client can see, in throwaway realms written through
// `/admin-api/realms/set`:
//
//   A. `keys.signingAlgorithms` is empty by default; a list without RS256 is
//      refused at the write;
//   B. empty changes nothing: the JWK Set carries EC signing keys and
//      discovery names ES256 for ID Tokens;
//   C. a realm naming only RS256 beside a realm naming nothing: its JWK Set
//      holds RSA signing keys alone and its encryption keys as before; its
//      discovery names RS256 alone for ID Tokens, introspection and JARM and
//      ["RS256","none"] for UserInfo, and still accepts an ES256 client
//      assertion; the realm beside it still names ES256; an application
//      naming ES256 for its ID Tokens is refused there and registered beside
//      it; an unlisted access-token algorithm cannot be written, and one
//      written before the list signs RS256; RS256,ES256 lets an ES256 ID
//      Token be issued;
//   D. `keys.jwksCertificateUrl`: off by default, keys carrying x5c; on,
//      every key names its chain by x5u at an address that answers the same
//      chain, no x5c, each still a usable key, the set under half the size;
//      the realm beside it unchanged; with the list, the x5u keys are RSA;
//   E. ES256K in a PRODUCT realm with no list (#1533, #1577): no secp256k1
//      signing key, ES256K named for nothing it signs and nothing it accepts
//      (DPoP among them, which keeps ES256), while a development realm still
//      publishes the key; a list naming ES256K publishes it in product; the
//      realm's crypto report lists, for every list it shares with discovery,
//      exactly what discovery publishes; an ES256K client assertion at the
//      product token endpoint is refused with no list and accepted where a
//      list names it.
//
// NOT carried, and why (class (d)): the helpers on hand-made key and
// document inputs (C1–C3), `signJwtAs()`/`signJwtAsAsync()` refusing a
// non-RS256 signature with STS-KEYS-0166 (a library call: no door asks this
// service to sign with an algorithm the client chose but registration, which
// C asserts), the dead-link guard on a certificate the address cannot serve
// (E6), and the COSE and XML ES256K verdicts (F11's COSE half and F13: the
// families verifying those, phases 7 and 9, own their wire halves).
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
var log = bunyan.createLogger({ name: "sts_signing_algorithm_allowlist",
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

// HOW MANY ROWS CARRY A CODE, in the default realm's audit log and in the
// list realm's together: the root API's refusal may be recorded in either.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  let n = 0;
  for (const where of [base, base + "/realm/" + LIST]) {
    const r = await send(where + "/admin-api/audit?per=500&code=" +
                         encodeURIComponent(code));
    n += Number((r.body && r.body.matched) || 0);
  }
  log.debug("Leaving codeCount(). " + n);
  return n;
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

const LIST = "saal-" + STAMP;
const PLAIN = "saap-" + STAMP;
const PRODUCT = "saak-" + STAMP;
const CREATED = [];
const SECRET = "saa-" + STAMP + "-0123456789abcdef-secret";
const PERSON = "saa-" + STAMP;
const KEY = "keys.signingAlgorithms";

async function realm(id) {
  log.debug("Entering realm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Signing allowlist " + STAMP },
    "created the realm " + id);
  CREATED.push(id);
  // Development is what this job asserts; a product stack's realms would
  // otherwise inherit the process's mode.
  await setting(id, "global.mode", "development");
  await ok(base + "/realm/" + id + "/admin-api/users/create", {
    username: PERSON, invent: false, credential: "password",
    password: SECRET, attributes: { cn: "SAA " + PERSON, givenName: "SAA",
      sn: PERSON, mail: PERSON + "@saa.test" } }, "created " + PERSON);
  log.debug("Leaving realm().");
}

function registration(id, idTokenAlg, extra) {
  log.debug("Entering registration(). " + id);
  const fields = Object.assign({ oauthClientId: [id],
    oauthClientSecret: SECRET,
    oauthTokenEndpointAuthMethod: "client_secret_post",
    oauthGrantType: ["password", "client_credentials"] }, extra || {});
  if (idTokenAlg) {
    fields.oauthIdTokenSignedResponseAlg = idTokenAlg;
  }
  log.debug("Leaving registration().");
  return { identifier: id, name: id, protocols: ["oauth2", "oidc"],
           fields: fields };
}

async function register(realmId, id, idTokenAlg, extra) {
  log.debug("Entering register(). " + realmId + " " + id);
  const r = await postJson(base + "/realm/" + realmId +
                           "/admin-api/applications/create",
                           registration(id, idTokenAlg, extra));
  log.debug("Leaving register(). " + r.status);
  return r;
}

async function tokens(realmId, id) {
  log.debug("Entering tokens(). " + realmId + " " + id);
  const r = await send(base + "/realm/" + realmId + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: PERSON,
      password: SECRET, scope: "openid", client_id: id,
      client_secret: SECRET }).toString() });
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving tokens().");
  return r.body;
}

async function doc(realmId, path) {
  log.debug("Entering doc(). " + realmId + path);
  const r = await send(base + "/realm/" + realmId + path);
  assert.strictEqual(r.status, 200, path + " " + r.raw.slice(0, 300));
  log.debug("Leaving doc().");
  return r.body;
}

function signingKeys(keys) {
  log.debug("Entering signingKeys().");
  log.debug("Leaving signingKeys().");
  return keys.filter(function (k) {
    return k.use !== "enc";
  });
}

function encKeys(keys) {
  log.debug("Entering encKeys().");
  log.debug("Leaving encKeys().");
  return keys.filter(function (k) {
    return k.use === "enc";
  }).map(function (k) {
    return k.kty + "/" + (k.crv || "");
  }).sort().join(",");
}

function hasK1(keys) {
  log.debug("Entering hasK1().");
  log.debug("Leaving hasK1().");
  return signingKeys(keys).some(function (k) {
    return k.alg === "ES256K" || k.crv === "secp256k1";
  });
}

async function test() {
  log.debug("Entering test().");
  await realm(LIST);
  await realm(PLAIN);

  log.info("=== A. the row ===");
  const row = await configRow(LIST, KEY);
  check("A1. keys.signingAlgorithms is empty by default", function () {
    assert.ok(row, "no row");
    assert.ok(row.value === "" || row.value === null ||
              row.value === undefined ||
              (Array.isArray(row.value) && row.value.length === 0),
              JSON.stringify(row.value));
  });
  const noRsa = await postJson(base + "/admin-api/realms/set", { id: LIST,
    key: KEY, value: "ES256,PS256" });
  check("A2. a list without RS256 is refused at the write, naming RS256",
        function () {
    assert.strictEqual(noRsa.status, 400, noRsa.raw.slice(0, 300));
    assert.ok(/RS256/.test(noRsa.raw), noRsa.raw.slice(0, 300));
  });

  log.info("=== B. empty changes nothing ===");
  const plainKeys = (await doc(PLAIN, "/oauth2/jwks")).keys;
  const plainDisc = await doc(PLAIN, "/.well-known/openid-configuration");
  check("B1. with no list the JWK Set carries EC signing keys and " +
        "discovery names ES256 for ID Tokens", function () {
    assert.ok(signingKeys(plainKeys).some(function (k) {
      return k.kty === "EC";
    }));
    assert.ok(plainDisc.id_token_signing_alg_values_supported
      .indexOf("ES256") >= 0);
  });

  log.info("=== C. a realm naming only RS256 ===");
  await setting(LIST, KEY, "RS256");
  const listKeys = (await doc(LIST, "/oauth2/jwks")).keys;
  check("C1. its JWK Set holds RSA signing keys alone", function () {
    assert.ok(signingKeys(listKeys).length > 0);
    signingKeys(listKeys).forEach(function (k) {
      assert.strictEqual(k.kty, "RSA", (k.alg || "") + " " + k.kty);
    });
  });
  check("C2. and its encryption keys as before", function () {
    assert.strictEqual(encKeys(listKeys), encKeys(plainKeys));
  });
  const listDisc = await doc(LIST, "/.well-known/openid-configuration");
  check("C3. its discovery names RS256 alone for what it signs, `none` " +
        "kept for UserInfo", function () {
    assert.deepStrictEqual(listDisc.id_token_signing_alg_values_supported,
                           ["RS256"]);
    assert.deepStrictEqual(listDisc.userinfo_signing_alg_values_supported,
                           ["RS256", "none"]);
    assert.deepStrictEqual(
      listDisc.introspection_signing_alg_values_supported, ["RS256"]);
    assert.deepStrictEqual(
      listDisc.authorization_signing_alg_values_supported, ["RS256"]);
  });
  check("C4. and still accepts an ES256 client assertion", function () {
    assert.ok(listDisc.token_endpoint_auth_signing_alg_values_supported
      .indexOf("ES256") >= 0);
  });
  const plainAgain = await doc(PLAIN, "/.well-known/openid-configuration");
  check("C5. the realm beside it still names ES256", function () {
    assert.ok(plainAgain.id_token_signing_alg_values_supported
      .indexOf("ES256") >= 0);
  });
  const refused = await register(LIST, "saa-es", "ES256");
  const taken = await register(PLAIN, "saa-es", "ES256");
  check("C6. an application naming ES256 for its ID Tokens is refused in " +
        "the realm with the list", function () {
    assert.strictEqual(refused.status, 400, refused.raw.slice(0, 300));
    assert.ok(/ES256/.test(refused.raw), refused.raw.slice(0, 300));
  });
  check("C7. and registered in the realm beside it", function () {
    assert.strictEqual(taken.status, 200, taken.raw.slice(0, 300));
  });
  const atWrite = await postJson(base + "/realm/" + LIST +
                                 "/admin-api/config/set", {
    key: "oauth2.accessTokenSigningAlg", value: "ES256" });
  check("C8. an unlisted access-token algorithm cannot be written at the " +
        "realm's own config/set", function () {
    assert.strictEqual(atWrite.status, 400, atWrite.raw.slice(0, 300));
    assert.ok(/keys\.signingAlgorithms/.test(atWrite.raw),
              atWrite.raw.slice(0, 300));
  });
  const k192Before = await codeCount("STS-KEYS-0192");
  const atRoot = await postJson(base + "/admin-api/realms/set", {
    id: LIST, key: "oauth2.accessTokenSigningAlg", value: "ES256" });
  let k192 = await codeCount("STS-KEYS-0192");
  for (let i = 0; i < 20 && k192 <= k192Before; i += 1) {
    await sleep(150);
    k192 = await codeCount("STS-KEYS-0192");
  }
  check("C8a. the root API's realms/set refuses the same write, 400, by " +
        "the rule across settings, recorded STS-KEYS-0192", function () {
    assert.strictEqual(atRoot.status, 400, atRoot.raw.slice(0, 300));
    assert.ok(/keys\.signingAlgorithms/.test(atRoot.raw),
              atRoot.raw.slice(0, 300));
    assert.ok(k192 > k192Before, k192Before + " -> " + k192);
  });
  await ok(base + "/realm/" + LIST + "/admin-api/config/reset", { key: KEY },
           "reset the list");
  await setting(LIST, "oauth2.accessTokenSigningAlg", "ES256");
  const rs = await register(LIST, "saa-rs", null);
  assert.strictEqual(rs.status, 200, rs.raw.slice(0, 300));
  const before = await tokens(LIST, "saa-rs");
  await setting(LIST, KEY, "RS256");
  const after = await tokens(LIST, "saa-rs");
  check("C9. with no list that setting signs ES256, and once the list is " +
        "set the same setting signs RS256", function () {
    assert.strictEqual(headerOf(before.access_token).alg, "ES256");
    assert.strictEqual(headerOf(after.access_token).alg, "RS256");
    assert.strictEqual(headerOf(after.id_token).alg, "RS256");
  });
  await ok(base + "/realm/" + LIST + "/admin-api/config/reset",
           { key: "oauth2.accessTokenSigningAlg" }, "reset the setting");
  await setting(LIST, KEY, "RS256,ES256");
  const second = await register(LIST, "saa-es2", "ES256");
  check("C10. a listed second algorithm is registrable", function () {
    assert.strictEqual(second.status, 200, second.raw.slice(0, 300));
  });
  const esTokens = await tokens(LIST, "saa-es2");
  check("C11. and signs", function () {
    assert.strictEqual(headerOf(esTokens.id_token).alg, "ES256");
  });
  await ok(base + "/realm/" + LIST + "/admin-api/config/reset", { key: KEY },
           "reset the list");

  log.info("=== D. keys.jwksCertificateUrl ===");
  const urlRow = await configRow(LIST, "keys.jwksCertificateUrl");
  check("D1. the flag is off by default", function () {
    assert.ok(urlRow, "no row");
    assert.strictEqual(String(urlRow.value), "false");
  });
  let offSet = await doc(LIST, "/oauth2/jwks");
  const chained = function (set) {
    return set.keys.filter(function (k) {
      return Array.isArray(k.x5c) && k.x5c.length > 0;
    });
  };
  for (let i = 0; i < 40 && !(chained(offSet).length > 0 &&
                              chained(offSet)[0].x5c.length > 1); i += 1) {
    await sleep(250);
    offSet = await doc(LIST, "/oauth2/jwks");
  }
  const chains = chained(offSet);
  check("D2. off: the keys carry x5c and no x5u", function () {
    assert.ok(chains.length > 0 && chains[0].x5c.length > 1,
              chains.length + " chained");
    assert.ok(!offSet.keys.some(function (k) {
      return k.x5u;
    }));
  });
  await setting(LIST, "keys.jwksCertificateUrl", true);
  const onSet = await doc(LIST, "/oauth2/jwks");
  const named = onSet.keys.filter(function (k) {
    return k.x5u;
  });
  check("D3. on: every chained key names its chain by x5u, none carries " +
        "x5c, and each is still a usable key", function () {
    assert.strictEqual(named.length, chains.length);
    assert.strictEqual(chained(onSet).length, 0);
    named.forEach(function (k) {
      assert.ok(nodeCrypto.createPublicKey({ key: Object.assign({}, k,
        { x5u: undefined }), format: "jwk" }), k.kid);
    });
  });
  check("D4. and the JWK Set is smaller", function () {
    assert.ok(JSON.stringify(onSet).length < JSON.stringify(offSet).length,
              JSON.stringify(offSet).length + " -> " +
              JSON.stringify(onSet).length);
  });
  const original = chains.filter(function (k) {
    return k.kid === named[0].kid;
  })[0];
  const served = await send(named[0].x5u);
  check("D5. the address answers the same chain the x5c carried",
        function () {
    assert.strictEqual(served.status, 200);
    assert.deepStrictEqual(pemsIn(served.raw).map(b64Of), original.x5c);
  });
  const besideSet = await doc(PLAIN, "/oauth2/jwks");
  check("D6. the realm beside it is unchanged", function () {
    assert.ok(besideSet.keys.some(function (k) {
      return k.x5c;
    }));
    assert.ok(!besideSet.keys.some(function (k) {
      return k.x5u;
    }));
  });
  await setting(LIST, KEY, "RS256");
  const composed = (await doc(LIST, "/oauth2/jwks")).keys;
  await ok(base + "/realm/" + LIST + "/admin-api/config/reset",
           { key: "keys.jwksCertificateUrl" }, "reset the flag");
  const rsaOnlyOff = (await doc(LIST, "/oauth2/jwks")).keys;
  check("D4a. where the set is RSA alone, as in-process, x5u leaves it " +
        "less than half the size", function () {
    assert.ok(JSON.stringify(composed).length <
              JSON.stringify(rsaOnlyOff).length / 2,
              JSON.stringify(rsaOnlyOff).length + " -> " +
              JSON.stringify(composed).length);
  });
  check("D7. the flag and the allowlist compose: RSA keys named by x5u",
        function () {
    const x5u = signingKeys(composed).filter(function (k) {
      return k.x5u;
    });
    assert.ok(x5u.length > 0);
    signingKeys(composed).forEach(function (k) {
      assert.strictEqual(k.kty, "RSA");
    });
  });

  log.info("=== E. ES256K in product ===");
  await realm(PRODUCT);
  await setting(PRODUCT, "global.mode", "product");
  const pKeys = (await doc(PRODUCT, "/oauth2/jwks")).keys;
  check("E1. a product realm with no list publishes no secp256k1 signing " +
        "key, and a development realm still does", function () {
    assert.ok(!hasK1(pKeys));
    assert.ok(hasK1(plainKeys));
  });
  const pDisc = await doc(PRODUCT, "/.well-known/openid-configuration");
  const pAs = await doc(PRODUCT, "/.well-known/oauth-authorization-server");
  check("E2. its discovery names ES256K for nothing it signs", function () {
    ["id_token", "userinfo", "introspection", "authorization"]
      .forEach(function (what) {
        const list = pDisc[what + "_signing_alg_values_supported"];
        assert.ok(Array.isArray(list) && list.indexOf("ES256K") < 0, what);
      });
  });
  check("E3. and nothing it accepts, DPoP among them, which keeps ES256",
        function () {
    ["dpop", "token_endpoint_auth", "request_object"].forEach(function (w) {
      const list = pDisc[w + "_signing_alg_values_supported"];
      assert.ok(!Array.isArray(list) || list.indexOf("ES256K") < 0, w);
    });
    assert.ok(pDisc.dpop_signing_alg_values_supported.indexOf("ES256") >= 0);
  });
  const report = await send(base + "/realm/" + PRODUCT + "/admin-api/crypto");
  check("E4. the realm's crypto report lists, for every list it shares " +
        "with discovery, exactly what discovery publishes", function () {
    assert.strictEqual(report.status, 200, report.raw.slice(0, 300));
    const family = report.body.families.filter(function (one) {
      return one.name === "OAuth2 / OIDC";
    })[0];
    const rows = {};
    family.algorithms.forEach(function (one) {
      rows[one.what] = one.values;
    });
    const signed = function (list) {
      return (list || []).filter(function (alg) {
        return alg !== "none";
      });
    };
    const pairs = [
      ["ID Token, when a client registers one", pDisc,
       "id_token_signing_alg_values_supported"],
      ["UserInfo response", pDisc, "userinfo_signing_alg_values_supported"],
      ["JWT introspection response (RFC 9701)", pAs,
       "introspection_signing_alg_values_supported"],
      ["Request object signature (RFC 9101)", pAs,
       "request_object_signing_alg_values_supported"],
      ["DPoP proof", pAs, "dpop_signing_alg_values_supported"]];
    pairs.forEach(function (one) {
      assert.ok(rows[one[0]], "no report row " + one[0]);
      assert.deepStrictEqual(signed(rows[one[0]]), signed(one[1][one[2]]),
                             one[0]);
    });
  });
  const k1 = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  const k1Jwk = Object.assign(k1.publicKey.export({ format: "jwk" }),
                              { kid: "k1", use: "sig", alg: "ES256K" });
  const made = await postJson(base + "/realm/" + PRODUCT +
                              "/admin-api/applications/create", {
    identifier: "saa-k1", name: "saa-k1", protocols: ["oauth2"],
    fields: { oauthClientId: ["saa-k1"],
              oauthTokenEndpointAuthMethod: "private_key_jwt",
              oauthGrantType: ["client_credentials"],
              oauthJwks: JSON.stringify({ keys: [k1Jwk] }) } });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  const tokenUrl = base + "/realm/" + PRODUCT + "/oauth2/token";
  const present = function () {
    const now = Math.floor(Date.now() / 1000);
    const h = Buffer.from(JSON.stringify({ alg: "ES256K", kid: "k1",
                                           typ: "JWT" })).toString("base64url");
    const p = Buffer.from(JSON.stringify({ iss: "saa-k1", sub: "saa-k1",
      aud: tokenUrl, iat: now, exp: now + 300,
      jti: "k1-" + nodeCrypto.randomBytes(8).toString("hex") }))
      .toString("base64url");
    const sig = nodeCrypto.sign("sha256", Buffer.from(h + "." + p),
      { key: k1.privateKey, dsaEncoding: "ieee-p1363" });
    return send(tokenUrl, { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials",
        client_id: "saa-k1", client_assertion: h + "." + p + "." +
          sig.toString("base64url"), client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" })
        .toString() });
  };
  const k1Bare = await present();
  check("E5. an ES256K client assertion is refused at the product token " +
        "endpoint with no list", function () {
    assert.strictEqual(k1Bare.status, 401, k1Bare.raw.slice(0, 300));
    assert.strictEqual(k1Bare.body.error, "invalid_client");
  });
  await setting(PRODUCT, KEY, "RS256,ES256K");
  const pListed = (await doc(PRODUCT, "/oauth2/jwks")).keys;
  check("E6. a list naming ES256K publishes its key in product", function () {
    assert.ok(hasK1(pListed));
  });
  const k1Listed = await present();
  check("E7. and an ES256K client assertion is then accepted", function () {
    assert.strictEqual(k1Listed.status, 200, k1Listed.raw.slice(0, 300));
  });

  assert.ok(checks >= 30, "only " + checks + " checks ran; a section has " +
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
