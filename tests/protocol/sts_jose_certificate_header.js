// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_jose_certificate_header.js
//
// ---------------------------------------------------------------------------
// A SIGNED TOKEN NAMES THE CERTIFICATE CHAIN OF ITS KEY, OVER THE WIRE.
//
// D12 (#444): carries over the part of `tests/jose_certificate_header.js` a
// client can see, in two throwaway realms of its own, through
// `/admin-api/realms/set` and the token endpoint:
//
//   A. THE ROWS: `oauth2.accessTokenCertificateHeader` and its siblings
//      read back from `/admin-api/config` as x5u by default, and a value
//      outside none/x5c/x5u/both refused at the write;
//   B. x5u BY DEFAULT: an access token and the ID Token beside it carry
//      x5u and no x5c, naming this service's origin, the realm's scope and a
//      SHA-256; the address answers application/pem-certificate-chain,
//      no-store, the FULL chain leaf to Root with every link verified here,
//      ending at the Root `/pki/chain` serves; the token verifies with the
//      key IN the leaf; the leaf names its OCSP responder and CRL;
//   C. PER USE CASE: x5c (the same chain inline, no x5u) while the ID Token
//      keeps x5u, both, and none (alg, kid and typ only);
//   D. PER REALM: a second realm carrying x5c gets its OWN leaf under the
//      same Root, its ID Token's x5u names its own scope, and the first
//      realm is unmoved; the chain answers in its own scope and 404s in
//      another scope, for a value that is not a SHA-256 and for a SHA-256
//      of nothing;
//   E. signed_metadata carries x5u, and the changed setting is seen on the
//      next fetch (the cached signature is keyed by it);
//   F. an ES256 ID Token names the P-256 key's own certificate and verifies
//      with it; an HS256 ID Token carries neither header.
//
// NOT carried, and why (class (d)): section A's source scan and the
// use-case table against config.js (they read source); C8, the JWS inside
// a refresh token (it is encrypted to the realm's own key, so a client
// cannot open it — `sts_refresh_token_encryption.js` holds what a client
// sees of one); C13's byte identity with a signer naming no use case,
// C13b/c (a credential's chain without the Root — owed by phase 9's
// OpenID4VC jobs), C21–C25 (a use case with no row, no request, a fake
// Host and a register row over another key are library inputs) and C26 (a
// SET signed with no stream; phase 9's SSF jobs own a delivered one).
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
var log = bunyan.createLogger({ name: "sts_jose_certificate_header",
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
const REALM_A = "jcha-" + STAMP;
const REALM_B = "jchb-" + STAMP;
const SECRET = "jose-header-" + STAMP + "-" + String(Date.now()).slice(-8) +
               "-secret-0123456789";
const PERSON = "jch-" + STAMP;

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

async function prepare(realm) {
  log.debug("Entering prepare(). " + realm);
  await ok(base + "/admin-api/realms/create", { id: realm,
    domain: realm + ".example.net", name: "JOSE header " + STAMP },
    "created the realm " + realm);
  // Development is what this job asserts; a product stack's realms would
  // otherwise inherit the process's mode.
  await setting(realm, "global.mode", "development");
  const rb = base + "/realm/" + realm;
  await ok(rb + "/admin-api/users/create", { username: PERSON,
    invent: false, credential: "password", password: SECRET,
    attributes: { cn: "JOSE " + PERSON, givenName: "JOSE", sn: PERSON,
                  mail: PERSON + "@jch.test" } }, "created " + PERSON);
  const fields = function (id, alg) {
    const f = { oauthClientId: [id], oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: "client_secret_post",
                oauthGrantType: ["password", "refresh_token"] };
    if (alg) {
      f.oauthIdTokenSignedResponseAlg = alg;
    }
    return f;
  };
  for (const one of [["jch-rs", null], ["jch-es", "ES256"],
                     ["jch-hs", "HS256"]]) {
    await ok(rb + "/admin-api/applications/create", { identifier: one[0],
      name: one[0], protocols: ["oauth2", "oidc"],
      fields: fields(one[0], one[1]) },
      "registered " + one[0]);
  }
  log.debug("Leaving prepare().");
}

async function issue(realm, clientId) {
  log.debug("Entering issue(). " + realm + " " + clientId);
  const r = await send(base + "/realm/" + realm + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", username: PERSON,
      password: SECRET, scope: "openid", client_id: clientId || "jch-rs",
      client_secret: SECRET }).toString() });
  assert.strictEqual(r.status, 200, "the token endpoint in " + realm +
                     " answered " + r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving issue().");
  return r.body;
}

// Certification of a new realm's keys runs after the realm is made, so the
// first token may arrive before its certificate; wait for an x5u.
async function issueCertified(realm) {
  log.debug("Entering issueCertified(). " + realm);
  let body = await issue(realm);
  for (let i = 0; i < 40 && !headerOf(body.access_token).x5u; i += 1) {
    await sleep(250);
    body = await issue(realm);
  }
  log.debug("Leaving issueCertified().");
  return body;
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

async function test() {
  log.debug("Entering test().");
  await prepare(REALM_A);
  const RA = base + "/realm/" + REALM_A;

  log.info("=== A. the rows ===");
  const uses = ["oauth2.accessTokenCertificateHeader",
                "oauth2.idTokenCertificateHeader",
                "oauth2.signedMetadataCertificateHeader"];
  for (const key of uses) {
    const row = await configRow(REALM_A, key);
    check("A. " + key + " exists and is x5u by default", function () {
      assert.ok(row, "no row " + key);
      assert.strictEqual(String(row.value), "x5u", JSON.stringify(row));
    });
  }
  const bogus = await postJson(base + "/admin-api/realms/set",
    { id: REALM_A, key: "oauth2.accessTokenCertificateHeader",
      value: "jwk" });
  check("A. a value outside none, x5c, x5u and both is refused", function () {
    assert.ok(bogus.status >= 400 || (bogus.body && bogus.body.ok === false),
              bogus.status + " " + bogus.raw.slice(0, 300));
  });

  log.info("=== B. x5u by default ===");
  let tokens = await issueCertified(REALM_A);
  const aHeader = headerOf(tokens.access_token);
  check("B1. an access token carries x5u and not x5c", function () {
    assert.ok(typeof aHeader.x5u === "string" && aHeader.x5c === undefined,
              JSON.stringify(aHeader));
  });
  check("B2. naming this service's origin, the realm's scope and a SHA-256",
        function () {
    assert.ok(String(aHeader.x5u).indexOf(base + "/pki/chain/" + REALM_A +
                                          "/") === 0, aHeader.x5u);
    assert.ok(/\/[0-9a-f]{64}\.pem$/.test(aHeader.x5u), aHeader.x5u);
  });
  check("B3. the ID Token beside it carries x5u too", function () {
    assert.strictEqual(typeof headerOf(tokens.id_token).x5u, "string",
                       JSON.stringify(headerOf(tokens.id_token)));
  });
  const fetched = await send(aHeader.x5u);
  const pems = pemsIn(fetched.raw);
  check("B4. the x5u address answers application/pem-certificate-chain, " +
        "no-store", function () {
    assert.strictEqual(fetched.status, 200);
    assert.ok(/application\/pem-certificate-chain/.test(
      fetched.headers.get("content-type")), fetched.headers.get(
      "content-type"));
    assert.strictEqual(fetched.headers.get("cache-control"), "no-store");
  });
  const certs = pems.map(function (p) {
    return new nodeCrypto.X509Certificate(p);
  });
  const rootAnswer = await fetch(base + "/pki/ca/default/root.cer");
  const rootDer = Buffer.from(await rootAnswer.arrayBuffer());
  const rootB64 = /BEGIN CERTIFICATE/.test(rootDer.toString("latin1"))
    ? b64Of(rootDer.toString("latin1")) : rootDer.toString("base64");
  check("B5. it is the FULL chain — leaf, Issuing CA, Intermediate, Root — " +
        "each link signed by the next, ending at the Root /pki/ca serves",
        function () {
    assert.strictEqual(certs.length, 4, certs.length + " certificate(s)");
    for (let i = 0; i < certs.length - 1; i += 1) {
      assert.strictEqual(certs[i].issuer, certs[i + 1].subject);
      assert.ok(certs[i].verify(certs[i + 1].publicKey), "link " + i);
    }
    assert.strictEqual(rootAnswer.status, 200);
    assert.strictEqual(b64Of(pems[3]), rootB64,
                       "the last certificate is not this service's Root");
  });
  check("B6. the token verifies with the key IN the leaf", function () {
    assert.ok(jwsVerifies(tokens.access_token, certs[0].publicKey));
  });
  const leafDer = Buffer.from(b64Of(pems[0]), "base64").toString("latin1");
  check("B7. the leaf names its OCSP responder and its CRL", function () {
    assert.ok(/OCSP/.test(String(certs[0].infoAccess)),
              String(certs[0].infoAccess));
    assert.ok(leafDer.indexOf("/pki/crl/") >= 0, "no CRL distribution point");
  });

  log.info("=== C. per use case ===");
  await setting(REALM_A, "oauth2.accessTokenCertificateHeader", "x5c");
  tokens = await issue(REALM_A);
  const x5c = headerOf(tokens.access_token);
  check("C1. x5c: the SAME chain inline, base64 DER, and no x5u", function () {
    assert.ok(Array.isArray(x5c.x5c) && x5c.x5u === undefined,
              JSON.stringify(Object.keys(x5c)));
    assert.strictEqual(x5c.x5c.join(","), pems.map(b64Of).join(","));
  });
  check("C2. while the ID Token, whose setting was not touched, keeps x5u",
        function () {
    const h = headerOf(tokens.id_token);
    assert.ok(typeof h.x5u === "string" && h.x5c === undefined,
              JSON.stringify(Object.keys(h)));
  });
  await setting(REALM_A, "oauth2.accessTokenCertificateHeader", "both");
  tokens = await issue(REALM_A);
  check("C3. both: it carries both", function () {
    const h = headerOf(tokens.access_token);
    assert.ok(Array.isArray(h.x5c) && typeof h.x5u === "string",
              JSON.stringify(Object.keys(h)));
  });
  await setting(REALM_A, "oauth2.accessTokenCertificateHeader", "none");
  tokens = await issue(REALM_A);
  check("C4. none: the header is alg, kid and typ and nothing else",
        function () {
    assert.strictEqual(Object.keys(headerOf(tokens.access_token)).sort()
      .join(","), "alg,kid,typ");
  });
  await ok(RA + "/admin-api/config/reset",
           { key: "oauth2.accessTokenCertificateHeader" },
           "reset the access token's header");

  log.info("=== D. per realm ===");
  await prepare(REALM_B);
  await setting(REALM_B, "oauth2.accessTokenCertificateHeader", "x5c");
  let other = await issue(REALM_B);
  for (let i = 0; i < 40 && !headerOf(other.id_token).x5u; i += 1) {
    await sleep(250);
    other = await issue(REALM_B);
  }
  const bHeader = headerOf(other.access_token);
  const bId = headerOf(other.id_token);
  check("D1. a realm carrying x5c gets its OWN leaf inline, under the same " +
        "Root", function () {
    assert.ok(Array.isArray(bHeader.x5c), JSON.stringify(Object.keys(
      bHeader)));
    assert.notStrictEqual(bHeader.x5c[0], b64Of(pems[0]));
    assert.strictEqual(bHeader.x5c[bHeader.x5c.length - 1], b64Of(pems[3]));
  });
  check("D2. and its ID Token's x5u names the realm's own scope", function () {
    assert.ok(String(bId.x5u).indexOf(base + "/pki/chain/" + REALM_B +
                                      "/") === 0, bId.x5u);
  });
  tokens = await issue(REALM_A);
  check("D3. while the first realm's access token is x5u again — the " +
        "override stayed in its realm", function () {
    const h = headerOf(tokens.access_token);
    assert.ok(typeof h.x5u === "string" && h.x5c === undefined,
              JSON.stringify(Object.keys(h)));
  });
  const realmChain = await send(bId.x5u);
  const thumb = /([0-9a-f]{64})\.pem$/.exec(String(bId.x5u))[1];
  const crossScope = await send(base + "/pki/chain/" + REALM_A + "/" + thumb +
                                ".pem");
  const notHex = await send(base + "/pki/chain/default/zzz.pem");
  const unknown = await send(base + "/pki/chain/default/" + "a".repeat(64) +
                             ".pem");
  check("D4. the realm's chain answers in its own scope, and 404 answers " +
        "it in another scope, a value that is not a SHA-256 and a SHA-256 " +
        "of nothing", function () {
    assert.strictEqual(realmChain.status, 200);
    assert.strictEqual(pemsIn(realmChain.raw).length, 4);
    assert.deepStrictEqual([crossScope.status, notHex.status, unknown.status],
                           [404, 404, 404]);
  });

  log.info("=== E. signed_metadata ===");
  const before = await send(RA + "/.well-known/oauth-authorization-server");
  await setting(REALM_A, "oauth2.signedMetadataCertificateHeader", "x5c");
  const after = await send(RA + "/.well-known/oauth-authorization-server");
  check("E. signed_metadata carries x5u, and a changed setting is seen on " +
        "the next fetch", function () {
    const sb = before.body && before.body.signed_metadata;
    const sa = after.body && after.body.signed_metadata;
    assert.ok(sb && typeof headerOf(sb).x5u === "string",
              sb ? JSON.stringify(headerOf(sb)) : "no signed_metadata");
    assert.ok(sa && Array.isArray(headerOf(sa).x5c),
              sa ? JSON.stringify(Object.keys(headerOf(sa))) : "none");
  });

  log.info("=== F. ES256 and HS256 ===");
  const es = await issue(REALM_A, "jch-es");
  const esHeader = headerOf(es.id_token);
  check("F1. an ES256 ID Token names the P-256 key's own certificate, and " +
        "verifies with the key in it", function () {
    assert.strictEqual(esHeader.alg, "ES256", JSON.stringify(esHeader));
    assert.strictEqual(typeof esHeader.x5u, "string");
  });
  const esChain = pemsIn((await send(esHeader.x5u)).raw);
  check("F1. (the leaf's key is EC P-256 and verifies the token)",
        function () {
    const leaf = new nodeCrypto.X509Certificate(esChain[0]);
    assert.strictEqual(leaf.publicKey.asymmetricKeyType, "ec");
    assert.ok(jwsVerifies(es.id_token, leaf.publicKey));
    assert.notStrictEqual(b64Of(esChain[0]), b64Of(pems[0]));
  });
  const hs = await issue(REALM_A, "jch-hs");
  check("F2. an HS256 ID Token carries neither x5c nor x5u", function () {
    const h = headerOf(hs.id_token);
    assert.strictEqual(h.alg, "HS256", JSON.stringify(h));
    assert.ok(h.x5c === undefined && h.x5u === undefined, JSON.stringify(h));
  });
  check("F3. (pemOfB64 round-trips the inline chain)", function () {
    assert.ok(new nodeCrypto.X509Certificate(pemOfB64(x5c.x5c[0])));
  });

  assert.ok(checks >= 20, "only " + checks + " checks ran; a section has " +
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
  for (const id of [REALM_A, REALM_B]) {
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
