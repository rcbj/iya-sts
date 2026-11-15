// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_jose_kid.js
//
// ---------------------------------------------------------------------------
// A SIGNED TOKEN'S `kid` MAY BE ITS KEY'S RFC 9278 THUMBPRINT URI, OVER THE
// WIRE.
//
// D12 (#444): carries over the part of `tests/jose_kid.js` a client can
// see, in two throwaway realms, through `/admin-api/realms/set` and the
// realm's own token endpoint and JWK Set. Every thumbprint is computed HERE
// from the published JWK (RFC 7638 section 3.2's members, RFC 9278's URI),
// and every signature is verified here with node's crypto or noble's ML-DSA,
// so nothing of this service's checks its own work:
//
//   A. `keys.kidFormat` reads back `internal` by default, and a format the
//      library does not have is refused;
//   B. with nothing set, an access token, its ID Token and signed_metadata
//      carry the internal kid, and the JWK Set names no key by a URI;
//   C. set to jwk-thumbprint-uri, the access token's and ID Token's kid is
//      the RSA key's URI, signed_metadata's at once, x5u unaffected; the RSA
//      key is still keys[0] under its internal kid; every signing key is
//      listed a second time under its own URI, after every signing key and
//      before the encryption keys, nothing else changed; the token verifies
//      against the entry its kid names and an earlier token against the
//      internal one; an ES256 and an ML-DSA-44 ID Token carry their own
//      keys' URIs over the P-256 and AKP entries and verify with them;
//      `/gnap/keys` names the URI;
//   D. off again: the internal kid back and the second entries gone;
//   E. a realm's setting reaches that realm alone.
//
// NOT carried, and why (class (d)): RFC 7638's example key and the AKP
// member set as library vectors (C here computes the same thumbprints
// against live keys), the lookup accepting either name and refusing a
// foreign URI (`kidNamesKey()` has no door of its own), and C14/C15's
// Security Event Tokens (signed with no stream; phase 9's SSF jobs own a
// delivered one).
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
var log = bunyan.createLogger({ name: "sts_jose_kid",
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

const mldsa = require("@noble/post-quantum/ml-dsa.js");

const REALM = "jkid-" + STAMP;
const OTHER = "jkio-" + STAMP;
const CREATED = [];
const SECRET = "jose-kid-" + STAMP + "-" + String(Date.now()).slice(-8) +
               "-secret-0123456789";
const PERSON = "jkid-" + STAMP;
const PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
const MEMBERS = { RSA: ["e", "kty", "n"], EC: ["crv", "kty", "x", "y"],
                  OKP: ["crv", "kty", "x"], AKP: ["alg", "kty", "pub"] };

function isUri(kid) {
  log.debug("Entering isUri().");
  log.debug("Leaving isUri().");
  return String(kid || "").indexOf(PREFIX) === 0;
}

// RFC 7638 section 3.2: the required members, in lexical order, no spaces;
// RFC 9278: the URI over its SHA-256.
function thumbprintUri(jwk) {
  log.debug("Entering thumbprintUri(). " + jwk.kty);
  const members = MEMBERS[jwk.kty];
  assert.ok(members, "no RFC 7638 member list for kty " + jwk.kty);
  const canonical = "{" + members.map(function (m) {
    return JSON.stringify(m) + ":" + JSON.stringify(jwk[m]);
  }).join(",") + "}";
  const uri = PREFIX + nodeCrypto.createHash("sha256").update(canonical)
    .digest("base64url");
  log.debug("Leaving thumbprintUri().");
  return uri;
}

function verifiesWithJwk(token, jwk) {
  log.debug("Entering verifiesWithJwk(). " + jwk.kty);
  let good = false;
  if (jwk.kty === "AKP") {
    const parts = String(token).split(".");
    const impl = { "ML-DSA-44": mldsa.ml_dsa44, "ML-DSA-65": mldsa.ml_dsa65,
                   "ML-DSA-87": mldsa.ml_dsa87 }[jwk.alg];
    good = !!impl && impl.verify(
      new Uint8Array(Buffer.from(jwk.pub, "base64url")),
      new Uint8Array(Buffer.from(parts[0] + "." + parts[1])),
      new Uint8Array(Buffer.from(parts[2], "base64url")));
  } else {
    good = jwsVerifies(token, nodeCrypto.createPublicKey({ key: jwk,
                                                           format: "jwk" }));
  }
  log.debug("Leaving verifiesWithJwk(). " + good);
  return good;
}

async function prepare(realm) {
  log.debug("Entering prepare(). " + realm);
  await ok(base + "/admin-api/realms/create", { id: realm,
    domain: realm + ".example.net", name: "JOSE kid " + STAMP },
    "created the realm " + realm);
  CREATED.push(realm);
  // Development is what this job asserts; a product stack's realms would
  // otherwise inherit the process's mode.
  await setting(realm, "global.mode", "development");
  const rb = base + "/realm/" + realm;
  await ok(rb + "/admin-api/users/create", { username: PERSON,
    invent: false, credential: "password", password: SECRET,
    attributes: { cn: "Kid " + PERSON, givenName: "Kid", sn: PERSON,
                  mail: PERSON + "@jkid.test" } }, "created " + PERSON);
  for (const one of [["jkid-rs", null], ["jkid-es", "ES256"],
                     ["jkid-pq", "ML-DSA-44"]]) {
    const fields = { oauthClientId: [one[0]], oauthClientSecret: SECRET,
                     oauthTokenEndpointAuthMethod: "client_secret_post",
                     oauthGrantType: ["password", "refresh_token"] };
    if (one[1]) {
      fields.oauthIdTokenSignedResponseAlg = one[1];
    }
    await ok(rb + "/admin-api/applications/create", { identifier: one[0],
      name: one[0], protocols: ["oauth2", "oidc"], fields: fields },
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
      password: SECRET, scope: "openid", client_id: clientId || "jkid-rs",
      client_secret: SECRET }).toString() });
  assert.strictEqual(r.status, 200, "the token endpoint in " + realm +
                     " answered " + r.status + " " + r.raw.slice(0, 400));
  log.debug("Leaving issue().");
  return r.body;
}

async function jwks(realm) {
  log.debug("Entering jwks(). " + realm);
  const r = await send(base + "/realm/" + realm + "/oauth2/jwks");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving jwks().");
  return r.body.keys;
}

async function signedMetadata(realm) {
  log.debug("Entering signedMetadata().");
  const r = await send(base + "/realm/" + realm +
                       "/.well-known/oauth-authorization-server");
  log.debug("Leaving signedMetadata().");
  return r.body && r.body.signed_metadata;
}

async function test() {
  log.debug("Entering test().");
  await prepare(REALM);

  log.info("=== A. the row ===");
  const row = await configRow(REALM, "keys.kidFormat");
  check("A1. keys.kidFormat is `internal` by default", function () {
    assert.ok(row, "no keys.kidFormat row");
    assert.strictEqual(String(row.value), "internal", JSON.stringify(row));
  });
  const bogus = await postJson(base + "/admin-api/realms/set", { id: REALM,
    key: "keys.kidFormat", value: "jwk-thumbprint" });
  check("A2. a format the library does not have is refused", function () {
    assert.ok(bogus.status >= 400 || (bogus.body && bogus.body.ok === false),
              bogus.status + " " + bogus.raw.slice(0, 300));
  });

  log.info("=== B. by default ===");
  let tokens = await issue(REALM);
  const before = tokens.access_token;
  let keys = await jwks(REALM);
  const internalKid = keys[0].kid;
  const metaBefore = await signedMetadata(REALM);
  check("B1. an access token and its ID Token carry the internal kid, the " +
        "RSA key's, keys[0]", function () {
    assert.strictEqual(keys[0].kty, "RSA");
    assert.strictEqual(headerOf(before).kid, internalKid);
    assert.strictEqual(headerOf(tokens.id_token).kid, internalKid);
    assert.ok(!isUri(internalKid), internalKid);
  });
  check("B2. and the JWK Set names no key by a thumbprint URI", function () {
    assert.ok(!keys.some(function (k) {
      return isUri(k.kid);
    }), keys.map(function (k) {
      return k.kid;
    }).join(", "));
  });
  check("B3. signed_metadata is signed under the internal kid too",
        function () {
    assert.ok(metaBefore, "no signed_metadata");
    assert.strictEqual(headerOf(metaBefore).kid, internalKid);
  });
  const offCount = keys.length;

  log.info("=== C. on ===");
  await setting(REALM, "keys.kidFormat", "jwk-thumbprint-uri");
  tokens = await issue(REALM);
  const access = tokens.access_token;
  const rsaUri = thumbprintUri(keys[0]);
  check("C1. the access token's kid is the RSA key's RFC 9278 URI, " +
        "computed here", function () {
    assert.strictEqual(headerOf(access).kid, rsaUri);
  });
  check("C2. and so is the ID Token's", function () {
    assert.strictEqual(headerOf(tokens.id_token).kid, rsaUri);
  });
  const metaAfter = await signedMetadata(REALM);
  check("C3. and signed_metadata's at once, although a copy under the " +
        "internal kid is still inside its cache window", function () {
    assert.strictEqual(headerOf(metaAfter).kid, rsaUri);
  });
  check("C4. the certificate header is unaffected", function () {
    assert.strictEqual(headerOf(before).x5u === undefined,
                       headerOf(access).x5u === undefined);
  });
  keys = await jwks(REALM);
  const kids = keys.map(function (k) {
    return k.kid;
  });
  const signing = keys.filter(function (k) {
    return k.use !== "enc" && !isUri(k.kid);
  });
  const uriEntries = keys.filter(function (k) {
    return isUri(k.kid);
  });
  check("C5. the RSA key is still keys[0], under its internal kid",
        function () {
    assert.strictEqual(kids[0], internalKid);
  });
  check("C6. every signing key is listed a second time under its own " +
        "thumbprint URI, computed here from the published members",
        function () {
    assert.strictEqual(uriEntries.length, signing.length);
    signing.forEach(function (k) {
      const uri = thumbprintUri(k);
      const twin = keys.filter(function (one) {
        return one.kid === uri;
      })[0];
      assert.ok(twin, "no URI entry for " + (k.alg || k.kty));
      assert.strictEqual(thumbprintUri(twin), uri);
    });
  });
  const firstUri = kids.findIndex(isUri);
  const lastSigning = keys.reduce(function (at, k, i) {
    return (k.use !== "enc" && !isUri(k.kid)) ? i : at;
  }, -1);
  const lastUri = keys.reduce(function (at, k, i) {
    return isUri(k.kid) ? i : at;
  }, -1);
  const firstEnc = keys.findIndex(function (k) {
    return k.use === "enc";
  });
  check("C7. the second entries follow every signing key and precede the " +
        "encryption keys", function () {
    assert.ok(firstUri > lastSigning && (firstEnc < 0 || firstEnc > lastUri),
              JSON.stringify({ firstUri: firstUri, lastSigning: lastSigning,
                               firstEnc: firstEnc }));
  });
  check("C8. nothing else in the set changed", function () {
    assert.strictEqual(keys.length, offCount + uriEntries.length);
  });
  const named = keys.filter(function (k) {
    return k.kid === rsaUri;
  })[0];
  const old = keys.filter(function (k) {
    return k.kid === internalKid;
  })[0];
  check("C9. the token verifies against the entry its kid names, and the " +
        "earlier token against the internal one", function () {
    assert.ok(verifiesWithJwk(access, named));
    assert.ok(verifiesWithJwk(before, old));
  });
  const es = await issue(REALM, "jkid-es");
  const esEntry = keys.filter(function (k) {
    return k.kid === headerOf(es.id_token).kid;
  })[0];
  check("C10. an ES256 ID Token carries its key's URI, listed over the " +
        "P-256 key, and verifies with it", function () {
    assert.ok(isUri(headerOf(es.id_token).kid), headerOf(es.id_token).kid);
    assert.ok(esEntry && esEntry.crv === "P-256", JSON.stringify(esEntry));
    assert.strictEqual(thumbprintUri(esEntry), esEntry.kid);
    assert.ok(verifiesWithJwk(es.id_token, esEntry));
  });
  const pq = await issue(REALM, "jkid-pq");
  const pqEntry = keys.filter(function (k) {
    return k.kid === headerOf(pq.id_token).kid;
  })[0];
  check("C11. an ML-DSA-44 ID Token carries its AKP key's URI over alg, kty " +
        "and pub, and verifies with it", function () {
    assert.strictEqual(headerOf(pq.id_token).alg, "ML-DSA-44");
    assert.ok(isUri(headerOf(pq.id_token).kid), headerOf(pq.id_token).kid);
    assert.ok(pqEntry && pqEntry.kty === "AKP" &&
              pqEntry.alg === "ML-DSA-44", JSON.stringify(pqEntry));
    assert.strictEqual(thumbprintUri(pqEntry), pqEntry.kid);
    assert.ok(verifiesWithJwk(pq.id_token, pqEntry));
  });
  const gnap = await send(base + "/realm/" + REALM + "/gnap/keys");
  check("C12. GNAP's key document names the kid its jwt-signed tokens carry",
        function () {
    assert.strictEqual(gnap.status, 200, gnap.raw.slice(0, 300));
    assert.strictEqual(gnap.body.jwt.kid, rsaUri, gnap.raw.slice(0, 300));
  });

  log.info("=== D. off again ===");
  await ok(base + "/realm/" + REALM + "/admin-api/config/reset",
           { key: "keys.kidFormat" }, "reset keys.kidFormat");
  tokens = await issue(REALM);
  keys = await jwks(REALM);
  check("D. turning it off restores the internal kid and drops the second " +
        "entries", function () {
    assert.strictEqual(headerOf(tokens.access_token).kid, internalKid);
    assert.ok(!keys.some(function (k) {
      return isUri(k.kid);
    }));
    assert.strictEqual(keys.length, offCount);
  });

  log.info("=== E. one realm ===");
  await prepare(OTHER);
  await setting(OTHER, "keys.kidFormat", "jwk-thumbprint-uri");
  const otherKeys = await jwks(OTHER);
  const otherTokens = await issue(OTHER);
  const mine = await jwks(REALM);
  check("E1. a realm carrying the setting signs under its own key's URI " +
        "and lists it", function () {
    const kid = headerOf(otherTokens.access_token).kid;
    assert.strictEqual(kid, thumbprintUri(otherKeys[0]));
    assert.ok(otherKeys.some(function (k) {
      return k.kid === kid;
    }));
    assert.notStrictEqual(kid, rsaUri);
  });
  check("E2. while the realm beside it, which does not, keeps its " +
        "internal kid and its JWK Set", function () {
    assert.ok(!mine.some(function (k) {
      return isUri(k.kid);
    }));
  });

  assert.ok(checks >= 18, "only " + checks + " checks ran; a section has " +
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
