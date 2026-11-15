// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_signer_chain_validation.js
//
// ---------------------------------------------------------------------------
// THE SIGNER CERTIFICATE'S WHOLE CHAIN, VALIDATED WHERE AN RFC 7523 SIGNATURE
// IS, OVER THE WIRE.
//
// D12 (#444): carries over the part of `tests/signer_chain_validation.js` a
// client can see, at a throwaway realm's token endpoint. The in-process
// file's reason for staying in process — every interesting input is a
// hierarchy nobody would deploy — is answered here by building those
// hierarchies with node-forge in the job and registering them through
// `/admin-api/applications/set`. Codes are read off `/admin-api/audit`:
//
//   1. a key pair `/admin-api/pki/issue` made verifies an RFC 7523 grant by
//      kid and by its x5c chain;
//   2. a certificate forged under that LEAF (an end-entity used as an
//      issuer) presented in x5c is refused — PINNED: recorded STS-OAUTH-0047
//      (the signature), not STS-PKI-0158;
//   3. registered keys, checked at USE: a self-signed certificate pinned is
//      accepted even with cA=TRUE; an expired one is refused (STS-PKI-0157);
//      one holding another key than its JWK (STS-PKI-0160); a chain through
//      an end-entity certificate and an external CA without keyCertSign
//      (STS-PKI-0158); an external chain is accepted with its root and
//      refused without it; an unreadable certificate, taken at the write,
//      is refused at use (STS-PKI-0161); a bare key with no chain is still
//      accepted;
//   4. another realm's leaf registered here is refused, and a registered
//      realm leaf is refused once its branch is rebuilt;
//   5. client authentication (private_key_jwt at a PRODUCT realm, which
//      checks it) refuses a key whose pinned certificate expired, with the
//      same code, and accepts the same key bare.
//
// NOT carried, and why: `pki.verifyLeaf()` and `verifySignerChain()` as
// library calls (the same inputs drive them here through the grant),
// STS-PKI-0159 (an Issuing CA presented as the signer needs that CA's
// private key, which only this service holds; a leaf without
// digitalSignature is owed), and RFC 7522 by value, managed and pinned
// (owed by the SAML bearer grant's job, `sts_saml2_bearer_grant.js`).
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
var log = bunyan.createLogger({ name: "sts_signer_chain_validation",
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

const forge = require("node-forge");

const REALM = "scv-" + STAMP;
const OTHER = "scvo-" + STAMP;
const CREATED = [];
const ISS = "scv-iss-" + STAMP;
const PERSON = "scv-" + STAMP;
const GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
let jtiCounter = 0;

function api(realmId) {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return base + "/realm/" + realmId + "/admin-api";
}

function tokenUrl(realmId) {
  log.debug("Entering tokenUrl().");
  log.debug("Leaving tokenUrl().");
  return base + "/realm/" + realmId + "/oauth2/token";
}

function b64u(value) {
  log.debug("Entering b64u().");
  log.debug("Leaving b64u().");
  return Buffer.from(value).toString("base64url");
}

function jws(header, claims, keyPem) {
  log.debug("Entering jws().");
  const input = b64u(JSON.stringify(header)) + "." +
                b64u(JSON.stringify(claims));
  const sig = nodeCrypto.sign("sha256", Buffer.from(input), keyPem);
  log.debug("Leaving jws().");
  return input + "." + sig.toString("base64url");
}

function claims(realmId, iss, sub) {
  log.debug("Entering claims().");
  const now = Math.floor(Date.now() / 1000);
  jtiCounter += 1;
  log.debug("Leaving claims().");
  return { iss: iss || ISS, sub: sub || PERSON, aud: tokenUrl(realmId),
           iat: now, exp: now + 120,
           jti: "scv-" + jtiCounter + "-" +
                nodeCrypto.randomBytes(6).toString("hex") };
}

function grant(realmId, assertion) {
  log.debug("Entering grant().");
  log.debug("Leaving grant().");
  return send(tokenUrl(realmId), { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: GRANT, assertion: assertion })
      .toString() });
}

// A certificate made here. `opts`: cn, issuer (forge attributes; self-issued
// when absent), signer (a forge private key; its own when absent), ca,
// keyCertSign, notBefore, notAfter, publicKey (another key than its own).
function makeCert(opts) {
  log.debug("Entering makeCert(). " + opts.cn);
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const c = forge.pki.createCertificate();
  c.publicKey = opts.publicKey || keys.publicKey;
  c.serialNumber = "01" + nodeCrypto.randomBytes(8).toString("hex");
  c.validity.notBefore = opts.notBefore || new Date(Date.now() - 3600e3);
  c.validity.notAfter = opts.notAfter || new Date(Date.now() + 86400e3);
  const subject = [{ name: "commonName", value: opts.cn }];
  c.setSubject(subject);
  c.setIssuer(opts.issuer || subject);
  c.setExtensions([{ name: "basicConstraints", cA: !!opts.ca },
    { name: "keyUsage", digitalSignature: !opts.ca || !!opts.keyCertSign,
      keyCertSign: !!opts.keyCertSign, cRLSign: !!opts.keyCertSign }]);
  c.sign(opts.signer || keys.privateKey, forge.md.sha256.create());
  log.debug("Leaving makeCert().");
  return { cert: c, keys: keys,
           b64: forge.util.encode64(forge.asn1.toDer(
             forge.pki.certificateToAsn1(c)).getBytes()),
           keyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

function jwkOf(keyPem, kid, x5c) {
  log.debug("Entering jwkOf(). " + kid);
  const jwk = Object.assign(nodeCrypto.createPublicKey(keyPem)
    .export({ format: "jwk" }), { kid: kid, use: "sig", alg: "RS256" });
  if (x5c) {
    jwk.x5c = x5c;
  }
  log.debug("Leaving jwkOf().");
  return jwk;
}

async function codeCount(realmId, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api(realmId) + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

// The request `fn` makes is refused with `error`, and `code` is recorded for
// it: the count rises by one at least, and the answer names no code.
async function refusedWith(realmId, code, error, what, fn) {
  log.debug("Entering refusedWith(). " + code);
  const before = await codeCount(realmId, code);
  const r = await fn();
  let after = await codeCount(realmId, code);
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(realmId, code);
  }
  check(what + " (" + code + ")", function () {
    assert.ok(r.status === 400 || r.status === 401, r.status + " " +
              r.raw.slice(0, 300));
    assert.strictEqual(r.body.error, error, r.raw.slice(0, 300));
    assert.ok(after > before, code + " rows " + before + " -> " + after);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), r.raw.slice(0, 300));
  });
  log.debug("Leaving refusedWith().");
  return r;
}

async function register(realmId, app, keys) {
  log.debug("Entering register(). " + app);
  await ok(api(realmId) + "/applications/set", { application: app,
    attribute: "oauthAssertionJwks", value: JSON.stringify({ keys: keys }) },
    "registered " + keys.length + " key(s) on " + app);
  log.debug("Leaving register().");
}

async function prepare(realmId) {
  log.debug("Entering prepare(). " + realmId);
  await ok(base + "/admin-api/realms/create", { id: realmId,
    domain: realmId + ".example.net", name: "Signer chains " + STAMP },
    "created the realm " + realmId);
  CREATED.push(realmId);
  // Development is what sections 1-4 assert (section 5 switches it).
  await setting(realmId, "global.mode", "development");
  await ok(api(realmId) + "/pki/build", { organisation: "Signer chains",
    country: "US" }, "built the realm's certificate authority");
  await ok(api(realmId) + "/users/create", { username: PERSON,
    invent: false, credential: "none", attributes: { cn: "SCV " + PERSON,
      givenName: "SCV", sn: PERSON, mail: PERSON + "@scv.test" } },
    "created " + PERSON);
  await ok(api(realmId) + "/applications/create", { identifier: "scv-app",
    name: "scv-app", protocols: ["oauth2"],
    fields: { oauthClientId: ["scv-app"] } }, "registered scv-app");
  const issued = await ok(api(realmId) + "/pki/issue",
                          { identifier: "scv-app" }, "issued a key pair");
  const pk = (await ok(api(realmId) + "/applications/reveal-secret",
    { application: "scv-app", secret: "oauthAssertionPrivateKey" },
    "revealed the private key")).value;
  const view = await send(api(realmId) + "/applications?application=scv-app");
  const fields = (view.body.application || view.body).fields;
  await ok(api(realmId) + "/applications/add", { application: "scv-app",
    attribute: "oauthAssertionIssuer", value: ISS }, "declared the issuer");
  log.debug("Leaving prepare().");
  return { kid: issued.kid, privateKeyPem: pk,
           jwks: JSON.parse(fields.oauthAssertionJwks) };
}

async function test() {
  log.debug("Entering test().");
  const mine = await prepare(REALM);
  const x5c = mine.jwks.keys[0].x5c;

  log.info("=== 1. the realm's own key pair ===");
  const byKid = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: mine.kid }, claims(REALM), mine.privateKeyPem));
  const byChain = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    x5c: x5c }, claims(REALM), mine.privateKeyPem));
  check("1. an issued key pair verifies the grant by kid and by its chain",
        function () {
    assert.strictEqual(byKid.status, 200, byKid.raw.slice(0, 300));
    assert.strictEqual(byChain.status, 200, byChain.raw.slice(0, 300));
    assert.strictEqual(x5c.length, 4);
  });

  log.info("=== 2. a certificate forged under the leaf ===");
  const leaf = forge.pki.certificateFromAsn1(forge.asn1.fromDer(
    forge.util.decode64(x5c[0])));
  const leafKey = forge.pki.privateKeyFromPem(mine.privateKeyPem);
  const forged = makeCert({ cn: "forged under a leaf",
                            issuer: leaf.subject.attributes,
                            signer: leafKey });
  await refusedWith(REALM, "STS-OAUTH-0047", "invalid_grant",
    "2. a certificate forged under the issued LEAF, in x5c, is refused — " +
    "PINNED: recorded as a signature that did not verify", function () {
      return grant(REALM, jws({ alg: "RS256", typ: "JWT",
        x5c: [forged.b64].concat(x5c) }, claims(REALM), forged.keyPem));
    });

  log.info("=== 3. registered keys, checked at use ===");
  const pinned = makeCert({ cn: "pinned self-signed CA", ca: true,
                            keyCertSign: true });
  await register(REALM, "scv-app", [jwkOf(pinned.keyPem, "pin1",
                                          [pinned.b64])]);
  const pinnedUse = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: "pin1" }, claims(REALM), pinned.keyPem));
  check("3a. a self-signed certificate pinned is accepted, even with " +
        "cA=TRUE", function () {
    assert.strictEqual(pinnedUse.status, 200, pinnedUse.raw.slice(0, 300));
  });
  const expired = makeCert({ cn: "expired pinned",
    notBefore: new Date(Date.now() - 10 * 86400e3),
    notAfter: new Date(Date.now() - 86400e3) });
  await register(REALM, "scv-app", [jwkOf(expired.keyPem, "exp1",
                                          [expired.b64])]);
  await refusedWith(REALM, "STS-PKI-0157", "invalid_grant",
    "3b. an expired pinned certificate is refused at use", function () {
      return grant(REALM, jws({ alg: "RS256", typ: "JWT", kid: "exp1" },
                              claims(REALM), expired.keyPem));
    });
  const stranger = makeCert({ cn: "holds another key" });
  await register(REALM, "scv-app", [jwkOf(pinned.keyPem, "mis1",
                                          [stranger.b64])]);
  await refusedWith(REALM, "STS-PKI-0160", "invalid_grant",
    "3c. a certificate holding another key than its JWK is refused",
    function () {
      return grant(REALM, jws({ alg: "RS256", typ: "JWT", kid: "mis1" },
                              claims(REALM), pinned.keyPem));
    });
  await register(REALM, "scv-app", [jwkOf(forged.keyPem, "ee1",
                                          [forged.b64].concat(x5c))]);
  await refusedWith(REALM, "STS-PKI-0158", "invalid_grant",
    "3d. a registered chain through an end-entity certificate is refused",
    function () {
      return grant(REALM, jws({ alg: "RS256", typ: "JWT", kid: "ee1" },
                              claims(REALM), forged.keyPem));
    });
  const root = makeCert({ cn: "external root", ca: true, keyCertSign: true });
  const extLeaf = makeCert({ cn: "external leaf",
                             issuer: root.cert.subject.attributes,
                             signer: root.keys.privateKey });
  await register(REALM, "scv-app", [jwkOf(extLeaf.keyPem, "ext1",
                                          [extLeaf.b64, root.b64])]);
  const withRoot = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: "ext1" }, claims(REALM), extLeaf.keyPem));
  check("3e. an external chain is accepted with its root", function () {
    assert.strictEqual(withRoot.status, 200, withRoot.raw.slice(0, 300));
  });
  await register(REALM, "scv-app", [jwkOf(extLeaf.keyPem, "ext2",
                                          [extLeaf.b64])]);
  const alone = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: "ext2" }, claims(REALM), extLeaf.keyPem));
  check("3f. and refused without it", function () {
    assert.strictEqual(alone.status, 400, alone.raw.slice(0, 300));
    assert.strictEqual(alone.body.error, "invalid_grant");
    assert.ok(/trust chain/.test(alone.body.error_description),
              alone.body.error_description);
  });
  const noSign = makeCert({ cn: "CA without keyCertSign", ca: true,
                            keyCertSign: false });
  const underNoSign = makeCert({ cn: "leaf of a CA without keyCertSign",
                                 issuer: noSign.cert.subject.attributes,
                                 signer: noSign.keys.privateKey });
  await register(REALM, "scv-app", [jwkOf(underNoSign.keyPem, "nks1",
                                          [underNoSign.b64, noSign.b64])]);
  await refusedWith(REALM, "STS-PKI-0158", "invalid_grant",
    "3g. a chain through a CA without keyCertSign is refused", function () {
      return grant(REALM, jws({ alg: "RS256", typ: "JWT", kid: "nks1" },
                              claims(REALM), underNoSign.keyPem));
    });
  const bare = makeCert({ cn: "bare key" });
  await register(REALM, "scv-app", [jwkOf(bare.keyPem, "bare1")]);
  const bareUse = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: "bare1" }, claims(REALM), bare.keyPem));
  check("3h. a bare key, which has no chain, is still accepted", function () {
    assert.strictEqual(bareUse.status, 200, bareUse.raw.slice(0, 300));
  });

  await register(REALM, "scv-app", [jwkOf(bare.keyPem, "bad1",
                                          ["AAAAnotacertificate"])]);
  await refusedWith(REALM, "STS-PKI-0161", "invalid_grant",
    "3i. an unreadable certificate, taken at the write, is refused at use",
    function () {
      return grant(REALM, jws({ alg: "RS256", typ: "JWT", kid: "bad1" },
                              claims(REALM), bare.keyPem));
    });

  log.info("=== 4. realms and branches ===");
  const theirs = await prepare(OTHER);
  await register(REALM, "scv-app", [jwkOf(theirs.privateKeyPem, "oth1",
                                          theirs.jwks.keys[0].x5c)]);
  const across = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: "oth1" }, claims(REALM), theirs.privateKeyPem));
  check("4a. another realm's leaf registered here is refused", function () {
    assert.strictEqual(across.status, 400, across.raw.slice(0, 300));
    assert.strictEqual(across.body.error, "invalid_grant");
  });
  await register(REALM, "scv-app", mine.jwks.keys);
  const stillOk = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: mine.kid }, claims(REALM), mine.privateKeyPem));
  await ok(api(REALM) + "/pki/build", { organisation: "Signer chains again",
    country: "US" }, "rebuilt the realm's branch");
  const rebuilt = await grant(REALM, jws({ alg: "RS256", typ: "JWT",
    kid: mine.kid }, claims(REALM), mine.privateKeyPem));
  check("4b. a registered realm leaf verifies until its branch is rebuilt, " +
        "and is refused after", function () {
    assert.strictEqual(stillOk.status, 200, stillOk.raw.slice(0, 300));
    assert.strictEqual(rebuilt.status, 400, rebuilt.raw.slice(0, 300));
    assert.strictEqual(rebuilt.body.error, "invalid_grant");
  });

  log.info("=== 5. client authentication, in product ===");
  await setting(REALM, "global.mode", "product");
  await ok(api(REALM) + "/applications/create", { identifier: "scv-cli",
    name: "scv-cli", protocols: ["oauth2"],
    fields: { oauthClientId: ["scv-cli"],
              oauthTokenEndpointAuthMethod: "private_key_jwt",
              oauthGrantType: ["client_credentials"],
              oauthJwks: JSON.stringify({ keys: [jwkOf(expired.keyPem,
                "cexp", [expired.b64])] }) } }, "registered scv-cli");
  const clientAuth = function (kid) {
    return send(tokenUrl(REALM), { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials",
        client_id: "scv-cli", client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: jws({ alg: "RS256", typ: "JWT", kid: kid },
          claims(REALM, "scv-cli", "scv-cli"), expired.keyPem) })
        .toString() });
  };
  await refusedWith(REALM, "STS-PKI-0157", "invalid_client",
    "5a. client authentication refuses a key whose pinned certificate " +
    "expired", function () {
      return clientAuth("cexp");
    });
  await ok(api(REALM) + "/applications/set", { application: "scv-cli",
    attribute: "oauthJwks", value: JSON.stringify({ keys: [jwkOf(
      expired.keyPem, "cbare")] }) }, "registered the same key bare");
  const bareClient = await clientAuth("cbare");
  check("5b. and accepts the same key bare", function () {
    assert.strictEqual(bareClient.status, 200, bareClient.raw.slice(0, 300));
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
