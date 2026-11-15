// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_tls_client_certificates.js
//
// ---------------------------------------------------------------------------
// A PERSON'S TLS CLIENT CERTIFICATE AND THE IDENTITY GATE, OVER THE WIRE
// (2026-09-13, #671, #1290).
//
// D12 (#444): carries over tests/tls_client_certificates.js's claims that a
// client can see. Two people in a throwaway realm, each signed in to the
// portal as the static portal does (`portal_signin.js`), issue themselves
// credentials at `/account-api/signing-key` and present them to
// `GET /tls/sign-in` on the main port:
//
//   A. THE CERTIFICATE: `clientAuth`, the person's CN and
//      `urn:sts:person:` name, their mail as the rfc822Name, issued by THIS
//      realm's TLS Client Issuing CA; the key handed back is the
//      certificate's; and the refusals by code, read off the realm's audit —
//      a key algorithm a browser does not present (refused by the account
//      API's request model first, STS-ACCOUNT-0018), a label that is not a
//      short name (STS-PKI-0169), the cap
//      (`pki.personTlsClientCertificateMax`, STS-PKI-0170);
//   B. THE FILES: the key and the chain as PEM (#671 dropped the PKCS#12),
//      the chain the leaf and its Issuing CA;
//   C/D. THE GATE AND THE DOOR, over a real handshake: the TLS client leaf
//      signs its holder in, IN ITS REALM, the answer naming them; the same
//      person's RFC 7523 signing key pair (same Root, same realm, same
//      person) is presented, verifies, and starts no session; the leaf
//      asked at another realm's path signs its holder in to THEIR realm
//      (the session goes in the realm of the authority that signed the
//      leaf: root CLAUDE.md, *Trust realms*, 5); somebody else's revocation of
//      it is refused (STS-PKI-0171); and the holder's own leaves it
//      signing nobody in.
//
// What stays in process (class (d)): no private key in the register, and
// `mtls.peerVerified()` — both internal state; the fixtures that each break
// ONE rule of the gate (a `clientAuth` leaf from the assertions authority, a
// `tls-client` leaf with no `clientAuth`, CN and SAN disagreeing), which no
// door of this service issues.
//
// It runs in a development realm: in product a certificate is a first
// factor and a sign-in asks for a second (rcbj, 2026-11-09), which is the
// sign-in surface's own job.
//
// OWNED HERE (local: true): this repository's own portal, account API and
// main port.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const https = require("https");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_tls_client_certificates",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TARGET = new URL(base);
const STAMP = names.runStamp();
function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                       .slice(0, 31);
}
const REALM = realmId("tlscc-");
const OTHER_REALM = realmId("tlsco-");
const ALICE = ("alice" + STAMP).toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 30);
const BOB = ("bob" + STAMP).toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 30);
const PASSWORD = "Tls-Client-" + String(Date.now()).slice(-8) + "-Pw!x";

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

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const r = await fetch(base + path, {
    method: method,
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload) });
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in api(): " + ((e && e.message) || e));
    // Not JSON; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving api(). " + r.status);
  return { status: r.status, body: body, raw: raw };
}

async function ok(method, path, payload, what) {
  log.debug("Entering ok().");
  const r = await api(method, path, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
            what + ": " + method + " " + path + " answered " + r.status +
            " " + r.raw.slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await api("GET", "/realm/" + realm + "/admin-api/audit?per=500" +
                      "&code=" + encodeURIComponent(code));
  const rows = (r.body && (r.body.events || r.body.rows)) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return rows.length;
}

async function sawCode(realm, code, before) {
  log.debug("Entering sawCode(). " + code);
  for (let i = 0; i < 30; i += 1) {
    if (await codeCount(realm, code) > before) {
      log.debug("Leaving sawCode(). Seen.");
      return true;
    }
    await sleep(200);
  }
  log.debug("Leaving sawCode(). Not seen.");
  return false;
}

// `GET <path>` over a connection of its own presenting `cert`/`key`.
function present(path, cert, key) {
  log.debug("Entering present(). " + path);
  log.debug("Leaving present().");
  return new Promise(function (resolve, reject) {
    const req = https.request({
      method: "GET", hostname: TARGET.hostname, port: TARGET.port,
      path: path, agent: false, cert: cert, key: key,
      headers: { accept: "application/json", authorization: "none" }
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in present(): " + ((e && e.message) || e));
          // Not JSON; the caller reads `raw`.
          json = null;
        }
        resolve({ status: res.statusCode, json: json, raw: raw,
                  cookies: res.headers["set-cookie"] || [] });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function fileText(file) {
  log.debug("Entering fileText().");
  log.debug("Leaving fileText().");
  return Buffer.from(String(file.base64), "base64").toString("utf8");
}

function pemBlocks(text) {
  log.debug("Entering pemBlocks().");
  log.debug("Leaving pemBlocks().");
  return String(text).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
}

async function person(username) {
  log.debug("Entering person(). " + username);
  await ok("POST", "/realm/" + REALM + "/admin-api/users/create", {
    username: username, invent: false, credential: "password",
    password: PASSWORD,
    attributes: { givenName: "Tls", sn: username,
                  mail: username + "@" + REALM + ".example.net" } },
    "created " + username);
  const browser = await portal.signInToThePortal(base + "/realm/" + REALM,
    username, null, { password: PASSWORD });
  log.debug("Leaving person().");
  return browser;
}

// The TLS client certificate a person issues themselves; the answer's
// `view.fresh`, shown once.
async function issueTls(browser, label, keyAlg) {
  log.debug("Entering issueTls().");
  const r = await browser.act("/portal/signing-key",
    { action: "generate-tls-client", label: label, key_alg: keyAlg });
  log.debug("Leaving issueTls(). " + r.status);
  return r;
}

async function signedIn(path, cert, key) {
  log.debug("Entering signedIn().");
  let r = null;
  // A new realm authority reaches the handshake truststore on the node's
  // next change pull, so the first full handshake is retried briefly.
  for (let i = 0; i < 20; i += 1) {
    r = await present(path, cert, key);
    const cc = (r.json && r.json.clientCertificate) || r.json || {};
    if (r.json && (r.json.signedIn === true || cc.verified === true)) {
      break;
    }
    await sleep(500);
  }
  log.debug("Leaving signedIn().");
  return r;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. two throwaway realms and two people ===");
  for (const id of [REALM, OTHER_REALM]) {
    await ok("POST", "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "TLS client " + STAMP },
      "created the realm " + id);
  }
  // A generation per check below, against a limit of five per window.
  await ok("POST", "/realm/" + REALM + "/admin-api/config/set",
           { key: "pki.personSelfServicePerIdentity", value: 100 },
           "raised the per-identity limit in the realm");
  await ok("POST", "/realm/" + REALM + "/admin-api/config/set",
           { key: "pki.personSelfServicePerAddress", value: 100 },
           "raised the per-address limit in the realm");
  const alice = await person(ALICE);
  const bob = await person(BOB);

  log.info("=== A. the certificate, and its refusals ===");
  const issued = await issueTls(alice, "laptop", "ec-p256");
  assert.strictEqual(issued.status, 200, String(issued.text).slice(0, 400));
  const fresh = issued.json.view.fresh;
  const chainText = fileText(fresh.files.chain);
  const keyText = fileText(fresh.files.key);
  const blocks = pemBlocks(chainText);
  const leaf = new crypto.X509Certificate(blocks[0]);
  const issuer = new crypto.X509Certificate(blocks[1] || blocks[0]);
  check("A. a clientAuth certificate naming the person by CN and " +
        "urn:sts:person:, their mail the rfc822Name", function () {
    assert.ok(/CN=/.test(leaf.subject) &&
              leaf.subject.indexOf(ALICE) >= 0, leaf.subject);
    assert.ok(String(leaf.subjectAltName).indexOf("urn:sts:person:" +
              ALICE) >= 0, leaf.subjectAltName);
    assert.ok(String(leaf.subjectAltName).indexOf("email:" + ALICE + "@") >=
              0, leaf.subjectAltName);
    assert.ok((leaf.toLegacyObject().ext_key_usage || [])
      .indexOf("1.3.6.1.5.5.7.3.2") >= 0,
      JSON.stringify(leaf.toLegacyObject().ext_key_usage));
    assert.strictEqual(fresh.issued.serialHex.toLowerCase(),
                       leaf.serialNumber.toLowerCase());
  });
  check("A. issued by this realm's TLS Client Issuing CA", function () {
    assert.ok(leaf.verify(issuer.publicKey), "the chain's second " +
              "certificate did not sign the leaf");
    assert.ok(/TLS Client/i.test(issuer.subject), issuer.subject);
    assert.ok(issuer.subject.indexOf(REALM) >= 0 ||
              leaf.issuer.indexOf(REALM) >= 0, issuer.subject);
  });
  check("B. the key and the chain arrive as PEM, the key the " +
        "certificate's", function () {
    assert.ok(/-----BEGIN (EC )?PRIVATE KEY-----/.test(keyText),
              keyText.slice(0, 60));
    assert.strictEqual(blocks.length >= 2, true, chainText.slice(0, 200));
    const pub = crypto.createPublicKey(crypto.createPrivateKey(keyText))
      .export({ type: "spki", format: "der" });
    assert.ok(pub.equals(leaf.publicKey.export({ type: "spki",
                                                 format: "der" })));
  });
  const before18 = await codeCount(REALM, "STS-ACCOUNT-0018");
  const badAlg = await issueTls(alice, "laptop2", "ed25519");
  const saw18 = await sawCode(REALM, "STS-ACCOUNT-0018", before18);
  check("A. a key algorithm a browser does not present is refused 400 — " +
        "by the account API's request model, whose key_alg is a closed " +
        "list (STS-ACCOUNT-0018, where the in-process call meets " +
        "STS-PKI-0169)", function () {
    assert.strictEqual(badAlg.status, 400, String(badAlg.text).slice(0, 300));
    assert.ok(saw18, "no STS-ACCOUNT-0018 row");
  });
  const before169 = await codeCount(REALM, "STS-PKI-0169");
  const badLabel = await issueTls(alice, "<script>", "ec-p256");
  const saw169 = await sawCode(REALM, "STS-PKI-0169", before169);
  check("A. a label that is not a short name is refused 400 " +
        "(STS-PKI-0169)", function () {
    assert.strictEqual(badLabel.status, 400,
                       String(badLabel.text).slice(0, 300));
    assert.ok(saw169, "no STS-PKI-0169 row");
  });
  await ok("POST", "/realm/" + REALM + "/admin-api/config/set",
           { key: "pki.personTlsClientCertificateMax", value: 1 },
           "capped the person at one certificate");
  const before170 = await codeCount(REALM, "STS-PKI-0170");
  const capped = await issueTls(alice, "phone", "ec-p256");
  const saw170 = await sawCode(REALM, "STS-PKI-0170", before170);
  await ok("POST", "/realm/" + REALM + "/admin-api/config/reset",
           { key: "pki.personTlsClientCertificateMax" }, "lifted the cap");
  check("A. the cap refuses a second valid certificate (STS-PKI-0170)",
        function () {
    assert.strictEqual(capped.status, 400, String(capped.text).slice(0, 300));
    assert.ok(saw170, "no STS-PKI-0170 row");
  });

  log.info("=== C/D. the gate and the door ===");
  const signInPath = "/realm/" + REALM + "/tls/sign-in";
  const signed = await signedIn(signInPath, chainText, keyText);
  check("D. the TLS client certificate signs its holder in, in its realm",
        function () {
    assert.strictEqual(signed.status, 200, signed.raw.slice(0, 300));
    assert.strictEqual(signed.json.signedIn, true, signed.raw.slice(0, 400));
    assert.strictEqual((signed.json.session || {}).username, ALICE,
                       signed.raw.slice(0, 400));
    assert.strictEqual((signed.json.session || {}).realm, REALM,
                       signed.raw.slice(0, 400));
    assert.ok(signed.cookies.length > 0, "no session cookie was set");
  });
  const elsewhere = await present("/realm/" + OTHER_REALM + "/tls/sign-in",
                                  chainText, keyText);
  check("C. asked at another realm's path, the certificate still signs its " +
        "holder in to THEIR realm, the realm of the authority that signed " +
        "it, never the realm the path names", function () {
    assert.strictEqual(elsewhere.status, 200, elsewhere.raw.slice(0, 300));
    const s = elsewhere.json.session || {};
    assert.strictEqual(s.realm, REALM, elsewhere.raw.slice(0, 400));
    assert.strictEqual(s.username, ALICE, elsewhere.raw.slice(0, 400));
  });
  const assertion = await alice.act("/portal/signing-key",
    { action: "generate", purpose: "jwt", label: "assertions" });
  assert.strictEqual(assertion.status, 200,
                     String(assertion.text).slice(0, 400));
  const aFresh = assertion.json.view.fresh || {};
  const aFiles = aFresh.files || {};
  const aCert = fileText(aFiles.chain || aFiles.certificate || {});
  const aKey = fileText(aFiles.key || {});
  const viaAssertion = await signedIn(signInPath, aCert, aKey);
  check("C. the same person's RFC 7523 signing key pair verifies and starts " +
        "no session: it is not an identity", function () {
    assert.ok(/BEGIN CERTIFICATE/.test(aCert), JSON.stringify(Object.keys(
      aFiles)));
    assert.strictEqual(viaAssertion.status, 200,
                       viaAssertion.raw.slice(0, 300));
    assert.notStrictEqual(viaAssertion.json.signedIn, true,
                          viaAssertion.raw.slice(0, 400));
  });
  const before171 = await codeCount(REALM, "STS-PKI-0171");
  const notTheirs = await bob.act("/portal/signing-key",
    { action: "revoke-tls-client", serial: fresh.issued.serialHex,
      reason: "keyCompromise" });
  const saw171 = await sawCode(REALM, "STS-PKI-0171", before171);
  const stillSigned = await present(signInPath, chainText, keyText);
  check("D. somebody else cannot revoke it (400, STS-PKI-0171), and it " +
        "still signs its holder in", function () {
    assert.strictEqual(notTheirs.status, 400,
                       String(notTheirs.text).slice(0, 300));
    assert.ok(saw171, "no STS-PKI-0171 row");
    assert.strictEqual(stillSigned.json && stillSigned.json.signedIn, true,
                       stillSigned.raw.slice(0, 300));
  });
  const revoked = await alice.act("/portal/signing-key",
    { action: "revoke-tls-client", serial: fresh.issued.serialHex,
      reason: "keyCompromise" });
  assert.strictEqual(revoked.status, 200, String(revoked.text).slice(0, 300));
  let after = null;
  for (let i = 0; i < 20; i += 1) {
    after = await present(signInPath, chainText, keyText);
    if (after.json && after.json.signedIn !== true) {
      break;
    }
    await sleep(500);
  }
  check("D. revoked by its holder, it signs nobody in", function () {
    assert.strictEqual(after.status, 200, after.raw.slice(0, 300));
    assert.notStrictEqual(after.json.signedIn, true, after.raw.slice(0, 400));
  });
  log.info("sts_tls_client_certificates: " + checks + " checks passed.");
  log.debug("Leaving test().");
}

test().then(function () {
  log.info("Test completed successfully.");
}).catch(function (e) {
  log.error("sts_tls_client_certificates FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
