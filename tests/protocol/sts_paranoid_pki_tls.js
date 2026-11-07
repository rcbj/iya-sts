// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_paranoid_pki_tls.js
//
// ===========================================================================
// PARANOID PKI MODE AT THE CLIENT-CERTIFICATE SIDE OF TLS (#1360, Phase 1).
//
// `local: true`, and `exclusive`: the hold is asked in the DEFAULT realm, because
// a handshake has no realm in it, so a realm's own master and row decide nothing
// there. Its section writes the default realm's master for a moment, and it adds
// a CA to the process's truststore. Both are put back in a `finally`. What it
// asserts is what the service does: the token endpoint's answer, what `GET
// /admin-api/tls-connection` reports of the connection it was asked over, and the
// door's own count of refusals.
//
// LDAPS and the debugger are not driven here: a stack does not publish either for
// a client certificate, and `tests/listener_path_rules.js` holds the same function
// on a listener of its own over real handshakes.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const credentials = require("../tools/pep-credential.js");
const kit = require("../tools/trust_kit.js");
const facts = require("./service_facts.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, the arrangement tests/vendored/wait_for.js has.
  appconfigProblem = e;
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_paranoid_pki_tls",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "paranoid-tls-" + STAMP;
const SELF_APP = "paranoid-self-" + STAMP;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function send(method, path, payload) {
  log.debug("Entering send(). " + method + " " + path);
  const target = new URL(base + path);
  const headers = { accept: "application/json" };
  const body = payload === undefined ? "" : JSON.stringify(payload);
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve, reject) {
    const transport = target.protocol === "http:" ? require("http") : https;
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers
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
          log.debug("Caught in send(): " + ((e && e.message) || e));
          json = null;
        }
        resolve({ status: res.statusCode, raw: raw, json: json });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

// A request over a TLS connection presenting a client certificate.
function tlsRequest(method, path, body, client, headers) {
  log.debug("Entering tlsRequest(). " + path);
  const target = new URL(base + path);
  log.debug("Leaving tlsRequest().");
  return new Promise(function (resolve, reject) {
    const req = https.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, cert: client.pem, key: client.key,
      rejectUnauthorized: false, agent: false,
      headers: Object.assign({ accept: "application/json" }, headers || {},
        body ? { "content-type": "application/x-www-form-urlencoded",
                 "content-length": Buffer.byteLength(body) } : {})
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
          log.debug("Caught in tlsRequest(): " + ((e && e.message) || e));
        }
        resolve({ status: res.statusCode, raw: raw, json: json });
      });
    });
    req.on("error", reject);
    req.end(body || "");
  });
}

function realmApi() {
  log.debug("Entering realmApi().");
  log.debug("Leaving realmApi().");
  return "/realm/" + REALM + "/admin-api";
}

async function setRow(prefix, setting, value) {
  log.debug("Entering setRow(). " + setting);
  const out = await send("POST", prefix + "/pki/trust/set-row",
                         { setting: setting, value: value });
  assert.strictEqual(out.status, 200, out.raw.slice(0, 300));
  log.debug("Leaving setRow().");
}

async function countOf(purpose) {
  log.debug("Entering countOf().");
  const view = await send("GET", realmApi() + "/pki/trust");
  log.debug("Leaving countOf().");
  return view.json.rows.filter(function (row) {
    return row.purpose === purpose;
  })[0];
}

// RFC 8705 section 2.2: equality is the method, and validity is not exempt.
async function anExpiredPinIsRefused() {
  log.debug("Entering anExpiredPinIsRefused().");
  log.info("=== a. self_signed_tls_client_auth ===");
  const now = Date.now();
  const expired = await kit.mint({ cn: SELF_APP,
    usages: ["digitalSignature"], notBefore: now - 3 * kit.DAY,
    notAfter: now - kit.DAY, signatureAlg: "sha256-rsa" });
  const x509 = new nodeCrypto.X509Certificate(expired.pem);
  const jwk = Object.assign(x509.publicKey.export({ format: "jwk" }),
    { kid: "self", x5c: [x509.raw.toString("base64")] });
  const made = await send("POST", realmApi() + "/applications/create", {
    identifier: SELF_APP, name: SELF_APP, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: SELF_APP,
              oauthTokenEndpointAuthMethod: "self_signed_tls_client_auth",
              oauthJwks: JSON.stringify({ keys: [jwk] }) } });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 400));
  const grant = "grant_type=client_credentials&client_id=" + SELF_APP;
  const url = "/realm/" + REALM + "/oauth2/token";
  await setRow(realmApi(), "pki.paranoid", "on");
  const before = await countOf("tls-client-self-signed");
  const refused = await tlsRequest("POST", url, grant, expired);
  // The refusal lands on one node and the count is read from another, so what
  // is awaited is the other node hearing of it. It may not be a different number.
  let after = await countOf("tls-client-self-signed");
  for (let i = 0; i < 75 && after.refused < before.refused + 1; i++) {
    await new Promise(function (resolve) {
      setTimeout(resolve, 200);
    });
    after = await countOf("tls-client-self-signed");
  }
  check("an expired registered certificate is refused at the token endpoint",
        function () {
    assert.ok(refused.status === 400 || refused.status === 401,
              refused.status + " " + refused.raw.slice(0, 300));
    assert.strictEqual(refused.json.error, "invalid_client", refused.raw);
  });
  check("no code is sent", function () {
    assert.ok(!/STS-[A-Z]+-[0-9]{4}/.test(refused.raw), refused.raw);
  });
  check("the door's count rises by one", function () {
    assert.strictEqual(after.refused, before.refused + 1);
    assert.ok(/expired/.test(after.lastRefusal), after.lastRefusal);
  });
  await setRow(realmApi(), "pki.paranoidTlsClientSelfSigned", false);
  const off = await tlsRequest("POST", url, grant, expired);
  check("with its row off it is accepted, as it was", function () {
    assert.strictEqual(off.status, 200, off.raw.slice(0, 300));
    assert.ok(off.json.access_token);
  });
  await setRow(realmApi(), "pki.paranoidTlsClientSelfSigned", true);
  await setRow(realmApi(), "pki.paranoid", "off");
  const masterOff = await tlsRequest("POST", url, grant, expired);
  check("and with the master off", function () {
    assert.strictEqual(masterOff.status, 200, masterOff.raw.slice(0, 300));
  });
  log.debug("Leaving anExpiredPinIsRefused().");
}

// The main port's hold: a CA presented as a client certificate. OpenSSL takes
// it, and the rules of `tls-client` do not.
async function theMainPortHolds() {
  log.debug("Entering theMainPortHolds().");
  log.info("=== b. the main port ===");
  const root = await kit.mint({ cn: "paranoid tls root " + STAMP, ca: true });
  const good = await kit.mint({ cn: "paranoid good " + STAMP, issuer: root,
                                eku: ["clientAuth"] });
  const caLeaf = await kit.mint({ cn: "paranoid ca " + STAMP, issuer: root,
    ca: true, pathLen: 0, usages: ["digitalSignature", "keyCertSign"],
    eku: ["clientAuth"] });
  const token = process.env.STS_ADMIN_API_TOKEN;
  const seen = async function (client) {
    log.debug("Entering seen().");
    const out = await tlsRequest("GET", "/admin-api/tls-connection", "", client,
                                 { authorization: "Bearer " + token });
    assert.strictEqual(out.status, 200, out.raw.slice(0, 300));
    log.debug("Leaving seen().");
    return out.json;
  };
  // Recorded BEFORE it is posted (#1307), so an add answered late is still
  // removed; the post is this job's own, through the management API.
  const added = [];
  credentials.recordAnchor(added, root.pem);
  const posted = await send("POST", "/admin-api/tls/trust/add",
                            { certificates: root.pem });
  assert.strictEqual(posted.status, 200, posted.raw.slice(0, 300));
  credentials.confirmAnchor(root.pem);
  const product = await facts.isProduct(base + "/admin-api");
  try {
    const before = await seen(caLeaf);
    await send("POST", "/admin-api/config/set",
               { key: "pki.paranoid", value: "on" });
    const onGood = await seen(good);
    const onCa = await seen(caLeaf);
    // A handshake has no realm in it, so a realm's row decides nothing here.
    await setRow(realmApi(), "pki.paranoidTlsClient", false);
    const realmRowOff = await seen(caLeaf);
    await setRow("/admin-api", "pki.paranoidTlsClient", false);
    const rowOff = await seen(caLeaf);
    const verified = function (view) {
      log.debug("Entering verified().");
      log.debug("Leaving verified().");
      return view.clientCertificate && view.clientCertificate.verified;
    };
    check("by default, a CA presented as a client is unverified in product " +
          "and verifies in development", function () {
      assert.strictEqual(verified(before), !product,
                         JSON.stringify(before).slice(0, 400));
    });
    check("master on, a good client verifies", function () {
      assert.strictEqual(verified(onGood), true,
                         JSON.stringify(onGood).slice(0, 400));
    });
    check("and a CA presented as a client is treated as unverified",
          function () {
      assert.strictEqual(verified(onCa), false,
                         JSON.stringify(onCa).slice(0, 400));
    });
    check("a realm's own row off changes nothing at a handshake", function () {
      assert.strictEqual(verified(realmRowOff), false,
                         JSON.stringify(realmRowOff).slice(0, 400));
    });
    check("with the default realm's row off it verifies again", function () {
      assert.strictEqual(verified(rowOff), true,
                         JSON.stringify(rowOff).slice(0, 400));
    });
  } finally {
    await send("POST", "/admin-api/config/reset",
               { key: "pki.paranoidTlsClient" });
    await send("POST", "/admin-api/config/reset", { key: "pki.paranoid" });
    await credentials.settleAnchors(base, added, null);
  }
  log.debug("Leaving theMainPortHolds().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Paranoid PKI at the client-certificate side of TLS, " + base);
  const made = await send("POST", "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net", name: REALM });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  await anExpiredPinIsRefused();
  await theMainPortHolds();
  assert.ok(checks >= 9, "only " + checks + " checks ran; a section has " +
                                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_paranoid_pki_tls")
  .description("Paranoid PKI at the client-certificate side of TLS (#1360).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
