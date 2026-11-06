// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_paranoid_pki_outbound.js
//
// ===========================================================================
// PARANOID PKI MODE AT AN OUTBOUND REQUEST (#1360, Phase 2).
//
// `local: true`. In a realm of its own, the service dials listeners this job runs,
// through the RFC 9728 import, which takes a URL and fetches it under federation's
// outbound policy. Each listener counts what it is asked. The assertions are the
// operation's answer and that count: a refused server is asked NOTHING.
//
//   * a certificate from a CA only the realm's signer truststore holds is reached,
//     so an operator names a private CA once;
//   * revoked (a CRL this job serves over plain http) and an EKU that omits
//     serverAuth are refused, and nothing is requested of them;
//   * with the row or the master off the signer truststore is out of it as well,
//     which is the earlier behaviour: a private CA named nowhere is not trusted.
//
// The other dialers stand on the same `tls.connect()`: `tests/outbound_gate.js`
// holds each transport, an in-process claim because no stack carries a revoked SMTP
// relay. No key material is written anywhere: the CA is made here, for this run.
// ===========================================================================

const assert = require("assert");
const http = require("http");
const https = require("https");
const { Command, Option } = require("commander");
const kit = require("../tools/trust_kit.js");

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
var log = bunyan.createLogger({ name: "sts_paranoid_pki_outbound",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "paranoid-out-" + STAMP;
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";

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

function api() {
  log.debug("Entering api().");
  log.debug("Leaving api().");
  return "/realm/" + REALM + "/admin-api";
}

// A listener on every interface, counting what it is asked.
async function listener(cert, root) {
  log.debug("Entering listener().");
  const out = { asked: 0, server: null, url: "" };
  out.server = https.createServer(
    { key: cert.key, cert: cert.pem + root.pem },
    function (req, res) {
      out.asked += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ resource: "https://api.paranoid.example",
                               authorization_servers: [base] }));
    });
  await new Promise(function (resolve) {
    out.server.listen(0, "0.0.0.0", resolve);
  });
  out.url = "https://" + HOST + ":" + out.server.address().port +
            "/.well-known/oauth-protected-resource";
  log.debug("Leaving listener().");
  return out;
}

function load(one) {
  log.debug("Entering load().");
  log.debug("Leaving load().");
  return send("POST", api() + "/applications/load-resource-metadata",
              { url: one.url });
}

async function setRow(setting, value) {
  log.debug("Entering setRow(). " + setting);
  const out = await send("POST", api() + "/pki/trust/set-row",
                         { setting: setting, value: value });
  assert.strictEqual(out.status, 200, out.raw.slice(0, 300));
  log.debug("Leaving setRow().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Paranoid PKI at an outbound request, " + base);
  const made = await send("POST", "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net", name: REALM,
    // A development realm in every mode: the listeners below are on this job's
    // own host, which product refuses to dial for a reason of its own
    // (`sts_outbound_tls.js` holds that), and the master is set by hand here.
    overrides: { "global.mode": "development" } });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));

  const root = await kit.mint({ cn: "paranoid outbound " + STAMP, ca: true });
  const crls = http.createServer(function (req, res) {
    res.writeHead(200, { "Content-Type": "application/pkix-crl" });
    res.end(crls.body);
  });
  await new Promise(function (resolve) {
    crls.listen(0, "0.0.0.0", resolve);
  });
  const crlUrl = "http://" + HOST + ":" + crls.address().port + "/o.crl";
  const profile = { usages: ["digitalSignature", "keyEncipherment"],
                    san: [(/^[0-9.]+$/.test(HOST) ? "IP:" : "DNS:") + HOST],
                    issuer: root, crls: [crlUrl] };
  const goodCert = await kit.mint(Object.assign(
    { cn: "good", eku: ["serverAuth"] }, profile));
  const revokedCert = await kit.mint(Object.assign(
    { cn: "revoked", eku: ["serverAuth"] }, profile));
  const ekuCert = await kit.mint(Object.assign(
    { cn: "eku", eku: ["emailProtection"] }, profile));
  crls.body = await kit.crlOf(root, [revokedCert.serialHex]);
  const good = await listener(goodCert, root);
  const revoked = await listener(revokedCert, root);
  const wrongEku = await listener(ekuCert, root);

  try {
    log.info("=== a. the CA is only in the signer truststore ===");
    await setRow("pki.paranoid", "on");
    const before = await load(good);
    check("before it is added, the server is not trusted", function () {
      assert.strictEqual(before.status, 400, before.raw.slice(0, 300));
      assert.strictEqual(good.asked, 0);
    });
    const added = await send("POST", api() + "/pki/trust/add",
                             { certificates: root.pem });
    assert.strictEqual(added.status, 200, added.raw.slice(0, 300));
    const reached = await load(good);
    check("with it added, the same server is reached", function () {
      assert.strictEqual(reached.status, 200, reached.raw.slice(0, 400));
      assert.strictEqual(good.asked, 1);
    });

    log.info("=== b. what paranoid refuses ===");
    const refusedRevoked = await load(revoked);
    check("a revoked server is refused, and asked nothing", function () {
      assert.strictEqual(refusedRevoked.status, 400,
                         refusedRevoked.raw.slice(0, 300));
      assert.strictEqual(revoked.asked, 0);
      assert.ok(!/STS-[A-Z]+-[0-9]{4}/.test(refusedRevoked.raw));
    });
    const refusedEku = await load(wrongEku);
    check("an EKU that omits serverAuth is refused, and asked nothing",
          function () {
      assert.strictEqual(refusedEku.status, 400, refusedEku.raw.slice(0, 300));
      assert.strictEqual(wrongEku.asked, 0);
    });

    log.info("=== c. the row, and the master ===");
    await setRow("pki.paranoidOutboundTls", false);
    const offNoStore = await load(revoked);
    check("with the row off the signer truststore is out of it too, so this " +
          "server is untrusted rather than revoked, which is how it was",
          function () {
      assert.strictEqual(offNoStore.status, 400, offNoStore.raw.slice(0, 300));
    });
    await setRow("pki.paranoidOutboundTls", true);
    await setRow("pki.paranoid", "off");
    const masterOff = await load(good);
    check("and with the master off", function () {
      assert.strictEqual(masterOff.status, 400, masterOff.raw.slice(0, 300));
    });
  } finally {
    [good, revoked, wrongEku].forEach(function (one) {
      one.server.close();
    });
    crls.close();
  }
  assert.ok(checks >= 6, "only " + checks + " checks ran; a section has " +
                                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_paranoid_pki_outbound")
  .description("Paranoid PKI at an outbound request (#1360).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
