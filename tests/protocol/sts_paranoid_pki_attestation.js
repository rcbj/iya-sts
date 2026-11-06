// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_paranoid_pki_attestation.js
//
// ===========================================================================
// PARANOID PKI MODE AT A FEDERATED AUTHORITY (#1360, Phase 5).
//
// `local: true`. In a realm of its own, with the master forced on, a federated
// SPIFFE bundle's authority is held to its fields when it is accepted: a leaf
// and an expired CA are refused at `/admin-api/spiffe/federation-set`, a good
// CA is taken, and with the row off the expired one is taken too.
//
// The rest of Phase 5 needs a wallet, an agent or an authenticator, and each is
// driven beside its own coverage: `sts_webauthn_attestation.js` section 1b over
// HTTP; `tests/vc_mdoc.js` section 5, `tests/oid4vp_wallet_mfa.js` 4g to 4i and
// `tests/spiffe_attestors.js` in process; every path rule in
// `tests/certificate_trust.js` section N.
// ===========================================================================

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_paranoid_pki_attestation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "paranoid-att-" + STAMP;

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

async function setRow(setting, value) {
  log.debug("Entering setRow(). " + setting);
  const out = await send("POST", api() + "/pki/trust/set-row",
                         { setting: setting, value: value });
  assert.strictEqual(out.status, 200, out.raw.slice(0, 300));
  log.debug("Leaving setRow().");
}

function bundleOf(cert) {
  log.debug("Entering bundleOf().");
  log.debug("Leaving bundleOf().");
  return { keys: [{ kty: "RSA", use: "x509-svid",
                    x5c: [cert.pem.replace(/-----[^-]+-----|\s+/g, "")] }],
           spiffe_sequence: 1, spiffe_refresh_hint: 300 };
}

function federate(name, cert) {
  log.debug("Entering federate(). " + name);
  log.debug("Leaving federate().");
  return send("POST", api() + "/spiffe/federation-set",
              { trustDomain: name, document: bundleOf(cert) });
}

async function aFederatedAuthority() {
  log.debug("Entering aFederatedAuthority().");
  const now = Date.now();
  const root = await kit.mint({ cn: "federated root " + STAMP, ca: true });
  const leaf = await kit.mint({ cn: "federated leaf " + STAMP, issuer: root });
  const expired = await kit.mint({ cn: "federated old " + STAMP, ca: true,
    notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
  await setRow("pki.paranoid", "on");
  const asLeaf = await federate("leaf.example", leaf);
  check("a certificate that is no authority is refused", function () {
    assert.strictEqual(asLeaf.status, 400, asLeaf.raw.slice(0, 300));
    assert.ok(/certificate authority/.test(asLeaf.raw),
              asLeaf.raw.slice(0, 300));
    assert.ok(!/STS-/.test(asLeaf.raw), "an error code left the service");
  });
  const asOld = await federate("old.example", expired);
  check("an expired authority is refused", function () {
    assert.strictEqual(asOld.status, 400, asOld.raw.slice(0, 300));
    assert.ok(/expired/.test(asOld.raw), asOld.raw.slice(0, 300));
  });
  const asGood = await federate("good.example", root);
  check("a good authority is taken", function () {
    assert.strictEqual(asGood.status, 200, asGood.raw.slice(0, 300));
  });
  await setRow("pki.paranoidSpiffeSvid", false);
  const rowOff = await federate("old.example", expired);
  check("with the row off the expired one is taken", function () {
    assert.strictEqual(rowOff.status, 200, rowOff.raw.slice(0, 300));
  });
  log.debug("Leaving aFederatedAuthority().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Paranoid PKI at a federated authority, " + base);
  const made = await send("POST", "/admin-api/realms/create", {
    id: REALM, domain: REALM + ".example.net", name: REALM });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  await aFederatedAuthority();
  assert.ok(checks >= 4, "only " + checks + " checks ran; a section has " +
                                          "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_paranoid_pki_attestation")
  .description("Paranoid PKI at a federated authority (#1360).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
