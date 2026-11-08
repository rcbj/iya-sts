// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_paranoid_pki_settings.js
//
// ===========================================================================
// EVERY PARANOID PKI SETTING, THROUGH THE DOOR AN OPERATOR USES (#1360).
//
// `local: true`: this repository's management API, in every mode the launcher
// runs and against an AWS target. The in-process half is
// `tests/paranoid_settings.js`.
//
// In a realm of its own (start from a known state) it writes the master and
// every use case's row, through both `POST /admin-api/config/set` and the
// page's own `set-row`, and reads each back through `GET /admin-api/pki/trust`;
// the realm beside it does not move.
//
// **WHAT A PROTOCOL REQUEST CAN PROVE GROWS PER PHASE**, by `phase` in the table:
// a setting governs nothing until its sites are wired, which
// `docs/pki-use-cases.md` says of each. Phase 0 wires
// `anchor-admission` at the client-certificate truststore, whose mode is asked
// in the DEFAULT realm because a handshake has no realm. So that section writes
// to the default realm, which is why this job is `exclusive`, and puts it back
// in a `finally`: refused with the master on, accepted with the row off.
// ===========================================================================

const assert = require("assert");
const https = require("https");
const { Command, Option } = require("commander");
const credentials = require("../tools/pep-credential.js");
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
var log = bunyan.createLogger({ name: "sts_paranoid_pki_settings",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36);
const REALM = "paranoid-" + STAMP;
const OTHER = "paranoid-b-" + STAMP;

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

function inRealm(id) {
  log.debug("Entering inRealm().");
  log.debug("Leaving inRealm().");
  // The default realm has no prefix.
  return id === "default" ? "/admin-api" : "/realm/" + id + "/admin-api";
}

// The page's answer, in a realm.
async function viewOf(id) {
  log.debug("Entering viewOf().");
  const view = await send("GET", inRealm(id) + "/pki/trust");
  assert.strictEqual(view.status, 200, view.raw.slice(0, 400));
  log.debug("Leaving viewOf().");
  return view.json;
}

async function theRowsAnswerTheirSwitch() {
  log.debug("Entering theRowsAnswerTheirSwitch().");
  const before = await viewOf(REALM);
  check("twenty-three use cases, each with its setting", function () {
    assert.strictEqual(before.rows.length, 23);
    before.rows.forEach(function (row) {
      assert.ok(/^pki\.paranoid[A-Z]/.test(row.setting), row.setting);
      assert.strictEqual(row.on, true, row.setting + " defaults on");
    });
  });
  const auto = before.master;
  check("auto: on in product, off in development, and it says which",
        function () {
    assert.strictEqual(auto.value, "auto");
    assert.strictEqual(auto.inForce, auto.product, JSON.stringify(auto));
    assert.ok(/pki\.paranoid=auto/.test(auto.decidedBy), auto.decidedBy);
  });
  const on = await send("POST", inRealm(REALM) + "/config/set",
                        { key: "pki.paranoid", value: "on" });
  assert.strictEqual(on.status, 200, on.raw.slice(0, 400));
  const forced = await viewOf(REALM);
  const beside = await viewOf(OTHER);
  check("the master written through the settings door is in force", function () {
    assert.strictEqual(forced.master.value, "on");
    assert.strictEqual(forced.master.inForce, true);
    forced.rows.forEach(function (row) {
      assert.strictEqual(row.inForce, true, row.purpose);
    });
  });
  check("per realm: the realm beside it did not move", function () {
    assert.strictEqual(beside.master.value, "auto");
  });
  for (const row of forced.rows) {
    const off = await send("POST", inRealm(REALM) + "/pki/trust/set-row",
                           { setting: row.setting, value: false });
    assert.strictEqual(off.status, 200, off.raw.slice(0, 400));
    const read = (await viewOf(REALM)).rows.filter(function (one) {
      return one.purpose === row.purpose;
    })[0];
    check(row.purpose + ": off through the page's act, and read back",
          function () {
      assert.strictEqual(read.on, false);
      assert.strictEqual(read.inForce, false);
    });
    const back = await send("POST", inRealm(REALM) + "/config/set",
                            { key: row.setting, value: true });
    assert.strictEqual(back.status, 200, back.raw.slice(0, 400));
    const again = (await viewOf(REALM)).rows.filter(function (one) {
      return one.purpose === row.purpose;
    })[0];
    check(row.purpose + ": on through the settings door, and read back",
          function () {
      assert.strictEqual(again.on, true);
      assert.strictEqual(again.inForce, true);
    });
  }
  const offMaster = await send("POST", inRealm(REALM) + "/pki/trust/set-row",
                               { setting: "pki.paranoid", value: "off" });
  assert.strictEqual(offMaster.status, 200, offMaster.raw.slice(0, 400));
  const allOff = await viewOf(REALM);
  check("the master off wins whatever the rows say", function () {
    assert.strictEqual(allOff.master.inForce, false);
    allOff.rows.forEach(function (row) {
      assert.strictEqual(row.on, true, row.purpose);
      assert.strictEqual(row.inForce, false, row.purpose);
    });
  });
  const stray = await send("POST", inRealm(REALM) + "/pki/trust/set-row",
                           { setting: "pki.crlLifetimeMinutes", value: 60 });
  const bad = await send("POST", inRealm(REALM) + "/pki/trust/set-row",
                         { setting: "pki.paranoid", value: "sometimes" });
  check("set-row writes only these settings, and only their values",
        function () {
    assert.strictEqual(stray.status, 400, stray.raw.slice(0, 300));
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
  });
  log.debug("Leaving theRowsAnswerTheirSwitch().");
}

// `anchor-admission` at the client-certificate truststore: the one row a request
// can prove in Phase 0.
async function theAdmissionRowDecides() {
  log.debug("Entering theAdmissionRowDecides().");
  const minted = await credentials.mint({ crlBase: "",
    rootSubject: "CN=paranoid admission " + STAMP + ",O=iya-sts tests",
    subject: "CN=paranoid-admission-leaf-" + STAMP + ",O=iya-sts tests" });
  const add = function (pem) {
    log.debug("Entering add().");
    log.debug("Leaving add().");
    return send("POST", "/admin-api/tls/trust/add", { certificates: pem });
  };
  const remove = async function (pem) {
    log.debug("Entering remove().");
    const fingerprint = require("crypto").createHash("sha256")
      .update(Buffer.from(pem.replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, ""), "base64")).digest("hex");
    const gone = await send("POST", "/admin-api/tls/trust/remove",
                            { fingerprint: fingerprint });
    log.debug("Leaving remove(). " + gone.status);
    return gone;
  };
  const masterWas = (await viewOf("default")).master.value;
  try {
    const on = await send("POST", "/admin-api/config/set",
                          { key: "pki.paranoid", value: "on" });
    assert.strictEqual(on.status, 200, on.raw.slice(0, 300));
    const leaf = await add(minted.certPem);
    check("a leaf offered to the client truststore is refused, by name",
          function () {
      assert.strictEqual(leaf.status, 400, leaf.raw.slice(0, 300));
      assert.ok(/is a leaf/.test(leaf.json.errors.join(" ")),
                leaf.raw.slice(0, 300));
    });
    const root = await add(minted.anchorPem);
    check("and a self-signed CA is admitted", function () {
      assert.strictEqual(root.status, 200, root.raw.slice(0, 300));
    });
    await remove(minted.anchorPem);
    const off = await send("POST", "/admin-api/pki/trust/set-row",
                           { setting: "pki.paranoidAnchorAdmission",
                             value: false });
    assert.strictEqual(off.status, 200, off.raw.slice(0, 300));
    const allowed = await add(minted.certPem);
    check("with the row off, the store takes what OpenSSL can read, as it " +
          "did", function () {
      assert.strictEqual(allowed.status, 200, allowed.raw.slice(0, 300));
    });
    await remove(minted.certPem);
    const counted = (await viewOf("default")).rows.filter(function (row) {
      return row.purpose === "anchor-admission";
    })[0];
    check("and the row reads back off on the page", function () {
      assert.strictEqual(counted.on, false);
    });
  } finally {
    await send("POST", "/admin-api/config/reset",
               { key: "pki.paranoidAnchorAdmission" });
    await send("POST", "/admin-api/config/reset", { key: "pki.paranoid" });
    log.debug("Put back: the master was " + masterWas);
  }
  log.debug("Leaving theAdmissionRowDecides().");
}

// A row decides at its own door: refused with the row on, written with it off.
// The attestation rows, which need an authenticator, a wallet or an agent, are
// `sts_webauthn_attestation.js`, `sts_paranoid_pki_attestation.js` and the
// in-process files `tests/CLAUDE.md` names for them.
async function refusedThenWritten(id, setting, path, body, what) {
  log.debug("Entering refusedThenWritten(). " + setting);
  const url = inRealm(id) + path;
  const refused = await send("POST", url, body);
  check(what + " is refused at the door with " + setting + " on", function () {
    assert.strictEqual(refused.status, 400, refused.raw.slice(0, 300));
  });
  await send("POST", inRealm(id) + "/pki/trust/set-row",
             { setting: setting, value: false });
  const written = await send("POST", url, body);
  check("and written with it off", function () {
    assert.strictEqual(written.status, 200, written.raw.slice(0, 300));
  });
  log.debug("Leaving refusedThenWritten().");
}

async function theRowsAtTheirDoors() {
  log.debug("Entering theRowsAtTheirDoors().");
  const now = Date.now();
  const expired = await kit.mint({ cn: "paranoid settings expired",
    notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
  const expiredCa = await kit.mint({ cn: "paranoid settings expired CA",
    ca: true, notBefore: now - 3 * kit.DAY, notAfter: now - kit.DAY });
  const base64 = expired.pem.replace(/-----[^-]+-----|\s+/g, "");
  const id = "paranoid-doors-" + STAMP;
  const made = await send("POST", "/admin-api/realms/create",
    { id: id, domain: id + ".example.net", name: id });
  assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  await send("POST", inRealm(id) + "/pki/trust/set-row",
             { setting: "pki.paranoid", value: "on" });
  await refusedThenWritten(id, "pki.paranoidEncryptionRecipient",
    "/applications/create",
    { identifier: "https://sp.doors.example/" + STAMP, name: "doors sp",
      protocols: ["saml2"],
      fields: { samlAssertionConsumerService:
                  ["https://sp.doors.example/acs"],
                samlEncryptionCertificate: base64 } },
    "an expired encryption certificate");
  const fed = "doors-" + STAMP;
  const relationship = await send("POST", inRealm(id) + "/federation/create",
    { id: fed, role: "service-provider", protocol: "saml2",
      peer: "https://idp.doors.example/" + STAMP });
  assert.strictEqual(relationship.status, 200,
                     relationship.raw.slice(0, 300));
  await refusedThenWritten(id, "pki.paranoidFederationPartner",
    "/federation/set",
    { id: fed, field: "fedSigningCertificate", value: expired.pem },
    "an expired partner certificate");
  await refusedThenWritten(id, "pki.paranoidCaImport", "/pki/import-ca",
    { scope: id, useCase: "jose", certificatePem: expiredCa.pem,
      privateKeyPem: expiredCa.key },
    "an expired certificate authority");
  log.debug("Leaving theRowsAtTheirDoors().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Paranoid PKI settings at " + base);
  for (const id of [REALM, OTHER]) {
    const made = await send("POST", "/admin-api/realms/create", {
      id: id, domain: id + ".example.net", name: id });
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  }
  await theRowsAnswerTheirSwitch();
  await theAdmissionRowDecides();
  await theRowsAtTheirDoors();
  assert.ok(checks >= 56, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_paranoid_pki_settings")
  .description("Every paranoid PKI setting over HTTP (#1360).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
