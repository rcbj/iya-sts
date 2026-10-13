// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_android_attestation_status.js
//
// ===========================================================================
// GOOGLE'S ANDROID ATTESTATION STATUS LIST, OVER HTTP, IN EVERY MODE (#256,
// 2026-10-06).
//
// `tests/attestation_revocation.js` holds the list's format, import, lookup,
// consultation and recheck in process, and `tests/device_enrolment.js` 3f–3i
// and `tests/webauthn_attestation.js` C16b–c the two verifiers. This job
// holds the RUNNING service to the parts a unit cannot reach: the dataset in
// the catalogue `/admin-api/risk` reads, the upload door taking its format,
// the provider needing no terms acceptance, and the device registration
// page's `androidStatus` reading the version every process sees — with
// request workers in `single-node` and two nodes in `cluster`.
//
//   1. THE STATUS IS DRAWN, with the address the refresh job dials — empty
//      in every local suite stack (docker-compose-run-tests.yml), Google's
//      on an AWS target, and reported rather than asserted.
//   2. AN UPLOAD: a synthetic list through `POST /admin-api/risk/upload`
//      becomes `active` with one row per REVOKED or SUSPENDED entry, and
//      `GET /admin-api/device-registration`'s `androidStatus` names it.
//   3. A REFUSAL: a document that is not the list is `refused`, and the
//      active version is unchanged.
//   4. A NEWER LIST REPLACES IT (the latest only).
//
// Every serial is random and this run's own, so no key any other job
// registered is on the list; the list is the whole service's and is left
// loaded, which a later job sees only as "good".
// ===========================================================================

const assert = require("assert");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js (beside this file) gives.
  appconfigProblem = e;
  appconfig = {};
}

const bunyan = require("bunyan");
const log = bunyan.createLogger({ name: "sts_android_attestation_status",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const crypto = require("crypto");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const DATASET = "android.attestation-status";
const FORMAT = "android-attestation-status-json";

// THE SAME BOUND AS sts_admin_risk_upload.js, for its reason: how long to
// wait for a verdict under an instrumented coverage run, not a claim about
// speed.
const SETTLE_MS = 180000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
}

function serial() {
  log.debug("Entering serial().");
  // Sixteen random bytes with a non-zero first nibble, upper case: the list
  // writes serials that way and the service keys them in lower case.
  const hex = "a" + crypto.randomBytes(16).toString("hex").slice(1);
  log.debug("Leaving serial().");
  return hex.toUpperCase();
}

function listOf(entries) {
  log.debug("Entering listOf().");
  log.debug("Leaving listOf().");
  return Buffer.from(JSON.stringify({ entries: entries }));
}

async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const opts = Object.assign({ method: method, redirect: "manual" },
                             options || {});
  const r = await fetch(url, opts);
  const text = await r.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON — a page or an empty body. The text is kept.
    body = null;
  }
  log.debug("Leaving call(). status=" + r.status);
  return { status: r.status, body: body, text: text };
}

async function upload(file) {
  log.debug("Entering upload().");
  const q = new URLSearchParams({ dataset: DATASET, format: FORMAT })
    .toString();
  const reply = await call("POST", base + "/admin-api/risk/upload?" + q,
                           { headers: { "Content-Type":
                                        "application/octet-stream" },
                             body: file });
  log.debug("Leaving upload().");
  return reply;
}

async function datasetRow() {
  log.debug("Entering datasetRow().");
  const r = await call("GET", base + "/admin-api/risk");
  assert.strictEqual(r.status, 200, "GET /admin-api/risk answered " +
                     r.status + " " + r.text.slice(0, 300));
  const d = r.body.datasets.filter(function (one) {
    return one.dataset === DATASET;
  })[0];
  log.debug("Leaving datasetRow().");
  return d;
}

async function settled(version) {
  log.debug("Entering settled(). " + version);
  const deadline = Date.now() + SETTLE_MS;
  for (;;) {
    const d = (await datasetRow()) || { versions: [] };
    const v = (d.versions || []).filter(function (one) {
      return one.version === version;
    })[0];
    // `ready` is transient, as sts_admin_risk_upload.js says.
    if (v && v.state !== "loading" && v.state !== "ready") {
      log.debug("Leaving settled(). " + v.state);
      return v;
    }
    if (Date.now() > deadline) {
      log.debug("Leaving settled(). Timed out.");
      assert.fail("version " + version + " of " + DATASET + " was still " +
                  (v ? v.state : "not recorded") + " after " +
                  (SETTLE_MS / 60000) + " minutes");
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
}

async function status() {
  log.debug("Entering status().");
  const r = await call("GET", base + "/admin-api/device-registration");
  assert.strictEqual(r.status, 200, "GET /admin-api/device-registration " +
                     "answered " + r.status + " " + r.text.slice(0, 300));
  assert.ok(r.body.androidStatus, "no androidStatus in " +
            r.text.slice(0, 400));
  log.debug("Leaving status().");
  return r.body.androidStatus;
}

// THE ACTIVE VERSION, read until it is the one expected: the import
// activates on whichever process took the upload, and another process (a
// request worker, the other node) reads it from the store.
async function statusShowing(version) {
  log.debug("Entering statusShowing(). " + version);
  const deadline = Date.now() + SETTLE_MS;
  for (;;) {
    const s = await status();
    if (s.active === version || Date.now() > deadline) {
      log.debug("Leaving statusShowing(). " + s.active);
      return s;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 500);
    });
  }
}

async function main() {
  log.debug("Entering main().");

  log.info("=== 1. the stack dials nobody ===");
  const first = await status();
  // Empty in every local stack (docker-compose-run-tests.yml); an AWS
  // target keeps Google's address, and nothing tells a job which it is
  // against, so the address is reported rather than asserted.
  check("androidStatus is drawn, with the address the job dials (\"" +
        first.url + "\")", function () {
          assert.strictEqual(typeof first.active, "string",
                             JSON.stringify(first));
          assert.strictEqual(typeof first.url, "string",
                             JSON.stringify(first));
        });
  const row = await datasetRow();
  check("the list is a dataset Monitoring → Risk lists, read from its one " +
        "format", function () {
          assert.ok(row, "no " + DATASET + " in GET /admin-api/risk");
        });

  log.info("=== 2. an upload ===");
  const entries = {};
  entries[serial()] = { status: "REVOKED", reason: "KEY_COMPROMISE" };
  entries[serial()] = { status: "SUSPENDED", reason: "SOFTWARE_FLAW" };
  entries[serial()] = { status: "SOMETHING_ELSE" };
  const r = await upload(listOf(entries));
  check("POST /admin-api/risk/upload takes the list, with no terms to " +
        "accept", function () {
          assert.strictEqual(r.status, 202, r.text.slice(0, 400));
        });
  const v = await settled(r.body.version);
  check("it becomes active with a row for each REVOKED or SUSPENDED entry",
        function () {
          assert.strictEqual(v.state, "active", JSON.stringify(v));
          assert.strictEqual(v.rowCount, 2, JSON.stringify(v));
        });
  const shown = await statusShowing(r.body.version);
  check("the device registration page's androidStatus names it", function () {
    assert.strictEqual(shown.active, r.body.version, JSON.stringify(shown));
    assert.strictEqual(shown.rows, 2, JSON.stringify(shown));
    assert.strictEqual(shown.stale, false, JSON.stringify(shown));
  });

  log.info("=== 3. a refusal ===");
  const bad = await upload(Buffer.from("this is not the list"));
  if (bad.status === 202) {
    const refused = await settled(bad.body.version);
    check("a document that is not the list is refused", function () {
      assert.strictEqual(refused.state, "refused", JSON.stringify(refused));
    });
  } else {
    check("a document that is not the list is refused at the door",
          function () {
            assert.ok(bad.status >= 400 && bad.status < 500,
                      bad.status + " " + bad.text.slice(0, 300));
          });
  }
  const still = await status();
  check("and the active version is unchanged", function () {
    assert.strictEqual(still.active, r.body.version, JSON.stringify(still));
  });

  log.info("=== 4. a newer list replaces it ===");
  const newer = {};
  newer[serial()] = { status: "REVOKED" };
  const r2 = await upload(listOf(newer));
  assert.strictEqual(r2.status, 202, r2.text.slice(0, 400));
  const v2 = await settled(r2.body.version);
  const replaced = await statusShowing(r2.body.version);
  check("a newer list is active in its place, with its own rows", function () {
    assert.strictEqual(v2.state, "active", JSON.stringify(v2));
    assert.strictEqual(replaced.active, r2.body.version,
                       JSON.stringify(replaced));
    assert.strictEqual(replaced.rows, 1, JSON.stringify(replaced));
  });

  log.info("sts_android_attestation_status: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_android_attestation_status FAILED: " +
            ((e && e.stack) || e));
  process.exit(1);
});
