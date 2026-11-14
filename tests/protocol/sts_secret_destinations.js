// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

// File: sts_secret_destinations.js
// ---------------------------------------------------------------------------
// SECRET PUSH DESTINATIONS OVER /admin-api (#221 P3, 2026-10-06).
//
// `tests/secret_destinations.js` holds the write path to every store with the
// stores faked. This job drives the register over HTTP against a running
// service, in a realm of its own:
//
//   0. The realm; the register is empty.
//   1. An aws destination with no region and no credential is refused (400).
//   2. A vault destination with a token: added, usable, `credentialSet` —
//      and the token is in NO answer: not the register's, not the
//      application's, and `reveal-secret` refuses it.
//   3. DEVELOPMENT MODE (the view's `fileAllowed`): a file destination on
//      the directory the runner and the service share. A test push writes
//      a canary into an existing test file, which the runner reads; a test
//      push to a file that does not exist is refused and creates none; the
//      json payload writes {username, password, realm, rotatedAt}.
//      PRODUCT MODE: a file destination is not offered and is refused.
//   4. Both are removed, and the register is empty again. The realm is
//      left standing, as every realm job's is.
//
// Step 3's development half SKIPS, saying why, where there is no directory
// both this runner and the service write (`SECRET_PUSH_TEST_DIR`, set by the
// compose stack; an AWS target has none).
// `local: true` — written here, not in the parent project.
// ---------------------------------------------------------------------------

"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
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
var log = bunyan.createLogger({ name: "sts_secret_destinations",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const SAFE = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20);
const REALM = ("secdest-" + SAFE).slice(0, 31);
const realmApi = base + "/realm/" + REALM + "/admin-api";
const TOKEN = "hvs.secdest-" + nodeCrypto.randomBytes(12).toString("hex");
const VAULT_ID = "vault-" + SAFE;
const FILE_ID = "file-" + SAFE;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
    // Not JSON — the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
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

async function register() {
  log.debug("Entering register().");
  const r = await send(realmApi + "/secret-destinations");
  assert.strictEqual(r.status, 200, "GET /secret-destinations answered " +
                     r.status + " " + String(r.raw).slice(0, 300));
  log.debug("Leaving register().");
  return r;
}

async function fileHalf(view) {
  log.debug("Entering fileHalf().");
  if (!view.fileAllowed) {
    const refused = await postJson(realmApi +
      "/secret-destinations/add-destination",
      { identifier: FILE_ID, provider: "file", directory: "/tmp" });
    check("product mode: a file destination is not offered and is refused",
          function () {
            assert.ok(view.providers.indexOf("file") < 0,
                      JSON.stringify(view.providers));
            assert.strictEqual(refused.status, 400,
                               String(refused.raw).slice(0, 300));
          });
    log.debug("Leaving fileHalf(). Product mode.");
    return false;
  }
  const shared = String(process.env.SECRET_PUSH_TEST_DIR || "");
  if (!shared) {
    log.info("SKIPPED (step 3): SECRET_PUSH_TEST_DIR is not set, so there " +
             "is no directory this runner and the service both write (an " +
             "AWS target has none).");
    log.debug("Leaving fileHalf(). No shared directory.");
    return false;
  }
  // The same path in both containers (docker-compose-run-tests.yml's
  // `sts-test-secret-push`): the runner makes the files, the service writes
  // into them (it never creates one).
  const dir = path.join(shared, "secdest-" + SAFE);
  fs.mkdirSync(dir, { recursive: true, mode: 0o777 });
  fs.chmodSync(dir, 0o777);
  const canary = path.join(dir, "canary");
  fs.writeFileSync(canary, "untouched");
  fs.chmodSync(canary, 0o666);
  try {
    await ok(realmApi + "/secret-destinations/add-destination",
             { identifier: FILE_ID, name: "files " + STAMP, provider: "file",
               directory: dir }, "added a file destination");
    const row = (await register()).body.destinations.filter(function (d) {
      return d.identifier === FILE_ID;
    })[0];
    check("a file destination needs no credential in development and is " +
          "usable", function () {
            assert.ok(row && row.usable, JSON.stringify(row));
          });
    const tested = await ok(realmApi + "/secret-destinations/test-push",
                            { id: row.id, secretName: "canary" },
                            "test-pushed to the canary");
    const written = fs.readFileSync(canary, "utf8");
    check("a test push writes a random canary into the existing file",
          function () {
            assert.ok(written !== "untouched" && written.length >= 40,
                      String(written.length));
            assert.ok(tested.version, JSON.stringify(tested));
          });
    const missing = await postJson(realmApi +
      "/secret-destinations/test-push", { id: row.id,
                                          secretName: "not-there" });
    check("a test push to a file that does not exist is refused and " +
          "creates none", function () {
            assert.strictEqual(missing.status, 400,
                               String(missing.raw).slice(0, 300));
            assert.ok(!fs.existsSync(path.join(dir, "not-there")));
          });
    await ok(realmApi + "/secret-destinations/update-destination",
             { id: row.id, payload: "json" }, "changed the payload");
    await ok(realmApi + "/secret-destinations/test-push",
             { id: row.id, secretName: "canary" },
             "test-pushed the json payload");
    const json = JSON.parse(fs.readFileSync(canary, "utf8"));
    check("the json payload is {username, password, realm, rotatedAt}",
          function () {
            assert.deepStrictEqual(Object.keys(json).sort(),
                                   ["password", "realm", "rotatedAt",
                                    "username"]);
            assert.strictEqual(json.username, "sts-test-push");
            assert.strictEqual(json.realm, REALM);
          });
    await ok(realmApi + "/secret-destinations/remove-destination",
             { id: row.id }, "removed the file destination");
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      log.debug("Caught in fileHalf(): " + ((e && e.message) || e));
      // A file the service wrote may not be the runner's to remove; it is
      // named for this run and harms nothing.
    }
  }
  log.debug("Leaving fileHalf().");
  return true;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a realm, and an empty register ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "secret destinations " + STAMP },
    "created the realm");
  const empty = await register();
  check("the register of a new realm is empty, and says what each " +
        "provider's credential is", function () {
          assert.deepStrictEqual(empty.body.destinations, []);
          assert.ok(empty.body.credentialShapes.vault,
                    JSON.stringify(empty.body).slice(0, 300));
        });

  log.info("=== 1. a destination missing what its provider needs ===");
  const refused = await postJson(realmApi +
    "/secret-destinations/add-destination",
    { identifier: "aws-" + SAFE, provider: "aws" });
  check("an aws destination with no region and no credential is refused",
        function () {
          assert.strictEqual(refused.status, 400,
                             String(refused.raw).slice(0, 300));
        });

  log.info("=== 2. the write credential is write-only ===");
  await ok(realmApi + "/secret-destinations/add-destination",
           { identifier: VAULT_ID, name: "vault " + STAMP, provider: "vault",
             endpoint: "https://vault.secdest.example.test:8200",
             mount: "secret", payload: "json", credential: TOKEN },
           "added a vault destination");
  const listed = await register();
  const vault = listed.body.destinations.filter(function (d) {
    return d.identifier === VAULT_ID;
  })[0];
  check("the vault destination is usable, says its credential is set, and " +
        "the register carries no token", function () {
          assert.ok(vault && vault.usable && vault.credentialSet,
                    JSON.stringify(vault));
          assert.ok(listed.raw.indexOf(TOKEN) < 0);
        });
  const app = await send(realmApi + "/applications?application=" +
                         encodeURIComponent(VAULT_ID));
  check("the application's own answer carries no token", function () {
    assert.strictEqual(app.status, 200, String(app.raw).slice(0, 300));
    assert.ok(app.raw.indexOf(TOKEN) < 0);
  });
  const reveal = await postJson(realmApi + "/applications/reveal-secret",
    { application: VAULT_ID, secret: "secretDestCredential" });
  check("reveal-secret refuses a destination's write credential",
        function () {
          assert.strictEqual(reveal.status, 400,
                             String(reveal.raw).slice(0, 300));
          assert.ok(reveal.raw.indexOf(TOKEN) < 0);
        });
  const plain = await postJson(realmApi +
    "/secret-destinations/update-destination",
    { id: vault.id, endpoint: "http://vault.secdest.example.test:8200" });
  check("a plain http address is refused on a change", function () {
    assert.strictEqual(plain.status, 400, String(plain.raw).slice(0, 300));
  });

  log.info("=== 3. a file destination: development only ===");
  await fileHalf(listed.body);

  log.info("=== 4. removal ===");
  await ok(realmApi + "/secret-destinations/remove-destination",
           { id: vault.id }, "removed the vault destination");
  const after = await register();
  check("the register is empty again", function () {
    assert.deepStrictEqual(after.body.destinations, []);
  });
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_secret_destinations FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
