// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_console_after_root.js
//
// ---------------------------------------------------------------------------
// THE CONSOLE SIGNS IN AT ONCE AFTER THE ROOT IS REPLACED (#296, 2026-09-27).
//
// The console is a relying party of this service's own authorization server
// and signs its client assertion with a key the realm's certificate authority
// issues it (`common/oidc_rp.ts`, `surfaceKey()`). Replacing the Root
// (`POST /admin-api/pki/build-root`) makes that key's chain refuse, so the
// next sign-in issues a new one under a cluster claim. The claim used to be
// held for its whole lifetime (~21 s) after the issuance instead of released,
// so a SECOND replacement inside that window left the next sign-in waiting for
// a key nobody was issuing, and it failed with STS-AUTHN-0208 after 21 s. In
// memory mode `sts_metadata` straight after `sts_admin_api_operations` was that
// sequence.
//
// So, deterministically:
//   1. sign in to the console (a key held or issued);
//   2. replace the Root, sign in again — the key is re-issued under the new
//      branch;
//   3. replace the Root AGAIN at once, sign in again — the second re-issue,
//      inside the first one's window, which is the case that failed.
// Each sign-in must succeed, reach a console page, and take less than the
// claim's window. After a replacement the listener serves a certificate from
// the new Root, which this process's trust store does not hold, so each
// sign-in runs in a child process trusting the anchor the service serves at
// that moment — what the runner does between two jobs.
//
// OWNED HERE (local: true): this repository's console, PKI and authorization
// server. It replaces the service Root twice, like `sts_admin_api_operations`
// does once; the runner fetches the new anchor before the next job.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const childProcess = require("child_process");
const { Command, Option } = require("commander");

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
var log = bunyan.createLogger({ name: "sts_console_after_root",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const CONSOLE_USER = "sts-console-after-root";
// Well inside the claim's window (twice oidcRp.backChannelTimeoutS, 10 s by
// default, plus a second): a sign-in that waited for the window to run out
// took ~21 s and then failed.
const SIGN_IN_BUDGET_MS = 15000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// The program a child runs: either one `build-root` (CAR_ACTION=root), or one
// console sign-in and one console read, with the answer on stdout as JSON.
// It is data here, and runs in the child. The build-root is a child's too,
// because after the first replacement this process's own trust store no
// longer holds the anchor the listener serves.
const CHILD = [
  "const consoleSignIn = require(process.env.CAR_SIGNIN);",
  "const started = Date.now();",
  "(async function () {",
  "  const out = { ok: false };",
  "  try {",
  "    if (process.env.CAR_ACTION === 'root') {",
  "      const r = await fetch(process.env.CAR_BASE +",
  "        '/admin-api/pki/build-root', { method: 'POST',",
  "        headers: { 'Content-Type': 'application/json' }, body: '{}' });",
  "      out.status = r.status;",
  "      out.ok = r.status === 200;",
  "      out.why = out.ok ? '' : (await r.text()).slice(0, 300);",
  "      out.ms = Date.now() - started;",
  "      process.stdout.write(JSON.stringify(out));",
  "      return;",
  "    }",
  "    const cookie = await consoleSignIn.signInToTheConsole(",
  "      process.env.CAR_BASE, process.env.CAR_USER, null,",
  "      { grant: 'read' });",
  "    const page = await fetch(process.env.CAR_BASE + '/admin/tokens',",
  "      { redirect: 'manual', headers: cookie ? { cookie: cookie } : {} });",
  "    out.ok = page.status === 200;",
  "    out.status = page.status;",
  "  } catch (e) {",
  "    out.why = String((e && e.message) || e).slice(0, 600);",
  "  }",
  "  out.ms = Date.now() - started;",
  "  process.stdout.write(JSON.stringify(out));",
  "})();"
].join("\n");

// Sign in from a child that trusts `anchorPem` (and whatever this process
// trusts already). Answers `{ ok, status, ms, why }`.
function signInTrusting(anchorPem, step, action) {
  log.debug("Entering signInTrusting(). " + step);
  const file = path.join(os.tmpdir(), "sts-console-after-root-" +
                         process.pid + "-" + step + ".pem");
  const already = process.env.NODE_EXTRA_CA_CERTS &&
    fs.existsSync(process.env.NODE_EXTRA_CA_CERTS)
    ? fs.readFileSync(process.env.NODE_EXTRA_CA_CERTS, "utf8") : "";
  fs.writeFileSync(file, already + "\n" + (anchorPem || ""));
  const run = childProcess.spawnSync(process.execPath, ["-e", CHILD], {
    env: Object.assign({}, process.env, {
      NODE_EXTRA_CA_CERTS: file,
      CAR_SIGNIN: path.join(__dirname, "console_signin.js"),
      CAR_BASE: base, CAR_USER: CONSOLE_USER, CAR_ACTION: action || ""
    }),
    encoding: "utf8", timeout: 60000
  });
  try {
    fs.unlinkSync(file);
  } catch (e) {
    // A temporary file the child no longer needs; nothing depends on it.
    log.debug("Caught in signInTrusting(): " + ((e && e.message) || e));
  }
  let answer = null;
  try {
    answer = JSON.parse(run.stdout || "");
  } catch (e) {
    log.debug("Caught in signInTrusting(): " + ((e && e.message) || e));
    answer = { ok: false, why: "the child wrote no answer (exit " +
               run.status + "): " + String(run.stderr || "").slice(-600) };
  }
  log.debug("Leaving signInTrusting(). " + JSON.stringify(answer));
  return answer;
}

async function replaceTheRoot(step) {
  log.debug("Entering replaceTheRoot().");
  const answer = signInTrusting(await anchorNow(), step + "-root", "root");
  assert.ok(answer && answer.ok, "POST /admin-api/pki/build-root failed: " +
            JSON.stringify(answer));
  log.debug("Leaving replaceTheRoot().");
}

async function anchorNow() {
  log.debug("Entering anchorNow().");
  const trust = require(path.join(__dirname, "..", "tools", "trust.js"));
  const pem = await trust.fetchCertificate(base, 10000, { fresh: true });
  log.debug("Leaving anchorNow().");
  return pem;
}

function signedIn(answer, what) {
  log.debug("Entering signedIn().");
  check(what, function () {
    assert.ok(answer && answer.ok, "the console sign-in failed: " +
              JSON.stringify(answer));
    assert.ok(answer.ms < SIGN_IN_BUDGET_MS, "the console sign-in took " +
              answer.ms + " ms; a sign-in that waits out the key claim's " +
              "window is the defect (#296)");
  });
  log.debug("Leaving signedIn().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 1. the console, before anything is replaced ===");
  signedIn(signInTrusting(await anchorNow(), "before"),
           "the console signs in");

  log.info("=== 2. the Root replaced, and the console at once ===");
  await replaceTheRoot("first");
  signedIn(signInTrusting(await anchorNow(), "first"),
           "the console signs in at once after the Root is replaced — its " +
           "key re-issued under the new branch");

  log.info("=== 3. replaced again inside the first re-issue's window ===");
  await replaceTheRoot("second");
  signedIn(signInTrusting(await anchorNow(), "second"),
           "and again at once after a SECOND replacement, inside the first " +
           "re-issue's claim window (the STS-AUTHN-0208 case)");

  assert.ok(checks >= 3, "only " + checks + " checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The console signs in at once after POST /admin-api/pki/" +
    "build-root, twice in a row (#296).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
