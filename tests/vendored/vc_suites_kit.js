"use strict";
//
// File: vc_suites_kit.js
//
// ---------------------------------------------------------------------------
// WHAT THE SIX W3C VC AND DID SUITE JOBS SHARE (#194-#199, 2026-09-26). Not a
// job.
//
//   * setUp()        a THROWAWAY DEVELOPMENT REALM — the VC-API adapter
//                    (oid4vc/vc_api.ts) is a test control, closed in
//                    product, and a realm's mode is its own, so this runs in
//                    every local mode — with a client that may be issued
//                    `vc-api:issue` and `vc-api:verify` (this service's own
//                    protected scopes, declared by an administrator) and a
//                    token carrying both. The suites authenticate the way
//                    vc-test-suite-implementations lets them: OAuth 2.0
//                    client credentials, the secret in an environment
//                    variable the manifest names.
//   * suiteDir()     where tests/vc-suites/fetch-suites.sh installed a suite
//                    (STS_VC_SUITES_DIR, /opt/vc-suites in the tests image).
//   * writeConfig()  the suite's localConfig.cjs — the implementation
//                    manifest, pointing at the realm's adapter.
//   * runMocha()     a suite run through its own mocha with mocha's JSON
//                    reporter, the context hook (tests/vc-suites/
//                    offline-contexts.cjs) required; answers every test with
//                    its state.
//   * judge()        every failure either a DOCUMENTED EXCEPTION (the job's
//                    table, each also on its ticket) or the job's failure;
//                    an exception that did not occur is said, so the table
//                    cannot outlive its reason unnoticed.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const names = require("./random_username.js");

const log = require("bunyan").createLogger({ name: "vc_suites_kit",
  level: process.env.LOG_LEVEL || "info" });

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const root = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");

const SUITES_DIR = process.env.STS_VC_SUITES_DIR || "/opt/vc-suites";
const OFFLINE = path.join(__dirname, "..", "vc-suites",
                          "offline-contexts.cjs");

// A JSON call to this service. The preload (tests/tools/attach-admin-token.js)
// presents the run's /admin-api token on every /admin-api URL.
async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const given = options || {};
  const headers = Object.assign({}, given.headers || {});
  let body;
  if (given.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(given.json);
  } else if (given.form !== undefined) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(given.form).toString();
  }
  const r = await fetch(url, { method: method, headers: headers,
                               body: body });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json,
           headers: r.headers };
}

async function ok(url, json, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, { json: json });
  assert.ok(r.status === 200 || r.status === 201,
    what + ": " + r.status + " " + r.text.slice(0, 300));
  log.info("  " + what);
  log.debug("Leaving ok().");
  return r.json;
}

// ---------------------------------------------------------------------------
// THE REALM, THE CLIENT AND THE TOKEN.
// ---------------------------------------------------------------------------
async function setUp(prefix) {
  log.debug("Entering setUp(). " + prefix);
  const tag = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
    .slice(0, 12);
  const realm = prefix + "-" + tag;
  const realmBase = root + "/realm/" + realm;
  await ok(root + "/admin-api/realms/create", { id: realm,
    domain: realm + ".example.net", name: "W3C suite " + realm,
    overrides: { "global.mode": "development" } },
    "created the development realm " + realm);
  await ok(realmBase + "/admin-api/config/set",
           { key: "oauth2.openRegistration", value: true },
           "opened registration in " + realm);
  const reg = await call("POST", realmBase + "/oauth2/register", { json: {
    grant_types: ["client_credentials"],
    token_endpoint_auth_method: "client_secret_post",
    client_name: "W3C VC test suites" } });
  assert.strictEqual(reg.status, 201, "registration: " +
                     reg.text.slice(0, 300));
  for (const scope of ["vc-api:issue", "vc-api:verify"]) {
    await ok(realmBase + "/admin-api/applications/add",
             { application: reg.json.client_id,
               attribute: "oauthAllowedScope", value: scope },
             "declared " + scope + " on " + reg.json.client_id);
  }
  const token = await call("POST", realmBase + "/oauth2/token", { form: {
    grant_type: "client_credentials", client_id: reg.json.client_id,
    client_secret: reg.json.client_secret,
    scope: "vc-api:issue vc-api:verify" } });
  assert.strictEqual(token.status, 200, "token: " + token.text.slice(0, 300));
  const issuers = await call("GET", realmBase + "/vc-api/issuers",
    { headers: { Authorization: "Bearer " + token.json.access_token } });
  assert.strictEqual(issuers.status, 200, "the issuer list: " +
                     issuers.text.slice(0, 300));
  const byName = {};
  issuers.json.issuers.forEach(function (one) {
    byName[one.name] = one;
  });
  log.info("  a vc-api:issue vc-api:verify token for " + reg.json.client_id);
  log.debug("Leaving setUp().");
  return { realm: realm, realmBase: realmBase, root: root,
           clientId: reg.json.client_id,
           clientSecret: reg.json.client_secret,
           token: token.json.access_token, issuers: byName };
}

function suiteDir(name) {
  log.debug("Entering suiteDir(). " + name);
  const dir = path.join(SUITES_DIR, name);
  assert.ok(fs.existsSync(path.join(dir, "package.json")),
    "the " + name + " is not installed at " + dir + " (tests/vc-suites/" +
    "fetch-suites.sh, run by tests/Dockerfile; STS_VC_SUITES_DIR points a " +
    "hand run elsewhere)");
  log.debug("Leaving suiteDir().");
  return dir;
}

function commitOf(dir) {
  log.debug("Entering commitOf().");
  let commit = "";
  try {
    commit = fs.readFileSync(path.join(dir, "COMMIT"), "utf8").trim();
  } catch (e) {
    log.debug("Caught in commitOf(): " + ((e && e.message) || e));
    commit = "(no COMMIT file)";
  }
  log.debug("Leaving commitOf().");
  return commit;
}

// The implementation manifest's OAuth 2.0 half, for the env's secret.
function oauth2Of(ctx) {
  log.debug("Entering oauth2Of().");
  log.debug("Leaving oauth2Of().");
  return { clientId: ctx.clientId, clientSecret: "VC_API_CLIENT_SECRET",
           tokenAudience: ctx.realmBase,
           tokenEndpoint: ctx.realmBase + "/oauth2/token" };
}

// An issuer, verifier or other endpoint entry of the manifest.
function endpoint(ctx, name, url, tags, scope, extra) {
  log.debug("Entering endpoint(). " + name);
  log.debug("Leaving endpoint().");
  return Object.assign({ id: name, endpoint: url, tags: tags,
                         scopes: [scope] }, extra || {});
}

function writeConfig(dir, implementation, settings) {
  log.debug("Entering writeConfig().");
  const config = { settings: Object.assign({ enableInteropTests: false,
    testAllImplementations: false }, settings || {}),
    implementations: [implementation] };
  fs.writeFileSync(path.join(dir, "localConfig.cjs"),
    "module.exports = " + JSON.stringify(config, null, 2) + ";\n");
  log.debug("Leaving writeConfig().");
}

// ---------------------------------------------------------------------------
// A MOCHA RUN. `files` are paths under the suite (default: tests/). Answers
// `{ tests: [{ title, state, message }], stats }`.
// ---------------------------------------------------------------------------
function runMocha(dir, ctx, opts) {
  log.debug("Entering runMocha(). " + dir);
  const o = opts || {};
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "vc-suite-")),
                        "report.json");
  const args = [path.join(dir, "node_modules", "mocha", "bin", "mocha.js")]
    .concat(o.files || ["tests/"])
    .concat(["--timeout", String(o.timeoutMs || 60000), "--preserve-symlinks",
             "--require", OFFLINE, "--reporter", "json",
             "--reporter-option", "output=" + out]);
  const env = Object.assign({}, process.env, {
    VC_API_CLIENT_SECRET: ctx.clientSecret,
    VC_API_REALM_BASE: ctx.realmBase,
    VC_API_TOKEN: ctx.token,
    NODE_PATH: [path.join(__dirname, "..", "node_modules"),
                process.env.NODE_PATH || ""].join(path.delimiter)
  }, o.env || {});
  const done = childProcess.spawnSync(process.execPath, args, {
    cwd: dir, env: env, encoding: "utf8", maxBuffer: 256 * 1024 * 1024,
    timeout: o.wallMs || 20 * 60 * 1000 });
  if (done.error) {
    throw new Error("mocha could not be run: " + done.error.message);
  }
  (done.stderr || "").split("\n").filter(function (line) {
    return /offline-contexts: fetching/.test(line);
  }).forEach(function (line) {
    log.info("  " + line.trim());
  });
  let report;
  try {
    report = JSON.parse(fs.readFileSync(out, "utf8"));
  } catch (e) {
    log.debug("Caught in runMocha(): " + ((e && e.message) || e));
    throw new Error("the suite wrote no JSON report (exit " + done.status +
                    "): " + String(done.stderr || done.stdout).slice(-3000));
  }
  const tests = [];
  (report.passes || []).forEach(function (t) {
    tests.push({ title: t.fullTitle, state: "passed", message: "" });
  });
  (report.failures || []).forEach(function (t) {
    tests.push({ title: t.fullTitle, state: "failed",
                 message: String((t.err && t.err.message) || "") });
  });
  (report.pending || []).forEach(function (t) {
    tests.push({ title: t.fullTitle, state: "pending", message: "" });
  });
  fs.rmSync(path.dirname(out), { recursive: true, force: true });
  log.debug("Leaving runMocha(). " + tests.length + " test(s).");
  return { tests: tests, stats: report.stats || {} };
}

function tally(tests) {
  log.debug("Entering tally().");
  const counts = { passed: 0, failed: 0, pending: 0 };
  tests.forEach(function (t) {
    counts[t.state] = (counts[t.state] || 0) + 1;
  });
  log.debug("Leaving tally().");
  return counts;
}

// ---------------------------------------------------------------------------
// EVERY FAILURE FIXED OR DOCUMENTED. `exceptions` maps a test's full title
// to its reason; `pendingReasons` maps a PENDING title (a test the suite
// itself skips) to why nothing here runs it. An unexplained pending test is
// reported, and so is an exception that did not occur.
// ---------------------------------------------------------------------------
function judge(what, tests, exceptions, pendingReasons) {
  log.debug("Entering judge(). " + what);
  const counts = tally(tests);
  log.info("  " + what + ": " + counts.passed + " passed, " + counts.failed +
           " failed, " + counts.pending + " pending");
  const unexplained = [];
  const seen = {};
  tests.forEach(function (t) {
    if (t.state === "failed") {
      if (exceptions[t.title]) {
        seen[t.title] = true;
        log.info("  [exception] " + t.title + ": " + exceptions[t.title]);
        return;
      }
      unexplained.push(t.title + ": " + t.message.slice(0, 600));
      log.error("  [unexplained failure] " + t.title + ": " +
                t.message.slice(0, 600));
    } else if (t.state === "pending") {
      const reason = (pendingReasons || {})[t.title] ||
        ((pendingReasons || {})["*"]);
      log.info("  [pending] " + t.title + (reason ? ": " + reason : ""));
    }
  });
  Object.keys(exceptions).forEach(function (title) {
    if (!seen[title]) {
      log.info("  [exception not seen] " + title + " — it passed or did " +
               "not run; if that holds, take it off the list.");
    }
  });
  assert.strictEqual(unexplained.length, 0, what + ": " + unexplained.length +
    " unexplained failure(s): " + unexplained.join(" | ").slice(0, 4000));
  assert.ok(counts.passed > 0, what + ": no test passed at all");
  log.debug("Leaving judge().");
  return counts;
}

module.exports = {
  root: root, call: call, ok: ok, setUp: setUp, suiteDir: suiteDir,
  commitOf: commitOf, oauth2Of: oauth2Of, endpoint: endpoint,
  writeConfig: writeConfig, runMocha: runMocha, tally: tally, judge: judge
};
