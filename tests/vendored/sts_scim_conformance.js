"use strict";
//
// File: sts_scim_conformance.js
//
// ---------------------------------------------------------------------------
// TWO SCIM 2.0 CONFORMANCE HARNESSES AGAINST /scim/v2 (#206, 2026-09-26).
//
// No official SCIM conformance suite exists — the IETF working group
// published none — so this runs the two independent ones that do:
//
//   1. python-scim's SCIM2-TESTER (Apache-2.0, 0.4.0, pinned by hash in
//      tests/scim-conformance/requirements.txt): discovery
//      (ServiceProviderConfig, ResourceTypes, Schemas), then for EVERY
//      resource type the service publishes, create, read, list, `.search`,
//      the `attributes` parameter, replace, PATCH add / remove / replace of
//      every attribute the published schema declares, and delete, plus a
//      random URL's error. It is driven by
//      tests/scim-conformance/scim2_tester_driver.py, which runs its
//      check_server() unchanged and prints every result as JSON.
//   2. SCIM2/TEST-SUITE (Apache-2.0, Go, pinned to a commit and a sha256 by
//      tests/scim-conformance/build-test-suite.sh): scim2-tester has no
//      filter expression, sortBy, pagination, Bulk or If-Match check at all,
//      and #206 said to evaluate this suite for what it leaves uncovered. It
//      covers all of them, one result per RFC 7643 / 7644 requirement.
//
// Both run against a THROWAWAY REALM of this service, with an OAuth access
// token carrying `scim:read scim:write` (the SCIM scopes are issued only to a
// client whose oauthAllowedScope declares them, #110), in development mode
// (`memory`) and product mode (`single-node`).
//
// WHAT FAILS THIS JOB: any scim2-tester result that is ERROR, CRITICAL or
// DEVIATION (its warning), and any scim2/test-suite result that is FAIL or
// WARN, unless it is in EXCEPTIONS below — each of which is recorded on #206
// with its reason. An exception that did not occur is reported, so the list
// cannot outlive the reason for it unnoticed.
//
// OWNED HERE (local: true): this repository's SCIM surface, its management
// API and its authorization server. tests/CLAUDE.md, *The SCIM conformance
// harnesses*, is the provenance of both tools.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");

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
var log = bunyan.createLogger({ name: "sts_scim_conformance",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TAG = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 12);
const REALM = "scimc-" + TAG;
const realmBase = root + "/realm/" + REALM;
const SCIM_BASE = realmBase + "/scim/v2";
const RELATIONSHIP = "scim-conformance-partner";
const PEER = "https://partner.scim-conformance.example";

// Where the two harnesses are. tests/Dockerfile installs both and sets these;
// a hand run on a host points them at a virtual environment and a binary (or
// a wrapper that runs the binary in a container).
const PYTHON = process.env.STS_SCIM2_TESTER_PYTHON ||
  "/opt/scim2-tester/bin/python";
const SUITE = process.env.STS_SCIM2_TEST_SUITE ||
  "/opt/scim2-test-suite/scim-compliance";
const DRIVER = path.join(__dirname, "..", "scim-conformance",
                         "scim2_tester_driver.py");

// ---------------------------------------------------------------------------
// THE DOCUMENTED EXCEPTIONS, each also recorded on #206 with its reason.
// Keyed `<harness> <id>`; `modes` limits one to development or product.
// ---------------------------------------------------------------------------
const TEST_RESOURCE = "scim2/test-suite's own TestResource resource type, " +
  "which only its built-in server defines (/TestResources); RFC 7643 has " +
  "no such resource, and the requirement is covered on User and Group by " +
  "the suite's other tests";
const NICKNAME = "the suite hard-codes nickName, an OPTIONAL RFC 7643 " +
  "attribute this directory has no place for and so no longer publishes in " +
  "/Schemas; a PATCH to an undeclared attribute is refused 400 invalidPath " +
  "rather than answered 200 and dropped";
const FUZZED_REF = "the suite's fuzzer gives a Group member the $ref " +
  "https://example.com/<random>, a URI that references no User or Group " +
  "(RFC 7643 section 2.3.7, referenceTypes User and Group), and it is " +
  "refused 400 invalidValue; a Group with real members is created and read " +
  "by the suite's other tests";
const ABSOLUTE_REF = "the suite joins the member's $ref onto its own base " +
  "URL (scim/client.go: BaseURL + \"/\" + path), and this service's $ref " +
  "is ABSOLUTE, as RFC 7643 section 2.3.7's examples are — so it GETs " +
  "<base>/https://… and is answered 404; the $ref itself resolves";
const HOME_EMAIL = "the suite hard-codes an email of type \"home\"; mail " +
  "has no type, so emails.type publishes only \"work\" (RFC 7643 section " +
  "2.3.1 lets a service provider restrict canonical values) and a home " +
  "address is refused 400 invalidValue rather than stored as a work one";
const EXCEPTIONS = {
  "test-suite RFC7643-2.1-L366/schemas_present/Group": FUZZED_REF,
  "test-suite RFC7643-2.1-L369/attribute_name_format/Group": FUZZED_REF,
  "test-suite RFC7643-2.3.7-L578/get_member_ref_returns_resource":
    ABSOLUTE_REF,
  "test-suite RFC7644-3.5.2.2-L2151/remove_multi_valued": HOME_EMAIL,
  "test-suite RFC7644-3.5.2.3-L2387/replace_value_path": HOME_EMAIL,
  "test-suite RFC7643-2.3.4-L521/integer_no_fraction": TEST_RESOURCE,
  "test-suite RFC7643-2.3.6-L537/binary_base64_encoded": TEST_RESOURCE,
  "test-suite RFC7643-2.3.7-L552/reference_is_uri": TEST_RESOURCE,
  "test-suite RFC7643-2.3.8-L595/no_nested_complex": TEST_RESOURCE,
  "test-suite RFC7643-3.3-L981/extension_container": TEST_RESOURCE,
  "test-suite RFC7643-6-L1655/required_extension": TEST_RESOURCE,
  "test-suite RFC7643-7-L1748/filter_case_exact": TEST_RESOURCE,
  "test-suite EXTRA-TYPE-INT/integer_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-TYPE-BOOL/boolean_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-TYPE-DT/datetime_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-TYPE-BIN/binary_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-TYPE-REF/reference_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-TYPE-COMPLEX/complex_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-MUT-IMMUTABLE/immutable_attr": TEST_RESOURCE,
  "test-suite EXTRA-MUT-WRITEONLY/write_only_attr": TEST_RESOURCE,
  "test-suite EXTRA-MUT-READONLY/read_only_ignored": TEST_RESOURCE,
  "test-suite EXTRA-RET-ALWAYS/returned_always": TEST_RESOURCE,
  "test-suite EXTRA-RET-NEVER/returned_never": TEST_RESOURCE,
  "test-suite EXTRA-CASE-EXACT/filter_case_exact": TEST_RESOURCE,
  "test-suite EXTRA-CASE-INSENSITIVE/filter_case_insensitive": TEST_RESOURCE,
  "test-suite EXTRA-EXT-CONTAINER/extension_container": TEST_RESOURCE,
  "test-suite EXTRA-EXT-ROUNDTRIP/extension_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-EXT-SCHEMAS/extension_schemas": TEST_RESOURCE,
  "test-suite EXTRA-MV-ROUNDTRIP/multi_valued_round_trip": TEST_RESOURCE,
  "test-suite EXTRA-MV-COMPLEX-PRIMARY/multi_complex_primary": TEST_RESOURCE,
  "test-suite RFC7644-3.5.2-L1808/operations_array": NICKNAME,
  "test-suite RFC7644-3.5.2.3-L2376/replace_non_existent": NICKNAME
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

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
  const r = await fetch(url, { method: method, headers: headers, body: body });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json };
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

// The throwaway realm, a client in it that may be issued the two SCIM
// scopes, and a token carrying both, addressed to this realm's resource
// server (RFC 9068 section 4).
async function setUp(product) {
  log.debug("Entering setUp().");
  await ok(root + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "SCIM conformance " + REALM },
    "created the realm " + REALM);
  // Product mode closes dynamic registration; this realm opens it for the
  // one client below.
  await ok(realmBase + "/admin-api/config/set",
           { key: "oauth2.openRegistration", value: true },
           "opened registration in " + REALM);
  // Development mode fills a provisioned person in with an invented persona
  // (scim.inventOnCreate); the harnesses read back what they wrote, so this
  // realm writes only that. Product invents nothing either way.
  await ok(realmBase + "/admin-api/config/set",
           { key: "scim.inventOnCreate", value: false },
           "a SCIM create in " + REALM + " invents nothing");
  // A service-provider-side federation relationship, so that the harness can
  // write this service's own `federationLinks` extension member, whose
  // `relationship` must name one (scim/CLAUDE.md, #109). Never enabled: a
  // link needs the relationship to exist, not to sign anybody in.
  await ok(realmBase + "/admin-api/federation/create", { id: RELATIONSHIP,
    role: "service-provider", protocol: "oidc", peer: PEER },
    "created the relationship " + RELATIONSHIP);
  const reg = await call("POST", realmBase + "/oauth2/register", { json: {
    grant_types: ["client_credentials"],
    token_endpoint_auth_method: "client_secret_basic",
    client_name: "SCIM conformance harnesses" } });
  assert.strictEqual(reg.status, 201, "registration: " + reg.text.slice(0,
                                                                        300));
  const client = reg.json;
  for (const scope of ["scim:read", "scim:write"]) {
    await ok(realmBase + "/admin-api/applications/add",
             { application: client.client_id,
               attribute: "oauthAllowedScope", value: scope },
             "declared " + scope + " on " + client.client_id);
  }
  const token = await call("POST", realmBase + "/oauth2/token", {
    headers: { Authorization: "Basic " + Buffer.from(client.client_id + ":" +
      client.client_secret).toString("base64") },
    form: { grant_type: "client_credentials",
            scope: "scim:read scim:write",
            resource: realmBase + "/resource" } });
  assert.strictEqual(token.status, 200, "token: " + token.text.slice(0, 300));
  assert.ok(String(token.json.scope || "").split(" ").indexOf("scim:write") >=
            0, "the token carries scim:write: " + token.text.slice(0, 300));
  log.info("  minted a scim:read scim:write token (" +
           (product ? "product" : "development") + " mode)");
  log.debug("Leaving setUp().");
  return token.json.access_token;
}

function run(command, args, env, what) {
  log.debug("Entering run(). " + what);
  const done = childProcess.spawnSync(command, args, {
    env: Object.assign({}, process.env, env), encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024, timeout: 20 * 60 * 1000 });
  if (done.error) {
    throw new Error(what + " could not be run (" + command + "): " +
                    done.error.message);
  }
  log.debug("Leaving run(). exit " + done.status);
  return done;
}

// scim2-tester, through the driver. Every result is one row.
function runScim2Tester(token) {
  log.debug("Entering runScim2Tester().");
  const done = run(PYTHON, [DRIVER], {
    SCIM_BASE_URL: SCIM_BASE, SCIM_TOKEN: token,
    SCIM_CA_FILE: process.env.NODE_EXTRA_CA_CERTS || "",
    SCIM_FEDERATION_RELATIONSHIP: RELATIONSHIP,
    SCIM_FEDERATION_PEER: PEER }, "scim2-tester");
  if (done.stderr) {
    log.debug("scim2-tester stderr: " + done.stderr.slice(0, 4000));
  }
  let report;
  try {
    report = JSON.parse(done.stdout);
  } catch (e) {
    log.debug("Caught in runScim2Tester(): " + ((e && e.message) || e));
    throw new Error("scim2-tester printed no JSON (exit " + done.status +
                    "): " + String(done.stderr || done.stdout).slice(0, 2000));
  }
  assert.ok(!report.crash, "scim2-tester crashed: " + report.crash);
  const rows = report.results.map(function (one) {
    const failing = ["ERROR", "CRITICAL", "DEVIATION"]
      .indexOf(one.status) >= 0;
    return { harness: "scim2-tester",
             id: one.title + (one.resourceType ? " [" + one.resourceType +
                                                 "]" : ""),
             outcome: one.status, failing: failing,
             message: String(one.reason || "") };
  });
  log.debug("Leaving runScim2Tester(). " + rows.length + " result(s).");
  return rows;
}

// scim2/test-suite: its verbose output is one `  [OUTCOME] ID/test` line per
// result, the message on the indented lines after it.
function runTestSuite(token) {
  log.debug("Entering runTestSuite().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scim2-test-suite-"));
  const env = {};
  if (process.env.NODE_EXTRA_CA_CERTS) {
    // Go reads the system roots from here on Linux.
    env.SSL_CERT_FILE = process.env.NODE_EXTRA_CA_CERTS;
  }
  const done = run(SUITE, ["-test.run", "TestCompliance",
    "-scim.url=" + SCIM_BASE, "-scim.token=" + token,
    "-scim.report=" + path.join(dir, "report.txt")], env, "scim2/test-suite");
  const rows = [];
  let last = null;
  String(done.stdout || "").split("\n").forEach(function (line) {
    const m = /^ {2}\[(PASS|FAIL|WARN|SKIP)\] (\S+)\s*$/.exec(line);
    if (m) {
      last = { harness: "test-suite", id: m[2], outcome: m[1],
               failing: m[1] === "FAIL" || m[1] === "WARN", message: "" };
      rows.push(last);
      return;
    }
    if (last && /^ {9}\S/.test(line)) {
      last.message += (last.message ? " " : "") + line.trim();
      return;
    }
    last = null;
  });
  assert.ok(rows.length > 50, "scim2/test-suite reported " + rows.length +
            " result(s) (exit " + done.status + "): " +
            String(done.stdout || done.stderr).slice(0, 2000));
  fs.rmSync(dir, { recursive: true, force: true });
  log.debug("Leaving runTestSuite(). " + rows.length + " result(s).");
  return rows;
}

function tally(rows, harness) {
  log.debug("Entering tally().");
  const counts = {};
  rows.filter(function (row) {
    return row.harness === harness;
  }).forEach(function (row) {
    counts[row.outcome] = (counts[row.outcome] || 0) + 1;
  });
  log.debug("Leaving tally().");
  return Object.keys(counts).sort().map(function (k) {
    return k + " " + counts[k];
  }).join(", ");
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(root + "/admin-api");
  log.info("=== 0. a throwaway realm and a scim:write token (" +
           (product ? "product" : "development") + " mode) ===");
  const token = await setUp(product);

  log.info("=== 1. python-scim scim2-tester ===");
  const tester = runScim2Tester(token);
  log.info("  scim2-tester: " + tally(tester, "scim2-tester"));
  check("scim2-tester discovered and exercised both resource types",
        function () {
    ["User", "Group"].forEach(function (type) {
      assert.ok(tester.some(function (row) {
        return row.id === "object_creation [" + type + "]" &&
               row.outcome === "SUCCESS";
      }), "no successful object_creation for " + type);
    });
  });

  log.info("=== 2. scim2/test-suite ===");
  const suite = runTestSuite(token);
  log.info("  scim2/test-suite: " + tally(suite, "test-suite"));

  const all = tester.concat(suite);
  const unexplained = [];
  const excepted = {};
  all.forEach(function (row) {
    if (!row.failing) {
      return;
    }
    const key = row.harness + " " + row.id;
    if (EXCEPTIONS[key]) {
      excepted[key] = true;
      log.info("  [exception] " + key + " (" + row.outcome + "): " +
               EXCEPTIONS[key]);
      return;
    }
    unexplained.push(key + " " + row.outcome + ": " +
                     row.message.slice(0, 500));
  });
  Object.keys(EXCEPTIONS).forEach(function (key) {
    if (!excepted[key]) {
      log.info("  [exception not seen] " + key + " — it passed or did not " +
               "run this time; if that holds, take it off the list.");
    }
  });
  unexplained.forEach(function (line) {
    log.error("  [unexplained] " + line);
  });
  check("every error and warning of both harnesses is fixed or a " +
        "documented exception", function () {
    assert.strictEqual(unexplained.length, 0, unexplained.length +
      " unexplained: " + unexplained.join(" | ").slice(0, 3000));
  });

  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("SCIM 2.0 conformance (#206): python-scim's scim2-tester and " +
    "scim2/test-suite against /scim/v2 of a throwaway realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
