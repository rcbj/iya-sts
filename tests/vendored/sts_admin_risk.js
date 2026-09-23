// File: sts_admin_risk.js
//
// ===========================================================================
// RISK DATASETS AND THE FAILURE HISTORY OVER HTTP, IN EVERY MODE (#62 P1,
// 2026-09-22).
//
// `tests/risk_datasets.js` holds the datasets to their rules in process, on
// the memory store. This job holds the RUNNING service to them through the
// two surfaces an operator uses — Monitoring → Risk (`/admin/risk`) and
// `/admin-api/risk` — so that in `single-node` and `cluster` it is the
// postgres driver's `sts_risk_*` tables that answer:
//
//   1. THE VIEW: every dataset in the catalogue, the store named, and the
//      page drawn with its lookup form;
//   2. IMPORT AND LOOK UP: an operator deny list imported through the API is
//      active, and a lookup of an address inside it names the list and the
//      version that answered;
//   3. A VERSION IS VERIFIED: a SHA-256 that does not match is refused and
//      the refused version is kept with its reason, the active one untouched;
//   4. A SECOND VERSION, THEN ROLLBACK: lookups follow each — through the
//      balancer in the `cluster` mode, so a version activated on one node is
//      answered by BOTH, which is the `risk-dataset` change row at work;
//   5. RULE 7: an unknown action is refused in the sentence the API's own
//      tests parse, and a superseded version's rows can be deleted;
//   6. THE FAILURE HISTORY: a refused SCIM Basic password (the reserved
//      password `invalid`, refused in every mode) is recorded for the door,
//      under a digest of a name that matched nobody — and the typed name is
//      nowhere in the answer.
//
// Every list here is the default realm's own operator deny list, and each
// run's content differs (the stamp is in a comment), so a run against a
// store an earlier run used loads new versions rather than finding its own.
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
const log = bunyan.createLogger({ name: "sts_admin_risk",
                                  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
const crypto = require("crypto");
const signin = require("./console_signin");

const stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
const base = String(process.env.OID4VCI_ISSUER_URL ||
                    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = Date.now().toString(36) + crypto.randomBytes(3).toString("hex");
const DATASET = "iplist.operator-deny";
const REALM = "default";

// Five /24 networks in 198.18.0.0/15 (RFC 2544, reserved for benchmarking):
// synthetic, as every fixture here is, and never dialled. The comment carries
// the stamp, so the content — and the version, which is its SHA-256 by
// default — is new on every run.
function listOf(third) {
  log.debug("Entering listOf().");
  const lines = ["# sts_admin_risk " + STAMP + " " + third];
  for (let i = 0; i < 5; i++) {
    lines.push("198.18." + (third + i) + ".0/24");
  }
  log.debug("Leaving listOf().");
  return lines.join("\n") + "\n";
}

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  ✓ " + what);
  log.debug("Leaving check().");
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

async function api(method, path, payload) {
  log.debug("Entering api(). " + method + " " + path);
  const options = payload === undefined ? {}
    : { headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload) };
  const reply = await call(method, base + path, options);
  log.debug("Leaving api().");
  return reply;
}

async function until(what, fn, limitMs) {
  log.debug("Entering until(). " + what);
  const deadline = Date.now() + (limitMs || 30000);
  for (;;) {
    const got = await fn();
    if (got) {
      log.debug("Leaving until(). Met.");
      return got;
    }
    if (Date.now() > deadline) {
      log.debug("Leaving until(). Timed out.");
      assert.fail("timed out waiting for " + what);
    }
    await new Promise(function (resolve) { setTimeout(resolve, 500); });
  }
}

async function lookup(address) {
  log.debug("Entering lookup(). " + address);
  const r = await api("GET", "/admin-api/risk?realm=" + REALM +
                      "&address=" + encodeURIComponent(address));
  assert.strictEqual(r.status, 200, "GET /admin-api/risk answered " +
                     r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving lookup().");
  return r.body;
}

function denyVersionIn(view) {
  log.debug("Entering denyVersionIn().");
  log.debug("Leaving denyVersionIn().");
  return (view.lookup && view.lookup.datasets &&
          view.lookup.datasets[DATASET]) || "";
}

async function theView(cookie) {
  log.debug("Entering theView().");
  log.info("=== 1. the view ===");
  const r = await api("GET", "/admin-api/risk?realm=" + REALM);
  check("GET /admin-api/risk lists every dataset and names its store",
        function () {
          assert.strictEqual(r.status, 200, r.text.slice(0, 300));
          const ids = r.body.datasets.map(function (d) {
            return d.dataset;
          });
          ["geo.city", "geo.country", "asn", "iplist.tor-exit",
           "iplist.reputation", "iplist.operator-deny",
           "iplist.operator-allow"].forEach(function (id) {
            assert.ok(ids.indexOf(id) >= 0, id + " is not in " +
                      ids.join(", "));
          });
          assert.ok(r.body.store && typeof r.body.store.database === "boolean",
                    JSON.stringify(r.body.store));
        });
  log.info("  (the risk store: " + JSON.stringify(r.body.store) + ")");
  if (cookie) {
    const page = await call("GET", base + "/admin/risk",
                            { headers: { Cookie: cookie } });
    check("Monitoring → Risk is drawn, with its lookup form", function () {
      assert.strictEqual(page.status, 200, page.text.slice(0, 300));
      assert.ok(page.text.indexOf('id="risk-lookup"') >= 0,
                "no lookup form on the page");
    });
  }
  log.debug("Leaving theView().");
  return r.body;
}

async function importAndLookUp() {
  log.debug("Entering importAndLookUp().");
  log.info("=== 2. import, and look up ===");
  const first = await api("POST", "/admin-api/risk/import", {
    dataset: DATASET, realm: REALM, format: "ip-list", content: listOf(10),
    version: "run-" + STAMP + "-a" });
  check("an operator deny list imported through the API is active",
        function () {
          assert.strictEqual(first.status, 200, first.text.slice(0, 400));
          assert.strictEqual(first.body.rows, 5, first.text.slice(0, 400));
          assert.strictEqual(first.body.activated, true);
        });
  const found = await until("the lookup to see version a", async function () {
    const v = await lookup("198.18.12.34");
    return denyVersionIn(v) === "run-" + STAMP + "-a" ? v : null;
  });
  check("a lookup of an address inside it names the list and the version",
        function () {
          assert.ok(found.lookup.lists.some(function (l) {
            return l.category === "operator-deny";
          }), JSON.stringify(found.lookup));
        });
  const outside = await lookup("198.18.99.1");
  check("and an address outside it is on no list of it", function () {
    assert.ok(!outside.lookup.lists.some(function (l) {
      return l.dataset === DATASET;
    }), JSON.stringify(outside.lookup));
  });
  log.debug("Leaving importAndLookUp().");
}

async function aVersionIsVerified() {
  log.debug("Entering aVersionIsVerified().");
  log.info("=== 3. a version is verified ===");
  const version = "run-" + STAMP + "-bad";
  const refused = await api("POST", "/admin-api/risk/import", {
    dataset: DATASET, realm: REALM, format: "ip-list", content: listOf(30),
    version: version, sha256: "0".repeat(64) });
  check("a SHA-256 that does not match is refused (400)", function () {
    assert.strictEqual(refused.status, 400, refused.text.slice(0, 300));
    assert.ok(/SHA-256/.test(refused.body.errors[0]), refused.text);
  });
  const view = await lookup("198.18.12.34");
  const row = view.datasets.filter(function (d) {
    return d.dataset === DATASET;
  })[0];
  const kept = row.versions.filter(function (v) {
    return v.version === version;
  })[0];
  check("the refused version is kept, with its reason, and the active one " +
        "is untouched", function () {
          assert.ok(kept, "no row for " + version);
          assert.strictEqual(kept.state, "refused");
          assert.ok(/SHA-256/.test(kept.refusal), kept.refusal);
          assert.strictEqual(row.activeVersion, "run-" + STAMP + "-a");
        });
  log.debug("Leaving aVersionIsVerified().");
}

async function aSecondVersionThenRollback() {
  log.debug("Entering aSecondVersionThenRollback().");
  log.info("=== 4. a second version, then rollback ===");
  const second = await api("POST", "/admin-api/risk/import", {
    dataset: DATASET, realm: REALM, format: "ip-list", content: listOf(20),
    version: "run-" + STAMP + "-b" });
  check("a second version is active", function () {
    assert.strictEqual(second.status, 200, second.text.slice(0, 300));
  });
  // Asked several times, so that in the `cluster` mode both nodes behind the
  // balancer have answered.
  for (let i = 0; i < 4; i++) {
    await until("every node to see version b", async function () {
      const v = await lookup("198.18.22.1");
      return denyVersionIn(v) === "run-" + STAMP + "-b" &&
        v.lookup.lists.some(function (l) {
          return l.category === "operator-deny";
        }) ? v : null;
    });
  }
  check("lookups follow it, on every node that answers", function () {});
  const back = await api("POST", "/admin-api/risk/rollback",
                         { dataset: DATASET, realm: REALM });
  check("rollback makes version a active again", function () {
    assert.strictEqual(back.status, 200, back.text.slice(0, 300));
    assert.strictEqual(back.body.version, "run-" + STAMP + "-a");
  });
  for (let i = 0; i < 4; i++) {
    await until("every node to see version a again", async function () {
      const v = await lookup("198.18.22.1");
      return denyVersionIn(v) === "run-" + STAMP + "-a" &&
        !v.lookup.lists.some(function (l) {
          return l.dataset === DATASET;
        }) ? v : null;
    });
  }
  check("and lookups follow the rollback, on every node that answers",
        function () {});
  log.debug("Leaving aSecondVersionThenRollback().");
}

async function ruleSeven() {
  log.debug("Entering ruleSeven().");
  log.info("=== 5. rule 7 ===");
  const unknown = await api("POST", "/admin-api/risk/explode",
                            { dataset: DATASET });
  check("an unknown action is refused in the sentence the API's tests parse",
        function () {
          assert.strictEqual(unknown.status, 400, unknown.text.slice(0, 300));
          assert.strictEqual(unknown.body.errors[0],
                             'Unknown action "explode". The 4 are: import, ' +
                             'activate, rollback, delete.');
        });
  const deleted = await api("POST", "/admin-api/risk/delete", {
    dataset: DATASET, realm: REALM, version: "run-" + STAMP + "-b" });
  check("a superseded version's rows are deleted, and its record stays",
        function () {
          assert.strictEqual(deleted.status, 200, deleted.text.slice(0, 300));
          assert.strictEqual(deleted.body.rows, 5, deleted.text);
        });
  log.debug("Leaving ruleSeven().");
}

async function theFailureHistory() {
  log.debug("Entering theFailureHistory().");
  log.info("=== 6. the failure history ===");
  const typed = "risk-probe-" + STAMP;
  const before = await api("GET", "/admin-api/risk?realm=" + REALM);
  const scim = await call("GET", base + "/scim/v2/Users", {
    headers: { Authorization: "Basic " +
      Buffer.from(typed + ":invalid").toString("base64") } });
  check("a SCIM Basic request with the reserved password is refused (401)",
        function () {
          assert.strictEqual(scim.status, 401, scim.text.slice(0, 300));
        });
  const after = await until("the failure to be recorded", async function () {
    const r = await api("GET", "/admin-api/risk?realm=" + REALM);
    const mine = (r.body.failures.rows || []).filter(function (row) {
      return row.door === "SCIM HTTP Basic" && !row.subject &&
        row.at >= Date.now() - 120000;
    });
    return r.body.failures.total > before.body.failures.total && mine.length
      ? r : null;
  });
  check("it is recorded for the door, under a digest of a name that " +
        "matched nobody", function () {
          const row = after.body.failures.rows.filter(function (one) {
            return one.door === "SCIM HTTP Basic";
          })[0];
          assert.ok(/^digest /.test(row.name), JSON.stringify(row));
          assert.ok(row.prefix, JSON.stringify(row));
          assert.ok(row.errorCode, JSON.stringify(row));
        });
  check("and the typed name is nowhere in the answer", function () {
    assert.ok(after.text.indexOf(typed) < 0, "the name is in the view");
  });
  log.info("  (failures held in the database: " +
           after.body.failures.store.database + ")");
  log.debug("Leaving theFailureHistory().");
}

async function main() {
  log.debug("Entering main().");
  const admin = "risk-admin-" + STAMP;
  const cookie = await signin.signInToTheConsole(base, admin, log,
                                                 { grant: "write" });
  await theView(cookie || "");
  await importAndLookUp();
  await aVersionIsVerified();
  await aSecondVersionThenRollback();
  await ruleSeven();
  await theFailureHistory();
  log.info("sts_admin_risk: " + checks + " check(s) passed.");
  log.debug("Leaving main().");
}

main().catch(function (e) {
  log.error("sts_admin_risk FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
