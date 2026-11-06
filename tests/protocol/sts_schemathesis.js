// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_schemathesis.js
//
// ===========================================================================
// SCHEMATHESIS AGAINST THE FOUR APIS AND THE PROTOCOL SURFACE (#1299).
//
// A `local: true` job. It provisions three realm profiles (product baseline,
// RFC 9700, OAuth 2.1) and a fuzz person through `/admin-api`, then runs the
// unmodified Schemathesis CLI against each (realm x surface) through the auth
// proxy — account-api, authn-api, admin-api, report-api from their published
// OpenAPI documents, and every protocol endpoint from a document synthesized
// from the running router. `schemathesis_kit.js` holds the PLAN and the run;
// `tests/schemathesis_plan.js` asserts the PLAN in process without a stack.
//
// It expects a DEDICATED, network-isolated product stack — the `fuzz` mode of
// run-tests.sh — because it uses any method and any input and the stack must
// not reach an external URL. It needs STS_ADMIN_API_TOKEN (the launcher mints
// it) and the Schemathesis install the tests image builds
// (STS_SCHEMATHESIS_DIR). It is `exclusive: true`: it creates realms and a
// fuzz person and drives the whole surface hard.
//
// It passes when every (realm x surface) run exits 0 — no server error, no
// leaked error code, no dropped frame-ancestors, no outbound fetch, and no
// built-in conformance failure. A run that exits 1 is a check failure (a
// finding); a run that exits 2 tested nothing or hit a schema/config error
// (a wiring problem). Each non-passing run is printed with its tail.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const kit = require("./schemathesis_kit.js");
const expectation = require("./expectation.js");

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
var log = bunyan.createLogger({ name: "sts_schemathesis",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

// The service's base URL, as every local protocol job reads it
// (enroll_clients_kit.js's computation).
function serviceBase() {
  log.debug("Entering serviceBase().");
  const stsUrl = process.env.WSTRUST_STS_URL ||
    "https://localhost:8081/sts";
  const base = String(process.env.OID4VCI_ISSUER_URL ||
    stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
  log.debug("Leaving serviceBase(). " + base);
  return base;
}

async function test() {
  log.debug("Entering test().");
  // THE FUZZ JOB RUNS ONLY IN THE `fuzz` MODE, AND NOWHERE ELSE — the same
  // self-skip the cells jobs take (sts_cells_map.js). It expects a DEDICATED,
  // network-isolated product stack (run-tests.sh's `fuzz` mode), throws any
  // input at every surface and runs for over an hour; against the ordinary
  // suite stack, which answers in no realm of its own and is not isolated,
  // it must not run at all. The marker is set by the fuzz compose overlay's
  // `tests` service (tests/docker-compose-run-tests-fuzz.yml), the way the
  // cells markers arrive — not through tools/modes.sh, whose "every mode
  // names every variable" rule would force a fuzz marker into every arm. So
  // a bare `./run-tests.sh`, which does not layer that overlay, leaves it
  // unset and this job is a skip rather than a 77-minute run against a stack
  // that is not built for it.
  if (!process.env.STS_TEST_FUZZ) {
    expectation.declineToRun(log, "not the fuzz mode: STS_TEST_FUZZ is " +
      "unset, so this is the ordinary suite stack and not the dedicated, " +
      "network-isolated product stack this job needs. Run it with " +
      "`./run-tests.sh --modes=fuzz --only=schemathesis`.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const base = serviceBase();
  log.info("[schemathesis] driving " + base + " in the three realm profiles");
  const results = await kit.run(base, { say: function (message) {
    log.info(message);
  } });
  results.forEach(function (one) {
    const where = one.surface + " @ " + one.realm;
    if (one.status === "pass") {
      log.info("  PASS " + where);
    } else {
      log.error("  " + one.status.toUpperCase() + " " + where + " (exit " +
                one.code + ")\n" +
                String(one.output || "").split("\n").slice(-60).join("\n"));
    }
    // The structured findings the checks recorded (route -> code/detail),
    // printed in full so the authoritative list survives whatever the output
    // slice above dropped. #1347's leak-sink work reads these lines.
    const findings = Array.isArray(one.findings) ? one.findings : [];
    if (findings.length) {
      log.error("  findings for " + where + " (" + findings.length + "):");
      findings.forEach(function (finding) {
        log.error("    [" + finding.kind + "] " + finding.status + " " +
                  finding.route + " -> " + finding.detail);
      });
    }
  });
  const bad = results.filter(function (one) {
    return one.status !== "pass";
  });
  assert.ok(results.length > 0, "the matrix ran at least one surface");
  assert.strictEqual(bad.length, 0, bad.length + " (realm x surface) " +
    "Schemathesis run(s) did not pass: " + bad.map(function (one) {
      return one.surface + " @ " + one.realm + " (" + one.status + ")";
    }).join(", "));
  log.info("[schemathesis] " + results.length + " runs, all passed.");
  log.debug("Leaving test().");
}

new Command()
  .description("Schemathesis (#1299) against the four APIs and the protocol " +
    "surface, in three realm profiles, on a dedicated product stack.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "reads WSTRUST_STS_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
