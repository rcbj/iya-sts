"use strict";
//
// File: sts_vc_di_eddsa_suite.js
//
// ---------------------------------------------------------------------------
// THE W3C DATA INTEGRITY EDDSA CRYPTOSUITES TEST SUITE AGAINST THIS SERVICE
// (#195, 2026-09-26).
//
// w3c/vc-di-eddsa-test-suite (W3C 3-clause BSD, pinned by
// tests/vc-suites/fetch-suites.sh) is the official interop suite for Data
// Integrity EdDSA Cryptosuites v1.0 — `eddsa-rdfc-2022` and
// `eddsa-jcs-2022` — issuer and verifier sides, each for VC 1.1 and 2.0.
// tests/vc_data_integrity.js holds the suites to the specification's
// published vectors; this is the independent check on an issued and a
// verified credential. The implementation is oid4vc/vc_api.ts's adapter in a
// throwaway development realm: the eddsa-rdfc-2022 and eddsa-jcs-2022
// issuers (the realm's Ed25519 key as a did:key) and the one verifier.
// Interop is on, so this issuer's credentials are checked by this verifier.
//
// WHAT FAILS THIS JOB: any failed test not in EXCEPTIONS (none since the
// first run; each would be recorded on #195 with its reason).
// ---------------------------------------------------------------------------

const { Command, Option } = require("commander");
const kit = require("./vc_suites_kit.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand run without one still loads.
  appconfigProblem = e;
  appconfig = {};
}
var log = require("bunyan").createLogger({ name: "sts_vc_di_eddsa_suite",
  level: appconfig.LOG_LEVEL || process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const SUITE = "vc-di-eddsa-test-suite";
const EXCEPTIONS = {};

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway development realm and a VC-API token ===");
  const ctx = await kit.setUp("vceddsa");
  const dir = kit.suiteDir(SUITE);
  log.info("  " + SUITE + " at " + kit.commitOf(dir));
  const both = { supports: { vc: ["1.1", "2.0"] } };
  kit.writeConfig(dir, {
    name: "iya-sts", implementation: "iya-sts VC-API adapter",
    oauth2: kit.oauth2Of(ctx),
    issuers: ["eddsa-rdfc-2022", "eddsa-jcs-2022"].map(function (name) {
      return kit.endpoint(ctx, ctx.issuers[name].id,
                          ctx.issuers[name].endpoint, [name], "vc-api:issue",
                          both);
    }),
    verifiers: [kit.endpoint(ctx, ctx.realmBase + "/vc-api",
                             ctx.realmBase + "/vc-api/credentials/verify",
                             ["eddsa-rdfc-2022", "eddsa-jcs-2022"],
                             "vc-api:verify", both)]
  }, { enableInteropTests: true });
  log.info("=== 1. the suite ===");
  const run = kit.runMocha(dir, ctx);
  kit.judge(SUITE, run.tests, EXCEPTIONS, {});
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The W3C Data Integrity EdDSA test suite (#195) against the " +
    "VC-API adapter of a throwaway realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
