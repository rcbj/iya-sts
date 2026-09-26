"use strict";
//
// File: sts_vc_jose_cose_suite.js
//
// ---------------------------------------------------------------------------
// THE W3C VC-JOSE-COSE TEST SUITE AGAINST THIS SERVICE (#198, 2026-09-26).
//
// w3c/vc-jose-cose-test-suite (W3C 3-clause BSD, pinned by
// tests/vc-suites/fetch-suites.sh) tests Securing Verifiable Credentials
// using JOSE and COSE: issuing and verifying `vc+jwt` / `vp+jwt`,
// `vc+sd-jwt` / `vp+sd-jwt` and `vc+cose` / `vp+cose`, 35 tests, every
// feature declared supported. It runs an implementation as a command line
// in a container (`docker compose run`); here the command is
// tests/vc-suites/jose-cose-cli.js over oid4vc/vc_api.ts's adapter, and
// tests/vc-suites/bin/docker — first on the suite's PATH — is what answers
// that one command shape (its header argues why no container is started).
// The adapter runs in a throwaway development realm.
//
// WHAT FAILS THIS JOB: any failed test not in EXCEPTIONS, each of which is
// also recorded on #198 with its reason. The four are the suite's FIXTURES
// disagreeing with the Recommendation or the RFCs under it; each names the
// clause.
// ---------------------------------------------------------------------------

const fs = require("fs");
const path = require("path");
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
var log = require("bunyan").createLogger({ name: "sts_vc_jose_cose_suite",
  level: appconfig.LOG_LEVEL || process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const SUITE = "vc-jose-cose-test-suite";

const EXCEPTIONS = {
  "JOSE Tests iya-sts 5. JWT Issuance with Unknown Extensions":
    "the suite expects the issuer to refuse a credential with the " +
    "members badExtension and anotherBadOne; its @context includes the " +
    "examples context, whose @vocab defines EVERY term, so JSON-LD safe " +
    "mode — how this issuer detects an undefined term (VCDM 2.0 section " +
    "5.2) — finds none, and no clause of the Recommendations makes a " +
    "vocab-defined term an error",
  "JOSE Tests iya-sts 7. JWT Presentation Verification":
    "the fixture presentation's exp is 1734397450 (2024-12-17T01:04:10Z); " +
    "RFC 7519 section 4.1.4 requires the current time to be before exp, so " +
    "a conforming verifier refuses it (the suite's fixture expired)",
  "SD-JWT Tests iya-sts 22. SD-JWT Presentation Verification":
    "the presentation's credential is signed EdDSA by a key the suite does " +
    "not supply (it names only the presentation's P-384 key); this " +
    "verifier verifies every credential a presentation carries " +
    "(VC-JOSE-COSE section 3.2.2: credentials in verifiable presentations " +
    "MUST be secured) and fetches no key, so it cannot verify that one",
  "COSE Tests iya-sts 31. COSE Basic Presentation Verification":
    "the credential inside the fixture presentation is not a compact JWS " +
    "(its data: URL holds six dot-separated parts); VC-JOSE-COSE section " +
    "3.3.2 says credentials in verifiable presentations MUST be secured, " +
    "and this verifier checks that they are"
};

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway development realm and a VC-API token ===");
  const ctx = await kit.setUp("vcjose");
  const dir = kit.suiteDir(SUITE);
  log.info("  " + SUITE + " at " + kit.commitOf(dir));
  kit.writeConfig(dir, {
    name: "iya-sts", implementation: "iya-sts VC-API adapter",
    "jose-cose": { features: { credential_jose: true, credential_sdjwt: true,
      credential_cose: true, presentation_jose: true,
      presentation_sdjwt: true, presentation_cose: true } }
  });
  const output = path.join(dir, "tests", "output");
  fs.readdirSync(output).filter(function (f) {
    return /\.json$/.test(f);
  }).forEach(function (f) {
    fs.unlinkSync(path.join(output, f));
  });
  const bin = path.join(__dirname, "..", "vc-suites", "bin");
  log.info("=== 1. the suite ===");
  const run = kit.runMocha(dir, ctx, { timeoutMs: 150000, env: {
    PATH: bin + path.delimiter + process.env.PATH,
    VC_JOSE_COSE_SUITE_DIR: dir } });
  kit.judge(SUITE, run.tests, EXCEPTIONS, {});
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The W3C VC-JOSE-COSE test suite (#198) against the VC-API " +
    "adapter of a throwaway realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
