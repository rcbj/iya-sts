"use strict";
//
// File: sts_vc_data_model_suite.js
//
// ---------------------------------------------------------------------------
// THE W3C VC DATA MODEL 2.0 TEST SUITE AGAINST THIS SERVICE (#194,
// 2026-09-26).
//
// w3c/vc-data-model-2.0-test-suite (W3C 3-clause BSD / test suite licence,
// pinned by tests/vc-suites/fetch-suites.sh) is the Working Group's own
// interoperability suite for the Recommendation: it drives an issuer, a
// verifier and a presentation verifier through the VC-API test endpoints and
// checks the data model's MUSTs on what comes back and what is refused. Here
// they are oid4vc/vc_api.ts's adapter in a throwaway development realm:
//
//   issuers     eddsa-rdfc-2022 (vc2.0) — the securing mechanism the suite
//               recommends — and jose-p256 (EnvelopingProof), this service's
//               VC-JOSE-COSE envelope
//   verifiers   /vc-api/credentials/verify (vc2.0, EnvelopingProof)
//   vpVerifiers /vc-api/presentations/verify (vc2.0, EnvelopingProof)
//
// Interop is on: with only this implementation configured it is this
// issuer's credentials checked by this verifier.
//
// WHAT FAILS THIS JOB: any failed test not in EXCEPTIONS, each of which is
// also recorded on #194 with its reason.
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
var log = require("bunyan").createLogger({ name: "sts_vc_data_model_suite",
  level: appconfig.LOG_LEVEL || process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const SUITE = "vc-data-model-2.0-test-suite";

// The suite's ENVELOPED PRESENTATION fixture is a VC-JWT 1.1 token — its
// payload carries the presentation in a `vp` claim — which VC-JOSE-COSE
// section 3.1.1 says a VCDM 2.0 envelope MUST NOT carry, and the
// VC-JOSE-COSE suite (#198, its test 15) requires a verifier to refuse. The
// two suites cannot both pass; this verifier follows the Recommendation.
const LEGACY_VP = "the suite's enveloped presentation is a VC-JWT 1.1 " +
  "token with a `vp` claim, which VC-JOSE-COSE section 3.1.1 forbids in a " +
  "VCDM 2.0 envelope (and the VC-JOSE-COSE suite's test 15 requires a " +
  "verifier to refuse); this verifier refuses it";
const EXCEPTIONS = {};
[
  "The @context property of the object MUST be present and include a " +
  "context, such as the base context for this specification, that defines " +
  "at least the id, type, and EnvelopedVerifiablePresentation terms as " +
  "defined by the base context provided by this specification.",
  "The id value of the object MUST be a data: URL [RFC2397] that expresses " +
  "a secured verifiable presentation using an enveloping securing " +
  "mechanism, such as Securing Verifiable Credentials using JOSE and COSE " +
  "[VC-JOSE-COSE].",
  "The type value of the object MUST be EnvelopedVerifiablePresentation."
].forEach(function (title) {
  EXCEPTIONS["Enveloped Verifiable Presentations iya-sts " + title] =
    LEGACY_VP;
});

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway development realm and a VC-API token ===");
  const ctx = await kit.setUp("vcdm");
  const dir = kit.suiteDir(SUITE);
  log.info("  " + SUITE + " at " + kit.commitOf(dir));
  const verify = ctx.realmBase + "/vc-api/credentials/verify";
  const vpVerify = ctx.realmBase + "/vc-api/presentations/verify";
  kit.writeConfig(dir, {
    name: "iya-sts", implementation: "iya-sts VC-API adapter",
    oauth2: kit.oauth2Of(ctx),
    issuers: [
      kit.endpoint(ctx, ctx.issuers["eddsa-rdfc-2022"].id,
                   ctx.issuers["eddsa-rdfc-2022"].endpoint, ["vc2.0"],
                   "vc-api:issue"),
      kit.endpoint(ctx, ctx.issuers["jose-p256"].id,
                   ctx.issuers["jose-p256"].endpoint, ["EnvelopingProof"],
                   "vc-api:issue")],
    verifiers: [kit.endpoint(ctx, ctx.realmBase + "/vc-api", verify,
                             ["vc2.0", "EnvelopingProof"], "vc-api:verify")],
    vpVerifiers: [kit.endpoint(ctx, ctx.realmBase + "/vc-api", vpVerify,
                               ["vc2.0", "EnvelopingProof"],
                               "vc-api:verify")]
  }, { enableInteropTests: true });
  log.info("=== 1. the suite ===");
  const run = kit.runMocha(dir, ctx);
  kit.judge(SUITE, run.tests, EXCEPTIONS, {});
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The W3C VC Data Model 2.0 test suite (#194) against the " +
    "VC-API adapter of a throwaway realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
