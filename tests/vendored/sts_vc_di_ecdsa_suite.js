"use strict";
//
// File: sts_vc_di_ecdsa_suite.js
//
// ---------------------------------------------------------------------------
// THE W3C DATA INTEGRITY ECDSA CRYPTOSUITES TEST SUITE AGAINST THIS SERVICE
// (#196, 2026-09-26).
//
// w3c/vc-di-ecdsa-test-suite (W3C 3-clause BSD, pinned by
// tests/vc-suites/fetch-suites.sh, its vectors — w3c/vc-di-ecdsa's
// TestVectors — pinned beside it) is the official interop suite for Data
// Integrity ECDSA Cryptosuites v1.0: `ecdsa-rdfc-2019` and `ecdsa-jcs-2019`
// over P-256 and P-384, and `ecdsa-sd-2023`, issuer and verifier sides. The
// implementation is oid4vc/vc_api.ts's adapter in a throwaway development
// realm: an issuer per suite and curve (the realm's P-256 and P-384 keys as
// did:keys; ecdsa-sd-2023 is P-256, as its section 3.5.8 fixes) and one
// verifier for all three suites. Interop is on.
//
// ONE FILE OF THE SUITE IS NOT RUN, AND ITS TEST IS RUN HERE INSTEAD.
// tests/60-sd-interop.js derives each issuer's ecdsa-sd-2023 base proof
// through a HOLDER it looks up by the name "Digital Bazaar"
// (config/runner.json) — that company's hosted endpoint, which a
// configuration of this implementation alone does not have, so its `before`
// hook fails before any assertion. Section 2 of this job is the same test
// with the holder named: this issuer's base proof derived by Digital
// Bazaar's own library — from the suite's installed dependencies, the code
// that hosted holder runs — and by this service's /vc-api/credentials/derive,
// and each derived proof verified by this service's verifier and by Digital
// Bazaar's.
//
// WHAT FAILS THIS JOB: any failed test not in EXCEPTIONS (none since the
// first run; each would be recorded on #196 with its reason).
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = require("bunyan").createLogger({ name: "sts_vc_di_ecdsa_suite",
  level: appconfig.LOG_LEVEL || process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const SUITE = "vc-di-ecdsa-test-suite";
const EXCEPTIONS = {};
// The interop matrix's cells the suite marks pending when a verifier does not
// support the issuer's key type (it skips, it does not fail).
const PENDING = {};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function bearer(ctx) {
  log.debug("Entering bearer().");
  log.debug("Leaving bearer().");
  return { Authorization: "Bearer " + ctx.token };
}

// Every test file of the suite but the one section 2 replaces.
function suiteFiles(dir) {
  log.debug("Entering suiteFiles().");
  const files = fs.readdirSync(path.join(dir, "tests")).filter(function (f) {
    return /^\d+-.*\.js$/.test(f) && f !== "60-sd-interop.js";
  }).map(function (f) {
    return "tests/" + f;
  });
  log.debug("Leaving suiteFiles(). " + files.length + " file(s).");
  return files;
}

// ---------------------------------------------------------------------------
// SECTION 2: ecdsa-sd-2023 interop with the holder named.
// ---------------------------------------------------------------------------
async function sdInterop(ctx, dir) {
  log.debug("Entering sdInterop().");
  const mock = path.join(dir, "tests", "mocks", "valid", "vc2.0");
  const document = JSON.parse(fs.readFileSync(path.join(mock,
                                                        "document.json")));
  const mandatory = JSON.parse(fs.readFileSync(path.join(mock,
                                               "mandatoryPointers.json")));
  const issuer = ctx.issuers["ecdsa-sd-2023-p256"];
  document.issuer = issuer.id;
  const issued = await kit.call("POST", issuer.endpoint, {
    headers: bearer(ctx),
    json: { credential: document,
            options: { mandatoryPointers: mandatory } } });
  check("this issuer secured the suite's interop credential with an " +
        "ecdsa-sd-2023 base proof", function () {
    assert.strictEqual(issued.status, 201, issued.text.slice(0, 600));
    assert.strictEqual(issued.json.verifiableCredential.proof.cryptosuite,
                       "ecdsa-sd-2023");
  });
  const base = issued.json.verifiableCredential;
  const verify = async function verify(vc) {
    log.debug("Entering verify().");
    const r = await kit.call("POST", ctx.realmBase +
                             "/vc-api/credentials/verify",
      { headers: bearer(ctx), json: { verifiableCredential: vc,
                                      options: { checks: ["proof"] } } });
    log.debug("Leaving verify(). " + r.status);
    return r;
  };
  const gen = await import(path.join(dir, "tests", "vc-generator",
                                     "index.js"));
  const byDb = await gen.deriveCredential({ verifiableCredential: base,
    suite: "ecdsa-sd-2023", selectivePointers: ["/credentialSubject/id"] });
  const theirs = await verify(byDb);
  check("Digital Bazaar's holder library derived a proof from this " +
        "issuer's base proof, and this verifier verified it", function () {
    assert.strictEqual(theirs.status, 200, theirs.text.slice(0, 800));
    assert.strictEqual(theirs.json.verified, true);
  });
  const derived = await kit.call("POST", ctx.realmBase +
                                 "/vc-api/credentials/derive",
    { headers: bearer(ctx), json: { verifiableCredential: base,
      options: { selectivePointers: ["/credentialSubject/id"] } } });
  check("this service derived a proof from its own base proof", function () {
    assert.strictEqual(derived.status, 201, derived.text.slice(0, 600));
  });
  const ours = await verify(derived.json.verifiableCredential);
  check("this verifier verified this service's derived proof", function () {
    assert.strictEqual(ours.status, 200, ours.text.slice(0, 800));
  });
  const nm = path.join(dir, "node_modules", "@digitalbazaar");
  const vcLib = await import(path.join(nm, "vc", "lib", "index.js"));
  const di = await import(path.join(nm, "data-integrity", "lib",
                                    "index.js"));
  const sd = await import(path.join(nm, "ecdsa-sd-2023-cryptosuite", "lib",
                                    "index.js"));
  // The suite's loader reads its own config by a path relative to the
  // working directory, so it is loaded from the suite's.
  const here = process.cwd();
  process.chdir(dir);
  let loader;
  try {
    loader = await import(path.join(dir, "tests", "documentLoader.js"));
  } finally {
    process.chdir(here);
  }
  const dbVerified = await vcLib.verifyCredential({
    credential: derived.json.verifiableCredential,
    suite: new di.DataIntegrityProof({
      cryptosuite: sd.createVerifyCryptosuite() }),
    // The suite's loader takes `{ url }` and answers a DID's document
    // bare; the vc library passes the URL and wants a RemoteDocument.
    documentLoader: async function documentLoader(url) {
      log.debug("Entering documentLoader().");
      const got = await loader.documentLoader({ url: url });
      log.debug("Leaving documentLoader().");
      return got && got.document !== undefined ? got
        : { contextUrl: null, documentUrl: url, document: got };
    } });
  check("Digital Bazaar's verifier verified this service's derived proof",
        function () {
    assert.strictEqual(dbVerified.verified, true,
      JSON.stringify(dbVerified.error || dbVerified.results || {})
        .slice(0, 1500));
  });
  const baseAtVerifier = await verify(base);
  check("a BASE proof is not accepted by the verifier (it is the " +
        "holder's to derive from)", function () {
    assert.strictEqual(baseAtVerifier.status, 400);
  });
  log.debug("Leaving sdInterop().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway development realm and a VC-API token ===");
  const ctx = await kit.setUp("vcecdsa");
  const dir = kit.suiteDir(SUITE);
  log.info("  " + SUITE + " at " + kit.commitOf(dir));
  const both = { vc: ["1.1", "2.0"] };
  const issuer = function issuer(name, tag, curve) {
    log.debug("Entering issuer(). " + name);
    log.debug("Leaving issuer().");
    return kit.endpoint(ctx, ctx.issuers[name].id, ctx.issuers[name].endpoint,
                        [tag], "vc-api:issue",
                        { supportedEcdsaKeyTypes: [curve], supports: both });
  };
  kit.writeConfig(dir, {
    name: "iya-sts", implementation: "iya-sts VC-API adapter",
    oauth2: kit.oauth2Of(ctx),
    issuers: [
      issuer("ecdsa-rdfc-2019-p256", "ecdsa-rdfc-2019", "P-256"),
      issuer("ecdsa-rdfc-2019-p384", "ecdsa-rdfc-2019", "P-384"),
      issuer("ecdsa-jcs-2019-p256", "ecdsa-jcs-2019", "P-256"),
      issuer("ecdsa-jcs-2019-p384", "ecdsa-jcs-2019", "P-384"),
      issuer("ecdsa-sd-2023-p256", "ecdsa-sd-2023", "P-256")],
    verifiers: [kit.endpoint(ctx, ctx.realmBase + "/vc-api",
      ctx.realmBase + "/vc-api/credentials/verify",
      ["ecdsa-rdfc-2019", "ecdsa-jcs-2019", "ecdsa-sd-2023"],
      "vc-api:verify", { supportedEcdsaKeyTypes: ["P-256", "P-384"],
                         supports: both })]
  }, { enableInteropTests: true });
  log.info("=== 1. the suite, but tests/60-sd-interop.js ===");
  const run = kit.runMocha(dir, ctx, { files: suiteFiles(dir) });
  kit.judge(SUITE, run.tests, EXCEPTIONS, PENDING);
  log.info("=== 2. ecdsa-sd-2023 interop, the holder named ===");
  await sdInterop(ctx, dir);
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The W3C Data Integrity ECDSA test suite (#196) against the " +
    "VC-API adapter of a throwaway realm.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
