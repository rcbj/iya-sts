"use strict";
//
// File: sts_did_test_suite.js
//
// ---------------------------------------------------------------------------
// THE W3C DID CORE TEST SUITE OVER THIS SERVICE'S DIDS AND ITS RESOLVER
// (#199, 2026-09-26).
//
// w3c/did-test-suite (W3C licence, pinned by tests/vc-suites/fetch-suites.sh)
// is the DID Working Group's suite for DID Core 1.0. It does not call an
// implementation: it runs jest over IMPLEMENTATION FIXTURE files — a DID
// method's DIDs with each document in each representation, and a resolver's
// and a dereferencer's recorded executions with their expected outcomes —
// and holds every one to the specification's MUSTs. So this job GENERATES
// those fixtures from the running service, in a throwaway development realm:
//
//   * did:web  — this realm's own DID, its document from vc_did.ts;
//   * did:key  — the realm's Ed25519, P-256 and P-384 keys, as the VC-API
//                adapter names its issuers;
//   * did:jwk  — one minted by this service's /did/generate;
//
// each resolved through oid4vc/vc_did_resolver.ts (/vc-api/resolve,
// /vc-api/dereference) in both representations it produces
// (application/did+json and application/did+ld+json); plus the executions
// that must fail — an invalid DID, a method it does not support, a did:web
// it does not fetch, a representation it does not produce, a fragment the
// document does not hold, a DID URL that is not one — each recorded with the
// outcome the suite should expect. Then the suite's six jest suites run over
// them, with the fixtures handed in as jest's `systemSuiteConfig` global,
// exactly as its own report generator does (services/runSuite.js).
//
// WHAT FAILS THIS JOB: any failed jest test not in EXCEPTIONS (none since the
// first run; each would be recorded on #199), and any fixture the service
// could not produce.
// ---------------------------------------------------------------------------

const assert = require("assert");
const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
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
var log = require("bunyan").createLogger({ name: "sts_did_test_suite",
  level: appconfig.LOG_LEVEL || process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const SUITE = "did-test-suite";
const IMPLEMENTATION = "iya-sts oid4vc/vc_did_resolver.ts";
const IMPLEMENTER = "iya-sts";
const TYPES = ["application/did+json", "application/did+ld+json"];
// THE ONE EXCEPTION, a test of the suite's that no unsuccessful
// resolveRepresentation can pass (and why no upstream fixture records one):
// it asks EVERY resolveRepresentation execution for a contentType and a
// parseable document stream, where DID Core section 7.1.2 makes contentType
// REQUIRED "if resolution is successful" and section 7.1 says an
// unsuccessful one's stream "MUST be an empty stream". The execution is kept
// because it is the only one that shows representationNotSupported.
const EXCEPTIONS = [{
  match: new RegExp("PARAMETER expected outcome: " +
    "representationNotSupportedErrorOutcome didResolutionMetadata 7\\.1 " +
    "DID Resolution - If resolveRepresentation was called, this structure " +
    "MUST contain a contentType property"),
  reason: "the suite requires a contentType and a document stream of an " +
    "UNSUCCESSFUL resolveRepresentation, which DID Core 7.1.2 requires only " +
    "on success and 7.1 says is an empty stream; kept to show the " +
    "representationNotSupported error" }];
// The suite's own `it.todo`s — requirements it has no test for yet.
const PENDING = { "*": "an it.todo in the suite itself" };

function bearer(ctx) {
  log.debug("Entering bearer().");
  log.debug("Leaving bearer().");
  return { Authorization: "Bearer " + ctx.token };
}

async function resolveCall(ctx, fn, did, accept) {
  log.debug("Entering resolveCall(). " + fn + " " + did);
  const q = new URLSearchParams({ did: did, function: fn });
  if (accept !== undefined) {
    q.set("accept", accept);
  }
  const r = await kit.call("GET", ctx.realmBase + "/vc-api/resolve?" + q,
                           { headers: bearer(ctx) });
  assert.ok(r.json && r.json.didResolutionMetadata, "resolve " + did + ": " +
            r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving resolveCall(). " + r.status);
  return r.json;
}

async function dereferenceCall(ctx, didUrl) {
  log.debug("Entering dereferenceCall(). " + didUrl);
  const q = new URLSearchParams({ didUrl: didUrl });
  const r = await kit.call("GET", ctx.realmBase + "/vc-api/dereference?" + q,
                           { headers: bearer(ctx) });
  assert.ok(r.json && r.json.dereferencingMetadata, "dereference " + didUrl +
            ": " + r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving dereferenceCall(). " + r.status);
  return r.json;
}

// ---------------------------------------------------------------------------
// THE FIXTURES.
// ---------------------------------------------------------------------------
async function methodFixture(ctx, method, dids) {
  log.debug("Entering methodFixture(). " + method);
  const fixture = { didMethod: method, implementation: IMPLEMENTATION,
                    implementer: IMPLEMENTER, supportedContentTypes: TYPES,
                    dids: dids, didParameters: {} };
  for (const did of dids) {
    const resolved = await resolveCall(ctx, "resolve", did);
    assert.ok(resolved.didDocument, "resolve " + did + ": " +
              JSON.stringify(resolved.didResolutionMetadata));
    const properties = Object.assign({}, resolved.didDocument);
    const context = properties["@context"];
    delete properties["@context"];
    fixture[did] = { didDocumentDataModel: { properties: properties } };
    for (const type of TYPES) {
      const rep = await resolveCall(ctx, "resolveRepresentation", did, type);
      assert.strictEqual(rep.didResolutionMetadata.contentType, type,
                         JSON.stringify(rep.didResolutionMetadata));
      fixture[did][type] = {
        didDocumentDataModel: { representationSpecificEntries:
          type === "application/did+ld+json" ? { "@context": context } : {} },
        representation: rep.didDocumentStream,
        didDocumentMetadata: rep.didDocumentMetadata,
        didResolutionMetadata: rep.didResolutionMetadata };
    }
  }
  log.debug("Leaving methodFixture().");
  return fixture;
}

// A resolver or dereferencer fixture: executions, and which outcome each is.
function recorder(method) {
  log.debug("Entering recorder(). " + method);
  const fixture = { didMethod: method, implementation: IMPLEMENTATION,
                    implementer: IMPLEMENTER, expectedOutcomes: {},
                    executions: [] };
  const add = function add(execution, outcome) {
    log.debug("Entering add(). " + outcome);
    fixture.executions.push(execution);
    (fixture.expectedOutcomes[outcome] =
      fixture.expectedOutcomes[outcome] || []).push(
      fixture.executions.length - 1);
    log.debug("Leaving add().");
  };
  log.debug("Leaving recorder().");
  return { fixture: fixture, add: add };
}

const OUTCOMES = { invalidDid: "invalidDidErrorOutcome",
                   notFound: "notFoundErrorOutcome",
                   representationNotSupported:
                     "representationNotSupportedErrorOutcome",
                   invalidDidUrl: "invalidDidUrlErrorOutcome",
                   methodNotSupported: "methodNotSupportedErrorOutcome" };

async function resolverFixture(ctx, method, cases) {
  log.debug("Entering resolverFixture(). " + method);
  const rec = recorder(method);
  for (const c of cases) {
    const output = await resolveCall(ctx, c.fn, c.did, c.accept);
    const error = output.didResolutionMetadata.error;
    assert.strictEqual(error || "", c.error || "", c.fn + " " + c.did +
                       " answered " + JSON.stringify(output
                         .didResolutionMetadata));
    rec.add({ function: c.fn, input: { did: c.did, resolutionOptions:
      c.accept === undefined ? {} : { accept: c.accept } },
      output: output }, error ? OUTCOMES[error] : "defaultOutcome");
  }
  log.debug("Leaving resolverFixture().");
  return rec.fixture;
}

async function dereferencerFixture(ctx, method, cases) {
  log.debug("Entering dereferencerFixture(). " + method);
  const rec = recorder(method);
  for (const c of cases) {
    const output = await dereferenceCall(ctx, c.didUrl);
    const error = output.dereferencingMetadata.error;
    assert.strictEqual(error || "", c.error || "", "dereference " +
      c.didUrl + " answered " + JSON.stringify(output.dereferencingMetadata));
    rec.add({ function: "dereference", input: { didUrl: c.didUrl,
      dereferenceOptions: {} }, output: output },
      error ? OUTCOMES[error] : "defaultOutcome");
  }
  log.debug("Leaving dereferencerFixture().");
  return rec.fixture;
}

// ---------------------------------------------------------------------------
// ONE JEST SUITE over the fixtures. services/runSuite.js hands them in as
// jest's `globals`, and that does NOT work: jest builds a global in the
// outer realm, and the suite's `toBeInfraMap()` is `instanceof Object` in
// the test's own — every map in the fixtures fails it. So the fixtures are a
// file that a `--setupFiles` module requires INSIDE the test environment,
// which is the same `systemSuiteConfig` global the spec files read.
// ---------------------------------------------------------------------------
function runJest(dir, suite, config) {
  log.debug("Entering runJest(). " + suite);
  const server = path.join(dir, "packages", "did-core-test-server");
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "did-suite-"));
  const out = path.join(work, "report.json");
  fs.writeFileSync(path.join(work, "fixtures.json"), JSON.stringify(config));
  fs.writeFileSync(path.join(work, "setup.js"),
    "global.systemSuiteConfig = require(" +
    JSON.stringify(path.join(work, "fixtures.json")) + ");\n");
  const done = childProcess.spawnSync(process.execPath, [
    path.join(server, "node_modules", "jest", "bin", "jest.js"),
    "--roots", path.join(server, "suites", suite),
    "--setupFiles", path.join(work, "setup.js"),
    "--json", "--outputFile=" + out, "--ci"], {
    cwd: server, encoding: "utf8", maxBuffer: 256 * 1024 * 1024,
    timeout: 10 * 60 * 1000 });
  if (done.error) {
    throw new Error("jest could not be run: " + done.error.message);
  }
  let report;
  try {
    report = JSON.parse(fs.readFileSync(out, "utf8"));
  } catch (e) {
    log.debug("Caught in runJest(): " + ((e && e.message) || e));
    throw new Error("jest wrote no report for " + suite + " (exit " +
                    done.status + "): " + String(done.stderr).slice(-3000));
  }
  const tests = [];
  (report.testResults || []).forEach(function (file) {
    (file.assertionResults || []).forEach(function (a) {
      tests.push({ title: suite + " " + a.fullName,
                   state: a.status === "passed" ? "passed"
                     : (a.status === "failed" ? "failed" : "pending"),
                   message: (a.failureMessages || []).join(" ") });
    });
    if (file.status === "failed" && !(file.assertionResults || []).length) {
      tests.push({ title: suite + " (the file)", state: "failed",
                   message: String(file.message || "") });
    }
  });
  fs.rmSync(work, { recursive: true, force: true });
  log.debug("Leaving runJest(). " + tests.length + " test(s).");
  return tests;
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway development realm and a VC-API token ===");
  const ctx = await kit.setUp("did");
  const dir = kit.suiteDir(SUITE);
  log.info("  " + SUITE + " at " + kit.commitOf(dir));

  log.info("=== 1. this service's DIDs ===");
  const own = await kit.call("GET", ctx.realmBase + "/did.json");
  assert.strictEqual(own.status, 200, "the realm's did:web document: " +
                     own.text.slice(0, 300));
  const didWeb = own.json.id;
  const didKeys = ["eddsa-rdfc-2022", "ecdsa-rdfc-2019-p256",
                   "ecdsa-rdfc-2019-p384"].map(function (name) {
    return ctx.issuers[name].id;
  });
  const generated = await kit.call("GET", ctx.realmBase +
                                   "/did/generate?method=jwk");
  assert.strictEqual(generated.status, 200, "/did/generate: " +
                     generated.text.slice(0, 300));
  const didJwk = generated.json.did;
  log.info("  " + didWeb + ", " + didKeys.length + " did:key, " +
           didJwk.slice(0, 40) + "…");

  log.info("=== 2. the fixtures ===");
  const methods = [await methodFixture(ctx, "did:web", [didWeb]),
                   await methodFixture(ctx, "did:key", didKeys),
                   await methodFixture(ctx, "did:jwk", [didJwk])];
  const resolvers = [
    await resolverFixture(ctx, "did:web", [
      { fn: "resolve", did: didWeb },
      { fn: "resolveRepresentation", did: didWeb,
        accept: "application/did+ld+json" },
      { fn: "resolveRepresentation", did: didWeb,
        accept: "application/did+json" },
      { fn: "resolve", did: "did:web:did.example.invalid",
        error: "notFound" },
      { fn: "resolveRepresentation", did: didWeb, accept: "image/png",
        error: "representationNotSupported" }]),
    await resolverFixture(ctx, "did:key", [
      { fn: "resolve", did: didKeys[0] },
      { fn: "resolveRepresentation", did: didKeys[1] },
      { fn: "resolve", did: "did:key:z6Mkinvalid!", error: "invalidDid" },
      { fn: "resolve", did: "did:example:123",
        error: "methodNotSupported" }]),
    await resolverFixture(ctx, "did:jwk", [
      { fn: "resolve", did: didJwk },
      { fn: "resolveRepresentation", did: didJwk,
        accept: "application/did+json" }])];
  const keyVm = didKeys[1] + "#" + didKeys[1].slice("did:key:".length);
  const dereferencers = [
    await dereferencerFixture(ctx, "did:key", [
      { didUrl: didKeys[1] },
      { didUrl: keyVm },
      { didUrl: didKeys[1] + "#nothing", error: "notFound" },
      { didUrl: "bad:invalid", error: "invalidDidUrl" }]),
    await dereferencerFixture(ctx, "did:web", [
      { didUrl: didWeb },
      { didUrl: own.json.verificationMethod[0].id },
      { didUrl: didWeb + "?service=files", error: "notFound" }])];

  log.info("=== 3. the suite ===");
  let tests = [];
  ["did-identifier", "did-core-properties", "did-production",
   "did-consumption"].forEach(function (suite) {
    tests = tests.concat(runJest(dir, suite, { didMethods: methods }));
  });
  tests = tests.concat(runJest(dir, "did-resolution",
                               { resolvers: resolvers }));
  tests = tests.concat(runJest(dir, "did-url-dereferencing",
                               { dereferencers: dereferencers }));
  kit.judge(SUITE, tests, EXCEPTIONS, PENDING);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The W3C DID Core test suite (#199) over fixtures generated " +
    "from this service's DIDs and resolver.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
