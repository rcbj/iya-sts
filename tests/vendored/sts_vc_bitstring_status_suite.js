"use strict";
//
// File: sts_vc_bitstring_status_suite.js
//
// ---------------------------------------------------------------------------
// THE W3C BITSTRING STATUS LIST TEST SUITE AGAINST THIS SERVICE, AND THE
// STATUS CHANGES IT DOES NOT MAKE (#197, 2026-09-26).
//
// w3c/vc-bitstring-status-list-test-suite (W3C 3-clause BSD, pinned by
// tests/vc-suites/fetch-suites.sh) is the official suite for Bitstring
// Status List v1.0: an issuer that attaches a BitstringStatusListEntry, the
// status list credential it names (fetched and decoded), and a verifier
// that checks it. The implementation is oid4vc/vc_api.ts's adapter in a
// throwaway development realm — its eddsa-rdfc-2022 issuer asked for a
// status entry, so the index is one of the realm's own lists
// (oid4vc/vc_status.ts), whose JSON-LD form (Data Integrity secured, #197)
// is what the suite reads.
//
// THE SUITE NEVER CHANGES A STATUS: its helper for the VC-API status
// endpoint (updateStatus()) is defined and called by no test, and its
// verifier tests are all positive. Section 2 is therefore the rest of the
// specification over the same endpoints — the status endpoint mapped onto
// `vc_status.setStatus()`, the act /admin/vc-status performs and one of the
// three that DISOWN a credential (oid4vc/CLAUDE.md 3ar): a revocation sets
// the bit in the published list and the verifier then refuses the
// credential, a suspension likewise and is lifted again, and a revocation
// is final.
//
// WHAT FAILS THIS JOB: any failed test of the suite not in EXCEPTIONS (none;
// each would be recorded on #197), and any check of section 2.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const zlib = require("zlib");
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
var log = require("bunyan").createLogger({
  name: "sts_vc_bitstring_status_suite",
  level: appconfig.LOG_LEVEL || process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const SUITE = "vc-bitstring-status-list-test-suite";
const EXCEPTIONS = {};
// Every pending test of this suite is an `it.skip` upstream: the optional
// statusSize / statusMessage / statusReference members (for a `message`
// purpose this issuer does not publish) and one MAY.
const PENDING = { "*": "skipped by the suite itself (it.skip upstream)" };

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

// The bit at `index` of a list's `encodedList` (Bitstring Status List
// section 3.2: a multibase base64url GZIP, index 0 the leftmost bit).
function bitOf(encodedList, index) {
  log.debug("Entering bitOf().");
  assert.strictEqual(encodedList.charAt(0), "u", "encodedList is base64url");
  const bytes = zlib.gunzipSync(Buffer.from(encodedList.slice(1),
                                            "base64url"));
  log.debug("Leaving bitOf().");
  return (bytes[Math.floor(index / 8)] >> (7 - (index % 8))) & 1;
}

async function issue(ctx, purpose) {
  log.debug("Entering issue().");
  const issuer = ctx.issuers["eddsa-rdfc-2022"];
  const options = { credentialStatus: { type: "BitstringStatusListEntry" } };
  if (purpose) {
    options.credentialStatus.statusPurpose = purpose;
  }
  const r = await kit.call("POST", issuer.endpoint, { headers: bearer(ctx),
    json: { credential: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      id: "urn:uuid:" + crypto.randomUUID(),
      type: ["VerifiableCredential"], issuer: issuer.id,
      credentialSubject: { id: "did:example:subject" } },
      options: options } });
  assert.strictEqual(r.status, 201, "issue: " + r.text.slice(0, 600));
  log.debug("Leaving issue().");
  return r.json.verifiableCredential;
}

async function verify(ctx, vc) {
  log.debug("Entering verify().");
  const r = await kit.call("POST", ctx.realmBase +
                           "/vc-api/credentials/verify",
    { headers: bearer(ctx), json: { verifiableCredential: vc,
      options: { checks: ["proof", "credentialStatus"] } } });
  log.debug("Leaving verify(). " + r.status);
  return r;
}

async function change(ctx, vc, purpose, status) {
  log.debug("Entering change().");
  const body = { credentialId: vc.id, credentialStatus: {
    type: "BitstringStatusListEntry", statusPurpose: purpose } };
  if (status !== undefined) {
    body.status = status;
  }
  const r = await kit.call("POST", ctx.realmBase + "/vc-api/credentials/" +
                           "status", { headers: bearer(ctx), json: body });
  log.debug("Leaving change(). " + r.status);
  return r;
}

// The list an entry names, as the suite reads it: JSON-LD, then published.
async function listOf(ctx, entry) {
  log.debug("Entering listOf().");
  const published = await kit.call("POST", entry.statusListCredential +
                                   "/publish", { headers: bearer(ctx),
                                                 json: {} });
  assert.strictEqual(published.status, 204, "publish: " + published.status);
  const r = await kit.call("GET", entry.statusListCredential, { headers: {
    Accept: "application/ld+json, application/json" } });
  assert.strictEqual(r.status, 200, "the list: " + r.text.slice(0, 300));
  log.debug("Leaving listOf().");
  return r.json;
}

function entryFor(vc, purpose) {
  log.debug("Entering entryFor().");
  log.debug("Leaving entryFor().");
  return [].concat(vc.credentialStatus).filter(function (e) {
    return e.statusPurpose === purpose;
  })[0];
}

async function statusChanges(ctx) {
  log.debug("Entering statusChanges().");
  const vc = await issue(ctx, "");
  const revocation = entryFor(vc, "revocation");
  check("an issued credential names a revocation and a suspension entry",
        function () {
    assert.ok(revocation && entryFor(vc, "suspension"),
              JSON.stringify(vc.credentialStatus));
  });
  const before = await verify(ctx, vc);
  check("it verifies, status included", function () {
    assert.strictEqual(before.status, 200, before.text.slice(0, 600));
    assert.ok(before.json.checks.indexOf("credentialStatus") >= 0);
  });
  const list0 = await listOf(ctx, revocation);
  const verifiedList = await verify(ctx, list0);
  check("the status list credential (JSON-LD) is itself a credential this " +
        "verifier verifies", function () {
    assert.strictEqual(verifiedList.status, 200,
                       verifiedList.text.slice(0, 600));
    assert.strictEqual(list0.issuer, list0.proof.verificationMethod
      .split("#")[0], "the list is signed by its issuer's key");
  });
  check("its revocation bit is clear", function () {
    assert.strictEqual(bitOf(list0.credentialSubject.encodedList,
                             Number(revocation.statusListIndex)), 0);
  });
  const revoked = await change(ctx, vc, "revocation");
  check("the VC-API status endpoint revokes it", function () {
    assert.strictEqual(revoked.status, 200, revoked.text.slice(0, 300));
  });
  const list1 = await listOf(ctx, revocation);
  check("the published revocation list now has its bit set", function () {
    assert.strictEqual(bitOf(list1.credentialSubject.encodedList,
                             Number(revocation.statusListIndex)), 1);
  });
  const after = await verify(ctx, vc);
  check("the verifier refuses the revoked credential", function () {
    assert.strictEqual(after.status, 400, after.text.slice(0, 300));
    assert.strictEqual(after.json.verified, false);
  });
  const unrevoke = await change(ctx, vc, "revocation", false);
  check("a revocation is final", function () {
    assert.strictEqual(unrevoke.status, 400, unrevoke.text.slice(0, 300));
  });
  const second = await issue(ctx, "suspension");
  const suspension = entryFor(second, "suspension");
  const suspended = await change(ctx, second, "suspension");
  const whileSuspended = await verify(ctx, second);
  const suspendedList = await listOf(ctx, suspension);
  check("a suspension sets the suspension bit and the verifier refuses the " +
        "credential", function () {
    assert.strictEqual(suspended.status, 200, suspended.text.slice(0, 300));
    assert.strictEqual(bitOf(suspendedList.credentialSubject.encodedList,
                             Number(suspension.statusListIndex)), 1);
    assert.strictEqual(whileSuspended.status, 400);
  });
  const lifted = await change(ctx, second, "suspension", false);
  const afterLift = await verify(ctx, second);
  check("a suspension is lifted, and the credential verifies again",
        function () {
    assert.strictEqual(lifted.status, 200, lifted.text.slice(0, 300));
    assert.strictEqual(afterLift.status, 200, afterLift.text.slice(0, 300));
  });
  const unknown = await change(ctx, { id: "urn:uuid:" +
    crypto.randomUUID() }, "revocation");
  check("a credential this realm issued no status for is 404", function () {
    assert.strictEqual(unknown.status, 404);
  });
  log.debug("Leaving statusChanges().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a throwaway development realm and a VC-API token ===");
  const ctx = await kit.setUp("vcbsl");
  const dir = kit.suiteDir(SUITE);
  log.info("  " + SUITE + " at " + kit.commitOf(dir));
  const tags = ["BitstringStatusList", "Revocation", "Suspension"];
  const issuer = ctx.issuers["eddsa-rdfc-2022"];
  kit.writeConfig(dir, {
    name: "iya-sts", implementation: "iya-sts VC-API adapter",
    oauth2: kit.oauth2Of(ctx),
    issuers: [kit.endpoint(ctx, issuer.id, issuer.endpoint, tags,
      "vc-api:issue", { options: { credentialStatus: {
        type: "BitstringStatusListEntry" } } })],
    verifiers: [kit.endpoint(ctx, ctx.realmBase + "/vc-api",
      ctx.realmBase + "/vc-api/credentials/verify", tags, "vc-api:verify",
      { options: { checks: ["proof", "credentialStatus"] } })],
    vpVerifiers: [kit.endpoint(ctx, ctx.realmBase + "/vc-api",
      ctx.realmBase + "/vc-api/presentations/verify", tags, "vc-api:verify")]
  }, { enableInteropTests: true });
  log.info("=== 1. the suite ===");
  const run = kit.runMocha(dir, ctx);
  kit.judge(SUITE, run.tests, EXCEPTIONS, PENDING);
  log.info("=== 2. the status changes the suite does not make ===");
  await statusChanges(ctx);
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The W3C Bitstring Status List test suite (#197) against the " +
    "VC-API adapter of a throwaway realm, and its status changes.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
