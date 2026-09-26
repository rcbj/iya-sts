"use strict";
//
// File: sts_oid4vp_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: OPENID4VP 1.0 VERIFIER (#187,
// 2026-09-24), on the three containers `sts_fapi_conformance.js` (#176)
// brought into the stack. The suite plays the WALLET, holding an SD-JWT VC
// it issues itself with a key made HERE, at run time (no key material in
// git), whose certificate the realm's Verifier trusts
// (`oid4vp.trustedIssuerCertificates`).
//
// `oid4vp-1final-verifier-test-plan`, SD-JWT VC, the `redirect_uri`
// Client Identifier Prefix with an unsigned request (the prefix this
// Verifier uses for one, `oid4vc/vc_verifier.ts`), by direct_post and by
// direct_post.jwt. The Verifier's own signed-request prefixes are
// pre-registered, decentralized_identifier, verifier_attestation and
// openid_federation, and since #230 x509_san_dns and x509_hash — the two
// the plan's signed variants use, run here by direct_post and
// direct_post.jwt with the request object passed by reference
// (`request_uri_signed`). For those the job reads the realm's Verifier
// certificate (`/oid4vp/verifier-certificate`) and hands the suite its
// trust anchor, and for x509_san_dns the bare DNS name as client_id.
//
// A module waits for the Verifier to send the End-User to the wallet. This
// job is that End-User: it asks the realm's start page for a request — the
// realm's `oid4vp.walletUrl` is the suite's authorization endpoint — and
// follows the redirect to the suite.
//
// OWNED HERE (local: true): this repository's Verifier.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const oidf = require("./conformance_suite.js");

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
var log = bunyan.createLogger({ name: "sts_oid4vp_conformance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 10);
// The type the suite's wallet holds its credential under — its built-in
// EUDI PID — which the Verifier is told to ask for.
const VCT = "urn:eudi:pid:1";

const PLANS = [
  { key: "vp-direct-post", name: "oid4vp-1final-verifier-test-plan",
    responseMode: "direct_post",
    variant: { vp_profile: "plain_vp", credential_format: "sd_jwt_vc",
               client_id_prefix: "redirect_uri", request_method: "url_query",
               response_mode: "direct_post" } },
  { key: "vp-direct-post-jwt", name: "oid4vp-1final-verifier-test-plan",
    responseMode: "direct_post.jwt",
    variant: { vp_profile: "plain_vp", credential_format: "sd_jwt_vc",
               client_id_prefix: "redirect_uri", request_method: "url_query",
               response_mode: "direct_post.jwt" } },
  // #230: the X.509 Client Identifier Prefixes, a signed request by
  // reference.
  { key: "vp-san-dns", name: "oid4vp-1final-verifier-test-plan",
    responseMode: "direct_post", prefix: "x509_san_dns",
    variant: { vp_profile: "plain_vp", credential_format: "sd_jwt_vc",
               client_id_prefix: "x509_san_dns",
               request_method: "request_uri_signed",
               response_mode: "direct_post" } },
  { key: "vp-san-dns-jwt", name: "oid4vp-1final-verifier-test-plan",
    responseMode: "direct_post.jwt", prefix: "x509_san_dns",
    variant: { vp_profile: "plain_vp", credential_format: "sd_jwt_vc",
               client_id_prefix: "x509_san_dns",
               request_method: "request_uri_signed",
               response_mode: "direct_post.jwt" } },
  { key: "vp-hash", name: "oid4vp-1final-verifier-test-plan",
    responseMode: "direct_post", prefix: "x509_hash",
    variant: { vp_profile: "plain_vp", credential_format: "sd_jwt_vc",
               client_id_prefix: "x509_hash",
               request_method: "request_uri_signed",
               response_mode: "direct_post" } },
  { key: "vp-hash-jwt", name: "oid4vp-1final-verifier-test-plan",
    responseMode: "direct_post.jwt", prefix: "x509_hash",
    variant: { vp_profile: "plain_vp", credential_format: "sd_jwt_vc",
               client_id_prefix: "x509_hash",
               request_method: "request_uri_signed",
               response_mode: "direct_post.jwt" } }
];

const EXPECTED = {};
// Conditions whose WARNING this service keeps, and why — the same sentences
// as `oauth-oidc/CLAUDE.md` 3bl.
const KNOWN_WARNINGS = {
  WarnOnUnusableJwksKeys: "the realm's JWKS carries post-quantum keys " +
    "(kty AKP) the suite cannot parse; rcbj (2026-09-24): PQC support " +
    "matters more than a clean run (3bg)"
};
// FAILUREs that are the suite's and not this service's, each argued.
const KNOWN_FAILURES = {
  // vp_formats_supported lists the post-quantum JWS algorithms this
  // Verifier checks an SD-JWT and a Key Binding JWT with; the suite's table
  // of JWS algorithms has ML-DSA but not SLH-DSA or the composite ML-DSA
  // algorithms, and rcbj's decision on #176 was PQC support over a clean run.
  VP1FinalValidateVpFormatsSupportedInClientMetadata: "the suite's JWS " +
    "algorithm table lacks SLH-DSA and the composite ML-DSA algorithms"
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const alias = "iya-" + plan.key + "-" + TAG;
  const wallet = oidf.SUITE + "test/a/" + alias + "/authorize";
  const key = await oidf.selfSignedKey("conformance issuer " + TAG);
  const id = ("vp-" + plan.key + "-" + TAG).slice(0, 31).replace(/-+$/, "");
  const realm = await oidf.makeRealm(root, id, "Conformance " + plan.name, [
    ["oid4vp.walletUrl", wallet], ["oid4vp.walletPresentationPath", ""],
    ["oid4vp.trustedIssuerCertificates", key.pem],
    ["oid4vp.expectedVct", VCT],
    // The suite's credential names no status list, and a foreign issuer
    // without one is admitted by `own-only` (the realm's own credentials
    // still need theirs).
    ["oid4vp.requireStatusReference", "own-only"],
    ["federation.outboundCaFile", oidf.suiteCaFile()]]);
  let client = { client_id: "redirect_uri:" + realm.base + "/oid4vp/response" };
  if (plan.prefix) {
    // #230: the Verifier's own certificate, and the anchor the suite checks
    // the request object's x5c against; x509_san_dns names the Verifier by
    // its bare DNS name (the suite adds the prefix), x509_hash by nothing
    // the suite needs told.
    const cert = await oidf.send(realm.base + "/oid4vp/verifier-certificate");
    assert.strictEqual(cert.status, 200, "the Verifier certificate: " +
                       cert.raw.slice(0, 300));
    client = { request_object_trust_anchor_pem:
                 cert.body.x509_san_dns.trust_anchor_pem };
    if (plan.prefix === "x509_san_dns") {
      client.client_id = cert.body.x509_san_dns.dns_name;
    }
  }
  const configuration = {
    alias: alias,
    description: "iya-sts " + plan.name + " " + STAMP,
    client: client,
    credential: { signing_jwk: key.jwk },
    browser: [{
      match: "https://*/test/a/*/verification-evidence",
      tasks: [{
        task: "Capture verification evidence",
        match: "https://*/test/a/*/verification-evidence",
        commands: [["wait", "xpath", "//*", 10,
                    ".*Deferred verification evidence.*",
                    "update-image-placeholder"]]
      }]
    }]
  };
  log.debug("Leaving prepare().");
  return { realm: realm, configuration: configuration };
}

// THE END-USER (see the header): the realm's start page, followed to the
// wallet, once per module that is waiting for a request.
function userFor(plan, prepared) {
  log.debug("Entering userFor(). " + plan.key);
  const started = {};
  log.debug("Leaving userFor().");
  return async function (id, info) {
    log.debug("Entering the End-User. " + id);
    if (started[id] || (info && info.status !== "WAITING")) {
      log.debug("Leaving the End-User. Already started.");
      return;
    }
    started[id] = true;
    const r = await oidf.send(prepared.realm.base + "/oid4vp/start?" +
      new URLSearchParams(Object.assign(
        { mode: "same-device", format: "dc+sd-jwt",
          response_mode: plan.responseMode },
        plan.prefix ? { client_id_prefix: plan.prefix } : {})).toString());
    const to = r.headers.get("location") || "";
    assert.ok(to.indexOf(oidf.SUITE) === 0, "the start page sent nobody to " +
              "the suite: " + r.status + " " + r.raw.slice(0, 300));
    const got = await oidf.suite("GET", to.slice(oidf.SUITE.length));
    log.info("  sent the End-User to the wallet: " + got.status);
    log.debug("Leaving the End-User.");
  };
}

async function test() {
  log.debug("Entering test().");
  await registry.isProduct(root);
  await oidf.waitForSuite();
  const unexpected = [];
  for (const plan of PLANS) {
    if (!oidf.selected(plan.key)) {
      continue;
    }
    log.info("=== " + plan.name + " " + JSON.stringify(plan.variant) +
             " (" + plan.key + ") ===");
    let ran = null;
    try {
      const prepared = await prepare(plan);
      ran = await oidf.runPlan(plan.name, plan.variant,
                               prepared.configuration, plan.key,
                               userFor(plan, prepared));
    } catch (e) {
      log.error("Caught in test(): " + plan.key + ": " +
                ((e && e.message) || e));
      unexpected.push(plan.key + " could not run: " +
                      ((e && e.message) || e));
      continue;
    }
    const judged = oidf.judge(plan.key, ran, EXPECTED, KNOWN_WARNINGS,
                              KNOWN_FAILURES);
    log.info("  " + plan.key + ": " + JSON.stringify(judged.counts) +
             ", plan " + oidf.SUITE + "plan-detail.html?plan=" + ran.planId);
    judged.unexplained.forEach(function (line) {
      unexpected.push(line);
    });
  }
  if (unexpected.length) {
    log.error("Unexplained:\n  " + unexpected.join("\n  "));
  }
  check("every module passed or is argued, and every warning is known",
        function () {
          assert.strictEqual(unexpected.length, 0, unexpected.join("\n"));
        });
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The OpenID Foundation conformance suite's OpenID4VP " +
    "verifier plan (#187), against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
