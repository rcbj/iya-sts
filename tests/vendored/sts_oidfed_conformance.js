"use strict";
//
// File: sts_oidfed_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: OPENID FEDERATION 1.1 (#187,
// 2026-09-24), on the three containers `sts_fapi_conformance.js` (#176)
// brought into the stack.
//
//   * `openid-federation-deployed-entity-test-plan`, twice, as the suite's
//     own CI runs it: once for a Leaf (a throwaway realm, which is a
//     subordinate of the default realm by `oidfed.realmsAreSubordinates`)
//     and once for the Trust Anchor itself (the default realm). The suite is
//     given the Trust Anchor's Federation Entity Keys, read here from its
//     own Entity Configuration, which is what an operator pins.
//   * `openid-federation-entity-joined-to-test-federation-op-test-plan`: the
//     suite plays a whole federation — a Trust Anchor and a Relying Party
//     beneath it, at addresses under its own test alias — and this realm is
//     the OpenID Provider that has joined it. So the realm trusts the suite's
//     Trust Anchor (`/admin-api/oidfed/add-trust-anchor`, with the keys made
//     HERE, at run time, and handed to the suite as its private JWK Set — no
//     key material in git) and registers the suite's Relying Party
//     automatically (OpenID Federation 1.1 section 12.1) when it arrives
//     with a request object whose chain ends at that anchor.
//
// The ledger is `conformance_suite.js`'s: a FAILED module, or a WARNING
// from a condition KNOWN_WARNINGS does not name, fails the job.
//
// OWNED HERE (local: true): this repository's OpenID Federation entity.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_oidfed_conformance",
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
const PASSWORD = "Conf-Passw0rd!-" + String(Date.now()).slice(-6);

const PLANS = [
  { key: "deployed-leaf", name: "openid-federation-deployed-entity-test-plan",
    variant: { server_metadata: "discovery",
               client_registration: "automatic" }, leaf: true },
  { key: "deployed-anchor",
    name: "openid-federation-deployed-entity-test-plan",
    variant: { server_metadata: "discovery",
               client_registration: "automatic" }, leaf: false },
  { key: "joined-op",
    name: "openid-federation-entity-joined-to-test-federation-op-test-plan",
    variant: { server_metadata: "discovery",
               client_registration: "automatic" }, joined: true }
];

const EXPECTED = {};
// Conditions whose WARNING this service keeps, and why — the same sentences
// as `oauth-oidc/CLAUDE.md` 3bp.
const KNOWN_WARNINGS = {
  WarnOnUnusableJwksKeys: "the realm's JWKS carries post-quantum keys " +
    "(kty AKP) the suite cannot parse; rcbj (2026-09-24): PQC support " +
    "matters more than a clean run (3bg)"
};
// FAILUREs that are the suite's and not this service's, each argued.
const KNOWN_FAILURES = {
  // The Entity Configuration's openid_provider metadata publishes the
  // post-quantum JWS algorithms this OP verifies a request object with.
  // The suite checks the list against its own table of JWS algorithms,
  // which has ML-DSA but not SLH-DSA or the composite ML-DSA algorithms of
  // draft-ietf-jose-pq-composite-sigs; they are JWS algorithms all the
  // same, and rcbj's decision on #176 was PQC support over a clean run.
  ValidateRequestAuthenticationSigningAlgValuesSupported: "the suite's " +
    "JWS algorithm table lacks SLH-DSA and the composite ML-DSA algorithms",
  // The suite decides whether the entity under test IS the Trust Anchor by
  // a string prefix — `entity.startsWith(anchor)` — and a Leaf realm's
  // identifier, https://…:8081/realm/<id>, begins with its Trust Anchor's,
  // https://…:8081. So it demands that the Leaf's Entity Configuration carry
  // no authority_hints, which OpenID Federation 1.1 section 3 REQUIRES of a
  // Leaf. Only in the Leaf's entity-configuration module.
  ["deployed-leaf/openid-federation-entity-configuration/" +
    "ValidateAbsenceOfAuthorityHints"]: "the suite's prefix test takes a " +
    "Leaf under its Trust Anchor's URL for the Trust Anchor"
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// An entity's own Entity Configuration's JWK Set, read without verifying:
// the Trust Anchor's keys are what an operator pins, and the suite checks
// the signature itself (OpenIDFederationPreconfiguredKeysMatchTrustAnchors
// KeysTest).
async function federationKeysOf(entityId) {
  log.debug("Entering federationKeysOf(). " + entityId);
  const r = await oidf.send(entityId.replace(/\/$/, "") +
                            "/.well-known/openid-federation");
  assert.strictEqual(r.status, 200, entityId + ": " + r.raw.slice(0, 200));
  const claims = JSON.parse(Buffer.from(r.raw.split(".")[1], "base64url")
                              .toString("utf8"));
  log.debug("Leaving federationKeysOf().");
  return claims.jwks;
}

// An EC P-256 JWK Set with the private halves, `kid`s set, for the suite's
// own federation (its Trust Anchor, its Relying Party's federation and
// client keys).
function ecJwks(kid) {
  log.debug("Entering ecJwks().");
  const pair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const priv = pair.privateKey.export({ format: "jwk" });
  priv.kid = kid;
  priv.use = "sig";
  priv.alg = "ES256";
  const pub = Object.assign({}, priv);
  delete pub.d;
  log.debug("Leaving ecJwks().");
  return { privateJwks: { keys: [priv] }, publicJwks: { keys: [pub] } };
}

async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const alias = "iya-" + plan.key + "-" + TAG;
  const configuration = {
    alias: alias,
    description: "iya-sts " + plan.name + " " + STAMP,
    server: { allow_unexpected_metadata_fields: oidf.EXTENSION_METADATA },
    federation: {}
  };
  if (!plan.joined) {
    let entity = root;
    if (plan.leaf) {
      const id = ("fed-" + plan.key + "-" + TAG).slice(0, 31)
        .replace(/-+$/, "");
      entity = (await oidf.makeRealm(root, id, "Conformance " + plan.name,
                                     [])).base;
    }
    configuration.federation = {
      entity_identifier: entity,
      de_trust_anchor: root,
      de_trust_anchor_jwks: await federationKeysOf(root)
    };
    log.debug("Leaving prepare(). Deployed.");
    return configuration;
  }
  // The joined plan: this realm, the OP, trusting the suite's anchor.
  const id = ("fed-" + plan.key + "-" + TAG).slice(0, 31).replace(/-+$/, "");
  const realm = await oidf.makeRealm(root, id, "Conformance " + plan.name,
    [["federation.outboundCaFile", oidf.suiteCaFile()]]);
  const person = names.usernameFor("conf-" + plan.key);
  await oidf.makePerson(realm.api, person, PASSWORD);
  const anchor = oidf.SUITE + "test/a/" + alias + "/trust-anchor";
  const anchorKeys = ecJwks("conf-anchor-" + TAG);
  await oidf.ok(realm.api + "/oidfed/add-trust-anchor", {
    entityId: anchor, jwks: JSON.stringify(anchorKeys.publicJwks) },
    "trusted the suite's Trust Anchor");
  configuration.federation = {
    entity_identifier: realm.base,
    rp_ec_jwks: ecJwks("conf-rp-fed-" + TAG).privateJwks,
    rp_client_jwks: ecJwks("conf-rp-client-" + TAG).privateJwks
  };
  configuration.federation_trust_anchor = {
    trust_anchor_jwks: anchorKeys.privateJwks };
  configuration.browser = [{
    match: realm.base + "/oauth2/authorize*",
    tasks: [
      { task: "Sign in", optional: true, match: realm.base + "/authn/login*",
        commands: [["text", "id", "username", person, "optional"],
                   ["text", "id", "password", PASSWORD, "optional"],
                   ["click", "id", "kc-login"]] },
      { task: "Consent", optional: true,
        match: realm.base + "/oauth2/consent*",
        commands: [["click", "id", "consent-allow"]] },
      { task: "Error page", optional: true,
        match: realm.base + "/oauth2/authorize*",
        commands: [["wait", "xpath", "//body", 10, ".*",
                    "update-image-placeholder-optional"]] },
      { task: "Verify complete", optional: true,
        match: oidf.SUITE + "test/*/callback*",
        commands: [["wait", "id", "submission_complete", 10]] }
    ]
  }];
  log.debug("Leaving prepare(). Joined.");
  return configuration;
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
      ran = await oidf.runPlan(plan.name, plan.variant, await prepare(plan),
                               plan.key);
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
  .description("The OpenID Foundation conformance suite's OpenID " +
    "Federation plans (#187), against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
