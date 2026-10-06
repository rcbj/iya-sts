// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_saml11_chain_delegation.js
//
// ---------------------------------------------------------------------------
// THE FOUR-TIER DELEGATION CHAIN OVER WS-TRUST WITH SAML 1.1 TOKENS (#487):
// one sign-in, then three RequestSecurityTokens carrying `<wst14:ActAs>`,
// every RST asking for `wst:TokenType`
// `http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1`.
//
// `sts_wstrust_chain_delegation.js` with SAML 1.1 where that job has SAML
// 2.0, on the same kit and the same exchange (`wstrust_chain_kit.js`): a
// UsernameToken sign-in, each requester its own service account, each
// AppliesTo the next tier's registered identifier, each hop presenting the
// SAML 1.1 assertion the hop before produced.
//
// **WHAT IS NOT THERE, AND WHY (the exception, ws-trust/CLAUDE.md).** SAML
// 1.1 has no Delegation Restriction: the SAML V2.0 Condition for Delegation
// Restriction is a SAML 2.0 condition type and cannot appear in a SAML 1.1
// assertion, and SAML 1.1 defines no element of its own for "this party
// acted". WS-Trust 1.4 section 9.3 asks an ActAs token to carry the identity
// acted as and names no representation of the requester. So every assertion
// here is about bob_end_user and names NO delegate, and the chain the SAML
// 2.0 job reads off the final assertion is read here from the delegation
// register instead, whose act note says SAML 1.1 cannot carry it.
//
// WHAT IT ASSERTS, in the SAML job's four layers:
//
//   1. THE REGISTRY.
//   2. THE WIRE: every RSTR a 200 whose wst:TokenType is SAML 1.1, a SAML
//      1.1 assertion (MajorVersion 1, MinorVersion 1) that parses on its
//      own, a new AssertionID, signed, about bob, restricted to exactly the
//      requested registered identifier, its Issuer the entityID the
//      AppliesTo's own metadata names (product, #480) or the STS's
//      placeholder name (development), its AuthenticationStatement's method
//      `am:password` at the sign-in and `am:unspecified` after, no
//      delegation element, and the AppliesTo application's SAML 1.1
//      attributes: `teams`, `roles` and `saml11CustomAttributes`' `tier`.
//   3. THE TARGET'S VALIDATION at sp1: the signature against `GET
//      /sts/cert` (AssertionID the identifier), the Conditions, the audience.
//   4. THE REGISTER AND THE PICTURE: one `wstrust-actas` act per hop,
//      producing a `SAML 1.1 assertion` and consuming the AssertionID
//      presented, its note saying SAML 1.1 cannot name who acted; the
//      issuance policy's sentence; apigw1 and esb1 each ONE box.
//
// In development and product mode alike; entries `-w11del`, left behind.
//
// OWNED HERE (local: true): the chain is this repository's own scenario.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const kit = require("./wstrust_chain_kit.js");

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
var log = bunyan.createLogger({ name: "sts_wstrust_saml11_chain_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const TAG = "w11del";
const SEMANTICS = "delegation";
const ELEMENT = "ActAs";
// The clock skew the target allows itself when it reads the Conditions.
const SKEW_MS = 60000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function test() {
  log.debug("Entering test().");
  const base = kit.serviceBase();
  const cast = kit.castFor(TAG, "saml11");
  const product = await kit.isProduct(base);
  log.info("The WS-Trust SAML 1.1 " + SEMANTICS + " chain at " + base + ": " +
           cast.user + " -> " + cast.tiers.map(function (t) {
             return t.identifier;
           }).join(" -> ") + " (" + (product ? "product" : "development") +
           " mode).");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS);
  check("1. the four entries register their identifiers and their SAML 1.1 " +
        "settings, and the three requesters may act towards the next tier " +
        "only", function () {});
  const issuers = [];
  for (let i = 0; i < cast.tiers.length; i++) {
    issuers.push(await kit.samlIssuerFor(base, cast.tiers[i], product));
  }
  log.info("[issuer] " + JSON.stringify(issuers));

  log.info("=== The sign-in ===");
  const signedIn = await kit.signIn(base, cast);
  let first;
  check("2a. the sign-in's SAML 1.1 assertion: about " + cast.user +
        ", restricted to " + cast.webapp.appliesTo + ", am:password, the " +
        "application's SAML 1.1 attributes", function () {
    first = kit.assertChainAssertion11(cast, signedIn.assertion, {
      what: cast.user + "'s sign-in assertion", issuer: issuers[0],
      audience: cast.webapp.appliesTo, authnMethod: kit.AM_PASSWORD });
  });

  const requesters = cast.requesters;
  const assertions = [first];
  for (let i = 0; i < requesters.length; i++) {
    const tier = requesters[i];
    const next = kit.tierNamed(cast, tier.next);
    log.info("=== Hop " + (i + 1) + ": " + tier.identifier + " <" + ELEMENT +
             "> for " + next.appliesTo + " ===");
    const answer = await kit.exchange(base, cast, tier, ELEMENT,
                                      assertions[i].xml);
    check("2" + "bcd"[i] + ". " + tier.identifier + "'s SAML 1.1 " +
          "assertion: about " + cast.user + ", restricted to " +
          next.appliesTo + " and no tier it has left, a new AssertionID, " +
          "NO delegate (SAML 1.1 has no Delegation Restriction)", function () {
      assertions.push(kit.assertChainAssertion11(cast, answer.assertion, {
        what: tier.identifier + "'s " + ELEMENT + " assertion",
        audience: next.appliesTo, issuer: issuers[i + 1],
        notAudience: cast.tiers.slice(0, i + 1).map(function (one) {
          return one.appliesTo;
        }),
        notIds: assertions.map(function (one) {
          return one.id;
        }),
        authnMethod: kit.AM_UNSPECIFIED }));
    });
  }
  const final = assertions[assertions.length - 1];
  log.info("=== The final assertion ===");
  log.info(final.xml);

  const certPem = await kit.signingCertificate(base);
  check("3. sp1's own validation: the signature verifies against the " +
        "realm's published certificate, the Conditions hold now, " +
        cast.provider.appliesTo + " is the one audience, about " + cast.user,
        function () {
    const atTarget = kit.validateAtTarget11(final.xml, certPem,
                                            cast.provider.appliesTo, SKEW_MS);
    assert.strictEqual(atTarget.nameId, cast.user);
    assertions.slice(0, -1).forEach(function (one, i) {
      kit.validateAtTarget11(one.xml, certPem,
                             cast.tiers[i].appliesTo, SKEW_MS);
    });
  });

  log.info("=== The register and the picture ===");
  const since = await kit.registerSince(base, cast, baselineAt);
  const hops = requesters.map(function (tier, i) {
    return { clientId: tier.identifier, target: tier.next,
             appliesTo: kit.tierNamed(cast, tier.next).appliesTo,
             consumedId: assertions[i].id, producedId: assertions[i + 1].id };
  });
  const acts = hops.map(function (hop) {
    return kit.actProducing(since.acts, hop.producedId, hop.clientId +
                            "'s " + ELEMENT + " assertion");
  });
  const type = ELEMENT === "ActAs" ? "wstrust-actas" : "wstrust-onbehalfof";
  hops.forEach(function (hop, i) {
    check("4" + "abc"[i] + ". the register: one " + type + " act (" +
          SEMANTICS + ") by " + hop.clientId + " for " + cast.user + " to " +
          hop.target + ", consuming " + hop.consumedId + " and producing a " +
          "SAML 1.1 assertion " + hop.producedId + ", allowed by the " +
          "issuance policy" + (product ? ", policed" : ""), function () {
      kit.assertAct(cast, acts[i], {
        type: type, mode: SEMANTICS, semantics: SEMANTICS,
        requester: hop.clientId, target: hop.target,
        appliesTo: hop.appliesTo, consumedId: hop.consumedId,
        producedId: hop.producedId, producedKind: "SAML 1.1 assertion",
        product: product });
      kit.actNotes(acts[i], ELEMENT, product, false, true);
    });
  });
  check("4d. the picture: a " + SEMANTICS + " line from " + cast.user +
        " to each requester, and " + cast.gateway.identifier + " and " +
        cast.esb.identifier + " each ONE box (#468)", function () {
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(0, 2), SEMANTICS);
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(1, 3), SEMANTICS);
  });

  assert.ok(checks >= 10, "only " + checks + " of 10 checks ran; a " +
            "section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_wstrust_saml11_chain_delegation")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider: one WS-Trust sign-in and three <wst14:ActAs> " +
    "exchanges asking for SAML 1.1, every assertion about the person with " +
    "the application's SAML 1.1 attributes and no delegate, the chain in the " +
    "delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
