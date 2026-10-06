// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_chain_impersonation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER IMPERSONATION CHAIN IN SAML ASSERTIONS OVER WS-TRUST: one
// sign-in, then three RequestSecurityTokens, each carrying `<wst:OnBehalfOf>`
// (#473).
//
// `sts_token_exchange_chain_impersonation.js` in the other protocol family.
// `wstrust_chain_kit.js` says what is shared, and why there are three hops
// where that job has two:
//
//   bob_end_user signs in to webapp1-wsimp. webapp1 sends his UsernameToken
//   in an Issue whose AppliesTo is its own registered identifier,
//   `https://webapp1-wsimp.example.com`. Back comes an assertion about bob,
//   restricted to that URI.
//
//   webapp1-wsimp, authenticated as its own service account, presents that
//   assertion in `<wst:OnBehalfOf>` for `https://apigw1-wsimp.example.com`.
//   apigw1-wsimp does the same for esb1's identifier, and esb1-wsimp for
//   sp1's. WS-Trust 1.3 section 9.2 asks for a token ABOUT somebody:
//   IMPERSONATION. The relying party is handed what reads as bob's own
//   assertion. So EVERY assertion here names bob and NO DELEGATE: no SAML
//   V2.0 Delegation Restriction at all, at any hop. The register is the only
//   place the three middle tiers exist, which is the OAuth impersonation
//   job's situation exactly. An impersonation also never launders a prior
//   delegation away (`wstrust.ts`, #186), but nothing earlier in this chain
//   delegated, so there is nothing to carry.
//
// The three requesters are configured to IMPERSONATE.
// `appDelegationSemantics` and `appDefaultDelegationSemantics` are
// `impersonation`, and `appAllowedToDelegateTo` names the next tier: the
// policy's rule 10 for an impersonation, "the actor must reach R". A realm's
// default semantics is delegation, under which OnBehalfOf is refused in
// product (`sts_delegation_policy.js` W3).
//
// WHAT IT ASSERTS, in the OAuth jobs' four layers:
//
//   1. THE REGISTRY: each entry read back with its registered identifier
//      on wstrustAppliesTo and samlEntityId, and each requester's policy.
//   2. THE WIRE: every RSTR a 200 with a SAML 2.0 assertion that parses on
//      its own, has a new ID, is signed, is about bob_end_user, is restricted
//      to exactly the requested registered identifier and to no tier it has
//      left, comes from one issuer, and carries no Delegation Restriction.
//      The sign-in's states PasswordProtectedTransport. Each exchanged one
//      states `unspecified`: bob presented nothing at that hop.
//   3. THE TARGET'S VALIDATION at sp1: the signature against the realm's
//      published certificate (`GET /sts/cert`), the Conditions' window, its
//      own identifier as the one audience, and nobody named as having acted.
//   4. THE REGISTER AND THE PICTURE: one `wstrust-onbehalfof` act per hop,
//      mode impersonation, found by the ID of the assertion it produced and
//      consuming the ID of the one presented. Each names the service
//      account and its application in the middle and the resolved
//      application as the target, with the issuance policy's ALLOWED
//      sentence; in product it is policed. Then the graph: apigw1-wsimp and
//      esb1-wsimp are each ONE box, reached by one hop and in the middle of
//      the next.
//
// In development and product mode alike (GET /admin-api/mode). The entries
// are left behind; a rerun reconciles them.
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
var log = bunyan.createLogger({ name: "sts_wstrust_chain_impersonation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const TAG = "wsimp";
const SEMANTICS = "impersonation";
const ELEMENT = "OnBehalfOf";
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
  const cast = kit.castFor(TAG);
  const product = await kit.isProduct(base);
  log.info("The WS-Trust impersonation chain at " + base + ": " + cast.user +
           " -> " + cast.tiers.map(function (t) {
             return t.identifier;
           }).join(" -> ") + " (" + (product ? "product" : "development") +
           " mode).");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS);
  check("1. the four entries register their identifiers on " +
        "wstrustAppliesTo and samlEntityId, and the three requesters " +
        "impersonate towards the next tier only", function () {});

  log.info("=== The sign-in ===");
  const signedIn = await kit.signIn(base, cast);
  let first;
  check("2a. the sign-in's assertion: about " + cast.user + ", restricted " +
        "to " + cast.webapp.appliesTo + ", PasswordProtectedTransport, no " +
        "delegate", function () {
    first = kit.assertChainAssertion(cast, signedIn.assertion, {
      what: cast.user + "'s sign-in assertion",
      audience: cast.webapp.appliesTo, delegates: [],
      authnContext: kit.AC_PASSWORD });
  });

  const requesters = cast.requesters;
  const assertions = [first];
  for (let i = 0; i < requesters.length; i++) {
    const tier = requesters[i];
    const next = kit.tierNamed(cast, tier.next);
    log.info("=== Hop " + (i + 1) + ": " + tier.identifier +
             " <OnBehalfOf> for " + next.appliesTo + " ===");
    const answer = await kit.exchange(base, cast, tier, ELEMENT,
                                      assertions[i].xml);
    check("2" + "bcd"[i] + ". " + tier.identifier + "'s assertion: about " +
          cast.user + ", restricted to " + next.appliesTo + " and no tier " +
          "it has left, a new ID, NO delegate (the middle is invisible)",
          function () {
      assertions.push(kit.assertChainAssertion(cast, answer.assertion, {
        what: tier.identifier + "'s OnBehalfOf assertion",
        audience: next.appliesTo, issuer: first.issuer,
        notAudience: cast.tiers.slice(0, i + 1).map(function (one) {
          return one.appliesTo;
        }),
        notIds: assertions.map(function (one) {
          return one.id;
        }),
        delegates: [], authnContext: kit.AC_UNSPECIFIED }));
    });
  }
  const final = assertions[assertions.length - 1];
  log.info("=== The final assertion ===");
  log.info(final.xml);

  const certPem = await kit.signingCertificate(base);
  check("3. sp1's own validation: the signature verifies against the " +
        "realm's published certificate, the Conditions hold now, " +
        cast.provider.appliesTo + " is the one audience, it is about " +
        cast.user + ", and nobody is named as having acted", function () {
    const atTarget = kit.validateAtTarget(final.xml, certPem,
                                          cast.provider.appliesTo, SKEW_MS);
    assert.strictEqual(atTarget.nameId, cast.user);
    assert.strictEqual(atTarget.restricted, false, "the final assertion " +
                       "carries a Delegation Restriction");
    assertions.slice(0, -1).forEach(function (one, i) {
      kit.validateAtTarget(one.xml, certPem,
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
                            "'s OnBehalfOf assertion");
  });
  hops.forEach(function (hop, i) {
    check("4" + "abc"[i] + ". the register: one wstrust-onbehalfof act " +
          "(impersonation) by " + hop.clientId + " for " + cast.user +
          " to " + hop.target + ", consuming " + hop.consumedId +
          " and producing " + hop.producedId + ", allowed by the issuance " +
          "policy" + (product ? ", policed" : ""), function () {
      kit.assertAct(cast, acts[i], {
        type: "wstrust-onbehalfof", mode: "impersonation",
        semantics: SEMANTICS, requester: hop.clientId, target: hop.target,
        appliesTo: hop.appliesTo, consumedId: hop.consumedId,
        producedId: hop.producedId, product: product });
    });
  });
  const findings = acts.reduce(function (all, act) {
    return all.concat(kit.noteStaleNotes(act, ELEMENT, product));
  }, []);
  check("4d. the picture: an impersonation line from " + cast.user +
        " to each requester, and " + cast.gateway.identifier + " and " +
        cast.esb.identifier + " each ONE box, reached by one hop and in " +
        "the middle of the next", function () {
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(0, 2),
                            "impersonation");
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(1, 3),
                            "impersonation");
  });

  assert.ok(checks >= 10, "only " + checks + " of 10 checks ran; a " +
            "section has stopped being called.");
  log.info(checks + " check(s) passed" + (findings.length
    ? "; " + findings.length + " finding(s) logged as WARN" : "") + ".");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_wstrust_chain_impersonation")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider: one WS-Trust sign-in and three <wst:OnBehalfOf> " +
    "exchanges, every assertion about the person and naming no delegate, " +
    "asserted on the wire, by the target's own validation and in the " +
    "delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
