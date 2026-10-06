// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_chain_delegation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER DELEGATION CHAIN IN SAML ASSERTIONS OVER WS-TRUST: one sign-in,
// then three RequestSecurityTokens, each carrying `<wst14:ActAs>` (#473).
//
// `sts_token_exchange_chain_delegation.js` in the other protocol family.
// `wstrust_chain_kit.js` says what is shared, and why there are three hops
// where that job has two:
//
//   bob_end_user signs in to webapp1-wsdel. webapp1 sends his UsernameToken
//   in an Issue whose AppliesTo is its own registered identifier,
//   `https://webapp1-wsdel.example.com`. Back comes an assertion about bob,
//   restricted to that URI, and naming no delegate: nobody acted for him.
//
//   webapp1-wsdel, authenticated as its own service account, presents that
//   assertion in `<wst14:ActAs>` for `https://apigw1-wsdel.example.com`.
//   apigw1-wsdel does the same for esb1's identifier, and esb1-wsdel for
//   sp1's. WS-Trust 1.4 section 9.3 makes ActAs COMPOSITE: the token is
//   about bob AND says the requester acts. This service writes that in the
//   SAML V2.0 Condition for Delegation Restriction
//   (sstc-saml-delegation-cs-01), one `<del:Delegate>` per party that acted.
//
//   AND THE CHAIN BEGINS WITH THE ORIGINAL CLIENT. The OAuth job nests
//   webapp1 beneath the gateway because the sign-in's token was issued TO it
//   (#443). Here webapp1 is in the chain because it made the first ActAs
//   itself, so it needs no special case (decision 3 of the kit). Each hop
//   copies the earlier delegates as they came and appends its requester, so
//   sp1's assertion reads
//
//       <del:Delegate>webapp1-wsdel</del:Delegate>
//       <del:Delegate>apigw1-wsdel</del:Delegate>
//       <del:Delegate>esb1-wsdel</del:Delegate>
//
//   "ordered from least to most recent; thus the earliest element is the
//   farthest removed from the immediate use of the assertion". The most
//   recent is esb1, which presents it to sp1. That is the nested `act` of
//   the OAuth job, written outermost-last. Each delegate is the
//   application's IDENTIFIER in the entity format. The requester
//   authenticated as the service account of that name, and the delegation
//   policy names the application (`delegationDecision.intermediary`).
//
// The three requesters are configured to DELEGATE.
// `appDelegationSemantics` and `appDefaultDelegationSemantics` are
// `delegation`, and `appAllowedToDelegateTo` names the next tier. That is
// the policy's rule 10: S, the application the presented assertion is
// restricted to, delegates to R, and the actor is S. Here S, the actor and
// the requester are one tier at every hop. Nothing is set on the person.
//
// THE ISSUER (#480, #494): every assertion's Issuer is, in EITHER mode, the
// entityID its AppliesTo's own `/saml2/metadata/{sp}` names (per SP, as SAML
// SSO names itself) — the same name its `/wsfed/metadata/{rp}` names.
//
// WHAT IT ASSERTS, in the OAuth jobs' four layers:
//
//   1. THE REGISTRY: each entry read back with its registered identifier
//      on wstrustAppliesTo and samlEntityId, and each requester's policy.
//   2. THE WIRE: every RSTR a 200 with a SAML 2.0 assertion that parses on
//      its own, has a new ID, is signed, is about bob_end_user, is restricted
//      to exactly the requested registered identifier and to no tier it has
//      left, and comes from one issuer. The sign-in's names no delegate and
//      states PasswordProtectedTransport. Each exchanged one names the whole
//      chain so far, compared in full. Each earlier delegate's
//      DelegationInstant is carried over unchanged, and the newest is not
//      before the one ahead of it. Its AuthnContext is `unspecified`: bob
//      presented nothing at that hop (ws-trust/CLAUDE.md).
//   3. THE TARGET'S VALIDATION at sp1: there is no introspection for an
//      assertion, so sp1 verifies the signature against the realm's
//      published certificate (`GET /sts/cert`), the Conditions' window
//      against its own clock, and its own identifier as the one audience.
//      Then it reads who acted.
//   4. THE REGISTER AND THE PICTURE: one `wstrust-actas` act per hop, mode
//      delegation, found by the ID of the assertion it produced and
//      consuming the ID of the one presented. Each names the service
//      account and its application in the middle and the application the
//      AppliesTo resolved to as the target, with the issuance policy's
//      ALLOWED sentence; in product it is policed. Then the graph:
//      apigw1-wsdel and esb1-wsdel are each ONE box, reached by one hop and
//      acting in the next (#468).
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
var log = bunyan.createLogger({ name: "sts_wstrust_chain_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const TAG = "wsdel";
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

// The earlier delegates are carried over AS THEY CAME, instants included,
// and the newest one is not before the one ahead of it.
function assertInstantsCarried(before, after, what) {
  log.debug("Entering assertInstantsCarried(). " + what);
  before.delegates.forEach(function (d, i) {
    assert.strictEqual(after.delegates[i].instant, d.instant, what + ": " +
      "the delegate " + d.nameId + "'s DelegationInstant changed from " +
      d.instant + " to " + after.delegates[i].instant + "; an earlier act " +
      "of delegation happened when it happened.");
  });
  const n = after.delegates.length;
  if (n >= 2) {
    assert.ok(Date.parse(after.delegates[n - 1].instant) >=
              Date.parse(after.delegates[n - 2].instant), what + ": the " +
              "newest delegate's instant is before the one ahead of it");
  }
  log.debug("Leaving assertInstantsCarried().");
}

async function test() {
  log.debug("Entering test().");
  const base = kit.serviceBase();
  const cast = kit.castFor(TAG);
  const product = await kit.isProduct(base);
  log.info("The WS-Trust delegation chain at " + base + ": " + cast.user +
           " -> " + cast.tiers.map(function (t) {
             return t.identifier;
           }).join(" -> ") + " (" + (product ? "product" : "development") +
           " mode).");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS);
  check("1. the four entries register their identifiers on " +
        "wstrustAppliesTo and samlEntityId, and the three requesters " +
        "delegate to the next tier only", function () {});

  // THE ISSUER EACH ASSERTION MUST CARRY (#480, #494): in either mode the
  // entityID each AppliesTo's own SAML metadata names.
  const issuers = [];
  for (let i = 0; i < cast.tiers.length; i++) {
    issuers.push(await kit.samlIssuerFor(base, cast.tiers[i], product));
  }
  log.info("[issuer] " + JSON.stringify(issuers));

  log.info("=== The sign-in ===");
  const signedIn = await kit.signIn(base, cast);
  let first;
  check("2a. the sign-in's assertion: about " + cast.user + ", restricted " +
        "to " + cast.webapp.appliesTo + ", PasswordProtectedTransport, no " +
        "delegate", function () {
    first = kit.assertChainAssertion(cast, signedIn.assertion, {
      issuer: issuers[0],
      what: cast.user + "'s sign-in assertion",
      audience: cast.webapp.appliesTo, delegates: [],
      authnContext: kit.AC_PASSWORD });
  });

  // The three hops: each requester presents what the hop before produced.
  const requesters = cast.requesters;
  const assertions = [first];
  for (let i = 0; i < requesters.length; i++) {
    const tier = requesters[i];
    const next = kit.tierNamed(cast, tier.next);
    log.info("=== Hop " + (i + 1) + ": " + tier.identifier + " <ActAs> for " +
             next.appliesTo + " ===");
    const answer = await kit.exchange(base, cast, tier, ELEMENT,
                                      assertions[i].xml);
    const chainSoFar = requesters.slice(0, i + 1).map(function (one) {
      return one.identifier;
    });
    check("2" + "bcd"[i] + ". " + tier.identifier + "'s assertion: about " +
          cast.user + ", restricted to " + next.appliesTo + " and no tier " +
          "it has left, a new ID, the delegates " +
          JSON.stringify(chainSoFar) + " least to most recent" +
          (i === 0 ? ", the original client " + tier.identifier + " first"
                   : ", the earlier ones carried over unchanged"),
          function () {
      const got = kit.assertChainAssertion(cast, answer.assertion, {
        what: tier.identifier + "'s ActAs assertion",
        audience: next.appliesTo, issuer: issuers[i + 1],
        notAudience: cast.tiers.slice(0, i + 1).map(function (one) {
          return one.appliesTo;
        }),
        notIds: assertions.map(function (one) {
          return one.id;
        }),
        delegates: chainSoFar, authnContext: kit.AC_UNSPECIFIED });
      assertInstantsCarried(assertions[i], got, tier.identifier + "'s " +
                            "ActAs assertion");
      assertions.push(got);
    });
  }
  const final = assertions[assertions.length - 1];
  log.info("=== The final assertion ===");
  log.info(final.xml);

  const certPem = await kit.signingCertificate(base);
  check("3. sp1's own validation: the signature verifies against the " +
        "realm's published certificate, the Conditions hold now, " +
        cast.provider.appliesTo + " is the one audience, and the " +
        "assertion says " + requesters.map(function (one) {
          return one.identifier;
        }).join(", then ") + " acted for " + cast.user, function () {
    const atTarget = kit.validateAtTarget(final.xml, certPem,
                                          cast.provider.appliesTo, SKEW_MS);
    assert.strictEqual(atTarget.nameId, cast.user);
    assert.deepStrictEqual(atTarget.delegates.map(function (d) {
      return d.nameId;
    }), requesters.map(function (one) {
      return one.identifier;
    }));
    // Every assertion in the chain verifies the same way, the sign-in's
    // included: they are what each tier was handed.
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
                            "'s ActAs assertion");
  });
  hops.forEach(function (hop, i) {
    check("4" + "abc"[i] + ". the register: one wstrust-actas act " +
          "(delegation) by " + hop.clientId + " for " + cast.user + " to " +
          hop.target + ", consuming " + hop.consumedId + " and producing " +
          hop.producedId + ", allowed by the issuance policy" +
          (product ? ", policed" : ""), function () {
      kit.assertAct(cast, acts[i], {
        type: "wstrust-actas", mode: "delegation", semantics: SEMANTICS,
        requester: hop.clientId, target: hop.target,
        appliesTo: hop.appliesTo, consumedId: hop.consumedId,
        producedId: hop.producedId, product: product });
    });
  });
  const findings = acts.reduce(function (all, act) {
    return all.concat(kit.actNotes(act, ELEMENT, product,
                                       false));
  }, []);
  check("4d. the picture: a delegation line from " + cast.user + " to " +
        "each requester, and " + cast.gateway.identifier + " and " +
        cast.esb.identifier + " each ONE box, reached by one hop and " +
        "acting in the next (#468)", function () {
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(0, 2),
                            "delegation");
    kit.assertGraphIsAChain(cast, since.graph, hops.slice(1, 3),
                            "delegation");
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
  .name("sts_wstrust_chain_delegation")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider: one WS-Trust sign-in and three <wst14:ActAs> " +
    "exchanges, the SAML Delegation Restriction growing to name every " +
    "requester, asserted on the wire, by the target's own validation and " +
    "in the delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
