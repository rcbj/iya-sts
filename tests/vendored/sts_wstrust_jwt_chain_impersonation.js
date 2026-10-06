// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_wstrust_jwt_chain_impersonation.js
//
// ---------------------------------------------------------------------------
// THE FOUR-TIER IMPERSONATION CHAIN OVER WS-TRUST WITH JWT RESPONSE TOKENS
// (#473): one sign-in, then three RequestSecurityTokens, each carrying
// `<wst:OnBehalfOf>`, every RST asking for `wst:TokenType`
// `urn:ietf:params:oauth:token-type:jwt`.
//
// `sts_wstrust_chain_impersonation.js` with JWTs where that job has SAML
// assertions. The exchange is WS-Trust's, exactly as there; rcbj has RFC
// 9068 and RFC 8693 govern ONLY the JWT's structure and contents.
// `sts_wstrust_jwt_chain_delegation.js` lists the claims and the
// exceptions. What differs here is RFC 8693 section 1.1's IMPERSONATION:
// OnBehalfOf (WS-Trust 1.3 section 9.2) asks for a token ABOUT bob, so
// every JWT carries NO `act`. Each one's `client_id` still names the
// requester that asked for it (RFC 9068 section 2.2): the token says which
// client holds it, not that the client acted for anybody, and so the OAuth
// impersonation job's tokens say the same.
//
// NEEDS #476 AND #477, as the delegation job does.
//
// WHAT IT ASSERTS, in the SAML job's four layers:
//
//   1. THE REGISTRY.
//   2. THE WIRE: every JWT `typ: at+jwt`, verified with the published key,
//      `iss`, `exp` the wst:Lifetime, `aud` exactly the registered
//      identifier, bob's `sub` at every hop, `client_id` the requester (none
//      on the sign-in's), a fresh `jti`, no `scope`, no `act`, no
//      `may_act`.
//   3. THE TARGET'S VALIDATION at sp1, and nobody named as having acted.
//   4. THE REGISTER AND THE PICTURE: one `wstrust-onbehalfof` act per hop,
//      found by `jti`, policed in product; apigw1 and esb1 each ONE box.
//
// In development and product mode alike; entries `-wjimp`, left behind.
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
var log = bunyan.createLogger({ name: "sts_wstrust_jwt_chain_impersonation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const TAG = "wjimp";
const SEMANTICS = "impersonation";
const ELEMENT = "OnBehalfOf";
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
  const cast = kit.castFor(TAG, "jwt");
  const product = await kit.isProduct(base);
  log.info("The WS-Trust JWT impersonation chain at " + base + ": " +
           cast.user + " -> " + cast.tiers.map(function (t) {
             return t.identifier;
           }).join(" -> ") + " (" + (product ? "product" : "development") +
           " mode).");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS);
  check("1. the four entries register their identifiers on " +
        "wstrustAppliesTo and samlEntityId, and the three requesters " +
        "impersonate towards the next tier only", function () {});
  const keys = await kit.jwks(base);
  const issuer = await kit.publishedIssuer(base);

  log.info("=== The sign-in ===");
  const signedIn = await kit.signIn(base, cast);
  let first;
  check("2a. the sign-in's JWT: typ at+jwt, verified with the published " +
        "key, iss " + issuer + ", aud " + cast.webapp.appliesTo + ", exp " +
        "the wst:Lifetime, no client_id (bob asked for himself), no act",
        function () {
    first = kit.assertChainJwt(cast, signedIn, keys, {
      what: cast.user + "'s sign-in JWT", audience: cast.webapp.appliesTo,
      issuer: issuer, clientId: "", act: undefined });
  });

  const requesters = cast.requesters;
  const tokens = [first];
  const answers = [signedIn];
  for (let i = 0; i < requesters.length; i++) {
    const tier = requesters[i];
    const next = kit.tierNamed(cast, tier.next);
    log.info("=== Hop " + (i + 1) + ": " + tier.identifier +
             " <OnBehalfOf> for " + next.appliesTo + " ===");
    const answer = await kit.exchange(base, cast, tier, ELEMENT,
                                      answers[i].inner);
    answers.push(answer);
    check("2" + "bcd"[i] + ". " + tier.identifier + "'s JWT: about " +
          cast.user + ", aud " + next.appliesTo + ", client_id " +
          tier.identifier + ", NO act (the middle is invisible)",
          function () {
      tokens.push(kit.assertChainJwt(cast, answer, keys, {
        what: tier.identifier + "'s OnBehalfOf JWT",
        audience: next.appliesTo, issuer: issuer, sub: first.claims.sub,
        clientId: tier.identifier, act: undefined,
        notJtis: tokens.map(function (one) {
          return one.claims.jti;
        }) }));
    });
  }
  const final = tokens[tokens.length - 1];
  log.info("=== The final JWT's claims ===");
  log.info(JSON.stringify(final.claims, null, 2));

  check("3. sp1's own validation: the published key, typ at+jwt, " +
        cast.provider.appliesTo + " in aud, the issuer GET /sts names, the " +
        "clock; and nobody is named as having acted", function () {
    const atTarget = kit.validateJwtAtTarget(final.token, keys,
                                             cast.provider.appliesTo,
                                             issuer, SKEW_MS);
    assert.strictEqual(atTarget.claims.act, undefined);
  });

  log.info("=== The register and the picture ===");
  const since = await kit.registerSince(base, cast, baselineAt);
  const hops = requesters.map(function (tier, i) {
    return { clientId: tier.identifier, target: tier.next,
             appliesTo: kit.tierNamed(cast, tier.next).appliesTo,
             consumedId: tokens[i].claims.jti,
             producedId: tokens[i + 1].claims.jti };
  });
  const acts = hops.map(function (hop) {
    return kit.actProducing(since.acts, hop.producedId, hop.clientId +
                            "'s OnBehalfOf JWT");
  });
  hops.forEach(function (hop, i) {
    check("4" + "abc"[i] + ". the register: one wstrust-onbehalfof act " +
          "(impersonation) by " + hop.clientId + " for " + cast.user + " to " +
          hop.target + ", consuming jti " + hop.consumedId + " and " +
          "producing jti " + hop.producedId + ", allowed by the issuance " +
          "policy" + (product ? ", policed" : ""), function () {
      kit.assertAct(cast, acts[i], {
        type: "wstrust-onbehalfof", mode: "impersonation",
        semantics: SEMANTICS,
        requester: hop.clientId, target: hop.target,
        appliesTo: hop.appliesTo, consumedId: hop.consumedId,
        producedId: hop.producedId, producedKind: "JWT",
        product: product });
    });
  });
  const findings = acts.reduce(function (all, act) {
    return all.concat(kit.actNotes(act, ELEMENT, product,
                                       true));
  }, []);
  check("4d. the picture: an impersonation line from " + cast.user +
        " to " +
        "each requester, and " + cast.gateway.identifier + " and " +
        cast.esb.identifier + " each ONE box (#468)", function () {
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
  .name("sts_wstrust_jwt_chain_impersonation")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider: one WS-Trust sign-in and three <wst:OnBehalfOf> " +
    "exchanges asking for JWTs, each held to RFC 9068 with no act, " +
    "asserted on the wire, by the target's own validation and in the " +
    "delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
