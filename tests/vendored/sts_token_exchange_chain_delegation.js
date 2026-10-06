// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_token_exchange_chain_delegation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER DELEGATION CHAIN OVER HTTP: one sign-in, then two RFC 8693
// hops, each WITH an actor_token (#467).
//
// The same four tiers as `sts_token_exchange_chain_impersonation.js`, under
// a tag of their own (`-del`), and the same sign-in — bob_end_user to
// webapp1-del, asking for `openid email profile offline_access app1-scope`
// with `resource=https://apigw1-del.example.com`, the gateway's registered
// audience. What changes is the middle:
//
//   AT EACH HOP THE EXCHANGING TIER FIRST OBTAINS ITS OWN TOKEN, a
//   client_credentials grant with its own client_id and secret asking for
//   app1-scope — so that token's subject is the tier itself — and sends it
//   as the `actor_token` (`actor_token_type` access_token) beside the
//   subject_token. That is RFC 8693 section 1.1's DELEGATION: the issued
//   token names bob_end_user as its subject and the tier in an `act` claim.
//
//   AND THE CHAIN BEGINS WITH THE ORIGINAL CLIENT (#443). The sign-in's
//   token carries no `act`, so the first hop nests the client it was issued
//   to — webapp1-del, its `client_id` — beneath the gateway, as the
//   token-chaining profile #443 cites requires ("add a nested act claim
//   containing a sub claim with the identity of the client that presented
//   the access token", MITRE PR 21-1421):
//
//       "act": { "sub": <apigw1-del>, "act": { "sub": <webapp1-del> } }
//
//   AND `act` NESTS (section 4.1). The second hop's subject_token already
//   carries that chain, so sp1-del's token reads
//
//       "act": { "sub": <esb1-del>,
//                "act": { "sub": <apigw1-del>,
//                         "act": { "sub": <webapp1-del> } } }
//
//   — "the outermost act claim represents the current actor while nested act
//   claims represent prior actors". Each actor's `sub` is the actor_token's
//   own subject, verbatim: `esb1-del` in development, where a
//   client_credentials token's subject is its client_id, and
//   `urn:sts:client:esb1-del` in RFC 9700 mode (implied by product), which
//   gives a client a namespace of its own (section 4.13). The original
//   client takes the same form in the same mode — `webapp1-del` or
//   `urn:sts:client:webapp1-del` — though it never sends a token of its own:
//   it is a client, named as the service names a client's subject.
//
// The middle tiers are configured to DELEGATE — `appDelegationSemantics`
// and `appDefaultDelegationSemantics` delegation, `appAllowedToDelegateTo`
// the next tier — which is the policy's rule 10 for a delegation: S (the
// application the subject token was issued for, its `aud`) delegates to R,
// and the actor is S. Here S, the actor and the exchanging client are all the
// same tier. Nothing is set on the person: `stsMayAct` names ONE delegate and
// this chain has two actors.
//
// WHAT IT ASSERTS, in the impersonation job's four layers, with the actor
// in each:
//
//   1. THE REGISTRY, as there.
//   2. THE WIRE: the sign-in's token as there, with no `act`; each actor
//      token about its tier (not the person), issued to it, carrying
//      app1-scope; each exchanged token about bob_end_user, carrying
//      app1-scope, addressed to the next tier, issued to the client that
//      asked, with `act` exactly as above — the whole chain, compared in
//      full, on the hop-1 token and on the final one.
//   3. INTROSPECTION at sp1-del: active, for bob_end_user, addressed to
//      sp1-del, app1-scope — and, where the response carries `act` (RFC 8693
//      section 7.2 registers it for introspection), the same nested `act`.
//   4. THE REGISTER AND THE PICTURE: one `oauth-delegation` act per hop,
//      found by the jti of the token it produced, naming the actor_token's
//      subject as the identity in the middle and the actor token's jti among
//      what it consumed, the issuance policy's ALLOWED sentence; in product,
//      policed with both tokens verified. Then the graph: a delegation line
//      from bob_end_user to each tier, and esb1-del ONE box.
//
// In development and product mode alike; entries left behind and
// reconciled on a rerun, as there.
//
// OWNED HERE (local: true): the chain is this repository's own scenario.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const kit = require("./token_exchange_chain_kit.js");

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
var log = bunyan.createLogger({ name: "sts_token_exchange_chain_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const TAG = "del";
const SEMANTICS = "delegation";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// A tier's own token: about the TIER, issued to it, carrying app1-scope —
// and naming nobody else. Its `sub` is the client_id, or the client in its
// own namespace in RFC 9700 mode.
function assertActorToken(cast, tier, token) {
  log.debug("Entering assertActorToken(). " + tier.identifier);
  const what = tier.identifier + "'s client_credentials token";
  const claims = kit.claimsOf(token, what);
  assert.ok(claims.sub === tier.identifier ||
            claims.sub === "urn:sts:client:" + tier.identifier,
    what + " should be about the tier itself and its sub is \"" +
    claims.sub + "\".");
  assert.strictEqual(claims.client_id, tier.identifier, what + " was " +
                     "issued to " + claims.client_id);
  assert.notStrictEqual(claims.username, cast.user, what + " names the " +
                        "person; a client_credentials token has no person.");
  assert.ok(claims.act === undefined, what + " carries act " +
            JSON.stringify(claims.act));
  kit.assertCommonScope(claims, what);
  log.info("[actor] " + what + ": sub=" + claims.sub + ", aud=" +
           JSON.stringify(claims.aud) + ", scope=\"" + claims.scope +
           "\", jti=" + claims.jti);
  log.debug("Leaving assertActorToken().");
  return claims;
}

// The form the service gives a CLIENT's subject in the mode, read off an
// actor token that is one: namespaced where the actor's is (RFC 9700 mode),
// the bare client_id where it is not. Product implies RFC 9700 mode, so a
// product service that does not namespace is a failure, not a form.
function clientSubjectLike(actorClaims, identifier, product) {
  log.debug("Entering clientSubjectLike(). " + identifier);
  const namespaced = /^urn:sts:client:/.test(String(actorClaims.sub || ""));
  assert.ok(!product || namespaced, "a product service gives a client the " +
            "subject urn:sts:client:<id> (RFC 9700 section 4.13, implied by " +
            "product) and the actor token's is \"" + actorClaims.sub + "\".");
  log.debug("Leaving clientSubjectLike().");
  return namespaced ? "urn:sts:client:" + identifier : identifier;
}

function assertActIs(claims, expected, what) {
  log.debug("Entering assertActIs(). " + what);
  assert.deepStrictEqual(claims.act, expected, what + " should carry " +
    "act " + JSON.stringify(expected) + " (RFC 8693 section 4.1: the " +
    "current actor outermost, prior actors nested beneath it) and carries " +
    JSON.stringify(claims.act) + ".");
  log.debug("Leaving assertActIs().");
}

async function test() {
  log.debug("Entering test().");
  const base = kit.serviceBase();
  const cast = kit.castFor(TAG);
  const product = await kit.isProduct(base);
  log.info("The delegation chain at " + base + ": " + cast.user + " -> " +
           cast.webapp.identifier + " -> " + cast.gateway.identifier +
           " -> " + cast.esb.identifier + " -> " +
           cast.provider.identifier + " (" +
           (product ? "product" : "development") + " mode).");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS);
  check("1. the four entries hold their audiences (none on " +
        cast.webapp.identifier + ") and declare " + kit.COMMON_SCOPE,
        function () {});

  log.info("=== The sign-in ===");
  const signedIn = await kit.signIn(base, cast);
  let first;
  check("2a. " + cast.webapp.identifier + "'s token: " + cast.user + ", " +
        kit.COMMON_SCOPE + ", addressed to " + cast.gateway.audience +
        ", no act", function () {
    first = kit.assertChainToken(cast, signedIn.access_token, {
      what: cast.webapp.identifier + "'s access token",
      audience: cast.gateway.audience, clientId: cast.webapp.identifier,
      notAudience: [cast.gateway.identifier] });
    assert.ok(first.act === undefined, JSON.stringify(first.act));
  });

  log.info("=== Hop 1: " + cast.gateway.identifier + " acts ===");
  const actor1 = await kit.clientCredentials(base, cast, cast.gateway);
  let actor1Claims;
  check("2b. " + cast.gateway.identifier + "'s actor token is about " +
        "itself and carries " + kit.COMMON_SCOPE, function () {
    actor1Claims = assertActorToken(cast, cast.gateway, actor1.access_token);
  });
  const hop1 = await kit.exchange(base, cast, cast.gateway,
                                  signedIn.access_token, actor1.access_token);
  // The client the chain began with, in its mode's form (#443).
  const originalSub = clientSubjectLike(actor1Claims, cast.webapp.identifier,
                                        product);
  let second;
  check("2c. " + cast.gateway.identifier + "'s exchanged token: " +
        cast.user + ", " + kit.COMMON_SCOPE + ", addressed to " +
        cast.esb.audience + ", act naming " + cast.gateway.identifier +
        " with the original client " + cast.webapp.identifier +
        " NESTED beneath it (#443)", function () {
    second = kit.assertChainToken(cast, hop1.access_token, {
      what: cast.gateway.identifier + "'s exchanged token",
      audience: cast.esb.audience, clientId: cast.gateway.identifier,
      notAudience: [cast.gateway.identifier, cast.gateway.audience] });
    assertActIs(second, { sub: actor1Claims.sub, act: { sub: originalSub } },
                cast.gateway.identifier + "'s exchanged token");
  });

  log.info("=== Hop 2: " + cast.esb.identifier + " acts ===");
  const actor2 = await kit.clientCredentials(base, cast, cast.esb);
  let actor2Claims;
  check("2d. " + cast.esb.identifier + "'s actor token is about itself " +
        "and carries " + kit.COMMON_SCOPE, function () {
    actor2Claims = assertActorToken(cast, cast.esb, actor2.access_token);
  });
  const hop2 = await kit.exchange(base, cast, cast.esb, hop1.access_token,
                                  actor2.access_token);
  let third;
  const nested = { sub: "", act: { sub: "", act: { sub: "" } } };
  check("2e. " + cast.esb.identifier + "'s exchanged token: " + cast.user +
        ", " + kit.COMMON_SCOPE + ", addressed to " + cast.provider.audience +
        ", act naming " + cast.esb.identifier + " with " +
        cast.gateway.identifier + " and then the original client " +
        cast.webapp.identifier + " NESTED beneath it (#443)", function () {
    third = kit.assertChainToken(cast, hop2.access_token, {
      what: cast.esb.identifier + "'s exchanged token",
      audience: cast.provider.audience, clientId: cast.esb.identifier,
      notAudience: [cast.gateway.identifier, cast.esb.audience,
                    cast.webapp.identifier] });
    nested.sub = actor2Claims.sub;
    nested.act.sub = actor1Claims.sub;
    nested.act.act.sub = originalSub;
    assertActIs(third, nested, cast.esb.identifier + "'s exchanged token");
  });
  log.info("=== The final access token's claims ===");
  log.info(JSON.stringify(third, null, 2));

  const introspection = await kit.introspect(base, cast, hop2.access_token);
  check("3. introspection at " + cast.provider.identifier + ": active, " +
        cast.user + ", addressed to " + cast.provider.audience + ", " +
        kit.COMMON_SCOPE + (introspection.act !== undefined
          ? ", the same nested act" : ""), function () {
    assert.strictEqual(introspection.active, true,
                       JSON.stringify(introspection));
    assert.strictEqual(introspection.username, cast.user,
                       JSON.stringify(introspection));
    assert.ok(kit.audienceList(introspection)
      .indexOf(cast.provider.audience) >= 0, JSON.stringify(introspection));
    kit.assertCommonScope(introspection, "the introspection of the final " +
                          "token");
    if (introspection.act !== undefined) {
      assertActIs(introspection, nested, "the introspection of the final " +
                  "token");
    } else {
      log.info("[introspection] the response carries no `act`; RFC 8693 " +
               "section 7.2 registers it for introspection without " +
               "requiring it.");
    }
  });

  log.info("=== The register and the picture ===");
  const since = await kit.registerSince(base, cast, baselineAt);
  const hops = [
    { clientId: cast.gateway.identifier, target: cast.esb.identifier,
      audience: cast.esb.audience, claims: second, subjectJti: first.jti,
      actor: actor1Claims, actorSub: actor1Claims.sub },
    { clientId: cast.esb.identifier, target: cast.provider.identifier,
      audience: cast.provider.audience, claims: third,
      subjectJti: second.jti, actor: actor2Claims,
      actorSub: actor2Claims.sub }
  ];
  const acts = hops.map(function (hop) {
    return kit.actProducing(since.acts, hop.claims.jti,
                            hop.clientId + "'s exchanged token");
  });
  hops.forEach(function (hop, i) {
    check("4" + "ab"[i] + ". the register: one oauth-delegation act by " +
          hop.actor.sub + " through " + hop.clientId + " for " + cast.user +
          " to " + hop.target + ", the actor token consumed, allowed by the " +
          "issuance policy" + (product ? ", policed, both tokens verified"
                                       : ""), function () {
      kit.assertAct(cast, acts[i], {
        type: "oauth-delegation", mode: "delegation",
        semantics: SEMANTICS, clientId: hop.clientId, target: hop.target,
        audience: hop.audience, presented: hop.actor.sub,
        subjectJti: hop.subjectJti, actorJti: hop.actor.jti,
        product: product });
    });
  });
  check("4c. the picture: a delegation line from " + cast.user + " to " +
        "each actor, and " + cast.esb.identifier + " both reached and " +
        "acting (one box where the actor's subject is its client_id)",
        function () {
    kit.assertGraphIsAChain(cast, since.graph, hops, "delegation");
  });

  assert.ok(checks >= 10, "only " + checks + " of 10 checks ran; a " +
            "section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_token_exchange_chain_delegation")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider: one sign-in and two RFC 8693 exchanges, each with " +
    "the tier's own client_credentials token as actor_token (delegation), " +
    "the nested act, app1-scope on every token, asserted on the wire, at " +
    "introspection and in the delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
