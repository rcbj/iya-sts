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
//   AND EVERY ENTRY CARRIES `iss` (#471): the issuer of the token it is in,
//   as the token-chaining profile has it ("a sub claim identifying PR1 and
//   an iss claim identifying the AS", MITRE PR 21-1421 section 2.4.1, and
//   the same for the nested original client). Every entry here was written
//   by this realm, so each level's `iss` is the token's own — on the hop-1
//   token, on the final one, and in the introspection of the final one.
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
//      sp1-del, app1-scope — and the same nested `act`, the whole chain back
//      to webapp1-del: RFC 8693 section 7.2 registers it for introspection
//      and the service returns it (#469), so a resource server that
//      introspects sees who acted.
//   4. THE REGISTER AND THE PICTURE: one `oauth-delegation` act per hop,
//      found by the jti of the token it produced, naming the actor_token's
//      subject as the identity in the middle and the actor token's jti among
//      what it consumed, the issuance policy's ALLOWED sentence; in product,
//      policed with both tokens verified. Then the graph: a delegation line
//      from bob_end_user to each tier, and esb1-del ONE box — in product
//      too, where its actor subject is `urn:sts:client:esb1-del` (#468).
//
// AND THE CHAIN FORKS AT THE BUS (#549). After esb1 there are TWO service
// providers, sp1-del and sp2-del, each exposing three delegated permissions
// — read, write and admin. read and write on both are delegated to esb1
// (`oauthDelegatedPermission`); admin on neither. esb1 exchanges ONCE PER
// PROVIDER, asking for app1-scope and all three permissions, none of which
// the subject token carries. The issuance policy (XACML, stage `exchange`)
// keeps a delegated permission the CALLER holds whether or not the
// subject_token carried it, and DROPS one it does not hold
// (STS-OAUTH-0954), in every mode — so each provider's token carries
// `app1-scope read write`, addressed to that provider, and NEVER admin. An
// admin in an issued scope is the bug this job exists to catch, and it is
// asserted on the token, at introspection and in the response's `scope`.
//
// AND EVERY TOKEN ABOUT THE PERSON CARRIES ROLES, GROUPS AND A CUSTOM CLAIM
// (#549): bob is in a group that holds a role, every tier names the groups
// claim `teams` (by cn) and a custom claim `tier`, so the ID Token, the
// sign-in's access token and every exchanged token carry `teams`, `roles`
// and `tier`. The actor tokens are about the tiers, which are in no group
// and hold no role, and are not held to them.
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
  // #550: a client_credentials token that asked for nothing else is
  // addressed to the client itself — its registered audience.
  assert.deepStrictEqual(kit.audienceList(claims), [tier.audience],
    what + " should be addressed to the tier itself (" + tier.audience +
    ", #550) and its aud is " + JSON.stringify(claims.aud) + ".");
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
  const cast = kit.castFor(TAG, { permissions: true });
  const providers = cast.providers;
  const product = await kit.isProduct(base);
  log.info("The delegation chain at " + base + ": " + cast.user + " -> " +
           cast.webapp.identifier + " -> " + cast.gateway.identifier +
           " -> " + cast.esb.identifier + " -> " +
           providers.map(function (one) {
             return one.identifier;
           }).join(" and ") + " (" +
           (product ? "product" : "development") + " mode).");
  const baselineAt = await kit.registerBaseline(base);
  await kit.provisionCast(base, cast, SEMANTICS);
  check("1. the five entries hold their audiences (none on " +
        cast.webapp.identifier + ") and declare " + kit.COMMON_SCOPE +
        "; each provider exposes read, write and admin, and " +
        cast.esb.identifier + " holds read and write on both and admin on " +
        "neither", function () {});

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
  check("2a-ii. the sign-in's access token and ID Token carry teams, " +
        "roles and tier (#549)", function () {
    kit.assertChainClaims(cast, first, cast.webapp.identifier +
                          "'s access token");
    assert.ok(signedIn.id_token, "the sign-in returned no ID Token: " +
              Object.keys(signedIn).join(", "));
    kit.assertChainClaims(cast, kit.claimsOf(signedIn.id_token, "the ID " +
                          "Token"), cast.webapp.identifier + "'s ID Token");
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
    assert.ok(second.iss, "the exchanged token names its issuer");
    assertActIs(second, { sub: actor1Claims.sub, iss: second.iss,
                          act: { sub: originalSub, iss: second.iss } },
                cast.gateway.identifier + "'s exchanged token");
    kit.assertChainClaims(cast, second, cast.gateway.identifier +
                          "'s exchanged token");
  });

  log.info("=== Hop 2: " + cast.esb.identifier + " acts, once per " +
           "service provider ===");
  const actor2 = await kit.clientCredentials(base, cast, cast.esb);
  let actor2Claims;
  check("2d. " + cast.esb.identifier + "'s actor token is about itself " +
        "and carries " + kit.COMMON_SCOPE, function () {
    actor2Claims = assertActorToken(cast, cast.esb, actor2.access_token);
  });
  // #550: an actor_token is the exchanging client's own. esb1 presenting
  // apigw1's token as its actor is refused, in every mode — without the
  // rule the issued token's act would name apigw1, decided with apigw1's
  // delegation settings.
  const borrowed = await kit.tokenRequest(base, {
    grant_type: kit.EXCHANGE_GRANT,
    subject_token: hop1.access_token,
    subject_token_type: kit.ACCESS_TOKEN_TYPE,
    actor_token: actor1.access_token,
    actor_token_type: kit.ACCESS_TOKEN_TYPE,
    audience: providers[0].audience, scope: kit.COMMON_SCOPE },
    kit.basicAuth(cast.esb.identifier,
                  kit.secretOf(cast, cast.esb.identifier)));
  check("2d-ii. " + cast.esb.identifier + " presenting " +
        cast.gateway.identifier + "'s token as its actor_token is refused " +
        "invalid_request (#550)", function () {
    assert.strictEqual(borrowed.status, 400, borrowed.text.slice(0, 400));
    assert.strictEqual(borrowed.json && borrowed.json.error,
                       "invalid_request", borrowed.text.slice(0, 400));
    assert.ok(!(borrowed.json && borrowed.json.access_token),
              "no token was issued");
  });
  // The chain every provider's token carries: esb1, then apigw1, then the
  // original client, every entry with the token's iss (#443, #471).
  const nestedFor = function (iss) {
    log.debug("Entering nestedFor().");
    log.debug("Leaving nestedFor().");
    return { sub: actor2Claims.sub, iss: iss,
             act: { sub: actor1Claims.sub, iss: iss,
                    act: { sub: originalSub, iss: iss } } };
  };
  const finals = [];
  for (let i = 0; i < providers.length; i++) {
    const provider = providers[i];
    const letter = "efghij"[i];
    // ALL THREE PERMISSIONS, none of which the subject token carries: read
    // and write are delegated to esb1, admin is not (#549).
    const asked = [kit.COMMON_SCOPE].concat(
      cast.permissions.names.map(function (name) {
        return kit.permissionId(provider, name);
      }));
    const hop = await kit.exchange(base, cast, cast.esb, hop1.access_token,
                                   actor2.access_token,
                                   { target: provider,
                                     scope: asked.join(" ") });
    let claims;
    check("2" + letter + ". " + cast.esb.identifier + "'s exchanged token " +
          "for " + provider.identifier + ": " + cast.user + ", addressed " +
          "to " + provider.audience + ", act naming " + cast.esb.identifier +
          " with " + cast.gateway.identifier + " and then " +
          cast.webapp.identifier + " nested beneath it (#443, #471)",
          function () {
      claims = kit.assertChainToken(cast, hop.access_token, {
        what: cast.esb.identifier + "'s exchanged token for " +
              provider.identifier,
        audience: provider.audience, clientId: cast.esb.identifier,
        notAudience: [cast.gateway.identifier, cast.esb.audience,
                      cast.webapp.identifier] });
      assert.ok(claims.iss, "the token names its issuer");
      assert.strictEqual(claims.iss, second.iss, "every hop was issued by " +
                         "the one authorization server");
      assertActIs(claims, nestedFor(claims.iss), cast.esb.identifier +
                  "'s exchanged token for " + provider.identifier);
    });
    check("2" + letter + "-ii. " + provider.identifier + "'s token carries " +
          "the delegated read and write the subject token did not, and " +
          "NOT admin, which was not delegated (#549)", function () {
      const scopes = kit.scopesOf(claims);
      ["read", "write"].forEach(function (name) {
        assert.ok(scopes.indexOf(name) >= 0, provider.identifier + "'s " +
          "token should carry " + name + ", delegated to " +
          cast.esb.identifier + ": scope=" + JSON.stringify(claims.scope));
        assert.ok(kit.scopesOf(second).indexOf(name) < 0, "the subject " +
          "token already carried " + name + "; the job no longer shows a " +
          "delegated permission ADDED by the exchange: " +
          JSON.stringify(second.scope));
      });
      assert.ok(scopes.indexOf("admin") < 0 &&
                scopes.indexOf(kit.permissionId(provider, "admin")) < 0,
        "A HUGE BUG: " + provider.identifier + "'s token carries admin, " +
        "which was never delegated to " + cast.esb.identifier + ": scope=" +
        JSON.stringify(claims.scope));
      assert.ok(String(hop.scope || "").split(/\s+/).indexOf("admin") < 0,
        "A HUGE BUG: the exchange response's scope names admin: " +
        JSON.stringify(hop.scope));
    });
    check("2" + letter + "-iii. and teams, roles and tier (#549)",
          function () {
      kit.assertChainClaims(cast, claims, cast.esb.identifier +
                            "'s exchanged token for " + provider.identifier);
    });
    finals.push({ provider: provider, hop: hop, claims: claims });
  }
  log.info("=== The final access tokens' claims ===");
  finals.forEach(function (one) {
    log.info(one.provider.identifier + ": " +
             JSON.stringify(one.claims, null, 2));
  });

  for (let i = 0; i < finals.length; i++) {
    const one = finals[i];
    const introspection = await kit.introspect(base, cast,
                                               one.hop.access_token,
                                               one.provider);
    check("3" + "abcdef"[i] + ". introspection at " +
          one.provider.identifier + ": active, " + cast.user + ", " +
          "addressed to " + one.provider.audience + ", " + kit.COMMON_SCOPE +
          " read write and no admin, the same nested act back to " +
          cast.webapp.identifier + " (#469, #549)", function () {
      assert.strictEqual(introspection.active, true,
                         JSON.stringify(introspection));
      assert.strictEqual(introspection.username, cast.user,
                         JSON.stringify(introspection));
      assert.ok(kit.audienceList(introspection)
        .indexOf(one.provider.audience) >= 0, JSON.stringify(introspection));
      kit.assertCommonScope(introspection, "the introspection of " +
                            one.provider.identifier + "'s token");
      const scopes = kit.scopesOf(introspection);
      assert.ok(scopes.indexOf("read") >= 0 && scopes.indexOf("write") >= 0,
                "introspection scope " + JSON.stringify(introspection.scope));
      assert.ok(scopes.indexOf("admin") < 0, "A HUGE BUG: introspection of " +
                one.provider.identifier + "'s token names admin: " +
                JSON.stringify(introspection.scope));
      assertActIs(introspection, nestedFor(one.claims.iss),
                  "the introspection of " + one.provider.identifier +
                  "'s token (RFC 8693 section 7.2, #469, #471)");
    });
  }

  log.info("=== The register and the picture ===");
  const since = await kit.registerSince(base, cast, baselineAt);
  const hops = [
    { clientId: cast.gateway.identifier, target: cast.esb.identifier,
      audience: cast.esb.audience, claims: second, subjectJti: first.jti,
      actor: actor1Claims, actorSub: actor1Claims.sub }
  ].concat(finals.map(function (one) {
    return { clientId: cast.esb.identifier,
             target: one.provider.identifier,
             audience: one.provider.audience, claims: one.claims,
             subjectJti: second.jti, actor: actor2Claims,
             actorSub: actor2Claims.sub };
  }));
  const acts = hops.map(function (hop) {
    return kit.actProducing(since.acts, hop.claims.jti,
                            hop.clientId + "'s exchanged token");
  });
  hops.forEach(function (hop, i) {
    check("4" + "abcdef"[i] + ". the register: one oauth-delegation act by " +
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
  check("4" + "abcdefg"[hops.length] + ". the picture: a delegation " +
        "line from " + cast.user + " to each actor, and " +
        cast.esb.identifier + " both reached and acting, ONE box in " +
        "either mode (#468)",
        function () {
    kit.assertGraphIsAChain(cast, since.graph, hops, "delegation");
  });

  assert.ok(checks >= 18, "only " + checks + " of 18 checks ran; a " +
            "section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_token_exchange_chain_delegation")
  .description("A web application, an API gateway, a service bus and " +
    "two service providers: one sign-in and RFC 8693 exchanges, each " +
    "with the tier's own client_credentials token as actor_token " +
    "(delegation), the nested act, app1-scope on every token, the " +
    "delegated read and write kept and the undelegated admin dropped, " +
    "roles, groups and a custom claim, asserted on the wire, at " +
    "introspection and in the delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
