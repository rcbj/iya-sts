// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_token_exchange_chain_impersonation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER IMPERSONATION CHAIN OVER HTTP: one sign-in, then two RFC 8693
// hops with NO actor_token (#467).
//
// The parent project's `tests/oauth2_delegation_chain.js`, without its
// browser — `token_exchange_chain_kit.js` says what was kept and why:
//
//   bob_end_user signs in to webapp1-imp (authorization code, PKCE, a public
//   client), asking for `openid email profile offline_access app1-scope`
//   with RFC 8707 `resource=https://apigw1-imp.example.com` — the gateway's
//   REGISTERED audience (rcbj: every hop names the token it wants by the
//   next tier's registered audience). The token comes back ADDRESSED to that
//   URI, and the OpenID Connect scopes stay off it.
//
//   apigw1-imp exchanges that token for one addressed to esb1-imp's
//   registered URI; esb1-imp exchanges THAT for sp1-imp's. Each exchange
//   asks for app1-scope and sends no actor_token: RFC 8693 section 1.1's
//   IMPERSONATION, the middle tiers invisible in every token they produce.
//
// The middle tiers are configured to impersonate — `appDelegationSemantics`
// and `appDefaultDelegationSemantics` impersonation, `appAllowedToDelegateTo`
// the next tier (the policy's rule 10, "the actor must reach R") — because a
// realm's default semantics is DELEGATION, under which the same request
// comes back carrying `act` naming the client.
//
// WHAT IT ASSERTS, in four layers, because any one of them passes alone:
//
//   1. THE REGISTRY: each entry read back with its audience — none on
//      webapp1-imp — and app1-scope declared.
//   2. THE WIRE: every token names bob_end_user, carries app1-scope and no
//      OpenID Connect scope, is addressed to the next tier and no longer to
//      the one it left, was issued to the client that asked, and carries NO
//      `act` claim.
//   3. INTROSPECTION at sp1-imp: the issuer's reading of the final token —
//      active, for bob_end_user, addressed to sp1-imp, app1-scope, no `act`.
//   4. THE REGISTER AND THE PICTURE: one `oauth-impersonation` act per hop,
//      found by the jti of the token it produced, naming no identity in the
//      middle, the application the audience resolved to as its target, the
//      issuance policy's ALLOWED sentence, and the subject token it
//      consumed; in product, policed and the subject token verified. Then
//      the graph: esb1-imp is ONE box, the target of the first hop and the
//      middle of the second.
//
// In development and product mode alike (GET /admin-api/mode): the same
// provisioning, and product's stricter facts asserted where it has them.
// The four entries are left behind; a rerun reconciles them.
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
var log = bunyan.createLogger({ name: "sts_token_exchange_chain_impersonation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

const TAG = "imp";
const SEMANTICS = "impersonation";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function assertNoAct(claims, what) {
  log.debug("Entering assertNoAct(). " + what);
  assert.ok(claims.act === undefined, what + " carries an `act` claim (" +
    JSON.stringify(claims.act) + "). No actor_token was sent and the tier " +
    "impersonates, so RFC 8693 section 1.1 leaves the middle out of the " +
    "token; the server invented an actor.");
  log.debug("Leaving assertNoAct().");
}

async function test() {
  log.debug("Entering test().");
  const base = kit.serviceBase();
  const cast = kit.castFor(TAG);
  const product = await kit.isProduct(base);
  log.info("The impersonation chain at " + base + ": " + cast.user + " -> " +
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
    assertNoAct(first, cast.webapp.identifier + "'s access token");
  });

  log.info("=== Hop 1: " + cast.gateway.identifier + " exchanges ===");
  const hop1 = await kit.exchange(base, cast, cast.gateway,
                                  signedIn.access_token, "");
  let second;
  check("2b. " + cast.gateway.identifier + "'s exchanged token: " +
        cast.user + ", " + kit.COMMON_SCOPE + ", addressed to " +
        cast.esb.audience + ", no act", function () {
    second = kit.assertChainToken(cast, hop1.access_token, {
      what: cast.gateway.identifier + "'s exchanged token",
      audience: cast.esb.audience, clientId: cast.gateway.identifier,
      notAudience: [cast.gateway.identifier, cast.gateway.audience] });
    assertNoAct(second, cast.gateway.identifier + "'s exchanged token");
    assert.ok(String(hop1.scope || "").split(" ")
      .indexOf(kit.COMMON_SCOPE) >= 0, "the response's scope member: " +
      JSON.stringify(hop1.scope));
  });

  log.info("=== Hop 2: " + cast.esb.identifier + " exchanges ===");
  const hop2 = await kit.exchange(base, cast, cast.esb, hop1.access_token,
                                  "");
  let third;
  check("2c. " + cast.esb.identifier + "'s exchanged token: " + cast.user +
        ", " + kit.COMMON_SCOPE + ", addressed to " +
        cast.provider.audience + ", no act", function () {
    third = kit.assertChainToken(cast, hop2.access_token, {
      what: cast.esb.identifier + "'s exchanged token",
      audience: cast.provider.audience, clientId: cast.esb.identifier,
      notAudience: [cast.gateway.identifier, cast.esb.audience,
                    cast.webapp.identifier] });
    assertNoAct(third, cast.esb.identifier + "'s exchanged token");
  });
  log.info("=== The final access token's claims ===");
  log.info(JSON.stringify(third, null, 2));

  const introspection = await kit.introspect(base, cast, hop2.access_token);
  check("3. introspection at " + cast.provider.identifier + ": active, " +
        cast.user + ", addressed to " + cast.provider.audience + ", " +
        kit.COMMON_SCOPE + ", no act", function () {
    assert.strictEqual(introspection.active, true,
                       JSON.stringify(introspection));
    assert.strictEqual(introspection.username, cast.user,
                       JSON.stringify(introspection));
    assert.ok(kit.audienceList(introspection)
      .indexOf(cast.provider.audience) >= 0, JSON.stringify(introspection));
    kit.assertCommonScope(introspection, "the introspection of the final " +
                          "token");
    assert.ok(introspection.act === undefined, JSON.stringify(introspection));
  });

  log.info("=== The register and the picture ===");
  const since = await kit.registerSince(base, cast, baselineAt);
  const hops = [
    { clientId: cast.gateway.identifier, target: cast.esb.identifier,
      audience: cast.esb.audience, claims: second, subjectJti: first.jti },
    { clientId: cast.esb.identifier, target: cast.provider.identifier,
      audience: cast.provider.audience, claims: third,
      subjectJti: second.jti }
  ];
  const acts = hops.map(function (hop) {
    return kit.actProducing(since.acts, hop.claims.jti,
                            hop.clientId + "'s exchanged token");
  });
  hops.forEach(function (hop, i) {
    check("4" + "ab"[i] + ". the register: one oauth-impersonation act by " +
          hop.clientId + " for " + cast.user + " to " + hop.target +
          ", allowed by the issuance policy" +
          (product ? ", policed, the subject token verified" : ""),
          function () {
      kit.assertAct(cast, acts[i], {
        type: "oauth-impersonation", mode: "impersonation",
        semantics: SEMANTICS, clientId: hop.clientId, target: hop.target,
        audience: hop.audience, presented: "", subjectJti: hop.subjectJti,
        actorJti: "", product: product });
    });
  });
  check("4c. the picture: " + cast.esb.identifier + " is one box, " +
        "reached by the first hop and in the middle of the second",
        function () {
    kit.assertGraphIsAChain(cast, since.graph, hops, "impersonation");
  });

  assert.ok(checks >= 8, "only " + checks + " of 8 checks ran; a " +
            "section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_token_exchange_chain_impersonation")
  .description("A web application, an API gateway, a service bus and a " +
    "service provider: one sign-in and two RFC 8693 exchanges with no " +
    "actor_token (impersonation), app1-scope on every token, asserted on " +
    "the wire, at introspection and in the delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
