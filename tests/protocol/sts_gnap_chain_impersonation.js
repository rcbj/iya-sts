// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_chain_impersonation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER GNAP IMPERSONATION CHAIN OVER THE WIRE (#497): a user
// assertion presented by a client trusted to skip interaction, then two RFC
// 9767 derivations — the GNAP equivalent of
// `sts_token_exchange_chain_impersonation.js` (#467),
// `sts_wstrust_chain_impersonation.js` (#473) and
// `sts_kerberos_chain_impersonation.js` (#486). `gnap_chain_kit.js` says
// why this is the mapping:
//
//   bob_end_user-gnimp signs in to webapp1-gnimp through this service's
//   OpenID Connect authorization endpoint, so webapp1 holds an ID Token
//   ISSUED TO IT. webapp1 — `gnapSkipInteraction`, impersonation in its
//   `appDelegationSemantics`, apigw1 on its `appAllowedToDelegateTo` —
//   presents that ID Token as `user.assertions` (RFC 9635 section 2.4) and
//   is issued a token about bob for apigw1 that names NO actor: S4U2Self's
//   place in the Kerberos job.
//
//   apigw1 derives a token for esb1, and esb1 one for sp1 (RFC 9767 section
//   4: each signs with its own key, presents `existing_access_token` and
//   asks for no interaction). Each derivation names its deriving resource
//   server in `act`, so sp1's token reads esb1 over apigw1: S4U2Proxy's
//   place.
//
// WHAT IT ASSERTS, in four layers:
//
//   1. THE REGISTRY: the four parties read back — each key on its entry,
//      each resource server's address, webapp1 allowing impersonation to
//      apigw1, apigw1 delegation to esb1, esb1 to sp1, sp1 nothing.
//   2. THE ASSERTION'S AUDIENCE (RFC 9635 section 11.13): bob's ID Token is
//      webapp1's, and apigw1 presenting it as its own user assertion is
//      refused — unknown_user on the wire, STS-GNAP-0073 on the audit — in
//      every mode, before any delegation question is asked.
//   3. EVERY TOKEN AS ITS RESOURCE SERVER WOULD HOLD IT: the JWS verified
//      against /oauth2/jwks by the job's own code; about bob; `aud` the ONE
//      registered resource server it is for; `client_id` the party that
//      asked; `act` absent on webapp1's, [apigw1] on esb1's, [esb1, apigw1]
//      on sp1's; the tier's own right and the common right on every token;
//      then introspection by that tier, signing with its own key, agreeing
//      and filtered for it. Every token counts against webapp1's grant.
//   4. THE REGISTER AND THE PICTURE: one `gnap-impersonation` act (webapp1
//      to apigw1, consuming the ID Token) and one `gnap-derivation` per
//      hop, each for bob and found by the jti it produced, each saying the
//      issuance policy allowed it by name. Then the graph: apigw1 and esb1
//      each ONE box (#468).
//
// In development and product mode alike (GET /admin-api/mode): every tier
// is registered, so the policy ALLOWS each act in both, and product
// enforces what development records. The entries are left behind; a rerun
// reconciles them and replaces every key.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const kit = require("./gnap_chain_kit.js");

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
var log = bunyan.createLogger({ name: "sts_gnap_chain_impersonation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const JOB = "sts_gnap_chain_impersonation";
const TAG = "gnimp";
const PLAN = {
  webapp1: { semantics: ["impersonation"], default: "impersonation" },
  apigw1: { semantics: ["delegation"], default: "delegation" },
  esb1: { semantics: ["delegation"], default: "delegation" }
};

async function test() {
  log.debug("Entering test().");
  const started = await kit.start(TAG);
  const G = started.G;
  const cast = started.cast;
  await kit.provisionCast(G, cast, PLAN, { oidcClient: true,
                                           skipInteraction: true });
  const subject = await G.h.subjectOf(cast.user);
  const baselineAt = await kit.registerBaseline(G.base);

  log.info("=== bob signs in to webapp1 (OpenID Connect) ===");
  const idToken = await kit.oidcSignIn(G, cast);
  kit.captureLayer(G, { hop: "bob→webapp1", requester: cast.user,
    target: cast.webapp.identifier, kind: "ID Token", format: "jwt",
    value: idToken.value, header: idToken.header, claims: idToken.claims,
    act: null, notes: "OpenID Connect authorization code flow with PKCE; " +
      "aud is webapp1, the client that will present it" });

  log.info("=== apigw1 presents webapp1's ID Token as its own: refused ===");
  await kit.refusedAs(G, "STS-GNAP-0073", "unknown_user", "apigw1 " +
    "presenting an ID Token issued to webapp1 as its own user assertion " +
    "(RFC 9635 section 11.13)", function () {
    log.debug("Entering the captured-assertion request.");
    log.debug("Leaving the captured-assertion request.");
    return kit.presentAssertion(G, cast.gateway, idToken.value,
                                cast.gateway.next, cast);
  });

  log.info("=== webapp1 presents bob's ID Token (impersonation) ===");
  const r = await kit.presentAssertion(G, cast.webapp, idToken.value,
                                       cast.gateway, cast);
  assert.strictEqual(r.status, 200, "webapp1's grant by assertion was " +
                     "refused: " + String(r.text).slice(0, 400));
  assert.ok(r.json.access_token && !r.json.interact, "webapp1 trusted to " +
            "skip interaction should be issued the token at once: " +
            r.text.slice(0, 400));
  const tokens = [];
  tokens.push(await kit.assertToken(G, cast, r.json.access_token, {
    holder: cast.webapp, target: cast.gateway, act: null,
    subject: subject }));
  kit.captureLayer(G, { hop: "webapp1→apigw1",
    requester: cast.webapp.identifier, target: cast.gateway.identifier,
    kind: "GNAP access token (jwt-signed)", format: "jwt-signed",
    value: tokens[0].value, header: tokens[0].header,
    claims: tokens[0].claims, act: null,
    notes: "issued to webapp1 for its user assertion, no interaction; " +
      "introspected by apigw1: " + JSON.stringify(tokens[0].introspection) });

  let held = r.json.access_token;
  const acted = [];
  for (const tier of [cast.gateway, cast.esb]) {
    log.info("=== " + tier.stem + " derives a token for " + tier.next.stem +
             " (RFC 9767 section 4) ===");
    held = await kit.derive(G, cast, tier, held.value);
    acted.push(tier);
    const seen = await kit.assertToken(G, cast, held, {
      holder: tier, target: tier.next, act: kit.actChain(G, cast, acted),
      subject: subject });
    tokens.push(seen);
    kit.captureLayer(G, { hop: tier.stem + "→" + tier.next.stem,
      requester: tier.identifier, target: tier.next.identifier,
      kind: "GNAP access token (jwt-signed)", format: "jwt-signed",
      value: seen.value, header: seen.header, claims: seen.claims,
      act: seen.claims.act || null,
      notes: "derived by " + tier.identifier + " from the token it was " +
        "handed; introspected by " + tier.next.identifier + ": " +
        JSON.stringify(seen.introspection) });
  }
  log.info("[target] sp1 holds a token about " + cast.user + " whose act " +
           "names esb1 over apigw1, and webapp1 nowhere: it impersonated.");
  await kit.assertOriginalClient(G, cast, tokens);

  log.info("=== the register and the picture ===");
  const seen = await kit.registerSince(G.base, cast, baselineAt);
  kit.assertAct(G, cast, kit.actProducing(seen.acts,
    tokens[0].claims.jti, "webapp1's token"), {
      type: "gnap-impersonation", mode: "impersonation",
      actor: cast.webapp, target: cast.gateway, semantics: "impersonation",
      consumedKind: "user assertion", consumedIdentifier: "id_token" });
  for (let i = 0; i < 2; i += 1) {
    const tier = [cast.gateway, cast.esb][i];
    kit.assertAct(G, cast, kit.actProducing(seen.acts,
      tokens[i + 1].claims.jti, tier.stem + "'s derived token"), {
        type: "gnap-derivation", mode: "delegation", actor: tier,
        target: tier.next, semantics: "delegation",
        consumedKind: "access_token",
        consumedIdentifier: tokens[i].claims.jti });
  }
  kit.assertPicture(cast, seen.graph, [
    { actor: cast.webapp, mode: "impersonation" },
    { actor: cast.gateway, mode: "delegation" },
    { actor: cast.esb, mode: "delegation" }]);
  kit.writeCapture(G, JOB, "impersonation");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name(JOB)
  .description("A four-tier GNAP impersonation chain: webapp1 presents " +
    "bob's ID Token as a user assertion for a token for apigw1, then RFC " +
    "9767 derivations to esb1 and sp1, with every token verified, the " +
    "register and the picture.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
