// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_chain_delegation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER GNAP DELEGATION CHAIN OVER THE WIRE (#497): bob's approval of
// webapp1's grant, then two RFC 9767 derivations — the GNAP equivalent of
// `sts_token_exchange_chain_delegation.js` (#467),
// `sts_wstrust_chain_delegation.js` (#473) and
// `sts_kerberos_chain_delegation.js` (#486). `gnap_chain_kit.js` says why
// this is the mapping:
//
//   webapp1-gndel asks for access at apigw1 with interaction; bob signs in
//   on the approval page and allows it, and webapp1 is issued a token about
//   bob for apigw1 — webapp1 is bob's own client, and acts for nobody.
//
//   apigw1 derives a token for esb1, and esb1 one for sp1 (RFC 9767 section
//   4), each signing with its own key, presenting the token it was handed
//   as `existing_access_token` and asking for no interaction. Each tier
//   names the next on `appAllowedToDelegateTo` and allows delegation.
//
// WHAT IT ASSERTS, in four layers:
//
//   1. THE REGISTRY: the four parties read back — each key on its entry,
//      each resource server's address, apigw1 delegating to esb1, esb1 to
//      sp1, webapp1 and sp1 to nobody.
//   2. EVERY TOKEN AS ITS RESOURCE SERVER WOULD HOLD IT: the JWS verified
//      against /oauth2/jwks by the job's own code; about bob; `aud` the ONE
//      registered resource server it is for; `client_id` the party that
//      asked; `act` absent on webapp1's, [apigw1] on esb1's and on sp1's
//      esb1 over apigw1 — RFC 8693 section 4.1's chain, most recent
//      outermost; the tier's own right and the common right on every token;
//      then introspection by that tier, signing with its own key, agreeing
//      and filtered for it.
//   3. THE ORIGINAL CLIENT (#443's question): not in `act`, which names only
//      the parties that acted, and not in `client_id`, which a derivation
//      makes the deriving tier. GNAP records it in the GRANT: every token of
//      the chain carries the ORIGINAL grant's `grant_id`, and that grant on
//      GET /admin-api/gnap names webapp1 as its client and bob as its
//      resource owner; each derivation grant names the token it came from.
//   4. THE REGISTER AND THE PICTURE: one `gnap-derivation` act per hop, mode
//      delegation, policed, for bob, consuming the token it was handed and
//      found by the jti it produced, each saying the issuance policy allowed
//      it by name. Then the graph: apigw1 and esb1 each ONE box (#468).
//
// In development and product mode alike (GET /admin-api/mode). The entries
// are left behind; a rerun reconciles them and replaces every key.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

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
var log = bunyan.createLogger({ name: "sts_gnap_chain_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const JOB = "sts_gnap_chain_delegation";
const TAG = "gndel";
const DELEGATES = { semantics: ["delegation"], default: "delegation" };
const PLAN = { apigw1: DELEGATES, esb1: DELEGATES };

async function test() {
  log.debug("Entering test().");
  const started = await kit.start(TAG);
  const G = started.G;
  const cast = started.cast;
  await kit.provisionCast(G, cast, PLAN, { finish: G.h.FINISH });
  const subject = await G.h.subjectOf(cast.user);
  const baselineAt = await kit.registerBaseline(G.base);

  log.info("=== bob approves webapp1's grant (interaction) ===");
  const first = await kit.approvedGrant(G, cast);
  const tokens = [];
  tokens.push(await kit.assertToken(G, cast, first, {
    holder: cast.webapp, target: cast.gateway, act: null,
    subject: subject }));
  kit.captureLayer(G, { hop: "webapp1→apigw1",
    requester: cast.webapp.identifier, target: cast.gateway.identifier,
    kind: "GNAP access token (jwt-signed)", format: "jwt-signed",
    value: tokens[0].value, header: tokens[0].header,
    claims: tokens[0].claims, act: null,
    notes: "issued to webapp1 after bob approved its grant on the " +
      "approval page; introspected by apigw1: " +
      JSON.stringify(tokens[0].introspection) });

  let held = first;
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
  log.info("=== the original client ===");
  const original = await kit.assertOriginalClient(G, cast, tokens);
  log.info("[target] sp1 holds a token about " + cast.user + " whose act " +
           "reads esb1 over apigw1, counted against " + original.client +
           "'s grant " + original.id + ".");

  log.info("=== the register and the picture ===");
  const seen = await kit.registerSince(G.base, cast, baselineAt);
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
    { actor: cast.gateway, mode: "delegation" },
    { actor: cast.esb, mode: "delegation" }]);
  kit.writeCapture(G, JOB, "delegation");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name(JOB)
  .description("A four-tier GNAP delegation chain: bob approves webapp1's " +
    "grant for apigw1, then RFC 9767 derivations to esb1 and sp1, with " +
    "every token verified, the original client traced through its grant, " +
    "the register and the picture.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
