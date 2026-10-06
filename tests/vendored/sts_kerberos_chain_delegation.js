// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_kerberos_chain_delegation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER KERBEROS DELEGATION CHAIN OVER THE WIRE: bob's own ticket, then
// three S4U2Proxy hops (#486) — the Kerberos equivalent of
// `sts_token_exchange_chain_delegation.js` (#467) and
// `sts_wstrust_chain_delegation.js` (#473). `kerberos_chain_kit.js` says
// why this is the mapping:
//
//   bob_end_user-krbdel authenticates to the KDC HIMSELF — an AS exchange
//   proving his password — and takes a FORWARDABLE ticket to webapp1-krbdel,
//   named by its registered SPN, which he hands it in an AP-REQ.
//
//   webapp1 presents that ticket as the evidence of an S4U2Proxy to apigw1;
//   apigw1 presents the ticket it was handed to esb1; esb1 to sp1. Classic
//   constrained delegation: each tier's entry names the next on
//   `appAllowedToDelegateTo`, and allows `delegation`.
//
// WHAT IT ASSERTS, in four layers, because any one of them passes alone:
//
//   1. THE REGISTRY: the person, and the four service principals read back
//      — each SPN on its entry, each delegating tier naming exactly the next
//      tier, sp1 and nobody else naming nobody.
//   2. THE WIRE: every KDC reply decoded — the ticket is for bob, to the SPN
//      asked for, the nonce echoed — and every ticket a hop presents is
//      FORWARDABLE, which classic delegation needs.
//   3. THE TARGET'S VALIDATION: each tier opens the AP-REQ it is handed with
//      its own key and the Authenticator with the session key, finds bob,
//      verifies the PAC's server signature, and reads the PAC's
//      S4U_DELEGATION_INFO ([MS-PAC] 2.9): absent on bob's own ticket, then
//      transited [webapp1], [webapp1, apigw1] and at sp1
//      [webapp1, apigw1, esb1] — webapp1 first, the original client (#443's
//      analogue), each S4U2proxyTarget the tier the ticket is for.
//   4. THE REGISTER AND THE PICTURE: one `krb5-s4u2proxy-classic` act per
//      hop, mode delegation, policed, for bob, from the requester to the
//      application its registered SPN names, attributed to
//      appAllowedToDelegateTo and to the issuance policy's ALLOWED sentence.
//      Then the graph: apigw1 and esb1 are each ONE box (#468).
//
// In development and product mode alike (GET /admin-api/mode); the KDC
// enforces the delegation policy in both. The entries are left behind; a
// rerun reconciles them and rotates each tier's key.
//
// OWNED HERE (local: true): the chain is this repository's own scenario.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const kit = require("./kerberos_chain_kit.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_chain_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const TAG = "krbdel";
const DELEGATES = { semantics: ["delegation"], default: "delegation",
                    delegates: true };
const PLAN = { webapp1: DELEGATES, apigw1: DELEGATES, esb1: DELEGATES };

// THE FIRST STEP: how bob's identity reaches webapp1 — his own credential,
// proved to the KDC, and the ticket it buys handed over in an AP-REQ.
async function signIn(K, cast) {
  log.debug("Entering signIn().");
  log.info("=== bob authenticates to the KDC and hands webapp1 a ticket ===");
  await kit.personKeys(K, cast);
  const own = await kit.userTicketTo(K, cast, cast.webapp);
  kit.assertReply(K, cast, own, cast.webapp, true,
                  "bob's own ticket to webapp1");
  const held = await kit.accept(K, cast, cast.webapp, own);
  kit.assertDelegationInfo(held, cast.webapp, null);
  log.debug("Leaving signIn().");
  return held;
}

async function test() {
  log.debug("Entering test().");
  const K = await kit.kdcContext();
  const cast = kit.castFor(K, TAG);
  await kit.provisionCast(K, cast, PLAN);
  const baselineAt = await kit.registerBaseline(K.base);

  let held = await signIn(K, cast);
  const transited = [];
  for (const tier of [cast.webapp, cast.gateway, cast.esb]) {
    log.info("=== " + tier.stem + " delegates to " + tier.next.stem +
             " (S4U2Proxy) ===");
    assert.ok(held.flagNames.indexOf("forwardable") >= 0, tier.stem +
              " holds evidence that is not forwardable: " +
              held.flagNames.join(","));
    const r = await kit.s4u2proxy(K, cast, tier, held.ticket);
    kit.assertReply(K, cast, r, tier.next, !!tier.next.next,
                    tier.stem + "'s ticket to " + tier.next.stem);
    held = await kit.accept(K, cast, tier.next, r);
    transited.push(tier);
    kit.assertDelegationInfo(held, tier.next, transited.slice());
  }
  log.info("[target] sp1 holds a ticket for " + cast.principal + " that " +
           "records every service it was delegated through, webapp1 first.");

  log.info("=== the register and the picture ===");
  const seen = await kit.registerSince(K, cast, baselineAt);
  for (const tier of [cast.webapp, cast.gateway, cast.esb]) {
    kit.assertAct(K, cast,
      kit.actFor(cast, seen.acts, "krb5-s4u2proxy-classic", tier.next), {
        type: "krb5-s4u2proxy-classic", mode: "delegation",
        requester: tier, target: tier.next, semantics: "delegation",
        classic: true });
  }
  kit.assertGraphIsAChain(cast, seen.graph, cast.webapp, cast.gateway);
  kit.assertGraphIsAChain(cast, seen.graph, cast.gateway, cast.esb);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_chain_delegation")
  .description("A four-tier Kerberos constrained-delegation chain: bob's " +
    "own ticket to webapp1, then S4U2Proxy to apigw1, esb1 and sp1, with " +
    "the PAC's S4U_DELEGATION_INFO, the register and the picture.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
