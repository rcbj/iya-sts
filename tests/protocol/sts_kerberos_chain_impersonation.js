// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_kerberos_chain_impersonation.js
//
// ---------------------------------------------------------------------------
// A FOUR-TIER KERBEROS IMPERSONATION CHAIN OVER THE WIRE: protocol
// transition, then two S4U2Proxy hops (#486) — the Kerberos equivalent of
// `sts_token_exchange_chain_impersonation.js` (#467) and
// `sts_wstrust_chain_impersonation.js` (#473). `kerberos_chain_kit.js` says
// why this is the mapping:
//
//   bob_end_user-krbimp signs in to webapp1-krbimp by a means that is NOT
//   Kerberos, and webapp1 hands apigw1 his NAME. apigw1 holds no credential
//   of his, so it uses S4U2Self ([MS-SFU] protocol transition): a ticket for
//   bob to itself, FORWARDABLE because its entry allows `impersonation`.
//
//   apigw1 presents that ticket as the evidence of an S4U2Proxy to esb1,
//   and esb1 the ticket it was handed to sp1. Classic constrained
//   delegation: apigw1 names esb1 and esb1 names sp1 on
//   `appAllowedToDelegateTo`, and both allow `delegation` — S4U2Proxy is
//   always asked of the policy as a delegation, whatever made the evidence.
//
// webapp1 makes no Kerberos request, as it makes no exchange in the OAuth
// job: it is where bob signed in, and apigw1 is the first tier to ACT.
//
// WHAT IT ASSERTS, in four layers, because any one of them passes alone:
//
//   1. THE REGISTRY: the four service principals read back — each SPN on
//      its entry, webapp1 and sp1 delegating to nobody and allowing no
//      semantics, apigw1 allowing impersonation and delegation to esb1,
//      esb1 delegation to sp1.
//   2. THE WIRE: every KDC reply decoded — for bob, to the SPN asked for,
//      the nonce echoed — and every ticket FORWARDABLE, sp1's included:
//      each request asked for it and each front end's TGT is forwardable
//      (RFC 4120 3.3.3, #492).
//   3. THE TARGET'S VALIDATION: each tier opens the AP-REQ it is handed with
//      its own key, finds bob, verifies the PAC's server signature, and
//      reads S4U_DELEGATION_INFO ([MS-PAC] 2.9): absent on the S4U2Self
//      ticket (nothing was delegated through anybody yet), transited
//      [apigw1] at esb1 and [apigw1, esb1] at sp1, each `SPN@REALM`, the
//      target its bare SPN (#489). webapp1 is on no list: it never held a
//      Kerberos credential of bob's.
//   4. THE REGISTER AND THE PICTURE: the `krb5-s4u2self` act (mode
//      impersonation, its ticket FORWARDABLE by the issuance policy) and one
//      `krb5-s4u2proxy-classic` act per hop (mode delegation), each policed,
//      for bob, with the policy's ALLOWED sentence in Kerberos's words —
//      S4U2Self or S4U2Proxy, the evidence ticket, the SPN (#490). Then the
//      graph: esb1 is ONE box (#468).
//
// ONE IMPERSONATION ROW, THEN DELEGATION ROWS — AND THAT IS [MS-SFU]'S MODEL
// (#491). The OAuth impersonation chain is impersonation at every hop,
// because a token exchanged with no actor_token carries nothing of the
// chain. Kerberos names the mechanisms: S4U2Self is protocol transition (an
// impersonation) and S4U2Proxy is constrained delegation, whatever made its
// evidence — and its ticket does carry the chain, in S4U_DELEGATION_INFO.
// So the register records apigw1's S4U2Self as impersonation and the two
// S4U2Proxy hops as delegation, and the console says why under the mode.
//
// In development and product mode alike (GET /admin-api/mode); the KDC
// enforces the delegation policy in both. The entries are left behind; a
// rerun reconciles them and rotates each tier's key.
//
// OWNED HERE (local: true): the chain is this repository's own scenario.
// ---------------------------------------------------------------------------

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
var log = bunyan.createLogger({ name: "sts_kerberos_chain_impersonation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const TAG = "krbimp";
const PLAN = {
  apigw1: { semantics: ["impersonation", "delegation"],
            default: "impersonation", delegates: true },
  esb1: { semantics: ["delegation"], default: "delegation", delegates: true }
};

// THE FIRST STEP: how bob's identity reaches apigw1 — his NAME, from a
// sign-in to webapp1 that is not Kerberos, and so no ticket of his at all.
// apigw1 turns the name into a ticket by protocol transition.
async function signIn(K, cast) {
  log.debug("Entering signIn().");
  log.info("=== bob signs in to webapp1 without Kerberos; apigw1 is told " +
           "his name and transitions (S4U2Self) ===");
  const r = await kit.s4u2self(K, cast, cast.gateway);
  kit.assertReply(K, cast, r, cast.gateway, true,
                  "apigw1's S4U2Self ticket for bob");
  const held = await kit.accept(K, cast, cast.gateway, r);
  kit.assertDelegationInfo(held, cast.gateway, null);
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
  for (const tier of [cast.gateway, cast.esb]) {
    log.info("=== " + tier.stem + " delegates to " + tier.next.stem +
             " (S4U2Proxy) ===");
    const r = await kit.s4u2proxy(K, cast, tier, held.ticket);
    kit.assertReply(K, cast, r, tier.next, true,
                    tier.stem + "'s ticket to " + tier.next.stem);
    held = await kit.accept(K, cast, tier.next, r);
    transited.push(tier);
    kit.assertDelegationInfo(held, tier.next, transited.slice());
  }
  log.info("[target] sp1 holds a ticket for " + cast.principal + " that " +
           "records apigw1 and esb1, and not webapp1.");

  log.info("=== the register and the picture ===");
  const seen = await kit.registerSince(K, cast, baselineAt);
  kit.assertAct(K, cast,
    kit.actFor(cast, seen.acts, "krb5-s4u2self", cast.gateway), {
      type: "krb5-s4u2self", mode: "impersonation",
      requester: cast.gateway, target: cast.gateway,
      semantics: "impersonation", classic: false });
  for (const tier of [cast.gateway, cast.esb]) {
    kit.assertAct(K, cast,
      kit.actFor(cast, seen.acts, "krb5-s4u2proxy-classic", tier.next), {
        type: "krb5-s4u2proxy-classic", mode: "delegation",
        requester: tier, target: tier.next, semantics: "delegation",
        classic: true });
  }
  kit.assertGraphIsAChain(cast, seen.graph, cast.gateway, cast.esb);
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_chain_impersonation")
  .description("A four-tier Kerberos impersonation chain: apigw1's " +
    "S4U2Self for a user who signed in to webapp1 without Kerberos, then " +
    "S4U2Proxy to esb1 and sp1, with the PAC's S4U_DELEGATION_INFO, the " +
    "register and the picture.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
