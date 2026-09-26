"use strict";
//
// File: sts_oid4vci_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: OPENID4VCI 1.0 ISSUER (#187,
// 2026-09-24), on the three containers `sts_fapi_conformance.js` (#176)
// brought into the stack. The suite plays the WALLET.
//
//   * `oid4vci-1_0-issuer-test-plan` under its `vci` profile (FAPI 2.0's
//     Security Profile beneath the issuer: PAR, PKCE, DPoP, private_key_jwt,
//     which is why the realm runs `oauth2.fapi=2-security`), SD-JWT VC,
//     three ways in: the wallet starting the authorization code flow itself,
//     this issuer starting it with a Credential Offer, and a pre-authorized
//     code with a transaction code.
//   * `oid4vci-1_0-issuer-haip-test-plan`, the High Assurance
//     Interoperability Profile's issuer plan, wallet-initiated.
//
// An issuer-initiated module waits for the OFFER, and a pre-authorized one
// then for the TRANSACTION CODE the person would type. This job is that
// operator (`onWaiting`): it asks this realm's own offer page for an offer
// — the realm's `oid4vci.walletUrl` is the suite's offer endpoint, so the
// page's link IS the delivery — and reads the transaction code off the same
// page, as the person would.
//
// OWNED HERE (local: true): this repository's credential issuer.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const oidf = require("./conformance_suite.js");

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
var log = bunyan.createLogger({ name: "sts_oid4vci_conformance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 10);
const PASSWORD = "Conf-Passw0rd!-" + String(Date.now()).slice(-6);
// The SD-JWT VC configuration this issuer publishes (`oid4vc/vc_configs.ts`).
const CONFIGURATION_ID = "IdentityCredential";
const CONFIGURATION_SCOPE = "identity_credential";

const VCI = { fapi_profile: "vci", credential_format: "sd_jwt_vc",
              authorization_request_type: "simple",
              client_auth_type: "private_key_jwt",
              fapi_request_method: "unsigned",
              fapi_response_mode: "plain_response",
              grant_management: "disabled", openid: "plain_oauth",
              sender_constrain: "dpop", vci_credential_encryption: "plain" };

const PLANS = [
  { key: "vci-wallet", name: "oid4vci-1_0-issuer-test-plan",
    variant: Object.assign({ vci_authorization_code_flow_variant:
                               "wallet_initiated",
                             vci_grant_type: "authorization_code" }, VCI) },
  { key: "vci-offer", name: "oid4vci-1_0-issuer-test-plan",
    variant: Object.assign({ vci_authorization_code_flow_variant:
                               "issuer_initiated",
                             vci_grant_type: "authorization_code" }, VCI),
    offer: "same-device" },
  { key: "vci-preauth", name: "oid4vci-1_0-issuer-test-plan",
    variant: Object.assign({ vci_authorization_code_flow_variant:
                               "issuer_initiated",
                             vci_grant_type: "pre_authorization_code" }, VCI),
    offer: "cross-device" },
  // HAIP's issuer plan authenticates every wallet with OAuth 2.0
  // Attestation-Based Client Authentication (`attest_jwt_client_auth`,
  // draft-ietf-oauth-attestation-based-client-auth), which this
  // authorization server does not implement: every module stops at its
  // first token request. It is listed NOT RUN so the gap is in the run's
  // own output, and runs once the method exists (rcbj/iya-sts#229).
  { key: "haip", name: "oid4vci-1_0-issuer-haip-test-plan", haip: true,
    pending: "this authorization server does not implement " +
             "attest_jwt_client_auth, which HAIP requires of every " +
             "wallet (#229)",
    variant: { credential_format: "sd_jwt_vc", grant_management: "disabled",
               vci_authorization_code_flow_variant: "wallet_initiated" } }
];

const EXPECTED = {};
// Conditions whose WARNING this service keeps, and why — the same sentences
// as `oauth-oidc/CLAUDE.md` 3bk.
const KNOWN_WARNINGS = {
  WarnOnUnusableJwksKeys: "the realm's JWKS carries post-quantum keys " +
    "(kty AKP) the suite cannot parse; rcbj (2026-09-24): PQC support " +
    "matters more than a clean run (3bg)",
  // OpenID4VCI 1.0 Appendix A.1.3 defines ldp_vc; the suite's list of
  // formats it can test does not include it.
  VCIValidateFormatOfCredentialConfigurationsInMetadata: "the issuer also " +
    "publishes ldp_vc configurations (OpenID4VCI 1.0 Appendix A.1.3), a " +
    "format the suite does not test"
};
// FAILUREs that are the suite's and not this service's, each argued.
const KNOWN_FAILURES = {
  // The post-quantum JWS algorithms a key proof may be signed with, and the
  // AKP keys in the realm's JWKS: the suite's JWS table has ML-DSA but not
  // SLH-DSA or the composite algorithms, and its JOSE library cannot parse
  // an AKP key at all. rcbj's decision on #176: PQC support over a clean
  // run.
  VCIValidateProofSigningAlgValuesSupported: "the suite's JWS algorithm " +
    "table lacks SLH-DSA and the composite ML-DSA algorithms",
  ValidateServerJWKs: "the suite's JOSE library cannot parse the realm's " +
    "post-quantum (kty AKP) keys",
  // Outside HAIP the suite verifies a Token Status List's signature only
  // with a `jwk` in its header or keys it already holds, and this realm's
  // names its key as every token here does, by `kid` and an `x5u` to the
  // certificate chain — both of which draft-ietf-oauth-status-list allows.
  // A `jwk` in the header would be a key the token vouches for itself.
  VerifyStatusListTokenSignatureUsingEmbeddedJwk: "the suite resolves a " +
    "status list token's key only from a header jwk, and this realm names " +
    "it by kid and x5u"
};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const alias = "iya-" + plan.key + "-" + TAG;
  const offerEndpoint = oidf.SUITE + "test/a/" + alias + "/credential_offer";
  const id = ("vci-" + plan.key + "-" + TAG).slice(0, 31).replace(/-+$/, "");
  // A key attester of the suite's, made here: the suite signs key
  // attestations with it, and the realm believes them
  // (`oid4vci.keyAttestationTrustedCertificates`).
  const attester = await oidf.selfSignedKey("conformance key attester " +
                                            TAG);
  const settings = [
    ["oid4vci.keyAttestationTrustedCertificates", attester.pem],
    ["oauth2.fapi", "2-security"], ["oauth2.openRegistration", true],
    ["oid4vci.walletUrl", offerEndpoint],
    ["oid4vci.walletIssuancePath", ""],
    ["federation.outboundCaFile", oidf.suiteCaFile()]];
  // HAIP: every wallet authenticates with OAuth 2.0 Attestation-Based
  // Client Authentication (#229). The CLIENT attester is a leaf a CA made
  // here issued — HAIP 4.4.1 refuses a self-signed one — and the realm
  // trusts the CA, which is never in the x5c the suite sends; FAPI 2.0
  // accepts the method only with oauth2.fapiAllowClientAttestation.
  let clientAttester = null;
  if (plan.haip) {
    clientAttester = await oidf.caAndLeaf("conformance client attester " +
                                          TAG);
    settings.push(["oauth2.clientAttestationTrustAnchors",
                   clientAttester.caPem],
                  ["oauth2.fapiAllowClientAttestation", true]);
  }
  const realm = await oidf.makeRealm(root, id, "Conformance " + plan.name,
                                     settings);
  const person = names.usernameFor("conf-" + plan.key);
  await oidf.makePerson(realm.api, person, PASSWORD);
  const redirect = oidf.SUITE + "test/a/" + alias + "/callback";
  const clients = [];
  for (let n = 1; n <= 2; n++) {
    const keys = oidf.keyPair("conf-" + plan.key + "-" + n);
    const metadata = {
      // The suite sends the second client's requests to its callback with
      // a query of its own (RFC 6749 section 3.1.2), and exact matching
      // means it is registered that way — the FAPI job's arrangement.
      redirect_uris: [n === 1 ? redirect
                              : redirect + "?dummy1=lorem&dummy2=ipsum"],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: keys.publicJwks,
      grant_types: ["authorization_code", "refresh_token",
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"],
      response_types: ["code"],
      scope: CONFIGURATION_SCOPE,
      client_name: "conformance wallet " + plan.key + " " + n };
    if (plan.haip) {
      // No key of its own: the attestation names the client instance key,
      // and the suite sends the PoP and DPoP beside it (normal mode).
      metadata.token_endpoint_auth_method = "attest_jwt_client_auth";
      delete metadata.token_endpoint_auth_signing_alg;
      delete metadata.jwks;
    }
    const registered = await oidf.send(realm.base + "/oauth2/register", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(metadata) });
    assert.strictEqual(registered.status, 201, plan.key + " client " + n +
                       ": " + registered.raw.slice(0, 400));
    const client = { client_id: registered.body.client_id,
                     scope: CONFIGURATION_SCOPE, dpop_signing_alg: "ES256" };
    if (!plan.haip) {
      client.jwks = keys.privateJwks;
    }
    clients.push(client);
  }
  const configuration = {
    alias: alias,
    description: "iya-sts " + plan.name + " " + STAMP,
    server: { allow_unexpected_metadata_fields: oidf.EXTENSION_METADATA },
    vci: { credential_issuer_url: realm.base,
           credential_configuration_id: CONFIGURATION_ID,
           // This issuer's own two members (`issuer_did`, and
           // `issuer_identifier` per configuration: which identifier a
           // configuration's credentials carry, docs/oid4vci.md), and the
           // members of its ldp_vc configurations (Appendix A.1.2), a
           // format the suite's schema does not know.
           allow_unexpected_credential_issuer_metadata_fields: [
             "issuer_did", "issuer_identifier", "credential_definition",
             "credential_signing_alg_values_supported"] },
    client_attestation: Object.assign(
      { key_attestation_jwks: { keys: [attester.jwk] } },
      clientAttester ? {
        attester_jwks: { keys: [clientAttester.jwk] },
        issuer: "https://attester.conformance.test/" + TAG } : {}),
    client: clients[0],
    client2: clients[1],
    browser: [{
      match: realm.base + "/oauth2/authorize*",
      tasks: [
        { task: "Sign in", optional: true,
          match: realm.base + "/authn/login*",
          commands: [["text", "id", "username", person, "optional"],
                     ["text", "id", "password", PASSWORD, "optional"],
                     ["click", "id", "kc-login"]] },
        { task: "Consent", optional: true,
          match: realm.base + "/oauth2/consent*",
          commands: [["click", "id", "consent-allow"]] },
        { task: "Error page", optional: true,
          match: realm.base + "/oauth2/authorize*",
          commands: [["wait", "xpath", "//body", 10, ".*",
                      "update-image-placeholder-optional"]] },
        { task: "Verify complete", optional: true,
          match: oidf.SUITE + "test/*/callback*",
          commands: [["wait", "id", "submission_complete", 10]] }
      ]
    }]
  };
  log.debug("Leaving prepare().");
  return { realm: realm, person: person, configuration: configuration };
}

// ---------------------------------------------------------------------------
// THE ISSUER'S OPERATOR (see the header). The offer page answers a
// same-device offer with a redirect to the wallet — the suite — and a
// cross-device one with a page carrying the wallet link and the
// transaction code; either way this job follows the link, and hands the
// suite the code when it asks for one.
// ---------------------------------------------------------------------------
function operatorFor(plan, prepared) {
  log.debug("Entering operatorFor(). " + plan.key);
  // What has been served, per module: how many offers and codes. The suite
  // logs a VCIWaitForCredentialOffer or VCIWaitForTxCode each time it
  // starts waiting for one, and a multiple-clients module waits for an
  // offer per client, so the count, not a flag, says whether it is owed.
  const served = {};
  log.debug("Leaving operatorFor().");
  return async function (id) {
    log.debug("Entering the offer operator. " + id);
    const mine = served[id] || (served[id] = { offers: 0, codes: 0,
                                               txCode: "" });
    const logs = (await oidf.suite("GET", "api/log/" + id)).body || [];
    const waits = function (src) {
      return logs.filter(function (e) {
        return e.src === src;
      }).length;
    };
    if (waits("VCIWaitForTxCode") > mine.codes && mine.txCode) {
      const wants = await oidf.exposed(id);
      const url = String(wants.tx_code_endpoint || "")
        .replace("your_tx_code", encodeURIComponent(mine.txCode));
      if (url.indexOf(oidf.SUITE) === 0) {
        mine.codes += 1;
        const r = await oidf.suite("GET", url.slice(oidf.SUITE.length));
        log.info("  handed the suite the transaction code: " + r.status);
      }
      log.debug("Leaving the offer operator. tx_code.");
      return;
    }
    if (!plan.offer || waits("VCIWaitForCredentialOffer") <= mine.offers) {
      log.debug("Leaving the offer operator. Nothing owed.");
      return;
    }
    mine.offers += 1;
    const page = await oidf.send(prepared.realm.base + "/issuer/offer?" +
      new URLSearchParams({ mode: plan.offer, by: "reference",
                            credential_configuration_ids:
                              CONFIGURATION_ID }).toString());
    let link = page.headers.get("location") || "";
    if (!link) {
      // The page's own two ids: the wallet link, and the code the person
      // would read off it (`oid4vc/vc_offers.ts`, renderOfferQrPage()).
      const decoded = page.raw.replace(/&amp;/g, "&");
      link = (decoded.match(/id="open_in_wallet" href="([^"]+)"/) ||
              [])[1] || "";
      mine.txCode = (decoded.match(/id="tx_code">([^<]*)</) || [])[1] || "";
    }
    assert.ok(link.indexOf(oidf.SUITE) === 0, "the offer page named no link " +
              "to the suite: " + page.status + " " + page.raw.slice(0, 300));
    const r = await oidf.suite("GET", link.slice(oidf.SUITE.length));
    log.info("  delivered a " + plan.offer + " credential offer: " + r.status +
             (mine.txCode ? " (a transaction code is held)" : ""));
    log.debug("Leaving the offer operator. Offer.");
  };
}

async function test() {
  log.debug("Entering test().");
  await registry.isProduct(root);
  await oidf.waitForSuite();
  const unexpected = [];
  for (const plan of PLANS) {
    if (!oidf.selected(plan.key)) {
      continue;
    }
    if (plan.pending) {
      log.warn("=== " + plan.name + " (" + plan.key + "): NOT RUN — " +
               plan.pending + " ===");
      continue;
    }
    log.info("=== " + plan.name + " " + JSON.stringify(plan.variant) +
             " (" + plan.key + ") ===");
    let ran = null;
    try {
      const prepared = await prepare(plan);
      ran = await oidf.runPlan(plan.name, plan.variant,
                               prepared.configuration, plan.key,
                               operatorFor(plan, prepared));
    } catch (e) {
      log.error("Caught in test(): " + plan.key + ": " +
                ((e && e.message) || e));
      unexpected.push(plan.key + " could not run: " +
                      ((e && e.message) || e));
      continue;
    }
    const judged = oidf.judge(plan.key, ran, EXPECTED, KNOWN_WARNINGS,
                              KNOWN_FAILURES);
    log.info("  " + plan.key + ": " + JSON.stringify(judged.counts) +
             ", plan " + oidf.SUITE + "plan-detail.html?plan=" + ran.planId);
    judged.unexplained.forEach(function (line) {
      unexpected.push(line);
    });
  }
  if (unexpected.length) {
    log.error("Unexplained:\n  " + unexpected.join("\n  "));
  }
  check("every module passed or is argued, and every warning is known",
        function () {
          assert.strictEqual(unexpected.length, 0, unexpected.join("\n"));
        });
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The OpenID Foundation conformance suite's OpenID4VCI " +
    "issuer plans (#187), against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
