// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_risk_initiation.js
//
// ===========================================================================
// AN IDENTITY-PROVIDER-INITIATED SIGN-IN STEPPED UP ON RISK, OVER THE WIRE
// (#715, #36; #444 D12, phase 7).
//
// `tests/wsfed_initiation.js` g and `tests/saml_initiation.js` D put a
// session at MEDIUM risk by writing its `risk` in process. A RUNNING
// service puts it there itself when its own scoring says so: in a
// development realm, `risk.assessSignIns` on with `risk.mediumScorePercent`
// 1 (any score at all is MEDIUM), `risk.highScorePercent` out of reach and
// `risk.minimumHistory` 1, a person's third password sign-in is scored
// MEDIUM (the first is UNSCORED — no history), while development only
// OBSERVES the level. Then `risk.enforceInDevelopment` goes on, and the
// identity-provider-initiated doors meet a one-factor session at MEDIUM:
//
//   W1. WS-Federation's `/wsfed/initiate/{rp}`: sent to sign in again with
//       a second factor demanded (303 to the screen, STS-RISK-0017);
//   W2. the same link carrying the one-trip marker and still denied:
//       refused 403 (STS-WSFED-0029), not sent round again;
//   W3. the relying party's own wsignin1.0: refused on risk 403
//       (STS-WSFED-0011), no step-up;
//   S1. SAML 2.0's `/saml2/unsolicited`: stepped up (303, STS-RISK-0017);
//   S2. back from that trip still unmet (`reprompted=1`): RequestDenied on
//       the POST form (STS-SAML-0112), not sent round again;
//   S3. SAML 1.1's Browser/POST start: stepped up too (STS-RISK-0017);
//   S4. back at the held flow (its `fid`, read off the screen's Cancel
//       answer with the cancellation taken off) still unmet: refused on a
//       page 403 (STS-SAML-0115), no SAMLResponse.
//
// NOT HERE: the in-process files' completed step-ups (D3, D6: a second
// factor given at the screen), and their product passes, where the
// policy's Deny is kept with no setting; the pending record's `forceMfa`
// and `returnTo` (internal state — S4's held flow is its outcome).
//
// OWNED HERE (local: true). Its realm is removed only on a private probe.
// ===========================================================================

const assert = require("assert");
const authnSignin = require("./authn_signin");
const K = require("./oauth_wire_kit.js").kit("sts_risk_initiation");
const S = require("./saml_wire_kit.js").samlKit(K);

const log = K.log;
const RP = "urn:sri:" + K.STAMP;
const REPLY = "https://sri-" + K.STAMP + ".example.test/wsfed";
const SP = "https://sri-sp-" + K.STAMP + ".example.test/sp";
const SP_ACS = "https://sri-sp-" + K.STAMP + ".example.test/acs";
const RP11 = "https://sri-rp-" + K.STAMP + ".example.test/rp";
const SHIRE = "https://sri-rp-" + K.STAMP + ".example.test/shire";
const PERSON = "sri-alice";
const PASSWORD = "Sri-Passw0rd!-" + K.rand(3);
let D = null;

async function signIn() {
  log.debug("Entering signIn().");
  const b = K.browser();
  const first = await b.go(K.rb(D) + "/wsfed?" + new URLSearchParams({
    wa: "wsignin1.0", wtrealm: RP, wreply: REPLY }).toString());
  assert.ok(K.toSignIn(first), K.shown(first));
  await authnSignin.signInWithJar(K.rb(D), K.base + first.location,
    { action: "login", username: PERSON, password: PASSWORD }, b.jar);
  log.debug("Leaving signIn().");
  return b;
}

async function riskLevel() {
  log.debug("Entering riskLevel().");
  const r = await K.send(K.rb(D) + "/admin-api/users?user=" + PERSON);
  log.debug("Leaving riskLevel().");
  return String(((r.json || {}).risk || {}).level || "");
}

async function setUp() {
  log.debug("Entering setUp().");
  D = await K.realm("sri", "development");
  await K.person(D, PERSON, PASSWORD);
  await K.set(D, "wsfed.idpInitiatedSso", true);
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: RP,
    name: RP, protocols: ["wsfed"], fields: { wsfedRealm: [RP],
      wsfedReplyUrl: [REPLY], wsfedIdpInitiatedSso: "TRUE" } }, "the RP");
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: SP,
    name: SP, protocols: ["saml2"], fields: { samlEntityId: [SP],
      samlAssertionConsumerService: [SP_ACS],
      saml2IdpInitiatedSso: "TRUE" } }, "the SP");
  await K.ok(K.rb(D) + "/admin-api/applications/create", { identifier: RP11,
    name: RP11, protocols: ["saml11"], fields: { samlEntityId: [RP11],
      samlAssertionConsumerService: [SHIRE],
      saml11IdpInitiatedSso: "TRUE" } }, "the SAML 1.1 RP");
  for (const [key, value] of [["risk.assessSignIns", true],
                              ["risk.mediumScorePercent", 1],
                              ["risk.highScorePercent", 1000000],
                              ["risk.minimumHistory", 1]]) {
    await K.set(D, key, value);
  }
  // Two sign-ins of history, then the one the conversation holds.
  await signIn();
  await K.sleep(800);
  await signIn();
  await K.sleep(800);
  const b = await signIn();
  let level = "";
  for (let i = 0; i < 20 && level !== "MEDIUM"; i += 1) {
    await K.sleep(250);
    level = await riskLevel();
  }
  assert.strictEqual(level, "MEDIUM", "the person's risk is " + level);
  await K.set(D, "risk.enforceInDevelopment", true);
  log.debug("Leaving setUp().");
  return b;
}

async function test() {
  log.debug("Entering test().");
  const b = await setUp();
  const initiate = K.rb(D) + "/wsfed/initiate/" + encodeURIComponent(RP);
  let got = await K.coded(D, "STS-RISK-0017", function () {
    return b.go(initiate + "?wctx=risk");
  });
  K.check("W1. WS-Federation's initiation link on a session at MEDIUM is " +
          "sent to sign in again, a second factor demanded (STS-RISK-0017)",
  function () {
    assert.strictEqual(got.answer.status, 303, K.shown(got.answer));
    assert.ok(/\/authn\/login/.test(got.answer.location));
    assert.ok(got.rose >= 1);
  });
  got = await K.coded(D, "STS-WSFED-0029", function () {
    return b.go(initiate + "?wctx=risk&sts_risk_retry=1");
  });
  K.check("W2. the link carrying the one-trip marker and still denied is " +
          "refused 403 (STS-WSFED-0029), not sent round again", function () {
    assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  got = await K.coded(D, "STS-WSFED-0011", function () {
    return b.go(K.rb(D) + "/wsfed?" + new URLSearchParams({
      wa: "wsignin1.0", wtrealm: RP, wreply: REPLY }).toString());
  });
  K.check("W3. the relying party's own wsignin1.0 is refused on risk 403 " +
          "(STS-WSFED-0011), no step-up", function () {
    assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
    assert.ok(got.rose >= 1);
  });
  const unsolicited = function (extra) {
    log.debug("Entering unsolicited().");
    log.debug("Leaving unsolicited().");
    return K.rb(D) + "/saml2/unsolicited?" + new URLSearchParams(
      Object.assign({ providerId: SP, shire: SP_ACS,
                      target: "rs-" + K.STAMP }, extra || {})).toString();
  };
  got = await K.coded(D, "STS-RISK-0017", function () {
    return b.go(unsolicited());
  });
  K.check("S1. SAML 2.0: an unsolicited Response for a session at MEDIUM " +
          "is STEPPED UP to the screen (STS-RISK-0017), not refused",
  function () {
    assert.strictEqual(got.answer.status, 303, K.shown(got.answer));
    assert.ok(/\/authn\/login/.test(got.answer.location));
    assert.ok(got.rose >= 1);
  });
  got = await K.coded(D, "STS-SAML-0112", function () {
    return b.go(unsolicited({ reprompted: "1" }));
  });
  const xml = S.messageOf(got.answer.text) || "";
  K.check("S2. back from that trip still unmet: RequestDenied, " +
          "STS-SAML-0112, and not sent round again", function () {
    assert.strictEqual(got.answer.status, 200, K.shown(got.answer));
    assert.ok(/status:RequestDenied"/.test(xml), xml.slice(0, 300));
    assert.ok(!/InResponseTo=/.test(xml));
    assert.ok(got.rose >= 1);
  });
  const sso11 = K.rb(D) + "/saml11/sso?" + new URLSearchParams({
    providerId: RP11, shire: SHIRE, TARGET: "https://sri.example.test/app" })
    .toString();
  got = await K.coded(D, "STS-RISK-0017", function () {
    return b.go(sso11);
  });
  K.check("S3. SAML 1.1: a session at MEDIUM is stepped up too " +
          "(STS-RISK-0017)", function () {
    assert.strictEqual(got.answer.status, 303, K.shown(got.answer));
    assert.ok(/\/authn\/login/.test(got.answer.location));
    assert.ok(got.rose >= 1);
  });
  // The held flow the trip returns to, read off the screen's Cancel answer
  // with the cancellation taken off.
  const at = K.base + got.answer.location;
  const opened = await authnSignin.screen(K.rb(D), at,
                                          { cookie: S.cookieOf(b) });
  S.keep(b, opened.setCookies);
  const cancelled = await authnSignin.submit(K.rb(D), at,
    { action: "cancel" }, { screen: opened, cookie: S.cookieOf(b) });
  S.keep(b, cancelled.setCookies);
  const back = new URL(cancelled.location || "/", K.base);
  back.searchParams.delete("authn_error");
  back.searchParams.delete("authn_error_description");
  got = await K.coded(D, "STS-SAML-0115", function () {
    return b.go(back.toString());
  });
  K.check("S4. back at the held flow still unmet: refused on a page 403 " +
          "(STS-SAML-0115), no SAMLResponse", function () {
    assert.ok(/[?&]fid=/.test(back.search), back.toString());
    assert.strictEqual(got.answer.status, 403, K.shown(got.answer));
    assert.ok(!/name="SAMLResponse"/.test(got.answer.text));
    assert.ok(got.rose >= 1);
  });
  log.debug("Leaving test().");
}

K.main(test, 7);
