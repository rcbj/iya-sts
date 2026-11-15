// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_interaction_codes.js
//
// ===========================================================================
// WHO MUST BE ASKED FOR A GNAP GRANT, HOW STRONGLY SIGNED IN, AND APPROVAL
// BY AN ABSENT OWNER — EACH REFUSAL BY ITS CODE, OVER THE WIRE (#444 D12
// phase 8; #432 phase 6, #738).
//
// `tests/gnap_interaction.js` drives `createGrant()` with a stubbed caller
// and moves the clock; `sts_gnap_interaction.js` asks the wire by the GNAP
// error each answers. This job adds the code each records on
// `/admin-api/audit`, in a development realm:
//
//   B. a grant needing its owner from a client that offered no interaction
//      (STS-GNAP-0113); a client trusted to skip asking for an `always`
//      type with no interaction (0892); a right needing an acr with no
//      interaction (0893);
//   E. the step-up: back from the sign-in still short of the type's acr
//      (STS-GNAP-0899), and of `interact.acr` phrh (0905);
//   F. approval by an absent owner (`gnap.ownerApproval`): a poll inside
//      the wait (too_fast, STS-GNAP-0133); a name nobody holds
//      (unknown_user, 0901); the owner's pending cap
//      (`gnap.ownerApprovalMaxPending` 1, 0897); a request answered twice
//      on `/portal/ciba` (STS-PORTAL-0243); a right needing mfa approved on
//      a password session (STS-PORTAL-0244); a request left unanswered past
//      `gnap.ownerApprovalLifetimeS` 60 (0894, a minute's wait).
//
// (d), with the reason: STS-GNAP-0890 and 0891 are the ISSUE stage dropping
// a right the earlier stages already refuse (an `always` right approved by
// skipping is 0892 before it, an acr unmet is the step-up's 0899); the
// in-process file reaches them only by calling the issue stage directly.
// A's verdict table and E's per-right demand are the policy's return
// values (their outcomes are the refusals here).
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_interaction_codes");
const G = require("./gnap_wire_kit.js").gnapKit(K);
const portalSignin = require("./portal_signin.js");

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Int-Passw0rd!-" + String(Date.now()).slice(-6);
const NEVER = "gic-never";
const ALWAYS = "gic-always";
const DFLT = "gic-default";
const MFA = "gic-mfa";

let realm = null;
let h = null;
let OWNER = "";

async function coded(code, what, act, verdict) {
  log.debug("Entering coded(). " + code);
  const c = await K.coded(realm, code, act);
  check(what + " (" + code + ")", function () {
    verdict(c.answer);
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
  });
  log.debug("Leaving coded().");
  return c.answer;
}

function errorIs(r, error) {
  log.debug("Entering errorIs().");
  assert.strictEqual(G.errorOf(r), error, r.status + " " +
                     String(r.text).slice(0, 400));
  assert.strictEqual(r.headers["cache-control"], "no-store");
  log.debug("Leaving errorIs().");
}

async function skipping(trusted, plain) {
  log.debug("Entering skipping().");
  log.info("=== B. who must be asked ===");
  await coded("STS-GNAP-0113", "B1. a grant that needs its owner, from a " +
              "client offering no interaction, is refused", function () {
    return G.direct(h, plain, [{ type: DFLT, actions: ["read"] }]);
  }, function (r) {
    errorIs(r, "invalid_interaction");
  });
  await coded("STS-GNAP-0892", "B2. a client trusted to skip, asking for " +
              "an always type with no interaction, is refused", function () {
    return G.direct(h, trusted, [{ type: ALWAYS }]);
  }, function (r) {
    errorIs(r, "invalid_interaction");
  });
  await coded("STS-GNAP-0893", "B3. a right needing an acr, with no " +
              "interaction, is refused", function () {
    return G.direct(h, trusted, [{ type: MFA }]);
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  log.debug("Leaving skipping().");
}

// A grant for `access` (with `interact` extra), its approval page reached
// by a password session, and the client back from the sign-in still short.
async function shortStep(c, access, interactExtra) {
  log.debug("Entering shortStep().");
  const sent = h.grantBody(c, { access_token: { access: access } });
  Object.assign(sent.interact, interactExtra || {});
  let r = await c.send("POST", h.GRANT, { json: sent });
  assert.strictEqual(r.status, 200, r.text);
  const pending = r.json;
  // A password session first, through an ordinary approval, so the
  // request below meets a session that is short rather than none.
  const b = h.browser();
  await h.redirectGrant(c, OWNER, { access_token: { access: [
    { type: DFLT, actions: ["read"] }] } }, { browser: b });
  // By hand rather than through reachApproval(), which would answer the
  // sign-in screen the step-up sends the browser to.
  r = await b.go("GET", pending.interact.redirect);
  assert.ok(r.status === 303 && /\/gnap\/approve\//.test(r.location),
            "the start URI forwards to the approval page: " + r.status);
  const approve = r.location;
  r = await b.go("GET", approve);
  assert.ok(r.status === 303 && /\/authn\/login/.test(r.location),
            "a password session is sent to sign in again: " + r.status +
            " " + r.location);
  const approval = { approve: approve };
  r = await b.go("GET", approval.approve + "?step_up_honoured=1");
  const done = h.finishParams(r.location, r);
  r = await c.send("POST", pending.continue.uri, {
    token: pending.continue.access_token.value,
    json: { interact_ref: done.ref } });
  log.debug("Leaving shortStep().");
  return r;
}

async function stepUp(plain) {
  log.debug("Entering stepUp().");
  log.info("=== E. the step-up ===");
  await coded("STS-GNAP-0899", "E1. back from the sign-in still short of " +
              "the type's acr, the request is denied", function () {
    return shortStep(plain, [{ type: MFA }]);
  }, function (r) {
    errorIs(r, "request_denied");
  });
  await coded("STS-GNAP-0905", "E2. back from the sign-in still short of " +
              "interact.acr phrh, the request is denied", function () {
    return shortStep(plain, [{ type: NEVER }], { acr: ["phrh"] });
  }, function (r) {
    errorIs(r, "request_denied");
  });
  log.debug("Leaving stepUp().");
}

async function absentOwner() {
  log.debug("Entering absentOwner().");
  log.info("=== F. approval by an absent owner ===");
  await K.set(realm, "gnap.ownerApproval", true);
  await K.set(realm, "gnap.ownerApprovalLifetimeS", 60);
  const naming = function (who) {
    log.debug("Entering naming().");
    log.debug("Leaving naming().");
    return { user: { sub_ids: [{ format: "email",
                                 email: who + "@gnap.test" }] } };
  };
  const absent = G.client();
  await coded("STS-GNAP-0901", "F1. a waiting grant naming a person the " +
              "directory does not hold is unknown_user", function () {
    return G.direct(h, absent, [{ type: DFLT, actions: ["read"] }],
                    naming("gic-nobody-" + K.STAMP));
  }, function (r) {
    errorIs(r, "unknown_user");
  });
  let r = await G.direct(h, absent, [{ type: MFA }], naming(OWNER));
  assert.strictEqual(r.status, 200, r.text);
  assert.ok(r.json.continue && !r.json.access_token, r.text);
  const waiting = r.json.continue;
  await coded("STS-GNAP-0133", "F2. a poll inside the wait is too_fast",
              function () {
    return absent.send("POST", waiting.uri,
                       { token: waiting.access_token.value });
  }, function (one) {
    errorIs(one, "too_fast");
  });
  await K.set(realm, "gnap.ownerApprovalMaxPending", 1);
  const second = G.client();
  await coded("STS-GNAP-0897", "F3. a second request waiting for the same " +
              "owner past gnap.ownerApprovalMaxPending 1 is refused",
              function () {
    return G.direct(h, second, [{ type: NEVER }], naming(OWNER));
  }, function (one) {
    assert.ok(one.status >= 400, one.text);
  });
  await K.unset(realm, "gnap.ownerApprovalMaxPending");
  const portal = await portalSignin.signInToThePortal(h.realmBase, OWNER,
    null, { password: PASSWORD });
  // The page's operation answer (the renderers are the image build's).
  const page = await portal.page("/portal/ciba");
  const listed = ((page.json && page.json.gnap) || [])[0] || {};
  assert.ok(listed.id, "the request is listed on the owner's /portal/ciba: " +
            JSON.stringify(page.json).slice(0, 300));
  const m = [null, listed.id];
  await coded("STS-PORTAL-0244", "F4. a right needing mfa approved on the " +
              "portal by a password session is refused", function () {
    return portal.act("/portal/ciba", { action: "gnap-approve", id: m[1],
                                        right: "t0r0" });
  }, function (one) {
    assert.ok(!/Approved/.test(String(one.json && one.json.message)),
              JSON.stringify(one.json).slice(0, 300));
  });
  r = await portal.act("/portal/ciba", { action: "gnap-deny", id: m[1] });
  assert.strictEqual(r.status, 200, JSON.stringify(r.json).slice(0, 300));
  await coded("STS-PORTAL-0243", "F5. a request answered again after it " +
              "was answered is refused", function () {
    return portal.act("/portal/ciba", { action: "gnap-deny", id: m[1] });
  }, function (one) {
    assert.ok(!/Denied/.test(String(one.json && one.json.message)) ||
              one.status >= 400, JSON.stringify(one.json).slice(0, 300));
  });
  const late = G.client();
  r = await G.direct(h, late, [{ type: NEVER }], naming(OWNER));
  assert.strictEqual(r.status, 200, r.text);
  const lateCont = r.json.continue;
  log.info("waiting 62 s for gnap.ownerApprovalLifetimeS 60 to pass");
  await K.sleep(62000);
  await coded("STS-GNAP-0894", "F6. a request its owner left unanswered " +
              "past gnap.ownerApprovalLifetimeS is finalized rejected",
              function () {
    return late.send("POST", lateCont.uri,
                     { token: lateCont.access_token.value });
  }, function (one) {
    assert.ok(one.status >= 400, one.text);
  });
  log.debug("Leaving absentOwner().");
}

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("gic", "development", {}, PASSWORD);
  realm = made.id;
  h = made.h;
  OWNER = "gic-owner-" + K.STAMP;
  await h.ensurePerson(OWNER);
  await G.resourceServer(h, "gic-rs-" + K.STAMP, G.client(),
                         "https://gic-rs.gnap.test/api", [
    { type: NEVER, interaction: "never" },
    { type: ALWAYS, interaction: "always" },
    { type: DFLT, actions: ["read", "delete"], consentActions: ["delete"] },
    { type: MFA, acr: "mfa" }]);
  const trusted = G.client();
  await G.entry(h, "gic-trusted-" + K.STAMP, "gnap-client", trusted,
                { gnapSkipInteraction: "TRUE", gnapFinishUri: [h.FINISH] });
  const plain = G.client();
  await G.entry(h, "gic-plain-" + K.STAMP, "gnap-client", plain,
                { gnapFinishUri: [h.FINISH] });
  await skipping(trusted, plain);
  await stepUp(plain);
  await absentOwner();
  log.debug("Leaving test().");
}

K.main(test, 11);
