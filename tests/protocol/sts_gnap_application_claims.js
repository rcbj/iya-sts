// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_application_claims.js
//
// ===========================================================================
// AN APPLICATION'S OWN GNAP ACCESS-TOKEN CLAIMS IN A REAL GNAP TOKEN, OVER
// THE WIRE (#444 D12 phase 8; #1250) — `tests/application_claims.js` E,
// the half phase 7 left for phase 8's GNAP flow.
//
// The in-process file asks `configuredJwtClaims('gnap_access_token')` and
// mints a token with the token module. Here the application's rows are
// written through `/admin-api/applications/set-custom-claim`, and the
// claims are read out
// of the access tokens a person's approved grants release, in a
// development realm:
//
//   E0. three rows set on a GNAP client: `tenant`, `plan`, and `uid` =
//       ${username};
//   E1. its token carries the application's rows, ${username} expanded,
//       and no groups or roles were added;
//   E2. another GNAP client's token carries none of them;
//   E3. `access`, `grant_id` and `username` are reserved, and an OAuth
//       application cannot set the GNAP set (STS-REG-0206);
//   E6. the protocol claims win: the token's `sub` and `iss` are the
//       protocol's.
//
// (d), with the reason: E1's "over the realm's" and E2's realm set — the
// REALM's `gnap_access_token` set has no door: `/admin-api/claims/replace`
// takes `access_token` and `id_token` only, and the in-process file calls
// `setClaimSet()`; E4 (a stored row naming `access` ignored) needs a
// row no door writes (the door refuses it, E3); E5 is the console tab's
// model.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_application_claims");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Clm-Passw0rd!-" + String(Date.now()).slice(-6);
const TYPE = "gac-photos";

function claimsOf(value) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(value).split(".")[1], "base64url")
    .toString("utf8"));
}

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("gac", "development", {}, PASSWORD);
  const id = made.id;
  const h = made.h;
  const ADA = "gac-ada-" + K.STAMP;
  await h.ensurePerson(ADA);
  await G.resourceServer(h, "gac-rs-" + K.STAMP, G.client(),
                         "https://gac-rs.gnap.test/api",
                         [{ type: TYPE, actions: ["read"] }]);
  const APP = "gac-gnap-" + K.STAMP;
  const OTHER = "gac-other-" + K.STAMP;
  const mine = G.client();
  const other = G.client();
  await G.entry(h, APP, "gnap-client", mine, { gnapFinishUri: [h.FINISH] });
  await G.entry(h, OTHER, "gnap-client", other,
                { gnapFinishUri: [h.FINISH] });
  const row = function (application, name, value) {
    log.debug("Entering row(). " + name);
    log.debug("Leaving row().");
    return K.send(K.rb(id) + "/admin-api/applications/set-custom-claim",
                  { json: { application: application,
                            set: "gnap_access_token", name: name,
                            value: value } });
  };
  const rows = [await row(APP, "tenant", "app"),
                await row(APP, "plan", "gold"),
                await row(APP, "uid", "${username}")];
  check("E0. three GNAP rows set on the application", function () {
    rows.forEach(function (r) {
      assert.strictEqual(r.status, 200, K.shown(r));
    });
  });
  const ours = await h.redirectGrant(mine, ADA, { access_token: {
    access: [{ type: TYPE, actions: ["read"] }] } });
  const claims = claimsOf(ours.released.access_token.value);
  check("E1. the application's token carries its rows, ${username} " +
        "expanded", function () {
    assert.strictEqual(claims.tenant, "app", JSON.stringify(claims));
    assert.strictEqual(claims.plan, "gold", JSON.stringify(claims));
    assert.strictEqual(claims.uid, ADA, JSON.stringify(claims));
  });
  check("E1b. and groups and roles are not added", function () {
    assert.strictEqual(claims.groups, undefined, JSON.stringify(claims));
    assert.strictEqual(claims.roles, undefined, JSON.stringify(claims));
  });
  const theirs = await h.redirectGrant(other, ADA, { access_token: {
    access: [{ type: TYPE, actions: ["read"] }] } });
  const otherClaims = claimsOf(theirs.released.access_token.value);
  check("E2. another GNAP client's token carries none of them",
        function () {
    assert.strictEqual(otherClaims.tenant, undefined,
                       JSON.stringify(otherClaims));
    assert.strictEqual(otherClaims.plan, undefined);
  });
  const OAUTH = "gac-oauth-" + K.STAMP;
  await K.app(id, OAUTH, { oauthClientId: [OAUTH] },
              { protocols: ["oauth2"] });
  const refusals = [];
  const c = await K.coded(id, "STS-REG-0206", async function () {
    refusals.push(await row(APP, "access", "nope"));
    refusals.push(await row(APP, "grant_id", "nope"));
    refusals.push(await row(APP, "username", "nope"));
    refusals.push(await row(OAUTH, "tenant", "nope"));
  });
  check("E3. access, grant_id and username are reserved, and an OAuth " +
        "application cannot set the GNAP set (STS-REG-0206)", function () {
    refusals.forEach(function (r) {
      assert.strictEqual(r.status, 400, K.shown(r));
    });
    assert.ok(c.rose >= 4, "STS-REG-0206 rose " + c.rose);
  });
  check("E6. the protocol claims are the protocol's: sub the person, iss " +
        "this realm's grant endpoint's issuer", function () {
    assert.ok(/^urn:uuid:/.test(String(claims.sub)), JSON.stringify(claims));
    assert.ok(String(claims.iss || "").indexOf(id) >= 0,
              JSON.stringify(claims));
  });
  log.debug("Leaving test().");
}

K.main(test, 6);
