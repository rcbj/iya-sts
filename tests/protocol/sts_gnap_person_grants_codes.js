// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_person_grants_codes.js
//
// ===========================================================================
// WHAT A CLIENT IS TOLD ABOUT A PERSON, AND HOW A GNAP GRANT ENDS, EACH BY
// ITS CODE, OVER THE WIRE (#444 D12 phase 8; #432 phase 7).
//
// `tests/gnap_person_grants.js` drives the engine's own steps and moves the
// clock; `sts_gnap_core.js` sections 7 and 15 ask the wire by status. This
// job adds the code each records on `/admin-api/audit`, in a development
// realm:
//
//   A. per-client opaque subject identifiers: different for two clients,
//      stable for one; one client's identifier presented by the other as a
//      user reference is refused (STS-GNAP-0070);
//   B. a client trusted to skip asking for subject information with no
//      interaction and no assertion is told nothing (STS-GNAP-0793 is its
//      log line; no audit row, since nothing is refused);
//   C. the grant lifetime (`gnap.grantLifetimeS` 60, a minute's wait): a
//      rotation past it refused (STS-GNAP-0791), a continuation past it
//      refused (0790);
//   G. the per-person revoke naming somebody who is not the grant's owner
//      (STS-GNAP-0792), and the owner's revoke done.
//
// (d), with the reason: A's shared identifier for two clients of one
// registered sector needs a sector document the console's create fetches
// (the in-process file writes the field as a sighting would); D's
// finalization reasons are `sts_gnap_core.js` section 15's; F's
// self-declared marks are the approval page's view (`sts_gnap_core.js`).
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_person_grants_codes");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Per-Passw0rd!-" + String(Date.now()).slice(-6);
const TYPE = "gpg-photos";

let realm = null;
let h = null;

function access() {
  log.debug("Entering access().");
  log.debug("Leaving access().");
  return [{ type: TYPE, actions: ["read"] }];
}

async function opaqueOf(c, who) {
  log.debug("Entering opaqueOf().");
  const done = await h.redirectGrant(c, who, { access_token: { access:
    access() }, subject: { sub_id_formats: ["opaque"] } });
  const ids = ((done.released.subject || {}).sub_ids || []);
  const one = ids.filter(function (s) {
    return s.format === "opaque";
  })[0];
  assert.ok(one && one.id, JSON.stringify(done.released).slice(0, 400));
  log.debug("Leaving opaqueOf().");
  return { id: one.id, done: done };
}

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

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("gpg", "development", {}, PASSWORD);
  realm = made.id;
  h = made.h;
  const ALICE = "gpg-alice-" + K.STAMP;
  const BOB = "gpg-bob-" + K.STAMP;
  await h.ensurePerson(ALICE);
  await h.ensurePerson(BOB);
  await G.resourceServer(h, "gpg-rs-" + K.STAMP, G.client(),
                         "https://gpg-rs.gnap.test/api",
                         [{ type: TYPE, actions: ["read"] }]);
  const c1 = G.client();
  const c2 = G.client();
  const trusted = G.client();
  await G.entry(h, "gpg-one-" + K.STAMP, "gnap-client", c1,
                { gnapFinishUri: [h.FINISH] });
  await G.entry(h, "gpg-two-" + K.STAMP, "gnap-client", c2,
                { gnapFinishUri: [h.FINISH] });
  await G.entry(h, "gpg-trusted-" + K.STAMP, "gnap-client", trusted,
                { gnapFinishUri: [h.FINISH], gnapSkipInteraction: "TRUE" });

  log.info("=== A. per-client opaque identifiers ===");
  const one = await opaqueOf(c1, ALICE);
  const again = await opaqueOf(c1, ALICE);
  const two = await opaqueOf(c2, ALICE);
  check("A1. one person's opaque identifier is stable for one client and " +
        "different for another", function () {
    assert.strictEqual(again.id, one.id);
    assert.notStrictEqual(two.id, one.id);
  });
  await coded("STS-GNAP-0070", "A2. one client's opaque identifier " +
              "presented by another as a user reference is refused",
              function () {
    return c2.send("POST", h.GRANT, { json: h.grantBody(c2, {
      access_token: { access: access() }, user: one.id }) });
  }, function (r) {
    assert.strictEqual(G.errorOf(r), "unknown_user", r.text);
  });
  const own = await c1.send("POST", h.GRANT, { json: h.grantBody(c1, {
    access_token: { access: access() }, user: one.id }) });
  check("A3. and by the client it was issued to it is accepted", function () {
    assert.strictEqual(own.status, 200, own.text);
  });

  log.info("=== B. no authorization, no subject ===");
  // STS-GNAP-0793 is a log line (nothing is refused: the grant is answered
  // with no subject), so the outcome is what is asserted.
  const b1 = await G.direct(h, trusted, access(),
                            { subject: { sub_id_formats: ["opaque"] } });
  check("B1. a trusted client asking for subject information with no " +
        "interaction and no assertion is told nothing about anybody",
        function () {
    assert.ok(!(b1.json && b1.json.subject), b1.text);
  });

  log.info("=== C. the grant lifetime ===");
  await K.set(realm, "gnap.grantLifetimeS", 60);
  // Two grants, one for each refusal: whichever is asked first finalizes
  // its grant as expired.
  const forRotation = await h.redirectGrant(c1, BOB, { access_token: {
    access: access() } });
  const forContinuation = await h.redirectGrant(c1, BOB, { access_token: {
    access: access() } });
  const token = forRotation.released.access_token;
  const cont = forContinuation.released.continue;
  log.info("waiting 62 s for gnap.grantLifetimeS 60 to pass");
  await K.sleep(62000);
  await coded("STS-GNAP-0791", "C1. a rotation after the grant's lifetime " +
              "is refused", function () {
    return c1.send("POST", token.manage.uri,
                   { token: token.manage.access_token.value });
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await coded("STS-GNAP-0790", "C2. a continuation after the grant's " +
              "lifetime is refused", function () {
    return c1.send("POST", cont.uri, { token: cont.access_token.value,
                                       json: {} });
  }, function (r) {
    assert.ok(r.status >= 400, r.text);
  });
  await K.unset(realm, "gnap.grantLifetimeS");

  log.info("=== G. the per-person revoke ===");
  const live = await h.redirectGrant(c2, BOB, { access_token: { access:
    access() } });
  const person = await K.send(h.realmApi + "/users?user=" +
                              encodeURIComponent(BOB));
  const listed = ((person.json && person.json.gnapGrants) || [])
    .filter(function (g) {
      return !g.finalization || !g.finalization.reason;
    });
  assert.ok(listed.length >= 1, JSON.stringify(person.json &&
    person.json.gnapGrants).slice(0, 400));
  const grantId = listed[listed.length - 1].id;
  await coded("STS-GNAP-0792", "G1. the per-person revoke naming somebody " +
              "who is not the grant's owner is refused", function () {
    return K.send(h.realmApi + "/gnap/revoke-grant",
                  { json: { grant: grantId, user: ALICE } });
  }, function (r) {
    assert.strictEqual(r.status, 400, K.shown(r));
  });
  const done = await K.send(h.realmApi + "/gnap/revoke-grant",
                            { json: { grant: grantId, user: BOB } });
  check("G2. and naming the grant's own owner revokes it", function () {
    assert.strictEqual(done.status, 200, K.shown(done));
  });
  log.info("G's grant " + grantId + "; the released token was " +
           (live.released.access_token ? "issued" : "absent"));
  log.debug("Leaving test().");
}

K.main(test, 8);
