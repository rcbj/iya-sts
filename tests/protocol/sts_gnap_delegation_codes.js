// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_delegation_codes.js
//
// ===========================================================================
// WHO MAY ACT FOR WHOM IN GNAP, EACH REFUSAL BY ITS CODE, IN A PRODUCT
// REALM, OVER THE WIRE (#444 D12 phase 8; #432 phase 1, #186, #497).
//
// `tests/gnap_delegation.js` drives the grant endpoint in process with
// assertions it mints; `sts_gnap_delegation.js` runs in whichever mode the
// SERVICE is in. This job makes its own product realm, so product's
// refusals are asked whatever the probe is: each trusted client presents
// an ID Token this realm issued to IT about the person, from an ordinary
// grant the person approved, and the code each refusal records is read off
// `/admin-api/audit`:
//
//   I1. a client whose semantics do not include impersonation
//       (STS-GNAP-0772);
//   I6. impersonation in the client's semantics, R on its
//       appAllowedToDelegateTo: issued;
//   I7. impersonation allowed and R not reachable by the client (0770);
//   I9. a subject carrying stsNotDelegated (0771);
//   I10. a subject outside the client's appDelegationSubjectGroup (0771),
//        and I11 a member of it allowed;
//   A.  an ID Token issued to another client (STS-GNAP-0073);
//   II1. a resource server deriving for another with no relationship
//        (0776), and one whose appAllowedToDelegateTo names it allowed.
//
// (d), with the reason: I12 and I13 (STS-GNAP-0774) need a `may_act` claim
// in the user assertion, and this service mints none into an ID Token —
// the in-process file signs its own; IV's map is the console's drawing.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_delegation_codes");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Del-Passw0rd!-" + String(Date.now()).slice(-6);
const TYPE = "gdc-photos";
const RS = { a: "https://gdc-a.gnap.test/api",
             b: "https://gdc-b.gnap.test/api",
             c: "https://gdc-c.gnap.test/api" };

let realm = null;
let h = null;
const keys = {};

function right(locations) {
  log.debug("Entering right().");
  log.debug("Leaving right().");
  return { type: TYPE, actions: ["read"], locations: locations };
}

function claimsOf(value) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(value).split(".")[1], "base64url")
    .toString("utf8"));
}

async function party(identifier, kind, fields) {
  log.debug("Entering party(). " + identifier);
  keys[identifier] = G.client();
  await G.entry(h, identifier, kind, keys[identifier], fields);
  log.debug("Leaving party().");
}

// An ID Token about `who` issued to `client`, from an approved grant.
async function assertionFor(client, who) {
  log.debug("Entering assertionFor(). " + client + " " + who);
  const done = await h.redirectGrant(keys[client], who, {
    access_token: { access: [right([RS.b])] },
    subject: { assertion_formats: ["id_token"] } });
  const one = ((done.released.subject || {}).assertions || [])
    .filter(function (a) {
      return a.format === "id_token";
    })[0];
  assert.ok(one && one.value, JSON.stringify(done.released).slice(0, 300));
  log.debug("Leaving assertionFor().");
  return one.value;
}

function impersonate(client, assertion, access) {
  log.debug("Entering impersonate(). " + client);
  log.debug("Leaving impersonate().");
  return keys[client].send("POST", h.GRANT, { json: {
    client: { key: keys[client].keyObject() },
    access_token: { access: access || [right([RS.a])] },
    user: { assertions: [{ format: "id_token", value: assertion }] } } });
}

async function refusedAs(code, what, act, status) {
  log.debug("Entering refusedAs(). " + code);
  const c = await K.coded(realm, code, act);
  check(what + " (" + code + ")", function () {
    assert.strictEqual(c.answer.status, status || 403, c.answer.text);
    assert.ok(c.rose >= 1, code + " rose " + c.rose);
    assert.strictEqual(c.answer.headers["cache-control"], "no-store");
  });
  log.debug("Leaving refusedAs().");
  return c.answer;
}

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("gdc", "product", {}, PASSWORD);
  realm = made.id;
  h = made.h;
  const ALICE = "gdc-alice-" + K.STAMP;
  const BOB = "gdc-bob-" + K.STAMP;
  const CAROL = "gdc-carol-" + K.STAMP;
  for (const who of [ALICE, BOB, CAROL]) {
    await h.ensurePerson(who);
  }
  await h.ok(h.realmApi + "/users/set-not-delegated",
             { user: BOB, value: true }, "set stsNotDelegated on Bob");
  const GROUP = "gdc-staff-" + K.STAMP;
  const g = await h.ok(h.realmApi + "/groups/create", { group: GROUP },
                       "created the staff group");
  await h.ok(h.realmApi + "/groups/add-member",
             { group: GROUP, member: CAROL }, "Carol joined the group");
  const groupDn = g.dn || (g.group && g.group.dn) || "";
  assert.ok(/^cn=/i.test(groupDn), JSON.stringify(g).slice(0, 300));

  const A = "gdc-rs-a-" + K.STAMP;
  const B = "gdc-rs-b-" + K.STAMP;
  const C = "gdc-rs-c-" + K.STAMP;
  await party(B, "gnap-resource-server", { gnapResourceServerUri: RS.b });
  await party(C, "gnap-resource-server",
              { gnapResourceServerUri: RS.c });
  await party(A, "gnap-resource-server", { gnapResourceServerUri: RS.a,
    appAllowedToDelegateTo: [B],
    oauthAuthorizationDetailsType: [JSON.stringify({ type: TYPE,
      locations: [RS.a, RS.b, RS.c] })] });
  const PLAIN = "gdc-plain-" + K.STAMP;
  const IMP = "gdc-imp-" + K.STAMP;
  const SELF = "gdc-imp-self-" + K.STAMP;
  const STAFF = "gdc-imp-staff-" + K.STAMP;
  const base = { gnapSkipInteraction: "TRUE", gnapFinishUri: [h.FINISH] };
  await party(PLAIN, "gnap-client", base);
  await party(IMP, "gnap-client", Object.assign({
    appDelegationSemantics: ["impersonation"],
    appAllowedToDelegateTo: [A, B, C] }, base));
  await party(SELF, "gnap-client", Object.assign({
    appDelegationSemantics: ["impersonation"] }, base));
  await party(STAFF, "gnap-client", Object.assign({
    appDelegationSemantics: ["impersonation"],
    appAllowedToDelegateTo: [A], appDelegationSubjectGroup: [groupDn] },
    base));

  log.info("=== I. impersonation by assertion, in product ===");
  const plainAlice = await assertionFor(PLAIN, ALICE);
  await refusedAs("STS-GNAP-0772", "I1. product: a trusted client whose " +
                  "semantics do not include impersonation is refused " +
                  "request_denied", function () {
    return impersonate(PLAIN, plainAlice);
  });
  const impAlice = await assertionFor(IMP, ALICE);
  let r = await impersonate(IMP, impAlice, [right([RS.a, RS.b, RS.c])]);
  check("I6. impersonation in the client's semantics, R on its " +
        "appAllowedToDelegateTo: issued, the token the person's",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(/^urn:uuid:/.test(claimsOf(r.json.access_token.value).sub),
              r.text);
  });
  const original = r.json.access_token.value;
  const selfAlice = await assertionFor(SELF, ALICE);
  await refusedAs("STS-GNAP-0770", "I7. impersonation allowed and R not " +
                  "reachable by the client is refused", function () {
    return impersonate(SELF, selfAlice);
  });
  const impBob = await assertionFor(IMP, BOB);
  await refusedAs("STS-GNAP-0771", "I9. a subject carrying " +
                  "stsNotDelegated is refused", function () {
    return impersonate(IMP, impBob);
  });
  const staffAlice = await assertionFor(STAFF, ALICE);
  await refusedAs("STS-GNAP-0771", "I10. a subject outside the client's " +
                  "appDelegationSubjectGroup is refused", function () {
    return impersonate(STAFF, staffAlice);
  });
  const staffCarol = await assertionFor(STAFF, CAROL);
  r = await impersonate(STAFF, staffCarol);
  check("I11. and a member of the group is allowed", function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  await refusedAs("STS-GNAP-0073", "A1. an ID Token issued to another " +
                  "client is refused", function () {
    return impersonate(IMP, plainAlice);
  });

  log.info("=== II. derivation, in product ===");
  const derive = function (who, existing, access) {
    log.debug("Entering derive().");
    log.debug("Leaving derive().");
    return keys[who].send("POST", h.GRANT, { json: {
      client: { key: keys[who].keyObject() },
      existing_access_token: existing,
      access_token: { access: access } } });
  };
  await refusedAs("STS-GNAP-0776", "II1. product: a resource server " +
                  "deriving for another with no relationship is refused",
                  function () {
    return derive(C, original, [right([RS.b])]);
  });
  r = await derive(A, original, [right([RS.b])]);
  check("II3. a resource server whose appAllowedToDelegateTo names the " +
        "other derives for it, the act naming it", function () {
    assert.strictEqual(r.status, 200, r.text);
    const claims = claimsOf(r.json.access_token.value);
    assert.strictEqual(claims.aud, B, JSON.stringify(claims));
    assert.strictEqual(claims.act && claims.act.sub, "urn:sts:client:" + A,
                       JSON.stringify(claims));
  });
  log.debug("Leaving test().");
}

K.main(test, 9);
