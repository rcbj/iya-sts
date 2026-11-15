// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_instances_wire.js
//
// ===========================================================================
// AN UNREGISTERED KEY AS AN INSTANCE OF A REGISTERED GNAP CLIENT, AND THE
// INSTANCE RECORDS IT IS HANDED, OVER THE WIRE (#444 D12 phase 8; #1216,
// #1219, #1221).
//
// `tests/gnap_unregistered_instances.js` and `tests/gnap_instances.js` hold
// `GnapGrants.identifyCaller()`, `classInstanceOf()`, the revocation
// module's `grantProblem()` and the instance store with the key proof
// stubbed and the clock replaced. This job asks `/gnap` and
// `/gnap/introspect` with keys it signs with, in a PRODUCT realm (a
// development one for I4), and reads each refusal's code off
// `/admin-api/audit`:
//
//   I1. an unknown key whose class_id names a registered client with a
//       registered finish URI is an instance of it — accepted, handed an
//       instance_id, never skipping the approval page although the client
//       is trusted to skip it — and nothing is written to the entry;
//   I2. a class_id naming nobody, a resource server, an entry development
//       filed on first sight, or a client with no finish URI: 401
//       invalid_client, STS-GNAP-0906; no class_id: STS-GNAP-0082;
//   I3. gnap.unregisteredInstances off: STS-GNAP-0082;
//   I4. development: the eligible claim files no entry; with no class_id
//       one is filed;
//   I5. the instance_id by reference is still an instance; with the setting
//       off it no longer resolves (STS-GNAP-0080);
//   I6. a remembered approval skips the page for the client's registered
//       key and not for an instance; I7 a registered key is identified by
//       its key whatever class_id it sends;
//   I8. the instance's grant and token are live at use; I9 with the
//       setting off they are refused (STS-GNAP-0907), and back on, live;
//   I10. an edit of the entry's gnapKey ends the grant bound to the key it
//        no longer names (STS-GNAP-0731 at its continuation) and leaves the
//        instance's alone;
//   N1/N2. the same key at the same client is handed the same instance_id,
//       another key another (gnap_instances N1, N2);
//   N3. an instance unused for gnap.grantLifetimeS is unknown (STS-GNAP-
//       0080), and the gnap.grant-expiry job's run succeeds after it (N6).
//
// (d), with the reason: N2's createdAt/seenAt, N4 (which records
// purgeInstances() deletes) and N5 (touchInstance()'s once-a-minute
// refresh) are the store's fields and timing, which no answer carries.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_instances_wire");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Inst-Passw0rd!-" + String(Date.now()).slice(-6);
const TYPE = "gi-photos";

function rights() {
  log.debug("Entering rights().");
  log.debug("Leaving rights().");
  return [{ type: TYPE, actions: ["read"] }];
}

// A grant request with the redirect interaction, `client` by value with a
// class_id, or by reference when `reference` is given.
function body(h, c, classId, reference) {
  log.debug("Entering body().");
  const b = h.grantBody(c, { access_token: { access: rights() } });
  if (reference) {
    b.client = reference;
  } else if (classId) {
    b.client.class_id = classId;
  }
  log.debug("Leaving body().");
  return b;
}

// The redirect dance for a pending answer: the person signs in, approves
// (or meets a remembered approval), and the client continues.
async function finish(h, c, sent, pending, who, b) {
  log.debug("Entering finish().");
  const browser = b || h.browser();
  const approval = await h.reachApproval(browser, pending.interact.redirect,
                                         who);
  const drawn = !(approval.page.status === 303 &&
                  /hash=/.test(approval.page.location));
  const r = await h.answer(browser, approval, "allow");
  const done = h.finishParams(r.location, r);
  const released = await c.send("POST", pending.continue.uri, {
    token: pending.continue.access_token.value,
    json: { interact_ref: done.ref } });
  assert.strictEqual(released.status, 200, released.text.slice(0, 400));
  log.debug("Leaving finish(). drawn=" + drawn);
  return { drawn: drawn, released: released.json };
}

async function productPass() {
  log.debug("Entering productPass().");
  log.info("=== I1-I3, I5-I10, N1-N3: a product realm ===");
  const { id, h } = await G.gnapRealm("gip", "product", {}, PASSWORD);
  const WHO = "gi-owner-" + K.STAMP;
  await h.ensurePerson(WHO);
  const rs = G.client();
  await G.resourceServer(h, "gi-rs-" + K.STAMP, rs,
                         "https://gi-rs.gnap.test/api",
                         [{ type: TYPE, actions: ["read"] }]);
  const SPA = "gi-spa-" + K.STAMP;
  const NO_FINISH = "gi-nofinish-" + K.STAMP;
  const RSID = "gi-rs-" + K.STAMP;
  const registered = G.client();
  await G.entry(h, SPA, "gnap-client", registered,
                { gnapFinishUri: [h.FINISH] });
  await G.entry(h, NO_FINISH, "gnap-client", null, {});
  const trustedKey = G.client();
  const TRUSTED = "gi-trusted-" + K.STAMP;
  await G.entry(h, TRUSTED, "gnap-client", null,
                { gnapFinishUri: [h.FINISH], gnapSkipInteraction: "TRUE" });

  // I1, with a client trusted to skip: its instance is still asked.
  const before = await G.application(h, TRUSTED);
  let r = await trustedKey.send("POST", h.GRANT,
                                { json: body(h, trustedKey, TRUSTED) });
  check("I1. product: an unknown key whose class_id names a registered " +
        "client (trusted to skip) with a finish URI is accepted as an " +
        "instance, handed an instance_id, and sent to the approval page",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.interact && r.json.interact.redirect, r.text);
    assert.ok(!r.json.access_token, r.text);
    assert.ok(typeof r.json.instance_id === "string" &&
              r.json.instance_id.length > 8, r.text);
  });
  const after = await G.application(h, TRUSTED);
  check("I1b. and nothing about the key is written to the entry",
        function () {
    assert.ok(!(after.fields && after.fields.gnapKey),
              JSON.stringify(after.fields));
    assert.strictEqual(JSON.stringify((after.fields || {})
      .gnapKeyIdentity || null), JSON.stringify((before.fields || {})
      .gnapKeyIdentity || null));
  });

  // N1.
  const again = await trustedKey.send("POST", h.GRANT,
                                      { json: body(h, trustedKey, TRUSTED) });
  const other = G.client();
  const otherAnswer = await other.send("POST", h.GRANT,
                                       { json: body(h, other, TRUSTED) });
  check("N1. the same key at the same client is handed the same " +
        "instance_id; another key another", function () {
    assert.strictEqual(again.status, 200, again.text);
    assert.strictEqual(again.json.instance_id, r.json.instance_id);
    assert.strictEqual(otherAnswer.status, 200, otherAnswer.text);
    assert.notStrictEqual(otherAnswer.json.instance_id, r.json.instance_id);
  });
  const instanceId = r.json.instance_id;

  // I2: a development-filed entry first (the realm is development for one
  // request, a key sent with no class_id).
  await K.set(id, "global.mode", "development");
  const seenKey = G.client();
  const seen = await seenKey.send("POST", h.GRANT,
                                  { json: body(h, seenKey, null) });
  await K.set(id, "global.mode", "product");
  assert.strictEqual(seen.status, 200, seen.text);
  const listed = await K.send(h.realmApi + "/applications?per=200");
  const SEEN = ((listed.json && listed.json.applications) || [])
    .map(function (one) {
      return one.identifier;
    }).filter(function (one) {
      return /^gnap-/.test(one);
    })[0];
  assert.ok(SEEN, "development filed an entry for the bare key: " +
            JSON.stringify(listed.json).slice(0, 400));
  const refusals = [];
  const c906 = await K.coded(id, "STS-GNAP-0906", async function () {
    for (const name of ["gi-nobody-" + K.STAMP, RSID, SEEN, NO_FINISH]) {
      const k = G.client();
      refusals.push(await k.send("POST", h.GRANT,
                                 { json: body(h, k, name) }));
    }
  });
  check("I2. product: a class_id naming nobody, a resource server, an " +
        "entry development filed on first sight, or a client with no " +
        "finish URI is 401 invalid_client (STS-GNAP-0906)", function () {
    refusals.forEach(function (one) {
      assert.strictEqual(one.status, 401, one.text);
      assert.strictEqual(G.errorOf(one), "invalid_client", one.text);
      assert.strictEqual(one.headers["cache-control"], "no-store");
    });
    assert.ok(c906.rose >= 4, "STS-GNAP-0906 rose " + c906.rose);
  });
  const bare = G.client();
  const c82 = await K.coded(id, "STS-GNAP-0082", function () {
    return bare.send("POST", h.GRANT, { json: body(h, bare, null) });
  });
  check("I2b. an unknown key with no class_id is STS-GNAP-0082, as before",
        function () {
    assert.strictEqual(G.errorOf(c82.answer), "invalid_client",
                       c82.answer.text);
    assert.ok(c82.rose >= 1);
  });

  // I3 and I5b, with the setting off.
  await K.set(id, "gnap.unregisteredInstances", false);
  const offKey = G.client();
  const off = await K.coded(id, "STS-GNAP-0082", function () {
    return offKey.send("POST", h.GRANT, { json: body(h, offKey, TRUSTED) });
  });
  const refOff = await K.coded(id, "STS-GNAP-0080", function () {
    return trustedKey.send("POST", h.GRANT,
                           { json: body(h, trustedKey, null, instanceId) });
  });
  await K.unset(id, "gnap.unregisteredInstances");
  check("I3. gnap.unregisteredInstances off: the eligible claim is " +
        "STS-GNAP-0082, as before #1216", function () {
    assert.strictEqual(off.answer.status, 401, off.answer.text);
    assert.ok(off.rose >= 1);
  });
  check("I5b. and the instance_id it was handed no longer resolves " +
        "(STS-GNAP-0080)", function () {
    assert.ok(off.answer.status >= 400);
    assert.ok(refOff.answer.status >= 400, refOff.answer.text);
    assert.ok(refOff.rose >= 1, "STS-GNAP-0080 rose " + refOff.rose);
  });

  // I5.
  r = await trustedKey.send("POST", h.GRANT,
                            { json: body(h, trustedKey, null, instanceId) });
  check("I5. the instance_id by reference resolves to the same client and " +
        "is still an instance: the approval page, not a token", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.interact && r.json.interact.redirect, r.text);
    assert.ok(!r.json.access_token, r.text);
  });

  // I6, I7: the client's registered key, approved once and remembered,
  // skips the page; an instance of the same client does not.
  const browser = h.browser();
  const sentA = body(h, registered, SPA);
  r = await registered.send("POST", h.GRANT, { json: sentA });
  assert.strictEqual(r.status, 200, r.text);
  const firstA = await finish(h, registered, sentA, r.json, WHO, browser);
  const sentA2 = body(h, registered, SPA);
  r = await registered.send("POST", h.GRANT, { json: sentA2 });
  const secondA = await finish(h, registered, sentA2, r.json, WHO, browser);
  const instanceKey = G.client();
  const sentB = body(h, instanceKey, SPA);
  r = await instanceKey.send("POST", h.GRANT, { json: sentB });
  assert.strictEqual(r.status, 200, r.text);
  const firstB = await finish(h, instanceKey, sentB, r.json, WHO, browser);
  check("I6. a remembered approval skips the page for the client's " +
        "registered key, and not for an unregistered instance", function () {
    assert.strictEqual(firstA.drawn, true);
    assert.strictEqual(secondA.drawn, false);
    assert.strictEqual(firstB.drawn, true);
  });
  check("I7. a registered key is identified by its key, whatever class_id " +
        "it sends: it is handed no instance record of an instance",
        function () {
    assert.ok(secondA.released.access_token, JSON.stringify(secondA));
  });

  // I8.
  const tokenB = firstB.released.access_token.value;
  const tokenA = secondA.released.access_token.value;
  let contB = firstB.released.continue;
  const contA = secondA.released.continue;
  r = await G.introspect(h, rs, tokenB);
  let cont = await instanceKey.send("POST", contB.uri,
                                    { token: contB.access_token.value,
                                      json: {} });
  check("I8. the instance's token is active at introspection and its " +
        "grant answers its continuation, although its key is not on the " +
        "entry", function () {
    assert.strictEqual(r.json && r.json.active, true, r.text);
    assert.strictEqual(cont.status, 200, cont.text);
  });
  // A continuation answers a new continuation access token (section 5).
  contB = cont.json.continue || contB;

  // I9.
  await K.set(id, "gnap.unregisteredInstances", false);
  const i9 = await K.coded(id, "STS-GNAP-0907", async function () {
    return [await G.introspect(h, rs, tokenB),
            await instanceKey.send("POST", contB.uri,
              { token: contB.access_token.value, json: {} })];
  });
  await K.unset(id, "gnap.unregisteredInstances");
  // The introspection's code is on its log line only (an inactive answer
  // is a 200, which records no code); the continuation's refusal is the
  // audited one.
  check("I9. with gnap.unregisteredInstances off the instance's token " +
        "introspects inactive and its continuation is refused " +
        "(STS-GNAP-0907)", function () {
    assert.strictEqual(i9.answer[0].json && i9.answer[0].json.active, false,
                       i9.answer[0].text);
    assert.ok(i9.answer[1].status >= 400, i9.answer[1].text);
    assert.ok(i9.rose >= 1, "STS-GNAP-0907 rose " + i9.rose);
  });
  r = await G.introspect(h, rs, tokenB);
  check("I9b. and with it back on the same token is active again",
        function () {
    assert.strictEqual(r.json && r.json.active, true, r.text);
  });

  // I10.
  const replacement = G.client();
  const edited = await K.appSet(id, SPA, "gnapKey",
                                JSON.stringify(replacement.keyObject()));
  assert.strictEqual(edited.status, 200, edited.text);
  const i10 = await K.coded(id, "STS-GNAP-0731", function () {
    return registered.send("POST", contA.uri,
                           { token: contA.access_token.value, json: {} });
  });
  const aActive = await G.introspect(h, rs, tokenA);
  const bActive = await G.introspect(h, rs, tokenB);
  check("I10. an edit of the entry's gnapKey ends the grant bound to the " +
        "key it no longer names (its token inactive; its continuation " +
        "refused) and leaves the instance's grant alone", function () {
    assert.strictEqual(aActive.json && aActive.json.active, false,
                       aActive.text);
    assert.ok(i10.answer.status >= 400, i10.answer.text);
    assert.strictEqual(bActive.json && bActive.json.active, true,
                       bActive.text);
  });
  log.info("I10's continuation answered " + i10.answer.status + " " +
           G.errorOf(i10.answer) + "; STS-GNAP-0731 rose " + i10.rose);

  // N3: an instance unused for the grant lifetime is unknown.
  await K.set(id, "gnap.grantLifetimeS", 60);
  const shortKey = G.client();
  r = await shortKey.send("POST", h.GRANT,
                          { json: body(h, shortKey, TRUSTED) });
  assert.strictEqual(r.status, 200, r.text);
  const shortId = r.json.instance_id;
  log.info("waiting 62 s for an instance record to outlive " +
           "gnap.grantLifetimeS 60");
  await K.sleep(62000);
  const n3 = await K.coded(id, "STS-GNAP-0080", function () {
    return shortKey.send("POST", h.GRANT,
                         { json: body(h, shortKey, null, shortId) });
  });
  check("N3. an instance record unused for gnap.grantLifetimeS is " +
        "answered as unknown (STS-GNAP-0080)", function () {
    assert.ok(n3.answer.status >= 400, n3.answer.text);
    assert.ok(n3.rose >= 1);
  });
  await G.runJob(id, "gnap.grant-expiry");
  const n6 = await shortKey.send("POST", h.GRANT,
                                 { json: body(h, shortKey, null, shortId) });
  check("N6. the gnap.grant-expiry job's run succeeds, and the record is " +
        "still unknown after it", function () {
    assert.ok(n6.status >= 400, n6.text);
  });
  await K.unset(id, "gnap.grantLifetimeS");
  log.debug("Leaving productPass().");
}

async function developmentPass() {
  log.debug("Entering developmentPass().");
  log.info("=== I4: a development realm ===");
  const { id, h } = await G.gnapRealm("gid", "development", {}, PASSWORD);
  const SPA = "gi-spa-" + K.STAMP;
  await G.resourceServer(h, "gi-rs-" + K.STAMP, G.client(),
                         "https://gi-rs.gnap.test/api",
                         [{ type: TYPE, actions: ["read"] }]);
  await G.entry(h, SPA, "gnap-client", null,
                { gnapFinishUri: [h.FINISH] });
  const count = async function () {
    const l = await K.send(h.realmApi + "/applications?per=200");
    return ((l.json && l.json.applications) || []).length;
  };
  const n0 = await count();
  const k = G.client();
  const r = await k.send("POST", h.GRANT, { json: body(h, k, SPA) });
  const n1 = await count();
  check("I4. development: the eligible claim is an instance too, and no " +
        "gnap-* entry is filed for the key", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.instance_id, r.text);
    assert.strictEqual(n1, n0);
  });
  const bareKey = G.client();
  const bare = await bareKey.send("POST", h.GRANT,
                                  { json: body(h, bareKey, null) });
  const n2 = await count();
  check("I4b. while an unknown key with no class_id is still given an " +
        "entry on first sight", function () {
    assert.strictEqual(bare.status, 200, bare.text);
    assert.strictEqual(n2, n1 + 1);
  });
  log.debug("Leaving developmentPass().");
}

async function test() {
  log.debug("Entering test().");
  await productPass();
  await developmentPass();
  log.debug("Leaving test().");
}

K.main(test, 18);
