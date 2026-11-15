// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_revocation_wire.js
//
// ===========================================================================
// WHAT ENDS A GNAP GRANT FROM OUTSIDE THE PROTOCOL, OVER THE WIRE (#444 D12
// phase 8; #432 phase 2).
//
// `tests/gnap_revocation.js` drives `logout.terminate()`, `revokeGrantsOf()`
// and the revocation module's checks against grants in the store, in a
// child process. This job makes real grants — a person signing in at the
// screen and approving at the page — in a product realm, and ends them
// through the doors an operator has:
//
//   B. a sign-out of ONE session (`/admin-api/sessions/revoke` of its row)
//      ends the grant approved on it and not one approved on another;
//   C. `/admin-api/sessions` lists a GNAP grant as a live row of its own,
//      and revoking that row ends it;
//   E. a global sign-out (`/admin-api/logout/global`) ends every grant;
//   F. an account disabled (`/admin-api/users/disable`): its tokens
//      introspect inactive, its continuation is refused, and its Shared
//      Signals token is refused invalid_token at the transmitter;
//   G. the client's application entry deleted: its grant's token inactive
//      and its continuation refused.
//
// Each token is introspected by the resource server with its own key.
//
// (d), with the reason: STS-GNAP-0730 and STS-GNAP-0734 are the check AT
// USE on a node the disable has not reached — on one node the disable ends
// the grant first, so a continuation or a presentation meets an ended
// grant (its own code, asserted here) and never the check; STS-GNAP-0731
// at use likewise for a deleted entry (the deletion ends its grants). The
// in-process file stubs that node. A's `heldIds()` is internal state.
// Owed: D (a partner's signal-revoke-grants, `sts_gnap_signals`' door) and
// H (a device marked compromised ending the grants its key holds).
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ===========================================================================

const assert = require("assert");
const K = require("./oauth_wire_kit.js").kit("sts_gnap_revocation_wire");
const G = require("./gnap_wire_kit.js").gnapKit(K);

const log = K.log;
const check = K.check;
const PASSWORD = "Gnap-Rev-Passw0rd!-" + String(Date.now()).slice(-6);
const TYPE = "grv-photos";

let realm = null;
let h = null;
let rs = null;
let c = null;

// A grant approved by `who` in `browser`: answers the released response.
async function approved(who, browser, client, access) {
  log.debug("Entering approved().");
  const one = client || c;
  const sent = h.grantBody(one, { access_token: { access: access ||
    [{ type: TYPE, actions: ["read"] }] } });
  const r = await one.send("POST", h.GRANT, { json: sent });
  assert.strictEqual(r.status, 200, r.text);
  const approval = await h.reachApproval(browser, r.json.interact.redirect,
                                         who);
  const answered = await h.answer(browser, approval, "allow");
  const done = h.finishParams(answered.location, answered);
  const released = await one.send("POST", r.json.continue.uri, {
    token: r.json.continue.access_token.value,
    json: { interact_ref: done.ref } });
  assert.strictEqual(released.status, 200, released.text.slice(0, 400));
  log.debug("Leaving approved().");
  return released.json;
}

async function active(token) {
  log.debug("Entering active().");
  const r = await G.introspect(h, rs, token);
  log.debug("Leaving active(). " + r.text.slice(0, 80));
  return !!(r.json && r.json.active === true);
}

async function rowsOf(who) {
  log.debug("Entering rowsOf().");
  const r = await K.send(h.realmApi + "/sessions?per=200&q=" +
                         encodeURIComponent(who));
  log.debug("Leaving rowsOf().");
  return ((r.json && r.json.sessions) || []).filter(function (one) {
    return one.username === who;
  });
}

async function revokeRow(row) {
  log.debug("Entering revokeRow().");
  const r = await K.send(h.realmApi + "/sessions/revoke",
                         { json: { key: row.key, select: row.id } });
  assert.strictEqual(r.status, 200, K.shown(r));
  log.debug("Leaving revokeRow().");
  return r;
}

function isGnapRow(row) {
  log.debug("Entering isGnapRow().");
  log.debug("Leaving isGnapRow().");
  return row.family === "gnap";
}

async function sessions() {
  log.debug("Entering sessions().");
  log.info("=== B, C: one session's sign-out, and the GNAP row ===");
  const ANN = "grv-ann-" + K.STAMP;
  await h.ensurePerson(ANN);
  const b1 = h.browser();
  const g1 = await approved(ANN, b1);
  const first = (await rowsOf(ANN)).filter(function (one) {
    return !isGnapRow(one);
  });
  assert.strictEqual(first.length, 1, "one session after the first " +
                     "sign-in: " + JSON.stringify(first).slice(0, 400));
  const b2 = h.browser();
  const g2 = await approved(ANN, b2);
  const rows = await rowsOf(ANN);
  log.info("ANN's rows: " + JSON.stringify(rows.map(function (one) {
    return [one.kind, one.protocol, String(one.id).slice(0, 24)];
  })));
  const gnapRows = rows.filter(isGnapRow);
  check("C1. /admin-api/sessions lists each GNAP grant the person approved " +
        "as a live row of its own, naming the session it was approved on",
        function () {
    assert.strictEqual(gnapRows.length, 2, JSON.stringify(rows).slice(0, 600));
    assert.ok(gnapRows.some(function (one) {
      return one.sessionId === first[0].sessionId;
    }), JSON.stringify(gnapRows).slice(0, 600));
  });
  await revokeRow(first[0]);
  const a1 = await active(g1.access_token.value);
  const a2 = await active(g2.access_token.value);
  check("B1. a sign-out of one session ends the grant approved on it: its " +
        "token introspects inactive", function () {
    assert.strictEqual(a1, false);
  });
  check("B2. and leaves the grant approved on another session live",
        function () {
    assert.strictEqual(a2, true);
  });
  // The first grant ended with its session, so the GNAP rows left are the
  // second grant's.
  const g2Rows = (await rowsOf(ANN)).filter(isGnapRow);
  assert.ok(g2Rows.length >= 1, "the second grant's row is still listed");
  for (const one of g2Rows) {
    await revokeRow(one);
  }
  const after = await active(g2.access_token.value);
  check("C2. revoking the GNAP row on /admin-api/sessions ends that " +
        "grant: its token introspects inactive", function () {
    assert.strictEqual(after, false);
  });
  const cont = await c.send("POST", g2.continue.uri,
                            { token: g2.continue.access_token.value,
                              json: {} });
  check("C2b. and its continuation is refused invalid_continuation",
        function () {
    assert.ok(cont.status >= 400, cont.text);
    assert.strictEqual(G.errorOf(cont), "invalid_continuation", cont.text);
  });
  log.debug("Leaving sessions().");
}

async function globalSignOut() {
  log.debug("Entering globalSignOut().");
  log.info("=== E: a global sign-out ===");
  const BOB = "grv-bob-" + K.STAMP;
  await h.ensurePerson(BOB);
  const g3 = await approved(BOB, h.browser());
  const g4 = await approved(BOB, h.browser());
  const r = await K.send(h.realmApi + "/logout/global",
                         { json: { user: BOB } });
  assert.strictEqual(r.status, 200, K.shown(r));
  const a3 = await active(g3.access_token.value);
  const a4 = await active(g4.access_token.value);
  check("E1. a global sign-out ends every grant the person approved, on " +
        "every session", function () {
    assert.strictEqual(a3, false);
    assert.strictEqual(a4, false);
  });
  log.debug("Leaving globalSignOut().");
}

async function disabled() {
  log.debug("Entering disabled().");
  log.info("=== F: an account disabled ===");
  const DAN = "grv-dan-" + K.STAMP;
  await h.ensurePerson(DAN);
  const g5 = await approved(DAN, h.browser());
  const g6 = await approved(DAN, h.browser(), null,
                            ["ssf.read"]);
  const r = await K.send(h.realmApi + "/users/disable",
                         { json: { user: DAN, reason: "d12" } });
  assert.strictEqual(r.status, 200, K.shown(r));
  const a5 = await active(g5.access_token.value);
  const cont = await c.send("POST", g5.continue.uri,
                            { token: g5.continue.access_token.value,
                              json: {} });
  check("F1. a disabled resource owner's token introspects inactive",
        function () {
    assert.strictEqual(a5, false);
  });
  check("F2. and the grant's continuation is refused " +
        "invalid_continuation", function () {
    assert.ok(cont.status >= 400, cont.text);
    assert.strictEqual(G.errorOf(cont), "invalid_continuation", cont.text);
  });
  const ssfToken = g6.access_token.value;
  const ssf = await c.send("GET", h.realmBase + "/ssf/status", {
    token: ssfToken });
  check("F3. the person's Shared Signals token is refused invalid_token at " +
        "the transmitter", function () {
    assert.strictEqual(ssf.status, 401, ssf.text);
    assert.ok(/invalid_token/.test(ssf.text + " " +
      JSON.stringify(ssf.headers)), ssf.text);
  });
  log.info("F2 answered " + cont.status + " " + cont.text.slice(0, 200) +
           "; F3 " + ssf.status + " " + ssf.text.slice(0, 200));
  log.debug("Leaving disabled().");
}

async function deleted() {
  log.debug("Entering deleted().");
  log.info("=== G: the client's entry deleted ===");
  const EVE = "grv-eve-" + K.STAMP;
  await h.ensurePerson(EVE);
  const other = G.client();
  const ID = "grv-gone-" + K.STAMP;
  await G.entry(h, ID, "gnap-client", other,
                { gnapFinishUri: [h.FINISH] });
  const g7 = await approved(EVE, h.browser(), other);
  const before = await active(g7.access_token.value);
  const r = await K.send(h.realmApi + "/applications/forget",
                         { json: { application: ID } });
  assert.strictEqual(r.status, 200, K.shown(r));
  const after = await active(g7.access_token.value);
  const cont = await other.send("POST", g7.continue.uri,
                                { token: g7.continue.access_token.value,
                                  json: {} });
  check("G1. the client's application entry deleted ends its grant: the " +
        "token, active before, introspects inactive", function () {
    assert.strictEqual(before, true);
    assert.strictEqual(after, false);
  });
  check("G2. and its continuation is refused", function () {
    assert.ok(cont.status >= 400, cont.text);
  });
  log.info("G2 answered " + cont.status + " " + cont.text.slice(0, 200));
  log.debug("Leaving deleted().");
}

async function test() {
  log.debug("Entering test().");
  const made = await G.gnapRealm("grv", "product", {}, PASSWORD);
  realm = made.id;
  h = made.h;
  rs = G.client();
  await G.resourceServer(h, "grv-rs-" + K.STAMP, rs,
                         "https://grv-rs.gnap.test/api",
                         [{ type: TYPE, actions: ["read"] }]);
  c = G.client();
  await G.entry(h, "grv-client-" + K.STAMP, "gnap-client", c,
                { gnapFinishUri: [h.FINISH], oauthAllowedScope: ["ssf.read"] });
  await sessions();
  await globalSignOut();
  await disabled();
  await deleted();
  log.debug("Leaving test().");
}

K.main(test, 11);
