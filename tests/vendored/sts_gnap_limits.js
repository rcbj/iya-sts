// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_limits.js
//
// ---------------------------------------------------------------------------
// WHO OWNS WHAT A GNAP RIGHT NAMES, AND A RIGHT'S LIMITS FROM THE APPROVAL
// PAGE TO THE RESOURCE SERVER'S TOTALS, OVER HTTP (#432 PHASE 5), in
// whichever mode the service is in.
//
//   1. OWNERSHIP FROM A REGISTERED RESOURCE SET: a resource server registers
//      a set (RFC 9767 section 3.4) naming a group as the owner of one
//      identifier (`resource_owners`), and one naming nobody is refused; a
//      person who is not in the group reaches the approval page and is
//      REFUSED there, a member approves, and the RS's introspection of the
//      token returns the right with its limits and the `grant_id`.
//   2. A LOWERED LIMIT: a grant for the demonstration type asking to spend
//      at most 100 EUR in 5 operations; the person lowers the amount to 30
//      on the approval page; the token says 30 — read by this job's OWN
//      decoding of the jwt-signed token, with the grant it counts against —
//      and a raised amount posted to the page is refused.
//   3. THE DEMONSTRATION RESOURCE SERVER SPENDS (`POST /gnap/rs/spend`): 20,
//      then 20 refused (403 insufficient_scope), a failing operation
//      refunded (502), 10 more to exactly 30, and one more refused; another
//      currency refused.
//   4. THE ABSENT OWNER ON /portal/ciba (#432 phase 6's flow): a request
//      naming somebody who does not own the identifier waits on their
//      portal and their approval is REFUSED there; one naming the owner is
//      approved with its limit LOWERED on the portal, and the token says so.
//
// The in-process half — the vocabulary, lookups, the policy in both stages,
// the totals across periods and the shared store's statement — is
// `tests/gnap_limits_ownership.js`. A THROWAWAY TRUST REALM, left behind.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");
const flowLib = require("./gnap_flow.js");

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
var log = bunyan.createLogger({ name: "sts_gnap_limits",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const PASSWORD = "gnap-lim-Passw0rd!-" + String(Date.now()).slice(-6);
const h = flowLib.harness({
  base: base,
  realm: usernameFor("gnaplim").replace(/[^a-z0-9-]/g, "").slice(0, 30),
  password: PASSWORD,
  log: log
});
const check = h.check;
const OWNER = usernameFor("gnap-lim-owner");
const STRANGER = usernameFor("gnap-lim-stranger");
const ACCT = "lim-account";
const ACCT_URI = "https://acct.lim.test/api";

// The jwt-signed token's claims, read by this job: the payload of a compact
// JWS. The signature is the service's to check at its resource server; this
// job reads what the token SAYS about its limits.
function claimsOf(value) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(value).split(".")[1], "base64url")
                          .toString("utf8"));
}

// A browser signed in to the realm's portal, through the portal's own code
// flow and the sign-in screen, and the page at `path` once it is drawn.
async function portal(b, who, path) {
  log.debug("Entering portal().");
  let r = await b.go("GET", "/realm/" + h.realm + path);
  for (let hop = 0; hop < 12; hop++) {
    if (r.status === 302 || r.status === 303) {
      r = await b.go("GET", r.location);
      continue;
    }
    const authnId = (r.text.match(/name="authn_id" value="([^"]+)"/) ||
                     [])[1];
    if (r.status === 200 && authnId) {
      r = await b.go("POST", "/realm/" + h.realm + "/authn/login",
                     { authn_id: authnId, username: who, password: PASSWORD,
                       action: "login", csrf_token: h.csrfOf(r.text) });
      continue;
    }
    break;
  }
  log.debug("Leaving portal().");
  return r;
}

// The waiting GNAP request on a /portal/ciba page, and its CSRF token.
function waitingOn(page) {
  log.debug("Entering waitingOn().");
  const m = new RegExp('name="action" value="gnap-approve"><input ' +
                       'type="hidden" name="id" value="([^"]+)"')
    .exec(page.text);
  log.debug("Leaving waitingOn().");
  return { id: m ? m[1] : "", csrf: h.csrfOf(page.text) };
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving GNAP ownership and limits at " + h.realmBase);
  await h.createRealm("GNAP ownership and limits");
  await h.setting("gnap.continueWaitS", 0);
  // The jwt-signed format, so this job can read the token's claims itself.
  await h.setting("gnap.accessTokenFormat", "jwt-signed");
  await h.ensurePerson(OWNER);
  await h.ensurePerson(STRANGER);

  // =========================================================================
  // 1. OWNERSHIP FROM A REGISTERED RESOURCE SET.
  // =========================================================================
  log.info("=== 1. ownership from a resource set ===");
  let r = await h.apiPost(h.realmApi + "/groups/create",
                          { group: "lim-owners-" + h.realm });
  const groupDn = r.body && r.body.dn;
  check("1a. the owner group is created", function () {
    assert.ok(r.status === 200 && groupDn, r.raw);
  });
  await h.ok(h.realmApi + "/groups/add-member", { group: groupDn,
                                                  member: OWNER },
             "added the owner to the group");
  const RS = "lim-rs-" + h.realm;
  const rsKey = new gnap.Client({ key: gnap.newKey("ES256") });
  await h.ok(h.realmApi + "/applications/create", {
    identifier: RS, kind: "gnap-resource-server",
    protocols: ["gnap", "oauth2"],
    fields: { gnapKey: JSON.stringify(rsKey.keyObject()),
              gnapResourceServerUri: ACCT_URI } }, "registered " + RS);
  await h.ok(h.realmApi + "/applications/set-access-type", {
    application: RS, type: ACCT, actions: ["read", "spend"],
    limits: JSON.stringify({ type: "object",
      properties: { count: { type: "integer", minimum: 0 } },
      additionalProperties: false }) }, "declared the account type");
  const registration = function (owners) {
    log.debug("Entering registration().");
    log.debug("Leaving registration().");
    return rsKey.send("POST", h.realmBase + "/gnap/resource", { json: {
      access: [{ type: ACCT, identifier: "acct-team", actions: ["read"] }],
      resource_server: { key: rsKey.keyObject() },
      resource_owners: owners } });
  };
  r = await registration({ "acct-team": "cn=nobody,ou=groups,dc=nowhere" });
  check("1b. an owner that is not a person or a group here is refused",
        function () {
    h.refused(r, "invalid_request", "an owner that names nobody");
  });
  r = await registration({ "acct-other": groupDn });
  check("1c. an owner for an identifier the set does not carry is refused",
        function () {
    h.refused(r, "invalid_request", "an owner for a stray identifier");
  });
  r = await registration({ "acct-team": groupDn });
  check("1d. the set is registered with its owner", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.resource_reference, r.text);
  });
  const owned = { type: ACCT, identifier: "acct-team", actions: ["read"],
                  limits: { count: 3 } };
  const client = new gnap.Client({ key: gnap.newKey("ES256") });
  let body = h.grantBody(client, { access_token: { access: [owned] } });
  r = await client.send("POST", h.GRANT, { json: body });
  check("1e. the grant request naming the owned identifier is accepted",
        function () {
    assert.strictEqual(r.status, 200, r.text);
  });
  let pending = r.json;
  let b = h.browser();
  let approval = await h.reachApproval(b, pending.interact.redirect, STRANGER);
  check("1f. somebody who does not own it is REFUSED on the approval page",
        function () {
    assert.strictEqual(approval.page.status, 400,
                       approval.page.text.slice(0, 400));
    assert.ok(/cannot approve this request/.test(approval.page.text),
              approval.page.text.slice(0, 600));
  });
  // The owner: a new grant (the stranger's browser holds the first one's
  // sign-in), approved and released.
  const released = await h.redirectGrant(client, OWNER,
    { access_token: { access: [owned] } });
  const token = released.released.access_token;
  check("1g. a member of the owner group approves it", function () {
    assert.ok(token && token.value, JSON.stringify(released.released));
  });
  r = await rsKey.send("POST", h.realmBase + "/gnap/introspect", { json: {
    access_token: token.value, resource_server: { key: rsKey.keyObject() } } });
  check("1h. the resource server's introspection returns the right with " +
        "its limits, and the grant they are counted against", function () {
    assert.strictEqual(r.json.active, true, r.text);
    assert.deepStrictEqual(r.json.access[0].limits, { count: 3 }, r.text);
    assert.ok(typeof r.json.grant_id === "string" && r.json.grant_id,
              r.text);
  });

  // =========================================================================
  // 2. A LOWERED LIMIT ON THE APPROVAL PAGE.
  // =========================================================================
  log.info("=== 2. a lowered limit ===");
  const spendRight = { type: h.DEMO, actions: ["spend"],
                       limits: { amount: "100", currency: "EUR",
                                 count: 5 } };
  const payer = new gnap.Client({ key: gnap.newKey("ES256") });
  const askAndLower = async function (amount) {
    log.debug("Entering askAndLower().");
    const asked = h.grantBody(payer,
                              { access_token: { access: [spendRight] } });
    let rr = await payer.send("POST", h.GRANT, { json: asked });
    assert.strictEqual(rr.status, 200, rr.text);
    const p = rr.json;
    const browser = h.browser();
    const ap = await h.reachApproval(browser, p.interact.redirect, OWNER);
    assert.ok(ap.page.status === 200 &&
              /name="lim_t0r0_amount" value="100"/.test(ap.page.text),
              "the page draws the amount as a control: " +
              ap.page.text.slice(0, 800));
    const form = "action=allow&right=t0r0&csrf_token=" +
      encodeURIComponent(h.csrfOf(ap.page.text)) +
      "&lim_t0r0_amount=" + encodeURIComponent(amount) +
      "&lim_t0r0_count=5";
    rr = await browser.go("POST", ap.approve, form);
    log.debug("Leaving askAndLower().");
    return { pending: p, answer: rr, asked: asked };
  };
  let lowered = await askAndLower("150");
  check("2a. a RAISED amount is refused by the page", function () {
    assert.strictEqual(lowered.answer.status, 400,
                       lowered.answer.text.slice(0, 400));
    assert.ok(/may only be lowered/.test(lowered.answer.text),
              lowered.answer.text.slice(0, 600));
  });
  lowered = await askAndLower("30");
  const finished = h.finishParams(lowered.answer.location, lowered.answer);
  r = await payer.send("POST", lowered.pending.continue.uri, {
    token: lowered.pending.continue.access_token.value,
    json: { interact_ref: finished.ref } });
  const spendToken = r.json && r.json.access_token;
  let claims = null;
  check("2b. the token carries the LOWERED limit, read off the token " +
        "itself, and the grant it is counted against", function () {
    assert.strictEqual(r.status, 200, r.text);
    claims = claimsOf(spendToken.value);
    assert.deepStrictEqual(claims.access[0].limits,
                           { amount: "30", currency: "EUR", count: 5 },
                           JSON.stringify(claims));
    assert.ok(typeof claims.grant_id === "string" && claims.grant_id,
              JSON.stringify(claims));
  });

  // =========================================================================
  // 3. THE DEMONSTRATION RESOURCE SERVER KEEPS THE TOTALS.
  // =========================================================================
  log.info("=== 3. the demonstration resource server spends ===");
  const spend = function (json) {
    log.debug("Entering spend().");
    log.debug("Leaving spend().");
    return payer.send("POST", h.realmBase + "/gnap/rs/spend",
                      { token: spendToken.value, json: json });
  };
  r = await spend({ amount: "20", currency: "EUR" });
  check("3a. 20 EUR is spent, 10 left", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.remaining.amount, "10", r.text);
    assert.strictEqual(r.json.grant_id, claims.grant_id, r.text);
  });
  r = await spend({ amount: "20", currency: "EUR" });
  check("3b. 20 more passes the limit: 403 insufficient_scope", function () {
    assert.strictEqual(r.status, 403, r.text);
    assert.strictEqual(r.json.error, "insufficient_scope", r.text);
    assert.ok(/insufficient_scope/.test(String(
      r.headers["www-authenticate"] || "")), JSON.stringify(r.headers));
  });
  r = await spend({ amount: "10", currency: "EUR", simulateFailure: true });
  check("3c. an operation that fails after its spend is REFUNDED",
        function () {
    assert.strictEqual(r.status, 502, r.text);
    assert.strictEqual(r.json.refunded, true, r.text);
  });
  r = await spend({ amount: "10", currency: "EUR" });
  check("3d. so 10 more is spent: exactly the limit", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.strictEqual(r.json.totals.amount, "30", r.text);
  });
  r = await spend({ amount: "0.01", currency: "EUR" });
  check("3e. and a cent more is refused", function () {
    assert.strictEqual(r.status, 403, r.text);
  });
  r = await spend({ amount: "1", currency: "USD" });
  check("3f. an operation in another currency is refused", function () {
    assert.strictEqual(r.status, 403, r.text);
    assert.ok(/EUR/.test(r.json.error_description), r.text);
  });
  r = await payer.send("POST", h.realmBase + "/gnap/rs/spend",
                       { json: { amount: "1", currency: "EUR" } });
  check("3g. with no token: the RS-first challenge", function () {
    assert.strictEqual(r.status, 401, r.text);
  });

  // =========================================================================
  // 4. THE ABSENT OWNER ON /portal/ciba.
  // =========================================================================
  log.info("=== 4. the absent owner ===");
  await h.setting("gnap.ownerApproval", true);
  await h.setting("gnap.ownerApprovalLifetimeS", 120);
  const absent = new gnap.Client({ key: gnap.newKey("ES256") });
  const ask = function (who) {
    log.debug("Entering ask().");
    log.debug("Leaving ask().");
    return absent.send("POST", h.GRANT, { json: {
      access_token: { access: [owned] },
      client: { key: absent.keyObject() },
      user: { sub_ids: [{ format: "email", email: who + "@gnap.test" }] } } });
  };
  const answerOnPortal = async function (who, form) {
    log.debug("Entering answerOnPortal().");
    const browser = h.browser();
    const page = await portal(browser, who, "/portal/ciba");
    const waiting = waitingOn(page);
    assert.ok(waiting.id, "the request is listed on " + who + "'s portal: " +
              page.text.slice(0, 600));
    const answer = await browser.go("POST", "/realm/" + h.realm +
      "/portal/ciba", "action=gnap-approve&id=" +
      encodeURIComponent(waiting.id) + "&right=t0r0&csrf_token=" +
      encodeURIComponent(waiting.csrf) + (form || ""));
    log.debug("Leaving answerOnPortal().");
    return { page: page, answer: answer };
  };
  r = await ask(STRANGER);
  check("4a. a request naming somebody else waits for them", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.continue && !r.json.access_token, r.text);
  });
  let answered = await answerOnPortal(STRANGER, "");
  check("4b. somebody who does not own it cannot approve it on the portal",
        function () {
    assert.strictEqual(answered.answer.status, 400,
                       answered.answer.text.slice(0, 400));
    assert.ok(/not yours to give/.test(answered.answer.text),
              answered.answer.text.slice(0, 600));
  });
  r = await ask(OWNER);
  const waitingCont = r.json && r.json.continue;
  check("4c. a request naming the owner waits for them", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(waitingCont, r.text);
  });
  answered = await answerOnPortal(OWNER, "&lim_t0r0_count=1");
  check("4d. the portal draws the limit, and the owner lowers it",
        function () {
    assert.ok(/name="lim_t0r0_count" value="3"/.test(answered.page.text),
              answered.page.text.slice(0, 800));
    assert.strictEqual(answered.answer.status, 303,
                       answered.answer.text.slice(0, 400));
  });
  r = await absent.send("POST", waitingCont.uri,
                        { token: waitingCont.access_token.value });
  check("4e. the client collects a token carrying the LOWERED limit",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(claimsOf(r.json.access_token.value)
                             .access[0].limits, { count: 1 }, r.text);
  });

  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_limits")
  .description("GNAP ownership of an identifier and a right's limits, from " +
    "the approval page to the resource server's totals (#432 phase 5), in " +
    "whichever mode the service is in.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
