// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_interaction.js
//
// ---------------------------------------------------------------------------
// WHO MUST BE ASKED FOR A GNAP GRANT, HOW STRONGLY THEY MUST HAVE SIGNED IN,
// AND APPROVAL BY AN ABSENT RESOURCE OWNER, OVER HTTP (#432 PHASE 6), in
// whichever mode the service is in.
//
//   0. THE CATALOGUE: four types on one resource server — interaction
//      `never`, `always`, a `default` one with a consent action, and one
//      needing acr `mfa` — and a client trusted to skip interaction.
//   1. A `never` TYPE is issued to a client nobody trusts, with no
//      interaction and nobody asked.
//   2. THE TRUSTED CLIENT skips a `default` type, and not an `always` one:
//      refused invalid_interaction without interaction, the approval page
//      drawn with it.
//   3. A REMEMBERED APPROVAL never stands in for an `always` type: the page
//      is drawn again for the same client and person, where a `default`
//      type's remembered approval skips it.
//   4. STEP-UP: the `mfa` type sends a password session back to the sign-in
//      screen instead of drawing the page; back with the marker and still
//      short, the request is denied and the client told request_denied.
//   5. APPROVAL BY AN ABSENT OWNER (`gnap.ownerApproval`): a request with no
//      interaction naming the owner waits; `too_fast` holds while the
//      client polls; the request is listed on the owner's `/portal/ciba`
//      and nobody else's; approved on a subset, the client's poll collects
//      the token; a second, denied, is user_denied; and another person
//      signing in at the approval page sends the grant to the owner, who
//      approves it on the portal.
//   6. `gnap.allowCrossUser` IS GONE: setting it is refused.
//
// The in-process half is `tests/gnap_interaction.js`. Everything runs in a
// THROWAWAY TRUST REALM that is left behind.
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
var log = bunyan.createLogger({ name: "sts_gnap_interaction",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const PASSWORD = "gnap-int-Passw0rd!-" + String(Date.now()).slice(-6);
const h = flowLib.harness({
  base: base,
  realm: usernameFor("gnapint").replace(/[^a-z0-9-]/g, "").slice(0, 30),
  password: PASSWORD,
  log: log
});
const check = h.check;
const OWNER = usernameFor("gnap-int-owner");
const OTHER = usernameFor("gnap-int-other");
const NEVER = "int-never";
const ALWAYS = "int-always";
const DFLT = "int-default";
const MFA = "int-mfa";

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
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

// The waiting GNAP request on a /portal/ciba page: its id, and the CSRF token.
function waitingOn(page) {
  log.debug("Entering waitingOn().");
  const m = /name="action" value="gnap-approve"><input type="hidden" name="id" value="([^"]+)"/.exec(page.text);
  log.debug("Leaving waitingOn().");
  return { id: m ? m[1] : "", csrf: h.csrfOf(page.text) };
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving per-type interaction, step-up and approval by an absent " +
           "owner at " + h.realmBase);
  await h.createRealm("GNAP interaction");
  await h.setting("gnap.continueWaitS", 0);
  await h.ensurePerson(OWNER);
  await h.ensurePerson(OTHER);

  // =========================================================================
  // 0. THE CATALOGUE AND A TRUSTED CLIENT.
  // =========================================================================
  log.info("=== 0. the catalogue ===");
  const RS = "int-rs-" + h.realm;
  const rsKey = new gnap.Client({ key: gnap.newKey("ES256") });
  await h.ok(h.realmApi + "/applications/create", {
    identifier: RS, kind: "gnap-resource-server", protocols: ["gnap"],
    fields: { gnapKey: JSON.stringify(rsKey.keyObject()),
              gnapResourceServerUri: "https://int.gnap.test/api" } },
             "registered the resource server");
  const declare = function (fields) {
    log.debug("Entering declare().");
    log.debug("Leaving declare().");
    return h.ok(h.realmApi + "/applications/set-access-type",
                Object.assign({ application: RS }, fields),
                "declared " + fields.type);
  };
  await declare({ type: NEVER, interaction: "never" });
  await declare({ type: ALWAYS, interaction: "always" });
  await declare({ type: DFLT, actions: ["read", "delete"],
                  consentActions: ["delete"] });
  await declare({ type: MFA, acr: "mfa" });
  const trusted = new gnap.Client({ key: gnap.newKey("ES256") });
  await h.ok(h.realmApi + "/applications/create", {
    identifier: "int-trusted-" + h.realm, kind: "gnap-client",
    protocols: ["gnap"],
    fields: { gnapKey: JSON.stringify(trusted.keyObject()),
              gnapSkipInteraction: "TRUE", gnapFinishUri: [h.FINISH] } },
             "registered the trusted client");
  const plain = new gnap.Client({ key: gnap.newKey("ES256") });
  const noInteraction = function (client, access, extra) {
    log.debug("Entering noInteraction().");
    log.debug("Leaving noInteraction().");
    return client.send("POST", h.GRANT, { json: Object.assign({
      access_token: { access: access },
      client: { key: client.keyObject() } }, extra || {}) });
  };

  // =========================================================================
  // 1. A never TYPE.
  // =========================================================================
  log.info("=== 1. interaction: never ===");
  let r = await noInteraction(plain, [{ type: NEVER }]);
  check("1. a never type is issued to an untrusted client with nobody asked",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token && r.json.access_token.value, r.text);
    assert.ok(!r.json.interact, r.text);
  });

  // =========================================================================
  // 2. THE TRUSTED CLIENT.
  // =========================================================================
  log.info("=== 2. the trusted client ===");
  r = await noInteraction(trusted, [{ type: DFLT, actions: ["read"] }]);
  check("2a. the trusted client skips a default type", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token && r.json.access_token.value, r.text);
  });
  r = await noInteraction(trusted, [{ type: ALWAYS }]);
  check("2b. and not an always type: invalid_interaction with none offered",
        function () {
    h.refused(r, "invalid_interaction", "an always type without interaction");
  });
  r = await noInteraction(trusted, [{ type: DFLT, actions: ["delete"] }]);
  check("2c. nor a right naming a consent action", function () {
    h.refused(r, "invalid_interaction", "a consent action");
  });
  r = await trusted.send("POST", h.GRANT, { json: h.grantBody(trusted, {
    access_token: { access: [{ type: ALWAYS }] } }) });
  check("2d. with interaction offered, the always type goes to the page",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.interact && r.json.interact.redirect, r.text);
    assert.ok(!r.json.access_token, r.text);
  });
  const trustedApproval = await h.reachApproval(h.browser(),
                                                r.json.interact.redirect,
                                                OWNER);
  check("2e. and the approval page is drawn for the person", function () {
    assert.strictEqual(trustedApproval.page.status, 200,
                       trustedApproval.page.text.slice(0, 300));
    assert.ok(/Allow access\?/.test(trustedApproval.page.text));
  });

  // =========================================================================
  // 3. REMEMBERED APPROVALS.
  // =========================================================================
  log.info("=== 3. remembered approvals ===");
  const rememberer = new gnap.Client({ key: gnap.newKey("ES256") });
  const b = h.browser();
  await h.redirectGrant(rememberer, OWNER,
                        { access_token: { access: [{ type: ALWAYS }] } },
                        { browser: b });
  await h.redirectGrant(rememberer, OWNER,
                        { access_token: { access: [{ type: DFLT,
                                                     actions: ["read"] }] } },
                        { browser: b });
  const again = async function (access) {
    log.debug("Entering again().");
    const res = await rememberer.send("POST", h.GRANT, { json: h.grantBody(
      rememberer, { access_token: { access: access } }) });
    assert.strictEqual(res.status, 200, res.text);
    const approval = await h.reachApproval(b, res.json.interact.redirect,
                                           OWNER);
    log.debug("Leaving again().");
    return approval.page;
  };
  let page = await again([{ type: ALWAYS }]);
  check("3a. an always type's remembered approval does not skip the page",
        function () {
    assert.strictEqual(page.status, 200, page.status + " " + page.location);
    assert.ok(/Allow access\?/.test(page.text), page.text.slice(0, 300));
  });
  page = await again([{ type: DFLT, actions: ["read"] }]);
  check("3b. control: a default type's remembered approval skips it",
        function () {
    assert.ok(page.status === 303 && /hash=/.test(page.location),
              page.status + " " + page.location);
  });

  // =========================================================================
  // 4. STEP-UP.
  // =========================================================================
  log.info("=== 4. step-up ===");
  const stepper = new gnap.Client({ key: gnap.newKey("ES256") });
  r = await stepper.send("POST", h.GRANT, { json: h.grantBody(stepper, {
    access_token: { access: [{ type: MFA }] } }) });
  assert.strictEqual(r.status, 200, r.text);
  const stepPending = r.json;
  const sb = h.browser();
  const stepApproval = await h.reachApproval(sb, stepPending.interact.redirect,
                                             OWNER);
  check("4a. a password session is sent to sign in again instead of being " +
        "shown the page", function () {
    assert.ok(stepApproval.page.status === 303 &&
              /\/authn\/login\?authn=/.test(stepApproval.page.location),
              stepApproval.page.status + " " + stepApproval.page.location +
              " " + stepApproval.page.text.slice(0, 200));
  });
  r = await sb.go("GET", stepApproval.approve + "?step_up_honoured=1");
  const stepFinish = h.finishParams(r.location, r);
  r = await stepper.send("POST", stepPending.continue.uri, {
    token: stepPending.continue.access_token.value,
    json: { interact_ref: stepFinish.ref } });
  check("4b. back from the sign-in still short of it, the request is " +
        "denied request_denied", function () {
    h.refused(r, "request_denied", "an unmet step-up");
  });

  // =========================================================================
  // 5. APPROVAL BY AN ABSENT OWNER.
  // =========================================================================
  log.info("=== 5. approval by an absent owner ===");
  await h.setting("gnap.ownerApproval", true);
  await h.setting("gnap.ownerApprovalLifetimeS", 60);
  const absent = new gnap.Client({ key: gnap.newKey("ES256") });
  const naming = { user: { sub_ids: [{ format: "email",
                                       email: OWNER + "@gnap.test" }] } };
  r = await noInteraction(absent, [{ type: DFLT, actions: ["read"] },
                                   { type: NEVER }], naming);
  check("5a. no interaction and a named owner: the grant waits", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.continue && !r.json.access_token && !r.json.interact,
              r.text);
  });
  let cont = r.json.continue;
  r = await absent.send("POST", cont.uri,
                        { token: cont.access_token.value });
  check("5b. too_fast holds while the client polls", function () {
    h.refused(r, "too_fast", "a poll inside the wait");
  });
  cont = r.json.continue || cont;
  const ownerBrowser = h.browser();
  page = await portal(ownerBrowser, OWNER, "/portal/ciba");
  const waiting = waitingOn(page);
  check("5c. the request is listed on the owner's /portal/ciba", function () {
    assert.strictEqual(page.status, 200, page.text.slice(0, 300));
    assert.ok(/Access requests/.test(page.text), page.text.slice(0, 300));
    assert.ok(waiting.id, "no gnap-approve form");
    assert.ok(!/<script/i.test(page.text), "a script on the page");
  });
  const otherPage = await portal(h.browser(), OTHER, "/portal/ciba");
  check("5d. and on nobody else's", function () {
    assert.strictEqual(otherPage.status, 200, otherPage.text.slice(0, 300));
    assert.ok(otherPage.text.indexOf(waiting.id) < 0);
  });
  r = await ownerBrowser.go("POST", "/realm/" + h.realm + "/portal/ciba",
                            "action=gnap-approve&id=" +
                            encodeURIComponent(waiting.id) +
                            "&right=t0r0&csrf_token=" +
                            encodeURIComponent(waiting.csrf));
  check("5e. the owner approves the first right only", function () {
    assert.strictEqual(r.status, 303, r.text.slice(0, 300));
    assert.ok(/Approved/.test(decodeURIComponent(r.location)), r.location);
  });
  r = await absent.send("POST", cont.uri, { token: cont.access_token.value });
  check("5f. the client's next poll collects a token carrying what the " +
        "owner left ticked", function () {
    assert.strictEqual(r.status, 200, r.text);
    const access = r.json.access_token.access;
    assert.strictEqual(access.length, 1, r.text);
    assert.strictEqual(access[0].type, DFLT, r.text);
  });
  // A denial.
  r = await noInteraction(absent, [{ type: NEVER }], naming);
  assert.strictEqual(r.status, 200, r.text);
  cont = r.json.continue;
  page = await portal(ownerBrowser, OWNER, "/portal/ciba");
  const second = waitingOn(page);
  r = await ownerBrowser.go("POST", "/realm/" + h.realm + "/portal/ciba",
                            { action: "gnap-deny", id: second.id,
                              csrf_token: second.csrf });
  assert.strictEqual(r.status, 303, r.text.slice(0, 300));
  await pause((Number(cont.wait) || 0) * 1000 + 200);
  r = await absent.send("POST", cont.uri, { token: cont.access_token.value });
  check("5g. a request the owner denies is user_denied", function () {
    h.refused(r, "user_denied", "the owner's denial");
  });
  // Another person at the approval page.
  const named = new gnap.Client({ key: gnap.newKey("ES256") });
  const body = h.grantBody(named, Object.assign({
    access_token: { access: [{ type: DFLT, actions: ["read"] }] } }, naming));
  r = await named.send("POST", h.GRANT, { json: body });
  assert.strictEqual(r.status, 200, r.text);
  const crossPending = r.json;
  const cross = await h.reachApproval(h.browser(),
                                      crossPending.interact.redirect, OTHER);
  const crossFinish = h.finishParams(cross.page.location, cross.page);
  r = await named.send("POST", crossPending.continue.uri, {
    token: crossPending.continue.access_token.value,
    json: { interact_ref: crossFinish.ref } });
  check("5h. another person signing in at the page sends the grant to its " +
        "owner, and the client is told to keep waiting", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.continue && !r.json.access_token, r.text);
  });
  cont = r.json.continue;
  page = await portal(ownerBrowser, OWNER, "/portal/ciba");
  const third = waitingOn(page);
  check("5i. it is waiting on the owner's portal, naming who asked",
        function () {
    assert.ok(third.id, page.text.slice(0, 300));
    assert.ok(page.text.indexOf(OTHER) >= 0, "the requester is not named");
  });
  r = await ownerBrowser.go("POST", "/realm/" + h.realm + "/portal/ciba",
                            "action=gnap-approve&id=" +
                            encodeURIComponent(third.id) +
                            "&right=t0r0&csrf_token=" +
                            encodeURIComponent(third.csrf));
  assert.strictEqual(r.status, 303, r.text.slice(0, 300));
  r = await named.send("POST", cont.uri, { token: cont.access_token.value });
  check("5j. and the owner's approval releases it", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(r.json.access_token && r.json.access_token.value, r.text);
  });
  await h.setting("gnap.ownerApproval", false);

  // =========================================================================
  // 6. gnap.allowCrossUser IS GONE.
  // =========================================================================
  log.info("=== 6. gnap.allowCrossUser ===");
  const gone = await h.apiPost(h.realmApi + "/config/set",
                               { key: "gnap.allowCrossUser", value: "true" });
  check("6. setting gnap.allowCrossUser is refused: there is no such " +
        "setting", function () {
    assert.ok(gone.status >= 400 && gone.status < 500,
              gone.status + " " + String(gone.raw).slice(0, 300));
  });

  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_interaction")
  .description("Per-type interaction, step-up to a type's acr and approval " +
    "by an absent resource owner for GNAP (#432 phase 6), in whichever mode " +
    "the service is in.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
