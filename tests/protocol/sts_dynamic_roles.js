// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_dynamic_roles.js
//
// ===========================================================================
// DYNAMIC SELECTABLE ROLES, OVER THE WIRE (#1072).
//
// A dynamic role is held by nobody, offered at sign-in to whoever its own
// XACML policy permits, and carried on the tokens of that sign-in's
// application only when chosen (rcbj's decisions of 2026-11-20). This job
// drives the whole of it as a browser and an administrator would, in a
// throwaway development realm:
//
//   A. THE DEFINITION through /admin-api: a dynamic role made with
//      create-role, its policy set from ALFA, a member refused on it, and
//      the administrator's test (GET /admin-api/roles/eligibility) saying
//      who is eligible and who is not.
//   B. THE BOX: the sign-in screen's view offers "Choose roles for this
//      sign-in" in a realm that defines a dynamic role.
//   C. NOT TICKED: the eligible person signs in straight to the client and
//      the ID Token carries no dynamic role.
//   D. TICKED: the role step lists what may be chosen; a fabricated role is
//      refused and the step stays; the real one is chosen, the sign-in
//      completes, and the ID Token's roles claim carries it; the choice is
//      audited as roles.selection.chosen.
//   E. A PERSON THE POLICY DOES NOT PERMIT ticks the box and is offered
//      nothing: no step, signed in, no dynamic role.
//   F. TURNED OFF for the client (appDynamicRoleSelection FALSE): no box.
//   G. REQUIRED (the review follow-ups of 2026-11-23): the step is drawn
//      though the box is not ticked; the password grant, which cannot draw
//      it, is refused access_denied for the eligible person and not for the
//      clerk; and single sign-on into a second client the session chose
//      nothing for is not answered from the session — the sign-in screen,
//      or interaction_required with prompt=none.
//
// `local: true`: this repository's own /authn, /oauth2 and /admin-api.
// ===========================================================================

"use strict";

const assert = require("assert");
const wire = require("./passkey_wire_kit.js");
const authnSignin = require("./authn_signin");
const fixtures = require("./oauth_fixtures.js");

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
var log = bunyan.createLogger({ name: "sts_dynamic_roles",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const k = wire.kit("sts_dynamic_roles", { log: log });
const check = k.check;
const PASSWORD = "Dyn-Roles-Passw0rd!-" + String(Date.now()).slice(-6);
const ROLE = "dyn-oncall";
const POLICY = [
  "namespace oncall {",
  "    attribute kind {",
  "        category = subjectCat",
  "        id = \"employeeType\"",
  "        type = string",
  "    }",
  "    policy eligible {",
  "        id = \"urn:test:dyn-oncall-eligible\"",
  "        apply denyUnlessPermit",
  "        rule operators {",
  "            permit",
  "            target clause kind == \"operator\"",
  "        }",
  "    }",
  "}"
].join("\n");

function who(name) {
  log.debug("Entering who(). " + name);
  log.debug("Leaving who().");
  return (name + "-" + k.STAMP).slice(0, 30);
}

// The payload of a compact JWS, unverified: what this job reads is a claim.
function payloadOf(jwt) {
  log.debug("Entering payloadOf().");
  const part = String(jwt || "").split(".")[1] || "";
  let out = {};
  try {
    out = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch (e) {
    log.debug("Caught in payloadOf(): " + ((e && e.message) || e));
    out = {};
  }
  log.debug("Leaving payloadOf().");
  return out;
}

// An authorization request for the client, to the sign-in screen, keeping
// the PKCE verifier for the code's redemption.
async function start(realm) {
  log.debug("Entering start().");
  const challenge = fixtures.pkce();
  const started = await fetch(realm.base + "/oauth2/authorize?" +
    new URLSearchParams({ client_id: k.CLIENT, redirect_uri: k.REDIRECT,
      response_type: "code", scope: "openid",
      code_challenge: challenge.challenge,
      code_challenge_method: challenge.method }).toString(),
    { redirect: "manual", headers: k.BROWSER });
  const location = started.headers.get("location") || "";
  assert.ok(/\/authn\/login(?:\?app=[^#]*)?[?#]authn=/.test(location),
            "no sign-in screen: " + started.status + " " + location);
  const set = started.headers.getSetCookie ? started.headers.getSetCookie()
                                           : [];
  const opened = await authnSignin.screen(realm.base, location, {
    cookie: set.map(function (one) {
      return String(one).split(";")[0];
    }).join("; "), headers: k.BROWSER });
  log.debug("Leaving start().");
  return { opened: opened, verifier: challenge.verifier };
}

// A sign-in that went back to the authorization endpoint, followed to the
// client and redeemed: the token response's JSON.
async function tokensAfter(realm, answer, verifier) {
  log.debug("Entering tokensAfter().");
  let where = String(answer.location || "");
  let cookie = String(answer.cookie || "");
  let code = "";
  for (let i = 0; i < 5 && !code; i++) {
    const url = new URL(where, realm.base);
    if (url.toString().indexOf(k.REDIRECT) === 0) {
      code = url.searchParams.get("code") || "";
      break;
    }
    const r = await fetch(url.toString(), { redirect: "manual",
      headers: Object.assign({}, k.BROWSER, cookie ? { cookie: cookie }
                                                   : {}) });
    const set = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
    cookie = authnSignin.foldCookies(cookie, set);
    await r.text();
    where = r.headers.get("location") || "";
    assert.ok(where, "the authorization endpoint answered " + r.status +
                     " with nowhere to go");
  }
  assert.ok(code, "no authorization code reached the client: " + where);
  const r = await fetch(realm.base + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code",
      code: code, redirect_uri: k.REDIRECT, client_id: k.CLIENT,
      code_verifier: verifier }).toString() });
  const json = await r.json();
  assert.ok(r.status === 200 && json.id_token,
            "the token endpoint answered " + r.status + " " +
            JSON.stringify(json).slice(0, 300));
  log.debug("Leaving tokensAfter().");
  return json;
}

function rolesIn(tokens) {
  log.debug("Entering rolesIn().");
  const claims = payloadOf(tokens.id_token);
  const roles = claims.roles;
  log.debug("Leaving rolesIn().");
  return Array.isArray(roles) ? roles : (roles ? [String(roles)] : []);
}

// A. The definition, through /admin-api.
async function definition(realm, op, clerk) {
  log.debug("Entering definition().");
  const made = await k.call(realm, "POST", "/roles/create-role",
    { role: ROLE, membershipMode: "dynamic-selectable",
      displayName: "On call", description: "Operations on call" });
  const policy = await k.call(realm, "POST", "/roles/set-eligibility-policy",
    { role: ROLE, alfa: POLICY });
  check("A1. a dynamic role is made, and its policy set from ALFA",
    function () {
      assert.ok(made.status === 200 && made.body.ok !== false,
                made.raw.slice(0, 300));
      assert.ok(policy.status === 200 && policy.body.ok && policy.body.policy,
                policy.raw.slice(0, 300));
    });
  const member = await k.call(realm, "POST", "/roles/add-member",
    { role: ROLE, kind: "user", member: op });
  check("A2. nobody can be made a member of a dynamic role", function () {
    assert.strictEqual(member.status, 400, member.raw.slice(0, 300));
  });
  const yes = await k.call(realm, "GET", "/roles/eligibility?role=" +
    encodeURIComponent(ROLE) + "&user=" + encodeURIComponent(op));
  const no = await k.call(realm, "GET", "/roles/eligibility?role=" +
    encodeURIComponent(ROLE) + "&user=" + encodeURIComponent(clerk));
  const none = await k.call(realm, "GET", "/roles/eligibility");
  check("A3. the administrator's test: the operator is eligible, the " +
        "clerk is not, and asking nothing answers nothing", function () {
    assert.ok(yes.body.answered === true && yes.body.eligible === true &&
              yes.body.decision === "Permit", yes.raw.slice(0, 300));
    assert.ok(no.body.eligible === false && no.body.decision === "Deny",
              no.raw.slice(0, 300));
    assert.ok(none.status === 200 && none.body.answered === false,
              none.raw.slice(0, 300));
  });
  log.debug("Leaving definition().");
}

async function signInRaw(realm, name, tick) {
  log.debug("Entering signInRaw(). " + name);
  const s = await start(realm);
  const answer = await authnSignin.submit(realm.base, s.opened.id,
    { action: "login", username: name, password: PASSWORD,
      choose_roles: tick ? "1" : undefined },
    { screen: s.opened, cookie: s.opened.cookie, headers: k.BROWSER });
  log.debug("Leaving signInRaw(). " + answer.next + " " + answer.step);
  return { s: s, answer: answer };
}

async function signIns(realm, op, clerk) {
  log.debug("Entering signIns().");
  // B. The box.
  const s0 = await start(realm);
  check("B1. the sign-in screen offers \"Choose roles for this sign-in\"",
    function () {
      assert.strictEqual(s0.opened.view && s0.opened.view.chooseRoles, true,
                         JSON.stringify(s0.opened.view || {}).slice(0, 300));
    });
  // C. Not ticked.
  const plain = await signInRaw(realm, op, false);
  check("C1. not ticked: no role step, straight to the client", function () {
    assert.strictEqual(plain.answer.next, "redirect", k.said(plain.answer));
  });
  const plainTokens = await tokensAfter(realm, plain.answer,
                                        plain.s.verifier);
  check("C2. and the ID Token carries no dynamic role", function () {
    assert.ok(rolesIn(plainTokens).indexOf(ROLE) < 0,
              JSON.stringify(rolesIn(plainTokens)));
  });
  // D. Ticked.
  const ticked = await signInRaw(realm, op, true);
  check("D1. ticked: the sign-in is held at the role step", function () {
    assert.ok(ticked.answer.next === "mfa" &&
              /\/authn\/roles[?#]/.test(String(ticked.answer.location)),
              k.said(ticked.answer));
  });
  const opened = await authnSignin.step(ticked.answer.location,
    { cookie: ticked.answer.cookie, headers: k.BROWSER });
  const offered = ((opened.view && opened.view.roles &&
                    opened.view.roles.offered) || []).map(function (one) {
    return one.name;
  });
  check("D2. the step lists the eligible role, by its display name, and " +
        "nothing of its policy", function () {
    assert.deepStrictEqual(offered, [ROLE], JSON.stringify(opened.view));
    assert.strictEqual(opened.view.roles.offered[0].label, "On call");
    assert.ok(JSON.stringify(opened.view).indexOf("urn:test:dyn-oncall") < 0,
              "the policy is not in the view");
  });
  const fake = await authnSignin.stepAct(opened, "roles",
    { roles: ["ADMIN_WRITE"] });
  check("D3. a role the step did not offer is refused", function () {
    assert.ok(fake.status === 400 || fake.next === "refused" ||
              (fake.json && fake.json.ok === false), k.said(fake));
  });
  const chosen = await authnSignin.stepAct(opened, "roles",
                                           { roles: [ROLE] });
  check("D4. the offered role is chosen and the sign-in completes",
    function () {
      assert.strictEqual(chosen.next, "redirect", k.said(chosen));
    });
  const tokens = await tokensAfter(realm, chosen, ticked.s.verifier);
  check("D5. the ID Token's roles claim carries the chosen role",
    function () {
      assert.ok(rolesIn(tokens).indexOf(ROLE) >= 0,
                JSON.stringify(rolesIn(tokens)));
    });
  const audit = await k.call(realm, "GET",
                             "/audit?action=roles.selection.chosen");
  check("D6. the choice is audited as roles.selection.chosen", function () {
    const rows = (audit.body && (audit.body.rows || audit.body.events)) || [];
    assert.ok(rows.length >= 1, audit.raw.slice(0, 300));
  });
  // E. Not eligible.
  const notMine = await signInRaw(realm, clerk, true);
  check("E1. a person the policy does not permit is offered nothing: no " +
        "step, signed in", function () {
    assert.strictEqual(notMine.answer.next, "redirect",
                       k.said(notMine.answer));
  });
  const clerkTokens = await tokensAfter(realm, notMine.answer,
                                        notMine.s.verifier);
  check("E2. and carries no dynamic role", function () {
    assert.ok(rolesIn(clerkTokens).indexOf(ROLE) < 0,
              JSON.stringify(rolesIn(clerkTokens)));
  });
  log.debug("Leaving signIns().");
}

async function turnedOff(realm) {
  log.debug("Entering turnedOff().");
  const set = await k.call(realm, "POST", "/applications/set", {
    application: k.CLIENT, attribute: "appDynamicRoleSelection",
    value: "FALSE" });
  assert.ok(set.status === 200 && set.body.ok !== false,
            set.raw.slice(0, 300));
  const s = await start(realm);
  check("F1. turned off for the client, the screen offers no box",
    function () {
      assert.ok(!(s.opened.view && s.opened.view.chooseRoles),
                JSON.stringify(s.opened.view || {}).slice(0, 300));
    });
  log.debug("Leaving turnedOff().");
}

// G. A required role.
async function required(realm, op, clerk) {
  log.debug("Entering required().");
  const set = await k.call(realm, "POST", "/roles/set-selection",
    { role: ROLE, selection: "required" });
  assert.ok(set.status === 200 && set.body.ok !== false,
            set.raw.slice(0, 300));
  const held = await signInRaw(realm, op, false);
  check("G1. a required role draws the step though the box is not ticked",
    function () {
      assert.ok(held.answer.next === "mfa" &&
                /\/authn\/roles[?#]/.test(String(held.answer.location)),
                k.said(held.answer));
    });
  const opened = await authnSignin.step(held.answer.location,
    { cookie: held.answer.cookie, headers: k.BROWSER });
  const chosen = await authnSignin.stepAct(opened, "roles",
                                           { roles: [ROLE] });
  const grant = async function (name) {
    log.debug("Entering grant(). " + name);
    const r = await fetch(realm.base + "/oauth2/token", { method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "password", username: name,
        password: PASSWORD, client_id: k.CLIENT,
        scope: "openid" }).toString() });
    const json = await r.json().catch(function () { return {}; });
    log.debug("Leaving grant(). " + r.status);
    return { status: r.status, json: json };
  };
  const refusedGrant = await grant(op);
  const clerkGrant = await grant(clerk);
  check("G2. the password grant is refused access_denied for the eligible " +
        "person, and answered for the clerk", function () {
    assert.ok(refusedGrant.status === 400 &&
              refusedGrant.json.error === "access_denied",
              JSON.stringify(refusedGrant).slice(0, 300));
    assert.ok(clerkGrant.status === 200 && clerkGrant.json.access_token,
              JSON.stringify(clerkGrant).slice(0, 300));
  });
  const second = "dyn-client-2-" + k.STAMP;
  await k.client(realm, second);
  const authorize = async function (extra) {
    log.debug("Entering authorize().");
    const challenge = fixtures.pkce();
    const r = await fetch(realm.base + "/oauth2/authorize?" +
      new URLSearchParams(Object.assign({ client_id: second,
        redirect_uri: k.REDIRECT, response_type: "code", scope: "openid",
        state: "g", code_challenge: challenge.challenge,
        code_challenge_method: challenge.method }, extra || {}))
        .toString(),
      { redirect: "manual", headers: Object.assign({}, k.BROWSER,
        { cookie: String(chosen.cookie || "") }) });
    await r.text();
    log.debug("Leaving authorize(). " + r.status);
    return String(r.headers.get("location") || "");
  };
  const toScreen = await authorize();
  const passive = await authorize({ prompt: "none" });
  check("G3. single sign-on into a client the session chose nothing for " +
        "goes to the sign-in screen, and prompt=none is " +
        "interaction_required", function () {
    assert.ok(/\/authn\/login/.test(toScreen), toScreen);
    assert.ok(passive.indexOf(k.REDIRECT) === 0 &&
              new URL(passive).searchParams.get("error") ===
                "interaction_required", passive);
  });
  log.debug("Leaving required().");
}

async function test() {
  log.debug("Entering test().");
  const realm = await k.realm("dyn-roles", "development");
  await k.client(realm);
  await k.mustSet(realm, "oauth2.consentRequired", false);
  log.info("Driving " + realm.base);
  const op = who("dyn-op");
  const clerk = who("dyn-clerk");
  await k.person(realm, op, PASSWORD, { employeeType: "operator" });
  await k.person(realm, clerk, PASSWORD, { employeeType: "clerk" });
  await definition(realm, op, clerk);
  await signIns(realm, op, clerk);
  await required(realm, op, clerk);
  await turnedOff(realm);
  assert.ok(k.checks() >= 17, "only " + k.checks() + " checks ran; a " +
            "section has stopped being called.");
  log.debug("Leaving test().");
}

k.main(test);
