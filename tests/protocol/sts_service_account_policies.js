// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_service_account_policies.js
//
// ---------------------------------------------------------------------------
// A SERVICE ACCOUNT'S OWNERS AND THE NAMED POLICY IT NAMES, OVER THE WIRE
// (#600, #602, #1240).
//
// D12 (#444): carries over, through `/admin-api` and the directory's own
// LDAPS socket, in throwaway development realms this job creates and leaves
// behind:
//
//   A. tests/service_account_owners.js A, B and F: a person and a group own
//      an account, each once whatever it was called, in the order given; a
//      string is one owner per line and REPLACES the list; an empty list
//      and no `owners` are refused (STS-SVCACCT-0061); one owner who is
//      nobody refuses the whole set and writes nothing (0024); more than
//      twenty-five is refused (0031) and exactly twenty-five is not; with
//      `requireOwner` off the list still may not be emptied (0061); an
//      owner deleted is taken off the list and the other kept (#1612); an
//      LDAP modify writes two owners and is refused one naming nobody; the
//      one-at-a-time acts add an owner beside the others, never twice,
//      refuse to take off a non-owner (0032) or the last owner (0061), keep the
//      owners when a destination is cleared, refuse a destination that is
//      no secret destination, and refuse an ordinary person (0033); the
//      person page carries the rules the form is held to.
//   B. tests/service_account_policy_selection.js A, B, C and E: a named
//      profile is saved whole with a precedence, listed after `default` by
//      precedence with who names it, refused a malformed name or a
//      precedence out of 1..1000, and is the realm's own; a person who is
//      not a service account is refused a reference (STS-SVCACCT-0048), as
//      is a name the realm does not hold (STS-LDAP-0106), at the person
//      editor and over LDAP; a create naming one without the flag is
//      refused before anybody exists; clearing the flag is refused (0060)
//      and the reference stays; each account's LDAP door and browser follow
//      the profile it names, and neither profile lets its owner go (0061);
//      and a named profile an account names is not deleted
//      (STS-SVCACCT-0049) until nothing does.
//
// What stays in process is in each file's D12 note: the console's search,
// draft and section (drawn by the browser's bundle), the directory merge's
// list rule, an unknown reference falling back (it cannot be written over
// the wire), and the rotation job against a fake destination.
//
// Its realms are removed at the end only when STS_TEST_REMOVE_REALMS is
// "1" (a shared private probe would fill otherwise); the suite leaves them.
//
// OWNED HERE (local: true): this repository's own management API and
// directory.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const authnSignin = require("./authn_signin.js");

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
var log = bunyan.createLogger({ name: "sts_service_account_policies",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
function realmId(prefix) {
  log.debug("Entering realmId().");
  log.debug("Leaving realmId().");
  return (prefix + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
    .slice(0, 31);
}
const OWNERS = realmId("sao-");
const SELECT = realmId("sas-");
const OTHER = realmId("sax-");
const PASSWORD = "Sv1c-Acc0unt-Pa55word!x";
const MAX_OWNERS = 25;
const WEB = "sa-web";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function send(url, options) {
  log.debug("Entering send(). url=" + url);
  const r = await fetch(url, Object.assign({ redirect: "manual" },
                                           options || {}));
  const raw = await r.text();
  let body = null;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // Not JSON — an empty answer or a page; the caller reads `raw`.
    body = null;
  }
  log.debug("Leaving send(). status=" + r.status);
  return { status: r.status, body: body, raw: raw };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=1&code=" + encodeURIComponent(code));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving codeCount().");
  return Number(r.body.matched || 0);
}

// Runs `act` and answers it with how far the code's count on the realm's
// audit grew: a code is recorded, never sent.
async function coded(api, code, act) {
  log.debug("Entering coded(). " + code);
  const before = await codeCount(api, code);
  const answer = await act();
  let now = before;
  for (let i = 0; i < 20 && now <= before; i += 1) {
    now = await codeCount(api, code);
    if (now <= before) {
      await sleep(150);
    }
  }
  log.debug("Leaving coded(). " + before + " -> " + now);
  return { answer: answer, grew: now - before };
}

function refusedWith(got, code, what) {
  log.debug("Entering refusedWith(). " + code);
  check(what + ", recorded as " + code, function () {
    assert.ok(got.answer.status >= 400 && got.answer.status < 500,
              got.answer.status + " " + got.answer.raw.slice(0, 300));
    assert.ok(got.grew >= 1, code + " rows grew by " + got.grew);
    assert.ok(got.answer.raw.indexOf(code) < 0, "the code was sent");
  });
  log.debug("Leaving refusedWith().");
}

function apiOf(realm) {
  log.debug("Entering apiOf().");
  log.debug("Leaving apiOf().");
  return base + "/realm/" + realm + "/admin-api";
}

function dnOf(realm, who) {
  log.debug("Entering dnOf().");
  log.debug("Leaving dnOf().");
  return "uid=" + who + ",ou=users,dc=" + realm + ",dc=example,dc=net";
}

function person(api, who) {
  log.debug("Entering person(). " + who);
  log.debug("Leaving person().");
  return ok(api + "/users/create", { username: who, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "Person " + who, givenName: "Person", sn: who,
                  mail: who + "@sa.example.net" } }, "created " + who);
}

async function account(api, who, owner) {
  log.debug("Entering account(). " + who);
  await person(api, who);
  const made = await ok(api + "/users/set-service-account", { user: who,
    owners: [owner] }, "made " + who + " a service account");
  log.debug("Leaving account().");
  return made;
}

async function ownersOf(api, who) {
  log.debug("Entering ownersOf(). " + who);
  const r = await send(api + "/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const sa = r.body.serviceAccount;
  log.debug("Leaving ownersOf().");
  return { view: r.body, account: sa, owners: sa ? sa.owners : [] };
}

function attributesOf(view) {
  log.debug("Entering attributesOf().");
  const ldap = (view && view.ldap) || {};
  log.debug("Leaving attributesOf().");
  return (ldap.entry && ldap.entry.attributes) || {};
}

function valuesOf(view, name) {
  log.debug("Entering valuesOf(). " + name);
  const attributes = attributesOf(view);
  const key = Object.keys(attributes).filter(function (k) {
    return k.toLowerCase() === name.toLowerCase();
  })[0];
  log.debug("Leaving valuesOf().");
  return key ? attributes[key].map(String) : [];
}

// The whole service-account profile with `changes` on top: a save replaces
// the whole profile.
async function fullPolicy(api, changes) {
  log.debug("Entering fullPolicy().");
  const r = await send(api + "/policies");
  const out = Object.assign({}, r.body.serviceAccount.defaults,
                            changes || {});
  log.debug("Leaving fullPolicy().");
  return out;
}

function ldapUrl() {
  log.debug("Entering ldapUrl().");
  const host = new URL(base).hostname;
  log.debug("Leaving ldapUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + host + ":" + (process.env.STS_LDAPS_PORT || 636));
}

// One LDAPS connection bound as `dn`; `then(client)` runs on it. Answers the
// bind's result code and what `then` answered.
function overLdap(dn, password, then) {
  log.debug("Entering overLdap(). dn=" + dn);
  log.debug("Leaving overLdap().");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: ldapUrl(), reconnect: false,
      timeout: 20000, connectTimeout: 15000,
      tlsOptions: { rejectUnauthorized:
                      process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0" } });
    client.on("error", function (e) {
      // The operation in flight reports it; an unhandled 'error' would throw.
      log.debug("The LDAP client emitted an error: " + e.message);
    });
    client.bind(dn, password, function (e) {
      if (e || !then) {
        client.unbind();
        resolve({ code: e ? e.code : 0, then: null });
        return;
      }
      then(client).then(function (out) {
        client.unbind();
        resolve({ code: 0, then: out });
      }, function (err) {
        log.debug("Caught in overLdap(): " + ((err && err.message) || err));
        client.unbind();
        resolve({ code: 0, then: { code: (err && err.code) || -1 } });
      });
    });
  });
}

function modify(client, dn, changes) {
  log.debug("Entering modify(). dn=" + dn);
  log.debug("Leaving modify().");
  return new Promise(function (resolve) {
    client.modify(dn, changes.map(function (one) {
      return new ldapjs.Change({ operation: one[0],
        modification: new ldapjs.Attribute({ type: one[1],
                                             values: one[2] }) });
    }), function (e) {
      // The refusal's text is the result's diagnosticMessage (#261).
      resolve({ code: e ? e.code : 0, message: e ? String(
        e.diagnosticMessage || e.lde_message || e.message || "") : "" });
    });
  });
}

function del(client, dn) {
  log.debug("Entering del(). dn=" + dn);
  log.debug("Leaving del().");
  return new Promise(function (resolve) {
    client.del(dn, function (e) {
      resolve({ code: e ? e.code : 0, message: e ? e.message : "" });
    });
  });
}

// The sign-in screen for `who`, through an authorization request of the
// realm's public client `WEB`, as a browser reaches it.
async function screenSignIn(realm, who) {
  log.debug("Entering screenSignIn(). " + who);
  const realmBase = base + "/realm/" + realm;
  const verifier = crypto.randomBytes(32).toString("base64url");
  const at = await fetch(realmBase + "/oauth2/authorize?" +
    new URLSearchParams({ response_type: "code", client_id: WEB,
      redirect_uri: "https://sa-web.example.net/cb", scope: "openid",
      state: "s-" + STAMP, code_challenge_method: "S256",
      code_challenge: crypto.createHash("sha256").update(verifier)
        .digest("base64url") }).toString(), { redirect: "manual" });
  const where = new URL(at.headers.get("location") || "", realmBase)
    .toString();
  const answer = await authnSignin.signIn(realmBase, where,
    { action: "login", username: who, password: PASSWORD }, {});
  log.debug("Leaving screenSignIn(). " + answer.next);
  return answer;
}

async function aRealm(id) {
  log.debug("Entering aRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Service account policies " + STAMP },
    "created the realm " + id);
  await ok(apiOf(id) + "/applications/create", { identifier: WEB,
    kind: "oauth2-client", name: WEB, protocols: ["oauth2", "oidc"],
    fields: { oauthClientId: [WEB], oauthTokenEndpointAuthMethod: "none",
              oauthGrantType: ["authorization_code"],
              oauthRedirectUri: ["https://sa-web.example.net/cb"] } },
    "created the realm's sign-in client");
  log.debug("Leaving aRealm().");
}

async function theList() {
  log.debug("Entering theList().");
  log.info("=== A1. a service account's list of owners ===");
  const api = apiOf(OWNERS);
  for (const who of ["sao", "sao-ann", "sao-bob"]) {
    await person(api, who);
  }
  await ok(api + "/groups/create", { group: "sao-ops" }, "made a group");
  const annDn = dnOf(OWNERS, "sao-ann");
  const made = await ok(api + "/users/set-service-account", { user: "sao",
    owners: ["sao-ann", "sao-ops", annDn.toUpperCase()] },
    "named a person, a group and the person again");
  check("a person and a group own it, each once, in the order given",
        function () {
    const owners = made.account.owners;
    assert.strictEqual(owners.length, 2, JSON.stringify(owners));
    assert.deepStrictEqual(owners.map(function (o) {
      return o.kind + ":" + o.name;
    }), ["person:sao-ann", "group:sao-ops"]);
  });
  const stored = await ownersOf(api, "sao");
  check("the entry holds one stsServiceAccountOwner value per owner",
        function () {
    assert.strictEqual(valuesOf(stored.view, "stsServiceAccountOwner")
      .length, 2);
  });
  const lines = await ok(api + "/users/set-service-account", { user: "sao",
    owners: "sao-bob\n\n sao-ann \n" }, "named owners one per line");
  check("a string is one owner per line, and the list is REPLACED",
        function () {
    assert.deepStrictEqual(lines.account.owners.map(function (o) {
      return o.name;
    }), ["sao-bob", "sao-ann"]);
  });
  const setTo = function (body) {
    return function () {
      return postJson(api + "/users/set-service-account",
                      Object.assign({ user: "sao" }, body));
    };
  };
  // An account that names owners never loses its last (rcbj, 2026-11-15).
  refusedWith(await coded(api, "STS-SVCACCT-0061", setTo({ owners: [] })),
    "STS-SVCACCT-0061", "an empty list is refused: the account names " +
    "owners now");
  refusedWith(await coded(api, "STS-SVCACCT-0061", setTo({})),
    "STS-SVCACCT-0061", "and so is no `owners` at all: a set replaces the " +
    "list");
  refusedWith(await coded(api, "STS-SVCACCT-0024",
    setTo({ owners: ["sao-ann", "nobody-at-all"] })),
    "STS-SVCACCT-0024", "one owner who is nobody refuses the whole set");
  const unchanged = await ownersOf(api, "sao");
  check("and nothing is written", function () {
    assert.strictEqual(valuesOf(unchanged.view, "stsServiceAccountOwner")
      .length, 2);
  });
  const many = [];
  for (let i = 0; i <= MAX_OWNERS; i += 1) {
    await person(api, "sao-p" + i);
    many.push("sao-p" + i);
  }
  refusedWith(await coded(api, "STS-SVCACCT-0031", setTo({ owners: many })),
    "STS-SVCACCT-0031", "more than " + MAX_OWNERS + " owners is refused");
  const enough = await postJson(api + "/users/set-service-account",
    { user: "sao", owners: many.slice(0, MAX_OWNERS) });
  check("and exactly " + MAX_OWNERS + " is not", function () {
    assert.strictEqual(enough.status, 200, enough.raw.slice(0, 300));
    assert.strictEqual(enough.body.account.owners.length, MAX_OWNERS);
  });
  await ok(api + "/policies/save-serviceAccount-policy",
           await fullPolicy(api, { requireOwner: false }),
           "turned requireOwner off");
  refusedWith(await coded(api, "STS-SVCACCT-0061", function () {
    return postJson(api + "/users/set-service-account",
                    { user: "sao", owners: "" });
  }), "STS-SVCACCT-0061", "with requireOwner off the list still may not " +
      "be emptied once it names an owner");
  const bare = await ownersOf(api, "sao");
  check("and every owner is still on the entry", function () {
    assert.strictEqual(valuesOf(bare.view, "stsServiceAccountOwner").length,
                       MAX_OWNERS);
  });
  await ok(api + "/policies/reset-serviceAccount-policy",
           { profile: "default" }, "reset the policy");
  await ok(api + "/users/set-service-account", { user: "sao",
    owners: ["sao-ann", "sao-bob"] }, "named two owners");
  const bobDn = dnOf(OWNERS, "sao-bob");
  const gone = await overLdap(dnOf(OWNERS, "sao-ann"), PASSWORD,
                              function (client) {
    return del(client, bobDn);
  });
  const after = await ownersOf(api, "sao");
  check("an owner deleted is taken off the list, and the other owner kept",
        function () {
    assert.strictEqual(gone.then.code, 0, JSON.stringify(gone));
    assert.strictEqual(after.owners.length, 1, JSON.stringify(after.owners));
    assert.strictEqual(after.owners[0].dn.toLowerCase(), annDn.toLowerCase());
    assert.strictEqual(after.owners[0].kind, "person");
  });
  check("the person page carries the rules the form is held to",
        function () {
    const rules = after.view.page && after.view.page.serviceAccountRules;
    assert.ok(rules, JSON.stringify(Object.keys(after.view.page || {})));
    assert.strictEqual(rules.requiresOwner, true);
    assert.strictEqual(rules.maxOwners, MAX_OWNERS);
    assert.strictEqual(String(rules.dn).toLowerCase(),
                       dnOf(OWNERS, "sao").toLowerCase());
    assert.strictEqual(after.account.policy.requiresOwner, true);
  });
  log.debug("Leaving theList().");
}

async function theLdapModify() {
  log.debug("Entering theLdapModify().");
  log.info("=== A2. an LDAP modify writes owners ===");
  const api = apiOf(OWNERS);
  for (const who of ["sal", "sal-a", "sal-b"]) {
    await person(api, who);
  }
  const dn = dnOf(OWNERS, "sal");
  const two = await overLdap(dn, PASSWORD, function (client) {
    return modify(client, dn, [
      ["replace", "stsServiceAccount", ["TRUE"]],
      ["replace", "stsServiceAccountOwner", [dnOf(OWNERS, "sal-a"),
                                             dnOf(OWNERS, "sal-b")]]]);
  });
  const read = await ownersOf(api, "sal");
  check("an LDAP modify writes two owners", function () {
    assert.strictEqual(two.then.code, 0, JSON.stringify(two));
    assert.strictEqual(read.owners.length, 2, JSON.stringify(read.owners));
  });
  const nobody = await overLdap(dn, PASSWORD, function (client) {
    return modify(client, dn, [["add", "stsServiceAccountOwner",
      ["uid=nobody,ou=users,dc=" + OWNERS + ",dc=example,dc=net"]]]);
  });
  const still = await ownersOf(api, "sal");
  check("and is refused one that names nobody", function () {
    assert.notStrictEqual(nobody.then.code, 0, JSON.stringify(nobody));
    assert.strictEqual(still.owners.length, 2);
  });
  log.debug("Leaving theLdapModify().");
}

async function oneAtATime() {
  log.debug("Entering oneAtATime().");
  log.info("=== A3. one owner, or the destination, at a time ===");
  const api = apiOf(OWNERS);
  for (const who of ["saf-ann", "saf-bo", "saf-plain"]) {
    await person(api, who);
  }
  await account(api, "saf", "saf-ann");
  const ann = dnOf(OWNERS, "saf-ann");
  const bo = dnOf(OWNERS, "saf-bo");
  const added = await ok(api + "/users/add-service-account-owner",
    { user: "saf", owner: bo }, "added an owner");
  check("an owner added is written beside the old at once, and the act " +
        "answers the account", function () {
    assert.strictEqual(added.changed, true);
    assert.strictEqual(added.account.owners.length, 2);
    assert.ok(/is now an owner of saf/.test(added.message), added.message);
  });
  const twice = await ok(api + "/users/add-service-account-owner",
    { user: "saf", owner: "saf-bo" }, "added the same owner by name");
  check("an owner already listed, by another name, is not listed twice",
        function () {
    assert.strictEqual(twice.changed, false);
    assert.strictEqual(twice.account.owners.length, 2);
  });
  refusedWith(await coded(api, "STS-SVCACCT-0032", function () {
    return postJson(api + "/users/remove-service-account-owner",
                    { user: "saf", owner: dnOf(OWNERS, "saf-plain") });
  }), "STS-SVCACCT-0032", "taking off somebody who is not an owner is " +
      "refused");
  const off = await ok(api + "/users/remove-service-account-owner",
    { user: "saf", owner: bo.toUpperCase() }, "took an owner off");
  check("one is taken off, whatever its case", function () {
    assert.strictEqual(off.account.owners.length, 1);
    assert.strictEqual(off.account.owners[0].dn.toLowerCase(),
                       ann.toLowerCase());
  });
  refusedWith(await coded(api, "STS-SVCACCT-0061", function () {
    return postJson(api + "/users/remove-service-account-owner",
                    { user: "saf", owner: ann });
  }), "STS-SVCACCT-0061", "the last owner stays, whatever the policy");
  const kept = await ownersOf(api, "saf");
  check("and is still listed", function () {
    assert.strictEqual(kept.owners.length, 1);
  });
  const half = await postJson(api + "/users/set-service-account-destination",
    { user: "saf", destination: "", secretName: "only-a-name" });
  const cleared = await postJson(api +
    "/users/set-service-account-destination",
    { user: "saf", destination: "", secretName: "" });
  check("a destination is both or neither, and clearing it keeps the " +
        "owners", function () {
    assert.strictEqual(half.status, 400, half.raw.slice(0, 300));
    assert.strictEqual(cleared.status, 200, cleared.raw.slice(0, 300));
    assert.strictEqual(cleared.body.account.owners.length, 1);
    assert.ok(!cleared.body.account.destination);
  });
  const nowhere = await postJson(api +
    "/users/set-service-account-destination",
    { user: "saf", destination: "cn=nowhere,ou=applications,dc=" + OWNERS +
      ",dc=example,dc=net", secretName: "s" });
  check("a destination that is no secret destination is refused",
        function () {
    assert.strictEqual(nowhere.status, 400, nowhere.raw.slice(0, 300));
  });
  refusedWith(await coded(api, "STS-SVCACCT-0033", function () {
    return postJson(api + "/users/add-service-account-owner",
                    { user: "saf-plain", owner: ann });
  }), "STS-SVCACCT-0033", "an ordinary person has no owners to add to");
  const plain = await ownersOf(api, "saf-plain");
  check("and is not made a service account by it", function () {
    assert.strictEqual(plain.account, null);
  });
  log.debug("Leaving oneAtATime().");
}

async function saveNamed(api, profile, changes, precedence) {
  log.debug("Entering saveNamed(). " + profile);
  const body = Object.assign(await fullPolicy(api, changes),
    { profile: profile, precedence: precedence === undefined ? 50
                                                             : precedence });
  const saved = await ok(api + "/policies/save-serviceAccount-policy", body,
                         "saved the named profile " + profile);
  log.debug("Leaving saveNamed().");
  return saved;
}

async function theProfiles() {
  log.debug("Entering theProfiles().");
  log.info("=== B1. named service-account profiles ===");
  const api = apiOf(SELECT);
  const bad = await postJson(api + "/policies/save-serviceAccount-policy",
    Object.assign(await fullPolicy(api), { profile: "Not A Name" }));
  const high = await postJson(api + "/policies/save-serviceAccount-policy",
    Object.assign(await fullPolicy(api), { profile: "weekly",
                                           precedence: 1001 }));
  check("a malformed name and a precedence out of 1..1000 are refused",
        function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 300));
    assert.strictEqual(high.status, 400, high.raw.slice(0, 300));
  });
  await saveNamed(api, "weekly", { rotationIntervalDays: 7,
                                   allowLdapBind: false }, 20);
  await saveNamed(api, "alpha", {}, 90);
  const view = await send(api + "/policies");
  const sa = view.body.serviceAccount;
  const weekly = (sa.named || []).filter(function (one) {
    return one.name === "weekly";
  })[0];
  check("a named profile is saved whole with its precedence, and listed " +
        "with who names it", function () {
    assert.ok(weekly, JSON.stringify(Object.keys(sa)));
    assert.strictEqual(weekly.precedence, 20);
    assert.ok(weekly.namedBy && Array.isArray(weekly.namedBy.people),
              JSON.stringify(weekly));
    const kind = view.body.kinds.filter(function (k) {
      return k.id === "serviceAccount";
    })[0];
    assert.strictEqual(kind.tabbed, true);
  });
  check("listed after default, by precedence", function () {
    const listed = (sa.profiles || sa.named || []).map(function (one) {
      return one.name;
    });
    const order = listed.filter(function (n) {
      return n === "weekly" || n === "alpha";
    });
    assert.deepStrictEqual(order, ["weekly", "alpha"], JSON.stringify(listed));
  });
  const elsewhere = await send(apiOf(OTHER) + "/policies");
  check("a named profile is the realm's own: another realm does not hold " +
        "it", function () {
    assert.ok(!(elsewhere.body.serviceAccount.named || []).some(
      function (one) {
        return one.name === "weekly";
      }), JSON.stringify(elsewhere.body.serviceAccount.named));
  });
  log.debug("Leaving theProfiles().");
}

async function theReference() {
  log.debug("Entering theReference().");
  log.info("=== B2. the reference, at every door ===");
  const api = apiOf(SELECT);
  await person(api, "sab-owner");
  await person(api, "sab-person");
  await account(api, "sab-acct", "sab-owner");
  await saveNamed(api, "narrow", { allowLdapBind: false });
  const name = function (who, value) {
    return function () {
      return postJson(api + "/users/set-attribute", { user: who,
        attribute: "stsServiceAccountPolicy", value: value });
    };
  };
  refusedWith(await coded(api, "STS-SVCACCT-0048",
                          name("sab-person", "narrow")),
    "STS-SVCACCT-0048", "a person who is not a service account is refused " +
    "a reference");
  refusedWith(await coded(api, "STS-LDAP-0106", name("sab-acct", "nowhere")),
    "STS-LDAP-0106", "a name the realm does not hold is refused");
  await ok(api + "/users/set-attribute", { user: "sab-acct",
    attribute: "stsServiceAccountPolicy", value: "narrow" },
    "named the profile");
  const named = await ownersOf(api, "sab-acct");
  check("a service account names a held profile, read with the account",
        function () {
    assert.strictEqual(named.account.policy.name, "narrow",
                       JSON.stringify(named.account.policy));
    assert.ok(named.account.policy.doors.indexOf("ldap") < 0,
              JSON.stringify(named.account.policy.doors));
    assert.deepStrictEqual(valuesOf(named.view, "stsServiceAccountPolicy"),
                           ["narrow"]);
  });
  const notOne = await overLdap(dnOf(SELECT, "sab-person"), PASSWORD,
                                function (client) {
    return modify(client, dnOf(SELECT, "sab-person"),
                  [["replace", "stsServiceAccountPolicy", ["narrow"]]]);
  });
  const unknown = await overLdap(dnOf(SELECT, "sab-owner"), PASSWORD,
                                 function (client) {
    return modify(client, dnOf(SELECT, "sab-acct"),
                  [["replace", "stsServiceAccountPolicy", ["nowhere"]]]);
  });
  const kept = await ownersOf(api, "sab-acct");
  check("an LDAP modify meets the same two rules", function () {
    assert.notStrictEqual(notOne.then.code, 0, JSON.stringify(notOne));
    assert.ok(/SERVICE ACCOUNT/.test(notOne.then.message),
              notOne.then.message);
    assert.notStrictEqual(unknown.then.code, 0, JSON.stringify(unknown));
    assert.ok(/stsServiceAccountPolicy/.test(unknown.then.message),
              unknown.then.message);
    assert.deepStrictEqual(valuesOf(kept.view, "stsServiceAccountPolicy"),
                           ["narrow"]);
  });
  const created = await coded(api, "STS-SVCACCT-0048", function () {
    return postJson(api + "/users/create", { username: "sab-new",
      invent: false, credential: "none",
      attributes: { givenName: "New", sn: "Person",
                    mail: "sab-new@sa.example.net",
                    stsServiceAccountPolicy: "narrow" } });
  });
  refusedWith(created, "STS-SVCACCT-0048", "a create naming it without " +
              "the flag is refused");
  const nobody = await send(api + "/users?q=sab-new");
  check("and nobody was made", function () {
    assert.ok(!(nobody.body.users || []).some(function (row) {
      return row.key === "sab-new";
    }));
  });
  // A service account is never made a person again (rcbj, 2026-11-15).
  refusedWith(await coded(api, "STS-SVCACCT-0060", function () {
    return postJson(api + "/users/set-service-account",
                    { user: "sab-acct", serviceAccount: false });
  }), "STS-SVCACCT-0060", "the account cannot be made a person again");
  const cleared = await ownersOf(api, "sab-acct");
  check("and it keeps the reference", function () {
    assert.deepStrictEqual(valuesOf(cleared.view, "stsServiceAccountPolicy"),
                           ["narrow"]);
  });
  log.debug("Leaving theReference().");
}

async function theReaders() {
  log.debug("Entering theReaders().");
  log.info("=== B3. each account is governed by the profile it names ===");
  const api = apiOf(SELECT);
  await person(api, "sac-owner");
  await account(api, "sac-named", "sac-owner");
  await account(api, "sac-plain", "sac-owner");
  await saveNamed(api, "loose", { allowLdapBind: false,
    allowBrowserSignIn: true, exemptFromSecondFactor: true,
    requireOwner: false });
  await ok(api + "/users/set-attribute", { user: "sac-named",
    attribute: "stsServiceAccountPolicy", value: "loose" },
    "named the loose profile");
  const namedBind = await overLdap(dnOf(SELECT, "sac-named"), PASSWORD);
  const plainBind = await overLdap(dnOf(SELECT, "sac-plain"), PASSWORD);
  check("the LDAP door follows each account's own profile", function () {
    assert.strictEqual(namedBind.code, 49);
    assert.strictEqual(plainBind.code, 0);
  });
  const namedScreen = await screenSignIn(SELECT, "sac-named");
  const plainScreen = await screenSignIn(SELECT, "sac-plain");
  check("and so does the browser", function () {
    assert.strictEqual(namedScreen.next, "redirect",
                       JSON.stringify(namedScreen.json));
    assert.strictEqual(plainScreen.next, "refused",
                       JSON.stringify(plainScreen.json));
  });
  // Both name an owner, so neither may lose it whatever its profile says
  // (rcbj, 2026-11-15); requireOwner is the create's question now.
  refusedWith(await coded(api, "STS-SVCACCT-0061", function () {
    return postJson(api + "/users/set-service-account",
                    { user: "sac-named", owners: [] });
  }), "STS-SVCACCT-0061", "an account under a profile with requireOwner " +
      "off still keeps its owner");
  refusedWith(await coded(api, "STS-SVCACCT-0061", function () {
    return postJson(api + "/users/set-service-account",
                    { user: "sac-plain", owners: [] });
  }), "STS-SVCACCT-0061", "and so does one naming default");
  log.debug("Leaving theReaders().");
}

async function theDelete() {
  log.debug("Entering theDelete().");
  log.info("=== B4. a profile an account names is not deleted ===");
  const api = apiOf(SELECT);
  refusedWith(await coded(api, "STS-SVCACCT-0049", function () {
    return postJson(api + "/policies/reset-serviceAccount-policy",
                    { profile: "loose" });
  }), "STS-SVCACCT-0049", "a named profile an account names is not deleted");
  await ok(api + "/users/set-attribute", { user: "sac-named",
    attribute: "stsServiceAccountPolicy", value: "" },
    "took the reference off");
  const gone = await postJson(api + "/policies/reset-serviceAccount-policy",
                              { profile: "loose" });
  const view = await send(api + "/policies");
  check("and is once nothing names it", function () {
    assert.strictEqual(gone.status, 200, gone.raw.slice(0, 300));
    assert.ok(!(view.body.serviceAccount.named || []).some(function (one) {
      return one.name === "loose";
    }));
  });
  log.debug("Leaving theDelete().");
}

async function testBody() {
  log.debug("Entering testBody().");
  for (const id of [OWNERS, SELECT, OTHER]) {
    await aRealm(id);
  }
  await theList();
  await theLdapModify();
  await oneAtATime();
  await theProfiles();
  await theReference();
  await theReaders();
  await theDelete();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving testBody().");
}

// THE REALMS ARE REMOVED ONLY WHEN STS_TEST_REMOVE_REALMS IS "1": a private
// probe many jobs share fills its directory otherwise, while the suite's own
// rule (tests/CLAUDE.md, *No job removes a realm*) leaves them standing.
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS === "1") {
    for (const id of [OWNERS, SELECT, OTHER]) {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("Removed the realm " + id + ": " + r.status);
    }
  }
  log.debug("Leaving removeRealms().");
}

async function test() {
  log.debug("Entering test().");
  try {
    await testBody();
  } finally {
    await removeRealms();
  }
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_service_account_policies FAILED: " +
            ((e && e.stack) || e));
  process.exit(1);
});
