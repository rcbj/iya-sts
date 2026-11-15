// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_named_policies.js
//
// ---------------------------------------------------------------------------
// NAMED LOCALE AND AUTHENTICATION POLICIES, AND AN ORDERED CHOICE FROM A
// CLOSED LIST, OVER THE WIRE (D12, #444).
//
// In two throwaway realms it leaves behind, through `/admin-api`, the
// authorization endpoint, `/authn-api` and the shells the browser is given:
//
//   L. THE LOCALE POLICY (D12: carries over tests/locale_policy.js A-D and
//      the shell's half of E). `default` saved whole and its tag
//      canonicalised; a malformed tag and a field left out refused
//      (STS-I18N-0004), a malformed name and a precedence outside 1-1000 by
//      the request schema first (STS-API-0009); named
//      profiles listed by precedence; an application names one
//      (STS-REG-0203 for one the realm lacks) and so does a group
//      (STS-LDAP-0195); `namedBy` says who; a profile still named is not
//      deleted (STS-I18N-0014) and is once nothing names it; the front
//      door's shell carries the realm's default and the sign-in screen's
//      shell the application's profile (`data-sts-locale-default`); a
//      person created with no preferredLanguage is given the default's tag,
//      one created with a language keeps it, a removed one is not put back
//      by a later write, and a profile with population off gives none;
//      another realm sees none of it.
//   A. NAMED AUTHENTICATION POLICIES (D12: carries over
//      tests/named_authn_policies.js A, B, D, E, G and the sign-in half of
//      C). Saved and listed with its two lists; a bad name (the request
//      schema, STS-API-0009), `default` (STS-AUTHN-0532) and each unknown
//      mechanism (0533) refused;
//      `appAuthnPolicy`'s choices are `default` and the realm's policies,
//      and one the realm lacks is refused (STS-REG-0203); the sign-in
//      screen for an application naming a passkeys-only policy offers no
//      password where a plain one does; a policy named is not deleted
//      (STS-AUTHN-0534, naming the application), is once nothing names it,
//      and a name nobody holds is refused (0535); the policies view lists
//      who names each; another realm does not see it.
//   O. AN ORDERED CHOICE (D12: carries over tests/ordered_choice_setting.js
//      1, 3-6 and 9). `webauthn.algorithms` describes itself as ordered
//      with a note per value; the console's fields posted to
//      `/admin-api/config/set-many` store the ticked values in number
//      order, a tie keeps the posted order and a number that is not one
//      goes last; ticking nothing is STS-ADMIN-0840 and a value outside the
//      list STS-CORE-0006, each changing nothing; `GET /admin-api/webauthn`
//      reports the offered ones first in rank order, RS1 not offered while
//      insecure algorithms are off, the list the realm's.
//
// NOT CARRIED, and why: locale_policy.js E's order (ui_locales, the
// person, the cookie, Accept-Language) is decided in the browser for every
// static surface, by the runtime the shell loads, from the default this job
// does read; a group-ranked choice for a known person is the same function
// as the application's, reached through a session. named_authn_policies.js
// C3 (a reference to a policy the realm does not hold fails closed) cannot
// be made over the wire: the field and the delete both refuse it; F is the
// console's browser-drawn markup. ordered_choice_setting.js 2 and 8 are
// that markup too.
//
// ITS REALMS ARE REMOVED AT THE END ONLY WHEN ASKED
// (`STS_TEST_REMOVE_REALMS=1`, which a hand run against a long-lived probe
// sets so that its directory does not fill): tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, so by default they stay.
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_named_policies",
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
const REALM = realmId("npol-");
const OTHER = realmId("npolb-");
const DOMAIN = REALM + ".example.net";
const realmBase = base + "/realm/" + REALM;
let api = realmBase + "/admin-api";
const KEY = "webauthn.algorithms";
const REDIRECT = "https://npol.example.net/cb";

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
  return { status: r.status, body: body, raw: raw, headers: r.headers };
}

function postJson(url, payload) {
  log.debug("Entering postJson().");
  log.debug("Leaving postJson().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

async function ok(path, payload, what) {
  log.debug("Entering ok().");
  const r = await postJson(api + path, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + path + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function newestSeq() {
  log.debug("Entering newestSeq().");
  const r = await send(api + "/audit?per=1");
  log.debug("Leaving newestSeq().");
  return (r.body && r.body.newestSeq) || 0;
}

// The codes recorded in this realm after `since`; a response carries none.
async function codesSince(since, wanted) {
  log.debug("Entering codesSince().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await send(api + "/audit?per=200");
    found = ((r.body && r.body.events) || []).filter(function (row) {
      return row.seq > since && row.errorCode;
    }).map(function (row) {
      return row.errorCode;
    });
    if (!wanted || found.indexOf(wanted) >= 0) {
      break;
    }
    await sleep(150);
  }
  log.debug("Leaving codesSince(). " + found.join(","));
  return found;
}

async function refused(path, payload, code, what) {
  log.debug("Entering refused().");
  const since = await newestSeq();
  const r = await postJson(api + path, payload);
  const codes = await codesSince(since, code);
  check(what + " (400, " + code + " on the audit row)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 400));
    assert.ok(r.body && r.body.ok === false, r.raw.slice(0, 400));
    assert.ok(codes.indexOf(code) >= 0, "recorded: " + codes.join(","));
    assert.ok(r.raw.indexOf(code) < 0, "the code was sent");
  });
  log.debug("Leaving refused().");
  return r;
}

async function policies() {
  log.debug("Entering policies().");
  const r = await send(api + "/policies");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving policies().");
  return r.body;
}

function person(username, extra) {
  log.debug("Entering person().");
  const attributes = Object.assign({ cn: username, sn: "Policy",
    givenName: "Person", mail: username + "@" + DOMAIN }, extra || {});
  log.debug("Leaving person().");
  return { username: username, invent: false, credential: "none",
           attributes: attributes };
}

async function languageOf(user) {
  log.debug("Entering languageOf().");
  const r = await send(api + "/users?user=" + encodeURIComponent(user));
  const attrs = (((r.body || {}).ldap || {}).entry || {}).attributes || {};
  log.debug("Leaving languageOf().");
  return [].concat(attrs.preferredLanguage || []);
}

// The `data-sts-locale-default` a shell carries.
function shellDefault(html) {
  log.debug("Entering shellDefault().");
  const m = /<html[^>]*data-sts-locale-default="([^"]*)"/.exec(html || "");
  log.debug("Leaving shellDefault().");
  return m ? m[1] : null;
}

// An authorization request for a client; answers the sign-in screen's id,
// the shell it is drawn in and the screen's view.
async function signInScreen(client) {
  log.debug("Entering signInScreen().");
  const verifier = nodeCrypto.randomBytes(32).toString("base64url");
  const challenge = nodeCrypto.createHash("sha256").update(verifier)
    .digest("base64url");
  const authorize = await send(realmBase + "/oauth2/authorize?" +
    new URLSearchParams({ client_id: client, response_type: "code",
      redirect_uri: REDIRECT, scope: "openid", state: "s", nonce: "n",
      code_challenge: challenge, code_challenge_method: "S256" })
      .toString());
  const location = authorize.headers.get("location") || "";
  const cookie = (authorize.headers.get("set-cookie") || "").split(";")[0];
  const id = (/[?&]authn=([^&]+)/.exec(location) || [])[1];
  assert.ok(authorize.status === 302 && id, authorize.status + " " +
            location + " " + authorize.raw.slice(0, 200));
  const shell = await send(new URL(location, base).toString(),
                           { headers: { Cookie: cookie } });
  const view = await send(realmBase + "/authn-api/pending/" + id,
                          { headers: { Cookie: cookie } });
  assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  log.debug("Leaving signInScreen().");
  return { html: shell.raw, view: view.body.view };
}

function oidcApp(identifier, fields) {
  log.debug("Entering oidcApp().");
  log.debug("Leaving oidcApp().");
  return { identifier: identifier, protocols: ["oauth2", "oidc"],
    fields: Object.assign({ oauthClientId: [identifier],
      oauthRedirectUri: [REDIRECT], oauthGrantType: ["authorization_code"],
      oauthResponseType: ["code"] }, fields || {}) };
}

async function localePolicy() {
  log.debug("Entering localePolicy().");
  const save = "/policies/save-locale-policy";
  log.info("=== L-A. the default profile ===");
  const saved = await ok(save, { profile: "default", defaultLocale: "fr-ca",
                                 populatePreferredLanguage: true },
                         "saved the default");
  check("the default profile is saved, its tag canonicalised", function () {
    assert.strictEqual(saved.profile.defaultLocale, "fr-CA");
    assert.strictEqual(saved.profile.populatePreferredLanguage, true);
    assert.strictEqual(saved.profile.from, "realm");
  });
  await refused(save, { profile: "default", defaultLocale: "not a tag!",
                        populatePreferredLanguage: true },
                "STS-I18N-0004", "a malformed tag");
  await refused(save, { profile: "Mobile!", defaultLocale: "sv",
                        populatePreferredLanguage: true, precedence: 10 },
                "STS-API-0009", "a malformed profile name, refused by the " +
                "request schema's pattern before the policy's own rule " +
                "(STS-I18N-0003) could be reached");
  await refused(save, { profile: "default", defaultLocale: "sv" },
                "STS-I18N-0004", "a save that leaves a field out");

  log.info("=== L-B. named profiles and what names them ===");
  const mobile = await ok(save, { profile: "mobile", defaultLocale: "sv",
    populatePreferredLanguage: true, precedence: 50 }, "saved mobile");
  const teams = await ok(save, { profile: "teams", defaultLocale: "es-MX",
    populatePreferredLanguage: true, precedence: 10 }, "saved teams");
  check("named profiles are saved with a precedence", function () {
    assert.strictEqual(mobile.profile.precedence, 50);
    assert.strictEqual(teams.profile.precedence, 10);
  });
  await refused(save, { profile: "ranked", defaultLocale: "sv",
                        populatePreferredLanguage: true, precedence: 0 },
                "STS-API-0009", "a precedence outside 1 to 1000, refused by " +
                "the request schema");
  const listed = (await policies()).locale.named.map(function (one) {
    return one.name;
  });
  check("the named profiles list by precedence", function () {
    assert.deepStrictEqual(listed, ["teams", "mobile"]);
  });
  await ok("/applications/create", oidcApp("loc-app"), "the application");
  await ok("/applications/set", { application: "loc-app",
                                  attribute: "appLocalePolicy",
                                  value: "mobile" }, "named mobile");
  await refused("/applications/set", { application: "loc-app",
                                       attribute: "appLocalePolicy",
                                       value: "nowhere" },
                "STS-REG-0203", "an application naming a profile the " +
                "realm does not hold");
  await ok("/groups/create", { group: "loc-group" }, "a group");
  await ok("/groups/set-policy", { group: "loc-group",
                                   attribute: "stsLocalePolicy",
                                   policy: "teams" }, "the group names teams");
  await refused("/groups/set-policy", { group: "loc-group",
                                        attribute: "stsLocalePolicy",
                                        policy: "nowhere" },
                "STS-LDAP-0195", "a group naming a profile the realm does " +
                "not hold");
  const named = {};
  (await policies()).locale.named.forEach(function (one) {
    named[one.name] = one.namedBy;
  });
  check("namedBy answers the group and the application naming each",
        function () {
    assert.ok(named.teams.groups.indexOf("loc-group") >= 0,
              JSON.stringify(named.teams));
    assert.ok(named.mobile.applications.indexOf("loc-app") >= 0,
              JSON.stringify(named.mobile));
  });
  await refused("/policies/reset-locale-policy", { profile: "teams" },
                "STS-I18N-0014", "a profile a group names is not deleted");
  await refused("/policies/reset-locale-policy", { profile: "mobile" },
                "STS-I18N-0014", "a profile an application names is not " +
                "deleted");
  const front = await send(realmBase + "/");
  const screen = await signInScreen("loc-app");
  check("the front door's shell carries the realm's default, the sign-in " +
        "screen's the profile its application names", function () {
    assert.strictEqual(shellDefault(front.raw), "fr-CA",
                       front.raw.slice(0, 300));
    assert.strictEqual(shellDefault(screen.html), "sv",
                       String(screen.html).slice(0, 300));
  });
  await ok("/groups/set-policy", { group: "loc-group",
                                   attribute: "stsLocalePolicy", policy: "" },
           "the group names nothing");
  const gone = await ok("/policies/reset-locale-policy", { profile: "teams" },
                        "deleted teams");
  check("once nothing names it the profile is deleted", function () {
    assert.strictEqual(gone.removed, true, JSON.stringify(gone));
  });

  log.info("=== L-C. a new person's language ===");
  await ok("/users/create", person("loc-plain"), "a person with none");
  await ok("/users/create", person("loc-own", { preferredLanguage: "es-PA" }),
           "a person with a language");
  const plain = await languageOf("loc-plain");
  const own = await languageOf("loc-own");
  check("a person created with no language is given the default's tag, " +
        "and one created with a language keeps it", function () {
    assert.deepStrictEqual(plain, ["fr-CA"]);
    assert.deepStrictEqual(own, ["es-PA"]);
  });
  await ok("/users/remove-attribute", { user: "loc-plain",
    attribute: "preferredLanguage", value: "fr-CA" }, "removed it");
  await ok("/users/set-attribute", { user: "loc-plain",
    attribute: "description", value: "touched" }, "wrote the entry again");
  const removed = await languageOf("loc-plain");
  check("a removed language stays removed when the entry is written again",
        function () {
    assert.deepStrictEqual(removed, []);
  });
  await ok(save, { profile: "default", defaultLocale: "fr-CA",
                   populatePreferredLanguage: false },
           "turned population off");
  await ok("/users/create", person("loc-none"), "a person after that");
  const none = await languageOf("loc-none");
  check("a profile with population off gives none", function () {
    assert.deepStrictEqual(none, []);
  });
  log.debug("Leaving localePolicy().");
}

async function authnPolicies() {
  log.debug("Entering authnPolicies().");
  const save = "/policies/save-named-authn-policy";
  const del = "/policies/delete-named-authn-policy";
  log.info("=== A-A. saving ===");
  await ok(save, { name: "passkeys-only", description: "Passwordless",
                   mechanisms: ["webauthn"],
                   secondFactors: ["securityKey", "totp"] },
           "saved passkeys-only");
  const listed = ((await policies()).authn.named || []).filter(function (p) {
    return p.name === "passkeys-only";
  })[0];
  check("a named policy is saved in ou=authnPolicies and listed with its " +
        "two lists", function () {
    assert.ok(listed, "not listed");
    assert.strictEqual(listed.description, "Passwordless");
    assert.deepStrictEqual(listed.mechanisms, ["webauthn"]);
    assert.deepStrictEqual(listed.secondFactors, ["securityKey", "totp"]);
    assert.ok(/^cn=passkeys-only,ou=authnPolicies/.test(listed.dn),
              listed.dn);
  });
  await refused(save, { name: "Bad Name" }, "STS-API-0009",
                "a bad name, refused by the request schema's pattern");
  await refused(save, { name: "default" }, "STS-AUTHN-0532",
                "`default` as a name");
  const unknown = await refused(save, { name: "odd",
    mechanisms: ["smoke-signals"], secondFactors: ["carrier-pigeon"] },
    "STS-AUTHN-0533", "unknown mechanisms");
  check("each unknown mechanism is its own sentence", function () {
    assert.strictEqual((unknown.body.errors || []).length, 2,
                       unknown.raw.slice(0, 300));
  });
  await ok(save, { name: "open" }, "saved a policy listing nothing");

  log.info("=== A-B. the field ===");
  const fresh = await send(api + "/applications/new");
  const row = (fresh.body.fields || []).filter(function (one) {
    return one.attribute === "appAuthnPolicy";
  })[0];
  check("appAuthnPolicy's choices are default and the realm's policies, " +
        "and the two old attributes are gone", function () {
    assert.deepStrictEqual(row && row.choices,
                           ["default", "open", "passkeys-only"]);
    assert.ok(!(fresh.body.fields || []).some(function (one) {
      return one.attribute === "appAuthnMechanism" ||
             one.attribute === "appMfaMechanism";
    }));
  });
  await ok("/applications/create", oidcApp("nap-web",
           { appAuthnPolicy: "passkeys-only" }), "an application naming it");
  await ok("/applications/create", oidcApp("nap-plain"), "a plain one");
  await refused("/applications/set", { application: "nap-web",
                                       attribute: "appAuthnPolicy",
                                       value: "ghost" },
                "STS-REG-0203", "a policy the realm does not hold");

  log.info("=== A-C. the sign-in screen reads it ===");
  const strict = await signInScreen("nap-web");
  const loose = await signInScreen("nap-plain");
  check("an application naming a passkeys-only policy is offered a " +
        "passkey and no password; a plain one is offered both", function () {
    assert.strictEqual(strict.view.password, false,
                       JSON.stringify(strict.view).slice(0, 300));
    assert.strictEqual(strict.view.passkey, true);
    assert.strictEqual(loose.view.password, true,
                       JSON.stringify(loose.view).slice(0, 300));
  });

  log.info("=== A-D, E. deleting, and who names it ===");
  const shown = ((await policies()).authn.named || []).filter(function (p) {
    return p.name === "passkeys-only";
  })[0];
  check("the policies view names the application naming it", function () {
    assert.deepStrictEqual(shown.namedBy.applications, ["nap-web"]);
    assert.deepStrictEqual(shown.namedBy.groups, []);
    assert.strictEqual(shown.precedence, 100);
  });
  const inUse = await refused(del, { name: "passkeys-only" },
                              "STS-AUTHN-0534", "a policy still named");
  check("and the refusal names the application", function () {
    assert.ok(/nap-web/.test((inUse.body.errors || []).join(" ")));
  });
  await ok("/applications/set", { application: "nap-web",
                                  attribute: "appAuthnPolicy",
                                  value: "default" }, "named default");
  const gone = await ok(del, { name: "passkeys-only" }, "deleted it");
  check("once nothing names it, it is deleted", function () {
    assert.strictEqual(gone.removed, true, JSON.stringify(gone));
  });
  await refused(del, { name: "never-was" }, "STS-AUTHN-0535",
                "a name nobody holds");
  log.debug("Leaving authnPolicies().");
}

// The console's fields for `webauthn.algorithms`: a tick and a number per
// chosen value.
function fieldsFor(chosen) {
  log.debug("Entering fieldsFor().");
  const fields = { from: "/admin/webauthn" };
  fields[KEY + ".ordered"] = "1";
  Object.keys(chosen).forEach(function (value) {
    fields[KEY + ".pick." + value] = "1";
    fields[KEY + ".rank." + value] = String(chosen[value]);
  });
  log.debug("Leaving fieldsFor().");
  return fields;
}

async function webauthnView() {
  log.debug("Entering webauthnView().");
  const r = await send(api + "/webauthn");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving webauthnView().");
  return r.body.status;
}

function offered(status) {
  log.debug("Entering offered().");
  log.debug("Leaving offered().");
  return status.algorithms.filter(function (one) {
    return one.offered;
  }).map(function (one) {
    return one.name + "#" + one.rank;
  }).join(",");
}

async function orderedChoice() {
  log.debug("Entering orderedChoice().");
  log.info("=== O. an ordered choice from a closed list ===");
  const saved = await ok("/config/set-many", fieldsFor({ "ES256": 3,
    "ML-DSA-65": 1, "Ed25519": 2 }), "saved three, numbered 3, 1, 2");
  const setting = saved.settings.filter(function (one) {
    return one.key === KEY;
  })[0];
  check("the setting describes itself as ordered, with a note per value",
        function () {
    assert.strictEqual(setting.ordered, true);
    assert.ok(setting.csvValues.length > 10);
    setting.csvValues.forEach(function (value) {
      assert.ok(String((setting.csvValueNotes || {})[value] || "")
        .length > 0, value);
    });
    assert.ok(/post-quantum, RFC 9964/.test(
      setting.csvValueNotes["ML-DSA-65"]));
  });
  let status = await webauthnView();
  check("the three are stored in the order they were numbered, and the " +
        "report lists them first, the list the realm's", function () {
    assert.strictEqual(offered(status), "ML-DSA-65#1,Ed25519#2,ES256#3");
    assert.strictEqual(status.algorithmsSource, "realm");
  });
  await ok("/config/set-many", fieldsFor({ "RS256": "x", "ES384": 1,
                                           "ES256": 1 }),
           "saved a tie and a number that is not one");
  status = await webauthnView();
  check("a tie keeps the posted order; a number that is not one goes last",
        function () {
    assert.strictEqual(offered(status), "ES384#1,ES256#2,RS256#3");
  });
  await refused("/config/set-many", fieldsFor({}), "STS-ADMIN-0840",
                "a save ticking nothing");
  await refused("/config/set-many", fieldsFor({ "ES256": 1,
                                                "NOT-AN-ALG": 2 }),
                "STS-CORE-0006", "a value outside the closed list");
  status = await webauthnView();
  check("neither refusal changed the setting", function () {
    assert.strictEqual(offered(status), "ES384#1,ES256#2,RS256#3");
  });
  await ok("/config/set-many", fieldsFor({ "ES256": 2, "ML-DSA-87": 1,
                                           "RS256": 3 }), "saved again");
  status = await webauthnView();
  const rs1 = status.algorithms.filter(function (one) {
    return one.name === "RS1";
  })[0];
  check("the report follows the save, and every other row says why it is " +
        "not offered; RS1 because insecure algorithms are off", function () {
    assert.strictEqual(offered(status), "ML-DSA-87#1,ES256#2,RS256#3");
    status.algorithms.filter(function (one) {
      return !one.offered;
    }).forEach(function (one) {
      assert.ok(one.rank === undefined && !!one.notOfferedBecause,
                JSON.stringify(one));
    });
    assert.strictEqual(rs1.notOfferedBecause, "insecure-off");
  });
  log.debug("Leaving orderedChoice().");
}

async function otherRealm() {
  log.debug("Entering otherRealm().");
  log.info("=== L-D, A-G. another realm sees none of it ===");
  api = base + "/realm/" + OTHER + "/admin-api";
  const view = await policies();
  check("another realm holds no named locale profile and no named " +
        "authentication policy of the first", function () {
    assert.deepStrictEqual(view.locale.named || [], []);
    assert.ok(!(view.authn.named || []).some(function (one) {
      return one.name === "open";
    }), JSON.stringify(view.authn.named));
    assert.strictEqual(view.locale.profile.defaultLocale, "en");
  });
  log.debug("Leaving otherRealm().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. the throwaway realms " + REALM + " and " + OTHER + " ===");
  for (const id of [REALM, OTHER]) {
    const made = await postJson(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Named policies " + STAMP });
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  }
  await localePolicy();
  await authnPolicies();
  await orderedChoice();
  await otherRealm();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// The realms this job made, removed from the default realm only when
// STS_TEST_REMOVE_REALMS is "1" (the header says why).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Kept.");
    return;
  }
  for (const id of [REALM, OTHER]) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("removed the realm " + id + ": " + r.status);
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A removal that fails leaves a realm behind, which is what a run
      // without the switch does anyway; the job's verdict stands.
      log.info("could not remove the realm " + id);
    }
  }
  log.debug("Leaving removeRealms().");
}

test().then(function () {
  return true;
}, function (e) {
  log.error("sts_named_policies FAILED: " + ((e && e.stack) || e));
  return false;
}).then(async function (passed) {
  await removeRealms();
  if (!passed) {
    process.exit(1);
  }
});
