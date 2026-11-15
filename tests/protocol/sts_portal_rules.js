// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_portal_rules.js
//
// ---------------------------------------------------------------------------
// FOUR THINGS THE USER PORTAL'S API ANSWERS, OVER THE WIRE: A REALM'S CUSTOM
// ATTRIBUTES, THE DELEGATE SEARCH, TWO LISTS THAT MUST NOT READ AS EMPTY,
// AND RESOURCES I OWN.
//
// D12 (#444): carries over what a client can see of
// `tests/portal_custom_attributes.js`, `tests/portal_delegate_search.js`,
// `tests/portal_list_refusals.js` and `tests/portal_owned.js`. Each person
// signs in AS THE STATIC PORTAL (`portal_signin.js`: PKCE, a DPoP-bound
// `account:manage` token) and asks `/account-api` what the portal asks;
// every fixture is made through `/admin-api`, and every code is read off the
// realm's audit log, never off a response:
//
//   A. CUSTOM ATTRIBUTES (#700), in a PRODUCT realm: a definition's two
//      portal flags off by default, editable stored visible, visible alone
//      not editable, a malformed flag refused; `update-person-attribute`
//      changing the flags, the label and the description and keeping what
//      was not sent, hiding one ending its editing, its refusals (0206 an
//      undefined name, 0207 a bad flag or an empty label, 0208 a changed
//      syntax or cardinality); the Overview's `customAttributes` carrying
//      only the visible ones with the person's values; `POST
//      /account-api/attributes` writing a multi-valued one as a set and a
//      single-valued one as one value (0629 for two), refusing a read-only
//      (0628), hidden (0627) or undefined (0626) one; a required one not
//      emptied (STS-LDAP-0164) but replaced.
//   B. THE DELEGATE SEARCH (`GET /account-api/delegate/candidates`): native
//      people found by part of a uid; never the person themselves, a
//      disabled account, a service account, a group, an application or
//      another realm's person; each result the uid, the cn and the DN only;
//      fewer than three characters refused (STS-PORTAL-0620, audited as the
//      person) and a search audited with its text; ten at most with `more`;
//      choosing one names them through `POST /account-api/delegate`; and
//      `stsProvisionedBy`, the stamp the search reads, refused at every
//      door a caller has — `/admin-api`'s create and set-attribute, an LDAP
//      add, and the portal's own attribute editor.
//   C. THE LISTS: `/account-api/self-issued` answers an entry with nothing
//      enrolled the empty list, never a refusal.
//   D. RESOURCES I OWN (#604): the four `/account-api/owned/*` lists — a
//      role naming the person, a group owned by a group they are in, a
//      service account naming them, an application owned through a group —
//      each row saying how, nothing naming somebody else, the person's
//      groups not listed, the rows counted.
//
// NOT CARRIED, and why: the stamp written by a federated or consumer
// provider's create, its exclusion from the search, and its survival of an
// overwrite and a re-homing (`portal_delegate_search.js` A1–A6, A12, part of
// B2): only a partner's sign-in writes it, so they are OWED to the
// federation family's phase (7); the store's LIKE statement and the
// over-fetched page (B7, B10: store facts) and the page's drawing and
// debounce (D: the browser bundle) are class (d); SCIM's table (A11) is a
// module table, (d). `portal_list_refusals.js`'s STS-PORTAL-0616 (a token
// whose person has no entry) and STS-PORTAL-0617 (a token whose `sub` and
// person disagree) cannot be produced over the wire: deleting a person ends
// their sessions and so their token, and no issuance makes a mismatched one
// — class (d). `portal_owned.js` B (the pages, the column) is the bundle,
// (d); its D (an owner administering through `/admin-api`) is
// `sts_portal_owner_edits.js`'s already. The odd characters of B6 (`*`,
// `(`, `%`, `_` in a uid) are asserted only for the ones `/admin-api` lets a
// username carry; the rest are logged as not creatable.
//
// THE REALMS are throwaway; each is removed only when
// STS_TEST_REMOVE_REALMS=1 (a private probe's switch; tests/CLAUDE.md, *No
// job removes a realm*).
//
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const portal = require("./portal_signin.js");

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
var log = bunyan.createLogger({ name: "sts_portal_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const R_ATTR = "prat-" + STAMP;
const R_DELEG = "prdl-" + STAMP;
const R_OTHER = "prot-" + STAMP;
const R_OWNED = "prow-" + STAMP;
const PASSWORD = "Pr-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
// Every name the search may find carries this, so the text finds only what
// this run made.
const TOKEN = "dsq" + STAMP.slice(-6);
const FLOOR = 40;

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

function rb(realm) {
  log.debug("Entering rb().");
  log.debug("Leaving rb().");
  return base + "/realm/" + realm;
}

async function send(method, url, payload) {
  log.debug("Entering send(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload) });
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

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await send("POST", url, payload);
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    "POST " + url + " should have " + what + "; it answered " + r.status +
    " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

async function makeRealm(id, mode) {
  log.debug("Entering makeRealm(). " + id);
  await ok(base + "/admin-api/realms/create", { id: id,
    domain: id + ".example.net", name: "Portal rules " + id },
    "created the realm " + id);
  // One address signing many people in, in seconds, is what risk scoring
  // counts (sts_admin_client_policies.js's reason).
  await ok(base + "/admin-api/realms/set", { id: id,
    key: "risk.assessSignIns", value: "false" }, "risk scoring off");
  if (mode) {
    await ok(base + "/admin-api/realms/set", { id: id, key: "global.mode",
      value: mode }, "set " + id + " to " + mode);
    // PRODUCT REQUIRES A SECOND FACTOR OF EVERYBODY unless this is on, and
    // what is asked here is the portal's API, not the sign-in.
    await ok(base + "/admin-api/realms/set", { id: id,
      key: "authn.allowOptionalSecondFactor", value: "true" },
      "let a password alone sign in");
  }
  log.debug("Leaving makeRealm().");
}

async function person(realm, username, attributes) {
  log.debug("Entering person(). " + username);
  const made = await ok(rb(realm) + "/admin-api/users/create", {
    username: username, invent: false, credential: "password",
    password: PASSWORD,
    attributes: Object.assign({ cn: "Person " + username, givenName: "Pr",
                                sn: username, mail: username +
                                  "@pr.example.test" }, attributes || {}) },
    "created " + username + " in " + realm);
  log.debug("Leaving person().");
  return made;
}

// The audit rows of the realm carrying `code` (waited for a little: a row
// may land just after the answer).
async function codeRows(realm, code, atLeast) {
  log.debug("Entering codeRows(). " + code);
  let rows = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await send("GET", rb(realm) + "/admin-api/audit?per=500&code=" +
                         encodeURIComponent(code));
    rows = (r.body && (r.body.events || r.body.rows)) || [];
    const n = Number((r.body && r.body.matched) || rows.length);
    if (n >= (atLeast || 0)) {
      log.debug("Leaving codeRows(). " + n);
      return { n: n, rows: rows };
    }
    await sleep(150);
  }
  log.debug("Leaving codeRows(). short");
  return { n: rows.length, rows: rows };
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const got = await codeRows(realm, code, 0);
  log.debug("Leaving codeCount().");
  return got.n;
}

function viewOf(answer) {
  log.debug("Entering viewOf().");
  const j = (answer && answer.json) || {};
  log.debug("Leaving viewOf().");
  return j.view || j;
}

// A custom attribute's definition as `GET /admin-api/policies` carries it:
// the object named `name` that says whether the portal shows it.
async function definitionOf(realm, name) {
  log.debug("Entering definitionOf(). " + name);
  const r = await send("GET", rb(realm) + "/admin-api/policies");
  let found = null;
  (function walk(node) {
    if (found || !node || typeof node !== "object") {
      return;
    }
    if (!Array.isArray(node) && node.name === name &&
        Object.prototype.hasOwnProperty.call(node, "portalVisible")) {
      found = node;
      return;
    }
    Object.keys(node).forEach(function (k) {
      walk(node[k]);
    });
  })(r.body);
  log.debug("Leaving definitionOf(). " + !!found);
  return found;
}

function flagsOf(def) {
  log.debug("Entering flagsOf().");
  log.debug("Leaving flagsOf().");
  return JSON.stringify([def && def.portalVisible, def && def.portalEditable]);
}

// A person's values of one attribute, as `/admin-api/users` reads them.
async function valuesOf(realm, username, attribute) {
  log.debug("Entering valuesOf(). " + attribute);
  const r = await send("GET", rb(realm) + "/admin-api/users?user=" +
                       encodeURIComponent(username));
  let out = [];
  (function walk(node) {
    if (!node || typeof node !== "object") {
      return;
    }
    Object.keys(node).forEach(function (k) {
      if (k.toLowerCase() === attribute.toLowerCase() &&
          (Array.isArray(node[k]) || typeof node[k] === "string")) {
        out = [].concat(node[k]).map(String);
      } else {
        walk(node[k]);
      }
    });
  })(r.body);
  log.debug("Leaving valuesOf().");
  return out.sort();
}

// ---------------------------------------------------------------------------
// A. CUSTOM ATTRIBUTES.
// ---------------------------------------------------------------------------
async function partAttributes() {
  log.debug("Entering partAttributes().");
  log.info("=== A. a realm's custom attributes on the portal (product) ===");
  await makeRealm(R_ATTR, "product");
  const api = rb(R_ATTR) + "/admin-api";
  await ok(api + "/policies/define-person-attribute",
           { name: "deskNumber", label: "Desk", syntax: "string" },
           "defined deskNumber");
  await ok(api + "/policies/define-person-attribute",
           { name: "nickName", label: "Nicknames", syntax: "string",
             multiValued: true, portalEditable: true },
           "defined nickName");
  await ok(api + "/policies/define-person-attribute",
           { name: "badgeColour", label: "Badge colour", syntax: "string",
             portalVisible: true }, "defined badgeColour");
  const desk = await definitionOf(R_ATTR, "deskNumber");
  const nick = await definitionOf(R_ATTR, "nickName");
  const colour = await definitionOf(R_ATTR, "badgeColour");
  check("A1. both portal flags are off by default; made editable it is " +
        "stored visible too; made visible alone it is not editable",
        function () {
    assert.strictEqual(flagsOf(desk), "[false,false]", JSON.stringify(desk));
    assert.strictEqual(flagsOf(nick), "[true,true]", JSON.stringify(nick));
    assert.strictEqual(flagsOf(colour), "[true,false]",
                       JSON.stringify(colour));
  });
  const before = await codeCount(R_ATTR, "STS-LDAP-0169") +
    await codeCount(R_ATTR, "STS-API-0009");
  const badFlag = await send("POST", api +
    "/policies/define-person-attribute",
    { name: "okName", label: "x", syntax: "string",
      portalVisible: "maybe" });
  const after = await codeCount(R_ATTR, "STS-LDAP-0169") +
    await codeCount(R_ATTR, "STS-API-0009");
  check("A2. a define with a flag that is neither yes nor no is refused, " +
        "its code recorded and none sent, and nothing is defined",
        function () {
    assert.strictEqual(badFlag.status, 400, badFlag.raw.slice(0, 300));
    assert.ok(after >= before + 1, before + " -> " + after);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(badFlag.raw), badFlag.raw);
  });
  assert.strictEqual(await definitionOf(R_ATTR, "okName"), null);

  await ok(api + "/policies/update-person-attribute",
           { name: "deskNumber", portalEditable: true,
             label: "Desk number", description: "Where you sit" },
           "made deskNumber editable");
  let d1 = await definitionOf(R_ATTR, "deskNumber");
  check("A3. update-person-attribute makes it editable (and so visible) and " +
        "changes its label and description, and nothing else", function () {
    assert.strictEqual(flagsOf(d1), "[true,true]", JSON.stringify(d1));
    assert.strictEqual(d1.label, "Desk number");
    assert.strictEqual(d1.description, "Where you sit");
    assert.strictEqual(d1.syntax, "string");
    assert.ok(d1.multi === false || d1.multiValued === false,
              JSON.stringify(d1));
  });
  await ok(api + "/policies/update-person-attribute",
           { name: "deskNumber", portalVisible: false }, "hid deskNumber");
  d1 = await definitionOf(R_ATTR, "deskNumber");
  check("A4. hiding it alone ends its editing, and keeps the label",
        function () {
    assert.strictEqual(flagsOf(d1), "[false,false]", JSON.stringify(d1));
    assert.strictEqual(d1.label, "Desk number");
  });
  const refusals = [
    [{ name: "noSuchThing", label: "x" }, "STS-LDAP-0206",
     "a name the realm does not define"],
    [{ name: "deskNumber", portalEditable: "x" }, "STS-LDAP-0207",
     "a flag that is neither yes nor no"],
    [{ name: "deskNumber", label: "" }, "STS-LDAP-0207", "an empty label"],
    [{ name: "deskNumber", syntax: "integer" }, "STS-LDAP-0208",
     "a changed syntax"],
    [{ name: "nickName", multiValued: false }, "STS-LDAP-0208",
     "a changed cardinality"]];
  for (const one of refusals) {
    const ownBefore = await codeCount(R_ATTR, one[1]);
    const schemaBefore = await codeCount(R_ATTR, "STS-API-0009");
    const r = await send("POST", api + "/policies/update-person-attribute",
                         one[0]);
    await sleep(100);
    const own = await codeCount(R_ATTR, one[1]);
    const schema = await codeCount(R_ATTR, "STS-API-0009");
    check("A5. " + one[2] + " is refused 400, recorded as " + one[1] +
          (own > ownBefore ? "" : " (the request schema's STS-API-0009 " +
           "first)"), function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(own > ownBefore || schema > schemaBefore,
                one[1] + " " + ownBefore + "->" + own + "; 0009 " +
                schemaBefore + "->" + schema);
    });
  }
  await ok(api + "/policies/update-person-attribute",
           { name: "nickName", syntax: "string", multiValued: true },
           "sent nickName's own syntax and cardinality");
  const sameNick = await definitionOf(R_ATTR, "nickName");
  check("A6. the syntax and cardinality sent as they are are taken and " +
        "change nothing", function () {
    assert.strictEqual(flagsOf(sameNick), "[true,true]",
                       JSON.stringify(sameNick));
  });

  const who = "prat-ada-" + STAMP;
  await person(R_ATTR, who, { badgeColour: "blue" });
  const ada = await portal.signInToThePortal(rb(R_ATTR), who, log,
                                             { password: PASSWORD });
  const overview = viewOf(await ada.api("GET", "/account-api/overview"));
  const shown = (overview.customAttributes || []).map(function (one) {
    return one.name + ":" + one.editable + ":" + [].concat(one.values || [])
      .join("|");
  });
  const nickRow = (overview.customAttributes || []).filter(function (one) {
    return one.name === "nickName";
  })[0] || {};
  check("A7. the Overview carries the visible custom attributes only, with " +
        "the person's values and whether each is editable", function () {
    assert.deepStrictEqual(shown, ["badgeColour:false:blue",
                                   "nickName:true:"],
                           JSON.stringify(overview.customAttributes));
  });
  check("A8. each row carries its label, syntax, cardinality and " +
        "description", function () {
    assert.strictEqual(nickRow.label, "Nicknames", JSON.stringify(nickRow));
    assert.strictEqual(nickRow.multi, true);
    assert.strictEqual(nickRow.syntax, "string");
    assert.strictEqual(nickRow.description, "");
  });

  const post = function (body) {
    log.debug("Entering post().");
    log.debug("Leaving post().");
    return ada.api("POST", "/account-api/attributes", body);
  };
  let r = await post({ attribute: "nickName", values: ["Ada", "Countess"] });
  const first = await valuesOf(R_ATTR, who, "nickName");
  check("A9. a self-edit of an editable multi-valued attribute writes every " +
        "value sent", function () {
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    assert.deepStrictEqual(first, ["Ada", "Countess"]);
  });
  r = await post({ attribute: "NICKNAME",
                   values: ["Countess", "Enchantress", ""] });
  const second = await valuesOf(R_ATTR, who, "nickName");
  check("A10. a second edit replaces the set: one kept, one added, one " +
        "removed, and an empty box is no value", function () {
    assert.strictEqual(r.status, 200, JSON.stringify(r.json));
    assert.deepStrictEqual(second, ["Countess", "Enchantress"]);
  });
  const c628 = await codeCount(R_ATTR, "STS-PORTAL-0628");
  const c627 = await codeCount(R_ATTR, "STS-PORTAL-0627");
  const c626 = await codeCount(R_ATTR, "STS-PORTAL-0626");
  const read = await post({ attribute: "badgeColour", values: ["red"] });
  const hidden = await post({ attribute: "deskNumber", values: ["12B"] });
  const unknown = await post({ attribute: "favouriteColour",
                               values: ["red"] });
  const n628 = (await codeRows(R_ATTR, "STS-PORTAL-0628", c628 + 1)).n;
  const n627 = (await codeRows(R_ATTR, "STS-PORTAL-0627", c627 + 1)).n;
  const n626 = (await codeRows(R_ATTR, "STS-PORTAL-0626", c626 + 1)).n;
  const colourNow = await valuesOf(R_ATTR, who, "badgeColour");
  const deskNow = await valuesOf(R_ATTR, who, "deskNumber");
  check("A11. one visible but not editable, one hidden and one undefined " +
        "are refused 403, 403 and 400 — STS-PORTAL-0628, 0627, 0626 — " +
        "changing nothing", function () {
    assert.strictEqual(read.status, 403, JSON.stringify(read.json));
    assert.strictEqual(hidden.status, 403, JSON.stringify(hidden.json));
    assert.strictEqual(unknown.status, 400, JSON.stringify(unknown.json));
    assert.ok(n628 > c628 && n627 > c627 && n626 > c626,
              [c628, n628, c627, n627, c626, n626].join(","));
    assert.deepStrictEqual(colourNow, ["blue"]);
    assert.deepStrictEqual(deskNow, []);
  });
  await ok(api + "/policies/update-person-attribute",
           { name: "deskNumber", portalEditable: true },
           "made deskNumber editable again");
  const single = await post({ attribute: "deskNumber", values: ["12B"] });
  const moved = await post({ attribute: "deskNumber", values: "12C" });
  const c629 = await codeCount(R_ATTR, "STS-PORTAL-0629");
  const two = await post({ attribute: "deskNumber", values: ["1", "2"] });
  const n629 = (await codeRows(R_ATTR, "STS-PORTAL-0629", c629 + 1)).n;
  const deskAfter = await valuesOf(R_ATTR, who, "deskNumber");
  check("A12. a single-valued attribute is set to the one value sent, and " +
        "two values are refused 400 (STS-PORTAL-0629)", function () {
    assert.strictEqual(single.status, 200, JSON.stringify(single.json));
    assert.strictEqual(moved.status, 200, JSON.stringify(moved.json));
    assert.strictEqual(two.status, 400, JSON.stringify(two.json));
    assert.ok(n629 > c629, c629 + " -> " + n629);
    assert.deepStrictEqual(deskAfter, ["12C"]);
  });
  await ok(api + "/policies/save-attributes-policy",
           { profile: "default", requiredAttributes:
             ["givenName", "sn", "mail", "nickName"] },
           "required nickName");
  const c164 = await codeCount(R_ATTR, "STS-LDAP-0164");
  const emptied = await post({ attribute: "nickName", values: [] });
  const n164 = (await codeRows(R_ATTR, "STS-LDAP-0164", c164 + 1)).n;
  const kept = await valuesOf(R_ATTR, who, "nickName");
  check("A13. a required custom attribute cannot be emptied (400, " +
        "STS-LDAP-0164), and nothing is written", function () {
    assert.strictEqual(emptied.status, 400, JSON.stringify(emptied.json));
    assert.ok(n164 > c164, c164 + " -> " + n164);
    assert.deepStrictEqual(kept, ["Countess", "Enchantress"]);
  });
  const replaced = await post({ attribute: "nickName", values: ["Lady"] });
  const lady = await valuesOf(R_ATTR, who, "nickName");
  check("A14. a required multi-valued attribute is replaced outright: the " +
        "new value is added before the old ones are removed", function () {
    assert.strictEqual(replaced.status, 200, JSON.stringify(replaced.json));
    assert.deepStrictEqual(lady, ["Lady"]);
  });
  log.debug("Leaving partAttributes().");
}

// ---------------------------------------------------------------------------
// B. THE DELEGATE SEARCH.
// ---------------------------------------------------------------------------
function ldapAdd(url, bindDn, dn, entry) {
  log.debug("Entering ldapAdd(). " + dn);
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: url, reconnect: false,
      timeout: 15000, connectTimeout: 10000,
      tlsOptions: { rejectUnauthorized: true, servername: "localhost" } });
    client.on("error", function (e) {
      // ldapjs emits on the client as well as calling back; the operation in
      // flight reports it.
      log.debug("The LDAP client emitted an error: " + e.message);
    });
    client.bind(bindDn, PASSWORD, function (e) {
      if (e) {
        log.debug("Caught in ldapAdd(): bind " + e.message);
        client.unbind(function () {});
        log.debug("Leaving ldapAdd(). The bind failed.");
        resolve({ ok: false, error: "bind: " + e.name });
        return;
      }
      client.add(dn, entry, function (e2) {
        if (e2) {
          log.debug("Caught in ldapAdd(): add " + e2.message);
        }
        client.unbind(function () {});
        log.debug("Leaving ldapAdd().");
        resolve({ ok: !e2, error: e2 ? e2.name : "" });
      });
    });
  });
}

async function partDelegate() {
  log.debug("Entering partDelegate().");
  log.info("=== B. the delegate search ===");
  await makeRealm(R_DELEG, "");
  await makeRealm(R_OTHER, "");
  const api = rb(R_DELEG) + "/admin-api";
  const ALICE = TOKEN + "-alice";
  const BOB = TOKEN + "-bob";
  const DISABLED = TOKEN + "-disabled";
  const SVC = TOKEN + "-svc";
  const aliceMade = await person(R_DELEG, ALICE);
  const bobMade = await person(R_DELEG, BOB, { cn: "Bob Native" });
  await person(R_DELEG, DISABLED);
  await ok(api + "/users/disable", { user: DISABLED }, "disabled one");
  await person(R_DELEG, SVC);
  await ok(api + "/users/set-service-account", { user: SVC,
    owners: [ALICE] }, "made a service account");
  await ok(api + "/groups/create", { group: TOKEN + "-group" },
           "created a group");
  await ok(api + "/applications/create", { identifier: TOKEN + "-app",
    name: TOKEN + "-app", protocols: ["oauth2"],
    fields: { oauthClientId: [TOKEN + "-app"] } }, "created an application");
  await person(R_OTHER, TOKEN + "-elsewhere");
  // THE ODD CHARACTERS: only those a username may carry at /admin-api.
  const odd = {};
  for (const ch of ["*", "(", "%", "_"]) {
    const name = TOKEN + "q" + ch + "x";
    const r = await send("POST", api + "/users/create", { username: name,
      invent: false, credential: "password", password: PASSWORD,
      attributes: { cn: "Odd " + name, givenName: "Odd", sn: "Odd",
                    mail: "odd" + Buffer.from(ch).toString("hex") +
                      "@pr.example.test" } });
    if (r.status === 200 && r.body && r.body.ok !== false) {
      odd[ch] = name;
    } else {
      log.info("a username holding " + JSON.stringify(ch) + " is not " +
               "creatable at /admin-api (" + r.status + "), so its literal " +
               "match is not asked");
    }
  }
  await person(R_DELEG, TOKEN + "qyx");
  for (let i = 0; i < 12; i += 1) {
    await person(R_DELEG, TOKEN + "cap" + String(i).padStart(2, "0"));
  }
  const alice = await portal.signInToThePortal(rb(R_DELEG), ALICE, log,
                                               { password: PASSWORD });
  const search = function (q) {
    log.debug("Entering search().");
    log.debug("Leaving search().");
    return alice.api("GET", "/account-api/delegate/candidates?q=" +
                     encodeURIComponent(q));
  };
  const uidsOf = function (answer) {
    log.debug("Entering uidsOf().");
    log.debug("Leaving uidsOf().");
    return ((answer && answer.json && answer.json.people) || [])
      .map(function (one) {
        return one.uid;
      });
  };
  let found = await search(TOKEN + "-");
  const uids = uidsOf(found);
  check("B1. a uid substring finds the native people of the realm",
        function () {
    assert.strictEqual(found.status, 200, JSON.stringify(found.json));
    assert.ok(uids.indexOf(BOB) >= 0, uids.join(","));
  });
  const excluded = { themselves: ALICE, "a disabled account": DISABLED,
                     "a service account": SVC, "a group": TOKEN + "-group",
                     "an application": TOKEN + "-app",
                     "another realm's person": TOKEN + "-elsewhere" };
  Object.keys(excluded).forEach(function (what) {
    check("B2. it does not find " + what, function () {
      assert.ok(uids.indexOf(excluded[what]) < 0, uids.join(","));
      assert.ok(!(found.json.people || []).some(function (one) {
        return String(one.dn).toLowerCase().indexOf("=" +
          excluded[what].toLowerCase() + ",") >= 0;
      }), JSON.stringify(found.json.people));
    });
  });
  check("B3. each result is the uid, the cn and the DN, and nothing else",
        function () {
    assert.ok((found.json.people || []).every(function (one) {
      return Object.keys(one).sort().join(",") === "cn,dn,uid";
    }), JSON.stringify(found.json.people).slice(0, 300));
    assert.ok((found.json.people || []).some(function (one) {
      return one.uid === BOB && one.cn === "Bob Native" &&
        String(one.dn).toLowerCase() === String(bobMade.dn).toLowerCase();
    }), JSON.stringify(found.json.people).slice(0, 300) + " " + bobMade.dn);
  });
  const c620 = await codeCount(R_DELEG, "STS-PORTAL-0620");
  const short = await search("ab");
  const rows620 = await codeRows(R_DELEG, "STS-PORTAL-0620", c620 + 1);
  check("B4. fewer than three characters is refused 400, STS-PORTAL-0620, " +
        "audited as the person", function () {
    assert.strictEqual(short.status, 400, JSON.stringify(short.json));
    assert.ok(rows620.n > c620, c620 + " -> " + rows620.n);
    assert.ok(rows620.rows.some(function (row) {
      return String(row.actor || "").indexOf(ALICE) >= 0;
    }), JSON.stringify(rows620.rows[0] || {}).slice(0, 300));
  });
  const audited = await send("GET", rb(R_DELEG) + "/admin-api/audit?" +
    "per=500&action=portal.delegation.search&outcome=success");
  const okRow = ((audited.body && (audited.body.events ||
    audited.body.rows)) || []).filter(function (row) {
    return String(row.actor || "").indexOf(ALICE) >= 0;
  })[0];
  check("B5. a search is audited as the person's call, with its text",
        function () {
    assert.ok(okRow, String(audited.raw).slice(0, 300));
    assert.ok(JSON.stringify(okRow).indexOf(TOKEN + "-") >= 0,
              JSON.stringify(okRow).slice(0, 300));
  });
  for (const ch of Object.keys(odd)) {
    const answer = await search(TOKEN + "q" + ch);
    check("B6. " + JSON.stringify(ch) + " matches itself and nothing else",
          function () {
      assert.strictEqual(answer.status, 200, JSON.stringify(answer.json));
      assert.deepStrictEqual(uidsOf(answer), [odd[ch]]);
    });
  }
  found = await search(TOKEN + "cap");
  const capAll = found;
  found = await search(TOKEN + "cap0");
  check("B7. twelve matches answer ten and say more matched; exactly ten " +
        "answer ten and say nothing more did", function () {
    assert.strictEqual(uidsOf(capAll).length, 10, JSON.stringify(capAll.json)
      .slice(0, 300));
    assert.strictEqual(capAll.json.more, true);
    assert.strictEqual(uidsOf(found).length, 10);
    assert.strictEqual(found.json.more, false);
  });
  found = await search(BOB);
  const chosen = (found.json.people || [])[0] || {};
  const set = await alice.api("POST", "/account-api/delegate",
                              { action: "set", delegate: chosen.dn });
  const now = viewOf(await alice.api("GET", "/account-api/delegate"));
  check("B8. choosing a result names them through the existing POST: the " +
        "delegate is their DN", function () {
    assert.strictEqual(set.status, 200, JSON.stringify(set.json));
    assert.ok(JSON.stringify(now).toLowerCase().indexOf(
      String(chosen.dn).toLowerCase()) >= 0, JSON.stringify(now)
      .slice(0, 300));
  });

  // THE STAMP: every door a caller has refuses it.
  const forged = await send("POST", api + "/users/create", {
    username: TOKEN + "-forged", invent: false, credential: "password",
    password: PASSWORD, attributes: { cn: "Forged", givenName: "F",
      sn: "F", mail: "forged@pr.example.test",
      stsProvisionedBy: "federation:x" } });
  const forgedThere = await send("GET", api + "/users?user=" +
                                 encodeURIComponent(TOKEN + "-forged"));
  const setStamp = await send("POST", api + "/users/set-attribute",
    { user: BOB, attribute: "stsProvisionedBy", value: "federation:x" });
  const selfStamp = await alice.api("POST", "/account-api/attributes",
    { attribute: "stsProvisionedBy", values: ["federation:x"] });
  check("B9. /admin-api's create and set-attribute, and the portal's own " +
        "editor, refuse stsProvisionedBy, and nothing is written",
        function () {
    assert.ok(forged.status >= 400, forged.raw.slice(0, 300));
    assert.ok(!(forgedThere.status === 200 && forgedThere.raw.indexOf(
      TOKEN + "-forged") >= 0 && /stsprovisionedby/i.test(forgedThere.raw)),
              forgedThere.raw.slice(0, 300));
    assert.ok(setStamp.status >= 400, setStamp.raw.slice(0, 300));
    assert.ok(selfStamp.status >= 400, JSON.stringify(selfStamp.json));
  });
  const bobAttrs = await valuesOf(R_DELEG, BOB, "stsProvisionedBy");
  assert.deepStrictEqual(bobAttrs, []);
  const usersDn = String(aliceMade.dn).replace(/^[^,]+,/, "");
  const ldapUrl = process.env.STS_LDAPS_URL || ("ldaps://localhost:" +
    (process.env.STS_LDAPS_PORT || 636));
  const defaultCount = async function () {
    log.debug("Entering defaultCount().");
    const r = await send("GET", base + "/admin-api/audit?per=500&code=" +
                         "STS-LDAP-0076");
    log.debug("Leaving defaultCount().");
    return Number((r.body && r.body.matched) || 0);
  };
  const c76 = await codeCount(R_DELEG, "STS-LDAP-0076") +
    await defaultCount();
  const added = await ldapAdd(ldapUrl, aliceMade.dn,
    "uid=" + TOKEN + "-ldapforged," + usersDn,
    { objectClass: ["inetOrgPerson"], uid: TOKEN + "-ldapforged",
      cn: "Forged", sn: "Forged", stsProvisionedBy: "federation:x" });
  const ldapThere = await send("GET", api + "/users?user=" +
                               encodeURIComponent(TOKEN + "-ldapforged"));
  let n76 = 0;
  for (let i = 0; i < 20 && n76 <= c76; i += 1) {
    n76 = await codeCount(R_DELEG, "STS-LDAP-0076") + await defaultCount();
    if (n76 <= c76) {
      await sleep(150);
    }
  }
  check("B10. an LDAP add naming stsProvisionedBy is refused " +
        "(STS-LDAP-0076), and no entry is made", function () {
    assert.strictEqual(added.ok, false, JSON.stringify(added));
    assert.ok(n76 > c76, c76 + " -> " + n76);
    assert.ok(!/stsprovisionedby/i.test(ldapThere.raw),
              ldapThere.raw.slice(0, 300));
  });
  log.info("B10's refusal: " + added.error);

  // C. THE LIST: an entry with nothing enrolled is the empty list.
  log.info("=== C. a portal list that must not read as empty ===");
  const selfIssued = await alice.api("GET", "/account-api/self-issued");
  check("C1. /account-api/self-issued answers an entry with nothing " +
        "enrolled 200 and an empty list, never a refusal", function () {
    assert.strictEqual(selfIssued.status, 200,
                       JSON.stringify(selfIssued.json));
    const v = viewOf(selfIssued);
    assert.ok(Array.isArray(v.subjects) && v.subjects.length === 0,
              JSON.stringify(v).slice(0, 300));
  });
  log.debug("Leaving partDelegate().");
}

// ---------------------------------------------------------------------------
// D. RESOURCES I OWN.
// ---------------------------------------------------------------------------
async function partOwned() {
  log.debug("Entering partOwned().");
  log.info("=== D. resources I own ===");
  await makeRealm(R_OWNED, "");
  const api = rb(R_OWNED) + "/admin-api";
  const ANN = "po-ann-" + STAMP;
  const BO = "po-bo-" + STAMP;
  const SVC = "po-svc-" + STAMP;
  const SVC2 = "po-svc2-" + STAMP;
  for (const one of [ANN, BO, SVC, SVC2]) {
    await person(R_OWNED, one);
  }
  await ok(api + "/groups/create", { group: "po-team" }, "po-team");
  await ok(api + "/groups/add-member", { group: "po-team", member: ANN },
           "ann in po-team");
  await ok(api + "/groups/create", { group: "po-other" }, "po-other");
  await ok(api + "/groups/create", { group: "po-bos" }, "po-bos");
  await ok(api + "/groups/add-owner", { group: "po-other", owner: "po-team" },
           "po-team owns po-other");
  await ok(api + "/groups/add-owner", { group: "po-bos", owner: BO },
           "bo owns po-bos");
  await ok(api + "/roles/create-role", { role: "po-staff",
    description: "Staff" }, "po-staff");
  await ok(api + "/roles/create-role", { role: "po-ops" }, "po-ops");
  await ok(api + "/roles/add-owner", { role: "po-staff", owner: ANN },
           "ann owns po-staff");
  await ok(api + "/roles/add-owner", { role: "po-ops", owner: BO },
           "bo owns po-ops");
  await ok(api + "/applications/create", { identifier: "po-app",
    name: "po-app", protocols: ["oauth2"],
    fields: { oauthClientId: ["po-app"] } }, "po-app");
  await ok(api + "/applications/add-owner", { application: "po-app",
    owner: "po-team" }, "po-team owns po-app");
  await ok(api + "/users/set-service-account", { user: SVC, owners: [ANN] },
           "ann owns a service account");
  await ok(api + "/users/set-service-account", { user: SVC2, owners: [BO] },
           "bo owns another");
  const ann = await portal.signInToThePortal(rb(R_OWNED), ANN, log,
                                             { password: PASSWORD });
  const views = {};
  for (const kind of ["roles", "groups", "service-accounts",
                      "applications"]) {
    const r = await ann.api("GET", "/account-api/owned/" + kind);
    assert.strictEqual(r.status, 200, kind + ": " + JSON.stringify(r.json));
    views[kind] = viewOf(r);
  }
  const namesOf = function (kind) {
    log.debug("Entering namesOf().");
    log.debug("Leaving namesOf().");
    return (views[kind].rows || []).map(function (row) {
      return row.name;
    });
  };
  check("D1. a role naming the person is theirs, and says so; one naming " +
        "somebody else is not", function () {
    assert.deepStrictEqual(namesOf("roles"), ["po-staff"],
                           JSON.stringify(views.roles));
    assert.strictEqual(views.roles.rows[0].via.you, true);
  });
  check("D2. a group owned by a group the person is in is theirs through it",
        function () {
    assert.deepStrictEqual(namesOf("groups"), ["po-other"],
                           JSON.stringify(views.groups));
    assert.deepStrictEqual(views.groups.rows[0].via.groups, ["po-team"]);
    assert.strictEqual(views.groups.rows[0].via.you, false);
  });
  check("D3. a service account naming the person is theirs", function () {
    assert.deepStrictEqual(namesOf("service-accounts"), [SVC],
                           JSON.stringify(views["service-accounts"]));
  });
  check("D4. an application owned through a group is theirs", function () {
    assert.deepStrictEqual(namesOf("applications"), ["po-app"],
                           JSON.stringify(views.applications));
    assert.deepStrictEqual(views.applications.rows[0].via.groups,
                           ["po-team"]);
  });
  check("D5. the view counts the rows and does not list the person's groups",
        function () {
    assert.strictEqual(views.roles.groups, undefined);
    assert.strictEqual(views.roles.paging.total, 1,
                       JSON.stringify(views.roles.paging));
  });
  log.debug("Leaving partOwned().");
}

async function test() {
  log.debug("Entering test().");
  log.info("The portal's rules at " + base);
  await partAttributes();
  await partDelegate();
  await partOwned();
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 every realm this run made
// is removed at the end, pass or fail. A suite run leaves them standing
// (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of [R_ATTR, R_DELEG, R_OTHER, R_OWNED]) {
    const r = await send("POST", base + "/admin-api/realms/remove",
                         { id: id });
    log.info("removed the realm " + id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    log.info("removing the realms failed: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error(failure.stack || failure.message);
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
