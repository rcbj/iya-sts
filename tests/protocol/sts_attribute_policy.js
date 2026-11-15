// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_attribute_policy.js
//
// ---------------------------------------------------------------------------
// THE ATTRIBUTE POLICY, ITS NAMED PROFILES AND THE CUSTOM ATTRIBUTE
// REGISTER, OVER THE WIRE (#396, #1241).
//
// D12 (#444): carries over
//
//   * tests/attribute_policy.js — in a product realm and a development
//     realm this job creates:
//       A. the built-in default (uid, cn, sn, givenName, mail), enforced in
//          product; the catalogue offers what a person may be given, locks
//          uid, cn and sn, and never userPassword, memberOf or a binary;
//       B. a save replaces the list in the canonical spelling; userPassword
//          and memberOf refused (STS-LDAP-0166), so is a save with no list;
//          a profile name no cn can be refused by the schema (STS-API-0009,
//          where in process the action's own STS-LDAP-0165 is),
//          a description carrying a code refused (STS-LDAP-0211) and not
//          stored; an empty list saved; a reset back to the default;
//       C. custom attributes defined, refused (STS-LDAP-0170, and the
//          schema's pattern for a name that is no descr), offered by the
//          person editor under Custom with their syntax, a value checked
//          against it; another realm does not see them;
//       D. product: a create missing a required attribute refused
//          (STS-LDAP-0162) naming what is missing and writing nothing; a cn
//          made of the names; a required custom attribute asked for;
//       E. an edit taking a required value away refused (STS-LDAP-0164);
//          one of an attribute nothing requires is not; a person who never
//          held a required attribute may still be edited;
//       F. a custom attribute removed only once nothing requires it
//          (STS-LDAP-0173) and nobody holds a value (STS-LDAP-0172);
//          an unknown one (STS-LDAP-0174);
//       G. development enforces nothing, and says so;
//       H. the LDAP socket in product: an add missing a required attribute
//          and a modify deleting one are objectClassViolation (65), under
//          STS-LDAP-0162 and -0164, bound with an app password (an
//          administrator's own password is refused at a password-only door
//          in product, STS-AUTHN-0213);
//       I. the policies view carries the kind's five acts, the catalogue
//          and the filter that finds who lacks one.
//     Its D bootstrap exemption is a create only the realm's own seed
//     makes; it stays in process (d).
//   * tests/attribute_policy_named.js — named profiles: saved with a
//     precedence, listed in order, out of range refused (STS-LDAP-0166),
//     the realm's own; a person naming one is held to it at the create
//     (0162), a missing profile refused at the write (STS-LDAP-0106); a
//     group naming one holds its members at an edit (0164) and marks the
//     editor's row required, a non-member free; the lowest precedence wins;
//     the missing count judges each person by their own profile; a profile
//     something names is not deleted (STS-LDAP-0197) and the view lists who
//     names it; the custom attribute a named profile requires kept (0173);
//     the LDAP socket's add naming a profile held to it. Its D (a
//     reference no profile answers) is a state no door writes — the write
//     refuses it (0106) and the delete refuses while it is named (0197) —
//     so it stays in process (d).
//
// OWNED HERE (local: true): this repository's own management API and
// directory socket.
// ---------------------------------------------------------------------------

const assert = require("assert");
const ldapjs = require("ldapjs");
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
var log = bunyan.createLogger({ name: "sts_attribute_policy",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const PRODUCT = ("attrp-" + STAMP).slice(0, 31);
const DEV = ("attrd-" + STAMP).slice(0, 31);
const TAG = STAMP.slice(-8);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function hostOf(url) {
  log.debug("Entering hostOf().");
  log.debug("Leaving hostOf().");
  return new URL(url).hostname;
}

function ldapsUrl() {
  log.debug("Entering ldapsUrl().");
  log.debug("Leaving ldapsUrl().");
  return process.env.STS_LDAPS_URL ||
    ("ldaps://" + hostOf(base) + ":" + (process.env.STS_LDAPS_PORT || 636));
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

function post(url, payload) {
  log.debug("Entering post().");
  log.debug("Leaving post().");
  return send(url, { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload || {}) });
}

function apiOf(realm) {
  log.debug("Entering apiOf().");
  log.debug("Leaving apiOf().");
  return base + "/realm/" + realm + "/admin-api";
}

async function ok(promise, what) {
  log.debug("Entering ok().");
  const r = await promise;
  assert.ok(r.status === 200 && r.body && r.body.ok !== false,
    what + ": answered " + r.status + " " + String(r.raw).slice(0, 400));
  log.debug("Leaving ok().");
  return r.body;
}

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return ((r.body && r.body.errors) || []).join(" ");
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// The rows of the realm's audit log carrying `code`. A code is never sent.
async function rowsWith(api, code) {
  log.debug("Entering rowsWith(). " + code);
  const r = await send(api + "/audit?per=500&code=" + encodeURIComponent(code));
  log.debug("Leaving rowsWith().");
  return (r.body && r.body.events) || [];
}

// Runs `fn` and answers its result and whether a row carrying `code` was
// added — for `target`, when one is given.
async function recording(api, code, fn, target) {
  log.debug("Entering recording(). " + code);
  const mine = function (rows) {
    return rows.filter(function (row) {
      return !target || row.target === target;
    }).length;
  };
  const before = mine(await rowsWith(api, code));
  const out = await fn();
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(100);
    after = mine(await rowsWith(api, code));
  }
  log.debug("Leaving recording(). " + before + " -> " + after);
  return { out: out, recorded: after > before };
}

function policy(api, action, payload) {
  log.debug("Entering policy(). " + action);
  log.debug("Leaving policy().");
  return post(api + "/policies/" + action, payload);
}

async function attributesView(api, query) {
  log.debug("Entering attributesView().");
  const r = await send(api + "/policies" + (query || ""));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving attributesView().");
  return r.body;
}

function full(given, sur) {
  log.debug("Entering full().");
  log.debug("Leaving full().");
  return { givenName: given, sn: sur,
           mail: given.toLowerCase() + "@attr.example.test" };
}

function createUser(api, username, attributes, extra) {
  log.debug("Entering createUser(). " + username);
  log.debug("Leaving createUser().");
  return post(api + "/users/create", Object.assign({ username: username,
    invent: false, attributes: attributes || {} }, extra || {}));
}

function setAttribute(api, user, attribute, value) {
  log.debug("Entering setAttribute(). " + user + " " + attribute);
  log.debug("Leaving setAttribute().");
  return post(api + "/users/set-attribute", { user: user,
    attribute: attribute, value: value });
}

async function person(api, user) {
  log.debug("Entering person(). " + user);
  const r = await send(api + "/users?user=" + encodeURIComponent(user));
  log.debug("Leaving person().");
  return r.body || {};
}

function attributeOf(answer, name) {
  log.debug("Entering attributeOf().");
  const attrs = (answer.ldap && answer.ldap.entry &&
                 answer.ldap.entry.attributes) || {};
  log.debug("Leaving attributeOf().");
  return [].concat(attrs[name] || []);
}

function editorRow(answer, name) {
  log.debug("Entering editorRow().");
  log.debug("Leaving editorRow().");
  return ((answer.attributeEditor && answer.attributeEditor.attributes) ||
          []).filter(function (row) {
    return row.name === name;
  })[0] || null;
}

// An LDAPS client bound as `dn`, or the bind's error.
function bound(dn, password) {
  log.debug("Entering bound().");
  return new Promise(function (resolve, reject) {
    const client = ldapjs.createClient({ url: ldapsUrl(),
      tlsOptions: { rejectUnauthorized: false } });
    client.on("error", function (e) {
      log.debug("Caught in bound(): " + ((e && e.message) || e));
      reject(e);
    });
    client.bind(dn, password, function (e) {
      if (e) {
        client.unbind();
        log.debug("Leaving bound(). Refused.");
        reject(e);
        return;
      }
      log.debug("Leaving bound().");
      resolve(client);
    });
  });
}

function ldapAdd(client, dn, attributes) {
  log.debug("Entering ldapAdd(). " + dn);
  return new Promise(function (resolve) {
    client.add(dn, attributes, function (e) {
      log.debug("Leaving ldapAdd(). " + (e ? e.name : "ok"));
      resolve(e ? { ok: false, name: e.name } : { ok: true });
    });
  });
}

function ldapModify(client, dn, operation, attribute, value) {
  log.debug("Entering ldapModify(). " + dn);
  return new Promise(function (resolve) {
    const modification = new ldapjs.Attribute({ type: attribute,
      values: value === undefined ? [] : [value] });
    client.modify(dn, new ldapjs.Change({ operation: operation,
                                          modification: modification }),
      function (e) {
        log.debug("Leaving ldapModify(). " + (e ? e.name : "ok"));
        resolve(e ? { ok: false, name: e.name } : { ok: true });
      });
  });
}

async function builtIn(api) {
  log.debug("Entering builtIn().");
  log.info("=== A. the built-in default ===");
  const view = (await attributesView(api)).attributes;
  check("A. the built-in default requires uid, cn, sn, givenName and mail, " +
        "enforced in product mode", function () {
    assert.deepStrictEqual(view.profile.required,
                           ["uid", "cn", "sn", "givenName", "mail"]);
    assert.strictEqual(view.profile.from, "built-in");
    assert.strictEqual(view.enforced, true);
  });
  const lower = view.catalogue.map(function (row) {
    return row.name.toLowerCase();
  });
  check("A. the catalogue offers what a person may be given, locks uid, cn " +
        "and sn, and never a credential, memberOf or a binary", function () {
    ["uid", "cn", "sn", "givenname", "mail", "telephonenumber",
     "employeenumber"].forEach(function (one) {
      assert.ok(lower.indexOf(one) >= 0, one);
    });
    ["userpassword", "memberof", "jpegphoto",
     "ststotpcredential"].forEach(function (one) {
      assert.ok(lower.indexOf(one) < 0, one);
    });
    assert.deepStrictEqual(view.catalogue.filter(function (row) {
      return row.locked;
    }).map(function (row) {
      return row.name;
    }).sort(), ["cn", "sn", "uid"]);
  });
  log.debug("Leaving builtIn().");
}

async function saves(api) {
  log.debug("Entering saves().");
  log.info("=== B. saves and their refusals ===");
  const saved = await ok(policy(api, "save-attributes-policy",
    { requiredAttributes: ["GIVENNAME", "telephoneNumber"] }), "saved");
  check("B. a save replaces the list, in the canonical spelling",
        function () {
    assert.strictEqual(saved.profile.from, "realm");
    assert.deepStrictEqual(saved.profile.required,
      ["uid", "cn", "sn", "givenName", "telephoneNumber"]);
  });
  for (const one of [["givenName, userPassword", "userPassword"],
                     [["memberOf"], "memberOf"]]) {
    const r = await recording(api, "STS-LDAP-0166", function () {
      return policy(api, "save-attributes-policy",
                    { requiredAttributes: one[0] });
    });
    check("B. " + one[1] + " cannot be required (STS-LDAP-0166)",
          function () {
      assert.strictEqual(r.out.status, 400, r.out.raw.slice(0, 300));
      assert.ok(r.recorded, "no STS-LDAP-0166 row");
    });
  }
  const badName = await recording(api, "STS-API-0009", function () {
    return policy(api, "save-attributes-policy",
                  { profile: "Not A Name!", requiredAttributes: ["mail"] });
  });
  const noList = await recording(api, "STS-LDAP-0166", function () {
    return policy(api, "save-attributes-policy", {});
  });
  check("B. a profile name no cn can be is refused by the request's schema " +
        "(STS-API-0009); a save with no list by the action (STS-LDAP-0166)",
        function () {
    assert.ok(badName.out.status === 400 && badName.recorded,
              badName.out.raw.slice(0, 300));
    assert.ok(/"profile" must match pattern/.test(errorsOf(badName.out)));
    assert.ok(noList.out.status === 400 && noList.recorded,
              noList.out.raw.slice(0, 300));
  });
  const coded = await recording(api, "STS-LDAP-0211", function () {
    return policy(api, "save-attributes-policy",
      { requiredAttributes: ["mail"],
        description: "kept for the operator (STS-LDAP-0001)." });
  });
  const afterCoded = (await attributesView(api)).attributes.profile;
  check("B. a description carrying an operator code is refused " +
        "(STS-LDAP-0211), the refusal names no code, nothing is stored",
        function () {
    assert.ok(coded.out.status === 400 && coded.recorded,
              coded.out.raw.slice(0, 300));
    assert.ok(errorsOf(coded.out).indexOf("STS-") < 0);
    assert.ok(afterCoded.description.indexOf("STS-LDAP-0001") < 0);
    assert.ok(afterCoded.required.indexOf("telephoneNumber") >= 0);
  });
  const empty = await ok(policy(api, "save-attributes-policy",
    { requiredAttributes: [] }), "saved an empty list");
  check("B. a form with nothing ticked saves an empty list, and uid, cn and " +
        "sn are still required", function () {
    assert.deepStrictEqual(empty.profile.required, ["uid", "cn", "sn"]);
    assert.strictEqual(empty.profile.problems.length, 0);
  });
  const reset = await ok(policy(api, "reset-attributes-policy", {}),
                         "reset");
  check("B. a reset goes back to the built-in default", function () {
    assert.strictEqual(reset.removed, true);
    assert.deepStrictEqual(reset.profile.required,
                           ["uid", "cn", "sn", "givenName", "mail"]);
  });
  log.debug("Leaving saves().");
}

async function custom(api) {
  log.debug("Entering custom().");
  log.info("=== C. custom attributes ===");
  await ok(policy(api, "define-person-attribute", { name: "employeeBadge",
    label: "Badge number", syntax: "string", multiValued: "single" }),
    "defined employeeBadge");
  await ok(policy(api, "define-person-attribute", { name: "clearanceLevel",
    label: "Clearance", syntax: "integer" }), "defined clearanceLevel");
  const view = (await attributesView(api)).attributes;
  check("C. two custom attributes are defined", function () {
    const listed = (view.custom || []).map(function (one) {
      return one.name;
    }).sort();
    assert.deepStrictEqual(listed, ["clearanceLevel", "employeeBadge"]);
  });
  const descr = await policy(api, "define-person-attribute",
                             { name: "9lives", label: "x" });
  check("C. a name that is no RFC 4512 descr is refused by the schema",
        function () {
    assert.strictEqual(descr.status, 400, descr.raw.slice(0, 300));
    assert.ok(/"name" must match pattern/.test(errorsOf(descr)));
  });
  for (const one of [["stsShadow", "a name beginning sts"],
                     ["memberOf", "memberOf"],
                     ["telephoneNumber", "a name the schema already has"],
                     ["EMPLOYEEBADGE", "a second definition, in another " +
                      "case"]]) {
    const r = await recording(api, "STS-LDAP-0170", function () {
      return policy(api, "define-person-attribute",
                    { name: one[0], label: "x" });
    });
    check("C. " + one[1] + " is refused as STS-LDAP-0170", function () {
      assert.ok(r.out.status === 400 && r.recorded, r.out.raw.slice(0, 300));
    });
  }
  log.debug("Leaving custom().");
}

async function enforcement(api) {
  log.debug("Entering enforcement().");
  log.info("=== C/D/E. the editor, creates and edits in product ===");
  const BARE = "attrp-bare-" + TAG;
  const bare = await recording(api, "STS-LDAP-0162", function () {
    return createUser(api, BARE, {});
  });
  const bareAfter = await person(api, BARE);
  check("D. a create with nothing typed is refused as STS-LDAP-0162, " +
        "naming what is missing, and nothing is written", function () {
    assert.ok(bare.out.status === 400 && bare.recorded,
              bare.out.raw.slice(0, 300));
    assert.deepStrictEqual(bare.out.body.missing,
                           ["cn", "sn", "givenName", "mail"]);
    assert.ok(bareAfter.known === false || !bareAfter.ldap ||
              !bareAfter.ldap.entry, JSON.stringify(bareAfter).slice(0, 300));
  });
  const WHOLE = "attrp-whole-" + TAG;
  await ok(createUser(api, WHOLE, full("Ada", "Lovelace")),
           "created a whole person");
  const whole = await person(api, WHOLE);
  check("D. a create with givenName, sn and mail succeeds, its cn made of " +
        "the names", function () {
    assert.deepStrictEqual(attributeOf(whole, "cn"), ["Ada Lovelace"]);
  });
  const row = editorRow(whole, "clearanceLevel");
  check("C. the person editor offers a custom attribute under Custom with " +
        "its syntax", function () {
    assert.ok(row && row.custom === true && row.group === "custom" &&
              row.format === "integer" && row.multi === false,
              JSON.stringify(row));
  });
  const goodValue = await setAttribute(api, WHOLE, "clearanceLevel", "3");
  const badValue = await setAttribute(api, WHOLE, "clearanceLevel", "three");
  check("C. a custom attribute's values are checked against its syntax",
        function () {
    assert.strictEqual(goodValue.status, 200, goodValue.raw.slice(0, 300));
    assert.strictEqual(badValue.status, 400, badValue.raw.slice(0, 300));
    assert.ok(/not a whole number/.test(errorsOf(badValue)));
  });
  await ok(policy(api, "save-attributes-policy", { requiredAttributes:
    ["givenName", "mail", "employeeBadge"] }), "required a custom one");
  const noBadge = await createUser(api, "attrp-nobadge-" + TAG,
                                   full("Grace", "Hopper"));
  const withBadge = await createUser(api, "attrp-badge-" + TAG,
    Object.assign(full("Grace", "Hopper"), { employeeBadge: "B-1" }));
  check("D. a required custom attribute is asked for, and accepted once " +
        "given", function () {
    assert.strictEqual(noBadge.status, 400, noBadge.raw.slice(0, 300));
    assert.deepStrictEqual(noBadge.body.missing, ["employeeBadge"]);
    assert.strictEqual(withBadge.status, 200, withBadge.raw.slice(0, 300));
  });
  const emptied = await recording(api, "STS-LDAP-0164", function () {
    return setAttribute(api, WHOLE, "givenName", "");
  });
  const keptName = attributeOf(await person(api, WHOLE), "givenName");
  check("E. an edit emptying a required attribute is refused as " +
        "STS-LDAP-0164, and the value is kept", function () {
    assert.ok(emptied.out.status === 400 && emptied.recorded,
              emptied.out.raw.slice(0, 300));
    assert.deepStrictEqual(keptName, ["Ada"]);
  });
  const phone = await setAttribute(api, WHOLE, "telephoneNumber",
                                   "+1 555 0100");
  const unphone = await setAttribute(api, WHOLE, "telephoneNumber", "");
  check("E. an attribute nothing requires is set and emptied freely",
        function () {
    assert.strictEqual(phone.status, 200, phone.raw.slice(0, 300));
    assert.strictEqual(unphone.status, 200, unphone.raw.slice(0, 300));
  });
  // A person made under the default list holds no employeeBadge, which is
  // required now: a person who never held a required attribute may still
  // be edited.
  const lacking = await setAttribute(api, WHOLE, "title", "Administrator");
  check("E. a person who never held a required attribute may still be " +
        "edited", function () {
    assert.strictEqual(lacking.status, 200, lacking.raw.slice(0, 300));
  });

  log.info("=== F. a custom attribute removed ===");
  const whileRequired = await recording(api, "STS-LDAP-0173", function () {
    return policy(api, "remove-person-attribute", { name: "employeeBadge" });
  });
  await ok(policy(api, "save-attributes-policy",
                  { requiredAttributes: ["givenName", "mail"] }),
           "stopped requiring it");
  const whileHeld = await recording(api, "STS-LDAP-0172", function () {
    return policy(api, "remove-person-attribute", { name: "employeeBadge" });
  });
  await ok(setAttribute(api, "attrp-badge-" + TAG, "employeeBadge", ""),
           "emptied the badge");
  const nobodyHolds = await policy(api, "remove-person-attribute",
                                   { name: "employeeBadge" });
  const unknown = await recording(api, "STS-LDAP-0174", function () {
    return policy(api, "remove-person-attribute", { name: "neverDefined" });
  });
  check("F. a custom attribute is not removed while the profile requires " +
        "it (0173) or a person holds a value (0172), and is once neither " +
        "does; an unknown one is refused (0174)", function () {
    assert.ok(whileRequired.out.status === 400 && whileRequired.recorded,
              whileRequired.out.raw.slice(0, 300));
    assert.ok(whileHeld.out.status === 400 && whileHeld.recorded,
              whileHeld.out.raw.slice(0, 300));
    assert.strictEqual(whileHeld.out.body.holders, 1);
    assert.strictEqual(nobodyHolds.status, 200, nobodyHolds.raw.slice(0, 300));
    assert.strictEqual(nobodyHolds.body.removed, true);
    assert.ok(unknown.out.status === 400 && unknown.recorded,
              unknown.out.raw.slice(0, 300));
  });
  log.debug("Leaving enforcement().");
}

async function development(devApi, productApi) {
  log.debug("Entering development().");
  log.info("=== G. development, and another realm ===");
  await ok(policy(devApi, "define-person-attribute",
                  { name: "devOnly", label: "Dev only" }), "defined devOnly");
  const view = (await attributesView(devApi)).attributes;
  const bare = await createUser(devApi, "attrd-bare-" + TAG, {});
  check("G. development mode enforces nothing, and says so", function () {
    assert.strictEqual(view.enforced, false);
    assert.ok(view.rules.some(function (one) {
      return /not enforced/.test(one);
    }), JSON.stringify(view.rules));
  });
  check("G. a create with nothing typed succeeds in development",
        function () {
    assert.strictEqual(bare.status, 200, bare.raw.slice(0, 300));
  });
  const other = (await attributesView(productApi)).attributes;
  check("C. a realm does not see another realm's custom attributes",
        function () {
    assert.ok(!(other.custom || []).some(function (one) {
      return one.name === "devOnly";
    }), JSON.stringify(other.custom));
  });
  log.debug("Leaving development().");
}

async function theView(api) {
  log.debug("Entering theView().");
  log.info("=== I. the view and the acts ===");
  const answer = await attributesView(api, "?missing=count");
  const member = answer.attributes;
  const kind = answer.kinds.filter(function (one) {
    return one.id === "attributes";
  })[0];
  check("I. the policies view carries the catalogue, the five acts and the " +
        "filter that finds the people who lack one", function () {
    assert.strictEqual(member.enforced, true);
    assert.ok(member.catalogue.length > 20);
    assert.strictEqual(member.missingAsked, true);
    assert.ok(/^\(\|\(!\(uid=\*\)\)/.test(member.missingFilter),
              member.missingFilter);
    assert.deepStrictEqual(kind.actions, ["save-attributes-policy",
      "reset-attributes-policy", "define-person-attribute",
      "update-person-attribute", "remove-person-attribute"]);
  });
  const defined = await policy(api, "define-person-attribute",
                               { name: "viewProbe", label: "View probe" });
  const removed = await policy(api, "remove-person-attribute",
                               { name: "viewProbe" });
  check("I. the define and remove acts reach the register", function () {
    assert.strictEqual(defined.status, 200, defined.raw.slice(0, 300));
    assert.strictEqual(removed.status, 200, removed.raw.slice(0, 300));
    assert.strictEqual(removed.body.removed, true);
  });
  log.debug("Leaving theView().");
}

async function named(api, devApi) {
  log.debug("Entering named().");
  log.info("=== named profiles (attribute_policy_named.js) ===");
  await ok(policy(api, "save-attributes-policy", { profile: "contractors",
    requiredAttributes: ["givenName", "mail", "telephoneNumber"],
    precedence: 50 }), "saved contractors");
  await ok(policy(api, "save-attributes-policy", { profile: "strict",
    requiredAttributes: ["givenName", "mail", "title"], precedence: 10 }),
    "saved strict");
  // A number past the schema's bound is the schema's refusal; the same
  // value as a string, which the schema admits, reaches the action's own
  // range check (STS-LDAP-0166), the in-process file's refusal.
  const numeric = await policy(api, "save-attributes-policy",
    { profile: "loose", requiredAttributes: [], precedence: 5000 });
  const badPrecedence = await recording(api, "STS-LDAP-0166", function () {
    return policy(api, "save-attributes-policy", { profile: "loose",
      requiredAttributes: [], precedence: "5000" });
  });
  const listed = (await attributesView(api)).attributes.named || [];
  const order = ["default:0"].concat(listed.map(function (one) {
    return one.name + ":" + one.precedence;
  }));
  check("A. named profiles are saved with a precedence and listed after " +
        "default in precedence order; out of range is refused " +
        "(STS-LDAP-0166)", function () {
    assert.deepStrictEqual(order, ["default:0", "strict:10",
                                   "contractors:50"]);
    assert.ok(badPrecedence.out.status === 400 && badPrecedence.recorded,
              badPrecedence.out.raw.slice(0, 300));
    assert.ok(/"precedence" must be <= 1000/.test(errorsOf(numeric)),
              numeric.raw.slice(0, 300));
  });
  const devNamed = (await attributesView(devApi)).attributes.named || [];
  check("A. a named profile is the realm's own: another realm holds none " +
        "of these", function () {
    assert.ok(!devNamed.some(function (one) {
      return one.name === "contractors" || one.name === "strict";
    }), JSON.stringify(devNamed));
  });
  const lacking = await recording(api, "STS-LDAP-0162", function () {
    return createUser(api, "np-lack-" + TAG, Object.assign(
      full("Lacking", "Person"), { stsAttributePolicy: "contractors" }));
  });
  const whole = await createUser(api, "np-whole-" + TAG, Object.assign(
    full("Whole", "Person"), { stsAttributePolicy: "Contractors",
                               telephoneNumber: "+1 555 0100" }));
  const plain = await createUser(api, "np-plain-" + TAG,
                                 full("Plain", "Person"));
  const ghost = await recording(api, "STS-LDAP-0106", function () {
    return createUser(api, "np-ghost-" + TAG, Object.assign(
      full("Ghost", "Person"), { stsAttributePolicy: "gone" }));
  });
  check("B. a newcomer naming a profile is held to its list (0162) and made " +
        "once it is met; one naming none is held to default; a profile the " +
        "realm does not hold is refused at the write (0106)", function () {
    assert.ok(lacking.out.status === 400 && lacking.recorded,
              lacking.out.raw.slice(0, 300));
    assert.deepStrictEqual(lacking.out.body.missing, ["telephoneNumber"]);
    assert.ok(/"contractors"/.test(errorsOf(lacking.out)));
    assert.strictEqual(whole.status, 200, whole.raw.slice(0, 300));
    assert.strictEqual(plain.status, 200, plain.raw.slice(0, 300));
    assert.ok(ghost.out.status === 400 && ghost.recorded,
              ghost.out.raw.slice(0, 300));
  });
  const GROUP = "np-group-" + TAG;
  const MEMBER = "np-member-" + TAG;
  const OUTSIDER = "np-outsider-" + TAG;
  for (const name of [MEMBER, OUTSIDER]) {
    await ok(createUser(api, name, Object.assign(full("Titled", name),
                                                 { title: "Engineer" })),
             "created " + name);
  }
  await ok(post(api + "/groups/create", { group: GROUP }), "made the group");
  await ok(post(api + "/groups/add-member", { group: GROUP, member: MEMBER }),
           "added the member");
  await ok(post(api + "/groups/set-policy", { group: GROUP,
    attribute: "stsAttributePolicy", policy: "strict" }),
    "named strict on the group");
  const memberRow = editorRow(await person(api, MEMBER), "title");
  const outsiderRow = editorRow(await person(api, OUTSIDER), "title");
  const kept = await recording(api, "STS-LDAP-0164", function () {
    return setAttribute(api, MEMBER, "title", "");
  });
  const dropped = await setAttribute(api, OUTSIDER, "title", "");
  check("C. a member of a group naming a profile may not lose a value it " +
        "requires (0164), and the editor marks the row required; a " +
        "non-member may", function () {
    assert.strictEqual(memberRow.required, true);
    assert.strictEqual(outsiderRow.required, false);
    assert.ok(kept.out.status === 400 && kept.recorded,
              kept.out.raw.slice(0, 300));
    assert.ok(/"strict"/.test(errorsOf(kept.out)));
    assert.strictEqual(dropped.status, 200, dropped.raw.slice(0, 300));
  });
  await ok(setAttribute(api, MEMBER, "stsAttributePolicy", "contractors"),
           "the member names contractors");
  const cleared = await setAttribute(api, MEMBER, "title", "");
  check("C. between the person's reference and their group's, the lowest " +
        "precedence (the group's strict) still holds", function () {
    assert.strictEqual(cleared.status, 400, cleared.raw.slice(0, 300));
    assert.ok(/"strict"/.test(errorsOf(cleared)));
  });
  const groupHeld = await recording(api, "STS-LDAP-0197", function () {
    return policy(api, "reset-attributes-policy", { profile: "strict" });
  });
  await ok(post(api + "/groups/set-policy", { group: GROUP,
    attribute: "stsAttributePolicy", policy: "" }), "cleared the group's");
  const personHeld = await recording(api, "STS-LDAP-0197", function () {
    return policy(api, "reset-attributes-policy", { profile: "contractors" });
  });
  const contractors = ((await attributesView(api)).attributes.named || [])
    .filter(function (one) {
      return one.name === "contractors";
    })[0];
  check("F. a named profile a group or a person names is not deleted " +
        "(0197), and the view lists the people naming it", function () {
    assert.ok(groupHeld.out.status === 400 && groupHeld.recorded,
              groupHeld.out.raw.slice(0, 300));
    assert.ok(errorsOf(groupHeld.out).indexOf(GROUP) >= 0);
    assert.ok(personHeld.out.status === 400 && personHeld.recorded,
              personHeld.out.raw.slice(0, 300));
    const people = (contractors && contractors.namedBy &&
                    contractors.namedBy.people) || [];
    assert.ok(people.indexOf(MEMBER) >= 0 &&
              people.indexOf("np-whole-" + TAG) >= 0,
              JSON.stringify(contractors && contractors.namedBy));
  });
  const BADGE = "npBadge" + TAG.replace(/[^a-z0-9]/g, "");
  await ok(policy(api, "define-person-attribute", { name: BADGE,
                                                    label: "Badge" }),
           "defined a badge");
  await ok(policy(api, "save-attributes-policy", { profile: "strict",
    requiredAttributes: [BADGE], precedence: 10 }), "strict requires it");
  const required = await recording(api, "STS-LDAP-0173", function () {
    return policy(api, "remove-person-attribute", { name: BADGE });
  });
  await ok(policy(api, "save-attributes-policy", { profile: "strict",
    requiredAttributes: ["title"], precedence: 10 }), "strict no longer");
  const free = await policy(api, "remove-person-attribute", { name: BADGE });
  check("F. a custom attribute a named profile requires is not removed " +
        "(0173), and is once none does", function () {
    assert.ok(required.out.status === 400 && required.recorded,
              required.out.raw.slice(0, 300));
    assert.strictEqual(free.status, 200, free.raw.slice(0, 300));
  });
  const gone = await ok(policy(api, "reset-attributes-policy",
                               { profile: "strict" }), "deleted strict");
  const left = ((await attributesView(api)).attributes.named || [])
    .map(function (one) {
      return one.name;
    });
  check("F. a named profile nobody names is deleted", function () {
    assert.strictEqual(gone.removed, true);
    assert.deepStrictEqual(left, ["contractors"]);
  });
  log.debug("Leaving named().");
}

async function counted(devApi) {
  log.debug("Entering counted().");
  log.info("=== E (named). the missing count, per person's profile ===");
  const count = async function () {
    return (await attributesView(devApi, "?missing=count")).attributes
      .missing;
  };
  const before = await count();
  await ok(policy(devApi, "save-attributes-policy", { profile: "phones",
    requiredAttributes: ["telephoneNumber"], precedence: 20 }),
    "saved phones");
  const GROUP = "nc-group-" + TAG;
  await ok(post(devApi + "/groups/create", { group: GROUP }), "made a group");
  await ok(post(devApi + "/groups/set-policy", { group: GROUP,
    attribute: "stsAttributePolicy", policy: "phones" }), "named phones");
  await ok(createUser(devApi, "nc-own-" + TAG, Object.assign(
    full("Own", "Ref"), { stsAttributePolicy: "phones" })), "own ref");
  await ok(createUser(devApi, "nc-grouped-" + TAG, full("Grouped", "Ref")),
           "grouped");
  await ok(post(devApi + "/groups/add-member", { group: GROUP,
    member: "nc-grouped-" + TAG }), "added to the group");
  await ok(createUser(devApi, "nc-default-" + TAG, full("Default", "Ref")),
           "under default");
  const after = await count();
  check("E. the count judges each person against their own profile: the " +
        "one naming it and the group's member are counted, the one under " +
        "default is not; development refuses nobody", function () {
    assert.strictEqual(typeof before, "number");
    assert.strictEqual(after, before + 2, before + " -> " + after);
  });
  log.debug("Leaving counted().");
}

async function socket(api) {
  log.debug("Entering socket().");
  log.info("=== H. the LDAP socket in product ===");
  const ADMIN = "attrp-admin-" + TAG;
  const PERSON = "attrp-sock-" + TAG;
  await ok(createUser(api, ADMIN, full("Admin", "Socket"),
    { credential: "password", password: "Attr-Admin-" + TAG + "-Pw!x" }),
    "created the administrator");
  await ok(post(api + "/rbac/grant", { username: ADMIN, role: "write" }),
           "granted Admin Write");
  // Writing stsAttributePolicy over the socket is a security
  // administrator's, as tests/attribute_policy_named.js grants it.
  await ok(post(api + "/rbac/grant", { username: ADMIN, role: "security" }),
           "granted Security Administrator");
  await ok(createUser(api, PERSON, full("Sock", "Person")),
           "created the person");
  const adminDn = (await person(api, ADMIN)).ldap.entry.dn;
  const personDn = (await person(api, PERSON)).ldap.entry.dn;
  const users = adminDn.replace(/^[^,]*,/, "");
  let refusedOwn = null;
  try {
    const c = await bound(adminDn, "Attr-Admin-" + TAG + "-Pw!x");
    c.unbind();
  } catch (e) {
    log.debug("Caught in socket(): " + ((e && e.message) || e));
    // Expected: the administrator's own password at a password-only door.
    refusedOwn = e;
  }
  check("H. an administrator's own password is refused at the LDAP bind in " +
        "product (a password-only door)", function () {
    assert.ok(refusedOwn && refusedOwn.name === "InvalidCredentialsError",
              String(refusedOwn && refusedOwn.name));
  });
  const app = await ok(post(api + "/users/create-app-password",
    { user: ADMIN, name: "attribute policy job", doors: ["ldap"] }),
    "made an LDAP app password");
  const client = await bound(adminDn, app.appPassword);
  try {
    const NEW = "uid=attrp-ldap-" + TAG + "," + users;
    const classes = ["top", "person", "organizationalPerson",
                     "inetOrgPerson"];
    const partial = await recording(api, "STS-LDAP-0162", function () {
      return ldapAdd(client, NEW, { objectClass: classes,
        uid: "attrp-ldap-" + TAG, cn: "Lin Partial", sn: "Partial" });
    }, NEW);
    check("H. an LDAP add missing givenName and mail is objectClassViolation " +
          "(65), recorded as STS-LDAP-0162", function () {
      assert.strictEqual(partial.out.name, "ObjectclassViolationError");
      assert.ok(partial.recorded, "no STS-LDAP-0162 row for " + NEW);
    });
    const complete = await ldapAdd(client, NEW, { objectClass: classes,
      uid: "attrp-ldap-" + TAG, cn: "Lin Whole", sn: "Whole",
      givenName: "Lin", mail: "lin@attr.example.test" });
    check("H. an LDAP add carrying them succeeds", function () {
      assert.ok(complete.ok, JSON.stringify(complete));
    });
    const taken = await recording(api, "STS-LDAP-0164", function () {
      return ldapModify(client, personDn, "delete", "mail");
    }, personDn);
    const mail = attributeOf(await person(api, PERSON), "mail");
    check("H. an LDAP modify deleting mail is objectClassViolation, recorded " +
          "as STS-LDAP-0164, and changes nothing", function () {
      assert.strictEqual(taken.out.name, "ObjectclassViolationError");
      assert.ok(taken.recorded, "no STS-LDAP-0164 row for " + personDn);
      assert.strictEqual(mail.length, 1);
    });
    const other = await ldapModify(client, personDn, "replace", "title",
                                   "Engineer");
    check("H. an LDAP modify of an attribute nothing requires succeeds",
          function () {
      assert.ok(other.ok, JSON.stringify(other));
    });
    await ok(policy(api, "save-attributes-policy", { profile: "socketprobe",
      requiredAttributes: ["givenName", "mail", "title"], precedence: 30 }),
      "saved socketprobe");
    const NAMED = "uid=attrn-ldap-" + TAG + "," + users;
    const namedAdd = function (extra) {
      return ldapAdd(client, NAMED, Object.assign({ objectClass: classes,
        uid: "attrn-ldap-" + TAG, cn: "Ann Probe", sn: "Probe",
        givenName: "Ann", mail: "ann@attr.example.test",
        stsAttributePolicy: "socketprobe" }, extra));
    };
    const short = await recording(api, "STS-LDAP-0162", function () {
      return namedAdd({});
    }, NAMED);
    const met = await namedAdd({ title: "Probe" });
    check("G (named). an LDAP add naming a profile is held to it " +
          "(objectClassViolation, STS-LDAP-0162), and succeeds with what " +
          "it requires", function () {
      assert.strictEqual(short.out.name, "ObjectclassViolationError");
      assert.ok(short.recorded, "no STS-LDAP-0162 row for " + NAMED);
      assert.ok(met.ok, JSON.stringify(met));
    });
  } finally {
    client.unbind();
  }
  log.debug("Leaving socket().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. a product realm " + PRODUCT + " and a development realm " +
           DEV + " ===");
  for (const id of [PRODUCT, DEV]) {
    await ok(post(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Attribute policy " + STAMP }),
      "created the realm " + id);
  }
  const productApi = apiOf(PRODUCT);
  const devApi = apiOf(DEV);
  await ok(post(productApi + "/config/set", { key: "global.mode",
                                              value: "product" }),
           "switched " + PRODUCT + " to product");
  await builtIn(productApi);
  await saves(productApi);
  await custom(productApi);
  await enforcement(productApi);
  await development(devApi, productApi);
  await theView(productApi);
  await named(productApi, devApi);
  await counted(devApi);
  await socket(productApi);
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

async function main() {
  log.debug("Entering main().");
  try {
    await test();
    log.info("Test completed successfully.");
    log.debug("Leaving main().");
    process.exit(0);
  } catch (e) {
    log.error("Test failed: " + ((e && e.stack) || e));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
}

main();
