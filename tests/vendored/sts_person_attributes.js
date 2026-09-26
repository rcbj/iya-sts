"use strict";
//
// File: sts_person_attributes.js
//
// ===========================================================================
// A PERSON'S ATTRIBUTES, SET, ADDED TO AND REMOVED FROM THROUGH /admin-api,
// OVER HTTP (#228, 2026-09-26). `local: true`.
//
// A realm of its own, so the person it makes and the values it writes are in
// a directory nothing else reads. The in-process half is
// `tests/person_attribute_editor.js`; this is the half an AWS target and the
// product mode can run.
//
//   1. GET /admin-api/users?user= publishes `attributeEditor`: the entry's
//      DN in the realm's own tree, `title` among the editable attributes and
//      `userPassword` and `mail` among the withheld ones.
//   2. set-attribute, add-attribute and remove-attribute write the entry, and
//      the next GET reads what they wrote.
//   3. The refusals are 400s with a reason: a credential, the address, an add
//      to a single-valued attribute, a country code that is not one, and a
//      person the realm does not hold — the same name in the DEFAULT realm.
//   4. The OpenAPI document declares the three operations.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_person_attributes",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("pat").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const DOMAIN = REALM + ".example.net";
const WHO = usernameFor("pat-person").replace(/[^a-z0-9-]/g, "")
  .slice(0, 40);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function realmApi() {
  log.debug("Entering realmApi().");
  log.debug("Leaving realmApi().");
  return base + "/realm/" + REALM + "/admin-api";
}

async function call(method, url, body) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it into the message.
    json = null;
  }
  log.debug("Leaving call().");
  return { status: r.status, json: json, text: text };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

async function refused(url, body, what, pattern) {
  log.debug("Entering refused().");
  const r = await call("POST", url, body);
  check(what, function () {
    assert.strictEqual(r.status, 400, r.status + " " + r.text.slice(0, 300));
    assert.ok(r.json && r.json.ok === false &&
              pattern.test((r.json.errors || []).join(" ")),
              r.text.slice(0, 400));
  });
  log.debug("Leaving refused().");
}

async function editorOf(api, who) {
  log.debug("Entering editorOf().");
  const r = await call("GET", api + "/users?user=" + encodeURIComponent(who));
  assert.strictEqual(r.status, 200, r.text.slice(0, 300));
  log.debug("Leaving editorOf().");
  return r.json && r.json.attributeEditor;
}

function valuesIn(editor, name) {
  log.debug("Entering valuesIn().");
  const row = ((editor && editor.attributes) || []).filter(function (one) {
    return one.name === name;
  })[0];
  log.debug("Leaving valuesIn().");
  return row ? row.values : null;
}

async function test() {
  log.debug("Entering test().");
  log.info("Editing a person's attributes at " + base + " in the realm " +
           REALM);
  await ok(base + "/admin-api/realms/create",
           { id: REALM, domain: DOMAIN, name: "person attributes (#228)" },
           "created the realm");
  await ok(realmApi() + "/users/create",
           { username: WHO, invent: false,
             attributes: { cn: "Pat Person", sn: "Person" } },
           "created the person");

  // 1. THE PUBLISHED EDITOR
  let editor = await editorOf(realmApi(), WHO);
  check("1. GET /admin-api/users?user= publishes attributeEditor, in the " +
        "realm's own tree", function () {
    assert.ok(editor && Array.isArray(editor.attributes),
              JSON.stringify(editor).slice(0, 300));
    assert.ok(/dc=example,dc=net$/i.test(editor.dn) &&
              editor.dn.indexOf(REALM) >= 0, editor.dn);
  });
  check("1. title is editable; userPassword and mail are withheld",
        function () {
    assert.ok(valuesIn(editor, "title"), "no title row");
    const withheld = editor.withheld.map(function (one) {
      return one.name;
    });
    assert.ok(withheld.indexOf("userPassword") >= 0 &&
              withheld.indexOf("mail") >= 0, withheld.join(","));
  });

  // 2. THE THREE EDITS
  await ok(realmApi() + "/users/set-attribute",
           { user: WHO, attribute: "title", value: "Field Technician" },
           "set the title");
  await ok(realmApi() + "/users/add-attribute",
           { user: WHO, attribute: "mobile", value: "+46 70 000 00 01" },
           "added a mobile number");
  await ok(realmApi() + "/users/add-attribute",
           { user: WHO, attribute: "mobile", value: "+46 70 000 00 02" },
           "added a second mobile number");
  await ok(realmApi() + "/users/remove-attribute",
           { user: WHO, attribute: "mobile", value: "+46 70 000 00 01" },
           "removed the first");
  await ok(realmApi() + "/users/set-attribute",
           { user: WHO, attribute: "c", value: "se" },
           "set the country");
  editor = await editorOf(realmApi(), WHO);
  check("2. the next read holds what the three edits wrote", function () {
    assert.deepStrictEqual(valuesIn(editor, "title"), ["Field Technician"]);
    assert.deepStrictEqual(valuesIn(editor, "mobile"),
                           ["+46 70 000 00 02"]);
    assert.deepStrictEqual(valuesIn(editor, "c"), ["SE"]);
  });

  // 3. THE REFUSALS
  await refused(realmApi() + "/users/set-attribute",
                { user: WHO, attribute: "userPassword", value: "x" },
                "3. userPassword is refused, naming set-password",
                /set-password/);
  await refused(realmApi() + "/users/set-attribute",
                { user: WHO, attribute: "mail", value: "p@example.net" },
                "3. mail is refused, naming set-mail", /set-mail/);
  await refused(realmApi() + "/users/add-attribute",
                { user: WHO, attribute: "displayName", value: "Pat" },
                "3. an add to a single-valued attribute is refused",
                /one value/);
  await refused(realmApi() + "/users/set-attribute",
                { user: WHO, attribute: "c", value: "Sweden" },
                "3. a country that is not a code is refused", /ISO 3166/);
  await refused(base + "/admin-api/users/set-attribute",
                { user: WHO, attribute: "title", value: "x" },
                "3. the same name in the DEFAULT realm is nobody there",
                /no person called/);

  // 4. THE DOCUMENT
  const doc = await call("GET", base + "/admin-api/openapi.json");
  check("4. the OpenAPI document declares the three operations", function () {
    const ids = [];
    Object.keys((doc.json && doc.json.paths) || {}).forEach(function (p) {
      Object.keys(doc.json.paths[p]).forEach(function (method) {
        ids.push(String((doc.json.paths[p][method] || {}).operationId));
      });
    });
    ["setUserAttribute", "addUserAttributeValue",
     "removeUserAttributeValue"].forEach(function (id) {
      assert.ok(ids.indexOf(id) >= 0, id + " is not declared");
    });
  });

  assert.ok(checks >= 11, "only " + checks + " checks ran; a section has " +
            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_person_attributes")
  .description("#228: set, add to and remove from a person's attributes " +
    "through /admin-api, in a realm of its own.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
