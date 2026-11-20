// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_person_editor.js
//
// ---------------------------------------------------------------------------
// WHAT AN ADMINISTRATOR CHANGES ON A PERSON, OVER THE WIRE (D12, #444).
//
// In one throwaway realm it leaves behind, through `/admin-api` only:
//
//   A. THE ATTRIBUTE EDITOR (D12: carries over
//      tests/person_attribute_editor.js). `GET /admin-api/users?user=`'s
//      `attributeEditor` lists what may be edited and what is withheld with a
//      reason; `set-attribute`, `add-attribute` and `remove-attribute` do what
//      they say and move nothing else; every refusal is a 400 whose code is
//      read off `/admin-api/audit` (ADMIN-0518, LDAP-0102, 0103, 0105, 0106,
//      0107, 0108, 0109, 0211); the shaped values (a country upper-cased, a
//      date stored YYYYMMDD, a language range, an http(s) labeledURI, a DN, no
//      control character or over-long value).
//   B. THE FIELD GRID (D12: carries over tests/person_fields.js).
//      `GET /admin-api/users/new` publishes every editable attribute in one
//      group with an example; `update-fields` sets, clears, adds to and takes
//      from, changes nothing for the same values in another order, and
//      refuses ADMIN-0839 (saving nothing), 0838, 0834 and LDAP-0102; the
//      form's `field.<name>.<n>` boxes with `present`; a create taking the
//      grid's attributes and refusing a value the editor refuses
//      (LDAP-0106).
//   C. A PERSON'S KEY PAIRS, THE REFUSALS' CODES (D12: carries over the
//      residual of tests/person_credentials.js; the feature itself is
//      `sts_user_credentials.js`'s). An RFC 7522 key pair issued to a person
//      writes no RFC 7523 one; a SAML assertion signed with it about
//      somebody else is refused STS-OAUTH-0242; an upload carrying a private
//      key is STS-PKI-0141, a self-signed one STS-PKI-0147, one for nobody
//      STS-PKI-0109 and an application's leaf STS-PKI-0155.
//   D. WHO WROTE AN ADDRESS DECIDES WHETHER IT IS VERIFIED (D12: carries
//      over tests/mail_address_sources.js 1-3). A typed address on a create
//      and `set-mail` are verified (`stsMailVerified`), an invented one is
//      not; a SCIM create is; an LDAP modify bound as the person is not,
//      and one bound as an Admin Write holder is.
//
// NOT CARRIED, and why: person_fields.js E and F are the server-drawn page's
// markup, which the console no longer serves (`/admin/*` answers the static
// shell and the browser draws it); person_attribute_editor.js 5 is the
// in-process account observer, whose consequences (SSF, SCIM client) have
// jobs of their own; mail_address_sources.js 4 needs a federation partner
// and belongs with the federation family.
//
// ITS REALMS ARE REMOVED AT THE END ONLY WHEN ASKED
// (`STS_TEST_REMOVE_REALMS=1`, which a hand run against a long-lived probe
// sets so that its directory does not fill): tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, so by default they stay.
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const nodeCrypto = require("crypto");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const signer = require("./saml_xmldsig.js");

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
var log = bunyan.createLogger({ name: "sts_person_editor",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

// The debugger's own certificate encoder, for a certificate this realm
// never issued.
const REPO = process.env.MOCK_STS_DIR || path.join(__dirname, "..", "..");
const x509 = require(path.join(REPO, "common", "crypto_impl", "x509.js"));
const keys = require(path.join(REPO, "common", "crypto_impl",
                               "key_material.js"));

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("pedit-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
  .slice(0, 31);
const DOMAIN = REALM + ".example.net";
const realmBase = base + "/realm/" + REALM;
const api = realmBase + "/admin-api";
const TOKEN_ENDPOINT = realmBase + "/oauth2/token";
const USERS_DN = "ou=users," + DOMAIN.split(".").map(function (label) {
  return "dc=" + label;
}).join(",");
const LDAP_URL = "ldap://" + new URL(base).hostname + ":" +
                 (process.env.STS_LDAP_PORT || "389");
const SAML_GRANT = "urn:ietf:params:oauth:grant-type:saml2-bearer";

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

// The newest audit sequence number in this realm, so a refusal's row is the
// one recorded after it.
async function newestAt() {
  log.debug("Entering newestAt().");
  const r = await send(api + "/audit?per=1");
  log.debug("Leaving newestAt().");
  // BY TIME (#465): `seq` is unique across processes and rises within
  // each, but it is not one order across them, so a row a request worker
  // numbered from a lower block than the newest row here would be missed.
  // A reader resumes by `at`, as the audit API says.
  const newest = (r.body && r.body.events && r.body.events[0]) || {};
  return newest.at || 0;
}

// The codes recorded in this realm after `since` — never read off a
// response, which carries none.
async function codesSince(since, wanted) {
  log.debug("Entering codesSince().");
  let found = [];
  for (let i = 0; i < 20; i += 1) {
    const r = await send(api + "/audit?per=200");
    found = ((r.body && r.body.events) || []).filter(function (row) {
      return row.at > since && row.errorCode;
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

// POST an act that must be refused 400, and the code it records.
async function refused(url, payload, code, what) {
  log.debug("Entering refused().");
  const since = await newestAt();
  const r = await postJson(url, payload);
  const codes = await codesSince(since, code);
  check(what + " (400, " + code + " on the audit row)", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 400));
    assert.ok(r.body && r.body.ok === false, r.raw.slice(0, 400));
    assert.ok(codes.indexOf(code) >= 0, "recorded: " + codes.join(","));
    assert.ok(r.raw.indexOf(code) < 0, "the code was sent: " +
              r.raw.slice(0, 300));
  });
  log.debug("Leaving refused().");
  return r;
}

async function view(user) {
  log.debug("Entering view().");
  const r = await send(api + "/users?user=" + encodeURIComponent(user));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving view().");
  return r.body;
}

// A person's values of one attribute, as the editor publishes them.
async function valuesOf(user, attribute) {
  log.debug("Entering valuesOf().");
  const body = await view(user);
  const row = ((body.attributeEditor || {}).attributes || [])
    .filter(function (one) {
      return one.name.toLowerCase() === attribute.toLowerCase();
    })[0];
  log.debug("Leaving valuesOf().");
  return row ? row.values.map(String) : [];
}

// The entry's stored attributes, lower-cased names, as `ldap.entry` shows.
async function storedOf(user) {
  log.debug("Entering storedOf().");
  const attrs = (((await view(user)).ldap || {}).entry || {}).attributes ||
                {};
  const out = {};
  Object.keys(attrs).forEach(function (name) {
    out[name.toLowerCase()] = attrs[name];
  });
  log.debug("Leaving storedOf().");
  return out;
}

function person(username, extra) {
  log.debug("Entering person().");
  log.debug("Leaving person().");
  return Object.assign({ username: username, invent: false,
    credential: "none",
    attributes: { cn: username, sn: "Editor", givenName: "Person",
                  mail: username + "@" + DOMAIN } }, extra || {});
}

async function attributeEditor() {
  log.debug("Entering attributeEditor().");
  const ALICE = "pae-alice";
  const set = api + "/users/set-attribute";
  const add = api + "/users/add-attribute";
  const remove = api + "/users/remove-attribute";
  await ok(api + "/users/create", person(ALICE,
    { credential: "password", password: "Pae-Pass-" + STAMP + "-1!x" }),
    "created the person");

  log.info("=== A1. the list ===");
  const first = await view(ALICE);
  const editor = first.attributeEditor || {};
  const editable = (editor.attributes || []).filter(function (row) {
    return row.editable;
  }).map(function (row) {
    return row.name;
  });
  const withheld = editor.withheld || [];
  check("title, telephoneNumber, manager, schacDateOfBirth, c, " +
        "employeeStatus, cn, sn and displayName are editable", function () {
    ["title", "telephoneNumber", "manager", "schacDateOfBirth", "c",
     "employeeStatus", "cn", "sn", "displayName"].forEach(function (name) {
      assert.ok(editable.indexOf(name) >= 0, name + ": " + editable.join());
    });
  });
  check("userPassword, uid and mail are withheld, each with a reason, and " +
        "memberOf and stsTotpCredential are on neither list", function () {
    ["userPassword", "uid", "mail"].forEach(function (name) {
      const row = withheld.filter(function (one) {
        return one.name === name;
      })[0];
      assert.ok(row && String(row.why).length > 20 &&
                editable.indexOf(name) < 0, name + JSON.stringify(row));
    });
    ["memberOf", "stsTotpCredential"].forEach(function (name) {
      assert.ok(editable.indexOf(name) < 0 && !withheld.some(function (one) {
        return one.name === name;
      }), name);
    });
    assert.ok(new RegExp("^uid=" + ALICE + ",").test(editor.dn), editor.dn);
  });

  log.info("=== A2. set, add, remove, and nothing else moves ===");
  const before = await storedOf(ALICE);
  await ok(set, { user: ALICE, attribute: "title",
                  value: "Principal Engineer" }, "set the title");
  await ok(set, { user: ALICE, attribute: "title",
                  value: "Staff Engineer" }, "set the title again");
  const titles = await valuesOf(ALICE, "title");
  check("set-attribute replaces the value, and a second set replaces " +
        "rather than adds", function () {
    assert.deepStrictEqual(titles, ["Staff Engineer"]);
  });
  await ok(add, { user: ALICE, attribute: "telephoneNumber",
                  value: "+1 555 0100" }, "added a number");
  const second = await ok(add, { user: ALICE, attribute: "telephonenumber",
                                 value: "+1 555 0101" },
                          "added a second number by a lower-case name");
  const phones = await valuesOf(ALICE, "telephoneNumber");
  check("add-attribute appends, and the name is matched in any case",
        function () {
    assert.strictEqual(second.attribute, "telephoneNumber");
    assert.deepStrictEqual(phones.slice().sort(),
                           ["+1 555 0100", "+1 555 0101"]);
  });
  await ok(remove, { user: ALICE, attribute: "telephoneNumber",
                     value: "+1 555 0100" }, "removed one number");
  const kept = await valuesOf(ALICE, "telephoneNumber");
  check("remove-attribute takes off the one value", function () {
    assert.deepStrictEqual(kept, ["+1 555 0101"]);
  });
  await ok(set, { user: ALICE, attribute: "title", value: "" },
           "set the title empty");
  const after = await storedOf(ALICE);
  check("an empty set removes the attribute, and the entryUUID, the " +
        "password and every other attribute are exactly as they were",
        function () {
    assert.ok(!after.title, JSON.stringify(after.title));
    assert.ok(before.entryuuid && before.userpassword,
              Object.keys(before).join());
    Object.keys(before).forEach(function (name) {
      if (["title", "telephonenumber", "modifytimestamp"]
            .indexOf(name) >= 0) {
        return;
      }
      assert.deepStrictEqual(after[name], before[name], name);
    });
  });

  log.info("=== A3. every refusal, coded ===");
  await refused(set, { user: "", attribute: "title", value: "x" },
                "STS-ADMIN-0518", "no person named");
  await refused(set, { user: "pae-nobody", attribute: "title", value: "x" },
                "STS-LDAP-0102", "nobody there");
  for (const name of ["userPassword", "mail", "uid", "memberOf",
                      "stsTotpCredential"]) {
    await refused(set, { user: ALICE, attribute: name, value: "x" },
                  "STS-LDAP-0103", name + " is not edited here");
  }
  await refused(add, { user: ALICE, attribute: "displayName", value: "Al" },
                "STS-LDAP-0105", "an add to a single-valued attribute");
  await refused(add, { user: ALICE, attribute: "telephoneNumber",
                       value: "" },
                "STS-LDAP-0106", "an add of nothing");
  await refused(add, { user: ALICE, attribute: "telephoneNumber",
                       value: "+1 555 0101" },
                "STS-LDAP-0107", "a duplicate add");
  await refused(remove, { user: ALICE, attribute: "telephoneNumber",
                          value: "+1 555 9999" },
                "STS-LDAP-0108", "removing a value not held");
  await refused(set, { user: ALICE, attribute: "cn", value: "" },
                "STS-LDAP-0109", "emptying cn");
  await refused(remove, { user: ALICE, attribute: "sn", value: "Editor" },
                "STS-LDAP-0109", "removing the last sn");

  log.info("=== A4. the shaped values ===");
  const shaped = [
    ["c", "Sweden", false], ["c", "XX", false], ["c", "se", "SE"],
    ["schacCountryOfCitizenship", "dk", "DK"],
    ["schacDateOfBirth", "1990-02-30", false],
    ["schacDateOfBirth", "1990-02-28", "19900228"],
    ["schacDateOfBirth", "19900301", "19900301"],
    ["preferredLanguage", "en_GB!", false],
    ["preferredLanguage", "da, en-gb;q=0.8", "da, en-gb;q=0.8"],
    ["labeledURI", "javascript:alert(1)", false],
    ["labeledURI", "ftp://example.org/", false],
    ["labeledURI", "https://example.org/ Home page",
     "https://example.org/ Home page"],
    ["manager", "Bob in accounts", false],
    ["manager", "uid=bob,ou=users,dc=example,dc=com",
     "uid=bob,ou=users,dc=example,dc=com"],
    ["description", "two\nlines", false],
    // Over the wire the API's own request schema bounds the value first
    // (STS-API-0009), before the editor's 1024 would.
    ["description", "x".repeat(1025), false, "STS-API-0009"],
    ["description", "x".repeat(1024), "x".repeat(1024)]
  ];
  for (const row of shaped) {
    const label = row[0] + " \"" + JSON.stringify(row[1]).slice(1, 25) +
                  "\"";
    if (row[2] === false) {
      await refused(set, { user: ALICE, attribute: row[0], value: row[1] },
                    row[3] || "STS-LDAP-0106", label + " is refused");
    } else {
      await ok(set, { user: ALICE, attribute: row[0], value: row[1] },
               "set " + label);
      const held = await valuesOf(ALICE, row[0]);
      check(label + " is stored as \"" + String(row[2]).slice(0, 24) + "\"",
            function () {
        assert.deepStrictEqual(held, [row[2]]);
      });
    }
  }
  const coded = await refused(set, { user: ALICE, attribute: "description",
    value: "kept for the operator (STS-LDAP-0001)." }, "STS-LDAP-0211",
    "a description carrying an operator's code");
  const description = await valuesOf(ALICE, "description");
  check("the code is not stored and the refusal does not repeat it",
        function () {
    assert.ok(description.join(" ").indexOf("STS-LDAP-0001") < 0);
    assert.ok(coded.raw.indexOf("STS-") < 0, coded.raw.slice(0, 300));
  });
  log.debug("Leaving attributeEditor().");
}

async function fieldGrid() {
  log.debug("Entering fieldGrid().");
  const update = api + "/users/update-fields";
  log.info("=== B-A. the catalogue ===");
  const fresh = await send(api + "/users/new");
  check("GET /admin-api/users/new publishes every editable attribute in " +
        "exactly one known group, each with an example", function () {
    assert.strictEqual(fresh.status, 200, fresh.raw.slice(0, 300));
    const groups = (fresh.body.fieldGroups || []).map(function (g) {
      return g.id;
    });
    const rows = fresh.body.gridFields || [];
    assert.ok(rows.length > 30, String(rows.length));
    const seen = {};
    rows.forEach(function (row) {
      assert.ok(groups.indexOf(row.group) >= 0, JSON.stringify(row));
      assert.ok(String(row.example || "").length > 0, JSON.stringify(row));
      assert.ok(!seen[row.attribute], "twice: " + row.attribute);
      seen[row.attribute] = true;
    });
    assert.ok(rows.filter(function (row) {
      return row.simple;
    }).length >= 8);
  });

  log.info("=== B-B. update-fields ===");
  await ok(api + "/users/create", person("pf-alice"), "created the person");
  const first = await ok(update, { user: "pf-alice", fields: {
    title: "Engineer", mobile: ["+1 555 0101", "+1 555 0102"], c: "se" } },
    "updated three fields");
  const b1 = { title: await valuesOf("pf-alice", "title"),
               mobile: await valuesOf("pf-alice", "mobile"),
               c: await valuesOf("pf-alice", "c") };
  check("a single value is set, a list written, a country upper-cased",
        function () {
    assert.strictEqual(first.changed.length, 3, JSON.stringify(first));
    assert.deepStrictEqual(b1, { title: ["Engineer"],
      mobile: ["+1 555 0101", "+1 555 0102"], c: ["SE"] });
  });
  await ok(update, { user: "pf-alice", fields: { title: "",
    mobile: ["+1 555 0102", "+1 555 0103"] } }, "cleared and moved");
  const b2 = { title: await valuesOf("pf-alice", "title"),
               mobile: await valuesOf("pf-alice", "mobile") };
  check("an empty single value clears it, a list is added to and taken " +
        "from", function () {
    assert.deepStrictEqual(b2, { title: [],
                                 mobile: ["+1 555 0102", "+1 555 0103"] });
  });
  const same = await ok(update, { user: "pf-alice", fields: {
    mobile: ["+1 555 0103", "+1 555 0102"] } }, "wrote the same values");
  check("the same values in another order change nothing", function () {
    assert.strictEqual(same.changed.length, 0, JSON.stringify(same));
  });
  await ok(update, { user: "pf-alice", fields: { cn: ["Alice Renamed"] } },
           "renamed cn");
  const cn = await valuesOf("pf-alice", "cn");
  check("a required list (cn) moves from one value to another", function () {
    assert.deepStrictEqual(cn, ["Alice Renamed"]);
  });
  const partial = await refused(update, { user: "pf-alice",
    fields: { c: "zz", title: "Lead" } }, "STS-ADMIN-0839",
    "a refused value in a save");
  const b3 = { title: await valuesOf("pf-alice", "title"),
               c: await valuesOf("pf-alice", "c") };
  check("and nothing of that save is written", function () {
    assert.strictEqual((partial.body.changed || []).length, 0);
    assert.deepStrictEqual(b3, { title: [], c: ["SE"] });
  });
  const withheld = await refused(update, { user: "pf-alice",
    fields: { memberOf: "cn=x" } }, "STS-ADMIN-0839",
    "an attribute the editor does not change");
  check("that refusal names the attribute", function () {
    assert.ok(/memberOf/.test((withheld.body.errors || []).join(" ")));
  });
  const single = await postJson(update, { user: "pf-alice",
    fields: { displayName: ["One", "Two"] } });
  check("two values for a single-valued attribute are refused", function () {
    assert.strictEqual(single.status, 400, single.raw.slice(0, 300));
    assert.ok(/holds one value/.test((single.body.errors || []).join(" ")),
              single.raw.slice(0, 300));
  });
  await refused(update, { user: "pf-alice" }, "STS-ADMIN-0838",
                "nothing named");
  await refused(update, { user: "pf-alice", present: "mobile",
                          "field.mobile.0": "" }, "STS-ADMIN-0834",
                "an empty list box");
  await refused(update, { user: "pf-nobody", fields: { title: "x" } },
                "STS-LDAP-0102", "a person who is not there");

  log.info("=== B-C. the form's body ===");
  await ok(update, { user: "pf-alice", present: "mobile title pager",
                     "field.mobile.0": "+1 555 0200",
                     "field.pager": "+1 555 0300" }, "posted the form");
  const b4 = { mobile: await valuesOf("pf-alice", "mobile"),
               pager: await valuesOf("pf-alice", "pager"),
               title: await valuesOf("pf-alice", "title") };
  check("boxes and present: a list replaced, a field present and absent " +
        "cleared", function () {
    assert.deepStrictEqual(b4, { mobile: ["+1 555 0200"],
                                 pager: ["+1 555 0300"], title: [] });
  });

  log.info("=== B-D. a create takes the grid's attributes ===");
  await ok(api + "/users/create", { username: "pf-bob", credential: "none",
    invent: false, attributes: { cn: "Bob", sn: "Grid", givenName: "Bob",
      mail: "pf-bob@" + DOMAIN, title: "Analyst",
      mobile: ["+1 555 0400", "+1 555 0401"], c: "de" } },
    "created a person with grid attributes");
  const b5 = { title: await valuesOf("pf-bob", "title"),
               mobile: (await valuesOf("pf-bob", "mobile")).length,
               c: await valuesOf("pf-bob", "c") };
  check("a create writes an editor attribute, a list and a shaped value",
        function () {
    assert.deepStrictEqual(b5, { title: ["Analyst"], mobile: 2, c: ["DE"] });
  });
  await refused(api + "/users/create", { username: "pf-carol",
    credential: "none", invent: false, attributes: { cn: "Carol",
      sn: "Grid", givenName: "Carol", mail: "pf-carol@" + DOMAIN,
      c: "zz" } }, "STS-LDAP-0106", "a create with a value the editor " +
    "refuses");
  const carol = await send(api + "/users?user=pf-carol");
  check("and nobody was created", function () {
    assert.ok(carol.status === 404 || (carol.body && carol.body.known ===
              false), carol.status + " " + carol.raw.slice(0, 200));
  });
  log.debug("Leaving fieldGrid().");
}

// A self-signed leaf this realm never issued.
async function selfSigned(cn) {
  log.debug("Entering selfSigned().");
  const pair = await keys.generateKeyPair("rsa-2048");
  const cert = await x509.issueCertificate({
    subject: [{ name: "CN", value: cn }],
    subjectPublicKey: pair.publicPem, signatureAlg: "sha256-rsa",
    profile: "digital-signature",
    issuer: { privateKeyPem: pair.privatePem, keyAlg: "rsa-2048" },
    extensions: {
      basicConstraints: { present: true, critical: true, ca: false },
      keyUsage: { present: true, critical: true,
                  usages: ["digitalSignature"] } } });
  log.debug("Leaving selfSigned().");
  return { pem: cert.pem, privatePem: pair.privatePem };
}

async function samlGrant(iss, sub, privateKeyPem, certificatePem) {
  log.debug("Entering samlGrant().");
  const built = signer.buildAssertion({ issuer: iss, subject: sub,
                                        audience: TOKEN_ENDPOINT,
                                        recipient: TOKEN_ENDPOINT });
  const r = await send(TOKEN_ENDPOINT, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: SAML_GRANT,
      assertion: signer.b64u(signer.sign(built, privateKeyPem,
                                         certificatePem || "", {})) })
      .toString() });
  log.debug("Leaving samlGrant().");
  return r;
}

async function keyPairs() {
  log.debug("Entering keyPairs().");
  const ALICE = "pc-alice";
  const BOB = "pc-bob";
  const APP = "pc-app";
  log.info("=== C. a person's key pairs ===");
  await ok(api + "/pki/build", { organisation: "Person editor",
                                 country: "US" },
           "built a certificate authority");
  await ok(api + "/users/create", person(ALICE), "created Alice");
  await ok(api + "/users/create", person(BOB), "created Bob");
  await ok(api + "/applications/create", { identifier: APP,
    protocols: ["oauth2"], fields: { oauthClientId: APP } },
    "created an application");
  const issued = await ok(api + "/pki/issue", { identifier: ALICE,
    target: "person", purpose: "saml", keyAlg: "rsa-2048" },
    "issued Alice an RFC 7522 key pair");
  const creds = ((await view(ALICE)).credentials || {}).keyPairs || [];
  const byPurpose = {};
  creds.forEach(function (one) {
    byPurpose[one.purpose] = one;
  });
  check("issuing the SAML profile writes no RFC 7523 key pair, and the " +
        "view carries no private key", function () {
    assert.strictEqual((byPurpose.saml || {}).held, true,
                       JSON.stringify(creds).slice(0, 300));
    assert.ok(!(byPurpose.jwt || {}).held, JSON.stringify(byPurpose.jwt));
    assert.ok(JSON.stringify(creds).indexOf("PRIVATE KEY") < 0);
  });
  const self = await samlGrant(ALICE, ALICE, issued.privateKeyPem,
                               issued.certificatePem);
  check("an assertion Alice signed about herself is accepted", function () {
    assert.strictEqual(self.status, 200, self.raw.slice(0, 300));
  });
  const since = await newestAt();
  const other = await samlGrant(ALICE, BOB, issued.privateKeyPem,
                                issued.certificatePem);
  const otherCodes = await codesSince(since, "STS-OAUTH-0242");
  check("the same key naming Bob is refused, STS-OAUTH-0242 on the audit " +
        "row", function () {
    assert.strictEqual(other.status, 400, other.raw.slice(0, 300));
    assert.strictEqual((other.body || {}).error, "invalid_grant");
    assert.ok(otherCodes.indexOf("STS-OAUTH-0242") >= 0,
              otherCodes.join(","));
  });
  const own = await selfSigned(ALICE);
  const upload = api + "/pki/upload-certificate";
  await refused(upload, { identifier: ALICE, target: "person",
    purpose: "saml", certificate: own.pem, chain: own.privatePem },
    "STS-PKI-0141", "an upload carrying a private key");
  await refused(upload, { identifier: ALICE, target: "person",
    purpose: "saml", certificate: own.pem }, "STS-PKI-0147",
    "a self-signed certificate with no chain to an authority");
  await refused(upload, { identifier: "pc-nobody", target: "person",
    purpose: "saml", certificate: own.pem }, "STS-PKI-0109",
    "an upload for a person nobody in this realm is");
  await ok(api + "/pki/issue", { identifier: APP, purpose: "jwt" },
           "issued the application a key pair");
  const appView = await send(api + "/applications?application=" + APP);
  const appCert = ((appView.body.application || appView.body).fields || {})
    .oauthAssertionCertificate;
  await refused(upload, { identifier: ALICE, target: "person",
    purpose: "jwt", certificate: appCert }, "STS-PKI-0155",
    "this realm's certificate for an application, uploaded for a person");
  log.debug("Leaving keyPairs().");
}

function ldapModify(bindDn, dn, value) {
  log.debug("Entering ldapModify().");
  log.debug("Leaving ldapModify().");
  return new Promise(function (resolve, reject) {
    const client = ldapjs.createClient({ url: LDAP_URL });
    client.on("error", function (e) {
      log.debug("Caught in ldapModify(): " + ((e && e.message) || e));
      reject(e);
    });
    client.bind(bindDn, "any-password-" + STAMP, function (bindError) {
      if (bindError) {
        client.destroy();
        reject(bindError);
        return;
      }
      client.modify(dn, new ldapjs.Change({ operation: "replace",
        modification: new ldapjs.Attribute({ type: "mail",
                                             values: [value] }) }),
      function (modifyError) {
        client.unbind();
        if (modifyError) {
          reject(modifyError);
        } else {
          resolve();
        }
      });
    });
  });
}

async function verifiedOf(user) {
  log.debug("Entering verifiedOf().");
  const stored = await storedOf(user);
  log.debug("Leaving verifiedOf().");
  return { mail: stored.mail || [], verified: stored.stsmailverified || [] };
}

async function addressSources() {
  log.debug("Entering addressSources().");
  log.info("=== D1. the console and /admin-api ===");
  await ok(api + "/users/create", person("mas-typed"), "a typed address");
  await ok(api + "/users/create", { username: "mas-invented", invent: true,
                                    credential: "none" },
           "an invented person");
  const typed = await verifiedOf("mas-typed");
  const invented = await verifiedOf("mas-invented");
  check("a typed address on a create is verified, an invented one is not",
        function () {
    assert.deepStrictEqual(typed.verified, typed.mail);
    assert.ok(invented.mail.length === 1 && invented.verified.length === 0,
              JSON.stringify(invented));
  });
  await ok(api + "/users/set-mail", { user: "mas-invented",
                                      mail: "set@example.com" },
           "set the address");
  const set = await verifiedOf("mas-invented");
  check("set-mail writes the address, verified", function () {
    assert.deepStrictEqual(set, { mail: ["set@example.com"],
                                  verified: ["set@example.com"] });
  });
  const bad = await postJson(api + "/users/set-mail",
                             { user: "mas-invented", mail: "not an address" });
  const unchanged = await verifiedOf("mas-invented");
  check("set-mail refuses a non-address and keeps the one held",
        function () {
    assert.strictEqual(bad.status, 400, bad.raw.slice(0, 200));
    assert.deepStrictEqual(unchanged.mail, ["set@example.com"]);
  });

  log.info("=== D2. SCIM ===");
  const CLIENT = "mas-scim-client";
  const SECRET = "mas-scim-" + STAMP + "-secret-value";
  await ok(api + "/applications/create", { identifier: CLIENT,
    protocols: ["oauth2"], fields: { oauthClientId: [CLIENT],
      oauthClientSecret: SECRET,
      oauthTokenEndpointAuthMethod: "client_secret_post",
      oauthGrantType: ["client_credentials"],
      oauthAllowedScope: ["scim:read", "scim:write"] } },
    "registered a provisioning client");
  const token = await send(TOKEN_ENDPOINT, { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
      client_id: CLIENT, client_secret: SECRET,
      scope: "scim:read scim:write",
      resource: realmBase + "/resource" }).toString() });
  assert.strictEqual(token.status, 200, token.raw.slice(0, 300));
  const scim = await send(realmBase + "/scim/v2/Users", { method: "POST",
    headers: { "Content-Type": "application/scim+json",
               Authorization: "Bearer " + token.body.access_token },
    body: JSON.stringify({
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      userName: "mas-scim", name: { givenName: "S", familyName: "Cim" },
      emails: [{ value: "scim@example.com", primary: true }] }) });
  assert.strictEqual(scim.status, 201, scim.raw.slice(0, 300));
  const scimHeld = await verifiedOf("mas-scim");
  check("an address a SCIM client provisions is verified", function () {
    assert.deepStrictEqual(scimHeld, { mail: ["scim@example.com"],
                                       verified: ["scim@example.com"] });
  });

  log.info("=== D3. LDAP ===");
  await ok(api + "/users/create", person("mas-ldap"), "an LDAP person");
  await ok(api + "/users/create", person("mas-ldapadm"), "an LDAP admin");
  await ok(api + "/rbac/grant", { username: "mas-ldapadm", role: "write" },
           "granted Admin Write");
  const selfDn = "uid=mas-ldap," + USERS_DN;
  const adminDn = "uid=mas-ldapadm," + USERS_DN;
  await ldapModify(selfDn, selfDn, "self@example.com");
  await ldapModify(adminDn, selfDn, "byadmin@example.com");
  await ldapModify(selfDn, selfDn, "self-again@example.com");
  const ldapSelf = await verifiedOf("mas-ldap");
  check("a modify bound as the PERSON writes the address unverified",
        function () {
    assert.deepStrictEqual(ldapSelf.mail, ["self-again@example.com"]);
    assert.ok(ldapSelf.verified.indexOf("self-again@example.com") < 0,
              JSON.stringify(ldapSelf));
  });
  await ldapModify(adminDn, selfDn, "byadmin2@example.com");
  const ldapAdmin = await verifiedOf("mas-ldap");
  check("a modify bound as an Admin Write holder verifies it", function () {
    assert.deepStrictEqual(ldapAdmin, { mail: ["byadmin2@example.com"],
      verified: ["byadmin2@example.com"] });
  });
  log.debug("Leaving addressSources().");
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. the throwaway realm " + REALM + " ===");
  await ok(base + "/admin-api/realms/create", { id: REALM, domain: DOMAIN,
    name: "Person editor " + STAMP }, "created the realm");
  await attributeEditor();
  await fieldGrid();
  await keyPairs();
  await addressSources();
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
  for (const id of [REALM]) {
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
  log.error("sts_person_editor FAILED: " + ((e && e.stack) || e));
  return false;
}).then(async function (passed) {
  await removeRealms();
  if (!passed) {
    process.exit(1);
  }
});
