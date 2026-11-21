// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_application_ldif.js
//
// ---------------------------------------------------------------------------
// AN APPLICATION EXPORTED TO LDIF AND IMPORTED INTO ANOTHER REALM, OVER THE
// WIRE (#546).
//
// In two throwaway realms it leaves behind:
//
//   a. an application made in the first, with a client secret, exported
//      through `POST /admin-api/applications/export-ldif`: one LDIF record,
//      the file to save beside it, and NO credential unless asked;
//   b. exported again with `credentials: true`, the secret in the clear;
//   c. that file imported into the second realm through
//      `POST /admin-api/applications/import-ldif`, where the application's
//      client secret gets a token at that realm's `/oauth2/token`;
//   d. the same file again refused (400) — an import never overwrites —
//      and so is a file carrying an attribute this registry derives;
//   e. a PERSON, the same pattern on Directory → Users (2026-11-14): made in
//      the first realm with a password, exported through
//      `POST /admin-api/users/export-ldif` with no credential unless asked,
//      imported into the second through `/users/import-ldif` with their
//      password's hash, and the same file again refused.
//   f. D12 (#444), tests/application_ldif.js's codes: an application nobody
//      recorded is STS-REG-0345, the same identifier again STS-REG-0349, a
//      derived attribute STS-REG-0350, an attribute the registry has no row
//      for STS-REG-0351, two records STS-REG-0347, a person's entry at the
//      application door STS-REG-0348 — each 400 with nothing made — and each
//      export and import audited without a value;
//   g. D12 (#444), tests/user_ldif.js: the person's file with an app password
//      and a stored certificate in it comes back with both, and the same
//      password BINDS over LDAPS in the realm it was imported into (a product
//      realm, so it is verified); a person nobody holds is STS-LDAP-0214, an
//      existing username STS-LDAP-0218 (unchanged), a recorded attribute and
//      an entryUUID STS-LDAP-0219, a clear password STS-LDAP-0220, two
//      records STS-LDAP-0216, an application's file at the person door
//      STS-LDAP-0217; each export and import audited without a value; and a
//      token holding only admin:read is refused at both doors.
//
// Left in process (class d): the secret sealed again at rest after an import
// (application_ldif.js D needs a persisting key-encryption key), the
// authenticator app, the passkey and its user handle, and the recovery codes
// carried in a person's file (there is no management-API door that enrols
// them), the closed response models (user_ldif.js E, which
// tests/openapi_response_models.js holds for every answer), and the console
// tab's markup (user_ldif.js F1-F2).
//
// OWNED HERE (local: true): this repository's own console operations and
// management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");
const tokens = require("../tools/admin-api-token.js");
const serviceTrust = require("../tools/service_trust.js");

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
var log = bunyan.createLogger({ name: "sts_application_ldif",
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
const FROM = realmId("ldifa-");
const TO = realmId("ldifb-");
const APP = "ldif-app-" + STAMP.toLowerCase();
const SECRET = "ldif-546-" + String(Date.now()).slice(-8) + "-secret-value";
const PERSON = ("ldifperson" + STAMP).toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 40);
const PASSWORD = "Ldif-Person-" + String(Date.now()).slice(-8) + "-Pw!x";

// REMOVAL IS OPT-IN (STS_TEST_REMOVE_REALMS=1). tests/CLAUDE.md's *No job
// removes a realm* is the rule for a shared run, where what a job leaves is
// there to be read afterwards; a hand run against a private service sets the
// variable, and the realms this job made are removed at its end, pass or
// fail, so a long series of runs does not fill the directory's ceiling.
const MADE_REALMS = [];

async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  for (const id of MADE_REALMS) {
    try {
      const r = await fetch(base + "/admin-api/realms/remove", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: id }) });
      log.info("  (removed the realm " + id + ": " + r.status + ")");
    } catch (e) {
      log.debug("Caught in removeRealms(): " + ((e && e.message) || e));
      // A realm that cannot be removed is left, as a shared run leaves it.
    }
  }
  log.debug("Leaving removeRealms().");
}

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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

// RFC 2849 folds a line at 76 columns, so a value is searched for in the
// unfolded text.
function unfold(ldif) {
  log.debug("Entering unfold().");
  log.debug("Leaving unfold().");
  return String(ldif || "").replace(/\r?\n /g, "");
}

// A code is never sent; the realm's audit log is where it is read back.
async function codeCount(api, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(api + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  assert.strictEqual(r.status, 200, "GET audit answered " + r.status);
  log.debug("Leaving codeCount().");
  return ((r.body && r.body.events) || []).length;
}

async function rowsOf(api, action) {
  log.debug("Entering rowsOf(). " + action);
  const r = await send(api + "/audit?per=500&action=" +
                       encodeURIComponent(action));
  assert.strictEqual(r.status, 200, "GET audit answered " + r.status);
  log.debug("Leaving rowsOf().");
  return (r.body && r.body.events) || [];
}

// POST `payload` to `url` and assert a 400 whose code `code` was recorded in
// the realm whose management API is `api`.
async function refusedCoded(api, url, payload, code, what) {
  log.debug("Entering refusedCoded(). " + code);
  const before = await codeCount(api, code);
  const r = await postJson(url, payload);
  let after = before;
  for (let i = 0; i < 25 && after <= before; i += 1) {
    after = await codeCount(api, code);
    if (after <= before) {
      await new Promise(function (resolve) {
        setTimeout(resolve, 150);
      });
    }
  }
  check(what + " — 400, recorded " + code, function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 400));
    assert.ok(r.body && r.body.ok === false, r.raw.slice(0, 400));
    assert.ok(after > before, "no new " + code + " row");
  });
  log.debug("Leaving refusedCoded().");
  return r;
}

// A simple bind over LDAPS: 0 when it binds.
function ldapsBind(dn, password) {
  log.debug("Entering ldapsBind(). " + dn);
  const host = new URL(base).hostname;
  const url = process.env.STS_LDAPS_URL ||
    ("ldaps://" + host + ":" + (process.env.STS_LDAPS_PORT || 636));
  const client = ldapjs.createClient({ url: url, reconnect: false,
    timeout: 20000, connectTimeout: 15000,
    tlsOptions: { rejectUnauthorized: true, servername: host } });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back; the bind reports.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving ldapsBind().");
  return new Promise(function (resolve) {
    client.bind(dn, password, function (e) {
      const code = e ? e.code : 0;
      try {
        client.unbind(function () {
          resolve(code);
        });
      } catch (err) {
        log.debug("Caught in ldapsBind(): " + ((err && err.message) || err));
        // A connection already closed cannot be unbound; the code stands.
        resolve(code);
      }
    });
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("=== 0. two throwaway realms " + FROM + " and " + TO + " ===");
  for (const id of [FROM, TO]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Application LDIF " + STAMP },
      "created the realm " + id);
    MADE_REALMS.push(id);
  }
  const fromApi = base + "/realm/" + FROM + "/admin-api";
  const toApi = base + "/realm/" + TO + "/admin-api";
  await ok(fromApi + "/applications/create", { identifier: APP,
    kind: "oauth2-client", name: APP, protocols: ["oauth2"],
    fields: { oauthClientId: [APP], oauthClientSecret: SECRET,
              oauthTokenEndpointAuthMethod: "client_secret_post",
              oauthGrantType: ["client_credentials"],
              oauthRedirectUri: ["https://ldif.example.net/cb"] } },
    "created the application");

  log.info("=== a. exported without credentials ===");
  const plain = await ok(fromApi + "/applications/export-ldif",
                         { application: APP }, "exported the application");
  check("one LDIF record naming the application, and the file to save",
        function () {
    assert.ok(/^dn: cn=/m.test(plain.ldif), plain.ldif.slice(0, 400));
    assert.strictEqual(plain.ldif.match(/^dn: /mg).length, 1);
    assert.ok(/^appIdentifier: /m.test(plain.ldif) &&
              unfold(plain.ldif).indexOf(APP) >= 0, plain.ldif.slice(0, 400));
    assert.ok(/^oauthRedirectUri: https:\/\/ldif\.example\.net\/cb$/m
      .test(plain.ldif), plain.ldif);
    const file = (plain.files || [])[0];
    assert.ok(file && /\.ldif$/.test(file.name), JSON.stringify(plain.files));
    assert.strictEqual(Buffer.from(file.base64, "base64").toString("utf8"),
                       plain.ldif);
  });
  check("by default no credential is in it, and none of what the " +
        "registry derived", function () {
    assert.strictEqual(plain.credentials, false);
    assert.ok(unfold(plain.ldif).indexOf(SECRET) < 0, "the secret leaked");
    assert.ok(!/^oauthClientSecret:/mi.test(plain.ldif), plain.ldif);
    assert.ok((plain.leftOut || []).indexOf("oauthClientSecret") >= 0,
              JSON.stringify(plain.leftOut));
    assert.ok(!/^appFirstSeen:/mi.test(plain.ldif), plain.ldif);
  });

  log.info("=== b. exported with credentials ===");
  const full = await ok(fromApi + "/applications/export-ldif",
                        { application: APP, credentials: true },
                        "exported the application with its credentials");
  check("the client secret is in it, in the clear", function () {
    assert.strictEqual(full.credentials, true);
    assert.ok(unfold(full.ldif).indexOf(SECRET) >= 0, full.ldif.slice(0, 600));
  });

  log.info("=== c. imported into the other realm ===");
  await ok(toApi + "/applications/import-ldif", { ldif: full.ldif },
           "imported the application");
  const token = await send(base + "/realm/" + TO + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials",
                                client_id: APP,
                                client_secret: SECRET }).toString() });
  check("its client secret gets a token in the realm it was imported into",
        function () {
    assert.strictEqual(token.status, 200, token.raw.slice(0, 400));
    assert.ok(token.body && token.body.access_token, token.raw.slice(0, 400));
  });

  log.info("=== d. the refusals ===");
  const again = await postJson(toApi + "/applications/import-ldif",
                               { ldif: full.ldif });
  check("the same identifier again is refused, never overwritten",
        function () {
    assert.strictEqual(again.status, 400, again.raw.slice(0, 400));
    assert.ok(again.body && again.body.ok === false, again.raw.slice(0, 400));
  });
  const other = full.ldif.split(APP).join(APP + "-b")
    .replace(/\n*$/, "\nappFirstSeen: 20260101000000Z\n");
  const derived = await postJson(toApi + "/applications/import-ldif",
                                 { ldif: other });
  check("a file carrying a derived attribute is refused", function () {
    assert.strictEqual(derived.status, 400, derived.raw.slice(0, 400));
  });

  log.info("=== e. a person, out and back in ===");
  await ok(fromApi + "/users/create", { username: PERSON, invent: false,
    attributes: { cn: "LDIF Person", sn: "Person", givenName: "LDIF",
                  mail: PERSON + "@example.net", title: "Engineer" },
    credential: "password", password: PASSWORD },
    "created the person");
  const person = await ok(fromApi + "/users/export-ldif", { user: PERSON },
                          "exported the person");
  check("one record naming the person, with no credential by default",
        function () {
    assert.ok(/^dn: uid=/m.test(person.ldif), person.ldif.slice(0, 400));
    assert.strictEqual(person.ldif.match(/^dn: /mg).length, 1);
    assert.ok(/^title: Engineer$/m.test(person.ldif), person.ldif);
    assert.ok(!/^userPassword:/mi.test(person.ldif), person.ldif);
    assert.ok(!/^entryUUID:/mi.test(person.ldif), person.ldif);
    assert.ok((person.leftOut || []).indexOf("userPassword") >= 0,
              JSON.stringify(person.leftOut));
    assert.ok(/\.ldif$/.test(((person.files || [])[0] || {}).name || ""),
              JSON.stringify(person.files));
  });
  const personFull = await ok(fromApi + "/users/export-ldif",
                              { user: PERSON, credentials: true },
                              "exported the person with credentials");
  check("with the box, the password's stored hash is in it", function () {
    assert.ok(/^userPassword:/mi.test(personFull.ldif) &&
              unfold(personFull.ldif).indexOf(PASSWORD) < 0,
              personFull.ldif.slice(0, 600));
  });
  const imported = await ok(toApi + "/users/import-ldif",
                            { ldif: personFull.ldif },
                            "imported the person");
  check("the person is made in the other realm with their password",
        function () {
    assert.strictEqual(imported.username, PERSON);
    assert.ok((imported.credentials || []).indexOf("userPassword") >= 0,
              JSON.stringify(imported));
    assert.strictEqual(imported.kerberosKeys, false);
  });
  const personAgain = await postJson(toApi + "/users/import-ldif",
                                     { ldif: personFull.ldif });
  check("the same person again is refused, never overwritten", function () {
    assert.strictEqual(personAgain.status, 400, personAgain.raw.slice(0, 400));
  });

  log.info("=== f. the application door's refusals, by code (D12) ===");
  await refusedCoded(fromApi, fromApi + "/applications/export-ldif",
    { application: APP + "-nobody" }, "STS-REG-0345",
    "an application nobody recorded");
  await refusedCoded(toApi, toApi + "/applications/import-ldif",
    { ldif: full.ldif }, "STS-REG-0349",
    "the same identifier again, never overwritten");
  const renamed = full.ldif.split(APP).join(APP + "-f");
  await refusedCoded(toApi, toApi + "/applications/import-ldif",
    { ldif: renamed.replace(/\n*$/, "\nappFirstSeen: 20260101000000Z\n") },
    "STS-REG-0350", "a derived attribute");
  await refusedCoded(toApi, toApi + "/applications/import-ldif",
    { ldif: renamed.replace(/\n*$/, "\nnoSuchAttribute: x\n") },
    "STS-REG-0351", "an attribute this registry has no row for");
  await refusedCoded(toApi, toApi + "/applications/import-ldif",
    { ldif: renamed + "\n\n" + renamed.split(APP + "-f").join(APP + "-g") },
    "STS-REG-0347", "a file of two records");
  await refusedCoded(toApi, toApi + "/applications/import-ldif",
    { ldif: person.ldif }, "STS-REG-0348",
    "a person's file at the application door");
  const madeAfter = await send(toApi + "/applications?application=" +
                               encodeURIComponent(APP + "-f"));
  check("and none of those refusals made the application", function () {
    assert.ok(madeAfter.body && madeAfter.body.found === false,
              madeAfter.raw.slice(0, 300));
  });
  const exports = (await rowsOf(fromApi, "application.export")).filter(
    function (row) {
      return row.target === APP;
    });
  const imports = (await rowsOf(toApi, "application.import")).filter(
    function (row) {
      return row.target === APP;
    });
  check("each export is audited in its realm, the import in the realm it " +
        "made the application in, never with the secret", function () {
    assert.strictEqual(exports.length, 2, JSON.stringify(exports));
    assert.strictEqual(imports.length, 1, JSON.stringify(imports));
    assert.ok(JSON.stringify(exports.concat(imports)).indexOf(SECRET) < 0);
  });

  log.info("=== g. the person door (D12) ===");
  // A product realm to import into, so the password that comes with the
  // file is CHECKED by the bind below rather than accepted as development
  // accepts anything; and its second-factor rule relaxed, because a simple
  // bind cannot ask for a second factor.
  const PROD = realmId("ldifp-");
  await ok(base + "/admin-api/realms/create", { id: PROD,
    domain: PROD + ".example.net", name: "Person LDIF product " + STAMP,
    overrides: { "global.mode": "product",
                 "authn.allowOptionalSecondFactor": "true" } },
    "created the product realm " + PROD);
  MADE_REALMS.push(PROD);
  const prodApi = base + "/realm/" + PROD + "/admin-api";
  const WHO = (PERSON + "g").slice(0, 40);
  await ok(fromApi + "/users/create", { username: WHO, invent: false,
    attributes: { cn: "LDIF G", sn: "G", givenName: "LDIF",
                  mail: WHO + "@example.net", title: "Engineer" },
    credential: "password", password: PASSWORD }, "created " + WHO);
  await ok(fromApi + "/users/create-app-password",
    { user: WHO, name: "ldif mail " + STAMP, doors: ["ldap"] },
    "made an app password for " + WHO);
  const pem = await new Promise(function (resolve) {
    // A certificate for the entry: any X.509 certificate will do for a
    // stored one, and the service's own listener certificate is at hand.
    const tls = require("tls");
    const u = new URL(base);
    const socket = tls.connect({ host: u.hostname, port: Number(u.port || 443),
      servername: u.hostname, ca: serviceTrust.trustedCa() }, function () {
      const der = socket.getPeerCertificate().raw;
      socket.end();
      resolve("-----BEGIN CERTIFICATE-----\n" +
              der.toString("base64").replace(/(.{64})/g, "$1\n")
                .replace(/\n$/, "") + "\n-----END CERTIFICATE-----\n");
    });
    socket.on("error", function () {
      resolve("");
    });
  });
  const stored = await postJson(fromApi + "/users/add-certificate",
                                { user: WHO, certificate: pem });
  check("a certificate is stored on the entry", function () {
    assert.ok(stored.status === 200 && stored.body && stored.body.ok,
              stored.raw.slice(0, 400));
  });
  const whoFull = await ok(fromApi + "/users/export-ldif",
    { user: WHO, credentials: true }, "exported " + WHO + " whole");
  const whoNames = unfold(whoFull.ldif).split("\n").map(function (line) {
    return line.split(":")[0].toLowerCase();
  });
  check("WITH the box the app password and the certificate are in it, no " +
        "entryUUID, and the header says UNENCRYPTED", function () {
    assert.ok(whoNames.indexOf("stsapppassword") >= 0 ||
              whoNames.some(function (n) {
                return /apppassword/.test(n);
              }), whoNames.join(","));
    assert.ok(whoNames.some(function (n) {
      return /^usercertificate/.test(n);
    }), whoNames.join(","));
    assert.ok(whoNames.indexOf("entryuuid") < 0, whoNames.join(","));
    assert.ok(/UNENCRYPTED|unencrypted/.test(whoFull.ldif),
              whoFull.ldif.slice(0, 400));
  });
  const landed = await ok(prodApi + "/users/import-ldif",
                          { ldif: whoFull.ldif }, "imported " + WHO);
  check("imported into the product realm with no Kerberos key, its " +
        "credentials named", function () {
    assert.strictEqual(landed.kerberosKeys, false);
    assert.ok((landed.credentials || []).indexOf("userPassword") >= 0,
              JSON.stringify(landed));
  });
  const passwords = await send(prodApi + "/users/app-passwords?user=" +
                               encodeURIComponent(WHO));
  check("the app password came with them", function () {
    assert.strictEqual(passwords.status, 200, passwords.raw.slice(0, 300));
    assert.ok(passwords.raw.indexOf("ldif mail " + STAMP) >= 0,
              passwords.raw.slice(0, 400));
  });
  const bound = await ldapsBind(String(landed.dn ||
    ("uid=" + WHO + ",ou=users,dc=" + PROD + ",dc=example,dc=net")),
    PASSWORD);
  const wrong = await ldapsBind(String(landed.dn ||
    ("uid=" + WHO + ",ou=users,dc=" + PROD + ",dc=example,dc=net")),
    PASSWORD + "-not");
  check("the same password verifies against the stored hash there: it " +
        "binds over LDAPS, and a wrong one is 49", function () {
    assert.strictEqual(bound, 0);
    assert.strictEqual(wrong, 49);
  });
  await refusedCoded(fromApi, fromApi + "/users/export-ldif",
    { user: WHO + "nobody" }, "STS-LDAP-0214", "a person nobody holds");
  // The entry as a record, comments (which carry the export's time) left
  // out: what the refusal below must not have changed.
  const recordOf = async function () {
    log.debug("Entering recordOf().");
    const r = await ok(prodApi + "/users/export-ldif",
                       { user: WHO, credentials: true }, "exported " + WHO);
    log.debug("Leaving recordOf().");
    return unfold(r.ldif).split("\n").filter(function (line) {
      return line.charAt(0) !== "#";
    }).join("\n");
  };
  const beforeAgain = await recordOf();
  await refusedCoded(prodApi, prodApi + "/users/import-ldif",
    { ldif: whoFull.ldif }, "STS-LDAP-0218", "an existing username");
  const afterAgain = await recordOf();
  check("and the existing person is unchanged", function () {
    assert.strictEqual(afterAgain, beforeAgain);
  });
  const otherPerson = person.ldif.split(PERSON).join(PERSON + "c");
  await refusedCoded(toApi, toApi + "/users/import-ldif",
    { ldif: otherPerson.replace(/\n*$/, "\nauthnMethod: pwd\n") },
    "STS-LDAP-0219", "a recorded attribute");
  await refusedCoded(toApi, toApi + "/users/import-ldif",
    { ldif: otherPerson.replace(/\n*$/, "\nentryUUID: " +
                                crypto.randomUUID() + "\n") },
    "STS-LDAP-0219", "an entryUUID");
  await refusedCoded(toApi, toApi + "/users/import-ldif",
    { ldif: otherPerson.replace(/\n*$/, "\nuserPassword: clear-text\n") },
    "STS-LDAP-0220", "a clear password");
  await refusedCoded(toApi, toApi + "/users/import-ldif",
    { ldif: otherPerson + "\n\n" +
            otherPerson.split(PERSON + "c").join(PERSON + "d") },
    "STS-LDAP-0216", "a file of two records");
  await refusedCoded(toApi, toApi + "/users/import-ldif",
    { ldif: plain.ldif }, "STS-LDAP-0217",
    "an application's file at the person door");
  const nobodyMade = await send(toApi + "/users?user=" +
                                encodeURIComponent(PERSON + "c"));
  check("and none of those refusals created the person", function () {
    assert.ok(nobodyMade.status === 200 && nobodyMade.body &&
              nobodyMade.body.known === false,
              nobodyMade.status + " " + nobodyMade.raw.slice(0, 300));
  });
  const userExports = (await rowsOf(fromApi, "user.export")).filter(
    function (row) {
      return row.target === WHO;
    });
  const userImports = (await rowsOf(prodApi, "user.import")).filter(
    function (row) {
      return row.target === WHO;
    });
  check("each person export and the import are audited, never with the " +
        "password or its hash", function () {
    assert.strictEqual(userExports.length, 1, JSON.stringify(userExports));
    assert.strictEqual(userImports.length, 1, JSON.stringify(userImports));
    const hash = (unfold(whoFull.ldif).match(/^userPassword:: ?(.*)$/mi) ||
                  unfold(whoFull.ldif).match(/^userPassword: ?(.*)$/mi) ||
                  [])[1] || "no-hash-found";
    const rows = JSON.stringify(userExports.concat(userImports));
    assert.ok(rows.indexOf(PASSWORD) < 0 && rows.indexOf(hash) < 0, rows);
  });
  const readOnly = await tokens.tokenFor(base, { scope: "admin:read" });
  for (const door of ["/users/export-ldif", "/users/import-ldif"]) {
    const r = await send(fromApi + door, { method: "POST",
      headers: { "Content-Type": "application/json",
                 authorization: "Bearer " + readOnly },
      body: JSON.stringify(door === "/users/export-ldif" ? { user: WHO }
                                                         : { ldif: "x" }) });
    check("a token holding only admin:read is refused at " + door,
          function () {
      assert.strictEqual(r.status, 403, r.raw.slice(0, 300));
      assert.ok(/admin:write/.test(r.raw), r.raw.slice(0, 600));
    });
  }

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().then(function () {
  return removeRealms();
}).catch(async function (e) {
  log.error("sts_application_ldif FAILED: " + ((e && e.stack) || e));
  await removeRealms();
  process.exit(1);
});
