"use strict";
//
// File: sts_ldap_read_authorization.js
//
// ---------------------------------------------------------------------------
// WHO MAY READ WHAT OVER LDAPS, PER IDENTITY (#106, 2026-09-23).
//
// A product-mode directory decides what a BOUND identity may read
// (`ldap/directory_read_policy.ts`): a person reads their own entry, of other
// people only what `ldap.directoryReadableAttributes` names (nothing by
// default), a group only if they are in it, and no application at all; an
// administrator reads their scope; an entry they may not see answers
// noSuchObject (32) exactly as a missing one; a filter cannot see what they
// may not read; a compare of it is 50; and only a person binds. Development
// decides none of it. `tests/directory_read_authorization.js` holds every row
// in process; this asks the same questions of a RUNNING service over its own
// LDAPS listener, the way a directory client does.
//
// **TWO THROWAWAY REALMS, ONE IN EACH MODE**, so both modes are asserted
// whichever mode the stack runs in (`sts_mode_weak_settings.js`'s pattern): a
// realm's `global.mode` is its own, and an LDAP operation runs in the realm
// its DN names. Each gets two people, an administrator on the realm's own
// roster, a group the reader is in and one they are not, and an application.
// The realms are left behind, as every job's throwaway realm is.
//
// A LOCAL JOB (tests/vendored/MANIFEST.js): this repository's own directory
// and its own sockets. It needs LDAPS reachable — STS_LDAPS_URL where the
// launcher sets it, otherwise the service's host on 636.
// ---------------------------------------------------------------------------
const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const ldapjs = require("ldapjs");
const names = require("./random_username.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // No appconfig file: the log level falls back to info, and the reason is
  // reported once the logger exists.
  appconfigProblem = e.message;
  appconfig = {};
}
var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_ldap_read_authorization",
  level: appconfig.logLevel || appconfig.LOG_LEVEL ||
         process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("No appconfig file was read: " + appconfigProblem);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "");
const PROD = "ldrp" + STAMP;
const DEV = "ldrd" + STAMP;
const READER = "ldr-reader-" + STAMP;
const OTHER = "ldr-other-" + STAMP;
const ADMIN = "ldr-admin-" + STAMP;
const IN_GROUP = "ldr-in-" + STAMP;
const OUT_GROUP = "ldr-out-" + STAMP;
const APP = "urn:ldr:app:" + STAMP;
const PHONE = "+1 555 0142";
const WIDENED = "objectClass,cn,uid,mail";
const PASSWORD = "Ldr-" + crypto.randomBytes(9).toString("base64url") +
                 "-Aa1!";
const FLOOR = 22;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check(). " + what);
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

function realmBase(id) {
  log.debug("Entering realmBase().");
  log.debug("Leaving realmBase().");
  return base + "/realm/" + id;
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

// One client per identity: in LDAP the connection IS the session.
function connect() {
  log.debug("Entering connect().");
  const url = ldapsUrl();
  const client = ldapjs.createClient({
    url: url, reconnect: false, timeout: 20000, connectTimeout: 15000,
    // Verified, with the trust this runner has for the service (the
    // launcher's NODE_EXTRA_CA_CERTS), as sts_ldaps.js does.
    tlsOptions: { rejectUnauthorized: true, servername: hostOf(url) }
  });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back, and an unhandled
    // 'error' is a process-level throw. The operation in flight reports it.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving connect().");
  return client;
}

function bind(client, dn, password) {
  log.debug("Entering bind(). dn=" + dn);
  log.debug("Leaving bind().");
  return new Promise(function (resolve) {
    client.bind(dn, password, function (e) {
      resolve({ code: e ? e.code : 0, message: e ? e.message : "" });
    });
  });
}

// ldapjs's client turns compareTrue (6) and compareFalse (5) into a success
// whose second argument says which, so a match is code 0 and `matched`.
function compare(client, dn, attribute, value) {
  log.debug("Entering compare().");
  log.debug("Leaving compare().");
  return new Promise(function (resolve) {
    client.compare(dn, attribute, value, function (e, matched) {
      resolve({ code: e ? e.code : 0, matched: !!matched });
    });
  });
}

// A search that settles either way: ldapjs emits `error` and NEVER `end` for
// a refused search, and a deadline stops a silent server hanging the job.
function search(client, dn, options) {
  log.debug("Entering search(). dn=" + dn);
  log.debug("Leaving search().");
  return new Promise(function (resolve) {
    const entries = [];
    let settled = false;
    const done = function (outcome) {
      log.debug("Entering done().");
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        resolve(outcome);
      }
      log.debug("Leaving done().");
    };
    const deadline = setTimeout(function () {
      done({ code: -1, entries: [] });
    }, 20000);
    client.search(dn, Object.assign({ filter: "(objectClass=*)" }, options),
                  function (e, res) {
      if (e) {
        done({ code: e.code, entries: [] });
        return;
      }
      res.on("searchEntry", function (entry) {
        const pojo = entry.pojo || entry;
        entries.push({ dn: String(pojo.objectName).toLowerCase()
                             .replace(/,\s+/g, ","),
                       attributes: pojo.attributes || [] });
      });
      res.on("error", function (err) {
        done({ code: err.code, entries: entries });
      });
      res.on("end", function (result) {
        done({ code: result ? result.status : 0, entries: entries });
      });
    });
  });
}

function unbind(client) {
  log.debug("Entering unbind().");
  log.debug("Leaving unbind().");
  return new Promise(function (resolve) {
    try {
      client.unbind(function () {
        resolve(true);
      });
    } catch (e) {
      log.debug("Caught in unbind(): " + ((e && e.message) || e));
      // A connection the server already closed cannot be unbound, and that
      // is not what any check here is about.
      resolve(false);
    }
  });
}

function lower(dn) {
  log.debug("Entering lower().");
  log.debug("Leaving lower().");
  return String(dn).toLowerCase().replace(/,\s+/g, ",");
}

function entryFor(result, dn) {
  log.debug("Entering entryFor().");
  log.debug("Leaving entryFor().");
  return (result.entries || []).filter(function (entry) {
    return entry.dn === lower(dn);
  })[0] || null;
}

function namesOf(entry) {
  log.debug("Entering namesOf().");
  log.debug("Leaving namesOf().");
  return ((entry && entry.attributes) || []).map(function (a) {
    return String(a.type || "").toLowerCase();
  });
}

function dnsOf(result) {
  log.debug("Entering dnsOf().");
  log.debug("Leaving dnsOf().");
  return (result.entries || []).map(function (entry) {
    return entry.dn;
  });
}

// The realm, its people, its groups, its application and its administrator.
async function setUp(realm, mode) {
  log.debug("Entering setUp(). " + realm);
  await ok(base + "/admin-api/realms/create",
           { id: realm, domain: realm + ".example.net",
             name: "#106 " + mode, overrides: { "global.mode": mode } },
           "created the " + mode + " realm " + realm);
  const api = realmBase(realm) + "/admin-api";
  const dns = {};
  for (const who of [READER, OTHER, ADMIN]) {
    const made = await ok(api + "/users/create", {
      username: who, invent: false, credential: "password",
      password: PASSWORD,
      attributes: { cn: "LDR " + who, sn: who, mail: who + "@ldr.test",
                    telephoneNumber: PHONE } },
      "created " + who + " in " + realm);
    dns[who] = String(made.dn);
  }
  const where = await call("GET", api + "/groups");
  assert.ok(where.status === 200 && where.json && where.json.usersDn &&
            where.json.baseDn,
            "GET " + api + "/groups should name the containers: " +
            where.status + " " + where.text.slice(0, 300));
  dns.users = String(where.json.usersDn);
  dns.groups = String(where.json.groupsDn);
  dns.applications = "ou=applications," + where.json.baseDn;
  dns.missing = "uid=ldr-nobody-" + STAMP + "," + dns.users;
  await ok(api + "/groups/create", { group: IN_GROUP }, "created " + IN_GROUP);
  await ok(api + "/groups/create", { group: OUT_GROUP },
           "created " + OUT_GROUP);
  await ok(api + "/groups/add-member", { group: IN_GROUP, member: READER },
           "put the reader in " + IN_GROUP);
  await ok(api + "/groups/add-member", { group: IN_GROUP, member: OTHER },
           "and the other person");
  await ok(api + "/groups/add-member", { group: OUT_GROUP, member: OTHER },
           "put only the other person in " + OUT_GROUP);
  dns.inGroup = "cn=" + IN_GROUP + "," + dns.groups;
  dns.outGroup = "cn=" + OUT_GROUP + "," + dns.groups;
  await ok(api + "/applications/create",
           { identifier: APP, name: "#106 " + STAMP, protocols: ["saml2"],
             fields: { samlEntityId: APP } },
           "created an application in " + realm);
  await ok(api + "/rbac/grant", { username: ADMIN, role: "read" },
           "granted " + ADMIN + " Admin Read on " + realm + "'s own roster");
  log.debug("Leaving setUp().");
  return dns;
}

// The application's DN, found by an ADMINISTRATOR's search: an entry under
// ou=applications carrying the identifier somewhere.
async function applicationDn(dns) {
  log.debug("Entering applicationDn().");
  const client = connect();
  const bound = await bind(client, dns[ADMIN], PASSWORD);
  assert.strictEqual(bound.code, 0, "the administrator should bind: " +
                     bound.code + " " + bound.message);
  const all = await search(client, dns.applications, { scope: "sub" });
  await unbind(client);
  const hit = (all.entries || []).filter(function (entry) {
    return entry.attributes.some(function (a) {
      return [].concat(a.values || []).indexOf(APP) !== -1;
    });
  })[0];
  assert.ok(hit, "an administrator's search of " + dns.applications +
            " should find the application " + APP + "; it answered " +
            all.code + " with " + dnsOf(all).join(", "));
  log.debug("Leaving applicationDn(). " + hit.dn);
  return hit.dn;
}

async function productRealm() {
  log.debug("Entering productRealm().");
  log.info("=== the PRODUCT realm " + PROD + " ===");
  const dns = await setUp(PROD, "product");
  const app = await applicationDn(dns);
  const api = realmBase(PROD) + "/admin-api";

  let client = connect();
  const bound = await bind(client, dns[READER], PASSWORD);
  check("PRODUCT: a person binds over LDAPS", function () {
    assert.strictEqual(bound.code, 0, bound.message);
  });
  const own = await search(client, dns[READER], { scope: "base" });
  check("PRODUCT: they read their own entry, telephoneNumber included",
        function () {
    assert.ok(own.code === 0 &&
              namesOf(entryFor(own, dns[READER])).indexOf(
                "telephonenumber") !== -1,
              JSON.stringify(own).slice(0, 400));
  });
  const otherBase = await search(client, dns[OTHER], { scope: "base" });
  const missing = await search(client, dns.missing, { scope: "base" });
  check("PRODUCT: another person's DN answers 32, as a DN that does not " +
        "exist does", function () {
    assert.ok(otherBase.code === 32 && missing.code === 32,
              otherBase.code + " / " + missing.code);
  });
  const everyone = await search(client, dns.users, { scope: "sub" });
  check("PRODUCT: a subtree search of ou=users returns them and not the " +
        "other person", function () {
    assert.ok(everyone.code === 0 && entryFor(everyone, dns[READER]) &&
              !entryFor(everyone, dns[OTHER]), dnsOf(everyone).join(", "));
  });
  const compareHidden = await compare(client, dns[OTHER], "mail",
                                      OTHER + "@ldr.test");
  check("PRODUCT: a compare on the other person answers 32", function () {
    assert.strictEqual(compareHidden.code, 32);
  });
  const groups = await search(client, dns.groups, { scope: "sub" });
  check("PRODUCT: the group they are in is visible, the other is not",
        function () {
    assert.ok(entryFor(groups, dns.inGroup) &&
              !entryFor(groups, dns.outGroup), dnsOf(groups).join(", "));
  });
  check("PRODUCT: and the group shows no member list", function () {
    assert.ok(namesOf(entryFor(groups, dns.inGroup)).indexOf("member") === -1,
              namesOf(entryFor(groups, dns.inGroup)).join(", "));
  });
  const outBase = await search(client, dns.outGroup, { scope: "base" });
  check("PRODUCT: the group they are not in answers 32", function () {
    assert.strictEqual(outBase.code, 32);
  });
  const appBase = await search(client, app, { scope: "base" });
  const apps = await search(client, dns.applications, { scope: "sub" });
  check("PRODUCT: the application answers 32", function () {
    assert.strictEqual(appBase.code, 32);
  });
  check("PRODUCT: and ou=applications shows only itself", function () {
    assert.ok(apps.code === 0 &&
              dnsOf(apps).join("|") === lower(dns.applications),
              dnsOf(apps).join(", "));
  });

  await ok(api + "/config/set",
           { key: "ldap.directoryReadableAttributes", value: WIDENED },
           "widened ldap.directoryReadableAttributes in " + PROD);
  try {
    const widened = await search(client, dns.users, { scope: "sub" });
    const theirs = namesOf(entryFor(widened, dns[OTHER]));
    check("PRODUCT: widened, the other person shows mail and not " +
          "telephoneNumber", function () {
      assert.ok(theirs.indexOf("mail") !== -1 &&
                theirs.indexOf("telephonenumber") === -1, theirs.join(", "));
    });
    const phones = await search(client, dns.users,
                                { scope: "sub",
                                  filter: "(telephoneNumber=*)" });
    check("PRODUCT: (telephoneNumber=*) matches the reader and not them",
          function () {
      assert.ok(phones.code === 0 && entryFor(phones, dns[READER]) &&
                !entryFor(phones, dns[OTHER]), dnsOf(phones).join(", "));
    });
    const mail = await compare(client, dns[OTHER], "mail",
                               OTHER + "@ldr.test");
    const phone = await compare(client, dns[OTHER], "telephoneNumber", PHONE);
    check("PRODUCT: a compare of mail answers, of telephoneNumber is 50",
          function () {
      assert.ok(mail.code === 0 && mail.matched === true && phone.code === 50,
                JSON.stringify([mail, phone]));
    });
  } finally {
    await call("POST", api + "/config/reset",
               { key: "ldap.directoryReadableAttributes" });
  }
  await unbind(client);

  client = connect();
  const adminBound = await bind(client, dns[ADMIN], PASSWORD);
  const adminOther = await search(client, dns[OTHER], { scope: "base" });
  const adminApp = await search(client, app, { scope: "base" });
  const adminOut = await search(client, dns.outGroup, { scope: "base" });
  await unbind(client);
  check("PRODUCT: the realm's Admin Read reads the other person whole",
        function () {
    assert.ok(adminBound.code === 0 && adminOther.code === 0 &&
              namesOf(entryFor(adminOther, dns[OTHER])).indexOf(
                "telephonenumber") !== -1 &&
              namesOf(entryFor(adminOther, dns[OTHER])).indexOf(
                "userpassword") === -1, JSON.stringify(adminOther)
                .slice(0, 400));
  });
  check("PRODUCT: and the application and every group", function () {
    assert.ok(adminApp.code === 0 && adminOut.code === 0,
              adminApp.code + " / " + adminOut.code);
  });

  client = connect();
  const appBind = await bind(client, app, PASSWORD);
  await unbind(client);
  check("PRODUCT: a bind as the application's DN is 49", function () {
    assert.strictEqual(appBind.code, 49, appBind.message);
  });
  log.debug("Leaving productRealm().");
}

async function developmentRealm() {
  log.debug("Entering developmentRealm().");
  log.info("=== the DEVELOPMENT realm " + DEV + " ===");
  const dns = await setUp(DEV, "development");
  const app = await applicationDn(dns);
  let client = connect();
  const bound = await bind(client, dns[READER], PASSWORD);
  const otherBase = await search(client, dns[OTHER], { scope: "base" });
  const phones = await search(client, dns.users,
                              { scope: "sub", filter: "(telephoneNumber=*)" });
  const phone = await compare(client, dns[OTHER], "telephoneNumber", PHONE);
  const outBase = await search(client, dns.outGroup, { scope: "base" });
  const appBase = await search(client, app, { scope: "base" });
  await unbind(client);
  check("development: a person binds", function () {
    assert.strictEqual(bound.code, 0, bound.message);
  });
  check("development: they read another person whole", function () {
    assert.ok(otherBase.code === 0 &&
              namesOf(entryFor(otherBase, dns[OTHER])).indexOf(
                "telephonenumber") !== -1, JSON.stringify(otherBase)
                .slice(0, 400));
  });
  check("development: (telephoneNumber=*) matches them", function () {
    assert.ok(entryFor(phones, dns[OTHER]), dnsOf(phones).join(", "));
  });
  check("development: a compare of their telephoneNumber answers",
        function () {
    assert.ok(phone.code === 0 && phone.matched === true,
              JSON.stringify(phone));
  });
  check("development: a group they are not in, and the application, answer",
        function () {
    assert.ok(outBase.code === 0 && appBase.code === 0,
              outBase.code + " / " + appBase.code);
  });
  client = connect();
  const appBind = await bind(client, app, "anything-at-all");
  await unbind(client);
  check("development: the application's DN binds, as every DN does",
        function () {
    assert.strictEqual(appBind.code, 0, appBind.message);
  });
  log.debug("Leaving developmentRealm().");
}

async function test() {
  log.debug("Entering test().");
  log.info("LDAPS at " + ldapsUrl() + "; realms " + PROD + " (product) and " +
           DEV + " (development), left behind.");
  await productRealm();
  await developmentRealm();
  // A FLOOR on the count: a section that stops running must fail the job.
  assert.ok(checks >= FLOOR,
    "only " + checks + " checks ran; a section stopped running.");
  log.info(checks + " checks passed.");
  log.debug("Leaving test().");
}

const program = new Command();
program.addOption(new Option("-u, --url <url>",
                  "ignored; kept for a uniform CLI across the suite"));
program.parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
