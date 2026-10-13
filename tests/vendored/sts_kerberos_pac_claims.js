// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_kerberos_pac_claims.js
//
// ---------------------------------------------------------------------------
// KERBEROS PAC CLIENT CLAIMS OVER THE WIRE (#493): a service ticket the KDC
// issues carries PAC_CLIENT_CLAIMS_INFO ([MS-PAC] 2.11, buffer type 13), and
// the claims in it are the ones `/admin-api/kerberos/claims` configures.
//
//   1. A throwaway trust realm with Kerberos ON and `krb5.pacClaims` on, a
//      person, and two service principals made with `create-service` — whose
//      keytabs are how this job opens the tickets, as each service would.
//   2. The realm's PAC claim set, through `POST /admin-api/kerberos/claims/
//      replace` (a fixed string, an int64, a placeholder and a directory
//      attribute), and the claim ids `GET` answers for it; one service's own
//      row through `POST /admin-api/applications/set-custom-claim`.
//   3. A TGT at the realm's `/KdcProxy`, then a service ticket for each
//      service: opened with the service's key, its PAC's server signature
//      verified, and its claims decoded by the codec — each by the claim id
//      the API named, of the type configured, with the value the person
//      has. The service with a row of its own gets that row in place of the
//      realm's; the other gets the realm's.
//   4. The preview `GET /admin-api/kerberos/claims?user=` answers is what
//      the TGT's claims came to.
//   5. `krb5.pacClaims` off on the realm: the next ticket has a PAC and no
//      claims buffer.
//
// AND THE TICKED CATALOGUE (#498): the person's entry holds two values of
// `ou` and a `title`; `POST /admin-api/kerberos/claims/attributes` ticks
// `ou`, `title` and `employeeType`, and a row named `title` sits in the set.
// The ticket carries `ou` as ONE string claim of both values, by the
// `pacClaimId` GET names for it; the row's `title`, not the entry's; and no
// `employeeType`, which the entry lacks.
//
// WHAT IT CHANGES: one trust realm, created here and left standing
// (`leave-test-created-realms`). The default realm's settings are not
// touched, so no other job's tickets change shape while this runs.
//
// OWNED HERE (local: true): this repository's KDC and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const path = require("path");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");
const wire = require("./krb5_wire.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_pac_claims",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

// The service's own PAC codec, from the tree this file sits in.
const kpac = require(path.join(__dirname, "..", "..", "kerberos",
                               "krb5_pac.js"));
const msgs = wire.msgs;
const kcrypto = wire.kcrypto;

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

const STAMP = names.runStamp();
const RID = ("pacclaims-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                  .slice(0, 31);
const DOMAIN = RID + ".example.net";
const KREALM = DOMAIN.toUpperCase();
const USER = names.usernameFor("pac-claims");
const PASSWORD = "Pac-Claims-Passw0rd!-" + String(Date.now()).slice(-6);
const MAIL = USER + "@" + DOMAIN;
const SPN_OWN = "HTTP/own." + DOMAIN;
const SPN_REALM = "HTTP/plain." + DOMAIN;
const realmApi = base + "/realm/" + RID + "/admin-api";

// How long a product person's keys may take to arrive (the krbtgt job's
// number), and how long a written setting or entry may take to reach the
// process that answers the KDC.
const KEYS_WAIT_MS = 30000;
const SETTLE_MS = 20000;

const K = { product: false, password: "" };

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

function pause(ms) {
  log.debug("Entering pause().");
  log.debug("Leaving pause().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: { "Content-Type": "application/json",
               Accept: "application/json" },
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
  log.debug("Leaving call(). HTTP " + r.status);
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

// A keytab's newest key per enctype.
function keysOf(keytabB64) {
  log.debug("Entering keysOf().");
  const keys = {};
  const kvnos = {};
  wire.readKeytab(Buffer.from(String(keytabB64), "base64"))
    .forEach(function (one) {
      if (kvnos[one.etype] === undefined || one.kvno > kvnos[one.etype]) {
        kvnos[one.etype] = one.kvno;
        keys[one.etype] = one.key;
      }
    });
  log.debug("Leaving keysOf().");
  return keys;
}

async function signIn(kdc) {
  log.debug("Entering signIn().");
  const started = Date.now();
  for (;;) {
    const r = await wire.asExchange(kdc, KREALM, USER,
                                    { password: K.password });
    if (r.tgt || Date.now() - started > KEYS_WAIT_MS) {
      log.debug("Leaving signIn().");
      return r;
    }
    await pause(500);
  }
}

// A service ticket opened with its service's key: the PAC, whether its server
// signature verifies, and its client claims as `{ id: [typeName, values] }`
// (null when there is no claims buffer).
async function opened(ticket, keys) {
  log.debug("Entering opened().");
  const encPart = ticket.encPart;
  const key = keys[encPart.etype];
  assert.ok(key, "no key of the ticket's enctype " + encPart.etype);
  const part = msgs.readEncTicketPart(await kcrypto.etypeById(encPart.etype)
    .decrypt(key, kcrypto.KEY_USAGE.KDC_REP_TICKET, encPart.cipher));
  const pacs = kpac.findPacs(part.authorizationData || []);
  assert.strictEqual(pacs.length, 1, "one PAC in the ticket");
  const pac = kpac.parsePac(pacs[0].bytes);
  const signatures = await kpac.verifySignatures(pac,
    { serverKey: { etype: encPart.etype, key: key } });
  const server = signatures.filter(function (one) {
    return one.type === kpac.TYPE.SERVER_CHECKSUM;
  })[0];
  const buffer = kpac.bufferOfType(pac, kpac.TYPE.CLIENT_CLAIMS);
  let claims = null;
  if (buffer) {
    assert.ok(buffer.parsed, "the claims buffer decodes: " + buffer.error);
    claims = {};
    buffer.parsed.claims.forEach(function (claim) {
      claims[claim.id] = [claim.typeName, claim.values];
    });
  }
  log.debug("Leaving opened().");
  return { verified: !!(server && server.verified === true),
           claims: claims,
           compression: buffer ? buffer.parsed.compressionName : null };
}

async function serviceTicket(kdc, tgt, spn, keys, want) {
  log.debug("Entering serviceTicket(). " + spn);
  const started = Date.now();
  for (;;) {
    const r = await wire.tgsExchange(kdc, tgt,
      { type: 3, name: spn.split("/") }, KREALM);
    assert.ok(r.ok, "a service ticket for " + spn + ": " +
              (r.error && r.error.toString()));
    const seen = await opened(r.ticket, keys);
    if (want(seen) || Date.now() - started > SETTLE_MS) {
      log.debug("Leaving serviceTicket().");
      return seen;
    }
    await pause(500);
  }
}

async function test() {
  log.debug("Entering test().");
  log.info("Kerberos PAC claims in the throwaway realm " + RID + " at " +
           base);
  K.product = await facts.isProduct(api);

  log.info("=== 1. the realm, the person and two service principals ===");
  await ok(api + "/realms/create",
           { id: RID, domain: DOMAIN, name: "#493 PAC claims",
             overrides: { "krb5.enabled": true, "krb5.realm": KREALM,
                          "krb5.pacClaims": true } },
           "created the realm " + RID + " with Kerberos and PAC claims on");
  K.password = K.product ? PASSWORD
    : String(await facts.setting(realmApi, "krb5.userPassword") ||
             "password!");
  await ok(realmApi + "/users/create",
           { username: USER, invent: false, credential: "password",
             password: PASSWORD,
             attributes: { cn: "pac " + USER, givenName: "pac", sn: USER,
                           displayName: "pac " + USER, mail: MAIL } },
           "created " + USER + " in " + RID);
  // A multi-valued `ou` and a `title` on the entry, for the ticked
  // catalogue (#498).
  await ok(realmApi + "/users/set-attribute",
           { user: USER, attribute: "ou", value: "blue" }, "set ou");
  await ok(realmApi + "/users/add-attribute",
           { user: USER, attribute: "ou", value: "green" }, "added an ou");
  await ok(realmApi + "/users/set-attribute",
           { user: USER, attribute: "title", value: "Entry title" },
           "set title");
  const own = await ok(realmApi + "/kerberos/principals/create-service",
                       { spn: SPN_OWN }, "created " + SPN_OWN);
  const plain = await ok(realmApi + "/kerberos/principals/create-service",
                         { spn: SPN_REALM }, "created " + SPN_REALM);
  const ownKeys = keysOf(own.keytab);
  const plainKeys = keysOf(plain.keytab);

  log.info("=== 2. the claim set, its ids and one service's own row ===");
  await ok(realmApi + "/kerberos/claims/replace", { set: "kerberos-pac",
    claims: [
      { name: "department", type: "string", value: "Sales" },
      { name: "level", type: "int64", value: "-7" },
      { name: "who", type: "string", value: "${username}" },
      { name: "mailclaim", type: "string", attribute: "mail" },
      { name: "title", type: "string", value: "Row title" }
    ] }, "replaced the realm's PAC claims");
  const ticked = await ok(realmApi + "/kerberos/claims/attributes",
                          { set: "kerberos-pac",
                            attributes: ["ou", "title", "employeeType"] },
                          "ticked ou, title and employeeType (#498)");
  await ok(realmApi + "/applications/set-custom-claim",
           { application: SPN_OWN + "@" + KREALM, set: "kerberos-pac",
             name: "department", type: "string", value: "Own team" },
           "set " + SPN_OWN + "'s own department");
  const view = await call("GET", realmApi + "/kerberos/claims?user=" +
                          encodeURIComponent(USER));
  const ids = {};
  check("GET /admin-api/kerberos/claims answers the set with a claim id " +
        "per row, ad://ext/<name>:<16 hex>, and says the realm has it on",
        function () {
    assert.strictEqual(view.status, 200, view.text.slice(0, 300));
    assert.strictEqual(view.json.enabled, true);
    view.json.sets[0].claims.forEach(function (row) {
      ids[row.name] = row.claimId;
    });
    ["department", "level", "who", "mailclaim"].forEach(function (name) {
      assert.ok(/^ad:\/\/ext\/[A-Za-z0-9._-]+:[0-9a-f]{16}$/
        .test(ids[name] || ""), name + ": " + ids[name]);
    });
  });
  check("the attributes action answers the three ticked, and GET names " +
        "them with the PAC claim id each catalogue row becomes (#498)",
        function () {
    assert.deepStrictEqual(ticked.attributes.slice().sort(),
                           ["employeeType", "ou", "title"]);
    assert.deepStrictEqual(view.json.sets[0].attributes.slice().sort(),
                           ["employeeType", "ou", "title"]);
    view.json.attributeCatalogue.forEach(function (row) {
      ids["@" + row.ldap] = row.pacClaimId;
    });
    assert.ok(/^ad:\/\/ext\/ou:[0-9a-f]{16}$/.test(ids["@ou"] || ""),
              "ou: " + ids["@ou"]);
    assert.strictEqual(ids["@title"], ids.title,
                       "a ticked title and a row named title share an id");
    assert.deepStrictEqual(view.json.preview.byLdap.ou.values,
                           ["blue", "green"]);
  });

  log.info("=== 3. a TGT and two service tickets ===");
  const kdc = wire.proxyTransport(base + "/realm/" + RID);
  const first = await signIn(kdc);
  check("AS exchange at /realm/" + RID + "/KdcProxy: a TGT for " + USER,
        function () {
    assert.ok(first.tgt, "no TGT: " + JSON.stringify(first.second ||
                                                     first.first));
  });
  const realmSeen = await serviceTicket(kdc, first.tgt, SPN_REALM, plainKeys,
    function (seen) { return !!seen.claims && !!seen.claims[ids["@ou"]]; });
  check("the service ticket for " + SPN_REALM + " carries a claims buffer, " +
        "uncompressed, under a server signature its own key verifies",
        function () {
    assert.ok(realmSeen.claims, "no PAC_CLIENT_CLAIMS_INFO");
    assert.strictEqual(realmSeen.compression, "COMPRESSION_FORMAT_NONE");
    assert.strictEqual(realmSeen.verified, true);
  });
  check("its claims are the realm's, by the ids the API named: a string, " +
        "an int64, the placeholder expanded and the directory's mail",
        function () {
    assert.deepStrictEqual(realmSeen.claims[ids.department],
                           ["STRING", ["Sales"]]);
    assert.deepStrictEqual(realmSeen.claims[ids.level], ["INT64", ["-7"]]);
    assert.deepStrictEqual(realmSeen.claims[ids.who], ["STRING", [USER]]);
    assert.deepStrictEqual(realmSeen.claims[ids.mailclaim],
                           ["STRING", [MAIL]]);
  });
  check("a ticked multi-valued attribute is one STRING claim of every " +
        "value; the set's row wins over a ticked attribute of its id; an " +
        "attribute the entry lacks is no claim (#498)", function () {
    assert.deepStrictEqual(realmSeen.claims[ids["@ou"]],
                           ["STRING", ["blue", "green"]]);
    assert.deepStrictEqual(realmSeen.claims[ids.title],
                           ["STRING", ["Row title"]]);
    assert.strictEqual(realmSeen.claims[ids["@employeeType"]], undefined);
  });
  const ownSeen = await serviceTicket(kdc, first.tgt, SPN_OWN, ownKeys,
    function (seen) {
      return !!seen.claims && !!seen.claims[ids.department] &&
             seen.claims[ids.department][1][0] === "Own team";
    });
  check("the service ticket for " + SPN_OWN + " carries its application's " +
        "own row in place of the realm's, and the rest of the realm's",
        function () {
    assert.ok(ownSeen.claims, "no claims buffer");
    assert.deepStrictEqual(ownSeen.claims[ids.department],
                           ["STRING", ["Own team"]]);
    assert.deepStrictEqual(ownSeen.claims[ids.level], ["INT64", ["-7"]]);
    assert.strictEqual(ownSeen.verified, true);
  });

  log.info("=== 4. the preview ===");
  check("the API's preview for " + USER + " names the claims the ticket " +
        "carried from its TGT", function () {
    const preview = {};
    view.json.preview.claims.forEach(function (claim) {
      preview[claim.id] = claim.values;
    });
    Object.keys(realmSeen.claims).forEach(function (id) {
      assert.deepStrictEqual(preview[id], realmSeen.claims[id][1],
                             "preview of " + id);
    });
  });

  log.info("=== 5. off ===");
  await ok(realmApi + "/config/set", { key: "krb5.pacClaims", value: false },
           "turned krb5.pacClaims off on " + RID);
  const second = await signIn(kdc);
  assert.ok(second.tgt, "a second TGT");
  const offSeen = await serviceTicket(kdc, second.tgt, SPN_REALM, plainKeys,
    function (seen) { return !seen.claims; });
  check("with krb5.pacClaims off the next service ticket has a PAC and no " +
        "claims buffer", function () {
    assert.strictEqual(offSeen.claims, null);
    assert.strictEqual(offSeen.verified, true);
  });

  const floor = 9;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_pac_claims")
  .description("A service ticket's PAC carries PAC_CLIENT_CLAIMS_INFO with " +
    "the claims /admin-api/kerberos/claims configures, a service's own row " +
    "replacing the realm's, its ticked directory attributes (#498), and " +
    "none with krb5.pacClaims off (#493).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
