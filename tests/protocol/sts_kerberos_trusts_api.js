// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_kerberos_trusts_api.js
//
// KERBEROS TRUSTS OVER /admin-api, END TO END (#430 Phase 4).
//
// Two throwaway trust realms, each with Kerberos on for a Kerberos realm of
// its own, and the seven acts of `POST /admin-api/kerberos/trusts/{action}`
// between them, each read back through `GET /admin-api/kerberos/trusts`:
//
//   1. a fresh realm holds no trust;
//   2. add a trust-realm record from A to B — the health says B holds no
//      matching record — and a refused contradiction;
//   3. pair — B's record for A is written in the same act;
//   4. rotate-key with mirror — both realms at kvno 2, the generated keys in
//      the reply once and the reply not cacheable, kvno 1 kept with a grace;
//   5. the application panel: a Kerberos service of B naming a front end of
//      A (appAllowedToActOnBehalfOf) and A in krb5S4uSelfRealm, read in its
//      `GET /admin-api/applications?application=` answer's
//      `page.krb5Across`;
//   6. disable and enable;
//   7. remove — refused without the partner realm in `confirm`, done with
//      it, and the drill-down then naming the trust as unknown.
//
// NO KEY IS EVER IN A READ: every GET is searched for the keys a generate
// returned and for the trust password.
//
// WHAT IT CHANGES: two trust realms, created here and left standing
// (`leave-test-created-realms`). `local: true`: this repository's KDC
// records and API.

const assert = require("assert");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const facts = require("./service_facts.js");

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
var log = bunyan.createLogger({ name: "sts_kerberos_trusts_api",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const api = base + "/admin-api";

const STAMP = names.runStamp();
function rid(tag) {
  log.debug("Entering rid().");
  log.debug("Leaving rid().");
  return ("trust" + tag + "-" + STAMP).toLowerCase()
    .replace(/[^a-z0-9-]/g, "").slice(0, 31);
}
const A = { id: rid("a") };
const B = { id: rid("b") };
[A, B].forEach(function (r) {
  r.domain = r.id + ".example.net";
  r.krb = r.domain.toUpperCase();
  r.api = base + "/realm/" + r.id + "/admin-api";
});
const PASSWORD = "Trust-Passw0rd-" + String(Date.now()).slice(-8) +
                 "-shared-between-two-realms";

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
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
  return { status: r.status, json: json, text: text,
           cacheControl: r.headers.get("cache-control") || "" };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": POST " + url + " answered " + r.status + " " +
            r.text.slice(0, 400));
  log.info("  " + what);
  log.debug("Leaving ok().");
  return r;
}

// Every key a generate returned, to search every read for.
const SECRETS = [PASSWORD];

async function read(realm, query) {
  log.debug("Entering read().");
  const r = await call("GET", realm.api + "/kerberos/trusts" + (query || ""));
  assert.strictEqual(r.status, 200, "GET /admin-api/kerberos/trusts in " +
                     realm.id + " answered " + r.status + " " +
                     r.text.slice(0, 300));
  SECRETS.forEach(function (secret) {
    assert.ok(r.text.indexOf(secret) === -1,
              "a read of the trusts carried key material");
  });
  log.debug("Leaving read().");
  return r.json;
}

function kinds(row) {
  log.debug("Entering kinds().");
  log.debug("Leaving kinds().");
  return ((row && row.health) || []).map(function (one) {
    return one.kind;
  });
}

async function test() {
  log.debug("Entering test().");
  log.info("Kerberos trusts over /admin-api between " + A.id + " and " +
           B.id + " at " + base);
  const product = await facts.isProduct(api);

  log.info("=== 0. two trust realms with Kerberos on ===");
  for (const r of [A, B]) {
    await ok(api + "/realms/create",
             { id: r.id, domain: r.domain, name: "#430 trusts " + r.id,
               overrides: { "krb5.enabled": true, "krb5.realm": r.krb } },
             "created " + r.id + " answering as " + r.krb);
  }

  log.info("=== 1. a fresh realm holds no trust ===");
  let v = await read(A);
  check("1. GET answers no trust in a fresh realm, the form's attribute " +
        "set and the trust settings", function () {
    assert.strictEqual(v.total, 0);
    assert.ok(v.form.attributes.indexOf("quarantined") >= 0);
    assert.ok(v.form.trustRealms.some(function (one) {
      return one.id === B.id && one.kerberosRealm === B.krb;
    }), JSON.stringify(v.form.trustRealms));
    assert.strictEqual(typeof v.settings.graceSeconds, "number");
  });

  log.info("=== 2. add, and a refused contradiction ===");
  await ok(A.api + "/kerberos/trusts/add",
           { partnerRealm: B.krb, type: "trust-realm",
             partnerTrustRealm: B.id, direction: "bidirectional",
             keySource: "password", password: PASSWORD,
             attributes: ["quarantined"], suffixes: [B.domain] },
           "added A's trust with " + B.krb);
  v = await read(A, "?trust=" + encodeURIComponent(B.krb));
  check("2a. the drill-down describes both keys at kvno 1 from a " +
        "password, and says " + B.id + " holds no matching record",
        function () {
    assert.ok(v.trust, JSON.stringify(v).slice(0, 300));
    assert.strictEqual(v.trust.incoming.kvno, 1);
    assert.strictEqual(v.trust.outgoing.source, "password");
    assert.ok(kinds(v.trust).indexOf("unpaired") >= 0,
              JSON.stringify(v.trust.health));
  });
  const bad = await call("POST", A.api + "/kerberos/trusts/update",
    { partnerRealm: B.krb,
      attributes: ["no-tgt-delegation", "enable-tgt-delegation"] });
  check("2b. a contradiction is refused, 400, naming both bits", function () {
    assert.strictEqual(bad.status, 400, bad.text.slice(0, 300));
    assert.ok(/cannot both be set/.test(bad.text), bad.text.slice(0, 300));
  });

  log.info("=== 3. pair ===");
  const paired = await ok(A.api + "/kerberos/trusts/pair",
                          { partnerRealm: B.krb },
                          "paired A's trust onto " + B.id);
  v = await read(B, "?trust=" + encodeURIComponent(A.krb));
  check("3. pair writes " + B.id + "'s record for " + A.krb + " in the " +
        "same act, both keys at kvno 1", function () {
    assert.strictEqual(paired.json.created, true);
    assert.ok(v.trust, JSON.stringify(v).slice(0, 300));
    assert.strictEqual(v.trust.direction, "bidirectional");
    assert.strictEqual(v.trust.incoming.kvno, 1);
  });

  log.info("=== 4. rotate-key with mirror ===");
  const rotated = await ok(A.api + "/kerberos/trusts/rotate-key",
                           { partnerRealm: B.krb, keySource: "generate",
                             mirror: true },
                           "rotated both sides");
  Object.keys(rotated.json.shown || {}).forEach(function (side) {
    Object.keys(rotated.json.shown[side]).forEach(function (etype) {
      SECRETS.push(rotated.json.shown[side][etype]);
    });
  });
  const vA = await read(A, "?trust=" + encodeURIComponent(B.krb));
  const vB = await read(B, "?trust=" + encodeURIComponent(A.krb));
  check("4. both realms move to kvno 2; the generated keys are in the " +
        "reply once and it is not cacheable; kvno 1 is kept with a grace",
        function () {
    assert.ok(SECRETS.length > 1, "no generated key in the reply");
    assert.ok(/no-store/.test(rotated.cacheControl), rotated.cacheControl);
    assert.strictEqual(vA.trust.outgoing.kvno, 2);
    assert.strictEqual(vB.trust.incoming.kvno, 2);
    assert.strictEqual(vB.trust.incoming.previous.kvno, 1);
    assert.ok(vB.trust.incoming.previous.acceptedUntil);
  });

  log.info("=== 5. the application panel ===");
  const front = "HTTP/front." + A.domain + "@" + A.krb;
  const identifier = "HTTP/back." + B.domain + "@" + B.krb;
  await ok(B.api + "/applications/create",
           { identifier: identifier, name: "#430 back end",
             protocols: ["krb5"],
             fields: { krb5ServicePrincipalName: ["HTTP/back." + B.domain],
                       appAllowedToActOnBehalfOf: [front],
                       krb5S4uSelfRealm: [A.krb] } },
           "created " + identifier + " in " + B.id);
  const app = await call("GET", B.api + "/applications?application=" +
                         encodeURIComponent(identifier));
  const across = app.json && app.json.page ? app.json.page.krb5Across : null;
  check("5. its answer's page.krb5Across reads the foreign front end and " +
        "the S4U2Self realm against " + B.id + "'s trust with " + A.krb,
        function () {
    assert.strictEqual(app.status, 200, app.text.slice(0, 300));
    assert.ok(across, "no krb5Across in the answer");
    assert.strictEqual(across.frontEnds.length, 1);
    assert.strictEqual(across.frontEnds[0].actor, front);
    assert.strictEqual(across.frontEnds[0].ok, true,
                       JSON.stringify(across.frontEnds[0]));
    assert.strictEqual(across.selfRealms[0].accepted, true);
    assert.ok(across.choices.krb5S4uSelfRealm.indexOf(A.krb) >= 0);
  });

  log.info("=== 6. disable and enable ===");
  await ok(B.api + "/kerberos/trusts/disable", { partnerRealm: A.krb },
           "disabled " + B.id + "'s trust");
  v = await read(B, "?trust=" + encodeURIComponent(A.krb));
  const offApp = await call("GET", B.api + "/applications?application=" +
                            encodeURIComponent(identifier));
  check("6a. disabled: the record says so, keeps its keys, and the panel " +
        "names the disabled trust", function () {
    assert.strictEqual(v.trust.enabled, false);
    assert.ok(kinds(v.trust).indexOf("disabled") >= 0);
    assert.strictEqual(v.trust.incoming.held, true);
    assert.ok(offApp.json.page.krb5Across.frontEnds[0].problems
      .some(function (one) { return one.kind === "disabled"; }));
  });
  await ok(B.api + "/kerberos/trusts/enable", { partnerRealm: A.krb },
           "enabled it again");
  v = await read(B, "?trust=" + encodeURIComponent(A.krb));
  check("6b. enabled again", function () {
    assert.strictEqual(v.trust.enabled, true);
  });

  log.info("=== 7. remove ===");
  const unconfirmed = await call("POST", A.api + "/kerberos/trusts/remove",
                                 { partnerRealm: B.krb, confirm: "yes" });
  check("7a. remove without the partner realm in confirm is refused, 400",
        function () {
    assert.strictEqual(unconfirmed.status, 400,
                       unconfirmed.text.slice(0, 300));
  });
  await ok(A.api + "/kerberos/trusts/remove",
           { partnerRealm: B.krb, confirm: B.krb }, "removed A's trust");
  v = await read(A, "?trust=" + encodeURIComponent(B.krb));
  check("7b. it is gone, and the drill-down names it as unknown",
        function () {
    assert.strictEqual(v.trust, null);
    assert.strictEqual(v.unknownTrust, B.krb);
    assert.strictEqual(v.total, 0);
  });
  log.info("(product mode: " + product + ")");

  const floor = 10;
  assert.ok(checks >= floor, "only " + checks + " checks ran (floor " +
            floor + "); a section has stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_kerberos_trusts_api")
  .description("Kerberos trusts over /admin-api between two trust realms: " +
    "add, pair, rotate with mirror and grace, the application panel, " +
    "disable and enable, and remove (#430 Phase 4).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
