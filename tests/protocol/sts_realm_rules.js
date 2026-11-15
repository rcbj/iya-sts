// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_realm_rules.js
//
// ---------------------------------------------------------------------------
// WHAT A TRUST REALM MAY CARRY, AND ITS DNS DOMAIN, OVER THE WIRE.
//
// D12 (#444): carries over two in-process files, so that their claims stay
// covered when the Rust runtime replaces Node:
//
//   * `tests/config_realm_layer.js` — the three locks on a realm's layer:
//       1. `POST /admin-api/realms/create`'s `overrides` are CARRIED, not
//          dropped (GET /admin-api/realms reads them back);
//       2. `realms.*` is refused on a realm, at create and at `realms/set`;
//       3. the restart-only rows: a realm may carry exactly the
//          `realmRuntime` ones (the list below, which is the in-process
//          file's `EXPECTED_REALM_RUNTIME`), and EVERY other restart-only
//          setting is refused on a realm with the restart sentence — walked
//          over the whole table the realm's `GET /admin-api/config` lists;
//          `global.https` refused by name, `oauth2.rfc9700` accepted on a
//          realm while the PROCESS still reads it as restart-only;
//       and the reading end: a realm in RFC 9700 mode keeps the process's
//       scheme in its issuer.
//   * `tests/realm_domain.js` — a realm's DNS domain (2026-09-18):
//       A. the shape, refused 400 and recorded STS-CORE-0099 on the audit
//          log (one label, a numeric top-level label, a bad character, a
//          leading hyphen, a 64-character label); normalised in lower case,
//          an internationalised name kept as its A-label;
//       B. a realm with none is `<id>.<global.domain>`, and its base DN is
//          the RFC 2247 mapping;
//       C. the names seeded from it: the SPIFFE trust domain, the Kerberos
//          realm in capitals with Kerberos still OFF, no service principal,
//          no SAML / WS-* name, an OpenID4VP client id keeping the id suffix,
//          and a caller's own trust domain winning over the seeded one;
//       D. no two realms share a domain (the default realm's included,
//          STS-CORE-0100), and one INSIDE another's is allowed;
//       E. it is FIXED (STS-CORE-0101); the same domain again is no change;
//       F. over the LDAP socket: each realm a naming context of its own in
//          the root DSE, a person found under their own realm's base, a
//          nested realm's person invisible from the parent's base, and a DN
//          in no realm's tree answered noSuchObject;
//       G. an invented mail address is in the realm's domain.
//
// Every write is a realm this job creates: nothing process-wide is changed.
// (A `realms.*` key posted to a REALM's `/admin-api/config/set` lands on the
// PROCESS, by design, so this job only ever uses `/admin-api/realms/set` for
// the realm layer, the door the in-process file's `setOverride()` is.)
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const ldap = require("ldapjs");
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
var log = bunyan.createLogger({ name: "sts_realm_rules",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const LDAP_URL = process.env.STS_LDAP_URL ||
  ("ldap://" + new URL(base).hostname + ":" +
   (process.env.STS_LDAP_PORT || 389));
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const RESTART_REFUSAL = "cannot be changed while this service is running";
const ON_ONE_REALM = "cannot be set on one realm";

// The in-process file's EXPECTED_REALM_RUNTIME: the restart-only rows a realm
// may carry because each is bound with the realm rather than the process.
const REALM_RUNTIME = [
  "oauth2.rfc9700", "oauth2.oauth21", "oauth2.fapi",
  "krb5.realm", "krb5.domainSid", "krb5.krbtgtPassword",
  "krb5.servicePrincipal", "krb5.servicePassword", "krb5.serviceSalt",
  "krb5.kvno", "krb5.enctypes", "krb5.userPassword",
  "krb5.autoServicePassword",
  "spiffe.trustDomain", "spiffe.x509KeyType", "spiffe.jwtKeyType",
  "spiffe.workloadSocketEnabled", "spiffe.workloadSocket",
  "spiffe.workloadPort", "spiffe.workloadTcpSourceAuthenticated",
  "spiffe.serverPort", "spiffe.serverSocketEnabled", "spiffe.serverSocket",
  "spiffe.brokerPort", "spiffe.grpcHost", "listeners.realm"
];

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

function errorsOf(r) {
  log.debug("Entering errorsOf().");
  log.debug("Leaving errorsOf().");
  return ((r.body && r.body.errors) || []).join(" ");
}

// How many audit rows of the default realm carry `code` — the realm the
// `/admin-api/realms/*` requests arrive in. Codes are never sent; this is
// where they are read.
async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(base + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  const rows = (r.body && (r.body.events || r.body.rows)) || [];
  log.debug("Leaving codeCount(). " + rows.length);
  return Number((r.body && r.body.matched) || rows.length);
}

async function sawCode(code, before) {
  log.debug("Entering sawCode(). " + code);
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(code);
  }
  log.debug("Leaving sawCode(). " + before + " -> " + after);
  return after > before;
}

async function realmRow(id) {
  log.debug("Entering realmRow(). " + id);
  const r = await send(base + "/admin-api/realms?per=500");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const all = (r.body && r.body.realms) || [];
  log.debug("Leaving realmRow().");
  return { row: all.filter(function (one) {
    return one.id === id;
  })[0] || null, listing: r.body };
}

function settingOf(row, key) {
  log.debug("Entering settingOf().");
  const one = ((row && row.settings) || []).filter(function (s) {
    return s.key === key;
  })[0];
  log.debug("Leaving settingOf().");
  return one ? one.value : undefined;
}

async function configRows(realm) {
  log.debug("Entering configRows().");
  const r = await send(base + (realm ? "/realm/" + realm : "") +
                       "/admin-api/config");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const rows = [];
  (r.body.groups || []).forEach(function (g) {
    (g.settings || []).forEach(function (s) {
      rows.push(s);
    });
  });
  log.debug("Leaving configRows(). " + rows.length);
  return rows;
}

function ldapSearch(client, dn, options) {
  log.debug("Entering ldapSearch(). " + dn);
  log.debug("Leaving ldapSearch().");
  return new Promise(function (resolve) {
    client.search(dn, options, function (err, res) {
      if (err) {
        resolve({ error: err.name, entries: [] });
        return;
      }
      const entries = [];
      res.on("searchEntry", function (entry) {
        entries.push(entry.pojo || entry.object);
      });
      res.on("error", function (e) {
        resolve({ error: e.name, entries: entries });
      });
      res.on("end", function () {
        resolve({ error: null, entries: entries });
      });
    });
  });
}

function attr(entry, type) {
  log.debug("Entering attr().");
  const a = ((entry && entry.attributes) || []).filter(function (x) {
    return String(x.type).toLowerCase() === type.toLowerCase();
  })[0];
  log.debug("Leaving attr().");
  return a ? a.values : [];
}

// ---------------------------------------------------------------------------
// config_realm_layer.js
// ---------------------------------------------------------------------------
async function theRealmLayer() {
  log.debug("Entering theRealmLayer().");
  log.info("=== 1. what a realm may carry (config_realm_layer) ===");
  const made = "rl-made-" + STAMP;
  await ok(base + "/admin-api/realms/create", { id: made,
    name: "Realm layer " + STAMP,
    overrides: { "oauth2.rfc9700": true } },
    "created a realm with an override");
  const mine = (await realmRow(made)).row;
  check("a create's `overrides` are CARRIED by the realm it makes (they " +
        "were dropped until 2026-08-25)", function () {
    assert.ok(mine, "the realm is not listed");
    assert.strictEqual(String(settingOf(mine, "oauth2.rfc9700")), "true",
                       JSON.stringify(mine.settings));
  });

  const badId = "rl-bad-" + STAMP;
  const badCreate = await postJson(base + "/admin-api/realms/create", {
    id: badId, overrides: { "realms.pathSegment": "zone" } });
  check("a create carrying a realms.* override is refused, and no realm is " +
        "made", function () {
    assert.strictEqual(badCreate.status, 400, badCreate.raw.slice(0, 300));
    assert.ok(errorsOf(badCreate).indexOf(ON_ONE_REALM) >= 0,
              errorsOf(badCreate));
  });
  const leftBehind = (await realmRow(badId)).row;
  check("the refused create left no realm behind", function () {
    assert.strictEqual(leftBehind, null, JSON.stringify(leftBehind));
  });

  for (const pair of [["realms.pathSegment", "zone"],
                      ["realms.enabled", "false"]]) {
    const r = await postJson(base + "/admin-api/realms/set",
                             { id: made, key: pair[0], value: pair[1] });
    check("realms/set REFUSES " + pair[0] + " on a realm", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(errorsOf(r).indexOf(ON_ONE_REALM) >= 0, errorsOf(r));
    });
  }

  const processRows = await configRows("");
  const realmRows = await configRows(made);
  const inRealm = {};
  realmRows.forEach(function (s) {
    inRealm[s.key] = s;
  });
  const restartOnly = processRows.filter(function (s) {
    return !!s.restartReason;
  });
  const carried = restartOnly.filter(function (s) {
    return inRealm[s.key] && inRealm[s.key].editable === true;
  }).map(function (s) {
    return s.key;
  });
  check("the restart-only rows a realm may carry are EXACTLY the " +
        "realmRuntime ones — add one and this is the line that makes it a " +
        "decision", function () {
    assert.deepStrictEqual(carried.slice().sort(),
                           REALM_RUNTIME.slice().sort());
  });
  const rfc = processRows.filter(function (s) {
    return s.key === "oauth2.rfc9700";
  })[0];
  check("the PROCESS still reads oauth2.rfc9700 as restart-only", function () {
    assert.ok(rfc && rfc.editable === false && rfc.restartReason,
              JSON.stringify(rfc));
  });

  const leaked = [];
  let restartSentence = 0;
  const others = restartOnly.filter(function (s) {
    return REALM_RUNTIME.indexOf(s.key) < 0 && !/^realms\./.test(s.key);
  });
  for (const s of others) {
    // The setting's OWN current value, so it is type-valid by construction
    // and the only ground left to refuse it on is the restart rule.
    const r = await postJson(base + "/admin-api/realms/set",
      { id: made, key: s.key, value: s.text === undefined ? "" : s.text });
    // Observed: most are refused with the restart sentence; the rows that
    // are a property of the OS process (workers.*, global.proxyProtocol and
    // the like) are refused as "cannot be set on one realm" instead. Both
    // are a refusal on the realm layer, which is the claim.
    const why = errorsOf(r);
    if (r.status === 400 && why.indexOf(RESTART_REFUSAL) >= 0) {
      restartSentence += 1;
    } else if (!(r.status === 400 && why.indexOf(ON_ONE_REALM) >= 0)) {
      leaked.push(s.key + " (" + r.status + " " + why.slice(0, 80) + ")");
    }
  }
  check("every OTHER restart-only setting is refused on a realm (" +
        others.length + " walked, " + restartSentence + " with the restart " +
        "sentence)", function () {
    assert.ok(others.length > 100, "only " + others.length + " rows");
    assert.deepStrictEqual(leaked, []);
    assert.ok(restartSentence > 0, String(restartSentence));
  });
  const https = await postJson(base + "/admin-api/realms/set",
    { id: made, key: "global.https", value: "true" });
  check("a realm may NOT carry global.https — it binds no socket",
        function () {
    assert.strictEqual(https.status, 400, https.raw.slice(0, 300));
  });
  const rfcOn = await postJson(base + "/admin-api/realms/set",
    { id: made, key: "oauth2.fapi", value: "off" });
  check("while a realmRuntime row (oauth2.fapi) is accepted on it",
        function () {
    assert.strictEqual(rfcOn.status, 200, rfcOn.raw.slice(0, 300));
  });

  const disc = await send(base + "/realm/" + made +
                          "/.well-known/openid-configuration");
  const plain = await send(base + "/.well-known/openid-configuration");
  check("THE READING END: a realm in RFC 9700 mode keeps the process's " +
        "scheme in its issuer — it inherits no claim about a socket it " +
        "does not bind", function () {
    assert.strictEqual(disc.status, 200, disc.raw.slice(0, 300));
    assert.strictEqual(new URL(disc.body.issuer).protocol,
                       new URL(plain.body.issuer).protocol);
    assert.strictEqual(disc.body.issuer, plain.body.issuer + "/realm/" + made);
  });
  log.debug("Leaving theRealmLayer().");
}

// ---------------------------------------------------------------------------
// realm_domain.js
// ---------------------------------------------------------------------------
async function theDomain() {
  log.debug("Entering theDomain().");
  log.info("=== 2. a realm's DNS domain (realm_domain) ===");
  const before99 = await codeCount("STS-CORE-0099");
  const shapes = ["localhost", "example.123", "bad_label.example",
                  "-lead.example", new Array(65).join("a") + ".example"];
  const shapeId = "rd-shape-" + STAMP;
  for (const d of shapes) {
    const r = await postJson(base + "/admin-api/realms/create",
                             { id: shapeId, domain: d });
    check("A. the domain " + JSON.stringify(d.slice(0, 24)) + " is refused " +
          "400, naming the rule", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(/is a DNS name of at least two labels/.test(errorsOf(r)),
                errorsOf(r));
      assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "a code was sent");
    });
  }
  const saw99 = await sawCode("STS-CORE-0099", before99);
  const shapeRow = (await realmRow(shapeId)).row;
  check("A. recorded STS-CORE-0099 on the audit log, and no realm made",
        function () {
    assert.ok(saw99, "no STS-CORE-0099 row was recorded");
    assert.strictEqual(shapeRow, null, JSON.stringify(shapeRow));
  });

  const own = "rd-own-" + STAMP;
  const ownDomain = "craptastic-" + STAMP + ".net";
  await ok(base + "/admin-api/realms/create", { id: own,
    domain: "  Craptastic-" + STAMP + ".NET. " }, "created a domain realm");
  const idn = "rd-idn-" + STAMP;
  await ok(base + "/admin-api/realms/create", { id: idn,
    domain: "bücher-" + STAMP + ".example" }, "created an IDN realm");
  const plain = "rd-plain-" + STAMP;
  await ok(base + "/admin-api/realms/create", { id: plain },
           "created a realm with no domain");
  const listed = await realmRow(own);
  const home = listed.listing.defaultDomain;
  const rows = {};
  (listed.listing.realms || []).forEach(function (r) {
    rows[r.id] = r;
  });
  check("A. kept trimmed and in lower case, without the trailing dot",
        function () {
    assert.strictEqual(rows[own].domain, ownDomain);
  });
  check("A. an internationalised name is kept as its A-label", function () {
    assert.ok(/^xn--/.test(rows[idn].domain) &&
              rows[idn].domain.indexOf("bücher") < 0, rows[idn].domain);
  });
  check("B. a realm with no domain is <id>.<global.domain>, rooted at the " +
        "RFC 2247 mapping of it", function () {
    assert.ok(home, JSON.stringify(Object.keys(listed.listing)));
    assert.strictEqual(rows[plain].domain, plain + "." + home);
    assert.strictEqual(rows[plain].baseDn, "dc=" + plain + "," +
                       home.split(".").map(function (l) {
                         return "dc=" + l;
                       }).join(","));
  });
  check("B. a realm with its own domain is a TREE OF ITS OWN", function () {
    assert.strictEqual(rows[own].baseDn, "dc=craptastic-" + STAMP + ",dc=net");
  });

  const seeded = {};
  (await configRows(own)).forEach(function (s) {
    if (s.source === "realm") {
      seeded[s.key] = s.value;
    }
  });
  check("C. the SPIFFE trust domain IS the domain", function () {
    assert.strictEqual(seeded["spiffe.trustDomain"], ownDomain);
  });
  check("C. the Kerberos realm is the domain in capitals, and Kerberos is " +
        "still created OFF", function () {
    assert.strictEqual(seeded["krb5.realm"], ownDomain.toUpperCase());
    assert.strictEqual(String(seeded["krb5.enabled"]), "false");
  });
  check("C. no service principal and no SAML, WS-Trust or WS-Federation " +
        "name is seeded (#523)", function () {
    ["krb5.servicePrincipal", "saml2.entityId", "saml11.providerId",
     "wsfed.entityId", "wstrust.issuer", "saml.issuer"].forEach(function (k) {
      assert.ok(!(k in seeded), k + " was seeded: " +
                JSON.stringify(Object.keys(seeded)));
    });
  });
  check("C. the OpenID4VP client id keeps the id suffix it always had",
        function () {
    assert.ok(String(seeded["oid4vp.clientId"]).slice(-(own.length + 1)) ===
              "-" + own, String(seeded["oid4vp.clientId"]));
  });
  const chosen = "rd-chosen-" + STAMP;
  await ok(base + "/admin-api/realms/create", { id: chosen,
    domain: "chosen-" + STAMP + ".test",
    overrides: { "spiffe.trustDomain": "mine-" + STAMP + ".test" } },
    "created a realm with a trust domain of the caller's");
  const chosenRow = (await realmRow(chosen)).row;
  check("C. the caller's trust domain wins over the seeded one", function () {
    assert.strictEqual(settingOf(chosenRow, "spiffe.trustDomain"),
                       "mine-" + STAMP + ".test");
  });

  const before100 = await codeCount("STS-CORE-0100");
  const twin = await postJson(base + "/admin-api/realms/create",
    { id: "rd-twin-" + STAMP, domain: ownDomain.toUpperCase() });
  const asHome = await postJson(base + "/admin-api/realms/create",
    { id: "rd-home-" + STAMP, domain: home });
  check("D. a domain another realm has is refused, naming that realm",
        function () {
    assert.strictEqual(twin.status, 400, twin.raw.slice(0, 300));
    assert.ok(errorsOf(twin).indexOf("\"" + own + "\" realm's") >= 0,
              errorsOf(twin));
  });
  check("D. and so is the default realm's own (global.domain)", function () {
    assert.strictEqual(asHome.status, 400, asHome.raw.slice(0, 300));
    assert.ok(/"default" realm's \(global\.domain\)/.test(errorsOf(asHome)),
              errorsOf(asHome));
  });
  const saw100 = await sawCode("STS-CORE-0100", before100);
  const twinRow = (await realmRow("rd-twin-" + STAMP)).row;
  const homeRow = (await realmRow("rd-home-" + STAMP)).row;
  check("D. recorded STS-CORE-0100, and neither realm was made",
        function () {
    assert.ok(saw100, "no STS-CORE-0100 row was recorded");
    assert.strictEqual(twinRow, null);
    assert.strictEqual(homeRow, null);
  });
  const child = "rd-child-" + STAMP;
  const nested = await postJson(base + "/admin-api/realms/create",
    { id: child, domain: "dev." + ownDomain });
  check("D. ONE INSIDE ANOTHER'S IS ALLOWED", function () {
    assert.strictEqual(nested.status, 200, nested.raw.slice(0, 300));
  });

  const before101 = await codeCount("STS-CORE-0101");
  const moved = await postJson(base + "/admin-api/realms/update",
    { id: own, domain: "elsewhere-" + STAMP + ".net" });
  check("E. the domain is FIXED once the realm exists", function () {
    assert.strictEqual(moved.status, 400, moved.raw.slice(0, 300));
    assert.ok(/is fixed when the realm is created/.test(errorsOf(moved)),
              errorsOf(moved));
  });
  const saw101 = await sawCode("STS-CORE-0101", before101);
  const same = await postJson(base + "/admin-api/realms/update",
    { id: own, domain: ownDomain, name: "Renamed " + STAMP });
  const afterMove = (await realmRow(own)).row;
  check("E. recorded STS-CORE-0101; the domain is unchanged, and the same " +
        "domain again is no change while the rest of the update is saved",
        function () {
    assert.ok(saw101, "no STS-CORE-0101 row was recorded");
    assert.strictEqual(afterMove.domain, ownDomain);
    assert.strictEqual(same.status, 200, same.raw.slice(0, 300));
    assert.strictEqual(afterMove.name, "Renamed " + STAMP);
  });

  log.info("=== F. the directory over the LDAP socket (" + LDAP_URL + ") ===");
  const person = "rdp" + STAMP;
  const kid = "rdk" + STAMP;
  await ok(base + "/realm/" + own + "/admin-api/users/create",
           { username: person, invent: false,
             attributes: { cn: "Realm Rules", sn: "Rules" } },
           "created a person in " + own);
  await ok(base + "/realm/" + child + "/admin-api/users/create",
           { username: kid, invent: false,
             attributes: { cn: "Realm Kid", sn: "Kid" } },
           "created a person in " + child);
  const client = ldap.createClient({ url: LDAP_URL });
  client.on("error", function (e) {
    log.debug("Caught in the LDAP client: " + ((e && e.message) || e));
  });
  try {
    const ownBase = rows[own].baseDn;
    const childBase = "dc=dev," + ownBase;
    const dse = await ldapSearch(client, "", { scope: "base",
      filter: "(objectclass=*)", attributes: ["namingContexts"] });
    const contexts = attr(dse.entries[0], "namingContexts").map(function (v) {
      return String(v).toLowerCase();
    });
    check("F. each realm is a naming context of its own in the root DSE, " +
          "the nested one included", function () {
      [ownBase, childBase, rows[plain].baseDn].forEach(function (dn) {
        assert.ok(contexts.indexOf(dn.toLowerCase()) >= 0,
                  dn + " not in " + contexts.length + " contexts");
      });
    });
    const found = await ldapSearch(client, ownBase, { scope: "sub",
      filter: "(uid=" + person + ")" });
    check("F. a person is found under their own realm's base", function () {
      assert.strictEqual(found.error, null);
      assert.strictEqual(found.entries.length, 1);
      assert.strictEqual(String(found.entries[0].objectName).toLowerCase(),
                         ("uid=" + person + ",ou=users," + ownBase)
                           .toLowerCase());
    });
    // The development seed of a realm this job just created: its demo
    // people's addresses are invented in the AMBIENT realm's domain.
    const seededOwn = await ldapSearch(client, "uid=alice,ou=users," + ownBase,
      { scope: "base", filter: "(objectclass=*)", attributes: ["mail"] });
    const seededKid = await ldapSearch(client, "uid=alice,ou=users," +
      childBase, { scope: "base", filter: "(objectclass=*)",
                   attributes: ["mail"] });
    check("G. an invented mail address is in the realm's own domain, the " +
          "nested realm's in its own", function () {
      assert.deepStrictEqual(attr(seededOwn.entries[0], "mail"),
                             ["alice@" + ownDomain]);
      assert.deepStrictEqual(attr(seededKid.entries[0], "mail"),
                             ["alice@dev." + ownDomain]);
    });
    const fromParent = await ldapSearch(client, ownBase, { scope: "sub",
      filter: "(uid=" + kid + ")" });
    const fromChild = await ldapSearch(client, childBase, { scope: "sub",
      filter: "(uid=" + kid + ")" });
    check("F. a nested realm is a SEPARATE tree: its person is invisible " +
          "from the parent's base and found under its own", function () {
      assert.strictEqual(fromParent.entries.length, 0,
                         JSON.stringify(fromParent.entries).slice(0, 300));
      assert.strictEqual(fromChild.entries.length, 1);
    });
    const nowhere = await ldapSearch(client, "dc=nowhere-" + STAMP +
                                     ",dc=test",
                                     { scope: "sub", filter: "(uid=*)" });
    check("F. a DN in no realm's tree is answered noSuchObject", function () {
      assert.strictEqual(nowhere.error, "NoSuchObjectError");
    });
  } finally {
    client.unbind(function () {
      log.debug("Leaving the LDAP connection.");
    });
  }
  log.debug("Leaving theDomain().");
}

async function test() {
  log.debug("Entering test().");
  await theRealmLayer();
  await theDomain();
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_realm_rules FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
