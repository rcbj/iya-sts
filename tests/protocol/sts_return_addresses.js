// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_return_addresses.js
//
// ---------------------------------------------------------------------------
// A RETURN ADDRESS DEVELOPMENT LEARNT IS NOT ONE PRODUCT BELIEVES, OVER THE
// WIRE, WITH ITS CODES.
//
// D12 (#444): carries over `tests/return_address_provenance.js`. The two
// operations themselves are driven by `sts_admin_api_operations.js` (by their
// sentences); what is held here, in a throwaway realm of this job's own that
// it switches between the two modes through the ROOT API's `realms/set`, is
// the rest of that file's claims, each by what a client sees and the code
// read back off the realm's audit log:
//
//   A. a development sighting (SAML 1.1's inter-site transfer service, which
//      records a `shire` before it needs a session) that ADDS an address
//      marks it observed — held and still trusted in development — and one
//      that repeats a REGISTERED address does not demote it; the mark is
//      DERIVED, so no write may assert one;
//   B. in product the marked address is refused (400, a sentence saying it
//      was learnt in development and how to confirm it, STS-REG-0049), the
//      registered one is still delivered to, and the drill-down says product
//      does not trust it; an entry holding ONLY an observed address refuses
//      a request naming none with STS-REG-0049 too;
//   C. confirm: an unmarked address refused (STS-REG-0050), an attribute
//      that is not a return address — OBSERVED refused at the API's door by
//      its closed request schema (STS-API-0009) before the registry's
//      STS-REG-0051 is reached, which is in-process only — and no address
//      (STS-REG-0052); a confirm takes the mark off and keeps the address,
//      product then delivers to it, and a second confirm is refused;
//   D. discard takes both off, and product then refuses the address as one
//      that is not on the entry, not as an observed one;
//   E. an explicit `add` is a registration (no mark), and `remove` takes a
//      mark with its value.
//
// NOT carried: F (the console's own client learning a callback from a Host
// header) — the console is a static public client since #446 and the
// relying party that learnt one is the embedded debugger, whose listener no
// test stack binds; G (every check ASKS the one function) is a statement
// about the source, class (d).
//
// OWNED HERE (local: true): this repository's own management API.
// ---------------------------------------------------------------------------

const assert = require("assert");
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
var log = bunyan.createLogger({ name: "sts_return_addresses",
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
const REALM = "rap-" + STAMP;
const RB = base + "/realm/" + REALM;
const ACS = "samlAssertionConsumerService";
const RP = "urn:test:" + REALM + ":rp";
const ONLY = "urn:test:" + REALM + ":only";
const REGISTERED = "https://registered.rap-" + STAMP + ".test/acs";
const LEARNT = "https://learnt.rap-" + STAMP + ".test/acs";
const SECOND = "https://second.rap-" + STAMP + ".test/acs";
const ADDED = "https://added.rap-" + STAMP + ".test/acs";
const FOURTH = "https://fourth.rap-" + STAMP + ".test/acs";
const NEVER = "https://never.rap-" + STAMP + ".test/acs";

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

function textOf(raw) {
  log.debug("Entering textOf().");
  log.debug("Leaving textOf().");
  return String(raw || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
}

// A SAML 1.1 sighting: one POST to the inter-site transfer service, which
// records the shire before it needs a session.
function sight(providerId, shire) {
  log.debug("Entering sight().");
  const form = { providerId: providerId,
                 TARGET: "https://app.rap-" + STAMP + ".test/" };
  if (shire) {
    form.shire = shire;
  }
  log.debug("Leaving sight().");
  return send(RB + "/saml11/sso", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString() });
}

async function entry(identifier) {
  log.debug("Entering entry().");
  const r = await send(RB + "/admin-api/applications?application=" +
                       encodeURIComponent(identifier));
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  const e = r.body.application || r.body.entry || r.body;
  log.debug("Leaving entry().");
  return e;
}

function acsOf(e) {
  log.debug("Entering acsOf().");
  log.debug("Leaving acsOf().");
  return [].concat(((e && e.fields) || {})[ACS] || []);
}

function observedOf(e, value) {
  log.debug("Entering observedOf().");
  log.debug("Leaving observedOf().");
  return ((e && e.returnAddressesObserved) || []).filter(function (row) {
    return row.value === value;
  })[0] || null;
}

async function mode(value) {
  log.debug("Entering mode(). " + value);
  if (value === "product") {
    await ok(base + "/admin-api/realms/set", { id: REALM, key: "global.mode",
      value: "product" }, "put the realm in product mode");
  } else {
    await ok(base + "/admin-api/realms/unset", { id: REALM,
      key: "global.mode" }, "put the realm back in development mode");
  }
  // Wait until the realm answers in that mode: a shire nobody ever
  // registered is refused in product and accepted in development.
  for (let i = 0; i < 60; i += 1) {
    const probe = await sight(RP, NEVER);
    if ((value === "product") === (probe.status === 400)) {
      break;
    }
    await sleep(250);
  }
  log.debug("Leaving mode().");
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(RB + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
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

async function refusedWith(path, payload, code, what) {
  log.debug("Entering refusedWith(). " + code);
  const before = await codeCount(code);
  const r = await postJson(RB + "/admin-api" + path, payload);
  const saw = await sawCode(code, before);
  check(what + " (" + code + ")", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.body && r.body.ok === false, r.raw.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "a code was sent");
    assert.ok(saw, "no " + code + " row was recorded");
  });
  log.debug("Leaving refusedWith().");
  return r;
}

async function test() {
  log.debug("Entering test().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Return addresses " + STAMP },
    "created the realm");
  await ok(RB + "/admin-api/applications/create", { identifier: RP, name: RP,
    protocols: ["saml11"],
    fields: { samlEntityId: [RP], samlAssertionConsumerService: [REGISTERED] }
  }, "registered the relying party with one assertion consumer");
  await ok(RB + "/admin-api/applications/create", { identifier: ONLY,
    name: ONLY, protocols: ["saml11"], fields: { samlEntityId: [ONLY] } },
    "registered a relying party with none");

  log.info("=== A. a development sighting marks what it ADDS ===");
  const fresh = await entry(RP);
  check("A. an address given at CREATE is registered and carries no mark",
        function () {
    assert.deepStrictEqual(fresh.returnAddressesObserved || [], []);
  });
  const learnt = await sight(RP, LEARNT);
  const again = await sight(RP, REGISTERED);
  await sight(ONLY, LEARNT);
  const seen = await entry(RP);
  check("A. development accepts the shire a request named and writes it on " +
        "the entry", function () {
    assert.ok(learnt.status < 400, learnt.status + " " +
              textOf(learnt.raw).slice(0, 200));
    assert.ok(acsOf(seen).indexOf(LEARNT) >= 0, JSON.stringify(acsOf(seen)));
  });
  check("A. AND MARKS IT observed — held, and still trusted in development",
        function () {
    const row = observedOf(seen, LEARNT);
    assert.ok(row, JSON.stringify(seen.returnAddressesObserved));
    assert.strictEqual(row.attribute, ACS);
    assert.strictEqual(row.held, true);
    assert.strictEqual(row.trusted, true);
  });
  check("A. a sighting that repeats a REGISTERED address does not demote it",
        function () {
    assert.ok(again.status < 400, String(again.status));
    assert.strictEqual(observedOf(seen, REGISTERED), null);
  });
  const forged = await postJson(RB + "/admin-api/applications/add",
    { application: RP, attribute: "appReturnAddressObserved",
      value: ACS + " " + NEVER });
  check("A. the mark is DERIVED: a write may not assert one", function () {
    assert.strictEqual(forged.status, 400, forged.raw.slice(0, 300));
  });

  log.info("=== B. product withholds a marked address ===");
  const before49 = await codeCount("STS-REG-0049");
  await mode("product");
  const refused = await sight(RP, LEARNT);
  const delivered = await sight(RP, REGISTERED);
  const onlyNone = await sight(ONLY, "");
  const inProduct = await entry(RP);
  await mode("development");
  check("B. product REFUSES the observed address, saying it was learnt in " +
        "development and how to confirm it", function () {
    assert.strictEqual(refused.status, 400, String(refused.status));
    assert.ok(/nobody has confirmed it/.test(textOf(refused.raw)) &&
              /confirm-address/.test(textOf(refused.raw)),
              textOf(refused.raw).slice(0, 400));
  });
  check("B. while the registered address is still delivered to", function () {
    assert.ok(delivered.status < 400, delivered.status + " " +
              textOf(delivered.raw).slice(0, 200));
  });
  check("B. an entry holding ONLY an observed address refuses a request " +
        "naming none with the way to confirm it, not 'nothing registered'",
        function () {
    assert.strictEqual(onlyNone.status, 400, String(onlyNone.status));
    assert.ok(/confirm-address/.test(textOf(onlyNone.raw)),
              textOf(onlyNone.raw).slice(0, 400));
  });
  check("B. and the drill-down says product does not trust it", function () {
    const row = observedOf(inProduct, LEARNT);
    assert.ok(row, JSON.stringify(inProduct.returnAddressesObserved));
    assert.strictEqual(row.trusted, false);
  });
  const saw49 = await sawCode("STS-REG-0049", before49);
  const count49 = await codeCount("STS-REG-0049");
  check("B. both refusals recorded STS-REG-0049, and no code was sent",
        function () {
    assert.ok(saw49 && count49 - before49 >= 2, before49 + " -> " + count49);
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(refused.raw + onlyNone.raw));
  });

  log.info("=== C. confirm ===");
  await refusedWith("/applications/confirm-address", { application: RP,
    attribute: ACS, value: REGISTERED }, "STS-REG-0050",
    "C. confirming an address that is NOT marked is refused by name");
  // Observed: the API's request schema names the four return-address
  // attributes as a closed set, so this is refused at the door with
  // STS-API-0009 before the registry's own STS-REG-0051 can be reached;
  // the registry's code is reachable in process only.
  const notReturn = await refusedWith("/applications/confirm-address",
    { application: RP, attribute: "oauthPostLogoutRedirectUri",
      value: LEARNT }, "STS-API-0009",
    "C. an attribute that is not a return address is refused at the door");
  check("C. naming the four return-address attributes it accepts",
        function () {
    assert.ok(/not one of the 4 values it accepts/.test(
      (notReturn.body.errors || []).join(" ")), notReturn.raw.slice(0, 300));
  });
  await refusedWith("/applications/confirm-address", { application: RP,
    attribute: ACS }, "STS-REG-0052",
    "C. a confirm naming no address is refused");
  await ok(RB + "/admin-api/applications/confirm-address", { application: RP,
    attribute: ACS, value: LEARNT }, "confirmed the learnt address");
  const confirmed = await entry(RP);
  check("C. the MARK is gone and the ADDRESS stays", function () {
    assert.strictEqual(observedOf(confirmed, LEARNT), null);
    assert.ok(acsOf(confirmed).indexOf(LEARNT) >= 0);
  });
  await mode("product");
  const believed = await sight(RP, LEARNT);
  await mode("development");
  check("C. and product delivers to it now", function () {
    assert.ok(believed.status < 400, believed.status + " " +
              textOf(believed.raw).slice(0, 200));
  });
  await refusedWith("/applications/confirm-address", { application: RP,
    attribute: ACS, value: LEARNT }, "STS-REG-0050",
    "C. a second confirm is refused, not silently repeated");

  log.info("=== D. discard ===");
  await sight(RP, SECOND);
  const second = await entry(RP);
  check("D. a second sighting is marked", function () {
    assert.ok(observedOf(second, SECOND), JSON.stringify(
      second.returnAddressesObserved));
  });
  await ok(RB + "/admin-api/applications/discard-address", { application: RP,
    attribute: ACS, value: SECOND }, "discarded the second address");
  const discarded = await entry(RP);
  check("D. BOTH the mark and the address are gone", function () {
    assert.strictEqual(observedOf(discarded, SECOND), null);
    assert.ok(acsOf(discarded).indexOf(SECOND) < 0);
  });
  await mode("product");
  const gone = await sight(RP, SECOND);
  await mode("development");
  check("D. product refuses it as an address that is not on the entry, not " +
        "as an observed one", function () {
    assert.strictEqual(gone.status, 400, String(gone.status));
    assert.ok(!/nobody has confirmed it/.test(textOf(gone.raw)),
              textOf(gone.raw).slice(0, 300));
  });

  log.info("=== E. add and remove ===");
  await ok(RB + "/admin-api/applications/add", { application: RP,
    attribute: ACS, value: ADDED }, "added an address by hand");
  await sight(RP, FOURTH);
  const added = await entry(RP);
  check("E. an explicit add is a registration and carries no mark",
        function () {
    assert.ok(acsOf(added).indexOf(ADDED) >= 0);
    assert.strictEqual(observedOf(added, ADDED), null);
    assert.ok(observedOf(added, FOURTH), "the control sighting was not " +
              "marked");
  });
  await ok(RB + "/admin-api/applications/remove", { application: RP,
    attribute: ACS, value: FOURTH }, "removed the sighted address");
  const removed = await entry(RP);
  check("E. a remove takes the mark with the value", function () {
    assert.ok(acsOf(removed).indexOf(FOURTH) < 0);
    assert.strictEqual(observedOf(removed, FOURTH), null);
  });

  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_return_addresses FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
