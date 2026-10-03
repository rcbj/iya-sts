// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_gnap_delegation.js
//
// ---------------------------------------------------------------------------
// WHO MAY ACT FOR WHOM IN GNAP, OVER HTTP (#432 PHASE 1), in whichever mode the
// service is in.
//
// GNAP's two ways of obtaining a token about somebody else ask #186's
// delegation policy, and this job drives both against a running service:
//
//   I.   IMPERSONATION BY ASSERTION — a `gnapSkipInteraction` client presents
//        an ID Token this realm issued about a person. Without impersonation
//        in its `appDelegationSemantics`: product refuses (request_denied,
//        STS-GNAP-0772 on the audit) and development issues and records "WOULD
//        HAVE BEEN REFUSED". With it, and the resource server on its
//        `appAllowedToDelegateTo`: issued in both modes, the token the
//        person's with no `act`. The client acting as itself asks nothing.
//   II.  DERIVATION (RFC 9767 section 4) — a resource server with no
//        relationship to the downstream one: product refuses (0776),
//        development issues and records it. With `appAllowedToDelegateTo`:
//        issued, `act` naming the deriving resource server, and introspection
//        returning it. A wider derivation is refused in every mode (0513), and
//        so is one past `gnap.maxDerivationDepth` (0782).
//   III. THE REGISTER — each act a GNAP row on `GET /admin-api/delegation`,
//        filtered by type and protocol, refused acts as `refused` in product.
//
// The five formats' actor chain checked by code that is not the service's is
// `sts_gnap_rs.js` section 4b; the in-process half, with may_act, protected
// subjects and subject groups, is `tests/gnap_delegation.js`.
//
// Everything runs in a THROWAWAY TRUST REALM that is left behind.
//
// OWNED HERE (local: true): GNAP exists in this repository and nowhere else.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");
const gnap = require("./gnap_client.js");
const flowLib = require("./gnap_flow.js");
const registry = require("./sts_applications.js");

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
var log = bunyan.createLogger({ name: "sts_gnap_delegation",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const h = flowLib.harness({
  base: base,
  realm: usernameFor("gnapdeleg").replace(/[^a-z0-9-]/g, "").slice(0, 30),
  password: "gnap-deleg-Passw0rd!-" + String(Date.now()).slice(-6),
  log: log
});
const check = h.check;
const OWNER = usernameFor("gnap-deleg-owner");
const TYPE = "https://rs.gnap.test/photos";
let PRODUCT = false;

function claimsOf(value) {
  log.debug("Entering claimsOf().");
  log.debug("Leaving claimsOf().");
  return JSON.parse(Buffer.from(String(value).split(".")[1], "base64url")
                          .toString("utf8"));
}

function right(locations, actions) {
  log.debug("Entering right().");
  log.debug("Leaving right().");
  return { type: TYPE, actions: actions || ["read"], locations: locations };
}

// How many audit rows of this realm carry `code` — a code is recorded and
// never sent (sts_gnap_mtls.js's arrangement).
async function codeCount(code) {
  log.debug("Entering codeCount().");
  await new Promise(function (r) { setTimeout(r, 150); });
  const r = await h.apiGet(h.realmApi + "/audit?per=500&code=" +
                           encodeURIComponent(code));
  const body = r.body && typeof r.body === "object" ? r.body : {};
  const rows = body.rows || body.events || [];
  log.debug("Leaving codeCount().");
  return rows.length;
}

// A refusal as request_denied (RFC 9635 section 3.6) and as `code` on a new
// audit row of this realm.
async function refusedAs(code, what, fn) {
  log.debug("Entering refusedAs().");
  const before = await codeCount(code);
  const r = await fn();
  let after = before;
  for (let i = 0; i < 10 && after <= before; i += 1) {
    after = await codeCount(code);
  }
  check(what + " — request_denied, " + code, function () {
    h.refused(r, "request_denied", what);
    assert.strictEqual(r.status, 403, r.text);
    assert.ok(after > before, "no new audit row carries " + code + ": " +
              before + " before, " + after + " after");
  });
  log.debug("Leaving refusedAs().");
  return r;
}

async function newestAct(type) {
  log.debug("Entering newestAct().");
  const r = await h.apiGet(h.realmApi + "/delegation?protocol=GNAP&type=" +
                           encodeURIComponent(type));
  assert.strictEqual(r.status, 200, String(r.raw).slice(0, 300));
  log.debug("Leaving newestAct().");
  return (r.body.acts || [])[0] || null;
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving GNAP delegation at " + h.realmBase);
  PRODUCT = await registry.isProduct(base);
  log.info("The service is in " + (PRODUCT ? "product" : "development") +
           " mode.");
  await h.createRealm("GNAP delegation");
  await h.setting("gnap.continueWaitS", 0);
  await h.ensurePerson(OWNER);
  const ownerSubject = await h.subjectOf(OWNER);

  // =========================================================================
  // 0. THREE RESOURCE SERVERS AND TWO TRUSTED CLIENTS.
  // =========================================================================
  log.info("=== 0. the parties ===");
  const id = function (name) {
    log.debug("Entering id().");
    log.debug("Leaving id().");
    return name + "-" + h.realm;
  };
  const RS = { a: "https://rs-a.deleg.test/api",
               b: "https://rs-b.deleg.test/api",
               c: "https://rs-c.deleg.test/api" };
  const A = id("gd-rs-a");
  const B = id("gd-rs-b");
  const C = id("gd-rs-c");
  const PLAIN = id("gd-plain");
  const IMP = id("gd-imp");
  const keys = {};
  const register = async function (identifier, kind, fields) {
    log.debug("Entering register().");
    keys[identifier] = new gnap.Client({ key: gnap.newKey("ES256") });
    await h.ok(h.realmApi + "/applications/create", {
      identifier: identifier, kind: kind, protocols: ["gnap"],
      fields: Object.assign({ gnapKey: JSON.stringify(
        keys[identifier].keyObject()) }, fields) },
               "registered " + identifier);
    log.debug("Leaving register().");
  };
  await register(B, "gnap-resource-server", { gnapResourceServerUri: RS.b });
  await register(C, "gnap-resource-server", { gnapResourceServerUri: RS.c });
  // TYPE is CATALOGUED (#432 phase 4) — product mode refuses a type nobody
  // declares — owned by A and answering at B's and C's addresses, so every
  // right below keeps the targets its locations name.
  await register(A, "gnap-resource-server",
                 { gnapResourceServerUri: RS.a,
                   appAllowedToDelegateTo: [B],
                   oauthAuthorizationDetailsType: [JSON.stringify({
                     type: TYPE, locations: [RS.b, RS.c] })] });
  await register(PLAIN, "gnap-client", { gnapSkipInteraction: "TRUE" });
  await register(IMP, "gnap-client",
                 { gnapSkipInteraction: "TRUE",
                   appDelegationSemantics: ["impersonation"],
                   appAllowedToDelegateTo: [A, B, C] });

  // An ID Token this realm issued about the owner, from an ordinary grant.
  const relying = new gnap.Client({ key: gnap.newKey("ES256") });
  const signedIn = await h.redirectGrant(relying, OWNER, {
    subject: { assertion_formats: ["id_token"] } });
  const assertion = ((signedIn.released.subject || {}).assertions || [])
    .filter(function (one) { return one.format === "id_token"; })[0];
  check("an ID Token about the owner, from an ordinary grant", function () {
    assert.ok(assertion && assertion.value,
              JSON.stringify(signedIn.released));
  });
  const impersonate = function (who, access) {
    log.debug("Entering impersonate().");
    log.debug("Leaving impersonate().");
    return keys[who].send("POST", h.GRANT, { json: {
      client: { key: keys[who].keyObject() },
      access_token: { access: access },
      user: { assertions: [{ format: "id_token",
                             value: assertion.value }] } } });
  };

  // =========================================================================
  // I. IMPERSONATION BY ASSERTION.
  // =========================================================================
  log.info("=== I. impersonation by assertion ===");
  let r;
  let act;
  if (PRODUCT) {
    r = await refusedAs("STS-GNAP-0772", "I1. product: a trusted client " +
      "whose semantics do not include impersonation is refused the person's " +
      "token", function () {
      log.debug("Entering the I1 request.");
      log.debug("Leaving the I1 request.");
      return impersonate(PLAIN, [right([RS.a])]);
    });
    act = await newestAct("gnap-impersonation");
    check("I2. …and the act is a REFUSED GNAP impersonation", function () {
      assert.ok(act, "no act");
      assert.strictEqual(act.outcome, "refused", JSON.stringify(act));
      assert.strictEqual(act.intermediary.application, PLAIN);
      assert.strictEqual(act.target.application, A);
    });
  } else {
    r = await impersonate(PLAIN, [right([RS.a])]);
    act = await newestAct("gnap-impersonation");
    check("I1. development: the token is issued, and the act says it WOULD " +
          "HAVE BEEN REFUSED", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.ok(r.json.access_token, r.text);
      assert.strictEqual(act.outcome, "issued", JSON.stringify(act));
      assert.ok(/WOULD HAVE BEEN REFUSED/.test(act.authorizedBy),
                act.authorizedBy);
    });
  }
  r = await impersonate(IMP, [right([RS.a, RS.b, RS.c])]);
  const original = r.json && r.json.access_token
    ? r.json.access_token.value : "";
  check("I3. impersonation in the client's semantics and R on its " +
        "appAllowedToDelegateTo: issued in either mode, the token the " +
        "owner's and naming no actor", function () {
    assert.strictEqual(r.status, 200, r.text);
    const claims = claimsOf(original);
    assert.strictEqual(claims.sub, ownerSubject);
    assert.strictEqual(claims.act, undefined, JSON.stringify(claims));
  });
  act = await newestAct("gnap-impersonation");
  check("I4. …recorded as an issued act, one row per resource server",
        function () {
    assert.strictEqual(act.outcome, "issued", JSON.stringify(act));
    assert.ok(/allowed impersonation/.test(act.authorizedBy),
              act.authorizedBy);
    assert.strictEqual(act.produced.length, 1);
  });
  r = await keys[PLAIN].send("POST", h.GRANT, { json: {
    client: { key: keys[PLAIN].keyObject() },
    access_token: { access: ["gd-read"] } } });
  check("I5. the client acting as itself asks nothing and its token names " +
        "nobody", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.ok(!r.json.subject, r.text);
    assert.strictEqual(claimsOf(r.json.access_token.value).sub, undefined);
  });

  // =========================================================================
  // II. DERIVATION.
  // =========================================================================
  log.info("=== II. derivation ===");
  const derive = function (who, existing, access) {
    log.debug("Entering derive().");
    log.debug("Leaving derive().");
    return keys[who].send("POST", h.GRANT, { json: {
      client: { key: keys[who].keyObject() },
      existing_access_token: existing,
      access_token: { access: access } } });
  };
  if (PRODUCT) {
    await refusedAs("STS-GNAP-0776", "II1. product: C derives for B with no " +
      "relationship", function () {
      log.debug("Entering the II1 request.");
      log.debug("Leaving the II1 request.");
      return derive(C, original, [right([RS.b])]);
    });
    act = await newestAct("gnap-derivation");
    check("II2. …a REFUSED derivation row", function () {
      assert.strictEqual(act.outcome, "refused", JSON.stringify(act));
      assert.strictEqual(act.intermediary.application, C);
      assert.strictEqual(act.target.application, B);
    });
  } else {
    r = await derive(C, original, [right([RS.b])]);
    act = await newestAct("gnap-derivation");
    check("II1. development: C derives for B with no relationship, issued " +
          "and recorded as would have been refused", function () {
      assert.strictEqual(r.status, 200, r.text);
      assert.ok(/WOULD HAVE BEEN REFUSED/.test(act.authorizedBy),
                act.authorizedBy);
    });
  }
  r = await derive(A, original, [right([RS.b])]);
  const derived = r.json && r.json.access_token
    ? r.json.access_token.value : "";
  check("II3. A derives for B (A's appAllowedToDelegateTo names B): about " +
        "the owner, for B, act naming A", function () {
    assert.strictEqual(r.status, 200, r.text);
    const claims = claimsOf(derived);
    assert.strictEqual(claims.sub, ownerSubject);
    assert.strictEqual(claims.aud, B);
    assert.deepStrictEqual(claims.act, { sub: A });
  });
  r = await keys[B].send("POST", h.realmBase + "/gnap/introspect", { json: {
    access_token: derived, resource_server: { key: keys[B].keyObject() } } });
  check("II4. introspection by B returns the chain", function () {
    assert.strictEqual(r.json.active, true, r.text);
    assert.deepStrictEqual(r.json.act, { sub: A });
  });
  act = await newestAct("gnap-derivation");
  check("II5. …an issued derivation row naming the token it produced",
        function () {
    assert.strictEqual(act.outcome, "issued", JSON.stringify(act));
    assert.strictEqual(act.intermediary.application, A);
    assert.strictEqual(act.produced.length, 1);
  });
  await refusedAs("STS-GNAP-0513", "II6. a derivation asking for more than " +
    "the original carries, in every mode", function () {
    log.debug("Entering the II6 request.");
    log.debug("Leaving the II6 request.");
    return derive(A, original, [right([RS.b], ["read", "write"])]);
  });
  await h.setting("gnap.maxDerivationDepth", 1);
  await refusedAs("STS-GNAP-0782", "II7. with gnap.maxDerivationDepth 1, a " +
    "derivation from a derived token, in every mode", function () {
    log.debug("Entering the II7 request.");
    log.debug("Leaving the II7 request.");
    return derive(B, derived, [right([RS.b])]);
  });
  await h.setting("gnap.maxDerivationDepth", 2);
  r = await derive(B, derived, [right([RS.b])]);
  check("II8. at depth 2, B narrowing for itself: the chain nests, B over A",
        function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(claimsOf(r.json.access_token.value).act,
                           { sub: B, act: { sub: A } });
  });

  // =========================================================================
  // III. THE REGISTER.
  // =========================================================================
  log.info("=== III. the register ===");
  r = await h.apiGet(h.realmApi + "/delegation?protocol=GNAP");
  check("III1. GET /admin-api/delegation lists the GNAP acts of both kinds",
        function () {
    assert.strictEqual(r.status, 200, String(r.raw).slice(0, 300));
    const types = (r.body.acts || []).map(function (one) { return one.type; });
    assert.ok(types.indexOf("gnap-impersonation") >= 0, types.join(","));
    assert.ok(types.indexOf("gnap-derivation") >= 0, types.join(","));
    (r.body.acts || []).forEach(function (one) {
      assert.strictEqual(one.protocol, "GNAP");
    });
  });
  if (PRODUCT) {
    r = await h.apiGet(h.realmApi + "/delegation?protocol=GNAP&outcome=" +
                       "refused");
    check("III2. product's refusals are REFUSED acts", function () {
      assert.ok(Number(r.body.matched) >= 2, JSON.stringify(r.body.byOutcome));
    });
  }

  log.info(h.checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_gnap_delegation")
  .description("GNAP impersonation by user assertion and RFC 9767 " +
    "derivation under the delegation policy, in whichever mode the service " +
    "is in, and their acts on the delegation register.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
