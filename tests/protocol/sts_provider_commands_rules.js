// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_provider_commands_rules.js
//
// ---------------------------------------------------------------------------
// OPENID PROVIDER COMMANDS 1.0: THE COMMAND TOKEN, WHAT A RELYING PARTY'S
// ANSWERS ARE KEPT AS, AND WHICH CHANGES SEND WHICH COMMAND — OVER THE WIRE.
//
// D12 (#444): carries over the part of `tests/provider_commands.js` (#151)
// that `sts_provider_commands.js` (the test peer's relying party) does not
// hold. This job runs a relying party of its OWN — an https listener
// answering each command from a script — so the token it receives and the
// answers it gives are the job's to choose. In a throwaway DEVELOPMENT
// realm (product mode dials no internal address):
//
//   1. THE COMMAND TOKEN (section 5), read off a metadata command: typ
//      command+jwt, aud and client_id the client, tenant the realm, iss the
//      realm's issuer, metadata naming the realm's callback endpoint, a
//      callback_token, no sub and no nonce, at most two minutes long.
//   2. WHAT IS KEPT OF THE METADATA ANSWER: the commands it supports, and
//      its roles as section 2.2 defines one — strays, strings, numbers,
//      nulls and id-less or non-string ids left out, a bare id given itself
//      as its display.
//   3. AN ACCOUNT COMMAND: activate sends sub and the account's claims; the
//      aud_sub the relying party answers is learned and sent back on the
//      next command; in a tenant run's stream, a last_access that is a time
//      is reported and one that is not is left out of the row.
//   4. A DEAD LETTER RETRIED BY HAND: incompatible_state (409) is a dead
//      delivery; `POST /admin-api/commands/retry-delivery` queues it again as
//      a new generation, which lands.
//   5. AUTOMATIC COMMANDS: a profile change is `maintain`, a role the
//      person holds moving is `maintain`, and a disable — `suspend`, a
//      command this relying party did not list — sends nothing.
//   6. THE ACTS: an unknown action names the three; a client with no
//      command_endpoint is refused.
//   7. REGISTRATION: a command_endpoint with a fragment is refused, one with
//      a query is not.
//
// NOT carried, and why: the sweep's retry of a 503 on a test clock and the
// tenant run resumed with Last-Event-ID (already `sts_provider_commands.js`
// sections 5 and 6); a sign-in's bookkeeping (pwdFailureTime) sending
// nothing — written only by a refused LDAP bind's own counter, which no
// /admin-api door writes (class (d)); 9c–9h, the response models held to
// rows a v1.0.0 build persisted and the SCIM clients' door (store fixtures,
// class (d)); 10, a persisted token row's client_id (store internals,
// class (d)).
//
// THE RELYING PARTY runs on CIBA_NOTIFY_HOST, GNAP_PUSH_HOST or
// OUTBOUND_TEST_HOST (the name the service reaches this runner by), with a
// self-signed certificate the development realm is told not to verify
// (`federation.outboundSkipTlsVerification`, development only).
//
// OWNED HERE (local: true): this repository's own provider and API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const testCa = require("./outbound_test_ca.js");

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
var log = bunyan.createLogger({ name: "sts_provider_commands_rules",
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
const REALM = "pcr-" + STAMP;
const RB = base + "/realm/" + REALM;
const API = RB + "/admin-api";
const HOST = process.env.CIBA_NOTIFY_HOST || process.env.GNAP_PUSH_HOST ||
             process.env.OUTBOUND_TEST_HOST || "localhost";
const PERSON = "pcr-alice-" + STAMP;
const PASSWORD = "Pcr-" + nodeCrypto.randomBytes(9).toString("base64url") +
  "-Aa1!";
const APP = "pcr-app";
// `suspend` is left out on purpose: section 5c disables the person, and a
// relying party is sent only the commands it said it supports.
const SUPPORTED = ["metadata", "activate", "maintain", "audit",
                   "audit_tenant"];
const FLOOR = 15;

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

function decode(jwt) {
  log.debug("Entering decode().");
  const parts = String(jwt).split(".");
  log.debug("Leaving decode().");
  return { header: JSON.parse(Buffer.from(parts[0], "base64url")
             .toString("utf8")),
           claims: JSON.parse(Buffer.from(parts[1], "base64url")
             .toString("utf8")) };
}

async function call(method, url, body) {
  log.debug("Entering call(). " + method + " " + url);
  const r = await fetch(url, { method: method, redirect: "manual",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    // Not JSON; `text` carries it.
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json };
}

async function ok(url, payload, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, payload);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function setting(key, value) {
  log.debug("Entering setting(). " + key);
  log.debug("Leaving setting().");
  return ok(base + "/admin-api/realms/set", { id: REALM, key: key,
    value: String(value) }, "set " + key);
}

// THE RELYING PARTY: every command recorded with its decoded token; each
// answer taken from the front of `answers` (a 200 `{}` when it is empty).
async function relyingParty() {
  log.debug("Entering relyingParty().");
  const credential = await testCa.selfSignedCertificate(HOST);
  const state = { received: [], answers: [] };
  const server = https.createServer({ key: credential.key,
                                      cert: credential.cert },
    function (req, res) {
      let text = "";
      req.on("data", function (c) {
        text += c;
      });
      req.on("end", function () {
        const token = new URLSearchParams(text).get("command_token");
        let decoded = null;
        try {
          decoded = token ? decode(token) : null;
        } catch (e) {
          log.debug("Caught in relyingParty(): " + ((e && e.message) || e));
          // Kept as null; the check that reads it says so.
          decoded = null;
        }
        state.received.push({ path: req.url, token: token,
                              decoded: decoded });
        const next = state.answers.shift() || { status: 200,
          body: { sub: "$sub", account_state: "active" } };
        // "$sub" is the sub the command named: an account answer must name
        // the same one (section 7.2).
        const body = Object.assign({}, next.body);
        if (body.sub === "$sub") {
          body.sub = decoded && decoded.claims.sub;
        }
        if (next.stream) {
          // A streaming tenant command's answer (section 8): Server-Sent
          // Events, one `account-state` per account, then the end.
          res.writeHead(200, { "content-type": "text/event-stream" });
          res.end(next.stream.map(function (one, i) {
            return "id: " + (i + 1) + "\nevent: " + one.event + "\ndata: " +
              JSON.stringify(one.data) + "\n\n";
          }).join(""));
          return;
        }
        res.writeHead(next.status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      });
    });
  log.debug("Leaving relyingParty().");
  return new Promise(function (resolve) {
    server.listen(Number(process.env.PCR_LISTENER_PORT || 0), "0.0.0.0",
                  function () {
      state.server = server;
      state.endpoint = "https://" + HOST + ":" + server.address().port +
        "/commands";
      resolve(state);
    });
  });
}

async function report() {
  log.debug("Entering report().");
  const r = await call("GET", API + "/commands");
  log.debug("Leaving report().");
  return r.json || {};
}

async function waitFor(what, until) {
  log.debug("Entering waitFor(). " + what);
  let last = null;
  for (let i = 0; i < 60; i += 1) {
    last = await report();
    if (until(last)) {
      log.debug("Leaving waitFor().");
      return last;
    }
    await sleep(250);
  }
  log.debug("Leaving waitFor(). Gave up.");
  throw new Error("waited for " + what + ": " +
                  JSON.stringify(last).slice(0, 1200));
}

async function received(rp, count) {
  log.debug("Entering received(). " + count);
  for (let i = 0; i < 60 && rp.received.length < count; i += 1) {
    await sleep(250);
  }
  log.debug("Leaving received(). " + rp.received.length);
  return rp.received;
}

function accountRow(r) {
  log.debug("Entering accountRow().");
  log.debug("Leaving accountRow().");
  return (r.accounts || []).filter(function (a) {
    return a.clientId === APP && a.username === PERSON;
  })[0];
}

async function tokenSection(rp) {
  log.debug("Entering tokenSection().");
  log.info("=== 1, 2. the metadata command ===");
  rp.answers.push({ status: 200, body: {
    context: { iss: RB, tenant: REALM }, commands_supported: SUPPORTED,
    command_endpoint: rp.endpoint, client_id: APP,
    roles: [{ id: "reader", display: "Reader" },
            { id: "editor", display: "Editor", description: "Changes things",
              stray: { nested: true } },
            { id: "bare" }, "a string", 7, null, { display: "no id" },
            { id: { not: "a string" }, display: "odd id" }] } });
  await ok(API + "/commands/send-tenant", { clientId: APP,
                                            command: "metadata" },
           "sent metadata");
  const got = await received(rp, 1);
  const m = got[0] && got[0].decoded;
  check("1. section 5: typ command+jwt, the baseline claims, metadata with " +
        "the realm's callback endpoint, no sub and no nonce", function () {
    assert.ok(m, JSON.stringify(got).slice(0, 300));
    assert.strictEqual(m.header.typ, "command+jwt");
    assert.strictEqual(m.claims.command, "metadata");
    assert.strictEqual(m.claims.aud, APP);
    assert.strictEqual(m.claims.client_id, APP);
    assert.strictEqual(m.claims.iss, RB);
    assert.ok(m.claims.metadata, JSON.stringify(m.claims));
    assert.strictEqual(m.claims.metadata.callback_endpoint,
                       RB + "/oauth2/commands/callback");
    assert.ok(m.claims.callback_token);
    assert.strictEqual(m.claims.sub, undefined);
    assert.strictEqual(m.claims.nonce, undefined);
    assert.ok(m.claims.exp - m.claims.iat <= 120);
  });
  const learned = await waitFor("metadata learned", function (r) {
    return (r.clients || []).some(function (c) {
      return c.clientId === APP && c.learned;
    });
  });
  const row = learned.clients.filter(function (c) {
    return c.clientId === APP;
  })[0];
  check("2. what the relying party supports is recorded", function () {
    assert.deepStrictEqual(row.learned.commandsSupported.slice().sort(),
                           SUPPORTED.slice().sort());
  });
  check("2. a role is kept as section 2.2 defines one, and nothing else is",
        function () {
    assert.deepStrictEqual(row.learned.roles, [
      { id: "reader", display: "Reader" },
      { id: "editor", display: "Editor", description: "Changes things" },
      { id: "bare", display: "bare" }
    ]);
  });
  log.debug("Leaving tokenSection().");
}

async function accountSection(rp) {
  log.debug("Entering accountSection().");
  log.info("=== 3. an account command ===");
  const before = rp.received.length;
  rp.answers.push({ status: 200, body: { sub: "$sub",
                                         account_state: "active",
                                         aud_sub: "rp-7" } });
  await ok(API + "/commands/send-account", { clientId: APP,
    username: PERSON, command: "activate" }, "sent activate");
  let got = await received(rp, before + 1);
  const a = got[before].decoded.claims;
  check("3a. activate sends sub and the account's claims, and no metadata",
        function () {
    assert.strictEqual(a.command, "activate");
    assert.ok(/^\S+$/.test(String(a.sub)), JSON.stringify(a));
    assert.strictEqual(a.email, PERSON + "@suite.example.test");
    assert.strictEqual(a.metadata, undefined);
  });
  const first = await waitFor("the account row", function (r) {
    return !!accountRow(r);
  });
  check("3b. the state answered is recorded", function () {
    assert.strictEqual(accountRow(first).state, "active",
                       JSON.stringify(accountRow(first)));
  });
  rp.answers.push({ status: 200, body: { sub: "$sub",
                                         account_state: "active" } });
  await ok(API + "/commands/send-account", { clientId: APP,
    username: PERSON, command: "audit" }, "sent audit");
  got = await received(rp, before + 2);
  check("3c. the learned aud_sub is sent back on the next command",
        function () {
    assert.strictEqual(got[before + 1].decoded.claims.aud_sub, "rp-7",
                       JSON.stringify(got[before + 1].decoded.claims));
  });
  log.info("--- a tenant run's last_access (section 8) ---");
  rp.answers.push({ stream: [
    { event: "account-state", data: { sub: a.sub, account_state: "active",
                                      last_access: 1700000000 } },
    { event: "account-state", data: { sub: "someone-else-" + STAMP,
                                      account_state: "active",
                                      last_access: { at: 1 } } },
    { event: "command-complete", data: { total_accounts: 2 } }] });
  await ok(API + "/commands/send-tenant", { clientId: APP,
    command: "audit_tenant" }, "started a tenant run");
  const streamed = await waitFor("the tenant run's rows", function (r) {
    return (r.accounts || []).some(function (row) {
      return row.sub === "someone-else-" + STAMP;
    }) && accountRow(r) && "lastAccess" in accountRow(r);
  });
  const stranger = streamed.accounts.filter(function (row) {
    return row.sub === "someone-else-" + STAMP;
  })[0];
  check("3d. a stream's last_access that is a time (a number or a string) " +
        "is reported, and one that is not (an object) is left out of the " +
        "row", function () {
    assert.strictEqual(accountRow(streamed).lastAccess, 1700000000,
                       JSON.stringify(accountRow(streamed)));
    assert.ok(!("lastAccess" in stranger), JSON.stringify(stranger));
  });
  log.debug("Leaving accountSection().");
}

async function retrySection(rp) {
  log.debug("Entering retrySection().");
  log.info("=== 4. a dead letter, retried by hand ===");
  const before = rp.received.length;
  rp.answers.push({ status: 409, body: { error: "incompatible_state",
                                         sub: "$sub",
                                         account_state: "active" } });
  await ok(API + "/commands/send-account", { clientId: APP,
    username: PERSON, command: "activate" }, "sent activate again");
  await received(rp, before + 1);
  const dead = await waitFor("a dead delivery", function (r) {
    return (r.deliveries || []).some(function (d) {
      return d.clientId === APP && d.state === "dead";
    });
  });
  const row = dead.deliveries.filter(function (d) {
    return d.clientId === APP && d.state === "dead";
  })[0];
  check("4a. incompatible_state is a dead delivery", function () {
    assert.strictEqual(row.state, "dead", JSON.stringify(row));
  });
  rp.answers.push({ status: 200, body: { sub: "$sub",
                                         account_state: "active" } });
  const retried = await ok(API + "/commands/retry-delivery",
                           { delivery: row.id },
                           "retried the dead delivery");
  await received(rp, before + 2);
  check("4b. a dead letter is retried by hand as a new generation, and the " +
        "relying party is sent it again", function () {
    const again = retried.row || retried.delivery || retried;
    assert.ok(Number(again.generation) >= 2, JSON.stringify(retried)
      .slice(0, 300));
    assert.strictEqual(rp.received.length, before + 2);
    assert.strictEqual(rp.received[before + 1].decoded.claims.command,
                       "activate");
  });
  log.debug("Leaving retrySection().");
}

async function commandsAfter(rp, before, what) {
  log.debug("Entering commandsAfter(). " + what);
  await sleep(2500);
  log.debug("Leaving commandsAfter().");
  return rp.received.slice(before).map(function (one) {
    return one.decoded && one.decoded.claims.command;
  });
}

async function automaticSection(rp) {
  log.debug("Entering automaticSection().");
  log.info("=== 5. automatic commands ===");
  let before = rp.received.length;
  await ok(API + "/users/set-mail", { user: PERSON,
    mail: "changed-" + PERSON + "@suite.example.test" },
    "changed the person's mail");
  const maintained = await commandsAfter(rp, before, "profile");
  check("5a. a profile change is maintain", function () {
    assert.deepStrictEqual(maintained, ["maintain"]);
  });
  before = rp.received.length;
  await ok(API + "/roles/add-member", { role: "REPORT_USE", kind: "user",
                                        member: PERSON },
           "gave the person a role");
  const roleMaintained = await commandsAfter(rp, before, "role");
  check("5b. a role the person holds moving is maintain, as a group is",
        function () {
    assert.deepStrictEqual(roleMaintained, ["maintain"]);
  });
  before = rp.received.length;
  await ok(API + "/users/disable", { user: PERSON }, "disabled the person");
  const disabled = await commandsAfter(rp, before, "disable");
  check("5c. a disable is suspend, which this relying party did not list " +
        "among what it supports, so nothing is sent", function () {
    assert.deepStrictEqual(disabled, []);
  });
  log.debug("Leaving automaticSection().");
}

async function actsSection() {
  log.debug("Entering actsSection().");
  log.info("=== 6. the acts ===");
  const unknown = await call("POST", API + "/commands/dance", {});
  check("6a. an unknown action is refused, naming the three", function () {
    assert.strictEqual(unknown.status, 400, unknown.text.slice(0, 200));
    assert.strictEqual(unknown.json.message, "Unknown action \"dance\". " +
      "The 3 are: send-account, send-tenant and retry-delivery.");
  });
  await registry.ensurePerson(RB, "pcr-bob-" + STAMP, PASSWORD);
  const noEndpoint = await call("POST", API + "/commands/send-account", {
    clientId: "pcr-plain", username: "pcr-bob-" + STAMP, command: "audit" });
  check("6b. a client with no command_endpoint is refused", function () {
    assert.strictEqual(noEndpoint.status, 400, noEndpoint.text.slice(0,
                                                                     300));
    assert.strictEqual(noEndpoint.json.ok, false);
  });
  log.debug("Leaving actsSection().");
}

async function registrationSection() {
  log.debug("Entering registrationSection().");
  log.info("=== 7. registration ===");
  const register = function (endpoint) {
    return call("POST", RB + "/oauth2/register", {
      redirect_uris: ["https://rp.pcr.example/cb"],
      token_endpoint_auth_method: "client_secret_post",
      grant_types: ["authorization_code"], response_types: ["code"],
      scope: "openid", command_endpoint: endpoint });
  };
  const fragment = await register("https://rp.pcr.example/c#x");
  const query = await register("https://rp.pcr.example/c?q=1");
  check("7a. a command_endpoint with a fragment is refused; one with a " +
        "query is not", function () {
    assert.strictEqual(fragment.status, 400, fragment.text.slice(0, 200));
    assert.strictEqual(fragment.json.error, "invalid_client_metadata");
    assert.strictEqual(query.status, 201, query.text.slice(0, 200));
    assert.strictEqual(query.json.command_endpoint,
                       "https://rp.pcr.example/c?q=1");
  });
  log.debug("Leaving registrationSection().");
}

async function test() {
  log.debug("Entering test().");
  const rp = await relyingParty();
  try {
    await ok(base + "/admin-api/realms/create", { id: REALM,
      domain: REALM + ".example.net", name: "Provider commands " + STAMP },
      "created the realm");
    await setting("global.mode", "development");
    await setting("oauth2.openRegistration", true);
    await setting("oauth2.providerCommands", true);
    await setting("oauth2.commandBackoffMs", 200);
    await setting("federation.outboundSkipTlsVerification", true);
    await registry.ensurePerson(RB, PERSON, PASSWORD);
    await ok(API + "/applications/create", { identifier: APP, name: APP,
      protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: [APP], oauthCommandEndpoint: rp.endpoint,
                oauthRedirectUri: ["https://rp.pcr.example/cb"] } },
      "created the client");
    await ok(API + "/applications/create", { identifier: "pcr-plain",
      name: "pcr-plain", protocols: ["oauth2", "oidc"],
      fields: { oauthClientId: ["pcr-plain"],
                oauthRedirectUri: ["https://rp.pcr.example/cb"] } },
      "created the client with no command_endpoint");
    await tokenSection(rp);
    await accountSection(rp);
    await retrySection(rp);
    await actsSection();
    await registrationSection();
    await automaticSection(rp);
  } finally {
    rp.server.close();
  }
  assert.ok(checks >= FLOOR, "only " + checks + " checks ran; the floor is " +
            FLOOR);
  log.info(checks + " check(s) passed.");
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) the realm this run made is removed at
// the end, pass or fail. A suite run leaves it standing (tests/CLAUDE.md,
// *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const r = await call("POST", base + "/admin-api/realms/remove",
                       { id: REALM });
  log.info("removed the realm " + REALM + " (" + r.status + ")");
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realm is removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // A removal that fails is logged; the job's verdict is the test's.
    log.warn("could not remove the realm: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main(). Failed.");
    process.exit(1);
  }
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
  process.exit(0);
}

main();
