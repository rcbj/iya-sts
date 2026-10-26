// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_scim_client.js
//
// ---------------------------------------------------------------------------
// THE OUTBOUND SCIM CLIENT, OVER HTTP, INTO THIS SERVICE'S OWN /scim/v2
// (#552, 2026-10-13).
//
// What #552 promised beside the in-process test (`tests/scim_client.js`,
// which drives the client against a fake service provider written in the
// test): "a client in one realm provisioning into ANOTHER realm's own
// /scim/v2 on the same service". Two throwaway realms:
//
//   * the TARGET realm is the service provider. Its /scim/v2 needs a
//     credential in both modes, so a confidential client is registered there
//     (client_credentials, client_secret_basic) and declared for scim:read
//     and scim:write (#110: the SCIM scopes are issued only to a client whose
//     oauthAllowedScope declares them) — what sts_scim_conformance.js does;
//   * the SOURCE realm holds a person, a group with that person in it, and a
//     scim-client application entry (POST /admin-api/scim/clients/add-client)
//     pointed at the target's /scim/v2, authenticating with OAuth 2.0
//     client_credentials at the TARGET realm's token endpoint.
//
// Then, over HTTP only:
//   1. test-connection reads the target's discovery documents;
//   2. a reconciliation pushes the person and the group; the target's
//      /scim/v2 holds a User whose externalId is the source entry's UUID
//      (the person's `sub` is urn:uuid:<that>) and a Group naming that
//      User's id as a member;
//   3. a change (`title`) propagates;
//   4. a disable propagates as `active: false` (#552: a disabled account is
//      always active false there, whatever deprovisioning says);
//   5. the client's queue drains: nothing queued or retrying, no dead letter.
//
// THE CLIENT REQUIRES TLS WITH THE SERVER IDENTITY CHECKED (RFC 7644 section
// 7.2) in both modes, and it does not take this service's own certificate on
// trust: the job hands it the anchor the launcher gave the job
// (NODE_EXTRA_CA_CERTS, the service Root or the listener certificate) as the
// client's `caCertificates`, which is exactly what an operator pointing a
// client at a private service provider does. The service then dials the
// address the job was given (`https://sts:8081` in the local modes, the
// balancer in `cluster`) — so it must reach itself there under a name its
// certificate carries; in the local stacks it does. A run against a
// deployment whose public address does not route back to its own nodes (an
// NLB that does not hairpin) cannot make that connection, and this job says
// so in its failure rather than passing.
//
// OWNED HERE (local: true): this repository's outbound SCIM client, its SCIM
// service provider, its authorization server and its management API.
// tests/CLAUDE.md's question 2 — asserted over HTTP against a running
// service — and the only one an AWS target or the product mode can run.
// ---------------------------------------------------------------------------

const assert = require("assert");
const fs = require("fs");
const nodeCrypto = require("crypto");
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
var log = bunyan.createLogger({ name: "sts_scim_client",
                                level: appconfig.LOG_LEVEL ||
                                       process.env.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const TAG = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(0, 12);
const SOURCE = "scimcs-" + TAG;
const TARGET = "scimct-" + TAG;
const sourceBase = root + "/realm/" + SOURCE;
const targetBase = root + "/realm/" + TARGET;
const sourceApi = sourceBase + "/admin-api";
const targetApi = targetBase + "/admin-api";
const TARGET_SCIM = targetBase + "/scim/v2";
const PERSON = names.usernameFor("scimc-pat");
const GROUP = "scimc-group-" + TAG;
const CLIENT = "scimc-push-" + TAG;
// How long one propagation may take: the act sends at once (deliver-now),
// and the scim-client.deliver sweep (scimClient.sweepS, 15 s) is the net.
const WAIT_MS = 120000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, url, options) {
  log.debug("Entering call(). " + method + " " + url);
  const given = options || {};
  const headers = Object.assign({}, given.headers || {});
  let body;
  if (given.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(given.json);
  } else if (given.form !== undefined) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(given.form).toString();
  }
  const r = await fetch(url, { method: method, headers: headers, body: body });
  const text = await r.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    log.debug("Caught in call(): " + ((e && e.message) || e));
    json = null;
  }
  log.debug("Leaving call(). " + r.status);
  return { status: r.status, text: text, json: json };
}

async function ok(url, json, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, { json: json });
  assert.ok(r.status === 200 || r.status === 201,
    what + ": " + r.status + " " + r.text.slice(0, 600));
  log.info("  " + what);
  log.debug("Leaving ok().");
  return r.json;
}

function sleep(ms) {
  log.debug("Entering sleep().");
  log.debug("Leaving sleep().");
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// The anchor the launcher gave this job for the service's certificate, as
// PEM, or '' on a hand run against a publicly trusted one.
function serviceAnchor() {
  log.debug("Entering serviceAnchor().");
  const file = process.env.NODE_EXTRA_CA_CERTS || "";
  let pem = "";
  if (file) {
    try {
      pem = fs.readFileSync(file, "utf8");
    } catch (e) {
      log.debug("Caught in serviceAnchor(): " + ((e && e.message) || e));
      throw new Error("NODE_EXTRA_CA_CERTS names " + file + ", which could " +
                      "not be read: " + e.message);
    }
  }
  log.debug("Leaving serviceAnchor(). " + (pem ? "an anchor" : "none"));
  return pem;
}

// The target realm: SCIM creates nothing invented, and a confidential
// client there holds scim:read and scim:write. Answers its credentials.
async function setUpTarget() {
  log.debug("Entering setUpTarget().");
  await ok(root + "/admin-api/realms/create", { id: TARGET,
    domain: TARGET + ".example.net", name: "SCIM client target " + TARGET },
    "created the target realm " + TARGET);
  await ok(targetApi + "/config/set",
           { key: "oauth2.openRegistration", value: true },
           "opened registration in " + TARGET);
  await ok(targetApi + "/config/set",
           { key: "scim.inventOnCreate", value: false },
           "a SCIM create in " + TARGET + " invents nothing");
  const reg = await call("POST", targetBase + "/oauth2/register", { json: {
    grant_types: ["client_credentials"],
    token_endpoint_auth_method: "client_secret_basic",
    client_name: "The source realm's outbound SCIM client" } });
  assert.strictEqual(reg.status, 201, "registration: " +
                     reg.text.slice(0, 300));
  for (const scope of ["scim:read", "scim:write"]) {
    await ok(targetApi + "/applications/add",
             { application: reg.json.client_id,
               attribute: "oauthAllowedScope", value: scope },
             "declared " + scope + " on " + reg.json.client_id);
  }
  log.debug("Leaving setUpTarget().");
  return { id: reg.json.client_id, secret: reg.json.client_secret };
}

// A token of the target realm's, for this job's own reads of its /scim/v2.
async function targetToken(client) {
  log.debug("Entering targetToken().");
  const token = await call("POST", targetBase + "/oauth2/token", {
    headers: { Authorization: "Basic " + Buffer.from(client.id + ":" +
      client.secret).toString("base64") },
    form: { grant_type: "client_credentials", scope: "scim:read scim:write",
            resource: targetBase + "/resource" } });
  assert.strictEqual(token.status, 200, "token: " + token.text.slice(0, 300));
  log.debug("Leaving targetToken().");
  return token.json.access_token;
}

// One SCIM list query at the target, answered as its Resources.
async function targetList(token, type, filter) {
  log.debug("Entering targetList(). " + type);
  const r = await call("GET", TARGET_SCIM + "/" + type + "?filter=" +
                       encodeURIComponent(filter),
                       { headers: { Authorization: "Bearer " + token,
                                    Accept: "application/scim+json" } });
  assert.strictEqual(r.status, 200, "GET " + type + " at the target: " +
                     r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving targetList().");
  return (r.json && r.json.Resources) || [];
}

// The client's page as /admin-api draws it.
async function clientView() {
  log.debug("Entering clientView().");
  const r = await call("GET", sourceApi + "/scim/clients?client=" +
                       encodeURIComponent(CLIENT));
  assert.strictEqual(r.status, 200, "GET /admin-api/scim/clients: " +
                     r.status + " " + r.text.slice(0, 300));
  log.debug("Leaving clientView().");
  return r.json.client;
}

// Polls until `test` answers something truthy; fails naming what was
// waited for and the client's queues as they stand.
async function waitFor(what, test) {
  log.debug("Entering waitFor(). " + what);
  const until = Date.now() + WAIT_MS;
  let last = null;
  while (Date.now() < until) {
    last = await test();
    if (last) {
      log.debug("Leaving waitFor(). Seen.");
      return last;
    }
    await sleep(1000);
  }
  const view = await clientView();
  log.debug("Leaving waitFor(). Timed out.");
  throw new Error("waited " + (WAIT_MS / 1000) + "s for " + what + "; the " +
    "client's queues: " + JSON.stringify(view && view.queues).slice(0, 3000) +
    "; pausedUntil " + (view && view.pausedUntil) + ". A network failure " +
    "here (STS-SCIMC-0006) means the service could not reach " + root +
    " from inside itself under a name its certificate carries.");
}

async function theUser(token, uuid) {
  log.debug("Entering theUser().");
  const found = await targetList(token, "Users",
                                 "externalId eq " + JSON.stringify(uuid));
  log.debug("Leaving theUser(). " + found.length);
  return found.length === 1 ? found[0] : null;
}

async function test() {
  log.debug("Entering test().");
  const product = await facts.isProduct(root + "/admin-api");
  log.info("=== 0. two throwaway realms (" +
           (product ? "product" : "development") + " mode) ===");
  const credentials = await setUpTarget();
  const token = await targetToken(credentials);
  await ok(root + "/admin-api/realms/create", { id: SOURCE,
    domain: SOURCE + ".example.net", name: "SCIM client source " + SOURCE },
    "created the source realm " + SOURCE);
  await ok(sourceApi + "/users/create", { username: PERSON, invent: false,
    attributes: { cn: "Pat " + PERSON, givenName: "Pat", sn: PERSON,
                  mail: PERSON + "@scim-client.test" } },
    "created " + PERSON + " in the source realm");
  await ok(sourceApi + "/groups/create", { group: GROUP, members: [PERSON] },
           "created " + GROUP + " with " + PERSON + " in it");
  const who = await call("GET", sourceApi + "/users?user=" +
                         encodeURIComponent(PERSON));
  const subject = String((who.json && who.json.subject) || "");
  assert.ok(/^urn:uuid:[0-9a-f-]{36}$/.test(subject),
            "the person's subject: " + who.text.slice(0, 300));
  const uuid = subject.slice("urn:uuid:".length);

  log.info("=== 1. the client, and its service provider's discovery ===");
  const anchor = serviceAnchor();
  if (/^http:/.test(root)) {
    // STS_HTTPS=false: RFC 7644 section 7.2 requires TLS, and the client
    // dials plain http only in development with scimClient.allowHttp on.
    assert.ok(!product, "this service answers plain http, and a product " +
              "realm's SCIM client never dials it (RFC 7644 section 7.2)");
    await ok(sourceApi + "/config/set", { key: "scimClient.allowHttp",
                                          value: true },
             "let the source realm's client dial plain http (development)");
  }
  const added = await ok(sourceApi + "/scim/clients/add-client", Object.assign({
    identifier: CLIENT, name: "Into " + TARGET, baseUrl: TARGET_SCIM,
    authMethod: "oauth2", tokenEndpoint: targetBase + "/oauth2/token",
    oauthClientId: credentials.id, oauthClientSecret: credentials.secret,
    oauthClientAuth: "client_secret_basic",
    oauthScope: "scim:read scim:write",
    oauthResource: targetBase + "/resource",
    scopeMode: "groups", scopeGroups: GROUP,
    groupMode: "selected", groups: GROUP,
    deprovision: "deactivate", enabled: "true" },
    anchor ? { caCertificates: anchor } : {}), "added the client " + CLIENT);
  check("the client is usable, its secret set and never shown", function () {
    assert.ok(added.client && added.client.usable &&
              added.client.oauthClientSecretSet,
              JSON.stringify(added).slice(0, 1000));
    assert.ok(JSON.stringify(added).indexOf(credentials.secret) < 0,
              "the secret came back");
  });
  const tested = await call("POST", sourceApi +
                            "/scim/clients/test-connection",
                            { json: { id: CLIENT } });
  check("test-connection reads the target's /ServiceProviderConfig over " +
        "verified TLS with a token from the target's token endpoint",
        function () {
    assert.strictEqual(tested.status, 200, tested.text.slice(0, 1000));
    assert.ok(tested.json.discovery && tested.json.discovery.ok &&
              tested.json.discovery.filter,
              JSON.stringify(tested.json).slice(0, 1000));
  });

  log.info("=== 2. a reconciliation pushes the person and the group ===");
  const reconciled = await ok(sourceApi + "/scim/clients/reconcile",
                              { id: CLIENT }, "reconciled " + CLIENT);
  check("the reconciliation queued the person and the group", function () {
    assert.ok(reconciled.users === 1 && reconciled.groups === 1,
              JSON.stringify(reconciled));
  });
  const user = await waitFor("the person at the target", function () {
    return theUser(token, uuid);
  });
  check("the target holds a User whose externalId is the source entry's " +
        "UUID", function () {
    assert.strictEqual(user.userName, PERSON, JSON.stringify(user));
    assert.strictEqual(user.externalId, uuid, JSON.stringify(user));
    assert.notStrictEqual(user.active, false, JSON.stringify(user));
  });
  const group = await waitFor("the group at the target, with its member",
                              async function () {
    const found = await targetList(token, "Groups", "displayName eq " +
                                   JSON.stringify(GROUP));
    return found.length === 1 && (found[0].members || []).some(
      function (m) {
        return m.value === user.id;
      }) ? found[0] : null;
  });
  check("the target holds the Group, its member the target's own id for " +
        "the User", function () {
    assert.strictEqual(group.displayName, GROUP, JSON.stringify(group));
  });

  log.info("=== 3. a change propagates ===");
  const title = "Provisioned " + nodeCrypto.randomBytes(3).toString("hex");
  await ok(sourceApi + "/users/set-attribute", { user: PERSON,
    attribute: "title", value: title }, "set " + PERSON + "'s title");
  await ok(sourceApi + "/scim/clients/deliver-now", { id: CLIENT },
           "asked for delivery now");
  const changed = await waitFor("the title at the target",
                                async function () {
    const one = await theUser(token, uuid);
    return one && one.title === title ? one : null;
  });
  check("the changed title is at the target, on the same resource",
        function () {
    assert.strictEqual(changed.id, user.id, JSON.stringify(changed));
  });

  log.info("=== 4. a disable propagates as active false ===");
  await ok(sourceApi + "/users/disable", { user: PERSON },
           "disabled " + PERSON + " in the source realm");
  await ok(sourceApi + "/scim/clients/deliver-now", { id: CLIENT },
           "asked for delivery now");
  const off = await waitFor("active false at the target", async function () {
    const one = await theUser(token, uuid);
    return one && one.active === false ? one : null;
  });
  check("the person is active false at the target, and still there",
        function () {
    assert.strictEqual(off.id, user.id, JSON.stringify(off));
  });

  log.info("=== 5. the queue drains, with no dead letter ===");
  const drained = await waitFor("the client's queue to drain",
                                async function () {
    const view = await clientView();
    const counts = view && view.queues && view.queues.counts;
    return counts && counts.queued === 0 && counts.retrying === 0
      ? view : null;
  });
  check("nothing queued, nothing retrying, no dead letter, no pause",
        function () {
    assert.strictEqual(drained.queues.counts.dead, 0,
                       JSON.stringify(drained.queues.dead).slice(0, 2000));
    assert.ok(drained.queues.counts.sent >= 2,
              JSON.stringify(drained.queues.counts));
    assert.ok(!drained.pausedUntil, "paused until " + drained.pausedUntil);
  });
  await ok(sourceApi + "/scim/clients/remove-client", { id: CLIENT },
           "removed " + CLIENT);

  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The outbound SCIM client (#552): a client in one realm " +
    "provisioning into another realm's own /scim/v2 on the same service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
