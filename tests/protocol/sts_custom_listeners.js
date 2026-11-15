// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_custom_listeners.js
//
// ---------------------------------------------------------------------------
// CUSTOM LISTENERS AND THE APPLICATIONS MAPPED TO THEM, OVER THE WIRE (#472).
//
// D12 (#444): carries over `tests/custom_listeners.js` to
// `POST /admin-api/listeners/{set-listeners,set-applications}`, the
// listeners' own sockets and the audit log. `sts_realm_listener.js` already
// holds a realm's listener answering its realm (STS-TLS-0041) and SCIM moved
// off the main port (STS-TLS-0047); what is held here is the rest:
//
//   A. THE WRITE RULES, each refused 400 with its code read off the audit
//      log: a definition that is not JSON and a reserved id (STS-CORE-0153),
//      a public base that is not https (0146), the main port (0147); the
//      default realm taking no `listeners.realm`; a mapping naming no
//      application, a listener nobody defined, or `oauth-oidc` where
//      `oidfed` is not (0154); removing a listener a mapping names (0154);
//      another realm's listener in a realm's mapping (0154); `authn` and the
//      portal on two host names with a host-only cookie (0155); and a write
//      taking the management API off the listener it ARRIVED ON refused
//      (0156) and then accepted with `confirm`;
//   B. THE MAPPING AS READ (`GET /admin-api/listeners`' `applications`): a
//      realm's `*` comes before the service's entries, a realm with no
//      mapping inherits the service's, an unnamed application is on main;
//   C. THE SOCKETS: the service listener bound with an issued certificate
//      and no key reported; the authorization server refused there with a
//      404 naming where it is (STS-TLS-0047, which leaves no audit row: it
//      is marked above the protocol-call recorder); the console's shell on it
//      telling its runtime where the authorization server is and letting it
//      connect there; a realm mapping `*` to its own listener built on that
//      base with its prefix;
//   D. THE DEFINITIONS DRIVE THE SOCKETS: a new port closes the old listener
//      and binds the new one; a certificate file that cannot be read is a
//      failed listener (STS-TLS-0040, which is logged only: the view says
//      `failed` and why), not a stopped service; removing the
//      definition closes it.
//
// NOT carried: a port held by ANOTHER program being a failed listener
// (STS-TLS-0039) needs a foreign process on the service's own host, which a
// client cannot start (class (d)); the URL rule's `pinnedBaseUrl()` with no
// request is a library call, and is asserted here through what the realm's
// discovery document says instead.
//
// IT CHANGES PROCESS-WIDE STATE — `listeners.custom` and the service's
// mapping — and puts both back in a `finally`. The main port never loses an
// application: the console and the API are mapped to `main` AND the custom
// listener, so a job running beside this one still finds them. It wants
// four free ports the job can reach on the service's host,
// `STS_TEST_CUSTOM_LISTENER_PORTS` (default 8095,8096,8097,8098).
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
var log = bunyan.createLogger({ name: "sts_custom_listeners",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const HOST = new URL(base).hostname;
const MAIN_PORT = Number(new URL(base).port || 443);
const PORTS = String(process.env.STS_TEST_CUSTOM_LISTENER_PORTS ||
                     "8095,8096,8097,8098").split(",").map(Number);
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const A = "cla-" + STAMP;
const B = "clb-" + STAMP;
const ADM = "adm-" + STAMP.slice(-6);
const P2 = "p2-" + STAMP.slice(-6);
const RA = "ra-" + STAMP.slice(-6);
const ADM_BASE = "https://" + HOST + ":" + PORTS[0];
const REALM_BASE = "https://" + HOST + ":" + PORTS[1];

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
  let r;
  try {
    r = await fetch(url, Object.assign({ redirect: "manual" },
                                       options || {}));
  } catch (e) {
    log.debug("Caught in send(): " + ((e && e.message) || e));
    // A closed port: the caller asserts on status 0.
    log.debug("Leaving send(). No connection.");
    return { status: 0, body: null, raw: String((e && e.cause &&
      e.cause.code) || (e && e.message) || e), headers: new Headers() };
  }
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
  return { status: r.status, body: body, raw: raw, headers: r.headers };
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

function apiOf(realm, onBase) {
  log.debug("Entering apiOf().");
  log.debug("Leaving apiOf().");
  return (onBase || base) + (realm ? "/realm/" + realm : "") +
    "/admin-api";
}

async function codeCount(realm, code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(apiOf(realm) + "/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function sawCode(realm, code, before) {
  log.debug("Entering sawCode(). " + code);
  let after = before;
  for (let i = 0; i < 20 && after <= before; i += 1) {
    await sleep(150);
    after = await codeCount(realm, code);
  }
  log.debug("Leaving sawCode(). " + before + " -> " + after);
  return after > before;
}

// One write the rules must refuse, by its code on the realm's audit log.
async function refused(realm, action, value, code, what, extra) {
  log.debug("Entering refused(). " + code);
  const before = await codeCount(realm, code);
  const r = await postJson(apiOf(realm, extra && extra.onBase) +
                           "/listeners/" + action,
                           Object.assign({ value: value },
                                         extra && extra.body));
  const saw = await sawCode(realm, code, before);
  check(what + " (" + code + ")", function () {
    assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
    assert.ok(r.body && r.body.ok === false, r.raw.slice(0, 300));
    assert.ok(!/STS-[A-Z]+-\d{4}/.test(r.raw), "a code was sent");
    assert.ok(saw, "no " + code + " row on " + (realm || "default"));
  });
  log.debug("Leaving refused().");
  return r;
}

function setListeners(realm, value, what) {
  log.debug("Entering setListeners().");
  log.debug("Leaving setListeners().");
  return ok(apiOf(realm) + "/listeners/set-listeners", { value: value },
            what);
}

function setApplications(realm, value, what, extra) {
  log.debug("Entering setApplications().");
  log.debug("Leaving setApplications().");
  return ok(apiOf(realm, extra && extra.onBase) +
            "/listeners/set-applications",
            Object.assign({ value: value }, extra && extra.body), what);
}

async function view(realm) {
  log.debug("Entering view().");
  const r = await send(apiOf(realm) + "/listeners");
  assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
  log.debug("Leaving view().");
  return r.body;
}

function mappedOf(v, application) {
  log.debug("Entering mappedOf().");
  log.debug("Leaving mappedOf().");
  return (v.applications || []).filter(function (row) {
    return row.application === application;
  })[0] || {};
}

function customOf(v, id) {
  log.debug("Entering customOf().");
  log.debug("Leaving customOf().");
  return (v.custom || []).filter(function (row) {
    return row.id === id;
  })[0] || null;
}

async function until(what, fn, ms) {
  log.debug("Entering until(). " + what);
  const deadline = Date.now() + (ms || 15000);
  let last = null;
  while (Date.now() < deadline) {
    last = await fn();
    if (last && last.done) {
      log.debug("Leaving until().");
      return last;
    }
    await sleep(300);
  }
  log.debug("Leaving until(). Timed out.");
  return last || {};
}

function adm(port) {
  log.debug("Entering adm().");
  log.debug("Leaving adm().");
  return { id: ADM, port: port || PORTS[0], publicBaseUrl: ADM_BASE };
}

async function theRules() {
  log.debug("Entering theRules().");
  log.info("=== A. the rules every write is held to ===");
  await refused("", "set-listeners", "[{\"id\":", "STS-CORE-0153",
                "A. a definition that is not JSON is refused");
  await refused("", "set-listeners", [Object.assign(adm(), { id: "main" })],
                "STS-CORE-0153", "A. a reserved id is refused");
  await refused("", "set-listeners",
                [Object.assign(adm(), { publicBaseUrl: "http://x.test" })],
                "STS-CORE-0146", "A. a public base that is not https is " +
                "refused");
  // The port the PROCESS binds (global.port), which is not the port this
  // job dials where a container's port is published under another number.
  const mainRow = ((await view("")).listeners || []).filter(function (one) {
    return one.id === "main";
  })[0];
  await refused("", "set-listeners", [adm(Number(mainRow.port))],
                "STS-CORE-0147", "A. the main port is refused");
  await setListeners("", [adm()], "defined a well-formed service listener");
  const defined = await view("");
  check("A. a well-formed service listener is accepted, and listed",
        function () {
    const one = customOf(defined, ADM);
    assert.ok(one, JSON.stringify(defined.custom).slice(0, 300));
    assert.strictEqual(one.port, PORTS[0]);
    assert.strictEqual(one.publicBaseUrl, ADM_BASE);
  });
  const dflt = await postJson(base + "/admin-api/realms/set",
    { id: "default", key: "listeners.realm", value: JSON.stringify([adm()]) });
  check("A. the default realm takes no listeners.realm: its listeners are " +
        "the service's", function () {
    assert.strictEqual(dflt.status, 400, dflt.raw.slice(0, 300));
  });
  await refused("", "set-applications",
                { ["none-" + STAMP]: { listeners: [ADM] } },
                "STS-CORE-0154", "A. a mapping naming no application is " +
                "refused");
  await refused("", "set-applications",
                { portal: { listeners: ["nowhere-" + STAMP.slice(-4)] } },
                "STS-CORE-0154", "A. a mapping naming a listener nobody " +
                "defined is refused");
  await refused("", "set-applications",
                { "oauth-oidc": { listeners: [ADM] } }, "STS-CORE-0154",
                "A. oauth-oidc advertised where oidfed is not is refused " +
                "(the Entity Configuration is fetched at the issuer)");
  await setApplications("", {
    "admin-console": { listeners: ["main", ADM] },
    "management-api": { listeners: ["main", ADM] } },
    "put the console and the API on the custom listener too");
  await refused("", "set-listeners", "", "STS-CORE-0154",
                "A. a listener the mapping names cannot be removed");
  await setListeners(A, [{ id: RA, port: PORTS[1],
                           publicBaseUrl: REALM_BASE }],
                     "gave realm " + A + " a listener of its own");
  await refused(B, "set-applications", { portal: { listeners: [RA] } },
                "STS-CORE-0154", "A. another realm's listener is refused " +
                "in a realm's mapping");
  await setListeners("", [adm(), { id: P2, port: PORTS[3],
    publicBaseUrl: "https://portal-" + STAMP + ".other.test:" + PORTS[3] }],
    "defined a second service listener on another host name");
  await refused("", "set-applications", {
    "admin-console": { listeners: ["main", ADM] },
    "management-api": { listeners: ["main", ADM] },
    authn: { listeners: [ADM] }, portal: { listeners: [P2] } },
    "STS-CORE-0155", "A. authn and the portal on two host names with a " +
    "host-only cookie are refused");
  await setListeners("", [adm()], "took the second listener away again");
  log.debug("Leaving theRules().");
}

async function theApiMove() {
  log.debug("Entering theApiMove().");
  // Arriving on the custom listener, a mapping that leaves the API on main
  // alone takes it off the listener the write arrived on.
  const ready = await until("the custom listener answering the API",
                            async function () {
    const r = await send(ADM_BASE + "/admin-api/listeners");
    return { done: r.status === 200, detail: r.status };
  });
  assert.ok(ready.done, "the custom listener " + ADM_BASE + " never " +
            "answered the API: " + JSON.stringify(ready.detail));
  const moveApi = { "admin-console": { listeners: ["main", ADM] },
                    "management-api": { listeners: ["main"] } };
  await refused("", "set-applications", moveApi, "STS-CORE-0156",
                "A. taking the management API off the listener the write " +
                "arrived on is refused", { onBase: ADM_BASE });
  await setApplications("", moveApi, "moved the API with confirm",
                        { onBase: ADM_BASE, body: { confirm: true } });
  const after = await view("");
  check("A. and accepted when confirmed", function () {
    assert.deepStrictEqual(mappedOf(after, "management-api").listeners,
                           ["main"]);
  });
  await setApplications("", {
    "admin-console": { listeners: ["main", ADM] },
    "management-api": { listeners: ["main", ADM] } },
    "put the API back on both");
  log.debug("Leaving theApiMove().");
}

async function theMappingAndSockets() {
  log.debug("Entering theMappingAndSockets().");
  log.info("=== B. the mapping as read ===");
  await setApplications(A, { "*": { listeners: ["main", RA],
                                    advertised: RA } },
                        "mapped realm A's applications to its listener");
  const inA = await view(A);
  const inB = await view(B);
  const inDefault = await view("");
  check("B. a realm's * comes before the service's entries", function () {
    const row = mappedOf(inA, "admin-console");
    assert.deepStrictEqual(row.listeners, ["main", RA], JSON.stringify(row));
    assert.strictEqual(row.advertised, RA);
  });
  check("B. a realm with no mapping inherits the service's", function () {
    assert.deepStrictEqual(mappedOf(inB, "admin-console").listeners,
                           ["main", ADM]);
  });
  check("B. an application nobody named is on main", function () {
    assert.deepStrictEqual(mappedOf(inDefault, "oauth-oidc").listeners,
                           ["main"]);
  });

  log.info("=== C. the sockets ===");
  const bound = await until("both listeners bound", async function () {
    const v1 = await view("");
    const v2 = await view(A);
    const one = customOf(v1, ADM);
    const two = customOf(v2, RA);
    return { done: !!(one && two && one.state === "bound" &&
                      two.state === "bound"), detail: [one, two] };
  });
  check("C. both listeners are bound with an issued certificate, and no " +
        "key is reported", function () {
    assert.ok(bound.done, JSON.stringify(bound.detail).slice(0, 600));
    bound.detail.forEach(function (one) {
      assert.ok(one.certificate && one.certificate.source === "issued",
                JSON.stringify(one.certificate));
      assert.ok(!("key" in one.certificate) &&
                !/PRIVATE KEY/.test(JSON.stringify(one)));
    });
  });
  // OBSERVED: STS-TLS-0047 is marked on the response by app.js's
  // enterListener(), which runs above the protocol-call recorder, so the
  // refusal leaves no audit row and no log line a client could read; the
  // 404 and its sentence are what is asserted.
  const offHere = await send(ADM_BASE + "/.well-known/openid-configuration");
  check("C. the authorization server is refused on the console's listener " +
        "with a 404 that says where it is", function () {
    assert.strictEqual(offHere.status, 404, offHere.raw.slice(0, 200));
    assert.ok(/is not served on this listener/.test(offHere.raw),
              offHere.raw.slice(0, 200));
    assert.ok(offHere.raw.indexOf(":" + MAIN_PORT) > 0,
              offHere.raw.slice(0, 200));
  });
  const shell = await send(ADM_BASE + "/admin/listeners");
  check("C. the console's shell there tells its runtime where the " +
        "authorization server is, and lets it connect there", function () {
    assert.strictEqual(shell.status, 200, shell.raw.slice(0, 200));
    assert.ok(/data-sts-oauth="https?:/.test(shell.raw),
              shell.raw.slice(0, 300));
    assert.ok(/connect-src 'self' https?:/.test(String(
      shell.headers.get("content-security-policy") || "")));
  });
  const disc = await until("realm A's discovery on its listener",
                           async function () {
    const r = await send(REALM_BASE + "/realm/" + A +
                         "/.well-known/openid-configuration");
    return { done: r.status === 200, detail: r };
  });
  check("C. a realm mapping * to its own listener is built on its base " +
        "with its prefix", function () {
    assert.ok(disc.done, JSON.stringify(disc.detail.status));
    assert.strictEqual(disc.detail.body.issuer, REALM_BASE + "/realm/" + A);
  });
  log.debug("Leaving theMappingAndSockets().");
}

async function theDefinitionsDriveTheSockets() {
  log.debug("Entering theDefinitionsDriveTheSockets().");
  log.info("=== D. the definitions drive the sockets ===");
  const moved = "https://" + HOST + ":" + PORTS[2];
  await setListeners(A, [{ id: RA, port: PORTS[2], publicBaseUrl: moved }],
                     "moved realm A's listener to another port");
  const rebound = await until("the listener on its new port",
                              async function () {
    const gone = await send(REALM_BASE + "/realm/" + A +
                            "/.well-known/openid-configuration");
    const there = await send(moved + "/realm/" + A +
                             "/.well-known/openid-configuration");
    return { done: gone.status === 0 && there.status === 200,
             detail: [gone.status + " " + gone.raw.slice(0, 40),
                      there.status] };
  });
  check("D. a new port closes the old listener and binds the new one",
        function () {
    assert.ok(rebound.done, JSON.stringify(rebound.detail));
  });
  await setListeners(A, [{ id: RA, port: PORTS[2], publicBaseUrl: moved,
    certificateFile: "/nonexistent/" + STAMP + ".pem",
    privateKeyFile: "/nonexistent/" + STAMP + ".key" }],
    "named a certificate file that cannot be read");
  const failed = await until("the listener failing", async function () {
    const one = customOf(await view(A), RA);
    return { done: !!(one && one.state === "failed"), detail: one };
  });
  const live = await send(base + "/.well-known/openid-configuration");
  check("D. a certificate file that cannot be read is a failed listener " +
        "(STS-TLS-0040), not a stopped service", function () {
    assert.ok(failed.done, JSON.stringify(failed.detail).slice(0, 400));
    // STS-TLS-0040 is logged, not audited and not in this view (observed);
    // the view carries the state and the sentence.
    assert.ok(/could not be read/.test(String(failed.detail.why)),
              JSON.stringify(failed.detail).slice(0, 400));
    assert.strictEqual(live.status, 200);
  });
  await setApplications(A, "", "unmapped realm A's applications");
  await setListeners(A, "", "removed realm A's listener");
  const closed = await until("the listener closed", async function () {
    const one = customOf(await view(A), RA);
    const r = await send(moved + "/realm/" + A +
                         "/.well-known/openid-configuration");
    return { done: !one && r.status === 0, detail: [one, r.status] };
  });
  check("D. removing the definition closes the listener", function () {
    assert.ok(closed.done, JSON.stringify(closed.detail).slice(0, 300));
  });
  log.debug("Leaving theDefinitionsDriveTheSockets().");
}

// A KNOWN STATE: free this job's ports from any realm an earlier run left
// them on (no job removes a realm), as sts_realm_listener.js does.
async function freeThePorts() {
  log.debug("Entering freeThePorts().");
  const listed = await send(base + "/admin-api/realms?per=500");
  assert.strictEqual(listed.status, 200, listed.raw.slice(0, 300));
  for (const row of (listed.body.realms || [])) {
    const holds = (row.listeners || []).some(function (one) {
      return PORTS.indexOf(Number(one.port)) >= 0;
    });
    if (holds && row.id !== "default") {
      await setApplications(row.id, "", "unmapped realm " + row.id);
      await setListeners(row.id, "", "freed realm " + row.id + "'s ports");
    }
  }
  log.debug("Leaving freeThePorts().");
}

async function test() {
  log.debug("Entering test().");
  await freeThePorts();
  for (const id of [A, B]) {
    await ok(base + "/admin-api/realms/create", { id: id,
      domain: id + ".example.net", name: "Custom listeners " + STAMP },
      "created the realm " + id);
  }
  try {
    await theRules();
    await theApiMove();
    await theMappingAndSockets();
    await theDefinitionsDriveTheSockets();
  } finally {
    // Put the process back: the service's mapping first (a listener a
    // mapping names cannot be removed), then its listeners.
    const m = await postJson(base + "/admin-api/listeners/set-applications",
                             { value: "" });
    const l = await postJson(base + "/admin-api/listeners/set-listeners",
                             { value: "" });
    log.info("restored the service's mapping (" + m.status + ") and " +
             "listeners (" + l.status + ")");
  }
  const restored = await view("");
  check("the service's mapping and listeners are put back", function () {
    assert.strictEqual(customOf(restored, ADM), null);
    assert.strictEqual(restored.definitions.listeners, "");
    assert.strictEqual(restored.definitions.applications, "");
  });
  log.info("Test completed successfully. " + checks + " check(s) passed.");
  log.debug("Leaving test().");
}

test().catch(function (e) {
  log.error("sts_custom_listeners FAILED: " + ((e && e.stack) || e));
  process.exit(1);
});
