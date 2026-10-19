// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_caep_scopes.js
//
// ---------------------------------------------------------------------------
// CAEP INTEROPERABILITY PROFILE 1.0 SECTION 2.7.3, OVER THE WIRE (#334).
//
// An authorization server that issues tokens to SSF Receivers supports
// `ssf.read` and `ssf.manage`. `ssf.manage` is the write scope and includes
// every `ssf.read` permission, and this service holds one rule: write
// includes read. `ssf:read` and `ssf:write` are not Shared Signals scopes
// (rcbj, #334, 2026-10-19: no alias). Asserted here, in a throwaway realm
// left behind:
//
//   1. Discovery lists `ssf.read` and `ssf.manage`, and neither colon name.
//   2. A client that declares only `ssf.manage` is issued `ssf.read` as
//      well as `ssf.manage`, with `expires_in` at most 3600 (the default
//      lifetime, which is the profile's sixty-minute ceiling). Its manage
//      token creates a stream, reads it, reads its status, polls, asks for
//      verification and receives the verification SET.
//   3. A client that declares only `ssf.read` is issued `ssf.read`, lists
//      streams and is refused a create. The 403 names `ssf.manage`. It is
//      refused `ssf.manage`.
//   4. A client that declares only `ssf:read` is refused `ssf.read`; the
//      `ssf:read` token it can still get is refused by the transmitter. A
//      client that declares only `ssf:write` is refused `ssf.manage`.
//   5. An unauthenticated GET names `ssf.read` and `ssf.manage` in
//      `WWW-Authenticate`.
//   6. With `ssf.manage` withdrawn and `ssf.read` declared, the manage-only
//      token keeps its read and loses its write; with `ssf.read` withdrawn
//      too, it loses the read.
//
// The in-process half is `tests/ssf_profile_scopes.js`.
// OWNED HERE (local: true).
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
const { usernameFor } = require("./random_username.js");

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
var log = bunyan.createLogger({ name: "sts_ssf_caep_scopes",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("ssfcaep").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const SSF = "https://schemas.openid.net/secevent/ssf/event-type/";
const VERIFICATION = SSF + "verification";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "ssf-caep-" + String(Date.now()).slice(-8);
const COLON_WRITE = "caep-colonw-" + REALM;
const COLON_READ = "caep-colonr-" + REALM;
const MANAGE = "caep-manage-" + REALM;
const DOT = "caep-dotread-" + REALM;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

async function call(method, url, body, headers) {
  log.debug("Entering call().");
  const r = await fetch(url, { method: method,
    headers: Object.assign({ "Content-Type": "application/json" },
                           headers || {}),
    body: body === undefined ? undefined :
          (typeof body === "string" ? body : JSON.stringify(body)) });
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
  return { status: r.status, json: json, text: text,
           headers: r.headers };
}

async function ok(url, body, what) {
  log.debug("Entering ok().");
  const r = await call("POST", url, body);
  assert.ok(r.status === 200 && r.json && r.json.ok !== false,
            what + ": " + r.status + " " + r.text.slice(0, 400));
  log.debug("Leaving ok().");
  return r.json;
}

function application(identifier, scopes) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { identifier: identifier, kind: "oauth2-client", name: identifier,
           protocols: ["oauth2", "ssf"],
           fields: { oauthClientId: [identifier],
                     oauthAllowedScope: scopes,
                     oauthClientSecret: SECRET,
                     oauthGrantType: ["client_credentials"],
                     oauthTokenEndpointAuthMethod: "client_secret_post" } };
}

async function token(identifier, scope) {
  log.debug("Entering token().");
  const r = await call("POST", realmBase + "/oauth2/token",
    "grant_type=client_credentials&client_id=" +
    encodeURIComponent(identifier) + "&client_secret=" +
    encodeURIComponent(SECRET) + "&scope=" + encodeURIComponent(scope),
    { "Content-Type": "application/x-www-form-urlencoded" });
  log.debug("Leaving token(). status=" + r.status);
  return r;
}

function decode(jwt) {
  log.debug("Entering decode().");
  const part = String(jwt || "").split(".")[1] || "";
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function refusedInvalidScope(r) {
  log.debug("Entering refusedInvalidScope().");
  assert.strictEqual(r.status, 400, r.text.slice(0, 300));
  assert.strictEqual(r.json && r.json.error, "invalid_scope", r.text);
  assert.ok(/oauthAllowedScope/.test(r.text), r.text);
  log.debug("Leaving refusedInvalidScope().");
}

async function declare(identifier, scope, mode) {
  log.debug("Entering declare().");
  await ok(realmApi + "/applications/" + (mode || "add"),
           { application: identifier, attribute: "oauthAllowedScope",
             value: scope },
           (mode || "add") + " " + scope + " on " + identifier);
  log.debug("Leaving declare().");
}

function auth(accessToken) {
  log.debug("Entering auth().");
  log.debug("Leaving auth().");
  return { Authorization: "Bearer " + accessToken };
}

async function drainUntil(accessToken, id, arrived) {
  log.debug("Entering drainUntil().");
  const deadline = Date.now() + 5000;
  let got = [];
  for (;;) {
    const r = await call("POST", realmBase + "/ssf/poll",
                         { stream_id: id, returnImmediately: true,
                           maxEvents: 100 }, auth(accessToken));
    assert.strictEqual(r.status, 200, "poll: " + r.text.slice(0, 300));
    const sets = (r.json && r.json.sets) || {};
    const jtis = Object.keys(sets);
    got = got.concat(jtis.map(function (jti) {
      return decode(sets[jti]);
    }));
    if (jtis.length) {
      await call("POST", realmBase + "/ssf/poll",
                 { stream_id: id, ack: jtis, returnImmediately: true,
                   maxEvents: 0 }, auth(accessToken));
    }
    if (arrived(got) || Date.now() >= deadline) {
      log.debug("Leaving drainUntil().");
      return got;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 150);
    });
  }
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the CAEP profile scope names at " + realmBase);

  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "CAEP scopes" },
    "created the realm");
  await ok(realmApi + "/applications/create",
           application(COLON_WRITE, ["ssf:write"]),
           "created the ssf:write client");
  await ok(realmApi + "/applications/create",
           application(COLON_READ, ["ssf:read"]),
           "created the ssf:read client");
  await ok(realmApi + "/applications/create",
           application(MANAGE, ["ssf.manage"]),
           "created the manage client");
  await ok(realmApi + "/applications/create", application(DOT, ["ssf.read"]),
           "created the read client");

  log.info("=== 1. discovery lists the two profile names ===");
  let r = await call("GET", realmBase + "/.well-known/openid-configuration");
  check("scopes_supported lists ssf.read and ssf.manage, and neither " +
        "ssf:read nor ssf:write", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    const scopes = r.json.scopes_supported || [];
    ["ssf.read", "ssf.manage"].forEach(function (one) {
      assert.ok(scopes.indexOf(one) >= 0, one + " missing: " +
                JSON.stringify(scopes));
    });
    ["ssf:read", "ssf:write"].forEach(function (one) {
      assert.ok(scopes.indexOf(one) < 0, one + " is still published: " +
                JSON.stringify(scopes));
    });
  });

  log.info("=== 2. ssf.manage reads and writes ===");
  r = await token(MANAGE, "ssf.read");
  check("a client declaring only ssf.manage is issued ssf.read: write " +
        "includes read", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.strictEqual(r.json.scope, "ssf.read", r.text);
  });
  r = await token(MANAGE, "ssf.manage");
  check("and is issued ssf.manage in the spelling it asked for", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.strictEqual(r.json.scope, "ssf.manage", r.text);
    assert.strictEqual(decode(r.json.access_token).scope, "ssf.manage");
  });
  check("expires_in is at most 3600, the profile's sixty-minute ceiling " +
        "at the default lifetime", function () {
    assert.ok(Number(r.json.expires_in) > 0 &&
              Number(r.json.expires_in) <= 3600, JSON.stringify(r.json));
  });
  const manageToken = r.json.access_token;
  r = await call("POST", realmBase + "/ssf/stream",
                 { delivery: { method: POLL },
                   events_requested: [VERIFICATION] }, auth(manageToken));
  check("ssf.manage creates a stream", function () {
    assert.strictEqual(r.status, 201, r.text.slice(0, 400));
    assert.ok(r.json.stream_id, r.text);
  });
  const stream = r.json.stream_id;
  r = await call("GET", realmBase + "/ssf/stream?stream_id=" +
                        encodeURIComponent(stream), undefined,
                 auth(manageToken));
  check("and reads it back: manage includes read", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.strictEqual(r.json.stream_id, stream, r.text);
  });
  r = await call("GET", realmBase + "/ssf/status?stream_id=" +
                        encodeURIComponent(stream), undefined,
                 auth(manageToken));
  check("and reads the stream's status", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.strictEqual(r.json.status, "enabled", r.text);
  });
  r = await call("POST", realmBase + "/ssf/poll",
                 { stream_id: stream, returnImmediately: true,
                   maxEvents: 10 }, auth(manageToken));
  check("and polls: 200, and sets is an object", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
    assert.ok(r.json && r.json.sets && typeof r.json.sets === "object",
              r.text.slice(0, 400));
  });
  r = await call("POST", realmBase + "/ssf/verify",
                 { stream_id: stream, state: "caep-state" },
                 auth(manageToken));
  check("and asks for verification", function () {
    assert.strictEqual(r.status, 204, r.text);
  });
  const got = await drainUntil(manageToken, stream, function (list) {
    return list.some(function (one) {
      return Object.prototype.hasOwnProperty.call(one.events || {},
                                                   VERIFICATION);
    });
  });
  check("the verification SET arrives, echoing the state", function () {
    const found = got.filter(function (one) {
      return one.events && one.events[VERIFICATION];
    })[0];
    assert.ok(found, JSON.stringify(got.map(function (one) {
      return Object.keys(one.events || {});
    })));
    assert.strictEqual(found.events[VERIFICATION].state, "caep-state");
  });

  log.info("=== 3. a read declaration ===");
  r = await token(DOT, "ssf.manage");
  check("a client declaring only ssf.read is refused ssf.manage",
        function () {
    refusedInvalidScope(r);
  });
  r = await token(DOT, "ssf.read");
  check("and is issued ssf.read", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.scope, "ssf.read", r.text);
  });
  const readToken = r.json.access_token;
  r = await call("GET", realmBase + "/ssf/stream", undefined, auth(readToken));
  check("ssf.read lists the caller's streams", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
  });
  r = await call("POST", realmBase + "/ssf/stream",
                 { delivery: { method: POLL } }, auth(readToken));
  check("and is refused a create, which names ssf.manage", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 400));
    assert.ok(/ssf\.manage/.test(r.text), r.text.slice(0, 400));
  });

  log.info("=== 4. the colon names are not Shared Signals scopes ===");
  r = await token(COLON_READ, "ssf.read");
  check("a client declaring only ssf:read is refused ssf.read",
        function () {
    refusedInvalidScope(r);
  });
  r = await token(COLON_READ, "ssf:read");
  check("the ssf:read it declares is issued as an ordinary scope",
        function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 300));
    assert.strictEqual(r.json.scope, "ssf:read", r.text);
  });
  r = await call("GET", realmBase + "/ssf/stream", undefined,
                 auth(r.json.access_token));
  check("and the transmitter refuses it, naming ssf.read", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 400));
    assert.ok(/ssf\.read/.test(r.text), r.text.slice(0, 400));
  });
  r = await token(COLON_WRITE, "ssf.manage");
  check("a client declaring only ssf:write is refused ssf.manage",
        function () {
    refusedInvalidScope(r);
  });

  log.info("=== 5. the challenge names the profile scopes ===");
  r = await call("GET", realmBase + "/ssf/stream");
  check("an unauthenticated GET names ssf.read and ssf.manage", function () {
    assert.strictEqual(r.status, 401, r.text.slice(0, 300));
    const challenge = r.headers.get("www-authenticate") || "";
    assert.ok(/ssf\.read/.test(challenge), challenge);
    assert.ok(/ssf\.manage/.test(challenge), challenge);
  });

  log.info("=== 6. withdrawing the write declaration ===");
  await declare(MANAGE, "ssf.read");
  await declare(MANAGE, "ssf.manage", "remove");
  r = await call("GET", realmBase + "/ssf/stream?stream_id=" +
                        encodeURIComponent(stream), undefined,
                 auth(manageToken));
  check("with ssf.read still declared, the manage-only token keeps its " +
        "read", function () {
    assert.strictEqual(r.status, 200, r.text.slice(0, 400));
  });
  r = await call("POST", realmBase + "/ssf/status",
                 { stream_id: stream, status: "paused" }, auth(manageToken));
  check("and is refused a write, naming oauthAllowedScope", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 400));
    assert.ok(/oauthAllowedScope/.test(r.text), r.text.slice(0, 400));
  });
  await declare(MANAGE, "ssf.read", "remove");
  r = await call("GET", realmBase + "/ssf/stream?stream_id=" +
                        encodeURIComponent(stream), undefined,
                 auth(manageToken));
  check("with nothing declared it is refused the read, naming " +
        "oauthAllowedScope", function () {
    assert.strictEqual(r.status, 403, r.text.slice(0, 400));
    assert.ok(/oauthAllowedScope/.test(r.text), r.text.slice(0, 400));
  });

  assert.ok(checks >= 21, "only " + checks + " of 21 checks ran");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_ssf_caep_scopes")
  .description("CAEP Interoperability Profile scope names over the wire " +
    "(#334): ssf.read and ssf.manage, and write includes read.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
