"use strict";
//
// File: sts_ssf_allowed_events.js
//
// ---------------------------------------------------------------------------
// `ssfAllowedEvents`: AN APPLICATION ENTRY THAT LIMITS WHICH SHARED SIGNALS
// EVENT TYPES A STREAM IT OWNS IS SENT.
//
// It is the one attribute on an application entry that limits SSF, and it is
// enforced at two moments, both asserted here against a CONTROL — an
// application with no limit, whose stream asks for the same types and receives
// every event the limited one does not:
//
//   1. AGREEMENT. A stream the application creates or PATCHes is agreed only
//      the types its entry allows; the rest are absent from `events_delivered`.
//   2. DELIVERY. Tightening the entry after the stream exists stops that type
//      reaching it — so the limit cannot be escaped by creating a stream first.
//      Loosening it again gives back only what the stream was AGREED, never a
//      type withheld at agreement (section 6): delivery is the agreement less
//      what the entry no longer allows (`ssf/ssf_streams.ts`,
//      `deliversEvent()`). The stream's own configuration reports what
//      delivery will actually do.
//
// Plus the two write refusals (a value that is not `caep`, `risc` or a known
// event type URI; an entry not declared for Shared Signals), and the rule that
// SSF's own verification event is always allowed.
//
// Events are emitted by hand through `/admin-api/risc/emit`, which goes through
// the same candidate selection and `transmit()` as an automatic emission.
// Everything runs in a THROWAWAY TRUST REALM that is left behind.
//
// OWNED HERE (local: true): the attribute is this repository's own.
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
var log = bunyan.createLogger({ name: "sts_ssf_allowed_events",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug('CONFIG_FILE could not be read, so the configuration is empty: ' +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const REALM = usernameFor("ssfallow").replace(/[^a-z0-9-]/g, "").slice(0, 30);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const SESSION_REVOKED = CAEP + "session-revoked";
const ACCOUNT_DISABLED = RISC + "account-disabled";
const ACCOUNT_PURGED = RISC + "account-purged";
const VERIFICATION =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";
const POLL = "urn:ietf:rfc:8936";
const SECRET = "ssf-allowed-" + String(Date.now()).slice(-8);
const LIMITED = "ssf-limited-" + REALM;
const FREE = "ssf-free-" + REALM;
const UNDECLARED = "ssf-undeclared-" + REALM;

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

function application(identifier, protocols, fields) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { identifier: identifier, kind: "oauth2-client", name: identifier,
           protocols: protocols,
           // The Shared Signals scopes are issued only to a client that
           // declares them (#110).
           fields: Object.assign({ oauthClientId: [identifier],
                                   oauthAllowedScope: ["ssf:read",
                                                       "ssf:write"],
                                   oauthClientSecret: SECRET,
                                   oauthTokenEndpointAuthMethod:
                                     "client_secret_post" }, fields || {}) };
}

async function tokenFor(identifier) {
  log.debug("Entering tokenFor().");
  const r = await fetch(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&client_id=" +
          encodeURIComponent(identifier) +
          "&client_secret=" + encodeURIComponent(
              SECRET) + "&scope=" + encodeURIComponent("ssf:read " +
              "ssf:write") });
  const json = await r.json();
  assert.ok(json.access_token,
            "a token for " + identifier + ": " + JSON.stringify(json));
  log.debug("Leaving tokenFor().");
  return json.access_token;
}

function ssf(token) {
  log.debug("Entering ssf().");
  const auth = { Authorization: "Bearer " + token };
  log.debug("Leaving ssf().");
  return {
    create: function (body) {
      log.debug("Entering create().");
      log.debug("Leaving create().");
      return call("POST", realmBase + "/ssf/stream", body, auth);
    },
    read: function (id) {
      log.debug("Entering read().");
      log.debug("Leaving read().");
      return call("GET",
                  realmBase + "/ssf/stream?stream_id=" + encodeURIComponent(id),
                  undefined, auth);
    },
    patch: function (body) {
      log.debug("Entering patch().");
      log.debug("Leaving patch().");
      return call("PATCH", realmBase + "/ssf/stream", body, auth);
    },
    verify: function (id) {
      log.debug("Entering verify().");
      log.debug("Leaving verify().");
      return call("POST", realmBase + "/ssf/verify",
                  { stream_id: id, state: "allowed-" + id }, auth);
    },
    async drain(id) {
      log.debug("Entering drain().");
      const r = await call("POST", realmBase + "/ssf/poll",
                           { stream_id: id, returnImmediately: true,
                             maxEvents: 100 }, auth);
      assert.strictEqual(r.status, 200, "poll: " + r.text.slice(0, 300));
      const sets = r.json.sets || {};
      const jtis = Object.keys(sets);
      if (jtis.length) {
        await call("POST", realmBase + "/ssf/poll",
                   { stream_id: id, ack: jtis, returnImmediately: true,
                     maxEvents: 0 }, auth);
      }
      log.debug("Leaving drain().");
      return jtis.map(function (jti) {
        const payload = JSON.parse(Buffer.from(sets[jti].split(".")[1],
                                               "base64url").toString("utf8"));
        return Object.keys(payload.events || {})[0];
      });
    }
  };
}

async function emit(type, account) {
  log.debug("Entering emit().");
  log.debug("Leaving emit().");
  return ok(realmApi + "/risc/emit",
            { type: type, account_id: account,
              reason_admin: "sts_ssf_allowed_events" },
            "emitted " + type);
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving ssfAllowedEvents at " + realmBase);

  log.info("=== 0. the realm and three applications ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
                                                domain: REALM + ".example.net",
                                                name: "SSF " +
      "allowed events" }, "created " +
      "the realm");
  const refusedCreate = await call("POST", realmApi + "/applications/create",
    application("ssf-bad-" + REALM, ["oauth2", "ssf"],
                { ssfAllowedEvents: ["caep", "not-an-event"] }));
  check("a create carrying a value that is not caep, risc or a known event " +
        "type URI is refused, naming the value", function () {
          assert.strictEqual(refusedCreate.status, 400, refusedCreate.text);
          assert.ok(/not-an-event/.test(refusedCreate.text) &&
                    /not an event type/.test(refusedCreate.text),
                    refusedCreate.text);
        });
  await ok(realmApi + "/applications/create",
           application(LIMITED, ["oauth2", "ssf"],
                       { ssfAllowedEvents: ["caep", ACCOUNT_DISABLED] }),
           "created the limited application");
  await ok(realmApi + "/applications/create",
           application(FREE, ["oauth2", "ssf"]), "created " +
      "the control");
  await ok(realmApi + "/applications/create",
           application(UNDECLARED, ["oauth2"]), "created " +
      "an OAuth-only entry");
  const undeclared = await call("POST", realmApi + "/applications/add",
    { application: UNDECLARED, attribute: "ssfAllowedEvents", value: "caep" });
  check("ssfAllowedEvents on an entry not declared for Shared Signals is " +
        "refused, naming the family", function () {
    assert.strictEqual(undeclared.status, 400, undeclared.text);
    assert.ok(/Shared Signals/.test(undeclared.text), undeclared.text);
  });
  const badAdd = await call("POST", realmApi + "/applications/add",
    { application: LIMITED, attribute: "ssfAllowedEvents",
      value: RISC + "account-exploded" });
  check("adding an unknown event type URI is refused", function () {
    assert.strictEqual(badAdd.status, 400, badAdd.text);
  });

  log.info("=== 1. agreement: the stream is agreed only what the entry " +
           "allows ===");
  const limited = ssf(await tokenFor(LIMITED));
  const free = ssf(await tokenFor(FREE));
  // No `aud`: it is Transmitter-Supplied (SSF 1.0 section 8.1.1, #144) and
  // each stream is addressed to the application that created it.
  const asked = { delivery: { method: POLL },
                  events_requested: [SESSION_REVOKED, ACCOUNT_DISABLED,
                                     ACCOUNT_PURGED, VERIFICATION] };
  let r = await limited.create(asked);
  check("the limited application's stream is agreed session-revoked, " +
        "account-disabled and SSF's verification event (which no entry has " +
        "to name), not account-purged",
        function () {
          assert.strictEqual(r.status, 201, r.text);
          assert.deepStrictEqual(r.json.events_delivered.slice().sort(),
                                 [ACCOUNT_DISABLED, SESSION_REVOKED,
                                  VERIFICATION].sort());
        });
  const limitedStream = r.json.stream_id;
  r = await free.create(asked);
  check("the control's identical request is agreed all four", function () {
    assert.strictEqual(r.status, 201, r.text);
    assert.deepStrictEqual(r.json.events_delivered.slice().sort(),
                           [ACCOUNT_DISABLED, ACCOUNT_PURGED, SESSION_REVOKED,
                            VERIFICATION].sort());
  });
  const freeStream = r.json.stream_id;
  await limited.drain(limitedStream);
  await free.drain(freeStream);

  log.info("=== 2. delivery follows what was agreed ===");
  const account = usernameFor("ssf-allowed-person");
  await emit("account-disabled", account);
  await emit("account-purged", account);
  let got = await limited.drain(limitedStream);
  let control = await free.drain(freeStream);
  check("the control receives both RISC events — the pipe works", function () {
    assert.ok(control.indexOf(ACCOUNT_DISABLED) >= 0 &&
              control.indexOf(ACCOUNT_PURGED) >= 0, JSON.stringify(control));
  });
  check("the limited stream receives account-disabled and not account-purged",
        function () {
    assert.ok(got.indexOf(ACCOUNT_DISABLED) >= 0, JSON.stringify(got));
    assert.ok(got.indexOf(ACCOUNT_PURGED) < 0, JSON.stringify(got));
  });

  log.info("=== 3. tightening the entry reaches a stream that already exists " +
           "===");
  await ok(realmApi + "/applications/remove",
           { application: LIMITED, attribute: "ssfAllowedEvents",
                                                value: ACCOUNT_DISABLED },
           "removed " +
                                                    "account-disabled");
  r = await limited.read(limitedStream);
  check("the stream's configuration now reports session-revoked and " +
        "verification, and no longer account-disabled", function () {
    assert.strictEqual(r.status, 200, r.text);
    const one = Array.isArray(r.json) ? r.json[0] : r.json;
    assert.deepStrictEqual(one.events_delivered.slice().sort(),
                           [SESSION_REVOKED, VERIFICATION].sort(),
                           JSON.stringify(one));
  });
  await emit("account-disabled", account);
  got = await limited.drain(limitedStream);
  control = await free.drain(freeStream);
  check("an account-disabled emitted now reaches the control and not the " +
        "limited stream", function () {
    assert.ok(control.indexOf(ACCOUNT_DISABLED) >= 0, JSON.stringify(control));
    assert.ok(got.indexOf(ACCOUNT_DISABLED) < 0, JSON.stringify(got));
  });

  log.info("=== 4. SSF's own verification event is always allowed ===");
  r = await limited.verify(limitedStream);
  got = await limited.drain(limitedStream);
  check("a verification event reaches a stream whose entry names only caep " +
        "(SSF's own events are always allowed)",
        function () {
    assert.ok(r.status === 204 || r.status === 200, r.text);
    assert.ok(got.indexOf(VERIFICATION) >= 0, JSON.stringify(got));
  });

  log.info("=== 5. a PATCH is agreed against the entry too ===");
  r = await limited.patch({ stream_id: limitedStream,
                            events_requested: [ACCOUNT_PURGED,
                                               SESSION_REVOKED] });
  check("PATCHing events_requested to account-purged and session-revoked " +
        "agrees only session-revoked", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(r.json.events_delivered, [SESSION_REVOKED]);
  });

  log.info("=== 6. emptying the entry lifts the limit ===");
  await ok(realmApi + "/applications/remove",
           { application: LIMITED, attribute: "ssfAllowedEvents",
                                                value: "caep" }, "removed " +
                                                    "caep, leaving nothing");
  r = await limited.read(limitedStream);
  check("lifting the limit does NOT hand back what was withheld when the " +
        "stream was agreed — the stored agreement is still session-revoked " +
        "alone, and the receiver has to ask again", function () {
          assert.strictEqual(r.status, 200, r.text);
          const one = Array.isArray(r.json) ? r.json[0] : r.json;
          assert.deepStrictEqual(one.events_delivered, [SESSION_REVOKED],
                                 JSON.stringify(one));
        });
  r = await limited.patch({ stream_id: limitedStream,
                            events_requested: [ACCOUNT_PURGED,
                                               SESSION_REVOKED] });
  check("with no values the same PATCH is agreed both", function () {
    assert.strictEqual(r.status, 200, r.text);
    assert.deepStrictEqual(r.json.events_delivered.slice().sort(),
                           [ACCOUNT_PURGED, SESSION_REVOKED].sort());
  });
  await emit("account-purged", usernameFor("ssf-allowed-second"));
  got = await limited.drain(limitedStream);
  check("and an account-purged now reaches it", function () {
    assert.ok(got.indexOf(ACCOUNT_PURGED) >= 0, JSON.stringify(got));
  });

  assert.ok(checks >= 13, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_ssf_allowed_events")
  .description("ssfAllowedEvents on an application entry: a stream the " +
    "application owns is agreed only the Shared Signals event types its " +
    "entry allows, every delivery checks again, and both write refusals.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
