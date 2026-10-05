// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_subject_issuer.js
//
// ---------------------------------------------------------------------------
// AN EVENT AN ADMINISTRATOR RAISES NAMES THE PERSON UNDER THE ISSUER THE
// RECEIVER DISCOVERED — OVER THE WIRE (#154).
//
// A receiver matches an `iss_sub` pair against the issuer it discovered. The
// doors that raise an event with no request in hand — /admin-api's
// set-password, disable and enable — named the person under this process's
// OWN address (`issuerFor(null)`), which behind a published port, a proxy or
// a compose network name is an address no receiver discovered:
// `https://127.0.0.1:8081` inside SETs whose `iss` was
// `https://127.0.0.1:38081`. `tests/ssf_subject_issuer.js` holds the fix in
// process with the published issuer set on the stream by hand; this job is
// the half that runs where the mismatch actually happens — every local mode
// and an AWS target — with the issuer DISCOVERED, as a receiver would:
//
//   0. A throwaway realm (left behind), two receivers, and a person.
//   1. The issuer is read from the realm's SSF configuration at the URL this
//      job reaches the service by.
//   2. Stream A covers everybody (an empty subject list; `ssf.defaultSubjects`
//      is ALL). Stream B ADDS the person as `iss_sub` under the DISCOVERED
//      issuer — before the fix that stream was not even handed the event,
//      because a stream's subject key is the issuer and the subject together.
//   3. set-password, disable and enable through /admin-api.
//   4. Both streams are polled: each receives credential-change,
//      account-disabled and account-enabled about the person, every SET's
//      `iss` is the discovered issuer, and every `iss_sub` in its `sub_id` —
//      at the top or as a complex subject's member — is the SET's `iss`.
//
// Where the service's own address IS the address this job reaches (the
// cluster mode pins `global.publicBaseUrl` to the balancer), the assertions
// hold trivially. Measured 2026-10-05 against one container published on
// 38081 → 8081: 16 checks pass with the fix; without it (develop at
// b2656873) the first credential-change on stream A names the person under
// `https://127.0.0.1:8081/realm/…` in a SET whose `iss` is
// `https://localhost:38081/realm/…`, and the job fails there.
//
// OWNED HERE (local: true): this repository's own transmitter, in a
// throwaway realm it leaves behind.
// ---------------------------------------------------------------------------

const assert = require("assert");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_ssf_subject_issuer",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const REALM = ("ssfiss154-" + STAMP).toLowerCase().replace(/[^a-z0-9-]/g, "")
                                                  .slice(0, 31);
const realmBase = base + "/realm/" + REALM;
const realmApi = realmBase + "/admin-api";
const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const CREDENTIAL_CHANGE = CAEP + "credential-change";
const ACCOUNT_DISABLED = RISC + "account-disabled";
const ACCOUNT_ENABLED = RISC + "account-enabled";
const WANTED = [CREDENTIAL_CHANGE, ACCOUNT_DISABLED, ACCOUNT_ENABLED];
const POLL = "urn:ietf:rfc:8936";
const SECRET = "ssf-iss-154-" + String(Date.now()).slice(-8);
const EVERYBODY = "ssfiss-a-" + STAMP.toLowerCase();
const NAMED = "ssfiss-b-" + STAMP.toLowerCase();
const PERSON = names.usernameFor("ssfiss-alice");
const PASSWORD = "Ssf-154-Passw0rd!-" + String(Date.now()).slice(-6);

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

function application(identifier) {
  log.debug("Entering application().");
  log.debug("Leaving application().");
  return { identifier: identifier, kind: "oauth2-client", name: identifier,
           protocols: ["oauth2", "ssf"],
           // The Shared Signals and SCIM scopes are issued only to a client
           // that declares them (#110).
           fields: { oauthClientId: [identifier],
                     oauthAllowedScope: ["ssf:read", "ssf:write",
                                         "scim:read"],
                     oauthClientSecret: SECRET,
                     oauthTokenEndpointAuthMethod: "client_secret_post",
                     oauthGrantType: ["client_credentials"] } };
}

async function tokenFor(identifier, scope) {
  log.debug("Entering tokenFor().");
  const r = await fetch(realmBase + "/oauth2/token", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials&client_id=" +
          encodeURIComponent(identifier) +
          "&client_secret=" + encodeURIComponent(SECRET) +
          "&scope=" + encodeURIComponent(scope) });
  const json = await r.json();
  assert.ok(json.access_token,
            "a token for " + identifier + ": " + JSON.stringify(json));
  log.debug("Leaving tokenFor().");
  return json.access_token;
}

function decode(token) {
  log.debug("Entering decode().");
  const parts = String(token).split(".");
  log.debug("Leaving decode().");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// Every SET waiting on the stream, decoded, and acknowledged.
async function drain(token, streamId) {
  log.debug("Entering drain().");
  const auth = { Authorization: "Bearer " + token };
  const r = await call("POST", realmBase + "/ssf/poll",
                       { stream_id: streamId, returnImmediately: true,
                         maxEvents: 100 }, auth);
  assert.strictEqual(r.status, 200, "poll: " + r.text.slice(0, 300));
  const sets = (r.json && r.json.sets) || {};
  const jtis = Object.keys(sets);
  if (jtis.length) {
    await call("POST", realmBase + "/ssf/poll",
               { stream_id: streamId, ack: jtis, returnImmediately: true,
                 maxEvents: 0 }, auth);
  }
  log.debug("Leaving drain(). " + jtis.length + " SET(s).");
  return jtis.map(function (jti) {
    return decode(sets[jti]);
  });
}

function typeOf(set) {
  log.debug("Entering typeOf().");
  log.debug("Leaving typeOf().");
  return Object.keys((set && set.events) || {})[0] || "";
}

// Every `iss_sub` in a subject: the subject itself, or a complex subject's
// members.
function issSubsIn(subject) {
  log.debug("Entering issSubsIn().");
  const out = [];
  const one = function (s) {
    if (s && typeof s === "object" && s.format === "iss_sub") {
      out.push(s);
    }
  };
  one(subject);
  if (subject && subject.format === "complex") {
    Object.keys(subject).forEach(function (k) {
      one(subject[k]);
    });
  }
  log.debug("Leaving issSubsIn().");
  return out;
}

// Whether a SET is about the person: an `iss_sub` naming their `sub`.
function aboutPerson(set, sub) {
  log.debug("Entering aboutPerson().");
  log.debug("Leaving aboutPerson().");
  return issSubsIn(set && set.sub_id).some(function (s) {
    return String(s.sub) === sub;
  });
}

// Polls until the stream has handed over every wanted type about the person,
// for at most ten seconds: delivery is on a promise after /admin-api answers,
// and in the cluster mode the poll may reach another node.
async function collect(token, streamId, sub) {
  log.debug("Entering collect().");
  const seen = [];
  for (let i = 0; i < 40; i++) {
    (await drain(token, streamId)).forEach(function (set) {
      seen.push(set);
    });
    const types = seen.filter(function (set) {
      return aboutPerson(set, sub);
    }).map(typeOf);
    if (WANTED.every(function (u) {
      return types.indexOf(u) >= 0;
    })) {
      break;
    }
    await new Promise(function (r) {
      setTimeout(r, 250);
    });
  }
  log.debug("Leaving collect(). " + seen.length + " SET(s).");
  return seen;
}

function hold(label, sets, issuer, sub) {
  log.debug("Entering hold().");
  WANTED.forEach(function (uri) {
    const name = uri.split("/").pop();
    const mine = sets.filter(function (set) {
      return typeOf(set) === uri && aboutPerson(set, sub);
    });
    check(label + ": " + (/^[aeiou]/.test(name) ? "an " : "a ") + name +
          " about the person arrived", function () {
      assert.ok(mine.length > 0, JSON.stringify(sets.map(function (set) {
        return { type: typeOf(set), sub_id: set.sub_id };
      })));
    });
    mine.forEach(function (set) {
      check(label + ": " + name + "'s iss is the discovered issuer, and " +
            "every iss_sub in its sub_id names the person under it",
            function () {
        assert.strictEqual(set.iss, issuer, JSON.stringify(set));
        const named = issSubsIn(set.sub_id);
        assert.ok(named.length > 0 && named.every(function (s) {
          return s.iss === set.iss;
        }), "SET iss " + set.iss + ", sub_id " +
            JSON.stringify(set.sub_id));
      });
    });
  });
  log.debug("Leaving hold().");
}

async function test() {
  log.debug("Entering test().");
  log.info("Driving the subject's issuer at " + realmBase);

  log.info("=== 0. the realm, two receivers and a person ===");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "SSF subject issuer " + STAMP },
    "created the realm");
  await ok(realmApi + "/applications/create", application(EVERYBODY),
           "created receiver A");
  await ok(realmApi + "/applications/create", application(NAMED),
           "created receiver B");
  await ok(realmApi + "/users/create", { username: PERSON, invent: false,
    credential: "password", password: PASSWORD,
    attributes: { cn: "SSF " + PERSON, givenName: "SSF", sn: "Issuer",
                  mail: PERSON + "@ssfiss154.test" } }, "created " + PERSON);
  const tokenA = await tokenFor(EVERYBODY, "ssf:read ssf:write scim:read");
  const tokenB = await tokenFor(NAMED, "ssf:read ssf:write");
  const listed = await call("GET", realmBase + "/scim/v2/Users?filter=" +
    encodeURIComponent("userName eq \"" + PERSON + "\""), undefined,
    { Authorization: "Bearer " + tokenA });
  const scimId = listed.json && listed.json.Resources &&
                 listed.json.Resources[0] && listed.json.Resources[0].id;
  check("the person's sub is read through SCIM (urn:uuid:<entryUUID>)",
        function () {
    assert.ok(scimId, listed.status + " " + listed.text.slice(0, 300));
  });
  const SUB = "urn:uuid:" + scimId;

  log.info("=== 1. the issuer, discovered as a receiver discovers it ===");
  const discovered = await call("GET",
                                realmBase + "/.well-known/ssf-configuration");
  const ISSUER = String((discovered.json && discovered.json.issuer) || "");
  check("the realm's SSF configuration publishes an issuer", function () {
    assert.strictEqual(discovered.status, 200, discovered.text.slice(0, 300));
    assert.ok(/^https?:\/\//.test(ISSUER), discovered.text.slice(0, 300));
  });
  // The service's OWN address (`issuerFor(null)`) is not visible from here;
  // in every stack but the cluster mode it is not this one.
  log.info("  discovered issuer " + ISSUER);

  log.info("=== 2. stream A about everybody, stream B naming the person " +
           "under the discovered issuer ===");
  const asked = { delivery: { method: POLL }, events_requested: WANTED };
  const a = await call("POST", realmBase + "/ssf/stream", asked,
                       { Authorization: "Bearer " + tokenA });
  const b = await call("POST", realmBase + "/ssf/stream", asked,
                       { Authorization: "Bearer " + tokenB });
  check("both poll streams are created, agreed all three types, under the " +
        "discovered issuer", function () {
    [a, b].forEach(function (r) {
      assert.strictEqual(r.status, 201, r.text.slice(0, 400));
      assert.deepStrictEqual(r.json.events_delivered.slice().sort(),
                             WANTED.slice().sort(), r.text.slice(0, 400));
      assert.strictEqual(r.json.iss, ISSUER, r.text.slice(0, 400));
    });
  });
  const streamA = a.json.stream_id;
  const streamB = b.json.stream_id;
  const added = await call("POST", realmBase + "/ssf/subjects/add",
    { stream_id: streamB,
      subject: { format: "iss_sub", iss: ISSUER, sub: SUB },
      verified: true }, { Authorization: "Bearer " + tokenB });
  check("stream B adds the person as iss_sub under the discovered issuer",
        function () {
    assert.ok(added.status === 200 || added.status === 204,
              added.status + " " + added.text.slice(0, 300));
  });
  // Whatever creating the person sent is not what this job is about.
  await drain(tokenA, streamA);
  await drain(tokenB, streamB);

  log.info("=== 3. set-password, disable and enable through /admin-api ===");
  await ok(realmApi + "/users/set-password",
           { user: PERSON, generate: true }, "set the password");
  await ok(realmApi + "/users/disable", { user: PERSON }, "disabled");
  await ok(realmApi + "/users/enable", { user: PERSON }, "enabled");

  log.info("=== 4. every SET names the person under its own iss ===");
  hold("A (everybody)", await collect(tokenA, streamA, SUB), ISSUER, SUB);
  hold("B (the person, added under the discovered issuer)",
       await collect(tokenB, streamB, SUB), ISSUER, SUB);

  assert.ok(checks >= 12, "only " + checks + " checks ran; a section has " +
                                             "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_ssf_subject_issuer")
  .description("An administrator's set-password, disable and enable send " +
    "CAEP and RISC events naming the person under the issuer a receiver " +
    "discovered (#154), on a stream about everybody and on one that added " +
    "the person under that issuer.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
