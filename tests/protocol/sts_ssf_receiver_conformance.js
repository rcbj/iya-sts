// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_ssf_receiver_conformance.js
//
// ---------------------------------------------------------------------------
// THE OPENID FOUNDATION'S CONFORMANCE SUITE: SHARED SIGNALS RECEIVER (#932,
// 2026-11-02). `openid-ssf-receiver-test-plan` and
// `openid-ssf-receiver-caep-test-plan` (the CAEP Interop Profile), each by
// push and by poll, against this service as the RECEIVER, on the containers
// `sts_fapi_conformance.js` (#176) brought into the stack. The suite plays
// the TRANSMITTER: each module publishes a configuration document, a JWKS,
// a token endpoint, stream management and a poll endpoint under its own
// issuer, and waits for the receiver to act. `sts_ssf_oidf_conformance.js`
// (#187) is the other direction.
//
//   1. Per plan a throwaway realm with a person, and a SIGNALS-ONLY
//      federation relationship (`ssf`, #374) to the suite's transmitter:
//      client credentials at the suite's token endpoint (client_secret_post,
//      the plans' dynamic auth mode), the suite's certificate as
//      `federation.outboundCaFile`, `fedSignalEmailMatch` on, and the person
//      linked under the iss_sub subject the suite is told to send. The suite
//      is told the person's `email` and that `iss_sub` (the interop profile
//      wants both formats, section 2.5).
//   2. The realm's `signal-response` policy is the built-in template with
//      `signalsOnlyEndSessionEvents` set to session-revoked and
//      credential-change: a signals-only partner's word is RECORDED and
//      nothing more by default (#374, rcbj's decision), so the effect the
//      ticket asks the job to assert is the one an operator turns on, through
//      the policy, as the documentation says. `ssf.actOnSignalsInDevelopment`
//      is on, since the conformance modes are development ones.
//   3. Each module waits for the receiver's ACTS, and this job is the
//      administrator pressing them, through `/admin-api/federation/signals-*`
//      (the relationship page's buttons): discover (the module's keys are
//      new), create the stream, and then what the module waits for — read,
//      update, replace, status, verify, poll, delete.
//   4. THE EFFECT, not only the acknowledgement: before the module that
//      sends the CAEP events (`openid-ssf-receiver-stream-supported-events`
//      and `openid-ssf-receiver-stream-caep-interop`) the person signs in
//      for real; afterwards the person holds no live session and the
//      realm's inbox records `signal-end-person-sessions` done for the
//      session-revoked. A missing effect fails the job like a FAILED module.
//   5. The ledger is `conformance_suite.js`'s.
//
// NO CLASSICAL TWIN, AND WHY. The twins (`conformance_suite.js`, THE
// CLASSICAL TWINS) exist where the suite cannot read this service's
// post-quantum keys. In these plans the suite reads none: it signs every SET
// itself (RS256) and this service verifies; the token request authenticates
// with a client secret; nothing this realm signs reaches the suite. So no
// post-quantum entry is in the ledger and the run is already the classical
// proof — the FAPI job's position.
//
// OWNED HERE (local: true): this repository's SSF receiver.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const { Command, Option } = require("commander");
const names = require("./random_username.js");
const registry = require("./sts_applications.js");
const oidf = require("./conformance_suite.js");

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
var log = bunyan.createLogger({ name: "sts_ssf_receiver_conformance",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var root = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const STAMP = names.runStamp();
const TAG = STAMP.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 10);
const PASSWORD = "Conf-Passw0rd!-" + String(Date.now()).slice(-6);
const REDIRECT = "https://receiver.invalid/callback";
const RELATIONSHIP = "oidf-transmitter";
// The issuer of the iss_sub subject the suite is told to send: an HR feed's,
// which is the kind of partner a signals-only relationship is for. An
// administrator links the person under it (#374).
const HR_ISSUER = "https://hr.conformance.test";
// How long the job waits for one thing a module does (a verification, the
// events) before it stops waiting and lets the module's own deadline judge.
const WAIT_MS = 150000;

const CAEP = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC = "https://schemas.openid.net/secevent/risc/event-type/";
const SSF = "https://schemas.openid.net/secevent/ssf/event-type/";
// The CAEP Interop Profile's three (section 3), which its plan delivers.
const INTEROP_EVENTS = [CAEP + "session-revoked", CAEP + "credential-change",
                        CAEP + "device-compliance-change"];
// Every event the default plan's transmitter can generate a SET for.
const ALL_EVENTS = ["session-revoked", "token-claims-change",
  "credential-change", "assurance-level-change", "device-compliance-change",
  "session-established", "session-presented", "risk-level-change"]
  .map(function (e) {
    return CAEP + e;
  }).concat(["account-credential-change-required", "account-purged",
    "account-disabled", "account-enabled", "identifier-changed",
    "identifier-recycled", "credential-compromise", "opt-in",
    "opt-out-initiated", "opt-out-cancelled", "opt-out-effective",
    "recovery-activated", "recovery-information-changed",
    "sessions-revoked"].map(function (e) {
    return RISC + e;
  })).concat([SSF + "stream-updated"]);

const COMMON = { ssf_auth_mode: "dynamic",
                 client_auth_type: "client_secret_post" };
const PLANS = [
  { key: "rx-ssf-push", name: "openid-ssf-receiver-test-plan",
    delivery: "push", events: ALL_EVENTS,
    variant: Object.assign({ ssf_delivery_mode: "push",
                             ssf_profile: "default" }, COMMON) },
  { key: "rx-ssf-poll", name: "openid-ssf-receiver-test-plan",
    delivery: "poll", events: ALL_EVENTS,
    variant: Object.assign({ ssf_delivery_mode: "poll",
                             ssf_profile: "default" }, COMMON) },
  { key: "rx-caep-push", name: "openid-ssf-receiver-caep-test-plan",
    delivery: "push", events: INTEROP_EVENTS,
    variant: Object.assign({ ssf_delivery_mode: "push" }, COMMON) },
  { key: "rx-caep-poll", name: "openid-ssf-receiver-caep-test-plan",
    delivery: "poll", events: INTEROP_EVENTS,
    variant: Object.assign({ ssf_delivery_mode: "poll" }, COMMON) }
];

// A module the suite judged FAILED, argued (none yet).
const EXPECTED = {};
// Conditions whose WARNING is kept, and why (none yet).
const KNOWN_WARNINGS = {};
// Conditions whose FAILURE is argued (none yet).
const KNOWN_FAILURES = {};

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE REALM (header points 1 and 2).
// ---------------------------------------------------------------------------
async function prepare(plan) {
  log.debug("Entering prepare(). " + plan.key);
  const id = ("ssfr-" + plan.key.replace(/^rx-/, "") + "-" + TAG)
    .slice(0, 31).replace(/-+$/, "");
  const realm = await oidf.makeRealm(root, id, "Conformance " + plan.name, [
    ["oauth2.openRegistration", true],
    ["federation.outboundCaFile", oidf.suiteCaFile()],
    ["ssf.actOnSignalsInDevelopment", true]]);
  const person = names.usernameFor("conf-" + plan.key);
  await oidf.makePerson(realm.api, person, PASSWORD);
  const mail = person + "@conformance.test";
  const registered = await oidf.send(realm.base + "/oauth2/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "conformance sign-in " + plan.key,
      grant_types: ["authorization_code"], response_types: ["code"],
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: "client_secret_post" }) });
  assert.strictEqual(registered.status, 201, plan.key + " client: " +
                     registered.raw.slice(0, 400));
  // THE EFFECT AN OPERATOR TURNS ON (header point 2): the built-in
  // signal-response template, with a signals-only partner's session-revoked
  // and credential-change ending the person's sessions, chosen by name.
  const policy = "conf-signal-response";
  await oidf.ok(realm.api + "/xacml/create-from-template", {
    template: "signal-response", name: policy,
    p_signalsOnlyEndSessionEvents: "session-revoked, credential-change" },
    "built the signal-response policy");
  await oidf.ok(realm.api + "/config/set", {
    key: "xacml.signalResponsePolicy", value: policy },
    "chose the signal-response policy");
  const alias = "iya-" + plan.key + "-" + TAG;
  // The suite's transmitter answers under its base URL for the alias; the
  // job checks this against what the first module exposes and follows that.
  const issuer = oidf.SUITE + "test/a/" + alias;
  const sub = "emp-" + crypto.randomBytes(6).toString("hex");
  const client = { id: "iya-rx-" + plan.key,
                   secret: crypto.randomBytes(24).toString("base64url") };
  await oidf.ok(realm.api + "/federation/create", { id: RELATIONSHIP,
    role: "service-provider", protocol: "ssf", peer: issuer,
    name: "The conformance suite's transmitter" },
    "registered the relationship");
  const fields = [["fedSignalsClientId", client.id],
                  ["fedSignalsClientSecret", client.secret],
                  ["fedSignalsScope", "ssf.read ssf.manage"],
                  ["fedSignalsDelivery", plan.delivery],
                  ["fedSignalEmailMatch", "TRUE"]];
  for (const [field, value] of fields) {
    await oidf.ok(realm.api + "/federation/set", { id: RELATIONSHIP,
      field: field, value: value }, "set " + field);
  }
  for (const event of plan.events) {
    await oidf.ok(realm.api + "/federation/add-value", { id: RELATIONSHIP,
      field: "fedSignalsEvents", value: event }, "asked for " + event);
  }
  await oidf.ok(realm.api + "/users/federation-link", { user: person,
    relationship: RELATIONSHIP, issuer: HR_ISSUER, subject: sub },
    "linked " + person + " under " + HR_ISSUER);
  await oidf.ok(realm.api + "/federation/enable", { id: RELATIONSHIP },
                "enabled the relationship");
  const configuration = {
    alias: alias,
    description: "iya-sts " + plan.name + " " + STAMP,
    ssf: {
      stream: { audience: realm.base },
      subjects: { valid: [{ format: "email", email: mail },
                          { format: "iss_sub", iss: HR_ISSUER, sub: sub }] }
    },
    client: { client_id: client.id, client_secret: client.secret,
              scope: "ssf.read ssf.manage" }
  };
  log.debug("Leaving prepare().");
  return { realm: realm, person: person, clientId: registered.body.client_id,
           issuer: issuer, configuration: configuration };
}

// ---------------------------------------------------------------------------
// THE ADMINISTRATOR'S ACTS (header point 3).
// ---------------------------------------------------------------------------
async function signals(prepared, action, extra) {
  log.debug("Entering signals(). " + action);
  const r = await oidf.send(prepared.realm.api + "/federation/" + action, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ id: RELATIONSHIP }, extra || {})) });
  const done = r.status === 200 && r.body && r.body.ok !== false;
  log.info("    " + action + ": " + (done ? "ok" : r.status + " " +
           JSON.stringify((r.body && r.body.errors) || r.raw).slice(0, 300)));
  log.debug("Leaving signals(). " + done);
  return { ok: done, body: r.body || {} };
}

async function report(prepared) {
  log.debug("Entering report().");
  const r = await oidf.send(prepared.realm.api + "/ssf/transmitters");
  log.debug("Leaving report(). " + r.status);
  return r.body || {};
}

async function arrivals(prepared) {
  log.debug("Entering arrivals().");
  const got = (await report(prepared)).received || [];
  log.debug("Leaving arrivals(). " + got.length);
  return got.filter(function (row) {
    return row && row.relationship === RELATIONSHIP;
  });
}

async function moduleStatus(id) {
  log.debug("Entering moduleStatus(). " + id);
  const info = (await oidf.suite("GET", "api/info/" + id)).body || {};
  log.debug("Leaving moduleStatus(). " + info.status);
  return String(info.status || "");
}

async function moduleSaid(id, pattern) {
  log.debug("Entering moduleSaid().");
  const logs = (await oidf.suite("GET", "api/log/" + id)).body || [];
  log.debug("Leaving moduleSaid().");
  return logs.some(function (entry) {
    return pattern.test(String(entry.msg || ""));
  });
}

// Polls (a poll stream) and waits until `until()` holds or the module ends.
async function deliverUntil(prepared, plan, id, what, until) {
  log.debug("Entering deliverUntil(). " + what);
  const deadline = Date.now() + WAIT_MS;
  while (Date.now() < deadline) {
    if (plan.delivery === "poll") {
      await signals(prepared, "signals-poll-now");
    }
    if (await until()) {
      log.debug("Leaving deliverUntil(). " + what);
      return true;
    }
    const status = await moduleStatus(id);
    if (status === "FINISHED" || status === "INTERRUPTED") {
      log.debug("Leaving deliverUntil(). The module ended.");
      return false;
    }
    await oidf.waitMs(1500);
  }
  log.info("    gave up waiting for " + what);
  log.debug("Leaving deliverUntil(). Gave up.");
  return false;
}

// The transmitter the module exposes: its issuer and token endpoint. The
// relationship follows them when they are not what prepare() assumed.
async function followTransmitter(prepared, id) {
  log.debug("Entering followTransmitter(). " + id);
  const exposed = await oidf.exposed(id);
  const issuer = String(exposed.ssf_issuer || prepared.issuer);
  const tokenUrl = String(exposed.ssf_token_endpoint || issuer + "/token");
  if (issuer !== prepared.issuer) {
    log.info("    the transmitter's issuer is " + issuer);
    await oidf.ok(prepared.realm.api + "/federation/set", { id: RELATIONSHIP,
      field: "fedSignalsIssuer", value: issuer }, "set fedSignalsIssuer");
    prepared.issuer = issuer;
  }
  if (tokenUrl !== prepared.tokenUrl) {
    await oidf.ok(prepared.realm.api + "/federation/set", { id: RELATIONSHIP,
      field: "fedSignalsTokenUrl", value: tokenUrl },
      "set fedSignalsTokenUrl");
    prepared.tokenUrl = tokenUrl;
  }
  log.debug("Leaving followTransmitter().");
}

async function liveSessions(prepared) {
  log.debug("Entering liveSessions().");
  const r = await oidf.send(prepared.realm.api + "/sessions?per=500&q=" +
                            encodeURIComponent(prepared.person));
  const rows = (r.body && (r.body.sessions || r.body.rows)) || [];
  const key = prepared.person.toLowerCase();
  log.debug("Leaving liveSessions().");
  return rows.filter(function (row) {
    return String(row.username || row.key || "").toLowerCase() === key &&
           !/ldap|kerberos/i.test(String(row.protocol || ""));
  });
}

// The person signs in for real, so the CAEP events have a session to end.
async function signIn(prepared) {
  log.debug("Entering signIn().");
  await registry.authorizationCode(prepared.realm.base, {
    clientId: prepared.clientId, redirectUri: REDIRECT,
    username: prepared.person, password: PASSWORD, scope: "openid" });
  const live = await liveSessions(prepared);
  log.info("    " + prepared.person + " signed in (" + live.length +
           " live session(s))");
  log.debug("Leaving signIn().");
  return live.length;
}

// THE EFFECT (header point 4): the person's sessions are gone, and the
// inbox says the session-revoked ended them. ONLY THIS MODULE'S ARRIVALS
// COUNT (2026-11-04): `before` is the inbox as the module started, and a
// row already in it — the previous module's session-revoked, done — is not
// this module's. Matching it made a module whose events never arrived
// report "reaction recorded done: true" beside a live session.
async function effectOf(prepared, plan, liveBefore, findings, before) {
  log.debug("Entering effectOf().");
  // Keyed by the SET's jti, which a row keeps while its reactions are
  // written; a row with none is keyed by its arrival time.
  const keyOf = function keyOf(row) {
    log.debug("Entering keyOf().");
    log.debug("Leaving keyOf().");
    return String(row.jti || row.receivedAt || "");
  };
  const earlier = new Set((before || []).map(keyOf));
  let live = null;
  let ended = false;
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    live = await liveSessions(prepared);
    ended = (await arrivals(prepared)).filter(function (row) {
      return !earlier.has(keyOf(row));
    }).some(function (row) {
      return (row.events || []).indexOf(CAEP + "session-revoked") >= 0 &&
             row.person === prepared.person && row.verified === true &&
             (row.reactions || []).some(function (x) {
               return x.reaction === "signal-end-person-sessions" && x.done;
             });
    });
    if (ended && live.length === 0) {
      break;
    }
    await oidf.waitMs(1000);
  }
  if (!(liveBefore > 0 && ended && live.length === 0)) {
    findings.push(plan.key + ": the CAEP session-revoked did not end " +
      prepared.person + "'s sessions (" + liveBefore + " before, " +
      (live ? live.length : "?") + " after; a reaction to this module's " +
      "session-revoked recorded done: " + ended + ")");
  } else {
    log.info("    the session-revoked ended " + prepared.person + "'s " +
             liveBefore + " session(s), verified and recorded");
  }
  log.debug("Leaving effectOf().");
}

// What one module waits for, played once, while runModule() watches it.
async function operate(prepared, plan, id, moduleName, findings) {
  log.debug("Entering operate(). " + moduleName);
  log.info("  operating " + moduleName + " (" + id + ")");
  await followTransmitter(prepared, id);
  // A stream left over (runOne() deletes each once its module ended) would
  // be asked about at a module that never created it, and fail there.
  if (await heldStream(prepared)) {
    findings.push(plan.key + ": a stream was still held when " + moduleName +
                  " started");
  }
  await signals(prepared, "signals-discover");
  const created = await signals(prepared, "signals-create-stream");
  if (!created.ok) {
    log.debug("Leaving operate(). No stream.");
    return;
  }
  const short = moduleName.replace(/^openid-ssf-receiver-/, "");
  const inboxBefore = await arrivals(prepared);
  const seenBefore = inboxBefore.length;
  if (short === "happypath") {
    await signals(prepared, "signals-read-stream");
    await signals(prepared, "signals-update-stream");
    await signals(prepared, "signals-replace-stream");
    await signals(prepared, "signals-delete-stream");
  } else if (short === "stream-create-delete") {
    await signals(prepared, "signals-delete-stream");
  } else if (short === "stream-status-update") {
    await signals(prepared, "signals-set-status",
                  { status: "paused", reason: "conformance" });
    await signals(prepared, "signals-delete-stream");
  } else if (short === "stream-verification") {
    await signals(prepared, "signals-verify");
    await deliverUntil(prepared, plan, id, "the verification",
      async function () {
        const view = (await report(prepared)).relationships || [];
        return view.some(function (r) {
          return r.relationship === RELATIONSHIP && !!r.verifiedAt;
        });
      });
    await signals(prepared, "signals-delete-stream");
  } else if (short === "unsolicited-stream-verification") {
    await deliverUntil(prepared, plan, id, "the unsolicited verification",
      async function () {
        return (await arrivals(prepared)).some(function (row) {
          return (row.reactions || []).some(function (x) {
            return x.event === "verification" &&
                   /transmitter-initiated/.test(String(x.why || ""));
          });
        });
      });
    await signals(prepared, "signals-delete-stream");
  } else if (short === "stream-supported-events" ||
             short === "stream-caep-interop") {
    const liveBefore = await signIn(prepared);
    if (short === "stream-caep-interop") {
      await signals(prepared, "signals-read-stream");
      await signals(prepared, "signals-read-status");
    }
    await signals(prepared, "signals-verify");
    // Every event delivered once per subject, and acknowledged: the
    // supported-events module says so; the interop module ends.
    await deliverUntil(prepared, plan, id, "the events", async function () {
      return short === "stream-caep-interop"
        ? (await moduleStatus(id)) === "FINISHED"
        : await moduleSaid(id, /Detected expected delivery & ack/);
    });
    log.info("    " + ((await arrivals(prepared)).length - seenBefore) +
             " SET(s) arrived");
    await effectOf(prepared, plan, liveBefore, findings, inboxBefore);
    if (short === "stream-supported-events") {
      await signals(prepared, "signals-delete-stream");
    }
  } else {
    findings.push(plan.key + ": no operator for " + moduleName);
  }
  log.debug("Leaving operate(). " + short);
}

// The stream this realm holds at the suite, if any.
async function heldStream(prepared) {
  log.debug("Entering heldStream().");
  const view = ((await report(prepared)).relationships || [])
    .filter(function (r) {
      return r.relationship === RELATIONSHIP;
    })[0] || {};
  log.debug("Leaving heldStream(). " + (view.streamId || "none"));
  return String(view.streamId || "");
}

// A module, its operator beside it, and the stream deleted once the module
// has ended — while the suite answers a finished module's requests with
// nothing, so the NEXT module never sees a request about a stream it did
// not create (its stream endpoints log a failure for one).
async function runOne(planId, module, plan, prepared, findings) {
  log.debug("Entering runOne(). " + module.testModule);
  const operated = {};
  const got = await oidf.runModule(planId, module, async function (id, info) {
    if (operated[id] || info.status !== "WAITING") {
      return;
    }
    operated[id] = true;
    await operate(prepared, plan, id, module.testModule, findings);
  });
  if (await heldStream(prepared)) {
    await signals(prepared, "signals-delete-stream");
  }
  log.debug("Leaving runOne(). " + (got.result || got.status));
  return got;
}

async function runPlan(plan, prepared, findings) {
  log.debug("Entering runPlan(). " + plan.key);
  const created = await oidf.suite("POST", "api/plan?planName=" +
    encodeURIComponent(plan.name) + "&variant=" +
    encodeURIComponent(JSON.stringify(plan.variant)),
    prepared.configuration);
  assert.ok(created.status === 201 || created.status === 200,
            "creating " + plan.name + ": " + created.raw.slice(0, 400));
  const results = [];
  const modules = created.body.modules || [];
  for (let i = 0; i < modules.length; i++) {
    let got = await runOne(created.body.id, modules[i], plan, prepared,
                           findings);
    // conformance_suite.js's runPlan(): a module that timed out runs once
    // more; a verdict never does.
    if (got.status === "TIMED OUT") {
      log.info("  " + plan.key + " " + got.module + ": TIMED OUT; running " +
               "it once more.");
      got = await runOne(created.body.id, modules[i], plan, prepared,
                         findings);
    }
    log.info("  " + plan.key + " " + got.module + ": " +
             (got.result || got.status) +
             (got.failures.length ? " — " + got.failures[0].src + ": " +
                                    got.failures[0].msg : ""));
    results.push(got);
  }
  log.debug("Leaving runPlan().");
  return { planId: created.body.id, results: results };
}

async function test() {
  log.debug("Entering test().");
  if (await registry.isProduct(root)) {
    log.info("A product-mode service dials no internal address, and the " +
             "suite's transmitter is one; the conformance modes are " +
             "development ones (tests/CLAUDE.md).");
  }
  await oidf.waitForSuite();
  const unexpected = [];
  for (const plan of PLANS) {
    if (!oidf.selected(plan.key)) {
      continue;
    }
    log.info("=== " + plan.name + " " + JSON.stringify(plan.variant) +
             " (" + plan.key + ") ===");
    const findings = [];
    let ran = null;
    try {
      ran = await runPlan(plan, await prepare(plan), findings);
    } catch (e) {
      log.error("Caught in test(): " + plan.key + ": " +
                ((e && e.message) || e));
      unexpected.push(plan.key + " could not run: " +
                      ((e && e.message) || e));
      continue;
    }
    const judged = oidf.judge(plan.key, ran, EXPECTED, KNOWN_WARNINGS,
                              KNOWN_FAILURES);
    log.info("  " + plan.key + ": " + JSON.stringify(judged.counts) +
             ", plan " + oidf.SUITE + "plan-detail.html?plan=" + ran.planId);
    judged.unexplained.concat(findings).forEach(function (line) {
      unexpected.push(line);
    });
  }
  if (unexpected.length) {
    log.error("Unexplained:\n  " + unexpected.join("\n  "));
  }
  check("every module passed or is argued, every warning is known, and " +
        "every CAEP session-revoked ended the person's sessions",
        function () {
          assert.strictEqual(unexpected.length, 0, unexpected.join("\n"));
        });
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

new Command()
  .description("The OpenID Foundation conformance suite's Shared Signals " +
    "receiver plans (#932), push and poll, against this service.")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
