// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_report_sources.js
//
// ---------------------------------------------------------------------------
// TWO REPORT SOURCES OVER REAL ROWS: passkeyCeremonies (#1107) AND
// postLoginProgress (#1110).
//
// D12 (#444): carries over `tests/report_passkey_ceremonies.js` and
// `tests/report_post_login.js`. In a throwaway realm, a person in
// report-admins reads both sources through the reporting application's
// DPoP-bound token:
//
//   P. passkeyCeremonies: the catalog's fields are exactly the row
//      projection's, none indexed and not anchored, the door field names
//      every door, the categorical fields group; the three predefined
//      queries are published and each runs (A, C, E). Then a REAL path
//      (D): a console administrator enrols a passkey for a person through
//      /admin-api's admin-enrolment door with this file's own ES256 `none`
//      authenticator, and a second enrolment answering another challenge
//      is refused — both are registrations at admin-enrolment in the
//      source, the success with its algorithm, the refusal with its error
//      code, and no row carries an address or a summary (B).
//   L. postLoginProgress: the fields, not anchored, `progress` one of five
//      words and groupable, the three presets each one the form can draw
//      (A); with the realm's post-login activity on for people with no
//      passkey, two people are asked at a sign-in and press Skip — each a
//      row: snoozed, one ask, one skip, asked by the policy, a week's
//      snooze and no deadline — and somebody never asked has none (B); the
//      presets count two snoozed, nobody past grace, the two who skipped
//      (C); a limit of one answers one (D).
//
// NOT carried, and why: the projection of invented ring rows — a mismatch
// row, the pre-#1108 shape, Chrome/Firefox/Edge clients, ML-DSA lanes — and
// of invented progress rows (past grace, done, mailed by a started activity,
// a row from before #1110) on a moved clock (class (d): no authenticator
// here makes an ML-DSA passkey, no browser names those clients, and the
// clock does not move over the wire); the walk stopping inside
// `eachProgressAsync()` and `scanAsync()` (internal); the New Query form
// drawing a preset (the browser bundle, class (d)); STS-AUTHN-0022, a
// browser REPORTING a failed ceremony (no browser here; the refused row
// carries the finish's own code).
//
// OWNED HERE (local: true): this repository's own reports API.
// ---------------------------------------------------------------------------

const assert = require("assert");
const crypto = require("crypto");
const names = require("./random_username.js");
const reportSignin = require("./report_signin.js");
const consoleSignin = require("./console_signin.js");

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
var log = bunyan.createLogger({ name: "sts_report_sources",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
var ORIGIN = new URL(base).origin;
var RP_ID = new URL(base).hostname;
const STAMP = names.runStamp().toLowerCase().replace(/[^a-z0-9]/g, "")
  .slice(-10);
const REALM = "rsrc-" + STAMP;
const RB = base + "/realm/" + REALM;
const PASSWORD = "Rsrc-" + STAMP + "-Aa1!-pass";
const READER = "rsrc-reader-" + STAMP;
const HOLDER = "rsrc-holder-" + STAMP;
const SKIPPER = "rsrc-skipper-" + STAMP;
const ENROLLER = "rsrc-enroller-" + STAMP;
// The row projection's fields, in the catalog's order (#943, #1108).
const CEREMONY_FIELDS = ["timestamp", "day", "kind", "ceremony", "door",
  "outcome", "errorCode", "actor", "application", "role", "lane", "offered",
  "offerRule", "offeredFirst", "postQuantumOffered", "algorithm",
  "postQuantum", "held", "client", "clientError", "capabilities",
  "attachment", "transports", "attestation", "durationMs"];

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

// One call to the realm's /report-api with the session's DPoP-bound token
// and a fresh proof, retried once on a nonce the resource server asks for.
async function api(session, method, path, body) {
  log.debug("Entering api(). " + method + " " + path);
  const url = RB + "/report-api" + path;
  let r = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const headers = { Accept: "application/json",
      Authorization: "DPoP " + session.token,
      DPoP: session.key.proof(method, url, session.token) };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const raw = await fetch(url, { method: method, headers: headers,
      body: body === undefined ? undefined : JSON.stringify(body) });
    session.key.keepNonce(raw);
    const text = await raw.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      log.debug("Caught in api(): " + ((e && e.message) || e));
      // Not JSON; the caller reads `text`.
      json = null;
    }
    r = { status: raw.status, text: text, json: json };
    if (!(raw.status === 401 && /use_dpop_nonce/.test(
      String(raw.headers.get("www-authenticate") || "") + text))) {
      break;
    }
  }
  log.debug("Leaving api(). " + r.status);
  return r;
}

function brief(r) {
  log.debug("Entering brief().");
  log.debug("Leaving brief().");
  return r.status + " " + String(r.text || r.raw || "").slice(0, 300);
}

async function codeCount(code) {
  log.debug("Entering codeCount(). " + code);
  const r = await send(RB + "/admin-api/audit?per=500&code=" +
                       encodeURIComponent(code));
  log.debug("Leaving codeCount().");
  return Number((r.body && r.body.matched) || 0);
}

async function codesSettle(code, atLeast) {
  log.debug("Entering codesSettle(). " + code);
  let n = await codeCount(code);
  for (let i = 0; i < 20 && n < atLeast; i += 1) {
    await sleep(150);
    n = await codeCount(code);
  }
  log.debug("Leaving codesSettle(). " + n);
  return n;
}

// A person with a password, in the groups given.
async function person(name, groups, cn) {
  log.debug("Entering person(). " + name);
  await ok(RB + "/admin-api/users/create", { username: name, invent: false,
    attributes: { cn: cn || ("Person " + name), givenName: "Report",
                  sn: name, mail: name + "@" + REALM + ".example.net" },
    credential: "password", password: PASSWORD }, "created " + name);
  for (const group of groups || []) {
    await ok(RB + "/admin-api/groups/add-member", { group: group,
      member: name }, "put " + name + " in " + group);
  }
  log.debug("Leaving person().");
}

// ---------------------------------------------------------------------------
// CBOR, encode only, and an ES256 `none` authenticator: the shape
// sts_passkey_bulk_enrolment.js's is, written again here.
// ---------------------------------------------------------------------------
function cborHead(major, n) {
  log.debug("Entering cborHead().");
  let out;
  if (n < 24) {
    out = Buffer.from([(major << 5) | n]);
  } else if (n < 256) {
    out = Buffer.from([(major << 5) | 24, n]);
  } else {
    out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(n, 1);
  }
  log.debug("Leaving cborHead().");
  return out;
}

function cbor(value) {
  log.debug("Entering cbor().");
  let out;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const b = Buffer.from(value);
    out = Buffer.concat([cborHead(2, b.length), b]);
  } else if (typeof value === "string") {
    const b = Buffer.from(value, "utf8");
    out = Buffer.concat([cborHead(3, b.length), b]);
  } else if (typeof value === "number") {
    out = value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  } else {
    const entries = Array.from(value.entries());
    out = Buffer.concat([cborHead(5, entries.length)].concat(
      entries.map(function (kv) {
        return Buffer.concat([cbor(kv[0]), cbor(kv[1])]);
      })));
  }
  log.debug("Leaving cbor().");
  return out;
}

function sha256(buf) {
  log.debug("Entering sha256().");
  log.debug("Leaving sha256().");
  return crypto.createHash("sha256").update(buf).digest();
}

// One registration of a fresh ES256 credential for the challenge given.
function registration(challenge) {
  log.debug("Entering registration().");
  const credentialId = crypto.randomBytes(32);
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const cose = new Map([[1, 2], [3, -7], [-1, 1],
                         [-2, Buffer.from(jwk.x, "base64url")],
                         [-3, Buffer.from(jwk.y, "base64url")]]);
  const idLen = Buffer.alloc(2);
  idLen.writeUInt16BE(credentialId.length, 0);
  const authData = Buffer.concat([sha256(Buffer.from(RP_ID, "utf8")),
    Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), idLen,
    credentialId, cbor(cose)]);
  const attestationObject = cbor(new Map([["fmt", "none"],
    ["attStmt", new Map()], ["authData", authData]]));
  const id = credentialId.toString("base64url");
  log.debug("Leaving registration().");
  return {
    id: id, rawId: id, type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: { credProps: { rk: true } },
    response: {
      attestationObject: attestationObject.toString("base64url"),
      clientDataJSON: Buffer.from(JSON.stringify({
        type: "webauthn.create", challenge: challenge,
        origin: ORIGIN, crossOrigin: false }), "utf8").toString("base64url"),
      transports: ["internal"] } };
}

// A preset run as the page runs one: answered at once, or — a limit over
// the realm's sync cap in auto mode — queued, waited for and its result
// read. Answers the rows' answer either way.
async function runAnswered(session, document) {
  log.debug("Entering runAnswered().");
  let r = await api(session, "POST", "/queries", document);
  if (r.status === 202 && r.json && r.json.job) {
    const id = r.json.job.id;
    for (let i = 0; i < 120; i += 1) {
      const job = await api(session, "GET", "/jobs/" + id);
      if (job.json && job.json.job &&
          !/^(queued|running)$/.test(job.json.job.status)) {
        break;
      }
      await sleep(500);
    }
    r = await api(session, "GET", "/jobs/" + id + "/result");
  }
  log.debug("Leaving runAnswered(). " + r.status);
  return r;
}

async function test() {
  log.debug("Entering test().");
  await ok(base + "/admin-api/realms/create", { id: REALM,
    domain: REALM + ".example.net", name: "Report sources " + STAMP },
    "created the realm");
  await person(READER, ["report-admins", "report-users"]);
  await person(HOLDER, []);
  await person(SKIPPER, []);
  const reader = await reportSignin.signInToReport(RB, READER, null,
    { password: PASSWORD });

  log.info("=== P-A. the passkeyCeremonies source ===");
  const ceremonies = (await api(reader, "GET",
                                "/catalog/passkeyCeremonies")).json.source;
  const idsOf = function (source) {
    return source.fields.map(function (one) {
      return one.id;
    });
  };
  check("A1-A2. the catalog has passkeyCeremonies, its fields the row " +
        "projection's and no other", function () {
    assert.deepStrictEqual(idsOf(ceremonies), CEREMONY_FIELDS);
  });
  check("A3. none is indexed (the audit ring has no index), and the source " +
        "is not anchored", function () {
    assert.ok(ceremonies.fields.every(function (one) {
      return one.indexed.length === 0;
    }), JSON.stringify(ceremonies.fields.map(function (one) {
      return one.indexed;
    })));
    assert.strictEqual(ceremonies.anchored, false);
  });
  const door = ceremonies.fields.filter(function (one) {
    return one.id === "door";
  })[0];
  check("A4. the door field names every door the ceremony module writes",
        function () {
    ["sign-in-step", "usernameless", "portal", "activation", "upgrade",
     "admin-enrolment", "device-link"].forEach(function (one) {
      assert.ok(door.meaning.indexOf(one) >= 0, one);
    });
  });
  check("A5. the groupable fields are the categorical ones", function () {
    const groupable = ceremonies.fields.filter(function (one) {
      return one.group;
    }).map(function (one) {
      return one.id;
    });
    ["day", "kind", "ceremony", "door", "outcome", "errorCode",
     "application", "client", "algorithm"].forEach(function (one) {
      assert.ok(groupable.indexOf(one) >= 0, one);
    });
    ["timestamp", "actor", "durationMs", "transports"].forEach(
      function (one) {
        assert.ok(groupable.indexOf(one) < 0, one);
      });
  });
  const presetIds = (ceremonies.presets || []).map(function (one) {
    return one.id;
  });
  check("E. the three predefined queries are published in the presets " +
        "shape", function () {
    assert.deepStrictEqual(presetIds, ["ml-dsa-registrations-failed-by-client",
      "ml-dsa-asked-classical-made-by-client",
      "classical-sign-ins-by-ml-dsa-holders"]);
    ceremonies.presets.forEach(function (one) {
      assert.ok(one.name && one.document &&
                one.document.source === "passkeyCeremonies",
                JSON.stringify(one));
    });
  });
  for (const preset of ceremonies.presets) {
    const r = await runAnswered(reader, preset.document);
    check("C. " + preset.id + " is a valid query document the API runs",
          function () {
      assert.strictEqual(r.status, 200, brief(r));
    });
  }

  log.info("=== P-D. a real ceremony reaches the source ===");
  const admin = await consoleSignin.signInToTheConsole(RB, ENROLLER, null,
                                                       { grant: "write" });
  const policies = await send(RB + "/admin-api/policies");
  const passkeyDefaults = {};
  policies.body.passkey.fields.forEach(function (one) {
    passkeyDefaults[one.key] = one.default;
  });
  await ok(RB + "/admin-api/policies/save-passkey-policy",
    Object.assign({ profile: "default" }, passkeyDefaults,
                  { adminEnrolment: "on" }), "turned adminEnrolment on");
  const begin = function () {
    return admin.api("POST", "/admin-api/users/begin-passkey-enrolment",
                     { user: HOLDER, lane: "classical", kind: "passkey" });
  };
  const finish = function (begun, credential) {
    return admin.api("POST", "/admin-api/users/finish-passkey-enrolment",
      { user: HOLDER, enrolmentId: begun.json.enrolmentId,
        credential: JSON.stringify(credential) });
  };
  const first = await begin();
  const enrolled = await finish(first,
                                registration(first.json.ceremony.challenge));
  const second = await begin();
  const refused = await finish(second,
                               registration("not-the-challenge-" + STAMP));
  check("precondition: one enrolment succeeds and one, answering another " +
        "challenge, is refused", function () {
    assert.strictEqual(enrolled.status, 200, JSON.stringify(enrolled.json));
    assert.ok(refused.status >= 400, JSON.stringify(refused.json));
  });
  const rows = await api(reader, "POST", "/queries", {
    source: "passkeyCeremonies",
    select: ["kind", "ceremony", "door", "outcome", "errorCode", "actor",
             "algorithm", "lane", "application", "day", "timestamp"],
    where: { op: "eq", field: "door", value: "admin-enrolment" },
    limit: 20 });
  const mine = ((rows.json && rows.json.rows) || []).filter(function (one) {
    return one.actor === HOLDER || one.actor === ENROLLER;
  });
  check("D. the two ceremonies are rows of the source: registrations at " +
        "admin-enrolment, one success with its algorithm and one refused " +
        "with its error code", function () {
    assert.strictEqual(rows.status, 200, brief(rows));
    const ok1 = mine.filter(function (one) {
      return one.outcome === "success";
    })[0];
    const bad = mine.filter(function (one) {
      return one.outcome === "refused";
    })[0];
    assert.ok(ok1 && bad, brief(rows));
    [ok1, bad].forEach(function (one) {
      assert.strictEqual(one.kind, "ceremony");
      assert.strictEqual(one.ceremony, "registration");
    });
    assert.strictEqual(ok1.algorithm, "ES256", JSON.stringify(ok1));
    assert.strictEqual(ok1.errorCode, "", JSON.stringify(ok1));
    assert.ok(/^STS-[A-Z]+-\d{4}$/.test(bad.errorCode), JSON.stringify(bad));
    assert.strictEqual(ok1.day, new Date().toISOString().slice(0, 10));
  });
  const wide = await api(reader, "POST", "/queries", {
    source: "passkeyCeremonies", select: CEREMONY_FIELDS, limit: 20,
    where: { op: "eq", field: "door", value: "admin-enrolment" } });
  check("B. no address or summary is copied onto a row", function () {
    assert.strictEqual(wide.status, 200, brief(wide));
    assert.ok(wide.json.rows.length >= 2, brief(wide));
    wide.json.rows.forEach(function (one) {
      assert.deepStrictEqual(Object.keys(one).sort(),
                             CEREMONY_FIELDS.slice().sort());
    });
    assert.ok(!/127\.0\.0\.1|::ffff|summary/.test(wide.text), wide.text);
  });

  log.info("=== L-A. the postLoginProgress source ===");
  const progress = (await api(reader, "GET",
                              "/catalog/postLoginProgress")).json.source;
  check("L-A. postLoginProgress has every field the row makes, reads the " +
        "progress store (not anchored), and progress is one of five words " +
        "a count may group by", function () {
    const ids = idsOf(progress);
    ["username", "activity", "profile", "role", "progress", "invitedAt",
     "snoozedUntil", "asks", "skips", "done", "doneAt", "deadline",
     "graceEnded", "askedBy", "mailedBy", "mails", "firstMailedAt",
     "lastMailedAt"].forEach(function (id) {
      assert.ok(ids.indexOf(id) >= 0, id);
    });
    assert.strictEqual(progress.anchored, false);
    const word = progress.fields.filter(function (one) {
      return one.id === "progress";
    })[0];
    assert.deepStrictEqual(word.values,
                           ["done", "past-grace", "snoozed", "asked",
                            "mailed"]);
    assert.strictEqual(word.group, true);
  });
  check("L-A. the three predefined queries, each one the form can draw: " +
        "one filter leaf, at most one group and one order", function () {
    assert.deepStrictEqual(progress.presets.map(function (one) {
      return one.id;
    }), ["progress-by-activity", "past-grace-period", "skipped-most"]);
    progress.presets.forEach(function (one) {
      const doc = one.document;
      assert.ok(!doc.where || (doc.where.op !== "and" &&
                               doc.where.op !== "or"), one.id);
      assert.ok(!doc.groupBy || doc.groupBy.length <= 1, one.id);
      assert.ok(!doc.orderBy || doc.orderBy.length <= 1, one.id);
    });
  });

  log.info("=== L-B. people asked at a sign-in, and the presets run ===");
  const postLoginDefaults = {};
  policies.body.postLogin.fields.forEach(function (one) {
    postLoginDefaults[one.key] = one.default;
  });
  await ok(RB + "/admin-api/policies/save-postLogin-policy",
    Object.assign({ profile: "default" }, postLoginDefaults,
                  { enabled: "on", noPasskey: "invite" }),
    "turned the post-login activity on for people with no passkey");
  // Each sign-in is asked the activity and presses Skip
  // (authn_signin.js's skipPostLogin(), as every sign-in helper does).
  await reportSignin.signInToReport(RB, SKIPPER, null,
                                    { password: PASSWORD });
  await reportSignin.signInToReport(RB, READER, null,
                                    { password: PASSWORD });
  const seen = await api(reader, "POST", "/queries", {
    source: "postLoginProgress",
    select: ["username", "activity", "profile", "progress", "asks", "skips",
             "done", "askedBy", "invitedAt", "snoozedUntil", "deadline",
             "graceEnded"], limit: 20 });
  const rowOf = function (who) {
    return ((seen.json && seen.json.rows) || []).filter(function (one) {
      return one.username === who;
    })[0];
  };
  check("L-B. a person asked at a sign-in who pressed Skip is one row: the " +
        "activity, the default profile, snoozed, one ask and one skip, " +
        "asked by the policy, a week's snooze from the invitation and no " +
        "deadline", function () {
    const one = rowOf(SKIPPER);
    assert.ok(one, brief(seen));
    assert.strictEqual(one.activity, "pqc-passkey-migration");
    assert.strictEqual(one.profile, "default");
    assert.strictEqual(one.progress, "snoozed");
    assert.strictEqual(one.asks, 1);
    assert.strictEqual(one.skips, 1);
    assert.strictEqual(one.done, false);
    assert.strictEqual(one.askedBy, "policy");
    assert.strictEqual(one.deadline, null);
    assert.strictEqual(one.graceEnded, false);
    const snooze = Date.parse(one.snoozedUntil) - Date.parse(one.invitedAt);
    assert.ok(Math.abs(snooze - 7 * 86400000) < 60000, String(snooze));
  });
  check("L-B. somebody never asked has no row", function () {
    assert.strictEqual(rowOf(HOLDER), undefined, brief(seen));
  });
  const preset = function (id) {
    return progress.presets.filter(function (one) {
      return one.id === id;
    })[0].document;
  };
  const byActivity = await runAnswered(reader,
                                       preset("progress-by-activity"));
  const pastGrace = await runAnswered(reader, preset("past-grace-period"));
  const skippedMost = await runAnswered(reader, preset("skipped-most"));
  check("L-C. progress by activity counts each word: two snoozed",
        function () {
    assert.strictEqual(byActivity.status, 200, brief(byActivity));
    assert.deepStrictEqual(byActivity.json.rows,
                           [{ progress: "snoozed", count: 2 }]);
  });
  check("L-C. nobody is past their grace period", function () {
    assert.strictEqual(pastGrace.status, 200, brief(pastGrace));
    assert.strictEqual(pastGrace.json.rows.length, 0, brief(pastGrace));
  });
  check("L-C. the people who skipped most are the two who skipped once",
        function () {
    assert.strictEqual(skippedMost.status, 200, brief(skippedMost));
    assert.deepStrictEqual(skippedMost.json.rows.map(function (one) {
      return one.username;
    }).sort(), [READER, SKIPPER].sort());
  });
  const two = await api(reader, "POST", "/queries", Object.assign({},
    preset("skipped-most"), { limit: 1 }));
  check("L-D. a limit of one answers one", function () {
    assert.strictEqual(two.json.rows.length, 1, brief(two));
  });
  log.debug("Leaving test().");
}

// REMOVAL IS OPT-IN: with STS_TEST_REMOVE_REALMS=1 (a private probe that
// would otherwise fill its directory) every realm this run made — each id
// carries the run's STAMP — is removed at the end, pass or fail. A suite run
// leaves them standing (tests/CLAUDE.md, *No job removes a realm*).
async function removeRealms() {
  log.debug("Entering removeRealms().");
  if (process.env.STS_TEST_REMOVE_REALMS !== "1") {
    log.debug("Leaving removeRealms(). Not asked to.");
    return;
  }
  const listed = await send(base + "/admin-api/realms?per=500");
  const mine = ((listed.body && listed.body.realms) || []).filter(
    function (one) {
      return one.id !== "default" && one.id.indexOf(STAMP) >= 0;
    });
  for (const one of mine) {
    const r = await postJson(base + "/admin-api/realms/remove",
                             { id: one.id });
    log.info("removed the realm " + one.id + " (" + r.status + ")");
  }
  log.debug("Leaving removeRealms().");
}

async function main() {
  log.debug("Entering main().");
  let failure = null;
  try {
    await test();
  } catch (e) {
    log.debug("Caught in main(): " + ((e && e.message) || e));
    // Reported below, after the realms are removed.
    failure = e;
  }
  try {
    await removeRealms();
  } catch (e) {
    log.debug("Caught in main() removing realms: " +
              ((e && e.message) || e));
    // A removal that fails leaves a realm on a private probe; not a test
    // failure.
    log.info("could not remove the realms: " + ((e && e.message) || e));
  }
  if (failure) {
    log.error("FAILED after " + checks + " check(s): " +
              ((failure && failure.stack) || failure));
    log.debug("Leaving main().");
    process.exit(1);
  }
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving main().");
}

main();
