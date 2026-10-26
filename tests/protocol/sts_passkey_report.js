// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

"use strict";
//
// File: sts_passkey_report.js
//
// ---------------------------------------------------------------------------
// MONITORING → PASSKEYS OVER HTTP (#942, 2026-10-23).
//
// Who holds which passkey algorithm, as `GET /admin-api/passkey-report`
// answers it and `/admin/passkey-report` draws it. Against the running
// service:
//
//   a. the console page answers its shell, the three operations are in the
//      OpenAPI document, and the report refuses a caller with no token;
//   b. the report answers its shape: people by kind, keys by algorithm and
//      lane, models, the attestation extension point (#941), the profiles
//      with their postQuantumRequired, where the numbers came from, and the
//      limits — and the kinds add up to the people holding a passkey;
//   c. a GROUP filter counts its members only: a person made here with no
//      passkey, put in a group made here, is that group's one person and
//      holds none; the list of `none` in that group names them, and its
//      paging says the list is whole;
//   d. two filters, a passkey profile nobody named and the default profile
//      are refused 400; an unknown list name is refused at the gate;
//   e. the export of that list is CSV with its header and the person, and
//      JSON with `rows`;
//   f. Recount now queues the recount job (`runId`), and an action that
//      does not exist is refused 400.
//
// No passkey is enrolled here: a WebAuthn ceremony needs an authenticator,
// which `tests/passkey_report.js` stands in for in process, where the
// counts, the changes and the recount are compared with a count of every
// person. What only HTTP can show is the operation, its gate and its
// answers, in every mode.
//
// OWNED HERE (local: true): this repository's own console and management API
// (tests/CLAUDE.md, *where a new test goes*, rule 1).
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const { Command, Option } = require("commander");

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
var log = bunyan.createLogger({ name: "sts_passkey_report",
                                level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = String(process.env.OID4VCI_ISSUER_URL ||
                  stsUrl.replace(/\/sts\/?$/, "")).replace(/\/+$/, "");
const OPERATION = "/admin-api/passkey-report";
const STAMP = Date.now().toString(36);

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// One request over node's own https. The management API's token is attached
// by the launcher's preload (`tests/tools/attach-admin-token.js`) unless
// `bare` sends `Authorization: none`.
function send(method, path, options) {
  log.debug("Entering send(). " + method + " " + path);
  const o = options || {};
  const target = new URL(base + path);
  const headers = Object.assign({ accept: "application/json" },
                                o.headers || {});
  const body = o.json === undefined ? "" : JSON.stringify(o.json);
  if (body) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  if (o.bare) {
    // `tests/tools/attach-admin-token.js` leaves this alone, and the service
    // reads it as a malformed credential: a caller with no token.
    headers.authorization = "none";
  }
  log.debug("Leaving send().");
  return new Promise(function (resolve, reject) {
    const transport = target.protocol === "http:" ? require("http") : https;
    const req = transport.request({
      method: method, hostname: target.hostname, port: target.port,
      path: target.pathname + target.search, headers: headers
    }, function (res) {
      const chunks = [];
      res.on("data", function (c) {
        chunks.push(c);
      });
      res.on("end", function () {
        const raw = Buffer.concat(chunks).toString("utf8");
        let json = null;
        try {
          json = JSON.parse(raw);
        } catch (e) {
          log.debug("Caught in send(): " + ((e && e.message) || e));
          // Not JSON: a page, a CSV, or Express's own 404; the caller reads
          // `raw`.
          json = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, raw: raw,
                  json: json });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

// The query string of an object.
function qs(query) {
  log.debug("Entering qs().");
  log.debug("Leaving qs().");
  return "?" + Object.keys(query).map(function (k) {
    return encodeURIComponent(k) + "=" + encodeURIComponent(query[k]);
  }).join("&");
}

async function test() {
  log.debug("Entering test().");
  log.info("Monitoring → Passkeys at " + base);

  log.info("=== a. the page, the document and the gate ===");
  const shell = await send("GET", "/admin/passkey-report",
                           { headers: { accept: "text/html" } });
  const doc = await send("GET", "/admin-api/openapi.json");
  const anonymous = await send("GET", OPERATION, { bare: true });
  check("the console page answers its shell, the operations are " +
        "published, and the report refuses a caller with no token",
        function () {
    assert.strictEqual(shell.status, 200, shell.raw.slice(0, 200));
    assert.ok(/<html/i.test(shell.raw), shell.raw.slice(0, 200));
    const paths = Object.keys((doc.json && doc.json.paths) || {});
    ["/admin-api/passkey-report", "/admin-api/passkey-report/export",
     "/admin-api/passkey-report/recount"].forEach(function (p) {
      assert.ok(paths.indexOf(p) >= 0, p + " is not in the document");
    });
    assert.strictEqual(anonymous.status, 401, anonymous.raw.slice(0, 200));
  });

  log.info("=== b. the report's shape ===");
  const whole = await send("GET", OPERATION);
  const v = whole.json || {};
  check("the report answers people, keys, models, attestation, profiles " +
        "and limits", function () {
    assert.strictEqual(whole.status, 200, whole.raw.slice(0, 300));
    assert.strictEqual(v.filter && v.filter.scope, "realm");
    ["holding", "postQuantumOnly", "classicalOnly", "both"]
      .forEach(function (name) {
        assert.strictEqual(typeof v.people[name], "number",
                           name + ": " + JSON.stringify(v.people));
      });
    assert.ok(Array.isArray(v.keys.byAlgorithm), JSON.stringify(v.keys));
    assert.ok(Array.isArray(v.models), JSON.stringify(v.models));
    assert.strictEqual(typeof v.attestation.recorded, "boolean");
    assert.ok(Array.isArray(v.profiles) && v.profiles.some(function (p) {
      return p.name === "default" && typeof p.postQuantumRequired ===
             "string";
    }), JSON.stringify(v.profiles));
    assert.ok(v.limits && v.limits.listScan > 0 && v.limits.export > 0,
              JSON.stringify(v.limits));
  });
  check("the kinds add up to the people holding a passkey, and the keys to " +
        "their algorithms", function () {
    const p = v.people;
    assert.strictEqual(p.postQuantumOnly + p.classicalOnly + p.both,
                       p.holding, JSON.stringify(p));
    const sum = v.keys.byAlgorithm.reduce(function (n, r) {
      return n + r.count;
    }, 0);
    assert.strictEqual(sum, v.keys.total, JSON.stringify(v.keys));
    v.keys.byAlgorithm.forEach(function (r) {
      assert.strictEqual(r.postQuantum, /^ML-DSA-/.test(r.algorithm),
                         JSON.stringify(r));
    });
    if (v.counted && v.counted.from === "baseline") {
      assert.ok(v.counted.at && typeof v.counted.changesSince === "number",
                JSON.stringify(v.counted));
    }
  });

  log.info("=== c. a group's population ===");
  const person = "pkr-http-" + STAMP;
  const group = "pkr-http-group-" + STAMP;
  // The attributes are what the realm's attribute policy (#396) requires of
  // every person in product mode; `invent: false` fills none of them, so the
  // create was refused (400) in the single-node mode until 2026-10-26.
  const madePerson = await send("POST", "/admin-api/users/create",
                                { json: { username: person, invent: false,
                                          attributes: {
                                            cn: "Passkey Report " + person,
                                            givenName: "Passkey",
                                            sn: person,
                                            mail: person +
                                                  "@passkey-report.test" } } });
  const madeGroup = await send("POST", "/admin-api/groups/create",
                               { json: { group: group } });
  const joined = await send("POST", "/admin-api/groups/add-member",
                            { json: { group: group, member: person } });
  check("a person and a group are made, and the person put in it",
        function () {
    assert.strictEqual(madePerson.status, 200, madePerson.raw.slice(0, 300));
    assert.strictEqual(madeGroup.status, 200, madeGroup.raw.slice(0, 300));
    assert.strictEqual(joined.status, 200, joined.raw.slice(0, 300));
  });
  const inGroup = await send("GET", OPERATION + qs({ group: group,
                                                     list: "none" }));
  const g = inGroup.json || {};
  check("the group's report counts its one member, holding no passkey, " +
        "and lists them", function () {
    assert.strictEqual(inGroup.status, 200, inGroup.raw.slice(0, 300));
    assert.strictEqual(g.filter.scope, "group");
    assert.strictEqual(g.people.total, 1, JSON.stringify(g.people));
    assert.strictEqual(g.people.none, 1, JSON.stringify(g.people));
    assert.strictEqual(g.population.complete, true,
                       JSON.stringify(g.population));
    const names = (g.list.rows || []).map(function (r) {
      return r.username;
    });
    assert.deepStrictEqual(names, [person], JSON.stringify(g.list));
    assert.strictEqual(g.list.paging.complete, true,
                       JSON.stringify(g.list.paging));
    assert.strictEqual(g.list.paging.hasNext, false);
  });

  log.info("=== d. the refusals ===");
  for (const asked of [{ group: group, profile: "x" },
                       { profile: "pkr-no-such-" + STAMP },
                       { profile: "default" }]) {
    const r = await send("GET", OPERATION + qs(asked));
    check(JSON.stringify(asked) + " is refused 400", function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(r.json && r.json.ok === false && r.json.errors.length,
                r.raw.slice(0, 300));
    });
  }
  const badList = await send("GET", OPERATION + qs({ list: "nonsense" }));
  check("a list name outside its closed set is refused at the gate",
        function () {
    assert.strictEqual(badList.status, 400, badList.raw.slice(0, 300));
  });

  log.info("=== e. the export ===");
  const csv = await send("GET", OPERATION + "/export" +
                         qs({ group: group, list: "none" }),
                         { headers: { accept: "text/csv" } });
  const json = await send("GET", OPERATION + "/export" +
                          qs({ group: group, list: "none",
                               format: "json" }));
  check("the export is CSV with its header and the person, and JSON with " +
        "rows", function () {
    assert.strictEqual(csv.status, 200, csv.raw.slice(0, 300));
    assert.ok(/text\/csv/.test(String(csv.headers["content-type"])),
              String(csv.headers["content-type"]));
    assert.ok(/attachment/.test(String(csv.headers["content-disposition"])));
    assert.ok(/^username,dn,kind,passkeys,/.test(csv.raw),
              csv.raw.slice(0, 200));
    assert.ok(csv.raw.indexOf(person) >= 0, csv.raw.slice(0, 400));
    assert.strictEqual(json.status, 200, json.raw.slice(0, 300));
    assert.ok(json.json && Array.isArray(json.json.rows) &&
              json.json.rows.length === 1, json.raw.slice(0, 300));
  });

  log.info("=== f. Recount now ===");
  const recount = await send("POST", OPERATION + "/recount", { json: {} });
  const unknown = await send("POST", OPERATION + "/nonsense", { json: {} });
  check("a recount is queued on the scheduler, and an unknown action is " +
        "refused", function () {
    assert.strictEqual(recount.status, 200, recount.raw.slice(0, 300));
    assert.ok(recount.json && recount.json.ok === true &&
              recount.json.runId, recount.raw.slice(0, 300));
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
  });

  assert.ok(checks >= 10, "only " + checks + " checks ran; a section has " +
                                            "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_passkey_report")
  .description("Monitoring → Passkeys over HTTP (#942).")
  .addOption(new Option("-u, --url <url>", "base url (unused: this test " +
                                           "needs no browser)"))
  .parse(process.argv);

test().then(function () {
  process.exit(0);
}, function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
