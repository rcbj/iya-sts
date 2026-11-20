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
// Sections a-f enrol no passkey: they run in the default realm, whose
// people every other job adds to.
//
// D12 (#444) ADDS SECTION g, carrying what a client can see of
// `tests/passkey_report.js`, in a throwaway realm with REAL enrolments
// through `/account-api/keys` (the kit's ES256 and ML-DSA-65
// authenticators, one model's AAGUID on two of them):
//
//   g1. Recount now makes a fresh baseline, and its people, algorithms and
//       model are a count of every person made here (B2-B11);
//   g2. an enrolment, a removal and a person deleted over LDAP each move
//       the report at once with no recount, and a rename notes nothing (C);
//   g3. a recount after the changes gives the numbers the changes had
//       already given, with no change noted since (D);
//   g4. two filters, a profile nobody named, the default profile and an
//       unknown application are refused 400, coded STS-AUTHN-0416 (F), and
//       an unknown action STS-AUTHN-0418 (I);
//   g5. each kind's list is exactly its people, a list paged one row at a
//       time by the `from` cursor visits each holder once, one algorithm's
//       list, and the people with no passkey (G);
//   g6. the CSV and JSON exports carry every holder (H1, H2, H4).
//
// NOT CARRIED (class (d)): B1 (no baseline before a recount: a realm's
// first baseline is written as soon as its first key is, so a client never
// meets a realm without one), A (a person's facets from values no ceremony can
// make — an unreadable algorithm, a value that is not a key), E (that no
// count reads the directory: a spy on the directory's scan), H3 (the
// formula-quoting of a cell: no column a person controls carries free
// text), I's scheduler registration (a module table).
//
// OWNED HERE (local: true): this repository's own console and management API
// (tests/CLAUDE.md, *where a new test goes*, rule 1).
// ---------------------------------------------------------------------------

const assert = require("assert");
const https = require("https");
const { Command, Option } = require("commander");
const ldapjs = require("ldapjs");
const wire = require("./passkey_wire_kit.js");
const portalSignin = require("./portal_signin.js");

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

// ---------------------------------------------------------------------------
// g. IN A REALM OF ITS OWN, WITH REAL ENROLMENTS (D12, #444).
// ---------------------------------------------------------------------------
const MODEL = "c0ffee00-0000-4000-8000-00000000d12b";

function ldapDelete(dn, binder) {
  log.debug("Entering ldapDelete().");
  const url = "ldap://" + new URL(base).hostname + ":" +
              (process.env.STS_LDAP_PORT || "389");
  log.debug("Leaving ldapDelete().");
  return new Promise(function (resolve) {
    const client = ldapjs.createClient({ url: url });
    function done(error) {
      client.unbind();
      resolve(error ? { ok: false, message: error.message } : { ok: true });
    }
    client.on("error", function (e) {
      log.debug("Caught in ldapDelete(): " + ((e && e.message) || e));
      resolve({ ok: false, message: String(e && e.message) });
    });
    // Development checks no LDAP password (ldap/CLAUDE.md).
    client.bind(binder, "any-" + STAMP, function (bindError) {
      if (bindError) {
        done(bindError);
        return;
      }
      client.del(dn, done);
    });
  });
}

async function realmReport() {
  log.debug("Entering realmReport().");
  log.info("=== g. in a realm of its own, with real enrolments ===");
  const K = wire.kit("sts_passkey_report", { log: log });
  const realm = await K.realm("pkrep", "development");
  try {
    await realmReportIn(K, realm);
  } finally {
    // Removed only where STS_TEST_REMOVE_REALMS=1 (the kit's rule).
    await K.removeRealms();
  }
  log.debug("Leaving realmReport().");
}

async function realmReportIn(K, realm) {
  log.debug("Entering realmReportIn().");
  const op = "/realm/" + realm.id + OPERATION;
  const password = "Pk-report-" + STAMP + "-Aa1!";
  const nameOf = function (kind) {
    return ("pkr-" + kind + "-" + K.STAMP).slice(0, 40);
  };
  const portals = {};
  for (const kind of ["pq", "cl", "both", "none"]) {
    await K.person(realm, nameOf(kind), password);
    portals[kind] = await portalSignin.signInToThePortal(realm.base,
      nameOf(kind), null, { password: password });
  }
  const aaguid = Buffer.from(MODEL.replace(/-/g, ""), "hex");
  const keys = {
    pq: K.authenticator({ alg: -49, aaguid: aaguid }),
    cl: K.authenticator({ aaguid: aaguid }),
    bothCl: K.authenticator({}),
    bothPq: K.authenticator({ alg: -49 })
  };
  const enrolled = [await K.enrol(portals.pq, keys.pq),
                    await K.enrol(portals.cl, keys.cl),
                    await K.enrol(portals.both, keys.bothCl),
                    await K.enrol(portals.both, keys.bothPq)];
  enrolled.forEach(function (e) {
    assert.strictEqual(e.done && e.done.status, 200,
                       JSON.stringify(e.done && e.done.json).slice(0, 300));
  });
  const read = async function (query) {
    const r = await send("GET", op + qs(query || {}));
    assert.strictEqual(r.status, 200, r.raw.slice(0, 300));
    return r.json;
  };
  const recountAndWait = async function (since) {
    const queued = await send("POST", op + "/recount", { json: {} });
    assert.strictEqual(queued.status, 200, queued.raw.slice(0, 300));
    let v = null;
    for (let i = 0; i < 60; i += 1) {
      v = await read({});
      if (v.counted && v.counted.from === "baseline" &&
          String(v.counted.at) !== String(since || "") &&
          v.counted.changesSince === 0) {
        break;
      }
      await K.sleep(500);
    }
    return v;
  };
  const first = await read({});
  const v = await recountAndWait((first.counted || {}).at);
  const mldsa = (v.keys.byAlgorithm || []).filter(function (r) {
    return r.algorithm === "ML-DSA-65";
  })[0] || {};
  const model = (v.models || []).filter(function (m) {
    return m.aaguid === MODEL;
  })[0] || {};
  check("g1. Recount now makes the baseline: one post-quantum only, one " +
        "classical only, one with both, the rest none, four keys, two of " +
        "them ML-DSA-65, the model holding two keys of two algorithms",
        function () {
    assert.strictEqual(v.counted && v.counted.from, "baseline",
                       JSON.stringify(v.counted));
    assert.strictEqual(v.people.postQuantumOnly, 1, JSON.stringify(v.people));
    assert.strictEqual(v.people.classicalOnly, 1);
    assert.strictEqual(v.people.both, 1);
    assert.strictEqual(v.people.holding, 3);
    assert.strictEqual(v.people.none, v.people.total - 3);
    assert.strictEqual(v.keys.total, 4, JSON.stringify(v.keys));
    assert.ok(mldsa.count === 2 && mldsa.postQuantum === true,
              JSON.stringify(mldsa));
    assert.ok(model.total === 2 && model.postQuantum === true &&
              model.algorithms.length === 2, JSON.stringify(v.models));
  });

  const noneKey = K.authenticator({ alg: -49 });
  const late = await K.enrol(portals.none, noneKey);
  assert.strictEqual(late.done.status, 200, JSON.stringify(late.done.json));
  const c1 = await read({});
  const renamed = await portals.cl.api("POST", "/account-api/keys/rename",
    { credentialId: keys.cl.credentialId, label: "Work key" });
  const c2 = await read({});
  const removed = await portals.both.api("POST", "/account-api/keys/remove",
    { credentialId: keys.bothPq.credentialId });
  const c3 = await read({});
  // The kit's realm has the DNS domain `<id>.example.net`, so its tree is
  // rooted there (ldap/CLAUDE.md).
  const users = "ou=users,dc=" + realm.id + ",dc=example,dc=net";
  const dn = "uid=" + nameOf("pq") + "," + users;
  const binder = "uid=" + nameOf("none") + "," + users;
  const gone = await ldapDelete(dn, binder);
  let c4 = await read({});
  for (let i = 0; i < 20 && c4.people.postQuantumOnly !== 1; i += 1) {
    await K.sleep(250);
    c4 = await read({});
  }
  check("g2. an enrolment moves the report at once, with no recount, and " +
        "is counted as a change since the baseline", function () {
    assert.strictEqual(c1.people.postQuantumOnly, 2, JSON.stringify(c1.people));
    assert.ok(c1.counted.changesSince >= 1, JSON.stringify(c1.counted));
  });
  check("g2. a rename is written and notes nothing: it moves no facet",
        function () {
    assert.strictEqual(renamed.status, 200, JSON.stringify(renamed.json));
    assert.strictEqual(c2.counted.changesSince, c1.counted.changesSince,
                       JSON.stringify([c1.counted, c2.counted]));
  });
  check("g2. a removal moves the person who held both to classical only",
        function () {
    assert.strictEqual(removed.status, 200, JSON.stringify(removed.json));
    assert.strictEqual(c3.people.both, 0, JSON.stringify(c3.people));
    assert.strictEqual(c3.people.classicalOnly, 2);
  });
  check("g2. a person deleted over LDAP takes their passkey out of the " +
        "report with them", function () {
    assert.ok(gone.ok, dn + ": " + JSON.stringify(gone));
    assert.strictEqual(c4.people.postQuantumOnly, 1,
                       JSON.stringify(c4.people));
  });

  const fresh = await recountAndWait(v.counted.at);
  check("g3. a recount after the changes gives the numbers the changes had " +
        "already given, every algorithm's count too, with no change noted " +
        "since", function () {
    ["postQuantumOnly", "classicalOnly", "both", "none", "holding"]
      .forEach(function (name) {
        assert.strictEqual(fresh.people[name], c4.people[name], name);
      });
    assert.strictEqual(JSON.stringify(fresh.keys.byAlgorithm),
                       JSON.stringify(c4.keys.byAlgorithm));
    assert.strictEqual(fresh.counted.changesSince, 0,
                       JSON.stringify(fresh.counted));
  });

  const group = "pkr-g-" + K.STAMP;
  await K.call(realm, "POST", "/groups/create", { group: group });
  const refusals = [[{ group: group, profile: "x" }, "two filters"],
                    [{ profile: "pkr-nobody-" + K.STAMP },
                     "a profile nobody named"],
                    [{ profile: "default" }, "the default profile"],
                    [{ application: "pkr-no-such-" + K.STAMP },
                     "an unknown application"]];
  for (const pair of refusals) {
    const n = await K.codeCount(realm, "STS-AUTHN-0416");
    const r = await send("GET", op + qs(pair[0]));
    const recorded = await K.newCodes(realm, "STS-AUTHN-0416", n);
    check("g4. " + pair[1] + " is refused 400, coded STS-AUTHN-0416",
          function () {
      assert.strictEqual(r.status, 400, r.raw.slice(0, 300));
      assert.ok(recorded > 0, "no STS-AUTHN-0416 row");
    });
  }
  const n18 = await K.codeCount(realm, "STS-AUTHN-0418");
  const unknown = await send("POST", op + "/nonsense", { json: {} });
  const recorded18 = await K.newCodes(realm, "STS-AUTHN-0418", n18);
  check("g4. an unknown action is refused 400, coded STS-AUTHN-0418",
        function () {
    assert.strictEqual(unknown.status, 400, unknown.raw.slice(0, 300));
    assert.ok(recorded18 > 0, "no STS-AUTHN-0418 row");
  });

  const mine = function (body) {
    return ((body.list && body.list.rows) || []).map(function (r) {
      return r.username;
    }).filter(function (name) {
      return /^pkr-(pq|cl|both|none)-/.test(name);
    }).sort();
  };
  const pqList = await read({ list: "post-quantum-only" });
  const clList = await read({ list: "classical-only" });
  const algList = await read({ list: "algorithm", algorithm: "ML-DSA-65" });
  const noneList = await read({ list: "none", per: "500" });
  check("g5. each kind's list is exactly its people, one algorithm's list " +
        "too, and the people with no passkey hold none", function () {
    assert.deepStrictEqual(mine(pqList), [nameOf("none")]);
    assert.deepStrictEqual(mine(clList), [nameOf("both"), nameOf("cl")]
      .sort());
    assert.deepStrictEqual(mine(algList), [nameOf("none")]);
    assert.strictEqual(mine(noneList).length, 0,
                       JSON.stringify(noneList.list));
    assert.ok((noneList.list.rows || []).every(function (r) {
      return r.kind === "none";
    }), JSON.stringify(noneList.list.rows).slice(0, 300));
  });
  const seen = [];
  let from = "";
  for (let page = 1; page < 20; page += 1) {
    const one = await read({ list: "holding", per: "1",
                             page: String(page), from: from });
    (one.list.rows || []).forEach(function (r) {
      seen.push(r.username);
    });
    if (!one.list.paging.hasNext) {
      break;
    }
    from = one.list.paging.nextFrom;
  }
  check("g5. paged one row at a time by the cursor, every holder is " +
        "visited, and none twice", function () {
    assert.deepStrictEqual(seen.slice().sort(), [nameOf("both"),
      nameOf("cl"), nameOf("none")].sort(), JSON.stringify(seen));
    assert.strictEqual(new Set(seen).size, seen.length);
  });

  const csv = await send("GET", op + "/export" + qs({ list: "holding" }),
                         { headers: { accept: "text/csv" } });
  const json = await send("GET", op + "/export" +
                          qs({ list: "holding", format: "json" }));
  check("g6. the export is a CSV with its header carrying the holders, and " +
        "JSON with every row", function () {
    assert.strictEqual(csv.status, 200, csv.raw.slice(0, 300));
    assert.ok(/^username,dn,kind,passkeys,/.test(csv.raw),
              csv.raw.slice(0, 200));
    [nameOf("both"), nameOf("cl"), nameOf("none")].forEach(function (name) {
      assert.ok(csv.raw.indexOf(name) >= 0, name);
    });
    assert.strictEqual(json.status, 200, json.raw.slice(0, 300));
    assert.strictEqual(json.json.rows.length, 3, json.raw.slice(0, 300));
  });
  log.debug("Leaving realmReportIn().");
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

  await realmReport();

  assert.ok(checks >= 25, "only " + checks + " checks ran; a section has " +
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
