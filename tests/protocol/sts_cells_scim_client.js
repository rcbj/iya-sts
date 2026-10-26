// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: sts_cells_scim_client.js
//
// ===========================================================================
// THE OUTBOUND SCIM CLIENT ACROSS TWO CELLS (#553, 2026-10-13).
//
// One outbound SCIM client (an application entry, so every cell has it),
// pushing to ONE fake SCIM service provider this job serves — over HTTPS,
// on its own host (`OUTBOUND_TEST_HOST`, `GNAP_PUSH_HOST`), with a
// certificate from a CA made at run time and handed to the client as its
// `caCertificates` — declared to be in a THIRD jurisdiction (`eu`) neither
// cell is in. The provider tells the two cells apart by the address each
// dials from, learnt from the first person each pushes. In a realm of the
// job's own:
//
//   1. A REFUSED TRANSFER PUSHES NOTHING: with the realm listing only cell
//      A's jurisdiction to `eu`, a person homed at cell B never reaches the
//      provider — not even a lookup naming them.
//   2. USERS FROM BOTH CELLS END UP PRESENT once the realm lists cell B's
//      too, each pushed by the cell they are homed in.
//   3. A GROUP WITH MEMBERS IN BOTH CELLS KEEPS EVERY MEMBER, through a
//      change in either cell.
//   4. A 503 SEEN BY ONE CELL PAUSES BOTH: cell A is answered 503, and cell
//      B's view of the client shows the pause.
//   5. MOVING A PERSON TO THE OTHER CELL DOES NOT DEACTIVATE THEM: no write
//      ever sets them `active: false`, and their new cell pushes them.
//   6. DELETING A GROUP NEEDS BOTH CELLS: with cell A the group's owner (the
//      realm's `cells.homeCell`) and the link to cell B cut
//      (tests/tools/cell_link.js), the group taken out of the client's
//      scope is NOT deleted; with the link back, it is.
//
// Nothing the provider receives names a cell (checked on every request).
//
// `local: true`: this repository's own `/admin-api` and outbound client,
// against the `cells` stack only this repository's launcher builds. It
// declines to run in every other mode. It restores the link before it ends,
// whatever happened, and runs before sts_cells_unreachable.js. NOT YET RUN
// when written: the in-process half is tests/scim_client_cells.js.
// ===========================================================================
"use strict";

const assert = require("assert");
const https = require("https");
const nodeCrypto = require("crypto");
const { Command, Option } = require("commander");
const expectation = require("./expectation.js");
const kit = require("./cells_kit.js");
const testCa = require("./outbound_test_ca.js");

var appconfig;
let appconfigProblem = null;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason wait_for.js gives.
  appconfigProblem = e;
  appconfig = {};
}

const log = require("bunyan").createLogger({ name: "sts_cells_scim_client",
  level: appconfig.LOG_LEVEL || "info" });
if (appconfigProblem) {
  log.debug("CONFIG_FILE could not be read, so the configuration is empty: " +
            appconfigProblem.message);
}

const STAMP = Date.now().toString(36);
const REALM = "cellssc" + STAMP;
const CLIENT = "cells-scim-" + STAMP;
const GROUP = "cells-scim-grp-" + STAMP;
const OTHER_GROUP = "cells-scim-none-" + STAMP;
const PASSWORD = "Cells-scim-" + STAMP + "-Aa1!";
const SP_USER = "pusher-" + STAMP;
const SP_PASSWORD = "sp-" + STAMP + "-" +
  nodeCrypto.randomBytes(9).toString("hex");
const HOST = process.env.OUTBOUND_TEST_HOST || process.env.GNAP_PUSH_HOST ||
             "localhost";
const PEOPLE = { alice: "csa-" + STAMP, bob: "csb-" + STAMP,
                 carol: "csc-" + STAMP, dan: "csd-" + STAMP };
// How long one propagation may take: an act sends at once, and the
// scim-client.deliver sweep (scimClient.sweepS, 15 s) is the net.
const WAIT_MS = 150000;

let checks = 0;
function check(what, fn) {
  log.debug("Entering check().");
  fn();
  checks += 1;
  log.info("  [ok] " + what);
  log.debug("Leaving check().");
}

// ---------------------------------------------------------------------------
// THE FAKE SERVICE PROVIDER: RFC 7644's resources, PATCH and filtering, and
// a record of every request with the address it came from.
// ---------------------------------------------------------------------------
const sp = { users: {}, groups: {}, seq: 0, requests: [], failWritesFrom: {},
             served503: 0 };

function reply(res, status, body) {
  log.debug("Entering reply().");
  res.writeHead(status, { "Content-Type": "application/scim+json" });
  res.end(body === undefined ? "" : JSON.stringify(body));
  log.debug("Leaving reply().");
}

function scimError(res, status, scimType) {
  log.debug("Entering scimError().");
  reply(res, status, { schemas: [
    "urn:ietf:params:scim:api:messages:2.0:Error"], status: String(status),
    scimType: scimType });
  log.debug("Leaving scimError().");
}

function withMeta(r, type) {
  log.debug("Entering withMeta().");
  log.debug("Leaving withMeta().");
  return Object.assign({}, r.body, { id: r.id, meta: { resourceType: type } });
}

function patchResource(r, ops) {
  log.debug("Entering patchResource().");
  (ops || []).forEach(function (op) {
    if (op.path === "active") {
      r.body.active = op.value;
    } else if (op.path === "displayName") {
      r.body.displayName = op.value;
    } else if (op.path === "members" && op.op === "add") {
      const have = (r.body.members || []).map(function (m) {
        return m.value;
      });
      r.body.members = (r.body.members || []).concat(
        (op.value || []).filter(function (m) {
          return have.indexOf(m.value) < 0;
        }));
    } else if (/^members\[value eq /.test(op.path) && op.op === "remove") {
      const v = JSON.parse(/eq (".*")\]$/.exec(op.path)[1]);
      r.body.members = (r.body.members || []).filter(function (m) {
        return m.value !== v;
      });
    }
  });
  log.debug("Leaving patchResource().");
}

function handle(req, res, raw) {
  log.debug("Entering handle(). " + req.method + " " + req.url);
  const url = new URL(req.url, "https://" + HOST);
  const from = String(req.socket.remoteAddress || "")
    .replace(/^::ffff:/, "");
  const body = raw ? JSON.parse(raw) : null;
  sp.requests.push({ from: from, method: req.method,
                     path: url.pathname + url.search, raw: raw || "",
                     headers: JSON.stringify(req.headers) });
  const want = "Basic " + Buffer.from(SP_USER + ":" + SP_PASSWORD)
    .toString("base64");
  if (req.headers.authorization !== want) {
    scimError(res, 401);
    return;
  }
  if (req.method !== "GET" && sp.failWritesFrom[from]) {
    sp.failWritesFrom[from] -= 1;
    sp.served503 += 1;
    res.writeHead(503, { "Content-Type": "application/scim+json",
                         "Retry-After": "5" });
    res.end(JSON.stringify({ status: "503" }));
    return;
  }
  const parts = url.pathname.replace(/^\/scim\/v2/, "").split("/")
    .filter(Boolean);
  if (parts[0] === "ServiceProviderConfig") {
    reply(res, 200, { patch: { supported: true },
                      filter: { supported: true, maxResults: 1000 },
                      etag: { supported: false }, bulk: { supported: false } });
    return;
  }
  if (parts[0] === "ResourceTypes") {
    reply(res, 200, { Resources: [
      { name: "User", endpoint: "/Users", schemaExtensions: [] },
      { name: "Group", endpoint: "/Groups", schemaExtensions: [] }] });
    return;
  }
  const type = parts[0] === "Users" ? "User"
    : parts[0] === "Groups" ? "Group" : "";
  if (!type) {
    scimError(res, 404);
    return;
  }
  const store = type === "User" ? sp.users : sp.groups;
  const id = parts[1];
  if (!id && req.method === "GET") {
    const filter = url.searchParams.get("filter") || "";
    const m = /^(\w+) eq (".*")$/.exec(filter);
    const all = Object.keys(store).map(function (k) {
      return store[k];
    }).filter(function (r) {
      return !m || String(r.body[m[1]] || "") === JSON.parse(m[2]);
    });
    reply(res, 200, { totalResults: all.length, startIndex: 1,
                      Resources: all.map(function (r) {
                        return withMeta(r, type);
                      }) });
    return;
  }
  if (!id && req.method === "POST") {
    const clash = Object.keys(store).some(function (k) {
      const b = store[k].body;
      return b.externalId === body.externalId ||
             (type === "User" ? b.userName === body.userName
                              : b.displayName === body.displayName);
    });
    if (clash) {
      scimError(res, 409, "uniqueness");
      return;
    }
    const made = { id: "sp-" + (++sp.seq), body: body, from: from };
    store[made.id] = made;
    reply(res, 201, withMeta(made, type));
    return;
  }
  const r = store[id];
  if (!r) {
    scimError(res, 404);
    return;
  }
  if (req.method === "GET") {
    reply(res, 200, withMeta(r, type));
  } else if (req.method === "PUT") {
    r.body = body;
    reply(res, 200, withMeta(r, type));
  } else if (req.method === "PATCH") {
    patchResource(r, body.Operations);
    reply(res, 200, withMeta(r, type));
  } else if (req.method === "DELETE") {
    delete store[id];
    res.writeHead(204);
    res.end();
  } else {
    scimError(res, 405);
  }
  log.debug("Leaving handle().");
}

async function startProvider() {
  log.debug("Entering startProvider().");
  const ca = await testCa.makeCa();
  const tls = await testCa.listenerCertificate(ca, HOST);
  const server = https.createServer(tls, function (req, res) {
    let raw = "";
    req.on("data", function (c) {
      raw += c;
    });
    req.on("end", function () {
      try {
        handle(req, res, raw);
      } catch (e) {
        log.debug("Caught in startProvider(): " + ((e && e.message) || e));
        res.writeHead(500);
        res.end();
      }
    });
  });
  await new Promise(function (resolve) {
    server.listen(0, "0.0.0.0", resolve);
  });
  const base = "https://" + HOST + ":" + server.address().port + "/scim/v2";
  log.debug("Leaving startProvider(). " + base);
  return { server: server, base: base, caPem: ca.certPem };
}

// ---------------------------------------------------------------------------
// WHAT THE PROVIDER HOLDS.
// ---------------------------------------------------------------------------
function userBy(uuid) {
  log.debug("Entering userBy().");
  const hit = Object.keys(sp.users).map(function (k) {
    return sp.users[k];
  }).filter(function (r) {
    return r.body.externalId === uuid;
  })[0] || null;
  log.debug("Leaving userBy().");
  return hit;
}

function groupHeld() {
  log.debug("Entering groupHeld().");
  const hit = Object.keys(sp.groups).map(function (k) {
    return sp.groups[k];
  }).filter(function (r) {
    return r.body.displayName === GROUP;
  })[0] || null;
  log.debug("Leaving groupHeld().");
  return hit;
}

function memberIds() {
  log.debug("Entering memberIds().");
  const g = groupHeld();
  log.debug("Leaving memberIds().");
  return g ? (g.body.members || []).map(function (m) {
    return m.value;
  }).sort() : [];
}

function mentions(text) {
  log.debug("Entering mentions().");
  log.debug("Leaving mentions().");
  return sp.requests.some(function (r) {
    return r.path.indexOf(text) >= 0 || r.raw.indexOf(text) >= 0;
  });
}

async function uuidOf(base, username) {
  log.debug("Entering uuidOf(). " + username);
  const got = await kit.api(base, "GET", "/users?user=" +
                            encodeURIComponent(username));
  assert.strictEqual(got.status, 200, got.raw.slice(0, 300));
  const uuid = kit.entryUuidIn(got.body);
  assert.ok(uuid, "no entryUUID for " + username + ": " +
            got.raw.slice(0, 300));
  log.debug("Leaving uuidOf().");
  return uuid;
}

async function act(base, action, extra) {
  log.debug("Entering act(). " + action);
  const got = await kit.api(base, "POST", "/scim/clients/" + action,
                            Object.assign({ id: CLIENT }, extra || {}));
  log.debug("Leaving act(). " + got.status);
  return got;
}

async function ok(base, method, path, body, what) {
  log.debug("Entering ok(). " + what);
  const got = await kit.api(base, method, path, body);
  assert.ok(got.status === 200 && got.body && got.body.ok !== false,
            what + " answered " + got.status + ": " + got.raw.slice(0, 400));
  log.debug("Leaving ok().");
  return got;
}

// ---------------------------------------------------------------------------
// THE JOB.
// ---------------------------------------------------------------------------
async function setUp(cells, provider) {
  log.debug("Entering setUp().");
  const realm = await kit.throwawayRealm(cells, REALM);
  // Only cell A's jurisdiction is listed to `eu` at first.
  await kit.setSetting(realm.a, "cells.permittedTransfers",
                       cells.jurisdictions.a + ">eu");
  await ok(realm.a, "POST", "/scim/clients/add-client", {
    identifier: CLIENT, name: "Cells SCIM " + STAMP, baseUrl: provider.base,
    authMethod: "basic", username: SP_USER, password: SP_PASSWORD,
    caCertificates: provider.caPem, scopeMode: "all",
    groupMode: "selected", groups: [GROUP], deprovision: "deactivate",
    jurisdiction: "eu", enabled: "true" }, "add-client at cell A");
  await kit.until("cell B knows the client", 60000, async function () {
    const got = await kit.api(realm.b, "GET", "/scim/clients?client=" +
                              encodeURIComponent(CLIENT));
    return got.status === 200 && got.body && got.body.client;
  });
  for (const [who, base] of [["alice", realm.a], ["bob", realm.b]]) {
    const made = await kit.createPerson(base, PEOPLE[who], PASSWORD, "");
    assert.strictEqual(made.status, 200, made.raw.slice(0, 300));
  }
  await ok(realm.a, "POST", "/groups/create", { group: GROUP },
           "the group created at cell A");
  await ok(realm.a, "POST", "/groups/add-member",
           { group: GROUP, member: PEOPLE.alice }, "alice into the group");
  await kit.until("cell B knows the group", 60000, async function () {
    const got = await kit.api(realm.b, "POST", "/groups/add-member",
                              { group: GROUP, member: PEOPLE.bob });
    return got.status === 200 && got.body && got.body.ok !== false;
  });
  log.debug("Leaving setUp().");
  return realm;
}

async function test() {
  log.debug("Entering test().");
  const cells = kit.cellsFromEnv();
  if (!cells) {
    expectation.declineToRun(log, "STS_TEST_CELL_B_URL is not set: this is " +
      "not the `cells` mode (./run-tests.sh --modes=cells), so there is no " +
      "second cell to push from.");
    log.debug("Leaving test(). Skipped.");
    return;
  }
  const provider = await startProvider();
  try {
    await run(cells, provider);
  } finally {
    // The link is restored whatever happened: a job after this one that
    // found it down would fail for a reason that is not its own.
    await kit.link("POST", "up");
    provider.server.close();
  }
  assert.ok(checks >= 11, "only " + checks + " checks ran; a section has " +
    "stopped being called.");
  log.info(checks + " check(s) passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

async function run(cells, provider) {
  log.debug("Entering run().");
  const realm = await setUp(cells, provider);
  const uuids = { alice: await uuidOf(realm.a, PEOPLE.alice),
                  bob: await uuidOf(realm.b, PEOPLE.bob) };

  log.info("=== 1. a refused transfer pushes nothing ===");
  await act(realm.a, "reconcile");
  await kit.until("alice (cell A) at the provider", WAIT_MS,
                  async function () {
                    return userBy(uuids.alice);
                  });
  // Long enough for cell B's sweep to have run twice.
  await new Promise(function (resolve) {
    setTimeout(resolve, 35000);
  });
  check("a person homed at cell B, whose transfer to eu the realm does not " +
        "list, never reaches the provider — not even a lookup", function () {
    assert.ok(!mentions(uuids.bob) && !mentions(PEOPLE.bob),
              "the provider saw " + PEOPLE.bob);
  });
  const addrA = userBy(uuids.alice).from;

  log.info("=== 2. users from both cells end up present ===");
  await kit.setSetting(realm.a, "cells.permittedTransfers",
                       cells.jurisdictions.a + ">eu," +
                       cells.jurisdictions.b + ">eu");
  await kit.until("cell B reads the listed transfer", 60000,
                  async function () {
                    const v = await kit.settingAt(realm.b,
                                                  "cells.permittedTransfers");
                    return String(v || "").indexOf(cells.jurisdictions.b +
                                                   ">eu") >= 0;
                  });
  await act(realm.a, "reconcile");
  await kit.until("bob (cell B) at the provider", WAIT_MS, async function () {
    return userBy(uuids.bob);
  });
  const addrB = userBy(uuids.bob).from;
  check("users from both cells are present, each pushed from the cell they " +
        "are homed in", function () {
    assert.ok(userBy(uuids.alice) && userBy(uuids.bob));
    assert.notStrictEqual(addrA, addrB, "both pushed from " + addrA);
  });

  log.info("=== 3. a group with members in both cells ===");
  const both = [userBy(uuids.alice).id, userBy(uuids.bob).id].sort();
  await kit.until("the group holds alice and bob", WAIT_MS,
                  async function () {
                    return JSON.stringify(memberIds()) ===
                           JSON.stringify(both);
                  });
  check("a group with members in both cells holds every member", function () {
    assert.deepStrictEqual(memberIds(), both);
  });
  const madeC = await kit.createPerson(realm.a, PEOPLE.carol, PASSWORD, "");
  assert.strictEqual(madeC.status, 200, madeC.raw.slice(0, 300));
  await ok(realm.a, "POST", "/groups/add-member",
           { group: GROUP, member: PEOPLE.carol }, "carol into the group");
  const madeD = await kit.createPerson(realm.b, PEOPLE.dan, PASSWORD, "");
  assert.strictEqual(madeD.status, 200, madeD.raw.slice(0, 300));
  await ok(realm.b, "POST", "/groups/add-member",
           { group: GROUP, member: PEOPLE.dan }, "dan into the group");
  uuids.carol = await uuidOf(realm.a, PEOPLE.carol);
  uuids.dan = await uuidOf(realm.b, PEOPLE.dan);
  await kit.until("the group holds all four", WAIT_MS, async function () {
    return userBy(uuids.carol) && userBy(uuids.dan) &&
           memberIds().length === 4;
  });
  check("a change in either cell keeps every member of the other",
        function () {
          const want = ["alice", "bob", "carol", "dan"].map(function (who) {
            return userBy(uuids[who]).id;
          }).sort();
          assert.deepStrictEqual(memberIds(), want);
        });
  check("the group exists once, created by one cell and adopted by the " +
        "other", function () {
    assert.strictEqual(Object.keys(sp.groups).length, 1);
  });

  log.info("=== 4. a 503 seen by one cell pauses both ===");
  sp.failWritesFrom[addrA] = 1;
  await act(realm.a, "reconcile", { cell: cells.ids.a });
  await kit.until("cell A was answered 503", WAIT_MS, async function () {
    return sp.served503 > 0;
  });
  const paused = await kit.until("cell B's view shows the client paused",
    60000, async function () {
      const got = await kit.api(realm.b, "GET", "/scim/clients");
      const row = ((got.body && got.body.clients) || []).filter(
        function (c) {
          return c.identifier === CLIENT;
        })[0];
      return row && row.pausedUntil ? row : null;
    });
  check("a 503 at cell A pauses the client at cell B too (the shared pause)",
        function () {
          assert.ok(paused.pausedUntil, JSON.stringify(paused).slice(0, 300));
          assert.ok(paused.failures >= 1, JSON.stringify(paused));
        });
  const lifted = await act(realm.a, "deliver-now");
  check("deliver-now lifts it for every cell, each cell's result listed",
        function () {
          assert.strictEqual(lifted.status, 200, lifted.raw.slice(0, 300));
          assert.ok(Array.isArray(lifted.body.cells) &&
                    lifted.body.cells.length === 2, lifted.raw);
        });

  log.info("=== 5. a move is not a deactivation ===");
  const bobId = userBy(uuids.bob).id;
  const before = sp.requests.length;
  const moved = await kit.api(realm.b, "POST", "/cells/rehome",
                              { username: PEOPLE.bob, target: cells.ids.a });
  assert.strictEqual(moved.status, 200, moved.raw.slice(0, 300));
  await act(realm.a, "reconcile");
  await kit.until("cell A pushes bob after the move", WAIT_MS,
                  async function () {
                    return sp.requests.slice(before).some(function (r) {
                      return r.from === addrA && r.method === "PUT" &&
                             r.path.indexOf("/Users/" + bobId) >= 0;
                    });
                  });
  check("moving a person to the other cell never deactivates them, and " +
        "their new cell pushes them", function () {
    const off = sp.requests.slice(before).filter(function (r) {
      return r.path.indexOf("/Users/" + bobId) >= 0 &&
             /"active"\s*:\s*false|"path":"active","value":false/
               .test(r.raw);
    });
    assert.strictEqual(off.length, 0, JSON.stringify(off).slice(0, 400));
    assert.notStrictEqual(userBy(uuids.bob).body.active, false);
  });
  check("and they stay in the group", function () {
    assert.ok(memberIds().indexOf(bobId) >= 0, JSON.stringify(memberIds()));
  });

  log.info("=== 6. deleting a group needs both cells ===");
  await kit.setSetting(realm.a, "cells.homeCell", cells.ids.a);
  await kit.until("cell B reads the realm's home cell", 60000,
                  async function () {
                    return (await kit.settingAt(realm.b, "cells.homeCell")) ===
                           cells.ids.a;
                  });
  await kit.link("POST", "down");
  await ok(realm.a, "POST", "/scim/clients/update-client",
           { id: CLIENT, groups: [OTHER_GROUP] },
           "the group taken out of the client's scope");
  await act(realm.a, "reconcile", { cell: cells.ids.a });
  await new Promise(function (resolve) {
    setTimeout(resolve, 40000);
  });
  check("with cell B unreachable from the owner, the group is not deleted",
        function () {
          assert.ok(groupHeld(), "the group was deleted with cell B away");
        });
  await kit.link("POST", "up");
  await act(realm.a, "deliver-now", { cell: cells.ids.a });
  await kit.until("the group is deleted once cell B answers", WAIT_MS,
                  async function () {
                    return !groupHeld();
                  });
  check("with cell B answering none, the owner deletes the group",
        function () {
          assert.ok(!groupHeld());
        });

  check("no request the provider received names a cell", function () {
    const seen = sp.requests.map(function (r) {
      return r.path + " " + r.raw + " " + r.headers;
    }).join("\n");
    [cells.ids.a, cells.ids.b].forEach(function (id) {
      assert.ok(seen.indexOf(id) < 0, "the provider saw " + id);
    });
  });
  log.debug("Leaving run().");
}

const program = new Command();
program
  .name("sts_cells_scim_client")
  .description("one outbound SCIM client across two cells (#553): a refused " +
      "transfer pushes nothing, users from both cells pushed from home, a " +
      "group keeping both cells' members, a shared pause, a move that is " +
      "not a deactivation, and a group deleted only when both cells answer.")
  .addOption(new Option("-u, --url <url>",
      "base url (unused: the cells come from STS_TEST_CELL_*_URL)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
