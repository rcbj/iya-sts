// ===========================================================================
// sts_directory_bulk_load_ldap.js — THE SAME FIVE THOUSAND PEOPLE, THROUGH THE
// RAW LDAP SOCKET.
//
// The second of three jobs that do one piece of work through three doors and
// report how long each one took. `bulk_load.js` holds everything they share —
// the sizes, the invented people, the stopwatch, the preflight and the report
// — and this file owns the door and nothing else.
//
//   sts_directory_bulk_load_scim.js   /scim/v2
//   sts_directory_bulk_load_ldap.js   this file — RFC 4511 on TCP 389
//   sts_directory_bulk_load_api.js    /admin-api
//
// What it does, in the DEFAULT realm, and none of it is undone:
//
//   1. binds once, and then creates 5000 people with an LDAP `add` each;
//   2. creates 50 groups with an `add` each, as `groupOfNames`;
//   3. adds 100 people to each group with a `modify`, ONE AT A TIME — 5000
//      writes, so that every person is in exactly one group and every group
//      holds exactly a hundred;
//   4. reads back a sample of the people and every group, HALF over LDAP and
//      half over `/admin-api`;
//   5. reports, per operation, how long it took.
//
// ---------------------------------------------------------------------------
// **THIS IS THE ONLY JOB IN EITHER SUITE THAT TOUCHES THE DIRECTORY'S OWN
// SOCKET**, and that is why it is worth having rather than being the SCIM job
// with a different transport.
//
// Everything else that reaches this directory reaches it over HTTP: SCIM, the
// console, the management API, the groups claim. All four go through
// `ldap_server.js`'s FUNCTIONS and none of them goes through its PROTOCOL — so
// the BER codec, the ldapjs submodule this service is built on, the add
// handler's four refusals and the modify handler's change loop were, until this
// job, exercised by nothing in this repository at all. `tests/CLAUDE.md`'s
// placement rule sends a job here when it needs something the parent's suite
// cannot arrange, and a raw socket on the service under test is exactly that:
// the parent's stacks do not publish 389.
//
// ---------------------------------------------------------------------------
// WHERE THE SOCKET IS, AND WHY IT NEEDS SAYING.
//
// `docker-compose.yml` deliberately does NOT publish 389 and 636 — a host
// already running slapd would fail to start the stack with a port binding error
// naming a service nobody was thinking about — so this job cannot simply assume
// `localhost:389`. Two arrangements reach it and both are set up by a launcher:
//
//   * `./docker-run-tests.sh` — the runner is a container on the bridge with
//     the service, so `ldap://sts:389` works with nothing published at all.
//   * `./local-run-tests.sh` — the runner is a host process, so that launcher
//     picks a FREE host port and layers `tests/docker-compose-ldap.yml` over
//     the compose file to map it to 389. The operator's own `docker compose up`
//     is untouched.
//
// Either way the launcher hands this job `STS_LDAP_URL`. Without it the job
// falls back to the service's own hostname on 389, which is what a hand-run
// against a service started with `node server.js` gets — and if nothing is
// listening it FAILS, naming the variable and both launchers. **It is not
// skipped**: this suite's rule since 2026-08-28 is that a job which cannot run
// is a failure rather than a green tick, because a suite that reports success
// having driven nothing is worse than one that is honestly absent.
//
// ---------------------------------------------------------------------------
// WHAT THIS DOOR DOES THAT THE OTHER TWO DO NOT, AND THE OTHER WAY ROUND.
//
// All three send the same attributes for the same people. What each door does
// IN ADDITION is a real difference and part of the result:
//
//   * **AN LDAP `add` INVENTS NOTHING AND REGISTERS NOBODY.** It is
//     `putEntry()`, a NUL-byte refusal, an audit row and the account observer.
//     `vc_claims.js` is never called, so these five thousand entries carry
//     exactly what was sent and nothing else; and `stats.noteKnownIdentity()`
//     is not called either, so none of these people appears on `/admin/users`
//     until they authenticate. The SCIM door does both.
//   * **IT IS THE ONLY DOOR THAT CHOOSES THE DN.** The other two are handed a
//     username and apply `namePlan()`. Here the job writes
//     `uid=<name>,ou=users` itself — which is what `namePlan()` would have
//     produced, and saying so is the point: get it wrong and the one-entry-per-
//     person refusal in the add handler is what catches it.
//   * **IT IS THE ONLY DOOR WITH A CONNECTION.** One bind, five thousand adds
//     on it. That is what a provisioning client does and it is why the numbers
//     below are lower than the HTTP doors' — there is no TLS handshake, no
//     middleware stack and no router per operation. **That is the finding, not
//     a flaw in the comparison.**
//
// ---------------------------------------------------------------------------
// THE READ-BACK GOES THROUGH BOTH DOORS AND THAT IS DELIBERATE.
//
// A sample is read with an LDAP search — because a job that wrote over LDAP and
// verified only over HTTP would leave the search path unexercised, and search
// is half of what this protocol is — and one entry is then read out of
// `/admin-api/ldap/directory` as well, so that a store which answered the
// socket out of some cache the HTTP views cannot see would still be caught.
// Neither on its own is enough.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
const ldapjs = require("ldapjs");
const bulk = require("./bulk_load.js");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_directory_bulk_load_ldap",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const SIZES = bulk.SIZES;
// THE DOOR THIS JOB STAMPS ITS PEOPLE WITH, and it is a variable so that a
// SECOND job can drive this same file at a different scale without the two
// meeting. `sts_directory_bulk_load_ldap_50k.js` sets it: both run in one
// suite, against one directory that nothing deletes from, and two jobs sharing
// a stamp would collide on every name — reported as LDAP_ENTRY_ALREADY_EXISTS
// fifty thousand times, which names the one-entry-per-person rule and has
// nothing to do with it.
const STAMP = bulk.stampFor(process.env.BULK_DOOR || "ldap");

// THE BIND. This directory refuses no bind — any DN, any password, anonymous —
// which `ldap/CLAUDE.md` argues at length, so this is a name in the audit log
// rather than a credential. It is bound as a DN so that the row says something
// a reader can act on.
const BIND_DN = "cn=" + STAMP.prefix + ",ou=users";
const BIND_PASSWORD = "not-checked-in-development";

var http = bulk.httpFor(base, log);
var checks = bulk.checker(log);
const check = checks.check;

// Where the socket is. See the header: the launchers set this, and the fallback
// is what a hand-run against `node server.js` gets.
function ldapUrl() {
  if (process.env.STS_LDAP_URL) {
    return String(process.env.STS_LDAP_URL);
  }
  let host = "localhost";
  try {
    host = new URL(base).hostname || "localhost";
  } catch (e) {
    // An unparseable base is somebody's typo and localhost is the useful
    // guess; the connection error below names both this and the variable.
    host = "localhost";
  }
  return "ldap://" + host + ":" + (process.env.STS_LDAP_PORT || 389);
}

// ---------------------------------------------------------------------------
// THE CLIENT, AND WHY EVERY OPERATION IS PROMISIFIED BY HAND.
//
// ldapjs is callback-based and this job is `await`-shaped like its two
// siblings, which matters for more than tidiness: the three have to measure the
// same thing, and "the wall time of one operation, one at a time" is only true
// if the next one does not start until this one has finished. A callback loop
// would have been five thousand adds in flight at once, which is a throughput
// benchmark of a queue rather than a latency measurement of a write.
// ---------------------------------------------------------------------------
function connect() {
  log.debug("Entering connect(). url=" + ldapUrl());
  const client = ldapjs.createClient({
    url: ldapUrl(),
    // NO RECONNECT, deliberately. A dropped connection halfway through five
    // thousand adds must be a failure this job reports, not something it hides
    // by silently reconnecting and carrying on with a gap in the numbers.
    reconnect: false,
    timeout: 30000,
    connectTimeout: 15000
  });
  client.on("error", function (e) {
    // ldapjs emits on the client as well as calling back, and an unhandled
    // 'error' on an EventEmitter is a process-level throw. Logged here and
    // reported by whichever operation was in flight.
    log.debug("The LDAP client emitted an error: " + e.message);
  });
  log.debug("Leaving connect().");
  return client;
}

function bindTo(client) {
  return new Promise(function (resolve, reject) {
    client.bind(BIND_DN, BIND_PASSWORD, function (e) {
      if (e) {
        reject(e);
        return;
      }
      resolve(true);
    });
  });
}

// One `add`, timed. Resolves with `{ok, ms, error}` rather than rejecting, so
// that the loops below can count refusals the way the HTTP jobs count a 400 —
// five thousand rejections through a try/catch each would be the same code with
// more of it.
function addEntry(client, dn, attributes) {
  return new Promise(function (resolve) {
    const started = process.hrtime.bigint();
    client.add(dn, attributes, function (e) {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      resolve({ ok: !e, ms: ms, error: e ? (e.message || String(e)) : "" });
    });
  });
}

function modifyEntry(client, dn, change) {
  return new Promise(function (resolve) {
    const started = process.hrtime.bigint();
    client.modify(dn, change, function (e) {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      resolve({ ok: !e, ms: ms, error: e ? (e.message || String(e)) : "" });
    });
  });
}

// ---------------------------------------------------------------------------
// A SEARCH, COLLECTED — AND THE TWO WAYS THIS IS EASY TO WRITE WRONG.
//
// Not timed: the read-back is a check rather than one of the three
// measurements, and timing it would put a fourth row in a table whose whole
// point is that its three rows are comparable across three files.
//
// **1. IT MUST SETTLE ON `error` AND NOT WAIT FOR `end`.** ldapjs emits ONE of
// the two: a search that ends in a non-success result code emits `error` and
// NEVER emits `end`. The first version of this function collected the error and
// resolved from `end`, so any search this server refused left the promise
// pending for ever — the job stopped with no output and no failure, which is
// the worst shape a test can take. It is the same mistake in the client that
// the server had in the handler (see below), which is a fair warning about how
// natural it is.
//
// **2. A SIZE LIMIT IS AN ANSWER, NOT A FAILURE.** RFC 4511 section 4.5.2: the
// entries already sent are a valid PARTIAL answer and result code 4 is how the
// client knows it is partial. So a `SizeLimitExceededError` resolves with what
// arrived and says so on the result, rather than throwing — and this job
// asserts on that flag, because `ldap.sizeLimit` is 500 by default and this run
// creates five thousand people. `NoSuchObjectError` resolves empty for the same
// reason: "nothing is at that DN" is exactly what the caller asked.
//
// **AND EVERY SEARCH CARRIES A DEADLINE OF ITS OWN.** ldapjs's client `timeout`
// covers a request that gets no response at all; it did NOT cover the case this
// job found, where the server sends entries and then never sends the result. A
// promise that can hang is the one failure a suite cannot report about itself,
// so this one cannot: it rejects with what it had.
// ---------------------------------------------------------------------------
const SEARCH_DEADLINE_MS = Number(process.env.BULK_SEARCH_DEADLINE_MS || 60000);

function searchFor(client, dn, options) {
  return new Promise(function (resolve, reject) {
    const found = [];
    let settled = false;
    const deadline = setTimeout(function () {
      if (settled) {
        return;
      }
      settled = true;
      reject(new Error("the LDAP search of " + dn + " sent " + found.length +
        " entry/entries and then never finished — no SearchResultDone within " +
        (SEARCH_DEADLINE_MS / 1000) + "s. THAT IS THE DEFECT THIS DEADLINE " +
        "EXISTS FOR: this server used to end a size-limited search with a " +
        "bare `next()`, sending no result message at all, so every client " +
        "waited for ever on an idle connection. If this fires again, look at " +
        "the size-limit branch of the search handler in ldap/ldap_server.js " +
        "before looking anywhere else."));
    }, SEARCH_DEADLINE_MS);
    function settle(fn, value) {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(deadline);
      fn(value);
    }
    client.search(dn, options || { scope: "base" }, function (e, res) {
      if (e) {
        settle(reject, e);
        return;
      }
      res.on("searchEntry", function (entry) {
        // ldapjs 3 hands back `entry.pojo`; the older shape is `entry.object`.
        // Both are read because this repository pins a fork of the submodule
        // and a job that knew only one shape would break on a bump for a
        // reason that has nothing to do with this service.
        found.push(entry.pojo || entry.object || entry);
      });
      res.on("error", function (searchError) {
        const name = String(searchError.name || "");
        if (name === "NoSuchObjectError") {
          settle(resolve, Object.assign(found, { truncated: false }));
          return;
        }
        if (name === "SizeLimitExceededError") {
          settle(resolve, Object.assign(found, { truncated: true }));
          return;
        }
        settle(reject, searchError);
      });
      res.on("end", function () {
        settle(resolve, Object.assign(found, { truncated: false }));
      });
    });
  });
}

// The attributes of a `searchEntry`, as `{lowercased name: [values]}`. ldapjs 3
// returns `pojo.attributes` as an array of `{type, values}`; the older `object`
// shape is a flat map. Both are folded here rather than at three call sites.
function attributesOf(entry) {
  const out = {};
  if (entry && Array.isArray(entry.attributes)) {
    entry.attributes.forEach(function (attribute) {
      out[String(attribute.type).toLowerCase()] =
        [].concat(attribute.values || attribute.vals || []);
    });
    return out;
  }
  Object.keys(entry || {}).forEach(function (name) {
    if (name === "dn" || name === "controls" || name === "objectName") {
      return;
    }
    out[name.toLowerCase()] = [].concat(entry[name]);
  });
  return out;
}

function dnOf(entry) {
  return String((entry && (entry.objectName || entry.dn)) || "");
}

// ---------------------------------------------------------------------------
// 0. WHERE THE CONTAINERS ARE.
//
// Read from `/admin-api/groups`, which reports `baseDn`, `usersDn` and
// `groupsDn` for the realm it is asked in. Read rather than assembled from
// `ldap.baseDn`, because the DNs this job writes into have to be the ones this
// service is actually serving — a realm prefix, a changed base, a container
// renamed, and an assembled DN would be refused by the add handler's parent
// check with a message about a missing container rather than about a wrong
// assumption.
// ---------------------------------------------------------------------------
async function containers() {
  log.debug("Entering containers().");
  const reply = await http.get(http.api("/groups"));
  assert.strictEqual(reply.status, 200,
    "GET /admin-api/groups answered " + reply.status + ". It is where this " +
    "job reads the containers it writes into.");
  const info = reply.body || {};
  check("the service names its own containers", function () {
    assert.ok(info.usersDn && info.groupsDn,
      "GET /admin-api/groups did not report usersDn and groupsDn. This job " +
      "writes DNs beneath them and will not assemble one from ldap.baseDn: an " +
      "assembled DN that is wrong is refused by the add handler's parent " +
      "check, which reports a missing container rather than a bad guess.");
  });
  log.info("Writing into " + info.usersDn + " and " + info.groupsDn +
           " over " + ldapUrl() + ".");
  log.debug("Leaving containers().");
  return { usersDn: info.usersDn, groupsDn: info.groupsDn,
           baseDn: info.baseDn };
}

// ---------------------------------------------------------------------------
// 1. FIVE THOUSAND PEOPLE.
// ---------------------------------------------------------------------------
async function createThePeople(client, where, catalogue) {
  log.debug("Entering createThePeople().");
  log.info("=== Creating " + SIZES.USERS + " people over LDAP in the default " +
           "realm ===");

  const watch = bulk.Stopwatch("users.create [ldap]").begin();
  const created = [];
  const failures = [];

  for (let i = 1; i <= SIZES.USERS; i += 1) {
    const person = bulk.personAt(STAMP, i);
    const dn = "uid=" + person.username + "," + where.usersDn;
    // THE SAME OBJECT CLASSES `namePlan()` WRITES, and the same `uid`. This
    // door chooses the entry itself (see the header), so a difference here
    // would be a difference between the five thousand people this job creates
    // and the five thousand the other two do — which is the one thing that
    // would make the three sets of numbers incomparable.
    const attributes = Object.assign({
      objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
      uid: person.username
    }, bulk.attributesFor(person, catalogue));
    const reply = await addEntry(client, dn, attributes);
    watch.lap(reply.ms);
    if (reply.ok) {
      created.push({ username: person.username, dn: dn });
    } else if (failures.length < 5) {
      // THE FIRST FIVE, WHOLE. Five thousand identical refusals in a log is a
      // wall nobody reads, and the interesting information is in the first one.
      failures.push(dn + " -> " + reply.error.slice(0, 300));
    }
    if (i % 500 === 0) {
      const so_far = bulk.summaryOf(watch);
      log.info("  " + i + "/" + SIZES.USERS + " added — mean " +
               bulk.ms(so_far.meanMs) + ", median " +
               bulk.ms(so_far.medianMs) + ", " +
               so_far.perSecond.toFixed(1) + "/s");
    }
  }
  watch.end();

  check("every add was accepted", function () {
    assert.strictEqual(created.length, SIZES.USERS,
      created.length + " of " + SIZES.USERS + " LDAP adds were accepted. The " +
      "first few refusals were:\n  " + failures.join("\n  ") + "\nA partial " +
      "run makes every number below an average over a different population " +
      "than the one it claims. Note the shapes this can take that the HTTP " +
      "doors cannot: LDAP_ADMIN_LIMIT_EXCEEDED (11) is the entry ceiling, " +
      "LDAP_ENTRY_ALREADY_EXISTS (68) is one entry per person, and " +
      "LDAP_NO_SUCH_OBJECT (32) is a missing container.");
  });

  const summary = bulk.summaryOf(watch);
  log.info("[users] " + SIZES.USERS + " added over LDAP in " +
           (summary.wallMs / 1000).toFixed(1) + "s — mean " +
           bulk.ms(summary.meanMs) + ", median " + bulk.ms(summary.medianMs));
  log.debug("Leaving createThePeople().");
  return { people: created, summary: summary };
}

// ---------------------------------------------------------------------------
// 2. FIFTY GROUPS.
//
// AS `groupOfNames` WITH NO `member`, which RFC 4519 says a real directory
// would refuse — `member` is MUST. This one is schemaless and accepts it, the
// SCIM door creates exactly the same empty group, and the memberships are the
// third thing being measured: folding a hundred of them into the create would
// time one operation and report two.
// ---------------------------------------------------------------------------
async function createTheGroups(client, where) {
  log.debug("Entering createTheGroups().");
  log.info("=== Creating " + SIZES.GROUPS + " groups over LDAP ===");

  const watch = bulk.Stopwatch("groups.create [ldap]").begin();
  const created = [];
  const failures = [];

  for (let g = 1; g <= SIZES.GROUPS; g += 1) {
    const displayName = bulk.groupNameAt(STAMP, g);
    const dn = "cn=" + displayName + "," + where.groupsDn;
    const reply = await addEntry(client, dn, {
      objectClass: ["top", "groupOfNames"],
      cn: displayName,
      description: "Created by tests/vendored/sts_directory_bulk_load_ldap.js, " +
                   "run " + STAMP.run + "."
    });
    watch.lap(reply.ms);
    if (reply.ok) {
      created.push({ displayName: displayName, dn: dn });
    } else if (failures.length < 5) {
      failures.push(dn + " -> " + reply.error.slice(0, 300));
    }
  }
  watch.end();

  check("every group was added", function () {
    assert.strictEqual(created.length, SIZES.GROUPS,
      created.length + " of " + SIZES.GROUPS + " groups were added. The first " +
      "few refusals were:\n  " + failures.join("\n  "));
  });

  const summary = bulk.summaryOf(watch);
  log.info("[groups] " + SIZES.GROUPS + " added in " +
           (summary.wallMs / 1000).toFixed(1) + "s — mean " +
           bulk.ms(summary.meanMs) + ", median " + bulk.ms(summary.medianMs));
  log.debug("Leaving createTheGroups().");
  return { groups: created, summary: summary };
}

// ---------------------------------------------------------------------------
// 3. A HUNDRED PEOPLE INTO EACH GROUP, ONE `modify` AT A TIME.
//
// ONE MODIFY PER MEMBERSHIP, for the reason the SCIM job gives about its
// PATCHes and one more that is specific to this door: an LDAP `add` change on a
// multi-valued attribute is the operation a real provisioning client uses, and
// this service implements it by rebuilding the whole value list. If it ever
// gets slower as a group fills, THIS is the number that shows it — which is why
// the per-group mean is logged beside the overall one.
// ---------------------------------------------------------------------------
async function addTheMembers(client, people, groups) {
  log.debug("Entering addTheMembers().");
  log.info("=== Adding " + SIZES.PER_GROUP + " people to each of " +
           groups.length + " groups (" + (SIZES.PER_GROUP * groups.length) +
           " modify operations) over LDAP ===");

  const watch = bulk.Stopwatch("group.add-member [ldap]").begin();
  const failures = [];
  const expected = {};
  let written = 0;

  for (let g = 0; g < groups.length; g += 1) {
    const group = groups[g];
    // A BLOCK PER GROUP, so every person is in EXACTLY ONE group. That is what
    // makes the read-back an exact claim: a group holding a hundred and one
    // members is then a defect rather than an arrangement this file chose.
    const block = people.slice(g * SIZES.PER_GROUP, (g + 1) * SIZES.PER_GROUP);
    const perGroup = [];
    for (const person of block) {
      const change = new ldapjs.Change({
        operation: "add",
        modification: { type: "member", values: [person.dn] }
      });
      const reply = await modifyEntry(client, group.dn, change);
      watch.lap(reply.ms);
      perGroup.push(reply.ms);
      if (reply.ok) {
        written += 1;
        expected[group.dn] = (expected[group.dn] || 0) + 1;
      } else if (failures.length < 5) {
        failures.push(group.dn + " += " + person.dn + " -> " +
                      reply.error.slice(0, 300));
      }
    }
    if ((g + 1) % 10 === 0 || g === groups.length - 1) {
      const mean = perGroup.reduce(function (n, one) { return n + one; }, 0) /
          (perGroup.length || 1);
      const so_far = bulk.summaryOf(watch);
      log.info("  " + (g + 1) + "/" + groups.length + " groups filled — this " +
               "group's mean " + bulk.ms(mean) + ", overall mean " +
               bulk.ms(so_far.meanMs) + ", " + written + " membership(s) " +
               "written");
    }
  }
  watch.end();

  check("every modify was accepted", function () {
    assert.strictEqual(written, SIZES.PER_GROUP * groups.length,
      written + " of " + (SIZES.PER_GROUP * groups.length) + " modify " +
      "operations were accepted. The first few refusals were:\n  " +
      failures.join("\n  "));
  });

  const summary = bulk.summaryOf(watch);
  log.info("[members] " + written + " memberships in " +
           (summary.wallMs / 1000).toFixed(1) + "s — mean " +
           bulk.ms(summary.meanMs) + ", median " + bulk.ms(summary.medianMs));
  log.debug("Leaving addTheMembers().");
  return { summary: summary, expected: expected };
}

// ---------------------------------------------------------------------------
// 4. READ IT BACK, OVER BOTH DOORS.
// ---------------------------------------------------------------------------
async function itReadsBackWhatItWrote(client, people, groups, catalogue,
                                      expected) {
  log.debug("Entering itReadsBackWhatItWrote().");
  log.info("=== Reading back a sample over LDAP, one entry over HTTP, and " +
           "every group ===");

  // THE SAMPLE IS SPREAD RATHER THAN TAKEN FROM THE FRONT. A store that stopped
  // writing halfway through would pass a check of the first twenty five
  // entries, and that is precisely the failure this is here for.
  const step = Math.max(1, Math.floor(people.length / SIZES.SAMPLE));
  const sampled = [];
  for (let i = 0; i < people.length && sampled.length < SIZES.SAMPLE; i += step) {
    sampled.push(people[i]);
  }

  let missing = 0;
  const wrongValues = [];
  for (const person of sampled) {
    const found = await searchFor(client, person.dn, { scope: "base" });
    if (!found.length) {
      missing += 1;
      continue;
    }
    const held = attributesOf(found[0]);
    if ((held.uid || []).indexOf(person.username) < 0) {
      wrongValues.push(person.dn + " reads back with uid=" +
                       JSON.stringify(held.uid));
    }
  }
  check("the sampled people are all readable over the socket that wrote them",
        function () {
    assert.strictEqual(missing, 0,
      missing + " of " + sampled.length + " sampled people could not be read " +
      "back with an LDAP search at their own DN, spread across the whole run. " +
      "An add that answered success and stored nothing is the defect that " +
      "makes every timing above meaningless.");
    assert.deepStrictEqual(wrongValues, [],
      "and each must carry the uid it was created with.");
  });

  // ---------------------------------------------------------------------
  // A ONE-LEVEL SEARCH FOR THIS RUN'S PEOPLE, WHICH IS THE CHECK NO OTHER DOOR
  // CAN MAKE — and the one that found the defect this whole job paid for.
  //
  // It exercises the FILTER, the SCOPE and the size limit of the search handler
  // rather than a base lookup, and it is the half of this protocol the other
  // two bulk-load jobs cannot reach at all. What it asks is deliberately more
  // than `ldap.sizeLimit` (500 by default) against five thousand people, so it
  // reaches the truncation branch every time.
  //
  // **WHAT IT ASSERTS IS THAT THE SEARCH FINISHES.** Until 2026-09-06 this
  // server sent five hundred entries and then no SearchResultDone at all — a
  // bare `next()` in the size-limit branch — so every client hung for ever on
  // an idle connection, and the audit row claimed result code 4 that nothing
  // sent. `ldap.sizeLimit` is 500 and the seeded directory holds twenty-six
  // entries, so nothing in either suite had ever reached that branch.
  //
  // The count is a floor rather than an equality, and `truncated` is checked
  // rather than asserted false: a partial answer WITH result code 4 is correct
  // (RFC 4511 section 4.5.2) and a complete one is correct too — an operator
  // who raised `ldap.sizeLimit` must not fail this run. What is not correct,
  // and what this asserts against, is either of them arriving without an end.
  // ---------------------------------------------------------------------
  const anyPerson = sampled[0];
  const subtree = await searchFor(client, anyPerson.dn.split(",").slice(1)
                                  .join(","), {
    scope: "one",
    filter: "(uid=" + STAMP.prefix + "-*)",
    attributes: ["uid"]
  });
  check("a one-level search finds this run's people AND FINISHES", function () {
    assert.ok(subtree.length > 0,
      "a one-level search under the users container for `uid=" + STAMP.prefix +
      "-*` returned nothing, although " + people.length + " entries were just " +
      "added there and read back one by one.");
    // The deadline in searchFor() is what turns the historical defect into a
    // failure rather than a hang; reaching this line at all is the assertion.
    // This one says what SHAPE of answer arrived, so the log records which of
    // the two correct outcomes this run got.
    log.info("  a one-level search for uid=" + STAMP.prefix + "-* returned " +
             subtree.length + " entry/entries and ended " +
             (subtree.truncated
               ? "with LDAP_SIZE_LIMIT_EXCEEDED (4), which is the correct " +
                 "answer for a search bigger than ldap.sizeLimit"
               : "with success, so ldap.sizeLimit is above " + subtree.length) +
             ".");
  });

  // AND THE TRUNCATION IS REPORTED RATHER THAN SILENT, asserted only when it
  // happened. A partial answer a client cannot tell from a complete one is the
  // other half of the same defect: this server would have been entitled to send
  // five hundred entries and `success`, and the client would have concluded
  // that five hundred is how many there are.
  if (subtree.truncated) {
    check("a truncated search says so rather than looking complete",
          function () {
      assert.ok(subtree.length < people.length,
        "the search reported LDAP_SIZE_LIMIT_EXCEEDED and returned all " +
        subtree.length + " of this run's " + people.length + " people, which " +
        "is the two halves of that answer disagreeing.");
    });
  }

  // ONE FULL ENTRY, THROUGH THE OTHER DOOR, so that a store answering the
  // socket out of something the HTTP views cannot see would still be caught.
  const one = sampled[Math.floor(sampled.length / 2)];
  const entry = await http.get(http.api("/ldap/directory?q=" +
                                        encodeURIComponent(one.username) +
                                        "&per=5"));
  check("a person's entry carries the fields this job sent", function () {
    assert.strictEqual(entry.status, 200,
      "GET /admin-api/ldap/directory answered " + entry.status + ".");
    const rows = (entry.body && entry.body.entries) || [];
    const found = rows.filter(function (row) {
      return String(row.dn || "").toLowerCase() === one.dn.toLowerCase();
    })[0];
    assert.ok(found,
      "the entry at " + one.dn + " was written over LDAP, read back over " +
      "LDAP, and is not in the service's own HTTP view of its store. That is " +
      "the disagreement this second read exists to find.");
    const attributes = found.attributes || {};
    const held = {};
    Object.keys(attributes).forEach(function (name) {
      held[name.toLowerCase()] = [].concat(attributes[name]);
    });
    const person = bulk.personAt(STAMP, Number(one.username.split("-").pop()));
    const wanted = bulk.attributesFor(person, catalogue);
    const wrong = [];
    Object.keys(wanted).forEach(function (name) {
      const values = held[name.toLowerCase()] || [];
      if (values.indexOf(wanted[name]) < 0) {
        wrong.push(name + ": sent " + JSON.stringify(wanted[name]) +
                   ", holds " + JSON.stringify(values));
      }
    });
    assert.deepStrictEqual(wrong, [],
      "THE ENTRY DOES NOT HOLD WHAT THE ADD WAS SENT:\n  " + wrong.join("\n  "));
  });

  // EVERY GROUP, over `/admin-api` — because `memberCount`, `presentCount` and
  // `danglingCount` are the service's own reading of the membership values and
  // are exactly what a raw search cannot tell apart. A hundred values, some of
  // which name nobody, is what a membership written from a wrong DN looks like
  // and it is indistinguishable over the socket from a hundred good ones.
  const wrongCounts = [];
  for (const group of groups) {
    const reply = await http.get(http.api("/groups?group=" +
                                          encodeURIComponent(group.dn)));
    const held = (reply.body && reply.body.group) || {};
    if (reply.status !== 200 || held.memberCount !== SIZES.PER_GROUP ||
        held.presentCount !== SIZES.PER_GROUP || held.danglingCount !== 0) {
      wrongCounts.push(group.displayName + " -> " + reply.status +
                       " memberCount=" + held.memberCount +
                       " presentCount=" + held.presentCount +
                       " danglingCount=" + held.danglingCount +
                       " (expected " + (expected[group.dn] || 0) + " written)");
    }
  }
  check("every group holds exactly its hundred, and all of them resolve",
        function () {
    assert.deepStrictEqual(wrongCounts, [],
      "these groups do not hold what was written into them:\n  " +
      wrongCounts.join("\n  "));
  });

  log.info("[read-back] OK — " + sampled.length + " people read over the " +
           "socket, one entry checked attribute by attribute over HTTP, and " +
           "all " + groups.length + " groups hold exactly " +
           SIZES.PER_GROUP + " members that resolve.");
  log.debug("Leaving itReadsBackWhatItWrote().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Filling the DEFAULT realm's directory at " + base + " with " +
           SIZES.USERS + " people, " + SIZES.GROUPS + " groups and " +
           (SIZES.GROUPS * SIZES.PER_GROUP) + " memberships, ALL OF IT OVER " +
           "LDAP v3 at " + ldapUrl() + ". NOTHING IS DELETED AFTERWARDS.");

  bulk.checkSizes(assert);

  const ready = await bulk.preflight({ log: log, assert: assert, http: http,
                                       checks: checks });
  const where = await containers();

  const client = connect();
  try {
    await bindTo(client);
  } catch (e) {
    // A FAILURE AND NOT A SKIP. See the header: a job that reports green having
    // driven nothing is worse than one that is honestly absent, and the message
    // is long because the cause is almost always the port rather than the
    // service.
    assert.fail("could not bind to " + ldapUrl() + ": " + (e.message || e) +
      "\n\nThis job drives the directory's OWN SOCKET, which " +
      "docker-compose.yml deliberately does not publish (a host running " +
      "slapd would fail to start the stack). Both launchers arrange it and " +
      "set STS_LDAP_URL: ./docker-run-tests.sh puts the runner on the bridge " +
      "with the service, and ./local-run-tests.sh picks a free host port and " +
      "layers tests/docker-compose-ldap.yml over the compose file. Running " +
      "this file by hand against `node server.js` needs STS_LDAP_URL, or " +
      "STS_LDAP_PORT if the service is on this host. It is NOT skipped when " +
      "it cannot connect: the socket is the thing under test.");
  }
  log.info("Bound to " + ldapUrl() + " as " + BIND_DN + ". This directory " +
           "refuses no bind — any DN, any password, anonymous — so that name " +
           "is what the audit log will say and not a credential.");

  try {
    const people = await createThePeople(client, where, ready.catalogue);
    const groups = await createTheGroups(client, where);
    const members = await addTheMembers(client, people.people, groups.groups);
    await itReadsBackWhatItWrote(client, people.people, groups.groups,
                                 ready.catalogue, members.expected);
    bulk.report(log, [people.summary, groups.summary, members.summary], {
      base: base, door: "ldap", doorLabel: "LDAP v3 (" + ldapUrl() + ")",
      run: STAMP.run, prefix: STAMP.prefix, held: ready.held
    });

    log.info("LEFT BEHIND ON PURPOSE, in the default realm: " +
             people.people.length + " people at uid=" + STAMP.prefix + "-*, " +
             groups.groups.length + " groups at cn=" + STAMP.prefix +
             "-grp-*, and " + (SIZES.GROUPS * SIZES.PER_GROUP) +
             " memberships between them. Read them at " + base +
             "/admin/ldap/directory, or with an ldapsearch against " +
             ldapUrl() + ".");
  } finally {
    // UNBOUND IN A `finally` so that a failing assertion still closes the
    // socket. It is the one thing this job holds that a process exit would not
    // tidy tidily — the service logs an unbind, and a connection dropped
    // instead shows up in its own log as a client that went away.
    await new Promise(function (resolve) {
      client.unbind(function () { resolve(true); });
    });
    log.debug("Unbound.");
  }

  // ELEVEN UNCONDITIONALLY, AND A TWELFTH WHEN THE ONE-LEVEL SEARCH TRUNCATES —
  // which it does at the default `ldap.sizeLimit` of 500 against five thousand
  // people, and does not on a service whose operator raised it. The floor is
  // the unconditional count, because a floor that counted the conditional one
  // would fail a correct run on a correctly configured service.
  assert.ok(checks.count >= 11,
    "only " + checks.count + " checks ran. This file and the shared " +
    "preflight make eleven against a healthy service, and a twelfth when the " +
    "one-level search hits ldap.sizeLimit, so a count this low means a " +
    "SECTION STOPPED BEING CALLED rather than that the work got simpler.");
  log.info(checks.count + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_directory_bulk_load_ldap")
  .description("Create 5000 people, 50 groups and 5000 memberships in the " +
      "mock STS's DEFAULT realm ENTIRELY OVER LDAP v3 on the raw socket, " +
      "read them back, and report how long each kind of write took on " +
      "average. Deletes nothing.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .addOption(new Option("-l, --ldap-url <url>",
      "ldap:// url of the directory under test")
      .default(process.env.STS_LDAP_URL || ""))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");
http = bulk.httpFor(base, log);
if (program.opts().ldapUrl) {
  process.env.STS_LDAP_URL = String(program.opts().ldapUrl);
}

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
