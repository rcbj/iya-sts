// ===========================================================================
// sts_directory_bulk_load_api.js — THE SAME FIVE THOUSAND PEOPLE, THROUGH THIS
// SERVICE'S OWN MANAGEMENT API.
//
// The third of three jobs that do one piece of work through three doors and
// report how long each one took. `bulk_load.js` holds everything they share and
// this file owns the door and nothing else.
//
//   sts_directory_bulk_load_scim.js   /scim/v2
//   sts_directory_bulk_load_ldap.js   LDAP v3 on the raw socket
//   sts_directory_bulk_load_api.js    this file — /admin-api
//
// What it does, in the DEFAULT realm, and none of it is undone:
//
//   1. creates 5000 people through `POST /admin-api/users/create`;
//   2. creates 50 groups through `POST /admin-api/groups/create`;
//   3. adds 100 of those people to each group, ONE AT A TIME, through
//      `POST /admin-api/groups/add-member` — 5000 writes;
//   4. reads back a sample of the people and every group;
//   5. reports, per operation, how long it took.
//
// ---------------------------------------------------------------------------
// **TWO OF THOSE THREE OPERATIONS DID NOT EXIST UNTIL 2026-09-06, AND THIS JOB
// IS WHY THEY DO.**
//
// `/admin-api/groups` was a READ and so was `/admin/groups`. This service's own
// management API could put a PERSON in the directory and had no way to put them
// in a GROUP: the only two doors onto a group were an `ldapadd` on the raw
// socket and `POST /scim/v2/Groups`. So the console could report a dangling
// member, a claimed membership and the two groups that decide who may use it,
// and could not create any of them.
//
// **RULE 7 COULD NOT HAVE FOUND THAT AND THAT IS THE INTERESTING PART.** That
// rule is a parity check between the console and this API — every control there
// has an operation here, every operation here names a control there — and it is
// SATISFIED EXACTLY WHEN BOTH ARE MISSING. It reports drift, not absence. What
// found this was writing a third bulk-load job and discovering it could not be
// written: a job called "through the Management API" that had to reach for SCIM
// for two of its three sections would have been measuring the thing it was
// named after only a third of the time.
//
// The two operations, the two console controls that mirror them and the
// `setGroupWriter()` slot behind both were added in that change.
// `admin-ui/CLAUDE.md`, `mgmt-api/CLAUDE.md` and `ldap/CLAUDE.md` argue them.
//
// ---------------------------------------------------------------------------
// WHY THIS FILE IS HERE RATHER THAN IN THE PARENT PROJECT.
//
// `tests/CLAUDE.md`'s placement rule asks FIRST whether the thing under test is
// this service's `/admin` console or its `/admin-api`, and this job is nothing
// but that API driven ten thousand times. It is an OWNERSHIP argument rather
// than a capability one: the tree that ADDS an operation to that API is the
// tree that should go red when the operation loses its handler. Its two
// siblings are here on their own arguments — SCIM's is that it shares this
// one's realm decisions, LDAP's is that it needs a socket no stack over there
// publishes.
//
// ---------------------------------------------------------------------------
// WHAT THIS DOOR DOES THAT THE OTHER TWO DO NOT.
//
// All three send the same attributes for the same people. What differs:
//
//   * **IT SENDS `invent: false`**, which is what the console's own New user
//     form sends and what this job's predecessor sent. So these entries carry
//     their object classes, their uid, a description and what was sent — and
//     `vc_claims.js` is never asked to make up the rest. The SCIM door DOES
//     invent, because `scim.js` calls `createUser()` without that flag; the
//     LDAP door invents nothing because it never reaches that function at all.
//   * **IT IS THE ONLY DOOR THAT REFUSES AN UNKNOWN ATTRIBUTE.** `POST
//     /admin-api/users/create` validates every name against the catalogue at
//     `GET /admin-api/users/new` and fails the whole create on one it does not
//     know. SCIM silently has no member for some of them; LDAP is schemaless
//     and accepts anything. That is why the shared preflight reads that
//     catalogue for ALL THREE jobs — it is the strictest of the three doors,
//     and a population that satisfies it satisfies the other two.
//   * **IT PUTS THE PERSON ON `/admin/users`.** `createUser()` calls
//     `stats.noteKnownIdentity()`, so these five thousand appear in the
//     identity register as known-without-a-sign-in. SCIM does too, through the
//     same function; an LDAP `add` does not.
//
// ---------------------------------------------------------------------------
// IT WRITES TO THE DEFAULT REALM AND DELETES NOTHING. The argument is in
// `sts_directory_bulk_load_scim.js`'s header, in full, and is not repeated
// here: the measurement is of a directory that already holds thousands of
// entries, the entries are the deliverable, and nothing this suite creates is
// removed. Every name carries the door and the run stamp so that three jobs in
// one suite and two runs of the suite never collide.
//
// WHAT THE TIMINGS ARE AND ARE NOT is also argued there: one request at a time,
// measured around the `fetch`, and the MEDIAN is the number to believe.
// ===========================================================================

"use strict";

const assert = require("assert");
const { Command, Option } = require("commander");
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
var log = bunyan.createLogger({ name: "sts_directory_bulk_load_api",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");

const SIZES = bulk.SIZES;
const STAMP = bulk.stampFor("api");

var http = bulk.httpFor(base, log);
var checks = bulk.checker(log);
const check = checks.check;

// ---------------------------------------------------------------------------
// 0. THE TWO OPERATIONS THIS JOB NEEDS, CHECKED BEFORE IT WRITES ANYTHING.
//
// Asked of the generated OpenAPI document rather than by trying one and reading
// the failure, because the two answers look identical from a client and are
// completely different facts: `POST /admin-api/groups/create` against a service
// that does not have it is a 404 from the express fallthrough, and against a
// service that has it and cannot write is a 400 saying no directory is loaded.
// A job that could not tell those apart would report "the group create is
// broken" for a build without `ldap_server.js`.
// ---------------------------------------------------------------------------
async function theOperationsExist() {
  log.debug("Entering theOperationsExist().");
  const doc = await http.get(http.api("/openapi.json"));
  assert.strictEqual(doc.status, 200,
    "GET /admin-api/openapi.json answered " + doc.status + ". It is generated " +
    "from the operation table this job drives.");
  const paths = Object.keys((doc.body && doc.body.paths) || {});
  const wanted = ["/admin-api/users/create", "/admin-api/groups/create",
                  "/admin-api/groups/add-member"];
  const absent = wanted.filter(function (path) {
    return paths.indexOf(path) < 0;
  });
  check("the three operations this job drives are published", function () {
    assert.deepStrictEqual(absent, [],
      "this service's OpenAPI document does not publish " + absent.join(", ") +
      ". The two group operations arrived on 2026-09-06 and this job is the " +
      "reason they exist — see the header. A service without them is one " +
      "built before that change, and this job cannot be run against it: two " +
      "of its three measurements would be of a 404.");
  });
  log.debug("Leaving theOperationsExist().");
}

// ---------------------------------------------------------------------------
// 1. FIVE THOUSAND PEOPLE.
// ---------------------------------------------------------------------------
async function createThePeople(catalogue) {
  log.debug("Entering createThePeople().");
  log.info("=== Creating " + SIZES.USERS + " people through /admin-api in " +
           "the default realm ===");

  const watch = bulk.Stopwatch("users.create [admin-api]").begin();
  const created = [];
  const failures = [];

  for (let i = 1; i <= SIZES.USERS; i += 1) {
    const person = bulk.personAt(STAMP, i);
    const reply = await http.postJson(http.api("/users/create"), {
      username: person.username,
      // `invent` DEFAULTS TO TRUE and is turned off here deliberately: this job
      // is measuring what it takes to write a person somebody SENT, and leaving
      // the invention on would be timing `vc_claims.js` making up the other
      // twenty attributes as well. The entries are still fully populated — that
      // is what the catalogue loop in the shared preflight is for. The header
      // says what the other two doors do instead.
      invent: false,
      attributes: bulk.attributesFor(person, catalogue)
    });
    watch.lap(reply.ms);
    if (reply.status === 200 && reply.body && reply.body.ok !== false) {
      created.push({ username: person.username,
                     dn: (reply.body.entry && reply.body.entry.dn) ||
                         reply.body.dn || "" });
    } else if (failures.length < 5) {
      // THE FIRST FIVE, WHOLE. Five thousand identical refusals in a log is a
      // wall nobody reads, and the interesting information is in the first one.
      failures.push(person.username + " -> " + reply.status + " " +
                    String(reply.text).slice(0, 300));
    }
    if (i % 500 === 0) {
      const so_far = bulk.summaryOf(watch);
      log.info("  " + i + "/" + SIZES.USERS + " created — mean " +
               bulk.ms(so_far.meanMs) + ", median " +
               bulk.ms(so_far.medianMs) + ", " +
               so_far.perSecond.toFixed(1) + "/s");
    }
  }
  watch.end();

  check("every create was accepted", function () {
    assert.strictEqual(created.length, SIZES.USERS,
      created.length + " of " + SIZES.USERS + " creates were accepted. The " +
      "first few refusals were:\n  " + failures.join("\n  ") + "\nA partial " +
      "run makes every number below an average over a different population " +
      "than the one it claims, which is why this is asserted rather than " +
      "reported.");
  });
  check("every created person came back with a DN", function () {
    const nameless = created.filter(function (one) { return !one.dn; });
    assert.strictEqual(nameless.length, 0,
      nameless.length + " create(s) answered ok and named no entry. The DN is " +
      "what the group memberships below are written from, so a create that " +
      "does not say where it put somebody is a create this job cannot use.");
  });

  const summary = bulk.summaryOf(watch);
  log.info("[users] " + SIZES.USERS + " created in " +
           (summary.wallMs / 1000).toFixed(1) + "s — mean " +
           bulk.ms(summary.meanMs) + ", median " + bulk.ms(summary.medianMs));
  log.debug("Leaving createThePeople().");
  return { people: created, summary: summary };
}

// ---------------------------------------------------------------------------
// 2. FIFTY GROUPS.
//
// NO MEMBERS AT CREATE, although this operation would take them: the membership
// writes are the third thing being measured and folding a hundred of them into
// the create would time one operation and report two. That is the same decision
// the other two jobs make, for the same reason, and it is what keeps the three
// `groups.create` rows comparable.
// ---------------------------------------------------------------------------
async function createTheGroups() {
  log.debug("Entering createTheGroups().");
  log.info("=== Creating " + SIZES.GROUPS + " groups through /admin-api ===");

  const watch = bulk.Stopwatch("groups.create [admin-api]").begin();
  const created = [];
  const failures = [];

  for (let g = 1; g <= SIZES.GROUPS; g += 1) {
    const displayName = bulk.groupNameAt(STAMP, g);
    const reply = await http.postJson(http.api("/groups/create"), {
      group: displayName,
      note: "Created by tests/vendored/sts_directory_bulk_load_api.js, run " +
            STAMP.run + "."
    });
    watch.lap(reply.ms);
    if (reply.status === 200 && reply.body && reply.body.ok !== false &&
        reply.body.dn) {
      created.push({ displayName: displayName, dn: reply.body.dn });
    } else if (failures.length < 5) {
      failures.push(displayName + " -> " + reply.status + " " +
                    String(reply.text).slice(0, 300));
    }
  }
  watch.end();

  check("every group was created", function () {
    assert.strictEqual(created.length, SIZES.GROUPS,
      created.length + " of " + SIZES.GROUPS + " groups were created. The " +
      "first few refusals were:\n  " + failures.join("\n  "));
  });
  check("each group came back with the DN it was put at", function () {
    const wrong = created.filter(function (one) {
      return one.dn.toLowerCase().indexOf("cn=") !== 0;
    });
    assert.strictEqual(wrong.length, 0,
      "this operation puts a group at `cn=<name>,ou=groups` and answers with " +
      "the DN, which is what the membership writes below are addressed by. " +
      wrong.length + " came back with something else, e.g. " +
      JSON.stringify(wrong.slice(0, 3)));
  });
  // ONE OF THEM READ BACK BEFORE ANY MEMBER IS WRITTEN, and it is a real read
  // rather than an assumption. RFC 4519 makes `member` MUST on a
  // `groupOfNames` and this directory is schemaless, so it accepts one with
  // none — but the whole of section 3 is a claim about a count that STARTS AT
  // ZERO, and a create that quietly seeded a member would make every group
  // hold a hundred and one and report fifty defects in the read-back with
  // nothing pointing at the create.
  const first = await http.get(http.api("/groups?group=" +
                                        encodeURIComponent(created[0].dn)));
  check("a group is created with no members at all", function () {
    const held = (first.body && first.body.group) || {};
    assert.strictEqual(first.status, 200,
      "GET /admin-api/groups answered " + first.status + " for the group " +
      "just created at " + created[0].dn + ".");
    assert.strictEqual(held.memberCount, 0,
      created[0].dn + " holds " + held.memberCount + " membership value(s) " +
      "and nothing has been added to it yet. Section 3 counts up from zero, " +
      "so a group that starts with members makes every count below wrong by " +
      "the same amount and points at the wrong operation.");
  });

  const summary = bulk.summaryOf(watch);
  log.info("[groups] " + SIZES.GROUPS + " created in " +
           (summary.wallMs / 1000).toFixed(1) + "s — mean " +
           bulk.ms(summary.meanMs) + ", median " + bulk.ms(summary.medianMs));
  log.debug("Leaving createTheGroups().");
  return { groups: created, summary: summary };
}

// ---------------------------------------------------------------------------
// 3. A HUNDRED PEOPLE INTO EACH GROUP, ONE AT A TIME.
//
// **THE MEMBER IS SENT AS A DN AND NOT AS A USERNAME**, although this operation
// takes either. Two reasons and the second is the one that matters: the other
// two jobs write a DN — SCIM's member id IS a DN and an LDAP `modify` has
// nothing else to write — so sending a name here would be this job measuring a
// resolution step the other two never pay for; and the DN is what the create
// above answered with, so what is written is what this service said rather than
// what this file assembled.
// ---------------------------------------------------------------------------
async function addTheMembers(people, groups) {
  log.debug("Entering addTheMembers().");
  log.info("=== Adding " + SIZES.PER_GROUP + " people to each of " +
           groups.length + " groups (" + (SIZES.PER_GROUP * groups.length) +
           " membership writes) through /admin-api ===");

  const watch = bulk.Stopwatch("group.add-member [admin-api]").begin();
  const failures = [];
  const expected = {};
  let written = 0;
  let unchanged = 0;

  for (let g = 0; g < groups.length; g += 1) {
    const group = groups[g];
    // A BLOCK PER GROUP, so every person is in EXACTLY ONE group. That is what
    // makes the read-back an exact claim.
    const block = people.slice(g * SIZES.PER_GROUP, (g + 1) * SIZES.PER_GROUP);
    const perGroup = [];
    for (const person of block) {
      const reply = await http.postJson(http.api("/groups/add-member"), {
        group: group.dn,
        member: person.dn
      });
      watch.lap(reply.ms);
      perGroup.push(reply.ms);
      if (reply.status === 200 && reply.body && reply.body.ok !== false) {
        written += 1;
        expected[group.dn] = (expected[group.dn] || 0) + 1;
        if (reply.body.changed === false) {
          // THE IDEMPOTENT ANSWER, COUNTED SEPARATELY. This operation answers
          // ok with `changed: false` for somebody already in the group, which
          // is deliberate and argued at the operation — but in THIS job every
          // person is added to exactly one group exactly once, so a single one
          // of these means two blocks overlapped and the counts below are
          // about to disagree with the writes above.
          unchanged += 1;
        }
      } else if (failures.length < 5) {
        failures.push(group.displayName + " += " + person.username + " -> " +
                      reply.status + " " + String(reply.text).slice(0, 300));
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

  check("every membership write was accepted", function () {
    assert.strictEqual(written, SIZES.PER_GROUP * groups.length,
      written + " of " + (SIZES.PER_GROUP * groups.length) + " membership " +
      "writes were accepted. The first few refusals were:\n  " +
      failures.join("\n  "));
  });
  check("every membership write actually changed something", function () {
    assert.strictEqual(unchanged, 0,
      unchanged + " membership write(s) answered `changed: false`, meaning " +
      "that person was already in that group. This job puts each person in " +
      "exactly one group exactly once, so that cannot happen unless two " +
      "blocks overlapped — and if it did, the group counts below are a claim " +
      "about an arrangement this file got wrong rather than about the " +
      "service. It is asserted separately from the count above because both " +
      "answers are a 200 and only this one distinguishes them.");
  });

  const summary = bulk.summaryOf(watch);
  log.info("[members] " + written + " memberships in " +
           (summary.wallMs / 1000).toFixed(1) + "s — mean " +
           bulk.ms(summary.meanMs) + ", median " + bulk.ms(summary.medianMs));
  log.debug("Leaving addTheMembers().");
  return { summary: summary, expected: expected };
}

// ---------------------------------------------------------------------------
// 4. READ IT BACK.
//
// The people come back over SCIM and the entry out of the directory's own view;
// the groups out of `/admin-api/groups`, which is the READ half of the resource
// whose two writes this job just drove. That last one is the pairing that
// matters here: a create and an add that answered 200 and wrote nothing produce
// exactly the timings above, and they would look like the fastest run this
// service has ever had.
// ---------------------------------------------------------------------------
async function itReadsBackWhatItWrote(people, groups, catalogue, expected) {
  log.debug("Entering itReadsBackWhatItWrote().");
  log.info("=== Reading back a sample of the people, and every group ===");

  // SCIM needs a credential (RFC 7644 section 2). In development mode any
  // username and any password but one is accepted, so this is a turnstile
  // rather than a lock — and reading back through a DIFFERENT door from the one
  // that wrote is the rule `sts_admin_api_operations.js` states.
  const auth = "Basic " + Buffer.from("bulk-load-" + STAMP.run +
                                      ":not-checked-in-development")
                                .toString("base64");
  function scimGet(path) {
    return http.timed(base + "/scim/v2" + path, {
      headers: { "Accept": "application/scim+json", "Authorization": auth }
    });
  }

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
    const reply = await scimGet("/Users/" + encodeURIComponent(person.dn));
    if (reply.status !== 200 || !reply.body) {
      missing += 1;
      continue;
    }
    if (reply.body.userName !== person.username) {
      wrongValues.push(person.dn + " reads back as userName=" +
                       JSON.stringify(reply.body.userName));
    }
  }
  check("the sampled people are all in the directory", function () {
    assert.strictEqual(missing, 0,
      missing + " of " + sampled.length + " sampled people could not be read " +
      "back at GET /scim/v2/Users/<dn>, spread across the whole run.");
    assert.deepStrictEqual(wrongValues, [],
      "and each must read back under the username it was created with.");
  });

  // ONE FULL ENTRY, READ OUT OF THE DIRECTORY ITSELF, so that the attributes
  // this job filled are asserted where they are STORED rather than through a
  // mapping that could be inventing them.
  const one = sampled[Math.floor(sampled.length / 2)];
  const entry = await http.get(http.api("/ldap/directory?q=" +
                                        encodeURIComponent(one.username) +
                                        "&per=5"));
  check("a person's entry carries the fields this job filled", function () {
    assert.strictEqual(entry.status, 200,
      "GET /admin-api/ldap/directory answered " + entry.status + ".");
    const rows = (entry.body && entry.body.entries) || [];
    const found = rows.filter(function (row) {
      return String(row.dn || "").toLowerCase() === one.dn.toLowerCase();
    })[0];
    assert.ok(found,
      "the entry at " + one.dn + " is not in the directory's own view of " +
      "itself, searching for " + one.username + ". It answered with " +
      rows.length + " row(s).");
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
      "THE ENTRY DOES NOT HOLD WHAT THE CREATE WAS SENT. Every attribute this " +
      "job fills is on the catalogue that create validates against, so a " +
      "value that did not land is a create that accepted it and dropped it — " +
      "which no status code shows:\n  " + wrong.join("\n  "));
  });

  // EVERY GROUP, not a sample: there are only fifty of them and the counts are
  // the whole claim of section 3. `danglingCount` is the one field that can
  // tell "a hundred members" from "a hundred member VALUES, some of which name
  // nobody" — which is what a membership written from a wrong DN looks like.
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
      "these groups do not hold what was written into them. `memberCount` is " +
      "the values on the entry, `presentCount` how many of them name an entry " +
      "this directory holds, and a difference between the two is a dangling " +
      "member — which is what a membership written from the wrong DN " +
      "produces, silently, with a 200 on the way in:\n  " +
      wrongCounts.join("\n  "));
  });

  // AND THE GROUP LIST SEES THEM, which is a different question from the
  // drill-down above and is the one rule 7 is about: these fifty were created
  // through an operation that mirrors a console control, and a list that could
  // not find them would be the two halves of one resource disagreeing.
  const list = await http.get(http.api("/groups?q=" +
                                       encodeURIComponent(STAMP.prefix) +
                                       "&per=" + (SIZES.GROUPS + 10)));
  check("the group list finds this run's groups", function () {
    assert.strictEqual(list.status, 200,
      "GET /admin-api/groups answered " + list.status + ".");
    const shown = ((list.body && list.body.groups) || []).filter(function (row) {
      return String(row.dn || "").indexOf(STAMP.prefix) >= 0;
    });
    assert.strictEqual(shown.length, SIZES.GROUPS,
      "the list filtered to this run's prefix shows " + shown.length +
      " group(s) and " + SIZES.GROUPS + " were created. `matched` was " +
      (list.body && list.body.matched) + ". The drill-down found all fifty " +
      "one by one, so a disagreement here is between the two halves of one " +
      "resource rather than about whether the groups exist.");
  });

  log.info("[read-back] OK — " + sampled.length + " people sampled across " +
           "the run, one entry checked attribute by attribute, all " +
           groups.length + " groups hold exactly " + SIZES.PER_GROUP +
           " members that resolve, and the list finds them.");
  log.debug("Leaving itReadsBackWhatItWrote().");
}

// ---------------------------------------------------------------------------
// THE RUN.
// ---------------------------------------------------------------------------
async function test() {
  log.debug("Entering test().");
  log.info("Filling the DEFAULT realm's directory at " + base + " with " +
           SIZES.USERS + " people, " + SIZES.GROUPS + " groups and " +
           (SIZES.GROUPS * SIZES.PER_GROUP) + " memberships, ALL OF IT " +
           "THROUGH /admin-api. NOTHING IS DELETED AFTERWARDS.");

  bulk.checkSizes(assert);

  const ready = await bulk.preflight({ log: log, assert: assert, http: http,
                                       checks: checks });
  await theOperationsExist();
  const people = await createThePeople(ready.catalogue);
  const groups = await createTheGroups();
  const members = await addTheMembers(people.people, groups.groups);
  await itReadsBackWhatItWrote(people.people, groups.groups, ready.catalogue,
                               members.expected);
  bulk.report(log, [people.summary, groups.summary, members.summary], {
    base: base, door: "api", doorLabel: "the management API (/admin-api)",
    run: STAMP.run, prefix: STAMP.prefix, held: ready.held
  });

  log.info("LEFT BEHIND ON PURPOSE, in the default realm: " +
           people.people.length + " people at uid=" + STAMP.prefix + "-*, " +
           groups.groups.length + " groups at cn=" + STAMP.prefix + "-grp-*, " +
           "and " + (SIZES.GROUPS * SIZES.PER_GROUP) + " memberships between " +
           "them. Read them at " + base + "/admin/ldap/directory and " + base +
           "/admin/groups.");

  assert.ok(checks.count >= 15,
    "only " + checks.count + " checks ran. This file and the shared " +
    "preflight make fifteen against a healthy service, so a count this " +
    "low means a SECTION STOPPED BEING CALLED rather than that the " +
    "work got simpler.");
  log.info(checks.count + " checks passed.");
  log.info("Test completed successfully.");
  log.debug("Leaving test().");
}

const program = new Command();
program
  .name("sts_directory_bulk_load_api")
  .description("Create 5000 people, 50 groups and 5000 memberships in the " +
      "mock STS's DEFAULT realm ENTIRELY THROUGH /admin-api, read them back, " +
      "and report how long each kind of write took on average. Deletes " +
      "nothing.")
  .addOption(new Option("-u, --url <url>", "base url of the STS under test")
      .default(base))
  .parse(process.argv);
base = String(program.opts().url || base).replace(/\/+$/, "");
http = bulk.httpFor(base, log);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
