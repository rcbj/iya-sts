// ===========================================================================
// bulk_load.js — WHAT THE THREE BULK-LOAD JOBS SHARE, WHICH IS EVERYTHING
// EXCEPT THE DOOR.
//
// There are three of them since 2026-09-06 and they ask ONE question:
//
//   sts_directory_bulk_load_scim.js   SCIM 2.0            POST /scim/v2/Users
//   sts_directory_bulk_load_ldap.js   LDAP v3, raw socket  an `add` on 389
//   sts_directory_bulk_load_api.js    this service's own   POST /admin-api/...
//
// Each puts five thousand people, fifty groups and five thousand memberships
// into the DEFAULT realm through ITS OWN protocol, reads back what it wrote,
// and reports how long every write took. **The numbers are only worth having
// if the three are comparable**, and they are comparable only if the people are
// the same people, the sizes are the same sizes, the stopwatch is the same
// stopwatch and the report is the same report. That is this file.
//
// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY NOT HERE.
//
// **The door.** Not one line of this module opens a socket, signs a request or
// knows what a SCIM resource looks like. Each job owns its own transport, its
// own attribute spelling and its own read-back, because that is the thing under
// test and a shared implementation of it would be three jobs measuring one
// piece of code three times.
//
// **The preflight's WRITES.** `preflight()` below reads the directory and
// raises the entry ceiling over `/admin-api`, from every job including the LDAP
// one. That is not the LDAP job cheating: the ceiling is a SETTING, there is no
// way to change a setting over LDAP, and the alternative — three jobs each with
// their own copy of "ask the management API for room" — is the drift this file
// exists to prevent. What each job must do through its own door is the
// WRITES IT IS MEASURING, and it does.
//
// ---------------------------------------------------------------------------
// THE PEOPLE ARE DETERMINISTIC FROM THE INDEX, and that is worth the paragraph
// it was worth in the job this module was extracted from: a failure at person
// 3,417 has to be reproducible, and a `Math.random()` in here would make "run
// it again and look" impossible. The lists are small and the combinations are
// not — index arithmetic over six lists gives every one of five thousand people
// a different name, a different address and a different employee number without
// a dictionary in the file.
//
// The VALUES have to survive input validation (this service validates every
// endpoint), so each generator produces the shape its attribute is actually
// for: an address in `street`, an e-mail with an `@` in it, a phone number that
// looks like one. A field filled with `xxx` would be a test of nothing and
// would eventually fail against a validator for the right reason.
//
// ---------------------------------------------------------------------------
// EVERY NAME CARRIES THE DOOR AS WELL AS THE RUN, AND THAT IS NEW HERE.
//
// One job could stamp its people `bulk-<run>-000001`. Three cannot: they run in
// one suite against one directory, none of them deletes anything, and a
// collision would be reported as `LDAP_ENTRY_ALREADY_EXISTS` five thousand
// times by whichever ran second — a refusal that names the one-entry-per-person
// rule and has nothing to do with it. So the prefix is `bulk-<door>-<run>-` and
// `stampFor()` is the only place it is built.
// ===========================================================================

"use strict";

const names = require("./random_username.js");

// ---------------------------------------------------------------------------
// THE SIZES. 5000 / 50 / 100 is what these jobs were asked for and what they do
// by default. The three environment variables override them, for two honest
// uses: a smaller run while somebody is editing one of these files, and a
// larger one when the question is where it starts to hurt.
//
// **THEY ARE SHARED ON PURPOSE.** Setting `BULK_USERS=500` has to move all
// three or the comparison between them stops meaning anything — which is
// exactly what a per-job variable would invite somebody to do by accident.
// ---------------------------------------------------------------------------
const SIZES = {
  USERS: Number(process.env.BULK_USERS || 5000),
  GROUPS: Number(process.env.BULK_GROUPS || 50),
  PER_GROUP: Number(process.env.BULK_MEMBERS_PER_GROUP || 100),
  // How many of the created people are read back one by one at the end. A
  // sample rather than all of them: the read-back is there to show that what
  // was written is what is stored, and five thousand more requests would double
  // each run to say the same thing a twenty-fifth time.
  SAMPLE: Number(process.env.BULK_READ_BACK_SAMPLE || 25)
};

// The three checked against each other, because the alternative is a job that
// silently puts the same person in two groups and reports a membership count
// nobody can read. Called by each job before it writes anything.
function checkSizes(assert) {
  assert.ok(SIZES.USERS > 0 && SIZES.GROUPS > 0 && SIZES.PER_GROUP > 0,
    "BULK_USERS, BULK_GROUPS and BULK_MEMBERS_PER_GROUP must all be positive; " +
    "they are " + SIZES.USERS + ", " + SIZES.GROUPS + " and " +
    SIZES.PER_GROUP + ".");
  assert.ok(SIZES.GROUPS * SIZES.PER_GROUP <= SIZES.USERS,
    SIZES.GROUPS + " groups of " + SIZES.PER_GROUP + " needs " +
    (SIZES.GROUPS * SIZES.PER_GROUP) + " people and only " + SIZES.USERS +
    " are being created. These jobs put each person in exactly one group so " +
    "that `a hundred members` is an exact claim; overlapping the blocks would " +
    "make the read-back check assert something the job arranged rather than " +
    "something the service did.");
}

// ---------------------------------------------------------------------------
// THE RUN'S OWN MARK, AND THE DOOR'S.
//
// Nothing any of these jobs writes is ever deleted, so a second run against the
// same service has to be able to create five thousand people beside the last
// run's five thousand — and a person reading the directory afterwards has to be
// able to tell them apart, and to tell SCIM's five thousand from LDAP's.
//
// `door` is a short word (`scim`, `ldap`, `api`) and it is REQUIRED rather than
// defaulted: a job that forgot it would collide with the other two and the
// failure would arrive as a refusal about one entry per person.
// ---------------------------------------------------------------------------
function stampFor(door) {
  const run = String(names.runStamp()).toLowerCase().replace(/[^a-z0-9]/g, "")
      .slice(0, 12);
  const which = String(door || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  if (!which) {
    throw new Error("bulk_load.stampFor() needs the door this job drives — " +
                    "'scim', 'ldap' or 'api'. Every name a bulk job invents " +
                    "carries it, because the three run in one suite against " +
                    "one directory and none of them deletes anything.");
  }
  return { door: which, run: run, prefix: "bulk-" + which + "-" + run };
}

// ---------------------------------------------------------------------------
// THE STOPWATCH.
//
// It keeps every lap rather than a running total, because the median and the
// percentiles are the point: a mean on its own cannot tell a service that got
// uniformly slower from one that stalled once for four seconds, and those two
// are different defects.
// ---------------------------------------------------------------------------
function Stopwatch(what) {
  return {
    what: what,
    laps: [],
    startedAt: 0,
    finishedAt: 0,
    begin: function () { this.startedAt = Date.now(); return this; },
    lap: function (ms) { this.laps.push(ms); },
    end: function () { this.finishedAt = Date.now(); return this; }
  };
}

function percentile(sorted, fraction) {
  if (!sorted.length) {
    return 0;
  }
  // The nearest-rank definition, which is the one that cannot invent a value no
  // request ever took: p95 of five thousand laps is a lap that happened.
  const rank = Math.ceil(fraction * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1];
}

function summaryOf(watch) {
  const sorted = watch.laps.slice(0).sort(function (a, b) { return a - b; });
  const total = watch.laps.reduce(function (n, ms) { return n + ms; }, 0);
  const wall = (watch.finishedAt || Date.now()) - (watch.startedAt || Date.now());
  return {
    operation: watch.what,
    count: watch.laps.length,
    // THE WALL CLOCK AND THE SUM ARE BOTH REPORTED AND THEY ARE NOT THE SAME
    // NUMBER. The sum is time spent inside operations; the wall clock is that
    // plus whatever the job did between them. A gap between the two is the JOB
    // being slow, not the service, and reporting one without the other would
    // hide which.
    wallMs: wall,
    inRequestsMs: total,
    meanMs: watch.laps.length ? total / watch.laps.length : 0,
    medianMs: percentile(sorted, 0.5),
    p95Ms: percentile(sorted, 0.95),
    p99Ms: percentile(sorted, 0.99),
    minMs: sorted.length ? sorted[0] : 0,
    maxMs: sorted.length ? sorted[sorted.length - 1] : 0,
    perSecond: wall > 0 ? (watch.laps.length / (wall / 1000)) : 0
  };
}

function ms(n) { return n.toFixed(2) + "ms"; }

// A counter of assertions, so that each job can put a floor under its own —
// `sts_admin_console.js`'s rule: a section that stops being called takes its
// assertions with it and the run still says "passed", which is the one failure
// mode a suite cannot report about itself.
function checker(log) {
  const state = { count: 0 };
  state.check = function (what, fn) {
    fn();
    state.count += 1;
    log.debug("check passed: " + what);
  };
  return state;
}

// ---------------------------------------------------------------------------
// THE FAKE PEOPLE.
// ---------------------------------------------------------------------------
const GIVEN = ["Ada", "Bram", "Cleo", "Dmitri", "Esi", "Farid", "Greta",
               "Hana", "Ilya", "Jun", "Kofi", "Lena", "Mateo", "Nadia",
               "Omar", "Priya", "Quinn", "Rosa", "Sven", "Tariq", "Ulla",
               "Viktor", "Wren", "Ximena", "Yusuf", "Zora"];
const FAMILY = ["Abara", "Bergström", "Castellanos", "Dvorak", "Eriksen",
                "Fontaine", "Gallagher", "Haddad", "Ishikawa", "Jovanovic",
                "Kowalski", "Lindqvist", "Mwangi", "Nakamura", "Oyelaran",
                "Petrov", "Quiroga", "Rasmussen", "Salvatierra", "Tanaka",
                "Ueda", "Vasquez", "Wickramasinghe", "Xu", "Yildirim",
                "Zeleny"];
const TITLES = ["Systems Engineer", "Security Analyst", "Product Manager",
                "Staff Accountant", "Field Technician", "Research Fellow",
                "Support Specialist", "Data Steward", "Site Reliability Engineer",
                "Programme Director"];
const DEPARTMENTS = ["Engineering", "Security", "Finance", "Operations",
                     "Research", "Support", "Legal", "Facilities"];
const CITIES = [["Auckland", "AUK", "1010", "NZ"],
                ["Bristol", "BST", "BS1 4DJ", "GB"],
                ["Cape Town", "WC", "8001", "ZA"],
                ["Dortmund", "NW", "44135", "DE"],
                ["Edmonton", "AB", "T5J 0N3", "CA"],
                ["Fukuoka", "40", "812-0011", "JP"],
                ["Galway", "G", "H91 T8NW", "IE"],
                ["Hyderabad", "TG", "500081", "IN"],
                ["Ipswich", "SFK", "IP1 1BB", "GB"],
                ["Jyväskylä", "KS", "40100", "FI"]];
const STREETS = ["Harbour Road", "Kestrel Lane", "Old Mill Way",
                 "Sixth Avenue", "Threadneedle Street", "Warehouse Row"];
const LANGUAGES = ["en-GB", "en-US", "de-DE", "ja-JP", "fi-FI", "es-MX"];
const EMPLOYEE_TYPES = ["staff", "contractor", "intern", "vendor"];
const ORGANISATIONS = ["Northwind Trading", "Fabrikam Industrial",
                       "Contoso Health", "Litware Logistics"];

// The generators, BY THE LDAP ATTRIBUTE NAME the catalogue publishes — which is
// the vocabulary two of the three doors speak natively and the third is mapped
// onto. That choice is deliberate and it decides where the translation lives:
// the SCIM job carries an LDAP-to-SCIM map it READS from `GET /admin-api/scim`
// rather than a second set of generators, so a person written over SCIM and a
// person written over LDAP differ in how they got there and in nothing else.
const FIELDS = {
  givenName: function (p) { return p.given; },
  sn: function (p) { return p.family; },
  cn: function (p) { return p.given + " " + p.family; },
  displayName: function (p) { return p.given + " " + p.family.charAt(0) + "."; },
  mail: function (p) { return p.username + "@example.test"; },
  telephoneNumber: function (p) {
    return "+44 1632 " + String(100000 + (p.i % 900000)).slice(0, 6);
  },
  mobile: function (p) {
    return "+44 7700 " + String(900000 + (p.i % 99999)).slice(0, 6);
  },
  title: function (p) { return TITLES[p.i % TITLES.length]; },
  o: function (p) { return ORGANISATIONS[p.i % ORGANISATIONS.length]; },
  ou: function (p) { return DEPARTMENTS[p.i % DEPARTMENTS.length]; },
  departmentNumber: function (p) {
    return "D-" + String(100 + (p.i % 800));
  },
  employeeNumber: function (p) { return "E" + String(1000000 + p.i); },
  employeeType: function (p) {
    return EMPLOYEE_TYPES[p.i % EMPLOYEE_TYPES.length];
  },
  street: function (p) {
    return String(1 + (p.i % 400)) + " " + STREETS[p.i % STREETS.length];
  },
  l: function (p) { return p.city[0]; },
  st: function (p) { return p.city[1]; },
  postalCode: function (p) { return p.city[2]; },
  c: function (p) { return p.city[3]; },
  preferredLanguage: function (p) {
    return LANGUAGES[p.i % LANGUAGES.length];
  },
  description: function (p) {
    return "Created by tests/vendored/sts_directory_bulk_load_" + p.door +
           ".js, run " + p.run + ", person " + p.i + " of " + SIZES.USERS + ".";
  }
};

function personAt(stamp, i) {
  const username = stamp.prefix + "-" + String(i).padStart(6, "0");
  return {
    i: i,
    door: stamp.door,
    run: stamp.run,
    username: username,
    given: GIVEN[i % GIVEN.length],
    family: FAMILY[(i * 7 + Math.floor(i / FAMILY.length)) % FAMILY.length],
    city: CITIES[i % CITIES.length]
  };
}

function attributesFor(person, catalogue) {
  const out = {};
  catalogue.forEach(function (attribute) {
    out[attribute] = FIELDS[attribute](person);
  });
  return out;
}

function groupNameAt(stamp, g) {
  return stamp.prefix + "-grp-" + String(g).padStart(3, "0");
}

// ---------------------------------------------------------------------------
// HTTP.
//
// One helper, and it TIMES every call — because in these jobs the duration of
// the operation is the thing being measured and a second code path that did not
// measure would eventually be the one doing the work.
//
// **THE LDAP JOB USES THIS TOO, for its preflight and for the half of its
// read-back that comes off `/admin-api`.** What it does NOT use it for is any
// of the three things it is timing, and that is the line: this module measures,
// and the job's own door writes.
// ---------------------------------------------------------------------------
function httpFor(base, log) {
  const at = String(base).replace(/\/+$/, "");
  async function timed(url, options) {
    log.debug("Entering timed(). url=" + url);
    const started = process.hrtime.bigint();
    const r = await fetch(url, options || {});
    const text = await r.text();
    const took = Number(process.hrtime.bigint() - started) / 1e6;
    let body;
    try {
      body = JSON.parse(text);
    } catch (e) {
      // Not JSON — an HTML page or an empty body. The caller reports the status
      // and the raw text, which says more than a parse error would.
      body = null;
    }
    log.debug("Leaving timed(). status=" + r.status + " in " +
              took.toFixed(1) + "ms");
    return { status: r.status, body: body, text: text, ms: took };
  }
  return {
    base: at,
    timed: timed,
    get: function (url) { return timed(url); },
    postJson: function (url, payload) {
      return timed(url, { method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(payload || {}) });
    },
    api: function (path) { return at + "/admin-api" + path; }
  };
}

// The total the directory reports, whatever the paging shape of the answer.
// Read defensively on purpose: these jobs ask for one entry per page and only
// want the TOTAL, and a paging field renamed under them should leave the run
// reporting "unknown" rather than failing on arithmetic.
function entryCountOf(body) {
  if (!body) {
    return 0;
  }
  const paging = body.paging || body.entriesPaging || {};
  const candidates = [paging.total, paging.matched, body.total, body.count,
                      (body.entries || []).length];
  for (const value of candidates) {
    if (typeof value === "number") {
      return value;
    }
  }
  return 0;
}

// ---------------------------------------------------------------------------
// 0. WHAT IS ALREADY HERE, AND ROOM TO PUT MORE.
//
// Shared by all three jobs and identical in all three, which is why it is here:
// the ceiling, the catalogue and the "is the service actually there" probe are
// facts about the DIRECTORY rather than about any door onto it.
//
// IT RAISES `ldap.maxEntries` AND LEAVES IT RAISED, WHICH IS THE ONE SETTING
// THESE JOBS DO NOT PUT BACK.
//
// The ceiling defaults to 2000 entries and it is PROCESS-WIDE — the cap is on
// what this node process holds, not on a realm — so five thousand people do not
// fit under it, and with three of these jobs in one suite fifteen thousand do
// not fit under whatever the last one left.
//
// tests/CLAUDE.md's rule is that a job restores a setting with `reset` rather
// than by writing the old value back. **Restoring this one would be worse than
// leaving it**, and that is a judgement rather than an oversight: the entries
// stay, so a ceiling put back to 2000 is a service that holds fifteen thousand
// entries and refuses to create the next one — every later create, in any
// protocol, by anybody. The raised ceiling changes nothing that has already
// happened and unblocks everything that comes next, which is the opposite trade
// from the one that rule was written for.
// ---------------------------------------------------------------------------
async function preflight(options) {
  const opts = options || {};
  const log = opts.log;
  const assert = opts.assert;
  const http = opts.http;
  const check = opts.checks.check;
  log.debug("Entering preflight().");
  log.info("=== Preflight ===");

  // A SERVICE THAT IS NOT THERE IS A FAILURE AND NOT A SKIP, which is the rule
  // CLAUDE.md records the 2026-08-28 default flip for: a job that reports green
  // having driven nothing is worse than one that is honestly absent.
  const status = await http.get(http.api("/status"));
  assert.strictEqual(status.status, 200,
    "GET /admin-api/status answered " + status.status + " at " + http.base +
    ". This job needs the mock and nothing else.");

  const before = await http.get(http.api("/ldap/directory?per=1"));
  check("the directory answers before anything is written", function () {
    assert.strictEqual(before.status, 200,
      "GET /admin-api/ldap/directory answered " + before.status + ". Every " +
      "assertion below is about what that endpoint holds, so this is a " +
      "failure rather than something to work around.");
    assert.notStrictEqual(before.body && before.body.directory, false,
      "this process has no embedded directory loaded, so there is nowhere " +
      "to put five thousand people. That is a build without " +
      "ldap/ldap_server.js rather than a fault, and it is still a failure " +
      "for this job.");
  });
  const held = entryCountOf(before.body);
  log.info("The default realm's directory holds " + held + " entry(ies) " +
           "before this job writes anything.");

  const wanted = Math.max(2000,
      Math.ceil((held + SIZES.USERS + SIZES.GROUPS + SIZES.SAMPLE + 50) * 1.2));
  const raised = await http.postJson(http.api("/config/set"),
                                     { key: "ldap.maxEntries", value: wanted });
  check("the entry ceiling was raised", function () {
    assert.ok(raised.status === 200 && raised.body && raised.body.ok !== false,
      "POST /admin-api/config/set should raise ldap.maxEntries to " + wanted +
      "; it answered " + raised.status + " " +
      String(raised.text).slice(0, 300) + ". The default is 2000 and it is " +
      "PROCESS-WIDE, so without this the writes below stop being timed and " +
      "start being refused partway through — which reads in the log as a " +
      "service that got slower.");
  });
  log.info("ldap.maxEntries is now " + wanted + " and is LEFT THERE. Putting " +
           "it back would leave this service holding more entries than it " +
           "will create, so the next create by anybody, in any protocol, " +
           "would be refused.");

  // THE CATALOGUE, read rather than written down. `POST /admin-api/users/create`
  // REFUSES an attribute that is not on it and fails the whole create, so a
  // field invented here that the document has never heard of would fail five
  // thousand creates for a reason that is not about the load at all.
  //
  // **ALL THREE JOBS FILL THE SAME SET, AND THAT IS WHY THIS IS SHARED.** The
  // LDAP door would accept any attribute name at all — the directory is
  // schemaless — and the SCIM door has its own vocabulary. Reading the
  // management API's catalogue in every one of them is what makes the three
  // populations identical, so a difference in the timings is a difference in
  // the door.
  const form = await http.get(http.api("/users/new"));
  assert.strictEqual(form.status, 200,
    "GET /admin-api/users/new answered " + form.status + ". It is the " +
    "attribute catalogue a create validates against and these jobs fill " +
    "every field it offers.");
  const offered = ((form.body && form.body.fields) || []).map(function (row) {
    return row.attribute;
  });
  const usable = Object.keys(FIELDS).filter(function (attribute) {
    return offered.indexOf(attribute) >= 0;
  });
  const unknown = Object.keys(FIELDS).filter(function (attribute) {
    return offered.indexOf(attribute) < 0;
  });
  if (unknown.length) {
    // A WARNING AND NOT A FAILURE, and the floor below is what keeps that
    // honest: the catalogue is allowed to change, and this file having a
    // generator for something it no longer offers is a stale generator rather
    // than a broken service.
    log.warn("bulk_load.js has generators for " + unknown.join(", ") + ", and " +
             "GET /admin-api/users/new does not offer them. They are NOT " +
             "sent — a create carrying an attribute that is not on the " +
             "catalogue is refused whole.");
  }
  check("the catalogue offers most of the fields these jobs fill", function () {
    assert.ok(usable.length >= 10,
      "only " + usable.length + " of bulk_load.js's " +
      Object.keys(FIELDS).length + " generated attributes are on the " +
      "catalogue " + JSON.stringify(offered) + ". Below ten, this job is " +
      "creating five thousand nearly-empty entries and calling them " +
      "populated, which is the one way its numbers could be quietly wrong.");
  });
  log.info("Filling " + usable.length + " attribute(s) per person: " +
           usable.join(", "));

  log.debug("Leaving preflight(). " + held + " entry(ies) held.");
  return { held: held, catalogue: usable };
}

// ---------------------------------------------------------------------------
// THE NUMBERS.
//
// Logged as a table a person reads AND as one bunyan record per operation, so
// that the run's own log file — tests/report/<run>/logs/NN-<job>.log — is the
// record rather than something a person had to copy out of a terminal.
//
// **THE DOOR IS ON EVERY ROW AND IN EVERY RECORD**, which is the whole point of
// there being three of these: a reader comparing them has three log files, and
// a table that said only `users.create` in all three would be three tables
// nobody could line up.
//
// `BULK_TIMINGS_FILE` writes the same thing as JSON where somebody wants to
// plot it. **The door is spliced into the filename** rather than used as given:
// one variable and three jobs would otherwise be three writes to one path, and
// the file left on disk would be whichever job finished last — silently, with
// two runs' numbers gone. Unset, nothing is written and nothing is lost.
// ---------------------------------------------------------------------------
function report(log, summaries, meta) {
  log.debug("Entering report().");
  log.info("=== How long each operation took, through " + meta.doorLabel +
           " ===");
  // ---------------------------------------------------------------------
  // THE ONE THING THAT MAKES THESE THREE TABLES NOT DIRECTLY COMPARABLE, SAID
  // ON EVERY ONE OF THEM RATHER THAN IN A HEADER SOMEBODY MIGHT NOT READ.
  //
  // The three jobs run in one suite against ONE directory and none of them
  // deletes anything, so each starts against a bigger store than the last —
  // roughly empty, then five thousand, then ten. A measured run:
  //
  //   users.create  [scim]        52.18ms  starting from  26 entries
  //   users.create  [ldap]        33.11ms  starting from  5,300
  //   users.create  [admin-api]   50.20ms  starting from  10,400
  //
  // and within the SCIM job alone the create went from 9ms at the five
  // hundredth person to 54ms at the five thousandth. **A create here is not
  // constant-time in the size of the directory**, which is itself worth
  // knowing and is the thing this job exists to measure — but it means the
  // three `users.create` rows are three different questions, and reading them
  // as "LDAP is faster than SCIM" would be reading the store's growth as a
  // property of the door.
  //
  // `directoryEntriesBefore` is on the JSON for exactly this, and it is the
  // number to line the tables up by. **THE MEMBERSHIP ROWS ARE THE HONEST
  // COMPARISON**: a membership write touches one group entry whose size is the
  // same in all three runs, and there the doors differ by two orders of
  // magnitude for a reason that is about the door.
  //
  // Running one job against a fresh service is how to compare like with like:
  // `BULK_USERS=5000 node sts_directory_bulk_load_<door>.js` against a mock
  // that has just started.
  // ---------------------------------------------------------------------
  log.info("  This run started against " + meta.held + " directory " +
           "entry(ies). A create here is NOT constant-time in the size of the " +
           "store, and the three bulk-load jobs run one after another against " +
           "one directory that nothing deletes from — so compare the " +
           "`users.create` row with a run that started from a similar number, " +
           "not with the other two doors' rows in the same suite. The " +
           "membership rows are the comparison that holds.");

  // The first column is 30 wide because the operation name carries the door
  // (`group.add-member [admin-api]` is 28) and a name wider than its column
  // pushes every other cell on that ROW right — so the one row that
  // overflows is the one a reader cannot line up with the other two files.
  const widths = [30, 7, 10, 11, 11, 11, 11, 10, 11, 9];
  const header = ["operation", "count", "total", "mean", "median", "p95",
                  "p99", "fastest", "slowest", "rate"];
  function row(cells) {
    return cells.map(function (cell, n) {
      return String(cell).padEnd(widths[n]);
    }).join("");
  }
  log.info(row(header));
  log.info(row(widths.map(function (w) { return "-".repeat(w - 1); })));
  summaries.forEach(function (one) {
    log.info(row([one.operation, one.count,
                  (one.wallMs / 1000).toFixed(1) + "s",
                  ms(one.meanMs), ms(one.medianMs), ms(one.p95Ms),
                  ms(one.p99Ms), ms(one.minMs), ms(one.maxMs),
                  one.perSecond.toFixed(1) + "/s"]));
  });

  summaries.forEach(function (one) {
    // ONE RECORD PER OPERATION, with the numbers as NUMBERS. The table above is
    // for a person and this is for whatever reads the log afterwards; a reader
    // that had to parse "8.24ms" back out of a padded column would be the
    // reason somebody eventually deletes the table.
    log.info(Object.assign({ door: meta.door }, one),
             "timing: [" + meta.door + "] " + one.operation + " mean " +
             ms(one.meanMs) + " over " + one.count + " call(s)");
  });

  const document = {
    service: meta.base,
    door: meta.door,
    doorLabel: meta.doorLabel,
    runStamp: meta.run,
    prefix: meta.prefix,
    when: new Date().toISOString(),
    sizes: { users: SIZES.USERS, groups: SIZES.GROUPS,
             membersPerGroup: SIZES.PER_GROUP },
    directoryEntriesBefore: meta.held,
    operations: summaries
  };
  const where = process.env.BULK_TIMINGS_FILE;
  if (where) {
    try {
      const fs = require("fs");
      const dot = where.lastIndexOf(".");
      const slash = Math.max(where.lastIndexOf("/"), where.lastIndexOf("\\"));
      const path = dot > slash
        ? where.slice(0, dot) + "." + meta.door + where.slice(dot)
        : where + "." + meta.door;
      fs.writeFileSync(path, JSON.stringify(document, null, 2));
      log.info("The timings are also at " + path + ".");
    } catch (e) {
      // Worth a line and not worth failing a run that measured everything it
      // was asked to: the numbers are in the log either way, which is where
      // these jobs' own headers say the record is.
      log.warn("Could not write the timings file: " + e.message);
    }
  }
  log.debug("Leaving report().");
}

module.exports = {
  SIZES: SIZES,
  checkSizes: checkSizes,
  stampFor: stampFor,
  Stopwatch: Stopwatch,
  summaryOf: summaryOf,
  percentile: percentile,
  ms: ms,
  checker: checker,
  FIELDS: FIELDS,
  personAt: personAt,
  attributesFor: attributesFor,
  groupNameAt: groupNameAt,
  httpFor: httpFor,
  entryCountOf: entryCountOf,
  preflight: preflight,
  report: report
};
