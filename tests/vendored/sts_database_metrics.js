'use strict';
//
// File: sts_database_metrics.js
//
// ===========================================================================
// THE DATABASE REPORT, AGAINST A REAL POSTGRESQL (2026-09-11).
//
// **THIS REPOSITORY'S OWN (`local: true`)**, on the first of
// `tests/CLAUDE.md`'s two questions: what it drives is `/admin/database` and
// `/admin-api/database`, and the tree that adds a page to that console is the
// tree that should go red when the page stops answering.
//
// `tests/database_metrics.js` holds the contracts that need no database — the
// probe table against the page's sections, every statement a read, the three
// "no database" sentences. **What needs a SERVER is everything that makes the
// page worth having**, and none of it is assertable in process:
//
//   * **THAT THE STATEMENTS ARE VALID SQL FOR THIS SERVER AT ALL.** They are
//     PostgreSQL's grammar and PostgreSQL's catalog; an in-process test
//     asserting they parse would be asserting its own opinion of both.
//   * **THAT THE COLUMNS ARRIVE.** The page draws the keys the server hands
//     back — that is the whole design — so "it renders" and "it renders
//     something" are different claims and only a server can tell them apart.
//   * **THAT A PROBE THE ROLE MAY NOT READ COSTS A ROW AND NOT THE PAGE.**
//   * **AND THAT NO CREDENTIAL IS IN THE REPLY.** The connection string
//     carries a password, and the one thing this surface must never do is
//     print it.
//
// **IT SKIPS RATHER THAN FAILS WHEN THERE IS NO DATABASE**, which is this
// suite's narrow exception and is argued here: every other job in it drives a
// service whose configuration the launcher controls, and `persistence.mode`
// is RESTART-ONLY — the store is opened before the listener binds — so a job
// cannot switch it on for itself. The launchers' stacks run postgres and this
// runs there; a hand-run against the default memory-mode service has nothing
// to test, and the honest report for that is SKIPPED with the reason rather
// than green having driven nothing.
// ===========================================================================

const assert = require("assert");
const { Command, Option } = require("commander");

var appconfig;
try {
  appconfig = require(process.env.CONFIG_FILE);
} catch (e) {
  // The launchers always set CONFIG_FILE; a hand-run without one must still
  // load, for the reason tests/wait_for.js gives.
  appconfig = {};
}

var bunyan = require("bunyan");
var log = bunyan.createLogger({ name: "sts_database_metrics",
                                level: appconfig.LOG_LEVEL || "info" });
log.info("Log initialized. logLevel=" + log.level());

var stsUrl = process.env.WSTRUST_STS_URL || "https://localhost:8081/sts";
var base = process.env.OID4VCI_ISSUER_URL || stsUrl.replace(/\/sts\/?$/, "");
base = String(base).replace(/\/+$/, "");
var api = base + "/admin-api";

var checks = 0;
function check(what, fn) {
  fn();
  checks += 1;
  log.info("  ✓ " + what);
}

async function getJson(path) {
  const r = await fetch(api + path);
  const raw = await r.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch (e) {
    // Not JSON — an HTML error page. Quoting it whole says more than a parse
    // failure would.
    body = raw;
  }
  return { status: r.status, body: body, raw: raw };
}

async function test() {
  log.info("=== A. the report answers at all ===");

  const view = await getJson("/database");
  check("GET /admin-api/database answers 200", function () {
    assert.strictEqual(view.status, 200, view.raw.slice(0, 300));
  });

  // **200 WITH `available: false` IS NOT A FAILURE AND IS THE ORDINARY CASE.**
  // `persistence.mode` defaults to `memory`, the question was answerable, and
  // the answer is that there is nothing to report.
  if (!view.body.available) {
    check("it says WHICH of three reasons there is no database, rather than " +
          "answering with empty tables — not configured, configured and not " +
          "open, and open with no metrics function are three different " +
          "things to do something about", function () {
            assert.ok(String(view.body.why).length > 60,
              JSON.stringify(view.body).slice(0, 300));
            assert.strictEqual(view.body.probes, undefined,
              "a probes member on an unavailable report would let a client " +
              "read an empty object as 'everything is zero'");
          });
    log.warn("persistence.mode is \"" + view.body.mode + "\", so there is no " +
             "database to report on and the rest of this job is SKIPPED. " +
             "That is not a pass: the sections below are the only ones that " +
             "assert anything about a real server. persistence.mode is " +
             "restart-only, so a job cannot switch it on for itself — run " +
             "this against a stack whose service is in postgres mode.");
    log.info(checks + " check(s) passed; the database sections were skipped.");
    return;
  }

  log.info("=== B. it connected, and it says what to ===");

  check("the report is available and the collection succeeded", function () {
    assert.strictEqual(view.body.ok, true,
      "the database could not be read: " + view.body.error);
  });
  check("and it names the target as four FIELDS rather than as the " +
        "connection string they were parsed out of", function () {
          const t = view.body.target || {};
          assert.ok(t.host && t.database, JSON.stringify(t));
          assert.ok(Object.prototype.hasOwnProperty.call(t, "user"));
        });
  check("**AND NO CREDENTIAL IS IN THE REPLY**, which is the one thing this " +
        "surface must never do: the connection string carries a password",
        function () {
          const raw = JSON.stringify(view.body);
          assert.ok(raw.indexOf("postgres://") < 0, "a connection string");
          assert.ok(!/"password"/.test(raw), "a password member");
        });
  check("the pool is reported beside the server's own counts — they are " +
        "different ends and answer different questions: postgres can say how " +
        "many connections exist, and only the client can say how many of " +
        "them this service is holding", function () {
          assert.ok(view.body.pool && typeof view.body.pool.max === "number",
            JSON.stringify(view.body.pool));
        });
  check("and the whole collection is bounded by a statement timeout on the " +
        "single connection the page borrows", function () {
          assert.ok(view.body.statementTimeoutMs >= 250,
            String(view.body.statementTimeoutMs));
          assert.strictEqual(view.body.statementTimeoutSet, true);
        });

  log.info("=== C. the columns are the SERVER's ===");

  const probes = view.body.probes;
  check("every probe ran", function () {
    assert.ok(Object.keys(probes).length >= 15,
      Object.keys(probes).length + " probe(s)");
  });

  // **THE ASSERTION THIS JOB EXISTS FOR.** The page draws the keys the server
  // handed back, so what has to be true is that the server handed back keys —
  // and a named column would be this test having the same opinion the page
  // was supposed to have stopped having.
  check("pg_stat_database came back with a substantial number of columns, " +
        "and this job does NOT name any of them: the count differs between " +
        "major versions (twenty-eight on PostgreSQL 16, thirty on 18) and a " +
        "test naming one would be the same mistake the page exists not to " +
        "make", function () {
          const db = probes.database;
          assert.ok(db && db.ok, JSON.stringify(db).slice(0, 200));
          assert.ok(db.row && Object.keys(db.row).length >= 15,
            "only " + Object.keys(db.row || {}).length + " columns");
        });
  check("and the two counters every version of that view has ARE there, " +
        "which is the floor a client can rely on", function () {
          const row = probes.database.row;
          assert.ok(Object.prototype.hasOwnProperty.call(row, "xact_commit"));
          assert.ok(Object.prototype.hasOwnProperty.call(row, "blks_hit"));
        });

  log.info("=== D. a probe that could not be collected is a ROW ===");

  check("the failed list is present, and every entry in it carries " +
        "PostgreSQL's own SQLSTATE — 42P01 (a view this server version does " +
        "not have) and 42501 (a grant this role does not hold) are " +
        "completely different things to do about, and a message alone would " +
        "make a client parse English", function () {
          assert.ok(Array.isArray(view.body.failed));
          view.body.failed.forEach(function (id) {
            assert.strictEqual(probes[id].ok, false);
            assert.ok(typeof probes[id].code === "string",
              id + " has no SQLSTATE");
            assert.ok(String(probes[id].what).length > 20,
              id + " does not say what it would have shown");
          });
        });
  check("and a failure costs a ROW rather than the page: the other probes " +
        "still answered", function () {
          const ok = Object.keys(probes).filter(function (id) {
            return probes[id].ok;
          });
          assert.ok(ok.length >= Object.keys(probes).length -
                                 view.body.failed.length);
          assert.ok(ok.length > 5, ok.length + " probes answered");
        });

  log.info("=== E. the schema this service owns ===");

  check("the schema is reported as the SERVER's current_schema() — there is " +
        "no setting for it, it comes from the search_path in the connection " +
        "string, and current_schema() is what every schema probe actually " +
        "scoped to", function () {
          assert.ok(view.body.schema, JSON.stringify(view.body.schema));
        });
  check("the tables this service owns are there, with their statistics",
        function () {
          const tables = probes.tables;
          assert.ok(tables && tables.ok, JSON.stringify(tables).slice(0, 200));
          assert.ok(tables.rows.length >= 5,
            tables.rows.length + " table(s)");
          const names = tables.rows.map(function (one) { return one.relname; });
          assert.ok(names.indexOf("sts_ldap_entries") >= 0, names.join(", "));
        });
  check("and their sizes, with the planner's row estimate NORMALISED: " +
        "reltuples is -1 for a table that has never been analysed, which is " +
        "every table in a database this service has just built, and a page " +
        "that printed it would report minus one row", function () {
          const sizes = probes.sizes;
          assert.ok(sizes && sizes.ok);
          sizes.rows.forEach(function (row) {
            assert.ok(row.estimated_rows === null ||
                      Number(row.estimated_rows) >= 0,
              row.relname + " estimated_rows=" + row.estimated_rows);
          });
        });
  check("the columns and the constraints are there too, which is the " +
        "'stats about the schema' half", function () {
          assert.ok(probes.columns.ok && probes.columns.rows.length >= 20);
          assert.ok(probes.constraints.ok &&
                    probes.constraints.rows.length >= 5);
        });

  // **THE ONE ASSERTION ON THIS PAGE THAT IS NOT A MEASUREMENT.**
  // `tests/postgres_schema.js` compares the driver's declared objects against
  // `postgres/schema.sql` character for character, and neither of those is
  // ever compared against a RUNNING SERVER — so a database built by an older
  // copy of that file satisfies both and is missing a table.
  check("and the schema DRIFT check reports no missing object, which is a " +
        "claim nothing else in this service makes: the driver's declared " +
        "objects against what the server actually has", function () {
          const drift = view.body.schemaDrift;
          assert.ok(drift && Array.isArray(drift.missing), JSON.stringify(drift));
          assert.deepStrictEqual(drift.missing, [],
            "the database is missing objects the driver declares: " +
            drift.missing.join(", "));
          assert.ok(drift.declared.length >= 5);
        });

  log.info("=== F. the four derived ratios ===");

  check("the report carries the ratios PostgreSQL deliberately does not " +
        "keep — it stores counters, because a counter can be subtracted " +
        "between two readings and a ratio cannot", function () {
          const d = view.body.derived;
          assert.ok(d, "no derived block");
          assert.ok(d.cacheHitPercent === null ||
                    (d.cacheHitPercent >= 0 && d.cacheHitPercent <= 100),
            "cacheHitPercent=" + d.cacheHitPercent);
          assert.ok(d.rollbackPercent === null ||
                    (d.rollbackPercent >= 0 && d.rollbackPercent <= 100),
            "rollbackPercent=" + d.rollbackPercent);
          assert.ok(Array.isArray(d.unusedIndexes));
        });
  check("and an index this service's own schema declares as a PRIMARY KEY is " +
        "never called unused — a primary key with no scans is an ordinary " +
        "state and flagging it would make the one actionable number on the " +
        "page noise", function () {
          const primaries = (probes.indexes.rows || [])
            .filter(function (one) { return one.is_primary; })
            .map(function (one) {
              return one.table_name + "." + one.index_name;
            });
          view.body.derived.unusedIndexes.forEach(function (name) {
            assert.ok(primaries.indexOf(name) < 0,
              name + " is a primary key and is listed as unused");
          });
        });

  log.info("=== G. the page itself ===");

  const page = await fetch(base + "/admin/database", { redirect: "manual" });
  check("/admin/database is BEHIND THE GATE, like every other page of that " +
        "console — the metrics are an operator's business and the reply " +
        "names hosts, ports and a user", function () {
          assert.ok(page.status === 303 || page.status === 302,
            "status " + page.status);
        });

  log.info(checks + " check(s) passed.");
}

const program = new Command();
program
  .name("sts_database_metrics")
  .description("Drive /admin/database and /admin-api/database against a real " +
      "PostgreSQL: that every probe ran, that the columns arriving are the " +
      "SERVER's rather than any this test names, that a probe the service's " +
      "least-privilege role cannot read costs a ROW and not the page and " +
      "carries PostgreSQL's SQLSTATE, that the schema drift check finds " +
      "nothing missing, that a never-analysed table does not report minus " +
      "one row, and that no connection string or password is in the reply. " +
      "SKIPPED with the reason when persistence.mode is not postgres, which " +
      "a job cannot switch on for itself because it is restart-only.")
  // Accepted and ignored: run-report.js passes --url to every job.
  .addOption(new Option("-u, --url <url>",
      "base url (unused: this test needs no browser)"))
  .parse(process.argv);

test().catch(function (e) {
  log.error(e.stack || e.message);
  process.exit(1);
});
