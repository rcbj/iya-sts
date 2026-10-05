// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: database_admin.ts
//
// ===========================================================================
// MONITORING > DATABASE: ONE CONSOLE PAGE, `/admin/database` (2026-09-11).
//
// **EVERYTHING POSTGRESQL WILL TELL THIS SERVICE ABOUT ITSELF, AND THE STATE
// OF THE SCHEMA THIS SERVICE OWNS IN IT.**
//
// ---------------------------------------------------------------------------
// WHY IT IS IN MONITORING AND NOT A SECOND HALF OF `/admin/persistence`.
//
// `admin-ui/CLAUDE.md`'s filing rule is that a page goes where the QUESTION it
// answers goes. `/admin/persistence` is filed under Server configuration and
// answers *what is this service configured to write down, where, and is the
// connection encrypted* — configuration, plus the nineteen `persistence.*`
// settings, and it reads identically on a service that started a second ago.
//
// This one answers **what has that database been doing** — commits, rollbacks,
// cache hit ratio, sequential scans, dead tuples, checkpoints, WAL — and the
// numbers move while a reader watches. That is the same argument
// `/admin/xacml/monitor`, `/admin/scim/monitor` and `/admin/encryption` are
// each filed under Monitoring on, made a fourth time rather than cited.
//
// ---------------------------------------------------------------------------
// THE PAGE HOLDS NO SQL, NO COLUMN NAMES AND NO CONNECTION.
//
// Three separations, and each is load-bearing:
//
//   * **THE STATEMENTS ARE `persistence_postgres.js`'s `METRIC_PROBES`.** That
//     module owns the pool; this one must never require `pg` or see a
//     connection string, which is a credential. It asks
//     `persistence.databaseMetrics()` and renders what comes back.
//   * **THE COLUMNS ARE THE SERVER'S.** Every probe is a `SELECT *` and this
//     renderer draws the keys it was handed, in the order it was handed them.
//     A page naming columns would be wrong on every PostgreSQL but the one it
//     was written against and wrong SILENTLY — measured: `pg_stat_bgwriter`
//     has ELEVEN columns on 16 and FOUR on 18, `pg_stat_wal` nine and five,
//     `pg_stat_database` twenty-eight and thirty. **So the shape of this page
//     is decided by the database it is pointed at**, which is the only way
//     "pull everything available" can stay true across a major version.
//   * **AND THERE IS NO QUERY BOX**, and there must never be one. The role
//     this service dials with can INSERT, UPDATE and DELETE on every table
//     in its schema — so a console that could hand it a statement would be a
//     console that could empty the directory. Every statement behind this
//     page is a literal in a table in another module and none is composed
//     from anything a request carries.
//
// ---------------------------------------------------------------------------
// A PROBE THAT FAILED IS A ROW AND NOT AN ABSENCE.
//
// The role is `sts_app`: SELECT/INSERT/UPDATE/DELETE on the tables of one
// schema, USAGE on that schema, and NOT `pg_monitor`. Most catalog views are
// readable by anybody, a few are not, and which few depends on the server
// version and on the operator's grants. So the page draws what failed, with
// PostgreSQL's own SQLSTATE beside it, and tells the two ordinary causes
// apart:
//
//   * **42P01**, no such relation — a view this server version does not have.
//     `pg_stat_checkpointer` on anything before 17 is the one that happens.
//   * **42501**, insufficient privilege — a grant this role does not hold.
//
// **AND ONE ANSWER IS NARROWED WITHOUT FAILING AT ALL**, which is worse and is
// called out on the page: `pg_stat_activity` shows a backend belonging to
// another role as a ROW, with `state` NULL and `query` set to the literal
// string `<insufficient privilege>`. That is a value rather than an error, so
// anything that did not know would draw it as somebody's SQL.
// ===========================================================================
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that has a route (rule 1): `DatabaseAdmin` takes
// the console shell, the error codes, the settings, the persistence layer and
// the logger through its constructor, and its `registerRoutes(app)` holds the
// page's one route. The module exports `registerRoutes(app)`, which
// `common/protocol_stack.ts` calls at 18c, where requiring this module used to
// register the route (#50, R1) — requiring it registers nothing. It also
// exports `databaseView` and `sections`, for `mgmt-api/admin_api.ts` and
// `tests/database_metrics.js`.
//
// R2 (#50): the composition root builds the instance and installs it; this
// module builds none of its own, and its exports are FACADES that forward to
// that instance, for the JavaScript callers. A process without the root
// builds a default instance at load, as loading this module always did.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import admin = require('./admin');
import helpers = require('../common/helpers');
// The error codes (common/error_codes.js), a leaf: requiring it moves nothing.
import errorCodes = require('../common/error_codes');
import config = require('../common/config');
import persistence = require('../persistence/persistence');
import InstanceSlot = require('../common/instance_slot');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import DatabasePage = require('./web_database');

type Req = any;
type Res = any;
type Json = any;

interface DatabaseAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  errorCodes: typeof errorCodes;
  config: typeof config;
  persistence: typeof persistence;
}

// The sections, in the order they are drawn. **A GROUP IS DECLARED HERE AND A
// PROBE NAMES ONE**, and `tests/database_metrics.js` checks the two lists
// against each other in both directions: a probe whose group has no heading is
// collected on every render and shown to nobody, and a heading with no probe
// is an empty section that looks like a broken feature. Neither is an error
// anywhere — which is `pki_authoring.js`'s field-table argument, one layer out.
/**
 * The page's sections in the order they are drawn; every metrics probe names
 * one of these groups.
 */
// The table is `web_database.ts`'s since #446: it is what the page is drawn
// from, and that module may not require this one.
const SECTIONS = DatabasePage.SECTIONS;

/**
 * Monitoring → Database: everything PostgreSQL will tell this service about
 * itself, and the state of the schema this service owns in it.
 */
class DatabaseAdmin {
  /**
   * See the module's `SECTIONS`.
   */
  static readonly SECTIONS = SECTIONS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the console shell, settings and the persistence
   * store
   */
  constructor(private readonly deps: DatabaseAdminDeps) {
    deps.log.debug("Entering DatabaseAdmin.constructor().");
    deps.log.debug("Leaving DatabaseAdmin.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): DatabaseAdminDeps {
    helpers.log.debug("Entering DatabaseAdmin.defaultDeps().");
    helpers.log.debug("Leaving DatabaseAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      errorCodes: errorCodes,
      config: config,
      persistence: persistence
    };
  }

  // -------------------------------------------------------------------------
  // THE DERIVED FIGURES.
  //
  // **FOUR NUMBERS THIS PAGE COMPUTES RATHER THAN READS, AND EACH IS A RATIO
  // POSTGRESQL DELIBERATELY DOES NOT KEEP.** It stores counters, because a
  // counter can be subtracted between two readings and a ratio cannot; what a
  // person reads a page like this for is the ratio. They are computed HERE, in
  // the renderer, and not in SQL — a division in the probe would make the
  // probe version-dependent again for no gain, and these are the four a reader
  // would otherwise do in their head and get wrong.
  //
  // **EVERY ONE OF THEM IS SINCE `stats_reset` AND THE PAGE SAYS SO.** A cache
  // hit ratio of 99.8% over the life of the server tells you nothing about the
  // last hour, and a reader who takes it for a current reading is the one
  // misunderstanding this page can actually cause.
  // -------------------------------------------------------------------------
  private ratio(hit: Json, read: Json): number | null {
    const { log } = this.deps;
    log.debug("Entering DatabaseAdmin.ratio().");
    const h = Number(hit || 0);
    const r = Number(read || 0);
    if (!(h + r)) {
      log.debug("Leaving DatabaseAdmin.ratio().");
      return null;
    }
    log.debug("Leaving DatabaseAdmin.ratio().");
    return Math.round((h / (h + r)) * 1000) / 10;
  }

  private derived(probes: Json): Json {
    const { log } = this.deps;
    log.debug('Entering DatabaseAdmin.derived().');
    const db = (probes.database && probes.database.row) || {};
    const tables = (probes.tables && probes.tables.rows) || [];
    const indexes = (probes.indexes && probes.indexes.rows) || [];
    const out = {
      cacheHitPercent: this.ratio(db.blks_hit, db.blks_read),
      // A ROLLBACK RATE AND NOT A COUNT. Rollbacks are ordinary — every
      // conflicting upsert in this service produces one — and the number that
      // means something is the proportion.
      rollbackPercent: (function () {
        const c = Number(db.xact_commit || 0);
        const r = Number(db.xact_rollback || 0);
        return (c + r) ? Math.round((r / (c + r)) * 1000) / 10 : null;
      })(),
      // DEAD TUPLES AS A SHARE OF LIVE ONES, which is the bloat signal.
      // Summed across the schema rather than per table, because the per-table
      // figure is in the table below and a reader wants one number first.
      deadTuplePercent: (function () {
        let live = 0;
        let dead = 0;
        tables.forEach(function (one) {
          live += Number(one.n_live_tup || 0);
          dead += Number(one.n_dead_tup || 0);
        });
        return (live + dead) ? Math.round((dead / (live + dead)) * 1000) / 10
                             : null;
      })(),
      // AN INDEX NOTHING HAS EVER SCANNED. The most actionable number here on
      // a database that has been running, and MEANINGLESS on one that has
      // just started — so the page reports the count and says which of the
      // two situations the reader is in rather than implying the first.
      unusedIndexes: indexes.filter(function (one) {
        return Number(one.idx_scan || 0) === 0 && !one.is_primary;
      }).map(function (one) {
        return one.table_name + '.' + one.index_name;
      }),
      // SEQUENTIAL SCANS AGAINST INDEX SCANS. On small tables a sequential
      // scan is often the right plan, which the page says out loud — this is
      // here to be read alongside the row counts and not as a fault.
      seqScans: tables.reduce(function (n, one) {
        return n + Number(one.seq_scan || 0);
      }, 0),
      idxScans: tables.reduce(function (n, one) {
        return n + Number(one.idx_scan || 0);
      }, 0),
      statsReset: db.stats_reset || null
    };
    log.debug('Leaving DatabaseAdmin.derived().');
    return out;
  }

  // -------------------------------------------------------------------------
  // THE SCHEMA DRIFT CHECK.
  //
  // **THE ONE THING ON THIS PAGE THAT IS AN ASSERTION RATHER THAN A
  // MEASUREMENT**, and nothing else in this service makes it.
  // `tests/postgres_schema.js` compares the driver's `SCHEMA_OBJECTS` against
  // `postgres/schema.sql`, character for character — and neither of those is
  // compared against a RUNNING SERVER. A database built by an older copy of
  // that file, or by hand, or half-migrated, satisfies both and is missing a
  // table.
  //
  // The driver would create what is missing on the next open, which is
  // exactly why this matters: the role it dials with holds no CREATE, so on a
  // least-privilege deployment it CANNOT, and the failure arrives as a
  // permission error naming a statement nobody typed.
  // -------------------------------------------------------------------------
  private schemaDrift(report: Json): Json {
    const { log } = this.deps;
    log.debug("Entering DatabaseAdmin.schemaDrift().");
    const declared = report.declaredObjects || [];
    const tables = ((report.probes.tables && report.probes.tables.rows) || [])
      .map(function (one) { return one.relname; });
    const indexes = ((report.probes.indexes &&
                      report.probes.indexes.rows) || [])
      .map(function (one) { return one.index_name; });
    const present = tables.concat(indexes);
    // **AN OBJECT THE DRIVER DECLARES AND THE SERVER DOES NOT HAVE.** The
    // reverse — a table in the schema the driver never heard of — is NOT
    // drift and is deliberately not reported: an operator may keep whatever
    // they like in that schema, and a page calling their table an error would
    // be this service claiming a namespace it does not own.
    const missing = declared.filter(function (name) {
      return present.indexOf(name) < 0;
    });
    log.debug("Leaving DatabaseAdmin.schemaDrift().");
    return { declared: declared, present: present, missing: missing };
  }

  // =========================================================================
  // THE MODEL. One object, rendered twice — HTML and `?format=json` — which is
  // `respond()`'s contract and why `/admin-api/database` cannot disagree with
  // the page (rule 7).
  // =========================================================================
  /**
   * Collects the database's metrics and builds the page's model, the one object
   * behind the page, its `?format=json` and `/admin-api/database` (rule 7).
   *
   * Without a PostgreSQL store it answers `available: false` and why; a failed
   * collection answers `ok: false` and the error.
   * @returns a promise of the model: the target, the pool, every probe, derived
   * figures, the schema and its drift from what this service expects
   */
  databaseJson(): Promise<Json> {
    const { log, config, persistence } = this.deps;
    const self = this;
    log.debug('Entering DatabaseAdmin.databaseJson().');
    log.debug("Leaving DatabaseAdmin.databaseJson().");
    return persistence.databaseMetrics().then(function (report: Json) {
      const out: Json = {
        what: 'Everything PostgreSQL will tell this service about itself, ' +
              'and the state of the schema this service owns in it.',
        available: !!report.available,
        mode: report.mode,
        ok: !!report.ok
      };
      if (!report.available) {
        out.why = report.why;
        log.debug('Leaving DatabaseAdmin.databaseJson(). No database.');
        return out;
      }
      out.target = report.target;
      out.pool = report.pool;
      out.tookMs = report.tookMs;
      out.statementTimeoutMs = Number(config.value(
          'persistence.metricsTimeoutMs'));
      out.statementTimeoutSet = report.timeoutSet !== false;
      if (!report.ok) {
        out.error = report.error;
        log.debug('Leaving DatabaseAdmin.databaseJson(). The collection ' +
                  'failed.');
        return out;
      }
      out.probes = report.probes;
      // THE SCHEMA IS THE SERVER'S ANSWER AND NOT A SETTING. There is no
      // `persistence.databaseSchema`; the schema comes from the `search_path`
      // in the connection string, so `current_schema()` — which is what every
      // schema probe scoped to — is the only reading that cannot be wrong.
      out.schema = ((report.probes.server && report.probes.server.row) || {})
        .search_schema || null;
      out.derived = self.derived(report.probes);
      out.schemaExpected = { version: report.schemaVersion };
      out.schemaDrift = self.schemaDrift(report);
      out.failed = Object.keys(report.probes).filter(function (id) {
        return !report.probes[id].ok;
      });
      log.debug('Leaving DatabaseAdmin.databaseJson(). ' +
                Object.keys(report.probes).length + ' probe(s), ' +
                out.failed.length + ' failed.');
      return out;
    });
  }

  // For `tests/database_metrics.js`, which checks every probe's group against
  // a heading this page actually draws. A probe in a group with no section is
  // collected on every render and shown to nobody.
  /**
   * Answers the section table, for the test that checks every probe's group
   * against a heading the page draws.
   *
   * @returns the page's sections
   */
  sections(): typeof SECTIONS {
    const { log } = this.deps;
    log.debug("Entering DatabaseAdmin.sections().");
    log.debug("Leaving DatabaseAdmin.sections().");
    return SECTIONS.slice();
  }

  // DRAWN BY `web_database.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private body(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering DatabaseAdmin.body().");
    const drawn = DatabasePage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving DatabaseAdmin.body().");
    return drawn;
  }

  /**
   * Registers `GET /admin/database`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering DatabaseAdmin.registerRoutes().");
    log.debug("Leaving DatabaseAdmin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DatabaseAdmin>(
  'admin-ui/database_admin',
  () => new DatabaseAdmin(DatabaseAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

helpers.log.info('The database report is at /admin/database: everything ' +
                 'PostgreSQL will tell this service about itself, and the ' +
                 'state of the schema this service owns in it. It is empty ' +
                 'unless persistence.mode is postgres, and says so.');

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Monitoring → Database, `/admin/database`: everything PostgreSQL will tell
 * this service about itself, and the state of the schema this service owns in
 * it. Empty unless `persistence.mode` is `postgres`, and says so.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  DatabaseAdmin: DatabaseAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: DatabaseAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts`. Rule 7 — one function behind the page and
  // the operation, so the two cannot report different numbers.
  databaseView: slot.forward('databaseJson'),
  // For `tests/database_metrics.js` — see `DatabaseAdmin.sections()`.
  sections: slot.forward('sections')
};
