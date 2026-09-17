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
const SECTIONS = [
  { group: 'Server',
    heading: 'The server',
    blurb: 'Which PostgreSQL this is, who this service connects as, and how ' +
           'big the database has become.' },
  { group: 'Activity',
    heading: 'What it has done, and who is connected',
    blurb: 'Every counter PostgreSQL keeps for this database, the backends ' +
           'on it, and the locks they hold.' },
  { group: 'Background',
    heading: 'The background machinery',
    blurb: 'The writer, the checkpointer, the write-ahead log and the ' +
           'archiver. Three of these four views moved or arrived between ' +
           'major versions, which is why this page asks each of them for ' +
           'every column rather than naming any.' },
  { group: 'Schema',
    heading: 'The schema this service owns',
    blurb: 'Per-table and per-index statistics, sizes, columns and ' +
           'constraints — scoped to <code>current_schema()</code>, so an ' +
           'operator who moved the schema in their connection string gets ' +
           'their own tables rather than somebody else\'s.' },
  { group: 'Configuration',
    heading: 'How the server is configured',
    blurb: 'Every setting an operator changed from its built-in default — ' +
           'PostgreSQL\'s own answer to "what did somebody set" — plus a ' +
           'named handful that matter whether or not anybody touched them.' }
];

class DatabaseAdmin {
  static readonly SECTIONS = SECTIONS;

  constructor(private readonly deps: DatabaseAdminDeps) {
    deps.log.debug("Entering DatabaseAdmin.constructor().");
    deps.log.debug("Leaving DatabaseAdmin.constructor().");
  }

  // What the composition root passes: the real modules, as the load-time
  // instance was built from before R2 (#50).
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
  // RENDERING A VALUE THIS PAGE HAS NEVER HEARD OF.
  //
  // Every cell here came out of a `SELECT *`, so this function is the only
  // thing that decides how an arbitrary postgres value is drawn — and the
  // cases below are each a real shape that arrives, rather than defensive
  // programming:
  //
  //   * **`null` is not `0` and not an empty string**, and on this page the
  //     difference is usually the whole point: a null `idx_scan` means the
  //     column is not collected, a zero means an index nothing has ever used.
  //   * **A `bigint` arrives as a STRING** from `pg`, deliberately — it does
  //     not fit in a double — so it must not be run through a numeric
  //     formatter that would quietly round it.
  //   * **A timestamp arrives as a `Date`** and is rendered to the second: the
  //     microseconds PostgreSQL keeps are noise on a page somebody is reading.
  //   * **`<insufficient privilege>` is postgres's own string** for a column
  //     this role may not read. It is drawn as the refusal it is rather than
  //     as a value, because it is the one string on this page that would
  //     otherwise be mistaken for somebody's query.
  // -------------------------------------------------------------------------
  private cell(value: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DatabaseAdmin.cell().");
    if (value === null || value === undefined) {
      log.debug("Leaving DatabaseAdmin.cell().");
      return '<span class="muted">—</span>';
    }
    if (value === '<insufficient privilege>') {
      log.debug("Leaving DatabaseAdmin.cell().");
      return '<span class="muted">withheld</span>';
    }
    if (value instanceof Date) {
      log.debug("Leaving DatabaseAdmin.cell().");
      return admin.esc(value.toISOString()
                            .replace('T', ' ')
                            .replace(/\..*$/, 'Z'));
    }
    if (typeof value === 'boolean') {
      log.debug("Leaving DatabaseAdmin.cell().");
      return value ? '<span class="ok">yes</span>'
                   : '<span class="muted">no</span>';
    }
    if (typeof value === 'object') {
      log.debug("Leaving DatabaseAdmin.cell().");
      return '<code>' + admin.esc(JSON.stringify(value)) + '</code>';
    }
    const text = String(value);
    // A definition or a version banner runs to hundreds of characters and
    // would stretch the table past the width of the page; `clipped()` is the
    // console's own control for that and opens out on a click, so nothing is
    // lost.
    if (text.length > 90) {
      log.debug("Leaving DatabaseAdmin.cell().");
      return admin.clipped(text, 90);
    }
    log.debug("Leaving DatabaseAdmin.cell().");
    return admin.esc(text);
  }

  // A column name as a person reads it. `n_tup_hot_upd` is PostgreSQL's name
  // and is what somebody searching its documentation will type, so it is KEPT
  // and shown as itself — this only replaces the underscores for the eye. The
  // raw name goes in a `title`, so the page never costs a reader the string
  // they would need to look it up.
  private columnLabel(name: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DatabaseAdmin.columnLabel().");
    log.debug("Leaving DatabaseAdmin.columnLabel().");
    return '<span title="' + admin.esc(name) + '">' +
           admin.esc(String(name).replace(/_/g, ' ')) + '</span>';
  }

  private probeFailure(id: string, probe: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DatabaseAdmin.probeFailure().");
    const why = probe.code === '42P01'
      ? 'This server version does not have that view.' +
        (probe.expected
          ? ' It arrived in PostgreSQL ' + probe.expected + ', so this is ' +
            'the ordinary answer on anything older and not a fault.'
          : '')
      : (probe.code === '42501'
          ? 'This service\'s database role may not read it. Granting ' +
            '<code>pg_monitor</code> to that role is what fills it in; this ' +
            'service does not ask for it.'
          : '');
    log.debug("Leaving DatabaseAdmin.probeFailure().");
    return '<tr><td><code>' + admin.esc(id) + '</code></td>' +
           '<td>' + admin.esc(probe.what) + '</td>' +
           '<td><code>' + admin.esc(probe.code || '—') + '</code></td>' +
           '<td>' + admin.esc(probe.error) +
           (why ? '<br><span class="muted">' + why + '</span>' : '') +
           '</td></tr>';
  }

  // A single-row probe, drawn as label/value pairs. A wide row — thirty
  // columns for `pg_stat_database` — is unreadable as a table with thirty
  // headings and one line under them, which is what the first version of this
  // did.
  private rowTable(probe: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering DatabaseAdmin.rowTable().");
    if (!probe.row) {
      log.debug("Leaving DatabaseAdmin.rowTable().");
      return admin.note('That view answered no row at all, which for a ' +
                        'probe scoped to this database means the server ' +
                        'keeps no statistics for it yet.');
    }
    const keys = Object.keys(probe.row);
    log.debug("Leaving DatabaseAdmin.rowTable().");
    return '<table class="grid"><tbody>' +
      keys.map(function (key) {
        return '<tr><th>' + self.columnLabel(key) + '</th><td>' +
               self.cell(probe.row[key]) + '</td></tr>';
      }).join('') +
      '</tbody></table>';
  }

  // A many-row probe, drawn as a table whose HEADINGS ARE THE KEYS OF THE
  // FIRST ROW. That is the whole reason this page survives a major version
  // change, and it is why an empty result has to be handled here rather than
  // falling out of the loop: with no row there are no keys, and a table with
  // no headings is not an empty table, it is a rendering bug.
  private rowsTable(probe: Json): string {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering DatabaseAdmin.rowsTable().");
    if (!probe.rows || !probe.rows.length) {
      log.debug("Leaving DatabaseAdmin.rowsTable().");
      return '<p class="muted">No rows.</p>';
    }
    const keys = Object.keys(probe.rows[0]);
    log.debug("Leaving DatabaseAdmin.rowsTable().");
    // `.wide` is the console's OWN overflow wrapper (`overflow-x:auto`),
    // reused rather than a class of this page's invention: a thirty-column
    // `pg_stat_user_tables` is wider than any screen, and a second answer to
    // "how does a table scroll here" is how one page comes to behave
    // differently from the rest.
    return '<div class="wide"><table class="grid"><thead><tr>' +
      keys.map(function (key) {
        return '<th>' + self.columnLabel(key) + '</th>';
      }).join('') +
      '</tr></thead><tbody>' +
      probe.rows.map(function (row) {
        return '<tr>' + keys.map(function (key) {
          return '<td>' + self.cell(row[key]) + '</td>';
        }).join('') + '</tr>';
      }).join('') +
      '</tbody></table></div>';
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
  sections(): typeof SECTIONS {
    const { log } = this.deps;
    log.debug("Entering DatabaseAdmin.sections().");
    log.debug("Leaving DatabaseAdmin.sections().");
    return SECTIONS.slice();
  }

  // =========================================================================
  // THE PAGE.
  // =========================================================================
  private renderDatabase(req: Req, res: Res): void {
    const { log, admin, errorCodes } = this.deps;
    const self = this;
    log.debug('Entering DatabaseAdmin.renderDatabase().');
    self.databaseJson().then(function (json) {
      admin.respond(req, res, json, 'Database', '/admin/database',
                    self.body(json));
      log.debug('Leaving DatabaseAdmin.renderDatabase().');
    }).catch(function (e) {
      log.error(errorCodes.tag('STS-ADMIN-0598') + 'database_admin: the ' +
                                                   'page threw: ' +
                (e && e.stack ? e.stack : e));
      errorCodes.mark(res, 'STS-ADMIN-0598');
      admin.respond(req, res,
                    { ok: false, error: String(e && e.message || e) },
                    'Database', '/admin/database',
                    admin.warn('This page could not be drawn: ' +
                               admin.esc(String(e && e.message || e)),
                               'It threw'));
    });
    log.debug("Leaving DatabaseAdmin.renderDatabase().");
  }

  private body(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug('Entering DatabaseAdmin.body().');

    // NO DATABASE AT ALL. The commonest state by a wide margin — `memory` is
    // the default — so it is a paragraph that says which of the three "no"
    // answers this is, rather than an empty page with tables on it.
    if (!json.available) {
      log.debug('Leaving DatabaseAdmin.body(). Not available.');
      return admin.note(
        '<p>' + admin.esc(json.why) + '</p>' +
        '<p>What this page would show: everything PostgreSQL keeps about ' +
        'itself — commits and rollbacks, the cache hit ratio, every backend ' +
        'and lock, the checkpointer and the write-ahead log — beside ' +
        'per-table ' +
        'and per-index statistics for the schema this service owns, its ' +
        'sizes, ' +
        'its columns and its constraints. <a href="/admin/persistence">The ' +
        'persistence page</a> is where the mode is configured and is what ' +
        'this ' +
        'page reports the consequences of.</p>',
        'There is no database to report on');
    }

    const target = json.target || {};
    const tiles = '<div class="tiles">' +
      admin.tile(json.ok ? 'up' : 'down', 'database') +
      admin.tile(String((json.probes && json.probes.size &&
                         json.probes.size.row &&
                         json.probes.size.row.pretty) || '—'), 'on disk') +
      admin.tile(json.derived && json.derived.cacheHitPercent !== null
        ? json.derived.cacheHitPercent + '%' : '—', 'cache hit') +
      admin.tile(String((json.pool && json.pool.total) || 0) + '/' +
                 String((json.pool && json.pool.max) || 0), 'pool') +
      admin.tile(String(json.tookMs) + 'ms', 'collected in') +
      admin.tile(String((json.failed || []).length), 'probes unavailable') +
      '</div>';

    const what = admin.note(
      '<p>This page is <strong>what the database has been DOING</strong>. ' +
      '<a ' +
      'href="/admin/persistence">Persistence</a>, under Settings, is what ' +
      'this ' +
      'service is CONFIGURED to write down and where &mdash; that page reads ' +
      'the same on a service that started a second ago, and the numbers ' +
      'here ' +
      'move while you watch.</p><p><strong>The shape of this page is ' +
      'decided ' +
      'by the database it is pointed at.</strong> Every statement behind it ' +
      'is ' +
      'a <code>SELECT *</code>, and the columns drawn are the ones this ' +
      'server ' +
      'returned, in its order. That is not laziness: PostgreSQL moves these ' +
      'views between major versions &mdash; <code>pg_stat_bgwriter</code> ' +
      'has ' +
      'eleven columns on 16 and four on 18, because the checkpoint counters ' +
      'moved to a view that does not exist before 17 &mdash; so a page ' +
      'naming ' +
      'its columns would be wrong on every server but one, and wrong in the ' +
      'way that reads as a blank cell.</p><p><strong>There is no query box ' +
      'here and there must never be one.</strong> The role this service ' +
      'dials ' +
      'with can INSERT, UPDATE and DELETE on six tables, so a console that ' +
      'could hand it a statement would be a console that could empty the ' +
      'directory. Every statement is a literal in ' +
      '<code>persistence/persistence_postgres.js</code> and none is built ' +
      'from ' +
      'anything a request carries. They are all catalog reads, bounded by ' +
      'PostgreSQL\'s own <code>statement_timeout</code> at ' +
      admin.esc(String(json.statementTimeoutMs)) + 'ms' +
      (json.statementTimeoutSet ? '' :
        ' &mdash; <strong>which this server would not accept, so that bound ' +
        'is ' +
        'NOT in force</strong>') +
      ', on the single connection this page borrows.</p>',
      'What this page is, and the three things it will not do');

    const connection = admin.note(
      '<p>Connected to <code>' + admin.esc(String(target.host || '?')) + ':' +
      admin.esc(String(target.port || '?')) + '/' +
      admin.esc(String(target.database || '?')) + '</code> as <code>' +
      admin.esc(String(target.user || '?')) + '</code>, schema <code>' +
      admin.esc(String(json.schema || '?')) + '</code>. ' +
      admin.esc(String(target.tls || '')) + '</p>' +
      '<p><strong>The pool figures are this PROCESS\'s and the backend ' +
      'counts ' +
      'are the SERVER\'s</strong>, and they answer different questions: ' +
      'PostgreSQL can say how many connections exist, and only the client ' +
      'can ' +
      'say how many of them this service is holding and how many callers are ' +
      'queued for one. The pool is sampled BEFORE this page borrows a ' +
      'connection, so the numbers are what it was doing when you asked ' +
      'rather ' +
      'than what it is doing because you asked &mdash; on a pool whose ' +
      'maximum ' +
      'is four, counting our own would invent a quarter of it.</p>',
      'Which end each number comes from');

    // THE NARROWED ANSWER, said once and prominently rather than as a
    // footnote under a table somebody has already misread.
    const narrowed = admin.warn(
      '<p>This service connects as an ordinary application role &mdash; ' +
      'SELECT, INSERT, UPDATE and DELETE on six tables, USAGE on one schema, ' +
      'and <strong>not <code>pg_monitor</code></strong>. Most of what is ' +
      'below ' +
      'is readable by anybody; two things are not, and they fail ' +
      'differently:</p><ul><li>a view this role may not read ' +
      '<strong>fails</strong>, and is drawn as a row in <em>What could not ' +
      'be ' +
      'collected</em> with PostgreSQL\'s SQLSTATE beside it;</li><li>a ' +
      '<strong>backend belonging to another role does not fail</strong> ' +
      '&mdash; it appears as a row with its state empty and its query given ' +
      'as ' +
      'the literal string <code>&lt;insufficient privilege&gt;</code>, which ' +
      'is a value and not an error. This page draws that as ' +
      '<em>withheld</em>. ' +
      'The same is true of <code>pg_stat_replication</code>: an empty table ' +
      'there means either that there are no standbys or that this role may ' +
      'not ' +
      'see them, and nothing in this service can tell those ' +
      'apart.</li></ul><p>Granting <code>pg_monitor</code> to the ' +
      'application ' +
      'role fills all of it in. This service does not ask for it, because ' +
      'the ' +
      'whole point of <code>postgres/schema.sql</code> is that the role it ' +
      'dials with holds the least it can.</p>',
      'What this role is NOT allowed to see, and how each kind of refusal ' +
      'looks');

    if (!json.ok) {
      log.debug('Leaving DatabaseAdmin.body(). The collection failed.');
      return tiles + what + admin.warn(
        '<p>No statistics could be collected at all: <code>' +
        admin.esc(String(json.error)) + '</code></p>' +
        '<p>That is ONE fact rather than twenty &mdash; it means no ' +
        'connection ' +
        'was obtained, so every probe would have failed for the same reason ' +
        'and listing them separately would say the same thing twenty times. ' +
        'The service itself may still be answering: it holds the directory ' +
        'in ' +
        'memory and writes THROUGH this store, so a database that has gone ' +
        'away is a service that cannot persist rather than one that cannot ' +
        'reply.</p>',
        'The database could not be reached') + connection;
    }

    log.debug("Leaving DatabaseAdmin.body().");
    return tiles + what + connection + narrowed +
           self.derivedBlock(json) +
           self.driftBlock(json) +
           SECTIONS.map(function (section) {
             return self.sectionBlock(section, json);
           }).join('') +
           self.failureBlock(json);
  }

  private derivedBlock(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DatabaseAdmin.derivedBlock().");
    const d = json.derived;
    const unused = d.unusedIndexes.length
      ? '<p><strong>' + d.unusedIndexes.length + ' index(es) have never ' +
        'been ' +
        'scanned:</strong> ' + d.unusedIndexes.map(function (one) {
          return '<code>' + admin.esc(one) + '</code>';
        }).join(', ') + '. On a database that has been serving traffic that ' +
        'is ' +
        'the most actionable number on this page &mdash; an index nothing ' +
        'reads is write cost and disk for nothing. On one that has just ' +
        'started it means only that nothing has queried yet, and the ' +
        'counters ' +
        'below say which situation this is.</p>'
      : '<p>Every index here has been scanned at least once.</p>';
    log.debug("Leaving DatabaseAdmin.derivedBlock().");
    return '<h3>The four ratios</h3>' + admin.note(
      '<table class="grid"><tbody>' +
      '<tr><th>Cache hit</th><td>' +
        (d.cacheHitPercent === null ? '<span class="muted">nothing read ' +
                                      'yet</span>'
          : admin.esc(String(d.cacheHitPercent)) + '%') +
        '</td><td class="why">Blocks found in the buffer cache against ' +
        'blocks ' +
        'read from disk. PostgreSQL keeps the two counters and not the ' +
        'ratio, ' +
        'because a counter can be subtracted between two readings and a ' +
        'ratio ' +
        'cannot.</td></tr>' +
      '<tr><th>Rollbacks</th><td>' +
        (d.rollbackPercent === null ? '<span class="muted">no transactions ' +
                                      'yet</span>'
          : admin.esc(String(d.rollbackPercent)) + '%') +
        '</td><td class="why">A share and not a count: rollbacks are ' +
        'ordinary ' +
        'here &mdash; a conflicting upsert produces one &mdash; and only the ' +
        'proportion means anything.</td></tr>' +
      '<tr><th>Dead tuples</th><td>' +
        (d.deadTuplePercent === null
          ? '<span class="muted">no rows yet</span>'
          : admin.esc(String(d.deadTuplePercent)) + '%') +
        '</td><td class="why">Dead rows as a share of all rows, summed ' +
        'across ' +
        'the schema. This is the bloat signal; autovacuum is what brings it ' +
        'down, and the per-table vacuum times are in the schema ' +
        'section.</td></tr><tr><th>Scans</th><td>' +
      admin.esc(String(d.seqScans)) + ' ' +
            'sequential, ' +
        admin.esc(String(d.idxScans)) + ' index</td>' +
        '<td class="why">On six small tables a sequential scan is ' +
        'frequently ' +
        'the right plan and this is <em>not</em> a fault to chase &mdash; ' +
        'read ' +
        'it beside the row counts below.</td></tr>' +
      '</tbody></table>' + unused +
      '<p class="muted"><strong>Every figure on this page is cumulative ' +
      'since ' +
      (d.statsReset
        ? admin.esc(String(new Date(d.statsReset).toISOString()
            .replace('T', ' ').replace(/\..*$/, 'Z')))
        : 'the statistics were last reset') +
      '</strong>, which is what PostgreSQL counts from. A cache hit ratio ' +
      'over ' +
      'the life of a server says nothing about the last hour, and reading it ' +
      'as a current figure is the one misunderstanding this page can ' +
      'actually ' +
      'cause.</p>',
      'Four numbers this page computes, and what each is not');
  }

  private driftBlock(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering DatabaseAdmin.driftBlock().");
    const drift = json.schemaDrift;
    if (!drift.declared.length) {
      log.debug("Leaving DatabaseAdmin.driftBlock().");
      return '';
    }
    const body = drift.missing.length
      ? admin.warn(
          '<p><strong>' + drift.missing.length + ' object(s) this ' +
          'service\'s ' +
          'driver declares are NOT in the database:</strong> ' +
          drift.missing.map(function (one) {
            return '<code>' + admin.esc(one) + '</code>';
          }).join(', ') + '.</p><p>The driver creates what is missing when ' +
          'it ' +
          'opens &mdash; and on a least-privilege deployment it ' +
          '<strong>cannot</strong>, because the role it dials with holds no ' +
          'CREATE. There the failure arrives as a permission error naming a ' +
          'statement nobody typed. Re-run <code>postgres/schema.sql</code> ' +
          'as ' +
          'the owner.</p>',
          'The schema is missing something the driver expects')
      : admin.note(
          '<p>All ' + drift.declared.length + ' objects the driver declares ' +
          'are present, at schema version ' +
          admin.esc(String(json.schemaExpected.version)) + '.</p>' +
          '<p>Nothing else in this service makes this check. ' +
          '<code>tests/postgres_schema.js</code> compares the driver against ' +
          '<code>postgres/schema.sql</code> character for character, and ' +
          'neither of those is ever compared against a <em>running ' +
          'server</em> ' +
          '&mdash; so a database built by an older copy of that file, or by ' +
          'hand, or half-migrated, satisfies both and is missing a ' +
          'table.</p>' +
          '<p>The reverse is deliberately <em>not</em> reported: a table in ' +
          'this schema the driver never heard of is an operator\'s ' +
          'business, ' +
          'and a page calling it an error would be this service claiming a ' +
          'namespace it does not own.</p>',
          'The schema is what the driver expects');
    log.debug("Leaving DatabaseAdmin.driftBlock().");
    return '<h3>Schema drift</h3>' + body;
  }

  private sectionBlock(section: Json, json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering DatabaseAdmin.sectionBlock().");
    const ids = Object.keys(json.probes).filter(function (id) {
      return json.probes[id].group === section.group && json.probes[id].ok;
    });
    if (!ids.length) {
      log.debug("Leaving DatabaseAdmin.sectionBlock().");
      return '';
    }
    log.debug("Leaving DatabaseAdmin.sectionBlock().");
    return '<h3>' + admin.esc(section.heading) + '</h3>' +
      admin.note(section.blurb) +
      ids.map(function (id) {
        const probe = json.probes[id];
        return '<h4>' + admin.esc(id) +
          ' <span class="muted">' +
          (probe.shape === 'rows' ? probe.count + ' row(s)' : '1 row') +
          ', ' + probe.tookMs + 'ms</span></h4>' +
          '<p class="muted">' + admin.esc(probe.what) + '</p>' +
          (probe.shape === 'rows' ? self.rowsTable(probe)
                                  : self.rowTable(probe));
      }).join('');
  }

  private failureBlock(json: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering DatabaseAdmin.failureBlock().");
    if (!json.failed.length) {
      log.debug("Leaving DatabaseAdmin.failureBlock().");
      return '<h3>What could not be collected</h3>' +
        admin.note('Nothing. Every one of the ' +
                   Object.keys(json.probes).length + ' probes answered.');
    }
    log.debug("Leaving DatabaseAdmin.failureBlock().");
    return '<h3>What could not be collected</h3>' + admin.note(
      '<p>' + json.failed.length + ' of ' + Object.keys(json.probes).length +
      ' probes did not answer. <strong>Each one costs a row here rather ' +
      'than ' +
      'the page</strong>, which is why they are run and caught separately: ' +
      'which views a role may read depends on the server version and on the ' +
      'operator\'s grants, and one rejection must not take the other ' +
      'nineteen ' +
      'with it.</p>' +
      '<table class="grid"><thead><tr><th>Probe</th><th>What it would ' +
      'show</th>' +
      '<th>SQLSTATE</th><th>Why not</th></tr></thead><tbody>' +
      json.failed.map(function (id) {
        return self.probeFailure(id, json.probes[id]);
      }).join('') +
      '</tbody></table>',
      json.failed.length + ' probe(s) unavailable');
  }

  registerRoutes(app: { get: Function }): void {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering DatabaseAdmin.registerRoutes().");
    app.get('/admin/database', function (req, res) {
      log.debug('Entering GET /admin/database.');
      self.renderDatabase(req, res);
      log.debug('Leaving GET /admin/database.');
    });
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  DatabaseAdmin: DatabaseAdmin,
  installInstance: (instance: DatabaseAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts`. Rule 7 — one function behind the page and
  // the operation, so the two cannot report different numbers.
  databaseView: slot.forward('databaseJson'),
  // For `tests/database_metrics.js` — see `DatabaseAdmin.sections()`.
  sections: slot.forward('sections')
};
