// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_database.ts
//
// ---------------------------------------------------------------------------
// MONITORING → DATABASE, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Monitoring → Database from the answer of `GET /admin-api/database`:
// everything PostgreSQL reports about itself, the four figures computed from
// its counters, and the schema drift check.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `DatabaseAdmin`'s in `admin-ui/database_admin.ts`, moved
// with their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * The page's sections in the order they are drawn; every metrics probe names
 * one of these groups.
 */
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

/**
 * Draws Monitoring → Database from the answer of `GET /admin-api/database`:
 * everything PostgreSQL reports about itself, the four figures computed from
 * its counters, and the schema drift check.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class DatabasePage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return DatabasePage.body(view);
  }

  /**
   * The page's sections in the order they are drawn.
   */
  static readonly SECTIONS = SECTIONS;

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
  static cell(value: Json): string {
    if (value === null || value === undefined) {
      return '<span class="muted">—</span>';
    }
    if (value === '<insufficient privilege>') {
      return '<span class="muted">withheld</span>';
    }
    if (value instanceof Date) {
      return kit.esc(value.toISOString()
                            .replace('T', ' ')
                            .replace(/\..*$/, 'Z'));
    }
    if (typeof value === 'boolean') {
      return value ? '<span class="ok">yes</span>'
                   : '<span class="muted">no</span>';
    }
    if (typeof value === 'object') {
      return '<code>' + kit.esc(JSON.stringify(value)) + '</code>';
    }
    const text = String(value);
    // A definition or a version banner runs to hundreds of characters and
    // would stretch the table past the width of the page; `clipped()` is the
    // console's own control for that and opens out on a click, so nothing is
    // lost.
    if (text.length > 90) {
      return kit.clipped(text, 90);
    }
    return kit.esc(text);
  }

  // A column name as a person reads it. `n_tup_hot_upd` is PostgreSQL's name
  // and is what somebody searching its documentation will type, so it is KEPT
  // and shown as itself — this only replaces the underscores for the eye. The
  // raw name goes in a `title`, so the page never costs a reader the string
  // they would need to look it up.
  static columnLabel(name: Json): string {
    return '<span title="' + kit.esc(name) + '">' +
           kit.esc(String(name).replace(/_/g, ' ')) + '</span>';
  }

  static probeFailure(id: string, probe: Json): string {
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
    return '<tr><td><code>' + kit.esc(id) + '</code></td>' +
           '<td>' + kit.esc(probe.what) + '</td>' +
           '<td><code>' + kit.esc(probe.code || '—') + '</code></td>' +
           '<td>' + kit.esc(probe.error) +
           (why ? '<br><span class="muted">' + why + '</span>' : '') +
           '</td></tr>';
  }

  // A single-row probe, drawn as label/value pairs. A wide row — thirty
  // columns for `pg_stat_database` — is unreadable as a table with thirty
  // headings and one line under them, which is what the first version of this
  // did.
  static rowTable(probe: Json): string {
    const self = this;
    if (!probe.row) {
      return kit.note('That view answered no row at all, which for a ' +
                        'probe scoped to this database means the server ' +
                        'keeps no statistics for it yet.');
    }
    const keys = Object.keys(probe.row);
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
  static rowsTable(probe: Json): string {
    const self = this;
    if (!probe.rows || !probe.rows.length) {
      return '<p class="muted">No rows.</p>';
    }
    const keys = Object.keys(probe.rows[0]);
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

  static body(json: Json): string {
    const self = this;

    // NO DATABASE AT ALL. The commonest state by a wide margin — `memory` is
    // the default — so it is a paragraph that says which of the three "no"
    // answers this is, rather than an empty page with tables on it.
    if (!json.available) {
      return kit.note(
        '<p>' + kit.esc(json.why) + '</p>' +
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
      kit.tile(json.ok ? 'up' : 'down', 'database') +
      kit.tile(String((json.probes && json.probes.size &&
                         json.probes.size.row &&
                         json.probes.size.row.pretty) || '—'), 'on disk') +
      kit.tile(json.derived && json.derived.cacheHitPercent !== null
        ? json.derived.cacheHitPercent + '%' : '—', 'cache hit') +
      kit.tile(String((json.pool && json.pool.total) || 0) + '/' +
                 String((json.pool && json.pool.max) || 0), 'pool') +
      kit.tile(String(json.tookMs) + 'ms', 'collected in') +
      kit.tile(String((json.failed || []).length), 'probes unavailable') +
      '</div>';

    const what = kit.note(
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
      kit.esc(String(json.statementTimeoutMs)) + 'ms' +
      (json.statementTimeoutSet ? '' :
        ' &mdash; <strong>which this server would not accept, so that bound ' +
        'is ' +
        'NOT in force</strong>') +
      ', on the single connection this page borrows.</p>',
      'What this page is, and the three things it will not do');

    const connection = kit.note(
      '<p>Connected to <code>' + kit.esc(String(target.host || '?')) + ':' +
      kit.esc(String(target.port || '?')) + '/' +
      kit.esc(String(target.database || '?')) + '</code> as <code>' +
      kit.esc(String(target.user || '?')) + '</code>, schema <code>' +
      kit.esc(String(json.schema || '?')) + '</code>. ' +
      kit.esc(String(target.tls || '')) + '</p>' +
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
    const narrowed = kit.warn(
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
      return tiles + what + kit.warn(
        '<p>No statistics could be collected at all: <code>' +
        kit.esc(String(json.error)) + '</code></p>' +
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

    return tiles + what + connection + narrowed +
           self.derivedBlock(json) +
           self.driftBlock(json) +
           SECTIONS.map(function (section) {
             return self.sectionBlock(section, json);
           }).join('') +
           self.failureBlock(json);
  }

  static derivedBlock(json: Json): string {
    const d = json.derived;
    const unused = d.unusedIndexes.length
      ? '<p><strong>' + d.unusedIndexes.length + ' index(es) have never ' +
        'been ' +
        'scanned:</strong> ' + d.unusedIndexes.map(function (one) {
          return '<code>' + kit.esc(one) + '</code>';
        }).join(', ') + '. On a database that has been serving traffic that ' +
        'is ' +
        'the most actionable number on this page &mdash; an index nothing ' +
        'reads is write cost and disk for nothing. On one that has just ' +
        'started it means only that nothing has queried yet, and the ' +
        'counters ' +
        'below say which situation this is.</p>'
      : '<p>Every index here has been scanned at least once.</p>';
    return '<h3>The four ratios</h3>' + kit.note(
      '<table class="grid"><tbody>' +
      '<tr><th>Cache hit</th><td>' +
        (d.cacheHitPercent === null ? '<span class="muted">nothing read ' +
                                      'yet</span>'
          : kit.esc(String(d.cacheHitPercent)) + '%') +
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
          : kit.esc(String(d.rollbackPercent)) + '%') +
        '</td><td class="why">A share and not a count: rollbacks are ' +
        'ordinary ' +
        'here &mdash; a conflicting upsert produces one &mdash; and only the ' +
        'proportion means anything.</td></tr>' +
      '<tr><th>Dead tuples</th><td>' +
        (d.deadTuplePercent === null
          ? '<span class="muted">no rows yet</span>'
          : kit.esc(String(d.deadTuplePercent)) + '%') +
        '</td><td class="why">Dead rows as a share of all rows, summed ' +
        'across ' +
        'the schema. This is the bloat signal; autovacuum is what brings it ' +
        'down, and the per-table vacuum times are in the schema ' +
        'section.</td></tr><tr><th>Scans</th><td>' +
      kit.esc(String(d.seqScans)) + ' ' +
            'sequential, ' +
        kit.esc(String(d.idxScans)) + ' index</td>' +
        '<td class="why">On six small tables a sequential scan is ' +
        'frequently ' +
        'the right plan and this is <em>not</em> a fault to chase &mdash; ' +
        'read ' +
        'it beside the row counts below.</td></tr>' +
      '</tbody></table>' + unused +
      '<p class="muted"><strong>Every figure on this page is cumulative ' +
      'since ' +
      (d.statsReset
        ? kit.esc(String(new Date(d.statsReset).toISOString()
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

  static driftBlock(json: Json): string {
    const drift = json.schemaDrift;
    if (!drift.declared.length) {
      return '';
    }
    const body = drift.missing.length
      ? kit.warn(
          '<p><strong>' + drift.missing.length + ' object(s) this ' +
          'service\'s ' +
          'driver declares are NOT in the database:</strong> ' +
          drift.missing.map(function (one) {
            return '<code>' + kit.esc(one) + '</code>';
          }).join(', ') + '.</p><p>The driver creates what is missing when ' +
          'it ' +
          'opens &mdash; and on a least-privilege deployment it ' +
          '<strong>cannot</strong>, because the role it dials with holds no ' +
          'CREATE. There the failure arrives as a permission error naming a ' +
          'statement nobody typed. Re-run <code>postgres/schema.sql</code> ' +
          'as ' +
          'the owner.</p>',
          'The schema is missing something the driver expects')
      : kit.note(
          '<p>All ' + drift.declared.length + ' objects the driver declares ' +
          'are present, at schema version ' +
          kit.esc(String(json.schemaExpected.version)) + '.</p>' +
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
    return '<h3>Schema drift</h3>' + body;
  }

  static sectionBlock(section: Json, json: Json): string {
    const self = this;
    const ids = Object.keys(json.probes).filter(function (id) {
      return json.probes[id].group === section.group && json.probes[id].ok;
    });
    if (!ids.length) {
      return '';
    }
    return '<h3>' + kit.esc(section.heading) + '</h3>' +
      kit.note(section.blurb) +
      ids.map(function (id) {
        const probe = json.probes[id];
        return '<h4>' + kit.esc(id) +
          ' <span class="muted">' +
          (probe.shape === 'rows' ? probe.count + ' row(s)' : '1 row') +
          ', ' + probe.tookMs + 'ms</span></h4>' +
          '<p class="muted">' + kit.esc(probe.what) + '</p>' +
          (probe.shape === 'rows' ? self.rowsTable(probe)
                                  : self.rowTable(probe));
      }).join('');
  }

  static failureBlock(json: Json): string {
    const self = this;
    if (!json.failed.length) {
      return '<h3>What could not be collected</h3>' +
        kit.note('Nothing. Every one of the ' +
                   Object.keys(json.probes).length + ' probes answered.');
    }
    return '<h3>What could not be collected</h3>' + kit.note(
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
}

export = DatabasePage;
