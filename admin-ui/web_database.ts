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

// THE SECTIONS' WORDS IN THE READER'S LANGUAGE (#539). `SECTIONS` stays the
// English table `database_admin.ts` reads; the page draws each heading and
// blurb from here, by group, and falls back to the table for a group this
// does not name.
const SECTION_WORDS = function (t: Json): Record<string, Json> {
  return {
    Server: { heading: t.html('consoleDatabase.serverHeading'),
              blurb: t.html('consoleDatabase.serverBlurb') },
    Activity: { heading: t.html('consoleDatabase.activityHeading'),
                blurb: t.html('consoleDatabase.activityBlurb') },
    Background: { heading: t.html('consoleDatabase.backgroundHeading'),
                  blurb: t.html('consoleDatabase.backgroundBlurb') },
    Schema: { heading: t.html('consoleDatabase.schemaHeading'),
              blurb: t.html('consoleDatabase.schemaBlurb') },
    Configuration: { heading: t.html('consoleDatabase.configHeading'),
                     blurb: t.html('consoleDatabase.configBlurb') }
  };
};

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
   * @param ctx - the render context (`WebKit.context()`), whose translator
   *   the page is drawn with (#539); the default when absent
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return DatabasePage.body(view, (ctx && ctx.t) || kit.context().t);
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
  // Every helper below takes the page's translator `t` (#539) from body().
  static cell(value: Json, t: Json): string {
    if (value === null || value === undefined) {
      return '<span class="muted">—</span>';
    }
    if (value === '<insufficient privilege>') {
      return '<span class="muted">' + t.html('consoleDatabase.withheld') +
             '</span>';
    }
    if (value instanceof Date) {
      return kit.esc(value.toISOString()
                            .replace('T', ' ')
                            .replace(/\..*$/, 'Z'));
    }
    if (typeof value === 'boolean') {
      return value ? '<span class="ok">' + t.html('consoleDatabase.yes') +
                     '</span>'
                   : '<span class="muted">' + t.html('consoleDatabase.no') +
                     '</span>';
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
      return kit.clipped(text, 90, t);
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

  // The explanation is this page's prose and is translated (#539); the
  // probe's error beside it stays as PostgreSQL wrote it.
  static probeFailure(id: string, probe: Json, t: Json): string {
    const why = probe.code === '42P01'
      ? t.html('consoleDatabase.noView') +
        (probe.expected
          ? t.html('consoleDatabase.viewArrived',
                   { version: probe.expected })
          : '')
      : (probe.code === '42501'
          ? t.html('consoleDatabase.mayNotRead')
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
  static rowTable(probe: Json, t: Json): string {
    const self = this;
    if (!probe.row) {
      return kit.note(t.html('consoleDatabase.noRow'));
    }
    const keys = Object.keys(probe.row);
    return '<table class="grid"><tbody>' +
      keys.map(function (key) {
        return '<tr><th>' + self.columnLabel(key) + '</th><td>' +
               self.cell(probe.row[key], t) + '</td></tr>';
      }).join('') +
      '</tbody></table>';
  }

  // A many-row probe, drawn as a table whose HEADINGS ARE THE KEYS OF THE
  // FIRST ROW. That is the whole reason this page survives a major version
  // change, and it is why an empty result has to be handled here rather than
  // falling out of the loop: with no row there are no keys, and a table with
  // no headings is not an empty table, it is a rendering bug.
  static rowsTable(probe: Json, t: Json): string {
    const self = this;
    if (!probe.rows || !probe.rows.length) {
      return '<p class="muted">' + t.html('consoleDatabase.noRows') + '</p>';
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
          return '<td>' + self.cell(row[key], t) + '</td>';

        }).join('') + '</tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  static body(json: Json, t: Json): string {
    const self = this;

    // NO DATABASE AT ALL. The commonest state by a wide margin — `memory` is
    // the default — so it is a paragraph that says which of the three "no"
    // answers this is, rather than an empty page with tables on it.
    if (!json.available) {
      // `why` is the view's sentence, drawn as it comes; the link is markup
      // a message cannot carry, so the paragraph is cut at it.
      return kit.note(
        '<p>' + kit.esc(json.why) + '</p>' +
        '<p>' + t.html('consoleDatabase.wouldShow') +
        ' <a href="/admin/persistence">' +
        t.html('consoleDatabase.persistencePage') + '</a> ' +
        t.html('consoleDatabase.wouldShowAfter') + '</p>',
        t.html('consoleDatabase.noDatabaseTitle'));
    }

    const target = json.target || {};
    const tiles = '<div class="tiles">' +
      kit.tile(json.ok ? t.text('consoleDatabase.up')
                       : t.text('consoleDatabase.down'),
               t.text('consoleDatabase.tileDatabase')) +
      kit.tile(String((json.probes && json.probes.size &&
                         json.probes.size.row &&
                         json.probes.size.row.pretty) || '—'),
               t.text('consoleDatabase.tileOnDisk')) +
      kit.tile(json.derived && json.derived.cacheHitPercent !== null
        ? json.derived.cacheHitPercent + '%' : '—',
               t.text('consoleDatabase.tileCacheHit')) +
      kit.tile(String((json.pool && json.pool.total) || 0) + '/' +
                 String((json.pool && json.pool.max) || 0),
               t.text('consoleDatabase.tilePool')) +
      kit.tile(String(json.tookMs) + 'ms',
               t.text('consoleDatabase.tileCollectedIn')) +
      kit.tile(String((json.failed || []).length),
               t.text('consoleDatabase.tileUnavailable')) +
      '</div>';

    const what = kit.note(
      '<p>' + t.html('consoleDatabase.whatDoing') +
      ' <a href="/admin/persistence">' +
      t.html('consoleDatabase.persistence') + '</a>' +
      t.html('consoleDatabase.whatConfigured') + '</p><p>' +
      t.html('consoleDatabase.whatShape') + '</p><p>' +
      t.html('consoleDatabase.whatNoQuery',
             { ms: String(json.statementTimeoutMs) }) +
      (json.statementTimeoutSet ? '' :
        t.html('consoleDatabase.timeoutNotInForce')) +
      t.html('consoleDatabase.singleConnection') + '</p>',
      t.html('consoleDatabase.whatTitle'));

    // The connection's coordinates and its TLS sentence are the view's.
    const connection = kit.note(
      '<p>' + t.html('consoleDatabase.connectedTo',
                     { where: String(target.host || '?') + ':' +
                         String(target.port || '?') + '/' +
                         String(target.database || '?'),
                       user: String(target.user || '?'),
                       schema: String(json.schema || '?') }) + ' ' +
      kit.esc(String(target.tls || '')) + '</p>' +
      '<p>' + t.html('consoleDatabase.poolFigures') + '</p>',
      t.html('consoleDatabase.connectionTitle'));

    // THE NARROWED ANSWER, said once and prominently rather than as a
    // footnote under a table somebody has already misread.
    const narrowed = kit.warn(
      '<p>' + t.html('consoleDatabase.narrowedRole') + '</p><ul><li>' +
      t.html('consoleDatabase.narrowedView') + '</li><li>' +
      t.html('consoleDatabase.narrowedBackend') + '</li></ul><p>' +
      t.html('consoleDatabase.narrowedGrant') + '</p>',
      t.html('consoleDatabase.narrowedTitle'));

    // A database that could not be reached is a failure, and its box stays
    // English (#539).
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
           self.derivedBlock(json, t) +
           self.driftBlock(json, t) +
           SECTIONS.map(function (section) {
             return self.sectionBlock(section, json, t);
           }).join('') +
           self.failureBlock(json, t);
  }

  static derivedBlock(json: Json, t: Json): string {
    const d = json.derived;
    // The index names are code, put in by the page; the sentences around
    // them are messages.
    const unused = d.unusedIndexes.length
      ? '<p>' + t.html('consoleDatabase.unusedHead',
                       { n: d.unusedIndexes.length }) + ' ' +
        d.unusedIndexes.map(function (one) {
          return '<code>' + kit.esc(one) + '</code>';
        }).join(', ') + t.html('consoleDatabase.unusedWhy') + '</p>'
      : '<p>' + t.html('consoleDatabase.allScanned') + '</p>';
    return '<h3>' + t.html('consoleDatabase.ratios') + '</h3>' + kit.note(
      '<table class="grid"><tbody>' +
      '<tr><th>' + t.html('consoleDatabase.cacheHit') + '</th><td>' +
        (d.cacheHitPercent === null ? '<span class="muted">' +
          t.html('consoleDatabase.nothingRead') + '</span>'
          : kit.esc(String(d.cacheHitPercent)) + '%') +
        '</td><td class="why">' + t.html('consoleDatabase.cacheHitWhy') +
        '</td></tr>' +
      '<tr><th>' + t.html('consoleDatabase.rollbacks') + '</th><td>' +
        (d.rollbackPercent === null ? '<span class="muted">' +
          t.html('consoleDatabase.noTransactions') + '</span>'
          : kit.esc(String(d.rollbackPercent)) + '%') +
        '</td><td class="why">' + t.html('consoleDatabase.rollbacksWhy') +
        '</td></tr>' +
      '<tr><th>' + t.html('consoleDatabase.deadTuples') + '</th><td>' +
        (d.deadTuplePercent === null
          ? '<span class="muted">' + t.html('consoleDatabase.noRowsYet') +
            '</span>'
          : kit.esc(String(d.deadTuplePercent)) + '%') +
        '</td><td class="why">' + t.html('consoleDatabase.deadTuplesWhy') +
        '</td></tr><tr><th>' + t.html('consoleDatabase.scans') +
        '</th><td>' +
        t.html('consoleDatabase.scansValue',
               { seq: String(d.seqScans), idx: String(d.idxScans) }) +
        '</td>' +
        '<td class="why">' + t.html('consoleDatabase.scansWhy') +
        '</td></tr>' +
      '</tbody></table>' + unused +
      '<p class="muted">' +
      (d.statsReset
        ? t.html('consoleDatabase.cumulativeSince',
                 { since: String(new Date(d.statsReset).toISOString()
                   .replace('T', ' ').replace(/\..*$/, 'Z')) })
        : t.html('consoleDatabase.cumulativeSinceReset')) +
      t.html('consoleDatabase.cumulativeWhy') + '</p>',
      t.html('consoleDatabase.ratiosTitle'));
  }

  static driftBlock(json: Json, t: Json): string {
    const drift = json.schemaDrift;
    if (!drift.declared.length) {
      return '';
    }
    const body = drift.missing.length
      ? kit.warn(
          '<p>' + t.html('consoleDatabase.missingHead',
                         { n: drift.missing.length }) + ' ' +
          drift.missing.map(function (one) {
            return '<code>' + kit.esc(one) + '</code>';
          }).join(', ') + '.</p><p>' +
          t.html('consoleDatabase.missingWhy') + '</p>',
          t.html('consoleDatabase.missingTitle'))
      : kit.note(
          '<p>' + t.html('consoleDatabase.allPresent',
                         { n: drift.declared.length,
                           version: String(json.schemaExpected.version) }) +
          '</p>' +
          '<p>' + t.html('consoleDatabase.onlyCheck') + '</p>' +
          '<p>' + t.html('consoleDatabase.reverseNot') + '</p>',
          t.html('consoleDatabase.presentTitle'));
    return '<h3>' + t.html('consoleDatabase.drift') + '</h3>' + body;
  }

  static sectionBlock(section: Json, json: Json, t: Json): string {
    const self = this;
    const ids = Object.keys(json.probes).filter(function (id) {
      return json.probes[id].group === section.group && json.probes[id].ok;
    });
    if (!ids.length) {
      return '';
    }
    const words = SECTION_WORDS(t)[section.group] ||
      { heading: kit.esc(section.heading), blurb: section.blurb };
    return '<h3>' + words.heading + '</h3>' +
      kit.note(words.blurb) +
      ids.map(function (id) {
        const probe = json.probes[id];
        return '<h4>' + kit.esc(id) +
          ' <span class="muted">' +
          (probe.shape === 'rows'
            ? t.html('consoleDatabase.rowsTook',
                     { n: probe.count, ms: probe.tookMs })
            : t.html('consoleDatabase.oneRowTook', { ms: probe.tookMs })) +
          '</span></h4>' +
          '<p class="muted">' + kit.esc(probe.what) + '</p>' +
          (probe.shape === 'rows' ? self.rowsTable(probe, t)
                                  : self.rowTable(probe, t));
      }).join('');
  }

  static failureBlock(json: Json, t: Json): string {
    const self = this;
    if (!json.failed.length) {
      return '<h3>' + t.html('consoleDatabase.notCollected') + '</h3>' +
        kit.note(t.html('consoleDatabase.allAnswered',
                        { n: Object.keys(json.probes).length }));
    }
    return '<h3>' + t.html('consoleDatabase.notCollected') + '</h3>' +
      kit.note(
      '<p>' + t.html('consoleDatabase.someFailed',
                     { failed: json.failed.length,
                       total: Object.keys(json.probes).length }) + '</p>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleDatabase.thProbe') + '</th><th>' +
      t.html('consoleDatabase.thWouldShow') + '</th>' +
      '<th>SQLSTATE</th><th>' + t.html('consoleDatabase.thWhyNot') +
      '</th></tr></thead><tbody>' +
      json.failed.map(function (id) {
        return self.probeFailure(id, json.probes[id], t);
      }).join('') +
      '</tbody></table>',
      t.html('consoleDatabase.unavailableTitle',
             { n: json.failed.length }));
  }
}

export = DatabasePage;
