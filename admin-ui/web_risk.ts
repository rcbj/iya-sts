// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_risk.ts
//
// ---------------------------------------------------------------------------
// MONITORING → RISK AND RISK SCORING, DRAWN FROM THEIR VIEWS ALONE (#446,
// 2026-10-05).
//
// Draws Risk from the answer of `GET /admin-api/risk` — the datasets a score
// reads and their versions, the assessments and standings, an address lookup,
// the operator's lists and the refused passwords — and Risk scoring from that
// of `GET /admin-api/risk/metrics`.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `RiskAdmin`'s in `admin-ui/risk_admin.ts`, moved with their
// comments; that module still draws the page until the console's cutover, by
// calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * The console path of Monitoring → Risk: the datasets a score reads and the
 * failure history.
 */
const PAGE = '/admin/risk';

// THE UPLOAD (#215): its own path, because its body is a file the body
// parsers leave unread (`common/app.js`), which is decided by path.
/**
 * The path a dataset version is uploaded to as a file.
 */
const UPLOAD = '/admin/risk/upload';

// MONITORING → RISK SCORING (#62): the scoring system measured — what it
// assessed over a window, how the levels and signals fell, how long it took
// and what it did about it. A second page rather than a section of the one
// above, because rcbj asked for it as a page and because the two answer
// different questions: that one is "what does the service know", this one
// "is the scoring working".
/**
 * The console path of Monitoring → Risk scoring: the scoring system measured.
 */
const METRICS_PAGE = '/admin/risk-scoring';

const LEVELS = ['HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];

// Each level's colour: the same four as the badge on a person's user page
// (`admin.ts`'s `riskBadge()`), so a level reads the same on both.
const LEVEL_COLOURS: Record<string, string> = {
  LOW: '#188038', MEDIUM: '#f9ab00', HIGH: '#d93025', UNSCORED: '#5f6368' };

/**
 * Draws Risk from the answer of `GET /admin-api/risk` — the datasets a score
 * reads and their versions, the assessments and standings, an address lookup,
 * the operator's lists and the refused passwords — and Risk scoring from that
 * of `GET /admin-api/risk/metrics`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class RiskPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return RiskPage.html(ctx, view);
  }

  // One person in a Who cell: their username linked to their Directory →
  // Users page in this realm, with the subject under it; the subject alone
  // when the directory no longer holds them.
  static whoCell(row: Json): string {
    const subject = '<code>' + kit.esc(row.subject) + '</code>';
    if (!row.username) {
      return subject + '<br><small>(no directory entry)</small>';
    }
    const link = row.userHref;
    return '<a href="' + kit.esc(link) + '"><strong>' +
      kit.esc(row.username) + '</strong></a><br><small>' + subject +
      '</small>';
  }

  // One table of counts with a bar each, largest first. `colour` gives a
  // row's bar colour; `limit` keeps the longest tables short.
  static bars(id: string, head: string, counts: Json, total: number,
               colour?: (k: string) => string, limit?: number,
               order?: string[]): string {
    const esc = kit.esc.bind(kit);
    const keys = order ? order.filter(function (k: string): boolean {
      return counts[k] !== undefined;
    }) : Object.keys(counts || {}).sort(function (a: string,
                                                   b: string): number {
      return counts[b] - counts[a];
    });
    const shown = limit ? keys.slice(0, limit) : keys;
    const rows = shown.map(function (k: string): string {
      const n = Number(counts[k]) || 0;
      const share = total ? n / total : 0;
      return '<tr><td>' + esc(k || '(none)') + '</td><td class="num">' + n +
        '</td><td class="num">' + (share * 100).toFixed(1) + '%</td>' +
        '<td style="width:45%"><div style="height:12px;border-radius:3px;' +
        'width:' + Math.max(share * 100, n ? 0.5 : 0).toFixed(1) + '%;' +
        'background:' + (colour ? colour(k) : '#1a73e8') + '"></div></td>' +
        '</tr>';
    }).join('');
    return '<table class="grid" id="' + id + '"><thead><tr><th>' +
      esc(head) + '</th><th>Count</th><th>Share</th><th></th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="4">None in this window.</td>' +
                           '</tr>') + '</tbody></table>' +
      (limit && keys.length > limit ? '<p><small>' + (keys.length - limit) +
       ' more not shown; the JSON has every one.</small></p>' : '');
  }

  // The levels over time: a column per bucket, stacked by level, drawn as
  // markup — no script, for the reason the console has none.
  static timeline(m: Json): string {
    const esc = kit.esc.bind(kit);
    const byAt = new Map<number, Json>();
    (m.assessments.series || []).forEach(function (b: Json): void {
      byAt.set(Number(b.at), b);
    });
    const first = Math.floor(Number(m.since) / m.bucketMs) * m.bucketMs;
    const columns: Json[] = [];
    for (let at = first; at <= Number(m.since) + Number(m.windowMs);
         at += m.bucketMs) {
      columns.push(byAt.get(at) || { at: at, total: 0 });
    }
    const peak = Math.max(1, ...columns.map(function (c: Json): number {
      return Number(c.total) || 0;
    }));
    const stamp = function (ms: number): string {
      return new Date(ms).toISOString().slice(0, 16).replace('T', ' ');
    };
    const bars = columns.map(function (c: Json): string {
      const parts = LEVELS.filter(function (l: string): boolean {
        return Number(c[l]) > 0;
      }).map(function (l: string): string {
        return '<div style="height:' + (Number(c[l]) / peak * 100)
          .toFixed(2) + '%;background:' + LEVEL_COLOURS[l] + '"></div>';
      }).join('');
      const title = stamp(c.at) + ' UTC: ' + (Number(c.total) || 0) +
        ' assessment(s)' + LEVELS.filter(function (l: string): boolean {
          return Number(c[l]) > 0;
        }).map(function (l: string): string {
          return ', ' + c[l] + ' ' + l;
        }).join('');
      return '<div title="' + esc(title) + '" style="flex:1;display:flex;' +
        'flex-direction:column-reverse;min-width:3px">' + parts + '</div>';
    }).join('');
    const legend = LEVELS.map(function (l: string): string {
      return '<span style="display:inline-block;width:10px;height:10px;' +
        'background:' + LEVEL_COLOURS[l] + ';margin:0 4px 0 12px"></span>' +
        l;
    }).join('');
    return '<div id="risk-timeline" style="display:flex;align-items:' +
      'flex-end;gap:2px;height:160px;padding:6px;border:1px solid #dadce0;' +
      'border-radius:6px">' + bars + '</div><p><small>' +
      esc(stamp(first)) + ' UTC to now, a column per ' +
      esc(RiskPage.duration(m.bucketMs)) + '; the tallest is ' + peak +
      '. Hover a column for its counts.' + legend + '</small></p>';
  }

  // A duration in the largest unit that divides it.
  /**
   * Says a duration in the largest unit that divides it.
   *
   * @param ms - the duration in milliseconds
   * @returns the duration as text
   */
  static duration(ms: number): string {
    if (ms % 86400000 === 0) {
      return ms / 86400000 + ' day' + (ms === 86400000 ? '' : 's');
    }
    if (ms % 3600000 === 0) {
      return ms / 3600000 + ' hour' + (ms === 3600000 ? '' : 's');
    }
    return ms / 60000 + ' minutes';
  }

  // THE CALIBRATION REPORT (`RiskEngine.calibrate()`): advice, drawn beside
  // what is set now, with the setting that would apply it named.
  static calibrationHtml(m: Json): string {
    const esc = kit.esc.bind(kit);
    const c = m.calibration;
    const pct = function (x: number): string {
      return (x * 100).toFixed(1) + '%';
    };
    const threshold = function (name: string, t: Json, key: string): string {
      return '<tr><td>' + name + '</td><td class="num">' + esc(t.current) +
        '</td><td class="num">' + pct(t.share) + '</td><td class="num">' +
        pct(t.target) + '</td><td class="num">' + (t.suggested === null
          ? '<small>fewer than ' + c.minimums.assessments + ' assessments' +
            '</small>'
          : esc(Number(t.suggested).toPrecision(3)) + ' <small>(<code>' +
            key + '</code> = ' + Math.max(1, Math.round(t.suggested * 100)) +
            ')</small>') + '</td></tr>';
    };
    const rows = c.signals.map(function (s: Json): string {
      return '<tr><td><code>' + esc(s.signal) + '</code></td>' +
        '<td class="num">&times;' + esc(s.factor) +
        (s.factor !== s.builtIn ? ' <small>(built in &times;' +
                                  esc(s.builtIn) + ')</small>' : '') +
        '</td><td class="num">' + s.fired + '</td><td class="num">' +
        s.high + '</td><td class="num">' + s.answered + '</td>' +
        '<td class="num">' + s.notMe + '</td><td>' +
        (s.suggested === null ? '<small>' + esc(s.advice) + '</small>'
          : '<strong>' + esc(s.advice) + '</strong> &times;' +
            esc(s.suggested)) + '</td></tr>';
    }).join('');
    const suggested = c.signals.filter(function (s: Json): boolean {
      return s.suggested !== null && s.advice !== 'keep';
    }).map(function (s: Json): string {
      return s.signal + '=' + s.suggested;
    });
    return '<h3 id="risk-calibration">Calibration</h3><p>Advice from this ' +
      'window, never applied by itself. <strong>Thresholds</strong>: the ' +
      'score the target share of sign-ins reaches. <strong>Factors</strong>' +
      ': how often a sign-in carrying the signal was answered "not me" on ' +
      '/portal/sign-ins, against how often any answered sign-in was (' +
      pct(c.notMeRate) + ' of ' + c.answered + '), scaled onto the current ' +
      'factor. The answers are a biased sample — a flagged sign-in is ' +
      'likelier to be asked about — so read a suggestion as a direction.' +
      '</p><table class="grid" id="risk-calibration-thresholds"><thead><tr>' +
      '<th>Level</th><th>From score</th><th>Share now</th><th>Target</th>' +
      '<th>Suggested</th></tr></thead><tbody>' +
      threshold('MEDIUM or worse', c.thresholds.medium,
                'risk.mediumScorePercent') +
      threshold('HIGH', c.thresholds.high, 'risk.highScorePercent') +
      '</tbody></table><table class="grid" id="risk-calibration-signals">' +
      '<thead><tr><th>Signal</th><th>Factor</th><th>Fired</th>' +
      '<th>Ended HIGH</th><th>Answered</th><th>"Not me"</th>' +
      '<th>Suggestion</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      (suggested.length ? '<p>To apply every suggestion, set <code>' +
        'risk.signalFactors</code> to <code id="risk-calibration-apply">' +
        esc(suggested.join(',')) + '</code> on Monitoring &rarr; Risk.</p>'
        : '') +
      (c.invalidFactors.length ? '<div class="err">risk.signalFactors ' +
        'entries ignored (STS-RISK-0026): ' +
        esc(c.invalidFactors.join(', ')) + '</div>' : '');
  }

  static metricsHtml(m: Json): string {
    const esc = kit.esc.bind(kit);
    const a = m.assessments;
    const p = m.process;
    const level = function (k: string): string {
      return LEVEL_COLOURS[k] || '#5f6368';
    };
    const windows = m.windows.map(function (w: string): string {
      return w === m.window ? '<strong>' + esc(w) + '</strong>'
        : '<a href="' + esc(METRICS_PAGE + '?window=' + w) + '">' +
          esc(w) + '</a>';
    }).join(' &middot; ');
    const high = Number(a.byLevel.HIGH) || 0;
    const people = Object.keys(m.standings).reduce(function (s: number,
                                                           k: string) {
      return s + Number(m.standings[k]);
    }, 0);
    const signals = m.signals.slice().sort(function (x: Json,
                                                     y: Json): number {
      return y.fired - x.fired || y.factor - x.factor;
    }).map(function (s: Json): string {
      const share = a.total ? s.fired / a.total : 0;
      return '<tr><td><code>' + esc(s.signal) + '</code></td><td>' +
        esc(s.what) + '</td><td class="num">&times;' + esc(s.factor) +
        '</td><td class="num">' + s.fired + '</td><td class="num">' +
        (share * 100).toFixed(1) + '%</td></tr>';
    }).join('');
    const counts = function (table: Json): string {
      const keys = Object.keys(table || {});
      return keys.length ? keys.map(function (k: string): string {
        return esc(k) + ' ' + table[k];
      }).join(', ') : 'none';
    };
    const d = p ? p.durationMs : { samples: 0 };
    const breach = p ? p.breachedPasswords : null;
    return kit.note('The scoring system measured: what it assessed, how ' +
        'the levels and signals fell, how long it took and what it did. ' +
        'The first sections are counted in the ' + (m.database
          ? 'database, over every node' : 'memory of THIS process (there ' +
            'is no database)') + ' for the realm <code>' + esc(m.realm) +
        '</code>' + (p ? '; <em>This process</em>, at the bottom, is ' +
                         'since this process started' : '') + '. Every ' +
        'person\'s own assessments are on ' +
        '<a href="' + PAGE + '">Monitoring &rarr; Risk</a>; the numbers ' +
        'are also <code>GET /admin-api/risk/metrics</code>.') +
      '<p id="risk-window">Window: ' + windows + '</p>' +
      '<div class="tiles">' +
        kit.tile(a.total, 'assessments') +
        kit.tile(a.subjects, 'people assessed') +
        kit.tile(high, 'HIGH') +
        kit.tile(a.total ? (high / a.total * 100).toFixed(1) + '%' : '—',
                   'of them HIGH') +
        kit.tile(a.meanScore.toPrecision(3), 'mean score') +
        kit.tile(a.bots, 'automated clients') +
        (p ? kit.tile(d.samples ? Math.round(d.p95) + ' ms' : '—',
                        'p95 to assess') : '') +
      '</div>' +
      '<h3>Assessments over time</h3>' + this.timeline(m) +
      '<h3>By level</h3>' +
      this.bars('risk-by-level', 'Level', a.byLevel, a.total, level,
                undefined, LEVELS) +
      '<p><small>MEDIUM from a score of ' + esc(m.thresholds.medium) +
      ', HIGH from ' + esc(m.thresholds.high) + ' (<code>risk.' +
      'mediumScorePercent</code>, <code>risk.highScorePercent</code>). ' +
      (m.enforced ? 'Decisions are ENFORCED.' : 'Development mode: ' +
       'decisions are OBSERVED, not enforced.') + '</small></p>' +
      '<h3>Scores</h3>' +
      this.bars('risk-by-band', 'Score', a.byBand, a.total, undefined,
                undefined, m.bands) +
      '<h3>People by current standing</h3>' +
      this.bars('risk-standings', 'Level', m.standings, people, level,
                undefined, LEVELS) +
      '<h3>Signals</h3><p>Each signal with the factor it multiplies a ' +
      'score by and how often it fired in the window: a signal that fires ' +
      'on most sign-ins, or never, is the first thing to calibrate.</p>' +
      '<table class="grid" id="risk-signals"><thead><tr><th>Signal</th>' +
      '<th>What</th><th>Factor</th><th>Fired</th><th>Of assessments</th>' +
      '</tr></thead><tbody>' + signals + '</tbody></table>' +
      this.calibrationHtml(m) +
      '<h3>Decisions</h3>' +
      this.bars('risk-by-decision', 'Decision', a.byDecision, a.total) +
      '<h3>Doors</h3>' +
      this.bars('risk-by-door', 'Door', a.byDoor, a.total) +
      '<h3>When assessed</h3>' +
      this.bars('risk-by-phase', 'Phase', a.byPhase, a.total) +
      '<h3>Countries</h3>' +
      this.bars('risk-by-country', 'Country', a.byCountry, a.total,
                undefined, 15) +
      '<h3>What people said</h3>' +
      '<p id="risk-feedback">Of the sign-ins in this window, people said ' +
      '<strong>' + a.feedback.confirmed + '</strong> were them and <strong>' +
      a.feedback.denied + '</strong> were NOT, on /portal/sign-ins.</p>' +
      (!p ? '' : '<h3>This process</h3>' +
      '<table class="grid" id="risk-process"><tbody>' +
      '<tr><th>Since</th><td>' + esc(this.when(p.since)) + '</td></tr>' +
      '<tr><th>Assessed</th><td>' + p.assessed + ' (' + p.failed +
      ' could not be assessed and stood unassessed)</td></tr>' +
      '<tr><th>Time to assess</th><td>' + (d.samples
        ? 'mean ' + d.mean.toFixed(1) + ' ms, p50 ' + d.p50 + ', p95 ' +
          d.p95 + ', p99 ' + d.p99 + ', max ' + d.max + ' ms, over the ' +
          'last ' + d.samples : 'nothing assessed yet') + '</td></tr>' +
      '<tr><th>Reactions taken</th><td>' + counts(p.reactions.taken) +
      '</td></tr><tr><th>Observed only</th><td>' +
      counts(p.reactions.observed) + '</td></tr><tr><th>Failed</th><td>' +
      counts(p.reactions.failed) + '</td></tr>' +
      '<tr><th>Live sessions re-checked</th><td>' + p.rescore.runs +
      ' run(s) of <code>risk.rescore</code>, ' + p.rescore.sessions +
      ' session(s) checked, ' + p.rescore.raised + ' raised</td></tr>' +
      '<tr><th>Breached passwords</th><td>' + (breach
        ? (breach.enabled ? 'screening on' : 'screening off') + ': ' +
          breach.screened + ' screened, ' + breach.breached + ' found ' +
          'breached, ' + breach.unanswered + ' unanswered, ' +
          breach.fromCache + ' answered from the cache'
        : 'not loaded in this process') + '</td></tr>' +
      '</tbody></table>');
  }

  // ONE DROP-DOWN OF THE PAIRS THAT GO TOGETHER (#219). A dataset is read
  // from only some formats (`risk_datasets.ts`'s CATALOGUE), and two
  // drop-downs — every dataset beside every format — offered forty-eight
  // combinations of which ten are real, the rest refused only once the form
  // was sent. So each dataset is a group and its options are its own
  // formats; the field is `dataset|format`, which the console's runtime
  // sends as the two fields the operation takes
  // (`ConsoleRuntime.splitJoinedFields()`).
  /**
   * Draws the one drop-down of the valid dataset and format pairs, grouped by
   * dataset.
   *
   * @param view - the page's view: `datasets` (each with its `formats`) and
   *   `formats`
   * @param id - the element's id
   * @returns the labelled select
   */
  static pairSelect(view: Json, id: string): string {
    const formatLabel = RiskPage.formatLabels(view);
    return '<label>Dataset and its format <select name="dataset|format" ' +
      'id="' + kit.esc(id) + '" required>' +
      view.datasets.map(function (d: Json): string {
        return '<optgroup label="' + kit.esc(d.title + ' (' + d.dataset +
                                             ')') + '">' +
          (d.formats || []).map(function (format: string): string {
            return '<option value="' + kit.esc(d.dataset + '|' + format) +
              '">' + kit.esc(d.title + ' — ' +
                             (formatLabel[format] || format)) + '</option>';
          }).join('') + '</optgroup>';
      }).join('') + '</select></label>';
  }

  // A format's name for a person: its id and whose file it is.
  static formatLabels(view: Json): Json {
    const out = {};
    (view.formats || []).forEach(function (f: Json): void {
      out[f.format] = f.format + (f.provider ? ' (' + f.provider + ')' : '');
    });
    return out;
  }

  // WHICH FILE GOES WITH WHICH DATASET (#219), said once above both forms:
  // every pair the drop-down offers, with what the file looks like.
  /**
   * Draws the table of which file format each dataset is read from.
   *
   * @param view - the page's view
   * @returns a collapsible table
   */
  static pairGuide(view: Json): string {
    const byFormat = {};
    (view.formats || []).forEach(function (f: Json): void {
      byFormat[f.format] = f;
    });
    const rows = view.datasets.map(function (d: Json): string {
      return (d.formats || []).map(function (format: string, i: number) {
        const f = byFormat[format] || {};
        return '<tr>' + (i === 0
          ? '<td rowspan="' + d.formats.length + '"><strong>' +
            kit.esc(d.title) + '</strong><br><code>' + kit.esc(d.dataset) +
            '</code>' + (d.perRealm ? '<br><small>a list per realm</small>'
                                    : '') + '</td>'
          : '') + '<td><code>' + kit.esc(format) + '</code></td><td>' +
          kit.esc(f.what || '') + '</td></tr>';
      }).join('');
    }).join('');
    return '<details open><summary>Which file goes with which dataset' +
      '</summary><p>Each dataset is read from the formats listed beside it ' +
      'and no other; the drop-downs below offer only these pairs.</p>' +
      '<table class="grid"><thead><tr><th>Dataset</th><th>Format</th>' +
      '<th>What the file looks like</th></tr></thead><tbody>' + rows +
      '</tbody></table></details>';
  }

  static when(ms: number): string {
    return ms ? new Date(ms).toISOString().replace('.000Z', 'Z') : '—';
  }

  static html(ctx: Json, view: Json): string {
    const self = this;
    // Called for every value drawn, so no Entering/Leaving pair: a hot path,
    // which the code style allows when it says so.
    const esc = function (v: unknown): string {
      return kit.esc(v);
    };
    const canWrite = ctx.write;
    const active = view.datasets.filter(function (d: Json): boolean {
      return d.state === 'active';
    }).length;
    const stale = view.datasets.filter(function (d: Json): boolean {
      return d.state === 'stale';
    }).length;
    const tiles = '<div class="tiles">' +
      kit.tile(String(active), 'datasets active') +
      kit.tile(String(stale), 'stale (counted for nothing)') +
      kit.tile(String(view.failures.total),
                 'refused passwords in ' + view.failures.windowDays + ' days') +
      '</div>';
    const about = kit.note(
      '<p>The external datasets a risk score reads, and the refused ' +
      'passwords it counts (#62). <strong>Nothing here is fetched while ' +
      'anybody signs in</strong>: a dataset arrives as a file, is checked ' +
      '(its SHA-256 where one is named, and a version much smaller than the ' +
      'active one is refused as a likely truncated download), and only then ' +
      'becomes active. A dataset older than its staleness limit counts for ' +
      'nothing and never refuses anybody.</p><p>' + esc(view.store.why) +
      '</p><p>A file of millions of rows is <strong>uploaded</strong> ' +
      'with the first form below — as the provider publishes it, ' +
      '<code>.gz</code>, <code>.zip</code> or plain; it is expanded as it ' +
      'is read and nothing expanded is written to disk — or dropped in ' +
      '<code>risk.datasetsDirectory</code> with a manifest' +
      (view.directory ? ' (now <code>' + esc(view.directory) + '</code>)'
                      : ' (not set)') +
      '. An upload answers as soon as the file is stored: the version ' +
      'shows as <em>loading</em>, then <em>active</em> or <em>refused</em> ' +
      'with its reason — reload this page to follow it. The second form is ' +
      'for a list you can paste.</p>',
      'What this page is');
    const rows = view.datasets.map(function (d: Json): string {
      const versions = d.versions.slice(0, 6).map(function (v: Json): string {
        const controls = !canWrite ? '' :
          ((v.state === 'ready' || v.state === 'superseded')
            ? self.form('activate', d, v.version, 'Activate') : '') +
          (v.state !== 'active' && v.state !== 'loading' &&
           v.state !== 'deleted'
            ? self.form('delete', d, v.version, 'Delete rows') : '');
        return '<tr><td><code>' + esc(v.version) + '</code></td><td>' +
          esc(v.state) + (v.refusal ? '<br><small>' + esc(v.refusal) +
                          '</small>' : '') + '</td><td class="num">' +
          v.rowCount + '</td><td><small>' + esc(v.provider) + ', ' +
          esc(v.licence) + '<br>' + esc(v.source) + ', ' +
          esc(v.verification) + '</small></td><td><small>published ' +
          esc(self.when(v.publishedAt)) + '<br>loaded ' +
          esc(self.when(v.loadedAt)) + '</small></td><td>' + controls +
          '</td></tr>';
      }).join('');
      return '<h3>' + esc(d.title) + ' <small><code>' + esc(d.dataset) +
        '</code>' + (d.perRealm ? ' in realm ' + esc(d.realm) : '') +
        '</small></h3><p>' + esc(d.what) + '</p><p><strong>' +
        esc(d.state) + '</strong>' +
        (d.activeVersion ? ': version <code>' + esc(d.activeVersion) +
                           '</code>, ' + d.rows + ' rows, published ' +
                           esc(self.when(d.publishedAt)) : '') +
        (d.attribution ? '<br><small>' + self.credit(
          view.attributions.filter(function (c: Json): boolean {
            return c.provider === d.provider;
          })[0] || { text: d.attribution, url: d.attributionUrl }) +
                         '</small>' : '') +
        (canWrite && d.previousVersion
          ? ' ' + self.form('rollback', d, '', 'Roll back to ' +
                            d.previousVersion) : '') + '</p>' +
        (versions ? '<table class="grid"><thead><tr><th>Version</th>' +
                    '<th>State</th><th>Rows</th><th>Source</th>' +
                    '<th>When</th><th></th></tr></thead><tbody>' + versions +
                    '</tbody></table>' : '');
    }).join('');
    const lookupForm = '<form method="get" action="' + PAGE + '">' +
      '<input type="hidden" name="realm" value="' + esc(view.realm) + '">' +
      '<label>What do the datasets say about <input type="text" ' +
      'name="address" id="risk-lookup-address" value="' +
      esc(view.lookup ? view.lookup.address : '') + '"></label> ' +
      '<button type="submit" id="risk-lookup">Look up</button></form>' +
      (view.lookup ? '<pre>' + esc(JSON.stringify(view.lookup, null, 2)) +
                     '</pre>' + (view.lookup.attributions || [])
                       .map(function (a: Json): string {
                         return '<p class="attribution"><small>' +
                           self.credit(a) + '</small></p>';
                       }).join('') : '');
    // THE UPLOAD (#215): a real form with a real submit button and no
    // script. Its FIELDS COME BEFORE ITS FILE, and that order is load-bearing:
    // a browser sends the parts in document order, the CSRF token this
    // shell adds is the first of them, and `risk_upload.ts` checks the token
    // and the fields before it writes a byte of the file.
    const uploadForm = !canWrite ? '' :
      self.pairGuide(view) +
      '<h3>Upload a file</h3><form method="post" action="' + UPLOAD +
      '" enctype="multipart/form-data" id="risk-upload-form">' +
      self.pairSelect(view, 'risk-upload-pair') + ' ' + (view.realmOnly
        ? '<input type="hidden" name="realm" value="' + esc(view.realm) +
          '">'
        : '<label>Realm (an operator list only) <input type="text" ' +
          'name="realm" value=""></label>') + '<br>' +
      '<label>Version <input type="text" name="version" ' +
      'placeholder="default: its SHA-256"></label> <label>SHA-256 of the ' +
      'file as sent <input type="text" name="sha256"></label><br>' +
      (view.realmOnly ? '' :
        '<label><input type="checkbox" name="acceptTerms" ' +
        'id="risk-upload-accept"> I have read and accept the provider\'s ' +
        'terms (below), recorded in my name</label><br>') +
      // THE SIGNATURE OVERRIDE, for the FIDO MDS3 BLOB only: FIDO has
      // published BLOBs whose signature does not verify, and this loads one
      // anyway, recorded as `overridden` with the reason, in this
      // administrator's name (`risk_datasets.importMds()`).
      '<label><input type="checkbox" name="overrideSignature" ' +
      'id="risk-upload-override-signature"> FIDO MDS3 only: load the BLOB ' +
      'even if its signature or signing chain does not verify. <strong>Its ' +
      'contents are then unauthenticated</strong>; the version is recorded ' +
      'as <code>overridden</code>, with the reason, in my name</label><br>' +
      '<label>File (<code>.gz</code>, <code>.zip</code> holding one file, ' +
      'or plain text) <input type="file" name="file" id="risk-upload-file" ' +
      'required></label><br><button type="submit" id="risk-upload">' +
      'Upload and import</button></form>';
    const importForm = !canWrite ? '' :
      '<h3>Paste a list</h3><form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="import">' +
      self.pairSelect(view, 'risk-import-pair') + ' ' + (view.realmOnly
        ? '<input type="hidden" name="realm" value="' + esc(view.realm) +
          '">'
        : '<label>Realm (an operator list only) <input type="text" ' +
          'name="realm" value=""></label>') + '<br>' +
      '<label>Version <input type="text" name="version" ' +
      'placeholder="default: its SHA-256"></label> <label>SHA-256 ' +
      '<input type="text" name="sha256"></label><br>' +
      (view.realmOnly ? '' :
        '<label><input type="checkbox" name="acceptTerms" ' +
        'id="risk-import-accept"> I have read and accept the provider\'s ' +
        'terms (below), recorded in my name</label><br>') +
      '<textarea name="content" rows="8" cols="80" id="risk-import-content" ' +
      'placeholder="One address, CIDR block or range per line"></textarea>' +
      '<br><button type="submit" id="risk-import">Import and activate' +
      '</button></form>';
    const failureRows = view.failures.rows.map(function (f: Json): string {
      return '<tr><td><small>' + esc(self.when(f.at)) + '</small></td><td>' +
        (f.subject ? self.whoCell(f)
                   : '<small>' + esc(f.name) + '</small>') + '</td><td>' +
        esc(f.door) + '</td><td><code>' + esc(f.prefix) + '</code>' +
        (f.asn ? '<br><small>AS' + f.asn + '</small>' : '') + '</td><td>' +
        '<code>' + esc(f.errorCode) + '</code></td></tr>';
    }).join('');
    const failures = '<h3>Refused passwords in realm ' + esc(view.realm) +
      ' <small>(last ' + view.failures.windowDays + ' days)</small></h3><p>' +
      esc(view.failures.store.why) + '</p><table class="grid"><thead><tr>' +
      '<th>When</th><th>Who</th><th>Door</th><th>Network</th><th>Code</th>' +
      '</tr></thead><tbody>' +
      (failureRows || '<tr><td colspan="5">None recorded.</td></tr>') +
      '</tbody></table>';
    const providers = '<h3>Whose data, on what terms</h3><p><strong>' +
      esc(view.redistribution) + '</strong> Each provider\'s terms bind ' +
      'the deployment that downloads its data, and some of them bind ' +
      'whoever redistributes it.</p><table class="grid"><thead><tr>' +
      '<th>Provider</th><th>Licence</th><th>Terms</th><th>Accepted</th>' +
      '</tr></thead><tbody>' + view.providers.map(function (p: Json): string {
        const acceptance = !p.supported ? 'not supported'
          : !p.needsAcceptance ? 'nothing to accept'
          : p.accepted ? 'by ' + esc(p.accepted.acceptedBy) + ' through ' +
                         esc(p.accepted.acceptedVia) + '<br><small>' +
                         esc(self.when(p.accepted.acceptedAt)) + ' on ' +
                         esc(p.accepted.deployment) + '</small>'
          : '<strong>' + (p.changed ? 'the terms changed since they were ' +
                                      'accepted' : 'not accepted') +
            '</strong>';
        const form = canWrite && p.needsAcceptance && !p.accepted
          ? '<form method="post" action="' + PAGE + '" class="inline">' +
            '<input type="hidden" name="action" value="accept-terms">' +
            '<input type="hidden" name="provider" value="' + esc(p.provider) +
            '"><button type="submit" id="risk-accept-' + esc(p.provider) +
            '">I have read and accept these terms</button></form>' : '';
        return '<tr><td>' + (p.url ? '<a href="' + esc(p.url) + '">' +
          esc(p.title) + '</a>' : esc(p.title)) + '</td><td>' +
          (p.licenceUrl ? '<a href="' + esc(p.licenceUrl) + '">' +
           esc(p.licence) + '</a>' : esc(p.licence)) + '</td><td><small>' +
          esc(p.terms) + '</small></td><td>' + acceptance + form +
          '</td></tr>';
      }).join('') + '</tbody></table>';
    // EVERY PROVIDER WHOSE DATA AN ACTIVE DATASET HOLDS, credited under
    // everything on this page — the failures' networks and the assessments'
    // locations included — as CC BY 4.0 and CC BY-SA 4.0 ask.
    const credits = view.attributions.length
      ? '<h3>Data credits</h3>' + view.attributions.map(function (c: Json) {
          return '<p class="attribution"><small>' + self.credit(c) +
            '</small></p>';
        }).join('') : '';
    const assessments = this.assessmentsHtml(ctx, view);
    if (view.realmOnly) {
      return tiles + kit.note('This is the <code>' + esc(view.realm) +
        '</code> realm\'s risk: its assessments, its people\'s standings, ' +
        'its operator allow and deny lists and its refused passwords. The ' +
        'datasets every realm shares — geolocation, networks, Tor exits, ' +
        'reputation, security-key metadata — their providers\' terms and ' +
        'the <code>risk.</code> settings are the whole service\'s, and a ' +
        'service administrator manages them.', 'What this page is') +
        assessments + '<h3>Look up an address</h3>' + lookupForm + rows +
        uploadForm + importForm + failures + credits;
    }
    return tiles + about + assessments + '<h3>Look up an address</h3>' +
      lookupForm + rows + uploadForm + importForm + providers + failures +
      credits +
      '<h2>Settings</h2>' + SettingsForms.forms(view.settings, PAGE);
  }

  // ---------------------------------------------------------------------------
  // THE ASSESSMENTS (#62 P2): every sign-in scored in the last week, newest
  // first, with what went in and what came out — and the people by current
  // standing. The Decision column is what the issuance policy decided on
  // the assessment (#62 P3): permit, step-up, refuse, or `observe:` one of
  // those where development set it aside; `observe` alone for a sign-in
  // assessed after its session.
  // The providers whose data a row shows are credited under the table, as
  // DB-IP's licence asks of every page that displays its results.
  // ---------------------------------------------------------------------------
  static assessmentsHtml(ctx: Json, view: Json): string {
    const self = this;
    // Each pager carries every other parameter (the realm, the level, the
    // person, the other list's page) so the reader keeps their place.
    const params = kit.pageParamsOf(ctx.query);
    const assessmentsNav = kit.pageNavPair(PAGE, params,
                                             view.assessmentsPaging);
    const subjectsNav = kit.pageNavPair(PAGE, params,
                                          view.subjectsPaging);
    // Called for every value drawn: a hot path, with no Entering/Leaving.
    const esc = function (v: unknown): string {
      return kit.esc(v);
    };
    const credits = new Map<string, Json>();
    const rows = view.assessments.rows.map(function (a: Json): string {
      ((a.datasets && a.datasets.attributions) || [])
        .forEach(function (c: Json): void {
          credits.set(c.provider || c.text, c);
        });
      const signals = (a.signals || []).filter(function (x: Json): boolean {
        return x.signal !== 'model';
      }).map(function (x: Json): string {
        return esc(x.signal) + ' ×' + esc(x.factor);
      }).join(', ');
      // THE REGISTERED DEVICE (#164 phase 5), from the model's row: its id
      // linked to its page, how it was recognised, and what the register
      // said of it at the sign-in.
      const modelRow = (a.signals || []).filter(function (x: Json) {
        return x.signal === 'model';
      })[0] || {};
      const dev = modelRow.device;
      const deviceCell = dev ? '<br>registered device <a href="' +
        esc('/admin/devices?device=' + encodeURIComponent(dev.id)) +
        '"><code>' + esc(String(dev.id).slice(0, 8)) + '</code></a> (' +
        esc(dev.via) + ', ' + esc(dev.compliance) + ', ' +
        esc(dev.attestation) + (dev.status === 'compromised'
          ? ', <strong>compromised</strong>' : '') +
        (dev.own ? '' : ', not theirs') + ')' : '';
      return '<tr><td><small>' + esc(self.when(a.at)) + '</small></td><td>' +
        self.whoCell(a) + '<br><small>' + esc(a.door) +
        '</small></td><td><code>' + esc(a.addressPrefix) + '</code>' +
        (a.asn ? '<br><small>AS' + a.asn + ' ' + esc(a.asOrg) + '</small>'
               : '') + (a.country ? '<br><small>' + esc(a.city ? a.city +
                                                     ', ' : '') +
                                    esc(a.country) + '</small>' : '') +
        '</td><td><small>' + esc([a.uaFamily, a.uaOs, a.uaPlatform]
          .filter(Boolean).join(' / ') || '—') +
        (a.bot ? ' (automated)' : '') + '<br>' + esc(a.credentialKind) +
        deviceCell + '</small></td><td class="num">' +
        esc(Number(a.score).toPrecision(3)) + '</td><td><strong>' +
        esc(a.level) + '</strong></td><td><small>' + (signals || '—') +
        '</small></td><td>' + esc(a.decision) +
        // What the person said about it on /portal/sign-ins (#62 P6).
        (a.feedback ? '<br><small>' + (a.feedback === 'denied'
          ? '<strong>not them</strong>' : 'confirmed by them') + '</small>'
          : '') + '</td></tr>';
    }).join('');
    const people = view.subjects.map(function (p: Json): string {
      return '<tr><td>' + self.whoCell(p) + '</td><td>' +
        '<strong>' + esc(p.level) + '</strong>' +
        (p.previousLevel && p.previousLevel !== p.level
          ? ' <small>(was ' + esc(p.previousLevel) + ')</small>' : '') +
        '</td><td class="num">' + esc(Number(p.score).toPrecision(3)) +
        '</td><td><small>' + esc(p.reason) + '</small></td><td><small>' +
        esc(self.when(p.updatedAt)) + '</small></td></tr>';
    }).join('');
    let credit = '';
    credits.forEach(function (c: Json): void {
      credit += '<p class="attribution"><small>' + self.credit(c) +
        '</small></p>';
    });
    return '<h3>Sign-ins assessed <small>(the last 7 days, and what the ' +
      'issuance policy decided)</small></h3><p>' + (view.assessmentsInDatabase
        ? 'Held in the database.'
        : 'Held in this process: there is no database with a key to seal ' +
          'them under.') + ' ' + view.assessments.total +
      ' assessment(s).</p>' + assessmentsNav.head +
      '<table class="grid" id="risk-assessments"><thead>' +
      '<tr><th>When</th><th>Who</th><th>Network</th><th>Device</th>' +
      '<th>Score</th><th>Level</th><th>Signals</th><th>Decision</th></tr>' +
      '</thead><tbody>' + (rows || '<tr><td colspan="8">None yet.</td></tr>') +
      '</tbody></table>' + assessmentsNav.foot + credit +
      '<h3>People by current standing</h3>' + subjectsNav.head +
      '<table class="grid" id="risk-subjects"><thead><tr><th>Who</th>' +
      '<th>Level</th><th>Score</th><th>Why</th><th>Updated</th></tr>' +
      '</thead><tbody>' + (people || '<tr><td colspan="5">None yet.</td>' +
                          '</tr>') + '</tbody></table>' + subjectsNav.foot;
  }

  // A provider's credit as its licence asks (`risk_terms.attributionOf()`):
  // the attribution LINKED to the source, the licence named and linked, and
  // that the data was modified here — CC BY 4.0 section 3(a), which DB-IP's
  // licence asks for on every page that displays its results.
  static credit(c: Json): string {
    const esc = kit.esc.bind(kit);
    const source = c.url ? '<a href="' + esc(c.url) + '" rel="noopener">' +
      esc(c.text) + '</a>' : esc(c.text);
    const licence = c.licence ? ', licensed under ' + (c.licenceUrl
      ? '<a href="' + esc(c.licenceUrl) + '" rel="noopener">' +
        esc(c.licence) + '</a>' : esc(c.licence)) : '';
    return source + licence + (c.modified ? '; ' + esc(c.modified) : '') +
      '.';
  }

  // One small POST form: an action on one dataset (and version).
  static form(action: string, d: Json, version: string,
               label: string): string {
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="dataset" value="' + kit.esc(d.dataset) +
      '"><input type="hidden" name="realm" value="' + kit.esc(d.realm) +
      '"><input type="hidden" name="version" value="' + kit.esc(version) +
      '"><button type="submit" id="risk-' + action + '-' +
      kit.esc(d.dataset).replace(/[^a-z0-9]/gi, '-') +
      (version ? '-' + kit.esc(version).replace(/[^a-z0-9]/gi, '-') : '') +
      '">' + kit.esc(label) + '</button></form>';
  }
}

export = RiskPage;
