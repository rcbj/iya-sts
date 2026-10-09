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
  static whoCell(row: Json, t: Json): string {
    const subject = '<code>' + kit.esc(row.subject) + '</code>';
    if (!row.username) {
      return subject + '<br><small>' + t.html('consoleRisk.noEntry') +
        '</small>';
    }
    const link = row.userHref;
    return '<a href="' + kit.esc(link) + '"><strong>' +
      kit.esc(row.username) + '</strong></a><br><small>' + subject +
      '</small>';
  }

  // One table of counts with a bar each, largest first. `colour` gives a
  // row's bar colour; `limit` keeps the longest tables short.
  static bars(t: Json, id: string, head: string, counts: Json, total: number,
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
      return '<tr><td>' + esc(k || t.text('consoleRisk.none')) +
        '</td><td class="num">' + n +
        '</td><td class="num">' + (share * 100).toFixed(1) + '%</td>' +
        '<td style="width:45%"><div style="height:12px;border-radius:3px;' +
        'width:' + Math.max(share * 100, n ? 0.5 : 0).toFixed(1) + '%;' +
        'background:' + (colour ? colour(k) : '#1a73e8') + '"></div></td>' +
        '</tr>';
    }).join('');
    return '<table class="grid" id="' + id + '"><thead><tr><th>' +
      esc(head) + '</th><th>' + t.html('consoleRisk.th.count') + '</th><th>' +
      t.html('consoleRisk.th.share') + '</th><th></th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="4">' +
                           t.html('consoleRisk.noneInWindow') + '</td>' +
                           '</tr>') + '</tbody></table>' +
      (limit && keys.length > limit ? '<p><small>' +
       t.html('consoleRisk.moreNotShown', { n: keys.length - limit }) +
       '</small></p>' : '');
  }

  // The levels over time: a column per bucket, stacked by level, drawn as
  // markup — no script, for the reason the console has none.
  static timeline(m: Json, t: Json): string {
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
      const title = t.text('consoleRisk.timeline.column',
                           { at: stamp(c.at), n: Number(c.total) || 0 }) +
        LEVELS.filter(function (l: string): boolean {
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
      t.html('consoleRisk.timeline.caption', {
        from: stamp(first), bucket: RiskPage.duration(m.bucketMs, t),
        peak: peak }) + legend + '</small></p>';
  }

  // A duration in the largest unit that divides it.
  /**
   * Says a duration in the largest unit that divides it.
   *
   * @param ms - the duration in milliseconds
   * @param t - the page's translator (#539)
   * @returns the duration as text
   */
  static duration(ms: number, t: Json): string {
    if (ms % 86400000 === 0) {
      return t.text('consoleRisk.duration.days', { n: ms / 86400000 });
    }
    if (ms % 3600000 === 0) {
      return t.text('consoleRisk.duration.hours', { n: ms / 3600000 });
    }
    return t.text('consoleRisk.duration.minutes', { n: ms / 60000 });
  }

  // THE CALIBRATION REPORT (`RiskEngine.calibrate()`): advice, drawn beside
  // what is set now, with the setting that would apply it named.
  static calibrationHtml(m: Json, t: Json): string {
    const esc = kit.esc.bind(kit);
    const c = m.calibration;
    const pct = function (x: number): string {
      return (x * 100).toFixed(1) + '%';
    };
    // The threshold is `th`, not `t` as it was: `t` is the translator
    // (#539).
    const threshold = function (name: string, th: Json, key: string): string {
      return '<tr><td>' + name + '</td><td class="num">' + esc(th.current) +
        '</td><td class="num">' + pct(th.share) + '</td><td class="num">' +
        pct(th.target) + '</td><td class="num">' + (th.suggested === null
          ? '<small>' + t.html('consoleRisk.calibration.fewer',
                               { n: c.minimums.assessments }) +
            '</small>'
          : esc(Number(th.suggested).toPrecision(3)) + ' <small>(<code>' +
            key + '</code> = ' + Math.max(1, Math.round(th.suggested * 100)) +
            ')</small>') + '</td></tr>';
    };
    const rows = c.signals.map(function (s: Json): string {
      return '<tr><td><code>' + esc(s.signal) + '</code></td>' +
        '<td class="num">&times;' + esc(s.factor) +
        (s.factor !== s.builtIn ? ' <small>' +
                                  t.html('consoleRisk.calibration.builtIn',
                                         { factor: s.builtIn }) +
                                  '</small>' : '') +
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
    return '<h3 id="risk-calibration">' +
      t.html('consoleRisk.calibration.heading') + '</h3><p>' +
      t.html('consoleRisk.calibration.note',
             { rate: pct(c.notMeRate), answered: c.answered }) +
      '</p><table class="grid" id="risk-calibration-thresholds"><thead><tr>' +
      '<th>' + t.html('consoleRisk.th.level') + '</th><th>' +
      t.html('consoleRisk.th.fromScore') + '</th><th>' +
      t.html('consoleRisk.th.shareNow') + '</th><th>' +
      t.html('consoleRisk.th.target') + '</th>' +
      '<th>' + t.html('consoleRisk.th.suggested') + '</th></tr></thead>' +
      '<tbody>' +
      threshold(t.html('consoleRisk.calibration.mediumOrWorse'),
                c.thresholds.medium, 'risk.mediumScorePercent') +
      threshold('HIGH', c.thresholds.high, 'risk.highScorePercent') +
      '</tbody></table><table class="grid" id="risk-calibration-signals">' +
      '<thead><tr><th>' + t.html('consoleRisk.th.signal') + '</th><th>' +
      t.html('consoleRisk.th.factor') + '</th><th>' +
      t.html('consoleRisk.th.fired') + '</th>' +
      '<th>' + t.html('consoleRisk.th.endedHigh') + '</th><th>' +
      t.html('consoleRisk.th.answered') + '</th><th>' +
      t.html('consoleRisk.th.notMe') + '</th>' +
      '<th>' + t.html('consoleRisk.th.suggestion') + '</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table>' +
      // The code element carries an id, which a message cannot, so the
      // sentence is drawn around it (#539).
      (suggested.length ? '<p>' +
        t.html('consoleRisk.calibration.applyBefore') +
        '<code id="risk-calibration-apply">' +
        esc(suggested.join(',')) + '</code>' +
        t.html('consoleRisk.calibration.applyAfter') + '</p>'
        : '') +
      (c.invalidFactors.length ? '<div class="err">risk.signalFactors ' +
        'entries ignored (STS-RISK-0026): ' +
        esc(c.invalidFactors.join(', ')) + '</div>' : '');
  }

  // `ctx` is optional: the console's page table calls this with the view
  // alone, and then the default translator draws it (#539).
  static metricsHtml(m: Json, ctx?: Json): string {
    const t = (ctx || kit.context()).t;
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
      }).join(', ') : t.html('consoleRisk.metrics.none');
    };
    const d = p ? p.durationMs : { samples: 0 };
    const breach = p ? p.breachedPasswords : null;
    // The link is markup a message cannot carry, so the note is drawn
    // around it (#539).
    return kit.note(t.html('consoleRisk.metrics.noteBefore', {
        where: m.database ? 'database' : 'memory', realm: m.realm,
        process: p ? 'yes' : 'no' }) +
        '<a href="' + PAGE + '">' + t.html('consoleRisk.link.risk') +
        '</a>' + t.html('consoleRisk.metrics.noteAfter')) +
      '<p id="risk-window">' + t.html('consoleRisk.metrics.window') + ' ' +
      windows + '</p>' +
      '<div class="tiles">' +
        kit.tile(a.total, t.text('consoleRisk.tile.assessments')) +
        kit.tile(a.subjects, t.text('consoleRisk.tile.peopleAssessed')) +
        kit.tile(high, 'HIGH') +
        kit.tile(a.total ? (high / a.total * 100).toFixed(1) + '%' : '—',
                   t.text('consoleRisk.tile.ofThemHigh')) +
        kit.tile(a.meanScore.toPrecision(3),
                 t.text('consoleRisk.tile.meanScore')) +
        kit.tile(a.bots, t.text('consoleRisk.tile.bots')) +
        (p ? kit.tile(d.samples ? Math.round(d.p95) + ' ms' : '—',
                        t.text('consoleRisk.tile.p95')) : '') +
      '</div>' +
      '<h3>' + t.html('consoleRisk.metrics.overTime') + '</h3>' +
      this.timeline(m, t) +
      '<h3>' + t.html('consoleRisk.metrics.byLevel') + '</h3>' +
      this.bars(t, 'risk-by-level', t.text('consoleRisk.th.level'),
                a.byLevel, a.total, level, undefined, LEVELS) +
      '<p><small>' + t.html('consoleRisk.metrics.thresholds', {
        medium: m.thresholds.medium, high: m.thresholds.high }) + ' ' +
      (m.enforced ? t.html('consoleRisk.metrics.enforced')
        : t.html('consoleRisk.metrics.observed')) + '</small></p>' +
      '<h3>' + t.html('consoleRisk.metrics.scores') + '</h3>' +
      this.bars(t, 'risk-by-band', t.text('consoleRisk.th.score'), a.byBand,
                a.total, undefined, undefined, m.bands) +
      '<h3>' + t.html('consoleRisk.standings.heading') + '</h3>' +
      this.bars(t, 'risk-standings', t.text('consoleRisk.th.level'),
                m.standings, people, level, undefined, LEVELS) +
      '<h3>' + t.html('consoleRisk.metrics.signals') + '</h3><p>' +
      t.html('consoleRisk.metrics.signalsNote') + '</p>' +
      '<table class="grid" id="risk-signals"><thead><tr><th>' +
      t.html('consoleRisk.th.signal') + '</th>' +
      '<th>' + t.html('consoleRisk.th.what') + '</th><th>' +
      t.html('consoleRisk.th.factor') + '</th><th>' +
      t.html('consoleRisk.th.fired') + '</th><th>' +
      t.html('consoleRisk.th.ofAssessments') + '</th>' +
      '</tr></thead><tbody>' + signals + '</tbody></table>' +
      this.calibrationHtml(m, t) +
      '<h3>' + t.html('consoleRisk.metrics.decisions') + '</h3>' +
      this.bars(t, 'risk-by-decision', t.text('consoleRisk.th.decision'),
                a.byDecision, a.total) +
      '<h3>' + t.html('consoleRisk.metrics.doors') + '</h3>' +
      this.bars(t, 'risk-by-door', t.text('consoleRisk.th.door'), a.byDoor,
                a.total) +
      '<h3>' + t.html('consoleRisk.metrics.whenAssessed') + '</h3>' +
      this.bars(t, 'risk-by-phase', t.text('consoleRisk.th.phase'),
                a.byPhase, a.total) +
      '<h3>' + t.html('consoleRisk.metrics.countries') + '</h3>' +
      this.bars(t, 'risk-by-country', t.text('consoleRisk.th.country'),
                a.byCountry, a.total, undefined, 15) +
      '<h3>' + t.html('consoleRisk.metrics.said') + '</h3>' +
      '<p id="risk-feedback">' + t.html('consoleRisk.metrics.saidText', {
        confirmed: a.feedback.confirmed, denied: a.feedback.denied }) +
      '</p>' +
      (!p ? '' : '<h3>' + t.html('consoleRisk.process.heading') + '</h3>' +
      '<table class="grid" id="risk-process"><tbody>' +
      '<tr><th>' + t.html('consoleRisk.process.since') + '</th><td>' +
      esc(this.when(p.since)) + '</td></tr>' +
      '<tr><th>' + t.html('consoleRisk.process.assessed') + '</th><td>' +
      t.html('consoleRisk.process.assessedText',
             { n: p.assessed, failed: p.failed }) + '</td></tr>' +
      '<tr><th>' + t.html('consoleRisk.process.time') + '</th><td>' +
      (d.samples
        ? t.html('consoleRisk.process.timeText', {
          mean: d.mean.toFixed(1), p50: d.p50, p95: d.p95, p99: d.p99,
          max: d.max, n: d.samples })
        : t.html('consoleRisk.process.nothingAssessed')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleRisk.process.taken') + '</th><td>' +
      counts(p.reactions.taken) +
      '</td></tr><tr><th>' + t.html('consoleRisk.process.observed') +
      '</th><td>' +
      counts(p.reactions.observed) + '</td></tr><tr><th>' +
      t.html('consoleRisk.process.failed') + '</th><td>' +
      counts(p.reactions.failed) + '</td></tr>' +
      '<tr><th>' + t.html('consoleRisk.process.rechecked') + '</th><td>' +
      t.html('consoleRisk.process.rescoreText', {
        runs: p.rescore.runs, sessions: p.rescore.sessions,
        raised: p.rescore.raised }) + '</td></tr>' +
      '<tr><th>' + t.html('consoleRisk.process.breached') + '</th><td>' +
      (breach
        ? t.html('consoleRisk.process.breachText', {
          on: breach.enabled ? 'yes' : 'no', screened: breach.screened,
          breached: breach.breached, unanswered: breach.unanswered,
          cache: breach.fromCache })
        : t.html('consoleRisk.process.breachNotLoaded')) + '</td></tr>' +
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
   * @param t - the page's translator (#539)
   * @returns the labelled select
   */
  static pairSelect(view: Json, id: string, t: Json): string {
    const formatLabel = RiskPage.formatLabels(view);
    return '<label>' + t.html('consoleRisk.pair.label') +
      ' <select name="dataset|format" ' +
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
   * @param t - the page's translator (#539)
   * @returns a collapsible table
   */
  static pairGuide(view: Json, t: Json): string {
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
            '</code>' + (d.perRealm ? '<br><small>' +
                                      t.html('consoleRisk.pair.perRealm') +
                                      '</small>'
                                    : '') + '</td>'
          : '') + '<td><code>' + kit.esc(format) + '</code></td><td>' +
          kit.esc(f.what || '') + '</td></tr>';
      }).join('');
    }).join('');
    return '<details open><summary>' + t.html('consoleRisk.pair.summary') +
      '</summary><p>' + t.html('consoleRisk.pair.note') + '</p>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleRisk.th.dataset') + '</th><th>' +
      t.html('consoleRisk.th.format') + '</th>' +
      '<th>' + t.html('consoleRisk.th.fileLooks') + '</th></tr></thead>' +
      '<tbody>' + rows +
      '</tbody></table></details>';
  }

  static when(ms: number): string {
    return ms ? new Date(ms).toISOString().replace('.000Z', 'Z') : '—';
  }

  static html(ctx: Json, view: Json): string {
    const t = ctx.t;
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
      kit.tile(String(active), t.text('consoleRisk.tile.active')) +
      kit.tile(String(stale), t.text('consoleRisk.tile.stale')) +
      kit.tile(String(view.failures.total),
                 t.text('consoleRisk.tile.refused',
                        { days: view.failures.windowDays })) +
      '</div>';
    const about = kit.note(
      '<p>' + t.html('consoleRisk.about.datasets') + '</p><p>' +
      esc(view.store.why) +
      '</p><p>' + t.html('consoleRisk.about.upload', {
        set: view.directory ? 'yes' : 'no', directory: view.directory }) +
      '</p>',
      t.text('consoleRisk.about.label'));
    const rows = view.datasets.map(function (d: Json): string {
      const versions = d.versions.slice(0, 6).map(function (v: Json): string {
        const controls = !canWrite ? '' :
          ((v.state === 'ready' || v.state === 'superseded')
            ? self.form('activate', d, v.version,
                        t.text('consoleRisk.dataset.activate')) : '') +
          (v.state !== 'active' && v.state !== 'loading' &&
           v.state !== 'deleted'
            ? self.form('delete', d, v.version,
                        t.text('consoleRisk.dataset.deleteRows')) : '');
        return '<tr><td><code>' + esc(v.version) + '</code></td><td>' +
          esc(v.state) + (v.refusal ? '<br><small>' + esc(v.refusal) +
                          '</small>' : '') + '</td><td class="num">' +
          v.rowCount + '</td><td><small>' + esc(v.provider) + ', ' +
          esc(v.licence) + '<br>' + esc(v.source) + ', ' +
          esc(v.verification) + '</small></td><td><small>' +
          t.html('consoleRisk.dataset.published',
                 { at: self.when(v.publishedAt) }) + '<br>' +
          t.html('consoleRisk.dataset.loaded',
                 { at: self.when(v.loadedAt) }) +
          '</small></td><td>' + controls +
          '</td></tr>';
      }).join('');
      return '<h3>' + esc(d.title) + ' <small><code>' + esc(d.dataset) +
        '</code>' + (d.perRealm
          ? t.html('consoleRisk.dataset.inRealm', { realm: d.realm }) : '') +
        '</small></h3><p>' + esc(d.what) + '</p><p><strong>' +
        esc(d.state) + '</strong>' +
        (d.activeVersion
          ? t.html('consoleRisk.dataset.activeVersion', {
            version: d.activeVersion, rows: d.rows,
            at: self.when(d.publishedAt) }) : '') +
        (d.attribution ? '<br><small>' + self.credit(
          view.attributions.filter(function (c: Json): boolean {
            return c.provider === d.provider;
          })[0] || { text: d.attribution, url: d.attributionUrl }, t) +
                         '</small>' : '') +
        (canWrite && d.previousVersion
          ? ' ' + self.form('rollback', d, '',
                            t.text('consoleRisk.dataset.rollBack',
                                   { version: d.previousVersion })) : '') +
        '</p>' +
        (versions ? '<table class="grid"><thead><tr><th>' +
                    t.html('consoleRisk.th.version') + '</th>' +
                    '<th>' + t.html('consoleRisk.th.state') + '</th><th>' +
                    t.html('consoleRisk.th.rows') + '</th><th>' +
                    t.html('consoleRisk.th.source') + '</th>' +
                    '<th>' + t.html('consoleRisk.th.when') +
                    '</th><th></th></tr></thead><tbody>' + versions +
                    '</tbody></table>' : '');
    }).join('');
    const lookupForm = '<form method="get" action="' + PAGE + '">' +
      '<input type="hidden" name="realm" value="' + esc(view.realm) + '">' +
      '<label>' + t.html('consoleRisk.lookup.label') +
      ' <input type="text" ' +
      'name="address" id="risk-lookup-address" value="' +
      esc(view.lookup ? view.lookup.address : '') + '"></label> ' +
      '<button type="submit" id="risk-lookup">' +
      t.html('consoleRisk.lookup.button') + '</button></form>' +
      (view.lookup ? '<pre>' + esc(JSON.stringify(view.lookup, null, 2)) +
                     '</pre>' + (view.lookup.attributions || [])
                       .map(function (a: Json): string {
                         return '<p class="attribution"><small>' +
                           self.credit(a, t) + '</small></p>';
                       }).join('') : '');
    // THE UPLOAD (#215): a real form with a real submit button and no
    // script. Its FIELDS COME BEFORE ITS FILE, and that order is load-bearing:
    // a browser sends the parts in document order, the CSRF token this
    // shell adds is the first of them, and `risk_upload.ts` checks the token
    // and the fields before it writes a byte of the file.
    const uploadForm = !canWrite ? '' :
      self.pairGuide(view, t) +
      '<h3>' + t.html('consoleRisk.upload.heading') +
      '</h3><form method="post" action="' + UPLOAD +
      '" enctype="multipart/form-data" id="risk-upload-form">' +
      self.pairSelect(view, 'risk-upload-pair', t) + ' ' + (view.realmOnly
        ? '<input type="hidden" name="realm" value="' + esc(view.realm) +
          '">'
        : '<label>' + t.html('consoleRisk.form.realm') +
          ' <input type="text" ' +
          'name="realm" value=""></label>') + '<br>' +
      '<label>' + t.html('consoleRisk.form.version') +
      ' <input type="text" name="version" ' +
      'placeholder="' + esc(t.text('consoleRisk.form.versionPlaceholder')) +
      '"></label> <label>' + t.html('consoleRisk.upload.sha256') +
      ' <input type="text" name="sha256"></label><br>' +
      (view.realmOnly ? '' :
        '<label><input type="checkbox" name="acceptTerms" ' +
        'id="risk-upload-accept"> ' + t.html('consoleRisk.form.acceptTerms') +
        '</label><br>') +
      // THE SIGNATURE OVERRIDE, for the FIDO MDS3 BLOB only: FIDO has
      // published BLOBs whose signature does not verify, and this loads one
      // anyway, recorded as `overridden` with the reason, in this
      // administrator's name (`risk_datasets.importMds()`).
      '<label><input type="checkbox" name="overrideSignature" ' +
      'id="risk-upload-override-signature"> ' +
      t.html('consoleRisk.upload.override') + '</label><br>' +
      '<label>' + t.html('consoleRisk.upload.file') +
      ' <input type="file" name="file" id="risk-upload-file" ' +
      'required></label><br><button type="submit" id="risk-upload">' +
      t.html('consoleRisk.upload.button') + '</button></form>';
    const importForm = !canWrite ? '' :
      '<h3>' + t.html('consoleRisk.paste.heading') +
      '</h3><form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="import">' +
      self.pairSelect(view, 'risk-import-pair', t) + ' ' + (view.realmOnly
        ? '<input type="hidden" name="realm" value="' + esc(view.realm) +
          '">'
        : '<label>' + t.html('consoleRisk.form.realm') +
          ' <input type="text" ' +
          'name="realm" value=""></label>') + '<br>' +
      '<label>' + t.html('consoleRisk.form.version') +
      ' <input type="text" name="version" ' +
      'placeholder="' + esc(t.text('consoleRisk.form.versionPlaceholder')) +
      '"></label> <label>SHA-256 ' +
      '<input type="text" name="sha256"></label><br>' +
      (view.realmOnly ? '' :
        '<label><input type="checkbox" name="acceptTerms" ' +
        'id="risk-import-accept"> ' + t.html('consoleRisk.form.acceptTerms') +
        '</label><br>') +
      '<textarea name="content" rows="8" cols="80" id="risk-import-content" ' +
      'placeholder="' + esc(t.text('consoleRisk.paste.placeholder')) +
      '"></textarea>' +
      '<br><button type="submit" id="risk-import">' +
      t.html('consoleRisk.paste.button') +
      '</button></form>';
    const failureRows = view.failures.rows.map(function (f: Json): string {
      return '<tr><td><small>' + esc(self.when(f.at)) + '</small></td><td>' +
        (f.subject ? self.whoCell(f, t)
                   : '<small>' + esc(f.name) + '</small>') + '</td><td>' +
        esc(f.door) + '</td><td><code>' + esc(f.prefix) + '</code>' +
        (f.asn ? '<br><small>AS' + f.asn + '</small>' : '') + '</td><td>' +
        '<code>' + esc(f.errorCode) + '</code></td></tr>';
    }).join('');
    const failures = '<h3>' + t.html('consoleRisk.failures.heading', {
        realm: view.realm }) +
      ' <small>' + t.html('consoleRisk.failures.lastDays',
                          { days: view.failures.windowDays }) +
      '</small></h3><p>' +
      esc(view.failures.store.why) + '</p><table class="grid"><thead><tr>' +
      '<th>' + t.html('consoleRisk.th.when') + '</th><th>' +
      t.html('consoleRisk.th.who') + '</th><th>' +
      t.html('consoleRisk.th.door') + '</th><th>' +
      t.html('consoleRisk.th.network') + '</th><th>' +
      t.html('consoleRisk.th.code') + '</th>' +
      '</tr></thead><tbody>' +
      (failureRows || '<tr><td colspan="5">' +
       t.html('consoleRisk.failures.none') + '</td></tr>') +
      '</tbody></table>';
    const providers = '<h3>' + t.html('consoleRisk.providers.heading') +
      '</h3><p><strong>' +
      esc(view.redistribution) + '</strong> ' +
      t.html('consoleRisk.providers.note') +
      '</p><table class="grid"><thead><tr>' +
      '<th>' + t.html('consoleRisk.th.provider') + '</th><th>' +
      t.html('consoleRisk.th.licence') + '</th><th>' +
      t.html('consoleRisk.th.terms') + '</th><th>' +
      t.html('consoleRisk.th.accepted') + '</th>' +
      '</tr></thead><tbody>' + view.providers.map(function (p: Json): string {
        const acceptance = !p.supported
          ? t.html('consoleRisk.providers.notSupported')
          : !p.needsAcceptance
            ? t.html('consoleRisk.providers.nothingToAccept')
          : p.accepted ? t.html('consoleRisk.providers.acceptedBy', {
            by: p.accepted.acceptedBy, via: p.accepted.acceptedVia }) +
                         '<br><small>' +
                         t.html('consoleRisk.providers.acceptedOn', {
                           at: self.when(p.accepted.acceptedAt),
                           deployment: p.accepted.deployment }) + '</small>'
          : '<strong>' + (p.changed
            ? t.html('consoleRisk.providers.changed')
            : t.html('consoleRisk.providers.notAccepted')) +
            '</strong>';
        const form = canWrite && p.needsAcceptance && !p.accepted
          ? '<form method="post" action="' + PAGE + '" class="inline">' +
            '<input type="hidden" name="action" value="accept-terms">' +
            '<input type="hidden" name="provider" value="' + esc(p.provider) +
            '"><button type="submit" id="risk-accept-' + esc(p.provider) +
            '">' + t.html('consoleRisk.providers.acceptButton') +
            '</button></form>' : '';
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
      ? '<h3>' + t.html('consoleRisk.credits.heading') + '</h3>' +
        view.attributions.map(function (c: Json) {
          return '<p class="attribution"><small>' + self.credit(c, t) +
            '</small></p>';
        }).join('') : '';
    const assessments = this.assessmentsHtml(ctx, view);
    if (view.realmOnly) {
      return tiles + kit.note(t.html('consoleRisk.about.realmOnly',
                                     { realm: view.realm }),
                              t.text('consoleRisk.about.label')) +
        assessments + '<h3>' + t.html('consoleRisk.lookup.heading') +
        '</h3>' + lookupForm + rows +
        uploadForm + importForm + failures + credits;
    }
    return tiles + about + assessments + '<h3>' +
      t.html('consoleRisk.lookup.heading') + '</h3>' +
      lookupForm + rows + uploadForm + importForm + providers + failures +
      credits +
      '<h2>' + t.html('consoleRisk.settings.heading') + '</h2>' +
      SettingsForms.forms(view.settings, PAGE, undefined, t);
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
    const t = ctx.t;
    const self = this;
    // Each pager carries every other parameter (the realm, the level, the
    // person, the other list's page) so the reader keeps their place.
    const params = kit.pageParamsOf(ctx.query);
    const assessmentsNav = kit.pageNavPair(PAGE, params,
                                             view.assessmentsPaging, t);
    const subjectsNav = kit.pageNavPair(PAGE, params,
                                          view.subjectsPaging, t);
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
      const model = RiskPage.modelCell(modelRow, t);
      const dev = modelRow.device;
      const deviceCell = dev ? '<br>' +
        t.html('consoleRisk.device.registered') + ' <a href="' +
        esc('/admin/devices?device=' + encodeURIComponent(dev.id)) +
        '"><code>' + esc(String(dev.id).slice(0, 8)) + '</code></a> (' +
        esc(dev.via) + ', ' + esc(dev.compliance) + ', ' +
        esc(dev.attestation) + (dev.status === 'compromised'
          ? t.html('consoleRisk.device.compromised') : '') +
        (dev.own ? '' : t.html('consoleRisk.device.notTheirs')) + ')' : '';
      return '<tr><td><small>' + esc(self.when(a.at)) + '</small></td><td>' +
        self.whoCell(a, t) + '<br><small>' + esc(a.door) +
        '</small></td><td><code>' + esc(a.addressPrefix) + '</code>' +
        (a.asn ? '<br><small>AS' + a.asn + ' ' + esc(a.asOrg) + '</small>'
               : '') + (a.country ? '<br><small>' + esc(a.city ? a.city +
                                                     ', ' : '') +
                                    esc(a.country) + '</small>' : '') +
        '</td><td><small>' + esc([a.uaFamily, a.uaOs, a.uaPlatform]
          .filter(Boolean).join(' / ') || '—') +
        (a.bot ? t.html('consoleRisk.assessment.automated') : '') + '<br>' +
        esc(a.credentialKind) +
        deviceCell + '</small></td><td class="num">' +
        esc(Number(a.score).toPrecision(3)) + '</td><td><strong>' +
        esc(a.level) + '</strong></td><td><small>' + model +
        (model && signals ? '<br>' : '') + (signals || (model ? '' : '—')) +
        '</small></td><td>' + esc(a.decision) +
        // What the person said about it on /portal/sign-ins (#62 P6).
        (a.feedback ? '<br><small>' + (a.feedback === 'denied'
          ? '<strong>' + t.html('consoleRisk.assessment.notThem') +
            '</strong>'
          : t.html('consoleRisk.assessment.confirmed')) + '</small>'
          : '') + '</td></tr>';
    }).join('');
    const people = view.subjects.map(function (p: Json): string {
      return '<tr><td>' + self.whoCell(p, t) + '</td><td>' +
        '<strong>' + esc(p.level) + '</strong>' +
        (p.previousLevel && p.previousLevel !== p.level
          ? ' <small>' + t.html('consoleRisk.standings.was',
                                { level: p.previousLevel }) +
            '</small>' : '') +
        '</td><td class="num">' + esc(Number(p.score).toPrecision(3)) +
        '</td><td><small>' + esc(p.reason) + '</small></td><td><small>' +
        esc(self.when(p.updatedAt)) + '</small></td></tr>';
    }).join('');
    let credit = '';
    credits.forEach(function (c: Json): void {
      credit += '<p class="attribution"><small>' + self.credit(c, t) +
        '</small></p>';
    });
    return '<h3>' + t.html('consoleRisk.assessments.heading') + ' <small>' +
      t.html('consoleRisk.assessments.sub') + '</small></h3><p>' +
      (view.assessmentsInDatabase
        ? t.html('consoleRisk.assessments.inDatabase')
        : t.html('consoleRisk.assessments.inProcess')) + ' ' +
      t.html('consoleRisk.assessments.count',
             { n: view.assessments.total }) +
      '</p>' + assessmentsNav.head +
      '<table class="grid" id="risk-assessments"><thead>' +
      '<tr><th>' + t.html('consoleRisk.th.when') + '</th><th>' +
      t.html('consoleRisk.th.who') + '</th><th>' +
      t.html('consoleRisk.th.network') + '</th><th>' +
      t.html('consoleRisk.th.device') + '</th>' +
      '<th>' + t.html('consoleRisk.th.score') + '</th><th>' +
      t.html('consoleRisk.th.level') + '</th><th>' +
      t.html('consoleRisk.th.signals') + '</th><th>' +
      t.html('consoleRisk.th.decision') + '</th></tr>' +
      '</thead><tbody>' + (rows || '<tr><td colspan="8">' +
                           t.html('consoleRisk.noneYet') + '</td></tr>') +
      '</tbody></table>' + assessmentsNav.foot + credit +
      '<h3>' + t.html('consoleRisk.standings.heading') + '</h3>' +
      subjectsNav.head +
      '<table class="grid" id="risk-subjects"><thead><tr><th>' +
      t.html('consoleRisk.th.who') + '</th>' +
      '<th>' + t.html('consoleRisk.th.level') + '</th><th>' +
      t.html('consoleRisk.th.score') + '</th><th>' +
      t.html('consoleRisk.th.why') + '</th><th>' +
      t.html('consoleRisk.th.updated') + '</th></tr>' +
      '</thead><tbody>' + (people || '<tr><td colspan="5">' +
                          t.html('consoleRisk.noneYet') + '</td>' +
                          '</tr>') + '</tbody></table>' + subjectsNav.foot;
  }

  // ---------------------------------------------------------------------------
  // THE MODEL'S FACTORS (#499), from the assessment's model row: each
  // feature's population/person ratio and the USER TERM, p(u|A)/p(u|L) —
  // Freeman et al.'s Eq. (7) — which multiply to the model's score, so the
  // cell explains all of it. The user term's counts follow it: the person's
  // sign-ins, the realm's, and how many people signed in. Empty for a
  // sign-in the model did not score, or an assessment written before the
  // user term was recorded (it then shows the two features only).
  //
  // THE LEVELS WHOSE LOOKUP FOUND NOTHING follow (#502): no network, no
  // country, no browser the User-Agent named. The model counts each as
  // unseen on both sides, so they are what makes a new unmapped address's
  // ip factor what it is; drawn for an unscored sign-in too.
  // ---------------------------------------------------------------------------
  static modelCell(row: Json, t: Json): string {
    const f = row && row.factors;
    const unknown = row && Array.isArray(row.unknown) && row.unknown.length
      ? t.html('consoleRisk.model.unknown') + ' ' +
        row.unknown.map(function (l: unknown): string {
        return kit.esc(l);
      }).join(', ') : '';
    if (!f || typeof f !== 'object') {
      return unknown ? t.html('consoleRisk.model.model') + ' ' + unknown
        : '';
    }
    const parts = ['ip', 'ua', 'user'].filter(function (k: string): boolean {
      return typeof f[k] === 'number';
    }).map(function (k: string): string {
      return kit.esc(k) + ' ×' + kit.esc(Number(f[k]).toPrecision(3));
    });
    // The user term's counts are `terms`, no longer `t`: `t` is the
    // translator (#539).
    const terms = row.terms;
    const counts = terms && typeof terms === 'object' &&
      typeof f.user === 'number'
      ? ' ' + t.html('consoleRisk.model.counts', {
        mine: terms.userSignIns, all: terms.signIns, people: terms.users })
      : '';
    const said = parts.length ? parts.join(' · ') + counts : '';
    return said || unknown
      ? t.html('consoleRisk.model.model') + ' ' + said +
        (said && unknown ? ' · ' : '') + unknown : '';
  }

  // A provider's credit as its licence asks (`risk_terms.attributionOf()`):
  // the attribution LINKED to the source, the licence named and linked, and
  // that the data was modified here — CC BY 4.0 section 3(a), which DB-IP's
  // licence asks for on every page that displays its results.
  static credit(c: Json, t: Json): string {
    const esc = kit.esc.bind(kit);
    const source = c.url ? '<a href="' + esc(c.url) + '" rel="noopener">' +
      esc(c.text) + '</a>' : esc(c.text);
    const licence = c.licence ? t.html('consoleRisk.licensedUnder') +
      (c.licenceUrl
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
