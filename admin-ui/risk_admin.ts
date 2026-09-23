'use strict';
//
// File: admin-ui/risk_admin.ts
//
// ===========================================================================
// MONITORING → RISK (#62 P1, 2026-09-22): the external datasets a risk score
// reads, and the attributable failure history.
//
// What it draws, all of it out of `risk/risk_datasets.ts` and
// `risk/risk_failures.ts` and none of it a second way:
//
//   * WHICH STORE holds them — the database, or this process where there is
//     none (`risk_store.describe()`), because "kept in the database" is a
//     postgres guarantee and the page must not imply otherwise.
//   * THE DATASET REGISTRY — every dataset the service knows, its active
//     version and whether it is fresh, stale or empty, the provider's
//     attribution (DB-IP's licence requires its link on a page that uses its
//     data, and this is that page), and every version recorded, refused ones
//     with their reason.
//   * WHAT THE DATASETS SAY ABOUT AN ADDRESS (`?address=`), which is the
//     question an operator asks after loading one.
//   * THE FAILURE HISTORY of a realm: who (a subject, or a name's digest),
//     from which network, at which door, with which code. Never an address
//     and never a typed name.
//
// Admin Write may import a version by pasting it (an IP list; a file of
// millions of rows goes through `risk.datasetsDirectory`), activate one, roll
// back to the previous, or delete a version that is not active. Rule 7:
// every one of those is `/admin-api/risk/:action`, which calls `riskAction()`
// below, and `GET /admin-api/risk` answers `riskView()`.
//
// A REALM ADMINISTRATOR SEES IT TOO (2026-09-22; it was a service page
// until then): under `/realm/<id>/admin/risk` the page is their realm's —
// its assessments, standings, refused passwords and operator allow and deny
// lists, which they may manage. What is the service's is left off the page
// for them (`realmOnly`): the service datasets' controls and versions, the
// providers' terms and who accepted them, the `risk.` settings, and on the
// scoring page this process's own counts. `admin_scope.ts` refuses the
// same things at the gate, so the page hiding them is a courtesy and not the
// control. The data credits stay: the licences ask for them wherever the
// data is shown.
// ===========================================================================

import admin = require('./admin');
import adminViews = require('../admin-core/admin_views');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');
import riskDatasets = require('../risk/risk_datasets');
import riskFailures = require('../risk/risk_failures');
import riskEngine = require('../risk/risk_engine');

type Req = any;
type Res = any;
type Json = any;

const PAGE = '/admin/risk';

// MONITORING → RISK SCORING (#62): the scoring system measured — what it
// assessed over a window, how the levels and signals fell, how long it took
// and what it did about it. A second page rather than a section of the one
// above, because rcbj asked for it as a page and because the two answer
// different questions: that one is "what does the service know", this one
// "is the scoring working".
const METRICS_PAGE = '/admin/risk-scoring';

// The windows offered, by the name the query carries.
const WINDOWS: Record<string, number> = {
  '1h': 3600000, '24h': 86400000, '7d': 7 * 86400000, '30d': 30 * 86400000 };

// Each level's colour: the same four as the badge on a person's user page
// (`admin.ts`'s `riskBadge()`), so a level reads the same on both.
const LEVEL_COLOURS: Record<string, string> = {
  LOW: '#188038', MEDIUM: '#f9ab00', HIGH: '#d93025', UNSCORED: '#5f6368' };
const LEVELS = ['HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];

// What `riskAction()` does, and what each needs.
const ACTIONS = ['import', 'activate', 'rollback', 'delete', 'accept-terms'];

// The failure page's size, and the window it reads.
const FAILURES_PER_PAGE = 50;
const FAILURE_WINDOW_MS = 7 * 86400000;

interface RiskAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  realms: typeof realms;
  datasets: typeof riskDatasets;
  failures: typeof riskFailures;
  engine: typeof riskEngine;
  parseBody: typeof helpers.parseBody;
  now(): number;
}

class RiskAdmin {
  static readonly PAGE = PAGE;
  static readonly ACTIONS = ACTIONS;

  constructor(private readonly deps: RiskAdminDeps) {
    deps.log.debug("Entering RiskAdmin.constructor().");
    deps.log.debug("Leaving RiskAdmin.constructor().");
  }

  static defaultDeps(): RiskAdminDeps {
    helpers.log.debug("Entering RiskAdmin.defaultDeps().");
    helpers.log.debug("Leaving RiskAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      adminViews: adminViews,
      errorCodes: errorCodes,
      realms: realms,
      datasets: riskDatasets,
      failures: riskFailures,
      engine: riskEngine,
      parseBody: helpers.parseBody,
      now: function (): number {
        return Date.now();
      }
    };
  }

  // The realm the failures and the per-realm lists are shown for: the one
  // named in `?realm=` if it exists, and the default realm otherwise.
  private realmOf(query: Json): string {
    const { log, realms } = this.deps;
    log.debug("Entering RiskAdmin.realmOf().");
    const asked = String((query && query.realm) || '').trim();
    const known = asked && (asked === 'default' || realms.get(asked));
    log.debug("Leaving RiskAdmin.realmOf().");
    // Unnamed, the realm the page is drawn in: `/realm/acme/admin/risk` is
    // acme's, which is what a realm administrator of acme signs in to.
    return known ? asked : (realms.currentId() || 'default');
  }

  // -------------------------------------------------------------------------
  // THE VIEW: what `GET /admin/risk?format=json` and `GET /admin-api/risk`
  // both answer. `query.address` adds the lookup; `query.offset` pages the
  // failures.
  // -------------------------------------------------------------------------
  // `realmOnly` is for a realm administrator: the realm's own and nothing
  // of the service's (see the header).
  async riskView(query: Json, realmOnly?: boolean): Promise<Json> {
    const { log, datasets, failures, engine, now } = this.deps;
    log.debug("Entering RiskAdmin.riskView().");
    const q = query || {};
    const realm = this.realmOf(q);
    const registry = await datasets.registry(realm);
    const offset = Math.max(0, Number(q.offset) || 0);
    const history = await failures.list(realm, {
      since: now() - FAILURE_WINDOW_MS, limit: FAILURES_PER_PAGE,
      offset: offset });
    const address = String(q.address || '').trim();
    const lookup = address ? await datasets.lookup(address, realm) : null;
    // `subject` narrows the assessments to one person — the link under the
    // risk badge on their Directory → Users page (#62).
    const assessed = await engine.view(realm, { level: q.level || '',
                                               subject: q.subject || '',
                                               offset: q.aoffset || 0 });
    log.debug("Leaving RiskAdmin.riskView().");
    return {
      realm: realm,
      realmOnly: !!realmOnly,
      store: registry.store,
      directory: realmOnly ? '' : registry.directory,
      datasets: realmOnly
        ? registry.datasets.filter(function (d: Json): boolean {
            return !!d.perRealm && d.realm === realm;
          })
        : registry.datasets,
      formats: registry.formats,
      providers: realmOnly ? [] : registry.providers,
      acceptances: realmOnly ? [] : registry.acceptances,
      attributions: registry.attributions,
      redistribution: registry.redistribution,
      lookup: lookup,
      assessments: assessed.assessments,
      subjects: assessed.subjects,
      signals: assessed.signals,
      assessmentsInDatabase: assessed.inDatabase,
      failures: {
        store: failures.describe(), windowDays: FAILURE_WINDOW_MS / 86400000,
        total: history.total, offset: offset, limit: FAILURES_PER_PAGE,
        rows: history.rows
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE ACTIONS: the four the page's forms post and `/admin-api/risk/:action`
  // calls. `via` names the door, for the audit row.
  // -------------------------------------------------------------------------
  // `actor` names who acted: the console's signed-in administrator, or ''
  // for the management API, which authenticates a client rather than a
  // person — its audit row for the request names the caller.
  async riskAction(body: Json, via: string, actor?: string): Promise<Json> {
    const { log, datasets, errorCodes } = this.deps;
    log.debug("Entering RiskAdmin.riskAction().");
    const who = String(actor || '') || (/api/i.test(via)
      ? 'a management API client' : via);
    const b = body || {};
    const action = String(b.action || '');
    const refuse = (why: string): Json => {
      log.debug("Leaving RiskAdmin.riskAction(). " + why);
      return errorCodes.mark({ ok: false, errors: [why] }, 'STS-RISK-0011');
    };
    if (ACTIONS.indexOf(action) < 0) {
      return refuse('Unknown action "' + action + '". The ' + ACTIONS.length +
                    ' are: ' + ACTIONS.join(', ') + '.');
    }
    if (action === 'accept-terms') {
      const provider = String(b.provider || '').trim();
      if (!provider) {
        return refuse('Name the provider whose terms are accepted.');
      }
      const accepted = await require('../risk/risk_terms').accept({
        provider: provider, acceptedBy: who, via: via });
      log.debug("Leaving RiskAdmin.riskAction(). Terms.");
      return accepted;
    }
    const dataset = String(b.dataset || '').trim();
    const realm = String(b.realm || '').trim();
    if (!dataset) {
      return refuse('Name the dataset.');
    }
    let result: Json;
    if (action === 'import') {
      if (!String(b.format || '').trim() || typeof b.content !== 'string' ||
          !b.content.trim()) {
        return refuse('An import needs a format and the file\'s content.');
      }
      result = await datasets.importVersion({
        dataset: dataset, realm: realm, format: String(b.format).trim(),
        content: b.content, version: String(b.version || '').trim() || '',
        publishedAt: b.publishedAt ? Date.parse(String(b.publishedAt)) || 0
                                   : 0,
        provider: b.provider ? String(b.provider) : undefined,
        licence: b.licence ? String(b.licence) : undefined,
        attribution: b.attribution === undefined ? undefined
                                                 : String(b.attribution),
        sha256: String(b.sha256 || '').trim() || undefined,
        activate: String(b.activate) !== 'false', source: 'upload',
        // The console's checkbox (`on`) or the API's boolean: accept the
        // provider's current terms as part of this import, for this actor.
        acceptTerms: b.acceptTerms === true || b.acceptTerms === 'true' ||
                     b.acceptTerms === 'on',
        actor: who });
    } else if (action === 'activate' || action === 'delete') {
      const version = String(b.version || '').trim();
      if (!version) {
        return refuse('Name the version.');
      }
      result = action === 'activate'
        ? await datasets.activateVersion(realm, dataset, version, who)
        : await datasets.deleteVersion(realm, dataset, version, who);
    } else {
      result = await datasets.rollback(realm, dataset, who);
    }
    log.debug("Leaving RiskAdmin.riskAction(). ok=" + !!(result && result.ok));
    return result;
  }

  // -------------------------------------------------------------------------
  // THE SCORING SYSTEM, MEASURED: what `GET /admin/risk-scoring?format=json`
  // and `GET /admin-api/risk/metrics` both answer. `window` is one of
  // WINDOWS' names (24h by default); `realm` as on the page above.
  // -------------------------------------------------------------------------
  async metricsView(query: Json, realmOnly?: boolean): Promise<Json> {
    const { log, engine } = this.deps;
    log.debug("Entering RiskAdmin.metricsView().");
    const q = query || {};
    const name = WINDOWS[String(q.window || '')] ? String(q.window) : '24h';
    const measured = await engine.metrics(this.realmOf(q), WINDOWS[name]);
    if (realmOnly) {
      // THIS PROCESS's counts are every realm's (see the header).
      delete measured.process;
    }
    log.debug("Leaving RiskAdmin.metricsView().");
    return Object.assign({ window: name, windows: Object.keys(WINDOWS),
                           realmOnly: !!realmOnly }, measured);
  }

  // One table of counts with a bar each, largest first. `colour` gives a
  // row's bar colour; `limit` keeps the longest tables short.
  private bars(id: string, head: string, counts: Json, total: number,
               colour?: (k: string) => string, limit?: number,
               order?: string[]): string {
    const { log, admin } = this.deps;
    log.debug("Entering RiskAdmin.bars(). " + id);
    const esc = admin.esc.bind(admin);
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
    log.debug("Leaving RiskAdmin.bars().");
    return '<table class="grid" id="' + id + '"><thead><tr><th>' +
      esc(head) + '</th><th>Count</th><th>Share</th><th></th></tr></thead>' +
      '<tbody>' + (rows || '<tr><td colspan="4">None in this window.</td>' +
                           '</tr>') + '</tbody></table>' +
      (limit && keys.length > limit ? '<p><small>' + (keys.length - limit) +
       ' more not shown; the JSON has every one.</small></p>' : '');
  }

  // The levels over time: a column per bucket, stacked by level, drawn as
  // markup — no script, for the reason the console has none.
  private timeline(m: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering RiskAdmin.timeline().");
    const esc = admin.esc.bind(admin);
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
    log.debug("Leaving RiskAdmin.timeline().");
    return '<div id="risk-timeline" style="display:flex;align-items:' +
      'flex-end;gap:2px;height:160px;padding:6px;border:1px solid #dadce0;' +
      'border-radius:6px">' + bars + '</div><p><small>' +
      esc(stamp(first)) + ' UTC to now, a column per ' +
      esc(RiskAdmin.duration(m.bucketMs)) + '; the tallest is ' + peak +
      '. Hover a column for its counts.' + legend + '</small></p>';
  }

  // A duration in the largest unit that divides it.
  static duration(ms: number): string {
    helpers.log.debug("Entering RiskAdmin.duration().");
    helpers.log.debug("Leaving RiskAdmin.duration().");
    if (ms % 86400000 === 0) {
      return ms / 86400000 + ' day' + (ms === 86400000 ? '' : 's');
    }
    if (ms % 3600000 === 0) {
      return ms / 3600000 + ' hour' + (ms === 3600000 ? '' : 's');
    }
    return ms / 60000 + ' minutes';
  }

  private metricsHtml(m: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering RiskAdmin.metricsHtml().");
    const esc = admin.esc.bind(admin);
    const a = m.assessments;
    const p = m.process;
    const level = function (k: string): string {
      return LEVEL_COLOURS[k] || '#5f6368';
    };
    const windows = m.windows.map(function (w: string): string {
      return w === m.window ? '<strong>' + esc(w) + '</strong>'
        : '<a href="' + esc(METRICS_PAGE + '?window=' + w + '&realm=' +
                            encodeURIComponent(m.realm)) + '">' + esc(w) +
          '</a>';
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
    log.debug("Leaving RiskAdmin.metricsHtml().");
    return admin.note('The scoring system measured: what it assessed, how ' +
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
        admin.tile(a.total, 'assessments') +
        admin.tile(a.subjects, 'people assessed') +
        admin.tile(high, 'HIGH') +
        admin.tile(a.total ? (high / a.total * 100).toFixed(1) + '%' : '—',
                   'of them HIGH') +
        admin.tile(a.meanScore.toPrecision(3), 'mean score') +
        admin.tile(a.bots, 'automated clients') +
        (p ? admin.tile(d.samples ? Math.round(d.p95) + ' ms' : '—',
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
                undefined, ['< 0.001', '0.001 – 0.01', '0.01 – 0.1',
                            '0.1 – 1', '≥ 1']) +
      '<h3>People by current standing</h3>' +
      this.bars('risk-standings', 'Level', m.standings, people, level,
                undefined, LEVELS) +
      '<h3>Signals</h3><p>Each signal with the factor it multiplies a ' +
      'score by and how often it fired in the window: a signal that fires ' +
      'on most sign-ins, or never, is the first thing to calibrate.</p>' +
      '<table class="grid" id="risk-signals"><thead><tr><th>Signal</th>' +
      '<th>What</th><th>Factor</th><th>Fired</th><th>Of assessments</th>' +
      '</tr></thead><tbody>' + signals + '</tbody></table>' +
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

  // ===== THE PAGE ==========================================================

  private when(ms: number): string {
    const { log } = this.deps;
    log.debug("Entering RiskAdmin.when().");
    log.debug("Leaving RiskAdmin.when().");
    return ms ? new Date(ms).toISOString().replace('.000Z', 'Z') : '—';
  }

  private html(req: Req, view: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering RiskAdmin.html().");
    // Called for every value drawn, so no Entering/Leaving pair: a hot path,
    // which the code style allows when it says so.
    const esc = function (v: unknown): string {
      return admin.esc(v);
    };
    const canWrite = admin.mayWrite(req);
    const active = view.datasets.filter(function (d: Json): boolean {
      return d.state === 'active';
    }).length;
    const stale = view.datasets.filter(function (d: Json): boolean {
      return d.state === 'stale';
    }).length;
    const tiles = '<div class="tiles">' +
      admin.tile(String(active), 'datasets active') +
      admin.tile(String(stale), 'stale (counted for nothing)') +
      admin.tile(String(view.failures.total),
                 'refused passwords in ' + view.failures.windowDays + ' days') +
      '</div>';
    const about = admin.note(
      '<p>The external datasets a risk score reads, and the refused ' +
      'passwords it counts (#62). <strong>Nothing here is fetched while ' +
      'anybody signs in</strong>: a dataset arrives as a file, is checked ' +
      '(its SHA-256 where one is named, and a version much smaller than the ' +
      'active one is refused as a likely truncated download), and only then ' +
      'becomes active. A dataset older than its staleness limit counts for ' +
      'nothing and never refuses anybody.</p><p>' + esc(view.store.why) +
      '</p><p>A file of millions of rows goes in <code>' +
      'risk.datasetsDirectory</code> with a manifest' +
      (view.directory ? ' (now <code>' + esc(view.directory) + '</code>)'
                      : ' (not set)') +
      '; the form below is for a list you can paste.</p>',
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
    const importForm = !canWrite ? '' :
      '<h3>Import a version</h3><form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="import">' +
      '<label>Dataset <select name="dataset" id="risk-import-dataset">' +
      view.datasets.map(function (d: Json): string {
        return '<option value="' + esc(d.dataset) + '">' + esc(d.dataset) +
          '</option>';
      }).join('') + '</select></label> <label>Format <select name="format" ' +
      'id="risk-import-format">' +
      view.formats.map(function (f: Json): string {
        return '<option value="' + esc(f.format) + '">' + esc(f.format) +
          '</option>';
      }).join('') + '</select></label> ' + (view.realmOnly
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
        (f.subject ? '<code>' + esc(f.subject) + '</code>'
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
    const assessments = this.assessmentsHtml(view);
    log.debug("Leaving RiskAdmin.html().");
    if (view.realmOnly) {
      return tiles + admin.note('This is the <code>' + esc(view.realm) +
        '</code> realm\'s risk: its assessments, its people\'s standings, ' +
        'its operator allow and deny lists and its refused passwords. The ' +
        'datasets every realm shares — geolocation, networks, Tor exits, ' +
        'reputation, security-key metadata — their providers\' terms and ' +
        'the <code>risk.</code> settings are the whole service\'s, and a ' +
        'service administrator manages them.', 'What this page is') +
        assessments + '<h3>Look up an address</h3>' + lookupForm + rows +
        importForm + failures + credits;
    }
    return tiles + about + assessments + '<h3>Look up an address</h3>' +
      lookupForm + rows + importForm + providers + failures + credits +
      '<h2>Settings</h2>' + admin.configFormsFor(PAGE);
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
  private assessmentsHtml(view: Json): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering RiskAdmin.assessmentsHtml().");
    // Called for every value drawn: a hot path, with no Entering/Leaving.
    const esc = function (v: unknown): string {
      return admin.esc(v);
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
      return '<tr><td><small>' + esc(self.when(a.at)) + '</small></td><td>' +
        '<code>' + esc(a.subject) + '</code><br><small>' + esc(a.door) +
        '</small></td><td><code>' + esc(a.addressPrefix) + '</code>' +
        (a.asn ? '<br><small>AS' + a.asn + ' ' + esc(a.asOrg) + '</small>'
               : '') + (a.country ? '<br><small>' + esc(a.city ? a.city +
                                                     ', ' : '') +
                                    esc(a.country) + '</small>' : '') +
        '</td><td><small>' + esc([a.uaFamily, a.uaOs, a.uaPlatform]
          .filter(Boolean).join(' / ') || '—') +
        (a.bot ? ' (automated)' : '') + '<br>' + esc(a.credentialKind) +
        '</small></td><td class="num">' +
        esc(Number(a.score).toPrecision(3)) + '</td><td><strong>' +
        esc(a.level) + '</strong></td><td><small>' + (signals || '—') +
        '</small></td><td>' + esc(a.decision) +
        // What the person said about it on /portal/sign-ins (#62 P6).
        (a.feedback ? '<br><small>' + (a.feedback === 'denied'
          ? '<strong>not them</strong>' : 'confirmed by them') + '</small>'
          : '') + '</td></tr>';
    }).join('');
    const people = view.subjects.map(function (p: Json): string {
      return '<tr><td><code>' + esc(p.subject) + '</code></td><td>' +
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
    log.debug("Leaving RiskAdmin.assessmentsHtml().");
    return '<h3>Sign-ins assessed <small>(the last 7 days, and what the ' +
      'issuance policy decided)</small></h3><p>' + (view.assessmentsInDatabase
        ? 'Held in the database.'
        : 'Held in this process: there is no database with a key to seal ' +
          'them under.') + ' ' + view.assessments.total +
      ' assessment(s).</p><table class="grid" id="risk-assessments"><thead>' +
      '<tr><th>When</th><th>Who</th><th>Network</th><th>Device</th>' +
      '<th>Score</th><th>Level</th><th>Signals</th><th>Decision</th></tr>' +
      '</thead><tbody>' + (rows || '<tr><td colspan="8">None yet.</td></tr>') +
      '</tbody></table>' + credit + '<h3>People by current standing</h3>' +
      '<table class="grid" id="risk-subjects"><thead><tr><th>Who</th>' +
      '<th>Level</th><th>Score</th><th>Why</th><th>Updated</th></tr>' +
      '</thead><tbody>' + (people || '<tr><td colspan="5">None yet.</td>' +
                          '</tr>') + '</tbody></table>';
  }

  // A provider's credit as its licence asks (`risk_terms.attributionOf()`):
  // the attribution LINKED to the source, the licence named and linked, and
  // that the data was modified here — CC BY 4.0 section 3(a), which DB-IP's
  // licence asks for on every page that displays its results.
  private credit(c: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering RiskAdmin.credit().");
    const esc = admin.esc.bind(admin);
    const source = c.url ? '<a href="' + esc(c.url) + '" rel="noopener">' +
      esc(c.text) + '</a>' : esc(c.text);
    const licence = c.licence ? ', licensed under ' + (c.licenceUrl
      ? '<a href="' + esc(c.licenceUrl) + '" rel="noopener">' +
        esc(c.licence) + '</a>' : esc(c.licence)) : '';
    log.debug("Leaving RiskAdmin.credit().");
    return source + licence + (c.modified ? '; ' + esc(c.modified) : '') +
      '.';
  }

  // One small POST form: an action on one dataset (and version).
  private form(action: string, d: Json, version: string,
               label: string): string {
    const { log, admin } = this.deps;
    log.debug("Entering RiskAdmin.form(). " + action);
    log.debug("Leaving RiskAdmin.form().");
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="dataset" value="' + admin.esc(d.dataset) +
      '"><input type="hidden" name="realm" value="' + admin.esc(d.realm) +
      '"><input type="hidden" name="version" value="' + admin.esc(version) +
      '"><button type="submit" id="risk-' + action + '-' +
      admin.esc(d.dataset).replace(/[^a-z0-9]/gi, '-') +
      (version ? '-' + admin.esc(version).replace(/[^a-z0-9]/gi, '-') : '') +
      '">' + admin.esc(label) + '</button></form>';
  }

  // Whether the request is a realm administrator's (#32): theirs is the
  // realm-only view. The console's session and the management API's token
  // both answer through `gateStateFor()`.
  realmOnly(req: Req): boolean {
    const { log, adminViews } = this.deps;
    log.debug("Entering RiskAdmin.realmOnly().");
    let state: Json = null;
    try {
      state = adminViews.gateStateFor(req);
    } catch (e) {
      log.debug("Caught in RiskAdmin.realmOnly(): " + ((e && e.message) || e));
      // No gate state to read: not a realm administrator's request, and the
      // gate in front of this route has already decided who it is.
      state = null;
    }
    log.debug("Leaving RiskAdmin.realmOnly().");
    return !!(state && state.authority === 'realm');
  }

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering RiskAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      const realmOnly = self.realmOnly(req);
      self.riskView(req.query, realmOnly).then(function (view: Json) {
        admin.respond(req, res, view, 'Risk', PAGE,
                      admin.messagesOf(req) + self.html(req, view));
        log.debug('Leaving GET ' + PAGE + '.');
      }).catch(function (e: Json): void {
        log.warn(errorCodes.tag('STS-RISK-0011') + 'risk: the page could ' +
                 'not be drawn: ' + ((e && e.message) || e));
        errorCodes.mark(res, 'STS-RISK-0011');
        res.status(500).type('text/plain')
           .send('The risk page could not be drawn: ' +
                 ((e && e.message) || e));
        log.debug('Leaving GET ' + PAGE + '. Failed.');
      });
    });
    app.get(METRICS_PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + METRICS_PAGE + '.');
      const realmOnly = self.realmOnly(req);
      self.metricsView(req.query, realmOnly).then(function (view: Json) {
        admin.respond(req, res, view, 'Risk scoring', METRICS_PAGE,
                      admin.messagesOf(req) + self.metricsHtml(view));
        log.debug('Leaving GET ' + METRICS_PAGE + '.');
      }).catch(function (e: Json): void {
        log.warn(errorCodes.tag('STS-RISK-0025') + 'risk: the scoring ' +
                 'metrics could not be drawn: ' + ((e && e.message) || e));
        errorCodes.mark(res, 'STS-RISK-0025');
        res.status(500).type('text/plain')
           .send('The risk scoring metrics could not be drawn: ' +
                 ((e && e.message) || e));
        log.debug('Leaving GET ' + METRICS_PAGE + '. Failed.');
      });
    });
    app.post(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + PAGE + '.');
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-RISK-0011');
        admin.respondToAction(req, res, PAGE, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + PAGE + '. Read-only.');
        return;
      }
      const state = self.deps.adminViews.gateStateFor(req);
      self.riskAction(parseBody(req), 'the admin console',
                      (state && state.username) || '')
        .then(function (result: Json): void {
          if (!result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-RISK-0011');
          }
          admin.respondToAction(req, res, PAGE, result);
          log.debug('Leaving POST ' + PAGE + '.');
        }).catch(function (e: Json): void {
          log.warn(errorCodes.tag('STS-RISK-0011') + 'risk: an action ' +
                   'failed: ' + ((e && e.message) || e));
          admin.respondToAction(req, res, PAGE, errorCodes.mark({
            ok: false, errors: [String((e && e.message) || e)] },
            'STS-RISK-0011'));
          log.debug('Leaving POST ' + PAGE + '. Threw.');
        });
    });
    log.debug("Leaving RiskAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<RiskAdmin>(
  'admin-ui/risk_admin',
  () => new RiskAdmin(RiskAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  RiskAdmin: RiskAdmin,
  installInstance: (instance: RiskAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  METRICS_PAGE: METRICS_PAGE,
  WINDOWS: WINDOWS,
  ACTIONS: RiskAdmin.ACTIONS,
  metricsView: slot.forward('metricsView'),
  realmOnly: slot.forward('realmOnly'),
  riskView: slot.forward('riskView'),
  riskAction: slot.forward('riskAction')
};
