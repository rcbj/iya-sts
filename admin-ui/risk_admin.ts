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
// A SERVICE PAGE (`admin_scope.ts`): the datasets are the whole service's,
// so a realm's own administrators do not see it. The failure history and an
// operator list are per realm, and the page names the realm it shows.
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
    return known ? asked : 'default';
  }

  // -------------------------------------------------------------------------
  // THE VIEW: what `GET /admin/risk?format=json` and `GET /admin-api/risk`
  // both answer. `query.address` adds the lookup; `query.offset` pages the
  // failures.
  // -------------------------------------------------------------------------
  async riskView(query: Json): Promise<Json> {
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
      store: registry.store,
      directory: registry.directory,
      datasets: registry.datasets,
      formats: registry.formats,
      providers: registry.providers,
      acceptances: registry.acceptances,
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
      }).join('') + '</select></label> <label>Realm (an operator list ' +
      'only) <input type="text" name="realm" value=""></label><br>' +
      '<label>Version <input type="text" name="version" ' +
      'placeholder="default: its SHA-256"></label> <label>SHA-256 ' +
      '<input type="text" name="sha256"></label><br>' +
      '<label><input type="checkbox" name="acceptTerms" ' +
      'id="risk-import-accept"> I have read and accept the provider\'s ' +
      'terms (below), recorded in my name</label><br>' +
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

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering RiskAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.riskView(req.query).then(function (view: Json): void {
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
  ACTIONS: RiskAdmin.ACTIONS,
  riskView: slot.forward('riskView'),
  riskAction: slot.forward('riskAction')
};
