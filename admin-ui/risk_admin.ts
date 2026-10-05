// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// Admin Write may import a version by pasting it (an IP list) or by
// UPLOADING THE FILE (#215: `POST /admin/risk/upload`, a plain
// multipart/form-data form with no script, streamed to disk and expanded as
// it is read by `risk/risk_upload.ts` — a DB-IP city file of hundreds of
// megabytes arrives this way), activate one, roll back to the previous, or
// delete a version that is not active. Rule 7: every one of those is
// `/admin-api/risk/:action` or `POST /admin-api/risk/upload`, which call
// `riskAction()` and `uploadDoor()` below, and `GET /admin-api/risk` answers
// `riskView()`.
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
import lingeringClose = require('../common/lingering_close');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');
import riskDatasets = require('../risk/risk_datasets');
import riskFailures = require('../risk/risk_failures');
import riskEngine = require('../risk/risk_engine');
import riskStore = require('../risk/risk_store');
import riskUpload = require('../risk/risk_upload');
import websecurity = require('../common/websecurity');
import adminScope = require('./admin_scope');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import RiskPage = require('./web_risk');

type Req = any;
type Res = any;
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

// The windows offered, by the name the query carries.
/**
 * The windows the metrics page offers, by the name the query carries, each with
 * its span in milliseconds.
 */
const WINDOWS: Record<string, number> = {
  '1h': 3600000, '24h': 86400000, '7d': 7 * 86400000, '30d': 30 * 86400000 };

// What `riskAction()` does, and what each needs.
/**
 * The actions `riskAction()` takes: `import`, `activate`, `rollback`, `delete`
 * and `accept-terms`.
 */
const ACTIONS = ['import', 'activate', 'rollback', 'delete', 'accept-terms'];

// EVERY ACTION `/risk` HAS, which is what the unknown-action refusal names
// (2026-09-26). `upload` (#215) is answered by a route of its own, registered
// above `/risk/:action`, so `riskAction()` never sees it — but it is still one
// of this resource's actions, and `tests/vendored/admin_api.js` reads THIS
// sentence for the console/API parity (rule 7): an action missing from it is
// invisible to that check. `sts_admin_api_operations.js` compares the sentence
// with the OpenAPI document and found `upload` missing.
const NAMED_ACTIONS = ACTIONS.concat(['upload']);

// The failure page's size, and the window it reads.
const FAILURES_PER_PAGE = 50;
// The standings table's page size when `per` does not say; the assessments
// take the console's default.
const SUBJECTS_PER_PAGE = 25;
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
  upload: typeof riskUpload;
  websecurity: typeof websecurity;
  adminScope: typeof adminScope;
  parseBody: typeof helpers.parseBody;
  nameForSubject: typeof helpers.nameForSubject;
  now(): number;
}

/**
 * Monitoring → Risk and Monitoring → Risk scoring: the external datasets a risk
 * score reads, the failure history, the assessments and the scoring system
 * measured, and the imports an Admin Write may make.
 */
class RiskAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;
  /**
   * See the module's `UPLOAD`.
   */
  static readonly UPLOAD = UPLOAD;
  /**
   * See the module's `ACTIONS`.
   */
  static readonly ACTIONS = ACTIONS;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console, the risk datasets, failures, engine and upload,
   * and a clock
   */
  constructor(private readonly deps: RiskAdminDeps) {
    deps.log.debug("Entering RiskAdmin.constructor().");
    deps.log.debug("Leaving RiskAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
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
      upload: riskUpload,
      websecurity: websecurity,
      adminScope: adminScope,
      parseBody: helpers.parseBody,
      nameForSubject: helpers.nameForSubject,
      now: function (): number {
        return Date.now();
      }
    };
  }

  // BOTH PAGES ARE PER REALM (2026-09-26, rcbj): the realm shown is the one
  // the page is drawn in — `/realm/acme/admin/risk` is acme's, the bare
  // `/admin/risk` the default realm's — and nothing in the request names
  // another. `?realm=` did until that day, which let the default realm's
  // console draw any realm's people and made every lookup on the page ask
  // which realm it was in; another realm's risk is read under its prefix.
  private realmOf(): string {
    const { log, realms } = this.deps;
    log.debug("Entering RiskAdmin.realmOf().");
    log.debug("Leaving RiskAdmin.realmOf().");
    return realms.currentId() || 'default';
  }

  // WHO EACH SUBJECT IS (2026-09-26, rcbj): every person on the page is
  // stored as their `urn:uuid:` subject, which nobody can read, so each row
  // that names one gains `username` — the name the directory files them
  // under, '' when the entry is gone. The directory answers for the ambient
  // realm, which is the page's (`realmOf()`); once per subject.
  private nameSubjects(lists: Json[][]): void {
    const { log, nameForSubject, realms } = this.deps;
    log.debug("Entering RiskAdmin.nameSubjects().");
    const known = new Map<string, string>();
    lists.forEach(function (rows: Json[]): void {
      (rows || []).forEach(function (row: Json): void {
        const sub = String(row.subject || '');
        if (!sub) {
          return;
        }
        if (!known.has(sub)) {
          known.set(sub, nameForSubject(sub));
        }
        row.username = known.get(sub);
        // Where the name links, made here because a realm's prefix is this
        // process's to know (#446): the page draws the link it is given.
        if (row.username) {
          row.userHref = realms.href('/admin/users?user=' +
                                     encodeURIComponent(String(row.username)));
        }
      });
    });
    log.debug("Leaving RiskAdmin.nameSubjects(). " + known.size +
              " subject(s).");
  }

  // -------------------------------------------------------------------------
  // THE VIEW: what `GET /admin/risk?format=json` and `GET /admin-api/risk`
  // both answer. `query.address` adds the lookup; `query.offset` pages the
  // failures.
  //
  // THE ASSESSMENTS AND THE STANDINGS ARE PAGED (2026-09-26, rcbj), each on
  // a parameter of its own — `assessmentsPage`, `subjectsPage` — with `per`
  // shared, the console's arrangement for a page of several lists
  // (`pagingOf()`, `pageParamsOf()`), because neither grows under a bound
  // anybody sets: a row per sign-in for a week, and a row per person ever
  // assessed. Unlike the other pages' lists these are paged IN THE STORE
  // (a LIMIT and an OFFSET on postgres), since the whole list is what the
  // pager exists not to read; so the page asked for is fetched first and,
  // when it was past the end, the last page is fetched again — the pager
  // CLAMPS rather than refuses, and the reply says which page it drew.
  // -------------------------------------------------------------------------
  // `realmOnly` is for a realm administrator: the realm's own and nothing
  // of the service's (see the header).
  /**
   * Builds the view `GET /admin/risk?format=json` and `GET /admin-api/risk`
   * both answer: the store, the dataset registry, the failure history, and the
   * assessments and standings, each paged in the store.
   *
   * @param query - `address` for a lookup, `offset` for the failures, and the
   * paging parameters
   * @param realmOnly - true for a realm administrator, who sees the realm's own
   * and nothing of the service's
   * @returns the view
   */
  async riskView(query: Json, realmOnly?: boolean): Promise<Json> {
    const { log, datasets, failures, engine, now } = this.deps;
    log.debug("Entering RiskAdmin.riskView().");
    const q = query || {};
    const realm = this.realmOf();
    const registry = await datasets.registry(realm);
    const offset = Math.max(0, Number(q.offset) || 0);
    const history = await failures.list(realm, {
      since: now() - FAILURE_WINDOW_MS, limit: FAILURES_PER_PAGE,
      offset: offset });
    const address = String(q.address || '').trim();
    const lookup = address ? await datasets.lookup(address, realm) : null;
    // `subject` narrows the assessments to one person — the link under the
    // risk badge on their Directory → Users page (#62).
    const assessmentsOpts = { name: 'assessments', noun: 'assessments' };
    const subjectsOpts = { name: 'subjects', noun: 'people',
                           defaultPer: SUBJECTS_PER_PAGE };
    const unbounded = Number.MAX_SAFE_INTEGER;
    const fetchPages = function (a: Json, p: Json): Promise<Json> {
      log.debug("Entering fetchPages().");
      log.debug("Leaving fetchPages().");
      return engine.view(realm, { level: q.level || '',
                                  subject: q.subject || '',
                                  limit: a.perPage, offset: a.offset,
                                  subjectsLimit: p.perPage,
                                  subjectsOffset: p.offset });
    };
    let assessed = await fetchPages(
      adminViews.pagingOf(q, unbounded, assessmentsOpts),
      adminViews.pagingOf(q, unbounded, subjectsOpts));
    const assessmentsPaging = adminViews.pagingOf(
      q, assessed.assessments.total, assessmentsOpts);
    const subjectsPaging = adminViews.pagingOf(q, assessed.subjectsTotal,
                                               subjectsOpts);
    if (assessed.assessments.rows.length === 0 &&
          assessmentsPaging.total > 0 ||
        assessed.subjects.length === 0 && subjectsPaging.total > 0) {
      // A page past the end of either list: the clamped pages, again.
      assessed = await fetchPages(assessmentsPaging, subjectsPaging);
    }
    this.nameSubjects([assessed.assessments.rows, assessed.subjects,
                       history.rows]);
    log.debug("Leaving RiskAdmin.riskView().");
    const view: Json = {
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
      assessmentsPaging: adminViews.pagingJson(assessmentsPaging),
      subjects: assessed.subjects,
      subjectsPaging: adminViews.pagingJson(subjectsPaging),
      signals: assessed.signals,
      assessmentsInDatabase: assessed.inDatabase,
      failures: {
        store: failures.describe(), windowDays: FAILURE_WINDOW_MS / 86400000,
        total: history.total, offset: offset, limit: FAILURES_PER_PAGE,
        rows: history.rows
      }
    };
    // THE SETTINGS, as every page that owns settings answers them (#446).
    // A realm's own administrator is shown none: the `risk.` settings are
    // the whole service's.
    if (!realmOnly) {
      view.settings = this.deps.admin.configSettingsJson(PAGE);
    }
    return view;
  }

  // -------------------------------------------------------------------------
  // THE ACTIONS: the four the page's forms post and `/admin-api/risk/:action`
  // calls. `via` names the door, for the audit row.
  // -------------------------------------------------------------------------
  // `actor` names who acted: the console's signed-in administrator, or ''
  // for the management API, which authenticates a client rather than a
  // person — its audit row for the request names the caller.
  /**
   * Performs one of the page's actions, for its forms and
   * `/admin-api/risk/:action`.
   *
   * @param body - `action` and its fields
   * @param via - the door, for the audit row
   * @param actor - the signed-in administrator, or '' for the management API
   * @returns `ok` with a message, or a refusal carrying its error code
   */
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
      return refuse('Unknown action "' + action + '". The ' +
                    NAMED_ACTIONS.length + ' are: ' +
                    NAMED_ACTIONS.join(', ') + '.');
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
  /**
   * Builds the view `GET /admin/risk-scoring?format=json` and `GET
   * /admin-api/risk/metrics` both answer: what was assessed over the window,
   * how the levels and signals fell, how long it took and what it did.
   *
   * @param query - `window`, one of `WINDOWS`' names (24h by default)
   * @param realmOnly - true for a realm administrator
   * @returns the view
   */
  async metricsView(query: Json, realmOnly?: boolean): Promise<Json> {
    const { log, engine } = this.deps;
    log.debug("Entering RiskAdmin.metricsView().");
    const q = query || {};
    const name = WINDOWS[String(q.window || '')] ? String(q.window) : '24h';
    const measured = await engine.metrics(this.realmOf(), WINDOWS[name]);
    if (realmOnly) {
      // THIS PROCESS's counts are every realm's (see the header).
      delete measured.process;
    }
    log.debug("Leaving RiskAdmin.metricsView().");
    // The score bands the page's histogram is drawn in (#446): the
    // store's, which a page drawn from this answer cannot ask.
    return Object.assign({ window: name, windows: Object.keys(WINDOWS),
                           realmOnly: !!realmOnly,
                           bands: riskStore.BANDS }, measured);
  }

  // ===== THE PAGE ==========================================================

  // DRAWN BY `web_risk.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private html(req: Req, view: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering RiskAdmin.html().");
    const drawn = RiskPage.render(JSON.parse(JSON.stringify(view)),
      admin.renderContext(req));
    log.debug("Leaving RiskAdmin.html().");
    return drawn;
  }

  // Whether the request is a realm administrator's (#32): theirs is the
  // realm-only view. The console's session and the management API's token
  // both answer through `gateStateFor()`.
  /**
   * Answers whether the request is a realm administrator's, whose view is the
   * realm's own.
   *
   * @param req - the request
   * @returns true for a realm authority
   */
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

  // -------------------------------------------------------------------------
  // WHO IS UPLOADING, AND THE TWO CHECKS THE GATE LEFT TO THE UPLOAD (#215):
  // the door `risk/risk_upload.ts` is handed. `csrf` is the console's — the
  // token is a field of the form, read before the file (the management API
  // has none: its caller sends a bearer token, which no other site can make
  // a browser attach). `scope` is a realm administrator's reach, the same
  // rule `/admin/risk`'s own actions meet at the gate (`admin_scope.ts`),
  // asked of the upload's fields because the gate could not read them.
  // -------------------------------------------------------------------------
  /**
   * Builds the door `risk/risk_upload.ts` is handed: who is uploading, the
   * console's CSRF check, and a realm administrator's scope check on the
   * upload's fields.
   *
   * @param req - the request
   * @param via - which surface asked
   * @param withCsrf - whether to check the console's CSRF token
   * @returns the door: `via`, `source`, `actor`, `csrf` and `scope`
   */
  uploadDoor(req: Req, via: string, withCsrf: boolean): Json {
    const { log, adminViews, websecurity, adminScope } = this.deps;
    log.debug("Entering RiskAdmin.uploadDoor().");
    let state: Json = null;
    try {
      state = adminViews.gateStateFor(req);
    } catch (e) {
      log.debug("Caught in RiskAdmin.uploadDoor(): " +
                ((e && e.message) || e));
      // No gate state (the management API with its gate off): no realm
      // authority to confine, and no session to hold a token for.
      state = null;
    }
    const sessionId = state && state.session ? String(state.session.id) : '';
    log.debug("Leaving RiskAdmin.uploadDoor().");
    return {
      via: via,
      source: 'upload',
      actor: (state && state.username) ||
             (/api/i.test(via) ? 'a management API client' : via),
      csrf: withCsrf ? function (fields: Json): Json {
        log.debug("Entering the upload's CSRF check.");
        log.debug("Leaving the upload's CSRF check.");
        return websecurity.checkCsrf(sessionId, fields);
      } : null,
      scope: function (fields: Json): Json {
        log.debug("Entering the upload's scope check.");
        const refused = adminScope.refusalFor(state, PAGE, fields, {});
        log.debug("Leaving the upload's scope check.");
        return refused ? { code: refused.code,
                           why: String(refused.detail || refused.reason) }
                       : null;
      }
    };
  }

  // The management API's upload (#215): the same door, no CSRF (see
  // `uploadDoor()`), the file as the body and the fields in the query.
  /**
   * Receives the management API's upload: the file as the body and the fields
   * in the query, with no CSRF check.
   *
   * @param req - the request
   * @param via - which surface asked
   * @returns a promise of the upload's result
   */
  receiveUpload(req: Req, via: string): Promise<Json> {
    const { log, upload } = this.deps;
    log.debug("Entering RiskAdmin.receiveUpload().");
    log.debug("Leaving RiskAdmin.receiveUpload().");
    return upload.receiveRaw(req, this.uploadDoor(req, via, false));
  }

  /**
   * Registers both pages, the actions and the upload.
   *
   * @param app - the shared express app
   */
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
                      admin.messagesOf(req) +
                      // Drawn by `web_risk.ts` (#446), as the Risk page is.
                      RiskPage.metricsHtml(JSON.parse(JSON.stringify(view))));
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
    // THE UPLOAD (#215). The gate has already asked for Admin Write and the
    // policy on the headers; `risk_upload.ts` checks the token and the realm
    // from the fields before it writes the file.
    app.post(UPLOAD, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + UPLOAD + '.');
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-RISK-0011');
        lingeringClose.arm(req, res);
        admin.respondToAction(req, res, PAGE, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + UPLOAD + '. Read-only.');
        return;
      }
      self.deps.upload.receiveForm(req, self.uploadDoor(req,
                                                        'the admin console',
                                                        true))
        .then(function (answer: Json): void {
          if (answer.close) {
            lingeringClose.arm(req, res);
          }
          if (answer.code) {
            errorCodes.mark(res, answer.code);
          }
          if (answer.code === 'STS-ADMIN-0005') {
            // The gate's own CSRF refusal, in the gate's words: a form that
            // did not come from this console is not redirected into it.
            res.status(403).type('text/plain')
               .send('That form did not come from this console. ' +
                     (answer.body.errors || []).join(' ') + '\n');
            log.debug('Leaving POST ' + UPLOAD + '. CSRF.');
            return;
          }
          admin.respondToAction(req, res, PAGE, answer.body);
          log.debug('Leaving POST ' + UPLOAD + '. ' + answer.status);
        }).catch(function (e: Json): void {
          log.warn(errorCodes.tag('STS-RISK-0037') + 'risk: an upload ' +
                   'failed: ' + ((e && e.stack) || e));
          lingeringClose.arm(req, res);
          admin.respondToAction(req, res, PAGE, errorCodes.mark({
            ok: false, errors: [String((e && e.message) || e)] },
            'STS-RISK-0037'));
          log.debug('Leaving POST ' + UPLOAD + '. Threw.');
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

/**
 * Monitoring → Risk (`/admin/risk`) and Monitoring → Risk scoring
 * (`/admin/risk-scoring`), and what the management API mirrors of them (rule
 * 7).
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  RiskAdmin: RiskAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: RiskAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  UPLOAD: UPLOAD,
  METRICS_PAGE: METRICS_PAGE,
  WINDOWS: WINDOWS,
  ACTIONS: RiskAdmin.ACTIONS,
  metricsView: slot.forward('metricsView'),
  realmOnly: slot.forward('realmOnly'),
  riskView: slot.forward('riskView'),
  riskAction: slot.forward('riskAction'),
  uploadDoor: slot.forward('uploadDoor'),
  receiveUpload: slot.forward('receiveUpload')
};
