// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scheduler_admin.ts
//
// ===========================================================================
// MONITORING → SCHEDULER (2026-09-22, #49): IS THE BACKGROUND WORK HAPPENING?
//
// `GET /admin/scheduler` draws what `cluster/scheduler.ts`'s `status()`
// answers: which process leads the scheduler and since when, then ONE ROW FOR
// EVERY REGISTERED JOB — including the ones that are off, with the reason, so
// a job that never runs is on the page rather than missing from it — with its
// kind and scope, its schedule, its last run (when, how long, and whether it
// succeeded, failed with its code, was abandoned or is running now), and the
// time to its next run as a duration AND an absolute time in UTC, both from
// the DATABASE's clock so every node draws the same figure. A per-process job
// has one sub-row per node and process. Below the jobs, the recent runs,
// filtered by job and outcome; `?run=<id>` is one run.
//
// **EVERYTHING ON IT IS READ FROM THE STORE**, never from this process's
// memory — the scheduler's header, point 5 — so the page is the same whichever
// process answers it.
//
// **NO SCRIPT** (the root CLAUDE.md: a console page with a script has to argue
// it, and this one cannot — a countdown is a nicety, not the page's job). The
// time to next run is worked out when the page is drawn and does not count
// down; the page says *as of* and has a Refresh link, and every duration is
// beside its absolute time, so a stale page cannot be misread.
//
// **TWO CONTROLS, BOTH REAL FORM BUTTONS, ADMIN WRITE ONLY.** *Run now*
// queues a run of a job that allows it — the leader starts it at its next
// tick, wherever the button was pressed — and *Step down* asks the leader to
// hand the scheduler to another node (D10), which only a clustered service
// has. Both are refused to a realm administrator for anything that is not
// their own realm's (`admin_scope.ts`'s `/admin/scheduler` rule): a
// service-scoped job and the step-down belong to the service.
//
// **A REALM ADMINISTRATOR** sees the service jobs read-only and their own
// realm's rows of the realm jobs, and nothing of any other realm.
//
// Rule 7: `GET /admin-api/scheduler` answers `schedulerView()`, the function
// the page's `?format=json` answers; `POST /admin-api/scheduler/run` and
// `/step-down` are `schedulerAction()`, the function the page's forms post to.
//
// TYPESCRIPT, AS A CLASS (#50): `caches_admin.ts`'s shape — dependencies
// through the constructor, `registerRoutes(app)` called by
// `common/protocol_stack.ts` (18i), and facades for the JavaScript callers.
// ===========================================================================

import admin = require('./admin');
import adminViews = require('../admin-core/admin_views');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import realms = require('../common/realms');
import InstanceSlot = require('../common/instance_slot');
import schedulerModule = require('../cluster/scheduler');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import SchedulerPage = require('./web_scheduler');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Monitoring → Scheduler.
 */
const PAGE = '/admin/scheduler';

interface SchedulerAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  scheduler: typeof schedulerModule;
  parseBody: typeof helpers.parseBody;
}

/**
 * Monitoring → Scheduler: which process leads the scheduler, every registered
 * job with its last and next run, and the recent runs, all read from the store.
 */
class SchedulerAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the console and the scheduler
   */
  constructor(private readonly deps: SchedulerAdminDeps) {
    deps.log.debug("Entering SchedulerAdmin.constructor().");
    deps.log.debug("Leaving SchedulerAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): SchedulerAdminDeps {
    helpers.log.debug("Entering SchedulerAdmin.defaultDeps().");
    helpers.log.debug("Leaving SchedulerAdmin.defaultDeps().");
    return {
      log: helpers.log,
      admin: admin,
      adminViews: adminViews,
      errorCodes: errorCodes,
      scheduler: schedulerModule,
      parseBody: helpers.parseBody
    };
  }

  // The realm a request is confined to: a realm administrator's own, or ''
  // for a service administrator (and for a caller with no console session,
  // which the gate has already let through, as a management API token is).
  /**
   * Answers the realm a request is confined to.
   *
   * @param req - the request
   * @returns a realm administrator's own realm, or '' for a service
   * administrator or a caller with no console session
   */
  confinedRealm(req: Req): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering SchedulerAdmin.confinedRealm().");
    let state: Json = null;
    try {
      state = adminViews.gateStateFor(req);
    } catch (e) {
      log.debug("Caught in SchedulerAdmin.confinedRealm(): " +
                ((e && e.message) || e));
      state = null;
    }
    // A realm's own management API token (`mgmt-api/admin_api.ts` says so on
    // the response) is confined exactly as a realm administrator is.
    const tokenRealm = req && req.res && req.res.locals &&
                       req.res.locals.realmTokenOf;
    log.debug("Leaving SchedulerAdmin.confinedRealm().");
    if (tokenRealm) {
      return String(tokenRealm);
    }
    return state && state.authority === 'realm'
      ? String(state.identityRealm || '') : '';
  }

  private actorOf(req: Req): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering SchedulerAdmin.actorOf().");
    let who = '';
    try {
      const state: Json = adminViews.gateStateFor(req);
      who = String((state && state.username) || '');
    } catch (e) {
      log.debug("Caught in SchedulerAdmin.actorOf(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving SchedulerAdmin.actorOf().");
    return who;
  }

  // -------------------------------------------------------------------------
  // THE VIEW MODEL: the report, or one run when `run` is named. One function
  // for the page's `?format=json` and for `GET /admin-api/scheduler`.
  // -------------------------------------------------------------------------
  /**
   * Builds the view model for the page's `?format=json` and `GET
   * /admin-api/scheduler`: the scheduler's report, or one run when the query
   * names `run`.
   *
   * @param req - the request, for the realm it is confined to
   * @param query - the query's values: `run`, and the job and outcome filters
   * @returns the report or the one run
   */
  async schedulerView(req: Req, query?: Json): Promise<Json> {
    const { log, scheduler, adminViews, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.schedulerView().");
    const q = query || {};
    const realm = this.confinedRealm(req);
    const runId = SchedulerPage.firstOf(q.run);
    const report: Json = await scheduler.status({
      realm: realm, job: SchedulerPage.firstOf(q.job),
      outcome: SchedulerPage.firstOf(q.outcome)
    });
    report.confinedToRealm = realm || null;
    report.filters = { job: SchedulerPage.firstOf(q.job) || null,
                       outcome: SchedulerPage.firstOf(q.outcome) || null };
    if (runId) {
      const run = scheduler.findRun(runId);
      const visible = run && (!realm || run.realm === realm ||
                              run.realm === realms.DEFAULT_ID);
      log.debug("Leaving SchedulerAdmin.schedulerView(). One run.");
      return { generatedAt: report.generatedAt, run: runId,
               found: !!visible, detail: visible ? run : null,
               leader: report.leader };
    }
    const paged = adminViews.pagedRows(q, report.runs, { noun: 'runs' });
    report.runs = paged.shown;
    report.runsPaging = adminViews.pagingJson(paged.paging);
    Object.defineProperty(report, 'paging', { value: paged.paging,
                                              enumerable: false });
    // THE JOBS ARE PAGED TOO (2026-09-22, rcbj), on `jobsPage`, because the
    // list grows without a bound anybody sets: every owner registers its
    // jobs, and a REALM job has a row per realm — a service with fifty realms
    // has fifty rows of each. The runs list beside it has been paged since
    // it was written. Its own parameter, so the two move independently and
    // each keeps the other where the reader left it (`pageParamsOf()`).
    // EVERY job's id, before the page narrows the list: the runs filter's
    // menu is built from it, and a menu offering only the jobs on the
    // current page could not filter by any other.
    const everyJobId: string[] = [];
    (report.jobs as Json[]).forEach(function (job: Json): void {
      if (everyJobId.indexOf(String(job.id)) < 0) {
        everyJobId.push(String(job.id));
      }
    });
    const pagedJobs = adminViews.pagedRows(q, report.jobs, { noun: 'jobs',
                                                            name: 'jobs' });
    report.jobs = pagedJobs.shown;
    report.jobsPaging = adminViews.pagingJson(pagedJobs.paging);
    report.jobIds = everyJobId;
    // The page's settings, as every page that owns settings answers them
    // (#446): the page is drawn from this view alone. A realm's own
    // administrator is shown none, as the page never drew them one.
    if (!realm) {
      report.settings = admin.configSettingsJson(PAGE);
    }
    Object.defineProperty(report, 'jobsPagingRaw', {
      value: pagedJobs.paging, enumerable: false });
    log.debug("Leaving SchedulerAdmin.schedulerView(). " +
              report.jobs.length + " job row(s).");
    return report;
  }

  // -------------------------------------------------------------------------
  // THE TWO ACTIONS: `{ action: 'run', job, realm?, params? }` and
  // `{ action: 'step-down' }`. Answers `{ ok, ... }` or `{ ok: false,
  // errorCode, errors }`. A realm administrator is refused a service job, a
  // job in another realm and the step-down (STS-SCHED-0007) — the console's
  // gate refuses it first through `admin_scope.ts`, and this says it again
  // for a caller that did not come through that gate.
  // -------------------------------------------------------------------------
  /**
   * Takes one of the page's two actions: `run` a job now, or `step-down` the
   * leader.
   *
   * A realm administrator is refused a service job, a job in another realm and
   * the step-down (`STS-SCHED-0007`).
   * @param req - the request
   * @param body - `{ action: 'run', job, realm?, params? }` or `{ action:
   * 'step-down' }`
   * @param via - which surface asked
   * @returns `{ ok, ... }`, or `{ ok: false, errorCode, errors }`
   */
  schedulerAction(req: Req, body: Json, via: string): Json {
    const { log, scheduler } = this.deps;
    log.debug("Entering SchedulerAdmin.schedulerAction().");
    const b = body || {};
    const action = String(b.action || '').trim();
    const realm = this.confinedRealm(req);
    const actor = this.actorOf(req);
    if (action === 'step-down') {
      if (realm) {
        log.debug("Leaving SchedulerAdmin.schedulerAction(). Realm admin.");
        return { ok: false, errorCode: 'STS-SCHED-0007', errors: [
          'Handing the scheduler to another node is a service ' +
          'administrator\'s act.'] };
      }
      const answer = scheduler.requestStepDown({ requestedBy: actor,
                                                 via: via });
      log.debug("Leaving SchedulerAdmin.schedulerAction(). Step-down.");
      return answer.ok
        ? { ok: true, accepted: true, command: answer.command,
            leaderAtRequest: answer.leaderAtRequest,
            message: 'The scheduler\'s leader was asked to stand down. It ' +
                     'does so at its next tick, and another node takes the ' +
                     'lead at its next heartbeat.' }
        : { ok: false, errorCode: answer.errorCode, errors: [answer.why] };
    }
    if (action !== 'run') {
      log.debug("Leaving SchedulerAdmin.schedulerAction(). Unknown action.");
      // THE SENTENCE IS THE SHAPE THE SUITE READS (`Unknown action "x".
      // <phrase>: <list>.`): `admin_api.js` checks every console action has
      // an operation from it, and `sts_admin_api_operations.js` compares the
      // list with the OpenAPI document.
      return { ok: false, errorCode: 'STS-ADMIN-0012', errors: [
        'Unknown action "' + action + '". The actions here are: run, ' +
        'step-down.'] };
    }
    const jobId = String(b.job || '').trim();
    const job = scheduler.job(jobId);
    const wanted = String(b.realm || '').trim() || realms.currentId();
    if (realm && job && (job.scope !== 'realm' || wanted !== realm)) {
      log.debug("Leaving SchedulerAdmin.schedulerAction(). Confined.");
      return { ok: false, errorCode: 'STS-SCHED-0007', errors: [
        job.scope !== 'realm'
          ? jobId + ' runs for the whole service, which a realm ' +
            'administrator of "' + realm + '" does not administer.'
          : 'That run names the "' + wanted + '" realm, and a realm ' +
            'administrator of "' + realm + '" may run jobs in that realm ' +
            'only.'] };
    }
    let params: Json = b.params;
    if (typeof params === 'string' && params.trim()) {
      try {
        params = JSON.parse(params);
      } catch (e) {
        log.debug("Caught in SchedulerAdmin.schedulerAction(): " +
                  ((e && e.message) || e));
        log.debug("Leaving SchedulerAdmin.schedulerAction(). Bad params.");
        return { ok: false, errorCode: 'STS-ADMIN-0012', errors: [
          'params is not JSON: ' + ((e && e.message) || e)] };
      }
    }
    const answer = scheduler.requestRun(jobId, {
      realm: wanted, params: params && typeof params === 'object'
        ? params : null,
      requestedBy: actor, via: via,
      channel: /management API/.test(via) ? 'http' : 'console' });
    log.debug("Leaving SchedulerAdmin.schedulerAction(). " +
              (answer.ok ? 'Queued.' : 'Refused.'));
    return answer.ok
      ? { ok: true, accepted: true, runId: answer.runId,
          alreadyQueued: !!answer.alreadyQueued, run: answer.run,
          href: PAGE + '?run=' + encodeURIComponent(answer.runId),
          message: 'A run of ' + jobId + ' is queued' +
                   (answer.alreadyQueued ? ' (one already was; this is it)'
                     : '') + '. The scheduler\'s leader starts it at its ' +
                   'next tick.' }
      : { ok: false, errorCode: answer.errorCode, status: answer.status,
          errors: [answer.why] };
  }

  // DRAWN BY `web_scheduler.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  private body(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.body().");
    const drawn = SchedulerPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving SchedulerAdmin.body().");
    return drawn;
  }

  /**
   * Registers `GET /admin/scheduler` and its actions.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering SchedulerAdmin.registerRoutes().");
    log.debug("Leaving SchedulerAdmin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2): see
// `caches_admin.ts`.
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<SchedulerAdmin>(
  'admin-ui/scheduler_admin',
  () => new SchedulerAdmin(SchedulerAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Monitoring → Scheduler, `/admin/scheduler`: is the background work happening?
 * Every job the scheduler knows, with its runs, read from the store so every
 * process draws the same page.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  SchedulerAdmin: SchedulerAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: SchedulerAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7): the page's own JSON and action.
  schedulerView: slot.forward('schedulerView'),
  schedulerAction: slot.forward('schedulerAction')
};
