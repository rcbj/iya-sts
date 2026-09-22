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

type Req = any;
type Res = any;
type Json = any;

const PAGE = '/admin/scheduler';

// What each state is called on the page.
const STATE_WORDS: Json = {
  succeeded: 'succeeded', failed: 'failed', abandoned: 'abandoned',
  running: 'running now', queued: 'queued'
};

interface SchedulerAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  adminViews: typeof adminViews;
  errorCodes: typeof errorCodes;
  scheduler: typeof schedulerModule;
  parseBody: typeof helpers.parseBody;
}

class SchedulerAdmin {
  static readonly PAGE = PAGE;

  constructor(private readonly deps: SchedulerAdminDeps) {
    deps.log.debug("Entering SchedulerAdmin.constructor().");
    deps.log.debug("Leaving SchedulerAdmin.constructor().");
  }

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

  // A repeated parameter arrives as an array; the first one wins.
  private firstOf(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering SchedulerAdmin.firstOf().");
    const one = Array.isArray(value) ? value[0] : value;
    log.debug("Leaving SchedulerAdmin.firstOf().");
    return one === undefined || one === null || typeof one === 'object'
      ? '' : String(one).trim();
  }

  // The realm a request is confined to: a realm administrator's own, or ''
  // for a service administrator (and for a caller with no console session,
  // which the gate has already let through, as a management API token is).
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
  async schedulerView(req: Req, query?: Json): Promise<Json> {
    const { log, scheduler, adminViews } = this.deps;
    log.debug("Entering SchedulerAdmin.schedulerView().");
    const q = query || {};
    const realm = this.confinedRealm(req);
    const runId = this.firstOf(q.run);
    const report: Json = await scheduler.status({
      realm: realm, job: this.firstOf(q.job), outcome: this.firstOf(q.outcome)
    });
    report.confinedToRealm = realm || null;
    report.filters = { job: this.firstOf(q.job) || null,
                       outcome: this.firstOf(q.outcome) || null };
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
      return { ok: false, errorCode: 'STS-ADMIN-0012', errors: [
        'The action "' + action + '" is not one of run and step-down.'] };
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

  // -------------------------------------------------------------------------
  // THE DRAWING.
  // -------------------------------------------------------------------------
  private when(iso: string | null, inMs?: number | null): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.when().");
    if (!iso) {
      log.debug("Leaving SchedulerAdmin.when(). None.");
      return '—';
    }
    const rel = inMs === undefined || inMs === null ? ''
      : (inMs <= 0 ? 'now' : 'in ' + schedulerModule.Scheduler.span(inMs)) +
        '<br>';
    log.debug("Leaving SchedulerAdmin.when().");
    return rel + '<small><code>' + admin.esc(iso) + '</code></small>';
  }

  private outcomeText(run: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.outcomeText().");
    const word = STATE_WORDS[run.state] || run.state;
    let text = '<strong>' + admin.esc(word) + '</strong>';
    if (run.errorCode) {
      text += ' <code>' + admin.esc(run.errorCode) + '</code>';
    }
    if (run.why) {
      text += '<br><small>' + admin.esc(run.why) + '</small>';
    }
    log.debug("Leaving SchedulerAdmin.outcomeText().");
    return text;
  }

  private lastRunCell(job: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.lastRunCell().");
    const parts: string[] = [];
    if (job.running) {
      parts.push('<strong>running now</strong> since <code>' +
                 admin.esc(job.running.startedAt || '') + '</code> on ' +
                 admin.esc(job.running.nodeName || job.running.host) +
                 ' (pid ' + admin.esc(job.running.pid) + ', attempt ' +
                 job.running.attempt + ')');
    }
    const last = job.lastRun;
    if (last) {
      parts.push('<a href="' + admin.esc(PAGE + '?run=' +
                                         encodeURIComponent(last.runId)) +
                 '">' + this.outcomeText(last).replace(/<br>.*$/, '') +
                 '</a><br><small>' + admin.esc(last.startedAt || '') +
                 ' → ' + admin.esc(last.endedAt || '') +
                 (last.durationMs !== null ? ', ' +
                  admin.esc(schedulerModule.Scheduler.span(last.durationMs)) +
                  ' (' + last.durationMs + ' ms)' : '') + ', ' +
                 admin.esc(last.trigger) + ', on ' +
                 admin.esc(last.nodeName || last.host || '?') + '</small>' +
                 (last.why ? '<br><small>' + admin.esc(last.why) +
                  '</small>' : ''));
    }
    if (!parts.length) {
      parts.push('<em>never run</em>');
    }
    log.debug("Leaving SchedulerAdmin.lastRunCell().");
    return parts.join('<br>');
  }

  private nextRunCell(job: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.nextRunCell().");
    let text: string;
    switch (job.nextRunState) {
      case 'off':
        text = '—';
        break;
      case 'manual-only':
        text = '<em>on demand only</em>';
        break;
      case 'queued':
        text = '<strong>queued</strong> (manual run requested by ' +
               admin.esc(job.queued[0].requestedBy || 'somebody') + ')<br>' +
               '<small><code>' + admin.esc(job.queued[0].queuedAt || '') +
               '</code></small>';
        break;
      case 'due':
        text = '<strong>due now</strong> — waiting for the leader\'s next ' +
               'tick<br><small><code>' + admin.esc(job.nextRunAt) +
               '</code></small>';
        break;
      case 'overdue':
        text = '<strong>overdue since</strong> <code>' +
               admin.esc(job.overdueSince) + '</code><br><small>' +
               admin.esc(job.overdueWhy || '') + '</small>';
        break;
      case 'running':
        text = 'after this run; next slot ' +
               this.when(job.nextRunAt, job.nextRunInMs);
        break;
      default:
        text = this.when(job.nextRunAt, job.nextRunInMs);
    }
    log.debug("Leaving SchedulerAdmin.nextRunCell().");
    return text;
  }

  private runNowCell(job: Json, canWrite: boolean): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.runNowCell().");
    if (!canWrite || !job.manual || job.readOnly || job.state === 'off') {
      log.debug("Leaving SchedulerAdmin.runNowCell(). No control.");
      return job.state === 'off' && job.manual
        ? '<small>off</small>' : '—';
    }
    log.debug("Leaving SchedulerAdmin.runNowCell().");
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="run">' +
      '<input type="hidden" name="job" value="' + admin.esc(job.id) + '">' +
      '<input type="hidden" name="realm" value="' + admin.esc(job.realm) +
      '">' +
      '<button type="submit" id="scheduler-run-' + admin.esc(job.id) + '-' +
      admin.esc(job.realm) + '">Run now</button></form>';
  }

  private jobsTable(json: Json, canWrite: boolean): string {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering SchedulerAdmin.jobsTable().");
    const rows = json.jobs.map(function (job: Json): string {
      const state = job.state === 'off'
        ? '<strong>off</strong><br><small>' + admin.esc(job.offReason) +
          '</small>'
        : 'enabled' + (job.readOnly ? '<br><small>read-only here: a ' +
                       'service job</small>' : '');
      const head = '<tr id="job-' + admin.esc(job.id) + '-' +
        admin.esc(job.realm) + '">' +
        '<td><a href="' + admin.esc(PAGE + '?job=' +
                                    encodeURIComponent(job.id)) +
        '"><code>' + admin.esc(job.id) + '</code></a><br>' +
        admin.esc(job.title) + '<br><small>' + admin.esc(job.describe) +
        '</small><br><small>owner <code>' + admin.esc(job.owner) +
        '</code></small></td>' +
        '<td>' + admin.esc(job.kind) + '<br><small>' +
        admin.esc(job.scope) + (job.scope === 'realm'
          ? ': <code>' + admin.esc(job.realm) + '</code>' : '') +
        '</small></td>' +
        '<td>' + admin.esc(job.schedule.text) + '</td>' +
        '<td>' + state + '</td>' +
        '<td>' + (job.kind === 'per-process'
          ? '<em>per process, below</em>' : self.lastRunCell(job)) + '</td>' +
        '<td>' + self.nextRunCell(job) + '</td>' +
        '<td>' + self.runNowCell(job, canWrite) + '</td></tr>';
      const subs = (job.processes || []).map(function (p: Json): string {
        return '<tr class="sub"><td colspan="4"><small>↳ ' +
          admin.esc(p.nodeName || p.host) + ', pid ' + admin.esc(p.pid) +
          (p.worker ? ' (request worker)' : ' (front process)') +
          (p.stale ? ' — <strong>no run for two slots; the process has ' +
           'probably gone</strong>' : '') + '</small></td><td>' +
          self.outcomeText(p) + '<br><small>' +
          admin.esc(p.startedAt || '') + '</small></td><td>' +
          self.when(p.nextRunAt, p.nextRunInMs) + '</td><td></td></tr>';
      }).join('');
      const noProcess = job.kind === 'per-process' &&
        !(job.processes || []).length
        ? '<tr class="sub"><td colspan="7"><small>↳ no process has run ' +
          'it yet</small></td></tr>' : '';
      return head + subs + noProcess;
    }).join('');
    log.debug("Leaving SchedulerAdmin.jobsTable(). " + json.jobs.length +
              " row(s).");
    return '<table class="grid"><thead><tr><th>Job</th>' +
      '<th>Kind and scope</th><th>Schedule</th><th>State</th>' +
      '<th>Last run</th><th>Time to next run</th><th>Run now</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="7">No job is registered.</td></tr>') +
      '</tbody></table>';
  }

  private leaderBlock(json: Json, canWrite: boolean): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.leaderBlock().");
    const l = json.leader || {};
    let who: string;
    if (!l.known) {
      who = '<strong>No process has led the scheduler yet.</strong> The ' +
            'leader writes a row when it takes the lead and at every tick.';
    } else {
      who = (l.thisProcess ? '<strong>This process</strong> — ' : '') +
        '<strong>' + admin.esc(l.nodeName || l.host) + '</strong>, pid ' +
        admin.esc(l.pid) + (l.clustered
          ? ', node <code>' + admin.esc(l.node) + '</code>, lease token ' +
            admin.esc(l.token) : ' — <em>not clustered</em>: the one front ' +
            'process leads, and nothing else could') +
        '<br><small>leading since <code>' + admin.esc(l.since || '?') +
        '</code>' + (l.leaseAcquiredAt ? ' (the lease was acquired ' +
        '<code>' + admin.esc(l.leaseAcquiredAt) + '</code>)' : '') +
        '; last tick <code>' + admin.esc(l.lastTickAt || '?') + '</code>' +
        (l.lastTickAgoMs !== null ? ', ' +
         admin.esc(schedulerModule.Scheduler.span(l.lastTickAgoMs)) +
         ' ago' : '') + '</small>' +
        (l.live ? '' : admin.warn('The leader has not ticked for longer ' +
                                  'than three ticks. No job is running on ' +
                                  'schedule until a node leads again.'));
    }
    const stepDown = canWrite && l.clustered && !json.confinedToRealm
      ? '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="step-down">' +
        '<button type="submit" id="scheduler-step-down">Step down</button>' +
        '</form> <small>asks the leader to hand the scheduler to another ' +
        'node; it stands down at its next tick</small>'
      : '';
    log.debug("Leaving SchedulerAdmin.leaderBlock().");
    return '<h3>Leader</h3><p>' + who + '</p>' + stepDown;
  }

  private runsTable(json: Json, query: Json): string {
    const { log, admin, adminViews } = this.deps;
    const self = this;
    log.debug("Entering SchedulerAdmin.runsTable().");
    const params = adminViews.pageParamsOf(query);
    ['job', 'outcome'].forEach(function (name: string): void {
      const value = self.firstOf(query[name]);
      if (value) {
        params[name] = value;
      }
    });
    const nav = admin.pageNavPair(PAGE, params, json.paging);
    const jobOptions = ['<option value="">every job</option>'].concat(
      json.jobs.map(function (j: Json): string {
        return j.id;
      }).filter(function (id: string, i: number, all: string[]): boolean {
        return all.indexOf(id) === i;
      }).map(function (id: string): string {
        return '<option value="' + admin.esc(id) + '"' +
          (json.filters.job === id ? ' selected' : '') + '>' +
          admin.esc(id) + '</option>';
      })).join('');
    const outcomeOptions = ['', 'succeeded', 'failed', 'abandoned',
                            'running', 'queued'].map(function (o: string) {
      return '<option value="' + o + '"' +
        ((json.filters.outcome || '') === o ? ' selected' : '') + '>' +
        (o || 'every outcome') + '</option>';
    }).join('');
    const filter = '<form method="get" action="' + PAGE + '" class="inline">' +
      '<label>Job <select name="job">' + jobOptions + '</select></label> ' +
      '<label>Outcome <select name="outcome">' + outcomeOptions +
      '</select></label> <button type="submit">Filter</button></form>';
    const rows = json.runs.map(function (r: Json): string {
      return '<tr><td><a href="' + admin.esc(PAGE + '?run=' +
                                             encodeURIComponent(r.runId)) +
        '"><code>' + admin.esc(r.runId) + '</code></a></td>' +
        '<td><code>' + admin.esc(r.jobId || '') + '</code></td>' +
        '<td><code>' + admin.esc(r.realm || '') + '</code></td>' +
        '<td>' + admin.esc(r.trigger) + '</td>' +
        '<td>' + admin.esc(r.nodeName || r.host || '—') +
        (r.pid ? ' <small>pid ' + admin.esc(r.pid) + '</small>' : '') +
        '</td><td class="num">' + (r.fenceAt || '—') + '</td>' +
        '<td class="num">' + r.attempt + '</td>' +
        '<td>' + self.outcomeText(r) + '</td>' +
        '<td class="num">' + (r.durationMs === null ? '—'
                               : r.durationMs + ' ms') + '</td>' +
        '<td><small>' + admin.esc(r.startedAt || r.queuedAt || '') +
        '</small></td></tr>';
    }).join('');
    log.debug("Leaving SchedulerAdmin.runsTable().");
    return '<h3>Recent runs</h3>' + filter + nav.head +
      '<table class="grid"><thead><tr><th>Run</th><th>Job</th>' +
      '<th>Realm</th><th>Trigger</th><th>Node</th><th>Fence</th>' +
      '<th>Attempt</th><th>Outcome</th><th>Duration</th><th>Started</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="10">No run is recorded.</td></tr>') +
      '</tbody></table>' + nav.foot;
  }

  private listHtml(req: Req, json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.listHtml().");
    const canWrite = admin.mayWrite(req);
    const off = json.jobs.filter(function (j: Json): boolean {
      return j.state === 'off';
    }).length;
    const failing = json.jobs.filter(function (j: Json): boolean {
      return j.lastRun && j.lastRun.state === 'failed';
    }).length;
    const tiles = '<div class="tiles">' +
      admin.tile(String(json.jobs.length), 'job rows') +
      admin.tile(String(off), 'off') +
      admin.tile(String(failing), 'last run failed') +
      admin.tile(String(json.tickS) + ' s', 'tick') +
      '</div>';
    const asOf = '<p><small>As of <code>' + admin.esc(json.generatedAt) +
      '</code> by ' + admin.esc(json.clock) + '\'s clock, drawn by ' +
      admin.esc(json.answeredBy.nodeName || json.answeredBy.host) +
      ', pid ' + admin.esc(json.answeredBy.pid) + '. <a href="' + PAGE +
      '">Refresh</a> — the times below do not count down.</small></p>';
    const what = admin.note(
      '<p>This page answers <strong>whether the background work is ' +
      'happening</strong>. Every periodic job in this service is registered ' +
      'with one scheduler and is listed here, including the ones that are ' +
      'off. A <em>cluster</em> job runs once for the whole service, on the ' +
      'scheduler\'s leader; a <em>per-process</em> job runs in every process ' +
      'that holds what it cleans, and has a row per process.</p>' +
      '<p>A job runs once per <strong>slot</strong> — a multiple of its ' +
      'interval by the database\'s clock, or an occurrence of its cron ' +
      'expression — so a slot missed while no node led runs once when one ' +
      'does. A run is claimed before it starts, and the claim\'s time is ' +
      'its <strong>fence</strong>: a node that paused past its claim cannot ' +
      'write an outcome over the attempt that took it over, which is shown ' +
      'as <em>abandoned</em>.</p>', 'What this page is');
    const unknown = json.unknownDisabledIds.length
      ? admin.warn('<code>scheduler.disabledJobs</code> names ' +
                   json.unknownDisabledIds.map(function (id: string) {
                     return '<code>' + admin.esc(id) + '</code>';
                   }).join(', ') + ', which no job is called.')
      : '';
    const disabled = json.enabled ? ''
      : admin.warn('<code>scheduler.enabled</code> is off: no job runs, on ' +
                   'its schedule or by hand.');
    const commands = json.commands.length
      ? '<h3>Commands</h3><table class="grid"><thead><tr><th>Command</th>' +
        '<th>State</th><th>Requested</th><th>By</th><th>Obeyed by</th>' +
        '</tr></thead><tbody>' + json.commands.map(function (c: Json) {
          return '<tr><td>' + admin.esc(c.command) + '</td><td>' +
            admin.esc(c.state) + '</td><td><small>' +
            admin.esc(c.queuedAt || '') + '</small></td><td>' +
            admin.esc(c.requestedBy || '—') + '</td><td>' +
            admin.esc(c.obeyedBy ? (c.obeyedBy.nodeName || c.obeyedBy.host) +
                      ' pid ' + c.obeyedBy.pid : '—') + '</td></tr>';
        }).join('') + '</tbody></table>'
      : '';
    log.debug("Leaving SchedulerAdmin.listHtml().");
    return admin.messagesOf(req) + tiles + asOf + disabled + unknown + what +
      this.leaderBlock(json, canWrite) + '<h3>Jobs</h3>' +
      this.jobsTable(json, canWrite) + this.runsTable(json, req.query || {}) +
      commands + (json.confinedToRealm ? ''
        : '<h2>Settings</h2>' + admin.configFormsFor(PAGE));
  }

  private detailHtml(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering SchedulerAdmin.detailHtml().");
    if (!json.found) {
      log.debug("Leaving SchedulerAdmin.detailHtml(). No such run.");
      return admin.warn('There is no run <code>' + admin.esc(json.run) +
        '</code> here. <a href="' + PAGE + '">Every recent run</a> is ' +
        'listed on the Scheduler page.');
    }
    const r = json.detail;
    const row = function (label: string, value: string): string {
      return '<tr><th>' + label + '</th><td>' + value + '</td></tr>';
    };
    log.debug("Leaving SchedulerAdmin.detailHtml().");
    return '<table class="grid"><tbody>' +
      row('Run', '<code>' + admin.esc(r.runId) + '</code>') +
      row('Job', '<code>' + admin.esc(r.jobId || '') + '</code>') +
      row('Realm', '<code>' + admin.esc(r.realm || '') + '</code>') +
      row('Trigger', admin.esc(r.trigger) +
          (r.requestedBy ? ' by ' + admin.esc(r.requestedBy) : '') +
          (r.requestedVia ? ' at ' + admin.esc(r.requestedVia) : '')) +
      row('Outcome', this.outcomeText(r)) +
      row('Attempt', String(r.attempt) + (r.takenOver
        ? ' (it took over an attempt that lost its claim)' : '')) +
      row('Fence', String(r.fenceAt || '—')) +
      row('Node', admin.esc(r.nodeName || r.host || '—') + (r.pid
        ? ', pid ' + admin.esc(r.pid) : '')) +
      row('Due', '<code>' + admin.esc(r.dueAt || '—') + '</code>') +
      row('Queued', '<code>' + admin.esc(r.queuedAt || '—') + '</code>') +
      row('Started', '<code>' + admin.esc(r.startedAt || '—') + '</code>') +
      row('Ended', '<code>' + admin.esc(r.endedAt || '—') + '</code>') +
      row('Duration', r.durationMs === null ? '—' : r.durationMs + ' ms') +
      row('Parameters', r.params ? '<code>' +
          admin.esc(JSON.stringify(r.params)) + '</code>' : '—') +
      row('Result', r.result ? '<code>' + admin.esc(String(r.result)) +
          '</code>' : '—') +
      (r.abandonedOf ? row('Abandoned attempt of', '<a href="' +
        admin.esc(PAGE + '?run=' + encodeURIComponent(r.abandonedOf)) +
        '"><code>' + admin.esc(r.abandonedOf) + '</code></a>') : '') +
      '</tbody></table>';
  }

  private async renderScheduler(req: Req, res: Res): Promise<void> {
    const { log, admin, errorCodes } = this.deps;
    log.debug("Entering SchedulerAdmin.renderScheduler().");
    const json: Json = await this.schedulerView(req, req.query);
    if (json.run === undefined) {
      admin.respond(req, res, json, 'Scheduler', PAGE,
                    this.listHtml(req, json));
      log.debug("Leaving SchedulerAdmin.renderScheduler(). The list.");
      return;
    }
    const title = json.found ? 'Run ' + json.run : 'No such run';
    if (!json.found) {
      errorCodes.mark(res, 'STS-SCHED-0016');
    }
    admin.respond(req, res, json, 'Scheduler — ' + title, PAGE,
                  this.detailHtml(json), admin.upTo(PAGE, title, {}));
    log.debug("Leaving SchedulerAdmin.renderScheduler(). One run.");
  }

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, admin, errorCodes, parseBody } = this.deps;
    const self = this;
    log.debug("Entering SchedulerAdmin.registerRoutes().");
    app.get(PAGE, function (req: Req, res: Res, next: Function): void {
      log.debug('Entering GET ' + PAGE + '.');
      self.renderScheduler(req, res).catch(function (e: Json): void {
        log.debug('Caught in GET ' + PAGE + ': ' + ((e && e.message) || e));
        next(e);
      });
      log.debug('Leaving GET ' + PAGE + '.');
    });
    app.post(PAGE, function (req: Req, res: Res): void {
      log.debug('Entering POST ' + PAGE + '.');
      if (!admin.mayWrite(req)) {
        errorCodes.mark(res, 'STS-ADMIN-0012');
        admin.respondToAction(req, res, PAGE, { ok: false, errors: [
          'This console session may read but not write.'] });
        log.debug('Leaving POST ' + PAGE + '. Read-only.');
        return;
      }
      const result = self.schedulerAction(req, parseBody(req),
                                          'the admin console');
      admin.respondToAction(req, res, result.ok && result.href
        ? result.href : PAGE, result);
      log.debug('Leaving POST ' + PAGE + '.');
    });
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

export = {
  registerRoutes: slot.forward('registerRoutes'),
  SchedulerAdmin: SchedulerAdmin,
  installInstance: (instance: SchedulerAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7): the page's own JSON and action.
  schedulerView: slot.forward('schedulerView'),
  schedulerAction: slot.forward('schedulerAction')
};
