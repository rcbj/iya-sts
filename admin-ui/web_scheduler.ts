// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_scheduler.ts
//
// ---------------------------------------------------------------------------
// MONITORING → SCHEDULER, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Scheduler from the answer of `GET /admin-api/scheduler`: every
// periodic job and its last and next run, the leader, the recent runs, and one
// run.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `SchedulerAdmin`'s in `admin-ui/scheduler_admin.ts`, moved
// with their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import SettingsForms = require('./web_settings');

type Json = any;

/**
 * The console path of Monitoring → Scheduler.
 */
const PAGE = '/admin/scheduler';

// What each state is called on the page (#539: in the reader's language, so
// a function over literal keys rather than a table of English words — the
// catalog test finds a key only where it is written out).
/**
 * Names a run's state on the page.
 *
 * @param state - the run's state
 * @param t - the page's translator
 * @returns the word as HTML, or the state itself when it has none
 */
function stateWord(state: string, t: Json): string {
  switch (state) {
    case 'succeeded':
      return t.html('consoleScheduler.state.succeeded');
    case 'failed':
      return t.html('consoleScheduler.state.failed');
    case 'abandoned':
      return t.html('consoleScheduler.state.abandoned');
    case 'running':
      return t.html('consoleScheduler.state.running');
    case 'queued':
      return t.html('consoleScheduler.state.queued');
    default:
      return kit.esc(state);
  }
}

// The outcome filter's options: the bare state names (`running`, not
// `running now`), as they always were.
/**
 * Names an option of the outcome filter.
 *
 * @param outcome - the option's value, '' for every outcome
 * @param t - the page's translator
 * @returns the label as HTML
 */
function outcomeLabel(outcome: string, t: Json): string {
  switch (outcome) {
    case '':
      return t.html('consoleScheduler.filter.everyOutcome');
    case 'succeeded':
      return t.html('consoleScheduler.filter.succeeded');
    case 'failed':
      return t.html('consoleScheduler.filter.failed');
    case 'abandoned':
      return t.html('consoleScheduler.filter.abandoned');
    case 'running':
      return t.html('consoleScheduler.filter.running');
    case 'queued':
      return t.html('consoleScheduler.filter.queued');
    default:
      return kit.esc(outcome);
  }
}

/**
 * Draws Scheduler from the answer of `GET /admin-api/scheduler`: every
 * periodic job and its last and next run, the leader, the recent runs, and one
 * run.
 *
 * A static utility class; it holds no state and takes no dependencies.
 * Every method that draws words takes the page's translator `t` (#539).
 */
class SchedulerPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return SchedulerPage.body(ctx, view);
  }

  // A repeated parameter arrives as an array; the first one wins.
  static firstOf(value: unknown): string {
    const one = Array.isArray(value) ? value[0] : value;
    return one === undefined || one === null || typeof one === 'object'
      ? '' : String(one).trim();
  }

  // -------------------------------------------------------------------------
  // THE DRAWING.
  // -------------------------------------------------------------------------
  static when(iso: string | null, inMs: number | null | undefined,
              t: Json): string {
    if (!iso) {
      return '—';
    }
    const rel = inMs === undefined || inMs === null ? ''
      : (inMs <= 0 ? t.html('consoleScheduler.when.now')
         : t.html('consoleScheduler.when.in', { span: kit.span(inMs) })) +
        '<br>';
    return rel + '<small><code>' + kit.esc(iso) + '</code></small>';
  }

  static outcomeText(run: Json, t: Json): string {
    let text = '<strong>' + stateWord(run.state, t) + '</strong>';
    if (run.errorCode) {
      text += ' <code>' + kit.esc(run.errorCode) + '</code>';
    }
    if (run.why) {
      text += '<br><small>' + kit.esc(run.why) + '</small>';
    }
    return text;
  }

  static lastRunCell(job: Json, t: Json): string {
    const parts: string[] = [];
    if (job.running) {
      parts.push(t.html('consoleScheduler.last.runningNow', {
        since: job.running.startedAt || '',
        node: job.running.nodeName || job.running.host,
        pid: job.running.pid, attempt: job.running.attempt }));
    }
    const last = job.lastRun;
    if (last) {
      parts.push('<a href="' + kit.esc(PAGE + '?run=' +
                                         encodeURIComponent(last.runId)) +
                 '">' + this.outcomeText(last, t).replace(/<br>.*$/, '') +
                 '</a><br><small>' + kit.esc(last.startedAt || '') +
                 ' → ' + kit.esc(last.endedAt || '') +
                 (last.durationMs !== null ? ', ' +
                  kit.esc(kit.span(last.durationMs)) +
                  ' (' + last.durationMs + ' ms)' : '') + ', ' +
                 kit.esc(last.trigger) + ', ' +
                 t.html('consoleScheduler.last.on',
                        { node: last.nodeName || last.host || '?' }) +
                 '</small>' +
                 (last.why ? '<br><small>' + kit.esc(last.why) +
                  '</small>' : ''));
    }
    if (!parts.length) {
      parts.push(t.html('consoleScheduler.last.never'));
    }
    return parts.join('<br>');
  }

  static nextRunCell(job: Json, t: Json): string {
    let text: string;
    switch (job.nextRunState) {
      case 'off':
        text = '—';
        break;
      case 'manual-only':
        text = t.html('consoleScheduler.next.manualOnly');
        break;
      case 'queued':
        // The requester is a person's name, kept out of the message so it
        // is escaped exactly as it always was.
        text = t.html('consoleScheduler.next.queuedA') + ' ' +
               kit.esc(job.queued[0].requestedBy ||
                       t.text('consoleScheduler.next.somebody')) +
               t.html('consoleScheduler.next.queuedB') + '<br>' +
               '<small><code>' + kit.esc(job.queued[0].queuedAt || '') +
               '</code></small>';
        break;
      case 'due':
        text = t.html('consoleScheduler.next.due') +
               '<br><small><code>' + kit.esc(job.nextRunAt) +
               '</code></small>';
        break;
      case 'overdue':
        text = t.html('consoleScheduler.next.overdue') + ' <code>' +
               kit.esc(job.overdueSince) + '</code><br><small>' +
               kit.esc(job.overdueWhy || '') + '</small>';
        break;
      case 'running':
        text = t.html('consoleScheduler.next.afterThisRun') + ' ' +
               this.when(job.nextRunAt, job.nextRunInMs, t);
        break;
      default:
        text = this.when(job.nextRunAt, job.nextRunInMs, t);
    }
    return text;
  }

  static runNowCell(job: Json, canWrite: boolean, t: Json): string {
    if (!canWrite || !job.manual || job.readOnly || job.state === 'off') {
      return job.state === 'off' && job.manual
        ? '<small>' + t.html('consoleScheduler.jobs.off') + '</small>' : '—';
    }
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="run">' +
      '<input type="hidden" name="job" value="' + kit.esc(job.id) + '">' +
      '<input type="hidden" name="realm" value="' + kit.esc(job.realm) +
      '">' +
      '<button type="submit" id="scheduler-run-' + kit.esc(job.id) + '-' +
      kit.esc(job.realm) + '">' + t.html('consoleScheduler.jobs.runNow') +
      '</button></form>';
  }

  static jobsTable(json: Json, canWrite: boolean, query: Json,
                   t: Json): string {
    const self = this;
    const nav = kit.pageNavPair(PAGE, kit.pageParamsOf(query),
                                  json.jobsPaging);
    const rows = json.jobs.map(function (job: Json): string {
      const state = job.state === 'off'
        ? '<strong>' + t.html('consoleScheduler.jobs.off') +
          '</strong><br><small>' + kit.esc(job.offReason) +
          '</small>'
        : t.html('consoleScheduler.jobs.enabled') +
          (job.readOnly ? '<br><small>' +
           t.html('consoleScheduler.jobs.readOnly') + '</small>' : '');
      const head = '<tr id="job-' + kit.esc(job.id) + '-' +
        kit.esc(job.realm) + '">' +
        '<td><a href="' + kit.esc(PAGE + '?job=' +
                                    encodeURIComponent(job.id)) +
        '"><code>' + kit.esc(job.id) + '</code></a><br>' +
        kit.esc(job.title) + '<br><small>' + kit.esc(job.describe) +
        '</small><br><small>' +
        t.html('consoleScheduler.jobs.owner', { owner: job.owner }) +
        '</small></td>' +
        '<td>' + kit.esc(job.kind) + '<br><small>' +
        kit.esc(job.scope) + (job.scope === 'realm'
          ? ': <code>' + kit.esc(job.realm) + '</code>' : '') +
        '</small></td>' +
        '<td>' + kit.esc(job.schedule.text) + '</td>' +
        '<td>' + state + '</td>' +
        '<td>' + (job.kind === 'per-process'
          ? t.html('consoleScheduler.jobs.perProcess')
          : self.lastRunCell(job, t)) + '</td>' +
        '<td>' + self.nextRunCell(job, t) + '</td>' +
        '<td>' + self.runNowCell(job, canWrite, t) + '</td></tr>';
      const subs = (job.processes || []).map(function (p: Json): string {
        return '<tr class="sub"><td colspan="4"><small>↳ ' +
          kit.esc(p.nodeName || p.host) + ', pid ' + kit.esc(p.pid) +
          ' ' + (p.worker ? t.html('consoleScheduler.jobs.requestWorker')
                          : t.html('consoleScheduler.jobs.frontProcess')) +
          (p.stale ? ' — <strong>' + t.html('consoleScheduler.jobs.stale') +
           '</strong>' : '') + '</small></td><td>' +
          self.outcomeText(p, t) + '<br><small>' +
          kit.esc(p.startedAt || '') + '</small></td><td>' +
          self.when(p.nextRunAt, p.nextRunInMs, t) + '</td><td></td></tr>';
      }).join('');
      const noProcess = job.kind === 'per-process' &&
        !(job.processes || []).length
        ? '<tr class="sub"><td colspan="7"><small>↳ ' +
          t.html('consoleScheduler.jobs.noProcess') + '</small></td></tr>'
        : '';
      return head + subs + noProcess;
    }).join('');
    return nav.head + '<table class="grid"><thead><tr><th>' +
      t.html('consoleScheduler.th.job') + '</th>' +
      '<th>' + t.html('consoleScheduler.th.kindScope') + '</th><th>' +
      t.html('consoleScheduler.th.schedule') + '</th><th>' +
      t.html('consoleScheduler.th.state') + '</th>' +
      '<th>' + t.html('consoleScheduler.th.lastRun') + '</th><th>' +
      t.html('consoleScheduler.th.nextRun') + '</th><th>' +
      t.html('consoleScheduler.th.runNow') + '</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="7">' +
               t.html('consoleScheduler.jobs.none') + '</td></tr>') +
      '</tbody></table>' + nav.foot;
  }

  static leaderBlock(json: Json, canWrite: boolean, t: Json): string {
    const l = json.leader || {};
    let who: string;
    if (!l.known) {
      who = t.html('consoleScheduler.leader.none');
    } else {
      who = (l.thisProcess
        ? t.html('consoleScheduler.leader.thisProcess') + ' ' : '') +
        t.html('consoleScheduler.leader.node',
               { node: l.nodeName || l.host, pid: l.pid }) + (l.clustered
          ? t.html('consoleScheduler.leader.clustered',
                   { node: l.node, token: l.token })
          : ' ' + t.html('consoleScheduler.leader.notClustered')) +
        '<br><small>' +
        t.html('consoleScheduler.leader.since', { since: l.since || '?' }) +
        (l.leaseAcquiredAt ? ' ' +
         t.html('consoleScheduler.leader.leaseAcquired',
                { at: l.leaseAcquiredAt }) : '') +
        t.html('consoleScheduler.leader.lastTick',
               { at: l.lastTickAt || '?' }) +
        (l.lastTickAgoMs !== null ? ', ' +
         t.html('consoleScheduler.leader.ago',
                { span: kit.span(l.lastTickAgoMs) }) : '') + '</small>' +
        (l.live ? '' : kit.warn(t.html('consoleScheduler.leader.stalled')));
    }
    const stepDown = canWrite && l.clustered && !json.confinedToRealm
      ? '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="step-down">' +
        '<button type="submit" id="scheduler-step-down">' +
        t.html('consoleScheduler.leader.stepDown') + '</button>' +
        '</form> <small>' + t.html('consoleScheduler.leader.stepDownWhat') +
        '</small>'
      : '';
    return '<h3>' + t.html('consoleScheduler.leader.heading') + '</h3><p>' +
      who + '</p>' + stepDown;
  }

  static runsTable(json: Json, query: Json, t: Json): string {
    const self = this;
    const params = kit.pageParamsOf(query);
    ['job', 'outcome'].forEach(function (name: string): void {
      const value = self.firstOf(query[name]);
      if (value) {
        params[name] = value;
      }
    });
    const nav = kit.pageNavPair(PAGE, params, json.runsPaging);
    const jobOptions = ['<option value="">' +
      t.html('consoleScheduler.filter.everyJob') + '</option>'].concat(
      ((json.jobIds || []) as string[]).map(function (id: string): string {
        return '<option value="' + kit.esc(id) + '"' +
          (json.filters.job === id ? ' selected' : '') + '>' +
          kit.esc(id) + '</option>';
      })).join('');
    const outcomeOptions = ['', 'succeeded', 'failed', 'abandoned',
                            'running', 'queued'].map(function (o: string) {
      return '<option value="' + o + '"' +
        ((json.filters.outcome || '') === o ? ' selected' : '') + '>' +
        outcomeLabel(o, t) + '</option>';
    }).join('');
    const filter = '<form method="get" action="' + PAGE + '" class="inline">' +
      '<label>' + t.html('consoleScheduler.filter.job') +
      ' <select name="job">' + jobOptions + '</select></label> ' +
      '<label>' + t.html('consoleScheduler.filter.outcome') +
      ' <select name="outcome">' + outcomeOptions +
      '</select></label> <button type="submit">' +
      t.html('consoleScheduler.filter.submit') + '</button></form>';
    const rows = json.runs.map(function (r: Json): string {
      return '<tr><td><a href="' + kit.esc(PAGE + '?run=' +
                                             encodeURIComponent(r.runId)) +
        '"><code>' + kit.esc(r.runId) + '</code></a></td>' +
        '<td><code>' + kit.esc(r.jobId || '') + '</code></td>' +
        '<td><code>' + kit.esc(r.realm || '') + '</code></td>' +
        '<td>' + kit.esc(r.trigger) + '</td>' +
        '<td>' + kit.esc(r.nodeName || r.host || '—') +
        (r.pid ? ' <small>pid ' + kit.esc(r.pid) + '</small>' : '') +
        '</td><td class="num">' + (r.fenceAt || '—') + '</td>' +
        '<td class="num">' + r.attempt + '</td>' +
        '<td>' + self.outcomeText(r, t) + '</td>' +
        '<td class="num">' + (r.durationMs === null ? '—'
                               : r.durationMs + ' ms') + '</td>' +
        '<td><small>' + kit.esc(r.startedAt || r.queuedAt || '') +
        '</small></td></tr>';
    }).join('');
    return '<h3>' + t.html('consoleScheduler.runs.heading') + '</h3>' +
      filter + nav.head +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleScheduler.th.run') + '</th><th>' +
      t.html('consoleScheduler.th.job') + '</th>' +
      '<th>' + t.html('consoleScheduler.th.realm') + '</th><th>' +
      t.html('consoleScheduler.th.trigger') + '</th><th>' +
      t.html('consoleScheduler.th.node') + '</th><th>' +
      t.html('consoleScheduler.th.fence') + '</th>' +
      '<th>' + t.html('consoleScheduler.th.attempt') + '</th><th>' +
      t.html('consoleScheduler.th.outcome') + '</th><th>' +
      t.html('consoleScheduler.th.duration') + '</th><th>' +
      t.html('consoleScheduler.th.started') + '</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="10">' +
               t.html('consoleScheduler.runs.none') + '</td></tr>') +
      '</tbody></table>' + nav.foot;
  }

  static listHtml(ctx: Json, json: Json): string {
    const t = ctx.t;
    const canWrite = ctx.write;
    const off = json.jobs.filter(function (j: Json): boolean {
      return j.state === 'off';
    }).length;
    const failing = json.jobs.filter(function (j: Json): boolean {
      return j.lastRun && j.lastRun.state === 'failed';
    }).length;
    const tiles = '<div class="tiles">' +
      kit.tile(String(json.jobs.length),
               t.text('consoleScheduler.tile.jobRows')) +
      kit.tile(String(off), t.text('consoleScheduler.tile.off')) +
      kit.tile(String(failing), t.text('consoleScheduler.tile.failed')) +
      kit.tile(String(json.tickS) + ' s',
               t.text('consoleScheduler.tile.tick')) +
      '</div>';
    const asOf = '<p><small>' + t.html('consoleScheduler.asOf', {
      at: json.generatedAt, clock: json.clock,
      node: json.answeredBy.nodeName || json.answeredBy.host,
      pid: json.answeredBy.pid }) + ' <a href="' + PAGE +
      '">' + t.html('consoleScheduler.refresh') + '</a> ' +
      t.html('consoleScheduler.noCountdown') + '</small></p>';
    // A `<p>` is markup no message carries, so each paragraph is a message.
    const what = kit.note(
      '<p>' + t.html('consoleScheduler.what.p1') + '</p>' +
      '<p>' + t.html('consoleScheduler.what.p2') + '</p>',
      t.html('consoleScheduler.what.label'));
    const unknown = json.unknownDisabledIds.length
      ? kit.warn(t.html('consoleScheduler.unknownA') + ' ' +
                   json.unknownDisabledIds.map(function (id: string) {
                     return '<code>' + kit.esc(id) + '</code>';
                   }).join(', ') + t.html('consoleScheduler.unknownB'))
      : '';
    const disabled = json.enabled ? ''
      : kit.warn(t.html('consoleScheduler.disabled'));
    const commands = json.commands.length
      ? '<h3>' + t.html('consoleScheduler.commands.heading') +
        '</h3><table class="grid"><thead><tr><th>' +
        t.html('consoleScheduler.th.command') + '</th>' +
        '<th>' + t.html('consoleScheduler.th.state') + '</th><th>' +
        t.html('consoleScheduler.th.requested') + '</th><th>' +
        t.html('consoleScheduler.th.by') + '</th><th>' +
        t.html('consoleScheduler.th.obeyedBy') + '</th>' +
        '</tr></thead><tbody>' + json.commands.map(function (c: Json) {
          return '<tr><td>' + kit.esc(c.command) + '</td><td>' +
            kit.esc(c.state) + '</td><td><small>' +
            kit.esc(c.queuedAt || '') + '</small></td><td>' +
            kit.esc(c.requestedBy || '—') + '</td><td>' +
            kit.esc(c.obeyedBy ? (c.obeyedBy.nodeName || c.obeyedBy.host) +
                      ' pid ' + c.obeyedBy.pid : '—') + '</td></tr>';
        }).join('') + '</tbody></table>'
      : '';
    return tiles + asOf + disabled + unknown + what +
      this.leaderBlock(json, canWrite, t) + '<h3>' +
      t.html('consoleScheduler.jobs.heading') + '</h3>' +
      this.jobsTable(json, canWrite, ctx.query || {}, t) +
      this.runsTable(json, ctx.query || {}, t) +
      commands + (json.confinedToRealm ? ''
        : '<h2>' + t.html('consoleScheduler.settings.heading') + '</h2>' +
          SettingsForms.forms(json.settings, PAGE, undefined,
                              t));
  }

  static detailHtml(json: Json, t: Json): string {
    if (!json.found) {
      // A run that is not there is a refusal, and refusals stay English
      // (#539, decision 6).
      return kit.warn('There is no run <code>' + kit.esc(json.run) +
        '</code> here. <a href="' + PAGE + '">Every recent run</a> is ' +
        'listed on the Scheduler page.');
    }
    const r = json.detail;
    const row = function (label: string, value: string): string {
      return '<tr><th>' + label + '</th><td>' + value + '</td></tr>';
    };
    return '<table class="grid"><tbody>' +
      row(t.html('consoleScheduler.th.run'),
          '<code>' + kit.esc(r.runId) + '</code>') +
      row(t.html('consoleScheduler.th.job'),
          '<code>' + kit.esc(r.jobId || '') + '</code>') +
      row(t.html('consoleScheduler.th.realm'),
          '<code>' + kit.esc(r.realm || '') + '</code>') +
      row(t.html('consoleScheduler.th.trigger'), kit.esc(r.trigger) +
          (r.requestedBy ? ' ' + t.html('consoleScheduler.detail.by') + ' ' +
           kit.esc(r.requestedBy) : '') +
          (r.requestedVia ? ' ' + t.html('consoleScheduler.detail.at') +
           ' ' + kit.esc(r.requestedVia) : '')) +
      row(t.html('consoleScheduler.th.outcome'), this.outcomeText(r, t)) +
      row(t.html('consoleScheduler.th.attempt'), String(r.attempt) +
          (r.takenOver
           ? ' ' + t.html('consoleScheduler.detail.tookOver') : '')) +
      row(t.html('consoleScheduler.th.fence'), String(r.fenceAt || '—')) +
      row(t.html('consoleScheduler.th.node'),
          kit.esc(r.nodeName || r.host || '—') + (r.pid
        ? ', pid ' + kit.esc(r.pid) : '')) +
      row(t.html('consoleScheduler.detail.due'),
          '<code>' + kit.esc(r.dueAt || '—') + '</code>') +
      row(t.html('consoleScheduler.detail.queued'),
          '<code>' + kit.esc(r.queuedAt || '—') + '</code>') +
      row(t.html('consoleScheduler.th.started'),
          '<code>' + kit.esc(r.startedAt || '—') + '</code>') +
      row(t.html('consoleScheduler.detail.ended'),
          '<code>' + kit.esc(r.endedAt || '—') + '</code>') +
      row(t.html('consoleScheduler.th.duration'),
          r.durationMs === null ? '—' : r.durationMs + ' ms') +
      row(t.html('consoleScheduler.detail.params'), r.params ? '<code>' +
          kit.esc(JSON.stringify(r.params)) + '</code>' : '—') +
      row(t.html('consoleScheduler.detail.result'), r.result ? '<code>' +
          kit.esc(String(r.result)) + '</code>' : '—') +
      (r.abandonedOf ? row(t.html('consoleScheduler.detail.abandonedOf'),
        '<a href="' +
        kit.esc(PAGE + '?run=' + encodeURIComponent(r.abandonedOf)) +
        '"><code>' + kit.esc(r.abandonedOf) + '</code></a>') : '') +
      '</tbody></table>';
  }

  // THE PAGE'S BODY, the list or one run (#446): one method, so that it can
  // be one renderer. The notice and error banner stays outside it.
  /**
   * Draws the page's body: every job and recent run, or one run.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json): string {
    return json.run === undefined ? this.listHtml(ctx, json)
      : this.detailHtml(json, ctx.t);
  }
}

export = SchedulerPage;
