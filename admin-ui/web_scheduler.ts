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

// What each state is called on the page.
const STATE_WORDS: Json = {
  succeeded: 'succeeded', failed: 'failed', abandoned: 'abandoned',
  running: 'running now', queued: 'queued'
};

/**
 * Draws Scheduler from the answer of `GET /admin-api/scheduler`: every
 * periodic job and its last and next run, the leader, the recent runs, and one
 * run.
 *
 * A static utility class; it holds no state and takes no dependencies.
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
  static when(iso: string | null, inMs?: number | null): string {
    if (!iso) {
      return '—';
    }
    const rel = inMs === undefined || inMs === null ? ''
      : (inMs <= 0 ? 'now' : 'in ' + kit.span(inMs)) +
        '<br>';
    return rel + '<small><code>' + kit.esc(iso) + '</code></small>';
  }

  static outcomeText(run: Json): string {
    const word = STATE_WORDS[run.state] || run.state;
    let text = '<strong>' + kit.esc(word) + '</strong>';
    if (run.errorCode) {
      text += ' <code>' + kit.esc(run.errorCode) + '</code>';
    }
    if (run.why) {
      text += '<br><small>' + kit.esc(run.why) + '</small>';
    }
    return text;
  }

  static lastRunCell(job: Json): string {
    const parts: string[] = [];
    if (job.running) {
      parts.push('<strong>running now</strong> since <code>' +
                 kit.esc(job.running.startedAt || '') + '</code> on ' +
                 kit.esc(job.running.nodeName || job.running.host) +
                 ' (pid ' + kit.esc(job.running.pid) + ', attempt ' +
                 job.running.attempt + ')');
    }
    const last = job.lastRun;
    if (last) {
      parts.push('<a href="' + kit.esc(PAGE + '?run=' +
                                         encodeURIComponent(last.runId)) +
                 '">' + this.outcomeText(last).replace(/<br>.*$/, '') +
                 '</a><br><small>' + kit.esc(last.startedAt || '') +
                 ' → ' + kit.esc(last.endedAt || '') +
                 (last.durationMs !== null ? ', ' +
                  kit.esc(kit.span(last.durationMs)) +
                  ' (' + last.durationMs + ' ms)' : '') + ', ' +
                 kit.esc(last.trigger) + ', on ' +
                 kit.esc(last.nodeName || last.host || '?') + '</small>' +
                 (last.why ? '<br><small>' + kit.esc(last.why) +
                  '</small>' : ''));
    }
    if (!parts.length) {
      parts.push('<em>never run</em>');
    }
    return parts.join('<br>');
  }

  static nextRunCell(job: Json): string {
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
               kit.esc(job.queued[0].requestedBy || 'somebody') + ')<br>' +
               '<small><code>' + kit.esc(job.queued[0].queuedAt || '') +
               '</code></small>';
        break;
      case 'due':
        text = '<strong>due now</strong> — waiting for the leader\'s next ' +
               'tick<br><small><code>' + kit.esc(job.nextRunAt) +
               '</code></small>';
        break;
      case 'overdue':
        text = '<strong>overdue since</strong> <code>' +
               kit.esc(job.overdueSince) + '</code><br><small>' +
               kit.esc(job.overdueWhy || '') + '</small>';
        break;
      case 'running':
        text = 'after this run; next slot ' +
               this.when(job.nextRunAt, job.nextRunInMs);
        break;
      default:
        text = this.when(job.nextRunAt, job.nextRunInMs);
    }
    return text;
  }

  static runNowCell(job: Json, canWrite: boolean): string {
    if (!canWrite || !job.manual || job.readOnly || job.state === 'off') {
      return job.state === 'off' && job.manual
        ? '<small>off</small>' : '—';
    }
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="run">' +
      '<input type="hidden" name="job" value="' + kit.esc(job.id) + '">' +
      '<input type="hidden" name="realm" value="' + kit.esc(job.realm) +
      '">' +
      '<button type="submit" id="scheduler-run-' + kit.esc(job.id) + '-' +
      kit.esc(job.realm) + '">Run now</button></form>';
  }

  static jobsTable(json: Json, canWrite: boolean, query: Json): string {
    const self = this;
    const nav = kit.pageNavPair(PAGE, kit.pageParamsOf(query),
                                  json.jobsPaging);
    const rows = json.jobs.map(function (job: Json): string {
      const state = job.state === 'off'
        ? '<strong>off</strong><br><small>' + kit.esc(job.offReason) +
          '</small>'
        : 'enabled' + (job.readOnly ? '<br><small>read-only here: a ' +
                       'service job</small>' : '');
      const head = '<tr id="job-' + kit.esc(job.id) + '-' +
        kit.esc(job.realm) + '">' +
        '<td><a href="' + kit.esc(PAGE + '?job=' +
                                    encodeURIComponent(job.id)) +
        '"><code>' + kit.esc(job.id) + '</code></a><br>' +
        kit.esc(job.title) + '<br><small>' + kit.esc(job.describe) +
        '</small><br><small>owner <code>' + kit.esc(job.owner) +
        '</code></small></td>' +
        '<td>' + kit.esc(job.kind) + '<br><small>' +
        kit.esc(job.scope) + (job.scope === 'realm'
          ? ': <code>' + kit.esc(job.realm) + '</code>' : '') +
        '</small></td>' +
        '<td>' + kit.esc(job.schedule.text) + '</td>' +
        '<td>' + state + '</td>' +
        '<td>' + (job.kind === 'per-process'
          ? '<em>per process, below</em>' : self.lastRunCell(job)) + '</td>' +
        '<td>' + self.nextRunCell(job) + '</td>' +
        '<td>' + self.runNowCell(job, canWrite) + '</td></tr>';
      const subs = (job.processes || []).map(function (p: Json): string {
        return '<tr class="sub"><td colspan="4"><small>↳ ' +
          kit.esc(p.nodeName || p.host) + ', pid ' + kit.esc(p.pid) +
          (p.worker ? ' (request worker)' : ' (front process)') +
          (p.stale ? ' — <strong>no run for two slots; the process has ' +
           'probably gone</strong>' : '') + '</small></td><td>' +
          self.outcomeText(p) + '<br><small>' +
          kit.esc(p.startedAt || '') + '</small></td><td>' +
          self.when(p.nextRunAt, p.nextRunInMs) + '</td><td></td></tr>';
      }).join('');
      const noProcess = job.kind === 'per-process' &&
        !(job.processes || []).length
        ? '<tr class="sub"><td colspan="7"><small>↳ no process has run ' +
          'it yet</small></td></tr>' : '';
      return head + subs + noProcess;
    }).join('');
    return nav.head + '<table class="grid"><thead><tr><th>Job</th>' +
      '<th>Kind and scope</th><th>Schedule</th><th>State</th>' +
      '<th>Last run</th><th>Time to next run</th><th>Run now</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="7">No job is registered.</td></tr>') +
      '</tbody></table>' + nav.foot;
  }

  static leaderBlock(json: Json, canWrite: boolean): string {
    const l = json.leader || {};
    let who: string;
    if (!l.known) {
      who = '<strong>No process has led the scheduler yet.</strong> The ' +
            'leader writes a row when it takes the lead and at every tick.';
    } else {
      who = (l.thisProcess ? '<strong>This process</strong> — ' : '') +
        '<strong>' + kit.esc(l.nodeName || l.host) + '</strong>, pid ' +
        kit.esc(l.pid) + (l.clustered
          ? ', node <code>' + kit.esc(l.node) + '</code>, lease token ' +
            kit.esc(l.token) : ' — <em>not clustered</em>: the one front ' +
            'process leads, and nothing else could') +
        '<br><small>leading since <code>' + kit.esc(l.since || '?') +
        '</code>' + (l.leaseAcquiredAt ? ' (the lease was acquired ' +
        '<code>' + kit.esc(l.leaseAcquiredAt) + '</code>)' : '') +
        '; last tick <code>' + kit.esc(l.lastTickAt || '?') + '</code>' +
        (l.lastTickAgoMs !== null ? ', ' +
         kit.esc(kit.span(l.lastTickAgoMs)) +
         ' ago' : '') + '</small>' +
        (l.live ? '' : kit.warn('The leader has not ticked for longer ' +
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
    return '<h3>Leader</h3><p>' + who + '</p>' + stepDown;
  }

  static runsTable(json: Json, query: Json): string {
    const self = this;
    const params = kit.pageParamsOf(query);
    ['job', 'outcome'].forEach(function (name: string): void {
      const value = self.firstOf(query[name]);
      if (value) {
        params[name] = value;
      }
    });
    const nav = kit.pageNavPair(PAGE, params, json.runsPaging);
    const jobOptions = ['<option value="">every job</option>'].concat(
      ((json.jobIds || []) as string[]).map(function (id: string): string {
        return '<option value="' + kit.esc(id) + '"' +
          (json.filters.job === id ? ' selected' : '') + '>' +
          kit.esc(id) + '</option>';
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
        '<td>' + self.outcomeText(r) + '</td>' +
        '<td class="num">' + (r.durationMs === null ? '—'
                               : r.durationMs + ' ms') + '</td>' +
        '<td><small>' + kit.esc(r.startedAt || r.queuedAt || '') +
        '</small></td></tr>';
    }).join('');
    return '<h3>Recent runs</h3>' + filter + nav.head +
      '<table class="grid"><thead><tr><th>Run</th><th>Job</th>' +
      '<th>Realm</th><th>Trigger</th><th>Node</th><th>Fence</th>' +
      '<th>Attempt</th><th>Outcome</th><th>Duration</th><th>Started</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="10">No run is recorded.</td></tr>') +
      '</tbody></table>' + nav.foot;
  }

  static listHtml(ctx: Json, json: Json): string {
    const canWrite = ctx.write;
    const off = json.jobs.filter(function (j: Json): boolean {
      return j.state === 'off';
    }).length;
    const failing = json.jobs.filter(function (j: Json): boolean {
      return j.lastRun && j.lastRun.state === 'failed';
    }).length;
    const tiles = '<div class="tiles">' +
      kit.tile(String(json.jobs.length), 'job rows') +
      kit.tile(String(off), 'off') +
      kit.tile(String(failing), 'last run failed') +
      kit.tile(String(json.tickS) + ' s', 'tick') +
      '</div>';
    const asOf = '<p><small>As of <code>' + kit.esc(json.generatedAt) +
      '</code> by ' + kit.esc(json.clock) + '\'s clock, drawn by ' +
      kit.esc(json.answeredBy.nodeName || json.answeredBy.host) +
      ', pid ' + kit.esc(json.answeredBy.pid) + '. <a href="' + PAGE +
      '">Refresh</a> — the times below do not count down.</small></p>';
    const what = kit.note(
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
      ? kit.warn('<code>scheduler.disabledJobs</code> names ' +
                   json.unknownDisabledIds.map(function (id: string) {
                     return '<code>' + kit.esc(id) + '</code>';
                   }).join(', ') + ', which no job is called.')
      : '';
    const disabled = json.enabled ? ''
      : kit.warn('<code>scheduler.enabled</code> is off: no job runs, on ' +
                   'its schedule or by hand.');
    const commands = json.commands.length
      ? '<h3>Commands</h3><table class="grid"><thead><tr><th>Command</th>' +
        '<th>State</th><th>Requested</th><th>By</th><th>Obeyed by</th>' +
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
      this.leaderBlock(json, canWrite) + '<h3>Jobs</h3>' +
      this.jobsTable(json, canWrite, ctx.query || {}) +
      this.runsTable(json, ctx.query || {}) +
      commands + (json.confinedToRealm ? ''
        : '<h2>Settings</h2>' + SettingsForms.forms(json.settings, PAGE));
  }

  static detailHtml(json: Json): string {
    if (!json.found) {
      return kit.warn('There is no run <code>' + kit.esc(json.run) +
        '</code> here. <a href="' + PAGE + '">Every recent run</a> is ' +
        'listed on the Scheduler page.');
    }
    const r = json.detail;
    const row = function (label: string, value: string): string {
      return '<tr><th>' + label + '</th><td>' + value + '</td></tr>';
    };
    return '<table class="grid"><tbody>' +
      row('Run', '<code>' + kit.esc(r.runId) + '</code>') +
      row('Job', '<code>' + kit.esc(r.jobId || '') + '</code>') +
      row('Realm', '<code>' + kit.esc(r.realm || '') + '</code>') +
      row('Trigger', kit.esc(r.trigger) +
          (r.requestedBy ? ' by ' + kit.esc(r.requestedBy) : '') +
          (r.requestedVia ? ' at ' + kit.esc(r.requestedVia) : '')) +
      row('Outcome', this.outcomeText(r)) +
      row('Attempt', String(r.attempt) + (r.takenOver
        ? ' (it took over an attempt that lost its claim)' : '')) +
      row('Fence', String(r.fenceAt || '—')) +
      row('Node', kit.esc(r.nodeName || r.host || '—') + (r.pid
        ? ', pid ' + kit.esc(r.pid) : '')) +
      row('Due', '<code>' + kit.esc(r.dueAt || '—') + '</code>') +
      row('Queued', '<code>' + kit.esc(r.queuedAt || '—') + '</code>') +
      row('Started', '<code>' + kit.esc(r.startedAt || '—') + '</code>') +
      row('Ended', '<code>' + kit.esc(r.endedAt || '—') + '</code>') +
      row('Duration', r.durationMs === null ? '—' : r.durationMs + ' ms') +
      row('Parameters', r.params ? '<code>' +
          kit.esc(JSON.stringify(r.params)) + '</code>' : '—') +
      row('Result', r.result ? '<code>' + kit.esc(String(r.result)) +
          '</code>' : '—') +
      (r.abandonedOf ? row('Abandoned attempt of', '<a href="' +
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
      : this.detailHtml(json);
  }
}

export = SchedulerPage;
