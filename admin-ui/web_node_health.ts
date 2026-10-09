// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_node_health.ts
//
// ---------------------------------------------------------------------------
// MONITORING → NODE HEALTH, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Monitoring → Node Health from the answer of `GET
// /admin-api/node-health`: the cluster's totals and, for each node, its
// container's CPU and memory, every process and worker thread, the ECS agent's
// figures and the machine's own.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `NodeHealthAdmin`'s in `admin-ui/node_health_admin.ts`,
// moved with their comments; that module still draws the page until the
// console's cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

// One mebibyte: the unit every memory figure is drawn in. The module that
// builds the view (`node_health_admin.ts`) has the same constant; a `web_`
// module may not require it.
const MIB = 1024 * 1024;

// A VALUE THE VIEW CARRIES, INSIDE A TRANSLATED SENTENCE (#539 phase 6). A
// message's parameters are escaped by the translator, which writes an
// apostrophe as `&#39;` where `kit.esc()` writes `&apos;`; so a sentence
// that carries the view's own words is formatted with this mark in the
// value's place and the value, escaped by `kit.esc()` as before, put in
// after. English stays the bytes it was.
const MARK = '\u0001';

/**
 * Draws Monitoring → Node Health from the answer of `GET
 * /admin-api/node-health`: the cluster's totals and, for each node, its
 * container's CPU and memory, every process and worker thread, the ECS agent's
 * figures and the machine's own.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class NodeHealthPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`); the server's
   *   own drawing passes none, and gets English
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return NodeHealthPage.clusterHtml(view, ctx || kit.context());
  }

  // A formatted message with `MARK` replaced by markup already escaped.
  static put(message: string, html: string): string {
    return message.split(MARK).join(html);
  }

  // One decimal place, as a number. `NodeHealthAdmin.round1()`, which the
  // view is built with, written out here for the reason `MIB` is.
  static round1(n: number): number {
    return Math.round(n * 10) / 10;
  }

  // Bytes as MiB, or a dash for a figure that is not there.
  static mib(value: unknown): string {
    return typeof value === 'number' ? (value / MIB).toFixed(1) + ' MiB'
                                     : '—';
  }

  // A percentage, or a dash.
  static pct(value: unknown): string {
    return typeof value === 'number' ? value.toFixed(1) + ' %' : '—';
  }

  // A table of three columns: label, value and why.
  static rows(items: [string, string, string][]): string {
    return '<table class="grid"><tbody>' +
      items.map(function (one: [string, string, string]): string {
        return '<tr><th>' + kit.esc(one[0]) + '</th><td>' + one[1] +
          '</td><td><small>' + one[2] + '</small></td></tr>';
      }).join('') + '</tbody></table>';
  }

  // "Not available:" and the view's reason, under a section's heading.
  static notAvailableHtml(t: Json, why: unknown): string {
    return '<p><strong>' + t.html('consoleNodeHealth.notAvailable') +
      '</strong> ' + kit.esc(why) + '</p>';
  }

  // Each section below is handed the page's translator `t` by its caller
  // (#539); a local that was called `t` before — the throttling figures,
  // the totals — has a longer name now.
  static cpuHtml(cpu: Json, t: Json): string {
    const head = '<h2 id="cpu">' + t.html('consoleNodeHealth.headCpu') +
      '</h2>';
    if (!cpu.available) {
      return head + this.notAvailableHtml(t, cpu.unavailableText);
    }
    const thr = cpu.throttling;
    if (cpu.fromEcs) {
      const ecsHtml = head + '<p>' + kit.esc(cpu.limitText) + '</p>' +
        this.rows([
          [t.text('consoleNodeHealth.utilisation'),
           kit.esc(this.pct(cpu.utilisationPercent)),
           cpu.percentOfVcpus
             ? t.html('consoleNodeHealth.ecsCoresOf',
                      { cores: String(cpu.coresUsed),
                        of: String(cpu.percentOfVcpus) })
             : t.html('consoleNodeHealth.ecsCores',
                      { cores: String(cpu.coresUsed) })]
        ]) + '<p><small>' + t.html('consoleNodeHealth.theCgroup') + ' ' +
        kit.esc(cpu.cgroupUnavailableText || '') + '</small></p>';
      return ecsHtml;
    }
    const html = head + '<p>' + kit.esc(cpu.limitText) + '</p>' +
      this.rows([
        [t.text('consoleNodeHealth.utilisation'),
         kit.esc(this.pct(cpu.utilisationPercent)),
         t.html('consoleNodeHealth.utilisationWhy',
                { cores: String(cpu.coresUsed),
                  of: String(cpu.percentOfVcpus),
                  seconds: String(cpu.windowSeconds),
                  sampled: cpu.sampled === 'fresh-sample' ? 'fresh'
                                                          : 'previous' })],
        [t.text('consoleNodeHealth.cpuTimeUsed'),
         kit.esc(cpu.usageSeconds) + ' s',
         t.html('consoleNodeHealth.cpuTimeWhy',
                { user: String(cpu.userSeconds === null ? '—'
                                                        : cpu.userSeconds),
                  system: String(cpu.systemSeconds === null
                                   ? '—' : cpu.systemSeconds) })],
        [t.text('consoleNodeHealth.throttled'), thr
           ? t.html('consoleNodeHealth.throttledPeriods',
                    { n: String(thr.throttledPeriods),
                      periods: String(thr.periods) })
           : '—',
         thr ? t.html('consoleNodeHealth.throttledWhy',
                      { pct: this.pct(thr.throttledPercentOfPeriods),
                        seconds: String(thr.throttledSeconds) })
           : kit.esc(cpu.throttlingText)]
      ]) + '<p><small>' +
      t.html('consoleNodeHealth.fromCgroup',
             { version: String(cpu.cgroupVersion),
               source: String(cpu.source) }) + '</small></p>';
    return html;
  }

  static memoryHtml(m: Json, t: Json): string {
    const head = '<h2 id="memory">' +
      t.html('consoleNodeHealth.headMemory') + '</h2>';
    if (!m.available) {
      return head + this.notAvailableHtml(t, m.unavailableText);
    }
    const html = head + '<p>' + kit.esc(m.limitText) + '</p>' +
      this.rows([
        [t.text('consoleNodeHealth.inUse'),
         kit.esc(this.mib(m.currentBytes)),
         (m.utilisationPercent === null
            ? t.html('consoleNodeHealth.noLimit')
            : t.html('consoleNodeHealth.pctOf',
                     { pct: this.pct(m.utilisationPercent),
                       of: this.mib(m.limitBytes) })) +
         (m.peakBytes === null ? ''
            : t.html('consoleNodeHealth.peak',
                     { peak: this.mib(m.peakBytes) }))],
        [t.text('consoleNodeHealth.anonymous'),
         kit.esc(this.mib(m.anonBytes)),
         t.html('consoleNodeHealth.anonymousWhy')],
        [t.text('consoleNodeHealth.pageCache'),
         kit.esc(this.mib(m.fileBytes)),
         t.html('consoleNodeHealth.pageCacheWhy')],
        [t.text('consoleNodeHealth.kernel'),
         kit.esc(this.mib(m.kernelBytes)),
         t.html('consoleNodeHealth.kernelWhy')],
        [t.text('consoleNodeHealth.oomKills'), m.oomKills === null ? '—'
                                                  : kit.esc(m.oomKills),
         t.html('consoleNodeHealth.oomKillsWhy')]
      ]) + '<p><small>' + kit.esc(m.statText) + ' ' +
      (m.fromEcs
        ? this.put(t.html('consoleNodeHealth.fromEcsAgent', { why: MARK }),
                   kit.esc(m.cgroupUnavailableText || ''))
        : t.html('consoleNodeHealth.fromCgroup',
                 { version: String(m.cgroupVersion),
                   source: String(m.source) })) + '</small></p>';
    return html;
  }

  static processesHtml(p: Json, t: Json): string {
    const self = this;
    const totals = p.totals;
    const html = '<h2 id="processes">' +
      t.html('consoleNodeHealth.headProcesses') + '</h2>' +
      this.rows([
        [t.text('consoleNodeHealth.processes'), kit.esc(totals.processes),
         t.html('consoleNodeHealth.listedBelow')],
        [t.text('consoleNodeHealth.workerThreads'),
         kit.esc(totals.workerThreads || 0),
         t.html('consoleNodeHealth.workerThreadsWhy')],
        [t.text('consoleNodeHealth.residentAll'),
         kit.esc(this.mib(totals.rssBytes)),
         t.html('consoleNodeHealth.residentWhy',
                { n: String(totals.processesWithRss) })],
        [t.text('consoleNodeHealth.heapAll'),
         kit.esc(this.mib(totals.heapUsedBytes)),
         t.html('consoleNodeHealth.heapWhy',
                { total: this.mib(totals.heapTotalBytes),
                  n: String(totals.isolatesWithHeap) })]
      ]) + kit.note(kit.esc(p.totalsText),
                    t.text('consoleNodeHealth.totalsLabel')) +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleNodeHealth.thProcess') + '</th>' +
      '<th>' + t.html('consoleNodeHealth.thResident') + '</th><th>' +
      t.html('consoleNodeHealth.thHeapUsed') + '</th><th>' +
      t.html('consoleNodeHealth.thHeapTotal') + '</th>' +
      '<th>' + t.html('consoleNodeHealth.thExternal') + '</th><th>' +
      t.html('consoleNodeHealth.thArrayBuffers') + '</th><th>' +
      t.html('consoleNodeHealth.thCpuTime') + '</th></tr>' +
      '</thead><tbody>' +
      p.rows.map(function (r: Json): string {
        const thread = r.kind === 'thread';
        return '<tr><td>' + (thread
          ? t.html('consoleNodeHealth.threadOfPid',
                   { thread: String(r.threadId), pid: String(r.pid) })
          : 'pid ' + kit.esc(r.pid)) + '<br><small>' +
          kit.esc(r.role) + '</small></td><td>' +
          (thread ? '<small>' + t.html('consoleNodeHealth.theProcesss') +
                    '</small>'
           : r.unreadable ? '<small>' + kit.esc(r.unreadable) + '</small>'
             : kit.esc(self.mib(r.rssBytes))) +
          (r.notReported ? '<br><small>' + kit.esc(r.notReported) +
                           '</small>' : '') +
          '</td><td>' + kit.esc(self.mib(r.heapUsedBytes)) + '</td><td>' +
          kit.esc(self.mib(r.heapTotalBytes)) + '</td><td>' +
          kit.esc(self.mib(r.externalBytes)) + '</td><td>' +
          kit.esc(self.mib(r.arrayBuffersBytes)) + '</td><td>' +
          (thread ? '<small>' + t.html('consoleNodeHealth.theProcesss') +
                    '</small>'
           : r.cpuUserSeconds === null ? '—'
             : kit.esc(self.round1(r.cpuUserSeconds +
                                   r.cpuSystemSeconds)) +
               ' s' + (r.processWide
                 ? '<br><small>' + t.html('consoleNodeHealth.everyThreads') +
                   '</small>' : '')) + '</td></tr>';
      }).join('') + '</tbody></table>' +
      // A worker that did not answer is a problem the page reports, and a
      // problem's text stays English (#539).
      (p.unanswered.length ? kit.warn(
        p.unanswered.length + ' worker thread(s) did not report: ' +
        p.unanswered.map(function (u: Json): string {
          return 'thread ' + kit.esc(u.threadId) + ', ' +
            kit.esc(u.role) + ' (' + kit.esc(u.why) + ')';
        }).join('; ') + '.') : '') +
      (p.debuggerNote ? '<p><small>' + kit.esc(p.debuggerNote) +
                        '</small></p>' : '');
    return html;
  }

  static ecsHtml(e: Json, t: Json): string {
    const head = '<h2 id="ecs">' + t.html('consoleNodeHealth.headEcs') +
      '</h2>';
    if (!e.available) {
      return head + this.notAvailableHtml(t, e.unavailableText);
    }
    const s = e.stats || {};
    const limits = e.taskLimits || {};
    const html = head + '<p>' + kit.esc(e.text) + '</p>' +
      this.rows([
        [t.text('consoleNodeHealth.taskLimits'),
         kit.esc(limits.cpuVcpus === undefined ||
                   limits.cpuVcpus === null
                     ? '—' : limits.cpuVcpus) + ' vCPU, ' +
           kit.esc(limits.memoryMiB === undefined ||
                     limits.memoryMiB === null
                       ? '—' : limits.memoryMiB) + ' MiB', '/task'],
        [t.text('consoleNodeHealth.memory'),
         kit.esc(this.mib(s.memoryUsageBytes)),
         (s.memoryLimitUnlimited
            ? t.html('consoleNodeHealth.noContainerLimit')
            : t.html('consoleNodeHealth.ofSize',
                     { size: this.mib(s.memoryLimitBytes) })) +
         ', /task/stats'],
        [t.text('consoleNodeHealth.cpu'),
         s.cpuCoresUsed === null || s.cpuCoresUsed === undefined
           ? '—' : t.html('consoleNodeHealth.cores',
                          { n: String(s.cpuCoresUsed) }),
         t.html('consoleNodeHealth.ecsCpuWhy',
                { pct: this.pct(s.cpuPercentOfTaskLimit) })]
      ]) + (e.unavailableText ? '<p><small>' + kit.esc(e.unavailableText) +
                                '</small></p>' : '');
    return html;
  }

  // `t` is optional because `node_health_admin.ts` draws one node's
  // sections with this alone, in English (`tests/node_health_page.js`).
  static html(json: Json, t?: Json): string {
    t = t || kit.context().t;
    const cpu = json.cpu;
    const mem = json.memory;
    const na = t.text('consoleNodeHealth.na');
    const tiles = '<div class="tiles">' +
      kit.tile(cpu.available ? this.pct(cpu.utilisationPercent) : na,
                 t.text('consoleNodeHealth.cpu')) +
      kit.tile(!mem.available ? na
                   : mem.utilisationPercent === null
                     ? this.mib(mem.currentBytes)
                     : this.pct(mem.utilisationPercent),
               t.text('consoleNodeHealth.memory')) +
      kit.tile(this.mib(json.processes.totals.rssBytes),
                 t.text('consoleNodeHealth.tileResident')) +
      kit.tile(String(json.processes.totals.processes),
               t.text('consoleNodeHealth.processes')) +
      kit.tile(String(json.processes.totals.workerThreads || 0),
                 t.text('consoleNodeHealth.workerThreads')) +
      '</div>';
    const about = kit.note(
      '<p>' + kit.esc(json.scopeText) + '</p><p>' +
      t.html('consoleNodeHealth.about') + '</p>',
      t.text('consoleNodeHealth.whatThisPageIs'));
    const m = json.machine;
    const machine = '<h2 id="machine">' +
      t.html('consoleNodeHealth.headMachine') + '</h2>' +
      '<p>' + kit.esc(m.text) + '</p>' +
      this.rows([
        [t.text('consoleNodeHealth.loadAverage'),
         kit.esc((m.loadavg || []).map(function (n: number): string {
           return n.toFixed(2);
         }).join(' / ')), t.html('consoleNodeHealth.loadAverageWhy')],
        [t.text('consoleNodeHealth.memory'),
         t.html('consoleNodeHealth.freeOf',
                { free: this.mib(m.freememBytes),
                  total: this.mib(m.totalmemBytes) }),
         'os.freemem() and os.totalmem()'],
        [t.text('consoleNodeHealth.cpus'), kit.esc(m.cpus), 'os.cpus()']
      ]);
    const html = tiles + about + this.cpuHtml(cpu, t) +
      this.memoryHtml(mem, t) + this.processesHtml(json.processes, t) +
      this.ecsHtml(json.ecs, t) + machine;
    return html;
  }

  // The page for every node: the cluster's totals and a section per node,
  // this node's from its live view and every other's from its snapshot.
  // The page's words are its translator's (#539 phase 6); what the view
  // carries — a state's sentence, a limit's text — is drawn as it comes.
  static clusterHtml(json: Json, ctx: Json): string {
    const t = ctx.t;
    const self = this;
    const c = json.cluster || {};
    const nodes: Json[] = json.nodes || [];
    const own = nodes.filter(function (n: Json): boolean {
      return n.self;
    })[0];
    if (!c.clustered || nodes.length < 2) {
      const html = kit.note(kit.esc(c.text || ''),
                            t.text('consoleNodeHealth.cluster')) +
        (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
        (own && own.view ? this.html(own.view, t)
                         : nodes[0] && nodes[0].view
                           ? this.html(nodes[0].view, t) : '');
      return html;
    }
    const totals = json.totals;
    const html = '<h2 id="cluster">' + t.html('consoleNodeHealth.cluster') +
      '</h2><p>' + kit.esc(c.text) +
      '</p>' + (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
      this.rows([
        [t.text('consoleNodeHealth.containerMemory'),
         kit.esc(this.mib(totals.memoryUsedBytes)),
         totals.memoryLimitBytes === null
           ? t.html('consoleNodeHealth.noTotalLimit')
           : t.html('consoleNodeHealth.pctOf',
                    { pct: this.pct(totals.memoryPercent),
                      of: this.mib(totals.memoryLimitBytes) })],
        [t.text('consoleNodeHealth.cpu'), totals.cpuCoresUsed === null
           ? '—'
           : t.html('consoleNodeHealth.cores',
                    { n: String(totals.cpuCoresUsed) }),
         totals.cpuPercent === null
           ? t.html('consoleNodeHealth.notMeasured')
           : t.html('consoleNodeHealth.pctOfCores',
                    { pct: this.pct(totals.cpuPercent),
                      of: String(totals.cpuOf) })],
        [t.text('consoleNodeHealth.processes'),
         t.html('consoleNodeHealth.processesAndThreads',
                { processes: String(totals.processes),
                  threads: String(totals.workerThreads || 0) }),
         t.html('consoleNodeHealth.residentHeap',
                { resident: this.mib(totals.rssBytes),
                  heap: this.mib(totals.heapUsedBytes) })]
      ]) + '<p><small>' + kit.esc(totals.text) + '</small></p>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleNodeHealth.thNode') + '</th><th>' +
      t.html('consoleNodeHealth.thState') + '</th>' +
      '<th>' + t.html('consoleNodeHealth.thAge') +
      '</th></tr></thead><tbody>' +
      nodes.map(function (n: Json): string {
        return '<tr><td><a href="#node-' + kit.esc(n.name) + '">' +
          kit.esc(n.name) + '</a>' +
          (n.self ? ' ' + t.html('consoleNodeHealth.thisNode') : '') +
          '</td><td>' + kit.esc(n.state) + '</td><td>' +
          (n.ageSeconds === null ? '—' : kit.esc(n.ageSeconds) + ' s') +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      nodes.map(function (n: Json): string {
        const head = '<h2 id="node-' + kit.esc(n.name) + '">' +
          t.html('consoleNodeHealth.nodeNamed', { name: String(n.name) }) +
          (n.self ? ' ' + t.html('consoleNodeHealth.thisNode') : '') +
          '</h2><p>' +
          '<strong>' + kit.esc(n.state) + '</strong>: ' +
          kit.esc(n.stateText) + '</p>';
        if (!n.view) {
          return head;
        }
        let body = '';
        try {
          body = self.html(n.view, t);
        } catch (e) {
          // A snapshot from another version of this page may lack a figure
          // this one draws; the node is still listed, and says so.
          return head + kit.warn('This node\'s snapshot could not be ' +
                                   'drawn: ' + kit.esc((e && e.message) ||
                                                         e) + '.');
        }
        // Another node's sections carry its name in their anchors, so the
        // page's own `id="cpu"` and the rest stay this node's.
        return head + (n.self ? body
          : body.replace(/ id="/g, ' id="' + kit.esc(n.name) + '-'));
      }).join('');
    return html;
  }
}

export = NodeHealthPage;
