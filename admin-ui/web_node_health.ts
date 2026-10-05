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
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return NodeHealthPage.clusterHtml(view);
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

  static cpuHtml(cpu: Json): string {
    const head = '<h2 id="cpu">Container CPU</h2>';
    if (!cpu.available) {
      return head + '<p><strong>Not available:</strong> ' +
        kit.esc(cpu.unavailableText) + '</p>';
    }
    const t = cpu.throttling;
    if (cpu.fromEcs) {
      const ecsHtml = head + '<p>' + kit.esc(cpu.limitText) + '</p>' +
        this.rows([
          ['Utilisation', kit.esc(this.pct(cpu.utilisationPercent)),
           kit.esc(cpu.coresUsed) + ' CPU(s)' + (cpu.percentOfVcpus
             ? ' of ' + kit.esc(cpu.percentOfVcpus) : '') +
           ', as the ECS agent measured it']
        ]) + '<p><small>The cgroup: ' +
        kit.esc(cpu.cgroupUnavailableText || '') + '</small></p>';
      return ecsHtml;
    }
    const html = head + '<p>' + kit.esc(cpu.limitText) + '</p>' +
      this.rows([
        ['Utilisation', kit.esc(this.pct(cpu.utilisationPercent)),
         kit.esc(cpu.coresUsed) + ' of ' + kit.esc(cpu.percentOfVcpus) +
         ' CPU(s) over ' + kit.esc(cpu.windowSeconds) + ' s, ' +
         (cpu.sampled === 'fresh-sample' ? 'two samples taken for this page'
                                         : 'since the previous page')],
        ['CPU time used', kit.esc(cpu.usageSeconds) + ' s',
         'every process of the container since it started (user ' +
         kit.esc(cpu.userSeconds === null ? '—' : cpu.userSeconds) +
         ' s, system ' +
         kit.esc(cpu.systemSeconds === null ? '—' : cpu.systemSeconds) +
         ' s)'],
        ['Throttled', t ? kit.esc(t.throttledPeriods) + ' of ' +
           kit.esc(t.periods) + ' periods' : '—',
         t ? kit.esc(this.pct(t.throttledPercentOfPeriods)) + ' of ' +
             'periods, ' + kit.esc(t.throttledSeconds) + ' s held back ' +
             'by the quota'
           : kit.esc(cpu.throttlingText)]
      ]) + '<p><small>From cgroup v' + kit.esc(cpu.cgroupVersion) +
      ', <code>' + kit.esc(cpu.source) + '</code>.</small></p>';
    return html;
  }

  static memoryHtml(m: Json): string {
    const head = '<h2 id="memory">Container memory</h2>';
    if (!m.available) {
      return head + '<p><strong>Not available:</strong> ' +
        kit.esc(m.unavailableText) + '</p>';
    }
    const html = head + '<p>' + kit.esc(m.limitText) + '</p>' +
      this.rows([
        ['In use', kit.esc(this.mib(m.currentBytes)),
         (m.utilisationPercent === null ? 'no limit to measure against'
            : kit.esc(this.pct(m.utilisationPercent)) + ' of ' +
              kit.esc(this.mib(m.limitBytes))) +
         (m.peakBytes === null ? ''
            : '; the most it has used is ' +
              kit.esc(this.mib(m.peakBytes)))],
        ['Anonymous', kit.esc(this.mib(m.anonBytes)),
         'the processes\' own memory: heaps, stacks, buffers'],
        ['Page cache', kit.esc(this.mib(m.fileBytes)),
         'files the kernel caches, and gives back under pressure'],
        ['Kernel', kit.esc(this.mib(m.kernelBytes)),
         'the kernel\'s own structures on the container\'s behalf'],
        ['Killed for memory', m.oomKills === null ? '—'
                                                  : kit.esc(m.oomKills),
         'processes the kernel killed at the limit (oom_kill, in ' +
         'memory.events or v1\'s memory.oom_control)']
      ]) + '<p><small>' + kit.esc(m.statText) + ' From ' +
      (m.fromEcs ? 'the ECS agent, because the cgroup cannot be read: ' +
                   kit.esc(m.cgroupUnavailableText || '')
                 : 'cgroup v' + kit.esc(m.cgroupVersion) + ', <code>' +
                   kit.esc(m.source) + '</code>') + '.</small></p>';
    return html;
  }

  static processesHtml(p: Json): string {
    const self = this;
    const t = p.totals;
    const html = '<h2 id="processes">Node.js processes and worker threads' +
      '</h2>' +
      this.rows([
        ['Processes', kit.esc(t.processes), 'listed below'],
        ['Worker threads', kit.esc(t.workerThreads || 0),
         'request and hosted-surface workers, threads of the front process'],
        ['Resident, in all', kit.esc(this.mib(t.rssBytes)),
         'across ' + kit.esc(t.processesWithRss) + ' process(es); a ' +
         'thread\'s is its process\'s'],
        ['Heap used, in all', kit.esc(this.mib(t.heapUsedBytes)),
         'of ' + kit.esc(this.mib(t.heapTotalBytes)) + ' allocated, ' +
         'across ' + kit.esc(t.isolatesWithHeap) + ' V8 isolate(s)']
      ]) + kit.note(kit.esc(p.totalsText), 'How the totals add up') +
      '<table class="grid"><thead><tr><th>Process or thread</th>' +
      '<th>Resident</th><th>Heap used</th><th>Heap total</th>' +
      '<th>External</th><th>Array buffers</th><th>CPU time</th></tr>' +
      '</thead><tbody>' +
      p.rows.map(function (r: Json): string {
        const thread = r.kind === 'thread';
        return '<tr><td>' + (thread ? 'thread ' + kit.esc(r.threadId) +
                             ' of pid ' + kit.esc(r.pid)
                           : 'pid ' + kit.esc(r.pid)) + '<br><small>' +
          kit.esc(r.role) + '</small></td><td>' +
          (thread ? '<small>the process\'s</small>'
           : r.unreadable ? '<small>' + kit.esc(r.unreadable) + '</small>'
             : kit.esc(self.mib(r.rssBytes))) +
          (r.notReported ? '<br><small>' + kit.esc(r.notReported) +
                           '</small>' : '') +
          '</td><td>' + kit.esc(self.mib(r.heapUsedBytes)) + '</td><td>' +
          kit.esc(self.mib(r.heapTotalBytes)) + '</td><td>' +
          kit.esc(self.mib(r.externalBytes)) + '</td><td>' +
          kit.esc(self.mib(r.arrayBuffersBytes)) + '</td><td>' +
          (thread ? '<small>the process\'s</small>'
           : r.cpuUserSeconds === null ? '—'
             : kit.esc(self.round1(r.cpuUserSeconds +
                                   r.cpuSystemSeconds)) +
               ' s' + (r.processWide ? '<br><small>every thread\'s' +
                                       '</small>' : '')) + '</td></tr>';
      }).join('') + '</tbody></table>' +
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

  static ecsHtml(e: Json): string {
    const head = '<h2 id="ecs">ECS task metadata</h2>';
    if (!e.available) {
      return head + '<p><strong>Not available:</strong> ' +
        kit.esc(e.unavailableText) + '</p>';
    }
    const s = e.stats || {};
    const limits = e.taskLimits || {};
    const html = head + '<p>' + kit.esc(e.text) + '</p>' +
      this.rows([
        ['Task limits', kit.esc(limits.cpuVcpus === undefined ||
                                  limits.cpuVcpus === null
                                    ? '—' : limits.cpuVcpus) + ' vCPU, ' +
           kit.esc(limits.memoryMiB === undefined ||
                     limits.memoryMiB === null
                       ? '—' : limits.memoryMiB) + ' MiB', '/task'],
        ['Memory', kit.esc(this.mib(s.memoryUsageBytes)),
         (s.memoryLimitUnlimited ? 'no container limit (the agent\'s "none")'
            : 'of ' + kit.esc(this.mib(s.memoryLimitBytes))) +
         ', /task/stats'],
        ['CPU', s.cpuCoresUsed === null || s.cpuCoresUsed === undefined
           ? '—' : kit.esc(s.cpuCoresUsed) + ' CPU(s)',
         kit.esc(this.pct(s.cpuPercentOfTaskLimit)) + ' of the task\'s ' +
         'vCPUs, between the agent\'s last two samples']
      ]) + (e.unavailableText ? '<p><small>' + kit.esc(e.unavailableText) +
                                '</small></p>' : '');
    return html;
  }

  static html(json: Json): string {
    const cpu = json.cpu;
    const mem = json.memory;
    const tiles = '<div class="tiles">' +
      kit.tile(cpu.available ? this.pct(cpu.utilisationPercent) : 'n/a',
                 'CPU') +
      kit.tile(!mem.available ? 'n/a'
                   : mem.utilisationPercent === null
                     ? this.mib(mem.currentBytes)
                     : this.pct(mem.utilisationPercent), 'Memory') +
      kit.tile(this.mib(json.processes.totals.rssBytes),
                 'Resident, all processes') +
      kit.tile(String(json.processes.totals.processes), 'Processes') +
      kit.tile(String(json.processes.totals.workerThreads || 0),
                 'Worker threads') +
      '</div>';
    const about = kit.note(
      '<p>' + kit.esc(json.scopeText) + '</p><p>The container\'s CPU and ' +
      'memory are read from its cgroup (v2), each process\'s and worker ' +
      'thread\'s from the process or thread itself, when the page is ' +
      'drawn; nothing is kept but the ' +
      'previous CPU sample. This page changes nothing.</p>',
      'What this page is');
    const m = json.machine;
    const machine = '<h2 id="machine">The machine, not the container</h2>' +
      '<p>' + kit.esc(m.text) + '</p>' +
      this.rows([
        ['Load average', kit.esc((m.loadavg || []).map(
          function (n: number): string {
            return n.toFixed(2);
          }).join(' / ')), '1, 5 and 15 minutes (os.loadavg())'],
        ['Memory', kit.esc(this.mib(m.freememBytes)) + ' free of ' +
           kit.esc(this.mib(m.totalmemBytes)),
         'os.freemem() and os.totalmem()'],
        ['CPUs', kit.esc(m.cpus), 'os.cpus()']
      ]);
    const html = tiles + about + this.cpuHtml(cpu) + this.memoryHtml(mem) +
      this.processesHtml(json.processes) + this.ecsHtml(json.ecs) + machine;
    return html;
  }

  // The page for every node: the cluster's totals and a section per node,
  // this node's from its live view and every other's from its snapshot.
  static clusterHtml(json: Json): string {
    const self = this;
    const c = json.cluster || {};
    const nodes: Json[] = json.nodes || [];
    const own = nodes.filter(function (n: Json): boolean {
      return n.self;
    })[0];
    if (!c.clustered || nodes.length < 2) {
      const html = kit.note(kit.esc(c.text || ''), 'Cluster') +
        (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
        (own && own.view ? this.html(own.view)
                         : nodes[0] && nodes[0].view
                           ? this.html(nodes[0].view) : '');
      return html;
    }
    const t = json.totals;
    const html = '<h2 id="cluster">Cluster</h2><p>' + kit.esc(c.text) +
      '</p>' + (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
      this.rows([
        ['Container memory', kit.esc(this.mib(t.memoryUsedBytes)),
         t.memoryLimitBytes === null ? 'no total limit to measure against'
           : kit.esc(this.pct(t.memoryPercent)) + ' of ' +
             kit.esc(this.mib(t.memoryLimitBytes))],
        ['CPU', t.cpuCoresUsed === null ? '—'
           : kit.esc(t.cpuCoresUsed) + ' CPU(s)',
         t.cpuPercent === null ? 'not measured'
           : kit.esc(this.pct(t.cpuPercent)) + ' of ' +
             kit.esc(t.cpuOf) + ' CPU(s)'],
        ['Processes', kit.esc(t.processes) + ' and ' +
           kit.esc(t.workerThreads || 0) + ' worker thread(s)',
         kit.esc(this.mib(t.rssBytes)) + ' resident (processes only), ' +
         kit.esc(this.mib(t.heapUsedBytes)) + ' of heap used']
      ]) + '<p><small>' + kit.esc(t.text) + '</small></p>' +
      '<table class="grid"><thead><tr><th>Node</th><th>State</th>' +
      '<th>Age</th></tr></thead><tbody>' +
      nodes.map(function (n: Json): string {
        return '<tr><td><a href="#node-' + kit.esc(n.name) + '">' +
          kit.esc(n.name) + '</a>' + (n.self ? ' (this node)' : '') +
          '</td><td>' + kit.esc(n.state) + '</td><td>' +
          (n.ageSeconds === null ? '—' : kit.esc(n.ageSeconds) + ' s') +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      nodes.map(function (n: Json): string {
        const head = '<h2 id="node-' + kit.esc(n.name) + '">Node ' +
          kit.esc(n.name) + (n.self ? ' (this node)' : '') + '</h2><p>' +
          '<strong>' + kit.esc(n.state) + '</strong>: ' +
          kit.esc(n.stateText) + '</p>';
        if (!n.view) {
          return head;
        }
        let body = '';
        try {
          body = self.html(n.view);
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
