// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_worker_pools.ts
//
// ---------------------------------------------------------------------------
// MONITORING → WORKER POOLS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Monitoring → Worker Pools from the answer of `GET
// /admin-api/worker-pools`: the cluster's totals and a section per node, each
// pool with its figures and worker threads.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `WorkerPoolsAdmin`'s in `admin-ui/worker_pools_admin.ts`,
// moved with their comments; that module still draws the page until the
// console's cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws Monitoring → Worker Pools from the answer of `GET
 * /admin-api/worker-pools`: the cluster's totals and a section per node, each
 * pool with its figures and worker threads.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class WorkerPoolsPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return WorkerPoolsPage.clusterHtml(view);
  }

  // The page for every node: the cluster's totals and a section per node.
  static clusterHtml(json: Json): string {
    const self = this;
    const c = json.cluster || {};
    const nodes: Json[] = json.nodes || [];
    const own = nodes.filter(function (n: Json): boolean {
      return n.self;
    })[0];
    if (!c.clustered || nodes.length < 2) {
      const first = own || nodes[0];
      const html = kit.note(kit.esc(c.text || ''), 'Cluster') +
        (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
        (first && first.view && first.view.pools ? this.html(first.view)
                                                 : '');
      return html;
    }
    const t = json.totals;
    const html = '<h2 id="cluster">Cluster</h2><p>' + kit.esc(c.text) +
      '</p>' + (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
      '<table class="grid"><thead><tr><th>Pool</th><th>Worker threads</th>' +
      '<th>Busy</th><th>Free</th><th>Started</th><th>Crashed</th>' +
      '<th>Nodes on</th></tr></thead><tbody>' +
      t.pools.map(function (p: Json): string {
        return '<tr><td>' + kit.esc(p.title) + '</td><td>' +
          kit.esc(p.currentWorkers) + '</td><td>' +
          kit.esc(p.busyWorkers) + '</td><td>' +
          kit.esc(p.freeWorkers) + '</td><td>' + kit.esc(p.forked) +
          '</td><td>' + kit.esc(p.crashed) +
          (p.failedStarts ? ' (' + kit.esc(p.failedStarts) + ' never ' +
                            'started)' : '') + '</td><td>' +
          kit.esc(p.nodesOn) + '</td></tr>';
      }).join('') + '</tbody></table><p><small>' + kit.esc(t.text) +
      '</small></p>' +
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
        if (!n.view || !Array.isArray(n.view.pools)) {
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
        // page's own `id="pool-request"` and the rest stay this node's.
        return head + (n.self ? body
          : body.replace(/ id="/g, ' id="' + kit.esc(n.name) + '-'));
      }).join('');
    return html;
  }

  // A figure, or a dash for one that does not exist yet.
  static ms(value: unknown): string {
    return value === null || value === undefined ? '—' : value + ' ms';
  }

  // The seven figures of one pool, as a table of two columns.
  static figures(p: Json): string {
    const r = p.restarts;
    const t = p.responseTime;
    const row = function (label: string, value: string, why: string):
      string {
      return '<tr><th>' + kit.esc(label) + '</th><td>' + value +
        '</td><td><small>' + why + '</small></td></tr>';
    };
    const html = '<table class="grid"><tbody>' +
      row('Current workers', kit.esc(p.currentWorkers),
          'worker threads started now, ' + kit.esc(p.readyWorkers) +
          ' of them ready') +
      row('Busy', kit.esc(p.busyWorkers), 'with a request in flight') +
      row('Free', kit.esc(p.freeWorkers), 'ready and idle') +
      row('Maximum workers', kit.esc(p.maxWorkers),
          '<code>' + kit.esc(p.setting) + '</code>') +
      row('Initial workers', kit.esc(p.initialWorkers),
          'what the pool was started with') +
      row('Restarts and crashes',
          kit.esc(r.crashed) + ' crashed' +
          (r.failedStarts ? ' (' + kit.esc(r.failedStarts) + ' never ' +
                            'started)' : '') + ', ' +
          kit.esc(r.replaced) + ' replaced, ' +
          kit.esc(r.stopped) + ' stopped',
          kit.esc(r.forked) + ' started in all; a crash is an exit ' +
          'nobody asked for') +
      row('Average response time',
          this.ms(t.averageMs) + ' (recent ' +
            this.ms(t.recentAverageMs) + ')',
          kit.esc(t.answered) + ' answered, dispatch to answer; ' +
          'worst ' + this.ms(t.maxMs)) +
      '</tbody></table>';
    return html;
  }

  static html(json: Json): string {
    const self = this;
    const tiles = '<div class="tiles">' +
      json.pools.map(function (p: Json): string {
        return kit.tile(p.state === 'off' ? 'off'
                                            : String(p.currentWorkers),
                          p.title);
      }).join('') + '</div>';
    const about = kit.note(
      '<p>' + kit.esc(json.scopeText) + '</p><p>Every figure is read from ' +
      'the pool\'s own module when the page is drawn, and counts from when ' +
      'this process started. The sizes are Global settings on ' +
      '<a href="/admin/config">Configuration</a>; this page changes ' +
      'nothing.</p>', 'What this page is');
    const sections = json.pools.map(function (p: Json): string {
      const head = '<h2 id="pool-' + kit.esc(p.id) + '">' +
        kit.esc(p.title) + '</h2><p><code>' + kit.esc(p.module) +
        '</code> · <code>' + kit.esc(p.setting) + '</code> · <strong>' +
        kit.esc(p.state) + '</strong>: ' + kit.esc(p.stateText) + '</p>';
      if (p.state === 'off') {
        return head;
      }
      let detail = '';
      if (p.workers.length) {
        detail = '<h3>Worker threads</h3><table class="grid"><thead><tr>' +
          '<th>Thread</th><th>Slot</th><th>State</th><th>In flight</th>' +
          '<th>Served</th><th>Up</th></tr></thead><tbody>' +
          p.workers.map(function (w: Json): string {
            return '<tr><td>' + kit.esc(w.threadId) + '</td><td>' +
              kit.esc(w.slot === null ? '—' : w.slot) + '</td><td>' +
              (w.retiring ? 'stopping' : !w.ready ? 'starting'
                                       : w.busy ? 'busy' : 'free') +
              '</td><td>' + kit.esc(w.inFlight) + '</td><td>' +
              kit.esc(w.served) + '</td><td>' +
              (w.upSeconds === null ? '—' : kit.esc(w.upSeconds) + ' s') +
              '</td></tr>';
          }).join('') + '</tbody></table>';
      }
      return head + self.figures(p) + detail;
    }).join('');
    return tiles + about + sections;
  }
}

export = WorkerPoolsPage;
