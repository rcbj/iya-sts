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
   * @param ctx - the render context (`WebKit.context()`); the server's
   *   own drawing passes none, and gets English
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    return WorkerPoolsPage.clusterHtml(view, ctx || kit.context());
  }

  // The page for every node: the cluster's totals and a section per node.
  // The page's words are its translator's (#539 phase 6); what the view
  // carries — a pool's title, a state's sentence — is drawn as it comes.
  static clusterHtml(json: Json, ctx: Json): string {
    const t = ctx.t;
    const self = this;
    const c = json.cluster || {};
    const nodes: Json[] = json.nodes || [];
    const own = nodes.filter(function (n: Json): boolean {
      return n.self;
    })[0];
    if (!c.clustered || nodes.length < 2) {
      const first = own || nodes[0];
      const html = kit.note(kit.esc(c.text || ''),
                            t.text('consoleWorkerPools.cluster')) +
        (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
        (first && first.view && first.view.pools
          ? this.html(first.view, t) : '');
      return html;
    }
    // `totals`, which was `t` before the translator took the name.
    const totals = json.totals;
    const html = '<h2 id="cluster">' + t.html('consoleWorkerPools.cluster') +
      '</h2><p>' + kit.esc(c.text) +
      '</p>' + (c.readError ? kit.warn(kit.esc(c.readError)) : '') +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleWorkerPools.thPool') + '</th><th>' +
      t.html('consoleWorkerPools.thWorkerThreads') + '</th>' +
      '<th>' + t.html('consoleWorkerPools.thBusy') + '</th><th>' +
      t.html('consoleWorkerPools.thFree') + '</th><th>' +
      t.html('consoleWorkerPools.thStarted') + '</th><th>' +
      t.html('consoleWorkerPools.thCrashed') + '</th>' +
      '<th>' + t.html('consoleWorkerPools.thNodesOn') +
      '</th></tr></thead><tbody>' +
      totals.pools.map(function (p: Json): string {
        return '<tr><td>' + kit.esc(p.title) + '</td><td>' +
          kit.esc(p.currentWorkers) + '</td><td>' +
          kit.esc(p.busyWorkers) + '</td><td>' +
          kit.esc(p.freeWorkers) + '</td><td>' + kit.esc(p.forked) +
          '</td><td>' + kit.esc(p.crashed) +
          (p.failedStarts ? ' ' + t.html('consoleWorkerPools.neverStarted',
                                         { n: String(p.failedStarts) })
                          : '') + '</td><td>' +
          kit.esc(p.nodesOn) + '</td></tr>';
      }).join('') + '</tbody></table><p><small>' + kit.esc(totals.text) +
      '</small></p>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleWorkerPools.thNode') + '</th><th>' +
      t.html('consoleWorkerPools.thState') + '</th>' +
      '<th>' + t.html('consoleWorkerPools.thAge') +
      '</th></tr></thead><tbody>' +
      nodes.map(function (n: Json): string {
        return '<tr><td><a href="#node-' + kit.esc(n.name) + '">' +
          kit.esc(n.name) + '</a>' +
          (n.self ? ' ' + t.html('consoleWorkerPools.thisNode') : '') +
          '</td><td>' + kit.esc(n.state) + '</td><td>' +
          (n.ageSeconds === null ? '—' : kit.esc(n.ageSeconds) + ' s') +
          '</td></tr>';
      }).join('') + '</tbody></table>' +
      nodes.map(function (n: Json): string {
        const head = '<h2 id="node-' + kit.esc(n.name) + '">' +
          t.html('consoleWorkerPools.nodeNamed', { name: String(n.name) }) +
          (n.self ? ' ' + t.html('consoleWorkerPools.thisNode') : '') +
          '</h2><p>' +
          '<strong>' + kit.esc(n.state) + '</strong>: ' +
          kit.esc(n.stateText) + '</p>';
        if (!n.view || !Array.isArray(n.view.pools)) {
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

  // The seven figures of one pool, as a table of two columns. `t` is the
  // translator its caller hands it; the response times, which were `t`
  // before, are `rt`.
  static figures(p: Json, t: Json): string {
    const r = p.restarts;
    const rt = p.responseTime;
    const row = function (label: string, value: string, why: string):
      string {
      return '<tr><th>' + kit.esc(label) + '</th><td>' + value +
        '</td><td><small>' + why + '</small></td></tr>';
    };
    const html = '<table class="grid"><tbody>' +
      row(t.text('consoleWorkerPools.currentWorkers'),
          kit.esc(p.currentWorkers),
          t.html('consoleWorkerPools.currentWorkersWhy',
                 { ready: String(p.readyWorkers) })) +
      row(t.text('consoleWorkerPools.busy'), kit.esc(p.busyWorkers),
          t.html('consoleWorkerPools.busyWhy')) +
      row(t.text('consoleWorkerPools.free'), kit.esc(p.freeWorkers),
          t.html('consoleWorkerPools.freeWhy')) +
      row(t.text('consoleWorkerPools.maxWorkers'), kit.esc(p.maxWorkers),
          '<code>' + kit.esc(p.setting) + '</code>') +
      row(t.text('consoleWorkerPools.initialWorkers'),
          kit.esc(p.initialWorkers),
          t.html('consoleWorkerPools.initialWorkersWhy')) +
      row(t.text('consoleWorkerPools.restarts'),
          t.html('consoleWorkerPools.crashed',
                 { n: String(r.crashed) }) +
          (r.failedStarts ? ' ' + t.html('consoleWorkerPools.neverStarted',
                                         { n: String(r.failedStarts) })
                          : '') + ', ' +
          t.html('consoleWorkerPools.replacedStopped',
                 { replaced: String(r.replaced),
                   stopped: String(r.stopped) }),
          t.html('consoleWorkerPools.restartsWhy',
                 { n: String(r.forked) })) +
      row(t.text('consoleWorkerPools.averageResponse'),
          t.html('consoleWorkerPools.averageRecent',
                 { average: this.ms(rt.averageMs),
                   recent: this.ms(rt.recentAverageMs) }),
          t.html('consoleWorkerPools.answeredWorst',
                 { n: String(rt.answered), worst: this.ms(rt.maxMs) })) +
      '</tbody></table>';
    return html;
  }

  static html(json: Json, t: Json): string {
    const self = this;
    const tiles = '<div class="tiles">' +
      json.pools.map(function (p: Json): string {
        return kit.tile(p.state === 'off'
                          ? t.text('consoleWorkerPools.off')
                          : String(p.currentWorkers),
                          p.title);
      }).join('') + '</div>';
    // The link to Configuration carries an href, which a message may not,
    // so the sentence around it is two messages with the anchor in code.
    const about = kit.note(
      '<p>' + kit.esc(json.scopeText) + '</p><p>' +
      t.html('consoleWorkerPools.aboutBefore') +
      '<a href="/admin/config">' +
      t.html('consoleWorkerPools.aboutLink') + '</a>' +
      t.html('consoleWorkerPools.aboutAfter') + '</p>',
      t.text('consoleWorkerPools.whatThisPageIs'));
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
        detail = '<h3>' + t.html('consoleWorkerPools.thWorkerThreads') +
          '</h3><table class="grid"><thead><tr>' +
          '<th>' + t.html('consoleWorkerPools.thThread') + '</th><th>' +
          t.html('consoleWorkerPools.thSlot') + '</th><th>' +
          t.html('consoleWorkerPools.thState') + '</th><th>' +
          t.html('consoleWorkerPools.thInFlight') + '</th>' +
          '<th>' + t.html('consoleWorkerPools.thServed') + '</th><th>' +
          t.html('consoleWorkerPools.thUp') + '</th></tr></thead><tbody>' +
          p.workers.map(function (w: Json): string {
            return '<tr><td>' + kit.esc(w.threadId) + '</td><td>' +
              kit.esc(w.slot === null ? '—' : w.slot) + '</td><td>' +
              (w.retiring ? t.html('consoleWorkerPools.stopping')
                : !w.ready ? t.html('consoleWorkerPools.starting')
                  : w.busy ? t.html('consoleWorkerPools.stateBusy')
                    : t.html('consoleWorkerPools.stateFree')) +
              '</td><td>' + kit.esc(w.inFlight) + '</td><td>' +
              kit.esc(w.served) + '</td><td>' +
              (w.upSeconds === null ? '—' : kit.esc(w.upSeconds) + ' s') +
              '</td></tr>';
          }).join('') + '</tbody></table>';
      }
      return head + self.figures(p, t) + detail;
    }).join('');
    return tiles + about + sections;
  }
}

export = WorkerPoolsPage;
