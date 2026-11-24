// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_cluster_status.ts
//
// ---------------------------------------------------------------------------
// PLATFORM → CLUSTER'S STATUS BLOCK, DRAWN FROM ITS VIEW ALONE (#2070,
// 2026-11-24).
//
// `GET /admin-api/cluster` has answered a `status` member since #46 —
// `admin-ui/admin.ts`'s `clusterStatusBlock()`: `cluster.status()`, the
// member snapshot folded by name, the leases, every other cell's cluster,
// the shared secrets and the read barrier. The console drew it in node
// until #446 made the console a static application, and nothing drew it
// after: the page showed the five settings and none of what they decide
// about. This draws it from that member, in the order and with the
// readings the node-side block had — every time the database's clock, a
// node's role read from the LEASE TABLE and not from its own mode, the
// nodes that left or expired folded rather than dropped — and the
// node-side block now calls this, so there is one copy of it.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its words are the `consoleCluster` catalog's (#539).
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

/**
 * Draws /admin/cluster's status block from the page view's `status`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ClusterStatusPage {
  // A TIME AGAINST THE DATABASE'S CLOCK, never the browser's. Tenths of a
  // second up to two minutes, because every lifetime and every heartbeat on
  // this page is seconds long; past two minutes it is a duration. As TEXT,
  // for a message's parameter (which the message escapes); `ago()` is the
  // same escaped for a cell.
  /**
   * Words an instant as "... ago" or "in ..." against a reference instant.
   *
   * @param now - the reference, milliseconds (the database's clock)
   * @param at - the instant, milliseconds; nothing for a dash
   * @param t - the page's translator
   * @returns the text, unescaped
   */
  static agoText(now: number, at: number, t: Json): string {
    if (!now || !at) {
      return '—';
    }
    const ms = now - at;
    const size = Math.abs(ms);
    const much = size >= 120000
      ? kit.durationText(size)
      : String(Math.round(size / 100) / 10) + 's';
    return ms >= 0 ? t.text('consoleCluster.ago', { d: much })
                   : t.text('consoleCluster.inTime', { d: much });
  }

  /**
   * `agoText()`, escaped for a cell.
   *
   * @param now - the reference, milliseconds
   * @param at - the instant, milliseconds
   * @param t - the page's translator
   * @returns the text as HTML
   */
  static ago(now: number, at: number, t: Json): string {
    return kit.esc(ClusterStatusPage.agoText(now, at, t));
  }

  /**
   * Draws the whole status block.
   *
   * @param info - the view's `status`
   * @param t - the page's translator
   * @returns the block as HTML
   */
  static render(info: Json, t: Json): string {
    const self = info.self || {};
    const off = self.mode === 'off';
    const caps = self.capabilities || { rows: [], missing: [],
                                        acceptedMissing: [],
                                        unknownAccepted: [], ready: true };
    const barrier = info.barrier || {};
    const r1 = function (n: number): string {
      return String(Math.round((Number(n) || 0) * 10) / 10);
    };
    const leasesHere = (self.leases || []).map(function (lease: Json) {
      return t.html('consoleCluster.leaseAt',
                    { name: String(lease.name), token: String(lease.token) });
    }).join(', ');
    const rows = [
      [t.text('consoleCluster.thMode'),
        '<strong>' + kit.esc(self.mode || '') + '</strong> — ' +
        kit.esc(self.why || '') +
        (self.refused ? '. ' + kit.warn(kit.esc(self.refused)) : '')],
      [t.text('consoleCluster.thThisNode'), off
        ? t.html('consoleCluster.notMember')
        : t.html(self.role === 'worker' ? 'consoleCluster.nodeWorker'
                                        : 'consoleCluster.nodeFront',
                 { id: String(self.nodeId || ''),
                   name: String(self.name || '') }) +
          (self.joinedAt
            ? t.html('consoleCluster.joinedAt', { at: String(self.joinedAt) })
            : '')],
      [t.text('consoleCluster.thHeartbeat'), off ? '—'
        : t.html('consoleCluster.heartbeat',
                 { every: String(self.heartbeatMs), ttl: String(self.ttlMs) }) +
          (self.msSinceRenewal !== null && self.msSinceRenewal !== undefined
            ? t.html('consoleCluster.renewed',
                     { ms: String(self.msSinceRenewal) })
            : '') +
          (self.heartbeatFailures
            ? t.html('consoleCluster.heartbeatFailures',
                     { n: String(self.heartbeatFailures),
                       error: String(self.lastHeartbeatError || '') })
            : '')],
      [t.text('consoleCluster.thLeasesHere'), off || !leasesHere
        ? t.html('consoleCluster.none') : leasesHere],
      [t.text('consoleCluster.thBarrier'), barrier.active
        ? t.html('consoleCluster.barrier',
                 { requests: String(barrier.requests || 0),
                   wait: r1(barrier.meanWaitMs),
                   gaveUp: String(barrier.gaveUp || 0),
                   held: String(barrier.heldForCommit || 0),
                   hold: r1(barrier.meanHoldMs) }) +
          (barrier.commitFailures
            ? t.html('consoleCluster.barrierFailed',
                     { n: String(barrier.commitFailures) })
            : '')
        : t.html('consoleCluster.barrierOff')]
    ];

    const html = '<h2>' + t.html('consoleCluster.rightNow') + '</h2>' +
      (off ? kit.note(t.html('consoleCluster.offNote')) : '') +
      '<table class="key"><tr><th>' + t.html('consoleCluster.thWhat') +
      '</th><th>' + t.html('consoleCluster.thAnswer') + '</th></tr>' +
      rows.map(function (row) {
        return '<tr><th>' + kit.esc(row[0]) + '</th><td>' + row[1] +
               '</td></tr>';
      }).join('') + '</table>' +
      ClusterStatusPage.members(info, t) +
      ClusterStatusPage.otherCells(info.otherCells, t) +
      ClusterStatusPage.capabilities(caps, t) +
      ClusterStatusPage.secrets(info.secrets, t);

    // FRAMED AS KEY PAIRS IS (`secframe`, rcbj 2026-11-16).
    return kit.frame(html);
  }

  // THE ROSTER: who is running, and when anything last heard from them.
  // The live members first, one row each, with what only that node can say
  // about itself; the names that left or expired folded underneath.
  /**
   * Draws the Members and Leases sections.
   *
   * @param info - the view's `status`
   * @param t - the page's translator
   * @returns the sections as HTML
   */
  static members(info: Json, t: Json): string {
    const self = info.self || {};
    const off = self.mode === 'off';
    const folded = info.members;
    const heading = '<h2>' + t.html('consoleCluster.membersHeading') +
      '</h2>';
    if (off || !folded) {
      return heading + kit.note(off
        ? t.html('consoleCluster.noListOff')
        : t.html('consoleCluster.noListYet', { mode: String(self.mode) }));
    }
    const now = Number(info.databaseNow) || 0;
    const nodes: Json[] = info.nodes || [];
    const byId: Json = {};
    nodes.forEach(function (node: Json) {
      byId[node.nodeId] = node;
    });
    const live: Json[] = (folded.running || []).map(function (id: string) {
      return byId[id];
    }).filter(Boolean);
    const gone: Json[] = (folded.leftOrExpired || []).map(function (one: Json) {
      return Object.assign({}, byId[one.nodeId] || {}, one);
    });
    const restarts = folded.restarts || {};
    const leases: Json[] = info.leases || [];
    const serviceLease = info.serviceLease || 'service';
    const nameOf: Json = {};
    nodes.forEach(function (node: Json) {
      nameOf[node.nodeId] = node.name;
    });
    // A lapsed lease row is left out: a released lease is expired and never
    // deleted, so listing every row would say a node holds what it gave up.
    const leasesOf: Json = {};
    leases.forEach(function (lease: Json) {
      if (lease.expiresAt <= now) {
        return;
      }
      (leasesOf[lease.holder] = leasesOf[lease.holder] || []).push(lease);
    });
    const ago = function (at: number): string {
      return ClusterStatusPage.ago(now, at, t);
    };
    const agoTxt = function (at: number): string {
      return ClusterStatusPage.agoText(now, at, t);
    };
    // Serving or standby, read from the lease table (active-passive: the
    // member holding the service lease serves).
    const roleOf = function (node: Json): string {
      const mine = leasesOf[node.nodeId] || [];
      const serving = node.mode === 'active-active' ||
        mine.some(function (lease: Json) {
          return lease.name === serviceLease;
        });
      return serving
        ? '<span class="state-valid">' + t.html('consoleCluster.serving') +
          '</span>'
        : '<span class="state-none">' + t.html('consoleCluster.standby') +
          '</span>';
    };
    const whereOf = function (node: Json): string {
      const where = node.info || {};
      const parts = [];
      if (where.host) {
        parts.push('<code>' + kit.esc(String(where.host)) +
                   (where.port ? ':' + kit.esc(String(where.port)) : '') +
                   '</code>');
      }
      if (where.pid) {
        parts.push(t.html('consoleCluster.pid', { pid: String(where.pid) }));
      }
      if (where.workers) {
        parts.push(t.html('consoleCluster.workers',
                          { n: String(where.workers) }));
      }
      return parts.length ? parts.join('<br>') : '—';
    };
    const upOf = function (node: Json): string {
      const where = node.info || {};
      const r = restarts[node.name || ''];
      const history = r
        ? '<br><span class="sub">' +
          t.html('consoleCluster.restarted',
                 { n: String(r.count), ago: agoTxt(r.lastEndedAt) }) +
          '</span>'
        : '';
      if (where.uptimeMs) {
        return kit.esc(kit.durationText(where.uptimeMs)) + history;
      }
      return t.html('consoleCluster.joinedAgo',
                    { ago: agoTxt(node.startedAt) }) +
        history;
    };
    const seenOf = function (node: Json): string {
      const stall = Number((node.info || {}).lastStallMs) || 0;
      return ago(node.heartbeatAt) + (stall
        ? '<br>' + t.html('consoleCluster.lastStall',
                          { s: String(Math.round(stall / 100) / 10) })
        : '');
    };
    const leasesCell = function (node: Json): string {
      const mine = leasesOf[node.nodeId] || [];
      return mine.length ? mine.map(function (lease: Json) {
        return t.html('consoleCluster.leaseAt',
                      { name: String(lease.name),
                        token: String(lease.token) });
      }).join('<br>') : t.html('consoleCluster.none');
    };
    const agreesCell = function (node: Json): string {
      if (node.agrees === null || node.agrees === undefined) {
        return t.html('consoleCluster.agreesUnknown');
      }
      return node.agrees ? t.html('consoleCluster.agreesYes')
                         : t.html('consoleCluster.agreesNo');
    };

    const liveRows = live.map(function (node: Json) {
      return '<tr><td><strong>' + kit.esc(node.name || '') + '</strong>' +
        (node.nodeId === self.nodeId
          ? ' <em>' + t.html('consoleCluster.thisNode') + '</em>' : '') +
        '<br><code>' + kit.esc(node.nodeId) + '</code></td><td>' +
        whereOf(node) + '</td><td>' + roleOf(node) + '<br>' +
        kit.esc(node.mode || '') + '</td><td>' +
        (node.version ? kit.esc(node.version)
                      : t.html('consoleCluster.unknown')) + '</td><td>' +
        upOf(node) + '</td><td>' + seenOf(node) + '</td><td>' +
        ago(node.expiresAt) + '</td><td>' + leasesCell(node) + '</td><td>' +
        agreesCell(node) + '</td></tr>';
    }).join('');

    const goneRows = gone.map(function (node: Json) {
      return '<tr><td><strong>' + kit.esc(node.name || '') +
        '</strong><br><code>' + kit.esc(node.nodeId || '') +
        '</code></td><td>' + whereOf(node) + '</td><td>' +
        kit.esc(node.mode || '') + '</td><td>' +
        (node.version ? kit.esc(node.version)
                      : t.html('consoleCluster.unknown')) + '</td><td>' +
        ago(node.startedAt) + '</td><td>' + ago(node.heartbeatAt) +
        '</td><td>' + (node.leftAt
          ? t.html('consoleCluster.leftCleanly',
                   { ago: agoTxt(node.leftAt) })
          : t.html('consoleCluster.expired',
                   { ago: agoTxt(node.expiresAt) })) +
        (node.earlierLives
          ? '<br><span class="sub">' +
            t.html('consoleCluster.earlierLives',
                   { n: String(node.earlierLives) }) + '</span>'
          : '') + '</td></tr>';
    }).join('');

    const goneTable = !gone.length ? ''
      : '<details class="fold"><summary>' +
        t.html('consoleCluster.goneSummary', { n: String(gone.length) }) +
        '</summary><div class="foldbody"><p>' +
        t.html('consoleCluster.goneNote') + '</p>' +
        kit.wideTable(t.text('consoleCluster.labelGone'),
          '<table><tr><th>' + t.html('consoleCluster.thNode') + '</th><th>' +
          t.html('consoleCluster.thWhere') + '</th><th>' +
          t.html('consoleCluster.thMode') + '</th><th>' +
          t.html('consoleCluster.thVersion') + '</th><th>' +
          t.html('consoleCluster.thStarted') + '</th><th>' +
          t.html('consoleCluster.thLastSeen') + '</th><th>' +
          t.html('consoleCluster.thEnded') + '</th></tr>' + goneRows +
          '</table>') + '</div></details>';

    const leaseTable = '<h2>' + t.html('consoleCluster.leasesHeading') +
      '</h2><p>' + t.html('consoleCluster.leasesNote') + '</p>' +
      '<table><tr><th>' + t.html('consoleCluster.thLease') + '</th><th>' +
      t.html('consoleCluster.thHolder') + '</th><th>' +
      t.html('consoleCluster.thToken') + '</th><th>' +
      t.html('consoleCluster.thExpires') + '</th></tr>' +
      (leases.length ? leases.map(function (lease: Json) {
        return '<tr><td><code>' + kit.esc(lease.name) + '</code></td><td>' +
          kit.esc(nameOf[lease.holder] || lease.holder || '') + '</td><td>' +
          kit.esc(String(lease.token)) + '</td><td>' +
          (lease.expiresAt <= now
            ? t.html('consoleCluster.releasedOrExpired')
            : ago(lease.expiresAt)) + '</td></tr>';
      }).join('')
        : '<tr><td colspan="4">' + t.html('consoleCluster.none') +
          '</td></tr>') + '</table>';

    return heading + '<div class="tiles">' +
      kit.tile(live.length, t.text('consoleCluster.tileRunning')) +
      kit.tile(Object.keys(leasesOf).length,
               t.text('consoleCluster.tileHolding')) +
      kit.tile(gone.length, t.text('consoleCluster.tileGone')) +
      '</div><p>' +
      t.html('consoleCluster.asOf',
             { age: String(Math.round((Number(info.snapshotAgeMs) || 0) /
                                      100) / 10) }) + '</p>' +
      kit.wideTable(t.text('consoleCluster.labelRunning'),
        '<table><tr><th>' + t.html('consoleCluster.thNode') + '</th><th>' +
        t.html('consoleCluster.thWhere') + '</th><th>' +
        t.html('consoleCluster.thState') + '</th><th>' +
        t.html('consoleCluster.thVersion') + '</th><th>' +
        t.html('consoleCluster.thUp') + '</th><th>' +
        t.html('consoleCluster.thLastSeen') + '</th><th>' +
        t.html('consoleCluster.thExpires') + '</th><th>' +
        t.html('consoleCluster.thLeases') + '</th><th>' +
        t.html('consoleCluster.thAgrees') + '</th></tr>' +
        (liveRows || '<tr><td colspan="9">' +
         t.html('consoleCluster.noLive') + '</td></tr>') + '</table>') +
      goneTable + leaseTable;
  }

  // EVERY OTHER CELL'S CLUSTER (#361), asked over the inter-cell channel
  // before the page was answered; nothing in a single-cell service.
  /**
   * Draws the other cells' section.
   *
   * @param held - the view's `status.otherCells`, or null
   * @param t - the page's translator
   * @returns the section as HTML, or '' in single-cell mode
   */
  static otherCells(held: Json, t: Json): string {
    if (!held) {
      return '';
    }
    const sections = (held.cells || []).map(function (row: Json) {
      const head = '<h3>' + t.html('consoleCluster.cellHeading',
        { cell: String(row.cell), jurisdiction:
          String(row.jurisdiction || '?') }) + '</h3>';
      if (!row.reachable) {
        return head + kit.warn(t.html('consoleCluster.cellNoAnswer',
                                      { error: String(row.error || '') }));
      }
      const sum = row.summary || {};
      const at = Number(sum.at) || 0;
      if (!sum.clustered) {
        return head + kit.note(t.html('consoleCluster.cellNotClustered',
          { ms: String(row.answeredMs), mode: String(sum.mode || 'off') }));
      }
      const members = sum.members || { live: [], restarts: {}, gone: [] };
      const restarts = members.restarts || {};
      const agoT = function (when: number): string {
        return ClusterStatusPage.ago(at, when, t);
      };
      const agoTx = function (when: number): string {
        return ClusterStatusPage.agoText(at, when, t);
      };
      const live = (members.live || []).map(function (n: Json) {
        const r = restarts[n.name] || null;
        return '<tr><td><strong>' + kit.esc(n.name) + '</strong></td><td>' +
          kit.esc(n.mode || '') + '</td><td>' +
          (n.version ? kit.esc(n.version)
                     : t.html('consoleCluster.unknown')) + '</td><td>' +
          (n.uptimeMs ? kit.esc(kit.durationText(n.uptimeMs)) : '—') +
          (r ? '<br><span class="sub">' +
               t.html('consoleCluster.restarted',
                      { n: String(r.count), ago: agoTx(r.lastEndedAt) }) +
               '</span>' : '') +
          '</td><td>' + agoT(n.heartbeatAt) +
          (n.lastStallMs ? '<br>' + t.html('consoleCluster.lastStall',
            { s: String(Math.round(n.lastStallMs / 100) / 10) }) : '') +
          '</td><td>' + kit.esc(String(n.workers || 0)) + '</td><td>' +
          ((n.leases || []).map(function (l: string) {
            return '<code>' + kit.esc(l) + '</code>';
          }).join('<br>') || t.html('consoleCluster.none')) + '</td><td>' +
          (n.agrees === null || n.agrees === undefined
            ? t.html('consoleCluster.agreesThere')
            : n.agrees ? t.html('consoleCluster.agreesYes')
                       : '<strong>' + t.html('consoleCluster.agreesNoShort') +
                         '</strong>') + '</td></tr>';
      }).join('');
      const gone = (members.gone || []).map(function (n: Json) {
        return '<tr><td>' + kit.esc(n.name || '—') + '</td><td>' +
          (n.version ? kit.esc(n.version)
                     : t.html('consoleCluster.unknown')) + '</td><td>' +
          (n.how === 'left'
            ? t.html('consoleCluster.leftCleanly',
                     { ago: agoTx(n.endedAt) })
            : t.html('consoleCluster.expired',
                     { ago: agoTx(n.endedAt) })) +
          (n.earlierLives ? '<br><span class="sub">' +
            t.html('consoleCluster.earlierLives',
                   { n: String(n.earlierLives) }) + '</span>' : '') +
          '</td></tr>';
      }).join('');
      const pools = (sum.pools || []).map(function (node: Json) {
        return (node.pools || []).map(function (p: Json) {
          return '<tr><td>' + kit.esc(node.name) +
            (node.state && node.state !== 'live'
              ? ' <em>(' + kit.esc(node.state) + ')</em>' : '') +
            '</td><td>' + kit.esc(p.title || p.id) + '</td><td>' +
            kit.esc(p.state || '') + '</td><td>' +
            kit.esc(String(p.currentWorkers)) + '</td><td>' +
            kit.esc(String(p.busyWorkers)) + '</td><td>' +
            kit.esc(String(p.freeWorkers)) + '</td><td>' +
            kit.esc(String(p.crashed)) + '</td><td>' +
            kit.esc(String(p.failedStarts)) + '</td></tr>';
        }).join('');
      }).join('');
      return head + '<div class="tiles">' +
        kit.tile((members.live || []).length,
                 t.text('consoleCluster.tileRunning')) +
        kit.tile((sum.leases || []).length,
                 t.text('consoleCluster.tileLeasesHeld')) +
        kit.tile((members.gone || []).length,
                 t.text('consoleCluster.tileGone')) +
        '</div><p class="sub">' +
        t.html('consoleCluster.cellSummary',
               { mode: String(sum.mode || ''),
                 ms: String(row.answeredMs) }) + '</p>' +
        kit.wideTable(t.text('consoleCluster.labelCellRunning',
                             { cell: String(row.cell) }),
          '<table><tr><th>' + t.html('consoleCluster.thNode') + '</th><th>' +
          t.html('consoleCluster.thMode') + '</th><th>' +
          t.html('consoleCluster.thVersion') + '</th><th>' +
          t.html('consoleCluster.thUp') + '</th><th>' +
          t.html('consoleCluster.thLastSeen') + '</th><th>' +
          t.html('consoleCluster.thRequestWorkers') + '</th><th>' +
          t.html('consoleCluster.thLeases') + '</th><th>' +
          t.html('consoleCluster.thAgrees') + '</th></tr>' +
          (live || '<tr><td colspan="8">' +
           t.html('consoleCluster.noRunning') + '</td></tr>') +
          '</table>') +
        (gone ? '<details class="fold"><summary>' +
          t.html('consoleCluster.cellGoneSummary',
                 { n: String((members.gone || []).length) }) +
          '</summary><div class="foldbody">' +
          kit.wideTable(t.text('consoleCluster.labelCellGone',
                               { cell: String(row.cell) }),
            '<table><tr><th>' + t.html('consoleCluster.thNode') +
            '</th><th>' + t.html('consoleCluster.thVersion') + '</th><th>' +
            t.html('consoleCluster.thEnded') + '</th></tr>' + gone +
            '</table>') + '</div></details>' : '') +
        (pools ? kit.wideTable(t.text('consoleCluster.labelCellPools',
                                      { cell: String(row.cell) }),
          '<table><tr><th>' + t.html('consoleCluster.thNode') + '</th><th>' +
          t.html('consoleCluster.thPool') + '</th><th>' +
          t.html('consoleCluster.thState') + '</th><th>' +
          t.html('consoleCluster.thPoolWorkers') + '</th><th>' +
          t.html('consoleCluster.thBusy') + '</th><th>' +
          t.html('consoleCluster.thFree') + '</th><th>' +
          t.html('consoleCluster.thCrashed') + '</th><th>' +
          t.html('consoleCluster.thFailedStarts') + '</th></tr>' + pools +
          '</table>')
          : (sum.poolsError
            ? kit.note(t.html('consoleCluster.poolsError',
                              { error: String(sum.poolsError) }))
            : ''));
    }).join('');
    return '<h2>' + t.html('consoleCluster.otherHeading') + '</h2>' +
      kit.note(t.html('consoleCluster.otherNote')) +
      (held.error ? kit.warn(kit.esc(held.error)) : '') +
      (sections || kit.note(t.html('consoleCluster.otherNone')));
  }

  /**
   * Draws what active-active depends on: the capability table.
   *
   * @param caps - `status.self.capabilities`
   * @param t - the page's translator
   * @returns the section as HTML
   */
  static capabilities(caps: Json, t: Json): string {
    const rows: Json[] = caps.rows || [];
    const accepted: string[] = caps.acceptedMissing || [];
    const unknown: string[] = caps.unknownAccepted || [];
    return '<h2>' + t.html('consoleCluster.capsHeading') + '</h2><p>' +
      (caps.ready
        ? (accepted.length
          ? t.html('consoleCluster.capsAccepted', { ids: accepted.join(', ') })
          : t.html('consoleCluster.capsReady'))
        : t.html('consoleCluster.capsMissing',
                 { missing: String((caps.missing || []).length),
                   total: String(rows.length) })) +
      (unknown.length
        ? ' ' + t.html('consoleCluster.capsUnknown',
                       { ids: unknown.join(', ') })
        : '') +
      '</p><table><tr><th>' + t.html('consoleCluster.thCapability') +
      '</th><th>#46</th><th>' + t.html('consoleCluster.thState') +
      '</th><th>' + t.html('consoleCluster.thWhat') + '</th><th>' +
      t.html('consoleCluster.thWhere') + '</th></tr>' +
      rows.map(function (row: Json) {
        return '<tr><td><code>' + kit.esc(row.id) + '</code></td><td>' +
          kit.esc(row.section || '') + '</td><td>' +
          (row.provided ? t.html('consoleCluster.provided')
            : (row.accepted ? t.html('consoleCluster.acceptedMissing')
                            : t.html('consoleCluster.missing'))) +
          '</td><td>' + kit.esc(row.what || '') + '</td><td><code>' +
          kit.esc(row.by || '') + '</code></td></tr>';
      }).join('') + '</table>';
  }

  /**
   * Draws where each shared secret's value came from, never the value.
   *
   * @param secrets - `status.secrets`, or nothing
   * @param t - the page's translator
   * @returns the section as HTML
   */
  static secrets(secrets: Json, t: Json): string {
    const list: Json[] = (secrets && secrets.secrets) || [];
    return '<h2>' + t.html('consoleCluster.secretsHeading') + '</h2>' +
      '<table><tr><th>' + t.html('consoleCluster.thSecret') + '</th><th>' +
      t.html('consoleCluster.thSource') + '</th><th>' +
      t.html('consoleCluster.thWhat') + '</th></tr>' +
      list.map(function (one: Json) {
        return '<tr><td><code>' + kit.esc(one.name) + '</code></td><td>' +
          kit.esc(one.source || '') + '</td><td>' + kit.esc(one.what || '') +
          '</td></tr>';
      }).join('') + '</table>';
  }
}

export = ClusterStatusPage;
