// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_caches.ts
//
// ---------------------------------------------------------------------------
// MONITORING → CACHES, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Caches from the answer of `GET /admin-api/caches`: every cache and
// replay store this process holds, what the other cluster nodes report, and
// one store's entries.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `CachesAdmin`'s in `admin-ui/caches_admin.ts`, moved with
// their comments; that module still draws the page until the console's
// cutover, by calling `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

const PAGE = '/admin/caches';

/**
 * Draws Caches from the answer of `GET /admin-api/caches`: every cache and
 * replay store this process holds, what the other cluster nodes report, and
 * one store's entries.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class CachesPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return CachesPage.body(ctx, view);
  }

  static ratioText(c: Json): string {
    if (!c.counted) {
      return 'not counted';
    }
    return c.hitRatio === null
      ? '—' : (Math.round(c.hitRatio * 1000) / 10) + '%';
  }

  // The bound as a number and, for a per-realm store, "per realm". A store
  // reporting none is a regression (`STS-CORE-0096`) and says so.
  static boundText(c: Json): string {
    if (c.maxEntries === null) {
      return 'none reported';
    }
    return String(c.maxEntries) + (c.scope === 'realm' ? ' per realm' : '');
  }

  // Under the bound: the fullest realm for a per-realm store, and what was
  // dropped or refused at it.
  static boundDetail(c: Json): string {
    const parts: string[] = [];
    if (c.scope === 'realm') {
      parts.push('fullest realm: ' + c.largestRealm);
    }
    if (c.evictions) {
      parts.push(c.evictions + ' dropped at the bound');
    }
    if (c.refusals) {
      parts.push(c.refusals + ' refused at the bound');
    }
    if (c.atBound) {
      parts.push('AT THE BOUND');
    }
    return parts.length
      ? '<br><small>' + kit.esc(parts.join('; ')) + '</small>' : '';
  }

  static settingsText(c: Json): string {
    return c.settings.length
      ? c.settings.map(function (k: string): string {
        return '<code>' + kit.esc(k) + '</code>';
      }).join(', ')
      : '—';
  }

  static tableOf(caches: Json[]): string {
    const self = this;
    const rows = caches.map(function (c: Json): string {
      return '<tr>' +
        '<td><a href="' + kit.esc(PAGE + '?cache=' +
                                    encodeURIComponent(c.name)) + '">' +
        kit.esc(c.title) + '</a><br><code>' + kit.esc(c.name) +
        '</code></td>' +
        '<td>' + kit.esc(c.description) +
        '<br><small>' + kit.esc(c.lifetime) + '</small>' +
        (c.bound ? '<br><small>' + kit.esc(c.bound) + '</small>' : '') +
        (c.problem ? kit.warn('Its entries could not be listed: ' +
                                kit.esc(c.problem)) : '') + '</td>' +
        '<td>' + kit.esc((c.scope === 'realm' ? 'per realm' : 'process') +
                           (c.persisted ? ', persisted' : '')) + '</td>' +
        '<td class="num">' + c.size + '</td>' +
        '<td class="num">' + c.valid + '</td>' +
        '<td class="num">' + c.expired + '</td>' +
        '<td class="num">' + kit.esc(self.boundText(c)) +
        self.boundDetail(c) + '</td>' +
        '<td class="num">' + kit.esc(self.ratioText(c)) +
        (c.counted ? '<br><small>' + c.hits + ' hit(s), ' + c.misses +
                     ' miss(es)</small>' : '') + '</td>' +
        '<td><code>' + kit.esc(c.owner) + '</code><br>' +
        self.settingsText(c) + '</td>' +
        '</tr>';
    }).join('');
    return '<table class="grid"><thead><tr>' +
      '<th>Name</th><th>Description</th><th>Scope</th>' +
      '<th>Current size</th><th>Valid</th><th>Expired</th>' +
      '<th>Max size</th><th>Hit ratio</th><th>Owner and settings</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="9">None is registered.</td></tr>') +
      '</tbody></table>';
  }

  static listHtml(json: Json): string {
    const self = this;
    const tiles = '<div class="tiles">' +
      kit.tile(String(json.totals.caches), 'caches') +
      kit.tile(String(json.totals.entries), 'entries held') +
      kit.tile(String(json.totals.expired), 'expired, not yet evicted') +
      kit.tile(String(json.pid), 'process') +
      '</div>';
    const what = kit.note(
      '<p>This page answers <strong>what this service is holding in memory ' +
      'that it could rebuild, and whether holding it is paying off</strong>. ' +
      'A cache is listed here by the module that owns it; a store whose ' +
      'entries cannot be rebuilt &mdash; a replay history, a session, an ' +
      'issued code &mdash; is a register and is not a cache, whatever its ' +
      'variable is called.</p>' +
      '<p><strong>Valid</strong> entries are still good. ' +
      '<strong>Expired</strong> ones are past their deadline, or were built ' +
      'from something that has since changed, and are still held because ' +
      'nothing has looked them up or pushed them out yet. The <strong>hit ' +
      'ratio</strong> is lookups answered from the cache over all lookups, ' +
      'since this process started. Every figure in the two tables is ' +
      'this process\'s own (pid ' + kit.esc(json.pid) + '): a request ' +
      'worker or another cluster node holds caches of its own, and what ' +
      'the other nodes report is in its own section below. Keys are shown ' +
      'and values never are.</p>' +
      '<p><strong>Every store has a bound.</strong> For a store kept per ' +
      'trust realm it is per realm: Current size counts every realm, and ' +
      'the fullest realm is the figure to compare with it. A bound is ' +
      'either <em>enforced</em> &mdash; the store drops its oldest entry, ' +
      'or, for a replay history, refuses the new one rather than forget a ' +
      'live one &mdash; or <em>structural</em>, where the store cannot ' +
      'outgrow something else that is bounded, such as one key set per ' +
      'realm. Each row says which.</p>', 'What this page is');
    const caches = json.caches.filter(function (c: Json): boolean {
      return c.kind !== 'replay';
    });
    const replays = json.caches.filter(function (c: Json): boolean {
      return c.kind === 'replay';
    });
    const table = '<h3>Caches</h3>' + self.tableOf(caches) +
      '<h3>Replay caches and nonces</h3>' +
      kit.note('These make a one-time value work once, so their entries ' +
                 'cannot be rebuilt and none of them has a control. A ' +
                 '<strong>hit</strong> here is a value found already held ' +
                 '&mdash; for a replay history, a second use refused; for a ' +
                 'nonce store, a nonce honoured &mdash; and each row says ' +
                 'which. A store that refuses when full says so in its ' +
                 'lifetime.', 'What a hit means here') +
      self.tableOf(replays);
    const others = self.otherProcessesHtml(json.otherProcesses);
    const skipped = '<h3>Not held by this process, and not listed</h3>' +
      '<table class="grid"><thead><tr><th>What</th><th>Where</th>' +
      '<th>Why it is not a row above</th></tr></thead><tbody>' +
      json.notListed.map(function (n: Json): string {
        return '<tr><td>' + kit.esc(n.what) + '</td><td><code>' +
          kit.esc(n.where) + '</code></td><td>' + kit.esc(n.why) +
          '</td></tr>';
      }).join('') + '</tbody></table>';
    return tiles + what + table + others + skipped;
  }

  // The other processes' figures: one folded table per process, sizes and
  // counters only, titled from THIS process's registry (every node of one
  // build registers the same stores; a name this build does not know is
  // shown as the name).
  static otherProcessesHtml(list: Json[]): string {
    const self = this;
    if (!list || !list.length) {
      return '<h3>Other cluster nodes</h3>' +
        kit.note('No other process\'s figures are visible: this service ' +
                   'is not clustered, or no other node has published a ' +
                   'report yet (a node publishes its first about five ' +
                   'seconds after it joins).', 'Nothing to show');
    }
    const sections = list.map(function (p: Json): string {
      const rows = p.caches.map(function (c: Json): string {
        const lookups = (c.hits || 0) + (c.misses || 0);
        const ratio = c.hits === null ? 'not counted'
          : (lookups ? (Math.round(c.hits / lookups * 1000) / 10) + '%' :
             '—');
        const shown = Object.assign({
          atBound: c.maxEntries !== null && c.largestRealm >= c.maxEntries
        }, c);
        return '<tr><td>' + kit.esc(c.title) +
          '<br><code>' + kit.esc(c.name) + '</code></td>' +
          '<td class="num">' + c.size + '</td>' +
          '<td class="num">' + c.valid + '</td>' +
          '<td class="num">' + kit.esc(self.boundText(shown)) +
          self.boundDetail(shown) + '</td>' +
          '<td class="num">' + kit.esc(ratio) + '</td></tr>';
      }).join('');
      const label = (p.thisNode ? 'This node\'s front process' : 'Node ' +
                     (p.name || p.nodeId)) + ' — ' + (p.host || '?') +
        ', pid ' + p.pid + ', ' + p.totals.entries + ' entries, as of ' +
        p.ageSeconds + ' s ago';
      return '<details><summary>' + kit.esc(label) + '</summary>' +
        '<table class="grid"><thead><tr><th>Name</th><th>Current size</th>' +
        '<th>Valid</th><th>Max size</th><th>Hit ratio</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></details>';
    }).join('');
    return '<h3>Other cluster nodes</h3>' +
      kit.note('Each node\'s front process publishes the sizes and ' +
                 'counters of its caches on its cluster membership row ' +
                 'every thirty seconds; this is the last each one ' +
                 'published. Rows are not published, so a drill-down is ' +
                 'always this process\'s own.', 'Where these come from') +
      sections;
  }

  static detailHtml(json: Json, query: Json): string {
    if (!json.found) {
      return kit.warn('There is no cache called <code>' +
        kit.esc(json.cache) + '</code> in this process. <a href="' +
        PAGE + '">Every cache</a> is listed on the Caches page.');
    }
    const c = json.summary;
    const tiles = '<div class="tiles">' +
      kit.tile(String(c.size), 'current size') +
      kit.tile(String(c.valid), 'valid') +
      kit.tile(String(c.expired), 'expired') +
      kit.tile(this.boundText(c), 'max size') +
      (c.scope === 'realm'
        ? kit.tile(String(c.largestRealm), 'fullest realm') : '') +
      kit.tile(this.ratioText(c), 'hit ratio') +
      '</div>';
    const about = '<table class="grid"><tbody>' +
      '<tr><th>Name</th><td><code>' + kit.esc(c.name) + '</code></td></tr>' +
      '<tr><th>Description</th><td>' + kit.esc(c.description) +
      '</td></tr>' +
      '<tr><th>How an entry ends</th><td>' + kit.esc(c.lifetime) +
      '</td></tr>' +
      '<tr><th>Bound</th><td>' + kit.esc(c.bound || '') +
      (c.evictions || c.refusals
        ? ' ' + kit.esc(c.evictions + ' dropped and ' + c.refusals +
                          ' refused at it since this process started.')
        : '') + '</td></tr>' +
      '<tr><th>Scope</th><td>' +
      kit.esc(c.scope === 'realm' ? 'One per trust realm' :
                'One for the process') + '</td></tr>' +
      '<tr><th>Kind</th><td>' +
      kit.esc(c.kind === 'replay' ? 'Replay cache or nonce store' :
                'Cache') + (c.persisted ? ', persisted' : '') +
      '</td></tr>' +
      '<tr><th>Lookups</th><td>' + (c.counted
        ? c.hits + ' hit(s), ' + c.misses + ' miss(es) since pid ' +
          kit.esc(json.pid) + ' started. A hit is ' +
          kit.esc(c.hitMeaning) + '.'
        : 'Not counted: ' + kit.esc(c.notCountedWhy) + '.') +
      '</td></tr>' +
      '<tr><th>Owner</th><td><code>' + kit.esc(c.owner) + '</code></td></tr>' +
      '<tr><th>Settings</th><td>' + this.settingsText(c) + '</td></tr>' +
      '</tbody></table>' +
      (c.problem ? kit.warn('Its entries could not be listed: ' +
                              kit.esc(c.problem)) : '');
    const params = kit.pageParamsOf(query);
    const nav = kit.pageNavPair(PAGE, params, json.entriesPaging);
    const rows = json.entries.map(function (e: Json): string {
      return '<tr>' +
        '<td>' + (e.realm === null ? '—' : '<code>' + kit.esc(e.realm) +
                  '</code>') + '</td>' +
        '<td>' + kit.clipped(e.key, 120) + '</td>' +
        '<td>' + kit.esc(e.valid ? 'valid' : 'expired') + '</td>' +
        '<td>' + kit.esc(e.remaining) + '</td>' +
        '<td>' + (e.validUntil ? '<code>' + kit.esc(e.validUntil) +
                  '</code>' : '—') + '</td>' +
        '</tr>';
    }).join('');
    const table = '<h3>Entries</h3>' +
      kit.perPageForm(PAGE, 'cache', c.name, json.entriesPaging.perPage,
                        'The entries are ordered by deadline, soonest ' +
                        'first; those with none come last.') +
      nav.head +
      '<table class="grid"><thead><tr><th>Realm</th><th>Key</th>' +
      '<th>State</th><th>Still valid for</th><th>Valid until</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="5">This cache holds nothing right ' +
       'now.</td></tr>') +
      '</tbody></table>' + nav.foot;
    return tiles + about + table;
  }

  // THE PAGE'S BODY, the list or one cache, from the answer the API gives
  // (`publicJson()`, which has no `paging` object: a drill-down's paging is
  // `entriesPaging`).
  /**
   * Draws the page's body: every cache, or one cache's entries.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the public view
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json): string {
    return json.cache === undefined ? this.listHtml(json)
      : this.detailHtml(json, ctx.query);
  }
}

export = CachesPage;
