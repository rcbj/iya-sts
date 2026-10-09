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

// A VALUE THE VIEW CARRIES, INSIDE A TRANSLATED SENTENCE (#539 phase 6). A
// message's parameters are escaped by the translator, which writes an
// apostrophe as `&#39;` where `kit.esc()` writes `&apos;`; so a sentence
// that carries the view's own words — `hitMeaning`, which says "a token's
// status" — is formatted with this mark in the value's place and the value,
// escaped by `kit.esc()` as before, put in after. English stays the bytes it
// was.
const MARK = '\u0001';

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
    return CachesPage.body(ctx || kit.context(), view);
  }

  // A formatted message with `MARK` replaced by markup already escaped.
  static put(message: string, html: string): string {
    return message.split(MARK).join(html);
  }

  // The helpers below have no context, so each is handed the page's
  // translator `t` by its caller (#539).
  static ratioText(c: Json, t: Json): string {
    if (!c.counted) {
      return t.text('consoleCaches.notCounted');
    }
    return c.hitRatio === null
      ? '—' : (Math.round(c.hitRatio * 1000) / 10) + '%';
  }

  // The bound as a number and, for a per-realm store, "per realm". A store
  // reporting none is a regression (`STS-CORE-0096`) and says so.
  static boundText(c: Json, t: Json): string {
    if (c.maxEntries === null) {
      return t.text('consoleCaches.noneReported');
    }
    return c.scope === 'realm'
      ? t.text('consoleCaches.boundPerRealm', { n: String(c.maxEntries) })
      : String(c.maxEntries);
  }

  // Under the bound: the fullest realm for a per-realm store, and what was
  // dropped or refused at it.
  static boundDetail(c: Json, t: Json): string {
    const parts: string[] = [];
    if (c.scope === 'realm') {
      parts.push(t.text('consoleCaches.fullestRealmIs',
                        { n: String(c.largestRealm) }));
    }
    if (c.evictions) {
      parts.push(t.text('consoleCaches.droppedAtBound',
                        { n: String(c.evictions) }));
    }
    if (c.refusals) {
      parts.push(t.text('consoleCaches.refusedAtBound',
                        { n: String(c.refusals) }));
    }
    if (c.atBound) {
      parts.push(t.text('consoleCaches.atTheBound'));
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

  static tableOf(caches: Json[], t: Json): string {
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
        '<td>' + kit.esc((c.scope === 'realm'
                            ? t.text('consoleCaches.scopePerRealm')
                            : t.text('consoleCaches.scopeProcess')) +
                           (c.persisted
                             ? t.text('consoleCaches.persisted') : '')) +
        '</td>' +
        '<td class="num">' + c.size + '</td>' +
        '<td class="num">' + c.valid + '</td>' +
        '<td class="num">' + c.expired + '</td>' +
        '<td class="num">' + kit.esc(self.boundText(c, t)) +
        self.boundDetail(c, t) + '</td>' +
        '<td class="num">' + kit.esc(self.ratioText(c, t)) +
        (c.counted ? '<br><small>' +
                     t.html('consoleCaches.hitsMisses',
                            { hits: String(c.hits),
                              misses: String(c.misses) }) +
                     '</small>' : '') + '</td>' +
        '<td><code>' + kit.esc(c.owner) + '</code><br>' +
        self.settingsText(c) + '</td>' +
        '</tr>';
    }).join('');
    return '<table class="grid"><thead><tr>' +
      '<th>' + t.html('consoleCaches.thName') + '</th><th>' +
      t.html('consoleCaches.thDescription') + '</th><th>' +
      t.html('consoleCaches.thScope') + '</th>' +
      '<th>' + t.html('consoleCaches.thCurrentSize') + '</th><th>' +
      t.html('consoleCaches.thValid') + '</th><th>' +
      t.html('consoleCaches.thExpired') + '</th>' +
      '<th>' + t.html('consoleCaches.thMaxSize') + '</th><th>' +
      t.html('consoleCaches.thHitRatio') + '</th><th>' +
      t.html('consoleCaches.thOwnerSettings') + '</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="9">' +
       t.html('consoleCaches.noneRegistered') + '</td></tr>') +
      '</tbody></table>';
  }

  static listHtml(json: Json, t: Json): string {
    const self = this;
    const tiles = '<div class="tiles">' +
      kit.tile(String(json.totals.caches),
               t.text('consoleCaches.tileCaches')) +
      kit.tile(String(json.totals.entries),
               t.text('consoleCaches.tileEntriesHeld')) +
      kit.tile(String(json.totals.expired),
               t.text('consoleCaches.tileExpiredHeld')) +
      kit.tile(String(json.pid), t.text('consoleCaches.tileProcess')) +
      '</div>';
    const what = kit.note(
      '<p>' + t.html('consoleCaches.aboutWhat') + '</p>' +
      '<p>' + self.put(t.html('consoleCaches.aboutFigures',
                              { pid: MARK }), kit.esc(json.pid)) + '</p>' +
      '<p>' + t.html('consoleCaches.aboutBound') + '</p>',
      t.text('consoleCaches.whatThisPageIs'));
    const caches = json.caches.filter(function (c: Json): boolean {
      return c.kind !== 'replay';
    });
    const replays = json.caches.filter(function (c: Json): boolean {
      return c.kind === 'replay';
    });
    const table = '<h3>' + t.html('consoleCaches.headCaches') + '</h3>' +
      self.tableOf(caches, t) +
      '<h3>' + t.html('consoleCaches.headReplay') + '</h3>' +
      kit.note(t.html('consoleCaches.replayNote'),
               t.text('consoleCaches.replayNoteLabel')) +
      self.tableOf(replays, t);
    const others = self.otherProcessesHtml(json.otherProcesses, t);
    const skipped = '<h3>' + t.html('consoleCaches.headNotListed') +
      '</h3>' +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleCaches.thWhat') + '</th><th>' +
      t.html('consoleCaches.thWhere') + '</th>' +
      '<th>' + t.html('consoleCaches.thWhyNot') +
      '</th></tr></thead><tbody>' +
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
  // `t` is optional because `tests/cache_registry.js` draws this section
  // alone, in English.
  static otherProcessesHtml(list: Json[], t?: Json): string {
    t = t || kit.context().t;
    const self = this;
    if (!list || !list.length) {
      return '<h3>' + t.html('consoleCaches.headOtherNodes') + '</h3>' +
        kit.note(t.html('consoleCaches.noOtherNodes'),
                 t.text('consoleCaches.nothingToShow'));
    }
    const sections = list.map(function (p: Json): string {
      const rows = p.caches.map(function (c: Json): string {
        const lookups = (c.hits || 0) + (c.misses || 0);
        const ratio = c.hits === null ? t.text('consoleCaches.notCounted')
          : (lookups ? (Math.round(c.hits / lookups * 1000) / 10) + '%' :
             '—');
        const shown = Object.assign({
          atBound: c.maxEntries !== null && c.largestRealm >= c.maxEntries
        }, c);
        return '<tr><td>' + kit.esc(c.title) +
          '<br><code>' + kit.esc(c.name) + '</code></td>' +
          '<td class="num">' + c.size + '</td>' +
          '<td class="num">' + c.valid + '</td>' +
          '<td class="num">' + kit.esc(self.boundText(shown, t)) +
          self.boundDetail(shown, t) + '</td>' +
          '<td class="num">' + kit.esc(ratio) + '</td></tr>';
      }).join('');
      const label = (p.thisNode
        ? t.text('consoleCaches.thisNodeFront')
        : t.text('consoleCaches.nodeNamed',
                 { name: String(p.name || p.nodeId) })) + ' — ' +
        t.text('consoleCaches.nodeFigures',
               { host: String(p.host || '?'), pid: String(p.pid),
                 entries: String(p.totals.entries),
                 age: String(p.ageSeconds) });
      return '<details><summary>' + kit.esc(label) + '</summary>' +
        '<table class="grid"><thead><tr><th>' +
        t.html('consoleCaches.thName') + '</th><th>' +
        t.html('consoleCaches.thCurrentSize') + '</th>' +
        '<th>' + t.html('consoleCaches.thValid') + '</th><th>' +
        t.html('consoleCaches.thMaxSize') + '</th><th>' +
        t.html('consoleCaches.thHitRatio') + '</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></details>';
    }).join('');
    return '<h3>' + t.html('consoleCaches.headOtherNodes') + '</h3>' +
      kit.note(t.html('consoleCaches.otherNodesNote'),
               t.text('consoleCaches.otherNodesNoteLabel')) +
      sections;
  }

  static detailHtml(json: Json, query: Json, t: Json): string {
    if (!json.found) {
      return kit.warn('There is no cache called <code>' +
        kit.esc(json.cache) + '</code> in this process. <a href="' +
        PAGE + '">Every cache</a> is listed on the Caches page.');
    }
    const c = json.summary;
    const tiles = '<div class="tiles">' +
      kit.tile(String(c.size), t.text('consoleCaches.tileCurrentSize')) +
      kit.tile(String(c.valid), t.text('consoleCaches.tileValid')) +
      kit.tile(String(c.expired), t.text('consoleCaches.tileExpired')) +
      kit.tile(this.boundText(c, t), t.text('consoleCaches.tileMaxSize')) +
      (c.scope === 'realm'
        ? kit.tile(String(c.largestRealm),
                   t.text('consoleCaches.tileFullestRealm')) : '') +
      kit.tile(this.ratioText(c, t), t.text('consoleCaches.tileHitRatio')) +
      '</div>';
    const about = '<table class="grid"><tbody>' +
      '<tr><th>' + t.html('consoleCaches.thName') + '</th><td><code>' +
      kit.esc(c.name) + '</code></td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thDescription') + '</th><td>' +
      kit.esc(c.description) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thHowEnds') + '</th><td>' +
      kit.esc(c.lifetime) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thBound') + '</th><td>' +
      kit.esc(c.bound || '') +
      (c.evictions || c.refusals
        ? ' ' + kit.esc(t.text('consoleCaches.droppedRefusedSince',
                               { evictions: String(c.evictions),
                                 refusals: String(c.refusals) }))
        : '') + '</td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thScope') + '</th><td>' +
      kit.esc(c.scope === 'realm'
        ? t.text('consoleCaches.scopeOnePerRealm')
        : t.text('consoleCaches.scopeOneProcess')) + '</td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thKind') + '</th><td>' +
      kit.esc(c.kind === 'replay'
        ? t.text('consoleCaches.kindReplay')
        : t.text('consoleCaches.kindCache')) +
      (c.persisted ? t.html('consoleCaches.persisted') : '') +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thLookups') + '</th><td>' +
      // Two view values in one sentence: the pid in `MARK`'s place, the
      // hit's meaning in a second mark's.
      (c.counted
        ? this.put(t.html('consoleCaches.lookupsCounted',
                          { hits: String(c.hits), misses: String(c.misses),
                            pid: MARK, meaning: '\u0002' }),
                   kit.esc(json.pid)).split('\u0002')
            .join(kit.esc(c.hitMeaning))
        : this.put(t.html('consoleCaches.lookupsNotCounted',
                          { why: MARK }), kit.esc(c.notCountedWhy))) +
      '</td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thOwner') + '</th><td><code>' +
      kit.esc(c.owner) + '</code></td></tr>' +
      '<tr><th>' + t.html('consoleCaches.thSettings') + '</th><td>' +
      this.settingsText(c) + '</td></tr>' +
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
        '<td>' + kit.esc(e.valid ? t.text('consoleCaches.stateValid')
                                 : t.text('consoleCaches.stateExpired')) +
        '</td>' +
        '<td>' + kit.esc(e.remaining) + '</td>' +
        '<td>' + (e.validUntil ? '<code>' + kit.esc(e.validUntil) +
                  '</code>' : '—') + '</td>' +
        '</tr>';
    }).join('');
    const table = '<h3>' + t.html('consoleCaches.headEntries') + '</h3>' +
      kit.perPageForm(PAGE, 'cache', c.name, json.entriesPaging.perPage,
                        t.html('consoleCaches.entriesOrder')) +
      nav.head +
      '<table class="grid"><thead><tr><th>' +
      t.html('consoleCaches.thRealm') + '</th><th>' +
      t.html('consoleCaches.thKey') + '</th>' +
      '<th>' + t.html('consoleCaches.thState') + '</th><th>' +
      t.html('consoleCaches.thStillValidFor') + '</th><th>' +
      t.html('consoleCaches.thValidUntil') + '</th>' +
      '</tr></thead><tbody>' +
      (rows || '<tr><td colspan="5">' +
       t.html('consoleCaches.holdsNothing') + '</td></tr>') +
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
    const t = ctx.t;
    return json.cache === undefined ? this.listHtml(json, t)
      : this.detailHtml(json, ctx.query, t);
  }
}

export = CachesPage;
