// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_passkey_report.ts
//
// ---------------------------------------------------------------------------
// MONITORING → PASSKEYS, DRAWN FROM ITS VIEW ALONE (#942, 2026-10-23).
//
// Draws the answer of `GET /admin-api/passkey-report`
// (`common/passkey_report.ts`'s `reportAsync()`): who in the realm holds
// which kind of passkey. The Metadata tab carries where the numbers came
// from (the recount's baseline and the changes noted since, or the
// population a filter read), the filter and Recount now; then People (the
// four kinds), Algorithms (by algorithm and lane), Models (AAGUID by
// algorithm), Profiles (what each passkey profile asks, and a link to count
// its population), Attestation (#941's tab, empty until the key rows carry
// the algorithm) and, when the query names one, the List behind a count with
// its export.
//
// **THE LIST PAGES BY A CURSOR, AND THE LINKS CARRY IT.** A realm list is
// read in key order from where the page before stopped, so the Next link
// carries `from` (the view's `paging.nextFrom`) beside `page`; a page asked
// without it is found by reading from the start, which the view says when
// it stopped short (`paging.complete`).
//
// The page's own words are the `consolePasskeyReport` catalogs'. WHAT THE
// SERVER SAYS IS DATA (#539): a refusal, a group's DN, a model's name are
// drawn as they are, escaped.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_`
// modules only, logs nothing, and is bundled for a browser by
// `build-typescript.sh` with the rest of the console. Born static: no page
// module draws it.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');

type Json = any;

const PAGE_PATH = '/admin/passkey-report';
const API_PATH = '/admin-api/passkey-report';
const TAB = 'passkey-report-tab-';

// The kinds, each with its catalog word.
const KIND_WORDS: Record<string, string> = {
  'post-quantum-only': 'kindPostQuantumOnly',
  'classical-only': 'kindClassicalOnly',
  both: 'kindBoth',
  none: 'kindNone'
};

/**
 * Draws Monitoring → Passkeys from the answer of `GET
 * /admin-api/passkey-report`.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class PasskeyReportPage {
  /** The page's console path. */
  static readonly PAGE_PATH = PAGE_PATH;

  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    const context = ctx || kit.context();
    const t = context.t;
    const v = view || {};
    const self = PasskeyReportPage;
    return kit.note(t.html('consolePasskeyReport.lead')) +
      self.counted(v, t) +
      self.filterForm(v, context) +
      self.recountForm(context) +
      '<h2 data-tab="people">' + t.html('consolePasskeyReport.people') +
      '</h2>' + self.people(v, context) +
      '<h2 data-tab="algorithms">' +
      t.html('consolePasskeyReport.algorithms') + '</h2>' +
      self.algorithms(v, context) +
      '<h2 data-tab="models">' + t.html('consolePasskeyReport.models') +
      '</h2>' + self.models(v, context) +
      '<h2 data-tab="profiles">' + t.html('consolePasskeyReport.profiles') +
      '</h2>' + self.profiles(v, context) +
      '<h2 data-tab="attestation">' +
      t.html('consolePasskeyReport.attestation') + '</h2>' +
      self.attestation(v, t) +
      (v.list ? '<h2 data-tab="list">' + t.html('consolePasskeyReport.list') +
                '</h2>' + self.list(v, context) : '') +
      '<div data-metadata>' + kit.note('<a href="' + API_PATH + '">' +
        t.html('consolePasskeyReport.linkApi') + '</a> &middot; ' +
        '<a href="/admin/policies#passkey">' +
        t.html('consolePasskeyReport.linkPolicies') + '</a> &middot; ' +
        '<a href="/admin/webauthn">' +
        t.html('consolePasskeyReport.linkWebauthn') + '</a> &middot; ' +
        '<a href="/admin/scheduler">' +
        t.html('consolePasskeyReport.linkScheduler') + '</a>') + '</div>';
  }

  // The view's filter as query parameters, for every link the page draws.
  private static filterQuery(v: Json): Record<string, string> {
    const f = v.filter || {};
    const out: Record<string, string> = {};
    ['group', 'profile', 'application'].forEach(function (name) {
      if (f[name]) {
        out[name] = String(f[name]);
      }
    });
    return out;
  }

  // A link to this page with the filter kept and `extra` added; `tab` the
  // fragment it lands on.
  private static href(v: Json, extra: Record<string, string>,
                      tab: string): string {
    const q = Object.assign(PasskeyReportPage.filterQuery(v), extra);
    const parts = Object.keys(q).filter(function (k) {
      return q[k] !== '' && q[k] !== undefined && q[k] !== null;
    }).map(function (k) {
      return encodeURIComponent(k) + '=' + encodeURIComponent(q[k]);
    });
    return PAGE_PATH + (parts.length ? '?' + parts.join('&') : '') +
      (tab ? '#' + TAB + tab : '');
  }

  // A number in the reader's language, as TEXT (a message's parameter is
  // escaped by the translator, and a tile escapes its own); a dash where it
  // is unknown. `cell()` is the same, escaped, for markup.
  private static n(t: Json, value: Json): string {
    if (value === null || value === undefined || value === '') {
      return '—';
    }
    return typeof t.number === 'function' ? t.number(Number(value))
                                          : String(value);
  }

  // `n()`, escaped, for a table cell.
  private static cell(t: Json, value: Json): string {
    return kit.esc(PasskeyReportPage.n(t, value));
  }

  // A share of a total, as a percentage; a dash for an unknown total.
  private static share(t: Json, part: Json, total: Json): string {
    const whole = Number(total);
    if (!whole || part === null || part === undefined) {
      return '—';
    }
    const ratio = Number(part) / whole;
    return kit.esc(typeof t.number === 'function'
      ? t.number(ratio, { style: 'percent', maximumFractionDigits: 1 })
      : (Math.round(ratio * 1000) / 10) + '%');
  }

  // Where the numbers came from, and what a filter read.
  private static counted(v: Json, t: Json): string {
    const self = PasskeyReportPage;
    const c = v.counted || null;
    let out = '';
    if (!c) {
      out += kit.warn(t.html('consolePasskeyReport.countedNever'));
    } else if (c.from === 'population') {
      const p = v.population || {};
      out += kit.note(t.html('consolePasskeyReport.countedPopulation', {
        read: self.n(t, p.read), members: self.n(t, p.members) }));
      if (p.complete === false) {
        out += kit.warn(t.html('consolePasskeyReport.populationCut', {
          limit: self.n(t, (v.limits || {}).population),
          read: self.n(t, p.read) }));
      }
      (p.groups || []).forEach(function (g: Json) {
        if (!g.found) {
          out += kit.warn(t.html('consolePasskeyReport.groupMissing',
                                 { group: g.asked }));
        }
      });
    } else {
      out += kit.note(t.html(c.changesSince
        ? 'consolePasskeyReport.countedBaseline'
        : 'consolePasskeyReport.countedNoChanges', {
          at: String(c.at || ''), holders: self.n(t, c.holders),
          duration: self.n(t, c.durationMs),
          changes: self.n(t, c.changesSince),
          last: String(c.lastChangeAt || '') }));
      out += kit.note(t.html('consolePasskeyReport.howAggregate'));
    }
    const f = v.filter || {};
    const scope = f.scope === 'group'
      ? t.html('consolePasskeyReport.scopeGroup', { name: f.group })
      : (f.scope === 'profile'
        ? t.html('consolePasskeyReport.scopeProfile', { name: f.profile })
        : (f.scope === 'application'
          ? t.html('consolePasskeyReport.scopeApplication',
                   { name: f.application })
          : t.html('consolePasskeyReport.scopeRealm')));
    out += kit.note(t.html('consolePasskeyReport.filterIs') + ' ' + scope);
    if (v.application) {
      out += kit.note(t.html('consolePasskeyReport.applicationNote', {
        profile: String(v.application.applies || 'default'),
        groups: self.n(t, v.application.groupPolicies) }));
    }
    return out;
  }

  // The filter: one GET form, one box each; a GET form navigates to its
  // query in the static console.
  private static filterForm(v: Json, ctx: Json): string {
    const t = ctx.t;
    const f = v.filter || {};
    const box = function (name: string, word: string, value: string): string {
      return '<label>' + t.html('consolePasskeyReport.' + word) +
        ' <input type="text" name="' + name + '" value="' +
        kit.esc(value || '') + '" maxlength="512"></label> ';
    };
    const profiles = (v.profiles || []).filter(function (p: Json) {
      return p.name && p.name !== 'default';
    });
    const select = profiles.length
      ? '<label>' + t.html('consolePasskeyReport.filterProfile') +
        ' <select name="profile"><option value="">—</option>' +
        profiles.map(function (p: Json) {
          return '<option value="' + kit.esc(p.name) + '"' +
            (p.name === f.profile ? ' selected' : '') + '>' +
            kit.esc(p.name) + '</option>';
        }).join('') + '</select></label> '
      : '';
    return '<form method="get" action="' + PAGE_PATH + '">' +
      box('group', 'filterGroup', f.group) + select +
      box('application', 'filterApplication', f.application) +
      '<button type="submit">' + t.html('consolePasskeyReport.filterApply') +
      '</button></form>' +
      (f.scope && f.scope !== 'realm'
        ? kit.note('<a href="' + PAGE_PATH + '">' +
                   t.html('consolePasskeyReport.filterClear') + '</a>')
        : '');
  }

  // Recount now, drawn only for a reader who may write.
  private static recountForm(ctx: Json): string {
    if (!ctx.write) {
      return '';
    }
    const t = ctx.t;
    return '<form method="post" action="' + PAGE_PATH + '">' +
      '<input type="hidden" name="action" value="recount">' +
      '<button type="submit">' + t.html('consolePasskeyReport.recount') +
      '</button></form>' +
      kit.note(t.html('consolePasskeyReport.recountNote'));
  }

  // The People tab: the tiles, and the four kinds with their lists.
  private static people(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PasskeyReportPage;
    const p = v.people || {};
    const tiles = '<div class="tiles">' +
      kit.tile(self.n(t, p.total),
               t.text('consolePasskeyReport.tilePeople')) +
      kit.tile(self.n(t, p.holding),
               t.text('consolePasskeyReport.tileHolding')) +
      kit.tile(self.n(t, p.withPostQuantum),
               t.text('consolePasskeyReport.tileWithPq')) +
      kit.tile(self.n(t, p.none), t.text('consolePasskeyReport.tileNone')) +
      '</div>';
    const counts: Record<string, Json> = {
      'post-quantum-only': p.postQuantumOnly,
      'classical-only': p.classicalOnly,
      both: p.both,
      none: p.none
    };
    const rows = Object.keys(KIND_WORDS).map(function (kind) {
      return '<tr><td>' + t.html('consolePasskeyReport.' + KIND_WORDS[kind]) +
        '</td><td>' + self.cell(t, counts[kind]) + '</td><td>' +
        self.share(t, counts[kind], p.total) + '</td><td><a href="' +
        kit.esc(self.href(v, { list: kind }, 'list')) + '">' +
        t.html('consolePasskeyReport.showList') + '</a></td></tr>';
    }).join('');
    return tiles + '<table><tr><th>' + t.html('consolePasskeyReport.kind') +
      '</th><th>' + t.html('consolePasskeyReport.count') + '</th><th>' +
      t.html('consolePasskeyReport.share') + '</th><th></th></tr>' + rows +
      '</table>' + kit.note(t.html('consolePasskeyReport.kindNote'));
  }

  // A lane in the reader's words.
  private static laneWord(t: Json, lane: string): string {
    return lane === 'pqc' ? t.html('consolePasskeyReport.lanePqc')
                          : t.html('consolePasskeyReport.laneClassical');
  }

  // The Algorithms tab: every algorithm in every lane, with its list.
  private static algorithms(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PasskeyReportPage;
    const k = v.keys || {};
    const rows = (k.byAlgorithm || []).map(function (r: Json) {
      return '<tr><td><code>' + kit.esc(r.algorithm) + '</code></td><td>' +
        kit.esc(String(r.coseAlg)) + '</td><td>' + self.laneWord(t, r.lane) +
        '</td><td>' + (r.postQuantum ? t.html('consolePasskeyReport.yes')
                                     : t.html('consolePasskeyReport.no')) +
        '</td><td>' + self.cell(t, r.count) + '</td><td>' +
        self.share(t, r.count, k.total) + '</td><td><a href="' +
        kit.esc(self.href(v, { list: 'algorithm', algorithm: r.algorithm,
                               lane: r.lane }, 'list')) + '">' +
        t.html('consolePasskeyReport.showList') + '</a></td></tr>';
    }).join('');
    if (!rows) {
      return kit.note(t.html('consolePasskeyReport.noKeys'));
    }
    return kit.note(t.html('consolePasskeyReport.keysTotal', {
      total: self.n(t, k.total), pq: self.n(t, k.postQuantum),
      classical: self.n(t, k.classical) })) +
      '<table><tr><th>' + t.html('consolePasskeyReport.algorithm') +
      '</th><th>' + t.html('consolePasskeyReport.coseAlg') + '</th><th>' +
      t.html('consolePasskeyReport.lane') + '</th><th>' +
      t.html('consolePasskeyReport.postQuantum') + '</th><th>' +
      t.html('consolePasskeyReport.count') + '</th><th>' +
      t.html('consolePasskeyReport.share') + '</th><th></th></tr>' + rows +
      '</table>';
  }

  // The Models tab: each AAGUID and the algorithms its keys use.
  private static models(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PasskeyReportPage;
    const rows = (v.models || []).map(function (m: Json) {
      const id = m.aaguid === '(other)'
        ? t.html('consolePasskeyReport.other')
        : (m.aaguid ? '<code>' + kit.esc(m.aaguid) + '</code>'
                    : t.html('consolePasskeyReport.unreported'));
      const algs = (m.algorithms || []).map(function (a: Json) {
        return '<code>' + kit.esc(a.algorithm) + '</code> ' +
          self.cell(t, a.count);
      }).join(', ');
      const link = m.aaguid === '(other)' ? ''
        : '<a href="' + kit.esc(self.href(v, {
            list: 'model', aaguid: m.aaguid || 'unreported' }, 'list')) +
          '">' + t.html('consolePasskeyReport.showList') + '</a>';
      return '<tr><td>' + id + '</td><td>' + kit.esc(m.name || '') +
        '</td><td>' + algs + '</td><td>' + self.cell(t, m.total) +
        '</td><td>' + link + '</td></tr>';
    }).join('');
    if (!rows) {
      return kit.note(t.html('consolePasskeyReport.noModels'));
    }
    return '<table><tr><th>' + t.html('consolePasskeyReport.aaguid') +
      '</th><th>' + t.html('consolePasskeyReport.model') + '</th><th>' +
      t.html('consolePasskeyReport.algorithms') + '</th><th>' +
      t.html('consolePasskeyReport.count') + '</th><th></th></tr>' + rows +
      '</table>';
  }

  // The Profiles tab: what each passkey profile asks, and its population.
  private static profiles(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PasskeyReportPage;
    const named = (v.profiles || []).filter(function (p: Json) {
      return p.name !== 'default';
    });
    const rows = (v.profiles || []).map(function (p: Json) {
      const link = p.name === 'default' || !(p.selectGroups || []).length
        ? ''
        : '<a href="' + kit.esc(PAGE_PATH + '?profile=' +
                                encodeURIComponent(p.name) + '#' + TAB +
                                'people') + '">' +
          t.html('consolePasskeyReport.countThisProfile') + '</a>';
      return '<tr><td><code>' + kit.esc(p.name) + '</code></td><td><code>' +
        kit.esc(p.postQuantumRequired || 'off') + '</code></td><td>' +
        kit.esc((p.selectGroups || []).join(', ')) + '</td><td>' +
        kit.esc((p.selectApplications || []).join(', ')) + '</td><td>' +
        self.cell(t, p.precedence) + '</td><td>' + link + '</td></tr>';
    }).join('');
    return kit.note(t.html('consolePasskeyReport.profilesNote')) +
      (named.length ? ''
                    : kit.note(t.html('consolePasskeyReport.noProfiles'))) +
      '<table><tr><th>' + t.html('consolePasskeyReport.profileName') +
      '</th><th><code>postQuantumRequired</code></th><th>' +
      t.html('consolePasskeyReport.selectGroups') + '</th><th>' +
      t.html('consolePasskeyReport.selectApplications') + '</th><th>' +
      t.html('consolePasskeyReport.precedence') + '</th><th></th></tr>' +
      rows + '</table>';
  }

  // The Attestation tab (#941): empty until the key rows carry it.
  private static attestation(v: Json, t: Json): string {
    const self = PasskeyReportPage;
    const a = v.attestation || {};
    if (!a.recorded) {
      return kit.note(t.html('consolePasskeyReport.attestationPending'));
    }
    return '<table><tr><th>' + t.html('consolePasskeyReport.algorithm') +
      '</th><th>' + t.html('consolePasskeyReport.coseAlg') + '</th><th>' +
      t.html('consolePasskeyReport.postQuantum') + '</th><th>' +
      t.html('consolePasskeyReport.count') + '</th></tr>' +
      (a.rows || []).map(function (r: Json) {
        return '<tr><td><code>' + kit.esc(r.algorithm) + '</code></td><td>' +
          kit.esc(String(r.coseAlg)) + '</td><td>' +
          (r.postQuantum ? t.html('consolePasskeyReport.yes')
                         : t.html('consolePasskeyReport.no')) + '</td><td>' +
          self.cell(t, r.count) + '</td></tr>';
      }).join('') + '</table>';
  }

  // What the list is of, in the reader's words.
  private static listName(l: Json, t: Json): string {
    if (KIND_WORDS[l.list]) {
      return t.html('consolePasskeyReport.' + KIND_WORDS[l.list]);
    }
    if (l.list === 'algorithm') {
      return l.lane
        ? t.html('consolePasskeyReport.listAlgorithmLane', {
            algorithm: l.algorithm, lane: l.lane === 'pqc'
              ? t.text('consolePasskeyReport.lanePqc')
              : t.text('consolePasskeyReport.laneClassical') })
        : t.html('consolePasskeyReport.listAlgorithm',
                 { algorithm: l.algorithm });
    }
    if (l.list === 'model') {
      return t.html('consolePasskeyReport.listModel',
                    { aaguid: l.aaguid || 'unreported' });
    }
    return t.html('consolePasskeyReport.listHolding');
  }

  // The List tab: one page of the people behind a count, its paging and
  // its export.
  private static list(v: Json, ctx: Json): string {
    const t = ctx.t;
    const self = PasskeyReportPage;
    const l = v.list || {};
    const pg = l.paging || {};
    const keep: Record<string, string> = { list: String(l.list || '') };
    if (l.algorithm) {
      keep.algorithm = String(l.algorithm);
    }
    if (l.lane) {
      keep.lane = String(l.lane);
    }
    if (l.list === 'model') {
      keep.aaguid = String(l.aaguid || 'unreported');
    }
    const rows = (l.rows || []).map(function (r: Json) {
      const keys = (r.keys || []).map(function (k: Json) {
        return '<code>' + kit.esc(k.algorithm) + '</code> (' +
          self.laneWord(t, k.lane) + (k.model ? ', ' + kit.esc(k.model) : '') +
          ')';
      }).join('<br>');
      return '<tr><td><a href="/admin/users?user=' +
        encodeURIComponent(String(r.username || '')) + '">' +
        kit.esc(r.username) + '</a></td><td>' +
        t.html('consolePasskeyReport.' + (KIND_WORDS[r.kind] || 'kindNone')) +
        '</td><td>' + self.cell(t, r.passkeys) + '</td><td>' + keys +
        '</td></tr>';
    }).join('');
    const per = String(pg.perPage || '');
    const nav: string[] = [];
    if (Number(pg.page) > 1) {
      nav.push('<a href="' + kit.esc(self.href(v, Object.assign({}, keep,
        { per: per }), 'list')) + '">' +
        t.html('consolePasskeyReport.first') + '</a>');
    }
    if (pg.hasNext) {
      nav.push('<a href="' + kit.esc(self.href(v, Object.assign({}, keep, {
        per: per, page: String(Number(pg.page || 1) + 1),
        from: String(pg.nextFrom || '') }), 'list')) + '">' +
        t.html('consolePasskeyReport.next') + '</a>');
    }
    const exportHref = function (format: string): string {
      const q = Object.assign(self.filterQuery(v), keep, { format: format });
      return API_PATH + '/export?' + Object.keys(q).map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(q[k]);
      }).join('&');
    };
    return kit.note(t.html('consolePasskeyReport.listHeading') + ' ' +
                    self.listName(l, t)) +
      (pg.complete === false
        ? kit.warn(t.html('consolePasskeyReport.listCut',
                          { scanned: self.n(t, pg.scanned) }))
        : '') +
      (rows
        ? '<table><tr><th>' + t.html('consolePasskeyReport.username') +
          '</th><th>' + t.html('consolePasskeyReport.kind') + '</th><th>' +
          t.html('consolePasskeyReport.passkeysCol') + '</th><th>' +
          t.html('consolePasskeyReport.algorithms') + '</th></tr>' + rows +
          '</table>'
        : kit.note(t.html('consolePasskeyReport.listEmpty'))) +
      kit.note(t.html('consolePasskeyReport.pageOf', {
        page: self.n(t, pg.page) }) +
        (nav.length ? ' &middot; ' + nav.join(' &middot; ') : '')) +
      kit.note('<a href="' + kit.esc(exportHref('csv')) +
               '" download="passkeys.csv">' +
               t.html('consolePasskeyReport.exportCsv') + '</a> &middot; ' +
               '<a href="' + kit.esc(exportHref('json')) +
               '" download="passkeys.json">' +
               t.html('consolePasskeyReport.exportJson') + '</a> &middot; ' +
               t.html('consolePasskeyReport.exportNote', {
                 limit: self.n(t, (v.limits || {}).export) }));
  }
}

export = PasskeyReportPage;
