// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_oauth2_monitor.ts
//
// ---------------------------------------------------------------------------
// MONITORING → OAUTH 2.0 / OIDC ACTIVITY, DRAWN FROM ITS VIEW ALONE (#446,
// 2026-10-05).
//
// Draws OAuth 2.0 / OIDC activity from the answer of `GET
// /admin-api/oauth2/monitor`: what the authorization server has done in this
// realm, per mechanism and per client, and the pushed authorization requests
// it still holds.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `OAuth2MonitorAdmin`'s in
// `oauth-oidc/oauth2_monitor_admin.ts`, moved with their comments; that module
// still draws the page until the console's cutover, by calling `render()` with
// its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

// The page's own path. `oauth2_monitor_console.ts` reads it from here: this
// module may not require that one.
const PAGE = '/admin/oauth2/monitor';

// Which pushed requests the table shows. `par.list()` knows these three words
// and nothing else; an `expired` record is swept before it could be listed.
// The filter is drawn from this list, so it is here, and the model that
// checks a query against it reads it back.
const STATES = ['live', 'spent', 'all'];

// The list parameters a Withdraw carries back so the 303 lands on the page and
// filter the reader was on. Rebuilt from these names and never echoed, for
// `listViewFromBack()`'s reason in admin.js: a redirect target taken out of a
// body is an open redirect, and one carrying a newline a header injection.
const BACK_PARAMS = ['state', 'client_id', 'per', 'page', 'clientsPage',
                     'stepUpClientsPage'];

/**
 * Draws OAuth 2.0 / OIDC activity from the answer of `GET
 * /admin-api/oauth2/monitor`: what the authorization server has done in this
 * realm, per mechanism and per client, and the pushed authorization requests
 * it still holds.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class OAuth2MonitorPage {
  /**
   * The page's path.
   */
  static readonly PAGE_PATH = PAGE;

  /**
   * The states the held-requests filter offers.
   */
  static readonly STATES = STATES;

  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @param ctx - the render context: the page's query and whether
   *   the reader may write (`WebKit.context()`)
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    return OAuth2MonitorPage.body(ctx, view);
  }

  static code(value: Json) {
    return value ? '<code>' + esc(value) + '</code>'
                 : '<span class="sub">—</span>';
  }

  static hidden(name: Json, value: Json) {
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(value) + '">';
  }

  // The list view as the reader left it, from a query the page is looking at.
  static listViewOf(query: Json) {
    const out = {};
    BACK_PARAMS.forEach(function (key) {
      const raw = (query || {})[key];
      const value = Array.isArray(raw) ? raw[0] : raw;
      if (value !== undefined && value !== null && String(value) !== '') {
        out[key] = String(value).slice(0, 256);
      }
    });
    return out;
  }

  // A request_uri is 34 characters of namespace and 43 of reference, which does
  // not fit a table cell beside eleven others. The cell shows the start of the
  // reference and opens to the whole value — in the markup, so it can be
  // selected and copied with no script.
  static requestUriCell(uri: Json) {
    const value = String(uri || '');
    const reference = value.slice(value.lastIndexOf(':') + 1);
    return '<details><summary><code title="' + esc(value) + '">…:' +
           esc(reference.slice(0, 10)) + '…</code></summary><code>' +
           esc(value) + '</code></details>';
  }

  // ---------------------------------------------------------------------------
  // THE PARTS OF THE RFC 9126 SECTION.
  // ---------------------------------------------------------------------------
  // The totals were `t` until #539 made `t` the translator's name on every
  // page; they are `totals` now.
  static tilesHtml(section: Json, t: Json) {
    const totals = section.totals;
    const held = section.pushedRequests;
    return '<div class="tiles">' +
      kit.tile(totals.pushed || 0, t.text('consoleOauth2Monitor.tPushed')) +
      kit.tile(totals.pushRefused || 0,
               t.text('consoleOauth2Monitor.tPushRefused')) +
      kit.tile(totals.resolved || 0,
               t.text('consoleOauth2Monitor.tResolved')) +
      kit.tile(totals.spent || 0, t.text('consoleOauth2Monitor.tSpent')) +
      kit.tile(totals.expired || 0, t.text('consoleOauth2Monitor.tExpired')) +
      kit.tile(totals.resolveRefused || 0,
               t.text('consoleOauth2Monitor.tResolveRefused')) +
      kit.tile(totals.deleted || 0, t.text('consoleOauth2Monitor.tDeleted')) +
      kit.tile(held.filter.state === 'all' && !held.filter.client_id
                   ? held.total : '—', t.text('consoleOauth2Monitor.tHeld')) +
      '</div>';
  }

  static countersHtml(section: Json, t: Json) {
    return '<table id="counters-' + esc(section.id) + '"><thead><tr><th>' +
      t.html('consoleOauth2Monitor.colCounted') + '</th><th>' +
      t.html('consoleOauth2Monitor.colCounter') + '</th><th>' +
      t.html('consoleOauth2Monitor.colTotal') + '</th></tr></thead><tbody>' +
      section.events.map(function (one) {
        return '<tr><td>' + esc(one.label) + '</td><td><code>' +
               esc(one.event) + '</code></td><td class="num">' + one.count +
               '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  static errorsHtml(rows: Json, t: Json) {
    return '<table><thead><tr><th>' +
      t.html('consoleOauth2Monitor.colError') + '</th><th>' +
      t.html('consoleOauth2Monitor.colCount') + '</th>' +
      '</tr>' +
      '</thead><tbody>' + (rows.length ? rows.map(function (r) {
        return '<tr><td><code>' + esc(r.name) + '</code></td><td class="num">' +
               r.count + '</td></tr>';
      }).join('') : '<tr><td colspan="2" class="sub">' +
        t.html('consoleOauth2Monitor.none') + '</td></tr>') +
      '</tbody></table>';
  }

  // Every section's per-client table. `emptyText` is the section's own, because
  // "nobody has done this" is a sentence about what THIS section counts; the
  // page parameter is carried on the section's paging (`pagingOf()` decides
  // it).
  static clientsHtml(ctx: Json, section: Json, emptyText: Json) {
    const t = ctx.t;
    const noun = t.text('consoleOauth2Monitor.nounClients');
    const nav = kit.pageNavPair(PAGE, ctx.query,
                                  Object.assign({ param: section.clientsParam ||
                                                         'clientsPage',
                                                  noun: noun },
                                                section.clientsPaging));
    const heads = section.events.map(function (one) {
      return '<th title="' + esc(one.label) + '">' + esc(one.counter) + '</th>';
    }).join('');
    const rows = section.clients.length ? section.clients.map(function (c) {
      return '<tr><td><a href="/admin/applications?application=' +
        encodeURIComponent(c.client_id) + '"><code>' + esc(c.client_id) +
        '</code></a></td>' + section.events.map(function (one) {
          return '<td class="num">' + (c.counters[one.counter] || 0) + '</td>';
        }).join('') + '<td>' + (c.errors.length ? c.errors.map(function (e) {
          return '<code>' + esc(e.name) + '</code> ' + e.count;
        }).join(', ') : '<span class="sub">' +
          t.html('consoleOauth2Monitor.none') + '</span>') + '</td><td>' +
        esc(c.lastAt || '—') + '<div class="sub">' + esc(c.lastEvent || '') +
        '</div></td></tr>';
    }).join('') : '<tr><td colspan="' + (section.events.length + 3) +
                  '" class="sub">' + esc(emptyText) + '</td></tr>';
    return nav.head + '<table><thead><tr><th>' +
      t.html('consoleOauth2Monitor.colClient') + '</th>' + heads +
      '<th>' + t.html('consoleOauth2Monitor.colErrors') + '</th><th>' +
      t.html('consoleOauth2Monitor.colLast') + '</th></tr></thead><tbody>' +
      rows + '</tbody></table>' + nav.foot;
  }

  static filterHtml(held: Json, t: Json) {
    const options = STATES.map(function (state) {
      return '<option value="' + esc(state) + '"' +
             (held.filter.state === state ? ' selected' : '') + '>' +
             esc(state) + '</option>';
    }).join('');
    return '<form method="get" action="' + esc(PAGE) + '#held" ' +
      'class="inline"><label>' + t.html('consoleOauth2Monitor.state') +
      ' <select name="state">' + options +
      '</select></label> <label>client_id <input name="client_id" size="24" ' +
      'value="' + esc(held.filter.client_id) + '"></label> <label>' +
      t.html('consoleOauth2Monitor.rows') + ' ' +
      '<input name="per" size="4" value="' + esc(String(held.limit)) +
      '"></label> <button type="submit" class="secondary">' +
      t.html('consoleOauth2Monitor.show') + '</button>' +
      '</form>';
  }

  static pushedRow(one: Json, back: Json, t: Json) {
    const self = this;
    const source = one.source === 'request'
      ? t.html('consoleOauth2Monitor.requestObject') + '<div class="sub">' +
        esc(one.request_object_alg || '?') +
        (one.request_object_encrypted
          ? t.html('consoleOauth2Monitor.encrypted',
                   { alg: one.request_object_encrypted }) : '') + '</div>'
      : t.html('consoleOauth2Monitor.form');
    const redirect = self.code(one.redirect_uri) +
      (one.redirect_uri_unregistered
      ? '<div class="state-invalid">' +
        t.html('consoleOauth2Monitor.unregistered') + '</div>' : '');
    return '<tr><td>' + self.requestUriCell(one.request_uri) + '</td><td>' +
      self.code(one.client_id) + '</td><td>' +
      self.code(one.authorization_server) +
      '</td><td>' + esc(one.state) + (one.spent_at ? '<div class="sub">' +
      esc(one.spent_at) + '</div>' : '') + '</td><td>' + esc(one.created_at) +
      '</td><td>' + esc(one.expires_at) + '<div class="sub">' +
      t.html('consoleOauth2Monitor.expiresIn', { s: one.expires_in }) +
      '</div></td><td class="num">' + one.reads +
      '</td><td>' + (one.client_authenticated
        ? t.html('consoleOauth2Monitor.yes')
        : '<strong>' + t.html('consoleOauth2Monitor.no') + '</strong>') +
      '<div class="sub">' + esc(one.authentication_method || 'none') +
      '</div></td><td>' + source + '</td><td>' + redirect +
      '<div class="sub">' + esc(one.response_type) +
      (one.scope ? ' · ' + esc(one.scope) : '') + '</div></td><td>' +
      self.code(one.dpop_jkt) + '</td><td><form method="post" action="' +
      esc(PAGE) + '">' + self.hidden('action', 'delete-pushed-request') +
      self.hidden('request_uri', one.request_uri) + self.hidden('back', back) +
      '<button type="submit" class="danger" title="' +
      esc(t.text('consoleOauth2Monitor.withdrawTitle')) + '">' +
      t.html('consoleOauth2Monitor.withdraw') + '</button>' +
      '</form></td></tr>';
  }

  static pushedRequestsHtml(ctx: Json, section: Json) {
    const self = this;
    const t = ctx.t;
    const held = section.pushedRequests;
    const back = kit.queryWith(self.listViewOf(ctx.query), {});
    const noun = t.text('consoleOauth2Monitor.nounPushed');
    const nav = kit.pageNavPair(PAGE, ctx.query,
                                  Object.assign({ param: 'page',
                                                  noun: noun },
                                                held.paging));
    const rows = held.items.length ? held.items.map(function (one) {
      return self.pushedRow(one, back, t);
    }).join('') : '<tr><td colspan="12" class="sub">' +
                  (held.filter.state === 'all' && !held.filter.client_id
                    ? t.html('consoleOauth2Monitor.noneHeld')
                    : t.html('consoleOauth2Monitor.noneMatch')) +
                  '</td></tr>';
    const th = function (key: string): string {
      return '<th>' + t.html(key) + '</th>';
    };
    return self.filterHtml(held, t) + nav.head +
      '<table id="pushed-requests">' +
      '<thead><tr><th>request_uri</th>' +
      th('consoleOauth2Monitor.colClient') +
      th('consoleOauth2Monitor.colAs') + th('consoleOauth2Monitor.colState') +
      th('consoleOauth2Monitor.colCreated') +
      th('consoleOauth2Monitor.colExpires') +
      th('consoleOauth2Monitor.colReads') +
      th('consoleOauth2Monitor.colAuthenticated') +
      th('consoleOauth2Monitor.colSource') + '<th>redirect_uri</th>' +
      '<th>DPoP jkt</th>' +
      '<th></th></tr></thead><tbody>' + rows + '</tbody></table>' + nav.foot +
      '<p class="sub">' +
      t.html('consoleOauth2Monitor.heldNote',
             { total: held.total, capacity: held.capacity,
               lifetime: held.lifetime_s }) +
      '</p>';
  }

  static parSectionHtml(ctx: Json, section: Json) {
    const self = this;
    const t = ctx.t;
    return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
      '</h2>' +
      kit.note(t.html('consoleOauth2Monitor.parNote')) +
      self.tilesHtml(section, t) +
      '<h3>' + t.html('consoleOauth2Monitor.everyCounter') + '</h3>' +
      self.countersHtml(section, t) +
      '<h3>' + t.html('consoleOauth2Monitor.byClient') + '</h3>' +
      self.clientsHtml(ctx, section,
                       t.text('consoleOauth2Monitor.parNoClients')) +
      '<h3>' + t.html('consoleOauth2Monitor.allErrors') + '</h3>' +
      self.errorsHtml(section.errors, t) +
      '<h3 id="held">' + t.html('consoleOauth2Monitor.heldHeading') +
      '</h3>' +
      self.pushedRequestsHtml(ctx, section);
  }

  // ---------------------------------------------------------------------------
  // THE RFC 9470 SECTION (2026-09-13). Counts, and the one requirement that is
  // not written on an application's page: what this service's own resource
  // server demands. No list and no control — a requirement is a property of a
  // request that has already been answered, so there is nothing held to show.
  // ---------------------------------------------------------------------------
  static stepUpTilesHtml(section: Json, t: Json) {
    const totals = section.totals;
    return '<div class="tiles">' +
      kit.tile(totals.stepUpMetBySession || 0,
               t.text('consoleOauth2Monitor.tMetBySession')) +
      kit.tile((totals.stepUpReauthMaxAge || 0) +
                 (totals.stepUpReauthAcr || 0),
               t.text('consoleOauth2Monitor.tSentAgain')) +
      kit.tile(totals.stepUpMetAfterSignIn || 0,
               t.text('consoleOauth2Monitor.tMetAfter')) +
      kit.tile(totals.stepUpUnmet || 0, 'unmet_authentication_requirements') +
      kit.tile(totals.stepUpLoginRequired || 0, 'login_required') +
      kit.tile(totals.stepUpChallenged || 0,
               t.text('consoleOauth2Monitor.tChallenges')) +
      '</div>';
  }

  static stepUpSectionHtml(ctx: Json, section: Json) {
    const self = this;
    const t = ctx.t;
    const own = section.ownResourceRequirement || {};
    const ownText = (own.acr_values || own.max_age !== null)
      ? (own.acr_values ? 'acr_values <code>' + esc(own.acr_values) +
                          '</code>' : '') +
        (own.acr_values && own.max_age !== null
          ? t.html('consoleOauth2Monitor.and') : '') +
        (own.max_age !== null
          ? t.html('consoleOauth2Monitor.maxAge',
                   { s: String(own.max_age) }) : '')
      : t.html('consoleOauth2Monitor.nothing');
    // The step-up note's last sentence lists the acr values, and the own
    // resource server paragraph runs into a link and a path holding braces;
    // each is split where markup or a brace would have to go (#539).
    return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
      '</h2>' +
      kit.note(t.html('consoleOauth2Monitor.stepUpNote') +
        section.acrValuesSupported.map(function (one) {
          return '<code>' + esc(one) + '</code>';
        }).join(' &lt; ') + t.html('consoleOauth2Monitor.stepUpNoteEnd')) +
      self.stepUpTilesHtml(section, t) +
      '<p>' + t.html('consoleOauth2Monitor.ownRequires') + ownText +
      ' — ' +
      '<a href="/admin/oauth2">' + t.html('consoleOauth2Monitor.ownLink') +
      '</a>' +
      t.html('consoleOauth2Monitor.ownApi',
             { path: '/oauth2/step-up/resource/{application}' }) + '</p>' +
      '<h3>' + t.html('consoleOauth2Monitor.everyCounter') + '</h3>' +
      self.countersHtml(section, t) +
      '<h3>' + t.html('consoleOauth2Monitor.byClient') + '</h3>' +
      self.clientsHtml(ctx, section,
                       t.text('consoleOauth2Monitor.stepUpNoClients')) +
      '<h3>' + t.html('consoleOauth2Monitor.allErrors') + '</h3>' +
      self.errorsHtml(section.errors, t);
  }

  // THE PAGE'S BODY, one method so that it can be one renderer (#446): what
  // the route handler assembled, less the notice and error banner, which is
  // the shell's to draw.
  /**
   * Draws the page's body: the lead, a link per section, each section, and
   * the closing notes.
   *
   * @param ctx - the render context (`WebKit.context()`)
   * @param json - the view from `monitorView()`
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json) {
    const self = this;
    const t = ctx.t;
    const sections = json.sections.map(function (section) {
      if (section.id === 'par') {
        return self.parSectionHtml(ctx, section);
      }
      return section.id === 'stepup' ?
        self.stepUpSectionHtml(ctx, section) : '';
    }).join('');
    const inner =
      kit.note(t.html('consoleOauth2Monitor.lead', { since: json.since })) +
      '<p class="links">' + json.sections.map(function (section) {
        return '<a href="#section-' + esc(section.id) + '">' +
               esc(section.title) + '</a>';
      }).join(' · ') + '</p>' +
      sections +
      kit.note(t.html('consoleOauth2Monitor.noReset') +
                 '<a href="/admin/audit">' +
                 t.html('consoleOauth2Monitor.auditLog') + '</a>' +
                 t.html('consoleOauth2Monitor.noResetEnd')) +
      '<p class="links"><a href="' + esc(PAGE) + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/oauth2/monitor</code> · <a ' +
      'href="/admin/oauth2">' + t.html('consoleOauth2Monitor.settingsLink') +
      '</a> · <a ' +
      'href="/admin/error-codes">' +
      t.html('consoleOauth2Monitor.errorCodesLink') + '</a></p>';
    return inner;
  }
}

export = OAuth2MonitorPage;
