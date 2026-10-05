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
  static tilesHtml(section: Json) {
    const t = section.totals;
    const held = section.pushedRequests;
    return '<div class="tiles">' +
      kit.tile(t.pushed || 0, 'pushed') +
      kit.tile(t.pushRefused || 0, 'pushes refused') +
      kit.tile(t.resolved || 0, 'request_uris read') +
      kit.tile(t.spent || 0, 'spent') +
      kit.tile(t.expired || 0, 'expired unspent') +
      kit.tile(t.resolveRefused || 0, 'refused at /authorize') +
      kit.tile(t.deleted || 0, 'withdrawn') +
      kit.tile(held.filter.state === 'all' && !held.filter.client_id
                   ? held.total : '—', 'held now') +
      '</div>';
  }

  static countersHtml(section: Json) {
    return '<table id="counters-' + esc(section.id) + '"><thead><tr><th>What ' +
      'was counted</th><th>Counter</th><th>Total</th></tr></thead><tbody>' +
      section.events.map(function (one) {
        return '<tr><td>' + esc(one.label) + '</td><td><code>' +
               esc(one.event) + '</code></td><td class="num">' + one.count +
               '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  static errorsHtml(rows: Json) {
    return '<table><thead><tr><th>OAuth error returned</th><th>Count</th>' +
      '</tr>' +
      '</thead><tbody>' + (rows.length ? rows.map(function (r) {
        return '<tr><td><code>' + esc(r.name) + '</code></td><td class="num">' +
               r.count + '</td></tr>';
      }).join('') : '<tr><td colspan="2" class="sub">none</td></tr>') +
      '</tbody></table>';
  }

  // Every section's per-client table. `emptyText` is the section's own, because
  // "nobody has done this" is a sentence about what THIS section counts; the
  // page parameter is carried on the section's paging (`pagingOf()` decides
  // it).
  static clientsHtml(ctx: Json, section: Json, emptyText: Json) {
    const nav = kit.pageNavPair(PAGE, ctx.query,
                                  Object.assign({ param: section.clientsParam ||
                                                         'clientsPage',
                                                  noun: 'clients' },
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
        }).join(', ') : '<span class="sub">none</span>') + '</td><td>' +
        esc(c.lastAt || '—') + '<div class="sub">' + esc(c.lastEvent || '') +
        '</div></td></tr>';
    }).join('') : '<tr><td colspan="' + (section.events.length + 3) +
                  '" class="sub">' + esc(emptyText) + '</td></tr>';
    return nav.head + '<table><thead><tr><th>Client</th>' + heads +
      '<th>Errors returned</th><th>Last activity</th></tr></thead><tbody>' +
      rows + '</tbody></table>' + nav.foot;
  }

  static filterHtml(held: Json) {
    const options = STATES.map(function (state) {
      return '<option value="' + esc(state) + '"' +
             (held.filter.state === state ? ' selected' : '') + '>' +
             esc(state) + '</option>';
    }).join('');
    return '<form method="get" action="' + esc(PAGE) + '#held" ' +
      'class="inline"><label>State <select name="state">' + options +
      '</select></label> <label>client_id <input name="client_id" size="24" ' +
      'value="' + esc(held.filter.client_id) + '"></label> <label>Rows ' +
      '<input name="per" size="4" value="' + esc(String(held.limit)) +
      '"></label> <button type="submit" class="secondary">Show</button>' +
      '</form>';
  }

  static pushedRow(one: Json, back: Json) {
    const self = this;
    const source = one.source === 'request'
      ? 'request object<div class="sub">' + esc(one.request_object_alg || '?') +
        (one.request_object_encrypted ? ', encrypted ' +
         esc(one.request_object_encrypted) : '') + '</div>'
      : 'form';
    const redirect = self.code(one.redirect_uri) +
      (one.redirect_uri_unregistered
      ? '<div class="state-invalid">unregistered — accepted under RFC 9126 ' +
        'section 2.4 for an authenticated client</div>' : '');
    return '<tr><td>' + self.requestUriCell(one.request_uri) + '</td><td>' +
      self.code(one.client_id) + '</td><td>' +
      self.code(one.authorization_server) +
      '</td><td>' + esc(one.state) + (one.spent_at ? '<div class="sub">' +
      esc(one.spent_at) + '</div>' : '') + '</td><td>' + esc(one.created_at) +
      '</td><td>' + esc(one.expires_at) + '<div class="sub">in ' +
      one.expires_in + 's</div></td><td class="num">' + one.reads +
      '</td><td>' + (one.client_authenticated ? 'yes' : '<strong>no</strong>') +
      '<div class="sub">' + esc(one.authentication_method || 'none') +
      '</div></td><td>' + source + '</td><td>' + redirect +
      '<div class="sub">' + esc(one.response_type) +
      (one.scope ? ' · ' + esc(one.scope) : '') + '</div></td><td>' +
      self.code(one.dpop_jkt) + '</td><td><form method="post" action="' +
      esc(PAGE) + '">' + self.hidden('action', 'delete-pushed-request') +
      self.hidden('request_uri', one.request_uri) + self.hidden('back', back) +
      '<button type="submit" class="danger" title="Withdraw this ' +
      'request_uri: the authorization endpoint refuses it from now ' +
      'on">Withdraw</button>' +
      '</form></td></tr>';
  }

  static pushedRequestsHtml(ctx: Json, section: Json) {
    const self = this;
    const held = section.pushedRequests;
    const back = kit.queryWith(self.listViewOf(ctx.query), {});
    const nav = kit.pageNavPair(PAGE, ctx.query,
                                  Object.assign({ param: 'page',
                                                  noun: 'pushed requests' },
                                                held.paging));
    const rows = held.items.length ? held.items.map(function (one) {
      return self.pushedRow(one, back);
    }).join('') : '<tr><td colspan="12" class="sub">No pushed authorization ' +
                  'request ' + (held.filter.state === 'all' &&
                                !held.filter.client_id
                    ? 'is held in this realm.' : 'matches this filter.') +
                  '</td></tr>';
    return self.filterHtml(held) + nav.head + '<table id="pushed-requests">' +
      '<thead><tr><th>request_uri</th><th>Client</th><th>Authorization server' +
      '</th><th>State</th><th>Created</th><th>Expires</th><th>Reads</th>' +
      '<th>Client authenticated</th><th>Source</th><th>redirect_uri</th>' +
      '<th>DPoP jkt</th>' +
      '<th></th></tr></thead><tbody>' + rows + '</tbody></table>' + nav.foot +
      '<p class="sub">Held: ' + held.total + ' matching, at most ' +
      held.capacity + ' live per realm (oauth2.parMaxRequests), each for ' +
      held.lifetime_s + ' seconds (oauth2.parRequestUriLifetimeS). A spent ' +
      'request_uri is kept until it would have expired, so a replay is ' +
      'refused as already used rather than as unknown. Withdrawing needs ' +
      'Admin Write.' +
      '</p>';
  }

  static parSectionHtml(ctx: Json, section: Json) {
    const self = this;
    return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
      '</h2>' +
      kit.note('A client pushes the parameters of an authorization request ' +
        'to /oauth2/par over the back channel and is answered a request_uri; ' +
        'the browser then carries only that reference to /oauth2/authorize. ' +
        'The request is read there at least twice in one browser flow and is ' +
        'spent when an authorization response is issued on it.') +
      self.tilesHtml(section) +
      '<h3>Every counter</h3>' + self.countersHtml(section) +
      '<h3>By client</h3>' +
      self.clientsHtml(ctx, section, 'No client has pushed an authorization ' +
                                'request in this realm since the process ' +
                                'started.') +
      '<h3>Errors returned, all clients</h3>' +
      self.errorsHtml(section.errors) +
      '<h3 id="held">Pushed requests still held</h3>' +
      self.pushedRequestsHtml(ctx, section);
  }

  // ---------------------------------------------------------------------------
  // THE RFC 9470 SECTION (2026-09-13). Counts, and the one requirement that is
  // not written on an application's page: what this service's own resource
  // server demands. No list and no control — a requirement is a property of a
  // request that has already been answered, so there is nothing held to show.
  // ---------------------------------------------------------------------------
  static stepUpTilesHtml(section: Json) {
    const t = section.totals;
    return '<div class="tiles">' +
      kit.tile(t.stepUpMetBySession || 0, 'met by the session') +
      kit.tile((t.stepUpReauthMaxAge || 0) + (t.stepUpReauthAcr || 0),
                 'sent to sign in again') +
      kit.tile(t.stepUpMetAfterSignIn || 0, 'met after signing in') +
      kit.tile(t.stepUpUnmet || 0, 'unmet_authentication_requirements') +
      kit.tile(t.stepUpLoginRequired || 0, 'login_required') +
      kit.tile(t.stepUpChallenged || 0, 'resource challenges') +
      '</div>';
  }

  static stepUpSectionHtml(ctx: Json, section: Json) {
    const self = this;
    const own = section.ownResourceRequirement || {};
    const ownText = (own.acr_values || own.max_age !== null)
      ? (own.acr_values ? 'acr_values <code>' + esc(own.acr_values) +
                          '</code>' : '') +
        (own.acr_values && own.max_age !== null ? ' and ' : '') +
        (own.max_age !== null ? 'max_age <code>' + esc(String(own.max_age)) +
                                '</code> seconds' : '')
      : 'nothing';
    return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
      '</h2>' +
      kit.note('A resource server that finds the authentication behind a ' +
        'token too weak or too old answers 401 ' +
        '<code>insufficient_user_authentication</code> with the ' +
        '<code>acr_values</code> and <code>max_age</code> it needs, and the ' +
        'client repeats them in an authorization request. The authorization ' +
        'endpoint answers from the session when the session meets them, ' +
        'sends the person to sign in again once when it does not, and ' +
        'refuses <code>unmet_authentication_requirements</code> when that ' +
        'sign-in did not meet them either. Each authorization-endpoint count ' +
        'is one pass, so a step-up that succeeds counts once as sent to sign ' +
        'in again and once as met after signing in. The context classes this ' +
        'service ' +
        'produces are ' + section.acrValuesSupported.map(function (one) {
          return '<code>' + esc(one) + '</code>';
        }).join(' &lt; ') + '.') +
      self.stepUpTilesHtml(section) +
      '<p>This service\'s own resource server (UserInfo, the OpenID4VCI ' +
      'endpoints, SCIM, Shared Signals) requires ' + ownText + ' — ' +
      '<a href="/admin/oauth2">oauth2.stepUpAcrValues and ' +
      'oauth2.stepUpMaxAgeS</a>. A registered API\'s requirement is on its ' +
      'application entry (<code>oauthStepUpAcrValues</code>, ' +
      '<code>oauthStepUpMaxAge</code>), enforced by ' +
      '<code>/oauth2/step-up/resource/{application}</code>.</p>' +
      '<h3>Every counter</h3>' + self.countersHtml(section) +
      '<h3>By client</h3>' +
      self.clientsHtml(ctx, section, 'No authorization request in this realm ' +
                                'has carried acr_values or max_age, and no ' +
                                'resource server here has challenged a ' +
                                'token, ' +
                                'since the process started.') +
      '<h3>Errors returned, all clients</h3>' + self.errorsHtml(section.errors);
  }

  // THE PAGE'S BODY, one method so that it can be one renderer (#446): what
  // the route handler assembled, less the notice and error banner, which is
  // the shell's to draw.
  /**
   * Draws the page's body: the lead, a link per section, each section, and
   * the closing notes.
   *
   * @param ctx - the request, of which only the query is read
   * @param json - the view from `monitorView()`
   * @returns the body as HTML
   */
  static body(ctx: Json, json: Json) {
    const self = this;
    const sections = json.sections.map(function (section) {
      if (section.id === 'par') {
        return self.parSectionHtml(ctx, section);
      }
      return section.id === 'stepup' ?
        self.stepUpSectionHtml(ctx, section) : '';
    }).join('');
    const inner =
      kit.note('<strong>What the authorization server has done</strong> ' +
                 'in ' +
                 'this realm since ' + esc(json.since) + ', one section ' +
                 'per mechanism. The counters are merged across every ' +
                 'process ' +
                 'answering this realm.') +
      '<p class="links">' + json.sections.map(function (section) {
        return '<a href="#section-' + esc(section.id) + '">' +
               esc(section.title) + '</a>';
      }).join(' · ') + '</p>' +
      sections +
      kit.note('There is no reset: a console that could zero its own ' +
                 'monitoring would make every number on it one somebody ' +
                 'might have zeroed. The durable record of each withdrawal ' +
                 'is the ' +
                 '<a href="/admin/audit">Audit log</a>.') +
      '<p class="links"><a href="' + esc(PAGE) + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/oauth2/monitor</code> · <a ' +
      'href="/admin/oauth2">OAuth 2.0 / OIDC settings</a> · <a ' +
      'href="/admin/error-codes">Error ' +
      'codes</a></p>';
    return inner;
  }
}

export = OAuth2MonitorPage;
