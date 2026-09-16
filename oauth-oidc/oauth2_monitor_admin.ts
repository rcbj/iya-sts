'use strict';
//
// File: oauth2_monitor_admin.ts
//
// ---------------------------------------------------------------------------
// MONITORING -> OAUTH 2.0 / OIDC ACTIVITY, `/admin/oauth2/monitor`
// (2026-09-13).
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `acme/acme_admin.ts` draws `/admin/acme/monitor`. Every fact on the page
// comes out of ONE call to `oauth2_monitor_console.ts`, which is the same call
// `GET /admin-api/oauth2/monitor` answers with (rule 7).
//
// **WHERE IT IS FILED IS DECIDED BY THE QUESTION IT ANSWERS.** `/admin/oauth2`
// is what the authorization server is CONFIGURED to do; this is what it has
// DONE — so it is under Monitoring, beside the other protocol traffic pages,
// and the path under `/admin/oauth2/` is not evidence (admin-ui/CLAUDE.md, *THE
// XACML MONITOR IS IN `Monitoring`*).
//
// **THE PAGE IS IN SECTIONS**, one per mechanism `oauth2_monitor.SECTIONS`
// names, so the next OAuth mechanism worth counting adds a section here rather
// than a page beside it. RFC 9126's pushed authorization requests are the
// first: counted per client, and the requests the store still holds listed
// with a Withdraw button each. RFC 9470's step-up is the second (2026-09-13):
// counted per client, with the requirement this service's own resource
// server enforces.
//
// **REQUIRED AT 18f**, from `common/protocol_stack.js`, for 18a's reason: it
// requires `admin-ui/admin` for the shell — a require the other way would
// close a cycle — and `oauth2_monitor_console.ts`, which requires
// `oauth-oidc/par.ts`, `oauth-oidc/oauth2_monitor.ts`, `oauth-oidc/step_up.ts`
// and `admin-core/admin_views.ts`, libraries already loaded by that line.
// `oauth2.ts` at 9 cannot require it: that would drag the whole console in
// front of the authorization server.
//
// No script, like every page of this console but one: paging and the filter
// are GET links and a GET form, and Withdraw is a POST form the console gate
// checks CSRF and Admin Write on before this handler runs.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1): `OAuth2MonitorAdmin`
// takes the console shell, the view model and the rest through its
// constructor, and its `registerRoutes(app)` holds the page's two routes in
// their old order. The TRANSITIONAL code at the bottom builds one from the
// real modules and registers its routes at load, where they always were.
// The module still exports nothing but the class: it is required for its
// routes.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import consoleModel = require('./oauth2_monitor_console');

type Req = any;
type Res = any;
type Next = any;
type Json = any;

interface OAuth2MonitorAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  // The console's HTML escaper, `admin.esc`.
  esc: typeof admin.esc;
  consoleModel: typeof consoleModel;
}

const PAGE = consoleModel.PAGE_PATH;

// The list parameters a Withdraw carries back so the 303 lands on the page and
// filter the reader was on. Rebuilt from these names and never echoed, for
// `listViewFromBack()`'s reason in admin.js: a redirect target taken out of a
// body is an open redirect, and one carrying a newline a header injection.
const BACK_PARAMS = ['state', 'client_id', 'per', 'page', 'clientsPage',
                     'stepUpClientsPage'];

class OAuth2MonitorAdmin {
  constructor(private readonly deps: OAuth2MonitorAdminDeps) {
    deps.log.debug("Entering OAuth2MonitorAdmin.constructor().");
    deps.log.debug("Leaving OAuth2MonitorAdmin.constructor().");
  }

  private code(value: Json) {
    const { log, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.code().");
    log.debug("Leaving OAuth2MonitorAdmin.code().");
    return value ? '<code>' + esc(value) + '</code>'
                 : '<span class="sub">—</span>';
  }

  private hidden(name: Json, value: Json) {
    const { log, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.hidden().");
    log.debug("Leaving OAuth2MonitorAdmin.hidden().");
    return '<input type="hidden" name="' + esc(name) + '" value="' +
           esc(value) + '">';
  }

  // The notice or error a redirect brought back. `admin.js` has one of these
  // and does not export it; this is the same two lines, escaped the same way.
  private messagesOf(req: Req) {
    const { log, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.messagesOf().");
    const notice = String(req.query.notice || '').slice(0, 500);
    const error = String(req.query.error || '').slice(0, 500);
    log.debug("Leaving OAuth2MonitorAdmin.messagesOf().");
    return (notice ? '<div class="ok">' + esc(notice) + '</div>' : '') +
           (error ? '<div class="err">' + esc(error) + '</div>' : '');
  }

  // The list view as the reader left it, from a query the page is looking at.
  private listViewOf(query: Json) {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.listViewOf().");
    const out = {};
    BACK_PARAMS.forEach(function (key) {
      const raw = (query || {})[key];
      const value = Array.isArray(raw) ? raw[0] : raw;
      if (value !== undefined && value !== null && String(value) !== '') {
        out[key] = String(value).slice(0, 256);
      }
    });
    log.debug("Leaving OAuth2MonitorAdmin.listViewOf().");
    return out;
  }

  // The same, out of a form's `back` field.
  private listViewFromBack(raw: Json) {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorAdmin.listViewFromBack().");
    let params = null;
    try {
      params = new URLSearchParams(String(raw || '').replace(/^\?/, ''));
    } catch (e) {
      // Unparseable: the bare page is the right answer, and is what a form
      // carrying no `back` at all gets anyway.
      log.debug("Caught in OAuth2MonitorAdmin.listViewFromBack(): " +
                ((e && e.message) || e));
      log.debug("Leaving OAuth2MonitorAdmin.listViewFromBack(). Unparseable.");
      return {};
    }
    const query = {};
    params.forEach(function (value, key) {
      if (!Object.prototype.hasOwnProperty.call(query, key)) {
        query[key] = value;
      }
    });
    log.debug("Leaving OAuth2MonitorAdmin.listViewFromBack().");
    return self.listViewOf(query);
  }

  private queryRefused(req: Req, res: Res) {
    const { log, errorCodes, consoleModel } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.queryRefused().");
    const query = consoleModel.checkQuery(req);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-ADMIN-0700');
      res.status(400)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(query.detail);
      log.debug("Leaving OAuth2MonitorAdmin.queryRefused(). Refused.");
      return true;
    }
    log.debug("Leaving OAuth2MonitorAdmin.queryRefused().");
    return false;
  }

  // A request_uri is 34 characters of namespace and 43 of reference, which does
  // not fit a table cell beside eleven others. The cell shows the start of the
  // reference and opens to the whole value — in the markup, so it can be
  // selected and copied with no script.
  private requestUriCell(uri: Json) {
    const { log, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.requestUriCell().");
    const value = String(uri || '');
    const reference = value.slice(value.lastIndexOf(':') + 1);
    log.debug("Leaving OAuth2MonitorAdmin.requestUriCell().");
    return '<details><summary><code title="' + esc(value) + '">…:' +
           esc(reference.slice(0, 10)) + '…</code></summary><code>' +
           esc(value) + '</code></details>';
  }

  // ---------------------------------------------------------------------------
  // THE PARTS OF THE RFC 9126 SECTION.
  // ---------------------------------------------------------------------------
  private tilesHtml(section: Json) {
    const { log, admin } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.tilesHtml().");
    const t = section.totals;
    const held = section.pushedRequests;
    log.debug("Leaving OAuth2MonitorAdmin.tilesHtml().");
    return '<div class="tiles">' +
      admin.tile(t.pushed || 0, 'pushed') +
      admin.tile(t.pushRefused || 0, 'pushes refused') +
      admin.tile(t.resolved || 0, 'request_uris read') +
      admin.tile(t.spent || 0, 'spent') +
      admin.tile(t.expired || 0, 'expired unspent') +
      admin.tile(t.resolveRefused || 0, 'refused at /authorize') +
      admin.tile(t.deleted || 0, 'withdrawn') +
      admin.tile(held.filter.state === 'all' && !held.filter.client_id
                   ? held.total : '—', 'held now') +
      '</div>';
  }

  private countersHtml(section: Json) {
    const { log, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.countersHtml().");
    log.debug("Leaving OAuth2MonitorAdmin.countersHtml().");
    return '<table id="counters-' + esc(section.id) + '"><thead><tr><th>What ' +
      'was counted</th><th>Counter</th><th>Total</th></tr></thead><tbody>' +
      section.events.map(function (one) {
        return '<tr><td>' + esc(one.label) + '</td><td><code>' +
               esc(one.event) + '</code></td><td class="num">' + one.count +
               '</td></tr>';
      }).join('') + '</tbody></table>';
  }

  private errorsHtml(rows: Json) {
    const { log, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.errorsHtml().");
    log.debug("Leaving OAuth2MonitorAdmin.errorsHtml().");
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
  private clientsHtml(req: Req, section: Json, emptyText: Json) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.clientsHtml().");
    const nav = admin.pageNavPair(PAGE, req.query,
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
    log.debug("Leaving OAuth2MonitorAdmin.clientsHtml().");
    return nav.head + '<table><thead><tr><th>Client</th>' + heads +
      '<th>Errors returned</th><th>Last activity</th></tr></thead><tbody>' +
      rows + '</tbody></table>' + nav.foot;
  }

  private filterHtml(held: Json) {
    const { log, consoleModel, esc } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.filterHtml().");
    const options = consoleModel.STATES.map(function (state) {
      return '<option value="' + esc(state) + '"' +
             (held.filter.state === state ? ' selected' : '') + '>' +
             esc(state) + '</option>';
    }).join('');
    log.debug("Leaving OAuth2MonitorAdmin.filterHtml().");
    return '<form method="get" action="' + esc(PAGE) + '#held" ' +
      'class="inline"><label>State <select name="state">' + options +
      '</select></label> <label>client_id <input name="client_id" size="24" ' +
      'value="' + esc(held.filter.client_id) + '"></label> <label>Rows ' +
      '<input name="per" size="4" value="' + esc(String(held.limit)) +
      '"></label> <button type="submit" class="secondary">Show</button>' +
      '</form>';
  }

  private pushedRow(one: Json, back: Json) {
    const { log, esc } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorAdmin.pushedRow().");
    const source = one.source === 'request'
      ? 'request object<div class="sub">' + esc(one.request_object_alg || '?') +
        (one.request_object_encrypted ? ', encrypted ' +
         esc(one.request_object_encrypted) : '') + '</div>'
      : 'form';
    const redirect = self.code(one.redirect_uri) +
      (one.redirect_uri_unregistered
      ? '<div class="state-invalid">unregistered — accepted under RFC 9126 ' +
        'section 2.4 for an authenticated client</div>' : '');
    log.debug("Leaving OAuth2MonitorAdmin.pushedRow().");
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

  private pushedRequestsHtml(req: Req, section: Json) {
    const { log, admin, consoleModel } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorAdmin.pushedRequestsHtml().");
    const held = section.pushedRequests;
    const back = consoleModel.queryWith(self.listViewOf(req.query), {});
    const nav = admin.pageNavPair(PAGE, req.query,
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
    log.debug("Leaving OAuth2MonitorAdmin.pushedRequestsHtml().");
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

  private parSectionHtml(req: Req, section: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorAdmin.parSectionHtml().");
    log.debug("Leaving OAuth2MonitorAdmin.parSectionHtml().");
    return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
      '</h2>' +
      admin.note('A client pushes the parameters of an authorization request ' +
        'to /oauth2/par over the back channel and is answered a request_uri; ' +
        'the browser then carries only that reference to /oauth2/authorize. ' +
        'The request is read there at least twice in one browser flow and is ' +
        'spent when an authorization response is issued on it.') +
      self.tilesHtml(section) +
      '<h3>Every counter</h3>' + self.countersHtml(section) +
      '<h3>By client</h3>' +
      self.clientsHtml(req, section, 'No client has pushed an authorization ' +
                                'request in this realm since the process ' +
                                'started.') +
      '<h3>Errors returned, all clients</h3>' +
      self.errorsHtml(section.errors) +
      '<h3 id="held">Pushed requests still held</h3>' +
      self.pushedRequestsHtml(req, section);
  }

  // ---------------------------------------------------------------------------
  // THE RFC 9470 SECTION (2026-09-13). Counts, and the one requirement that is
  // not written on an application's page: what this service's own resource
  // server demands. No list and no control — a requirement is a property of a
  // request that has already been answered, so there is nothing held to show.
  // ---------------------------------------------------------------------------
  private stepUpTilesHtml(section: Json) {
    const { log, admin } = this.deps;
    log.debug("Entering OAuth2MonitorAdmin.stepUpTilesHtml().");
    const t = section.totals;
    log.debug("Leaving OAuth2MonitorAdmin.stepUpTilesHtml().");
    return '<div class="tiles">' +
      admin.tile(t.stepUpMetBySession || 0, 'met by the session') +
      admin.tile((t.stepUpReauthMaxAge || 0) + (t.stepUpReauthAcr || 0),
                 'sent to sign in again') +
      admin.tile(t.stepUpMetAfterSignIn || 0, 'met after signing in') +
      admin.tile(t.stepUpUnmet || 0, 'unmet_authentication_requirements') +
      admin.tile(t.stepUpLoginRequired || 0, 'login_required') +
      admin.tile(t.stepUpChallenged || 0, 'resource challenges') +
      '</div>';
  }

  private stepUpSectionHtml(req: Req, section: Json) {
    const { log, admin, esc } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorAdmin.stepUpSectionHtml().");
    const own = section.ownResourceRequirement || {};
    const ownText = (own.acr_values || own.max_age !== null)
      ? (own.acr_values ? 'acr_values <code>' + esc(own.acr_values) +
                          '</code>' : '') +
        (own.acr_values && own.max_age !== null ? ' and ' : '') +
        (own.max_age !== null ? 'max_age <code>' + esc(String(own.max_age)) +
                                '</code> seconds' : '')
      : 'nothing';
    log.debug("Leaving OAuth2MonitorAdmin.stepUpSectionHtml().");
    return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
      '</h2>' +
      admin.note('A resource server that finds the authentication behind a ' +
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
      self.clientsHtml(req, section, 'No authorization request in this realm ' +
                                'has carried acr_values or max_age, and no ' +
                                'resource server here has challenged a ' +
                                'token, ' +
                                'since the process started.') +
      '<h3>Errors returned, all clients</h3>' + self.errorsHtml(section.errors);
  }

  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, parseBody, errorCodes, admin, esc,
            consoleModel } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorAdmin.registerRoutes().");
    // -------------------------------------------------------------------------
    // GET /admin/oauth2/monitor
    // -------------------------------------------------------------------------
    app.get('/admin/oauth2/monitor', function (req, res) {
      log.debug("Entering the admin OAuth 2.0 monitor page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin OAuth 2.0 monitor page. Bad query.");
        return;
      }
      const json = consoleModel.monitorView(req);
      const sections = json.sections.map(function (section) {
        if (section.id === 'par') {
          return self.parSectionHtml(req, section);
        }
        return section.id === 'stepup' ?
          self.stepUpSectionHtml(req, section) : '';
      }).join('');
      const inner = self.messagesOf(req) +
        admin.note('<strong>What the authorization server has done</strong> ' +
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
        admin.note('There is no reset: a console that could zero its own ' +
                   'monitoring would make every number on it one somebody ' +
                   'might have zeroed. The durable record of each withdrawal ' +
                   'is the ' +
                   '<a href="/admin/audit">Audit log</a>.') +
        '<p class="links"><a href="' + esc(PAGE) + '?format=json">JSON</a> · ' +
        '<code>GET /admin-api/oauth2/monitor</code> · <a ' +
        'href="/admin/oauth2">OAuth 2.0 / OIDC settings</a> · <a ' +
        'href="/admin/error-codes">Error ' +
        'codes</a></p>';
      admin.respond(req, res, json, 'OAuth 2.0 / OIDC activity', PAGE, inner);
      log.debug("Leaving the admin OAuth 2.0 monitor page.");
    });

    // -------------------------------------------------------------------------
    // POST /admin/oauth2/monitor — Withdraw. The gate has already checked CSRF
    // and Admin Write; the action decides and writes the audit row.
    // -------------------------------------------------------------------------
    app.post('/admin/oauth2/monitor', function (req, res) {
      log.debug("Entering the admin OAuth 2.0 monitor action.");
      const body = parseBody(req);
      const target = PAGE +
                     consoleModel.queryWith(self.listViewFromBack(body.back),
                                            {}) +
                     '#held';
      let result = null;
      try {
        result = consoleModel.monitorAction(body, {
          via: 'console', actor: consoleModel.consoleActorOf(req) });
      } catch (e) {
        log.error(errorCodes.tag('STS-ADMIN-0705') + 'oauth2 monitor console ' +
                  'action threw: ' + ((e && e.stack) || e));
        result = errorCodes.mark({ ok: false,
                                   errors: ['The action could not be ' +
                                            'completed.'] },
                                 'STS-ADMIN-0705');
      }
      admin.respondToAction(req, res, target, result);
      log.debug("Leaving the admin OAuth 2.0 monitor action. ok=" + result.ok);
    });

    log.debug("Leaving OAuth2MonitorAdmin.registerRoutes().");
  }
}

// THE TRANSITIONAL CODE — see the header above. One instance, built from the
// real modules, and its routes registered at load, where they always were.
const monitorAdmin = new OAuth2MonitorAdmin({
  log: helpers.log,
  parseBody: helpers.parseBody,
  errorCodes: errorCodes,
  admin: admin,
  esc: admin.esc,
  consoleModel: consoleModel
});
monitorAdmin.registerRoutes(app);

export = { OAuth2MonitorAdmin: OAuth2MonitorAdmin };
