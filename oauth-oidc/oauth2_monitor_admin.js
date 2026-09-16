// @ts-check
'use strict';
//
// File: oauth2_monitor_admin.js
//
// ---------------------------------------------------------------------------
// MONITORING -> OAUTH 2.0 / OIDC ACTIVITY, `/admin/oauth2/monitor`
// (2026-09-13).
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `acme/acme_admin.js` draws `/admin/acme/monitor`. Every fact on the page
// comes out of ONE call to `oauth2_monitor_console.js`, which is the same call
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
// close a cycle — and `oauth2_monitor_console.js`, which requires
// `oauth-oidc/par.js`, `oauth-oidc/oauth2_monitor.js`, `oauth-oidc/step_up.js`
// and `admin-core/admin_views.js`, libraries already loaded by that line.
// `oauth2.js` at 9 cannot require it: that would drag the whole console in
// front of the authorization server.
//
// No script, like every page of this console but one: paging and the filter
// are GET links and a GET form, and Withdraw is a POST form the console gate
// checks CSRF and Admin Write on before this handler runs.
// ---------------------------------------------------------------------------

const app = require('../common/app');
const { log, parseBody } = require('../common/helpers');
const errorCodes = require('../common/error_codes');
const admin = require('../admin-ui/admin');
const consoleModel = require('./oauth2_monitor_console');

const esc = admin.esc;
const PAGE = consoleModel.PAGE_PATH;

// The list parameters a Withdraw carries back so the 303 lands on the page and
// filter the reader was on. Rebuilt from these names and never echoed, for
// `listViewFromBack()`'s reason in admin.js: a redirect target taken out of a
// body is an open redirect, and one carrying a newline a header injection.
const BACK_PARAMS = ['state', 'client_id', 'per', 'page', 'clientsPage',
                     'stepUpClientsPage'];

function code(value) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return value ? '<code>' + esc(value) + '</code>'
               : '<span class="sub">—</span>';
}

function hidden(name, value) {
  log.debug("Entering hidden().");
  log.debug("Leaving hidden().");
  return '<input type="hidden" name="' + esc(name) + '" value="' +
         esc(value) + '">';
}

// The notice or error a redirect brought back. `admin.js` has one of these
// and does not export it; this is the same two lines, escaped the same way.
function messagesOf(req) {
  log.debug("Entering messagesOf().");
  const notice = String(req.query.notice || '').slice(0, 500);
  const error = String(req.query.error || '').slice(0, 500);
  log.debug("Leaving messagesOf().");
  return (notice ? '<div class="ok">' + esc(notice) + '</div>' : '') +
         (error ? '<div class="err">' + esc(error) + '</div>' : '');
}

// The list view as the reader left it, from a query the page is looking at.
function listViewOf(query) {
  log.debug("Entering listViewOf().");
  const out = {};
  BACK_PARAMS.forEach(function (key) {
    const raw = (query || {})[key];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value !== undefined && value !== null && String(value) !== '') {
      out[key] = String(value).slice(0, 256);
    }
  });
  log.debug("Leaving listViewOf().");
  return out;
}

// The same, out of a form's `back` field.
function listViewFromBack(raw) {
  log.debug("Entering listViewFromBack().");
  let params = null;
  try {
    params = new URLSearchParams(String(raw || '').replace(/^\?/, ''));
  } catch (e) {
    // Unparseable: the bare page is the right answer, and is what a form
    // carrying no `back` at all gets anyway.
    log.debug("Caught in listViewFromBack(): " + ((e && e.message) || e));
    log.debug("Leaving listViewFromBack(). Unparseable.");
    return {};
  }
  const query = {};
  params.forEach(function (value, key) {
    if (!Object.prototype.hasOwnProperty.call(query, key)) {
      query[key] = value;
    }
  });
  log.debug("Leaving listViewFromBack().");
  return listViewOf(query);
}

function queryRefused(req, res) {
  log.debug("Entering queryRefused().");
  const query = consoleModel.checkQuery(req);
  if (!query.ok) {
    errorCodes.mark(res, 'STS-ADMIN-0700');
    res.status(400)
       .type('text/plain')
       .set('Cache-Control', 'no-store')
       .send(query.detail);
    log.debug("Leaving queryRefused(). Refused.");
    return true;
  }
  log.debug("Leaving queryRefused().");
  return false;
}

// A request_uri is 34 characters of namespace and 43 of reference, which does
// not fit a table cell beside eleven others. The cell shows the start of the
// reference and opens to the whole value — in the markup, so it can be
// selected and copied with no script.
function requestUriCell(uri) {
  log.debug("Entering requestUriCell().");
  const value = String(uri || '');
  const reference = value.slice(value.lastIndexOf(':') + 1);
  log.debug("Leaving requestUriCell().");
  return '<details><summary><code title="' + esc(value) + '">…:' +
         esc(reference.slice(0, 10)) + '…</code></summary><code>' +
         esc(value) + '</code></details>';
}

// ---------------------------------------------------------------------------
// THE PARTS OF THE RFC 9126 SECTION.
// ---------------------------------------------------------------------------
function tilesHtml(section) {
  log.debug("Entering tilesHtml().");
  const t = section.totals;
  const held = section.pushedRequests;
  log.debug("Leaving tilesHtml().");
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

function countersHtml(section) {
  log.debug("Entering countersHtml().");
  log.debug("Leaving countersHtml().");
  return '<table id="counters-' + esc(section.id) + '"><thead><tr><th>What ' +
    'was counted</th><th>Counter</th><th>Total</th></tr></thead><tbody>' +
    section.events.map(function (one) {
      return '<tr><td>' + esc(one.label) + '</td><td><code>' +
             esc(one.event) + '</code></td><td class="num">' + one.count +
             '</td></tr>';
    }).join('') + '</tbody></table>';
}

function errorsHtml(rows) {
  log.debug("Entering errorsHtml().");
  log.debug("Leaving errorsHtml().");
  return '<table><thead><tr><th>OAuth error returned</th><th>Count</th></tr>' +
    '</thead><tbody>' + (rows.length ? rows.map(function (r) {
      return '<tr><td><code>' + esc(r.name) + '</code></td><td class="num">' +
             r.count + '</td></tr>';
    }).join('') : '<tr><td colspan="2" class="sub">none</td></tr>') +
    '</tbody></table>';
}

// Every section's per-client table. `emptyText` is the section's own, because
// "nobody has done this" is a sentence about what THIS section counts; the
// page parameter is carried on the section's paging (`pagingOf()` decides it).
function clientsHtml(req, section, emptyText) {
  log.debug("Entering clientsHtml().");
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
  log.debug("Leaving clientsHtml().");
  return nav.head + '<table><thead><tr><th>Client</th>' + heads +
    '<th>Errors returned</th><th>Last activity</th></tr></thead><tbody>' +
    rows + '</tbody></table>' + nav.foot;
}

function filterHtml(held) {
  log.debug("Entering filterHtml().");
  const options = consoleModel.STATES.map(function (state) {
    return '<option value="' + esc(state) + '"' +
           (held.filter.state === state ? ' selected' : '') + '>' +
           esc(state) + '</option>';
  }).join('');
  log.debug("Leaving filterHtml().");
  return '<form method="get" action="' + esc(PAGE) + '#held" ' +
    'class="inline"><label>State <select name="state">' + options +
    '</select></label> <label>client_id <input name="client_id" size="24" ' +
    'value="' + esc(held.filter.client_id) + '"></label> <label>Rows ' +
    '<input name="per" size="4" value="' + esc(String(held.limit)) +
    '"></label> <button type="submit" class="secondary">Show</button>' +
    '</form>';
}

function pushedRow(one, back) {
  log.debug("Entering pushedRow().");
  const source = one.source === 'request'
    ? 'request object<div class="sub">' + esc(one.request_object_alg || '?') +
      (one.request_object_encrypted ? ', encrypted ' +
       esc(one.request_object_encrypted) : '') + '</div>'
    : 'form';
  const redirect = code(one.redirect_uri) + (one.redirect_uri_unregistered
    ? '<div class="state-invalid">unregistered — accepted under RFC 9126 ' +
      'section 2.4 for an authenticated client</div>' : '');
  log.debug("Leaving pushedRow().");
  return '<tr><td>' + requestUriCell(one.request_uri) + '</td><td>' +
    code(one.client_id) + '</td><td>' + code(one.authorization_server) +
    '</td><td>' + esc(one.state) + (one.spent_at ? '<div class="sub">' +
    esc(one.spent_at) + '</div>' : '') + '</td><td>' + esc(one.created_at) +
    '</td><td>' + esc(one.expires_at) + '<div class="sub">in ' +
    one.expires_in + 's</div></td><td class="num">' + one.reads +
    '</td><td>' + (one.client_authenticated ? 'yes' : '<strong>no</strong>') +
    '<div class="sub">' + esc(one.authentication_method || 'none') +
    '</div></td><td>' + source + '</td><td>' + redirect +
    '<div class="sub">' + esc(one.response_type) +
    (one.scope ? ' · ' + esc(one.scope) : '') + '</div></td><td>' +
    code(one.dpop_jkt) + '</td><td><form method="post" action="' +
    esc(PAGE) + '">' + hidden('action', 'delete-pushed-request') +
    hidden('request_uri', one.request_uri) + hidden('back', back) +
    '<button type="submit" class="danger" title="Withdraw this request_uri: ' +
    'the authorization endpoint refuses it from now on">Withdraw</button>' +
    '</form></td></tr>';
}

function pushedRequestsHtml(req, section) {
  log.debug("Entering pushedRequestsHtml().");
  const held = section.pushedRequests;
  const back = consoleModel.queryWith(listViewOf(req.query), {});
  const nav = admin.pageNavPair(PAGE, req.query,
                                Object.assign({ param: 'page',
                                                noun: 'pushed requests' },
                                              held.paging));
  const rows = held.items.length ? held.items.map(function (one) {
    return pushedRow(one, back);
  }).join('') : '<tr><td colspan="12" class="sub">No pushed authorization ' +
                'request ' + (held.filter.state === 'all' &&
                              !held.filter.client_id
                  ? 'is held in this realm.' : 'matches this filter.') +
                '</td></tr>';
  log.debug("Leaving pushedRequestsHtml().");
  return filterHtml(held) + nav.head + '<table id="pushed-requests"><thead>' +
    '<tr><th>request_uri</th><th>Client</th><th>Authorization server</th>' +
    '<th>State</th><th>Created</th><th>Expires</th><th>Reads</th><th>Client ' +
    'authenticated</th><th>Source</th><th>redirect_uri</th><th>DPoP jkt</th>' +
    '<th></th></tr></thead><tbody>' + rows + '</tbody></table>' + nav.foot +
    '<p class="sub">Held: ' + held.total + ' matching, at most ' +
    held.capacity + ' live per realm (oauth2.parMaxRequests), each for ' +
    held.lifetime_s + ' seconds (oauth2.parRequestUriLifetimeS). A spent ' +
    'request_uri is kept until it would have expired, so a replay is refused ' +
    'as already used rather than as unknown. Withdrawing needs Admin Write.' +
    '</p>';
}

function parSectionHtml(req, section) {
  log.debug("Entering parSectionHtml().");
  log.debug("Leaving parSectionHtml().");
  return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
    '</h2>' +
    admin.note('A client pushes the parameters of an authorization request ' +
      'to /oauth2/par over the back channel and is answered a request_uri; ' +
      'the browser then carries only that reference to /oauth2/authorize. ' +
      'The request is read there at least twice in one browser flow and is ' +
      'spent when an authorization response is issued on it.') +
    tilesHtml(section) +
    '<h3>Every counter</h3>' + countersHtml(section) +
    '<h3>By client</h3>' +
    clientsHtml(req, section, 'No client has pushed an authorization ' +
                              'request in this realm since the process ' +
                              'started.') +
    '<h3>Errors returned, all clients</h3>' + errorsHtml(section.errors) +
    '<h3 id="held">Pushed requests still held</h3>' +
    pushedRequestsHtml(req, section);
}

// ---------------------------------------------------------------------------
// THE RFC 9470 SECTION (2026-09-13). Counts, and the one requirement that is
// not written on an application's page: what this service's own resource
// server demands. No list and no control — a requirement is a property of a
// request that has already been answered, so there is nothing held to show.
// ---------------------------------------------------------------------------
function stepUpTilesHtml(section) {
  log.debug("Entering stepUpTilesHtml().");
  const t = section.totals;
  log.debug("Leaving stepUpTilesHtml().");
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

function stepUpSectionHtml(req, section) {
  log.debug("Entering stepUpSectionHtml().");
  const own = section.ownResourceRequirement || {};
  const ownText = (own.acr_values || own.max_age !== null)
    ? (own.acr_values ? 'acr_values <code>' + esc(own.acr_values) +
                        '</code>' : '') +
      (own.acr_values && own.max_age !== null ? ' and ' : '') +
      (own.max_age !== null ? 'max_age <code>' + esc(String(own.max_age)) +
                              '</code> seconds' : '')
    : 'nothing';
  log.debug("Leaving stepUpSectionHtml().");
  return '<h2 id="section-' + esc(section.id) + '">' + esc(section.title) +
    '</h2>' +
    admin.note('A resource server that finds the authentication behind a ' +
      'token too weak or too old answers 401 ' +
      '<code>insufficient_user_authentication</code> with the ' +
      '<code>acr_values</code> and <code>max_age</code> it needs, and the ' +
      'client repeats them in an authorization request. The authorization ' +
      'endpoint answers from the session when the session meets them, sends ' +
      'the person to sign in again once when it does not, and refuses ' +
      '<code>unmet_authentication_requirements</code> when that sign-in did ' +
      'not meet them either. Each authorization-endpoint count is one pass, ' +
      'so a step-up that succeeds counts once as sent to sign in again and ' +
      'once as met after signing in. The context classes this service ' +
      'produces are ' + section.acrValuesSupported.map(function (one) {
        return '<code>' + esc(one) + '</code>';
      }).join(' &lt; ') + '.') +
    stepUpTilesHtml(section) +
    '<p>This service\'s own resource server (UserInfo, the OpenID4VCI ' +
    'endpoints, SCIM, Shared Signals) requires ' + ownText + ' — ' +
    '<a href="/admin/oauth2">oauth2.stepUpAcrValues and ' +
    'oauth2.stepUpMaxAgeS</a>. A registered API\'s requirement is on its ' +
    'application entry (<code>oauthStepUpAcrValues</code>, ' +
    '<code>oauthStepUpMaxAge</code>), enforced by ' +
    '<code>/oauth2/step-up/resource/{application}</code>.</p>' +
    '<h3>Every counter</h3>' + countersHtml(section) +
    '<h3>By client</h3>' +
    clientsHtml(req, section, 'No authorization request in this realm has ' +
                              'carried acr_values or max_age, and no ' +
                              'resource server here has challenged a token, ' +
                              'since the process started.') +
    '<h3>Errors returned, all clients</h3>' + errorsHtml(section.errors);
}

// ---------------------------------------------------------------------------
// GET /admin/oauth2/monitor
// ---------------------------------------------------------------------------
app.get('/admin/oauth2/monitor', function (req, res) {
  log.debug("Entering the admin OAuth 2.0 monitor page.");
  if (queryRefused(req, res)) {
    log.debug("Leaving the admin OAuth 2.0 monitor page. Bad query.");
    return;
  }
  const json = consoleModel.monitorView(req);
  const sections = json.sections.map(function (section) {
    if (section.id === 'par') {
      return parSectionHtml(req, section);
    }
    return section.id === 'stepup' ? stepUpSectionHtml(req, section) : '';
  }).join('');
  const inner = messagesOf(req) +
    admin.note('<strong>What the authorization server has done</strong> in ' +
               'this realm since ' + esc(json.since) + ', one section per ' +
               'mechanism. The counters are merged across every process ' +
               'answering this realm.') +
    '<p class="links">' + json.sections.map(function (section) {
      return '<a href="#section-' + esc(section.id) + '">' +
             esc(section.title) + '</a>';
    }).join(' · ') + '</p>' +
    sections +
    admin.note('There is no reset: a console that could zero its own ' +
               'monitoring would make every number on it one somebody might ' +
               'have zeroed. The durable record of each withdrawal is the ' +
               '<a href="/admin/audit">Audit log</a>.') +
    '<p class="links"><a href="' + esc(PAGE) + '?format=json">JSON</a> · ' +
    '<code>GET /admin-api/oauth2/monitor</code> · <a href="/admin/oauth2">' +
    'OAuth 2.0 / OIDC settings</a> · <a href="/admin/error-codes">Error ' +
    'codes</a></p>';
  admin.respond(req, res, json, 'OAuth 2.0 / OIDC activity', PAGE, inner);
  log.debug("Leaving the admin OAuth 2.0 monitor page.");
});

// ---------------------------------------------------------------------------
// POST /admin/oauth2/monitor — Withdraw. The gate has already checked CSRF and
// Admin Write; the action decides and writes the audit row.
// ---------------------------------------------------------------------------
app.post('/admin/oauth2/monitor', function (req, res) {
  log.debug("Entering the admin OAuth 2.0 monitor action.");
  const body = parseBody(req);
  const target = PAGE +
                 consoleModel.queryWith(listViewFromBack(body.back), {}) +
                 '#held';
  let result = null;
  try {
    result = consoleModel.monitorAction(body, {
      via: 'console', actor: consoleModel.consoleActorOf(req) });
  } catch (e) {
    log.error(errorCodes.tag('STS-ADMIN-0705') + 'oauth2 monitor console ' +
              'action threw: ' + ((e && e.stack) || e));
    result = errorCodes.mark({ ok: false, errors: ['The action could not be ' +
                                                   'completed.'] },
                             'STS-ADMIN-0705');
  }
  admin.respondToAction(req, res, target, result);
  log.debug("Leaving the admin OAuth 2.0 monitor action. ok=" + result.ok);
});

module.exports = {};
