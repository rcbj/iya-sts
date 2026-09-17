'use strict';
//
// File: oauth2_monitor_console.ts
//
// ---------------------------------------------------------------------------
// WHAT THE OAUTH 2.0 / OIDC MONITORING PAGE AND ITS MANAGEMENT API OPERATIONS
// READ AND DO — ONE MODEL, TWO DOORS (rule 7, 2026-09-13).
//
// `gnap/gnap_console.ts`'s and `acme/acme_console.ts`'s arrangement, for the
// authorization server's own traffic: a VIEW computes the facts once and both
// doors render them, an ACTION changes state once and both doors report it.
// **No route, no `res`, no markup**, and a view reads nothing from the request
// but its query. `oauth2_monitor_admin.ts` draws the markup and
// `oauth2_monitor_api.ts` sends the JSON, both out of the SAME call.
//
//   GET  /admin/oauth2/monitor   monitorView()    Monitoring
//   POST /admin/oauth2/monitor   monitorAction()  delete-pushed-request
//
// **IT IS BESIDE THE PROTOCOL AND NOT IN `admin-core/`**, for
// `gnap_console.js`'s reason: what a pushed request IS lives in `par.ts` and
// what is counted lives in `oauth2_monitor.ts`, and a view in another
// directory reading those stores field by field is a second place for that
// knowledge to go stale.
//
// **THE PAGE IS SECTIONED, AND SO IS THIS MODEL.** `oauth2_monitor.SECTIONS` is
// the list of mechanisms the page draws, and each section here carries its own
// events, totals, per-client rows and errors — so a second mechanism is a
// second entry in that table and a second view beside `parSectionView()`, not
// a second page. RFC 9126 is the first and RFC 9470 (`stepUpSectionView()`,
// 2026-09-13) the second.
//
// **TWO WAYS TO PAGE THE PUSHED REQUESTS, ONE ANSWER.** The console pages with
// `page` and `per`, as every list on it does; `/admin-api` also accepts
// `offset` and `limit`, which is `par.list()`'s own vocabulary and what a
// machine walking a store expects. Where both are sent, `offset`/`limit` win,
// and the reply always carries both spellings of where it is.
//
// **THERE IS NO RESET, AND THERE IS ONE CONTROL.** A console that could zero
// its own monitoring would make every number on it one somebody might have
// zeroed (`acme/acme_admin.ts`). WITHDRAWING a pushed request is a different
// kind of act: it changes what the authorization endpoint will accept rather
// than what the page reports, it is counted (`par.deleted`) rather than
// erasing a count, and it is audited.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `OAuth2MonitorConsole` takes the logger, the error-code table, the
// audit log, the validator, the view layer, the PAR store, the counters and
// the step-up library through its constructor. The module still exports its
// old names, for the page and the management API, which require it by those
// names — the functions, since R2, FACADES over the instance the composition
// root builds and installs; a process without the root builds a default one
// at load.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import audit = require('../common/audit');
import validation = require('../common/validation');
import adminViews = require('../admin-core/admin_views');
import par = require('./par');
import monitor = require('./oauth2_monitor');
import stepUp = require('./step_up');

type Req = any;
type Json = any;

interface OAuth2MonitorConsoleDeps {
  log: typeof helpers.log;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  validation: typeof validation;
  adminViews: typeof adminViews;
  par: typeof par;
  monitor: typeof monitor;
  stepUp: typeof stepUp;
}

const vz = validation.z;
const vt = validation.types;

const PAGE_PATH = '/admin/oauth2/monitor';

const MONITOR_ACTIONS = ['delete-pushed-request'];

// Which pushed requests the table shows. `par.list()` knows these three words
// and nothing else; an `expired` record is swept before it could be listed.
const STATES = ['live', 'spent', 'all'];

// The largest page of pushed requests one reply carries — `par.list()`'s own
// ceiling, repeated as a bound on the query rather than discovered by a silent
// clamp.
const MAX_LIMIT = 500;

const DEFAULT_LIMIT = 50;

// The query both doors accept. `format` is the console's `?format=json`.
const QUERY = vz.looseObject({
  state: vt.opt(vt.oneOf(STATES)),
  client_id: vt.opt(vt.identifier),
  page: vt.opt(vt.integer(1, 1000000)),
  per: vt.opt(vt.integer(1, MAX_LIMIT)),
  clientsPage: vt.opt(vt.integer(1, 1000000)),
  stepUpClientsPage: vt.opt(vt.integer(1, 1000000)),
  offset: vt.opt(vt.integer(0, 100000000)),
  limit: vt.opt(vt.integer(1, MAX_LIMIT)),
  format: vt.opt(vt.oneOf(['json', 'JSON', 'html']))
});

const DELETE_BODY = vz.looseObject({
  request_uri: vz.string().min(1).max(512)
});

class OAuth2MonitorConsole {
  static readonly PAGE_PATH = PAGE_PATH;
  static readonly MONITOR_ACTIONS = MONITOR_ACTIONS;
  static readonly STATES = STATES;
  static readonly MAX_LIMIT = MAX_LIMIT;

  constructor(private readonly deps: OAuth2MonitorConsoleDeps) {
    deps.log.debug("Entering OAuth2MonitorConsole.constructor().");
    deps.log.debug("Leaving OAuth2MonitorConsole.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): OAuth2MonitorConsoleDeps {
    helpers.log.debug("Entering OAuth2MonitorConsole.defaultDeps().");
    helpers.log.debug("Leaving OAuth2MonitorConsole.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      audit: audit,
      validation: validation,
      adminViews: adminViews,
      par: par,
      monitor: monitor,
      stepUp: stepUp
    };
  }

  private refused(code: string, sentence: string): Json {
    const { log, errorCodes } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.refused(). code=" + code);
    log.debug("Leaving OAuth2MonitorConsole.refused().");
    return errorCodes.mark({ ok: false, errors: [sentence] }, code);
  }

  // Whether a query is one both doors accept. Answers the validation result,
  // so the door can refuse with its own code and the detail.
  checkQuery(req: Req): Json {
    const { log, validation } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.checkQuery().");
    const checked = validation.check(req, 'query', QUERY);
    log.debug("Leaving OAuth2MonitorConsole.checkQuery(). ok=" + checked.ok);
    return checked;
  }

  private first(value: unknown): unknown {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.first().");
    log.debug("Leaving OAuth2MonitorConsole.first().");
    return Array.isArray(value) ? value[0] : value;
  }

  private intOf(value: unknown): number | null {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.intOf().");
    const once = this.first(value);
    const n = parseInt(String(once === undefined ? '' : once), 10);
    log.debug("Leaving OAuth2MonitorConsole.intOf().");
    return isFinite(n) ? n : null;
  }

  // The filter the table was asked for, in the one spelling both doors use.
  private filterOf(query: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.filterOf().");
    const state = String(this.first(query.state) || '');
    const out = {
      state: STATES.indexOf(state) >= 0 ? state : 'all',
      client_id: String(this.first(query.client_id) || '')
    };
    log.debug("Leaving OAuth2MonitorConsole.filterOf(). state=" + out.state);
    return out;
  }

  // A count table — `{ word: n }` — as rows, largest first.
  private table(counts: Json): Json[] {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.table().");
    log.debug("Leaving OAuth2MonitorConsole.table().");
    return Object.keys(counts || {}).map(function (name) {
      return { name: name, count: Number(counts[name]) || 0 };
    }).sort(function (a, b) {
      return b.count - a.count || a.name.localeCompare(b.name);
    });
  }

  // -------------------------------------------------------------------------
  // THE PUSHED REQUESTS STILL HELD, one page of them.
  //
  // `par.list()` sweeps before it lists, so an expired unspent request is
  // counted (`par.expired`) by the act of reading this page — which is the
  // counter's own design, and why the snapshot is taken AFTER the list below.
  // -------------------------------------------------------------------------
  private pushedRequestsView(query: Json, filter: Json): Json {
    const { log, par } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorConsole.pushedRequestsView().");
    const askedOffset = self.intOf(query.offset);
    const askedLimit = self.intOf(query.limit);
    const byOffset = askedOffset !== null || askedLimit !== null;
    const per = Math.min(MAX_LIMIT, Math.max(1, self.intOf(query.per) ||
                                                 DEFAULT_LIMIT));
    const limit = byOffset
      ? Math.min(MAX_LIMIT, Math.max(1, askedLimit || DEFAULT_LIMIT)) : per;
    const askedPage = Math.max(1, self.intOf(query.page) || 1);
    let offset = byOffset ? Math.max(0, askedOffset || 0)
                          : (askedPage - 1) * limit;
    const options = { state: filter.state, clientId: filter.client_id };
    let held = par.list(Object.assign({ offset: offset, limit: limit },
                                      options));
    // A PAGE past the end is clamped to the last one, which is what every
    // list on the console does; an OFFSET past the end is answered empty,
    // which is what a machine walking a store expects to be told it has
    // reached.
    if (!byOffset && held.total > 0 && offset >= held.total) {
      offset = (Math.ceil(held.total / limit) - 1) * limit;
      held = par.list(Object.assign({ offset: offset, limit: limit },
                                    options));
    }
    const pages = Math.max(1, Math.ceil(held.total / limit));
    const page = Math.min(pages, Math.floor(offset / limit) + 1);
    const shown = held.items.length;
    log.debug("Leaving OAuth2MonitorConsole.pushedRequestsView(). " + shown +
              " of " + held.total + " row(s).");
    return {
      filter: filter,
      total: held.total,
      offset: offset,
      limit: limit,
      capacity: held.capacity,
      lifetime_s: held.lifetime_s,
      // `pagingJson()`'s members, so a client that has learned to walk the
      // other lists of this API reads this one without being told anything.
      paging: {
        page: page, pages: pages, perPage: limit,
        firstRow: shown ? offset + 1 : 0,
        lastRow: shown ? offset + shown : 0,
        total: held.total
      },
      items: held.items
    };
  }

  // What every section of the page is made of: its events, totals,
  // per-client rows (paged under a parameter of the section's own, so paging
  // one section's clients does not move another's) and errors. `pagingName`
  // is `pagingOf()`'s `name` — the query parameter is that followed by
  // `Page`.
  private countedSectionView(query: Json, snap: Json, id: string,
                             fallbackTitle: string,
                             pagingName: string): Json {
    const { log, adminViews } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorConsole.countedSectionView(). id=" + id);
    const section = snap.sections.filter(function (one) {
      return one.id === id;
    })[0] || { id: id, title: fallbackTitle };
    const events = snap.events.filter(function (one) {
      return one.section === section.id;
    });
    const totals: Json = {};
    events.forEach(function (one) {
      totals[one.counter] = Number(snap.totals[one.counter]) || 0;
    });
    // A client is listed in this section when any of the section's counters
    // moved for it; an id counted only by a later section is not a row here.
    const allClients = Object.keys(snap.rows).filter(function (id) {
      return events.some(function (one) {
        return Number(snap.rows[id][one.counter]) > 0;
      });
    }).map(function (id) {
      const row = snap.rows[id];
      const counters: Json = {};
      events.forEach(function (one) {
        counters[one.counter] = Number(row[one.counter]) || 0;
      });
      return { client_id: id, counters: counters,
               errors: self.table(row.errors),
               lastAt: row.lastAt || null, lastEvent: row.lastEvent || null };
    });
    const clientPaging = adminViews.pagingOf(query, allClients.length,
                                             { name: pagingName,
                                               noun: 'clients' });
    log.debug("Leaving OAuth2MonitorConsole.countedSectionView(). " +
              allClients.length + " client(s).");
    return {
      id: section.id,
      title: section.title,
      events: events.map(function (one) {
        return { event: one.event, counter: one.counter, label: one.label,
                 count: totals[one.counter] };
      }),
      totals: totals,
      lastAt: snap.totals.lastAt || null,
      lastEvent: snap.totals.lastEvent || null,
      errors: self.table(snap.totals.errors),
      clientsPaging: adminViews.pagingJson(clientPaging),
      // The query parameter that pages this section's clients —
      // `pagingJson()` does not carry it, and the page's links must move this
      // section alone.
      clientsParam: clientPaging.param,
      clients: allClients.slice(clientPaging.offset,
                                clientPaging.offset + clientPaging.perPage)
    };
  }

  // RFC 9126's section: the counts, with the pushed requests the store still
  // holds.
  private parSectionView(query: Json, snap: Json, held: Json): Json {
    const { log } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.parSectionView().");
    const view = this.countedSectionView(
      query, snap, 'par', 'Pushed authorization requests (RFC 9126)',
      'clients');
    view.pushedRequests = held;
    log.debug("Leaving OAuth2MonitorConsole.parSectionView().");
    return view;
  }

  // RFC 9470's section (2026-09-13): counts only. It holds no store to list —
  // a requirement is a property of a request, and the request is gone once it
  // has been answered — so what the page can add beside the counts is the two
  // settings this service's own resource server enforces, which is the one
  // requirement here that is not written on an application's page.
  private stepUpSectionView(query: Json, snap: Json): Json {
    const { log, stepUp } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.stepUpSectionView().");
    const view = this.countedSectionView(
      query, snap, 'stepup', 'Step-up authentication (RFC 9470)',
      'stepUpClients');
    const own = stepUp.ownResourceRequirement();
    view.ownResourceRequirement = {
      acr_values: own.acrValues.join(' ') || null,
      max_age: own.maxAge
    };
    view.acrValuesSupported = stepUp.SUPPORTED.slice();
    log.debug("Leaving OAuth2MonitorConsole.stepUpSectionView().");
    return view;
  }

  // -------------------------------------------------------------------------
  // GET /admin/oauth2/monitor and GET /admin-api/oauth2/monitor.
  // -------------------------------------------------------------------------
  monitorView(req: Req): Json {
    const { log, monitor } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorConsole.monitorView().");
    const query = (req && req.query) || {};
    const filter = self.filterOf(query);
    const held = self.pushedRequestsView(query, filter);
    const snap = monitor.snapshot();
    const json = {
      page: PAGE_PATH,
      title: 'OAuth 2.0 / OIDC activity',
      since: snap.startedAt,
      sections: [self.parSectionView(query, snap, held),
                 self.stepUpSectionView(query, snap)],
      actions: MONITOR_ACTIONS.slice()
    };
    log.debug("Leaving OAuth2MonitorConsole.monitorView().");
    return json;
  }

  // -------------------------------------------------------------------------
  // POST /admin/oauth2/monitor and POST /admin-api/oauth2/monitor/{action}.
  //
  // `context.via` is `console` or `api`, and `context.actor` the console
  // session's username where there is one; the audit row names both.
  // -------------------------------------------------------------------------
  monitorAction(body: Json, context?: Json): Json {
    const { log, par, audit } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorConsole.monitorAction(). action=" +
              (body && body.action));
    const ctx = context || {};
    const action = String((body && body.action) || '');
    const actor = String(ctx.actor || (ctx.via === 'api' ? 'admin-api' : ''));
    if (MONITOR_ACTIONS.indexOf(action) < 0) {
      log.debug("Leaving OAuth2MonitorConsole.monitorAction(). Unknown " +
                "action.");
      return self.refused('STS-ADMIN-0701', 'Unknown action "' +
                          action.slice(0, 60) + '". There is one: ' +
                          MONITOR_ACTIONS.join(', ') + '.');
    }
    const parsed = DELETE_BODY.safeParse(body || {});
    if (!parsed.success) {
      log.debug("Leaving OAuth2MonitorConsole.monitorAction(). No usable " +
                "request_uri.");
      return self.refused('STS-ADMIN-0702', 'The delete-pushed-request ' +
                          'action needs `request_uri`: the whole value a ' +
                          'push answered, as listed on ' +
                          '/admin/oauth2/monitor.');
    }
    const uri = parsed.data.request_uri;
    if (!par.isPushedRequestUri(uri)) {
      log.debug("Leaving OAuth2MonitorConsole.monitorAction(). Not in the " +
                "namespace.");
      return self.refused('STS-ADMIN-0703', 'That is not a pushed ' +
                          'request_uri: every one this service issues ' +
                          'begins "' + par.REQUEST_URI_PREFIX +
                          '" (RFC 9126 section 2.2).');
    }
    const before = par.get(uri);
    if (!before || !par.remove(uri)) {
      log.debug("Leaving OAuth2MonitorConsole.monitorAction(). Not held.");
      return self.refused('STS-ADMIN-0704', 'No pushed authorization ' +
                          'request with that request_uri is held in this ' +
                          'realm. It was never pushed here, it expired and ' +
                          'was swept, or it was already withdrawn.');
    }
    audit.audit({
      category: ctx.via === 'api' ? 'api' : 'admin',
      action: 'oauth2.par.withdraw',
      protocol: 'OAuth 2.0 / OIDC', channel: 'http',
      outcome: 'success', actor: actor, target: before.client_id,
      detail: 'withdrew a ' + before.state + ' pushed authorization ' +
              'request for client ' + before.client_id + ' at the "' +
              before.authorization_server + '" authorization server, via ' +
              (ctx.via || 'an unnamed door')
    });
    log.info('oauth2 monitor: ' + (actor || 'an administrator') +
             ' withdrew a ' + before.state + ' pushed authorization ' +
             'request for client "' + before.client_id + '".');
    log.debug("Leaving OAuth2MonitorConsole.monitorAction(). Withdrawn.");
    return {
      ok: true,
      request_uri: uri,
      client_id: before.client_id,
      state: before.state,
      message: 'The pushed authorization request for client ' +
               before.client_id + ' was withdrawn. Its request_uri is ' +
               'refused invalid_request_uri at the authorization endpoint ' +
               'from now on.'
    };
  }

  // The console session's username, for the audit row. Here rather than in
  // `oauth2_monitor_admin.ts` for `acme_console.js`'s reason: the admin view
  // layer may be required by this file and not by that one
  // (tests/admin_actions_layer.js).
  consoleActorOf(req: Req): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering OAuth2MonitorConsole.consoleActorOf().");
    let name = '';
    try {
      name = String(adminViews.gateStateFor(req).username || '');
    } catch (e) {
      // A request with no console session behind it names nobody; the row
      // says `an administrator` rather than failing the withdrawal over a
      // label.
      log.debug("Caught in OAuth2MonitorConsole.consoleActorOf(): " +
                ((e && e.message) || e));
      name = '';
    }
    log.debug("Leaving OAuth2MonitorConsole.consoleActorOf().");
    return name;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<OAuth2MonitorConsole>(
  'oauth-oidc/oauth2_monitor_console',
  () => new OAuth2MonitorConsole(OAuth2MonitorConsole.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  OAuth2MonitorConsole: OAuth2MonitorConsole,
  installInstance: (instance: OAuth2MonitorConsole): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE_PATH: OAuth2MonitorConsole.PAGE_PATH,
  MONITOR_ACTIONS: OAuth2MonitorConsole.MONITOR_ACTIONS,
  STATES: OAuth2MonitorConsole.STATES,
  MAX_LIMIT: OAuth2MonitorConsole.MAX_LIMIT,
  checkQuery: slot.forward('checkQuery'),
  monitorView: slot.forward('monitorView'),
  monitorAction: slot.forward('monitorAction'),
  consoleActorOf: slot.forward('consoleActorOf'),
  // The query-string builder the page's paging and `back` use, handed on from
  // the view layer: `admin.queryWith` is a re-export of a function that moved,
  // and tests/admin_actions_layer.js refuses a call through the console.
  queryWith: adminViews.queryWith
};
