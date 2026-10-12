// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oidfed_admin.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS -> OPENID FEDERATION (#132, #133, 2026-09-23): the console page.
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `scep/scep_admin.ts` draws SCEP's. Every fact on the page comes out of ONE
// call to `oidfed.view()`, which is the same call `GET /admin-api/oidfed`
// answers with, and every control is one of `oidfed.act()`'s actions, which
// `POST /admin-api/oidfed/:action` takes too (rule 7).
//
// No script, like every page of this console but one: every control is a
// form, and the JSON fields (a JWK Set, a metadata policy) are textareas.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import oidfed = require('./oidfed');

type Json = any;

const esc = admin.esc;

interface OidfedAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  oidfed: typeof oidfed;
  // The console's gate state, for who acted (`admin-core/admin_views`),
  // lazily: it requires route modules.
  adminViews: () => Json;
}

/**
 * Protocols → OpenID Federation, `/admin/oidfed`: every fact from one
 * `oidfed.view()` call and every control one of `oidfed.act()`'s actions, the
 * same two `/admin-api/oidfed` answers with (rule 7).
 */
class OidfedAdmin {
  /**
   * Builds an instance over what it depends on.
   *
   * @param deps - the logger, the body parser, the error-code table, the
   * console, the federation entity and the lazily loaded gate state
   */
  constructor(private readonly deps: OidfedAdminDeps) {
    deps.log.debug("Entering OidfedAdmin.constructor().");
    deps.log.debug("Leaving OidfedAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): OidfedAdminDeps {
    helpers.log.debug("Entering OidfedAdmin.defaultDeps().");
    helpers.log.debug("Leaving OidfedAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody, errorCodes: errorCodes,
      admin: admin, oidfed: oidfed,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  // Who is acting, for the audit row: the console's signed-in operator.
  /**
   * Answers who is acting, for the audit row: the console's signed-in operator.
   *
   * @param req - the request
   * @returns the operator's name, or ''
   */
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering OidfedAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in OidfedAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving OidfedAdmin.actorOf().");
    return (state && state.username) || '';
  }

  /**
   * Draws the whole page in the console's shell, or its JSON.
   *
   * @param req - the request
   * @param res - the response
   * @param extraTop - markup to draw above the sections, such as an action's
   * result
   * @param resolution - a resolution to show, if any
   */
  // THE VIEW THE PAGE AND `GET /admin-api/oidfed` BOTH ANSWER (#446): the
  // realm's federation, with the page's settings. One function, so the API
  // answers everything the page is drawn from.
  /**
   * Returns the view the page is drawn from and the API operation answers.
   *
   * @param req - the request, which the federation view reads
   * @returns the view
   */
  async oidfedView(req: Json): Promise<Json> {
    const { log, admin, oidfed, adminViews } = this.deps;
    log.debug("Entering OidfedAdmin.oidfedView().");
    const view = await oidfed.view(req);
    view.settings = admin.configSettingsJson('/admin/oidfed');
    this.pageLists(view, (req && req.query) || {}, adminViews());
    log.debug("Leaving OidfedAdmin.oidfedView().");
    return view;
  }

  // ---------------------------------------------------------------------------
  // EVERY LIST ON THE PAGE THAT GROWS IS PAGED (#313's sweep, 2026-10-12).
  //
  // The Federation Entity Keys are kept for good, one row per rotation, the
  // shape `/admin/keys/history` pages for the realm's signing keys; the
  // subordinates and the revoked ones grow with registration and with every
  // realm created; the issued and carried marks with every issuance; the
  // Trust Anchors and the mark policies with what an administrator adds. So
  // each is one page on a parameter named for it — `keysPage`,
  // `subordinatesPage`, `formerPage`, `anchorsPage`, `issuedPage`,
  // `heldPage`, `policiesPage` — with `per` shared, the arrangement every
  // page holding several lists has. `counts` keeps each list's whole length.
  //
  // A SUBORDINATE'S HISTORY IS CUT TO ITS LATEST EVENTS, not paged: it is a
  // fold inside one row, a pager per row would be a page of pagers, and the
  // whole history is published at `/oidfed/subordinate-events` (#137) for
  // anybody who wants it. `eventsTotal` says how many there are.
  //
  // This is the console's view, not `oidfed.view()`, which the module's own
  // callers read whole.
  // ---------------------------------------------------------------------------
  /**
   * Pages the view's growing lists in place and cuts each subordinate's
   * history to its latest events.
   *
   * @param view - `oidfed.view()`'s answer, changed in place
   * @param query - the request's query
   * @param views - `admin-core/admin_views`, for `pagedRows()`
   */
  pageLists(view: Json, query: Json, views: Json): void {
    const { log } = this.deps;
    log.debug("Entering OidfedAdmin.pageLists().");
    const lists: Array<[string, string, string]> = [
      ['keys', 'keys', 'keys'],
      ['subordinates', 'subordinates', 'subordinates'],
      ['formerSubordinates', 'former', 'revoked subordinates'],
      ['trustAnchors', 'anchors', 'Trust Anchors'],
      ['issuedMarks', 'issued', 'Trust Marks'],
      ['heldMarks', 'held', 'Trust Marks'],
      ['markPolicies', 'policies', 'policies']
    ];
    view.counts = {};
    view.paging = {};
    lists.forEach(function (list) {
      const member = list[0];
      const page = views.pagedRows(query, view[member] || [],
        { name: list[1], noun: list[2] });
      view[member] = page.shown;
      view.counts[member] = page.paging.total;
      view.paging[member] = views.pagingJson(page.paging);
    });
    const cut = function (row: Json): void {
      const events: Json[] = Array.isArray(row.events) ? row.events : [];
      row.eventsTotal = events.length;
      row.events = events.slice(-OidfedAdmin.HISTORY_SHOWN);
    };
    view.subordinates.forEach(cut);
    view.formerSubordinates.forEach(cut);
    log.debug("Leaving OidfedAdmin.pageLists().");
  }

  /**
   * How many of a subordinate's latest events its row carries.
   */
  static readonly HISTORY_SHOWN = 25;

  /**
   * Registers `GET` and `POST /admin/oidfed`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: Json): void {
    const { log, parseBody, admin, oidfed, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.registerRoutes().");
    log.debug("Leaving OidfedAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<OidfedAdmin>(
  'oidfed/oidfed_admin',
  () => new OidfedAdmin(OidfedAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Protocols → OpenID Federation, the console page for the realm as a federation
 * entity.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  OidfedAdmin: OidfedAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: OidfedAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  oidfedView: slot.forward('oidfedView')
};
