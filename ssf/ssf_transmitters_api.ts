// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_transmitters_api.ts
//
// ===========================================================================
// `/admin-api/ssf/transmitters` (#153, 2026-09-26; read only since #373):
// /admin/ssf/transmitters for a machine (rule 7) — every federation
// relationship whose partner's Shared Signals this realm receives, what
// arrived, and the blocks and locks partners put on people
// (`ssf_transmitters.ts`'s `report()`). The acts are the relationship's,
// `POST /admin-api/federation/signals-*`. Never a secret. Registers no route:
// `mgmt-api/admin_api.ts` spreads ROUTES into its table.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');

type Req = any;
type Res = any;
type Json = any;

interface TransmittersApiDeps {
  log: typeof helpers.log;
  loadTransmitters(): Json;
  loadViews(): Json;
}

const BASE = '/admin-api';

/**
 * The management API's report of the federation partners whose Shared Signals
 * this realm receives, `/admin-api/ssf/transmitters`: the monitoring page's
 * report, for a machine. It registers no route; `mgmt-api/admin_api.ts`
 * spreads `ROUTES` into its table.
 */
class SsfTransmittersApi {
  /**
   * Builds the API from its dependencies.
   *
   * @param deps - the modules it reads, from `SsfTransmittersApi.defaultDeps()`
   * or the composition root
   */
  constructor(private readonly deps: TransmittersApiDeps) {
    deps.log.debug("Entering SsfTransmittersApi.constructor().");
    deps.log.debug("Leaving SsfTransmittersApi.constructor().");
  }

  /**
   * Returns the real modules the API depends on, as the composition root passes
   * them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): TransmittersApiDeps {
    helpers.log.debug("Entering SsfTransmittersApi.defaultDeps().");
    helpers.log.debug("Leaving SsfTransmittersApi.defaultDeps().");
    return {
      log: helpers.log,
      loadTransmitters: function (): Json {
        return require('./ssf_transmitters');
      },
      // The console's paging (`pagedRows()`), reached when a request
      // arrives: admin_views requires most of the service, and this module
      // is built with the other API modules, before it is wanted.
      loadViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  /**
   * Builds the installed instance's route table into the module's `ROUTES`.
   *
   * @param instance - the installed instance
   */
  static wire(instance: SsfTransmittersApi): void {
    helpers.log.debug("Entering SsfTransmittersApi.wire().");
    routes = instance.buildRoutes();
    helpers.log.debug("Leaving SsfTransmittersApi.wire().");
  }

  /**
   * Sends a JSON answer with `Cache-Control: no-store`, without the error code.
   *
   * @param res - the response
   * @param status - the HTTP status
   * @param body - the body
   */
  sendJson(res: Res, status: number, body: Json): void {
    const { log } = this.deps;
    log.debug("Entering SsfTransmittersApi.sendJson(). status=" + status);
    const reply = Object.assign({}, body);
    delete reply.errorCode;
    res.status(status).type('application/json')
       .set('Cache-Control', 'no-store')
       .send(JSON.stringify(reply, null, 2));
    log.debug("Leaving SsfTransmittersApi.sendJson().");
  }

  // -------------------------------------------------------------------------
  // THE THREE LISTS THAT GROW, PAGED (#313's sweep, 2026-10-12).
  //
  // The blocks and the account locks are persisted, one row per (person,
  // relationship), so they grow with the people partners name; what arrived
  // was CUT at 200 rows newest first, so a row past the two hundredth could
  // not be reached at all. Each is now a page of the whole list on a
  // parameter of its own — `blocksPage`, `locksPage`, `receivedPage`, `per`
  // shared — and `relationship` narrows what arrived BEFORE it is paged.
  // The relationship cards are not paged: there is one per federation
  // relationship whose signals are on, and `federation.max` caps those.
  // `counts` carries each list's whole length, for a reader that wants the
  // number without walking the pages.
  // -------------------------------------------------------------------------
  /**
   * Builds the report the page and the API answer with: the transmitters'
   * report with its three growing lists paged.
   *
   * @param query - the request's query
   * @returns the report
   */
  pagedReport(query: Json): Json {
    const { log, loadTransmitters, loadViews } = this.deps;
    log.debug("Entering SsfTransmittersApi.pagedReport().");
    const q = query || {};
    const relationship = Array.isArray(q.relationship) ? q.relationship[0]
      : q.relationship;
    // Every row that arrived: the inbox is bounded by ssf.foreignInboxMax,
    // and the page is what bounds the answer.
    const report = loadTransmitters().report({
      relationship: relationship, limit: Infinity });
    const views = loadViews();
    const received = views.pagedRows(q, report.received || [],
      { name: 'received', noun: 'signals' });
    const blocks = views.pagedRows(q, report.blocks || [],
      { name: 'blocks', noun: 'blocks' });
    const locks = views.pagedRows(q, report.locks || [],
      { name: 'locks', noun: 'locks' });
    const out = Object.assign({}, report, {
      received: received.shown,
      blocks: blocks.shown,
      locks: locks.shown,
      counts: { received: received.paging.total,
                blocks: blocks.paging.total,
                locks: locks.paging.total },
      paging: { received: views.pagingJson(received.paging),
                blocks: views.pagingJson(blocks.paging),
                locks: views.pagingJson(locks.paging) }
    });
    log.debug("Leaving SsfTransmittersApi.pagedReport(). " +
              out.received.length + " of " + out.counts.received +
              " arrival(s).");
    return out;
  }

  /**
   * Builds the route table: `GET /admin-api/ssf/transmitters`, the
   * monitoring report.
   *
   * @returns the routes
   */
  buildRoutes(): Json[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmittersApi.buildRoutes().");
    const ROUTES = [
      { method: 'GET', path: BASE + '/ssf/transmitters',
        tag: 'Shared Signals', operationId: 'getPartnerSignals',
        summary: 'The federation partners whose Shared Signals this realm ' +
                 'receives',
        description: 'Everything /admin/ssf/transmitters draws: each ' +
          'federation relationship whose signals are on (its kind — ' +
          '`sign-in` or `signals-only` — SSF issuer, discovered ' +
          'configuration, delivery, stream, counts and blocks), every ' +
          'Security Event Token that arrived with whether it verified, the ' +
          'person it named and what it led to, the sign-ins partners have ' +
          'blocked and the account locks a signals-only partner put on ' +
          'people here. Never a secret. `relationship` narrows what ' +
          'arrived. What arrived, the blocks and the locks are each one ' +
          'page, moved by `receivedPage`, `blocksPage` and `locksPage` ' +
          'with `per` shared, and described by `paging`. A partner\'s ' +
          'stream is configured on its relationship and acted on with ' +
          '`POST /admin-api/federation/signals-*`.',
        mirrors: 'GET /admin/ssf/transmitters',
        parameters: [
          { name: 'relationship', in: 'query', required: false,
            schema: { type: 'string' },
            description: 'Only what arrived from this relationship. ' +
                         'Applied before what arrived is paged.' },
          { name: 'receivedPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of what arrived, newest first. ' +
                         'Clamped, like every page parameter here.' },
          { name: 'blocksPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the sign-ins partners blocked.' },
          { name: 'locksPage', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Which page of the account locks partners put ' +
                         'on people here.' },
          { name: 'per', in: 'query', required: false,
            schema: { type: 'integer', minimum: 1 },
            description: 'Rows per page, shared by the three lists.' }
        ],
        responseDescription: 'The report.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`relationships`, `received`, ' +
                                       '`blocks`, `locks` (each one page), ' +
                                       '`counts` (each list\'s whole ' +
                                       'length), `paging`, `observeOnly`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API partners' signals " +
                    "endpoint.");
          self.sendJson(res, 200, self.pagedReport(req.query));
          log.debug("Leaving the management API partners' signals " +
                    "endpoint.");
        } }
    ];
    log.debug("Leaving SsfTransmittersApi.buildRoutes().");
    return ROUTES;
  }
}

let routes: Json[] = [];

const slot = new InstanceSlot<SsfTransmittersApi>(
  'ssf/ssf_transmitters_api',
  () => new SsfTransmittersApi(SsfTransmittersApi.defaultDeps()),
  SsfTransmittersApi.wire,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/admin-api/ssf/transmitters`: the federation partners' Shared Signals, for
 * a machine.
 *
 * @namespace
 */
export = {
  SsfTransmittersApi: SsfTransmittersApi,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: SsfTransmittersApi): void =>
    slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  /**
   * The route table `mgmt-api/admin_api.ts` spreads into its own.
   */
  get ROUTES(): Json[] {
    helpers.log.debug("Entering ROUTES().");
    slot.get();
    helpers.log.debug("Leaving ROUTES().");
    return routes;
  }
};
