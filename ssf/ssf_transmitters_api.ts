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

  /**
   * Builds the route table: `GET /admin-api/ssf/transmitters`, the
   * monitoring report.
   *
   * @returns the routes
   */
  buildRoutes(): Json[] {
    const { log, loadTransmitters } = this.deps;
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
          'arrived. A partner\'s stream is configured on its relationship ' +
          'and acted on with `POST /admin-api/federation/signals-*`.',
        mirrors: 'GET /admin/ssf/transmitters',
        responseDescription: 'The report.',
        responseSchema: { type: 'object', additionalProperties: true,
                          description: '`relationships`, `received`, ' +
                                       '`blocks`, `locks`, `observeOnly`.' },
        handler: function (req: Req, res: Res): void {
          log.debug("Entering the management API partners' signals " +
                    "endpoint.");
          self.sendJson(res, 200, loadTransmitters().report({
            relationship: req.query.relationship }));
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
