// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf_transmitters_admin.ts
//
// ===========================================================================
// /admin/ssf/transmitters — SIGNALS FROM PARTNERS (#153, 2026-09-26; a
// monitoring page since #373, 2026-10-01): every federation relationship
// whose partner's Shared Signals this realm receives, its stream at the
// partner and whether it is healthy, what arrived and what it led to, the
// sign-ins partners have blocked and the account locks a signals-only
// partner's event put on people here. Its twin is
// `GET /admin-api/ssf/transmitters` (`ssf_transmitters_api.ts`, rule 7); both
// draw `ssf_transmitters.ts`'s `report()`. Never a secret.
//
// READ ONLY SINCE #373. A partner's stream is CONFIGURED on its relationship
// (`fedSignals*`) and ACTED ON from the relationship's page — Discover,
// Create stream, Verify, Poll now, Unblock — because the relationship is
// what the partner is (rcbj's call on #373: a foreign transmitter is a
// federation partner in spirit). A second set of controls here would be a
// second door onto the same acts, and the one an operator reading this page
// during an incident did not need.
// ===========================================================================

import helpers = require('../common/helpers');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import transmitters = require('./ssf_transmitters');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import SsfTransmittersPage = require('./web_ssf_transmitters');

type Json = any;

const esc = admin.esc;
/**
 * The console page's path, `/admin/ssf/transmitters`.
 */
const PAGE = '/admin/ssf/transmitters';

interface TransmittersAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  transmitters: typeof transmitters;
}

/**
 * The monitoring page for the federation partners whose Shared Signals this
 * realm receives: each relationship's stream, what arrived and what it led
 * to, and the blocks and locks partners put on people. It draws
 * `ssf_transmitters.ts`'s report, performs nothing, and never shows a secret.
 */
class SsfTransmittersAdmin {
  /**
   * The page's path; the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  /**
   * Builds the page from its dependencies.
   *
   * @param deps - the modules it reads, from
   * `SsfTransmittersAdmin.defaultDeps()` or the composition root
   */
  constructor(private readonly deps: TransmittersAdminDeps) {
    deps.log.debug("Entering SsfTransmittersAdmin.constructor().");
    deps.log.debug("Leaving SsfTransmittersAdmin.constructor().");
  }

  /**
   * Returns the real modules the page depends on, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): TransmittersAdminDeps {
    helpers.log.debug("Entering SsfTransmittersAdmin.defaultDeps().");
    helpers.log.debug("Leaving SsfTransmittersAdmin.defaultDeps().");
    return { log: helpers.log, admin: admin, transmitters: transmitters };
  }

  // DRAWN BY `web_ssf_transmitters.ts` (#446): this page is converted for the
  // static console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering SsfTransmittersAdmin.body().");
    const drawn = SsfTransmittersPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving SsfTransmittersAdmin.body().");
    return drawn;
  }

  /**
   * Registers `GET /admin/ssf/transmitters` on the app.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, admin, transmitters } = this.deps;
    const self = this;
    log.debug("Entering SsfTransmittersAdmin.registerRoutes().");
    log.debug("Leaving SsfTransmittersAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<SsfTransmittersAdmin>(
  'ssf/ssf_transmitters_admin',
  () => new SsfTransmittersAdmin(SsfTransmittersAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The monitoring page for federation partners' Shared Signals,
 * `/admin/ssf/transmitters`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  SsfTransmittersAdmin: SsfTransmittersAdmin,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: SsfTransmittersAdmin): void =>
    slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE
};
