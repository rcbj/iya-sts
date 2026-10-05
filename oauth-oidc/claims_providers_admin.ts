// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: claims_providers_admin.ts
//
// ===========================================================================
// /admin/claim-providers — THE CLAIMS PROVIDER REGISTER ON THE CONSOLE (#147,
// 2026-09-24): every OpenID Provider this realm fetches aggregated or
// distributed claims from, the redirect URI to register at each, and every
// person's link — with add, update, remove and revoke. Its twin is
// `GET|POST /admin-api/claim-providers` (`claims_providers_api.ts`, rule 7);
// both call `claims_providers.ts`'s `view()` and `act()`. Never a client
// secret and never a person's token.
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import claimsProviders = require('./claims_providers');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import ClaimsProvidersPage = require('./web_claims_providers');

type Json = any;

const esc = admin.esc;
/**
 * The page's path.
 */
const PAGE = '/admin/claim-providers';

interface ClaimsProvidersAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  providers: typeof claimsProviders;
  // The console's gate state, for who acted (`admin-core/admin_views`),
  // lazily: it requires route modules.
  adminViews: () => Json;
}

/**
 * The console page `/admin/claim-providers`: the Claims Provider register and
 * every person's link, with add, update, remove and revoke.
 */
class ClaimsProvidersAdmin {
  /**
   * Builds the page from its dependencies.
   *
   * @param deps - the logger, body parser, base URL reader, error codes,
   *   console shell, Claims Provider register and a lazy loader of the gate
   *   state
   */
  constructor(private readonly deps: ClaimsProvidersAdminDeps) {
    deps.log.debug("Entering ClaimsProvidersAdmin.constructor().");
    deps.log.debug("Leaving ClaimsProvidersAdmin.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ClaimsProvidersAdminDeps {
    helpers.log.debug("Entering ClaimsProvidersAdmin.defaultDeps().");
    helpers.log.debug("Leaving ClaimsProvidersAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes, admin: admin,
      providers: claimsProviders,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  // Who is acting, for the audit row: the console's signed-in operator.
  /**
   * Returns the signed-in console operator, for the audit row.
   *
   * @param req - the console request
   * @returns the operator's username, or ''
   */
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering ClaimsProvidersAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in ClaimsProvidersAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving ClaimsProvidersAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // DRAWN BY `web_claims_providers.ts` (#446): this page is converted for the
  // static console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering ClaimsProvidersAdmin.body().");
    const drawn = ClaimsProvidersPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving ClaimsProvidersAdmin.body().");
    return drawn;
  }

  /**
   * Registers `GET` and `POST /admin/claim-providers`: the page, and its acts.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, parseBody, admin, providers, errorCodes,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering ClaimsProvidersAdmin.registerRoutes().");
    log.debug("Leaving ClaimsProvidersAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<ClaimsProvidersAdmin>(
  'oauth-oidc/claims_providers_admin',
  () => new ClaimsProvidersAdmin(ClaimsProvidersAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The console page `/admin/claim-providers` (#147), the Claims Provider
 * register.
 *
 * The composition root builds the instance and calls `registerRoutes()`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  ClaimsProvidersAdmin: ClaimsProvidersAdmin,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: ClaimsProvidersAdmin): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE
};
