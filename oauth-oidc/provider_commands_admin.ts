// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: provider_commands_admin.ts
//
// ===========================================================================
// TWO CONSOLE PAGES (#151, 2026-09-26):
//
// **`/admin/commands` — OPENID PROVIDER COMMANDS.** Every client that
// registered a `command_endpoint` and what its `metadata` answer said it
// supports; sending an account command about a person and a tenant command
// about everybody; the account-state register (what each relying party said
// about each person); the tenant runs; the command deliveries with their
// dead letters. Its twin is `/admin-api/commands` (`provider_commands_api.ts`,
// rule 7); both call `provider_commands.ts`'s `report()` and `act()`.
//
// **`/admin/deliveries` — MONITORING → OUTBOUND DELIVERIES.** The shared
// outbound queue (`outbound_delivery.ts`) by kind — Back-Channel Logout
// Tokens, CIBA pings and pushes, OpenID Provider Commands — with each kind's
// counts, its rows, a filter by state, and Retry on a dead letter. Its twin
// is `/admin-api/deliveries`.
//
// Neither shows a token or a body.
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import providerCommands = require('./provider_commands');
import outbound = require('./outbound_delivery');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import ProviderCommandsPage = require('./web_provider_commands');

type Req = any;
type Json = any;

/**
 * The path of the OpenID Provider Commands page.
 */
const PAGE = '/admin/commands';
/**
 * The path of the outbound deliveries page.
 */
const DELIVERIES = '/admin/deliveries';

interface ProviderCommandsAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  commands: typeof providerCommands;
  outbound: typeof outbound;
  adminViews: () => Json;
}

/**
 * The console pages `/admin/commands` (OpenID Provider Commands) and
 * `/admin/deliveries` (every outbound delivery, with its dead letters).
 */
class ProviderCommandsAdmin {
  /**
   * The path of the OpenID Provider Commands page.
   */
  static readonly PAGE = PAGE;
  /**
   * The path of the outbound deliveries page.
   */
  static readonly DELIVERIES = DELIVERIES;

  /**
   * Builds the pages from their dependencies.
   *
   * @param deps - the logger, body parser, base URL reader, error codes,
   *   console shell, command module, outbound queue and a lazy loader of the
   *   gate state
   */
  constructor(private readonly deps: ProviderCommandsAdminDeps) {
    deps.log.debug("Entering ProviderCommandsAdmin.constructor().");
    deps.log.debug("Leaving ProviderCommandsAdmin.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): ProviderCommandsAdminDeps {
    helpers.log.debug("Entering ProviderCommandsAdmin.defaultDeps().");
    helpers.log.debug("Leaving ProviderCommandsAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes, admin: admin,
      commands: providerCommands, outbound: outbound,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  /**
   * Returns the signed-in console operator, for the audit row.
   *
   * @param req - the console request
   * @returns the operator's username, or ''
   */
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering ProviderCommandsAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in ProviderCommandsAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving ProviderCommandsAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // DRAWN BY `web_provider_commands.ts` (#446): this page is converted for the
  // static console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  commandsBody(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering ProviderCommandsAdmin.commandsBody().");
    const drawn =
      ProviderCommandsPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving ProviderCommandsAdmin.commandsBody().");
    return drawn;
  }

  /**
   * Registers `GET` and `POST` for both pages.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, parseBody, admin, commands, errorCodes, outbound,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering ProviderCommandsAdmin.registerRoutes().");
    log.debug("Leaving ProviderCommandsAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<ProviderCommandsAdmin>(
  'oauth-oidc/provider_commands_admin',
  () => new ProviderCommandsAdmin(ProviderCommandsAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The console pages for OpenID Provider Commands and the outbound deliveries
 * (#151).
 *
 * The composition root builds the instance and calls `registerRoutes()`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  ProviderCommandsAdmin: ProviderCommandsAdmin,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: ProviderCommandsAdmin): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  DELIVERIES: DELIVERIES
};
