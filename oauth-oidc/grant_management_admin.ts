// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: grant_management_admin.ts
//
// ---------------------------------------------------------------------------
// `/admin/grants` (#142, 2026-09-24): the OAuth grants this realm holds —
// Grant Management for OAuth 2.0's register, which `grant_management.ts`
// keeps — with a Revoke button on each.
//
// **FILED BESIDE CONSENT, AND THE PAIR IS THE ARGUMENT.** Consent is what a
// PERSON agreed an application may ask for; a grant is what a CLIENT holds
// on the strength of it, named, and able to ask for more (merge) or start
// again (replace). Two registers answering the two halves of one question.
//
// Every fact comes out of `grant_management.list()`, the call
// `GET /admin-api/grants` answers with, and the one control is
// `grant_management.act()`, which `POST /admin-api/grants/revoke-grant`
// takes too (rule 7). No script: Revoke is a POST form the console gate
// checks CSRF and Admin Write on before this handler runs.
//
// **REQUIRED AT 18m**, from `common/protocol_stack.ts`, for 18a's reason: it
// requires `admin-ui/admin` for the shell, which `grant_management.ts` at 9
// could not require without loading the console ahead of the authorization
// server.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import grantManagement = require('./grant_management');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import GrantsPage = require('./web_grants');

type Json = any;

const esc = admin.esc;
const PAGE = '/admin/grants';

interface GrantManagementAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  grants: typeof grantManagement;
  // The console's gate state, for who acted (`admin-core/admin_views`),
  // lazily: it requires route modules.
  adminViews: () => Json;
}

/**
 * The console page `/admin/grants`: every OAuth grant the realm holds, with a
 * Revoke button on each.
 */
class GrantManagementAdmin {
  /**
   * Builds the page from its dependencies.
   *
   * @param deps - the logger, body parser, error codes, console shell, grant
   *   register and a lazy loader of the console's gate state
   */
  constructor(private readonly deps: GrantManagementAdminDeps) {
    deps.log.debug("Entering GrantManagementAdmin.constructor().");
    deps.log.debug("Leaving GrantManagementAdmin.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): GrantManagementAdminDeps {
    helpers.log.debug("Entering GrantManagementAdmin.defaultDeps().");
    helpers.log.debug("Leaving GrantManagementAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody, errorCodes: errorCodes,
      admin: admin, grants: grantManagement,
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
    log.debug("Entering GrantManagementAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in GrantManagementAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving GrantManagementAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // DRAWN BY `web_grants.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering GrantManagementAdmin.body().");
    const drawn = GrantsPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving GrantManagementAdmin.body().");
    return drawn;
  }

  /**
   * Registers `GET` and `POST /admin/grants`: the page, and its one act.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, parseBody, admin, grants, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering GrantManagementAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin grants page.");
      const json = { grants: grants.list(String((req.query || {}).client_id ||
                                                '').slice(0, 256) ||
                                         undefined) };
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.body(json);
      admin.respond(req, res, json, 'Grants', PAGE, inner);
      log.debug("Leaving the admin grants page.");
    });
    app.post(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin grants action.");
      let result: Json = null;
      try {
        result = grants.act(parseBody(req), { via: 'console',
                                              actor: self.actorOf(req) });
      } catch (e: any) {
        log.error(errorCodes.tag('STS-OAUTH-0674') + 'oauth2: a console ' +
                  'grants action failed: ' + ((e && e.stack) || e));
        result = errorCodes.mark({ ok: false, errors:
                                     ['The action could not be completed.'] },
                                 'STS-OAUTH-0674');
      }
      admin.respondToAction(req, res, PAGE, result);
      log.debug("Leaving the admin grants action.");
    });
    log.debug("Leaving GrantManagementAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<GrantManagementAdmin>(
  'oauth-oidc/grant_management_admin',
  () => new GrantManagementAdmin(GrantManagementAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The console page `/admin/grants` (#142), Grant Management's register.
 *
 * The composition root builds the instance and calls `registerRoutes()`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  GrantManagementAdmin: GrantManagementAdmin,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: GrantManagementAdmin): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin()
};
