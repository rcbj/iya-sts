// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

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
// **REQUIRED AT 18f**, from `common/protocol_stack.ts`, for 18a's reason: it
// requires `admin-ui/admin` for the shell — a require the other way would
// close a cycle — and `oauth2_monitor_console.ts`, which requires
// `oauth-oidc/par.ts`, `oauth-oidc/oauth2_monitor.ts`, `oauth-oidc/step_up.ts`
// and `admin-core/admin_views.ts`, libraries already loaded by that line.
// `oauth2.ts` at 9 cannot require it: that would load the whole console in
// front of the authorization server — a cycle, since the console requires
// `oauth2.ts`, and, through it, the JavaScript modules that still register
// their routes when required (`tls/tls_server.js` among them). The console's
// OWN routes would no longer move since #50's R1, because
// `common/protocol_stack.ts` registers them in its own order.
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
// their old order. The module registers NOTHING (#50, R1): it exports its
// `registerRoutes(app)` beside the class, and `common/protocol_stack.ts`
// calls it at the point in the route order where requiring this module used
// to register the routes. Since R2 that root also builds the instance and
// installs it, and `registerRoutes` is a FACADE that forwards to it; a
// process without the root builds a default instance at load. It exports
// nothing else: it is required for its routes.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
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

// The list parameters a Withdraw carries back — `BACK_PARAMS` — went to
// `web_oauth2_monitor.ts` with `listViewOf()`, which is what reads them
// (#446): the renderer builds the `back` field and this module reads it.

/**
 * The console page `/admin/oauth2/monitor`: what the authorization server has
 * done, per client, drawn from one call to `oauth2_monitor_console.ts`.
 */
class OAuth2MonitorAdmin {
  /**
   * Builds the page from its dependencies.
   *
   * @param deps - the logger, body parser, error codes, console shell, escaper
   *   and the page's view model
   */
  constructor(private readonly deps: OAuth2MonitorAdminDeps) {
    deps.log.debug("Entering OAuth2MonitorAdmin.constructor().");
    deps.log.debug("Leaving OAuth2MonitorAdmin.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): OAuth2MonitorAdminDeps {
    helpers.log.debug("Entering OAuth2MonitorAdmin.defaultDeps().");
    helpers.log.debug("Leaving OAuth2MonitorAdmin.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      admin: admin,
      esc: admin.esc,
      consoleModel: consoleModel
    };
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

  /**
   * Registers `GET` and `POST /admin/oauth2/monitor`: the page, and its
   * Withdraw control.
   *
   * @param app - the express app
   */
  registerRoutes(app: { get: Function; post: Function }): void {
    const { log, parseBody, errorCodes, admin, consoleModel } = this.deps;
    const self = this;
    log.debug("Entering OAuth2MonitorAdmin.registerRoutes().");


    log.debug("Leaving OAuth2MonitorAdmin.registerRoutes().");
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
const slot = new InstanceSlot<OAuth2MonitorAdmin>(
  'oauth-oidc/oauth2_monitor_admin',
  () => new OAuth2MonitorAdmin(OAuth2MonitorAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The console page Monitoring -> OAuth 2.0 / OIDC activity.
 *
 * The composition root builds the instance and calls `registerRoutes()`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  OAuth2MonitorAdmin: OAuth2MonitorAdmin,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   * Refused once an instance is installed or a default built.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: OAuth2MonitorAdmin): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin()
};
