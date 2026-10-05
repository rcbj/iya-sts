// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: scep_admin.ts
//
// ---------------------------------------------------------------------------
// THE TWO SCEP CONSOLE PAGES: Protocols -> SCEP and Monitoring -> SCEP
// enrollments (2026-09-13).
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `gnap/gnap_admin.ts` draws GNAP's. Every fact on either page comes out of ONE
// call to `scep_console.ts`, which is the same call `/admin-api/scep` and
// `/admin-api/scep/monitor` answer with (rule 7).
//
// **ONE ACTION IS NOT A REDIRECT, AND IT IS THE ONE THAT MAKES A SECRET.**
// `respondToAction()` answers a form with a 303 carrying its message on the
// query string, which is right for "the host name was added" and wrong for a
// challenge password: a secret on a query string is a secret in the browser
// history, the access log and the next request's Referer. So a created
// challenge is answered with a 200 PAGE, `Cache-Control: no-store` (which
// `admin.respond()` sets), showing it ONCE with the `sscep` commands that use
// it. Nothing stores it to show it again — the entry holds a SHA-256 of it.
//
// No script, like every page of this console but one: paging is links and
// every control is a form.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `ScepAdmin` takes the modules it uses through its constructor
// (`ScepAdminDeps`). Since #50's R2 the composition root builds the instance
// (`ScepAdmin.defaultDeps()`) and installs it; the module's old export names
// are FACADES that forward to it, for the JavaScript callers, and a process
// without the root builds a default when the module finishes loading.
// `ScepAdmin` is exported beside them for the composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the module
// exports and `common/protocol_stack.ts` calls (#50, R1) at the point in the
// route order where requiring this module used to register them, so rule 1's
// order is unchanged. Requiring the module registers nothing.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
const { log, parseBody } = helpers;
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import core = require('../common/cert_enrollment');
import consoleModel = require('./scep_console');
import InstanceSlot = require('../common/instance_slot');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import ScepPage = require('./web_scep');

const esc = admin.esc;

// What `ScepAdmin` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface ScepAdminDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  core: typeof core;
  consoleModel: typeof consoleModel;
  esc: typeof esc;
}

type RouteApp = typeof app;

/**
 * The two SCEP console pages, Protocols > SCEP and Monitoring > SCEP
 * enrollments, drawn in the console's shell from one call to `scep_console`.
 *
 * A created challenge password is answered with a page showing it once, never
 * with a redirect.
 */
class ScepAdmin {
  /**
   * Builds the pages' owner.
   *
   * @param deps - the logger, body parser, error codes, the console shell, the
   *   enrollment core, the SCEP view model and the HTML escaper
   */
  constructor(private readonly deps: ScepAdminDeps) {
    deps.log.debug("Entering ScepAdmin.constructor().");
    deps.log.debug("Leaving ScepAdmin.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the modules the load-time instance is built from
   */
  static defaultDeps(): ScepAdminDeps {
    helpers.log.debug("Entering ScepAdmin.defaultDeps().");
    helpers.log.debug("Leaving ScepAdmin.defaultDeps().");
    return {
      log: log,
      parseBody: parseBody,
      errorCodes: errorCodes,
      admin: admin,
      core: core,
      consoleModel: consoleModel,
      esc: esc
    };
  }

  /**
   * Refuses a page request whose query string the view model does not accept,
   * with a 400 (STS-SCEP-0060).
   *
   * @param req - the request
   * @param res - the response
   * @returns true when it refused
   */
  queryRefused(req, res) {
    const { log, consoleModel, errorCodes } = this.deps;
    log.debug("Entering ScepAdmin.queryRefused().");
    const query = consoleModel.queryOf(req);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-SCEP-0060');
      res.status(400)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(query.detail);
      log.debug("Leaving ScepAdmin.queryRefused(). Refused.");
      return true;
    }
    log.debug("Leaving ScepAdmin.queryRefused().");
    return false;
  }

  // DRAWN BY `web_scep.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(req, json) {
    const { log, admin } = this.deps;
    log.debug("Entering ScepAdmin.body().");
    const drawn = ScepPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving ScepAdmin.body().");
    return drawn;
  }

  // THE ROUTES, registered where they always were: the module exports
  // this, and `common/protocol_stack.ts` calls it (#50, R1) at the point
  // where requiring the module used to register them, so the route order
  // is unchanged (rule 1). Nothing calls it at load.
  /**
   * Registers `GET /admin/scep`, `POST /admin/scep` and `GET
   * /admin/scep/monitor`; called by `common/protocol_stack.ts`.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, parseBody, consoleModel, admin, esc, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering ScepAdmin.registerRoutes().");


    log.debug("Leaving ScepAdmin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<ScepAdmin>(
  'scep/scep_admin',
  () => new ScepAdmin(ScepAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The two SCEP console pages.
 *
 * The exports forward to the instance the composition root installs.
 *
 * @namespace
 */
export = {
  /**
   * Registers the SCEP console pages on the installed instance.
   */
  registerRoutes: slot.forward('registerRoutes'),
  ScepAdmin: ScepAdmin,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: ScepAdmin): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin()
};
