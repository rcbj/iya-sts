// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_admin.ts
//
// ---------------------------------------------------------------------------
// THE TWO GNAP CONSOLE PAGES: Protocols -> GNAP and Monitoring -> GNAP grants.
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `xacml/xacml_admin.ts` draws XACML's — a console page is a `path` and a
// `label` in `admin-ui/admin.ts`'s `SECTIONS` whoever builds the body. Every
// fact on either page comes out of ONE call to `gnap_console.ts`, which is the
// same call `/admin-api/gnap` and `/admin-api/gnap/monitor` answer with, so the
// page and the operation cannot disagree (rule 7).
//
// **WHERE EACH IS FILED IS DECIDED BY THE QUESTION IT ANSWERS** — the rule
// `/admin/xacml/monitor` established. `/admin/gnap` is what the authorization
// server IS and how it is configured, so it is a Protocols page and it carries
// the `gnap.*` settings (`SETTING_HOMES`). `/admin/gnap/monitor` is what the
// applications using it have DONE, so it is filed under Monitoring and carries
// no setting and no reset: a console that could zero its own monitoring would
// make every number on it one somebody might have zeroed.
//
// No script, like every page of this console but one: the grant filter is a
// set of links, paging is links, and the two actions are forms.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape, for a module that registers routes (rule 1): `GnapAdmin` takes the
// console shell, the view model and the rest through its constructor, and its
// `registerRoutes(app)` holds the three routes in their old order. The
// composition root builds the instance (#50, R2), and the module's
// `registerRoutes(app)` is a FACADE forwarding to it, which
// `common/protocol_stack.ts` calls (#50, R1) right after `gnap_interact.ts`'s,
// exactly where requiring this file registered them before; that function is
// the module's one export beside the class. A process that loads this module
// without the root builds a default instance when the module loads.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import admin = require('../admin-ui/admin');
import consoleModel = require('./gnap_console');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import GnapPage = require('./web_gnap');

type Req = import('express').Request;
type Res = import('express').Response;

// The console's messages banner, which a page draws when the shell offers
// one.
type ConsoleShell = typeof admin & {
  messagesOf?: (req: Req) => string;
};

interface GnapAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  admin: ConsoleShell;
  consoleModel: typeof consoleModel;
}

// The routes' own table of what an express app offers.
interface RouteTable {
  get(path: string, ...handlers: Array<(req: Req, res: Res) => unknown>):
    unknown;
  post(path: string, ...handlers: Array<(req: Req, res: Res) => unknown>):
    unknown;
}

const vz = validation.z;
const vt = validation.types;

const PAGE_QUERY = vz.looseObject({
  state: vt.opt(vt.oneOf(['processing', 'pending', 'approved', 'finalized'])),
  grantsPage: vt.opt(vt.integer(1, 1000000)),
  resourcesPage: vt.opt(vt.integer(1, 1000000)),
  page: vt.opt(vt.integer(1, 1000000)),
  per: vt.opt(vt.integer(1, 1000)),
  format: vt.opt(vt.oneOf(['json', 'JSON', 'html']))
});

const ACTION_FORM = vz.looseObject({
  action: vt.opt(vt.token),
  grant: vt.opt(vt.base64url),
  reference: vt.opt(vt.base64url),
  // The person whose grant it is (#432 phase 7): set by the GNAP grants tab
  // of their page on /admin/users, which the answer goes back to.
  user: vt.opt(vt.name),
  csrf_token: vt.opt(vt.token)
});

/**
 * The two GNAP console pages, Protocols -> GNAP (`/admin/gnap`) and Monitoring
 * -> GNAP grants (`/admin/gnap/monitor`), drawn in the console's shell from one
 * call to `gnap_console.ts` each.
 */
class GnapAdmin {
  /**
   * Builds the pages from the modules they read.
   *
   * @param deps - the modules the composition root passes
   */
  constructor(private readonly deps: GnapAdminDeps) {
    deps.log.debug("Entering GnapAdmin.constructor().");
    deps.log.debug("Leaving GnapAdmin.constructor().");
  }

  private queryRefused(req: Req, res: Res): boolean {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering GnapAdmin.queryRefused().");
    const query = validation.check(req, 'query', PAGE_QUERY);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-GNAP-0663');
      res.status(400)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(query.detail);
      log.debug("Leaving GnapAdmin.queryRefused().");
      return true;
    }
    log.debug("Leaving GnapAdmin.queryRefused().");
    return false;
  }

  // DRAWN BY `web_gnap.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(req, json) {
    const { log, admin } = this.deps;
    log.debug("Entering GnapAdmin.body().");
    const drawn = GnapPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving GnapAdmin.body().");
    return drawn;
  }

  // The three routes, in the order this file has always registered them.
  /**
   * Registers the three console routes, in the order this file always
   * registered them.
   *
   * Called by `common/protocol_stack.ts` after `gnap_interact.ts`'s routes.
   *
   * @param app - the shared express application
   */
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, parseBody, errorCodes, validation, admin,
            consoleModel } = this.deps;
    log.debug("Entering GnapAdmin.registerRoutes().");

    // -----------------------------------------------------------------------
    // GET /admin/gnap
    // -----------------------------------------------------------------------
    app.get('/admin/gnap', function (req, res) {
      log.debug("Entering the admin GNAP page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin GNAP page. Bad query.");
        return;
      }
      const json = consoleModel.gnapView(req);
      const inner = (typeof admin.messagesOf === 'function' ?
                     admin.messagesOf(req) : '') + self.body(req, json);
      admin.respond(req, res, json, 'GNAP', '/admin/gnap', inner);
      log.debug("Leaving the admin GNAP page.");
    });

    // -----------------------------------------------------------------------
    // POST /admin/gnap
    // -----------------------------------------------------------------------
    app.post('/admin/gnap', function (req, res) {
      log.debug("Entering the admin GNAP action.");
      const body = parseBody(req);
      const posted = validation.checkParsed(body, 'body', ACTION_FORM);
      if (!posted.ok) {
        log.debug("Leaving the admin GNAP action. Malformed.");
        const result = errorCodes.mark({ ok: false, errors: [posted.detail] },
                                       'STS-GNAP-0664');
        return admin.respondToAction(req, res, '/admin/gnap', result);
      }
      const result = consoleModel.gnapAction(posted.value,
                                             { via: 'console', req: req });
      // From a person's page (#432 phase 7): back to its GNAP grants tab, at
      // the section heading inside it, which shows the tab again
      // (`tabbedPanels()`).
      const target = posted.value.user
        ? '/admin/users?user=' + encodeURIComponent(posted.value.user) +
          '#gnap-grants'
        : '/admin/gnap';
      admin.respondToAction(req, res, target, result);
      log.debug("Leaving the admin GNAP action. ok=" + result.ok);
      return undefined;
    });

    // -----------------------------------------------------------------------
    // GET /admin/gnap/monitor
    // -----------------------------------------------------------------------
    app.get('/admin/gnap/monitor', function (req, res) {
      log.debug("Entering the admin GNAP monitor page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin GNAP monitor page. Bad query.");
        return;
      }
      const json = consoleModel.gnapMonitorView(req);
      const inner = (typeof admin.messagesOf === 'function' ?
                     admin.messagesOf(req) : '') +
        // Drawn by `web_gnap.ts` (#446), as the GNAP page is.
        GnapPage.monitorBody(admin.renderContext(req),
                             JSON.parse(JSON.stringify(json)));
      admin.respond(req, res, json, 'GNAP grants', '/admin/gnap/monitor',
                    inner);
      log.debug("Leaving the admin GNAP monitor page.");
    });

    log.debug("Leaving GnapAdmin.registerRoutes().");
  }

  // What the composition root passes (#50, R2): the real modules, as the
  // module built its own instance from before.
  /**
   * Returns the real modules the instance was built from before the composition
   * root (#50, R2) passed them.
   *
   * @returns the default dependencies
   */
  static defaultDeps(): GnapAdminDeps {
    helpers.log.debug("Entering GnapAdmin.defaultDeps().");
    helpers.log.debug("Leaving GnapAdmin.defaultDeps().");
    return {
      log: helpers.log,
      parseBody: helpers.parseBody,
      errorCodes: errorCodes,
      validation: validation,
      admin: admin,
      consoleModel: consoleModel
    };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` (see `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<GnapAdmin>(
  'gnap/gnap_admin',
  () => new GnapAdmin(GnapAdmin.defaultDeps()),
  null,
  helpers.log);
// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The two GNAP console pages: Protocols -> GNAP and Monitoring -> GNAP grants.
 *
 * @namespace
 */
export = {
  /**
   * Installs the instance the composition root built (#50, R2).
   *
   * @param instance - the instance the facades forward to
   */
  installInstance: (instance: GnapAdmin): void => slot.install(instance),
  /**
   * Says where the installed instance came from: `root`, `default`, or `none`.
   *
   * @returns the origin label
   */
  instanceOrigin: (): string => slot.origin(),
  registerRoutes: slot.forward('registerRoutes'),
  GnapAdmin: GnapAdmin
};
