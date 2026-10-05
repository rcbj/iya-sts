// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: acme_admin.ts
//
// ---------------------------------------------------------------------------
// THE TWO ACME CONSOLE PAGES: Protocols -> ACME and Monitoring -> ACME
// enrollments.
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `gnap/gnap_admin.ts` draws GNAP's. Every fact on either page comes out of ONE
// call to `acme_console.ts`, which is the same call `/admin-api/acme` and
// `/admin-api/acme/monitor` answer with (rule 7).
//
// **WHERE EACH IS FILED IS DECIDED BY THE QUESTION IT ANSWERS.** `/admin/acme`
// is what the server IS — its directory, its Issuing CA, the profiles, the EAB
// keys, the accounts, the certificates, the host names an entry may be issued
// for, and the `acme.*` settings. `/admin/acme/monitor` is what it has DONE,
// and carries no control: a console that could zero its own monitoring would
// make every number on it one somebody might have zeroed.
//
// **ONE ACTION ANSWERS A PAGE AND NOT A REDIRECT: `create-eab`.** Its reply
// holds the HMAC key, which a client cannot be configured without and which is
// never shown again — and `respondToAction()` answers a 303 whose message rides
// on the query string, which is the browser history, the access log and the
// next request's Referer. So that one action renders a 200 page with
// `Cache-Control: no-store` (through `admin.respond()`), and every other action
// goes through `respondToAction()`.
//
// No script, like every page of this console but one: paging is links and each
// control is a form the console gate checks CSRF and Admin Write on.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AcmeAdmin` takes the modules it uses through its constructor
// (`AcmeAdminDeps`). Since #50's R2 the composition root builds the instance
// (`AcmeAdmin.defaultDeps()`) and installs it; the module's old export names
// are FACADES that forward to it, for the JavaScript callers, and a process
// without the root builds a default when the module finishes loading.
// `AcmeAdmin` is exported beside them for the composition root.
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
import validation = require('../common/validation');
import admin = require('../admin-ui/admin');
import consoleModel = require('./acme_console');
import InstanceSlot = require('../common/instance_slot');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import AcmePage = require('./web_acme');

const esc = admin.esc;
const vz = validation.z;
const vt = validation.types;

const PAGE_QUERY = vz.looseObject({
  per: vt.opt(vt.integer(1, 1000)),
  page: vt.opt(vt.integer(1, 1000000)),
  certificatesPage: vt.opt(vt.integer(1, 1000000)),
  credentialsPage: vt.opt(vt.integer(1, 1000000)),
  accountsPage: vt.opt(vt.integer(1, 1000000)),
  hostNamesPage: vt.opt(vt.integer(1, 1000000)),
  format: vt.opt(vt.oneOf(['json', 'JSON', 'html']))
});

const ACTION_FORM = vz.looseObject({
  action: vt.token,
  csrf_token: vt.opt(vt.token)
});

// What `AcmeAdmin` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface AcmeAdminDeps {
  log: typeof log;
  parseBody: typeof parseBody;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  admin: typeof admin;
  consoleModel: typeof consoleModel;
  esc: typeof esc;
}

type RouteApp = typeof app;

/**
 * The two ACME console pages, Protocols -> ACME (`/admin/acme`) and Monitoring
 * -> ACME enrollments (`/admin/acme/monitor`), drawn from `acme_console.ts` in
 * the console's shell.
 *
 * `create-eab` answers an uncached page holding the HMAC key once; every other
 * action answers through `respondToAction()`.
 */
class AcmeAdmin {
  /**
   * Creates the pages.
   *
   * @param deps - the modules they use: the console shell, the view model,
   * validation and the rest
   */
  constructor(private readonly deps: AcmeAdminDeps) {
    deps.log.debug("Entering AcmeAdmin.constructor().");
    deps.log.debug("Leaving AcmeAdmin.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the dependencies
   */
  static defaultDeps(): AcmeAdminDeps {
    helpers.log.debug("Entering AcmeAdmin.defaultDeps().");
    helpers.log.debug("Leaving AcmeAdmin.defaultDeps().");
    return {
      log: log,
      parseBody: parseBody,
      errorCodes: errorCodes,
      validation: validation,
      admin: admin,
      consoleModel: consoleModel,
      esc: esc
    };
  }

  /**
   * Checks a page's query and, when it is not acceptable, answers 400
   * (STS-ACME-0097).
   *
   * @param req - the request
   * @param res - its response
   * @returns true when the request was refused and answered
   */
  queryRefused(req, res) {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering AcmeAdmin.queryRefused().");
    const query = validation.check(req, 'query', PAGE_QUERY);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-ACME-0097');
      res.status(400)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(query.detail);
      log.debug("Leaving AcmeAdmin.queryRefused(). Refused.");
      return true;
    }
    log.debug("Leaving AcmeAdmin.queryRefused().");
    return false;
  }

  // The page that answers `create-eab`: the key, once.
  /**
   * Answers `create-eab` with an uncached page showing the new key and its
   * certbot line, once.
   *
   * @param req - the request
   * @param res - its response
   * @param result - the action's answer
   */
  createdEabPage(req, res, result, backHref?) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering AcmeAdmin.createdEabPage().");
    const inner = admin.warn('<strong>Copy the HMAC key now.</strong> It is ' +
        'stored sealed on the entry and is never shown again; this page is ' +
        'not cached.') +
      '<table class="kv"><tr><th>For</th><td>' +
      AcmePage.code(result.targetUri) +
      '</td></tr><tr><th>Directory</th><td>' +
      AcmePage.code(result.directory) +
      '</td></tr><tr><th>Key id (--eab-kid)</th><td>' +
      AcmePage.code(result.kid) +
      '</td></tr><tr><th>HMAC key (--eab-hmac-key)</th><td>' +
      AcmePage.code(result.hmacKey) + '</td></tr><tr><th>MAC</th><td>' +
      AcmePage.code(result.alg) + '</td></tr><tr><th>Unused until</th><td>' +
      esc(result.expiresAt) + '</td></tr></table>' +
      '<h2>certbot</h2><pre>' + esc(result.certbot) + '</pre>' +
      '<p class="links">' + (backHref
        ? '<a href="' + esc(backHref) + '">Back to the application</a> · '
        : '') + '<a href="/admin/acme#eab">Back to ACME</a></p>';
    admin.respond(req, res, result, 'ACME — EAB key', '/admin/acme', inner);
    log.debug("Leaving AcmeAdmin.createdEabPage().");
  }

  // DRAWN BY `web_acme.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(req, json) {
    const { log, admin } = this.deps;
    log.debug("Entering AcmeAdmin.body().");
    const drawn = AcmePage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving AcmeAdmin.body().");
    return drawn;
  }

  // THE ROUTES, registered where they always were: the module exports
  // this, and `common/protocol_stack.ts` calls it (#50, R1) at the point
  // where requiring the module used to register them, so the route order
  // is unchanged (rule 1). Nothing calls it at load.
  /**
   * Registers `GET /admin/acme`, `POST /admin/acme` and `GET
   * /admin/acme/monitor`; called by the composition root at this module's place
   * in the route order.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, consoleModel, admin, esc, parseBody, validation,
            errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AcmeAdmin.registerRoutes().");


    log.debug("Leaving AcmeAdmin.registerRoutes().");
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
const slot = new InstanceSlot<AcmeAdmin>(
  'acme/acme_admin',
  () => new AcmeAdmin(AcmeAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The ACME console pages.
 *
 * Exports `registerRoutes`, the class and the instance hooks of the composition
 * root.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  AcmeAdmin: AcmeAdmin,
  installInstance: (instance: AcmeAdmin): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin()
};
