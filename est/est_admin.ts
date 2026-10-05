// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: est_admin.ts
//
// ---------------------------------------------------------------------------
// THE TWO EST CONSOLE PAGES: Protocols -> EST and Monitoring -> EST enrollments
// (2026-09-13).
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `gnap/gnap_admin.ts` draws GNAP's. Every fact on either page comes out of ONE
// call to `est_console.ts`, which is the call `/admin-api/est` and
// `/admin-api/est/monitor` answer with, so the page and the operation cannot
// disagree (rule 7).
//
// **WHERE EACH IS FILED IS DECIDED BY THE QUESTION IT ANSWERS.** `/admin/est`
// is what the EST server IS and how it is configured, so it carries the `est.*`
// settings and the four controls; `/admin/est/monitor` is what it has DONE and
// carries no control and no reset.
//
// **THE ONE ACTION THAT DOES NOT REDIRECT** is "issue a certificate with a
// server-generated key": its answer includes a private key, and
// `respondToAction()` answers a form with a 303 carrying the message on the
// query string — a private key there is a private key in the browser history,
// the access log and the next request's Referer. It answers a 200 page with
// `Cache-Control: no-store` instead, and the key is on that page once.
//
// No script: every control is a form and every list pages with links.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `EstAdmin` takes the modules it uses through its constructor
// (`EstAdminDeps`). Since #50's R2 the composition root builds the instance
// (`EstAdmin.defaultDeps()`) and installs it; the module's old export names are
// FACADES that forward to it, for the JavaScript callers, and a process without
// the root builds a default when the module finishes loading. `EstAdmin` is
// exported beside them for the composition root.
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
import consoleModel = require('./est_console');
import InstanceSlot = require('../common/instance_slot');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import EstPage = require('./web_est');

const esc = admin.esc;
const vz = validation.z;
const vt = validation.types;

const PAGE_QUERY = vz.looseObject({
  certificatesPage: vt.opt(vt.integer(1, 1000000)),
  page: vt.opt(vt.integer(1, 1000000)),
  per: vt.opt(vt.integer(1, 1000)),
  format: vt.opt(vt.oneOf(['json', 'JSON', 'html'])),
  notice: vt.opt(vt.message),
  error: vt.opt(vt.message)
});

// What `EstAdmin` needs from the rest of the service: the modules this file
// used to reach for itself, passed in so that the composition root can build
// one and a test can build one with stubs.
interface EstAdminDeps {
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
 * The two EST console pages, Protocols → EST (`/admin/est`) and Monitoring →
 * EST enrollments (`/admin/est/monitor`), drawn in the console's shell from one
 * call to `est_console.ts` each.
 *
 * Issuing with a server-generated key answers with a one-time page carrying the
 * private key rather than a redirect.
 */
class EstAdmin {
  /**
   * Builds the pages from their dependencies.
   *
   * @param deps - the modules they read, from `EstAdmin.defaultDeps()` or the
   * composition root
   */
  constructor(private readonly deps: EstAdminDeps) {
    deps.log.debug("Entering EstAdmin.constructor().");
    deps.log.debug("Leaving EstAdmin.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the real modules the pages depend on, as the composition root
   * passes them.
   *
   * @returns the dependencies
   */
  static defaultDeps(): EstAdminDeps {
    helpers.log.debug("Entering EstAdmin.defaultDeps().");
    helpers.log.debug("Leaving EstAdmin.defaultDeps().");
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
   * Validates a page's query, answering 400 when it is malformed.
   *
   * @param req - the request
   * @param res - the response
   * @returns true when the query was refused and answered
   */
  queryRefused(req, res) {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering EstAdmin.queryRefused().");
    const query = validation.check(req, 'query', PAGE_QUERY);
    if (!query.ok) {
      errorCodes.mark(res, 'STS-EST-0030');
      res.status(400)
         .type('text/plain')
         .set('Cache-Control', 'no-store')
         .send(query.detail);
      log.debug("Leaving EstAdmin.queryRefused(). Refused.");
      return true;
    }
    log.debug("Leaving EstAdmin.queryRefused().");
    return false;
  }

  /**
   * Draws the console's pending messages for a request.
   *
   * @param req - the request
   * @returns the HTML
   */
  messages(req) {
    const { log, admin } = this.deps;
    log.debug("Entering EstAdmin.messages().");
    log.debug("Leaving EstAdmin.messages().");
    return typeof admin.messagesOf === 'function' ? admin.messagesOf(req) : '';
  }

  // DRAWN BY `web_est.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  estPageBody(req, json) {
    const { log, admin } = this.deps;
    log.debug("Entering EstAdmin.estPageBody().");
    const drawn = EstPage.render(JSON.parse(JSON.stringify(json)),
      admin.renderContext(req));
    log.debug("Leaving EstAdmin.estPageBody().");
    return drawn;
  }

  // The one-time page for a server-generated key.
  /**
   * Draws the one-time page for a certificate issued with a server-generated
   * key: the private key, the certificate and its chain.
   *
   * @param result - the issue action's result
   * @returns the HTML
   */
  issuedKeyPage(result, backHref?) {
    const { log, admin, esc } = this.deps;
    log.debug("Entering EstAdmin.issuedKeyPage().");
    log.debug("Leaving EstAdmin.issuedKeyPage().");
    return admin.warn('<strong>' + esc(result.message) + '</strong> Copy the ' +
      'private key now: this page is not stored, and nothing on this console ' +
      'will show it again.') +
      '<h2>Private key (PKCS#8)</h2><pre>' + esc(result.privateKeyPem) +
      '</pre><h2>Certificate</h2><table class="kv"><tr><th>Serial</th><td>' +
      '<code>' + esc(result.record.serialHex) + '</code></td></tr><tr><th>' +
      'Profile</th><td>' + esc(result.record.profile) + '</td></tr><tr><th>' +
      'Names</th><td>' + result.record.names.map(function (n) {
        return '<code>' + esc(n) + '</code>';
      }).join('<br>') + '</td></tr><tr><th>Expires</th><td>' +
      esc(result.record.notAfter) + '</td></tr></table><pre>' +
      esc(result.certificatePem) + '</pre><h3>Chain</h3><pre>' +
      esc((result.chainPem || []).join('')) + '</pre>' +
      '<p class="links">' + (backHref
        ? '<a href="' + esc(backHref) + '">Back to the application</a> · '
        : '') + '<a href="/admin/est">Back to EST</a></p>';
  }

  // THE ROUTES, registered where they always were: the module exports
  // this, and `common/protocol_stack.ts` calls it (#50, R1) at the point
  // where requiring the module used to register them, so the route order
  // is unchanged (rule 1). Nothing calls it at load.
  /**
   * Registers `GET` and `POST /admin/est` and `GET /admin/est/monitor` on the
   * app. Called by `common/protocol_stack.ts`.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, consoleModel, admin, parseBody, errorCodes, esc } = this.deps;
    const self = this;
    log.debug("Entering EstAdmin.registerRoutes().");
    // -------------------------------------------------------------------------
    // GET /admin/est
    // -------------------------------------------------------------------------
    app.get('/admin/est', function (req, res) {
      log.debug("Entering the admin EST page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin EST page. Bad query.");
        return;
      }
      const json = consoleModel.estView(req);
      admin.respond(req, res, json, 'EST', '/admin/est',
                    self.messages(req) + self.estPageBody(req, json));
      log.debug("Leaving the admin EST page.");
    });

    // -------------------------------------------------------------------------
    // POST /admin/est
    // -------------------------------------------------------------------------
    app.post('/admin/est', function (req, res) {
      log.debug("Entering the admin EST action.");
      const body = parseBody(req);
      consoleModel.estAction(body, { via: 'console', req: req })
        .then(function (result) {
          // A form on an application's page comes back there (2026-10-01).
          const back = admin.enrollmentReturnTo(body, '/admin/est');
          if (result && result.ok && result.privateKeyPem) {
            admin.respond(req, res, result, 'EST — a server-generated key',
                          '/admin/est', self.issuedKeyPage(result,
                            back === '/admin/est' ? '' : back));
            log.debug("Leaving the admin EST action. A one-time key page.");
            return;
          }
          if (result && !result.ok) {
            errorCodes.mark(res, errorCodes.codeOf(result) || 'STS-EST-0031');
          }
          admin.respondToAction(req, res, back, result);
          log.debug("Leaving the admin EST action. ok=" + !!(result &&
                                                             result.ok));
        }, function (e) {
          log.error(errorCodes.tag('STS-EST-0020') +
                    'est console: the action failed: ' + ((e && e.stack) || e));
          const failed = errorCodes.mark({ ok: false, errors: ['The action ' +
            'could not be completed.'] }, 'STS-EST-0020');
          admin.respondToAction(req, res, '/admin/est', failed);
          log.debug("Leaving the admin EST action. Threw.");
        });
    });

    app.get('/admin/est/monitor', function (req, res) {
      log.debug("Entering the admin EST monitor page.");
      if (self.queryRefused(req, res)) {
        log.debug("Leaving the admin EST monitor page. Bad query.");
        return;
      }
      const json = consoleModel.estMonitorView(req);
      // Drawn by `web_est.ts` (#446), as the EST page is.
      const inner = self.messages(req) +
        EstPage.monitorBody(admin.renderContext(req),
                            JSON.parse(JSON.stringify(json)));
      admin.respond(req, res, json, 'EST enrollments', '/admin/est/monitor',
                    inner);
      log.debug("Leaving the admin EST monitor page.");
    });
    log.debug("Leaving EstAdmin.registerRoutes().");
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
const slot = new InstanceSlot<EstAdmin>(
  'est/est_admin',
  () => new EstAdmin(EstAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The two EST console pages.
 *
 * Exports `registerRoutes`, the `EstAdmin` class, and the instance slot's
 * facades.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  EstAdmin: EstAdmin,
  /**
   * Installs the instance the facades forward to.
   */
  installInstance: (instance: EstAdmin): void => slot.install(instance),
  /**
   * Says where the current instance came from.
   */
  instanceOrigin: (): string => slot.origin()
};
