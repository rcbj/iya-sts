// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oidfed_admin.ts
//
// ---------------------------------------------------------------------------
// PROTOCOLS -> OPENID FEDERATION (#132, #133, 2026-09-23): the console page.
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `scep/scep_admin.ts` draws SCEP's. Every fact on the page comes out of ONE
// call to `oidfed.view()`, which is the same call `GET /admin-api/oidfed`
// answers with, and every control is one of `oidfed.act()`'s actions, which
// `POST /admin-api/oidfed/:action` takes too (rule 7).
//
// No script, like every page of this console but one: every control is a
// form, and the JSON fields (a JWK Set, a metadata policy) are textareas.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import oidfed = require('./oidfed');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import OidfedPage = require('./web_oidfed');

type Json = any;

const esc = admin.esc;

interface OidfedAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  oidfed: typeof oidfed;
  // The console's gate state, for who acted (`admin-core/admin_views`),
  // lazily: it requires route modules.
  adminViews: () => Json;
}

/**
 * Protocols → OpenID Federation, `/admin/oidfed`: every fact from one
 * `oidfed.view()` call and every control one of `oidfed.act()`'s actions, the
 * same two `/admin-api/oidfed` answers with (rule 7).
 */
class OidfedAdmin {
  /**
   * Builds an instance over what it depends on.
   *
   * @param deps - the logger, the body parser, the error-code table, the
   * console, the federation entity and the lazily loaded gate state
   */
  constructor(private readonly deps: OidfedAdminDeps) {
    deps.log.debug("Entering OidfedAdmin.constructor().");
    deps.log.debug("Leaving OidfedAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): OidfedAdminDeps {
    helpers.log.debug("Entering OidfedAdmin.defaultDeps().");
    helpers.log.debug("Leaving OidfedAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody, errorCodes: errorCodes,
      admin: admin, oidfed: oidfed,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  // Who is acting, for the audit row: the console's signed-in operator.
  /**
   * Answers who is acting, for the audit row: the console's signed-in operator.
   *
   * @param req - the request
   * @returns the operator's name, or ''
   */
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering OidfedAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in OidfedAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving OidfedAdmin.actorOf().");
    return (state && state.username) || '';
  }

  /**
   * Draws the whole page in the console's shell, or its JSON.
   *
   * @param req - the request
   * @param res - the response
   * @param extraTop - markup to draw above the sections, such as an action's
   * result
   * @param resolution - a resolution to show, if any
   */
  // THE VIEW THE PAGE AND `GET /admin-api/oidfed` BOTH ANSWER (#446): the
  // realm's federation, with the page's settings. One function, so the API
  // answers everything the page is drawn from.
  /**
   * Returns the view the page is drawn from and the API operation answers.
   *
   * @param req - the request, which the federation view reads
   * @returns the view
   */
  async oidfedView(req: Json): Promise<Json> {
    const { log, admin, oidfed } = this.deps;
    log.debug("Entering OidfedAdmin.oidfedView().");
    const view = await oidfed.view(req);
    view.settings = admin.configSettingsJson('/admin/oidfed');
    log.debug("Leaving OidfedAdmin.oidfedView().");
    return view;
  }

  async draw(req: Json, res: Json, extraTop: string,
             resolution: Json): Promise<void> {
    const { log, admin } = this.deps;
    log.debug("Entering OidfedAdmin.draw().");
    const json = await this.oidfedView(req);
    // A RESOLUTION just made is shown under the form that made it: the
    // action's answer, beside the view rather than in it.
    const inner = (extraTop || '') +
      (typeof admin.messagesOf === 'function' ? admin.messagesOf(req) : '') +
      this.body(Object.assign({ resolution: resolution }, json));
    admin.respond(req, res, json, 'OpenID Federation', '/admin/oidfed', inner);
    log.debug("Leaving OidfedAdmin.draw().");
  }

  // DRAWN BY `web_oidfed.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering OidfedAdmin.body().");
    const drawn = OidfedPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving OidfedAdmin.body().");
    return drawn;
  }

  /**
   * Registers `GET` and `POST /admin/oidfed`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: Json): void {
    const { log, parseBody, admin, oidfed, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering OidfedAdmin.registerRoutes().");
    app.get('/admin/oidfed', function (req: Json, res: Json): void {
      log.debug("Entering the admin OpenID Federation page.");
      self.draw(req, res, '', null).catch(function (e: any): void {
        log.error(errorCodes.tag('STS-OIDFED-0050') + 'oidfed: the console ' +
                  'page failed: ' + ((e && e.stack) || e));
        errorCodes.mark(res, 'STS-OIDFED-0050');
        res.status(500).type('text/plain').send('The page failed.');
      });
      log.debug("Leaving the admin OpenID Federation page.");
    });
    app.post('/admin/oidfed', function (req: Json, res: Json): void {
      log.debug("Entering the admin OpenID Federation action.");
      const body = parseBody(req);
      oidfed.act(body, { via: 'console', actor: self.actorOf(req), req: req })
        .then(function (result: Json): Promise<void> | void {
          const json = /json/i.test(String(req.headers['content-type'] || ''));
          if (result.ok && result.resolution && !json) {
            // A RESOLUTION is shown in full on the page, rather than as a
            // one-line message on a redirect.
            return self.draw(req, res, admin.note(esc(result.message)),
                             result.resolution);
          }
          admin.respondToAction(req, res, '/admin/oidfed', result);
        })
        .catch(function (e: any): void {
          log.error(errorCodes.tag('STS-OIDFED-0050') + 'oidfed: a console ' +
                    'action failed: ' + ((e && e.stack) || e));
          admin.respondToAction(req, res, '/admin/oidfed', errorCodes.mark(
            { ok: false, errors: ['The action could not be completed.'] },
            'STS-OIDFED-0050'));
        });
      log.debug("Leaving the admin OpenID Federation action handler.");
    });
    log.debug("Leaving OidfedAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<OidfedAdmin>(
  'oidfed/oidfed_admin',
  () => new OidfedAdmin(OidfedAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Protocols → OpenID Federation, the console page for the realm as a federation
 * entity.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  OidfedAdmin: OidfedAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: OidfedAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  oidfedView: slot.forward('oidfedView')
};
