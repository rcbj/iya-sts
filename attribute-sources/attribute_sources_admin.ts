// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: attribute_sources_admin.ts
// ---------------------------------------------------------------------------
// THE CONSOLE PAGE /admin/attribute-sources (#94 part C): Directory →
// Attribute sources.
//
// The register of the operators' SQL databases this realm reads people's
// attributes from, each with its status; a form to add one; per source a
// Test (connect, and read one person's row without writing it), a Refresh
// now (every person, on the scheduler) and an Edit fold; a form to read one
// person now; and the two settings. Every act is `attribute_sources.ts`'s
// `act()`, which `POST /admin-api/attribute-sources/{action}` calls too
// (rule 7), and the page draws `view()`, which `GET /admin-api/
// attribute-sources` answers.
//
// **NO SCRIPT**: every control is a form, and the Edit fold a `<details>`,
// as the console's other folds are.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import attributeSources = require('./attribute_sources');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import AttributeSourcesPage = require('./web_attribute_sources');

type Json = any;

const esc = admin.esc;
/**
 * The page's path.
 */
const PAGE = '/admin/attribute-sources';

interface AttributeSourcesAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  sources: typeof attributeSources;
  adminViews: () => Json;
}

/**
 * The console page `/admin/attribute-sources`: the attribute source
 * register, with add, change, test, refresh and remove.
 */
class AttributeSourcesAdmin {
  /**
   * Builds the page from its dependencies.
   *
   * @param deps - the logger, body parser, error codes, console shell, the
   *   register and a lazy loader of the gate state
   */
  constructor(private readonly deps: AttributeSourcesAdminDeps) {
    deps.log.debug("Entering AttributeSourcesAdmin.constructor().");
    deps.log.debug("Leaving AttributeSourcesAdmin.constructor().");
  }

  /**
   * Returns the dependencies built from this module's own imports.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): AttributeSourcesAdminDeps {
    helpers.log.debug("Entering AttributeSourcesAdmin.defaultDeps().");
    helpers.log.debug("Leaving AttributeSourcesAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody, errorCodes: errorCodes,
      admin: admin, sources: attributeSources,
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
    log.debug("Entering AttributeSourcesAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in AttributeSourcesAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving AttributeSourcesAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // THE JSON THE PAGE AND THE OPERATION BOTH ANSWER (#446). Until then they
  // answered two: the page's carried `settings`, which its Settings block is
  // drawn from, and `GET /admin-api/attribute-sources` answered the register
  // without it — so a console drawn from the API could not have drawn the
  // page. One function, so they cannot differ again.
  /**
   * Returns the view the page is drawn from and the API operation answers:
   * the register's own view, with the page's settings added.
   *
   * @returns the view
   */
  attributeSourcesView(): Json {
    const { log, admin, sources } = this.deps;
    log.debug("Entering AttributeSourcesAdmin.attributeSourcesView().");
    const json = Object.assign(sources.view(),
                               { settings: admin.configSettingsJson(PAGE) });
    log.debug("Leaving AttributeSourcesAdmin.attributeSourcesView().");
    return json;
  }

  // DRAWN BY `web_attribute_sources.ts` (#446): this page is converted for the
  // static console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering AttributeSourcesAdmin.body().");
    const drawn = AttributeSourcesPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving AttributeSourcesAdmin.body().");
    return drawn;
  }

  /**
   * Registers `GET` and `POST /admin/attribute-sources`: the page, and its
   * acts.
   *
   * @param app - the express app
   */
  registerRoutes(app: Json): void {
    const { log, parseBody, admin, sources, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering AttributeSourcesAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin attribute sources page.");
      const json = self.attributeSourcesView();
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.body(json);
      admin.respond(req, res, json, 'Attribute sources', PAGE, inner);
      log.debug("Leaving the admin attribute sources page.");
    });
    app.post(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin attribute sources action.");
      Promise.resolve().then(function (): Json {
        const body = parseBody(req);
        // THE REFRESH MODES ARE CHECKBOXES, one `refresh` repeated, and the
        // body parser keeps the last: the console's own reader takes them
        // all. An update that ticked none says so rather than keeping the
        // old modes — the form always shows every box.
        if (body.action === 'add-source' || body.action === 'update-source') {
          body.refresh = admin.listField(req, body, 'refresh');
          // An unticked box posts nothing: on this form that means off.
          body.trustPublicRoots = body.trustPublicRoots === 'true';
          body.caCertificates = String(body.caCertificates || '');
        }
        return sources.act(body, { via: 'console',
                                   actor: self.actorOf(req) });
      }).catch(function (e: any): Json {
        log.error(errorCodes.tag('STS-ATTR-0002') + 'attribute sources: a ' +
                  'console action failed: ' + ((e && e.stack) || e));
        return errorCodes.mark({ ok: false, errors:
                                   ['The action could not be completed.'] },
                               'STS-ATTR-0002');
      }).then(function (result: Json): void {
        admin.respondToAction(req, res, PAGE, result);
        log.debug("Leaving the admin attribute sources action.");
      });
    });
    log.debug("Leaving AttributeSourcesAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<AttributeSourcesAdmin>(
  'attribute-sources/attribute_sources_admin',
  () => new AttributeSourcesAdmin(AttributeSourcesAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The console page `/admin/attribute-sources` (#94), the attribute source
 * register.
 *
 * The composition root builds the instance and calls `registerRoutes()`.
 *
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  AttributeSourcesAdmin: AttributeSourcesAdmin,
  /**
   * Installs the instance the composition root built, and runs its wiring.
   *
   * @param instance - the instance every facade here forwards to
   */
  installInstance: (instance: AttributeSourcesAdmin): void =>
    slot.install(instance),
  /**
   * Tells where the instance in use came from.
   *
   * @returns `root`, `default` or `none`
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  attributeSourcesView: slot.forward('attributeSourcesView')
};
