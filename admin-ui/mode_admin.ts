// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mode_admin.ts
//
// ===========================================================================
// SERVER CONFIGURATION → MODE (#181, 2026-09-23): WHAT `global.mode` CHANGES,
// AND WHAT IS IN FORCE IN THIS REALM NOW.
//
// `GET /admin/mode` draws `common/mode.js`'s `report()` and nothing else:
// which mode the realm the console is in runs in, every requirement the mode
// changes with the development answer, the product answer and the one in
// force, every development-only setting with the value stored and the value
// in force (they differ exactly where a realm was switched to product with
// such a value still stored), and what product mode still does not check.
//
// **THE PROSE CITED THIS PAGE BEFORE IT EXISTED.** `mode.js`'s REQUIREMENTS
// comment, `global.mode`'s description, `docs/what-is-not-checked.md` and the
// root CLAUDE.md all said `/admin/mode` and `GET /admin-api/mode` published
// the report, and neither was registered — only tests read it. So the page is
// the report, drawn, and adds no fact of its own: a sentence here that is not
// in `report()` would be the second copy `mode.js`'s header refuses.
//
// **A REALM'S PAGE**, not a service page: the mode is per trust realm, so a
// realm administrator reads their own realm's answer. It CHANGES nothing —
// `global.mode` is a Global setting drawn on `/admin/config` (SETTING_HOMES),
// and this page links there rather than being a second door onto it, so
// there is no control and no POST.
//
// **NOT PAGED, deliberately.** Its rows are the REQUIREMENTS and NOT_YET
// tables and the `onlyWhile` rows of `config.js` — bounded by the source,
// not by anything a deployment accumulates — and a reader comparing two
// requirements must not have to turn a page to do it.
//
// Rule 7: `GET /admin-api/mode` answers `modeView()`, the function the page's
// `?format=json` answers.
//
// TYPESCRIPT, AS A CLASS (#50): `vc_status_admin.ts`'s shape — dependencies
// through the constructor, `registerRoutes(app)` called by
// `common/protocol_stack.ts` (18k), facades for the JavaScript callers.
// ===========================================================================

import admin = require('./admin');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import mode = require('../common/mode');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import ModePage = require('./web_mode');

type Req = any;
type Res = any;
type Json = any;

/**
 * The console path of Server configuration → Mode.
 */
const PAGE = '/admin/mode';

interface ModeAdminDeps {
  log: typeof helpers.log;
  admin: typeof admin;
  mode: typeof mode;
}

/**
 * Server configuration → Mode: what `global.mode` changes and what is in force
 * in the ambient realm now, drawn from `mode.report()` and changing nothing.
 */
class ModeAdmin {
  /**
   * See the module's `PAGE`.
   */
  static readonly PAGE = PAGE;

  /**
   * Builds an instance over the modules it depends on.
   *
   * @param deps - the logger, the console and `common/mode.js`
   */
  constructor(private readonly deps: ModeAdminDeps) {
    deps.log.debug("Entering ModeAdmin.constructor().");
    deps.log.debug("Leaving ModeAdmin.constructor().");
  }

  /**
   * Answers the real modules the composition root passes to the constructor.
   *
   * @returns the dependencies of a default instance
   */
  static defaultDeps(): ModeAdminDeps {
    helpers.log.debug("Entering ModeAdmin.defaultDeps().");
    helpers.log.debug("Leaving ModeAdmin.defaultDeps().");
    return { log: helpers.log, admin: admin, mode: mode };
  }

  // The page's JSON, and the management API's answer: `mode.report()` for
  // the ambient realm, whole.
  /**
   * Answers the page's JSON and `GET /admin-api/mode`: `mode.report()` for the
   * ambient realm, whole.
   *
   * @returns the mode report
   */
  modeView(): Json {
    const { log, mode } = this.deps;
    log.debug("Entering ModeAdmin.modeView().");
    const report = mode.report();
    log.debug("Leaving ModeAdmin.modeView(). " + report.mode + ", " +
              report.requirements.length + " requirement(s).");
    return report;
  }

  // ---------------------------------------------------------------------------
  // THE PAGE IS DRAWN BY `web_mode.ts`, FROM THE VIEW AS A CALLER OF THE API
  // RECEIVES IT (#446, 2026-10-05).
  //
  // This page is the first converted for the static console: its body is
  // `ModePage.render()`, a function a browser can load, and it was this
  // class's `html()` moved. Until the console's cutover this process still
  // draws the page, and it hands the renderer the view passed THROUGH JSON —
  // so anything the renderer needs that `GET /admin-api/mode` would not carry
  // fails here, on the server, on the day somebody adds it.
  // ---------------------------------------------------------------------------
  private html(json: Json): string {
    const { log } = this.deps;
    log.debug("Entering ModeAdmin.html().");
    const drawn = ModePage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving ModeAdmin.html().");
    return drawn;
  }

  /**
   * Registers `GET /admin/mode`.
   *
   * @param app - the shared express app
   */
  registerRoutes(app: { get: Function }): void {
    const { log, admin } = this.deps;
    const self = this;
    log.debug("Entering ModeAdmin.registerRoutes().");
    log.debug("Leaving ModeAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<ModeAdmin>(
  'admin-ui/mode_admin',
  () => new ModeAdmin(ModeAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * Server configuration → Mode, `/admin/mode`: what `global.mode` changes, and
 * what is in force in this realm now. A realm's page with no control and no
 * POST.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  ModeAdmin: ModeAdmin,
  /**
   * Installs the instance the composition root built and runs its
   * wire step; a second install is refused.
   */
  installInstance: (instance: ModeAdmin): void => slot.install(instance),
  /**
   * Says where the instance in use came from: `root`, `default` or
   * `none`.
   */
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE,
  // For `mgmt-api/admin_api.ts` (rule 7).
  modeView: slot.forward('modeView')
};
