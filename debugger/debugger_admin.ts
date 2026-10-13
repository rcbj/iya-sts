// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: debugger_admin.ts
//
// ===========================================================================
// SERVER CONFIGURATION > PROTOCOL DEBUGGER: `/admin/debugger` (2026-09-13).
//
// One page, and `GET /admin-api/debugger` answers from the same function
// (rule 7). It reports what `debugger/debugger_server.ts` did at startup —
// whether the debugger is embedded, the listener and the origin, the api
// process and what it may dial — and draws the `Protocol debugger` settings
// group beneath, because `debugger.port` beside the port that actually bound is
// the reading that answers "why is it not where I set it".
//
// **THERE IS NO CONTROL ON IT BUT THE SETTINGS**, and none of those opens the
// gate: who may use the debugger is the two console roles on `/admin/rbac`,
// and this page links there rather than repeating them.
//
// ---------------------------------------------------------------------------
// WHERE IT IS REQUIRED, AND THE ONE LAZY REQUIRE IN IT.
//
// `common/protocol_stack.ts` requires it beside the other report pages at 18,
// and `mgmt-api/admin_api.ts` at 19 requires it in the ordinary direction for
// the view. It must not require `debugger_server.ts` at the top: that module
// requires `tls/tls_server.js`, which registers `/tls` routes and is at 20, so
// the require would drag those ahead of the management API's (rule 1). The
// status is read inside the view instead, when every module is loaded — the
// arrangement `common/oidc_rp.ts` makes with the same module.
//
// The page and the operation are pinned to the front process
// (`common/request_pool.js`'s NEVER_DISPATCHED): only it holds the listener
// and the child.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DebuggerAdmin` takes the modules it uses through its constructor
// (`DebuggerAdminDeps`). Since #50's R2 the composition root builds the
// instance; the module's old names are FACADES forwarding to it, for the
// callers that are not converted, and a process without the root builds a
// default at load.
// `DebuggerAdmin` is exported beside them for that root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the module
// exports as a facade and `common/protocol_stack.ts`
// calls at 18e, the point in the route order where requiring this module
// used to register them (#50, R1), so the order is unchanged. Requiring the
// module registers nothing.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import admin = require('../admin-ui/admin');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
const { log } = helpers;
import errorCodes = require('../common/error_codes');
// The page's renderer (#446): a `web_` module, loadable in a browser.
import DebuggerPage = require('./web_debugger');

const PAGE_PATH = '/admin/debugger';

// What `DebuggerAdmin` needs from the rest of the service: the modules this
// file used to reach for itself, passed in so that the composition root can
// build one and a test can build one with stubs.
interface DebuggerAdminDeps {
  admin: typeof admin;
  log: typeof log;
  errorCodes: typeof errorCodes;
  // Required when first called, as the JavaScript did, for the reason
  // given where each is called.
  loadDebuggerServer(): typeof import('./debugger_server');
}

type RouteApp = typeof app;

/**
 * The console page `/admin/debugger`: what the embedded debugger did at
 * startup, and its settings group.
 *
 * `GET /admin-api/debugger` answers from the same view.
 */
class DebuggerAdmin {
  /**
   * Builds the page over the given modules.
   *
   * @param deps - the console shell, the logger, the error codes and a loader
   *   for debugger_server
   */
  constructor(private readonly deps: DebuggerAdminDeps) {
    deps.log.debug("Entering DebuggerAdmin.constructor().");
    deps.log.debug("Leaving DebuggerAdmin.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies the load-time default instance is built from.
   *
   * @returns the real modules, with debugger_server required lazily
   */
  static defaultDeps(): DebuggerAdminDeps {
    helpers.log.debug("Entering DebuggerAdmin.defaultDeps().");
    helpers.log.debug("Leaving DebuggerAdmin.defaultDeps().");
    return {
      admin: admin,
      log: log,
      errorCodes: errorCodes,
      loadDebuggerServer: function () {
        return require('./debugger_server');
      }
    };
  }

  // The JSON the page and the operation both answer.
  /**
   * Returns the JSON the page and the API operation both answer: the
   * debugger server's status with the settings group added.
   *
   * @returns the view
   */
  debuggerView() {
    const { log, loadDebuggerServer, admin } = this.deps;
    log.debug("Entering DebuggerAdmin.debuggerView().");
    // THE LAZY REQUIRE — see the header.
    const status = loadDebuggerServer().status();
    status.settings = admin.configSettingsJson(PAGE_PATH);
    log.debug("Leaving DebuggerAdmin.debuggerView().");
    return status;
  }

  // DRAWN BY `web_debugger.ts` (#446): this page is converted for the static
  // console, and its renderer is a module a browser can load. Until the
  // cutover this process still draws it, handing the renderer the view passed
  // THROUGH JSON, so it is held to what the API's caller receives.
  body(json) {
    const { log } = this.deps;
    log.debug("Entering DebuggerAdmin.body().");
    const drawn = DebuggerPage.render(JSON.parse(JSON.stringify(json)));
    log.debug("Leaving DebuggerAdmin.body().");
    return drawn;
  }

  // THE ROUTES, registered where they always were: the composition root
  // (`common/protocol_stack.ts`) calls this through the export below, at
  // the point where requiring this module used to register them, so the
  // route order is unchanged (rule 1; #50, R1).
  /**
   * Registers `GET /admin/debugger` on the app.
   *
   * A view that throws is drawn as a warning and marked STS-DBG-0023.
   * @param app - the shared express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, errorCodes, admin } = this.deps;
    const self = this;
    log.debug("Entering DebuggerAdmin.registerRoutes().");
    log.debug("Leaving DebuggerAdmin.registerRoutes().");
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DebuggerAdmin>(
  'debugger/debugger_admin',
  () => new DebuggerAdmin(DebuggerAdmin.defaultDeps()),
  null,
  helpers.log);

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * Server configuration > Protocol debugger: the `/admin/debugger` page.
 *
 * The functions forward to the DebuggerAdmin instance the composition root
 * installs; `registerRoutes` is called by `common/protocol_stack.ts`.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  DebuggerAdmin: DebuggerAdmin,
  /** Installs the instance the composition root built. */
  installInstance: (instance: DebuggerAdmin): void => slot.install(instance),
  /** Says where the installed instance came from. */
  instanceOrigin: (): string => slot.origin(),
  // For `mgmt-api/admin_api.ts` — rule 7, one function behind both.
  debuggerView: slot.forward('debuggerView')
};
