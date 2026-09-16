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
// (`DebuggerAdminDeps`), and the module still exports its old names from a
// TRANSITIONAL instance built from the real modules, for the callers that
// are not converted. `DebuggerAdmin` is exported beside them for the
// composition root.
//
// **THE ROUTES ARE REGISTERED BY `registerRoutes()`**, which the module
// exports from the transitional instance and `common/protocol_stack.ts`
// calls at 18e, the point in the route order where requiring this module
// used to register them (#50, R1), so the order is unchanged. Requiring the
// module registers nothing.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import admin = require('../admin-ui/admin');
import helpers = require('../common/helpers');
const { log } = helpers;
import errorCodes = require('../common/error_codes');

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

class DebuggerAdmin {
  constructor(private readonly deps: DebuggerAdminDeps) {
    deps.log.debug("Entering DebuggerAdmin.constructor().");
    deps.log.debug("Leaving DebuggerAdmin.constructor().");
  }

  // The JSON the page and the operation both answer.
  debuggerView() {
    const { log, loadDebuggerServer, admin } = this.deps;
    log.debug("Entering DebuggerAdmin.debuggerView().");
    // THE LAZY REQUIRE — see the header.
    const status = loadDebuggerServer().status();
    status.settings = admin.configSettingsJson(PAGE_PATH);
    log.debug("Leaving DebuggerAdmin.debuggerView().");
    return status;
  }

  row(label, value) {
    const { log, admin } = this.deps;
    log.debug("Entering DebuggerAdmin.row().");
    log.debug("Leaving DebuggerAdmin.row().");
    return '<tr><th>' + admin.esc(label) + '</th><td>' + value + '</td></tr>';
  }

  code(text) {
    const { log, admin } = this.deps;
    log.debug("Entering DebuggerAdmin.code().");
    log.debug("Leaving DebuggerAdmin.code().");
    return text === null || text === undefined || text === ''
      ? '<span class="muted">none</span>'
      : '<code>' + admin.esc(String(text)) + '</code>';
  }

  body(json) {
    const { log, admin } = this.deps;
    log.debug("Entering DebuggerAdmin.body().");
    const api = json.api || {};
    const origin = json.publicBaseUrl ||
                   (json.scheme + '://&lt;this host&gt;:' + json.port);
    const tiles = '<div class="tiles">' +
      admin.tile(json.embedded ? 'embedded' : 'off', 'debugger') +
      admin.tile(json.listening ? String(json.port) : 'not bound', 'listener') +
      admin.tile(String(api.state || 'stopped'), 'api process') +
      admin.tile(api.allowList ? String((api.allowedRanges || []).length)
                               : 'none', 'allow-listed ranges') +
      '</div>';
    const what = admin.note(
      'The identity protocol debugger, served by this process on a listener ' +
      'of its own so that its pages — which carry inline scripts and render ' +
      'tokens from any identity provider — are on an origin other than this ' +
      'console\'s. Its user interface is static files; its api runs as a ' +
      'child process on a unix socket, forwarded at <code>/api</code>. It is ' +
      'signed in to through this service\'s authorization server as ' +
      this.code(json.clientId) + ', and every request needs an access token ' +
      'addressed to ' + this.code(json.audience) + ' carrying ' +
      this.code(json.permission) +
      ' — which the authorization server issues to members of the two groups ' +
      'on <a href="/admin/rbac">Admin roles</a> and leaves off for anybody ' +
      'else. <strong>No setting below opens it.</strong>');
    const problems = [json.startProblem, json.listenError, api.lastError]
      .filter(Boolean);
    const warning = !json.embedded ? '' : (problems.length
      ? admin.warn(problems.map(admin.esc).join('<br>'), 'Not running')
      : '');
    const listener = '<h2>Listener</h2><table class="kv">' +
      this.row('Embedded', this.code(json.embedded ? 'yes' : 'no') + ' — ' +
               'debugger.enabled is ' + this.code(json.setting) + ' in ' +
               this.code(json.mode) + ' mode') +
      this.row('Port', this.code(json.port) + (json.listening ? ' (bound)' :
                                                ' (not bound)')) +
      this.row('Origin', json.listening
        ? '<code>' + origin + '</code>'
        : '<span class="muted">not serving</span>') +
      this.row('Static site', this.code(json.uiDirectory)) +
      this.row('Client', this.code(json.clientId)) +
      this.row('Resource server', this.code(json.resource)) +
      this.row('Permission', this.code(json.permission)) +
      '</table>';
    const process = '<h2>Api process</h2><table class="kv">' +
      this.row('State', this.code(api.state)) +
      this.row('Process id', this.code(api.pid)) +
      this.row('Socket', this.code(api.socket)) +
      this.row('Tree', this.code(api.apiDirectory)) +
      this.row('Starts', this.code(api.starts)) +
      this.row('Failures in a row', this.code(api.consecutiveFailures)) +
      this.row('Listening since', this.code(api.listeningAt)) +
      this.row('Last exit', api.lastExit
        ? this.code((api.lastExit.signal ? 'signal ' + api.lastExit.signal
                                         : 'code ' + api.lastExit.code) +
                    ' at ' + api.lastExit.at + ' after ' +
                    api.lastExit.upSeconds + 's')
        : this.code('')) +
      this.row('May dial', api.allowList
        ? (api.allowedRanges || []).map(this.code.bind(this)).join(' ') +
               ((api.allowListProblems || []).length
                 ? '<br>' + admin.warn('Left out, not ranges: ' +
                                       api.allowListProblems.map(admin.esc)
                                         .join(', '),
                                         'debugger.allowedDestinations')
                 : '')
        : 'anything, private networks included — development mode passes the ' +
               'api no allow-list') +
      '</table>';
    log.debug("Leaving DebuggerAdmin.body().");
    return tiles + what + warning + listener + process +
           '<h2>Settings</h2>' + admin.configFormsFor(PAGE_PATH);
  }

  // THE ROUTES, registered where they always were: the composition root
  // (`common/protocol_stack.ts`) calls this through the export below, at
  // the point where requiring this module used to register them, so the
  // route order is unchanged (rule 1; #50, R1).
  registerRoutes(app: RouteApp): void {
    const { log, errorCodes, admin } = this.deps;
    const self = this;
    log.debug("Entering DebuggerAdmin.registerRoutes().");
    app.get(PAGE_PATH, function (req, res) {
      log.debug("Entering GET " + PAGE_PATH + ".");
      let json = null;
      try {
        json = self.debuggerView();
      } catch (e) {
        log.error(errorCodes.tag('STS-DBG-0023') + 'debugger_admin: the page ' +
                  'threw: ' + ((e && e.stack) || e));
        errorCodes.mark(res, 'STS-DBG-0023');
        admin.respond(req, res,
                      { ok: false, error: String((e && e.message) || e) },
                      'Protocol debugger', PAGE_PATH,
                      admin.warn(admin.esc(String((e && e.message) || e)),
                                 'This page could not be drawn'));
        log.debug("Leaving GET " + PAGE_PATH + ". It threw.");
        return;
      }
      admin.respond(req, res, json, 'Protocol debugger', PAGE_PATH,
                    self.body(json));
      log.debug("Leaving GET " + PAGE_PATH + ".");
    });
    log.debug("Leaving DebuggerAdmin.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE (#50): built from the real modules, as the
// composition root will build one, and the source of every name this
// module exports. It goes when that root builds the modules as well as
// registering their routes (#50's R2).
const debuggerAdmin = new DebuggerAdmin({
  admin: admin,
  log: log,
  errorCodes: errorCodes,
  loadDebuggerServer: function () {
    return require('./debugger_server');
  }
});

// ROUTES ARE REGISTERED BY THE COMPOSITION ROOT (#50, R1): requiring this
// module no longer registers anything. `common/protocol_stack.ts` calls the
// exported `registerRoutes(app)` at the point in the route order where
// requiring this module used to register them.

export = {
  registerRoutes: (target: any): void => debuggerAdmin.registerRoutes(target),
  DebuggerAdmin: DebuggerAdmin,
  // For `mgmt-api/admin_api.ts` — rule 7, one function behind both.
  debuggerView: debuggerAdmin.debuggerView.bind(debuggerAdmin) as
    DebuggerAdmin['debuggerView']
};
