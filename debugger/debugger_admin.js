// @ts-check
'use strict';
//
// File: debugger_admin.js
//
// ===========================================================================
// SERVER CONFIGURATION > PROTOCOL DEBUGGER: `/admin/debugger` (2026-09-13).
//
// One page, and `GET /admin-api/debugger` answers from the same function
// (rule 7). It reports what `debugger/debugger_server.js` did at startup —
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
// `common/protocol_stack.js` requires it beside the other report pages at 18,
// and `mgmt-api/admin_api.js` at 19 requires it in the ordinary direction for
// the view. It must not require `debugger_server.js` at the top: that module
// requires `tls/tls_server.js`, which registers `/tls` routes and is at 20, so
// the require would drag those ahead of the management API's (rule 1). The
// status is read inside the view instead, when every module is loaded — the
// arrangement `common/oidc_rp.js` makes with the same module.
//
// The page and the operation are pinned to the front process
// (`common/request_pool.js`'s NEVER_DISPATCHED): only it holds the listener
// and the child.
// ===========================================================================

const app = require('../common/app');
const admin = require('../admin-ui/admin');
const { log } = require('../common/helpers');
const errorCodes = require('../common/error_codes');

const PAGE_PATH = '/admin/debugger';

// The JSON the page and the operation both answer.
function debuggerView() {
  log.debug("Entering debuggerView().");
  // THE LAZY REQUIRE — see the header.
  const status = require('./debugger_server').status();
  status.settings = admin.configSettingsJson(PAGE_PATH);
  log.debug("Leaving debuggerView().");
  return status;
}

function row(label, value) {
  log.debug("Entering row().");
  log.debug("Leaving row().");
  return '<tr><th>' + admin.esc(label) + '</th><td>' + value + '</td></tr>';
}

function code(text) {
  log.debug("Entering code().");
  log.debug("Leaving code().");
  return text === null || text === undefined || text === ''
    ? '<span class="muted">none</span>'
    : '<code>' + admin.esc(String(text)) + '</code>';
}

function body(json) {
  log.debug("Entering body().");
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
    code(json.clientId) + ', and every request needs an access token ' +
    'addressed to ' + code(json.audience) + ' carrying ' +
    code(json.permission) + ' — which the authorization server issues to ' +
    'members of the two groups on <a href="/admin/rbac">Admin roles</a> and ' +
    'leaves off for anybody else. <strong>No setting below opens ' +
    'it.</strong>');
  const problems = [json.startProblem, json.listenError, api.lastError]
    .filter(Boolean);
  const warning = !json.embedded ? '' : (problems.length
    ? admin.warn(problems.map(admin.esc).join('<br>'), 'Not running')
    : '');
  const listener = '<h2>Listener</h2><table class="kv">' +
    row('Embedded', code(json.embedded ? 'yes' : 'no') + ' — ' +
        'debugger.enabled is ' + code(json.setting) + ' in ' +
        code(json.mode) + ' mode') +
    row('Port', code(json.port) + (json.listening ? ' (bound)' :
                                    ' (not bound)')) +
    row('Origin', json.listening
      ? '<code>' + origin + '</code>'
      : '<span class="muted">not serving</span>') +
    row('Static site', code(json.uiDirectory)) +
    row('Client', code(json.clientId)) +
    row('Resource server', code(json.resource)) +
    row('Permission', code(json.permission)) +
    '</table>';
  const process = '<h2>Api process</h2><table class="kv">' +
    row('State', code(api.state)) +
    row('Process id', code(api.pid)) +
    row('Socket', code(api.socket)) +
    row('Tree', code(api.apiDirectory)) +
    row('Starts', code(api.starts)) +
    row('Failures in a row', code(api.consecutiveFailures)) +
    row('Listening since', code(api.listeningAt)) +
    row('Last exit', api.lastExit
      ? code((api.lastExit.signal ? 'signal ' + api.lastExit.signal
                                  : 'code ' + api.lastExit.code) +
             ' at ' + api.lastExit.at + ' after ' +
             api.lastExit.upSeconds + 's')
      : code('')) +
    row('May dial', api.allowList
      ? (api.allowedRanges || []).map(code).join(' ') +
        ((api.allowListProblems || []).length
          ? '<br>' + admin.warn('Left out, not ranges: ' +
                                api.allowListProblems.map(admin.esc)
                                  .join(', '), 'debugger.allowedDestinations')
          : '')
      : 'anything, private networks included — development mode passes the ' +
        'api no allow-list') +
    '</table>';
  log.debug("Leaving body().");
  return tiles + what + warning + listener + process +
         '<h2>Settings</h2>' + admin.configFormsFor(PAGE_PATH);
}

app.get(PAGE_PATH, function (req, res) {
  log.debug("Entering GET " + PAGE_PATH + ".");
  let json = null;
  try {
    json = debuggerView();
  } catch (e) {
    log.error(errorCodes.tag('STS-DBG-0023') + 'debugger_admin: the page ' +
              'threw: ' + ((e && e.stack) || e));
    errorCodes.mark(res, 'STS-DBG-0023');
    admin.respond(req, res, { ok: false, error: String((e && e.message) || e) },
                  'Protocol debugger', PAGE_PATH,
                  admin.warn(admin.esc(String((e && e.message) || e)),
                             'This page could not be drawn'));
    log.debug("Leaving GET " + PAGE_PATH + ". It threw.");
    return;
  }
  admin.respond(req, res, json, 'Protocol debugger', PAGE_PATH, body(json));
  log.debug("Leaving GET " + PAGE_PATH + ".");
});

module.exports = {
  // For `mgmt-api/admin_api.js` — rule 7, one function behind both.
  debuggerView: debuggerView
};
