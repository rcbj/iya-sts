'use strict';
//
// File: gnap_admin.ts
//
// ---------------------------------------------------------------------------
// THE TWO GNAP CONSOLE PAGES: Protocols -> GNAP and Monitoring -> GNAP grants.
//
// Drawn here, in the console's shell through `admin.respond()`, the way
// `xacml/xacml_admin.js` draws XACML's — a console page is a `path` and a
// `label` in `admin-ui/admin.js`'s `SECTIONS` whoever builds the body. Every
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
// console shell, the view model and the rest through its constructor, and
// its `registerRoutes(app)` holds the three routes in their old order. The
// TRANSITIONAL instance below is built from the real modules and registers
// them at load, exactly where the file registered them before; the module
// still exports an empty object beside the class.
// ---------------------------------------------------------------------------

import app = require('../common/app');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import admin = require('../admin-ui/admin');
import consoleModel = require('./gnap_console');

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
  csrf_token: vt.opt(vt.token)
});

class GnapAdmin {
  constructor(private readonly deps: GnapAdminDeps) {
    deps.log.debug("Entering GnapAdmin.constructor().");
    deps.log.debug("Leaving GnapAdmin.constructor().");
  }

  private when(seconds: number): string {
    const { log } = this.deps;
    log.debug("Entering GnapAdmin.when().");
    log.debug("Leaving GnapAdmin.when().");
    return seconds ?
           new Date(seconds * 1000).toISOString()
                                   .replace('T', ' ')
                                   .replace(/\.\d+Z$/, 'Z') : '—';
  }

  private list(values: unknown[] | null | undefined): string {
    const { log, admin } = this.deps;
    const esc = admin.esc;
    log.debug("Entering GnapAdmin.list().");
    log.debug("Leaving GnapAdmin.list().");
    return (values || []).length ? (values || []).map(function (one) {
      return '<code>' + esc(one) + '</code>';
    }).join(' ') : '<span class="sub">none</span>';
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

  // The three routes, in the order this file has always registered them.
  registerRoutes(app: RouteTable): void {
    const self = this;
    const { log, parseBody, errorCodes, validation, admin,
            consoleModel } = this.deps;
    const esc = admin.esc;
    const list = function (values) {
      return self.list(values);
    };
    const when = function (seconds) {
      return self.when(seconds);
    };
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
      const endpointRows = Object.keys(json.endpoints).map(function (name) {
        return '<tr><th>' + esc(name) + '</th><td><code>' +
               esc(json.endpoints[name]) + '</code></td></tr>';
      }).join('');
      const capabilityRows = json.authorizationServers.length
        ? json.authorizationServers.map(function (profile) {
          const caps = profile.capabilities;
          return '<tr><td><code>' + esc(profile.id) + '</code></td>' +
            '<td><code>' + esc(caps.grant_request_endpoint) +
            '</code></td>' +
            '<td>' + list(caps.interaction_start_modes_supported) + '</td>' +
            '<td>' + list(caps.interaction_finish_methods_supported) +
            '</td>' +
            '<td>' + list(caps.key_proofs_supported) + '</td>' +
            '<td>' + list(caps.token_formats_supported) + '</td>' +
            '<td>' +
            (caps.key_rotation_supported === undefined ? '—' :
             esc(caps.key_rotation_supported)) + '</td></tr>';
        }).join('')
        : '<tr><td colspan="7" class="sub">No named authorization server ' +
          'exists in this realm yet; the default one answers at ' +
          '<code>' + esc(json.endpoints.grant) + '</code>.</td></tr>';
      const stateLinks = ['all'].concat(json.grants.states)
        .map(function (state) {
          const on = (state === 'all' &&
                      !json.grants.state) || state === json.grants.state;
          return on ? '<strong>' + esc(state) + '</strong>'
                    : '<a href="/admin/gnap' +
                      (state === 'all' ? '' : '?state=' + esc(state)) +
                      '#list-grantsPage">' +
                      esc(state) + '</a>';
        }).join(' · ');
      const grantNav = admin.pageNavPair('/admin/gnap', req.query,
                                         Object.assign({},
                                                       json.grants.paging,
                                                       { param:
                                                           'grantsPage' }));
      const grantRows = json.grants.rows.length ?
                        json.grants.rows.map(function (grant) {
        const control = grant.state === 'finalized' ? '<span ' +
          'class="sub">finalized</span>'
          : '<form method="post" action="/admin/gnap"><input type="hidden" ' +
            'name="action" value="revoke-grant"><input type="hidden" ' +
            'name="grant" value="' + esc(grant.id) + '">' +
            '<button type="submit" class="danger">Revoke</button></form>';
        return '<tr><td><code>' + esc(grant.id) + '</code></td><td>' +
          esc(grant.state) + '</td><td><a ' +
          'href="/admin/applications?application=' + encodeURIComponent(
              grant.client || '') + '"><code>' +
          esc(grant.client) + '</code></a><div class="sub">' + esc(
              grant.proof) + '</div></td><td>' +
          (grant.resourceOwner ?
           '<code>' + esc(grant.resourceOwner) + '</code>' :
           '<span ' +
              'class="sub">none</span>') + '</td><td><code>' + esc(
                  grant.authorizationServer) + '</code></td><td>' +
          (grant.interaction ? list(grant.interaction.modes) +
            (grant.interaction.finish ?
             '<div class="sub">finish: ' + esc(grant.interaction.finish) +
             '</div>' : '')
            : '<span class="sub">none</span>') + '</td>' +
          '<td class="num">' + grant.tokens + '</td><td>' + esc(
              when(grant.updatedAt)) + '</td><td>' + control + '</td></tr>';
      }).join('') : '<tr><td colspan="9" class="sub">No grants' +
                    (json.grants.state ? ' ' +
          'in the ' +
        esc(json.grants.state) + ' state' : '') + ' in this realm.</td></tr>';
      const resourceNav = admin.pageNavPair('/admin/gnap', req.query,
                                            Object.assign(
                                                {},
                                                json.resourceSets.paging,
                                                {
        param: 'resourcesPage' }));
      const resourceRows = json.resourceSets.rows.length ?
                           json.resourceSets.rows.map(function (row) {
        return '<tr><td><code>' + esc(row.reference) +
          '</code></td><td><code>' +
          esc(row.resourceServer) +
          '</code></td><td><code>' + esc(JSON.stringify(
              row.access)) + '</code></td><td>' +
          list(row.tokenFormats) + '</td><td>' +
          (row.introspectionRequired ? 'yes' : 'no') + '</td><td>' +
          esc(when(row.createdAt)) + '</td><td><form method="post" ' +
          'action="/admin/gnap"><input type="hidden" name="action" ' +
          'value="delete-resource-set"><input type="hidden" ' +
          'name="reference" ' +
          'value="' + esc(row.reference) + '"><button ' +
          'type="submit" class="danger">Delete</button></form></td></tr>';
      }).join('') : '<tr><td colspan="7" class="sub">No resource server ' +
        'has registered a resource set in this realm (RFC 9767 section ' +
        '3.4).</td></tr>';
      const material = json.verificationMaterial;
      const caps = json.capabilities;
      const inner = (typeof admin.messagesOf === 'function' ?
                     admin.messagesOf(req) : '') +
        admin.note('<strong>GNAP (RFC 9635) and its resource server ' +
          'connections ' +
          '(RFC 9767), one authorization server per trust realm.</strong> A ' +
          'client instance proves a key at the grant endpoint, a resource ' +
          'owner ' +
          'approves in a browser through the one sign-in screen, and the ' +
          'tokens ' +
          'are released at the continuation URI in any of the five RFC 9767 ' +
          'formats. ' +
          (json.enabled ? '' :
           '<strong>GNAP is turned off in this realm.</strong>')) +
        admin.warn('<strong>A key proof is verified in every mode.</strong> ' +
          'An ' +
          'unsigned or wrongly signed request is refused whatever ' +
          '<code>global.mode</code> says, because a token bound to a key ' +
          'nobody ' +
          'proved holding is bound to nothing. What is mode-gated is what ' +
          'happens to a proved key this service has never seen (development ' +
          'makes an application entry for it; product refuses it) and to an ' +
          'unregistered finish URI.') +
        '<h2>Endpoints</h2><table class="kv">' + endpointRows +
        '</table><h2>Authorization ' +
        'servers</h2><p class="sub">Each named authorization server is also ' +
        'a ' +
        'GNAP authorization server at <code>/{id}/gnap</code>. Its ' +
        'discovery ' +
        'members are overridden or removed on <a ' +
        'href="/admin/authorization-servers">Authorization servers</a>, and ' +
        'what ' +
        'it publishes is what its grant endpoint ' +
        'enforces.</p><table><thead><tr><th>Server</th><th>Grant ' +
        'endpoint</th><th>Start modes</th><th>Finish</th><th>Key ' +
        'proofs</th><th>Token formats</th><th>Key rotation</th></tr>' +
        '</thead>' +
        '<tbody><tr><td><code>default</code></td><td>' +
        '<code>' + esc(caps.grant_request_endpoint) +
        '</code></td><td>' + list(caps.interaction_start_modes_supported) +
        '</td><td>' +
        list(caps.interaction_finish_methods_supported) + '</td><td>' +
        list(caps.key_proofs_supported) + '</td><td>' +
        list(caps.token_formats_supported) + '</td><td>' +
        esc(caps.key_rotation_supported) + '</td></tr>' + capabilityRows +
        '</tbody></table><h2>Token ' +
        'formats</h2><table class="kv"><tr><th>jwt-signed</th><td>RS256, ' +
        'verified against <code>' +
        esc(material ? material.jwt.jwks_uri : '') +
        '</code></td></tr><tr><th>jwt-encrypted</th><td>Nested in a JWE: to ' +
        'the ' +
        'resource server\'s <code>gnapJweKey</code>, or to this ' +
        'authorization ' +
        'server (introspect it)</td></tr><tr><th>macaroon</th><td>' +
        'HMAC-SHA256 ' +
        'under a root key per resource server, carried sealed as ' +
        '<code>gnapMacaroonKey</code> on its ' +
        'entry</td></tr><tr><th>biscuit</th><td>Ed25519 root key ' +
        '<code>' + esc(material ? material.biscuit.root_public_key : '') +
        '</code></td></tr>' +
        '<tr><th>zcap</th><td>Ed25519Signature2020 delegation from <code>' +
        esc(material ? material.zcap.controller :
            '') + '</code></td></tr></table><h2 ' +
        'id="list-grantsPage">Grants</h2><p ' +
        'class="sub">' + stateLinks + ' — ' + json.grants.paging.total +
        ' grant(s)</p>' + grantNav.head +
        '<table><thead><tr><th>Grant</th><th>State</th><th>Client</th><th>' +
        'Resource owner</th><th>Server</th><th>Interaction</th>' +
        '<th>Tokens</th>' +
        '<th>Updated</th><th></th></tr></thead><tbody>' + grantRows +
        '</tbody></table>' + grantNav.foot +
        '<h2 id="list-resourcesPage">Registered resource sets</h2>' +
        resourceNav.head +
        '<table><thead><tr><th>Reference</th><th>Resource server</th><th>' +
        'Access</th><th>Formats</th><th>Introspection</th>' +
        '<th>Registered</th><th>' +
        '</th></tr></thead><tbody>' + resourceRows +
        '</tbody></table>' + resourceNav.foot +
        '<h2>Settings</h2>' + admin.configFormsFor('/admin/gnap') +
        '<p class="links"><a href="/admin/gnap?format=json">JSON</a> · ' +
        '<code>GET ' +
        '/admin-api/gnap</code> · <a href="/admin/gnap/monitor">GNAP grants ' +
        '(monitoring)</a> · <a href="/admin/applications/new">New ' +
        'application</a> · <a href="/admin/error-codes">Error codes</a></p>';
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
      admin.respondToAction(req, res, '/admin/gnap', result);
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
      const t = json.totals;
      const tiles = '<div class="tiles">' +
        admin.tile(json.applications, 'applications') +
        admin.tile(t.grants, 'grant requests') +
        admin.tile(t.approved, 'approved') +
        admin.tile(t.denied, 'denied') +
        admin.tile(t.tokens, 'tokens issued') +
        admin.tile(t.rotations + t.keyRotations, 'rotations') +
        admin.tile(t.tokenRevocations + t.revoked, 'revocations') +
        admin.tile(t.proofFailures, 'failed proofs') +
        admin.tile(t.introspections, 'introspections') +
        '</div>';
      const formatRow = Object.keys(json.tokensByFormat)
        .map(function (format) {
          return '<td class="num">' + json.tokensByFormat[format] + '</td>';
        }).join('');
      const nav = admin.pageNavPair('/admin/gnap/monitor', req.query,
                                    json.paging);
      const rows = json.rows.length ? json.rows.map(function (row) {
        const c = row.counters;
        const formats = Object.keys(c.formats || {})
                              .filter(function (f) {
                                return c.formats[f];
                              })
                              .map(function (f) {
          return esc(f) + ' ' + c.formats[f];
        }).join(', ');
        const errors = Object.keys(c.errors || {}).map(function (code) {
          return '<code>' + esc(code) + '</code> ' + c.errors[code];
        }).join(', ');
        return '<tr><td><a href="/admin/applications?application=' +
          encodeURIComponent(row.identifier) +
          '"><code>' + esc(row.identifier) + '</code></a>' +
          (row.name ? '<div ' +
              'class="sub">' + esc(row.name) +
          '</div>' : '') + '</td><td>' + esc(row.role) +
          (row.webApplication ?
           '<div ' +
              'class="sub">web</div>' : '') +
          '</td><td class="num">' + row.grantsHeld.pending + ' / ' +
          row.grantsHeld.approved + ' ' +
              '/ ' +
          row.grantsHeld.finalized + '</td><td class="num">' +
          row.activeTokens +
          '</td><td ' +
          'class="num">' + c.grants + '</td><td class="num">' + c.approved +
          '</td><td ' +
              'class="num">' + c.denied +
          '</td><td class="num">' + c.tokens + '<div class="sub">' +
          (formats ||
              '—') + '</div></td><td ' +
          'class="num">' + (c.rotations + c.keyRotations) + '</td><td ' +
              'class="num">' +
          (c.tokenRevocations +
           c.revoked) + '</td><td class="num">' + c.proofFailures +
          '</td><td ' +
          'class="num">' + c.introspections + ' / ' + c.registrations +
          ' / ' +
          c.derivations + '</td><td>' + (errors || '<span ' +
              'class="sub">none</span>') + '</td><td>' + esc(
                  row.lastAt || '—') + '<div ' +
                  'class="sub">' + esc(row.lastEvent || '') +
                  '</div></td></tr>';
      }).join('') : '<tr><td colspan="14" class="sub">No application in ' +
                    'this realm uses GNAP yet.</td></tr>';
      const inner = (typeof admin.messagesOf === 'function' ?
                     admin.messagesOf(req) : '') +
        admin.note('<strong>What the applications using GNAP have ' +
                   'done</strong>, ' +
                   'counted since ' +
          esc(json.since) + ' in this trust realm. An application is listed ' +
          'when ' +
          'it is declared for GNAP, when it has spoken it, or both — so an ' +
          'entry ' +
          'provisioned and never used shows here as idle.') +
        tiles +
        '<h2>Tokens by format</h2><table><thead><tr>' + Object.keys(
            json.tokensByFormat).map(function (f) {
          return '<th>' + esc(f) + '</th>';
        }).join('') + '</tr></thead><tbody><tr>' + formatRow +
        '</tr></tbody></table><h2 ' +
        'id="list-page">Applications</h2>' + nav.head +
        '<table><thead><tr><th>Application</th><th>Role</th><th>Grants ' +
        'held<div ' +
        'class="sub">pending / approved / finalized</div></th><th>Live ' +
        'tokens</th><th>Requested</th><th>Approved</th><th>Denied</th>' +
        '<th>Tokens ' +
        'issued</th><th>Rotations</th><th>Revocations</th><th>Failed ' +
        'proofs</th><th>RS calls<div class="sub">introspect / register / ' +
        'derive</div></th><th>Errors returned</th><th>Last ' +
        'activity</th></tr></thead><tbody>' + rows + '</tbody></table>' +
        nav.foot +
        admin.note('There is no reset. The counters start with the process ' +
          'and ' +
          'are per realm; the durable record of each act is the <a ' +
          'href="/admin/audit">Audit log</a>.') +
        '<p class="links"><a href="/admin/gnap/monitor?format=json">JSON</a> ' +
        '· ' +
        '<code>GET /admin-api/gnap/monitor</code> · <a ' +
        'href="/admin/gnap">GNAP ' +
        'settings</a></p>';
      admin.respond(req, res, json, 'GNAP grants', '/admin/gnap/monitor',
                    inner);
      log.debug("Leaving the admin GNAP monitor page.");
    });

    log.debug("Leaving GnapAdmin.registerRoutes().");
  }
}

// THE TRANSITIONAL INSTANCE — see the header above. Built from the real
// modules, and its routes registered at load, where they always were.
const pages = new GnapAdmin({
  log: helpers.log,
  parseBody: helpers.parseBody,
  errorCodes: errorCodes,
  validation: validation,
  admin: admin,
  consoleModel: consoleModel
});
pages.registerRoutes(app);

export = {
  GnapAdmin: GnapAdmin
};
