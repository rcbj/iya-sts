'use strict';
//
// File: grant_management_admin.ts
//
// ---------------------------------------------------------------------------
// `/admin/grants` (#142, 2026-09-24): the OAuth grants this realm holds —
// Grant Management for OAuth 2.0's register, which `grant_management.ts`
// keeps — with a Revoke button on each.
//
// **FILED BESIDE CONSENT, AND THE PAIR IS THE ARGUMENT.** Consent is what a
// PERSON agreed an application may ask for; a grant is what a CLIENT holds
// on the strength of it, named, and able to ask for more (merge) or start
// again (replace). Two registers answering the two halves of one question.
//
// Every fact comes out of `grant_management.list()`, the call
// `GET /admin-api/grants` answers with, and the one control is
// `grant_management.act()`, which `POST /admin-api/grants/revoke-grant`
// takes too (rule 7). No script: Revoke is a POST form the console gate
// checks CSRF and Admin Write on before this handler runs.
//
// **REQUIRED AT 18m**, from `common/protocol_stack.ts`, for 18a's reason: it
// requires `admin-ui/admin` for the shell, which `grant_management.ts` at 9
// could not require without loading the console ahead of the authorization
// server.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import grantManagement = require('./grant_management');

type Json = any;

const esc = admin.esc;
const PAGE = '/admin/grants';

interface GrantManagementAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  grants: typeof grantManagement;
  // The console's gate state, for who acted (`admin-core/admin_views`),
  // lazily: it requires route modules.
  adminViews: () => Json;
}

class GrantManagementAdmin {
  constructor(private readonly deps: GrantManagementAdminDeps) {
    deps.log.debug("Entering GrantManagementAdmin.constructor().");
    deps.log.debug("Leaving GrantManagementAdmin.constructor().");
  }

  static defaultDeps(): GrantManagementAdminDeps {
    helpers.log.debug("Entering GrantManagementAdmin.defaultDeps().");
    helpers.log.debug("Leaving GrantManagementAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody, errorCodes: errorCodes,
      admin: admin, grants: grantManagement,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  // Who is acting, for the audit row: the console's signed-in operator.
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering GrantManagementAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in GrantManagementAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving GrantManagementAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // The page body for `json`, the view `GET /admin-api/grants` answers.
  body(json: Json): string {
    const { log, admin } = this.deps;
    log.debug("Entering GrantManagementAdmin.body().");
    const when = function (sec: Json): string {
      log.debug("Entering when().");
      log.debug("Leaving when().");
      return Number(sec) > 0 ? new Date(Number(sec) * 1000).toISOString()
                             : '—';
    };
    const rows = json.grants.length ? json.grants.map(function (g: Json) {
      const scopes = (g.scopes || []).map(function (s: Json): string {
        return '<code>' + esc(s.scope || '') + '</code>' +
          (s.resource ? ' for ' + esc(s.resource.join(', ')) : '');
      }).join('<br>');
      return '<tr><td><code>' + esc(g.grantId) + '</code></td><td><code>' +
        esc(g.clientId) + '</code></td><td><code>' + esc(g.subject) +
        '</code></td><td>' + scopes +
        (g.authorization_details ? '<br><span class="sub">' +
          esc(String(g.authorization_details.length)) +
          ' authorization detail(s)</span>' : '') +
        (g.claims ? '<br><span class="sub">claims ' +
          esc(g.claims.join(', ')) + '</span>' : '') + '</td><td>' +
        esc(String(g.generation)) + '</td><td>' + esc(when(g.created_at)) +
        '<br>' + esc(when(g.last_updated)) + '</td><td>' +
        esc(when(g.expires_at)) + '</td><td>' + esc(String(g.tokens)) +
        '</td><td><form method="post" action="' + PAGE + '" ' +
        'class="inline"><input type="hidden" name="action" ' +
        'value="revoke-grant"><input type="hidden" name="grantId" value="' +
        esc(g.grantId) + '"> <button type="submit" class="danger">Revoke' +
        '</button></form></td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">No client holds a grant ' +
      'in this realm. A grant is made by an authorization request carrying ' +
      '<code>grant_management_action=create</code>.</td></tr>';
    log.debug("Leaving GrantManagementAdmin.body().");
    return admin.note('<strong>Grant Management for OAuth 2.0.</strong> A ' +
        'confidential client names what a person let it do — creating a ' +
        'grant, merging more into one or replacing it through ordinary ' +
        'authorization requests — and reads or revokes it at ' +
        '<code>/oauth2/grants/{grant_id}</code> with the ' +
        '<code>grant_management_query</code> and ' +
        '<code>grant_management_revoke</code> scopes. A grant exists once ' +
        'its tokens are claimed, and expires with the last of them. ' +
        'Revoking one here is what a client\'s DELETE does: every refresh ' +
        'token under it is refused on every node, and every token this ' +
        'realm recorded under it is revoked. What the person AGREED to is ' +
        '<a href="/admin/consent">Consent</a>.') +
      '<table><thead><tr><th>grant_id</th><th>Client</th><th>Subject</th>' +
      '<th>Scopes</th><th>Generation</th><th>Created / updated</th>' +
      '<th>Expires</th><th>Tokens held</th><th></th></tr></thead><tbody>' +
      rows + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/grants</code></p>';
  }

  registerRoutes(app: Json): void {
    const { log, parseBody, admin, grants, errorCodes } = this.deps;
    const self = this;
    log.debug("Entering GrantManagementAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin grants page.");
      const json = { grants: grants.list(String((req.query || {}).client_id ||
                                                '').slice(0, 256) ||
                                         undefined) };
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.body(json);
      admin.respond(req, res, json, 'Grants', PAGE, inner);
      log.debug("Leaving the admin grants page.");
    });
    app.post(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin grants action.");
      let result: Json = null;
      try {
        result = grants.act(parseBody(req), { via: 'console',
                                              actor: self.actorOf(req) });
      } catch (e: any) {
        log.error(errorCodes.tag('STS-OAUTH-0674') + 'oauth2: a console ' +
                  'grants action failed: ' + ((e && e.stack) || e));
        result = errorCodes.mark({ ok: false, errors:
                                     ['The action could not be completed.'] },
                                 'STS-OAUTH-0674');
      }
      admin.respondToAction(req, res, PAGE, result);
      log.debug("Leaving the admin grants action.");
    });
    log.debug("Leaving GrantManagementAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<GrantManagementAdmin>(
  'oauth-oidc/grant_management_admin',
  () => new GrantManagementAdmin(GrantManagementAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  GrantManagementAdmin: GrantManagementAdmin,
  installInstance: (instance: GrantManagementAdmin): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin()
};
