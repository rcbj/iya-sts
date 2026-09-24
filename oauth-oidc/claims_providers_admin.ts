'use strict';
//
// File: claims_providers_admin.ts
//
// ===========================================================================
// /admin/claim-providers — THE CLAIMS PROVIDER REGISTER ON THE CONSOLE (#147,
// 2026-09-24): every OpenID Provider this realm fetches aggregated or
// distributed claims from, the redirect URI to register at each, and every
// person's link — with add, update, remove and revoke. Its twin is
// `GET|POST /admin-api/claim-providers` (`claims_providers_api.ts`, rule 7);
// both call `claims_providers.ts`'s `view()` and `act()`. Never a client
// secret and never a person's token.
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import admin = require('../admin-ui/admin');
import InstanceSlot = require('../common/instance_slot');
import claimsProviders = require('./claims_providers');

type Json = any;

const esc = admin.esc;
const PAGE = '/admin/claim-providers';

interface ClaimsProvidersAdminDeps {
  log: typeof helpers.log;
  parseBody: typeof helpers.parseBody;
  baseUrlOf: typeof helpers.baseUrlOf;
  errorCodes: typeof errorCodes;
  admin: typeof admin;
  providers: typeof claimsProviders;
  // The console's gate state, for who acted (`admin-core/admin_views`),
  // lazily: it requires route modules.
  adminViews: () => Json;
}

class ClaimsProvidersAdmin {
  constructor(private readonly deps: ClaimsProvidersAdminDeps) {
    deps.log.debug("Entering ClaimsProvidersAdmin.constructor().");
    deps.log.debug("Leaving ClaimsProvidersAdmin.constructor().");
  }

  static defaultDeps(): ClaimsProvidersAdminDeps {
    helpers.log.debug("Entering ClaimsProvidersAdmin.defaultDeps().");
    helpers.log.debug("Leaving ClaimsProvidersAdmin.defaultDeps().");
    return {
      log: helpers.log, parseBody: helpers.parseBody,
      baseUrlOf: helpers.baseUrlOf, errorCodes: errorCodes, admin: admin,
      providers: claimsProviders,
      adminViews: function (): Json {
        return require('../admin-core/admin_views');
      }
    };
  }

  // Who is acting, for the audit row: the console's signed-in operator.
  actorOf(req: Json): string {
    const { log, adminViews } = this.deps;
    log.debug("Entering ClaimsProvidersAdmin.actorOf().");
    let state: Json = null;
    try {
      state = adminViews().gateStateFor(req);
    } catch (e: any) {
      log.debug("Caught in ClaimsProvidersAdmin.actorOf(): " +
                ((e && e.message) || e));
      state = null;
    }
    log.debug("Leaving ClaimsProvidersAdmin.actorOf().");
    return (state && state.username) || '';
  }

  // The page body for `json`, the view `GET /admin-api/claim-providers`
  // answers; `callback` is the redirect URI to register at a provider.
  body(json: Json, callback: string): string {
    const { log, admin } = this.deps;
    log.debug("Entering ClaimsProvidersAdmin.body().");
    const form = function (action: string, fields: Json, label: string,
                           danger: boolean): string {
      return '<form method="post" action="' + PAGE + '" class="inline">' +
        '<input type="hidden" name="action" value="' + action + '">' +
        Object.keys(fields).map(function (k: string): string {
          return '<input type="hidden" name="' + esc(k) + '" value="' +
            esc(fields[k]) + '">';
        }).join('') + ' <button type="submit"' +
        (danger ? ' class="danger"' : '') + '>' + label + '</button></form>';
    };
    const providers = json.providers.length
      ? json.providers.map(function (p: Json): string {
        return '<tr id="claim-provider-' + esc(p.id) + '"><td><code>' +
          esc(p.id) + '</code><br>' + esc(p.name) + '</td><td><code>' +
          esc(p.issuer) + '</code></td><td class="sub">authorize <code>' +
          esc(p.authorizationEndpoint) + '</code><br>token <code>' +
          esc(p.tokenEndpoint) + '</code><br>claims <code>' +
          esc(p.claimsEndpoint) + '</code><br>keys <code>' +
          esc(p.jwksUri) + '</code></td><td><code>' + esc(p.clientId) +
          '</code><br>' + esc(p.authMethod) + (p.hasSecret ? ', secret held'
            : '') + '<br>scope <code>' + esc(p.scope) + '</code></td><td>' +
          p.claims.map(function (c: string): string {
            return '<code>' + esc(c) + '</code>';
          }).join(' ') + '</td><td>' + esc(p.delivery) + '</td><td>' +
          form('remove-provider', { id: p.id }, 'Remove', true) +
          '</td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">No Claims Provider is registered ' +
        'in this realm.</td></tr>';
    const links = json.links.length
      ? json.links.map(function (l: Json): string {
        return '<tr><td><code>' + esc(l.username) + '</code></td><td><code>' +
          esc(l.provider) + '</code></td><td><code>' + esc(l.sub) +
          '</code></td><td>' + esc(new Date(l.linkedAt).toISOString()) +
          '</td><td>' + (l.expiresAt ? esc(new Date(l.expiresAt)
            .toISOString()) : '—') + (l.refreshable ? ', refreshable' : '') +
          (l.stale ? ' <strong>stale</strong>' : '') + '</td><td>' +
          form('revoke-link', { username: l.username, provider: l.provider },
               'Revoke', true) + '</td></tr>';
      }).join('')
      : '<tr><td colspan="6" class="sub">Nobody has linked a Claims ' +
        'Provider. A person links one on <code>/portal/claim-sources</code>.' +
        '</td></tr>';
    const field = function (name: string, label: string, hint: string,
                            type?: string): string {
      return '<label>' + label + ' <input type="' + (type || 'text') +
        '" name="' + name + '" autocomplete="off"></label>' +
        (hint ? ' <span class="sub">' + hint + '</span>' : '') + '<br>';
    };
    const add = '<h3>Register a Claims Provider</h3>' +
      '<form method="post" action="' + PAGE + '" id="claim-provider-add">' +
      '<input type="hidden" name="action" value="add-provider">' +
      field('id', 'Id', 'lower-case letters, digits and hyphens') +
      field('name', 'Name', '') +
      field('issuer', 'Issuer', 'its OpenID Provider issuer') +
      '<label><input type="checkbox" name="discover" value="true" ' +
      'checked> fill the endpoints below that are left empty from its ' +
      'discovery document</label><br>' +
      field('authorizationEndpoint', 'Authorization endpoint', '') +
      field('tokenEndpoint', 'Token endpoint', '') +
      field('claimsEndpoint', 'Claims endpoint', 'its UserInfo endpoint') +
      field('jwksUri', 'JWKS URI', '') +
      field('clientId', 'client_id', 'this realm\'s client at the provider') +
      field('clientSecret', 'Client secret', 'sealed; never shown again',
            'password') +
      '<label>Client authentication <select name="authMethod">' +
      '<option>client_secret_basic</option><option>client_secret_post' +
      '</option><option>none</option></select></label><br>' +
      field('scope', 'Scope', 'default openid') +
      field('claims', 'Claims it supplies', 'space-separated names') +
      '<label>Delivery <select name="delivery"><option>aggregated</option>' +
      '<option>distributed</option></select></label><br>' +
      '<button type="submit">Register</button></form>';
    log.debug("Leaving ClaimsProvidersAdmin.body().");
    return admin.note('<strong>OpenID Connect Claims Aggregation.</strong> ' +
        'A Claims Provider is another OpenID Provider that vouches for ' +
        'claims about a person this realm does not hold. A person links one ' +
        'on the portal; after that a relying party asking for one of its ' +
        'claims gets it as an <em>aggregated</em> claim (the provider\'s ' +
        'signed JWT, verified here first) or a <em>distributed</em> one ' +
        '(its endpoint and the person\'s access token there) — never in ' +
        'place of a value the person\'s own entry holds. Register this ' +
        'realm at the provider as a client whose redirect URI is <code ' +
        'id="claim-provider-callback">' + esc(callback) + '</code> and ' +
        'whose UserInfo responses are signed ' +
        '(<code>userinfo_signed_response_alg</code>). A federation ' +
        'partner\'s claim sources are honoured only from a provider ' +
        'registered here.') +
      '<table><thead><tr><th>Provider</th><th>Issuer</th><th>Endpoints</th>' +
      '<th>Client</th><th>Claims</th><th>Delivery</th><th></th></tr>' +
      '</thead><tbody>' + providers + '</tbody></table>' + add +
      '<h3>Links</h3><table><thead><tr><th>Person</th><th>Provider</th>' +
      '<th>Their sub there</th><th>Linked</th><th>Token</th><th></th></tr>' +
      '</thead><tbody>' + links + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/claim-providers</code></p>';
  }

  registerRoutes(app: Json): void {
    const { log, parseBody, admin, providers, errorCodes,
            baseUrlOf } = this.deps;
    const self = this;
    log.debug("Entering ClaimsProvidersAdmin.registerRoutes().");
    app.get(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin claim providers page.");
      const json = providers.view();
      const callback = baseUrlOf(req) + json.callbackPath;
      const inner = (typeof admin.messagesOf === 'function'
        ? admin.messagesOf(req) : '') + self.body(json, callback);
      admin.respond(req, res, Object.assign({ redirectUri: callback }, json),
                    'Claims Providers', PAGE, inner);
      log.debug("Leaving the admin claim providers page.");
    });
    app.post(PAGE, function (req: Json, res: Json): void {
      log.debug("Entering the admin claim providers action.");
      Promise.resolve().then(function (): Json {
        return providers.act(parseBody(req), { via: 'console',
                                               actor: self.actorOf(req) });
      }).catch(function (e: any): Json {
        log.error(errorCodes.tag('STS-OAUTH-0686') + 'oauth2: a console ' +
                  'Claims Provider action failed: ' + ((e && e.stack) || e));
        return errorCodes.mark({ ok: false, errors:
                                   ['The action could not be completed.'] },
                               'STS-OAUTH-0686');
      }).then(function (result: Json): void {
        admin.respondToAction(req, res, PAGE, result);
        log.debug("Leaving the admin claim providers action.");
      });
    });
    log.debug("Leaving ClaimsProvidersAdmin.registerRoutes().");
  }
}

const slot = new InstanceSlot<ClaimsProvidersAdmin>(
  'oauth-oidc/claims_providers_admin',
  () => new ClaimsProvidersAdmin(ClaimsProvidersAdmin.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  ClaimsProvidersAdmin: ClaimsProvidersAdmin,
  installInstance: (instance: ClaimsProvidersAdmin): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  PAGE: PAGE
};
