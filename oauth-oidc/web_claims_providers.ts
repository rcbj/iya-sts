// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_claims_providers.ts
//
// ---------------------------------------------------------------------------
// OAUTH 2.0 → CLAIMS PROVIDERS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Claims Providers from the answer of `GET /admin-api/claim-providers`:
// the providers this realm aggregates or distributes claims from, the redirect
// URI to register at each, and every link a person made.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `ClaimsProvidersAdmin`'s in
// `oauth-oidc/claims_providers_admin.ts`, moved with their comments; that
// module still draws the page until the console's cutover, by calling
// `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

/**
 * The page's path.
 */
const PAGE = '/admin/claim-providers';

/**
 * Draws Claims Providers from the answer of `GET /admin-api/claim-providers`:
 * the providers this realm aggregates or distributes claims from, the redirect
 * URI to register at each, and every link a person made.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class ClaimsProvidersPage {
  /**
   * Draws the page's body from its view.
   *
   * @param view - the answer of the page's management API operation
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return ClaimsProvidersPage.body(view);
  }

  // The page body for `json`, the view `GET /admin-api/claim-providers`
  // answers, its `redirectUri` the address to register at a provider.
  /**
   * Draws the page body.
   *
   * @param json - the view `GET /admin-api/claim-providers` answers
   * @returns the HTML
   */
  static body(json: Json): string {
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
    return kit.note('<strong>OpenID Connect Claims Aggregation.</strong> ' +
        'A Claims Provider is another OpenID Provider that vouches for ' +
        'claims about a person this realm does not hold. A person links one ' +
        'on the portal; after that a relying party asking for one of its ' +
        'claims gets it as an <em>aggregated</em> claim (the provider\'s ' +
        'signed JWT, verified here first) or a <em>distributed</em> one ' +
        '(its endpoint and the person\'s access token there) — never in ' +
        'place of a value the person\'s own entry holds. Register this ' +
        'realm at the provider as a client whose redirect URI is <code ' +
        'id="claim-provider-callback">' + esc(json.redirectUri) +
        '</code> and ' +
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
}

export = ClaimsProvidersPage;
