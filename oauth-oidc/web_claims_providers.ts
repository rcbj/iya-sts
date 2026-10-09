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
   * @param ctx - the render context; the server-side caller passes none and
   *   is drawn in the default (English) translator (#539)
   * @returns the body as HTML
   */
  static render(view: Json, ctx?: Json): string {
    const t = (ctx || kit.context()).t;
    return ClaimsProvidersPage.body(view, t);
  }

  // The page body for `json`, the view `GET /admin-api/claim-providers`
  // answers, its `redirectUri` the address to register at a provider.
  /**
   * Draws the page body.
   *
   * @param json - the view `GET /admin-api/claim-providers` answers
   * @param t - the page's translator (#539)
   * @returns the HTML
   */
  static body(json: Json, t: Json): string {
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
          esc(p.issuer) + '</code></td><td class="sub">' +
          t.html('consoleClaimsProviders.epAuthorize') + ' <code>' +
          esc(p.authorizationEndpoint) + '</code><br>' +
          t.html('consoleClaimsProviders.epToken') + ' <code>' +
          esc(p.tokenEndpoint) + '</code><br>' +
          t.html('consoleClaimsProviders.epClaims') + ' <code>' +
          esc(p.claimsEndpoint) + '</code><br>' +
          t.html('consoleClaimsProviders.epKeys') + ' <code>' +
          esc(p.jwksUri) + '</code></td><td><code>' + esc(p.clientId) +
          '</code><br>' + esc(p.authMethod) + (p.hasSecret
            ? t.html('consoleClaimsProviders.secretHeld') : '') + '<br>' +
          t.html('consoleClaimsProviders.scope') + ' <code>' +
          esc(p.scope) + '</code></td><td>' +
          p.claims.map(function (c: string): string {
            return '<code>' + esc(c) + '</code>';
          }).join(' ') + '</td><td>' + esc(p.delivery) + '</td><td>' +
          form('remove-provider', { id: p.id },
               t.html('consoleClaimsProviders.remove'), true) +
          '</td></tr>';
      }).join('')
      : '<tr><td colspan="7" class="sub">' +
        t.html('consoleClaimsProviders.noProviders') + '</td></tr>';
    const links = json.links.length
      ? json.links.map(function (l: Json): string {
        return '<tr><td><code>' + esc(l.username) + '</code></td><td><code>' +
          esc(l.provider) + '</code></td><td><code>' + esc(l.sub) +
          '</code></td><td>' + esc(new Date(l.linkedAt).toISOString()) +
          '</td><td>' + (l.expiresAt ? esc(new Date(l.expiresAt)
            .toISOString()) : '—') +
          (l.refreshable ? t.html('consoleClaimsProviders.refreshable')
                         : '') +
          (l.stale ? ' <strong>' + t.html('consoleClaimsProviders.stale') +
                     '</strong>' : '') + '</td><td>' +
          form('revoke-link', { username: l.username, provider: l.provider },
               t.html('consoleClaimsProviders.revoke'), true) + '</td></tr>';
      }).join('')
      : '<tr><td colspan="6" class="sub">' +
        t.html('consoleClaimsProviders.noLinks') + '</td></tr>';
    const field = function (name: string, label: string, hint: string,
                            type?: string): string {
      return '<label>' + label + ' <input type="' + (type || 'text') +
        '" name="' + name + '" autocomplete="off"></label>' +
        (hint ? ' <span class="sub">' + hint + '</span>' : '') + '<br>';
    };
    const add = '<h3>' + t.html('consoleClaimsProviders.addHeading') +
      '</h3>' +
      '<form method="post" action="' + PAGE + '" id="claim-provider-add">' +
      '<input type="hidden" name="action" value="add-provider">' +
      field('id', t.html('consoleClaimsProviders.fId'),
            t.html('consoleClaimsProviders.fIdHint')) +
      field('name', t.html('consoleClaimsProviders.fName'), '') +
      field('issuer', t.html('consoleClaimsProviders.fIssuer'),
            t.html('consoleClaimsProviders.fIssuerHint')) +
      '<label><input type="checkbox" name="discover" value="true" ' +
      'checked> ' + t.html('consoleClaimsProviders.fDiscover') +
      '</label><br>' +
      field('authorizationEndpoint',
            t.html('consoleClaimsProviders.fAuthorization'), '') +
      field('tokenEndpoint', t.html('consoleClaimsProviders.fToken'), '') +
      field('claimsEndpoint', t.html('consoleClaimsProviders.fClaims'),
            t.html('consoleClaimsProviders.fClaimsHint')) +
      field('jwksUri', 'JWKS URI', '') +
      field('clientId', 'client_id',
            t.html('consoleClaimsProviders.fClientIdHint')) +
      field('clientSecret', t.html('consoleClaimsProviders.fSecret'),
            t.html('consoleClaimsProviders.fSecretHint'), 'password') +
      '<label>' + t.html('consoleClaimsProviders.fAuthMethod') +
      ' <select name="authMethod">' +
      '<option>client_secret_basic</option><option>client_secret_post' +
      '</option><option>none</option></select></label><br>' +
      field('scope', t.html('consoleClaimsProviders.fScope'),
            t.html('consoleClaimsProviders.fScopeHint')) +
      field('claims', t.html('consoleClaimsProviders.fSupplies'),
            t.html('consoleClaimsProviders.fSuppliesHint')) +
      '<label>' + t.html('consoleClaimsProviders.fDelivery') +
      ' <select name="delivery"><option>aggregated</option>' +
      '<option>distributed</option></select></label><br>' +
      '<button type="submit">' + t.html('consoleClaimsProviders.register') +
      '</button></form>';
    // The callback address is a <code> with an id, markup a message may not
    // carry, so the note is two messages around it (#539).
    return kit.note(t.html('consoleClaimsProviders.noteA') + '<code ' +
        'id="claim-provider-callback">' + esc(json.redirectUri) +
        '</code>' + t.html('consoleClaimsProviders.noteB')) +
      '<table><thead><tr><th>' + t.html('consoleClaimsProviders.colProvider') +
      '</th><th>' + t.html('consoleClaimsProviders.colIssuer') + '</th><th>' +
      t.html('consoleClaimsProviders.colEndpoints') + '</th>' +
      '<th>' + t.html('consoleClaimsProviders.colClient') + '</th><th>' +
      t.html('consoleClaimsProviders.colClaims') + '</th><th>' +
      t.html('consoleClaimsProviders.colDelivery') + '</th><th></th></tr>' +
      '</thead><tbody>' + providers + '</tbody></table>' + add +
      '<h3>' + t.html('consoleClaimsProviders.linksHeading') +
      '</h3><table><thead><tr><th>' +
      t.html('consoleClaimsProviders.colPerson') + '</th><th>' +
      t.html('consoleClaimsProviders.colProvider') + '</th>' +
      '<th>' + t.html('consoleClaimsProviders.colTheirSub') + '</th><th>' +
      t.html('consoleClaimsProviders.colLinked') + '</th><th>' +
      t.html('consoleClaimsProviders.colToken') + '</th><th></th></tr>' +
      '</thead><tbody>' + links + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/claim-providers</code></p>';
  }
}

export = ClaimsProvidersPage;
