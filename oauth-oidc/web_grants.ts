// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_grants.ts
//
// ---------------------------------------------------------------------------
// MONITORING → GRANTS, DRAWN FROM ITS VIEW ALONE (#446, 2026-10-05).
//
// Draws Monitoring → Grants from the answer of `GET /admin-api/grants`: every
// grant a client holds under Grant Management for OAuth 2.0, each with its
// Revoke form.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Its methods were `GrantManagementAdmin`'s in
// `oauth-oidc/grant_management_admin.ts`, moved with their comments; that
// module still draws the page until the console's cutover, by calling
// `render()` with its view passed through JSON.
// ---------------------------------------------------------------------------

import kit = require('../admin-ui/web_kit');

type Json = any;

// The console's escaping, under the name the moved code calls it by.
const esc = kit.esc;

const PAGE = '/admin/grants';

/**
 * Draws Monitoring → Grants from the answer of `GET /admin-api/grants`: every
 * grant a client holds under Grant Management for OAuth 2.0, each with its
 * Revoke form.
 *
 * A static utility class; it holds no state and takes no dependencies.
 */
class GrantsPage {
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
    return GrantsPage.body(view, t);
  }

  // The page body for `json`, the view `GET /admin-api/grants` answers.
  /**
   * Draws the page body.
   *
   * @param json - the view `GET /admin-api/grants` answers
   * @param t - the page's translator (#539)
   * @returns the HTML
   */
  static body(json: Json, t: Json): string {
    const when = function (sec: Json): string {
      return Number(sec) > 0 ? new Date(Number(sec) * 1000).toISOString()
                             : '—';
    };
    const rows = json.grants.length ? json.grants.map(function (g: Json) {
      const scopes = (g.scopes || []).map(function (s: Json): string {
        return '<code>' + esc(s.scope || '') + '</code>' +
          (s.resource ? t.html('consoleGrants.scopeFor',
                               { resource: s.resource.join(', ') }) : '');
      }).join('<br>');
      return '<tr><td><code>' + esc(g.grantId) + '</code></td><td><code>' +
        esc(g.clientId) + '</code></td><td><code>' + esc(g.subject) +
        '</code></td><td>' + scopes +
        (g.authorization_details ? '<br><span class="sub">' +
          t.html('consoleGrants.details',
                 { n: String(g.authorization_details.length) }) +
          '</span>' : '') +
        (g.claims ? '<br><span class="sub">' +
          t.html('consoleGrants.claims', { claims: g.claims.join(', ') }) +
          '</span>' : '') + '</td><td>' +
        esc(String(g.generation)) + '</td><td>' + esc(when(g.created_at)) +
        '<br>' + esc(when(g.last_updated)) + '</td><td>' +
        esc(when(g.expires_at)) + '</td><td>' + esc(String(g.tokens)) +
        '</td><td><form method="post" action="' + PAGE + '" ' +
        'class="inline"><input type="hidden" name="action" ' +
        'value="revoke-grant"><input type="hidden" name="grantId" value="' +
        esc(g.grantId) + '"> <button type="submit" class="danger">' +
        t.html('consoleGrants.revoke') + '</button></form></td></tr>';
    }).join('') : '<tr><td colspan="9" class="sub">' +
      t.html('consoleGrants.none') + '</td></tr>';
    // The grant endpoint's path carries `{grant_id}`, braces a catalog
    // message may not hold, so it goes in as a parameter (#539).
    return kit.note(t.html('consoleGrants.note',
                           { path: '/oauth2/grants/{grant_id}' }) +
        '<a href="/admin/consent">' + t.html('consoleGrants.consentLink') +
        '</a>' + t.html('consoleGrants.noteEnd')) +
      '<table><thead><tr><th>grant_id</th><th>' +
      t.html('consoleGrants.colClient') + '</th><th>' +
      t.html('consoleGrants.colSubject') + '</th>' +
      '<th>' + t.html('consoleGrants.colScopes') + '</th><th>' +
      t.html('consoleGrants.colGeneration') + '</th><th>' +
      t.html('consoleGrants.colCreated') + '</th>' +
      '<th>' + t.html('consoleGrants.colExpires') + '</th><th>' +
      t.html('consoleGrants.colTokens') + '</th><th></th></tr></thead>' +
      '<tbody>' +
      rows + '</tbody></table>' +
      '<p class="links"><a href="' + PAGE + '?format=json">JSON</a> · ' +
      '<code>GET /admin-api/grants</code></p>';
  }
}

export = GrantsPage;
