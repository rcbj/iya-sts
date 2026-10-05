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
   * @returns the body as HTML
   */
  static render(view: Json): string {
    return GrantsPage.body(view);
  }

  // The page body for `json`, the view `GET /admin-api/grants` answers.
  /**
   * Draws the page body.
   *
   * @param json - the view `GET /admin-api/grants` answers
   * @returns the HTML
   */
  static body(json: Json): string {
    const when = function (sec: Json): string {
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
    return kit.note('<strong>Grant Management for OAuth 2.0.</strong> A ' +
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
}

export = GrantsPage;
