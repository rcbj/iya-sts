// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_owned.ts
//
// ---------------------------------------------------------------------------
// RESOURCES I OWN (#604), DRAWN IN THE BROWSER, from `GET
// /account-api/owned/<kind>` (`portal_owned.ts`): the roles, groups, service
// accounts and applications whose owner values name the person or a group
// they are in, one page each, with how each is theirs. Read-only.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const KINDS = ['roles', 'groups', 'service-accounts', 'applications'];

/**
 * `/portal/owned/*`. A static utility class.
 */
class OwnedPages {
  /**
   * A page's body.
   *
   * @param view - `GET /account-api/owned/<kind>`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const kind = KINDS.indexOf(view.kind) >= 0 ? view.kind : 'roles';
    const rows: Json[] = view.rows || [];
    const how = function (via: Json): string {
      const parts: string[] = [];
      if (via && via.you) {
        parts.push(t.html('portalOwned.you'));
      }
      ((via && via.groups) || []).forEach(function (cn: string) {
        parts.push(t.html('portalOwned.viaGroup', { group: cn }));
      });
      return parts.join('<br>');
    };
    const body = rows.length
      ? '<table><tr><th>' + t.html('portalOwned.thName') + '</th><th>' +
        t.html('portalOwned.thDetail') + '</th><th>' +
        t.html('portalOwned.thHow') + '</th></tr>' +
        rows.map(function (row: Json): string {
          return '<tr><td><strong>' + kit.esc(row.name) + '</strong>' +
            (row.dn ? '<br><small><code>' + kit.esc(row.dn) +
                      '</code></small>' : '') + '</td><td>' +
            kit.esc(row.detail || '') + '</td><td>' + how(row.via) +
            '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalOwned.none', { kind: kind }) +
        '</p>';
    const path = kit.BASE + '/owned/' + kind;
    return '<div class="card"><h2>' + t.html('portalOwned.heading',
      { kind: kind }) + '</h2><p class="sub">' +
      t.html('portalOwned.sub') + '</p>' + body +
      kit.pageNav(path, ctx.query, view.paging, 'page', t) +
      ((view.groups || []).length
        ? '<p class="note">' + t.html('portalOwned.yourGroups',
            { groups: view.groups.join(', ') }) + '</p>'
        : '') + '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = KINDS.map(function (kind: string) {
    return { path: kit.BASE + '/owned/' + kind,
             operation: '/account-api/owned/' + kind,
             render: OwnedPages.render };
  });
}

export = OwnedPages;
