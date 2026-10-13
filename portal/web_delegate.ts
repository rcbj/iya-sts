// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_delegate.ts
//
// ---------------------------------------------------------------------------
// `/portal/delegate`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/delegate` (`portal_delegate.ts`): who may act for the person
// (RFC 8693 `may_act`), a form to name them and one to clear it.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/delegate';

/**
 * `/portal/delegate`. A static utility class.
 */
class DelegatePages {
  /**
   * The page's body.
   *
   * @param view - `GET /account-api/delegate`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    // The DN is data and goes in as a parameter (#539); which of the three
    // sentences is drawn is the code's choice, as it was.
    const current = view.mayAct
      ? '<p>' + (view.delegate
          ? (view.delegate.kind === 'person'
            ? t.html('portalDelegate.currentPerson', { dn: view.mayAct })
            : t.html('portalDelegate.currentApplication',
                     { dn: view.mayAct }))
          : t.html('portalDelegate.currentStale', { dn: view.mayAct })) +
        '</p>'
      : '<p>' + t.html('portalDelegate.nobody') + '</p>';
    return '<div class="card"><h2>' + t.html('portalDelegate.heading') +
      '</h2><p class="sub">' + t.html('portalDelegate.sub') + '</p>' +
      current +
      (view.notDelegated
        ? '<div class="err">' + t.html('portalDelegate.notDelegated') +
          '</div>' : '') +
      '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="set">' +
      '<p><label>' + t.html('portalDelegate.dnLabel') +
      ' <input type="text" name="delegate" size="60" maxlength="1024" ' +
      'required value="' + kit.esc(view.mayAct || '') +
      '" placeholder="uid=bob,ou=users,..."></label></p><p>' +
      '<button type="submit">' + t.html('portalDelegate.name') +
      '</button></p></form>' +
      (view.mayAct
        ? '<form method="post" action="' + PATH + '">' +
          '<input type="hidden" name="action" value="clear">' +
          '<p><button class="danger" type="submit">' +
          t.html('portalDelegate.clear') + '</button></p></form>' : '') +
      '</div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/delegate',
      render: DelegatePages.render }
  ];
}

export = DelegatePages;
