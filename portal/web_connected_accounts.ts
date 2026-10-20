// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_connected_accounts.ts
//
// ---------------------------------------------------------------------------
// `/portal/connected-accounts`, DRAWN IN THE BROWSER (#565), from `GET
// /account-api/connected-accounts` (`portal_connected_accounts.ts`): every
// consumer or social provider the realm offers, with Connect or Disconnect.
// Connect's answer is the provider's address, and the runtime sends the
// window there; the provider's return comes back here with `done` or
// `problem`, drawn from the view. A connect that needs a fresh sign-in is
// answered `stepUp`, which the runtime turns into one.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/connected-accounts';

/**
 * `/portal/connected-accounts`. A static utility class.
 */
class ConnectedAccountsPages {
  /**
   * One Connect or Disconnect form.
   *
   * @param action - `connect` or `disconnect`
   * @param id - the provider relationship
   * @param label - the button's HTML
   * @param danger - whether the button is a danger one
   * @returns the form's HTML
   */
  static form(action: string, id: string, label: string,
              danger: boolean): string {
    return '<form method="post" action="' + kit.esc(PATH) + '" ' +
      'style="display:inline">' +
      '<input type="hidden" name="action" value="' + action + '">' +
      '<input type="hidden" name="id" value="' + kit.esc(id) + '">' +
      '<button type="submit"' + (danger ? ' class="danger"' : '') +
      ' id="connected-account-' + action + '-' + kit.esc(id) + '">' + label +
      '</button></form> ';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/connected-accounts`' answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const form = ConnectedAccountsPages.form;
    // Text only (#565, the plan's decision 9): a provider's mark is under
    // its own brand rules.
    const rows = (view.providers || []).map(function (p: Json): string {
      return '<div class="card connected-account" id="connected-account-' +
        kit.esc(p.id) + '"><p><strong>' + kit.esc(p.name) + '</strong>' +
        (p.providerLabel && p.providerLabel !== p.name
          ? ' <span class="sub">' + kit.esc(p.providerLabel) + '</span>'
          : '') + '</p>' +
        (p.connected
          ? '<p class="connected-account-on">' +
            t.html('portalConnectedAccounts.connected') + '</p>' +
            form('disconnect', p.id,
                 t.html('portalConnectedAccounts.disconnect'), true)
          : form('connect', p.id,
                 t.html('portalConnectedAccounts.connect'), false)) +
        '</div>';
    });
    return (view.problem ? '<div class="err">' + kit.esc(view.problem) +
                           '</div>' : '') +
      (view.notice ? '<div class="ok">' + kit.esc(view.notice) + '</div>'
                   : '') +
      '<div class="card"><h2>' + t.html('portalConnectedAccounts.heading') +
      '</h2><p class="sub">' + t.html('portalConnectedAccounts.sub') +
      '</p></div>' +
      (rows.length ? rows.join('')
        : '<div class="card"><p id="connected-accounts-none">' +
          t.html('portalConnectedAccounts.none') + '</p></div>');
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/connected-accounts',
      render: ConnectedAccountsPages.render }
  ];
}

export = ConnectedAccountsPages;
