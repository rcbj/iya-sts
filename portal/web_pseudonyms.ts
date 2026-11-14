// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_pseudonyms.ts
//
// ---------------------------------------------------------------------------
// SIGN-IN NAMES, DRAWN IN THE BROWSER (#644), from
// `portal_pseudonyms.ts`'s operations:
//
//   * `/portal/pseudonyms` (signed in): the live names, a pending email,
//     and the forms that add, remove or cancel;
//   * `/portal/verify-pseudonym` (a link, drawn for nobody): a button,
//     because opening the link spends nothing — then the name confirmed.
//
// This is not `/portal/verify-email`. The refusals stay in English.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import PortalShell = require('./web_portal_shell');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PAGE = kit.BASE + '/pseudonyms';
const VERIFY = kit.BASE + '/verify-pseudonym';

/**
 * The sign-in-name pages. A static utility class.
 */
class PseudonymPages {
  /**
   * `/portal/pseudonyms`'s cards.
   *
   * @param view - `GET /account-api/pseudonyms`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static page(view: Json, ctx: Json): string {
    const t = ctx.t;
    const names = view.pseudonyms || [];
    const rows = names.map(function (name: string): string {
      return '<tr><td><code>' + kit.esc(name) + '</code></td><td>' +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="remove">' +
        '<input type="hidden" name="value" value="' + kit.esc(name) + '">' +
        '<button type="submit">' + t.html('portalPseudonyms.remove') +
        '</button></form></td></tr>';
    }).join('');
    const pending = view.pending
      ? '<p>' + t.html('portalPseudonyms.pending',
                       { address: view.pending }) + '</p>' +
        '<form method="post" action="' + PAGE + '">' +
        '<input type="hidden" name="action" value="cancel-pending">' +
        '<p><button type="submit">' + t.html('portalPseudonyms.cancel') +
        '</button></p></form>'
      : '';
    const list = '<div class="card"><h2>' +
      t.html('portalPseudonyms.listHeading') + '</h2>' +
      (names.length
        ? '<table>' + rows + '</table>'
        : '<p class="sub">' + t.html('portalPseudonyms.none') + '</p>') +
      pending + '</div>';
    const add = '<div class="card"><h2>' +
      t.html('portalPseudonyms.heading') + '</h2><p>' +
      t.html('portalPseudonyms.intro') + '</p>' +
      (view.available ? ''
        : '<p class="note">' + t.html('portalPseudonyms.noMail') + '</p>') +
      '<form method="post" action="' + PAGE + '">' +
      '<input type="hidden" name="action" value="add">' +
      '<label for="pseudonym">' + t.html('portalPseudonyms.addLabel') +
      '</label><input type="text" id="pseudonym" name="value" ' +
      'maxlength="254" autocomplete="off" required>' +
      '<p><button type="submit">' + t.html('portalPseudonyms.addButton') +
      '</button></p></form><p class="note">' +
      t.html('portalPseudonyms.capNote') + '</p></div>';
    return list + add;
  }

  /**
   * `/portal/verify-pseudonym`'s title.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the title
   */
  static verifyTitle(view: Json, ctx: Json): string {
    if (view.refused || !view.address) {
      return 'Confirm a sign-in name';
    }
    return view.verified ? ctx.t.text('portalPseudonyms.verified.title')
                         : ctx.t.text('portalPseudonyms.verify.title');
  }

  /**
   * `/portal/verify-pseudonym`'s body.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static verify(view: Json, ctx: Json): string {
    const t = ctx.t;
    if (view.refused || !view.address) {
      return '<div class="card"><h1>Confirm a sign-in name</h1>' +
        (view.refused ? '<div class="err">' + kit.esc(view.refused) +
                        '</div>' : '') + '</div>';
    }
    if (view.verified) {
      return '<div class="card">' +
        PortalShell.chooser(t, ctx.locale, (ctx.prefix || '') + kit.BASE) +
        '<h1>' + t.html('portalPseudonyms.verified.heading') + '</h1><p>' +
        t.html('portalPseudonyms.verified.body',
               { address: view.address, name: view.username }) +
        '</p><p><a href="' + kit.BASE + '">' +
        t.html('portalPseudonyms.verified.toAccount') + '</a></p></div>';
    }
    return '<div class="card">' +
      PortalShell.chooser(t, ctx.locale, ctx.here) +
      '<h1>' + t.html('portalPseudonyms.verify.heading') + '</h1><p>' +
      t.html('portalPseudonyms.verify.confirm',
             { address: view.address, name: view.username }) + '</p>' +
      '<form method="post" action="' + VERIFY + '">' +
      '<input type="hidden" name="user" value="' + kit.esc(view.username) +
      '"><input type="hidden" name="token" value="' + kit.esc(view.token) +
      '"><button type="submit">' + t.html('portalPseudonyms.verify.button') +
      '</button></form></div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PAGE, operation: '/account-api/pseudonyms',
      render: PseudonymPages.page },
    { path: VERIFY, operation: '/account-api/verify-pseudonym',
      access: 'link', render: PseudonymPages.verify,
      title: PseudonymPages.verifyTitle }
  ];
}

export = PseudonymPages;
