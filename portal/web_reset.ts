// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_reset.ts
//
// ---------------------------------------------------------------------------
// `/portal/reset-password`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/reset-password` (`account_reset.ts`). A page drawn for
// nobody: no column, the language chooser of its own, and one of four
// states, each its view's:
//
//   * `refused` — the one sentence every failure of a link gets (or the rate
//     limit's, with `tooMany`);
//   * `done` — the password is set and the link spent: what to do next;
//   * `username` — the form, the link's two values riding in it;
//   * none of them — a request that did not validate, whose reason the
//     runtime draws above the card.
//
// The refusals stay in English, as every refusal does (#539).
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import PortalShell = require('./web_portal_shell');
import PasswordPages = require('./web_password');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/reset-password';

/**
 * `/portal/reset-password`. A static utility class.
 */
class ResetPages {
  /**
   * The page's title.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    if (view.refused) {
      return view.tooMany ? 'Too many attempts' : 'Password reset link';
    }
    return view.done ? ctx.t.text('portal.resetDone.title')
                     : ctx.t.text('portal.reset.title');
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/reset-password`'s answer, or a POST's
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    if (view.refused) {
      const heading = ResetPages.title(view, ctx);
      return '<div class="card"><h1>' + kit.esc(heading) + '</h1>' +
        (view.tooMany ? '<p>' + kit.esc(view.refused) + '</p>'
                      : '<div class="err">' + kit.esc(view.refused) +
                        '</div>') + '</div>';
    }
    if (view.done) {
      // The link is spent, so the chooser returns to the portal, where the
      // Sign in link goes too.
      return '<div class="card">' +
        PortalShell.chooser(t, ctx.locale, (ctx.prefix || '') + kit.BASE) +
        '<h1>' + t.html('portal.resetDone.heading') + '</h1>' +
        '<div class="ok">' + t.html('portal.resetDone.ok') + '</div>' +
        '<p>' + t.html('portal.resetDone.next') + '</p>' +
        '<p><a href="' + kit.esc(view.signIn || kit.BASE) + '">' +
        t.html('portal.signIn') + '</a></p></div>';
    }
    if (!view.username) {
      return '<div class="card"><h1>' + t.html('portal.reset.title') +
        '</h1></div>';
    }
    return '<div class="card">' +
      PortalShell.chooser(t, ctx.locale, ctx.here) +
      '<h1>' + t.html('portal.reset.title') + '</h1>' +
      '<p class="sub">' + t.html('portal.reset.sub',
        { name: view.username, base: view.base }) + '</p>' +
      '<form method="post" action="' + PATH + '">' +
      // THE TOKEN RIDES IN THE FORM, for the activation form's reason:
      // nobody is signed in, so there is no session to carry it on, and a
      // POST keeps it out of a referer and an access log.
      '<input type="hidden" name="user" value="' + kit.esc(view.username) +
      '"><input type="hidden" name="token" value="' + kit.esc(view.token) +
      '"><label for="password">' + t.html('portal.reset.password') +
      '</label><input type="password" id="password" name="password" ' +
      'autocomplete="new-password"><label for="confirm">' +
      t.html('portal.reset.again') + '</label><input type="password" ' +
      'id="confirm" name="confirm" autocomplete="new-password">' +
      PasswordPages.rulesNote(view.rules, t) +
      '<button type="submit">' + t.html('portal.reset.submit') +
      '</button></form></div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/reset-password', access: 'link',
      render: ResetPages.render, title: ResetPages.title }
  ];
}

export = ResetPages;
