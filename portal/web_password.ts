// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_password.ts
//
// ---------------------------------------------------------------------------
// `/portal/password`, DRAWN IN THE BROWSER (#568), from `GET
// /account-api/password` (`account_password.ts`). One form, and the field
// somebody signed in already has to fill in anyway: the current password,
// which the change re-proves.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

/**
 * `/portal/password`. A static utility class.
 */
class PasswordPages {
  // WHAT A PASSWORD HERE MUST BE (2026-09-12), said on the form that asks
  // for one. In development nothing is checked, and the note says so rather
  // than listing rules nobody applies.
  /**
   * The password rules, as a note.
   *
   * @param rules - `{ enforced, rules }`
   * @param t - the translator
   * @returns the note's HTML
   */
  static rulesNote(rules: Json, t: Json): string {
    const said = rules || { enforced: false, rules: [] };
    return '<p class="note">' + t.html(said.enforced
      ? 'portal.rules.enforced' : 'portal.rules.development',
      { rules: (said.rules || []).join(', ') }) + '</p>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/password`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    return '<div class="card"><p class="sub">' +
      (view.hasPassword ? t.html('portal.password.has')
                        : t.html('portal.password.none')) + '</p>' +
      '<form method="post" action="' + kit.BASE + '/password">' +
      '<label for="current">' + t.html('portal.password.current') +
      '</label><input type="password" id="current" name="current" ' +
      'autocomplete="current-password"><label for="next">' +
      t.html('portal.password.new') + '</label><input type="password" ' +
      'id="next" name="next" autocomplete="new-password">' +
      '<label for="confirm">' + t.html('portal.password.confirm') +
      '</label><input type="password" id="confirm" name="confirm" ' +
      'autocomplete="new-password">' +
      PasswordPages.rulesNote(view.rules, t) +
      '<button type="submit">' + t.html('portal.password.submit') +
      '</button></form><p class="note">' + t.html('portal.password.note') +
      '</p></div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: kit.BASE + '/password', operation: '/account-api/password',
      render: PasswordPages.render }
  ];
}

export = PasswordPages;
