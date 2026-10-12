// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_password.ts
//
// ---------------------------------------------------------------------------
// THE FORCED PASSWORD CHANGE, DRAWN IN THE BROWSER (#571, 2026-10-12).
//
// `/authn/password-change` was `authn.ts`'s `passwordChangePage()` until
// #571; this is its renderer, over `GET /authn-api/password-change/{id}`'s
// view (`Authn.passwordChangeView()`): whose password, and why it must be
// changed now where there is a reason (English, as every refusal). The form
// is the runtime's to send (`POST /authn-api/password-change/{id}`).
//
// A `web_` MODULE: it requires only another `web_` module and logs nothing.
// ---------------------------------------------------------------------------

import WebAuthnLogin = require('./web_authn_login');

type Json = any;

/**
 * The forced password change's renderer. A static utility class.
 */
class WebAuthnPassword {
  /**
   * The page's body, under the language chooser.
   *
   * @param view - the step's view
   * @param ctx - the surface's context: `t`, and an act's `error`
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const esc = WebAuthnLogin.esc;
    const error = [String(v.notice || ''), String((ctx && ctx.error) || '')]
      .filter(Boolean).join(' ');
    return '<h1>' + t.html('authn.passwordChange.heading') + '</h1>' +
      '<p class="sub">' + t.html('authn.passwordChange.sub',
                                 { name: String(v.username) }) + '</p>' +
      (error ? '<div class="err" id="authn-error">' + esc(error) + '</div>'
             : '') +
      '<form method="post" action="/authn/password-change">' +
      '<label for="new_password">' + t.html('authn.passwordChange.new') +
      '</label><input type="password" id="new_password" ' +
      'name="new_password" autocomplete="new-password" autofocus>' +
      '<label for="confirm_password">' +
      t.html('authn.passwordChange.confirm') + '</label><input ' +
      'type="password" id="confirm_password" name="confirm_password" ' +
      'autocomplete="new-password">' +
      '<button type="submit" id="password-change-submit">' +
      t.html('authn.passwordChange.submit') + '</button></form>' +
      '<div class="meta">' + t.html('authn.passwordChange.meta') + '</div>';
  }

  /**
   * The document's title.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    void view;
    return ctx.t.text('authn.passwordChange.title');
  }
}

export = WebAuthnPassword;
