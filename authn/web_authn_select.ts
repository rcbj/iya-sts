// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_select.ts
//
// ---------------------------------------------------------------------------
// THE FEDERATION CHOOSER, DRAWN IN THE BROWSER (#571, 2026-10-12).
//
// `/authn/select-idp` was `authn.ts`'s `selectIdpPage()` until #571; this is
// its renderer, over `GET /authn-api/pending/{id}/partners`'s view
// (`Authn.selectIdpView()`). It is still NOT the sign-in screen with its
// form hidden — no password field, no form, links only (`authn/CLAUDE.md`
// argues it) — and the problems are printed one banner each, English, as an
// operator reads them.
//
// A `web_` MODULE: it requires only another `web_` module and logs nothing.
// ---------------------------------------------------------------------------

import WebAuthnLogin = require('./web_authn_login');

type Json = any;

/**
 * The federation chooser's renderer. A static utility class.
 */
class WebAuthnSelect {
  /**
   * The chooser's body, under the language chooser.
   *
   * @param view - the chooser's view
   * @param ctx - the surface's context; its `t` is the page's translator
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const esc = WebAuthnLogin.esc;
    return '<h1>' + t.html('authn.selectIdp.heading') + '</h1>' +
      '<p class="sub">' + t.html('authn.selectIdp.at',
                                 { base: String(v.base) }) + '</p>' +
      (v.problems || []).map(function (one: string): string {
        return '<div class="err">' + esc(one) + '</div>';
      }).join('') +
      WebAuthnLogin.partnerButtons(v.partners || [],
        v.application ? t.html('authn.selectIdp.blurbNamed',
                               { application: String(v.application) })
                      : t.html('authn.selectIdp.blurb')) +
      '<div class="meta"><div>' + t.html('authn.selectIdp.meta') +
      '</div><div>' + t.html('authn.selectIdp.signingInFor',
                             { protocol: String(v.protocol) }) + '</div>' +
      WebAuthnLogin.details(v.details) + '</div>';
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
    return ctx.t.text('authn.selectIdp.title');
  }
}

export = WebAuthnSelect;
