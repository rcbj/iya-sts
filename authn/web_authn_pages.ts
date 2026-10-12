// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_pages.ts
//
// ---------------------------------------------------------------------------
// THE SIGN-IN SURFACE'S PAGE TABLE (#571, 2026-10-12).
//
// Rows in `common/web_surface.ts`'s shape — the screen, the federation
// chooser and the forced password change, each with the `/authn-api`
// operation its view is the answer of; and the SPNEGO sign-in's bodies
// (#575), whose view the shell carries instead. Each operation names its resource in
// the PATH (the pending sign-in's id, the step's id), which the browser
// reads off the location's query (`?authn=`, `?change=`) — the addresses
// `beginAuthentication()` and the screen's acts have always sent a browser
// to. It is also the renderers' bundle, `authn/authn.bundle.js` under the
// global `StsAuthn`, which `tests/web_surfaces.js` loads to draw a page from
// a view after the wire and compare it, byte for byte, with this process's
// drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebAuthnLogin = require('./web_authn_login');
import WebAuthnSelect = require('./web_authn_select');
import WebAuthnPassword = require('./web_authn_password');
import WebAuthnSpnego = require('../kerberos/web_authn_spnego');

type Json = any;

/**
 * The surface's pages.
 */
const PAGES = [
  { path: '/authn/login',
    operation: function (query: Json): string {
      return '/authn-api/pending/' + encodeURIComponent(String(query.authn ||
                                                               ''));
    },
    render: function (view: Json, ctx: Json): string {
      return WebAuthnLogin.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebAuthnLogin.title(view, ctx);
    } },
  { path: '/authn/select-idp',
    operation: function (query: Json): string {
      return '/authn-api/pending/' + encodeURIComponent(String(query.authn ||
                                                               '')) +
        '/partners';
    },
    render: function (view: Json, ctx: Json): string {
      return WebAuthnSelect.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebAuthnSelect.title(view, ctx);
    } },
  { path: '/authn/password-change',
    operation: function (query: Json): string {
      return '/authn-api/password-change/' +
        encodeURIComponent(String(query.change || ''));
    },
    render: function (view: Json, ctx: Json): string {
      return WebAuthnPassword.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebAuthnPassword.title(view, ctx);
    } },
  // THE SPNEGO SIGN-IN'S BODIES (#575). `/authn/spnego` is an RFC 4559
  // exchange the runtime never drives: the page is EMBEDDED — its view is
  // the state the shell carried on the response the exchange answered
  // (`data-sts-state`), not an operation's answer, so it has no operation
  // and `authn/web_authn.ts` never fetches one for it.
  { path: '/authn/spnego',
    embedded: true,
    operation: function (): string {
      return '';
    },
    render: function (view: Json, ctx: Json): string {
      return WebAuthnSpnego.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebAuthnSpnego.title(view, ctx);
    } }
];

/**
 * The sign-in surface's page table. A static utility class.
 */
class AuthnPages {
  /**
   * Every page.
   */
  static readonly PAGES = PAGES;

  /**
   * The card around a page, for the surface's `frame`: the chooser and the
   * body inside the sign-in card, as the server-drawn pages had it. A
   * problem page draws its own card and is left as it is.
   *
   * @param body - the chooser and the page's body
   * @param ctx - the surface's context, with the page's `view`
   * @returns the framed markup
   */
  static frame(body: string, ctx: Json): string {
    if (!ctx || !ctx.view) {
      return body;
    }
    // The SPNEGO sign-in's tables need the wide card (#575).
    return '<div class="card' + (ctx.view.door === 'spnego' ? ' wide' : '') +
      '">' + body + '</div>';
  }

  /**
   * Draws a page's body from its view.
   *
   * @param path - the page's path
   * @param view - its operation's view
   * @param ctx - the render context
   * @returns the HTML, or '' for a path that is not a page
   */
  static render(path: string, view: Json, ctx: Json): string {
    const row = PAGES.filter(function (one) {
      return one.path === path;
    })[0];
    return row ? row.render(view, ctx) : '';
  }
}

export = AuthnPages;
