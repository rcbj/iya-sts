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
// chooser, the forced password change and, since #574, the wallet's start and
// wait pages — each with the `/authn-api`
// operation its view is the answer of. Each operation names its resource in
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
// THE WALLET'S TWO PAGES (#574), whose renderers are beside their server
// module in `oid4vc/`.
import WebVcSignin = require('../oid4vc/web_vc_signin');

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
  // THE WALLET SIGN-IN (#574): the start, asked with the location's
  // `authn`/`mfa`, `siop` and `enrol`; and the wait page, whose view is the
  // transaction's (its `state`) for the browser that started it.
  { path: '/authn/wallet',
    operation: function (query: Json): string {
      const asked = ['authn', 'mfa', 'siop', 'enrol'].filter(function (name) {
        return query[name] !== undefined && query[name] !== '';
      }).map(function (name) {
        return name + '=' + encodeURIComponent(String(query[name]));
      });
      return '/authn-api/wallet' + (asked.length ? '?' + asked.join('&')
                                                 : '');
    },
    render: function (view: Json, ctx: Json): string {
      return WebVcSignin.Pages.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebVcSignin.Pages.title(view, ctx);
    } },
  { path: '/authn/wallet/wait',
    operation: function (query: Json): string {
      return '/authn-api/wallet/' + encodeURIComponent(String(query.state ||
                                                              ''));
    },
    render: function (view: Json, ctx: Json): string {
      return WebVcSignin.Pages.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebVcSignin.Pages.title(view, ctx);
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
    return '<div class="card">' + body + '</div>';
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
