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
// chooser and the forced password change (#571), and since #572 and #573
// the second-factor and emailed-factor steps — each with the `/authn-api`
// operation its view is the answer of. Each operation names its resource in
// the PATH (the pending sign-in's id, the step's id), which the browser
// reads off the location's query (`?authn=`, `?change=`, `?mfa=`) — the
// addresses
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
import WebAuthnMfa = require('./web_authn_mfa');
import WebAuthnEmail = require('./web_authn_email');

type Json = any;

/**
 * A second-factor or emailed-factor step's view (#572, #573): `GET
 * /authn-api/mfa/{id}?page=`, the step's id off `?mfa=`, and the passkey a
 * person chose off `?key=` (#534).
 *
 * @param page - the page's name to the API
 * @returns the row's `operation`
 */
function stepOperation(page: string): (query: Json) => string {
  return function (query: Json): string {
    return '/authn-api/mfa/' + encodeURIComponent(String(query.mfa || '')) +
      '?page=' + page + (query.key ? '&key=' +
                         encodeURIComponent(String(query.key)) : '');
  };
}

/**
 * A second-factor page's row.
 *
 * @param path - the page's path
 * @param page - its name to the API
 * @param render - its renderer
 * @returns the row
 */
function stepRow(path: string, page: string,
                 render: (view: Json, ctx: Json) => string): Json {
  return { path: path, operation: stepOperation(page), render: render,
           title: function (view: Json, ctx: Json): string {
             return WebAuthnMfa.title(view, ctx);
           } };
}

/**
 * An emailed factor's page's row.
 *
 * @param path - the page's path
 * @param page - its name to the API
 * @returns the row
 */
function emailRow(path: string, page: string): Json {
  return { path: path, operation: stepOperation(page),
           render: function (view: Json, ctx: Json): string {
             return WebAuthnEmail.render(view, ctx);
           },
           title: function (view: Json, ctx: Json): string {
             return WebAuthnEmail.title(view, ctx);
           } };
}

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
  // THE STEPS AFTER THE SCREEN (#572, #573).
  stepRow('/authn/totp', 'totp', WebAuthnMfa.totp),
  stepRow('/authn/webauthn', 'webauthn', WebAuthnMfa.webauthn),
  stepRow('/authn/backup-code', 'backup-code', WebAuthnMfa.backup),
  stepRow('/authn/password-factor', 'password', WebAuthnMfa.password),
  stepRow('/authn/mfa-setup', 'setup', WebAuthnMfa.setup),
  emailRow('/authn/email-code', 'email-code'),
  emailRow('/authn/email-link', 'email-link'),
  emailRow('/authn/email-link/open', 'email-link-open')
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
