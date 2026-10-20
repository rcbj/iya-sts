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
// chooser and the forced password change (#571), each with the `/authn-api`
// operation its view is the answer of; the wallet's start and wait pages
// (#574), likewise; the SPNEGO sign-in's bodies (#575), whose view the
// shell carries instead; and the second-factor and emailed-factor steps
// (#572, #573); and the OAuth consent screen (#576). Each operation names
// its resource in the PATH (the pending sign-in's id, the step's id, the
// pending consent's id), which the browser reads off the location's query
// (`?authn=`, `?change=`, `?mfa=`, `?consent=`) — the addresses
// `beginAuthentication()`, `beginConsent()` and the screen's acts have
// always sent a browser to. It is also the renderers' bundle, `authn/authn.bundle.js` under the
// global `StsAuthn`, which `tests/web_surfaces.js` loads to draw a page from
// a view after the wire and compare it, byte for byte, with this process's
// drawing.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebAuthnLogin = require('./web_authn_login');
import WebAuthnSelect = require('./web_authn_select');
// THE ACCOUNT PICKER (#561).
import WebAuthnAccounts = require('./web_authn_accounts');
import WebAuthnPassword = require('./web_authn_password');
import WebAuthnMfa = require('./web_authn_mfa');
import WebAuthnEmail = require('./web_authn_email');
// THE WALLET'S TWO PAGES (#574), whose renderers are beside their server
// module in `oid4vc/`.
import WebVcSignin = require('../oid4vc/web_vc_signin');
import WebAuthnSpnego = require('../kerberos/web_authn_spnego');
// THE OAUTH CONSENT SCREEN (#576), whose renderer is beside its server
// module in `oauth-oidc/`.
import WebConsentScreen = require('../oauth-oidc/web_consent_screen');

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
  // THE ACCOUNT PICKER (#561): a browser holding several signed-in
  // accounts chooses which a sign-in continues as, keyed by the pending
  // sign-in as the chooser is.
  { path: '/authn/accounts',
    operation: function (query: Json): string {
      return '/authn-api/pending/' + encodeURIComponent(String(query.authn ||
                                                               '')) +
        '/accounts';
    },
    render: function (view: Json, ctx: Json): string {
      return WebAuthnAccounts.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebAuthnAccounts.title(view, ctx);
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
    } },
  // THE STEPS AFTER THE SCREEN (#572, #573).
  stepRow('/authn/totp', 'totp', WebAuthnMfa.totp),
  stepRow('/authn/webauthn', 'webauthn', WebAuthnMfa.webauthn),
  stepRow('/authn/backup-code', 'backup-code', WebAuthnMfa.backup),
  stepRow('/authn/password-factor', 'password', WebAuthnMfa.password),
  stepRow('/authn/mfa-setup', 'setup', WebAuthnMfa.setup),
  emailRow('/authn/email-code', 'email-code'),
  emailRow('/authn/email-link', 'email-link'),
  emailRow('/authn/email-link/open', 'email-link-open'),
  // THE OAUTH CONSENT SCREEN (#576): `/oauth2/consent?consent=<id>`, the
  // address the authorization endpoint has always sent a person to, drawn
  // from `GET /authn-api/consent/{id}`. The one page of this surface outside
  // `/authn`: the runtime owns it beside its base (`AuthnSurface`).
  { path: '/oauth2/consent',
    operation: function (query: Json): string {
      return '/authn-api/consent/' +
        encodeURIComponent(String(query.consent || ''));
    },
    render: function (view: Json, ctx: Json): string {
      return WebConsentScreen.render(view, ctx);
    },
    title: function (view: Json, ctx: Json): string {
      return WebConsentScreen.title(view, ctx);
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
    // The SPNEGO sign-in's tables need the wide card (#575); the consent
    // screen's scope rows a wider card of their own (#576), as its own
    // stylesheet had it.
    return '<div class="card' + (ctx.view.door === 'spnego' ? ' wide'
      : (ctx.view.consent === true ? ' consent' : '')) + '">' + body +
      '</div>';
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
