// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_accounts.ts
//
// ---------------------------------------------------------------------------
// THE ACCOUNT PICKER, DRAWN IN THE BROWSER (#561).
//
// `/authn/accounts?authn=<id>` is where a sign-in waits when the browser
// holds several signed-in accounts and the request names none of them, or
// asked for the picker (`prompt=select_account`). This draws it from `GET
// /authn-api/pending/{id}/accounts`'s view (`Authn.accountsView()`):
//
//   * each SIGNED-IN account, a button that continues as it — Select;
//   * each SIGNED-OUT account the browser remembers, a button that signs in
//     again as it (its name filled in) and one that forgets it;
//   * Use another account, always drawn, and disabled — with the sentence
//     saying why — where every place the browser has is a signed-in account
//     (the plan's D11).
//
// Every account is named by its KEY, a hidden field; never a sid. The two
// kinds of choice are drawn apart, under their own headings (FR-3: selecting
// an account is not signing in as a new one). A time is drawn in UTC, the
// same bytes wherever it is drawn (`tests/web_surfaces.js` compares them).
//
// A `web_` MODULE: it requires only another `web_` module and logs nothing.
// ---------------------------------------------------------------------------

import WebAuthnLogin = require('./web_authn_login');

type Json = any;

/**
 * The account picker's renderer. A static utility class.
 */
class WebAuthnAccounts {
  /**
   * An instant, to the minute, in UTC.
   *
   * @param ms - epoch milliseconds
   * @returns `YYYY-MM-DD HH:MM UTC`, or '' for none
   */
  static when(ms: unknown): string {
    const n = Number(ms) || 0;
    if (!(n > 0)) {
      return '';
    }
    return new Date(n).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }

  /**
   * One account's row: its names, its time, and its buttons.
   *
   * @param one - the account, from the view
   * @param i - its place, for the ids
   * @param t - the translator
   * @returns the markup
   */
  static row(one: Json, i: number, t: Json): string {
    const esc = WebAuthnLogin.esc;
    const live = one.state === 'signed-in';
    const name = String(one.displayName || one.username || '');
    const when = WebAuthnAccounts.when(live ? one.signedInAt
                                            : one.signedOutAt);
    return '<form method="post" action="/authn/accounts" class="account" ' +
      'id="account-' + i + '">' +
      '<input type="hidden" name="account" value="' + esc(one.key) + '">' +
      '<div class="account-name"><strong>' + esc(name) + '</strong>' +
      (one.username && one.username !== name
        ? ' <span class="sub">' + esc(one.username) + '</span>' : '') +
      '</div>' +
      (when ? '<div class="sub">' +
        t.html(live ? 'authn.accounts.signedInAt'
                    : 'authn.accounts.signedOutAt', { when: when }) +
        '</div>' : '') +
      '<div class="row">' +
      (live
        ? '<button type="submit" id="account-select-' + i + '" ' +
          'name="action" value="select">' +
          t.html('authn.accounts.select') + '</button>'
        : '<button type="submit" id="account-again-' + i + '" ' +
          'name="action" value="select">' +
          t.html('authn.accounts.signInAgain') + '</button>' +
          '<button type="submit" id="account-forget-' + i + '" ' +
          'name="action" value="forget" class="secondary">' +
          t.html('authn.accounts.forget') + '</button>') +
      '</div></form>';
  }

  /**
   * The picker's body, under the language chooser.
   *
   * @param view - the picker's view
   * @param ctx - the surface's context; its `t` is the page's translator,
   *   its `error` an act's refusal (English)
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const esc = WebAuthnLogin.esc;
    const accounts: Json[] = Array.isArray(v.accounts) ? v.accounts : [];
    const live = accounts.filter(function (one) {
      return one.state === 'signed-in';
    });
    const out = accounts.filter(function (one) {
      return one.state !== 'signed-in';
    });
    const open = !(v.another && v.another.open === false);
    const error = String((ctx && ctx.error) || '');
    let i = 0;
    return '<h1>' + t.html('authn.accounts.heading') + '</h1>' +
      '<p class="sub">' + t.html('authn.accounts.at',
                                 { base: String(v.base) }) + '</p>' +
      (error ? '<div class="err" id="accounts-error">' + esc(error) +
               '</div>' : '') +
      (v.application
        ? '<p>' + t.html('authn.accounts.blurbNamed',
                         { application: String(v.application) }) + '</p>'
        : '<p>' + t.html('authn.accounts.blurb') + '</p>') +
      (live.length
        ? '<h2>' + t.html('authn.accounts.signedIn') + '</h2>' +
          '<div class="accounts" id="accounts-live">' +
          live.map(function (one) {
            return WebAuthnAccounts.row(one, i++, t);
          }).join('') + '</div>'
        : '') +
      (out.length
        ? '<h2>' + t.html('authn.accounts.signedOut') + '</h2>' +
          '<div class="accounts" id="accounts-remembered">' +
          out.map(function (one) {
            return WebAuthnAccounts.row(one, i++, t);
          }).join('') + '</div>'
        : '') +
      '<h2>' + t.html('authn.accounts.anotherHeading') + '</h2>' +
      '<form method="post" action="/authn/accounts">' +
      '<div class="row"><button type="submit" id="account-another" ' +
      'name="action" value="another"' + (open ? '' : ' disabled') + '>' +
      t.html('authn.accounts.another') + '</button></div>' +
      (open ? '' : '<p class="sub" id="accounts-full">' +
        t.html('authn.accounts.full', { max: String(v.max || '') }) +
        '</p>') +
      '</form>' +
      '<div class="meta"><div>' +
      t.html('authn.accounts.signingInFor',
             { protocol: String(v.protocol || '') }) + '</div>' +
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
    return ctx.t.text('authn.accounts.title');
  }
}

export = WebAuthnAccounts;
