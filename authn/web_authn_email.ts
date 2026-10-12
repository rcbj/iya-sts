// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_email.ts
//
// ---------------------------------------------------------------------------
// THE EMAILED CODE AND SIGN-IN LINK PAGES, DRAWN IN THE BROWSER (#573,
// 2026-10-12).
//
// `/authn/email-code`, `/authn/email-link` and `/authn/email-link/open` were
// drawn by `email_factor.ts` until #573 (`askPage()`, `codePage()`,
// `waitPage()`, the open page and `endPage()`). These are their renderers
// now, over `GET /authn-api/mfa/{id}?page=`'s view (`EmailFactor.view()`),
// in the `emailFactor` catalogs' words, word for word, with the element ids
// the tests know (`email-send`, `code`, `email-code-submit`,
// `email-code-resend`, `email-link-resend`, `email-done`,
// `email-link-continue`, `email-error`).
//
// A view is one of six states (`ask`, `code`, `wait`, `elsewhere`, `open`,
// `end`); `email_factor.ts` says what each is. The `wait` page's `<meta>`
// refresh is the runtime's poll (`web_authn.ts`). An `end` page is a
// refusal, English every word (#539), as `endPage()` drew it.
//
// A `web_` MODULE: it requires another `web_` module only and logs nothing.
// ---------------------------------------------------------------------------

import WebAuthnLogin = require('./web_authn_login');

type Json = any;

/**
 * The emailed factor's renderers. A static utility class.
 */
class WebAuthnEmail {
  /**
   * The refusal an act left and the notice a sign-in act left, as one
   * `.err` box.
   *
   * @param v - the view (`notice`)
   * @param ctx - the context (`error`)
   * @returns the markup, or ''
   */
  static error(v: Json, ctx: Json): string {
    const text = [String((v && v.notice) || ''),
                  String((ctx && ctx.error) || '')].filter(Boolean).join(' ');
    return text ? '<div class="err" id="email-error">' +
                  WebAuthnLogin.esc(text) + '</div>' : '';
  }

  /**
   * Who the step is for, under the heading.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the markup
   */
  static forWhom(v: Json, t: Json): string {
    return '<p class="sub">' + (v.primary
      ? t.html('emailFactor.signingInAs', { name: String(v.username) })
      : t.html('emailFactor.secondFactorFor', { name: String(v.username) })) +
      '</p>';
  }

  /**
   * The other factors a second-factor step can still be finished with.
   *
   * @param v - the view (`others`)
   * @param t - the translator
   * @returns the markup
   */
  static others(v: Json, t: Json): string {
    const o = v.others || {};
    const q = '?mfa=' + encodeURIComponent(String(v.id || ''));
    return (o.totp ? '<div><a href="/authn/totp' + q + '">' +
                     t.html('emailFactor.other.totp') + '</a></div>' : '') +
      (o.webauthn ? '<div><a href="/authn/webauthn' + q + '">' +
                    t.html('emailFactor.other.securityKey') + '</a></div>'
                  : '') +
      (o.password ? '<div><a href="/authn/password-factor' + q + '">' +
                    t.html('emailFactor.other.password') + '</a></div>'
                  : '') +
      (o.backup ? '<div><a href="/authn/backup-code' + q + '">' +
                  t.html('emailFactor.other.recoveryCode') + '</a></div>'
                : '');
  }

  /**
   * A refusal that ends the page: English, as `endPage()` drew it.
   *
   * @param v - `{ title, sentence }`
   * @returns the markup
   */
  static end(v: Json): string {
    const esc = WebAuthnLogin.esc;
    return '<h1>' + esc(v.title) + '</h1><div class="err" id="email-error">' +
      esc(v.sentence) + '</div><p class="meta">Start again from the ' +
      'application that sent you here.</p>';
  }

  /**
   * The page that asks before a code or a link is mailed.
   *
   * @param v - the view
   * @param ctx - the context
   * @returns the body
   */
  static ask(v: Json, ctx: Json): string {
    const t = ctx.t;
    const code = v.kind === 'code';
    const where = String(v.address || '');
    const willSend = code
      ? (where ? t.html('emailFactor.ask.codeTo', { address: where })
               : t.html('emailFactor.ask.codeAccount'))
      : (where ? t.html('emailFactor.ask.linkTo', { address: where })
               : t.html('emailFactor.ask.linkAccount'));
    return '<h1>' + (code ? t.html('emailFactor.ask.codeHeading')
                          : t.html('emailFactor.ask.linkHeading')) + '</h1>' +
      '<p class="sub">' + t.html('emailFactor.secondFactorFor',
                                 { name: String(v.username) }) + '</p>' +
      WebAuthnEmail.error(v, ctx) + '<p>' + willSend + '</p>' +
      '<form method="post" action="' + (code ? '/authn/email-code'
                                            : '/authn/email-link') + '">' +
      '<div class="row"><button type="submit" id="email-send" name="action" ' +
      'value="send">' + t.html('emailFactor.ask.send') + '</button></div>' +
      '</form><div class="meta">' + WebAuthnEmail.others(v, t) + '</div>';
  }

  /**
   * The code page: the code was sent, type it.
   *
   * @param v - the view
   * @param ctx - the context (`notice`: `resent` after a send)
   * @returns the body
   */
  static code(v: Json, ctx: Json): string {
    const t = ctx.t;
    const where = String(v.address || '');
    return '<h1>' + t.html('emailFactor.checkEmail') + '</h1>' +
      WebAuthnEmail.forWhom(v, t) + WebAuthnEmail.error(v, ctx) +
      (ctx.notice === 'resent' ? '<div class="ok">' +
         t.html('emailFactor.code.resent') + '</div>' : '') +
      '<p>' + (where
        ? t.html('emailFactor.code.sentTo', { address: where,
                                              minutes: v.minutes })
        : t.html('emailFactor.code.sentAccount', { minutes: v.minutes })) +
      '</p><form method="post" action="/authn/email-code">' +
      '<label for="code">' + t.html('emailFactor.code.label') + '</label>' +
      '<input type="text" class="code" id="code" name="code" ' +
      'autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 -]*" ' +
      'maxlength="9" autofocus placeholder="000000">' +
      '<div class="row"><button type="submit" id="email-code-submit" ' +
      'name="action" value="verify">' + t.html('emailFactor.code.submit') +
      '</button></div></form>' +
      '<form method="post" action="/authn/email-code"><div class="row">' +
      '<button type="submit" id="email-code-resend" class="secondary" ' +
      'name="action" value="send">' + t.html('emailFactor.code.resend') +
      '</button></div></form><div class="meta"><div>' +
      t.html('emailFactor.code.note') + '</div>' +
      WebAuthnEmail.others(v, t) + '</div>';
  }

  /**
   * The page that waits for the mailed link to be opened.
   *
   * @param v - the view
   * @param ctx - the context (`notice`: `resent` after a send)
   * @returns the body
   */
  static wait(v: Json, ctx: Json): string {
    const t = ctx.t;
    const where = String(v.address || '');
    return '<h1>' + t.html('emailFactor.checkEmail') + '</h1>' +
      WebAuthnEmail.forWhom(v, t) + WebAuthnEmail.error(v, ctx) +
      (ctx.notice === 'resent' ? '<div class="ok">' +
         t.html('emailFactor.wait.resent') + '</div>' : '') +
      '<p>' + (where
        ? t.html('emailFactor.wait.sentTo', { address: where,
                                              minutes: v.minutes })
        : t.html('emailFactor.wait.sentAccount', { minutes: v.minutes })) +
      '</p><form method="post" action="/authn/email-link"><div class="row">' +
      '<button type="submit" id="email-link-resend" class="secondary" ' +
      'name="action" value="send">' + t.html('emailFactor.wait.resend') +
      '</button></div></form><div class="meta"><div>' +
      t.html('emailFactor.wait.note', { seconds: v.seconds }) + '</div>' +
      WebAuthnEmail.others(v, t) + '</div>';
  }

  /**
   * Draws an emailed factor's page from its view.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    if (v.state === 'end') {
      return WebAuthnEmail.end(v);
    }
    if (v.state === 'elsewhere') {
      return '<h1>' + t.html('emailFactor.elsewhere.heading') +
        '</h1><p id="email-done">' + t.html('emailFactor.elsewhere.body') +
        '</p>';
    }
    if (v.state === 'open') {
      return '<h1>' + t.html('emailFactor.open.heading') + '</h1>' +
        '<p class="sub">' + t.html('emailFactor.open.as',
                                   { name: String(v.username) }) + '</p>' +
        WebAuthnEmail.error(v, ctx) +
        '<form method="post" action="/authn/email-link/open">' +
        '<div class="row"><button type="submit" id="email-link-continue" ' +
        'name="action" value="open">' + t.html('emailFactor.open.continue') +
        '</button></div></form><div class="meta"><div>' +
        t.html('emailFactor.open.note') + '</div></div>';
    }
    if (v.state === 'code') {
      return WebAuthnEmail.code(v, ctx);
    }
    if (v.state === 'wait') {
      return WebAuthnEmail.wait(v, ctx);
    }
    return WebAuthnEmail.ask(v, ctx);
  }

  /**
   * The document's title.
   *
   * @param view - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    if (v.state === 'end') {
      return String(v.title) + ' — mock authentication service';
    }
    const key = v.state === 'elsewhere' ? 'emailFactor.elsewhere.title'
      : (v.state === 'open' ? 'emailFactor.open.title'
        : (v.state === 'code' ? 'emailFactor.code.title'
          : (v.state === 'wait' ? 'emailFactor.wait.title'
                                : 'emailFactor.ask.title')));
    return t.text('emailFactor.shell.title', { title: t.text(key) });
  }
}

export = WebAuthnEmail;
