// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_activation.ts
//
// ---------------------------------------------------------------------------
// `/portal/activate`, DRAWN IN THE BROWSER FOR NOBODY (#568), from `GET
// /account-api/activation` and the views its POST answers
// (`account_activation.ts`): the setup form, then the passkey's ceremony and
// the authenticator app's QR code where they were chosen, then *account
// ready*. Each step after the first is drawn in place from the answer, so the
// authenticator's secret never reaches a URL or the history.
//
// THE TOKEN RIDES IN THE FORM, the one place a credential is a hidden field:
// nobody is signed in, so there is nothing else to carry it on, and a POST
// keeps it out of a referer and an access log.
//
// THE PASSKEY IS A CHECKBOX SINCE #1135 (rcbj, 2026-10-29): register one or
// not. Until then three radios asked whether it was to be used instead of a
// password or as a second step after it, which a person setting up an
// account for the first time could not be expected to answer. What the
// passkey will be is a fact the view states (`secondStep`), from whether a
// password was set and what the realm allows, and the key step and *account
// ready* say it from that.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import PortalShell = require('./web_portal_shell');
import PasswordPages = require('./web_password');
import KeysPages = require('./web_keys');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/activate';

/**
 * `/portal/activate`. A static utility class.
 */
class ActivationPages {
  /**
   * The link's two fields, carried by every step's form.
   *
   * @param view - the step's view
   * @returns the HTML
   */
  static linkFields(view: Json): string {
    return '<input type="hidden" name="user" value="' + kit.esc(view.user) +
      '"><input type="hidden" name="token" value="' + kit.esc(view.token) +
      '">';
  }

  /**
   * The first step: the password, the passkey and the authenticator app.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the HTML
   */
  static setup(view: Json, t: Json): string {
    // A view from before #1135 has no `passkeyOffered`; WebAuthn being on
    // was the whole question then.
    const offered = view.passkeyOffered === undefined
      ? !!view.webauthnEnabled : !!view.passkeyOffered;
    return '<h1>' + t.html('portal.activate.title') + '</h1>' +
      '<p class="sub">' + t.html('portal.activate.sub',
        { name: view.user, base: view.base }) + '</p>' +
      '<form method="post" action="' + PATH + '">' +
      ActivationPages.linkFields(view) +
      '<h2>' + t.html('portal.activate.passwordHeading') + '</h2>' +
      '<label for="password">' + t.html('portal.activate.password') +
      '</label><input type="password" id="password" name="password" ' +
      'autocomplete="new-password"><label for="confirm">' +
      t.html('portal.activate.confirm') + '</label><input type="password" ' +
      'id="confirm" name="confirm" autocomplete="new-password">' +
      PasswordPages.rulesNote(view.rules, t) +
      // A PASSWORD MAY BE LEFT EMPTY only where a passkey may be the only
      // way in (#1135); elsewhere the page says a password is needed, and
      // `spend()` refuses a key-only setup there (STS-PORTAL-0007).
      (offered && view.passkeyAlone !== false
        ? '<p class="note">' + t.html('portal.activate.eitherNote') + '</p>'
        : '') +
      (offered && view.passkeyAlone === false
        ? '<p class="note">' + t.html('portal.activate.passwordNeeded') +
          '</p>'
        : '') +
      (offered
        ? '<h2>' + t.html('portal.activate.passkeyHeading') + '</h2>' +
          '<p class="note">' + t.html('portal.activate.passkeyNote') +
          '</p>' +
          '<label class="chk"><input type="checkbox" name="passkey" ' +
          'value="1"> ' + t.html('portal.activate.passkeyBox') +
          '</label>' +
          // WHICH KIND, `/portal/keys`' two calls to action as radios,
          // because this one form carries a password too.
          KeysPages.kindChoice(view.kinds, t) +
          // The lane (#643), where the realm offers both.
          KeysPages.laneChoice(view.lanes, t) +
          '<p class="note">' + t.html('portal.activate.passkeyStepNote') +
          '</p>'
        : '') +
      // THE AUTHENTICATOR APP: a checkbox of its own — a SECOND factor
      // beside whichever way in was chosen. Drawn only when offered;
      // the operation checks the setting again.
      (view.totpOffered
        ? '<h2>' + t.html('portal.activate.totpHeading') + '</h2>' +
          '<label class="chk"><input type="checkbox" name="totp" ' +
          'value="1"> ' + t.html('portal.activate.totpBox') + '</label>' +
          '<p class="note">' + t.html('portal.activate.totpNote') + '</p>'
        : '') +
      '<button type="submit">' + t.html('portal.activate.continue') +
      '</button></form>';
  }

  // THE PASSKEY'S STEP (2026-10-01): `/portal/keys`' ceremony, authorised by
  // the link. The runtime runs it from `#wa-data` and sends `#wa-form`.
  /**
   * The passkey step.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the HTML
   */
  static key(view: Json, t: Json): string {
    const pending = view.pending || {};
    const securityKey = pending.kind === 'security-key';
    return '<h1>' + (securityKey ? t.html('portal.key.useHeading')
                                 : t.html('portal.key.createHeading')) +
      '</h1><p class="sub">' + (view.secondStep
        ? t.html('portal.activateKey.subMfa', { name: view.user })
        : t.html('portal.activateKey.subPrimary', { name: view.user })) +
      '</p><p class="note">' + (securityKey
        ? t.html('portal.key.promptSecurityKey')
        : t.html('portal.key.promptPasskey')) + ' ' +
      t.html('portal.activateKey.notUntil') + '</p>' +
      KeysPages.ceremonyData(pending) +
      '<button id="wa-go" type="button">' + (securityKey
        ? t.html('portal.key.register') : t.html('portal.key.create')) +
      '</button>' +
      '<form method="post" action="' + PATH + '" id="wa-form">' +
      ActivationPages.linkFields(view) +
      '<input type="hidden" name="passkey" value="1">' +
      (view.wantsTotp ? '<input type="hidden" name="totp" value="1">' : '') +
      '<input type="hidden" name="step" value="key">' +
      '<input type="hidden" name="enrolment_id" value="' +
      kit.esc(pending.id) + '">' +
      '<input type="hidden" name="credential" id="wa-credential">' +
      '<button class="secondary">' + t.html('portal.key.didNotAsk') +
      '</button></form><p class="note">' +
      t.html('portal.activateKey.cannot') + '</p>';
  }

  // THE AUTHENTICATOR APP'S STEP. The QR code is a server-drawn SVG; the
  // typed secret beside it is the whole credential, for a phone that IS the
  // browser or a desktop app with no camera.
  /**
   * The authenticator step.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the HTML
   */
  static totp(view: Json, t: Json): string {
    const e = view.enrolment || {};
    return '<h1>' + t.html('portal.totp.scanHeading') + '</h1>' +
      '<p class="sub">' + t.html('portal.activateTotp.sub',
        { name: view.user }) + '</p>' +
      (view.warning ? '<div class="err">' + kit.esc(view.warning) +
                      '</div>' : '') +
      (e.qr ? '<p><img src="' + kit.esc(e.qr) + '" width="240" ' +
              'height="240" alt="' + kit.esc(t.text('portal.totp.qrAlt')) +
              '"></p>' : '') +
      '<h2>' + t.html('portal.totp.typeIt') + '</h2><table class="grid">' +
      '<tr><th>' + t.html('portal.totp.secret') + '</th><td><code>' +
      kit.esc(e.grouped) + '</code></td></tr><tr><th>' +
      t.html('portal.totp.account') + '</th><td><code>' +
      kit.esc(view.user) + '</code></td></tr><tr><th>' +
      t.html('portal.totp.issuer') + '</th><td>' + kit.esc(e.issuer) +
      '</td></tr><tr><th>' + t.html('portal.totp.algorithm') + '</th><td>' +
      t.html('portal.totp.algorithmValue', {
        alg: 'HMAC-' + String(e.algorithm).replace(/^SHA/, 'SHA-'),
        digits: String(e.digits), period: String(e.period) }) +
      '</td></tr></table>' +
      '<form method="post" action="' + PATH + '">' +
      ActivationPages.linkFields(view) +
      '<input type="hidden" name="step" value="totp">' +
      // Whether a passkey was registered, so the page that finishes says
      // what was set up.
      (view.passkey ? '<input type="hidden" name="passkey" value="1">'
                    : '') +
      '<label for="code">' + t.html('portal.totp.codeLabel',
        { digits: String(e.digits) }) + '</label>' +
      '<input type="text" id="code" name="code" ' +
      'autocomplete="one-time-code" inputmode="numeric" maxlength="' +
      kit.esc(String(e.digits)) + '" placeholder="' +
      '0'.repeat(Number(e.digits) || 6) + '"><button type="submit">' +
      t.html('portal.activateTotp.finish') + '</button></form>' +
      '<p class="note">' + t.html('portal.activateTotp.note') + '</p>';
  }

  // *ACCOUNT READY*. THEY ARE SENT TO SIGN IN AND NOT SIGNED IN: the link
  // proved possession of a link, not the credential just configured. The
  // link is the portal's own, whose sign-in starts when it is PRESSED.
  /**
   * The finish.
   *
   * @param view - the view
   * @param t - the translator
   * @returns the HTML
   */
  static ready(view: Json, t: Json): string {
    return '<h1>' + t.html('portal.ready.heading') + '</h1>' +
      '<div class="ok">' + (view.password ? t.html('portal.ready.okPassword')
                                          : t.html('portal.ready.okSetUp')) +
      '</div>' +
      (view.warning ? '<div class="err">' + kit.esc(view.warning) +
                      '</div>' : '') +
      (view.withTotp ? '<p>' + t.html('portal.ready.totp') + '</p>' : '') +
      (view.passkey
        ? '<p>' + (view.secondStep ? t.html('portal.ready.keyMfa')
                                   : t.html('portal.ready.keyPrimary')) +
          '</p>' : '') +
      '<p><a href="' + kit.esc(view.signIn || kit.BASE) + '">' +
      t.html('portal.signIn') + '</a></p>';
  }

  /**
   * The page's body, drawn for nobody.
   *
   * @param view - the step's view
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const step = String(view.step || 'refused');
    // THE LANGUAGE CHOOSER returns to the link, whose GET draws the first
    // step again — safe to repeat, since nothing is spent until the finish;
    // after the finish, to the portal.
    const back = step === 'ready' ? (ctx.prefix || '') + kit.BASE : ctx.here;
    const chooser = PortalShell.chooser(t, ctx.locale, back);
    let inner = '';
    if (step === 'setup') {
      inner = ActivationPages.setup(view, t);
    } else if (step === 'key') {
      inner = ActivationPages.key(view, t);
    } else if (step === 'totp') {
      inner = ActivationPages.totp(view, t);
    } else if (step === 'ready') {
      inner = ActivationPages.ready(view, t);
    } else {
      inner = '<h1>' + kit.esc(view.title || 'Activation link') + '</h1>' +
        (view.refused ? '<div class="err">' + kit.esc(view.refused) +
                        '</div>' : '');
    }
    return '<div class="card">' + chooser + inner + '</div>';
  }

  /**
   * The page's title.
   *
   * @param view - the step's view
   * @param ctx - the render context
   * @returns the title
   */
  static title(view: Json, ctx: Json): string {
    const t = ctx.t;
    const step = String(view.step || 'refused');
    if (step === 'setup') {
      return t.text('portal.activate.title');
    }
    if (step === 'key') {
      return t.text('portal.key.createHeading');
    }
    if (step === 'totp') {
      return t.text('portal.activateTotp.title');
    }
    if (step === 'ready') {
      return t.text('portal.ready.title');
    }
    return String(view.title || 'Activation link');
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/activation', access: 'link',
      render: ActivationPages.render, title: ActivationPages.title }
  ];
}

export = ActivationPages;
