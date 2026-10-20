// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_mfa.ts
//
// ---------------------------------------------------------------------------
// THE SECOND-FACTOR STEPS, DRAWN IN THE BROWSER (#572, 2026-10-12).
//
// `/authn/totp`, `/authn/webauthn`, `/authn/backup-code`,
// `/authn/password-factor` and `/authn/mfa-setup` were drawn by `authn.ts`
// until #572 (`totpPage()`, `webauthnPage()`, `backupCodePage()`,
// `passwordFactorPage()`, `mfaSetupPage()` and `mfaSetupTotpPage()`). These
// are their renderers now, over `GET /authn-api/mfa/{id}?page=`'s view
// (`Authn.mfaView()`), in the `authn` catalogs' words #539 wrote for those
// pages — word for word — and with the element ids every test knows
// (`code`, `totp-submit`, `backup-submit`, `password`,
// `password-factor-submit`, `wa-go`, `wa-choices`, `mfa-setup-totp`,
// `mfa-setup-webauthn`, `mfa-setup-ignore`, `mfa-setup-confirm`,
// `wallet-second-factor`, `password-second-factor`,
// `email-second-factor`).
//
// THE VIEW IS LANGUAGE-FREE AND THE DECISIONS ARE THE SERVER'S: which ways
// round the factor a page offers, whether the passkey ceremony registers or
// asserts, which passkeys a person chooses between. Every form is the
// runtime's to send (`web_authn.ts`), each button the act its `action`
// names; the passkey button runs the ceremony there.
//
// THE TOTP SET-UP'S QR CODE IS DRAWN HERE (`common/web_qr.ts`) from the
// `otpauth:` URI the view carries: no picture crosses the API.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import WebAuthnLogin = require('./web_authn_login');
import WebQr = require('../common/web_qr');

type Json = any;

/**
 * The second-factor steps' renderers. A static utility class.
 */
class WebAuthnMfa {
  /**
   * The refusal an act left, and the problem the view carries, as one
   * `.err` box.
   *
   * @param ctx - the context: `error`
   * @param own - the view's own sentence, if any
   * @returns the markup, or ''
   */
  static error(ctx: Json, own?: string): string {
    const text = [String(own || ''), String((ctx && ctx.error) || '')]
      .filter(Boolean).join(' ');
    return text ? '<div class="err" id="authn-error">' +
                  WebAuthnLogin.esc(text) + '</div>' : '';
  }

  /**
   * The Start over control every step's page carries (rcbj, 2026-10-12):
   * a real button the runtime sends as the step's `start-over` act, which
   * ends the step and returns to the sign-in screen for the same request.
   * A form of its own, never inside another, so the button posts nothing
   * of the page's code or password boxes.
   *
   * @param t - the translator
   * @returns the markup
   */
  static startOver(t: Json): string {
    return '<form method="post" class="start-over"><div class="row">' +
      '<button type="submit" class="secondary" id="start-over" ' +
      'name="action" value="start-over">' +
      t.html('authn.startOver.button') + '</button></div>' +
      '<p class="sub">' + t.html('authn.startOver.note') + '</p></form>';
  }

  /**
   * A step's address on another of its pages.
   *
   * @param path - the page's path
   * @param v - the view
   * @returns the address
   */
  static href(path: string, v: Json): string {
    return path + '?mfa=' + encodeURIComponent(String(v.id || ''));
  }

  /**
   * The ways round the factor a page asks for, in the order each page drew
   * them.
   *
   * @param v - the view (`links`)
   * @param t - the translator
   * @param backupKey - the recovery-code link's message on this page
   * @returns the markup
   */
  static links(v: Json, t: Json, backupKey: string): string {
    const l = v.links || {};
    const href = WebAuthnMfa.href;
    let out = '';
    if (l.totp) {
      out += '<div><a href="' + href('/authn/totp', v) + '">' +
        t.html('authn.secondFactor.totpInstead') + '</a></div>';
    }
    if (l.webauthn) {
      out += '<div><a href="' + href('/authn/webauthn', v) + '">' +
        t.html('authn.secondFactor.passkeyInstead') + '</a></div>';
    }
    if (l.wallet) {
      out += '<div><a id="wallet-second-factor" href="' +
        href('/authn/wallet', v) + '">' +
        t.html('authn.secondFactor.walletInstead') + '</a></div>';
    }
    if (l.password) {
      out += '<div><a id="password-second-factor" href="' +
        href('/authn/password-factor', v) + '">' +
        t.html('authn.secondFactor.passwordInstead') + '</a></div>';
    }
    if (l.email === 'code' || l.email === 'link') {
      out += '<div><a id="email-second-factor" href="' +
        href(l.email === 'code' ? '/authn/email-code' : '/authn/email-link',
             v) + '">' +
        (l.email === 'code' ? t.html('authn.secondFactor.emailCodeInstead')
                            : t.html('authn.secondFactor.emailLinkInstead')) +
        '</a></div>';
    }
    if (l.backup && backupKey) {
      out += '<div><a href="' + href('/authn/backup-code', v) + '">' +
        t.html(backupKey) + '</a></div>';
    }
    return out;
  }

  /**
   * `/authn/totp`: the one-time code.
   *
   * @param v - the view
   * @param ctx - the context
   * @returns the body
   */
  static totp(v: Json, ctx: Json): string {
    const t = ctx.t;
    const digits = Number((v.totp && v.totp.digits) || 6);
    const period = String((v.totp && v.totp.period) || 30);
    return '<h1>' + t.html('authn.totp.heading') + '</h1><p class="sub">' +
      t.html('authn.totp.sub', { name: String(v.username) }) + '</p>' +
      WebAuthnMfa.error(ctx) +
      '<form method="post" action="/authn/totp">' +
      '<label for="code">' + t.html('authn.totp.label', { digits: digits }) +
      '</label><input type="text" class="code" id="code" name="code" ' +
      'autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]*" ' +
      'maxlength="' + digits + '" autofocus placeholder="' +
      '0'.repeat(digits) + '">' +
      '<div class="row"><button type="submit" id="totp-submit" name="action" ' +
      'value="totp">' + t.html('authn.totp.signIn') + '</button></div>' +
      '</form>' + WebAuthnMfa.startOver(t) + '<div class="meta"><div>' +
      t.html('authn.totp.meta', { period: period }) + '</div>' +
      WebAuthnMfa.links(v, t, 'authn.totp.backup') + '</div>';
  }

  /**
   * `/authn/password-factor`: the password after a wallet.
   *
   * @param v - the view
   * @param ctx - the context
   * @returns the body
   */
  static password(v: Json, ctx: Json): string {
    const t = ctx.t;
    return '<h1>' + t.html('authn.passwordFactor.heading') +
      '</h1><p class="sub">' + t.html('authn.passwordFactor.sub',
                                      { name: String(v.username) }) +
      '</p>' + WebAuthnMfa.error(ctx) +
      '<form method="post" action="/authn/password-factor">' +
      '<label for="password">' + t.html('authn.passwordFactor.password') +
      '</label><input type="password" id="password" name="password" ' +
      'autocomplete="current-password" autofocus>' +
      '<div class="row"><button type="submit" id="password-factor-submit" ' +
      'name="action" value="password">' +
      t.html('authn.passwordFactor.signIn') + '</button></div></form>' +
      WebAuthnMfa.startOver(t) + '<div class="meta"><div>' + t.html('authn.passwordFactor.meta',
        { amr: JSON.stringify(v.amr || []) }) + '</div>' +
      WebAuthnMfa.links(v, t, '') + '</div>';
  }

  /**
   * `/authn/backup-code`: a recovery code in place of the second factor.
   *
   * @param v - the view
   * @param ctx - the context
   * @returns the body
   */
  static backup(v: Json, ctx: Json): string {
    const t = ctx.t;
    const b = v.backup || {};
    const back = b.back === 'webauthn' ? '/authn/webauthn'
      : (b.back === 'email-code' ? '/authn/email-code'
        : (b.back === 'email-link' ? '/authn/email-link' : '/authn/totp'));
    return '<h1>' + t.html('authn.backupCode.heading') +
      '</h1><p class="sub">' + t.html('authn.backupCode.sub',
        { factor: String(b.factor || 'app'), name: String(v.username) }) +
      '</p>' + WebAuthnMfa.error(ctx) +
      // HOW MANY ARE LEFT, ON THE WAY IN: somebody down to their last code
      // needs to know while they can still do something about it.
      (b.low ? '<div class="warn">' + t.html('authn.backupCode.low', {
                 remaining: b.remaining, total: b.total }) + '</div>' : '') +
      '<form method="post" action="/authn/backup-code">' +
      '<label for="code">' + t.html('authn.backupCode.label') + '</label>' +
      '<input type="text" id="code" name="code" autocomplete="one-time-code" ' +
      'autocapitalize="characters" spellcheck="false" maxlength="64" ' +
      'autofocus placeholder="XXXXX-XXXXX">' +
      '<div class="row"><button type="submit" id="backup-submit" ' +
      'name="action" value="backup-code">' +
      t.html('authn.backupCode.signIn') + '</button></div></form>' +
      WebAuthnMfa.startOver(t) + '<div class="meta"><div>' + t.html('authn.backupCode.once') +
      '</div>' +
      (b.total ? '<div>' + t.html('authn.backupCode.count', {
                   remaining: String(b.remaining),
                   total: String(b.total) }) + '</div>' : '') +
      // BACK TO THE MECHANISM THEY ARE CONFIGURED FOR: arriving here by
      // mistake must not cost a code.
      '<div><a href="' + WebAuthnMfa.href(back, v) + '">' +
      t.html('authn.backupCode.back', { factor: String(b.factor || 'app') }) +
      '</a></div></div>';
  }

  /**
   * `/authn/webauthn`: the passkey step, in either of its roles. The
   * ceremony is the runtime's (`#wa-go`).
   *
   * @param v - the view
   * @param ctx - the context
   * @returns the body
   */
  static webauthn(v: Json, ctx: Json): string {
    const t = ctx.t;
    const esc = WebAuthnLogin.esc;
    const w = v.webauthn || {};
    const create = w.mode === 'create';
    const choosing = Array.isArray(w.choices) && w.choices.length > 0;
    const href = WebAuthnMfa.href('/authn/webauthn', v);
    return '<h1>' + (create ? t.html('authn.webauthn.headingCreate')
                            : t.html('authn.webauthn.headingGet')) +
      '</h1><p class="sub">' + (v.passwordless
        ? t.html('authn.webauthn.subPasswordless',
                 { name: String(v.username) })
        : t.html('authn.webauthn.subSecond', { name: String(v.username) })) +
      '</p>' + WebAuthnMfa.error(ctx, w.problem) +
      (choosing
        // THE CHOICE (#534): a link per passkey, which draws this page again
        // for that one.
        ? '<p>' + t.html('authn.webauthn.choose') + '</p><ul id="wa-choices">' +
          w.choices.map(function (one: Json): string {
            return '<li><a href="' + href + '&amp;key=' +
              encodeURIComponent(String(one.id)) + '">' + esc(one.name) +
              '</a></li>';
          }).join('') + '</ul>'
        : (w.chosen
          ? '<p class="sub">' + t.html('authn.webauthn.using',
                                       { name: String(w.chosen.name) }) +
            ' &middot; <a href="' + href + '">' +
            t.html('authn.webauthn.chooseAnother') + '</a></p>'
          : '') +
          '<form method="post" action="/authn/webauthn">' +
          (w.chosen ? '<input type="hidden" name="key" value="' +
                      esc(w.chosen.id) + '">' : '') +
          (create ? WebAuthnMfa.laneChoice(w, t) : '') +
          '<div class="row"><button type="submit" id="wa-go" name="action" ' +
          'value="webauthn">' + (create ? t.html('authn.webauthn.create')
                                        : t.html('authn.webauthn.use')) +
          '</button></div></form>') +
      WebAuthnMfa.startOver(t) +
      // THE TECHNICAL LINES FOLDED (#470): a person signing in reads the
      // heading, the button and the ways out; somebody debugging opens it.
      '<details class="meta"><summary>' + t.html('authn.webauthn.details') +
      '</summary><div>' + (w.widened
        ? t.html('authn.webauthn.rpIdWidened', { rpId: String(w.rpId) })
        : t.html('authn.webauthn.rpId', { rpId: String(w.rpId) })) +
      '</div><div>challenge: <code>' + esc(w.challenge) + '</code></div>' +
      '<div>' + esc((create
        ? 'attestation ' + w.attestation + ', algorithms ' +
          (w.algorithms || []).join('/') + ', ' : '') +
        'user verification ' + w.userVerification) + ' ' +
      (w.userVerification === 'required'
        ? t.html('authn.webauthn.uvChecked')
        : t.html('authn.webauthn.uvRequested')) +
      esc(create && w.residentKey !== 'discouraged'
        ? ', resident key ' + w.residentKey : '') +
      (create && w.attachment && w.attachment !== 'any'
        ? ', ' + t.html('authn.webauthn.attachmentOnly',
                        { attachment: String(w.attachment) }) : '') +
      '</div><div>' + (create ? t.html('authn.webauthn.modeCreate')
                              : t.html('authn.webauthn.modeGet')) +
      '</div><div>' + (v.passwordless
        ? t.html('authn.webauthn.amrPasswordless',
                 { name: String(v.username) })
        : t.html('authn.webauthn.amrSecond', { name: String(v.username) })) +
      '</div></details><div class="links">' +
      WebAuthnMfa.links(v, t, 'authn.webauthn.backup') + '</div>';
  }

  // WHICH LANE (#643): a classical passkey or a post-quantum one, asked only
  // where the realm offers both (`webauthn.pqcAlongsideClassical`) and only
  // of a registration. Radios inside the ceremony's form, so the button that
  // runs the ceremony sends the choice; nothing is drawn with one lane, and
  // the request is then exactly what it was.
  /**
   * The lane choice of a registration, or ''.
   *
   * @param w - the step's passkey facts
   * @param t - the translator
   * @returns the radios, or ''
   */
  static laneChoice(w: Json, t: Json): string {
    const lanes: string[] = Array.isArray(w.lanes) ? w.lanes : [];
    if (lanes.length < 2) {
      return '';
    }
    const rows: Json = {
      classical: [t.html('authn.webauthn.laneClassical'),
                  t.html('authn.webauthn.laneClassicalWhat')],
      pqc: [t.html('authn.webauthn.lanePqc'),
            t.html('authn.webauthn.lanePqcWhat')]
    };
    const chosen = String(w.lane || 'classical');
    return '<fieldset id="wa-lanes"><legend>' +
      t.html('authn.webauthn.laneWhich') + '</legend>' +
      lanes.map(function (lane: string): string {
        return '<label><input type="radio" name="lane" value="' +
          WebAuthnLogin.esc(lane) + '"' + (lane === chosen ? ' checked' : '') +
          '> ' + rows[lane][0] + ' <span class="sub">' + rows[lane][1] +
          '</span></label>';
      }).join('<br>') + '</fieldset>';
  }

  /**
   * `/authn/mfa-setup`: the choice, or an authenticator app's secret and
   * the code that confirms it.
   *
   * @param v - the view
   * @param ctx - the context
   * @returns the body
   */
  static setup(v: Json, ctx: Json): string {
    const t = ctx.t;
    const s = v.setup || {};
    const name = String(v.username);
    const button = function (action: string, label: string): string {
      return '<form method="post" action="/authn/mfa-setup">' +
        '<div class="row"><button type="submit" id="mfa-setup-' + action +
        '" name="action" value="' + action + '">' + label +
        '</button></div></form>';
    };
    if (s.state === 'totp' && s.totp) {
      const k = s.totp;
      return '<h1>' + t.html('authn.mfaSetup.scanHeading') +
        '</h1><p class="sub">' + t.html('authn.mfaSetup.scanSub',
                                        { name: name }) + '</p>' +
        WebAuthnMfa.error(ctx) +
        '<div class="qr">' + WebQr.svg(String(k.uri), { pixels: 220,
          id: 'mfa-setup-qr', label: t.text('authn.mfaSetup.qrAlt') }) +
        '</div><p>' + t.html('authn.mfaSetup.typeIt', {
          secret: String(k.secret), algorithm: String(k.algorithm),
          digits: k.digits, period: k.period }) + '</p>' +
        '<form method="post" action="/authn/mfa-setup">' +
        '<label for="code">' + t.html('authn.mfaSetup.codeLabel',
                                      { digits: k.digits }) +
        '</label><input type="text" class="code" id="code" name="code" ' +
        'autocomplete="one-time-code" inputmode="numeric" maxlength="' +
        Number(k.digits) + '" autofocus>' +
        '<div class="row"><button type="submit" id="mfa-setup-confirm" ' +
        'name="action" value="confirm-totp">' +
        t.html('authn.mfaSetup.finish') + '</button></div></form>' +
        WebAuthnMfa.startOver(t);
    }
    const offered = s.offered || {};
    return '<h1>' + t.html('authn.mfaSetup.heading') + '</h1><p class="sub">' +
      (s.recovery ? t.html('authn.mfaSetup.subRecovery', { name: name })
        : s.proved ? t.html('authn.mfaSetup.subProved', { name: name })
        : (s.optional ? t.html('authn.mfaSetup.subOptional', { name: name })
                      : t.html('authn.mfaSetup.subRequired', { name: name }))) +
      '</p>' + WebAuthnMfa.error(ctx) +
      (offered.totp
        ? '<h2>' + t.html('authn.mfaSetup.totpHeading') + '</h2><p>' +
          t.html('authn.mfaSetup.totpText') + '</p>' +
          button('totp', t.html('authn.mfaSetup.totpButton')) : '') +
      (offered.webauthn
        ? '<h2>' + t.html('authn.mfaSetup.passkeyHeading') + '</h2><p>' +
          t.html('authn.mfaSetup.passkeyText') + '</p>' +
          button('webauthn', t.html('authn.mfaSetup.passkeyButton')) : '') +
      (s.optional
        ? '<h2>' + t.html('authn.mfaSetup.ignoreHeading') + '</h2><p>' +
          t.html('authn.mfaSetup.ignoreText') + '</p>' +
          button('ignore', t.html('authn.mfaSetup.ignoreButton')) : '') +
      WebAuthnMfa.startOver(t) + '<div class="meta">' + t.html('authn.mfaSetup.meta') + '</div>';
  }

  /**
   * The document's title for a step's page.
   *
   * @param v - the view
   * @param ctx - the context
   * @returns the title, as text
   */
  static title(v: Json, ctx: Json): string {
    const t = ctx.t;
    const page = String((v && v.page) || '');
    if (page === 'setup') {
      return t.text('authn.mfaSetup.titleSuffix', {
        title: v.setup && v.setup.state === 'totp'
          ? t.text('authn.mfaSetup.totpTitle')
          : t.text('authn.mfaSetup.title') });
    }
    return t.text(page === 'webauthn' ? 'authn.webauthn.title'
      : (page === 'backup-code' ? 'authn.backupCode.title'
        : (page === 'password' ? 'authn.passwordFactor.title'
                               : 'authn.totp.title')));
  }
}

export = WebAuthnMfa;
