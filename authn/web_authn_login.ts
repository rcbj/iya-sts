// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_authn_login.ts
//
// ---------------------------------------------------------------------------
// THE SIGN-IN SCREEN, DRAWN IN THE BROWSER (#571, 2026-10-12).
//
// `/authn/login` was drawn by `authn.ts`'s `loginPage()` until #571. This is
// its renderer now: the screen's body drawn from `GET
// /authn-api/pending/{id}`'s view (`Authn.screenView()`) in the page's
// language, from the `authn` catalog namespace #539 wrote for this page,
// word for word, and with the element ids every test, password manager and
// person's muscle memory knows (`username`, `password`, `kc-login`,
// `kc-cancel`, `kc-anonymous`, `use_webauthn`, `webauthn_only`,
// `remember_browser`, `wa-passkey-go`, `kc-email-code`, `kc-email-link`,
// `wallet-signin`, `siop-signin`, `wallet-mfa-note`, `wallet-withheld`).
//
// THE VIEW IS LANGUAGE-FREE AND THE DECISIONS ARE THE SERVER'S: which doors,
// which boxes checked and disabled, which partner buttons — each is a fact
// of the view, and this module only chooses the words for it. The form is
// the runtime's to send (`web_authn.ts`), each button the act its `action`
// names, so nothing here posts anywhere by itself.
//
// SCRIPT IS REQUIRED (rcbj on #569): the shell's `<noscript>` says so, and
// nothing here is a fallback for a browser without it.
//
// A `web_` MODULE: it requires nothing and logs nothing — it runs in a
// browser, and in node where `tests/web_surfaces.js` draws it from the same
// view to compare.
// ---------------------------------------------------------------------------

// The console's prose fold (`WebKit.note()`), the standard collapsible
// text the sign-out page uses too: a paragraph longer than a line becomes a
// `<details>` whose summary is its first sentence (rcbj, 2026-10-12).
import kit = require('../admin-ui/web_kit');

type Json = any;

/**
 * The sign-in screen's renderer. A static utility class.
 */
class WebAuthnLogin {
  /**
   * Escapes text for HTML, as `Html.esc()` does.
   *
   * @param value - anything
   * @returns the escaped text
   */
  static esc(value: unknown): string {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * The opening of a box's label: `chk`, and `off` beside it where the box
   * is disabled, which the card draws greyed (#608).
   *
   * @param disabled - whether the box in it is disabled
   * @returns the label's opening tag
   */
  static chk(disabled: boolean): string {
    return '<label class="chk' + (disabled ? ' off' : '') + '">';
  }

  /**
   * The two passkey boxes, the policy's sentences and the demands' notes —
   * `loginPage()`'s rules, each a fact of the view.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the markup
   */
  static keyBoxes(v: Json, t: Json): string {
    const keys = v.keys || {};
    const d = v.demands || {};
    const chk = WebAuthnLogin.chk;
    let out = keys.enabled ? '' : chk(true) + '<input type="checkbox" ' +
      'disabled> ' + t.html('authn.login.passkeysOff') + '</label>';
    if (keys.enabled && keys.mfaAllowed) {
      // A box CHECKED by a demand is disabled too, but it is in force rather
      // than unavailable, so it is not greyed.
      out += chk(!!d.passwordless) + '<input type="checkbox" ' +
        'id="use_webauthn" name="use_webauthn" value="1"' +
        (d.mfa || d.key ? ' checked disabled' : '') +
        (d.passwordless ? ' disabled' : '') + '> ' +
        t.html('authn.login.keySecond') +
        (d.passwordless ? t.html('authn.login.keySecondNotAvailable') : '') +
        (d.key ? (d.mfa ? t.html('authn.login.keySecondRequiredSecond')
                        : t.html('authn.login.keySecondRequired')) : '') +
        '</label>' +
        (d.mfa || d.key
          ? '<input type="hidden" name="use_webauthn" value="1">' : '');
    } else if (keys.enabled) {
      out += chk(true) + '<input type="checkbox" disabled> ' +
        t.html('authn.login.keySecondOff') + '</label>';
    }
    if (keys.enabled && keys.primaryAllowed && !v.locked) {
      out += chk(!!d.mfa) + '<input type="checkbox" id="webauthn_only" ' +
        'name="webauthn_only" value="1"' + (d.mfa ? ' disabled' : '') +
        (d.passwordless ? ' checked disabled' : '') + '> ' +
        t.html('authn.login.keyOnly') +
        (d.key && !d.mfa ? t.html('authn.login.keyOnlyAccepted') : '') +
        (d.mfa ? t.html('authn.login.keyOnlyNotAvailable') : '') +
        (d.passwordless
          ? (d.via ? t.html('authn.login.keyOnlyRequiredRelationship',
                            { name: d.via })
                   : t.html('authn.login.keyOnlyRequiredApplication'))
          : '') + '</label>' +
        (d.passwordless
          ? '<input type="hidden" name="webauthn_only" value="1">' : '');
    } else if (keys.enabled) {
      out += chk(true) + '<input type="checkbox" disabled> ' +
        t.html('authn.login.keyOnlyOff') +
        (d.passwordless
          ? ' ' + t.html('authn.login.keyOnlyCannotComplete',
                         { name: d.via || '' }) : '') + '</label>';
    }
    return out;
  }

  /**
   * "Remember this browser" (#265), where the realm offers it.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the markup, or ''
   */
  static rememberBox(v: Json, t: Json): string {
    return v.remember
      ? '<label class="chk"><input type="checkbox" id="remember_browser" ' +
        'name="remember_browser" value="1"> ' +
        t.html('authn.login.remember') + ' <span class="sub">' +
        t.html('authn.login.rememberNote') + '</span></label>'
      : '';
  }

  /**
   * The form: the username, the password, the boxes and the buttons — or,
   * where the application allows nothing on this screen, only Cancel.
   *
   * @param v - the view
   * @param t - the translator
   * @param ctx - the context: `autofill` false after a refused passkey
   * @returns the markup
   */
  static form(v: Json, t: Json, ctx: Json): string {
    const esc = WebAuthnLogin.esc;
    if (!v.screen) {
      return '<form method="post" action="/authn/login"><p class="sub">' +
        t.html('authn.login.noScreen') + '</p><div class="row"><button ' +
        'type="submit" id="kc-cancel" name="action" value="cancel" ' +
        'class="secondary">' + t.html('authn.login.cancel') +
        '</button></div></form>';
    }
    const autofill = v.passkey && !(ctx && ctx.autofill === false);
    const email = v.email || {};
    // A PASSKEY WITH NO USERNAME, REQUIRED (#608): no username field and no
    // Sign In — the passkey button is the way in, beside Cancel.
    if (v.usernameless) {
      return '<form method="post" action="/authn/login">' +
        (v.fingerprint
          ? '<input type="hidden" name="device_fp" id="device-fp" value="">'
          : '') +
        WebAuthnLogin.keyBoxes(v, t) +
        WebAuthnLogin.rememberBox(v, t) +
        '<div class="row"><button type="submit" id="wa-passkey-go" ' +
        'name="action" value="passkey">' + t.html('authn.login.passkey') +
        '</button><button type="submit" id="kc-cancel" name="action" ' +
        'value="cancel" class="secondary">' + t.html('authn.login.cancel') +
        '</button></div></form>';
    }
    return '<form method="post" action="/authn/login">' +
      (v.fingerprint
        ? '<input type="hidden" name="device_fp" id="device-fp" value="">'
        : '') +
      '<label for="username">' + t.html('authn.login.username') +
      '</label><input type="text" id="username" name="username" ' +
      // `webauthn` LAST in the token list (HTML's autofill detail tokens):
      // the field offers this realm's passkeys where the browser supports
      // conditional mediation, and is an ordinary username field elsewhere.
      'autocomplete="username' + (autofill ? ' webauthn' : '') + '" ' +
      (v.locked ? 'readonly ' : 'autofocus ') + 'value="' + esc(v.hint) +
      '">' +
      (v.password
        ? '<label for="password">' + t.html('authn.login.password') +
          '</label><input type="password" id="password" name="password" ' +
          'autocomplete="current-password">'
        : '') +
      WebAuthnLogin.keyBoxes(v, t) +
      WebAuthnLogin.rememberBox(v, t) +
      '<div class="row"><button type="submit" id="kc-login" name="action" ' +
      'value="login">' + t.html('authn.login.signIn') + '</button>' +
      (v.anonymous
        ? '<button type="submit" id="kc-anonymous" name="action" ' +
          'value="anonymous" class="secondary" title="' +
          esc(t.text('authn.login.anonymousTitle')) + '">' +
          t.html('authn.login.anonymous') + '</button>'
        : '') +
      '<button type="submit" id="kc-cancel" name="action" value="cancel" ' +
      'class="secondary">' + t.html('authn.login.cancel') +
      '</button></div>' +
      // A PASSKEY AND NO USERNAME (#474): after Sign In, so Enter in the
      // username field still means Sign In. The runtime runs the ceremony.
      (v.passkey
        ? '<div class="row"><button type="submit" id="wa-passkey-go" ' +
          'name="action" value="passkey" class="secondary">' +
          t.html('authn.login.passkey') + '</button></div>'
        : '') +
      (email.code || email.link
        ? '<div class="row">' +
          (email.code
            ? '<button type="submit" id="kc-email-code" name="action" ' +
              'value="email-code" class="secondary">' +
              t.html('authn.login.emailCode') + '</button>' : '') +
          (email.link
            ? '<button type="submit" id="kc-email-link" name="action" ' +
              'value="email-link" class="secondary">' +
              t.html('authn.login.emailLink') + '</button>' : '') +
          '</div>'
        : '') +
      '</form>';
  }

  /**
   * A list of partner buttons under a sentence. The consumer and social
   * providers (#565) come first, as a group of their own and each as
   * "Continue with …", text only: a provider's mark is under its own brand
   * rules, which is a decision this screen has not taken.
   *
   * @param links - `[{ label, protocolLabel, peer, href, category }]`
   * @param blurb - the sentence, HTML
   * @param t - the translator, for the consumer providers' buttons
   * @returns the markup
   */
  static partnerButtons(links: Json[], blurb: string, t?: Json): string {
    const esc = WebAuthnLogin.esc;
    const all = links || [];
    const consumer = all.filter(function (one: Json): boolean {
      return one.category === 'consumer';
    });
    const enterprise = all.filter(function (one: Json): boolean {
      return one.category !== 'consumer';
    });
    const social = consumer.length
      ? '<div class="social">' + consumer.map(function (one: Json): string {
          return '<a class="fedbtn" href="' + esc(one.href) + '">' +
            (t ? t.html('authn.options.continueWith',
                        { provider: String(one.label) })
               : esc(one.label)) + '</a>';
        }).join('') + '</div>'
      : '';
    return '<div class="fed">' + kit.note(blurb) + social +
      enterprise.map(function (one: Json): string {
        return '<a class="fedbtn" href="' + esc(one.href) + '">' +
          esc(one.label) + '<span>' + esc(one.protocolLabel) +
          (one.peer ? ' · ' + esc(one.peer) : '') + '</span></a>';
      }).join('') + '</div>';
  }

  /**
   * The partners, the Kerberos door and the wallet, each where offered.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the markup
   */
  static doors(v: Json, t: Json): string {
    const esc = WebAuthnLogin.esc;
    let out = '';
    const p = v.partners;
    if (p && p.options && p.options.length) {
      out += WebAuthnLogin.partnerButtons(p.options,
        p.kind === 'own-many' ? t.html('authn.options.federatedOwnMany')
          : (p.kind === 'own-one' ? t.html('authn.options.federatedOwnOne')
                                  : t.html('authn.options.federatedAny')), t);
    }
    const k = v.kerberos;
    if (k && k.state === 'withheld-key') {
      out += '<div class="fed"><p>' +
        t.html('authn.options.kerberosWithheldKey') + '</p></div>';
    } else if (k && k.state === 'withheld-mfa') {
      out += '<div class="fed"><p>' +
        t.html('authn.options.kerberosWithheldMfa') + '</p></div>';
    } else if (k) {
      out += '<div class="fed">' + kit.note(t.html('authn.options.kerberos')) +
        '<a class="fedbtn" href="' + esc(k.href) + '">' +
        t.html('authn.options.kerberosButton') +
        '<span>SPNEGO &middot; RFC 4559</span></a></div>';
    }
    const w = v.wallet;
    if (w && w.state === 'withheld') {
      out += '<div class="fed"><p id="wallet-withheld">' +
        t.html('authn.options.walletWithheld') + '</p></div>';
    } else if (w) {
      out += '<div class="fed">' + kit.note(t.html('authn.options.wallet') +
        (w.mfaNote ? ' <span id="wallet-mfa-note">' +
                     t.html('authn.options.walletMfaNote') + '</span>' : '')) +
        '<a class="fedbtn" id="wallet-signin" href="' + esc(w.href) +
        '">' + t.html('authn.options.walletButton') +
        '<span>OpenID4VP &middot; Digital Credentials API</span></a>' +
        (w.siop
          ? '<a class="fedbtn" id="siop-signin" href="' + esc(w.siop) +
            '">' + t.html('authn.options.siopButton') +
            '<span>SIOPv2 &middot; ' + t.html('authn.options.siopNote') +
            '</span></a>'
          : '') + '</div>';
    }
    return out;
  }

  /**
   * The protocol's own rows: parameter names and values, drawn as they are.
   *
   * @param details - `[{ label, value, note }]`
   * @returns the markup
   */
  static details(details: Json[]): string {
    const esc = WebAuthnLogin.esc;
    return (details || []).map(function (d: Json): string {
      return '<div>' + esc(d.label) + ': <code>' + esc(d.value) + '</code>' +
        (d.note ? ' (' + esc(d.note) + ')' : '') + '</div>';
    }).join('');
  }

  // THE POST-QUANTUM PANEL (#946): what a person reads when the passkey they
  // used is classical and the application requires a post-quantum one —
  // which a platform answering "no credential found" never said. In the
  // page's language; the refusal's own sentence, above it, stays English
  // (#539). The links are the view's: registration on the account page
  // where passkeys may be registered here, and #939's upgrade when
  // `postQuantumUpgradeOffered()` is true. Shared by the screen and the
  // passkey step's page.
  /**
   * The post-quantum panel, or ''.
   *
   * @param help - the view's `{ register, upgrade }`, or null
   * @param t - the translator
   * @returns the markup
   */
  static postQuantumPanel(help: Json, t: Json): string {
    if (!help) {
      return '';
    }
    const esc = WebAuthnLogin.esc;
    return '<div class="warn" id="authn-post-quantum-required">' +
      '<p><strong>' + t.html('authn.pqRequired.heading') + '</strong></p>' +
      '<p>' + t.html('authn.pqRequired.text') + '</p>' +
      '<p>' + t.html('authn.pqRequired.how') + '</p>' +
      (help.upgrade
        ? '<p><a id="authn-post-quantum-upgrade" href="' +
          esc(help.upgrade) + '">' + t.html('authn.pqRequired.upgrade') +
          '</a></p>' : '') +
      (help.register
        ? '<p><a id="authn-post-quantum-register" href="' +
          esc(help.register) + '">' + t.html('authn.pqRequired.register') +
          '</a></p>' : '') + '</div>';
  }

  /**
   * The sign-in screen's body, under the chooser.
   *
   * @param view - `GET /authn-api/pending/{id}`'s view
   * @param ctx - the surface's context: `t`, and `error` — an act's
   *   refusal, English — and `autofill`
   * @returns the body
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    const esc = WebAuthnLogin.esc;
    const error = [String(v.error || ''), String((ctx && ctx.error) || '')]
      .filter(Boolean).join(' ');
    return '<h1>' + t.html('authn.login.heading') + '</h1>' +
      '<p class="sub">' + t.html('authn.login.at', { base: String(v.base) }) +
      '</p>' +
      (error ? '<div class="err" id="authn-error">' + esc(error) + '</div>'
             : '') +
      // A CLASSICAL PASSKEY REFUSED WHERE A POST-QUANTUM ONE IS REQUIRED
      // (#946), after its ceremony: the panel, under the sentence.
      WebAuthnLogin.postQuantumPanel(v.postQuantumRequired, t) +
      (v.locked ? '<p class="sub">' + t.html('authn.login.linkAccount',
                                             { name: String(v.locked) }) +
                  '</p>' : '') +
      WebAuthnLogin.form(v, t, ctx) +
      (v.forgot ? '<p class="meta"><a href="' + esc(v.forgot) + '">' +
                  t.html('authn.login.forgot') + '</a></p>' : '') +
      WebAuthnLogin.doors(v, t) +
      // The explanations fold (`kit.note()`); the facts under them — the
      // protocol and its parameters — stay as lines.
      '<div class="meta">' +
      (v.verifiesCredentials
        ? kit.note(t.html('authn.login.metaChecked')) +
          kit.note(t.html('authn.login.metaPasswordlessChecked'))
        : kit.note(t.html('authn.login.metaUnchecked')) +
          kit.note(t.html('authn.login.metaPasswordlessUnchecked'))) +
      '<div>' + t.html('authn.login.signingInFor',
                       { protocol: String(v.protocol) }) + '</div>' +
      (v.passkey ? kit.note(t.html('authn.login.metaPasskey')) : '') +
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
    return ctx.t.text('authn.login.title');
  }
}

export = WebAuthnLogin;
