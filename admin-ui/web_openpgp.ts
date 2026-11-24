// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_openpgp.ts
//
// ---------------------------------------------------------------------------
// DIRECTORY → OpenPGP KEYS (#1955 P6), drawn in the browser from `GET
// /admin-api/openpgp` (`mgmt-api/openpgp_api.ts`): one person, named by
// `user`, with their OpenPGP key, its pending challenge, its publication in
// the Web Key Directory, their S/MIME certificate and how their mail is
// encrypted; and every act the portal offers the person, posted to
// `/admin/openpgp` and so reaching `POST /admin-api/openpgp/<action>` (rule
// 7). The challenge an administrator issues is the PERSON'S to sign: the page
// shows it to hand over, and takes back what they signed.
//
// Three tabs — the person, registering a key for them, and the realm's
// directory — each framed; the lead is the Metadata.
//
// A static utility class, on `web_kit.ts`'s terms: it holds no state, logs
// nothing, and is bundled for a browser.
// ---------------------------------------------------------------------------
import WebKit = require('./web_kit');

type Json = any;

const PAGE = '/admin/openpgp';

/**
 * Draws Directory → OpenPGP keys from its view.
 */
class OpenPgpPage {
  /**
   * One act's form for the person, with its fields and button.
   *
   * @param user - the person
   * @param action - the act
   * @param fields - the HTML of its fields
   * @param button - the button's HTML label
   * @param danger - whether it is destructive
   * @returns the HTML
   */
  static form(user: string, action: string, fields: string, button: string,
              danger?: boolean): string {
    const esc = WebKit.esc;
    return '<form method="post" action="' + PAGE + '" class="inline">' +
      '<input type="hidden" name="action" value="' + esc(action) + '">' +
      '<input type="hidden" name="user" value="' + esc(user) + '">' +
      fields + '<button' + (danger ? ' class="danger"' : '') +
      ' type="submit">' + button + '</button></form>';
  }

  /**
   * The person tab.
   *
   * @param t - the translator
   * @param p - the person
   * @param write - whether the reader may write
   * @returns the HTML
   */
  static personTab(t: Json, p: Json, write: boolean): string {
    return '<h2 data-tab="person">' + WebKit.esc(p.username) + '</h2>' +
      OpenPgpPage.personBody(t, p, write);
  }

  // THE TAB'S BODY, without the heading that makes it a tab of this page:
  // a person's OpenPGP and S/MIME sub-tab on Directory → Users (#2052)
  // draws the same body, and its forms post to `/admin/openpgp` and so
  // reach the same `POST /admin-api/openpgp/<action>`.
  /**
   * The person tab's body: the key, its Web Key Directory publication, the
   * mail encryption and the S/MIME certificate, each with its forms.
   *
   * @param t - the translator
   * @param p - the person
   * @param write - whether the reader may write
   * @returns the HTML
   */
  static personBody(t: Json, p: Json, write: boolean): string {
    const esc = WebKit.esc;
    const k = p.key;
    const m = p.mailEncryption || {};
    const w = p.wkd || {};
    const key = k
      ? '<table class="grid"><tbody>' +
        '<tr><th>' + t.html('consoleOpenpgp.fingerprint') + '</th><td>' +
        '<code>' + esc(k.fingerprint) + '</code></td></tr>' +
        '<tr><th>' + t.html('consoleOpenpgp.version') + '</th><td>v' +
        esc(k.version) + '</td></tr>' +
        '<tr><th>' + t.html('consoleOpenpgp.algorithm') + '</th><td>' +
        esc(k.algorithm) + (k.encryption ? ' / ' + esc(k.encryption) : '') +
        '</td></tr><tr><th>' + t.html('consoleOpenpgp.userIds') +
        '</th><td>' + (k.userIds || []).map(esc).join('<br>') +
        '</td></tr><tr><th>' + t.html('consoleOpenpgp.registered') +
        '</th><td>' + esc(k.registeredAt) + ' (' + esc(k.registeredVia) +
        ')</td></tr><tr><th>' + t.html('consoleOpenpgp.expires') +
        '</th><td>' + esc(k.expiresAt || '—') + '</td></tr></tbody>' +
        '</table>' + (write ? OpenPgpPage.form(p.username, 'remove', '',
          t.html('consoleOpenpgp.remove'), true) : '')
      : WebKit.note(t.html('consoleOpenpgp.noKey'));
    const wkd = '<p>' + (w.optedIn ? t.html('consoleOpenpgp.wkdOptedIn')
                                   : t.html('consoleOpenpgp.wkdNotOptedIn')) +
      (w.url ? ' <code>' + esc(w.url) + '</code>' : '') + '</p>' +
      (write && k ? OpenPgpPage.form(p.username, w.optedIn ? 'withdraw'
                                                           : 'publish', '',
        w.optedIn ? t.html('consoleOpenpgp.withdraw')
                  : t.html('consoleOpenpgp.publish')) : '');
    const labels: Json = { none: 'consoleOpenpgp.mail.none',
                           openpgp: 'consoleOpenpgp.mail.openpgp',
                           smime: 'consoleOpenpgp.mail.smime' };
    const choices = ['none', 'openpgp', 'smime'].map(function (c: string) {
      return '<option value="' + c + '"' + (m.choice === c ? ' selected' : '') +
        '>' + t.html(labels[c]) + '</option>';
    }).join('');
    const mail = '<p>' + t.html('consoleOpenpgp.mailNow', {
      choice: t.text(labels[m.choice] || labels.none) }) + '</p>' +
      (m.smimeCertificate ? '<p>' + t.html('consoleOpenpgp.smimeCurrent', {
        subject: m.smimeCertificate.subject,
        serial: m.smimeCertificate.serial }) + '</p>'
        : (m.smimeProblem ? WebKit.note(esc(m.smimeProblem)) : '')) +
      (write ? OpenPgpPage.form(p.username, 'mail-encryption',
        '<select name="choice">' + choices + '</select>',
        t.html('consoleOpenpgp.save')) +
        '<br>' + OpenPgpPage.form(p.username, 'smime',
          '<textarea name="certificate" rows="4" cols="60"></textarea>',
          t.html('consoleOpenpgp.smimeSet')) : '');
    return WebKit.frame('<p>' + t.html('consoleOpenpgp.mailAddress') +
      ' <code>' +
        esc(p.mail || '—') + '</code></p>' + key + '<h3>' +
        t.html('consoleOpenpgp.wkdHeading') + '</h3>' + wkd + '<h3>' +
        t.html('consoleOpenpgp.mailHeading') + '</h3>' + mail);
  }

  /**
   * The registration tab: issue a challenge, then take back what was signed.
   *
   * @param t - the translator
   * @param p - the person
   * @param write - whether the reader may write
   * @returns the HTML
   */
  static registerTab(t: Json, p: Json, write: boolean): string {
    return '<h2 data-tab="register">' + t.html('consoleOpenpgp.registerTab') +
      '</h2>' + OpenPgpPage.registerBody(t, p, write);
  }

  /**
   * The registration tab's body, for this page and a person's sub-tab
   * (#2052).
   *
   * @param t - the translator
   * @param p - the person
   * @param write - whether the reader may write
   * @returns the HTML
   */
  static registerBody(t: Json, p: Json, write: boolean): string {
    const esc = WebKit.esc;
    const c = p.challenge;
    const body = !write ? WebKit.note(t.html('consoleOpenpgp.readOnly'))
      : (c ? '<p>' + t.html('consoleOpenpgp.challengeShown', {
          at: c.expiresAt }) + '</p><pre>' + esc(c.text) + '</pre>' +
          OpenPgpPage.form(p.username, 'register',
            '<label>' + t.html('consoleOpenpgp.publicKey') +
            '<br><textarea name="publicKey" rows="6" cols="66"></textarea>' +
            '</label><br><label>' + t.html('consoleOpenpgp.signed') +
            '<br><textarea name="signed" rows="6" cols="66"></textarea>' +
            '</label><br>', t.html('consoleOpenpgp.register')) +
          OpenPgpPage.form(p.username, 'challenge', '',
                           t.html('consoleOpenpgp.challengeAgain'))
        : OpenPgpPage.form(p.username, 'challenge', '',
                           t.html('consoleOpenpgp.challenge')));
    return WebKit.frame(WebKit.note(
      t.html('consoleOpenpgp.registerWhat')) + body);
  }

  /**
   * A person's OpenPGP and S/MIME sub-tab on Directory → Users (#2052):
   * this page's two person bodies, from `GET /admin-api/openpgp?user=`.
   *
   * @param t - the translator
   * @param v - the composed answer
   * @param write - whether the reader may write
   * @returns the HTML
   */
  static personPanel(t: Json, v: Json, write: boolean): string {
    if (!v || !v.person) {
      return WebKit.frame(WebKit.note(
        t.html('consoleOpenpgp.personUnavailable')));
    }
    return OpenPgpPage.personBody(t, v.person, write) +
      '<h3>' + t.html('consoleOpenpgp.registerTab') + '</h3>' +
      OpenPgpPage.registerBody(t, v.person, write) +
      '<p class="sub"><a href="' + PAGE + '">' +
      t.html('consoleOpenpgp.central') + '</a></p>';
  }

  /**
   * Draws the page's body.
   *
   * @param view - `GET /admin-api/openpgp`'s answer
   * @param ctx - the render context: the translator, the page's query and
   *   whether the reader may write
   * @returns the body as HTML
   */
  static render(view: Json, ctx: Json): string {
    const c = ctx || WebKit.context();
    const t = c.t;
    const v = view || {};
    const esc = WebKit.esc;
    // The person tab, whether this form is drawn in it or above it on
    // Metadata: a search answers there.
    const find = '<form method="get" action="' + PAGE +
      '#openpgp-tab-person"><div ' +
      'class="formrow"><label for="pgp-user">' +
      t.html('consoleOpenpgp.user') + '</label><input type="text" ' +
      'id="pgp-user" name="user" size="24" maxlength="256" value="' +
      esc(v.user || '') + '"><button type="submit">' +
      t.html('consoleOpenpgp.show') + '</button></div></form>';
    const person = v.person
      ? OpenPgpPage.personTab(t, v.person, !!c.write) +
        OpenPgpPage.registerTab(t, v.person, !!c.write)
      : '<h2 data-tab="person">' + t.html('consoleOpenpgp.personTab') +
        '</h2>' + WebKit.frame(find + (v.user
          ? WebKit.note(t.html('consoleOpenpgp.nobody', { user: v.user }))
          : WebKit.note(t.html('consoleOpenpgp.namePerson')))) +
        '<h2 data-tab="register">' + t.html('consoleOpenpgp.registerTab') +
        '</h2>' + WebKit.frame(WebKit.note(
          t.html('consoleOpenpgp.namePerson')));
    const w = v.wkd || {};
    const directory = '<h2 data-tab="directory">' +
      t.html('consoleOpenpgp.directoryTab') + '</h2>' +
      WebKit.frame('<p>' + (w.enabled ? t.html('consoleOpenpgp.wkdOn')
                                      : t.html('consoleOpenpgp.wkdOff')) +
        '</p><p>' + t.html('consoleOpenpgp.wkdDomains') + ' ' +
        ((w.domains || []).map(function (d: string): string {
          return '<code>' + esc(d) + '</code>';
        }).join(', ') || '—') + '</p>' +
        WebKit.note(t.html('consoleOpenpgp.wkdWhat')));
    return WebKit.note(t.html('consoleOpenpgp.lead'),
                       t.text('consoleOpenpgp.whatThisIs')) +
      (v.person ? find : '') + person + directory;
  }
}

export = OpenPgpPage;
