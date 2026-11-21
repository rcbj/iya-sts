// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_openpgp.ts
//
// ---------------------------------------------------------------------------
// `/portal/openpgp`, DRAWN IN THE BROWSER (#1955 P6), from `GET
// /account-api/openpgp` (`account_openpgp.ts`): the person's OpenPGP key and
// how to register one — ask for a challenge, sign it with `gpg --clearsign`
// (on a YubiKey's OpenPGP card the card signs), paste it with the public
// key — its publication in the Web Key Directory, their S/MIME certificate,
// and how their mail is encrypted. Every form posts to `POST
// /portal/openpgp` (the account API's `actOnOpenPgp`) with its `action`.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const PATH = kit.BASE + '/openpgp';

/**
 * `/portal/openpgp`. A static utility class.
 */
class OpenPgpPages {
  /**
   * A form posting one act, its fields and its button.
   *
   * @param action - the act
   * @param fields - the HTML of its fields
   * @param button - the button's HTML label
   * @param danger - whether the button is a destructive one
   * @returns the HTML
   */
  static form(action: string, fields: string, button: string,
              danger?: boolean): string {
    return '<form method="post" action="' + PATH + '">' +
      '<input type="hidden" name="action" value="' + kit.esc(action) + '">' +
      fields + '<button' + (danger ? ' class="danger"' : '') +
      ' type="submit">' + button + '</button></form>';
  }

  /**
   * The key card: the registered key, or that there is none.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the HTML
   */
  static keyCard(v: Json, t: Json): string {
    const k = v.key;
    if (!k) {
      return '<div class="card"><h2>' + t.html('portalOpenpgp.key.heading') +
        '</h2><p id="openpgp-none">' + t.html('portalOpenpgp.key.none') +
        '</p></div>';
    }
    return '<div class="card"><h2>' + t.html('portalOpenpgp.key.heading') +
      '</h2><table>' +
      '<tr><th>' + t.html('portalOpenpgp.key.fingerprint') + '</th><td>' +
      '<code id="openpgp-fingerprint">' + kit.esc(k.fingerprint) +
      '</code></td></tr>' +
      '<tr><th>' + t.html('portalOpenpgp.key.version') + '</th><td>v' +
      kit.esc(k.version) + '</td></tr>' +
      '<tr><th>' + t.html('portalOpenpgp.key.algorithm') + '</th><td>' +
      kit.esc(k.algorithm) + (k.encryption ? ' / ' + kit.esc(k.encryption)
                                           : '') + '</td></tr>' +
      '<tr><th>' + t.html('portalOpenpgp.key.userIds') + '</th><td>' +
      (k.userIds || []).map(kit.esc).join('<br>') + '</td></tr>' +
      '<tr><th>' + t.html('portalOpenpgp.key.registered') + '</th><td>' +
      (k.registeredAt ? t.date(k.registeredAt) : '—') + '</td></tr>' +
      '<tr><th>' + t.html('portalOpenpgp.key.expires') + '</th><td>' +
      (k.expiresAt ? t.date(k.expiresAt)
                   : t.html('portalOpenpgp.key.never')) + '</td></tr>' +
      '</table><p class="note">' + t.html('portalOpenpgp.key.notHardware') +
      '</p>' + OpenPgpPages.form('remove', '',
        t.html('portalOpenpgp.key.remove'), true) + '</div>';
  }

  /**
   * The registration card: ask for a challenge, then sign and paste it.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the HTML
   */
  static registerCard(v: Json, t: Json): string {
    const c = v.challenge;
    const head = '<div class="card"><h2>' + t.html(v.key
      ? 'portalOpenpgp.register.replaceHeading'
      : 'portalOpenpgp.register.heading') + '</h2><p class="sub">' +
      t.html('portalOpenpgp.register.intro', { mail: v.mail || '—' }) +
      '</p>';
    if (!c) {
      return head + OpenPgpPages.form('challenge', '',
        t.html('portalOpenpgp.register.ask')) + '</div>';
    }
    return head + '<p>' + t.html('portalOpenpgp.register.step1',
                                 { at: t.date(c.expiresAt) }) + '</p>' +
      '<pre id="openpgp-challenge">' + kit.esc(c.text) + '</pre>' +
      '<p>' + t.html('portalOpenpgp.register.step2') + '</p>' +
      '<pre>gpg --clearsign &gt; signed.txt\ngpg --armor --export ' +
      kit.esc(v.mail || '<you@example.org>') + '</pre>' +
      OpenPgpPages.form('register',
        '<label for="openpgp-key">' + t.html('portalOpenpgp.register.key') +
        '</label><textarea id="openpgp-key" name="publicKey" rows="8" ' +
        'cols="66"></textarea><label for="openpgp-signed">' +
        t.html('portalOpenpgp.register.signed') + '</label><textarea ' +
        'id="openpgp-signed" name="signed" rows="8" cols="66"></textarea>',
        t.html('portalOpenpgp.register.submit')) +
      OpenPgpPages.form('challenge', '',
                        t.html('portalOpenpgp.register.again')) + '</div>';
  }

  /**
   * The Web Key Directory card.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the HTML
   */
  static wkdCard(v: Json, t: Json): string {
    const w = v.wkd || {};
    let body = '';
    if (!w.enabled) {
      body = '<p>' + t.html('portalOpenpgp.wkd.off') + '</p>';
    } else if (!w.domainServed) {
      body = '<p>' + t.html('portalOpenpgp.wkd.otherDomain') + '</p>';
    } else if (!v.key) {
      body = '<p>' + t.html('portalOpenpgp.wkd.noKey') + '</p>';
    } else if (w.optedIn) {
      body = '<p>' + t.html('portalOpenpgp.wkd.published') + '</p>' +
        (w.url ? '<p><code id="openpgp-wkd-url">' + kit.esc(w.url) +
                 '</code></p>' : '') +
        OpenPgpPages.form('withdraw', '',
                          t.html('portalOpenpgp.wkd.withdraw'));
    } else {
      body = '<p>' + t.html('portalOpenpgp.wkd.notPublished') + '</p>' +
        OpenPgpPages.form('publish', '', t.html('portalOpenpgp.wkd.publish'));
    }
    return '<div class="card"><h2>' + t.html('portalOpenpgp.wkd.heading') +
      '</h2><p class="sub">' + t.html('portalOpenpgp.wkd.intro') + '</p>' +
      body + '</div>';
  }

  /**
   * The mail encryption card, with the S/MIME certificate.
   *
   * @param v - the view
   * @param t - the translator
   * @returns the HTML
   */
  static mailCard(v: Json, t: Json): string {
    const m = v.mailEncryption || {};
    const choices = [
      { id: 'none', usable: true, label: 'portalOpenpgp.mail.none' },
      { id: 'openpgp', usable: !!m.openpgpUsable,
        label: 'portalOpenpgp.mail.openpgp' },
      { id: 'smime', usable: !!m.smimeUsable,
        label: 'portalOpenpgp.mail.smime' }
    ];
    const radios = choices.map(function (c: Json): string {
      return '<label><input type="radio" name="choice" value="' + c.id +
        '"' + (m.choice === c.id ? ' checked' : '') +
        (c.usable || m.choice === c.id ? '' : ' disabled') + '> ' +
        t.html(c.label) + '</label><br>';
    }).join('');
    const cert = m.smimeCertificate;
    return '<div class="card"><h2>' + t.html('portalOpenpgp.mail.heading') +
      '</h2><p class="sub">' + t.html('portalOpenpgp.mail.intro') + '</p>' +
      OpenPgpPages.form('mail-encryption', radios,
                        t.html('portalOpenpgp.mail.save')) +
      '<h3>' + t.html('portalOpenpgp.smime.heading') + '</h3>' +
      (cert
        ? '<p id="openpgp-smime">' + t.html('portalOpenpgp.smime.current',
            { subject: cert.subject, serial: cert.serial }) + '</p>' +
          OpenPgpPages.form('smime', '<input type="hidden" ' +
            'name="certificate" value="">',
            t.html('portalOpenpgp.smime.remove'), true)
        : '<p>' + (m.smimeProblem
            ? t.html('portalOpenpgp.smime.unusable')
            : t.html('portalOpenpgp.smime.none')) + '</p>') +
      OpenPgpPages.form('smime', '<label for="openpgp-smime-cert">' +
        t.html('portalOpenpgp.smime.paste') + '</label><textarea ' +
        'id="openpgp-smime-cert" name="certificate" rows="6" cols="66">' +
        '</textarea>', t.html('portalOpenpgp.smime.set')) + '</div>';
  }

  /**
   * The page's body.
   *
   * @param view - `GET /account-api/openpgp`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static render(view: Json, ctx: Json): string {
    const t = ctx.t;
    const v = view || {};
    return OpenPgpPages.keyCard(v, t) + OpenPgpPages.registerCard(v, t) +
      OpenPgpPages.wkdCard(v, t) + OpenPgpPages.mailCard(v, t);
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: PATH, operation: '/account-api/openpgp',
      render: OpenPgpPages.render }
  ];
}

export = OpenPgpPages;
