// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_mail.ts
//
// ---------------------------------------------------------------------------
// THE MAIL CHANNEL'S THREE PORTAL PAGES, DRAWN IN THE BROWSER (#568), from
// `portal_mail.ts`'s operations:
//
//   * `/portal/email` (signed in): the address and whether it is verified,
//     the change of address, the messages a person may decline, and what was
//     sent;
//   * `/portal/verify-email` (a link, drawn for nobody): a button, because
//     opening the link spends nothing — then the address verified;
//   * `/portal/forgot-password` (drawn for nobody): the form, one field or
//     three, and after a request the one sentence that says nothing.
//
// The refusals stay in English, as every refusal does (#539).
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// ---------------------------------------------------------------------------

import kit = require('./web_portal_kit');
import PortalShell = require('./web_portal_shell');

type Json = any;
type PortalPage = import('../types/account-api').PortalPage;

const EMAIL = kit.BASE + '/email';
const VERIFY = kit.BASE + '/verify-email';
const FORGOT = kit.BASE + '/forgot-password';

/**
 * The mail channel's portal pages. A static utility class.
 */
class MailPages {
  // A CATEGORY'S WORDS (#539): its label and description in the page's
  // language, by its id — literal keys, so the catalog test sees them. A
  // category this page does not know keeps the English the view carries.
  /**
   * A message category's label and description, as HTML.
   *
   * @param cat - the category
   * @param t - the translator
   * @returns `{ label, what }`
   */
  static wordsOf(cat: Json, t: Json): { label: string; what: string } {
    if (cat.id === 'security') {
      return { label: t.html('portalMail.category.security.label'),
               what: t.html('portalMail.category.security.what') };
    }
    if (cat.id === 'account') {
      return { label: t.html('portalMail.category.account.label'),
               what: t.html('portalMail.category.account.what') };
    }
    if (cat.id === 'notification') {
      return { label: t.html('portalMail.category.notification.label'),
               what: t.html('portalMail.category.notification.what') };
    }
    return { label: kit.esc(cat.label), what: kit.esc(cat.what) };
  }

  /**
   * `/portal/email`'s cards.
   *
   * @param view - `GET /account-api/email`'s answer
   * @param ctx - the render context
   * @returns the HTML
   */
  static email(view: Json, ctx: Json): string {
    const t = ctx.t;
    const available = !!view.available;
    const cards: string[] = [];
    cards.push('<div class="card"><h2>' + t.html('portalMail.email.heading') +
      '</h2><table>' +
      '<tr><th>' + t.html('portalMail.email.address') + '</th><td>' +
      (view.address
        ? '<code>' + kit.esc(view.address) + '</code>'
        : t.html('portalMail.email.none')) +
      '</td></tr><tr><th>' + t.html('portalMail.email.verified') +
      '</th><td>' + (view.verified
        ? '<strong>' + t.html('portalMail.email.yes') + '</strong>'
        : t.html('portalMail.email.no')) + '</td></tr>' +
      (view.changing ? '<tr><th>' + t.html('portalMail.email.changingTo') +
                       '</th><td>' + t.html('portalMail.email.changingToValue',
                                            { address: view.changing }) +
                       '</td></tr>' : '') +
      '</table>' +
      (view.address && !view.verified && available
        ? '<form method="post" action="' + EMAIL + '">' +
          '<input type="hidden" name="action" value="verify">' +
          '<p><button type="submit">' + t.html('portalMail.email.sendVerify') +
          '</button></p></form><p class="note">' +
          t.html('portalMail.email.verifyNote') + '</p>'
        : '') +
      (!available ? '<p class="note">' +
                    t.html('portalMail.email.noMail') + '</p>' : '') +
      // CHANGING IT (#64, D5). Drawn disabled, with the reason, where mail
      // cannot be sent: the change is only ever made by following a link.
      '<h3>' + t.html('portalMail.email.changeHeading') +
      '</h3><form method="post" action="' + EMAIL + '">' +
      '<input type="hidden" name="action" value="change">' +
      '<label for="address">' + t.html('portalMail.email.newAddress') +
      '</label><input type="email" ' +
      'id="address" name="address" maxlength="254" autocomplete="email"' +
      (available ? ' required' : ' disabled') + '>' +
      '<p><button type="submit" id="email-change"' +
      (available ? '' : ' disabled') + '>' +
      t.html('portalMail.email.sendChange') + '</button></p></form>' +
      '<p class="note">' + t.html('portalMail.email.changeNote') +
      (available ? '' : ' <strong>' +
        t.html('portalMail.email.changeUnavailable') + '</strong>') +
      '</p></div>');
    const rows = (view.categories || []).map(function (cat: Json): string {
      const words = MailPages.wordsOf(cat, t);
      return '<tr><td>' + words.label + '</td><td>' + words.what +
        '</td><td>' + (cat.optional
          ? '<label><input type="checkbox" name="' + kit.esc(cat.id) +
            '" value="on"' + (cat.sent ? ' checked' : '') + '> ' +
            t.html('portalMail.sends.sendMe') + '</label>'
          : t.html('portalMail.sends.always')) + '</td></tr>';
    }).join('');
    cards.push('<div class="card"><h2>' + t.html('portalMail.sends.heading') +
      '</h2><form method="post" action="' + EMAIL + '">' +
      '<input type="hidden" name="action" value="preferences">' +
      '<table><tr><th>' + t.html('portalMail.sends.messages') + '</th><th>' +
      t.html('portalMail.sends.what') + '</th><th></th></tr>' +
      rows + '</table><p><button type="submit">' +
      t.html('portalMail.sends.save') + '</button></p></form>' +
      '<p class="note">' + t.html('portalMail.sends.note') + '</p></div>');
    const sent: Json[] = view.sent || [];
    cards.push('<div class="card"><h2>' + t.html('portalMail.sent.heading') +
      '</h2>' + (sent.length
      ? '<table><tr><th>' + t.html('portalMail.sent.when') + '</th><th>' +
        t.html('portalMail.sent.message') + '</th><th>' +
        t.html('portalMail.sent.to') + '</th><th>' +
        t.html('portalMail.sent.state') + '</th></tr>' +
        sent.map(function (row: Json): string {
          return '<tr><td>' +
            kit.esc(row.queuedAt ? t.date(Number(row.queuedAt)) : '') +
            '</td><td>' + kit.esc(row.subject) + '</td><td><code>' +
            kit.esc(row.to) + '</code></td><td>' + kit.esc(row.state) +
            '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalMail.sent.nothing') + '</p>') +
      // A page at a time, on `sentPage` (#313's sweep).
      kit.pageNav(EMAIL, ctx.query, view.sentPaging, 'sentPage', t) +
      '</div>');
    return cards.join('');
  }

  /**
   * `/portal/verify-email`'s title.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the title
   */
  static verifyTitle(view: Json, ctx: Json): string {
    if (view.refused || !view.address) {
      return 'Verify your address';
    }
    return view.verified ? ctx.t.text('portalMail.verified.title')
                         : ctx.t.text('portalMail.verify.title');
  }

  /**
   * `/portal/verify-email`'s body: a refusal, the button, or the address
   * verified.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static verify(view: Json, ctx: Json): string {
    const t = ctx.t;
    if (view.refused || !view.address) {
      return '<div class="card"><h1>Verify your address</h1>' +
        (view.refused ? '<div class="err">' + kit.esc(view.refused) +
                        '</div>' : '') + '</div>';
    }
    if (view.verified) {
      // The link is spent and opening it now is refused, so the chooser
      // returns to the account it links to.
      return '<div class="card">' +
        PortalShell.chooser(t, ctx.locale, (ctx.prefix || '') + kit.BASE) +
        '<h1>' + t.html('portalMail.verified.heading') + '</h1><p>' +
        t.html('portalMail.verified.body',
               { address: view.address, name: view.username }) +
        '</p><p><a href="' + kit.BASE + '">' +
        t.html('portalMail.verified.toAccount') + '</a></p></div>';
    }
    return '<div class="card">' +
      PortalShell.chooser(t, ctx.locale, ctx.here) +
      '<h1>' + t.html('portalMail.verify.heading') + '</h1><p>' +
      t.html('portalMail.verify.confirm',
             { address: view.address, name: view.username }) + '</p>' +
      '<form method="post" action="' + VERIFY + '">' +
      // THE TOKEN RIDES IN THE FORM, for the activation form's reason.
      '<input type="hidden" name="user" value="' + kit.esc(view.username) +
      '"><input type="hidden" name="token" value="' + kit.esc(view.token) +
      '"><button type="submit">' + t.html('portalMail.verify.button') +
      '</button></form></div>';
  }

  /**
   * `/portal/forgot-password`'s title.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the title
   */
  static forgotTitle(view: Json, ctx: Json): string {
    if (view.notOffered) {
      return 'Not offered here';
    }
    return view.tooMany ? 'Too many attempts'
                        : ctx.t.text('portalMail.forgot.title');
  }

  /**
   * `/portal/forgot-password`'s body: the form, with the one sentence once a
   * request was made.
   *
   * @param view - the view
   * @param ctx - the render context
   * @returns the HTML
   */
  static forgot(view: Json, ctx: Json): string {
    const t = ctx.t;
    if (view.notOffered) {
      return '<div class="card"><h1>Not offered here</h1><p>' +
        kit.esc(view.notOffered) + '</p></div>';
    }
    if (view.tooMany) {
      return '<div class="card"><h1>Too many attempts</h1><p>' +
        kit.esc(view.tooMany) + '</p></div>';
    }
    // The chooser returns to the form's GET — after the POST too, which
    // answers with the same form.
    const chooser = PortalShell.chooser(t, ctx.locale,
                                        (ctx.prefix || '') + FORGOT);
    const note = view.note ? '<div class="ok">' + kit.esc(view.note) +
                             '</div>' : '';
    // THREE FIELDS WHERE A RECOVERY CODE IS ASKED FOR (#64, D4).
    if (view.threeFields) {
      return '<div class="card">' + chooser + '<h1>' +
        t.html('portalMail.forgot.heading') + '</h1>' + note +
        '<p class="sub">' + t.html('portalMail.forgot.subThree') + '</p>' +
        '<form method="post" action="' + FORGOT + '">' +
        '<label for="account">' + t.html('portalMail.forgot.username') +
        '</label><input type="text" id="account" name="account" ' +
        'maxlength="256" autocomplete="username" required>' +
        '<label for="address">' + t.html('portalMail.forgot.address') +
        '</label><input type="email" id="address" name="address" ' +
        'maxlength="254" autocomplete="email" required>' +
        '<label for="code">' + t.html('portalMail.forgot.code') +
        '</label><input type="text" id="code" name="code" maxlength="64" ' +
        'autocomplete="one-time-code" autocapitalize="characters" ' +
        'spellcheck="false" required placeholder="XXXXX-XXXXX">' +
        '<button type="submit">' + t.html('portalMail.forgot.send') +
        '</button></form><p class="note">' +
        t.html('portalMail.forgot.noCodes') + '</p></div>';
    }
    return '<div class="card">' + chooser + '<h1>' +
      t.html('portalMail.forgot.heading') + '</h1>' + note +
      '<p class="sub">' + t.html('portalMail.forgot.sub') + '</p>' +
      '<form method="post" action="' + FORGOT + '">' +
      '<label for="account">' + t.html('portalMail.forgot.account') +
      '</label><input type="text" id="account" name="account" ' +
      'maxlength="256" autocomplete="username" required>' +
      '<button type="submit">' + t.html('portalMail.forgot.send') +
      '</button></form></div>';
  }

  /**
   * The pages, for `web_portal_pages.ts`.
   */
  static readonly PAGES: PortalPage[] = [
    { path: EMAIL, operation: '/account-api/email', render: MailPages.email },
    { path: VERIFY, operation: '/account-api/verify-email', access: 'link',
      render: MailPages.verify, title: MailPages.verifyTitle },
    { path: FORGOT, operation: '/account-api/forgot-password',
      access: 'public', render: MailPages.forgot,
      title: MailPages.forgotTitle }
  ];
}

export = MailPages;
