// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_mail.ts — THE MAIL CHANNEL'S THREE PORTAL PAGES (#63,
// 2026-09-22): /portal/email, /portal/verify-email and
// /portal/forgot-password.
//
// **/portal/email** is behind the portal's sign-in and belongs to the person
// looking at it (portal/CLAUDE.md: no route takes an identity from the
// request). It shows the address this service writes to and whether it is
// VERIFIED, sends a verification link to it, lets the person decline the one
// category that may be declined (`notification`; security notices and links
// somebody asked for cannot be), and lists what this service has sent them —
// the template, when and what became of it, never the body.
//
// **/portal/verify-email** is the link that message carries. Nobody is signed
// in to follow it — the TOKEN is the credential, as on /portal/activate — and
// opening it SPENDS NOTHING: the page draws a button, and the address is
// verified by the POST. A mail scanner or a browser prefetch that opens every
// link in a message would otherwise verify an address nobody read.
//
// **/portal/forgot-password** is the self-service reset. A person names their
// account (by username or by the address on its entry) and the answer is ONE
// SENTENCE WHATEVER HAPPENED, sent BEFORE the work is done, so neither its
// words nor its timing say whether an account exists. It is not offered —
// and answers 404 — where `common/mail_uses.ts`'s `resetOffered()` says no:
// the setting off, no transport, or development mode, which checks no
// password and so has nothing to reset. It carries no CSRF token, because
// nobody is signed in to forge a request as: a cross-site POST can at most
// send a person a reset link they did not ask for, which the per-identity and
// per-address rate limits and the mail ceiling bound, and which changes
// nothing until the link is used.
//
// **A REAL SUBMIT BUTTON AND NO SCRIPT** on every one of them, under the
// service-wide `script-src 'none'`.
//
// **IT IS A FILE BESIDE `portal.ts`**, registered through `register(context)`
// exactly as `portal_app_passwords.ts` is, for its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import mail = require('../common/mail');
import mailUses = require('../common/mail_uses');
// THE LANGUAGE OF THESE PAGES (#539 phase 3): the chooser, on the pages
// nobody is signed in to (the shell draws it on the signed-in one).
import PageLocale = require('../common/page_locale');

type Req = import('express').Request;
type Res = import('express').Response;
type Json = any;

// What the portal hands over — `portal_app_passwords.ts`'s context, and
// `bare()` for the two pages nobody is signed in to.
interface PortalContext {
  app: {
    get(path: string, handler: (req: Req, res: Res) => unknown): unknown;
    post(path: string, handler: (req: Req, res: Res) => unknown): unknown;
  };
  BASE: string;
  log: {
    debug(message: string): void;
    info(message: string): void;
  };
  esc(value: unknown): string;
  shell(path: string, session: Json, message: unknown, error: unknown,
        body: string): string;
  send(res: Res, status: number, body: string): unknown;
  bare(title: string, inner: string, translator?: any): string;
  // The portal's translator (#539): `null` on a page nobody is signed in to.
  translatorFor(session: Json): any;
  requireSignIn(req: Req, res: Res, path: string, action: unknown): Json;
  // error-code: none — the portal helper's type, not a call to it.
  refuseShape(res: Res, result: Json): unknown;
  innerCode(result: Json): string;
  baseUrlOf(req: Req): string;
  parseBody(req: Req): Json;
  validation: Json;
  websecurity: Json;
  accessGate: Json;
  audit: Json;
  errorCodes: Json;
  config: { value(key: string): any };
}

interface PortalMailDeps {
  log: { debug(message: string): void };
  mail: Json;
  mailUses: Json;
  realms: Json;
}

// A checkbox or a flag that says yes.
function saysYes(value: unknown): boolean {
  helpers.log.debug("Entering saysYes().");
  helpers.log.debug("Leaving saysYes().");
  return ['on', 'true', '1', 'yes'].indexOf(String(value || '')) >= 0;
}

class PortalMailPage {
  readonly EMAIL: string;
  readonly VERIFY: string;
  readonly FORGOT: string;
  private readonly EMAIL_FORM: Json;
  private readonly EMAIL_QUERY: Json;
  private readonly LINK: Json;
  private readonly FORGOT_FORM: Json;

  constructor(private readonly deps: PortalMailDeps,
              private readonly ctx: PortalContext) {
    ctx.log.debug("Entering PortalMailPage.constructor().");
    const vz = ctx.validation.z;
    const vt = ctx.validation.types;
    this.EMAIL = ctx.BASE + '/email';
    this.VERIFY = ctx.BASE + '/verify-email';
    this.FORGOT = ctx.BASE + '/forgot-password';
    this.EMAIL_FORM = vz.object({
      // `change` (#64, D5): a new address, pending until its link is used.
      action: vt.opt(vt.oneOf(['verify', 'preferences', 'change'])),
      address: vz.string().max(254).optional(),
      notification: vt.opt(vt.flag),
      csrf_token: vt.opt(vt.token)
    });
    this.EMAIL_QUERY = vz.object({
      done: vz.string().max(300).optional()
    });
    this.LINK = vz.object({
      user: vt.opt(vt.name),
      token: vt.opt(vt.token)
    });
    this.FORGOT_FORM = vz.object({
      account: vz.string().max(256).optional(),
      // #64, D4: the address on the account and one recovery code, asked
      // for while `mail.resetRequiresBackupCode` is on.
      address: vz.string().max(254).optional(),
      code: vz.string().max(64).optional()
    });
    ctx.log.debug("Leaving PortalMailPage.constructor().");
  }

  // -------------------------------------------------------------------------
  // /portal/email
  // -------------------------------------------------------------------------
  private emailPage(session: Json, message: unknown, error: unknown): string {
    const { log, shell, esc, websecurity } = this.ctx;
    const { mail } = this.deps;
    log.debug("Entering PortalMailPage.emailPage().");
    const t = this.ctx.translatorFor(session);
    const who = String(session.user.username);
    const person = mail.recipient(who) || { address: '', verified: false };
    const csrf = websecurity.field(session.id);
    const cards: string[] = [];
    const available = mail.available();
    // THE PENDING CHANGE (#64, D5), if one is waiting for its link.
    const entry = mail.directory() ? mail.directory().personEntry(who) : null;
    const pending = entry
      ? String(((entry.attributes || {}).stsmailverifyaddress || [])[0] || '')
      : '';
    const changing = pending && person.address &&
                     pending.toLowerCase() !== person.address.toLowerCase()
      ? pending : (pending && !person.address ? pending : '');
    cards.push('<div class="card"><h2>' + t.html('portalMail.email.heading') +
      '</h2><table>' +
      '<tr><th>' + t.html('portalMail.email.address') + '</th><td>' +
      (person.address
        ? '<code>' + esc(person.address) + '</code>'
        : t.html('portalMail.email.none')) +
      '</td></tr><tr><th>' + t.html('portalMail.email.verified') +
      '</th><td>' + (person.verified
        ? '<strong>' + t.html('portalMail.email.yes') + '</strong>'
        : t.html('portalMail.email.no')) + '</td></tr>' +
      (changing ? '<tr><th>' + t.html('portalMail.email.changingTo') +
                  '</th><td>' + t.html('portalMail.email.changingToValue',
                                       { address: changing }) +
                  '</td></tr>' : '') +
      '</table>' +
      (person.address && !person.verified && available
        ? '<form method="post" action="' + this.EMAIL + '">' + csrf +
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
      '</h3><form method="post" action="' + this.EMAIL + '">' +
      csrf + '<input type="hidden" name="action" value="change">' +
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
    const declined = mail.declined(who);
    // A CATEGORY'S WORDS (#539): its label and description in this page's
    // language, by its id — literal keys, so the catalog test sees them. A
    // category this page does not know keeps the English the table holds.
    const wordsOf = function (cat: Json): { label: string; what: string } {
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
      return { label: esc(cat.label), what: esc(cat.what) };
    };
    const rows = mail.CATEGORIES.map(function (cat: Json) {
      const words = wordsOf(cat);
      return '<tr><td>' + words.label + '</td><td>' + words.what +
        '</td><td>' + (cat.optional
          ? '<label><input type="checkbox" name="' + esc(cat.id) +
            '" value="on"' + (declined.indexOf(cat.id) < 0 ? ' checked' : '') +
            '> ' + t.html('portalMail.sends.sendMe') + '</label>'
          : t.html('portalMail.sends.always')) + '</td></tr>';
    }).join('');
    cards.push('<div class="card"><h2>' + t.html('portalMail.sends.heading') +
      '</h2>' +
      '<form method="post" action="' + this.EMAIL + '">' + csrf +
      '<input type="hidden" name="action" value="preferences">' +
      '<table><tr><th>' + t.html('portalMail.sends.messages') + '</th><th>' +
      t.html('portalMail.sends.what') + '</th><th></th></tr>' +
      rows + '</table><p><button type="submit">' +
      t.html('portalMail.sends.save') + '</button></p></form>' +
      '<p class="note">' + t.html('portalMail.sends.note') + '</p></div>');
    const sent = mail.list({ username: who }).slice(0, 20);
    // The subject, the address and the delivery state are data, drawn as
    // they are; the time is a human date in the page's language (#539).
    cards.push('<div class="card"><h2>' + t.html('portalMail.sent.heading') +
      '</h2>' + (sent.length
      ? '<table><tr><th>' + t.html('portalMail.sent.when') + '</th><th>' +
        t.html('portalMail.sent.message') + '</th><th>' +
        t.html('portalMail.sent.to') + '</th><th>' +
        t.html('portalMail.sent.state') + '</th>' +
        '</tr>' + sent.map(function (row: Json) {
          return '<tr><td>' +
            esc(row.queuedAt ? t.date(Number(row.queuedAt)) : '') +
            '</td><td>' +
            esc(row.subject) + '</td><td><code>' + esc(row.to) +
            '</code></td><td>' + esc(row.state) + '</td></tr>';
        }).join('') + '</table>'
      : '<p class="sub">' + t.html('portalMail.sent.nothing') + '</p>') +
      '</div>');
    log.debug("Leaving PortalMailPage.emailPage().");
    return shell(this.EMAIL, session, message, error, cards.join(''));
  }

  private getEmail(req: Req, res: Res): unknown {
    const ctx = this.ctx;
    const { log } = ctx;
    log.debug('Entering GET ' + this.EMAIL + '.');
    const session = ctx.requireSignIn(req, res, this.EMAIL,
                                      ctx.accessGate.ACTION.READ);
    if (!session) {
      log.debug('Leaving GET ' + this.EMAIL + '. Not signed in.');
      return undefined;
    }
    const asked = ctx.validation.check(req, 'query', this.EMAIL_QUERY);
    if (!asked.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(asked) || 'STS-PORTAL-0001');
      log.debug('Leaving GET ' + this.EMAIL + '. Malformed.');
      return ctx.refuseShape(res, asked);
    }
    log.debug('Leaving GET ' + this.EMAIL + '.');
    return ctx.send(res, 200, this.emailPage(session, asked.value.done || null,
                                             null));
  }

  private async postEmail(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { mail, mailUses } = this.deps;
    log.debug('Entering POST ' + this.EMAIL + '.');
    const session = ctx.requireSignIn(req, res, this.EMAIL,
                                      ctx.accessGate.ACTION.MANAGE_OWN);
    if (!session) {
      log.debug('Leaving POST ' + this.EMAIL + '. Not signed in.');
      return undefined;
    }
    const who = String(session.user.username);
    const posted = ctx.validation.checkParsed(ctx.parseBody(req), 'body',
                                              this.EMAIL_FORM);
    if (!posted.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(posted) || 'STS-PORTAL-0001');
      log.debug('Leaving POST ' + this.EMAIL + '. Malformed.');
      return ctx.refuseShape(res, posted);
    }
    const body = posted.value;
    const csrf = ctx.websecurity.checkCsrf(session.id, body);
    if (!csrf.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(csrf) || 'STS-PORTAL-0017');
      log.debug('Leaving POST ' + this.EMAIL + '. CSRF.');
      return ctx.send(res, 403, this.emailPage(session, null, csrf.detail));
    }
    let result: Json = null;
    if (body.action === 'verify') {
      const allowed = await ctx.websecurity.attemptShared('mail-verify', req,
                                                          who);
      if (!allowed.ok) {
        ctx.errorCodes.mark(res, ctx.innerCode(allowed) || 'STS-HTTP-0017');
        log.debug('Leaving POST ' + this.EMAIL + '. Rate limited.');
        return ctx.send(res, 429, this.emailPage(session, null,
                                                 allowed.detail));
      }
      result = mail.available()
        ? mailUses.startVerification(who, 'the portal', who)
        : ctx.errorCodes.mark({ ok: false, errors: ['This service has no ' +
            'way to send mail here at the moment.'] }, 'STS-MAIL-0032');
    } else if (body.action === 'change') {
      const allowed = await ctx.websecurity.attemptShared('mail-verify', req,
                                                          who);
      if (!allowed.ok) {
        ctx.errorCodes.mark(res, ctx.innerCode(allowed) || 'STS-HTTP-0017');
        log.debug('Leaving POST ' + this.EMAIL + '. Rate limited.');
        return ctx.send(res, 429, this.emailPage(session, null,
                                                 allowed.detail));
      }
      result = mail.available()
        ? mailUses.startAddressChange(who, String(body.address || ''),
                                      'the portal', who)
        : ctx.errorCodes.mark({ ok: false, errors: ['This service has no ' +
            'way to send mail here at the moment.'] }, 'STS-MAIL-0032');
    } else if (body.action === 'preferences') {
      result = mail.setDeclined(who, 'notification',
                                !saysYes(body.notification),
                                who);
    } else {
      result = ctx.errorCodes.mark({ ok: false, errors: ['That is not ' +
        'something this page does.'] }, 'STS-MAIL-0025');
    }
    if (!result.ok) {
      ctx.errorCodes.mark(res, ctx.errorCodes.codeOf(result) ||
                               'STS-MAIL-0025');
      log.debug('Leaving POST ' + this.EMAIL + '. Refused.');
      return ctx.send(res, 400, this.emailPage(session, null,
                                               (result.errors || [])[0]));
    }
    log.debug('Leaving POST ' + this.EMAIL + '. Done.');
    res.status(303).set('Location', this.EMAIL + '?done=' +
      encodeURIComponent(this.doneText(session, body, result))).end();
    return undefined;
  }

  // THE SUCCESS SENTENCE IN THE PERSON'S LANGUAGE (#539). `mail` and
  // `mailUses` answer an English `message`, which other callers (the console,
  // the API) still show; here the same facts are put in the page's words
  // instead, at the redirect, since the sentence travels in `?done=`. A
  // result this cannot place keeps its English, or `Done.`.
  private doneText(session: Json, body: Json, result: Json): string {
    const { log, config } = this.ctx;
    const { mail } = this.deps;
    log.debug("Entering PortalMailPage.doneText().");
    const t = this.ctx.translatorFor(session);
    const who = String(session.user.username);
    const minutes = Number(config.value('mail.verificationTtlMinutes'));
    let out = '';
    if (body.action === 'verify') {
      const person = mail.recipient(who) || { address: '' };
      out = result.verified
        ? t.text('portalMail.done.alreadyVerified',
                 { address: person.address })
        : t.text('portalMail.done.verifySent',
                 { address: person.address, minutes: minutes });
    } else if (body.action === 'change') {
      const person = mail.recipient(who) || { address: '' };
      const wanted = String(body.address || '').trim();
      out = person.address
        ? t.text('portalMail.done.changeSent',
                 { address: wanted, minutes: minutes,
                   current: person.address })
        : t.text('portalMail.done.changeSentUnset',
                 { address: wanted, minutes: minutes });
    } else if (body.action === 'preferences') {
      out = saysYes(body.notification)
        ? t.text('portalMail.done.notificationsOn')
        : t.text('portalMail.done.notificationsOff');
    }
    log.debug("Leaving PortalMailPage.doneText().");
    return out || result.message || t.text('portalMail.done.done');
  }

  // -------------------------------------------------------------------------
  // /portal/verify-email — GET draws a button, POST spends the link.
  // -------------------------------------------------------------------------
  private verifyRefused(res: Res, status: number, code: string,
                        sentence: string): unknown {
    const { log, errorCodes, send, bare, esc } = this.ctx;
    log.debug("Entering PortalMailPage.verifyRefused(). " + code);
    errorCodes.mark(res, code);
    log.debug("Leaving PortalMailPage.verifyRefused().");
    return send(res, status, bare('Verify your address',
      '<div class="card"><h1>Verify your address</h1><div class="err">' +
      esc(sentence) + '</div></div>'));
  }

  private async verify(req: Req, res: Res, spend: boolean): Promise<unknown> {
    const ctx = this.ctx;
    const { log, esc } = ctx;
    const { mailUses } = this.deps;
    log.debug('Entering ' + (spend ? 'POST ' : 'GET ') + this.VERIFY + '.');
    const asked = spend
      ? ctx.validation.checkParsed(ctx.parseBody(req), 'body', this.LINK)
      : ctx.validation.check(req, 'query', this.LINK);
    if (!asked.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(asked) || 'STS-PORTAL-0001');
      log.debug('Leaving ' + this.VERIFY + '. Malformed.');
      return ctx.refuseShape(res, asked);
    }
    const username = String(asked.value.user || '').trim();
    const token = String(asked.value.token || '');
    const allowed = await ctx.websecurity.attemptShared('mail-verify', req,
                                                        username);
    if (!allowed.ok) {
      log.debug('Leaving ' + this.VERIFY + '. Rate limited.');
      return this.verifyRefused(res, 429,
                                ctx.innerCode(allowed) || 'STS-HTTP-0017',
                                allowed.detail);
    }
    const checked = spend ? mailUses.completeVerification(username, token)
                          : mailUses.checkVerification(username, token);
    if (!checked.ok) {
      log.debug('Leaving ' + this.VERIFY + '. Refused.');
      return this.verifyRefused(res, 400, 'STS-MAIL-0024',
                                (checked.errors || [''])[0]);
    }
    // THE LANGUAGE (#539): nobody is signed in to this page, so the
    // portal's translator for nobody, and a chooser of its own. The
    // refusals above stay English, as every refusal does.
    const t = ctx.translatorFor(null);
    if (spend) {
      log.debug('Leaving POST ' + this.VERIFY + '. Verified.');
      // No GET draws this page again — the link is spent, and opening it
      // now is refused — so the chooser returns to the account it links to.
      return ctx.send(res, 200, ctx.bare(t.text('portalMail.verified.title'),
        '<div class="card">' +
        PageLocale.chooser(t, realms.currentPrefix(),
                           PageLocale.herePath(realms.currentPrefix() +
                                               ctx.BASE)) +
        '<h1>' + t.html('portalMail.verified.heading') + '</h1><p>' +
        t.html('portalMail.verified.body',
               { address: checked.address, name: username }) +
        '</p><p><a href="' + ctx.BASE + '">' +
        t.html('portalMail.verified.toAccount') + '</a></p></div>', t));
    }
    log.debug('Leaving GET ' + this.VERIFY + '. Drawing the button.');
    return ctx.send(res, 200, ctx.bare(t.text('portalMail.verify.title'),
      '<div class="card">' +
      // Drawn by a GET only: the link itself redraws it.
      PageLocale.chooser(t, realms.currentPrefix(),
        PageLocale.herePath(realms.currentPrefix() + this.VERIFY +
          '?user=' + encodeURIComponent(username) +
          '&token=' + encodeURIComponent(token))) +
      '<h1>' + t.html('portalMail.verify.heading') + '</h1><p>' +
      t.html('portalMail.verify.confirm',
             { address: checked.address, name: username }) + '</p>' +
      '<form method="post" action="' + this.VERIFY + '">' +
      // THE TOKEN RIDES IN THE FORM, for the activation form's reason.
      '<input type="hidden" name="user" value="' + esc(username) + '">' +
      '<input type="hidden" name="token" value="' + esc(token) + '">' +
      '<button type="submit">' + t.html('portalMail.verify.button') +
      '</button></form></div>', t));
  }

  // -------------------------------------------------------------------------
  // /portal/forgot-password
  // -------------------------------------------------------------------------
  // THE LANGUAGE (#539): nobody is signed in to this page, so the portal's
  // translator for nobody, and a chooser of its own that returns to the
  // form's GET — after the POST too, which answers with the same form.
  private forgotForm(note: string): string {
    const { log, esc, bare } = this.ctx;
    log.debug("Entering PortalMailPage.forgotForm().");
    const t = this.ctx.translatorFor(null);
    const chooser = PageLocale.chooser(t, realms.currentPrefix(),
      PageLocale.herePath(realms.currentPrefix() + this.FORGOT));
    // THREE FIELDS WHERE A RECOVERY CODE IS ASKED FOR (#64, D4).
    if (this.deps.mailUses.resetNeedsRecoveryCode()) {
      log.debug("Leaving PortalMailPage.forgotForm(). Three fields.");
      return bare(t.text('portalMail.forgot.title'),
        '<div class="card">' + chooser + '<h1>' +
        t.html('portalMail.forgot.heading') + '</h1>' +
        (note ? '<div class="ok">' + esc(note) + '</div>' : '') +
        '<p class="sub">' + t.html('portalMail.forgot.subThree') + '</p>' +
        '<form method="post" action="' + this.FORGOT + '">' +
        '<label for="account">' + t.html('portalMail.forgot.username') +
        '</label>' +
        '<input type="text" id="account" name="account" maxlength="256" ' +
        'autocomplete="username" required>' +
        '<label for="address">' + t.html('portalMail.forgot.address') +
        '</label>' +
        '<input type="email" id="address" name="address" maxlength="254" ' +
        'autocomplete="email" required>' +
        '<label for="code">' + t.html('portalMail.forgot.code') +
        '</label>' +
        '<input type="text" id="code" name="code" maxlength="64" ' +
        'autocomplete="one-time-code" autocapitalize="characters" ' +
        'spellcheck="false" required placeholder="XXXXX-XXXXX">' +
        '<button type="submit">' + t.html('portalMail.forgot.send') +
        '</button></form>' +
        '<p class="note">' + t.html('portalMail.forgot.noCodes') +
        '</p></div>', t);
    }
    log.debug("Leaving PortalMailPage.forgotForm().");
    return bare(t.text('portalMail.forgot.title'),
      '<div class="card">' + chooser + '<h1>' +
      t.html('portalMail.forgot.heading') + '</h1>' +
      (note ? '<div class="ok">' + esc(note) + '</div>' : '') +
      '<p class="sub">' + t.html('portalMail.forgot.sub') + '</p>' +
      '<form method="post" action="' + this.FORGOT + '">' +
      '<label for="account">' + t.html('portalMail.forgot.account') +
      '</label>' +
      '<input type="text" id="account" name="account" maxlength="256" ' +
      'autocomplete="username" required>' +
      '<button type="submit">' + t.html('portalMail.forgot.send') +
      '</button></form></div>', t);
  }

  private notOffered(res: Res): unknown {
    const { log, errorCodes, send, bare } = this.ctx;
    log.debug("Entering PortalMailPage.notOffered().");
    errorCodes.mark(res, 'STS-MAIL-0033');
    log.debug("Leaving PortalMailPage.notOffered().");
    return send(res, 404, bare('Not offered here',
      '<div class="card"><h1>Not offered here</h1><p>A forgotten password ' +
      'cannot be reset from here. Ask whoever manages your account.</p>' +
      '</div>'));
  }

  private getForgot(req: Req, res: Res): unknown {
    const { log } = this.ctx;
    const { mailUses } = this.deps;
    log.debug('Entering GET ' + this.FORGOT + '.');
    if (!mailUses.resetOffered()) {
      log.debug('Leaving GET ' + this.FORGOT + '. Not offered.');
      return this.notOffered(res);
    }
    log.debug('Leaving GET ' + this.FORGOT + '.');
    return this.ctx.send(res, 200, this.forgotForm(''));
  }

  private async postForgot(req: Req, res: Res): Promise<unknown> {
    const ctx = this.ctx;
    const { log } = ctx;
    const { mailUses, realms } = this.deps;
    log.debug('Entering POST ' + this.FORGOT + '.');
    if (!mailUses.resetOffered()) {
      log.debug('Leaving POST ' + this.FORGOT + '. Not offered.');
      return this.notOffered(res);
    }
    const posted = ctx.validation.checkParsed(ctx.parseBody(req), 'body',
                                              this.FORGOT_FORM);
    if (!posted.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(posted) || 'STS-PORTAL-0001');
      log.debug('Leaving POST ' + this.FORGOT + '. Malformed.');
      return ctx.refuseShape(res, posted);
    }
    const account = String(posted.value.account || '').trim();
    const allowed = await ctx.websecurity.attemptShared('forgot-password', req,
                                                        account.toLowerCase());
    if (!allowed.ok) {
      ctx.errorCodes.mark(res, ctx.innerCode(allowed) || 'STS-HTTP-0017');
      log.debug('Leaving POST ' + this.FORGOT + '. Rate limited.');
      return ctx.send(res, 429, ctx.bare('Too many attempts',
        '<div class="card"><h1>Too many attempts</h1><p>' +
        ctx.esc(allowed.detail) + '</p></div>'));
    }
    // THE ANSWER FIRST, THE WORK AFTER (header): the same page, whatever
    // becomes of the request.
    // The sentence is `mailUses.RESET_ANSWER`, in the page's language
    // (#539): the same words whatever happened, so it says no more.
    const t = ctx.translatorFor(null);
    ctx.send(res, 200, this.forgotForm(t.text('portalMail.forgot.answer')));
    const realm = realms.current();
    setImmediate(function (): void {
      realms.run(realm, function (): unknown {
        return mailUses.requestReset(account, 'the forgot-password form',
          { address: String(posted.value.address || ''),
            code: String(posted.value.code || '') })
          .catch(function (e: Json) {
            log.debug('Caught in POST forgot-password: ' +
                      ((e && e.message) || e));
          });
      });
    });
    log.debug('Leaving POST ' + this.FORGOT + '. Answered.');
    return undefined;
  }

  registerRoutes(app: PortalContext['app']): void {
    const self = this;
    const { log } = this.ctx;
    log.debug("Entering PortalMailPage.registerRoutes().");
    app.get(this.EMAIL, function (req, res) {
      return self.getEmail(req, res);
    });
    app.post(this.EMAIL, function (req, res) {
      return self.postEmail(req, res);
    });
    app.get(this.VERIFY, function (req, res) {
      return self.verify(req, res, false);
    });
    app.post(this.VERIFY, function (req, res) {
      return self.verify(req, res, true);
    });
    app.get(this.FORGOT, function (req, res) {
      return self.getForgot(req, res);
    });
    app.post(this.FORGOT, function (req, res) {
      return self.postForgot(req, res);
    });
    log.debug("Leaving PortalMailPage.registerRoutes().");
  }
}

/**
 * The portal pages at /portal/email, /portal/verify-email and
 * /portal/forgot-password: the mail channel's three portal pages: a person's
 * address, its verification, and self-service password reset (#63).
 *
 * Its routes are registered by `register()`, which `portal.ts` calls at the one
 * point in its body where the route order is right.
 */
class PortalMail {
  /**
   * Builds the page's module over its dependencies.
   *
   * @param deps - the modules the page reads and writes through
   */
  constructor(private readonly deps: PortalMailDeps) {
    deps.log.debug("Entering PortalMail.constructor().");
    deps.log.debug("Leaving PortalMail.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): PortalMailDeps {
    helpers.log.debug("Entering PortalMail.defaultDeps().");
    helpers.log.debug("Leaving PortalMail.defaultDeps().");
    return { log: helpers.log, mail: mail, mailUses: mailUses,
             realms: realms };
  }

  /**
   * Registers the page's routes on the portal's app.
   *
   * @param context - what the portal shares with its pages: the app, `BASE`,
   *   the logger, the page shell, the sign-in check and the refusal helpers
   * @returns the paths of the pages
   */
  register(context: PortalContext): { paths: string[] } {
    context.log.debug("Entering PortalMail.register().");
    const page = new PortalMailPage(this.deps, context);
    page.registerRoutes(context.app);
    context.log.debug("Leaving PortalMail.register().");
    return { paths: [page.EMAIL, page.VERIFY, page.FORGOT] };
  }
}

const slot = new InstanceSlot<PortalMail>(
  'portal/portal_mail',
  () => new PortalMail(PortalMail.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The portal pages at /portal/email, /portal/verify-email and
 * /portal/forgot-password, registered by `portal.ts`.
 * @namespace
 */
export = {
  PortalMail: PortalMail,
  installInstance: (instance: PortalMail): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  register: slot.forward('register')
};
