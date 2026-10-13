// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// portal/portal_mail.ts — THE MAIL CHANNEL'S THREE PORTAL PAGES (#63,
// 2026-09-22): /portal/email, /portal/verify-email and
// /portal/forgot-password — SIX `/account-api` OPERATIONS SINCE #568, the
// pages drawn in the browser by `web_mail.ts`.
//
// **/portal/email** is signed in and belongs to the person looking at it:
// the person is the access token's subject, and no operation takes an
// identity from the request (portal/CLAUDE.md). It shows the address this
// service writes to and whether it is VERIFIED, sends a verification link to
// it, starts a change of address (#64, D5) that is made only by following a
// link, lets the person decline the one category that may be declined
// (`notification`; security notices and links somebody asked for cannot
// be), and lists what this service has sent them — the template, when and
// what became of it, never the body.
//
// **/portal/verify-email** is the link that message carries. Nobody is
// signed in to follow it — the TOKEN is the credential, as on
// /portal/activate (`access: 'link'`) — and the GET SPENDS NOTHING: the page
// draws a button, and the address is verified by the POST. A mail scanner or
// a browser prefetch that opens every link in a message would otherwise
// verify an address nobody read.
//
// **/portal/forgot-password** is the self-service reset (`access:
// 'public'`). A person names their account (by username or by the address
// on its entry) and the answer is ONE SENTENCE WHATEVER HAPPENED, sent
// BEFORE the work is done, so neither its words nor its timing say whether
// an account exists. It is not offered — and answers 404 — where
// `common/mail_uses.ts`'s `resetOffered()` says no: the setting off, no
// transport, or development mode, which checks no password and so has
// nothing to reset. Nobody is signed in to forge a request as: a cross-site
// POST can at most send a person a reset link they did not ask for, which
// the per-identity and per-address rate limits and the mail ceiling bound,
// and which changes nothing until the link is used.
//
// A refusal carries the page's `view`, so the runtime draws the page again
// with the reason, as a re-rendered page did.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import realms = require('../common/realms');
import mail = require('../common/mail');
import mailUses = require('../common/mail_uses');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

interface PortalMailDeps {
  log: { debug(message: string): void };
  mail: Json;
  mailUses: Json;
  realms: Json;
}

// WHAT WAS SENT, A PAGE AT A TIME (#313's sweep): the outbox keeps every
// message to this person until its retention, and the page drew the newest
// twenty and silently stopped there. It pages on `sentPage`, twenty a page.
const SENT_PER_PAGE = 20;

const EMAIL_QUERY = vz.object({
  sentPage: vt.opt(vt.integer(1, 100000))
    .describe('Which page of `sent`, newest first. Clamped to the last.')
});

const EMAIL_FORM = vz.object({
  // `change` (#64, D5): a new address, pending until its link is used.
  action: vt.opt(vt.oneOf(['verify', 'preferences', 'change']))
    .describe('`verify` sends a link to the address on your entry; ' +
              '`change` sends one to `address`; `preferences` saves ' +
              '`notification`.'),
  address: vz.string().max(254).optional()
    .describe('The new address, for `change`.'),
  notification: vt.opt(vt.flag)
    .describe('`on` to be sent notifications, for `preferences`.')
});

// THE LINK'S TWO VALUES, in the query of the GET and the body of the POST.
// The token rides in the body, for the activation form's reason.
const LINK = vz.object({
  user: vt.opt(vt.name).describe('The username the link names.'),
  token: vt.opt(vt.token).describe('The link\'s single-use secret.')
});

const FORGOT_FORM = vz.object({
  account: vz.string().max(256).optional()
    .describe('Your username, or the address on your account.'),
  // #64, D4: the address on the account and one recovery code, asked for
  // while `mail.resetRequiresBackupCode` is on.
  address: vz.string().max(254).optional()
    .describe('The address on your account, where a recovery code is asked ' +
              'for.'),
  code: vz.string().max(64).optional()
    .describe('One of your recovery codes, where one is asked for.')
});

// The refusal where a forgotten password cannot be reset from here.
const NOT_OFFERED = 'A forgotten password cannot be reset from here. Ask ' +
  'whoever manages your account.';

// The refusal where no transport can send mail.
const NO_MAIL = 'This service has no way to send mail here at the moment.';

/**
 * Says whether a checkbox or a flag said yes.
 *
 * @param value - the value
 * @returns true for `on`, `true`, `1` or `yes`
 */
function saysYes(value: unknown): boolean {
  helpers.log.debug("Entering saysYes().");
  helpers.log.debug("Leaving saysYes().");
  return ['on', 'true', '1', 'yes'].indexOf(String(value || '')) >= 0;
}

/**
 * The mail channel's portal pages, as account API operations: a person's
 * address, its verification, and self-service password reset (#63).
 */
class PortalMail {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules the pages read and write through
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

  // -------------------------------------------------------------------------
  // /portal/email
  // -------------------------------------------------------------------------
  /**
   * `/portal/email`'s view: the address, whether it is verified, a pending
   * change, the categories and the person's choices, and what was sent.
   *
   * @param username - the signed-in person
   * @param wanted - the page of `sent` asked for; the first when left out
   * @returns the view
   */
  emailView(username: string, wanted?: number): Json {
    const { log, mail } = this.deps;
    log.debug("Entering PortalMail.emailView().");
    const person = mail.recipient(username) || { address: '',
                                                 verified: false };
    const available = !!mail.available();
    // THE PENDING CHANGE (#64, D5), if one is waiting for its link.
    const entry = mail.directory() ? mail.directory().personEntry(username)
                                   : null;
    const pending = entry
      ? String(((entry.attributes || {}).stsmailverifyaddress || [])[0] || '')
      : '';
    const changing = pending && person.address &&
                     pending.toLowerCase() !== person.address.toLowerCase()
      ? pending : (pending && !person.address ? pending : '');
    const declined: string[] = mail.declined(username) || [];
    const allSent: Json[] = mail.list({ username: username }) || [];
    const sentPages = Math.max(1, Math.ceil(allSent.length / SENT_PER_PAGE));
    const sentAt = Math.min(Math.max(1, Number(wanted) || 1), sentPages);
    const view = {
      address: String(person.address || ''),
      verified: !!person.verified,
      changing: changing,
      available: available,
      categories: mail.CATEGORIES.map(function (cat: Json): Json {
        return { id: cat.id, label: cat.label, what: cat.what,
                 optional: !!cat.optional,
                 sent: declined.indexOf(cat.id) < 0 };
      }),
      // The subject, the address and the delivery state are data; the time
      // is drawn as a human date in the page's language (#539).
      sent: allSent.slice((sentAt - 1) * SENT_PER_PAGE,
                          sentAt * SENT_PER_PAGE)
        .map(function (row: Json): Json {
          return { queuedAt: row.queuedAt || null, subject: row.subject,
                   to: row.to, state: row.state };
        }),
      sentPaging: { page: sentAt, pages: sentPages, per: SENT_PER_PAGE,
                    total: allSent.length }
    };
    log.debug("Leaving PortalMail.emailView().");
    return view;
  }

  // THE SUCCESS SENTENCE IN THE PERSON'S LANGUAGE (#539). `mail` and
  // `mailUses` answer an English `message`, which other callers (the console,
  // the API) still show; here the same facts are put in the page's words. A
  // result this cannot place keeps its English, or `Done.`.
  /**
   * What a successful act says.
   *
   * @param ctx - the account API's helpers
   * @param username - the signed-in person
   * @param body - the checked body
   * @param result - what the act answered
   * @returns the sentence
   */
  doneText(ctx: AccountContext, username: string, body: Json,
           result: Json): string {
    const { log, mail } = this.deps;
    log.debug("Entering PortalMail.doneText().");
    const t = ctx.translatorFor(username);
    const minutes = Number(ctx.config.value('mail.verificationTtlMinutes'));
    let out = '';
    if (body.action === 'verify') {
      const person = mail.recipient(username) || { address: '' };
      out = result.verified
        ? t.text('portalMail.done.alreadyVerified',
                 { address: person.address })
        : t.text('portalMail.done.verifySent',
                 { address: person.address, minutes: minutes });
    } else if (body.action === 'change') {
      const person = mail.recipient(username) || { address: '' };
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
    log.debug("Leaving PortalMail.doneText().");
    return out || result.message || t.text('portalMail.done.done');
  }

  /**
   * Verifies the address, starts a change of it, or saves the choices.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async postEmail(ctx: AccountContext, req: Json, res: Json,
                  caller: AccountCaller, body: Json): Promise<unknown> {
    const { log, mail, mailUses } = this.deps;
    const { errorCodes, websecurity } = ctx;
    log.debug("Entering PortalMail.postEmail().");
    const who = caller.username;
    let result: Json = null;
    if (body.action === 'verify' || body.action === 'change') {
      const allowed = await websecurity.attemptShared('mail-verify', req, who);
      if (!allowed.ok) {
        log.debug("Leaving PortalMail.postEmail(). Rate limited.");
        return ctx.refuse(res, 429, errorCodes.codeOf(allowed) ||
                          'STS-HTTP-0017', allowed.detail,
                          { view: this.emailView(who) });
      }
      if (!mail.available()) {
        result = errorCodes.mark({ ok: false, errors: [NO_MAIL] },
                                 'STS-MAIL-0032');
      } else if (body.action === 'verify') {
        result = mailUses.startVerification(who, 'the portal', who);
      } else {
        result = mailUses.startAddressChange(who, String(body.address || ''),
                                             'the portal', who);
      }
    } else if (body.action === 'preferences') {
      result = mail.setDeclined(who, 'notification',
                                !saysYes(body.notification), who);
    } else {
      result = errorCodes.mark({ ok: false, errors: ['That is not ' +
        'something this page does.'] }, 'STS-MAIL-0025');
    }
    if (!result.ok) {
      log.debug("Leaving PortalMail.postEmail(). Refused.");
      return ctx.refuse(res, 400, errorCodes.codeOf(result) ||
                        'STS-MAIL-0025',
                        (result.errors || ['That could not be done.'])[0],
                        { view: this.emailView(who) });
    }
    log.debug("Leaving PortalMail.postEmail(). Done.");
    return ctx.json(res, 200, { ok: true,
      message: this.doneText(ctx, who, body, result) });
  }

  // -------------------------------------------------------------------------
  // /portal/verify-email — the GET checks and spends nothing, the POST
  // spends the link.
  // -------------------------------------------------------------------------
  /**
   * Checks an address verification link, or spends it.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param link - the checked `user` and `token`
   * @param spend - true for the POST
   * @returns nothing
   */
  async verify(ctx: AccountContext, req: Json, res: Json, link: Json,
               spend: boolean): Promise<unknown> {
    const { log, mailUses } = this.deps;
    const { errorCodes, websecurity } = ctx;
    log.debug("Entering PortalMail.verify(). " + (spend ? 'POST' : 'GET'));
    const username = String(link.user || '').trim();
    const token = String(link.token || '');
    const allowed = await websecurity.attemptShared('mail-verify', req,
                                                    username);
    if (!allowed.ok) {
      log.debug("Leaving PortalMail.verify(). Rate limited.");
      return ctx.refuse(res, 429, errorCodes.codeOf(allowed) ||
                        'STS-HTTP-0017', allowed.detail,
                        { view: { refused: allowed.detail } });
    }
    const checked = spend ? mailUses.completeVerification(username, token)
                          : mailUses.checkVerification(username, token);
    if (!checked.ok) {
      log.debug("Leaving PortalMail.verify(). Refused.");
      const sentence = (checked.errors || [''])[0];
      return ctx.refuse(res, 400, 'STS-MAIL-0024', sentence,
                        { view: { refused: sentence } });
    }
    if (spend) {
      log.debug("Leaving PortalMail.verify(). Verified.");
      // Drawn from this view in place: the link is spent, and opening it
      // now is refused.
      return ctx.json(res, 200, { ok: true,
        view: { verified: true, address: checked.address,
                username: username } });
    }
    log.debug("Leaving PortalMail.verify(). The button.");
    return ctx.json(res, 200, { address: checked.address,
                                username: username, token: token });
  }

  // -------------------------------------------------------------------------
  // /portal/forgot-password
  // -------------------------------------------------------------------------
  /**
   * The form's view: whether the three-field form is asked for.
   *
   * @returns the view
   */
  forgotView(): Json {
    const { log, mailUses } = this.deps;
    log.debug("Entering PortalMail.forgotView().");
    log.debug("Leaving PortalMail.forgotView().");
    // THREE FIELDS WHERE A RECOVERY CODE IS ASKED FOR (#64, D4).
    return { threeFields: !!mailUses.resetNeedsRecoveryCode() };
  }

  /**
   * Refuses the forgot-password form where it is not offered: 404.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @returns nothing
   */
  notOffered(ctx: AccountContext, res: Json): unknown {
    const { log } = this.deps;
    log.debug("Entering PortalMail.notOffered().");
    log.debug("Leaving PortalMail.notOffered().");
    return ctx.refuse(res, 404, 'STS-MAIL-0033', NOT_OFFERED,
                      { view: { notOffered: NOT_OFFERED } });
  }

  /**
   * Answers the one sentence, then asks for a reset link after the answer.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param body - the checked body
   * @returns nothing
   */
  async postForgot(ctx: AccountContext, req: Json, res: Json,
                   body: Json): Promise<unknown> {
    const { log, mailUses, realms } = this.deps;
    const { errorCodes, websecurity } = ctx;
    log.debug("Entering PortalMail.postForgot().");
    if (!mailUses.resetOffered()) {
      log.debug("Leaving PortalMail.postForgot(). Not offered.");
      return this.notOffered(ctx, res);
    }
    const account = String(body.account || '').trim();
    const allowed = await websecurity.attemptShared('forgot-password', req,
                                                    account.toLowerCase());
    if (!allowed.ok) {
      log.debug("Leaving PortalMail.postForgot(). Rate limited.");
      return ctx.refuse(res, 429, errorCodes.codeOf(allowed) ||
                        'STS-HTTP-0017', allowed.detail,
                        { view: Object.assign(this.forgotView(),
                                              { tooMany: allowed.detail }) });
    }
    // THE ANSWER FIRST, THE WORK AFTER (header): the same page, whatever
    // becomes of the request. The sentence is `mailUses.RESET_ANSWER`, in
    // the page's language (#539): the same words whatever happened, so it
    // says no more.
    const t = ctx.translatorFor('');
    ctx.json(res, 200, { ok: true, view: Object.assign(this.forgotView(),
      { note: t.text('portalMail.forgot.answer') }) });
    const realm = realms.current();
    setImmediate(function (): void {
      realms.run(realm, function (): unknown {
        return mailUses.requestReset(account, 'the forgot-password form',
          { address: String(body.address || ''),
            code: String(body.code || '') })
          .catch(function (e: Json) {
            log.debug('Caught in PortalMail.postForgot(): ' +
                      ((e && e.message) || e));
          });
      });
    });
    log.debug("Leaving PortalMail.postForgot(). Answered.");
    return undefined;
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log, mailUses } = this.deps;
    const self = this;
    log.debug("Entering PortalMail.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/email', operationId: 'getEmail',
        tag: 'Email', access: 'person', mirrors: 'GET ' + ctx.PORTAL +
                                                 '/email',
        summary: 'Your email address, its messages, and what was sent',
        description: '`address` and whether it is `verified`, a change ' +
          'waiting for its link (`changing`), whether mail can be sent ' +
          '(`available`), the message `categories` (only `notification` ' +
          'is `optional`; `sent` says whether you are sent it), and one ' +
          'page of the messages `sent` to you, newest first — never their ' +
          'bodies — moved by `sentPage` and described by `sentPaging`.',
        query: EMAIL_QUERY,
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return ctx.json(res, 200,
            self.emailView(caller.username, input.query.sentPage || 1));
        } },
      { method: 'POST', path: ctx.BASE + '/email', operationId: 'postEmail',
        tag: 'Email', access: 'person', mirrors: 'POST ' + ctx.PORTAL +
                                                 '/email',
        summary: 'Verifies your address, changes it, or saves your choices',
        description: '`verify` sends a verification link to your address; ' +
          '`change` sends one to a new address, which takes effect only ' +
          'when that link is used; `preferences` saves whether you are ' +
          'sent notifications. The two that send mail are rate limited. A ' +
          'refusal carries the page\'s `view`.',
        body: EMAIL_FORM,
        statuses: { 429: 'Too many attempts; try again later.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.postEmail(ctx, req, res, caller, input.body);
        } },
      { method: 'GET', path: ctx.BASE + '/verify-email',
        operationId: 'getEmailVerification', tag: 'Email', access: 'link',
        mirrors: 'GET ' + ctx.PORTAL + '/verify-email',
        summary: 'Checks an address verification link, and spends nothing',
        description: 'Takes no token: the link\'s `user` and `token` are ' +
          'the credential. Answers the address the link would verify, or ' +
          '`view.refused`. Opening it spends nothing, so a mail scanner ' +
          'cannot verify an address nobody read. Rate limited.',
        query: LINK,
        statuses: { 429: 'Too many attempts; `view.refused` says so.' },
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.verify(ctx, req, res, input.query, false);
        } },
      { method: 'POST', path: ctx.BASE + '/verify-email',
        operationId: 'verifyEmail', tag: 'Email', access: 'link',
        mirrors: 'POST ' + ctx.PORTAL + '/verify-email',
        summary: 'Verifies the address an address verification link names',
        description: 'Spends the link. Answers `view.verified`, or ' +
          '`view.refused`. Rate limited.',
        body: LINK,
        statuses: { 429: 'Too many attempts; `view.refused` says so.' },
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.verify(ctx, req, res, input.body, true);
        } },
      { method: 'GET', path: ctx.BASE + '/forgot-password',
        operationId: 'getForgotPassword', tag: 'Forgotten password',
        access: 'public', mirrors: 'GET ' + ctx.PORTAL + '/forgot-password',
        summary: 'Whether a forgotten password can be reset here, and how',
        description: '`threeFields` when a recovery code is asked for ' +
          'beside the account and its address. 404 where self-service ' +
          'reset is not offered (the setting off, no transport, or ' +
          'development mode).',
        query: vz.object({}),
        statuses: { 404: 'Not offered here; `view.notOffered` says so.' },
        handler: function (req: Json, res: Json): unknown {
          if (!mailUses.resetOffered()) {
            return self.notOffered(ctx, res);
          }
          return ctx.json(res, 200, self.forgotView());
        } },
      { method: 'POST', path: ctx.BASE + '/forgot-password',
        operationId: 'requestPasswordReset', tag: 'Forgotten password',
        access: 'public', mirrors: 'POST ' + ctx.PORTAL + '/forgot-password',
        summary: 'Asks for a password reset link',
        description: 'Answers ONE SENTENCE whatever happened (`view.note`), ' +
          'before the work is done, so neither its words nor its timing say ' +
          'whether the account exists; the link, if any, is mailed to the ' +
          'address on the account. Rate limited per account and address.',
        body: FORGOT_FORM,
        statuses: { 404: 'Not offered here.',
                    429: 'Too many attempts; `view.tooMany` says so.' },
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.postForgot(ctx, req, res, input.body);
        } }
    ];
    log.debug("Leaving PortalMail.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<PortalMail>(
  'portal/portal_mail',
  () => new PortalMail(PortalMail.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The mail channel's portal pages, as account API operations (#63, #568).
 * @namespace
 */
export = {
  PortalMail: PortalMail,
  installInstance: (instance: PortalMail): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
