// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_reset.ts
//
// ---------------------------------------------------------------------------
// /portal/reset-password — SPENDING A PASSWORD RESET LINK (2026-09-13), AS
// TWO `/account-api` OPERATIONS SINCE #568.
//
// An administrator pressed *Generate a password reset link* on this person's
// /admin/users page (or called POST /admin-api/users/issue-password-reset),
// or the person asked for one on /portal/forgot-password: their old password
// was removed, they were signed out of everything, and the link is how they
// choose a new one. It is the activation link's arrangement for somebody who
// already has an account, and it keeps every one of that link's properties:
//
//   * **UNAUTHENTICATED, AND THE TOKEN IS WHAT AUTHORISES IT** (`access:
//     'link'`). It takes a username for that reason and no other.
//   * **RATE LIMITED on the GET and the POST**, in a bucket of its own
//     (`password-reset`).
//   * **ONE SENTENCE FOR EVERY FAILURE** (`RESET_REFUSAL`), so nobody learns
//     which usernames have a link outstanding.
//   * **SPENT WHEN THE PASSWORD IS STORED**, not when the link is opened: the
//     GET spends nothing, so a mail scanner or a prefetch cannot burn it.
//   * **IT SIGNS NOBODY IN.** The last step is the ordinary sign-in screen,
//     reached through `/portal`, which is where a second factor they hold is
//     asked for.
//
// It does ONE thing, where the activation form offers a key and an
// authenticator as well: the person already has their second factors — an
// administrator took only the password away — and a form offering to enrol
// more on a link would be a way to add a second factor with nothing but the
// link.
//
// **THE PASSWORD GOES THROUGH `credentials.setPassword()`**, so product mode
// holds it to the realm's password policy and its history, which carries the
// password the link removed. `pwdReset` is cleared: a password the person just
// chose is not one they must change. **CAEP credential-change (`password`,
// `create`, initiated by the user)** is said when it is stored.
//
// **SEVERAL NODES (#46): THE LINK IS CLAIMED BEFORE ANYTHING IS SET.**
// `credentials.spendPasswordReset()` claims it in the store; the claim is
// kept only by the request that FINISHES (the response is marked
// `LINK_SPENT`), and every other answer gives it back when the response ends
// (`holdLinkClaim()`), so the link works again exactly as it did on one
// node. A JSON answer ends the response as a page did, so the arrangement is
// unchanged.
//
// The page is drawn in the browser by `web_reset.ts`; a refusal carries the
// page's `view`, so the runtime draws the refusal card or the form again
// with its reason.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import realms = require('../common/realms');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;

const vz = validation.z;
const vt = validation.types;

// One sentence for every way a reset link can fail — see the header.
const RESET_REFUSAL =
  'This password reset link is not valid. It may have expired, it may ' +
  'already have been used, or it may never have been issued. Ask for a new ' +
  'one on the "Forgot your password?" page where it is offered, or ask ' +
  'whoever manages your account.';

const RESET_QUERY = vz.object({
  user: vt.opt(vt.name).describe('The username the link names.'),
  token: vt.opt(vt.token).describe('The link\'s single-use secret.')
});

// THE TOKEN RIDES IN THE BODY, for the activation form's reason: nobody is
// signed in, so there is no session to carry it on, and a POST keeps it out
// of a referer and an access log.
const RESET_FORM = vz.object({
  user: vt.opt(vt.name).describe('The username the link names.'),
  token: vt.opt(vt.token).describe('The link\'s single-use secret.'),
  password: vz.string().max(1024).optional().describe('The new password.'),
  confirm: vz.string().max(1024).optional()
    .describe('The new password again.')
});

// The response a request that FINISHED is marked with, so the claim on the
// link is kept rather than given back (`holdLinkClaim()`).
const LINK_SPENT = Symbol('account.resetLinkSpent');

interface AccountResetDeps {
  log: typeof helpers.log;
  credentials: typeof credentials;
  realms: typeof realms;
  breachedPasswords(): Json;
  accountSignals(): Json;
}

/**
 * `/portal/reset-password`'s account API operations.
 */
class AccountReset {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountResetDeps) {
    deps.log.debug("Entering AccountReset.constructor().");
    deps.log.debug("Leaving AccountReset.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountResetDeps {
    helpers.log.debug("Entering AccountReset.defaultDeps().");
    helpers.log.debug("Leaving AccountReset.defaultDeps().");
    return {
      log: helpers.log, credentials: credentials, realms: realms,
      breachedPasswords: function breachedPasswords(): Json {
        helpers.log.debug("Entering breachedPasswords().");
        helpers.log.debug("Leaving breachedPasswords().");
        return require('../common/breached_passwords');
      },
      accountSignals: function accountSignals(): Json {
        helpers.log.debug("Entering accountSignals().");
        helpers.log.debug("Leaving accountSignals().");
        return require('../ssf/account_signals');
      }
    };
  }

  // WHERE A "SIGN IN" LINK GOES (#32): drawn in the realm the person belongs
  // to, so the realm chooser has nothing to ask them. In the default realm,
  // once realms are defined, `?realm=default` is the choice already made.
  /**
   * The portal address a "Sign in" link on the page goes to.
   *
   * @param ctx - the account API's helpers
   * @returns the path
   */
  signInHref(ctx: AccountContext): string {
    const { log, realms } = this.deps;
    log.debug("Entering AccountReset.signInHref().");
    const skip = realms.isDefault() && realms.active();
    log.debug("Leaving AccountReset.signInHref().");
    return ctx.PORTAL + (skip ? '?realm=' +
      encodeURIComponent(realms.DEFAULT_ID) : '');
  }

  /**
   * The form's view: the link's two values, the service's address the
   * sentence names, and the password rules.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param username - the person the link names
   * @param token - the link's secret
   * @returns the view
   */
  formView(ctx: AccountContext, req: Json, username: string,
           token: string): Json {
    const { log, credentials } = this.deps;
    log.debug("Entering AccountReset.formView().");
    const rules: Json = credentials.passwordRules(username) || {};
    log.debug("Leaving AccountReset.formView().");
    return { username: username, token: token, base: ctx.baseUrlOf(req),
             rules: { enforced: !!rules.enforced,
                      rules: (rules.rules || []).slice(0) } };
  }

  // A LINK THAT IS NOT GOOD: the one sentence, as a view the page draws.
  /**
   * Refuses the link with the one sentence.
   *
   * @param ctx - the account API's helpers
   * @param res - the response
   * @param status - the HTTP status
   * @param code - the error code
   * @param sentence - what to say (RESET_REFUSAL, or a rate limit's)
   * @returns nothing
   */
  refuseLink(ctx: AccountContext, res: Json, status: number, code: string,
             sentence: string): unknown {
    const { log } = this.deps;
    log.debug("Entering AccountReset.refuseLink(). " + code);
    log.debug("Leaving AccountReset.refuseLink().");
    return ctx.refuse(res, status, code, sentence,
                      { view: { refused: sentence,
                                tooMany: status === 429 } });
  }

  /**
   * Gives the link's claim back when the response ends, unless the request
   * finished (`LINK_SPENT`).
   *
   * @param res - the response
   * @param handle - the claim
   * @returns nothing
   */
  holdLinkClaim(res: Json, handle: Json): void {
    const { credentials, log } = this.deps;
    log.debug("Entering AccountReset.holdLinkClaim().");
    let settled = false;
    const settle = function (): void {
      log.debug("Entering settle().");
      if (settled) {
        log.debug("Leaving settle(). Already settled.");
        return;
      }
      settled = true;
      if (!res[LINK_SPENT]) {
        credentials.releaseLink(handle);
      }
      log.debug("Leaving settle().");
    };
    res.once('finish', settle);
    res.once('close', settle);
    log.debug("Leaving AccountReset.holdLinkClaim().");
  }

  /**
   * GET: checks the link and answers the form's view. Spends nothing.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param query - the checked query
   * @returns nothing
   */
  async look(ctx: AccountContext, req: Json, res: Json,
             query: Json): Promise<unknown> {
    const { log, credentials } = this.deps;
    const { audit, websecurity, errorCodes } = ctx;
    log.debug("Entering AccountReset.look().");
    const username = String(query.user || '').trim();
    const token = String(query.token || '');
    const allowed = await websecurity.attemptShared('password-reset', req,
                                                    username);
    if (!allowed.ok) {
      log.debug("Leaving AccountReset.look(). Rate limited.");
      return this.refuseLink(ctx, res, 429, errorCodes.codeOf(allowed) ||
                             'STS-PORTAL-0070', allowed.detail);
    }
    const checked = credentials.checkPasswordReset(username, token);
    if (!checked.ok) {
      log.info('portal: a password reset link was refused for "' + username +
               '" (' + checked.reason + ').');
      audit.record({
        category: 'authentication', action: 'portal.password-reset.refused',
        errorCode: errorCodes.codeOf(checked) || 'STS-PORTAL-0071',
        actor: username, outcome: 'failure',
        summary: 'a password reset link was refused',
        detail: { reason: checked.reason,
                  address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountReset.look(). Refused.");
      return this.refuseLink(ctx, res, 400, errorCodes.codeOf(checked) ||
                             'STS-PORTAL-0071', RESET_REFUSAL);
    }
    log.debug("Leaving AccountReset.look(). The form.");
    return ctx.json(res, 200, this.formView(ctx, req, username, token));
  }

  /**
   * POST: checks the link again, claims it, sets the password and spends it.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param body - the checked body
   * @returns nothing
   */
  async spend(ctx: AccountContext, req: Json, res: Json,
              body: Json): Promise<unknown> {
    const { log, credentials } = this.deps;
    const { audit, websecurity, errorCodes } = ctx;
    log.debug("Entering AccountReset.spend().");
    const username = String(body.user || '').trim();
    const token = String(body.token || '');
    const allowed = await websecurity.attemptShared('password-reset', req,
                                                    username);
    if (!allowed.ok) {
      log.debug("Leaving AccountReset.spend(). Rate limited.");
      return this.refuseLink(ctx, res, 429, errorCodes.codeOf(allowed) ||
                             'STS-PORTAL-0070', allowed.detail);
    }
    // **CHECKED AGAIN ON THE POST**, for the activation form's reason: a
    // request assembled by hand never met the GET.
    const checked = credentials.checkPasswordReset(username, token);
    if (!checked.ok) {
      audit.record({
        category: 'authentication', action: 'portal.password-reset.refused',
        errorCode: errorCodes.codeOf(checked) || 'STS-PORTAL-0071',
        actor: username, outcome: 'failure',
        summary: 'a password reset link was refused',
        detail: { reason: checked.reason,
                  address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountReset.spend(). Refused.");
      return this.refuseLink(ctx, res, 400, errorCodes.codeOf(checked) ||
                             'STS-PORTAL-0071', RESET_REFUSAL);
    }
    const view = this.formView(ctx, req, username, token);
    const password = String(body.password || '');
    if (!password) {
      log.debug("Leaving AccountReset.spend(). No password.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0072',
                        'Type a new password, twice.', { view: view });
    }
    if (password !== String(body.confirm || '')) {
      log.debug("Leaving AccountReset.spend(). They differ.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0072',
                        'The two passwords do not match.', { view: view });
    }
    if (password === credentials.RESERVED_REFUSAL) {
      log.debug("Leaving AccountReset.spend(). The reserved password.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0072',
        'That password is reserved and is refused at every sign-in, so it ' +
        'cannot be yours.', { view: view });
    }
    // **SPENT IN THE STORE BEFORE THE PASSWORD IS SET**, and given back
    // unless the password is stored — see `holdLinkClaim()`.
    const spent = await credentials.spendPasswordReset(username, token);
    if (!spent.ok) {
      audit.record({
        category: 'authentication', action: 'portal.password-reset.refused',
        errorCode: errorCodes.codeOf(spent) || 'STS-AUTHN-0183',
        actor: username, outcome: 'failure',
        summary: 'a link was refused: another request is spending it or has ' +
                 'spent it',
        detail: { reason: spent.reason || '',
                  address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountReset.spend(). The link is being spent.");
      return this.refuseLink(ctx, res, 400, errorCodes.codeOf(spent) ||
                             'STS-AUTHN-0183', RESET_REFUSAL);
    }
    this.holdLinkClaim(res, spent.handle);
    // Screened against Pwned Passwords first (#62 P6).
    await this.deps.breachedPasswords().screen(password);
    const set = credentials.setPassword(username, password);
    if (!set.ok) {
      log.debug("Leaving AccountReset.spend(). The password was refused.");
      return ctx.refuse(res, 400, errorCodes.codeOf(set) || 'STS-PORTAL-0073',
                        (set.errors || ['The password could not be set.'])[0],
                        { view: view });
    }
    res[LINK_SPENT] = true;
    credentials.consumePasswordReset(username);
    credentials.setPasswordResetRequired(username, false);
    await websecurity.succeededShared('password-reset', req, username);
    audit.record({
      category: 'authentication', action: 'portal.password-reset',
      actor: username, target: username, outcome: 'success',
      summary: username + ' chose a new password from a reset link',
      detail: { address: websecurity.addressOf(req) }
    });
    this.deps.accountSignals().credentialChanged({ username: username,
      credentialType: 'password', changeType: 'create',
      initiatingEntity: 'user', via: 'portal',
      reasonAdmin: username + ' set a new password from a password reset ' +
                              'link.',
      reasonUser: 'You chose a new password.' });
    log.info('portal: ' + username + ' set a new password from a reset ' +
             'link; the link is spent.');
    log.debug("Leaving AccountReset.spend(). Set.");
    // THE DONE CARD, drawn from this view in place: nobody is signed in, and
    // the link is spent, so its GET would now only refuse. `/portal` and not
    // the sign-in screen, for `finishActivation()`'s reason: `/authn/login`
    // draws a form for a pending record, and `/portal` is what mints one.
    return ctx.json(res, 200, { ok: true,
      view: { done: true, signIn: this.signInHref(ctx) } });
  }

  /**
   * The operations, for `account-api/account_api.ts`.
   *
   * @param ctx - the account API's helpers
   * @returns the operations
   */
  accountOperations(ctx: AccountContext): AccountOperation[] {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering AccountReset.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/reset-password',
        operationId: 'getPasswordReset', tag: 'Password reset link',
        access: 'link', mirrors: 'GET ' + ctx.PORTAL + '/reset-password',
        summary: 'Checks a password reset link, and spends nothing',
        description: 'Takes no token: the link\'s `user` and `token` are ' +
          'the credential. Answers the form\'s view — the username, the ' +
          'service\'s address and the password rules — or one sentence for ' +
          'every way a link can fail (`view.refused`), so nobody learns ' +
          'which usernames have a link outstanding. Rate limited.',
        query: RESET_QUERY,
        statuses: { 429: 'Too many attempts; `view.refused` says so.' },
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.look(ctx, req, res, input.query);
        } },
      { method: 'POST', path: ctx.BASE + '/reset-password',
        operationId: 'spendPasswordReset', tag: 'Password reset link',
        access: 'link', mirrors: 'POST ' + ctx.PORTAL + '/reset-password',
        summary: 'Sets a new password from a reset link, and spends it',
        description: 'Checks the link again, claims it, screens the ' +
          'password against breached passwords and the password policy, ' +
          'stores it, clears the must-change flag, and spends the link; ' +
          'signs nobody in. CAEP credential-change is sent. A refusal ' +
          'carries the page\'s `view`; success answers `view.done`.',
        body: RESET_FORM,
        statuses: { 429: 'Too many attempts; `view.refused` says so.' },
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.spend(ctx, req, res, input.body);
        } }
    ];
    log.debug("Leaving AccountReset.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountReset>(
  'portal/account_reset',
  () => new AccountReset(AccountReset.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/reset-password`'s account API operations (#568).
 * @namespace
 */
export = {
  AccountReset: AccountReset,
  installInstance: (instance: AccountReset): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
