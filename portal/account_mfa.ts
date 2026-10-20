// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_mfa.ts
//
// ---------------------------------------------------------------------------
// `/portal/mfa`'s TWO OPERATIONS (#568): the authenticator app page's view,
// and the one door its eight forms post to.
//
// Moved from `portal.ts` when the portal became a static application; the
// page is drawn in the browser by `web_mfa.ts`. The page holds four things,
// and so does the view: the authenticator app (enrolled, being set up, or
// offered), the emailed second factor (#64), the recovery codes, and what
// all of it is.
//
// **ONE DOOR AND EIGHT ACTIONS**, rather than eight paths: they are steps of
// one thing, `action` is a closed set the form itself draws, and that is the
// shape `/admin`'s action endpoints have had since the console was written.
// **`manage-own` FOR ALL OF THEM**, `start` included: minting a secret and
// holding it is a change to how this person will sign in, even though
// nothing is written to the directory until `confirm`. A deployment that
// later lets a helpdesk role READ an account must not have the enrolment door
// on the read side of that line.
//
// **THE IDENTITY IS THE TOKEN'S AND THERE IS NO PARAMETER FOR IT** — and on
// this door more than any other: a `username` read from the body would let
// anybody signed in enrol THEIR OWN authenticator app as somebody else's
// second factor, which is not a leak but a takeover.
//
// **THE PENDING ENROLMENT IS RE-READ FROM WHAT IS HELD** on every view: the
// QR code and the URI are DERIVED from the secret each time rather than kept
// beside it, so there is one copy of the secret and a page redrawn after a
// mistyped code shows the same account — nobody scans again for a typo.
// `start` therefore answers `{ ok }` and the runtime asks the view again,
// which is where the QR comes from: the server-rendered page answered `start`
// with a 303 for the same reason, so that a reload could not re-submit it and
// mint a SECOND secret behind the one just scanned.
//
// **THE RECOVERY CODES ARE SHOWN ONCE, IN PLACE.** `generate-codes` mints a
// set and stores nothing; its answer carries the set in `view.fresh`, which
// the runtime draws without a URL or a history entry — the reason the old
// page RENDERED rather than redirected. `confirm-codes` stores the hashes;
// `discard-codes` throws the pending set away. Only hashes are ever stored,
// so nothing can show a set again.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import totp = require('../common/totp');
// The mode (common/mode.js): which sentence the page's "what this is" card
// says about the rest of the credentials (#543 round 2).
import mode = require('../common/mode');
import backupCodes = require('../common/backup_codes');
import validation = require('../common/validation');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;
type AccountCaller = import('../types/account-api').AccountCaller;

const vz = validation.z;
const vt = validation.types;

const MFA_FORM = vz.object({
  action: vt.opt(vt.oneOf(['start', 'confirm', 'remove',
                          // The recovery codes, since 2026-09-11.
                          'generate-codes', 'confirm-codes',
                          'discard-codes',
                          // #64: the emailed second factor, on and off.
                          'email-factor-on', 'email-factor-off']))
    .describe('The step: `start` an authenticator app, `confirm` it with a ' +
              'code, `remove` it; `generate-codes`, `confirm-codes` or ' +
              '`discard-codes` a set of recovery codes; ' +
              '`email-factor-on` or `email-factor-off`.'),
  // #64: which emailed factor, for `email-factor-on`.
  kind: vt.opt(vt.oneOf(['code', 'link']))
    .describe('For `email-factor-on`: a mailed `code` or a sign-in `link`.'),
  // A STRING AND NOT AN INTEGER. `007123` is a code and 7123 is not: parsing
  // a one-time password as a number loses the leading zeros that one code in
  // ten has. The digit count is checked in `common/totp.ts`, where the
  // person's own enrolment says what it should be.
  code: vz.string().max(32).optional()
    .describe('For `confirm`: the code the app shows.'),
  // THE PENDING SET'S HANDLE (2026-09-11), which the Confirm and Throw-away
  // forms carry back: a handle rather than the username, so that two tabs
  // cannot confirm each other's set; opaque, so nothing here validates more
  // than its length.
  handle: vz.string().max(128).optional()
    .describe('For `confirm-codes` and `discard-codes`: the pending set\'s ' +
              'handle, from `generate-codes`\'s answer.')
});

interface AccountMfaDeps {
  log: typeof helpers.log;
  credentials: typeof credentials;
  totp: typeof totp;
  backupCodes: typeof backupCodes;
  accountSignals(): Json;
  mailFactor(): Json;
  authnPolicy(): Json;
}

/**
 * `/portal/mfa`'s account API operations.
 */
class AccountMfa {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountMfaDeps) {
    deps.log.debug("Entering AccountMfa.constructor().");
    deps.log.debug("Leaving AccountMfa.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountMfaDeps {
    helpers.log.debug("Entering AccountMfa.defaultDeps().");
    helpers.log.debug("Leaving AccountMfa.defaultDeps().");
    return {
      log: helpers.log, credentials: credentials, totp: totp,
      backupCodes: backupCodes,
      accountSignals: function accountSignals(): Json {
        helpers.log.debug("Entering accountSignals().");
        helpers.log.debug("Leaving accountSignals().");
        return require('../ssf/account_signals');
      },
      mailFactor: function mailFactor(): Json {
        helpers.log.debug("Entering mailFactor().");
        helpers.log.debug("Leaving mailFactor().");
        return require('../common/mail_factor');
      },
      authnPolicy: function authnPolicy(): Json {
        helpers.log.debug("Entering authnPolicy().");
        helpers.log.debug("Leaving authnPolicy().");
        return require('../common/authn_policy');
      }
    };
  }

  // ---------------------------------------------------------------------------
  // THE PENDING ENROLMENT, RE-RENDERED FROM WHAT IS HELD — see the header.
  // ---------------------------------------------------------------------------
  /**
   * The authenticator app enrolment in progress, with its QR code drawn.
   *
   * @param ctx - the account API's helpers
   * @param username - the signed-in person
   * @param base - this realm's base URL, for the issuer the app shows
   * @returns the enrolment, or null when none is pending
   */
  async pendingEnrolmentFor(ctx: AccountContext, username: string,
                            base: string): Promise<Json> {
    const { log, credentials, totp } = this.deps;
    log.debug("Entering AccountMfa.pendingEnrolmentFor().");
    const held: Json = credentials.pendingTotpFor(username);
    if (!held) {
      log.debug("Leaving AccountMfa.pendingEnrolmentFor(). Nothing pending.");
      return null;
    }
    const issuer = totp.issuerFor(base);
    const uri = totp.otpauthUri({ issuer: issuer, account: username,
                                  secret: held.secret,
                                  algorithm: held.algorithm,
                                  digits: held.digits, period: held.period });
    let qr = '';
    try {
      qr = await totp.qrSvgDataUri(uri);
    } catch (e) {
      // NOT fatal, and the page says so by showing the typed secret alone. A
      // QR renderer that fails must not cost somebody the ability to set up
      // a second factor, because the transcribable form is the whole
      // credential.
      log.error(ctx.errorCodes.tag('STS-PORTAL-0016') +
                'portal: the QR code could not be drawn (' +
                ((e && e.message) || e) + '), so the enrolment is offered by ' +
                'hand only.');
      qr = '';
    }
    log.debug("Leaving AccountMfa.pendingEnrolmentFor(). Rendered.");
    return { grouped: totp.grouped(held.secret), issuer: issuer, qr: qr,
             algorithm: held.algorithm, digits: held.digits,
             period: held.period };
  }

  // THE EMAILED SECOND FACTOR (#64), rcbj's D8: a person OPTS IN. Null when
  // the realm offers neither kind and the person has not opted in — the card
  // is then not drawn. `mail_factor`'s own words (the masked address, the
  // reason it is not used) travel as data.
  /**
   * The emailed second factor's state, for its card.
   *
   * @param username - the signed-in person
   * @returns the state, or null when the card is not drawn
   */
  emailFactorOf(username: string): Json {
    const { log } = this.deps;
    log.debug("Entering AccountMfa.emailFactorOf().");
    const mailFactor = this.deps.mailFactor();
    const policy = this.deps.authnPolicy();
    const status: Json = mailFactor.status(username) || {};
    const allowed = {
      code: !!policy.allows('emailCode', 'second-factor'),
      link: !!policy.allows('emailLink', 'second-factor')
    };
    if (!allowed.code && !allowed.link && !status.optedIn) {
      log.debug("Leaving AccountMfa.emailFactorOf(). Not offered here.");
      return null;
    }
    log.debug("Leaving AccountMfa.emailFactorOf().");
    return { allowed: allowed, optedIn: status.optedIn || '',
             usable: !!status.usable, kind: status.kind || '',
             why: String(status.why || ''),
             offered: { code: !!(status.offered || {}).code,
                        link: !!(status.offered || {}).link },
             verified: !!status.verified,
             masked: status.address ? mailFactor.masked(status.address) : '' };
  }

  /**
   * The page's view.
   *
   * @param ctx - the account API's helpers
   * @param caller - the signed-in person
   * @param base - this realm's base URL
   * @param fresh - a just-generated set of recovery codes, or null
   * @returns the view
   */
  async view(ctx: AccountContext, caller: AccountCaller, base: string,
             fresh?: Json): Promise<Json> {
    const { log, credentials, totp, backupCodes } = this.deps;
    log.debug("Entering AccountMfa.view().");
    const username = caller.username;
    const mechanisms: Json = credentials.mechanismsFor(username) || {};
    const live: Json = totp.settings() || {};
    const codes: Json = backupCodes.settings() || {};
    const doors: Json = credentials.passwordOnlyDoors(username) || {};
    const status: Json = mechanisms.backupCodes ||
      { present: false, remaining: 0, total: 0 };
    const detail: Json = mechanisms.totpDetail || null;
    const out: Json = {
      username: username,
      // Whether a presented password is verified in this realm: the about
      // card said "any password is accepted" in every mode until #543's
      // round 2.
      verifiesCredentials: mode.verifiesCredentials(),
      totp: {
        enrolled: !!mechanisms.totp, usable: !!mechanisms.totpUsable,
        detail: mechanisms.totp && detail
          ? { enrolledAt: detail.enrolledAt || 0,
              lastUsedAt: detail.lastUsedAt || 0,
              algorithm: String(detail.algorithm || 'SHA1'),
              digits: Number(detail.digits || 6),
              period: Number(detail.period || 30) } : null,
        offered: !!totp.offered(),
        digits: live.digits, period: live.period
      },
      doors: { applies: !!doors.applies,
               refused: (doors.refused || []).slice(0) },
      setup: await this.pendingEnrolmentFor(ctx, username, base),
      emailFactor: this.emailFactorOf(username),
      codes: {
        enabled: !!codes.enabled, count: codes.count, length: codes.length,
        advised: !!mechanisms.recoveryAdvised,
        present: !!status.present, usable: !!status.usable,
        why: String(status.why || ''),
        remaining: Number(status.remaining || 0),
        total: Number(status.total || 0),
        generatedAt: status.generatedAt || 0,
        lastUsedAt: status.lastUsedAt || 0
      },
      fresh: null
    };
    // STATE 3 OF THE RECOVERY CODES CARD: a set generated and being shown,
    // formatted here as the person is to write it down.
    if (fresh && fresh.ok && fresh.codes && fresh.codes.length) {
      out.fresh = { handle: String(fresh.handle || ''),
                    replacing: !!fresh.replacing,
                    codes: fresh.codes.map(function (code: string): string {
                      return backupCodes.formatted(code);
                    }) };
    }
    log.debug("Leaving AccountMfa.view().");
    return out;
  }

  /**
   * Carries out one of the page's eight actions.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param caller - the signed-in person
   * @param body - the checked body
   * @returns nothing
   */
  async act(ctx: AccountContext, req: Json, res: Json, caller: AccountCaller,
            body: Json): Promise<unknown> {
    const { log, credentials } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountMfa.act().");
    const self = this;
    const username = caller.username;
    const action = String(body.action || '');
    const base = ctx.baseUrlOf(req);
    const t = ctx.translatorFor(username);
    const codeOf = function (result: Json, fallback: string): string {
      return ctx.errorCodes.codeOf(result) ||
        String((result && result.errorCode) || '') || fallback;
    };
    const refuse = async function (status: number, code: string,
                                   why: string, fresh?: Json):
        Promise<unknown> {
      // error-code: none — the code is the caller's, passed in `code`.
      return ctx.refuse(res, status, code, why,
                        { view: await self.view(ctx, caller, base, fresh) });
    };

    if (action === 'remove') {
      const removed: Json = credentials.removeTotp(username);
      if (!removed.ok) {
        log.debug("Leaving AccountMfa.act(). Nothing to remove.");
        return refuse(400, codeOf(removed, 'STS-PORTAL-0021'),
                      (removed.errors || ['It could not be removed.'])[0]);
      }
      // THE SESSIONS THE APP'S CODES SIGNED IN END (#722); every other
      // stays. Never undoing the removal.
      const ended: Json = ctx.endFactorSessions(username, { kind: 'totp' },
                                                'the authenticator app');
      audit.record({
        category: 'authentication', action: 'portal.mfa.removed',
        actor: username, outcome: 'success',
        summary: username + ' removed their own authenticator app',
        detail: { address: websecurity.addressOf(req),
                  sessionsEnded: ended.sessionsEnded }
      });
      // CAEP credential-change (#145), as the console's clear-totp sends.
      const signals = this.deps.accountSignals();
      signals.credentialChanged({ username: username,
        credentialType: signals.TOTP_CREDENTIAL_TYPE,
        changeType: 'delete', initiatingEntity: 'user', via: 'portal',
        reasonAdmin: username + ' removed their authenticator app.',
        reasonUser: 'You removed your authenticator app.' });
      log.info('portal: ' + username + ' removed their authenticator app. ' +
               'That account is down to one factor.');
      log.debug("Leaving AccountMfa.act(). Removed.");
      const said = t.text('portal.done.totpRemoved');
      return ctx.json(res, 200, { ok: true,
        message: ended.sentence ? said + ' ' + ended.sentence : said,
        sessionsEnded: ended.sessionsEnded });
    }

    // THE EMAILED SECOND FACTOR (#64). `common/mail_factor.ts` decides, and
    // refuses anything it could not honour at the next sign-in.
    if (action === 'email-factor-on' || action === 'email-factor-off') {
      const mailFactor = this.deps.mailFactor();
      const done: Json = action === 'email-factor-on'
        ? mailFactor.optIn(username, body.kind, username, 'portal')
        : mailFactor.clear(username, username, 'portal');
      if (!done.ok) {
        log.debug("Leaving AccountMfa.act(). Email factor refused.");
        return refuse(400, codeOf(done, 'STS-PORTAL-0092'),
                      (done.errors || ['That could not be done.'])[0]);
      }
      // TURNED OFF, THE SESSIONS IT SIGNED IN AS A SECOND FACTOR END (#722),
      // and only when it was on.
      const ended: Json = action === 'email-factor-off' && done.removed
        ? ctx.endFactorSessions(username, { kind: 'email' },
                                'the emailed second factor')
        : { sessionsEnded: 0, sentence: '' };
      const said = action === 'email-factor-on'
        ? t.text('portal.done.emailOn') : t.text('portal.done.emailOff');
      log.debug("Leaving AccountMfa.act(). Email factor changed.");
      // Back to the card it was on, as the redirect's `#email-factor` did.
      return ctx.json(res, 200, { ok: true,
        message: ended.sentence ? said + ' ' + ended.sentence : said,
        sessionsEnded: ended.sessionsEnded,
        go: ctx.PORTAL + '/mfa#email-factor' });
    }

    if (action === 'start') {
      // **THE SETTING IS CHECKED AT THE DOOR AND NOT ONLY ON THE PAGE**: the
      // page is markup and this is the door, so a form posted by hand while
      // the TOTP row is off must not mint a secret.
      const begun: Json = credentials.beginTotpEnrolment(username,
                                                         { base: base });
      if (!begun.ok) {
        log.debug("Leaving AccountMfa.act(). Refused to start.");
        return refuse(400, codeOf(begun, 'STS-PORTAL-0022'),
                      (begun.errors || ['The setup could not be ' +
                                        'started.'])[0]);
      }
      audit.record({
        category: 'authentication', action: 'portal.mfa.started',
        actor: username, outcome: 'success',
        summary: username + ' started setting up an authenticator app',
        detail: { address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountMfa.act(). Secret minted and held.");
      // NO MESSAGE AND NO VIEW: the runtime asks the view again, which draws
      // the pending enrolment from what is held — see the header.
      return ctx.json(res, 200, { ok: true });
    }

    if (action === 'confirm') {
      // RATE LIMITED. Six digits is a million values and this door checks
      // them for real; the sign-in's own code step is limited for the same
      // reason and with the same buckets.
      const allowed = await websecurity.attemptShared('mfa-code', req,
                                                      username);
      if (!allowed.ok) {
        log.debug("Leaving AccountMfa.act(). Rate limited.");
        return refuse(429, codeOf(allowed, 'STS-PORTAL-0018'),
                      allowed.detail);
      }
      const confirmed: Json = credentials.confirmTotpEnrolment(
        username, String(body.code || ''));
      if (!confirmed.ok) {
        audit.record({
          category: 'authentication', action: 'portal.mfa.refused',
          errorCode: codeOf(confirmed, 'STS-PORTAL-0023'),
          actor: username, outcome: 'failure',
          summary: 'an authenticator app setup was not confirmed',
          detail: { reason: confirmed.reason || '',
                    address: websecurity.addressOf(req) }
        });
        log.debug("Leaving AccountMfa.act(). The code did not confirm.");
        // THE SAME PENDING SECRET IS REDRAWN, not a new one: a mistyped code
        // is the ordinary case.
        return refuse(400, codeOf(confirmed, 'STS-PORTAL-0023'),
                      (confirmed.errors || ['That code is not right.'])[0]);
      }
      audit.record({
        category: 'authentication', action: 'portal.mfa.enrolled',
        actor: username, outcome: 'success',
        summary: username + ' set up an authenticator app as a second factor',
        detail: { address: websecurity.addressOf(req) }
      });
      const signals = this.deps.accountSignals();
      signals.credentialChanged({ username: username,
        credentialType: signals.TOTP_CREDENTIAL_TYPE,
        changeType: 'create', initiatingEntity: 'user', via: 'portal',
        reasonAdmin: username + ' set up an authenticator app.',
        reasonUser: 'You set up an authenticator app.' });
      await websecurity.succeededShared('mfa-code', req, username);
      log.info('portal: ' + username + ' set up an authenticator app. A ' +
               'password alone will no longer sign them in.');
      // NO RECOVERY CODES ARE ISSUED BY THIS ENROLMENT (2026-09-11): a set is
      // generated when the person asks. What is left is the NUDGE, carried
      // on the message, and the card's standing prompt.
      log.debug("Leaving AccountMfa.act(). Enrolled.");
      return ctx.json(res, 200, { ok: true,
        message: confirmed.recoveryAdvised
          ? t.text('portal.done.totpSetUpNoCodes')
          : t.text('portal.done.totpSetUp') });
    }

    // THE RECOVERY CODES: GENERATE, CONFIRM, DISCARD (2026-09-11) — see the
    // header. All three are POSTs, for the reason the old page's were: a
    // list of credentials drawn by a page merely loading is a list in a
    // browser history entry.
    if (action === 'generate-codes') {
      const begun: Json = credentials.beginBackupCodes(username);
      audit.record({
        category: 'authentication',
        action: 'portal.mfa.backup-codes.generated',
        errorCode: begun.ok ? undefined : codeOf(begun, 'STS-PORTAL-0024'),
        actor: username, outcome: begun.ok ? 'success' : 'failure',
        summary: begun.ok
          ? username + ' generated a set of recovery codes and is being ' +
            'shown it; nothing is stored until they confirm'
          : username + ' asked for a set of recovery codes and none could ' +
            'be generated',
        detail: { count: begun.ok ? begun.codes.length : 0,
                  replacing: !!begun.replacing,
                  address: websecurity.addressOf(req),
                  errors: begun.ok ? undefined : (begun.errors || []) }
      });
      if (!begun.ok) {
        log.debug("Leaving AccountMfa.act(). Could not generate.");
        return refuse(400, codeOf(begun, 'STS-PORTAL-0024'),
                      (begun.errors || ['They could not be generated.'])[0]);
      }
      log.info('portal: ' + username + ' generated a set of recovery ' +
               'codes. They are being SHOWN and nothing is stored yet.');
      log.debug("Leaving AccountMfa.act(). Generated and showing.");
      // SHOWN ONCE, IN PLACE: the set rides in the answer's view and nowhere
      // else — never on a URL, never in the history.
      return ctx.json(res, 200, { ok: true,
                                  view: await this.view(ctx, caller, base,
                                                        begun) });
    }

    if (action === 'confirm-codes') {
      const stored: Json = credentials.confirmBackupCodes(
        username, String(body.handle || ''));
      // RECOVERY CODES ARE RECOVERY INFORMATION (#145): CAEP names no
      // credential type for them, and RISC's recovery-information-changed is
      // the event the console's clear already sends.
      if (stored.ok) {
        this.deps.accountSignals().recoveryInformationChanged({
          username: username, via: 'portal' });
      }
      audit.record({
        category: 'authentication',
        action: 'portal.mfa.backup-codes.confirmed',
        errorCode: stored.ok ? undefined : codeOf(stored, 'STS-PORTAL-0025'),
        actor: username, outcome: stored.ok ? 'success' : 'failure',
        summary: stored.ok
          ? username + ' confirmed they had saved their recovery codes, ' +
            'and the hashes were stored'
          : username + ' tried to confirm a set of recovery codes and it ' +
            'could not be stored',
        detail: { total: stored.ok ? stored.total : 0,
                  address: websecurity.addressOf(req),
                  errors: stored.ok ? undefined : (stored.errors || []) }
      });
      if (!stored.ok) {
        // **THE PENDING SET SURVIVES A FAILED WRITE AND THE PAGE REDRAWS WITH
        // THE CODES STILL ON IT** where it can: the person is looking at a
        // list they may already have written down.
        const held: Json = credentials.pendingBackupCodesFor(
          username, String(body.handle || ''));
        log.debug("Leaving AccountMfa.act(). The confirm failed.");
        return refuse(400, codeOf(stored, 'STS-PORTAL-0025'),
          (stored.errors || ['They could not be stored.'])[0],
          held ? { ok: true, handle: String(body.handle || ''),
                   codes: held.codes } : null);
      }
      log.debug("Leaving AccountMfa.act(). Confirmed and stored.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portal.done.codesSaved', { n: stored.total }) });
    }

    if (action === 'discard-codes') {
      credentials.discardBackupCodes(username, String(body.handle || ''));
      audit.record({
        category: 'authentication',
        action: 'portal.mfa.backup-codes.discarded',
        actor: username, outcome: 'success',
        summary: username + ' threw away a set of recovery codes without ' +
                 'storing it',
        detail: { address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountMfa.act(). Discarded.");
      return ctx.json(res, 200, { ok: true,
        message: t.text('portal.done.codesDiscarded') });
    }

    // An `action` the schema allowed and this door does not know is not
    // reachable from the page; it is refused with the page drawn again.
    log.debug("Leaving AccountMfa.act(). No action.");
    return refuse(400, 'STS-PORTAL-0026', 'Nothing was asked for.');
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
    log.debug("Entering AccountMfa.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/mfa', operationId: 'getMfa',
        tag: 'Authenticator app', access: 'person',
        mirrors: 'GET ' + ctx.PORTAL + '/mfa',
        summary: 'Your authenticator app, emailed factor and recovery codes',
        description: '`totp`: whether an authenticator app is set up (and ' +
          'its algorithm, digits, period, when set up and last used) and ' +
          'whether one is offered. `setup`: an enrolment in progress — the ' +
          'QR code as a `data:` image, the secret grouped for typing, the ' +
          'issuer and the parameters — derived from the pending secret on ' +
          'every call. `doors`: the password-only doors that refuse your ' +
          'own password. `emailFactor`: the emailed second factor, or null ' +
          'where none is offered. `codes`: your recovery codes\' state — ' +
          'never the codes, of which only hashes are stored.',
        query: vz.object({}),
        handler: function (req: Json, res: Json,
                           caller: AccountCaller): unknown {
          return self.view(ctx, caller, ctx.baseUrlOf(req))
            .then(function (view: Json) {
              return ctx.json(res, 200, view);
            });
        } },
      { method: 'POST', path: ctx.BASE + '/mfa', operationId: 'changeMfa',
        tag: 'Authenticator app', access: 'person',
        mirrors: 'POST ' + ctx.PORTAL + '/mfa',
        summary: 'Sets up, confirms or removes your second factors',
        description: '`start` mints a secret and holds it (ask the view for ' +
          'the QR code); `confirm` checks a code from the app (rate ' +
          'limited) and enrols it; `remove` takes it off, and ends ' +
          'every session its codes signed in (`sessionsEnded`, #722). ' +
          '`generate-codes` answers a set of recovery codes ONCE, in ' +
          '`view.fresh`, and stores nothing; `confirm-codes` stores their ' +
          'hashes; `discard-codes` throws the pending set away. ' +
          '`email-factor-on` (with `kind`) and `email-factor-off` opt in ' +
          'and out of the emailed second factor. A refusal carries the ' +
          'page\'s `view`.',
        body: MFA_FORM,
        statuses: { 429: 'Too many codes tried; try again later.' },
        handler: function (req: Json, res: Json, caller: AccountCaller,
                           input: Json): unknown {
          return self.act(ctx, req, res, caller, input.body);
        } }
    ];
    log.debug("Leaving AccountMfa.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountMfa>(
  'portal/account_mfa',
  () => new AccountMfa(AccountMfa.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/mfa`'s account API operations (#568).
 * @namespace
 */
export = {
  AccountMfa: AccountMfa,
  installInstance: (instance: AccountMfa): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
