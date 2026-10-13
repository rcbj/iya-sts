// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: email_factor.ts
//
// ---------------------------------------------------------------------------
// THE EMAILED CODE AND THE EMAILED SIGN-IN LINK (#64, 2026-09-23).
//
// Two mechanisms, each usable as a FIRST factor (the username alone, then the
// mailbox) or as a SECOND (after a password, a wallet or any other first
// factor), where this realm's authentication policy allows it
// (`common/authn_policy.ts`) — and OFF by default, because NIST SP 800-63B-4
// section 3.1.3.1 says email "SHALL NOT be used for out-of-band
// authentication". An operator may turn them on; the policy page says why
// they should think twice.
//
// ---------------------------------------------------------------------------
// WHAT EVERY PATH HERE HOLDS TO:
//
//   * **ONLY A VERIFIED ADDRESS IS MAILED.** `stsMailVerified` equal to
//     `mail` — the address a person proved they read, or one a trusted source
//     (an administrator, SCIM, a federation partner) wrote. A code sent to an
//     address nobody proved is a code anybody might read.
//   * **THE SECRET IS NEVER STORED.** A code or a link token is minted from
//     the CSPRNG, mailed, and kept on the sign-in step as a scrypt hash only
//     (`common/mail_factor.ts`). The mail channel drops a sent message's body.
//   * **VALID FOR AT MOST TEN MINUTES** (the policy's `emailCodeTtlS`, section
//     3.1.3.2's bound), **ONCE** — a cluster claim on the step and the send
//     spends it on exactly one node — and a resend replaces the last one.
//   * **A BOUNDED NUMBER OF WRONG CODES PER STEP** (`emailCodeAttempts`),
//     after which the step ends; the per-person and per-network rate limits
//     the one-time code screen uses (`mfa-code`) on top; and at the policy's
//     `emailFailureLimit` consecutive failures, the person's emailed factor
//     is turned off (section 3.2.2).
//   * **AS A FIRST FACTOR THE ANSWER NEVER SAYS WHETHER THE ACCOUNT EXISTS.**
//     An unknown name, a disabled account, an address that is not verified —
//     each gets the same "check your mail" page as a real one, on a DECOY
//     step no code can ever finish, and nothing is mailed.
//   * **A LINK FINISHES ONLY IN THE BROWSER THAT STARTED THE SIGN-IN** (rcbj's
//     D3). The step keeps the hash of a cookie set when the link was sent;
//     opened anywhere else it spends nothing and says where to open it. The
//     opposite — approve from any device, and the waiting tab continues — is
//     the login-CSRF shape: an attacker starts a sign-in as the victim, and
//     the victim clicks.
//   * **A GET SPENDS NOTHING AND SENDS NOTHING.** A mail scanner fetches every
//     link in a message, so the link lands on a page with a Continue button;
//     and the "email me a code instead" links on the other factor screens
//     lead to a page that asks before anything is mailed.
//   * **NO SCRIPT** on any page here. The waiting page is refreshed by a
//     <meta> tag, as the wallet's QR page is.
//
// ---------------------------------------------------------------------------
// `amr` IS `otp` AND `acr` IS `mfa` AS A SECOND FACTOR, `1` AS A FIRST (D1,
// D2). RFC 8176 registers no value for email; a single-use secret sent to the
// person is what `otp` names, as it is for a recovery code. The session's
// authentication event says which (`credential.kind` `email-code` or
// `email-link`), and so does the XACML request, whose policy may refuse a
// session standing on one. An emailed factor NEVER answers a step-up on risk.
//
// ---------------------------------------------------------------------------
// A ROUTE MODULE ON THE COMPOSITION ROOT'S PATTERN (#50): it registers nothing
// when required; `common/protocol_stack.ts` builds it and calls
// `registerRoutes(app)` just after `authn`, whose pending steps it reads
// through the functions that module exports — never the store itself.
// ---------------------------------------------------------------------------

import stsCrypto = require('../common/crypto');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
import realms = require('../common/realms');
import errorCodes = require('../common/error_codes');
import validation = require('../common/validation');
import audit = require('../common/audit');
import authnPolicy = require('../common/authn_policy');
import mailFactor = require('../common/mail_factor');
import websecurity = require('../common/websecurity');
import clusterClaims = require('../cluster/cluster_claims');
// THE SESSION, and the reason this file is below #8 in the require order.
import authn = require('./authn');

const { log, xmlEscape } = helpers;

// The cookie that ties a mailed link to the browser that asked for it.
/**
 * The cookie that ties a mailed sign-in link to the browser that asked for
 * it.
 */
const BINDING_COOKIE = 'sts_email_binding';

// How often the waiting page of a link asks again whether it was opened —
// the `<meta>` refresh it had, a poll in the browser since #573.
const WAIT_REFRESH_S = 4;

// A claim outlives the step by the clock disagreement other single-use values
// allow.
const CLAIM_SKEW_MS = 60 * 1000;

// THE FORMS ARE GONE (#573): the bodies of the acts are `/authn-api`'s,
// declared and checked in `authn/authn_api.ts`.

type Kind = 'code' | 'link';

interface EmailFactorDeps {
  log: typeof helpers.log;
  xmlEscape: typeof helpers.xmlEscape;
  baseUrlOf: typeof helpers.baseUrlOf;
  parseBody: typeof helpers.parseBody;
  config: typeof config;
  realms: typeof realms;
  errorCodes: typeof errorCodes;
  validation: typeof validation;
  audit: typeof audit;
  authnPolicy: typeof authnPolicy;
  mailFactor: typeof mailFactor;
  websecurity: typeof websecurity;
  clusterClaims: typeof clusterClaims;
  authn: typeof authn;
  now(): number;
  // The mail channel, asked lazily: it requires the directory.
  mail(): any;
  // Whether an account is disabled, asked lazily for the same reason.
  isDisabled(username: string): boolean;
}

type RouteApp = { get: Function; post: Function };

/**
 * The emailed code and the emailed sign-in link, as a first or a second
 * factor, where the realm's authentication policy allows them (#64).
 *
 * Only a verified address is mailed, the secret is kept only as a hash and
 * spent once for the cluster, and a link finishes only in the browser that
 * started the sign-in. Off by default.
 */
class EmailFactor {
  /**
   * The link-binding cookie's name, as a static member.
   */
  static readonly BINDING_COOKIE = BINDING_COOKIE;

  /**
   * Builds the factor over the dependencies given.
   *
   * @param deps - the logger, settings, sign-in service, mail channel and
   * factor library, rate limits, cluster claims, audit log and clock
   */
  constructor(private readonly deps: EmailFactorDeps) {
    deps.log.debug("Entering EmailFactor.constructor().");
    deps.log.debug("Leaving EmailFactor.constructor().");
  }

  /**
   * Returns the dependencies built from the real modules, as the composition
   * root passes them.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): EmailFactorDeps {
    log.debug("Entering EmailFactor.defaultDeps().");
    log.debug("Leaving EmailFactor.defaultDeps().");
    return {
      log: log,
      xmlEscape: xmlEscape,
      baseUrlOf: helpers.baseUrlOf,
      parseBody: helpers.parseBody,
      config: config,
      realms: realms,
      errorCodes: errorCodes,
      validation: validation,
      audit: audit,
      authnPolicy: authnPolicy,
      mailFactor: mailFactor,
      websecurity: websecurity,
      clusterClaims: clusterClaims,
      authn: authn,
      now: function (): number {
        return Date.now();
      },
      mail: function () {
        return require('../common/mail');
      },
      isDisabled: function (username: string): boolean {
        log.debug("Entering EmailFactor isDisabled().");
        let out = false;
        try {
          out = !!require('../common/account_state').isDisabled(username);
        } catch (e) {
          log.debug("Caught in EmailFactor isDisabled(): " +
                    ((e && e.message) || e));
          // No account state in this process: a test with no directory, in
          // which nobody is disabled.
          out = false;
        }
        log.debug("Leaving EmailFactor isDisabled().");
        return out;
      }
    };
  }

  private mechanismOf(kind: Kind): string {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.mechanismOf().");
    log.debug("Leaving EmailFactor.mechanismOf().");
    return kind === 'code' ? 'emailCode' : 'emailLink';
  }

  private kindOfFactor(factor: unknown): Kind | '' {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.kindOfFactor().");
    log.debug("Leaving EmailFactor.kindOfFactor().");
    return factor === 'email-code' ? 'code'
      : (factor === 'email-link' ? 'link' : '');
  }

  // WHICH EMAILED FACTOR A STEP MAY BE ANSWERED WITH: the one it asks for, or
  // the one it offers as a way round another (`step.email`). '' if neither.
  private kindAllowedOn(step: any, wanted: Kind): Kind | '' {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.kindAllowedOn().");
    const asked = this.kindOfFactor(step && step.factor);
    const out = asked === wanted || (step && step.email === wanted)
      ? wanted : '';
    log.debug("Leaving EmailFactor.kindAllowedOn(). " + (out || 'no'));
    return out;
  }

  private hashOf(value: string): string {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.hashOf().");
    log.debug("Leaving EmailFactor.hashOf().");
    return stsCrypto.digest('sha256', String(value), 'base64url');
  }

  private bindingOf(req: any): string {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.bindingOf().");
    const value = String(authn.cookiesOf(req)[BINDING_COOKIE] || '');
    log.debug("Leaving EmailFactor.bindingOf().");
    return /^[A-Za-z0-9_-]{32,64}$/.test(value) ? value : '';
  }

  // The binding cookie, set when a link is sent. Path=/ and one per browser,
  // for the wallet door's reason: the step keeps the hash, and a realm's step
  // is in that realm's store.
  private setBinding(res: any, value: string, ttlS: number): void {
    const { log, config } = this.deps;
    log.debug("Entering EmailFactor.setBinding().");
    res.append('Set-Cookie', BINDING_COOKIE + '=' + value +
      '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + Math.ceil(ttlS) +
      (config.value('global.https') ? '; Secure' : ''));
    log.debug("Leaving EmailFactor.setBinding().");
  }

  // -------------------------------------------------------------------------
  // ARMING A STEP: a fresh secret, its hash on the step, and the mail. The
  // answer says whether it went; a refusal from the mail channel is RECORDED
  // (its code) and the page offers the other factors, never the reason —
  // which could say whether an address exists.
  // -------------------------------------------------------------------------
  private async arm(req: any, res: any, mfaId: string, step: any,
                    kind: Kind): Promise<{ ok: boolean; why?: string;
                                           code?: string }> {
    const { log, authnPolicy, mailFactor, errorCodes, audit, now } =
      this.deps;
    log.debug("Entering EmailFactor.arm(). " + kind);
    const settings = authnPolicy.emailSettings();
    const held = step.emailState || null;
    const at = now();
    if (held && held.kind === kind) {
      if (held.sends >= settings.maxSends) {
        log.debug("Leaving EmailFactor.arm(). Sent enough.");
        return { ok: false, code: 'STS-AUTHN-0257',
                 why: 'No more ' + (kind === 'code' ? 'codes' : 'links') +
                      ' can be sent for this sign-in. Start again from the ' +
                      'application that sent you here.' };
      }
      if (at - held.sentAt < settings.resendS * 1000) {
        log.debug("Leaving EmailFactor.arm(). Too soon.");
        return { ok: false, code: 'STS-AUTHN-0258',
                 why: 'One was sent less than ' + settings.resendS +
                      ' seconds ago. Check your mail, or wait a moment ' +
                      'and ask again.' };
      }
    }
    const secret = kind === 'code' ? mailFactor.mintCode()
                                   : mailFactor.mintToken();
    const state: any = {
      kind: kind,
      hash: step.decoy ? '' : await mailFactor.hash(secret),
      sentAt: at,
      sends: (held && held.kind === kind ? held.sends : 0) + 1,
      attempts: 0,
      expiresAt: at + settings.ttlS * 1000,
      binding: ''
    };
    if (kind === 'link') {
      const binding = stsCrypto.randomBytes(32).toString('base64url');
      state.binding = this.hashOf(binding);
      this.setBinding(res, binding, settings.ttlS + 60);
    }
    step.emailState = state;
    step.expires = Math.max(Number(step.expires) || 0, state.expiresAt);
    this.deps.authn.saveMfaStep(mfaId, step);
    if (step.decoy) {
      log.debug("Leaving EmailFactor.arm(). A decoy: nothing mailed.");
      return { ok: true };
    }
    const minutes = Math.max(1, Math.round(settings.ttlS / 60));
    const sent = this.deps.mail().send(kind === 'code'
      ? { username: step.username, template: 'sign-in-code',
          values: { username: step.username, code: secret,
                    minutes: String(minutes) },
          dedupKey: 'sign-in:' + mfaId + ':' + state.sends, via: 'authn' }
      : { username: step.username, template: 'sign-in-link',
          values: { username: step.username, minutes: String(minutes) },
          links: { signin: authn.EMAIL_LINK_OPEN_PATH + '?mfa=' +
                           encodeURIComponent(mfaId) + '&t=' +
                           encodeURIComponent(secret) },
          dedupKey: 'sign-in:' + mfaId + ':' + state.sends, via: 'authn' });
    const refused = !sent || !sent.ok;
    audit.audit({ action: refused ? 'authn.mail-factor.refused'
                                  : 'authn.mail-factor.sent',
      outcome: refused ? 'failure' : 'success',
      actor: step.username, target: step.username, channel: 'http',
      protocol: 'Authentication',
      errorCode: refused ? (((sent && sent.refused && sent.refused[0]) || {})
                              .code || 'STS-AUTHN-0259') : undefined,
      summary: refused
        ? 'an emailed ' + kind + ' could not be sent to ' + step.username
        : 'an emailed ' + kind + ' was sent to ' + step.username,
      detail: { kind: kind, first: !!step.primary, send: state.sends } });
    if (refused) {
      log.warn(errorCodes.tag('STS-AUTHN-0259') + 'authn: an emailed ' +
               kind + ' for "' + step.username + '" was not sent: ' +
               ((sent && sent.error) || 'the mail channel refused it'));
      log.debug("Leaving EmailFactor.arm(). Not sent.");
      return { ok: false, code: 'STS-AUTHN-0259',
               why: 'The message could not be sent just now.' };
    }
    log.debug("Leaving EmailFactor.arm(). Sent.");
    return { ok: true };
  }

  // -------------------------------------------------------------------------
  // THE PAGES, AS VIEWS (#573, 2026-10-12). `/authn/email-code`,
  // `/authn/email-link` and `/authn/email-link/open` are pages of the
  // sign-in surface since #573: each answers the shell, and the browser draws
  // it from `GET /authn-api/mfa/{id}?page=` (`view()` below) in the
  // `emailFactor` catalogs' words — facts and no words here — and sends its
  // acts to `/authn-api` (`sendAct()`, `codeAct()`, `openAct()`).
  //
  // A view is one of six STATES: `ask` (nothing mailed yet: a "use email
  // instead" link must not itself send anything), `code` (a code was sent),
  // `wait` (a link was sent: the browser asks again every `seconds` — the
  // `<meta>` refresh the page had — until the step is spent), `elsewhere`
  // (the waiting tab after the link was opened: the sign-in went on in the
  // tab the link opened, D3), `open` (where the mailed link lands, with a
  // Continue button — a GET spends nothing) and `end` (a refusal: English,
  // every word, #539, with a title and a sentence — what `endPage()` drew).
  //
  // THE LANGUAGE (#539): a SECOND factor's view names the person's own
  // `preferredLanguage`; a FIRST factor's never does — the page is the
  // decoy's too (see the header), and a page drawn in the account holder's
  // language would say that the account exists.
  // -------------------------------------------------------------------------

  // Where the address is named, it is MASKED, and on a first factor it is not
  // named at all: the person typed only a name, and the page must not tell
  // them whose address it is — or that there is one. Answers the masked
  // address, or '' on a first factor.
  private whereTo(step: any): string {
    const { log, mailFactor } = this.deps;
    log.debug("Entering EmailFactor.whereTo().");
    if (step.primary) {
      log.debug("Leaving EmailFactor.whereTo(). A first factor.");
      return '';
    }
    const status = mailFactor.status(step.username);
    log.debug("Leaving EmailFactor.whereTo().");
    return String(mailFactor.masked(status.address) || '');
  }

  // The other factors a second-factor step can still be finished with, as
  // the other pages offer them.
  private otherFactors(step: any): any {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.otherFactors().");
    const out = { totp: false, webauthn: false, password: false,
                  backup: false };
    if (step.primary) {
      log.debug("Leaving EmailFactor.otherFactors(). A first factor.");
      return out;
    }
    const asked = String(step.factor || '');
    out.totp = asked === 'totp' || step.alternate === 'totp';
    out.webauthn = asked === 'webauthn' || step.alternate === 'webauthn';
    out.password = asked === 'password' || !!step.passwordAlternate;
    out.backup = !!step.backup;
    log.debug("Leaving EmailFactor.otherFactors().");
    return out;
  }

  // What the code, wait and ask views share.
  private stepFacts(mfaId: string, step: any, kind: Kind,
                    state: string): any {
    const { log, authnPolicy } = this.deps;
    log.debug("Entering EmailFactor.stepFacts(). " + state);
    const settings = authnPolicy.emailSettings();
    const out = { state: state, kind: kind, id: String(mfaId),
      primary: !!step.primary, username: String(step.username),
      address: this.whereTo(step),
      minutes: Math.round(settings.ttlS / 60), seconds: WAIT_REFRESH_S,
      // A sentence a sign-in act left for this page (#571), said once.
      notice: this.noticeOf(mfaId, step),
      others: this.otherFactors(step) };
    log.debug("Leaving EmailFactor.stepFacts().");
    return out;
  }

  // A refusal's view: English, every word of it (#539).
  private endView(title: string, sentence: string): any {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.endView().");
    log.debug("Leaving EmailFactor.endView().");
    return { state: 'end', title: title, sentence: sentence };
  }

  /**
   * One emailed factor page's view: `{ status, view, code?, uiLocales,
   * preferredLanguage }`. Sends nothing and spends nothing.
   *
   * @param req - the request (the binding cookie is read off it)
   * @param page - `email-code`, `email-link` or `email-link-open`
   * @param mfaId - the step's id
   * @returns the view, with the status and error code to answer it with
   */
  view(req: any, page: string, mfaId: string): any {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.view(). " + page);
    const kind: Kind = page === 'email-code' ? 'code' : 'link';
    const step = authn.mfaStepFor(mfaId);
    const record = (step && step.authn) || {};
    const lang = { uiLocales: String(record.uiLocales || ''),
                   preferredLanguage: step && !step.primary
                     ? authn.preferredLanguageOf(String(step.username)) ||
                       null : null };
    const live = !!step && !!this.kindAllowedOn(step, kind);
    if (!live && page === 'email-link') {
      // THE WAITING TAB, AFTER THE LINK WAS OPENED: the step is spent, and
      // the sign-in went on in the tab the link opened (D3). Not a
      // refusal — the usual end of a waiting tab — so it is translated.
      log.debug("Leaving EmailFactor.view(). Elsewhere.");
      return Object.assign({ status: 200, view: { state: 'elsewhere' } },
                           lang);
    }
    if (!live) {
      log.debug("Leaving EmailFactor.view(). No step.");
      return Object.assign({ status: 400, code: 'STS-AUTHN-0019',
        view: this.endView('This sign-in has expired', 'There is no ' +
          'sign-in waiting for an emailed ' + kind + ' here. It may have ' +
          'finished, or run out of time.') }, lang);
    }
    const armed = !!step.emailState && step.emailState.kind === kind;
    if (page === 'email-link-open') {
      if (!this.boundHere(req, step)) {
        log.debug("Leaving EmailFactor.view(). Another browser.");
        return Object.assign({ status: 400, code: 'STS-AUTHN-0266',
          view: this.endView('Open it where you started', 'This link works ' +
            'only in the browser where you started signing in. Copy it ' +
            'into that browser, or start again here.') }, lang);
      }
      log.debug("Leaving EmailFactor.view(). The link opened.");
      return Object.assign({ status: 200, view: { state: 'open',
        id: String(mfaId), username: String(step.username) } }, lang);
    }
    log.debug("Leaving EmailFactor.view().");
    return Object.assign({ status: 200, view: this.stepFacts(mfaId, step,
      kind, armed ? (kind === 'code' ? 'code' : 'wait') : 'ask') }, lang);
  }

  // Whether this browser holds the binding cookie the link was sent with
  // (D3): opened anywhere else, a link spends nothing.
  private boundHere(req: any, step: any): boolean {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.boundHere().");
    const state = (step && step.emailState) || {};
    const here = this.bindingOf(req);
    const out = !!here && !!state.binding &&
                this.hashOf(here) === state.binding;
    log.debug("Leaving EmailFactor.boundHere(). " + out);
    return out;
  }

  // A refusal that ends the page (what `endPage()` drew): the title and the
  // sentence, English, for the browser to draw; never an error code.
  private endAnswer(res: any, status: number, title: string,
                    sentence: string): void {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.endAnswer(). " + status);
    authn.answerJson(res, status, { ok: false, next: 'refused',
      errors: [String(sentence)], end: { title: String(title) } });
    log.debug("Leaving EmailFactor.endAnswer().");
  }

  // A refusal the page draws over itself, the step kept: a wrong code, a
  // rate limit, a message that could not be sent.
  private stayRefused(res: any, status: number, sentence: string): void {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.stayRefused(). " + status);
    authn.answerJson(res, status, { ok: false, next: 'refused',
                                    errors: [String(sentence)] });
    log.debug("Leaving EmailFactor.stayRefused().");
  }

  // -------------------------------------------------------------------------
  // THE TWO WAYS IN, called by `authn.ts`.
  // -------------------------------------------------------------------------

  // A SECOND FACTOR ASKED FOR BY THE SIGN-IN SCREEN (#571) — or by a
  // wallet's or an emailed first factor's step after it (#572): the step
  // exists and the first message is sent now;
  // the screen is a static surface whose act answers the step's address,
  // and `GET` of that page draws the code or waiting page for an armed step.
  // A message that could not be sent is said there, once (`emailNotice`).
  /**
   * Arms an emailed second factor for the sign-in screen's act: the first
   * code or link is sent, and a refusal to send is kept for the page.
   *
   * @param req - the request
   * @param res - the response (a link's binding cookie is set on it)
   * @param mfaId - the id of the pending second-factor step
   */
  async armSecondFactor(req: any, res: any, mfaId: string): Promise<void> {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.armSecondFactor().");
    const step = authn.mfaStepFor(mfaId);
    const kind = step ? this.kindOfFactor(step.factor) : '';
    if (!step || !kind) {
      log.debug("Leaving EmailFactor.armSecondFactor(). No step.");
      return;
    }
    const armed = await this.arm(req, res, mfaId, step, kind);
    if (!armed.ok) {
      this.deps.errorCodes.mark(res, armed.code);
      const held = authn.mfaStepFor(mfaId);
      if (held) {
        held.emailNotice = armed.why + ' Use another way to finish ' +
                           'signing in, if you have one.';
        authn.saveMfaStep(mfaId, held);
      }
    }
    log.debug("Leaving EmailFactor.armSecondFactor().");
  }

  // A sentence a sign-in act left for the page it sent the browser to
  // (#571), said once.
  private noticeOf(mfaId: string, step: any): string {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.noticeOf().");
    const said = String((step && step.emailNotice) || '');
    if (said) {
      delete step.emailNotice;
      authn.saveMfaStep(mfaId, step);
    }
    log.debug("Leaving EmailFactor.noticeOf().");
    return said;
  }

  // A FIRST FACTOR, from the sign-in screen's two buttons.
  /**
   * Starts an emailed code or link as a first factor from the sign-in
   * screen.
   *
   * Every reason a real sign-in cannot proceed (no account, no verified
   * address, a disabled account) gets the same page on a decoy step that no
   * code can finish, and nothing is mailed; the refusal is audited.
   * @param req - the request
   * @param res - the response, which this writes
   * @param base - the service's base URL
   * @param record - the pending authorization record
   * @param username - the name typed on the sign-in screen
   * @param kind - `code` or `link`
   */
  async beginFirstFactor(req: any, res: any, base: string, record: any,
                         username: string, kind: Kind): Promise<void> {
    const { log, authn, authnPolicy, websecurity, errorCodes, mailFactor,
            audit, now } = this.deps;
    log.debug("Entering EmailFactor.beginFirstFactor(). " + kind);
    if (!authnPolicy.active(this.mechanismOf(kind), 'primary')) {
      log.info('authn: an emailed ' + kind + ' was asked for as a first ' +
               'factor and this realm does not offer one.');
      errorCodes.mark(res, 'STS-AUTHN-0260');
      authn.refuseAtScreen(res, record, 'This realm does not offer ' +
        'an emailed ' + kind + ' as a way to sign in.');
      log.debug("Leaving EmailFactor.beginFirstFactor(). Not offered.");
      return;
    }
    if (record.forceKey || record.forcePasswordless || record.lockedUsername) {
      errorCodes.mark(res, 'STS-AUTHN-0260');
      authn.refuseAtScreen(res, record, 'This sign-in asks for a ' +
        'security key or a password, and an emailed ' + kind + ' answers ' +
        'neither.');
      log.debug("Leaving EmailFactor.beginFirstFactor(). Demanded else.");
      return;
    }
    const allowed = await websecurity.attemptShared('sign-in', req, username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0008');
      authn.refuseAtScreen(res, record, allowed.detail, 429);
      log.debug("Leaving EmailFactor.beginFirstFactor(). Rate limited.");
      return;
    }
    // THE DECOY (see the header). Every reason a real sign-in could not
    // proceed ends here, on the same page.
    const status = mailFactor.status(username);
    const reason = !status.address ? 'no account, or no address'
      : (!status.verified ? 'the address is not verified'
        : (this.deps.isDisabled(username) ? 'the account is disabled' : ''));
    authn.takePending(record);
    const step: any = {
      authn: record, username: username,
      challenge: stsCrypto.randomBytes(32).toString('base64url'),
      factor: 'email-' + kind, alternate: '', backup: false,
      passwordless: false, primary: true, firstAmr: [],
      decoy: !!reason, email: '',
      expires: now() + authn.mfaStepTtlMs()
    };
    const mfaId = authn.mintMfaStep(step);
    if (reason) {
      audit.audit({ action: 'authn.mail-factor.refused', outcome: 'failure',
        actor: username, target: username, channel: 'http',
        protocol: 'Authentication', errorCode: 'STS-AUTHN-0261',
        summary: 'an emailed ' + kind + ' first factor was asked for "' +
                 username + '" and not sent: ' + reason,
        detail: { kind: kind, first: true } });
      log.info('authn: an emailed ' + kind + ' for "' + username + '" was ' +
               'not sent (' + reason + '); the page does not say so.');
      errorCodes.mark(res, 'STS-AUTHN-0261');
    }
    await this.arm(req, res, mfaId, step, kind);
    // SINCE #571 THE SCREEN'S ACT ANSWERS THE STEP'S ADDRESS (`/authn-api`),
    // and that page's GET draws the code or waiting page for the armed step
    // — the same page whatever the reason, decoy included.
    void base;
    authn.stepAnswer(res, 'mfa', 'email-' + kind, mfaId,
                     kind === 'code' ? authn.EMAIL_CODE_PATH
                                     : authn.EMAIL_LINK_PATH, 'mfa');
    log.debug("Leaving EmailFactor.beginFirstFactor().");
  }

  // -------------------------------------------------------------------------
  // SPENDING A SECRET: the claim that makes it once for the cluster, and the
  // finish — a first factor's or a second's.
  // -------------------------------------------------------------------------
  private async spend(req: any, res: any, mfaId: string, step: any,
                      kind: Kind): Promise<boolean> {
    const { log, authn, clusterClaims, realms, mailFactor, websecurity,
            audit, errorCodes } = this.deps;
    log.debug("Entering EmailFactor.spend(). " + kind);
    const state = step.emailState;
    const claimed = await clusterClaims.claim({
      scope: 'authn.email-secret', value: mfaId + ':' + state.sends,
      ttlMs: Math.max(0, state.expiresAt - this.deps.now()) + CLAIM_SKEW_MS,
      realm: realms.currentId() });
    if (!claimed.ok) {
      log.info('authn: an emailed ' + kind + ' for "' + step.username +
               '" was already used (' + (claimed.reason || 'store') + ').');
      errorCodes.mark(res, claimed.reason === 'used' ? 'STS-AUTHN-0262'
                                                     : 'STS-AUTHN-0263');
      this.endAnswer(res, 400, 'Already used', claimed.reason === 'used'
        ? 'That ' + kind + ' has already been used.'
        : 'That ' + kind + ' could not be checked just now.');
      log.debug("Leaving EmailFactor.spend(). Not claimed.");
      return false;
    }
    await websecurity.succeededShared('mfa-code', req, step.username);
    mailFactor.noteSuccess(step.username);
    audit.audit({ action: 'authn.mail-factor.accepted', outcome: 'success',
      actor: step.username, target: step.username, channel: 'http',
      protocol: 'Authentication',
      summary: step.username + ' presented an emailed ' + kind +
               (step.primary ? ' as a first factor' : ' as a second factor'),
      detail: { kind: kind, first: !!step.primary } });
    if (step.primary) {
      authn.dropMfaStep(mfaId);
      const done = await authn.finishEmailFirstFactor(req, res, step, kind);
      if (done && done.refused) {
        errorCodes.mark(res, done.errorCode || 'STS-AUTHN-0009');
        this.endAnswer(res, 403, 'Not signed in', done.why);
      }
      log.debug("Leaving EmailFactor.spend(). First factor.");
      return true;
    }
    authn.finishEmailSecondFactor(req, res, mfaId, step, kind);
    log.debug("Leaving EmailFactor.spend(). Second factor.");
    return true;
  }

  // A wrong secret: counted on the step and — for a real account holding the
  // factor or using it first — on the entry.
  private async countWrong(res: any, mfaId: string, step: any,
                       kind: Kind): Promise<string> {
    const { log, authn, authnPolicy, mailFactor, audit, errorCodes } =
      this.deps;
    log.debug("Entering EmailFactor.countWrong(). " + kind);
    const state = step.emailState;
    state.attempts += 1;
    const limit = authnPolicy.emailSettings().attempts;
    if (!step.decoy) {
      mailFactor.noteFailure(step.username);
    }
    audit.audit({ action: 'authn.mail-factor.refused', outcome: 'failure',
      actor: step.username, target: step.username, channel: 'http',
      protocol: 'Authentication', errorCode: 'STS-AUTHN-0264',
      summary: 'a wrong emailed ' + kind + ' for ' + step.username,
      detail: { kind: kind, attempt: state.attempts, limit: limit } });
    errorCodes.mark(res, 'STS-AUTHN-0264');
    if (state.attempts >= limit) {
      authn.dropMfaStep(mfaId);
      log.debug("Leaving EmailFactor.countWrong(). The step ended.");
      return 'ended';
    }
    authn.saveMfaStep(mfaId, step);
    log.debug("Leaving EmailFactor.countWrong(). " + state.attempts + " of " +
              limit + ".");
    return 'That ' + kind + ' is not right. ' + (limit - state.attempts) +
           ' more attempt(s) before this sign-in ends.';
  }

  // The step behind an act, if it is live and may be answered with this
  // kind; otherwise the end page is answered and null returned.
  private liveStep(res: any, mfaId: string, kind: Kind): any {
    const { log, authn, errorCodes } = this.deps;
    log.debug("Entering EmailFactor.liveStep().");
    const step = authn.mfaStepFor(mfaId);
    if (!step || !this.kindAllowedOn(step, kind)) {
      errorCodes.mark(res, 'STS-AUTHN-0019');
      this.endAnswer(res, 400, 'This sign-in has expired',
                     'There is no sign-in waiting for an emailed ' + kind +
                     ' here. It may have finished, or run out of time.');
      log.debug("Leaving EmailFactor.liveStep(). None.");
      return null;
    }
    log.debug("Leaving EmailFactor.liveStep().");
    return step;
  }

  // -------------------------------------------------------------------------
  // THE ACTS (#573), `/authn-api`'s operations on an emailed factor's step —
  // what the three forms' POSTs did, moved whole. A send or a refusal the
  // page can recover from answers the page again (`next: stay` with
  // `notice: resent`, or `next: refused` with the sentence); a refusal that
  // ends the sign-in answers an end page (`end: { title }`); a spent secret
  // answers the sign-in's next step (`authn.ts`, JSON because the API set
  // `res.locals.authnApi`).
  // -------------------------------------------------------------------------
  /**
   * Mails a new code or link for a live step (the page's Send and Send
   * again). A link's binding cookie is set on this answer.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param kind - `code` or `link`
   * @returns a promise settled when the answer is sent
   */
  async sendAct(req: any, res: any, mfaId: string,
                kind: Kind): Promise<void> {
    const { log, errorCodes, authn } = this.deps;
    log.debug("Entering EmailFactor.sendAct(). " + kind);
    const step = this.liveStep(res, mfaId, kind);
    if (!step) {
      log.debug("Leaving EmailFactor.sendAct(). No step.");
      return;
    }
    const armed = await this.arm(req, res, mfaId, step, kind);
    if (!armed.ok) {
      errorCodes.mark(res, armed.code);
      this.stayRefused(res, 400, String(armed.why));
      log.debug("Leaving EmailFactor.sendAct(). Not sent.");
      return;
    }
    authn.answerJson(res, 200, { ok: true, next: 'stay', notice: 'resent' });
    log.debug("Leaving EmailFactor.sendAct(). Sent.");
  }

  /**
   * Checks a typed code and, when it is right and unexpired, spends it and
   * finishes the step. Wrong codes are counted and end the step at the
   * policy's limit.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param code - the code as typed
   * @returns a promise settled when the answer is sent
   */
  async codeAct(req: any, res: any, mfaId: string,
                code: string): Promise<void> {
    const { log, errorCodes, websecurity, mailFactor, now } = this.deps;
    log.debug("Entering EmailFactor.codeAct().");
    const step = this.liveStep(res, mfaId, 'code');
    if (!step) {
      log.debug("Leaving EmailFactor.codeAct(). No step.");
      return;
    }
    const state = step.emailState;
    if (!state || state.kind !== 'code') {
      errorCodes.mark(res, 'STS-AUTHN-0039');
      this.stayRefused(res, 400, 'No code has been sent for this sign-in ' +
                                 'yet.');
      log.debug("Leaving EmailFactor.codeAct(). Nothing sent.");
      return;
    }
    const allowed = await websecurity.attemptShared('mfa-code', req,
                                                    step.username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0040');
      this.stayRefused(res, 429, allowed.detail);
      log.debug("Leaving EmailFactor.codeAct(). Rate limited.");
      return;
    }
    if (now() > state.expiresAt) {
      errorCodes.mark(res, 'STS-AUTHN-0265');
      this.stayRefused(res, 400, 'That code has expired. Send a new one.');
      log.debug("Leaving EmailFactor.codeAct(). Expired.");
      return;
    }
    const typed = mailFactor.normalizeCode(code);
    const right = !!typed && !!state.hash &&
                  await mailFactor.matches(typed, state.hash);
    if (!right) {
      const said = await this.countWrong(res, mfaId, step, 'code');
      if (said === 'ended') {
        this.endAnswer(res, 400, 'Too many wrong codes', 'This sign-in has ' +
                       'ended.');
      } else {
        this.stayRefused(res, 400, said);
      }
      log.debug("Leaving EmailFactor.codeAct(). Wrong.");
      return;
    }
    await this.spend(req, res, mfaId, step, 'code');
    log.debug("Leaving EmailFactor.codeAct().");
  }

  /**
   * Checks a mailed link's token in the browser that started the sign-in —
   * the Continue button of the page the link lands on — and, when it
   * matches and is unexpired, spends it and finishes the step.
   *
   * @param req - the request
   * @param res - the response
   * @param mfaId - the step's id
   * @param token - the link's `t`
   * @returns a promise settled when the answer is sent
   */
  async openAct(req: any, res: any, mfaId: string,
                token: string): Promise<void> {
    const { log, errorCodes, websecurity, mailFactor, now } = this.deps;
    log.debug("Entering EmailFactor.openAct().");
    const step = this.liveStep(res, mfaId, 'link');
    if (!step) {
      log.debug("Leaving EmailFactor.openAct(). No step.");
      return;
    }
    const state = step.emailState || {};
    if (!this.boundHere(req, step)) {
      errorCodes.mark(res, 'STS-AUTHN-0266');
      this.endAnswer(res, 400, 'Open it where you started', 'This link ' +
        'works only in the browser where you started signing in.');
      log.debug("Leaving EmailFactor.openAct(). Another browser.");
      return;
    }
    const allowed = await websecurity.attemptShared('mfa-code', req,
                                                    step.username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0040');
      this.endAnswer(res, 429, 'Too many attempts', allowed.detail);
      log.debug("Leaving EmailFactor.openAct(). Rate limited.");
      return;
    }
    if (state.kind !== 'link' || now() > state.expiresAt) {
      errorCodes.mark(res, 'STS-AUTHN-0265');
      this.endAnswer(res, 400, 'That link has expired', 'Ask for a new one ' +
        'on the page where you started signing in.');
      log.debug("Leaving EmailFactor.openAct(). Expired.");
      return;
    }
    const right = !!token && !!state.hash &&
                  await mailFactor.matches(String(token), state.hash);
    if (!right) {
      const said = await this.countWrong(res, mfaId, step, 'link');
      this.endAnswer(res, 400, 'That link is not right', said === 'ended'
        ? 'This sign-in has ended.' : 'That link is not the latest one ' +
          'sent. Use the newest message.');
      log.debug("Leaving EmailFactor.openAct(). Wrong.");
      return;
    }
    await this.spend(req, res, mfaId, step, 'link');
    log.debug("Leaving EmailFactor.openAct().");
  }

  // THE ROUTES, registered by the composition root just after `authn`: the
  // three pages answer the sign-in surface's shell (#573), whatever their
  // query — the view says what is wrong with it, in the page — and their
  // form POSTs are gone. The mailed link keeps pointing at
  // `/authn/email-link/open?mfa=…&t=…`, and its GET still spends nothing:
  // it draws a Continue button, which spends it through `/authn-api`.
  /**
   * Registers the three `/authn/email-*` pages' shells.
   *
   * @param app - the express app
   */
  registerRoutes(app: RouteApp): void {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.registerRoutes().");
    [authn.EMAIL_CODE_PATH, authn.EMAIL_LINK_PATH,
     authn.EMAIL_LINK_OPEN_PATH].forEach(function (path: string) {
      (app as any).get(path, function (req: any, res: any) {
        log.debug('Entering GET ' + path + '.');
        const id = String((req.query && req.query.mfa) || '');
        const step = /^[A-Za-z0-9_-]{1,128}$/.test(id)
          ? authn.mfaStepFor(id) : null;
        authn.signInShell(req, res, String((step && step.authn &&
                                            step.authn.application) || ''));
        log.debug('Leaving GET ' + path + '.');
      });
    });
    log.debug("Leaving EmailFactor.registerRoutes().");
  }
}


const slot = new InstanceSlot<EmailFactor>(
  'authn/email_factor',
  () => new EmailFactor(EmailFactor.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The emailed code and sign-in link, as first or second factors (#64).
 *
 * Exports the class for the composition root and facades that forward to
 * the installed instance; `authn.ts` calls the two `begin` functions.
 * @namespace
 */
export = {
  registerRoutes: slot.forward('registerRoutes'),
  EmailFactor: EmailFactor,
  installInstance: (instance: EmailFactor): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BINDING_COOKIE: EmailFactor.BINDING_COOKIE,
  view: slot.forward('view'),
  sendAct: slot.forward('sendAct'),
  codeAct: slot.forward('codeAct'),
  openAct: slot.forward('openAct'),
  beginFirstFactor: slot.forward('beginFirstFactor'),
  armSecondFactor: slot.forward('armSecondFactor')
};
