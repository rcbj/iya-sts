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

import nodeCrypto = require('crypto');
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
const BINDING_COOKIE = 'sts_email_binding';

// How often the waiting page of a link refreshes itself.
const WAIT_REFRESH_S = 4;

// A claim outlives the step by the clock disagreement other single-use values
// allow.
const CLAIM_SKEW_MS = 60 * 1000;

const vz = validation.z;
const vt = validation.types;

const STEP_QUERY = vz.object({
  mfa: vt.opt(vt.base64url)
});

const CODE_FORM = vz.object({
  mfa_id: vt.opt(vt.base64url),
  action: vt.opt(vt.oneOf(['send', 'verify'])),
  // A STRING, as the one-time code screen's is: `007123` is not 7123.
  code: vz.string().max(32).optional(),
  csrf_token: vt.opt(vt.token)
});

const LINK_FORM = vz.object({
  mfa_id: vt.opt(vt.base64url),
  action: vt.opt(vt.oneOf(['send'])),
  csrf_token: vt.opt(vt.token)
});

const OPEN_QUERY = vz.object({
  mfa: vt.opt(vt.base64url),
  t: vt.opt(vt.base64url)
});

const OPEN_FORM = vz.object({
  mfa_id: vt.opt(vt.base64url),
  t: vt.opt(vt.base64url),
  csrf_token: vt.opt(vt.token)
});

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

class EmailFactor {
  static readonly BINDING_COOKIE = BINDING_COOKIE;

  constructor(private readonly deps: EmailFactorDeps) {
    deps.log.debug("Entering EmailFactor.constructor().");
    deps.log.debug("Leaving EmailFactor.constructor().");
  }

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
    return nodeCrypto.createHash('sha256').update(String(value), 'utf8')
      .digest('base64url');
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
      const binding = nodeCrypto.randomBytes(32).toString('base64url');
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
  // THE PAGES. The sign-in screen's own look (`authn.CARD_CSS`), no script.
  // -------------------------------------------------------------------------
  private shell(title: string, body: string, refreshUrl?: string): string {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering EmailFactor.shell().");
    log.debug("Leaving EmailFactor.shell().");
    return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">' +
      (refreshUrl ? '<meta http-equiv="refresh" content="' + WAIT_REFRESH_S +
                    ';url=' + xmlEscape(refreshUrl) + '">' : '') +
      '<title>' + xmlEscape(title) + ' — mock authentication service' +
      '</title><style>' + authn.CARD_CSS +
      'input.code{font-size:1.4em;letter-spacing:.35em;text-align:center;' +
      'font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
      '</style></head><body><div class="card">' + body +
      '</div></body></html>\n';
  }

  private send(res: any, status: number, html: string): void {
    const { log } = this.deps;
    log.debug("Entering EmailFactor.send(). " + status);
    // `no-store` for the reason every page in a sign-in carries it.
    res.status(status).type('text/html').set('Cache-Control', 'no-store')
      .send(html);
    log.debug("Leaving EmailFactor.send().");
  }

  // Where the address is named, it is MASKED, and on a first factor it is not
  // named at all: the person typed only a name, and the page must not tell
  // them whose address it is — or that there is one.
  private whereTo(step: any): string {
    const { log, mailFactor, xmlEscape } = this.deps;
    log.debug("Entering EmailFactor.whereTo().");
    if (step.primary) {
      log.debug("Leaving EmailFactor.whereTo(). A first factor.");
      return 'the address on the account, if it has a verified one';
    }
    const status = mailFactor.status(step.username);
    log.debug("Leaving EmailFactor.whereTo().");
    return '<code>' + xmlEscape(mailFactor.masked(status.address)) +
           '</code>';
  }

  // The other factors a second-factor step can still be finished with, as
  // the other screens draw them.
  private otherFactorsHtml(mfaId: string, step: any): string {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.otherFactorsHtml().");
    if (step.primary) {
      log.debug("Leaving EmailFactor.otherFactorsHtml(). A first factor.");
      return '';
    }
    const q = '?mfa=' + encodeURIComponent(mfaId);
    const asked = String(step.factor || '');
    let out = '';
    if (asked === 'totp' || step.alternate === 'totp') {
      out += '<div><a href="/authn/totp' + q + '">Use your authenticator ' +
             'app instead</a></div>';
    }
    if (asked === 'webauthn' || step.alternate === 'webauthn') {
      out += '<div><a href="/authn/webauthn' + q + '">Use your security key ' +
             'instead</a></div>';
    }
    if (asked === 'password' || step.passwordAlternate) {
      out += '<div><a href="' + authn.PASSWORD_FACTOR_PATH + q + '">Use ' +
             'your password instead</a></div>';
    }
    if (step.backup) {
      out += '<div><a href="' + authn.BACKUP_CODE_PATH + q + '">Use a ' +
             'recovery code</a></div>';
    }
    log.debug("Leaving EmailFactor.otherFactorsHtml().");
    return out;
  }

  // The page that asks before a code or a link is mailed — reached from a
  // "use email instead" link, which must not itself send anything.
  private askPage(mfaId: string, step: any, kind: Kind,
                  error: string): string {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering EmailFactor.askPage(). " + kind);
    const path = kind === 'code' ? authn.EMAIL_CODE_PATH
                                 : authn.EMAIL_LINK_PATH;
    const out = this.shell('Email', '<h1>' + (kind === 'code'
        ? 'Email me a code' : 'Email me a sign-in link') + '</h1>' +
      '<p class="sub">Second factor for <code>' +
      xmlEscape(step.username) + '</code></p>' +
      (error ? '<div class="err">' + xmlEscape(error) + '</div>' : '') +
      '<p>A ' + (kind === 'code' ? 'six-digit code' : 'single-use link') +
      ' will be sent to ' + this.whereTo(step) + '.</p>' +
      '<form method="post" action="' + path + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<input type="hidden" name="action" value="send">' +
      '<button type="submit" id="email-send">Send it</button></form>' +
      '<div class="meta">' + this.otherFactorsHtml(mfaId, step) + '</div>');
    log.debug("Leaving EmailFactor.askPage().");
    return out;
  }

  private codePage(mfaId: string, step: any, error: string,
                   notice: string): string {
    const { log, xmlEscape, authnPolicy } = this.deps;
    log.debug("Entering EmailFactor.codePage().");
    const settings = authnPolicy.emailSettings();
    const out = this.shell('Your emailed code', '<h1>Check your email</h1>' +
      '<p class="sub">' + (step.primary ? 'Signing in as ' : 'Second factor ' +
        'for ') + '<code>' + xmlEscape(step.username) + '</code></p>' +
      (error ? '<div class="err" id="email-error">' + xmlEscape(error) +
               '</div>' : '') +
      (notice ? '<div class="ok">' + xmlEscape(notice) + '</div>' : '') +
      '<p>A six-digit code was sent to ' + this.whereTo(step) + '. It works ' +
      'once, for ' + Math.round(settings.ttlS / 60) + ' minutes.</p>' +
      '<form method="post" action="' + authn.EMAIL_CODE_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<input type="hidden" name="action" value="verify">' +
      '<label for="code">The code from the message</label>' +
      '<input type="text" class="code" id="code" name="code" ' +
      'autocomplete="one-time-code" inputmode="numeric" pattern="[0-9 -]*" ' +
      'maxlength="9" autofocus placeholder="000000">' +
      '<button type="submit" id="email-code-submit">Sign in</button>' +
      '</form>' +
      '<form method="post" action="' + authn.EMAIL_CODE_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<input type="hidden" name="action" value="send">' +
      '<button type="submit" id="email-code-resend" class="secondary">' +
      'Send a new code</button></form>' +
      '<div class="meta"><div>A new code replaces the last one. Nobody from ' +
      'this service will ever ask you for it.</div>' +
      this.otherFactorsHtml(mfaId, step) + '</div>');
    log.debug("Leaving EmailFactor.codePage().");
    return out;
  }

  private waitPage(mfaId: string, step: any, error: string,
                   notice: string): string {
    const { log, xmlEscape, realms, authnPolicy } = this.deps;
    log.debug("Entering EmailFactor.waitPage().");
    const settings = authnPolicy.emailSettings();
    const out = this.shell('Check your email', '<h1>Check your email</h1>' +
      '<p class="sub">' + (step.primary ? 'Signing in as ' : 'Second factor ' +
        'for ') + '<code>' + xmlEscape(step.username) + '</code></p>' +
      (error ? '<div class="err" id="email-error">' + xmlEscape(error) +
               '</div>' : '') +
      (notice ? '<div class="ok">' + xmlEscape(notice) + '</div>' : '') +
      '<p>A sign-in link was sent to ' + this.whereTo(step) + '. <strong>' +
      'Open it in this browser</strong> — it works only here, once, for ' +
      Math.round(settings.ttlS / 60) + ' minutes.</p>' +
      '<form method="post" action="' + authn.EMAIL_LINK_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<input type="hidden" name="action" value="send">' +
      '<button type="submit" id="email-link-resend" class="secondary">' +
      'Send a new link</button></form>' +
      '<div class="meta"><div>This page checks every ' + WAIT_REFRESH_S +
      ' seconds. A new link replaces the last one.</div>' +
      this.otherFactorsHtml(mfaId, step) + '</div>',
      realms.href(authn.EMAIL_LINK_PATH + '?mfa=' +
                  encodeURIComponent(mfaId)));
    log.debug("Leaving EmailFactor.waitPage().");
    return out;
  }

  private endPage(res: any, status: number, title: string,
                  sentence: string): void {
    const { log, xmlEscape } = this.deps;
    log.debug("Entering EmailFactor.endPage().");
    this.send(res, status, this.shell(title, '<h1>' + xmlEscape(title) +
      '</h1><div class="err" id="email-error">' + xmlEscape(sentence) +
      '</div><p class="meta">Start again from the application that sent ' +
      'you here.</p>'));
    log.debug("Leaving EmailFactor.endPage().");
  }

  // -------------------------------------------------------------------------
  // THE TWO WAYS IN, called by `authn.ts`.
  // -------------------------------------------------------------------------

  // A SECOND FACTOR: the step exists and asks for an emailed factor. The
  // first one is sent at once — the person is expecting it.
  async beginSecondFactor(req: any, res: any, base: string,
                          mfaId: string): Promise<void> {
    const { log, authn } = this.deps;
    log.debug("Entering EmailFactor.beginSecondFactor().");
    void base;
    const step = authn.mfaStepFor(mfaId);
    const kind = step ? this.kindOfFactor(step.factor) : '';
    if (!step || !kind) {
      this.endPage(res, 400, 'This sign-in has expired',
                   'There is no sign-in waiting for an emailed factor.');
      log.debug("Leaving EmailFactor.beginSecondFactor(). No step.");
      return;
    }
    const armed = await this.arm(req, res, mfaId, step, kind);
    const error = armed.ok ? '' : armed.why + ' Use another way to finish ' +
                                  'signing in, if you have one.';
    if (!armed.ok) {
      this.deps.errorCodes.mark(res, armed.code);
    }
    this.send(res, 200, kind === 'code'
      ? this.codePage(mfaId, step, error, '')
      : this.waitPage(mfaId, step, error, ''));
    log.debug("Leaving EmailFactor.beginSecondFactor().");
  }

  // A FIRST FACTOR, from the sign-in screen's two buttons.
  async beginFirstFactor(req: any, res: any, base: string, record: any,
                         username: string, kind: Kind): Promise<void> {
    const { log, authn, authnPolicy, websecurity, errorCodes, mailFactor,
            audit, now } = this.deps;
    log.debug("Entering EmailFactor.beginFirstFactor(). " + kind);
    if (!authnPolicy.active(this.mechanismOf(kind), 'primary')) {
      log.info('authn: an emailed ' + kind + ' was asked for as a first ' +
               'factor and this realm does not offer one.');
      errorCodes.mark(res, 'STS-AUTHN-0260');
      authn.sendLoginPageFor(res, base, record, 'This realm does not offer ' +
        'an emailed ' + kind + ' as a way to sign in.');
      log.debug("Leaving EmailFactor.beginFirstFactor(). Not offered.");
      return;
    }
    if (record.forceKey || record.forcePasswordless || record.lockedUsername) {
      errorCodes.mark(res, 'STS-AUTHN-0260');
      authn.sendLoginPageFor(res, base, record, 'This sign-in asks for a ' +
        'security key or a password, and an emailed ' + kind + ' answers ' +
        'neither.');
      log.debug("Leaving EmailFactor.beginFirstFactor(). Demanded else.");
      return;
    }
    const allowed = await websecurity.attemptShared('sign-in', req, username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0008');
      authn.sendLoginPageFor(res, base, record, allowed.detail);
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
      challenge: nodeCrypto.randomBytes(32).toString('base64url'),
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
    this.send(res, 200, kind === 'code' ? this.codePage(mfaId, step, '', '')
                                        : this.waitPage(mfaId, step, '', ''));
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
      this.endPage(res, 400, 'Already used', claimed.reason === 'used'
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
        this.endPage(res, 403, 'Not signed in', done.why);
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
  private async refuse(res: any, mfaId: string, step: any,
                       kind: Kind): Promise<string> {
    const { log, authn, authnPolicy, mailFactor, audit, errorCodes } =
      this.deps;
    log.debug("Entering EmailFactor.refuse(). " + kind);
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
      log.debug("Leaving EmailFactor.refuse(). The step ended.");
      return 'ended';
    }
    authn.saveMfaStep(mfaId, step);
    log.debug("Leaving EmailFactor.refuse(). " + state.attempts + " of " +
              limit + ".");
    return 'That ' + kind + ' is not right. ' + (limit - state.attempts) +
           ' more attempt(s) before this sign-in ends.';
  }

  // The step behind a form or a query, if it is live and may be answered
  // with this kind; otherwise the page that says so is drawn and null
  // answered.
  private liveStep(res: any, mfaId: string, kind: Kind): any {
    const { log, authn, errorCodes } = this.deps;
    log.debug("Entering EmailFactor.liveStep().");
    const step = authn.mfaStepFor(mfaId);
    if (!step || !this.kindAllowedOn(step, kind)) {
      errorCodes.mark(res, 'STS-AUTHN-0019');
      this.endPage(res, 400, 'This sign-in has expired',
                   'There is no sign-in waiting for an emailed ' + kind +
                   ' here. It may have finished, or run out of time.');
      log.debug("Leaving EmailFactor.liveStep(). None.");
      return null;
    }
    log.debug("Leaving EmailFactor.liveStep().");
    return step;
  }

  // -------------------------------------------------------------------------
  // THE HANDLERS.
  // -------------------------------------------------------------------------
  async handleCodeGet(req: any, res: any): Promise<void> {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering EmailFactor.handleCodeGet().");
    const asked = validation.check(req, 'query', STEP_QUERY);
    if (!asked.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0018');
      this.endPage(res, 400, 'Not a sign-in', 'That address is not one ' +
                   'this service handed out.');
      log.debug("Leaving EmailFactor.handleCodeGet(). Invalid.");
      return;
    }
    const mfaId = String(asked.value.mfa || '');
    const step = this.liveStep(res, mfaId, 'code');
    if (!step) {
      log.debug("Leaving EmailFactor.handleCodeGet(). No step.");
      return;
    }
    const armed = step.emailState && step.emailState.kind === 'code';
    this.send(res, 200, armed ? this.codePage(mfaId, step, '', '')
                              : this.askPage(mfaId, step, 'code', ''));
    log.debug("Leaving EmailFactor.handleCodeGet().");
  }

  async handleCodePost(req: any, res: any): Promise<void> {
    const { log, validation, parseBody, errorCodes, websecurity,
            mailFactor, now } = this.deps;
    log.debug("Entering EmailFactor.handleCodePost().");
    const posted = validation.checkParsed(parseBody(req), 'body', CODE_FORM);
    if (!posted.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0039');
      this.endPage(res, 400, 'Not a sign-in', 'That form is not one this ' +
                   'service drew.');
      log.debug("Leaving EmailFactor.handleCodePost(). Invalid.");
      return;
    }
    const mfaId = String(posted.value.mfa_id || '');
    const step = this.liveStep(res, mfaId, 'code');
    if (!step) {
      log.debug("Leaving EmailFactor.handleCodePost(). No step.");
      return;
    }
    if (String(posted.value.action || '') === 'send') {
      const armed = await this.arm(req, res, mfaId, step, 'code');
      if (!armed.ok) {
        errorCodes.mark(res, armed.code);
      }
      this.send(res, 200, this.codePage(mfaId, step,
        armed.ok ? '' : armed.why, armed.ok ? 'A new code is on its way.'
                                            : ''));
      log.debug("Leaving EmailFactor.handleCodePost(). Sent.");
      return;
    }
    const state = step.emailState;
    if (!state || state.kind !== 'code') {
      this.send(res, 200, this.askPage(mfaId, step, 'code',
        'No code has been sent for this sign-in yet.'));
      log.debug("Leaving EmailFactor.handleCodePost(). Nothing sent.");
      return;
    }
    const allowed = await websecurity.attemptShared('mfa-code', req,
                                                    step.username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0040');
      this.send(res, 200, this.codePage(mfaId, step, allowed.detail, ''));
      log.debug("Leaving EmailFactor.handleCodePost(). Rate limited.");
      return;
    }
    if (now() > state.expiresAt) {
      errorCodes.mark(res, 'STS-AUTHN-0265');
      this.send(res, 200, this.codePage(mfaId, step, 'That code has ' +
        'expired. Send a new one.', ''));
      log.debug("Leaving EmailFactor.handleCodePost(). Expired.");
      return;
    }
    const typed = mailFactor.normalizeCode(posted.value.code);
    const right = !!typed && !!state.hash &&
                  await mailFactor.matches(typed, state.hash);
    if (!right) {
      const said = await this.refuse(res, mfaId, step, 'code');
      if (said === 'ended') {
        this.endPage(res, 400, 'Too many wrong codes', 'This sign-in has ' +
                     'ended.');
      } else {
        this.send(res, 200, this.codePage(mfaId, step, said, ''));
      }
      log.debug("Leaving EmailFactor.handleCodePost(). Wrong.");
      return;
    }
    await this.spend(req, res, mfaId, step, 'code');
    log.debug("Leaving EmailFactor.handleCodePost().");
  }

  async handleLinkGet(req: any, res: any): Promise<void> {
    const { log, validation, errorCodes } = this.deps;
    log.debug("Entering EmailFactor.handleLinkGet().");
    const asked = validation.check(req, 'query', STEP_QUERY);
    if (!asked.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0018');
      this.endPage(res, 400, 'Not a sign-in', 'That address is not one ' +
                   'this service handed out.');
      log.debug("Leaving EmailFactor.handleLinkGet(). Invalid.");
      return;
    }
    const mfaId = String(asked.value.mfa || '');
    const step = this.deps.authn.mfaStepFor(mfaId);
    if (!step || !this.kindAllowedOn(step, 'link')) {
      // THE WAITING TAB, AFTER THE LINK WAS OPENED: the step is spent, and
      // the sign-in went on in the tab the link opened (D3).
      this.send(res, 200, this.shell('Signed in elsewhere',
        '<h1>Nothing is waiting here</h1><p id="email-done">If you opened ' +
        'the link, the sign-in has continued in the tab it opened, and you ' +
        'can close this one. If you did not, this sign-in has run out of ' +
        'time; start again from the application that sent you here.</p>'));
      log.debug("Leaving EmailFactor.handleLinkGet(). No step.");
      return;
    }
    const armed = step.emailState && step.emailState.kind === 'link';
    this.send(res, 200, armed ? this.waitPage(mfaId, step, '', '')
                              : this.askPage(mfaId, step, 'link', ''));
    log.debug("Leaving EmailFactor.handleLinkGet().");
  }

  async handleLinkPost(req: any, res: any): Promise<void> {
    const { log, validation, parseBody, errorCodes } = this.deps;
    log.debug("Entering EmailFactor.handleLinkPost().");
    const posted = validation.checkParsed(parseBody(req), 'body', LINK_FORM);
    if (!posted.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0039');
      this.endPage(res, 400, 'Not a sign-in', 'That form is not one this ' +
                   'service drew.');
      log.debug("Leaving EmailFactor.handleLinkPost(). Invalid.");
      return;
    }
    const mfaId = String(posted.value.mfa_id || '');
    const step = this.liveStep(res, mfaId, 'link');
    if (!step) {
      log.debug("Leaving EmailFactor.handleLinkPost(). No step.");
      return;
    }
    const armed = await this.arm(req, res, mfaId, step, 'link');
    if (!armed.ok) {
      errorCodes.mark(res, armed.code);
    }
    this.send(res, 200, this.waitPage(mfaId, step, armed.ok ? '' : armed.why,
      armed.ok ? 'A new link is on its way.' : ''));
    log.debug("Leaving EmailFactor.handleLinkPost().");
  }

  // WHERE THE MAILED LINK LANDS. Spends nothing: a Continue button, posting
  // the same two values back.
  async handleOpenGet(req: any, res: any): Promise<void> {
    const { log, validation, errorCodes, xmlEscape } = this.deps;
    log.debug("Entering EmailFactor.handleOpenGet().");
    const asked = validation.check(req, 'query', OPEN_QUERY);
    if (!asked.ok || !asked.value.mfa || !asked.value.t) {
      errorCodes.mark(res, 'STS-AUTHN-0018');
      this.endPage(res, 400, 'Not a sign-in link', 'That link is not one ' +
                   'this service sent.');
      log.debug("Leaving EmailFactor.handleOpenGet(). Invalid.");
      return;
    }
    const mfaId = String(asked.value.mfa);
    const step = this.liveStep(res, mfaId, 'link');
    if (!step) {
      log.debug("Leaving EmailFactor.handleOpenGet(). No step.");
      return;
    }
    const state = step.emailState || {};
    const here = this.bindingOf(req);
    if (!here || !state.binding || this.hashOf(here) !== state.binding) {
      errorCodes.mark(res, 'STS-AUTHN-0266');
      this.endPage(res, 400, 'Open it where you started', 'This link works ' +
        'only in the browser where you started signing in. Copy it into ' +
        'that browser, or start again here.');
      log.debug("Leaving EmailFactor.handleOpenGet(). Another browser.");
      return;
    }
    this.send(res, 200, this.shell('Continue signing in',
      '<h1>Continue signing in</h1><p class="sub">As <code>' +
      xmlEscape(step.username) + '</code></p>' +
      '<form method="post" action="' + authn.EMAIL_LINK_OPEN_PATH + '">' +
      '<input type="hidden" name="mfa_id" value="' + xmlEscape(mfaId) + '">' +
      '<input type="hidden" name="t" value="' +
      xmlEscape(String(asked.value.t)) + '">' +
      '<button type="submit" id="email-link-continue">Continue</button>' +
      '</form><div class="meta"><div>If you did not ask to sign in, close ' +
      'this page: nothing happens until Continue is pressed.</div></div>'));
    log.debug("Leaving EmailFactor.handleOpenGet().");
  }

  async handleOpenPost(req: any, res: any): Promise<void> {
    const { log, validation, parseBody, errorCodes, websecurity,
            mailFactor, now } = this.deps;
    log.debug("Entering EmailFactor.handleOpenPost().");
    const posted = validation.checkParsed(parseBody(req), 'body', OPEN_FORM);
    if (!posted.ok || !posted.value.mfa_id || !posted.value.t) {
      errorCodes.mark(res, 'STS-AUTHN-0039');
      this.endPage(res, 400, 'Not a sign-in link', 'That form is not one ' +
                   'this service drew.');
      log.debug("Leaving EmailFactor.handleOpenPost(). Invalid.");
      return;
    }
    const mfaId = String(posted.value.mfa_id);
    const step = this.liveStep(res, mfaId, 'link');
    if (!step) {
      log.debug("Leaving EmailFactor.handleOpenPost(). No step.");
      return;
    }
    const state = step.emailState || {};
    const here = this.bindingOf(req);
    if (!here || !state.binding || this.hashOf(here) !== state.binding) {
      errorCodes.mark(res, 'STS-AUTHN-0266');
      this.endPage(res, 400, 'Open it where you started', 'This link works ' +
        'only in the browser where you started signing in.');
      log.debug("Leaving EmailFactor.handleOpenPost(). Another browser.");
      return;
    }
    const allowed = await websecurity.attemptShared('mfa-code', req,
                                                    step.username);
    if (!allowed.ok) {
      errorCodes.mark(res, 'STS-AUTHN-0040');
      this.endPage(res, 429, 'Too many attempts', allowed.detail);
      log.debug("Leaving EmailFactor.handleOpenPost(). Rate limited.");
      return;
    }
    if (state.kind !== 'link' || now() > state.expiresAt) {
      errorCodes.mark(res, 'STS-AUTHN-0265');
      this.endPage(res, 400, 'That link has expired', 'Ask for a new one ' +
        'on the page where you started signing in.');
      log.debug("Leaving EmailFactor.handleOpenPost(). Expired.");
      return;
    }
    const right = !!state.hash &&
                  await mailFactor.matches(String(posted.value.t), state.hash);
    if (!right) {
      const said = await this.refuse(res, mfaId, step, 'link');
      this.endPage(res, 400, 'That link is not right', said === 'ended'
        ? 'This sign-in has ended.' : 'That link is not the latest one ' +
          'sent. Use the newest message.');
      log.debug("Leaving EmailFactor.handleOpenPost(). Wrong.");
      return;
    }
    await this.spend(req, res, mfaId, step, 'link');
    log.debug("Leaving EmailFactor.handleOpenPost().");
  }

  // Every handler writes a response; one that threw would leave a browser
  // waiting on a request nothing answers.
  private failed(res: any, e: any): void {
    const { log, errorCodes } = this.deps;
    log.debug("Entering EmailFactor.failed().");
    log.error(errorCodes.tag('STS-AUTHN-0267') + 'authn: the emailed ' +
              'factor failed: ' + ((e && (e.stack || e.message)) || e));
    if (!res.headersSent) {
      errorCodes.mark(res, 'STS-AUTHN-0267');
      this.endPage(res, 500, 'Something went wrong', 'This sign-in could ' +
                   'not continue.');
    }
    log.debug("Leaving EmailFactor.failed().");
  }

  // THE ROUTES, registered by the composition root just after `authn`.
  registerRoutes(app: RouteApp): void {
    const { log, authn } = this.deps;
    const self = this;
    log.debug("Entering EmailFactor.registerRoutes().");
    const on = function (method: string, path: string, name: string): void {
      log.debug("Entering EmailFactor.registerRoutes() on().");
      (app as any)[method](path, function (req: any, res: any) {
        log.debug('Entering ' + method.toUpperCase() + ' ' + path + '.');
        (self as any)[name](req, res).catch(function (e: any) {
          log.debug("Caught in EmailFactor route: " +
                    ((e && e.message) || e));
          self.failed(res, e);
        });
        log.debug('Leaving ' + method.toUpperCase() + ' ' + path + '.');
      });
      log.debug("Leaving EmailFactor.registerRoutes() on().");
    };
    on('get', authn.EMAIL_CODE_PATH, 'handleCodeGet');
    on('post', authn.EMAIL_CODE_PATH, 'handleCodePost');
    on('get', authn.EMAIL_LINK_PATH, 'handleLinkGet');
    on('post', authn.EMAIL_LINK_PATH, 'handleLinkPost');
    on('get', authn.EMAIL_LINK_OPEN_PATH, 'handleOpenGet');
    on('post', authn.EMAIL_LINK_OPEN_PATH, 'handleOpenPost');
    log.debug("Leaving EmailFactor.registerRoutes().");
  }
}

const slot = new InstanceSlot<EmailFactor>(
  'authn/email_factor',
  () => new EmailFactor(EmailFactor.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  registerRoutes: slot.forward('registerRoutes'),
  EmailFactor: EmailFactor,
  installInstance: (instance: EmailFactor): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  BINDING_COOKIE: EmailFactor.BINDING_COOKIE,
  beginSecondFactor: slot.forward('beginSecondFactor'),
  beginFirstFactor: slot.forward('beginFirstFactor')
};
