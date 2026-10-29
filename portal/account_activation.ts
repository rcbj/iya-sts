// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: account_activation.ts
//
// ---------------------------------------------------------------------------
// `/portal/activate`'s TWO OPERATIONS (#568): THE ACTIVATION LINK, CHECKED,
// AND SPENT. Moved from `portal.ts` when the portal became a static
// application; the page is drawn in the browser by `web_activation.ts`, for
// nobody — nobody is signed in.
//
// THE ONE PLACE A USERNAME COMES FROM THE REQUEST, AND IT IS NOT AN
// EXCEPTION TO THE PORTAL'S RULE: nobody is signed in yet, and what
// authorises it is the TOKEN beside the name, which is a credential. So both
// operations are `access: 'link'` — no access token — and:
//
//   * THE LINK IS A CREDENTIAL AND IS TREATED AS ONE: rate limited on the GET
//     as on the POST (`activation`, the cluster's shared window), checked
//     again on the POST (a form is markup; the door is here), and **every way
//     it can fail answers the SAME sentence** (`ACTIVATION_REFUSAL`) — wrong,
//     expired, never issued and no such person are four facts, and telling
//     them apart would let anybody enumerate who has an activation
//     outstanding.
//   * **IT IS SPENT WHEN THE SETUP FINISHES, NOT WHEN IT IS OPENED** — a link
//     consumed on a GET would be burned by a prefetch, a mail scanner or a
//     reload. The POST CLAIMS it in the store before it sets anything
//     (`credentials.spendActivation()`, #46), and the claim is KEPT only by
//     the request that finishes; every other answer gives it back when the
//     response ends (`holdLinkClaim()`), so the link works again exactly as
//     it did on one node.
//   * IT DOES NOT SIGN ANYBODY IN. The last step of setup is to use what was
//     just configured, at the ordinary sign-in — the *account ready* view's
//     link is the portal's own, whose sign-in runs the flow.
//
// THE STEPS, each a view the POST answers and the browser draws in place:
// `setup` (a password, and optionally a passkey and an authenticator app),
// then `key` (the WebAuthn ceremony, authorised by the link, 2026-10-01) if a
// passkey was chosen, then `totp` (scan and prove) if the app was asked for,
// then `ready`. The link is not spent while `key` or `totp` is drawn:
// somebody whose key will not register, or who cannot find their phone,
// still holds a usable link.
//
// A PASSKEY CARRIES NO ROLE SINCE #1135 (rcbj, 2026-10-29), so the setup
// asks only whether to set a password, register a passkey, or both. Until
// then it asked whether the passkey was to be used INSTEAD of a password or
// as a SECOND step after it (`key_role`), and refused a second-step passkey
// with no password. A passkey with no password is now an account that signs
// in passwordless — where the realm lets a passkey be a first factor
// (`webauthnPolicy.useAllowed('primary')`). WHERE IT DOES NOT, A KEY-ONLY
// ACTIVATION IS STILL REFUSED (STS-PORTAL-0007), and again in
// `credentials.removeKey()` at the other end of the same rule: it would
// finish with an account nobody can use, its owner included. `key_role` is
// still accepted, `primary` and `mfa` meaning "register a passkey", because
// a form or a test written before #1135 sends it.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import credentials = require('../common/credentials');
import validation = require('../common/validation');
import passkeyPolicy = require('../common/passkey_policy');
import webauthnPolicy = require('../authn/webauthn_policy');
import totp = require('../common/totp');
import realms = require('../common/realms');
import authn = require('../authn/authn');

type Json = any;
type AccountOperation = import('../types/account-api').AccountOperation;
type AccountContext = import('../types/account-api').AccountContext;

const vz = validation.z;
const vt = validation.types;

// One sentence for every way an activation link can fail — see the header.
const ACTIVATION_REFUSAL =
  'This activation link is not valid. It may have expired, it may already ' +
  'have been used, or it may never have been issued. Ask whoever set up your ' +
  'account for a new one.';

const ACTIVATE_QUERY = vz.object({
  user: vt.opt(vt.name).describe('The username the link names.'),
  token: vt.opt(vt.token).describe('The link\'s single-use token.')
});

const ACTIVATE_FORM = vz.object({
  user: vt.opt(vt.name).describe('The username the link names.'),
  token: vt.opt(vt.token).describe('The link\'s single-use token.'),
  password: vz.string().max(1024).optional()
    .describe('`setup`: the password to set.'),
  confirm: vz.string().max(1024).optional()
    .describe('`setup`: the password again.'),
  // WHETHER TO REGISTER A PASSKEY (#1135): a checkbox, because a passkey
  // carries no role and there is nothing else to choose about it.
  passkey: vt.opt(vt.flag).describe('`setup`: `1` registers a passkey.'),
  // THE FIELD IT REPLACED, STILL ACCEPTED (#1135): `primary` and `mfa`
  // both mean "register a passkey" and `none` means not. A closed set as
  // before, so a value nobody ever sent is still refused.
  key_role: vt.opt(vt.oneOf(['none', 'primary', 'mfa']))
    .describe('Before #1135: `primary` or `mfa` registers a passkey, ' +
              '`none` does not; `passkey` says the same.'),
  // THE AUTHENTICATOR APP (2026-09-10). A checkbox of its own: it is a
  // SECOND factor beside whichever way in was chosen.
  totp: vt.opt(vt.flag).describe('`1`: set up an authenticator app too.'),
  // WHICH POST THIS IS, named explicitly rather than inferred from whether
  // `code` is present: an empty code box and Finish must not read as a fresh
  // start.
  step: vt.opt(vt.oneOf(['setup', 'key', 'totp']))
    .describe('Which step this answers.'),
  code: vz.string().max(32).optional()
    .describe('`totp`: the code the authenticator app shows.'),
  // THE PASSKEY'S STEP (2026-10-01), `/portal/keys`' three fields.
  kind: vt.opt(vt.oneOf(['passkey', 'security-key']))
    .describe('`setup`: where the passkey lives.'),
  // THE LANE (#643), as `/portal/keys` asks it: carried on the pending
  // registration, never read back off the browser's answer.
  lane: vt.opt(vt.oneOf(['classical', 'pqc']))
    .describe('`setup`: `classical` (the default) or `pqc`, where the realm ' +
              'offers a post-quantum passkey beside a classical one.'),
  enrolment_id: vt.opt(vt.base64url)
    .describe('`key`: the pending registration.'),
  credential: vz.string().max(validation.CAP.TEXT).optional()
    .describe('`key`: the browser\'s ceremony result, as JSON.')
});

// A LINK'S CLAIM, HELD FOR THE LIFE OF ONE RESPONSE (2026-09-14, #46): the
// request that finishes marks its response, and the claim is released when
// any other ends.
const LINK_SPENT = Symbol('portal.linkSpent');

interface AccountActivationDeps {
  log: typeof helpers.log;
  credentials: typeof credentials;
  passkeyPolicy: typeof passkeyPolicy;
  webauthnPolicy: typeof webauthnPolicy;
  totp: typeof totp;
  realms: typeof realms;
  authn: typeof authn;
  accountSignals(): Json;
  breachedPasswords(): Json;
}

/**
 * `/portal/activate`'s account API operations: spending an activation link.
 */
class AccountActivation {
  /**
   * Builds the module over its dependencies.
   *
   * @param deps - the modules it reads through
   */
  constructor(private readonly deps: AccountActivationDeps) {
    deps.log.debug("Entering AccountActivation.constructor().");
    deps.log.debug("Leaving AccountActivation.constructor().");
  }

  /**
   * Returns the dependencies the composition root passes.
   *
   * @returns the production dependency set
   */
  static defaultDeps(): AccountActivationDeps {
    helpers.log.debug("Entering AccountActivation.defaultDeps().");
    helpers.log.debug("Leaving AccountActivation.defaultDeps().");
    return {
      log: helpers.log, credentials: credentials,
      passkeyPolicy: passkeyPolicy, webauthnPolicy: webauthnPolicy,
      totp: totp, realms: realms, authn: authn,
      accountSignals: function accountSignals(): Json {
        helpers.log.debug("Entering accountSignals().");
        helpers.log.debug("Leaving accountSignals().");
        return require('../ssf/account_signals');
      },
      breachedPasswords: function breachedPasswords(): Json {
        helpers.log.debug("Entering breachedPasswords().");
        helpers.log.debug("Leaving breachedPasswords().");
        return require('../common/breached_passwords');
      }
    };
  }

  // WHETHER A PASSKEY WAS ASKED FOR (#1135): the `passkey` checkbox, or
  // `key_role` as a form written before #1135 posts it, whose `primary` and
  // `mfa` both asked for one. The step views carry the answer as `passkey`
  // so that the next POST says it again.
  /**
   * Whether a step's body asks for a passkey.
   *
   * @param body - the checked body
   * @returns true where a passkey is to be registered
   */
  wantsPasskey(body: Json): boolean {
    const { log } = this.deps;
    log.debug("Entering AccountActivation.wantsPasskey().");
    const flag = String(body.passkey || '');
    const role = String(body.key_role || 'none');
    const wants = flag === '1' || flag === 'true' || flag === 'on' ||
                  flag === 'yes' || role === 'primary' || role === 'mfa';
    log.debug("Leaving AccountActivation.wantsPasskey(). " + wants);
    return wants;
  }

  // WHERE THE *SIGN IN* LINK GOES (#32): the portal of the realm the link is
  // in; in the default realm, once realms are defined, `?realm=default` is
  // the choice already made.
  /**
   * The portal's sign-in address.
   *
   * @param ctx - the account API's helpers
   * @returns the address
   */
  signInHref(ctx: AccountContext): string {
    const { log, realms } = this.deps;
    log.debug("Entering AccountActivation.signInHref().");
    const skip = realms.isDefault() && realms.active();
    log.debug("Leaving AccountActivation.signInHref().");
    return ctx.PORTAL + (skip ? '?realm=' +
      encodeURIComponent(realms.DEFAULT_ID) : '');
  }

  /**
   * The first step's view: the password, the passkey and the app.
   *
   * @param base - the base the request arrived on
   * @param username - the link's person
   * @param token - the link's token
   * @returns the view
   */
  setupView(base: string, username: string, token: string): Json {
    const { log, credentials, webauthnPolicy, totp } = this.deps;
    log.debug("Entering AccountActivation.setupView().");
    const rules: Json = credentials.passwordRules(username) || {};
    log.debug("Leaving AccountActivation.setupView().");
    return { step: 'setup', user: username, token: token, base: base,
             rules: { enforced: !!rules.enforced,
                      rules: (rules.rules || []).slice(0) },
             webauthnEnabled: !!webauthnPolicy.settings().enabled,
             // WHAT THE PAGE MAY OFFER (#1135): whether a passkey may be
             // registered at all, and whether one may be the only way in.
             // The form asks nothing about a passkey's use; these decide
             // what it offers and what it says, and `spend()` asks both
             // again.
             passkeyOffered: !!webauthnPolicy.enrolmentAllowed().ok,
             passkeyAlone: !!webauthnPolicy.useAllowed('primary').ok,
             kinds: webauthnPolicy.authenticatorKinds(),
             // The lanes a passkey may be created in (#643).
             lanes: webauthnPolicy.lanes(),
             totpOffered: !!totp.offered() };
  }

  /**
   * A refusal's view: the link refused, or too many attempts.
   *
   * @param title - the heading
   * @param why - the sentence, for a GET; '' where the answer's errors say it
   * @returns the view
   */
  refusedView(title: string, why: string): Json {
    const { log } = this.deps;
    log.debug("Entering AccountActivation.refusedView().");
    log.debug("Leaving AccountActivation.refusedView().");
    // `refused` is the runtime's name for a refusal the view draws itself
    // (`account-api/CLAUDE.md`): set, the sentence is not drawn twice.
    return { step: 'refused', title: title, refused: why };
  }

  // THE PASSKEY'S STEP (2026-10-01): `/portal/keys`' ceremony, authorised by
  // the link. THE BASE IS THE ONE THE REQUEST ARRIVED ON: the RP ID is its
  // host.
  /**
   * The passkey step's view.
   *
   * @param base - the base the request arrived on
   * @param username - the link's person
   * @param token - the link's token
   * @param pending - the pending registration
   * @param wantsTotp - whether the app was asked for too
   * @returns the view
   */
  keyView(base: string, username: string, token: string, pending: Json,
          wantsTotp: boolean): Json {
    const { log, authn, passkeyPolicy, webauthnPolicy, credentials } =
      this.deps;
    log.debug("Entering AccountActivation.keyView().");
    const rpId = authn.rpIdOf(base);
    const lane = String(pending.lane || 'classical');
    // The name the prompt shows (#533), the post-quantum lane's naming
    // ML-DSA (#643).
    const user = credentials.laneUser(username,
      passkeyPolicy.displayNameFor(username, username), lane);
    // WHAT THE PASSKEY WILL BE (#1135), from the facts rather than from a
    // choice: a second step where a password was set on the first POST and
    // the realm lets a key answer that step, else the way in on its own.
    const secondStep = !!credentials.mechanismsFor(username).password &&
                       !!webauthnPolicy.useAllowed('mfa').ok;
    log.debug("Leaving AccountActivation.keyView().");
    return { step: 'key', user: username, token: token,
             passkey: true, secondStep: secondStep, wantsTotp: !!wantsTotp,
             pending: { id: pending.id, kind: pending.kind || '',
                        lane: lane,
                        challenge: pending.challenge,
                        rpId: rpId, user: user.name,
                        userHandle: pending.userHandle || '',
                        display: user.displayName,
                        exclude: (pending.exclude || []).slice(0),
                        options: webauthnPolicy.creationOptions(rpId,
                          pending.kind, lane) }
           };
  }

  // THE AUTHENTICATOR APP'S STEP: the secret to scan or type, drawn by a
  // POST and so never on a URL. The QR code is a server-drawn SVG; the typed
  // secret is not a fallback nobody sees.
  /**
   * The waiting authenticator enrolment, rendered, or null.
   *
   * @param ctx - the account API's helpers
   * @param username - the link's person
   * @param base - the base the request arrived on
   * @returns the enrolment, or null
   */
  async pendingEnrolmentFor(ctx: AccountContext, username: string,
                            base: string): Promise<Json> {
    const { log, credentials, totp } = this.deps;
    log.debug("Entering AccountActivation.pendingEnrolmentFor().");
    const held: Json = credentials.pendingTotpFor(username);
    if (!held) {
      log.debug("Leaving AccountActivation.pendingEnrolmentFor(). None.");
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
      // NOT fatal: the typed secret is the whole credential.
      log.error(ctx.errorCodes.tag('STS-PORTAL-0016') +
                'portal: the QR code could not be drawn (' +
                ((e && e.message) || e) + '), so the enrolment is offered ' +
                'by hand only.');
    }
    log.debug("Leaving AccountActivation.pendingEnrolmentFor().");
    return { grouped: totp.grouped(held.secret), issuer: issuer, qr: qr,
             algorithm: held.algorithm, digits: held.digits,
             period: held.period };
  }

  /**
   * Keeps a link's claim for this response, and gives it back when the
   * response ends unless the activation finished.
   *
   * @param res - the response
   * @param handle - the claim
   * @returns nothing
   */
  holdLinkClaim(res: Json, handle: Json): void {
    const { log, credentials } = this.deps;
    log.debug("Entering AccountActivation.holdLinkClaim().");
    let settled = false;
    const settle = function settle(): void {
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
    log.debug("Leaving AccountActivation.holdLinkClaim().");
  }

  // THE ONE PLACE AN ACTIVATION FINISHES (2026-09-10): every way in spends
  // the link, writes the audit row and answers the same view. The mark keeps
  // the claim the POST took.
  /**
   * Spends the link and answers *account ready*.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param username - the link's person
   * @param withKey - whether a passkey was registered
   * @param withTotp - whether an authenticator app was set up
   * @param warning - what could not be set up, or ''
   * @returns nothing
   */
  finish(ctx: AccountContext, req: Json, res: Json, username: string,
         withKey: boolean, withTotp: boolean, warning: string): unknown {
    const { log, credentials } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountActivation.finish(). " + username);
    const mechanisms: Json = credentials.mechanismsFor(username);
    const password = !!mechanisms.password;
    // THE PASSKEY'S SENTENCE ON *ACCOUNT READY* (#1135) is a fact about
    // the account, not a choice: it is asked for after the password where
    // the person has one and the realm lets a key answer that step
    // (`mfaKeys` counts the keys that may), else it is the way in.
    const secondStep = !!withKey && password &&
                       Number(mechanisms.mfaKeys || 0) > 0;
    res[LINK_SPENT] = true;
    // AN OPERATOR'S RECOVERY (#724), for a person who held a passkey before
    // this link was issued: read before the link is consumed.
    credentials.noteActivationRecovery(username);
    credentials.consumeActivation(username);
    audit.record({
      category: 'authentication', action: 'portal.activate',
      actor: username, outcome: 'success',
      summary: username + ' completed account setup',
      detail: { password: password, passkey: !!withKey, totp: !!withTotp,
                backupCodes: 0, address: websecurity.addressOf(req) }
    });
    log.info('portal: ' + username + ' completed account setup (' +
             (password ? 'password' : 'no password') + ', passkey: ' +
             (withKey ? 'yes' : 'no') + ', authenticator app: ' +
             (withTotp ? 'yes' : 'no') +
             '). The activation link is now spent.');
    // CAEP credential-change for what setup created (#145). A passkey's is
    // sent by the `key` step that registered it.
    const signals = this.deps.accountSignals();
    if (password) {
      signals.credentialChanged({ username: username,
        credentialType: 'password', changeType: 'create',
        initiatingEntity: 'user', via: 'portal activation',
        reasonAdmin: username + ' set a password when activating their ' +
                     'account.',
        reasonUser: 'You set a password for your new account.' });
    }
    if (withTotp) {
      signals.credentialChanged({ username: username,
        credentialType: signals.TOTP_CREDENTIAL_TYPE,
        changeType: 'create', initiatingEntity: 'user',
        via: 'portal activation',
        reasonAdmin: username + ' set up an authenticator app when ' +
                     'activating their account.',
        reasonUser: 'You set up an authenticator app.' });
    }
    log.debug("Leaving AccountActivation.finish(). Set up.");
    // **NOT SIGNED IN**: the link proved possession of a link, not the
    // credential just configured. The *Sign in* link is the portal's own,
    // whose sign-in mints its pending record when it is PRESSED.
    return ctx.json(res, 200, { ok: true, view: {
      step: 'ready', password: password, passkey: !!withKey,
      secondStep: secondStep, withTotp: !!withTotp, warning: warning || '',
      signIn: this.signInHref(ctx) } });
  }

  // WHAT AN ACTIVATION DOES ONCE ITS KEY IS SETTLED (2026-10-01): the
  // authenticator app if it was asked for — returning WITHOUT finishing, the
  // link unspent — then the finish. A REFUSAL DOES NOT LOSE THE ACTIVATION:
  // an app that cannot be started finishes the setup with what was
  // configured and says what did not happen. The setting is checked here and
  // not only where the box is drawn: the form is markup and this is the door.
  /**
   * The authenticator step if asked for, else the finish.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param username - the link's person
   * @param token - the link's token
   * @param withKey - whether a passkey was registered
   * @param wantsTotp - whether the app was asked for
   * @param warning - what could not be set up, or ''
   * @returns nothing
   */
  async afterKey(ctx: AccountContext, req: Json, res: Json, username: string,
                 token: string, withKey: boolean, wantsTotp: boolean,
                 warning: string): Promise<unknown> {
    const { log, credentials, totp } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountActivation.afterKey().");
    const base = ctx.baseUrlOf(req);
    if (wantsTotp && totp.offered()) {
      const begun: Json = credentials.beginTotpEnrolment(username,
                                                         { base: base });
      if (begun.ok) {
        const enrolment = await this.pendingEnrolmentFor(ctx, username, base);
        if (enrolment) {
          audit.record({
            category: 'authentication', action: 'portal.activate.mfa.started',
            actor: username, outcome: 'success',
            summary: username + ' started setting up an authenticator app ' +
                     'while activating',
            detail: { address: websecurity.addressOf(req) }
          });
          log.debug("Leaving AccountActivation.afterKey(). The app's step.");
          return ctx.json(res, 200, { ok: true, view: {
            step: 'totp', user: username, token: token, passkey: withKey,
            enrolment: enrolment, warning: warning || '' } });
        }
      }
      log.warn(ctx.errorCodes.tag('STS-PORTAL-0009') +
               'portal: an authenticator app was asked for while ' +
               'activating "' + username + '" and could not be started (' +
               (begun.errors || []).join(' ') + '). The activation ' +
               'finishes without it rather than being refused.');
      log.debug("Leaving AccountActivation.afterKey(). No authenticator.");
      return this.finish(ctx, req, res, username, withKey, false,
        (warning ? warning + ' ' : '') + 'The authenticator app could NOT ' +
        'be set up: ' + (begun.errors || ['it was refused.'])[0] +
        ' Everything else is set up, and you can add one from your ' +
        'account pages after you sign in.');
    }
    log.debug("Leaving AccountActivation.afterKey(). Finishing.");
    return this.finish(ctx, req, res, username, withKey, false, warning);
  }

  /**
   * Checks a link and answers the first step.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param query - the checked query
   * @returns nothing
   */
  async open(ctx: AccountContext, req: Json, res: Json,
             query: Json): Promise<unknown> {
    const { log, credentials, passkeyPolicy } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountActivation.open().");
    const username = String(query.user || '').trim();
    const token = String(query.token || '');
    // The person's passkey policy (#535).
    passkeyPolicy.select(username, '');
    // RATE LIMITED even on the GET: an endpoint that takes a credential must
    // not answer guesses at network speed.
    const allowed = await websecurity.attemptShared('activation', req,
                                                    username);
    if (!allowed.ok) {
      log.debug("Leaving AccountActivation.open(). Rate limited.");
      return ctx.refuse(res, 429, ctx.errorCodes.codeOf(allowed) ||
                        'STS-PORTAL-0002', allowed.detail,
                        { view: this.refusedView('Too many attempts',
                                                 allowed.detail) });
    }
    const checked: Json = credentials.checkActivation(username, token);
    if (!checked.ok) {
      log.info('portal: an activation link was refused for "' + username +
               '" (' + checked.reason + ').');
      audit.record({
        category: 'authentication', action: 'portal.activate.refused',
        errorCode: ctx.errorCodes.codeOf(checked) || 'STS-PORTAL-0003',
        actor: username, outcome: 'failure',
        summary: 'an activation link was refused',
        detail: { reason: checked.reason,
                  address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountActivation.open(). Refused.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(checked) ||
                        'STS-PORTAL-0003', ACTIVATION_REFUSAL,
                        { view: this.refusedView('Activation link',
                                                 ACTIVATION_REFUSAL) });
    }
    log.debug("Leaving AccountActivation.open(). The setup form.");
    return ctx.json(res, 200, this.setupView(ctx.baseUrlOf(req), username,
                                             token));
  }

  /**
   * The passkey step answered: registers the key, or draws a fresh ceremony.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param username - the link's person
   * @param token - the link's token
   * @param body - the checked body
   * @returns nothing
   */
  async keyStep(ctx: AccountContext, req: Json, res: Json, username: string,
                token: string, body: Json): Promise<unknown> {
    const { log, credentials, authn } = this.deps;
    const { audit, websecurity } = ctx;
    log.debug("Entering AccountActivation.keyStep().");
    const base = ctx.baseUrlOf(req);
    const wantsTotp = String(body.totp || '') === '1';
    const waitingKey: Json = credentials.pendingKeyEnrolmentFor(username);
    if (!waitingKey) {
      log.debug("Leaving AccountActivation.keyStep(). Expired.");
      return ctx.refuse(res, 400, 'STS-PORTAL-0102',
        'That passkey setup expired before it was finished. Nothing was ' +
        'lost — choose again below.',
        { view: this.setupView(base, username, token) });
    }
    const keyKind = waitingKey.kind || '';
    let ceremony: Json = null;
    try {
      ceremony = JSON.parse(String(body.credential || 'null'));
    } catch (e) {
      log.debug("Caught in AccountActivation.keyStep(): " +
                ((e && e.message) || e));
      // Not JSON: a hand-made request. The sentence below answers it.
      ceremony = null;
    }
    let refused = '';
    let refusedCode = '';
    let enrolled: Json = null;
    const rpRefusal = authn.rpIdProblem(base);
    if (!ceremony) {
      refused = 'Your browser did not run the ceremony, so there is ' +
                'nothing to register. A passkey is created by the browser ' +
                'and no form can do it.';
      refusedCode = 'STS-PORTAL-0102';
    } else if (rpRefusal) {
      refused = rpRefusal;
      refusedCode = 'STS-PORTAL-0102';
    } else {
      let done: Json = null;
      try {
        done = await credentials.confirmKeyEnrolment(username,
          String(body.enrolment_id || ''), ceremony,
          { origin: authn.expectedOriginFor(base, ceremony),
            rpId: authn.rpIdOf(base),
            // The ceremony's row names this door (#943).
            door: 'activation' });
      } catch (e) {
        log.debug("Caught in AccountActivation.keyStep(): " +
                  ((e && e.message) || e));
        done = { ok: false, reason: 'error',
                 errors: ['The passkey could not be created.'] };
      }
      if (done.ok) {
        enrolled = done;
      } else {
        refused = (done.errors || ['The passkey could not be created.'])[0];
        refusedCode = ctx.errorCodes.codeOf(done) || 'STS-PORTAL-0102';
        if (done.reason === 'browser') {
          refused += keyKind === 'security-key'
            ? ' If you have no security key to hand, open your activation ' +
              'link again and choose "A passkey on this device or your ' +
              'phone".'
            : ' You can try again, save it to your phone when the browser ' +
              'offers, or open your activation link again and choose "A ' +
              'security key".';
        }
      }
    }
    if (!enrolled) {
      audit.record({
        category: 'authentication', action: 'portal.activate.key.refused',
        errorCode: refusedCode, actor: username, outcome: 'failure',
        summary: 'a security key was not registered during activation',
        detail: { reason: refused, address: websecurity.addressOf(req) }
      });
      // ANY FAILURE DRAWS A FRESH CEREMONY, with a fresh challenge: the
      // person is one step from done and the link is still unspent.
      credentials.abandonKeyEnrolment(username);
      const again: Json = credentials.beginKeyEnrolment(username, {
        kind: keyKind, label: waitingKey.label,
        lane: waitingKey.lane || 'classical' });
      const fresh = again.ok ? credentials.pendingKeyEnrolmentFor(username)
                             : null;
      log.debug("Leaving AccountActivation.keyStep(). Not registered.");
      return ctx.refuse(res, 400, refusedCode || 'STS-PORTAL-0102', refused,
        { view: fresh
            ? this.keyView(base, username, token, fresh, wantsTotp)
            : this.setupView(base, username, token) });
    }
    const heldKey = credentials.keysOf(username).filter(function (one) {
      return one.credentialId === String(enrolled.credentialId || '');
    })[0] || null;
    const signals = this.deps.accountSignals();
    signals.credentialChanged({ username: username,
      credentialType: signals.keyCredentialType(heldKey),
      fido2Aaguid: String((heldKey && heldKey.aaguid) || ''),
      friendlyName: String((heldKey && heldKey.label) || ''),
      changeType: 'create', initiatingEntity: 'user',
      via: 'portal activation',
      reasonAdmin: username + ' registered a security key when activating ' +
                   'their account.',
      reasonUser: 'You registered a security key for your new account.' });
    audit.record({
      category: 'authentication', action: 'portal.activate.key.enrolled',
      actor: username, outcome: 'success',
      summary: username + ' registered a passkey while activating',
      detail: { algorithm: credentials.keyAlgorithm(heldKey).text,
                address: websecurity.addressOf(req) }
    });
    log.info('portal: ' + username + ' registered a passkey while ' +
             'spending an activation link.');
    log.debug("Leaving AccountActivation.keyStep(). Registered.");
    return this.afterKey(ctx, req, res, username, token, true, wantsTotp,
                         '');
  }

  /**
   * Answers one step of an activation.
   *
   * @param ctx - the account API's helpers
   * @param req - the request
   * @param res - the response
   * @param body - the checked body
   * @returns nothing
   */
  async spend(ctx: AccountContext, req: Json, res: Json,
              body: Json): Promise<unknown> {
    const { log, credentials, passkeyPolicy, webauthnPolicy } = this.deps;
    const { audit, websecurity } = ctx;
    const self = this;
    log.debug("Entering AccountActivation.spend().");
    const username = String(body.user || '').trim();
    const token = String(body.token || '');
    const base = ctx.baseUrlOf(req);
    passkeyPolicy.select(username, '');
    const allowed = await websecurity.attemptShared('activation', req,
                                                    username);
    if (!allowed.ok) {
      log.debug("Leaving AccountActivation.spend(). Rate limited.");
      return ctx.refuse(res, 429, ctx.errorCodes.codeOf(allowed) ||
                        'STS-PORTAL-0002', allowed.detail,
                        { view: this.refusedView('Too many attempts', '') });
    }
    // **THE TOKEN IS CHECKED AGAIN ON THE POST**: a POST assembled by hand
    // never met the GET at all.
    const checked: Json = credentials.checkActivation(username, token);
    if (!checked.ok) {
      log.info('portal: an activation POST was refused for "' + username +
               '" (' + checked.reason + ').');
      log.debug("Leaving AccountActivation.spend(). Refused.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(checked) ||
                        'STS-PORTAL-0003', ACTIVATION_REFUSAL,
                        { view: this.refusedView('Activation link', '') });
    }
    // **SPENT IN THE STORE BEFORE ANYTHING IS SET**, and given back unless
    // this request finishes the activation.
    const spent: Json = await credentials.spendActivation(username, token);
    if (!spent.ok) {
      log.info('portal: an activation POST was refused for "' + username +
               '" (' + spent.reason + ').');
      audit.record({
        category: 'authentication', action: 'portal.activate.refused',
        errorCode: ctx.errorCodes.codeOf(spent) || 'STS-AUTHN-0183',
        actor: username, outcome: 'failure',
        summary: 'a link was refused: another request is spending it or ' +
                 'has spent it',
        detail: { reason: spent.reason || '',
                  address: websecurity.addressOf(req) }
      });
      log.debug("Leaving AccountActivation.spend(). Being spent.");
      return ctx.refuse(res, 400, ctx.errorCodes.codeOf(spent) ||
                        'STS-AUTHN-0183', ACTIVATION_REFUSAL,
                        { view: this.refusedView('Activation link', '') });
    }
    this.holdLinkClaim(res, spent.handle);

    const password = String(body.password || '');
    const confirm = String(body.confirm || '');
    const wantsKey = this.wantsPasskey(body);
    const wantsTotp = String(body.totp || '') === '1';
    const step = String(body.step || 'setup');
    const setupRefused = function setupRefused(code: string,
                                               why: string): unknown {
      log.debug("Entering setupRefused().");
      log.debug("Leaving setupRefused().");
      // error-code: none — the code is the caller's, passed in `code`.
      return ctx.refuse(res, 400, code, why,
                        { view: self.setupView(base, username, token) });
    };

    // THE APP'S STEP: a code for an enrolment already waiting. Handled first,
    // and the password guards do not run on it: this POST carries no
    // password, which was set on the first one.
    if (step === 'totp') {
      const waiting = await this.pendingEnrolmentFor(ctx, username, base);
      if (!waiting) {
        log.debug("Leaving AccountActivation.spend(). Enrolment expired.");
        return setupRefused('STS-PORTAL-0004',
          'That authenticator setup expired before it was confirmed. ' +
          'Nothing was lost — set it up again below, or leave the box ' +
          'unticked and use your password alone.');
      }
      const confirmed: Json = credentials.confirmTotpEnrolment(
        username, String(body.code || ''));
      if (!confirmed.ok) {
        audit.record({
          category: 'authentication', action: 'portal.activate.mfa.refused',
          errorCode: ctx.errorCodes.codeOf(confirmed) || 'STS-PORTAL-0005',
          actor: username, outcome: 'failure',
          summary: 'an authenticator app was not confirmed during activation',
          detail: { reason: confirmed.reason || '',
                    address: websecurity.addressOf(req) }
        });
        // THE SAME SECRET IS REDRAWN: mistyping six digits must not mean
        // scanning again.
        log.debug("Leaving AccountActivation.spend(). Code refused.");
        return ctx.refuse(res, 400, ctx.errorCodes.codeOf(confirmed) ||
                          'STS-PORTAL-0005',
                          (confirmed.errors || ['That code is not ' +
                                                'right.'])[0],
                          { view: { step: 'totp', user: username,
                                    token: token, passkey: wantsKey,
                                    enrolment: waiting, warning: '' } });
      }
      log.info('portal: ' + username + ' set up an authenticator app while ' +
               'spending an activation link.');
      log.debug("Leaving AccountActivation.spend(). Finishing with the app.");
      return this.finish(ctx, req, res, username, wantsKey, true, '');
    }

    // THE PASSKEY'S CEREMONY, ANSWERED, before the password guards for the
    // app's reason.
    if (step === 'key') {
      log.debug("Leaving AccountActivation.spend(). The key step.");
      return this.keyStep(ctx, req, res, username, token, body);
    }

    if (password && password !== confirm) {
      log.debug("Leaving AccountActivation.spend(). Mismatch.");
      return setupRefused('STS-PORTAL-0006',
                          'The two passwords do not match.');
    }
    // **AT LEAST ONE WAY IN.** Until #1135 a passkey chosen as a second
    // step with no password was refused here, because the person had said
    // the key was not a way in. A key carries no role now: with no password
    // it is the way in — where the realm lets a passkey be a first factor.
    // Where it does not, the key could only ever be a second step after a
    // password nobody set, so the activation is refused for the same reason
    // as before, and the realm's own sentence says why. A realm that takes
    // no new passkey at all is refused by the enrolment below (0101).
    if (!password && !wantsKey) {
      log.debug("Leaving AccountActivation.spend(). No way in.");
      return setupRefused('STS-PORTAL-0007',
        'Set a password, or register a passkey. You need at least one way ' +
        'to sign in.');
    }
    if (!password && webauthnPolicy.enrolmentAllowed().ok) {
      const alone: Json = webauthnPolicy.useAllowed('primary');
      if (!alone.ok) {
        log.debug("Leaving AccountActivation.spend(). A passkey cannot be " +
                  "the only way in here.");
        return setupRefused('STS-PORTAL-0007',
          'A passkey cannot sign anybody in on its own here, so it cannot ' +
          'be your only way in (' + String(alone.why || '') + '). Set a ' +
          'password as well; your passkey is asked for after it.');
      }
    }
    if (password) {
      // Screened against Pwned Passwords first (#62 P6).
      await this.deps.breachedPasswords().screen(password);
      const set: Json = credentials.setPassword(username, password);
      if (!set.ok) {
        log.debug("Leaving AccountActivation.spend(). Password refused.");
        return setupRefused(ctx.errorCodes.codeOf(set) || 'STS-PORTAL-0008',
          (set.errors || ['The password could not be set.'])[0]);
      }
      // THE RECOVERY WITH THE PASSWORD WRITE (#900), as the reset door
      // records it. finish() records it too, but a person who chose a
      // passkey or an app beside the password could stop at that step: the
      // password was set and finish() never ran, so a password-only sign-in
      // passed the not-weaker rule. Recording it twice is harmless.
      credentials.noteActivationRecovery(username);
    }

    // THE PASSKEY, IF ONE WAS CHOSEN (2026-10-01): the ceremony is drawn and
    // the link is NOT spent. One that cannot be started is refused where it
    // was the ONLY way in; beside a password the setup finishes and says what
    // did not happen. No role is passed (#1135).
    if (wantsKey) {
      const begunKey: Json = credentials.beginKeyEnrolment(username, {
        kind: String(body.kind || ''),
        // The lane (#643), refused there where the realm does not offer it.
        lane: String(body.lane || 'classical') });
      const pendingKey = begunKey.ok
        ? credentials.pendingKeyEnrolmentFor(username) : null;
      if (pendingKey) {
        audit.record({
          category: 'authentication', action: 'portal.activate.key.started',
          actor: username, outcome: 'success',
          summary: username + ' started registering a passkey while ' +
                   'activating',
          detail: { kind: pendingKey.kind || 'any',
                    lane: pendingKey.lane || 'classical',
                    address: websecurity.addressOf(req) }
        });
        log.debug("Leaving AccountActivation.spend(). The key's ceremony.");
        return ctx.json(res, 200, { ok: true, view: this.keyView(base,
          username, token, pendingKey, wantsTotp) });
      }
      const why = (begunKey.errors || ['it was refused.'])[0];
      if (!password) {
        log.debug("Leaving AccountActivation.spend(). No key, no password.");
        return setupRefused('STS-PORTAL-0101',
          'A passkey cannot be set up here: ' + why + ' Set a password ' +
          'instead.');
      }
      log.warn(ctx.errorCodes.tag('STS-PORTAL-0100') +
               'portal: a security key was asked for while activating "' +
               username + '" and could not be started (' + why + '). The ' +
               'activation goes on without it rather than being refused.');
      log.debug("Leaving AccountActivation.spend(). Without the key.");
      return this.afterKey(ctx, req, res, username, token, false, wantsTotp,
        'The passkey could NOT be set up: ' + why + ' Everything else is ' +
        'set up, and you can create one on your Passkeys page after you ' +
        'sign in.');
    }
    log.debug("Leaving AccountActivation.spend(). After the setup.");
    return this.afterKey(ctx, req, res, username, token, false, wantsTotp,
                         '');
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
    log.debug("Entering AccountActivation.accountOperations().");
    const rows: AccountOperation[] = [
      { method: 'GET', path: ctx.BASE + '/activation',
        operationId: 'getActivation', tag: 'Activation', access: 'link',
        mirrors: 'GET ' + ctx.PORTAL + '/activate',
        summary: 'Checks an activation link and answers the setup form',
        description: 'Takes no token: the link\'s `user` and `token` are ' +
          'the credential. Spends nothing — a link opened by a prefetch or ' +
          'a mail scanner still works. Rate limited. Every failure answers ' +
          'the same sentence. The answer is the first step: the password ' +
          'rules, whether a passkey and an authenticator app are offered, ' +
          'and whether a passkey may be the only way in (`passkeyAlone`, ' +
          '#1135).',
        query: ACTIVATE_QUERY,
        statuses: { 429: 'Too many attempts.' },
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.open(ctx, req, res, input.query);
        } },
      { method: 'POST', path: ctx.BASE + '/activation',
        operationId: 'activate', tag: 'Activation', access: 'link',
        mirrors: 'POST ' + ctx.PORTAL + '/activate',
        summary: 'Answers one step of an activation',
        description: '`setup` sets the password and starts a passkey (the ' +
          '`key` view) or an authenticator app (the `totp` view) where they ' +
          'were chosen; `key` answers the passkey\'s ceremony; `totp` the ' +
          'app\'s code. The link is checked again, claimed before anything ' +
          'is set, and spent only by the step that finishes, which answers ' +
          'the `ready` view. Nobody is signed in by it. A passkey carries ' +
          'no role (#1135): `passkey` asks for one, and `key_role` is ' +
          'still accepted, `primary` and `mfa` both asking for one.',
        body: ACTIVATE_FORM,
        statuses: { 429: 'Too many attempts.' },
        handler: function (req: Json, res: Json, caller: Json,
                           input: Json): unknown {
          return self.spend(ctx, req, res, input.body);
        } }
    ];
    log.debug("Leaving AccountActivation.accountOperations().");
    return rows;
  }
}

const slot = new InstanceSlot<AccountActivation>(
  'portal/account_activation',
  () => new AccountActivation(AccountActivation.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * `/portal/activate`'s account API operations (#568).
 * @namespace
 */
export = {
  AccountActivation: AccountActivation,
  installInstance: (instance: AccountActivation): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  accountOperations: slot.forward('accountOperations')
};
