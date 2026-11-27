// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mail_uses.ts
//
// ===========================================================================
// WHAT THE MAIL CHANNEL IS FOR (#63, 2026-09-22): the four uses rcbj put in
// the ticket's scope, each a caller of `common/mail.ts`'s `send()` and of
// nothing below it.
//
//   1. **SELF-SERVICE PASSWORD RESET.** A person names their account at
//      /portal/forgot-password (linked from the sign-in screen) and a
//      single-use /portal/reset-password link is mailed to the address on
//      its entry. It fires RISC `recovery-activated` with the person as the
//      initiating entity — #63's first comment, and the half #146 left
//      waiting.
//   2. **ADDRESS VERIFICATION.** A single-use link to the address on the
//      entry; following it records THAT ADDRESS as verified
//      (`stsMailVerified`). The state is the address, not a flag, so an
//      entry whose `mail` changes is unverified without anybody having to
//      remember to clear anything.
//   3. **AN ADMINISTRATOR'S LINKS, MAILED.** The reset link and the
//      activation link an administrator issues can go to the person instead
//      of being shown to the administrator — which is the better arrangement
//      for everybody, because an administrator who never sees a person's
//      reset link cannot be the one who used it.
//   4. **SECURITY NOTICES**, which a person cannot decline: disabled,
//      sessions ended by an administrator, password changed or reset, any
//      other credential added or removed (#2163), a
//      credential marked compromised, recovery started, the address changed
//      (to the OLD address). When the SERVICE did it (risk scoring), the
//      realm's Admin Write roster is told as well. Since #2162 also a
//      SIGN-IN THAT SUCCEEDED LOOKING UNUSUAL and a RUN OF REFUSED
//      PASSWORDS, each at most once in `mail.signInAlertWindowS` per kind
//      (`signInAlert()`, `refusedAttempts()`).
//   5. **AN ACCESS REQUEST WAITING FOR ITS OWNER** (#432 phase 6), a
//      notification a person may decline: a GNAP grant a client asked for
//      while they were not there, waiting on /portal/ciba.
//   6. **A STARTED POST-LOGIN ACTIVITY'S REMINDER** (#1111), a notification
//      a person may decline: sign in, and the post-login activity asks you
//      to do it. The one link is the portal's path; it carries no credential
//      (`common/post_login_activities.ts`). Each activity has its own
//      message since #2009's P4 — a post-quantum passkey
//      (`post-login-reminder`, the id it always had), a post-quantum
//      mail-encryption key, a new PIV certificate — named by
//      `post_login_kinds.ts`'s table.
//   7. **AN AUTHZEN ACCESS REQUEST WAITING FOR ITS APPROVERS** (#1180), a
//      notification a person may decline, waiting on
//      /portal/access-requests — and, for an emergency access the policy
//      allowed and granted at once, a security notice nobody may decline,
//      asking for the review after use (`authzen/authzen_access_request.ts`).
//   8. **A CREDENTIAL THAT EXPIRES SOON** (#2247, ASVS 5.0.0 6.4.5), a
//      security notice: the certificates a person holds that reach one of
//      `mail.expiryReminderDays`, all in one message, each once per step
//      (`credentialsExpiring()`, asked by `common/credential_expiry.ts`'s
//      job, which finds them).
//
// A LIBRARY (rule 3). Its requires of the credential store and the account
// signals are LAZY, at the moment of use: `ssf/account_signals.ts` calls
// this module, and `common/credentials.ts` is far up a chain this module
// must not load early (spec-review lessons, #145).
//
// **EVERY ANSWER THE FORGOT-PASSWORD FORM GETS IS THE SAME** whether the
// account exists, has an address, is disabled or was refused by a ceiling —
// and the work is done AFTER the answer is decided, not before, so the time
// it takes says nothing either. What happened is on the audit row.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import realms = require('./realms');
import mode = require('./mode');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import stsCrypto = require('./crypto');
import mail = require('./mail');
import Classes = require('./domain_classes');
// The activities' table (#2009 P4): which reminder each one is sent with. A
// leaf that requires nothing of this service.
import PostLoginKinds = require('./post_login_kinds');
// The batch a door's several credential changes are told in (#2163): an
// ambient slot, so a door wraps its work once and every signal inside it,
// however deep, joins the one notice.
import { AsyncLocalStorage } from 'async_hooks';

type Json = any;

// The paths a mailed link names (the portal registers them).
const RESET_PATH = '/portal/reset-password';
const ACTIVATE_PATH = '/portal/activate';
const VERIFY_PATH = '/portal/verify-email';
// Where a sign-in alert sends the person (#2162): their recent sign-ins,
// where "This wasn't me" signs every session out.
const SIGN_INS_PATH = '/portal/sign-ins';

// THE KINDS OF UNUSUAL SIGN-IN A PERSON IS TOLD OF (#2162), each told at
// most once in `mail.signInAlertWindowS`. `risk/risk_engine.ts` decides
// which a sign-in shows.
const SIGN_IN_ALERT_KINDS = ['new-device', 'new-country', 'anonymiser',
                             'after-refusals', 'unusual'];

// Where an expiry reminder sends the person (#2247): their portal, whose
// pages each line of the message names.
const PORTAL_PATH = '/portal';

// How each kind of expiring credential is renewed (#2247): the portal page
// a line names, or `administrator` where the person cannot do it themselves
// (a certificate stored for sign-in, from whichever authority issued it).
const EXPIRY_RENEWAL: Record<string, string> = {
  'certificate': 'certificates',
  'piv': 'tokens',
  'smime': 'openpgp',
  'tls-client': 'signing-key',
  'signin-certificate': 'administrator'
};

// The one sentence the forgot-password form answers, whatever happened.
const RESET_ANSWER = 'If that names an account here with an email address ' +
  'it may be reached at, a link to choose a new password has been sent ' +
  'there. It works once and for a limited time. Nothing changes until it ' +
  'is used.';

// ---------------------------------------------------------------------------
// A CREDENTIAL ADDED OR REMOVED, TOLD TO THE PERSON (#2163, ASVS 5.0.0
// 6.3.7). Until then only a password change was mailed. The kinds below are
// what a person signs in or receives encrypted mail with; each change is
// told in the person's language as one line of the `credential-changed`
// notice — WHAT changed (the kind and its label, never a secret), WHEN, and
// BY WHOM (the person, or an administrator) — and the notice says what to
// do if it was not them.
//
// The CAEP credential types (`ssf/account_signals.ts`) a change arrives
// under, as the kind the mail names. A type not listed is not mailed: the
// Kerberos keys (derived from the password, whose change is mailed), a
// wallet credential this service issued, a self-issued key, a HOBA or ACME
// key, the emailed factor (which tells the person itself).
// ---------------------------------------------------------------------------
const CREDENTIAL_KINDS: Record<string, string> = {
  'fido2-roaming': 'passkey',
  'fido2-platform': 'passkey',
  'fido-u2f': 'passkey',
  'app': 'totp',
  'urn:iya:sts:credential-type:hotp-token': 'hotp',
  'urn:iya:sts:credential-type:yubikey-otp': 'yubiotp',
  'x509': 'certificate'
};

// The kinds a door may name directly (`credentialChanged()`), beside those:
// the ones held only as directory attributes, told by `ldap_server.js`.
const OWN_KINDS = ['passkey', 'totp', 'app-password', 'hotp', 'yubiotp',
                   'recovery-codes', 'certificate', 'certificate-binding',
                   'smime', 'openpgp'];

// One change, as a notice line.
interface CredentialChangeItem {
  username: string;
  kind: string;
  change: string;
  label: string;
  by: string;
}

// The ambient batch: the changes told inside one door's act, per person.
interface CredentialBatch {
  items: CredentialChangeItem[];
}

const credentialBatches = new AsyncLocalStorage<CredentialBatch>();

interface MailUsesDeps {
  log: typeof helpers.log;
  config: typeof config;
  realms: typeof realms;
  mode: typeof mode;
  errorCodes: typeof errorCodes;
  audit: typeof audit;
  crypto: typeof stsCrypto;
  mail: typeof mail;
  now: () => number;
  credentials: () => Json;
  accountSignals: () => Json;
  // #724: the recovery question, asked before a self-service link is mailed.
  // Optional, so a caller built before it (a test's fake) asks nothing.
  passkeyPolicy?: () => Json;
}

/**
 * What the mail channel is for: self-service password reset, address
 * verification, an administrator's links mailed to the person, and security
 * notices.
 *
 * Each use is a caller of `common/mail.ts`'s `send()`. The forgot-password
 * form's answer is the same whatever happened.
 */
class MailUses {
  /**
   * The one sentence the forgot-password form answers, whatever happened.
   */
  static readonly RESET_ANSWER = RESET_ANSWER;
  /**
   * The path an address verification link names: `/portal/verify-email`.
   */
  static readonly VERIFY_PATH = VERIFY_PATH;

  /**
   * Creates the mail uses.
   *
   * @param deps - its dependencies: the logger, config, realms, mode, the
   * error-code table, the audit log, the crypto module, the mail channel, a
   * clock, and lazy readers of the credential store and account signals
   */
  constructor(private readonly deps: MailUsesDeps) {
    deps.log.debug("Entering MailUses.constructor().");
    deps.log.debug("Leaving MailUses.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the dependencies
   */
  static defaultDeps(): MailUsesDeps {
    helpers.log.debug("Entering MailUses.defaultDeps().");
    helpers.log.debug("Leaving MailUses.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      realms: realms,
      mode: mode,
      errorCodes: errorCodes,
      audit: audit,
      crypto: stsCrypto,
      mail: mail,
      now: function (): number {
        return Date.now();
      },
      credentials: function (): Json {
        return require('./credentials');
      },
      accountSignals: function (): Json {
        return require('../ssf/account_signals');
      },
      passkeyPolicy: function (): Json {
        return require('./passkey_policy');
      }
    };
  }

  // The time, UTC, to the minute: a dedup key's bucket now. What a MESSAGE
  // says is `instant()`, put into words in the recipient's language by the
  // mail channel (#539).
  private when(): string {
    const { log, now } = this.deps;
    log.debug("Entering MailUses.when().");
    log.debug("Leaving MailUses.when().");
    return new Date(now()).toISOString().replace('T', ' ').slice(0, 16) +
      ' UTC';
  }

  // -------------------------------------------------------------------------
  // VALUES THAT FOLLOW THE RECIPIENT'S LANGUAGE (#539). A message is sent in
  // the language of the person it goes to, which only `common/mail.ts`
  // knows (per recipient, in `queueOne()`). So what this file wants SAID —
  // "an administrator", a time — is handed over as a message of the
  // `mailValues` catalog (common/locales/mailValues/) or an instant, and the
  // channel puts it into words there. A name, an address, a username, and a
  // reason a person or a refusal wrote, are data and stay as given.
  // -------------------------------------------------------------------------
  /**
   * A value the mail channel puts into words in the recipient's language: a
   * message of the `mailValues` catalog.
   *
   * @param key - the message's key under `mailValues.`
   * @param params - its parameters, data
   * @returns `{ i18n, params }`
   */
  static said(key: string, params?: Json): Json {
    helpers.log.debug("Entering MailUses.said(). " + key);
    helpers.log.debug("Leaving MailUses.said().");
    return params ? { i18n: 'mailValues.' + key, params: params }
                  : { i18n: 'mailValues.' + key };
  }

  // Now, as an instant the channel formats for the recipient.
  private instant(): Json {
    const { log, now } = this.deps;
    log.debug("Entering MailUses.instant().");
    log.debug("Leaving MailUses.instant().");
    return { date: now() };
  }

  // A value as a dedup key's part: a string as it is, a message or an
  // instant as its JSON, which is deterministic for what this file builds.
  /**
   * Turns a value — a string, or a message or instant for the channel — into
   * a deterministic string for a dedup key.
   *
   * @param value - the value
   * @returns the string
   */
  static keyOf(value: unknown): string {
    helpers.log.debug("Entering MailUses.keyOf().");
    if (value && typeof value === 'object') {
      helpers.log.debug("Leaving MailUses.keyOf(). JSON.");
      return JSON.stringify(value);
    }
    helpers.log.debug("Leaving MailUses.keyOf().");
    return String(value == null ? '' : value);
  }

  // -------------------------------------------------------------------------
  // 1. SELF-SERVICE RESET — is it offered here at all? The sign-in screen and
  // the portal ask before drawing the link.
  // -------------------------------------------------------------------------
  /**
   * Tells whether self-service password reset is offered in the ambient realm,
   * for the sign-in screen and the portal to ask before drawing the link.
   *
   * @returns true when offered
   */
  resetOffered(): boolean {
    const { log, config, mode, mail } = this.deps;
    log.debug("Entering MailUses.resetOffered().");
    const offered = !!config.value('mail.selfServiceReset') &&
      mode.verifiesCredentials() && mail.available();
    log.debug("Leaving MailUses.resetOffered(). " + offered);
    return offered;
  }

  // -------------------------------------------------------------------------
  // A PERSON ASKED FOR A RESET LINK, naming their account by username or by
  // the address on its entry. Answers `{ ok: true, message: RESET_ANSWER,
  // outcome }` always — `outcome` is for the audit row and the tests, and
  // NO CALLER may show it (header). Resolves once the attempt is decided.
  // -------------------------------------------------------------------------
  //
  // **WITH A RECOVERY CODE (#64, rcbj's D4)** while `mail.resetRequiresBackup
  // Code` is on — the default: `identifier` is then the USERNAME only, and
  // `extra` carries the ADDRESS the person says is on the account and one of
  // their RECOVERY CODES. All three must be right before anything is mailed,
  // and the code is SPENT when they are — so one code cannot be replayed to
  // send a stream of reset mail. A wrong code, with the right name and
  // address, tells the address owner somebody tried; nothing else does. The
  // answer to the browser is the same sentence whatever happened.
  /**
   * Tells whether a reset request must carry the account's address and one of
   * its recovery codes (`mail.resetRequiresBackupCode`, on by default).
   *
   * @returns true when a recovery code is required
   */
  resetNeedsRecoveryCode(): boolean {
    const { log, config } = this.deps;
    log.debug("Entering MailUses.resetNeedsRecoveryCode().");
    log.debug("Leaving MailUses.resetNeedsRecoveryCode().");
    return config.value('mail.resetRequiresBackupCode') !== false;
  }

  // The recovery question for the forgot-password door (#724): the code of
  // its refusal, or ''. A person holding no passkey is not covered, and a
  // process with no passkey policy (a test's deps) asks nothing.
  private recoveryRefused(creds: Json, username: string): string {
    const { log } = this.deps;
    log.debug("Entering MailUses.recoveryRefused().");
    const policy = this.deps.passkeyPolicy ? this.deps.passkeyPolicy() : null;
    if (!policy || typeof creds.holdsPasskey !== 'function') {
      log.debug("Leaving MailUses.recoveryRefused(). Not asked.");
      return '';
    }
    policy.select(username, '');
    const refused = policy.recoveryRefusal({ username: username,
      door: 'forgot-password', at: 'door',
      covered: creds.holdsPasskey(username) });
    log.debug("Leaving MailUses.recoveryRefused(). " +
              (refused ? refused.code : 'allowed'));
    return refused ? refused.code : '';
  }

  /**
   * Handles a person asking for a reset link: mails a single-use link to the
   * address on the entry when everything checks out, and fires RISC
   * recovery-activated.
   *
   * With a recovery code required, all three of username, address and code must
   * be right, and the code is spent. The answer is the same sentence whatever
   * happened; `outcome` must never be shown.
   *
   * @param identifier - the username, or the address on the entry when no
   * recovery code is required
   * @param via - the surface it came through
   * @param extra - `address` and `code` when a recovery code is required
   * @returns a promise of `{ ok: true, message, outcome }`
   */
  async requestReset(identifier: string, via: string,
                     extra?: { address?: string; code?: string }):
      Promise<Json> {
    const { log, config, mail, audit, credentials, accountSignals } =
      this.deps;
    const needsCode = this.resetNeedsRecoveryCode();
    log.debug("Entering MailUses.requestReset().");
    const asked = String(identifier || '').trim().slice(0, 256);
    const answer = function (outcome: string, code?: string): Json {
      log.debug("Entering answer(). " + outcome);
      audit.audit({ action: 'mail.reset-requested',
        outcome: code ? 'refused' : 'success',
        errorCode: code || '', target: asked, protocol: 'Mail',
        channel: 'http',
        summary: 'a self-service password reset was asked for "' + asked +
                 '": ' + outcome,
        detail: { via: via || 'the forgot-password form' } });
      log.debug("Leaving answer().");
      return { ok: true, message: RESET_ANSWER, outcome: outcome };
    };
    if (!this.resetOffered()) {
      log.debug("Leaving MailUses.requestReset(). Not offered.");
      return answer('not offered here', 'STS-MAIL-0030');
    }
    const dir = mail.directory();
    let username = '';
    if (dir && asked) {
      // With the recovery code, the account is named by its USERNAME: the
      // address is the second field and is checked against it.
      if (!needsCode && asked.indexOf('@') > 0 &&
          typeof dir.personByMail === 'function') {
        username = String(dir.personByMail(asked) || '');
      }
      if (!username && dir.personEntry(asked)) {
        username = asked;
      }
    }
    if (!username) {
      log.debug("Leaving MailUses.requestReset(). Nobody.");
      return answer('no such account', 'STS-MAIL-0012');
    }
    const creds = credentials();
    if (creds.accountDisabled(username)) {
      log.debug("Leaving MailUses.requestReset(). Disabled.");
      return answer('the account is disabled', 'STS-MAIL-0030');
    }
    // NO SELF-SERVICE RECOVERY FOR A PASSKEY HOLDER WHERE THE PASSKEY
    // POLICY SAYS operator-only (#724), decided by the issuance policy and
    // asked BEFORE a recovery code is spent or anything is mailed. The form's
    // answer is the same sentence; the audit row names the code.
    const recoveryCode = this.recoveryRefused(creds, username);
    if (recoveryCode) {
      log.debug("Leaving MailUses.requestReset(). Operator-only recovery.");
      return answer('the passkey policy lets only an operator recover this ' +
                    'account', recoveryCode);
    }
    const who = mail.recipient(username);
    if (!who || !who.address) {
      log.debug("Leaving MailUses.requestReset(). No address.");
      return answer('the account has no address', 'STS-MAIL-0011');
    }
    if ((needsCode || config.value('mail.resetRequiresVerifiedAddress')) &&
        !who.verified) {
      log.debug("Leaving MailUses.requestReset(). Unverified.");
      return answer('the address is not verified', 'STS-MAIL-0011');
    }
    if (needsCode) {
      const given = String((extra && extra.address) || '').trim();
      if (!given || given.toLowerCase() !== who.address.toLowerCase()) {
        log.debug("Leaving MailUses.requestReset(). Not its address.");
        return answer('the address given is not the account\'s',
                      'STS-MAIL-0036');
      }
      const status = typeof creds.backupCodeStatus === 'function'
        ? creds.backupCodeStatus(username) : { remaining: 0 };
      if (!status || !status.remaining) {
        log.debug("Leaving MailUses.requestReset(). No recovery codes.");
        return answer('the account holds no unused recovery code',
                      'STS-MAIL-0037');
      }
      let verdict: Json = null;
      try {
        verdict = await creds.verifyBackupCodeAsync(username,
          String((extra && extra.code) || ''));
      } catch (e) {
        log.debug("Caught in MailUses.requestReset(): " +
                  ((e && e.message) || e));
        verdict = { ok: false, reason: 'error' };
      }
      if (!verdict || !verdict.ok) {
        // THE ADDRESS OWNER IS TOLD, once an hour at most: the name and the
        // address were right, so this is somebody who knows both.
        mail.send({ username: username, template: 'reset-refused-attempt',
          values: { username: username, when: this.instant() },
          dedupKey: 'reset-refused:' + this.when().slice(0, 13),
          via: via || 'the forgot-password form', actor: '' });
        log.debug("Leaving MailUses.requestReset(). Wrong recovery code.");
        return answer('the recovery code is not right (' +
                      String((verdict && verdict.reason) || '') + ')',
                      'STS-MAIL-0035');
      }
      // THE CODE IS SPENT, so the set shrank: RISC
      // recovery-information-changed (#235), beside the recovery-activated
      // this door sends once the link is mailed.
      accountSignals().recoveryInformationChanged({ username: username,
        initiatingEntity: 'user', via: 'portal',
        reasonAdmin: username + ' spent a recovery code on the ' +
                     'forgot-password form; ' +
                     String(verdict.remaining) + ' remain.',
        reasonUser: 'You used one of your recovery codes.' });
    }
    const issued = creds.issuePasswordReset(username, { source: 'self' });
    if (!issued || !issued.ok) {
      log.debug("Leaving MailUses.requestReset(). Not issued.");
      return answer('no link could be issued: ' +
                    String((issued && issued.errors && issued.errors[0]) ||
                           ''), 'STS-MAIL-0030');
    }
    const sent = mail.send({
      username: username, template: 'password-reset',
      values: { username: username, requestedBy: needsCode
                  ? MailUses.said('requestedBy.recoveryCode')
                  : MailUses.said('requestedBy.signInScreen'),
                expiresMinutes: String(config.value(
                  'security.passwordResetTtlMinutes')) },
      links: { link: RESET_PATH + '?user=' + encodeURIComponent(username) +
                     '#token=' + encodeURIComponent(issued.token) },
      via: via || 'the forgot-password form', actor: username
    });
    if (!sent.ok) {
      log.debug("Leaving MailUses.requestReset(). Not queued.");
      return answer('not mailed: ' + String(sent.error || ''),
                    (sent.refused[0] && sent.refused[0].code) ||
                    'STS-MAIL-0001');
    }
    // RISC recovery-activated, the person's own (#63's first comment).
    accountSignals().recoveryActivated({ username: username,
      initiatingEntity: 'user', via: 'portal', mailed: true,
      reasonAdmin: username + ' started account recovery with a ' +
                   'self-service password reset link, mailed to the ' +
                   'address on their entry.',
      reasonUser: 'You asked for a password reset link.' });
    log.debug("Leaving MailUses.requestReset(). Mailed.");
    return answer('mailed');
  }

  // -------------------------------------------------------------------------
  // 2. ADDRESS VERIFICATION — mail a link to the address on the entry now.
  // `{ ok, message }` or a coded refusal.
  // -------------------------------------------------------------------------
  /**
   * Mails a single-use verification link, bound to the address the account has
   * now, to that address.
   *
   * @param username - the person
   * @param via - the surface it came through
   * @param actor - who asked, when not the person
   * @returns `{ ok, message }` (with `verified` when already verified), or a
   * coded refusal
   */
  startVerification(username: string, via: string, actor?: string): Json {
    const { log, config, mail, crypto, errorCodes, now } = this.deps;
    log.debug("Entering MailUses.startVerification(). " + username);
    const dir = mail.directory();
    const who = mail.recipient(username);
    if (!dir || !who) {
      log.debug("Leaving MailUses.startVerification(). Nobody.");
      return errorCodes.mark({ ok: false, errors: ['There is nobody called "' +
        String(username || '') + '" in this realm.'] }, 'STS-MAIL-0012');
    }
    if (!who.address) {
      log.debug("Leaving MailUses.startVerification(). No address.");
      return errorCodes.mark({ ok: false, errors: ['The entry has no email ' +
        'address to verify.'] }, 'STS-MAIL-0011');
    }
    if (who.verified) {
      log.debug("Leaving MailUses.startVerification(). Already.");
      return { ok: true, verified: true, message: who.address +
               ' is already verified.' };
    }
    const token = stsCrypto.randomBytes(32).toString('base64url');
    const ttl = Number(config.value('mail.verificationTtlMinutes'));
    // BOUND TO THE ADDRESS THE ACCOUNT HAS NOW (#64): the hash is of the
    // token AND `mail`, so a link outlives no change of address by anybody.
    dir.writeMailFlag(username, 'stsMailVerifyToken',
                      crypto.hashSecret(this.boundToken(token, who.address)));
    dir.writeMailFlag(username, 'stsMailVerifyExpires',
                      String(now() + ttl * 60000));
    dir.writeMailFlag(username, 'stsMailVerifyAddress', who.address);
    const sent = mail.send({
      username: username, template: 'address-verification',
      values: { username: username, address: who.address,
                expiresMinutes: String(ttl) },
      links: { link: VERIFY_PATH + '?user=' + encodeURIComponent(username) +
                     '#token=' + encodeURIComponent(token) },
      via: via, actor: actor || username
    });
    if (!sent.ok) {
      log.debug("Leaving MailUses.startVerification(). Not queued.");
      return errorCodes.mark({ ok: false, errors: ['No verification link ' +
        'was sent: ' + String(sent.error || 'it was refused') + '.'] },
        (sent.refused[0] && sent.refused[0].code) || 'STS-MAIL-0001');
    }
    log.debug("Leaving MailUses.startVerification(). Sent.");
    return { ok: true, message: 'A link was sent to ' + who.address +
             '. Follow it within ' + ttl + ' minutes to verify it.' };
  }

  // Is this link good? `{ ok, address }`, or a coded refusal whose one
  // sentence is the same for every reason.
  /**
   * Checks a verification link: the token, bound to the address it was sent
   * for, still unspent.
   *
   * @param username - the person
   * @param token - the link's token
   * @returns `{ ok, address }`, or a coded refusal whose sentence is the same
   * for every reason
   */
  checkVerification(username: string, token: string): Json {
    const { log, mail, crypto, errorCodes, now } = this.deps;
    log.debug("Entering MailUses.checkVerification(). " + username);
    const refused = errorCodes.mark({ ok: false, errors: ['This verification ' +
      'link is not valid: it may have been used, have expired, or have been ' +
      'sent to an address the account no longer has.'] }, 'STS-MAIL-0024');
    const dir = mail.directory();
    const entry = dir && username ? dir.personEntry(String(username)) : null;
    if (!entry || !token) {
      log.debug("Leaving MailUses.checkVerification(). Nobody.");
      return refused;
    }
    // The pending verification is the Credential's, its token a secret
    // named here because this is the check that needs it (#1579); the
    // address it is checked against is the User's.
    const attrs = entry.attributes || {};
    const pending = Classes.Credential.fromEntry(attrs,
      { secrets: ['mailVerifyToken'] });
    const stored = pending.mailVerifyToken || '';
    const expires = Number(pending.mailVerifyExpires || 0);
    const address = pending.mailVerifyAddress || '';
    const current = Classes.User.fromEntry(attrs).email || '';
    // THE HASH IS OF THE TOKEN AND THE ADDRESS THE ACCOUNT HAD WHEN IT WAS
    // SENT (#64), so a link for an address somebody has since replaced — or
    // a change asked for from an address since replaced — verifies nothing.
    // `address` is what the link proves: the account's own (a verification)
    // or the NEW one it was sent to (a change, rcbj's D5).
    if (!stored || !expires || expires < now() || !address ||
        !crypto.verifySecret(this.boundToken(String(token), current),
                             stored)) {
      log.debug("Leaving MailUses.checkVerification(). Refused.");
      return refused;
    }
    log.debug("Leaving MailUses.checkVerification(). Good.");
    return { ok: true, address: address,
             change: address.toLowerCase() !== current.toLowerCase(),
             former: current };
  }

  // Follow the link: the address is recorded as verified and the link spent.
  /**
   * Follows a verification link: the address is recorded as verified and the
   * link spent; a new address becomes `mail` now.
   *
   * @param username - the person
   * @param token - the link's token
   * @returns `{ ok, address, changed }`, or a coded refusal
   */
  async completeVerification(username: string, token: string):
      Promise<Json> {
    const { log, mail, audit } = this.deps;
    log.debug("Entering MailUses.completeVerification(). " + username);
    const checked = this.checkVerification(username, token);
    if (!checked.ok) {
      log.debug("Leaving MailUses.completeVerification(). Refused.");
      return checked;
    }
    const dir = mail.directory();
    if (checked.change) {
      // A NEW ADDRESS BECOMES `mail` NOW, AND NOT BEFORE (D5), verified —
      // the person proved it — and the directory tells the former one.
      // THE CLAIM IS ANSWERED BEFORE THE LINK IS SPENT (#644): a collision
      // leaves the triple, so the link can be tried again, and is the
      // code recorded. Any other failure still spends the link.
      const written = dir && typeof dir.writeAddress === 'function'
        ? await dir.writeAddress(username, checked.address, 'link') : false;
      const accepted = written === true ||
        (!!written && (written as Json).ok === true);
      if (!accepted) {
        const code = written && (written as Json).code;
        if (code === 'STS-LDAP-0202') {
          log.debug("Leaving MailUses.completeVerification(). The address " +
                    "is already a name.");
          return this.deps.errorCodes.mark({ ok: false, errors: ['The new ' +
            'address could not be stored. Try again.'] }, 'STS-LDAP-0202');
        }
        dir.writeMailFlag(username, 'stsMailVerifyToken', '');
        dir.writeMailFlag(username, 'stsMailVerifyExpires', '');
        dir.writeMailFlag(username, 'stsMailVerifyAddress', '');
        log.debug("Leaving MailUses.completeVerification(). Not written.");
        return this.deps.errorCodes.mark({ ok: false, errors: ['The new ' +
          'address could not be stored. Try again.'] }, 'STS-MAIL-0038');
      }
    }
    dir.writeMailFlag(username, 'stsMailVerifyToken', '');
    dir.writeMailFlag(username, 'stsMailVerifyExpires', '');
    dir.writeMailFlag(username, 'stsMailVerifyAddress', '');
    if (!checked.change) {
      dir.writeMailFlag(username, 'stsMailVerified', checked.address);
    }
    audit.audit({ action: 'mail.verified', actor: username, target: username,
      protocol: 'Mail', channel: 'http',
      summary: username + ' verified the address ' + checked.address,
      detail: { address: checked.address } });
    log.debug("Leaving MailUses.completeVerification(). Verified.");
    return { ok: true, address: checked.address, changed: !!checked.change,
             message: checked.change
               ? checked.address + ' is now your verified address.'
               : checked.address + ' is verified.' };
  }

  // The token as it is hashed: with the address the account has, lower-cased.
  private boundToken(token: string, address: string): string {
    const { log } = this.deps;
    log.debug("Entering MailUses.boundToken().");
    log.debug("Leaving MailUses.boundToken().");
    return String(token) + '\n' + String(address || '').trim().toLowerCase();
  }

  // -------------------------------------------------------------------------
  // 2b. A PERSON CHANGES THEIR OWN ADDRESS (#64, rcbj's D5): the new address
  // is held as `stsMailVerifyAddress` and mailed a verification link; it
  // becomes `mail` only when that link is followed. Until then the account
  // keeps the address it had — resets and codes go on going there — so an
  // address nobody proved is never where a credential is sent.
  // -------------------------------------------------------------------------
  /**
   * Starts a person's change of their own address: the new address is held
   * aside and mailed a verification link, and becomes `mail` only when that
   * link is followed.
   *
   * @param username - the person
   * @param address - the new address
   * @param via - the surface it came through
   * @param actor - who asked, when not the person
   * @returns `{ ok, message }`, or a coded refusal
   */
  startAddressChange(username: string, address: string, via: string,
                     actor?: string): Json {
    const { log, config, mail, crypto, errorCodes, now } = this.deps;
    log.debug("Entering MailUses.startAddressChange(). " + username);
    const dir = mail.directory();
    const who = mail.recipient(username);
    if (!dir || !who) {
      log.debug("Leaving MailUses.startAddressChange(). Nobody.");
      return errorCodes.mark({ ok: false, errors: ['There is nobody called "' +
        String(username || '') + '" in this realm.'] }, 'STS-MAIL-0012');
    }
    const wanted = String(address || '').trim();
    const bad = require('./mail_transports').addressProblem(wanted);
    if (!wanted || bad) {
      log.debug("Leaving MailUses.startAddressChange(). Not an address.");
      return errorCodes.mark({ ok: false, errors: ['"' + wanted.slice(0, 80) +
        '" is not an address this service can send to' +
        (bad ? ': it ' + bad : '') + '.'] }, 'STS-MAIL-0039');
    }
    if (who.address && wanted.toLowerCase() === who.address.toLowerCase()) {
      log.debug("Leaving MailUses.startAddressChange(). The same address.");
      return this.startVerification(username, via, actor);
    }
    const token = stsCrypto.randomBytes(32).toString('base64url');
    const ttl = Number(config.value('mail.verificationTtlMinutes'));
    dir.writeMailFlag(username, 'stsMailVerifyToken',
                      crypto.hashSecret(this.boundToken(token, who.address)));
    dir.writeMailFlag(username, 'stsMailVerifyExpires',
                      String(now() + ttl * 60000));
    dir.writeMailFlag(username, 'stsMailVerifyAddress', wanted);
    const sent = mail.sendToPendingAddress({
      username: username, template: 'address-verification',
      values: { username: username, address: wanted,
                expiresMinutes: String(ttl) },
      links: { link: VERIFY_PATH + '?user=' + encodeURIComponent(username) +
                     '#token=' + encodeURIComponent(token) },
      via: via, actor: actor || username
    });
    if (!sent.ok) {
      log.debug("Leaving MailUses.startAddressChange(). Not queued.");
      return errorCodes.mark({ ok: false, errors: ['No verification link ' +
        'was sent: ' + String(sent.error || 'it was refused') + '.'] },
        (sent.refused[0] && sent.refused[0].code) || 'STS-MAIL-0001');
    }
    log.debug("Leaving MailUses.startAddressChange(). Sent.");
    return { ok: true, message: 'A link was sent to ' + wanted + '. Your ' +
             'address changes to it when you follow the link, within ' + ttl +
             ' minutes; until then it stays ' + (who.address || 'unset') +
             '.' };
  }

  // -------------------------------------------------------------------------
  // 3. AN ADMINISTRATOR'S LINK, MAILED. `kind` is `reset` or `activation`,
  // `token` the one just issued. `{ ok, mailedTo, message }` or a coded
  // refusal; the caller then shows the link only if this failed.
  // -------------------------------------------------------------------------
  /**
   * Mails a reset or activation link an administrator just issued to the
   * person, instead of showing it to the administrator.
   *
   * @param kind - `reset` or `activation`
   * @param username - the person
   * @param token - the link's token
   * @param actor - the administrator
   * @param via - the surface it came through
   * @returns `{ ok, mailedTo, message }`, or a coded refusal after which the
   * caller shows the link
   */
  mailAdministratorLink(kind: string, username: string, token: string,
                        actor: string, via: string): Json {
    const { log, config, mail, errorCodes } = this.deps;
    log.debug("Entering MailUses.mailAdministratorLink(). " + kind);
    const reset = kind === 'reset';
    const sent = mail.send({
      username: username,
      template: reset ? 'password-reset' : 'account-activation',
      values: { username: username,
                requestedBy: actor
                  ? MailUses.said('requestedBy.administratorNamed',
                                  { actor: actor })
                  : MailUses.said('requestedBy.administrator'),
                expiresMinutes: String(config.value(reset
                  ? 'security.passwordResetTtlMinutes'
                  : 'security.activationTtlMinutes')) },
      links: { link: (reset ? RESET_PATH : ACTIVATE_PATH) + '?user=' +
                     encodeURIComponent(username) + '#token=' +
                     encodeURIComponent(token) },
      via: via, actor: actor
    });
    if (!sent.ok) {
      log.debug("Leaving MailUses.mailAdministratorLink(). Not queued.");
      return errorCodes.mark({ ok: false, errors: ['The link was not mailed: ' +
        String(sent.error || 'it was refused') + '.'] },
        (sent.refused[0] && sent.refused[0].code) || 'STS-MAIL-0001');
    }
    const to = sent.queued[0] ? sent.queued[0].to
      : (sent.duplicates[0] ? sent.duplicates[0].to : '');
    log.debug("Leaving MailUses.mailAdministratorLink(). Mailed.");
    return { ok: true, mailedTo: to, message: 'The link was mailed to ' + to +
             ' and is not shown here.' };
  }

  // -------------------------------------------------------------------------
  // 4. A SECURITY NOTICE. `kind` is a security template id. It never throws
  // and never refuses loudly: a notice is sent from the middle of an act that
  // has already happened. `bySystem` also tells the realm's administrators.
  // -------------------------------------------------------------------------
  /**
   * Sends a security notice a person cannot decline, and tells the realm's
   * administrators too when the service itself acted.
   *
   * Never throws; a failure is logged (STS-MAIL-0031).
   *
   * @param kind - the security template's id
   * @param username - the person
   * @param facts - `values`, `dedupKey`, `via`, `actor`, `bySystem` and `act`
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  notice(kind: string, username: string, facts?: Json): Json {
    const { log, config, mail, realms } = this.deps;
    log.debug("Entering MailUses.notice(). " + kind + " " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'off' };
    try {
      if (!config.value('mail.securityNotices') || !username ||
          !mail.available()) {
        log.debug("Leaving MailUses.notice(). Off, nobody, or no transport.");
        return out;
      }
      const values = Object.assign({ username: username,
                                     when: this.instant() },
                                   f.values || {});
      out = mail.send({
        username: username, template: kind, values: values,
        dedupKey: f.dedupKey || (kind + ':' + MailUses.keyOf(values.how ||
                                 values.why || values.by || '')),
        via: f.via || 'a security notice', actor: f.actor || ''
      });
      if (f.bySystem && config.value('mail.notifyAdministrators')) {
        mail.send({
          toAdministrators: true, template: 'administrator-alert',
          values: { username: username, when: values.when,
                    act: f.act || kind,
                    why: values.why || '' },
          dedupKey: 'admin:' + kind + ':' + username,
          via: f.via || 'a security notice', actor: 'the service'
        });
      }
    } catch (e) {
      log.debug("Caught in MailUses.notice(): " + ((e && e.message) || e));
      log.warn(this.deps.errorCodes.tag('STS-MAIL-0031') + 'mail: a ' + kind +
               ' notice for ' + username + ' in the "' + realms.currentId() +
               '" realm could not be queued: ' + ((e && e.message) || e));
    }
    log.debug("Leaving MailUses.notice().");
    return out;
  }

  // THE CAEP / RISC acts `ssf/account_signals.ts` sees, turned into notices.
  // `act` is the account-signals method's name; `n` its notice.
  /**
   * Turns a CAEP or RISC act `ssf/account_signals.ts` sees into the matching
   * security notice.
   *
   * @param act - the account-signals method's name
   * @param n - its notice
   * @returns what `notice()` answered, or a skip
   */
  fromAccountSignal(act: string, n: Json): Json {
    const { log } = this.deps;
    log.debug("Entering MailUses.fromAccountSignal(). " + act);
    const notice = n || {};
    const username = String(notice.username || '');
    const system = String(notice.initiatingEntity || '') === 'system';
    let out: Json = { ok: false, skipped: 'not a notice' };
    // THE PASSWORD ITSELF — an app password (#101) carries a friendlyName
    // and is not "your password was changed".
    if (act === 'credentialChanged' &&
        String(notice.credentialType || 'password') === 'password' &&
        !notice.friendlyName) {
      out = this.notice('password-changed', username, {
        // `reasonUser` is CAEP's `reason_user`, a sentence the door that
        // acted wrote in English for every receiver; it stays as written.
        values: { how: notice.reasonUser || notice.via
          ? String(notice.reasonUser || notice.via)
          : MailUses.said('how.by', {
              entity: String(notice.initiatingEntity || 'someone') }) },
        via: notice.via });
    } else if (act === 'credentialCompromised') {
      out = this.notice('credential-compromised', username, {
        values: { what: MailUses.said('credential.type', {
                    type: String(notice.credentialType || 'password') }),
                  why: String(notice.reasonUser || '') },
        bySystem: system,
        act: MailUses.said('act.credentialCompromised'),
        via: notice.via });
    } else if (act === 'recoveryActivated' && !notice.mailed) {
      out = this.notice('recovery-started', username, {
        values: { by: notice.initiatingEntity === 'user'
          ? MailUses.said('by.you') : MailUses.said('by.administrator') },
        via: notice.via });
    } else {
      // EVERY OTHER CREDENTIAL ADDED OR REMOVED (#2163).
      const item = MailUses.credentialChangeOf(act, notice);
      if (item) {
        out = this.credentialChanged(item);
      }
    }
    log.debug("Leaving MailUses.fromAccountSignal().");
    return out;
  }

  // -------------------------------------------------------------------------
  // 4b. A CREDENTIAL ADDED OR REMOVED (#2163). See CREDENTIAL_KINDS above.
  // -------------------------------------------------------------------------
  /**
   * The notice line an account signal is, or null when it is not one this
   * use mails: a password itself (the `password-changed` notice's), a type
   * no kind names, a change with no `changeType`, or one the service or a
   * policy made (a renewal superseding a certificate, a key a policy no
   * longer accepts), which no person did and nobody has to answer for.
   *
   * @param act - the account-signals method's name
   * @param n - its notice
   * @returns `{ username, kind, change, label, by }`, or null
   */
  static credentialChangeOf(act: string, n: Json): CredentialChangeItem |
      null {
    helpers.log.debug("Entering MailUses.credentialChangeOf(). " + act);
    const notice = n || {};
    const username = String(notice.username || '');
    const type = String(notice.credentialType || '');
    const changeType = String(notice.changeType || '');
    const entity = String(notice.initiatingEntity || 'admin');
    let kind = '';
    if (act === 'credentialChanged') {
      // An app password (#101) is a password with a name. A SCEP challenge
      // password is a password too, and an enrolment secret rather than
      // anything a person signs in with.
      if (type === 'password') {
        kind = notice.friendlyName && !/SCEP/.test(String(notice.via || ''))
          ? 'app-password' : '';
      } else {
        kind = CREDENTIAL_KINDS[type] || '';
      }
    } else if (act === 'recoveryInformationChanged') {
      // A SET GENERATED OR REMOVED, never a code spent: the person spending
      // one is at the screen, and was not asked to be told of it.
      kind = 'recovery-codes';
    }
    const change = changeType === 'create'
      ? (kind === 'recovery-codes' ? 'generated' : 'added')
      : (changeType === 'delete' || changeType === 'revoke' ? 'removed'
        : (changeType === 'update' ? 'changed' : ''));
    if (!kind || !username || !change || entity === 'system' ||
        entity === 'policy') {
      helpers.log.debug("Leaving MailUses.credentialChangeOf(). Not one.");
      return null;
    }
    helpers.log.debug("Leaving MailUses.credentialChangeOf(). " + kind);
    return { username: username, kind: kind, change: change,
             label: String(notice.friendlyName || ''),
             by: entity === 'user' ? 'user' : 'admin' };
  }

  /**
   * Tells a person that a credential of theirs was added, removed or
   * changed (#2163): at once, or — inside `batch()` — as one line of the
   * one notice the batch sends when it ends.
   *
   * Never throws. Off with `mail.credentialChangeNotices` (or every
   * security notice, `mail.securityNotices`), or without a transport.
   *
   * @param item - `{ username, kind, change, label, by }`: `kind` one of
   *   the kinds above, `change` `added`, `generated`, `removed` or
   *   `changed`, `by` `user` or `admin`
   * @returns what `notice()` answered, `{ ok: true, batched: true }`, or a
   *   skip
   */
  credentialChanged(item: CredentialChangeItem): Json {
    const { log, config } = this.deps;
    log.debug("Entering MailUses.credentialChanged().");
    const one = item || ({} as CredentialChangeItem);
    if (!one.username || OWN_KINDS.indexOf(String(one.kind)) < 0) {
      log.debug("Leaving MailUses.credentialChanged(). Not one.");
      return { ok: false, skipped: 'not a credential change' };
    }
    let on = true;
    try {
      on = !!config.value('mail.credentialChangeNotices');
    } catch (e) {
      log.debug("Caught in MailUses.credentialChanged(): " +
                ((e && e.message) || e));
      // A configuration that cannot be read keeps the default, which is on.
      on = true;
    }
    if (!on) {
      log.debug("Leaving MailUses.credentialChanged(). Off.");
      return { ok: false, skipped: 'off' };
    }
    const held = credentialBatches.getStore();
    if (held) {
      held.items.push({ username: String(one.username),
                        kind: String(one.kind), change: String(one.change),
                        label: String(one.label || ''),
                        by: one.by === 'user' ? 'user' : 'admin' });
      log.debug("Leaving MailUses.credentialChanged(). Batched.");
      return { ok: true, batched: true };
    }
    const out = this.sendCredentialNotice(String(one.username), [one]);
    log.debug("Leaving MailUses.credentialChanged().");
    return out;
  }

  // The one notice for one person's changes: a line each, the repeats
  // (the same change told by two doors) dropped.
  private sendCredentialNotice(username: string,
                               items: CredentialChangeItem[]): Json {
    const { log } = this.deps;
    log.debug("Entering MailUses.sendCredentialNotice(). " + items.length);
    const seen: string[] = [];
    const lines: Json[] = [];
    let byUser = true;
    items.forEach(function (one: CredentialChangeItem): void {
      const key = one.kind + '|' + one.change + '|' + (one.label || '');
      if (seen.indexOf(key) >= 0) {
        return;
      }
      seen.push(key);
      if (one.by !== 'user') {
        byUser = false;
      }
      lines.push(one.label
        ? MailUses.said('credentialChange.itemNamed', {
            kind: one.kind, change: one.change, label: one.label })
        : MailUses.said('credentialChange.item', {
            kind: one.kind, change: one.change }));
    });
    // ONE CHANGE MAILS ONCE: the same change told again in the channel's
    // window (`mail.dedupWindowS`) is that message, not another.
    const out = this.notice('credential-changed', username, {
      values: { what: { list: lines },
                by: MailUses.said('credentialChange.by',
                                  { entity: byUser ? 'user' : 'admin' }) },
      dedupKey: 'credential-changed:' + seen.join(',') + ':' +
                this.when(),
      via: 'a credential change' });
    log.debug("Leaving MailUses.sendCredentialNotice().");
    return out;
  }

  /**
   * Runs a door's act as ONE batch of credential changes (#2163): every
   * change told inside it, however deep, is held, and when `fn` returns —
   * or its promise settles — each person is sent one notice listing every
   * line of theirs. An administrator removing all of a person's factors
   * sends one message, not one per factor. A batch inside a batch is the
   * outer one.
   *
   * @param fn - the act
   * @returns what `fn` returns
   */
  batch<T>(fn: () => T): T {
    const { log } = this.deps;
    log.debug("Entering MailUses.batch().");
    if (credentialBatches.getStore()) {
      log.debug("Leaving MailUses.batch(). Inside another.");
      return fn();
    }
    const held: CredentialBatch = { items: [] };
    const self = this;
    const flush = function (): void {
      log.debug("Entering flush().");
      const people: string[] = [];
      held.items.forEach(function (one: CredentialChangeItem): void {
        if (people.indexOf(one.username) < 0) {
          people.push(one.username);
        }
      });
      people.forEach(function (who: string): void {
        self.sendCredentialNotice(who, held.items.filter(
          function (one: CredentialChangeItem): boolean {
            return one.username === who;
          }));
      });
      held.items = [];
      log.debug("Leaving flush().");
    };
    let answer: T;
    try {
      answer = credentialBatches.run(held, fn);
    } catch (e) {
      log.debug("Caught in MailUses.batch(): " + ((e && e.message) || e));
      // What was changed before the throw was changed: it is told.
      flush();
      throw e;
    }
    if (answer && typeof (answer as Json).then === 'function') {
      log.debug("Leaving MailUses.batch(). A promise.");
      return (answer as Json).then(function (value: Json): Json {
        flush();
        return value;
      }, function (e: Json): Json {
        flush();
        throw e;
      });
    }
    flush();
    log.debug("Leaving MailUses.batch().");
    return answer;
  }

  // -------------------------------------------------------------------------
  // 5. AN ACCESS REQUEST WAITING FOR ITS RESOURCE OWNER (#432 phase 6): a
  // GNAP grant a client asked for on this person's behalf while they were
  // not there (RFC 9635 section 1.4), waiting on `/portal/ciba`. Never
  // throws: the request is already queued, and a message that cannot be
  // sent leaves it waiting there all the same.
  // -------------------------------------------------------------------------
  /**
   * Tells a person that an application's request waits for their approval
   * on the portal.
   *
   * @param username - the resource owner
   * @param facts - `client` (the registered identifier), `rights` (the
   *   access types asked for, data; empty says "access" in the person's
   *   language), `expiresMinutes`, `dedupKey`
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  accessRequested(username: string, facts: Json): Json {
    const { log, mail, errorCodes, realms } = this.deps;
    log.debug("Entering MailUses.accessRequested(). " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'no transport' };
    try {
      if (!username || !mail.available()) {
        log.debug("Leaving MailUses.accessRequested(). Nobody, or no " +
                  "transport.");
        return out;
      }
      out = mail.send({
        username: username, template: 'access-request',
        values: { username: username, client: String(f.client || ''),
                  rights: f.rights ? String(f.rights)
                    : MailUses.said('rights.access'),
                  expiresMinutes: String(f.expiresMinutes || '') },
        links: { link: '/portal/ciba' },
        dedupKey: String(f.dedupKey || ('access-request:' + username)),
        via: 'a GNAP access request', actor: String(f.client || '')
      });
    } catch (e) {
      log.debug("Caught in MailUses.accessRequested(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-MAIL-0180') + 'mail: the access request ' +
               'notice for ' + username + ' in the "' + realms.currentId() +
               '" realm could not be queued: ' + ((e && e.message) || e));
    }
    log.debug("Leaving MailUses.accessRequested().");
    return out;
  }

  // -------------------------------------------------------------------------
  // 6. A STARTED POST-LOGIN ACTIVITY'S REMINDER (#1111): to the address on
  // the person's entry, never one a request names; the link is the portal's
  // path on this service's pinned origin, which signs nobody in. The dedup
  // key names the started activity and the mail's number, so a run repeated on
  // another node inside `mail.dedupWindowS` queues it once.
  // -------------------------------------------------------------------------
  /**
   * Tells the realm's administrators that a certificate it relies on changed
   * state (#1360). The audit calls this on a change only.
   *
   * @param facts - `{ changes, dedupKey }`
   * @returns what the channel answered, or null when it could not send
   */
  pkiPinStatus(facts: Json): Json {
    const { log, mail } = this.deps;
    log.debug("Entering MailUses.pkiPinStatus().");
    let out: Json = null;
    try {
      out = mail.send({
        toAdministrators: true, template: 'pki-pin-status',
        values: { changes: String(facts.changes || '') },
        dedupKey: String(facts.dedupKey || ''),
        via: 'the pinned certificate audit', actor: 'the service'
      });
    } catch (e) {
      log.debug("Caught in MailUses.pkiPinStatus(): " +
                ((e && e.message) || e));
    }
    log.debug("Leaving MailUses.pkiPinStatus().");
    return out;
  }

  /**
   * Mails a person a started post-login activity's reminder to sign in.
   *
   * @param username - the person
   * @param facts - `started` (its id), `activity` (which activity: its
   *   own message, #2009 P4; the passkey migration's when absent, as a
   *   reminder asked before P4 always was), `mails` (how many it sent them
   *   before this one), `actor` (who started it)
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  postLoginReminder(username: string, facts: Json): Json {
    const { log, mail, errorCodes, realms } = this.deps;
    log.debug("Entering MailUses.postLoginReminder(). " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'no transport' };
    try {
      if (!username || !mail.available()) {
        log.debug("Leaving MailUses.postLoginReminder(). Nobody, or no " +
                  "transport.");
        return out;
      }
      out = mail.send({
        username: username,
        template: PostLoginKinds.templateOf(String(f.activity || '')),
        values: { username: username },
        links: { signin: '/portal' },
        dedupKey: 'post-login-reminder:' + String(f.started || '') + ':' +
                  username + ':' + String(Number(f.mails) || 0),
        via: 'a started post-login activity', actor: String(f.actor || '')
      });
    } catch (e) {
      log.debug("Caught in MailUses.postLoginReminder(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-AUTHN-0494') + 'mail: the post-login ' +
               'reminder for ' + username + ' in the "' + realms.currentId() +
               '" realm could not be queued: ' + ((e && e.message) || e));
      out = { ok: false, skipped: 'threw' };
    }
    log.debug("Leaving MailUses.postLoginReminder().");
    return out;
  }

  // -------------------------------------------------------------------------
  // 8. A UMA 2.0 REQUEST WAITING FOR ITS RESOURCE OWNER (#1194): an "ask me
  // each time" share was matched, and the request waits on /portal/shared.
  // Never throws, for `accessRequested()`'s reason.
  // -------------------------------------------------------------------------
  /**
   * Tells a resource owner that a UMA request waits for their approval.
   *
   * @param username - the owner
   * @param facts - `requester`, `client`, `resource`, `scopes`,
   *   `expiresMinutes`, `dedupKey`
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  umaApprovalRequested(username: string, facts: Json): Json {
    const { log, mail, errorCodes, realms } = this.deps;
    log.debug("Entering MailUses.umaApprovalRequested(). " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'no transport' };
    try {
      if (!username || !mail.available()) {
        log.debug("Leaving MailUses.umaApprovalRequested(). Nobody, or no " +
                  "transport.");
        return out;
      }
      out = mail.send({
        username: username, template: 'uma-approval',
        values: { username: username, requester: String(f.requester || ''),
                  client: String(f.client || ''),
                  resource: String(f.resource || ''),
                  scopes: String(f.scopes || ''),
                  expiresMinutes: String(f.expiresMinutes || '') },
        links: { link: '/portal/shared' },
        dedupKey: String(f.dedupKey || ('uma-approval:' + username)),
        via: 'a UMA request', actor: String(f.client || '')
      });
    } catch (e) {
      log.debug("Caught in MailUses.umaApprovalRequested(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-MAIL-0180') + 'mail: the UMA approval ' +
               'notice for ' + username + ' in the "' + realms.currentId() +
               '" realm could not be queued: ' + ((e && e.message) || e));
    }
    log.debug("Leaving MailUses.umaApprovalRequested().");
    return out;
  }

  // -------------------------------------------------------------------------
  // 7. AN AUTHZEN ACCESS REQUEST WAITING FOR ITS APPROVERS (#1180): to the
  // address on the approver's own entry, never one a request names; the
  // link is the portal page, which signs nobody in. The dedup key names the
  // task and the approver, so a request mailed again inside
  // `mail.dedupWindowS` is queued once. Never throws.
  // -------------------------------------------------------------------------
  /**
   * Tells an approver an AuthZEN access request waits for them, or — for
   * an emergency access already granted — asks for their review.
   *
   * @param username - the approver
   * @param facts - `requester`, `subject`, `action`, `resource`,
   *   `application` (data, from the denied tuple), `emergency`,
   *   `justification`, `expiresMinutes`, `dedupKey`
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  authzenAccessRequested(username: string, facts: Json): Json {
    const { log, mail, errorCodes, realms } = this.deps;
    log.debug("Entering MailUses.authzenAccessRequested(). " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'no transport' };
    try {
      if (!username || !mail.available()) {
        log.debug("Leaving MailUses.authzenAccessRequested(). Nobody, or " +
                  "no transport.");
        return out;
      }
      const values: Json = { username: username,
                             requester: String(f.requester || ''),
                             subject: String(f.subject || ''),
                             action: String(f.action || ''),
                             resource: String(f.resource || ''),
                             application: String(f.application || '') };
      if (f.emergency) {
        values.justification = String(f.justification || '');
      } else {
        values.expiresMinutes = String(f.expiresMinutes || '');
      }
      out = mail.send({
        username: username,
        template: f.emergency ? 'authzen-emergency-access'
                              : 'authzen-access-request',
        values: values,
        links: { link: '/portal/access-requests' },
        dedupKey: String(f.dedupKey || ('authzen-access-request:' +
                                        username)),
        via: 'an AuthZEN access request', actor: String(f.requester || '')
      });
    } catch (e) {
      log.debug("Caught in MailUses.authzenAccessRequested(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-AUTHZEN-0093') + 'mail: the AuthZEN ' +
               'access request notice for ' + username + ' in the "' +
               realms.currentId() + '" realm could not be queued: ' +
               ((e && e.message) || e));
      out = { ok: false, skipped: 'threw' };
    }
    log.debug("Leaving MailUses.authzenAccessRequested().");
    return out;
  }

  /**
   * Tells the requester that an approval of their access request was
   * revoked (#1203). No link. Skips a requester the channel cannot
   * address, so an application never becomes a refused send.
   *
   * @param username - the requester
   * @param facts - `approver`, `subject`, `action`, `resource`,
   *   `application` (data, from the task) and `dedupKey`
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  authzenAccessRevoked(username: string, facts: Json): Json {
    const { log, mail, errorCodes, realms } = this.deps;
    log.debug("Entering MailUses.authzenAccessRevoked(). " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'no transport' };
    try {
      if (!username || !mail.available()) {
        log.debug("Leaving MailUses.authzenAccessRevoked(). Nobody, or " +
                  "no transport.");
        return out;
      }
      const person = mail.recipient(username);
      if (!person || !person.address) {
        out = { ok: false, skipped: 'no address' };
        log.debug("Leaving MailUses.authzenAccessRevoked(). No address.");
        return out;
      }
      out = mail.send({
        username: username,
        template: 'authzen-access-revoked',
        values: { username: username,
                  approver: String(f.approver || ''),
                  subject: String(f.subject || ''),
                  action: String(f.action || ''),
                  resource: String(f.resource || ''),
                  application: String(f.application || '') },
        dedupKey: String(f.dedupKey || ('authzen-access-revoked:' +
                                        username)),
        via: 'an AuthZEN access revocation',
        actor: String(f.approver || '')
      });
    } catch (e) {
      // The revocation already stands. This is only the notice.
      log.debug("Caught in MailUses.authzenAccessRevoked(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-AUTHZEN-0138') + 'mail: the AuthZEN ' +
               'access revocation notice for ' + username + ' in the "' +
               realms.currentId() + '" realm could not be queued: ' +
               ((e && e.message) || e));
      out = { ok: false, skipped: 'threw' };
    }
    log.debug("Leaving MailUses.authzenAccessRevoked().");
    return out;
  }

  // -------------------------------------------------------------------------
  // 4c. A SIGN-IN THAT SUCCEEDED LOOKING UNUSUAL, AND A RUN OF REFUSED
  // PASSWORDS (#2162, ASVS 5.0.0 6.3.5). Security notices: a person cannot
  // decline them, an operator can (`mail.signInAlerts`). Each kind is told
  // at most once in `mail.signInAlertWindowS` — the outbox is the record
  // (`mail.queuedWithin()`), so the window is the cluster's and survives a
  // restart for as long as `mail.retentionS` keeps the row. Never throws:
  // the sign-in has already happened.
  // -------------------------------------------------------------------------
  private signInAlertsOn(): boolean {
    const { log, config, mail } = this.deps;
    log.debug("Entering MailUses.signInAlertsOn().");
    const on = !!config.value('mail.signInAlerts') &&
      !!config.value('mail.securityNotices') && mail.available();
    log.debug("Leaving MailUses.signInAlertsOn(). " + on);
    return on;
  }

  /**
   * Tells a person that a sign-in to their account succeeded looking
   * unusual: when, roughly where, with what browser or device, by which
   * method, what was unusual, and a link to their recent sign-ins, where
   * saying it was not them signs every session out.
   *
   * A kind already told in `mail.signInAlertWindowS` is left out, and
   * nothing is sent when every kind was.
   *
   * @param username - the person
   * @param facts - `kinds` (of SIGN_IN_ALERT_KINDS), `at` (ms), `city`,
   *   `subdivision`, `country`, `browser`, `os`, `method` (the credential
   *   kind)
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  signInAlert(username: string, facts: Json): Json {
    const { log, config, mail } = this.deps;
    log.debug("Entering MailUses.signInAlert(). " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'off' };
    try {
      if (!username || !this.signInAlertsOn()) {
        log.debug("Leaving MailUses.signInAlert(). Off or nobody.");
        return out;
      }
      const windowS = Number(config.value('mail.signInAlertWindowS'));
      const kinds = (Array.isArray(f.kinds) ? f.kinds : [])
        .map(String).filter(function (k: string, i: number, all: string[]) {
          return SIGN_IN_ALERT_KINDS.indexOf(k) >= 0 && all.indexOf(k) === i;
        });
      const fresh = kinds.filter(function (k: string): boolean {
        return !mail.queuedWithin(username, 'sign-in-alert', 'kind:' + k,
                                  windowS);
      });
      if (!fresh.length) {
        log.debug("Leaving MailUses.signInAlert(). Told already.");
        return { ok: false, skipped: kinds.length ? 'told in the window'
                                                  : 'nothing unusual' };
      }
      const place = [f.city, f.subdivision, f.country].map(function (v) {
        return String(v || '').trim();
      }).filter(Boolean).join(', ');
      const browser = String(f.browser || '').trim();
      const os = String(f.os || '').trim();
      out = mail.send({
        username: username, template: 'sign-in-alert',
        values: {
          username: username,
          when: { date: Number(f.at) || this.deps.now() },
          place: place || MailUses.said('signIn.placeUnknown'),
          device: browser || os
            ? MailUses.said('signIn.device', { browser: browser || '?',
                                                os: os || '?' })
            : MailUses.said('signIn.deviceUnknown'),
          method: MailUses.said('signIn.method',
                                { kind: String(f.method || 'other') }),
          what: { list: fresh.map(function (k: string): Json {
            return MailUses.said('signIn.kind', { kind: k });
          }) }
        },
        links: { link: SIGN_INS_PATH },
        // EACH KIND IS A KEY: the message is about every fresh kind, so a
        // later sign-in showing any of them in the window finds it.
        dedupKey: 'kind:' + fresh[0],
        dedupAlso: fresh.slice(1).map(function (k: string): string {
          return 'kind:' + k;
        }),
        dedupWindowS: windowS,
        via: 'a sign-in alert', actor: '' });
    } catch (e) {
      log.debug("Caught in MailUses.signInAlert(): " + ((e && e.message) ||
                                                         e));
      log.warn(this.deps.errorCodes.tag('STS-MAIL-0031') + 'mail: a ' +
               'sign-in alert for ' + username + ' could not be queued: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving MailUses.signInAlert().");
    return out;
  }

  /**
   * Tells a person that passwords were refused for their account enough
   * times to reach the sign-in limit, whether or not anybody then signed
   * in; at most once in `mail.signInAlertWindowS`.
   *
   * @param username - the person
   * @param facts - `count` (refusals) and `minutes` (the window they were
   *   counted in)
   * @returns what `send()` answered, or `{ ok: false, skipped }`
   */
  refusedAttempts(username: string, facts: Json): Json {
    const { log, config, mail } = this.deps;
    log.debug("Entering MailUses.refusedAttempts(). " + username);
    const f = facts || {};
    let out: Json = { ok: false, skipped: 'off' };
    try {
      if (!username || !this.signInAlertsOn()) {
        log.debug("Leaving MailUses.refusedAttempts(). Off or nobody.");
        return out;
      }
      out = mail.send({
        username: username, template: 'sign-in-refusals',
        values: { username: username, when: this.instant(),
                  count: String(Number(f.count) || 0),
                  minutes: String(Number(f.minutes) || 0) },
        links: { link: SIGN_INS_PATH },
        dedupKey: 'refusals',
        dedupWindowS: Number(config.value('mail.signInAlertWindowS')),
        via: 'a sign-in alert', actor: '' });
    } catch (e) {
      log.debug("Caught in MailUses.refusedAttempts(): " +
                ((e && e.message) || e));
      log.warn(this.deps.errorCodes.tag('STS-MAIL-0031') + 'mail: the ' +
               'refused-attempts notice for ' + username + ' could not be ' +
               'queued: ' + ((e && e.message) || e));
    }
    log.debug("Leaving MailUses.refusedAttempts().");
    return out;
  }

  // -------------------------------------------------------------------------
  // 4d. A CREDENTIAL THAT EXPIRES SOON (#2247, ASVS 5.0.0 6.4.5). A security
  // notice, off with `mail.expiryReminders` (or every security notice).
  // `common/credential_expiry.ts` finds what is due and keeps, on its own
  // rows, which step each was told at; the outbox is the cluster's record
  // as well (`mail.queuedWithin()`), so a second node's run, or this one's
  // after a crash between the send and the row, sends nothing twice.
  // -------------------------------------------------------------------------
  /**
   * Whether expiry reminders are sent in the ambient realm: the switch,
   * security notices and a transport.
   *
   * @returns true when they are
   */
  expiryRemindersOn(): boolean {
    const { log, config, mail } = this.deps;
    log.debug("Entering MailUses.expiryRemindersOn().");
    const on = !!config.value('mail.expiryReminders') &&
      !!config.value('mail.securityNotices') && mail.available();
    log.debug("Leaving MailUses.expiryRemindersOn(). " + on);
    return on;
  }

  /**
   * Reminds a person that credentials of theirs expire soon: one message
   * naming every item, each with its kind, its label, the day it expires
   * and how it is renewed. An item already queued at its step (the outbox)
   * is left out, and nothing is sent when every item was.
   *
   * @param username - the person
   * @param items - `{ key, step, kind, label, notAfter }`: the credential's
   *   index key, the reminder step in days, its kind (of EXPIRY_RENEWAL),
   *   a label, and when it expires (ms)
   * @returns what `send()` answered, or `{ ok: false, skipped }`, with
   *   `told`: the keys now told at their step (sent, or found queued)
   */
  credentialsExpiring(username: string, items: Json[]): Json {
    const { log, mail } = this.deps;
    log.debug("Entering MailUses.credentialsExpiring(). " + username);
    let out: Json = { ok: false, skipped: 'off', told: [] };
    try {
      const all = (Array.isArray(items) ? items : []).filter(function (i:
          Json): boolean {
        return !!(i && i.key && Number(i.step) > 0);
      });
      if (!username || !all.length || !this.expiryRemindersOn()) {
        log.debug("Leaving MailUses.credentialsExpiring(). Off or nothing.");
        return out;
      }
      const keyOf = function (i: Json): string {
        return 'expiry:' + String(i.key) + ':' + String(Number(i.step));
      };
      const windowOf = function (i: Json): number {
        return Number(i.step) * 86400;
      };
      const queued: string[] = [];
      const fresh = all.filter(function (i: Json): boolean {
        if (mail.queuedWithin(username, 'credential-expiring', keyOf(i),
                              windowOf(i))) {
          queued.push(String(i.key));
          return false;
        }
        return true;
      });
      if (!fresh.length) {
        log.debug("Leaving MailUses.credentialsExpiring(). Told already.");
        return { ok: false, skipped: 'told at this step', told: queued };
      }
      out = mail.send({
        username: username, template: 'credential-expiring',
        values: {
          username: username,
          what: { list: fresh.map(function (i: Json): Json {
            const kind = String(i.kind || '');
            const at = Number(i.notAfter);
            return MailUses.said('expiry.item', {
              kind: kind,
              label: String(i.label || '').slice(0, 200) || '?',
              date: Number.isFinite(at) && at > 0
                ? new Date(at).toISOString().slice(0, 10) : '?',
              renew: EXPIRY_RENEWAL[kind] || 'administrator'
            });
          }) }
        },
        links: { link: PORTAL_PATH },
        // EACH ITEM AT ITS STEP IS A KEY: the message is about every fresh
        // one, so a later run finding any of them at that step finds it.
        dedupKey: keyOf(fresh[0]),
        dedupAlso: fresh.slice(1).map(keyOf),
        dedupWindowS: Math.max.apply(null, fresh.map(windowOf)),
        via: 'a credential expiry reminder', actor: '' });
      // TOLD: queued or found queued, and a refusal that would be the same
      // next run (no address, required encryption the person never chose);
      // a ceiling, a full outbox or the realm's own mail problem (no
      // transport, no link base) is tried again at the next run, and the
      // job stops its run at the realm's own (`again`).
      const retry = ['STS-MAIL-0001', 'STS-MAIL-0010', 'STS-MAIL-0015',
                     'STS-MAIL-0031', 'STS-MAIL-0244'];
      const again = (out.refused || []).some(function (r: Json): boolean {
        return retry.indexOf(String((r && r.code) || '')) >= 0;
      });
      out.again = again;
      out.told = queued.concat(out.ok || !again
        ? fresh.map(function (i: Json): string {
          return String(i.key);
        }) : []);
    } catch (e) {
      log.debug("Caught in MailUses.credentialsExpiring(): " +
                ((e && e.message) || e));
      log.warn(this.deps.errorCodes.tag('STS-MAIL-0246') + 'mail: the ' +
               'credential expiry reminder for ' + username + ' could not ' +
               'be queued: ' + ((e && e.message) || e));
      out = { ok: false, skipped: 'threw', told: [] };
    }
    log.debug("Leaving MailUses.credentialsExpiring().");
    return out;
  }

  // An account was disabled (`common/account_state.ts`), by `by`.
  /**
   * Sends the account-disabled notice.
   *
   * @param username - the person
   * @param why - the reason
   * @param bySystem - true when the service disabled it, which also tells
   * administrators
   * @returns what `notice()` answered
   */
  accountDisabled(username: string, why: string, bySystem: boolean): Json {
    const { log } = this.deps;
    log.debug("Entering MailUses.accountDisabled(). " + username);
    log.debug("Leaving MailUses.accountDisabled().");
    return this.notice('account-disabled', username, {
      values: { why: String(why || '') }, bySystem: bySystem,
      act: MailUses.said('act.accountDisabled'), via: 'account state' });
  }

  // An administrator ended a person's sessions.
  /**
   * Sends the notice that an administrator ended a person's sessions.
   *
   * @param username - the person
   * @param count - how many were ended
   * @param by - who ended them: a name, or a `mailValues` message
   * (`MailUses.said()`) the channel words in the person's language
   * @returns what `notice()` answered
   */
  sessionsEnded(username: string, count: number, by: string | Json): Json {
    const { log } = this.deps;
    log.debug("Entering MailUses.sessionsEnded(). " + username);
    log.debug("Leaving MailUses.sessionsEnded().");
    return this.notice('sessions-ended', username, {
      values: { count: String(count),
                by: by && typeof by === 'object' ? by
                  : by ? String(by) : MailUses.said('by.administrator') },
      dedupKey: 'sessions-ended:' + username, via: 'an administrator' });
  }

  // The `mail` attribute of an entry changed: the OLD address is told, and
  // only it — the entry's own record of where it could be reached, which is
  // the directory's value as it was, never an address from a request.
  /**
   * Tells the former address that an entry's `mail` changed, and only it.
   *
   * @param username - the person
   * @param formerAddress - the address as it was on the entry
   * @param newAddress - the address now
   * @returns what the send answered, or `{ ok: false, skipped }`
   */
  addressChanged(username: string, formerAddress: string,
                 newAddress: string): Json {
    const { log, mail, config } = this.deps;
    log.debug("Entering MailUses.addressChanged(). " + username);
    if (!formerAddress || !config.value('mail.securityNotices') ||
        !mail.available()) {
      log.debug("Leaving MailUses.addressChanged(). Nothing to tell.");
      return { ok: false, skipped: 'nothing to tell' };
    }
    const out = mail.sendToFormerAddress({
      username: username, formerAddress: formerAddress,
      template: 'address-changed',
      values: { username: username, when: this.instant(),
                address: newAddress || MailUses.said('address.none') },
      dedupKey: 'address-changed:' + formerAddress + '>' + newAddress,
      via: 'a directory change' });
    log.debug("Leaving MailUses.addressChanged().");
    return out;
  }
}

const slot = new InstanceSlot<MailUses>(
  'common/mail_uses',
  () => new MailUses(MailUses.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

/**
 * The four uses of the mail channel: password reset, address verification, an
 * administrator's links and security notices.
 *
 * Exports the class and facades forwarding to the instance the composition root
 * built.
 *
 * @namespace
 */
export = {
  MailUses: MailUses,
  installInstance: (instance: MailUses): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  RESET_ANSWER: MailUses.RESET_ANSWER,
  VERIFY_PATH: MailUses.VERIFY_PATH,
  said: MailUses.said,
  resetOffered: slot.forward('resetOffered'),
  requestReset: slot.forward('requestReset'),
  resetNeedsRecoveryCode: slot.forward('resetNeedsRecoveryCode'),
  startVerification: slot.forward('startVerification'),
  startAddressChange: slot.forward('startAddressChange'),
  checkVerification: slot.forward('checkVerification'),
  completeVerification: slot.forward('completeVerification'),
  mailAdministratorLink: slot.forward('mailAdministratorLink'),
  notice: slot.forward('notice'),
  fromAccountSignal: slot.forward('fromAccountSignal'),
  credentialChanged: slot.forward('credentialChanged'),
  credentialChangeOf: MailUses.credentialChangeOf,
  batch: slot.forward('batch'),
  accountDisabled: slot.forward('accountDisabled'),
  sessionsEnded: slot.forward('sessionsEnded'),
  signInAlert: slot.forward('signInAlert'),
  refusedAttempts: slot.forward('refusedAttempts'),
  expiryRemindersOn: slot.forward('expiryRemindersOn'),
  credentialsExpiring: slot.forward('credentialsExpiring'),
  EXPIRY_RENEWAL: EXPIRY_RENEWAL,
  SIGN_IN_ALERT_KINDS: SIGN_IN_ALERT_KINDS,
  addressChanged: slot.forward('addressChanged'),
  accessRequested: slot.forward('accessRequested'),
  authzenAccessRequested: slot.forward('authzenAccessRequested'),
  authzenAccessRevoked: slot.forward('authzenAccessRevoked'),
  postLoginReminder: slot.forward('postLoginReminder'),
  pkiPinStatus: slot.forward('pkiPinStatus')
};
