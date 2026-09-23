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
//      sessions ended by an administrator, password changed or reset, a
//      credential marked compromised, recovery started, the address changed
//      (to the OLD address). When the SERVICE did it (risk scoring), the
//      realm's Admin Write roster is told as well.
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

import nodeCrypto = require('crypto');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');
import config = require('./config');
import realms = require('./realms');
import mode = require('./mode');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import stsCrypto = require('./crypto');
import mail = require('./mail');

type Json = any;

// The paths a mailed link names (the portal registers them).
const RESET_PATH = '/portal/reset-password';
const ACTIVATE_PATH = '/portal/activate';
const VERIFY_PATH = '/portal/verify-email';

// The one sentence the forgot-password form answers, whatever happened.
const RESET_ANSWER = 'If that names an account here with an email address ' +
  'it may be reached at, a link to choose a new password has been sent ' +
  'there. It works once and for a limited time. Nothing changes until it ' +
  'is used.';

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
}

class MailUses {
  static readonly RESET_ANSWER = RESET_ANSWER;
  static readonly VERIFY_PATH = VERIFY_PATH;

  constructor(private readonly deps: MailUsesDeps) {
    deps.log.debug("Entering MailUses.constructor().");
    deps.log.debug("Leaving MailUses.constructor().");
  }

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
      }
    };
  }

  // The time, as a person reads it in a message: UTC, to the minute.
  private when(): string {
    const { log, now } = this.deps;
    log.debug("Entering MailUses.when().");
    log.debug("Leaving MailUses.when().");
    return new Date(now()).toISOString().replace('T', ' ').slice(0, 16) +
      ' UTC';
  }

  // -------------------------------------------------------------------------
  // 1. SELF-SERVICE RESET — is it offered here at all? The sign-in screen and
  // the portal ask before drawing the link.
  // -------------------------------------------------------------------------
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
  async requestReset(identifier: string, via: string): Promise<Json> {
    const { log, config, mail, audit, credentials, accountSignals } =
      this.deps;
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
      if (asked.indexOf('@') > 0 && typeof dir.personByMail === 'function') {
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
    const who = mail.recipient(username);
    if (!who || !who.address) {
      log.debug("Leaving MailUses.requestReset(). No address.");
      return answer('the account has no address', 'STS-MAIL-0011');
    }
    if (config.value('mail.resetRequiresVerifiedAddress') && !who.verified) {
      log.debug("Leaving MailUses.requestReset(). Unverified.");
      return answer('the address is not verified ' +
                    '(mail.resetRequiresVerifiedAddress)', 'STS-MAIL-0011');
    }
    const issued = creds.issuePasswordReset(username);
    if (!issued || !issued.ok) {
      log.debug("Leaving MailUses.requestReset(). Not issued.");
      return answer('no link could be issued: ' +
                    String((issued && issued.errors && issued.errors[0]) ||
                           ''), 'STS-MAIL-0030');
    }
    const sent = mail.send({
      username: username, template: 'password-reset',
      values: { username: username, requestedBy: 'you, or somebody who ' +
                'knew your account name, on the sign-in screen',
                expiresMinutes: String(config.value(
                  'security.passwordResetTtlMinutes')) },
      links: { link: RESET_PATH + '?user=' + encodeURIComponent(username) +
                     '&token=' + encodeURIComponent(issued.token) },
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
    const token = nodeCrypto.randomBytes(32).toString('base64url');
    const ttl = Number(config.value('mail.verificationTtlMinutes'));
    dir.writeMailFlag(username, 'stsMailVerifyToken', crypto.hashSecret(token));
    dir.writeMailFlag(username, 'stsMailVerifyExpires',
                      String(now() + ttl * 60000));
    dir.writeMailFlag(username, 'stsMailVerifyAddress', who.address);
    const sent = mail.send({
      username: username, template: 'address-verification',
      values: { username: username, address: who.address,
                expiresMinutes: String(ttl) },
      links: { link: VERIFY_PATH + '?user=' + encodeURIComponent(username) +
                     '&token=' + encodeURIComponent(token) },
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
    const attrs = entry.attributes || {};
    const first = function (name: string): string {
      log.debug("Entering first().");
      const v = attrs[name.toLowerCase()] || [];
      log.debug("Leaving first().");
      return v.length ? String(v[0]) : '';
    };
    const stored = first('stsMailVerifyToken');
    const expires = Number(first('stsMailVerifyExpires') || 0);
    const address = first('stsMailVerifyAddress');
    const current = first('mail');
    if (!stored || !expires || expires < now() || !address ||
        address.toLowerCase() !== current.toLowerCase() ||
        !crypto.verifySecret(String(token), stored)) {
      log.debug("Leaving MailUses.checkVerification(). Refused.");
      return refused;
    }
    log.debug("Leaving MailUses.checkVerification(). Good.");
    return { ok: true, address: address };
  }

  // Follow the link: the address is recorded as verified and the link spent.
  completeVerification(username: string, token: string): Json {
    const { log, mail, audit } = this.deps;
    log.debug("Entering MailUses.completeVerification(). " + username);
    const checked = this.checkVerification(username, token);
    if (!checked.ok) {
      log.debug("Leaving MailUses.completeVerification(). Refused.");
      return checked;
    }
    const dir = mail.directory();
    dir.writeMailFlag(username, 'stsMailVerifyToken', '');
    dir.writeMailFlag(username, 'stsMailVerifyExpires', '');
    dir.writeMailFlag(username, 'stsMailVerifyAddress', '');
    dir.writeMailFlag(username, 'stsMailVerified', checked.address);
    audit.audit({ action: 'mail.verified', actor: username, target: username,
      protocol: 'Mail', channel: 'http',
      summary: username + ' verified the address ' + checked.address,
      detail: { address: checked.address } });
    log.debug("Leaving MailUses.completeVerification(). Verified.");
    return { ok: true, address: checked.address,
             message: checked.address + ' is verified.' };
  }

  // -------------------------------------------------------------------------
  // 3. AN ADMINISTRATOR'S LINK, MAILED. `kind` is `reset` or `activation`,
  // `token` the one just issued. `{ ok, mailedTo, message }` or a coded
  // refusal; the caller then shows the link only if this failed.
  // -------------------------------------------------------------------------
  mailAdministratorLink(kind: string, username: string, token: string,
                        actor: string, via: string): Json {
    const { log, config, mail, errorCodes } = this.deps;
    log.debug("Entering MailUses.mailAdministratorLink(). " + kind);
    const reset = kind === 'reset';
    const sent = mail.send({
      username: username,
      template: reset ? 'password-reset' : 'account-activation',
      values: { username: username,
                requestedBy: 'an administrator' + (actor ? ' (' + actor + ')'
                                                         : ''),
                expiresMinutes: String(config.value(reset
                  ? 'security.passwordResetTtlMinutes'
                  : 'security.activationTtlMinutes')) },
      links: { link: (reset ? RESET_PATH : ACTIVATE_PATH) + '?user=' +
                     encodeURIComponent(username) + '&token=' +
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
      const values = Object.assign({ username: username, when: this.when() },
                                   f.values || {});
      out = mail.send({
        username: username, template: kind, values: values,
        dedupKey: f.dedupKey || (kind + ':' + String(values.how ||
                                 values.why || values.by || '')),
        via: f.via || 'a security notice', actor: f.actor || ''
      });
      if (f.bySystem && config.value('mail.notifyAdministrators')) {
        mail.send({
          toAdministrators: true, template: 'administrator-alert',
          values: { username: username, when: values.when,
                    act: String(f.act || kind),
                    why: String(values.why || '') },
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
        values: { how: String(notice.reasonUser || notice.via ||
                              'by ' + (notice.initiatingEntity || 'someone')) },
        via: notice.via });
    } else if (act === 'credentialCompromised') {
      out = this.notice('credential-compromised', username, {
        values: { what: String(notice.credentialType || 'password'),
                  why: String(notice.reasonUser || '') },
        bySystem: system, act: 'credential marked compromised',
        via: notice.via });
    } else if (act === 'recoveryActivated' && !notice.mailed) {
      out = this.notice('recovery-started', username, {
        values: { by: notice.initiatingEntity === 'user' ? 'you'
                                                         : 'an administrator' },
        via: notice.via });
    }
    log.debug("Leaving MailUses.fromAccountSignal().");
    return out;
  }

  // An account was disabled (`common/account_state.ts`), by `by`.
  accountDisabled(username: string, why: string, bySystem: boolean): Json {
    const { log } = this.deps;
    log.debug("Entering MailUses.accountDisabled(). " + username);
    log.debug("Leaving MailUses.accountDisabled().");
    return this.notice('account-disabled', username, {
      values: { why: String(why || '') }, bySystem: bySystem,
      act: 'account disabled', via: 'account state' });
  }

  // An administrator ended a person's sessions.
  sessionsEnded(username: string, count: number, by: string): Json {
    const { log } = this.deps;
    log.debug("Entering MailUses.sessionsEnded(). " + username);
    log.debug("Leaving MailUses.sessionsEnded().");
    return this.notice('sessions-ended', username, {
      values: { count: String(count), by: String(by || 'an administrator') },
      dedupKey: 'sessions-ended:' + username, via: 'an administrator' });
  }

  // The `mail` attribute of an entry changed: the OLD address is told, and
  // only it — the entry's own record of where it could be reached, which is
  // the directory's value as it was, never an address from a request.
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
      values: { username: username, when: this.when(),
                address: newAddress || '(none)' },
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

export = {
  MailUses: MailUses,
  installInstance: (instance: MailUses): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  RESET_ANSWER: MailUses.RESET_ANSWER,
  VERIFY_PATH: MailUses.VERIFY_PATH,
  resetOffered: slot.forward('resetOffered'),
  requestReset: slot.forward('requestReset'),
  startVerification: slot.forward('startVerification'),
  checkVerification: slot.forward('checkVerification'),
  completeVerification: slot.forward('completeVerification'),
  mailAdministratorLink: slot.forward('mailAdministratorLink'),
  notice: slot.forward('notice'),
  fromAccountSignal: slot.forward('fromAccountSignal'),
  accountDisabled: slot.forward('accountDisabled'),
  sessionsEnded: slot.forward('sessionsEnded'),
  addressChanged: slot.forward('addressChanged')
};
