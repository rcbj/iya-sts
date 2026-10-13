// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mail_factor.ts
//
// ---------------------------------------------------------------------------
// THE EMAILED FACTOR, AS A FACT ABOUT A PERSON (#64, 2026-09-23).
//
// What `authn/email_factor.ts`'s screens, `credentials.mechanismsFor()`, the
// portal and the console all need to agree on, in one place:
//
//   * WHETHER A PERSON HOLDS THE EMAILED SECOND FACTOR. rcbj's decision (D8)
//     is an OPT-IN: `stsMailFactor` (`code` or `link`) on the entry, set by
//     the person on /portal/mfa and cleared by an administrator on /admin/mfa.
//     The implicit alternative — anybody with a verified address holds it the
//     moment a realm allows it — would make every such person a second-factor
//     holder at once, and in product mode `secondFactorRefusal()` would then
//     refuse their password at the five password-only doors overnight.
//
//     **HELD MEANS USABLE NOW**: opted in, the realm's authentication policy
//     allows that mechanism as a second factor, the realm can send mail, and
//     the address is VERIFIED. A person whose address changed, or whose realm
//     turned email off, does not hold it — and so is not asked for it, rather
//     than asked for a code that can never arrive. The opt-in itself stays on
//     the entry, so it comes back when the address is verified again.
//
//   * THE SECRETS: a six-digit code or a 32-byte link token, minted here from
//     the operating system's CSPRNG and kept only as a scrypt hash
//     (`crypto.hashSecret()`, the one place this service hashes a secret) on
//     the sign-in step, never on the entry and never in a log.
//
//   * THE FAILURES: NIST SP 800-63B-4 section 3.2.2 — "no more than 100"
//     consecutive failures before the authenticator is disabled. Counted on
//     the entry (`stsMailFactorFailures`), because a count kept on a sign-in
//     step dies with the step and an attacker starts a new one; the limit is
//     the authentication policy's `emailFailureLimit`. At it the opt-in is
//     CLEARED, the person is told (a security notice to the address they
//     proved) and so are their administrators.
//
// IT IS A LIBRARY (rule 3): it registers no route, requires only leaves at
// load, and reaches `mail.ts` — which requires the directory and the
// scheduler — LAZILY.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import crypto = require('./crypto');
import errorCodes = require('./error_codes');
import audit = require('./audit');
import authnPolicy = require('./authn_policy');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

type Kind = 'code' | 'link';

// The mechanism id in the authentication policy for each kind.
const MECHANISM: Record<Kind, string> = {
  code: 'emailCode',
  link: 'emailLink'
};

interface MailFactorDeps {
  log: typeof helpers.log;
  crypto: {
    hashSecretAsync(plaintext: string): Promise<string>;
    verifySecretAsync(plaintext: string, stored: unknown): Promise<boolean>;
  };
  errorCodes: typeof errorCodes;
  audit: { audit(row: Record<string, unknown>): unknown };
  authnPolicy: {
    allows(mechanism: string, role: string): boolean;
    active(mechanism: string, role: string): boolean;
    emailSettings(): { failureLimit: number; ttlS: number;
                       attempts: number; resendS: number; maxSends: number };
  };
  randomInt(min: number, max: number): number;
  randomBytes(size: number): Buffer;
  // The mail channel, asked lazily (see the header).
  mail(): any;
}

/**
 * The emailed second factor as a fact about a person: whether they hold it, the
 * codes and link tokens it sends, and the failures that turn it off.
 *
 * An opt-in on the entry (`stsMailFactor`); held means usable now: opted in,
 * allowed by the realm's authentication policy, mail can be sent and the
 * address is verified.
 */
class MailFactor {
  /**
   * The authentication policy's mechanism for each kind: `emailCode` and
   * `emailLink`.
   */
  static readonly MECHANISM = MECHANISM;
  /**
   * The two kinds of emailed factor: `code` and `link`.
   */
  static readonly KINDS: Kind[] = ['code', 'link'];

  /**
   * Creates the emailed factor.
   *
   * @param deps - its dependencies: the logger, the secret hasher, the
   * error-code table, the audit log, the authentication policy, a CSPRNG and
   * the mail channel
   */
  constructor(private readonly deps: MailFactorDeps) {
    deps.log.debug("Entering MailFactor.constructor().");
    deps.log.debug("Leaving MailFactor.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the dependencies
   */
  static defaultDeps(): MailFactorDeps {
    log.debug("Entering MailFactor.defaultDeps().");
    log.debug("Leaving MailFactor.defaultDeps().");
    return {
      log: log,
      crypto: crypto as unknown as MailFactorDeps['crypto'],
      errorCodes: errorCodes,
      audit: audit,
      authnPolicy: authnPolicy as unknown as MailFactorDeps['authnPolicy'],
      randomInt: function (min: number, max: number): number {
        return crypto.randomInt(min, max);
      },
      randomBytes: function (size: number): Buffer {
        return crypto.randomBytes(size);
      },
      mail: function () {
        return require('./mail');
      }
    };
  }

  /**
   * Tells whether a value is one of the two kinds, `code` or `link`.
   *
   * @param value - the value
   * @returns true when it is
   */
  static isKind(value: unknown): value is Kind {
    log.debug("Entering MailFactor.isKind().");
    log.debug("Leaving MailFactor.isKind().");
    return value === 'code' || value === 'link';
  }

  // -------------------------------------------------------------------------
  // READING THE PERSON.
  // -------------------------------------------------------------------------
  private entryOf(username: string): Record<string, string> | null {
    const { log } = this.deps;
    log.debug("Entering MailFactor.entryOf().");
    let entry = null;
    try {
      const directory = this.deps.mail().directory();
      entry = directory && username
        ? directory.personEntry(String(username)) : null;
    } catch (e) {
      log.debug("Caught in MailFactor.entryOf(): " + ((e && e.message) || e));
      // No mail channel in this process (a test that loaded none): no entry
      // to read, which reads as "holds no emailed factor".
      entry = null;
    }
    if (!entry) {
      log.debug("Leaving MailFactor.entryOf(). None.");
      return null;
    }
    const out = this.valuesOf(entry.attributes || {});
    log.debug("Leaving MailFactor.entryOf().");
    return out;
  }

  // The four values this file reads off a person's attributes (lower-cased
  // names, as the store keeps them). One place, so `entryOf()` and
  // `heldOfAttributes()` read an entry the same way.
  private valuesOf(attrs: Record<string, unknown[]>): Record<string, string> {
    const { log } = this.deps;
    log.debug("Entering MailFactor.valuesOf().");
    const first = function (name: string): string {
      log.debug("Entering first().");
      const values = attrs[name.toLowerCase()] || [];
      log.debug("Leaving first().");
      return values.length ? String(values[0]) : '';
    };
    const out = {
      mail: first('mail').trim(),
      verified: first('stsMailVerified').trim(),
      factor: first('stsMailFactor').trim().toLowerCase(),
      failures: first('stsMailFactorFailures').trim()
    };
    log.debug("Leaving MailFactor.valuesOf().");
    return out;
  }

  // Everything a page or a sign-in asks about one person's emailed factor.
  /**
   * Answers everything a page or a sign-in asks about one person's emailed
   * factor.
   *
   * @param username - the person
   * @returns `{ optedIn, kind, usable, why, verified, address, offered,
   * failures }`, where `why` says what keeps an opted-in factor from being
   * usable
   */
  status(username: string) {
    const { log } = this.deps;
    log.debug("Entering MailFactor.status(). " + username);
    const out = this.statusOfValues(this.entryOf(username));
    log.debug("Leaving MailFactor.status().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE KIND HELD, FROM ATTRIBUTES ALREADY READ (#352, 2026-09-29).
  //
  // `/admin/users` counts who holds a second factor over everybody in the
  // realm, and an emailed factor that is usable is one (`mechanismsFor()`'s
  // `mfaRequired`). Asking `held()` per person was a lookup and a copy of the
  // whole entry each; the directory's credential census hands over the four
  // attributes instead, and this answers from them by the SAME rule
  // `status()` applies — `statusOfValues()` is both.
  //
  // Nobody opted in is answered before the realm's policy is asked, which is
  // the common case and is `status()`'s own first test, so it is the same
  // answer without two policy reads per person. Where this process has no
  // mail channel directory, nobody holds one — `entryOf()`'s answer.
  // ---------------------------------------------------------------------------
  /**
   * Returns the kind of emailed factor held, from a person's attributes.
   *
   * @param attrs - the person's attributes, lower-cased names to values
   * @returns `code`, `link`, or '' when none is usable
   */
  heldOfAttributes(attrs: Record<string, unknown[]>): Kind | '' {
    const { log } = this.deps;
    log.debug("Entering MailFactor.heldOfAttributes().");
    let directory = null;
    try {
      directory = this.deps.mail().directory();
    } catch (e) {
      log.debug("Caught in MailFactor.heldOfAttributes(): " +
                ((e && e.message) || e));
      // No mail channel in this process: `entryOf()` reads nobody then.
      directory = null;
    }
    if (!directory || !attrs) {
      log.debug("Leaving MailFactor.heldOfAttributes(). No directory.");
      return '';
    }
    const values = this.valuesOf(attrs);
    if (!MailFactor.isKind(values.factor)) {
      log.debug("Leaving MailFactor.heldOfAttributes(). Not opted in.");
      return '';
    }
    const s = this.statusOfValues(values);
    log.debug("Leaving MailFactor.heldOfAttributes().");
    return s.usable ? s.kind : '';
  }

  // `status()`'s rule, over values already read. Null is nobody.
  private statusOfValues(entry: Record<string, string> | null) {
    const { log, authnPolicy } = this.deps;
    log.debug("Entering MailFactor.statusOfValues().");
    const kind: Kind | '' = entry && MailFactor.isKind(entry.factor)
      ? entry.factor as Kind : '';
    const verified = !!(entry && entry.mail &&
      entry.verified.toLowerCase() === entry.mail.toLowerCase());
    const offered = {
      code: authnPolicy.active(MECHANISM.code, 'second-factor'),
      link: authnPolicy.active(MECHANISM.link, 'second-factor')
    };
    let why = '';
    if (!kind) {
      why = 'not opted in';
    } else if (!authnPolicy.allows(MECHANISM[kind], 'second-factor')) {
      why = 'this realm\'s authentication policy does not accept an emailed ' +
            kind + ' as a second factor';
    } else if (!offered[kind]) {
      why = 'this realm cannot send mail';
    } else if (!verified) {
      why = 'the address on the account is not verified';
    }
    const out = {
      optedIn: kind,
      kind: kind,
      usable: !!kind && !why,
      why: why,
      verified: verified,
      address: entry ? entry.mail : '',
      offered: offered,
      failures: Number((entry && entry.failures) || 0) || 0
    };
    log.debug("Leaving MailFactor.statusOfValues(). " + (out.usable
      ? 'usable' : why));
    return out;
  }

  // The kind a person HOLDS right now, or ''.
  /**
   * Returns the kind of emailed factor a person holds right now.
   *
   * @param username - the person
   * @returns `code`, `link`, or '' when none is usable
   */
  held(username: string): Kind | '' {
    const { log } = this.deps;
    log.debug("Entering MailFactor.held().");
    const s = this.status(username);
    log.debug("Leaving MailFactor.held().");
    return s.usable ? s.kind : '';
  }

  // A masked address for a page: `j***@example.com`. The person proved they
  // own it; a page naming it in full to whoever typed their account name
  // would be account enumeration with an address attached.
  /**
   * Masks an address for a page, such as `j***@example.com`.
   *
   * @param address - the address
   * @returns the masked address, or `your address` for one without a local part
   */
  masked(address: string): string {
    const { log } = this.deps;
    log.debug("Entering MailFactor.masked().");
    const at = String(address || '').lastIndexOf('@');
    if (at < 1) {
      log.debug("Leaving MailFactor.masked(). Not an address.");
      return 'your address';
    }
    const local = address.slice(0, at);
    log.debug("Leaving MailFactor.masked().");
    return local.charAt(0) + '***' + address.slice(at);
  }

  // -------------------------------------------------------------------------
  // WRITING THE PERSON.
  // -------------------------------------------------------------------------
  private write(username: string, name: string, value: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering MailFactor.write(). " + name);
    let written = false;
    try {
      const directory = this.deps.mail().directory();
      written = !!(directory &&
                   typeof directory.writeMailFlag === 'function' &&
                   directory.writeMailFlag(username, name, value));
    } catch (e) {
      log.debug("Caught in MailFactor.write(): " + ((e && e.message) || e));
      // Reported to the caller as not written, which refuses the act.
      written = false;
    }
    log.debug("Leaving MailFactor.write(). " + written);
    return written;
  }

  // THE OPT-IN, by the person from /portal/mfa. Refused unless it would be
  // USABLE at once: an opt-in the next sign-in could not honour is a setting
  // that lies.
  /**
   * Turns a person's emailed second factor on, from `/portal/mfa`; refused
   * unless it would be usable at once.
   *
   * Audited, and a CAEP credential-change is sent.
   *
   * @param username - the person
   * @param kind - `code` or `link`
   * @param actor - who did it
   * @param via - the surface it came through
   * @returns `{ ok, kind }`, or `{ ok: false, errors }` marked with its code
   * (STS-AUTHN-0247 to STS-AUTHN-0251)
   */
  optIn(username: string, kind: unknown, actor: string, via: string) {
    const { log, errorCodes, audit, authnPolicy } = this.deps;
    log.debug("Entering MailFactor.optIn(). " + username + " " + kind);
    if (!MailFactor.isKind(kind)) {
      log.debug("Leaving MailFactor.optIn(). Not a kind.");
      return errorCodes.mark({ ok: false, errors: ['An emailed second ' +
        'factor is a `code` or a `link`.'] }, 'STS-AUTHN-0247');
    }
    const mechanism = MECHANISM[kind];
    if (!authnPolicy.allows(mechanism, 'second-factor')) {
      log.debug("Leaving MailFactor.optIn(). Not allowed.");
      return errorCodes.mark({ ok: false, errors: ['This realm\'s ' +
        'authentication policy does not accept an emailed ' + kind + ' as a ' +
        'second factor.'] }, 'STS-AUTHN-0248');
    }
    if (!authnPolicy.active(mechanism, 'second-factor')) {
      log.debug("Leaving MailFactor.optIn(). No mail.");
      return errorCodes.mark({ ok: false, errors: ['This realm cannot send ' +
        'mail just now, so an emailed ' + kind + ' could not reach you.'] },
                             'STS-AUTHN-0249');
    }
    const status = this.status(username);
    if (!status.verified) {
      log.debug("Leaving MailFactor.optIn(). Unverified.");
      return errorCodes.mark({ ok: false, errors: ['Your address is not ' +
        'verified. Verify it on the Email page first: a code sent to an ' +
        'address nobody proved they read is a code anybody might read.'] },
                             'STS-AUTHN-0250');
    }
    if (!this.write(username, 'stsMailFactor', kind) ||
        !this.write(username, 'stsMailFactorFailures', '')) {
      log.debug("Leaving MailFactor.optIn(). Not written.");
      return errorCodes.mark({ ok: false, errors: ['Your choice could not ' +
        'be stored. Try again.'] }, 'STS-AUTHN-0251');
    }
    audit.audit({ action: 'authn.mail-factor.change', actor: actor,
      target: username, channel: 'http', protocol: 'Authentication',
      summary: username + ' now receives an emailed ' + kind + ' as a ' +
               'second factor',
      detail: { kind: kind, via: via } });
    // A CREDENTIAL CREATED, or changed from a code to a link (#236).
    this.signalChange(username, status.optedIn
      ? (status.optedIn === kind ? '' : 'update') : 'create',
                      kind, actor, via, '');
    log.debug("Leaving MailFactor.optIn(). Stored.");
    return { ok: true, kind: kind };
  }

  // THE OPT-OUT, by the person or by an administrator — or by this service at
  // the failure limit, when `why` says so.
  /**
   * Turns a person's emailed second factor off: by the person, an
   * administrator, or this service at the failure limit.
   *
   * @param username - the person
   * @param actor - who did it; '' for this service
   * @param via - the surface it came through
   * @param why - the reason, when there is one
   * @returns `{ ok, removed, was }`
   */
  clear(username: string, actor: string, via: string, why?: string) {
    const { log, audit } = this.deps;
    log.debug("Entering MailFactor.clear(). " + username);
    const before = this.status(username).optedIn;
    if (!before) {
      log.debug("Leaving MailFactor.clear(). Nothing held.");
      return { ok: true, removed: false };
    }
    const written = this.write(username, 'stsMailFactor', '') &&
                    this.write(username, 'stsMailFactorFailures', '');
    if (written) {
      audit.audit({ action: 'authn.mail-factor.change', actor: actor,
        target: username, channel: 'http', protocol: 'Authentication',
        summary: username + ' no longer receives an emailed ' + before +
                 ' as a second factor' + (why ? ' (' + why + ')' : ''),
        detail: { kind: '', was: before, via: via, why: why || '' } });
      this.signalChange(username, 'delete', before, actor, via, why || '');
    }
    log.debug("Leaving MailFactor.clear(). " + written);
    return { ok: written, removed: written, was: before };
  }

  // -------------------------------------------------------------------------
  // CAEP `credential-change` FOR THE EMAILED FACTOR (#236, 2026-09-26). This
  // file is the only way the opt-in is written — the portal, the console and
  // `/admin-api`, and the failure limit, all come through `optIn()` and
  // `clear()` — so the event is sent HERE (the #145 rule: at the funnel).
  // The credential type is this service's own URN: CAEP 1.0 section 3.3.1
  // has no value for a code sent to an address (`ssf/account_signals.ts`).
  // Who initiated it is read off the actor: the person themselves, nobody
  // (this service, at the failure limit), or an administrator. `change` ''
  // means nothing changed and nothing is sent. Required LAZILY: Shared
  // Signals' facade is reached at the moment an event is due.
  // -------------------------------------------------------------------------
  private signalChange(username: string, change: string, kind: string,
                       actor: string, via: string, why: string): void {
    const { log } = this.deps;
    log.debug("Entering MailFactor.signalChange(). " + change);
    if (!change) {
      log.debug("Leaving MailFactor.signalChange(). Nothing changed.");
      return;
    }
    const initiating = !actor ? 'system'
      : (actor === username ? 'user' : 'admin');
    const what = 'the emailed ' + kind + ' as a second factor';
    const verb = change === 'create' ? 'turned on'
      : (change === 'update' ? 'changed' : 'turned off');
    try {
      const signals = require('../ssf/account_signals');
      signals.credentialChanged({ username: username,
        credentialType: signals.EMAIL_OTP_CREDENTIAL_TYPE,
        changeType: change, initiatingEntity: initiating,
        friendlyName: 'emailed ' + kind, via: via,
        reasonAdmin: (initiating === 'system' ? 'This service'
          : (initiating === 'user' ? username : 'An administrator')) + ' ' +
          verb + ' ' + what + ' for ' + username + (why ? ' (' + why + ')'
                                                        : '') + '.',
        reasonUser: 'Your emailed second factor was ' + verb +
                    (why ? ': ' + why : '') + '.' });
    } catch (e) {
      log.debug("Caught in MailFactor.signalChange(): " +
                ((e && e.message) || e));
      // No Shared Signals facade in this process: the change is written and
      // audited, which is what matters; there is nobody to tell.
    }
    log.debug("Leaving MailFactor.signalChange().");
  }

  // A success clears the count.
  /**
   * Clears a person's count of consecutive failures after a success.
   *
   * @param username - the person
   */
  noteSuccess(username: string): void {
    const { log } = this.deps;
    log.debug("Entering MailFactor.noteSuccess().");
    if (this.status(username).failures) {
      this.write(username, 'stsMailFactorFailures', '');
    }
    log.debug("Leaving MailFactor.noteSuccess().");
  }

  // A failure counts; at the limit the factor is turned off (see the header).
  // Only a person who HOLDS the factor as a second factor, or used an emailed
  // code as a first, is counted — `username` is always a real account here,
  // never a name somebody typed that has no entry.
  /**
   * Counts a failed emailed code or link on the person's entry; at the
   * authentication policy's limit the factor is turned off (STS-AUTHN-0252), a
   * RISC credential-compromise is sent and the person and administrators are
   * mailed.
   *
   * @param username - the person
   * @returns `{ failures, cleared }`
   */
  noteFailure(username: string): { failures: number; cleared: boolean } {
    const { log, authnPolicy, errorCodes } = this.deps;
    log.debug("Entering MailFactor.noteFailure(). " + username);
    const status = this.status(username);
    const failures = status.failures + 1;
    const limit = authnPolicy.emailSettings().failureLimit;
    if (failures < limit) {
      this.write(username, 'stsMailFactorFailures', String(failures));
      log.debug("Leaving MailFactor.noteFailure(). " + failures + ".");
      return { failures: failures, cleared: false };
    }
    log.warn(errorCodes.tag('STS-AUTHN-0252') + 'authn: ' + failures +
             ' consecutive failed emailed codes or links for "' + username +
             '", the limit of ' + limit + '. Their emailed factor is turned ' +
             'off (NIST SP 800-63B-4 section 3.2.2).');
    this.clear(username, '', 'failure-limit', failures + ' consecutive ' +
               'failures, the limit');
    this.write(username, 'stsMailFactorFailures', '');
    // RISC `credential-compromise` (#231): a hundred wrong codes is somebody
    // other than the person trying to get in. The person is mailed below in
    // words of this factor's own, so the generic notice is not (`mailed`).
    try {
      const signals = require('../ssf/account_signals');
      signals.credentialCompromised({ username: username,
        credentialType: signals.EMAIL_OTP_CREDENTIAL_TYPE,
        initiatingEntity: 'system', mailed: true, via: 'authn',
        reasonAdmin: failures + ' consecutive failed emailed codes or ' +
                     'links for ' + username + ' reached the limit of ' +
                     limit + ', and the factor was turned off.',
        reasonUser: 'Too many wrong codes or links turned your emailed ' +
                    'second factor off.' });
    } catch (e) {
      log.debug("Caught in MailFactor.noteFailure(): " +
                ((e && e.message) || e));
      // No Shared Signals facade in this process: the factor is off, which
      // is the act that matters.
    }
    try {
      const mail = this.deps.mail();
      const when = new Date().toISOString();
      mail.send({ username: username, template: 'credential-compromised',
                  values: { username: username, when: when,
                            what: 'emailed second factor',
                            why: failures + ' wrong codes or links in a row ' +
                                 'turned it off.' },
                  dedupKey: 'mail-factor-limit:' + when.slice(0, 13),
                  via: 'authn' });
      mail.send({ toAdministrators: true, template: 'administrator-alert',
                  values: { username: username, when: when,
                            act: 'turned off the emailed second factor',
                            why: failures + ' consecutive failed codes or ' +
                                 'links reached the limit of ' + limit +
                                 '.' },
                  dedupKey: 'mail-factor-limit:' + username + ':' +
                            when.slice(0, 13),
                  via: 'authn' });
    } catch (e) {
      log.debug("Caught in MailFactor.noteFailure(): " +
                ((e && e.message) || e));
      // The notices are best effort; the factor is already off, which is
      // the act that matters.
    }
    log.debug("Leaving MailFactor.noteFailure(). Cleared.");
    return { failures: failures, cleared: true };
  }

  // -------------------------------------------------------------------------
  // THE SECRETS.
  // -------------------------------------------------------------------------

  // Six digits, uniformly: `randomInt` rejects the bias a modulus would add,
  // and the leading zeros are kept — one code in ten starts with one.
  /**
   * Mints a uniformly random six-digit code, leading zeros kept.
   *
   * @returns the code
   */
  mintCode(): string {
    const { log } = this.deps;
    log.debug("Entering MailFactor.mintCode().");
    const out = String(this.deps.randomInt(0, 1000000)).padStart(6, '0');
    log.debug("Leaving MailFactor.mintCode().");
    return out;
  }

  // 256 bits, base64url: a link token nobody guesses in the life of a step.
  /**
   * Mints a 256-bit link token, base64url.
   *
   * @returns the token
   */
  mintToken(): string {
    const { log } = this.deps;
    log.debug("Entering MailFactor.mintToken().");
    log.debug("Leaving MailFactor.mintToken().");
    return this.deps.randomBytes(32).toString('base64url');
  }

  /**
   * Hashes a code or token with scrypt, for keeping on the sign-in step.
   *
   * @param secret - the code or token
   * @returns a promise of the hash
   */
  hash(secret: string): Promise<string> {
    const { log } = this.deps;
    log.debug("Entering MailFactor.hash().");
    log.debug("Leaving MailFactor.hash().");
    return this.deps.crypto.hashSecretAsync(String(secret));
  }

  // Constant-time by construction: scrypt, then the stored comparison.
  /**
   * Tells whether a code or token matches its stored hash; an unreadable hash
   * matches nothing.
   *
   * @param secret - what was presented
   * @param stored - the stored hash
   * @returns a promise of true when it matches
   */
  matches(secret: string, stored: unknown): Promise<boolean> {
    const { log } = this.deps;
    log.debug("Entering MailFactor.matches().");
    if (!stored || !secret) {
      log.debug("Leaving MailFactor.matches(). Nothing to compare.");
      return Promise.resolve(false);
    }
    log.debug("Leaving MailFactor.matches().");
    return this.deps.crypto.verifySecretAsync(String(secret), stored)
      .catch(function (e) {
        log.debug("Caught in MailFactor.matches(): " +
                  ((e && e.message) || e));
        // An unreadable hash matches nothing.
        return false;
      });
  }

  // What a code a person typed looks like once the spaces and dashes a mail
  // client or a phone added are gone. Anything that is not then six digits
  // is refused before the hash is asked.
  /**
   * Normalises a code a person typed, removing spaces and dashes.
   *
   * @param typed - what was typed
   * @returns the six digits, or '' when it is not six digits
   */
  normalizeCode(typed: unknown): string {
    const { log } = this.deps;
    log.debug("Entering MailFactor.normalizeCode().");
    const out = String(typed || '').replace(/[\s-]/g, '');
    log.debug("Leaving MailFactor.normalizeCode().");
    return /^\d{6}$/.test(out) ? out : '';
  }
}

const slot = new InstanceSlot<MailFactor>(
  'common/mail_factor',
  () => new MailFactor(MailFactor.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The emailed second factor, as a fact about a person: opt-in, usability,
 * secrets and the failure limit.
 *
 * Exports the class and facades forwarding to the instance the composition root
 * built.
 *
 * @namespace
 */
export = {
  MailFactor: MailFactor,
  installInstance: (instance: MailFactor): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  MECHANISM: MailFactor.MECHANISM,
  KINDS: MailFactor.KINDS,
  isKind: MailFactor.isKind,
  status: slot.forward('status'),
  held: slot.forward('held'),
  heldOfAttributes: slot.forward('heldOfAttributes'),
  masked: slot.forward('masked'),
  optIn: slot.forward('optIn'),
  clear: slot.forward('clear'),
  noteSuccess: slot.forward('noteSuccess'),
  noteFailure: slot.forward('noteFailure'),
  mintCode: slot.forward('mintCode'),
  mintToken: slot.forward('mintToken'),
  hash: slot.forward('hash'),
  matches: slot.forward('matches'),
  normalizeCode: slot.forward('normalizeCode')
};
