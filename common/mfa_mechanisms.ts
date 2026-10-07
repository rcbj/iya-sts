// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: mfa_mechanisms.ts
//
// ---------------------------------------------------------------------------
// WHICH SECOND FACTORS A SESSION HAS GIVEN, AND WHICH AN APPLICATION ALLOWS
// (#475, 2026-10-07).
//
// `appMfaMechanism` on an application entry is the list of the second
// factors its people may use — the authentication policy's second-factor
// mechanisms (`common/authn_policy.ts`'s MECHANISMS, the ones that can take
// that role): password, securityKey, totp, recoveryCode, emailCode,
// emailLink, wallet. None listed leaves the realm's policy as it is. It is
// `appAuthnMechanism`'s (#457) companion, and its four rules are rcbj's
// (2026-10-07):
//
//   * **NARROW ONLY.** The list is read beside the realm's authentication
//     policy and never instead of it: a factor the realm has switched off
//     stays off for every application, emailed ones included (NIST SP
//     800-63B-4 section 3.1.3.1).
//   * **OPTIONS ONLY.** It says WHICH second factors, never WHETHER one is
//     needed — that stays the realm's, the account's and risk's.
//   * **A RE-PROMPT, AS #457.** The issuance policy's `mfa-mechanism` rule
//     denies a browser issuance to the application when the session gave a
//     second factor and none of them is allowed, and the doors send the
//     person to sign in again.
//   * **NONE HELD, ENROL ONE.** A person asked for a second factor who holds
//     none the application allows is offered the allowed ones the sign-in
//     can enrol — after proving one they hold, if they hold any, because
//     enrolling for them before that would let anybody who knows the
//     password skip the factor the account has (`authn/CLAUDE.md`).
//
// This module supplies the facts: WHAT THE SESSION GAVE, read off its
// authentication events, and WHAT THE APPLICATION ALLOWS, its entry's values
// as written. **THE DECISION IS NOT HERE** (rcbj, 2026-09-22: every
// authorization decision is XACML policy).
//
// HOW AN EVENT MAPS. Only an event this service recorded (`authority`
// local) with `acr` `mfa` gave a second factor, and the credential that
// answered LAST (`context.credential.kind`) is that factor — every
// second-factor finisher in `authn/authn.ts` names it:
//
//   * `webauthn` → securityKey, when a first factor precedes it (`pwd` or
//     `pop` in the `amr`). A passkey on its own is a FIRST factor (#474) and
//     gives none.
//   * `totp` → totp; `backup-code` → recoveryCode.
//   * `email-code` / `email-link` → emailCode / emailLink.
//   * `password` → password (after a wallet); `wallet` → wallet (after a
//     password).
//
// A federation partner's or a KDC's second factor is theirs, not this
// service's, and gives none here — as `authn_mechanisms.ts` refuses to read
// a partner's `amr` as this service's password.
//
// A LEAF, `authn_mechanisms.ts`'s arrangement: it requires bunyan and nothing
// of this service, so the issuance gate can require it lazily and
// `common/applications.js` can read its ids without a cycle.
// ---------------------------------------------------------------------------

// This module's own logger, for `common/mode.js`'s reason: a leaf cannot
// require the shared one in helpers.js. The level is STS_LOG_LEVEL, then
// CONFIG_FILE's logLevel, then info.
let logLevelProblem: any = null;
const log = require('bunyan').createLogger({
  name: 'sts-mfa-mechanisms',
  level: (function () {
    if (process.env.STS_LOG_LEVEL) {
      return process.env.STS_LOG_LEVEL;
    }
    try {
      return require(process.env.CONFIG_FILE as string).logLevel || 'info';
    } catch (e) {
      logLevelProblem = e;
      return 'info';
    }
  })()
});
if (logLevelProblem) {
  log.debug('No log level from CONFIG_FILE, so info: ' +
            ((logLevelProblem && logLevelProblem.message) || logLevelProblem));
}

// The second-factor mechanisms, in the authentication policy's ids and its
// order. `tests/mfa_mechanism_enforcement.js` holds this list to the
// policy's MECHANISMS, so the two cannot drift.
const IDS = ['password', 'securityKey', 'totp', 'recoveryCode', 'emailCode',
             'emailLink', 'wallet'];

// The credential kind a finisher names → the mechanism. `webauthn` is
// decided in ofEvent(), because a passkey alone is a first factor.
const BY_CREDENTIAL: Record<string, string> = {
  'totp': 'totp',
  'backup-code': 'recoveryCode',
  'email-code': 'emailCode',
  'email-link': 'emailLink',
  'password': 'password',
  'wallet': 'wallet'
};

// The factor names `authn/authn.ts` keeps on a pending second-factor step
// (`factor`, `alternate`, `email`, the recovery code and the password
// after a wallet) → the mechanism.
const BY_STEP_FACTOR: Record<string, string> = {
  'webauthn': 'securityKey',
  'totp': 'totp',
  'backup': 'recoveryCode',
  'email-code': 'emailCode',
  'email-link': 'emailLink',
  'code': 'emailCode',
  'link': 'emailLink',
  'password': 'password',
  'wallet': 'wallet'
};

/**
 * Which second factors a session has given, and which an application entry
 * allows (#475). Facts for the issuance policy, which decides, and for the
 * sign-in screen, which offers.
 */
class MfaMechanisms {
  static readonly IDS: string[] = IDS.slice(0);

  /**
   * The second factor one authentication event gave, if any.
   *
   * @param event - an event as `authn.authenticationEvent()` builds it
   * @returns the mechanism ids, each once (none, or one)
   */
  static ofEvent(event: any): string[] {
    log.debug('Entering MfaMechanisms.ofEvent().');
    const one = event || {};
    if (one.authenticated === false ||
        String((one.authority || {}).kind || '') !== 'local' ||
        String(one.acr || '') !== 'mfa') {
      log.debug('Leaving MfaMechanisms.ofEvent(). No second factor of ' +
                'this service\'s.');
      return [];
    }
    const amr = [].concat(one.amr || []).map(String);
    const credential = String(((one.context || {}).credential || {}).kind ||
                              '');
    let id = BY_CREDENTIAL[credential] || '';
    if (credential === 'webauthn') {
      id = amr.indexOf('pwd') >= 0 || amr.indexOf('pop') >= 0
        ? 'securityKey' : '';
    }
    log.debug('Leaving MfaMechanisms.ofEvent(). ' + (id || 'none'));
    return id ? [id] : [];
  }

  /**
   * The second factors a session has given: the union over its events.
   *
   * @param session - a session as `authn` keeps it, or null
   * @returns the mechanism ids, each once
   */
  static satisfiedBy(session: any): string[] {
    log.debug('Entering MfaMechanisms.satisfiedBy().');
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const out: string[] = [];
    events.forEach(function (event: any) {
      MfaMechanisms.ofEvent(event).forEach(function (id) {
        if (out.indexOf(id) < 0) {
          out.push(id);
        }
      });
    });
    log.debug('Leaving MfaMechanisms.satisfiedBy(). ' +
              (out.join(', ') || 'none'));
    return out;
  }

  /**
   * The second factors an application entry allows, as written: none is
   * whatever the realm allows. A value no mechanism has is kept, so a
   * misspelt list allows nothing rather than everything.
   *
   * @param fields - the entry's fields, or null
   * @returns the mechanism ids, each once
   */
  static allowedOf(fields: any): string[] {
    log.debug('Entering MfaMechanisms.allowedOf().');
    const held = fields ? fields.appMfaMechanism : null;
    const out: string[] = [];
    [].concat(held === undefined || held === null ? [] : held)
      .forEach(function (one: any) {
        const id = String(one).trim();
        if (id && out.indexOf(id) < 0) {
          out.push(id);
        }
      });
    log.debug('Leaving MfaMechanisms.allowedOf(). ' +
              (out.join(', ') || 'whatever the realm allows'));
    return out;
  }

  /**
   * The mechanism a pending step's factor name stands for.
   *
   * @param factor - `webauthn`, `totp`, `backup`, `email-code`, ...
   * @returns the mechanism id, or ''
   */
  static ofStepFactor(factor: unknown): string {
    log.debug('Entering MfaMechanisms.ofStepFactor().');
    const id = BY_STEP_FACTOR[String(factor || '')] || '';
    log.debug('Leaving MfaMechanisms.ofStepFactor(). ' + (id || 'none'));
    return id;
  }

  /**
   * Whether a list allows a pending step's factor: an empty list allows
   * every one.
   *
   * @param allowed - the application's list, from allowedOf()
   * @param factor - a step's factor name
   * @returns true when it may be asked for
   */
  static allowsStepFactor(allowed: string[], factor: unknown): boolean {
    log.debug('Entering MfaMechanisms.allowsStepFactor().');
    const out = !allowed.length ||
      allowed.indexOf(MfaMechanisms.ofStepFactor(factor)) >= 0;
    log.debug('Leaving MfaMechanisms.allowsStepFactor(). ' + out);
    return out;
  }
}

export = MfaMechanisms;
