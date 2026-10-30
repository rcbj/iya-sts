// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authn_mechanisms.ts
//
// ---------------------------------------------------------------------------
// WHICH SIGN-IN MECHANISMS A SESSION HAS SATISFIED, AND WHICH AN APPLICATION
// ALLOWS (#457, 2026-10-06).
//
// The list of the mechanisms an application's people may sign in to it with
// was `appAuthnMechanism` on its entry until #1148, and is since then the
// first-factor list (`stsAuthnPolicyMechanism`) of the NAMED AUTHENTICATION
// POLICY the entry names (`appAuthnPolicy`) — `federation.MECHANISM_IDS`:
// password, password-mfa, webauthn, federation, spnego, wallet — and none
// listed allows every one. `webauthn` names EVERY passkey the person holds
// alike since #1135 (until then, a key enrolled in the `primary` role): a
// key has no role, and this list, over the realm's policy, decides whether
// any key may sign somebody in to this application on its own. Until #457
// it was one value and only ROUTED a sign-in; nothing refused a person
// whose session stood on another mechanism. Now the issuance
// policy decides it at every BROWSER issuance (rcbj: browser-based
// authentication only, both modes, a re-prompt rather than a refusal), and
// this module supplies its two facts:
//
//   * **WHAT THE SESSION SATISFIES**, read off its authentication EVENTS —
//     an event records no mechanism, so it is worked out from what each one
//     does record: who vouched (`authority.kind`: local, federation,
//     kerberos), the RFC 8176 `amr`, the `acr`, and the credential that
//     answered (`context.credential.kind`). Every event of the session counts:
//     a re-prompt APPENDS one, and the session then satisfies what it asked
//     for.
//   * **WHAT THE APPLICATION ALLOWS**: since #1148 the first-factor list of
//     the NAMED AUTHENTICATION POLICY its `appAuthnPolicy` names
//     (`authn_policy.ts`'s `mechanismsFor()`), which replaced its own
//     `appAuthnMechanism`; none named, or `default`, allows every one.
//
// **THE DECISION IS NOT HERE** (rcbj, 2026-09-22: every authorization
// decision is XACML policy). The built-in issuance policy's
// `authn-mechanism` rule compares the two; `common/issuance_gate.js` asks it,
// and the doors re-prompt on its obligation.
//
// HOW EACH EVENT MAPS, and why:
//
//   * `federation` — the authority is a federation partner. The partner's own
//     `amr` rides in the same event and is NOT read as this service's
//     password or key: the partner checked those, this service did not.
//   * `spnego` — the authority is Kerberos (a ticket presented at
//     `/authn/spnego`). Its `pwd` and `hwk` come from the ticket's flags and
//     are the KDC's, for the same reason.
//   * `password` — this service checked a password (`amr` `pwd`).
//   * `password-mfa` — a password and a second factor (`pwd`, `acr` `mfa`).
//   * `webauthn` — the credential that answered was a WebAuthn key. Read off
//     the credential and not off `hwk`, which a hardware-backed WALLET also
//     sets.
//   * `wallet` — a wallet presentation (`amr` `pop`, which only
//     `/authn/wallet` records).
//
// An event this service did not record the authority of (`unrecorded`, a
// session row older than events) satisfies nothing, and neither does an
// emailed first factor, a TLS client certificate or an anonymous session:
// they are not among the mechanisms an application can name, so an
// application that names any is re-prompted for one of those.
//
// A LEAF: it requires bunyan and nothing of this service, so the gate — in
// the parent project's Kerberos COPY closure — can require it LAZILY without
// owing a COPY line, and `authn/authn.ts` and the protocols can require it
// without a cycle.
// ---------------------------------------------------------------------------

// This module's own logger, for `common/mode.js`'s reason: a leaf cannot
// require the shared one in helpers.js. The level is STS_LOG_LEVEL, then
// CONFIG_FILE's logLevel, then info.
let logLevelProblem: any = null;
const log = require('bunyan').createLogger({
  name: 'sts-authn-mechanisms',
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

/**
 * Which sign-in mechanisms a session's authentication events satisfy, and
 * which an application entry allows (#457). Facts for the issuance policy,
 * which decides.
 */
class AuthnMechanisms {
  /**
   * The mechanisms one authentication event satisfies.
   *
   * @param event - an event as `authn.authenticationEvent()` builds it
   * @returns the mechanism ids, each once
   */
  static ofEvent(event: any): string[] {
    log.debug('Entering AuthnMechanisms.ofEvent().');
    const one = event || {};
    if (one.authenticated === false) {
      log.debug('Leaving AuthnMechanisms.ofEvent(). Nobody authenticated.');
      return [];
    }
    const authority = String((one.authority || {}).kind || '');
    if (authority === 'federation') {
      log.debug('Leaving AuthnMechanisms.ofEvent(). federation.');
      return ['federation'];
    }
    if (authority === 'kerberos') {
      log.debug('Leaving AuthnMechanisms.ofEvent(). spnego.');
      return ['spnego'];
    }
    if (authority !== 'local') {
      log.debug('Leaving AuthnMechanisms.ofEvent(). The authority is ' +
                (authority || 'unstated') + '.');
      return [];
    }
    const amr = [].concat(one.amr || []).map(String);
    const credential = String(((one.context || {}).credential || {}).kind ||
                              '');
    const out: string[] = [];
    if (amr.indexOf('pwd') >= 0) {
      out.push('password');
      if (String(one.acr || '') === 'mfa') {
        out.push('password-mfa');
      }
    }
    if (credential === 'webauthn') {
      out.push('webauthn');
    }
    if (amr.indexOf('pop') >= 0) {
      out.push('wallet');
    }
    log.debug('Leaving AuthnMechanisms.ofEvent(). ' +
              (out.join(', ') || 'none'));
    return out;
  }

  /**
   * The mechanisms a session satisfies: the union over its events.
   *
   * @param session - a session as `authn` keeps it, or null
   * @returns the mechanism ids, each once
   */
  static satisfiedBy(session: any): string[] {
    log.debug('Entering AuthnMechanisms.satisfiedBy().');
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    const out: string[] = [];
    events.forEach(function (event: any) {
      AuthnMechanisms.ofEvent(event).forEach(function (id) {
        if (out.indexOf(id) < 0) {
          out.push(id);
        }
      });
    });
    log.debug('Leaving AuthnMechanisms.satisfiedBy(). ' +
              (out.join(', ') || 'none'));
    return out;
  }

  /**
   * The mechanisms a sign-in allows: the first-factor list of the named
   * authentication policy that applies — the one its application's
   * `appAuthnPolicy` names (#1148) or one of the person's groups'
   * `stsAuthnPolicy` names, the lowest precedence winning (#1237). None is
   * every one. A value no mechanism has is kept, so a misspelt list — or a
   * policy that does not exist — allows nothing rather than everything.
   *
   * @param fields - the entry's fields, or null
   * @param person - the person signing in, where known (#1237): the policy
   *   one of their groups names competes with the application's
   * @returns the mechanism ids, each once
   */
  static allowedOf(fields: any, person?: unknown): string[] {
    log.debug('Entering AuthnMechanisms.allowedOf().');
    // Required lazily: the policy is a leaf over the directory slot, and
    // this module is required by its callers before the slot is filled.
    // The person too, once known (#1237): their groups' policies compete
    // with the application's on precedence.
    const held = fields || person
      ? require('./authn_policy').mechanismsFor(fields || null, person)
        .mechanisms
      : null;
    const out: string[] = [];
    [].concat(held === undefined || held === null ? [] : held)
      .forEach(function (one: any) {
        const id = String(one).trim();
        if (id && out.indexOf(id) < 0) {
          out.push(id);
        }
      });
    log.debug('Leaving AuthnMechanisms.allowedOf(). ' +
              (out.join(', ') || 'every one'));
    return out;
  }
}

export = AuthnMechanisms;
