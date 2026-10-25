// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: phishing_resistance.ts
//
// ---------------------------------------------------------------------------
// WHETHER AN AUTHENTICATION WAS PHISHING-RESISTANT, AND WHETHER ITS KEY WAS
// HARDWARE-PROTECTED: THE TWO acr VALUES OF OPENID CONNECT EAP ACR VALUES
// 1.0 (Final, 15 June 2025), AS EVIDENCE THIS SERVICE HOLDS (#723,
// 2026-10-19).
//
// Section 2 defines them, and the definitions are the whole test:
//
//   phr   "Phishing-Resistant. An authentication mechanism where a party
//         potentially under the control of the Relying Party cannot gain
//         sufficient information to be able to successfully authenticate to
//         the End User's OpenID Provider as if that party were the End
//         User."
//
//   phrh  "Phishing-Resistant Hardware-Protected. An authentication
//         mechanism meeting the requirements for phishing-resistant
//         authentication above in which additionally information needed to
//         be able to successfully authenticate to the End User's OpenID
//         Provider as if that party were the End User is held in a
//         hardware-protected device or component."
//
// So `phrh` is `phr` and more, and either is a statement about the
// MECHANISM — not about how many factors there were, which is why neither
// sits on `oauth-oidc/step_up.ts`'s ladder of `0` < `1` < `mfa`.
//
// **THIS MODULE ANSWERS FROM EVIDENCE AND CLAIMS NOTHING THE EVENT DOES NOT
// RECORD** — the rule `authn.ts` keeps for `amr` and `acr` ("calling that
// `mfa` because it is phishing-resistant would be the fake this profile
// refuses everywhere else") applied to the two values that ARE about
// phishing resistance. What earns what, from one authentication EVENT as
// `authn.authenticationEvent()` records it:
//
//   * **`phr`, a WebAuthn ASSERTION** (`context.credential.kind` `webauthn`,
//     `ceremony` not `registration`), as a first factor or as the step after
//     a password. The client data names the origin and the signature covers
//     it, and the RP ID scopes the credential, so a page somebody else
//     controls cannot obtain an assertion this service will accept (WebAuthn
//     Level 3 section 7.2 checks both) — section 2's test, met by
//     construction.
//   * **NOT a WebAuthn REGISTRATION made at the sign-in screen**, where a
//     person who proved only a password enrols a key in the same act. EAP
//     section 4: "allowing people to retrieve a phishing-resistant
//     credential using only a phishable shared secret negates much of the
//     value provided by the phishing-resistant credential itself." Whoever
//     phished the password could have enrolled that key; the NEXT sign-in
//     with it is an assertion and earns `phr`.
//   * **`phr`, a TLS client certificate** (`kind` `certificate`): the
//     CertificateVerify signs the handshake transcript, which binds this
//     server's own certificate, so a relaying party can neither replay nor
//     forward it. **Never `phrh`**: nothing this service holds says where the
//     certificate's private key lives.
//   * **`phrh`, a WebAuthn assertion whose key's attestation is TRUSTED and
//     whose BE flag is CLEAR** (`attestationTrusted: true`,
//     `backupEligible: false`). Trusted is `authn/webauthn_attestation.ts`'s
//     word: the statement verified and chains to an anchor — the realm's or
//     the FIDO Metadata Service's — so the model is known rather than
//     claimed. BE clear is a single-device credential (the authenticator
//     data's flags, WebAuthn Level 3 section 6.1): one that is never backed
//     up off the authenticator that made it. A SYNCED passkey
//     (BE set) is copied by its provider and so is not held in a hardware
//     component; an UNATTESTED key (`none`, self, or a chain nothing here
//     anchors) is only the authenticator's say-so. Both earn `phr` and never
//     `phrh`. A flag the ceremony did not report is not clear.
//   * **A federated event carries its partner's word**: an `acr` of `phr` or
//     `phrh` reported by the partner (`authority.kind` `federation`) is that
//     value, which is `step_up.ts`'s exact-acr rule for any partner's class.
//     The partner applied the same definition at its own origin; this
//     service checked nothing it could add to that.
//   * **Nothing else**: a password, a one-time code (TOTP or emailed), an
//     emailed link, a recovery code, a wallet presentation (a cross-device
//     presentation can be relayed by a QR code), a Kerberos ticket over
//     SPNEGO, an anonymous session. `amr` `hwk` is NOT read: a hardware-
//     backed wallet sets it too (`authn_mechanisms.ts`), and it says nothing
//     about the origin.
//
// **A SESSION IS ITS LATEST AUTHENTICATED EVENT**, because that is what the
// session's `acr`, `amr` and `auth_time` already are (authn/CLAUDE.md, rcbj's
// choice): a `prompt=login` answered with a password after a passkey leaves a
// session whose token says `pwd`, and it must not also say `phr`.
//
// **THE DECISION IS NOT HERE.** `step_up.ts` decides whether a session meets
// a request for one of these values; the issuance policy decides whether an
// application may be issued to on it (`urn:sts:xacml:phishing-resistance`,
// which `factOf()` gives a value even when neither was earned). This file
// only says what the evidence earned.
//
// **THE CLASS URIs LIVE HERE TOO (#736), AND NOWHERE ELSE.** SAML's
// RequestedAuthnContext and WS-Federation's `wauth` name the same two
// classes with the URIs OpenID Connect EAP ACR Values 1.0 section 5
// registers (IANA Level of Assurance Profiles):
//
//   phr   http://schemas.openid.net/pape/policies/2007/06/phishing-resistant
//   phrh  http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware
//
// `signInFor()` is the exact-comparison reading, which is SAML's default:
// any listed reference can satisfy. A list of only these URIs forces a key,
// and a list of only the hardware URI must earn `phrh`. A list that also
// names some other class forces nothing here — that other class can answer
// the request. `assertionUri()` is the strongest asked class the session
// earned, or '' so the caller keeps the vocabulary it already asserts.
//
// A LEAF, `authn_mechanisms.ts`'s shape: bunyan and nothing of this service,
// so `common/issuance_gate.js` — in the parent project's Kerberos COPY
// closure — can require it LAZILY on a browser issuance without owing a COPY
// line, and `step_up.ts` and `authn.ts` without a cycle.
// ---------------------------------------------------------------------------

// This module's own logger, for `common/mode.js`'s reason: a leaf cannot
// require the shared one in helpers.js. The level is STS_LOG_LEVEL, then
// CONFIG_FILE's logLevel, then info.
let logLevelProblem: any = null;
const log = require('bunyan').createLogger({
  name: 'sts-phishing-resistance',
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

// The two values, as section 2 spells them.
const PHR = 'phr';
const PHRH = 'phrh';

// The same two classes, as a SAML AuthnContextClassRef or a WS-Federation
// wauth names them (EAP ACR Values 1.0 section 5). URLs stay on one line.
const URI_PHR =
  'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant';
const URI_PHRH =
  'http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware';

// What the XACML fact carries when neither was earned, so a rule can tell
// "not phishing-resistant" from "not asked" — an absent designator is an
// empty bag either way.
const NONE = 'none';

/**
 * The EAP ACR Values 1.0 classes, `phr` and `phrh`, as this service's
 * evidence earns them (#723). Facts for `step_up.ts` and the issuance
 * policy, which decide.
 */
class PhishingResistance {
  /**
   * `phr`: phishing-resistant.
   */
  static readonly PHR = PHR;
  /**
   * `phrh`: phishing-resistant, the key hardware-protected.
   */
  static readonly PHRH = PHRH;
  /**
   * The two values, weaker first.
   */
  static readonly CLASSES = [PHR, PHRH];
  /**
   * What the XACML fact says when neither was earned.
   */
  static readonly NONE = NONE;
  /**
   * The SAML and WS-Federation URI for `phr`.
   */
  static readonly URI_PHR = URI_PHR;
  /**
   * The SAML and WS-Federation URI for `phrh`.
   */
  static readonly URI_PHRH = URI_PHRH;

  /**
   * Tells whether a value is one of the two EAP classes.
   *
   * @param value - an acr value
   * @returns true for `phr` and `phrh`
   */
  static isClass(value: unknown): boolean {
    log.debug('Entering PhishingResistance.isClass().');
    log.debug('Leaving PhishingResistance.isClass().');
    return value === PHR || value === PHRH;
  }

  /**
   * The classes one authentication event earns: [], [`phr`] or [`phr`,
   * `phrh`].
   *
   * @param event - an event as `authn.authenticationEvent()` builds it
   * @returns the classes, weaker first
   */
  static ofEvent(event: any): string[] {
    log.debug('Entering PhishingResistance.ofEvent().');
    const one = event || {};
    if (one.authenticated === false) {
      log.debug('Leaving PhishingResistance.ofEvent(). Nobody ' +
                'authenticated.');
      return [];
    }
    const authority = String((one.authority || {}).kind || '');
    if (authority === 'federation') {
      const said = String(one.acr || '');
      const out = said === PHRH ? [PHR, PHRH] : (said === PHR ? [PHR] : []);
      log.debug('Leaving PhishingResistance.ofEvent(). The partner said ' +
                (said || 'nothing') + '.');
      return out;
    }
    if (authority !== 'local') {
      log.debug('Leaving PhishingResistance.ofEvent(). The authority is ' +
                (authority || 'unstated') + '.');
      return [];
    }
    const credential = (one.context || {}).credential || {};
    const kind = String(credential.kind || '');
    if (kind === 'certificate') {
      log.debug('Leaving PhishingResistance.ofEvent(). A client ' +
                'certificate: phr.');
      return [PHR];
    }
    if (kind !== 'webauthn' || credential.ceremony === 'registration') {
      log.debug('Leaving PhishingResistance.ofEvent(). ' +
                (kind === 'webauthn' ? 'A key enrolled in this act.'
                                     : 'Not an origin-bound ceremony (' +
                                       (kind || 'unstated') + ').'));
      return [];
    }
    const hardware = credential.attestationTrusted === true &&
                     credential.backupEligible === false;
    log.debug('Leaving PhishingResistance.ofEvent(). A WebAuthn assertion: ' +
              (hardware ? 'phrh.' : 'phr.'));
    return hardware ? [PHR, PHRH] : [PHR];
  }

  /**
   * The session's latest authenticated event, or null.
   *
   * @param session - a session as `authn` keeps it, or null
   * @returns the event, or null
   */
  static latestEventOf(session: any): any {
    log.debug('Entering PhishingResistance.latestEventOf().');
    const events = session && Array.isArray(session.events)
      ? session.events : [];
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i] && events[i].authenticated !== false) {
        log.debug('Leaving PhishingResistance.latestEventOf().');
        return events[i];
      }
    }
    log.debug('Leaving PhishingResistance.latestEventOf(). None.');
    return null;
  }

  /**
   * The classes a session earns: its latest authenticated event's.
   *
   * @param session - a session as `authn` keeps it, or null
   * @returns the classes, weaker first
   */
  static ofSession(session: any): string[] {
    log.debug('Entering PhishingResistance.ofSession().');
    const event = PhishingResistance.latestEventOf(session);
    const out = event ? PhishingResistance.ofEvent(event) : [];
    log.debug('Leaving PhishingResistance.ofSession(). ' +
              (out.join(' ') || 'none'));
    return out;
  }

  /**
   * The classes a token's own `acr` states: `phrh` states both.
   *
   * @param acr - the token's `acr`
   * @returns the classes, weaker first
   */
  static ofAcr(acr: unknown): string[] {
    log.debug('Entering PhishingResistance.ofAcr().');
    const said = String(acr === undefined || acr === null ? '' : acr);
    log.debug('Leaving PhishingResistance.ofAcr().');
    return said === PHRH ? [PHR, PHRH] : (said === PHR ? [PHR] : []);
  }

  /**
   * Why a session did not earn `phrh`, in a sentence, for a refusal's
   * description; '' when it did.
   *
   * @param session - a session as `authn` keeps it, or null
   * @returns the reason, or ''
   */
  static hardwareShortfallOf(session: any): string {
    log.debug('Entering PhishingResistance.hardwareShortfallOf().');
    const event = PhishingResistance.latestEventOf(session);
    const credential = ((event || {}).context || {}).credential || {};
    let why = '';
    if (PhishingResistance.ofEvent(event).indexOf(PHRH) >= 0) {
      why = '';
    } else if (String(credential.kind || '') === 'certificate') {
      why = 'the sign-in was a client certificate, and nothing this ' +
            'service holds says its private key is in hardware';
    } else if (String(credential.kind || '') !== 'webauthn') {
      why = 'the sign-in was not a phishing-resistant ceremony';
    } else if (credential.backupEligible !== false) {
      why = credential.backupEligible === true
        ? 'the passkey is backup-eligible (BE set): a synced passkey is ' +
          'copied by its provider, not held in one hardware component'
        : 'the passkey did not report its backup eligibility';
    } else {
      why = 'the passkey\'s attestation is not trusted (none, self, or a ' +
            'chain to no anchor this realm holds), so its hardware is the ' +
            'authenticator\'s say-so';
    }
    log.debug('Leaving PhishingResistance.hardwareShortfallOf().');
    return why;
  }

  /**
   * The XACML fact: the classes earned, or [`none`].
   *
   * @param classes - what `ofEvent()` or `ofSession()` answered
   * @returns a bag that always holds something
   */
  static factOf(classes: string[] | null | undefined): string[] {
    log.debug('Entering PhishingResistance.factOf().');
    const out = (classes || []).filter(PhishingResistance.isClass);
    log.debug('Leaving PhishingResistance.factOf().');
    return out.length ? out : [NONE];
  }

  /**
   * Whether a STORED passkey's recorded evidence can earn `phrh` (#739).
   * The same two facts `ofEvent()` reads off an assertion: the attestation
   * statement is trusted, and backup eligibility was reported clear. A flag
   * that was not recorded is not clear. A registration in the same act is
   * not a stored key, and is not asked here.
   *
   * @param key - a key as `credentials.keysOf()` returns it
   * @returns true when that record can earn `phrh`
   */
  static storedKeyEarnsHardware(key: any): boolean {
    log.debug('Entering PhishingResistance.storedKeyEarnsHardware().');
    const one = key || {};
    const attestation = one.attestation || {};
    const earns = attestation.trusted === true &&
                  one.backupEligible === false;
    log.debug('Leaving PhishingResistance.storedKeyEarnsHardware(). ' +
              earns);
    return earns;
  }

  /**
   * The EAP class a SAML or WS-Federation URI names, or ''.
   *
   * @param uri - an AuthnContextClassRef or a wauth value
   * @returns `phr`, `phrh`, or ''
   */
  static classOfUri(uri: unknown): string {
    log.debug('Entering PhishingResistance.classOfUri().');
    const text = String(uri === undefined || uri === null ? '' : uri).trim();
    const out = text === URI_PHR ? PHR : (text === URI_PHRH ? PHRH : '');
    log.debug('Leaving PhishingResistance.classOfUri(). ' + (out || 'none'));
    return out;
  }

  /**
   * The URI for one EAP class, or '' for anything else.
   *
   * @param cls - `phr` or `phrh`
   * @returns the class URI, or ''
   */
  static uriOfClass(cls: unknown): string {
    log.debug('Entering PhishingResistance.uriOfClass().');
    const out = cls === PHRH ? URI_PHRH : (cls === PHR ? URI_PHR : '');
    log.debug('Leaving PhishingResistance.uriOfClass().');
    return out;
  }

  /**
   * Class URIs from a request field: one string, a repeated parameter, or
   * several separated by whitespace or commas. Empty pieces are dropped.
   *
   * @param value - what the request carried
   * @returns the URIs, in order
   */
  static uriList(value: unknown): string[] {
    log.debug('Entering PhishingResistance.uriList().');
    const raw = Array.isArray(value) ? value : (
      value === undefined || value === null || value === '' ? [] : [value]);
    const out: string[] = [];
    raw.forEach(function (one) {
      String(one === undefined || one === null ? '' : one)
        .split(/[\s,]+/)
        .forEach(function (part) {
          const text = part.trim();
          if (text) {
            out.push(text);
          }
        });
    });
    log.debug('Leaving PhishingResistance.uriList(). ' + out.length);
    return out;
  }

  /**
   * What a list of class URIs requires of the sign-in (#736). Exact
   * comparison: any listed reference can satisfy, so a key is forced only
   * when every reference is one of these two URIs. `phishingClass` is
   * `phrh` only when every one of them is the hardware URI.
   *
   * @param uris - AuthnContextClassRef or wauth values
   * @returns `{ forceKey, phishingClass, eapOnly }`
   */
  static signInFor(uris: unknown): {
    forceKey: boolean, phishingClass: string, eapOnly: boolean
  } {
    log.debug('Entering PhishingResistance.signInFor().');
    const list = PhishingResistance.uriList(uris);
    const classes = list.map(function (one) {
      return PhishingResistance.classOfUri(one);
    });
    const eapOnly = list.length > 0 && classes.every(function (one) {
      return one === PHR || one === PHRH;
    });
    const onlyHardware = eapOnly && classes.every(function (one) {
      return one === PHRH;
    });
    const out = {
      forceKey: eapOnly,
      phishingClass: onlyHardware ? PHRH : '',
      eapOnly: eapOnly
    };
    log.debug('Leaving PhishingResistance.signInFor(). ' +
              (out.eapOnly ? (out.phishingClass || PHR) : 'not eap-only'));
    return out;
  }

  /**
   * Whether a session meets an EAP-only class-URI list. Any other list is
   * not this demand — another class can answer it — and this answers true,
   * including for an empty list. No session meets an EAP-only list.
   *
   * @param session - a session as `authn` keeps it, or null
   * @param uris - the requested class URIs
   * @returns true when the demand is met or there is none
   */
  static eapDemandMet(session: any, uris: unknown): boolean {
    log.debug('Entering PhishingResistance.eapDemandMet().');
    const demand = PhishingResistance.signInFor(uris);
    if (!demand.eapOnly) {
      log.debug('Leaving PhishingResistance.eapDemandMet(). Not an ' +
                'EAP-only list.');
      return true;
    }
    const earned = PhishingResistance.ofSession(session);
    const met = demand.phishingClass === PHRH
      ? earned.indexOf(PHRH) >= 0
      : earned.indexOf(PHR) >= 0;
    log.debug('Leaving PhishingResistance.eapDemandMet(). ' + met);
    return met;
  }

  /**
   * The class URI to put on an assertion when the request named one and
   * the session earned it: `phrh` over `phr`. '' when nothing was asked or
   * nothing earned was asked, so the caller keeps its own class.
   *
   * @param session - a session as `authn` keeps it, or null
   * @param uris - the requested class URIs
   * @returns the URI, or ''
   */
  static assertionUri(session: any, uris: unknown): string {
    log.debug('Entering PhishingResistance.assertionUri().');
    const asked = PhishingResistance.uriList(uris).map(function (one) {
      return PhishingResistance.classOfUri(one);
    });
    const earned = PhishingResistance.ofSession(session);
    let out = '';
    if (asked.indexOf(PHRH) >= 0 && earned.indexOf(PHRH) >= 0) {
      out = URI_PHRH;
    } else if (asked.indexOf(PHR) >= 0 && earned.indexOf(PHR) >= 0) {
      out = URI_PHR;
    }
    log.debug('Leaving PhishingResistance.assertionUri(). ' +
              (out ? 'a class' : 'the caller\'s own'));
    return out;
  }
}

export = PhishingResistance;
