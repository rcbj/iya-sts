'use strict';
//
// File: authn_context.ts
//
// ===========================================================================
// HOW A SESSION AUTHENTICATED, IN THE TWO SAML VOCABULARIES — ONCE.
//
// SAML 2.0 says it with an <AuthnContextClassRef> (saml-authn-context-2.0-os),
// SAML 1.1 with an AuthenticationMethod URI (saml-core-1.1 section 7.1), and
// WS-Federation carries whichever of the two its token type is. Until
// 2026-09-12 the question was answered in FOUR places — `saml2_sso.js`,
// `saml11_sso.js`, `wsfed.js`, and the defaults of the two builders — and all
// four had the same three outcomes: two factors, a security key alone, and
// EVERYTHING ELSE CALLED A PASSWORD.
//
// **"EVERYTHING ELSE" WAS WRONG IN EVERY MODE, AND THAT IS WHY THIS FILE IS
// NOT BEHIND A PREDICATE.** Five kinds of session here never saw a password:
//
//   * a TLS client certificate on the main port — amr ["swk"];
//   * a Kerberos ticket over SPNEGO — `via` "Kerberos v5 (SPNEGO)", with an amr
//     read off the ticket's flags that may be ["pwd"] because the KDC was
//     pre-authenticated with a key derived from one;
//   * a federated sign-in — amr carrying "federated", where the only honest
//     statement is the PARTNER'S;
//   * the unauthenticated session a person chooses at the sign-in screen —
//     `authenticated: false`, amr [];
//   * a session whose amr names nothing at all.
//
// Every one of them produced `PasswordProtectedTransport` / `am:password` —
// an assertion telling a relying party that enforces an authentication
// context that a password was typed when none was. A relying party that
// requires a certificate-based sign-in would refuse the genuine one; one that
// requires a password would accept an anonymous session. That is a fact about
// the assertion rather than about the permissiveness of a mock, so it is fixed
// in both modes.
//
// **AN ORDINARY PASSWORD SIGN-IN PRODUCES EXACTLY WHAT IT ALWAYS DID** —
// `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport` and
// `urn:oasis:names:tc:SAML:1.0:am:password` — and so do the two security-key
// shapes. That is the contract to keep: the parent project's SAML and
// WS-Federation jobs sign in with a password and must not see a byte move.
//
// ---------------------------------------------------------------------------
// WHY THIS DIRECTORY AND NOT common/.
//
// The three files that used to answer this each said they would not share it,
// for the reason that a require from `saml/` into `ws-federation/` would make
// the newer and more widely spoken profile depend on the older and more niche
// one. That reason is about DIRECTION, and it is honoured: this file is in
// `saml/`, both SAML vocabularies are SAML's, and `wsfed.js` already requires
// `saml/saml2.js` and `saml/saml11.js` in exactly this direction. It is not in
// `common/` because nothing outside the three SAML-carrying families speaks
// either vocabulary.
//
// A LIBRARY (rule 3). It registers no route and requires only `helpers.js` for
// the logger, so its position in the require order is not a position.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `AuthnContext` takes its logger through its constructor, the URIs are
// its static constants, and the module still exports `forSession()` and the
// constants from a TRANSITIONAL instance for the six unconverted modules that
// require it.
// ===========================================================================

import helpers = require('../common/helpers');

// What `forSession()` answers.
interface AuthnReading {
  kind: string;
  saml2: string;
  saml11: string;
  multiFactor: boolean;
  hardwareKey: boolean;
}

// The session members this module reads.
interface SessionLike {
  amr?: unknown;
  acr?: string;
  via?: string;
  authenticated?: boolean;
}

interface AuthnContextDeps {
  log: { debug(message: string): void };
}

// --- SAML 2.0 authentication context classes (saml-authn-context-2.0-os) ---
const AC_PREFIX = 'urn:oasis:names:tc:SAML:2.0:ac:classes:';

// --- SAML 1.1 authentication methods (saml-core-1.1 section 7.1) ------------
const AM_PREFIX = 'urn:oasis:names:tc:SAML:1.0:am:';

class AuthnContext {
  static readonly AC_PASSWORD_PROTECTED =
    AC_PREFIX + 'PasswordProtectedTransport';
  static readonly AC_PASSWORD = AC_PREFIX + 'Password';
  static readonly AC_KERBEROS = AC_PREFIX + 'Kerberos';
  // TLSClient and not X509: the X509 class is "the principal authenticated by
  // means of a digital signature where the key was validated as part of an
  // X.509 PKI" at the MESSAGE level, and what the main port verified is the
  // client certificate of the TLS HANDSHAKE, which is exactly what TLSClient
  // names.
  static readonly AC_TLS_CLIENT = AC_PREFIX + 'TLSClient';
  static readonly AC_X509 = AC_PREFIX + 'X509';
  static readonly AC_UNSPECIFIED = AC_PREFIX + 'unspecified';
  // Microsoft's, and used for the reason wsfed.js recorded long before this
  // file: SAML 2.0's own classes have no member that describes a WebAuthn key
  // after a password without overstating a specific mechanism, and
  // `multipleauthn` is exactly the claim — more than one factor — and what
  // AD FS emits for it.
  static readonly AC_MULTIFACTOR =
    'http://schemas.microsoft.com/claims/multipleauthn';

  static readonly AM_PASSWORD = AM_PREFIX + 'password';
  static readonly AM_KERBEROS = 'urn:ietf:rfc:1510';
  // "SSL/TLS Certificate Based Client Authentication" — RFC 2246 by number,
  // which is how section 7.1 spells it.
  static readonly AM_TLS_CLIENT = 'urn:ietf:rfc:2246';
  static readonly AM_X509 = AM_PREFIX + 'X509-PKI';
  static readonly AM_HARDWARE_TOKEN = AM_PREFIX + 'HardwareToken';
  static readonly AM_UNSPECIFIED = AM_PREFIX + 'unspecified';

  // A partner's SAML 2.0 class, said in SAML 1.1 — for a federated session
  // re-asserted over a 1.1 profile. Only the classes with a 1.1 method that
  // means the same thing are listed; anything else becomes `unspecified`,
  // which overstates nothing.
  private static readonly SAML2_TO_SAML11: Readonly<Record<string, string>> = {
    [AuthnContext.AC_PASSWORD_PROTECTED]: AuthnContext.AM_PASSWORD,
    [AuthnContext.AC_PASSWORD]: AuthnContext.AM_PASSWORD,
    [AuthnContext.AC_KERBEROS]: AuthnContext.AM_KERBEROS,
    [AuthnContext.AC_TLS_CLIENT]: AuthnContext.AM_TLS_CLIENT,
    [AuthnContext.AC_X509]: AuthnContext.AM_X509,
    [AuthnContext.AC_MULTIFACTOR]: AuthnContext.AC_MULTIFACTOR
  };

  // And the other way, for a partner that spoke SAML 1.1 or
  // WS-Federation-1.1.
  private static readonly SAML11_TO_SAML2: Readonly<Record<string, string>> = {
    [AuthnContext.AM_PASSWORD]: AuthnContext.AC_PASSWORD_PROTECTED,
    [AuthnContext.AM_KERBEROS]: AuthnContext.AC_KERBEROS,
    [AuthnContext.AM_TLS_CLIENT]: AuthnContext.AC_TLS_CLIENT,
    [AuthnContext.AM_X509]: AuthnContext.AC_X509,
    [AuthnContext.AC_MULTIFACTOR]: AuthnContext.AC_MULTIFACTOR
  };

  constructor(private readonly deps: AuthnContextDeps) {
    deps.log.debug("Entering AuthnContext.constructor().");
    deps.log.debug("Leaving AuthnContext.constructor().");
  }

  // Called several times per reading, so no Entering/Leaving pair — the
  // hot-path exception, stated as it requires.
  private static has(list: string[], value: string): boolean {
    return list.indexOf(value) >= 0;
  }

  private static result(kind: string, saml2: string, saml11: string,
                        multiFactor: boolean,
                        hardwareKey: boolean): AuthnReading {
    return { kind: kind, saml2: saml2, saml11: saml11,
             multiFactor: !!multiFactor, hardwareKey: !!hardwareKey };
  }

  // ---------------------------------------------------------------------------
  // WHAT THIS SERVICE'S OWN SIGN-IN DID, read off the amr, the acr and the
  // door.
  //
  // THE ORDER IS THE RULE, and each step is above the next for a reason:
  //
  //   1. TWO FACTORS first, because a Kerberos ticket that claims both
  //      pre-authentication and hardware, and a password followed by a key or a
  //      one-time code, are all multi-factor whatever door they came through.
  //      `acr === 'mfa'` is the acr this service's own screen and the SPNEGO
  //      sign-in set; it is lower-cased because acr is opaque to everybody but
  //      its minter and this is the one minter.
  //   2. KERBEROS next, BEFORE the password test — a ticket whose KDC was
  //      pre-authenticated reports amr ["pwd"], and calling that
  //      PasswordProtectedTransport would name the wrong protocol.
  //   3. A SECURITY KEY ALONE, which SAML 1.1 has a method for and SAML 2.0
  //      does not (see AC_MULTIFACTOR's note: `unspecified` overstates
  //      nothing).
  //   4. A TLS CLIENT CERTIFICATE (amr "swk").
  //   5. A PASSWORD.
  //   6. NOTHING — which is `unspecified` in both, the one member of either
  //      list that claims no mechanism.
  // ---------------------------------------------------------------------------
  private ownSignIn(amr: string[], acr: string, via: string): AuthnReading {
    const { log } = this.deps;
    const C = AuthnContext;
    log.debug("Entering AuthnContext.ownSignIn(). amr=" + amr.join(',') +
              ", acr=" + acr);
    const hardwareKey = C.has(amr, 'hwk');
    const password = C.has(amr, 'pwd');
    const code = C.has(amr, 'otp');
    const kerberos = /kerberos/i.test(via);
    if ((hardwareKey && password) || (code && password) ||
        String(acr).toLowerCase() === 'mfa') {
      log.debug("Leaving AuthnContext.ownSignIn(). Multi-factor.");
      return C.result('multi-factor', C.AC_MULTIFACTOR, C.AC_MULTIFACTOR,
                      true, hardwareKey);
    }
    if (kerberos) {
      log.debug("Leaving AuthnContext.ownSignIn(). A Kerberos ticket.");
      return C.result('kerberos', C.AC_KERBEROS, C.AM_KERBEROS, false,
                      hardwareKey);
    }
    if (hardwareKey) {
      log.debug("Leaving AuthnContext.ownSignIn(). A security key, and one " +
                "factor.");
      return C.result('hardware-key', C.AC_UNSPECIFIED, C.AM_HARDWARE_TOKEN,
                      false, true);
    }
    if (C.has(amr, 'swk')) {
      log.debug("Leaving AuthnContext.ownSignIn(). A TLS client certificate.");
      return C.result('certificate', C.AC_TLS_CLIENT, C.AM_TLS_CLIENT, false,
                      false);
    }
    if (password) {
      log.debug("Leaving AuthnContext.ownSignIn(). A password.");
      return C.result('password', C.AC_PASSWORD_PROTECTED, C.AM_PASSWORD,
                      false, false);
    }
    log.debug("Leaving AuthnContext.ownSignIn(). Nothing this service can " +
              "name.");
    return C.result('none', C.AC_UNSPECIFIED, C.AM_UNSPECIFIED, false, false);
  }

  // ---------------------------------------------------------------------------
  // WHAT A FEDERATION PARTNER SAID, re-asserted rather than replaced.
  //
  // `federation_sp.js` puts the partner's own authentication context on the
  // session's `acr` and — since 2026-09-12 — the partner's amr beside
  // "federated" rather than instead of it. Three cases:
  //
  //   * the partner's acr is a SAML class or a SAML 1.1 method this file
  //     knows — it is carried in the vocabulary it arrived in, and translated
  //     into the other where the two mean the same thing;
  //   * the partner said nothing SAML-shaped but sent an amr (an OpenID
  //     Provider) — the amr is read exactly as this service's own would be;
  //   * the partner said nothing — `unspecified`. Inventing `pwd` because a
  //     partner probably used a password would put a factor in an assertion
  //     nobody performed, which is `federation_sp.js`'s decision 1.
  // ---------------------------------------------------------------------------
  private federatedSignIn(amr: string[], acr?: string): AuthnReading {
    const { log } = this.deps;
    const C = AuthnContext;
    log.debug("Entering AuthnContext.federatedSignIn(). acr=" +
              (acr || '(none)'));
    const partnerAmr =
        amr.filter(function (value) { return value !== 'federated'; });
    const said = String(acr || '').trim();
    const hwk = C.has(partnerAmr, 'hwk');
    if (said === C.AC_MULTIFACTOR) {
      log.debug("Leaving AuthnContext.federatedSignIn(). The partner said " +
                "multi-factor.");
      return C.result('federated', said, said, true, hwk);
    }
    if (said.indexOf(AC_PREFIX) === 0) {
      log.debug("Leaving AuthnContext.federatedSignIn(). A SAML 2.0 class " +
                "from the partner.");
      return C.result('federated', said,
                      C.SAML2_TO_SAML11[said] || C.AM_UNSPECIFIED, false, hwk);
    }
    if (said.indexOf(AM_PREFIX) === 0 || C.SAML11_TO_SAML2[said]) {
      log.debug("Leaving AuthnContext.federatedSignIn(). A SAML 1.1 method " +
                "from the partner.");
      return C.result('federated',
                      C.SAML11_TO_SAML2[said] || C.AC_UNSPECIFIED, said,
                      false, hwk);
    }
    if (partnerAmr.length || String(said).toLowerCase() === 'mfa') {
      const read = this.ownSignIn(partnerAmr, said, '');
      log.debug("Leaving AuthnContext.federatedSignIn(). The partner's amr, " +
                "read as ours.");
      return C.result('federated', read.saml2, read.saml11, read.multiFactor,
                      read.hardwareKey);
    }
    log.debug("Leaving AuthnContext.federatedSignIn(). The partner said " +
              "nothing.");
    return C.result('federated', C.AC_UNSPECIFIED, C.AM_UNSPECIFIED, false,
                    false);
  }

  // ---------------------------------------------------------------------------
  // THE ONE ENTRY POINT. `{ kind, saml2, saml11, multiFactor, hardwareKey }`.
  //
  // `multiFactor` and `hardwareKey` are what a DEMAND is checked against — a
  // SAML 2.0 RequestedAuthnContext or a WS-Federation `wauth` — so they come
  // from the same reading as the URIs and the two can never disagree about one
  // session.
  // ---------------------------------------------------------------------------
  forSession(session?: SessionLike | null): AuthnReading {
    const { log } = this.deps;
    const C = AuthnContext;
    log.debug("Entering AuthnContext.forSession().");
    if (!session) {
      log.debug("Leaving AuthnContext.forSession(). No session.");
      return C.result('none', C.AC_UNSPECIFIED, C.AM_UNSPECIFIED, false,
                      false);
    }
    const amr = Array.isArray(session.amr) ? session.amr.map(String) : [];
    // THE UNAUTHENTICATED SESSION. Nobody is in it, whatever else is on the
    // record, and an assertion saying a password protected it would be the
    // single most misleading sentence this service could sign.
    if (session.authenticated === false) {
      log.debug("Leaving AuthnContext.forSession(). An unauthenticated " +
                "session.");
      return C.result('none', C.AC_UNSPECIFIED, C.AM_UNSPECIFIED, false,
                      false);
    }
    if (C.has(amr, 'federated')) {
      const federated = this.federatedSignIn(amr, session.acr);
      log.debug("Leaving AuthnContext.forSession(). " + federated.kind + ".");
      return federated;
    }
    const own = this.ownSignIn(amr, session.acr || '', session.via || '');
    log.debug("Leaving AuthnContext.forSession(). " + own.kind + ".");
    return own;
  }
}

// THE TRANSITIONAL INSTANCE — see the header above.
const context = new AuthnContext({ log: helpers.log });

export = {
  AuthnContext: AuthnContext,
  forSession: context.forSession.bind(context) as AuthnContext['forSession'],
  AC_PASSWORD_PROTECTED: AuthnContext.AC_PASSWORD_PROTECTED,
  AC_KERBEROS: AuthnContext.AC_KERBEROS,
  AC_TLS_CLIENT: AuthnContext.AC_TLS_CLIENT,
  AC_UNSPECIFIED: AuthnContext.AC_UNSPECIFIED,
  AC_MULTIFACTOR: AuthnContext.AC_MULTIFACTOR,
  AM_PASSWORD: AuthnContext.AM_PASSWORD,
  AM_KERBEROS: AuthnContext.AM_KERBEROS,
  AM_TLS_CLIENT: AuthnContext.AM_TLS_CLIENT,
  AM_HARDWARE_TOKEN: AuthnContext.AM_HARDWARE_TOKEN,
  AM_UNSPECIFIED: AuthnContext.AM_UNSPECIFIED
};
