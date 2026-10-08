// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: webauthn_policy.ts
//
// ---------------------------------------------------------------------------
// THE WEBAUTHN CEREMONY'S OPTIONS, AND WHAT THIS SERVICE WILL DO WITH A KEY
// (2026-09-10).
//
// **THIS IS RULE 3: A LIBRARY.** It registers no route, so its position in the
// require order is not a position. It requires `common/config`,
// `common/helpers`, `common/error_codes` and `./webauthn` — the last of which
// requires npm leaves and `common/crypto` — so it cannot join a cycle and
// nothing that requires it moves a route.
//
// ---------------------------------------------------------------------------
// WHY IT IS NOT IN `authn/webauthn.js` NEXT DOOR, WHICH IS THE OBVIOUS PLACE.
//
// That file is deliberately loadable ON ITS OWN. The debugger's
// `tests/webauthn_cross_impl.js` copies it — one file, beside its own scripts —
// and runs it against the same real ceremonies its browser-side implementation
// verifies, because two independent readings of one specification that agree is
// a real result and one implementation agreeing with itself is none. Its own
// header says so, and its `require('../common/helpers')` is inside a try/catch
// for exactly that reason.
//
// A `require('../common/config')` in there would end that. Not loudly: the same
// try/catch would swallow it and the module would go on verifying, with a
// settings function that silently answered defaults in the one place a reader
// would trust it. So the settings live here and the verifier stays a verifier.
//
// ---------------------------------------------------------------------------
// WHY IT IS NOT IN `authn/authn.ts`, WHICH IS THE OTHER OBVIOUS PLACE.
//
// `admin-ui/crypto_metadata.ts` (20a) and `admin-ui/admin.ts` (18) both need
// the report, and `authn/authn.ts` is 8 — requiring it from either would be
// requiring a module that is already loaded, which is harmless, but it would
// also mean the console reaching into the sign-in service for a table of
// algorithms. The rule `/admin/crypto-metadata` is built on is that an
// algorithm table is read FROM THE MODULE THAT PERFORMS THE ALGORITHM; this
// module is the one that decides the ceremony's parameters, so it is the one
// that reports them.
//
// ---------------------------------------------------------------------------
// THREE KINDS OF SETTING AND THE DIFFERENCE MATTERS AT EVERY CALL SITE.
//
//   * **CEREMONY** — handed to the browser in the options and no more. This
//     service cannot make a browser honour any of them.
//   * **CTAP2** — also handed to the browser, and translated by it into what
//     it asks the authenticator for. Same standing: a request, not a check.
//   * **POLICY** — `enabled`, `primaryAllowed`, `mfaAllowed`,
//     `maxKeysPerPerson`. Not WebAuthn at all. These are enforced HERE, by the
//     callers below.
//   * **ATTESTATION** (#105) — `attestationPolicy` and the six settings
//     beside it, read by `attestationSettings()` and enforced by
//     `./webauthn_attestation.ts` on the statement a registration carries:
//     WebAuthn Level 3 section 7.1's steps 21-25, which DO refuse.
//
// **ONE CEREMONY OPTION IS ALSO ENFORCED AND IT IS THE ONE THAT COULD BE.**
// `userVerification: 'required'` is sent to the browser AND checked against the
// UV flag in the authenticator data when the ceremony comes back, because that
// flag is IN the signed bytes — so it is a claim this service can verify rather
// than a preference it can only express. `attestation` (the CONVEYANCE),
// `residentKey` and `authenticatorAttachment` have no equivalent: nothing
// signed says what the browser was asked for, so a check would be a
// comparison against a value this service itself supplied. The attestation
// STATEMENT that comes back is signed, and is what the fourth kind checks.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `WebauthnPolicy` takes `config`, the logger, the verifier's tables
// (`./webauthn`, which stays JavaScript: the parent project copies it) and
// the error codes through its constructor. The two tables stay module-level
// data, and `ALG_IDS` is still filled at load from the verifier's table.
// Since #50's R2 the composition root builds the instance; every old name is
// a FACADE forwarding to it, for `authn.ts`, `admin_views.ts`, the console
// and the tests, and a process without the root builds a default at load.
// `WebauthnPolicy` is exported beside them for that root.
// ---------------------------------------------------------------------------

import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import webauthn = require('./webauthn');
// The error codes. A LEAF that requires nothing, so it cannot close a cycle
// from here. A refusal this module RETURNS carries its code non-enumerably,
// under the Symbol `mark()` uses, so a caller's `errorCodes.codeOf()` reads it
// and nothing that serialises the answer can send it anywhere.
import errorCodes = require('../common/error_codes');
// The mode's reading of `webauthn.attestationPolicy` (#105): its `by-mode`
// default, and `off` refused in product. A leaf: it requires `config` and
// `error_codes`, both already here.
import mode = require('../common/mode');
// THE AUTHENTICATION POLICY (#64): its passkey and security-key rows are
// asked in `roleAllowed()`. A LEAF, so no cycle.
import authnPolicy = require('../common/authn_policy');
// #527: the passkey policy, a leaf, which since 2026-10-08 decides the
// usernameless sign-in and a security key's resident key.
import passkeyPolicy = require('../common/passkey_policy');

// JOSE spelling -> COSE identifier, INVERTED from the verifier's own table
// rather than written out. That table is what decides whether a signature can
// be checked at all, so deriving the offer from it is what stops this service
// asking a browser for an algorithm it would then refuse to verify — a
// credential that enrols perfectly and never works again.
/**
 * JOSE algorithm names mapped to COSE identifiers, inverted from the
 * verifier's own table so the offer cannot name what it cannot verify.
 */
const ALG_IDS = {};
Object.keys(webauthn.COSE_ALGS).forEach(function (id) {
  ALG_IDS[webauthn.COSE_ALGS[id]] = Number(id);
});

// The order the default is written in, used when a caller's list leaves nothing
// usable. It is ES256 then RS256 because those are the two every authenticator
// implements and the two `pubKeyCredParams` was hardcoded to before any of this
// was settable.
const FALLBACK_ALGS = ['ES256', 'RS256'];

// THE POST-QUANTUM ALGORITHMS (2026-10-01): RFC 9964's ML-DSA, what
// `webauthn.pqcOnly` narrows the request to — and what it asks for when the
// list names none of them, because an empty request is refused by the
// browser and a classical one is what the setting says not to send.
/**
 * The post-quantum WebAuthn algorithms, RFC 9964's ML-DSA, in the order
 * `webauthn.pqcOnly` requests them when the list names none.
 */
const PQC_ALGS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

// THE INSECURE ONES (2026-10-01), by name: the verifier's
// `INSECURE_COSE_ALGS` read through its own table, so the two cannot list
// different algorithms. Offered and accepted only where
// `insecureAlgorithmsAllowed()` says.
/**
 * The broken WebAuthn algorithms (SHA-1's RS1), offered and accepted only
 * where `webauthn.insecureAlgorithms` allows them.
 */
const INSECURE_ALGS = webauthn.INSECURE_COSE_ALGS.map(function (id) {
  return webauthn.COSE_ALGS[String(id)];
});

// The attestation statement formats `authn/webauthn_attestation.ts` verifies
// (#105): all eight of WebAuthn Level 3 section 8. Written here rather than
// read from that module because this one is required by it, and a table of
// eight names is data, not behaviour — `tests/webauthn_attestation.js`
// asserts the two agree.
/**
 * The attestation statement formats `authn/webauthn_attestation.ts`
 * verifies: all eight of WebAuthn Level 3 section 8.
 */
const ATTESTATION_FORMATS = ['packed', 'tpm', 'android-key',
                             'android-safetynet', 'fido-u2f', 'none', 'apple',
                             'compound'];

// ---------------------------------------------------------------------------
// WHICH CHECK A CEREMONY FAILED, AS AN ERROR CODE (2026-09-12).
//
// `authn/webauthn.js` names every check it makes and reports the ones that
// failed, in order. It cannot carry a code itself: it is copied, one file, into
// the debugger's cross-implementation test, where `../common/error_codes` does
// not exist. So the mapping from its check NAMES to codes lives here, beside
// the verifier's other policy, and both ceremony doors — the sign-in screen and
// `credentials.confirmKeyEnrolment()` — ask it. The FIRST failed check decides,
// because the verifier lists them in the order a relying party makes them.
//
// A name this table does not know answers the generic code rather than
// nothing, so a check added to the verifier still reaches the log with a code
// — one that says the table is behind.
// ---------------------------------------------------------------------------
const FAILED_CHECK_CODES = {
  'clientData.type is webauthn.create': 'STS-AUTHN-0028',
  'clientData.type is webauthn.get': 'STS-AUTHN-0028',
  'challenge matches': 'STS-AUTHN-0029',
  'origin matches': 'STS-AUTHN-0030',
  'rpIdHash is SHA-256 of the RP ID': 'STS-AUTHN-0031',
  'user presence': 'STS-AUTHN-0032',
  'user verification': 'STS-AUTHN-0033',
  'attested credential data present': 'STS-AUTHN-0034',
  'signature counter advanced': 'STS-AUTHN-0035',
  'signature verifies': 'STS-AUTHN-0036',
  // WebAuthn Level 3 section 7.1's remaining registration checks (#105).
  'credential algorithm was offered': 'STS-AUTHN-0228',
  'credential ID is at most 1023 bytes': 'STS-AUTHN-0229',
  'backup state only where backup eligible': 'STS-AUTHN-0230',
  // An assertion by a key whose algorithm is insecure, with
  // `webauthn.insecureAlgorithms` off (2026-10-01).
  'algorithm is allowed': 'STS-AUTHN-0294'
};

// The `authenticatorSelection` member of the creation options. Its
// `authenticatorAttachment` is absent unless the setting names one — see
// creationOptions().
interface AuthenticatorSelection {
  userVerification: string;
  residentKey: string;
  requireResidentKey: boolean;
  authenticatorAttachment?: string;
}

interface WebauthnPolicyDeps {
  config: typeof config;
  log: typeof helpers.log;
  webauthn: typeof webauthn;
  errorCodes: typeof errorCodes;
  mode: typeof mode;
}

/**
 * The WebAuthn ceremony's options and this service's policy on keys, read
 * from the ambient realm's settings.
 *
 * Ceremony and CTAP2 settings are requests to the browser; the policy
 * settings, user verification and the attestation policy are enforced.
 */
class WebauthnPolicy {
  /**
   * Builds the policy over the dependencies given.
   *
   * @param deps - the settings, logger, verifier, error-code registry and
   * mode
   */
  constructor(private readonly deps: WebauthnPolicyDeps) {
    deps.log.debug("Entering WebauthnPolicy.constructor().");
    deps.log.debug("Leaving WebauthnPolicy.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  /**
   * Returns the dependencies built from the real modules, as the composition
   * root passes them.
   *
   * @returns the default dependency set
   */
  static defaultDeps(): WebauthnPolicyDeps {
    helpers.log.debug("Entering WebauthnPolicy.defaultDeps().");
    helpers.log.debug("Leaving WebauthnPolicy.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      webauthn: webauthn,
      errorCodes: errorCodes,
      mode: mode
    };
  }

  // ---------------------------------------------------------------------------
  // THE SETTINGS, READ IN ONE PLACE.
  //
  // Every one through `config.value()`, which answers out of the AMBIENT REALM
  // — so one realm may demand user verification and require a resident key
  // while another asks for neither, and neither had to be told about the other.
  // That falls out of the realm design rather than being arranged here.
  //
  // Unlike `totp.settings()`, **NOTHING HERE IS COPIED ONTO A CREDENTIAL AND
  // FROZEN**. A TOTP secret is verified with the digits and period the QR code
  // told the app, so changing the setting must not invalidate an existing
  // enrolment. A WebAuthn assertion carries its own algorithm in the
  // credential's stored public key and its own RP ID hash in the signed bytes,
  // so there is nothing for a later setting to contradict — every row below
  // applies to the NEXT ceremony and to every existing key alike.
  // ---------------------------------------------------------------------------
  /**
   * Reads every WebAuthn setting in the ambient realm, each bounded to its
   * legal values.
   *
   * Nothing here is frozen onto a credential; every value applies to the next
   * ceremony and to existing keys alike.
   * @returns the settings: enabled, RP name and id, algorithms, user
   * verification, attestation, timeout, attachment, resident key, credProps
   * and the enrolment policy
   */
  settings() {
    const { config, log } = this.deps;
    log.debug('Entering WebauthnPolicy.settings().');
    const attachment =
      String(config.value('webauthn.authenticatorAttachment') ||
                              'any');
    // ONE READ OF THE PASSKEY POLICY (#527) for the two values it decides.
    const passkeys = passkeyPolicy.read();
    const out = {
      enabled: config.value('webauthn.enabled') !== false,
      rpName: String(config.value('webauthn.rpName') || 'Mock authorization ' +
                                                        'server'),
      rpId: String(config.value('webauthn.rpId') || '').trim(),
      algorithms: this.algorithmsOffered(),
      userVerification: this.oneOf(config.value('webauthn.userVerification'),
                                   ['discouraged', 'preferred', 'required'],
                                   'preferred'),
      attestation: this.oneOf(config.value('webauthn.attestation'),
                         ['none', 'indirect', 'direct', 'enterprise'],
                         'direct'),
      timeoutMs: this.clamp(config.value('webauthn.timeoutMs'), 10000, 600000,
                            60000),
      // `any` is carried as the empty string on the way out, because the
      // options dictionary's absent member and its "no preference" value are
      // the same thing to a browser and there is no third state to represent.
      authenticatorAttachment: this.oneOf(attachment,
                                          ['any', 'platform', 'cross-platform'],
                                          'any'),
      // What a security key (or an enrolment naming no kind) is asked to
      // store: `required` while usernameless sign-in is off, the policy's
      // `securityKeyResidentKey` while it is on (#527, rcbj's answers 1 and
      // 2). It was the setting `webauthn.residentKey`, default discouraged.
      residentKey: passkeyPolicy.securityKeyResidentKey(passkeys),
      credProps: config.value('webauthn.credProps') !== false,
      primaryAllowed: config.value('webauthn.primaryAllowed') !== false,
      // A SIGN-IN WITH NO USERNAME (#474): off unless the realm's passkey
      // policy allows it (#527; it was the setting webauthn.usernameless).
      usernameless: passkeyPolicy.allowsUsernameless(passkeys),
      mfaAllowed: config.value('webauthn.mfaAllowed') !== false,
      // The two algorithm flags (2026-10-01).
      insecureAlgorithms: this.insecureAlgorithmsAllowed(),
      pqcOnly: this.pqcOnly(),
      maxKeysPerPerson: this.clamp(config.value('webauthn.maxKeysPerPerson'), 1,
                                   50,
                                   10)
    };
    log.debug('Leaving WebauthnPolicy.settings(). uv=' + out.userVerification +
              ', ' + out.algorithms.length + ' algorithm(s).');
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE ATTESTATION POLICY (#105), read in the same one place as the rest.
  //
  // `policy` is what is IN FORCE: `webauthn.attestationPolicy` through
  // `mode.valueInForce()` (product reads a stored `off` as `by-mode`), and
  // `by-mode` resolved by `mode.acceptsUnverifiedAttestation()` — `off` in
  // development, `verify-if-present` in product. `demandsTrust` is whether
  // ANY setting needs a statement that chains to an anchor: the policy
  // `require-trusted`, an AAGUID allow-list, a certification level or FIPS —
  // each of which is a claim about the authenticator that only a trusted
  // statement can make. A demand for trust verifies whatever the policy
  // says, and asks the browser for `direct` attestation (creationOptions()).
  // ---------------------------------------------------------------------------
  /**
   * Reads the attestation policy in force (#105).
   *
   * `by-mode` resolves to `off` in development and `verify-if-present` in
   * product. `demandsTrust` is true when any setting needs a statement that
   * chains to a trust anchor.
   * @returns the configured and effective policy, the trust anchors, the
   * AAGUID allow-list, certification level, FIPS and Android settings, and
   * `demandsTrust`
   */
  attestationSettings() {
    const { config, log, mode } = this.deps;
    log.debug('Entering WebauthnPolicy.attestationSettings().');
    const configured = this.oneOf(
      mode.valueInForce('webauthn.attestationPolicy'),
      ['by-mode', 'off', 'verify-if-present', 'require-trusted'], 'by-mode');
    const policy = configured === 'by-mode'
      ? (mode.acceptsUnverifiedAttestation() ? 'off' : 'verify-if-present')
      : configured;
    const asked = config.value('webauthn.attestationAllowedAaguids');
    const allowedAaguids = (Array.isArray(asked) ? asked
                                                 : String(asked || '')
                                                     .split(','))
      .map(function (one) {
        return String(one || '').trim().toLowerCase().replace(/-/g, '');
      })
      .filter(function (one) { return /^[0-9a-f]{32}$/.test(one); });
    const minCertificationLevel = this.oneOf(
      config.value('webauthn.attestationMinCertificationLevel'),
      ['none', 'L1', 'L1plus', 'L2', 'L2plus', 'L3', 'L3plus'], 'none');
    const requireFips = config.value('webauthn.attestationRequireFips') ===
                        true;
    const out = {
      configured: configured,
      policy: policy,
      trustAnchorsPem: String(config.value('webauthn.attestationTrustAnchors')
                              || ''),
      allowedAaguids: allowedAaguids,
      minCertificationLevel: minCertificationLevel,
      requireFips: requireFips,
      allowSafetynet: config.value('webauthn.attestationAllowSafetynet') ===
                      true,
      androidSoftwareKeys:
        config.value('webauthn.attestationAndroidSoftwareKeys') === true,
      demandsTrust: policy === 'require-trusted' ||
                    allowedAaguids.length > 0 ||
                    minCertificationLevel !== 'none' || requireFips
    };
    log.debug('Leaving WebauthnPolicy.attestationSettings(). policy=' +
              out.policy + ', demandsTrust=' + out.demandsTrust);
    return out;
  }

  private oneOf(value, allowed, dflt) {
    const { log } = this.deps;
    log.debug("Entering WebauthnPolicy.oneOf().");
    const wanted = String(value == null ? '' : value);
    log.debug("Leaving WebauthnPolicy.oneOf().");
    return allowed.indexOf(wanted) >= 0 ? wanted : dflt;
  }

  private clamp(value, low, high, dflt) {
    const { log } = this.deps;
    log.debug("Entering WebauthnPolicy.clamp().");
    const n = Number(value);
    if (!Number.isFinite(n)) {
      log.debug("Leaving WebauthnPolicy.clamp().");
      return dflt;
    }
    log.debug("Leaving WebauthnPolicy.clamp().");
    return Math.max(low, Math.min(high, n));
  }

  // The offered algorithms, as JOSE names, filtered against what the verifier
  // can actually check. A name outside that table is DROPPED WITH A WARNING
  // rather than passed through: `pubKeyCredParams` naming an algorithm this
  // service cannot verify produces a credential that registers, is stored, and
  // then fails every assertion it is ever used for — with the failure landing
  // at sign-in rather than at enrolment, which is the worst possible place for
  // it.
  /**
   * Returns the algorithms to offer, as JOSE names, keeping only those the
   * verifier can check.
   *
   * A name it cannot verify is dropped with a warning; when nothing usable
   * is left it falls back to ES256 and RS256.
   * @returns the algorithm names
   */
  algorithmsOffered() {
    const { config, log } = this.deps;
    log.debug('Entering WebauthnPolicy.algorithmsOffered().');
    const asked = config.value('webauthn.algorithms');
    const list = (Array.isArray(asked) ? asked : String(asked || '').split(','))
      .map(function (name) { return String(name || '').trim(); })
      .filter(Boolean);
    const insecureAllowed = this.insecureAlgorithmsAllowed();
    const pqcOnly = this.pqcOnly();
    let kept = [];
    list.forEach(function (name) {
      if (ALG_IDS[name] === undefined) {
        log.warn('webauthn: "' + name + '" is not an algorithm this service ' +
                 'can verify, so it is NOT being offered to browsers. The ' +
                 'ones it knows ' +
                 'are ' + Object.keys(ALG_IDS).join(', ') + '. Offering ' +
                 'one it cannot check would enrol a credential that never ' +
                 'works again.');
        return;
      }
      // AN INSECURE ONE ONLY WHERE THE REALM ALLOWS IT (2026-10-01): named in
      // the list or not, it is dropped while `webauthn.insecureAlgorithms`
      // is off (or the service is in product mode, which ignores it).
      if (INSECURE_ALGS.indexOf(name) >= 0 && !insecureAllowed) {
        log.debug('webauthn: ' + name + ' is insecure and ' +
                  'webauthn.insecureAlgorithms is off; not offered.');
        return;
      }
      if (kept.indexOf(name) < 0) {
        kept.push(name);
      }
    });
    // ON, THE INSECURE ONES ARE REQUESTED TOO, last: the flag says to use
    // them, and an authenticator takes the first algorithm it supports, so
    // at the end they are asked for only from one that supports nothing
    // better.
    if (insecureAllowed) {
      INSECURE_ALGS.forEach(function (name) {
        if (kept.indexOf(name) < 0) {
          kept.push(name);
        }
      });
    }
    // POST-QUANTUM ONLY (2026-10-01): the request narrowed to ML-DSA, and
    // all three where the list names none. It narrows what is REQUESTED,
    // and so what may be registered (section 7.1's offered-algorithm
    // check); a classical key already enrolled goes on signing in.
    if (pqcOnly) {
      kept = kept.filter(function (name) {
        return PQC_ALGS.indexOf(name) >= 0;
      });
      if (!kept.length) {
        log.debug('Leaving WebauthnPolicy.algorithmsOffered(). PQC only, ' +
                  'and the list names no ML-DSA: all three.');
        return PQC_ALGS.slice();
      }
    }
    if (!kept.length) {
      // NOT an empty list. `pubKeyCredParams: []` is a registration the browser
      // refuses outright, with an error the ceremony reports as one of its
      // several indistinguishable failures — so a typo in one setting would
      // look like a broken authenticator. The default is the safe answer and
      // the warning is how somebody finds out.
      log.warn('webauthn: webauthn.algorithms named nothing this service can ' +
               'verify, so the ceremony is offering ' +
               FALLBACK_ALGS.join(' and ') +
               ' instead. An empty pubKeyCredParams is refused by the ' +
               'browser and would look like a hardware failure.');
      log.debug('Leaving WebauthnPolicy.algorithmsOffered(). Fell back.');
      return FALLBACK_ALGS.slice();
    }
    log.debug('Leaving WebauthnPolicy.algorithmsOffered(). ' + kept.length +
              ' offered.');
    return kept;
  }

  // ---------------------------------------------------------------------------
  // THE TWO ALGORITHM FLAGS (2026-10-01, rcbj), PER REALM like every runtime
  // setting (`config.value()` reads the ambient realm's override first).
  //
  // `webauthn.insecureAlgorithms`, off by default: the broken algorithms
  // (SHA-1's RS1) are offered and accepted. DEVELOPMENT ONLY, the row's
  // `onlyWhile: 'usesBrokenAlgorithms'` — product cannot set it, and a value
  // that reached it anyway is ignored here, because product never uses a
  // broken algorithm (`mode.usesBrokenAlgorithms()`).
  //
  // `webauthn.pqcOnly`, off by default: only ML-DSA is requested.
  // ---------------------------------------------------------------------------
  /**
   * Tells whether this realm offers and accepts the insecure WebAuthn
   * algorithms (RS1): `webauthn.insecureAlgorithms`, in development mode
   * only.
   *
   * @returns true when they are allowed
   */
  insecureAlgorithmsAllowed(): boolean {
    const { config, log, mode } = this.deps;
    log.debug('Entering WebauthnPolicy.insecureAlgorithmsAllowed().');
    const allowed = config.value('webauthn.insecureAlgorithms') === true &&
                    mode.usesBrokenAlgorithms();
    log.debug('Leaving WebauthnPolicy.insecureAlgorithmsAllowed(). ' +
              allowed);
    return allowed;
  }

  /**
   * Tells whether this realm requests only the post-quantum algorithms
   * (ML-DSA): `webauthn.pqcOnly`.
   *
   * @returns true when it does
   */
  pqcOnly(): boolean {
    const { config, log } = this.deps;
    log.debug('Entering WebauthnPolicy.pqcOnly().');
    const only = config.value('webauthn.pqcOnly') === true;
    log.debug('Leaving WebauthnPolicy.pqcOnly(). ' + only);
    return only;
  }

  // The COSE identifiers for `pubKeyCredParams`, in the order the names were
  // given. Separate from `algorithms` above because the page wants the names
  // and the ceremony wants the numbers, and computing either from the other at
  // two call sites is how the two come to disagree.
  /**
   * Returns the offered algorithms as COSE identifiers for
   * `pubKeyCredParams`, in the same order.
   *
   * @returns the COSE algorithm identifiers
   */
  algorithmIds() {
    const { log } = this.deps;
    log.debug("Entering WebauthnPolicy.algorithmIds().");
    log.debug("Leaving WebauthnPolicy.algorithmIds().");
    return this.algorithmsOffered()
      .map(function (name) { return ALG_IDS[name]; });
  }

  // Is the mechanism offered at all? Read at every door rather than only on the
  // page that draws the button, for the reason `authn.ts` gives about
  // `authn.unauthenticatedSessions` and `totp.js` repeats: a page is markup and
  // an endpoint is a door, and a form posted by hand while the setting is off
  // must not enrol anybody.
  /**
   * Tells whether WebAuthn is offered in this realm at all.
   *
   * @returns the `webauthn.enabled` setting
   */
  offered() {
    const { log } = this.deps;
    log.debug("Entering WebauthnPolicy.offered().");
    log.debug("Leaving WebauthnPolicy.offered().");
    return this.settings().enabled;
  }

  // May a key be enrolled in this role? ONE function for both roles rather than
  // two predicates, so that a caller cannot check the wrong one — `roleAllowed`
  // takes the role it is about to write, which is the same string
  // `credentials.addKey()` will be handed.
  //
  // **IT ANSWERS ABOUT ENROLMENT AND NEVER ABOUT AUTHENTICATION.** A key
  // already enrolled in a role that has since been turned off goes on working,
  // for `webauthn.enabled`'s reason: an account configured for two factors is
  // still configured for two, and a setting that silently downgraded it would
  // be a security control whose off switch does something other than what it
  // says. Worse for `primary`, where the person's ONLY credential would be the
  // one being switched off — an operator moving a knob must not be able to lock
  // somebody out of their own account.
  /**
   * Decides whether a new key may be enrolled in a role, or used as a first
   * factor.
   *
   * Answers about enrolment only: a key already enrolled in a role since
   * switched off goes on working. Asks the realm's authentication policy
   * after this module's own settings.
   * @param role - `primary` or `mfa`
   * @returns `{ ok: true }`, or `{ ok: false, why }` carrying an error code
   */
  roleAllowed(role) {
    const { log, errorCodes } = this.deps;
    log.debug('Entering WebauthnPolicy.roleAllowed(). role=' + role);
    const live = this.settings();
    if (!live.enabled) {
      log.debug('Leaving WebauthnPolicy.roleAllowed(). WebAuthn is not ' +
                'offered here.');
      return errorCodes.mark({ ok: false,
               why: 'Security keys are switched off in this realm ' +
                    '(webauthn.enabled). A key already enrolled goes on ' +
                    'working; no new one can be enrolled.' }, 'STS-AUTHN-0044');
    }
    if (String(role) === 'primary' && !live.primaryAllowed) {
      log.debug('Leaving WebauthnPolicy.roleAllowed(). Primary keys are not ' +
                'allowed here.');
      return errorCodes.mark({ ok: false,
               why: 'A security key cannot be the only credential on an ' +
                    'account in this realm (webauthn.primaryAllowed). Enrol ' +
                    'it as a second factor beside a password ' +
                    'instead.' }, 'STS-AUTHN-0045');
    }
    if (String(role) === 'mfa' && !live.mfaAllowed) {
      log.debug('Leaving WebauthnPolicy.roleAllowed(). Second-factor keys ' +
                'are not allowed here.');
      return errorCodes.mark({ ok: false,
               why: 'A security key cannot be a second factor in this realm ' +
                    '(webauthn.mfaAllowed). An authenticator app is the ' +
                    'other one, where the authentication policy allows ' +
                    'it.' }, 'STS-AUTHN-0046');
    }
    // THE AUTHENTICATION POLICY'S TWO ROWS (#64), asked after this module's
    // own settings and with the same contract: a key already enrolled goes
    // on being asked for as a second factor, and what the row stops is a
    // NEW one, or — as a first factor — signing in with one at all.
    const policyRow: { mechanism: string;
                       as: 'primary' | 'second-factor';
                       code: string } = String(role) === 'primary'
      ? { mechanism: 'passkey', as: 'primary', code: 'STS-AUTHN-0253' }
      : { mechanism: 'securityKey', as: 'second-factor',
          code: 'STS-AUTHN-0254' };
    if (!authnPolicy.allows(policyRow.mechanism, policyRow.as)) {
      log.debug('Leaving WebauthnPolicy.roleAllowed(). The authentication ' +
                'policy does not accept it.');
      return errorCodes.mark({ ok: false,
               why: String(role) === 'primary'
                 ? 'This realm\'s authentication policy does not accept a ' +
                   'security key or passkey as a first factor. Sign in with ' +
                   'what it does accept.'
                 : 'This realm\'s authentication policy does not accept a ' +
                   'NEW security key as a second factor. A key already ' +
                   'enrolled goes on working.' }, policyRow.code);
    }
    log.debug('Leaving WebauthnPolicy.roleAllowed(). Allowed.');
    return { ok: true };
  }

  /**
   * Maps a failed ceremony to the error code of its first failed check.
   *
   * @param verdict - the result of `verifyRegistration()` or
   * `verifyAssertion()`
   * @returns the check's code, or the generic code when none is known
   */
  failureCodeFor(verdict) {
    const { log } = this.deps;
    log.debug("Entering WebauthnPolicy.failureCodeFor().");
    const failed = (verdict && Array.isArray(verdict.failed)) ? verdict.failed :
                    [];
    for (let i = 0; i < failed.length; i++) {
      if (FAILED_CHECK_CODES[failed[i]]) {
        log.debug("Leaving WebauthnPolicy.failureCodeFor().");
        return FAILED_CHECK_CODES[failed[i]];
      }
    }
    log.debug("Leaving WebauthnPolicy.failureCodeFor().");
    return 'STS-AUTHN-0037';
  }

  // ---------------------------------------------------------------------------
  // THE OPTIONS, AS THE BROWSER RECEIVES THEM.
  //
  // Built here and handed to the page as ONE JSON object on a data attribute,
  // rather than as eleven attributes the script picks apart. Two reasons, and
  // the second is the load-bearing one:
  //
  //   * The script is a STATIC RESOURCE (`/authn/webauthn.js`), served under
  //     `script-src 'self'` — see `app.js` and the six-scripted-pages rule. It
  //     cannot be generated per request, so everything that varies has to
  //     travel as data.
  //   * **A DICTIONARY THE SERVER BUILT IS ONE PLACE TO GET IT WRONG.** Eleven
  //     attributes read one at a time is eleven chances for the script to
  //     coerce a value differently from the way this file meant it — `"false"`
  //     being truthy is the classic — and none of them would fail loudly. What
  //     the script does now is `JSON.parse` and pass it on.
  //
  // **NOTHING SECRET IS IN IT AND NOTHING IN IT IS TRUSTED ON THE WAY BACK.**
  // The options are a REQUEST to the browser; every security property of the
  // ceremony is checked against the pending step and the origin when the result
  // arrives — see `verifyRegistration()` and `verifyAssertion()`. A person who
  // edits this attribute in the developer tools changes what their own browser
  // is asked for and nothing about what this service will accept.
  // ---------------------------------------------------------------------------
  // `kind` is which of `/portal/keys`' two calls to action the PERSON pressed
  // (#470, 2026-10-06; it was a three-way radio from 2026-09-26): `passkey`
  // ("Create a passkey") or `security-key` ("Use a security key"), the two
  // `authenticatorKinds()` offers.
  //
  //   * `passkey` REQUIRES a discoverable credential (#474, rcbj's decision:
  //     a passkey is one that can be found without a username, so one that
  //     cannot is not made under that name) and HINTS `client-device` then
  //     `hybrid`
  //     (WebAuthn Level 3 section 5.4.8) — and sends NO attachment, which is
  //     the lesson of 2026-09-26: a hard `platform` refused outright on a
  //     browser with nothing built in (Linux Firefox), where a hint lets the
  //     browser offer a phone instead. `discouraged` is what made Chrome and
  //     Edge offer a security key or a phone and never the device itself.
  //   * `security-key` asks for `cross-platform` and hints `security-key`;
  //     its resident key is the passkey policy's (#527): `required` while
  //     usernameless sign-in is off, so both buttons make a discoverable
  //     credential (a tester found one key giving two results by button),
  //     and `securityKeyResidentKey` (default `required`) while it is on.
  //
  // A kind narrows nothing beyond the hint while
  // `webauthn.authenticatorAttachment` names one: that setting is the realm's
  // filter, and `authenticatorKinds()` then offers only the button it allows.
  // No `kind`, and the sign-in screen's ceremony, is the request as it always
  // was, with no hint.
  /**
   * Builds the registration options the browser receives.
   *
   * A `kind` adds hints, prefers a discoverable credential for a passkey and
   * asks a security key for `cross-platform`, the last only while the
   * attachment setting is `any`. A policy that demands a trusted statement
   * asks for `direct` attestation.
   * @param rpId - the relying party id
   * @param kind - `passkey` or `security-key`, as the person chose, if any
   * @returns the options: RP, algorithms, attestation, timeout,
   * authenticator selection, hints and credProps
   */
  creationOptions(rpId, kind?) {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.creationOptions(). rpId=' + rpId);
    const live = this.settings();
    const wanted = String(kind || '');
    const asked = live.authenticatorAttachment === 'any' &&
                  wanted === 'security-key' ? 'cross-platform' : '';
    const residentKey = wanted === 'passkey' ? 'required' : live.residentKey;
    const hints = wanted === 'passkey' ? ['client-device', 'hybrid']
      : (wanted === 'security-key' ? ['security-key'] : []);
    // A POLICY THAT NEEDS A STATEMENT ASKS FOR ONE (#105). `none` and
    // `indirect` let the browser strip or anonymise the statement, and a
    // realm that requires a trusted one would then refuse every enrolment
    // for a reason nobody could see on this page. `enterprise` is kept: it
    // asks for more, not less.
    const attestation = this.attestationSettings().demandsTrust &&
                        live.attestation !== 'enterprise'
      ? 'direct' : live.attestation;
    const out = {
      rp: { name: live.rpName, id: rpId },
      algorithms: this.algorithmIds(),
      attestation: attestation,
      timeout: live.timeoutMs,
      authenticatorSelection: <AuthenticatorSelection>{
        userVerification: live.userVerification,
        residentKey: residentKey,
        // WebAuthn Level 3 keeps `requireResidentKey` for Level 1 clients and
        // says it MUST be true exactly when `residentKey` is `required`. Sent
        // rather than omitted, because the browsers that still read it are the
        // ones that would otherwise ignore the modern member entirely.
        requireResidentKey: residentKey === 'required'
      },
      credProps: live.credProps,
      hints: hints
    };
    // ABSENT AND NOT `"any"`. The options dictionary has no value meaning "no
    // preference" — the member is simply not there — and sending the string
    // `"any"` is a validation error in the browser rather than a wide filter.
    if (live.authenticatorAttachment !== 'any') {
      out.authenticatorSelection.authenticatorAttachment =
          live.authenticatorAttachment;
    } else if (asked) {
      out.authenticatorSelection.authenticatorAttachment = asked;
    }
    log.debug('Leaving WebauthnPolicy.creationOptions(). attestation=' +
              out.attestation);
    return out;
  }

  // WHICH OF THE TWO CALLS TO ACTION `/portal/keys` DRAWS (#470): "Create a
  // passkey" and "Use a security key" while `webauthn.authenticatorAttachment`
  // is `any`; only the passkey button while it is `platform`, and only the
  // security key's while it is `cross-platform` — so the page offers no
  // button the ceremony would contradict.
  /**
   * Lists the kinds of passkey a person may create on `/portal/keys`, as the
   * attachment setting allows.
   *
   * @returns `passkey`, `security-key` or both
   */
  authenticatorKinds() {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.authenticatorKinds().');
    const attachment = this.settings().authenticatorAttachment;
    const out = attachment === 'platform' ? ['passkey']
      : (attachment === 'cross-platform' ? ['security-key']
                                         : ['passkey', 'security-key']);
    log.debug('Leaving WebauthnPolicy.authenticatorKinds(). ' +
              out.join(','));
    return out;
  }

  /**
   * Builds the authentication options the browser receives.
   *
   * @param rpId - the relying party id
   * @returns the RP id, the user verification requirement and the timeout
   */
  requestOptions(rpId) {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.requestOptions(). rpId=' + rpId);
    const live = this.settings();
    const out = {
      rpId: rpId,
      userVerification: live.userVerification,
      timeout: live.timeoutMs
    };
    log.debug('Leaving WebauthnPolicy.requestOptions(). uv=' +
              out.userVerification);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE USERNAMELESS SIGN-IN (#474): a passkey the browser finds by itself —
  // a discoverable credential, `allowCredentials` empty — from the button on
  // the sign-in screen or the username field's autofill.
  //
  // **OFFERED ONLY WHERE A PRIMARY KEY IS**: `webauthn.enabled`,
  // `webauthn.primaryAllowed` and the passkey policy's `allowUsernameless`
  // (#527; it was `webauthn.usernameless`), which is OFF by default.
  // **USER VERIFICATION IS REQUIRED AND CHECKED**, whatever
  // `webauthn.userVerification` says (rcbj's decision): the sign-in is then
  // a key the person possesses and a PIN or biometric that verified them on
  // it, two factors on one device, recorded `amr ["hwk","user"]` and `acr
  // "mfa"`. Without the flag it would be possession alone of a credential
  // that names its own account, which no setting should be able to allow.
  // ---------------------------------------------------------------------------
  /**
   * Says whether a usernameless passkey sign-in is offered in this realm.
   *
   * @returns `{ ok: true }`, or `{ ok: false, why }` naming the setting
   */
  usernamelessOffered() {
    const { log, errorCodes } = this.deps;
    log.debug("Entering WebauthnPolicy.usernamelessOffered().");
    const live = this.settings();
    const why = !live.enabled
      ? 'Passkeys are switched off in this realm (webauthn.enabled).'
      : (!live.primaryAllowed
        ? 'A passkey may not sign anybody in on its own in this realm ' +
          '(webauthn.primaryAllowed).'
        : (!live.usernameless
          ? 'Signing in with a passkey and no username is switched off in ' +
            'this realm (the passkey policy\'s allowUsernameless, on ' +
            'Directory → Policies).'
          : ''));
    log.debug("Leaving WebauthnPolicy.usernamelessOffered(). " +
              (why ? 'No.' : 'Yes.'));
    return why ? errorCodes.mark({ ok: false, why: why }, 'STS-AUTHN-0301')
               : { ok: true };
  }

  /**
   * Builds the authentication options of a usernameless ceremony: no
   * `allowCredentials`, and user verification required.
   *
   * @param rpId - the relying party id
   * @returns the RP id, `userVerification: required` and the timeout
   */
  discoverableRequestOptions(rpId) {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.discoverableRequestOptions().');
    const out = {
      rpId: rpId,
      userVerification: 'required',
      timeout: this.settings().timeoutMs
    };
    log.debug('Leaving WebauthnPolicy.discoverableRequestOptions().');
    return out;
  }

  // Does this ceremony have to have verified the PERSON? What
  // `authn/webauthn.js` is handed as `requireUserVerification`, and the one
  // ceremony setting that becomes a CHECK rather than a request — see the
  // header.
  /**
   * Tells whether a ceremony must have verified the person, which the
   * verifier then checks.
   *
   * @returns true when `webauthn.userVerification` is `required`
   */
  requireUserVerification() {
    const { log } = this.deps;
    log.debug("Entering WebauthnPolicy.requireUserVerification().");
    log.debug("Leaving WebauthnPolicy.requireUserVerification().");
    return this.settings().userVerification === 'required';
  }

  // ---------------------------------------------------------------------------
  // WHAT `/admin/webauthn` AND `/admin/crypto-metadata` DRAW. Read from this
  // module and from the verifier beside it rather than written down over there,
  // which is that page's whole design: the algorithm table lives with the code
  // that performs the algorithm, so the report cannot describe something this
  // service does not do.
  // ---------------------------------------------------------------------------
  /**
   * Describes the relying party for `/admin/webauthn` and
   * `/admin/crypto-metadata`: every algorithm and curve the verifier knows,
   * which are offered, and the ceremony and attestation settings.
   *
   * @returns the report
   */
  report() {
    const { log, webauthn } = this.deps;
    log.debug('Entering WebauthnPolicy.report().');
    const live = this.settings();
    const attestationPolicy = this.attestationSettings();
    const out = {
      offered: live.enabled,
      rpName: live.rpName,
      rpId: live.rpId,
      rpIdSource: live.rpId ? 'configured' : 'the host this service was ' +
                                             'reached on',
      // EVERY algorithm the verifier knows, with the ones being offered marked
      // — rather than only the offered ones. A page that listed two rows could
      // not answer the question somebody comes to it with, which is *what else
      // could I ask for*.
      algorithms: Object.keys(webauthn.COSE_ALGS).map(function (id) {
        const name = webauthn.COSE_ALGS[id];
        return { name: name, coseAlg: Number(id),
                 offered: live.algorithms.indexOf(name) >= 0,
                 postQuantum: PQC_ALGS.indexOf(name) >= 0,
                 insecure: INSECURE_ALGS.indexOf(name) >= 0 };
      }),
      insecureAlgorithms: live.insecureAlgorithms,
      pqcOnly: live.pqcOnly,
      curves: Object.keys(webauthn.COSE_CURVES).map(function (id) {
        return { name: webauthn.COSE_CURVES[id], coseCurve: Number(id) };
      }),
      userVerification: live.userVerification,
      userVerificationEnforced: live.userVerification === 'required',
      attestation: live.attestation,
      // WHAT IS DONE WITH THE STATEMENT (#105). `attestationVerified` was the
      // literal `false` and `attestationFormats` the three formats the parser
      // recognised; both are now what `authn/webauthn_attestation.ts`
      // verifies, under the policy in force.
      attestationPolicy: attestationPolicy.policy,
      attestationPolicyConfigured: attestationPolicy.configured,
      attestationVerified: attestationPolicy.policy !== 'off' ||
                           attestationPolicy.demandsTrust,
      attestationDemandsTrust: attestationPolicy.demandsTrust,
      attestationFormats: ATTESTATION_FORMATS.slice(),
      attestationAllowedAaguids: attestationPolicy.allowedAaguids,
      attestationMinCertificationLevel:
        attestationPolicy.minCertificationLevel,
      attestationRequireFips: attestationPolicy.requireFips,
      attestationAllowSafetynet: attestationPolicy.allowSafetynet,
      attestationAndroidSoftwareKeys: attestationPolicy.androidSoftwareKeys,
      attestationTrustAnchors: attestationPolicy.trustAnchorsPem
        ? (attestationPolicy.trustAnchorsPem.match(
            /-----BEGIN CERTIFICATE-----/g) || []).length : 0,
      timeoutMs: live.timeoutMs,
      authenticatorAttachment: live.authenticatorAttachment,
      residentKey: live.residentKey,
      credProps: live.credProps,
      primaryAllowed: live.primaryAllowed,
      mfaAllowed: live.mfaAllowed,
      usernameless: live.usernameless,
      maxKeysPerPerson: live.maxKeysPerPerson,
      signatureCounter: 'checked — an authenticator\'s counter only ever ' +
                        'goes up, so one that went backwards is a cloned key.',
      clientDataHash: 'SHA-256 over clientDataJSON, concatenated after ' +
                      'authenticatorData and signed by the authenticator.'
    };
    log.debug('Leaving WebauthnPolicy.report(). ' + out.algorithms.length +
              ' algorithm(s) known.');
    return out;
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<WebauthnPolicy>(
  'authn/webauthn_policy',
  () => new WebauthnPolicy(WebauthnPolicy.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

/**
 * The WebAuthn ceremony options and the service's policy on security keys.
 *
 * Exports the class for the composition root and facades that forward to
 * the installed instance.
 * @namespace
 */
export = {
  WebauthnPolicy: WebauthnPolicy,
  installInstance: (instance: WebauthnPolicy): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  settings: slot.forward('settings'),
  offered: slot.forward('offered'),
  roleAllowed: slot.forward('roleAllowed'),
  algorithmsOffered: slot.forward('algorithmsOffered'),
  algorithmIds: slot.forward('algorithmIds'),
  insecureAlgorithmsAllowed: slot.forward('insecureAlgorithmsAllowed'),
  pqcOnly: slot.forward('pqcOnly'),
  PQC_ALGS: PQC_ALGS,
  INSECURE_ALGS: INSECURE_ALGS,
  creationOptions: slot.forward('creationOptions'),
  authenticatorKinds: slot.forward('authenticatorKinds'),
  requestOptions: slot.forward('requestOptions'),
  usernamelessOffered: slot.forward('usernamelessOffered'),
  discoverableRequestOptions: slot.forward('discoverableRequestOptions'),
  requireUserVerification: slot.forward('requireUserVerification'),
  attestationSettings: slot.forward('attestationSettings'),
  ATTESTATION_FORMATS: ATTESTATION_FORMATS,
  report: slot.forward('report'),
  failureCodeFor: slot.forward('failureCodeFor'),
  // The JOSE-name-to-COSE-identifier map, exported for the tests that assert
  // the offer cannot name something the verifier does not know. DATA, like the
  // two tables it is derived from.
  ALG_IDS: ALG_IDS
};
