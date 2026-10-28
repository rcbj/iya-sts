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
// The ambient realm's name, which the passkey policy may append to rp.name
// (#533). A leaf here: `config` and `helpers` already require it.
import realms = require('../common/realms');

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
// ONE COPY since #718: the passkey policy's, which decides whether a key's
// algorithm is post-quantum and cannot require this module back.
const PQC_ALGS = passkeyPolicy.POST_QUANTUM_ALGORITHMS.slice();

// ---------------------------------------------------------------------------
// THE TWO LANES (#643, 2026-10-19): a classical passkey and a post-quantum
// one held side by side by one person, on one authenticator if it can make
// both.
//
// **WHY A LANE IS MORE THAN A NAME.** Under CTAP 2.x a new discoverable
// credential for the same RP ID and the same user handle REPLACES the one the
// authenticator held, and a credential manager does the same; the default
// list asks for ML-DSA first and an authenticator takes the first algorithm it
// supports; and `excludeCredentials` names every key the person holds. So a
// second registration on one authenticator was refused, or silently removed
// the first from the device while its row stayed here. Each lane therefore has
// its own user handle (`credentials.userHandleOf(name, { lane })`), its own
// algorithm list (`algorithmsOffered(lane)`) and its own exclude list
// (`credentials.beginKeyEnrolment()`).
//
// **OFF BY DEFAULT** (`webauthn.pqcAlongsideClassical`, per realm), and off
// is every ceremony exactly as it was: `lanes()` is `['classical']`, and the
// classical lane's list is the configured one, ML-DSA included.
// **`webauthn.pqcOnly` WINS** where both reach the process (a write of the
// pair is refused, `laneWriteRule()`, but an environment variable or a file
// is not a write): the realm then requests ML-DSA only, so there is one lane.
// ---------------------------------------------------------------------------
/**
 * The passkey lanes (#643): `classical` (the configured list without ML-DSA,
 * under the person's handle) and `pqc` (ML-DSA only, under a second handle).
 */
const LANES = ['classical', 'pqc'];

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
  // A profile's registration rows laid over the selection (#940), only
  // while `withRows()` runs.
  private rowsOverride: { registrationAlgorithms: string[];
                          registrationMode: string;
                          postQuantumRequired: string;
                          lanes: string } | null = null;

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
      // THE SERVICE'S NAME A PROMPT SHOWS, with the realm's name and/or the
      // organisation's where the passkey policy appends them (#533).
      rpName: passkeyPolicy.rpNameFor(
        String(config.value('webauthn.rpName') || 'Authorization ' +
                                                  'server'),
        String((realms.current() || {}).name || realms.currentId() || ''),
        String(config.value('saml.organizationName') || ''), passkeys),
      rpId: String(config.value('webauthn.rpId') || '').trim(),
      algorithms: this.algorithmsOffered(),
      userVerification: this.oneOf(config.value('webauthn.userVerification'),
                                   ['discouraged', 'preferred', 'required'],
                                   'required'),
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
      // WHETHER A REGISTRATION ASKS FOR THE KEY'S MINIMUM PIN LENGTH (#529):
      // only while the passkey policy enforces one, so a realm that does not
      // sends exactly the options it always did.
      minPinLength: passkeyPolicy.pinLengthRule(passkeys).enforce,
      mfaAllowed: config.value('webauthn.mfaAllowed') !== false,
      // The two algorithm flags (2026-10-01).
      insecureAlgorithms: this.insecureAlgorithmsAllowed(),
      pqcOnly: this.pqcOnly(),
      // THE TWO LANES (#643): whether a person may hold a classical and a
      // post-quantum passkey side by side, as `lanes()` reads it.
      pqcAlongsideClassical: this.alongsideClassical(),
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
    // A SERIAL BOUND TO THE PERSON (#532) is only worth what the certificate
    // naming it is worth, so the passkey policy's attribute demands a
    // trusted statement as an AAGUID list does.
    const enterpriseSerialAttribute =
      passkeyPolicy.enterpriseSerialAttribute();
    // THE ALGORITHMS AN ATTESTATION MUST BE SIGNED WITH (#941) are only
    // worth what the chain carrying them is worth — anybody can mint an
    // ML-DSA chain — so the passkey policy's list demands a trusted
    // statement too, and asks the browser for direct attestation.
    const attestationAlgorithms = passkeyPolicy.attestationAlgorithms();
    // ENTERPRISE ATTESTATION'S RP IDs (#1114), and the conveyance they
    // qualify: read here so `webauthn_attestation.ts` judges a statement
    // by the same two values `attestationConveyance()` asked with.
    const conveyance = this.oneOf(config.value('webauthn.attestation'),
                                  ['none', 'indirect', 'direct',
                                   'enterprise'], 'direct');
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
      enterpriseSerialAttribute: enterpriseSerialAttribute,
      attestationAlgorithms: attestationAlgorithms,
      conveyance: conveyance,
      enterpriseRpIds: WebauthnPolicy.enterpriseRpIdsOf(
        config.value('webauthn.attestationEnterpriseRpIds')),
      demandsTrust: policy === 'require-trusted' ||
                    allowedAaguids.length > 0 ||
                    minCertificationLevel !== 'none' || requireFips ||
                    !!enterpriseSerialAttribute ||
                    attestationAlgorithms.length > 0
    };
    log.debug('Leaving WebauthnPolicy.attestationSettings(). policy=' +
              out.policy + ', demandsTrust=' + out.demandsTrust);
    return out;
  }

  // ---------------------------------------------------------------------------
  // WHAT A REGISTRATION ASKS FOR, BY RP ID (#1114). WebAuthn Level 3
  // section 5.4.7: `enterprise` is honoured by a client only for an RP ID
  // its policy allows and answered by an authenticator only for one
  // provisioned into it, so this service asks for it only for an RP ID
  // `webauthn.attestationEnterpriseRpIds` lists. Anywhere else the request
  // asks for `direct` — the most a request can ask without it — and
  // `downgraded` says so, for the ceremony's row and the key's record. A
  // policy that demands a trusted statement (#105) asks for `direct`
  // whatever the conveyance setting, as it always did; an enterprise
  // request satisfies it too, since it asks for more, not less.
  // ---------------------------------------------------------------------------
  /**
   * The attestation conveyance a registration for `rpId` asks for (#1114).
   *
   * @param rpId - the ceremony's RP ID
   * @returns `{ configured, requested, downgraded }`: the setting, what is
   *   sent, and whether `enterprise` was set and the RP ID is not listed
   */
  attestationConveyance(rpId: string) {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.attestationConveyance(). rpId=' +
              rpId);
    const settings = this.attestationSettings();
    const out = WebauthnPolicy.conveyanceFor(settings,
      settings.enterpriseRpIds.indexOf(
        String(rpId || '').trim().toLowerCase()) >= 0);
    log.debug('Leaving WebauthnPolicy.attestationConveyance(). ' +
              out.requested + (out.downgraded ? ' (downgraded)' : ''));
    return out;
  }

  /**
   * The conveyance asked for under `settings` (`attestationSettings()`),
   * for an RP ID that is or is not on the enterprise list (#1114).
   *
   * @param settings - the attestation settings in force
   * @param listed - whether the ceremony's RP ID is listed
   * @returns `{ configured, requested, downgraded }`
   */
  static conveyanceFor(settings: any, listed: boolean) {
    helpers.log.debug('Entering WebauthnPolicy.conveyanceFor().');
    const configured = String((settings && settings.conveyance) || 'direct');
    const downgraded = configured === 'enterprise' && !listed;
    const requested = configured === 'enterprise'
      ? (listed ? 'enterprise' : 'direct')
      : (settings && settings.demandsTrust ? 'direct' : configured);
    helpers.log.debug('Leaving WebauthnPolicy.conveyanceFor().');
    return { configured: configured, requested: requested,
             downgraded: downgraded };
  }

  /**
   * The enterprise RP ID list as the setting holds it: trimmed, lower
   * case, each once (#1114).
   *
   * @param raw - the setting's value, a list or comma-separated text
   * @returns the RP IDs
   */
  static enterpriseRpIdsOf(raw: unknown): string[] {
    helpers.log.debug('Entering WebauthnPolicy.enterpriseRpIdsOf().');
    const out: string[] = [];
    (Array.isArray(raw) ? raw : String(raw || '').split(','))
      .forEach(function (one) {
        const id = String(one || '').trim().toLowerCase();
        if (id && out.indexOf(id) < 0) {
          out.push(id);
        }
      });
    helpers.log.debug('Leaving WebauthnPolicy.enterpriseRpIdsOf(). ' +
                      out.length);
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
   * is left it falls back to ES256 and RS256. A `lane` (#643) narrows the
   * list while `webauthn.pqcAlongsideClassical` is on: `classical` to the
   * names that are not ML-DSA (ES256 and RS256 where that leaves none),
   * `pqc` to ML-DSA (all three where the list names none). With the switch
   * off a lane changes nothing. `classicalOnly` (#944) asks for the
   * classical retry's list instead (`classicalRetryAlgorithms()`), and is
   * ignored where the realm forbids that retry.
   * @param lane - `classical` or `pqc`, or nothing for the configured list
   * @param classicalOnly - the classical retry of a registration (#944)
   * @returns the algorithm names
   */
  algorithmsOffered(lane?: string, classicalOnly?: boolean) {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.algorithmsOffered(). lane=' +
              String(lane || ''));
    // THE CLASSICAL RETRY (#944), where the realm allows one. Where it does
    // not, the flag is IGNORED rather than honoured: a pending ceremony
    // that was armed for a retry before `webauthn.pqcOnly` or the passkey
    // policy changed is then asked for, and held to, the list the realm
    // offers now — never a classical one it forbids.
    if (classicalOnly === true && this.classicalRetryRefusal().ok) {
      const retry = this.classicalRetryAlgorithms(lane);
      log.debug('Leaving WebauthnPolicy.algorithmsOffered(). ' +
                retry.length + ' classical, a retry.');
      return retry;
    }
    const offered = this.lanedAlgorithms(lane);
    // A POST-QUANTUM PASSKEY REQUIRED AT REGISTRATION (#718): only ML-DSA
    // is offered, whatever the lane, so nobody makes a key the policy will
    // refuse at the write — and all three the verifier knows where the
    // list names none, for `pqcOnly`'s reason: an empty request is refused
    // by the browser, and a classical one is what the row says not to make.
    // A save asking for it where no ML-DSA is offered is refused
    // (STS-AUTHN-0357); this is the answer to a setting changed since.
    if (!this.requiresPostQuantumAt('registration')) {
      log.debug('Leaving WebauthnPolicy.algorithmsOffered(). ' +
                offered.length + ' offered.');
      return offered;
    }
    const pq = offered.filter(function (name) {
      return PQC_ALGS.indexOf(name) >= 0;
    });
    const out = pq.length ? pq : PQC_ALGS.filter(function (name) {
      return ALG_IDS[name] !== undefined;
    });
    log.debug('Leaving WebauthnPolicy.algorithmsOffered(). ' + out.length +
              ' post-quantum, as the passkey policy requires.');
    return out;
  }

  /**
   * Says whether the realm in hand offers any ML-DSA algorithm at
   * registration (#718), in either lane: the configured list names one,
   * `webauthn.pqcOnly` is on (which asks for all three where it names
   * none), or the post-quantum lane is offered beside the classical one.
   * Asked by the passkey policy at a save that requires a post-quantum
   * passkey; read BEFORE that requirement's own narrowing, which would
   * otherwise answer yes for every realm.
   *
   * @param rows - the registration rows of the profile being saved (#940);
   *   the selected profile's when omitted
   * @returns true where one is offered
   */
  offersPostQuantum(rows?: { registrationAlgorithms?: unknown;
                             registrationMode?: unknown;
                             postQuantumRequired?: unknown } | null): boolean {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.offersPostQuantum().');
    // THE ROWS OF THE PROFILE BEING SAVED (#940) where they are given, since
    // its own list or mode may offer what the realm does not, or the
    // reverse; the selected profile's otherwise.
    const out = this.withRows(rows, () => {
      const lanes = this.alongsideClassical() ? LANES : [''];
      return lanes.some((lane) => {
        return this.lanedAlgorithms(lane).some(function (name) {
          return PQC_ALGS.indexOf(name) >= 0;
        });
      });
    });
    log.debug('Leaving WebauthnPolicy.offersPostQuantum(). ' + out);
    return out;
  }

  /**
   * The lane a new passkey is made in (#718 on #643's lanes): the one asked
   * for, and `classical` where none is; but the post-quantum lane for a
   * classical choice or none while the passkey policy requires a
   * post-quantum passkey at registration and both lanes are offered —
   * `lanes()` then offers it alone, and a classical-lane credential would
   * be one the policy refuses, made under the classical handle, replacing
   * the person's classical passkey on the device. An unknown lane is
   * returned as it is, for `laneRefusal()` to refuse.
   *
   * @param asked - the lane asked for, or ''
   * @returns the lane
   */
  enrolmentLane(asked: string): string {
    const { log } = this.deps;
    const wanted = String(asked || '');
    log.debug('Entering WebauthnPolicy.enrolmentLane(). ' + wanted);
    const out = (wanted === '' || wanted === 'classical') &&
                this.alongsideClassical() &&
                this.registersPostQuantumOnly()
      ? 'pqc' : (wanted || 'classical');
    log.debug('Leaving WebauthnPolicy.enrolmentLane(). ' + out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE CLASSICAL RETRY OF A REGISTRATION (#944, 2026-10-23).
  //
  // The list is ML-DSA first and an authenticator takes the first algorithm
  // it supports — but a platform may fail the whole registration when it is
  // offered an algorithm the authenticator cannot do (`NotSupportedError`,
  // or an error that says less), and then the person had nowhere to go. The
  // sign-in step and `/portal/keys` now offer a retry that asks for the
  // classical algorithms only, and THIS SERVICE DECIDES WHETHER THAT RETRY
  // MAY BE MADE, NOT THE PAGE: a request for it is refused at the door
  // (STS-AUTHN-0420) wherever a classical passkey would be refused anyway —
  //
  //   * `webauthn.pqcOnly` is on: the realm requests ML-DSA and nothing else;
  //   * the selected passkey policy requires a post-quantum passkey at
  //     registration (`postQuantumRequired: registration-and-sign-in`).
  //
  // Under `postQuantumRequired: sign-in` the retry IS allowed on
  // `/portal/keys`: a classical passkey may still be registered there
  // (#718's reading of the row), for the applications whose profile does
  // not require one. It is refused AT THE SIGN-IN STEP (`at: 'sign-in'`),
  // whose registration signs the person in at once: the session would be
  // refused the moment the key was written (STS-AUTHN-0356), so the retry
  // would be a ceremony spent on a refusal knowable before it. The retry's
  // list is the lane's own less
  // ML-DSA — `lanedAlgorithms('classical')` while both lanes are on, since a
  // classical passkey belongs in the classical lane, under its handle — and
  // `FALLBACK_ALGS` where that leaves nothing.
  // ---------------------------------------------------------------------------
  /**
   * Decides whether a registration may be retried with the classical
   * algorithms only (#944).
   *
   * @param at - `sign-in` for the sign-in step's registration, which signs
   *   the person in at once; anything else for `/portal/keys`
   * @returns `{ ok: true }`, or `{ ok: false, why, reason }` carrying
   *   STS-AUTHN-0420; `reason` names the rule in a few words (#1112)
   */
  classicalRetryRefusal(at?: string) {
    const { log, errorCodes } = this.deps;
    log.debug('Entering WebauthnPolicy.classicalRetryRefusal(). ' +
              String(at || ''));
    // A `pq-only` PASSKEY PROFILE (#940) forbids the retry exactly as
    // webauthn.pqcOnly does, for its population; and a profile with a mode
    // of its own (`pq-first`, `classical-only`) is not held to the realm's
    // pqcOnly, which it replaces for its people (`requestsPostQuantumOnly()`).
    if (this.registrationMode() === 'pq-only') {
      log.debug('Leaving WebauthnPolicy.classicalRetryRefusal(). The ' +
                'profile is post-quantum only.');
      // `reason` (#1112): the rule in a few words, for the ceremony row of
      // a client rule this refusal stops (`common/passkey_clients.ts`).
      return errorCodes.mark({ ok: false,
               reason: 'registrationMode pq-only',
               why: 'The passkey policy offers post-quantum (ML-DSA) ' +
                    'passkeys only here (registrationMode is pq-only), so ' +
                    'a classical one cannot be made instead. Use a device ' +
                    'or a security key that can make an ML-DSA passkey.' },
               'STS-AUTHN-0420');
    }
    if (this.requestsPostQuantumOnly()) {
      log.debug('Leaving WebauthnPolicy.classicalRetryRefusal(). PQC only.');
      return errorCodes.mark({ ok: false,
               reason: 'webauthn.pqcOnly',
               why: 'This realm requests post-quantum (ML-DSA) passkeys ' +
                    'only (webauthn.pqcOnly), so a classical one cannot be ' +
                    'made instead. Use a device or a security key that can ' +
                    'make an ML-DSA passkey.' }, 'STS-AUTHN-0420');
    }
    if (this.requiresPostQuantumAt('registration')) {
      log.debug('Leaving WebauthnPolicy.classicalRetryRefusal(). Required ' +
                'at registration.');
      return errorCodes.mark({ ok: false,
               reason: 'postQuantumRequired registration-and-sign-in',
               why: 'The passkey policy requires a post-quantum (ML-DSA) ' +
                    'passkey at registration (postQuantumRequired is ' +
                    'registration-and-sign-in), so a classical one cannot ' +
                    'be made instead. Use a device or a security key that ' +
                    'can make an ML-DSA passkey.' }, 'STS-AUTHN-0420');
    }
    if (at === 'sign-in' && this.requiresPostQuantumAt('sign-in')) {
      log.debug('Leaving WebauthnPolicy.classicalRetryRefusal(). Required ' +
                'at sign-in.');
      return errorCodes.mark({ ok: false,
               reason: 'postQuantumRequired sign-in',
               why: 'The passkey policy requires a post-quantum (ML-DSA) ' +
                    'passkey to sign in here (postQuantumRequired), so a ' +
                    'classical one made now would not sign you in. Use a ' +
                    'device or a security key that can make an ML-DSA ' +
                    'passkey.' }, 'STS-AUTHN-0420');
    }
    log.debug('Leaving WebauthnPolicy.classicalRetryRefusal(). Allowed.');
    return { ok: true };
  }

  /**
   * The lane a classical retry is made in (#944): the classical lane while
   * both lanes are offered, whatever lane failed; the lane asked for (or
   * `classical`) otherwise, where there is only one.
   *
   * @param lane - the lane the failed registration was armed in
   * @returns the lane
   */
  classicalRetryLane(lane?: string): string {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.classicalRetryLane().');
    const out = this.alongsideClassical() ? 'classical'
                                          : String(lane || 'classical');
    log.debug('Leaving WebauthnPolicy.classicalRetryLane(). ' + out);
    return out;
  }

  // THE RETRY'S LIST (#944): the retry lane's own, less ML-DSA, and the
  // fallback where that leaves nothing. Not asked about the refusal: the
  // callers ask it first.
  private classicalRetryAlgorithms(lane?: string): string[] {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.classicalRetryAlgorithms().');
    const retryLane = this.classicalRetryLane(lane);
    const out = this.lanedAlgorithms(retryLane).filter(function (name) {
      return PQC_ALGS.indexOf(name) < 0;
    });
    log.debug('Leaving WebauthnPolicy.classicalRetryAlgorithms(). ' +
              out.length + ' classical.');
    return out.length ? out : FALLBACK_ALGS.slice();
  }

  /**
   * Says whether a page should offer the classical retry of a registration
   * armed in a lane (#944): the realm allows it, and the offer it would
   * replace asked for ML-DSA — a retry of a list that names no ML-DSA would
   * ask for the same thing again.
   *
   * @param lane - the lane the registration is armed in
   * @param at - `sign-in` at the sign-in step, as `classicalRetryRefusal()`
   * @returns true where the retry is offered
   */
  classicalFallbackOffered(lane?: string, at?: string): boolean {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.classicalFallbackOffered().');
    const out = this.classicalRetryRefusal(at).ok &&
      this.algorithmsOffered(lane).some(function (name) {
        return PQC_ALGS.indexOf(name) >= 0;
      });
    log.debug('Leaving WebauthnPolicy.classicalFallbackOffered(). ' + out);
    return out;
  }

  /**
   * Says whether a registration armed in a lane asks for ML-DSA at all
   * (#944): the pages offer the fallback's guidance only where it does.
   *
   * @param lane - the lane the registration is armed in
   * @param classicalOnly - whether it is the classical retry already
   * @returns true where ML-DSA is asked for
   */
  asksPostQuantum(lane?: string, classicalOnly?: boolean): boolean {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.asksPostQuantum().');
    const out = this.algorithmsOffered(lane, classicalOnly)
      .some(function (name) {
        return PQC_ALGS.indexOf(name) >= 0;
      });
    log.debug('Leaving WebauthnPolicy.asksPostQuantum(). ' + out);
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE UPGRADE OF A CLASSICAL PASSKEY TO AN ML-DSA ONE (#939, 2026-10-23;
  // rule 3ct).
  //
  // A person holding a classical passkey had two ways to an ML-DSA one: a
  // second registration, which leaves two rows for one authenticator, or
  // removing the classical key and registering again, which locks them out
  // if the new registration fails after the removal. The upgrade is one
  // ceremony pair — an ASSERTION with the classical key over a challenge
  // minted for this upgrade (proof of possession, fresh), then a
  // REGISTRATION offering ML-DSA only — and one write at the end
  // (`credentials.confirmKeyUpgrade()`), so the classical key is touched
  // only once the new one has verified.
  //
  // **WHAT THE WRITE DOES FOLLOWS THE LANES** (rcbj's decision on #939),
  // unless the caller names it (#1100: the post-login activity's `method`):
  // with both lanes on, the upgrade ADDS the ML-DSA key in the
  // post-quantum lane under that lane's user handle and keeps the classical
  // one (#643's two lanes, `alongside`); OFF, the ML-DSA key REPLACES the
  // classical one in place, under the classical lane's handle — on one
  // authenticator the new discoverable credential then replaces the old
  // one on the device too, which is what "in place" means there (`replace`).
  //
  // **THE ALGORITHMS ARE ML-DSA ONLY**, the lane's list (or the configured
  // one, with one lane) less everything else, in `webauthn.algorithms`'
  // order, and all three the verifier knows where it names none —
  // `pqcOnly`'s reason: an empty request is refused by the browser, and a
  // classical one is the thing the upgrade exists not to make. There is no
  // classical retry of an upgrade (#944's): its point is ML-DSA.
  //
  // **WHERE IT RUNS** (#1100, 2026-10-28): at a sign-in, as the post-login
  // activity's PQC migration (`common/post_login.ts`), and from the
  // console on a person's behalf. It was a button on `/portal/keys` behind
  // `webauthn.pqcUpgrade` until then; rcbj had both removed, so whether a
  // realm's people are asked is the post-login policy's to say. Nothing
  // about it differs between development and product mode: the
  // proof is a signature this service verifies in both, as it verifies the
  // UV flag in both, and the attestation the new key brings is held to the
  // policy in force (`attestationSettings()`, which is the mode's).
  // ---------------------------------------------------------------------------
  /**
   * Decides whether this realm offers #939's upgrade of a classical passkey
   * to an ML-DSA one at all: WebAuthn on, an ML-DSA algorithm the verifier can check, and — with both lanes on —
   * the post-quantum lane offered. The person's own keys, role and the
   * passkey policy are asked by `credentials.keyUpgradeRefusal()`.
   *
   * @returns `{ ok: true }`, or `{ ok: false, why }` carrying STS-AUTHN-0450
   */
  upgradeRefusal() {
    const { log, errorCodes } = this.deps;
    log.debug('Entering WebauthnPolicy.upgradeRefusal().');
    if (!this.settings().enabled) {
      log.debug('Leaving WebauthnPolicy.upgradeRefusal(). WebAuthn is off.');
      return errorCodes.mark({ ok: false,
               why: 'Passkeys are switched off in this realm ' +
                    '(webauthn.enabled), so none can be upgraded.' },
               'STS-AUTHN-0450');
    }
    if (!this.upgradeAlgorithms().length) {
      log.debug('Leaving WebauthnPolicy.upgradeRefusal(). No ML-DSA.');
      return errorCodes.mark({ ok: false,
               why: 'This service can verify no ML-DSA algorithm, so a ' +
                    'passkey cannot be upgraded to one.' }, 'STS-AUTHN-0450');
    }
    if (this.alongsideClassical() && !this.laneRefusal('pqc').ok) {
      log.debug('Leaving WebauthnPolicy.upgradeRefusal(). The ' +
                'post-quantum lane is refused.');
      return errorCodes.mark({ ok: false,
               why: String(this.laneRefusal('pqc').why || '') },
               'STS-AUTHN-0450');
    }
    log.debug('Leaving WebauthnPolicy.upgradeRefusal(). Offered.');
    return { ok: true };
  }

  // WHETHER THE UPGRADE IS OFFERED HERE (#939), the flag #946's panel and
  // `/portal/keys` read: `upgradeRefusal()` as a boolean. Whether a given
  // person holds a key it applies to is `credentials.upgradableKeysOf()`'s
  // to say — this module cannot require the credential store, which
  // requires it.
  /**
   * Says whether this realm offers #939's upgrade of a classical passkey to
   * an ML-DSA one.
   *
   * @returns true where `upgradeRefusal()` allows it
   */
  postQuantumUpgradeOffered(): boolean {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.postQuantumUpgradeOffered().');
    const out = this.upgradeRefusal().ok;
    log.debug('Leaving WebauthnPolicy.postQuantumUpgradeOffered(). ' + out);
    return out;
  }

  /**
   * What an upgrade's write does here (#939): `alongside` (the ML-DSA key
   * added in the post-quantum lane, the classical one kept) while
   * `webauthn.pqcAlongsideClassical` is on, `replace` (the ML-DSA key in
   * the classical key's place) while it is off.
   *
   * @returns `alongside` or `replace`
   */
  upgradeMode(): string {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.upgradeMode().');
    const out = this.alongsideClassical() ? 'alongside' : 'replace';
    log.debug('Leaving WebauthnPolicy.upgradeMode(). ' + out);
    return out;
  }

  /**
   * The lane an upgrade's new key is made in (#939): `pqc` beside the
   * classical key, `classical` in its place.
   *
   * @returns `pqc` or `classical`
   */
  upgradeLane(): string {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.upgradeLane().');
    const out = this.upgradeMode() === 'alongside' ? 'pqc' : 'classical';
    log.debug('Leaving WebauthnPolicy.upgradeLane(). ' + out);
    return out;
  }

  /**
   * The algorithms an upgrade's registration offers (#939): ML-DSA only,
   * in the order the lane's list (`webauthn.algorithms`) names them, and
   * every ML-DSA the verifier knows where it names none.
   *
   * @returns the JOSE names, possibly none where the verifier knows no
   *   ML-DSA
   */
  upgradeAlgorithms(): string[] {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.upgradeAlgorithms().');
    const lane = this.alongsideClassical() ? 'pqc' : '';
    const named = this.lanedAlgorithms(lane).filter(function (name) {
      return PQC_ALGS.indexOf(name) >= 0;
    });
    const out = named.length ? named : PQC_ALGS.filter(function (name) {
      return ALG_IDS[name] !== undefined;
    });
    log.debug('Leaving WebauthnPolicy.upgradeAlgorithms(). ' + out.length +
              ' ML-DSA.');
    return out;
  }

  /**
   * `upgradeAlgorithms()` as COSE identifiers, for `pubKeyCredParams` and
   * for section 7.1's offered-algorithm check at the finish.
   *
   * @returns the COSE algorithm identifiers
   */
  upgradeAlgorithmIds(): number[] {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.upgradeAlgorithmIds().');
    log.debug('Leaving WebauthnPolicy.upgradeAlgorithmIds().');
    return this.upgradeAlgorithms().map(function (name) {
      return ALG_IDS[name];
    });
  }

  /**
   * The registration options of an upgrade (#939): `creationOptions()` for
   * the kind of authenticator the classical key is on, with ML-DSA only.
   *
   * @param rpId - the relying party id
   * @param kind - `passkey` or `security-key`, the classical key's group
   * @returns the options
   */
  upgradeCreationOptions(rpId, kind?) {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.upgradeCreationOptions().');
    const out = this.creationOptions(rpId, kind, this.upgradeLane());
    out.algorithms = this.upgradeAlgorithmIds();
    log.debug('Leaving WebauthnPolicy.upgradeCreationOptions(). ' +
              out.algorithms.length + ' ML-DSA.');
    return out;
  }

  // THE LANE'S LIST (#643), before #718's narrowing: what
  // `algorithmsOffered()` answered until a post-quantum passkey could be
  // required.
  private lanedAlgorithms(lane?: string): string[] {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.lanedAlgorithms(). lane=' +
              String(lane || ''));
    const all = this.configuredAlgorithms();
    const wanted = String(lane || '');
    // OFF, OR NO LANE NAMED: the list as it always was, ML-DSA and all, so a
    // realm that never turned the switch on sends exactly what it sent.
    if (!wanted || !this.alongsideClassical()) {
      log.debug('Leaving WebauthnPolicy.lanedAlgorithms(). ' + all.length +
                ' offered, no lane.');
      return all;
    }
    if (wanted === 'pqc') {
      // THE POST-QUANTUM LANE: `webauthn.pqcOnly`'s narrowing, and all three
      // the verifier knows where the list names none. Empty only where the
      // verifier knows no ML-DSA, which `laneRefusal()` refuses by name.
      const named = all.filter(function (name) {
        return PQC_ALGS.indexOf(name) >= 0;
      });
      const out = named.length ? named : PQC_ALGS.filter(function (name) {
        return ALG_IDS[name] !== undefined;
      });
      log.debug('Leaving WebauthnPolicy.lanedAlgorithms(). ' + out.length +
                ' post-quantum.');
      return out;
    }
    // THE CLASSICAL LANE: everything but ML-DSA, so an authenticator that
    // supports ML-DSA cannot answer this lane with a post-quantum key — the
    // first algorithm it supports would otherwise be ML-DSA both times.
    const classical = all.filter(function (name) {
      return PQC_ALGS.indexOf(name) < 0;
    });
    log.debug('Leaving WebauthnPolicy.lanedAlgorithms(). ' +
              classical.length + ' classical.');
    return classical.length ? classical : FALLBACK_ALGS.slice();
  }

  // THE CONFIGURED LIST, as `algorithmsOffered()` answered it before the
  // lanes (#643): `webauthn.algorithms` filtered against the verifier, the
  // two algorithm flags applied, and the fallback where nothing is left.
  // SINCE #940 the list is the SELECTED PASSKEY PROFILE'S
  // `registrationAlgorithms` where it names one, and the realm's
  // `webauthn.algorithms` where it says `realm`; and its
  // `registrationMode` replaces the realm's pqcOnly for its population —
  // `pq-only` narrows as pqcOnly does, `pq-first` puts ML-DSA first (all
  // three where the list names none, a list changed since the save that
  // checked it), `classical-only` drops ML-DSA. The verifier's table and the
  // insecure switch filter a profile's list exactly as the realm's.
  private configuredAlgorithms() {
    const { config, log } = this.deps;
    log.debug('Entering WebauthnPolicy.configuredAlgorithms().');
    const rows = this.registrationRows();
    const asked = rows.registrationAlgorithms.length
      ? rows.registrationAlgorithms : config.value('webauthn.algorithms');
    const list = (Array.isArray(asked) ? asked : String(asked || '').split(','))
      .map(function (name) { return String(name || '').trim(); })
      .filter(Boolean);
    const insecureAllowed = this.insecureAlgorithmsAllowed();
    const pqcOnly = this.requestsPostQuantumOnly();
    const mode = rows.registrationMode;
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
        log.debug('Leaving WebauthnPolicy.configuredAlgorithms(). PQC ' +
                  'only, and the list names no ML-DSA: all three.');
        return PQC_ALGS.slice();
      }
    }
    if (mode === 'pq-first') {
      // ML-DSA FIRST (#940), in the list's own order, then the rest in
      // theirs — so an authenticator that can make ML-DSA does, and one that
      // cannot still finds a classical algorithm in the same ceremony.
      const named = kept.filter(function (name) {
        return PQC_ALGS.indexOf(name) >= 0;
      });
      const pq = named.length ? named : PQC_ALGS.filter(function (name) {
        return ALG_IDS[name] !== undefined;
      });
      kept = pq.concat(kept.filter(function (name) {
        return PQC_ALGS.indexOf(name) < 0;
      }));
    } else if (mode === 'classical-only') {
      // NO ML-DSA (#940), for a population whose devices fail an ML-DSA
      // registration; the fallback below where that leaves nothing.
      kept = kept.filter(function (name) {
        return PQC_ALGS.indexOf(name) < 0;
      });
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
      log.debug('Leaving WebauthnPolicy.configuredAlgorithms(). Fell back.');
      return FALLBACK_ALGS.slice();
    }
    log.debug('Leaving WebauthnPolicy.configuredAlgorithms(). ' + kept.length +
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

  // ---------------------------------------------------------------------------
  // A POPULATION'S REGISTRATION ALGORITHMS (#940, rule 3cu).
  //
  // The passkey policy's profiles carry `registrationAlgorithms` (an ordered
  // list, or `realm`) and `registrationMode` (`realm`, `pq-only`, `pq-first`,
  // `classical-only`), selected by application or group as
  // `postQuantumRequired` is, and FALLING BACK TO THE REALM: `realm` and
  // `realm` is every ceremony exactly as it was. Everything a registration
  // offers already came through `algorithmsOffered()`, so the rows are read
  // THERE — `configuredAlgorithms()` (the list and the mode),
  // `alongsideClassical()` (no post-quantum lane for `classical-only`),
  // `lanes()` and `enrolmentLane()` (the post-quantum lane alone for
  // `pq-only`), `classicalRetryRefusal()` (`pq-only` refuses #944's retry,
  // STS-AUTHN-0420) and `laneRefusal()` (STS-AUTHN-0433) — and every door
  // follows: the sign-in step, `/portal/keys`, the activation link, the
  // recovery step and the retry.
  //
  // **`registrationOffer()` IS THE ONE ANSWER** to "which algorithms does a
  // registration offer this person, at this application, in this lane": the
  // selection for the person and application where they are given (#535's
  // `withSelection()`), the ambient one otherwise. Any new door that builds
  // `pubKeyCredParams` asks it (or `creationOptions()`, which reads the same
  // resolution), and never reads the rows itself.
  //
  // A PROFILE THAT IS NOT THE SELECTED ONE — the rows of a save being
  // checked, or the profile a question was asked about — is resolved by
  // `withRows()`, which lays its rows over the selection for one synchronous
  // computation and puts the selection back: node runs it to the end before
  // anything else, so no other request reads the override.
  // ---------------------------------------------------------------------------
  /**
   * The selected passkey profile's `registrationMode` (#940), or the rows
   * `withRows()` laid over it.
   *
   * @returns `realm`, `pq-only`, `pq-first` or `classical-only`
   */
  registrationMode(): string {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.registrationMode().');
    const out = this.registrationRows().registrationMode;
    log.debug('Leaving WebauthnPolicy.registrationMode(). ' + out);
    return out;
  }

  /**
   * Tells whether a registration here requests ML-DSA and nothing else
   * (#940): the passkey profile's `pq-only`, or the realm's
   * `webauthn.pqcOnly` where the profile follows the realm. A profile with
   * a mode of its own is not held to the realm's switch.
   *
   * @returns true where it does
   */
  requestsPostQuantumOnly(): boolean {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.requestsPostQuantumOnly().');
    const mode = this.registrationMode();
    const out = mode === 'pq-only' || (mode === 'realm' && this.pqcOnly());
    log.debug('Leaving WebauthnPolicy.requestsPostQuantumOnly(). ' + out);
    return out;
  }

  // The rows in force: `withRows()`'s while it runs, else the selected
  // profile's.
  private registrationRows(): { registrationAlgorithms: string[];
                                registrationMode: string;
                                postQuantumRequired: string;
                                lanes?: string } {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.registrationRows().');
    const out = this.rowsOverride || passkeyPolicy.registrationRows();
    log.debug('Leaving WebauthnPolicy.registrationRows(). ' +
              (this.rowsOverride ? 'Laid over.' : 'Selected.'));
    return out;
  }

  // #718's requirement at a stage, from the rows in force: `withRows()`'s
  // `postQuantumRequired` while it runs, else the selected profile's.
  private requiresPostQuantumAt(at: string): boolean {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.requiresPostQuantumAt(). ' + at);
    if (!this.rowsOverride) {
      const selected = passkeyPolicy.requiresPostQuantum(at);
      log.debug('Leaving WebauthnPolicy.requiresPostQuantumAt(). ' +
                selected);
      return selected;
    }
    const row = this.rowsOverride.postQuantumRequired;
    const out = at === 'registration' ? row === 'registration-and-sign-in'
      : (row === 'sign-in' || row === 'registration-and-sign-in');
    log.debug('Leaving WebauthnPolicy.requiresPostQuantumAt(). ' + out +
              ', laid over.');
    return out;
  }

  // WHETHER ONLY THE POST-QUANTUM LANE TAKES A NEW PASSKEY: #718's
  // requirement at registration, or #940's `pq-only`.
  private registersPostQuantumOnly(): boolean {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.registersPostQuantumOnly().');
    const out = this.requiresPostQuantumAt('registration') ||
                this.registrationMode() === 'pq-only';
    log.debug('Leaving WebauthnPolicy.registersPostQuantumOnly(). ' + out);
    return out;
  }

  // Runs `fn` with a profile's registration rows laid over the selection,
  // and puts back what was there, however `fn` ends.
  private withRows<T>(rows: { registrationAlgorithms?: unknown;
                              registrationMode?: unknown;
                              postQuantumRequired?: unknown;
                              lanes?: unknown } | null
                              | undefined,
                      fn: () => T): T {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.withRows().');
    if (!rows) {
      log.debug('Leaving WebauthnPolicy.withRows(). The selection.');
      return fn();
    }
    const before = this.rowsOverride;
    this.rowsOverride = {
      registrationAlgorithms: (Array.isArray(rows.registrationAlgorithms)
        ? rows.registrationAlgorithms : []).map(String).filter(Boolean),
      registrationMode: passkeyPolicy.REGISTRATION_MODES.indexOf(
        String(rows.registrationMode || '')) >= 0
        ? String(rows.registrationMode) : 'realm',
      postQuantumRequired: String(rows.postQuantumRequired || 'off'),
      lanes: String(rows.lanes || 'realm')
    };
    try {
      const out = fn();
      log.debug('Leaving WebauthnPolicy.withRows().');
      return out;
    } finally {
      this.rowsOverride = before;
    }
  }

  /**
   * THE ONE ANSWER to which algorithms a passkey registration offers
   * (#940): for a person at an application in a lane, under the passkey
   * profile selected for them (by application or group, #535), falling
   * back to the realm's settings. Every door that builds `pubKeyCredParams`
   * reads this resolution — `creationOptions()` and `algorithmIds()` are it
   * for the selection in force.
   *
   * @param who - `username` and `application` to select for (the ambient
   *   selection where neither is given), `lane` (#643) and `classicalOnly`
   *   (#944's retry)
   * @returns `{ algorithms, ids, profile, mode, from }`: the JOSE names in
   *   order, their COSE identifiers, the profile's name, its
   *   `registrationMode`, and `profile` or `realm` for where the list came
   *   from
   */
  registrationOffer(who?: { username?: string; application?: string;
                            lane?: string; classicalOnly?: boolean } | null):
      { algorithms: string[]; ids: number[]; profile: string; mode: string;
        from: string } {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.registrationOffer().');
    const asked = who || {};
    const build = () => {
      log.debug('Entering registrationOffer() build().');
      const names = this.algorithmsOffered(asked.lane,
                                           asked.classicalOnly === true);
      const result = {
        algorithms: names,
        ids: names.map(function (name) { return ALG_IDS[name]; }),
        profile: passkeyPolicy.selectedName(),
        mode: this.registrationMode(),
        from: passkeyPolicy.registrationAlgorithmsFrom()
      };
      log.debug('Leaving registrationOffer() build().');
      return result;
    };
    const out = asked.username || asked.application
      ? passkeyPolicy.withSelection(String(asked.username || ''),
                                    String(asked.application || ''), build)
      : build();
    log.debug('Leaving WebauthnPolicy.registrationOffer(). ' +
              out.algorithms.join(',') + ' (' + out.profile + ', ' +
              out.mode + ')');
    return out;
  }

  /**
   * Every algorithm a registration under a profile's rows may make (#940):
   * the union of every lane's list and the classical retry's where it is
   * allowed — what `credentials.addKey()`, which does not know which
   * ceremony made a key, holds the key to through the issuance policy.
   *
   * @param rows - a profile's registration rows; the selection's when
   *   omitted
   * @returns the JOSE names
   */
  registrationAlgorithmsAllowed(rows?: { registrationAlgorithms?: unknown;
                                         registrationMode?: unknown;
                                         postQuantumRequired?: unknown }
                                         | null): string[] {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.registrationAlgorithmsAllowed().');
    const out = this.withRows(rows, () => {
      const all: string[] = [];
      const add = function (names: string[]): void {
        log.debug('Entering registrationAlgorithmsAllowed() add().');
        names.forEach(function (name) {
          if (all.indexOf(name) < 0) {
            all.push(name);
          }
        });
        log.debug('Leaving registrationAlgorithmsAllowed() add().');
      };
      ['', 'classical', 'pqc'].forEach((lane) => {
        add(this.algorithmsOffered(lane));
      });
      if (this.classicalRetryRefusal().ok) {
        add(this.algorithmsOffered('', true));
      }
      return all;
    });
    log.debug('Leaving WebauthnPolicy.registrationAlgorithmsAllowed(). ' +
              out.length + ' algorithm(s).');
    return out;
  }

  /**
   * The algorithm identifiers a registration's finish holds a credential
   * to (#940): those the realm and the selected profile offer NOW, less any
   * the ceremony was not offered when it was armed — so a profile or a
   * setting changed between the two never widens what the browser was
   * asked for. Where nothing was recorded (a ceremony armed before #940),
   * the list now.
   *
   * @param now - `algorithmIds()` at the finish
   * @param offered - the identifiers recorded when the ceremony was armed
   * @returns the identifiers
   */
  static heldToOffer(now: number[], offered: unknown): number[] {
    helpers.log.debug('Entering WebauthnPolicy.heldToOffer().');
    if (!Array.isArray(offered) || !offered.length) {
      helpers.log.debug('Leaving WebauthnPolicy.heldToOffer(). Nothing ' +
                        'recorded.');
      return now.slice();
    }
    const asked = offered.map(Number);
    const out = now.filter(function (id) {
      return asked.indexOf(Number(id)) >= 0;
    });
    helpers.log.debug('Leaving WebauthnPolicy.heldToOffer(). ' + out.length +
                      ' of ' + now.length + '.');
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE LANES (#643): see the header beside `LANES`.
  // ---------------------------------------------------------------------------
  /**
   * Tells whether this realm lets a person hold a classical and a
   * post-quantum passkey side by side: `webauthn.pqcAlongsideClassical`,
   * and never while `webauthn.pqcOnly` is on — nor for a population whose
   * passkey profile is `classical-only` (#940), which makes no post-quantum
   * passkey in either lane.
   *
   * @returns true when both lanes are offered
   */
  alongsideClassical(): boolean {
    const { config, log } = this.deps;
    log.debug('Entering WebauthnPolicy.alongsideClassical().');
    // THE POPULATION'S `lanes` ROW FIRST (#1104), then the realm's switch.
    const lanes = String(this.registrationRows().lanes || 'realm');
    const on = (lanes === 'both' ||
                (lanes === 'realm' &&
                 config.value('webauthn.pqcAlongsideClassical') === true)) &&
               !this.pqcOnly() &&
               this.registrationMode() !== 'classical-only';
    log.debug('Leaving WebauthnPolicy.alongsideClassical(). ' + on);
    return on;
  }

  /**
   * The lanes a new passkey may be created in here: `classical` alone while
   * the switch is off, `classical` and `pqc` while it is on.
   *
   * @returns the lanes, in the order a page offers them
   */
  lanes(): string[] {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.lanes().');
    // THE POST-QUANTUM LANE ALONE while a post-quantum passkey is required
    // at registration (#718), or the passkey profile offers ML-DSA only
    // (#940's `pq-only`): a page then asks no question, and
    // `enrolmentLane()` makes its default this lane.
    const out = !this.alongsideClassical() ? ['classical']
      : (this.registersPostQuantumOnly() ? ['pqc'] : LANES.slice());
    log.debug('Leaving WebauthnPolicy.lanes(). ' + out.join(','));
    return out;
  }

  // ASKED AT THE START OF AN ENROLMENT AND AGAIN AT THE WRITE, like
  // `roleAllowed()`: a page is markup, and a lane posted by hand, or a switch
  // turned off while somebody was touching their key, must not put a key in
  // a lane the realm does not offer. **IT REFUSES AN ENROLMENT AND NEVER A
  // SIGN-IN**: a post-quantum key enrolled while the switch was on goes on
  // signing in after it is turned off, for `webauthn.enabled`'s reason.
  /**
   * Decides whether a new passkey may be created in a lane.
   *
   * @param lane - `classical` or `pqc`
   * @returns `{ ok: true }`, or `{ ok: false, why }` carrying an error code
   */
  laneRefusal(lane: string) {
    const { log, errorCodes } = this.deps;
    const wanted = String(lane || '');
    log.debug('Entering WebauthnPolicy.laneRefusal(). lane=' + wanted);
    if (LANES.indexOf(wanted) < 0) {
      log.debug('Leaving WebauthnPolicy.laneRefusal(). Not a lane.');
      return errorCodes.mark({ ok: false,
               why: 'A passkey is created in the "classical" lane or the ' +
                    '"pqc" lane. "' + wanted + '" is neither.' },
               'STS-AUTHN-0350');
    }
    // A CLASSICAL-ONLY POPULATION (#940) is refused the post-quantum lane
    // by name, so the sentence says which rule it is.
    if (wanted === 'pqc' && this.registrationMode() === 'classical-only') {
      log.debug('Leaving WebauthnPolicy.laneRefusal(). The profile is ' +
                'classical only.');
      return errorCodes.mark({ ok: false,
               why: 'The passkey policy offers classical passkeys only here ' +
                    '(registrationMode is classical-only), so a ' +
                    'post-quantum one cannot be created. A post-quantum ' +
                    'passkey already registered goes on working.' },
               'STS-AUTHN-0433');
    }
    if (wanted === 'pqc' && !this.alongsideClassical()) {
      log.debug('Leaving WebauthnPolicy.laneRefusal(). The post-quantum ' +
                'lane is not offered here.');
      return errorCodes.mark({ ok: false,
               why: 'A post-quantum passkey beside a classical one is not ' +
                    'offered in this realm (webauthn.pqcAlongsideClassical' +
                    (this.pqcOnly() ? ', and webauthn.pqcOnly is on' : '') +
                    '). A post-quantum passkey already registered goes on ' +
                    'working.' }, 'STS-AUTHN-0351');
    }
    if (wanted === 'pqc' && !this.algorithmsOffered('pqc').length) {
      log.debug('Leaving WebauthnPolicy.laneRefusal(). No ML-DSA can be ' +
                'offered.');
      return errorCodes.mark({ ok: false,
               why: 'This service can verify no ML-DSA algorithm, so a ' +
                    'post-quantum passkey cannot be created.' },
               'STS-AUTHN-0352');
    }
    log.debug('Leaving WebauthnPolicy.laneRefusal(). Allowed.');
    return { ok: true };
  }

  // THE RULE BETWEEN THE TWO SWITCHES (#643), handed to `config.js`'s
  // `addWriteRule()` below and so asked of every door that writes an
  // override — the console's, the API's and a restored value's. Both on is a
  // contradiction rather than a combination: `pqcOnly` says request ML-DSA
  // and nothing else, the lanes say offer a classical lane beside it. Refused
  // at the write rather than resolved quietly; a value that reaches the
  // process another way (the environment, a file) is read with `pqcOnly`
  // winning (`alongsideClassical()`).
  /**
   * Refuses a write that would turn on `webauthn.pqcAlongsideClassical`
   * and `webauthn.pqcOnly` together.
   *
   * @param key - the setting being written
   * @param parsed - its parsed value
   * @returns `{ problem, code }`, or null
   */
  static laneWriteRule(key: string, parsed: unknown) {
    helpers.log.debug('Entering WebauthnPolicy.laneWriteRule(). ' + key);
    const other = key === 'webauthn.pqcAlongsideClassical' ? 'webauthn.pqcOnly'
      : (key === 'webauthn.pqcOnly' ? 'webauthn.pqcAlongsideClassical' : '');
    if (!other || parsed !== true || config.value(other) !== true) {
      helpers.log.debug('Leaving WebauthnPolicy.laneWriteRule().');
      return null;
    }
    helpers.log.debug('Leaving WebauthnPolicy.laneWriteRule(). Refused.');
    return { code: 'STS-AUTHN-0353',
             problem: '"' + key + '" cannot be on while "' + other + '" is: ' +
                      'post-quantum only requests ML-DSA and nothing else, ' +
                      'and a post-quantum passkey beside a classical one ' +
                      'needs a classical lane. Turn "' + other + '" off ' +
                      'first.' };
  }

  // THE RULE BETWEEN THE CONVEYANCE AND ITS RP IDs (#1114), handed to
  // `config.js`'s `addWriteRule()` as the lanes' rule is. `enterprise` with
  // no RP ID listed would ask for `direct` at every ceremony while the page
  // said `enterprise`, so it is refused at the write — both ways round:
  // choosing `enterprise` while the list is empty, and emptying the list
  // while `enterprise` is chosen. The pair posted together is judged by
  // both new values (`beside`, `config.withWriteBatch()`). A value that
  // reaches the process another way (the environment, a file) is read as
  // it is: every ceremony asks for `direct`, and says so.
  /**
   * Refuses a write that would leave `webauthn.attestation` `enterprise`
   * with `webauthn.attestationEnterpriseRpIds` empty.
   *
   * @param key - the setting being written
   * @param parsed - its parsed value
   * @param inRealm - unused; the rule holds in a realm as in the process
   * @param beside - a companion setting's value as this write leaves it
   * @returns `{ problem, code }`, or null
   */
  static enterpriseWriteRule(key: string, parsed: unknown, inRealm?: boolean,
                             beside?: (key: string) => unknown) {
    helpers.log.debug('Entering WebauthnPolicy.enterpriseWriteRule(). ' +
                      key);
    const read = typeof beside === 'function' ? beside
      : function (other: string): unknown {
        return config.value(other);
      };
    let conveyance = '';
    let listed: string[] = [];
    if (key === 'webauthn.attestation') {
      conveyance = String(parsed || '');
      listed = WebauthnPolicy.enterpriseRpIdsOf(
        read('webauthn.attestationEnterpriseRpIds'));
    } else if (key === 'webauthn.attestationEnterpriseRpIds') {
      conveyance = String(read('webauthn.attestation') || '');
      listed = WebauthnPolicy.enterpriseRpIdsOf(parsed);
    }
    if (conveyance !== 'enterprise' || listed.length > 0) {
      helpers.log.debug('Leaving WebauthnPolicy.enterpriseWriteRule().');
      return null;
    }
    helpers.log.debug('Leaving WebauthnPolicy.enterpriseWriteRule(). ' +
                      'Refused.');
    return { code: 'STS-AUTHN-0500',
             problem: '"webauthn.attestation" cannot be enterprise while ' +
                      '"webauthn.attestationEnterpriseRpIds" is empty: ' +
                      'enterprise attestation is asked for only for an RP ' +
                      'ID that list names (WebAuthn Level 3 section ' +
                      '5.4.7). List the RP IDs your authenticators are ' +
                      'provisioned for, or choose direct.' };
  }

  // The COSE identifiers for `pubKeyCredParams`, in the order the names were
  // given. Separate from `algorithms` above because the page wants the names
  // and the ceremony wants the numbers, and computing either from the other at
  // two call sites is how the two come to disagree.
  /**
   * Returns the offered algorithms as COSE identifiers for
   * `pubKeyCredParams`, in the same order.
   *
   * @param lane - `classical` or `pqc` (#643), as `algorithmsOffered()`
   * @param classicalOnly - the classical retry (#944), as
   *   `algorithmsOffered()`
   * @returns the COSE algorithm identifiers
   */
  algorithmIds(lane?: string, classicalOnly?: boolean) {
    const { log } = this.deps;
    log.debug("Entering WebauthnPolicy.algorithmIds().");
    log.debug("Leaving WebauthnPolicy.algorithmIds().");
    return this.algorithmsOffered(lane, classicalOnly)
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
   * @param lane - `classical` or `pqc` (#643), the lane the enrolment was
   *   begun in; it decides the algorithms and nothing else
   * @param classicalOnly - the classical retry (#944): the algorithms less
   *   ML-DSA, where the realm allows it
   * @returns the options: RP, algorithms, attestation, timeout,
   * authenticator selection, hints and credProps
   */
  creationOptions(rpId, kind?, lane?: string, classicalOnly?: boolean) {
    const { log } = this.deps;
    log.debug('Entering WebauthnPolicy.creationOptions(). rpId=' + rpId);
    const live = this.settings();
    const wanted = String(kind || '');
    const asked = live.authenticatorAttachment === 'any' &&
                  wanted === 'security-key' ? 'cross-platform' : '';
    const residentKey = wanted === 'passkey' ? 'required' : live.residentKey;
    // THE HINTS ARE THE PASSKEY POLICY'S ROWS (#531), whose defaults are what
    // this line sent before: client-device then hybrid for a passkey,
    // security-key for a security key, none for an enrolment naming no kind.
    const hints = passkeyPolicy.hintsFor(wanted);
    // A POLICY THAT NEEDS A STATEMENT ASKS FOR ONE (#105). `none` and
    // `indirect` let the browser strip or anonymise the statement, and a
    // realm that requires a trusted one would then refuse every enrolment
    // for a reason nobody could see on this page. `enterprise` is kept: it
    // asks for more, not less — but only for an RP ID the realm lists
    // (#1114, `attestationConveyance()`); elsewhere it asks for `direct`.
    const attestation = this.attestationConveyance(rpId).requested;
    const out = {
      rp: { name: live.rpName, id: rpId },
      // THE LANE'S ALGORITHMS (#643); with no lane, or the switch off, the
      // configured list as it always was. The classical retry's (#944).
      algorithms: this.algorithmIds(lane, classicalOnly),
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
      // CTAP 2.1 section 12.4's extension, asked for only while the passkey
      // policy enforces a PIN length (#529); absent otherwise, so the options
      // a realm that does not are byte for byte what they were.
      minPinLength: live.minPinLength === true ? true : undefined,
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
    const out: { rpId: string; userVerification: string; timeout: number;
                 hints?: string[] } = {
      rpId: rpId,
      userVerification: live.userVerification,
      timeout: live.timeoutMs
    };
    // A SIGN-IN'S HINTS (#531), the passkey policy's `signInHints`; absent
    // where it names none, so the default request is what it always was.
    const hints = passkeyPolicy.hintsFor('sign-in');
    if (hints.length) {
      out.hints = hints;
    }
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
    const out: { rpId: string; userVerification: string; timeout: number;
                 hints?: string[] } = {
      rpId: rpId,
      userVerification: 'required',
      timeout: this.settings().timeoutMs
    };
    // The sign-in's hints (#531), as `requestOptions()` sends them.
    const hints = passkeyPolicy.hintsFor('sign-in');
    if (hints.length) {
      out.hints = hints;
    }
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
      // THE LANES (#643): the switch, and each lane's algorithms while on.
      pqcAlongsideClassical: live.pqcAlongsideClassical,
      lanes: this.lanes().map((lane) => {
        return { lane: lane, algorithms: this.algorithmsOffered(lane) };
      }),
      // THE UPGRADE (#939): what its write does by default and the ML-DSA
      // it asks for; whether anybody is asked is the post-login policy's
      // (#1100).
      upgradeMode: this.upgradeMode(),
      upgradeAlgorithms: this.upgradeAlgorithms(),
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

// THE RULE BETWEEN THE TWO SWITCHES (#643), asked at every write of an
// override. Registered once, at load, by the module that reads both — as
// `tls/tls_server.js` registers its own.
if (typeof config.addWriteRule === 'function') {
  config.addWriteRule(WebauthnPolicy.laneWriteRule);
  // And enterprise attestation's RP ID list (#1114).
  config.addWriteRule(WebauthnPolicy.enterpriseWriteRule);
}

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
  // The lanes (#643).
  alongsideClassical: slot.forward('alongsideClassical'),
  lanes: slot.forward('lanes'),
  laneRefusal: slot.forward('laneRefusal'),
  // The post-quantum requirement's (#718).
  offersPostQuantum: slot.forward('offersPostQuantum'),
  enrolmentLane: slot.forward('enrolmentLane'),
  // The classical retry of a registration (#944), and #939's upgrade flag.
  classicalRetryRefusal: slot.forward('classicalRetryRefusal'),
  classicalRetryLane: slot.forward('classicalRetryLane'),
  classicalFallbackOffered: slot.forward('classicalFallbackOffered'),
  asksPostQuantum: slot.forward('asksPostQuantum'),
  postQuantumUpgradeOffered: slot.forward('postQuantumUpgradeOffered'),
  // The upgrade itself (#939).
  upgradeRefusal: slot.forward('upgradeRefusal'),
  upgradeMode: slot.forward('upgradeMode'),
  upgradeLane: slot.forward('upgradeLane'),
  upgradeAlgorithms: slot.forward('upgradeAlgorithms'),
  upgradeAlgorithmIds: slot.forward('upgradeAlgorithmIds'),
  upgradeCreationOptions: slot.forward('upgradeCreationOptions'),
  // A population's registration algorithms (#940): THE ONE ANSWER for a
  // person, application and lane, the union `addKey()` is held to, and the
  // finish's list against what was armed.
  registrationOffer: slot.forward('registrationOffer'),
  registrationAlgorithmsAllowed: slot.forward('registrationAlgorithmsAllowed'),
  registrationMode: slot.forward('registrationMode'),
  requestsPostQuantumOnly: slot.forward('requestsPostQuantumOnly'),
  heldToOffer: WebauthnPolicy.heldToOffer,
  laneWriteRule: WebauthnPolicy.laneWriteRule,
  LANES: LANES,
  PQC_ALGS: PQC_ALGS,
  INSECURE_ALGS: INSECURE_ALGS,
  creationOptions: slot.forward('creationOptions'),
  authenticatorKinds: slot.forward('authenticatorKinds'),
  requestOptions: slot.forward('requestOptions'),
  usernamelessOffered: slot.forward('usernamelessOffered'),
  discoverableRequestOptions: slot.forward('discoverableRequestOptions'),
  requireUserVerification: slot.forward('requireUserVerification'),
  attestationSettings: slot.forward('attestationSettings'),
  // Enterprise attestation by RP ID (#1114).
  attestationConveyance: slot.forward('attestationConveyance'),
  conveyanceFor: WebauthnPolicy.conveyanceFor,
  enterpriseRpIdsOf: WebauthnPolicy.enterpriseRpIdsOf,
  enterpriseWriteRule: WebauthnPolicy.enterpriseWriteRule,
  ATTESTATION_FORMATS: ATTESTATION_FORMATS,
  report: slot.forward('report'),
  failureCodeFor: slot.forward('failureCodeFor'),
  // The JOSE-name-to-COSE-identifier map, exported for the tests that assert
  // the offer cannot name something the verifier does not know. DATA, like the
  // two tables it is derived from.
  ALG_IDS: ALG_IDS
};
