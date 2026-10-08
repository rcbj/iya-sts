// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: passkey_policy.ts
//
// ---------------------------------------------------------------------------
// THE PASSKEY POLICY (#527, 2026-10-08): HOW A REALM'S PASSKEYS BEHAVE.
//
// rcbj: "I want to define a new policy (which can be overridden per realm)
// that governs the behavior of passkeys including whether usernameless
// logins are allowed (usernameless logins should be disabled by default).
// When usernameless logins are disabled, the 'use a security key' button
// should request discoverables." It is the fourth kind on Directory →
// Policies (`admin-core/policy_kinds.ts`), sharing nothing with the other
// three but `password_policy.ts`'s interface, and the home the companion
// tickets (#528–#534) add their rows to.
//
// ---------------------------------------------------------------------------
// rcbj's ANSWERS ON #527 (2026-10-08), and so the defaults:
//
//   allowUsernameless        false. Off, the sign-in screen offers no
//                            *Sign in with a passkey* button and no
//                            conditional-mediation autofill, and asks for no
//                            discoverable credential (`allowCredentials` is
//                            always the person's own). On, #474's flow,
//                            user verification required and checked. It
//                            REPLACES the setting `webauthn.usernameless`
//                            (retired, no shim; `REPLACED_SETTINGS`).
//   securityKeyResidentKey   `required`. What *Use a security key* (and an
//                            enrolment that names no kind) asks for WHILE
//                            usernameless is ON. While it is OFF the answer
//                            is `required` whatever this row says (answer 1:
//                            "request discoverables"), and the default is
//                            the same (answer 2: "same as when off"), so
//                            both buttons ask for a discoverable credential
//                            and a key enrolled through either works for a
//                            usernameless sign-in once a realm allows one.
//                            A realm may lower it to spare its keys' few
//                            resident slots. *Create a passkey* is
//                            `required` always (#474). It REPLACES the
//                            setting `webauthn.residentKey`.
//
// #528 (2026-10-08) added a row, and the more secure default is decided on
// the ticket:
//
//   backupEligibility        `allow`. `disallow` refuses a SYNCED passkey —
//                            one whose authenticator data has BE (backup
//                            eligible, WebAuthn Level 3 section 6.1) set — at
//                            registration, in `credentials.addKey()`, the one
//                            writer (STS-AUTHN-0312), and at sign-in, in
//                            `authn.ts`'s `startSessionHere()`, the line
//                            every door reaches (STS-AUTHN-0313). BE never
//                            changes for a credential's life, so the sign-in
//                            half catches a key enrolled before the realm
//                            said no. `allow` is the default because most
//                            passkeys people hold are synced, and refusing
//                            them is a realm's deliberate choice of
//                            device-bound keys (docs/authentication.md).
//
// #529 (2026-10-08) added three rows for a security key's PIN, CTAP 2.1
// section 12.4's minPinLength extension:
//
//   enforcePinLength         off. On, a registration asks the authenticator
//                            for its minimum PIN length (`extensions:
//                            { minPinLength: true }`), the reported value is
//                            recorded on the key (`minPinLength`), and a key
//                            below `minPinLength` is refused at registration
//                            (STS-AUTHN-0314) AND AT SIGN-IN (STS-AUTHN-0315).
//                            Decided on the ticket: the value is recorded and
//                            re-checked at every sign-in, so raising the
//                            minimum stops a key enrolled under a lower one,
//                            as #528 does for BE. A PIN can only be changed
//                            on the key, which re-registering records.
//   minPinLength             4 (CTAP 2.1's own floor), at most 63.
//   pinLengthOnlyIfSupported off: a key that does not report — every key not
//                            configured with this RP ID through CTAP 2.1
//                            `setMinPINLength`, and every platform or synced
//                            passkey — is refused while enforcing. On, such a
//                            key is accepted and only a REPORTED minimum is
//                            held to the rule; the docs warn that it is then
//                            unenforced for most keys.
//
// #531 (2026-10-08) made the WebAuthn hints (Level 3 section 5.4.8) rows:
// `passkeyHints` (`client-device,hybrid`), `securityKeyHints`
// (`security-key`) and `signInHints` (`none`), each an ORDERED list of
// `security-key`, `client-device` and `hybrid`, or `none`. The defaults are
// what the two portal buttons and the sign-in ceremonies sent before, so
// nothing changes until a realm sets them. A hint must not contradict the
// attachment the same request sends — `security-key` and `hybrid` imply
// `cross-platform`, `client-device` implies `platform` — so a save is
// refused for one that does, with the reason, and `hintsFor()` drops one a
// later change of `webauthn.authenticatorAttachment` made contradictory.
//
// #532 (2026-10-08) added `enterpriseSerialAttribute`, empty: the directory
// attribute on a person's entry holding the serial numbers of the security
// keys issued to them. Set, a registration must carry an attestation this
// service TRUSTS (it demands trust, as an AAGUID list does) whose
// certificate names a device serial (`pki.attestationDeviceSerial()`: the
// subject's serialNumber, or Yubico's serial extension), and that serial
// must be one of the person's values (STS-AUTHN-0320); a certificate with no
// serial this service can read is refused (STS-AUTHN-0321). The serial is
// recorded on the key. It is read through a fourth directory hook,
// `personAttributeValues()`, which never answers a secret attribute.
//
// #535 (2026-10-08) made the policy NAMED: beside `cn=default` a realm may
// keep profiles of its own (`cn=<name>`, lower-case letters, digits and
// hyphens), each with the same rows and three SELECTORS — the applications
// it applies to (`stsPasskeySelectApplication`), the groups (by cn or DN,
// `stsPasskeySelectGroup`) and a precedence (`stsPasskeyPrecedence`, 1 to
// 1000, lower first). Decided on the ticket:
//
//   * WHICH APPLIES is the matching profile with the LOWEST precedence — a
//     profile matches when the application the sign-in is for is one of its
//     applications, or the person is in one of its groups — ties broken by
//     name, and `default` when none matches. An application and a person
//     are not ranked against each other by kind: the administrator orders
//     the profiles, and a strict application profile wins over a lenient
//     person profile by being given the lower number.
//   * IT IS SELECTION, NOT AUTHORIZATION, and stays in this module rather
//     than the issuance policy: it decides which rows apply, and the rows'
//     refusals are what decide; a synchronous read at the doors cannot wait
//     on a PDP.
//   * IT IS AMBIENT: `select(username, application)` keeps the choice for
//     the rest of the request — on the REQUEST object `audit.js` holds for
//     every request (`currentRequest()`), so it can never outlive it into
//     the next request on a kept-alive connection, which an
//     AsyncLocalStorage `enterWith()` would — and `read()` with no
//     name reads the selected profile, so every answer above — the doors,
//     `webauthn_policy.ts`'s options, `credentials.addKey()` — reads the
//     profile for the person and application in hand without a parameter.
//     A door that selects nothing reads `default`.
//   * NAMED PROFILES ARE NOT INHERITED: a realm's named profiles are its
//     own, and only `default` follows the default realm's.
//   * Registration selects for the person and, where it is known (the
//     sign-in screen), the application; `/portal/keys` and activation know
//     no application, so only group selectors apply there.
//
// #534 (2026-10-08) added `aggregateDevices`, ON — what the sign-in did
// before: one "Use passkey" ceremony whose `allowCredentials` lists every
// key of the step's role, the authenticator choosing. Off, a person holding
// more than one is shown one choice per key, labelled with its name, and
// the ceremony then names only that key. It changes the request, not what
// is accepted: the assertion is checked against the key it names either way.
//
// #533 (2026-10-08) added the names a ceremony shows: `userDisplayName`
// (empty), an ordered list of up to six directory attributes or
// space-separated groups of them, the first with every value present
// becoming `user.displayName` (the username stays `user.name`); `rpNameExtras`
// (`none`), appending the realm's name and/or `saml.organizationName` to
// `rp.name`; and `credentialLabel` (empty), the label a new key is given,
// `{provider}` and `{kind}` filled in. Every value shown passes
// `displaySafe()`: no control or bidirectional-formatting characters,
// whitespace collapsed, at most 64 characters. The ticket's message key
// translated per language is NOT built: the portal has no translations.
// Empty is what each did before.
//
// #530 (2026-10-08) added `enforceAttestationAtSignIn`, off: on, every
// passkey sign-in holds the key's RECORDED attestation to the attestation
// rules in force now (`webauthn_attestation.ts`'s `signInVerdict()`), so a
// key registered before the rules were tightened stops working
// (STS-AUTHN-0316). Decided on the ticket: a key with no trusted statement
// fails any rule that demands trust, an AAGUID list included.
//
// One profile per realm, inherited from the default realm (answer 3); named
// policies chosen by application or group are #535.
//
// THE OTHER `webauthn.*` SETTINGS STAY SETTINGS, each for a reason, and #527
// says so: `userVerification`, `authenticatorAttachment` and `attestation`
// shape the browser's request and are already realm-overridable; the
// attestation policy, trust anchors, AAGUID list, certification level and
// FIPS rows are #105's verifier's, read by the attestation module and the
// metadata service, and move when #528 and #530 give that verifier policy
// rows to read; `maxKeysPerPerson`, `primaryAllowed` and `mfaAllowed` are the
// authentication policy's neighbours; the algorithms, PQC, timeout, RP and
// origins are process- or protocol-wide.
//
// ---------------------------------------------------------------------------
// WHERE IT LIVES: `cn=default,ou=passkeyPolicies`, and a realm with no entry
// of its own follows the default realm's, then the built-in defaults —
// `authn_policy.ts`'s arrangement exactly; `reset` deletes the realm's own
// entry. Not seeded, for the password policy's reason. In force in both
// modes: it decides how a person signs in.
//
// IT IS A LIBRARY (rule 3) AND A LEAF: `helpers`, `realms`, `error_codes`,
// the instance slot, and the directory through a slot `ldap/ldap_server.js`
// fills. `authn/webauthn_policy.ts` requires it.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
// The attachment setting a hint is held to (#531). `config` is below every
// module here; `helpers` already requires it.
import config = require('./config');
// THE AMBIENT SELECTION (#535), for the rest of a request.
import { AsyncLocalStorage } from 'async_hooks';

const { log } = helpers;

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'bool' | 'enum' | 'int' | 'list' | 'attribute' | 'attributes' |
        'text';
  dflt: boolean | string | number;
  values?: string[];
  min?: number;
  max?: number;
  unit?: string;
  label: string;
  what: string;
}

interface DirectoryHooks {
  allPasskeyPolicies?(): { name?: string; dn: string;
                           attributes?: Record<string, unknown> }[];
  writePasskeyPolicy?(name: string,
                      attributes: Record<string, unknown>): unknown;
  deletePasskeyPolicy?(name: string): unknown;
  personAttributeValues?(username: string, attribute: string): string[];
  personGroups?(username: string): { cn?: string; dn?: string }[];
  [hook: string]: unknown;
}

interface PasskeyProfile {
  name: string;
  stored: boolean;
  inherited: boolean;
  from: 'realm' | 'default-realm' | 'built-in';
  dn: string;
  description: string;
  sources: Record<string, string>;
  problems: string[];
  enforced: boolean;
  [field: string]: any;
}

interface PolicyResult {
  ok: boolean;
  errors?: string[];
  removed?: boolean;
  profile?: PasskeyProfile;
}

interface PasskeyPolicyDeps {
  log: typeof helpers.log;
  realms: {
    isDefault(realm?: unknown): boolean;
    run<T>(realm: unknown, fn: () => T): T;
    DEFAULT_REALM: unknown;
  };
  errorCodes: {
    mark<T>(target: T, code: string): T;
    tag(code: string): string;
  };
}

/**
 * The name of the one passkey policy profile, `default`.
 */
const DEFAULT_PROFILE = 'default';
/**
 * A named profile's name (#535): what a cn may be here.
 */
const PROFILE_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/;
/**
 * The selectors a named profile carries (#535), stored beside its rows.
 */
const SELECTORS = [
  { key: 'selectApplications', attribute: 'stsPasskeySelectApplication',
    what: 'The applications (identifier or client_id) a named passkey ' +
          'policy applies to, at a sign-in for one of them.' },
  { key: 'selectGroups', attribute: 'stsPasskeySelectGroup',
    what: 'The groups (cn or DN) whose members a named passkey policy ' +
          'applies to.' },
  { key: 'precedence', attribute: 'stsPasskeyPrecedence',
    what: 'Which named passkey policy wins where several match: the lowest, ' +
          'from 1 to 1000.' }
];
const DEFAULT_PRECEDENCE = 100;
/**
 * A selection (#535).
 */
interface Selection { name: string; username: string; application: string }
/**
 * The selection of each request in hand, keyed by the request object, so it
 * dies with the request (#535).
 */
const byRequest = new WeakMap<object, Selection>();
/**
 * `withSelection()`'s, for exactly the function it runs (#535).
 */
const scoped = new AsyncLocalStorage<Selection>();
/**
 * `select()`'s outside any request — a test, a job — where there is no
 * request object to keep it on (#535).
 */
const loose = new AsyncLocalStorage<Selection>();

// THESE TWO CARRY NO Entering/Leaving PAIR: every read of the policy asks
// them, several times per ceremony, and a pair would drown the log (the
// style's hot-path exception).
//
// The request this code runs for, from `audit.js`'s ambient source, or null.
// Required LAZILY: `audit.js` is a leaf below this module, and nothing here
// needs it at load.
function ambientRequest(): object | null {
  try {
    return require('./audit').currentRequest() || null;
  } catch (e) {
    log.debug("Caught in ambientRequest(): " + ((e && e.message) || e));
    return null;
  }
}

// The selection in force: `withSelection()`'s, else this request's, else
// one made outside a request.
function currentSelection(): Selection | undefined {
  const inScope = scoped.getStore();
  if (inScope) {
    return inScope;
  }
  const req = ambientRequest();
  return req ? byRequest.get(req) : loose.getStore();
}

/**
 * The resident-key requirements WebAuthn Level 3 section 5.4.6 defines.
 */
const RESIDENT_KEY_VALUES = ['discouraged', 'preferred', 'required'];
/**
 * What `backupEligibility` may be (#528).
 */
const BACKUP_ELIGIBILITY_VALUES = ['allow', 'disallow'];
/**
 * The bounds of `minPinLength` (#529): CTAP 2.1 section 6.5.1's minimum PIN
 * length is 4 Unicode code points and a PIN is at most 63 bytes.
 */
const MIN_PIN_LENGTH = 4;
const MAX_PIN_LENGTH = 63;
/**
 * The WebAuthn hints (Level 3 section 5.4.8) and the attachment each implies
 * (#531). An empty list is written `none`.
 */
const HINTS = ['security-key', 'client-device', 'hybrid'];
const HINT_ATTACHMENT: Record<string, string> = {
  'security-key': 'cross-platform', 'hybrid': 'cross-platform',
  'client-device': 'platform'
};
const NO_HINTS = 'none';
/**
 * What `rpNameExtras` may be (#533).
 */
const RP_NAME_EXTRAS = ['none', 'realm', 'organisation',
                        'realm-and-organisation'];

/**
 * The policy's fields: one table read as the schema, the console form, the API
 * body, the validation of a save and the parse of an entry.
 */
const FIELDS: PolicyField[] = [
  { key: 'allowUsernameless', attribute: 'stsPasskeyAllowUsernameless',
    type: 'bool', dflt: false,
    label: 'Allow a passkey sign-in with no username',
    what: 'OFF BY DEFAULT. On, the sign-in screen offers *Sign in with a ' +
          'passkey* and the username field\'s autofill, which ask the ' +
          'browser for any discoverable credential of this realm (WebAuthn ' +
          'Level 3 section 5.4, `allowCredentials` empty) and sign in the ' +
          'account its user handle names, with user verification required ' +
          'and checked. Off, neither is offered and a sign-in always names ' +
          'the person first. Replaces the setting webauthn.usernameless.' },
  { key: 'securityKeyResidentKey',
    attribute: 'stsPasskeySecurityKeyResidentKey', type: 'enum',
    values: RESIDENT_KEY_VALUES.slice(), dflt: 'required',
    label: 'What "Use a security key" asks for while usernameless sign-in ' +
           'is on',
    what: 'The `residentKey` an enrolment through *Use a security key* (or ' +
          'one that names no kind) sends WHILE usernameless sign-in is ON. ' +
          'While it is off the button always asks `required`, so it makes ' +
          'a discoverable credential as *Create a passkey* does (which asks ' +
          '`required` always). `discouraged` or `preferred` spare a ' +
          'security key\'s few resident slots, at the cost of a key that ' +
          'needs the username to sign in. Replaces the setting ' +
          'webauthn.residentKey.' },
  { key: 'backupEligibility',
    attribute: 'stsPasskeyBackupEligibility', type: 'enum',
    values: BACKUP_ELIGIBILITY_VALUES.slice(), dflt: 'allow',
    label: 'Synced passkeys (backup eligible)',
    what: '`allow` (the default) accepts any passkey. `disallow` accepts ' +
          'only DEVICE-BOUND ones: a passkey whose authenticator says it ' +
          'may be backed up or synced (the BE flag, WebAuthn Level 3 ' +
          'section 6.1) is refused when it is registered and when it signs ' +
          'somebody in, so a synced passkey enrolled before the realm said ' +
          'no stops working too. BE never changes for a credential.' },
  { key: 'enforcePinLength', attribute: 'stsPasskeyEnforcePinLength',
    type: 'bool', dflt: false,
    label: 'Require a minimum security-key PIN length',
    what: 'OFF BY DEFAULT. On, registration asks the authenticator for its ' +
          'minimum PIN length (CTAP 2.1 section 12.4, the minPinLength ' +
          'extension), records it on the key, and refuses a key whose ' +
          'minimum is below the next row, at registration and at every ' +
          'sign-in. A key answers only for relying parties it was ' +
          'configured to tell (CTAP 2.1 setMinPINLength with this RP ID); ' +
          'every other key, and every platform or synced passkey, does not ' +
          'report, and is refused unless the row after next is on.' },
  { key: 'minPinLength', attribute: 'stsPasskeyMinPinLength',
    type: 'int', dflt: MIN_PIN_LENGTH, min: MIN_PIN_LENGTH,
    max: MAX_PIN_LENGTH, unit: 'characters',
    label: 'Minimum security-key PIN length',
    what: 'The shortest PIN a security key may be set to accept, as the key ' +
          'itself reports it, while the row above is on. Between 4 (CTAP ' +
          '2.1\'s own floor) and 63.' },
  { key: 'pinLengthOnlyIfSupported',
    attribute: 'stsPasskeyPinLengthOnlyIfSupported', type: 'bool',
    dflt: false,
    label: 'Accept a key that does not report its PIN length',
    what: 'OFF BY DEFAULT, which is the strict reading: while the PIN ' +
          'length is enforced, a key that does not report it is refused. ' +
          'On, such a key is accepted and only a reported minimum is held ' +
          'to the rule — so the rule then binds only keys configured to ' +
          'report to this relying party.' },
  { key: 'enforceAttestationAtSignIn',
    attribute: 'stsPasskeyEnforceAttestationAtSignIn', type: 'bool',
    dflt: false,
    label: 'Hold every sign-in to the attestation rules in force',
    what: 'OFF BY DEFAULT. The attestation rules (the webauthn.attestation* ' +
          'settings: the policy, the AAGUID list, the certification level ' +
          'and FIPS) are checked when a passkey is registered. On, they are ' +
          'checked again at every sign-in against what was recorded then ' +
          'and the FIDO Metadata Service as it is now, so a key registered ' +
          'before a rule was tightened, or whose model was since reported ' +
          'compromised, stops signing anybody in. A key with no trusted ' +
          'attestation fails every rule that demands one.' },
  { key: 'passkeyHints', attribute: 'stsPasskeyHintsPasskey', type: 'list',
    values: HINTS.slice(), dflt: 'client-device,hybrid',
    label: 'Hints "Create a passkey" sends',
    what: 'The WebAuthn hints (Level 3 section 5.4.8) the portal\'s *Create ' +
          'a passkey* sends, in order, from security-key, client-device and ' +
          'hybrid, or none. They tell the browser which way of making the ' +
          'passkey to lead with. A hint may not contradict ' +
          'webauthn.authenticatorAttachment: client-device implies platform, ' +
          'security-key and hybrid cross-platform.' },
  { key: 'securityKeyHints', attribute: 'stsPasskeyHintsSecurityKey',
    type: 'list', values: HINTS.slice(), dflt: 'security-key',
    label: 'Hints "Use a security key" sends',
    what: 'The hints *Use a security key* sends, in order, or none. The ' +
          'button asks for a cross-platform authenticator, so client-device ' +
          'contradicts it and is refused.' },
  { key: 'signInHints', attribute: 'stsPasskeyHintsSignIn', type: 'list',
    values: HINTS.slice(), dflt: NO_HINTS,
    label: 'Hints a passkey sign-in sends',
    what: 'The hints a sign-in ceremony sends — the passkey step, the ' +
          'sign-in with no username and its autofill — in order, or none ' +
          '(the default: the browser offers every way it knows).' },
  { key: 'enterpriseSerialAttribute',
    attribute: 'stsPasskeyEnterpriseSerialAttribute', type: 'attribute',
    dflt: '',
    label: 'Directory attribute holding a person\'s security-key serials',
    what: 'EMPTY BY DEFAULT: no serial is checked. Set to an attribute of ' +
          'a person\'s entry (for example `serialNumber`, which may hold ' +
          'several values), a security key registers only with a TRUSTED ' +
          'enterprise attestation whose certificate names a device serial ' +
          'that is one of that person\'s values. Needs ' +
          'webauthn.attestation set to enterprise, and the vendor or ' +
          'platform configured to release enterprise attestation to this ' +
          'RP ID; without that the browser sends ordinary attestation and ' +
          'every registration is refused.' },
  { key: 'userDisplayName', attribute: 'stsPasskeyUserDisplayName',
    type: 'attributes', dflt: '',
    label: 'The name a passkey prompt shows for the person',
    what: 'EMPTY BY DEFAULT: the name the sign-in knows, else the ' +
          'username. Otherwise up to six directory attributes in order, ' +
          'separated by commas; a group of attributes separated by spaces ' +
          '(givenName sn) joins their values. The first whose every ' +
          'attribute has a value becomes user.displayName (WebAuthn Level 3 ' +
          'section 5.4.3), with control and direction-changing characters ' +
          'removed and at most 64 characters. The username is always ' +
          'user.name.' },
  { key: 'rpNameExtras', attribute: 'stsPasskeyRpNameExtras', type: 'enum',
    values: RP_NAME_EXTRAS.slice(), dflt: 'none',
    label: 'What a passkey prompt adds to the service\'s name',
    what: '`none` (the default) shows webauthn.rpName alone. `realm`, ' +
          '`organisation` or `realm-and-organisation` append the realm\'s ' +
          'name and/or saml.organizationName, so a person with accounts ' +
          'in several realms can tell the prompts apart.' },
  { key: 'credentialLabel', attribute: 'stsPasskeyCredentialLabel',
    type: 'text', dflt: '',
    label: 'The name a new passkey is given',
    what: 'EMPTY BY DEFAULT: the provider\'s name, else "Passkey" or ' +
          '"Security key". Otherwise this text, with {provider} and {kind} ' +
          'filled in, at most 60 characters. The person may rename it ' +
          'afterwards, as always.' },
  { key: 'aggregateDevices', attribute: 'stsPasskeyAggregateDevices',
    type: 'bool', dflt: true,
    label: 'Offer a person\'s passkeys as one sign-in choice',
    what: 'ON BY DEFAULT: one "Use passkey" step whose request lists every ' +
          'one of the person\'s passkeys, and the browser offers whichever ' +
          'is present. Off, a person with more than one is shown a choice ' +
          'per passkey, by its name, and the request names only that one.' }
];

/**
 * The fields, by key.
 */
const FIELD_BY_KEY: Record<string, PolicyField> = {};
FIELDS.forEach(function (field) {
  FIELD_BY_KEY[field.key] = field;
});

/**
 * The built-in value of every field, in force where no entry says otherwise.
 */
const DEFAULTS: Readonly<Record<string, boolean | string | number>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    out[field.key] = field.dflt;
    return out;
  }, {} as Record<string, boolean | string | number>));

/**
 * The directory schema of `ou=passkeyPolicies`: its container, object class
 * and attributes.
 */
const SCHEMA = {
  container: 'ou=passkeyPolicies',
  objectClasses: [
    { name: 'stsPasskeyPolicy',
      what: 'This service\'s class for a passkey policy: how passkeys behave ' +
            'in this realm. The entry is named by the PROFILE ' +
            '(`cn=default`).' }
  ],
  attributes: FIELDS.map(function (field) {
    return { name: field.attribute, what: field.what };
  }).concat(SELECTORS.map(function (field) {
    return { name: field.attribute, what: field.what };
  })).concat([
    { name: 'description',
      what: 'What the profile is for, for the next person.' }
  ])
};

/**
 * The passkey policy: how a realm's passkeys behave — whether a sign-in may
 * name no username, and what a security key is asked to store.
 *
 * Kept as a `stsPasskeyPolicy` entry in `ou=passkeyPolicies`; a realm with no
 * entry of its own inherits the default realm's, and failing that the built-in
 * defaults.
 */
class PasskeyPolicy {
  /**
   * The name of the one profile.
   */
  static readonly DEFAULT_PROFILE = DEFAULT_PROFILE;
  /**
   * The built-in value of every field.
   */
  static readonly DEFAULTS = DEFAULTS;
  /**
   * The policy's fields.
   */
  static readonly FIELDS = FIELDS;
  /**
   * The fields, by key.
   */
  static readonly FIELD_BY_KEY = FIELD_BY_KEY;
  /**
   * The directory schema of `ou=passkeyPolicies`.
   */
  static readonly SCHEMA = SCHEMA;

  private directory: DirectoryHooks | null = null;
  private warnedAboutNoDirectory = false;

  /**
   * Builds the policy with no directory installed.
   *
   * @param deps - the logger, realms and error codes
   */
  constructor(private readonly deps: PasskeyPolicyDeps) {
    deps.log.debug("Entering PasskeyPolicy.constructor().");
    deps.log.debug("Leaving PasskeyPolicy.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): PasskeyPolicyDeps {
    log.debug("Entering PasskeyPolicy.defaultDeps().");
    log.debug("Leaving PasskeyPolicy.defaultDeps().");
    return { log: log, realms: realms, errorCodes: errorCodes };
  }

  /**
   * Installs the directory hooks the policy is read from and written to; filled
   * by the directory.
   *
   * @param hooks - the directory's policy hooks, or null to remove them
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug('Entering PasskeyPolicy.setDirectory().');
    this.directory = hooks || null;
    log.debug('Leaving PasskeyPolicy.setDirectory(). The register ' +
              (this.directory ? 'has its container.' : 'has none.'));
  }

  /**
   * Returns the installed directory hooks, so a test can put back what was
   * there.
   *
   * @returns the hooks, or null
   */
  directoryInstalled(): DirectoryHooks | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.directoryInstalled().");
    log.debug("Leaving PasskeyPolicy.directoryInstalled().");
    return this.directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.haveDirectory().");
    if (this.directory &&
        typeof this.directory.allPasskeyPolicies === 'function') {
      log.debug("Leaving PasskeyPolicy.haveDirectory().");
      return true;
    }
    if (!this.warnedAboutNoDirectory) {
      this.warnedAboutNoDirectory = true;
      log.warn('passkey_policy: the embedded directory was never loaded, so ' +
               'there is no ou=passkeyPolicies. The BUILT-IN passkey policy ' +
               'is in force and cannot be edited in this process.');
    }
    log.debug("Leaving PasskeyPolicy.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  private firstValue(attributes: Record<string, unknown>,
                     name: string): unknown {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.firstValue().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving PasskeyPolicy.firstValue().");
    return Array.isArray(found) ? (found[0] === undefined ? '' : found[0])
      : (found === undefined || found === null ? '' : found);
  }

  // `service_account_policy.ts`'s parse, with `authn_policy.ts`'s enum.
  // Never guesses.
  private parseField(field: PolicyField,
                     raw: unknown): { value?: boolean | string | number;
                                      problem?: string } {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.parseField().");
    const text = String(raw === undefined || raw === null ? '' : raw).trim();
    if (field.type === 'attributes') {
      // UP TO SIX ITEMS, COMMAS BETWEEN THEM, each one to three attribute
      // names separated by spaces (#533).
      const items = text ? text.split(',').map(function (one) {
        return one.trim().split(/\s+/).filter(Boolean);
      }) : [];
      const bad = items.length > 6 || items.some(function (group) {
        return !group.length || group.length > 3 || group.some(function (n) {
          return !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(n);
        });
      });
      if (bad) {
        log.debug("Leaving PasskeyPolicy.parseField(). Not attributes.");
        return { problem: field.label + ' must be up to six attribute ' +
                          'names or space-separated groups of up to three, ' +
                          'separated by commas; "' + text.slice(0, 60) +
                          '" is not.' };
      }
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { value: items.map(function (group) {
        return group.join(' ');
      }).join(', ') };
    }
    if (field.type === 'text') {
      // A LABEL (#533): what displaySafe() keeps, at most 60 characters.
      const kept = PasskeyPolicy.displaySafe(text, 60);
      if (kept !== text.replace(/\s+/g, ' ')) {
        log.debug("Leaving PasskeyPolicy.parseField(). Not displayable.");
        return { problem: field.label + ' may hold no control or ' +
                          'direction-changing characters and at most 60 ' +
                          'characters.' };
      }
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { value: kept };
    }
    if (field.type === 'attribute') {
      // A DIRECTORY ATTRIBUTE NAME (#532), RFC 4512 section 1.4's descr, or
      // empty for none.
      if (text && !/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(text)) {
        log.debug("Leaving PasskeyPolicy.parseField(). Not a name.");
        return { problem: field.label + ' must be an attribute name — a ' +
                          'letter, then letters, digits and hyphens — or ' +
                          'empty; "' + text.slice(0, 60) + '" is not.' };
      }
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { value: text };
    }
    if (field.type === 'list') {
      // AN ORDERED LIST OF THE ROW'S VALUES (#531), commas or spaces between
      // them, each once; empty or `none` is the empty list, written `none`
      // so a stored empty list is not read as "no value" and its default.
      const items = text.toLowerCase() === NO_HINTS ? []
        : text.split(/[\s,]+/).filter(Boolean);
      const unknown = items.filter(function (one) {
        return (field.values || []).indexOf(one) < 0;
      });
      const twice = items.filter(function (one, at) {
        return items.indexOf(one) !== at;
      });
      if (unknown.length || twice.length || items.length > 8) {
        log.debug("Leaving PasskeyPolicy.parseField(). Not a list.");
        return { problem: field.label + ' must be "none" or a list of ' +
                          (field.values || []).join(', ') + ', each once; ' +
                          '"' + text.slice(0, 60) + '" is not.' };
      }
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { value: items.length ? items.join(',') : NO_HINTS };
    }
    if (field.type === 'int') {
      // `service_account_policy.ts`'s whole number, bounded by the row.
      const value = /^\d{1,6}$/.test(text) ? Number(text) : NaN;
      if (!(value >= Number(field.min) && value <= Number(field.max))) {
        log.debug("Leaving PasskeyPolicy.parseField(). Out of bounds.");
        return { problem: field.label + ' must be a whole number between ' +
                          field.min + ' and ' + field.max + '; "' +
                          text.slice(0, 40) + '" is not.' };
      }
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { value: value };
    }
    if (field.type === 'bool') {
      const lower = text.toLowerCase();
      if (['true', 'on', '1'].indexOf(lower) >= 0) {
        log.debug("Leaving PasskeyPolicy.parseField().");
        return { value: true };
      }
      if (['false', 'off', '0', ''].indexOf(lower) >= 0) {
        log.debug("Leaving PasskeyPolicy.parseField().");
        return { value: false };
      }
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { problem: field.label + ' is a yes-or-no setting, and "' +
                        text.slice(0, 40) + '" is neither.' };
    }
    if ((field.values || []).indexOf(text) < 0) {
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { problem: field.label + ' must be one of ' +
                        (field.values || []).join(', ') + '; "' +
                        text.slice(0, 40) + '" is not.' };
    }
    log.debug("Leaving PasskeyPolicy.parseField().");
    return { value: text };
  }

  // Every value of an attribute, as strings (#535's selectors are lists).
  private allValues(attributes: Record<string, unknown>,
                    name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.allValues().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving PasskeyPolicy.allValues().");
    return (Array.isArray(found) ? found : (found === undefined ||
                                            found === null || found === ''
                                              ? [] : [found]))
      .map(String).filter(Boolean);
  }

  // -------------------------------------------------------------------------
  // WHICH PROFILE APPLIES (#535).
  // -------------------------------------------------------------------------
  // `selectedName()` and `hasSelection()` carry NO Entering/Leaving pair:
  // every answer above calls one on every read, several times per ceremony,
  // and a pair here would drown the log (the style's hot-path exception).
  /**
   * The name of the profile selected for the rest of this request, or
   * `default` where nothing selected one.
   *
   * @returns the profile name
   */
  selectedName(): string {
    const store = currentSelection();
    return store && store.name ? store.name : DEFAULT_PROFILE;
  }

  /**
   * Says whether this request has selected a profile.
   *
   * @returns true once `select()` ran in this request
   */
  hasSelection(): boolean {
    return !!currentSelection();
  }

  /**
   * Works out which profile applies to a person signing in to an
   * application, without selecting it: the matching named profile with the
   * lowest precedence (ties by name), else `default`.
   *
   * @param username - the person, or '' where not yet known
   * @param application - the application, or '' where none is known
   * @returns the profile name
   */
  selectionFor(username: string, application: string): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.selectionFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving PasskeyPolicy.selectionFor(). No directory.");
      return DEFAULT_PROFILE;
    }
    const named = this.directory.allPasskeyPolicies().filter(function (one) {
      return String(one.name || '').toLowerCase() !== DEFAULT_PROFILE;
    });
    if (!named.length) {
      log.debug("Leaving PasskeyPolicy.selectionFor(). None named.");
      return DEFAULT_PROFILE;
    }
    const app = String(application || '').trim().toLowerCase();
    const hook = this.directory.personGroups;
    const groups = username && typeof hook === 'function'
      ? (hook.call(this.directory, username) || []).map(function (g: any) {
        return [String(g.cn || '').toLowerCase(),
                String(g.dn || '').toLowerCase()];
      }).reduce(function (all: string[], two: string[]) {
        return all.concat(two);
      }, []).filter(Boolean)
      : [];
    const matching = named.map((entry) => {
      const at = entry.attributes || {};
      const p = Number(this.firstValue(at, 'stsPasskeyPrecedence'));
      return {
        name: String(entry.name).toLowerCase(),
        precedence: p >= 1 && p <= 1000 ? p : DEFAULT_PRECEDENCE,
        apps: this.allValues(at, 'stsPasskeySelectApplication')
          .map(function (one) { return one.trim().toLowerCase(); }),
        groups: this.allValues(at, 'stsPasskeySelectGroup')
          .map(function (one) { return one.trim().toLowerCase(); })
      };
    }).filter(function (one) {
      return (!!app && one.apps.indexOf(app) >= 0) ||
             one.groups.some(function (g) { return groups.indexOf(g) >= 0; });
    }).sort(function (a, b) {
      return a.precedence - b.precedence || (a.name < b.name ? -1 : 1);
    });
    const out = matching.length ? matching[0].name : DEFAULT_PROFILE;
    log.debug("Leaving PasskeyPolicy.selectionFor(). " + out);
    return out;
  }

  /**
   * Selects the profile for a person and an application for the rest of
   * this request: every `read()` without a name reads it from here on.
   *
   * @param username - the person, or '' where not yet known
   * @param application - the application, or ''
   * @returns the profile name selected
   */
  select(username: unknown, application: unknown): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.select().");
    let name = DEFAULT_PROFILE;
    try {
      name = this.selectionFor(String(username || ''),
                               String(application || ''));
    } catch (e) {
      // A directory that cannot be asked selects the default: the default
      // profile is a realm's baseline, never weaker than nothing.
      log.debug("Caught in PasskeyPolicy.select(): " +
                ((e && e.message) || e));
      name = DEFAULT_PROFILE;
    }
    const chosen = { name: name, username: String(username || ''),
                     application: String(application || '') };
    const req = ambientRequest();
    if (req) {
      byRequest.set(req, chosen);
    } else {
      loose.enterWith(chosen);
    }
    log.debug("Leaving PasskeyPolicy.select(). " + name);
    return name;
  }

  /**
   * Runs `fn` with a profile selected for it, and only for it.
   *
   * @param username - the person
   * @param application - the application
   * @param fn - what to run
   * @returns what `fn` returns
   */
  withSelection<T>(username: unknown, application: unknown, fn: () => T): T {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.withSelection().");
    const name = this.selectionFor(String(username || ''),
                                   String(application || ''));
    log.debug("Leaving PasskeyPolicy.withSelection(). " + name);
    return scoped.run({ name: name, username: String(username || ''),
                        application: String(application || '') }, fn);
  }

  private entryIn(name: string) {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.entryIn().");
    const wanted = name.toLowerCase();
    log.debug("Leaving PasskeyPolicy.entryIn().");
    return this.directory.allPasskeyPolicies().filter(function (entry) {
      return String(entry.name || '').toLowerCase() === wanted;
    })[0] || null;
  }

  // THIS REALM'S OWN ENTRY, THEN THE DEFAULT REALM'S — `authn_policy.ts`'s
  // `entryFor()`.
  private entryFor(name: string):
      { entry: any; from: PasskeyProfile['from'] } {
    const { log, realms } = this.deps;
    log.debug("Entering PasskeyPolicy.entryFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving PasskeyPolicy.entryFor(). No directory.");
      return { entry: null, from: 'built-in' };
    }
    const own = this.entryIn(name);
    if (own) {
      log.debug("Leaving PasskeyPolicy.entryFor(). The realm's own.");
      return { entry: own, from: 'realm' };
    }
    if (realms.isDefault()) {
      log.debug("Leaving PasskeyPolicy.entryFor(). Built-in.");
      return { entry: null, from: 'built-in' };
    }
    const inherited = realms.run(realms.DEFAULT_REALM, () => {
      log.debug("Entering PasskeyPolicy.entryFor() default-realm read.");
      const found = this.entryIn(name);
      log.debug("Leaving PasskeyPolicy.entryFor() default-realm read.");
      return found;
    });
    log.debug("Leaving PasskeyPolicy.entryFor(). " +
              (inherited ? 'Inherited.' : 'Built-in.'));
    return inherited ? { entry: inherited, from: 'default-realm' }
      : { entry: null, from: 'built-in' };
  }

  /**
   * Reads the profile in force: this realm's entry, else the default realm's,
   * else the built-in defaults.
   *
   * Always answers. An unreadable stored value falls back to its default and is
   * named in `problems`.
   *
   * @param name - the profile name; `default` when omitted
   * @returns the profile's values, where each came from, and any problems
   */
  read(name?: string): PasskeyProfile {
    const { log } = this.deps;
    log.debug('Entering PasskeyPolicy.read(). name=' + name);
    // NO NAME IS THE SELECTED PROFILE (#535); a named profile that is not
    // there (removed since it was selected) is the default.
    const asked = String(name || this.selectedName()).toLowerCase();
    const profile = asked !== DEFAULT_PROFILE &&
                    (!this.haveDirectory() || !this.entryIn(asked))
      ? DEFAULT_PROFILE : asked;
    const found = this.entryFor(profile);
    const entry = found.entry;
    const values: Record<string, unknown> = Object.assign({}, DEFAULTS);
    const problems: string[] = [];
    const sources: Record<string, string> = {};
    FIELDS.forEach(function (field) {
      sources[field.key] = 'built-in';
    });
    if (entry) {
      const at = entry.attributes || {};
      FIELDS.forEach((field) => {
        const raw = this.firstValue(at, field.attribute);
        if (raw === '') {
          return;
        }
        const parsed = this.parseField(field, raw);
        if (parsed.problem) {
          problems.push(field.attribute + ' on ' + entry.dn + ' is ' +
                        'unreadable (' + parsed.problem + ') and the ' +
                        'built-in default of ' + field.dflt + ' is in force ' +
                        'instead.');
          return;
        }
        values[field.key] = parsed.value;
        sources[field.key] = found.from === 'realm' ? 'directory'
          : 'default realm';
      });
    }
    const at = entry ? (entry.attributes || {}) : {};
    const precedence = Number(this.firstValue(at, 'stsPasskeyPrecedence'));
    const out = Object.assign({
      name: profile,
      // THE SELECTORS (#535): empty for `default`, which needs none.
      selectApplications: profile === DEFAULT_PROFILE ? []
        : this.allValues(at, 'stsPasskeySelectApplication'),
      selectGroups: profile === DEFAULT_PROFILE ? []
        : this.allValues(at, 'stsPasskeySelectGroup'),
      precedence: profile === DEFAULT_PROFILE ? 0
        : (precedence >= 1 && precedence <= 1000 ? precedence
                                                 : DEFAULT_PRECEDENCE),
      stored: found.from === 'realm',
      inherited: found.from === 'default-realm',
      from: found.from,
      dn: entry ? entry.dn : '',
      description: entry ? String(this.firstValue(entry.attributes || {},
                                                  'description')) : '',
      sources: sources,
      problems: problems,
      // It decides how a person signs in, so it is in force in both modes.
      enforced: true
    }, values) as PasskeyProfile;
    log.debug('Leaving PasskeyPolicy.read(). From ' + found.from + '.');
    return out;
  }

  /**
   * Returns the profile that applies to a person, which is always the one
   * profile (#535 is where a choice between profiles comes).
   *
   * @param username - the person (unused; nothing assigns a profile)
   * @returns the profile in force
   */
  profileFor(username?: unknown): PasskeyProfile {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.profileFor().");
    void username;
    log.debug("Leaving PasskeyPolicy.profileFor().");
    return this.read();
  }

  /**
   * Lists the profiles: the one profile in force.
   *
   * @returns a one-element list
   */
  list(): PasskeyProfile[] {
    const { log } = this.deps;
    log.debug('Entering PasskeyPolicy.list().');
    // `default` first, then this realm's named profiles by precedence
    // (#535).
    const named = this.haveDirectory()
      ? this.directory.allPasskeyPolicies().map(function (one) {
        return String(one.name || '').toLowerCase();
      }).filter(function (one) {
        return one && one !== DEFAULT_PROFILE;
      }) : [];
    const rows = [this.read(DEFAULT_PROFILE)].concat(named.map((one) => {
      return this.read(one);
    }).sort(function (a, b) {
      return a.precedence - b.precedence || (a.name < b.name ? -1 : 1);
    }));
    log.debug('Leaving PasskeyPolicy.list(). ' + rows.length +
              ' profile(s).');
    return rows;
  }

  // -------------------------------------------------------------------------
  // WHAT THE CEREMONIES ASK.
  // -------------------------------------------------------------------------
  /**
   * Says whether a passkey sign-in that names no username is allowed in this
   * realm.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the `allowUsernameless` field
   */
  allowsUsernameless(profile?: PasskeyProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.allowsUsernameless().");
    const rules = profile || this.read();
    log.debug("Leaving PasskeyPolicy.allowsUsernameless().");
    return rules.allowUsernameless === true;
  }

  /**
   * Returns the `residentKey` an enrolment through *Use a security key* (or
   * one naming no kind) asks for: `required` while usernameless sign-in is
   * off (rcbj's answer 1 on #527), and the policy's `securityKeyResidentKey`
   * while it is on.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns `discouraged`, `preferred` or `required`
   */
  securityKeyResidentKey(profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.securityKeyResidentKey().");
    const rules = profile || this.read();
    const asked = String(rules.securityKeyResidentKey);
    const out = rules.allowUsernameless !== true ? 'required'
      : (RESIDENT_KEY_VALUES.indexOf(asked) >= 0 ? asked : 'required');
    log.debug("Leaving PasskeyPolicy.securityKeyResidentKey(). " + out);
    return out;
  }

  /**
   * Says whether this realm refuses a passkey that may be synced: one whose
   * authenticator data has BE set (#528).
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns true where `backupEligibility` is `disallow`
   */
  refusesBackupEligible(profile?: PasskeyProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.refusesBackupEligible().");
    const rules = profile || this.read();
    log.debug("Leaving PasskeyPolicy.refusesBackupEligible().");
    return rules.backupEligibility === 'disallow';
  }

  /**
   * The refusal of a backup-eligible passkey, or null where the realm allows
   * it or the credential is not one (#528). One sentence, so the portal, the
   * sign-in screen and the audit row say the same thing.
   *
   * @param backupEligible - the credential's BE flag; anything but `true` is
   *   not backup eligible (a flag never read is not refused)
   * @param at - `registration` or `sign-in`
   * @param profile - a profile already read; read afresh when omitted
   * @returns `{ code, why }` or null
   */
  backupEligibleRefusal(backupEligible: unknown, at: string,
                        profile?: PasskeyProfile | null):
      { code: string; why: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.backupEligibleRefusal().");
    if (backupEligible !== true || !this.refusesBackupEligible(profile)) {
      log.debug("Leaving PasskeyPolicy.backupEligibleRefusal(). Allowed.");
      return null;
    }
    const registering = at === 'registration';
    const out = {
      code: registering ? 'STS-AUTHN-0312' : 'STS-AUTHN-0313',
      why: 'That passkey can be synced or backed up (its authenticator ' +
           'set the backup-eligible flag), and this realm accepts only ' +
           'device-bound passkeys (the passkey ' +
           'policy\'s backupEligibility is disallow). ' +
           (registering
             ? 'Use a security key, or a passkey kept on this device only.'
             : 'Sign in another way, and register a device-bound key.')
    };
    log.debug("Leaving PasskeyPolicy.backupEligibleRefusal(). " + out.code);
    return out;
  }

  // The attachment each enrolment sends, as `webauthn_policy.ts`'s
  // `creationOptions()` decides it: the setting, or — for *Use a security
  // key* while the setting is `any` — `cross-platform`.
  private attachmentFor(kind: string): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.attachmentFor().");
    const setting = String(config.value('webauthn.authenticatorAttachment') ||
                           'any');
    log.debug("Leaving PasskeyPolicy.attachmentFor().");
    return setting !== 'any' ? setting
      : (kind === 'security-key' ? 'cross-platform' : '');
  }

  // The hints of a list that contradict an attachment.
  private contradicting(list: string[], attachment: string): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.contradicting().");
    log.debug("Leaving PasskeyPolicy.contradicting().");
    return !attachment ? [] : list.filter(function (hint) {
      return HINT_ATTACHMENT[hint] && HINT_ATTACHMENT[hint] !== attachment;
    });
  }

  // A save's hints that contradict the attachment their request sends.
  private hintProblems(values: Record<string, unknown>): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.hintProblems().");
    const out: string[] = [];
    const rows: [string, string][] = [['passkeyHints', 'passkey'],
                                      ['securityKeyHints', 'security-key']];
    rows.forEach(([key, kind]) => {
      const list = PasskeyPolicy.listOf(values[key]);
      const attachment = this.attachmentFor(kind);
      const bad = this.contradicting(list, attachment);
      if (bad.length) {
        out.push(FIELD_BY_KEY[key].label + ': ' + bad.join(', ') +
                 ' contradicts the authenticatorAttachment that request ' +
                 'sends (' + attachment + '); ' +
                 bad.map(function (hint) {
                   return hint + ' implies ' + HINT_ATTACHMENT[hint];
                 }).join(', ') + '.');
      }
    });
    log.debug("Leaving PasskeyPolicy.hintProblems(). " + out.length);
    return out;
  }

  /**
   * A stored hint list as an array: `none` and nothing are the empty list.
   *
   * @param value - the row's value
   * @returns the hints, in order
   */
  static listOf(value: unknown): string[] {
    log.debug("Entering PasskeyPolicy.listOf().");
    const text = String(value === undefined || value === null ? '' : value);
    log.debug("Leaving PasskeyPolicy.listOf().");
    return text === NO_HINTS ? [] : text.split(',').filter(function (one) {
      return HINTS.indexOf(one) >= 0;
    });
  }

  /**
   * The hints a ceremony sends (#531): `passkey` and `security-key` for the
   * two enrolment buttons, `sign-in` for every sign-in ceremony, and `''`
   * for an enrolment naming no kind, which sends none. A hint a later change
   * of `webauthn.authenticatorAttachment` made contradictory is dropped.
   *
   * @param kind - `passkey`, `security-key`, `sign-in` or `''`
   * @param profile - a profile already read; read afresh when omitted
   * @returns the hints, in order
   */
  hintsFor(kind: string, profile?: PasskeyProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.hintsFor(). " + kind);
    const key = kind === 'passkey' ? 'passkeyHints'
      : (kind === 'security-key' ? 'securityKeyHints'
        : (kind === 'sign-in' ? 'signInHints' : ''));
    if (!key) {
      log.debug("Leaving PasskeyPolicy.hintsFor(). No kind.");
      return [];
    }
    const rules = profile || this.read();
    const list = PasskeyPolicy.listOf(rules[key]);
    const bad = kind === 'sign-in' ? []
      : this.contradicting(list, this.attachmentFor(kind));
    if (bad.length) {
      log.warn(errorCodes.tag('STS-AUTHN-0319') + 'passkey policy: the ' +
               key + ' hint(s) ' + bad.join(', ') + ' contradict ' +
               'webauthn.authenticatorAttachment, changed since the policy ' +
               'was saved, and are not sent.');
    }
    log.debug("Leaving PasskeyPolicy.hintsFor().");
    return list.filter(function (one) {
      return bad.indexOf(one) < 0;
    });
  }

  /**
   * A value as a passkey prompt may show it (#533): no control (Cc) or
   * bidirectional-formatting characters, whitespace collapsed and trimmed,
   * at most `max` characters (code points).
   *
   * @param value - the text
   * @param max - the longest it may be
   * @returns the text, safe to show
   */
  static displaySafe(value: unknown, max: number): string {
    log.debug("Entering PasskeyPolicy.displaySafe().");
    const out = Array.from(String(value === undefined || value === null ? ''
                                                                        : value)
      // Whitespace first, so a tab or a line break becomes a space rather
      // than vanishing with the other control characters.
      .replace(/\s+/g, ' ')
      .replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '')
      .replace(/\s+/g, ' ').trim()).slice(0, max).join('').trim();
    log.debug("Leaving PasskeyPolicy.displaySafe().");
    return out;
  }

  /**
   * The `user.displayName` a ceremony sends for a person (#533): the first
   * configured attribute group whose every attribute has a value, made
   * display-safe, or the fallback (what the door sent before) where none is
   * configured or none has a value.
   *
   * @param username - the person
   * @param fallback - what to send otherwise
   * @param profile - a profile already read; read afresh when omitted
   * @returns the display name, at most 64 characters
   */
  displayNameFor(username: string, fallback: string,
                 profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.displayNameFor().");
    const rules = profile || this.read();
    const groups = String(rules.userDisplayName || '').split(',')
      .map(function (one) {
        return one.trim().split(/\s+/).filter(Boolean);
      }).filter(function (group) {
        return group.length > 0;
      });
    const hook = this.directory && this.directory.personAttributeValues;
    let found = '';
    groups.some((group) => {
      const parts = group.map((attribute) => {
        const values = typeof hook === 'function'
          ? (hook.call(this.directory, username, attribute) || []) : [];
        return PasskeyPolicy.displaySafe(values[0], 64);
      });
      if (parts.every(Boolean)) {
        found = PasskeyPolicy.displaySafe(parts.join(' '), 64);
      }
      return !!found;
    });
    log.debug("Leaving PasskeyPolicy.displayNameFor(). " +
              (found ? 'Configured.' : 'The fallback.'));
    return found || PasskeyPolicy.displaySafe(fallback || username, 64) ||
           username;
  }

  /**
   * `rp.name` with the extras the policy appends (#533).
   *
   * @param base - webauthn.rpName
   * @param realmName - the realm's name
   * @param organisation - saml.organizationName
   * @param profile - a profile already read; read afresh when omitted
   * @returns the name a prompt shows for the service
   */
  rpNameFor(base: string, realmName: string, organisation: string,
            profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.rpNameFor().");
    const rules = profile || this.read();
    const extras = String(rules.rpNameExtras || 'none');
    const parts = [PasskeyPolicy.displaySafe(base, 64)];
    if (extras === 'realm' || extras === 'realm-and-organisation') {
      parts.push(PasskeyPolicy.displaySafe(realmName, 64));
    }
    if (extras === 'organisation' || extras === 'realm-and-organisation') {
      parts.push(PasskeyPolicy.displaySafe(organisation, 64));
    }
    log.debug("Leaving PasskeyPolicy.rpNameFor().");
    return parts.filter(Boolean).join(' — ');
  }

  /**
   * The label a new key is given (#533): the policy's `credentialLabel` with
   * `{provider}` and `{kind}` filled in, or '' for the default.
   *
   * @param provider - the provider's name, or ''
   * @param kind - `Passkey` or `Security key`
   * @param profile - a profile already read; read afresh when omitted
   * @returns the label, or '' where the policy sets none
   */
  credentialLabelFor(provider: string, kind: string,
                     profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.credentialLabelFor().");
    const rules = profile || this.read();
    const template = String(rules.credentialLabel || '');
    log.debug("Leaving PasskeyPolicy.credentialLabelFor().");
    return !template ? '' : PasskeyPolicy.displaySafe(template
      .replace(/\{provider\}/g, provider || kind)
      .replace(/\{kind\}/g, kind), 60);
  }

  /**
   * Says whether a person's passkeys are offered as one sign-in choice
   * (#534).
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the `aggregateDevices` field
   */
  aggregatesDevices(profile?: PasskeyProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.aggregatesDevices().");
    const rules = profile || this.read();
    log.debug("Leaving PasskeyPolicy.aggregatesDevices().");
    return rules.aggregateDevices !== false;
  }

  /**
   * The attribute holding a person's security-key serials, or empty (#532).
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the attribute name, or ''
   */
  enterpriseSerialAttribute(profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.enterpriseSerialAttribute().");
    const rules = profile || this.read();
    log.debug("Leaving PasskeyPolicy.enterpriseSerialAttribute().");
    return String(rules.enterpriseSerialAttribute || '');
  }

  /**
   * The refusal of a registration's device serial, or null (#532): none is
   * bound, or the serial is one of the person's.
   *
   * @param username - the person registering the key
   * @param serial - the serial the trusted attestation certificate named,
   *   or nothing
   * @param profile - a profile already read; read afresh when omitted
   * @returns `{ code, why }` or null
   */
  enterpriseSerialRefusal(username: string, serial: unknown,
                          profile?: PasskeyProfile | null):
      { code: string; why: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.enterpriseSerialRefusal().");
    const attribute = this.enterpriseSerialAttribute(profile);
    if (!attribute) {
      log.debug("Leaving PasskeyPolicy.enterpriseSerialRefusal(). Not bound.");
      return null;
    }
    const given = String(serial === undefined || serial === null ? ''
                                                                 : serial)
      .trim();
    if (!given) {
      log.debug("Leaving PasskeyPolicy.enterpriseSerialRefusal(). None.");
      return { code: 'STS-AUTHN-0321',
               why: 'That security key\'s attestation names no device ' +
                    'serial this service can read, and this realm binds ' +
                    'security keys to the serials issued to each person ' +
                    '(the passkey policy\'s enterpriseSerialAttribute). ' +
                    'Use a key from your organisation, registered where ' +
                    'enterprise attestation is enabled.' };
    }
    const hook = this.directory && this.directory.personAttributeValues;
    const held = typeof hook === 'function'
      ? (hook.call(this.directory, username, attribute) || []) : [];
    const mine = held.some(function (one) {
      return String(one).trim().toLowerCase() === given.toLowerCase();
    });
    log.debug("Leaving PasskeyPolicy.enterpriseSerialRefusal(). " +
              (mine ? 'Bound.' : 'Not this person\'s.'));
    return mine ? null : {
      code: 'STS-AUTHN-0320',
      why: 'That security key (serial ' + given.slice(0, 64) + ') is not ' +
           'one issued to you: its serial is not on your directory entry ' +
           '(' + attribute + '). Use the key your organisation issued you.'
    };
  }

  /**
   * Says whether every passkey sign-in is held to the attestation rules in
   * force (#530).
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the `enforceAttestationAtSignIn` field
   */
  enforcesAttestationAtSignIn(profile?: PasskeyProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.enforcesAttestationAtSignIn().");
    const rules = profile || this.read();
    log.debug("Leaving PasskeyPolicy.enforcesAttestationAtSignIn().");
    return rules.enforceAttestationAtSignIn === true;
  }

  /**
   * The PIN-length rule in force (#529): whether it is enforced, the
   * minimum, and whether a key that does not report is accepted.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns `{ enforce, min, onlyIfSupported }`
   */
  pinLengthRule(profile?: PasskeyProfile | null):
      { enforce: boolean; min: number; onlyIfSupported: boolean } {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.pinLengthRule().");
    const rules = profile || this.read();
    const min = Number(rules.minPinLength);
    const out = {
      enforce: rules.enforcePinLength === true,
      min: min >= MIN_PIN_LENGTH && min <= MAX_PIN_LENGTH ? min
        : MIN_PIN_LENGTH,
      onlyIfSupported: rules.pinLengthOnlyIfSupported === true
    };
    log.debug("Leaving PasskeyPolicy.pinLengthRule(). enforce=" +
              out.enforce);
    return out;
  }

  /**
   * The refusal of a key's PIN length, or null (#529): a reported minimum
   * below the rule's, or none reported where the rule needs one.
   *
   * @param reported - the minimum PIN length the key reported; anything but
   *   a whole number is "not reported"
   * @param at - `registration` or `sign-in`
   * @param profile - a profile already read; read afresh when omitted
   * @returns `{ code, why }` or null
   */
  pinLengthRefusal(reported: unknown, at: string,
                   profile?: PasskeyProfile | null):
      { code: string; why: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.pinLengthRefusal().");
    const rule = this.pinLengthRule(profile);
    if (!rule.enforce) {
      log.debug("Leaving PasskeyPolicy.pinLengthRefusal(). Not enforced.");
      return null;
    }
    const value = typeof reported === 'number' && Number.isInteger(reported)
      ? reported : null;
    if (value === null && rule.onlyIfSupported) {
      log.debug("Leaving PasskeyPolicy.pinLengthRefusal(). Not reported, " +
                "and accepted.");
      return null;
    }
    if (value !== null && value >= rule.min) {
      log.debug("Leaving PasskeyPolicy.pinLengthRefusal(). Long enough.");
      return null;
    }
    const registering = at === 'registration';
    const out = {
      code: registering ? 'STS-AUTHN-0314' : 'STS-AUTHN-0315',
      why: (value === null
        ? 'That passkey did not report its minimum PIN length, and this ' +
          'realm requires a PIN of at least ' + rule.min + ' characters ' +
          '(the passkey policy\'s enforcePinLength). A security key ' +
          'reports it only to services it was configured to tell. '
        : 'That passkey accepts a PIN of ' + value + ' characters, and ' +
          'this realm requires at least ' + rule.min + ' (the passkey ' +
          'policy\'s minPinLength). ') +
        (registering
          ? 'Use a key configured with a longer minimum PIN.'
          : 'Sign in another way, and register a key whose minimum PIN ' +
            'is long enough.')
    };
    log.debug("Leaving PasskeyPolicy.pinLengthRefusal(). " + out.code);
    return out;
  }

  /**
   * Describes the policy in sentences, for the page and a save's answer.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the sentences
   */
  describe(profile?: PasskeyProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.describe().");
    const rules = profile || this.read();
    const securityKey = this.securityKeyResidentKey(rules);
    const out = [
      rules.allowUsernameless === true
        ? 'a passkey may sign a person in with no username (user ' +
          'verification required)'
        : 'every sign-in names the person first: no passkey sign-in ' +
          'without a username',
      '"Create a passkey" asks for a discoverable credential ' +
        '(residentKey required)',
      '"Use a security key" asks residentKey ' + securityKey +
        (securityKey === 'required'
          ? ', so it makes a discoverable credential too'
          : ', so a key enrolled through it may need the username to sign in'),
      rules.backupEligibility === 'disallow'
        ? 'only device-bound passkeys: a synced (backup-eligible) passkey ' +
          'is refused at registration and at sign-in'
        : 'synced (backup-eligible) passkeys are accepted',
      this.pinLengthSentence(rules),
      rules.enforceAttestationAtSignIn === true
        ? 'every passkey sign-in is held to the attestation rules in force'
        : 'the attestation rules are checked when a passkey is registered',
      '"Create a passkey" hints ' + this.hintSentence(rules.passkeyHints) +
        '; "Use a security key" ' +
        this.hintSentence(rules.securityKeyHints) + '; a sign-in ' +
        this.hintSentence(rules.signInHints),
      rules.enterpriseSerialAttribute
        ? 'a security key registers only with a trusted enterprise ' +
          'attestation naming a serial in the person\'s ' +
          rules.enterpriseSerialAttribute
        : 'no security-key serial is checked',
      'a passkey prompt shows ' + (rules.userDisplayName
        ? 'the person\'s ' + rules.userDisplayName
        : 'the person\'s name as the sign-in knows it') +
        (rules.rpNameExtras && rules.rpNameExtras !== 'none'
          ? ', and the service\'s name with its ' + rules.rpNameExtras
          : ''),
      rules.aggregateDevices === false
        ? 'a person with several passkeys chooses one at sign-in'
        : 'a person\'s passkeys are offered as one sign-in choice'
    ];
    log.debug("Leaving PasskeyPolicy.describe().");
    return out;
  }

  // A hint list in words (#531).
  private hintSentence(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.hintSentence().");
    const list = PasskeyPolicy.listOf(value);
    log.debug("Leaving PasskeyPolicy.hintSentence().");
    return list.length ? list.join(', ') : 'nothing';
  }

  // The PIN-length rule in a sentence (#529).
  private pinLengthSentence(rules: PasskeyProfile): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.pinLengthSentence().");
    const rule = this.pinLengthRule(rules);
    log.debug("Leaving PasskeyPolicy.pinLengthSentence().");
    return !rule.enforce
      ? 'no minimum PIN length is asked of a security key'
      : 'a security key must report a minimum PIN of at least ' + rule.min +
        ' characters, at registration and at sign-in' +
        (rule.onlyIfSupported ? '; a key that does not report is accepted'
                              : '; a key that does not report is refused');
  }

  // -------------------------------------------------------------------------
  // WRITING.
  // -------------------------------------------------------------------------
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.checkProfileName().");
    const text = String(name || DEFAULT_PROFILE).trim();
    // `default`, or a named profile (#535): lower-case letters, digits and
    // hyphens, which is what a cn here may be.
    if (text !== DEFAULT_PROFILE && !PROFILE_NAME.test(text)) {
      log.debug("Leaving PasskeyPolicy.checkProfileName().");
      return 'A passkey policy profile is "' + DEFAULT_PROFILE + '" or a ' +
             'name of lower-case letters, digits and hyphens, at most 64; "' +
             text.slice(0, 64) + '" is neither.';
    }
    log.debug("Leaving PasskeyPolicy.checkProfileName().");
    return null;
  }

  // A named profile's selectors as sent (#535): lists by comma, line or
  // array, each value at most 256 characters with no control character, at
  // most 32 of each, and a precedence from 1 to 1000 (100 when omitted).
  private checkSelectors(given: Record<string, any>):
      { applications: string[]; groups: string[]; precedence: number;
        problems: string[] } {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.checkSelectors().");
    const problems: string[] = [];
    const listOf = function (raw: unknown, what: string): string[] {
      log.debug("Entering checkSelectors() listOf().");
      const items = (Array.isArray(raw) ? raw : String(raw === undefined ||
                                                       raw === null ? ''
                                                                    : raw)
        .split(/[,\n]/)).map(function (one) {
          return String(one).trim();
        }).filter(Boolean);
      if (items.length > 32 || items.some(function (one) {
        return one.length > 256 || /[\u0000-\u001f\u007f]/.test(one);
      })) {
        problems.push(what + ' must be at most 32 values of at most 256 ' +
                      'characters each, with no control character.');
      }
      log.debug("Leaving checkSelectors() listOf().");
      return items.slice(0, 32);
    };
    const applications = listOf(given.selectApplications,
                                'The applications a named profile applies to');
    const groups = listOf(given.selectGroups,
                          'The groups a named profile applies to');
    const raw = given.precedence;
    const precedence = raw === undefined || raw === null || raw === ''
      ? DEFAULT_PRECEDENCE : Number(raw);
    if (!(Number.isInteger(precedence) && precedence >= 1 &&
          precedence <= 1000)) {
      problems.push('The precedence of a named profile is a whole number ' +
                    'from 1 to 1000; "' + String(raw).slice(0, 20) +
                    '" is not.');
    }
    if (!applications.length && !groups.length) {
      problems.push('A named profile with no application and no group ' +
                    'would apply to nobody; name at least one.');
    }
    log.debug("Leaving PasskeyPolicy.checkSelectors(). " + problems.length +
              " problem(s).");
    return { applications: applications, groups: groups,
             precedence: precedence, problems: problems };
  }

  /**
   * Validates a whole profile as sent; every field is required, except an
   * unticked checkbox on the console's form.
   *
   * @param given - the submitted fields
   * @returns the parsed values and the problems found
   */
  validate(given?: Record<string, any> | null) {
    const { log } = this.deps;
    log.debug('Entering PasskeyPolicy.validate().');
    const body = given || {};
    const values: Record<string, boolean | string | number> = {};
    const problems: string[] = [];
    FIELDS.forEach((field) => {
      let raw = body[field.key];
      if (raw === undefined && field.type === 'bool' &&
          body.form === 'console') {
        raw = 'false';
      }
      if (raw === undefined) {
        problems.push('`' + field.key + '` (' + field.label + ') is ' +
                      'required. A save replaces the whole profile, so ' +
                      'every field is sent.');
        return;
      }
      if (typeof raw === 'boolean' || typeof raw === 'number') {
        raw = String(raw);
      }
      const parsed = this.parseField(field, raw);
      if (parsed.problem) {
        problems.push(parsed.problem);
        return;
      }
      values[field.key] = parsed.value;
    });
    // HINTS THAT CONTRADICT THE ATTACHMENT THE SAME REQUEST SENDS (#531).
    this.hintProblems(values).forEach(function (one) {
      problems.push(one);
    });
    log.debug('Leaving PasskeyPolicy.validate(). ' + problems.length +
              ' problem(s).');
    return { values: values, problems: problems };
  }

  /**
   * Saves this realm's profile, replacing it whole.
   *
   * @param name - the profile name
   * @param given - every field of the profile
   * @returns `ok` and the profile now in force, or `ok: false` with `errors`
   */
  save(name: unknown, given?: Record<string, any> | null): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering PasskeyPolicy.save(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving PasskeyPolicy.save(). Not a profile that can ' +
                'exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0308');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    const checked = this.validate(given);
    // A NAMED PROFILE'S SELECTORS (#535), refused with the rows.
    const selectors = which === DEFAULT_PROFILE ? null
      : this.checkSelectors(given || {});
    if (selectors) {
      selectors.problems.forEach(function (one) {
        checked.problems.push(one);
      });
    }
    if (checked.problems.length) {
      log.debug('Leaving PasskeyPolicy.save(). The values were refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-AUTHN-0309');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving PasskeyPolicy.save(). No directory.');
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep a passkey policy. ' +
                        'ou=passkeyPolicies IS the register.'] },
                             'STS-AUTHN-0310');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'stsPasskeyPolicy'],
      description: String((given && given.description) || '').slice(0, 1024)
    };
    FIELDS.forEach(function (field) {
      const value = checked.values[field.key];
      attributes[field.attribute] = field.type === 'bool'
        ? (value ? 'TRUE' : 'FALSE') : String(value);
    });
    if (!attributes.description) {
      delete attributes.description;
    }
    if (selectors) {
      attributes.stsPasskeySelectApplication = selectors.applications;
      attributes.stsPasskeySelectGroup = selectors.groups;
      attributes.stsPasskeyPrecedence = String(selectors.precedence);
    }
    const written = this.directory.writePasskeyPolicy(which, attributes);
    if (!written) {
      log.debug('Leaving PasskeyPolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-AUTHN-0311');
    }
    log.debug('Leaving PasskeyPolicy.save(). Stored.');
    return { ok: true, profile: this.read(which) };
  }

  /**
   * Deletes this realm's own entry, so it inherits again.
   *
   * @param name - the profile name
   * @returns `ok`, whether an entry was removed, and the profile now in force
   */
  reset(name: unknown): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering PasskeyPolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving PasskeyPolicy.reset(). Not a profile that can ' +
                'exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0308');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    if (!this.haveDirectory()) {
      log.debug('Leaving PasskeyPolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(which) };
    }
    // A NAMED PROFILE IS REMOVED WHOLE (#535); `default` goes back to
    // inheriting.
    const removed = !!this.directory.deletePasskeyPolicy(which);
    log.debug('Leaving PasskeyPolicy.reset(). ' +
              (removed ? 'Removed.' : 'Nothing stored.'));
    return { ok: true, removed: removed,
             profile: this.read(which) };
  }

  /**
   * Says whether the policy is enforced; it is, in both modes.
   *
   * @returns true
   */
  enforced(): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.enforced().");
    log.debug("Leaving PasskeyPolicy.enforced().");
    return true;
  }
}

const slot = new InstanceSlot<PasskeyPolicy>(
  'common/passkey_policy',
  () => new PasskeyPolicy(PasskeyPolicy.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The passkey policy (#527): how a realm's passkeys behave. The fourth policy
 * on Directory > Policies. The exports forward to the instance the
 * composition root installs.
 *
 * @namespace
 */
export = {
  PasskeyPolicy: PasskeyPolicy,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: PasskeyPolicy): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  DEFAULT_PROFILE: PasskeyPolicy.DEFAULT_PROFILE,
  DEFAULTS: PasskeyPolicy.DEFAULTS,
  FIELDS: PasskeyPolicy.FIELDS,
  FIELD_BY_KEY: PasskeyPolicy.FIELD_BY_KEY,
  SCHEMA: PasskeyPolicy.SCHEMA,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileFor: slot.forward('profileFor'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  allowsUsernameless: slot.forward('allowsUsernameless'),
  securityKeyResidentKey: slot.forward('securityKeyResidentKey'),
  refusesBackupEligible: slot.forward('refusesBackupEligible'),
  backupEligibleRefusal: slot.forward('backupEligibleRefusal'),
  pinLengthRule: slot.forward('pinLengthRule'),
  enforcesAttestationAtSignIn: slot.forward('enforcesAttestationAtSignIn'),
  hintsFor: slot.forward('hintsFor'),
  select: slot.forward('select'),
  selectionFor: slot.forward('selectionFor'),
  selectedName: slot.forward('selectedName'),
  hasSelection: slot.forward('hasSelection'),
  withSelection: slot.forward('withSelection'),
  SELECTORS: SELECTORS,
  enterpriseSerialAttribute: slot.forward('enterpriseSerialAttribute'),
  displayNameFor: slot.forward('displayNameFor'),
  aggregatesDevices: slot.forward('aggregatesDevices'),
  rpNameFor: slot.forward('rpNameFor'),
  credentialLabelFor: slot.forward('credentialLabelFor'),
  displaySafe: PasskeyPolicy.displaySafe,
  enterpriseSerialRefusal: slot.forward('enterpriseSerialRefusal'),
  listOf: PasskeyPolicy.listOf,
  pinLengthRefusal: slot.forward('pinLengthRefusal'),
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
