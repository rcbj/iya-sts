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
//   allowUsernameless        TRUE since 2026-10-10 (rcbj: "Enable webauthn
//                            usernameless logins by default"; it was false
//                            on #527's answer). Off, the sign-in screen offers no
//                            *Sign in with a passkey* button and no
//                            conditional-mediation autofill, and asks for no
//                            discoverable credential (`allowCredentials` is
//                            always the person's own). On, #474's flow,
//                            user verification required and checked. It
//                            REPLACES the setting `webauthn.usernameless`
//                            (retired, no shim; `REPLACED_SETTINGS`).
//   requireUsernameless      FALSE (#608, rcbj 2026-10-13). On, and only
//                            for an application whose appAuthnMechanism is
//                            `webauthn` and nothing else, the sign-in
//                            screen asks for no username: *Sign in with a
//                            passkey* is the way in, and a sign-in that
//                            names somebody is refused (STS-AUTHN-0333).
//                            It needs allowUsernameless, and a save
//                            asking for one without the other is refused.
//                            THE `default` PROFILE DOES NOT HOLD THE ADMIN
//                            CONSOLE, THE DEBUGGER OR THE PORTAL TO IT
//                            (rcbj): those three are held only by a named
//                            profile that selects the application itself
//                            — `authn.ts`'s `usernamelessRequired()`
//                            decides, because the application's mechanisms
//                            and the hosted surfaces are not this leaf's.
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
// #718 (2026-10-19) added `postQuantumRequired`, `off`: `sign-in` refuses
// a passkey whose signature algorithm is not post-quantum (RFC 9964's
// ML-DSA-44, -65 or -87) when it signs somebody in (STS-AUTHN-0356), and
// `registration-and-sign-in` refuses one at registration too
// (STS-AUTHN-0355). rcbj's decisions on the ticket: three values, both
// roles (the primary credential and the second factor), and the passkey
// step's `allowCredentials` narrowed to the person's post-quantum keys
// while it is required. THE FACT IS THE ALGORITHM, NOT #643'S LANE: with
// the lanes off an authenticator that can make ML-DSA does so in the one
// lane, and its row records no lane, so a rule on the lane would refuse a
// post-quantum key. `question()` computes `postQuantum` from the algorithm,
// once, and carries the algorithm and the lane beside it for a realm's own
// rules. A save that requires it while the realm offers no ML-DSA at all
// is refused (STS-AUTHN-0357): nobody could enrol a passkey that satisfies
// it. Selected per application or group like every row, which is how
// "application X requires a post-quantum passkey" is said (#535).
//
// #724 (2026-10-19) added `recoveryAssurance`: whether a way back into the
// account that asks for no passkey — a password reset link, an activation
// link, a recovery code, an emailed code or link — may restore access for a
// person who holds a passkey.
//
//   recoveryAssurance        `any` IN DEVELOPMENT, `not-weaker` IN PRODUCT
//                            (rcbj's decision on #724, 2026-10-19: "not-weaker
//                            in product is fine for now"; the built-in
//                            default asks `mode.recoversWeakerThanPasskeys()`).
//                            `any` is what this service did before. Under
//                            `not-weaker` the first session after a recovery
//                            that is not a passkey sign-in reaches no
//                            application (STS-AUTHN-0381): the sign-in
//                            screen asks for a passkey to be registered,
//                            held to this profile's registration rules, and
//                            then for a sign-in with it. Under
//                            `operator-only` the self-service doors are
//                            refused for such a person as well
//                            (STS-AUTHN-0380) and only an operator's reset
//                            or activation link remains, the session it leads
//                            to limited as under `not-weaker`. THE ONLY
//                            OPTIONAL ROW ON A SAVE: absent, the built-in
//                            default is kept, so a caller that sent the whole
//                            profile before the row existed is not refused.
//                            The refusals are rules of the issuance policy
//                            (`recover-account`), as #536's are. The pending
//                            recovery is `stsRecoveryPending` on the person's
//                            entry, and the reset link records who issued it
//                            (`stsPasswordResetSource`): SCHEMA's
//                            `personAttributes`.
//
// #941 (2026-10-23) added `attestationAlgorithms`, `none`: the algorithms
// a passkey's ATTESTATION must be signed with — not the passkey's own
// (#718's row), the statement's and every certificate's of its chain, leaf
// to anchor, as `authn/webauthn_attestation.ts` records them. A list of
// `post-quantum` (any ML-DSA, SLH-DSA or composite ML-DSA signature),
// `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, `slh-dsa` and
// `composite-ml-dsa`; each signature must be one some entry allows. Set,
// it DEMANDS A TRUSTED STATEMENT, as an AAGUID list does: an algorithm in a
// chain nobody vouches for is the authenticator's say-so, and anybody can
// mint an ML-DSA chain. Self and none attestation carry no certificate and
// are refused. Decided by the issuance policy as every row is (reason
// `attestation-algorithm`): at registration where every key is written
// (STS-AUTHN-0411), and at sign-in only while `enforceAttestationAtSignIn`
// holds sign-ins to the attestation rules, by what was recorded
// (STS-AUTHN-0412) — so a key registered before #941, which recorded no
// algorithms, stops signing in then. OPTIONAL ON A SAVE, as #724's row is,
// so a caller sending the whole profile as it was is not refused.
//
// #946 (2026-10-23) added `postQuantumAllowCredentials`: `realm` (the
// default, optional on a save), `narrow` or `list-and-refuse` — how the
// passkey step's `allowCredentials` is built while `postQuantumRequired`
// applies at sign-in. `realm` follows the realm's setting of the same name
// (`webauthn.postQuantumAllowCredentials`, `narrow` by default), which is
// what the ticket asked for: per realm, or per policy. `narrow` is #718's
// filter; `list-and-refuse` names every key and lets the issuance policy's
// `post-quantum` rule refuse a classical assertion after the ceremony, with
// the sign-in screen's panel saying why. It decides nothing itself, and is
// sent to the issuance policy resolved, as a policy fact, for a realm's
// own rules.
//
// #940 (2026-10-23) added two rows that give a POPULATION its own
// registration algorithms (rule 3cu; rcbj's decision on the ticket: on the
// profiles, selected by application or group as `postQuantumRequired` is,
// falling back to the realm settings):
//
//   registrationAlgorithms   `realm` (an empty list, written `realm` rather
//                            than `none`, because empty means "the realm's
//                            webauthn.algorithms", not "no algorithm"): an
//                            ORDERED list of the algorithms a registration
//                            offers in place of the realm's.
//   registrationMode         `realm` (follow webauthn.pqcOnly and
//                            webauthn.pqcAlongsideClassical), `pq-only`
//                            (ML-DSA only, as pqcOnly), `pq-first` (ML-DSA
//                            first, then classical — the realm's pqcOnly is
//                            NOT applied to this population) or
//                            `classical-only` (no ML-DSA, and no
//                            post-quantum lane).
//
// Named `registration…` because they shape what a REGISTRATION offers and
// nothing else: `postQuantumRequired` accepts or refuses a passkey, and
// `attestationAlgorithms` is the attestation's. Both OPTIONAL on a save,
// `recoveryAssurance`'s arrangement. This leaf stores and checks them;
// `authn/webauthn_policy.ts` resolves them into `pubKeyCredParams`
// (`registrationOffer()`, the one answer every registration door asks).
// A save is refused where they contradict another row (STS-AUTHN-0430,
// 0431); a key outside the list is refused at the write by the issuance
// policy (`profile-algorithm`, STS-AUTHN-0432).
// #945 (2026-10-23) added `adminEnrolment`, `off` (optional on a save): `on`
// lets an administrator enrol a passkey for a person from the console or
// `/admin-api` — a registration ceremony run in the ADMINISTRATOR'S browser
// for the person's user handle and lane, verified as the person's own is
// (rcbj's decision on the ticket; no import of a registration made
// elsewhere). Asked of the PERSON's profile, at the begin as a courtesy and
// at `credentials.addKey()`, the one writer, as the enforcement
// (STS-AUTHN-0440). A key so enrolled carries `enrolledBy`, and the
// registration question carries it as the `enrolment` fact group, so a
// realm's own rule can forbid it by policy; no built-in rule reads it.
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
// the instance slot, the issuance gate (#536 — itself a leaf over `helpers`,
// `config` and `error_codes`, which reaches the engine lazily), and the
// directory through a slot `ldap/ldap_server.js` fills.
// `authn/webauthn_policy.ts` requires it.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
// The sentences `describe()` makes are filled from SENTENCES below, so the
// server can translate them into a console reader's language (#543).
import serverProse = require('./server_prose');
// The attachment setting a hint is held to (#531). `config` is below every
// module here; `helpers` already requires it.
import config = require('./config');
// THE ISSUANCE GATE (#536): whether a passkey may be registered or may sign
// somebody in is a question to the issuance policy, asked through it.
import issuanceGate = require('./issuance_gate');
// THE BUILT-IN DEFAULT OF `recoveryAssurance` (#724), which differs by mode.
// A leaf over `config` and `error_codes`, both already below this module.
import mode = require('./mode');
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
  // #724: a row a save may leave out, keeping the built-in default.
  optional?: boolean;
  // #940: a `list` row's word for the empty list (`none` when unset) and
  // its longest (eight when unset).
  empty?: string;
  maxItems?: number;
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
    currentId?(): string;
    DEFAULT_REALM: unknown;
  };
  errorCodes: {
    mark<T>(target: T, code: string): T;
    tag(code: string): string;
  };
  // The issuance gate's passkey question (#536).
  gate: {
    checkPasskey(request: Record<string, any>): {
      verdict: string; code?: string; reason?: string; decidedBy?: string;
      why?: string;
    };
  };
  // Whether the realm in hand offers any ML-DSA algorithm at registration
  // (#718), asked at a save that requires a post-quantum passkey.
  // `authn/webauthn_policy.ts` answers, and it requires this module, so the
  // default reaches it lazily. Since #940 it is asked of the ROWS being
  // saved (`rows`), which may give the population its own list and mode.
  offersPostQuantum(rows?: RegistrationRows): boolean;
  // Every algorithm a registration under a profile's rows may make (#940):
  // the union over the lanes and the classical retry, as
  // `webauthn_policy.ts`'s `registrationAlgorithmsAllowed()` answers it.
  // Reached lazily, for the same reason.
  registrationAlgorithmsAllowed(rows: RegistrationRows): string[];
}

// The rows a registration's algorithms are resolved from (#940), handed to
// `webauthn_policy.ts` where they are not the selected profile's own.
interface RegistrationRows {
  registrationAlgorithms: string[];
  registrationMode: string;
  postQuantumRequired: string;
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
// ---------------------------------------------------------------------------
// THE SENTENCES `describe()` MAKES, as templates (#543 phase 2) — one copy,
// filled there with `ServerProse.fill()` and matched by
// `common/server_prose.ts` to refill in a console reader's language. A
// `param.` key is a phrase that only ever stands inside another sentence.
// ---------------------------------------------------------------------------
const SENTENCES: Readonly<Record<string, string>> = Object.freeze({
  usernameless: 'a passkey may sign a person in with no username (user ' +
    'verification required)',
  noUsernameless: 'every sign-in names the person first: no passkey ' +
    'sign-in without a username',
  requireUsernameless: 'an application that signs in with a passkey alone ' +
    'asks for no username: a passkey sign-in with no username is the only ' +
    'way in',
  createPasskey: '"Create a passkey" asks for a discoverable credential ' +
    '(residentKey required)',
  securityKeyRequired: '"Use a security key" asks residentKey {{value}}, so ' +
    'it makes a discoverable credential too',
  securityKeyOther: '"Use a security key" asks residentKey {{value}}, so a ' +
    'key enrolled through it may need the username to sign in',
  deviceBound: 'only device-bound passkeys: a synced (backup-eligible) ' +
    'passkey is refused at registration and at sign-in',
  synced: 'synced (backup-eligible) passkeys are accepted',
  noPinLength: 'no minimum PIN length is asked of a security key',
  pinLengthAccepted: 'a security key must report a minimum PIN of at least ' +
    '{{n}} characters, at registration and at sign-in; a key that does ' +
    'not report is accepted',
  pinLengthRefused: 'a security key must report a minimum PIN of at least ' +
    '{{n}} characters, at registration and at sign-in; a key that does ' +
    'not report is refused',
  attestationAtSignIn: 'every passkey sign-in is held to the attestation ' +
    'rules in force',
  attestationAtRegistration: 'the attestation rules are checked when a ' +
    'passkey is registered',
  hints: '"Create a passkey" hints {{passkey}}; "Use a security key" ' +
    '{{securityKey}}; a sign-in {{signIn}}',
  'param.nothing': 'nothing',
  enterpriseSerial: 'a security key registers only with a trusted ' +
    'enterprise attestation naming a serial in the person\'s {{attribute}}',
  noEnterpriseSerial: 'no security-key serial is checked',
  promptAttribute: 'a passkey prompt shows the person\'s {{attribute}}',
  promptAttributeExtras: 'a passkey prompt shows the person\'s ' +
    '{{attribute}}, and the service\'s name with its {{extras}}',
  promptName: 'a passkey prompt shows the person\'s name as the sign-in ' +
    'knows it',
  promptNameExtras: 'a passkey prompt shows the person\'s name as the ' +
    'sign-in knows it, and the service\'s name with its {{extras}}',
  chooseOne: 'a person with several passkeys chooses one at sign-in',
  aggregate: 'a person\'s passkeys are offered as one sign-in choice',
  postQuantumOff: 'a passkey signs in and registers whatever its signature ' +
    'algorithm',
  postQuantumSignIn: 'only a post-quantum (ML-DSA) passkey signs a person ' +
    'in; a classical one may still be registered',
  postQuantumEverywhere: 'only a post-quantum (ML-DSA) passkey is ' +
    'registered or signs a person in',
  attestationAlgorithms: 'a passkey registers only with a trusted ' +
    'attestation whose statement and certificate chain are signed with ' +
    '{{algorithms}}',
  recoveryAny: 'an account recovery restores access at once, whatever ' +
    'passkey the person holds',
  recoveryNotWeaker: 'after an account recovery, a person who holds a ' +
    'passkey reaches no application until a passkey satisfying this ' +
    'policy has signed them in',
  recoveryOperatorOnly: 'a person who holds a passkey recovers their ' +
    'account only through an administrator, and then reaches no ' +
    'application until a passkey satisfying this policy has signed them in',
  // #940: said only where the profile sets a registration row of its own.
  registrationList: 'a passkey registration offers {{algorithms}}, in that ' +
    'order, in place of the realm\'s list',
  registrationPqOnly: 'a passkey registration offers only post-quantum ' +
    '(ML-DSA) algorithms, from {{algorithms}}, and no classical retry',
  registrationPqFirst: 'a passkey registration offers post-quantum ' +
    '(ML-DSA) algorithms first and the classical ones after them, from ' +
    '{{algorithms}}',
  registrationClassicalOnly: 'a passkey registration offers only classical ' +
    'algorithms, from {{algorithms}}: no post-quantum passkey is made',
  'param.realmAlgorithms': 'the realm\'s webauthn.algorithms',
  adminEnrolment: 'an administrator may enrol a passkey for a person, in ' +
    'the administrator\'s own browser, verified as the person\'s own is'
});

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
 * What `postQuantumRequired` may be (#718), in the order of strictness.
 */
const POST_QUANTUM_REQUIRED_VALUES = ['off', 'sign-in',
                                      'registration-and-sign-in'];
/**
 * The post-quantum WebAuthn signature algorithms (#718): RFC 9964's ML-DSA,
 * as JOSE names. THE ONE COPY: `authn/webauthn_policy.ts`'s `PQC_ALGS` is
 * this list, because that module requires this one and this one, a leaf,
 * cannot require it back.
 */
const POST_QUANTUM_ALGORITHMS: ReadonlyArray<string> =
  Object.freeze(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']);
/**
 * What `attestationAlgorithms` may list (#941): `post-quantum` allows any
 * post-quantum signature (ML-DSA, SLH-DSA, composite ML-DSA), the others
 * one parameter set or family. Empty, written `none`, is no rule.
 */
const ATTESTATION_ALGORITHM_VALUES: ReadonlyArray<string> =
  Object.freeze(['post-quantum', 'ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87',
                 'slh-dsa', 'composite-ml-dsa']);
/**
 * What `postQuantumAllowCredentials` may be (#946): `realm` follows the
 * realm's `webauthn.postQuantumAllowCredentials`.
 */
const POST_QUANTUM_ALLOW_CREDENTIALS = ['realm', 'narrow', 'list-and-refuse'];
/**
 * What `registrationMode` may be (#940): `realm` follows webauthn.pqcOnly
 * and webauthn.pqcAlongsideClassical.
 */
const REGISTRATION_MODES = ['realm', 'pq-only', 'pq-first', 'classical-only'];
/**
 * How an empty `registrationAlgorithms` is written (#940): the realm's
 * webauthn.algorithms, so the word is `realm` and not `none`.
 */
const REALM_LIST = 'realm';
// THE ALGORITHMS A PROFILE'S LIST MAY NAME (#940): `webauthn.algorithms`'
// own values — the verifier's table, which that row mirrors — read from the
// row so the two cannot drift, less RS1. SHA-1 is offered only by the
// development-only `webauthn.insecureAlgorithms`, a realm-wide switch, and a
// population's list is not a way to name it. The literal is for a process
// whose settings table lacks the row, which none does.
/**
 * The algorithms `registrationAlgorithms` may list (#940), as JOSE names.
 */
const REGISTRATION_ALGORITHM_VALUES: ReadonlyArray<string> = Object.freeze(
  ((((config.SETTINGS || []) as any[]).filter(function (row) {
    return row && row.key === 'webauthn.algorithms';
  })[0] || {}).csvValues as string[] ||
   ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'ES256', 'RS256'])
    .filter(function (name) {
      return name !== 'RS1';
    }));
/**
 * What `adminEnrolment` may be (#945).
 */
const ADMIN_ENROLMENT_VALUES = ['off', 'on'];
/**
 * What `recoveryAssurance` may be (#724).
 */
const RECOVERY_ASSURANCE = ['any', 'not-weaker', 'operator-only'];
/**
 * The recovery doors (#724), and which are the person's own. An operator's
 * door — a reset link or a generated password an administrator gave out, an
 * activation link — is not self-service.
 */
const RECOVERY_DOORS: Readonly<Record<string, { selfService: boolean }>> =
  Object.freeze({
    'forgot-password': { selfService: true },
    'password-reset': { selfService: true },
    'admin-reset': { selfService: false },
    'admin-password': { selfService: false },
    'activation': { selfService: false },
    'recovery-code': { selfService: true },
    'email-code': { selfService: true },
    'email-link': { selfService: true }
  });
/**
 * The credential kinds a sign-in names that are themselves a recovery door
 * (#724): a recovery code, an emailed code or link.
 */
const RECOVERY_CREDENTIALS: Readonly<Record<string, string>> = Object.freeze({
  'backup-code': 'recovery-code',
  'email-code': 'email-code',
  'email-link': 'email-link'
});

/**
 * The policy's fields: one table read as the schema, the console form, the API
 * body, the validation of a save and the parse of an entry.
 */
const FIELDS: PolicyField[] = [
  { key: 'allowUsernameless', attribute: 'stsPasskeyAllowUsernameless',
    type: 'bool', dflt: true,
    label: 'Allow a passkey sign-in with no username',
    what: 'ON BY DEFAULT. On, the sign-in screen offers *Sign in with a ' +
          'passkey* and the username field\'s autofill, which ask the ' +
          'browser for any discoverable credential of this realm (WebAuthn ' +
          'Level 3 section 5.4, `allowCredentials` empty) and sign in the ' +
          'account its user handle names, with user verification required ' +
          'and checked. Off, neither is offered and a sign-in always names ' +
          'the person first. Replaces the setting webauthn.usernameless.' },
  { key: 'requireUsernameless', attribute: 'stsPasskeyRequireUsernameless',
    type: 'bool', dflt: false,
    label: 'Require a passkey sign-in with no username',
    what: 'OFF BY DEFAULT. On, an application whose authentication ' +
          'mechanism is a passkey and nothing else (appAuthnMechanism ' +
          '`webauthn` alone) gets a sign-in screen with no username field: ' +
          '*Sign in with a passkey* is the way in, and a sign-in that names ' +
          'a person is refused. It needs the row above. The realm\'s ' +
          '`default` profile does not apply it to the admin console, the ' +
          'debugger or the user portal; a named profile selecting that ' +
          'application does.' },
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
  { key: 'postQuantumRequired', attribute: 'stsPasskeyPostQuantumRequired',
    type: 'enum', values: POST_QUANTUM_REQUIRED_VALUES.slice(), dflt: 'off',
    label: 'Require a post-quantum passkey',
    what: '`off` (the default) accepts a passkey whatever its signature ' +
          'algorithm. `sign-in` accepts only a POST-QUANTUM passkey, one ' +
          'whose algorithm is ML-DSA-44, ML-DSA-65 or ML-DSA-87 (RFC 9964), ' +
          'when it signs somebody in, as the first credential or as the ' +
          'second factor; a classical one may still be registered. ' +
          '`registration-and-sign-in` refuses a classical one at ' +
          'registration too, and enrolment then offers only ML-DSA. The ' +
          'algorithm decides, not the lane a key was created in. Refused ' +
          'while the realm offers no ML-DSA (webauthn.algorithms names ' +
          'none, and neither webauthn.pqcOnly nor ' +
          'webauthn.pqcAlongsideClassical is on).' },
  { key: 'postQuantumAllowCredentials',
    attribute: 'stsPasskeyPostQuantumAllowCredentials', type: 'enum',
    values: POST_QUANTUM_ALLOW_CREDENTIALS.slice(), dflt: 'realm',
    optional: true,
    label: 'Passkeys a sign-in names where a post-quantum one is required',
    what: '`realm` (the default) follows the realm\'s ' +
          'webauthn.postQuantumAllowCredentials. Read only while ' +
          'postQuantumRequired requires a post-quantum passkey at sign-in. ' +
          '`narrow` names only the person\'s post-quantum (ML-DSA) passkeys ' +
          'in the passkey step\'s request, so a classical one is never ' +
          'offered, and a person whose device holds only their classical ' +
          'one sees the platform\'s own "no passkey found" message. ' +
          '`list-and-refuse` names every passkey ' +
          'they hold and refuses a classical one after the ceremony, with a ' +
          'page saying that this application requires a post-quantum ' +
          'passkey and where to add one; the person may then pick a ' +
          'passkey that will be refused. A person holding no post-quantum ' +
          'passkey is told before any ceremony either way. Left out of a ' +
          'save, `realm` is kept.' },
  { key: 'registrationAlgorithms',
    attribute: 'stsPasskeyRegistrationAlgorithms', type: 'list',
    values: REGISTRATION_ALGORITHM_VALUES.slice(), dflt: REALM_LIST,
    empty: REALM_LIST, maxItems: REGISTRATION_ALGORITHM_VALUES.length,
    optional: true,
    label: 'Algorithms a passkey registration offers',
    what: '`realm` (the default) offers the realm\'s webauthn.algorithms. ' +
          'Otherwise the signature algorithms a passkey registration ' +
          'offers to this profile\'s people, in order of preference (an ' +
          'authenticator makes the first it supports), from the ' +
          'algorithms webauthn.algorithms may name. The next row may ' +
          'narrow or reorder it, and a passkey whose algorithm is not one ' +
          'this profile offers is refused when it is registered. Left out ' +
          'of a save, `realm` is kept.' },
  { key: 'registrationMode', attribute: 'stsPasskeyRegistrationMode',
    type: 'enum', values: REGISTRATION_MODES.slice(), dflt: 'realm',
    optional: true,
    label: 'Post-quantum algorithms at registration',
    what: '`realm` (the default) follows webauthn.pqcOnly and ' +
          'webauthn.pqcAlongsideClassical. `pq-only` offers only ML-DSA, ' +
          'and refuses a retry with the classical algorithms. `pq-first` ' +
          'offers ML-DSA first and the classical algorithms after it, even ' +
          'where the realm requests ML-DSA only. `classical-only` offers no ' +
          'ML-DSA and no post-quantum passkey beside a classical one, for ' +
          'people whose devices fail an ML-DSA registration. Refused with ' +
          'postQuantumRequired other than off or with ' +
          'attestationAlgorithms set (classical-only), and where the ' +
          'algorithms offered name no ML-DSA (pq-only, pq-first). Left out ' +
          'of a save, `realm` is kept.' },
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
          'per passkey, by its name, and the request names only that one.' },
  { key: 'recoveryAssurance', attribute: 'stsPasskeyRecoveryAssurance',
    type: 'enum', values: RECOVERY_ASSURANCE.slice(), dflt: 'any',
    optional: true,
    label: 'Account recovery for a person who holds a passkey',
    what: '`any` BY DEFAULT IN DEVELOPMENT, `not-weaker` IN PRODUCT. ' +
          'Whether a way back into the account that asks for no passkey ' +
          '— a password reset link, an activation link, a recovery code, ' +
          'an emailed code or link — restores access for a person who ' +
          'holds one. `any`: at once. `not-weaker`: the first sign-in ' +
          'after it that is not a passkey sign-in reaches no application; ' +
          'the person registers a passkey that satisfies this policy and ' +
          'signs in with it. `operator-only`: as not-weaker, and the ' +
          'self-service doors (the forgot-password form, a recovery code ' +
          'or an emailed code or link at sign-in) are refused; only an ' +
          'administrator\'s reset link, generated password or activation ' +
          'link remains. Left out of a save, the built-in default is kept.' },
  { key: 'attestationAlgorithms',
    attribute: 'stsPasskeyAttestationAlgorithms', type: 'list',
    values: ATTESTATION_ALGORITHM_VALUES.slice(), dflt: NO_HINTS,
    optional: true,
    label: 'Algorithms a passkey\'s attestation must be signed with',
    what: '`none` BY DEFAULT: an attestation is accepted whatever it is ' +
          'signed with. Otherwise a list from post-quantum, ml-dsa-44, ' +
          'ml-dsa-65, ml-dsa-87, slh-dsa and composite-ml-dsa: a passkey ' +
          'registers only with a TRUSTED attestation that carries a ' +
          'certificate, whose statement signature and the signature on ' +
          'every certificate of its chain, from the leaf to the trust ' +
          'anchor, are each one the list allows (`post-quantum` allows ' +
          'any ML-DSA, SLH-DSA or composite ML-DSA signature). Self and ' +
          'none attestation are refused, having no certificate. With ' +
          'enforceAttestationAtSignIn on, every sign-in holds the passkey ' +
          'to it by what its registration recorded, so a passkey ' +
          'registered before the rule stops working. This is the ' +
          'attestation\'s algorithm, not the passkey\'s own ' +
          '(postQuantumRequired). Left out of a save, the built-in default ' +
          'is kept.' },
  { key: 'adminEnrolment', attribute: 'stsPasskeyAdminEnrolment',
    type: 'enum', values: ADMIN_ENROLMENT_VALUES.slice(), dflt: 'off',
    optional: true,
    label: 'Let an administrator enrol a passkey for a person',
    what: '`off` BY DEFAULT. `on` lets an administrator holding the Admin ' +
          'Write console role enrol a passkey for a person this profile ' +
          'applies to, from the person\'s page on the console or ' +
          '/admin-api: the registration ceremony runs in the ' +
          'administrator\'s own browser, against an authenticator they ' +
          'hold (a security key to be handed over, say), under the ' +
          'person\'s user handle, and is verified exactly as the person\'s ' +
          'own registration is — attestation, algorithms and this ' +
          'policy\'s registration rules. Nothing made elsewhere can be ' +
          'imported. The key records which administrator enrolled it and ' +
          'when, and the person is told. Left out of a save, the built-in ' +
          'default is kept.' },
  // #740. Optional, so a save written before the row existed keeps the
  // stored value (or the built-in off) instead of failing as a missing
  // field. Refused while device-bound sessions are off: see save().
  { key: 'deviceBoundRequired',
    attribute: 'stsPasskeyDeviceBoundRequired',
    type: 'bool', dflt: false, optional: true,
    label: 'Require a device-bound session',
    what: 'OFF BY DEFAULT. On, an issuance to an application this ' +
          'profile covers waits until the sign-on session is bound to ' +
          'the browser\'s key, and is refused when the browser skipped ' +
          'that registration or the wait elapsed without a binding. A ' +
          'session that was never offered registration is not refused ' +
          'by this row. Refused while authn.deviceBoundSessions is off.' }
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
// `recoveryAssurance` (#724) is the one row whose built-in default differs
// by mode, so it is a GETTER asking `mode.js` each time it is read — the
// mode is a setting, and a copy taken at load would keep development's
// answer in a process switched to product. `Object.assign()` copies its
// value at the time of the copy, which is what `read()` and the console's
// defaults want.
const DEFAULTS: Readonly<Record<string, boolean | string | number>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    if (field.key === 'recoveryAssurance') {
      Object.defineProperty(out, field.key, {
        enumerable: true,
        get: function recoveryAssuranceDefault(): string {
          log.debug("Entering recoveryAssuranceDefault().");
          log.debug("Leaving recoveryAssuranceDefault().");
          return mode.recoversWeakerThanPasskeys() ? 'any' : 'not-weaker';
        }
      });
    } else {
      out[field.key] = field.dflt;
    }
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
  ]),
  // #724: what a recovery leaves on a PERSON's entry.
  personAttributes: [
    { name: 'stsRecoveryPending',
      what: 'A recovery restored access to this person, who holds a ' +
            'passkey, and no passkey has signed them in since: the door ' +
            'and when, as `<door> <ISO 8601 instant>`. While the passkey ' +
            'policy\'s recoveryAssurance is not-weaker or operator-only, ' +
            'a sign-in that is not a passkey reaches no application. ' +
            'Maintained by this service.' },
    { name: 'stsPasswordResetSource',
      what: 'Who issued the password reset link on this entry: `self` (the ' +
            'forgot-password form) or `operator` (an administrator). ' +
            'Written and cleared with the link. Maintained by this service.' }
  ]
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
  /**
   * The sentences `describe()` makes, as templates (#543).
   */
  static readonly SENTENCES = SENTENCES;
  /**
   * The recovery doors, and which are the person's own (#724).
   */
  static readonly RECOVERY_DOORS = RECOVERY_DOORS;
  /**
   * The credential kinds that are themselves a recovery door (#724).
   */
  static readonly RECOVERY_CREDENTIALS = RECOVERY_CREDENTIALS;

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
    return { log: log, realms: realms, errorCodes: errorCodes,
             gate: issuanceGate,
             offersPostQuantum: function (rows?: RegistrationRows): boolean {
               log.debug("Entering offersPostQuantum().");
               // LAZILY (#718): `webauthn_policy.ts` requires this module,
               // and is loaded long before any save asks this.
               const out = require('../authn/webauthn_policy')
                 .offersPostQuantum(rows) === true;
               log.debug("Leaving offersPostQuantum(). " + out);
               return out;
             },
             registrationAlgorithmsAllowed: function (
               rows: RegistrationRows): string[] {
               log.debug("Entering registrationAlgorithmsAllowed().");
               // LAZILY (#940), for #718's reason above.
               const out = require('../authn/webauthn_policy')
                 .registrationAlgorithmsAllowed(rows);
               log.debug("Leaving registrationAlgorithmsAllowed().");
               return Array.isArray(out) ? out.map(String) : [];
             } };
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
      // THE ROW'S OWN WORD FOR EMPTY (#940): `realm` for
      // `registrationAlgorithms`, whose empty list is the realm's, and the
      // row's own length bound, since that list may name every algorithm.
      const empty = field.empty || NO_HINTS;
      const items = text.toLowerCase() === empty ? []
        : text.split(/[\s,]+/).filter(Boolean);
      const unknown = items.filter(function (one) {
        return (field.values || []).indexOf(one) < 0;
      });
      const twice = items.filter(function (one, at) {
        return items.indexOf(one) !== at;
      });
      if (unknown.length || twice.length ||
          items.length > (field.maxItems || 8)) {
        log.debug("Leaving PasskeyPolicy.parseField(). Not a list.");
        return { problem: field.label + ' must be "' + empty + '" or a ' +
                          'list of ' + (field.values || []).join(', ') +
                          ', each once; "' + text.slice(0, 60) +
                          '" is not.' };
      }
      log.debug("Leaving PasskeyPolicy.parseField().");
      return { value: items.length ? items.join(',') : empty };
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

  // -------------------------------------------------------------------------
  // THE POLICIES THAT NAME ONE APPLICATION (#609), for its page: read-only,
  // and nothing is stored for it — the relation is the named profiles'
  // `stsPasskeySelectApplication` and nothing else (rcbj's decision 1). An
  // application answers to its identifier and to each client_id, matched as
  // `selectionFor()` matches the one a sign-in names: trimmed and in any
  // case. The one that applies is the lowest precedence among them (ties by
  // name), `selectionFor()`'s order, else `default` — for a sign-in naming
  // the application and nobody yet; a profile selecting a group the person
  // is in can still win for that person, which the page says.
  // -------------------------------------------------------------------------
  /**
   * Lists this realm's named profiles that name an application, in the
   * order `selectionFor()` ranks them, and which one applies to it.
   *
   * @param names - what the application answers to: its identifier and each
   *   client_id
   * @returns `{ policies, applies, appliesBy, groupPolicies }` — each
   *   policy `{ name, dn, precedence, selectApplications, selectGroups,
   *   matched, applies }`; `applies` the lowest precedence naming the
   *   application by any of its names, else `default`; `appliesBy` the
   *   profile a sign-in naming it by each one gets before any person is
   *   known; `groupPolicies` how many named profiles select by group and
   *   could still win for a person
   */
  forApplication(names: unknown[]): {
      policies: Array<{ name: string; dn: string; precedence: number;
                        selectApplications: string[];
                        selectGroups: string[]; matched: string[];
                        applies: boolean }>;
      applies: string; appliesBy: Record<string, string>;
      groupPolicies: number } {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.forApplication().");
    const wanted = (Array.isArray(names) ? names : []).map(function (one) {
      return String(one === undefined || one === null ? '' : one).trim()
        .toLowerCase();
    }).filter(Boolean);
    if (!this.haveDirectory()) {
      log.debug("Leaving PasskeyPolicy.forApplication(). No directory.");
      return { policies: [], applies: DEFAULT_PROFILE, appliesBy: {},
               groupPolicies: 0 };
    }
    const named = this.directory.allPasskeyPolicies().filter(function (one) {
      return String(one.name || '').toLowerCase() !== DEFAULT_PROFILE;
    }).map((entry) => {
      const at = entry.attributes || {};
      const p = Number(this.firstValue(at, 'stsPasskeyPrecedence'));
      const apps = this.allValues(at, 'stsPasskeySelectApplication');
      return {
        name: String(entry.name).toLowerCase(),
        dn: String(entry.dn || ''),
        precedence: p >= 1 && p <= 1000 ? p : DEFAULT_PRECEDENCE,
        selectApplications: apps,
        selectGroups: this.allValues(at, 'stsPasskeySelectGroup'),
        matched: apps.filter(function (one) {
          return wanted.indexOf(one.trim().toLowerCase()) >= 0;
        }),
        applies: false
      };
    });
    const policies = named.filter(function (one) {
      return one.matched.length > 0;
    }).sort(function (a, b) {
      return a.precedence - b.precedence || (a.name < b.name ? -1 : 1);
    });
    if (policies.length) {
      policies[0].applies = true;
    }
    const groupPolicies = named.filter(function (one) {
      return one.selectGroups.length > 0;
    }).length;
    const applies = policies.length ? policies[0].name : DEFAULT_PROFILE;
    // A SIGN-IN NAMES ONE OF THEM — an OAuth client its client_id, SAML its
    // entity ID — so where two policies name the application by different
    // names, which applies depends on the name: `selectionFor()`'s answer
    // for each, before any person is known.
    const appliesBy: Record<string, string> = {};
    (Array.isArray(names) ? names : []).forEach(function (one) {
      const raw = String(one === undefined || one === null ? '' : one).trim();
      if (!raw) {
        return;
      }
      const lower = raw.toLowerCase();
      const first = policies.filter(function (p) {
        return p.matched.some(function (m) {
          return m.trim().toLowerCase() === lower;
        });
      })[0];
      appliesBy[raw] = first ? first.name : DEFAULT_PROFILE;
    });
    log.debug("Leaving PasskeyPolicy.forApplication(). " + policies.length +
              " name it; " + applies + " applies.");
    return { policies: policies, applies: applies, appliesBy: appliesBy,
             groupPolicies: groupPolicies };
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
                        // The default IN FORCE (#910): DEFAULTS reads the
                        // mode for a row such as recoveryAssurance, whose
                        // `dflt` is only development's.
                        'built-in default of ' + DEFAULTS[field.key] +
                        ' is in force instead.');
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
   * Says whether this profile requires a passkey sign-in with no username
   * (#608) — the row, which needs `allowUsernameless`. Whether it holds a
   * given sign-in is `authn.ts`'s `usernamelessRequired()`: only an
   * application signing in with a passkey alone, and never a hosted surface
   * through the `default` profile.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns true where both rows are on
   */
  requiresUsernameless(profile?: PasskeyProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.requiresUsernameless().");
    const rules = profile || this.read();
    log.debug("Leaving PasskeyPolicy.requiresUsernameless().");
    return rules.requireUsernameless === true &&
           rules.allowUsernameless === true;
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
      { code: string; why: string; reason: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.backupEligibleRefusal().");
    // A flag never read is not a fact: nothing is asked about it.
    if (typeof backupEligible !== 'boolean') {
      log.debug("Leaving PasskeyPolicy.backupEligibleRefusal(). No flag.");
      return null;
    }
    const out = this.refusalFor(at, { backupEligible: backupEligible },
                                profile);
    log.debug("Leaving PasskeyPolicy.backupEligibleRefusal(). " +
              (out ? out.code : 'allowed'));
    return out;
  }

  /**
   * Says whether a signature algorithm is post-quantum (#718): one of RFC
   * 9964's ML-DSA-44, ML-DSA-65 and ML-DSA-87, by its JOSE name.
   *
   * @param algorithm - the algorithm's JOSE name
   * @returns true where it is
   */
  static isPostQuantum(algorithm: unknown): boolean {
    log.debug("Entering PasskeyPolicy.isPostQuantum().");
    const out = POST_QUANTUM_ALGORITHMS.indexOf(String(algorithm || '')) >= 0;
    log.debug("Leaving PasskeyPolicy.isPostQuantum(). " + out);
    return out;
  }

  /**
   * Says whether the selected profile requires a post-quantum passkey at a
   * stage (#718): `sign-in` under `sign-in` and
   * `registration-and-sign-in`, `registration` under the second only.
   *
   * @param at - `registration` or `sign-in`
   * @param profile - a profile already read; read afresh when omitted
   * @returns true where it does
   */
  requiresPostQuantum(at: string, profile?: PasskeyProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.requiresPostQuantum(). " + at);
    const rules = profile || this.read();
    const row = String(rules.postQuantumRequired || 'off');
    const out = at === 'registration'
      ? row === 'registration-and-sign-in'
      : (row === 'sign-in' || row === 'registration-and-sign-in');
    log.debug("Leaving PasskeyPolicy.requiresPostQuantum(). " + out);
    return out;
  }

  /**
   * How the passkey step's `allowCredentials` is built while a post-quantum
   * passkey is required at sign-in (#946): the selected profile's
   * `postQuantumAllowCredentials`, and the realm's
   * `webauthn.postQuantumAllowCredentials` where that row is `realm`.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns `narrow` or `list-and-refuse`
   */
  postQuantumAllowCredentials(profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.postQuantumAllowCredentials().");
    const rules = profile || this.read();
    const row = String(rules.postQuantumAllowCredentials || 'realm');
    // THE REALM'S SETTING where the row says `realm` — read through
    // `config.value()`, so the ambient realm's override answers — and
    // `narrow`, #718's behaviour, for anything that is neither value.
    const chosen = row === 'narrow' || row === 'list-and-refuse' ? row
      : String(config.value('webauthn.postQuantumAllowCredentials') || '');
    const out = chosen === 'list-and-refuse' ? 'list-and-refuse' : 'narrow';
    log.debug("Leaving PasskeyPolicy.postQuantumAllowCredentials(). " + out +
              (row === 'realm' ? ' (the realm\'s setting)' : ''));
    return out;
  }

  // -------------------------------------------------------------------------
  // A POPULATION'S REGISTRATION ALGORITHMS (#940, rule 3cu). These say what
  // the rows ARE; what a registration then offers — the verifier's table,
  // the insecure switch, the lanes, #718's narrowing — is
  // `webauthn_policy.ts`'s `registrationOffer()`, which reads them through
  // these.
  // -------------------------------------------------------------------------
  /**
   * The algorithms the selected profile's registrations offer in place of
   * the realm's (#940): its `registrationAlgorithms`, in order, or [] where
   * it follows the realm's webauthn.algorithms.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the JOSE names, in the profile's order
   */
  registrationAlgorithms(profile?: PasskeyProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.registrationAlgorithms().");
    const rules = profile || this.read();
    const text = String(rules.registrationAlgorithms === undefined ||
                        rules.registrationAlgorithms === null
      ? REALM_LIST : rules.registrationAlgorithms);
    const out = text === REALM_LIST ? [] : text.split(',').filter(
      function (one) {
        return REGISTRATION_ALGORITHM_VALUES.indexOf(one) >= 0;
      });
    log.debug("Leaving PasskeyPolicy.registrationAlgorithms(). " +
              (out.join(',') || 'the realm\'s'));
    return out;
  }

  /**
   * The selected profile's `registrationMode` (#940): `realm`, `pq-only`,
   * `pq-first` or `classical-only`; `realm` for anything else.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the mode
   */
  registrationMode(profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.registrationMode().");
    const rules = profile || this.read();
    const row = String(rules.registrationMode || 'realm');
    const out = REGISTRATION_MODES.indexOf(row) >= 0 ? row : 'realm';
    log.debug("Leaving PasskeyPolicy.registrationMode(). " + out);
    return out;
  }

  /**
   * The rows a registration's algorithms are resolved from (#940), as
   * `webauthn_policy.ts` takes them for a profile that is not the selected
   * one: the list, the mode and `postQuantumRequired`.
   *
   * @param profile - a profile already read, or a save's values; the
   *   selected profile when omitted
   * @returns `{ registrationAlgorithms, registrationMode,
   *   postQuantumRequired }`
   */
  registrationRows(profile?: Record<string, any> | null): RegistrationRows {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.registrationRows().");
    const rules = (profile || this.read()) as PasskeyProfile;
    const out = {
      registrationAlgorithms: this.registrationAlgorithms(rules),
      registrationMode: this.registrationMode(rules),
      postQuantumRequired: POST_QUANTUM_REQUIRED_VALUES.indexOf(
        String(rules.postQuantumRequired)) >= 0
        ? String(rules.postQuantumRequired) : 'off'
    };
    log.debug("Leaving PasskeyPolicy.registrationRows(). " +
              out.registrationMode);
    return out;
  }

  /**
   * Says whether a profile gives its population registration rows of its
   * own (#940) — a list, or a mode other than `realm` — rather than
   * following the realm's settings. The issuance policy's
   * `profile-algorithm` rule binds only such a profile: under the realm's
   * settings the ceremony's own offered-algorithm check is the rule, as it
   * always was.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns `profile` or `realm`
   */
  registrationAlgorithmsFrom(profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.registrationAlgorithmsFrom().");
    const rules = profile || this.read();
    const out = this.registrationAlgorithms(rules).length ||
                this.registrationMode(rules) !== 'realm'
      ? 'profile' : 'realm';
    log.debug("Leaving PasskeyPolicy.registrationAlgorithmsFrom(). " + out);
    return out;
  }

  /**
   * The refusal of a passkey's signature algorithm, or null (#718): the
   * question asked about the one fact group `algorithm`, so the portal's
   * and the console's key rows say what the decision would. One sentence,
   * as `backupEligibleRefusal()` is.
   *
   * @param key - `{ algorithm, lane }`: `credentials.keyAlgorithm()`'s
   *   answer, or a stored key row's; an algorithm never recorded is not
   *   asked about
   * @param at - `registration` or `sign-in`
   * @param profile - a profile already read; read afresh when omitted
   * @returns `{ code, why, reason }` or null
   */
  postQuantumRefusal(key: { algorithm?: unknown; name?: unknown;
                            lane?: unknown } | null | undefined,
                     at: string, profile?: PasskeyProfile | null):
      { code: string; why: string; reason: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.postQuantumRefusal().");
    const k = key || {};
    const algorithm = String(k.name || k.algorithm || '');
    // An algorithm never read is not a fact: nothing is asked about it.
    if (!algorithm) {
      log.debug("Leaving PasskeyPolicy.postQuantumRefusal(). No algorithm.");
      return null;
    }
    const out = this.refusalFor(at, { algorithm: algorithm,
                                      lane: String(k.lane || '') }, profile);
    log.debug("Leaving PasskeyPolicy.postQuantumRefusal(). " +
              (out ? out.code : 'allowed'));
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
   * What an account recovery may restore for a person who holds a passkey
   * (#724): `any`, `not-weaker` or `operator-only`.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the row's value, the built-in default where it is unreadable
   */
  recoveryAssurance(profile?: PasskeyProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.recoveryAssurance().");
    const rules = profile || this.read();
    const value = String(rules.recoveryAssurance || '');
    log.debug("Leaving PasskeyPolicy.recoveryAssurance(). " + value);
    return RECOVERY_ASSURANCE.indexOf(value) >= 0 ? value
      : String(DEFAULTS.recoveryAssurance);
  }

  // =========================================================================
  // THE RECOVERY QUESTION (#724). A door that restores access without a
  // passkey asks it BEFORE it writes anything (`at: 'door'`), and every
  // session asks it at its start (`at: 'session'`, `authn.ts`'s
  // `startSessionHere()`). The facts are the caller's, because this leaf
  // reads no credential: the DOOR (one of RECOVERY_DOORS, or '' at a
  // session no door led to), whether the person holds a passkey
  // (`covered`), whether a recovery is pending on their entry, and at a
  // session the kind of credential that answered. The issuance policy
  // decides (`recover-account`); the reason picks the sentence.
  // =========================================================================
  /**
   * Asks the issuance policy whether a recovery may restore access, or a
   * session after one may reach an application (#724).
   *
   * @param facts - `{ username, door, at, credential, covered, pending }`
   * @param profile - a profile already read; read afresh when omitted
   * @returns `{ code, why, reason }`, or null where the policy allows it
   */
  recoveryRefusal(facts: Record<string, any>,
                  profile?: PasskeyProfile | null):
      { code: string; why: string; reason: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.recoveryRefusal().");
    const given = facts || {};
    const out = this.refusalFor('recovery', {
      username: String(given.username || ''),
      recovery: { door: String(given.door || ''),
                  at: String(given.at || 'door'),
                  credential: String(given.credential || ''),
                  covered: given.covered === true,
                  pending: given.pending === true } }, profile);
    log.debug("Leaving PasskeyPolicy.recoveryRefusal(). " +
              (out ? out.code : 'allowed'));
    return out;
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
      { code: string; why: string; reason: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.enterpriseSerialRefusal().");
    const out = this.refusalFor('registration',
                                { username: username, serial: serial },
                                profile);
    log.debug("Leaving PasskeyPolicy.enterpriseSerialRefusal(). " +
              (out ? out.code : 'allowed'));
    return out;
  }

  /**
   * The algorithms a passkey's attestation must be signed with (#941): the
   * selected profile's `attestationAlgorithms`, or [] for none.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the list, in the profile's order
   */
  attestationAlgorithms(profile?: PasskeyProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.attestationAlgorithms().");
    const rules = profile || this.read();
    const text = String(rules.attestationAlgorithms === undefined ||
                        rules.attestationAlgorithms === null
      ? NO_HINTS : rules.attestationAlgorithms);
    const out = text === NO_HINTS ? [] : text.split(',').filter(
      function (one) {
        return ATTESTATION_ALGORITHM_VALUES.indexOf(one) >= 0;
      });
    log.debug("Leaving PasskeyPolicy.attestationAlgorithms(). " +
              (out.join(',') || 'none'));
    return out;
  }

  /**
   * Whether an administrator may enrol a passkey for a person (#945): the
   * selected profile's `adminEnrolment` is `on`.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns true where it is on
   */
  adminEnrolmentAllowed(profile?: PasskeyProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.adminEnrolmentAllowed().");
    const rules = profile || this.read();
    const on = String(rules.adminEnrolment || 'off') === 'on';
    log.debug("Leaving PasskeyPolicy.adminEnrolmentAllowed(). " + on);
    return on;
  }

  // -------------------------------------------------------------------------
  // WHETHER AN ATTESTATION'S ALGORITHMS SATISFY THE LIST (#941), computed in
  // ONE place — `question()` — as `postQuantum` is for #718, so a door
  // never says it and the built-in rule reads one boolean. Every signature
  // must be one an entry allows: a statement algorithm by its COSE name
  // (only RFC 9964's ML-DSA is post-quantum there), a certificate by the
  // name, family and post-quantum flag `pki.attestationSignatureAlgorithm()`
  // gave it. And the statement must have been VERIFIED and TRUSTED and carry
  // a certificate: an algorithm nobody checked, or one in a chain no anchor
  // vouches for, satisfies nothing. An empty list is no rule.
  // -------------------------------------------------------------------------
  /**
   * Says whether an attestation's recorded algorithms satisfy a list of
   * `attestationAlgorithms` values (#941).
   *
   * @param facts - `webauthn_attestation.recordedAlgorithms()`'s answer
   * @param allowed - the list; empty is no rule
   * @returns true where it does
   */
  static attestationAlgorithmAllowed(facts: Record<string, any> | null,
                                     allowed: string[]): boolean {
    log.debug("Entering PasskeyPolicy.attestationAlgorithmAllowed().");
    if (!allowed || !allowed.length) {
      log.debug("Leaving PasskeyPolicy.attestationAlgorithmAllowed(). " +
                "No rule.");
      return true;
    }
    const f = facts || {};
    const certificates = Array.isArray(f.certificates) ? f.certificates : [];
    if (f.verified !== true || f.trusted !== true || !certificates.length) {
      log.debug("Leaving PasskeyPolicy.attestationAlgorithmAllowed(). Not " +
                "a trusted chain.");
      return false;
    }
    const one = function (name: string, family: string,
                          postQuantum: boolean): boolean {
      log.debug("Entering attestationAlgorithmAllowed() one().");
      const lower = String(name || '').toLowerCase();
      const ok = allowed.some(function (value) {
        return value === 'post-quantum' ? postQuantum
          : (value === 'slh-dsa' ? family === 'SLH-DSA'
            : (value === 'composite-ml-dsa' ? family === 'Composite ML-DSA'
                                            : lower === value));
      });
      log.debug("Leaving attestationAlgorithmAllowed() one(). " + ok);
      return ok;
    };
    const statements = Array.isArray(f.statements) ? f.statements : [];
    const out = statements.every(function (name: string) {
      return one(name, /^ML-DSA-/.test(String(name)) ? 'ML-DSA' : '',
                 PasskeyPolicy.isPostQuantum(name));
    }) && certificates.every(function (c: Record<string, any>) {
      return one(String((c && c.algorithm) || ''),
                 String((c && c.family) || ''),
                 !!(c && c.postQuantum === true));
    });
    log.debug("Leaving PasskeyPolicy.attestationAlgorithmAllowed(). " + out);
    return out;
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
      { code: string; why: string; reason: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.pinLengthRefusal().");
    const out = this.refusalFor(at, { minPinLength: reported }, profile);
    log.debug("Leaving PasskeyPolicy.pinLengthRefusal(). " +
              (out ? out.code : 'allowed'));
    return out;
  }

  // =========================================================================
  // THE PASSKEY QUESTION (#536). The rows above CONFIGURE how a realm's
  // passkeys behave; whether a given passkey may be registered or may sign
  // somebody in is DECIDED by the issuance policy (rcbj's rule that every
  // authorization decision is policy): `question()` gathers the facts and
  // the selected profile's rows, `issuance_gate.checkPasskey()` asks, and
  // `refusalFor()` turns the verdict back into the sentence the door has
  // always said, by the REASON the rule gave. Which profile applies (#535)
  // stays here: it chooses the settings and decides nothing.
  //
  // A fact group is carried only when its fact was GIVEN, so each door asks
  // about what it holds and no rule fires on a fact nobody sent:
  //   backupEligible  -> backup-eligible     minPinLength -> pin-length
  //   serial          -> serial (with whether the person holds it)
  //   attestation     -> attestation (with `attestationSettings`)
  //   algorithm       -> algorithm (with `postQuantum` and `lane`, #718)
  //   upgrade         -> upgrade (`mode`, the previous algorithm, #939)
  //   enrolledBy      -> enrolment (an administrator enrolled it, #945)
  // =========================================================================
  /**
   * Builds the passkey question (#536) for the issuance policy: the facts a
   * door holds and the selected profile's rows.
   *
   * @param at - `registration` or `sign-in`
   * @param facts - `{ username, backupEligible, minPinLength, serial,
   *   attestation, attestationSettings, enforceAttestation, algorithm,
   *   lane, upgrade }`, each optional — `upgrade` (#939) is `{ mode,
   *   previousAlgorithm }`
   * @param profile - a profile already read; read afresh when omitted
   * @returns the question `issuance_gate.checkPasskey()` takes
   */
  question(at: string, facts: Record<string, any>,
           profile?: PasskeyProfile | null): Record<string, any> {
    const { log, realms } = this.deps;
    log.debug("Entering PasskeyPolicy.question().");
    const given = facts || {};
    const rules = profile || this.read();
    const has = function (key: string): boolean {
      log.debug("Entering has().");
      log.debug("Leaving has().");
      return Object.prototype.hasOwnProperty.call(given, key);
    };
    const groups: string[] = [];
    const out: Record<string, any> = {
      action: at === 'registration' ? 'register-passkey'
        : (at === 'recovery' ? 'recover-account' : 'use-passkey'),
      subject: String(given.username || ''),
      realm: String(typeof realms.currentId === 'function'
        ? realms.currentId() || '' : ''),
      profile: String(rules.name || PasskeyPolicy.DEFAULT_PROFILE)
    };
    if (has('backupEligible')) {
      groups.push('backup-eligible');
      out.backupEligible = typeof given.backupEligible === 'boolean'
        ? given.backupEligible : undefined;
    }
    if (has('minPinLength')) {
      groups.push('pin-length');
      out.minPinLength = typeof given.minPinLength === 'number' &&
        Number.isInteger(given.minPinLength) ? given.minPinLength : null;
    }
    const attribute = this.enterpriseSerialAttribute(rules);
    if (has('serial')) {
      groups.push('serial');
      const serial = String(given.serial === undefined ||
                            given.serial === null ? '' : given.serial).trim();
      out.serial = serial;
      out.serialHeld = !!serial && !!attribute &&
        this.personHoldsSerial(String(given.username || ''), attribute,
                               serial);
    }
    if (has('attestation') && given.attestation) {
      groups.push('attestation');
      out.attestation = given.attestation;
      out.settings = given.attestationSettings || {};
    }
    // THE KEY'S SIGNATURE ALGORITHM (#718), and whether it is post-quantum,
    // decided HERE and nowhere else — a door hands over the algorithm it
    // holds (the ceremony's, or the row's through `keyAlgorithm()`) and
    // never its own reading of it. The lane goes beside it, unread by the
    // built-in rule: an ML-DSA key made with #643's switch off has none.
    if (has('algorithm')) {
      groups.push('algorithm');
      const algorithm = String(given.algorithm === undefined ||
                               given.algorithm === null ? ''
                                                        : given.algorithm)
        .trim();
      out.algorithm = algorithm;
      out.postQuantum = PasskeyPolicy.isPostQuantum(algorithm);
      out.lane = given.lane === 'pqc' ? 'pqc' : 'classical';
    }
    // THE ALGORITHMS THE KEY'S ATTESTATION WAS SIGNED WITH (#941), and
    // whether they satisfy the profile's list — decided HERE, as
    // `postQuantum` is: a door hands over what the record says
    // (`webauthn_attestation.recordedAlgorithms()`) and never its reading.
    // The raw names go beside the verdict for a realm's own rules.
    if (has('attestationAlgorithms')) {
      groups.push('attestation-algorithm');
      const a = given.attestationAlgorithms || {};
      out.attestationAlgorithm = {
        verified: a.verified === true, trusted: a.trusted === true,
        recorded: a.recorded === true,
        statement: String(a.statement || ''),
        statements: (Array.isArray(a.statements) ? a.statements : [])
          .map(String).slice(0, 8),
        certificates: (Array.isArray(a.certificates) ? a.certificates : [])
          .map(function (c) {
            return String((c && c.algorithm) || '');
          }).slice(0, 16),
        postQuantum: a.postQuantum === true };
      out.attestationAlgorithmAllowed =
        PasskeyPolicy.attestationAlgorithmAllowed(a,
          this.attestationAlgorithms(rules));
    }
    // AN UPGRADE OF A CLASSICAL PASSKEY (#939): the registration is the
    // second ceremony of an upgrade, with what its write will do
    // (`replace` or `alongside`) and the algorithm of the passkey it
    // upgrades. No built-in rule reads it — the new key is held to every
    // registration rule as any other is — so a realm's own rule may forbid
    // upgrades, or one mode of them, without touching the rest.
    if (has('upgrade') && given.upgrade) {
      groups.push('upgrade');
      const u = given.upgrade;
      const previous = String(u.previousAlgorithm || '');
      out.upgrade = {
        mode: u.mode === 'alongside' ? 'alongside' : 'replace',
        previousAlgorithm: previous,
        previousPostQuantum: PasskeyPolicy.isPostQuantum(previous) };
    }
    // WHETHER THE KEY'S ALGORITHM IS ONE THIS PROFILE OFFERS AT
    // REGISTRATION (#940), decided HERE as `postQuantum` is: at
    // register-passkey only, from the algorithm the door handed over and the
    // profile's rows resolved by `webauthn_policy.ts` — every lane's list
    // and the classical retry's, since the write does not know which
    // ceremony made the key. The ceremony's own offered-algorithm check
    // (WebAuthn Level 3 section 7.1) holds the credential to its LANE's
    // list; this holds every write, a key typed by value included, to the
    // profile's.
    const registrationRows = this.registrationRows(rules);
    const offeredHere = this.deps.registrationAlgorithmsAllowed(
      registrationRows);
    if (at === 'registration' && has('algorithm')) {
      groups.push('profile-algorithm');
      out.profileAlgorithmOffered =
        offeredHere.indexOf(String(out.algorithm || '')) >= 0;
    }
    // WHO ENROLLED IT (#945): an administrator, on the person's behalf. Sent
    // only with an `enrolledBy` record naming one, so the person's own
    // registration asks what it always asked; the boolean goes with the
    // group always, for a realm's own rule to read. No built-in rule does:
    // the switch is `adminEnrolment`, enforced at the writer.
    if (has('enrolledBy') && given.enrolledBy &&
        String(given.enrolledBy.username || '')) {
      groups.push('enrolment');
      out.enrolledByAdmin = true;
      out.enrolledBy = String(given.enrolledBy.username).slice(0, 256);
    }
    if (has('recovery') && given.recovery) {
      groups.push('recovery');
      const r = given.recovery;
      const door = String(r.door || '');
      out.recovery = {
        door: door, at: String(r.at || ''),
        credential: String(r.credential || ''),
        selfService: !!(RECOVERY_DOORS[door] &&
                        RECOVERY_DOORS[door].selfService),
        covered: r.covered === true, pending: r.pending === true };
    }
    out.groups = groups;
    const pin = this.pinLengthRule(rules);
    out.policy = {
      backupEligibility: String(rules.backupEligibility || 'allow'),
      enforcePinLength: pin.enforce,
      minPinLength: pin.min,
      pinLengthOnlyIfSupported: pin.onlyIfSupported,
      enforceAttestationAtSignIn: typeof given.enforceAttestation ===
        'boolean' ? given.enforceAttestation
                  : this.enforcesAttestationAtSignIn(rules),
      enterpriseSerialAttribute: attribute,
      postQuantumRequired: POST_QUANTUM_REQUIRED_VALUES.indexOf(
        String(rules.postQuantumRequired)) >= 0
        ? String(rules.postQuantumRequired) : 'off',
      recoveryAssurance: this.recoveryAssurance(rules),
      // #941: the list, [] for none.
      attestationAlgorithms: this.attestationAlgorithms(rules),
      // HOW THE PASSKEY STEP NAMED THE KEYS (#946), resolved — the realm's
      // setting where the row is `realm` — so a realm's own rule may tell a
      // classical key the person picked from a list from one they were
      // never offered. No built-in rule reads it: the refusal is the
      // `post-quantum` rule's either way.
      postQuantumAllowCredentials: this.postQuantumAllowCredentials(rules),
      // THE POPULATION'S REGISTRATION ALGORITHMS (#940): the mode as the row
      // says it, the list a registration under this profile may make, as
      // resolved (the realm's where the profile follows it), and whether the
      // profile sets either row — the last is what the built-in
      // `profile-algorithm` rule is gated on.
      registrationMode: registrationRows.registrationMode,
      registrationAlgorithms: offeredHere.slice(),
      registrationAlgorithmsFrom: this.registrationAlgorithmsFrom(rules),
      // #945: whether an administrator may enrol one, `off` or `on`.
      adminEnrolment: this.adminEnrolmentAllowed(rules) ? 'on' : 'off'
    };
    log.debug("Leaving PasskeyPolicy.question(). " + out.action + ' [' +
              groups.join(', ') + ']');
    return out;
  }

  // Whether the person's entry holds the serial in the named attribute
  // (#532), case-insensitively: the fact the serial rule is decided on.
  private personHoldsSerial(username: string, attribute: string,
                            serial: string): boolean {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.personHoldsSerial().");
    const hook = this.directory && this.directory.personAttributeValues;
    const held = typeof hook === 'function'
      ? (hook.call(this.directory, username, attribute) || []) : [];
    const mine = held.some(function (one) {
      return String(one).trim().toLowerCase() === serial.toLowerCase();
    });
    log.debug("Leaving PasskeyPolicy.personHoldsSerial(). " + mine);
    return mine;
  }

  /**
   * Asks the issuance policy whether a passkey may be registered or may sign
   * somebody in (#536), and words its refusal.
   *
   * @param at - `registration` or `sign-in`
   * @param facts - what the door holds (see `question()`)
   * @param profile - a profile already read; read afresh when omitted
   * @returns `{ code, why, reason }`, or null where the policy allows it
   */
  refusalFor(at: string, facts: Record<string, any>,
             profile?: PasskeyProfile | null):
      { code: string; why: string; reason: string } | null {
    const { log, gate } = this.deps;
    log.debug("Entering PasskeyPolicy.refusalFor().");
    const rules = profile || this.read();
    const asked = this.question(at, facts, rules);
    const answer = gate.checkPasskey(asked);
    if (!answer || answer.verdict !== 'refuse') {
      log.debug("Leaving PasskeyPolicy.refusalFor(). Allowed.");
      return null;
    }
    const out = {
      code: String(answer.code || 'STS-AUTHN-0322'),
      reason: String(answer.reason || ''),
      why: this.sentenceFor(String(answer.reason || ''), at, asked,
                            facts || {})
    };
    log.debug("Leaving PasskeyPolicy.refusalFor(). " + out.code + ' (' +
              (out.reason || 'no reason') + ', ' +
              String(answer.decidedBy || '') + ')');
    return out;
  }

  // The one sentence each reason has always had, so the portal, the sign-in
  // screen and the audit row say the same thing whoever decided. A reason
  // the built-in rules do not give — a realm's own rule — gets a sentence
  // naming the issuance policy.
  private sentenceFor(reason: string, at: string, asked: Record<string, any>,
                      facts: Record<string, any>): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.sentenceFor(). " + reason);
    const registering = at === 'registration';
    const policy = asked.policy || {};
    let why: string;
    if (reason === 'backup-eligible') {
      why = 'That passkey can be synced or backed up (its authenticator ' +
            'set the backup-eligible flag), and this realm accepts only ' +
            'device-bound passkeys (the passkey ' +
            'policy\'s backupEligibility is disallow). ' +
            (registering
              ? 'Use a security key, or a passkey kept on this device only.'
              : 'Sign in another way, and register a device-bound key.');
    } else if (reason === 'pin-length') {
      const value = asked.minPinLength;
      why = (value === null || value === undefined
        ? 'That passkey did not report its minimum PIN length, and this ' +
          'realm requires a PIN of at least ' + policy.minPinLength +
          ' characters (the passkey policy\'s enforcePinLength). A ' +
          'security key reports it only to services it was configured to ' +
          'tell. '
        : 'That passkey accepts a PIN of ' + value + ' characters, and ' +
          'this realm requires at least ' + policy.minPinLength +
          ' (the passkey policy\'s minPinLength). ') +
        (registering
          ? 'Use a key configured with a longer minimum PIN.'
          : 'Sign in another way, and register a key whose minimum PIN ' +
            'is long enough.');
    } else if (reason === 'serial-missing') {
      why = 'That security key\'s attestation names no device ' +
            'serial this service can read, and this realm binds ' +
            'security keys to the serials issued to each person ' +
            '(the passkey policy\'s enterpriseSerialAttribute). ' +
            'Use a key from your organisation, registered where ' +
            'enterprise attestation is enabled.';
    } else if (reason === 'post-quantum') {
      why = 'That passkey signs with ' +
            (String(asked.algorithm || '') || 'a classical algorithm') +
            ', and this realm requires a post-quantum passkey, one that ' +
            'signs with ML-DSA (the passkey policy\'s postQuantumRequired ' +
            'is ' + String(policy.postQuantumRequired || '') + '). ' +
            (registering
              ? 'Use an authenticator that can make an ML-DSA passkey.'
              : 'Sign in another way, and register a post-quantum passkey.');
    } else if (reason === 'attestation-algorithm') {
      const a = asked.attestationAlgorithm || {};
      const signed = [].concat(a.statements || [], a.certificates || [])
        .filter(Boolean).slice(0, 8).join(', ');
      why = (registering ? 'That passkey\'s attestation ' :
                           'This passkey was registered with an ' +
                           'attestation that ') +
            (!a.verified || !a.trusted
              ? (registering ? 'is not one this service verified and ' +
                               'trusts'
                             : 'this service did not verify and trust')
              : (!(a.certificates || []).length
                ? 'carries no certificate'
                : 'is signed with ' +
                  (signed || 'algorithms never recorded'))) +
            ', and this realm requires one signed with ' +
            ((policy.attestationAlgorithms || []).join(', ') || 'nothing') +
            ' (the passkey policy\'s attestationAlgorithms). ' +
            (registering
              ? 'Use an authenticator whose attestation is signed that way.'
              : 'Sign in another way, and register a passkey whose ' +
                'attestation is.');
    } else if (reason === 'profile-algorithm') {
      // #940: the population's own list, by the profile's name, so the
      // person and the operator read which profile said no.
      why = 'That passkey signs with ' +
            (String(asked.algorithm || '') || 'an algorithm never recorded') +
            ', which is not one the passkey policy offers here (profile ' +
            String(asked.profile || DEFAULT_PROFILE) + ': ' +
            ((policy.registrationAlgorithms || []).join(', ') || 'nothing') +
            ', registrationMode ' + String(policy.registrationMode || '') +
            '). Use an authenticator that can make one of those.';
    } else if (reason === 'serial-not-held') {
      why = 'That security key (serial ' +
            String(asked.serial || '').slice(0, 64) + ') is not ' +
            'one issued to you: its serial is not on your directory entry ' +
            '(' + policy.enterpriseSerialAttribute + '). Use the key your ' +
            'organisation issued you.';
    } else if (reason === 'recovery-self-service') {
      why = 'This account is protected by a passkey, and this realm lets ' +
            'it be recovered only by whoever manages it (the passkey ' +
            'policy\'s recoveryAssurance is operator-only). Sign in with ' +
            'your passkey, or ask an administrator for a reset or ' +
            'activation link.';
    } else if (reason === 'recovery-enrol-first') {
      why = 'This account was recovered without its passkey, and this ' +
            'realm lets it reach no application until a passkey has signed ' +
            'you in (the passkey policy\'s recoveryAssurance). Register a ' +
            'new passkey, then sign in with it.';
    } else {
      const sentences = (facts.attestationSentences || {}) as
        Record<string, string>;
      why = sentences[reason] ||
        'This realm\'s issuance policy ' + (registering
          ? 'does not let that passkey be registered here.'
          : 'no longer lets that passkey sign you in. Sign in another way.');
    }
    log.debug("Leaving PasskeyPolicy.sentenceFor().");
    return why;
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
    const fill = serverProse.fill;
    const extras = rules.rpNameExtras && rules.rpNameExtras !== 'none'
      ? rules.rpNameExtras : '';
    const prompt = rules.userDisplayName
      ? fill(extras ? SENTENCES.promptAttributeExtras
                    : SENTENCES.promptAttribute,
             { attribute: rules.userDisplayName, extras: extras })
      : fill(extras ? SENTENCES.promptNameExtras : SENTENCES.promptName,
             { extras: extras });
    const out = [
      rules.allowUsernameless === true
        ? SENTENCES.usernameless
        : SENTENCES.noUsernameless,
      ...(this.requiresUsernameless(rules)
        ? [SENTENCES.requireUsernameless] : []),
      SENTENCES.createPasskey,
      fill(securityKey === 'required' ? SENTENCES.securityKeyRequired
                                      : SENTENCES.securityKeyOther,
           { value: securityKey }),
      rules.backupEligibility === 'disallow'
        ? SENTENCES.deviceBound
        : SENTENCES.synced,
      this.pinLengthSentence(rules),
      rules.enforceAttestationAtSignIn === true
        ? SENTENCES.attestationAtSignIn
        : SENTENCES.attestationAtRegistration,
      fill(SENTENCES.hints, {
        passkey: this.hintSentence(rules.passkeyHints),
        securityKey: this.hintSentence(rules.securityKeyHints),
        signIn: this.hintSentence(rules.signInHints) }),
      rules.enterpriseSerialAttribute
        ? fill(SENTENCES.enterpriseSerial,
               { attribute: rules.enterpriseSerialAttribute })
        : SENTENCES.noEnterpriseSerial,
      prompt,
      rules.aggregateDevices === false
        ? SENTENCES.chooseOne
        : SENTENCES.aggregate,
      rules.postQuantumRequired === 'registration-and-sign-in'
        ? SENTENCES.postQuantumEverywhere
        : (rules.postQuantumRequired === 'sign-in'
          ? SENTENCES.postQuantumSignIn
          : SENTENCES.postQuantumOff),
      rules.recoveryAssurance === 'operator-only'
        ? SENTENCES.recoveryOperatorOnly
        : (rules.recoveryAssurance === 'not-weaker'
          ? SENTENCES.recoveryNotWeaker : SENTENCES.recoveryAny),
      // #941: said only while a list is set, so a profile without one is
      // described as it was.
      ...(this.attestationAlgorithms(rules).length
        ? [fill(SENTENCES.attestationAlgorithms,
                { algorithms: this.attestationAlgorithms(rules).join(', ') })]
        : []),
      // #940: said only where the profile sets a registration row of its
      // own, so a profile following the realm is described as it was.
      ...this.registrationSentences(rules),
      // #945: said only while it is on, so a profile with it off is
      // described as it was.
      ...(this.adminEnrolmentAllowed(rules) ? [SENTENCES.adminEnrolment] : [])
    ];
    log.debug("Leaving PasskeyPolicy.describe().");
    return out;
  }

  // The registration rows in words (#940): nothing for a profile that follows
  // the realm, a mode's sentence, else the list's.
  private registrationSentences(rules: PasskeyProfile): string[] {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.registrationSentences().");
    const list = this.registrationAlgorithms(rules);
    const mode = this.registrationMode(rules);
    const algorithms = list.length ? list.join(', ')
      : SENTENCES['param.realmAlgorithms'];
    const template = mode === 'pq-only' ? SENTENCES.registrationPqOnly
      : (mode === 'pq-first' ? SENTENCES.registrationPqFirst
        : (mode === 'classical-only' ? SENTENCES.registrationClassicalOnly
          : (list.length ? SENTENCES.registrationList : '')));
    log.debug("Leaving PasskeyPolicy.registrationSentences(). " + mode);
    return template ? [serverProse.fill(template,
                                        { algorithms: algorithms })] : [];
  }

  // A hint list in words (#531).
  private hintSentence(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.hintSentence().");
    const list = PasskeyPolicy.listOf(value);
    log.debug("Leaving PasskeyPolicy.hintSentence().");
    return list.length ? list.join(', ') : SENTENCES['param.nothing'];
  }

  // The PIN-length rule in a sentence (#529).
  private pinLengthSentence(rules: PasskeyProfile): string {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.pinLengthSentence().");
    const rule = this.pinLengthRule(rules);
    log.debug("Leaving PasskeyPolicy.pinLengthSentence().");
    return !rule.enforce
      ? SENTENCES.noPinLength
      : serverProse.fill(rule.onlyIfSupported ? SENTENCES.pinLengthAccepted
                                              : SENTENCES.pinLengthRefused,
                         { n: rule.min });
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

  // A save's values with every optional row it left out filled as the save
  // will leave it (#940): the realm's own stored value (#907's rule), else
  // the built-in default.
  private standingValues(which: string,
                         values: Record<string, boolean | string | number>):
      Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.standingValues().");
    const out: Record<string, any> = Object.assign({}, DEFAULTS);
    const own = this.directory &&
      typeof this.directory.allPasskeyPolicies === 'function'
      ? (this.directory.allPasskeyPolicies() || []).filter(function (one) {
        return String(one.name || '').toLowerCase() === which;
      })[0] : null;
    FIELDS.forEach((field) => {
      if (values[field.key] !== undefined) {
        out[field.key] = values[field.key];
        return;
      }
      if (!field.optional || !own) {
        return;
      }
      const raw = this.firstValue(own.attributes || {}, field.attribute);
      const parsed = raw === '' ? null : this.parseField(field, raw);
      if (parsed && !parsed.problem) {
        out[field.key] = parsed.value;
      }
    });
    log.debug("Leaving PasskeyPolicy.standingValues().");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE REGISTRATION ROWS AGAINST THE REST OF THE PROFILE (#940), at the
  // save, so a contradiction is the operator's to resolve rather than a
  // population that can register nothing the profile accepts:
  //
  //   * `classical-only` with `postQuantumRequired` other than off — a
  //     classical passkey can never satisfy that requirement, at sign-in
  //     (`sign-in`) or at registration too (`registration-and-sign-in`).
  //     The ticket's own sentence: "Classical-only must not be able to
  //     satisfy a postQuantumRequired profile".
  //   * `classical-only` with `attestationAlgorithms` set — every value of
  //     that list is a post-quantum family, so it admits only authenticators
  //     that attest with a post-quantum key, and a population held to
  //     classical-only is the one whose devices cannot make ML-DSA; the
  //     pair admits next to nobody, and says two opposite things.
  //   * `pq-only` or `pq-first` where the algorithms the profile would offer
  //     (its own list, else the realm's webauthn.algorithms) name no ML-DSA —
  //     STS-AUTHN-0357's reason for postQuantumRequired: the mode would ask
  //     for something the list never offers.
  //
  // STS-AUTHN-0430 for the first two, 0431 for the third. Asked of the rows
  // as they will stand; a later change of webauthn.algorithms is answered at
  // registration (`webauthn_policy.ts` offers all three ML-DSA then, as
  // pqcOnly does), and a requirement inherited past a classical-only mode is
  // answered by #718's narrowing, which wins.
  // ---------------------------------------------------------------------------
  private registrationContradiction(values: Record<string, any>):
      { code: string; problem: string } | null {
    const { log } = this.deps;
    log.debug("Entering PasskeyPolicy.registrationContradiction().");
    const rows = this.registrationRows(values);
    const mode = rows.registrationMode;
    const modeLabel = '`registrationMode` (' +
      FIELD_BY_KEY.registrationMode.label + ') is ' + mode;
    if (mode === 'classical-only' && rows.postQuantumRequired !== 'off') {
      log.debug("Leaving PasskeyPolicy.registrationContradiction(). " +
                "Classical only, post-quantum required.");
      return { code: 'STS-AUTHN-0430',
               problem: modeLabel + ', and `postQuantumRequired` (' +
                        FIELD_BY_KEY.postQuantumRequired.label + ') is ' +
                        rows.postQuantumRequired + ': a classical passkey ' +
                        'can never satisfy that requirement, so this ' +
                        'profile\'s people could register nothing that ' +
                        'signs them in. Set one of the two differently.' };
    }
    const attested = String(values.attestationAlgorithms || NO_HINTS);
    if (mode === 'classical-only' && attested !== NO_HINTS) {
      log.debug("Leaving PasskeyPolicy.registrationContradiction(). " +
                "Classical only, post-quantum attestation required.");
      return { code: 'STS-AUTHN-0430',
               problem: modeLabel + ', and `attestationAlgorithms` (' +
                        FIELD_BY_KEY.attestationAlgorithms.label + ') is ' +
                        attested + ': that list admits only an ' +
                        'authenticator attesting with a post-quantum ' +
                        'signature, which is not the device a ' +
                        'classical-only population holds. Set ' +
                        'attestationAlgorithms to none, or choose another ' +
                        'mode.' };
    }
    if (mode === 'pq-only' || mode === 'pq-first') {
      const asked = config.value('webauthn.algorithms');
      const list = rows.registrationAlgorithms.length
        ? rows.registrationAlgorithms
        : (Array.isArray(asked) ? asked : String(asked || '').split(','))
          .map(function (name) {
            return String(name || '').trim();
          });
      if (!list.some(PasskeyPolicy.isPostQuantum)) {
        log.debug("Leaving PasskeyPolicy.registrationContradiction(). A " +
                  "post-quantum mode with no ML-DSA offered.");
        return { code: 'STS-AUTHN-0431',
                 problem: modeLabel + ', and the algorithms this profile ' +
                          'would offer (' + (rows.registrationAlgorithms
                            .length ? 'its registrationAlgorithms'
                                    : 'the realm\'s webauthn.algorithms') +
                          ': ' + (list.filter(Boolean).join(', ') ||
                                  'nothing') +
                          ') name no ML-DSA algorithm, so the mode would ' +
                          'ask for what the list never offers. Add ' +
                          'ML-DSA-44, ML-DSA-65 or ML-DSA-87 to the list.' };
      }
    }
    log.debug("Leaving PasskeyPolicy.registrationContradiction(). None.");
    return null;
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
      if (raw === undefined && field.optional) {
        // LEFT OUT, the built-in default stays (#724): see the header.
        return;
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
    // REQUIRED WITHOUT BEING ALLOWED (#608): a screen with no username
    // field and no passkey sign-in without one would sign nobody in.
    if (values.requireUsernameless === true &&
        values.allowUsernameless === false) {
      problems.push('`requireUsernameless` (' +
                    FIELD_BY_KEY.requireUsernameless.label + ') needs ' +
                    '`allowUsernameless` on: a sign-in screen with no ' +
                    'username field signs in only with a passkey that ' +
                    'names its own account.');
    }
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
    // A POST-QUANTUM PASSKEY REQUIRED WHERE NONE CAN BE MADE (#718): with no
    // ML-DSA offered at registration, nobody could enrol a passkey the
    // profile accepts, and under `sign-in` every passkey sign-in would stop
    // at once. Asked of the realm's WebAuthn settings as they are now; a
    // later change to them is answered by enrolment offering all three
    // ML-DSA algorithms anyway (`webauthn_policy.ts`), as `pqcOnly` does.
    // THE PROFILE AS IT WILL STAND (#940): an optional row left out of this
    // save keeps what the realm's own entry stored (#907, below), so the
    // contradictions are asked of that, not of the body alone — a save of
    // the old shape must not slip `postQuantumRequired` past a stored
    // `classical-only`.
    const standing = this.standingValues(which, checked.values);
    const contradiction = this.registrationContradiction(standing);
    if (contradiction) {
      log.debug('Leaving PasskeyPolicy.save(). The registration rows ' +
                'contradict another row.');
      return errorCodes.mark({ ok: false, errors: [contradiction.problem] },
                             contradiction.code);
    }
    if (standing.postQuantumRequired !== 'off' &&
        !this.deps.offersPostQuantum(this.registrationRows(standing))) {
      log.debug('Leaving PasskeyPolicy.save(). Post-quantum required and ' +
                'none offered.');
      return errorCodes.mark({ ok: false,
               errors: ['`postQuantumRequired` (' +
                        FIELD_BY_KEY.postQuantumRequired.label + ') is ' +
                        checked.values.postQuantumRequired + ', and this ' +
                        'realm offers no ML-DSA algorithm at registration ' +
                        '(webauthn.algorithms names none, and neither ' +
                        'webauthn.pqcOnly nor ' +
                        'webauthn.pqcAlongsideClassical is on), so no ' +
                        'passkey anybody could register would satisfy it. ' +
                        'Offer ML-DSA first.'] }, 'STS-AUTHN-0357');
    }
    // A BOUND SESSION REQUIRED WHERE NONE CAN BE OFFERED (#740). The same
    // shape as post-quantum required with no ML-DSA: the profile would ask
    // for a session this realm never offers to bind. Saving it off, or
    // leaving it out, succeeds while the switch is off.
    if (standing.deviceBoundRequired === true &&
        config.value('authn.deviceBoundSessions') !== true) {
      log.debug('Leaving PasskeyPolicy.save(). A device-bound session ' +
                'is required and the feature is off.');
      return errorCodes.mark({ ok: false,
               errors: ['`deviceBoundRequired` (' +
                        FIELD_BY_KEY.deviceBoundRequired.label +
                        ') is on, and authn.deviceBoundSessions is off, ' +
                        'so no session could meet it. Turn device-bound ' +
                        'sessions on first.'] },
                             'STS-AUTHN-0461');
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
    // An optional row LEFT OUT keeps what the realm's own entry stored
    // (#907): the write below replaces the whole entry, so writing nothing
    // for it deleted a stored `recoveryAssurance`, and a client written
    // before the row existed — the caller `optional` is for — silently
    // reverted the operator's choice to the built-in default.
    const own = this.directory.allPasskeyPolicies().filter(function (one) {
      return String(one.name || '').toLowerCase() ===
             String(which).toLowerCase();
    })[0];
    const storedValue = function (attribute: string): unknown {
      const held = (own && own.attributes) || {};
      const key = Object.keys(held).filter(function (k) {
        return k.toLowerCase() === attribute.toLowerCase();
      })[0];
      return key === undefined ? undefined : held[key];
    };
    FIELDS.forEach(function (field) {
      const value = checked.values[field.key];
      if (value === undefined && field.optional) {
        const kept = storedValue(field.attribute);
        if (kept !== undefined) {
          attributes[field.attribute] = kept;
        }
        return;
      }
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
  SENTENCES: PasskeyPolicy.SENTENCES,
  POST_QUANTUM_ALGORITHMS: POST_QUANTUM_ALGORITHMS,
  POST_QUANTUM_REQUIRED_VALUES: POST_QUANTUM_REQUIRED_VALUES,
  isPostQuantum: PasskeyPolicy.isPostQuantum,
  requiresPostQuantum: slot.forward('requiresPostQuantum'),
  POST_QUANTUM_ALLOW_CREDENTIALS: POST_QUANTUM_ALLOW_CREDENTIALS,
  postQuantumAllowCredentials: slot.forward('postQuantumAllowCredentials'),
  postQuantumRefusal: slot.forward('postQuantumRefusal'),
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileFor: slot.forward('profileFor'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  allowsUsernameless: slot.forward('allowsUsernameless'),
  requiresUsernameless: slot.forward('requiresUsernameless'),
  securityKeyResidentKey: slot.forward('securityKeyResidentKey'),
  refusesBackupEligible: slot.forward('refusesBackupEligible'),
  backupEligibleRefusal: slot.forward('backupEligibleRefusal'),
  pinLengthRule: slot.forward('pinLengthRule'),
  enforcesAttestationAtSignIn: slot.forward('enforcesAttestationAtSignIn'),
  // #941.
  ATTESTATION_ALGORITHM_VALUES: ATTESTATION_ALGORITHM_VALUES,
  attestationAlgorithms: slot.forward('attestationAlgorithms'),
  adminEnrolmentAllowed: slot.forward('adminEnrolmentAllowed'),
  attestationAlgorithmAllowed: PasskeyPolicy.attestationAlgorithmAllowed,
  // #940: a population's registration algorithms.
  REGISTRATION_MODES: REGISTRATION_MODES,
  REGISTRATION_ALGORITHM_VALUES: REGISTRATION_ALGORITHM_VALUES,
  registrationAlgorithms: slot.forward('registrationAlgorithms'),
  registrationMode: slot.forward('registrationMode'),
  registrationRows: slot.forward('registrationRows'),
  registrationAlgorithmsFrom: slot.forward('registrationAlgorithmsFrom'),
  hintsFor: slot.forward('hintsFor'),
  select: slot.forward('select'),
  selectionFor: slot.forward('selectionFor'),
  forApplication: slot.forward('forApplication'),
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
  question: slot.forward('question'),
  refusalFor: slot.forward('refusalFor'),
  recoveryAssurance: slot.forward('recoveryAssurance'),
  recoveryRefusal: slot.forward('recoveryRefusal'),
  RECOVERY_DOORS: PasskeyPolicy.RECOVERY_DOORS,
  RECOVERY_CREDENTIALS: PasskeyPolicy.RECOVERY_CREDENTIALS,
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
