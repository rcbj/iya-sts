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

const { log } = helpers;

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'bool' | 'enum' | 'int';
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
          'attestation fails every rule that demands one.' }
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
  }).concat([
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
    const profile = String(name || DEFAULT_PROFILE);
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
    const out = Object.assign({
      name: profile,
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
    return this.read(DEFAULT_PROFILE);
  }

  /**
   * Lists the profiles: the one profile in force.
   *
   * @returns a one-element list
   */
  list(): PasskeyProfile[] {
    const { log } = this.deps;
    log.debug('Entering PasskeyPolicy.list().');
    const rows = [this.read(DEFAULT_PROFILE)];
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
    const rules = profile || this.read(DEFAULT_PROFILE);
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
    const rules = profile || this.read(DEFAULT_PROFILE);
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
    const rules = profile || this.read(DEFAULT_PROFILE);
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
    const rules = profile || this.read(DEFAULT_PROFILE);
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
    const rules = profile || this.read(DEFAULT_PROFILE);
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
    const rules = profile || this.read(DEFAULT_PROFILE);
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
        : 'the attestation rules are checked when a passkey is registered'
    ];
    log.debug("Leaving PasskeyPolicy.describe().");
    return out;
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
    if (text.toLowerCase() !== DEFAULT_PROFILE) {
      log.debug("Leaving PasskeyPolicy.checkProfileName().");
      return 'There is one passkey policy profile, "' + DEFAULT_PROFILE +
             '", and it applies to every person in this realm. "' +
             text.slice(0, 64) + '" cannot be created: nothing assigns a ' +
             'profile to a person yet (#535), so a second one would decide ' +
             'nothing while looking exactly like one that does.';
    }
    log.debug("Leaving PasskeyPolicy.checkProfileName().");
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
    const checked = this.validate(given);
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
    const written = this.directory.writePasskeyPolicy(DEFAULT_PROFILE,
                                                      attributes);
    if (!written) {
      log.debug('Leaving PasskeyPolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-AUTHN-0311');
    }
    log.debug('Leaving PasskeyPolicy.save(). Stored.');
    return { ok: true, profile: this.read(DEFAULT_PROFILE) };
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
    if (!this.haveDirectory()) {
      log.debug('Leaving PasskeyPolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(DEFAULT_PROFILE) };
    }
    const removed = !!this.directory.deletePasskeyPolicy(DEFAULT_PROFILE);
    log.debug('Leaving PasskeyPolicy.reset(). ' +
              (removed ? 'Removed.' : 'Nothing stored.'));
    return { ok: true, removed: removed,
             profile: this.read(DEFAULT_PROFILE) };
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
  pinLengthRefusal: slot.forward('pinLengthRefusal'),
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
