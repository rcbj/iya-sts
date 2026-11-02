// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: service_account_policy.ts
//
// ---------------------------------------------------------------------------
// THE SERVICE-ACCOUNT POLICY (#221, 2026-10-06): WHAT A REALM ALLOWS A
// SERVICE ACCOUNT, AND HOW ITS PASSWORD ROTATES.
//
// rcbj's decisions on #221 (2026-10-05): a service account is a PERSON entry
// with a flag (`common/service_accounts.ts`), and "Directory → Policies gets a
// third kind of policy, the service-account policy. Like the other two it is
// set per realm and inherited from the default realm. *Is MFA exempt for
// service accounts in this realm?* is its first question, and more will
// follow." This is that policy: a module of its own, sharing nothing with the
// password and authentication policies but `password_policy.ts`'s interface,
// put on the one page by `admin-core/policy_kinds.ts`.
//
// ---------------------------------------------------------------------------
// EVERY DEFAULT IS THE MORE SECURE ONE.
//
//   exemptFromSecondFactor   false. True takes a service account out of the
//                            authentication policy's second-factor
//                            requirements and out of the password-only doors'
//                            refusal (#101); `amr` still says `pwd` alone, so
//                            no relying party is told it got more.
//   allowBrowserSignIn       false. A service account signs in to no browser
//                            surface — the sign-in screen, the portal, the
//                            console — under STS-SVCACCT-0010, whichever
//                            first factor it presented.
//   the seven door rows      true. Which password doors accept the account:
//                            LDAP bind, WS-Trust UsernameToken, SCIM, SSF and
//                            EST Basic, the Kerberos AS exchange and the OAuth
//                            2.0 password grant. ALL ON because a service
//                            account exists to use them; the realm narrows.
//   rotationEnabled          false. Rotation pushes a password somewhere, and
//                            a new install has nowhere to push it
//                            (new-install-self-contained).
//   rotationIntervalDays     30.
//   rotationOverlapMinutes   60: how long the previous password still works.
//   generatedLength          32, and never below the password policy's
//                            minimum — the generated password meets that
//                            policy, which `credentials.preparePassword()`
//                            asks as at every door (3ac).
//   requireOwner             true. rcbj: "The owner is required, and the
//                            owner may be a person or a group."
//   rotationAlarmFailures    3 consecutive failed rotations before the alarm.
//
// **THE DOORS ARE ROWS, NOT A LIST.** The design named the field
// `allowedDoors`; it is seven yes-or-no rows here, one per door, because
// every policy on the page is drawn from its FIELDS by type, a save replaces
// the whole profile, and a row per door says on the page what each one is.
// `allowedDoors()` answers the list the design described.
//
// **THERE IS NO MAXIMUM-AGE RULE.** The design asked that the rotation
// interval not exceed the password policy's maximum age "where one is set";
// that policy has no maximum age (NIST SP 800-63B-4 section 3.1.1.2 asks
// verifiers not to require periodic changes), so there is nothing to compare
// against, and the rule is written down here rather than invented.
//
// ---------------------------------------------------------------------------
// WHERE IT LIVES: `cn=default,ou=serviceAccountPolicies`, AND A REALM
// INHERITS — `authn_policy.ts`'s arrangement exactly: a realm with no entry
// of its own follows the default realm's, then the built-in defaults; `reset`
// deletes the realm's own entry. Not seeded, for the password policy's reason.
//
// ---------------------------------------------------------------------------
// NAMED POLICIES, NAMED BY THE ACCOUNT (#1240, rcbj's decisions on #1234).
// Beside `default` a realm may hold named profiles (`cn=<name>`, lower-case
// letters, digits and hyphens), each the whole field set and a precedence
// (`stsServiceAccountPrecedence`), and each the REALM'S OWN: a named profile
// is never inherited from the default realm, where `default` still is.
//
//   * WHAT A PROFILE COVERS NAMES IT: a service account names its profile in
//     `stsServiceAccountPolicy` on its own entry, and nothing else does — no
//     application and no group, because the policy governs the account and
//     nothing else is one. The ranking is `policy_selection.ts`'s (3cx) with
//     one candidate, the person's, so the precedence is carried for the
//     common shape and decides nothing yet.
//   * ONLY A SERVICE ACCOUNT MAY NAME ONE (STS-SVCACCT-0048), at every door
//     that writes the attribute: the person editor (through this kind's
//     `holderRefusal` in its declaration), an LDAP add or modify
//     (`ldap_server.js`'s `serviceAccountWriteRefusal()`, asking
//     `writeRefusal()` here) and a create. The attribute is in
//     `service_accounts.ts`'s list, so it is cleared with the flag.
//   * A REFERENCE THE REALM DOES NOT HOLD applies `default` and is logged
//     (STS-SVCACCT-0047). Not fail-closed, as the authentication policy is,
//     because every field's default here is already the more secure one: the
//     default profile refuses a browser, exempts nobody from the second
//     factor and requires an owner unless the realm loosened it — and what
//     it governed before the account named anything. Refusing every door
//     would stop a program, and stopping the rotation would leave a password
//     unrotated, which is weaker, not stronger. And the reference cannot
//     dangle through this service: it is checked at every write and a named
//     profile is not deleted while an account names it (STS-SVCACCT-0049).
//   * EVERY READER RESOLVES THE ACCOUNT'S OWN PROFILE: the doors
//     (`credentials.serviceAccountRefusesDoor()`), the exemption
//     (`credentials.mfaRequirementFor()`), the browser (the console's
//     sign-out on becoming one), `requireOwner` at create and edit
//     (`service_accounts.check()`, the LDAP door), and the rotation job,
//     where each account rotates on its own profile's interval, overlap,
//     length and alarm threshold (`service_account_rotation.ts`).
//   * WHO NAMES A PROFILE is answered from the service-account index
//     (`service_accounts.names()`), not from a walk of the realm: only a
//     service account may hold the reference, so the realm's service accounts
//     are every possible holder, and that index is what the rotation job
//     already reads.
//
// IT IS A LIBRARY (rule 3) AND A LEAF: `helpers`, `realms`, `error_codes`,
// the instance slot, `policy_selection.ts` (a leaf), the directory through a
// slot `ldap/ldap_server.js` fills, and — LAZILY — the password policy (its
// minimum length), the destinations (`common/secret_destinations.ts`),
// which nothing that asks "may this account bind" should load, and
// `service_accounts.ts`, which requires this module lazily in its turn.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
// The sentences `describe()` makes are filled from SENTENCES below, so the
// server can translate them into a console reader's language (#543).
import serverProse = require('./server_prose');
// The shared selection (#1235, rule 3cx): the ranking, the name and
// precedence checks, the register of person references.
import PolicySelection = require('./policy_selection');

const { log } = helpers;

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'int' | 'bool';
  dflt: number | boolean;
  min?: number;
  max?: number;
  label: string;
  unit?: string;
  door?: string;
  what: string;
}

interface DirectoryHooks {
  allServiceAccountPolicies?(): { name?: string; dn: string;
                                  attributes?: Record<string, unknown> }[];
  writeServiceAccountPolicy?(name: string,
                             attributes: Record<string, unknown>): unknown;
  deleteServiceAccountPolicy?(name: string): unknown;
  [hook: string]: unknown;
}

interface ServiceAccountProfile {
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
  profile?: ServiceAccountProfile;
}

interface ServiceAccountPolicyDeps {
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
  // The password policy's minimum length in this realm, asked lazily.
  passwordMinLength(): number;
  // How many push destinations this realm has, asked lazily; -1 where the
  // destination register is not loaded in this process.
  destinationCount(): number;
  // The named profile a service account names (#1240), '' for none or for
  // an entry that is not a service account.
  referenceOf(username: string): string;
  // The service accounts naming a profile (#1240).
  peopleNaming(name: string): string[];
  // Whether an entry's attributes are a service account's.
  isServiceAccount(attributes: Record<string, unknown>): boolean;
}

/**
 * The name of the realm's own service-account policy profile, `default`.
 */
const DEFAULT_PROFILE = 'default';

/**
 * What a refusal calls one.
 */
const NOUN = 'service-account policy';

/**
 * A named profile's one selector (#1240): its precedence.
 */
const SELECTORS = [
  { key: 'precedence', attribute: 'stsServiceAccountPrecedence',
    what: 'Which named service-account policy wins where several are ' +
          'named: the lowest, from 1 to 1000. A service account names one ' +
          'policy, so today it decides nothing.' }
];

/**
 * How `common/policy_selection.ts` reads a named profile (#1240).
 */
const SELECTION = { precedenceAttribute: 'stsServiceAccountPrecedence',
                    defaultPrecedence: PolicySelection.DEFAULT_PRECEDENCE };

/**
 * The attribute that NAMES a service-account profile (#1240): on the
 * service account's own entry, and nowhere else.
 */
const REFERENCES = Object.freeze({ person: 'stsServiceAccountPolicy' });

/**
 * The password doors a service account may be allowed, in the order the page
 * draws them. `id` is what a door passes to `credentials.verify()` as `door`
 * (`browser` and `kerberos` are answered by the sign-in funnel and the KDC).
 */
// ---------------------------------------------------------------------------
// THE SENTENCES `describe()` MAKES, as templates (#543 phase 2) — one copy,
// filled there with `ServerProse.fill()` and matched by
// `common/server_prose.ts` to refill in a console reader's language. A
// `param.` key is a phrase that only ever stands inside another sentence.
// ---------------------------------------------------------------------------
const SENTENCES: Readonly<Record<string, string>> = Object.freeze({
  exempt: 'service accounts are EXEMPT from the second factor',
  notExempt: 'service accounts meet the second-factor rules everybody does',
  browser: 'service accounts may sign in at a browser',
  noBrowser: 'service accounts are refused at every browser sign-in',
  doors: 'password doors: {{list}}',
  'param.none': 'none',
  rotation: 'passwords rotate every {{days}} days, the previous one ' +
    'working for {{minutes}} minutes',
  noRotation: 'passwords do not rotate automatically',
  owner: 'every service account names an owner',
  noOwner: 'a service account may have no owner'
});

const DOORS = [
  { id: 'ldap', key: 'allowLdapBind', label: 'LDAP simple bind',
    what: 'A bind on 389 or 636 (RFC 4513).' },
  { id: 'wstrust', key: 'allowWsTrust', label: 'WS-Trust UsernameToken',
    what: 'A WS-Security UsernameToken sent to the security token service.' },
  { id: 'scim', key: 'allowScim', label: 'SCIM HTTP Basic',
    what: 'HTTP Basic at /scim/v2 (RFC 7617).' },
  { id: 'ssf', key: 'allowSsf', label: 'Shared Signals HTTP Basic',
    what: 'HTTP Basic at the /ssf endpoints (RFC 7617).' },
  { id: 'est', key: 'allowEst', label: 'EST HTTP Basic',
    what: 'HTTP Basic at /.well-known/est (RFC 7030 section 3.2.3).' },
  { id: 'kerberos', key: 'allowKerberos', label: 'Kerberos AS exchange',
    what: 'An AS-REQ whose pre-authentication proves the password\'s key ' +
          '(RFC 4120), and MS-KKDCP.' },
  { id: 'ropc', key: 'allowPasswordGrant', label: 'OAuth 2.0 password grant',
    what: 'grant_type=password at the token endpoint (RFC 6749 section ' +
          '4.3), where the realm allows the grant at all.' }
];

/**
 * The policy's fields: one table read as the schema, the console form, the API
 * body, the validation of a save and the parse of an entry.
 */
const FIELDS: PolicyField[] = ([
  { key: 'exemptFromSecondFactor',
    attribute: 'stsSvcAcctExemptFromSecondFactor', type: 'bool', dflt: false,
    label: 'Service accounts are exempt from the second factor',
    what: 'OFF BY DEFAULT. On, the authentication policy\'s second-factor ' +
          'requirements do not apply to a service account in this realm, ' +
          'and nor does the refusal of a password alone at the password ' +
          'doors (#101). The account\'s amr still says pwd only, so a ' +
          'relying party asking for more is refused it. WEAKER: an account ' +
          'on a password alone is an account anyone with the password is.' },
  { key: 'allowBrowserSignIn', attribute: 'stsSvcAcctAllowBrowserSignIn',
    type: 'bool', dflt: false,
    label: 'Service accounts may sign in at a browser',
    what: 'OFF BY DEFAULT. Off, the sign-in screen, the user portal and the ' +
          'admin console refuse a service account, whichever first factor ' +
          'it presents, and turning a person into a service account ends ' +
          'their browser sessions. A service account is used by a program, ' +
          'and a program has no business at a sign-in screen.' }
] as PolicyField[]).concat(DOORS.map(function (door) {
  return { key: door.key,
           attribute: 'stsSvcAcct' + door.key.charAt(0).toUpperCase() +
                      door.key.slice(1),
           type: 'bool' as const, dflt: true, door: door.id,
           label: 'Door: ' + door.label, what: door.what +
             ' Off, a service account\'s right password is refused there ' +
             'as a wrong one is.' };
})).concat([
  { key: 'rotationEnabled', attribute: 'stsSvcAcctRotationEnabled',
    type: 'bool', dflt: false,
    label: 'Rotate service-account passwords automatically',
    what: 'OFF BY DEFAULT. On, the service-accounts.rotate job gives every ' +
          'service account that names a push destination a new generated ' +
          'password each interval: pushed to the destination FIRST, its hash ' +
          'committed only after the push succeeds, the previous password ' +
          'kept for the overlap below. A failed push changes nothing. Cannot ' +
          'be turned on while this realm has no push destination.' },
  { key: 'rotationIntervalDays', attribute: 'stsSvcAcctRotationIntervalDays',
    type: 'int', dflt: 30, min: 1, max: 3650, unit: 'days',
    label: 'Rotation interval',
    what: 'How long a service account\'s password is kept before the job ' +
          'replaces it, counted from the last rotation (or the account\'s ' +
          'last password change).' },
  { key: 'rotationOverlapMinutes',
    attribute: 'stsSvcAcctRotationOverlapMinutes', type: 'int', dflt: 60,
    min: 0, max: 10080, unit: 'minutes',
    label: 'How long the previous password still works',
    what: 'After a rotation the previous password is accepted for this ' +
          'long, so a consumer slow to read the new one is not refused — ' +
          'nor counted by risk scoring as guessing (#226). The previous ' +
          'Kerberos keys are kept as long. 0: the old password stops at ' +
          'once.' },
  { key: 'generatedLength', attribute: 'stsSvcAcctGeneratedLength',
    type: 'int', dflt: 32, min: 16, max: 128, unit: 'characters',
    label: 'Length of a rotated password',
    what: 'Drawn by the password policy\'s generator, so it meets that ' +
          'policy, and never shorter than its minimum length.' },
  { key: 'requireOwner', attribute: 'stsSvcAcctRequireOwner', type: 'bool',
    dflt: true,
    label: 'A service account must name an owner',
    what: 'ON BY DEFAULT. The owner — a person or a group in this realm — ' +
          'is who answers for the account; a service account cannot be ' +
          'saved without one while this is on.' },
  { key: 'rotationAlarmFailures',
    attribute: 'stsSvcAcctRotationAlarmFailures', type: 'int', dflt: 3,
    min: 1, max: 100, unit: 'failures',
    label: 'Failed rotations in a row before the alarm',
    what: 'A failed rotation is retried at the job\'s next run. After this ' +
          'many in a row the account is reported on Monitoring → Service ' +
          'accounts and logged as an alarm (STS-SVCACCT-0042).' }
]);

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
const DEFAULTS: Readonly<Record<string, number | boolean>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    out[field.key] = field.dflt;
    return out;
  }, {} as Record<string, number | boolean>));

/**
 * The directory schema of `ou=serviceAccountPolicies`: its container, object
 * class and attributes.
 */
const SCHEMA = {
  container: 'ou=serviceAccountPolicies',
  objectClasses: [
    { name: 'stsServiceAccountPolicy',
      what: 'This service\'s class for a service-account policy: what a ' +
            'service account in this realm may do and how its password ' +
            'rotates. The entry is named by the PROFILE: `cn=default`, or ' +
            'a named profile a service account names in its ' +
            'stsServiceAccountPolicy.' }
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
 * The service-account policy: what a realm allows a service account — the
 * second factor, the browser, the password doors — and how its password
 * rotates.
 *
 * Kept as a `stsServiceAccountPolicy` entry in `ou=serviceAccountPolicies`; a
 * realm with no entry of its own inherits the default realm's, and failing that
 * the built-in defaults.
 */
class ServiceAccountPolicy {
  /**
   * The name of the realm's own profile, `default`.
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
   * The password doors a service account may be allowed.
   */
  static readonly DOORS = DOORS;
  /**
   * The directory schema of `ou=serviceAccountPolicies`.
   */
  static readonly SCHEMA = SCHEMA;
  /**
   * The sentences `describe()` makes, as templates (#543).
   */
  static readonly SENTENCES = SENTENCES;
  /**
   * A named profile's selectors: its precedence (#1240).
   */
  static readonly SELECTORS = SELECTORS;
  /**
   * The attribute a service account names its profile by (#1240).
   */
  static readonly REFERENCES = REFERENCES;

  private directory: DirectoryHooks | null = null;
  private warnedAboutNoDirectory = false;

  /**
   * Builds the policy with no directory installed.
   *
   * @param deps - the logger, realms, error codes, and lazy reads of the
   *   password policy's minimum and the destination count
   */
  constructor(private readonly deps: ServiceAccountPolicyDeps) {
    deps.log.debug("Entering ServiceAccountPolicy.constructor().");
    deps.log.debug("Leaving ServiceAccountPolicy.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules, and lazy reads of the password policy
   *   and the destination register
   */
  static defaultDeps(): ServiceAccountPolicyDeps {
    log.debug("Entering ServiceAccountPolicy.defaultDeps().");
    log.debug("Leaving ServiceAccountPolicy.defaultDeps().");
    return {
      log: log,
      realms: realms,
      errorCodes: errorCodes,
      passwordMinLength: function () {
        log.debug("Entering ServiceAccountPolicy passwordMinLength().");
        // LAZY, for the header's reason. The password policy is a leaf too.
        const passwordPolicy = require('./password_policy');
        const out = Number(passwordPolicy.read().minLength) || 0;
        log.debug("Leaving ServiceAccountPolicy passwordMinLength().");
        return out;
      },
      destinationCount: function () {
        log.debug("Entering ServiceAccountPolicy destinationCount().");
        let out = -1;
        try {
          // LAZY: the register is built after this module, and a process
          // that never loaded it (a test of this file alone) answers -1.
          const destinations = require('./secret_destinations');
          out = typeof destinations.list === 'function'
            ? destinations.list().length : -1;
        } catch (e) {
          log.debug("Caught in ServiceAccountPolicy destinationCount(): " +
                    ((e && e.message) || e));
          out = -1;
        }
        log.debug("Leaving ServiceAccountPolicy destinationCount().");
        return out;
      },
      referenceOf: function (username) {
        log.debug("Entering ServiceAccountPolicy referenceOf().");
        // LAZY, for the header's reason: the register requires this module
        // lazily too, and neither may load the other at load.
        const out = String(require('./service_accounts')
          .policyReference(username) || '');
        log.debug("Leaving ServiceAccountPolicy referenceOf().");
        return out;
      },
      peopleNaming: function (name) {
        log.debug("Entering ServiceAccountPolicy peopleNaming().");
        const accounts = require('./service_accounts');
        const wanted = PolicySelection.fold(name);
        // THE SERVICE-ACCOUNT INDEX, not the realm: only a service account
        // holds the reference (the header). One entry read per account.
        const out = (accounts.names() || []).filter(function (one) {
          return accounts.policyReference(one) === wanted;
        });
        log.debug("Leaving ServiceAccountPolicy peopleNaming(). " +
                  out.length);
        return out;
      },
      isServiceAccount: function (attributes) {
        log.debug("Entering ServiceAccountPolicy isServiceAccount().");
        const out = !!require('./service_accounts')
          .isServiceAccount(attributes);
        log.debug("Leaving ServiceAccountPolicy isServiceAccount().");
        return out;
      }
    };
  }

  /**
   * Installs the directory hooks the policy is read from and written to; filled
   * by the directory.
   *
   * @param hooks - the directory's policy hooks, or null to remove them
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug('Entering ServiceAccountPolicy.setDirectory().');
    this.directory = hooks || null;
    log.debug('Leaving ServiceAccountPolicy.setDirectory(). The register ' +
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
    log.debug("Entering ServiceAccountPolicy.directoryInstalled().");
    log.debug("Leaving ServiceAccountPolicy.directoryInstalled().");
    return this.directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.haveDirectory().");
    if (this.directory &&
        typeof this.directory.allServiceAccountPolicies === 'function') {
      log.debug("Leaving ServiceAccountPolicy.haveDirectory().");
      return true;
    }
    if (!this.warnedAboutNoDirectory) {
      this.warnedAboutNoDirectory = true;
      log.warn('service_account_policy: the embedded directory was never ' +
               'loaded, so there is no ou=serviceAccountPolicies. The ' +
               'BUILT-IN service-account policy is in force and cannot be ' +
               'edited in this process.');
    }
    log.debug("Leaving ServiceAccountPolicy.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  private firstValue(attributes: Record<string, unknown>,
                     name: string): unknown {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.firstValue().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving ServiceAccountPolicy.firstValue().");
    return Array.isArray(found) ? (found[0] === undefined ? '' : found[0])
      : (found === undefined || found === null ? '' : found);
  }

  // `authn_policy.ts`'s parse without its `enum`. Never guesses.
  private parseField(field: PolicyField,
                     raw: unknown): { value?: number | boolean;
                                      problem?: string } {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.parseField().");
    const text = String(raw === undefined || raw === null ? '' : raw).trim();
    if (field.type === 'bool') {
      const lower = text.toLowerCase();
      if (['true', 'on', '1'].indexOf(lower) >= 0) {
        log.debug("Leaving ServiceAccountPolicy.parseField().");
        return { value: true };
      }
      if (['false', 'off', '0', ''].indexOf(lower) >= 0) {
        log.debug("Leaving ServiceAccountPolicy.parseField().");
        return { value: false };
      }
      log.debug("Leaving ServiceAccountPolicy.parseField().");
      return { problem: field.label + ' is a yes-or-no setting, and "' +
                        text.slice(0, 40) + '" is neither.' };
    }
    if (!/^\d+$/.test(text)) {
      log.debug("Leaving ServiceAccountPolicy.parseField().");
      return { problem: field.label + ' must be a whole number between ' +
                        field.min + ' and ' + field.max + '; "' +
                        text.slice(0, 40) + '" is not one.' };
    }
    const value = Number(text);
    if (value < field.min || value > field.max) {
      log.debug("Leaving ServiceAccountPolicy.parseField().");
      return { problem: field.label + ' must be between ' + field.min +
                        ' and ' + field.max + '; ' + value + ' is not.' };
    }
    log.debug("Leaving ServiceAccountPolicy.parseField().");
    return { value: value };
  }

  // The rules that relate fields, asked of a save. `forSave` adds the two
  // that read OTHER registers (the password policy, the destinations), which
  // a read does not repeat: a profile already stored is reported by what it
  // says, and the password policy changing under it is that policy's save.
  private crossFieldProblems(values: Record<string, any>,
                             forSave: boolean): string[] {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.crossFieldProblems().");
    const out: string[] = [];
    if (forSave) {
      let minimum = 0;
      try {
        minimum = this.deps.passwordMinLength();
      } catch (e) {
        log.debug("Caught in ServiceAccountPolicy.crossFieldProblems(): " +
                  ((e && e.message) || e));
        minimum = 0;
      }
      if (Number(values.generatedLength) < minimum) {
        out.push('A rotated password of ' + values.generatedLength +
                 ' characters is shorter than this realm\'s password policy ' +
                 'allows (' + minimum + '). Raise the length, or lower the ' +
                 'password policy\'s minimum first.');
      }
      if (values.rotationEnabled === true &&
          this.deps.destinationCount() === 0) {
        out.push('Rotation cannot be turned on while this realm has no push ' +
                 'destination: a rotated password has to be pushed ' +
                 'somewhere before it is used. Register one under Directory ' +
                 '→ Secret destinations first.');
      }
    }
    log.debug("Leaving ServiceAccountPolicy.crossFieldProblems().");
    return out;
  }

  private entryIn(name: string) {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.entryIn().");
    const wanted = name.toLowerCase();
    log.debug("Leaving ServiceAccountPolicy.entryIn().");
    return this.directory.allServiceAccountPolicies().filter(function (entry) {
      return String(entry.name || '').toLowerCase() === wanted;
    })[0] || null;
  }

  // THIS REALM'S OWN ENTRY, THEN THE DEFAULT REALM'S — `authn_policy.ts`'s
  // `entryFor()`.
  private entryFor(name: string):
      { entry: any; from: ServiceAccountProfile['from'] } {
    const { log, realms } = this.deps;
    log.debug("Entering ServiceAccountPolicy.entryFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving ServiceAccountPolicy.entryFor(). No directory.");
      return { entry: null, from: 'built-in' };
    }
    const own = this.entryIn(name);
    if (own) {
      log.debug("Leaving ServiceAccountPolicy.entryFor(). The realm's own.");
      return { entry: own, from: 'realm' };
    }
    // A NAMED PROFILE IS THE REALM'S OWN (#1240): only `default` inherits.
    if (realms.isDefault() || name.toLowerCase() !== DEFAULT_PROFILE) {
      log.debug("Leaving ServiceAccountPolicy.entryFor(). Built-in.");
      return { entry: null, from: 'built-in' };
    }
    const inherited = realms.run(realms.DEFAULT_REALM, () => {
      log.debug("Entering ServiceAccountPolicy.entryFor() default-realm " +
                "read.");
      const found = this.entryIn(name);
      log.debug("Leaving ServiceAccountPolicy.entryFor() default-realm read.");
      return found;
    });
    log.debug("Leaving ServiceAccountPolicy.entryFor(). " +
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
  read(name?: string): ServiceAccountProfile {
    const { log } = this.deps;
    log.debug('Entering ServiceAccountPolicy.read(). name=' + name);
    const profile = String(name || DEFAULT_PROFILE).trim().toLowerCase();
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
      // THE PRECEDENCE (#1240): 0 for `default`, which is never ranked.
      precedence: profile === DEFAULT_PROFILE ? 0
        : PolicySelection.precedenceOf(entry ? entry.attributes || {} : {},
                                       SELECTION),
      stored: found.from === 'realm',
      inherited: found.from === 'default-realm',
      from: found.from,
      dn: entry ? entry.dn : '',
      description: entry ? String(this.firstValue(entry.attributes || {},
                                                  'description')) : '',
      sources: sources,
      problems: problems,
      // Like the authentication policy, and unlike a password rule, this
      // decides who gets in, so it is in force in both modes.
      enforced: true
    }, values) as ServiceAccountProfile;
    log.debug('Leaving ServiceAccountPolicy.read(). From ' + found.from + '.');
    return out;
  }

  /**
   * Returns the profile that governs a service account (#1240): the one its
   * `stsServiceAccountPolicy` names, else `default`.
   *
   * @param username - the account; '' or a person who is not one gets
   *   `default`
   * @returns the profile in force for it
   */
  profileFor(username?: unknown): ServiceAccountProfile {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.profileFor().");
    const name = String(username === undefined || username === null ? ''
      : username).trim();
    let reference = '';
    if (name) {
      try {
        reference = this.deps.referenceOf(name);
      } catch (e) {
        log.debug("Caught in ServiceAccountPolicy.profileFor(): " +
                  ((e && e.message) || e));
        // The register unreadable is no reference: `default`, the baseline.
        reference = '';
      }
    }
    log.debug("Leaving ServiceAccountPolicy.profileFor().");
    return this.profileForReference(reference, name);
  }

  /**
   * Returns the profile a reference comes to (#1240): the named profile the
   * realm holds, else `default` — and a name the realm does not hold is
   * logged (STS-SVCACCT-0047) and gets `default` too (the header says why).
   *
   * @param reference - the `stsServiceAccountPolicy` value, '' for none
   * @param holder - the account, for the log line
   * @returns the profile in force
   */
  profileForReference(reference: unknown,
                      holder?: unknown): ServiceAccountProfile {
    const { log, errorCodes } = this.deps;
    log.debug("Entering ServiceAccountPolicy.profileForReference().");
    if (!PolicySelection.fold(reference) || !this.haveDirectory()) {
      log.debug("Leaving ServiceAccountPolicy.profileForReference(). " +
                "Default.");
      return this.read(DEFAULT_PROFILE);
    }
    const ranked = PolicySelection.rank(
      this.directory.allServiceAccountPolicies(), SELECTION,
      [{ by: 'person', holder: String(holder || ''), value: reference }]);
    ranked.missing.forEach(function (one) {
      log.warn(errorCodes.tag('STS-SVCACCT-0047') + 'service-account ' +
               'policy: the service account "' + one.holder + '" names ' +
               'the service-account policy "' + one.name + '", which this ' +
               'realm does not hold; `default` governs it until the policy ' +
               'exists or the reference changes.');
    });
    log.debug("Leaving ServiceAccountPolicy.profileForReference(). " +
              ranked.name);
    return this.read(ranked.name);
  }

  /**
   * Lists the profiles: `default`, then this realm's named profiles by
   * precedence, ties by name (#1240).
   *
   * @returns the profiles
   */
  list(): ServiceAccountProfile[] {
    const { log } = this.deps;
    log.debug('Entering ServiceAccountPolicy.list().');
    const named = this.haveDirectory()
      ? PolicySelection.named(this.directory.allServiceAccountPolicies(),
                              SELECTION) : [];
    const rows = [this.read(DEFAULT_PROFILE)].concat(named.map((one) => {
      return this.read(one.name);
    }).sort(function (a, b) {
      return a.precedence - b.precedence || (a.name < b.name ? -1 : 1);
    }));
    log.debug('Leaving ServiceAccountPolicy.list(). ' + rows.length +
              ' profile(s).');
    return rows;
  }

  /**
   * Says whether any profile of this realm — `default` or a named one —
   * turns rotation on (#1240): the hourly job is off only where none does.
   *
   * @returns true where some service account could be rotated
   */
  rotatesAnywhere(): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.rotatesAnywhere().");
    const out = this.list().some((one) => {
      return this.rotation(one).enabled;
    });
    log.debug("Leaving ServiceAccountPolicy.rotatesAnywhere(). " + out);
    return out;
  }

  /**
   * What names a named profile (#1240): the service accounts whose
   * `stsServiceAccountPolicy` names it. No application or group names a
   * service-account profile.
   *
   * @param name - the profile's name
   * @returns `{ applications, groups, people }`
   */
  namedBy(name: unknown): { applications: string[]; groups: string[];
                            people: string[] } {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.namedBy().");
    const wanted = PolicySelection.fold(name);
    let people: string[] = [];
    if (wanted && wanted !== DEFAULT_PROFILE) {
      try {
        people = this.deps.peopleNaming(wanted);
      } catch (e) {
        log.debug("Caught in ServiceAccountPolicy.namedBy(): " +
                  ((e && e.message) || e));
        people = [];
      }
    }
    log.debug("Leaving ServiceAccountPolicy.namedBy(). " + people.length +
              " account(s).");
    return { applications: [], groups: [], people: people };
  }

  /**
   * Refuses a reference written onto an entry that may not hold it, or one
   * naming a profile the realm does not hold (#1240) — what an LDAP add or
   * modify and a create ask, beside the person editor's declaration.
   *
   * @param attributes - the entry's attributes as they would stand (any
   *   case, arrays or strings)
   * @returns `{ code, message }`, or null
   */
  writeRefusal(attributes: Record<string, unknown>):
      { code: string; message: string } | null {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.writeRefusal().");
    const value = PolicySelection.valuesOf(attributes,
                                           REFERENCES.person)[0];
    const text = PolicySelection.fold(value);
    if (!text) {
      log.debug("Leaving ServiceAccountPolicy.writeRefusal(). None.");
      return null;
    }
    const holder = this.holderRefusal(attributes);
    if (holder) {
      log.debug("Leaving ServiceAccountPolicy.writeRefusal(). Not a " +
                "service account.");
      return holder;
    }
    const choices = this.list().map(function (one) {
      return one.name;
    });
    const problem = PolicySelection.referenceProblem(text, choices,
                                                     REFERENCES.person);
    log.debug("Leaving ServiceAccountPolicy.writeRefusal(). " +
              (problem ? 'Not held.' : 'Allowed.'));
    return problem ? { code: 'STS-SVCACCT-0050', message: problem } : null;
  }

  /**
   * Refuses the reference on an entry that is not a service account
   * (#1240): this kind's `holderRefusal`, in its declaration.
   *
   * @param attributes - the entry's attributes
   * @returns `{ code, message }`, or null for a service account
   */
  holderRefusal(attributes: Record<string, unknown>):
      { code: string; message: string } | null {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.holderRefusal().");
    if (this.deps.isServiceAccount(attributes || {})) {
      log.debug("Leaving ServiceAccountPolicy.holderRefusal(). One.");
      return null;
    }
    log.debug("Leaving ServiceAccountPolicy.holderRefusal(). Not one.");
    return { code: 'STS-SVCACCT-0048',
             message: REFERENCES.person + ' names the service-account ' +
               'policy that governs a SERVICE ACCOUNT, and this person is ' +
               'not one. Make them a service account first (the Service ' +
               'account tab, or POST /admin-api/users/set-service-account).' };
  }

  // -------------------------------------------------------------------------
  // WHAT THE DOORS ASK.
  // -------------------------------------------------------------------------
  /**
   * Says whether a service account in this realm may use a door.
   *
   * @param door - a door id from `DOORS`, or `browser`
   * @param profile - a profile already read; read afresh when omitted
   * @returns false for a door this policy does not name: refuse by default
   */
  allowsDoor(door: string, profile?: ServiceAccountProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.allowsDoor(). " + door);
    const rules = profile || this.read(DEFAULT_PROFILE);
    if (door === 'browser') {
      log.debug("Leaving ServiceAccountPolicy.allowsDoor(). Browser.");
      return rules.allowBrowserSignIn === true;
    }
    const row = DOORS.filter(function (one) {
      return one.id === door;
    })[0];
    const out = !!row && rules[row.key] === true;
    log.debug("Leaving ServiceAccountPolicy.allowsDoor(). " + out);
    return out;
  }

  /**
   * Returns the ids of the password doors a service account may use.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the door ids, in `DOORS` order
   */
  allowedDoors(profile?: ServiceAccountProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.allowedDoors().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const out = DOORS.filter(function (one) {
      return rules[one.key] === true;
    }).map(function (one) {
      return one.id;
    });
    log.debug("Leaving ServiceAccountPolicy.allowedDoors(). " + out.length);
    return out;
  }

  /**
   * Says whether a service account in this realm is exempt from the second
   * factor.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the `exemptFromSecondFactor` field
   */
  exemptFromSecondFactor(profile?: ServiceAccountProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.exemptFromSecondFactor().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    log.debug("Leaving ServiceAccountPolicy.exemptFromSecondFactor().");
    return rules.exemptFromSecondFactor === true;
  }

  /**
   * Returns the rotation settings, bounded again here.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns whether rotation is on, the interval and overlap in
   *   milliseconds, the generated length and the alarm threshold
   */
  rotation(profile?: ServiceAccountProfile | null) {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.rotation().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const days = Math.min(3650, Math.max(1,
      Number(rules.rotationIntervalDays) || 30));
    const minutes = Math.min(10080, Math.max(0,
      Number(rules.rotationOverlapMinutes)));
    const out = {
      enabled: rules.rotationEnabled === true,
      intervalMs: days * 24 * 60 * 60 * 1000,
      overlapMs: (isNaN(minutes) ? 60 : minutes) * 60 * 1000,
      generatedLength: Math.min(128, Math.max(16,
        Number(rules.generatedLength) || 32)),
      alarmFailures: Math.min(100, Math.max(1,
        Number(rules.rotationAlarmFailures) || 3))
    };
    log.debug("Leaving ServiceAccountPolicy.rotation(). enabled=" +
              out.enabled);
    return out;
  }

  /**
   * Says whether a service account must name an owner.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the `requireOwner` field
   */
  requiresOwner(profile?: ServiceAccountProfile | null): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.requiresOwner().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    log.debug("Leaving ServiceAccountPolicy.requiresOwner().");
    return rules.requireOwner === true;
  }

  /**
   * Describes the policy in sentences, for the page and a save's answer.
   *
   * @param profile - a profile already read; read afresh when omitted
   * @returns the sentences
   */
  describe(profile?: ServiceAccountProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.describe().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const doors = DOORS.filter(function (one) {
      return rules[one.key] === true;
    }).map(function (one) {
      return one.label;
    });
    const rotation = this.rotation(rules);
    const fill = serverProse.fill;
    const out = [
      rules.exemptFromSecondFactor === true
        ? SENTENCES.exempt
        : SENTENCES.notExempt,
      rules.allowBrowserSignIn === true
        ? SENTENCES.browser
        : SENTENCES.noBrowser,
      fill(SENTENCES.doors, { list: doors.length ? doors.join(', ')
                                                 : SENTENCES['param.none'] }),
      rotation.enabled
        ? fill(SENTENCES.rotation, { days: rules.rotationIntervalDays,
                                     minutes: rules.rotationOverlapMinutes })
        : SENTENCES.noRotation,
      rules.requireOwner === true
        ? SENTENCES.owner
        : SENTENCES.noOwner
    ];
    log.debug("Leaving ServiceAccountPolicy.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WRITING.
  // -------------------------------------------------------------------------
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.checkProfileName().");
    // `default`, or a named profile (#1240): lower-case letters, digits and
    // hyphens, which is what a cn here may be.
    const out = PolicySelection.nameProblem(
      name === undefined || name === null || name === '' ? DEFAULT_PROFILE
        : name, NOUN, true);
    log.debug("Leaving ServiceAccountPolicy.checkProfileName().");
    return out;
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
    log.debug('Entering ServiceAccountPolicy.validate().');
    const body = given || {};
    const values: Record<string, number | boolean> = {};
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
    if (!problems.length) {
      this.crossFieldProblems(values, true).forEach(function (problem) {
        problems.push(problem);
      });
    }
    log.debug('Leaving ServiceAccountPolicy.validate(). ' + problems.length +
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
    log.debug('Entering ServiceAccountPolicy.save(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving ServiceAccountPolicy.save(). Not a profile that ' +
                'can exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-SVCACCT-0001');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    const checked = this.validate(given);
    // A NAMED PROFILE'S PRECEDENCE (#1240), refused with the rows.
    const selectors = which === DEFAULT_PROFILE ? null
      : PolicySelection.checkPrecedence(given, SELECTION);
    if (selectors) {
      selectors.problems.forEach(function (problem) {
        checked.problems.push(problem);
      });
    }
    if (checked.problems.length) {
      log.debug('Leaving ServiceAccountPolicy.save(). The values were ' +
                'refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-SVCACCT-0002');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving ServiceAccountPolicy.save(). No directory.');
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep a service-account policy. ' +
                        'ou=serviceAccountPolicies IS the register.'] },
                             'STS-SVCACCT-0003');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'stsServiceAccountPolicy'],
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
      attributes[SELECTION.precedenceAttribute] =
        String(selectors.precedence);
    }
    const written = this.directory.writeServiceAccountPolicy(which,
                                                             attributes);
    if (!written) {
      log.debug('Leaving ServiceAccountPolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-SVCACCT-0004');
    }
    log.debug('Leaving ServiceAccountPolicy.save(). Stored.');
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
    log.debug('Entering ServiceAccountPolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving ServiceAccountPolicy.reset(). Not a profile that ' +
                'can exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-SVCACCT-0001');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    if (!this.haveDirectory()) {
      log.debug('Leaving ServiceAccountPolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(which) };
    }
    // NOT WHILE A SERVICE ACCOUNT NAMES IT (#1240): it would be left naming
    // a profile the realm does not hold.
    const held = which === DEFAULT_PROFILE ? null
      : PolicySelection.deleteProblem(NOUN, which, this.namedBy(which));
    if (held) {
      log.debug('Leaving ServiceAccountPolicy.reset(). Still named.');
      return errorCodes.mark({ ok: false, errors: [held] },
                             'STS-SVCACCT-0049');
    }
    // A NAMED PROFILE IS REMOVED WHOLE; `default` goes back to inheriting.
    const removed = !!this.directory.deleteServiceAccountPolicy(which);
    log.debug('Leaving ServiceAccountPolicy.reset(). ' +
              (removed ? 'Removed.' : 'Nothing stored.'));
    return { ok: true, removed: removed, profile: this.read(which) };
  }

  /**
   * Says whether the policy is enforced; it is, in both modes.
   *
   * @returns true
   */
  enforced(): boolean {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.enforced().");
    log.debug("Leaving ServiceAccountPolicy.enforced().");
    return true;
  }
}

const slot = new InstanceSlot<ServiceAccountPolicy>(
  'common/service_account_policy',
  () => new ServiceAccountPolicy(ServiceAccountPolicy.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

// A SERVICE ACCOUNT NAMES ITS PROFILE (#1240): declared, so the person
// editor draws its picker on the Policies tab and checks the value against
// `default` and the realm's named profiles as they stand when asked — and
// refuses it on a person who is not a service account.
PolicySelection.declareReference('person', REFERENCES.person, NOUN,
  function () {
    log.debug("Entering service-account policy reference choices.");
    const names = slot.get().list().map(function (one) {
      return String(one.name);
    });
    log.debug("Leaving service-account policy reference choices.");
    return names;
  },
  function (attributes) {
    log.debug("Entering service-account policy holder refusal.");
    const out = slot.get().holderRefusal(attributes);
    log.debug("Leaving service-account policy holder refusal.");
    return out;
  });

/**
 * The service-account policy (#221): what a realm allows a service account and
 * how its password rotates. The third policy on Directory > Policies. The
 * exports forward to the instance the composition root installs.
 *
 * @namespace
 */
export = {
  ServiceAccountPolicy: ServiceAccountPolicy,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: ServiceAccountPolicy): void =>
    slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  DEFAULT_PROFILE: ServiceAccountPolicy.DEFAULT_PROFILE,
  DEFAULTS: ServiceAccountPolicy.DEFAULTS,
  FIELDS: ServiceAccountPolicy.FIELDS,
  FIELD_BY_KEY: ServiceAccountPolicy.FIELD_BY_KEY,
  DOORS: ServiceAccountPolicy.DOORS,
  SCHEMA: ServiceAccountPolicy.SCHEMA,
  SENTENCES: ServiceAccountPolicy.SENTENCES,
  SELECTORS: ServiceAccountPolicy.SELECTORS,
  REFERENCES: ServiceAccountPolicy.REFERENCES,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileFor: slot.forward('profileFor'),
  profileForReference: slot.forward('profileForReference'),
  rotatesAnywhere: slot.forward('rotatesAnywhere'),
  namedBy: slot.forward('namedBy'),
  writeRefusal: slot.forward('writeRefusal'),
  holderRefusal: slot.forward('holderRefusal'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  allowsDoor: slot.forward('allowsDoor'),
  allowedDoors: slot.forward('allowedDoors'),
  exemptFromSecondFactor: slot.forward('exemptFromSecondFactor'),
  rotation: slot.forward('rotation'),
  requiresOwner: slot.forward('requiresOwner'),
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
