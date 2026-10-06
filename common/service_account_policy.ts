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
// IT IS A LIBRARY (rule 3) AND A LEAF: `helpers`, `realms`, `error_codes`,
// the instance slot, the directory through a slot `ldap/ldap_server.js`
// fills, and — LAZILY, at a save — the password policy (its minimum length)
// and the destinations (`common/secret_destinations.ts`), which nothing that
// asks "may this account bind" should load.
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
}

/**
 * The name of the one service-account policy profile, `default`.
 */
const DEFAULT_PROFILE = 'default';

/**
 * The password doors a service account may be allowed, in the order the page
 * draws them. `id` is what a door passes to `credentials.verify()` as `door`
 * (`browser` and `kerberos` are answered by the sign-in funnel and the KDC).
 */
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
            'rotates. The entry is named by the PROFILE (`cn=default`).' }
  ],
  attributes: FIELDS.map(function (field) {
    return { name: field.attribute, what: field.what };
  }).concat([
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
   * The password doors a service account may be allowed.
   */
  static readonly DOORS = DOORS;
  /**
   * The directory schema of `ou=serviceAccountPolicies`.
   */
  static readonly SCHEMA = SCHEMA;

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
    if (realms.isDefault()) {
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
      // Like the authentication policy, and unlike a password rule, this
      // decides who gets in, so it is in force in both modes.
      enforced: true
    }, values) as ServiceAccountProfile;
    log.debug('Leaving ServiceAccountPolicy.read(). From ' + found.from + '.');
    return out;
  }

  /**
   * Returns the profile that applies to a person, which is always the one
   * profile.
   *
   * @param username - the person (unused; nothing assigns a profile)
   * @returns the profile in force
   */
  profileFor(username?: unknown): ServiceAccountProfile {
    const { log } = this.deps;
    log.debug("Entering ServiceAccountPolicy.profileFor().");
    void username;
    log.debug("Leaving ServiceAccountPolicy.profileFor().");
    return this.read(DEFAULT_PROFILE);
  }

  /**
   * Lists the profiles: the one profile in force.
   *
   * @returns a one-element list
   */
  list(): ServiceAccountProfile[] {
    const { log } = this.deps;
    log.debug('Entering ServiceAccountPolicy.list().');
    const rows = [this.read(DEFAULT_PROFILE)];
    log.debug('Leaving ServiceAccountPolicy.list(). ' + rows.length +
              ' profile(s).');
    return rows;
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
    const out = [
      rules.exemptFromSecondFactor === true
        ? 'service accounts are EXEMPT from the second factor'
        : 'service accounts meet the second-factor rules everybody does',
      rules.allowBrowserSignIn === true
        ? 'service accounts may sign in at a browser'
        : 'service accounts are refused at every browser sign-in',
      'password doors: ' + (doors.length ? doors.join(', ') : 'none'),
      rotation.enabled
        ? 'passwords rotate every ' + rules.rotationIntervalDays + ' days, ' +
          'the previous one working for ' + rules.rotationOverlapMinutes +
          ' minutes'
        : 'passwords do not rotate automatically',
      rules.requireOwner === true
        ? 'every service account names an owner'
        : 'a service account may have no owner'
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
    const text = String(name || DEFAULT_PROFILE).trim();
    if (text.toLowerCase() !== DEFAULT_PROFILE) {
      log.debug("Leaving ServiceAccountPolicy.checkProfileName().");
      return 'There is one service-account policy profile, "' +
             DEFAULT_PROFILE + '", and it applies to every service account ' +
             'in this realm. "' + text.slice(0, 64) + '" cannot be created: ' +
             'nothing assigns a profile to an account, so a second one would ' +
             'decide nothing while looking exactly like one that does.';
    }
    log.debug("Leaving ServiceAccountPolicy.checkProfileName().");
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
    const checked = this.validate(given);
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
    const written = this.directory.writeServiceAccountPolicy(DEFAULT_PROFILE,
                                                             attributes);
    if (!written) {
      log.debug('Leaving ServiceAccountPolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-SVCACCT-0004');
    }
    log.debug('Leaving ServiceAccountPolicy.save(). Stored.');
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
    log.debug('Entering ServiceAccountPolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving ServiceAccountPolicy.reset(). Not a profile that ' +
                'can exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-SVCACCT-0001');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving ServiceAccountPolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(DEFAULT_PROFILE) };
    }
    const removed = !!this.directory.deleteServiceAccountPolicy(
      DEFAULT_PROFILE);
    log.debug('Leaving ServiceAccountPolicy.reset(). ' +
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
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileFor: slot.forward('profileFor'),
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
