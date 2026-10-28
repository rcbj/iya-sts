// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: post_login_policy.ts
//
// ---------------------------------------------------------------------------
// THE POST-LOGIN ACTIVITY POLICY (#1096, 2026-10-28): WHAT A PERSON IS ASKED
// TO DO AFTER THEY SIGN IN, BEFORE THEY ARE SENT BACK TO THE APPLICATION.
//
// rcbj: "a generalized feature ... call it post login activity", targeted
// at people by group membership, configurable and enabled per realm. It is the seventh kind on
// Directory → Policies (`admin-core/policy_kinds.ts`), on `locale_policy.ts`'s
// pattern — `cn=default` inherited from the default realm, named profiles a
// realm's own — and its rows are one ACTIVITY's settings:
//
//   enabled        OFF by default (rcbj's answer 4). Off, nobody in the
//                  profile's reach is asked anything BY THE POLICY; a
//                  RUNNING STARTED activity (#1126) still asks its own
//                  population at sign-in under these rules, except where
//                  this is a NAMED profile — `default` off excludes nobody
//                  from a started activity, a named one off does.
//   activity       What is asked. One today, `pqc-passkey-migration`: a person
//                  holding a CLASSICAL passkey in a role (primary, or second
//                  factor) and no post-quantum one in it is asked to register
//                  an ML-DSA passkey in that role. `common/post_login.ts`
//                  decides who is due; `authn/authn.ts` asks.
//   snoozeDays     How long Skip puts the activity off for that person.
//   graceDays      The allotted time (rcbj's answer 2): counted from the
//                  person's FIRST invitation; past it Skip is gone and the
//                  sign-in is held until the activity is done (answer 3,
//                  "block the sign-in"). 0 is no deadline.
//   noPasskey      What a person holding NO passkey is asked (answer 1):
//                  `leave` alone, `invite` (always skippable), or `require`
//                  (skippable until the grace period ends).
//   noPasskeyRole  The role such a person registers it in: `primary` (a
//                  passwordless sign-in) or `mfa` (a second factor).
//   method         HOW a classical passkey is migrated (#1100): `upgrade`
//                  (prove the classical passkey, then an ML-DSA one
//                  REPLACES it in place on the same authenticator — one
//                  row, nothing left behind), `alongside` (an ML-DSA
//                  passkey beside it: in the post-quantum lane where the
//                  realm has two, on another authenticator where it has
//                  one), or `automatic` (the realm's lanes decide: alongside
//                  with two, upgrade with one).
//   attestation    WHAT COUNTS AS MIGRATED (#1102): `any` (the passkey's
//                  key algorithm is ML-DSA) or `post-quantum` (and its
//                  recorded attestation is post-quantum too).
//   noPasskeyFallback  For a person with no passkey (#1103): `none`
//                  (ML-DSA only) or `classical` (#944's classical retry is
//                  offered where the device cannot make ML-DSA).
//
// ---------------------------------------------------------------------------
// TARGETING IS BY GROUP, AND EXCLUSION IS A PROFILE.
//
// `cn=default` reaches every person in the realm. A named profile reaches the
// members of its groups (`stsPostLoginSelectGroup`, a group's cn or DN), and
// where several reach one person the LOWEST precedence wins
// (`stsPostLoginPrecedence`, 1 to 1000; ties by name) — the passkey policy's
// selection (#535), by group alone because rcbj asked for groups. So a group
// is EXCLUDED by a named profile that reaches it with `enabled` off and a
// lower precedence than the one that would ask it: no second list to keep in
// step with the first.
//
// IT IS SELECTION, NOT AUTHORIZATION: which rows apply to whom. What the rows
// then cause is `common/post_login.ts`'s.
//
// IT IS A LIBRARY (rule 3) AND A LEAF: `helpers`, `realms`, `error_codes`,
// the instance slot and `server_prose`, and the directory through a slot
// `ldap/ldap_server.js` fills.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
// The sentences `describe()` makes are filled from SENTENCES below, so the
// server can translate them into a console reader's language (#543).
import serverProse = require('./server_prose');

const { log } = helpers;

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'bool' | 'int' | 'enum';
  dflt: boolean | number | string;
  min?: number;
  max?: number;
  unit?: string;
  values?: string[];
  label: string;
  what: string;
}

interface DirectoryHooks {
  allPostLoginPolicies?(): { name?: string; dn: string;
                             attributes?: Record<string, unknown> }[];
  writePostLoginPolicy?(name: string,
                        attributes: Record<string, unknown>): unknown;
  deletePostLoginPolicy?(name: string): unknown;
  personGroups?(username: string): { cn?: string; dn?: string }[];
  [hook: string]: unknown;
}

interface PostLoginProfile {
  name: string;
  selectGroups: string[];
  precedence: number;
  stored: boolean;
  inherited: boolean;
  from: 'realm' | 'default-realm' | 'built-in';
  dn: string;
  description: string;
  sources: Record<string, string>;
  problems: string[];
  enforced: boolean;
  enabled: boolean;
  activity: string;
  snoozeDays: number;
  graceDays: number;
  noPasskey: string;
  noPasskeyRole: string;
  method: string;
  attestation: string;
  noPasskeyFallback: string;
  [field: string]: any;
}

interface PolicyResult {
  ok: boolean;
  errors?: string[];
  removed?: boolean;
  profile?: PostLoginProfile;
}

interface PostLoginPolicyDeps {
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
 * The name of the profile every realm has, `default`.
 */
const DEFAULT_PROFILE = 'default';

/**
 * A named profile's name: what a cn may be here.
 */
const PROFILE_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/;

/**
 * Where a named profile ranks when its entry says nothing readable.
 */
const DEFAULT_PRECEDENCE = 100;

/**
 * The activities a profile may ask for. One today.
 */
const ACTIVITIES = ['pqc-passkey-migration'];

// ---------------------------------------------------------------------------
// THE SENTENCES `describe()` MAKES, as templates (#543 phase 2) — one copy,
// filled there with `ServerProse.fill()` and matched by
// `common/server_prose.ts` to refill in a console reader's language. A
// `param.` key is a phrase that only ever stands inside another sentence.
// ---------------------------------------------------------------------------
const SENTENCES: Readonly<Record<string, string>> = Object.freeze({
  off: 'nobody this profile reaches is asked anything after signing in',
  pqcMigration: 'a person holding a classical passkey is asked, after ' +
    'signing in, to register a post-quantum (ML-DSA) passkey in the same ' +
    'role',
  methodUpgrade: 'the ML-DSA passkey replaces the classical one in place, ' +
    'after the person uses the classical one once',
  methodAlongside: 'the ML-DSA passkey is added beside the classical one',
  methodAutomatic: 'the ML-DSA passkey is added beside the classical one ' +
    'where two lanes are offered, and replaces it in place where one is',
  attestationAny: 'a passkey counts as post-quantum when its key ' +
    'algorithm is ML-DSA',
  attestationPq: 'a passkey counts as post-quantum only when its key ' +
    'algorithm and its recorded attestation are post-quantum',
  fallbackClassical: 'a person with no passkey whose device cannot make ' +
    'ML-DSA is offered a classical passkey instead',
  snooze: 'Skip puts it off for {{days}} day(s)',
  grace: 'after {{days}} day(s) from the first invitation Skip is gone and ' +
    'the sign-in is held until it is done',
  noGrace: 'it can always be skipped',
  noPasskeyLeave: 'a person holding no passkey is not asked',
  noPasskeyInvite: 'a person holding no passkey is invited to register a ' +
    'post-quantum passkey as {{role}}, and may always skip it',
  noPasskeyRequire: 'a person holding no passkey is asked to register a ' +
    'post-quantum passkey as {{role}}, and may skip it until the grace ' +
    'period ends',
  appliesTo: 'applies to the members of {{list}}, at precedence ' +
    '{{precedence}}',
  'param.primary': 'their primary sign-in',
  'param.mfa': 'a second factor',
  'param.noGroup': 'no group'
});

const SELECTORS = [
  { key: 'selectGroups', attribute: 'stsPostLoginSelectGroup',
    what: 'The groups (cn or DN) whose members a named post-login profile ' +
          'applies to.' },
  { key: 'precedence', attribute: 'stsPostLoginPrecedence',
    what: 'Which named post-login profile wins where several reach one ' +
          'person: the lowest, from 1 to 1000.' }
];

/**
 * The policy's fields: one table read as the schema, the console form, the
 * API body, the validation of a save and the parse of an entry.
 */
const FIELDS: PolicyField[] = [
  { key: 'enabled', attribute: 'stsPostLoginEnabled', type: 'bool',
    dflt: false,
    label: 'Ask after sign-in',
    what: 'OFF BY DEFAULT. On, every person this profile reaches who is due ' +
          'the activity below is asked to do it after signing in, before ' +
          'they are sent back to the application. A named profile with this ' +
          'off EXCLUDES the members of its groups.' },
  { key: 'activity', attribute: 'stsPostLoginActivity', type: 'enum',
    dflt: 'pqc-passkey-migration', values: ACTIVITIES,
    label: 'Activity',
    what: 'What is asked. pqc-passkey-migration: a person holding a passkey ' +
          'made with a classical algorithm as their primary sign-in, or as ' +
          'a second factor, is asked to register a post-quantum (ML-DSA) ' +
          'passkey in the same role. Whether the classical passkey is ' +
          'replaced in place or kept beside it is the method\'s to say ' +
          '(below). Nobody is asked where the realm offers no ML-DSA ' +
          'algorithm at registration (the default webauthn.algorithms ' +
          'does).' },
  { key: 'snoozeDays', attribute: 'stsPostLoginSnoozeDays', type: 'int',
    dflt: 7, min: 1, max: 90, unit: 'days',
    label: 'Skip puts it off for',
    what: 'How long Skip puts the activity off for that person.' },
  { key: 'graceDays', attribute: 'stsPostLoginGraceDays', type: 'int',
    dflt: 0, min: 0, max: 3650, unit: 'days',
    label: 'Allotted time',
    what: 'Counted from the person\'s FIRST invitation. When it has passed, ' +
          'Skip is gone and the sign-in is held — no session is started — ' +
          'until the activity is done. 0 is no deadline: it can always be ' +
          'skipped.' },
  { key: 'noPasskey', attribute: 'stsPostLoginNoPasskey', type: 'enum',
    dflt: 'leave', values: ['leave', 'invite', 'require'],
    label: 'A person with no passkey',
    what: 'leave: not asked. invite: asked to register a post-quantum ' +
          'passkey, and may always skip it. require: asked, and may skip it ' +
          'only until the allotted time has passed.' },
  { key: 'noPasskeyRole', attribute: 'stsPostLoginNoPasskeyRole',
    type: 'enum', dflt: 'primary', values: ['primary', 'mfa'],
    label: 'Registered by a person with no passkey as',
    what: 'primary: a passwordless sign-in. mfa: a second factor.' },
  { key: 'method', attribute: 'stsPostLoginMethod', type: 'enum',
    dflt: 'automatic', values: ['automatic', 'upgrade', 'alongside'],
    label: 'How a classical passkey is migrated',
    what: 'upgrade: the person uses their classical passkey once, then an ' +
          'ML-DSA passkey replaces it in place on the same authenticator — ' +
          'one passkey, nothing left behind. alongside: an ML-DSA passkey ' +
          'is added beside it, in the post-quantum lane where the realm ' +
          'offers two lanes, or on another authenticator where it offers ' +
          'one. automatic: alongside where the person\'s passkey policy ' +
          'offers two lanes, upgrade where it offers one.' },
  { key: 'attestation', attribute: 'stsPostLoginAttestation', type: 'enum',
    dflt: 'any', values: ['any', 'post-quantum'],
    label: 'A passkey counts as post-quantum when',
    what: 'any: its key algorithm is ML-DSA. post-quantum: its key ' +
          'algorithm is ML-DSA AND its recorded attestation was signed ' +
          'with post-quantum algorithms throughout; a passkey with a ' +
          'classical attestation, or none recorded, does not count, and ' +
          'its holder is asked for one that does.' },
  { key: 'noPasskeyFallback', attribute: 'stsPostLoginNoPasskeyFallback',
    type: 'enum', dflt: 'none', values: ['none', 'classical'],
    label: 'A person with no passkey whose device cannot make ML-DSA',
    what: 'none: ML-DSA only. classical: after an ML-DSA registration ' +
          'fails on the device, a retry with the classical algorithms is ' +
          'offered (where the passkey policy allows one) — a classical ' +
          'passkey is better than a password, and its holder is asked for ' +
          'the migration later like anyone else\'s.' }
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
const DEFAULTS: Readonly<Record<string, boolean | number | string>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    out[field.key] = field.dflt;
    return out;
  }, {} as Record<string, boolean | number | string>));

/**
 * The directory schema of `ou=postLoginPolicies`: its container, object class
 * and attributes.
 */
const SCHEMA = {
  container: 'ou=postLoginPolicies',
  objectClasses: [
    { name: 'stsPostLoginPolicy',
      what: 'This service\'s class for a post-login activity profile: what ' +
            'a person is asked to do after signing in. Named by the PROFILE ' +
            '(`cn=default`, or a named profile chosen by group).' }
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
 * The post-login activity policy: what a person is asked to do after signing
 * in, with named profiles chosen by group.
 *
 * Kept as `stsPostLoginPolicy` entries in `ou=postLoginPolicies`; a realm with
 * no `cn=default` of its own inherits the default realm's, and failing that
 * the built-in defaults (off).
 */
class PostLoginPolicy {
  /**
   * The name of the profile every realm has.
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
   * The selectors a named profile carries.
   */
  static readonly SELECTORS = SELECTORS;
  /**
   * The directory schema of `ou=postLoginPolicies`.
   */
  static readonly SCHEMA = SCHEMA;
  /**
   * The sentences `describe()` makes, as templates (#543).
   */
  static readonly SENTENCES = SENTENCES;
  /**
   * The activities a profile may ask for.
   */
  static readonly ACTIVITIES = ACTIVITIES;

  private directory: DirectoryHooks | null = null;
  private warnedAboutNoDirectory = false;

  /**
   * Builds the policy with no directory installed.
   *
   * @param deps - the logger, realms and error codes
   */
  constructor(private readonly deps: PostLoginPolicyDeps) {
    deps.log.debug("Entering PostLoginPolicy.constructor().");
    deps.log.debug("Leaving PostLoginPolicy.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): PostLoginPolicyDeps {
    log.debug("Entering PostLoginPolicy.defaultDeps().");
    log.debug("Leaving PostLoginPolicy.defaultDeps().");
    return { log: log, realms: realms, errorCodes: errorCodes };
  }

  /**
   * Installs the directory hooks the policy is read from and written to;
   * filled by the directory.
   *
   * @param hooks - the directory's policy hooks, or null to remove them
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug('Entering PostLoginPolicy.setDirectory().');
    this.directory = hooks || null;
    log.debug('Leaving PostLoginPolicy.setDirectory(). The register ' +
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
    log.debug("Entering PostLoginPolicy.directoryInstalled().");
    log.debug("Leaving PostLoginPolicy.directoryInstalled().");
    return this.directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.haveDirectory().");
    if (this.directory &&
        typeof this.directory.allPostLoginPolicies === 'function') {
      log.debug("Leaving PostLoginPolicy.haveDirectory().");
      return true;
    }
    if (!this.warnedAboutNoDirectory) {
      this.warnedAboutNoDirectory = true;
      log.warn('post_login_policy: the embedded directory was never loaded, ' +
               'so there is no ou=postLoginPolicies. The BUILT-IN policy ' +
               '(nobody is asked anything) is in force and cannot be edited ' +
               'in this process.');
    }
    log.debug("Leaving PostLoginPolicy.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  private firstValue(attributes: Record<string, unknown>,
                     name: string): unknown {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.firstValue().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving PostLoginPolicy.firstValue().");
    return Array.isArray(found) ? (found[0] === undefined ? '' : found[0])
      : (found === undefined || found === null ? '' : found);
  }

  // Every value of an attribute, as strings (the selector is a list).
  private allValues(attributes: Record<string, unknown>,
                    name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.allValues().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving PostLoginPolicy.allValues().");
    return (Array.isArray(found) ? found : (found === undefined ||
                                            found === null || found === ''
                                              ? [] : [found]))
      .map(String).filter(Boolean);
  }

  // `password_policy.ts`'s parse, for the three types here. Never guesses.
  private parseField(field: PolicyField,
                     raw: unknown): { value?: boolean | number | string;
                                      problem?: string } {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.parseField().");
    const text = String(raw === undefined || raw === null ? '' : raw).trim();
    if (field.type === 'bool') {
      const lower = text.toLowerCase();
      if (['true', 'on', '1'].indexOf(lower) >= 0) {
        log.debug("Leaving PostLoginPolicy.parseField().");
        return { value: true };
      }
      if (['false', 'off', '0', ''].indexOf(lower) >= 0) {
        log.debug("Leaving PostLoginPolicy.parseField().");
        return { value: false };
      }
      log.debug("Leaving PostLoginPolicy.parseField().");
      return { problem: field.label + ' is a yes-or-no setting, and "' +
                        text.slice(0, 40) + '" is neither.' };
    }
    if (field.type === 'enum') {
      const lower = text.toLowerCase();
      if ((field.values || []).indexOf(lower) < 0) {
        log.debug("Leaving PostLoginPolicy.parseField().");
        return { problem: field.label + ' is one of ' +
                          (field.values || []).join(', ') + '; "' +
                          text.slice(0, 40) + '" is not.' };
      }
      log.debug("Leaving PostLoginPolicy.parseField().");
      return { value: lower };
    }
    if (!/^[0-9]{1,6}$/.test(text) ||
        Number(text) < Number(field.min) || Number(text) > Number(field.max)) {
      log.debug("Leaving PostLoginPolicy.parseField().");
      return { problem: field.label + ' is a whole number of ' +
                        (field.unit || 'units') + ' from ' + field.min +
                        ' to ' + field.max + '; "' + text.slice(0, 40) +
                        '" is not.' };
    }
    log.debug("Leaving PostLoginPolicy.parseField().");
    return { value: Number(text) };
  }

  private entryIn(name: string) {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.entryIn().");
    const wanted = name.toLowerCase();
    log.debug("Leaving PostLoginPolicy.entryIn().");
    return this.directory.allPostLoginPolicies().filter(function (entry) {
      return String(entry.name || '').toLowerCase() === wanted;
    })[0] || null;
  }

  // THIS REALM'S OWN ENTRY, THEN — FOR `default` ONLY — THE DEFAULT REALM'S.
  private entryFor(name: string):
      { entry: any; from: PostLoginProfile['from'] } {
    const { log, realms } = this.deps;
    log.debug("Entering PostLoginPolicy.entryFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving PostLoginPolicy.entryFor(). No directory.");
      return { entry: null, from: 'built-in' };
    }
    const own = this.entryIn(name);
    if (own) {
      log.debug("Leaving PostLoginPolicy.entryFor(). The realm's own.");
      return { entry: own, from: 'realm' };
    }
    if (name !== DEFAULT_PROFILE || realms.isDefault()) {
      log.debug("Leaving PostLoginPolicy.entryFor(). Built-in.");
      return { entry: null, from: 'built-in' };
    }
    const inherited = realms.run(realms.DEFAULT_REALM, () => {
      log.debug("Entering PostLoginPolicy.entryFor() default-realm read.");
      const found = this.entryIn(name);
      log.debug("Leaving PostLoginPolicy.entryFor() default-realm read.");
      return found;
    });
    log.debug("Leaving PostLoginPolicy.entryFor(). " +
              (inherited ? 'Inherited.' : 'Built-in.'));
    return inherited ? { entry: inherited, from: 'default-realm' }
      : { entry: null, from: 'built-in' };
  }

  // A stored precedence, or the default where it is not a number in range.
  private precedenceOf(attributes: Record<string, unknown>): number {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.precedenceOf().");
    const p = Number(this.firstValue(attributes, 'stsPostLoginPrecedence'));
    log.debug("Leaving PostLoginPolicy.precedenceOf().");
    return p >= 1 && p <= 1000 ? p : DEFAULT_PRECEDENCE;
  }

  /**
   * Reads a profile: this realm's entry, else (for `default`) the default
   * realm's, else the built-in defaults.
   *
   * Always answers. An unreadable stored value falls back to its default and
   * is named in `problems`. A named profile that is not stored reads as
   * `default`.
   *
   * @param name - the profile name; `default` when omitted
   * @returns the profile's values, where each came from, and any problems
   */
  read(name?: string): PostLoginProfile {
    const { log } = this.deps;
    log.debug('Entering PostLoginPolicy.read(). name=' + name);
    const asked = String(name || DEFAULT_PROFILE).toLowerCase();
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
    const at = entry ? (entry.attributes || {}) : {};
    if (entry) {
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
      selectGroups: profile === DEFAULT_PROFILE ? []
        : this.allValues(at, 'stsPostLoginSelectGroup'),
      precedence: profile === DEFAULT_PROFILE ? DEFAULT_PRECEDENCE
        : this.precedenceOf(at),
      stored: found.from === 'realm',
      inherited: found.from === 'default-realm',
      from: found.from,
      dn: entry ? entry.dn : '',
      description: entry ? String(this.firstValue(at, 'description')) : '',
      sources: sources,
      problems: problems,
      // It asks; in force in both modes.
      enforced: true
    }, values) as PostLoginProfile;
    log.debug('Leaving PostLoginPolicy.read(). From ' + found.from + '.');
    return out;
  }

  /**
   * Lists the profiles: `default` first, then this realm's named profiles in
   * precedence order.
   *
   * @returns the profiles
   */
  list(): PostLoginProfile[] {
    const { log } = this.deps;
    log.debug('Entering PostLoginPolicy.list().');
    const named = this.namedProfiles().map((one) => {
      return this.read(one);
    }).sort(function (a, b) {
      return a.precedence - b.precedence || (a.name < b.name ? -1 : 1);
    });
    const rows = [this.read(DEFAULT_PROFILE)].concat(named);
    log.debug('Leaving PostLoginPolicy.list(). ' + rows.length +
              ' profile(s).');
    return rows;
  }

  private namedProfiles(): string[] {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.namedProfiles().");
    const out = this.haveDirectory()
      ? this.directory.allPostLoginPolicies().map(function (one) {
        return String(one.name || '').toLowerCase();
      }).filter(function (one) {
        return one && one !== DEFAULT_PROFILE;
      }) : [];
    log.debug("Leaving PostLoginPolicy.namedProfiles(). " + out.length);
    return out;
  }

  /**
   * The groups a person is in, as the directory's group hook answers (#535's
   * `personGroups()`, the passkey policy's): each `{ cn, dn }`, from the
   * person's own membership and never a walk of any group's members. Empty
   * where there is no directory or no hook; throws where the hook does, for
   * the caller to decide what a failure means.
   *
   * @param username - the person
   * @returns the groups
   */
  personGroups(username: unknown): { cn: string; dn: string }[] {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.personGroups().");
    const hook = this.haveDirectory() && this.directory
      ? this.directory.personGroups : null;
    const out = username && typeof hook === 'function'
      ? (hook.call(this.directory, String(username)) || [])
        .map(function (g: any) {
          return { cn: String((g && g.cn) || ''),
                   dn: String((g && g.dn) || '') };
        })
      : [];
    log.debug("Leaving PostLoginPolicy.personGroups(). " + out.length);
    return out;
  }

  /**
   * Returns the name of the profile that reaches a person: the named profile
   * of lowest precedence one of whose groups they are in (ties by name), else
   * `default`.
   *
   * @param username - the person
   * @param groupsOf - optional; answers the person's groups, so a caller
   *   that needs them too (`post_login.ts`, for a started activity's
   *   groups, #1126) asks the directory once; `personGroups()` otherwise
   * @returns the profile name
   */
  profileNameFor(username: unknown,
                 groupsOf?: () => { cn?: string; dn?: string }[]): string {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.profileNameFor().");
    if (!username || !this.haveDirectory()) {
      log.debug("Leaving PostLoginPolicy.profileNameFor(). default.");
      return DEFAULT_PROFILE;
    }
    let out = DEFAULT_PROFILE;
    try {
      const named = this.directory.allPostLoginPolicies()
        .filter(function (one) {
          return String(one.name || '').toLowerCase() !== DEFAULT_PROFILE;
        });
      if (named.length) {
        const held = typeof groupsOf === 'function' ? groupsOf()
          : this.personGroups(username);
        const groups = (held || [])
          .map(function (g: any) {
            return [String(g.cn || '').toLowerCase(),
                    String(g.dn || '').toLowerCase()];
          }).reduce(function (all: string[], two: string[]) {
            return all.concat(two);
          }, []).filter(Boolean);
        const hit = named.map((entry) => {
          const at = entry.attributes || {};
          return {
            name: String(entry.name).toLowerCase(),
            precedence: this.precedenceOf(at),
            groups: this.allValues(at, 'stsPostLoginSelectGroup')
              .map(function (one) {
                return one.trim().toLowerCase();
              })
          };
        }).filter(function (one) {
          return one.groups.some(function (g) {
            return groups.indexOf(g) >= 0;
          });
        }).sort(function (a, b) {
          return a.precedence - b.precedence || (a.name < b.name ? -1 : 1);
        })[0];
        out = hit ? hit.name : DEFAULT_PROFILE;
      }
    } catch (e) {
      // A directory that cannot be asked gives the default: the sign-in is
      // not held on a selection nobody could make.
      log.debug("Caught in PostLoginPolicy.profileNameFor(): " +
                ((e && e.message) || e));
      out = DEFAULT_PROFILE;
    }
    log.debug("Leaving PostLoginPolicy.profileNameFor(). " + out);
    return out;
  }

  /**
   * Reads the profile that reaches a person.
   *
   * @param username - the person
   * @param groupsOf - optional; as `profileNameFor()` takes it
   * @returns the profile
   */
  forPerson(username: unknown,
            groupsOf?: () => { cn?: string; dn?: string }[]):
      PostLoginProfile {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.forPerson().");
    const out = this.read(this.profileNameFor(username, groupsOf));
    log.debug("Leaving PostLoginPolicy.forPerson(). " + out.name);
    return out;
  }

  /**
   * Says whether any profile of this realm (or the inherited default) has an
   * activity switched on — the cheap question asked before any per-person
   * one.
   *
   * @returns true where one is on
   */
  anyEnabled(): boolean {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.anyEnabled().");
    let out = false;
    try {
      out = this.read(DEFAULT_PROFILE).enabled === true ||
        this.namedProfiles().some((one) => {
          return this.read(one).enabled === true;
        });
    } catch (e) {
      // Nothing can be read: nothing is asked.
      log.debug("Caught in PostLoginPolicy.anyEnabled(): " +
                ((e && e.message) || e));
      out = false;
    }
    log.debug("Leaving PostLoginPolicy.anyEnabled(). " + out);
    return out;
  }

  /**
   * Describes a profile in sentences, for the page and a save's answer.
   *
   * @param profile - a profile already read; `default` read when omitted
   * @returns the sentences
   */
  describe(profile?: PostLoginProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.describe().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const fill = serverProse.fill;
    const role = rules.noPasskeyRole === 'mfa' ? SENTENCES['param.mfa']
                                               : SENTENCES['param.primary'];
    const out = rules.enabled !== true ? [SENTENCES.off] : [
      SENTENCES.pqcMigration,
      rules.method === 'upgrade' ? SENTENCES.methodUpgrade
        : (rules.method === 'alongside' ? SENTENCES.methodAlongside
                                        : SENTENCES.methodAutomatic),
      rules.attestation === 'post-quantum' ? SENTENCES.attestationPq
                                           : SENTENCES.attestationAny,
      fill(SENTENCES.snooze, { days: String(rules.snoozeDays) }),
      Number(rules.graceDays) > 0
        ? fill(SENTENCES.grace, { days: String(rules.graceDays) })
        : SENTENCES.noGrace,
      rules.noPasskey === 'invite'
        ? fill(SENTENCES.noPasskeyInvite, { role: role })
        : (rules.noPasskey === 'require'
          ? fill(SENTENCES.noPasskeyRequire, { role: role })
          : SENTENCES.noPasskeyLeave)
    ].concat(rules.noPasskey !== 'leave' &&
             rules.noPasskeyFallback === 'classical'
      ? [SENTENCES.fallbackClassical] : []);
    if (rules.name !== DEFAULT_PROFILE) {
      out.unshift(fill(SENTENCES.appliesTo, {
        list: rules.selectGroups.length ? rules.selectGroups.join(', ')
                                        : SENTENCES['param.noGroup'],
        precedence: String(rules.precedence) }));
    }
    log.debug("Leaving PostLoginPolicy.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WRITING.
  // -------------------------------------------------------------------------
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.checkProfileName().");
    const text = String(name || DEFAULT_PROFILE).trim();
    if (text !== DEFAULT_PROFILE && !PROFILE_NAME.test(text)) {
      log.debug("Leaving PostLoginPolicy.checkProfileName().");
      return 'A post-login profile is "' + DEFAULT_PROFILE + '" or a name of ' +
             'lower-case letters, digits and hyphens, at most 64; "' +
             text.slice(0, 64) + '" is neither.';
    }
    log.debug("Leaving PostLoginPolicy.checkProfileName().");
    return null;
  }

  // A named profile's groups as sent: a list by comma, line or array, each at
  // most 512 characters with no control character, at most 64, at least one.
  private checkGroups(raw: unknown): { groups: string[];
                                       problems: string[] } {
    const { log } = this.deps;
    log.debug("Entering PostLoginPolicy.checkGroups().");
    const problems: string[] = [];
    const items = (Array.isArray(raw) ? raw : String(raw === undefined ||
                                                     raw === null ? '' : raw)
      .split(/[,\n]/)).map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
    if (items.length > 64 || items.some(function (one) {
      return one.length > 512 || /[\u0000-\u001f\u007f]/.test(one);
    })) {
      problems.push('The groups a named profile applies to must be at most ' +
                    '64 values of at most 512 characters each, with no ' +
                    'control character.');
    }
    if (!items.length) {
      problems.push('A named profile with no group would reach nobody; name ' +
                    'at least one.');
    }
    log.debug("Leaving PostLoginPolicy.checkGroups(). " + problems.length +
              " problem(s).");
    return { groups: items.slice(0, 64), problems: problems };
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
    log.debug('Entering PostLoginPolicy.validate().');
    const body = given || {};
    const values: Record<string, boolean | number | string> = {};
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
    log.debug('Leaving PostLoginPolicy.validate(). ' + problems.length +
              ' problem(s).');
    return { values: values, problems: problems };
  }

  /**
   * Saves a profile of this realm, replacing it whole.
   *
   * @param name - the profile name: `default`, or a named profile
   * @param given - every field, and for a named profile its groups and
   *   precedence
   * @returns `ok` and the profile now in force, or `ok: false` with `errors`
   */
  save(name: unknown, given?: Record<string, any> | null): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering PostLoginPolicy.save(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving PostLoginPolicy.save(). Not a profile that can ' +
                'exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0470');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    const checked = this.validate(given);
    const groups = which === DEFAULT_PROFILE ? null
      : this.checkGroups((given || {}).selectGroups);
    let precedence = DEFAULT_PRECEDENCE;
    if (groups) {
      groups.problems.forEach(function (one) {
        checked.problems.push(one);
      });
      const raw = (given || {}).precedence;
      const text = String(raw === undefined || raw === null || raw === ''
        ? DEFAULT_PRECEDENCE : raw).trim();
      if (!/^[0-9]{1,4}$/.test(text) || Number(text) < 1 ||
          Number(text) > 1000) {
        checked.problems.push('Precedence is a whole number from 1 to 1000; ' +
                              '"' + text.slice(0, 40) + '" is not.');
      } else {
        precedence = Number(text);
      }
    }
    if (checked.problems.length) {
      log.debug('Leaving PostLoginPolicy.save(). The values were refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-AUTHN-0471');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving PostLoginPolicy.save(). No directory.');
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep a post-login profile. ' +
                        'ou=postLoginPolicies IS the register.'] },
                             'STS-AUTHN-0472');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'stsPostLoginPolicy'],
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
    if (groups) {
      attributes.stsPostLoginSelectGroup = groups.groups;
      attributes.stsPostLoginPrecedence = String(precedence);
    }
    const written = this.directory.writePostLoginPolicy(which, attributes);
    if (!written) {
      log.debug('Leaving PostLoginPolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-AUTHN-0472');
    }
    log.debug('Leaving PostLoginPolicy.save(). Stored.');
    return { ok: true, profile: this.read(which) };
  }

  /**
   * Deletes a profile of this realm: `default` goes back to inheriting, and
   * a named profile is removed whole.
   *
   * @param name - the profile name
   * @returns `ok`, whether an entry was removed, and the profile now in force
   */
  reset(name: unknown): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering PostLoginPolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving PostLoginPolicy.reset(). Not a profile that can ' +
                'exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0470');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    if (!this.haveDirectory()) {
      log.debug('Leaving PostLoginPolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(which) };
    }
    const removed = !!this.directory.deletePostLoginPolicy(which);
    log.debug('Leaving PostLoginPolicy.reset(). ' +
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
    log.debug("Entering PostLoginPolicy.enforced().");
    log.debug("Leaving PostLoginPolicy.enforced().");
    return true;
  }
}

const slot = new InstanceSlot<PostLoginPolicy>(
  'common/post_login_policy',
  () => new PostLoginPolicy(PostLoginPolicy.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

/**
 * The post-login activity policy (#1096): what a person is asked to do after
 * signing in, with named profiles chosen by group. The seventh policy on
 * Directory > Policies. The exports forward to the instance the composition
 * root installs.
 *
 * @namespace
 */
export = {
  PostLoginPolicy: PostLoginPolicy,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: PostLoginPolicy): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  DEFAULT_PROFILE: PostLoginPolicy.DEFAULT_PROFILE,
  DEFAULTS: PostLoginPolicy.DEFAULTS,
  FIELDS: PostLoginPolicy.FIELDS,
  FIELD_BY_KEY: PostLoginPolicy.FIELD_BY_KEY,
  SELECTORS: PostLoginPolicy.SELECTORS,
  SCHEMA: PostLoginPolicy.SCHEMA,
  SENTENCES: PostLoginPolicy.SENTENCES,
  ACTIVITIES: PostLoginPolicy.ACTIVITIES,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  personGroups: slot.forward('personGroups'),
  profileNameFor: slot.forward('profileNameFor'),
  forPerson: slot.forward('forPerson'),
  anyEnabled: slot.forward('anyEnabled'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
