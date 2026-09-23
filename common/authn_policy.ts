'use strict';
//
// File: authn_policy.ts
//
// ---------------------------------------------------------------------------
// THE AUTHENTICATION POLICY (#64, 2026-09-23): WHICH WAYS OF SIGNING IN THIS
// REALM ACCEPTS AS A FIRST FACTOR, WHICH AS A SECOND, AND WHEN A SECOND IS
// REQUIRED.
//
// Asked for by rcbj as the second policy on Directory > Policies: "a default
// policy ... that defines primary authentication mechanisms and MFA
// mechanisms. This can be overridden per realm by an administrator." It is a
// SEPARATE policy from the password policy (rcbj, 2026-09-23: "I want the
// password policy to remain separate") drawn on the SAME page (and: "I do
// want the /admin/policies page to be one page that holds both policies. And,
// all future policies") — so this module shares nothing with
// `password_policy.ts` but its shape, and `admin-core/policy_kinds.ts` is what
// puts both on one page.
//
// ---------------------------------------------------------------------------
// IT REPLACED THREE SETTINGS, WITH NO SHIM (D7).
//
// `authn.mfaRequired` became `requireSecondFactor` (`if-held` | `always`),
// `totp.enabled` became `totpSecondFactor` and `backupCodes.enabled` became
// `recoveryCodeSecondFactor`. Each was a second place answering a question
// this entry answers, and two places answering "may TOTP be used here" is
// the drift the repository's CLAUDE.md files exist to prevent. `totp.ts` and
// `backup_codes.ts` still expose `enabled` on their settings — read from
// here — so every one of their callers is unchanged.
//
// **THERE IS NO `never`.** A person who HOLDS a second factor is asked for it
// whatever the realm says (`credentials.mfaRequirementFor()`), because the
// opposite reopens the bypass the TOTP work closed: the WebAuthn screen
// enrols on first use, so a realm that could switch a held factor off would
// let anyone who knew the password register a fresh key and skip it.
//
// ---------------------------------------------------------------------------
// WHERE IT LIVES: `cn=default,ou=authnPolicies`, AND A REALM INHERITS (D6).
//
// A directory entry per realm, for every reason the password policy's is —
// and, UNLIKE the password policy, a realm with no entry of its own is
// governed by THE DEFAULT REALM'S entry before it falls back to the built-in
// defaults. That is the literal "default policy, overridable per realm": an
// operator writes the service's policy once, in the default realm, and a
// realm administrator overrides it by saving their own. `reset` deletes the
// realm's own entry, which puts it back to inheriting. `read()` says which of
// the three is in force (`from`), and every field says where its value came
// from (`sources`).
//
// **THE ENTRY IS NOT SEEDED**, for `password_policy.ts`'s reason: a seed is
// written into one realm, and a computed default exists in every realm by
// construction.
//
// ---------------------------------------------------------------------------
// EMAIL, AND NIST SP 800-63B-4 SECTION 3.1.3.1 (D1).
//
// "Email SHALL NOT be used for out-of-band authentication." The two email
// mechanisms (#64) are therefore OFF in the built-in policy, and the page and
// the API say why beside them. An operator may still turn them on — rcbj's
// rule is the most secure option by default and a weaker one available with a
// written warning. Two further guards follow from the section:
//
//   * **An email row cannot be SAVED on while this realm's mail is not
//     functional** (`mail.available()`), and one already on is INACTIVE —
//     never offered — while it is not (`active()`): a mechanism nobody can
//     receive is a sign-in screen with a dead button.
//   * **An emailed secret is valid for at most ten minutes** (section
//     3.1.3.2's bound for an out-of-band secret, applied though email is not
//     one), and a person's email factor is turned off after at most 100
//     consecutive failures (section 3.2.2).
//
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND A LEAF, `password_policy.ts`'s arrangement: it
// requires `helpers`, `mode`, `realms`, `error_codes` and the instance slot,
// reaches the directory through a slot `ldap/ldap_server.js` fills, and
// reaches `common/mail.ts` LAZILY — mail requires the directory and the
// scheduler, and nothing that asks "may TOTP be used" should load either.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import mode = require('./mode');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');

const { log } = helpers;

type Role = 'primary' | 'second-factor';

// One way of signing in, and what it is CAPABLE of. A mechanism that cannot
// be a first factor has no `primary` field at all, so no save can turn it on
// as one: a TOTP is a shared secret this service also holds, and a recovery
// code is a way back to an account and not into it.
interface Mechanism {
  id: string;
  label: string;
  primary: boolean | null;       // the built-in default, or null: incapable
  secondFactor: boolean | null;
  email?: boolean;
  what: string;
}

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'int' | 'bool' | 'enum';
  dflt: number | boolean | string;
  min?: number;
  max?: number;
  values?: string[];
  label: string;
  unit?: string;
  mechanism?: string;
  role?: Role;
  email?: boolean;
  what: string;
}

interface DirectoryHooks {
  allAuthnPolicies?(): { name?: string; dn: string;
                         attributes?: Record<string, unknown> }[];
  writeAuthnPolicy?(name: string,
                    attributes: Record<string, unknown>): unknown;
  deleteAuthnPolicy?(name: string): unknown;
  [hook: string]: unknown;
}

interface AuthnProfile {
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
  profile?: AuthnProfile;
}

interface AuthnPolicyDeps {
  log: typeof helpers.log;
  mode: { current(): string };
  realms: {
    isDefault(realm?: unknown): boolean;
    run<T>(realm: unknown, fn: () => T): T;
    DEFAULT_REALM: unknown;
  };
  errorCodes: {
    mark<T>(target: T, code: string): T;
    tag(code: string): string;
  };
  // Whether this realm can send mail, asked lazily (see the header).
  mailAvailable(): boolean;
}

const DEFAULT_PROFILE = 'default';

const NIST_EMAIL_WARNING =
  'NIST SP 800-63B-4 section 3.1.3.1: "Email SHALL NOT be used for ' +
  'out-of-band authentication", because a mailbox may be reached with a ' +
  'password alone, and mail may be read in transit or rerouted. Off by ' +
  'default for that reason; turn it on only where that is an accepted risk.';

// ---------------------------------------------------------------------------
// THE MECHANISMS. The rows below are generated from this list, so a mechanism
// is one line here.
// ---------------------------------------------------------------------------
const MECHANISMS: Mechanism[] = [
  { id: 'password', label: 'Password', primary: true, secondFactor: true,
    what: 'A password on the sign-in screen. As a SECOND factor it is the ' +
          'password asked for after a wallet or other passwordless first ' +
          'factor.' },
  { id: 'passkey', label: 'Security key or passkey (passwordless)',
    primary: true, secondFactor: null,
    what: 'A WebAuthn credential enrolled in the primary role, signing in ' +
          'with no password.' },
  { id: 'securityKey', label: 'Security key (second factor)', primary: null,
    secondFactor: true,
    what: 'A WebAuthn credential enrolled in the mfa role, asked for after a ' +
          'first factor.' },
  { id: 'totp', label: 'Authenticator app (TOTP)', primary: null,
    secondFactor: true,
    what: 'An RFC 6238 one-time code. Never a first factor: this service ' +
          'holds the same shared secret the app does. Off here, nobody may ' +
          'ENROL one; a person who already holds one is still asked for it, ' +
          'because an off switch that downgraded every enrolled account to a ' +
          'password alone would do something other than it says (this row ' +
          'replaced totp.enabled, and keeps its contract).' },
  { id: 'recoveryCode', label: 'Recovery code', primary: null,
    secondFactor: true,
    what: 'A single-use code from a set the person generated. Off here, no ' +
          'new set may be generated; a set already held still works (this ' +
          'row replaced backupCodes.enabled, and keeps its contract).' },
  { id: 'emailCode', label: 'Emailed six-digit code', primary: false,
    secondFactor: false, email: true,
    what: 'A six-digit code mailed to the person\'s VERIFIED address. ' +
          NIST_EMAIL_WARNING },
  { id: 'emailLink', label: 'Emailed sign-in link', primary: false,
    secondFactor: false, email: true,
    what: 'A single-use link mailed to the person\'s VERIFIED address, which ' +
          'completes the sign-in only in the browser that started it. ' +
          NIST_EMAIL_WARNING },
  { id: 'certificate', label: 'TLS client certificate', primary: true,
    secondFactor: null,
    what: 'GET /tls/sign-in with a verified client certificate.' },
  { id: 'kerberos', label: 'Kerberos (SPNEGO)', primary: true,
    secondFactor: null,
    what: 'GET /authn/spnego with a Kerberos ticket.' },
  { id: 'wallet', label: 'Wallet presentation', primary: true,
    secondFactor: null,
    what: '/authn/wallet with a credential this realm issued, or a SIOPv2 ' +
          'self-issued ID Token from an enrolled key.' },
  { id: 'federation', label: 'Federation partner', primary: true,
    secondFactor: null,
    what: 'A sign-in asserted by a configured federation partner.' }
];

const MECHANISM_BY_ID: Record<string, Mechanism> = {};
MECHANISMS.forEach(function (m) {
  MECHANISM_BY_ID[m.id] = m;
});

// `emailCode` + `primary` -> `emailCodePrimary`, and the attribute beside it.
function fieldKeyOf(mechanism: string, role: Role): string {
  log.debug("Entering fieldKeyOf().");
  log.debug("Leaving fieldKeyOf().");
  return mechanism + (role === 'primary' ? 'Primary' : 'SecondFactor');
}

function attributeOf(key: string): string {
  log.debug("Entering attributeOf().");
  log.debug("Leaving attributeOf().");
  return 'stsAuthn' + key.charAt(0).toUpperCase() + key.slice(1);
}

// ---------------------------------------------------------------------------
// THE FIELDS. ONE TABLE, read five ways, as the password policy's is: the
// schema, the form on /admin/policies, the API body, the validation of a save
// and the parse of an entry.
// ---------------------------------------------------------------------------
const FIELDS: PolicyField[] = ([
  { key: 'requireSecondFactor', attribute: 'stsAuthnRequireSecondFactor',
    type: 'enum', values: ['if-held', 'always'], dflt: 'if-held',
    label: 'Second factor required',
    what: '`if-held`: a person is asked for a second factor when they hold ' +
          'one (or their entry says stsMfaRequired). `always`: everybody in ' +
          'this realm is, and somebody who holds none is sent to enrol one ' +
          'at their next sign-in. This replaced authn.mfaRequired. There is ' +
          'no "never": a held factor is always asked for.' }
] as PolicyField[]).concat(MECHANISMS.reduce(function (out: PolicyField[], m) {
  (['primary', 'second-factor'] as Role[]).forEach(function (role) {
    const dflt = role === 'primary' ? m.primary : m.secondFactor;
    if (dflt === null) {
      return;
    }
    const key = fieldKeyOf(m.id, role);
    out.push({ key: key, attribute: attributeOf(key), type: 'bool',
               dflt: dflt, mechanism: m.id, role: role, email: !!m.email,
               label: m.label + (role === 'primary' ? ' — as a first factor'
                                   : ' — as a second factor'),
               what: m.what });
  });
  return out;
}, [])).concat([
  { key: 'emailCodeTtlS', attribute: 'stsAuthnEmailCodeTtlS', type: 'int',
    dflt: 300, min: 60, max: 600, unit: 'seconds', email: true,
    label: 'How long an emailed code or link is valid',
    what: 'From the moment it is sent. At most ten minutes, NIST SP 800-63B-4 ' +
          'section 3.1.3.2\'s bound for an out-of-band secret.' },
  { key: 'emailCodeAttempts', attribute: 'stsAuthnEmailCodeAttempts',
    type: 'int', dflt: 5, min: 1, max: 10, unit: 'attempts', email: true,
    label: 'Wrong codes before the sign-in step ends',
    what: 'How many wrong codes one sign-in step accepts before it is ended ' +
          'and the person starts again. The per-person and per-network rate ' +
          'limits apply as well.' },
  { key: 'emailResendS', attribute: 'stsAuthnEmailResendS', type: 'int',
    dflt: 60, min: 15, max: 600, unit: 'seconds', email: true,
    label: 'Shortest wait before another code or link is sent',
    what: 'A new code or link replaces the last one, which stops working. At ' +
          'most three are sent for one sign-in step.' },
  { key: 'emailFailureLimit', attribute: 'stsAuthnEmailFailureLimit',
    type: 'int', dflt: 100, min: 5, max: 100, unit: 'failures', email: true,
    label: 'Consecutive failures before a person\'s email factor is turned off',
    what: 'NIST SP 800-63B-4 section 3.2.2 asks for no more than 100. The ' +
          'person, and their administrators, are told, and the person turns ' +
          'it on again from the portal.' }
]);

const FIELD_BY_KEY: Record<string, PolicyField> = {};
FIELDS.forEach(function (field) {
  FIELD_BY_KEY[field.key] = field;
});

const DEFAULTS: Readonly<Record<string, number | boolean | string>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    out[field.key] = field.dflt;
    return out;
  }, {} as Record<string, number | boolean | string>));

const SCHEMA = {
  container: 'ou=authnPolicies',
  objectClasses: [
    { name: 'stsAuthnPolicy',
      what: 'This service\'s class for an authentication policy: which ' +
            'mechanisms are accepted as a first and as a second factor, and ' +
            'when a second factor is required. The entry is named by the ' +
            'PROFILE (`cn=default`).' }
  ],
  attributes: FIELDS.map(function (field) {
    return { name: field.attribute, what: field.what };
  }).concat([
    { name: 'description',
      what: 'What the profile is for, for the next person.' }
  ]),
  personAttributes: [
    { name: 'stsMailFactor',
      what: 'Which emailed second factor this person opted in to: `code` or ' +
            '`link`. Absent: none. Set on /portal/mfa, cleared on /admin/mfa ' +
            'and after too many consecutive failures.' },
    { name: 'stsMailFactorFailures',
      what: 'Consecutive failed emailed codes or links, reset by a success. ' +
            'Maintained by this service.' }
  ]
};

class AuthnPolicy {
  static readonly DEFAULT_PROFILE = DEFAULT_PROFILE;
  static readonly DEFAULTS = DEFAULTS;
  static readonly FIELDS = FIELDS;
  static readonly FIELD_BY_KEY = FIELD_BY_KEY;
  static readonly MECHANISMS = MECHANISMS;
  static readonly SCHEMA = SCHEMA;
  static readonly NIST_EMAIL_WARNING = NIST_EMAIL_WARNING;

  private directory: DirectoryHooks | null = null;
  private warnedAboutNoDirectory = false;

  constructor(private readonly deps: AuthnPolicyDeps) {
    deps.log.debug("Entering AuthnPolicy.constructor().");
    deps.log.debug("Leaving AuthnPolicy.constructor().");
  }

  static defaultDeps(): AuthnPolicyDeps {
    log.debug("Entering AuthnPolicy.defaultDeps().");
    log.debug("Leaving AuthnPolicy.defaultDeps().");
    return {
      log: log,
      mode: mode,
      realms: realms,
      errorCodes: errorCodes,
      mailAvailable: function () {
        log.debug("Entering AuthnPolicy mailAvailable().");
        try {
          // LAZY, for the header's reason.
          const mail = require('./mail');
          const out = typeof mail.available === 'function' &&
                      !!mail.available();
          log.debug("Leaving AuthnPolicy mailAvailable().");
          return out;
        } catch (e) {
          log.debug("Caught in AuthnPolicy mailAvailable(): " +
                    ((e && e.message) || e));
          // No mail module in this process (a test that never loaded it) is
          // no mail, which is the direction that turns the email rows OFF.
          log.debug("Leaving AuthnPolicy mailAvailable(). No mail module.");
          return false;
        }
      }
    };
  }

  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug('Entering AuthnPolicy.setDirectory().');
    this.directory = hooks || null;
    log.debug('Leaving AuthnPolicy.setDirectory(). The authentication ' +
              'policy register ' +
              (this.directory ? 'has its container.' : 'has none.'));
  }

  directoryInstalled(): DirectoryHooks | null {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.directoryInstalled().");
    log.debug("Leaving AuthnPolicy.directoryInstalled().");
    return this.directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.haveDirectory().");
    if (this.directory &&
        typeof this.directory.allAuthnPolicies === 'function') {
      log.debug("Leaving AuthnPolicy.haveDirectory().");
      return true;
    }
    if (!this.warnedAboutNoDirectory) {
      this.warnedAboutNoDirectory = true;
      log.warn('authn_policy: the embedded directory was never loaded, so ' +
               'there is no ou=authnPolicies. The BUILT-IN authentication ' +
               'policy is in force and cannot be edited in this process.');
    }
    log.debug("Leaving AuthnPolicy.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  private firstValue(attributes: Record<string, unknown>,
                     name: string): unknown {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.firstValue().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving AuthnPolicy.firstValue().");
    return Array.isArray(found) ? (found[0] === undefined ? '' : found[0])
      : (found === undefined || found === null ? '' : found);
  }

  // `password_policy.ts`'s parse, with an `enum` type beside `int` and
  // `bool`. Never guesses: `12.5` is not 12 and `yes` is not TRUE.
  private parseField(field: PolicyField,
                     raw: unknown): { value?: number | boolean | string;
                                      problem?: string } {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.parseField().");
    const text = String(raw === undefined || raw === null ? '' : raw).trim();
    if (field.type === 'bool') {
      const lower = text.toLowerCase();
      if (['true', 'on', '1'].indexOf(lower) >= 0) {
        log.debug("Leaving AuthnPolicy.parseField().");
        return { value: true };
      }
      if (['false', 'off', '0', ''].indexOf(lower) >= 0) {
        log.debug("Leaving AuthnPolicy.parseField().");
        return { value: false };
      }
      log.debug("Leaving AuthnPolicy.parseField().");
      return { problem: field.label + ' is a yes-or-no setting, and "' +
                        text.slice(0, 40) + '" is neither.' };
    }
    if (field.type === 'enum') {
      if ((field.values || []).indexOf(text) >= 0) {
        log.debug("Leaving AuthnPolicy.parseField().");
        return { value: text };
      }
      log.debug("Leaving AuthnPolicy.parseField().");
      return { problem: field.label + ' is one of ' +
                        (field.values || []).join(', ') + '; "' +
                        text.slice(0, 40) + '" is not.' };
    }
    if (!/^\d+$/.test(text)) {
      log.debug("Leaving AuthnPolicy.parseField().");
      return { problem: field.label + ' must be a whole number between ' +
                        field.min + ' and ' + field.max + '; "' +
                        text.slice(0, 40) + '" is not one.' };
    }
    const value = Number(text);
    if (value < field.min || value > field.max) {
      log.debug("Leaving AuthnPolicy.parseField().");
      return { problem: field.label + ' must be between ' + field.min +
                        ' and ' + field.max + '; ' + value + ' is not.' };
    }
    log.debug("Leaving AuthnPolicy.parseField().");
    return { value: value };
  }

  // The rules that relate fields. A realm must leave SOME way in as a first
  // factor, or nobody could sign in to it — the console included.
  private crossFieldProblems(values: Record<string, any>): string[] {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.crossFieldProblems().");
    const out: string[] = [];
    const anyPrimary = MECHANISMS.some(function (m) {
      return m.primary !== null && values[fieldKeyOf(m.id, 'primary')];
    });
    if (!anyPrimary) {
      out.push('No mechanism is accepted as a first factor, so nobody could ' +
               'sign in to this realm — its administrators included. Leave ' +
               'at least one on.');
    }
    if (values.requireSecondFactor === 'always') {
      const anySecond = MECHANISMS.some(function (m) {
        return m.secondFactor !== null &&
               values[fieldKeyOf(m.id, 'second-factor')];
      });
      if (!anySecond) {
        out.push('A second factor is required of everybody, but no ' +
                 'mechanism is accepted as one, so nobody could finish ' +
                 'signing in. Turn one on, or require a second factor only ' +
                 'of those who hold one.');
      }
    }
    log.debug("Leaving AuthnPolicy.crossFieldProblems().");
    return out;
  }

  private entryIn(name: string) {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.entryIn().");
    const wanted = name.toLowerCase();
    log.debug("Leaving AuthnPolicy.entryIn().");
    return this.directory.allAuthnPolicies().filter(function (entry) {
      return String(entry.name || '').toLowerCase() === wanted;
    })[0] || null;
  }

  // THIS REALM'S OWN ENTRY, THEN THE DEFAULT REALM'S. The second read runs in
  // the default realm's context, which is what points the directory at that
  // realm's tree.
  private entryFor(name: string): { entry: any; from: AuthnProfile['from'] } {
    const { log, realms } = this.deps;
    log.debug("Entering AuthnPolicy.entryFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving AuthnPolicy.entryFor(). No directory.");
      return { entry: null, from: 'built-in' };
    }
    const own = this.entryIn(name);
    if (own) {
      log.debug("Leaving AuthnPolicy.entryFor(). The realm's own.");
      return { entry: own, from: 'realm' };
    }
    if (realms.isDefault()) {
      log.debug("Leaving AuthnPolicy.entryFor(). Built-in.");
      return { entry: null, from: 'built-in' };
    }
    const inherited = realms.run(realms.DEFAULT_REALM, () => {
      log.debug("Entering AuthnPolicy.entryFor() default-realm read.");
      const found = this.entryIn(name);
      log.debug("Leaving AuthnPolicy.entryFor() default-realm read.");
      return found;
    });
    log.debug("Leaving AuthnPolicy.entryFor(). " +
              (inherited ? 'Inherited.' : 'Built-in.'));
    return inherited ? { entry: inherited, from: 'default-realm' }
      : { entry: null, from: 'built-in' };
  }

  // THE PROFILE IN FORCE. Always answers; an unreadable stored value falls
  // back to the built-in default and is named in `problems`, for
  // `password_policy.ts`'s reason — somebody who broke one attribute must not
  // get a policy with no rule.
  read(name?: string): AuthnProfile {
    const { log } = this.deps;
    log.debug('Entering AuthnPolicy.read(). name=' + name);
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
      this.crossFieldProblems(values).forEach(function (problem) {
        problems.push(problem);
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
      // Unlike a password rule, which development mode does not check, this
      // policy decides what the sign-in screen OFFERS, in both modes.
      enforced: true
    }, values) as AuthnProfile;
    log.debug('Leaving AuthnPolicy.read(). From ' + found.from + '.');
    return out;
  }

  profileFor(username?: unknown): AuthnProfile {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.profileFor().");
    void username;
    log.debug("Leaving AuthnPolicy.profileFor().");
    return this.read(DEFAULT_PROFILE);
  }

  list(): AuthnProfile[] {
    const { log } = this.deps;
    log.debug('Entering AuthnPolicy.list().');
    const rows = [this.read(DEFAULT_PROFILE)];
    log.debug('Leaving AuthnPolicy.list(). ' + rows.length + ' profile(s).');
    return rows;
  }

  // -------------------------------------------------------------------------
  // WHAT THE DOORS ASK.
  // -------------------------------------------------------------------------

  // Whether the policy ALLOWS a mechanism in a role. An unknown mechanism or
  // a role it is incapable of is false.
  allows(mechanism: string, role: Role, profile?: AuthnProfile | null):
      boolean {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.allows(). " + mechanism + " " + role);
    const m = MECHANISM_BY_ID[mechanism];
    if (!m || (role === 'primary' ? m.primary : m.secondFactor) === null) {
      log.debug("Leaving AuthnPolicy.allows(). Incapable.");
      return false;
    }
    const rules = profile || this.read(DEFAULT_PROFILE);
    const out = !!rules[fieldKeyOf(mechanism, role)];
    log.debug("Leaving AuthnPolicy.allows(). " + out);
    return out;
  }

  // Whether a mechanism may be OFFERED right now: allowed, and — for the two
  // email mechanisms — this realm's mail is functional. Fail closed: a
  // mechanism nobody can receive is never drawn.
  active(mechanism: string, role: Role, profile?: AuthnProfile | null):
      boolean {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.active(). " + mechanism + " " + role);
    if (!this.allows(mechanism, role, profile)) {
      log.debug("Leaving AuthnPolicy.active(). Not allowed.");
      return false;
    }
    const m = MECHANISM_BY_ID[mechanism];
    const out = !m.email || this.mailUsable();
    log.debug("Leaving AuthnPolicy.active(). " + out);
    return out;
  }

  mailUsable(): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.mailUsable().");
    const out = !!this.deps.mailAvailable();
    log.debug("Leaving AuthnPolicy.mailUsable(). " + out);
    return out;
  }

  // `if-held` or `always`.
  requireSecondFactor(profile?: AuthnProfile | null): string {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.requireSecondFactor().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    log.debug("Leaving AuthnPolicy.requireSecondFactor().");
    return String(rules.requireSecondFactor);
  }

  // The email mechanisms' numbers, with the ten-minute bound applied again
  // here — a hand-edited entry is range-checked by `read()`, and this is the
  // line every emailed secret's lifetime is computed from.
  emailSettings(profile?: AuthnProfile | null) {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.emailSettings().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const out = {
      ttlS: Math.min(600, Math.max(60, Number(rules.emailCodeTtlS))),
      attempts: Math.max(1, Number(rules.emailCodeAttempts)),
      resendS: Math.max(15, Number(rules.emailResendS)),
      maxSends: 3,
      failureLimit: Math.min(100, Math.max(5,
                                           Number(rules.emailFailureLimit)))
    };
    log.debug("Leaving AuthnPolicy.emailSettings().");
    return out;
  }

  // The policy as sentences, for the page and for a save's answer.
  describe(profile?: AuthnProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.describe().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const names = (role: Role): string => {
      log.debug("Entering AuthnPolicy.describe() names().");
      const on = MECHANISMS.filter((m) => {
        return this.allows(m.id, role, rules);
      }).map(function (m) {
        return m.label;
      });
      log.debug("Leaving AuthnPolicy.describe() names().");
      return on.length ? on.join(', ') : 'none';
    };
    const out = [
      'first factors: ' + names('primary'),
      'second factors: ' + names('second-factor'),
      rules.requireSecondFactor === 'always'
        ? 'a second factor is required of everybody'
        : 'a second factor is required of those who hold one'
    ];
    const email = MECHANISMS.some((m) => {
      return m.email && (this.allows(m.id, 'primary', rules) ||
                         this.allows(m.id, 'second-factor', rules));
    });
    if (email) {
      const s = this.emailSettings(rules);
      out.push('an emailed code or link is valid for ' + s.ttlS +
               ' seconds' + (this.mailUsable() ? ''
                 : ' — INACTIVE: this realm cannot send mail'));
    }
    log.debug("Leaving AuthnPolicy.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WRITING.
  // -------------------------------------------------------------------------
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.checkProfileName().");
    const text = String(name || DEFAULT_PROFILE).trim();
    if (text.toLowerCase() !== DEFAULT_PROFILE) {
      log.debug("Leaving AuthnPolicy.checkProfileName().");
      return 'There is one authentication policy profile, "' +
             DEFAULT_PROFILE + '", and it applies to everybody in this ' +
             'realm. "' + text.slice(0, 64) + '" cannot be created: nothing ' +
             'assigns a profile to a person, so a second one would decide ' +
             'nothing while looking exactly like one that does.';
    }
    log.debug("Leaving AuthnPolicy.checkProfileName().");
    return null;
  }

  // Every field, as the password policy's save: one left out is refused by
  // name, except an unticked checkbox on the console's own form.
  validate(given?: Record<string, any> | null) {
    const { log } = this.deps;
    log.debug('Entering AuthnPolicy.validate().');
    const body = given || {};
    const values: Record<string, number | boolean | string> = {};
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
      this.crossFieldProblems(values).forEach(function (problem) {
        problems.push(problem);
      });
    }
    log.debug('Leaving AuthnPolicy.validate(). ' + problems.length +
              ' problem(s).');
    return { values: values, problems: problems };
  }

  // The email rows that a save would turn ON, which is what the mail check
  // refuses. A row already on and saved on again is refused too: a save is
  // the whole profile, and writing down a mechanism nobody can receive is
  // the mistake the check exists for.
  private emailRowsOn(values: Record<string, any>): PolicyField[] {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.emailRowsOn().");
    log.debug("Leaving AuthnPolicy.emailRowsOn().");
    return FIELDS.filter(function (field) {
      return field.type === 'bool' && field.email && values[field.key];
    });
  }

  save(name: unknown, given?: Record<string, any> | null): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering AuthnPolicy.save(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving AuthnPolicy.save(). Not a profile that can exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0242');
    }
    const checked = this.validate(given);
    if (checked.problems.length) {
      log.debug('Leaving AuthnPolicy.save(). The values were refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-AUTHN-0243');
    }
    const emailOn = this.emailRowsOn(checked.values);
    if (emailOn.length && !this.mailUsable()) {
      log.debug('Leaving AuthnPolicy.save(). Mail is not functional.');
      return errorCodes.mark({ ok: false, errors: [
        emailOn.map(function (f) {
          return f.label;
        }).join(', ') + ' cannot be turned on: this realm cannot send mail. ' +
        'Configure a transport on Server configuration > Mail (/admin/mail) ' +
        'first.'] }, 'STS-AUTHN-0244');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving AuthnPolicy.save(). No directory.');
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep an authentication policy. ' +
                        'ou=authnPolicies IS the register.'] },
                             'STS-AUTHN-0245');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'stsAuthnPolicy'],
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
    const written = this.directory.writeAuthnPolicy(DEFAULT_PROFILE,
                                                    attributes);
    if (!written) {
      log.debug('Leaving AuthnPolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-AUTHN-0246');
    }
    log.debug('Leaving AuthnPolicy.save(). Stored.');
    return { ok: true, profile: this.read(DEFAULT_PROFILE) };
  }

  // Deleting THIS REALM'S entry, which puts it back to inheriting — the
  // default realm's entry where there is one, the built-in defaults where
  // there is not.
  reset(name: unknown): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering AuthnPolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving AuthnPolicy.reset(). Not a profile that can exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0242');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving AuthnPolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(DEFAULT_PROFILE) };
    }
    const removed = !!this.directory.deleteAuthnPolicy(DEFAULT_PROFILE);
    log.debug('Leaving AuthnPolicy.reset(). ' +
              (removed ? 'Removed.' : 'Nothing stored.'));
    return { ok: true, removed: removed,
             profile: this.read(DEFAULT_PROFILE) };
  }

  enforced(): boolean {
    const { log } = this.deps;
    log.debug("Entering AuthnPolicy.enforced().");
    log.debug("Leaving AuthnPolicy.enforced().");
    return true;
  }
}

const slot = new InstanceSlot<AuthnPolicy>(
  'common/authn_policy',
  () => new AuthnPolicy(AuthnPolicy.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

export = {
  AuthnPolicy: AuthnPolicy,
  installInstance: (instance: AuthnPolicy): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  DEFAULT_PROFILE: AuthnPolicy.DEFAULT_PROFILE,
  DEFAULTS: AuthnPolicy.DEFAULTS,
  FIELDS: AuthnPolicy.FIELDS,
  FIELD_BY_KEY: AuthnPolicy.FIELD_BY_KEY,
  MECHANISMS: AuthnPolicy.MECHANISMS,
  SCHEMA: AuthnPolicy.SCHEMA,
  NIST_EMAIL_WARNING: AuthnPolicy.NIST_EMAIL_WARNING,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileFor: slot.forward('profileFor'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  allows: slot.forward('allows'),
  active: slot.forward('active'),
  mailUsable: slot.forward('mailUsable'),
  requireSecondFactor: slot.forward('requireSecondFactor'),
  emailSettings: slot.forward('emailSettings'),
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
