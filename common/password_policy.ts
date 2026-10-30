// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: password_policy.ts
//
// ---------------------------------------------------------------------------
// THE PASSWORD POLICY (2026-09-12): WHAT A PASSWORD HERE MUST LOOK LIKE, WHICH
// OF A PERSON'S OLD ONES IT MAY NOT BE, AND HOW ONE IS MADE UP.
//
// Asked for by rcbj as the first policy on a Directory > Policies page:
// a minimum length, a number of password generations that may not repeat, a
// number of symbols, an uppercase letter and a digit — with reasonable
// defaults, called the DEFAULT PROFILE, ENFORCED IN PRODUCT MODE, and applied
// on the first password a person sets as well as on every later one.
//
// **IT REPLACED A ONE-RULE POLICY THAT WAS HOURS OLD.** `credentials.ts` had a
// minimum length read from `security.passwordMinLength`, whose comment argued
// — correctly, as a reading of NIST SP 800-63B section 5.1.1.2 — that a
// verifier SHOULD NOT impose composition rules. The composition rules here
// are the deployment's choice rather than this file's advice, each of them
// can be turned off (a symbol count of 0, the two booleans false), and the
// history rule is one NIST does not argue against at all. What survives from
// that rule is the part that was right: ONE place decides, and every door
// that sets a password asks it.
//
// ---------------------------------------------------------------------------
// WHERE IT LIVES: A DIRECTORY ENTRY, `cn=default,ou=passwordPolicies`.
//
// rcbj chose a directory entry over a settings group, and the reasons are the
// ones every other register here was put in the directory for: it is per
// realm because the directory is, it persists and replicates with the
// directory, an `ldapsearch` finds it, and a container holds more than one
// profile the day a profile can be ASSIGNED to somebody.
//
// **THE ATTRIBUTE NAMES FOLLOW draft-behera-ldap-password-policy WHERE IT HAS
// ONE**, which is the schema OpenLDAP's ppolicy overlay and 389 Directory
// Server read: `pwdAttribute`, `pwdMinLength`, `pwdInHistory` on the policy,
// and `pwdHistory` and `pwdChangedTime` on the person. An LDAP administrator
// who has met a password policy entry before recognises this one. The draft
// defines no composition rule — it delegates "quality" to the server — so the
// three composition attributes, and the length of a generated password, are
// this service's own and are spelt `stsPwd*` so that nobody mistakes them for
// the draft's.
//
// **`pwdInHistory` MEANS WHAT THE DRAFT SAYS IT MEANS**: the number of PREVIOUS
// passwords kept. A new password may be neither the current one nor any of
// those, so a value of 5 refuses six passwords — which is how OpenLDAP reads
// the same attribute. 0 turns the rule off entirely, the current password
// included, again as the draft says.
//
// **THE ENTRY IS NOT SEEDED.** An absent `cn=default` means the BUILT-IN
// defaults below are in force, and the console says so; the entry is written
// the first time an operator saves the profile. That is `role-issuance`'s
// argument in `xacml/xacml_role_pep.ts` made again: a seed written into the
// directory at startup is written into ONE realm, a realm created later has
// none, and a policy that silently did not exist in some realms is the defect
// that argument was written about. A computed default exists in every realm
// by construction.
//
// ---------------------------------------------------------------------------
// ENFORCED WHERE A PASSWORD IS VERIFIED, WHICH IS PRODUCT MODE.
//
// `mode.verifiesCredentials()`, for the reason the length rule gave: a
// development-mode service checks no password at any door, so refusing one
// there would be a policy about a credential nothing reads — and it would
// break every fixture that sets one. The HISTORY is RECORDED in both modes,
// though, because recording costs nothing (it is the previous hash moving,
// never a new hash) and a realm switched to product mode should not start
// with an empty history for everybody.
//
// A GENERATED password satisfies the profile in BOTH modes, because it is
// made by drawing until it does — there is no mode in which this service
// hands somebody a password its own policy would refuse.
//
// ---------------------------------------------------------------------------
// THE GENERATOR IS `crypto.js`'s `randomString()`, AND ITS ONE JOB HERE IS
// THE DRAW (#65, 2026-09-23). It was the `generate-password` package, which
// rejection-samples correctly but pre-draws 256 random bytes into a buffer
// that lives at module scope between passwords, and is a dependency on the
// path of a secret for twenty lines — section 13's argument for not taking
// nanoid. `randomString()` draws each character with node's `randomInt()`,
// rejection-sampled inside node, so every character of the pool is equally
// likely and nothing is held between draws.
//
// `PasswordGenerator.generate()` keeps that package's option shape (the
// injected `generator` dependency is unchanged, so a test can still hand in
// a stub) and its `strict` meaning — at least one of each pool and no more.
// Symbol COUNTS are the profile's, so this file draws with all four pools on
// and REJECTS WHOLE PASSWORDS that fail the profile until one passes.
// Rejection at the password level keeps the result uniform over the
// passwords that pass, where "patch in another symbol" would not. A strict
// draw that misses a pool is one of the MAX_DRAWS below, where the package
// recursed without a bound.
//
// Every pool is on whatever the profile requires: a profile not REQUIRING an
// uppercase letter is not a profile forbidding one, and a smaller alphabet is
// a weaker password for nothing. Two characters are left out of the symbols —
// the double quote and the backtick — because a generated password is shown
// once and then pasted, frequently into a shell or a JSON body, and those two
// are the ones that silently end or change the string there.
//
// ---------------------------------------------------------------------------
// HOW A PASSWORD IS STORED IS A RULE OF THE PROFILE TOO (2026-10-22, #847).
//
// `stsPwdHashAlgorithm` names the algorithm a NEWLY stored password is hashed
// with — argon2id by default, at OWASP's minimum (m=19 MiB, t=2, p=1), or
// scrypt — and six more rows carry both algorithms' parameters. rcbj's
// decisions on #847: argon2id is the default; scrypt stays selectable; no
// bound is below OWASP's minimums, in either mode; a stored hash that is not
// the preferred algorithm AND parameters is hashed again at the person's next
// verified sign-in (`credentials.ts`); and the password policy governs
// people's passwords only — every other secret stays scrypt. The seven rows
// are OPTIONAL in a save: one left out keeps the value in force rather than
// being refused, because every caller written before they existed sends the
// six composition rows and nothing else, and keeping the value in force is
// what the "every field is sent" rule exists to guarantee. `hashSpec()` is
// what a password writer asks.
//
// ---------------------------------------------------------------------------
// NAMED POLICIES, AND WHAT NAMES ONE (#1236, 2026-10-30; rule 3cx). Until
// then the container held `cn=default` alone and a second name was refused,
// because nothing could ASSIGN one. #1234 gave every kind a way to: an
// application names its password policy in `appPasswordPolicy`, a group in
// `stsPasswordPolicy`, and a named policy carries every row `default` has
// plus `stsPasswordPrecedence`. `profileFor(username, application)` ranks
// the candidates — the application's reference and each of the person's
// groups' — through `common/policy_selection.ts`: the lowest precedence
// wins, ties by name, else `default`. A person names none of their own
// (#1234's table). A reader with no person in hand (the service-account
// policy's save check, a page with nobody signed in) reads `default`.
//
// **A REFERENCE TO A POLICY THE REALM DOES NOT HOLD FAILS CLOSED TO
// `default`** (STS-AUTHN-0539) — the WHOLE answer is `default`, whatever
// else ranked. Both writes are checked and a named policy is not deleted
// while anything names it (STS-AUTHN-0540), so only a write past the
// console makes one. `default` is the one policy an operator has stated
// for everybody, never weaker than no policy; letting the rest of the
// ranking stand would hand a person whatever lax profile some other group
// names exactly when the reference meant to override it is broken. The
// case against: an application's stricter policy is displaced by a broken
// GROUP reference. It was weighed and accepted — the answer must not
// depend on which reference broke, and the log names it.
//
// Named policies are the realm's own and are not inherited (#1234's
// decision 3); neither is `default`, which never was.
// ---------------------------------------------------------------------------
// IT IS A LIBRARY (rule 3) AND A LEAF. It requires `helpers.js`, `mode.js`,
// `crypto.js` and `error_codes.js`, registers no route, and reaches the
// directory through a slot `ldap/ldap_server.js` fills — `common/roles.js`'s
// arrangement exactly, and for its reason: that module is required at 21, so a
// require from here would drag every `/ldap` route to the front of the router.
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `PasswordPolicy` takes the logger, the mode, the generator and the
// error codes through its constructor, and holds the directory slot. The
// FIELDS table, the schema and the constants stay module-scope declarations
// and are exported as static members. A profile is
// `types/password-policy.d.ts`'s `PasswordProfile`. The module still exports
// every old name — `setDirectory` among them, the slot `ldap/ldap_server.js`
// fills at its require time. Since #50's R2 the composition root builds the
// instance (`PasswordPolicy.defaultDeps()`) and installs it; the module's old
// export names are FACADES that forward to it, for the JavaScript callers, and
// a process without the root builds a default when this module finishes
// loading.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import mode = require('./mode');
// The one random-value section (#65): every generated password's characters.
import stsCrypto = require('./crypto');
// The error codes. A LEAF that requires nothing, so it cannot close a cycle
// from here. A refusal this module RETURNS carries its code non-enumerably,
// under the Symbol `mark()` uses, so a caller reads it with `codeOf()` and
// nothing that serialises the answer can send it anywhere.
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
// The shared named-policy ranking (#1235, rule 3cx): a leaf of static
// methods over values handed in, so requiring it closes no cycle.
import PolicySelection = require('./policy_selection');
// The sentences `describe()` makes are filled from SENTENCES below, so the
// server can translate them into a console reader's language (#543).
import serverProse = require('./server_prose');

const { log } = helpers;

// The profile `read()` answers — declared once, in `types/`, for the callers
// that are still JavaScript.
type PasswordProfile = import('../types/password-policy').PasswordProfile;

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'int' | 'bool' | 'enum';
  dflt: number | boolean | string;
  min?: number;
  max?: number;
  // An `enum` row's closed set (#847).
  values?: string[];
  // A row a save may leave out (#847): it keeps the value in force, so a
  // caller written before the row existed loosens nothing by not naming it.
  optional?: boolean;
  label: string;
  unit?: string;
  what: string;
}

// What `ldap/ldap_server.js` installs through `setDirectory()`.
interface DirectoryHooks {
  allPasswordPolicies?(): { name?: string; dn: string;
                            attributes?: Record<string, unknown> }[];
  writePasswordPolicy?(name: string,
                       attributes: Record<string, unknown>): unknown;
  deletePasswordPolicy?(name: string): unknown;
  // #1236: the policy each of a person's groups names (`stsPasswordPolicy`),
  // and the groups naming one — the group index, no walk.
  personGroupReferences?(key: string, attribute: string):
    Array<{ cn?: string; dn?: string; value?: string }>;
  groupsNamingPolicy?(attribute: string, name: unknown): string[];
  [hook: string]: unknown;
}

// What a save or a reset answers.
interface PolicyResult {
  ok: boolean;
  errors?: string[];
  removed?: boolean;
  profile?: PasswordProfile;
}

// What this module needs from the rest of the service. Named for what is
// asked of each, so a test can supply exactly that and nothing more.
interface PasswordPolicyDeps {
  log: typeof helpers.log;
  mode: { verifiesCredentials(): boolean };
  generator: { generate(options: Record<string, unknown>): string };
  errorCodes: {
    mark<T>(target: T, code: string): T;
    tag(code: string): string;
  };
}

const DEFAULT_PROFILE = 'default';

// WHAT A NAMED POLICY CARRIES BESIDE ITS ROWS (#1236): its precedence, and
// nothing else — what it covers names it (rule 3cx).
const SELECTORS = [
  { key: 'precedence', attribute: 'stsPasswordPrecedence',
    what: 'Which named password policy wins where several are named for ' +
          'one person: the lowest, from 1 to 1000.' }
];
/**
 * How `common/policy_selection.ts` reads a named password policy (#1236).
 */
const SELECTION = { precedenceAttribute: 'stsPasswordPrecedence',
                    defaultPrecedence: PolicySelection.DEFAULT_PRECEDENCE };
/**
 * The attributes that NAME a password policy (#1236): on an application
 * and on a group. A person names none of their own.
 */
const REFERENCES = Object.freeze({ application: 'appPasswordPolicy',
                                   group: 'stsPasswordPolicy' });
/**
 * What a refusal or a log line calls one.
 */
const NOUN = 'password policy';
/**
 * The missing references already logged in this process, so a broken
 * reference is said once rather than at every password a sign-in verifies
 * (the upgrade check asks the profile then). Bounded.
 */
const MISSING_SAID = new Set<string>();
const MISSING_SAID_MAX = 1000;

// The two characters the generator leaves out of its symbol pool. See the
// header.
/**
 * The two characters the password generator leaves out of its symbol pool: a
 * double quote and a backtick.
 */
const GENERATOR_EXCLUDES = '"`';

// The four pools, with `generate-password`'s symbol set so a generated
// password reads as it always did. `GENERATOR_EXCLUDES` comes out of it.
/**
 * The generator's four character pools: lowercase, uppercase, numbers and
 * symbols.
 */
const GENERATOR_POOLS: Record<string, string> = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()+_-=}{[]|:;"/?.><,`~'
};

// THE DRAW, as a static utility (the header). `options` is the package's
// shape: `length`, a boolean per pool, `strict`, `exclude`. A strict draw
// that misses a pool answers '' — which fails every profile — rather than
// drawing again here, so the caller's MAX_DRAWS bounds it. Called once per
// generated password, so it logs like any other function.
/**
 * The password draw, as a static utility.
 */
class PasswordGenerator {
  /**
   * Draws a random password from the pools the options ask for.
   *
   * A strict draw that misses a pool answers '', which fails every profile,
   * rather than drawing again.
   *
   * @param options - `length`, a boolean per pool (`lowercase`, `uppercase`,
   * `numbers`, `symbols`), `strict`, and `exclude`, characters to leave out
   * @returns the password, or '' for a strict draw that missed a pool
   */
  static generate(options: Record<string, unknown>): string {
    log.debug('Entering PasswordGenerator.generate().');
    const exclude = String(options.exclude || '');
    const pools = Object.keys(GENERATOR_POOLS).filter(function (name) {
      return options[name] === true;
    }).map(function (name) {
      return Array.from(GENERATOR_POOLS[name]).filter(function (ch) {
        return exclude.indexOf(ch) < 0;
      }).join('');
    }).filter(function (pool) {
      return pool.length > 0;
    });
    const length = Number(options.length);
    const drawn: string = String(stsCrypto.randomString(pools.join(''),
                                                        length));
    if (options.strict && !pools.every(function (pool: string) {
      return Array.from(drawn).some(function (ch: string) {
        return pool.indexOf(ch) >= 0;
      });
    })) {
      log.debug('Leaving PasswordGenerator.generate(). A pool is missing.');
      return '';
    }
    log.debug('Leaving PasswordGenerator.generate().');
    return drawn;
  }
}

// Drawing stops here rather than looping forever. With the limits below —
// a generated length of at least twice the symbol count plus two — the chance
// of a single draw passing is well above one in ten, so a thousand failures
// in a row is not bad luck, it is a profile this function cannot satisfy, and
// saying so beats a request that never returns.
const MAX_DRAWS = 1000;

// ---------------------------------------------------------------------------
// THE FIELDS. ONE TABLE, AND EVERYTHING ELSE IS READ FROM IT: the schema this
// container publishes, the form on /admin/policies, the request body
// `/admin-api/policies/save` documents, the validation of a save, and the
// parse of an entry. Five readers of one list is the shape that keeps a new
// rule from being added to four of them.
// ---------------------------------------------------------------------------
const FIELDS: PolicyField[] = [
  { key: 'minLength', attribute: 'pwdMinLength', type: 'int',
    dflt: 12, min: 1, max: 1024,
    label: 'Minimum length',
    unit: 'characters',
    what: 'The shortest password this service will set, counted in ' +
          'characters (Unicode code points, so an emoji is one). The ' +
          'attribute is draft-behera-ldap-password-policy\'s. Twelve is the ' +
          'default; NIST SP 800-63B asks for at least 8, and 15 where a ' +
          'password is the only factor.' },
  { key: 'history', attribute: 'pwdInHistory', type: 'int',
    dflt: 5, min: 0, max: 24,
    label: 'Previous passwords that may not be reused',
    unit: 'passwords',
    what: 'How many of a person\'s PREVIOUS passwords are remembered and ' +
          'refused. The current password is always refused as well while ' +
          'this is above 0, so 5 means a new password may be none of the ' +
          'last six. 0 turns the rule off. The draft\'s attribute, with the ' +
          'draft\'s meaning. Each remembered password is kept as the hash it ' +
          'was already stored as (argon2id or scrypt), in pwdHistory on the ' +
          'person\'s own entry, and checking a new password costs one hash ' +
          'comparison per one remembered.' },
  { key: 'minSymbols', attribute: 'stsPwdMinSymbols', type: 'int',
    dflt: 1, min: 0, max: 16,
    label: 'Minimum number of symbols',
    unit: 'symbols',
    what: 'How many characters that are neither a letter, a digit nor ' +
          'whitespace a password must contain. 0 turns the rule off.' },
  { key: 'requireUppercase', attribute: 'stsPwdRequireUppercase', type: 'bool',
    dflt: true,
    label: 'Require an uppercase letter',
    what: 'Whether a password must contain at least one uppercase letter, in ' +
          'any script.' },
  { key: 'requireDigit', attribute: 'stsPwdRequireDigit', type: 'bool',
    dflt: true,
    label: 'Require a number',
    what: 'Whether a password must contain at least one decimal digit.' },
  { key: 'generatedLength', attribute: 'stsPwdGeneratedLength', type: 'int',
    dflt: 20, min: 12, max: 128,
    label: 'Length of a generated password',
    unit: 'characters',
    what: 'How long a password this service MAKES UP is — for a new user ' +
          'created from the console or /admin-api, an operator\'s Generate, ' +
          'and the product-mode bootstrap account. It must be at least the ' +
          'minimum length and at least twice the symbol count plus two. ' +
          'Twenty characters from a 90-character alphabet is about 130 bits.' },
  // -------------------------------------------------------------------------
  // HOW A PASSWORD IS STORED (2026-10-22, #847). The algorithm a NEWLY
  // stored password is hashed with, and both algorithms' parameters. Every
  // bound is OWASP's Password Storage Cheat Sheet minimum or above, in both
  // modes (rcbj's decision 2), and `common/crypto.js` clamps to the same
  // floors whatever this table says. A stored hash names its own algorithm
  // and parameters, so changing these reaches the NEXT password set and, at
  // a person's next verified sign-in, their stored hash (`credentials.ts`'s
  // upgrade). OPTIONAL: a save written before these rows existed keeps them.
  // -------------------------------------------------------------------------
  //
  // THE DEFAULT IS scrypt AT THE PRE-#847 PARAMETERS (rcbj, 2026-10-22,
  // #820), which every stored password already is; argon2id is selectable.
  // OWASP's scrypt pairs are reported, not enforced, until #872 makes
  // OWASP's minimum the default.
  // -------------------------------------------------------------------------
  { key: 'hashAlgorithm', attribute: 'stsPwdHashAlgorithm', type: 'enum',
    dflt: 'scrypt', values: stsCrypto.PASSWORD_HASH_ALGORITHMS.slice(),
    optional: true,
    label: 'Password hash algorithm',
    what: 'The algorithm a newly stored password is hashed with: scrypt ' +
          '(RFC 7914), the default, or argon2id (RFC 9106, the OWASP ' +
          'Password Storage Cheat Sheet\'s first choice). A stored hash ' +
          'names its own algorithm and parameters and keeps verifying; ' +
          'one that is not in this algorithm with these parameters is ' +
          'hashed again at the ' +
          'person\'s next verified sign-in. Client secrets, activation ' +
          'tokens, recovery codes and app passwords are not passwords and ' +
          'stay scrypt.' },
  { key: 'argon2Memory', attribute: 'stsPwdArgon2Memory', type: 'int',
    dflt: stsCrypto.ARGON2_LIMITS.memory.dflt,
    min: stsCrypto.ARGON2_LIMITS.memory.min,
    max: stsCrypto.ARGON2_LIMITS.memory.max, optional: true,
    label: 'argon2id memory',
    unit: 'KiB',
    what: 'The memory one argon2id hash uses, in kibibytes (m). 19456 KiB ' +
          '(19 MiB) is OWASP\'s minimum and the least this service will ' +
          'write. Raising it makes a stolen store slower to attack, and ' +
          'every sign-in uses that much more memory.' },
  { key: 'argon2Iterations', attribute: 'stsPwdArgon2Iterations',
    type: 'int', dflt: stsCrypto.ARGON2_LIMITS.passes.dflt,
    min: stsCrypto.ARGON2_LIMITS.passes.min,
    max: stsCrypto.ARGON2_LIMITS.passes.max, optional: true,
    label: 'argon2id iterations',
    unit: 'passes',
    what: 'How many passes argon2id makes over its memory (t). 2 is ' +
          'OWASP\'s minimum at 19 MiB; each pass adds the same time again.' },
  { key: 'argon2Parallelism', attribute: 'stsPwdArgon2Parallelism',
    type: 'int', dflt: stsCrypto.ARGON2_LIMITS.parallelism.dflt,
    min: stsCrypto.ARGON2_LIMITS.parallelism.min,
    max: stsCrypto.ARGON2_LIMITS.parallelism.max, optional: true,
    label: 'argon2id parallelism',
    unit: 'lanes',
    what: 'How many lanes argon2id divides its memory into (p). It is part ' +
          'of the hash, not a thread count: node computes a hash on one ' +
          'thread whatever this says. 1 is OWASP\'s figure.' },
  { key: 'scryptLogN', attribute: 'stsPwdScryptLogN', type: 'int',
    dflt: stsCrypto.SCRYPT_PASSWORD_LIMITS.logN.dflt,
    min: stsCrypto.SCRYPT_PASSWORD_LIMITS.logN.min,
    max: stsCrypto.SCRYPT_PASSWORD_LIMITS.logN.max, optional: true,
    label: 'scrypt cost (log2 of N)',
    what: 'scrypt\'s CPU and memory cost for a newly stored password while ' +
          'the algorithm is scrypt, as a power of two: 15 (the default) is ' +
          'N=32768. OWASP\'s table pairs it with the parallelism: 2^17 ' +
          'with p=1, 2^16 with p=2, 2^15 with p=3, 2^14 with p=5, or 2^13 ' +
          'with p=10. The default, 2^15 with p=1, is below it.' },
  { key: 'scryptBlockSize', attribute: 'stsPwdScryptBlockSize', type: 'int',
    dflt: stsCrypto.SCRYPT_PASSWORD_LIMITS.r.dflt,
    min: stsCrypto.SCRYPT_PASSWORD_LIMITS.r.min,
    max: stsCrypto.SCRYPT_PASSWORD_LIMITS.r.max, optional: true,
    label: 'scrypt block size (r)',
    what: 'scrypt\'s block size for a newly stored password while the ' +
          'algorithm is scrypt. Memory is about 128 × N × r bytes; 8 is ' +
          'the figure RFC 7914 and OWASP give.' },
  { key: 'scryptParallelism', attribute: 'stsPwdScryptParallelism',
    type: 'int', dflt: stsCrypto.SCRYPT_PASSWORD_LIMITS.p.dflt,
    min: stsCrypto.SCRYPT_PASSWORD_LIMITS.p.min,
    max: stsCrypto.SCRYPT_PASSWORD_LIMITS.p.max, optional: true,
    label: 'scrypt parallelism (p)',
    what: 'scrypt\'s parallelism for a newly stored password while the ' +
          'algorithm is scrypt. Node computes it on one thread, so a higher ' +
          'value costs time rather than cores; the cost\'s description ' +
          'lists the pairs OWASP accepts.' }
];

const FIELD_BY_KEY: Record<string, PolicyField> = {};
FIELDS.forEach(function (field) {
  FIELD_BY_KEY[field.key] = field;
});

const DEFAULTS: Readonly<Record<string, number | boolean | string>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    out[field.key] = field.dflt;
    return out;
  }, {} as Record<string, number | boolean | string>));

// ---------------------------------------------------------------------------
// THE SCHEMA. Published on /admin/policies the way every container's is,
// because this directory is schemaless and a container of entries carrying
// invented attributes has to say what they mean somewhere.
// ---------------------------------------------------------------------------
const SCHEMA = {
  container: 'ou=passwordPolicies',
  objectClasses: [
    { name: 'pwdPolicy',
      what: 'draft-behera-ldap-password-policy\'s class for a password ' +
            'policy entry. `pwdAttribute` names the attribute the policy ' +
            'governs, and here that is always `userPassword`.' },
    { name: 'stsPasswordPolicy',
      what: 'This service\'s own class, carrying the composition rules and ' +
            'the generated length the draft has no attribute for. The entry ' +
            'is named by the PROFILE: `cn=default`, or a named policy\'s ' +
            'name.' }
  ],
  attributes: [
    { name: 'pwdAttribute',
      what: 'The attribute this policy governs: `userPassword`.' }
  ].concat(FIELDS.map(function (field) {
    return { name: field.attribute, what: field.what };
  })).concat(SELECTORS.map(function (one) {
    return { name: one.attribute, what: one.what };
  })).concat([
    { name: 'description',
      what: 'What the profile is for, for the next person.' }
  ]),
  // THE TWO THAT GO ON A PERSON rather than on the policy. Listed here
  // because this module is what gives them their meaning, and in
  // `ldap/ldap_server.js`'s own list because that is where an attribute a
  // person's entry carries is named.
  personAttributes: [
    { name: 'pwdHistory',
      what: 'One value per remembered previous password, in the draft\'s ' +
            'form `time#syntaxOID#length#data` — the data being the hash ' +
            'that password was stored under, never the password. ' +
            'Maintained by this service and refused on an LDAP add or ' +
            'modify, because a history anybody can edit is a history ' +
            'anybody can empty.' },
    { name: 'pwdChangedTime',
      what: 'When the password was last set, as a GeneralizedTime. ' +
            'Maintained by this service.' }
  ]
};

// ---------------------------------------------------------------------------
// THE SENTENCES `describe()` MAKES, as templates (#543 phase 2). One copy:
// `describe()` fills them with `ServerProse.fill()`, and
// `common/server_prose.ts` matches a console answer's sentences against
// them to refill them in the reader's language — so a sentence edited here
// is the one translated, and one edited only in `describe()` cannot exist.
// ---------------------------------------------------------------------------
const SENTENCES: Readonly<Record<string, string>> = Object.freeze({
  minLength: 'at least {{n}} characters',
  minSymbolsOne: 'at least {{n}} symbol (a character that is not a ' +
    'letter, a number or a space)',
  minSymbolsMany: 'at least {{n}} symbols (a character that is not a ' +
    'letter, a number or a space)',
  uppercase: 'an uppercase letter',
  digit: 'a number',
  history: 'not your current password or any of the {{n}} before it'
});

// The syntax OID the draft's pwdHistory form names for the data half: Octet
// String, RFC 4517 section 3.3.25.
const OCTET_STRING_OID = '1.3.6.1.4.1.1466.115.121.1.40';

/**
 * The password policy: what a password here must look like, which of a person's
 * old ones it may not be, and how one is generated.
 *
 * `default` and any number of named policies, each an entry under
 * `ou=passwordPolicies` with built-in defaults for anything absent; an
 * application (`appPasswordPolicy`) and a group (`stsPasswordPolicy`) name
 * the one they are held to (#1236). Enforced in product mode.
 */
class PasswordPolicy {
  /**
   * The profile every realm has: `default`.
   */
  static readonly DEFAULT_PROFILE = DEFAULT_PROFILE;
  /**
   * The built-in value of every field, keyed by field.
   */
  static readonly DEFAULTS = DEFAULTS;
  /**
   * The policy's fields: key, directory attribute, type, default, bounds, label
   * and description. Every other table here is read from it.
   */
  static readonly FIELDS = FIELDS;
  /**
   * The fields, keyed by `key`.
   */
  static readonly FIELD_BY_KEY = FIELD_BY_KEY;
  /**
   * The schema `/admin/policies` publishes for the container: its object
   * classes, its attributes and the two a person's entry carries.
   */
  static readonly SCHEMA = SCHEMA;
  /**
   * The sentences `describe()` makes, as templates (#543).
   */
  static readonly SENTENCES = SENTENCES;
  /**
   * The syntax OID `pwdHistory`'s data half is named by: Octet String.
   */
  static readonly OCTET_STRING_OID = OCTET_STRING_OID;
  /**
   * What a named policy carries beside its rows: its precedence (#1236).
   */
  static readonly SELECTORS = SELECTORS;
  /**
   * The attributes naming a password policy: `appPasswordPolicy` on an
   * application, `stsPasswordPolicy` on a group (#1236).
   */
  static readonly REFERENCES = REFERENCES;

  // -------------------------------------------------------------------------
  // THE SLOT.
  // -------------------------------------------------------------------------
  private directory: DirectoryHooks | null = null;
  private warnedAboutNoDirectory = false;

  /**
   * Creates the password policy.
   *
   * @param deps - its dependencies: the logger, mode, the generator and the
   * error-code table
   */
  constructor(private readonly deps: PasswordPolicyDeps) {
    deps.log.debug("Entering PasswordPolicy.constructor().");
    deps.log.debug("Leaving PasswordPolicy.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the dependencies
   */
  static defaultDeps(): PasswordPolicyDeps {
    log.debug("Entering PasswordPolicy.defaultDeps().");
    log.debug("Leaving PasswordPolicy.defaultDeps().");
    return {
      log: log,
      mode: mode,
      generator: PasswordGenerator,
      errorCodes: errorCodes
    };
  }

  /**
   * Fills the directory slot the profile is read and written through; the
   * directory fills it.
   *
   * @param hooks - the directory's hooks, or null to empty the slot
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug('Entering PasswordPolicy.setDirectory().');
    this.directory = hooks || null;
    log.debug('Leaving PasswordPolicy.setDirectory(). The password policy ' +
              'register ' +
              (this.directory ? 'has its container.' : 'has none.'));
  }

  /**
   * Returns the directory hooks now installed.
   *
   * @returns the hooks, or null
   */
  directoryInstalled(): DirectoryHooks | null {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.directoryInstalled().");
    log.debug("Leaving PasswordPolicy.directoryInstalled().");
    return this.directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.haveDirectory().");
    if (this.directory &&
        typeof this.directory.allPasswordPolicies === 'function') {
      log.debug("Leaving PasswordPolicy.haveDirectory().");
      return true;
    }
    if (!this.warnedAboutNoDirectory) {
      this.warnedAboutNoDirectory = true;
      log.warn('password_policy: the embedded directory was never loaded, ' +
               'so there is no ou=passwordPolicies. The BUILT-IN default ' +
               'profile is in force and cannot be edited in this process — ' +
               'which is the policy an unedited service has anyway, so ' +
               'nothing is weaker than it would be.');
    }
    log.debug("Leaving PasswordPolicy.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  private firstValue(attributes: Record<string, unknown>,
                     name: string): unknown {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.firstValue().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving PasswordPolicy.firstValue().");
    return Array.isArray(found) ? (found[0] === undefined ? '' : found[0])
      : (found === undefined || found === null ? '' : found);
  }

  // One field's value out of whatever an entry or a request body carried.
  // Answers `{ value }` or `{ problem }`, never throws, and never guesses: an
  // integer with a fraction or a boolean spelt `yes` is a problem, because the
  // value will be compared against a password and a policy that read `12.5`
  // as 12 is a policy nobody wrote.
  private parseField(field: PolicyField,
                     raw: unknown): { value?: number | boolean | string;
                                      problem?: string } {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.parseField().");
    const text = String(raw === undefined || raw === null ? '' : raw).trim();
    if (field.type === 'enum') {
      const values = field.values || [];
      if (values.indexOf(text) < 0) {
        log.debug("Leaving PasswordPolicy.parseField().");
        return { problem: field.label + ' must be one of ' +
                          values.join(', ') + '; "' + text.slice(0, 40) +
                          '" is not.' };
      }
      log.debug("Leaving PasswordPolicy.parseField().");
      return { value: text };
    }
    if (field.type === 'bool') {
      const lower = text.toLowerCase();
      // LDAP's Boolean syntax is TRUE and FALSE (RFC 4517 section 3.3.3); a
      // form posts `on` for a ticked checkbox and nothing for an unticked
      // one, and a JSON body sends true and false. All three spellings are
      // one question.
      if (['true', 'on', '1'].indexOf(lower) >= 0) {
        log.debug("Leaving PasswordPolicy.parseField().");
        return { value: true };
      }
      if (['false', 'off', '0', ''].indexOf(lower) >= 0) {
        log.debug("Leaving PasswordPolicy.parseField().");
        return { value: false };
      }
      log.debug("Leaving PasswordPolicy.parseField().");
      return { problem: field.label + ' is a yes-or-no setting, and "' +
                        text.slice(0, 40) + '" is neither.' };
    }
    if (!/^\d+$/.test(text)) {
      log.debug("Leaving PasswordPolicy.parseField().");
      return { problem: field.label + ' must be a whole number between ' +
                        field.min + ' and ' + field.max + '; "' +
                        text.slice(0, 40) + '" is not one.' };
    }
    const value = Number(text);
    if (value < field.min || value > field.max) {
      log.debug("Leaving PasswordPolicy.parseField().");
      return { problem: field.label + ' must be between ' + field.min +
                        ' and ' + field.max + '; ' + value + ' is not.' };
    }
    log.debug("Leaving PasswordPolicy.parseField().");
    return { value: value };
  }

  // The rules that relate two fields, which no one field can check.
  private crossFieldProblems(values: Record<string, any>): string[] {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.crossFieldProblems().");
    const out: string[] = [];
    if (values.generatedLength < values.minLength) {
      out.push('A generated password would be ' + values.generatedLength +
               ' characters, which is shorter than the minimum length of ' +
               values.minLength + ' — this service would make up passwords ' +
               'its own policy refuses. Raise the generated length to at ' +
               'least ' + values.minLength + '.');
    }
    if (values.generatedLength < values.minSymbols * 2 + 2) {
      out.push('A generated password of ' + values.generatedLength +
               ' characters cannot reliably carry ' + values.minSymbols +
               ' symbols; it must be at least ' + (values.minSymbols * 2 + 2) +
               ' (twice the symbol count plus two).');
    }
    // OWASP's scrypt table (#847): the parallelism a cost needs. Asked
    // whichever algorithm is chosen, because the values are stored either
    // way and switching to scrypt must not switch to a pair below it.
    // NOT ENFORCED SINCE 2026-10-22 (rcbj, #820): the default itself,
    // 2^15 with p=1, is below the table, and a policy must be able to save
    // its own default. #872, which makes OWASP's minimum the default,
    // brings this check back.
    log.debug("Leaving PasswordPolicy.crossFieldProblems().");
    return out;
  }

  private entryFor(name: unknown) {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.entryFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving PasswordPolicy.entryFor().");
      return null;
    }
    const wanted = String(name).toLowerCase();
    log.debug("Leaving PasswordPolicy.entryFor().");
    return this.directory.allPasswordPolicies().filter(function (entry) {
      return String(entry.name || '').toLowerCase() === wanted;
    })[0] || null;
  }

  // THE PROFILE IN FORCE. Always answers — a stored entry parsed field by
  // field, with the built-in default standing in for any value that is absent
  // or unreadable, and a `problems` list naming each one that was.
  //
  // An unreadable value falls back to the DEFAULT rather than to "no rule",
  // which is the direction that matters: somebody who `ldapmodify`s
  // `pwdMinLength: twelve` has broken one attribute, and the answer to that
  // must not be a policy with no minimum length.
  /**
   * Reads the profile in force: the stored entry field by field, with the
   * built-in default for any value absent or unreadable.
   *
   * @param name - the profile; `default` when absent
   * @returns the profile's values, where each came from, and a `problems` list
   * naming each unreadable value
   */
  read(name?: string): PasswordProfile {
    const { log, mode } = this.deps;
    log.debug('Entering PasswordPolicy.read(). name=' + name);
    const profile = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    const entry = this.entryFor(profile);
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
        sources[field.key] = 'directory';
      });
      this.crossFieldProblems(values).forEach(function (problem) {
        problems.push(problem);
      });
    }
    const out = Object.assign({
      name: profile,
      stored: !!entry,
      dn: entry ? entry.dn : '',
      description: entry ? String(this.firstValue(entry.attributes || {},
                                                  'description')) : '',
      sources: sources,
      problems: problems,
      enforced: mode.verifiesCredentials()
    }, values) as PasswordProfile;
    // A NAMED POLICY'S PRECEDENCE (#1236), as the ranking reads it; `default`
    // ranks under nothing and carries none.
    if (profile.toLowerCase() !== DEFAULT_PROFILE) {
      out.precedence = entry
        ? PolicySelection.precedenceOf(entry.attributes || {}, SELECTION)
        : SELECTION.defaultPrecedence;
    }
    log.debug('Leaving PasswordPolicy.read(). ' +
              (entry ? 'Stored.' : 'Built-in defaults.'));
    return out;
  }

  // THE PROFILE THAT APPLIES TO A PASSWORD (#1236): the function existed
  // with a username it ignored so that assigning profiles would change this
  // body and no caller, and that is what happened. Every door already hands
  // in the person; the sign-in's forced change hands in the application too.
  /**
   * Returns the profile that applies to a person's password: of the policy
   * the application names (`appPasswordPolicy`) and the policies the
   * person's groups name (`stsPasswordPolicy`), the lowest precedence (ties
   * by name), else `default`. A reference to a policy this realm does not
   * hold makes the answer `default` (STS-AUTHN-0539).
   *
   * @param username - the person, or nothing: then `default`, unless an
   *   application names a policy
   * @param application - the application (a client_id or its identifier),
   *   where one is known
   * @returns the profile
   */
  profileFor(username?: unknown, application?: unknown): PasswordProfile {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.profileFor().");
    const name = this.selectionFor(username, application);
    log.debug("Leaving PasswordPolicy.profileFor(). " + name);
    return this.read(name);
  }

  /**
   * Works out which profile's name applies to a person and an application,
   * without reading it: `profileFor()`'s ranking.
   *
   * @param username - the person, or nothing
   * @param application - the application, or nothing
   * @returns the profile's name
   */
  selectionFor(username?: unknown, application?: unknown): string {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PasswordPolicy.selectionFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving PasswordPolicy.selectionFor(). No directory.");
      return DEFAULT_PROFILE;
    }
    const entries = this.directory.allPasswordPolicies();
    // NO NAMED POLICY, NOTHING TO RANK: the common case costs no group
    // lookup at all.
    if (!PolicySelection.named(entries, SELECTION).length) {
      log.debug("Leaving PasswordPolicy.selectionFor(). None named.");
      return DEFAULT_PROFILE;
    }
    const who = String(username === undefined || username === null ? ''
      : username).trim();
    const hook = this.directory.personGroupReferences;
    const groups = who && typeof hook === 'function'
      ? (hook.call(this.directory, who, REFERENCES.group) || []) : [];
    const references: Array<{ by: string; holder?: string;
                              value: unknown }> = [
      { by: 'application', holder: String(application || ''),
        value: this.applicationReference(application) }
    ];
    const ranked = PolicySelection.rank(entries, SELECTION, references
      .concat(PolicySelection.groupReferences(groups)));
    if (ranked.missing.length) {
      // FAIL CLOSED TO `default` (the header): the whole answer, whatever
      // else ranked. Said once per broken reference in this process.
      ranked.missing.forEach(function (one) {
        const key = one.by + '\u0000' + one.holder + '\u0000' + one.name;
        if (MISSING_SAID.has(key)) {
          return;
        }
        if (MISSING_SAID.size >= MISSING_SAID_MAX) {
          MISSING_SAID.clear();
        }
        MISSING_SAID.add(key);
        log.warn(errorCodes.tag('STS-AUTHN-0539') + 'password policy: the ' +
                 one.by + ' "' + one.holder + '" names the password ' +
                 'policy "' + one.name + '", which this realm does not ' +
                 'hold, so the default password policy applies to every ' +
                 'password it reaches until the policy exists or the ' +
                 'reference changes.');
      });
      log.debug("Leaving PasswordPolicy.selectionFor(). A reference is " +
                "missing; default.");
      return DEFAULT_PROFILE;
    }
    log.debug("Leaving PasswordPolicy.selectionFor(). " + ranked.name +
              " (" + ranked.by + ").");
    return ranked.name;
  }

  // THE PROFILE AN APPLICATION NAMES (#1236): its `appPasswordPolicy`, found
  // by what a sign-in names it by — a client_id, else its identifier. The
  // registry is required LAZILY: it is loaded after this leaf, and a require
  // at load would close a cycle. '' where nothing is named or nothing can be
  // asked — the passkey policy's `applicationReference()`.
  private applicationReference(application: unknown): string {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.applicationReference().");
    const name = String(application === undefined || application === null
      ? '' : application).trim();
    if (!name) {
      log.debug("Leaving PasswordPolicy.applicationReference(). None.");
      return '';
    }
    let out = '';
    try {
      const applications = require('./applications');
      const row = applications.forClientId(name) || applications.get(name);
      out = String([].concat(((row && row.fields) || {})[
        REFERENCES.application] || [])[0] || '');
    } catch (e) {
      log.debug("Caught in PasswordPolicy.applicationReference(): " +
                ((e && e.message) || e));
      out = '';
    }
    log.debug("Leaving PasswordPolicy.applicationReference(). " +
              (out || 'none'));
    return out;
  }

  /**
   * What names a named policy (#1236): the applications (the application
   * listing's index, lazily) and the groups (the directory's group index) —
   * what refuses its delete and what its Named policies entry lists.
   *
   * @param name - the policy's name
   * @returns `{ applications, groups, people }`; nobody names a password
   *   policy from their own entry
   */
  namedBy(name: unknown): { applications: string[]; groups: string[];
                            people: string[] } {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.namedBy().");
    let applications: string[] = [];
    try {
      applications = require('./applications')
        .applicationsNamingPolicy(REFERENCES.application, name);
    } catch (e) {
      log.debug("Caught in PasswordPolicy.namedBy(): " +
                ((e && e.message) || e));
      applications = [];
    }
    const hook = this.haveDirectory() ? this.directory.groupsNamingPolicy
      : null;
    const groups = typeof hook === 'function'
      ? (hook.call(this.directory, REFERENCES.group, name) || []) : [];
    log.debug("Leaving PasswordPolicy.namedBy(). " + applications.length +
              " application(s), " + groups.length + " group(s).");
    return { applications: applications, groups: groups, people: [] };
  }

  // Every profile: `default` first, then this realm's named policies in
  // precedence order (ties by name). Paged by the caller like every list
  // this console draws.
  /**
   * Lists every profile: `default`, then the named policies by precedence.
   *
   * @returns the profiles
   */
  list(): PasswordProfile[] {
    const { log } = this.deps;
    log.debug('Entering PasswordPolicy.list().');
    const named = this.haveDirectory()
      ? PolicySelection.named(this.directory.allPasswordPolicies(),
                              SELECTION) : [];
    const rows = [this.read(DEFAULT_PROFILE)].concat(named.map((one) => {
      return this.read(one.name);
    }));
    log.debug('Leaving PasswordPolicy.list(). ' + rows.length +
              ' profile(s).');
    return rows;
  }

  // -------------------------------------------------------------------------
  // WRITING.
  // -------------------------------------------------------------------------

  // `default` or a named policy's name (#1236): lower-case letters, digits
  // and hyphens, which is what a cn here may be. Until #1236 only `default`
  // was accepted, because nothing ASSIGNED a second profile to anybody; an
  // application's and a group's reference now do.
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.checkProfileName().");
    const out = PolicySelection.nameProblem(
      name === undefined || name === null || name === '' ? DEFAULT_PROFILE
        : name, NOUN, true);
    log.debug("Leaving PasswordPolicy.checkProfileName().");
    return out;
  }

  // A save carries EVERY field. A field left out is a problem rather than a
  // default, because the entry is REPLACED and a save that silently reset the
  // three fields a caller did not mention would be the one mistake here that
  // is invisible and loosens the policy.
  /**
   * Checks a save's body: every field is required, since a save replaces the
   * whole profile.
   *
   * On the console's own form an absent boolean means false.
   *
   * @param given - the posted fields
   * @param name - the profile being saved, whose stored value an optional
   *   row left out keeps; `default` when absent
   * @returns `{ values, problems }`
   */
  validate(given?: Record<string, any> | null, name?: unknown) {
    const { log } = this.deps;
    log.debug('Entering PasswordPolicy.validate().');
    // THE PROFILE BEING SAVED (#1236): an optional row left out keeps ITS
    // value in force, not `default`'s.
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    const body = given || {};
    const values: Record<string, number | boolean | string> = {};
    const problems: string[] = [];
    let inForce: PasswordProfile | null = null;
    FIELDS.forEach((field) => {
      let raw = body[field.key];
      if (raw === undefined && field.type === 'bool' &&
          body.form === 'console') {
        // AN UNTICKED CHECKBOX POSTS NOTHING, so on the console's own form an
        // absent boolean IS the answer "no". Only there — an API caller that
        // left one out gets told, for the reason above.
        raw = 'false';
      }
      if (raw === undefined && field.optional) {
        // LEFT OUT, THE VALUE IN FORCE STAYS (#847) — the stored one, or the
        // built-in default — so a save cannot lower a hash cost it did not
        // mention, which is the "every field is sent" rule's own reason.
        inForce = inForce || this.read(which);
        values[field.key] = inForce[field.key];
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
    if (!problems.length) {
      this.crossFieldProblems(values).forEach(function (problem) {
        problems.push(problem);
      });
    }
    log.debug('Leaving PasswordPolicy.validate(). ' + problems.length +
              ' problem(s).');
    return { values: values, problems: problems };
  }

  /**
   * Replaces a profile's entry with the values given: `default`, or a named
   * policy, which its first save creates.
   *
   * @param name - the profile: `default` or a name of lower-case letters,
   *   digits and hyphens (STS-AUTHN-0107)
   * @param given - every field, optionally `description`, and for a named
   *   policy `precedence` (1 to 1000, 100 when left out)
   * @returns `{ ok, profile }`, or `{ ok: false, errors }` marked with its
   * error code
   */
  save(name: unknown, given?: Record<string, any> | null): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering PasswordPolicy.save(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving PasswordPolicy.save(). Not a profile that can ' +
                'exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0107');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    const checked = this.validate(given, which);
    // A NAMED POLICY'S PRECEDENCE (#1236), refused with the rows.
    const selectors = which === DEFAULT_PROFILE ? null
      : PolicySelection.checkPrecedence(given || {}, SELECTION);
    if (selectors) {
      selectors.problems.forEach(function (one) {
        checked.problems.push(one);
      });
    }
    if (checked.problems.length) {
      log.debug('Leaving PasswordPolicy.save(). The values were refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-AUTHN-0108');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving PasswordPolicy.save(). No directory.');
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep a password policy. ' +
                        'ou=passwordPolicies IS the register.'] },
                             'STS-AUTHN-0109');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'pwdPolicy', 'stsPasswordPolicy'],
      pwdAttribute: 'userPassword',
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
      attributes[SELECTION.precedenceAttribute] = String(selectors.precedence);
    }
    const written = this.directory.writePasswordPolicy(which, attributes);
    if (!written) {
      log.debug('Leaving PasswordPolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-AUTHN-0110');
    }
    log.debug('Leaving PasswordPolicy.save(). Stored.');
    return { ok: true, profile: this.read(which) };
  }

  // Deleting the entry, which puts the BUILT-IN defaults back in force. It is
  // the one way to say "whatever this release thinks is reasonable" rather
  // than writing today's numbers down and keeping them forever. A NAMED
  // policy is removed whole (#1236), and not while anything names it.
  /**
   * Deletes a stored profile: `default`'s puts the built-in defaults back in
   * force; a named policy is removed, refused while an application or a
   * group names it (STS-AUTHN-0540).
   *
   * @param name - the profile
   * @returns `{ ok, removed, profile }`, or `{ ok: false, errors }`
   */
  reset(name: unknown): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering PasswordPolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving PasswordPolicy.reset(). Not a profile that can ' +
                'exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-AUTHN-0107');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    if (!this.haveDirectory()) {
      log.debug('Leaving PasswordPolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(which) };
    }
    // NOT WHILE AN APPLICATION OR A GROUP NAMES IT (#1236): it would be
    // left naming a policy the realm does not hold, which fails closed to
    // `default` — a loosening nobody asked for, made by a delete.
    const held = which === DEFAULT_PROFILE ? null
      : PolicySelection.deleteProblem(NOUN, which, this.namedBy(which));
    if (held) {
      log.debug('Leaving PasswordPolicy.reset(). Still named.');
      return errorCodes.mark({ ok: false, errors: [held] },
                             'STS-AUTHN-0540');
    }
    const removed = !!this.directory.deletePasswordPolicy(which);
    log.debug('Leaving PasswordPolicy.reset(). ' +
              (removed ? 'Removed.' : 'Nothing stored.'));
    return { ok: true, removed: removed,
             profile: this.read(which === DEFAULT_PROFILE ? which
                                                          : DEFAULT_PROFILE) };
  }

  // -------------------------------------------------------------------------
  // CHECKING A PASSWORD.
  // -------------------------------------------------------------------------
  private countMatching(password: string, pattern: RegExp): number {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.countMatching().");
    log.debug("Leaving PasswordPolicy.countMatching().");
    return Array.from(password).filter(function (ch) {
      return pattern.test(ch);
    }).length;
  }

  // What is wrong with this password under this profile — every rule it
  // breaks, not the first, so that a person fixes it once. INDEPENDENT OF THE
  // MODE: whether to ASK is the caller's decision (`credentials.ts` asks in
  // product mode), and the generator below asks in both.
  //
  // The character classes are Unicode's rather than ASCII's. A person whose
  // password is in Greek has uppercase letters, and a rule that only saw A to
  // Z would refuse them for not having what they plainly have.
  /**
   * Lists every rule a password breaks under a profile, whatever the mode; the
   * history rule is the caller's.
   *
   * Character classes are Unicode's rather than ASCII's.
   *
   * @param password - the password
   * @param profile - the profile; the default one when absent
   * @returns a phrase per broken rule, empty when it passes
   */
  problemsWith(password: unknown, profile?: PasswordProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.problemsWith().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const text = String(password === undefined || password === null ? '' :
                        password);
    const out: string[] = [];
    const length = Array.from(text).length;
    if (length < rules.minLength) {
      out.push('at least ' + rules.minLength + ' characters (it has ' +
               length + ')');
    }
    if (rules.minSymbols > 0) {
      const symbols = this.countMatching(text, /[^\p{L}\p{N}\s]/u);
      if (symbols < rules.minSymbols) {
        out.push('at least ' + rules.minSymbols + ' symbol' +
                 (rules.minSymbols === 1 ? '' : 's') + ' (it has ' + symbols +
                 ')');
      }
    }
    if (rules.requireUppercase && this.countMatching(text, /\p{Lu}/u) === 0) {
      out.push('an uppercase letter');
    }
    if (rules.requireDigit && this.countMatching(text, /\p{Nd}/u) === 0) {
      out.push('a number');
    }
    log.debug("Leaving PasswordPolicy.problemsWith().");
    return out;
  }

  // The rules as a person reads them, for the forms that ask for a password.
  /**
   * Describes a profile's rules as a person reads them, for the forms that ask
   * for a password.
   *
   * @param profile - the profile; the default one when absent
   * @returns a phrase per rule
   */
  describe(profile?: PasswordProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.describe().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const fill = serverProse.fill;
    const out = [fill(SENTENCES.minLength, { n: rules.minLength })];
    if (rules.minSymbols > 0) {
      out.push(fill(rules.minSymbols === 1 ? SENTENCES.minSymbolsOne
                                           : SENTENCES.minSymbolsMany,
                    { n: rules.minSymbols }));
    }
    if (rules.requireUppercase) {
      out.push(SENTENCES.uppercase);
    }
    if (rules.requireDigit) {
      out.push(SENTENCES.digit);
    }
    if (rules.history > 0) {
      out.push(fill(SENTENCES.history, { n: rules.history }));
    }
    log.debug("Leaving PasswordPolicy.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE HISTORY'S STORED FORM. Built and read here, because this is the
  // module that gives the draft's format its meaning; `ldap_server.js` stores
  // strings and `credentials.ts` decides what goes in them.
  // -------------------------------------------------------------------------
  /**
   * Spells a time as GeneralizedTime, without fractional seconds.
   *
   * @param when - the time; now when absent
   * @returns the timestamp
   */
  generalizedTime(when?: Date | number | string | null): string {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.generalizedTime().");
    const d = when instanceof Date ? when : new Date(when || Date.now());
    log.debug("Leaving PasswordPolicy.generalizedTime().");
    return d.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z');
  }

  /**
   * Builds one `pwdHistory` value in the draft's form,
   * `time#syntaxOID#length#data`, the data being the password's stored hash.
   *
   * @param hash - the hash the password was stored under (argon2id or scrypt)
   * @param when - when it was set; now when absent
   * @returns the value
   */
  historyValue(hash: unknown, when?: Date | number | string | null): string {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.historyValue().");
    const data = String(hash);
    log.debug("Leaving PasswordPolicy.historyValue().");
    return this.generalizedTime(when) + '#' + OCTET_STRING_OID + '#' +
           Buffer.byteLength(data, 'utf8') + '#' + data;
  }

  // The hash out of one stored value, or '' for one that is not in the form.
  // The DATA may itself contain `#`, so it is everything after the THIRD one.
  /**
   * Extracts the hash from one stored `pwdHistory` value.
   *
   * @param value - the stored value
   * @returns the hash, or '' for a value not in the form
   */
  hashOfHistoryValue(value: unknown): string {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.hashOfHistoryValue().");
    const text = String(value || '');
    const parts = text.split('#');
    if (parts.length < 4) {
      log.debug("Leaving PasswordPolicy.hashOfHistoryValue().");
      return '';
    }
    log.debug("Leaving PasswordPolicy.hashOfHistoryValue().");
    return parts.slice(3).join('#');
  }

  // -------------------------------------------------------------------------
  // MAKING ONE UP.
  // -------------------------------------------------------------------------
  /**
   * Makes up a password that satisfies a profile, drawing until one does.
   *
   * @param profile - the profile; the default one when absent
   * @returns the password
   * @throws Error (STS-AUTHN-0111) when 1000 draws produce none, which only a
   * hand-edited profile can cause
   */
  generate(profile?: PasswordProfile | null): string {
    const { log, generator, errorCodes } = this.deps;
    log.debug('Entering PasswordPolicy.generate().');
    const rules = profile || this.read(DEFAULT_PROFILE);
    const length = Math.max(rules.generatedLength, rules.minLength,
                            rules.minSymbols * 2 + 2);
    for (let draw = 1; draw <= MAX_DRAWS; draw++) {
      const candidate = generator.generate({
        length: length,
        lowercase: true,
        uppercase: true,
        numbers: true,
        symbols: true,
        strict: true,
        exclude: GENERATOR_EXCLUDES
      });
      if (this.problemsWith(candidate, rules).length === 0) {
        log.debug('Leaving PasswordPolicy.generate(). Drew a passing ' +
                  'password on draw ' + draw + '.');
        return candidate;
      }
    }
    // Unreachable with the limits `crossFieldProblems()` enforces on a save;
    // reachable only through a hand-edited entry, which `read()` has already
    // reported. Thrown rather than answered with a weaker password, because
    // the alternative is this service handing out a credential its own policy
    // refuses.
    log.error(errorCodes.tag('STS-AUTHN-0111') +
              'password_policy: ' + MAX_DRAWS + ' draws of ' + length +
              ' characters produced no password satisfying the profile. The ' +
              'profile cannot be satisfied by a generated password.');
    log.debug('Leaving PasswordPolicy.generate(). Gave up.');
    throw errorCodes.mark(new Error('No generated password of ' + length +
                    ' characters satisfied the password policy ' +
                    'in ' + MAX_DRAWS + ' draws. ' +
                    'Raise the generated length or lower the symbol count ' +
                    'on /admin/policies.'), 'STS-AUTHN-0111');
  }

  // -------------------------------------------------------------------------
  // HOW A NEW PASSWORD IS STORED (#847): the profile's algorithm and its
  // parameters, in the shape `crypto.hashPassword()` takes. NOT mode
  // dependent: the floors are OWASP's in both modes, and `crypto.js` clamps
  // to them again.
  // -------------------------------------------------------------------------
  /**
   * Returns the hash spec a profile names for a newly stored password.
   *
   * @param profile - the profile; the default one when absent
   * @returns `{ algorithm, memory, passes, parallelism }` or
   *   `{ algorithm: 'scrypt', logN, r, p }`, clamped by `crypto.js`
   */
  hashSpec(profile?: PasswordProfile | null): Record<string, any> {
    const { log } = this.deps;
    log.debug("Entering PasswordPolicy.hashSpec().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const spec = rules.hashAlgorithm === 'scrypt'
      ? { algorithm: 'scrypt', logN: rules.scryptLogN,
          r: rules.scryptBlockSize, p: rules.scryptParallelism }
      : { algorithm: 'argon2id', memory: rules.argon2Memory,
          passes: rules.argon2Iterations,
          parallelism: rules.argon2Parallelism };
    log.debug("Leaving PasswordPolicy.hashSpec(). " + spec.algorithm);
    return stsCrypto.passwordHashSpec(spec);
  }

  // Whether the profile is ENFORCED in this process — `mode.js`'s answer.
  /**
   * Tells whether the profile is enforced in this process:
   * `mode.verifiesCredentials()`.
   *
   * @returns true in product mode
   */
  enforced(): boolean {
    const { log, mode } = this.deps;
    log.debug("Entering PasswordPolicy.enforced().");
    log.debug("Leaving PasswordPolicy.enforced().");
    return mode.verifiesCredentials();
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module finishes loading (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PasswordPolicy>(
  'common/password_policy',
  () => new PasswordPolicy(PasswordPolicy.defaultDeps()),
  null,
  log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

// A GROUP NAMES ITS PASSWORD POLICY (#1236): declared, so the group page
// draws its picker and the directory's group writer checks it, offering
// `default` and the realm's named policies as they stand when asked.
PolicySelection.declareReference('group', REFERENCES.group, NOUN,
  function () {
    log.debug("Entering password policy reference choices.");
    const names = slot.get().list().map(function (one) {
      return String(one.name);
    });
    log.debug("Leaving password policy reference choices.");
    return names;
  });

/**
 * The password policy: composition rules, the history of previous passwords,
 * and the generator.
 *
 * Exports the classes, the constants and facades forwarding to the instance the
 * composition root built.
 *
 * @namespace
 */
export = {
  PasswordPolicy: PasswordPolicy,
  // The draw itself, for `tests/random_values.js`'s distribution check.
  PasswordGenerator: PasswordGenerator,
  GENERATOR_POOLS: GENERATOR_POOLS,
  GENERATOR_EXCLUDES: GENERATOR_EXCLUDES,
  installInstance: (instance: PasswordPolicy): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  DEFAULT_PROFILE: PasswordPolicy.DEFAULT_PROFILE,
  DEFAULTS: PasswordPolicy.DEFAULTS,
  FIELDS: PasswordPolicy.FIELDS,
  FIELD_BY_KEY: PasswordPolicy.FIELD_BY_KEY,
  SCHEMA: PasswordPolicy.SCHEMA,
  SENTENCES: PasswordPolicy.SENTENCES,
  OCTET_STRING_OID: PasswordPolicy.OCTET_STRING_OID,
  SELECTORS: PasswordPolicy.SELECTORS,
  REFERENCES: PasswordPolicy.REFERENCES,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileFor: slot.forward('profileFor'),
  selectionFor: slot.forward('selectionFor'),
  namedBy: slot.forward('namedBy'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  problemsWith: slot.forward('problemsWith'),
  describe: slot.forward('describe'),
  generate: slot.forward('generate'),
  hashSpec: slot.forward('hashSpec'),
  historyValue: slot.forward('historyValue'),
  hashOfHistoryValue: slot.forward('hashOfHistoryValue'),
  generalizedTime: slot.forward('generalizedTime'),
  enforced: slot.forward('enforced')
};
