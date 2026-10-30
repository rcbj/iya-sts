// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: locale_policy.ts
//
// ---------------------------------------------------------------------------
// THE LOCALE POLICY (#539, 2026-10-09): A REALM'S DEFAULT LANGUAGE, AND THE
// APPLICATIONS THAT HAVE ANOTHER.
//
// rcbj: "add a policy default per realm that automatically populates user
// locale parameter", and then "Let's be able to create multiple locale
// policies per realm an assign them to application objects." It is the fifth
// kind on Directory → Policies (`admin-core/policy_kinds.ts`), on
// `passkey_policy.ts`'s pattern — `cn=default` inherited from the default
// realm, named profiles a realm's own (#535's arrangement) — with two rows:
//
//   defaultLocale            `en`. The LAST step of a page's language
//                            (`common/page_locale.ts`): what a page is drawn
//                            in when `ui_locales`, the person's
//                            `preferredLanguage`, the language chooser and
//                            `Accept-Language` say nothing a catalog
//                            answers. Any well-formed BCP 47 tag (RFC 5646);
//                            one no catalog answers is kept — it still
//                            decides how dates and numbers are formatted —
//                            and the page says so. It is also the language a
//                            message is MAILED in to a person whose entry
//                            names none: it REPLACES `mail.defaultLanguage`
//                            (retired, no shim; `REPLACED_SETTINGS`), so the
//                            pages and the mail have one default.
//   populatePreferredLanguage  ON. A person entry CREATED without a
//                            `preferredLanguage` (RFC 2798 section 2.7) is
//                            given `defaultLocale` as one, at the one place
//                            every person entry is written
//                            (`ldap/ldap_server.js`). Existing entries are
//                            never rewritten: one with no value falls
//                            through to the same default when a page is
//                            drawn, so nothing a reader sees differs.
//
// ---------------------------------------------------------------------------
// NAMED PROFILES, AND WHAT NAMES THEM (#1238, rule 3cx; until then #539's
// lookup by application).
//
// Beside `cn=default` a realm may keep profiles of its own (`cn=<name>`,
// lower-case letters, digits and hyphens), each with the two rows and a
// PRECEDENCE (`stsLocalePrecedence`, 1 to 1000). A profile lists nothing:
// what it covers NAMES it (rcbj's decisions on #1234) —
//
//   * an application, in `appLocalePolicy` (`common/applications.js`);
//   * a group, in `stsLocalePolicy` (the group page's picker).
//
// Nobody names a locale profile from their own entry: a person's own
// language is `preferredLanguage`, which outranks every profile anyway.
// The candidates are the profile the application names and the profile each
// of the person's groups names; the LOWEST PRECEDENCE WINS, ties by name, and
// `default` applies where nothing names one (`common/policy_selection.ts`).
// `stsLocaleSelectApplication` and its one-profile-per-application refusal
// (STS-I18N-0007, retired) went with #1238, and no migration is owed.
//
// THE SELECTION IS AN ARGUMENT (`forApplication(application, person)`), not
// #535's ambient `select()`: every caller — a sign-in page, the consent
// screen, sign-out, SCIM's create, a static surface's shell — already holds
// the application it is drawing for, and the PERSON WHERE ONE IS KNOWN. A
// page drawn before anybody is known is chosen by its application alone.
//
// A REFERENCE TO A PROFILE THE REALM DOES NOT HOLD (written past the console,
// which checks every reference at the write) SELECTS NOTHING and is logged
// (STS-I18N-0013); where nothing else names a profile, `default` applies.
// This kind does NOT fail closed, where the authentication policy does
// (#1148): it decides only which language a page and a mail fall back to,
// and refusing to draw a page over that would guard nothing. A named profile
// something names is not deleted (STS-I18N-0014).
//
// Named profiles are NOT inherited across realms; only `default` follows the
// default realm's.
//
// IT IS A LIBRARY (rule 3) AND A LEAF: `helpers`, `realms`, `error_codes`,
// `i18n` (a leaf), `policy_selection` (a leaf), the instance slot, and the
// directory through a slot `ldap/ldap_server.js` fills; the application
// registry is reached LAZILY, as `passkey_policy.ts` reaches it. In force
// in both modes: it decides only what language a reader sees.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import i18n = require('./i18n');
import InstanceSlot = require('./instance_slot');
import PolicySelection = require('./policy_selection');
// The sentences `describe()` makes are filled from SENTENCES below, so the
// server can translate them into a console reader's language (#543).
import serverProse = require('./server_prose');

const { log } = helpers;

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'bool' | 'locale';
  dflt: boolean | string;
  label: string;
  what: string;
}

interface DirectoryHooks {
  allLocalePolicies?(): { name?: string; dn: string;
                          attributes?: Record<string, unknown> }[];
  writeLocalePolicy?(name: string,
                     attributes: Record<string, unknown>): unknown;
  deleteLocalePolicy?(name: string): unknown;
  personLanguage?(key: string): { value: string; populated: boolean };
  personGroupReferences?(key: string, attribute: string):
    { cn?: string; dn?: string; value?: string }[];
  groupsNamingPolicy?(attribute: string, name: unknown): string[];
  [hook: string]: unknown;
}

interface LocaleProfile {
  name: string;
  precedence: number;
  stored: boolean;
  inherited: boolean;
  from: 'realm' | 'default-realm' | 'built-in';
  dn: string;
  description: string;
  sources: Record<string, string>;
  problems: string[];
  enforced: boolean;
  defaultLocale: string;
  populatePreferredLanguage: boolean;
  [field: string]: any;
}

interface PolicyResult {
  ok: boolean;
  errors?: string[];
  removed?: boolean;
  profile?: LocaleProfile;
}

interface LocalePolicyDeps {
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
  i18n: {
    canonical(tag: unknown): string;
    answers(tag: string): boolean;
  };
}

/**
 * The name of the profile every realm has, `default`.
 */
const DEFAULT_PROFILE = 'default';

// ---------------------------------------------------------------------------
// THE SENTENCES `describe()` MAKES, as templates (#543 phase 2) — one copy,
// filled there with `ServerProse.fill()` and matched by
// `common/server_prose.ts` to refill in a console reader's language. A
// `param.` key is a phrase that only ever stands inside another sentence.
// ---------------------------------------------------------------------------
const SENTENCES: Readonly<Record<string, string>> = Object.freeze({
  drawnIn: 'a page whose reader names no language a catalog answers is ' +
    'drawn in {{tag}}',
  drawnInUncatalogued: 'a page whose reader names no language a catalog ' +
    'answers is drawn in {{tag}} — which no catalog answers, so its words ' +
    'are English and its dates and numbers are formatted for {{tag}}',
  populated: 'a person created without a preferredLanguage is given {{tag}}',
  notPopulated: 'a person created without a preferredLanguage is given none',
  mail: 'mail to a person whose entry names no language is written in ' +
    '{{tag}}'
});

// THE ONE SELECTOR A NAMED PROFILE CARRIES (#1238): its precedence. What it
// covers names it (REFERENCES), so the console and the API draw this row
// and no list.
const SELECTORS = [
  { key: 'precedence', attribute: 'stsLocalePrecedence',
    what: 'Which named locale policy wins where several are named for a ' +
          'page: the lowest, from 1 to 1000.' }
];
/**
 * How `common/policy_selection.ts` reads a named profile (#1238).
 */
const SELECTION = { precedenceAttribute: 'stsLocalePrecedence',
                    defaultPrecedence: PolicySelection.DEFAULT_PRECEDENCE };
/**
 * The attributes that NAME a locale profile (#1238): on an application and
 * on a group.
 */
const REFERENCES = Object.freeze({ application: 'appLocalePolicy',
                                   group: 'stsLocalePolicy' });

/**
 * The policy's fields: one table read as the schema, the console form, the
 * API body, the validation of a save and the parse of an entry.
 */
const FIELDS: PolicyField[] = [
  { key: 'defaultLocale', attribute: 'stsLocaleDefault', type: 'locale',
    dflt: 'en',
    label: 'Default language and region',
    what: 'A BCP 47 language tag (RFC 5646), such as en, fr-CA or zh-TW. ' +
          'Pages are drawn in it when the request, the person\'s ' +
          'preferredLanguage, the language chooser and the browser name ' +
          'nothing a catalog answers; dates and numbers are formatted for ' +
          'it even where no catalog does. Mail to a person whose entry ' +
          'names no language is written in it. Replaces the setting ' +
          'mail.defaultLanguage.' },
  { key: 'populatePreferredLanguage',
    attribute: 'stsLocalePopulatePreferredLanguage', type: 'bool',
    dflt: true,
    label: 'Give a new person this language',
    what: 'ON BY DEFAULT. A person entry created in this realm without a ' +
          'preferredLanguage (RFC 2798 section 2.7) is given the default ' +
          'language above as one — by the console, the management API, ' +
          'SCIM, a federated or self-service sign-up, or a bulk load. A ' +
          'named profile applies where the application that caused the ' +
          'creation names it, or one of the person\'s groups does. ' +
          'Existing entries are never rewritten.' }
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
const DEFAULTS: Readonly<Record<string, boolean | string>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    out[field.key] = field.dflt;
    return out;
  }, {} as Record<string, boolean | string>));

/**
 * The directory schema of `ou=localePolicies`: its container, object class
 * and attributes.
 */
const SCHEMA = {
  container: 'ou=localePolicies',
  objectClasses: [
    { name: 'stsLocalePolicy',
      what: 'This service\'s class for a locale policy: the language a ' +
            'realm\'s pages fall back to and gives a new person. Named by ' +
            'the PROFILE (`cn=default`, or a named profile an application ' +
            'or a group names).' }
  ],
  attributes: FIELDS.map(function (field) {
    return { name: field.attribute, what: field.what };
  }).concat(SELECTORS.map(function (field) {
    return { name: field.attribute, what: field.what };
  })).concat([
    { name: 'description',
      what: 'What the profile is for, for the next person.' }
  ]),
  // ON A PERSON (#539): what population wrote, so a page can tell the
  // policy's language from the person's own.
  personAttributes: [
    { name: 'stsPreferredLanguagePopulated',
      what: 'The preferredLanguage the locale policy gave this person when ' +
            'their entry was created. While preferredLanguage still equals ' +
            'it, it is the POLICY\'s choice and a page ranks it below the ' +
            'browser\'s language; once anybody sets another, it is the ' +
            'person\'s. Written by this service only.' }
  ]
};

/**
 * The locale policy: the language a realm's pages fall back to and give a new
 * person, with named profiles an application or a group names.
 *
 * Kept as `stsLocalePolicy` entries in `ou=localePolicies`; a realm with no
 * `cn=default` of its own inherits the default realm's, and failing that the
 * built-in defaults.
 */
class LocalePolicy {
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
   * The selector a named profile carries: its precedence.
   */
  static readonly SELECTORS = SELECTORS;
  /**
   * The attributes that name a profile, on an application and a group.
   */
  static readonly REFERENCES = REFERENCES;
  /**
   * The directory schema of `ou=localePolicies`.
   */
  static readonly SCHEMA = SCHEMA;
  /**
   * The sentences `describe()` makes, as templates (#543).
   */
  static readonly SENTENCES = SENTENCES;

  private directory: DirectoryHooks | null = null;
  private warnedAboutNoDirectory = false;

  /**
   * Builds the policy with no directory installed.
   *
   * @param deps - the logger, realms, error codes and the catalogs
   */
  constructor(private readonly deps: LocalePolicyDeps) {
    deps.log.debug("Entering LocalePolicy.constructor().");
    deps.log.debug("Leaving LocalePolicy.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): LocalePolicyDeps {
    log.debug("Entering LocalePolicy.defaultDeps().");
    log.debug("Leaving LocalePolicy.defaultDeps().");
    return { log: log, realms: realms, errorCodes: errorCodes, i18n: i18n };
  }

  /**
   * Installs the directory hooks the policy is read from and written to;
   * filled by the directory.
   *
   * @param hooks - the directory's policy hooks, or null to remove them
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): void {
    const { log } = this.deps;
    log.debug('Entering LocalePolicy.setDirectory().');
    this.directory = hooks || null;
    log.debug('Leaving LocalePolicy.setDirectory(). The register ' +
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
    log.debug("Entering LocalePolicy.directoryInstalled().");
    log.debug("Leaving LocalePolicy.directoryInstalled().");
    return this.directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.haveDirectory().");
    if (this.directory &&
        typeof this.directory.allLocalePolicies === 'function') {
      log.debug("Leaving LocalePolicy.haveDirectory().");
      return true;
    }
    if (!this.warnedAboutNoDirectory) {
      this.warnedAboutNoDirectory = true;
      log.warn('locale_policy: the embedded directory was never loaded, so ' +
               'there is no ou=localePolicies. The BUILT-IN locale policy ' +
               'is in force and cannot be edited in this process.');
    }
    log.debug("Leaving LocalePolicy.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  private firstValue(attributes: Record<string, unknown>,
                     name: string): unknown {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.firstValue().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving LocalePolicy.firstValue().");
    return Array.isArray(found) ? (found[0] === undefined ? '' : found[0])
      : (found === undefined || found === null ? '' : found);
  }

  // `passkey_policy.ts`'s parse, with a language tag for its enum. Never
  // guesses.
  private parseField(field: PolicyField,
                     raw: unknown): { value?: boolean | string;
                                      problem?: string } {
    const { log, i18n } = this.deps;
    log.debug("Entering LocalePolicy.parseField().");
    const text = String(raw === undefined || raw === null ? '' : raw).trim();
    if (field.type === 'bool') {
      const lower = text.toLowerCase();
      if (['true', 'on', '1'].indexOf(lower) >= 0) {
        log.debug("Leaving LocalePolicy.parseField().");
        return { value: true };
      }
      if (['false', 'off', '0', ''].indexOf(lower) >= 0) {
        log.debug("Leaving LocalePolicy.parseField().");
        return { value: false };
      }
      log.debug("Leaving LocalePolicy.parseField().");
      return { problem: field.label + ' is a yes-or-no setting, and "' +
                        text.slice(0, 40) + '" is neither.' };
    }
    const tag = i18n.canonical(text);
    if (!tag) {
      log.debug("Leaving LocalePolicy.parseField().");
      return { problem: field.label + ' must be a BCP 47 language tag ' +
                        '(RFC 5646) such as en, fr-CA or zh-TW; "' +
                        text.slice(0, 40) + '" is not one.' };
    }
    log.debug("Leaving LocalePolicy.parseField().");
    return { value: tag };
  }

  private entryIn(name: string) {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.entryIn().");
    const wanted = name.toLowerCase();
    log.debug("Leaving LocalePolicy.entryIn().");
    return this.directory.allLocalePolicies().filter(function (entry) {
      return String(entry.name || '').toLowerCase() === wanted;
    })[0] || null;
  }

  // THIS REALM'S OWN ENTRY, THEN — FOR `default` ONLY — THE DEFAULT REALM'S.
  private entryFor(name: string):
      { entry: any; from: LocaleProfile['from'] } {
    const { log, realms } = this.deps;
    log.debug("Entering LocalePolicy.entryFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving LocalePolicy.entryFor(). No directory.");
      return { entry: null, from: 'built-in' };
    }
    const own = this.entryIn(name);
    if (own) {
      log.debug("Leaving LocalePolicy.entryFor(). The realm's own.");
      return { entry: own, from: 'realm' };
    }
    if (name !== DEFAULT_PROFILE || realms.isDefault()) {
      log.debug("Leaving LocalePolicy.entryFor(). Built-in.");
      return { entry: null, from: 'built-in' };
    }
    const inherited = realms.run(realms.DEFAULT_REALM, () => {
      log.debug("Entering LocalePolicy.entryFor() default-realm read.");
      const found = this.entryIn(name);
      log.debug("Leaving LocalePolicy.entryFor() default-realm read.");
      return found;
    });
    log.debug("Leaving LocalePolicy.entryFor(). " +
              (inherited ? 'Inherited.' : 'Built-in.'));
    return inherited ? { entry: inherited, from: 'default-realm' }
      : { entry: null, from: 'built-in' };
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
  read(name?: string): LocaleProfile {
    const { log } = this.deps;
    log.debug('Entering LocalePolicy.read(). name=' + name);
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
      // THE PRECEDENCE (#1238): 0 for `default`, which is never ranked.
      // What a profile covers names it (`namedBy()`).
      precedence: profile === DEFAULT_PROFILE ? 0
        : PolicySelection.precedenceOf(at, SELECTION),
      stored: found.from === 'realm',
      inherited: found.from === 'default-realm',
      from: found.from,
      dn: entry ? entry.dn : '',
      description: entry ? String(this.firstValue(at, 'description')) : '',
      sources: sources,
      problems: problems,
      // It decides only what language a reader sees: in force in both modes.
      enforced: true
    }, values) as LocaleProfile;
    log.debug('Leaving LocalePolicy.read(). From ' + found.from + '.');
    return out;
  }

  /**
   * Lists the profiles: `default` first, then this realm's named profiles in
   * the order they rank (the lowest precedence first, ties by name).
   *
   * @returns the profiles
   */
  list(): LocaleProfile[] {
    const { log } = this.deps;
    log.debug('Entering LocalePolicy.list().');
    const named = this.namedProfiles().map((one) => {
      return this.read(one);
    }).sort(PolicySelection.compare);
    const rows = [this.read(DEFAULT_PROFILE)].concat(named);
    log.debug('Leaving LocalePolicy.list(). ' + rows.length +
              ' profile(s).');
    return rows;
  }

  private namedProfiles(): string[] {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.namedProfiles().");
    const out = this.haveDirectory()
      ? this.directory.allLocalePolicies().map(function (one) {
        return String(one.name || '').toLowerCase();
      }).filter(function (one) {
        return one && one !== DEFAULT_PROFILE;
      }) : [];
    log.debug("Leaving LocalePolicy.namedProfiles(). " + out.length);
    return out;
  }

  /**
   * Returns the name of the profile that applies to a page or a mail drawn
   * for an application and, where one is known, a person (#1238): of the
   * profile the application names (`appLocalePolicy`) and the profiles the
   * person's groups name (`stsLocalePolicy`), the lowest precedence (ties by
   * name), else `default`.
   *
   * @param application - an application's identifier or client_id, or ''
   * @param person - the person (a username, a DN or `urn:uuid:`), or ''
   *   where nobody is known yet: the application alone then chooses
   * @returns the profile name
   */
  profileNameFor(application: unknown, person?: unknown): string {
    const { log, errorCodes } = this.deps;
    log.debug("Entering LocalePolicy.profileNameFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving LocalePolicy.profileNameFor(). No directory.");
      return DEFAULT_PROFILE;
    }
    let out = DEFAULT_PROFILE;
    try {
      const entries = this.directory.allLocalePolicies();
      // NOTHING TO RANK, NOTHING TO ASK (the constant-cost rule): a realm
      // with no named profile — most of them — reads no application and no
      // group on a page.
      if (!PolicySelection.named(entries, SELECTION).length) {
        log.debug("Leaving LocalePolicy.profileNameFor(). None named.");
        return DEFAULT_PROFILE;
      }
      const who = String(person === undefined || person === null ? ''
        : person).trim();
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
      ranked.missing.forEach(function (one) {
        // A REFERENCE NO PROFILE ANSWERS (#1238) selects nothing, and where
        // nothing else names a profile `default` applies. Not closed: the
        // policy chooses a fallback language and guards nothing.
        log.warn(errorCodes.tag('STS-I18N-0013') + 'locale policy: the ' +
                 one.by + ' "' + one.holder + '" names the locale policy "' +
                 one.name + '", which this realm does not hold; it selects ' +
                 'nothing, and `default` applies where nothing else names ' +
                 'a profile, until the policy exists or the reference ' +
                 'changes.');
      });
      out = ranked.name;
    } catch (e) {
      // A directory that cannot be asked gives the default: a reader still
      // gets a page.
      log.debug("Caught in LocalePolicy.profileNameFor(): " +
                ((e && e.message) || e));
      out = DEFAULT_PROFILE;
    }
    log.debug("Leaving LocalePolicy.profileNameFor(). " + out);
    return out;
  }

  // THE PROFILE AN APPLICATION NAMES (#1238): its `appLocalePolicy`, found by
  // what a page names it by — a client_id, else its identifier (an entity
  // ID, a hosted surface's own client). The registry is required LAZILY: it
  // is loaded after this leaf, and a require at load would close a cycle.
  // '' where nothing is named or nothing can be asked.
  private applicationReference(application: unknown): string {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.applicationReference().");
    const name = String(application === undefined || application === null
      ? '' : application).trim();
    if (!name) {
      log.debug("Leaving LocalePolicy.applicationReference(). None.");
      return '';
    }
    let out = '';
    try {
      const applications = require('./applications');
      const row = applications.forClientId(name) || applications.get(name);
      out = String([].concat(((row && row.fields) || {})[
        REFERENCES.application] || [])[0] || '');
    } catch (e) {
      log.debug("Caught in LocalePolicy.applicationReference(): " +
                ((e && e.message) || e));
      out = '';
    }
    log.debug("Leaving LocalePolicy.applicationReference(). " +
              (out || 'none'));
    return out;
  }

  /**
   * Reads the profile that applies to an application and, where known, a
   * person.
   *
   * @param application - an application's identifier or client_id, or ''
   * @param person - the person, or '' where nobody is known yet
   * @returns the profile
   */
  forApplication(application: unknown, person?: unknown): LocaleProfile {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.forApplication().");
    const out = this.read(this.profileNameFor(application, person));
    log.debug("Leaving LocalePolicy.forApplication(). " + out.name);
    return out;
  }

  /**
   * What names a named profile (#1238): the applications (the application
   * listing's index, lazily, for `applicationReference()`'s reason) and the
   * groups (the directory's group index) — what refuses its delete and what
   * its Named policies entry lists.
   *
   * @param name - the profile's name
   * @returns `{ applications, groups, people }`; nobody names a locale
   *   profile from their own entry
   */
  namedBy(name: unknown): { applications: string[]; groups: string[];
                            people: string[] } {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.namedBy().");
    let applications: string[] = [];
    try {
      applications = require('./applications')
        .applicationsNamingPolicy(REFERENCES.application, name);
    } catch (e) {
      log.debug("Caught in LocalePolicy.namedBy(): " +
                ((e && e.message) || e));
      applications = [];
    }
    const hook = this.haveDirectory() ? this.directory.groupsNamingPolicy
      : null;
    const groups = typeof hook === 'function'
      ? (hook.call(this.directory, REFERENCES.group, name) || []) : [];
    log.debug("Leaving LocalePolicy.namedBy(). " + applications.length +
              " application(s), " + groups.length + " group(s).");
    return { applications: applications, groups: groups, people: [] };
  }

  /**
   * Returns the default locale for an application and, where known, a
   * person: their profile's `defaultLocale`.
   *
   * @param application - an application's identifier or client_id, or ''
   * @param person - the person, or '' where nobody is known yet
   * @returns a canonical language tag
   */
  defaultLocaleFor(application?: unknown, person?: unknown): string {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.defaultLocaleFor().");
    const out = String(this.forApplication(application || '', person || '')
      .defaultLocale);
    log.debug("Leaving LocalePolicy.defaultLocaleFor(). " + out);
    return out;
  }

  /**
   * Returns the `preferredLanguage` a person entry being CREATED without one
   * is given, or '' when the applicable profile populates nothing.
   *
   * @param application - the application that caused the creation, or ''
   * @param person - the person being created (their DN), whose groups may
   *   already name a profile, or ''
   * @returns the tag, or ''
   */
  populationFor(application?: unknown, person?: unknown): string {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.populationFor().");
    const profile = this.forApplication(application || '', person || '');
    const out = profile.populatePreferredLanguage === true
      ? String(profile.defaultLocale || '') : '';
    log.debug("Leaving LocalePolicy.populationFor(). " + (out || 'none'));
    return out;
  }

  /**
   * Returns a person's own `preferredLanguage` (RFC 2798 section 2.7: an
   * Accept-Language value), or '' where they name none or nobody is found.
   *
   * @param username - the person: a username, a DN or `urn:uuid:`
   * @returns the attribute's value, or ''
   */
  preferredLanguageOf(username: unknown): string {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.preferredLanguageOf().");
    const out = this.languageOf(username).value;
    log.debug("Leaving LocalePolicy.preferredLanguageOf(). " +
              (out || 'None.'));
    return out;
  }

  /**
   * Returns a person's `preferredLanguage` and whether it is still the value
   * this policy POPULATED when their entry was created (rcbj on #539: such a
   * value ranks below the browser's language on a page).
   *
   * @param username - the person: a username, a DN or `urn:uuid:`
   * @returns `{ value, populated }`; `value` is '' where none is named
   */
  languageOf(username: unknown): { value: string; populated: boolean } {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.languageOf().");
    const hook = this.directory && this.directory.personLanguage;
    let out = { value: '', populated: false };
    if (username && typeof hook === 'function') {
      try {
        const found = hook.call(this.directory, String(username)) || {};
        out = { value: String(found.value || ''),
                populated: found.populated === true };
      } catch (e) {
        log.debug("Caught in LocalePolicy.languageOf(): " +
                  ((e && e.message) || e));
        out = { value: '', populated: false };
      }
    }
    log.debug("Leaving LocalePolicy.languageOf(). " + (out.value || 'None.') +
              (out.populated ? ' (populated)' : ''));
    return out;
  }

  /**
   * Describes a profile in sentences, for the page and a save's answer.
   *
   * @param profile - a profile already read; `default` read when omitted
   * @returns the sentences
   */
  describe(profile?: LocaleProfile | null): string[] {
    const { log, i18n } = this.deps;
    log.debug("Entering LocalePolicy.describe().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const tag = String(rules.defaultLocale);
    const fill = serverProse.fill;
    const out = [
      fill(i18n.answers(tag) ? SENTENCES.drawnIn
                             : SENTENCES.drawnInUncatalogued, { tag: tag }),
      rules.populatePreferredLanguage === true
        ? fill(SENTENCES.populated, { tag: tag })
        : SENTENCES.notPopulated,
      fill(SENTENCES.mail, { tag: tag })
    ];
    log.debug("Leaving LocalePolicy.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WRITING.
  // -------------------------------------------------------------------------
  // `default` or a name a named profile may have: the one rule every kind
  // keeps (`PolicySelection.nameProblem()`, #1238).
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.checkProfileName().");
    const out = PolicySelection.nameProblem(String(name || DEFAULT_PROFILE),
                                            'locale policy profile', true);
    log.debug("Leaving LocalePolicy.checkProfileName().");
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
    log.debug('Entering LocalePolicy.validate().');
    const body = given || {};
    const values: Record<string, boolean | string> = {};
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
    log.debug('Leaving LocalePolicy.validate(). ' + problems.length +
              ' problem(s).');
    return { values: values, problems: problems };
  }

  /**
   * Saves a profile of this realm, replacing it whole.
   *
   * @param name - the profile name: `default`, or a named profile
   * @param given - every field, and for a named profile its `precedence`
   * @returns `ok` and the profile now in force, or `ok: false` with `errors`
   */
  save(name: unknown, given?: Record<string, any> | null): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering LocalePolicy.save(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving LocalePolicy.save(). Not a profile that can exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-I18N-0003');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    const checked = this.validate(given);
    // A NAMED PROFILE'S PRECEDENCE (#1238), from 1 to 1000, 100 when left
    // out. It carries no other selector: what it covers names it.
    const ranked = which === DEFAULT_PROFILE ? null
      : PolicySelection.checkPrecedence(given, SELECTION);
    if (ranked) {
      ranked.problems.forEach(function (one) {
        checked.problems.push(one);
      });
    }
    if (checked.problems.length) {
      log.debug('Leaving LocalePolicy.save(). The values were refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-I18N-0004');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving LocalePolicy.save(). No directory.');
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep a locale policy. ' +
                        'ou=localePolicies IS the register.'] },
                             'STS-I18N-0005');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'stsLocalePolicy'],
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
    if (ranked) {
      attributes[SELECTION.precedenceAttribute] = String(ranked.precedence);
    }
    const written = this.directory.writeLocalePolicy(which, attributes);
    if (!written) {
      log.debug('Leaving LocalePolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-I18N-0006');
    }
    log.debug('Leaving LocalePolicy.save(). Stored.');
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
    log.debug('Entering LocalePolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving LocalePolicy.reset(). Not a profile that can ' +
                'exist.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-I18N-0003');
    }
    const which = String(name || DEFAULT_PROFILE).trim().toLowerCase();
    if (!this.haveDirectory()) {
      log.debug('Leaving LocalePolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(which) };
    }
    // NOT WHILE AN APPLICATION OR A GROUP NAMES IT (#1238): it would be left
    // naming a profile the realm does not hold.
    const held = which === DEFAULT_PROFILE ? null
      : PolicySelection.deleteProblem('locale policy', which,
                                      this.namedBy(which));
    if (held) {
      log.debug('Leaving LocalePolicy.reset(). Still named.');
      return errorCodes.mark({ ok: false, errors: [held] },
                             'STS-I18N-0014');
    }
    const removed = !!this.directory.deleteLocalePolicy(which);
    log.debug('Leaving LocalePolicy.reset(). ' +
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
    log.debug("Entering LocalePolicy.enforced().");
    log.debug("Leaving LocalePolicy.enforced().");
    return true;
  }
}

const slot = new InstanceSlot<LocalePolicy>(
  'common/locale_policy',
  () => new LocalePolicy(LocalePolicy.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

// A GROUP NAMES ITS LOCALE PROFILE (#1238): declared, so the group page draws
// its picker and the directory's group writer checks it, offering `default`
// and the realm's named profiles as they stand when asked.
PolicySelection.declareReference('group', REFERENCES.group, 'locale policy',
  function () {
    log.debug("Entering locale policy reference choices.");
    const names = slot.get().list().map(function (one) {
      return String(one.name);
    });
    log.debug("Leaving locale policy reference choices.");
    return names;
  });

/**
 * The locale policy (#539): the language a realm's pages fall back to and
 * give a new person, with named profiles an application or a group names
 * (#1238). The fifth
 * policy on Directory > Policies. The exports forward to the instance the
 * composition root installs.
 *
 * @namespace
 */
export = {
  LocalePolicy: LocalePolicy,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: LocalePolicy): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  DEFAULT_PROFILE: LocalePolicy.DEFAULT_PROFILE,
  DEFAULTS: LocalePolicy.DEFAULTS,
  FIELDS: LocalePolicy.FIELDS,
  FIELD_BY_KEY: LocalePolicy.FIELD_BY_KEY,
  SELECTORS: LocalePolicy.SELECTORS,
  REFERENCES: LocalePolicy.REFERENCES,
  SCHEMA: LocalePolicy.SCHEMA,
  SENTENCES: LocalePolicy.SENTENCES,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileNameFor: slot.forward('profileNameFor'),
  forApplication: slot.forward('forApplication'),
  namedBy: slot.forward('namedBy'),
  defaultLocaleFor: slot.forward('defaultLocaleFor'),
  populationFor: slot.forward('populationFor'),
  preferredLanguageOf: slot.forward('preferredLanguageOf'),
  languageOf: slot.forward('languageOf'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
