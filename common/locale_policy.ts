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
// NAMED PROFILES ARE CHOSEN BY APPLICATION, AND ONLY BY APPLICATION.
//
// Beside `cn=default` a realm may keep profiles of its own (`cn=<name>`,
// lower-case letters, digits and hyphens), each with the two rows and the
// applications it applies to (`stsLocaleSelectApplication`, an application's
// identifier or client_id). rcbj asked for application objects alone, so
// there are no group selectors — and so NO PRECEDENCE: an application may be
// on ONE named profile, and a save that would put it on a second is refused
// (STS-I18N-0007) rather than ranked. Which profile applies is therefore a
// lookup, `forApplication()`, never a contest.
//
// `forApplication()` takes the application as an argument rather than
// selecting it for the rest of the request (#535's `select()`): every caller
// — a sign-in page, the consent screen, sign-out, SCIM's create — already
// holds the application it is drawing for, and a locale read is asked once
// per page, not at a dozen doors that cannot be handed it.
//
// Named profiles are NOT inherited across realms; only `default` follows the
// default realm's.
//
// IT IS A LIBRARY (rule 3) AND A LEAF: `helpers`, `realms`, `error_codes`,
// `i18n` (a leaf), the instance slot, and the directory through a slot
// `ldap/ldap_server.js` fills. In force in both modes: it decides only what
// language a reader sees.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import i18n = require('./i18n');
import InstanceSlot = require('./instance_slot');

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
  personLanguage?(key: string): string;
  [hook: string]: unknown;
}

interface LocaleProfile {
  name: string;
  selectApplications: string[];
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

/**
 * A named profile's name: what a cn may be here.
 */
const PROFILE_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/;

/**
 * The selector a named profile carries, stored beside its rows.
 */
const SELECTORS = [
  { key: 'selectApplications', attribute: 'stsLocaleSelectApplication',
    what: 'The applications (identifier or client_id) a named locale ' +
          'policy applies to. An application is on one named profile at ' +
          'most.' }
];

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
          'creation is one of its applications. Existing entries are never ' +
          'rewritten.' }
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
            'the PROFILE (`cn=default`, or a named profile chosen by ' +
            'application).' }
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
 * The locale policy: the language a realm's pages fall back to and give a new
 * person, with named profiles chosen by application.
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
   * The selector a named profile carries.
   */
  static readonly SELECTORS = SELECTORS;
  /**
   * The directory schema of `ou=localePolicies`.
   */
  static readonly SCHEMA = SCHEMA;

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

  // Every value of an attribute, as strings (the selector is a list).
  private allValues(attributes: Record<string, unknown>,
                    name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.allValues().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving LocalePolicy.allValues().");
    return (Array.isArray(found) ? found : (found === undefined ||
                                            found === null || found === ''
                                              ? [] : [found]))
      .map(String).filter(Boolean);
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
      selectApplications: profile === DEFAULT_PROFILE ? []
        : this.allValues(at, 'stsLocaleSelectApplication'),
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
   * Lists the profiles: `default` first, then this realm's named profiles by
   * name.
   *
   * @returns the profiles
   */
  list(): LocaleProfile[] {
    const { log } = this.deps;
    log.debug('Entering LocalePolicy.list().');
    const named = this.namedProfiles();
    const rows = [this.read(DEFAULT_PROFILE)].concat(named.sort()
      .map((one) => {
        return this.read(one);
      }));
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
   * Returns the name of the profile that applies to an application: the named
   * profile listing it, else `default`.
   *
   * @param application - an application's identifier or client_id, or ''
   * @returns the profile name
   */
  profileNameFor(application: unknown): string {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.profileNameFor().");
    const app = String(application || '').trim().toLowerCase();
    if (!app || !this.haveDirectory()) {
      log.debug("Leaving LocalePolicy.profileNameFor(). default.");
      return DEFAULT_PROFILE;
    }
    let out = DEFAULT_PROFILE;
    try {
      const hit = this.directory.allLocalePolicies().filter((entry) => {
        const name = String(entry.name || '').toLowerCase();
        return name !== DEFAULT_PROFILE &&
          this.allValues(entry.attributes || {},
                         'stsLocaleSelectApplication')
            .map(function (one) {
              return one.trim().toLowerCase();
            }).indexOf(app) >= 0;
      }).map(function (entry) {
        return String(entry.name || '').toLowerCase();
      }).sort()[0];
      out = hit || DEFAULT_PROFILE;
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

  /**
   * Reads the profile that applies to an application.
   *
   * @param application - an application's identifier or client_id, or ''
   * @returns the profile
   */
  forApplication(application: unknown): LocaleProfile {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.forApplication().");
    const out = this.read(this.profileNameFor(application));
    log.debug("Leaving LocalePolicy.forApplication(). " + out.name);
    return out;
  }

  /**
   * Returns the default locale for an application: its profile's
   * `defaultLocale`.
   *
   * @param application - an application's identifier or client_id, or ''
   * @returns a canonical language tag
   */
  defaultLocaleFor(application?: unknown): string {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.defaultLocaleFor().");
    const out = String(this.forApplication(application || '').defaultLocale);
    log.debug("Leaving LocalePolicy.defaultLocaleFor(). " + out);
    return out;
  }

  /**
   * Returns the `preferredLanguage` a person entry being CREATED without one
   * is given, or '' when the applicable profile populates nothing.
   *
   * @param application - the application that caused the creation, or ''
   * @returns the tag, or ''
   */
  populationFor(application?: unknown): string {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.populationFor().");
    const profile = this.forApplication(application || '');
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
    const hook = this.directory && this.directory.personLanguage;
    let out = '';
    if (username && typeof hook === 'function') {
      try {
        out = String(hook.call(this.directory, String(username)) || '');
      } catch (e) {
        log.debug("Caught in LocalePolicy.preferredLanguageOf(): " +
                  ((e && e.message) || e));
        out = '';
      }
    }
    log.debug("Leaving LocalePolicy.preferredLanguageOf(). " +
              (out || 'None.'));
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
    const out = [
      'a page whose reader names no language a catalog answers is drawn in ' +
        tag + (i18n.answers(tag) ? ''
          : ' — which no catalog answers, so its words are English and its ' +
            'dates and numbers are formatted for ' + tag),
      rules.populatePreferredLanguage === true
        ? 'a person created without a preferredLanguage is given ' + tag
        : 'a person created without a preferredLanguage is given none',
      'mail to a person whose entry names no language is written in ' + tag
    ];
    if (rules.name !== DEFAULT_PROFILE) {
      out.unshift('applies to ' + (rules.selectApplications.length
        ? rules.selectApplications.join(', ') : 'no application'));
    }
    log.debug("Leaving LocalePolicy.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WRITING.
  // -------------------------------------------------------------------------
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.checkProfileName().");
    const text = String(name || DEFAULT_PROFILE).trim();
    if (text !== DEFAULT_PROFILE && !PROFILE_NAME.test(text)) {
      log.debug("Leaving LocalePolicy.checkProfileName().");
      return 'A locale policy profile is "' + DEFAULT_PROFILE + '" or a ' +
             'name of lower-case letters, digits and hyphens, at most 64; "' +
             text.slice(0, 64) + '" is neither.';
    }
    log.debug("Leaving LocalePolicy.checkProfileName().");
    return null;
  }

  // A named profile's applications as sent: a list by comma, line or array,
  // each at most 256 characters with no control character, at most 64 of
  // them, at least one — and none already on ANOTHER named profile.
  private checkApplications(which: string, raw: unknown):
      { applications: string[]; problems: string[]; claimed: string[] } {
    const { log } = this.deps;
    log.debug("Entering LocalePolicy.checkApplications().");
    const problems: string[] = [];
    const items = (Array.isArray(raw) ? raw : String(raw === undefined ||
                                                     raw === null ? '' : raw)
      .split(/[,\n]/)).map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
    if (items.length > 64 || items.some(function (one) {
      return one.length > 256 || /[\u0000-\u001f\u007f]/.test(one);
    })) {
      problems.push('The applications a named profile applies to must be ' +
                    'at most 64 values of at most 256 characters each, with ' +
                    'no control character.');
    }
    if (!items.length) {
      problems.push('A named profile with no application would apply to ' +
                    'nothing; name at least one.');
    }
    const claimed: string[] = [];
    if (this.haveDirectory()) {
      this.directory.allLocalePolicies().forEach((entry) => {
        const name = String(entry.name || '').toLowerCase();
        if (name === DEFAULT_PROFILE || name === which) {
          return;
        }
        const theirs = this.allValues(entry.attributes || {},
                                      'stsLocaleSelectApplication')
          .map(function (one) {
            return one.trim().toLowerCase();
          });
        items.forEach(function (one) {
          if (theirs.indexOf(one.toLowerCase()) >= 0) {
            claimed.push(one + ' (on "' + name + '")');
          }
        });
      });
    }
    log.debug("Leaving LocalePolicy.checkApplications(). " +
              problems.length + " problem(s), " + claimed.length +
              " claimed.");
    return { applications: items.slice(0, 64), problems: problems,
             claimed: claimed };
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
   * @param given - every field, and for a named profile its applications
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
    const apps = which === DEFAULT_PROFILE ? null
      : this.checkApplications(which, (given || {}).selectApplications);
    if (apps) {
      apps.problems.forEach(function (one) {
        checked.problems.push(one);
      });
    }
    if (checked.problems.length) {
      log.debug('Leaving LocalePolicy.save(). The values were refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-I18N-0004');
    }
    if (apps && apps.claimed.length) {
      log.debug('Leaving LocalePolicy.save(). An application is claimed.');
      return errorCodes.mark({ ok: false,
               errors: ['An application is on one named locale profile at ' +
                        'most, and ' + apps.claimed.join(', ') + ' already ' +
                        (apps.claimed.length === 1 ? 'is' : 'are') + '. ' +
                        'Take it off that profile first.'] },
                             'STS-I18N-0007');
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
    if (apps) {
      attributes.stsLocaleSelectApplication = apps.applications;
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

/**
 * The locale policy (#539): the language a realm's pages fall back to and
 * give a new person, with named profiles chosen by application. The fifth
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
  SCHEMA: LocalePolicy.SCHEMA,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  profileNameFor: slot.forward('profileNameFor'),
  forApplication: slot.forward('forApplication'),
  defaultLocaleFor: slot.forward('defaultLocaleFor'),
  populationFor: slot.forward('populationFor'),
  preferredLanguageOf: slot.forward('preferredLanguageOf'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  describe: slot.forward('describe'),
  enforced: slot.forward('enforced')
};
