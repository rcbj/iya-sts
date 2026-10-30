// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: attribute_policy.ts
//
// ---------------------------------------------------------------------------
// THE ATTRIBUTE POLICY (#396, 2026-10-19): WHAT EVERY PERSON IN A REALM MUST
// CARRY, AND THE ATTRIBUTES A REALM ADDS TO WHAT A PERSON MAY CARRY.
//
// rcbj's ticket: "Minimum user attributes that must be populated for a new
// user object. Default: first name, sn, email. Add a policy that defines what
// the required fields must be for a realm." And on it, the same day: the page
// "should display a list of all attributes, custom attributes, ability to add
// a new attribute, and require each individual attribute as needed." It is
// the sixth kind on Directory → Policies (`admin-core/policy_kinds.ts`), on
// `locale_policy.ts`'s pattern: `cn=default` in `ou=attributePolicies`,
// inherited from the default realm while a realm has none of its own, and the
// built-in default while neither has.
//
// ---------------------------------------------------------------------------
// ONE FIELD, AND THREE ATTRIBUTES THAT ARE NOT IN IT.
//
//   requiredAttributes     `givenName, sn, mail` — the ticket's first name,
//                          surname and email. Any attribute a person here may
//                          be given a value for: the inetOrgPerson schema
//                          (`common/inetorgperson.ts`), the credential
//                          catalogue's extras, `mail`, and this realm's own
//                          custom attributes (below).
//
// **`uid`, `cn` AND `sn` ARE ALWAYS REQUIRED and are not in the field**
// (rcbj's choice on #396: locked). `uid` is the username; `cn` and `sn` are
// the `person` class's MUST list (RFC 4519 section 3.12), which
// `ldap/person_editor.ts` already refuses to empty. A create that names no
// `cn` is given `givenName sn` (`ldap_server.js`'s `createUser()`), so the
// name is not typed twice. `sn` is in the default list as well, because the
// ticket named it; leaving it out of a save changes nothing.
//
// **NEVER OFFERED**: `userPassword` (a person may be created with an
// activation link and no password — the credential is the password policy's
// question), the binary rows, `memberOf` (it grants console roles) and every
// `sts*` attribute (credentials and this service's own records). They are not
// in the person editor's universe, which is where the offered list comes from.
//
// ---------------------------------------------------------------------------
// ENFORCED IN PRODUCT MODE ONLY (`mode.createsIncompletePeople()`).
//
// Development mode creates a person at a sign-in with nothing typed, and a
// client under test needs a subject before it needs a surname; the policy is
// still stored, drawn and published there, and the page says it is not
// enforced — the password policy's arrangement. In product, a create that
// leaves a required attribute empty is refused at every door, and an edit
// that would take a required value AWAY is refused; a person who already
// lacked one keeps every other door (nothing here is retroactive, and the
// page counts them). The doors themselves are the directory's and SCIM's;
// this module answers what is required and what is missing.
//
// ---------------------------------------------------------------------------
// CUSTOM ATTRIBUTES: A REALM'S OWN REGISTER, `ou=attributeDefinitions`.
//
// The directory is schemaless — an LDAP client may write any attribute — but
// the console, `/admin-api` and a create offer an ALLOWLIST (`person_editor.ts`
// argues why). A custom attribute is how an administrator adds a name to that
// list for this realm: `cn=<name>` with a label, a syntax and whether it holds
// one value or several. It is then editable on a person's page, settable on
// `/admin/users/new` and `POST /admin-api/users/create`, its values checked
// against its syntax, and requirable here.
//
// * **THE REALM'S OWN, NOT INHERITED** — the rule named profiles follow. The
//   default realm's custom attributes are not another realm's; a profile a
//   realm inherits that requires a name the realm does not define says so in
//   `problems` and does not require it there.
// * **THE NAME** is an RFC 4512 `descr` (a letter, then letters, digits and
//   hyphens), at most 64, and may not be a name the directory already knows
//   (the schema's, the catalogue's, this service's own — `learnName()`'s
//   table), `memberOf`, or anything beginning `sts`.
// * **NEVER SECRET, NEVER BINARY.** `inetorgperson.ts` keeps a fixed list so
//   that no attribute appears on a page by accident; a custom attribute is a
//   deliberate administrator's act, and that stays true only while a
//   credential cannot be stored as one. The syntaxes are text.
// * **REMOVED ONLY WHILE NOBODY HOLDS A VALUE**, and not while this realm's
//   own profile requires it: a definition gone from under its values would
//   leave data no door offers again.
//
// ---------------------------------------------------------------------------
// NAMED POLICIES, NAMED BY THE PERSON AND BY THEIR GROUPS (#1241, part of
// #1234; rule 3cx).
//
// Beside `cn=default` a realm may keep NAMED profiles, `cn=<name>` in
// `ou=attributePolicies`: each a `requiredAttributes` list and a precedence
// (`stsAttributePolicyPrecedence`, 1 to 1000). They are THE REALM'S OWN,
// never inherited; `default` still is. What a named profile covers names it:
// `stsAttributePolicy` on the person's own entry, and the same attribute on
// a group (`common/policy_selection.ts`). The candidates are the person's
// reference and each of their groups' references; the lowest precedence
// wins, ties by name, else `default`.
//
// * AT A CREATE the person's reference is the one the write sets, and the
//   groups are those already listing the DN the person will have (a
//   dangling member of a group becomes a member the moment the entry exists)
//   plus any group the same write adds — `subject.groups`. No door adds a
//   group in the same write as a person today (SCIM's `groups` is read-only,
//   RFC 7643 section 4.1.2), so the parameter is the door's to use when one
//   does.
// * AT AN EDIT the person's reference is the one the entry will hold AFTER
//   the edit, and the groups are the ones they are in: the person is held
//   to the policy they are moving to. Naming a weaker policy is itself a
//   checked write (the person editor's closed set, STS-LDAP-0106).
// * A REFERENCE TO A NAME THE REALM DOES NOT HOLD selects nothing: the
//   candidates left decide, and `default` where none is left. Logged under
//   STS-LDAP-0196. It does not fail closed — the policy is a floor on what a
//   person holds, `default` is the floor everyone else is held to, and a
//   create refused for a dangling group reference would refuse a person for
//   something no one at the door can see.
// * A NAMED PROFILE SOMETHING NAMES IS NOT DELETED (STS-LDAP-0197): the
//   groups from the group index, the people from the holders of
//   `stsAttributePolicy` — asked ASYNCHRONOUSLY (`namedByAsync()`), so the
//   delete of a named profile answers a promise.
//
// The custom attribute register stays realm-wide and is no part of a
// profile: every profile may require a custom attribute, and one is not
// removed while ANY of the realm's own profiles requires it.
//
// IT IS A LIBRARY (rule 3): it registers no route. It requires `helpers`,
// `realms`, `mode`, `error_codes`, the instance slot and server prose, and
// reaches the directory through a slot `ldap/ldap_server.js` fills. The
// offered list is `ldap/person_editor.ts`'s universe, required LAZILY:
// `person_editor` requires this module at load, for the custom rows and the
// required flags it draws.
// ---------------------------------------------------------------------------

import helpers = require('./helpers');
import realms = require('./realms');
import errorCodes = require('./error_codes');
import InstanceSlot = require('./instance_slot');
// The sentences `describe()` makes are filled from SENTENCES below, so the
// server can translate them into a console reader's language (#543).
import serverProse = require('./server_prose');
// Which named profile applies (#1241, rule 3cx): a leaf of static methods.
import PolicySelection = require('./policy_selection');

const { log } = helpers;

// One row of FIELDS, below.
interface PolicyField {
  key: string;
  attribute: string;
  type: 'attributeList';
  dflt: string;
  label: string;
  what: string;
}

// One custom attribute, as the register answers it.
interface Definition {
  name: string;
  label: string;
  syntax: string;
  multi: boolean;
  description: string;
  dn: string;
}

// What the directory's slot offers. Validated whole (`setDirectory()`).
interface DirectoryHooks {
  allAttributePolicies(): { name?: string; dn: string;
                            attributes?: Record<string, unknown> }[];
  writeAttributePolicy(name: string,
                       attributes: Record<string, unknown>): unknown;
  deleteAttributePolicy(name: string): unknown;
  allAttributeDefinitions(): { name?: string; dn: string;
                               attributes?: Record<string, unknown> }[];
  writeAttributeDefinition(name: string,
                           attributes: Record<string, unknown>): unknown;
  deleteAttributeDefinition(name: string): unknown;
  // The spelling the directory knows a name by, or '' for a name it does not.
  knownName(name: string): string;
  // How many people in this realm hold a value of the attribute.
  holders(name: string): number;
  // How many people in this realm lack a value of any of the attributes —
  // or, given a function, of any of the attributes it answers for each
  // person (#1241): `(username, reference)`, the person's own
  // `stsAttributePolicy`, to the lower-cased names their profile requires.
  missing(names: string[] |
          ((username: string, reference: string) => string[])): number;
  // THE NAMED PROFILES' HOOKS (#1241, rule 3cx), optional so a process
  // with no group index (the bulk import) installs the nine above alone:
  // the person's groups with the policy each names, the groups naming a
  // policy, the policy each of some groups names, and the people naming one.
  personGroupReferences?(key: string, attribute: string):
    Array<{ cn?: string; dn?: string; value?: string }>;
  groupsNamingPolicy?(attribute: string, name: string): string[];
  groupReferences?(groups: string[], attribute: string):
    Array<{ cn?: string; dn?: string; value?: string }>;
  peopleNamingPolicyAsync?(attribute: string, name: string, limit?: number):
    Promise<{ people: string[]; complete: boolean }>;
}

// Whose profile is asked for (#1241): the person, the entry as it will be
// written (their own reference is read from it), and any group the same
// write adds. Every member optional; none at all is `default`.
interface Subject {
  uid?: string;
  attributes?: Record<string, unknown>;
  groups?: string[];
}

// An attribute a person may be given a value for, as the person editor
// publishes it.
interface OfferedRow {
  name: string;
  label: string;
  schema: string;
  custom?: boolean;
}

interface AttributeProfile {
  name: string;
  stored: boolean;
  inherited: boolean;
  from: 'realm' | 'default-realm' | 'built-in';
  dn: string;
  description: string;
  sources: Record<string, string>;
  problems: string[];
  enforced: boolean;
  requiredAttributes: string;
  // The whole list in force: the three always required, then the profile's.
  required: string[];
  // 0 for `default`, which is never ranked (#1241).
  precedence: number;
  [field: string]: any;
}

interface PolicyResult {
  ok: boolean;
  errors?: string[];
  removed?: boolean;
  profile?: AttributeProfile;
}

// What a refusal names besides its sentence (#1241): the profile applied.
interface CreateRefusal {
  missing: string[];
  policy: string;
  message: string;
}
interface EditRefusal {
  removed: string[];
  policy: string;
  message: string;
}

interface AttributePolicyDeps {
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
  // `mode.createsIncompletePeople()`: true where the policy is not enforced.
  createsIncompletePeople: () => boolean;
  // The person editor's universe: every attribute a person may be given a
  // value for, and the ones it withholds. Lazy — see the header.
  offered: () => OfferedRow[];
}

/**
 * The name of the profile every realm has, `default`.
 */
const DEFAULT_PROFILE = 'default';

/**
 * The attributes every person must hold whatever the profile says: the
 * username, and the `person` class's MUST list (RFC 4519 section 3.12).
 */
const ALWAYS_REQUIRED = Object.freeze(['uid', 'cn', 'sn']);

/**
 * The syntaxes a custom attribute may have, each with what it accepts.
 */
const SYNTAXES = Object.freeze([
  Object.freeze({ id: 'string',
                  what: 'Text, at most 1024 characters, no control ' +
                        'character.' }),
  Object.freeze({ id: 'integer',
                  what: 'A whole number (RFC 4517 section 3.3.16).' }),
  Object.freeze({ id: 'boolean',
                  what: 'TRUE or FALSE (RFC 4517 section 3.3.3).' }),
  Object.freeze({ id: 'date',
                  what: 'A date, stored YYYYMMDD and accepted as ' +
                        'YYYY-MM-DD too.' }),
  Object.freeze({ id: 'email',
                  what: 'An email address (RFC 5322 addr-spec, ' +
                        'local@domain).' }),
  Object.freeze({ id: 'uri',
                  what: 'An http or https URL.' }),
  Object.freeze({ id: 'dn',
                  what: 'A distinguished name (RFC 4514).' })
]);

/**
 * The most custom attributes one realm may define.
 */
const MAX_DEFINITIONS = 100;

/**
 * What the kind calls one profile, in a refusal (#1241).
 */
const NOUN = 'attribute policy';

/**
 * How `common/policy_selection.ts` ranks a named profile (#1241).
 */
const SELECTION = Object.freeze({
  precedenceAttribute: 'stsAttributePolicyPrecedence',
  defaultPrecedence: PolicySelection.DEFAULT_PRECEDENCE });

/**
 * The attributes that NAME an attribute profile (#1241, rule 3cx): on the
 * person's own entry and on a group, one spelling for both.
 */
const REFERENCES = Object.freeze({ group: 'stsAttributePolicy',
                                   person: 'stsAttributePolicy' });

/**
 * A named profile's one selector: its precedence. What it covers names it.
 */
const SELECTORS = [
  { key: 'precedence', attribute: 'stsAttributePolicyPrecedence',
    what: 'Which named attribute policy applies where the person and their ' +
          'groups name several: the lowest, from 1 to 1000.' }
];

// An RFC 4512 section 1.4 `descr`: a letter, then letters, digits and
// hyphens. At most 64 here.
const DESCR = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;

// C0 controls, DEL and the C1 range.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

// ---------------------------------------------------------------------------
// THE SENTENCES `describe()` MAKES, AND THE ANSWERS OF THE TWO ACTIONS THIS
// KIND HAS BESIDE SAVE AND RESET, as templates (#543) — one copy, filled
// with `ServerProse.fill()` and matched by `common/server_prose.ts` to refill
// in a console reader's language.
// ---------------------------------------------------------------------------
const SENTENCES: Readonly<Record<string, string>> = Object.freeze({
  required: 'a person in this realm must hold {{list}} to be created, and ' +
    'an edit may not take a value of any of them away',
  enforced: 'enforced: this realm is in product mode, so every door that ' +
    'creates or edits a person refuses one without them',
  notEnforced: 'not enforced: this realm is in development mode, where a ' +
    'person may be created with no more than a username',
  custom: 'this realm defines {{n}} custom attribute(s): {{list}}',
  noCustom: 'this realm defines no custom attribute',
  defined: 'The custom attribute {{name}} is defined in this realm at ' +
    '{{dn}}. It may now be set on a person and required by this policy.',
  undefined: 'The custom attribute {{name}} is no longer defined in this ' +
    'realm.',
  // #1241: said of a named profile only.
  named: 'it applies to a person who names it, or who is in a group that ' +
    'names it, where no other policy they name has a lower precedence ' +
    'than {{precedence}}'
});

/**
 * The policy's fields: one table read as the schema, the console form, the
 * API body, the validation of a save and the parse of an entry.
 */
const FIELDS: PolicyField[] = [
  { key: 'requiredAttributes', attribute: 'stsAttributeRequired',
    type: 'attributeList', dflt: 'givenName, sn, mail',
    label: 'Required attributes',
    what: 'The attributes every person in this realm must hold a value of, ' +
          'besides uid, cn and sn, which are always required. A list, or ' +
          'comma-separated. Any attribute a person may be given a value ' +
          'for: the inetOrgPerson schema, the credential catalogue, mail, ' +
          'and this realm\'s custom attributes. Enforced in product mode: a ' +
          'create without one is refused at every door, and an edit may not ' +
          'take one away. Default givenName, sn and mail.' }
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
const DEFAULTS: Readonly<Record<string, string>> =
  Object.freeze(FIELDS.reduce(function (out, field) {
    out[field.key] = field.dflt;
    return out;
  }, {} as Record<string, string>));

/**
 * The directory schema of `ou=attributePolicies` and
 * `ou=attributeDefinitions`: their containers, object classes and attributes.
 */
const SCHEMA = {
  container: 'ou=attributePolicies',
  definitionContainer: 'ou=attributeDefinitions',
  objectClasses: [
    { name: 'stsAttributePolicy',
      what: 'This service\'s class for an attribute policy: the attributes ' +
            'every person in a realm must hold. Named by the PROFILE ' +
            '(`cn=default`, or a named profile of the realm\'s own).' },
    { name: 'stsAttributeDefinition',
      what: 'This service\'s class for a custom attribute of a realm, in ' +
            'ou=attributeDefinitions, named by the attribute (`cn=<name>`).' }
  ],
  attributes: [
    { name: 'stsAttributeRequired',
      what: FIELDS[0].what },
    { name: 'description',
      what: 'What the profile or the custom attribute is for, for the ' +
            'next person.' },
    { name: 'stsAttributeLabel',
      what: 'A custom attribute\'s label, drawn beside its name.' },
    { name: 'stsAttributeSyntax',
      what: 'A custom attribute\'s syntax: string, integer, boolean, date, ' +
            'email, uri or dn. Its values are checked against it.' },
    { name: 'stsAttributeSingleValued',
      what: 'TRUE where a custom attribute holds one value, FALSE where it ' +
            'holds several.' },
    { name: 'stsAttributePolicyPrecedence',
      what: SELECTORS[0].what }
  ],
  // THE REFERENCE (#1241): on a person's entry and on a group's, the
  // profile it names. The directory is schemaless; listed for the reader.
  personAttributes: [
    { name: 'stsAttributePolicy',
      what: 'On a person or a group: the attribute policy it names, ' +
            '`default` or a named profile of the realm. One value.' }
  ]
};

/**
 * The attribute policy: the attributes every person in a realm must hold,
 * and the realm's custom attributes.
 *
 * Kept as an `stsAttributePolicy` entry in `ou=attributePolicies` and
 * `stsAttributeDefinition` entries in `ou=attributeDefinitions`; a realm with
 * no `cn=default` of its own follows the default realm's, and failing that
 * the built-in default.
 */
class AttributePolicy {
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
   * The directory schema of the two containers.
   */
  static readonly SCHEMA = SCHEMA;
  /**
   * The sentences `describe()` makes, as templates (#543).
   */
  static readonly SENTENCES = SENTENCES;
  /**
   * The attributes every person must hold whatever the profile says.
   */
  static readonly ALWAYS_REQUIRED = ALWAYS_REQUIRED;
  /**
   * The syntaxes a custom attribute may have.
   */
  static readonly SYNTAXES = SYNTAXES;
  /**
   * The most custom attributes one realm may define.
   */
  static readonly MAX_DEFINITIONS = MAX_DEFINITIONS;
  /**
   * How a named profile ranks (#1241).
   */
  static readonly SELECTION = SELECTION;
  /**
   * The attributes naming a profile, on a person and on a group (#1241).
   */
  static readonly REFERENCES = REFERENCES;
  /**
   * A named profile's selector: its precedence (#1241).
   */
  static readonly SELECTORS = SELECTORS;

  private directory: DirectoryHooks | null = null;
  private warnedAboutNoDirectory = false;

  /**
   * Builds the policy with no directory installed.
   *
   * @param deps - the logger, realms, error codes, the mode predicate and
   *   the person editor's universe
   */
  constructor(private readonly deps: AttributePolicyDeps) {
    deps.log.debug("Entering AttributePolicy.constructor().");
    deps.log.debug("Leaving AttributePolicy.constructor().");
  }

  /**
   * Returns the dependencies the default instance is built from.
   *
   * @returns the service's own modules
   */
  static defaultDeps(): AttributePolicyDeps {
    log.debug("Entering AttributePolicy.defaultDeps().");
    log.debug("Leaving AttributePolicy.defaultDeps().");
    return {
      log: log, realms: realms, errorCodes: errorCodes,
      createsIncompletePeople: function createsIncompletePeople() {
        log.debug("Entering createsIncompletePeople().");
        // LAZILY: `mode.js` requires `config.js`, which is loaded by then;
        // asked per call because the mode is per realm and runtime-settable.
        const answer = require('./mode').createsIncompletePeople();
        log.debug("Leaving createsIncompletePeople().");
        return answer;
      },
      offered: function offered() {
        log.debug("Entering offered().");
        // LAZILY, for the reason in the header: `ldap/person_editor.ts`
        // requires this module at load.
        const editor = require('../ldap/person_editor');
        // NEVER AN `sts` NAME (#1241): the editor's universe holds the
        // policy references the kinds declare on a person
        // (`stsAttributePolicy` among them), and a reference is not a fact
        // about the person a profile could require.
        const rows = editor.editableAttributes().filter(function (row) {
          return !/^sts/i.test(row.name);
        }).map(function (row) {
          return { name: row.name, label: row.label, schema: row.schema,
                   custom: !!row.custom };
        });
        // `uid` and `mail` are withheld from the editor (each has a door of
        // its own) and are attributes every person may hold all the same.
        editor.withheldAttributes().forEach(function (row) {
          if (row.kind === 'managed') {
            rows.push({ name: row.name, label: row.label,
                        schema: row.name === 'uid' ? 'RFC 4519 2.39'
                                                   : 'RFC 4524 2.16',
                        custom: false });
          }
        });
        log.debug("Leaving offered(). " + rows.length);
        return rows;
      }
    };
  }

  /**
   * Installs the directory hooks the policy and the register are read from
   * and written to; filled by the directory. Validated whole: a directory
   * that could read and not write would draw a form whose every button
   * fails.
   *
   * @param hooks - the directory's hooks, or null to remove them
   * @returns true when installed
   */
  setDirectory(hooks: DirectoryHooks | null | undefined): boolean {
    const { log } = this.deps;
    log.debug('Entering AttributePolicy.setDirectory().');
    const needed = ['allAttributePolicies', 'writeAttributePolicy',
                    'deleteAttributePolicy', 'allAttributeDefinitions',
                    'writeAttributeDefinition', 'deleteAttributeDefinition',
                    'knownName', 'holders', 'missing'];
    if (hooks && needed.some(function (name) {
      return typeof (hooks as any)[name] !== 'function';
    })) {
      log.warn('attribute_policy: a directory without all of ' +
               needed.join(', ') + ' was offered and refused.');
      log.debug('Leaving AttributePolicy.setDirectory(). Refused.');
      return false;
    }
    this.directory = hooks || null;
    log.debug('Leaving AttributePolicy.setDirectory(). The register ' +
              (this.directory ? 'has its containers.' : 'has none.'));
    return true;
  }

  /**
   * Returns the installed directory hooks, so a test can put back what was
   * there.
   *
   * @returns the hooks, or null
   */
  directoryInstalled(): DirectoryHooks | null {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.directoryInstalled().");
    log.debug("Leaving AttributePolicy.directoryInstalled().");
    return this.directory;
  }

  private haveDirectory(): boolean {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.haveDirectory().");
    if (this.directory) {
      log.debug("Leaving AttributePolicy.haveDirectory().");
      return true;
    }
    if (!this.warnedAboutNoDirectory) {
      this.warnedAboutNoDirectory = true;
      log.warn('attribute_policy: the embedded directory was never loaded, ' +
               'so there is no ou=attributePolicies. The BUILT-IN attribute ' +
               'policy is in force and cannot be edited in this process.');
    }
    log.debug("Leaving AttributePolicy.haveDirectory().");
    return false;
  }

  // -------------------------------------------------------------------------
  // READING.
  // -------------------------------------------------------------------------
  private valuesOf(attributes: Record<string, unknown>,
                   name: string): string[] {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.valuesOf().");
    const found = attributes[name] !== undefined ? attributes[name]
      : attributes[name.toLowerCase()];
    log.debug("Leaving AttributePolicy.valuesOf().");
    return (Array.isArray(found) ? found : (found === undefined ||
                                            found === null || found === ''
                                              ? [] : [found]))
      .map(String).filter(Boolean);
  }

  // A list as sent: an array, or a string split at commas and line breaks.
  private listOf(raw: unknown): string[] {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.listOf().");
    const items = (Array.isArray(raw) ? raw : String(raw === undefined ||
                                                     raw === null ? '' : raw)
      .split(/[,\n]/)).map(function (one) {
        return String(one).trim();
      }).filter(Boolean);
    log.debug("Leaving AttributePolicy.listOf(). " + items.length);
    return items;
  }

  /**
   * Lists every attribute a person in this realm may be given a value for,
   * which is what the policy may require: the person editor's universe, `uid`
   * and `mail`, and this realm's custom attributes.
   *
   * @returns the rows, each with `name`, `label`, `schema`, `custom`,
   *   `locked` (always required) and `required` (in force now)
   */
  catalogue(): Array<OfferedRow & { locked: boolean; required: boolean }> {
    const { log, offered } = this.deps;
    log.debug("Entering AttributePolicy.catalogue().");
    let rows: OfferedRow[] = [];
    try {
      rows = offered();
    } catch (e) {
      // The editor could not be asked (a process without it): the policy
      // still answers for the three it always requires.
      log.debug("Caught in AttributePolicy.catalogue(): " +
                ((e && e.message) || e));
      rows = ALWAYS_REQUIRED.map(function (name) {
        return { name: name, label: name, schema: 'RFC 4519' };
      });
    }
    const required = this.required().map(function (one) {
      return one.toLowerCase();
    });
    const seen = new Set<string>();
    const out = rows.filter(function (row) {
      const key = row.name.toLowerCase();
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    }).map(function (row) {
      const key = row.name.toLowerCase();
      return Object.assign({}, row, {
        custom: !!row.custom,
        locked: ALWAYS_REQUIRED.indexOf(key) >= 0,
        required: required.indexOf(key) >= 0 });
    });
    log.debug("Leaving AttributePolicy.catalogue(). " + out.length);
    return out;
  }

  // The offered names, lower-cased name -> canonical spelling; null where
  // the person editor could not be asked, which a READ must not take for
  // "nothing is offered" — that would quietly require less than the stored
  // profile says (a process with no editor, such as the bulk import, would
  // drop givenName and mail).
  private offeredNames(): Record<string, string> | null {
    const { log, offered } = this.deps;
    log.debug("Entering AttributePolicy.offeredNames().");
    const out: Record<string, string> = {};
    ALWAYS_REQUIRED.forEach(function (name) {
      out[name] = name;
    });
    try {
      offered().forEach(function (row) {
        out[row.name.toLowerCase()] = row.name;
      });
    } catch (e) {
      log.debug("Caught in AttributePolicy.offeredNames(): " +
                ((e && e.message) || e));
      log.debug("Leaving AttributePolicy.offeredNames(). Not known.");
      return null;
    }
    log.debug("Leaving AttributePolicy.offeredNames().");
    return out;
  }

  private entryIn(name: string) {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.entryIn().");
    const wanted = name.toLowerCase();
    log.debug("Leaving AttributePolicy.entryIn().");
    return this.directory.allAttributePolicies().filter(function (entry) {
      return String(entry.name || '').toLowerCase() === wanted;
    })[0] || null;
  }

  // THIS REALM'S OWN ENTRY, THEN THE DEFAULT REALM'S.
  private entryFor(name: string):
      { entry: any; from: AttributeProfile['from'] } {
    const { log, realms } = this.deps;
    log.debug("Entering AttributePolicy.entryFor().");
    if (!this.haveDirectory()) {
      log.debug("Leaving AttributePolicy.entryFor(). No directory.");
      return { entry: null, from: 'built-in' };
    }
    const own = this.entryIn(name);
    if (own) {
      log.debug("Leaving AttributePolicy.entryFor(). The realm's own.");
      return { entry: own, from: 'realm' };
    }
    if (realms.isDefault()) {
      log.debug("Leaving AttributePolicy.entryFor(). Built-in.");
      return { entry: null, from: 'built-in' };
    }
    const inherited = realms.run(realms.DEFAULT_REALM, () => {
      log.debug("Entering AttributePolicy.entryFor() default-realm read.");
      const found = this.entryIn(name);
      log.debug("Leaving AttributePolicy.entryFor() default-realm read.");
      return found;
    });
    log.debug("Leaving AttributePolicy.entryFor(). " +
              (inherited ? 'Inherited.' : 'Built-in.'));
    return inherited ? { entry: inherited, from: 'default-realm' }
      : { entry: null, from: 'built-in' };
  }

  /**
   * Reads the profile: this realm's entry, else the default realm's, else
   * the built-in default.
   *
   * Always answers. A stored name this realm does not offer — a custom
   * attribute since removed, or one only the default realm defines — is
   * named in `problems` and is not required here.
   *
   * A NAMED profile (#1241) is the realm's own entry only, never the
   * default realm's; one the realm does not hold reads as `default`.
   *
   * @param name - the profile name; `default` when omitted
   * @returns the profile's values, where they came from, and any problems
   */
  read(name?: string): AttributeProfile {
    const { log } = this.deps;
    log.debug('Entering AttributePolicy.read(). name=' + name);
    const asked = PolicySelection.fold(name) || DEFAULT_PROFILE;
    const own = asked !== DEFAULT_PROFILE && this.haveDirectory()
      ? this.entryIn(asked) : null;
    const profileName = own ? asked : DEFAULT_PROFILE;
    const found: { entry: any; from: AttributeProfile['from'] } = own
      ? { entry: own, from: 'realm' } : this.entryFor(DEFAULT_PROFILE);
    const entry = found.entry;
    const at = entry ? (entry.attributes || {}) : {};
    const offered = this.offeredNames();
    const problems: string[] = [];
    const stored = entry ? this.valuesOf(at, 'stsAttributeRequired') : null;
    const listed = stored === null ? this.listOf(DEFAULTS.requiredAttributes)
                                   : stored;
    const kept: string[] = [];
    listed.forEach(function (one) {
      // Where nothing could say what is offered, every stored name is kept
      // as stored: required, and not reported.
      const canonical = offered ? offered[one.toLowerCase()] : one;
      if (!canonical) {
        problems.push('stsAttributeRequired on ' + (entry ? entry.dn : '') +
                      ' names ' + one.slice(0, 64) + ', which a person in ' +
                      'this realm cannot be given a value for (a custom ' +
                      'attribute removed, or one another realm defines), ' +
                      'so it is not required here.');
        return;
      }
      if (kept.indexOf(canonical) < 0) {
        kept.push(canonical);
      }
    });
    const required = ALWAYS_REQUIRED.slice();
    kept.forEach(function (one) {
      if (required.map(function (r) {
        return r.toLowerCase();
      }).indexOf(one.toLowerCase()) < 0) {
        required.push(one);
      }
    });
    const out: AttributeProfile = {
      name: profileName,
      // 0 for `default`, which is never ranked (#1241).
      precedence: profileName === DEFAULT_PROFILE ? 0
        : PolicySelection.precedenceOf(at, SELECTION),
      stored: found.from === 'realm',
      inherited: found.from === 'default-realm',
      from: found.from,
      dn: entry ? entry.dn : '',
      description: entry ? (this.valuesOf(at, 'description')[0] || '') : '',
      sources: { requiredAttributes: found.from === 'realm' ? 'directory'
        : found.from === 'default-realm' ? 'default realm' : 'built-in' },
      problems: problems,
      enforced: this.enforced(),
      requiredAttributes: kept.join(', '),
      required: required
    };
    log.debug('Leaving AttributePolicy.read(). From ' + found.from + '; ' +
              required.length + ' required.');
    return out;
  }

  /**
   * Lists the profiles: `default`, then this realm's named profiles in
   * precedence order (#1241).
   *
   * @returns the profiles
   */
  list(): AttributeProfile[] {
    const { log } = this.deps;
    log.debug('Entering AttributePolicy.list().');
    const named = this.namedEntries().map((one) => {
      return this.read(one.name);
    }).sort(PolicySelection.compare);
    log.debug('Leaving AttributePolicy.list(). ' + (named.length + 1) +
              ' profile(s).');
    return [this.read(DEFAULT_PROFILE)].concat(named);
  }

  // The realm's own entries, as the directory hook answers them; [] with
  // no directory.
  private entries(): Array<{ name?: string; dn: string;
                             attributes?: Record<string, unknown> }> {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.entries().");
    const out = this.directory
      ? (this.directory.allAttributePolicies() || []) : [];
    log.debug("Leaving AttributePolicy.entries(). " + out.length);
    return out;
  }

  // The realm's own NAMED profiles (#1241): every entry but `default`.
  private namedEntries() {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.namedEntries().");
    const out = PolicySelection.named(this.entries(), SELECTION);
    log.debug("Leaving AttributePolicy.namedEntries(). " + out.length);
    return out;
  }

  // -------------------------------------------------------------------------
  // WHICH PROFILE APPLIES TO A PERSON (#1241, rule 3cx).
  // -------------------------------------------------------------------------
  // The subject a refusal is asked about where the caller named none: the
  // entry as written, its own uid.
  private subjectOf(attributes: Record<string, unknown> | undefined,
                    subject?: Subject | null): Subject {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.subjectOf().");
    const out: Subject = Object.assign({}, subject || {});
    if (out.attributes === undefined) {
      out.attributes = attributes || {};
    }
    if (out.uid === undefined) {
      out.uid = PolicySelection.valuesOf(out.attributes, 'uid')[0] || '';
    }
    log.debug("Leaving AttributePolicy.subjectOf().");
    return out;
  }

  /**
   * Chooses the profile that applies to a person: of the profiles their own
   * `stsAttributePolicy` and each of their groups' name, the lowest
   * precedence (ties by name), else `default`. A reference to a profile the
   * realm does not hold selects nothing and is logged (STS-LDAP-0196).
   *
   * @param subject - `uid` (their groups are read by it), `attributes` (the
   *   entry as it is or will be; their own reference is read from it) and
   *   `groups` (any the same write adds, by cn or DN)
   * @returns `{ name, by, holder, precedence, missing }`
   */
  selectionFor(subject?: Subject | null) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AttributePolicy.selectionFor().");
    const s = subject || {};
    const none = { name: DEFAULT_PROFILE, by: DEFAULT_PROFILE, holder: '',
                   precedence: 0, missing: [] as Array<{ by: string;
                     holder: string; name: string }> };
    if (!this.haveDirectory()) {
      log.debug("Leaving AttributePolicy.selectionFor(). No directory.");
      return none;
    }
    const entries = this.entries();
    const uid = String(s.uid || '').trim();
    const own = PolicySelection.valuesOf(s.attributes,
                                         REFERENCES.person)[0] || '';
    // NOTHING NAMED, NOTHING TO ASK: a realm with no named profile and a
    // person naming none answers `default` without reading their groups.
    if (!PolicySelection.named(entries, SELECTION).length &&
        !PolicySelection.fold(own)) {
      log.debug("Leaving AttributePolicy.selectionFor(). None named.");
      return none;
    }
    const references: Array<{ by: string; holder?: string;
                              value: unknown }> = [
      { by: 'person', holder: uid, value: own }
    ];
    const held = this.directory.personGroupReferences;
    const groups = uid && typeof held === 'function'
      ? (held.call(this.directory, uid, REFERENCES.group) || []) : [];
    const addedHook = this.directory.groupReferences;
    const added = (s.groups || []).length && typeof addedHook === 'function'
      ? (addedHook.call(this.directory, s.groups, REFERENCES.group) || [])
      : [];
    const ranked = PolicySelection.rank(entries, SELECTION, references
      .concat(PolicySelection.groupReferences(groups.concat(added))));
    ranked.missing.forEach(function (one) {
      // A REFERENCE NO PROFILE ANSWERS selects nothing: the person is held
      // to what the rest of their references name, or to `default` — the
      // floor every other person here is held to. See the header.
      log.warn(errorCodes.tag('STS-LDAP-0196') + 'attribute policy: the ' +
               one.by + ' "' + one.holder + '" names the attribute policy "' +
               one.name + '", which this realm does not hold; it selects ' +
               'nothing, and ' + (ranked.name === DEFAULT_PROFILE
                 ? '`default`' : '"' + ranked.name + '"') + ' applies.');
    });
    log.debug("Leaving AttributePolicy.selectionFor(). " + ranked.name +
              " by " + ranked.by);
    return ranked;
  }

  /**
   * Reads the profile that applies to a person (`selectionFor()`).
   *
   * @param subject - as `selectionFor()` takes it; none is `default`
   * @returns the profile
   */
  profileFor(subject?: Subject | null): AttributeProfile {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.profileFor().");
    const out = this.read(subject ? this.selectionFor(subject).name
                                  : DEFAULT_PROFILE);
    log.debug("Leaving AttributePolicy.profileFor(). " + out.name);
    return out;
  }

  /**
   * Returns every attribute a person in this realm must hold, in its
   * canonical spelling: `uid`, `cn` and `sn`, then the profile's — the
   * profile that applies to the subject (#1241), `default` without one.
   *
   * @param subject - whose profile; as `selectionFor()` takes it
   * @returns the names
   */
  required(subject?: Subject | null): string[] {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.required().");
    let out: string[];
    try {
      out = this.profileFor(subject).required;
    } catch (e) {
      // A policy that cannot be read still requires what the schema does.
      log.debug("Caught in AttributePolicy.required(): " +
                ((e && e.message) || e));
      out = ALWAYS_REQUIRED.slice();
    }
    log.debug("Leaving AttributePolicy.required(). " + out.length);
    return out;
  }

  /**
   * Says whether the policy is enforced in the ambient realm: in product
   * mode.
   *
   * @returns true in product mode
   */
  enforced(): boolean {
    const { log, createsIncompletePeople } = this.deps;
    log.debug("Entering AttributePolicy.enforced().");
    const out = !createsIncompletePeople();
    log.debug("Leaving AttributePolicy.enforced(). " + out);
    return out;
  }

  // Whether an attribute map (any case of name, a value or a list of them)
  // holds a non-empty value of a name.
  private holds(attributes: Record<string, unknown>, name: string): boolean {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.holds(). " + name);
    const wanted = name.toLowerCase();
    const out = Object.keys(attributes || {}).some(function (key) {
      if (key.toLowerCase() !== wanted) {
        return false;
      }
      const value = attributes[key];
      return (Array.isArray(value) ? value : [value]).some(function (one) {
        return one !== undefined && one !== null &&
               String(one).trim() !== '';
      });
    });
    log.debug("Leaving AttributePolicy.holds(). " + out);
    return out;
  }

  /**
   * Lists the required attributes a person's attributes hold no value of,
   * whether or not the policy is enforced — against the profile that
   * applies to them (#1241).
   *
   * @param attributes - the attributes, any case of name, a value or a list
   * @param subject - whose profile; by default the entry itself: its uid
   *   and its own reference
   * @returns the missing names, in the policy's order
   */
  missingFrom(attributes: Record<string, unknown>,
              subject?: Subject | null): string[] {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.missingFrom().");
    const out = this.required(this.subjectOf(attributes, subject))
      .filter((name) => {
        return !this.holds(attributes || {}, name);
      });
    log.debug("Leaving AttributePolicy.missingFrom(). " + out.length);
    return out;
  }

  /**
   * Lists the required attributes an edit would take away: held before and
   * not after. A required attribute the person already lacked is not one.
   * Asked of the profile that applies to the person as the edit leaves them
   * (#1241).
   *
   * @param before - the attributes before the edit
   * @param after - the attributes after it
   * @param subject - whose profile; by default the entry as it will be
   * @returns the names
   */
  removedBy(before: Record<string, unknown>,
            after: Record<string, unknown>,
            subject?: Subject | null): string[] {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.removedBy().");
    const out = this.required(this.subjectOf(after, subject))
      .filter((name) => {
        return this.holds(before || {}, name) &&
               !this.holds(after || {}, name);
      });
    log.debug("Leaving AttributePolicy.removedBy(). " + out.length);
    return out;
  }

  // Who a refusal says requires it (#1241): the realm's policy, or the
  // named one that applies.
  private whose(profile: AttributeProfile): string {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.whose().");
    log.debug("Leaving AttributePolicy.whose().");
    return profile.name === DEFAULT_PROFILE
      ? 'This realm\'s attribute policy requires every person'
      : 'The attribute policy "' + profile.name + '", which applies to ' +
        'this person, requires them';
  }

  /**
   * The refusal of a create, where the policy is enforced and something the
   * profile that applies requires is missing: the names, the profile and a
   * sentence. Null otherwise.
   *
   * WHOSE PROFILE (#1241): the person the write creates — the reference the
   * write sets on them, the groups already listing the DN they will have,
   * and `subject.groups`, any the same write adds.
   *
   * @param attributes - the attributes the person would be created with
   * @param subject - whose profile; by default the entry itself
   * @returns `{ missing, policy, message }`, or null
   */
  createRefusal(attributes: Record<string, unknown>,
                subject?: Subject | null): CreateRefusal | null {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.createRefusal().");
    if (!this.enforced()) {
      log.debug("Leaving AttributePolicy.createRefusal(). Not enforced.");
      return null;
    }
    const profile = this.profileFor(this.subjectOf(attributes, subject));
    const missing = profile.required.filter((name) => {
      return !this.holds(attributes || {}, name);
    });
    if (!missing.length) {
      log.debug("Leaving AttributePolicy.createRefusal(). Complete.");
      return null;
    }
    log.debug("Leaving AttributePolicy.createRefusal(). " + missing.length +
              " missing under " + profile.name + ".");
    return { missing: missing, policy: profile.name,
             message: this.whose(profile) + ' to hold ' +
                      profile.required.join(', ') + ', and this one would ' +
                      'have no value of ' + missing.join(', ') + '. ' +
                      'Directory > Policies > Attribute policy sets the ' +
                      'list.' };
  }

  /**
   * The refusal of an edit, where the policy is enforced and the edit would
   * take away a value the profile that applies requires. Null otherwise.
   *
   * WHOSE PROFILE (#1241): the person's as the edit leaves them — their own
   * reference after it, and the groups they are in.
   *
   * @param before - the attributes before the edit
   * @param after - the attributes after it
   * @param subject - whose profile; by default the entry as it will be
   * @returns `{ removed, policy, message }`, or null
   */
  editRefusal(before: Record<string, unknown>,
              after: Record<string, unknown>,
              subject?: Subject | null): EditRefusal | null {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.editRefusal().");
    if (!this.enforced()) {
      log.debug("Leaving AttributePolicy.editRefusal(). Not enforced.");
      return null;
    }
    const profile = this.profileFor(this.subjectOf(after, subject));
    const removed = profile.required.filter((name) => {
      return this.holds(before || {}, name) && !this.holds(after || {}, name);
    });
    if (!removed.length) {
      log.debug("Leaving AttributePolicy.editRefusal(). Nothing taken.");
      return null;
    }
    log.debug("Leaving AttributePolicy.editRefusal(). " + removed.length +
              " taken away under " + profile.name + ".");
    return { removed: removed, policy: profile.name,
             message: this.whose(profile) + ' to hold ' +
                      removed.join(', ') + ', so the edit may not leave ' +
                      (removed.length === 1 ? 'it' : 'them') + ' without a ' +
                      'value. Set another value instead.' };
  }

  /**
   * Gives an attribute map a `cn` of "givenName sn" where it names none and
   * holds either: `cn` is on `person`'s MUST list, and somebody who gave a
   * given name and a surname has said what it is. The map is changed in
   * place; nothing is derived where it already holds a `cn`.
   *
   * @param attributes - the attributes, any case of name, a value or a list
   * @returns true when a cn was written
   */
  deriveCommonName(attributes: Record<string, unknown>): boolean {
    const { log } = this.deps;
    log.debug('Entering AttributePolicy.deriveCommonName().');
    const valueOf = function (name: string): string {
      log.debug('Entering valueOf().');
      const key = Object.keys(attributes).filter(function (one) {
        return one.toLowerCase() === name;
      })[0];
      const values = key === undefined ? [] : [].concat(attributes[key]);
      log.debug('Leaving valueOf().');
      return String(values.filter(function (one) {
        return one !== undefined && one !== null && String(one).trim() !== '';
      })[0] || '').trim();
    };
    if (valueOf('cn')) {
      log.debug('Leaving AttributePolicy.deriveCommonName(). It has one.');
      return false;
    }
    const derived = [valueOf('givenname'), valueOf('sn')].filter(Boolean)
      .join(' ');
    if (!derived) {
      log.debug('Leaving AttributePolicy.deriveCommonName(). Nothing to ' +
                'make one of.');
      return false;
    }
    Object.keys(attributes).forEach(function (one) {
      if (one.toLowerCase() === 'cn') {
        delete attributes[one];
      }
    });
    attributes.cn = [derived];
    log.debug('Leaving AttributePolicy.deriveCommonName(). Derived.');
    return true;
  }

  /**
   * Counts the people in this realm who lack a value of an attribute their
   * own profile requires — those created before the policy said so, or in
   * development mode.
   *
   * EACH AGAINST THEIR OWN PROFILE (#1241), in the ONE walk the count was
   * already: the directory hands each person's username and own reference
   * to the judge below, which reads their groups' references off the group
   * index (`personGroupReferences()`, no walk) and ranks. The required list
   * of each profile is read once, and the answer for each distinct set of
   * references is kept for the count, so the added cost is an index lookup
   * per person. A realm with no named profile hands the directory `default`'s
   * list, as before; and where no group names one, no group is read.
   *
   * @returns the count, or null where there is no directory to ask, or the
   *   directory does not walk (a directory in the store)
   */
  peopleMissing(): number | null {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.peopleMissing().");
    if (!this.haveDirectory()) {
      log.debug("Leaving AttributePolicy.peopleMissing(). No directory.");
      return null;
    }
    let out: number | null = null;
    try {
      const raw = this.directory.missing(this.missingJudge());
      out = raw === null || raw === undefined ? null : (Number(raw) || 0);
    } catch (e) {
      log.debug("Caught in AttributePolicy.peopleMissing(): " +
                ((e && e.message) || e));
      out = null;
    }
    log.debug("Leaving AttributePolicy.peopleMissing(). " + out);
    return out;
  }

  // What `peopleMissing()` hands the directory (#1241): `default`'s list
  // where nothing is named, else a function from a person to the lower-cased
  // names their profile requires.
  private missingJudge(): string[] |
      ((username: string, reference: string) => string[]) {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.missingJudge().");
    const lower = function (names: string[]): string[] {
      log.debug("Entering missingJudge() lower().");
      log.debug("Leaving missingJudge() lower().");
      return names.map(function (one) {
        return one.toLowerCase();
      });
    };
    const entries = this.entries();
    const named = PolicySelection.named(entries, SELECTION);
    if (!named.length) {
      log.debug("Leaving AttributePolicy.missingJudge(). default alone.");
      return lower(this.required());
    }
    // A GROUP IS READ ONLY WHERE A GROUP NAMES ONE OF THESE.
    const naming = this.directory.groupsNamingPolicy;
    const groupsName = typeof naming === 'function' &&
      named.some((one) => {
        return (naming.call(this.directory, REFERENCES.group, one.name) ||
                []).length > 0;
      });
    const lists: Record<string, string[]> = {};
    const listOf = (name: string): string[] => {
      log.debug("Entering missingJudge() listOf(). " + name);
      if (!lists[name]) {
        lists[name] = lower(this.read(name).required);
      }
      log.debug("Leaving missingJudge() listOf().");
      return lists[name];
    };
    const answers = new Map<string, string[]>();
    const held = this.directory.personGroupReferences;
    const directory = this.directory;
    // ONCE PER PERSON on the count's walk: no Entering/Leaving pair, the
    // hot-path exception, stated as the style requires. A reference that
    // names nothing the realm holds is not logged here either — a line per
    // person would drown the log; the count is the answer.
    const judge = function (username: string, reference: string): string[] {
      const groups = groupsName && typeof held === 'function'
        ? (held.call(directory, username, REFERENCES.group) || []) : [];
      const references: Array<{ by: string; holder?: string;
                                value: unknown }> = [
        { by: 'person', holder: username, value: reference }
      ];
      PolicySelection.groupReferences(groups).forEach(function (one) {
        references.push(one);
      });
      const key = references.map(function (one) {
        return PolicySelection.fold(one.value);
      }).join('|');
      let found = answers.get(key);
      if (!found) {
        found = listOf(PolicySelection.rank(entries, SELECTION,
                                            references).name);
        answers.set(key, found);
      }
      return found;
    };
    log.debug("Leaving AttributePolicy.missingJudge(). By person.");
    return judge;
  }

  /**
   * Describes the profile in sentences, for the page and a save's answer.
   *
   * @param profile - a profile already read; `default` read when omitted
   * @returns the sentences
   */
  describe(profile?: AttributeProfile | null): string[] {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.describe().");
    const rules = profile || this.read(DEFAULT_PROFILE);
    const fill = serverProse.fill;
    const custom = this.definitions();
    const out = [
      fill(SENTENCES.required, { list: rules.required.join(', ') }),
      rules.enforced ? SENTENCES.enforced : SENTENCES.notEnforced,
      custom.length
        ? fill(SENTENCES.custom, { n: String(custom.length),
                                   list: custom.map(function (one) {
                                     return one.name;
                                   }).join(', ') })
        : SENTENCES.noCustom
    ];
    // A NAMED PROFILE says whom it reaches (#1241).
    if (rules.name !== DEFAULT_PROFILE) {
      out.splice(1, 0, fill(SENTENCES.named,
                            { precedence: String(rules.precedence) }));
    }
    log.debug("Leaving AttributePolicy.describe().");
    return out;
  }

  // -------------------------------------------------------------------------
  // WRITING THE PROFILE.
  // -------------------------------------------------------------------------
  private checkProfileName(name: unknown): string | null {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.checkProfileName().");
    // `default`, or a name a cn may be (#1241: named profiles).
    const out = PolicySelection.nameProblem(
      name === undefined || name === null || name === '' ? DEFAULT_PROFILE
                                                         : name,
      NOUN, true);
    log.debug("Leaving AttributePolicy.checkProfileName(). " +
              (out ? 'Refused.' : 'A name.'));
    return out;
  }

  /**
   * Validates a whole profile as sent: every name must be one a person here
   * may be given a value for. A console form that ticks nothing sends no
   * field, which is an empty list there and a refusal from an API caller.
   *
   * @param given - the submitted fields
   * @returns the canonical names and the problems found
   */
  validate(given?: Record<string, any> | null) {
    const { log } = this.deps;
    log.debug('Entering AttributePolicy.validate().');
    const body = given || {};
    const problems: string[] = [];
    let raw = body.requiredAttributes;
    if (raw === undefined && body.form === 'console') {
      raw = '';
    }
    if (raw === undefined) {
      problems.push('`requiredAttributes` (' + FIELDS[0].label + ') is ' +
                    'required. A save replaces the whole profile, so the ' +
                    'list is sent, empty for none beyond uid, cn and sn.');
      log.debug('Leaving AttributePolicy.validate(). No field.');
      return { values: [] as string[], problems: problems };
    }
    // A SAVE is refused where the editor cannot be asked: nothing could say
    // whether a name is one a person may hold.
    const offered = this.offeredNames() || {};
    const items = this.listOf(raw);
    if (items.length > 256) {
      problems.push('At most 256 attributes may be required.');
    }
    const values: string[] = [];
    const unknown: string[] = [];
    items.forEach(function (one) {
      const canonical = offered[one.toLowerCase()];
      if (!canonical) {
        unknown.push(one.slice(0, 64));
        return;
      }
      if (values.indexOf(canonical) < 0) {
        values.push(canonical);
      }
    });
    if (unknown.length) {
      problems.push('A person in this realm cannot be given a value for ' +
                    unknown.join(', ') + ', so ' +
                    (unknown.length === 1 ? 'it' : 'they') + ' cannot be ' +
                    'required. The attributes the policy may require are ' +
                    'the ones on its tab: the inetOrgPerson schema, the ' +
                    'credential catalogue, mail and this realm\'s custom ' +
                    'attributes — never userPassword, a binary attribute, ' +
                    'memberOf or an sts attribute.');
    }
    log.debug('Leaving AttributePolicy.validate(). ' + problems.length +
              ' problem(s).');
    return { values: values, problems: problems };
  }

  /**
   * Saves the profile of this realm, replacing it whole.
   *
   * @param name - the profile name: `default`, or a named profile's
   *   (#1241), created by its first save
   * @param given - `requiredAttributes`, an optional `description`, and a
   *   named profile's `precedence` (1 to 1000, 100 when omitted)
   * @returns `ok` and the profile now in force, or `ok: false` with `errors`
   */
  save(name: unknown, given?: Record<string, any> | null): PolicyResult {
    const { log, errorCodes } = this.deps;
    log.debug('Entering AttributePolicy.save(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving AttributePolicy.save(). Not a profile.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-LDAP-0165');
    }
    const which = PolicySelection.fold(name) || DEFAULT_PROFILE;
    const checked = this.validate(given);
    // A NAMED PROFILE'S PRECEDENCE (#1241), refused with the rows.
    const selectors = which === DEFAULT_PROFILE ? null
      : PolicySelection.checkPrecedence(given || {}, SELECTION);
    if (selectors) {
      selectors.problems.forEach(function (one) {
        checked.problems.push(one);
      });
    }
    if (checked.problems.length) {
      log.debug('Leaving AttributePolicy.save(). The values were refused.');
      return errorCodes.mark({ ok: false, errors: checked.problems },
                             'STS-LDAP-0166');
    }
    if (!this.haveDirectory()) {
      log.debug('Leaving AttributePolicy.save(). No directory.');
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep an attribute policy. ' +
                        'ou=attributePolicies IS the register.'] },
                             'STS-LDAP-0167');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'stsAttributePolicy'],
      description: String((given && given.description) || '').slice(0, 1024),
      // EVERY VALUE, AND NONE FOR AN EMPTY LIST: an entry with no
      // stsAttributeRequired is a profile requiring only the three always
      // required, which is a choice and not a missing field — `read()` tells
      // the two apart by the entry being there.
      stsAttributeRequired: checked.values
    };
    if (!attributes.description) {
      delete attributes.description;
    }
    if (!checked.values.length) {
      delete attributes.stsAttributeRequired;
    }
    if (selectors) {
      attributes[SELECTION.precedenceAttribute] =
        String(selectors.precedence);
    }
    const written = this.directory.writeAttributePolicy(which, attributes);
    if (!written) {
      log.debug('Leaving AttributePolicy.save(). The directory refused.');
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the profile — it is ' +
                        'at its maximum number of entries.'] },
                             'STS-LDAP-0168');
    }
    log.debug('Leaving AttributePolicy.save(). Stored ' + which + '.');
    return { ok: true, profile: this.read(which) };
  }

  /**
   * Deletes this realm's `default` profile, after which it follows the
   * default realm's, or the built-in default; or deletes a NAMED profile
   * (#1241), which is refused while a person or a group names it
   * (STS-LDAP-0197).
   *
   * The people naming a profile are the holders of `stsAttributePolicy`,
   * asked asynchronously (rcbj's rule: no synchronous walk on a request),
   * so the delete of a named profile answers a PROMISE; `default`'s answers
   * at once.
   *
   * @param name - the profile name
   * @returns `ok`, whether an entry was removed, and the profile now in
   *   force — or a promise of it, for a named profile
   */
  reset(name: unknown): PolicyResult | Promise<PolicyResult> {
    const { log, errorCodes } = this.deps;
    log.debug('Entering AttributePolicy.reset(). name=' + name);
    const refused = this.checkProfileName(name);
    if (refused) {
      log.debug('Leaving AttributePolicy.reset(). Not a profile.');
      return errorCodes.mark({ ok: false, errors: [refused] },
                             'STS-LDAP-0165');
    }
    const which = PolicySelection.fold(name) || DEFAULT_PROFILE;
    if (!this.haveDirectory()) {
      log.debug('Leaving AttributePolicy.reset(). No directory.');
      return { ok: true, removed: false, profile: this.read(which) };
    }
    if (which === DEFAULT_PROFILE) {
      const removed = !!this.directory.deleteAttributePolicy(DEFAULT_PROFILE);
      log.debug('Leaving AttributePolicy.reset(). ' +
                (removed ? 'Removed.' : 'Nothing stored.'));
      return { ok: true, removed: removed,
               profile: this.read(DEFAULT_PROFILE) };
    }
    log.debug('Leaving AttributePolicy.reset(). Asking who names ' + which +
              '.');
    return this.namedByAsync(which).then((holders) => {
      log.debug('Entering AttributePolicy.reset() after namedByAsync().');
      // NOT WHILE A PERSON OR A GROUP NAMES IT (#1241, rule 3cx): they
      // would be left naming a profile the realm does not hold.
      const held = PolicySelection.deleteProblem(NOUN, which, holders);
      if (held) {
        log.debug('Leaving AttributePolicy.reset() after namedByAsync(). ' +
                  'Still named.');
        return errorCodes.mark({ ok: false, errors: [held] },
                               'STS-LDAP-0197') as PolicyResult;
      }
      const removed = !!this.directory.deleteAttributePolicy(which);
      log.debug('Leaving AttributePolicy.reset() after namedByAsync(). ' +
                (removed ? 'Removed.' : 'Nothing stored.'));
      return { ok: true, removed: removed, profile: this.read(which) };
    });
  }

  /**
   * What names a named profile, as far as it can be told without a walk:
   * the groups (the directory's group index). Nobody names an attribute
   * profile from an application. The people are `namedByAsync()`'s.
   *
   * @param name - the profile's name
   * @returns `{ applications, groups, people }`; `people` empty here
   */
  namedBy(name: unknown): { applications: string[]; groups: string[];
                            people: string[] } {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.namedBy().");
    const hook = this.haveDirectory() ? this.directory.groupsNamingPolicy
      : null;
    const groups = typeof hook === 'function'
      ? (hook.call(this.directory, REFERENCES.group,
                   PolicySelection.fold(name)) || []) : [];
    log.debug("Leaving AttributePolicy.namedBy(). " + groups.length +
              " group(s).");
    return { applications: [], groups: groups, people: [] };
  }

  /**
   * What names a named profile (#1241): the groups, and the people whose
   * own `stsAttributePolicy` names it — the holders of that attribute,
   * asked of the directory asynchronously, at most fifty names.
   *
   * @param name - the profile's name
   * @returns a promise of `{ applications, groups, people, complete }`
   */
  async namedByAsync(name: unknown): Promise<{
      applications: string[]; groups: string[]; people: string[];
      complete: boolean }> {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.namedByAsync().");
    const out = Object.assign({ complete: true }, this.namedBy(name));
    const hook = this.haveDirectory()
      ? this.directory.peopleNamingPolicyAsync : null;
    if (typeof hook === 'function') {
      const found = await hook.call(this.directory, REFERENCES.person,
                                    PolicySelection.fold(name));
      out.people = (found && found.people) || [];
      out.complete = !found || found.complete !== false;
    }
    log.debug("Leaving AttributePolicy.namedByAsync(). " +
              out.people.length + " person(s).");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE CUSTOM ATTRIBUTE REGISTER.
  // -------------------------------------------------------------------------
  /**
   * Lists this realm's custom attributes, by name.
   *
   * @returns the definitions
   */
  definitions(): Definition[] {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.definitions().");
    if (!this.directory) {
      log.debug("Leaving AttributePolicy.definitions(). No directory.");
      return [];
    }
    let rows: Definition[] = [];
    try {
      rows = this.directory.allAttributeDefinitions().map((entry) => {
        const at = entry.attributes || {};
        const syntax = (this.valuesOf(at, 'stsAttributeSyntax')[0] ||
                        'string').toLowerCase();
        return {
          name: String(entry.name || ''),
          label: this.valuesOf(at, 'stsAttributeLabel')[0] ||
                 String(entry.name || ''),
          syntax: SYNTAXES.some(function (one) {
            return one.id === syntax;
          }) ? syntax : 'string',
          multi: String(this.valuesOf(at, 'stsAttributeSingleValued')[0] ||
                        'TRUE').toUpperCase() !== 'TRUE',
          description: this.valuesOf(at, 'description')[0] || '',
          dn: entry.dn
        };
      }).filter(function (one) {
        return DESCR.test(one.name);
      }).sort(function (a, b) {
        return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1;
      });
    } catch (e) {
      // A register that cannot be read offers nothing extra: the schema's
      // attributes are still every person's.
      log.debug("Caught in AttributePolicy.definitions(): " +
                ((e && e.message) || e));
      rows = [];
    }
    log.debug("Leaving AttributePolicy.definitions(). " + rows.length);
    return rows;
  }

  /**
   * Returns one custom attribute of this realm, by name in any case.
   *
   * @param name - the attribute
   * @returns the definition, or null
   */
  definition(name: unknown): Definition | null {
    const { log } = this.deps;
    log.debug("Entering AttributePolicy.definition().");
    const wanted = String(name || '').trim().toLowerCase();
    const out = this.definitions().filter(function (one) {
      return one.name.toLowerCase() === wanted;
    })[0] || null;
    log.debug("Leaving AttributePolicy.definition(). " + !!out);
    return out;
  }

  /**
   * Defines a custom attribute in this realm.
   *
   * @param body - `name`, `label`, `syntax`, `multiValued` (or `values`:
   *   `single` or `multiple`) and an optional `description`
   * @returns `{ ok: true, definition, message }`, or a refusal with a code
   */
  define(body?: Record<string, any> | null) {
    const { log, errorCodes } = this.deps;
    const given = body || {};
    const name = String(given.name === undefined ? '' : given.name).trim();
    log.debug("Entering AttributePolicy.define(). " + name);
    const problems: string[] = [];
    if (!DESCR.test(name)) {
      problems.push('A custom attribute\'s name is a letter followed by ' +
                    'letters, digits and hyphens, at most 64 (RFC 4512 ' +
                    'section 1.4, a descr); "' + name.slice(0, 64) + '" is ' +
                    'not one.');
    }
    const label = String(given.label === undefined ? '' : given.label).trim();
    if (!label || label.length > 128 || CONTROL.test(label)) {
      problems.push('A custom attribute needs a label of at most 128 ' +
                    'characters with no control character: it is what the ' +
                    'pages draw beside the name.');
    }
    const syntax = String(given.syntax === undefined ? 'string'
                                                     : given.syntax)
      .trim().toLowerCase() || 'string';
    if (!SYNTAXES.some(function (one) {
      return one.id === syntax;
    })) {
      problems.push('"' + syntax.slice(0, 32) + '" is not a syntax here; ' +
                    'the syntaxes are ' + SYNTAXES.map(function (one) {
                      return one.id;
                    }).join(', ') + '.');
    }
    const multiRaw = given.multiValued !== undefined ? given.multiValued
      : given.values;
    const multiText = String(multiRaw === undefined ? '' : multiRaw)
      .trim().toLowerCase();
    let multi = false;
    if (['true', 'on', '1', 'yes', 'multiple'].indexOf(multiText) >= 0) {
      multi = true;
    } else if (['false', 'off', '0', 'no', 'single', ''].indexOf(
        multiText) < 0) {
      problems.push('Whether a custom attribute holds several values is ' +
                    'yes or no (single or multiple); "' +
                    multiText.slice(0, 32) + '" is neither.');
    }
    const description = String(given.description === undefined
      ? '' : given.description).trim();
    if (description.length > 1024 || CONTROL.test(description)) {
      problems.push('A description is at most 1024 characters with no ' +
                    'control character.');
    }
    if (problems.length) {
      log.debug("Leaving AttributePolicy.define(). Refused.");
      return errorCodes.mark({ ok: false, errors: problems },
                             'STS-LDAP-0169');
    }
    if (!this.haveDirectory()) {
      log.debug("Leaving AttributePolicy.define(). No directory.");
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is nowhere to keep a custom attribute. ' +
                        'ou=attributeDefinitions IS the register.'] },
                             'STS-LDAP-0167');
    }
    const lower = name.toLowerCase();
    const known = String(this.directory.knownName(name) || '');
    const existing = this.definition(name);
    if (lower.indexOf('sts') === 0 || lower === 'memberof' || known ||
        existing) {
      log.debug("Leaving AttributePolicy.define(). The name is taken.");
      return errorCodes.mark({ ok: false, errors: [existing
        ? 'This realm already defines ' + existing.name + ' (' +
          existing.dn + '). Remove it first to define it again.'
        : lower.indexOf('sts') === 0
          ? 'A name beginning "sts" is this service\'s own: its ' +
            'credentials and records are spelt that way, and a custom ' +
            'attribute under one would be read as one of them.'
          : lower === 'memberof'
            ? 'memberOf is the directory\'s record of group membership, ' +
              'which grants the console roles; it is never an attribute an ' +
              'editor offers.'
            : 'The directory already knows ' + known + ' (a schema, ' +
              'catalogue or service attribute), so it cannot be defined ' +
              'again as a custom attribute.'] }, 'STS-LDAP-0170');
    }
    if (this.definitions().length >= MAX_DEFINITIONS) {
      log.debug("Leaving AttributePolicy.define(). The realm is full.");
      return errorCodes.mark({ ok: false,
               errors: ['This realm defines its maximum of ' +
                        MAX_DEFINITIONS + ' custom attributes.'] },
                             'STS-LDAP-0171');
    }
    const attributes: Record<string, unknown> = {
      objectClass: ['top', 'stsAttributeDefinition'],
      stsAttributeLabel: label,
      stsAttributeSyntax: syntax,
      stsAttributeSingleValued: multi ? 'FALSE' : 'TRUE'
    };
    if (description) {
      attributes.description = description;
    }
    if (!this.directory.writeAttributeDefinition(name, attributes)) {
      log.debug("Leaving AttributePolicy.define(). The directory refused.");
      return errorCodes.mark({ ok: false,
               errors: ['The directory would not store the definition — it ' +
                        'is at its maximum number of entries.'] },
                             'STS-LDAP-0168');
    }
    const made = this.definition(name);
    log.debug("Leaving AttributePolicy.define(). Defined.");
    return { ok: true, definition: made,
             message: serverProse.fill(SENTENCES.defined,
                                       { name: name,
                                         dn: made ? made.dn : '' }) };
  }

  /**
   * Removes a custom attribute of this realm, while nobody holds a value of
   * it and this realm's own profile does not require it.
   *
   * @param name - the attribute
   * @returns `{ ok: true, removed, message }`, or a refusal with a code
   */
  undefine(name: unknown) {
    const { log, errorCodes } = this.deps;
    const wanted = String(name === undefined || name === null ? ''
                                                              : name).trim();
    log.debug("Entering AttributePolicy.undefine(). " + wanted);
    if (!this.haveDirectory()) {
      log.debug("Leaving AttributePolicy.undefine(). No directory.");
      return errorCodes.mark({ ok: false,
               errors: ['There is no embedded directory in this process, so ' +
                        'there is no custom attribute to remove.'] },
                             'STS-LDAP-0167');
    }
    const found = this.definition(wanted);
    if (!found) {
      log.debug("Leaving AttributePolicy.undefine(). Not defined.");
      return errorCodes.mark({ ok: false,
               errors: ['This realm defines no custom attribute called "' +
                        wanted.slice(0, 64) + '".'] }, 'STS-LDAP-0174');
    }
    // NOT WHILE ANY OF THE REALM'S OWN PROFILES REQUIRES IT — `default`
    // where it is stored here, and every named one (#1241).
    const requiring = this.list().filter(function (profile) {
      return profile.stored && profile.required.map(function (one) {
        return one.toLowerCase();
      }).indexOf(found.name.toLowerCase()) >= 0;
    }).map(function (profile) {
      return profile.name;
    });
    if (requiring.length) {
      log.debug("Leaving AttributePolicy.undefine(). Required.");
      return errorCodes.mark({ ok: false,
               errors: ['This realm\'s attribute ' +
                        (requiring.length === 1 ? 'policy "' +
                          requiring[0] + '" requires '
                          : 'policies ' + requiring.join(', ') +
                            ' require ') +
                        found.name + '. Take it off the required list ' +
                        'first.'] }, 'STS-LDAP-0173');
    }
    const holders = Number(this.directory.holders(found.name)) || 0;
    if (holders > 0) {
      log.debug("Leaving AttributePolicy.undefine(). Held.");
      return errorCodes.mark({ ok: false,
               errors: [holders + ' ' + (holders === 1 ? 'person holds'
                                                       : 'people hold') +
                        ' a value of ' + found.name + ', and a definition ' +
                        'removed from under its values would leave data no ' +
                        'door here offers again. Remove the values first.'],
               holders: holders }, 'STS-LDAP-0172');
    }
    const removed = !!this.directory.deleteAttributeDefinition(found.name);
    log.debug("Leaving AttributePolicy.undefine(). " + removed);
    return { ok: true, removed: removed, name: found.name, dn: found.dn,
             message: serverProse.fill(SENTENCES.undefined,
                                       { name: found.name }) };
  }

  /**
   * Answers one of this kind's two acts beside save and reset
   * (`admin-core/policy_kinds.ts`'s `extraActions`): a custom attribute
   * defined or removed.
   *
   * @param action - `define-person-attribute` or `remove-person-attribute`
   * @param body - the act's body
   * @returns the act's answer, or a refusal naming the two acts
   */
  act(action: string, body: Record<string, any>) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering AttributePolicy.act(). " + action);
    if (action === 'define-person-attribute') {
      const out = this.define(body);
      log.debug("Leaving AttributePolicy.act(). define " + out.ok);
      return out;
    }
    if (action === 'remove-person-attribute') {
      const out = this.undefine((body || {}).name);
      log.debug("Leaving AttributePolicy.act(). remove " + out.ok);
      return out;
    }
    log.debug("Leaving AttributePolicy.act(). Not an act.");
    return errorCodes.mark({ ok: false,
             errors: ['"' + String(action).slice(0, 64) + '" is not an act ' +
                      'of the attribute policy; its two are ' +
                      'define-person-attribute and remove-person-attribute.'] },
                           'STS-ADMIN-0500');
  }
}

const slot = new InstanceSlot<AttributePolicy>(
  'common/attribute_policy',
  () => new AttributePolicy(AttributePolicy.defaultDeps()),
  null,
  log);

slot.buildNowUnlessDeferred();

// A PERSON AND A GROUP NAME THEIR ATTRIBUTE PROFILE (#1241, rule 3cx):
// declared, so the person page and the group page draw the picker and their
// writers check it, offering `default` and the realm's named profiles as
// they stand when asked.
const referenceChoices = function referenceChoices(): string[] {
  log.debug("Entering attribute policy reference choices.");
  const names = slot.get().list().map(function (one) {
    return String(one.name);
  });
  log.debug("Leaving attribute policy reference choices.");
  return names;
};
PolicySelection.declareReference('group', REFERENCES.group, NOUN,
                                 referenceChoices);
PolicySelection.declareReference('person', REFERENCES.person, NOUN,
                                 referenceChoices);

/**
 * The attribute policy (#396): the attributes every person in a realm must
 * hold, and the realm's custom attributes. The sixth policy on Directory >
 * Policies. The exports forward to the instance the composition root
 * installs.
 *
 * @namespace
 */
export = {
  AttributePolicy: AttributePolicy,
  /**
   * Installs the instance the module-level functions forward to.
   */
  installInstance: (instance: AttributePolicy): void => slot.install(instance),
  /**
   * Says where the installed instance came from.
   */
  instanceOrigin: (): string => slot.origin(),
  DEFAULT_PROFILE: AttributePolicy.DEFAULT_PROFILE,
  DEFAULTS: AttributePolicy.DEFAULTS,
  FIELDS: AttributePolicy.FIELDS,
  FIELD_BY_KEY: AttributePolicy.FIELD_BY_KEY,
  SCHEMA: AttributePolicy.SCHEMA,
  SENTENCES: AttributePolicy.SENTENCES,
  ALWAYS_REQUIRED: AttributePolicy.ALWAYS_REQUIRED,
  SYNTAXES: AttributePolicy.SYNTAXES,
  MAX_DEFINITIONS: AttributePolicy.MAX_DEFINITIONS,
  SELECTION: AttributePolicy.SELECTION,
  REFERENCES: AttributePolicy.REFERENCES,
  SELECTORS: AttributePolicy.SELECTORS,
  setDirectory: slot.forward('setDirectory'),
  directoryInstalled: slot.forward('directoryInstalled'),
  read: slot.forward('read'),
  list: slot.forward('list'),
  selectionFor: slot.forward('selectionFor'),
  profileFor: slot.forward('profileFor'),
  namedBy: slot.forward('namedBy'),
  namedByAsync: slot.forward('namedByAsync'),
  catalogue: slot.forward('catalogue'),
  required: slot.forward('required'),
  enforced: slot.forward('enforced'),
  missingFrom: slot.forward('missingFrom'),
  removedBy: slot.forward('removedBy'),
  createRefusal: slot.forward('createRefusal'),
  editRefusal: slot.forward('editRefusal'),
  peopleMissing: slot.forward('peopleMissing'),
  deriveCommonName: slot.forward('deriveCommonName'),
  validate: slot.forward('validate'),
  save: slot.forward('save'),
  reset: slot.forward('reset'),
  describe: slot.forward('describe'),
  definitions: slot.forward('definitions'),
  definition: slot.forward('definition'),
  define: slot.forward('define'),
  undefine: slot.forward('undefine'),
  act: slot.forward('act')
};
