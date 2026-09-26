'use strict';
//
// File: ldap/person_editor.ts
//
// ===========================================================================
// WHAT AN ADMINISTRATOR MAY CHANGE ON A PERSON'S ENTRY, ONE ATTRIBUTE AT A
// TIME (#228, 2026-09-26).
//
// `/admin/applications` has had a general attribute editor since the registry
// became writable — Set, Add to, Remove from, over a table of what is
// DECLARED — and a person's page had nothing of the kind. Everything on a
// person could be CREATED (`/admin/users/new`), and after that the only doors
// were the narrow ones: the address (`set-mail`), the credentials, the flags,
// or an `ldapmodify`. rcbj's ticket asks for the application page's
// mechanism on the user page, for the attributes that are neither sensitive
// nor managed; this file is where that line is drawn, and
// `admin-core/admin_actions.ts` (`set-attribute`, `add-attribute`,
// `remove-attribute`), the console's section on `/admin/users?user=` and
// `POST /admin-api/users/{action}` are the three doors onto it.
//
// ---------------------------------------------------------------------------
// WHAT IS EDITABLE: THE SCHEMA, MINUS WHAT IS MANAGED (rcbj, 2026-09-26).
//
// The universe is the list `common/inetorgperson.ts` already keeps — the
// union of person, organizationalPerson and inetOrgPerson, plus the Identity
// Assurance group — and the credential catalogue's (`oid4vc/vc_claims.ts`)
// rows that are on neither (`schacDateOfBirth`, `c`, `employeeStatus`). Two
// lists that exist to say what a person here IS, and not a third one: an
// attribute somebody adds to either appears here with nothing else to edit.
//
// **IT IS AN ALLOWLIST FOR `inetorgperson.ts`'s REASON**: an entry here
// carries whatever anybody put on it, including this service's own `sts*`
// credentials, `memberOf` (which grants the console roles — see
// `ldap_server.js`'s write authorization) and the sighting attributes a
// sign-in records. An attribute that is on neither list is not offered and is
// refused by name, so a new credential attribute cannot become editable by
// accident.
//
// From that universe, four kinds are taken out, and each is a refusal with a
// reason rather than an omission — a caller asking for one is told which
// door to use instead:
//
//   * **SECRET** — `userPassword`. A password is set through
//     `credentials.setPassword()`, which hashes it and asks the policy; an
//     attribute door that took it would write one in the clear.
//   * **BINARY** — the certificates, the photographs, `audio` and
//     `userPKCS12` (which carries a private key). Octets, not text; a text
//     box cannot hold one honestly.
//   * **MANAGED** — `uid`, the username, which names the entry and is what
//     every username lookup reads (a rename is not an attribute edit); and
//     `mail`, which has its own action (`set-mail`, drawn beside this
//     editor on the person's page) because a write of it is VERIFIED and the
//     former address is told (#63, #64).
//   * **THE ENTRY'S OWN NAME** — whichever attribute the entry's RDN is
//     built from. `uid` for everybody this service creates, so that is
//     already covered; but an entry a client certificate created is
//     `cn=<name>,ou=users`, and an edit of its `cn` would leave the DN saying
//     one thing and the entry another. Asked PER ENTRY, which is why
//     `editorFor()` answers a person rather than the schema.
//
// ---------------------------------------------------------------------------
// ONE VALUE OR SEVERAL: THE SCHEMA'S ANSWER, NOT A PREFERENCE.
//
// `set` replaces every value with one (an empty value clears the attribute);
// `add` and `remove` act on one value. `add` is refused on an attribute the
// schema declares SINGLE-VALUE — `displayName`, `employeeNumber` and
// `preferredLanguage` (RFC 2798), `c` (RFC 4519 2.2), `schacDateOfBirth`
// (SCHAC) — and on this service's own attributes that stand for one fact
// (`employeeStatus`, the three place-of-birth parts), because a second value
// is a second answer to a question with one. Everything else is multi-valued
// in its RFC, and `add` is how an operator records a second telephone
// number.
//
// **A MUST ATTRIBUTE CANNOT BE EMPTIED.** `cn` and `sn` are on `person`'s
// MUST list (RFC 4519 3.12), so clearing either, or removing its last value,
// is refused — the same rule a schema-checking directory would apply.
//
// ---------------------------------------------------------------------------
// THE VALUES ARE CHECKED WHERE THE SCHEMA GIVES THEM A SHAPE, and nowhere
// else. Every value is trimmed, is at most `MAX_VALUE_LENGTH` characters and
// carries no control character. Beyond that:
//
//   * a COUNTRY (`c`, `schacCountryOfCitizenship`, `placeOfBirthCountry`) is
//     an assigned ISO 3166-1 alpha-2 code, stored upper-case — what
//     `common/country_codes.js` turns into the alpha-3 an issued claim
//     carries, and a code it does not know would be sent as typed;
//   * `schacDateOfBirth` is a real date, stored `YYYYMMDD` (SCHAC's form)
//     and accepted as `YYYY-MM-DD` too, since that is the `birthdate` claim's;
//   * `preferredLanguage` is RFC 2798 2.7's Accept-Language syntax;
//   * `labeledURI` is RFC 2079's URI, optionally followed by a label — and
//     the URI must be http or https, because it is released as the
//     `website` claim and a relying party renders it as a link;
//   * `seeAlso`, `manager` and `secretary` hold a DN. It is checked for the
//     SHAPE of one and not for an entry being there: this directory keeps no
//     referential integrity (`GET /admin/ldap/service` says so) and a
//     manager in another directory is an ordinary thing to record.
//
// ---------------------------------------------------------------------------
// WHAT AN EDIT DOES BESIDES THE WRITE — nothing this file decides.
//
// The write goes through the directory's slot (below), which changes the one
// attribute in place, touches the directory (so it persists and replicates)
// and hands the before and after to `ldap_server.js`'s account observer — the
// same observer a SCIM PATCH and an `ldapmodify` reach, so Shared Signals
// reads an edit here exactly as it reads one arriving by either of those. An
// Identity Assurance verification (#127) covers a value only while the entry
// still holds it, so editing a verified value lets that verification lapse
// for it; that is `common/identity_assurance.ts`'s rule, and this file does
// not need to know it.
//
// The audit row names the attribute and the act and NOT the value: these are
// personal data, and the directory is where they are kept.
//
// ---------------------------------------------------------------------------
// THE DIRECTORY'S SLOT, AND WHY IT IS ONE.
//
// Reading and writing an entry is `ldap/ldap_server.js`'s, and this file
// cannot require it: that module is JavaScript and registers its
// `/admin/ldap/*` routes when it is required (rule 1), so a require from here
// — which `admin-core/admin_views.ts` loads long before position 21 — would
// drag those routes ahead of the console's. The other direction is the
// ordinary one: `ldap_server.js` requires this file and fills
// `setDirectory()` at its own require, as it fills the mail channel's and the
// identity-assurance register's. The slot is validated WHOLE — a directory
// that could read and not write would draw a form whose every button fails.
//
// A LIBRARY (rule 3): it registers no route.
// ===========================================================================

import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import InstanceSlot = require('../common/instance_slot');
import inetOrgPerson = require('../common/inetorgperson');
import vcClaims = require('../oid4vc/vc_claims');
import countryCodes = require('../common/country_codes');

// One editable attribute, as the page draws it and the API publishes it.
interface EditableRow {
  name: string;
  label: string;
  schema: string;
  multi: boolean;
  must: boolean;
  format: string;
  note: string;
}

// One attribute of the universe that is NOT editable, with the door to use.
interface Withheld {
  name: string;
  label: string;
  kind: string;
  why: string;
}

// What the directory's slot answers about one person.
interface LocatedPerson {
  dn: string;
  // Lower-cased names, array values — the stored map, or a copy of it.
  attributes: Record<string, unknown[]>;
  // The lower-cased attribute type(s) of the entry's RDN.
  naming: string[];
}

interface PersonDirectory {
  locate(key: string): LocatedPerson | null;
  // Replace one attribute's values (none removes it) and report it. Answers
  // whether the entry was written.
  write(dn: string, name: string, values: string[]): boolean;
}

interface EditRequest {
  attribute?: unknown;
  mode?: unknown;
  value?: unknown;
}

interface EditContext {
  actor?: string;
  via?: string;
}

interface PersonEditorDeps {
  log: { debug(message: string): void; warn(message: string): void };
  errorCodes: typeof errorCodes;
  // The schema's rows, and the credential catalogue's.
  schemaRows: () => Array<{ ldap: string; label: string; rfc: string;
                            must?: boolean; secret?: boolean;
                            binary?: boolean }>;
  catalogueRows: () => Array<{ ldap: string; label: string;
                               schema: string }>;
  alpha3: (code: string) => string;
  audit: (row: Record<string, unknown>) => void;
}

// The longest value an edit may write. A postal address or a description is
// the long case; a directory value longer than this is a document, and a
// document does not belong in a person's entry.
const MAX_VALUE_LENGTH = 1024;

// SINGLE-VALUE in the schema that defines each (see the header), and this
// service's own attributes that stand for one fact. Lower-cased.
const SINGLE_VALUED = ['displayname', 'employeenumber', 'preferredlanguage',
                       'c', 'schacdateofbirth', 'employeestatus',
                       'placeofbirthcountry', 'placeofbirthregion',
                       'placeofbirthlocality'];

// The shaped attributes, lower-cased name -> format. See the header.
const FORMATS: Record<string, string> = {
  c: 'country', schaccountryofcitizenship: 'country',
  placeofbirthcountry: 'country',
  schacdateofbirth: 'date',
  preferredlanguage: 'language',
  labeleduri: 'uri',
  seealso: 'dn', manager: 'dn', secretary: 'dn'
};

// What each format asks for, in the words a refusal and the page use.
const FORMAT_HINTS: Record<string, string> = {
  country: 'an ISO 3166-1 alpha-2 country code, such as SE',
  date: 'a date, YYYYMMDD or YYYY-MM-DD',
  language: 'a language range, such as en-GB or "da, en-gb;q=0.8"',
  uri: 'an http or https URL, optionally followed by a space and a label',
  dn: 'a distinguished name, such as uid=bob,ou=users,dc=example,dc=com'
};

// MANAGED: in the universe, and written by a door of its own.
const MANAGED: Record<string, string> = {
  uid: 'It is the username: it names the entry and every sign-in finds the ' +
       'person by it. A rename is not an attribute edit.',
  mail: 'It has a control of its own (Set the address on the person\'s ' +
        'page, or POST /admin-api/users/set-mail), because a write of it is ' +
        'VERIFIED and the former address is told it changed.'
};

const MODES = ['set', 'add', 'remove'];

// C0 controls, DEL and the C1 range. A newline in particular: nothing in a
// person's entry is a multi-line value here (`postalAddress` separates its
// lines with `$`, RFC 4517 3.3.28), and one would reach an LDIF export as a
// line break in the middle of a value.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

// RFC 2616 14.4 (which RFC 2798 2.7 cites through RFC 2068): a list of
// language ranges, each with an optional quality value.
const LANGUAGE_RANGE = /^(\*|[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*)(\s*;\s*q\s*=\s*(0(\.\d{0,3})?|1(\.0{0,3})?))?$/;

// The shape of a DN: one or more `type=value` RDNs. What a DN MEANS is the
// directory's business; this only refuses a value that is not one.
const DN_SHAPE = /^\s*[A-Za-z][A-Za-z0-9-]*\s*=\s*[^,=]+(\s*,\s*[A-Za-z][A-Za-z0-9-]*\s*=\s*[^,=]+)*\s*$/;

// The directory, through its slot. Module-level rather than on the instance,
// for `common/mail.ts`'s reason: `ldap_server.js` fills it at its own require,
// which may come before the composition root installs this module.
let directory: PersonDirectory | null = null;

class PersonEditor {
  static readonly MAX_VALUE_LENGTH = MAX_VALUE_LENGTH;
  static readonly MODES = MODES;

  constructor(private readonly deps: PersonEditorDeps) {
    deps.log.debug("Entering PersonEditor.constructor().");
    deps.log.debug("Leaving PersonEditor.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): PersonEditorDeps {
    helpers.log.debug("Entering PersonEditor.defaultDeps().");
    helpers.log.debug("Leaving PersonEditor.defaultDeps().");
    return {
      log: helpers.log,
      errorCodes: errorCodes,
      schemaRows: function schemaRows() {
        helpers.log.debug("Entering schemaRows().");
        helpers.log.debug("Leaving schemaRows().");
        return inetOrgPerson.attributes();
      },
      catalogueRows: function catalogueRows() {
        helpers.log.debug("Entering catalogueRows().");
        helpers.log.debug("Leaving catalogueRows().");
        return vcClaims.personFields();
      },
      alpha3: countryCodes.alpha3,
      // LAZILY: `common/audit.js` is a leaf, but it is the audit log's to be
      // loaded where the service loads it.
      audit: function audit(row) {
        helpers.log.debug("Entering audit().");
        require('../common/audit').record(row);
        helpers.log.debug("Leaving audit().");
      }
    };
  }

  // -------------------------------------------------------------------------
  // THE UNIVERSE, split in two: what may be edited, and what is withheld and
  // why. Computed per call from the two lists, so a row added to either
  // appears here with nothing else to change.
  // -------------------------------------------------------------------------
  private universe(): { editable: EditableRow[]; withheld: Withheld[] } {
    const { log, schemaRows, catalogueRows } = this.deps;
    log.debug("Entering PersonEditor.universe().");
    const editable: EditableRow[] = [];
    const withheld: Withheld[] = [];
    const seen = new Set<string>();
    const consider = function (name: string, label: string, schema: string,
                               flags: { must?: boolean; secret?: boolean;
                                        binary?: boolean }) {
      log.debug("Entering consider(). " + name);
      const key = name.toLowerCase();
      if (seen.has(key)) {
        log.debug("Leaving consider(). Already listed.");
        return;
      }
      seen.add(key);
      if (flags.secret) {
        withheld.push({ name: name, label: label, kind: 'secret',
          why: 'It is a credential. The password controls on the ' +
               'person\'s page reset it, and POST ' +
               '/admin-api/users/set-password sets one, hashing it under ' +
               'the password policy.' });
        log.debug("Leaving consider(). Secret.");
        return;
      }
      if (flags.binary) {
        withheld.push({ name: name, label: label, kind: 'binary',
          why: 'Its values are octets, not text, and a text box cannot hold ' +
               'one honestly. An LDAP client writes it.' });
        log.debug("Leaving consider(). Binary.");
        return;
      }
      if (MANAGED[key]) {
        withheld.push({ name: name, label: label, kind: 'managed',
                        why: MANAGED[key] });
        log.debug("Leaving consider(). Managed.");
        return;
      }
      const format = FORMATS[key] || '';
      editable.push({ name: name, label: label, schema: schema,
                      multi: SINGLE_VALUED.indexOf(key) < 0,
                      must: !!flags.must, format: format,
                      note: format ? FORMAT_HINTS[format] : '' });
      log.debug("Leaving consider(). Editable.");
    };
    schemaRows().forEach(function (row) {
      consider(row.ldap, row.label, row.rfc, row);
    });
    catalogueRows().forEach(function (row) {
      consider(row.ldap, row.label, row.schema, {});
    });
    log.debug("Leaving PersonEditor.universe(). " + editable.length +
              " editable, " + withheld.length + " withheld.");
    return { editable: editable, withheld: withheld };
  }

  // Every editable attribute, whoever the person is.
  editableAttributes(): EditableRow[] {
    const { log } = this.deps;
    log.debug("Entering PersonEditor.editableAttributes().");
    log.debug("Leaving PersonEditor.editableAttributes().");
    return this.universe().editable;
  }

  // The attributes of the schema that are NOT editable, each with the door to
  // use instead.
  withheldAttributes(): Withheld[] {
    const { log } = this.deps;
    log.debug("Entering PersonEditor.withheldAttributes().");
    log.debug("Leaving PersonEditor.withheldAttributes().");
    return this.universe().withheld;
  }

  // Whether a directory has been installed, for a page deciding whether to
  // draw a form at all.
  available(): boolean {
    const { log } = this.deps;
    log.debug("Entering PersonEditor.available().");
    log.debug("Leaving PersonEditor.available().");
    return !!directory;
  }

  // -------------------------------------------------------------------------
  // ONE PERSON'S EDITOR: every editable attribute with the values the entry
  // holds, and whether THIS entry lets it be edited — false, with the reason,
  // for the attribute the entry is named by. `null` where there is no
  // directory or no such person, which the page reads as "draw nothing".
  // -------------------------------------------------------------------------
  editorFor(key: string) {
    const { log } = this.deps;
    log.debug("Entering PersonEditor.editorFor(). key=" + key);
    const person = directory ? directory.locate(String(key || '')) : null;
    if (!person) {
      log.debug("Leaving PersonEditor.editorFor(). " +
                (directory ? "Nobody there." : "No directory."));
      return null;
    }
    const universe = this.universe();
    const attributes = universe.editable.map(function (row) {
      const held = person.attributes[row.name.toLowerCase()] || [];
      const naming = person.naming.indexOf(row.name.toLowerCase()) >= 0;
      return Object.assign({}, row, {
        values: held.map(String),
        editable: !naming,
        why: naming
          ? 'The entry is named by it (' + person.dn + '), so an edit would ' +
            'leave the DN and the entry disagreeing.'
          : ''
      });
    });
    log.debug("Leaving PersonEditor.editorFor(). " + person.dn);
    // The address as well, withheld from the editor but drawn beside it by
    // the page, whose `set-mail` form starts from it.
    return { dn: person.dn, attributes: attributes,
             withheld: universe.withheld,
             mail: String((person.attributes.mail || [])[0] || '') };
  }

  // -------------------------------------------------------------------------
  // THE ONE CHECK OF A VALUE, and its normal form. Answers `{ value }` or
  // `{ error }` — the words of a refusal, which the caller codes.
  // -------------------------------------------------------------------------
  private normalised(row: EditableRow, raw: unknown):
      { value?: string; error?: string } {
    const { log, alpha3 } = this.deps;
    log.debug("Entering PersonEditor.normalised(). " + row.name);
    const value = String(raw == null ? '' : raw).trim();
    if (value.length > MAX_VALUE_LENGTH) {
      log.debug("Leaving PersonEditor.normalised(). Too long.");
      return { error: 'is ' + value.length + ' characters long, and a value ' +
                      'here may be at most ' + MAX_VALUE_LENGTH };
    }
    if (CONTROL.test(value)) {
      log.debug("Leaving PersonEditor.normalised(). A control character.");
      return { error: 'contains a control character (a line break, a tab); ' +
                      'a multi-line postal address separates its lines ' +
                      'with $' };
    }
    const shaped = this.shaped(row.format, value, alpha3);
    log.debug("Leaving PersonEditor.normalised().");
    return shaped;
  }

  // A value against its format, where it has one.
  private shaped(format: string, value: string,
                 alpha3: (code: string) => string):
      { value?: string; error?: string } {
    const { log } = this.deps;
    log.debug("Entering PersonEditor.shaped(). " + (format || 'none'));
    const hint = format ? 'is not ' + FORMAT_HINTS[format] : '';
    if (!format || value === '') {
      log.debug("Leaving PersonEditor.shaped(). Nothing to check.");
      return { value: value };
    }
    if (format === 'country') {
      const code = value.toUpperCase();
      const known = /^[A-Z]{2}$/.test(code) && alpha3(code) !== code;
      log.debug("Leaving PersonEditor.shaped(). " + known);
      return known ? { value: code } : { error: hint };
    }
    if (format === 'date') {
      const m = /^(\d{4})-?(\d{2})-?(\d{2})$/.exec(value);
      const when = m ? new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1,
                                         Number(m[3]))) : null;
      const real = !!(m && when &&
                      when.getUTCFullYear() === Number(m[1]) &&
                      when.getUTCMonth() === Number(m[2]) - 1 &&
                      when.getUTCDate() === Number(m[3]));
      log.debug("Leaving PersonEditor.shaped(). " + real);
      return real ? { value: m[1] + m[2] + m[3] } : { error: hint };
    }
    if (format === 'language') {
      const ok = value.split(',').every(function (part) {
        return LANGUAGE_RANGE.test(part.trim());
      });
      log.debug("Leaving PersonEditor.shaped(). " + ok);
      return ok ? { value: value } : { error: hint };
    }
    if (format === 'uri') {
      const at = value.search(/\s/);
      const uri = at < 0 ? value : value.slice(0, at);
      let ok = false;
      try {
        const parsed = new URL(uri);
        ok = parsed.protocol === 'https:' || parsed.protocol === 'http:';
      } catch (e) {
        log.debug("Caught in PersonEditor.shaped(): " +
                  ((e && e.message) || e));
        // Not a URL at all: refused below with the same words as a URL of
        // the wrong scheme.
      }
      log.debug("Leaving PersonEditor.shaped(). " + ok);
      return ok ? { value: value } : { error: hint };
    }
    // `dn`, the last format.
    const ok = DN_SHAPE.test(value);
    log.debug("Leaving PersonEditor.shaped(). " + ok);
    return ok ? { value: value } : { error: hint };
  }

  // A refusal, coded.
  private refused(code: string, message: string,
                  extra?: Record<string, unknown>) {
    const { log, errorCodes } = this.deps;
    log.debug("Entering PersonEditor.refused(). " + code);
    log.debug("Leaving PersonEditor.refused().");
    return errorCodes.mark(Object.assign({ ok: false, errors: [message] },
                                         extra || {}), code);
  }

  // -------------------------------------------------------------------------
  // THE EDIT. `mode` is `set`, `add` or `remove`; see the header for what
  // each does and what each refuses.
  // -------------------------------------------------------------------------
  update(key: string, request: EditRequest, context?: EditContext) {
    const { log, audit } = this.deps;
    const ctx = context || {};
    const name = String((request && request.attribute) || '').trim();
    const mode = String((request && request.mode) || '').trim();
    log.debug("Entering PersonEditor.update(). key=" + key + " " + mode +
              " " + name);
    if (!directory) {
      log.warn(errorCodes.tag('STS-LDAP-0101') + 'ldap: a person\'s ' +
               'attribute edit found no directory installed.');
      log.debug("Leaving PersonEditor.update(). No directory.");
      return this.refused('STS-LDAP-0101', 'No directory is loaded in this ' +
                          'process, so there is no entry to change.');
    }
    if (MODES.indexOf(mode) < 0) {
      log.debug("Leaving PersonEditor.update(). Not a mode.");
      return this.refused('STS-LDAP-0105', '"' + mode.slice(0, 40) + '" is ' +
                          'not an edit; it is set, add or remove.');
    }
    const universe = this.universe();
    const row = universe.editable.filter(function (one) {
      return one.name.toLowerCase() === name.toLowerCase();
    })[0];
    if (!row) {
      const withheld = universe.withheld.filter(function (one) {
        return one.name.toLowerCase() === name.toLowerCase();
      })[0];
      log.debug("Leaving PersonEditor.update(). Not editable.");
      return this.refused('STS-LDAP-0103', withheld
        ? withheld.name + ' is not edited here. ' + withheld.why
        : 'A person here has no attribute called "' + name.slice(0, 64) +
          '" that this editor changes. The ' + universe.editable.length +
          ' it does are listed on the person\'s page and under ' +
          '`attributeEditor` in GET /admin-api/users?user=; credentials, ' +
          'group memberships and what this service records about sign-ins ' +
          'are not among them.');
    }
    const person = directory.locate(String(key || ''));
    if (!person) {
      log.debug("Leaving PersonEditor.update(). Nobody there.");
      return this.refused('STS-LDAP-0102', 'There is no person called "' +
                          String(key || '').slice(0, 80) + '" in this ' +
                          'realm\'s directory.');
    }
    const lower = row.name.toLowerCase();
    if (person.naming.indexOf(lower) >= 0) {
      log.debug("Leaving PersonEditor.update(). The entry's own name.");
      return this.refused('STS-LDAP-0104', row.name + ' names this entry (' +
                          person.dn + '), so it is not edited here: the DN ' +
                          'and the entry would disagree.');
    }
    if (mode === 'add' && !row.multi) {
      log.debug("Leaving PersonEditor.update(). Single-valued.");
      return this.refused('STS-LDAP-0105', row.name + ' holds one value, so ' +
                          'it is set rather than added to.');
    }
    const checked = this.normalised(row, request.value);
    if (checked.error !== undefined) {
      log.debug("Leaving PersonEditor.update(). The value was refused.");
      return this.refused('STS-LDAP-0106', 'The value for ' + row.name + ' ' +
                          checked.error + '.');
    }
    const value = String(checked.value);
    if (mode !== 'set' && value === '') {
      log.debug("Leaving PersonEditor.update(). No value.");
      return this.refused('STS-LDAP-0106', 'Name the value to ' + mode +
                          '.');
    }
    const before = (person.attributes[lower] || []).map(String);
    // A HOT PATH, run once per held value: no Entering/Leaving pair here,
    // which would drown the log in a line per value compared.
    const same = function (one: string) {
      return one.toLowerCase() === value.toLowerCase();
    };
    let after: string[];
    if (mode === 'set') {
      after = value === '' ? [] : [value];
    } else if (mode === 'add') {
      if (before.some(same)) {
        log.debug("Leaving PersonEditor.update(). Already held.");
        return this.refused('STS-LDAP-0107', row.name + ' already holds "' +
                            value.slice(0, 80) + '".');
      }
      after = before.concat([value]);
    } else {
      if (!before.some(same)) {
        log.debug("Leaving PersonEditor.update(). Not held.");
        return this.refused('STS-LDAP-0108', row.name + ' does not hold "' +
                            value.slice(0, 80) + '".');
      }
      after = before.filter(function (one) {
        return !same(one);
      });
    }
    if (row.must && !after.length) {
      log.debug("Leaving PersonEditor.update(). A MUST attribute.");
      return this.refused('STS-LDAP-0109', row.name + ' is required of ' +
                          'every person by the schema (RFC 4519 3.12), so ' +
                          'it cannot be left empty. Set another value ' +
                          'instead.');
    }
    const written = directory.write(person.dn, lower, after);
    audit({ category: 'admin', action: 'admin.user.attribute',
            actor: String(ctx.actor || ''), target: person.dn,
            outcome: written ? 'success' : 'failure',
            errorCode: written ? undefined : 'STS-LDAP-0110',
            // THE ATTRIBUTE AND THE ACT, NOT THE VALUE — see the header.
            summary: (written ? '' : 'could not ') + mode + ' ' + row.name +
                     ' on ' + person.dn,
            detail: { attribute: row.name, mode: mode,
                      values: after.length, via: String(ctx.via || '') } });
    if (!written) {
      log.debug("Leaving PersonEditor.update(). Not written.");
      return this.refused('STS-LDAP-0110', 'The directory did not store the ' +
                          'change to ' + row.name + ' on ' + person.dn + '.');
    }
    log.debug("Leaving PersonEditor.update(). " + mode + " " + row.name +
              ": " + before.length + " -> " + after.length + " value(s).");
    return { ok: true, dn: person.dn, attribute: row.name, mode: mode,
             values: after,
             message: (after.length
               ? row.name + ' on ' + person.dn + ' is now ' +
                 after.map(function (one) {
                   return '"' + one + '"';
                 }).join(', ') + '.'
               : row.name + ' was removed from ' + person.dn + '.') };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2); see
// `common/instance_slot.ts`. The exports below are FACADES for the
// JavaScript callers, and `setDirectory` is a plain function (see
// `directory` above).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<PersonEditor>(
  'ldap/person_editor',
  () => new PersonEditor(PersonEditor.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  PersonEditor: PersonEditor,
  installInstance: (instance: PersonEditor): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  MAX_VALUE_LENGTH: MAX_VALUE_LENGTH,
  MODES: MODES,
  // The directory's slot (rule 3e), filled by `ldap/ldap_server.js`. Both
  // members or nothing: see the header.
  setDirectory: function (d: PersonDirectory | null): boolean {
    helpers.log.debug("Entering setDirectory().");
    if (d && (typeof d.locate !== 'function' ||
              typeof d.write !== 'function')) {
      helpers.log.warn('ldap/person_editor: a directory without both ' +
                       'locate() and write() was offered and refused.');
      helpers.log.debug("Leaving setDirectory(). Refused.");
      return false;
    }
    directory = d || null;
    helpers.log.debug("Leaving setDirectory().");
    return true;
  },
  available: slot.forward('available'),
  editableAttributes: slot.forward('editableAttributes'),
  withheldAttributes: slot.forward('withheldAttributes'),
  editorFor: slot.forward('editorFor'),
  update: slot.forward('update')
};
