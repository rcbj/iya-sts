'use strict';
//
// File: inetorgperson.ts
//
// ===========================================================================
// WHAT A PERSON IS, IN THE SCHEMA THE PEOPLE IN THIS DIRECTORY ACTUALLY CARRY
// (2026-09-11).
//
// Every person `ldap/ldap_server.js` creates gets `objectClass: ['top',
// 'person', 'organizationalPerson', 'inetOrgPerson']`, and this file is the
// definition of that last class — the union of the three, since inetOrgPerson
// is a subclass of organizationalPerson which is a subclass of person.
//
// It exists because **`/portal` grew a page that had to answer "what does this
// identity provider hold about me", and there was no list to answer it from.**
// The four attributes it showed — username, subject, email, name — were read
// off the SESSION, so the page reported what the sign-in happened to carry
// rather than what the directory holds; a person whose entry had a department,
// a manager and a room number saw none of them.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A LIST AND NOT A READ OF THE ENTRY.
//
// The obvious implementation of that page is to print every attribute the
// entry carries. It was rejected, and the reason is the whole design of this
// file: **an entry in this directory carries whatever anybody put on it.** A
// TLS client certificate's subject becomes attributes RDN by RDN, SCIM writes
// its own mapping, `/admin/users/new` writes the credential catalogue's set,
// and this service puts its own `sts`-prefixed CREDENTIALS on the same object
// (ten secret ones by now — `ldap/ldap_server.js`'s `SECRET_ATTRIBUTES`
// lists them). A page that printed the entry would print
// `stsTotpCredential` — a shared secret — the day somebody enrolled an
// authenticator, with nothing anywhere having decided that it should.
//
// So the page draws a FIXED LIST and looks each name up. **A new attribute
// this service invents cannot appear on it by accident**, which is the
// property worth having, and it is a property of the list rather than of
// anybody remembering.
//
// ---------------------------------------------------------------------------
// THE SPELLINGS ARE CHECKED AGAINST `ldap/ldap_server.js` RATHER THAN TRUSTED.
//
// That module's `STANDARD_NAMES` already carries every one of these names, and
// `learnName()` is the ONE way into its canonical table precisely so that two
// independently maintained lists of spellings are REPORTED when they disagree
// rather than resolved by merge order. This file's names are merged the same
// way the applications, roles, XACML and credential-claim schemas are — so if
// a name here is spelt differently from the same name there, the service says
// so at startup instead of one page quietly rendering `seealso`.
//
// **ONE NAME IS DELIBERATELY NOT SPELT THE WAY RFC 2798 SPELLS IT.** That
// document writes `x500uniqueIdentifier`; RFC 4519 section 2.43, which is where
// the attribute type is actually registered, writes `x500UniqueIdentifier`.
// `ldap/ldap_server.js` chose the registered spelling and said why, and this
// file follows it rather than having the merge report a disagreement nobody
// intends to fix. They differ in a letter LDAP does not distinguish anyway.
//
// ---------------------------------------------------------------------------
// TWO KINDS OF ATTRIBUTE MAY NOT BE RENDERED, AND THEY ARE MARKED HERE RATHER
// THAN FILTERED AT THE PAGE.
//
// * **`secret: true` — `userPassword`.** It is on the `person` MAY list, so a
//   faithful reading of the schema puts it on the page, and what sits in it is
//   a scrypt hash. It is not a plaintext leak and it is still the thing a
//   sign-in is CHECKED against, and there is no version of "your account page"
//   that wants it. The page says the attribute is set and shows nothing, which
//   is what `/admin/users/new` already does with the same two attributes.
//
// * **`binary: true` — `audio`, `jpegPhoto`, `photo`, `userCertificate`,
//   `userPKCS12`, `userSMIMECertificate`.** RFC 4522 transfer syntax: these are
//   octets, not text. Interpolating them into HTML produces mojibake at best,
//   and **`userPKCS12` is a PKCS#12 bundle, which conventionally carries a
//   PRIVATE KEY** — so that one is both binary and a credential, and is the
//   reason this flag refuses rather than truncates. The page reports the size.
//
// Marking them HERE and not at the page is the point: a second surface that
// draws this list gets both refusals without having to know about them, and
// the list is where somebody adding an attribute will be standing.
//
// ---------------------------------------------------------------------------
// A LIBRARY (rule 3). It registers no route, so its position in the require
// order is not a position. It requires `helpers` and nothing else — not
// `config`, not `realms` — because it is a SCHEMA and there is nothing about
// it a deployment or a trust realm could change. It is required by
// `portal/portal.ts` and by `ldap/ldap_server.js`.
//
// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16).
//
// `InetOrgPerson` takes its logger through `InetOrgPersonDeps`; the schema
// tables stay module-level constants, because they are data and not state.
// The module still exports `CLASSES`, `CANONICAL_NAMES`, `classes`,
// `attributes`, `attribute`, `rowFor` and `describe`. Since #50's R2 the
// composition root builds the instance (`InetOrgPerson.defaultDeps()`) and
// installs it; the module's old export names are FACADES that forward to it,
// for the JavaScript callers, and a process without the root builds a default
// when this module finishes loading. `InetOrgPerson` is exported beside them
// for that root.
// ===========================================================================

import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');

// One row of the schema.
interface SchemaRow {
  ldap: string;
  label: string;
  rfc: string;
  must?: boolean;
  secret?: boolean;
  binary?: boolean;
  note?: string;
}

// One object class, with its rows.
interface SchemaClass {
  id: string;
  name: string;
  rfc: string;
  oid: string;
  what: string;
  attributes: SchemaRow[];
}

// A row ready to draw: see `rowFor()`.
interface DrawnRow {
  ldap: string;
  label: string;
  rfc: string;
  note: string;
  must: boolean;
  secret: boolean;
  binary: boolean;
  present: boolean;
  count: number;
  values: string[];
  bytes?: number;
}

// A stored attribute map: lower-cased names, array values.
type StoredEntry = Record<string, unknown> | null | undefined;

interface InetOrgPersonDeps {
  log: { debug(message: string): void };
}

// ---------------------------------------------------------------------------
// RFC 4519 SECTION 3.12 — `person`. The base, and the only one of the three
// with a MUST list.
//
// `telephoneNumber` is on this MAY list AND on organizationalPerson's below.
// That is not a mistake in either document — X.521 repeats it and RFC 4519
// carries the repetition — and it is listed ONCE here, where it is first
// admitted, because a page that drew it twice would look like a bug in the
// page rather than a curiosity of the schema.
// ---------------------------------------------------------------------------
const PERSON: SchemaRow[] = [
  { ldap: 'cn', label: 'Common name', must: true, rfc: 'RFC 4519 2.3',
    note: 'The full name this entry is filed under. Required by the schema, ' +
          'and the RDN of every person this service creates.' },
  { ldap: 'sn', label: 'Surname', must: true, rfc: 'RFC 4519 2.32' },
  { ldap: 'userPassword', label: 'Password', rfc: 'RFC 4519 2.41',
    secret: true,
    note: 'A scrypt hash rather than the password. It is never shown here ' +
          'and there is nowhere it could usefully be.' },
  { ldap: 'telephoneNumber', label: 'Telephone number', rfc: 'RFC 4519 2.35' },
  { ldap: 'seeAlso', label: 'See also', rfc: 'RFC 4519 2.30',
    note: 'The DN of another entry about the same thing.' },
  { ldap: 'description', label: 'Description', rfc: 'RFC 4519 2.5' }
];

// ---------------------------------------------------------------------------
// RFC 4519 SECTION 3.10 — `organizationalPerson`. Where this person is, in an
// organisation and on a map: almost all of it is address and telecoms.
// ---------------------------------------------------------------------------
const ORGANIZATIONAL_PERSON: SchemaRow[] = [
  { ldap: 'title', label: 'Job title', rfc: 'RFC 4519 2.38' },
  { ldap: 'ou', label: 'Organizational unit', rfc: 'RFC 4519 2.20' },
  { ldap: 'l', label: 'Locality', rfc: 'RFC 4519 2.16' },
  { ldap: 'st', label: 'State or province', rfc: 'RFC 4519 2.33' },
  { ldap: 'street', label: 'Street address', rfc: 'RFC 4519 2.34' },
  { ldap: 'postalAddress', label: 'Postal address', rfc: 'RFC 4519 2.23' },
  { ldap: 'postalCode', label: 'Postal code', rfc: 'RFC 4519 2.24' },
  { ldap: 'postOfficeBox', label: 'Post office box', rfc: 'RFC 4519 2.25' },
  { ldap: 'physicalDeliveryOfficeName', label: 'Delivery office',
    rfc: 'RFC 4519 2.22' },
  { ldap: 'registeredAddress', label: 'Registered address',
    rfc: 'RFC 4519 2.27' },
  { ldap: 'destinationIndicator', label: 'Destination indicator',
    rfc: 'RFC 4519 2.6' },
  { ldap: 'preferredDeliveryMethod', label: 'Preferred delivery method',
    rfc: 'RFC 4519 2.26' },
  { ldap: 'facsimileTelephoneNumber', label: 'Fax number',
    rfc: 'RFC 4519 2.10' },
  { ldap: 'internationalISDNNumber', label: 'ISDN number',
    rfc: 'RFC 4519 2.15' },
  { ldap: 'telexNumber', label: 'Telex number', rfc: 'RFC 4519 2.37' },
  { ldap: 'teletexTerminalIdentifier', label: 'Teletex terminal',
    rfc: 'RFC 4519 2.36' },
  { ldap: 'x121Address', label: 'X.121 address', rfc: 'RFC 4519 2.42' }
];

// ---------------------------------------------------------------------------
// RFC 2798's OWN MAY LIST — `inetOrgPerson`. What the class was ADDED for: the
// things an internet-era directory holds about a person that X.500's did not.
//
// **RFC 2798 DEFINES ONLY NINE ATTRIBUTE TYPES, AND THIS LIST HAS
// TWENTY-SEVEN.** That is not a mistake in either: an object class MAY-list
// names attributes, it does not define them, and the twenty-seven here are
// defined across FIVE documents — RFC 2798's own nine, RFC 4519's (`givenName`,
// `initials`, `o`, `businessCategory`, `uid`, `x500UniqueIdentifier`), RFC
// 4524's (`mail`, `manager`, `secretary`, `roomNumber`, `homePhone`,
// `homePostalAddress`, `mobile`, `pager`), RFC 2079's `labeledURI`, RFC 1274's
// `photo` and `audio`, and RFC 4523's `userCertificate`.
//
// **THE CITATION ON EACH ROW IS THE DOCUMENT THAT DEFINES THE ATTRIBUTE**, not
// the one whose MAY list it is met in, because the citation exists so that
// somebody reading the account page can go and look the attribute up. Getting
// this wrong is easy and quiet: an earlier draft of this file cited `mobile`
// and `pager` as RFC 2798 (they are RFC 4524), and put `audio` at RFC 2798 2.1
// (it is RFC 1274 9.3.45, and RFC 2798 2.1 is `carLicense`). **Every section
// number in this file was checked against the RFC text itself**, which is
// worth doing once rather than trusting: two other catalogues in this
// repository had a wrong one each, found by the same check.
// ---------------------------------------------------------------------------
const INET_ORG_PERSON: SchemaRow[] = [
  { ldap: 'uid', label: 'User id', rfc: 'RFC 4519 2.39',
    note: 'The login name. This service uses it as the username, and it is ' +
          'what everything else on this page is keyed by.' },
  { ldap: 'displayName', label: 'Display name', rfc: 'RFC 2798 2.3' },
  { ldap: 'givenName', label: 'Given name', rfc: 'RFC 4519 2.12' },
  { ldap: 'initials', label: 'Initials', rfc: 'RFC 4519 2.14' },
  { ldap: 'mail', label: 'Email address', rfc: 'RFC 4524 2.16',
    note: 'RFC 4524 registers it; inetOrgPerson is where it is met.' },
  { ldap: 'o', label: 'Organization', rfc: 'RFC 4519 2.19' },
  { ldap: 'businessCategory', label: 'Business category', rfc: 'RFC 4519 2.1' },
  { ldap: 'departmentNumber', label: 'Department number', rfc: 'RFC 2798 2.2' },
  { ldap: 'employeeNumber', label: 'Employee number', rfc: 'RFC 2798 2.4' },
  { ldap: 'employeeType', label: 'Employee type', rfc: 'RFC 2798 2.5',
    note: 'The one attribute on this page an XACML policy in this service ' +
          'reads by default — see xacml/xacml_pip.ts.' },
  { ldap: 'roomNumber', label: 'Room number', rfc: 'RFC 4524 2.22' },
  { ldap: 'manager', label: 'Manager', rfc: 'RFC 4524 2.17',
    note: 'A DN. Nothing here follows it.' },
  { ldap: 'secretary', label: 'Secretary', rfc: 'RFC 4524 2.23',
    note: 'A DN, like the manager beside it.' },
  { ldap: 'homePhone', label: 'Home phone', rfc: 'RFC 4524 2.12' },
  { ldap: 'homePostalAddress', label: 'Home address', rfc: 'RFC 4524 2.13' },
  { ldap: 'mobile', label: 'Mobile number', rfc: 'RFC 4524 2.18' },
  { ldap: 'pager', label: 'Pager number', rfc: 'RFC 4524 2.20' },
  { ldap: 'carLicense', label: 'Car licence', rfc: 'RFC 2798 2.1' },
  { ldap: 'preferredLanguage', label: 'Preferred language',
    rfc: 'RFC 2798 2.7',
    note: 'An RFC 2068 Accept-Language value. Nothing in this service reads ' +
          'it; no page is translated.' },
  { ldap: 'labeledURI', label: 'Labelled URI', rfc: 'RFC 2079',
    note: 'A URI and an optional label. **This service never dials it** — ' +
          'the rule about not fetching a URL a caller supplied covers an ' +
          'attribute on an entry too.' },
  // See the header: the registered spelling, not RFC 2798's.
  { ldap: 'x500UniqueIdentifier', label: 'X.500 unique identifier',
    rfc: 'RFC 4519 2.43' },

  // --- the binary five, and the one of them that is also a credential ------
  { ldap: 'jpegPhoto', label: 'Photograph (JPEG)', rfc: 'RFC 2798 2.6',
    binary: true },
  { ldap: 'photo', label: 'Photograph (G3 fax)', rfc: 'RFC 1274 9.3.7',
    binary: true,
    note: 'The older of the two photo attributes, and G3 fax rather than ' +
          'JPEG.' },
  { ldap: 'audio', label: 'Audio', rfc: 'RFC 1274 9.3.45', binary: true },
  { ldap: 'userCertificate', label: 'X.509 certificate', rfc: 'RFC 4523 4.1',
    binary: true,
    note: 'A DER certificate. **This is not the certificate a client ' +
          'presents to the main port** — nothing here reads this attribute ' +
          'during a TLS handshake, and a certificate written to it ' +
          'authorises nothing.' },
  { ldap: 'userSMIMECertificate', label: 'S/MIME certificate',
    rfc: 'RFC 2798 2.8', binary: true },
  { ldap: 'userPKCS12', label: 'PKCS#12 bundle', rfc: 'RFC 2798 2.9',
    binary: true,
    note: 'A PKCS#12 file, which conventionally carries a PRIVATE KEY. It is ' +
          'binary and it is a credential, and it is never shown.' }
];

// ---------------------------------------------------------------------------
// THE THREE CLASSES, IN INHERITANCE ORDER, WHICH IS ALSO THE ORDER A PAGE
// SHOULD DRAW THEM IN.
//
// A reader who does not already know that "the inetOrgPerson attributes" means
// the union of three object classes learns it from the headings, which is
// worth more on an account page than a flat alphabetical list would be.
// ---------------------------------------------------------------------------
const CLASSES: SchemaClass[] = [
  { id: 'person', name: 'person', rfc: 'RFC 4519 3.12', oid: '2.5.6.6',
    what: 'The base class. The only one of the three with attributes the ' +
          'schema REQUIRES.',
    attributes: PERSON },
  { id: 'organizationalPerson', name: 'organizationalPerson',
    rfc: 'RFC 4519 3.10', oid: '2.5.6.7',
    what: 'Where this person is — an organisation, an address, and the ' +
          'telecoms of the era the schema was written in.',
    attributes: ORGANIZATIONAL_PERSON },
  { id: 'inetOrgPerson', name: 'inetOrgPerson', rfc: 'RFC 2798',
    oid: '2.16.840.1.113730.3.2.2',
    what: 'What an internet-era directory holds about a person that X.500\'s ' +
          'did not: an email address, a photograph, a mobile number, a ' +
          'department.',
    attributes: INET_ORG_PERSON },
];

// Every row, flat, in class order. Built once — the rows are shared because
// they are read-only everywhere, and a caller that wants to sort gets a copy
// from `attributes()` below.
const ALL: SchemaRow[] = CLASSES.reduce(function (into: SchemaRow[], klass) {
  return into.concat(klass.attributes);
}, []);

// Lower-cased name -> row. Keyed the way a STORED entry is: `ldap_server.js`
// lower-cases every attribute name on the way in (RFC 4512 section 2.5 makes
// attribute descriptions case-insensitive), so a lookup against the stored map
// has to be lower-cased or every row on the page is empty. That is the one
// mistake this table exists to make impossible.
const BY_NAME: Map<string, SchemaRow> = new Map();
ALL.forEach(function (row) {
  BY_NAME.set(row.ldap.toLowerCase(), row);
});

// The canonical spelling of each, for `ldap/ldap_server.js` to merge into its
// own table through `learnName()`. The same shape `oid4vc/vc_claims.ts` offers
// and for the same reason — see the header: two lists of spellings that
// disagree are REPORTED rather than resolved by whichever was merged first.
const CANONICAL_NAMES: Record<string, string> = {};
ALL.forEach(function (row) {
  CANONICAL_NAMES[row.ldap.toLowerCase()] = row.ldap;
});

class InetOrgPerson {
  static readonly CLASSES = CLASSES;
  static readonly CANONICAL_NAMES = CANONICAL_NAMES;

  constructor(private readonly deps: InetOrgPersonDeps) {
    deps.log.debug("Entering InetOrgPerson.constructor().");
    deps.log.debug("Leaving InetOrgPerson.constructor().");
  }

  // What the composition root passes: the modules the load-time instance
  // was built from before R2.
  static defaultDeps(): InetOrgPersonDeps {
    helpers.log.debug("Entering InetOrgPerson.defaultDeps().");
    helpers.log.debug("Leaving InetOrgPerson.defaultDeps().");
    return { log: helpers.log };
  }

  // The classes, for a caller that is going to draw them. A shallow copy of
  // the list and of each class's row array, so that a caller sorting or
  // splicing cannot reorder the schema for everybody else.
  classes(): SchemaClass[] {
    const { log } = this.deps;
    log.debug("Entering InetOrgPerson.classes().");
    log.debug("Leaving InetOrgPerson.classes().");
    return CLASSES.map(function (klass) {
      return Object.assign({}, klass,
                           { attributes: klass.attributes.slice(0) });
    });
  }

  attributes(): SchemaRow[] {
    const { log } = this.deps;
    log.debug("Entering InetOrgPerson.attributes().");
    log.debug("Leaving InetOrgPerson.attributes().");
    return ALL.slice(0);
  }

  attribute(name: unknown): SchemaRow | null {
    const { log } = this.deps;
    log.debug("Entering InetOrgPerson.attribute().");
    log.debug("Leaving InetOrgPerson.attribute().");
    return BY_NAME.get(
      String(name == null ? '' : name).trim().toLowerCase()) || null;
  }

  // -------------------------------------------------------------------------
  // ONE ROW, READY TO DRAW: the schema row, and whatever the entry holds for
  // it.
  //
  // **THE REFUSALS ARE APPLIED HERE AND NOT AT THE PAGE**, which is the whole
  // reason this function exists rather than each caller joining the two halves
  // itself. A `secret` row never returns a value and a `binary` row returns its
  // SIZE, so a second surface that draws this list cannot leak what the first
  // one was careful about.
  //
  // `entry` is the stored attribute map — lower-cased names, array values,
  // which is exactly what `ldap/ldap_server.js` holds and hands over.
  // -------------------------------------------------------------------------
  rowFor(row: SchemaRow, entry: StoredEntry): DrawnRow {
    const { log } = this.deps;
    log.debug("Entering InetOrgPerson.rowFor().");
    const held = (entry || {})[row.ldap.toLowerCase()];
    const values: unknown[] = Array.isArray(held) ? held :
                   (held === undefined ? [] : [held]);
    const present = values.length > 0 &&
      values.some(function (one) {
        return String(one) !== '';
      });
    const out: DrawnRow = {
      ldap: row.ldap,
      label: row.label,
      rfc: row.rfc,
      note: row.note || '',
      must: !!row.must,
      secret: !!row.secret,
      binary: !!row.binary,
      present: present,
      count: values.length,
      values: []
    };
    if (!present) {
      log.debug("Leaving InetOrgPerson.rowFor().");
      return out;
    }
    if (row.secret) {
      log.debug("Leaving InetOrgPerson.rowFor().");
      // NAMED AND NOT PRINTED. See the header.
      return out;
    }
    if (row.binary) {
      // THE SIZE, not the octets. A Buffer knows its length; a string that
      // came back from a store that stringified it is measured in bytes rather
      // than characters, because what a reader wants to know is how big the
      // thing is.
      out.bytes = values.reduce<number>(function (total: number, one) {
        return total + (Buffer.isBuffer(one)
          ? one.length : Buffer.byteLength(String(one), 'utf8'));
      }, 0);
      log.debug("Leaving InetOrgPerson.rowFor().");
      return out;
    }
    out.values = values.map(String);
    log.debug("Leaving InetOrgPerson.rowFor().");
    return out;
  }

  // -------------------------------------------------------------------------
  // THE WHOLE THING FOR ONE ENTRY, grouped by class, which is what a page
  // wants.
  //
  // `held` on each class is how many of its attributes this entry actually
  // carries — a page that can say *4 of 6* in a heading can let a reader skip
  // a section, and computing it here means the page does not walk the rows
  // twice.
  // -------------------------------------------------------------------------
  describe(entry: StoredEntry) {
    const { log } = this.deps;
    const self = this;
    log.debug('Entering InetOrgPerson.describe(). ' +
              Object.keys(entry || {}).length + ' stored attribute(s).');
    const groups = CLASSES.map(function (klass) {
      const rows = klass.attributes.map(function (row) {
        return self.rowFor(row, entry);
      });
      return {
        id: klass.id, name: klass.name, rfc: klass.rfc, oid: klass.oid,
        what: klass.what,
        rows: rows,
        held: rows.filter(function (one) {
          return one.present;
        }).length,
        total: rows.length
      };
    });
    const held = groups.reduce(function (n, g) {
      return n + g.held;
    }, 0);
    log.debug('Leaving InetOrgPerson.describe(). ' + held + ' of ' +
              ALL.length + ' standard attribute(s) are set.');
    return { classes: groups, held: held, total: ALL.length };
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
const slot = new InstanceSlot<InetOrgPerson>(
  'common/inetorgperson',
  () => new InetOrgPerson(InetOrgPerson.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  InetOrgPerson: InetOrgPerson,
  installInstance: (instance: InetOrgPerson): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  CLASSES: CLASSES,
  CANONICAL_NAMES: CANONICAL_NAMES,
  classes: slot.forward('classes'),
  attributes: slot.forward('attributes'),
  attribute: slot.forward('attribute'),
  rowFor: slot.forward('rowFor'),
  describe: slot.forward('describe')
};
