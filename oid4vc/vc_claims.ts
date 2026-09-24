'use strict';
//
// File: vc_claims.ts
//
// ---------------------------------------------------------------------------
// WHAT AN ISSUED CREDENTIAL SAYS ABOUT A PERSON, and where each of those facts
// comes from.
//
// Until this file existed, the answer was seven lines in vc_issuer.ts:
// given_name, family_name, email, birthdate, nationality and an address, four
// of them constants written into the source. That is enough to demonstrate one
// credential and not enough to exercise a wallet — the interesting questions a
// holder asks are "what happens when the credential carries fourteen claims",
// "what does the verifier do with one it has never seen" and "does the issuer
// metadata really describe what arrives", and none of them can be asked without
// changing the claim list.
//
// So the claim list is CONFIGURATION, /admin/vc is the page that sets it, and
// this module is where it lives. It is a LIBRARY in the sense dpop.js and
// admin_stats.js are: it registers no route, so its position in the require
// order does not matter, and it requires only libraries that never require it
// back (each require below says why), so it cannot join a cycle. That matters
// more here than usual, because its readers sit at very different points of
// the require order — `common/claim_attributes.ts` (first of all),
// `oauth2.js` and vc_issuer.ts (early), `federation_map.js`, `admin.js` and
// `admin-core/` (late), and `ldap_server.js` and `scim_map.ts` (later still).
//
// ---------------------------------------------------------------------------
// THE CATALOGUE IS OF LDAP ATTRIBUTES, NOT OF CLAIMS, and that is the decision
// everything else here follows from.
//
// A claim name is this service's own invention until something backs it. An
// attribute type is a name a directory already knows, and this service HAS a
// directory — ldap_server.js seeds an entry for everybody who authenticates
// through any of the sixteen families. So the page offers what a person's entry
// can hold, each row saying which claim it becomes, and the value in the
// credential is the value in the directory. Two things fall out of that which
// were the point of doing it this way:
//
//   * the same fact is visible in two protocols. `mail` on uid=alice,ou=users
//     is what a wallet gets as `email`, so an LDAP client and an OID4VCI wallet
//     can be pointed at one service and shown the same person.
//   * "populate the fields" has an obvious meaning. A selected attribute that
//     an entry does not carry gets generated at the entry, once, and everything
//     downstream reads it from there.
//
// Three rows are NOT RFC 4519/4524/2798 and say so on the page: birthdate and
// nationality have no standard attribute type in those documents, so the SCHAC
// schema's names are borrowed (urn:mace:terena.org:schac), and they are
// borrowed rather than invented so that somebody who exports this directory
// into a real one has a name that already means what they want.
//
// ---------------------------------------------------------------------------
// THE GENERATED VALUES ARE GARBAGE, AND THEY ARE DETERMINISTIC.
//
// Garbage because nothing here is a real person and a mock that invented
// plausible-looking real data would eventually have one of those values
// believed. Deterministic — seeded from the username — because the alternative
// costs more than it looks: a random birthdate per call means the credential
// issued at 10:00 and the credential issued at 10:01 describe two different
// people, the directory entry disagrees with both, and a wallet's "did this
// change" check fires on something that is not the thing being tested. So alice
// is the same invented person for the life of the process AND across restarts,
// which also means the directory can be off entirely and the claims still hold
// still.
//
// One persona per user, not one value per field, for the same reason: a
// given_name of "Ingrid" beside an email of "kwame.osei@..." is two facts that
// contradict each other, and a reader who notices spends the next ten minutes
// deciding whether it is a bug here.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `VcClaims` takes the logger, the identity registry, the mode, the
// error codes and the per-realm selection store through its constructor. The
// catalogue and the store stay module-scope declarations (a store becomes per
// realm at its declaration), and the directory slot is the instance's. Since
// #50's R2 the composition root builds the instance; every old name is a
// FACADE forwarding to it — `setDirectory` among them, the slot
// `ldap_server.js` fills at its require time, after the root has installed
// the instance — and a process without the root builds a default at load.
// ---------------------------------------------------------------------------

import crypto = require('crypto');
// TRUST REALMS: the claim selection below is per realm.
import realms = require('../common/realms');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
// For ONE function: identityKeyOf(), which turns every spelling of a person
// into the one local name this service files them under. It is the same
// normalisation ldap_server.js uses to build `uid=<name>,ou=users` and that
// /admin/users files a row under, and using anything else here would be the bug
// CLAUDE.md's "one row is one local name" rule exists to prevent — see
// personaFor() for what it looked like: an access token whose sub is
// `urn:uuid:<entryUUID>` inventing a second alice, with her directory entry
// sitting right there unread.
//
// admin_stats.js is a library that registers no route and whose requires
// never reach this module, so this is no cycle and no ordering constraint. It
// is also already required by vc_issuer.ts and app.js, so nothing is loaded
// here that was not loaded anyway.
import stats = require('../common/admin_stats');
// THE MODE, for one question: may a value be INVENTED where the directory
// holds none? A LEAF (rule 3) — it requires only `config` — so this require
// can neither close a cycle nor move a route. See `valueFor()` and
// `generatedFor()`, the two places the persona reaches anything outside this
// file.
import mode = require('../common/mode');
// ISO 3166-1 alpha-3 and ICAO nationality codes (#128). A LEAF: `helpers`
// only.
import countryCodes = require('../common/country_codes');
// The error codes (common/error_codes.js). A LEAF that requires nothing, so it
// adds nothing to the short list of what this library may require.
import errorCodes = require('../common/error_codes');

// One row of the catalogue — see THE CATALOGUE below.
interface CatalogueRow {
  ldap: string;
  claim: string[];
  label: string;
  schema: string;
  from: string | null;
  ldpTerm: string | null;
  byDefault: boolean;
  toClaim?: (value: unknown) => string;
  // #128: the claim is an ARRAY of every value the attribute holds, each
  // through `toClaim` — `nationalities` is the one.
  multi?: boolean;
  // #128: a SECOND claim the same attribute becomes, converted —
  // `address.country_code` from `c`. A row, not a second row, because the
  // catalogue is keyed by attribute and one attribute is one selection.
  also?: { claim: string[]; toClaim: (value: unknown) => string };
}

// What `ldap_server.js` installs through `setDirectory()`.
interface DirectoryHooks {
  attributesFor?(key: string): Record<string, unknown[]> | null;
  populate?(): { examined?: number; changed?: number; values?: number;
                 attributes?: string[]; skipped?: string } | null;
}

interface VcClaimsDeps {
  log: typeof helpers.log;
  stats: { identityKeyOf(name: unknown): string };
  mode: { inventsClaimValues(): boolean };
  errorCodes: { tag(code: string): string };
  state: { selection: string[] };
}

// ---------------------------------------------------------------------------
// THE CATALOGUE.
//
// Per row:
//   ldap       the attribute type, spelled the way its schema document spells it
//   claim      the claim path it becomes — ['address','locality'] is nested
//   label      what the page and the credential's `display` call it
//   schema     where the attribute type is defined; shown on the page, because
//              the three non-standard ones have to be distinguishable from the
//              twenty-one standard ones at a glance
//   from       which member of the generated persona fills it
//   toClaim    the LDAP value -> claim value conversion, where the two differ.
//              Only two do, and both differ in punctuation only: a generalized
//              date is YYYYMMDD where a claim is YYYY-MM-DD (OIDC Core 5.1 says
//              ISO 8601 / RFC 3339), and a postalAddress separates lines with
//              '$' (RFC 4517 3.3.28) where the OIDC `formatted` member uses a
//              newline. Absent means the value passes through unchanged.
//   ldpTerm    the term to use in an ldp_vc credential, or null. See LDP below —
//              this is the one place where a claim cannot simply be added.
//   byDefault  whether it is selected on a fresh start. The ten that are
//              reproduce exactly the six claims this issuer carried before this
//              page existed.
//
// `claim` values are strings throughout. A directory attribute is a string
// (this store holds no syntaxes), and a credential whose `birthdate` was
// sometimes a number would be a different interoperability problem than the one
// this service is for.
// ---------------------------------------------------------------------------
const VC_ATTRIBUTES: CatalogueRow[] = [
  { ldap: 'givenName', claim: ['given_name'], label: 'Given name',
    // RFC 4519 section 2 is alphabetical: 2.6 is `destinationIndicator`.
    // This said 2.6 until 2026-09-11, when `common/inetorgperson.ts` was
    // checked against the RFC text and the two catalogues were compared.
    schema: 'RFC 4519 2.12', from: 'given', ldpTerm: 'given_name',
    byDefault: true },
  { ldap: 'sn', claim: ['family_name'], label: 'Family name',
    schema: 'RFC 4519 2.32', from: 'family', ldpTerm: 'family_name',
    byDefault: true },
  { ldap: 'mail', claim: ['email'], label: 'Email address',
    schema: 'RFC 4524 2.16', from: 'email', ldpTerm: 'email', byDefault: true },
  { ldap: 'schacDateOfBirth', claim: ['birthdate'], label: 'Date of birth',
    schema: 'SCHAC 1.5.0 (not RFC 4519)', from: 'birth', ldpTerm: 'birthDate',
    byDefault: true,
    // YYYYMMDD in the directory, YYYY-MM-DD in the credential. SCHAC defines
    // the attribute with the generalized-time-like syntax; OIDC Core 5.1
    // defines `birthdate` as ISO 8601-2004 YYYY-MM-DD. Neither side is being
    // corrected here — they are two documents that spell one date differently.
    toClaim: function (value) {
      helpers.log.debug("Entering toClaim().");
      const digits = String(value).replace(/[^0-9]/g, '');
      if (digits.length < 8) {
        helpers.log.debug("Leaving toClaim().");
        return String(value);
      }
      helpers.log.debug("Leaving toClaim().");
      return digits.slice(0, 4) + '-' + digits.slice(4, 6) + '-' +
             digits.slice(6, 8);
    } },
  // `nationalities` (#128, OpenID Connect for Identity Assurance Claims
  // Registration 1.0 section 4.1): every citizenship the entry holds, as ICAO
  // Doc 9303 three-letter codes. It REPLACED `nationality`, a single ISO
  // alpha-2 string that was this service's own invention (rcbj, no
  // back-compat). The directory keeps SCHAC's two letters.
  { ldap: 'schacCountryOfCitizenship', claim: ['nationalities'],
    label: 'Nationalities',
    schema: 'SCHAC 1.5.0 (not RFC 4519)', from: 'country', ldpTerm:
                                                             'nationality',
    byDefault: true, multi: true,
    toClaim: function (value) {
      helpers.log.debug("Entering toClaim().");
      helpers.log.debug("Leaving toClaim().");
      return countryCodes.icaoNationality(value);
    } },
  { ldap: 'street', claim: ['address', 'street_address'], label: 'Street ' +
      'address',
    schema: 'RFC 4519 2.34', from: 'street', ldpTerm: 'streetAddress',
    byDefault: true },
  { ldap: 'l', claim: ['address', 'locality'], label: 'Locality',
    schema: 'RFC 4519 2.16', from: 'locality', ldpTerm: 'locality',
    byDefault: true },
  { ldap: 'st', claim: ['address', 'region'], label: 'Region',
    schema: 'RFC 4519 2.33', from: 'region', ldpTerm: 'region',
    byDefault: true },
  { ldap: 'postalCode', claim: ['address', 'postal_code'], label: 'Postal code',
    schema: 'RFC 4519 2.24', from: 'postalCode', ldpTerm: null,
    byDefault: true },
  { ldap: 'c', claim: ['address', 'country'], label: 'Country',
    schema: 'RFC 4519 2.2', from: 'country', ldpTerm: 'country',
    byDefault: true,
    // The Claims Registration's `address.country_code` (section 4.2): the
    // same country as ISO 3166-1 Alpha-3 (#128).
    also: { claim: ['address', 'country_code'],
            toClaim: function (value) {
              helpers.log.debug("Entering toClaim().");
              helpers.log.debug("Leaving toClaim().");
              return countryCodes.alpha3(value);
            } } },

  // --- not selected on a fresh start ---------------------------------------
  { ldap: 'postalAddress', claim: ['address', 'formatted'],
    label: 'Formatted address',
    schema: 'RFC 4519 2.23', from: 'formatted', ldpTerm: null, byDefault: false,
    // RFC 4517 3.3.28: the lines of a postal address are separated by '$'. The
    // OIDC `formatted` member is "full mailing address, formatted for display",
    // with newlines. Same address, two punctuations.
    toClaim: function (value) {
      helpers.log.debug("Entering toClaim().");
      helpers.log.debug("Leaving toClaim().");
      return String(value).split('$').join('\n');
    } },
  { ldap: 'cn', claim: ['name'], label: 'Full name',
    schema: 'RFC 4519 2.3', from: 'display', ldpTerm: null, byDefault: false },
  { ldap: 'displayName', claim: ['nickname'], label: 'Display name',
    schema: 'RFC 2798 2.3', from: 'given', ldpTerm: null, byDefault: false },
  { ldap: 'uid', claim: ['preferred_username'], label: 'User id',
    schema: 'RFC 4519 2.39', from: 'username', ldpTerm: null,
    byDefault: false },
  { ldap: 'telephoneNumber', claim: ['phone_number'], label: 'Telephone number',
    schema: 'RFC 4519 2.35', from: 'phone', ldpTerm: null, byDefault: false },
  // `msisdn` (#128, the Claims Registration section 4.1): the mobile number
  // as E.164 digits with no `+`. It replaced `mobile_phone_number`, this
  // service's own name for the same attribute.
  { ldap: 'mobile', claim: ['msisdn'], label: 'Mobile number (MSISDN)',
    schema: 'RFC 4524 2.18', from: 'mobile', ldpTerm: null, byDefault: false,
    toClaim: function (value) {
      helpers.log.debug("Entering toClaim().");
      helpers.log.debug("Leaving toClaim().");
      return String(value).replace(/[^0-9]/g, '');
    } },
  // THE JOB TITLE IS `job_title` (#128, rcbj): the Claims Registration
  // defines `title` as an honorific ("Dr", "Prof"), which is the row below.
  { ldap: 'title', claim: ['job_title'], label: 'Job title',
    schema: 'RFC 4519 2.38', from: 'title', ldpTerm: null, byDefault: false },
  { ldap: 'schacPersonalTitle', claim: ['title'],
    label: 'Title (honorific)', schema: 'SCHAC 1.5.0 (not RFC 4519)',
    from: 'honorific', ldpTerm: null, byDefault: false },
  // The rest of the Claims Registration's section 4.1 (#128). No standard
  // attribute type exists for any of them, so they are this service's own,
  // like `employeeStatus`.
  { ldap: 'salutation', claim: ['salutation'], label: 'Salutation',
    schema: "this service's own (no standard type)", from: 'salutation',
    ldpTerm: null, byDefault: false },
  { ldap: 'birthFamilyName', claim: ['birth_family_name'],
    label: 'Family name at birth',
    schema: "this service's own (no standard type)", from: 'family',
    ldpTerm: null, byDefault: false },
  { ldap: 'birthGivenName', claim: ['birth_given_name'],
    label: 'Given name at birth',
    schema: "this service's own (no standard type)", from: 'given',
    ldpTerm: null, byDefault: false },
  { ldap: 'birthMiddleName', claim: ['birth_middle_name'],
    label: 'Middle name at birth',
    schema: "this service's own (no standard type)", from: null,
    ldpTerm: null, byDefault: false },
  { ldap: 'alsoKnownAs', claim: ['also_known_as'], label: 'Also known as',
    schema: "this service's own (no standard type)", from: null,
    ldpTerm: null, byDefault: false },
  { ldap: 'placeOfBirthCountry', claim: ['place_of_birth', 'country'],
    label: 'Country of birth',
    schema: "this service's own (no standard type)", from: 'country',
    ldpTerm: null, byDefault: false,
    // ISO 3166-1 Alpha-3, one of the three forms section 4.1 allows.
    toClaim: function (value) {
      helpers.log.debug("Entering toClaim().");
      helpers.log.debug("Leaving toClaim().");
      return countryCodes.alpha3(value);
    } },
  { ldap: 'placeOfBirthRegion', claim: ['place_of_birth', 'region'],
    label: 'Region of birth',
    schema: "this service's own (no standard type)", from: 'region',
    ldpTerm: null, byDefault: false },
  { ldap: 'placeOfBirthLocality', claim: ['place_of_birth', 'locality'],
    label: 'Locality of birth',
    schema: "this service's own (no standard type)", from: 'locality',
    ldpTerm: null, byDefault: false },
  { ldap: 'o', claim: ['organization'], label: 'Organization',
    schema: 'RFC 4519 2.19', from: 'organization', ldpTerm: null,
    byDefault: false },
  { ldap: 'ou', claim: ['organizational_unit'], label: 'Organizational unit',
    schema: 'RFC 4519 2.20', from: 'unit', ldpTerm: null, byDefault: false },
  { ldap: 'departmentNumber', claim: ['department'], label: 'Department',
    schema: 'RFC 2798 2.2', from: 'department', ldpTerm: null,
    byDefault: false },
  { ldap: 'employeeNumber', claim: ['employee_number'],
    label: 'Employee number',
    schema: 'RFC 2798 2.4', from: 'employeeNumber', ldpTerm: null, byDefault:
                                                                     false },
  { ldap: 'employeeType', claim: ['employee_type'], label: 'Employee type',
    schema: 'RFC 2798 2.5', from: 'employeeType', ldpTerm: null,
    byDefault: false },
  { ldap: 'preferredLanguage', claim: ['locale'], label: 'Locale',
    schema: 'RFC 2798 2.7', from: 'locale', ldpTerm: null, byDefault: false },
  { ldap: 'labeledURI', claim: ['website'], label: 'Web page',
    // RFC 2079's sections are unnumbered, so there is no `2` to cite.
    schema: 'RFC 2079', from: 'website', ldpTerm: null, byDefault: false },
  { ldap: 'description', claim: ['description'], label: 'Description',
    schema: 'RFC 4519 2.5', from: null, ldpTerm: null, byDefault: false },
  { ldap: 'employeeStatus', claim: ['employee_status'],
    label: 'Employee status',
    schema: "this service's own (no standard type)", from: 'employeeStatus',
    ldpTerm: null, byDefault: false }
];

// Lower-cased attribute name -> row. The store in ldap_server.js lower-cases
// every attribute name on the way in (@ldapjs/attribute does it, and LDAP
// attribute descriptions are case-insensitive anyway), so every lookup that
// starts from a stored entry has to start from the lower-cased name.
const BY_LDAP = new Map<string, CatalogueRow>();
VC_ATTRIBUTES.forEach(function (row) {
  BY_LDAP.set(row.ldap.toLowerCase(), row);
});

// ---------------------------------------------------------------------------
// THE SAME CATALOGUE READ AS "WHAT A PERSON HERE HAS", WHICH IS A DIFFERENT
// QUESTION FROM "WHAT A CREDENTIAL MAY CARRY" AND HAS THE SAME ANSWER.
//
// Added 2026-09-06 for /admin/users/new, the form on which an operator types a
// person's details by hand instead of accepting the invented ones. That form
// needs a list of the fields a person in this directory HAS, and `createUser()`
// needs a list of the attributes it will accept from a caller — and if those
// two lists were written out separately they would be a form offering a field
// the writer silently drops, which is the worst shape a form can have.
//
// **IT IS THE WHOLE CATALOGUE AND NOT THE SELECTED ROWS.** `selectedRows()` is
// about what an ISSUED CREDENTIAL asserts, which is a choice made on
// /admin/vc; a person's telephone number is a fact about them whether or not
// any credential carries it, and a create form that hid the unselected rows
// would make the directory's contents depend on an unrelated page's setting.
//
// **`uid` IS THE ONE ROW LEFT OUT, AND ITS ABSENCE IS THE POINT.** It is the
// USERNAME — `namePlan()` builds the DN out of it — so a form field for it
// would be a second box asking the same question as the one marked required,
// and a caller that filled both differently would create `uid=alice` whose uid
// says `bob`. The username is asked for once, at the top.
//
// `description` STAYS IN, though it is the one row that is never invented
// (`from` is null): this service writes a sentence there saying why the entry
// exists, and an operator who wants to say something else about a person
// should be able to. `createUser()` lets a typed one win over its own note and
// says so.
// ---------------------------------------------------------------------------
const PERSON_FIELDS = VC_ATTRIBUTES.filter(function (row) {
  return row.ldap.toLowerCase() !== 'uid';
});

// Lower-cased attribute name -> row, over PERSON_FIELDS. What a writer checks a
// caller's attribute name against; the store lower-cases every name on the way
// in, so this is keyed the way a stored entry is.
const PERSON_BY_LDAP = new Map<string, CatalogueRow>();
PERSON_FIELDS.forEach(function (row) {
  PERSON_BY_LDAP.set(row.ldap.toLowerCase(), row);
});

// What the directory should CALL each of these when it shows them.
// ldap_server.js merges this into its own CANONICAL_NAMES table rather than
// repeating the spellings, because a page showing `schacdateofbirth` where the
// schema document says `schacDateOfBirth` reads as a bug in the page.
const CANONICAL_NAMES: Record<string, string> = {};
VC_ATTRIBUTES.forEach(function (row) {
  CANONICAL_NAMES[row.ldap.toLowerCase()] = row.ldap;
});

// ---------------------------------------------------------------------------
// The selection.
//
// A list of lower-cased attribute names, per realm and persisted — see `state`
// below for why it is a list and not a Set.
// ---------------------------------------------------------------------------
// Canonically spelled, because this list is published — /admin/vc answers it in
// its JSON — and a page reporting `schacdateofbirth` as the default beside
// `schacDateOfBirth` as the selection would read as two different attributes.
// The Set below holds the lower-cased form, which is what every lookup uses.
const DEFAULT_SELECTION = VC_ATTRIBUTES.filter(function (
    row) { return row.byDefault; })
                                       .map(function (
                                           row) { return row.ldap; });

// PER TRUST REALM. Which attributes an issued credential asserts is a decision
// a realm makes for itself — two realms issuing the same credential type with
// different claims is exactly the case somebody defines a second realm to
// build. `realms.obj(factory)` is a plain object per realm, so
// `state.selection` reads and `state.selection = wanted` writes work exactly as
// the binding this replaced did, and each realm's default is the same default.
// **AN ARRAY AND NOT A SET, AND ONLY SO THAT IT CAN BE PERSISTED
// (2026-09-07).** This store is the credential claim set — an operator's
// choice, not something minted — and it has to reach every request worker or
// each one issues a different credential. A store replicates by declaring
// `persist:`, and what is written is `JSON.stringify` of the value: a Set
// serialises to `{}`, so declaring one would have persisted the shape and lost
// every member, silently and with nothing failing.
//
// The working value inside setSelection() is still a Set — membership and
// difference are what that function does — and only the STORED form is a list.
const state = realms.obj(function () {
  return { selection: DEFAULT_SELECTION.map(function (name) {
    return name.toLowerCase();
  }) };
}, { persist: 'vc_claims.state' });

// Deliberately not a real-looking set of names from one place: a mock whose
// invented people were all from one country teaches somebody's test suite that
// names look like that.
const GIVEN_NAMES = ['Ada', 'Kwame', 'Ingrid', 'Hiroshi', 'Rosa', 'Tariq',
                     'Mei',
                     'Olof', 'Priya', 'Diego', 'Yusuf', 'Freya', 'Nadia',
                     'Emeka',
                     'Sofia', 'Jonas'];
const FAMILY_NAMES = ['Lovelace', 'Osei', 'Lindqvist', 'Tanaka', 'Marquez',
                      'Haddad',
                      'Chen', 'Nilsen', 'Raman', 'Duarte', 'Demir', 'Halvorsen',
                      'Farouk', 'Okonkwo', 'Ferrari', 'Weber'];
const STREETS = ['Fictitious Way', 'Placeholder Street', 'Example Avenue',
                 'Sample Road',
                 'Mock Lane', 'Nowhere Terrace', 'Specimen Close', 'Dummy ' +
                     'Boulevard'];
// Locality, region, country and a postal code SHAPE that belongs to that
// country, kept together in one row so that an address cannot be assembled out
// of parts that contradict each other. `postal` is a template: # is a digit, @
// a letter.
const PLACES = [
  { locality: 'Springfield', region: 'IL', country: 'US', postal: '#####' },
  { locality: 'Fairview', region: 'OR', country: 'US', postal: '#####' },
  { locality: 'Riverton', region: 'NJ', country: 'US', postal: '#####' },
  { locality: 'Kingsford', region: 'ON', country: 'CA', postal: '@#@ #@#' },
  { locality: 'Eastgate', region: 'Greater Manchester', country: 'GB',
    postal: '@@# ' +
      '#@@' },
  { locality: 'Nordhavn', region: 'Hovedstaden', country: 'DK',
    postal: '####' },
  { locality: 'Sudbury', region: 'Victoria', country: 'AU', postal: '####' },
  { locality: 'Westerveld', region: 'Utrecht', country: 'NL',
    postal: '#### @@' }
];
const TITLES = ['Principal Engineer', 'Support Analyst', 'Directory ' +
    'Administrator',
                'Field Technician', 'Product Manager', 'Security Architect',
                'Staff Researcher', 'Service Desk Lead'];
// Honorifics and salutations (#128), invented as the rest is.
const HONORIFICS = ['Dr', 'Prof', 'Dr', 'Prof Dr'];
const SALUTATIONS = ['Mx', 'Ms', 'Mr'];
const DEPARTMENTS = ['0001', '0042', '1120', '3300', '7250', '8800'];
const UNITS = ['Engineering', 'Operations', 'Research', 'Support', 'Security'];
const EMPLOYEE_TYPES = ['Full time', 'Contractor', 'Intern', 'Part time'];
const EMPLOYEE_STATUSES = ['Active', 'On leave', 'Probation'];
const LOCALES = ['en-US', 'en-GB', 'sv-SE', 'ja-JP', 'pt-BR', 'nl-NL'];
// example.com, example.org and example.net are reserved for exactly this by
// RFC 2606, so an invented address cannot be somebody's real mailbox.
const MAIL_DOMAINS = ['example.com', 'example.org', 'example.net'];

class VcClaims {
  static readonly VC_ATTRIBUTES = VC_ATTRIBUTES;
  static readonly CANONICAL_NAMES = CANONICAL_NAMES;
  static readonly DEFAULT_SELECTION = DEFAULT_SELECTION;
  static readonly PERSON_FIELDS = PERSON_FIELDS;

  // The directory's hooks, or null — see setDirectory().
  private directory: DirectoryHooks | null = null;

  constructor(private readonly deps: VcClaimsDeps) {
    deps.log.debug("Entering VcClaims.constructor().");
    deps.log.debug("Leaving VcClaims.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): VcClaimsDeps {
    helpers.log.debug("Entering VcClaims.defaultDeps().");
    helpers.log.debug("Leaving VcClaims.defaultDeps().");
    return {
      log: helpers.log,
      stats: stats,
      mode: mode,
      errorCodes: errorCodes,
      state: state
    };
  }

  // The rows, in catalogue order, for a caller that is going to draw them. A
  // COPY of the array — the rows themselves are shared, because they are
  // read-only everywhere — so that a caller sorting or splicing the list cannot
  // reorder the catalogue for everybody else.
  personFields() {
    const { log } = this.deps;
    log.debug("Entering VcClaims.personFields().");
    log.debug("Leaving VcClaims.personFields().");
    return PERSON_FIELDS.slice(0);
  }

  // The row for one attribute name, in any case, or null. This is the whole of
  // the "may a create write this?" decision, and it is a lookup rather than a
  // regex on purpose: the set of attributes a person here has is a LIST, and a
  // caller sending `userPassword` or `oauthClientSecret` on a create form is
  // refused because those are not on it rather than because somebody remembered
  // to name them.
  personField(name: unknown) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.personField().");
    log.debug("Leaving VcClaims.personField().");
    return PERSON_BY_LDAP.get(String(name == null ? '' : name).trim()
      .toLowerCase()) || null;
  }

  // ---------------------------------------------------------------------------
  // LDP_VC IS THE ONE FORMAT WHERE A CLAIM CANNOT SIMPLY BE ADDED.
  //
  // The other two formats are JOSE-secured: a claim is a member of a JSON
  // object and any name works. An ldp_vc credential is JSON-LD, signed over
  // CANONICALIZED RDF, and bbs2023.js canonicalizes with `safe: true` — so a
  // term the vendored context does not define is not dropped quietly, it
  // THROWS, and the throw arrives at issuance time inside a cryptosuite rather
  // than on this page.
  //
  // The vendored context (contexts/idptools_identity_v1.json) is signed over,
  // so it cannot be edited to add a term without invalidating every credential
  // issued against the old one — which is exactly why it is vendored rather
  // than fetched. So each row names the term to use in that format or null, and
  // vc_issuer.ts filters the subject through the context it actually loaded. A
  // selected attribute with no term is simply absent from an ldp_vc credential;
  // the page says which those are, because "the same configuration produces
  // different credentials in different formats" is a surprise if it is
  // discovered rather than stated.
  // ---------------------------------------------------------------------------
  private ldpTermFor(row: CatalogueRow) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.ldpTermFor().");
    log.debug("Leaving VcClaims.ldpTermFor().");
    return row.ldpTerm || '';
  }

  // The selected rows, in CATALOGUE order rather than in the order they were
  // chosen. The order reaches the credential (it is the order of the
  // Disclosures and of the metadata's claims array), and a claims list that
  // reordered itself because somebody unticked and reticked a box would look
  // like a different credential to anything diffing them.
  selectedRows() {
    const { log, state } = this.deps;
    log.debug("Entering VcClaims.selectedRows().");
    log.debug("Leaving VcClaims.selectedRows().");
    return VC_ATTRIBUTES.filter((row) => {
      return state.selection.indexOf(row.ldap.toLowerCase()) >= 0;
    });
  }

  isSelected(ldapName: unknown) {
    const { log, state } = this.deps;
    log.debug("Entering VcClaims.isSelected().");
    log.debug("Leaving VcClaims.isSelected().");
    return state.selection.indexOf(String(ldapName || '').toLowerCase()) >= 0;
  }

  selectedNames() {
    const { log } = this.deps;
    log.debug("Entering VcClaims.selectedNames().");
    log.debug("Leaving VcClaims.selectedNames().");
    return this.selectedRows().map((row) => { return row.ldap; });
  }

  // Install a whole selection at once. Returns the errors rather than throwing,
  // because the caller is a form handler that has to redisplay them — the same
  // contract admin_stats.setClaimSet() has.
  //
  // An unknown attribute is an ERROR and not a silent omission: the page offers
  // a fixed list, so an unknown name means either a hand-written request (which
  // deserves an answer) or a rename here that left a caller behind. Both are
  // worth a message.
  setSelection(names: unknown[]) {
    const { log, state } = this.deps;
    log.debug("Entering VcClaims.setSelection(). " + (names || []).length +
              " name(s) offered.");
    const errors = [];
    const wanted = new Set<string>();
    (names || []).forEach((name) => {
      const key = String(name == null ? '' : name).trim().toLowerCase();
      if (!key) {
        return;
      }
      if (!BY_LDAP.has(key)) {
        errors.push('There is no attribute called "' + name + '" in the ' +
            'catalogue.');
        return;
      }
      wanted.add(key);
    });
    if (errors.length) {
      log.debug("Leaving VcClaims.setSelection(). " + errors.length + " " +
                "error(s); nothing changed.");
      return { ok: false, errors: errors };
    }
    // A Set for the difference below; the stored form is the list.
    const before = new Set(state.selection);
    const added = [];
    const removed = [];
    wanted.forEach((key) => {
      if (!before.has(key)) added.push(BY_LDAP.get(key).ldap);
    });
    before.forEach((key) => {
      if (!wanted.has(key)) removed.push(BY_LDAP.get(key).ldap);
    });
    state.selection = Array.from(wanted);
    log.info('vc: the credential claim set is now ' +
             (this.selectedNames().join(', ') || '(empty)') +
             '. Added: ' + (added.join(', ') || 'nothing') + '. Removed: ' +
             (removed.join(', ') || 'nothing') + '.');
    log.debug("Leaving VcClaims.setSelection(). " + wanted.size +
              " attribute(s) selected.");
    return { ok: true, selected: this.selectedNames(), added: added,
             removed: removed };
  }

  resetSelection() {
    const { log } = this.deps;
    log.debug("Entering VcClaims.resetSelection().");
    const result = this.setSelection(DEFAULT_SELECTION);
    log.debug("Leaving VcClaims.resetSelection().");
    return result;
  }

  // ---------------------------------------------------------------------------
  // THE INVENTED PEOPLE.
  //
  // A seeded PRNG rather than Math.random(), for the reason in the header: one
  // username is one invented person, for the life of this process and across
  // restarts. The seed is the first four bytes of SHA-256 over the name, which
  // is a hash used as a hash and not as a security boundary — there is nothing
  // to protect here, and saying so is cheaper than leaving a reader to wonder.
  //
  // mulberry32, written out rather than taken from a dependency: it is eight
  // lines and a dependency whose only job is to be deterministic is a
  // dependency whose version bump silently changes every generated value.
  // ---------------------------------------------------------------------------
  private randomFor(seedText: unknown) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.randomFor().");
    const digest = crypto.createHash('sha256')
                         .update(String(seedText), 'utf8')
                         .digest();
    let state = digest.readUInt32LE(0);
    log.debug("Leaving VcClaims.randomFor().");
    return () => {
      state = (state + 0x6d2b79f5) >>> 0;
      let t = state;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  private pick(random: () => number, list: any[]) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.pick().");
    log.debug("Leaving VcClaims.pick().");
    return list[Math.floor(random() * list.length) % list.length];
  }

  private digits(random: () => number, count: number) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.digits().");
    let out = '';
    for (let i = 0; i < count; i++) {
      out += String(Math.floor(random() * 10));
    }
    log.debug("Leaving VcClaims.digits().");
    return out;
  }

  // A postal code from one of the PLACES templates. '#' is a digit and '@' an
  // upper-case letter; everything else is copied. It produces the SHAPE of that
  // country's codes and not a code that exists, which is the whole intent.
  private postalCode(random: () => number, template: string) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.postalCode().");
    const letters = 'ABCDEFGHJKLMNPRSTUVWXYZ';
    log.debug("Leaving VcClaims.postalCode().");
    return String(template).split('').map((ch) => {
      if (ch === '#') {
        return String(Math.floor(random() * 10));
      }
      if (ch === '@') {
        return letters.charAt(Math.floor(random() * letters.length));
      }
      return ch;
    }).join('');
  }

  // One invented person. Every field is derived from the same stream, so they
  // are consistent with each other: the email is built from the given and
  // family names that are also in the entry, the postal code belongs to the
  // country, and the display name is the two names in the order the entry's cn
  // uses.
  //
  // The username is NOT invented — it is the name the person authenticated as.
  // An invented `uid` would disagree with the DN the entry sits at
  // (`uid=<name>`, which autoCreateUser() builds from the same string), and two
  // names for one object is the one kind of garbage this file must not produce.
  personaFor(name: unknown) {
    const { log, stats } = this.deps;
    log.debug("Entering VcClaims.personaFor(). name=" + name);
    // NORMALISED first, and this line is load-bearing. The three spellings of
    // one person reach this module from three directions — `alice` from the
    // directory sweep, `urn:uuid:<entryUUID>` from an access token's sub,
    // `alice@EXAMPLE.COM` from a Kerberos-authenticated one — and the seed is
    // the string. Seeding on the raw value invented a different person per
    // spelling and then failed to find the entry any of them had, so a
    // credential for alice asserted a name her own directory entry
    // contradicted. It looked like the directory was not being read at all,
    // which is the wrong thing to go looking at.
    const username = stats.identityKeyOf(name) || 'somebody';
    const random = this.randomFor(username);
    const given = this.pick(random, GIVEN_NAMES);
    const family = this.pick(random, FAMILY_NAMES);
    const place = this.pick(random, PLACES);
    const street = this.digits(random, 3) + ' ' + this.pick(random, STREETS);
    const postal = this.postalCode(random, place.postal);
    // A four-digit discriminator so that two users who drew the same pair of
    // names do not draw the same mailbox as well. Collisions are otherwise
    // certain: there are 256 name pairs and a mock can easily see more users
    // than that.
    const mailbox = (given + '.' + family).toLowerCase() + '.' +
                    this.digits(random, 4);
    const persona = {
      username: username,
      given: given,
      family: family,
      display: given + ' ' + family,
      email: mailbox + '@' + this.pick(random, MAIL_DOMAINS),
      // 1955-01-01 through 2004-12-31 or thereabouts, written the way SCHAC
      // writes it. The day is capped at 28 so that no invented person is born
      // on the 30th of February — a date a strict consumer rejects, which would
      // make this service look broken for a reason that has nothing to do with
      // credentials.
      birth: String(1955 + Math.floor(random() * 50)) +
             String(1 + Math.floor(random() * 12)).padStart(2, '0') +
             String(1 + Math.floor(random() * 28)).padStart(2, '0'),
      country: place.country,
      street: street,
      locality: place.locality,
      region: place.region,
      postalCode: postal,
      formatted: street + '$' + place.locality + '$' + place.region + ' ' +
                 postal + '$' + place.country,
      // +1-555-01xx is the North American fiction range (555-0100 to 555-0199
      // is reserved for exactly this), so no invented person is given a working
      // line.
      phone: '+1-555-01' + this.digits(random, 2),
      mobile: '+1-555-01' + this.digits(random, 2),
      title: this.pick(random, TITLES),
      organization: 'Example Corporation',
      unit: this.pick(random, UNITS),
      department: this.pick(random, DEPARTMENTS),
      employeeNumber: 'E' + this.digits(random, 6),
      employeeType: this.pick(random, EMPLOYEE_TYPES),
      employeeStatus: this.pick(random, EMPLOYEE_STATUSES),
      locale: this.pick(random, LOCALES),
      website: 'https://www.example.com/~' + username.toLowerCase(),
      // Drawn LAST (#128), so every value above is what it was for every
      // person before these two existed.
      honorific: this.pick(random, HONORIFICS),
      salutation: this.pick(random, SALUTATIONS)
    };
    log.debug("Leaving VcClaims.personaFor(). " + username + " is " +
              persona.display +
              ".");
    return persona;
  }

  // The values the SELECTED attributes would take for this person, keyed by the
  // LOWER-CASED attribute name — which is the key the directory's store uses,
  // so the caller can compare against an entry without normalising anything.
  //
  // A row with no `from` produces nothing. There is one: `description`, which
  // this service already writes on every entry (it records which protocols that
  // person has authenticated through), and inventing a second description would
  // overwrite a fact with a fiction.
  //
  // **NOTHING IN PRODUCT MODE (2026-09-12).** What this returns is written ONTO
  // DIRECTORY ENTRIES by `ldap_server.js`'s populate sweep, and a value written
  // there stops being `generated` and starts being `directory` — so an invented
  // birthdate put on an entry here would come back out of every credential and
  // every claims request as a fact the directory holds. Gating only
  // `valueFor()` below would have left that door open one step earlier.
  // `mode.inventsClaimValues()` is the question, and the sweep then reports
  // that it had nothing to fill rather than filling it.
  generatedFor(name: unknown) {
    const { log, mode } = this.deps;
    log.debug("Entering VcClaims.generatedFor(). name=" + name);
    if (!mode.inventsClaimValues()) {
      log.debug("Leaving VcClaims.generatedFor(). This realm invents no " +
                "claim values.");
      return {};
    }
    const persona = this.personaFor(name);
    const out = {};
    this.selectedRows().forEach((row) => {
      if (!row.from) {
        return;
      }
      const value = persona[row.from];
      if (value === undefined || value === null || value === '') {
        return;
      }
      out[row.ldap.toLowerCase()] = String(value);
    });
    log.debug("Leaving VcClaims.generatedFor(). " + Object.keys(out).length +
              " value(s).");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE DIRECTORY, WHICH THIS MODULE MUST NOT REQUIRE.
  //
  // ldap_server.js is required late in `common/protocol_stack.ts`, after the
  // console and the TLS module, and the reasons are in CLAUDE.md rule 6 —
  // requiring it from here would drag its routes into the express router ahead
  // of every console route, and /admin/sts-metadata is built by walking that
  // router. vc_issuer.ts requiring it would be worse still: that module is
  // required well before the console.
  //
  // So the dependency is inverted exactly as admin_stats.js's user observer and
  // admin.js's directory reader are: this module offers a slot, and
  // ldap_server.js fills it at ITS require time with two functions —
  //
  //   attributesFor(key) the lower-cased attributes of that person's entry, or
  //                        null when the directory holds nothing for them
  //   populate()           fill every existing person's missing selected
  //                        attributes, and say what it did
  //
  // Both are wrapped where they are called. A directory that threw must not be
  // able to fail an issuance — the same rule the user observer follows in the
  // other direction, and for the same reason: this service's job is to hand a
  // wallet a credential, and a store it consults is not allowed to prevent
  // that.
  // ---------------------------------------------------------------------------
  setDirectory(hooks: DirectoryHooks | null) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.setDirectory().");
    this.directory = hooks || null;
    log.debug("A directory was installed; credential claims will now be read " +
              "from entries and populated on them.");
    log.debug("Leaving VcClaims.setDirectory().");
  }

  private directoryAttributes(name: unknown) {
    const { log, stats, errorCodes } = this.deps;
    log.debug("Entering VcClaims.directoryAttributes().");
    if (!this.directory || typeof this.directory.attributesFor !== 'function') {
      log.debug("Leaving VcClaims.directoryAttributes().");
      return null;
    }
    try {
      // Normalised for the reason personaFor() gives: the directory files a
      // person under their local name, and an access token's
      // `urn:uuid:<entryUUID>` would otherwise look up an entry nothing ever
      // created.
      log.debug("Leaving VcClaims.directoryAttributes().");
      return this.directory.attributesFor(stats.identityKeyOf(name)) || null;
    } catch (e) {
      log.debug("Caught in VcClaims.directoryAttributes(): " +
                ((e && e.message) || e));
      log.error(errorCodes.tag('STS-VC-0047') +
                'the directory threw while being read for credential claims ' +
                'and was ignored; the credential is unaffected: ' + e.message);
      log.debug("Leaving VcClaims.directoryAttributes().");
      return null;
    }
    log.debug("Leaving VcClaims.directoryAttributes().");
  }

  // Fill in what the current selection needs, on every person already in the
  // directory. Returned rather than logged only, because the page that triggers
  // it has to be able to say what happened: "nothing to do" and "the directory
  // is not loaded" look identical from the outside and are entirely different
  // answers.
  populateDirectory() {
    const { log, errorCodes } = this.deps;
    log.debug("Entering VcClaims.populateDirectory().");
    if (!this.directory || typeof this.directory.populate !== 'function') {
      log.debug("Leaving VcClaims.populateDirectory(). There is no " +
                "directory loaded.");
      return { ok: false, loaded: false, examined: 0, changed: 0, values: 0,
               errors: ['The embedded LDAP directory is not loaded, so there ' +
                        'are no entries to populate. Nothing else is ' +
                        'affected: the claims below still reach every ' +
                        'credential, generated per user.'] };
    }
    try {
      const result = this.directory.populate() || {};
      log.debug("Leaving VcClaims.populateDirectory(). " +
                (result.changed || 0) + " entry/entries changed.");
      // `skipped` is the directory saying the sweep did not RUN (product mode
      // invents no claim value) — carried through, or the page behind
      // Populate reports "swept 0 entries" about a sweep that never started.
      return { ok: true, loaded: true, examined: result.examined || 0,
               changed: result.changed || 0, values: result.values || 0,
               attributes: result.attributes || [],
               skipped: result.skipped || undefined };
    } catch (e) {
      log.debug("Caught in VcClaims.populateDirectory(): " +
                ((e && e.message) || e));
      // Reported rather than thrown: this is called from a form handler and
      // from the moment the selection changes, and neither of those is allowed
      // to fail because a directory did.
      log.error(errorCodes.tag('STS-VC-0048') +
                'populating the directory for credential claims threw: ' +
                e.message);
      log.debug("Leaving VcClaims.populateDirectory(). It threw.");
      return { ok: false, loaded: true, examined: 0, changed: 0, values: 0,
               errors: ['The directory threw while being populated: ' +
                        e.message] };
    }
  }

  // ---------------------------------------------------------------------------
  // THE CLAIMS THEMSELVES.
  //
  // Three sources, in this order, and the order is the whole of the policy:
  //
  //   1. the ACCESS TOKEN, where it carries a claim of that name. A token claim
  //      is a statement this service already made about the person — it came
  //      from the sign-in or from the custom claims page — and a credential
  //      that contradicted the token that authorised it would be indefensible.
  //   2. the DIRECTORY entry. This is where the generated values live once an
  //      entry exists, and it is also where a value somebody set through LDAP
  //      lives: an operator who does `ldapmodify` on alice's `mail` expects the
  //      next credential to say so, and this is the line that makes that true.
  //   3. the GENERATED persona. Reached when the directory is off, when the
  //      person has no entry yet, or when the entry does not carry that
  //      attribute — and ONLY IN DEVELOPMENT MODE since 2026-09-12. A product
  //      realm (`mode.inventsClaimValues()` false) stops at the directory, and
  //      a claim neither source above produces is absent; see `valueFor()`.
  //
  // Nothing is ever left absent because a source was missing — IN DEVELOPMENT.
  // A selected claim that silently did not arrive would be indistinguishable,
  // at the wallet, from a selection that never took effect. Product mode takes
  // the other side of that trade on purpose: an absent claim is a thing a
  // wallet handles, and an invented one in a SIGNED credential is a thing it
  // believes.
  // ---------------------------------------------------------------------------
  private setPath(target: any, path: string[], value: unknown) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.setPath().");
    let node = target;
    for (let i = 0; i < path.length - 1; i++) {
      if (!node[path[i]] ||
          typeof node[path[i]] !== 'object') node[path[i]] = {};
      node = node[path[i]];
    }
    node[path[path.length - 1]] = value;
    log.debug("Leaving VcClaims.setPath().");
  }

  // The claim value a row takes, and where it came from. The `source` half is
  // not decoration: it is what /admin/vc shows in its preview, and "this came
  // from the entry" versus "this was invented just now" is the difference
  // between a populated directory and one that silently is not.
  private valueFor(row: CatalogueRow, name: unknown, tokenClaims: any,
                   attributes: any,
                     persona: any) {
    const { log, mode } = this.deps;
    log.debug("Entering VcClaims.valueFor().");
    const flat = row.claim.join('.');
    // A token claim only counts when it is at the TOP level and scalar. The
    // nested ones (address.locality) would need the token to carry an `address`
    // object of this shape, and a token that carried a partial one would
    // produce an address assembled out of two sources — which is worse than
    // either.
    if (row.claim.length === 1 && tokenClaims &&
        typeof tokenClaims[row.claim[0]] === 'string' &&
        tokenClaims[row.claim[0]] !== '') {
      log.debug("Leaving VcClaims.valueFor().");
      return { value: tokenClaims[row.claim[0]],
               raw: tokenClaims[row.claim[0]], source: 'access token',
               flat: flat };
    }
    const stored = attributes ? attributes[row.ldap.toLowerCase()] : null;
    // A MULTI row (#128) is every value, converted, in the entry's order.
    if (row.multi && stored && stored.length) {
      const values = stored.map(String).filter(function (one: string) {
        return one !== '';
      });
      if (values.length) {
        log.debug("Leaving VcClaims.valueFor(). Every value.");
        return { value: values.map(function (one: string) {
          return row.toClaim ? row.toClaim(one) : one;
        }), raw: values[0], source: 'directory', flat: flat };
      }
    }
    if (stored && stored.length && String(stored[0]) !== '') {
      // The FIRST value. LDAP attributes are multi-valued and claims are not,
      // and picking the first is the only rule that does not depend on
      // insertion order being meaningful — which it is not, in this store or in
      // a real directory.
      const raw = String(stored[0]);
      log.debug("Leaving VcClaims.valueFor().");
      return { value: row.toClaim ? row.toClaim(raw) : raw, raw: raw,
               source: 'directory', flat: flat };
    }
    if (!row.from) {
      log.debug("Leaving VcClaims.valueFor().");
      return null;
    }
    // ---------------------------------------------------------------------
    // THE THIRD SOURCE IS A DEVELOPMENT-MODE SOURCE (2026-09-12).
    //
    // Until this date an attribute the entry lacked was filled from the persona
    // in every mode — so a product deployment issued SIGNED credentials
    // carrying an invented birthdate, a `+1-555-01xx` telephone number and an
    // address in a town called Placeholder, and a verifier checking the
    // signature had every reason to believe them. The signature is what makes
    // this worse than an invented claim in an unsigned response: it is this
    // service vouching for a fact nobody gave it.
    //
    // So `mode.inventsClaimValues()` is asked here, and in product the row is
    // ABSENT — which is the opposite of this function's header ("nothing is
    // ever left absent because a source was missing") and is the right
    // opposite: a wallet or a relying party can handle a claim that is not
    // there, and cannot handle one that is false. Development is unchanged.
    //
    // One place, and it covers every reader: the credential builders, the
    // console preview, and `common/claim_attributes.ts`, whose token attributes
    // and OIDC Core 5.5 claims requests are all built by this function.
    // ---------------------------------------------------------------------
    if (!mode.inventsClaimValues()) {
      log.debug("Leaving VcClaims.valueFor(). Nothing on the entry, and " +
                "this realm invents nothing.");
      return null;
    }
    const raw = persona[row.from];
    if (raw === undefined || raw === null || raw === '') {
      log.debug("Leaving VcClaims.valueFor().");
      return null;
    }
    log.debug("Leaving VcClaims.valueFor().");
    const converted = row.toClaim ? row.toClaim(String(raw)) : String(raw);
    return { value: row.multi ? [converted] : converted, raw: String(raw),
             source: 'generated', flat: flat };
  }

  // The subject claims for one person, as the credential builders want them: a
  // plain object, nested where the catalogue nests, with no `sub` — that is the
  // caller's, because each format names its subject differently (a `sub` claim,
  // a credentialSubject.id, a did:jwk) and this module should not have an
  // opinion about which.
  //
  // `report` rides along for the console: same values, but flat and annotated
  // with where each came from. `rows` is which of the selected rows to build,
  // and it exists for one caller: a wallet that asked for a SUBSET of the
  // claims in its authorization_details (OID4VCI section 5.1.1). Absent means
  // all of them, which is what every other caller wants and what an
  // authorization carrying no `claims` member means.
  subjectClaimsFor(name: unknown, tokenClaims?: any, rows?: CatalogueRow[]) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.subjectClaimsFor(). name=" + name +
              (rows ? ", restricted to " + rows.length + " requested " +
               "claim(s)." :
               "."));
    const persona = this.personaFor(name);
    const attributes = this.directoryAttributes(name);
    const claims = {};
    const report = [];
    (rows || this.selectedRows()).forEach((row) => {
      const found = this.valueFor(row, name, tokenClaims, attributes, persona);
      if (!found) {
        return;
      }
      this.setPath(claims, row.claim, found.value);
      report.push({ ldap: row.ldap, claim: found.flat, value: found.value,
                    source: found.source, ldpTerm: this.ldpTermFor(row) });
      // The second claim the attribute becomes (#128), from the same value.
      if (row.also && found.raw !== undefined) {
        const second = row.also.toClaim(found.raw);
        this.setPath(claims, row.also.claim, second);
        report.push({ ldap: row.ldap, claim: row.also.claim.join('.'),
                      value: second, source: found.source, ldpTerm: null });
      }
    });
    log.debug("Leaving VcClaims.subjectClaimsFor(). " + report.length + " " +
              "claim(s), " +
              (attributes ? "the directory has an entry for them." : "no " +
                  "directory entry."));
    return { claims: claims, report: report, entryFound: !!attributes };
  }

  // ---------------------------------------------------------------------------
  // What the issuer METADATA advertises, built from the same selection the
  // credential is built from.
  //
  // This is not tidiness. An issuer whose metadata lists five claims and whose
  // credentials carry fourteen is teaching every wallet developer who reads it
  // that the metadata is not worth reading, and OID4VCI's whole discovery story
  // rests on it being worth reading. So there is one list and both sides derive
  // from it.
  //
  // `prefix` is where the claims sit in that format: nothing for dc+sd-jwt,
  // whose claims are at the top level of the payload, and ['credentialSubject']
  // for the two W3C formats.
  // ---------------------------------------------------------------------------
  metadataClaims(prefix?: string[]) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.metadataClaims(). prefix=" +
              (prefix || []).join('.'));
    const out = this.selectedRows().map((row) => {
      return { path: (prefix || []).concat(row.claim),
               display: [{ locale: 'en-US', name: row.label }] };
    });
    log.debug("Leaving VcClaims.metadataClaims(). " + out.length +
              " claim(s) advertised.");
    return out;
  }

  // The same, for ldp_vc: only the rows whose term the vendored context
  // defines, and FLAT — the context defines `streetAddress` and `locality` as
  // terms of their own, not as members of an `address` object, so that is where
  // they go.
  ldpMetadataClaims() {
    const { log } = this.deps;
    log.debug("Entering VcClaims.ldpMetadataClaims().");
    const out = this.selectedRows().filter((row) => this.ldpTermFor(row))
      .map((row) => {
        return { path: ['credentialSubject', row.ldpTerm],
                 display: [{ locale: 'en-US', name: row.label }] };
      });
    log.debug("Leaving VcClaims.ldpMetadataClaims(). " + out.length + " " +
              "claim(s) advertised.");
    return out;
  }

  // ---------------------------------------------------------------------------
  // THE CLAIM PATHS THIS ISSUER PUBLISHES FOR ONE FORMAT, and the rows a
  // wallet's request selects out of them.
  //
  // OID4VCI section 5.1.1 lets the Wallet put a `claims` member in its
  // authorization_details, an array of claims description objects (Appendix
  // A.1) each carrying a claims path pointer (Appendix B) into the credential.
  // So the wallet asks in the vocabulary the METADATA published — which is why
  // the validation and the filtering below both go through advertisedClaims()
  // rather than through the catalogue directly. A path that is not one this
  // issuer advertises selects nothing, and the authorization endpoint refuses
  // it rather than issuing a credential quietly missing a claim somebody asked
  // for.
  //
  // The prefix is the format's, exactly as the metadata builder needs it: an
  // SD-JWT VC keeps its claims at the top level of the payload, the two W3C
  // formats keep them under credentialSubject, and ldp_vc is additionally FLAT
  // and limited to the terms the vendored context defines.
  // ---------------------------------------------------------------------------
  advertisedClaims(format: string) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.advertisedClaims(). format=" + format);
    if (format === 'ldp_vc') {
      log.debug("Leaving VcClaims.advertisedClaims(). The ldp_vc list.");
      return this.ldpMetadataClaims();
    }
    log.debug("Leaving VcClaims.advertisedClaims().");
    return this.metadataClaims(format === 'jwt_vc_json' ?
                               ['credentialSubject'] : []);
  }

  // Where one catalogue row's claim sits in a credential of this format, or
  // null when this format cannot carry it at all (ldp_vc, whose context defines
  // no term for it). The mirror image of advertisedClaims(), and the two must
  // agree: a row whose path here is absent from the metadata would be
  // requestable and never issued.
  pathOfRow(row: CatalogueRow, format: string) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.pathOfRow(). " + row.ldap);
    if (format === 'ldp_vc') {
      log.debug("Leaving VcClaims.pathOfRow().");
      return this.ldpTermFor(row) ? ['credentialSubject',
                                     this.ldpTermFor(row)] : null;
    }
    log.debug("Leaving VcClaims.pathOfRow().");
    return (format === 'jwt_vc_json' ? ['credentialSubject'] : []).concat(
        row.claim);
  }

  // A claims path pointer as one comparable string. JSON rather than a join,
  // because a pointer may hold nulls and integers as well as strings (Appendix
  // B) and "a.0.b" would not tell those apart from the strings "0" and "b".
  pathKey(path: unknown) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.pathKey().");
    log.debug("Leaving VcClaims.pathKey().");
    return JSON.stringify(path);
  }

  // The selected rows a set of requested paths names, in CATALOGUE order rather
  // than request order: the order claims appear in a credential is this
  // issuer's, and section A.3 makes request order a display concern of the
  // wallet's.
  rowsForPaths(paths: unknown[], format: string) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.rowsForPaths(). " + (paths || []).length +
              " path(s), " +
        "format=" + format);
    const wanted = new Set((paths || []).map((path) => this.pathKey(path)));
    const out = this.selectedRows().filter((row) => {
      const path = this.pathOfRow(row, format);
      return path && wanted.has(this.pathKey(path));
    });
    log.debug("Leaving VcClaims.rowsForPaths(). " + out.length + " row(s) " +
              "selected.");
    return out;
  }

  // Which of the requested paths this issuer does not advertise for this
  // format. Returned rather than thrown: the caller is the authorization
  // endpoint, which has to name all of them in one error_description.
  unknownPaths(paths: unknown[], format: string) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.unknownPaths(). format=" + format);
    const advertised = new Set(this.advertisedClaims(format).map(
        (c) => { return this.pathKey(c.path); }));
    const out = (paths ||
                 []).filter((path) => {
                   return !advertised.has(this.pathKey(path));
                 });
    log.debug("Leaving VcClaims.unknownPaths(). " + out.length + " unknown.");
    return out;
  }

  // The ldp_vc credentialSubject members, read out of the claims object
  // subjectClaimsFor() built. Returned as {term: value} so the caller can drop
  // any term its loaded context turns out not to define — see the LDP note
  // above; the list here is derived from that file by hand and the caller
  // checks it against the file itself.
  ldpSubjectFrom(claims: any) {
    const { log } = this.deps;
    log.debug("Entering VcClaims.ldpSubjectFrom().");
    const out = {};
    this.selectedRows().forEach((row) => {
      if (!row.ldpTerm) {
        return;
      }
      let node = claims;
      for (let i = 0; i < row.claim.length && node &&
                      typeof node === 'object'; i++) {
        node = node[row.claim[i]];
      }
      if (node === undefined || node === null || node === '') {
        return;
      }
      out[row.ldpTerm] = String(node);
    });
    log.debug("Leaving VcClaims.ldpSubjectFrom(). " + Object.keys(out).length +
              " member(s).");
    return out;
  }

  // Which selected attributes an ldp_vc credential cannot carry. The page
  // states them; so does this function's one caller in the metadata, because a
  // wallet author comparing the three configurations will notice the difference
  // and should not have to guess whether it is deliberate.
  ldpOmitted() {
    const { log } = this.deps;
    log.debug("Entering VcClaims.ldpOmitted().");
    log.debug("Leaving VcClaims.ldpOmitted().");
    return this.selectedRows().filter((row) => { return !row.ldpTerm; })
                         .map((row) => { return row.ldap; });
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<VcClaims>(
  'oid4vc/vc_claims',
  () => new VcClaims(VcClaims.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  VcClaims: VcClaims,
  installInstance: (instance: VcClaims): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  VC_ATTRIBUTES: VcClaims.VC_ATTRIBUTES,
  CANONICAL_NAMES: VcClaims.CANONICAL_NAMES,
  DEFAULT_SELECTION: VcClaims.DEFAULT_SELECTION,
  selectedRows: slot.forward('selectedRows'),
  selectedNames: slot.forward('selectedNames'),
  isSelected: slot.forward('isSelected'),
  setSelection: slot.forward('setSelection'),
  resetSelection: slot.forward('resetSelection'),
  personaFor: slot.forward('personaFor'),
  // The catalogue read as "what a person here has" — /admin/users/new draws
  // from this and ldap_server.js's createUser() checks against it, so the form
  // cannot offer a field the writer would drop. See PERSON_FIELDS above.
  PERSON_FIELDS: VcClaims.PERSON_FIELDS,
  personFields: slot.forward('personFields'),
  personField: slot.forward('personField'),
  generatedFor: slot.forward('generatedFor'),
  // Filled by ldap_server.js at its require time; see the note above it.
  setDirectory: slot.forward('setDirectory'),
  populateDirectory: slot.forward('populateDirectory'),
  subjectClaimsFor: slot.forward('subjectClaimsFor'),
  metadataClaims: slot.forward('metadataClaims'),
  ldpMetadataClaims: slot.forward('ldpMetadataClaims'),
  advertisedClaims: slot.forward('advertisedClaims'),
  pathOfRow: slot.forward('pathOfRow'),
  pathKey: slot.forward('pathKey'),
  rowsForPaths: slot.forward('rowsForPaths'),
  unknownPaths: slot.forward('unknownPaths'),
  ldpSubjectFrom: slot.forward('ldpSubjectFrom'),
  ldpOmitted: slot.forward('ldpOmitted')
};
