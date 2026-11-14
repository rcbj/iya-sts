// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ldap/ldap_matching.ts
//
// ===========================================================================
// A SEARCH FILTER, MATCHED BY EACH ATTRIBUTE'S OWN EQUALITY RULE (#632,
// 2026-10-14).
//
// `@ldapjs/filter`'s `matches()` compares every value EXACTLY, except
// `objectClass`, which it folds because "most LDAP implementations behave in
// this manner". So `(uid=ALICE)` found nobody stored as `uid=alice` — though
// RFC 4519 section 2.39 gives `uid` the caseIgnoreMatch equality rule and
// caseIgnoreSubstringsMatch for substrings — while `existingUserEntry()`, the
// console and SCIM found her by the same name in any case, and the store's
// own index (`name_keys`, `mail_keys`) holds every value lower-cased. Two
// answers from one directory about one person.
//
// **WHAT THIS DOES.** The filter is walked here — AND, OR and NOT as RFC
// 4511 section 4.5.1.7 defines them (an empty AND is TRUE and an empty OR
// FALSE, RFC 4526) — and an equality or a substring assertion on an
// attribute whose schema gives it a case-ignoring rule is compared with both
// sides lower-cased. Every other assertion — a presence, an ordering, an
// approximate or extensible match, an attribute with an exact rule — is
// handed to the library's own leaf, unchanged, with `strictAttrCase` false
// (attribute DESCRIPTIONS are case-insensitive, RFC 4512 section 2.5;
// `ldap_server.js`'s search handler argues why that flag matters).
//
// **THE TABLE IS THE SCHEMA, NOT A GUESS.** The attributes below are the ones
// whose RFC gives them caseIgnoreMatch or caseIgnoreIA5Match equality — RFC
// 4519's user attributes (`uid`, `cn`, `sn`, `dc`, `ou`...), RFC 4524's `mail`
// and its other directory strings, and RFC 2798's inetOrgPerson additions.
// An attribute not named here keeps the library's exact comparison, which is
// what caseExactMatch / caseExactIA5Match attributes (`memberUid`, RFC 2307),
// octet strings and every `sts*` attribute of this service's own want.
// `mail` was case-sensitive here too, and caseIgnoreIA5Match (RFC 4524
// section 2.16) folds it the same way; it is in the table for that reason.
//
// **WHAT IT DOES NOT DO**: RFC 4518's string preparation beyond case —
// insignificant-space handling, Unicode normalisation — which no path here
// did before. Lower-casing is the whole of it, as it is in the store's index
// (`persistence/directory_codec.js`) and in the compare handler, so the three
// agree on every value.
//
// A LEAF: it requires nothing, and reads no setting, store or clock, so
// `ldap_server.js`'s search handler and `scim/scim_client.ts`'s scope filter
// can both ask it. Asked once per entry in scope of a search, so no
// Entering/Leaving pair — a subtree search of a large directory would drown
// the log in them (the hot-path exception the code style allows, stated
// here as it requires; `directory_read_policy.ts` makes the same one).
// ===========================================================================

// The attributes whose equality rule ignores case, lower-cased.
const CASE_IGNORE_ATTRIBUTES: ReadonlySet<string> = new Set([
  // RFC 4519 section 2: caseIgnoreMatch, or caseIgnoreIA5Match for `dc`.
  'businesscategory', 'c', 'cn', 'dc', 'description', 'destinationindicator',
  'dnqualifier', 'generationqualifier', 'givenname', 'houseidentifier',
  'initials', 'l', 'name', 'o', 'ou', 'physicaldeliveryofficename',
  'postalcode', 'postofficebox', 'serialnumber', 'sn', 'st', 'street',
  'title', 'uid',
  // The usual short and long spellings of the same attributes.
  'commonname', 'surname', 'gn', 'countryname', 'localityname',
  'stateorprovincename', 'streetaddress', 'organizationname',
  'organizationalunitname', 'domaincomponent', 'userid',
  // RFC 4524 section 2: caseIgnoreIA5Match (`mail`, `associatedDomain`) and
  // caseIgnoreMatch.
  'mail', 'rfc822mailbox', 'associateddomain', 'buildingname', 'co',
  'friendlycountryname', 'documentauthor', 'documentidentifier',
  'documentlocation', 'documentpublisher', 'documenttitle',
  'documentversion', 'drink', 'favouritedrink', 'host', 'info',
  'organizationalstatus', 'roomnumber', 'uniqueidentifier',
  // RFC 2798 section 2: inetOrgPerson's caseIgnoreMatch attributes.
  'carlicense', 'departmentnumber', 'displayname', 'employeenumber',
  'employeetype', 'preferredlanguage'
]);

// A filter as `@ldapjs/filter` parses one: only what is read here.
interface ParsedFilter {
  type: string;
  attribute?: string;
  value?: unknown;
  initial?: string;
  any?: string[];
  final?: string;
  clauses?: ParsedFilter[];
  filter?: ParsedFilter;
  matches(entry: Record<string, unknown>, strictAttrCase?: boolean): boolean;
}

// An entry as the search handler hands it: attribute name to its values.
type Matchable = Record<string, unknown>;

// The values an entry holds for `attribute`, its name compared in any case
// (RFC 4512 section 2.5), as strings.
function valuesOf(entry: Matchable, attribute: string): string[] {
  let found: unknown;
  if (Object.prototype.hasOwnProperty.call(entry, attribute)) {
    found = entry[attribute];
  } else {
    const wanted = attribute.toLowerCase();
    const name = Object.keys(entry).find(function (one) {
      return one.toLowerCase() === wanted;
    });
    found = name === undefined ? undefined : entry[name];
  }
  if (found === undefined || found === null) {
    return [];
  }
  return (Array.isArray(found) ? found : [found]).map(function (one) {
    return String(one);
  });
}

// A regular expression's special characters, escaped.
function escaped(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// The substring assertion `initial*any*...*final` as the library builds it,
// over lower-cased text.
function substringPattern(filter: ParsedFilter): RegExp {
  let source = '';
  if (filter.initial) {
    source += '^' + escaped(filter.initial.toLowerCase()) + '.*';
  }
  (filter.any || []).forEach(function (one) {
    source += escaped(String(one).toLowerCase()) + '.*';
  });
  if (filter.final) {
    source += escaped(filter.final.toLowerCase()) + '$';
  }
  return new RegExp(source);
}

/**
 * LDAP search filters matched by each attribute's own equality rule: an
 * equality or substring assertion on a caseIgnoreMatch or caseIgnoreIA5Match
 * attribute (RFC 4519, RFC 4524, RFC 2798) ignores case, and every other
 * assertion is the library's own.
 *
 * It reads no store, setting or clock.
 */
export = class LdapMatching {
  /**
   * The attributes whose equality rule ignores case, lower-cased.
   */
  static readonly CASE_IGNORE_ATTRIBUTES = CASE_IGNORE_ATTRIBUTES;

  /**
   * Says whether an attribute's equality rule ignores case.
   *
   * @param attribute - an attribute description, in any case; an option
   *   (`;lang-en`, `;binary`) is ignored
   * @returns true for caseIgnoreMatch or caseIgnoreIA5Match
   */
  static ignoresCase(attribute: string): boolean {
    const type = String(attribute || '').split(';')[0].toLowerCase();
    return CASE_IGNORE_ATTRIBUTES.has(type);
  }

  // Asked once per entry in scope of a search: no Entering/Leaving pair (the
  // hot-path exception, stated in the header above).
  /**
   * Says whether an entry matches a parsed search filter, each equality and
   * substring assertion compared by its attribute's equality rule.
   *
   * @param filter - a filter `@ldapjs/filter` parsed
   * @param entry - the entry's attributes, each an array of values
   * @returns true when it matches
   * @throws what the library's own leaf throws for a filter it cannot
   *   evaluate (an extensible match), which the caller reports
   */
  static matches(filter: ParsedFilter, entry: Matchable): boolean {
    switch (filter.type) {
      case 'AndFilter': {
        // RFC 4526: an empty AND is TRUE.
        return (filter.clauses || []).every(function (one) {
          return LdapMatching.matches(one, entry);
        });
      }
      case 'OrFilter': {
        // RFC 4526: an empty OR is FALSE.
        return (filter.clauses || []).some(function (one) {
          return LdapMatching.matches(one, entry);
        });
      }
      case 'NotFilter': {
        return !LdapMatching.matches(filter.filter as ParsedFilter, entry);
      }
      case 'EqualityFilter': {
        if (typeof filter.value !== 'string' ||
            !LdapMatching.ignoresCase(String(filter.attribute))) {
          return filter.matches(entry, false);
        }
        const wanted = filter.value.toLowerCase();
        return valuesOf(entry, String(filter.attribute)).some(function (one) {
          return one.toLowerCase() === wanted;
        });
      }
      case 'SubstringFilter': {
        if (!LdapMatching.ignoresCase(String(filter.attribute))) {
          return filter.matches(entry, false);
        }
        const pattern = substringPattern(filter);
        return valuesOf(entry, String(filter.attribute)).some(function (one) {
          return pattern.test(one.toLowerCase());
        });
      }
      default: {
        return filter.matches(entry, false);
      }
    }
  }
};
