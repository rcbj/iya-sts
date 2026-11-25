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
// **EXCEPT A SUBSTRING, WHICH IS NEVER THE LIBRARY'S (#2137, 2026-11-24).**
// The library matches one with a regular expression of `.*`s, which
// backtracks polynomially on a filter such as `(cn=*a*a*a*...*b)`; every
// substring assertion, exact-rule or case-ignoring, is matched here by one
// linear scan (`substringMatches()`, below), and the search handler refuses
// one wider than `MAX_SUBSTRING_COMPONENTS` before it evaluates anything.
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

// THE MOST COMPONENTS ONE SUBSTRING ASSERTION MAY HOLD (#2137, ASVS 5.0.0
// 1.3.12): its initial, each `any` and its final, counted together. A
// constant rather than a setting, because nothing legitimate comes near it:
// a person typing `(cn=*smith*)` writes one or two, a client library
// building a "contains every word" filter writes one per word, and RFC 4517
// section 4.2.29's grammar has no use for more than a handful. Thirty-two is
// eight times anything this service or its tests have ever sent, so it
// refuses only a filter built to be expensive. The search handler asks
// `widestSubstring()` before it evaluates anything and answers
// adminLimitExceeded (11) over it (`STS-LDAP-0226`).
//
// The cap is the second half of the fix, not the first: the matcher below
// is linear in the value whatever the count, so the cap bounds the work per
// value to (components x value length) rather than being what stops it
// growing without bound.
const MAX_SUBSTRING_COMPONENTS = 32;

// THE SUBSTRING ASSERTION `initial*any*...*final`, MATCHED LEFT TO RIGHT IN
// ONE PASS (#2137). Both this module and `@ldapjs/filter` built it as a
// regular expression, `^initial.*any1.*any2.*...final$`, and a chain of `.*`
// backtracks: `(cn=*a*a*a*...*b)` against a long value of `a`s is O(n^k) on
// the event loop. RFC 4511 section 4.5.1.7.2 and RFC 4517 section 4.2.29
// (caseExactSubstringsMatch, and the caseIgnore rules over prepared values)
// define the match as: `initial` a prefix, each `any` found in order after
// the one before without overlapping it, and `final` a suffix that overlaps
// nothing before it. Finding each `any` at its EARLIEST position is optimal
// — a later position leaves less room for everything after it and never
// more — so a left-to-right `indexOf` scan answers exactly what the regular
// expression did, with no backtracking.
//
// ONE DIFFERENCE, AND IT IS THE RFC'S: a regular expression's `.` does not
// match a line terminator, so `(description=a*b)` never matched a value
// holding "a\nb". The RFCs make no such exception, and this scan does not
// either. An empty component (the parser's `**`) matches the empty string,
// as the `.*` around it did. Values and components are compared as given:
// the caller lower-cases both for a caseIgnore attribute, and preserves case
// for every other.
function substringMatches(value: string, initial: string, any: string[],
                          final: string): boolean {
  let position = 0;
  if (initial) {
    if (!value.startsWith(initial)) {
      return false;
    }
    position = initial.length;
  }
  for (const one of any) {
    if (!one) {
      continue;
    }
    const at = value.indexOf(one, position);
    if (at < 0) {
      return false;
    }
    position = at + one.length;
  }
  if (final) {
    return value.length - final.length >= position && value.endsWith(final);
  }
  return true;
}

// How many components a substring assertion holds: its initial and final
// when present, and every `any`.
function componentsOf(filter: ParsedFilter): number {
  return (filter.initial ? 1 : 0) + (filter.any || []).length +
    (filter.final ? 1 : 0);
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
   * The most components (initial, each any, final) one substring assertion
   * may hold before a search is refused (#2137).
   */
  static readonly MAX_SUBSTRING_COMPONENTS = MAX_SUBSTRING_COMPONENTS;

  // Asked once per search, but recursive over the filter: no Entering/Leaving
  // pair (the hot-path exception, stated in the header above).
  /**
   * The component count of the widest substring assertion anywhere in a
   * filter, through every AND, OR and NOT; 0 when it holds none.
   *
   * @param filter - a filter `@ldapjs/filter` parsed
   * @returns the largest count of initial, any and final in one assertion
   */
  static widestSubstring(filter: ParsedFilter): number {
    if (!filter) {
      return 0;
    }
    switch (filter.type) {
      case 'AndFilter':
      case 'OrFilter': {
        return (filter.clauses || []).reduce(function (most, one) {
          return Math.max(most, LdapMatching.widestSubstring(one));
        }, 0);
      }
      case 'NotFilter': {
        return LdapMatching.widestSubstring(filter.filter as ParsedFilter);
      }
      case 'SubstringFilter': {
        return componentsOf(filter);
      }
      default: {
        return 0;
      }
    }
  }

  // Asked once per value of an entry in scope: no Entering/Leaving pair (the
  // hot-path exception, stated in the header above).
  /**
   * Says whether a value satisfies a substring assertion, in one
   * left-to-right pass with no regular expression (RFC 4511 section
   * 4.5.1.7.2, RFC 4517 section 4.2.29). Case is compared as given.
   *
   * @param value - the attribute value
   * @param initial - the prefix, or '' for none
   * @param any - the inner components, in order
   * @param final - the suffix, or '' for none
   * @returns true when the value matches
   */
  static substringMatches(value: string, initial: string, any: string[],
                          final: string): boolean {
    return substringMatches(value, initial, any, final);
  }

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
        // BOTH CASES BY THE ONE LINEAR SCAN (#2137): the library's own
        // `matches()` builds the same backtracking regular expression, so an
        // exact-rule attribute is no longer handed to it either. The values
        // are found as the library finds them (the attribute description in
        // any case) and compared with case preserved.
        const fold = LdapMatching.ignoresCase(String(filter.attribute));
        const prepared = function (text: unknown): string {
          const plain = text === undefined || text === null ? '' :
            String(text);
          return fold ? plain.toLowerCase() : plain;
        };
        const initial = prepared(filter.initial);
        const any = (filter.any || []).map(prepared);
        const final = prepared(filter.final);
        return valuesOf(entry, String(filter.attribute)).some(function (one) {
          return substringMatches(prepared(one), initial, any, final);
        });
      }
      default: {
        return filter.matches(entry, false);
      }
    }
  }
};
