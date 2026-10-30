// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: xacml_attribute_rows.ts
//
// ===========================================================================
// AN ATTRIBUTE ROW: HOW A MEMBER OF SOMEBODY ELSE'S JSON BECOMES AN XACML
// ATTRIBUTE, AND WHAT IT MAY NEVER BECOME (#563, #564). PURE: no I/O.
//
// Two adapters map a caller's JSON onto an XACML request through rows an
// administrator wrote: AuthZEN's attribute catalogue (`authzen/
// authzen_catalogue.ts`, a property of a subject, action, resource or
// context) and an access type's `xacml` rows (`xacml/fga_map.ts`, #564, a
// member of a validated RFC 9396 authorization detail). A row is the same
// thing in both — a member path, an attribute identifier, a category, a
// datatype, `single` or `bag` — and so are the two questions every row
// raises:
//
//   * WHICH IDENTIFIERS A ROW MAY NEVER NAME. A request-supplied attribute
//     suppresses the PIP (`xacml_pdp.js` asks the resolver only when the
//     request carried no value for a designator), so a row onto a trusted
//     identifier would let a caller forge it. `reservedProblem()`.
//   * HOW A JSON VALUE BECOMES XACML VALUES under a row: the row's datatype
//     wins, `null` is refused, an array only for a bag, a nested object
//     only through declared dotted rows, and a string parsed by
//     `xacml_datatypes.js`, which owns every lexical space. `valuesOf()` and
//     `walk()`.
//
// **ONE IMPLEMENTATION, BECAUSE TWO WOULD DRIFT IN THE ONE PLACE IT
// MATTERS.** The reserved list and the value rules are a security boundary
// — the line between what a caller may say and what the service asserts —
// and a copy for FGA would have been right on the day it was made. So both
// adapters call these, and each keeps only what is its own: its error
// codes, its row's other members (AuthZEN's `object`, FGA's common fields)
// and the sentence it tells its caller for an undeclared member.
//
// A problem is answered as `{ kind, message }` and the adapter maps the
// KIND to its own code — AuthZEN's `STS-AUTHZEN-0004`..`0008` are what they
// were before this module existed (`tests/authzen_map.js`), and FGA's are
// `STS-FGA-*`:
//
//   undeclared  a member no row names (the adapter writes the message)
//   null        a member, or a bag's element, that is JSON null
//   type        a JSON type the row's datatype does not take, or a string
//               that is not in the datatype's lexical space
//   array       an array for a single row, or more than MAX_BAG values
//   object      an object where a row sends values, or a bag holding one
//   depth       nested deeper than MAX_NESTING
// ===========================================================================

import helpers = require('../common/helpers');
import model = require('./xacml_model');
import datatypes = require('./xacml_datatypes');

const { log } = helpers;

// What the value rules need of a row.
interface ValueRow {
  dataType: string;
  multiplicity: string;
}

// A row as `walk()` reads it: the member path it maps, and the attribute.
interface WalkRow extends ValueRow {
  path: string;
  attributeId: string;
  category: string;
}

// One XACML attribute a row sends, its values lexical.
interface MappedAttribute {
  category: string;
  attributeId: string;
  dataType: string;
  values: string[];
}

// What the value rules refuse, by kind (the header's table).
interface Problem {
  kind: string;
  named: string;
  message: string;
}

// The categories a row may name, by short name. The full URIs are accepted
// too (any of these), and a row is stored with the URI.
const CATEGORY_NAMES = Object.freeze({
  'access-subject': model.CATEGORY.ACCESS_SUBJECT,
  'recipient-subject': model.CATEGORY.RECIPIENT_SUBJECT,
  'intermediary-subject': model.CATEGORY.INTERMEDIARY_SUBJECT,
  'codebase': model.CATEGORY.CODEBASE,
  'requesting-machine': model.CATEGORY.REQUESTING_MACHINE,
  'resource': model.CATEGORY.RESOURCE,
  'action': model.CATEGORY.ACTION,
  'environment': model.CATEGORY.ENVIRONMENT
});

// The datatypes a row may name, by short name — every datatype the engine
// has but `xpathExpression`, which a JSON value cannot carry (it needs the
// XML content it is evaluated against). The full URIs are accepted too.
const TYPE_NAMES = Object.freeze({
  'string': model.TYPE.STRING,
  'boolean': model.TYPE.BOOLEAN,
  'integer': model.TYPE.INTEGER,
  'double': model.TYPE.DOUBLE,
  'time': model.TYPE.TIME,
  'date': model.TYPE.DATE,
  'dateTime': model.TYPE.DATETIME,
  'dayTimeDuration': model.TYPE.DAYTIME_DURATION,
  'yearMonthDuration': model.TYPE.YEARMONTH_DURATION,
  'anyURI': model.TYPE.ANYURI,
  'hexBinary': model.TYPE.HEXBINARY,
  'base64Binary': model.TYPE.BASE64BINARY,
  'rfc822Name': model.TYPE.RFC822NAME,
  'x500Name': model.TYPE.X500NAME,
  'dnsName': model.TYPE.DNSNAME,
  'ipAddress': model.TYPE.IPADDRESS
});

// The two multiplicities.
const MULTIPLICITIES = Object.freeze(['single', 'bag']);

// This service's own namespace: everything in it is reserved. VOCABULARY,
// the settings and passkey-policy prefixes, the PIP's directory prefix and
// every trusted AuthZEN and FGA fact live there, and a prefix rule cannot
// fall behind a list.
const RESERVED_PREFIX = 'urn:sts:xacml:';

// XACML's own identifiers an adapter fills itself, or the PDP supplies.
const RESERVED_IDS = Object.freeze([
  model.ATTRIBUTE.SUBJECT_ID, model.ATTRIBUTE.RESOURCE_ID,
  model.ATTRIBUTE.ACTION_ID, model.ATTRIBUTE.CURRENT_TIME,
  model.ATTRIBUTE.CURRENT_DATE, model.ATTRIBUTE.CURRENT_DATETIME
]);

// The subject categories, where a bare name would be read as a directory
// attribute of the subject.
const SUBJECT_CATEGORIES = Object.freeze([
  model.CATEGORY.ACCESS_SUBJECT, model.CATEGORY.RECIPIENT_SUBJECT,
  model.CATEGORY.INTERMEDIARY_SUBJECT, model.CATEGORY.CODEBASE,
  model.CATEGORY.REQUESTING_MACHINE
]);

// `xacml_pip.ts`'s test for a bare directory attribute name, spelt the same.
const BARE_NAME = /^[A-Za-z][A-Za-z0-9;-]*$/;

// One segment of a member path. Narrower than a JSON member name on
// purpose: a dot is the path separator, so a member whose name holds one
// could never be told from a nested one.
const SEGMENT = /^[A-Za-z0-9_$@:-]{1,64}$/;

// The deepest a dotted path may go, and the longest identifier a row may
// carry. Generous; a bound because rows are walked per request.
const MAX_DEPTH = 6;
const MAX_ID_LENGTH = 512;

// The deepest `walk()` descends into objects no row maps whole.
const MAX_NESTING = 8;

// The longest a string value may be.
const MAX_VALUE = 8192;

// The most values a bag may carry.
const MAX_BAG = 256;

/**
 * Tells whether a value is a JSON object (not an array, not null).
 *
 * @param value - the value
 * @returns true for an object
 */
function isObject(value: unknown): boolean {
  log.debug("Entering isObject().");
  log.debug("Leaving isObject().");
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Builds one problem of the value rules.
 *
 * @param kind - the header's kind
 * @param named - the member's path, as the caller would read it
 * @param message - what the caller is told ('' for `undeclared`)
 * @returns the problem
 */
function problemOf(kind: string, named: string, message: string): Problem {
  log.debug("Entering problemOf(). " + kind);
  log.debug("Leaving problemOf().");
  return { kind: kind, named: named.slice(0, 200), message: message };
}

/**
 * The grammar and the value rules every attribute row shares, whichever
 * adapter wrote it. Pure, without I/O.
 */
class XacmlAttributeRows {
  /**
   * Says why an attribute identifier is reserved in a category, or null.
   *
   * @param attributeId - the identifier a row would send
   * @param category - the category's URI
   * @returns the reason, or null when a row may name it
   */
  static reservedProblem(attributeId: string, category: string):
      string | null {
    log.debug("Entering XacmlAttributeRows.reservedProblem().");
    const id = String(attributeId || '');
    if (id.toLowerCase().indexOf(RESERVED_PREFIX) === 0) {
      log.debug("Leaving XacmlAttributeRows.reservedProblem(). Ours.");
      return '"' + id + '" is in this service\'s own namespace (' +
        RESERVED_PREFIX + '), where every trusted fact lives — the roles, ' +
        'the realm, the protocol, the caller and its application. A ' +
        'request-supplied attribute suppresses the PIP, so a row mapping ' +
        'onto one would let a caller forge it';
    }
    if (RESERVED_IDS.indexOf(id) >= 0) {
      log.debug("Leaving XacmlAttributeRows.reservedProblem(). XACML's own.");
      return '"' + id + '" is filled by the adapter from the request\'s ' +
        'own identifiers (AuthZEN\'s subject.id, action.name or ' +
        'resource.id; an authorization detail\'s trusted facts), or ' +
        'supplied by the PDP, and from nothing else';
    }
    if (XacmlAttributeRows.isDirectoryName(id, category)) {
      log.debug("Leaving XacmlAttributeRows.reservedProblem(). A " +
                "directory attribute name.");
      return '"' + id + '" in a subject category is read as the subject\'s ' +
        'directory attribute, and for a subject this realm resolves the ' +
        'directory is authoritative. Send the member under an identifier ' +
        'of your own, such as urn:example:' + id;
    }
    log.debug("Leaving XacmlAttributeRows.reservedProblem(). Allowed.");
    return null;
  }

  /**
   * Tells whether an identifier is a bare directory attribute name in a
   * subject category — the reserved case an adapter may give a code of its
   * own.
   *
   * @param attributeId - the identifier
   * @param category - the category's URI
   * @returns true when the PIP would read it off the subject's entry
   */
  static isDirectoryName(attributeId: string, category: string): boolean {
    log.debug("Entering XacmlAttributeRows.isDirectoryName().");
    log.debug("Leaving XacmlAttributeRows.isDirectoryName().");
    return SUBJECT_CATEGORIES.indexOf(category) >= 0 &&
           BARE_NAME.test(String(attributeId || ''));
  }

  /**
   * Reads a category by short name or URI.
   *
   * @param text - what the row said
   * @returns the category's URI, or '' when it is not one
   */
  static categoryOf(text: string): string {
    log.debug("Entering XacmlAttributeRows.categoryOf().");
    const uris = Object.keys(CATEGORY_NAMES).map(function (key: string) {
      return CATEGORY_NAMES[key];
    });
    const out = CATEGORY_NAMES[text] || (uris.indexOf(text) >= 0 ? text : '');
    log.debug("Leaving XacmlAttributeRows.categoryOf().");
    return out;
  }

  /**
   * Reads a datatype by short name or URI; '' is `string`.
   *
   * @param text - what the row said
   * @returns the datatype's URI, or '' when it is not one
   */
  static dataTypeOf(text: string): string {
    log.debug("Entering XacmlAttributeRows.dataTypeOf().");
    const given = text || 'string';
    const uris = Object.keys(TYPE_NAMES).map(function (key: string) {
      return TYPE_NAMES[key];
    });
    const out = TYPE_NAMES[given] || (uris.indexOf(given) >= 0 ? given : '');
    log.debug("Leaving XacmlAttributeRows.dataTypeOf().");
    return out;
  }

  /**
   * Reads a member path: a name, or a dotted path of at most MAX_DEPTH
   * names, each a SEGMENT.
   *
   * @param text - the path
   * @returns its segments, or null when it is not a path
   */
  static segmentsOf(text: string): string[] | null {
    log.debug("Entering XacmlAttributeRows.segmentsOf().");
    const segments = text ? String(text).split('.') : [];
    if (!segments.length || segments.length > MAX_DEPTH ||
        !segments.every(function (one: string) {
          return SEGMENT.test(one);
        })) {
      log.debug("Leaving XacmlAttributeRows.segmentsOf(). Not a path.");
      return null;
    }
    log.debug("Leaving XacmlAttributeRows.segmentsOf().");
    return segments;
  }

  /**
   * Tells whether an attribute identifier has a usable shape: non-empty,
   * no white space, at most MAX_ID_LENGTH characters.
   *
   * @param attributeId - the identifier
   * @returns true when it does
   */
  static idShaped(attributeId: string): boolean {
    log.debug("Entering XacmlAttributeRows.idShaped().");
    log.debug("Leaving XacmlAttributeRows.idShaped().");
    return !!attributeId && attributeId.length <= MAX_ID_LENGTH &&
           !/\s/.test(attributeId);
  }

  /**
   * Walks one object's members against rows, mapping each declared one and
   * answering a problem for the rest. A member a row maps whole is
   * converted by `valuesOf()`; a member holding an object that some row
   * maps INTO is walked again; anything else is `undeclared`.
   *
   * @param value - the members at this level
   * @param prefix - the dotted path down to here, '' at the top
   * @param shown - how the caller's path is spelt, before the path
   * @param rows - the rows, each with its `path`
   * @param out - the attributes mapped so far
   * @param supplied - the paths supplied so far
   * @param depth - how deep this level is
   * @param skip - optional: true for a path that is deliberately not
   *   mapped, which is neither an attribute nor supplied
   * @returns a problem, or null
   */
  static walk(value: any, prefix: string, shown: string, rows: WalkRow[],
              out: MappedAttribute[], supplied: string[], depth: number,
              skip?: (path: string) => boolean): Problem | null {
    log.debug("Entering XacmlAttributeRows.walk(). " + prefix);
    const keys = Object.keys(value);
    for (let i = 0; i < keys.length; i += 1) {
      const key = keys[i];
      const path = prefix ? prefix + '.' + key : key;
      const named = shown + path;
      const member = value[key];
      if (skip && skip(path)) {
        continue;
      }
      const row = rows.filter(function (one: WalkRow) {
        return one.path === path;
      })[0];
      const branch = !row && rows.some(function (one: WalkRow) {
        return one.path.indexOf(path + '.') === 0;
      });
      if (!row && !(branch && isObject(member))) {
        log.debug("Leaving XacmlAttributeRows.walk(). Undeclared: " + named);
        return problemOf('undeclared', named, '');
      }
      if (member === null) {
        log.debug("Leaving XacmlAttributeRows.walk(). Null: " + named);
        return problemOf('null', named, named.slice(0, 200) + ' is null, ' +
          'which is neither an empty value nor an absent one. Leave the ' +
          'member out, or send a value.');
      }
      supplied.push(named);
      if (!row) {
        if (depth + 1 > MAX_NESTING) {
          log.debug("Leaving XacmlAttributeRows.walk(). Too deep.");
          return problemOf('depth', named, named.slice(0, 200) +
                           ' is nested too deeply.');
        }
        const deeper = XacmlAttributeRows.walk(member, path, shown, rows, out,
                                               supplied, depth + 1, skip);
        if (deeper) {
          log.debug("Leaving XacmlAttributeRows.walk(). Refused below.");
          return deeper;
        }
        continue;
      }
      const values = XacmlAttributeRows.valuesOf(row, member, named);
      if (values.problem) {
        log.debug("Leaving XacmlAttributeRows.walk(). " + values.problem.kind);
        return values.problem;
      }
      out.push({ category: row.category, attributeId: row.attributeId,
                 dataType: row.dataType, values: values.lexical });
    }
    log.debug("Leaving XacmlAttributeRows.walk().");
    return null;
  }

  /**
   * Converts one member's JSON value to the lexical values its row sends.
   *
   * @param row - the row: its datatype and multiplicity
   * @param member - the JSON value
   * @param named - the member's path, as the caller would read it
   * @returns `{ lexical }`, or `{ problem }`
   */
  static valuesOf(row: ValueRow, member: unknown, named: string):
      { lexical?: string[]; problem?: Problem } {
    log.debug("Entering XacmlAttributeRows.valuesOf(). " + named);
    const shown = named.slice(0, 200);
    if (isObject(member)) {
      log.debug("Leaving XacmlAttributeRows.valuesOf(). An object.");
      return { problem: problemOf('object', named,
        shown + ' is an object, and its row sends one ' +
        (row.multiplicity === 'bag' ? 'bag of values' : 'value') +
        '. A nested object reaches a request only through rows for its ' +
        'own members (' + shown + '.<member>).') };
    }
    if (Array.isArray(member) && row.multiplicity !== 'bag') {
      log.debug("Leaving XacmlAttributeRows.valuesOf(). An array for one " +
                "value.");
      return { problem: problemOf('array', named,
        shown + ' is an array, and its row sends a single value. A row ' +
        'whose multiplicity is bag takes an array.') };
    }
    const list = Array.isArray(member) ? member : [member];
    if (list.length > MAX_BAG) {
      log.debug("Leaving XacmlAttributeRows.valuesOf(). Too many values.");
      return { problem: problemOf('array', named,
        shown + ' carries more than ' + MAX_BAG + ' values.') };
    }
    const lexical: string[] = [];
    for (let i = 0; i < list.length; i += 1) {
      const one = list[i];
      if (one === null) {
        log.debug("Leaving XacmlAttributeRows.valuesOf(). A null element.");
        return { problem: problemOf('null', named,
          shown + ' holds a null, which is not a value.') };
      }
      if (isObject(one) || Array.isArray(one)) {
        log.debug("Leaving XacmlAttributeRows.valuesOf(). A nested element.");
        return { problem: problemOf('object', named,
          shown + ' holds an object or an array; a bag is of scalars.') };
      }
      const text = XacmlAttributeRows.lexicalOf(row.dataType, one);
      if (text === null) {
        log.debug("Leaving XacmlAttributeRows.valuesOf(). The wrong JSON " +
                  "type.");
        return { problem: problemOf('type', named,
          shown + ' is a JSON ' + typeof one + ', and its row sends ' +
          XacmlAttributeRows.typeName(row.dataType) + '. ' +
          XacmlAttributeRows.typeAdvice(row.dataType)) };
      }
      try {
        datatypes.parseValue(row.dataType, text);
      } catch (e) {
        log.debug("Caught in XacmlAttributeRows.valuesOf(): " +
                  ((e && e.message) || e));
        log.debug("Leaving XacmlAttributeRows.valuesOf(). Does not parse.");
        return { problem: problemOf('type', named,
          shown + ' is not a valid ' +
          XacmlAttributeRows.typeName(row.dataType) + ': ' +
          String((e && e.message) || e).slice(0, 200)) };
      }
      lexical.push(text);
    }
    log.debug("Leaving XacmlAttributeRows.valuesOf(). " + lexical.length +
              " value(s).");
    return { lexical: lexical };
  }

  /**
   * The lexical form of one JSON scalar at a datatype, or null when that
   * JSON type may not reach it. A string reaches every type (parsed after);
   * a boolean only a boolean; a number only an integer — and then only a
   * whole one — or a double.
   *
   * @param type - the row's datatype URI
   * @param value - the JSON scalar
   * @returns the lexical form, or null
   */
  static lexicalOf(type: string, value: unknown): string | null {
    log.debug("Entering XacmlAttributeRows.lexicalOf().");
    if (typeof value === 'string') {
      log.debug("Leaving XacmlAttributeRows.lexicalOf(). A string.");
      return value.length > MAX_VALUE ? null : value;
    }
    if (typeof value === 'boolean') {
      log.debug("Leaving XacmlAttributeRows.lexicalOf(). A boolean.");
      return type === model.TYPE.BOOLEAN ? String(value) : null;
    }
    if (typeof value === 'number' && isFinite(value)) {
      if (type === model.TYPE.INTEGER) {
        log.debug("Leaving XacmlAttributeRows.lexicalOf(). An integer?");
        return Number.isSafeInteger(value) ? String(value) : null;
      }
      log.debug("Leaving XacmlAttributeRows.lexicalOf(). A number.");
      return type === model.TYPE.DOUBLE ? String(value) : null;
    }
    log.debug("Leaving XacmlAttributeRows.lexicalOf(). Nothing.");
    return null;
  }

  /**
   * A datatype's short name, for a message.
   *
   * @param type - the datatype URI
   * @returns its short name
   */
  static typeName(type: string): string {
    log.debug("Entering XacmlAttributeRows.typeName().");
    const found = Object.keys(TYPE_NAMES).filter(function (key: string) {
      return TYPE_NAMES[key] === type;
    })[0];
    log.debug("Leaving XacmlAttributeRows.typeName().");
    return found || type;
  }

  /**
   * What a caller should send for a datatype, for a message.
   *
   * @param type - the datatype URI
   * @returns the advice
   */
  static typeAdvice(type: string): string {
    log.debug("Entering XacmlAttributeRows.typeAdvice().");
    let out = 'Send a string in its lexical form.';
    if (type === model.TYPE.BOOLEAN) {
      out = 'Send true or false.';
    } else if (type === model.TYPE.INTEGER) {
      out = 'Send a whole number; a fraction is refused.';
    } else if (type === model.TYPE.DOUBLE) {
      out = 'Send a number.';
    } else if (type === model.TYPE.STRING) {
      out = 'Send a string; a number or a boolean is not quietly one.';
    }
    log.debug("Leaving XacmlAttributeRows.typeAdvice().");
    return out;
  }

  /**
   * Tells whether a value is a JSON object (not an array, not null).
   *
   * @param value - the value
   * @returns true for an object
   */
  static isObject(value: unknown): boolean {
    log.debug("Entering XacmlAttributeRows.isObject().");
    log.debug("Leaving XacmlAttributeRows.isObject().");
    return isObject(value);
  }
}

/**
 * The attribute-row grammar and value rules AuthZEN's catalogue and FGA's
 * access-type rows share (#563, #564).
 * @namespace
 */
export = {
  XacmlAttributeRows: XacmlAttributeRows,
  CATEGORY_NAMES: CATEGORY_NAMES,
  TYPE_NAMES: TYPE_NAMES,
  MULTIPLICITIES: MULTIPLICITIES,
  RESERVED_PREFIX: RESERVED_PREFIX,
  MAX_DEPTH: MAX_DEPTH,
  MAX_ID_LENGTH: MAX_ID_LENGTH,
  MAX_BAG: MAX_BAG,
  reservedProblem: XacmlAttributeRows.reservedProblem,
  isDirectoryName: XacmlAttributeRows.isDirectoryName,
  categoryOf: XacmlAttributeRows.categoryOf,
  dataTypeOf: XacmlAttributeRows.dataTypeOf,
  segmentsOf: XacmlAttributeRows.segmentsOf,
  idShaped: XacmlAttributeRows.idShaped,
  walk: XacmlAttributeRows.walk,
  valuesOf: XacmlAttributeRows.valuesOf,
  lexicalOf: XacmlAttributeRows.lexicalOf,
  typeName: XacmlAttributeRows.typeName,
  typeAdvice: XacmlAttributeRows.typeAdvice
};
