// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen_catalogue.ts
//
// ===========================================================================
// THE AUTHZEN ATTRIBUTE CATALOGUE: WHICH PROPERTY OF A REQUEST BECOMES WHICH
// XACML ATTRIBUTE (#563, phase 1, #1160).
//
// AuthZEN Authorization API 1.0 gives a subject, an action and a resource
// each an open `properties` object, and the request an open `context`, and
// says nothing about what any member of them MEANS. XACML wants a category,
// an attribute identifier, a datatype and a bag. Nothing joins the two but a
// table somebody writes, so this is that table, one ROW per property:
//
//   object        subject | resource | action | context
//   property      the member's name, or a dotted path into a nested object
//                 (`address.country`) — a nested object reaches a request
//                 ONLY through declared dotted rows, never flattened
//   attributeId   the XACML attribute it is sent as
//   category      the XACML category; the object's own by default
//   dataType      the XACML datatype; the row's type wins over the JSON's
//   multiplicity  `single` (one value) or `bag` (a JSON array)
//
// **IT IS PER REALM AND IT LIVES ON THE API'S OWN OBJECT** — one value of
// `authzenAttribute` per row, on the realm's `sts-authzen-api` resource
// object (`common/applications.js`), the way GNAP's access-type catalogue
// lives on its resource server's object. The object IS the API as an OAuth
// resource (#1139), and what properties it accepts is part of what the API
// is. This module reads and checks a row; it stores nothing.
//
// **A PROPERTY THE CATALOGUE DOES NOT NAME IS REFUSED, IN EVERY MODE** (rcbj
// on #563, decision 4). A caller's JSON property name has no meaning here
// until an administrator gives it one, and inferring one would let an
// accident of naming decide a policy.
//
// ---------------------------------------------------------------------------
// THE RESERVED IDENTIFIERS, AND WHY A ROW MAY NEVER NAME ONE.
//
// **A REQUEST-SUPPLIED ATTRIBUTE SUPPRESSES THE PIP.** `xacml_pdp.js` asks
// the resolver only when the request carried NOTHING for a designator — what
// the PEP asserted wins over what the directory holds, which is right for a
// PEP describing its own request. It also means that an attribute present in
// the request with an EMPTY bag still reaches the PIP (the check is
// `values.length === 0`, and an empty bag has none), so "sent empty" never
// shadows the directory; but a VALUE does. A row mapping a caller's property
// onto `urn:sts:xacml:role` would therefore let any caller name the roles of
// the subject it asks about, and the policy would believe it. So:
//
//   * every identifier in this service's own namespace, `urn:sts:xacml:` —
//     `xacml_request.js`'s VOCABULARY, the settings and passkey-policy
//     prefixes, the PIP's directory prefix and the four trusted AuthZEN
//     facts all live there, and a prefix rule cannot fall behind a list;
//   * XACML's subject-id, resource-id and action-id, which the adapter fills
//     from `subject.id`, `resource.id` and `action.name` and from nothing
//     else, and the three current-time attributes the PDP supplies;
//   * in a SUBJECT category, a bare LDAP-shaped name (`employeeType`): the
//     PIP reads one of those off the subject's directory entry
//     (`xacml_pip.ts`'s `directoryAttributeFor()`), and for a subject this
//     realm resolves (`authzen.resolveSubjectTypes`) the directory is
//     authoritative (decision 5). A subject property is sent under an
//     identifier of the operator's own instead (`urn:example:department`).
//
// `context.application` is not a catalogue property either: the adapter
// reads it to choose the caller's application scope, and the application the
// policy sees is the trusted `urn:sts:xacml:authzen:application`.
// ===========================================================================

import helpers = require('../common/helpers');
import model = require('../xacml/xacml_model');

const { log } = helpers;

// One row of the catalogue, as `parse()` answers it.
interface CatalogueRow {
  object: string;
  property: string;
  attributeId: string;
  category: string;
  dataType: string;
  multiplicity: string;
  description: string;
}

// What `parse()` answers: a row, or why the value is not one.
interface Parsed {
  row?: CatalogueRow;
  problem?: string;
  code?: string;
}

// What `rowsOf()` answers.
interface Rows {
  rows: CatalogueRow[];
  problems: string[];
}

// The four objects an AuthZEN request carries properties on.
const OBJECTS = Object.freeze(['subject', 'resource', 'action', 'context']);

// Each object's category when the row names none.
const DEFAULT_CATEGORY = Object.freeze({
  subject: model.CATEGORY.ACCESS_SUBJECT,
  resource: model.CATEGORY.RESOURCE,
  action: model.CATEGORY.ACTION,
  context: model.CATEGORY.ENVIRONMENT
});

// The categories a row may name, by short name. The full URIs are accepted
// too (any of `model.CATEGORY`'s), and a row is stored with the URI.
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

// This service's own namespace: everything in it is reserved (the header).
const RESERVED_PREFIX = 'urn:sts:xacml:';

// XACML's own identifiers the adapter fills itself, or the PDP supplies.
const RESERVED_IDS = Object.freeze([
  model.ATTRIBUTE.SUBJECT_ID, model.ATTRIBUTE.RESOURCE_ID,
  model.ATTRIBUTE.ACTION_ID, model.ATTRIBUTE.CURRENT_TIME,
  model.ATTRIBUTE.CURRENT_DATE, model.ATTRIBUTE.CURRENT_DATETIME
]);

// The context members the adapter reads itself (the header):
// `application`, and since #1177 the Obligations Profile's
// `supported_obligations`, the PEP's declaration of what it can carry out.
const RESERVED_CONTEXT = Object.freeze(['application',
                                        'supported_obligations',
                                        // The Access Request and Approval
                                        // Profile's (#1180), verified by the
                                        // adapter and never a property.
                                        'approval']);

// THE CONTEXT MEMBERS THE TOKEN-EXCHANGE BINDING'S FIXED RULES READ (#1181;
// rcbj, 2026-10-30: the built-in conversion rules are fixed, "like the five
// fixed AuthZEN members", and a realm's catalogue may add rules but never
// override them). The Token Issuance Profile's six context keys and the
// binding's five: `authzen/authzen_exchange.ts` reads each by a rule of its
// own, so a row naming one — or a path under one, `may_act.sub` — would be
// a second, contradicting conversion of the same member. Refused at the
// write whether or not `authzen.tokenExchange` is on, so turning it on never
// meets a catalogue that already disagrees.
const BINDING_CONTEXT = Object.freeze(['client_id', 'acr', 'amr',
                                       'auth_time', 'cnf', 'jti',
                                       'subject_token_type',
                                       'actor_token_type', 'subject_token',
                                       'act', 'may_act']);

// The subject categories, where a bare name would be read as a directory
// attribute of the subject.
const SUBJECT_CATEGORIES = Object.freeze([
  model.CATEGORY.ACCESS_SUBJECT, model.CATEGORY.RECIPIENT_SUBJECT,
  model.CATEGORY.INTERMEDIARY_SUBJECT, model.CATEGORY.CODEBASE,
  model.CATEGORY.REQUESTING_MACHINE
]);

// `xacml_pip.ts`'s test for a bare directory attribute name, spelt the same.
const BARE_NAME = /^[A-Za-z][A-Za-z0-9;-]*$/;

// One segment of a property path. Narrower than a JSON member name on
// purpose: a dot is the path separator, so a member whose name holds one
// could never be told from a nested one.
const SEGMENT = /^[A-Za-z0-9_$@:-]{1,64}$/;

// The deepest a dotted path may go, and the longest identifier a row may
// carry. Generous; a bound because the catalogue is walked per request.
const MAX_DEPTH = 6;
const MAX_ID_LENGTH = 512;

/**
 * The AuthZEN attribute catalogue's grammar: one row read, checked and
 * written back, and the list on an entry read whole. Pure, without I/O.
 */
class AuthzenCatalogue {
  /**
   * Says why an attribute identifier is reserved in a category, or null.
   *
   * @param attributeId - the identifier a row would send
   * @param category - the category's URI
   * @returns the reason, or null when a row may name it
   */
  static reservedProblem(attributeId: string, category: string):
      string | null {
    log.debug("Entering AuthzenCatalogue.reservedProblem().");
    const id = String(attributeId || '');
    if (id.toLowerCase().indexOf(RESERVED_PREFIX) === 0) {
      log.debug("Leaving AuthzenCatalogue.reservedProblem(). Ours.");
      return '"' + id + '" is in this service\'s own namespace (' +
        RESERVED_PREFIX + '), where every trusted fact lives — the roles, ' +
        'the realm, the protocol, the caller and its application. A ' +
        'request-supplied attribute suppresses the PIP, so a row mapping ' +
        'onto one would let a caller forge it';
    }
    if (RESERVED_IDS.indexOf(id) >= 0) {
      log.debug("Leaving AuthzenCatalogue.reservedProblem(). XACML's own.");
      return '"' + id + '" is filled by the adapter from subject.id, ' +
        'action.name or resource.id, or supplied by the PDP, and from ' +
        'nothing else';
    }
    if (SUBJECT_CATEGORIES.indexOf(category) >= 0 && BARE_NAME.test(id)) {
      log.debug("Leaving AuthzenCatalogue.reservedProblem(). A directory " +
                "attribute name.");
      return '"' + id + '" in a subject category is read as the subject\'s ' +
        'directory attribute, and for a subject this realm resolves the ' +
        'directory is authoritative. Send the property under an ' +
        'identifier of your own, such as urn:example:' + id;
    }
    log.debug("Leaving AuthzenCatalogue.reservedProblem(). Allowed.");
    return null;
  }

  /**
   * Reads one stored value as a catalogue row, or says why it is not one.
   *
   * @param value - the value: a JSON object, as text or parsed
   * @returns `{ row }`, or `{ problem, code }`
   */
  static parse(value: unknown): Parsed {
    log.debug("Entering AuthzenCatalogue.parse().");
    let given: any = value;
    if (typeof value === 'string') {
      try {
        given = JSON.parse(value);
      } catch (e) {
        log.debug("Caught in AuthzenCatalogue.parse(): " +
                  ((e && e.message) || e));
        log.debug("Leaving AuthzenCatalogue.parse(). Not JSON.");
        return { code: 'STS-AUTHZEN-0010',
                 problem: 'a catalogue row is a JSON object, and this is ' +
                          'not JSON: ' + ((e && e.message) || e) };
      }
    }
    if (!given || typeof given !== 'object' || Array.isArray(given)) {
      log.debug("Leaving AuthzenCatalogue.parse(). Not an object.");
      return { code: 'STS-AUTHZEN-0010',
               problem: 'a catalogue row is a JSON object with object, ' +
                        'property, attributeId, and optionally category, ' +
                        'dataType and multiplicity' };
    }
    const known = ['object', 'property', 'attributeId', 'category',
                   'dataType', 'multiplicity', 'description'];
    const unknown = Object.keys(given).filter(function (key: string) {
      return known.indexOf(key) < 0;
    });
    if (unknown.length) {
      log.debug("Leaving AuthzenCatalogue.parse(). Unknown members.");
      return { code: 'STS-AUTHZEN-0010',
               problem: 'a catalogue row has no member ' +
                        unknown.map(function (one: string) {
                          return '"' + one.slice(0, 40) + '"';
                        }).join(', ') + '; it takes ' + known.join(', ') };
    }
    const text = function (key: string): string {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return typeof given[key] === 'string' ? given[key].trim() : '';
    };
    const object = text('object');
    if (OBJECTS.indexOf(object) < 0) {
      log.debug("Leaving AuthzenCatalogue.parse(). No object.");
      return { code: 'STS-AUTHZEN-0010',
               problem: 'object must be one of ' + OBJECTS.join(', ') };
    }
    const property = text('property');
    const segments = property ? property.split('.') : [];
    if (!segments.length || segments.length > MAX_DEPTH ||
        !segments.every(function (one: string) {
          return SEGMENT.test(one);
        })) {
      log.debug("Leaving AuthzenCatalogue.parse(). Bad property.");
      return { code: 'STS-AUTHZEN-0010',
               problem: 'property must be a member name, or a dotted path ' +
                        'of at most ' + MAX_DEPTH + ' names, each of ' +
                        'letters, digits, _ $ @ : or -' };
    }
    if (object === 'context' && RESERVED_CONTEXT.indexOf(segments[0]) >= 0) {
      log.debug("Leaving AuthzenCatalogue.parse(). A reserved context " +
                "member.");
      return { code: 'STS-AUTHZEN-0011',
               problem: 'context.' + segments[0] + ' is read by the adapter ' +
                        'itself (the caller\'s application, the ' +
                        'obligations the PEP can carry out, or an access ' +
                        'request\'s approval), never sent to ' +
                        'the policy as a property' };
    }
    if (object === 'context' && BINDING_CONTEXT.indexOf(segments[0]) >= 0) {
      log.debug("Leaving AuthzenCatalogue.parse(). A member the token-" +
                "exchange binding reads.");
      return { code: 'STS-AUTHZEN-0011',
               problem: 'context.' + segments[0] + ' is read by the OAuth ' +
                        'token-exchange binding\'s fixed conversion rules ' +
                        '(docs/authzen.md), which a catalogue row may add ' +
                        'to but never override' };
    }
    const attributeId = text('attributeId');
    if (!attributeId || attributeId.length > MAX_ID_LENGTH ||
        /\s/.test(attributeId)) {
      log.debug("Leaving AuthzenCatalogue.parse(). Bad attributeId.");
      return { code: 'STS-AUTHZEN-0010',
               problem: 'attributeId must be a non-empty identifier with no ' +
                        'white space, at most ' + MAX_ID_LENGTH +
                        ' characters' };
    }
    const categoryText = text('category');
    let category = DEFAULT_CATEGORY[object];
    if (categoryText) {
      const uris = Object.keys(CATEGORY_NAMES).map(function (key: string) {
        return CATEGORY_NAMES[key];
      });
      category = CATEGORY_NAMES[categoryText] ||
        (uris.indexOf(categoryText) >= 0 ? categoryText : '');
      if (!category) {
        log.debug("Leaving AuthzenCatalogue.parse(). Bad category.");
        return { code: 'STS-AUTHZEN-0010',
                 problem: 'category must be one of ' +
                          Object.keys(CATEGORY_NAMES).join(', ') +
                          ', or its XACML URI' };
      }
    }
    const typeText = text('dataType') || 'string';
    const typeUris = Object.keys(TYPE_NAMES).map(function (key: string) {
      return TYPE_NAMES[key];
    });
    const dataType = TYPE_NAMES[typeText] ||
      (typeUris.indexOf(typeText) >= 0 ? typeText : '');
    if (!dataType) {
      log.debug("Leaving AuthzenCatalogue.parse(). Bad dataType.");
      return { code: 'STS-AUTHZEN-0010',
               problem: 'dataType must be one of ' +
                        Object.keys(TYPE_NAMES).join(', ') +
                        ', or its URI' };
    }
    const multiplicity = text('multiplicity') || 'single';
    if (MULTIPLICITIES.indexOf(multiplicity) < 0) {
      log.debug("Leaving AuthzenCatalogue.parse(). Bad multiplicity.");
      return { code: 'STS-AUTHZEN-0010',
               problem: 'multiplicity must be single or bag' };
    }
    const reserved = AuthzenCatalogue.reservedProblem(attributeId, category);
    if (reserved) {
      log.debug("Leaving AuthzenCatalogue.parse(). Reserved.");
      return { code: SUBJECT_CATEGORIES.indexOf(category) >= 0 &&
                     BARE_NAME.test(attributeId)
                 ? 'STS-AUTHZEN-0012' : 'STS-AUTHZEN-0011',
               problem: reserved };
    }
    const row = { object: object, property: segments.join('.'),
                  attributeId: attributeId, category: category,
                  dataType: dataType, multiplicity: multiplicity,
                  description: text('description').slice(0, 500) };
    log.debug("Leaving AuthzenCatalogue.parse(). " + object + "." +
              row.property);
    return { row: row };
  }

  /**
   * Writes a row back as the value it is stored as: canonical JSON, the
   * category and datatype as URIs, a default left in so a reader sees it.
   *
   * @param row - a row `parse()` answered
   * @returns the stored value
   */
  static valueOf(row: CatalogueRow): string {
    log.debug("Entering AuthzenCatalogue.valueOf().");
    const out: any = { object: row.object, property: row.property,
                       attributeId: row.attributeId, category: row.category,
                       dataType: row.dataType,
                       multiplicity: row.multiplicity };
    if (row.description) {
      out.description = row.description;
    }
    log.debug("Leaving AuthzenCatalogue.valueOf().");
    return JSON.stringify(out);
  }

  /**
   * The key a row is found under: its object and property path. Two rows
   * with one key are one row written twice.
   *
   * @param row - the row, or `{ object, property }`
   * @returns `object:property`
   */
  static keyOf(row: { object: string; property: string }): string {
    log.debug("Entering AuthzenCatalogue.keyOf().");
    log.debug("Leaving AuthzenCatalogue.keyOf().");
    return String(row.object) + ':' + String(row.property);
  }

  /**
   * Reads every stored value on an entry. A value that is not a row, and a
   * second row for a key already read, are left out and named in
   * `problems` — a catalogue is read on every request, and one bad value
   * must not take the API down with it; the write doors refuse both.
   *
   * @param values - the stored values
   * @returns `{ rows, problems }`
   */
  static rowsOf(values: unknown): Rows {
    log.debug("Entering AuthzenCatalogue.rowsOf().");
    const out: Rows = { rows: [], problems: [] };
    const seen: string[] = [];
    (Array.isArray(values) ? values : (values ? [values] : []))
      .forEach(function (one: unknown) {
        const parsed = AuthzenCatalogue.parse(one);
        if (!parsed.row) {
          out.problems.push(parsed.problem || 'not a row');
          return;
        }
        const key = AuthzenCatalogue.keyOf(parsed.row);
        if (seen.indexOf(key) >= 0) {
          out.problems.push(parsed.row.object + '.' + parsed.row.property +
                            ' has more than one row; the first is used');
          return;
        }
        seen.push(key);
        out.rows.push(parsed.row);
      });
    log.debug("Leaving AuthzenCatalogue.rowsOf(). " + out.rows.length +
              " row(s), " + out.problems.length + " problem(s).");
    return out;
  }
}

/**
 * The AuthZEN attribute catalogue (#563): its grammar, its reserved
 * identifiers and the reading of an entry's rows.
 * @namespace
 */
export = {
  AuthzenCatalogue: AuthzenCatalogue,
  OBJECTS: OBJECTS,
  DEFAULT_CATEGORY: DEFAULT_CATEGORY,
  CATEGORY_NAMES: CATEGORY_NAMES,
  TYPE_NAMES: TYPE_NAMES,
  MULTIPLICITIES: MULTIPLICITIES,
  RESERVED_PREFIX: RESERVED_PREFIX,
  RESERVED_CONTEXT: RESERVED_CONTEXT,
  BINDING_CONTEXT: BINDING_CONTEXT,
  parse: AuthzenCatalogue.parse,
  valueOf: AuthzenCatalogue.valueOf,
  keyOf: AuthzenCatalogue.keyOf,
  rowsOf: AuthzenCatalogue.rowsOf,
  reservedProblem: AuthzenCatalogue.reservedProblem
};
