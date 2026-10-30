// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: fga_map.ts
//
// ===========================================================================
// A VALIDATED RFC 9396 AUTHORIZATION DETAIL, AS AN XACML REQUEST (#564, phase
// P2 of application-scoped fine-grained authorization). PURE: no I/O, no
// route, no store — the policy that answers the request, and where it is
// asked, are P1's and P3's.
//
// An access type (`oauthAuthorizationDetailsType`, rule 3am, the #432
// catalogue) is declared by the RESOURCE application that understands it,
// and since #564 that application OWNS the policy that decides details of
// the type. This module is the deterministic mapping the issue asks for:
// which member of a detail becomes which XACML attribute, and what never
// becomes one.
//
//   type                    resource  urn:sts:xacml:fga:detail-type, and
//                                     the resource-id at an issuance stage
//   actions, privileges     action    urn:sts:xacml:fga:detail:action,
//                                     ...:detail:privilege (string bags)
//   locations, datatypes    resource  urn:sts:xacml:fga:detail:location,
//                                     ...:detail:datatype (string bags)
//   identifier              resource  urn:sts:xacml:fga:detail:identifier
//   any other member        the type's `xacml` row for it, and nothing else
//   a `notForPolicy` member nothing — deliberately, and visibly so
//
// and, TRUSTED, written by the adapter from what it knows and never from the
// detail: the realm, the protocol, the subject and its kind, the client, the
// owning application, the definition's digest, the stage, the grant type and
// the `supplied` bag of every member path that reached the request
// (`xacml_request.js`'s `fga()`, rule 3br).
//
// ---------------------------------------------------------------------------
// THE COMMON DATA FIELDS ARE BUILT-IN ROWS (RFC 9396 section 2.2). The five
// fields mean the same in every type — and in a GNAP access right — so a
// policy may test them with no declaration, under identifiers in this
// service's own namespace that no type's row may name. They are applied
// WHEN PRESENT: the issue is explicit that a detail need not carry any of
// them, and an absent field is an absent attribute, never an empty one.
// A type's row may not name a common field, nor may `notForPolicy` list
// one: each is always mapped, by one row, under one identifier.
//
// THE TYPE'S ROWS (`xacml`) cover everything else, one member path per row,
// in AuthZEN's catalogue grammar where it applies (`path` for AuthZEN's
// `property`, no `object`; the category defaults to resource, because a
// detail describes access to a resource). The reserved identifiers and the
// value rules are `xacml_attribute_rows.ts`'s — shared with AuthZEN, never
// copied — so a detail can never forge a trusted attribute: a row onto
// `urn:sts:xacml:*`, subject-id, resource-id, action-id, the current-time
// attributes or a bare directory name in a subject category is refused when
// the definition is WRITTEN (STS-REG-0112, through `mappingOf()`).
//
// ---------------------------------------------------------------------------
// COVERAGE: `uncovered()`. The issue says the mapping "must not silently
// discard fields that affect authorization decisions or interpret unknown
// fields as trusted authorization attributes". The second half is the
// walk's: a member no row maps is refused, never guessed at. The first half
// is a question about the TYPE, not one detail — whether every member its
// JSON Schema PERMITS is either mapped or deliberately not — and it is
// answered here, so enabling FGA on an application (P1, P3) can be refused
// while the answer is not empty. The answer is a list of member paths, with
// two spellings for what no row can ever cover:
//
//   `*`          the schema permits members it does not name — there is no
//                schema, or its top level does not set
//                `additionalProperties: false`
//   `<path>.*`   the same, for a nested object some row or `notForPolicy`
//                entry reaches into
//
// **AN OPEN SCHEMA MAKES THE TYPE UNCOVERABLE, ON PURPOSE.** A schema that
// allows unnamed members lets a client send a member the policy has never
// heard of; the walk refuses it at request time (so nothing unknown becomes
// an attribute), but the TYPE cannot honestly be said to be covered, because
// the administrator has not decided what such a member means. Closing the
// schema is the one fix, and it is the right one: it also makes RFC 9396
// section 5 refuse the stranger at validation, before any policy is asked.
// `unevaluatedProperties: false` closes a level too, but only where the
// level has no applicator (`allOf`, `anyOf`, `oneOf`, `$ref`, `$dynamicRef`,
// `if`, `dependentSchemas`) that could evaluate members this module cannot
// enumerate without a schema engine of its own; `patternProperties` always
// leaves a level open, for the same reason. A conservative answer here
// costs an administrator one keyword; a generous one would cost the policy
// a member it never saw.
//
// ---------------------------------------------------------------------------
// THE DIGEST. `urn:sts:xacml:fga:definition-digest` is a SHA-256, lowercase
// hex, of the definition's canonical JSON (members sorted, no white space;
// a bare type name is `{"type":"<name>"}`), so a policy may be pinned to the
// definition it was written against and an edit of the definition is
// visible to it. Key order and spacing of the stored value do not change it.
//
// ---------------------------------------------------------------------------
// THE CODES, `STS-FGA-0100`..`0107` (numbered from 0100 so P1's lifecycle
// codes, written beside these, keep the low numbers): a definition that is
// not usable (0100), a detail that is not one of its type (0101), trusted
// facts that are not (0102), a member nothing covers (0103), and the value
// rules' four kinds (0104 null, 0105 type, 0106 array, 0107 object or
// depth). The details reaching `request()` have passed RFC 9396 validation,
// so every one of these is DEFENSIVE — a refusal, never an attribute.
// ===========================================================================

import helpers = require('../common/helpers');
import stsCrypto = require('../common/crypto');
import model = require('./xacml_model');
import xacmlRequest = require('./xacml_request');
import rowsGrammar = require('./xacml_attribute_rows');

const { log } = helpers;

// One row of a type's `xacml` member, as `mappingOf()` answers it.
interface FgaRow {
  path: string;
  attributeId: string;
  category: string;
  dataType: string;
  multiplicity: string;
  description?: string;
}

// What `mappingOf()` answers.
interface Mapping {
  xacml: FgaRow[];
  notForPolicy: string[];
  problem: string;
}

// What the adapter knows, and writes as trusted facts.
interface Trusted {
  realm?: string;
  protocol?: string;
  subject?: { id?: string; kind?: string };
  clientId?: string;
  application: string;
  stage: string;
  action?: string;
  resourceId?: string;
  grantType?: string;
  definitionDigest?: string;
}

// A request that cannot be built: the code and what was wrong.
interface Refusal {
  code: string;
  message: string;
}

// What `request()` answers.
interface Built {
  request?: any;
  attributes?: any[];
  supplied?: string[];
  digest?: string;
  refusal?: Refusal;
}

const V = xacmlRequest.VOCABULARY;

// RFC 9396 section 2.2's five common data fields, in its order.
const COMMON_FIELDS = Object.freeze(['locations', 'actions', 'datatypes',
                                     'identifier', 'privileges']);

// THE BUILT-IN ROWS (the header). The identifiers are the builder's, so
// they are spelt once.
const COMMON_ROWS: readonly FgaRow[] = Object.freeze([
  { path: 'locations', attributeId: V.FGA_DETAIL_LOCATION,
    category: model.CATEGORY.RESOURCE, dataType: model.TYPE.STRING,
    multiplicity: 'bag' },
  { path: 'actions', attributeId: V.FGA_DETAIL_ACTION,
    category: model.CATEGORY.ACTION, dataType: model.TYPE.STRING,
    multiplicity: 'bag' },
  { path: 'datatypes', attributeId: V.FGA_DETAIL_DATATYPE,
    category: model.CATEGORY.RESOURCE, dataType: model.TYPE.STRING,
    multiplicity: 'bag' },
  { path: 'identifier', attributeId: V.FGA_DETAIL_IDENTIFIER,
    category: model.CATEGORY.RESOURCE, dataType: model.TYPE.STRING,
    multiplicity: 'single' },
  { path: 'privileges', attributeId: V.FGA_DETAIL_PRIVILEGE,
    category: model.CATEGORY.ACTION, dataType: model.TYPE.STRING,
    multiplicity: 'bag' }
]);

// The members a row may carry.
const ROW_MEMBERS = Object.freeze(['path', 'attributeId', 'category',
                                   'dataType', 'multiplicity',
                                   'description']);

// The most rows, and `notForPolicy` entries, a type may carry. Generous; a
// bound because the rows are walked per detail.
const MAX_ROWS = 256;

// The value rules' kinds and the code each is refused under.
const VALUE_CODES = Object.freeze({
  null: 'STS-FGA-0104',
  type: 'STS-FGA-0105',
  array: 'STS-FGA-0106',
  object: 'STS-FGA-0107',
  depth: 'STS-FGA-0107'
});

// The JSON Schema applicators that could evaluate members a level's own
// `properties` does not name, so `unevaluatedProperties: false` alone does
// not close that level here (the header).
const APPLICATORS = Object.freeze(['allOf', 'anyOf', 'oneOf', '$ref',
                                   '$dynamicRef', 'if', 'then', 'else',
                                   'dependentSchemas']);

// What `uncovered()` lists for a level no row can ever cover.
const OPEN = '*';

/**
 * Builds a refusal.
 *
 * @param code - the error code
 * @param message - what was wrong
 * @returns the refusal
 */
function refused(code: string, message: string): Built {
  log.debug("Entering refused(). " + code);
  log.debug("Leaving refused().");
  return { refusal: { code: code, message: message } };
}

/**
 * Tells whether a path is a given path or below it.
 *
 * @param path - the path asked about
 * @param base - the path that may contain it
 * @returns true when `path` is `base` or a member of it
 */
function within(path: string, base: string): boolean {
  log.debug("Entering within().");
  log.debug("Leaving within().");
  return path === base || path.indexOf(base + '.') === 0;
}

/**
 * Sorts an object's members, all the way down, for a canonical form.
 *
 * @param value - any JSON value
 * @returns the same value with every object's members in order
 */
function canonical(value: any): any {
  log.debug("Entering canonical().");
  if (Array.isArray(value)) {
    log.debug("Leaving canonical(). An array.");
    return value.map(canonical);
  }
  if (value && typeof value === 'object') {
    const out: any = {};
    Object.keys(value).sort().forEach(function (key: string) {
      out[key] = canonical(value[key]);
    });
    log.debug("Leaving canonical(). An object.");
    return out;
  }
  log.debug("Leaving canonical().");
  return value;
}

/**
 * The mapping of RFC 9396 authorization details onto XACML for
 * fine-grained authorization: the grammar of a type's `xacml` and
 * `notForPolicy` members, its coverage, its digest and the request for one
 * detail. Pure, without I/O.
 */
class FgaMap {
  /**
   * Reads one `xacml` row of a type definition, or says why it is not one.
   *
   * @param value - the row, a JSON object
   * @param where - how a sentence names it (`xacml[2]`)
   * @returns `{ row }`, or `{ problem }`
   */
  static parseRow(value: unknown, where: string):
      { row?: FgaRow; problem?: string } {
    log.debug("Entering FgaMap.parseRow(). " + where);
    if (!rowsGrammar.XacmlAttributeRows.isObject(value)) {
      log.debug("Leaving FgaMap.parseRow(). Not an object.");
      return { problem: where + ' is not a JSON object of path, ' +
                        'attributeId, and optionally category, dataType, ' +
                        'multiplicity and description' };
    }
    const given: any = value;
    const stray = Object.keys(given).filter(function (key: string) {
      return ROW_MEMBERS.indexOf(key) < 0;
    });
    if (stray.length) {
      log.debug("Leaving FgaMap.parseRow(). Unknown members.");
      return { problem: where + ' has no member ' +
                        stray.map(function (one: string) {
                          return '"' + one.slice(0, 40) + '"';
                        }).join(', ') + '; a row takes ' +
                        ROW_MEMBERS.join(', ') };
    }
    const text = function (key: string): string {
      log.debug("Entering text().");
      log.debug("Leaving text().");
      return typeof given[key] === 'string' ? given[key].trim() : '';
    };
    const path = text('path');
    const segments = rowsGrammar.segmentsOf(path);
    if (!segments) {
      log.debug("Leaving FgaMap.parseRow(). Bad path.");
      return { problem: where + '.path must be a member name, or a dotted ' +
                        'path of at most ' + rowsGrammar.MAX_DEPTH +
                        ' names, each of letters, digits, _ $ @ : or -' };
    }
    const fixed = FgaMap.fixedMemberProblem(segments[0]);
    if (fixed) {
      log.debug("Leaving FgaMap.parseRow(). A fixed member.");
      return { problem: where + '.path: ' + fixed };
    }
    const attributeId = text('attributeId');
    if (!rowsGrammar.idShaped(attributeId)) {
      log.debug("Leaving FgaMap.parseRow(). Bad attributeId.");
      return { problem: where + '.attributeId must be a non-empty ' +
                        'identifier with no white space, at most ' +
                        rowsGrammar.MAX_ID_LENGTH + ' characters' };
    }
    const categoryText = text('category');
    const category = categoryText ? rowsGrammar.categoryOf(categoryText)
                                  : model.CATEGORY.RESOURCE;
    if (!category) {
      log.debug("Leaving FgaMap.parseRow(). Bad category.");
      return { problem: where + '.category must be one of ' +
                        Object.keys(rowsGrammar.CATEGORY_NAMES).join(', ') +
                        ', or its XACML URI' };
    }
    const dataType = rowsGrammar.dataTypeOf(text('dataType'));
    if (!dataType) {
      log.debug("Leaving FgaMap.parseRow(). Bad dataType.");
      return { problem: where + '.dataType must be one of ' +
                        Object.keys(rowsGrammar.TYPE_NAMES).join(', ') +
                        ', or its URI' };
    }
    const multiplicity = text('multiplicity') || 'single';
    if (rowsGrammar.MULTIPLICITIES.indexOf(multiplicity) < 0) {
      log.debug("Leaving FgaMap.parseRow(). Bad multiplicity.");
      return { problem: where + '.multiplicity must be single or bag' };
    }
    const reserved = rowsGrammar.reservedProblem(attributeId, category);
    if (reserved) {
      log.debug("Leaving FgaMap.parseRow(). Reserved.");
      return { problem: where + '.attributeId: ' + reserved };
    }
    const row: FgaRow = { path: segments.join('.'), attributeId: attributeId,
                          category: category, dataType: dataType,
                          multiplicity: multiplicity };
    if (text('description')) {
      row.description = text('description').slice(0, 500);
    }
    log.debug("Leaving FgaMap.parseRow(). " + row.path);
    return { row: row };
  }

  /**
   * Says why a top-level member may not be named by a row or by
   * `notForPolicy`, or ''.
   *
   * @param name - the path's first segment
   * @returns the sentence, or ''
   */
  static fixedMemberProblem(name: string): string {
    log.debug("Entering FgaMap.fixedMemberProblem().");
    if (name === 'type') {
      log.debug("Leaving FgaMap.fixedMemberProblem(). type.");
      return '"type" is sent by the adapter as ' + V.FGA_DETAIL_TYPE +
        ', a trusted fact, and nothing else may map it';
    }
    if (COMMON_FIELDS.indexOf(name) >= 0) {
      log.debug("Leaving FgaMap.fixedMemberProblem(). A common field.");
      return '"' + name + '" is one of RFC 9396 section 2.2\'s common data ' +
        'fields, which a built-in row always maps (' +
        COMMON_ROWS.filter(function (one: FgaRow) {
          return one.path === name;
        })[0].attributeId + ')';
    }
    log.debug("Leaving FgaMap.fixedMemberProblem().");
    return '';
  }

  /**
   * Reads a type definition's `xacml` and `notForPolicy` members — the
   * grammar every write door asks (`applications.js`'s
   * `authorizationDetailsTypeOf()`, `STS-REG-0112`). A definition with
   * neither is answered empty, and means what it meant before #564.
   *
   * @param definition - the parsed definition object
   * @returns `{ xacml, notForPolicy, problem }`; `problem` is '' when usable
   */
  static mappingOf(definition: any): Mapping {
    log.debug("Entering FgaMap.mappingOf().");
    const out: Mapping = { xacml: [], notForPolicy: [], problem: '' };
    const given = definition || {};
    if (given.xacml !== undefined) {
      if (!Array.isArray(given.xacml) || given.xacml.length > MAX_ROWS) {
        out.problem = 'xacml must be an array of at most ' + MAX_ROWS +
          ' rows';
        log.debug("Leaving FgaMap.mappingOf(). xacml not an array.");
        return out;
      }
      for (let i = 0; i < given.xacml.length; i += 1) {
        const parsed = FgaMap.parseRow(given.xacml[i], 'xacml[' + i + ']');
        if (!parsed.row) {
          out.problem = parsed.problem;
          log.debug("Leaving FgaMap.mappingOf(). A row.");
          return out;
        }
        const row = parsed.row;
        const clash = out.xacml.filter(function (one: FgaRow) {
          return within(row.path, one.path) || within(one.path, row.path);
        })[0];
        if (clash) {
          out.problem = 'xacml[' + i + '] maps ' + row.path + ', and ' +
            (clash.path === row.path
              ? 'another row maps it too'
              : 'another row maps ' + clash.path + ', so one would be an ' +
                'object holding the other');
          log.debug("Leaving FgaMap.mappingOf(). Two rows for one member.");
          return out;
        }
        const twin = out.xacml.filter(function (one: FgaRow) {
          return one.attributeId === row.attributeId &&
                 one.category === row.category;
        })[0];
        if (twin) {
          out.problem = 'xacml[' + i + '] sends ' + row.attributeId +
            ', which the row for ' + twin.path + ' sends already; two ' +
            'members under one attribute could not be told apart by a policy';
          log.debug("Leaving FgaMap.mappingOf(). Two rows for one attribute.");
          return out;
        }
        out.xacml.push(row);
      }
    }
    if (given.notForPolicy !== undefined) {
      if (!Array.isArray(given.notForPolicy) ||
          given.notForPolicy.length > MAX_ROWS) {
        out.problem = 'notForPolicy must be an array of at most ' + MAX_ROWS +
          ' member paths';
        log.debug("Leaving FgaMap.mappingOf(). notForPolicy not an array.");
        return out;
      }
      for (let j = 0; j < given.notForPolicy.length; j += 1) {
        const where = 'notForPolicy[' + j + ']';
        const value = given.notForPolicy[j];
        const segments = typeof value === 'string'
          ? rowsGrammar.segmentsOf(value.trim()) : null;
        if (!segments) {
          out.problem = where + ' must be a member name, or a dotted path ' +
            'of at most ' + rowsGrammar.MAX_DEPTH + ' names';
          log.debug("Leaving FgaMap.mappingOf(). A bad path.");
          return out;
        }
        const fixed = FgaMap.fixedMemberProblem(segments[0]);
        if (fixed) {
          out.problem = where + ': ' + fixed;
          log.debug("Leaving FgaMap.mappingOf(). A fixed member.");
          return out;
        }
        const path = segments.join('.');
        const overlap = out.notForPolicy.filter(function (one: string) {
          return within(path, one) || within(one, path);
        })[0];
        const mapped = out.xacml.filter(function (one: FgaRow) {
          return within(path, one.path) || within(one.path, path);
        })[0];
        if (overlap || mapped) {
          out.problem = where + ' names ' + path + ', which ' +
            (mapped ? 'the row for ' + mapped.path + ' maps'
                    : 'notForPolicy names already, as ' + overlap) +
            '; a member is mapped or deliberately not, never both';
          log.debug("Leaving FgaMap.mappingOf(). An overlap.");
          return out;
        }
        out.notForPolicy.push(path);
      }
    }
    log.debug("Leaving FgaMap.mappingOf(). " + out.xacml.length +
              " row(s), " + out.notForPolicy.length + " not for policy.");
    return out;
  }

  /**
   * The member paths a type's schema permits that are neither a common
   * field, nor mapped by a row, nor listed in `notForPolicy` — `*` (or
   * `<path>.*`) where the schema permits members it does not name (the
   * header). Empty means the type is covered and FGA may be enforced on it.
   *
   * @param definition - the definition as `applications.js` reads it, or
   *   the definition object itself
   * @returns the uncovered paths, sorted
   */
  static uncovered(definition: any): string[] {
    log.debug("Entering FgaMap.uncovered().");
    const given = definition || {};
    const rows = (Array.isArray(given.xacml) ? given.xacml : [])
      .map(function (one: any) {
        return String((one && one.path) || '');
      });
    const skipped = (Array.isArray(given.notForPolicy) ? given.notForPolicy
                                                       : []).map(String);
    const out: string[] = [];
    FgaMap.uncoveredAt(given.schema, '', rows, skipped, out, 0);
    out.sort();
    log.debug("Leaving FgaMap.uncovered(). " + out.length + " uncovered.");
    return out;
  }

  /**
   * One level of `uncovered()`: the members a schema node names, and
   * whether it names all it permits.
   *
   * @param schema - the schema of the object at `prefix`
   * @param prefix - the dotted path down to here, '' at the top
   * @param rows - the rows' paths
   * @param skipped - the `notForPolicy` paths
   * @param out - the uncovered paths so far
   * @param depth - how deep this level is
   */
  static uncoveredAt(schema: any, prefix: string, rows: string[],
                     skipped: string[], out: string[], depth: number): void {
    log.debug("Entering FgaMap.uncoveredAt(). " + (prefix || '(top)'));
    const open = prefix ? prefix + '.' + OPEN : OPEN;
    if (schema === false) {
      log.debug("Leaving FgaMap.uncoveredAt(). Nothing permitted.");
      return;
    }
    if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
      out.push(open);
      log.debug("Leaving FgaMap.uncoveredAt(). No schema: open.");
      return;
    }
    const properties = schema.properties && typeof schema.properties ===
      'object' && !Array.isArray(schema.properties) ? schema.properties : {};
    Object.keys(properties).forEach(function (name: string) {
      const path = prefix ? prefix + '.' + name : name;
      if (!prefix && (name === 'type' || COMMON_FIELDS.indexOf(name) >= 0)) {
        return;
      }
      if (rows.indexOf(path) >= 0 || skipped.some(function (one: string) {
        return within(path, one);
      })) {
        return;
      }
      const reached = rows.concat(skipped).some(function (one: string) {
        return one.indexOf(path + '.') === 0;
      });
      if (reached && depth + 1 < rowsGrammar.MAX_DEPTH) {
        FgaMap.uncoveredAt(properties[name], path, rows, skipped, out,
                           depth + 1);
        return;
      }
      out.push(path);
    });
    if (!FgaMap.closed(schema)) {
      out.push(open);
    }
    log.debug("Leaving FgaMap.uncoveredAt().");
  }

  /**
   * Tells whether a schema node permits only the members its `properties`
   * names (the header's rule).
   *
   * @param schema - the schema node, an object
   * @returns true when it is closed
   */
  static closed(schema: any): boolean {
    log.debug("Entering FgaMap.closed().");
    const patterns = schema.patternProperties &&
      typeof schema.patternProperties === 'object' &&
      Object.keys(schema.patternProperties).length > 0;
    if (patterns) {
      log.debug("Leaving FgaMap.closed(). patternProperties.");
      return false;
    }
    if (schema.additionalProperties === false) {
      log.debug("Leaving FgaMap.closed(). additionalProperties false.");
      return true;
    }
    const applied = APPLICATORS.some(function (key: string) {
      return schema[key] !== undefined;
    });
    log.debug("Leaving FgaMap.closed().");
    return schema.unevaluatedProperties === false && !applied;
  }

  /**
   * The definition's digest: SHA-256, lowercase hex, of its canonical JSON
   * (the header).
   *
   * @param definition - the definition as `applications.js` reads it (its
   *   `source`), the definition object, or the stored value
   * @returns the digest
   */
  static digest(definition: any): string {
    log.debug("Entering FgaMap.digest().");
    let value: any = definition;
    if (value && typeof value === 'object' && value.source &&
        typeof value.source === 'object') {
      value = value.source;
    } else if (typeof value === 'string') {
      const text = value.trim();
      if (text.charAt(0) === '{') {
        try {
          value = JSON.parse(text);
        } catch (e) {
          // Not a definition at all; its digest is of the text, which no
          // usable definition shares, so a policy pinned to one never
          // matches it.
          log.debug("Caught in FgaMap.digest(): " + ((e && e.message) || e));
          value = text;
        }
      } else {
        value = { type: text };
      }
    }
    const out = stsCrypto.digest('sha256', JSON.stringify(canonical(value)),
                                 'hex');
    log.debug("Leaving FgaMap.digest().");
    return out;
  }

  /**
   * Builds the XACML request for one validated authorization detail, or
   * refuses it (the header's codes).
   *
   * @param detail - the detail, as RFC 9396 validation passed it
   * @param definition - its type's definition as `applications.js` reads
   *   it (or `authorization_details.ts`'s `declaredTypes()` entry)
   * @param trusted - what the adapter knows: application, stage, realm,
   *   protocol, subject { id, kind }, clientId, action, resourceId,
   *   grantType, definitionDigest (computed when absent)
   * @returns `{ request, attributes, supplied, digest }`, or `{ refusal }`
   */
  static request(detail: unknown, definition: any, trusted: Trusted): Built {
    log.debug("Entering FgaMap.request().");
    if (!definition || typeof definition !== 'object' || definition.problem ||
        typeof definition.type !== 'string' || !definition.type) {
      log.debug("Leaving FgaMap.request(). No usable definition.");
      return refused('STS-FGA-0100', 'the type\'s definition is not usable' +
        (definition && definition.problem ? ': ' + definition.problem : ''));
    }
    const given: any = detail;
    if (!rowsGrammar.XacmlAttributeRows.isObject(detail) ||
        given.type !== definition.type) {
      log.debug("Leaving FgaMap.request(). Not a detail of the type.");
      return refused('STS-FGA-0101', 'the detail is not an object of type "' +
        definition.type.slice(0, 200) + '"');
    }
    const facts: any = trusted || {};
    if (xacmlRequest.FGA_STAGES.indexOf(facts.stage) < 0 ||
        typeof facts.application !== 'string' || !facts.application) {
      log.debug("Leaving FgaMap.request(). The trusted facts.");
      return refused('STS-FGA-0102', 'the adapter must name the owning ' +
        'application and a stage, one of ' +
        xacmlRequest.FGA_STAGES.join(', '));
    }
    const rows = COMMON_ROWS.concat(Array.isArray(definition.xacml)
                                      ? definition.xacml : []);
    const skipped: string[] = Array.isArray(definition.notForPolicy)
      ? definition.notForPolicy : [];
    const skip = function (path: string): boolean {
      log.debug("Entering skip().");
      log.debug("Leaving skip().");
      return path === 'type' || skipped.some(function (one: string) {
        return within(path, one);
      });
    };
    const attributes: any[] = [];
    const supplied: string[] = [];
    const problem = rowsGrammar.walk(given, '', '', rows, attributes,
                                     supplied, 0, skip);
    if (problem) {
      log.debug("Leaving FgaMap.request(). " + problem.kind);
      if (problem.kind === 'undeclared') {
        return refused('STS-FGA-0103', problem.named + ' is a member of the ' +
          'detail that the type "' + definition.type.slice(0, 200) + '" ' +
          'neither maps (xacml) nor lists in notForPolicy, so it cannot ' +
          'reach the policy, and a member nobody declared is never read as ' +
          'an attribute.');
      }
      return refused(VALUE_CODES[problem.kind] || 'STS-FGA-0105',
                     problem.message);
    }
    const digest = facts.definitionDigest || FgaMap.digest(definition);
    const subject = facts.subject || {};
    const request = new xacmlRequest.AuthorizationRequest({})
      .fga({ realm: facts.realm, protocol: facts.protocol,
             subject: { id: subject.id, kind: subject.kind },
             clientId: facts.clientId, application: facts.application,
             detailType: definition.type, definitionDigest: digest,
             stage: facts.stage, action: facts.action,
             resourceId: facts.resourceId, grantType: facts.grantType,
             supplied: supplied, attributes: attributes })
      .build();
    log.debug("Leaving FgaMap.request(). " + attributes.length +
              " mapped attribute(s).");
    return { request: request, attributes: attributes, supplied: supplied,
             digest: digest };
  }
}

/**
 * Fine-grained authorization's mapping (#564): a type's `xacml` and
 * `notForPolicy` grammar, its coverage, its digest, and one detail's XACML
 * request.
 * @namespace
 */
export = {
  FgaMap: FgaMap,
  COMMON_FIELDS: COMMON_FIELDS,
  COMMON_ROWS: COMMON_ROWS,
  OPEN: OPEN,
  mappingOf: FgaMap.mappingOf,
  uncovered: FgaMap.uncovered,
  digest: FgaMap.digest,
  request: FgaMap.request
};
