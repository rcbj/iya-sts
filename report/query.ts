// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: query.ts
//
// ---------------------------------------------------------------------------
// A REPORT IS A DOCUMENT (#956).
//
// The document names one catalog source, the fields to project, a filter
// tree, an order, a limit, a format and a mode. It is not a statement. A
// string, a `query` string, or a second source is rejected whole, and the
// refusal does not repeat what was sent: a statement must not land in the
// log as if this service had considered running it.
//
// Nothing in a document is ignored. An unknown key, a field the catalog
// does not have, a limit of zero and a parameter with no value are all
// refusals. The catalog is checked before the size cap, so a credential
// attribute id — which the catalog does not register — is an unknown field
// even when the limit is also too big. A refusal carries no partial plan.
//
// THE SHAPE IS THE MODEL'S (#1579). `QueryDocument` and the six `Filter`
// forms in `models/api/report.tsp` say what a document may hold — its keys,
// each one's type, the enumerations, the caps on every list, the language
// tag, which keys each kind of filter node takes — and `ModelZod` builds the
// check from them, so the Reports API OpenAPI document and the check are one
// declaration. What stays here is what one document cannot answer alone:
// whether the catalog has the source and the fields and lets a field be
// grouped, sorted or filtered, which operators a field's type takes, what
// type a value must be for that field, a saved parameter's value, a field
// ordered twice, a count's grouping, how deep a filter nests (JSON Schema
// bounds no recursion), and the size caps. Each refusal keeps the code, the
// error token and the sentence it always had: the model's issue is read for
// WHERE the document is wrong, and the sentence is chosen here.
//
// `mode: auto` runs synchronously when the source is bounded and the limit
// fits the synchronous cap, and asynchronously otherwise. A source a test
// marks unbounded cannot run synchronously at any limit.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');
import ModelZod = require('../common/model_zod');
import Catalog = require('./catalog');
import Limits = require('./limits');

const log = bunyan.createLogger({ name: 'sts-report-query' });

const WHERE_DEPTH = 8;
const STAMP_CAP = 40;

// The six forms a filter node takes, as the model names them.
const FORMS = ['FilterLogical', 'FilterNot', 'FilterIsNull', 'FilterValue',
  'FilterIn', 'FilterParam'];

type Issue = { code: string; path: Array<string | number>;
               input?: unknown; params?: Record<string, unknown> };

/**
 * The model's checks, built once: the document's and each filter form's,
 * the operators each form names, and the caps a refusal quotes.
 */
interface Shapes {
  document: any;
  forms: Record<string, any>;
  operators: Record<string, string[]>;
  caps: { select: number; groupBy: number; orderBy: number; args: number;
          inMin: number; inMax: number };
}

let shapes: Shapes | null = null;

function shapesOf(): Shapes {
  log.debug("Entering shapesOf().");
  if (!shapes) {
    const forms: Record<string, any> = {};
    const operators: Record<string, string[]> = {};
    FORMS.forEach(function (name: string): void {
      forms[name] = ModelZod.component('report', name, { typed: true });
      operators[name] = ModelZod.schemaOf('report', name).properties.op.enum
        .slice();
    });
    const document = ModelZod.schemaOf('report', 'QueryDocument').properties;
    const logical = ModelZod.schemaOf('report', 'FilterLogical').properties;
    const within = ModelZod.schemaOf('report', 'FilterIn').properties;
    shapes = {
      document: ModelZod.component('report', 'QueryDocument',
                                   { typed: true }),
      forms: forms,
      operators: operators,
      caps: { select: document.select.maxItems,
              groupBy: document.groupBy.maxItems,
              orderBy: document.orderBy.maxItems,
              args: logical.args.maxItems,
              inMin: within.value.minItems, inMax: within.value.maxItems }
    };
  }
  log.debug("Leaving shapesOf().");
  return shapes;
}

// The model's issues with one value; an empty list when it holds.
function issuesOf(check: any, value: unknown): Issue[] {
  log.debug("Entering issuesOf().");
  // The input is reported so that a member left out can be told from one
  // of the wrong type.
  const held = check.safeParse(value, { reportInput: true });
  log.debug("Leaving issuesOf().");
  return held.success ? [] : held.error.issues;
}

// The issues under one top-level key, in the order the model reported them.
function under(issues: Issue[], key: string): Issue[] {
  log.debug("Entering under().");
  const out = issues.filter(function (one: Issue): boolean {
    return one.path.length > 0 && one.path[0] === key;
  });
  log.debug("Leaving under().");
  return out;
}

// A key the document's schema does not name.
function unrecognised(issues: Issue[]): boolean {
  log.debug("Entering unrecognised().");
  const out = issues.some(function (one: Issue): boolean {
    return one.code === 'unrecognized_keys';
  });
  log.debug("Leaving unrecognised().");
  return out;
}

// A required member left out: an issue whose reported input is nothing,
// whichever check (a type, an enumeration) was asked first.
function missing(one: Issue): boolean {
  log.debug("Entering missing().");
  log.debug("Leaving missing().");
  return Object.prototype.hasOwnProperty.call(one, 'input') &&
    one.input === undefined;
}

interface LimitSource {
  syncMaxRows(): number;
  syncMaxBytes(): number;
  syncMaxMs(): number;
  asyncMaxRows(): number;
  asyncMaxBytes(): number;
  pdfMaxRows(): number;
  pdfMaxPages(): number;
}

interface QueryFailure {
  ok: false;
  code: string;
  error: string;
  description: string;
}

interface QueryPlan {
  source: string;
  select: string[];
  where: any;
  orderBy: Array<{ field: string; dir: string }>;
  limit: number;
  format: string;
  mode: string;
  locale: string | null;
  aggregate: string | null;
  groupBy: string[];
  execution: string;
  fields: string[];
}

type QueryResult = { ok: true; plan: QueryPlan } | QueryFailure;

function ownKeys(value: object): string[] {
  log.debug("Entering ownKeys().");
  const keys = Object.keys(value).filter(function (key) {
    return Object.prototype.hasOwnProperty.call(value, key);
  });
  log.debug("Leaving ownKeys().");
  return keys;
}

function plainObject(value: unknown): value is Record<string, unknown> {
  log.debug("Entering plainObject().");
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    log.debug("Leaving plainObject(). Not an object.");
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  const ok = proto === Object.prototype || proto === null;
  log.debug("Leaving plainObject().");
  return ok;
}

/**
 * Validates a report document and decides whether it runs now or as a job.
 * It does not read a row and it does not write a response.
 */
class Query {
  catalog: Catalog;
  limits: LimitSource;
  parameters: Record<string, unknown> | null;
  boundSource: string;

  /**
   * @param options - catalog and limits; both default to the service's own
   */
  constructor(options?: { catalog?: Catalog; limits?: LimitSource }) {
    log.debug("Entering Query().");
    const given = options || {};
    this.catalog = given.catalog || new Catalog();
    this.limits = given.limits || new Limits();
    this.parameters = null;
    this.boundSource = '';
    log.debug("Leaving Query().");
  }

  /**
   * Validates one document.
   *
   * @param document - the query document, or whatever was posted
   * @param parameters - values for a saved definition; omitted on an ad hoc
   *   query, where a `param` leaf is refused
   * @returns the plan, or the refusal. A refusal has no plan.
   */
  validate(document: unknown,
           parameters?: Record<string, unknown> | null): QueryResult {
    log.debug("Entering Query.validate().");
    this.parameters = parameters === undefined ? null : parameters;
    let result: QueryResult;
    const failure = this.document(document);
    if (failure) {
      result = failure;
    } else {
      // Parameters stay bound until the plan has copied them into values.
      result = this.planOf(document as Record<string, unknown>);
    }
    this.parameters = null;
    this.boundSource = '';
    log.debug("Leaving Query.validate().");
    return result;
  }

  /**
   * One refusal. The code literal lives at the call, so the table can see
   * it; this method only records it.
   *
   * @param code - the STS-REPORT code
   * @param error - the public error token
   * @param description - the English explanation, which never quotes a
   *   statement
   * @returns the refusal
   */
  private fail(code: string, error: string,
               description: string): QueryFailure {
    log.debug("Entering Query.fail().");
    log.warn(errorCodes.tag(code) + 'report query: ' + description);
    log.debug("Leaving Query.fail().");
    return { ok: false, code: code, error: error,
             description: description };
  }

  /**
   * The whole document, or the first thing wrong with it.
   *
   * @param document - what was posted
   * @returns a refusal, or null when a plan can be built
   */
  private document(document: unknown): QueryFailure | null {
    log.debug("Entering Query.document().");
    if (typeof document === 'string' || document == null ||
        !plainObject(document)) {
      log.debug("Leaving Query.document(). Not a document.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A report is a document, not a statement.');
    }
    // The model refuses both as keys it does not name. They are told apart
    // because they are how a statement or a second source arrives, and the
    // refusal says so without repeating them.
    const keys = ownKeys(document);
    if (keys.indexOf('query') >= 0 || keys.indexOf('sources') >= 0) {
      log.debug("Leaving Query.document(). A statement or a second source.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A report is a document, not a statement.');
    }
    const issues = issuesOf(shapesOf().document, document);
    if (unrecognised(issues.filter(function (one: Issue): boolean {
      return one.path.length === 0;
    }))) {
      log.debug("Leaving Query.document(). Unknown key.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The document has a key this service does not read.');
    }
    const shaped = this.shape(document, issues);
    log.debug("Leaving Query.document().");
    return shaped;
  }

  /**
   * Source, fields, filter, order, limit and the execution decision.
   * Fields are resolved before the size cap.
   *
   * @param document - a plain document whose keys are already known
   * @param issues - what the model found wrong with it
   * @returns a refusal, or null
   */
  private shape(document: Record<string, unknown>,
                issues: Issue[]): QueryFailure | null {
    log.debug("Entering Query.shape().");
    const source = this.sourceOf(document, under(issues, 'source'));
    if (source) {
      log.debug("Leaving Query.shape(). Source.");
      return source;
    }
    this.boundSource = String(document.source);
    if (under(issues, 'format').length) {
      log.debug("Leaving Query.shape(). Format.");
      return this.fail('STS-REPORT-0003', 'unsupported_format',
        'The format is not json, csv or pdf.');
    }
    if (under(issues, 'mode').length) {
      log.debug("Leaving Query.shape(). Mode.");
      return this.fail('STS-REPORT-0003', 'unsupported_operation',
        'The mode is not sync, async or auto.');
    }
    if (under(issues, 'locale').length) {
      log.debug("Leaving Query.shape(). Locale.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The locale is not a language tag.');
    }
    if (under(issues, 'aggregate').length) {
      log.debug("Leaving Query.shape(). Aggregate.");
      return this.fail('STS-REPORT-0003', 'unsupported_operation',
        'The only aggregate is count.');
    }
    const fields = this.fieldsOf(document, issues);
    if (fields) {
      log.debug("Leaving Query.shape(). Fields.");
      return fields;
    }
    const where = this.whereOf(document.where, 1);
    if (where) {
      log.debug("Leaving Query.shape(). Filter.");
      return where;
    }
    if (under(issues, 'limit').length) {
      log.debug("Leaving Query.shape(). Limit.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A limit is a positive whole number.');
    }
    const size = this.sizeOf(document);
    log.debug("Leaving Query.shape().");
    return size;
  }

  private sourceOf(document: Record<string, unknown>,
                   issues: Issue[]): QueryFailure | null {
    log.debug("Entering Query.sourceOf().");
    if (issues.length) {
      const first = issues[0];
      log.debug("Leaving Query.sourceOf(). Shape.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        missing(first) || first.code === 'too_small' ?
          'The document names no source.' : 'A report reads one source.');
    }
    if (!this.catalog.source(String(document.source))) {
      log.debug("Leaving Query.sourceOf(). Unknown.");
      return this.fail('STS-REPORT-0001', 'unknown_source',
        'No such source.');
    }
    log.debug("Leaving Query.sourceOf().");
    return null;
  }

  /**
   * select, groupBy and orderBy, against the catalog. An unknown field is
   * reported before a flag the field does not have.
   *
   * @param document - the document
   * @param issues - what the model found wrong with it
   * @returns a refusal, or null
   */
  private fieldsOf(document: Record<string, unknown>,
                   issues: Issue[]): QueryFailure | null {
    log.debug("Entering Query.fieldsOf().");
    const caps = shapesOf().caps;
    const sourceId = String(document.source);
    const counted = document.aggregate === 'count';
    const select = this.names(under(issues, 'select'), 'select',
      'A query selects at most ' + caps.select + ' fields.');
    if (select) {
      log.debug("Leaving Query.fieldsOf(). Select.");
      return select;
    }
    const selected = this.listOf(document.select);
    if (!selected.length && !counted) {
      log.debug("Leaving Query.fieldsOf(). Nothing selected.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A query with no aggregate names no field.');
    }
    const group = this.names(under(issues, 'groupBy'), 'groupBy',
      'A query groups by at most ' + caps.groupBy + ' fields.');
    if (group) {
      log.debug("Leaving Query.fieldsOf(). Group.");
      return group;
    }
    const groupBy = this.listOf(document.groupBy);
    if (groupBy.length && !counted) {
      log.debug("Leaving Query.fieldsOf(). Group without a count.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'groupBy needs a count.');
    }
    const order = this.orderOf(document.orderBy, under(issues, 'orderBy'));
    if (order.failure) {
      log.debug("Leaving Query.fieldsOf(). Order.");
      return order.failure;
    }
    const unknown = this.unknown(sourceId,
      selected.concat(groupBy, order.fields));
    if (unknown) {
      log.debug("Leaving Query.fieldsOf(). Unknown field.");
      return unknown;
    }
    const flags = this.flags(sourceId, selected, groupBy,
      order.fields, counted);
    if (flags) {
      log.debug("Leaving Query.fieldsOf(). Flag.");
      return flags;
    }
    if (counted) {
      const grouped = this.grouped(selected, groupBy, order.fields);
      if (grouped) {
        log.debug("Leaving Query.fieldsOf(). Not grouped.");
        return grouped;
      }
    }
    log.debug("Leaving Query.fieldsOf().");
    return null;
  }

  // A list of field ids the model has already held to its shape.
  private listOf(value: unknown): string[] {
    log.debug("Entering Query.listOf().");
    const out = Array.isArray(value) ? (value as string[]).slice() : [];
    log.debug("Leaving Query.listOf().");
    return out;
  }

  /**
   * The sentence for what the model found wrong with a list of field ids:
   * the list itself first, then the first entry, then its length.
   *
   * @param issues - the issues under the list's key
   * @param key - `select` or `groupBy`
   * @param tooLong - the sentence for a list over its cap
   * @returns a refusal, or null
   */
  private names(issues: Issue[], key: string,
                tooLong: string): QueryFailure | null {
    log.debug("Entering Query.names().");
    if (!issues.length) {
      log.debug("Leaving Query.names(). Held.");
      return null;
    }
    if (issues.some(function (one: Issue): boolean {
      return one.path.length === 1 && one.code === 'invalid_type';
    })) {
      log.debug("Leaving Query.names(). Not a list.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The ' + key + ' list is not a list.');
    }
    const entry = issues.filter(function (one: Issue): boolean {
      return one.path.length > 1;
    })[0];
    if (entry && entry.params && entry.params.uniqueItems) {
      log.debug("Leaving Query.names(). Twice.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A field is named twice.');
    }
    if (entry) {
      log.debug("Leaving Query.names(). Not a field id.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A ' + key + ' entry is not a field id.');
    }
    log.debug("Leaving Query.names(). Too long.");
    return this.fail('STS-REPORT-0004', 'invalid_query', tooLong);
  }

  private orderOf(value: unknown, issues: Issue[]):
      { fields: string[]; failure: QueryFailure | null } {
    log.debug("Entering Query.orderOf().");
    const self = this;
    const refused = function (description: string):
        { fields: string[]; failure: QueryFailure } {
      return { fields: [],
               failure: self.fail('STS-REPORT-0004', 'invalid_query',
                                  description) };
    };
    if (issues.some(function (one: Issue): boolean {
      return one.path.length === 1 && one.code === 'invalid_type';
    })) {
      log.debug("Leaving Query.orderOf(). Not a list.");
      return refused('The order is not a list.');
    }
    if (issues.some(function (one: Issue): boolean {
      return one.path.length === 1 && one.code === 'too_big';
    })) {
      log.debug("Leaving Query.orderOf(). Too long.");
      return refused('A query orders by at most ' +
        shapesOf().caps.orderBy + ' fields.');
    }
    const entry = issues[0];
    if (entry && entry.path.length === 2) {
      log.debug("Leaving Query.orderOf(). Not an entry.");
      return refused(unrecognised([entry]) ?
        'An order entry is a field and a direction.' :
        'An order entry is not a field and a direction.');
    }
    if (entry && missing(entry)) {
      log.debug("Leaving Query.orderOf(). A key left out.");
      return refused('An order entry is a field and a direction.');
    }
    if (entry && entry.path[2] === 'field') {
      log.debug("Leaving Query.orderOf(). No field.");
      return refused('An order entry names no field.');
    }
    if (entry) {
      log.debug("Leaving Query.orderOf(). Direction.");
      return refused('An order direction is asc or desc.');
    }
    // A field ordered twice is two distinct entries to the model.
    const fields: string[] = [];
    const list = Array.isArray(value) ? value : [];
    for (let i = 0; i < list.length; i++) {
      const field = String(list[i].field);
      if (fields.indexOf(field) >= 0) {
        log.debug("Leaving Query.orderOf(). Twice.");
        return refused('A field is named twice.');
      }
      fields.push(field);
    }
    log.debug("Leaving Query.orderOf().");
    return { fields: fields, failure: null };
  }

  private unknown(sourceId: string, ids: string[]): QueryFailure | null {
    log.debug("Entering Query.unknown().");
    for (let i = 0; i < ids.length; i++) {
      if (!this.catalog.field(sourceId, ids[i])) {
        log.debug("Leaving Query.unknown(). Missing.");
        return this.fail('STS-REPORT-0002', 'unknown_field',
          'The source has no such field.');
      }
    }
    log.debug("Leaving Query.unknown().");
    return null;
  }

  private flags(sourceId: string, select: string[], groupBy: string[],
                order: string[], counted: boolean): QueryFailure | null {
    log.debug("Entering Query.flags().");
    for (let i = 0; i < groupBy.length; i++) {
      const spec = this.catalog.field(sourceId, groupBy[i]);
      if (spec && !spec.group) {
        log.debug("Leaving Query.flags(). Not groupable.");
        return this.fail('STS-REPORT-0003', 'unsupported_operation',
          'That field cannot be grouped.');
      }
    }
    for (let i = 0; i < order.length; i++) {
      const spec = this.catalog.field(sourceId, order[i]);
      if (spec && !spec.sort && !counted) {
        log.debug("Leaving Query.flags(). Not sortable.");
        return this.fail('STS-REPORT-0003', 'unsupported_operation',
          'That field cannot be sorted.');
      }
    }
    log.debug("Leaving Query.flags().");
    return null;
  }

  private grouped(select: string[], groupBy: string[],
                  order: string[]): QueryFailure | null {
    log.debug("Entering Query.grouped().");
    for (let i = 0; i < select.length; i++) {
      if (groupBy.indexOf(select[i]) < 0) {
        log.debug("Leaving Query.grouped(). Selected and not grouped.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'A counted field has to be grouped.');
      }
    }
    if (order.length && !groupBy.length) {
      log.debug("Leaving Query.grouped(). Ordered count of every row.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A count of every row has no order.');
    }
    for (let i = 0; i < order.length; i++) {
      if (groupBy.indexOf(order[i]) < 0) {
        log.debug("Leaving Query.grouped(). Ordered and not grouped.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'A count is ordered by a grouped field.');
      }
    }
    log.debug("Leaving Query.grouped().");
    return null;
  }

  private whereOf(node: unknown, depth: number): QueryFailure | null {
    log.debug("Entering Query.whereOf().");
    if (node == null) {
      log.debug("Leaving Query.whereOf(). None.");
      return null;
    }
    if (depth > WHERE_DEPTH) {
      log.debug("Leaving Query.whereOf(). Too deep.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The filter is nested too deep.');
    }
    // The operator says which of the model's forms the node is meant to be.
    if (!plainObject(node) || typeof node.op !== 'string') {
      log.debug("Leaving Query.whereOf(). Not a node.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The filter is not a tree of operators.');
    }
    const operators = shapesOf().operators;
    if (operators.FilterLogical.indexOf(node.op) >= 0) {
      const both = this.logical(node, depth);
      log.debug("Leaving Query.whereOf().");
      return both;
    }
    if (operators.FilterNot.indexOf(node.op) >= 0) {
      const negated = this.negation(node, depth);
      log.debug("Leaving Query.whereOf().");
      return negated;
    }
    const leaf = this.leaf(node);
    log.debug("Leaving Query.whereOf().");
    return leaf;
  }

  /**
   * What the model found wrong with this node itself, leaving out what it
   * found inside a child filter, which the child's own visit reports.
   *
   * @param form - the model's form the node is meant to be
   * @param node - the node
   * @returns the node's own issues
   */
  private ownIssues(form: string, node: Record<string, unknown>): Issue[] {
    log.debug("Entering Query.ownIssues().");
    const issues = issuesOf(shapesOf().forms[form], node);
    const out = issues.filter(function (one: Issue): boolean {
      if (one.path[0] === 'arg' && node.arg !== undefined) {
        return false;
      }
      return !(one.path[0] === 'args' && one.path.length > 1 &&
               Array.isArray(node.args));
    });
    log.debug("Leaving Query.ownIssues().");
    return out;
  }

  private logical(node: Record<string, unknown>,
                  depth: number): QueryFailure | null {
    log.debug("Entering Query.logical().");
    const issues = this.ownIssues('FilterLogical', node);
    if (issues.length && Array.isArray(node.args) &&
        issues.every(function (one: Issue): boolean {
          return one.path.length === 1 && one.path[0] === 'args';
        })) {
      log.debug("Leaving Query.logical(). Length.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'An and or an or takes between 1 and ' + shapesOf().caps.args +
        ' filters.');
    }
    if (issues.length) {
      log.debug("Leaving Query.logical(). Shape.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'An and or an or takes a list of filters.');
    }
    const args = node.args as unknown[];
    for (let i = 0; i < args.length; i++) {
      const child = this.whereOf(args[i], depth + 1);
      if (child) {
        log.debug("Leaving Query.logical(). Child.");
        return child;
      }
    }
    log.debug("Leaving Query.logical().");
    return null;
  }

  private negation(node: Record<string, unknown>,
                   depth: number): QueryFailure | null {
    log.debug("Entering Query.negation().");
    if (this.ownIssues('FilterNot', node).length) {
      log.debug("Leaving Query.negation(). Shape.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A not takes one filter.');
    }
    const child = this.whereOf(node.arg, depth + 1);
    log.debug("Leaving Query.negation().");
    return child;
  }

  /**
   * A comparison, or isNull: the model's form first, then the field against
   * the catalog, then the operator against the field's type, then the value
   * against that type.
   *
   * @param node - the node
   * @returns a refusal, or null
   */
  private leaf(node: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.leaf().");
    const operators = shapesOf().operators;
    if (operators.FilterIsNull.indexOf(String(node.op)) >= 0) {
      const issues = this.ownIssues('FilterIsNull', node);
      if (issues.some(function (one: Issue): boolean {
        return one.path.length === 0 || missing(one);
      })) {
        log.debug("Leaving Query.leaf(). isNull shape.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'isNull names a field and nothing else.');
      }
      const named = this.leafField(node, issues);
      log.debug("Leaving Query.leaf().");
      return named;
    }
    const keys = ownKeys(node);
    const hasValue = keys.indexOf('value') >= 0;
    const hasParam = keys.indexOf('param') >= 0;
    if (hasValue && hasParam) {
      log.debug("Leaving Query.leaf(). Both.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A filter names a value or a parameter, not both.');
    }
    if (!hasValue && !hasParam) {
      log.debug("Leaving Query.leaf(). Neither.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A filter names a value or a parameter.');
    }
    if (hasParam && (this.parameters == null)) {
      log.debug("Leaving Query.leaf(). Unbound.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A saved parameter was not given.');
    }
    let form = 'FilterParam';
    if (!hasParam) {
      form = node.op === 'in' ? 'FilterIn' : 'FilterValue';
    }
    // The operator and the value are answered after the field, as they
    // always were: an operator the grammar does not have is one the field
    // does not take, and a value is held to the field's type below.
    const issues = this.ownIssues(form, node).filter(
      function (one: Issue): boolean {
        return one.path[0] !== 'op' && one.path[0] !== 'value';
      });
    if (unrecognised(issues)) {
      log.debug("Leaving Query.leaf(). Unknown key.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The filter has a key this service does not read.');
    }
    const named = this.leafField(node, issues);
    if (named) {
      log.debug("Leaving Query.leaf(). Field.");
      return named;
    }
    if (under(issues, 'param').length) {
      log.debug("Leaving Query.leaf(). Param name.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A parameter name is a string of 1 to 64 characters.');
    }
    const typed = this.leafValue(node, String(node.op));
    log.debug("Leaving Query.leaf().");
    return typed;
  }

  private leafField(node: Record<string, unknown>,
                    issues: Issue[]): QueryFailure | null {
    log.debug("Entering Query.leafField().");
    if (under(issues, 'field').length) {
      log.debug("Leaving Query.leafField(). No field.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A filter names no field.');
    }
    const spec = this.boundSource ?
      this.catalog.field(this.boundSource, String(node.field)) : null;
    if (!spec) {
      log.debug("Leaving Query.leafField(). Unknown.");
      return this.fail('STS-REPORT-0002', 'unknown_field',
        'The source has no such field.');
    }
    if (!spec.filter) {
      log.debug("Leaving Query.leafField(). Not filterable.");
      return this.fail('STS-REPORT-0003', 'unsupported_operation',
        'That field cannot be filtered.');
    }
    const op = String(node.op);
    if (op !== 'isNull' &&
        Catalog.operatorsFor(spec.type).indexOf(op) < 0) {
      log.debug("Leaving Query.leafField(). Operator.");
      return this.fail('STS-REPORT-0003', 'unsupported_operation',
        'That operator does not apply to the field.');
    }
    log.debug("Leaving Query.leafField().");
    return null;
  }

  /**
   * The value a comparison is made with — its own, or the saved parameter's
   * — held to the model's form for the operator, then to the field's type.
   *
   * @param node - a comparison whose field is the catalog's
   * @param op - its operator
   * @returns a refusal, or null
   */
  private leafValue(node: Record<string, unknown>,
                    op: string): QueryFailure | null {
    log.debug("Entering Query.leafValue().");
    const spec = this.catalog.field(this.boundSource, String(node.field));
    let value = node.value;
    if (Object.prototype.hasOwnProperty.call(node, 'param')) {
      const bag = this.parameters || {};
      if (!Object.prototype.hasOwnProperty.call(bag, node.param as string)) {
        log.debug("Leaving Query.leafValue(). Missing param.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'A parameter is missing.');
      }
      value = bag[String(node.param)];
    }
    if (op === 'in') {
      const listed = issuesOf(shapesOf().forms.FilterIn,
        { op: op, field: node.field, value: value });
      if (listed.some(function (one: Issue): boolean {
        return one.path.length === 1 && one.path[0] === 'value';
      })) {
        const caps = shapesOf().caps;
        log.debug("Leaving Query.leafValue(). in.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'in takes between ' + caps.inMin + ' and ' + caps.inMax +
          ' values.');
      }
    }
    const typed = this.typed(spec ? spec.type : '', op, value);
    log.debug("Leaving Query.leafValue().");
    return typed;
  }

  // The value against the field's type; `in`'s list is the model's already.
  private typed(type: string, op: string, value: unknown):
      QueryFailure | null {
    log.debug("Entering Query.typed().");
    if (op === 'in') {
      const list = value as unknown[];
      for (let i = 0; i < list.length; i++) {
        const one = this.oneValue(type, list[i]);
        if (one) {
          log.debug("Leaving Query.typed(). Element.");
          return one;
        }
      }
      log.debug("Leaving Query.typed().");
      return null;
    }
    const one = this.oneValue(type, value);
    log.debug("Leaving Query.typed().");
    return one;
  }

  private oneValue(type: string, value: unknown): QueryFailure | null {
    log.debug("Entering Query.oneValue().");
    if (type === 'string') {
      if (typeof value !== 'string') {
        log.debug("Leaving Query.oneValue(). String.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'The value is not a string.');
      }
      log.debug("Leaving Query.oneValue().");
      return null;
    }
    if (type === 'number') {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        log.debug("Leaving Query.oneValue(). Number.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'The value is not a finite number.');
      }
      log.debug("Leaving Query.oneValue().");
      return null;
    }
    if (type === 'boolean') {
      if (typeof value !== 'boolean') {
        log.debug("Leaving Query.oneValue(). Boolean.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'The value is not a boolean.');
      }
      log.debug("Leaving Query.oneValue().");
      return null;
    }
    if (type === 'timestamp') {
      if (typeof value === 'number' && Number.isFinite(value)) {
        log.debug("Leaving Query.oneValue(). Timestamp number.");
        return null;
      }
      if (typeof value === 'string' && value.length <= STAMP_CAP &&
          value.length > 0 && Number.isFinite(Date.parse(value))) {
        log.debug("Leaving Query.oneValue(). Timestamp string.");
        return null;
      }
      log.debug("Leaving Query.oneValue(). Timestamp.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The value is not a timestamp.');
    }
    log.debug("Leaving Query.oneValue(). No type.");
    return this.fail('STS-REPORT-0004', 'invalid_query',
      'The value is not usable.');
  }

  /**
   * The size cap, after every catalog and shape check. PDF over its row cap
   * is the same refusal and the explanation names CSV, because that is the
   * format that can carry the rows.
   *
   * @param document - a document that has already passed shape
   * @returns a refusal, or null
   */
  private sizeOf(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.sizeOf().");
    const src = this.catalog.source(String(document.source));
    const limit = Object.prototype.hasOwnProperty.call(document, 'limit') ?
      Number(document.limit) : this.limits.syncMaxRows();
    const format = Object.prototype.hasOwnProperty.call(document, 'format') ?
      String(document.format) : 'json';
    const mode = Object.prototype.hasOwnProperty.call(document, 'mode') ?
      String(document.mode) : 'auto';
    if (format === 'pdf' && limit > this.limits.pdfMaxRows()) {
      log.debug("Leaving Query.sizeOf(). PDF rows.");
      return this.fail('STS-REPORT-0005', 'result_too_large',
        'A PDF cannot hold this many rows. Ask for CSV.');
    }
    if (mode === 'sync' &&
        (limit > this.limits.syncMaxRows() || !src || !src.bounded)) {
      log.debug("Leaving Query.sizeOf(). Sync.");
      return this.fail('STS-REPORT-0005', 'result_too_large',
        limit > this.limits.syncMaxRows() ?
          'The limit is above the synchronous cap.' :
          'This source cannot be read synchronously.');
    }
    if ((mode === 'async' || mode === 'auto') &&
        limit > this.limits.asyncMaxRows()) {
      log.debug("Leaving Query.sizeOf(). Async.");
      return this.fail('STS-REPORT-0005', 'result_too_large',
        'The limit is above the asynchronous cap.');
    }
    if (mode === 'auto' && (!src || !src.bounded ||
        limit > this.limits.syncMaxRows()) &&
        limit > this.limits.asyncMaxRows()) {
      log.debug("Leaving Query.sizeOf(). Auto.");
      return this.fail('STS-REPORT-0005', 'result_too_large',
        'The limit is above the asynchronous cap.');
    }
    log.debug("Leaving Query.sizeOf().");
    return null;
  }

  /**
   * The plan. Called only after `document` returned null, so every check
   * above has passed. The filter is copied with parameters replaced by the
   * values they named.
   *
   * @param document - the valid document
   * @returns the plan
   */
  private planOf(document: Record<string, unknown>): QueryResult {
    log.debug("Entering Query.planOf().");
    const sourceId = String(document.source);
    const src = this.catalog.source(sourceId);
    const select = Array.isArray(document.select) ?
      (document.select as string[]).slice() : [];
    const groupBy = Array.isArray(document.groupBy) ?
      (document.groupBy as string[]).slice() : [];
    const counted = document.aggregate === 'count';
    const limit = Object.prototype.hasOwnProperty.call(document, 'limit') ?
      Number(document.limit) : this.limits.syncMaxRows();
    const format = typeof document.format === 'string' ?
      document.format : 'json';
    const mode = typeof document.mode === 'string' ? document.mode : 'auto';
    let execution = 'async';
    if (mode === 'sync') {
      execution = 'sync';
    } else if (mode === 'auto' && src && src.bounded &&
               limit <= this.limits.syncMaxRows()) {
      execution = 'sync';
    }
    const fields = counted ?
      (select.length ? select.slice() : groupBy.slice()).concat(['count']) :
      select.slice();
    const plan: QueryPlan = {
      source: sourceId,
      select: select,
      where: this.copyWhere(document.where),
      orderBy: this.copyOrder(document.orderBy),
      limit: limit,
      format: format,
      mode: mode,
      locale: typeof document.locale === 'string' ? document.locale : null,
      aggregate: counted ? 'count' : null,
      groupBy: groupBy,
      execution: execution,
      fields: fields
    };
    log.debug("Leaving Query.planOf().");
    return { ok: true, plan: plan };
  }

  private copyOrder(value: unknown): Array<{ field: string; dir: string }> {
    log.debug("Entering Query.copyOrder().");
    const out: Array<{ field: string; dir: string }> = [];
    const list = Array.isArray(value) ? value : [];
    for (let i = 0; i < list.length; i++) {
      const item = list[i] as Record<string, unknown>;
      out.push({ field: String(item.field), dir: String(item.dir) });
    }
    log.debug("Leaving Query.copyOrder().");
    return out;
  }

  private copyWhere(node: unknown): any {
    log.debug("Entering Query.copyWhere().");
    if (node == null) {
      log.debug("Leaving Query.copyWhere(). None.");
      return null;
    }
    const src = node as Record<string, unknown>;
    if (src.op === 'and' || src.op === 'or') {
      const args = (src.args as unknown[]).map((child) =>
        this.copyWhere(child));
      log.debug("Leaving Query.copyWhere(). Logical.");
      return { op: src.op, args: args };
    }
    if (src.op === 'not') {
      const arg = this.copyWhere(src.arg);
      log.debug("Leaving Query.copyWhere(). Not.");
      return { op: 'not', arg: arg };
    }
    if (src.op === 'isNull') {
      log.debug("Leaving Query.copyWhere(). isNull.");
      return { op: 'isNull', field: src.field };
    }
    let value = src.value;
    if (Object.prototype.hasOwnProperty.call(src, 'param')) {
      const bag = this.parameters || {};
      value = bag[String(src.param)];
    }
    if (src.op === 'in' && Array.isArray(value)) {
      log.debug("Leaving Query.copyWhere(). in.");
      return { op: 'in', field: src.field, value: value.slice() };
    }
    log.debug("Leaving Query.copyWhere().");
    return { op: src.op, field: src.field, value: value };
  }
}

export = Query;
