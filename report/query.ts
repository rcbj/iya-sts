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
// `mode: auto` runs synchronously when the source is bounded and the limit
// fits the synchronous cap, and asynchronously otherwise. A source a test
// marks unbounded cannot run synchronously at any limit.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import errorCodes = require('../common/error_codes');
import Catalog = require('./catalog');
import Limits = require('./limits');

const log = bunyan.createLogger({ name: 'sts-report-query' });

const DOCUMENT_KEYS = ['source', 'select', 'where', 'orderBy', 'limit',
  'format', 'mode', 'locale', 'aggregate', 'groupBy'];
const FORMATS = ['json', 'csv', 'pdf'];
const MODES = ['sync', 'async', 'auto'];
const DIRS = ['asc', 'desc'];
const LOCALE = /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/;
const WHERE_DEPTH = 8;
const SELECT_CAP = 64;
const ARGS_CAP = 16;
const IN_CAP = 50;
const ORDER_CAP = 8;
const GROUP_CAP = 8;
const STAMP_CAP = 40;

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
    const keys = ownKeys(document);
    if (keys.indexOf('query') >= 0 || keys.indexOf('sources') >= 0) {
      log.debug("Leaving Query.document(). A statement or a second source.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A report is a document, not a statement.');
    }
    for (let i = 0; i < keys.length; i++) {
      if (DOCUMENT_KEYS.indexOf(keys[i]) < 0) {
        log.debug("Leaving Query.document(). Unknown key.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'The document has a key this service does not read.');
      }
    }
    const shaped = this.shape(document);
    log.debug("Leaving Query.document().");
    return shaped;
  }

  /**
   * Source, fields, filter, order, limit and the execution decision.
   * Fields are resolved before the size cap.
   *
   * @param document - a plain document whose keys are already known
   * @returns a refusal, or null
   */
  private shape(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.shape().");
    const source = this.sourceOf(document);
    if (source) {
      log.debug("Leaving Query.shape(). Source.");
      return source;
    }
    this.boundSource = String(document.source);
    const format = this.formatOf(document);
    if (format) {
      log.debug("Leaving Query.shape(). Format.");
      return format;
    }
    const mode = this.modeOf(document);
    if (mode) {
      log.debug("Leaving Query.shape(). Mode.");
      return mode;
    }
    const locale = this.localeOf(document);
    if (locale) {
      log.debug("Leaving Query.shape(). Locale.");
      return locale;
    }
    const aggregate = this.aggregateOf(document);
    if (aggregate) {
      log.debug("Leaving Query.shape(). Aggregate.");
      return aggregate;
    }
    const fields = this.fieldsOf(document);
    if (fields) {
      log.debug("Leaving Query.shape(). Fields.");
      return fields;
    }
    const where = this.whereOf(document.where, 1);
    if (where) {
      log.debug("Leaving Query.shape(). Filter.");
      return where;
    }
    const limit = this.limitOf(document);
    if (limit) {
      log.debug("Leaving Query.shape(). Limit.");
      return limit;
    }
    const size = this.sizeOf(document);
    log.debug("Leaving Query.shape().");
    return size;
  }

  private sourceOf(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.sourceOf().");
    if (!Object.prototype.hasOwnProperty.call(document, 'source') ||
        document.source === '') {
      log.debug("Leaving Query.sourceOf(). Missing.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The document names no source.');
    }
    if (typeof document.source !== 'string') {
      log.debug("Leaving Query.sourceOf(). Not one source.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A report reads one source.');
    }
    if (!this.catalog.source(document.source)) {
      log.debug("Leaving Query.sourceOf(). Unknown.");
      return this.fail('STS-REPORT-0001', 'unknown_source',
        'No such source.');
    }
    log.debug("Leaving Query.sourceOf().");
    return null;
  }

  private formatOf(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.formatOf().");
    if (!Object.prototype.hasOwnProperty.call(document, 'format')) {
      log.debug("Leaving Query.formatOf(). Default.");
      return null;
    }
    if (FORMATS.indexOf(String(document.format)) < 0 ||
        typeof document.format !== 'string') {
      log.debug("Leaving Query.formatOf(). Unsupported.");
      return this.fail('STS-REPORT-0003', 'unsupported_format',
        'The format is not json, csv or pdf.');
    }
    log.debug("Leaving Query.formatOf().");
    return null;
  }

  private modeOf(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.modeOf().");
    if (!Object.prototype.hasOwnProperty.call(document, 'mode')) {
      log.debug("Leaving Query.modeOf(). Default.");
      return null;
    }
    if (MODES.indexOf(String(document.mode)) < 0 ||
        typeof document.mode !== 'string') {
      log.debug("Leaving Query.modeOf(). Unsupported.");
      return this.fail('STS-REPORT-0003', 'unsupported_operation',
        'The mode is not sync, async or auto.');
    }
    log.debug("Leaving Query.modeOf().");
    return null;
  }

  private localeOf(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.localeOf().");
    if (!Object.prototype.hasOwnProperty.call(document, 'locale') ||
        document.locale == null) {
      log.debug("Leaving Query.localeOf(). None.");
      return null;
    }
    const tag = String(document.locale);
    if (typeof document.locale !== 'string' || tag.length > 35 ||
        !LOCALE.test(tag)) {
      log.debug("Leaving Query.localeOf(). Not a tag.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The locale is not a language tag.');
    }
    log.debug("Leaving Query.localeOf().");
    return null;
  }

  private aggregateOf(document: Record<string, unknown>):
      QueryFailure | null {
    log.debug("Entering Query.aggregateOf().");
    if (!Object.prototype.hasOwnProperty.call(document, 'aggregate') ||
        document.aggregate == null) {
      log.debug("Leaving Query.aggregateOf(). None.");
      return null;
    }
    if (document.aggregate !== 'count') {
      log.debug("Leaving Query.aggregateOf(). Unsupported.");
      return this.fail('STS-REPORT-0003', 'unsupported_operation',
        'The only aggregate is count.');
    }
    log.debug("Leaving Query.aggregateOf().");
    return null;
  }

  /**
   * select, groupBy and orderBy, against the catalog. An unknown field is
   * reported before a flag the field does not have.
   *
   * @param document - the document
   * @returns a refusal, or null
   */
  private fieldsOf(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.fieldsOf().");
    const sourceId = String(document.source);
    const counted = document.aggregate === 'count';
    const select = this.names(document.select, 'select', true);
    if (select.failure) {
      log.debug("Leaving Query.fieldsOf(). Select.");
      return select.failure;
    }
    if (select.names.length > SELECT_CAP) {
      log.debug("Leaving Query.fieldsOf(). Too many fields.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A query selects at most ' + SELECT_CAP + ' fields.');
    }
    if (!select.names.length && !counted) {
      log.debug("Leaving Query.fieldsOf(). Nothing selected.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A query with no aggregate names no field.');
    }
    const groupBy = this.names(document.groupBy, 'groupBy', false);
    if (groupBy.failure) {
      log.debug("Leaving Query.fieldsOf(). Group.");
      return groupBy.failure;
    }
    if (groupBy.names.length && !counted) {
      log.debug("Leaving Query.fieldsOf(). Group without a count.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'groupBy needs a count.');
    }
    if (groupBy.names.length > GROUP_CAP) {
      log.debug("Leaving Query.fieldsOf(). Too many groups.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A query groups by at most ' + GROUP_CAP + ' fields.');
    }
    const order = this.orderOf(document.orderBy);
    if (order.failure) {
      log.debug("Leaving Query.fieldsOf(). Order.");
      return order.failure;
    }
    const unknown = this.unknown(sourceId,
      select.names.concat(groupBy.names, order.fields));
    if (unknown) {
      log.debug("Leaving Query.fieldsOf(). Unknown field.");
      return unknown;
    }
    const flags = this.flags(sourceId, select.names, groupBy.names,
      order.fields, counted);
    if (flags) {
      log.debug("Leaving Query.fieldsOf(). Flag.");
      return flags;
    }
    if (counted) {
      const grouped = this.grouped(select.names, groupBy.names, order.fields);
      if (grouped) {
        log.debug("Leaving Query.fieldsOf(). Not grouped.");
        return grouped;
      }
    }
    log.debug("Leaving Query.fieldsOf().");
    return null;
  }

  private names(value: unknown, key: string, required: boolean):
      { names: string[]; failure: QueryFailure | null } {
    log.debug("Entering Query.names().");
    if (value == null) {
      log.debug("Leaving Query.names(). Omitted. " + required);
      return { names: [], failure: null };
    }
    if (!Array.isArray(value)) {
      log.debug("Leaving Query.names(). Not a list.");
      return { names: [], failure: this.fail('STS-REPORT-0004',
        'invalid_query', 'The ' + key + ' list is not a list.') };
    }
    const names: string[] = [];
    for (let i = 0; i < value.length; i++) {
      if (typeof value[i] !== 'string' || !value[i]) {
        log.debug("Leaving Query.names(). Not a field id.");
        return { names: [], failure: this.fail('STS-REPORT-0004',
          'invalid_query', 'A ' + key + ' entry is not a field id.') };
      }
      if (names.indexOf(value[i]) >= 0) {
        log.debug("Leaving Query.names(). Twice.");
        return { names: [], failure: this.fail('STS-REPORT-0004',
          'invalid_query', 'A field is named twice.') };
      }
      names.push(value[i]);
    }
    log.debug("Leaving Query.names().");
    return { names: names, failure: null };
  }

  private orderOf(value: unknown):
      { fields: string[]; failure: QueryFailure | null } {
    log.debug("Entering Query.orderOf().");
    if (value == null) {
      log.debug("Leaving Query.orderOf(). None.");
      return { fields: [], failure: null };
    }
    if (!Array.isArray(value)) {
      log.debug("Leaving Query.orderOf(). Not a list.");
      return { fields: [], failure: this.fail('STS-REPORT-0004',
        'invalid_query', 'The order is not a list.') };
    }
    if (value.length > ORDER_CAP) {
      log.debug("Leaving Query.orderOf(). Too long.");
      return { fields: [], failure: this.fail('STS-REPORT-0004',
        'invalid_query',
        'A query orders by at most ' + ORDER_CAP + ' fields.') };
    }
    const fields: string[] = [];
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      if (!plainObject(item)) {
        log.debug("Leaving Query.orderOf(). Not an entry.");
        return { fields: [], failure: this.fail('STS-REPORT-0004',
          'invalid_query',
          'An order entry is not a field and a direction.') };
      }
      const keys = ownKeys(item);
      if (keys.length !== 2 || keys.indexOf('field') < 0 ||
          keys.indexOf('dir') < 0) {
        log.debug("Leaving Query.orderOf(). Extra key.");
        return { fields: [], failure: this.fail('STS-REPORT-0004',
          'invalid_query', 'An order entry is a field and a direction.') };
      }
      if (typeof item.field !== 'string' || !item.field) {
        log.debug("Leaving Query.orderOf(). No field.");
        return { fields: [], failure: this.fail('STS-REPORT-0004',
          'invalid_query', 'An order entry names no field.') };
      }
      if (DIRS.indexOf(String(item.dir)) < 0) {
        log.debug("Leaving Query.orderOf(). Direction.");
        return { fields: [], failure: this.fail('STS-REPORT-0004',
          'invalid_query', 'An order direction is asc or desc.') };
      }
      if (fields.indexOf(String(item.field)) >= 0) {
        log.debug("Leaving Query.orderOf(). Twice.");
        return { fields: [], failure: this.fail('STS-REPORT-0004',
          'invalid_query', 'A field is named twice.') };
      }
      fields.push(String(item.field));
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
    if (!plainObject(node) || typeof node.op !== 'string') {
      log.debug("Leaving Query.whereOf(). Not a node.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The filter is not a tree of operators.');
    }
    if (node.op === 'and' || node.op === 'or') {
      const both = this.logical(node, depth);
      log.debug("Leaving Query.whereOf().");
      return both;
    }
    if (node.op === 'not') {
      const negated = this.negation(node, depth);
      log.debug("Leaving Query.whereOf().");
      return negated;
    }
    const leaf = this.leaf(node);
    log.debug("Leaving Query.whereOf().");
    return leaf;
  }

  private logical(node: Record<string, unknown>,
                  depth: number): QueryFailure | null {
    log.debug("Entering Query.logical().");
    const keys = ownKeys(node);
    if (keys.length !== 2 || keys.indexOf('op') < 0 ||
        keys.indexOf('args') < 0 || !Array.isArray(node.args)) {
      log.debug("Leaving Query.logical(). Shape.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'An and or an or takes a list of filters.');
    }
    const args = node.args as unknown[];
    if (args.length < 1 || args.length > ARGS_CAP) {
      log.debug("Leaving Query.logical(). Length.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'An and or an or takes between 1 and ' + ARGS_CAP + ' filters.');
    }
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
    const keys = ownKeys(node);
    if (keys.length !== 2 || keys.indexOf('op') < 0 ||
        keys.indexOf('arg') < 0) {
      log.debug("Leaving Query.negation(). Shape.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A not takes one filter.');
    }
    const child = this.whereOf(node.arg, depth + 1);
    log.debug("Leaving Query.negation().");
    return child;
  }

  private leaf(node: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.leaf().");
    const op = String(node.op);
    const keys = ownKeys(node);
    if (op === 'isNull') {
      if (keys.length !== 2 || keys.indexOf('field') < 0) {
        log.debug("Leaving Query.leaf(). isNull shape.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'isNull names a field and nothing else.');
      }
      const named = this.leafField(node);
      log.debug("Leaving Query.leaf().");
      return named;
    }
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
    const allowed = op === 'in' ?
      ['op', 'field', hasParam ? 'param' : 'value'] :
      ['op', 'field', hasParam ? 'param' : 'value'];
    if (keys.length !== allowed.length) {
      log.debug("Leaving Query.leaf(). Extra.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'The filter has a key this service does not read.');
    }
    for (let i = 0; i < keys.length; i++) {
      if (allowed.indexOf(keys[i]) < 0) {
        log.debug("Leaving Query.leaf(). Unknown key.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'The filter has a key this service does not read.');
      }
    }
    const named = this.leafField(node);
    if (named) {
      log.debug("Leaving Query.leaf(). Field.");
      return named;
    }
    const typed = this.leafValue(node, op);
    log.debug("Leaving Query.leaf().");
    return typed;
  }

  private leafField(node: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.leafField().");
    if (typeof node.field !== 'string' || !node.field) {
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

  private leafValue(node: Record<string, unknown>,
                    op: string): QueryFailure | null {
    log.debug("Entering Query.leafValue().");
    const spec = this.catalog.field(this.boundSource, String(node.field));
    let value = node.value;
    if (Object.prototype.hasOwnProperty.call(node, 'param')) {
      if (typeof node.param !== 'string' || !node.param) {
        log.debug("Leaving Query.leafValue(). Param name.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'A parameter name is a string.');
      }
      const bag = this.parameters || {};
      if (!Object.prototype.hasOwnProperty.call(bag, node.param)) {
        log.debug("Leaving Query.leafValue(). Missing param.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'A parameter is missing.');
      }
      value = bag[String(node.param)];
    }
    const typed = this.typed(spec ? spec.type : '', op, value);
    log.debug("Leaving Query.leafValue().");
    return typed;
  }

  private typed(type: string, op: string, value: unknown):
      QueryFailure | null {
    log.debug("Entering Query.typed().");
    if (op === 'in') {
      if (!Array.isArray(value) || value.length < 1 ||
          value.length > IN_CAP) {
        log.debug("Leaving Query.typed(). in.");
        return this.fail('STS-REPORT-0004', 'invalid_query',
          'in takes between 1 and ' + IN_CAP + ' values.');
      }
      for (let i = 0; i < value.length; i++) {
        const one = this.oneValue(type, value[i]);
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

  private limitOf(document: Record<string, unknown>): QueryFailure | null {
    log.debug("Entering Query.limitOf().");
    if (!Object.prototype.hasOwnProperty.call(document, 'limit')) {
      log.debug("Leaving Query.limitOf(). Default.");
      return null;
    }
    const limit = document.limit;
    if (typeof limit !== 'number' || !Number.isFinite(limit) ||
        Math.floor(limit) !== limit || limit < 1) {
      log.debug("Leaving Query.limitOf(). Not a positive integer.");
      return this.fail('STS-REPORT-0004', 'invalid_query',
        'A limit is a positive whole number.');
    }
    log.debug("Leaving Query.limitOf().");
    return null;
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
