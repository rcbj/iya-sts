// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: catalog.ts
//
// ---------------------------------------------------------------------------
// THE REPORT CATALOG (#956).
//
// A report names a source and fields from this catalog. It never names a
// table, and it never names a credential: the credential attribute ids are
// absent, so a query that asks for one fails as an unknown field rather than
// as a value this service then has to remember not to print. The field set
// is closed. A reader who wants a column that is not here is asking for a
// catalog change, not a query.
//
// `bounded` is the adapter's promise that a limit can be honoured without
// holding the population: an ordered read keeps a heap of that size, and a
// count keeps the groups and discards the rows. A source a test builds with
// `bounded: false` cannot be run synchronously.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');

const log = bunyan.createLogger({ name: 'sts-report-catalog' });

// Credential attribute ids. None of them is a field of any source. Selecting
// one is `unknown_field` because the catalog does not have it, which is the
// property the test holds: the id is absent, not specially rejected.
const CREDENTIALS = ['userPassword', 'unicodePwd', 'ntPassword', 'krb5Key',
  'totpSecret', 'webauthnCredential', 'backupCodes', 'mailSecret',
  'clientSecret'];

// Low-cardinality enumerations a count may group by. A username is not one
// of them, and neither is a member list.
const GROUPABLE = ['status', 'enabled', 'type', 'protocol', 'category',
  'action', 'outcome', 'format', 'family', 'application'];

// Scalars a filter may name and a sort may not. `members` is not in this
// list because it cannot be filtered either.
const UNSORTABLE = ['entryUuid', 'memberOf', 'members'];

const OPERATORS = {
  string: ['eq', 'ne', 'contains', 'startsWith', 'in', 'isNull'],
  number: ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'isNull'],
  timestamp: ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'isNull'],
  boolean: ['eq', 'ne', 'isNull']
};

interface FieldSpec {
  id: string;
  type: string;
  filter: boolean;
  sort: boolean;
  group: boolean;
}

interface SourceSpec {
  id: string;
  bounded: boolean;
  retention: string;
  fields: FieldSpec[];
}

function field(id: string, type: string): FieldSpec {
  log.debug("Entering field().");
  const spec = {
    id: id,
    type: type,
    filter: id !== 'members',
    sort: UNSORTABLE.indexOf(id) < 0,
    group: GROUPABLE.indexOf(id) >= 0
  };
  log.debug("Leaving field().");
  return spec;
}

function source(id: string, retention: string,
                fields: FieldSpec[]): SourceSpec {
  log.debug("Entering source().");
  const spec = {
    id: id,
    bounded: true,
    retention: retention,
    fields: fields
  };
  log.debug("Leaving source().");
  return spec;
}

function standardSources(): SourceSpec[] {
  log.debug("Entering standardSources().");
  const sources = [
    source('users',
      'The directory as it is now. Not a history of accounts.',
      [field('username', 'string'), field('status', 'string'),
       field('createdAt', 'timestamp'), field('modifiedAt', 'timestamp'),
       field('entryUuid', 'string'), field('mail', 'string'),
       field('displayName', 'string'), field('memberOf', 'string')]),
    source('groups',
      'The directory as it is now. member lists are selected, not filtered.',
      [field('name', 'string'), field('description', 'string'),
       field('memberCount', 'number'), field('members', 'string')]),
    source('applications',
      'The realm\'s configured applications, as they are now.',
      [field('id', 'string'), field('name', 'string'),
       field('status', 'string'), field('enabled', 'boolean')]),
    source('federation',
      'The realm\'s configured federation relationships, as they are now.',
      [field('id', 'string'), field('partner', 'string'),
       field('protocol', 'string'), field('enabled', 'boolean')]),
    source('authMechanisms',
      'The realm\'s authentication policy, as it is now.',
      [field('id', 'string'), field('type', 'string'),
       field('enabled', 'boolean'), field('application', 'string')]),
    source('auditEvents',
      'The audit ring still held in this process, newest first, capped by ' +
      'audit.maxEvents (5000 unless an operator set another cap). Not a ' +
      'warehouse of sign-ins.',
      [field('timestamp', 'timestamp'), field('category', 'string'),
       field('action', 'string'), field('outcome', 'string'),
       field('actor', 'string')]),
    source('serviceMetrics',
      'A live snapshot of the service counters. Not a time series.',
      [field('name', 'string'), field('value', 'number'),
       field('family', 'string')]),
    source('reportJobs',
      'Report jobs this realm still holds. Artifacts age out on their own ' +
      'retention; the job row ages out later.',
      [field('id', 'string'), field('status', 'string'),
       field('format', 'string'), field('submittedAt', 'timestamp'),
       field('completedAt', 'timestamp'), field('byteSize', 'number')])
  ];
  log.debug("Leaving standardSources().");
  return sources;
}

/**
 * The closed set of sources a report may name, and the fields of each.
 */
class Catalog {
  sources: SourceSpec[];

  /**
   * @param sources - a test's own sources; omitted, the eight standard ones
   */
  constructor(sources?: SourceSpec[]) {
    log.debug("Entering Catalog().");
    this.sources = sources ? sources.slice() : standardSources();
    log.debug("Leaving Catalog().");
  }

  /**
   * The credential attribute ids, which no source registers.
   *
   * @returns the ids
   */
  static credentialIds(): string[] {
    log.debug("Entering Catalog.credentialIds().");
    log.debug("Leaving Catalog.credentialIds().");
    return CREDENTIALS.slice();
  }

  /**
   * The comparison operators a field type allows. Logical operators are
   * not among them.
   *
   * @param type - string, number, boolean or timestamp
   * @returns the operator names, or an empty list
   */
  static operatorsFor(type: string): string[] {
    log.debug("Entering Catalog.operatorsFor().");
    const list = OPERATORS[type] || [];
    log.debug("Leaving Catalog.operatorsFor().");
    return list.slice();
  }

  /**
   * Every source, in catalog order.
   *
   * @returns the sources
   */
  list(): SourceSpec[] {
    log.debug("Entering Catalog.list().");
    log.debug("Leaving Catalog.list().");
    return this.sources.slice();
  }

  /**
   * One source by its id.
   *
   * @param id - the source name
   * @returns the source, or null
   */
  source(id: string): SourceSpec | null {
    log.debug("Entering Catalog.source().");
    let found = null;
    for (let i = 0; i < this.sources.length; i++) {
      if (this.sources[i].id === id) {
        found = this.sources[i];
      }
    }
    log.debug("Leaving Catalog.source().");
    return found;
  }

  /**
   * One field of a source.
   *
   * @param sourceId - the source name
   * @param fieldId - the field id
   * @returns the field, or null
   */
  field(sourceId: string, fieldId: string): FieldSpec | null {
    log.debug("Entering Catalog.field().");
    const src = this.source(sourceId);
    let found = null;
    const fields = src ? src.fields : [];
    for (let i = 0; i < fields.length; i++) {
      if (fields[i].id === fieldId) {
        found = fields[i];
      }
    }
    log.debug("Leaving Catalog.field().");
    return found;
  }
}

export = Catalog;
