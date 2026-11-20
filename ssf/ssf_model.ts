// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: ssf/ssf_model.ts
//
// ---------------------------------------------------------------------------
// THE SHARED SIGNALS MODEL, AS THE FAMILY READS IT (#1579).
//
// `models/ssf/ssf.tsp` and `ssf_events.tsp` are the source of every event
// type this service knows and its payload members, every RFC 9493 subject
// format and its closed member set, SSF's complex subject, the delivery
// methods, the stream statuses and the credential types, the members of
// every document the transmitter answers and the receivers send, the
// Security Event Token's own claims, and the `err` values. The image build
// writes `models/generated/ssf.json` and this reads it:
//
//   * the TABLES — `events()`, `common()`, `formats()`, `complex()`,
//     `list()`, `deliveries()` — that `ssf_events.js`, `ssf_subjects.js` and
//     `ssf_streams.ts` build their rows from, in the model's order;
//   * `supplied(by)`: which stream configuration members the transmitter
//     and the receiver supply (SSF 1.0 section 8.1.1);
//   * `undeclared(id, value)` and `unknownError(code)`, the HOLDING: what a
//     document or the error list does not allow. The callers record what
//     they find under STS-SSF-0159 to 0162 and send the document unchanged,
//     because the model describes the wire and does not reshape it.
//
// A LEAF: it requires `common/model_tables` and bunyan, so the two
// libraries that read it (`ssf_events.js`, `ssf_subjects.js`) stay unable
// to join a cycle.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('../common/model_tables');

const log = bunyan.createLogger({
  name: 'sts-ssf-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL: Json = ModelTables.file('ssf.json');

const DOCUMENTS = new Map<string, Json>();

MODEL.members.forEach(function (set: Json) {
  DOCUMENTS.set(set.id, set);
});

const ERROR_CODES = new Set<string>(MODEL.errors.map(function (one: Json) {
  return one.code;
}));

/**
 * The Shared Signals model: the tables the family builds its rows from, and
 * the holding of what it answers and sends.
 */
class SsfModel {
  /**
   * Every event type, in catalogue order: `{ uri, family, name, subject,
   * subjectFormats?, deprecated?, members, what, cite }`, each member
   * `{ name, required, type, values?, what, cite? }`.
   *
   * @returns the rows; a copy
   */
  static events(): Json[] {
    log.debug("Entering SsfModel.events().");
    log.debug("Leaving SsfModel.events().");
    return JSON.parse(JSON.stringify(MODEL.events));
  }

  /**
   * The members several event types share (`caep`: CAEP 1.0 section 2's
   * four; `risc`: the three RISC gives the one type that has them).
   *
   * @param id - `caep` or `risc`
   * @returns the members; a copy
   */
  static common(id: string): Json[] {
    log.debug("Entering SsfModel.common(). " + id);
    const set = MODEL.commons.find(function (one: Json) {
      return one.id === id;
    });
    if (!set) {
      log.debug("Leaving SsfModel.common(). No such set.");
      throw new TypeError('The Shared Signals model has no common members ' +
                          id);
    }
    log.debug("Leaving SsfModel.common().");
    return JSON.parse(JSON.stringify(set.members));
  }

  /**
   * Every subject identifier format: `{ format, person, what, example,
   * cite, members }`, `example` as JSON text, each member `{ name,
   * required, check, types }`.
   *
   * @returns the rows; a copy
   */
  static formats(): Json[] {
    log.debug("Entering SsfModel.formats().");
    log.debug("Leaving SsfModel.formats().");
    return JSON.parse(JSON.stringify(MODEL.formats));
  }

  /**
   * SSF's complex subject: `{ format, memberName, cite, members }`.
   *
   * @returns a copy
   */
  static complex(): Json {
    log.debug("Entering SsfModel.complex().");
    log.debug("Leaving SsfModel.complex().");
    return JSON.parse(JSON.stringify(MODEL.complex));
  }

  /**
   * One list's values: `credential-types` or `stream-statuses`.
   *
   * @param id - the list's id
   * @returns the values; a copy
   */
  static list(id: string): string[] {
    log.debug("Entering SsfModel.list(). " + id);
    const list = MODEL.lists.find(function (one: Json) {
      return one.id === id;
    });
    if (!list) {
      log.debug("Leaving SsfModel.list(). No such list.");
      throw new TypeError('The Shared Signals model has no list ' + id);
    }
    log.debug("Leaving SsfModel.list().");
    return list.values.slice(0);
  }

  /**
   * The delivery methods: `{ method, name, what, cite }`.
   *
   * @returns the rows; a copy
   */
  static deliveries(): Json[] {
    log.debug("Entering SsfModel.deliveries().");
    log.debug("Leaving SsfModel.deliveries().");
    return JSON.parse(JSON.stringify(MODEL.deliveries));
  }

  /**
   * One document: `{ id, cite, members, list }`.
   *
   * @param id - the document's id, such as `stream-configuration`
   * @returns the document
   */
  static document(id: string): Json {
    log.debug("Entering SsfModel.document(). " + id);
    const set = DOCUMENTS.get(id);
    if (!set) {
      log.debug("Leaving SsfModel.document(). No such document.");
      throw new TypeError('The Shared Signals model has no document ' + id);
    }
    log.debug("Leaving SsfModel.document().");
    return set;
  }

  /**
   * The stream configuration members one party supplies (SSF 1.0 section
   * 8.1.1), in the model's order.
   *
   * @param by - `transmitter` or `receiver`
   * @returns the member names
   */
  static supplied(by: string): string[] {
    log.debug("Entering SsfModel.supplied(). " + by);
    const names = SsfModel.document('stream-configuration').list
      .filter(function (member: Json) {
        return member.supplier === by;
      }).map(function (member: Json) {
        return member.name;
      });
    log.debug("Leaving SsfModel.supplied(). " + names.length);
    return names;
  }

  /**
   * Whether a JSON value is one of the types a member may take.
   *
   * @param value - the value
   * @param types - from the model: `string`, `integer`, `number`,
   *   `boolean`, `array`, `object` or `any`
   * @returns true when it is
   */
  static fits(value: unknown, types: string[]): boolean {
    log.debug("Entering SsfModel.fits().");
    const fits = types.some(function (type) {
      if (type === 'any') {
        return true;
      }
      if (type === 'array') {
        return Array.isArray(value);
      }
      if (type === 'object') {
        return !!value && typeof value === 'object' && !Array.isArray(value);
      }
      if (type === 'integer') {
        return typeof value === 'number' && Number.isInteger(value);
      }
      return typeof value === type;
    });
    log.debug("Leaving SsfModel.fits().");
    return fits;
  }

  /**
   * What a document carries that the model does not allow: a member a closed
   * document does not name, a named member of a type it does not allow, and
   * a required member missing. Empty when the document is the model's.
   *
   * @param id - the document's id
   * @param value - the document
   * @param options - `open`: a member the model does not name is not a
   *   problem (a partner's document, which may extend the specification);
   *   `partial`: a required member may be missing (a request carrying only
   *   what it changes); `supplier`: every member but `stream_id` must be one
   *   that party supplies (SSF 1.0 section 8.1.1)
   * @returns one sentence per problem
   */
  static undeclared(id: string, value: Json, options?: Json): string[] {
    log.debug("Entering SsfModel.undeclared(). " + id);
    const set = SsfModel.document(id);
    const how: Json = options || {};
    const named = new Map<string, Json>();
    set.list.forEach(function (member: Json) {
      named.set(member.name, member);
    });
    const problems: string[] = [];
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      log.debug("Leaving SsfModel.undeclared(). Not an object.");
      return [id + ' is not a JSON object'];
    }
    Object.keys(value).forEach(function (key) {
      const member = named.get(key);
      if (!member) {
        if (set.members === 'closed' && !how.open) {
          problems.push(key + ' is not a member of ' + id);
        }
        return;
      }
      if (how.supplier && key !== 'stream_id' &&
          member.supplier !== how.supplier) {
        problems.push(key + ' is not ' + how.supplier + '-supplied in ' + id);
      }
      if (value[key] !== undefined &&
          !SsfModel.fits(value[key], member.types)) {
        problems.push(id + '.' + key + ' is not ' + member.types.join(' or '));
      }
    });
    set.list.forEach(function (member: Json) {
      if (!how.partial && member.required &&
          value[member.name] === undefined) {
        problems.push(member.name + ' is required in ' + id);
      }
    });
    log.debug("Leaving SsfModel.undeclared(). " + problems.length);
    return problems;
  }

  /**
   * Whether an `err` value is one the model does not declare.
   *
   * @param code - the `err` value
   * @returns true when the model does not declare it
   */
  static unknownError(code: string): boolean {
    log.debug("Entering SsfModel.unknownError().");
    log.debug("Leaving SsfModel.unknownError().");
    return !ERROR_CODES.has(code);
  }

  /**
   * Every `err` value the model declares, with the document defining it.
   *
   * @returns `[{ code, cite }]`
   */
  static errors(): Json[] {
    log.debug("Entering SsfModel.errors().");
    log.debug("Leaving SsfModel.errors().");
    return MODEL.errors.slice(0);
  }
}

export = SsfModel;
