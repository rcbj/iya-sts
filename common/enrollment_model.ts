// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: common/enrollment_model.ts
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE-ENROLLMENT MODEL, AS ACME, EST AND SCEP READ IT (#1579).
//
// `models/enrollment/acme.tsp`, `est.tsp` and `scep.tsp` are the source of
// every request document the three protocols read as JSON or as a query, of
// the answers ACME and EST's nonce send, of every error type, status and
// signed-attribute value, of the registers each branches on and of the
// operations each answers. The image build writes
// `models/generated/enrollment.json` and this reads it:
//
//   * `body(family, id)` is the zod object a document is checked against,
//     BUILT FROM THE MODEL. Each member becomes exactly the expression the
//     hand-written schema had — `z.string()` then its `min`, `max` and
//     `regex` in that order, `z.number().int()` then its bounds, `z.array()`
//     then its bounds, a nested strict, loose or stripping object, and in a
//     query `validation.types.integer()`, `oneOf()` and `opt()` — so a
//     refusal's sentence, which quotes zod's issue, reads word for word as it
//     always did (`tests/enrollment_model_wire.js`).
//   * `names()`, `rows()` and `operations()` are the registers and the
//     operations, in the model's order: the code keeps only what each row
//     DOES.
//   * `undeclared(family, id, value)` and `unknownTerm()` are the holding:
//     what an answer carries that its model does not allow, and a value a
//     register does not name. The callers record what they find under their
//     family's error code and send the answer unchanged, because the model
//     describes the wire and does not reshape it.
//
// A LEAF: it requires `common/validation`, `common/model_tables` and bunyan,
// so `acme/`, `est/` and `scep/` and `common/cert_enrollment.ts` may each
// require it at load.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('./model_tables');
import validation = require('./validation');

const log = bunyan.createLogger({
  name: 'sts-enrollment-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL: Json = ModelTables.file('enrollment.json');

const BODIES = new Map<string, any>();

/**
 * The certificate-enrollment model: the request validators built from it,
 * the registers and operations, and the holding of what is answered.
 */
class EnrollmentModel {
  /**
   * One member's zod type, as the hand-written schema wrote it.
   *
   * @param field - one member of a body in `enrollment.json`
   * @param input - `json` or `query`
   * @returns the zod type, not yet made optional
   */
  static fieldType(field: Json, input: string): any {
    log.debug("Entering EnrollmentModel.fieldType(). json=" + field.json);
    const vz: any = validation.z;
    const vt: any = validation.types;
    let out: any;
    if (field.json === 'string') {
      out = vz.string();
      if (field.minLength !== undefined) {
        out = out.min(field.minLength);
      }
      if (field.maxLength !== undefined) {
        out = out.max(field.maxLength);
      }
      if (field.pattern !== undefined) {
        out = field.patternMessage !== undefined
          ? out.regex(new RegExp(field.pattern), field.patternMessage)
          : out.regex(new RegExp(field.pattern));
      }
    } else if (field.json === 'integer') {
      out = input === 'query' ? vt.integer(field.minimum, field.maximum)
        : vz.number().int().min(field.minimum).max(field.maximum);
    } else if (field.json === 'boolean') {
      out = vz.boolean();
    } else if (field.json === 'any') {
      out = vz.any();
    } else if (field.json === 'literal') {
      out = vz.literal(field.value);
    } else if (field.json === 'enum') {
      out = vt.oneOf(field.values);
    } else if (field.json === 'array') {
      out = vz.array(EnrollmentModel.fieldType(field.items, input));
      if (field.minItems !== undefined) {
        out = out.min(field.minItems);
      }
      if (field.maxItems !== undefined) {
        out = out.max(field.maxItems);
      }
    } else if (field.json === 'object') {
      out = EnrollmentModel.objectOf(field.shape.others, field.shape.fields,
                                     input);
    } else {
      log.debug("Leaving EnrollmentModel.fieldType(). An unknown type.");
      throw new TypeError('No validator can be generated for the type ' +
                          field.json + ' of ' + field.name);
    }
    log.debug("Leaving EnrollmentModel.fieldType().");
    return out;
  }

  /**
   * An object of members: strict, loose or stripping.
   *
   * @param others - `strict`, `loose` or `strip`
   * @param fields - its members
   * @param input - `json` or `query`
   * @returns the zod object
   */
  static objectOf(others: string, fields: Json[], input: string): any {
    log.debug("Entering EnrollmentModel.objectOf(). others=" + others);
    const vz: any = validation.z;
    const vt: any = validation.types;
    const shape: Json = {};
    fields.forEach(function (field: Json) {
      let type = EnrollmentModel.fieldType(field, input);
      if (field.empty) {
        type = vt.opt(type);
      } else if (!field.required) {
        type = type.optional();
      }
      shape[field.name] = type;
    });
    let out: any;
    if (others === 'strict') {
      out = vz.strictObject(shape);
    } else if (others === 'loose') {
      out = vz.looseObject(shape);
    } else {
      out = vz.object(shape);
    }
    log.debug("Leaving EnrollmentModel.objectOf().");
    return out;
  }

  /**
   * One request document's validator, built once.
   *
   * @param family - `acme`, `est` or `scep`
   * @param id - the document's id in the model, such as `new-order`
   * @returns the zod object
   */
  static body(family: string, id: string): any {
    log.debug("Entering EnrollmentModel.body(). " + family + "/" + id);
    const key = family + '/' + id;
    if (!BODIES.has(key)) {
      const body = MODEL.bodies.find(function (one: Json) {
        return one.family === family && one.id === id;
      });
      if (!body) {
        log.debug("Leaving EnrollmentModel.body(). No such body.");
        throw new TypeError('The enrollment model has no body ' + key);
      }
      BODIES.set(key, EnrollmentModel.objectOf(body.others, body.fields,
                                               body.input));
    }
    log.debug("Leaving EnrollmentModel.body().");
    return BODIES.get(key);
  }

  /**
   * One register's rows, in the model's order.
   *
   * @param family - the family
   * @param id - the register's id, such as `account-algorithms`
   * @returns `[{ name, cite, value?, code?, counted?, values? }]`
   */
  static rows(family: string, id: string): Json[] {
    log.debug("Entering EnrollmentModel.rows(). " + family + "/" + id);
    const register = MODEL.registers.find(function (one: Json) {
      return one.family === family && one.id === id;
    });
    if (!register) {
      log.debug("Leaving EnrollmentModel.rows(). No such register.");
      throw new TypeError('The enrollment model has no register ' + family +
                          '/' + id);
    }
    log.debug("Leaving EnrollmentModel.rows().");
    return register.rows.map(function (row: Json) {
      return Object.assign({}, row);
    });
  }

  /**
   * One register's row names, in the model's order.
   *
   * @param family - the family
   * @param id - the register's id
   * @returns the names
   */
  static names(family: string, id: string): string[] {
    log.debug("Entering EnrollmentModel.names().");
    log.debug("Leaving EnrollmentModel.names().");
    return EnrollmentModel.rows(family, id).map(function (row: Json) {
      return row.name;
    });
  }

  /**
   * One register's rows as `{ name: value }`, or `{ code: name }` when
   * `byCode` is set.
   *
   * @param family - the family
   * @param id - the register's id
   * @param byCode - true to key each row's name by its code
   * @returns the map
   */
  static map(family: string, id: string, byCode?: boolean): Json {
    log.debug("Entering EnrollmentModel.map().");
    const out: Json = {};
    EnrollmentModel.rows(family, id).forEach(function (row: Json) {
      if (byCode) {
        out[row.code] = row.name;
      } else {
        out[row.name] = row.value;
      }
    });
    log.debug("Leaving EnrollmentModel.map().");
    return out;
  }

  /**
   * A family's operations, in the model's order.
   *
   * @param family - the family
   * @returns `[{ name, methods, cite, path?, accepts?, answers?, ... }]`
   */
  static operations(family: string): Json[] {
    log.debug("Entering EnrollmentModel.operations(). " + family);
    const list = MODEL.operations.find(function (one: Json) {
      return one.family === family;
    });
    if (!list) {
      log.debug("Leaving EnrollmentModel.operations(). None.");
      throw new TypeError('The enrollment model has no operations for ' +
                          family);
    }
    log.debug("Leaving EnrollmentModel.operations().");
    return list.list.map(function (op: Json) {
      return Object.assign({}, op, { methods: op.methods.slice(0) });
    });
  }

  /**
   * Whether a value is not one of a register's rows.
   *
   * @param family - the family
   * @param id - the register's id
   * @param name - the value sent
   * @returns true when the register does not name it
   */
  static unknownTerm(family: string, id: string, name: string): boolean {
    log.debug("Entering EnrollmentModel.unknownTerm().");
    const unknown = EnrollmentModel.names(family, id).indexOf(name) < 0;
    log.debug("Leaving EnrollmentModel.unknownTerm(). unknown=" + unknown);
    return unknown;
  }

  /**
   * Whether a JSON value is one of the types a member may take.
   *
   * @param value - the value
   * @param types - `string`, `integer`, `number`, `boolean`, `array`,
   *   `object` or `any`
   * @returns true when it is
   */
  static fits(value: unknown, types: string[]): boolean {
    log.debug("Entering EnrollmentModel.fits().");
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
    log.debug("Leaving EnrollmentModel.fits().");
    return fits;
  }

  /**
   * What a value carries that a list of members does not allow, walked
   * into each nested object and each array's objects.
   *
   * @param at - where the value is, for the sentence
   * @param list - the members
   * @param closed - true when a member not named is wrong
   * @param value - the value
   * @param problems - where a problem is added
   */
  static walk(at: string, list: Json[], closed: boolean, value: Json,
              problems: string[]): void {
    log.debug("Entering EnrollmentModel.walk(). " + at);
    const named = new Map<string, Json>();
    list.forEach(function (member: Json) {
      named.set(member.name, member);
    });
    Object.keys(value || {}).forEach(function (key) {
      const member = named.get(key);
      const one = value[key];
      if (!member) {
        if (closed) {
          problems.push(at + '.' + key + ' is not a member');
        }
        return;
      }
      if (one === undefined) {
        return;
      }
      if (!EnrollmentModel.fits(one, member.types)) {
        problems.push(at + '.' + key + ' is not ' + member.types.join(' or '));
        return;
      }
      if (member.values && member.values.indexOf(one) < 0) {
        problems.push(at + '.' + key + ' is "' + String(one).slice(0, 64) +
                      '", not one of ' + member.values.join(', '));
      }
      if (member.valueTypes) {
        Object.keys(one).forEach(function (inner) {
          if (!EnrollmentModel.fits(one[inner], member.valueTypes)) {
            problems.push(at + '.' + key + '.' + inner + ' is not ' +
                          member.valueTypes.join(' or '));
          }
        });
      }
      const items = Array.isArray(one) ? one : [one];
      items.forEach(function (item: unknown, i: number) {
        const where = at + '.' + key + (Array.isArray(one) ? '.' + i : '');
        if (member.items && Array.isArray(one) &&
            !EnrollmentModel.fits(item, member.items)) {
          problems.push(where + ' is not ' + member.items.join(' or '));
          return;
        }
        if (member.shape && item && typeof item === 'object') {
          EnrollmentModel.walk(where, member.shape.list,
                               member.shape.members === 'closed',
                               item as Json, problems);
        }
      });
    });
    list.forEach(function (member: Json) {
      if (member.required && (!value || value[member.name] === undefined)) {
        problems.push(at + '.' + member.name + ' is required');
      }
    });
    log.debug("Leaving EnrollmentModel.walk().");
  }

  /**
   * What an answer carries that its model does not allow: a member a closed
   * answer does not name, a member of a type or a value the model does not
   * allow, a required member missing — in it and in every object it holds.
   * Empty when the answer is the model's.
   *
   * @param family - the family
   * @param id - the answer's id, such as `order`
   * @param value - the answer
   * @returns one sentence per problem
   */
  static undeclared(family: string, id: string, value: Json): string[] {
    log.debug("Entering EnrollmentModel.undeclared(). " + family + "/" + id);
    const answer = MODEL.answers.find(function (one: Json) {
      return one.family === family && one.id === id;
    });
    if (!answer) {
      log.debug("Leaving EnrollmentModel.undeclared(). No such answer.");
      throw new TypeError('The enrollment model has no answer ' + family +
                          '/' + id);
    }
    const problems: string[] = [];
    EnrollmentModel.walk(id, answer.list, answer.members === 'closed', value,
                         problems);
    log.debug("Leaving EnrollmentModel.undeclared(). " + problems.length);
    return problems;
  }
}

export = EnrollmentModel;
