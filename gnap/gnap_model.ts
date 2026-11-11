// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap/gnap_model.ts
//
// ---------------------------------------------------------------------------
// THE GNAP MODEL, AS THE ENDPOINTS READ IT (#1579).
//
// `models/gnap/gnap.tsp` is the source of every document a client instance
// or a resource server sends, of the paths' parameters, of the registries
// the request walk reads, of every answer's members and of the error codes.
// The image build writes `models/generated/gnap.json` and this reads it:
//
//   * `schemas()` is the JSON Schema of each request document with every
//     `"$cap:NAME"` replaced by `common/validation.js`'s `CAP[NAME]`, the one
//     table of the shared caps — byte for byte the schemas
//     `gnap/gnap_schemas.ts` wrote by hand until #1579, so ajv answers every
//     refusal as it did (`tests/gnap_model_wire.js`).
//   * `params(id)` is the zod object a path's or a query's parameters, or a
//     `/gnap-api` act's body, are checked against: each the shared type of
//     `common/validation.js` it names, or one of its values, repeated where
//     it may repeat, closed where the model says so.
//   * `registry(id)` is one of the registries `gnap/gnap_request.ts`'s walk
//     and `gnap/gnap_keys.ts` branch on.
//   * `hold(id, body)` and `holdError(code)` are the holding: what an answer
//     carries that its member set does not allow, recorded under
//     STS-GNAP-0910 / 0911 with the answer sent unchanged, because the model
//     describes the wire and does not reshape it.
//
// A LEAF: it requires `common/validation`, `common/model_tables`,
// `common/error_codes` and bunyan.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('../common/model_tables');
import validation = require('../common/validation');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({
  name: 'sts-gnap-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL: Json = ModelTables.file('gnap.json');

const MEMBER_SETS = new Map<string, Json>();

MODEL.members.forEach(function (set: Json) {
  MEMBER_SETS.set(set.id, set);
});

const ERROR_CODES = new Set<string>(MODEL.errors.map(function (one: Json) {
  return one.code;
}));

// The most gaps `gaps()` keeps, newest last: what a test reads back.
const GAPS_KEPT = 100;

const GAPS: string[] = [];

const PARAMS = new Map<string, any>();

let SCHEMAS: Json | null = null;

/**
 * The GNAP model: the request schemas and validators built from it and the
 * holding of what the endpoints answer.
 */
class GnapModel {
  /**
   * The pattern every string that states none carries: no C0 control
   * character and no DEL.
   */
  static readonly SAFE: string = MODEL.safePattern;

  /**
   * A schema with every cap named by the model replaced by its number.
   *
   * @param value - a schema, or a part of one
   * @returns the resolved copy
   */
  // A hot path at load: no Entering/Leaving pair, because it recurses
  // through every node of six schemas and the pair would drown the log.
  static resolveCaps(value: any): any {
    if (Array.isArray(value)) {
      return value.map(GnapModel.resolveCaps);
    }
    if (value && typeof value === 'object') {
      const out: Json = {};
      Object.keys(value).forEach(function (key) {
        const one = value[key];
        if (key === 'maxLength' && typeof one === 'string' &&
            one.indexOf('$cap:') === 0) {
          const cap = (validation.CAP as Json)[one.slice(5)];
          if (typeof cap !== 'number') {
            throw new TypeError('The GNAP model names the cap ' + one +
                                ', which common/validation.js has not');
          }
          out[key] = cap;
        } else {
          out[key] = GnapModel.resolveCaps(one);
        }
      });
      return out;
    }
    return value;
  }

  /**
   * Every request document's JSON Schema, by name, caps resolved.
   *
   * @returns `{ grantRequest, continuation, ... }`
   */
  static schemas(): Json {
    log.debug("Entering GnapModel.schemas().");
    if (!SCHEMAS) {
      SCHEMAS = GnapModel.resolveCaps(MODEL.schemas);
    }
    log.debug("Leaving GnapModel.schemas().");
    return SCHEMAS as Json;
  }

  /**
   * One set of parameters' validator, built once.
   *
   * @param id - the set's id in the model: `as`, `continue`, `manage`,
   *   `interaction-id`, `approve-query`, `api-approve`, `api-code`
   * @returns the zod object
   */
  static params(id: string): any {
    log.debug("Entering GnapModel.params().");
    if (!PARAMS.has(id)) {
      const set = MODEL.params.find(function (one: Json) {
        return one.id === id;
      });
      if (!set) {
        log.debug("Leaving GnapModel.params(). No such set.");
        throw new TypeError('The GNAP model has no parameters ' + id);
      }
      const vt: any = validation.types;
      const shape: Json = {};
      set.params.forEach(function (param: Json) {
        let type = param.values ? vt.oneOf(param.values) : vt[param.kind];
        if (!type) {
          throw new TypeError('No validator can be generated for the kind ' +
                              param.kind + ' of ' + param.name);
        }
        if (param.repeatable) {
          type = vt.repeatable(type);
        }
        if (param.empty) {
          type = vt.opt(type);
        } else if (!param.required) {
          type = type.optional();
        }
        shape[param.name] = type;
      });
      const object = (validation.z as any).object(shape);
      PARAMS.set(id, set.closed ? object.strict() : object);
    }
    log.debug("Leaving GnapModel.params().");
    return PARAMS.get(id);
  }

  /**
   * One registry: a list of values, or a table of names to the members each
   * carries.
   *
   * @param id - the registry's id in the model
   * @returns a copy of its values
   */
  static registry(id: string): any {
    log.debug("Entering GnapModel.registry().");
    const one = (MODEL.registries || {})[id];
    if (!one) {
      log.debug("Leaving GnapModel.registry(). No such registry.");
      throw new TypeError('The GNAP model has no registry ' + id);
    }
    log.debug("Leaving GnapModel.registry().");
    return JSON.parse(JSON.stringify(one.values));
  }

  /**
   * One member set: an answer, a discovery document or an object in one.
   *
   * @param id - the set's id in the model
   * @returns `{ id, cite, members, list }`
   */
  static members(id: string): Json {
    log.debug("Entering GnapModel.members().");
    const set = MEMBER_SETS.get(id);
    if (!set) {
      log.debug("Leaving GnapModel.members(). No such set.");
      throw new TypeError('The GNAP model has no member set ' + id);
    }
    log.debug("Leaving GnapModel.members().");
    return set;
  }

  /**
   * Whether a JSON value is one of the types a member may take.
   *
   * @param value - the value
   * @param types - from the model
   * @returns true when it is
   */
  static fits(value: unknown, types: string[]): boolean {
    log.debug("Entering GnapModel.fits().");
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
    log.debug("Leaving GnapModel.fits().");
    return fits;
  }

  /**
   * What a value carries that its member set does not allow — a member a
   * closed set does not name, a member of a type or a value the set does
   * not allow, a required member missing — and the same of every object
   * it nests that the model names a set for. Empty when it is the model's.
   *
   * @param id - the member set's id
   * @param value - the answer, or the object nested in one
   * @param where - the path of the value, for the sentence
   * @returns one sentence per problem
   */
  static undeclared(id: string, value: Json, where?: string): string[] {
    log.debug("Entering GnapModel.undeclared().");
    const at = where || id;
    const set = GnapModel.members(id);
    const problems: string[] = [];
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      log.debug("Leaving GnapModel.undeclared(). Not an object.");
      return [at + ' is not an object'];
    }
    const named = new Map<string, Json>();
    set.list.forEach(function (member: Json) {
      named.set(member.name, member);
    });
    Object.keys(value).forEach(function (key) {
      const member = named.get(key);
      if (!member) {
        if (set.members === 'closed') {
          problems.push(at + '.' + key + ' is not a member of ' + id);
        }
        return;
      }
      const one = value[key];
      if (one === undefined) {
        return;
      }
      if (!GnapModel.fits(one, member.types)) {
        problems.push(at + '.' + key + ' is not ' + member.types.join(' or '));
        return;
      }
      if (member.values && member.values.indexOf(one) < 0) {
        problems.push(at + '.' + key + ' is not one of ' +
                      member.values.join(', '));
      }
      (member.sets || []).forEach(function (nested: string) {
        const list = Array.isArray(one) ? one : [one];
        list.forEach(function (item: any, i: number) {
          if (item && typeof item === 'object' && !Array.isArray(item)) {
            const path = at + '.' + key + (Array.isArray(one)
              ? '[' + i + ']' : '');
            GnapModel.undeclared(nested, item, path).forEach(function (p) {
              problems.push(p);
            });
          }
        });
      });
    });
    set.list.forEach(function (member: Json) {
      if (member.required && value[member.name] === undefined) {
        problems.push(at + '.' + member.name + ' is required in ' + id);
      }
    });
    log.debug("Leaving GnapModel.undeclared(). " + problems.length);
    return problems;
  }

  /**
   * Holds an answer to its member set, and records what does not fit under
   * STS-GNAP-0910. The answer is not touched.
   *
   * @param id - the member set's id
   * @param body - the answer about to be sent
   * @param where - the endpoint, for the log line
   * @returns the problems, empty when the answer is the model's
   */
  static hold(id: string, body: unknown, where: string): string[] {
    log.debug("Entering GnapModel.hold(). " + id);
    let problems: string[];
    try {
      problems = GnapModel.undeclared(id, body as Json);
    } catch (e) {
      log.debug("Caught in GnapModel.hold(): " + ((e && e.message) || e));
      problems = ['the answer could not be held to ' + id + ': ' +
                  ((e && e.message) || e)];
    }
    if (problems.length > 0) {
      log.error(errorCodes.tag('STS-GNAP-0910') + 'the ' + where +
                ' answer is not its model\'s (' + id + '): ' +
                problems.join('; '));
      GnapModel.remember(where + ': ' + problems.join('; '));
    }
    log.debug("Leaving GnapModel.hold(). " + problems.length);
    return problems;
  }

  /**
   * Records an error code the model does not declare under STS-GNAP-0911.
   * The response is not touched.
   *
   * @param code - the GNAP error code about to be sent
   * @param where - the endpoint, for the log line
   * @returns true when the model does not declare it
   */
  static holdError(code: string, where: string): boolean {
    log.debug("Entering GnapModel.holdError().");
    const unknown = !ERROR_CODES.has(code);
    if (unknown) {
      log.error(errorCodes.tag('STS-GNAP-0911') + 'the GNAP error code "' +
                code + '" sent by ' + where + ' is not declared in ' +
                'models/gnap/gnap.tsp.');
      GnapModel.remember(where + ': the error code ' + code);
    }
    log.debug("Leaving GnapModel.holdError().");
    return unknown;
  }

  private static remember(gap: string): void {
    log.debug("Entering GnapModel.remember().");
    GAPS.push(gap);
    if (GAPS.length > GAPS_KEPT) {
      GAPS.shift();
    }
    log.debug("Leaving GnapModel.remember().");
  }

  /**
   * The gaps this process recorded, newest last, at most a hundred.
   *
   * @returns a copy
   */
  static gaps(): string[] {
    log.debug("Entering GnapModel.gaps().");
    log.debug("Leaving GnapModel.gaps().");
    return GAPS.slice(0);
  }

  /**
   * Every error code the model declares, with the document defining it.
   *
   * @returns `[{ code, cite, own? }]`
   */
  static errors(): Json[] {
    log.debug("Entering GnapModel.errors().");
    log.debug("Leaving GnapModel.errors().");
    return MODEL.errors.slice(0);
  }
}

export = GnapModel;
