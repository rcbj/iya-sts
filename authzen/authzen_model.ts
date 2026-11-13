// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: authzen/authzen_model.ts
//
// ---------------------------------------------------------------------------
// THE AUTHZEN MODEL, AS THE ENDPOINTS READ IT (#1579).
//
// `models/authzen/authzen.tsp` and `authzen_members.tsp` are the source of
// every request the AuthZEN Authorization API reads, of every answer's
// members, of the Obligations Profile's registered types and of the Access
// Request profile's problem types. The image build writes
// `models/generated/authzen.json` and this reads it:
//
//   * `read(id, body)` is a request's SHAPE PASS, BUILT FROM THE MODEL: the
//     body an object, the members it may not carry, the members it does not
//     take (none, on a request whose `unknownMembers` is `ignored`: AuthZEN
//     1.0 section 10.1.1 has a receiver ignore them, at every depth, and
//     every request here says so since #936), then every field in the
//     order it is declared — its kind, its bounds, the object's own members — and the first refusal, with the
//     code and the sentence the model gives it. `field(id, path, value)`
//     reads one field a request checks at its own place between checks
//     that need state (`deferred`), and `item(id, name, value)` one item of
//     an array whose items are refused alone.
//   * `undeclared(id, value)` and `hold(id, value, where)` are the holding
//     of an answer: a member a closed set does not name, a member of a type
//     it does not allow, a required member missing, and the same of every
//     member set the answer holds. `hold()` records what it finds under
//     STS-AUTHZEN-0116 and changes nothing: the model describes the wire
//     and does not reshape it.
//   * `reservedContext()`, `obligationTypes()`, `problemType()` and
//     `valuesOf()` are the facts the code branches on.
//
// WHAT STAYS IN THE CODE, because it needs state: the catalogue's rows and
// their value rules, the caller's scope, the batch's bounds, a search's
// token, a submission's binding, freshness, idempotency and callbacks
// (`authzen/CLAUDE.md`, *THE REQUEST SHAPES ARE THE MODEL'S*).
//
// A LEAF: it requires `common/model_tables`, `common/error_codes` and
// bunyan.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('../common/model_tables');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({
  name: 'sts-authzen-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

// A request that cannot be read: the status, the code and what the caller
// is told.
interface Refusal {
  status: number;
  code: string;
  message: string;
}

const MODEL: Json = ModelTables.file('authzen.json');

const REQUESTS = new Map<string, Json>();

MODEL.requests.forEach(function (one: Json) {
  REQUESTS.set(one.id, one);
});

const MEMBER_SETS = new Map<string, Json>();

MODEL.members.forEach(function (set: Json) {
  MEMBER_SETS.set(set.id, set);
});

// The longest a stray member's name is quoted.
const MAX_QUOTED = 64;

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
 * Fills a sentence's placeholders.
 *
 * @param sentence - the model's template
 * @param values - the placeholders' values
 * @returns the sentence
 */
function fill(sentence: string, values: Json): string {
  log.debug("Entering fill().");
  const out = String(sentence || '').replace(/\{([A-Za-z]+)\}/g,
    function (all: string, name: string) {
      return values[name] === undefined ? all : String(values[name]);
    });
  log.debug("Leaving fill().");
  return out;
}

/**
 * A list joined by commas, the last by "and".
 *
 * @param names - the list
 * @returns the text
 */
function joinedAnd(names: string[]): string {
  log.debug("Entering joinedAnd().");
  log.debug("Leaving joinedAnd().");
  return names.length < 2 ? names.join('')
    : names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1];
}

/**
 * The AuthZEN model: the request readers built from it and the holding of
 * what the endpoints answer.
 */
class AuthzenModel {
  /**
   * One request of the model.
   *
   * @param id - the request's id, such as `evaluation`
   * @returns the request
   */
  static request(id: string): Json {
    log.debug("Entering AuthzenModel.request().");
    const request = REQUESTS.get(id);
    if (!request) {
      log.debug("Leaving AuthzenModel.request(). No such request.");
      throw new TypeError('The AuthZEN model has no request ' + id);
    }
    log.debug("Leaving AuthzenModel.request().");
    return request;
  }

  /**
   * One field of a request, by its dotted path.
   *
   * @param id - the request's id
   * @param path - such as `options.evaluations_semantic`
   * @returns the field
   */
  static fieldOf(id: string, path: string): Json {
    log.debug("Entering AuthzenModel.fieldOf().");
    let fields: Json[] = AuthzenModel.request(id).fields;
    let found: Json | undefined;
    path.split('.').forEach(function (name: string) {
      found = (fields || []).find(function (one: Json) {
        return one.name === name;
      });
      fields = found ? found.fields : [];
    });
    if (!found) {
      log.debug("Leaving AuthzenModel.fieldOf(). No such field.");
      throw new TypeError('The AuthZEN request ' + id + ' has no field ' +
                          path);
    }
    log.debug("Leaving AuthzenModel.fieldOf().");
    return found;
  }

  /**
   * The refusal of a field: the field's own code and sentence when it has
   * them, else what it inherits, else the kind's.
   *
   * @param request - the request
   * @param field - the field
   * @param kind - `absent`, `type` or `stray`
   * @param sentence - the kind's sentence, a key of `sentences`
   * @param values - the placeholders
   * @param inherited - the code and sentence of an enclosing field
   * @returns the refusal
   */
  static refusal(request: Json, field: Json, kind: string,
                 sentence: string, values: Json, inherited: Json): Refusal {
    log.debug("Entering AuthzenModel.refusal(). " + kind);
    // A sentence handed down by an enclosing field is that field's refusal
    // as a whole, which is a refusal of its type.
    const code = field.code || inherited.code ||
      (inherited.refusal ? request.codes.type : request.codes[kind]);
    const said = field.refusal || inherited.refusal ||
      (kind === 'absent' && field.absent) || request.sentences[sentence];
    const shown = Object.assign({}, values,
      field.refusal || !inherited.refusal ? {} : { path: inherited.path });
    log.debug("Leaving AuthzenModel.refusal().");
    return { status: 400, code: code, message: fill(said, shown) };
  }

  /**
   * Reads one field's value: its kind, its bounds and, for an object, its
   * own members in order.
   *
   * @param request - the request
   * @param field - the field
   * @param value - its value, or undefined when it is absent
   * @param path - the field's dotted path
   * @param inherited - the code, sentence and path a field with a
   *   `refusal` hands what it holds
   * @returns a refusal, or null
   */
  static check(request: Json, field: Json, value: unknown, path: string,
               inherited: Json): Refusal | null {
    log.debug("Entering AuthzenModel.check(). " + path);
    const values: Json = { path: path, maxLength: field.maxLength,
                           values: (field.values || []).join(', ') };
    const refuse = function (kind: string, sentence: string,
                             extra?: Json): Refusal {
      log.debug("Entering refuse(). " + kind);
      log.debug("Leaving refuse().");
      return AuthzenModel.refusal(request, field, kind, sentence,
                                  Object.assign(values, extra || {}),
                                  inherited);
    };
    if (field.kind === 'any') {
      log.debug("Leaving AuthzenModel.check(). Anything.");
      return null;
    }
    if (field.kind === 'never') {
      log.debug("Leaving AuthzenModel.check(). Must not be sent.");
      return value === undefined ? null : refuse('stray', 'strayMember');
    }
    const absent = value === undefined ||
      (field.kind === 'string' && field.nonEmpty === true && field.required &&
       (value === null || value === ''));
    if (absent) {
      if (!field.required) {
        log.debug("Leaving AuthzenModel.check(). Absent, and optional.");
        return null;
      }
      const required = (field.fields || []).filter(function (one: Json) {
        return one.required && one.kind === 'string';
      }).map(function (one: Json) {
        return path + '.' + one.name;
      });
      log.debug("Leaving AuthzenModel.check(). Absent.");
      return refuse('absent', field.kind === 'object' ? 'absentObject'
                                                      : 'absentString',
                    { required: required.join(' and ') });
    }
    const handed = field.refusal
      ? { code: field.code || inherited.code, refusal: field.refusal,
          path: path }
      : (field.code ? Object.assign({}, inherited, { code: field.code })
                    : inherited);
    const own = AuthzenModel.kindProblem(field, value);
    if (own) {
      log.debug("Leaving AuthzenModel.check(). Not " + field.kind + ".");
      return refuse('type', own);
    }
    if (field.kind === 'object') {
      const given: Json = value as Json;
      if (field.requireOne && !field.requireOne.some(function (name: string) {
        return !!given[name];
      })) {
        log.debug("Leaving AuthzenModel.check(). None of requireOne.");
        return refuse('type', 'notObject');
      }
      // An object's unknown members are refused unless it is open or its
      // request ignores them (AuthZEN 1.0 section 10.1.1).
      const ignores = field.open === true ||
        request.unknownMembers === 'ignored';
      const inner = AuthzenModel.readMembers(request, field.fields || [],
                                         given, path, handed,
                                         ignores ? null : '');
      log.debug("Leaving AuthzenModel.check(). An object.");
      return inner;
    }
    log.debug("Leaving AuthzenModel.check(). Fits.");
    return null;
  }

  /**
   * Whether a value is the kind its field is, within its bounds.
   *
   * @param field - the field
   * @param value - the value, present
   * @returns the sentence key of the refusal, or '' when it fits
   */
  static kindProblem(field: Json, value: any): string {
    log.debug("Entering AuthzenModel.kindProblem(). " + field.kind);
    let out = '';
    if (field.kind === 'object') {
      out = isObject(value) ? '' : 'notObject';
    } else if (field.kind === 'string') {
      out = typeof value !== 'string' ||
        (field.maxLength !== undefined && value.length > field.maxLength) ||
        (field.nonEmpty === true && value === '') ? 'notString' : '';
    } else if (field.kind === 'integer') {
      out = !Number.isSafeInteger(value) ||
        (field.minimum !== undefined && value < field.minimum)
        ? 'notString' : '';
    } else if (field.kind === 'boolean') {
      out = typeof value === 'boolean' ? '' : 'notString';
    } else if (field.kind === 'array') {
      out = !Array.isArray(value) ||
        (field.maxItems !== undefined && value.length > field.maxItems) ||
        (field.items === 'string' && !value.every(function (one: unknown) {
          return typeof one === 'string' &&
            (field.itemMaxLength === undefined ||
             one.length <= field.itemMaxLength);
        })) ? 'notArray' : '';
    } else if (field.kind === 'values') {
      const compared = field.coerce === 'string' ? String(value) : value;
      out = field.values.indexOf(compared) >= 0 ? '' : 'notOneOf';
    }
    log.debug("Leaving AuthzenModel.kindProblem(). " + (out || 'Fits.'));
    return out;
  }

  /**
   * Reads an object's members: each field it must not carry, then (unless
   * it is open) the first member it does not take, then every other field
   * in order. Deferred fields are left to their own place.
   *
   * @param request - the request
   * @param fields - the object's fields
   * @param given - the object
   * @param path - its dotted path, '' at the top
   * @param inherited - what an enclosing field with a `refusal` hands down
   * @param stray - the sentence for a member it does not take, '' for the
   *   kind's, or null when the object is open
   * @returns a refusal, or null
   */
  static readMembers(request: Json, fields: Json[], given: Json, path: string,
                 inherited: Json, stray: string | null): Refusal | null {
    log.debug("Entering AuthzenModel.readMembers(). " + (path || 'the body'));
    const named = fields.filter(function (one: Json) {
      return one.kind !== 'never';
    }).map(function (one: Json) {
      return one.name;
    });
    let scanned = false;
    for (let i = 0; i < fields.length; i += 1) {
      const field = fields[i];
      const at = path ? path + '.' + field.name : field.name;
      if (field.kind !== 'never' && !scanned) {
        // THE STRAY SCAN COMES AFTER THE LEADING MEMBERS IT MUST NOT CARRY:
        // a member a newer profile defines is named as that, not as a
        // mistake.
        scanned = true;
        const found = stray === null ? undefined
          : Object.keys(given).find(function (key: string) {
            return named.indexOf(key) < 0;
          });
        if (found !== undefined) {
          const values = { member: found.slice(0, MAX_QUOTED), path: path,
                           members: named.join(', '),
                           membersAnd: joinedAnd(named) };
          const code = inherited.code ||
            (inherited.refusal ? request.codes.type : request.codes.stray);
          const said = inherited.refusal || stray ||
            request.sentences.strayMember;
          log.debug("Leaving AuthzenModel.readMembers(). A stray member.");
          return { status: 400, code: code,
                   message: fill(said, inherited.refusal
                     ? { path: inherited.path } : values) };
        }
      }
      if (field.deferred === true) {
        continue;
      }
      const problem = AuthzenModel.check(request, field, given[field.name],
                                         at, inherited);
      if (problem) {
        log.debug("Leaving AuthzenModel.readMembers(). " + problem.code);
        return problem;
      }
    }
    log.debug("Leaving AuthzenModel.readMembers().");
    return null;
  }

  /**
   * A request's shape pass.
   *
   * @param id - the request's id
   * @param body - the parsed body, or undefined when it was not JSON
   * @returns the refusal, or null when the shape is the model's
   */
  static read(id: string, body: unknown): Refusal | null {
    log.debug("Entering AuthzenModel.read(). " + id);
    const request = AuthzenModel.request(id);
    if (!isObject(body)) {
      log.debug("Leaving AuthzenModel.read(). Not an object.");
      return { status: 400, code: request.codes.notObject,
               message: request.notObject };
    }
    const out = AuthzenModel.readMembers(request, request.fields, body as Json,
      '', {}, request.stray === undefined ||
        request.unknownMembers === 'ignored' ? null : request.stray);
    log.debug("Leaving AuthzenModel.read(). " + (out ? out.code : 'Fits.'));
    return out;
  }

  /**
   * Reads one field a request checks at its own place (`deferred`).
   *
   * @param id - the request's id
   * @param path - the field's dotted path
   * @param value - its value
   * @returns the refusal, or null
   */
  static field(id: string, path: string, value: unknown): Refusal | null {
    log.debug("Entering AuthzenModel.field(). " + id + " " + path);
    const request = AuthzenModel.request(id);
    const field = AuthzenModel.fieldOf(id, path);
    // An enclosing field's code is the field's own unless it names one.
    const parent = path.indexOf('.') > 0
      ? AuthzenModel.fieldOf(id, path.replace(/\.[^.]*$/, '')) : null;
    const inherited = parent && parent.code ? { code: parent.code } : {};
    const own = Object.assign({}, field, { deferred: false });
    const out = AuthzenModel.check(request, own, value, path, inherited);
    log.debug("Leaving AuthzenModel.field(). " + (out ? out.code : 'Fits.'));
    return out;
  }

  /**
   * Reads one item of an array whose items are refused alone
   * (`itemRefusal`): it must be a JSON object.
   *
   * @param id - the request's id
   * @param path - the array's dotted path
   * @param value - the item
   * @returns the refusal, or null
   */
  static item(id: string, path: string, value: unknown): Refusal | null {
    log.debug("Entering AuthzenModel.item(). " + id + " " + path);
    const request = AuthzenModel.request(id);
    const field = AuthzenModel.fieldOf(id, path);
    if (isObject(value)) {
      log.debug("Leaving AuthzenModel.item(). An object.");
      return null;
    }
    log.debug("Leaving AuthzenModel.item(). Not an object.");
    return { status: 400, code: field.code || request.codes.notObject,
             message: String(field.itemRefusal || '') };
  }

  /**
   * The members of the evaluation's `context` the request itself defines,
   * which a catalogue row may never name.
   *
   * @returns the names, in the order they are checked
   */
  static reservedContext(): string[] {
    log.debug("Entering AuthzenModel.reservedContext().");
    log.debug("Leaving AuthzenModel.reservedContext().");
    return AuthzenModel.fieldOf('evaluation', 'context').fields
      .map(function (one: Json) {
        return one.name;
      });
  }

  /**
   * One member set: an answer, a part of one, or an obligation type.
   *
   * @param id - the set's id
   * @returns `{ id, cite, members, list }`
   */
  static memberSet(id: string): Json {
    log.debug("Entering AuthzenModel.memberSet().");
    const set = MEMBER_SETS.get(id);
    if (!set) {
      log.debug("Leaving AuthzenModel.memberSet(). No such set.");
      throw new TypeError('The AuthZEN model has no member set ' + id);
    }
    log.debug("Leaving AuthzenModel.memberSet().");
    return set;
  }

  /**
   * The values a member may take, in the model's order.
   *
   * @param setId - the member set
   * @param name - the member
   * @returns the values
   */
  static valuesOf(setId: string, name: string): string[] {
    log.debug("Entering AuthzenModel.valuesOf().");
    const member = AuthzenModel.memberSet(setId).list.find(
      function (one: Json) {
        return one.name === name;
      });
    log.debug("Leaving AuthzenModel.valuesOf().");
    return member && member.values ? member.values.slice(0) : [];
  }

  /**
   * The Obligations Profile's registered types, in the model's order: each
   * with the properties it may not be handed without and those that
   * collect every assignment of their name.
   *
   * @returns `{ type: { required, arrays } }`
   */
  static obligationTypes(): Json {
    log.debug("Entering AuthzenModel.obligationTypes().");
    const out: Json = {};
    MODEL.members.filter(function (set: Json) {
      return set.obligation === true;
    }).forEach(function (set: Json) {
      out[set.id] = {
        required: set.list.filter(function (one: Json) {
          return one.required;
        }).map(function (one: Json) {
          return one.name;
        }),
        arrays: set.list.filter(function (one: Json) {
          return one.types.indexOf('array') >= 0;
        }).map(function (one: Json) {
          return one.name;
        })
      };
    });
    log.debug("Leaving AuthzenModel.obligationTypes().");
    return out;
  }

  /**
   * One of the Access Request profile's problem types.
   *
   * @param type - its last segment, such as `unknown_task`
   * @returns `{ uri, title }`
   */
  static problemType(type: string): { uri: string; title: string } {
    log.debug("Entering AuthzenModel.problemType().");
    const found = MODEL.problems.types.find(function (one: Json) {
      return one.type === type;
    });
    if (!found) {
      log.debug("Leaving AuthzenModel.problemType(). No such type.");
      throw new TypeError('The AuthZEN model has no problem type ' + type);
    }
    log.debug("Leaving AuthzenModel.problemType().");
    return { uri: MODEL.problems.prefix + found.type, title: found.title };
  }

  /**
   * Whether a JSON value is one of the types a member may take.
   *
   * @param value - the value
   * @param types - from the model
   * @returns true when it is
   */
  static fits(value: unknown, types: string[]): boolean {
    log.debug("Entering AuthzenModel.fits().");
    const fits = types.some(function (type) {
      if (type === 'any') {
        return true;
      }
      if (type === 'array') {
        return Array.isArray(value);
      }
      if (type === 'object') {
        return isObject(value);
      }
      if (type === 'integer') {
        return typeof value === 'number' && Number.isInteger(value);
      }
      return typeof value === type;
    });
    log.debug("Leaving AuthzenModel.fits().");
    return fits;
  }

  /**
   * What an answer carries that its member set does not allow: a member a
   * closed set does not name, a named member of a type or value the set
   * does not allow, a required member missing — and the same of every
   * member that is a member set of its own. Empty when the answer is the
   * model's.
   *
   * @param id - the member set's id
   * @param value - the answer
   * @param where - the path of the answer, for the sentences
   * @returns one sentence per problem
   */
  static undeclared(id: string, value: Json, where?: string): string[] {
    log.debug("Entering AuthzenModel.undeclared(). " + id);
    const set = AuthzenModel.memberSet(id);
    const at = where || id;
    const problems: string[] = [];
    if (!isObject(value)) {
      log.debug("Leaving AuthzenModel.undeclared(). Not an object.");
      return [at + ' is not a JSON object'];
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
      if (!AuthzenModel.fits(one, member.types)) {
        problems.push(at + '.' + key + ' is not ' + member.types.join(' or '));
        return;
      }
      if (member.values && member.values.indexOf(one) < 0) {
        problems.push(at + '.' + key + ' is not one of ' +
                      member.values.join(', '));
      }
      if (member.set) {
        [].concat(Array.isArray(one) ? one : [one])
          .forEach(function (inner: Json, i: number) {
            AuthzenModel.undeclared(member.set, inner, at + '.' + key +
              (Array.isArray(one) ? '[' + i + ']' : ''))
              .forEach(function (problem: string) {
                problems.push(problem);
              });
          });
      }
    });
    set.list.forEach(function (member: Json) {
      if (member.required && value[member.name] === undefined) {
        problems.push(at + '.' + member.name + ' is required in ' + id);
      }
    });
    log.debug("Leaving AuthzenModel.undeclared(). " + problems.length);
    return problems;
  }

  /**
   * Holds an answer to its member set: what it carries that the model does
   * not allow is recorded under STS-AUTHZEN-0116, and the answer is sent as
   * it was built.
   *
   * @param id - the member set's id
   * @param value - the answer
   * @param where - the endpoint, for the log line
   * @returns the problems, empty when the answer is the model's
   */
  static hold(id: string, value: Json, where: string): string[] {
    log.debug("Entering AuthzenModel.hold(). " + id);
    const problems = AuthzenModel.undeclared(id, value);
    if (problems.length) {
      log.error(errorCodes.tag('STS-AUTHZEN-0116') + 'authzen: the ' + id +
                ' answer of ' + where + ' is not its model\'s: ' +
                problems.slice(0, 5).join('; '));
    }
    log.debug("Leaving AuthzenModel.hold(). " + problems.length);
    return problems;
  }

  /**
   * `hold()`, answering the answer: for a call site that sends what it
   * holds in one expression.
   *
   * @param id - the member set's id
   * @param value - the answer
   * @param where - the endpoint, for the log line
   * @returns the answer, unchanged
   */
  static held(id: string, value: Json, where: string): Json {
    log.debug("Entering AuthzenModel.held().");
    AuthzenModel.hold(id, value, where);
    log.debug("Leaving AuthzenModel.held().");
    return value;
  }
}

export = AuthzenModel;
