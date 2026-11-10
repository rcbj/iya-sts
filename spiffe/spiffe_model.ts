// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: spiffe/spiffe_model.ts
//
// ---------------------------------------------------------------------------
// THE SPIFFE MODEL, AS THE SURFACES READ IT (#1579).
//
// `models/spiffe/*.tsp` is the source of every message of the Workload API,
// the SPIRE Server API and the Broker API (held by the build to the
// vendored protos), of each request field's refusal, of the statuses each
// service and method answers and why a method is unimplemented, of the
// SPIFFE ID grammar, of an X509-SVID leaf's rules, and of the bundle's and
// a JWT-SVID's members. The image build writes `models/generated/
// spiffe.json` and this reads it:
//
//   * `grammar()`, `svidRules()`, `registry(id)` and `notImplemented()` are
//     the facts `spiffe_id.ts`, `spiffe_auth.ts`, `spiffe_ca.ts` and
//     `spiffe_api.ts` decide with;
//   * `refusal(message, field, when, method)` is a request field's refusal:
//     the numeric status, the error code and the sentence;
//   * `holdReply(surface, method, reply)` holds what a handler hands
//     grpc-js to the method's response message BEFORE protobufjs serialises
//     it, which is where a member that is no field — a misspelt one, a
//     snake_case member of a well-known type — is dropped without a word;
//     `holdStatus()` holds the status a call ends with to the statuses its
//     service and method declare; `hold(id, value)` holds a document to a
//     member set. A gap is recorded under STS-SPIFFE-0154 / 0155 and the
//     answer is sent unchanged, because the model describes the wire and
//     does not reshape it.
//
// A LEAF: it requires `common/model_tables`, `common/error_codes` and
// bunyan, so every SPIFFE module may require it.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('../common/model_tables');
import errorCodes = require('../common/error_codes');

const log = bunyan.createLogger({
  name: 'sts-spiffe-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL: Json = ModelTables.file('spiffe.json');

// The SURFACES' NAME FOR A METHOD, which is what `spiffe_grpc.ts`'s wrappers
// are called with: the method on the Workload API and the Broker API, and
// `<Service>.<Method>` on the SPIRE Server API, whose six services share one
// surface. Keyed `<surface> <name>`.
const METHODS = new Map<string, Json>();

MODEL.services.forEach(function (service: Json) {
  const label = service.name.split('.').pop();
  service.methods.forEach(function (method: Json) {
    const name = service.surface === 'server'
      ? label + '.' + method.name : method.name;
    METHODS.set(service.surface + ' ' + name,
                { service: service, method: method, name: name });
  });
});

const MEMBER_SETS = new Map<string, Json>();

MODEL.members.forEach(function (set: Json) {
  MEMBER_SETS.set(set.id, set);
});

// The most gaps `gaps()` keeps, newest last: what a test reads back.
const GAPS_KEPT = 100;

const GAPS: string[] = [];

/**
 * The SPIFFE model: the facts the surfaces decide with, the refusals of a
 * request's fields, and the holding of what they answer.
 */
class SpiffeModel {
  /**
   * The SPIFFE ID grammar.
   *
   * @returns `{ scheme, maxBytes, maxTrustDomainBytes, trustDomainPattern,
   *   pathSegmentPattern, reservedPrefix, cite }`
   */
  static grammar(): Json {
    log.debug("Entering SpiffeModel.grammar().");
    log.debug("Leaving SpiffeModel.grammar().");
    return MODEL.grammar;
  }

  /**
   * An X509-SVID leaf's rules, in the order they are asked.
   *
   * @returns `[{ fact, equals | includes | excludes, problem }]`
   */
  static svidRules(): Json[] {
    log.debug("Entering SpiffeModel.svidRules().");
    log.debug("Leaving SpiffeModel.svidRules().");
    return MODEL.svid.leaf;
  }

  /**
   * One registry's values.
   *
   * @param id - `bundle-key-use` or `jwt-svid-typ`
   * @returns a copy of its values
   */
  static registry(id: string): string[] {
    log.debug("Entering SpiffeModel.registry().");
    const one = MODEL.registries[id];
    if (!one) {
      log.debug("Leaving SpiffeModel.registry(). No such registry.");
      throw new TypeError('The SPIFFE model has no registry ' + id);
    }
    log.debug("Leaving SpiffeModel.registry().");
    return one.values.slice(0);
  }

  /**
   * The SPIRE Server API methods this service does not implement, each
   * with its reason, by `<Service>.<Method>`.
   *
   * @returns the table
   */
  static notImplemented(): Record<string, string> {
    log.debug("Entering SpiffeModel.notImplemented().");
    const out: Record<string, string> = {};
    METHODS.forEach(function (one: Json, key: string) {
      if (key.indexOf('server ') === 0 &&
          one.method.unimplemented !== undefined) {
        out[one.name] = one.method.unimplemented;
      }
    });
    log.debug("Leaving SpiffeModel.notImplemented().");
    return out;
  }

  /**
   * Whether a request field's value, as the handler has read it, is empty:
   * absent, an empty string, list or byte string.
   *
   * @param value - the value
   * @returns true when it is
   */
  static isEmpty(value: unknown): boolean {
    log.debug("Entering SpiffeModel.isEmpty().");
    let empty = value === undefined || value === null || value === '';
    if (!empty && (Array.isArray(value) || value instanceof Uint8Array)) {
      empty = (value as any).length === 0;
    }
    log.debug("Leaving SpiffeModel.isEmpty().");
    return empty;
  }

  /**
   * One request field's refusal.
   *
   * @param message - the message's full name in the protos
   * @param field - the field
   * @param when - `empty`, `malformed` or `unexpected`
   * @param method - the method, where the message is shared and each
   *   method refuses it in its own words
   * @param reason - a malformed SPIFFE ID's sentence, for `{reason}`
   * @returns `{ status, statusName, code, message, errorInfo? }`
   */
  static refusal(message: string, field: string, when: string,
                 method?: string, reason?: string): Json {
    log.debug("Entering SpiffeModel.refusal(). " + message + '.' + field);
    const declared = MODEL.messages[message];
    const one = declared && declared.fields.find(function (f: Json) {
      return f.name === field;
    });
    const refusals = (one && one.refusals) || [];
    const found = refusals.find(function (r: Json) {
      return r.when === when && (!method || !r.method || r.method === method);
    });
    if (!found) {
      log.debug("Leaving SpiffeModel.refusal(). Not declared.");
      throw new TypeError('The SPIFFE model declares no ' + when +
                          ' refusal of ' + message + '.' + field +
                          (method ? ' in ' + method : ''));
    }
    const out: Json = {
      status: MODEL.statuses[found.status],
      statusName: found.status,
      code: found.code,
      message: found.message.split('{reason}').join(reason || '')
    };
    if (found.errorInfo) {
      out.errorInfo = found.errorInfo;
    }
    log.debug("Leaving SpiffeModel.refusal(). " + found.code);
    return out;
  }

  /**
   * Whether one value is what a field of its proto type accepts, as
   * protobufjs's `fromObject()` reads it.
   *
   * @param type - the field's type, from the model
   * @param value - the value
   * @returns true when it is
   */
  // A hot path: called for every field of every answer, so no
  // Entering/Leaving pair — it would drown the log.
  static scalarFits(type: Json, value: unknown): boolean {
    if (type.kind === 'enum') {
      const values = (MODEL.enums[type.name] || {}).values || {};
      return (typeof value === 'string' &&
              Object.prototype.hasOwnProperty.call(values, value)) ||
             (typeof value === 'number' && Number.isInteger(value));
    }
    switch (type.scalar) {
      case 'string':
        return typeof value === 'string';
      case 'bool':
        return typeof value === 'boolean';
      case 'bytes':
        return value instanceof Uint8Array || typeof value === 'string';
      case 'float':
      case 'double':
        return typeof value === 'number';
      case 'int32':
      case 'uint32':
        return typeof value === 'number' && Number.isInteger(value);
      default:
        // int64 and uint64: a number, a decimal string (`longs: String`),
        // or a Long.
        return (typeof value === 'number' && Number.isInteger(value)) ||
               (typeof value === 'string' && /^-?\d+$/.test(value)) ||
               (!!value && typeof value === 'object' &&
                typeof (value as any).low === 'number');
    }
  }

  /**
   * What a message object carries that its message does not take: a member
   * that is no field (protobufjs drops it), a value of the wrong type, and
   * the same of every message it nests. Empty when it is the model's.
   *
   * @param name - the message's full name
   * @param value - the object
   * @param where - its path, for the sentence
   * @returns one sentence per problem
   */
  // A hot path: it recurses through every answer, so no Entering/Leaving
  // pair — it would drown the log.
  static undeclared(name: string, value: unknown, where: string): string[] {
    const declared = MODEL.messages[name];
    if (!declared) {
      return [where + ' is ' + name + ', which the model does not declare'];
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return [where + ' is not a ' + name + ' message object'];
    }
    const problems: string[] = [];
    const fields = new Map<string, Json>();
    declared.fields.forEach(function (f: Json) {
      fields.set(f.name, f);
    });
    Object.keys(value).forEach(function (key) {
      const one = (value as Json)[key];
      const field = fields.get(key);
      if (!field) {
        problems.push(where + '.' + key + ' is no field of ' + name +
                      ', so it serialises to nothing');
        return;
      }
      if (one === undefined || one === null) {
        return;
      }
      const check = function (item: unknown, at: string): void {
        if (field.type.kind === 'message') {
          SpiffeModel.undeclared(field.type.name, item, at)
            .forEach(function (p) {
              problems.push(p);
            });
        } else if (!SpiffeModel.scalarFits(field.type, item)) {
          problems.push(at + ' is not a ' +
                        (field.type.scalar || field.type.name));
        }
      };
      if (field.repeated) {
        if (!Array.isArray(one)) {
          problems.push(where + '.' + key + ' is repeated and not a list');
          return;
        }
        one.forEach(function (item: unknown, i: number) {
          check(item, where + '.' + key + '[' + i + ']');
        });
      } else if (field.map) {
        if (typeof one !== 'object' || Array.isArray(one)) {
          problems.push(where + '.' + key + ' is a map and not an object');
          return;
        }
        Object.keys(one).forEach(function (k) {
          check(one[k], where + '.' + key + '[' + k + ']');
        });
      } else {
        check(one, where + '.' + key);
      }
    });
    return problems;
  }

  /**
   * The method a surface registers under a name, from the model.
   *
   * @param surface - `workload`, `server` or `broker`
   * @param name - the method, `<Service>.<Method>` on the SPIRE Server API
   * @returns `{ service, method, name }`, or undefined
   */
  static methodOf(surface: string, name: string): Json | undefined {
    log.debug("Entering SpiffeModel.methodOf().");
    log.debug("Leaving SpiffeModel.methodOf().");
    return METHODS.get(surface + ' ' + name);
  }

  /**
   * Holds what a handler answers to its method's response message, and
   * records what does not fit under STS-SPIFFE-0154. The answer is not
   * touched.
   *
   * @param surface - the surface
   * @param name - the method, as the surface names it
   * @param reply - the message about to be written
   * @returns the problems, empty when the answer is the model's
   */
  static holdReply(surface: string, name: string, reply: unknown): string[] {
    log.debug("Entering SpiffeModel.holdReply(). " + name);
    const one = SpiffeModel.methodOf(surface, name);
    let problems: string[];
    if (!one) {
      problems = ['the ' + surface + ' method ' + name + ' is not in the ' +
                  'model'];
    } else {
      // The response of an AttestAgent conversation is its challenge as well
      // as its result, and both are AttestAgentResponse: one message.
      try {
        problems = SpiffeModel.undeclared(one.method.response, reply,
                                          one.method.response);
      } catch (e) {
        log.debug("Caught in SpiffeModel.holdReply(): " +
                  ((e && e.message) || e));
        problems = ['the answer could not be held: ' +
                    ((e && e.message) || e)];
      }
    }
    if (problems.length > 0) {
      log.error(errorCodes.tag('STS-SPIFFE-0154') + 'the ' + surface + ' ' +
                name + ' answer is not its model\'s: ' + problems.join('; '));
      SpiffeModel.remember(surface + ' ' + name + ': ' + problems.join('; '));
    }
    log.debug("Leaving SpiffeModel.holdReply(). " + problems.length);
    return problems;
  }

  /**
   * Holds the status a call ends with to the statuses its service and
   * method declare, and records one they do not under STS-SPIFFE-0155. The
   * status is not touched.
   *
   * @param surface - the surface
   * @param name - the method, as the surface names it
   * @param code - the numeric gRPC status
   * @returns true when the model does not declare it
   */
  static holdStatus(surface: string, name: string, code: number): boolean {
    log.debug("Entering SpiffeModel.holdStatus(). " + name + ' ' + code);
    const one = SpiffeModel.methodOf(surface, name);
    const named = Object.keys(MODEL.statuses).find(function (key) {
      return MODEL.statuses[key] === code;
    }) || String(code);
    const allowed = one ? ['OK'].concat(one.service.statuses,
                                        one.method.statuses) : [];
    const undeclared = allowed.indexOf(named) < 0;
    if (undeclared) {
      log.error(errorCodes.tag('STS-SPIFFE-0155') + 'the ' + surface + ' ' +
                name + ' call ended ' + named + ', which models/spiffe ' +
                'does not declare for it.');
      SpiffeModel.remember(surface + ' ' + name + ': the status ' + named);
    }
    log.debug("Leaving SpiffeModel.holdStatus().");
    return undeclared;
  }

  /**
   * Whether a JSON value is one of the types a member may take.
   *
   * @param value - the value
   * @param types - from the model
   * @returns true when it is
   */
  // A hot path through every member: no Entering/Leaving pair.
  static fits(value: unknown, types: string[]): boolean {
    return types.some(function (type) {
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
  }

  /**
   * What a document carries that its member set does not allow — a member
   * a closed set does not name, a type or value the set does not allow, a
   * required member missing — and the same of every set it nests.
   *
   * @param id - the member set's id
   * @param value - the document
   * @param where - its path, for the sentence
   * @returns one sentence per problem
   */
  static members(id: string, value: unknown, where?: string): string[] {
    log.debug("Entering SpiffeModel.members().");
    const at = where || id;
    const set = MEMBER_SETS.get(id);
    if (!set) {
      log.debug("Leaving SpiffeModel.members(). No such set.");
      throw new TypeError('The SPIFFE model has no member set ' + id);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      log.debug("Leaving SpiffeModel.members(). Not an object.");
      return [at + ' is not an object'];
    }
    const problems: string[] = [];
    const doc = value as Json;
    const named = new Map<string, Json>();
    set.list.forEach(function (member: Json) {
      named.set(member.name, member);
    });
    Object.keys(doc).forEach(function (key) {
      const member = named.get(key);
      const one = doc[key];
      if (!member) {
        if (set.members === 'closed') {
          problems.push(at + '.' + key + ' is not a member of ' + id);
        }
        return;
      }
      if (one === undefined) {
        return;
      }
      if (!SpiffeModel.fits(one, member.types)) {
        problems.push(at + '.' + key + ' is not ' + member.types.join(' or '));
        return;
      }
      if (member.values && member.values.indexOf(one) < 0) {
        problems.push(at + '.' + key + ' is not one of ' +
                      member.values.join(', '));
      }
      if (member.set && Array.isArray(one)) {
        one.forEach(function (item: unknown, i: number) {
          SpiffeModel.members(member.set, item, at + '.' + key + '[' + i +
                              ']').forEach(function (p) {
            problems.push(p);
          });
        });
      }
    });
    set.list.forEach(function (member: Json) {
      if (member.required && doc[member.name] === undefined) {
        problems.push(at + '.' + member.name + ' is required in ' + id);
      }
    });
    log.debug("Leaving SpiffeModel.members(). " + problems.length);
    return problems;
  }

  /**
   * Holds a document — a bundle, a JWT-SVID's header or claims — to its
   * member set, and records what does not fit under STS-SPIFFE-0154. The
   * document is not touched.
   *
   * @param id - the member set's id
   * @param value - the document
   * @param where - what it is, for the log line
   * @returns the problems, empty when it is the model's
   */
  static hold(id: string, value: unknown, where: string): string[] {
    log.debug("Entering SpiffeModel.hold(). " + id);
    let problems: string[];
    try {
      problems = SpiffeModel.members(id, value);
    } catch (e) {
      log.debug("Caught in SpiffeModel.hold(): " + ((e && e.message) || e));
      problems = ['it could not be held to ' + id + ': ' +
                  ((e && e.message) || e)];
    }
    if (problems.length > 0) {
      log.error(errorCodes.tag('STS-SPIFFE-0154') + where + ' is not its ' +
                'model\'s (' + id + '): ' + problems.join('; '));
      SpiffeModel.remember(where + ': ' + problems.join('; '));
    }
    log.debug("Leaving SpiffeModel.hold(). " + problems.length);
    return problems;
  }

  private static remember(gap: string): void {
    log.debug("Entering SpiffeModel.remember().");
    GAPS.push(gap);
    if (GAPS.length > GAPS_KEPT) {
      GAPS.shift();
    }
    log.debug("Leaving SpiffeModel.remember().");
  }

  /**
   * The gaps this process recorded, newest last, at most a hundred.
   *
   * @returns a copy
   */
  static gaps(): string[] {
    log.debug("Entering SpiffeModel.gaps().");
    log.debug("Leaving SpiffeModel.gaps().");
    return GAPS.slice(0);
  }
}

export = SpiffeModel;
