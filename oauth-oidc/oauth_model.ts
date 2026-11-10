// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: oauth-oidc/oauth_model.ts
//
// ---------------------------------------------------------------------------
// THE OAUTH 2.0 AND OPENID CONNECT MODEL, AS THE ENDPOINTS READ IT (#1579).
//
// `models/oauth/oauth.tsp` and `oauth_members.tsp` are the source of every
// endpoint's request parameters, of the members of the discovery documents
// and of every answer, of the claim sets this service issues and of the
// error codes it sends. The image build writes `models/generated/oauth.json`
// and this reads it:
//
//   * `request(id)` is the zod object an endpoint checks its input against
//     with `validation.check()` / `checkParsed()`, BUILT FROM THE MODEL. Each
//     parameter becomes exactly the expression the hand-written schema had —
//     the shared type of `common/validation.js` it names, its bounds in the
//     order they were written, `repeatable()` and `opt()` — so a refusal
//     reads, word for word, as it always did (`tests/oauth_model_wire.js`).
//   * `undeclared(id, value)` and `unknownError(code)` are the holding: what
//     a member set or the error list does not name. The callers record what
//     they find under STS-OAUTH-1005 / 1006 and send the answer unchanged,
//     because the model describes the wire and does not reshape it.
//
// A LEAF: it requires `common/validation`, `common/model_tables` and bunyan.
// ---------------------------------------------------------------------------

import bunyan = require('bunyan');
import ModelTables = require('../common/model_tables');
import validation = require('../common/validation');

const log = bunyan.createLogger({
  name: 'sts-oauth-model',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

type Json = Record<string, any>;

const MODEL: Json = ModelTables.file('oauth.json');

const REQUESTS = new Map<string, any>();

const MEMBER_SETS = new Map<string, Json>();

MODEL.members.forEach(function (set: Json) {
  MEMBER_SETS.set(set.id, set);
});

const ERROR_CODES = new Set<string>(MODEL.errors.map(function (one: Json) {
  return one.code;
}));

/**
 * The OAuth 2.0 and OpenID Connect model: the request validators built from
 * it and the holding of what the endpoints answer.
 */
class OAuthModel {
  /**
   * The zod type of one parameter, as the hand-written schema wrote it.
   *
   * @param param - one parameter of `oauth.json`
   * @returns the zod type
   */
  static paramType(param: Json): any {
    log.debug("Entering OAuthModel.paramType().");
    const vt: any = validation.types;
    const vz: any = validation.z;
    let out: any;
    if (param.kind === 'integer') {
      out = vt.integer(param.minimum, param.maximum);
    } else if (param.kind === 'string') {
      out = vz.string();
      if (param.minLength !== undefined) {
        out = out.min(param.minLength);
      }
      if (param.maxLength !== undefined) {
        out = out.max(param.maxLength);
      }
      if (param.cap !== undefined) {
        out = out.max((validation.CAP as Json)[param.cap]);
      }
      if (param.pattern !== undefined) {
        out = out.regex(new RegExp(param.pattern));
      }
    } else if (vt[param.kind]) {
      out = vt[param.kind];
    } else {
      log.debug("Leaving OAuthModel.paramType(). An unknown kind.");
      throw new TypeError('No validator can be generated for the kind ' +
        param.kind + ' of ' + param.name);
    }
    if (param.repeatable) {
      out = vt.repeatable(out);
    }
    if (param.empty) {
      out = vt.opt(out);
    } else if (!param.required) {
      out = out.optional();
    }
    log.debug("Leaving OAuthModel.paramType().");
    return out;
  }

  /**
   * One endpoint's request validator, built once.
   *
   * @param id - the endpoint's id in the model, such as `token`
   * @returns the zod object
   */
  static request(id: string): any {
    log.debug("Entering OAuthModel.request().");
    if (!REQUESTS.has(id)) {
      const endpoint = MODEL.endpoints.find(function (one: Json) {
        return one.id === id;
      });
      if (!endpoint) {
        log.debug("Leaving OAuthModel.request(). No such endpoint.");
        throw new TypeError('The OAuth model has no endpoint ' + id);
      }
      const shape: Json = {};
      endpoint.params.forEach(function (param: Json) {
        shape[param.name] = OAuthModel.paramType(param);
      });
      const vz: any = validation.z;
      REQUESTS.set(id, endpoint.passThrough ? vz.looseObject(shape)
        : vz.object(shape));
    }
    log.debug("Leaving OAuthModel.request().");
    return REQUESTS.get(id);
  }

  /**
   * One member set: a discovery document, an answer or a claim set.
   *
   * @param id - the set's id in the model
   * @returns `{ id, cite, members, list }`
   */
  static members(id: string): Json {
    log.debug("Entering OAuthModel.members().");
    const set = MEMBER_SETS.get(id);
    if (!set) {
      log.debug("Leaving OAuthModel.members(). No such set.");
      throw new TypeError('The OAuth model has no member set ' + id);
    }
    log.debug("Leaving OAuthModel.members().");
    return set;
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
    log.debug("Entering OAuthModel.fits().");
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
    log.debug("Leaving OAuthModel.fits().");
    return fits;
  }

  /**
   * What an answer carries that its member set does not allow: a member a
   * closed set does not name, a named member of a type the set does not
   * allow, and a required member missing. Empty when the answer is the
   * model's.
   *
   * @param id - the member set's id
   * @param value - the answer, or a claim set
   * @returns one sentence per problem
   */
  static undeclared(id: string, value: Json): string[] {
    log.debug("Entering OAuthModel.undeclared().");
    const set = OAuthModel.members(id);
    const named = new Map<string, Json>();
    set.list.forEach(function (member: Json) {
      named.set(member.name, member);
    });
    const problems: string[] = [];
    Object.keys(value || {}).forEach(function (key) {
      const member = named.get(key);
      if (!member) {
        if (set.members === 'closed') {
          problems.push(key + ' is not a member of ' + id);
        }
        return;
      }
      if (value[key] !== undefined &&
          !OAuthModel.fits(value[key], member.types)) {
        problems.push(key + ' is not ' + member.types.join(' or '));
      }
    });
    set.list.forEach(function (member: Json) {
      if (member.required && (!value || value[member.name] === undefined)) {
        problems.push(member.name + ' is required in ' + id);
      }
    });
    log.debug("Leaving OAuthModel.undeclared(). " + problems.length);
    return problems;
  }

  /**
   * Whether an error code is one the model declares.
   *
   * @param code - the `error` value
   * @returns true when the model does not declare it
   */
  static unknownError(code: string): boolean {
    log.debug("Entering OAuthModel.unknownError().");
    log.debug("Leaving OAuthModel.unknownError().");
    return !ERROR_CODES.has(code);
  }

  /**
   * Every error code the model declares, with the document defining it.
   *
   * @returns `[{ code, cite }]`
   */
  static errors(): Json[] {
    log.debug("Entering OAuthModel.errors().");
    log.debug("Leaving OAuthModel.errors().");
    return MODEL.errors.slice(0);
  }
}

export = OAuthModel;
