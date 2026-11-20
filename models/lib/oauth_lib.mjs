// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/oauth_lib.mjs
//
// ---------------------------------------------------------------------------
// THE OAUTH 2.0 AND OPENID CONNECT MODEL, READ FROM A COMPILED PROGRAM (#1579).
//
// `readOAuth()` turns the `@endpoint`, `@members` and `@errorCodes` models
// into the tables `models/generated/oauth.json` holds: every endpoint's
// parameters with the shared type each is checked as, every discovery
// document's, answer's and claim set's members with the JSON types each may
// take, and the error codes. `checkOAuth()` refuses a model a validator
// could not be generated from faithfully — a bound on a type that takes
// none, a string with no bound, a pattern that does not compile, a name
// declared twice — and the problem stops the image build.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-oauth-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const ENDPOINT = Symbol.for('iya.oauth.endpoint');
const PARAM = Symbol.for('iya.oauth.param');
const MEMBERS = Symbol.for('iya.oauth.members');
const MEMBER = Symbol.for('iya.oauth.member');
const ERRORS = Symbol.for('iya.oauth.errors');
const ERROR = Symbol.for('iya.oauth.error');

// The JSON type each TypeSpec scalar is, by the standard library's name.
const SCALARS = { string: 'string', url: 'string', boolean: 'boolean',
  int8: 'integer', int16: 'integer', int32: 'integer', int64: 'integer',
  integer: 'integer', safeint: 'integer', uint8: 'integer',
  uint16: 'integer', uint32: 'integer', uint64: 'integer',
  float32: 'number', float64: 'number', numeric: 'number',
  decimal: 'number', unknown: 'any' };

// The shared types that take no bound of their own: each carries its own.
const BOUNDED_KINDS = ['identifier', 'name', 'redirectUri', 'scope',
  'opaque', 'uri', 'base64url'];

export const $decorators = {
  'IyaSts.OAuthLib': {
    endpoint: function (context, target, options) {
      context.program.stateMap(ENDPOINT).set(target, options);
    },
    param: function (context, target, options) {
      context.program.stateMap(PARAM).set(target, options);
    },
    members: function (context, target, options) {
      context.program.stateMap(MEMBERS).set(target, options);
    },
    member: function (context, target, options) {
      context.program.stateMap(MEMBER).set(target, options);
    },
    errorCodes: function (context, target) {
      context.program.stateMap(ERRORS).set(target, true);
    },
    errorCode: function (context, target, options) {
      context.program.stateMap(ERROR).set(target, options);
    }
  }
};

/**
 * The JSON types a TypeSpec type may be, as `typeof`-like names: `string`,
 * `integer`, `number`, `boolean`, `array`, `object`, or `any`.
 *
 * @param type - the TypeSpec type
 * @returns the names
 */
function jsonTypesOf(type) {
  log.debug("Entering jsonTypesOf().");
  if (type.kind === 'Model' && type.name === 'Array' && type.indexer) {
    log.debug("Leaving jsonTypesOf(). An array.");
    return ['array'];
  }
  if (type.kind === 'Model') {
    log.debug("Leaving jsonTypesOf(). An object.");
    return ['object'];
  }
  if (type.kind === 'String') {
    log.debug("Leaving jsonTypesOf(). A string literal.");
    return ['string'];
  }
  if (type.kind === 'Boolean') {
    log.debug("Leaving jsonTypesOf(). A boolean literal.");
    return ['boolean'];
  }
  if (type.kind === 'Number') {
    log.debug("Leaving jsonTypesOf(). A number literal.");
    return ['number'];
  }
  if (type.kind === 'Union') {
    const out = [];
    type.variants.forEach(function (variant) {
      jsonTypesOf(variant.type).forEach(function (one) {
        if (out.indexOf(one) < 0) {
          out.push(one);
        }
      });
    });
    log.debug("Leaving jsonTypesOf(). A union.");
    return out;
  }
  if (type.kind === 'Scalar') {
    let scalar = type;
    while (scalar && !SCALARS[scalar.name]) {
      scalar = scalar.baseScalar;
    }
    log.debug("Leaving jsonTypesOf(). A scalar.");
    return [scalar ? SCALARS[scalar.name] : 'unknown'];
  }
  if (type.kind === 'Intrinsic' && type.name === 'unknown') {
    log.debug("Leaving jsonTypesOf(). Anything.");
    return ['any'];
  }
  log.debug("Leaving jsonTypesOf(). Not a type a member may have.");
  return ['unknown'];
}

/**
 * One parameter of an endpoint, as the service builds its check.
 *
 * @param program - the compiled program
 * @param property - the property
 * @returns the parameter
 */
function paramOf(program, property) {
  log.debug("Entering paramOf().");
  const options = program.stateMap(PARAM).get(property) || {};
  let type = property.type;
  const repeatable = type.kind === 'Model' && type.name === 'Array' &&
    !!type.indexer;
  if (repeatable) {
    type = type.indexer.value;
  }
  const out = {
    name: property.name,
    kind: options.kind || 'string',
    types: jsonTypesOf(type),
    required: property.optional !== true,
    repeatable: repeatable,
    empty: options.empty === true,
    cite: options.cite || ''
  };
  ['minLength', 'maxLength', 'cap', 'pattern', 'minimum', 'maximum']
    .forEach(function (key) {
      if (options[key] !== undefined) {
        out[key] = options[key];
      }
    });
  log.debug("Leaving paramOf().");
  return out;
}

/**
 * One member of a discovery document, an answer or a claim set.
 *
 * @param program - the compiled program
 * @param property - the property
 * @returns the member
 */
function memberOf(program, property) {
  log.debug("Entering memberOf().");
  const options = program.stateMap(MEMBER).get(property) || {};
  const out = {
    name: property.name,
    types: jsonTypesOf(property.type),
    required: property.optional !== true,
    cite: options.cite || ''
  };
  // What an array's members may be, for a check that reads each one.
  if (property.type.kind === 'Model' && property.type.name === 'Array' &&
      property.type.indexer) {
    out.items = jsonTypesOf(property.type.indexer.value);
  }
  if (options.own === true) {
    out.own = true;
  }
  log.debug("Leaving memberOf().");
  return out;
}

/**
 * Every endpoint's request, every set of members and the error codes in a
 * compiled program.
 *
 * @param program - the compiled program
 * @returns `{ endpoints, members, errors }`
 */
export function readOAuth(program) {
  log.debug("Entering readOAuth().");
  const endpoints = [];
  program.stateMap(ENDPOINT).forEach(function (options, model) {
    const params = [];
    model.properties.forEach(function (property) {
      params.push(paramOf(program, property));
    });
    endpoints.push({ id: options.id, paths: options.paths.slice(0),
                     methods: options.methods.slice(0), input: options.input,
                     passThrough: options.passThrough === true,
                     cite: options.cite, model: model.name,
                     params: params });
  });
  const members = [];
  program.stateMap(MEMBERS).forEach(function (options, model) {
    const list = [];
    model.properties.forEach(function (property) {
      list.push(memberOf(program, property));
    });
    members.push({ id: options.id, cite: options.cite,
                   members: options.members, model: model.name,
                   list: list });
  });
  const errors = [];
  program.stateMap(ERRORS).forEach(function (flag, model) {
    model.properties.forEach(function (property) {
      const options = program.stateMap(ERROR).get(property) || {};
      errors.push({ code: property.name, cite: options.cite || '' });
    });
  });
  log.debug("Leaving readOAuth(). " + endpoints.length + " endpoint(s), " +
            members.length + " member set(s), " + errors.length +
            " error code(s).");
  return { endpoints: endpoints, members: members, errors: errors };
}

/**
 * The problems of one parameter: a validator generated from it would not be
 * the check its declaration says.
 *
 * @param where - the endpoint's id
 * @param param - from `readOAuth()`
 * @param problems - where a problem is added
 */
function paramProblems(where, param, problems) {
  log.debug("Entering paramProblems().");
  const at = where + '.' + param.name;
  const lengthy = ['minLength', 'maxLength', 'cap', 'pattern']
    .filter(function (key) {
      return param[key] !== undefined;
    });
  const bounded = ['minimum', 'maximum'].filter(function (key) {
    return param[key] !== undefined;
  });
  if (!param.cite) {
    problems.push(at + ' cites nothing');
  }
  if (param.kind === 'integer') {
    if (param.types.join() !== 'integer') {
      problems.push(at + ' is checked as an integer and is not one');
    }
    if (lengthy.length > 0) {
      problems.push(at + ' is an integer and takes ' + lengthy.join(', '));
    }
    if (bounded.length !== 2) {
      problems.push(at + ' is an integer with no minimum and maximum');
    }
  } else {
    if (param.types.join() !== 'string') {
      problems.push(at + ' is checked as ' + param.kind +
                    ' and is not a string');
    }
    if (bounded.length > 0) {
      problems.push(at + ' is not an integer and takes ' + bounded.join());
    }
  }
  if (BOUNDED_KINDS.indexOf(param.kind) >= 0 && lengthy.length > 0) {
    problems.push(at + ' is checked as ' + param.kind + ', which carries ' +
                  'its own bound, and also takes ' + lengthy.join(', '));
  }
  if (param.kind === 'string') {
    if (param.maxLength === undefined && param.cap === undefined) {
      problems.push(at + ' is a string with no bound');
    }
    if (param.maxLength !== undefined && param.cap !== undefined) {
      problems.push(at + ' states its bound twice');
    }
  }
  if (param.pattern !== undefined) {
    try {
      new RegExp(param.pattern);
    } catch (e) {
      log.debug("Caught in paramProblems(): " + ((e && e.message) || e));
      problems.push(at + '\'s pattern does not compile: ' + e.message);
    }
  }
  if (param.required && (param.empty || param.repeatable)) {
    problems.push(at + ' is required and may be empty or repeat');
  }
  log.debug("Leaving paramProblems().");
}

/**
 * Holds the model to what a validator and a check can be generated from.
 *
 * @param oauth - from `readOAuth()`
 * @returns the problems, empty when there are none
 */
export function checkOAuth(oauth) {
  log.debug("Entering checkOAuth().");
  const problems = [];
  const seen = new Set();
  oauth.endpoints.forEach(function (endpoint) {
    if (seen.has('endpoint:' + endpoint.id)) {
      problems.push('the endpoint ' + endpoint.id + ' is declared twice');
    }
    seen.add('endpoint:' + endpoint.id);
    if (!endpoint.cite) {
      problems.push('the endpoint ' + endpoint.id + ' cites nothing');
    }
    endpoint.paths.forEach(function (one) {
      if (one.charAt(0) !== '/') {
        problems.push('the endpoint ' + endpoint.id + '\'s path ' + one +
                      ' is not absolute');
      }
    });
    if (endpoint.params.length === 0) {
      problems.push('the endpoint ' + endpoint.id + ' has no parameter');
    }
    endpoint.params.forEach(function (param) {
      paramProblems(endpoint.id, param, problems);
    });
  });
  oauth.members.forEach(function (set) {
    if (seen.has('members:' + set.id)) {
      problems.push('the member set ' + set.id + ' is declared twice');
    }
    seen.add('members:' + set.id);
    if (!set.cite) {
      problems.push('the member set ' + set.id + ' cites nothing');
    }
    if (set.list.length === 0) {
      problems.push('the member set ' + set.id + ' has no member');
    }
    set.list.forEach(function (member) {
      if (!member.cite) {
        problems.push(set.id + '.' + member.name + ' cites nothing');
      }
      if (member.types.indexOf('unknown') >= 0) {
        problems.push(set.id + '.' + member.name + ' has a type no JSON ' +
                      'value is');
      }
    });
  });
  const codes = new Set();
  oauth.errors.forEach(function (error) {
    if (codes.has(error.code)) {
      problems.push('the error code ' + error.code + ' is declared twice');
    }
    codes.add(error.code);
    if (!error.cite) {
      problems.push('the error code ' + error.code + ' cites nothing');
    }
    if (!/^[\x20\x21\x23-\x5B\x5D-\x7E]+$/.test(error.code)) {
      problems.push('the error code ' + error.code + ' is outside RFC 6749 ' +
                    'section 5.2\'s character set');
    }
  });
  if (oauth.errors.length === 0) {
    problems.push('no error code is declared');
  }
  log.debug("Leaving checkOAuth(). " + problems.length + " problem(s).");
  return problems;
}
