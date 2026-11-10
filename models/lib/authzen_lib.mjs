// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/authzen_lib.mjs
//
// ---------------------------------------------------------------------------
// THE AUTHZEN MODEL, READ FROM A COMPILED PROGRAM (#1579).
//
// `readAuthzen()` turns the `@request`, `@members` and `@problemTypes`
// models into the tables `models/generated/authzen.json` holds: every
// request's fields, in the order they are checked, with what each is and
// how it is refused; every answer's members with the JSON types each may
// take; the Obligations Profile's registered types; and the Access Request
// and Approval Profile's problem types. `checkAuthzen()` refuses a model a
// reader could not be built from faithfully — an option on a kind of field
// it does not apply to, a sentence naming a placeholder nobody fills, a
// default that is not one of the values, a forbidden member with nothing to
// say, a name declared twice, a missing citation — and the problem stops
// the image build.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-authzen-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const REQUEST = Symbol.for('iya.authzen.request');
const FIELD = Symbol.for('iya.authzen.field');
const MEMBERS = Symbol.for('iya.authzen.members');
const MEMBER = Symbol.for('iya.authzen.member');
const PROBLEMS = Symbol.for('iya.authzen.problems');
const PROBLEM = Symbol.for('iya.authzen.problem');

// The JSON type each TypeSpec scalar is, by the standard library's name.
const SCALARS = { string: 'string', url: 'string', boolean: 'boolean',
  int8: 'integer', int16: 'integer', int32: 'integer', int64: 'integer',
  integer: 'integer', safeint: 'integer', uint8: 'integer',
  uint16: 'integer', uint32: 'integer', uint64: 'integer',
  float32: 'number', float64: 'number', numeric: 'number',
  decimal: 'number', unknown: 'any' };

// The placeholders a sentence may name.
const PLACEHOLDERS = ['path', 'member', 'members', 'membersAnd', 'required',
                      'maxLength', 'values'];

// The options that apply to one kind of field only.
const KIND_OPTIONS = {
  maxLength: ['string'], nonEmpty: ['string'], maxItems: ['array'],
  itemMaxLength: ['array'], itemRefusal: ['array'], minimum: ['integer'],
  requireOne: ['object'],
  open: ['object'], coerce: ['values'], default: ['values']
};

export const $decorators = {
  'IyaSts.AuthZenLib': {
    request: function (context, target, options) {
      context.program.stateMap(REQUEST).set(target, options);
    },
    field: function (context, target, options) {
      context.program.stateMap(FIELD).set(target, options);
    },
    members: function (context, target, options) {
      context.program.stateMap(MEMBERS).set(target, options);
    },
    member: function (context, target, options) {
      context.program.stateMap(MEMBER).set(target, options);
    },
    problemTypes: function (context, target, options) {
      context.program.stateMap(PROBLEMS).set(target, options);
    },
    problemType: function (context, target, options) {
      context.program.stateMap(PROBLEM).set(target, options);
    }
  }
};

/**
 * The scalar a TypeSpec scalar is, by the standard library's name.
 *
 * @param type - the scalar
 * @returns its JSON type, or 'unknown'
 */
function scalarOf(type) {
  log.debug("Entering scalarOf().");
  let scalar = type;
  while (scalar && !SCALARS[scalar.name]) {
    scalar = scalar.baseScalar;
  }
  log.debug("Leaving scalarOf().");
  return scalar ? SCALARS[scalar.name] : 'unknown';
}

/**
 * The JSON types a TypeSpec type may be: `string`, `integer`, `number`,
 * `boolean`, `array`, `object`, or `any`.
 *
 * @param type - the TypeSpec type
 * @returns the names
 */
function jsonTypesOf(type) {
  log.debug("Entering jsonTypesOf().");
  let out;
  if (type.kind === 'Model' && type.name === 'Array' && type.indexer) {
    out = ['array'];
  } else if (type.kind === 'Model' || type.kind === 'Intrinsic' &&
             type.name === 'null') {
    out = type.kind === 'Model' ? ['object'] : ['null'];
  } else if (type.kind === 'String') {
    out = ['string'];
  } else if (type.kind === 'Boolean') {
    out = ['boolean'];
  } else if (type.kind === 'Number') {
    out = ['number'];
  } else if (type.kind === 'Union') {
    out = [];
    type.variants.forEach(function (variant) {
      jsonTypesOf(variant.type).forEach(function (one) {
        if (out.indexOf(one) < 0) {
          out.push(one);
        }
      });
    });
  } else if (type.kind === 'Scalar') {
    out = [scalarOf(type)];
  } else if (type.kind === 'Intrinsic' && type.name === 'unknown') {
    out = ['any'];
  } else {
    out = ['unknown'];
  }
  log.debug("Leaving jsonTypesOf().");
  return out;
}

/**
 * What kind of field a TypeSpec type is: `object`, `string`, `array`,
 * `integer`, `boolean`, `values` (a union of string literals), `any` or
 * `never`.
 *
 * @param type - the TypeSpec type
 * @returns the kind
 */
function kindOf(type) {
  log.debug("Entering kindOf().");
  let kind = 'unknown';
  if (type.kind === 'Intrinsic' && type.name === 'never') {
    kind = 'never';
  } else if (type.kind === 'Intrinsic' && type.name === 'unknown') {
    kind = 'any';
  } else if (type.kind === 'Model' && type.name === 'Array' && type.indexer) {
    kind = 'array';
  } else if (type.kind === 'Model') {
    kind = 'object';
  } else if (type.kind === 'Union' &&
             Array.from(type.variants.values()).every(function (variant) {
               return variant.type.kind === 'String';
             })) {
    kind = 'values';
  } else if (type.kind === 'Scalar') {
    kind = scalarOf(type);
  }
  log.debug("Leaving kindOf(). " + kind);
  return kind;
}

/**
 * One field of a request, and the fields of an object field, in order.
 *
 * @param program - the compiled program
 * @param property - the property
 * @returns the field
 */
function fieldOf(program, property) {
  log.debug("Entering fieldOf().");
  const options = program.stateMap(FIELD).get(property) || {};
  const type = property.type;
  const out = { name: property.name, kind: kindOf(type),
                required: property.optional !== true,
                cite: options.cite || '' };
  ['code', 'refusal', 'absent', 'maxLength', 'nonEmpty', 'maxItems',
   'itemMaxLength', 'itemRefusal', 'minimum', 'requireOne', 'coerce',
   'default', 'open',
   'deferred'].forEach(function (key) {
    if (options[key] !== undefined) {
      out[key] = options[key];
    }
  });
  if (out.kind === 'array') {
    out.items = kindOf(type.indexer.value);
  }
  if (out.kind === 'values') {
    out.values = Array.from(type.variants.values()).map(function (variant) {
      return variant.type.value;
    });
  }
  if (out.kind === 'object') {
    out.fields = [];
    type.properties.forEach(function (inner) {
      out.fields.push(fieldOf(program, inner));
    });
  }
  log.debug("Leaving fieldOf().");
  return out;
}

/**
 * Every request, every set of members and the problem types in a compiled
 * program.
 *
 * @param program - the compiled program
 * @returns `{ requests, members, problems }`
 */
export function readAuthzen(program) {
  log.debug("Entering readAuthzen().");
  const requests = [];
  program.stateMap(REQUEST).forEach(function (options, model) {
    const fields = [];
    model.properties.forEach(function (property) {
      fields.push(fieldOf(program, property));
    });
    const out = { id: options.id, cite: options.cite,
                  paths: options.paths.slice(0),
                  methods: options.methods.slice(0),
                  notObject: options.notObject,
                  codes: Object.assign({}, options.codes),
                  sentences: Object.assign({}, options.sentences),
                  model: model.name, fields: fields };
    if (options.stray !== undefined) {
      out.stray = options.stray;
    }
    requests.push(out);
  });
  const members = [];
  program.stateMap(MEMBERS).forEach(function (options, model) {
    const list = [];
    model.properties.forEach(function (property) {
      const one = program.stateMap(MEMBER).get(property) || {};
      const member = { name: property.name,
                       types: jsonTypesOf(property.type),
                       required: property.optional !== true,
                       cite: one.cite || '' };
      if (one.own === true) {
        member.own = true;
      }
      // A member whose type is another member set is held to it too.
      const held = kindOf(property.type) === 'array'
        ? property.type.indexer.value : property.type;
      if (held.kind === 'Model' && program.stateMap(MEMBERS).has(held)) {
        member.set = program.stateMap(MEMBERS).get(held).id;
      }
      if (kindOf(property.type) === 'values') {
        member.values = Array.from(property.type.variants.values())
          .map(function (variant) {
            return variant.type.value;
          });
      }
      list.push(member);
    });
    const set = { id: options.id, cite: options.cite,
                  members: options.members, model: model.name, list: list };
    if (options.obligation === true) {
      set.obligation = true;
    }
    members.push(set);
  });
  const problems = { prefix: '', cite: '', types: [] };
  program.stateMap(PROBLEMS).forEach(function (options, model) {
    problems.prefix = options.prefix;
    problems.cite = options.cite;
    model.properties.forEach(function (property) {
      const one = program.stateMap(PROBLEM).get(property) || {};
      problems.types.push({ type: property.name, title: one.title || '',
                            cite: one.cite || '' });
    });
  });
  log.debug("Leaving readAuthzen(). " + requests.length + " request(s), " +
            members.length + " member set(s), " + problems.types.length +
            " problem type(s).");
  return { requests: requests, members: members, problems: problems };
}

/**
 * The placeholders a sentence names that no reader fills.
 *
 * @param sentence - the template
 * @returns the unknown names
 */
function unknownPlaceholders(sentence) {
  log.debug("Entering unknownPlaceholders().");
  const out = [];
  String(sentence || '').replace(/\{([A-Za-z]+)\}/g, function (all, name) {
    if (PLACEHOLDERS.indexOf(name) < 0) {
      out.push(name);
    }
    return all;
  });
  log.debug("Leaving unknownPlaceholders().");
  return out;
}

/**
 * The problems of one field and of the fields it holds.
 *
 * @param at - the field's dotted path, with its request's id
 * @param field - from `readAuthzen()`
 * @param problems - where a problem is added
 */
function fieldProblems(at, field, problems) {
  log.debug("Entering fieldProblems().");
  if (!field.cite) {
    problems.push(at + ' cites nothing');
  }
  if (field.kind === 'unknown') {
    problems.push(at + ' has a type no field may have');
  }
  Object.keys(KIND_OPTIONS).forEach(function (key) {
    if (field[key] !== undefined &&
        KIND_OPTIONS[key].indexOf(field.kind) < 0) {
      problems.push(at + ' is ' + field.kind + ' and takes ' + key);
    }
  });
  if (field.kind === 'never' && !field.refusal) {
    problems.push(at + ' may not be sent and says nothing when it is');
  }
  if (field.kind === 'array' && field.itemMaxLength !== undefined &&
      field.items !== 'string') {
    problems.push(at + '\'s items are not strings and take itemMaxLength');
  }
  if (field.default !== undefined &&
      (field.values || []).indexOf(field.default) < 0) {
    problems.push(at + '\'s default is not one of its values');
  }
  if (field.requireOne !== undefined) {
    field.requireOne.forEach(function (name) {
      if (!(field.fields || []).some(function (one) {
        return one.name === name;
      })) {
        problems.push(at + ' requires one of ' + name + ', which it does ' +
                      'not declare');
      }
    });
  }
  ['refusal', 'absent', 'itemRefusal'].forEach(function (key) {
    unknownPlaceholders(field[key]).forEach(function (name) {
      problems.push(at + '\'s ' + key + ' names {' + name + '}');
    });
  });
  (field.fields || []).forEach(function (inner) {
    fieldProblems(at + '.' + inner.name, inner, problems);
  });
  log.debug("Leaving fieldProblems().");
}

/**
 * Holds the model to what a reader and a check can be built from.
 *
 * @param authzen - from `readAuthzen()`
 * @returns the problems, empty when there are none
 */
export function checkAuthzen(authzen) {
  log.debug("Entering checkAuthzen().");
  const problems = [];
  const seen = new Set();
  authzen.requests.forEach(function (request) {
    if (seen.has('request:' + request.id)) {
      problems.push('the request ' + request.id + ' is declared twice');
    }
    seen.add('request:' + request.id);
    if (!request.cite) {
      problems.push('the request ' + request.id + ' cites nothing');
    }
    if (!request.notObject) {
      problems.push('the request ' + request.id + ' says nothing of a ' +
                    'body that is not an object');
    }
    request.paths.forEach(function (one) {
      if (one.charAt(0) !== '/') {
        problems.push('the request ' + request.id + '\'s path ' + one +
                      ' is not absolute');
      }
    });
    ['notObject', 'stray', 'absent', 'type'].forEach(function (key) {
      if (!/^STS-AUTHZEN-\d{4}$/.test(String(request.codes[key] || ''))) {
        problems.push('the request ' + request.id + ' has no ' + key +
                      ' code');
      }
    });
    Object.keys(request.sentences).concat(['stray']).forEach(function (key) {
      const sentence = key === 'stray' ? request.stray
        : request.sentences[key];
      unknownPlaceholders(sentence).forEach(function (name) {
        problems.push('the request ' + request.id + '\'s ' + key +
                      ' sentence names {' + name + '}');
      });
    });
    if (request.fields.length === 0) {
      problems.push('the request ' + request.id + ' has no field');
    }
    request.fields.forEach(function (field) {
      fieldProblems(request.id + '.' + field.name, field, problems);
    });
  });
  authzen.members.forEach(function (set) {
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
  const types = new Set();
  if (!authzen.problems.prefix || !authzen.problems.cite) {
    problems.push('the problem types have no prefix or cite nothing');
  }
  authzen.problems.types.forEach(function (one) {
    if (types.has(one.type)) {
      problems.push('the problem type ' + one.type + ' is declared twice');
    }
    types.add(one.type);
    if (!one.title || !one.cite) {
      problems.push('the problem type ' + one.type + ' has no title or ' +
                    'cites nothing');
    }
  });
  log.debug("Leaving checkAuthzen(). " + problems.length + " problem(s).");
  return problems;
}
