// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// File: models/lib/enrollment_lib.mjs
//
// ---------------------------------------------------------------------------
// THE CERTIFICATE-ENROLLMENT MODEL, READ FROM A COMPILED PROGRAM (#1579).
//
// `readEnrollment()` turns the `@body`, `@answer`, `@register` and
// `@operations` models of ACME, EST and SCEP into the tables
// `models/generated/enrollment.json` holds: every request document's
// members with their JSON type and bounds, every answer's members, every
// register's rows and every operation. `checkEnrollment()` refuses a model a
// validator could not be generated from faithfully — a string or an array
// with no upper bound, an integer without both bounds, a bound on a type
// that takes none, a pattern that does not compile, a `valuesFrom` naming no
// register, a missing citation, an id declared twice — and the problem
// stops the image build.
//
// This is an ES module because the TypeSpec compiler loads a library with
// `import()`. It imports nothing from the compiler.
// ---------------------------------------------------------------------------

import bunyan from 'bunyan';

const log = bunyan.createLogger({
  name: 'sts-enrollment-lib',
  level: process.env.LOG_LEVEL || process.env.STS_LOG_LEVEL || 'info'
});

const BODY = Symbol.for('iya.enrollment.body');
const SHAPE = Symbol.for('iya.enrollment.shape');
const FIELD = Symbol.for('iya.enrollment.field');
const ANSWER = Symbol.for('iya.enrollment.answer');
const MEMBER = Symbol.for('iya.enrollment.member');
const REGISTER = Symbol.for('iya.enrollment.register');
const TERM = Symbol.for('iya.enrollment.term');
const OPERATIONS = Symbol.for('iya.enrollment.operations');
const OP = Symbol.for('iya.enrollment.operation');

// The JSON type each TypeSpec scalar is, by the standard library's name.
const SCALARS = { string: 'string', url: 'string', boolean: 'boolean',
  int8: 'integer', int16: 'integer', int32: 'integer', int64: 'integer',
  integer: 'integer', safeint: 'integer', uint8: 'integer',
  uint16: 'integer', uint32: 'integer', uint64: 'integer',
  float32: 'number', float64: 'number', numeric: 'number' };

// How deep a nested object may go: a model that holds itself would not end.
const MAX_DEPTH = 6;

export const $decorators = {
  'IyaSts.EnrollmentLib': {
    body: function (context, target, options) {
      context.program.stateMap(BODY).set(target, options);
    },
    shape: function (context, target, options) {
      context.program.stateMap(SHAPE).set(target, options);
    },
    field: function (context, target, options) {
      context.program.stateMap(FIELD).set(target, options);
    },
    answer: function (context, target, options) {
      context.program.stateMap(ANSWER).set(target, options);
    },
    member: function (context, target, options) {
      context.program.stateMap(MEMBER).set(target, options);
    },
    register: function (context, target, options) {
      context.program.stateMap(REGISTER).set(target, options);
    },
    term: function (context, target, options) {
      context.program.stateMap(TERM).set(target, options);
    },
    operations: function (context, target, options) {
      context.program.stateMap(OPERATIONS).set(target, options);
    },
    operation: function (context, target, options) {
      context.program.stateMap(OP).set(target, options);
    }
  }
};

/**
 * Whether a TypeSpec type is an array.
 *
 * @param type - the type
 * @returns true when it is
 */
function isArray(type) {
  log.debug("Entering isArray().");
  log.debug("Leaving isArray().");
  return type.kind === 'Model' && type.name === 'Array' && !!type.indexer;
}

/**
 * The scalar JSON type of a TypeSpec scalar, through its base scalars.
 *
 * @param type - the scalar
 * @returns `string`, `integer`, `number`, `boolean` or `unknown`
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
 * The string values of a union of string literals, or null when it is not
 * one.
 *
 * @param type - the type
 * @returns the values, or null
 */
function literalsOf(type) {
  log.debug("Entering literalsOf().");
  if (type.kind === 'String') {
    log.debug("Leaving literalsOf(). One literal.");
    return [type.value];
  }
  if (type.kind !== 'Union') {
    log.debug("Leaving literalsOf(). Not a union.");
    return null;
  }
  const out = [];
  let all = true;
  type.variants.forEach(function (variant) {
    if (variant.type.kind === 'String') {
      out.push(variant.type.value);
    } else {
      all = false;
    }
  });
  log.debug("Leaving literalsOf().");
  return all ? out : null;
}

/**
 * One member of a request document: its JSON type, its bounds and, for an
 * array or an object, what it holds.
 *
 * @param program - the compiled program
 * @param type - the member's TypeSpec type
 * @param options - its `@field` options
 * @param depth - how deep in a nested object it is
 * @returns the member, without its name
 */
function fieldTypeOf(program, type, options, depth) {
  log.debug("Entering fieldTypeOf().");
  const out = {};
  if (isArray(type)) {
    out.json = 'array';
    ['minItems', 'maxItems'].forEach(function (key) {
      if (options[key] !== undefined) {
        out[key] = options[key];
      }
    });
    const itemOptions = {};
    ['minLength', 'maxLength', 'pattern', 'patternMessage']
      .forEach(function (key) {
        if (options[key] !== undefined) {
          itemOptions[key] = options[key];
        }
      });
    out.items = fieldTypeOf(program, type.indexer.value, itemOptions,
                            depth + 1);
    log.debug("Leaving fieldTypeOf(). An array.");
    return out;
  }
  ['minLength', 'maxLength', 'pattern', 'patternMessage', 'minimum',
   'maximum', 'valuesFrom'].forEach(function (key) {
    if (options[key] !== undefined) {
      out[key] = options[key];
    }
  });
  if (type.kind === 'Model') {
    out.json = 'object';
    out.shape = shapeOf(program, type, depth + 1);
    log.debug("Leaving fieldTypeOf(). An object.");
    return out;
  }
  const literals = literalsOf(type);
  if (literals && literals.length === 1) {
    out.json = 'literal';
    out.value = literals[0];
  } else if (literals) {
    out.json = 'enum';
    out.values = literals;
  } else if (type.kind === 'Scalar') {
    out.json = scalarOf(type);
  } else if (type.kind === 'Intrinsic' && type.name === 'unknown') {
    out.json = 'any';
  } else {
    out.json = 'unknown';
  }
  if (options.valuesFrom !== undefined) {
    out.json = 'enum';
  }
  log.debug("Leaving fieldTypeOf().");
  return out;
}

/**
 * A model's members, as a request document's shape.
 *
 * @param program - the compiled program
 * @param model - the model
 * @param depth - how deep it is
 * @returns `{ model, others, cite, fields }`
 */
function shapeOf(program, model, depth) {
  log.debug("Entering shapeOf(). " + model.name);
  const options = program.stateMap(SHAPE).get(model) ||
    program.stateMap(BODY).get(model) || {};
  const fields = [];
  if (depth <= MAX_DEPTH) {
    model.properties.forEach(function (property) {
      const fieldOptions = program.stateMap(FIELD).get(property) || {};
      const one = Object.assign({ name: property.name,
                                  required: property.optional !== true,
                                  empty: fieldOptions.empty === true,
                                  cite: fieldOptions.cite || '' },
                                fieldTypeOf(program, property.type,
                                            fieldOptions, depth));
      fields.push(one);
    });
  }
  log.debug("Leaving shapeOf().");
  return { model: model.name, others: options.others || '',
           cite: options.cite || '', fields: fields };
}

/**
 * The JSON types a TypeSpec type may be, for an answer's member.
 *
 * @param type - the type
 * @returns `string`, `integer`, `number`, `boolean`, `array`, `object` or
 *   `any`, as a list
 */
function jsonTypesOf(type) {
  log.debug("Entering jsonTypesOf().");
  if (isArray(type)) {
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
    return ['integer'];
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
    log.debug("Leaving jsonTypesOf(). A scalar.");
    return [scalarOf(type)];
  }
  if (type.kind === 'Intrinsic' && type.name === 'unknown') {
    log.debug("Leaving jsonTypesOf(). Anything.");
    return ['any'];
  }
  log.debug("Leaving jsonTypesOf(). Not a type a member may have.");
  return ['unknown'];
}

/**
 * An answer's members, with the members of each nested object.
 *
 * @param program - the compiled program
 * @param model - the model
 * @param depth - how deep it is
 * @returns the members
 */
function membersOf(program, model, depth) {
  log.debug("Entering membersOf(). " + model.name);
  const list = [];
  model.properties.forEach(function (property) {
    const options = program.stateMap(MEMBER).get(property) || {};
    const out = { name: property.name, types: jsonTypesOf(property.type),
                  required: property.optional !== true,
                  cite: options.cite || '' };
    const values = literalsOf(property.type);
    if (values) {
      out.values = values;
    }
    let inner = property.type;
    if (isArray(inner)) {
      inner = inner.indexer.value;
      out.items = jsonTypesOf(inner);
    }
    if (inner.kind === 'Model' && !isArray(inner) && depth < MAX_DEPTH &&
        inner.properties.size > 0) {
      const nested = program.stateMap(ANSWER).get(inner) || {};
      out.shape = { model: inner.name, members: nested.members || 'closed',
                    list: membersOf(program, inner, depth + 1) };
    }
    if (inner.kind === 'Model' && inner.indexer && !isArray(inner)) {
      // A record (`Record<string>`): any key, each value of one type.
      out.valueTypes = jsonTypesOf(inner.indexer.value);
    }
    if (options.own === true) {
      out.own = true;
    }
    list.push(out);
  });
  log.debug("Leaving membersOf().");
  return list;
}

/**
 * Every request document, answer, register and operation in a compiled
 * program.
 *
 * @param program - the compiled program
 * @returns `{ bodies, answers, registers, operations }`
 */
export function readEnrollment(program) {
  log.debug("Entering readEnrollment().");
  const registers = [];
  program.stateMap(REGISTER).forEach(function (options, model) {
    const rows = [];
    model.properties.forEach(function (property) {
      const term = program.stateMap(TERM).get(property) || {};
      const row = { name: property.name, cite: term.cite || '' };
      ['value', 'code', 'counted'].forEach(function (key) {
        if (term[key] !== undefined) {
          row[key] = term[key];
        }
      });
      if (term.values !== undefined) {
        row.values = term.values.slice(0);
      }
      rows.push(row);
    });
    registers.push({ id: options.id, family: options.family,
                     cite: options.cite, model: model.name, rows: rows });
  });
  const operations = [];
  program.stateMap(OPERATIONS).forEach(function (options, model) {
    const list = [];
    model.properties.forEach(function (property) {
      const op = program.stateMap(OP).get(property) || {};
      const row = { name: property.name, methods: (op.methods || []).slice(0),
                    cite: op.cite || '' };
      ['path', 'accepts', 'answers', 'authenticated', 'refused']
        .forEach(function (key) {
          if (op[key] !== undefined) {
            row[key] = op[key];
          }
        });
      list.push(row);
    });
    operations.push({ family: options.family, cite: options.cite,
                      model: model.name, list: list });
  });
  const bodies = [];
  program.stateMap(BODY).forEach(function (options, model) {
    const shape = shapeOf(program, model, 0);
    shape.fields.forEach(function (field) {
      resolveValues(field, options.family, registers, operations);
    });
    bodies.push({ id: options.id, family: options.family,
                  others: options.others, input: options.input,
                  cite: options.cite, model: model.name,
                  fields: shape.fields });
  });
  const answers = [];
  program.stateMap(ANSWER).forEach(function (options, model) {
    answers.push({ id: options.id, family: options.family,
                   members: options.members, cite: options.cite,
                   model: model.name, list: membersOf(program, model, 0) });
  });
  log.debug("Leaving readEnrollment(). " + bodies.length + " body(ies), " +
            answers.length + " answer(s), " + registers.length +
            " register(s), " + operations.length + " operation list(s).");
  return { bodies: bodies, answers: answers, registers: registers,
           operations: operations };
}

/**
 * Writes a `valuesFrom` member's values from its register — or, for
 * `operations`, from the family's operations — so the generated file says
 * what the validator accepts and the register stays the source.
 *
 * @param field - one member, walked into its items and shape
 * @param family - the document's family
 * @param registers - every register
 * @param operations - every operation list
 */
function resolveValues(field, family, registers, operations) {
  log.debug("Entering resolveValues().");
  if (field.valuesFrom !== undefined) {
    const source = field.valuesFrom === 'operations'
      ? (operations.find(function (one) {
        return one.family === family;
      }) || null)
      : (registers.find(function (one) {
        return one.family === family && one.id === field.valuesFrom;
      }) || null);
    const rows = source ? (source.rows || source.list) : [];
    field.values = rows.map(function (row) {
      return row.name;
    });
    field.resolved = !!source;
  }
  if (field.items) {
    resolveValues(field.items, family, registers, operations);
  }
  if (field.shape) {
    field.shape.fields.forEach(function (one) {
      resolveValues(one, family, registers, operations);
    });
  }
  log.debug("Leaving resolveValues().");
}

/**
 * The problems of one request member: a validator generated from it would
 * not be the check its declaration says.
 *
 * @param at - where it is, for the sentence
 * @param field - the member
 * @param input - `json` or `query`
 * @param problems - where a problem is added
 * @param top - true for a member, false for an array's item
 */
function fieldProblems(at, field, input, problems, top) {
  log.debug("Entering fieldProblems().");
  const lengthy = ['minLength', 'maxLength', 'pattern'].filter(function (k) {
    return field[k] !== undefined;
  });
  const bounded = ['minimum', 'maximum'].filter(function (k) {
    return field[k] !== undefined;
  });
  if (top && !field.cite) {
    problems.push(at + ' cites nothing');
  }
  if (field.json === 'unknown' || field.json === 'number') {
    problems.push(at + ' has a type no request member here is');
  }
  if (field.json === 'string' && field.maxLength === undefined) {
    problems.push(at + ' is a string with no bound');
  }
  if (field.json !== 'string' && lengthy.length > 0) {
    problems.push(at + ' is not a string and takes ' + lengthy.join(', '));
  }
  if (field.json === 'integer' && bounded.length !== 2) {
    problems.push(at + ' is an integer with no minimum and maximum');
  }
  if (field.json !== 'integer' && bounded.length > 0) {
    problems.push(at + ' is not an integer and takes ' + bounded.join(', '));
  }
  if (field.json === 'array' && field.maxItems === undefined) {
    problems.push(at + ' is an array with no bound');
  }
  if (field.json === 'enum' && input !== 'query') {
    problems.push(at + ' is an enumeration in a JSON document, which no ' +
                  'hand-written check had');
  }
  if (field.valuesFrom !== undefined && field.resolved !== true) {
    problems.push(at + '\'s valuesFrom names no register: ' +
                  field.valuesFrom);
  }
  if (field.patternMessage !== undefined && field.pattern === undefined) {
    problems.push(at + ' has a pattern message and no pattern');
  }
  if (field.pattern !== undefined) {
    try {
      new RegExp(field.pattern);
    } catch (e) {
      log.debug("Caught in fieldProblems(): " + ((e && e.message) || e));
      problems.push(at + '\'s pattern does not compile: ' + e.message);
    }
  }
  if (top && field.empty && (field.required || input !== 'query')) {
    problems.push(at + ' may be empty and is required or not in a query');
  }
  if (field.items) {
    fieldProblems(at + '[]', field.items, input, problems, false);
  }
  if (field.shape) {
    if (!field.shape.others) {
      problems.push(at + ' holds ' + field.shape.model + ', which is not ' +
                    'a @shape');
    }
    field.shape.fields.forEach(function (one) {
      fieldProblems(at + '.' + one.name, one, input, problems, true);
    });
  }
  log.debug("Leaving fieldProblems().");
}

/**
 * The problems of an answer's members.
 *
 * @param at - where they are
 * @param list - the members
 * @param problems - where a problem is added
 */
function memberProblems(at, list, problems) {
  log.debug("Entering memberProblems().");
  list.forEach(function (member) {
    if (!member.cite) {
      problems.push(at + '.' + member.name + ' cites nothing');
    }
    if (member.types.indexOf('unknown') >= 0 ||
        (member.items || []).indexOf('unknown') >= 0) {
      problems.push(at + '.' + member.name + ' has a type no JSON value is');
    }
    if (member.shape) {
      memberProblems(at + '.' + member.name, member.shape.list, problems);
    }
  });
  log.debug("Leaving memberProblems().");
}

/**
 * Holds the model to what a validator, a holding and a register reader can
 * be generated from.
 *
 * @param model - from `readEnrollment()`
 * @returns the problems, empty when there are none
 */
export function checkEnrollment(model) {
  log.debug("Entering checkEnrollment().");
  const problems = [];
  const seen = new Set();
  const once = function (what, key) {
    if (seen.has(what + ':' + key)) {
      problems.push('the ' + what + ' ' + key + ' is declared twice');
    }
    seen.add(what + ':' + key);
  };
  model.bodies.forEach(function (body) {
    const at = body.family + ' ' + body.id;
    once('body', body.family + '/' + body.id);
    if (!body.cite) {
      problems.push('the body ' + at + ' cites nothing');
    }
    body.fields.forEach(function (field) {
      fieldProblems(at + '.' + field.name, field, body.input, problems, true);
    });
  });
  model.answers.forEach(function (answer) {
    once('answer', answer.family + '/' + answer.id);
    if (!answer.cite) {
      problems.push('the answer ' + answer.family + ' ' + answer.id +
                    ' cites nothing');
    }
    if (answer.list.length === 0) {
      problems.push('the answer ' + answer.family + ' ' + answer.id +
                    ' has no member');
    }
    memberProblems(answer.family + ' ' + answer.id, answer.list, problems);
  });
  model.registers.forEach(function (register) {
    const at = register.family + ' ' + register.id;
    once('register', register.family + '/' + register.id);
    if (!register.cite) {
      problems.push('the register ' + at + ' cites nothing');
    }
    if (register.rows.length === 0) {
      problems.push('the register ' + at + ' has no row');
    }
    const values = new Set();
    register.rows.forEach(function (row) {
      if (!row.cite) {
        problems.push(at + '.' + row.name + ' cites nothing');
      }
      const wire = row.value !== undefined ? 'value ' + row.value
        : (row.code !== undefined ? 'code ' + row.code : null);
      if (wire !== null) {
        if (values.has(wire)) {
          problems.push(at + ' gives two rows the ' + wire);
        }
        values.add(wire);
      }
    });
  });
  model.operations.forEach(function (list) {
    once('operation list', list.family);
    if (!list.cite) {
      problems.push('the operations of ' + list.family + ' cite nothing');
    }
    list.list.forEach(function (op) {
      if (!op.cite) {
        problems.push(list.family + ' ' + op.name + ' cites nothing');
      }
      if (op.methods.length === 0) {
        problems.push(list.family + ' ' + op.name + ' answers no method');
      }
      op.methods.forEach(function (method) {
        if (['GET', 'POST', 'HEAD'].indexOf(method) < 0) {
          problems.push(list.family + ' ' + op.name + ' answers ' + method +
                        ', which no enrollment operation does');
        }
      });
    });
  });
  log.debug("Leaving checkEnrollment(). " + problems.length + " problem(s).");
  return problems;
}
